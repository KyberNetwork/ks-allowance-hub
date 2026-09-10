// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {IKSAllowanceHub} from './interfaces/IKSAllowanceHub.sol';

import {ERC20Params} from './types/ERC20Params.sol';
import {ERC20Transfer} from './types/ERC20Transfer.sol';
import {ERC721Params} from './types/ERC721Params.sol';
import {ERC721Transfer} from './types/ERC721Transfer.sol';
import {GenericCall} from './types/GenericCall.sol';
import {RelayerWitnessLibrary} from './types/RelayerWitness.sol';

import {ERC20TransferLibrary} from './types/ERC20Transfer.sol';
import {ERC721TransferLibrary} from './types/ERC721Transfer.sol';

import {ManagementBase} from 'ks-common-sc/src/base/ManagementBase.sol';
import {ManagementPausable} from 'ks-common-sc/src/base/ManagementPausable.sol';
import {ManagementRescuable} from 'ks-common-sc/src/base/ManagementRescuable.sol';
import {ISignatureTransfer} from 'ks-common-sc/src/interfaces/ISignatureTransfer.sol';

import {KSRoles} from 'ks-common-sc/src/libraries/KSRoles.sol';

import {TransientSlot} from 'openzeppelin-contracts/contracts/utils/TransientSlot.sol';

/**
 * @title KSAllowanceHub
 * @notice Separates token approval from execution
 * @dev Users grant their allowance to this hub (or to Permit2) once, instead of to every router
 * they interact with. Each entrypoint pulls the tokens directly to the routers that will consume
 * them, then calls those routers. The hub holds no balance between calls and is not meant to be an
 * allowance target for anything but the flows below.
 */
contract KSAllowanceHub is IKSAllowanceHub, ManagementPausable, ManagementRescuable {
  using ERC20TransferLibrary for *;
  using ERC721TransferLibrary for *;
  using TransientSlot for *;

  /// @inheritdoc IKSAllowanceHub
  ISignatureTransfer public immutable PERMIT2;

  /// @dev The transient slot holding the owner of the tokens spent by the in-flight call
  bytes32 internal constant TOKENS_OWNER_SLOT = bytes32(uint256(keccak256('TokensOwner')) - 1);

  /// @dev The role held by the routers the hub is allowed to call
  bytes32 internal constant WHITELIST_ROUTER_ROLE = keccak256('WHITELIST_ROUTER_ROLE');

  /**
   * @param initialAdmin The default admin, able to manage every role
   * @param initialGuardians The accounts able to pause the hub
   * @param initialRescuers The accounts able to rescue tokens stuck in the hub
   * @param initialWhitelistedRouters The routers the hub is allowed to call
   * @param permit2 The address of the Permit2 contract
   */
  constructor(
    address initialAdmin,
    address[] memory initialGuardians,
    address[] memory initialRescuers,
    address[] memory initialWhitelistedRouters,
    address permit2
  )
    ManagementBase(0, initialAdmin)
    ManagementPausable(initialGuardians)
    ManagementRescuable(initialRescuers)
  {
    PERMIT2 = ISignatureTransfer(permit2);
    _batchGrantRole(WHITELIST_ROUTER_ROLE, initialWhitelistedRouters);
    // Lets guardians drop a router from the whitelist without going through the admin
    _setRoleRevoker(WHITELIST_ROUTER_ROLE, KSRoles.GUARDIAN_ROLE);
  }

  /**
   * @dev Ensures the call does not spend more native token than it was sent with.
   * `nativeBalanceBefore` is read after `msg.value` has already been credited to the hub, so
   * adding `msg.value` back on the right-hand side reduces the check to
   * `balanceAfter >= balanceBeforeTheCall`: the call may spend its own `msg.value` in full, but
   * never any native token the hub was already holding.
   */
  modifier notOverspentNative() {
    uint256 nativeBalanceBefore = address(this).balance;
    _;
    if (address(this).balance + msg.value < nativeBalanceBefore) {
      revert NativeTokenOverspent();
    }
  }

  /**
   * @dev Publishes the token owner for the duration of the call so routers can read it back via
   * `msgSender()`, and doubles as the reentrancy guard: a non-zero slot means an entrypoint is
   * already in flight.
   * @param owner The owner of the tokens spent by the call
   */
  modifier lock(address owner) {
    TransientSlot.AddressSlot tokensOwner = TOKENS_OWNER_SLOT.asAddress();
    if (tokensOwner.tload() != address(0)) {
      revert AlreadyLocked();
    }
    tokensOwner.tstore(owner);
    _;
    tokensOwner.tstore(address(0));
  }

  /// @inheritdoc IKSAllowanceHub
  function msgSender() external view returns (address) {
    return TOKENS_OWNER_SLOT.asAddress().tload();
  }

  /// @inheritdoc IKSAllowanceHub
  function permitTransferAndExecute(
    ERC20Params[] calldata erc20Params,
    ERC721Params[] calldata erc721Params,
    GenericCall[] calldata genericCalls
  )
    external
    payable
    whenNotPaused
    lock(msg.sender)
    notOverspentNative
    returns (bytes[] memory results, uint256 gasUsed)
  {
    uint256 gasStart = gasleft();

    // Permits and transfers the ERC20 tokens, which are always pulled from `msg.sender`
    for (uint256 i = 0; i < erc20Params.length; i++) {
      erc20Params[i].permitTransfer();
    }

    // Permits and transfers the ERC721 tokens
    for (uint256 i = 0; i < erc721Params.length; i++) {
      erc721Params[i].permitTransfer(msg.sender);
    }

    // Reports the movements before executing, so the event reflects the funded state
    emit TransferTokens(
      msg.sender, msg.sender, msg.value, erc20Params.toTransfers(), erc721Params.toTransfers()
    );

    results = _executeGenericCalls(genericCalls);
    // `gasleft()` only decreases within a call, so the subtraction cannot underflow
    unchecked {
      gasUsed = gasStart - gasleft();
    }
  }

  /// @inheritdoc IKSAllowanceHub
  function permit2TransferAndExecute(
    ISignatureTransfer.PermitBatchTransferFrom calldata permit,
    address[] calldata targets,
    ERC721Params[] calldata erc721Params,
    GenericCall[] calldata genericCalls,
    address owner,
    bytes calldata signature
  )
    external
    payable
    whenNotPaused
    lock(owner)
    notOverspentNative
    checkLengths(targets.length, permit.permitted.length)
    returns (bytes[] memory results, uint256 gasUsed)
  {
    uint256 gasStart = gasleft();

    // Pairs each permitted token with its target, requesting the full permitted amount
    ISignatureTransfer.SignatureTransferDetails[] memory transferDetails =
      new ISignatureTransfer.SignatureTransferDetails[](targets.length);

    for (uint256 i = 0; i < targets.length; i++) {
      transferDetails[i].to = targets[i];
      transferDetails[i].requestedAmount = permit.permitted[i].amount;
    }

    // Built once, then reused for both the witness and the event
    ERC20Transfer[] memory erc20Transfers = permit.permitted.toTransfers(targets);
    ERC721Transfer[] memory erc721Transfers = erc721Params.toTransfers();

    if (owner == msg.sender) {
      // The owner is the caller, so the permit alone already pins everything that follows to the
      // owner's own transaction and no witness is needed.
      PERMIT2.permitTransferFrom(permit, transferDetails, owner, signature);
    } else {
      // A relayer is spending the owner's tokens, so the signature must additionally commit to
      // the relayer's identity and to the exact execution it is allowed to perform.
      bytes32 witness =
        RelayerWitnessLibrary.hash(msg.sender, targets, erc721Transfers, genericCalls);
      PERMIT2.permitWitnessTransferFrom(
        permit,
        transferDetails,
        owner,
        witness,
        RelayerWitnessLibrary.RELAYER_WITNESS_PERMIT2_TYPE_STRING,
        signature
      );
    }

    // Permits and transfers the ERC721 tokens, pulled from the owner rather than the caller
    for (uint256 i = 0; i < erc721Params.length; i++) {
      erc721Params[i].permitTransfer(owner);
    }

    // Reports the movements before executing, so the event reflects the funded state
    emit TransferTokens(msg.sender, owner, msg.value, erc20Transfers, erc721Transfers);

    results = _executeGenericCalls(genericCalls);
    // `gasleft()` only decreases within a call, so the subtraction cannot underflow
    unchecked {
      gasUsed = gasStart - gasleft();
    }
  }

  /**
   * @dev Executes the generic calls in order, forwarding each one its own native value
   * @param genericCalls The generic calls to execute
   * @return results The return data of each generic call, in the same order
   */
  function _executeGenericCalls(GenericCall[] calldata genericCalls)
    internal
    returns (bytes[] memory results)
  {
    results = new bytes[](genericCalls.length);
    for (uint256 i = 0; i < genericCalls.length; i++) {
      // The whitelist is what keeps the hub's allowances out of reach of arbitrary callees
      _checkRole(WHITELIST_ROUTER_ROLE, genericCalls[i].router);
      results[i] = genericCalls[i].execute();
    }
  }
}
