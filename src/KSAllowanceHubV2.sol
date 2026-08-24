// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {IKSAllowanceHubV2} from './interfaces/IKSAllowanceHubV2.sol';

import {ERC20Params} from './types/ERC20Params.sol';
import {ERC20Transfer} from './types/ERC20Transfer.sol';
import {ERC721Params} from './types/ERC721Params.sol';
import {ERC721Transfer} from './types/ERC721Transfer.sol';
import {GenericCall} from './types/GenericCall.sol';
import {RelayerWitnessLibrary} from './types/RelayerWitness.sol';
import {SolverWitnessLibrary} from './types/SolverWitness.sol';
import {ValidationParams} from './types/ValidationParams.sol';

import {ERC20TransferLibrary} from './types/ERC20Transfer.sol';
import {ERC721TransferLibrary} from './types/ERC721Transfer.sol';
import {NativeTransferLibrary} from './types/NativeTransfer.sol';

import {ManagementBase} from 'ks-common-sc/src/base/ManagementBase.sol';
import {ManagementPausable} from 'ks-common-sc/src/base/ManagementPausable.sol';
import {ManagementRescuable} from 'ks-common-sc/src/base/ManagementRescuable.sol';
import {IDaiLikePermit} from 'ks-common-sc/src/interfaces/IDaiLikePermit.sol';
import {ISignatureTransfer} from 'ks-common-sc/src/interfaces/ISignatureTransfer.sol';
import {KSRoles} from 'ks-common-sc/src/libraries/KSRoles.sol';
import {CalldataDecoder} from 'ks-common-sc/src/libraries/calldata/CalldataDecoder.sol';

import {
  IERC20Permit
} from 'openzeppelin-contracts/contracts/token/ERC20/extensions/IERC20Permit.sol';
import {TransientSlot} from 'openzeppelin-contracts/contracts/utils/TransientSlot.sol';
import {ECDSA} from 'openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol';

import {Multicallable} from 'solady/utils/Multicallable.sol';

/**
 * @title KSAllowanceHubV2
 * @notice Separates token approval from execution
 * @dev Users grant their allowance to this hub (or to Permit2) once, instead of to every router
 * they interact with. Each entrypoint pulls the tokens directly to the routers that will consume
 * them, then calls those routers. It is not meant to be an allowance target for anything but the
 * flows below; native left over from an over-sent `msg.value` is stranded until rescued.
 */
contract KSAllowanceHubV2 is
  IKSAllowanceHubV2,
  ManagementPausable,
  ManagementRescuable,
  Multicallable
{
  using CalldataDecoder for bytes;
  using ERC20TransferLibrary for *;
  using ERC721TransferLibrary for *;
  using NativeTransferLibrary for *;
  using TransientSlot for *;

  /// @inheritdoc IKSAllowanceHubV2
  ISignatureTransfer public immutable PERMIT2;

  /// @dev The transient slot holding the owner of the tokens spent by the in-flight call
  bytes32 internal constant TOKENS_OWNER_SLOT = bytes32(uint256(keccak256('TokensOwner')) - 1);

  /// @dev The role held by the routers the hub is allowed to call
  bytes32 internal constant WHITELIST_ROUTER_ROLE = keccak256('WHITELIST_ROUTER_ROLE');

  /// @dev Written into a witness slot the owner wants to leave open: any submitter, or any
  /// calls signer
  address internal constant ANY_ADDRESS = address(uint160(uint256(keccak256('ANY_ADDRESS'))));

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
    _batchGrantRole(WHITELIST_ROUTER_ROLE, initialWhitelistedRouters);
    // Lets guardians drop a router from the whitelist without going through the admin
    _setRoleRevoker(WHITELIST_ROUTER_ROLE, KSRoles.GUARDIAN_ROLE);

    PERMIT2 = ISignatureTransfer(permit2);
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

  /// @inheritdoc IKSAllowanceHubV2
  function msgSender() external view returns (address) {
    return TOKENS_OWNER_SLOT.asAddress().tload();
  }

  /**
   * @notice Runs several of the calls below in one transaction
   * @dev Every sub-call is a `delegatecall` and sees the same `msg.value`, though it arrived once,
   * so `notOverspentNative` bounds the batch as a whole, nesting included.
   * @dev Returns through `_multicallResultsToBytesArray`: Solady's `_multicallDirectReturn` would
   * end the context before the modifier's check ran.
   * @param data The encoded calls to run
   * @return The return data of each call, in the same order
   */
  function multicall(bytes[] calldata data)
    public
    payable
    override
    notOverspentNative
    returns (bytes[] memory)
  {
    return _multicallResultsToBytesArray(_multicall(data));
  }

  /// @inheritdoc IKSAllowanceHubV2
  function permitTokensToPermit2(
    address[] calldata tokens,
    address owner,
    bytes[] calldata permitData
  ) external whenNotPaused checkLengths(tokens.length, permitData.length) {
    for (uint256 i = 0; i < tokens.length; i++) {
      _permitToPermit2(tokens[i], owner, permitData[i]);
    }
  }

  /// @inheritdoc IKSAllowanceHubV2
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
      msg.sender,
      msg.sender,
      msg.value,
      erc20Params.toTransfers(),
      erc721Params.toTransfers(),
      genericCalls.toTransfers()
    );

    results = _executeGenericCalls(genericCalls);
    // `gasleft()` only decreases within a call, so the subtraction cannot underflow
    unchecked {
      gasUsed = gasStart - gasleft();
    }
  }

  /// @inheritdoc IKSAllowanceHubV2
  function permit2TransferAndExecute(
    ISignatureTransfer.PermitBatchTransferFrom calldata permit,
    address[] calldata targets,
    ERC721Params[] calldata erc721Params,
    GenericCall[] calldata genericCalls,
    address owner,
    bool permissionless,
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
      // The owner is the caller, so its own transaction already pins everything that follows and
      // no witness is needed, whatever `permissionless` says.
      PERMIT2.permitTransferFrom(permit, transferDetails, owner, signature);
    } else {
      // Someone other than the owner is spending its tokens, so the signature must also commit to
      // who may submit it and to the exact execution it is allowed to perform.
      bytes32 witness = RelayerWitnessLibrary.hash(
        _witnessCaller(permissionless), targets, erc721Transfers, genericCalls
      );
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
    emit TransferTokens(
      msg.sender, owner, msg.value, erc20Transfers, erc721Transfers, genericCalls.toTransfers()
    );

    results = _executeGenericCalls(genericCalls);
    // `gasleft()` only decreases within a call, so the subtraction cannot underflow
    unchecked {
      gasUsed = gasStart - gasleft();
    }
  }

  /// @inheritdoc IKSAllowanceHubV2
  function permit2TransferAndFulfill(
    ISignatureTransfer.PermitBatchTransferFrom calldata permit,
    address[] calldata targets,
    ERC721Params[] calldata erc721Params,
    ValidationParams[] calldata validationParams,
    address owner,
    bool permissionless,
    bytes calldata ownerSignature,
    GenericCall[] calldata genericCalls,
    bytes calldata callsSignature
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

    // Binds the signature to the solver, to who may authorise the calls, to where the funding
    // goes and to the validators that will judge it. `genericCalls` is left out: the owner signs
    // the outcome it wants, not the path the solver takes to produce it.
    bytes32 witness = SolverWitnessLibrary.hash(
      _witnessCaller(permissionless),
      _callsSigner(genericCalls, permit.deadline, callsSignature),
      targets,
      erc721Transfers,
      validationParams
    );
    PERMIT2.permitWitnessTransferFrom(
      permit,
      transferDetails,
      owner,
      witness,
      SolverWitnessLibrary.SOLVER_WITNESS_PERMIT2_TYPE_STRING,
      ownerSignature
    );

    // Permits and transfers the ERC721 tokens, pulled from the owner rather than the caller
    for (uint256 i = 0; i < erc721Params.length; i++) {
      erc721Params[i].permitTransfer(owner);
    }

    // Reports the movements before executing, so the event reflects the funded state
    emit TransferTokens(
      msg.sender, owner, msg.value, erc20Transfers, erc721Transfers, genericCalls.toTransfers()
    );

    // Snapshots the state each validator needs. This runs after the funding transfers, so a
    // validator measuring a delta measures what the fulfillment produced, not what the owner paid.
    bytes[] memory beforeExecutionOutputs = new bytes[](validationParams.length);
    for (uint256 i = 0; i < validationParams.length; i++) {
      beforeExecutionOutputs[i] = validationParams[i].beforeExecution();
    }

    results = _executeGenericCalls(genericCalls);

    // Rejects the whole fulfillment unless every validator accepts the resulting transition
    for (uint256 i = 0; i < validationParams.length; i++) {
      validationParams[i].afterExecution(beforeExecutionOutputs[i]);
    }

    // `gasleft()` only decreases within a call, so the subtraction cannot underflow
    unchecked {
      gasUsed = gasStart - gasleft();
    }
  }

  /**
   * @dev Mirrors `PermitHelper.callERC20Permit`, but names Permit2 as the spender rather than the
   * hub. Unrecognised lengths and reverting permits are both ignored.
   * @param token The token to permit
   * @param owner The address whose permit this is
   * @param permitData The permit payload
   */
  function _permitToPermit2(address token, address owner, bytes calldata permitData) internal {
    if (permitData.length == 32 * 5) {
      uint256 value = permitData.decodeUint256(0);
      uint256 deadline = permitData.decodeUint256(1);
      uint8 v = uint8(permitData.decodeUint256(2));
      bytes32 r = permitData.decodeBytes32(3);
      bytes32 s = permitData.decodeBytes32(4);

      try IERC20Permit(token).permit(owner, address(PERMIT2), value, deadline, v, r, s) {} catch {}
    } else if (permitData.length == 32 * 6) {
      uint256 nonce = permitData.decodeUint256(0);
      uint256 expiry = permitData.decodeUint256(1);
      bool allowed = permitData.decodeBool(2);
      uint8 v = uint8(permitData.decodeUint256(3));
      bytes32 r = permitData.decodeBytes32(4);
      bytes32 s = permitData.decodeBytes32(5);

      try IDaiLikePermit(token).permit(owner, address(PERMIT2), nonce, expiry, allowed, v, r, s) {}
        catch {}
    }
  }

  /**
   * @dev The calls signer a witness commits to. Recovered from the signature, so a tampered call
   * list yields a different address and the witness stops matching. The chain id and deadline are
   * hashed in too, which stops an authorisation being replayed elsewhere.
   * @param genericCalls The calls being authorised
   * @param deadline The permit deadline the authorisation is tied to
   * @param callsSignature The signature over the encoded calls, or empty
   * @return `ANY_ADDRESS` if unsigned, otherwise the recovered signer
   */
  function _callsSigner(
    GenericCall[] calldata genericCalls,
    uint256 deadline,
    bytes calldata callsSignature
  ) internal view returns (address) {
    return callsSignature.length == 0
      ? ANY_ADDRESS
      : ECDSA.recover(keccak256(abi.encode(block.chainid, genericCalls, deadline)), callsSignature);
  }

  /**
   * @dev The submitter a witness commits to. The flag needs no signature of its own: it only picks
   * which digest to rebuild, and the wrong pick fails verification.
   * @param permissionless Whether the owner signed for submission by anyone
   * @return `ANY_ADDRESS` if permissionless, otherwise `msg.sender`
   */
  function _witnessCaller(bool permissionless) internal view returns (address) {
    return permissionless ? ANY_ADDRESS : msg.sender;
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
