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

/// @title KSAllowanceHub
/// @notice Separates tokens approval from execution
contract KSAllowanceHub is IKSAllowanceHub, ManagementPausable, ManagementRescuable {
  using ERC20TransferLibrary for *;
  using ERC721TransferLibrary for *;
  using TransientSlot for *;

  /// @inheritdoc IKSAllowanceHub
  ISignatureTransfer public immutable PERMIT2;

  /// @notice The slot holding the address of the tokens owner, transiently.
  bytes32 internal constant TOKENS_OWNER_SLOT = bytes32(uint256(keccak256('TokensOwner')) - 1);

  /// @notice The role for whitelisted routers
  bytes32 internal constant WHITELIST_ROUTER_ROLE = keccak256('WHITELIST_ROUTER_ROLE');

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
  }

  /// @dev Ensures the native tokens are not overspent
  modifier notOverspentNative() {
    uint256 nativeBalanceBefore = address(this).balance;
    _;
    if (address(this).balance + msg.value < nativeBalanceBefore) {
      revert NativeTokenOverspent();
    }
  }

  /// @dev Locks the function for further calls, and sets the tokens owner
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

    /// @dev Permits and transfers the ERC20 tokens
    for (uint256 i = 0; i < erc20Params.length; i++) {
      erc20Params[i].permitTransfer();
    }

    /// @dev Permits and transfers the ERC721 tokens
    for (uint256 i = 0; i < erc721Params.length; i++) {
      erc721Params[i].permitTransfer(msg.sender);
    }

    /// @dev Emits the event
    emit TransferTokens(
      msg.sender, msg.sender, msg.value, erc20Params.toTransfers(), erc721Params.toTransfers()
    );

    /// @dev Executes the generic calls
    results = _executeGenericCalls(genericCalls);
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
    returns (bytes[] memory results, uint256 gasUsed)
  {
    uint256 gasStart = gasleft();

    /// @dev Prepares the transfer details
    ISignatureTransfer.SignatureTransferDetails[] memory transferDetails =
      new ISignatureTransfer.SignatureTransferDetails[](targets.length);

    for (uint256 i = 0; i < targets.length; i++) {
      transferDetails[i].to = targets[i];
      transferDetails[i].requestedAmount = permit.permitted[i].amount;
    }

    /// @dev Prepares the transfers data for signature verification and event emission
    ERC20Transfer[] memory erc20Transfers = permit.permitted.toTransfers(targets);
    ERC721Transfer[] memory erc721Transfers = erc721Params.toTransfers();

    /// @dev Transfers the ERC20 tokens using Permit2
    if (owner == msg.sender) {
      PERMIT2.permitTransferFrom(permit, transferDetails, owner, signature);
    } else {
      /// @dev Prepares the witness
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

    /// @dev Permits and transfers the ERC721 tokens
    for (uint256 i = 0; i < erc721Params.length; i++) {
      erc721Params[i].permitTransfer(owner);
    }

    /// @dev Emits the event
    emit TransferTokens(msg.sender, owner, msg.value, erc20Transfers, erc721Transfers);

    /// @dev Executes the generic calls
    results = _executeGenericCalls(genericCalls);
    unchecked {
      gasUsed = gasStart - gasleft();
    }
  }

  function _executeGenericCalls(GenericCall[] calldata genericCalls)
    internal
    returns (bytes[] memory results)
  {
    results = new bytes[](genericCalls.length);
    for (uint256 i = 0; i < genericCalls.length; i++) {
      if (!hasRole(WHITELIST_ROUTER_ROLE, genericCalls[i].router)) {
        revert UnwhitelistedRouter(genericCalls[i].router);
      }
      results[i] = genericCalls[i].execute();
    }
  }
}
