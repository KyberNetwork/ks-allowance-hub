// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {IKSAllowanceHub} from './interfaces/IKSAllowanceHub.sol';

import {ERC20Params} from './types/ERC20Params.sol';
import {ERC721Params} from './types/ERC721Params.sol';
import {GenericCall} from './types/GenericCall.sol';
import {RelayerWitnessLibrary} from './types/RelayerWitness.sol';

import {ERC20TransferLibrary} from './types/ERC20Transfer.sol';
import {ERC721TransferLibrary} from './types/ERC721Transfer.sol';

import {ManagementBase} from 'ks-common-sc/src/base/ManagementBase.sol';
import {ManagementPausable} from 'ks-common-sc/src/base/ManagementPausable.sol';
import {ManagementRescuable} from 'ks-common-sc/src/base/ManagementRescuable.sol';
import {ISignatureTransfer} from 'ks-common-sc/src/interfaces/ISignatureTransfer.sol';

import {KSRoles} from 'ks-common-sc/src/libraries/KSRoles.sol';

import {
  ReentrancyGuardTransient
} from 'openzeppelin-contracts/contracts/utils/ReentrancyGuardTransient.sol';

/// @title KSAllowanceHub
/// @notice Separates tokens approval from execution
contract KSAllowanceHub is
  IKSAllowanceHub,
  ManagementPausable,
  ManagementRescuable,
  ReentrancyGuardTransient
{
  using ERC20TransferLibrary for *;
  using ERC721TransferLibrary for *;

  /// @inheritdoc IKSAllowanceHub
  ISignatureTransfer public immutable PERMIT2;

  /// @notice The slot holding the msg.sender, transiently. bytes32(uint256(keccak256("MsgSender")) - 1)
  bytes32 internal constant MSG_SENDER_SLOT =
    0x1b9f6ca674ad582e8456f46124f629b489b9f44c7683704064683354005562b9;

  constructor(
    address initialAdmin,
    address[] memory initialGuardians,
    address[] memory initialRescuers,
    address permit2
  ) ManagementBase(0, initialAdmin) {
    _batchGrantRole(KSRoles.GUARDIAN_ROLE, initialGuardians);
    _batchGrantRole(KSRoles.RESCUER_ROLE, initialRescuers);

    PERMIT2 = ISignatureTransfer(permit2);
  }

  modifier notOverspent() {
    uint256 nativeBalanceBefore = address(this).balance;
    _;
    if (address(this).balance + msg.value < nativeBalanceBefore) {
      revert NativeTokenOverspent();
    }
  }

  /// @dev Sets the current
  modifier setMsgSender(address sender) {
    assembly ('memory-safe') {
      tstore(MSG_SENDER_SLOT, sender)
    }
    _;
  }

  /// @inheritdoc IKSAllowanceHub
  function msgSender() external view returns (address sender) {
    assembly ('memory-safe') {
      sender := tload(MSG_SENDER_SLOT)
    }
  }

  /// @inheritdoc IKSAllowanceHub
  function permitTransferAndExecute(
    ERC20Params[] calldata erc20Params,
    ERC721Params[] calldata erc721Params,
    GenericCall[] calldata genericCalls
  )
    external
    payable
    nonReentrant
    notOverspent
    setMsgSender(msg.sender)
    returns (bytes[] memory results, uint256 gasUsed)
  {
    uint256 gasStart = gasleft();

    /// @dev Processes the ERC20 tokens
    for (uint256 i = 0; i < erc20Params.length; i++) {
      erc20Params[i].process();
    }

    /// @dev Processes the ERC721 tokens
    for (uint256 i = 0; i < erc721Params.length; i++) {
      erc721Params[i].process(msg.sender);
    }

    emit CollectTokens(msg.sender, erc20Params.toTransfers(), erc721Params.toTransfers());

    /// @dev Executes the generic calls
    results = _executeGenericCalls(genericCalls);
    gasUsed = gasStart - gasleft();
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
    nonReentrant
    notOverspent
    setMsgSender(owner)
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

    /// @dev Transfers the ERC20 tokens using Permit2
    if (owner == msg.sender) {
      PERMIT2.permitTransferFrom(permit, transferDetails, owner, signature);
    } else {
      /// @dev Prepares the witness
      bytes32 witness = RelayerWitnessLibrary.hash(msg.sender, targets, erc721Params, genericCalls);
      PERMIT2.permitWitnessTransferFrom(
        permit,
        transferDetails,
        owner,
        witness,
        RelayerWitnessLibrary.RELAYER_WITNESS_PERMIT2_TYPE_STRING,
        signature
      );
    }

    /// @dev Processes the ERC721 tokens
    for (uint256 i = 0; i < erc721Params.length; i++) {
      erc721Params[i].process(owner);
    }

    emit CollectTokens(owner, permit.permitted.toTransfers(targets), erc721Params.toTransfers());

    /// @dev Executes the generic calls
    results = _executeGenericCalls(genericCalls);
    gasUsed = gasStart - gasleft();
  }

  function _executeGenericCalls(GenericCall[] calldata genericCalls)
    internal
    returns (bytes[] memory results)
  {
    results = new bytes[](genericCalls.length);
    for (uint256 i = 0; i < genericCalls.length; i++) {
      results[i] = genericCalls[i].execute();
    }
  }
}
