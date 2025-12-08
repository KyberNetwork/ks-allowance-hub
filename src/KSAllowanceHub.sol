// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IKSAllowanceHub} from './interfaces/IKSAllowanceHub.sol';

import {ERC20Params} from './types/ERC20Params.sol';
import {ERC721Params} from './types/ERC721Params.sol';
import {GenericCall} from './types/GenericCall.sol';
import {RelayerWitnessLibrary} from './types/RelayerWitness.sol';

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
  /// @inheritdoc IKSAllowanceHub
  ISignatureTransfer public immutable PERMIT2;

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

  /// @inheritdoc IKSAllowanceHub
  function permitTransferAndExecute(
    ERC20Params[] calldata erc20Params,
    ERC721Params[] calldata erc721Params,
    GenericCall[] calldata genericCalls
  ) external payable notOverspent nonReentrant returns (bytes[] memory results) {
    /// @dev Processes the ERC20 tokens
    for (uint256 i = 0; i < erc20Params.length; i++) {
      erc20Params[i].process();
    }

    /// @dev Processes the ERC721 tokens
    for (uint256 i = 0; i < erc721Params.length; i++) {
      erc721Params[i].process(msg.sender);
    }

    /// @dev Executes the generic calls
    results = _executeGenericCalls(genericCalls);
  }

  /// @inheritdoc IKSAllowanceHub
  function permit2TransferAndExecute(
    ISignatureTransfer.PermitBatchTransferFrom calldata permit,
    address[] calldata targets,
    ERC721Params[] calldata erc721Params,
    GenericCall[] calldata genericCalls,
    address owner,
    bytes calldata signature
  ) external payable notOverspent nonReentrant returns (bytes[] memory results) {
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

    /// @dev Executes the generic calls
    results = _executeGenericCalls(genericCalls);
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
