// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IKSApprovalProxy} from './interfaces/IKSApprovalProxy.sol';

import {ERC20Params} from './types/ERC20Params.sol';
import {ERC721Params} from './types/ERC721Params.sol';
import {GenericCall} from './types/GenericCall.sol';
import {RelayerWitness, RelayerWitnessLibrary} from './types/RelayerWitness.sol';

import {ManagementBase} from 'ks-common-sc/src/base/ManagementBase.sol';
import {ManagementPausable} from 'ks-common-sc/src/base/ManagementPausable.sol';
import {ManagementRescuable} from 'ks-common-sc/src/base/ManagementRescuable.sol';
import {ISignatureTransfer} from 'ks-common-sc/src/interfaces/ISignatureTransfer.sol';

import {KSRoles} from 'ks-common-sc/src/libraries/KSRoles.sol';

/// @title KSApprovalProxy
/// @notice Separates tokens approval from execution
contract KSApprovalProxy is IKSApprovalProxy, ManagementPausable, ManagementRescuable {
  /// @inheritdoc IKSApprovalProxy
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

  /// @inheritdoc IKSApprovalProxy
  function permitTransferAndExecute(
    ERC20Params[] calldata erc20Params,
    ERC721Params[] calldata erc721Params,
    GenericCall[] calldata genericCalls
  ) external returns (bytes[] memory results) {
    /// @dev Processes the ERC20 tokens
    for (uint256 i = 0; i < erc20Params.length; i++) {
      erc20Params[i].process();
    }

    /// @dev Processes the ERC721 tokens
    for (uint256 i = 0; i < erc721Params.length; i++) {
      erc721Params[i].process();
    }

    /// @dev Executes the generic calls
    results = _executeGenericCalls(genericCalls);
  }

  function permit2TransferAndExecute(
    ISignatureTransfer.PermitBatchTransferFrom calldata permit,
    address[] calldata targets,
    ERC721Params[] calldata erc721Params,
    GenericCall[] calldata genericCalls,
    bytes calldata signature
  ) external returns (bytes[] memory results) {
    /// @dev Transfers the ERC20 tokens using Permit2
    _permit2Transfer(permit, targets, msg.sender, 0, signature);

    /// @dev Processes the ERC721 tokens
    for (uint256 i = 0; i < erc721Params.length; i++) {
      erc721Params[i].process();
    }

    /// @dev Executes the generic calls
    results = _executeGenericCalls(genericCalls);
  }

  /// @inheritdoc IKSApprovalProxy
  function relayPermit2TransferAndExecute(
    ISignatureTransfer.PermitBatchTransferFrom calldata permit,
    address[] calldata targets,
    GenericCall[] calldata genericCalls,
    address owner,
    bytes calldata signature
  ) external returns (bytes[] memory results) {
    /// @dev Prepares the witness
    RelayerWitness memory witness =
      RelayerWitness({relayer: msg.sender, targets: targets, genericCalls: genericCalls});

    /// @dev Transfers the tokens using Permit2
    _permit2Transfer(permit, targets, owner, RelayerWitnessLibrary.hash(witness), signature);

    /// @dev Executes the generic calls
    results = _executeGenericCalls(genericCalls);
  }

  function _permit2Transfer(
    ISignatureTransfer.PermitBatchTransferFrom calldata permit,
    address[] calldata targets,
    address owner,
    bytes32 witness,
    bytes calldata signature
  ) internal {
    ISignatureTransfer.SignatureTransferDetails[] memory
      transferDetails = new ISignatureTransfer.SignatureTransferDetails[](targets.length);

    for (uint256 i = 0; i < targets.length; i++) {
      transferDetails[i].to = targets[i];
      transferDetails[i].requestedAmount = permit.permitted[i].amount;
    }

    if (witness == 0) {
      PERMIT2.permitTransferFrom(permit, transferDetails, owner, signature);
    } else {
      PERMIT2.permitWitnessTransferFrom(
        permit,
        transferDetails,
        owner,
        witness,
        RelayerWitnessLibrary.RELAYER_WITNESS_PERMIT2_TYPE_STRING,
        signature
      );
    }
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
