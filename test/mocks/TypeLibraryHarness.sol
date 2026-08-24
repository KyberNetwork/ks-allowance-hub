// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ERC20Params} from 'src/types/ERC20Params.sol';
import {ERC20Transfer, ERC20TransferLibrary} from 'src/types/ERC20Transfer.sol';
import {ERC721Params} from 'src/types/ERC721Params.sol';
import {ERC721Transfer, ERC721TransferLibrary} from 'src/types/ERC721Transfer.sol';
import {GenericCall, GenericCallLibrary} from 'src/types/GenericCall.sol';
import {NativeTransfer, NativeTransferLibrary} from 'src/types/NativeTransfer.sol';
import {RelayerWitness, RelayerWitnessLibrary} from 'src/types/RelayerWitness.sol';
import {SolverWitness, SolverWitnessLibrary} from 'src/types/SolverWitness.sol';
import {ValidationParams, ValidationParamsLibrary} from 'src/types/ValidationParams.sol';

import {ISignatureTransfer} from 'ks-common-sc/src/interfaces/ISignatureTransfer.sol';

/**
 * @notice External surface over the `internal` type libraries
 * @dev The projection helpers take `calldata` arrays, so they are unreachable from a test contract
 * without an external call frame to supply that calldata. This harness provides exactly that and
 * adds no logic of its own.
 */
contract TypeLibraryHarness {
  function erc20Transfers(ERC20Params[] calldata params)
    external
    pure
    returns (ERC20Transfer[] memory)
  {
    return ERC20TransferLibrary.toTransfers(params);
  }

  function erc20Transfers(
    ISignatureTransfer.TokenPermissions[] calldata permitted,
    address[] calldata targets
  ) external pure returns (ERC20Transfer[] memory) {
    return ERC20TransferLibrary.toTransfers(permitted, targets);
  }

  function erc721Transfers(ERC721Params[] calldata params)
    external
    pure
    returns (ERC721Transfer[] memory)
  {
    return ERC721TransferLibrary.toTransfers(params);
  }

  function nativeTransfers(GenericCall[] calldata calls)
    external
    pure
    returns (NativeTransfer[] memory)
  {
    return NativeTransferLibrary.toTransfers(calls);
  }

  function hashErc721Transfer(ERC721Transfer memory transfer) external pure returns (bytes32) {
    return ERC721TransferLibrary.hash(transfer);
  }

  function hashGenericCall(GenericCall memory call) external pure returns (bytes32) {
    return GenericCallLibrary.hash(call);
  }

  function hashValidationParams(ValidationParams memory params) external pure returns (bytes32) {
    return ValidationParamsLibrary.hash(params);
  }

  function hashRelayerWitness(RelayerWitness memory witness) external pure returns (bytes32) {
    return RelayerWitnessLibrary.hash(witness);
  }

  function hashRelayerWitnessFields(
    address relayer,
    address[] memory targets,
    ERC721Transfer[] memory transfers,
    GenericCall[] memory calls
  ) external pure returns (bytes32) {
    return RelayerWitnessLibrary.hash(relayer, targets, transfers, calls);
  }

  function hashSolverWitness(SolverWitness memory witness) external pure returns (bytes32) {
    return SolverWitnessLibrary.hash(witness);
  }

  function hashSolverWitnessFields(
    address solver,
    address callsSigner,
    address[] memory targets,
    ERC721Transfer[] memory transfers,
    ValidationParams[] memory params
  ) external pure returns (bytes32) {
    return SolverWitnessLibrary.hash(solver, callsSigner, targets, transfers, params);
  }

  function relayerWitnessTypeString() external pure returns (string memory) {
    return RelayerWitnessLibrary.RELAYER_WITNESS_PERMIT2_TYPE_STRING;
  }

  function relayerWitnessTypehash() external pure returns (bytes32) {
    return RelayerWitnessLibrary.RELAYER_WITNESS_TYPEHASH;
  }

  function solverWitnessTypeString() external pure returns (string memory) {
    return SolverWitnessLibrary.SOLVER_WITNESS_PERMIT2_TYPE_STRING;
  }

  function solverWitnessTypehash() external pure returns (bytes32) {
    return SolverWitnessLibrary.SOLVER_WITNESS_TYPEHASH;
  }

  function erc721TransferTypehash() external pure returns (bytes32) {
    return ERC721TransferLibrary.ERC721_TRANSFER_TYPEHASH;
  }

  function genericCallTypehash() external pure returns (bytes32) {
    return GenericCallLibrary.GENERIC_CALL_TYPEHASH;
  }

  function validationParamsTypehash() external pure returns (bytes32) {
    return ValidationParamsLibrary.VALIDATION_PARAMS_TYPEHASH;
  }
}
