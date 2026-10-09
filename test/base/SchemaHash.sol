// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Vm} from 'forge-std/Vm.sol';

import {JsonBindings} from 'utils/JsonBindings.sol';

import {
  PermitBatchWitnessTransferFrom as Permit2ExecutionWitness
} from 'src/v2/types/ExecutionWitness.sol';
import {
  PermitBatchWitnessTransferFrom as Permit2FulfillmentWitness
} from 'src/v2/types/FulfillmentWitness.sol';

import {AuthKey} from 'src/v2/authenticators/types/AuthKey.sol';
import {AuthDelegation} from 'src/v2/types/AuthDelegation.sol';
import {ExecutionOrder} from 'src/v2/types/ExecutionOrder.sol';
import {ExecutionWitness} from 'src/v2/types/ExecutionWitness.sol';
import {FulfillmentOrder} from 'src/v2/types/FulfillmentOrder.sol';
import {FulfillmentSolution} from 'src/v2/types/FulfillmentSolution.sol';
import {FulfillmentWitness} from 'src/v2/types/FulfillmentWitness.sol';
import {SolutionApproval} from 'src/v2/types/SolutionApproval.sol';

/**
 * @title SchemaHash
 * @notice Hashes a signed type against the `encodeType` its own struct declares, and exposes the
 * schemas that are needed as strings
 * @dev The schemas come from `forge bind-json`, so the expected side of a signature assertion is
 * read off the struct rather than transcribed.
 */
library SchemaHash {
  /// @dev `address(uint160(uint256(keccak256('hevm cheat code'))))`, written out so a library can
  /// reach the cheatcodes without inheriting a test contract
  Vm private constant VM = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

  function executionOrder(ExecutionOrder memory o) internal pure returns (bytes32) {
    return VM.eip712HashStruct(JsonBindings.schema_ExecutionOrder, abi.encode(o));
  }

  function fulfillmentOrder(FulfillmentOrder memory o) internal pure returns (bytes32) {
    return VM.eip712HashStruct(JsonBindings.schema_FulfillmentOrder, abi.encode(o));
  }

  function fulfillmentSolution(FulfillmentSolution memory s) internal pure returns (bytes32) {
    return VM.eip712HashStruct(JsonBindings.schema_FulfillmentSolution, abi.encode(s));
  }

  function solutionApproval(SolutionApproval memory a) internal pure returns (bytes32) {
    return VM.eip712HashStruct(JsonBindings.schema_SolutionApproval, abi.encode(a));
  }

  function executionWitness(ExecutionWitness memory w) internal pure returns (bytes32) {
    return VM.eip712HashStruct(JsonBindings.schema_ExecutionWitness, abi.encode(w));
  }

  function fulfillmentWitness(FulfillmentWitness memory w) internal pure returns (bytes32) {
    return VM.eip712HashStruct(JsonBindings.schema_FulfillmentWitness, abi.encode(w));
  }

  function authDelegation(AuthDelegation memory d) internal pure returns (bytes32) {
    return VM.eip712HashStruct(JsonBindings.schema_AuthDelegation, abi.encode(d));
  }

  function authKey(AuthKey memory k) internal pure returns (bytes32) {
    return VM.eip712HashStruct(JsonBindings.schema_AuthKey, abi.encode(k));
  }

  /// @dev The approvals are hashed from a typehash rather than a struct because production takes
  /// their keys already hashed, so a case may pin the encoding with hashes of its own choosing
  function masterKeyApprovalTypehash() internal pure returns (bytes32) {
    return keccak256(bytes(JsonBindings.schema_MasterKeyApproval));
  }

  /// @dev As {masterKeyApprovalTypehash}, for the type a master key signs
  function sessionKeyApprovalTypehash() internal pure returns (bytes32) {
    return keccak256(bytes(JsonBindings.schema_SessionKeyApproval));
  }

  /**
   * @dev The `structHash` Permit2 signs for an execution permit. Permit2 gives both witness
   * variants the same type name, so the two declarations collide and `bind-json` suffixes their
   * schemas in discovery order; `T712-SCHEMA-PERMIT2` pins which suffix is which.
   */
  function permit2ExecutionWitness(Permit2ExecutionWitness memory p)
    internal
    pure
    returns (bytes32)
  {
    return VM.eip712HashStruct(JsonBindings.schema_PermitBatchWitnessTransferFrom_0, abi.encode(p));
  }

  /// @dev The fulfillment counterpart of {permit2ExecutionWitness}
  function permit2FulfillmentWitness(Permit2FulfillmentWitness memory p)
    internal
    pure
    returns (bytes32)
  {
    return VM.eip712HashStruct(JsonBindings.schema_PermitBatchWitnessTransferFrom_1, abi.encode(p));
  }
}
