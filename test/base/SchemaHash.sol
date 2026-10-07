// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Vm} from 'forge-std/Vm.sol';

import {JsonBindings} from 'utils/JsonBindings.sol';

import {ExecutionOrder} from 'src/v2/types/ExecutionOrder.sol';
import {ExecutionWitness} from 'src/v2/types/ExecutionWitness.sol';
import {FulfillmentOrder} from 'src/v2/types/FulfillmentOrder.sol';
import {FulfillmentSolution} from 'src/v2/types/FulfillmentSolution.sol';
import {FulfillmentWitness} from 'src/v2/types/FulfillmentWitness.sol';
import {SolutionApproval} from 'src/v2/types/SolutionApproval.sol';

/**
 * @title SchemaHash
 * @notice Hashes a signed type against the `encodeType` its own struct declares
 * @dev The schemas come from `forge bind-json`, so the expected side of a signature assertion is
 * read off the struct rather than transcribed. Kept out of `V2TestBase` because referencing the
 * generated schemas from that contract does not compile: it sits on the IR stack limit.
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
}
