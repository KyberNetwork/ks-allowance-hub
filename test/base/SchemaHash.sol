// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Vm} from 'forge-std/Vm.sol';

import {JsonBindings} from '../../utils/JsonBindings.sol';

import {AHV2Order} from '../../src/types/AHV2Order.sol';
import {AHV2Solution} from '../../src/types/AHV2Solution.sol';
import {AHV2Witness, PermitBatchWitnessTransferFrom} from '../../src/types/AHV2Witness.sol';
import {AuthDelegation} from '../../src/types/AuthDelegation.sol';
import {CallParams} from '../../src/types/CallParams.sol';
import {ERC20Allowance} from '../../src/types/ERC20Allowance.sol';
import {ERC721Approval} from '../../src/types/ERC721Approval.sol';
import {HookParams} from '../../src/types/HookParams.sol';
import {SolutionApproval} from '../../src/types/SolutionApproval.sol';

/**
 * @title SchemaHash
 * @notice Single source of struct hashes for the suite, each taken against the `encodeType` its own
 * struct declares
 * @dev The schemas come from `forge bind-json`, so the expected side of a signature assertion is
 * read off the struct rather than transcribed. Digests are assembled from these hashes in
 * {V2TestBase}.
 */
library SchemaHash {
  /// @dev `address(uint160(uint256(keccak256('hevm cheat code'))))`, written out so a library can
  /// reach the cheatcodes without inheriting a test contract
  Vm private constant VM = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

  function ahv2Order(AHV2Order memory o) internal pure returns (bytes32) {
    return VM.eip712HashStruct(JsonBindings.schema_AHV2Order, abi.encode(o));
  }

  function ahv2Solution(AHV2Solution memory s) internal pure returns (bytes32) {
    return VM.eip712HashStruct(JsonBindings.schema_AHV2Solution, abi.encode(s));
  }

  function ahv2Witness(AHV2Witness memory w) internal pure returns (bytes32) {
    return VM.eip712HashStruct(JsonBindings.schema_AHV2Witness, abi.encode(w));
  }

  function solutionApproval(SolutionApproval memory a) internal pure returns (bytes32) {
    return VM.eip712HashStruct(JsonBindings.schema_SolutionApproval, abi.encode(a));
  }

  function authDelegation(AuthDelegation memory d) internal pure returns (bytes32) {
    return VM.eip712HashStruct(JsonBindings.schema_AuthDelegation, abi.encode(d));
  }

  function erc20Allowance(ERC20Allowance memory a) internal pure returns (bytes32) {
    return VM.eip712HashStruct(JsonBindings.schema_ERC20Allowance, abi.encode(a));
  }

  function erc721Approval(ERC721Approval memory a) internal pure returns (bytes32) {
    return VM.eip712HashStruct(JsonBindings.schema_ERC721Approval, abi.encode(a));
  }

  function callParams(CallParams memory c) internal pure returns (bytes32) {
    return VM.eip712HashStruct(JsonBindings.schema_CallParams, abi.encode(c));
  }

  function hookParams(HookParams memory h) internal pure returns (bytes32) {
    return VM.eip712HashStruct(JsonBindings.schema_HookParams, abi.encode(h));
  }

  /// @dev The `structHash` Permit2 signs for a witness permit
  function permit2Witness(PermitBatchWitnessTransferFrom memory p) internal pure returns (bytes32) {
    return VM.eip712HashStruct(JsonBindings.schema_PermitBatchWitnessTransferFrom, abi.encode(p));
  }
}
