// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from 'forge-std/Test.sol';

import {PermitHash} from 'test/libraries/PermitHash.sol';

import {JsonBindings} from 'utils/JsonBindings.sol';

import {AHV2OrderLib} from 'src/types/AHV2Order.sol';
import {AHV2SolutionLib} from 'src/types/AHV2Solution.sol';
import {AuthDelegationLib} from 'src/types/AuthDelegation.sol';
import {CallParamsLib} from 'src/types/CallParams.sol';
import {ERC20AllowanceLib} from 'src/types/ERC20Allowance.sol';
import {ERC721ApprovalLib} from 'src/types/ERC721Approval.sol';
import {HookParamsLib} from 'src/types/HookParams.sol';
import {SolutionApprovalLib} from 'src/types/SolutionApproval.sol';

/**
 * @title SchemaAuditTest
 * @notice T712-SCHEMA — every typehash against the `encodeType` its own struct declares
 * @dev The struct is the source of truth, and a production type string that drifts from it passes
 * every other case in the suite: the hub is self-consistent, and Permit2 derives its witness
 * typehash from the string the hub supplies, so the fork checks the hub against itself. These
 * schemas come from `forge bind-json`, which reads the struct declarations, so nothing here is a
 * transcription. Regenerate with `forge bind-json`; `foundry.toml` pins the file set under
 * `[bind_json]`, without which the output is not reproducible. The command is a fixed point, not
 * a single pass: the generated file is itself compiled, and imports the types it binds, so a type
 * added to the set appears only on the following run.
 */
contract SchemaAuditTest is Test {
  /// T712-SCHEMA — each typehash equals the hash of the schema derived from its struct
  function test_T712_SCHEMA_typehashesMatchTheirStructs() public pure {
    assertEq(
      ERC20AllowanceLib.ERC20_ALLOWANCE_TYPEHASH,
      keccak256(bytes(JsonBindings.schema_ERC20Allowance)),
      'ERC20Allowance'
    );
    assertEq(
      ERC721ApprovalLib.ERC721_APPROVAL_TYPEHASH,
      keccak256(bytes(JsonBindings.schema_ERC721Approval)),
      'ERC721Approval'
    );
    assertEq(
      CallParamsLib.CALL_PARAMS_TYPEHASH,
      keccak256(bytes(JsonBindings.schema_CallParams)),
      'CallParams'
    );
    assertEq(
      HookParamsLib.HOOK_PARAMS_TYPEHASH,
      keccak256(bytes(JsonBindings.schema_HookParams)),
      'HookParams'
    );
    assertEq(
      AHV2OrderLib.AHV2_ORDER_TYPEHASH, keccak256(bytes(JsonBindings.schema_AHV2Order)), 'AHV2Order'
    );
    assertEq(
      AHV2SolutionLib.AHV2_SOLUTION_TYPEHASH,
      keccak256(bytes(JsonBindings.schema_AHV2Solution)),
      'AHV2Solution'
    );
    assertEq(
      SolutionApprovalLib.SOLUTION_APPROVAL_TYPEHASH,
      keccak256(bytes(JsonBindings.schema_SolutionApproval)),
      'SolutionApproval'
    );
    assertEq(
      AuthDelegationLib.AUTH_DELEGATION_TYPEHASH,
      keccak256(bytes(JsonBindings.schema_AuthDelegation)),
      'AuthDelegation'
    );
  }

  /**
   * T712-SCHEMA-PERMIT2 — the Permit2 stub plus the witness type string equals its struct schema
   * @dev Permit2 completes its own stub with the string it is given and hashes the concatenation,
   * so the two together must reproduce the schema `bind-json` derived from the struct.
   */
  function test_T712_SCHEMA_PERMIT2_witnessTypeStringMatchesItsStruct() public pure {
    assertEq(
      string(
        abi.encodePacked(
          PermitHash._PERMIT_BATCH_WITNESS_TRANSFER_FROM_TYPEHASH_STUB,
          AHV2OrderLib.PERMIT2_ORDER_TYPE_STRING
        )
      ),
      JsonBindings.schema_PermitBatchWitnessTransferFrom,
      'AHV2Order permit'
    );
  }

  /**
   * T712-SCHEMA — the typehashes of the order, solution and approval match their
   * written-out strings
   * @dev The three type strings, written out here, against the production typehashes
   */
  function test_T712_SCHEMA_typeStringsWrittenOut() public pure {
    string memory callParams = 'CallParams(address callee,uint256 value,bytes data)';
    string memory hookParams = 'HookParams(address hook,bytes32 flags,bytes data)';
    string memory erc20Allowance = 'ERC20Allowance(address token,uint160 amount)';
    string memory erc721Approval = 'ERC721Approval(address token,uint256 tokenId)';
    string memory order =
      'AHV2Order(address owner,address authenticator,address exclusiveCaller,ERC20Allowance[] erc20Allowances,ERC721Approval[] erc721Approvals,HookParams[] hooks,CallParams[] calls,address solutionApprover,uint256 nonce,uint256 expiration,bytes clientData)';
    string memory solution =
      'AHV2Solution(address[] erc20Targets,uint160[] erc20Amounts,address[] erc721Targets,bytes[] solverData,uint256 nonce,uint256 expiration)';

    assertEq(
      AHV2OrderLib.AHV2_ORDER_TYPEHASH,
      keccak256(abi.encodePacked(order, callParams, erc20Allowance, erc721Approval, hookParams)),
      'AHV2Order'
    );
    assertEq(
      AHV2SolutionLib.AHV2_SOLUTION_TYPEHASH, keccak256(abi.encodePacked(solution)), 'AHV2Solution'
    );
    assertEq(
      SolutionApprovalLib.SOLUTION_APPROVAL_TYPEHASH,
      keccak256(
        abi.encodePacked(
          'SolutionApproval(AHV2Order order,AHV2Solution solution)',
          order,
          solution,
          callParams,
          erc20Allowance,
          erc721Approval,
          hookParams
        )
      ),
      'SolutionApproval'
    );
  }
}
