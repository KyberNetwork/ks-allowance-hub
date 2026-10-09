// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Test} from 'forge-std/Test.sol';

import {JsonBindings} from 'utils/JsonBindings.sol';

import {PermitHash} from 'test/libraries/PermitHash.sol';

import {AuthKeyLib} from 'src/v2/authenticators/types/AuthKey.sol';
import {MasterKeyApprovalLib} from 'src/v2/authenticators/types/MasterKeyApproval.sol';
import {SessionKeyApprovalLib} from 'src/v2/authenticators/types/SessionKeyApproval.sol';
import {AuthDelegationLib} from 'src/v2/types/AuthDelegation.sol';
import {ERC20TransferLib} from 'src/v2/types/ERC20Transfer.sol';
import {ERC721TransferLib} from 'src/v2/types/ERC721Transfer.sol';
import {ExecutionOrderLib} from 'src/v2/types/ExecutionOrder.sol';
import {ExecutionWitnessLib} from 'src/v2/types/ExecutionWitness.sol';
import {FulfillmentOrderLib} from 'src/v2/types/FulfillmentOrder.sol';
import {FulfillmentSolutionLib} from 'src/v2/types/FulfillmentSolution.sol';
import {FulfillmentWitnessLib} from 'src/v2/types/FulfillmentWitness.sol';
import {GenericCallLib} from 'src/v2/types/GenericCall.sol';
import {SolutionApprovalLib} from 'src/v2/types/SolutionApproval.sol';
import {ValidationParamsLib} from 'src/v2/types/ValidationParams.sol';

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
  function test_T712_SCHEMA_typehashesMatchTheirStructs() public pure {
    assertEq(
      ERC20TransferLib.ERC20_TRANSFER_TYPEHASH,
      keccak256(bytes(JsonBindings.schema_ERC20Transfer)),
      'ERC20Transfer'
    );
    assertEq(
      ERC721TransferLib.ERC721_TRANSFER_TYPEHASH,
      keccak256(bytes(JsonBindings.schema_ERC721Transfer)),
      'ERC721Transfer'
    );
    assertEq(
      GenericCallLib.GENERIC_CALL_TYPEHASH,
      keccak256(bytes(JsonBindings.schema_GenericCall)),
      'GenericCall'
    );
    assertEq(
      ValidationParamsLib.VALIDATION_PARAMS_TYPEHASH,
      keccak256(bytes(JsonBindings.schema_ValidationParams)),
      'ValidationParams'
    );
    assertEq(
      ExecutionOrderLib.EXECUTION_ORDER_TYPEHASH,
      keccak256(bytes(JsonBindings.schema_ExecutionOrder)),
      'ExecutionOrder'
    );
    assertEq(
      FulfillmentOrderLib.FULFILLMENT_ORDER_TYPEHASH,
      keccak256(bytes(JsonBindings.schema_FulfillmentOrder)),
      'FulfillmentOrder'
    );
    assertEq(
      FulfillmentSolutionLib.FULFILLMENT_SOLUTION_TYPEHASH,
      keccak256(bytes(JsonBindings.schema_FulfillmentSolution)),
      'FulfillmentSolution'
    );
    assertEq(
      SolutionApprovalLib.SOLUTION_APPROVAL_TYPEHASH,
      keccak256(bytes(JsonBindings.schema_SolutionApproval)),
      'SolutionApproval'
    );
    assertEq(
      ExecutionWitnessLib.EXECUTION_WITNESS_TYPEHASH,
      keccak256(bytes(JsonBindings.schema_ExecutionWitness)),
      'ExecutionWitness'
    );
    assertEq(
      FulfillmentWitnessLib.FULFILLMENT_WITNESS_TYPEHASH,
      keccak256(bytes(JsonBindings.schema_FulfillmentWitness)),
      'FulfillmentWitness'
    );
    assertEq(
      AuthDelegationLib.AUTH_DELEGATION_TYPEHASH,
      keccak256(bytes(JsonBindings.schema_AuthDelegation)),
      'AuthDelegation'
    );
    assertEq(AuthKeyLib.AUTH_KEY_TYPEHASH, keccak256(bytes(JsonBindings.schema_AuthKey)), 'AuthKey');
    assertEq(
      MasterKeyApprovalLib.MASTER_KEY_APPROVAL_TYPEHASH,
      keccak256(bytes(JsonBindings.schema_MasterKeyApproval)),
      'MasterKeyApproval'
    );
    assertEq(
      SessionKeyApprovalLib.SESSION_KEY_APPROVAL_TYPEHASH,
      keccak256(bytes(JsonBindings.schema_SessionKeyApproval)),
      'SessionKeyApproval'
    );
  }

  /**
   * @dev T712-SCHEMA-PERMIT2 — the witness type strings the hub supplies Permit2. Permit2
   * completes its
   * own stub with the string it is given and hashes the concatenation, so the two together must
   * reproduce the schema `bind-json` derived from the struct. This also pins which colliding
   * schema {SchemaHash} reads for which rail: the suffixes follow discovery order, and a swap
   * fails here.
   */
  function test_T712_SCHEMA_PERMIT2_witnessTypeStringsMatchTheirStructs() public pure {
    assertEq(
      string(
        abi.encodePacked(
          PermitHash._PERMIT_BATCH_WITNESS_TRANSFER_FROM_TYPEHASH_STUB,
          ExecutionWitnessLib.EXECUTION_WITNESS_PERMIT2_TYPE_STRING
        )
      ),
      JsonBindings.schema_PermitBatchWitnessTransferFrom_0,
      'ExecutionWitness permit'
    );
    assertEq(
      string(
        abi.encodePacked(
          PermitHash._PERMIT_BATCH_WITNESS_TRANSFER_FROM_TYPEHASH_STUB,
          FulfillmentWitnessLib.FULFILLMENT_WITNESS_PERMIT2_TYPE_STRING
        )
      ),
      JsonBindings.schema_PermitBatchWitnessTransferFrom_1,
      'FulfillmentWitness permit'
    );
  }
}
