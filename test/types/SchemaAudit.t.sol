// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from 'forge-std/Test.sol';

import {JsonBindings} from 'utils/JsonBindings.sol';

import {PermitHash} from 'test/libraries/PermitHash.sol';

import {AuthDelegationLib} from 'src/types/AuthDelegation.sol';
import {ERC20AllowanceLib} from 'src/types/ERC20Allowance.sol';
import {ERC20TransferLib} from 'src/types/ERC20Transfer.sol';
import {ERC721ApprovalLib} from 'src/types/ERC721Approval.sol';
import {ERC721TransferLib} from 'src/types/ERC721Transfer.sol';
import {ExecutionOrderLib} from 'src/types/ExecutionOrder.sol';
import {ExecutionWitnessLib} from 'src/types/ExecutionWitness.sol';
import {FulfillmentOrderLib} from 'src/types/FulfillmentOrder.sol';
import {FulfillmentSolutionLib} from 'src/types/FulfillmentSolution.sol';
import {FulfillmentWitnessLib} from 'src/types/FulfillmentWitness.sol';
import {GenericCallLib} from 'src/types/GenericCall.sol';
import {SolutionApprovalLib} from 'src/types/SolutionApproval.sol';
import {ValidationParamsLib} from 'src/types/ValidationParams.sol';
import {MasterKeyUpdateLib} from 'src/types/authenticators/MasterKeyUpdate.sol';
import {NonceRevocationLib} from 'src/types/authenticators/NonceRevocation.sol';
import {SessionKeyUpdateLib} from 'src/types/authenticators/SessionKeyUpdate.sol';
import {AuthKeyLib} from 'src/types/base/AuthKey.sol';

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
      MasterKeyUpdateLib.MASTER_KEY_UPDATE_TYPEHASH,
      keccak256(bytes(JsonBindings.schema_MasterKeyUpdate)),
      'MasterKeyUpdate'
    );
    assertEq(
      SessionKeyUpdateLib.SESSION_KEY_UPDATE_TYPEHASH,
      keccak256(bytes(JsonBindings.schema_SessionKeyUpdate)),
      'SessionKeyUpdate'
    );
    assertEq(
      NonceRevocationLib.NONCE_REVOCATION_TYPEHASH,
      keccak256(bytes(JsonBindings.schema_NonceRevocation)),
      'NonceRevocation'
    );
  }

  /**
   * T712-SCHEMA-PERMIT2 — the Permit2 stub plus each witness type string equals its struct schema
   * @dev Permit2 completes its own stub with the string it is given and hashes the concatenation,
   * so the two together must reproduce the schema `bind-json` derived from the struct. This also
   * pins which colliding schema {SchemaHash} reads for which rail: the suffixes follow discovery
   * order, and a swap fails here.
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

  /**
   * T712-SCHEMA — the four typehashes carrying client data match their written-out strings
   * @dev The four type strings that carry `clientData`, written out here, against the production
   * typehashes
   */
  function test_T712_SCHEMA_clientDataTypeStringsWrittenOut() public pure {
    string memory generic = 'GenericCall(address router,uint256 value,bytes data)';
    string memory validation =
      'ValidationParams(address validator,bytes32 action,bytes beforeExecutionInput,bytes afterExecutionInput)';

    assertEq(
      ExecutionOrderLib.EXECUTION_ORDER_TYPEHASH,
      keccak256(
        abi.encodePacked(
          'ExecutionOrder(address owner,address relayer,ERC20Transfer[] erc20Transfers,ERC721Transfer[] erc721Transfers,GenericCall[] genericCalls,uint256 nonce,uint256 expiration,bytes extraData,bytes clientData)',
          'ERC20Transfer(address token,address target,uint160 amount)',
          'ERC721Transfer(address token,uint256 tokenId,address target)',
          generic
        )
      ),
      'ExecutionOrder'
    );
    assertEq(
      FulfillmentOrderLib.FULFILLMENT_ORDER_TYPEHASH,
      keccak256(
        abi.encodePacked(
          'FulfillmentOrder(address owner,address solver,ERC20Allowance[] erc20Allowances,ERC721Approval[] erc721Approvals,ValidationParams[] validationParams,GenericCall[] ownerCalls,address solutionApprover,uint256 nonce,uint256 expiration,bytes extraData,bytes clientData)',
          'ERC20Allowance(address token,uint160 amount)',
          'ERC721Approval(address token,uint256 tokenId)',
          generic,
          validation
        )
      ),
      'FulfillmentOrder'
    );
    assertEq(
      ExecutionWitnessLib.EXECUTION_WITNESS_TYPEHASH,
      keccak256(
        abi.encodePacked(
          'ExecutionWitness(address relayer,address[] erc20Targets,ERC721Transfer[] erc721Transfers,GenericCall[] genericCalls,bytes extraData,bytes clientData)',
          'ERC721Transfer(address token,uint256 tokenId,address target)',
          generic
        )
      ),
      'ExecutionWitness'
    );
    assertEq(
      FulfillmentWitnessLib.FULFILLMENT_WITNESS_TYPEHASH,
      keccak256(
        abi.encodePacked(
          'FulfillmentWitness(address solver,ERC721Approval[] erc721Approvals,GenericCall[] ownerCalls,ValidationParams[] validationParams,address callsSigner,bytes extraData,bytes clientData)',
          'ERC721Approval(address token,uint256 tokenId)',
          generic,
          validation
        )
      ),
      'FulfillmentWitness'
    );
    assertEq(
      SolutionApprovalLib.SOLUTION_APPROVAL_TYPEHASH,
      keccak256(
        abi.encodePacked(
          'SolutionApproval(FulfillmentOrder order,FulfillmentSolution solution)',
          'ERC20Allowance(address token,uint160 amount)',
          'ERC721Approval(address token,uint256 tokenId)',
          'FulfillmentOrder(address owner,address solver,ERC20Allowance[] erc20Allowances,ERC721Approval[] erc721Approvals,ValidationParams[] validationParams,GenericCall[] ownerCalls,address solutionApprover,uint256 nonce,uint256 expiration,bytes extraData,bytes clientData)',
          'FulfillmentSolution(address[] erc20Targets,uint160[] erc20Amounts,address[] erc721Targets,GenericCall[] solverCalls,uint256 nonce,uint256 expiration)',
          generic,
          validation
        )
      ),
      'SolutionApproval'
    );
  }
}
