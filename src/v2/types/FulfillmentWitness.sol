// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ERC721Approval, ERC721ApprovalLib} from './ERC721Approval.sol';
import {GenericCall, GenericCallLib} from './GenericCall.sol';
import {ValidationParams, ValidationParamsLib} from './ValidationParams.sol';

import {ISignatureTransfer} from 'ks-common-sc/src/interfaces/ISignatureTransfer.sol';

/**
 * @notice Witness the owner's Permit2 signature covers when another account submits
 * {KSAllowanceHubV2-fulfillOrderWithPermit2Signature}
 * @dev Covers the parts of the order the permit does not; the permit covers the ERC20 tokens and
 * amounts. The route and the leg targets are not covered; the witness names the solver, the
 * validators and the solution approver instead.
 * @param solver Account that may submit the order; the dead address allows any account
 * @param erc721Approvals ERC721 legs
 * @param ownerCalls Router calls fixed by the owner
 * @param validationParams Validators of the solution's result
 * @param callsSigner Account whose signature the solution requires; the dead address requires none
 */
struct FulfillmentWitness {
  address solver;
  ERC721Approval[] erc721Approvals;
  GenericCall[] ownerCalls;
  ValidationParams[] validationParams;
  address callsSigner;
}

/**
 * @notice The struct Permit2 hashes for a fulfillment order's witness permit
 * @dev The execution variant has the same name and is declared beside {ExecutionWitness}.
 * @param permitted Tokens and amounts the permit covers
 * @param spender Account that may transfer them
 * @param nonce Permit2 nonce
 * @param deadline Last timestamp at which the permit may be used
 * @param witness The order's witness
 */
struct PermitBatchWitnessTransferFrom {
  ISignatureTransfer.TokenPermissions[] permitted;
  address spender;
  uint256 nonce;
  uint256 deadline;
  FulfillmentWitness witness;
}

library FulfillmentWitnessLib {
  using ERC721ApprovalLib for ERC721Approval[];
  using GenericCallLib for GenericCall[];
  using ValidationParamsLib for ValidationParams[];

  string internal constant FULFILLMENT_WITNESS_PERMIT2_TYPE_STRING = 'FulfillmentWitness witness)'
    'ERC721Approval(address token,uint256 tokenId)'
    'FulfillmentWitness(address solver,ERC721Approval[] erc721Approvals,GenericCall[] ownerCalls,ValidationParams[] validationParams,address callsSigner)'
    'GenericCall(address router,uint256 value,bytes data)'
    'TokenPermissions(address token,uint256 amount)'
    'ValidationParams(address validator,bytes32 action,bytes beforeExecutionInput,bytes afterExecutionInput)';

  bytes32 internal constant FULFILLMENT_WITNESS_TYPEHASH = keccak256(
    'FulfillmentWitness(address solver,ERC721Approval[] erc721Approvals,GenericCall[] ownerCalls,ValidationParams[] validationParams,address callsSigner)'
    'ERC721Approval(address token,uint256 tokenId)'
    'GenericCall(address router,uint256 value,bytes data)'
    'ValidationParams(address validator,bytes32 action,bytes beforeExecutionInput,bytes afterExecutionInput)'
  );

  /// @dev EIP-712 hash of the witness
  function hash(
    address solver,
    ERC721Approval[] calldata erc721Approvals,
    GenericCall[] calldata ownerCalls,
    ValidationParams[] calldata validationParams,
    address callsSigner
  ) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(
        FULFILLMENT_WITNESS_TYPEHASH,
        solver,
        erc721Approvals.hash(),
        ownerCalls.hash(),
        validationParams.hash(),
        callsSigner
      )
    );
  }

  /// @dev As {hash}, for arrays already in memory
  function hashMemory(
    address solver,
    ERC721Approval[] memory erc721Approvals,
    GenericCall[] memory ownerCalls,
    ValidationParams[] memory validationParams,
    address callsSigner
  ) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(
        FULFILLMENT_WITNESS_TYPEHASH,
        solver,
        erc721Approvals.hashMemory(),
        ownerCalls.hashMemory(),
        validationParams.hashMemory(),
        callsSigner
      )
    );
  }
}
