// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ERC721Approval, ERC721ApprovalLib} from './ERC721Approval.sol';
import {GenericCall, GenericCallLib} from './GenericCall.sol';
import {ValidationParams, ValidationParamsLib} from './ValidationParams.sol';

import {ISignatureTransfer} from 'ks-common-sc/src/interfaces/ISignatureTransfer.sol';

/**
 * @notice Attached to the owner's Permit2 signature on a relayed
 * {KSAllowanceHubV2-fulfillOrderWithPermit2Signature}
 * @dev Does not fix the solver's route or where the legs go; it names who may choose them and the
 * validators that bound the result instead. The ERC20 legs are the permit's own tokens and amounts.
 * @param solver The account that may submit; the dead-address sentinel permits any caller
 * @param erc721Approvals The NFT legs
 * @param ownerCalls The tail the owner fixes exactly, for effects no validator can check
 * @param validationParams The validators that bound the solver's route
 * @param callsSigner The account that may approve that route
 */
struct FulfillmentWitness {
  address solver;
  ERC721Approval[] erc721Approvals;
  GenericCall[] ownerCalls;
  ValidationParams[] validationParams;
  address callsSigner;
}

/**
 * @notice The type Permit2 hashes on the relayed fulfillment rail
 * @dev The fulfillment counterpart of the declaration beside {ExecutionWitness}, which says why
 * both exist and why they cannot share a file.
 * @param permitted Tokens and amounts the permit covers
 * @param spender The account that may transfer them
 * @param nonce Permit2's own nonce
 * @param deadline Last timestamp at which the permit may be used
 * @param witness The order, bound to the signature
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

  /// @dev EIP-712 hash of the witness attached to the owner's Permit2 signature
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
