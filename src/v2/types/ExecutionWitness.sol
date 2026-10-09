// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ERC721Transfer, ERC721TransferLib} from './ERC721Transfer.sol';

import {GenericCall, GenericCallLib} from './GenericCall.sol';
import {ISignatureTransfer} from 'ks-common-sc/src/interfaces/ISignatureTransfer.sol';
import {DynamicArrayLib} from 'solady/utils/DynamicArrayLib.sol';
import {EfficientHashLib} from 'solady/utils/EfficientHashLib.sol';

/**
 * @notice Attached to the owner's Permit2 signature on a relayed
 * {KSAllowanceHubV2-executeOrderWithPermit2Signature}
 * @dev Fixes everything the permit itself does not: the permit covers only tokens and amounts.
 * @param relayer The account that may submit; the dead-address sentinel permits any caller
 * @param erc20Targets The destination of each ERC20 leg, in order
 * @param erc721Transfers The NFT leg
 * @param genericCalls The exact router calls the owner agreed to
 */
struct ExecutionWitness {
  address relayer;
  address[] erc20Targets;
  ERC721Transfer[] erc721Transfers;
  GenericCall[] genericCalls;
}

/**
 * @notice The type Permit2 hashes on the relayed execution rail
 * @dev Permit2 completes its own stub with the witness type string the hub supplies, and this is
 * the result. Declaring it keeps that string checkable against a struct rather than a
 * transcription. Permit2 names both witness variants alike, so the fulfillment one is declared
 * beside
 * {FulfillmentWitness} and the two never share a file.
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
  ExecutionWitness witness;
}

library ExecutionWitnessLib {
  using ERC721TransferLib for ERC721Transfer[];
  using GenericCallLib for GenericCall[];

  string internal constant EXECUTION_WITNESS_PERMIT2_TYPE_STRING = 'ExecutionWitness witness)'
    'ERC721Transfer(address token,uint256 tokenId,address target)'
    'ExecutionWitness(address relayer,address[] erc20Targets,ERC721Transfer[] erc721Transfers,GenericCall[] genericCalls)'
    'GenericCall(address router,uint256 value,bytes data)'
    'TokenPermissions(address token,uint256 amount)';

  bytes32 internal constant EXECUTION_WITNESS_TYPEHASH = keccak256(
    'ExecutionWitness(address relayer,address[] erc20Targets,ERC721Transfer[] erc721Transfers,GenericCall[] genericCalls)'
    'ERC721Transfer(address token,uint256 tokenId,address target)'
    'GenericCall(address router,uint256 value,bytes data)'
  );

  /// @dev EIP-712 hash of the witness attached to the owner's Permit2 signature
  function hash(
    address relayer,
    address[] memory erc20Targets,
    ERC721Transfer[] calldata erc721Transfers,
    GenericCall[] calldata genericCalls
  ) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(
        EXECUTION_WITNESS_TYPEHASH,
        relayer,
        EfficientHashLib.hash(
          DynamicArrayLib.asBytes32Array(DynamicArrayLib.toUint256Array(erc20Targets))
        ),
        erc721Transfers.hash(),
        genericCalls.hash()
      )
    );
  }

  /// @dev As {hash}, for arrays already in memory
  function hashMemory(
    address relayer,
    address[] memory erc20Targets,
    ERC721Transfer[] memory erc721Transfers,
    GenericCall[] memory genericCalls
  ) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(
        EXECUTION_WITNESS_TYPEHASH,
        relayer,
        EfficientHashLib.hash(
          DynamicArrayLib.asBytes32Array(DynamicArrayLib.toUint256Array(erc20Targets))
        ),
        erc721Transfers.hashMemory(),
        genericCalls.hashMemory()
      )
    );
  }
}
