// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {EfficientHashLibExt} from '../libraries/EfficientHashLibExt.sol';

import {ERC721Transfer, ERC721TransferLib} from './ERC721Transfer.sol';
import {GenericCall, GenericCallLib} from './GenericCall.sol';

import {ISignatureTransfer} from 'ks-common-sc/src/interfaces/ISignatureTransfer.sol';

import {EfficientHashLib} from 'solady/utils/EfficientHashLib.sol';

/**
 * @notice Witness the owner's Permit2 signature covers when another account submits
 * {KSAllowanceHubV2-executeOrderWithPermit2Signature}
 * @dev Covers the parts of the order the permit does not; the permit covers the ERC20 tokens and
 * amounts.
 * @param relayer Account that may submit the order; the dead address allows any account
 * @param erc20Targets Target of each ERC20 transfer, in order
 * @param erc721Transfers ERC721 transfers
 * @param genericCalls Router calls
 * @param extraData The order's extra data
 * @param clientData The order's client data
 */
struct ExecutionWitness {
  address relayer;
  address[] erc20Targets;
  ERC721Transfer[] erc721Transfers;
  GenericCall[] genericCalls;
  bytes extraData;
  bytes clientData;
}

/**
 * @notice The struct Permit2 hashes for an execution order's witness permit
 * @dev Declared so that the witness type string the hub passes to Permit2 can be checked against a
 * struct. The fulfillment variant has the same name and is declared beside {FulfillmentWitness}.
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
  ExecutionWitness witness;
}

library ExecutionWitnessLib {
  using EfficientHashLib for bytes;
  using EfficientHashLibExt for address[];
  using ERC721TransferLib for ERC721Transfer[];
  using GenericCallLib for GenericCall[];

  string internal constant EXECUTION_WITNESS_PERMIT2_TYPE_STRING = 'ExecutionWitness witness)'
    'ERC721Transfer(address token,uint256 tokenId,address target)'
    'ExecutionWitness(address relayer,address[] erc20Targets,ERC721Transfer[] erc721Transfers,GenericCall[] genericCalls,bytes extraData,bytes clientData)'
    'GenericCall(address router,uint256 value,bytes data)'
    'TokenPermissions(address token,uint256 amount)';

  bytes32 internal constant EXECUTION_WITNESS_TYPEHASH = keccak256(
    'ExecutionWitness(address relayer,address[] erc20Targets,ERC721Transfer[] erc721Transfers,GenericCall[] genericCalls,bytes extraData,bytes clientData)'
    'ERC721Transfer(address token,uint256 tokenId,address target)'
    'GenericCall(address router,uint256 value,bytes data)'
  );

  /// @dev EIP-712 hash of the witness
  function hash(
    address relayer,
    bytes32 erc20TargetsHash,
    ERC721Transfer[] calldata erc721Transfers,
    GenericCall[] calldata genericCalls,
    bytes calldata extraData,
    bytes calldata clientData
  ) internal pure returns (bytes32) {
    return hash(
      relayer,
      erc20TargetsHash,
      erc721Transfers.hash(),
      genericCalls.hash(),
      extraData.hashCalldata(),
      clientData.hashCalldata()
    );
  }

  /// @dev As {hash}, from the already computed hashes of the array and bytes members
  function hash(
    address relayer,
    bytes32 erc20TargetsHash,
    bytes32 erc721TransfersHash,
    bytes32 genericCallsHash,
    bytes32 extraDataHash,
    bytes32 clientDataHash
  ) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(
        EXECUTION_WITNESS_TYPEHASH,
        relayer,
        erc20TargetsHash,
        erc721TransfersHash,
        genericCallsHash,
        extraDataHash,
        clientDataHash
      )
    );
  }

  /// @dev As {hash}, for arrays already in memory
  function hashMemory(
    address relayer,
    address[] memory erc20Targets,
    ERC721Transfer[] memory erc721Transfers,
    GenericCall[] memory genericCalls,
    bytes memory extraData,
    bytes memory clientData
  ) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(
        EXECUTION_WITNESS_TYPEHASH,
        relayer,
        erc20Targets.hashMemory(),
        erc721Transfers.hashMemory(),
        genericCalls.hashMemory(),
        keccak256(extraData),
        keccak256(clientData)
      )
    );
  }
}
