// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ERC721Transfer, ERC721TransferLibrary} from './ERC721Transfer.sol';
import {GenericCall, GenericCallLibrary} from './GenericCall.sol';

/**
 * @notice Attached to the owner's Permit2 signature on a relayed {KSAllowanceHubV2-transferAndExecute}
 * @dev Pins everything the permit itself does not: who may submit, where the tokens land, the NFT
 * leg and the exact router calls.
 */
struct ExecutionWitness {
  address relayer;
  address[] erc20Targets;
  ERC721Transfer[] erc721Transfers;
  GenericCall[] genericCalls;
}

using ExecutionWitnessLibrary for ExecutionWitness global;

library ExecutionWitnessLibrary {
  using ERC721TransferLibrary for ERC721Transfer[];
  using GenericCallLibrary for GenericCall[];

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
        keccak256(abi.encodePacked(erc20Targets)),
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
        keccak256(abi.encodePacked(erc20Targets)),
        erc721Transfers.hashMemory(),
        genericCalls.hashMemory()
      )
    );
  }
}
