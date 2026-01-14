// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ERC721Transfer} from './ERC721Transfer.sol';
import {GenericCall} from './GenericCall.sol';

import {ISignatureTransfer} from 'ks-common-sc/src/interfaces/ISignatureTransfer.sol';

/**
 * @notice Witness for a relayer
 * @param relayer The address of the relayer
 * @param genericCalls The generic calls to execute
 */
struct RelayerWitness {
  address relayer;
  address[] targets;
  ERC721Transfer[] erc721Transfers;
  GenericCall[] genericCalls;
}

using RelayerWitnessLibrary for RelayerWitness global;

/// @notice Contains functions for working with RelayerWitness
library RelayerWitnessLibrary {
  string internal constant RELAYER_WITNESS_PERMIT2_TYPE_STRING =
    'RelayerWitness witness)ERC721Transfer(address token,uint256 tokenId,address target)GenericCall(address router,uint256 value,bytes data)RelayerWitness(address relayer,address[] targets,ERC721Transfer[] erc721Transfers,GenericCall[] genericCalls)TokenPermissions(address token,uint256 amount)';

  bytes32 internal constant RELAYER_WITNESS_TYPE_HASH = keccak256(
    'RelayerWitness(address relayer,address[] targets,ERC721Transfer[] erc721Transfers,GenericCall[] genericCalls)ERC721Transfer(address token,uint256 tokenId,address target)GenericCall(address router,uint256 value,bytes data)'
  );

  function hash(
    address relayer,
    address[] memory targets,
    ERC721Transfer[] memory erc721Transfers,
    GenericCall[] memory genericCalls
  ) internal pure returns (bytes32) {
    bytes32[] memory erc721TransfersHashes = new bytes32[](erc721Transfers.length);
    for (uint256 i = 0; i < erc721Transfers.length; i++) {
      erc721TransfersHashes[i] = erc721Transfers[i].hash();
    }

    bytes32[] memory genericCallHashes = new bytes32[](genericCalls.length);
    for (uint256 i = 0; i < genericCalls.length; i++) {
      genericCallHashes[i] = genericCalls[i].hash();
    }

    return keccak256(
      abi.encode(
        RELAYER_WITNESS_TYPE_HASH,
        relayer,
        keccak256(abi.encodePacked(targets)),
        keccak256(abi.encodePacked(erc721TransfersHashes)),
        keccak256(abi.encodePacked(genericCallHashes))
      )
    );
  }

  function hash(RelayerWitness memory self) internal pure returns (bytes32) {
    return hash(self.relayer, self.targets, self.erc721Transfers, self.genericCalls);
  }
}
