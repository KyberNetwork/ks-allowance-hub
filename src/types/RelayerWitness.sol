// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ERC721Params} from './ERC721Params.sol';
import {GenericCall} from './GenericCall.sol';

/**
 * @notice Witness for a relayer
 * @param relayer The address of the relayer
 * @param genericCalls The generic calls to execute
 */
struct RelayerWitness {
  address relayer;
  address[] targets;
  ERC721Params[] erc721Params;
  GenericCall[] genericCalls;
}

using RelayerWitnessLibrary for RelayerWitness global;

/// @notice Contains functions for working with RelayerWitness
library RelayerWitnessLibrary {
  string internal constant RELAYER_WITNESS_PERMIT2_TYPE_STRING =
    'RelayerWitness witness)ERC721Params(address token,uint256 tokenId,address target,bytes permitData)GenericCall(address router,uint256 value,bytes data)RelayerWitness(address relayer,address[] targets,ERC721Params[] erc721Params,GenericCall[] genericCalls)TokenPermissions(address token,uint256 amount)';

  bytes32 internal constant RELAYER_WITNESS_TYPE_HASH = keccak256(
    'RelayerWitness(address relayer,address[] targets,ERC721Params[] erc721Params,GenericCall[] genericCalls)ERC721Params(address token,uint256 tokenId,address target,bytes permitData)GenericCall(address router,uint256 value,bytes data)'
  );

  function hash(
    address relayer,
    address[] calldata targets,
    ERC721Params[] calldata erc721Params,
    GenericCall[] calldata genericCalls
  ) internal pure returns (bytes32) {
    bytes32[] memory erc721ParamsHashes = new bytes32[](erc721Params.length);
    for (uint256 i = 0; i < erc721Params.length; i++) {
      erc721ParamsHashes[i] = erc721Params[i].hash();
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
        keccak256(abi.encodePacked(erc721ParamsHashes)),
        keccak256(abi.encodePacked(genericCallHashes))
      )
    );
  }

  function hash(RelayerWitness calldata self) internal pure returns (bytes32) {
    return hash(self.relayer, self.targets, self.erc721Params, self.genericCalls);
  }
}
