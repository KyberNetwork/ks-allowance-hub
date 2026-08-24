// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ERC721Transfer} from './ERC721Transfer.sol';
import {GenericCall} from './GenericCall.sol';

/**
 * @notice The extra data an owner signs when a relayer spends their tokens, pinning both the
 * relayer's identity and the exact execution it is allowed to perform
 * @param relayer The address allowed to submit the signature, or `ANY_ADDRESS` for anyone
 * @param targets The addresses the permitted ERC20 tokens must be transferred to
 * @param erc721Transfers The ERC721 movements the relayer is allowed to perform
 * @param genericCalls The exact calls the relayer is allowed to execute
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
  /// @dev The Permit2 witness type string, with the referenced structs sorted alphabetically
  string internal constant RELAYER_WITNESS_PERMIT2_TYPE_STRING =
    'RelayerWitness witness)ERC721Transfer(address token,uint256 tokenId,address target)GenericCall(address router,uint256 value,bytes data)RelayerWitness(address relayer,address[] targets,ERC721Transfer[] erc721Transfers,GenericCall[] genericCalls)TokenPermissions(address token,uint256 amount)';

  /// @dev The EIP-712 type hash of `RelayerWitness`, including its referenced struct definitions
  bytes32 internal constant RELAYER_WITNESS_TYPEHASH = keccak256(
    'RelayerWitness(address relayer,address[] targets,ERC721Transfer[] erc721Transfers,GenericCall[] genericCalls)ERC721Transfer(address token,uint256 tokenId,address target)GenericCall(address router,uint256 value,bytes data)'
  );

  /**
   * @notice Hashes the witness fields following EIP-712 struct encoding
   * @dev Takes the fields loose rather than as a struct so callers can hash what they already hold
   * without copying it into one.
   * @param relayer The address allowed to submit the signature, or `ANY_ADDRESS` for anyone
   * @param targets The addresses the permitted ERC20 tokens must be transferred to
   * @param erc721Transfers The ERC721 movements the relayer is allowed to perform
   * @param genericCalls The exact calls the relayer is allowed to execute
   * @return The EIP-712 hash of the witness
   */
  function hash(
    address relayer,
    address[] memory targets,
    ERC721Transfer[] memory erc721Transfers,
    GenericCall[] memory genericCalls
  ) internal pure returns (bytes32) {
    // EIP-712 encodes an array of structs as the hash of its concatenated member hashes
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
        RELAYER_WITNESS_TYPEHASH,
        relayer,
        keccak256(abi.encodePacked(targets)),
        keccak256(abi.encodePacked(erc721TransfersHashes)),
        keccak256(abi.encodePacked(genericCallHashes))
      )
    );
  }

  /**
   * @notice Hashes a witness following EIP-712 struct encoding
   * @param self The witness to hash
   * @return The EIP-712 hash of the witness
   */
  function hash(RelayerWitness memory self) internal pure returns (bytes32) {
    return hash(self.relayer, self.targets, self.erc721Transfers, self.genericCalls);
  }
}
