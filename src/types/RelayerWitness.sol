// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {GenericCall} from './GenericCall.sol';

/**
 * @notice Witness for a relayer
 * @param relayer The address of the relayer
 * @param genericCalls The generic calls to execute
 */
struct RelayerWitness {
  address relayer;
  address[] targets;
  GenericCall[] genericCalls;
}

using RelayerWitnessLibrary for RelayerWitness global;

/// @notice Contains functions for working with RelayerWitness
library RelayerWitnessLibrary {
  string internal constant RELAYER_WITNESS_PERMIT2_TYPE_STRING =
    'RelayerWitness witness)GenericCall(address router,uint256 value,bytes data)RelayerWitness(address relayer, address[] targets, GenericCall[] genericCalls)TokenPermissions(address token,uint256 amount)';

  bytes32 internal constant RELAYER_WITNESS_TYPE_HASH = keccak256(
    'RelayerWitness(address relayer, address[] targets, GenericCall[] genericCalls)GenericCall(address router,uint256 value,bytes data)'
  );

  function hash(RelayerWitness memory self) internal pure returns (bytes32) {
    bytes32[] memory genericCallHashes = new bytes32[](self.genericCalls.length);
    for (uint256 i = 0; i < self.genericCalls.length; i++) {
      genericCallHashes[i] = self.genericCalls[i].hash();
    }

    return keccak256(
      abi.encode(
        RELAYER_WITNESS_TYPE_HASH,
        self.relayer,
        keccak256(abi.encodePacked(self.targets)),
        keccak256(abi.encodePacked(genericCallHashes))
      )
    );
  }
}
