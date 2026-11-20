// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {EfficientHashLib} from 'solady/utils/EfficientHashLib.sol';

/// @title EfficientHashLibExt
/// @notice EIP-712 hashing of an `address[]`, `uint160[]`, `uint256[]` or `bytes[]` member, which
/// {EfficientHashLib} does not provide
library EfficientHashLibExt {
  using EfficientHashLib for *;

  /// @dev EIP-712 hash of the array: the hash of its elements as 32-byte words
  function hash(address[] calldata addresses) internal pure returns (bytes32) {
    bytes calldata words;
    assembly ('memory-safe') {
      words.offset := addresses.offset
      words.length := shl(5, addresses.length)
    }
    return words.hashCalldata();
  }

  /// @dev EIP-712 hash of the array: the hash of its elements as 32-byte words
  function hash(uint160[] calldata values) internal pure returns (bytes32) {
    bytes calldata words;
    assembly ('memory-safe') {
      words.offset := values.offset
      words.length := shl(5, values.length)
    }
    return words.hashCalldata();
  }

  /// @dev EIP-712 hash of the array: the hash of its elements as 32-byte words
  function hash(uint256[] calldata values) internal pure returns (bytes32) {
    bytes calldata words;
    assembly ('memory-safe') {
      words.offset := values.offset
      words.length := shl(5, values.length)
    }
    return words.hashCalldata();
  }

  /// @dev EIP-712 hash of the array: its elements' hashes, concatenated and hashed
  function hash(bytes[] calldata values) internal pure returns (bytes32) {
    bytes32[] memory valueHashes = EfficientHashLib.malloc(values.length);
    for (uint256 i = 0; i < values.length; i++) {
      valueHashes[i] = values[i].hashCalldata();
    }

    return EfficientHashLib.hash(valueHashes);
  }
}
