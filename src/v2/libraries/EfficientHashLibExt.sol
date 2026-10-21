// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {DynamicArrayLib} from 'solady/utils/DynamicArrayLib.sol';
import {EfficientHashLib} from 'solady/utils/EfficientHashLib.sol';

/// @title EfficientHashLibExt
/// @notice EIP-712 encoding of an `address[]` member, which {EfficientHashLib} does not provide
library EfficientHashLibExt {
  using DynamicArrayLib for *;
  using EfficientHashLib for *;

  /// @dev EIP-712 hash of the array, taken over its calldata words viewed as `bytes`
  function hash(address[] calldata addresses) internal pure returns (bytes32) {
    bytes calldata words;
    assembly ('memory-safe') {
      words.offset := addresses.offset
      words.length := shl(5, addresses.length)
    }
    return words.hashCalldata();
  }

  /// @dev As {hash}, for an array already in memory, whose words are hashed where they lie
  function hashMemory(address[] memory addresses) internal pure returns (bytes32) {
    return addresses.toUint256Array().asBytes32Array().hash();
  }
}
