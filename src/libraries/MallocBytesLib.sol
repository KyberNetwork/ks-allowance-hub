// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {EfficientHashLib} from 'solady/utils/EfficientHashLib.sol';

/// @title MallocBytesLib
/// @notice Allocates a `bytes[]` without zeroing its elements
library MallocBytesLib {
  /// @dev A `bytes[]` of `length` unwritten elements; the caller writes each before reading it
  function mallocBytes(uint256 length) internal pure returns (bytes[] memory array) {
    bytes32[] memory buffer = EfficientHashLib.malloc(length);
    assembly ('memory-safe') {
      array := buffer
    }
  }
}
