// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {DynamicArrayLib} from 'solady/utils/DynamicArrayLib.sol';

/**
 * @title DynamicArrayLibExt
 * @notice Allocation of a `bytes[]` without the zeroing that `new` performs, which
 * {DynamicArrayLib} does not provide
 * @dev Only for an array whose every slot is written before anything reads one, since an unwritten
 * slot holds whatever the allocator returned. {DynamicArrayLib} has casts for the word-sized
 * element types but none for `bytes[]`, whose elements are pointers.
 */
library DynamicArrayLibExt {
  /// @dev A `bytes[]` of `length` slots, none of them written
  function malloc(uint256 length) internal pure returns (bytes[] memory array) {
    uint256[] memory buffer = DynamicArrayLib.malloc(length);
    assembly ('memory-safe') {
      array := buffer
    }
  }
}
