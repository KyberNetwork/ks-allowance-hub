// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {DynamicArrayLib} from 'solady/utils/DynamicArrayLib.sol';

/**
 * @title DynamicArrayLibExt
 * @notice What {DynamicArrayLib} does not cover: allocating a `bytes[]` without the zeroing `new`
 * performs
 * @dev Only for an array whose every slot is written before anything reads one, since a slot left
 * alone holds whatever the allocator handed over. {DynamicArrayLib} has casts for the word-sized
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
