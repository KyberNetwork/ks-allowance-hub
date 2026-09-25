// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @notice A bitfield carried in one word, read by position
 * @dev Only the low 256 positions exist; anything above reads as false. Kept as `bytes32` rather
 * than `uint256`: the hub sits on the IR stack limit, and the numeric type tips it over.
 */
type PackedBits is bytes32;

using PackedBitsLibrary for PackedBits global;

library PackedBitsLibrary {
  /// @dev The bit at `index`, masked so the result is a canonical bool
  function pos(PackedBits self, uint256 index) internal pure returns (bool bit) {
    assembly ('memory-safe') {
      bit := and(shr(index, self), 0x1)
    }
  }
}
