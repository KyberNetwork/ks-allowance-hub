// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @notice A 256-bit field read by bit position
 * @dev Position 0 is the least significant bit. A position of 256 or more reads as false.
 */
type PackedBits is bytes32;

using PackedBitsLib for PackedBits global;

library PackedBitsLib {
  /// @dev Whether the bit at `index` is set
  function pos(PackedBits self, uint256 index) internal pure returns (bool bit) {
    assembly ('memory-safe') {
      bit := and(shr(index, self), 0x1)
    }
  }
}
