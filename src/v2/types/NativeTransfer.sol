// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @notice Event-only record of native paid to a router; never an input
struct NativeTransfer {
  address target;
  uint256 amount;
}
