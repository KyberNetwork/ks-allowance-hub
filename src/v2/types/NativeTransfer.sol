// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @notice Native value paid to a router, as reported in {IKSAllowanceHubV2-TransferTokens}
struct NativeTransfer {
  address target;
  uint256 amount;
}
