// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @notice Native value paid to a router, as reported in {IKSAllowanceHubV2-TransferTokens}
 * @param target Router the value is sent to
 * @param amount Native value sent
 */
struct NativeTransfer {
  address target;
  uint256 amount;
}
