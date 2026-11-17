// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @notice Native value paid to a callee, as reported in {IKSAllowanceHubV2-TransferTokens}
 * @param target Callee the value is sent to
 * @param amount Native value sent
 */
struct NativeTransfer {
  address target;
  uint256 amount;
}
