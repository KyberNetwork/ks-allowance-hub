// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title NativeSpendGuard
/// @notice Limits the native value a call may spend to the value it was sent
abstract contract NativeSpendGuard {
  /// @notice The call spent more native value than it was sent
  error NativeOverspent(uint256 spent, uint256 value);

  /**
   * @dev Reverts when the balance after the call is less than the balance before it minus
   * `msg.value`. `balanceBefore` already includes `msg.value`.
   */
  modifier guardNativeSpend() {
    uint256 balanceBefore = address(this).balance;
    _;
    if (address(this).balance + msg.value < balanceBefore) {
      revert NativeOverspent(balanceBefore - address(this).balance, msg.value);
    }
  }
}
