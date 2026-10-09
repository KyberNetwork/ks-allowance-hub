// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title NativeSpendGuard
/// @notice Limits the native value a call may spend to the value it was sent
abstract contract NativeSpendGuard {
  /// @notice The call spent more native value than it was sent, drawing on the contract's own
  error NativeOverSpent();

  /**
   * @dev `balanceBefore` already includes `msg.value`, so the check reduces to confirming that
   * the balance held before the call is intact, which protects any native value already held.
   */
  modifier guardNativeSpend() {
    uint256 balanceBefore = address(this).balance;
    _;
    if (address(this).balance + msg.value < balanceBefore) {
      revert NativeOverSpent();
    }
  }
}
