// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title NativeSpendGuard
/// @notice Caps how much native a call may spend at the value it was sent
abstract contract NativeSpendGuard {
  /// @notice The call spent more native than it was sent, dipping into the contract's own
  error NativeOverSpent();

  /**
   * @dev `balanceBefore` already includes `msg.value`, so the check reduces to "the balance held
   * before the call is still there", which protects any native the contract already had.
   */
  modifier guardNativeSpend() {
    uint256 balanceBefore = address(this).balance;
    _;
    if (address(this).balance + msg.value < balanceBefore) {
      revert NativeOverSpent();
    }
  }
}
