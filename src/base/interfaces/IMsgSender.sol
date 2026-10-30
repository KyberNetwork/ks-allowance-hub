// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title IMsgSender
/// @notice Interface of {MsgSender}
interface IMsgSender {
  /// @notice {msgSender} was set while the lock was held
  error AlreadyLocked(address sender);

  /**
   * @notice The account the current call is acting for
   * @return The owner of the innermost order being settled, or the zero address when no order is
   * being settled
   */
  function msgSender() external view returns (address);
}
