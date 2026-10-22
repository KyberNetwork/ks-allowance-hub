// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title IMsgSender
/// @notice Interface of {MsgSender}
interface IMsgSender {
  /// @notice A locked call was made while another was in progress
  error AlreadyLocked(address locker);

  /**
   * @notice The account the current locked call is acting for
   * @return The owner of the order being settled, or the zero address outside a locked call
   */
  function msgSender() external view returns (address);
}
