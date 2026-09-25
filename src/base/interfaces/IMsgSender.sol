// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title IMsgSender
/// @notice Interface of {MsgSender}
interface IMsgSender {
  error AlreadyLocked();

  /// @notice The owner the current call is acting for, or the zero address outside a locked call
  function msgSender() external view returns (address);
}
