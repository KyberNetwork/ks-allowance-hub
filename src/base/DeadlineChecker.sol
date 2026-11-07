// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title DeadlineChecker
/// @notice Rejects calls made after a deadline; a call at the deadline is accepted
abstract contract DeadlineChecker {
  /// @notice The deadline has passed
  error DeadlinePassed(uint256 deadline, uint256 currentTime);

  modifier checkDeadline(uint256 deadline) {
    _checkDeadline(deadline);
    _;
  }

  /// @dev Reverts when the current block timestamp is later than `deadline`
  function _checkDeadline(uint256 deadline) internal view {
    if (block.timestamp > deadline) {
      revert DeadlinePassed(deadline, block.timestamp);
    }
  }
}
