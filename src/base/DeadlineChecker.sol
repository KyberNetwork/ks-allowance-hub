// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title DeadlineChecker
/// @notice Rejects calls made after a signed deadline; the deadline block itself still passes
abstract contract DeadlineChecker {
  /// @notice The call arrived after the deadline it carries
  error DeadlinePassed(uint256 currentTime, uint256 deadline);

  modifier checkDeadline(uint256 deadline) {
    _checkDeadline(deadline);
    _;
  }

  /// @dev The check itself, held in one place rather than inlined at every modifier use
  function _checkDeadline(uint256 deadline) internal view {
    if (block.timestamp > deadline) {
      revert DeadlinePassed(block.timestamp, deadline);
    }
  }
}
