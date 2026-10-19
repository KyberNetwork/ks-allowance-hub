// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title DeadlineChecker
/// @notice Rejects calls made after a signed deadline; the deadline itself remains valid
abstract contract DeadlineChecker {
  /// @notice The call arrived after the deadline it carries
  error DeadlinePassed(uint256 deadline, uint256 currentTime);

  modifier checkDeadline(uint256 deadline) {
    _checkDeadline(deadline);
    _;
  }

  /// @dev Held in one place rather than inlined at every use of the modifier
  function _checkDeadline(uint256 deadline) internal view {
    if (block.timestamp > deadline) {
      revert DeadlinePassed(deadline, block.timestamp);
    }
  }
}
