// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title IAHV2Callee
/// @notice Interface a contract must implement to be called by the allowance hub
interface IAHV2Callee {
  /**
   * @notice Runs one action for the account {IMsgSender-msgSender} returns
   * @dev `ownerData` is empty for a solver's call. `solverData` is not signed by the owner, so a
   * callee must treat it as untrusted input within the limits `ownerData` sets.
   * @param ownerData Callee-specific payload signed by the owner; empty for a solver's call
   * @param solverData Callee-specific payload chosen by the solver
   * @return Callee-specific return data, which the hub returns to its caller
   */
  function execute(bytes calldata ownerData, bytes calldata solverData)
    external
    payable
    returns (bytes memory);
}
