// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title IAHV2OwnerCallee
/// @notice Interface a contract must implement to be called with an owner's call by the
/// allowance hub
interface IAHV2OwnerCallee {
  /**
   * @notice Runs one action fixed by the owner, for the account {IMsgSender-msgSender} returns
   * @dev `ownerData` is signed by the owner as part of the order. `solverData` is chosen by the
   * solver, is not signed by the owner, and is covered only by the solution approval when one is
   * required, so a callee treats it as untrusted input within the limits `ownerData` sets.
   * @param ownerData Callee-specific payload signed by the owner
   * @param solverData Callee-specific payload chosen by the solver
   * @return Callee-specific return data, which the hub returns to its caller
   */
  function ownerCall(bytes calldata ownerData, bytes calldata solverData)
    external
    payable
    returns (bytes memory);
}
