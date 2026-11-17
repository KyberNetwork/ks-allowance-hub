// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title IAHV2SolverCallee
/// @notice Interface a contract must implement to be called with a solver's call by the
/// allowance hub
interface IAHV2SolverCallee {
  /**
   * @notice Runs one action chosen by the solver, for the account {IMsgSender-msgSender} returns
   * @param data Callee-specific payload
   * @return Callee-specific return data, which the hub returns to its caller
   */
  function solverCall(bytes calldata data) external payable returns (bytes memory);
}
