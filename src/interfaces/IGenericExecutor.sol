// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title IGenericExecutor
/// @notice Generic interface for executors to be called by the router
interface IGenericExecutor {
  /// @notice Executes with given data
  function execute(bytes calldata data) external payable returns (bytes memory);
}
