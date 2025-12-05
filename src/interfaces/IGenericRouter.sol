// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title IGenericRouter
/// @notice Generic interface for routers used by KyberSwap
interface IGenericRouter {
  /// @notice Executes with given data
  function execute(bytes calldata data) external payable returns (bytes memory);
}
