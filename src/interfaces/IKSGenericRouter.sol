// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title IKSGenericRouter
 * @notice Generic interface for routers used with the KS Allowance Hub
 */
interface IKSGenericRouter {
  /**
   * @notice Executes the given payload
   * @dev The hub is the caller, so implementations that need the user must read it back from the
   * hub's `msgSender()` rather than from `msg.sender`.
   * @param data The router-specific payload to execute
   * @return The router's return data, surfaced in the hub's `results`
   */
  function ksExecute(bytes calldata data) external payable returns (bytes memory);
}
