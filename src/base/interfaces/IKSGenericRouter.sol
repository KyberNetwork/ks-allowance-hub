// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title IKSGenericRouter
/// @notice Interface every whitelisted router must implement to be callable by the allowance hub
interface IKSGenericRouter {
  /**
   * @notice Runs one router action on behalf of the hub's current `msgSender()`
   * @param data Router-specific payload
   * @return The router's own return data, handed back to the hub's caller
   */
  function ksExecute(bytes calldata data) external payable returns (bytes memory);
}
