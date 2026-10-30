// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title IKSGenericRouter
/// @notice Interface every whitelisted router must implement to be callable by the allowance hub
interface IKSGenericRouter {
  /**
   * @notice Runs one router action for the account the hub's {IMsgSender-msgSender} returns
   * @param data Router-specific payload
   * @return Router-specific return data, which the hub returns to its caller
   */
  function ksExecute(bytes calldata data) external payable returns (bytes memory);
}
