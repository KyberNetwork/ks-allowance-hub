// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {RouterParams} from '../types/RouterParams.sol';

import {ISignatureTransfer} from 'ks-common-sc/src/interfaces/ISignatureTransfer.sol';

/// @title IKSUniversalRouter
/// @notice Interface for the KSUniversalRouter
interface IKSUniversalRouter {
  /// @notice Thrown when the deadline is passed
  error DeadlinePassed(uint256 deadline, uint256 blockTimestamp);

  /**
   * @notice Collects tokens and executes calls with the executors
   * @param params The parameters for the execution
   * @return results The results of the execution of the calls
   */
  function execute(RouterParams calldata params) external payable returns (bytes[] memory results);

  /// @notice Returns the address of the permit2 contract
  function PERMIT2() external view returns (ISignatureTransfer);
}
