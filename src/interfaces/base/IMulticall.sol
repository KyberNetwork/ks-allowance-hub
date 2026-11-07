// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title IMulticall
/// @notice Interface of {Multicall}
interface IMulticall {
  /**
   * @notice Runs several calls to this contract in one transaction
   * @dev A revert in any entry reverts the batch.
   * @param data ABI-encoded calls to this contract
   * @return results Return data of each call, in order
   * @return gasUsages Gas used by each call, in order
   */
  function multicall(bytes[] calldata data)
    external
    payable
    returns (bytes[] memory results, uint256[] memory gasUsages);
}
