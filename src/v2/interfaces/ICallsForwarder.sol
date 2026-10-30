// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {PackedBits} from '../../base/types/PackedBits.sol';

/// @title ICallsForwarder
/// @notice Interface of {CallsForwarder}
interface ICallsForwarder {
  /**
   * @notice Calls each target with its payload
   * @dev Each target sees this contract as `msg.sender`. Native value sent with the call is not
   * forwarded and remains in this contract.
   * @param targets Contract to call for each entry
   * @param data Payload for the target at the same index
   * @param allowFailure One bit per entry; when an entry's bit is set, its revert is ignored and
   * the batch continues
   * @return results Return data of each call, in order
   */
  function forwardCalls(address[] calldata targets, bytes[] calldata data, PackedBits allowFailure)
    external
    payable
    returns (bytes[] memory results);
}
