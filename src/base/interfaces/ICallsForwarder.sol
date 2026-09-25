// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {PackedBits} from '../types/PackedBits.sol';

/// @title ICallsForwarder
/// @notice Interface of {CallsForwarder}
interface ICallsForwarder {
  error NotSupportedSelector(bytes4 selector);

  /**
   * @notice Relays a batch of calls that carry their own authorisation
   * @param targets Contract to call for each entry
   * @param data The call to make against the matching target
   * @param allowFailure One bit per entry: set to carry on when that call reverts
   * @return results Each call's return data, in order
   */
  function forward(address[] calldata targets, bytes[] calldata data, PackedBits allowFailure)
    external
    payable
    returns (bytes[] memory results);
}
