// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {PackedBits} from '../types/PackedBits.sol';

/// @title ICallsForwarder
/// @notice Interface of {CallsForwarder}
interface ICallsForwarder {
  /**
   * @notice The payload's selector is not one this contract will relay
   * @param selector The refused selector, read from the first four bytes of the payload
   */
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
