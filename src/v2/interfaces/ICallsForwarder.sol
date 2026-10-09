// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {PackedBits} from '../../base/types/PackedBits.sol';

/// @title ICallsForwarder
/// @notice Interface of {CallsForwarder}
interface ICallsForwarder {
  /// @notice The payload's selector is not one this contract will relay
  error NotSupportedSelector(bytes4 selector);

  /**
   * @notice Relays a batch of calls that carry their own authorisation
   * @param targets Contract to call for each entry
   * @param data The call to make against the matching target
   * @param allowFailure One bit per entry: set to continue when that call reverts
   * @return results Each call's return data, in order
   */
  function forwardCalls(address[] calldata targets, bytes[] calldata data, PackedBits allowFailure)
    external
    payable
    returns (bytes[] memory results);

  /**
   * @notice Runs several of this contract's own calls in one transaction
   * @dev Each entry is `delegatecall`ed, so every one sees the whole `msg.value`; the native-spend
   * guard bounds the batch rather than refusing value outright.
   * @param data One ABI-encoded call to this contract per entry
   * @return results Each call's return data, in order
   * @return gasUsages Gas spent inside each call, in order
   */
  function multicall(bytes[] calldata data)
    external
    payable
    returns (bytes[] memory results, uint256[] memory gasUsages);
}
