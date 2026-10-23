// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {PackedBits} from '../../base/types/PackedBits.sol';

/// @title ICallsForwarder
/// @notice Interface of {CallsForwarder}
interface ICallsForwarder {
  /// @notice The entry at `index` has a selector that is not allowed
  error UnsupportedSelector(uint256 index, bytes4 selector);

  /**
   * @notice Calls each target with its payload, provided the payload's selector is allowed
   * @dev The allowed selectors are Permit2's two `permit` overloads, ERC-2612 `permit`, the
   * DAI-style `permit`, the two ERC-721 `permit` variants, {IAuthDelegator-updateDelegation} and
   * {IOrderAuthenticator-updateAuthentication}. Each target sees this contract as `msg.sender`.
   * Native value sent with the call is not forwarded and remains in this contract. The call is
   * accepted while the hub is paused.
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

  /**
   * @notice Runs several calls to this contract in one transaction
   * @dev Each entry is run with `delegatecall`, so it keeps the original `msg.sender` and
   * `msg.value`. The native value spent by the whole batch is limited to `msg.value`. A revert in
   * any entry reverts the batch.
   * @param data ABI-encoded calls to this contract
   * @return results Return data of each call, in order
   * @return gasUsages Gas used by each call, in order
   */
  function multicall(bytes[] calldata data)
    external
    payable
    returns (bytes[] memory results, uint256[] memory gasUsages);
}
