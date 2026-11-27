// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {AHV2Order} from '../../types/AHV2Order.sol';
import {AHV2Solution} from '../../types/AHV2Solution.sol';

/// @title IAHV2Hook
/// @notice Interface a hook in an order's `hooks` must implement
/// @dev A hook reverts to refuse the order.
interface IAHV2Hook {
  /**
   * @notice Called before any asset moves. On the Permit2 signature transfer flow, the call
   * also precedes Permit2's check of the owner's signature.
   * @param order The order being settled
   * @param orderHash EIP-712 struct hash of `order`
   * @param solution The solution the order settles with
   * @param index Index of the hook's entry in `order.hooks`
   * @return Data passed to {afterSettlement} as `beforeSettlementResult`
   */
  function beforeSettlement(
    AHV2Order calldata order,
    bytes32 orderHash,
    AHV2Solution calldata solution,
    uint256 index
  ) external returns (bytes memory);

  /**
   * @notice Called after the order's calls
   * @param order The order being settled
   * @param orderHash EIP-712 struct hash of `order`
   * @param solution The solution the order settles with
   * @param index Index of the hook's entry in `order.hooks`
   * @param beforeSettlementResult What {beforeSettlement} returned; empty when {AHV2Order-flags}
   * does not select {beforeSettlement} for the hook
   */
  function afterSettlement(
    AHV2Order calldata order,
    bytes32 orderHash,
    AHV2Solution calldata solution,
    uint256 index,
    bytes calldata beforeSettlementResult
  ) external;
}
