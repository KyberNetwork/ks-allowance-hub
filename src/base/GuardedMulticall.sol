// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {NativeSpendGuard} from './NativeSpendGuard.sol';

import {Multicallable} from 'solady/utils/Multicallable.sol';

/**
 * @title GuardedMulticall
 * @notice Batches calls the way Solady does, but accepts value: every sub-call is a delegatecall
 * and therefore sees the same `msg.value` although it arrived once, so the batch is bounded as a
 * whole instead of refusing value outright.
 */
abstract contract GuardedMulticall is Multicallable, NativeSpendGuard {
  /**
   * @notice Runs several of this contract's own calls in one transaction
   * @param data One ABI-encoded call to this contract per entry
   * @return results Each call's return data, in order
   */
  function multicall(bytes[] calldata data)
    public
    payable
    override
    guardNativeSpend
    returns (bytes[] memory results)
  {
    // Returns normally rather than Solady's direct return, so the guard still runs afterwards
    return _multicallResultsToBytesArray(_multicall(data));
  }
}
