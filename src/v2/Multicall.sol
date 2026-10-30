// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {NativeSpendGuard} from '../base/NativeSpendGuard.sol';

import {IMulticall} from './interfaces/IMulticall.sol';

import {DynamicArrayLibExt} from './libraries/DynamicArrayLibExt.sol';

import {LowLevelCall} from 'openzeppelin-contracts/contracts/utils/LowLevelCall.sol';

import {DynamicArrayLib} from 'solady/utils/DynamicArrayLib.sol';

/// @title Multicall
/// @notice Runs several calls to this contract in one transaction
abstract contract Multicall is IMulticall, NativeSpendGuard {
  using DynamicArrayLib for *;
  using DynamicArrayLibExt for uint256;

  /// @inheritdoc IMulticall
  function multicall(bytes[] calldata data)
    external
    payable
    guardNativeSpend
    returns (bytes[] memory results, uint256[] memory gasUsages)
  {
    bool success;
    results = data.length.mallocBytes();
    gasUsages = data.length.malloc();

    for (uint256 i = 0; i < data.length; i++) {
      uint256 gasStart = gasleft();

      (success, results[i]) = address(this).delegatecall(data[i]);
      if (!success) {
        LowLevelCall.bubbleRevert(results[i]);
      }

      unchecked {
        gasUsages[i] = gasStart - gasleft();
      }
    }
  }
}
