// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {PackedBits} from '../base/types/PackedBits.sol';

import {ICallsForwarder} from './interfaces/ICallsForwarder.sol';

import {DynamicArrayLibExt} from './libraries/DynamicArrayLibExt.sol';

import {Common} from 'ks-common-sc/src/base/Common.sol';

import {LowLevelCall} from 'openzeppelin-contracts/contracts/utils/LowLevelCall.sol';

/**
 * @title CallsForwarder
 * @notice Relays calls, so that an approval such as a token permit, a delegation or an
 * authenticator update can run in the same transaction as the order that uses it
 * @dev Any account may relay any call. This contract holds no allowance, role or asset, so a call
 * it makes carries no authority beyond what its own payload proves. No contract may grant this
 * contract any authority.
 */
contract CallsForwarder is ICallsForwarder, Common {
  using DynamicArrayLibExt for uint256;

  /// @inheritdoc ICallsForwarder
  function forwardCalls(address[] calldata targets, bytes[] calldata data, PackedBits allowFailure)
    external
    payable
    checkLengths(targets.length, data.length)
    returns (bytes[] memory results)
  {
    bool success;
    results = targets.length.mallocBytes();

    for (uint256 i = 0; i < targets.length; i++) {
      (success, results[i]) = targets[i].call(data[i]);
      if (!success && !allowFailure.pos(i)) {
        LowLevelCall.bubbleRevert(results[i]);
      }
    }
  }
}
