// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {NativeSpendGuard} from '../base/NativeSpendGuard.sol';

import {PackedBits} from '../base/types/PackedBits.sol';

import {IAuthDelegator} from './interfaces/IAuthDelegator.sol';
import {ICallsForwarder} from './interfaces/ICallsForwarder.sol';
import {IOrderAuthenticator} from './interfaces/IOrderAuthenticator.sol';

import {DynamicArrayLibExt} from './libraries/DynamicArrayLibExt.sol';

import {Common} from 'ks-common-sc/src/base/Common.sol';

import {IDaiLikePermit} from 'ks-common-sc/src/interfaces/IDaiLikePermit.sol';
import {IERC721Permit_v3} from 'ks-common-sc/src/interfaces/IERC721Permit_v3.sol';
import {IERC721Permit_v4} from 'ks-common-sc/src/interfaces/IERC721Permit_v4.sol';

import {
  IERC20Permit
} from 'openzeppelin-contracts/contracts/token/ERC20/extensions/IERC20Permit.sol';

import {LowLevelCall} from 'openzeppelin-contracts/contracts/utils/LowLevelCall.sol';

import {DynamicArrayLib} from 'solady/utils/DynamicArrayLib.sol';

/**
 * @title CallsForwarder
 * @notice Relays calls that carry their own authorisation, such as token permits, delegations and
 * authenticator updates, so that an approval and the order that uses it can run in one
 * transaction
 * @dev Any account may relay any call whose selector is allowed. Every target sees this contract as
 * `msg.sender`, so only calls authorised by a signature in their own payload are allowed.
 */
abstract contract CallsForwarder is ICallsForwarder, NativeSpendGuard, Common {
  using DynamicArrayLib for *;
  using DynamicArrayLibExt for uint256;

  /// @dev Selectors of Permit2's two `permit` overloads
  bytes4 internal constant PERMIT2_PERMIT_SINGLE_SELECTOR =
    bytes4(keccak256('permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)'));

  bytes4 internal constant PERMIT2_PERMIT_BATCH_SELECTOR =
    bytes4(keccak256('permit(address,((address,uint160,uint48,uint48)[],address,uint256),bytes)'));

  /**
   * @inheritdoc ICallsForwarder
   * @dev Has no reentrancy lock: a relayed call may enter this contract's other entry points.
   */
  function forwardCalls(address[] calldata targets, bytes[] calldata data, PackedBits allowFailure)
    external
    payable
    checkLengths(targets.length, data.length)
    returns (bytes[] memory results)
  {
    bool success;
    results = targets.length.mallocBytes();

    for (uint256 i = 0; i < targets.length; i++) {
      // A payload shorter than four bytes reads as a zero selector, which is not allowed
      bytes4 selector = bytes4(data[i]);

      if (
        selector != PERMIT2_PERMIT_SINGLE_SELECTOR && selector != PERMIT2_PERMIT_BATCH_SELECTOR
          && selector != IERC20Permit.permit.selector && selector != IDaiLikePermit.permit.selector
          && selector != IERC721Permit_v3.permit.selector
          && selector != IERC721Permit_v4.permit.selector
          && selector != IAuthDelegator.updateDelegation.selector
          && selector != IOrderAuthenticator.updateAuthentication.selector
      ) {
        revert UnsupportedSelector(i, selector);
      }

      (success, results[i]) = targets[i].call(data[i]);
      if (!success && !allowFailure.pos(i)) {
        LowLevelCall.bubbleRevert(results[i]);
      }
    }
  }

  /// @inheritdoc ICallsForwarder
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
