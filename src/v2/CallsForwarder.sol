// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ICallsForwarder} from './interfaces/ICallsForwarder.sol';
import {IOrderAuthenticator} from './interfaces/IOrderAuthenticator.sol';

import {NativeSpendGuard} from '../base/NativeSpendGuard.sol';
import {PackedBits} from '../base/types/PackedBits.sol';

import {Common} from 'ks-common-sc/src/base/Common.sol';
import {IDaiLikePermit} from 'ks-common-sc/src/interfaces/IDaiLikePermit.sol';
import {IERC721Permit_v3} from 'ks-common-sc/src/interfaces/IERC721Permit_v3.sol';
import {IERC721Permit_v4} from 'ks-common-sc/src/interfaces/IERC721Permit_v4.sol';

import {
  IERC20Permit
} from 'openzeppelin-contracts/contracts/token/ERC20/extensions/IERC20Permit.sol';
import {LowLevelCall} from 'openzeppelin-contracts/contracts/utils/LowLevelCall.sol';

import {DynamicArrayLib} from 'solady/utils/DynamicArrayLib.sol';

import {DynamicArrayLibExt} from '../base/libraries/DynamicArrayLibExt.sol';

/**
 * @title CallsForwarder
 * @notice Relays calls that authorise themselves — token permits and authenticator updates — so
 * approval and the spend that follows fit in one transaction.
 * @dev Anyone may relay anyone's call: the signature inside each payload is the authorisation.
 * Safety rests on the selector allowlist, since this contract is the `msg.sender` every target
 * sees.
 */
abstract contract CallsForwarder is ICallsForwarder, NativeSpendGuard, Common {
  /// @dev Permit2's two `permit` overloads, written out because `.selector` cannot distinguish
  /// them
  bytes4 internal constant PERMIT2_PERMIT_SINGLE_SELECTOR =
    bytes4(keccak256('permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)'));

  bytes4 internal constant PERMIT2_PERMIT_BATCH_SELECTOR =
    bytes4(keccak256('permit(address,((address,uint160,uint48,uint48)[],address,uint256),bytes)'));

  /**
   * @inheritdoc ICallsForwarder
   * @dev Unlocked: a relayed call may reenter this contract's other entry points, which is safe
   * because nothing here moves assets and every payload authorises itself.
   */
  function forwardCalls(address[] calldata targets, bytes[] calldata data, PackedBits allowFailure)
    external
    payable
    checkLengths(targets.length, data.length)
    returns (bytes[] memory results)
  {
    bool success;
    results = DynamicArrayLibExt.malloc(targets.length);

    for (uint256 i = 0; i < targets.length; i++) {
      // A payload shorter than a selector reads as zero, which matches nothing below
      bytes4 selector = bytes4(data[i]);

      if (
        selector != PERMIT2_PERMIT_SINGLE_SELECTOR && selector != PERMIT2_PERMIT_BATCH_SELECTOR
          && selector != IERC20Permit.permit.selector && selector != IDaiLikePermit.permit.selector
          && selector != IERC721Permit_v3.permit.selector
          && selector != IERC721Permit_v4.permit.selector
          && selector != IOrderAuthenticator.updateAuthentication.selector
      ) {
        revert NotSupportedSelector(selector);
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
    results = DynamicArrayLibExt.malloc(data.length);
    gasUsages = DynamicArrayLib.malloc(data.length);

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
