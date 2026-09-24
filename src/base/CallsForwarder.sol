// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IAuthVerifier} from './interfaces/IAuthVerifier.sol';
import {ICallsForwarder} from './interfaces/ICallsForwarder.sol';

import {NativeSpendGuard} from './NativeSpendGuard.sol';

import {PackedBits} from './types/PackedBits.sol';

import {Common} from 'ks-common-sc/src/base/Common.sol';
import {IDaiLikePermit} from 'ks-common-sc/src/interfaces/IDaiLikePermit.sol';
import {IERC721Permit_v3} from 'ks-common-sc/src/interfaces/IERC721Permit_v3.sol';
import {IERC721Permit_v4} from 'ks-common-sc/src/interfaces/IERC721Permit_v4.sol';

import {
  IERC20Permit
} from 'openzeppelin-contracts/contracts/token/ERC20/extensions/IERC20Permit.sol';
import {LowLevelCall} from 'openzeppelin-contracts/contracts/utils/LowLevelCall.sol';

import {Multicallable} from 'solady/utils/Multicallable.sol';

/**
 * @title CallsForwarder
 * @notice Relays calls that authorise themselves — token permits and verifier updates — so an
 * approval and the spend that follows fit in one transaction.
 * @dev Anyone may relay anyone's call: the signature inside each payload is the authorisation.
 * The selector allowlist is what keeps that safe, since this contract is the `msg.sender` every
 * target sees.
 */
contract CallsForwarder is ICallsForwarder, NativeSpendGuard, Common, Multicallable {
  /// @dev Permit2's two `permit` overloads, written out because `.selector` cannot pick between them
  bytes4 internal constant PERMIT2_PERMIT_SINGLE_SELECTOR =
    bytes4(keccak256('permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)'));

  bytes4 internal constant PERMIT2_PERMIT_BATCH_SELECTOR =
    bytes4(keccak256('permit(address,((address,uint160,uint48,uint48)[],address,uint256),bytes)'));

  /**
   * @inheritdoc ICallsForwarder
   * @dev Unlocked: a relayed call may reenter this contract's other entry points, which is safe
   * because nothing here moves assets and every payload authorises itself.
   */
  function forward(address[] calldata targets, bytes[] calldata data, PackedBits allowFailure)
    external
    payable
    checkLengths(targets.length, data.length)
    returns (bytes[] memory results)
  {
    bool success;
    results = new bytes[](targets.length);

    for (uint256 i = 0; i < targets.length; i++) {
      // A payload shorter than a selector reads as zero, which matches nothing below
      bytes4 selector = bytes4(data[i]);

      if (
        selector != PERMIT2_PERMIT_SINGLE_SELECTOR && selector != PERMIT2_PERMIT_BATCH_SELECTOR
          && selector != IERC20Permit.permit.selector && selector != IDaiLikePermit.permit.selector
          && selector != IERC721Permit_v3.permit.selector
          && selector != IERC721Permit_v4.permit.selector
          && selector != IAuthVerifier.updateAuth.selector
      ) {
        revert NotSupportedSelector(selector);
      }

      (success, results[i]) = targets[i].call(data[i]);
      if (!success && !allowFailure.pos(i)) {
        LowLevelCall.bubbleRevert(results[i]);
      }
    }
  }

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
