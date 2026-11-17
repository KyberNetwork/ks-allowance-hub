// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IAHV2Hook} from '../interfaces/base/IAHV2Hook.sol';

import {Constants} from '../libraries/Constants.sol';
import {DynamicArrayLibExt} from '../libraries/DynamicArrayLibExt.sol';

import {AHV2Order} from './AHV2Order.sol';
import {AHV2Solution} from './AHV2Solution.sol';

import {EfficientHashLib} from 'solady/utils/EfficientHashLib.sol';

/**
 * @notice A hook an order calls around its settlement
 * @dev {Constants-BEFORE_SETTLEMENT_HOOK_FLAG} selects {IAHV2Hook-beforeSettlement} and
 * {Constants-AFTER_SETTLEMENT_HOOK_FLAG} selects {IAHV2Hook-afterSettlement}. Other bits are
 * ignored. On the Permit2 entry point, `beforeSettlement` runs before the owner's signature is
 * checked.
 * @param hook Hook contract; any address, with no role required
 * @param flags Bit mask of the calls the hub makes to `hook`
 * @param data Hook-specific data, which the hook reads from `order.hooks` at the index it is called
 * with
 */
struct HookParams {
  address hook;
  bytes32 flags;
  bytes data;
}

using HookParamsLib for HookParams global;

library HookParamsLib {
  using DynamicArrayLibExt for uint256;
  using EfficientHashLib for *;

  bytes32 internal constant HOOK_PARAMS_TYPEHASH =
    keccak256('HookParams(address hook,bytes32 flags,bytes data)');

  /// @dev EIP-712 hash of one entry
  function hash(HookParams calldata self) internal pure returns (bytes32) {
    return
      keccak256(abi.encode(HOOK_PARAMS_TYPEHASH, self.hook, self.flags, self.data.hashCalldata()));
  }

  /// @dev EIP-712 hash of the array: its member hashes, concatenated and hashed
  function hash(HookParams[] calldata hooks) internal pure returns (bytes32) {
    bytes32[] memory hookHashes = hooks.length.malloc();
    for (uint256 i = 0; i < hooks.length; i++) {
      hookHashes[i] = hash(hooks[i]);
    }

    return hookHashes.hash();
  }

  /// @dev Calls `beforeSettlement` on each hook that selects it and returns the results, in order;
  /// the result of a hook that does not select it is empty
  function beforeSettlement(
    HookParams[] calldata hooks,
    AHV2Order calldata order,
    bytes32 orderHash,
    AHV2Solution calldata solution
  ) internal returns (bytes[] memory results) {
    results = hooks.length.mallocBytes();
    for (uint256 i = 0; i < hooks.length; i++) {
      HookParams calldata params = hooks[i];
      if (params.flags & Constants.BEFORE_SETTLEMENT_HOOK_FLAG != bytes32(0)) {
        results[i] = IAHV2Hook(params.hook).beforeSettlement(order, orderHash, solution, i);
      } else {
        results[i] = new bytes(0);
      }
    }
  }

  /// @dev Calls `afterSettlement` on each hook that selects it, with the result of its
  /// `beforeSettlement`
  function afterSettlement(
    HookParams[] calldata hooks,
    AHV2Order calldata order,
    bytes32 orderHash,
    AHV2Solution calldata solution,
    bytes[] memory beforeSettlementResults
  ) internal {
    for (uint256 i = 0; i < hooks.length; i++) {
      HookParams calldata params = hooks[i];
      if (params.flags & Constants.AFTER_SETTLEMENT_HOOK_FLAG != bytes32(0)) {
        IAHV2Hook(params.hook)
          .afterSettlement(order, orderHash, solution, i, beforeSettlementResults[i]);
      }
    }
  }
}
