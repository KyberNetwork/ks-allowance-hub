// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {EfficientHashLib} from 'solady/utils/EfficientHashLib.sol';

/**
 * @notice A hook an order calls around its settlement
 * @dev {AHV2Order-flags} selects the calls the hub makes to the hook. On the Permit2 signature
 * transfer flow, `beforeSettlement` runs before Permit2 checks the owner's signature.
 * @param hook Hook contract; any address, with no role required
 * @param data Hook-specific data, which the hook reads from `order.hooks` at the index it is called
 * with
 */
struct HookParams {
  address hook;
  bytes data;
}

using HookParamsLib for HookParams global;

library HookParamsLib {
  using EfficientHashLib for *;

  bytes32 internal constant HOOK_PARAMS_TYPEHASH = keccak256('HookParams(address hook,bytes data)');

  /// @dev EIP-712 hash of one entry
  function hash(HookParams calldata self) internal pure returns (bytes32) {
    return keccak256(abi.encode(HOOK_PARAMS_TYPEHASH, self.hook, self.data.hashCalldata()));
  }

  /// @dev EIP-712 hash of the array: its member hashes, concatenated and hashed
  function hash(HookParams[] calldata hooks) internal pure returns (bytes32) {
    bytes32[] memory hookHashes = hooks.length.malloc();
    for (uint256 i = 0; i < hooks.length; i++) {
      hookHashes[i] = hash(hooks[i]);
    }

    return hookHashes.hash();
  }
}
