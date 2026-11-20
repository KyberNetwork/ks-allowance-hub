// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IAHV2Callee} from '../interfaces/base/IAHV2Callee.sol';

import {DynamicArrayLibExt} from '../libraries/DynamicArrayLibExt.sol';

import {NativeTransfer} from './NativeTransfer.sol';

import {EfficientHashLib} from 'solady/utils/EfficientHashLib.sol';

/**
 * @notice A call the hub makes to a callee for an order
 * @dev The callee may read the order's owner from {ISettlementContext-msgSender}.
 * @param callee Contract called; must hold the whitelisted callee role when the call runs
 * @param ownerData Callee-specific payload the owner signs, passed to {IAHV2Callee-execute}
 */
struct CallParams {
  address callee;
  bytes ownerData;
}

using CallParamsLib for CallParams global;

library CallParamsLib {
  using DynamicArrayLibExt for uint256;
  using EfficientHashLib for *;

  bytes32 internal constant CALL_PARAMS_TYPEHASH =
    keccak256('CallParams(address callee,bytes ownerData)');

  /// @dev EIP-712 hash of one call
  function hash(CallParams calldata self) internal pure returns (bytes32) {
    return keccak256(abi.encode(CALL_PARAMS_TYPEHASH, self.callee, self.ownerData.hashCalldata()));
  }

  /// @dev EIP-712 hash of the array: its member hashes, concatenated and hashed
  function hash(CallParams[] calldata calls) internal pure returns (bytes32) {
    bytes32[] memory callHashes = calls.length.malloc();
    for (uint256 i = 0; i < calls.length; i++) {
      callHashes[i] = hash(calls[i]);
    }

    return callHashes.hash();
  }

  /// @dev Calls `execute` on the callee with `value`, the call's `ownerData` and `solverData`
  function execute(CallParams calldata self, uint256 value, bytes calldata solverData)
    internal
    returns (bytes memory)
  {
    return IAHV2Callee(self.callee).execute{value: value}(self.ownerData, solverData);
  }

  /// @dev The calls given native value by `values`, as native transfers to their callees, in order
  function toNativeTransfers(CallParams[] calldata calls, uint256[] calldata values)
    internal
    pure
    returns (NativeTransfer[] memory transfers)
  {
    uint256 index = 0;
    transfers = calls.length.mallocNativeTransfers();

    for (uint256 i = 0; i < calls.length; i++) {
      CallParams calldata call = calls[i];
      if (values[i] > 0) {
        transfers[index++] = NativeTransfer({target: call.callee, amount: values[i]});
      }
    }

    assembly ('memory-safe') {
      mstore(transfers, index)
    }
  }
}
