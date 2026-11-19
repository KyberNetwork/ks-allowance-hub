// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IAHV2Callee} from '../interfaces/base/IAHV2Callee.sol';

import {DynamicArrayLibExt} from '../libraries/DynamicArrayLibExt.sol';

import {NativeTransfer} from './NativeTransfer.sol';

import {EfficientHashLib} from 'solady/utils/EfficientHashLib.sol';

/**
 * @notice A call the hub makes to a callee for an order or a solution
 * @dev The callee may read the order's owner from {IMsgSender-msgSender}. Both the solver's and
 * the owner's calls go to {IAHV2Callee-execute}.
 * @param callee Contract called; must hold the whitelisted callee role when the call runs
 * @param value Native value sent with the call, paid from the native value sent with the order
 * @param data Passed to {IAHV2Callee-execute} as `solverData` for a solver's call, or as
 * `ownerData` for an owner's call
 */
struct CallParams {
  address callee;
  uint256 value;
  bytes data;
}

using CallParamsLib for CallParams global;

library CallParamsLib {
  using DynamicArrayLibExt for uint256;
  using EfficientHashLib for *;

  bytes32 internal constant CALL_PARAMS_TYPEHASH =
    keccak256('CallParams(address callee,uint256 value,bytes data)');

  /// @dev EIP-712 hash of one call
  function hash(CallParams calldata self) internal pure returns (bytes32) {
    return
      keccak256(abi.encode(CALL_PARAMS_TYPEHASH, self.callee, self.value, self.data.hashCalldata()));
  }

  /// @dev EIP-712 hash of the array: its member hashes, concatenated and hashed
  function hash(CallParams[] calldata calls) internal pure returns (bytes32) {
    bytes32[] memory callHashes = calls.length.malloc();
    for (uint256 i = 0; i < calls.length; i++) {
      callHashes[i] = hash(calls[i]);
    }

    return callHashes.hash();
  }

  /// @dev Calls `execute` on the callee with empty `ownerData`, the call's data as `solverData`
  /// and the call's native value
  function executeSolverCall(CallParams calldata self) internal returns (bytes memory) {
    return IAHV2Callee(self.callee).execute{value: self.value}('', self.data);
  }

  /// @dev Calls `execute` on the callee with the call's data as `ownerData`, `solverData` and the
  /// call's native value
  function executeOwnerCall(CallParams calldata self, bytes calldata solverData)
    internal
    returns (bytes memory)
  {
    return IAHV2Callee(self.callee).execute{value: self.value}(self.data, solverData);
  }

  /// @dev The calls that carry native value, as native transfers to their callees: the solver's
  /// calls followed by the owner's calls
  function toNativeTransfers(CallParams[] calldata solverCalls, CallParams[] calldata ownerCalls)
    internal
    pure
    returns (NativeTransfer[] memory transfers)
  {
    uint256 index = 0;
    transfers = (solverCalls.length + ownerCalls.length).mallocNativeTransfers();

    for (uint256 i = 0; i < solverCalls.length; i++) {
      CallParams calldata call = solverCalls[i];
      if (call.value > 0) {
        transfers[index++] = NativeTransfer({target: call.callee, amount: call.value});
      }
    }

    for (uint256 i = 0; i < ownerCalls.length; i++) {
      CallParams calldata call = ownerCalls[i];
      if (call.value > 0) {
        transfers[index++] = NativeTransfer({target: call.callee, amount: call.value});
      }
    }

    assembly ('memory-safe') {
      mstore(transfers, index)
    }
  }
}
