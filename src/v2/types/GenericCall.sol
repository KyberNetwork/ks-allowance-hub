// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IKSGenericRouter} from '../../base/interfaces/IKSGenericRouter.sol';

import {DynamicArrayLibExt} from '../libraries/DynamicArrayLibExt.sol';

import {NativeTransfer} from './NativeTransfer.sol';

import {EfficientHashLib} from 'solady/utils/EfficientHashLib.sol';

/**
 * @notice One router call in an order
 * @dev The router may read the order's owner from {IMsgSender-msgSender}.
 * @param router Router called with `ksExecute`; must hold the whitelisted router role when the call
 * runs
 * @param value Native value sent with the call, paid from the native value sent with the order
 * @param data Payload passed to `ksExecute`
 */
struct GenericCall {
  address router;
  uint256 value;
  bytes data;
}

using GenericCallLib for GenericCall global;

library GenericCallLib {
  using DynamicArrayLibExt for uint256;
  using EfficientHashLib for *;

  bytes32 internal constant GENERIC_CALL_TYPEHASH =
    keccak256('GenericCall(address router,uint256 value,bytes data)');

  /// @dev EIP-712 hash of one call
  function hash(GenericCall calldata self) internal pure returns (bytes32) {
    return
      keccak256(abi.encode(GENERIC_CALL_TYPEHASH, self.router, self.value, keccak256(self.data)));
  }

  /// @dev As {hash}, for a call already in memory
  function hashMemory(GenericCall memory self) internal pure returns (bytes32) {
    return
      keccak256(abi.encode(GENERIC_CALL_TYPEHASH, self.router, self.value, keccak256(self.data)));
  }

  /// @dev EIP-712 hash of the array: its member hashes, concatenated and hashed
  function hash(GenericCall[] calldata calls) internal pure returns (bytes32) {
    bytes32[] memory callHashes = calls.length.malloc();
    for (uint256 i = 0; i < calls.length; i++) {
      callHashes[i] = hash(calls[i]);
    }

    return callHashes.hash();
  }

  /// @dev As {hash}, for an array already in memory
  function hashMemory(GenericCall[] memory calls) internal pure returns (bytes32) {
    bytes32[] memory callHashes = calls.length.malloc();
    for (uint256 i = 0; i < calls.length; i++) {
      callHashes[i] = hashMemory(calls[i]);
    }

    return callHashes.hash();
  }

  /// @dev Calls `ksExecute` on the router with the call's data and native value
  function execute(GenericCall calldata self) internal returns (bytes memory) {
    return IKSGenericRouter(self.router).ksExecute{value: self.value}(self.data);
  }

  /// @dev The calls that carry native value, as native transfers to their routers
  function toNativeTransfers(GenericCall[] calldata genericCalls)
    internal
    pure
    returns (NativeTransfer[] memory transfers)
  {
    uint256 index = 0;
    transfers = genericCalls.length.mallocNativeTransfers();

    for (uint256 i = 0; i < genericCalls.length; i++) {
      GenericCall calldata call = genericCalls[i];
      if (call.value > 0) {
        transfers[index++] = NativeTransfer({target: call.router, amount: call.value});
      }
    }

    assembly ('memory-safe') {
      mstore(transfers, index)
    }
  }

  /// @dev As {toNativeTransfers}, for the solver's calls followed by the owner's calls
  function toNativeTransfers(GenericCall[] calldata solverCalls, GenericCall[] calldata ownerCalls)
    internal
    pure
    returns (NativeTransfer[] memory transfers)
  {
    uint256 index = 0;
    transfers = (solverCalls.length + ownerCalls.length).mallocNativeTransfers();

    for (uint256 i = 0; i < solverCalls.length; i++) {
      GenericCall calldata call = solverCalls[i];
      if (call.value > 0) {
        transfers[index++] = NativeTransfer({target: call.router, amount: call.value});
      }
    }
    for (uint256 i = 0; i < ownerCalls.length; i++) {
      GenericCall calldata call = ownerCalls[i];
      if (call.value > 0) {
        transfers[index++] = NativeTransfer({target: call.router, amount: call.value});
      }
    }

    assembly ('memory-safe') {
      mstore(transfers, index)
    }
  }
}
