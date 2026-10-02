// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IKSGenericRouter} from '../../base/interfaces/IKSGenericRouter.sol';

import {NativeTransfer} from './NativeTransfer.sol';

/**
 * @notice One router call in an order
 * @dev `value` is paid out of the native the hub was sent, and `router` must hold the whitelisted
 * router role at the time the call runs.
 */
struct GenericCall {
  address router;
  uint256 value;
  bytes data;
}

using GenericCallLib for GenericCall global;

library GenericCallLib {
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
    bytes32[] memory callsHashes = new bytes32[](calls.length);
    for (uint256 i = 0; i < calls.length; i++) {
      callsHashes[i] = hash(calls[i]);
    }

    return keccak256(abi.encodePacked(callsHashes));
  }

  /// @dev As {hash}, for an array already in memory
  function hashMemory(GenericCall[] memory calls) internal pure returns (bytes32) {
    bytes32[] memory callsHashes = new bytes32[](calls.length);
    for (uint256 i = 0; i < calls.length; i++) {
      callsHashes[i] = hashMemory(calls[i]);
    }

    return keccak256(abi.encodePacked(callsHashes));
  }

  /// @dev Calls the router, forwarding the call's share of the native sent to the hub
  function execute(GenericCall calldata self) internal returns (bytes memory) {
    return IKSGenericRouter(self.router).ksExecute{value: self.value}(self.data);
  }

  /**
   * @dev The calls that carry value, for the event. Calls with no value are dropped and the array
   * is truncated in place, so an order with none emits an empty array rather than a run of zeros.
   */
  function toNativeTransfers(GenericCall[] calldata genericCalls)
    internal
    pure
    returns (NativeTransfer[] memory transfers)
  {
    uint256 index = 0;
    transfers = new NativeTransfer[](genericCalls.length);

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

  /**
   * @dev The calls that carry value, solver's route first then the owner's tail, for the event.
   * Calls with no value are dropped and the array is truncated in place, so an order with none
   * emits an empty array rather than a run of zero entries.
   */
  function toNativeTransfers(GenericCall[] calldata solverCalls, GenericCall[] calldata ownerCalls)
    internal
    pure
    returns (NativeTransfer[] memory transfers)
  {
    uint256 index = 0;
    transfers = new NativeTransfer[](solverCalls.length + ownerCalls.length);

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
