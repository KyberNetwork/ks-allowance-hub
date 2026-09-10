// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {GenericCall} from './GenericCall.sol';

/**
 * @notice A single native token movement, as reported in the `TransferTokens` event
 * @param target The address the native token was forwarded to
 * @param amount The amount forwarded
 */
struct NativeTransfer {
  address target;
  uint256 amount;
}

/// @notice Contains functions for working with NativeTransfer
library NativeTransferLibrary {
  /**
   * @notice Reduces the generic calls to the native token movements they produce
   * @param calls The generic calls to be executed
   * @return transfers The movements of the calls carrying a non-zero value, in call order
   */
  function toTransfers(GenericCall[] calldata calls)
    internal
    pure
    returns (NativeTransfer[] memory transfers)
  {
    // Only value-bearing calls are reported, so allocate for the worst case and shrink after
    uint256 index = 0;
    transfers = new NativeTransfer[](calls.length);

    for (uint256 i = 0; i < calls.length; i++) {
      if (calls[i].value > 0) {
        transfers[index++] = NativeTransfer({target: calls[i].router, amount: calls[i].value});
      }
    }

    // Truncates the array to the number of entries written. Memory-safe: this only lowers the
    // length of an array this function just allocated, and the free memory pointer is left past
    // the original allocation, so no other memory can be reached through it.
    assembly ('memory-safe') {
      mstore(transfers, index)
    }
  }
}
