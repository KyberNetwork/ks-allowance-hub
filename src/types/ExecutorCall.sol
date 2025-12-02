// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IGenericExecutor} from '../interfaces/IGenericExecutor.sol';

/**
 * @notice Parameters for calling an executor
 * @param executor The address of the executor
 * @param value The value to send to the executor
 * @param data The data to call the executor with
 */
struct ExecutorCall {
  address executor;
  uint256 value;
  bytes data;
}

using ExecutorCallLibrary for ExecutorCall global;

/// @notice Contains functions for working with ExecutorCall
library ExecutorCallLibrary {
  /// @notice Calls an executor
  function call(ExecutorCall calldata self) internal returns (bytes memory) {
    return IGenericExecutor(self.executor).execute{value: self.value}(self.data);
  }
}
