// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {DynamicArrayLibExt} from '../libraries/DynamicArrayLibExt.sol';

import {IKSActionValidator} from 'ks-action-validator-sc/src/interfaces/IKSActionValidator.sol';

import {EfficientHashLib} from 'solady/utils/EfficientHashLib.sol';

/**
 * @notice A validator of a fulfillment order and its inputs
 * @dev The validator's `beforeExecution` runs before any asset moves, and its `afterExecution` runs
 * after the solver's calls and before the owner's calls. On the Permit2 entry point,
 * `beforeExecution` runs before the owner's signature is checked.
 * @param validator Validator contract; any address, with no role required
 * @param action Validator-specific identifier of the check to perform
 * @param beforeExecutionInput Input passed to `beforeExecution`
 * @param afterExecutionInput Input passed to `afterExecution`, with the output `beforeExecution`
 * returned
 */
struct ValidationParams {
  address validator;
  bytes32 action;
  bytes beforeExecutionInput;
  bytes afterExecutionInput;
}

using ValidationParamsLib for ValidationParams global;

library ValidationParamsLib {
  using DynamicArrayLibExt for uint256;
  using EfficientHashLib for *;

  bytes32 internal constant VALIDATION_PARAMS_TYPEHASH = keccak256(
    'ValidationParams(address validator,bytes32 action,bytes beforeExecutionInput,bytes afterExecutionInput)'
  );

  /// @dev EIP-712 hash of one validator's parameters
  function hash(ValidationParams calldata self) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(
        VALIDATION_PARAMS_TYPEHASH,
        self.validator,
        self.action,
        keccak256(self.beforeExecutionInput),
        keccak256(self.afterExecutionInput)
      )
    );
  }

  /// @dev As {hash}, for parameters already in memory
  function hashMemory(ValidationParams memory self) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(
        VALIDATION_PARAMS_TYPEHASH,
        self.validator,
        self.action,
        keccak256(self.beforeExecutionInput),
        keccak256(self.afterExecutionInput)
      )
    );
  }

  /// @dev EIP-712 hash of the array: its member hashes, concatenated and hashed
  function hash(ValidationParams[] calldata params) internal pure returns (bytes32) {
    bytes32[] memory paramsHashes = params.length.malloc();
    for (uint256 i = 0; i < params.length; i++) {
      paramsHashes[i] = hash(params[i]);
    }

    return paramsHashes.hash();
  }

  /// @dev As {hash}, for an array already in memory
  function hashMemory(ValidationParams[] memory params) internal pure returns (bytes32) {
    bytes32[] memory paramsHashes = params.length.malloc();
    for (uint256 i = 0; i < params.length; i++) {
      paramsHashes[i] = hashMemory(params[i]);
    }

    return paramsHashes.hash();
  }

  /// @dev Calls `beforeExecution` on each validator and returns their outputs, in order
  function beforeExecution(ValidationParams[] calldata params)
    internal
    returns (bytes[] memory beforeExecutionOutputs)
  {
    beforeExecutionOutputs = params.length.mallocBytes();
    for (uint256 i = 0; i < params.length; i++) {
      ValidationParams calldata _params = params[i];
      beforeExecutionOutputs[i] = IKSActionValidator(_params.validator)
        .beforeExecution(_params.action, _params.beforeExecutionInput);
    }
  }

  /// @dev Calls `afterExecution` on each validator with the output its `beforeExecution` returned
  function afterExecution(ValidationParams[] calldata params, bytes[] memory beforeExecutionOutputs)
    internal
  {
    for (uint256 i = 0; i < params.length; i++) {
      ValidationParams calldata _params = params[i];
      IKSActionValidator(_params.validator)
        .afterExecution(
          _params.action,
          _params.beforeExecutionInput,
          beforeExecutionOutputs[i],
          _params.afterExecutionInput
        );
    }
  }
}
