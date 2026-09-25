// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IKSActionValidator} from 'ks-action-validator-sc/src/interfaces/IKSActionValidator.sol';

/**
 * @notice A validator to run around an order, and the inputs it needs
 * @dev In a fulfillment the solver picks the route, so these are what actually bound the outcome.
 */
struct ValidationParams {
  address validator;
  bytes32 action;
  bytes beforeExecutionInput;
  bytes afterExecutionInput;
}

using ValidationParamsLibrary for ValidationParams global;

library ValidationParamsLibrary {
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
    bytes32[] memory paramsHashes = new bytes32[](params.length);
    for (uint256 i = 0; i < params.length; i++) {
      paramsHashes[i] = hash(params[i]);
    }

    return keccak256(abi.encodePacked(paramsHashes));
  }

  /// @dev As {hash}, for an array already in memory
  function hashMemory(ValidationParams[] memory params) internal pure returns (bytes32) {
    bytes32[] memory paramsHashes = new bytes32[](params.length);
    for (uint256 i = 0; i < params.length; i++) {
      paramsHashes[i] = hashMemory(params[i]);
    }

    return keccak256(abi.encodePacked(paramsHashes));
  }

  /**
   * @dev Runs every validator's pre-hook and keeps each snapshot.
   * Called before anything moves, so a validator measures the whole order rather than its tail.
   */
  function beforeExecution(ValidationParams[] calldata params)
    internal
    returns (bytes[] memory beforeExecutionOutputs)
  {
    beforeExecutionOutputs = new bytes[](params.length);
    for (uint256 i = 0; i < params.length; i++) {
      ValidationParams calldata _params = params[i];
      beforeExecutionOutputs[i] = IKSActionValidator(_params.validator)
        .beforeExecution(_params.action, _params.beforeExecutionInput);
    }
  }

  /// @dev Each validator gets its own snapshot back, paired by index
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
