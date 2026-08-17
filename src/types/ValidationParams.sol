// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IKSActionValidator} from 'ks-action-validator-sc/src/interfaces/IKSActionValidator.sol';

/**
 * @notice The acceptance criteria an intent fill must satisfy, as signed by the token owner
 * @param validator The validator asked to judge the state transition
 * @param action The action identifier telling the validator what is being validated
 * @param beforeExecutionInput Action-specific input describing what to snapshot
 * @param afterExecutionInput Action-specific constraints the transition must satisfy
 */
struct ValidationParams {
  address validator;
  bytes32 action;
  bytes beforeExecutionInput;
  bytes afterExecutionInput;
}

using ValidationParamsLibrary for ValidationParams global;

/// @notice Contains functions for working with ValidationParams
library ValidationParamsLibrary {
  /// @dev The EIP-712 type hash of `ValidationParams`
  bytes32 internal constant VALIDATION_PARAMS_TYPEHASH = keccak256(
    'ValidationParams(address validator,bytes32 action,bytes beforeExecutionInput,bytes afterExecutionInput)'
  );

  /**
   * @notice Hashes the parameters following EIP-712 struct encoding
   * @param self The parameters to hash
   * @return The EIP-712 hash of the parameters
   */
  function hash(ValidationParams memory self) internal pure returns (bytes32) {
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

  /**
   * @notice Asks the validator to snapshot the state it will judge the transition against
   * @dev `validator` is an arbitrary address chosen by the owner and covered by the signature; the
   * hub calls it without knowing anything about it.
   * @param self The parameters of the validation
   * @return The encoded snapshot, to be handed back to `afterExecution`
   */
  function beforeExecution(ValidationParams calldata self) internal returns (bytes memory) {
    return
      IKSActionValidator(self.validator).beforeExecution(self.action, self.beforeExecutionInput);
  }

  /**
   * @notice Asks the validator to accept or reject the state transition that just happened
   * @dev Reverts the whole call if the validator rejects the transition.
   * @param self The parameters of the validation
   * @param beforeExecutionOutput The snapshot returned by `beforeExecution`
   */
  function afterExecution(ValidationParams calldata self, bytes memory beforeExecutionOutput)
    internal
  {
    IKSActionValidator(self.validator)
      .afterExecution(
        self.action, self.beforeExecutionInput, beforeExecutionOutput, self.afterExecutionInput
      );
  }
}
