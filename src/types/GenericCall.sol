// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IKSGenericRouter} from '../interfaces/IKSGenericRouter.sol';

/**
 * @notice A call to a whitelisted router
 * @param router The address of the router to call
 * @param value The native token amount to forward with the call
 * @param data The payload to pass to the router
 */
struct GenericCall {
  address router;
  uint256 value;
  bytes data;
}

using GenericCallLibrary for GenericCall global;

/// @notice Contains functions for working with GenericCall
library GenericCallLibrary {
  /// @dev The EIP-712 type hash of `GenericCall`
  bytes32 internal constant GENERIC_CALL_TYPEHASH =
    keccak256('GenericCall(address router,uint256 value,bytes data)');

  /**
   * @notice Hashes a call following EIP-712 struct encoding
   * @param self The call to hash
   * @return The EIP-712 hash of the call
   */
  function hash(GenericCall memory self) internal pure returns (bytes32) {
    return
      keccak256(abi.encode(GENERIC_CALL_TYPEHASH, self.router, self.value, keccak256(self.data)));
  }

  /**
   * @notice Calls the router, forwarding the requested native value
   * @dev Bubbles up the router's revert. The caller is responsible for checking that `router` is
   * whitelisted before reaching here.
   * @param self The call to execute
   * @return The router's return data
   */
  function execute(GenericCall calldata self) internal returns (bytes memory) {
    return IKSGenericRouter(self.router).ksExecute{value: self.value}(self.data);
  }
}
