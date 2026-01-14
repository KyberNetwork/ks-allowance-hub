// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IKSGenericRouter} from '../interfaces/IKSGenericRouter.sol';

/**
 * @notice Parameters for calling a generic router
 * @param router The address of the router
 * @param value The value to send along with the call
 * @param data The data to call the generic router with
 */
struct GenericCall {
  address router;
  uint256 value;
  bytes data;
}

using GenericCallLibrary for GenericCall global;

/// @notice Contains functions for working with GenericCall
library GenericCallLibrary {
  bytes32 internal constant GENERIC_CALL_TYPEHASH =
    keccak256('GenericCall(address router,uint256 value,bytes data)');

  function hash(GenericCall memory self) internal pure returns (bytes32) {
    return
      keccak256(abi.encode(GENERIC_CALL_TYPEHASH, self.router, self.value, keccak256(self.data)));
  }

  /// @notice Executes a generic call
  function execute(GenericCall calldata self) internal returns (bytes memory) {
    return IKSGenericRouter(self.router).ksExecute{value: self.value}(self.data);
  }
}
