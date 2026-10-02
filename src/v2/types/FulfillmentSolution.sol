// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {GenericCall, GenericCallLib} from './GenericCall.sol';

/**
 * @notice The route a solver chose for a {FulfillmentOrder}, approved separately from the order
 * @dev Signed by the `solutionApprover` the order names, not by the owner, which is what lets the
 * route be picked after the owner signed.
 */
struct FulfillmentSolution {
  GenericCall[] solverCalls;
  uint256 nonce;
  uint256 deadline;
}

using FulfillmentSolutionLib for FulfillmentSolution global;

library FulfillmentSolutionLib {
  using GenericCallLib for GenericCall[];

  bytes32 internal constant FULFILLMENT_SOLUTION_TYPEHASH = keccak256(
    'FulfillmentSolution(GenericCall[] solverCalls,uint256 nonce,uint256 deadline)'
    'GenericCall(address router,uint256 value,bytes data)'
  );

  /// @dev EIP-712 hash of the solution
  function hash(FulfillmentSolution calldata self) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(FULFILLMENT_SOLUTION_TYPEHASH, self.solverCalls.hash(), self.nonce, self.deadline)
    );
  }

  /// @dev As {hash}, for a solution already in memory
  function hashMemory(FulfillmentSolution memory self) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(
        FULFILLMENT_SOLUTION_TYPEHASH, self.solverCalls.hashMemory(), self.nonce, self.deadline
      )
    );
  }
}
