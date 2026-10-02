// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {FulfillmentSolution} from './FulfillmentSolution.sol';

/**
 * @notice An approver's binding of one {FulfillmentSolution} to the {FulfillmentOrder} it settles
 * @dev `orderHash` ties the approval to a single order, so a route approved for one cannot be
 * replayed against another.
 */
struct SolutionApproval {
  address owner;
  bytes32 orderHash;
  FulfillmentSolution solution;
}

library SolutionApprovalLib {
  bytes32 internal constant SOLUTION_APPROVAL_TYPEHASH = keccak256(
    'SolutionApproval(address owner,bytes32 orderHash,FulfillmentSolution solution)'
    'FulfillmentSolution(GenericCall[] solverCalls,uint256 nonce,uint256 deadline)'
    'GenericCall(address router,uint256 value,bytes data)'
  );

  /// @dev EIP-712 hash of the approval the solution approver produces
  function hash(address owner, bytes32 orderHash, FulfillmentSolution calldata solution)
    internal
    pure
    returns (bytes32)
  {
    return keccak256(abi.encode(SOLUTION_APPROVAL_TYPEHASH, owner, orderHash, solution.hash()));
  }

  /// @dev As {hash}, for a solution already in memory
  function hashMemory(address owner, bytes32 orderHash, FulfillmentSolution memory solution)
    internal
    pure
    returns (bytes32)
  {
    return
      keccak256(abi.encode(SOLUTION_APPROVAL_TYPEHASH, owner, orderHash, solution.hashMemory()));
  }
}
