// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {FulfillmentOrder} from './FulfillmentOrder.sol';
import {FulfillmentSolution} from './FulfillmentSolution.sol';

/**
 * @notice An approver's binding of one {FulfillmentSolution} to the {FulfillmentOrder} it settles
 * @dev The whole order is a member, so a route approved for one order cannot be presented with
 * another, and the approver signs the order in full rather than an opaque hash of it. The approval
 * carries no nonce: it settles at most as often as its order.
 */
struct SolutionApproval {
  FulfillmentOrder order;
  FulfillmentSolution solution;
}

library SolutionApprovalLib {
  bytes32 internal constant SOLUTION_APPROVAL_TYPEHASH = keccak256(
    'SolutionApproval(FulfillmentOrder order,FulfillmentSolution solution)'
    'ERC20Allowance(address token,uint160 amount)' 'ERC721Approval(address token,uint256 tokenId)'
    'FulfillmentOrder(address owner,address solver,ERC20Allowance[] erc20Allowances,ERC721Approval[] erc721Approvals,ValidationParams[] validationParams,GenericCall[] ownerCalls,address solutionApprover,uint256 nonce,uint256 deadline)'
    'FulfillmentSolution(address[] erc20Targets,address[] erc721Targets,GenericCall[] solverCalls,uint256 deadline)'
    'GenericCall(address router,uint256 value,bytes data)'
    'ValidationParams(address validator,bytes32 action,bytes beforeExecutionInput,bytes afterExecutionInput)'
  );

  /// @dev EIP-712 hash of the approval the solution approver produces
  function hash(bytes32 orderHash, FulfillmentSolution calldata solution)
    internal
    pure
    returns (bytes32)
  {
    return keccak256(abi.encode(SOLUTION_APPROVAL_TYPEHASH, orderHash, solution.hash()));
  }

  /// @dev As {hash}, for a solution already in memory
  function hashMemory(bytes32 orderHash, FulfillmentSolution memory solution)
    internal
    pure
    returns (bytes32)
  {
    return keccak256(abi.encode(SOLUTION_APPROVAL_TYPEHASH, orderHash, solution.hashMemory()));
  }
}
