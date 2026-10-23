// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {FulfillmentOrder} from './FulfillmentOrder.sol';
import {FulfillmentSolution} from './FulfillmentSolution.sol';

/**
 * @notice A solution approver's approval of one {FulfillmentSolution} for one {FulfillmentOrder}
 * @dev The approval carries no nonce, so it is valid for every settlement of its order.
 * @param order The order the solution settles
 * @param solution The approved solution
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

  /// @dev EIP-712 hash of the approval, taking the order by its struct hash
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
