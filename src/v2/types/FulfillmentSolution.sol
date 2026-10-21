// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {EfficientHashLibExt} from '../libraries/EfficientHashLibExt.sol';

import {GenericCall, GenericCallLib} from './GenericCall.sol';

/**
 * @notice The route a solver chose for a {FulfillmentOrder}, approved separately from the order
 * @dev Signed by the `solutionApprover` the order names, not by the owner, so the route may be
 * chosen after the owner has signed. The solver also chooses where each of the order's legs goes:
 * `erc20Targets[i]` receives `order.erc20Allowances[i]` and `erc721Targets[i]` receives
 * `order.erc721Approvals[i]`.
 * @param erc20Targets The destination of each ERC20 leg, one per leg and in order
 * @param erc721Targets The destination of each ERC721 leg, one per leg and in order
 * @param solverCalls The router calls that make up the route
 * @param deadline Last timestamp at which the solution may settle
 */
struct FulfillmentSolution {
  address[] erc20Targets;
  address[] erc721Targets;
  GenericCall[] solverCalls;
  uint256 deadline;
}

using FulfillmentSolutionLib for FulfillmentSolution global;

library FulfillmentSolutionLib {
  using EfficientHashLibExt for address[];
  using GenericCallLib for GenericCall[];

  bytes32 internal constant FULFILLMENT_SOLUTION_TYPEHASH = keccak256(
    'FulfillmentSolution(address[] erc20Targets,address[] erc721Targets,GenericCall[] solverCalls,uint256 deadline)'
    'GenericCall(address router,uint256 value,bytes data)'
  );

  /// @dev EIP-712 hash of the solution
  function hash(FulfillmentSolution calldata self) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(
        FULFILLMENT_SOLUTION_TYPEHASH,
        self.erc20Targets.hash(),
        self.erc721Targets.hash(),
        self.solverCalls.hash(),
        self.deadline
      )
    );
  }

  /// @dev As {hash}, for a solution already in memory
  function hashMemory(FulfillmentSolution memory self) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(
        FULFILLMENT_SOLUTION_TYPEHASH,
        self.erc20Targets.hashMemory(),
        self.erc721Targets.hashMemory(),
        self.solverCalls.hashMemory(),
        self.deadline
      )
    );
  }
}
