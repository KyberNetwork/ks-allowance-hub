// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {EfficientHashLibExt} from '../libraries/EfficientHashLibExt.sol';

import {GenericCall, GenericCallLib} from './GenericCall.sol';

/**
 * @notice The route and the leg targets a solver chose for a {FulfillmentOrder}
 * @dev Approved by the order's `solutionApprover` rather than signed by the owner, so it may be
 * chosen after the order is signed. `erc20Targets[i]` receives `order.erc20Allowances[i]` and
 * `erc721Targets[i]` receives `order.erc721Approvals[i]`, so each target array must have one entry
 * per leg. No approval is required when the order's `solutionApprover` is the dead address.
 * @param erc20Targets Target of each ERC20 leg, in order
 * @param erc721Targets Target of each ERC721 leg, in order
 * @param solverCalls Router calls of the route
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
