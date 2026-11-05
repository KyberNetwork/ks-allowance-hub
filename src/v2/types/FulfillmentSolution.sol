// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {EfficientHashLibExt} from '../libraries/EfficientHashLibExt.sol';

import {GenericCall, GenericCallLib} from './GenericCall.sol';

/**
 * @notice The route, the target of each transfer and the amount of each ERC20 transfer a solver
 * chose for a {FulfillmentOrder}
 * @dev Approved by the order's `solutionApprover` rather than signed by the owner, so it may be
 * chosen after the order is signed. `erc20Targets[i]` receives `erc20Amounts[i]` of
 * `order.erc20Allowances[i]` and `erc721Targets[i]` receives `order.erc721Approvals[i]`. The
 * solution specifies a target and an amount for each ERC20 transfer and a target for each ERC721
 * transfer, so each target array and `erc20Amounts` must have one entry per transfer. No approval
 * is required when the order's `solutionApprover` is the dead address.
 * @param erc20Targets Target of each ERC20 transfer, in order
 * @param erc20Amounts Amount of each ERC20 transfer, in order; each is at most its allowance
 * @param erc721Targets Target of each ERC721 transfer, in order
 * @param solverCalls Router calls of the route
 * @param nonce Nonce of the solution approval, spent in the `solutionApprover`'s namespace of the
 * hub's nonces when the approval is checked; ignored when `solutionApprover` is the dead address
 * @param expiration Last timestamp at which the solution may settle
 */
struct FulfillmentSolution {
  address[] erc20Targets;
  uint160[] erc20Amounts;
  address[] erc721Targets;
  GenericCall[] solverCalls;
  uint256 nonce;
  uint256 expiration;
}

using FulfillmentSolutionLib for FulfillmentSolution global;

library FulfillmentSolutionLib {
  using EfficientHashLibExt for address[];
  using EfficientHashLibExt for uint160[];
  using GenericCallLib for GenericCall[];

  bytes32 internal constant FULFILLMENT_SOLUTION_TYPEHASH = keccak256(
    'FulfillmentSolution(address[] erc20Targets,uint160[] erc20Amounts,address[] erc721Targets,GenericCall[] solverCalls,uint256 nonce,uint256 expiration)'
    'GenericCall(address router,uint256 value,bytes data)'
  );

  /// @dev EIP-712 hash of the solution
  function hash(FulfillmentSolution calldata self) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(
        FULFILLMENT_SOLUTION_TYPEHASH,
        self.erc20Targets.hash(),
        self.erc20Amounts.hash(),
        self.erc721Targets.hash(),
        self.solverCalls.hash(),
        self.nonce,
        self.expiration
      )
    );
  }

  /// @dev As {hash}, for a solution already in memory
  function hashMemory(FulfillmentSolution memory self) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(
        FULFILLMENT_SOLUTION_TYPEHASH,
        self.erc20Targets.hashMemory(),
        self.erc20Amounts.hashMemory(),
        self.erc721Targets.hashMemory(),
        self.solverCalls.hashMemory(),
        self.nonce,
        self.expiration
      )
    );
  }
}
