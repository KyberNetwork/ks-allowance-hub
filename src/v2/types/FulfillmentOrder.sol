// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ERC20Allowance, ERC20AllowanceLib} from './ERC20Allowance.sol';
import {ERC721Approval, ERC721ApprovalLib} from './ERC721Approval.sol';
import {GenericCall, GenericCallLib} from './GenericCall.sol';
import {ValidationParams, ValidationParamsLib} from './ValidationParams.sol';

/**
 * @notice An owner's signed order to move assets and leave the route to a solver
 * @dev Fixes neither the route nor where each leg goes, both of which are left to a
 * {FulfillmentSolution}: the owner names an approver for it and relies on the validators instead.
 * @param owner Account the assets come from
 * @param solver The account that may submit this order; the dead-address sentinel permits any
 * caller
 * @param erc20Allowances ERC20 legs, each moved in full from the owner to the target the solution
 * names for it
 * @param erc721Approvals ERC721 legs, each moved from the owner to the target the solution names
 * for it
 * @param validationParams Validators run before and after the solver's route, on which the owner
 * relies in place of signing that route
 * @param ownerCalls The tail the owner fixes exactly, run after the validators, for effects no
 * validator can check
 * @param solutionApprover The account that may approve the solver's route; the dead-address
 * sentinel accepts any route
 * @param nonce Burned against the owner, so one order settles at most once
 * @param deadline Last timestamp at which the order may settle
 */
struct FulfillmentOrder {
  address owner;
  address solver;
  ERC20Allowance[] erc20Allowances;
  ERC721Approval[] erc721Approvals;
  ValidationParams[] validationParams;
  GenericCall[] ownerCalls;
  address solutionApprover;
  uint256 nonce;
  uint256 deadline;
}

using FulfillmentOrderLib for FulfillmentOrder global;

library FulfillmentOrderLib {
  using ERC20AllowanceLib for ERC20Allowance[];
  using ERC721ApprovalLib for ERC721Approval[];
  using GenericCallLib for GenericCall[];
  using ValidationParamsLib for ValidationParams[];

  bytes32 internal constant FULFILLMENT_ORDER_TYPEHASH = keccak256(
    'FulfillmentOrder(address owner,address solver,ERC20Allowance[] erc20Allowances,ERC721Approval[] erc721Approvals,ValidationParams[] validationParams,GenericCall[] ownerCalls,address solutionApprover,uint256 nonce,uint256 deadline)'
    'ERC20Allowance(address token,uint160 amount)' 'ERC721Approval(address token,uint256 tokenId)'
    'GenericCall(address router,uint256 value,bytes data)'
    'ValidationParams(address validator,bytes32 action,bytes beforeExecutionInput,bytes afterExecutionInput)'
  );

  /// @dev EIP-712 hash of the order the owner signs
  function hash(FulfillmentOrder calldata order) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(
        FULFILLMENT_ORDER_TYPEHASH,
        order.owner,
        order.solver,
        order.erc20Allowances.hash(),
        order.erc721Approvals.hash(),
        order.validationParams.hash(),
        order.ownerCalls.hash(),
        order.solutionApprover,
        order.nonce,
        order.deadline
      )
    );
  }

  /// @dev As {hash}, for an order already in memory
  function hashMemory(FulfillmentOrder memory order) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(
        FULFILLMENT_ORDER_TYPEHASH,
        order.owner,
        order.solver,
        order.erc20Allowances.hashMemory(),
        order.erc721Approvals.hashMemory(),
        order.validationParams.hashMemory(),
        order.ownerCalls.hashMemory(),
        order.solutionApprover,
        order.nonce,
        order.deadline
      )
    );
  }
}
