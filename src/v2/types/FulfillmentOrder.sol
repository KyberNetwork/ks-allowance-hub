// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ERC20Transfer, ERC20TransferLib} from './ERC20Transfer.sol';
import {ERC721Transfer, ERC721TransferLib} from './ERC721Transfer.sol';
import {GenericCall, GenericCallLib} from './GenericCall.sol';
import {ValidationParams, ValidationParamsLib} from './ValidationParams.sol';

/**
 * @notice An owner's signed order to move assets and leave the route to a solver
 * @dev Does not fix that route, which is left to a {FulfillmentSolution}: the owner names an
 * approver for it and relies on the validators instead.
 * @param owner Account the assets come from
 * @param solver The account that may submit this order; the dead-address sentinel permits any
 * caller
 * @param erc20Transfers ERC20 legs, moved from the owner to their targets
 * @param erc721Transfers ERC721 legs, moved from the owner to their targets
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
  ERC20Transfer[] erc20Transfers;
  ERC721Transfer[] erc721Transfers;
  ValidationParams[] validationParams;
  GenericCall[] ownerCalls;
  address solutionApprover;
  uint256 nonce;
  uint256 deadline;
}

using FulfillmentOrderLib for FulfillmentOrder global;

library FulfillmentOrderLib {
  using ERC20TransferLib for ERC20Transfer[];
  using ERC721TransferLib for ERC721Transfer[];
  using GenericCallLib for GenericCall[];
  using ValidationParamsLib for ValidationParams[];

  bytes32 internal constant FULFILLMENT_ORDER_TYPEHASH = keccak256(
    'FulfillmentOrder(address owner,address solver,ERC20Transfer[] erc20Transfers,ERC721Transfer[] erc721Transfers,ValidationParams[] validationParams,GenericCall[] ownerCalls,address solutionApprover,uint256 nonce,uint256 deadline)'
    'ERC20Transfer(address token,address target,uint160 amount)'
    'ERC721Transfer(address token,uint256 tokenId,address target)'
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
        order.erc20Transfers.hash(),
        order.erc721Transfers.hash(),
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
        order.erc20Transfers.hashMemory(),
        order.erc721Transfers.hashMemory(),
        order.validationParams.hashMemory(),
        order.ownerCalls.hashMemory(),
        order.solutionApprover,
        order.nonce,
        order.deadline
      )
    );
  }
}
