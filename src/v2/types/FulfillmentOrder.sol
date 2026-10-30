// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ERC20Allowance, ERC20AllowanceLib} from './ERC20Allowance.sol';
import {ERC721Approval, ERC721ApprovalLib} from './ERC721Approval.sol';
import {GenericCall, GenericCallLib} from './GenericCall.sol';
import {ValidationParams, ValidationParamsLib} from './ValidationParams.sol';

/**
 * @notice An owner's order to transfer assets along a route chosen by a solver
 * @dev The order names neither the route nor the targets of its legs; a {FulfillmentSolution}
 * supplies both. The validators constrain the result of the solution, and `solutionApprover` may
 * be required to approve it. The validators do not observe the effects of `ownerCalls`.
 *
 * When `owner` submits the order, `solver` does not apply and no authentication is required
 * beyond the call itself, except that a Permit2 entry point still requires the owner's permit
 * signature, without a witness. The solution approval is required whoever submits. On a delegated
 * entry point the owner's own submission spends no nonce, so the same order may settle more than
 * once.
 * @param owner Account the assets are transferred from
 * @param solver Account that may submit the order besides the owner; the dead address allows any
 * account
 * @param erc20Allowances ERC20 legs, each transferred in full from the owner to the target the
 * solution names for it
 * @param erc721Approvals ERC721 legs, each transferred from the owner to the target the solution
 * names for it
 * @param validationParams Validators run before the legs are transferred and after the solver's
 * calls
 * @param ownerCalls Router calls fixed by the owner, run after the validators
 * @param solutionApprover Account whose signature the solution requires; the dead address
 * requires none
 * @param nonce Permit2 nonce on the Permit2 entry points; on the delegated entry points, for the
 * authenticator to spend
 * @param deadline Last timestamp at which the order may settle
 * @param metadata Data the hub does not read, covered by the order's signature
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
  string metadata;
}

using FulfillmentOrderLib for FulfillmentOrder global;

library FulfillmentOrderLib {
  using ERC20AllowanceLib for ERC20Allowance[];
  using ERC721ApprovalLib for ERC721Approval[];
  using GenericCallLib for GenericCall[];
  using ValidationParamsLib for ValidationParams[];

  bytes32 internal constant FULFILLMENT_ORDER_TYPEHASH = keccak256(
    'FulfillmentOrder(address owner,address solver,ERC20Allowance[] erc20Allowances,ERC721Approval[] erc721Approvals,ValidationParams[] validationParams,GenericCall[] ownerCalls,address solutionApprover,uint256 nonce,uint256 deadline,string metadata)'
    'ERC20Allowance(address token,uint160 amount)' 'ERC721Approval(address token,uint256 tokenId)'
    'GenericCall(address router,uint256 value,bytes data)'
    'ValidationParams(address validator,bytes32 action,bytes beforeExecutionInput,bytes afterExecutionInput)'
  );

  /// @dev EIP-712 hash of the order
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
        order.deadline,
        keccak256(bytes(order.metadata))
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
        order.deadline,
        keccak256(bytes(order.metadata))
      )
    );
  }
}
