// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ERC20Allowance, ERC20AllowanceLib} from './ERC20Allowance.sol';
import {ERC721Approval, ERC721ApprovalLib} from './ERC721Approval.sol';
import {FulfillmentSolution} from './FulfillmentSolution.sol';
import {GenericCall, GenericCallLib} from './GenericCall.sol';
import {ValidationParams, ValidationParamsLib} from './ValidationParams.sol';

import {DeadlineChecker} from '../base/DeadlineChecker.sol';
import {IKSAllowanceHubV2} from '../interfaces/IKSAllowanceHubV2.sol';

import {ICommon} from 'ks-common-sc/src/interfaces/ICommon.sol';

import {EfficientHashLib} from 'solady/utils/EfficientHashLib.sol';

/**
 * @notice An owner's order to transfer assets along a route chosen by a solver
 * @dev The order specifies neither the route, nor the targets of its transfers, nor the amounts of
 * its ERC20 transfers; a {FulfillmentSolution} supplies them. The validators constrain the result
 * of the solution, and `solutionApprover` may be required to approve it. The validators do not
 * observe the effects of `ownerCalls`.
 *
 * When `owner` submits the order, `solver` and `solutionApprover` do not apply and no
 * authentication is required beyond the call itself, except that a Permit2 entry point still
 * requires the owner's permit signature, without a witness. On a delegated entry point the owner's
 * own submission spends no nonce, so the same order may settle more than once.
 * @param owner Account the assets are transferred from
 * @param solver Account that may submit the order besides the owner; the dead address allows any
 * account
 * @param erc20Allowances ERC20 transfers, each of at most its `amount`, sent from the owner to the
 * target and in the amount the solution specifies for it
 * @param erc721Approvals ERC721 transfers, each sent from the owner to the target the solution
 * specifies for it
 * @param validationParams Validators run before the transfers are executed and after the solver's
 * calls
 * @param ownerCalls Router calls fixed by the owner, run after the validators
 * @param solutionApprover Account whose signature the solution requires when the owner does not
 * submit the order; the dead address requires none
 * @param nonce Permit2 nonce on the Permit2 entry points; on the delegated entry points, for the
 * authenticator to spend
 * @param expiration Last timestamp at which the order may settle
 * @param extraData Additional data the hub does not read, for the authenticator or other
 * contracts
 * @param clientData Data for off-chain clients, emitted in {IKSAllowanceHubV2-TransferTokens}
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
  uint256 expiration;
  bytes extraData;
  bytes clientData;
}

using FulfillmentOrderLib for FulfillmentOrder global;

library FulfillmentOrderLib {
  using EfficientHashLib for bytes;
  using ERC20AllowanceLib for ERC20Allowance[];
  using ERC721ApprovalLib for ERC721Approval[];
  using GenericCallLib for GenericCall[];
  using ValidationParamsLib for ValidationParams[];

  bytes32 internal constant FULFILLMENT_ORDER_TYPEHASH = keccak256(
    'FulfillmentOrder(address owner,address solver,ERC20Allowance[] erc20Allowances,ERC721Approval[] erc721Approvals,ValidationParams[] validationParams,GenericCall[] ownerCalls,address solutionApprover,uint256 nonce,uint256 expiration,bytes extraData,bytes clientData)'
    'ERC20Allowance(address token,uint160 amount)' 'ERC721Approval(address token,uint256 tokenId)'
    'GenericCall(address router,uint256 value,bytes data)'
    'ValidationParams(address validator,bytes32 action,bytes beforeExecutionInput,bytes afterExecutionInput)'
  );

  /// @dev EIP-712 hash of the order
  function hash(FulfillmentOrder calldata order) internal pure returns (bytes32) {
    return hash(
      order,
      order.erc721Approvals.hash(),
      order.validationParams.hash(),
      order.ownerCalls.hash(),
      order.extraData.hashCalldata(),
      order.clientData.hashCalldata()
    );
  }

  /// @dev As {hash}, from the already computed hashes of `erc721Approvals`, `validationParams`,
  /// `ownerCalls`, `extraData` and `clientData`
  function hash(
    FulfillmentOrder calldata order,
    bytes32 erc721ApprovalsHash,
    bytes32 validationParamsHash,
    bytes32 ownerCallsHash,
    bytes32 extraDataHash,
    bytes32 clientDataHash
  ) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(
        FULFILLMENT_ORDER_TYPEHASH,
        order.owner,
        order.solver,
        order.erc20Allowances.hash(),
        erc721ApprovalsHash,
        validationParamsHash,
        ownerCallsHash,
        order.solutionApprover,
        order.nonce,
        order.expiration,
        extraDataHash,
        clientDataHash
      )
    );
  }

  /// @dev As {hash}, also returning the hashes of the members the order's witness covers
  function membersHash(FulfillmentOrder calldata order)
    internal
    pure
    returns (
      bytes32 orderHash,
      bytes32 erc721ApprovalsHash,
      bytes32 validationParamsHash,
      bytes32 ownerCallsHash,
      bytes32 extraDataHash,
      bytes32 clientDataHash
    )
  {
    erc721ApprovalsHash = order.erc721Approvals.hash();
    validationParamsHash = order.validationParams.hash();
    ownerCallsHash = order.ownerCalls.hash();
    extraDataHash = order.extraData.hashCalldata();
    clientDataHash = order.clientData.hashCalldata();
    orderHash = hash(
      order,
      erc721ApprovalsHash,
      validationParamsHash,
      ownerCallsHash,
      extraDataHash,
      clientDataHash
    );
  }

  /**
   * @dev Emits {IKSAllowanceHubV2-TransferTokens} for the order with hash `orderHash`, pairing
   * each transfer with the target and amount `solution` specifies for it
   */
  function announce(
    FulfillmentOrder calldata order,
    bytes32 orderHash,
    FulfillmentSolution calldata solution
  ) internal {
    emit IKSAllowanceHubV2.TransferTokens(
      msg.sender,
      order.owner,
      orderHash,
      order.erc20Allowances.toTransfers(solution.erc20Targets, solution.erc20Amounts),
      order.erc721Approvals.toTransfers(solution.erc721Targets),
      solution.solverCalls.toNativeTransfers(order.ownerCalls),
      order.clientData
    );
  }

  /**
   * @dev Reverts when the order or `solution` has passed its expiration, or when `solution` does
   * not specify one target for each transfer and one amount for each ERC20 transfer
   */
  function checkFulfillment(FulfillmentOrder calldata order, FulfillmentSolution calldata solution)
    internal
    view
  {
    _checkDeadline(order.expiration);
    _checkDeadline(solution.expiration);
    _checkLengths(solution.erc20Targets.length, order.erc20Allowances.length);
    _checkLengths(solution.erc20Amounts.length, order.erc20Allowances.length);
    _checkLengths(solution.erc721Targets.length, order.erc721Approvals.length);
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
        order.expiration,
        keccak256(order.extraData),
        keccak256(order.clientData)
      )
    );
  }

  /// @dev Reverts when the current block timestamp is later than `deadline`
  function _checkDeadline(uint256 deadline) private view {
    if (block.timestamp > deadline) {
      revert DeadlineChecker.DeadlinePassed(deadline, block.timestamp);
    }
  }

  /// @dev Reverts when `length1` and `length2` differ
  function _checkLengths(uint256 length1, uint256 length2) private pure {
    if (length1 != length2) {
      revert ICommon.MismatchedArrayLengths();
    }
  }
}
