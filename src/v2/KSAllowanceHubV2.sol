// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {MsgSender} from '../base/MsgSender.sol';

import {AuthDelegator} from './AuthDelegator.sol';
import {CallsForwarder} from './CallsForwarder.sol';

import {IKSAllowanceHubV2} from './interfaces/IKSAllowanceHubV2.sol';
import {IOrderAuthenticator} from './interfaces/IOrderAuthenticator.sol';

import {DynamicArrayLibExt} from './libraries/DynamicArrayLibExt.sol';

import {ERC20Allowance, ERC20AllowanceLib} from './types/ERC20Allowance.sol';
import {ERC20Transfer, ERC20TransferLib} from './types/ERC20Transfer.sol';
import {ERC721Approval, ERC721ApprovalLib} from './types/ERC721Approval.sol';
import {ERC721Transfer, ERC721TransferLib} from './types/ERC721Transfer.sol';
import {ExecutionOrder} from './types/ExecutionOrder.sol';
import {ExecutionWitnessLib} from './types/ExecutionWitness.sol';
import {FulfillmentOrder} from './types/FulfillmentOrder.sol';
import {FulfillmentSolution} from './types/FulfillmentSolution.sol';
import {FulfillmentWitnessLib} from './types/FulfillmentWitness.sol';
import {GenericCall, GenericCallLib} from './types/GenericCall.sol';
import {SolutionApprovalLib} from './types/SolutionApproval.sol';
import {ValidationParams, ValidationParamsLib} from './types/ValidationParams.sol';

import {ManagementBase} from 'ks-common-sc/src/base/ManagementBase.sol';
import {ManagementPausable} from 'ks-common-sc/src/base/ManagementPausable.sol';
import {ManagementRescuable} from 'ks-common-sc/src/base/ManagementRescuable.sol';

import {IAllowanceTransfer} from 'ks-common-sc/src/interfaces/IAllowanceTransfer.sol';
import {ISignatureTransfer} from 'ks-common-sc/src/interfaces/ISignatureTransfer.sol';

import {KSRoles} from 'ks-common-sc/src/libraries/KSRoles.sol';

import {CalldataDecoder} from 'ks-common-sc/src/libraries/calldata/CalldataDecoder.sol';

import {
  SignatureChecker
} from 'openzeppelin-contracts/contracts/utils/cryptography/SignatureChecker.sol';

/**
 * @title KSAllowanceHubV2
 * @notice Single approval target for KyberSwap: pulls a user's ERC20s and ERC721s and passes them
 * to whitelisted routers in one transaction, so users approve this hub instead of every router.
 * @dev The owner signs one order struct — {ExecutionOrder} or {FulfillmentOrder} — which fixes
 * what may move and the `relayer` or `solver` who may submit it. An execution order also fixes
 * where each leg goes; a fulfillment order leaves that to its solution. Only the ERC20 pull rail
 * is the submitter's: the delegated entry points take it as an argument, and the
 * Permit2-signature ones have no choice to make.
 *
 * An order is authenticated either by the owner's own Permit2 signature, which carries the order
 * as its witness, or by an {IOrderAuthenticator} the owner delegated through {AuthDelegator}. An
 * owner submitting on their own behalf needs no authenticator; on the Permit2 rails they still
 * sign, with no witness to bind.
 *
 * A fulfillment splits in two: the owner fixes `ownerCalls` and the validators, while a
 * {FulfillmentSolution} supplies the route and the target of each leg, approved by the
 * `solutionApprover` the order names.
 * The validators run between the two, so they bound the solver's work before the owner's tail
 * acts on it.
 */
contract KSAllowanceHubV2 is
  IKSAllowanceHubV2,
  ManagementPausable,
  ManagementRescuable,
  AuthDelegator,
  CallsForwarder,
  MsgSender
{
  using CalldataDecoder for bytes;
  using DynamicArrayLibExt for *;
  using ERC20AllowanceLib for ERC20Allowance[];
  using ERC20TransferLib for ERC20Transfer[];
  using ERC721ApprovalLib for ERC721Approval[];
  using ERC721TransferLib for ERC721Transfer[];
  using GenericCallLib for GenericCall[];
  using ValidationParamsLib for ValidationParams[];

  /// @notice Only routers holding this role may be called by a settled order
  bytes32 internal constant WHITELISTED_ROUTER_ROLE = keccak256('WHITELISTED_ROUTER_ROLE');

  /**
   * @notice Sentinel for an order that names no counterparty: any caller may submit it, and on
   * `solutionApprover` any route is accepted without an approval signature
   */
  address internal constant DEAD_ADDRESS = 0x000000000000000000000000000000000000dEaD;

  address internal immutable PERMIT2;

  /**
   * @param initialAdmin Holder of the default admin role
   * @param initialGuardians Accounts that may pause the hub and revoke routers
   * @param initialRescuers Accounts that may sweep assets stranded in the hub
   * @param initialWhitelistedRouters Routers callable from the start
   * @param permit2 The canonical Permit2 deployment
   */
  constructor(
    address initialAdmin,
    address[] memory initialGuardians,
    address[] memory initialRescuers,
    address[] memory initialWhitelistedRouters,
    address permit2
  )
    ManagementBase(0, initialAdmin)
    ManagementPausable(initialGuardians)
    ManagementRescuable(initialRescuers)
    AuthDelegator('KyberSwap Allowance Hub', '2.0.0')
  {
    _batchGrantRole(WHITELISTED_ROUTER_ROLE, initialWhitelistedRouters);
    // Guardians may revoke a compromised router without waiting for the admin
    _setRoleRevoker(WHITELISTED_ROUTER_ROLE, KSRoles.GUARDIAN_ROLE);

    PERMIT2 = permit2;
  }

  /// @inheritdoc IKSAllowanceHubV2
  function executeOrderWithDelegatedAuthentication(
    ExecutionOrder calldata order,
    address authenticator,
    bytes calldata authenticationData,
    bool usePermit2Allowances
  )
    external
    payable
    whenNotPaused
    checkDeadline(order.deadline)
    lock(order.owner)
    checkDelegation(order.owner, authenticator)
    guardNativeSpend
    returns (bytes[] memory results)
  {
    bytes32 orderHash = order.hash();
    // Being the caller is the owner's own authentication; anyone else must present a credential
    if (msg.sender != order.owner) {
      if (msg.sender != order.relayer && order.relayer != DEAD_ADDRESS) {
        revert UnauthorizedRelayer(msg.sender);
      }
      IOrderAuthenticator(authenticator).authenticateExecution(order, orderHash, authenticationData);
    }

    _announceExecution(order, orderHash);

    _transferERC20s(order.owner, order.erc20Transfers, usePermit2Allowances);
    return _settleExecution(order);
  }

  /// @inheritdoc IKSAllowanceHubV2
  function executeOrderWithPermit2Signature(
    ExecutionOrder calldata order,
    bytes calldata permit2Signature
  )
    external
    payable
    whenNotPaused
    checkDeadline(order.deadline)
    lock(order.owner)
    guardNativeSpend
    returns (bytes[] memory results)
  {
    _announceExecution(order, order.hash());

    // Self-submitted: nothing to bind, since the order.owner is already the caller. Relayed: the
    // order is bound in as the witness, so a relayer cannot alter it
    ISignatureTransfer.PermitBatchTransferFrom memory permit =
      order.erc20Transfers.toPermitBatchTransferFrom(order.nonce, order.deadline);
    ISignatureTransfer.SignatureTransferDetails[] memory details =
      order.erc20Transfers.toSignatureTransferDetails();

    if (msg.sender == order.owner) {
      _permitTransferFrom(order.owner, permit, details, permit2Signature);
    } else if (msg.sender == order.relayer || order.relayer == DEAD_ADDRESS) {
      bytes32 witness = ExecutionWitnessLib.hash(
        order.relayer, order.erc20Transfers.targetsHash(), order.erc721Transfers, order.genericCalls
      );

      _permitWitnessTransferFrom(
        order.owner,
        permit,
        details,
        witness,
        ExecutionWitnessLib.EXECUTION_WITNESS_PERMIT2_TYPE_STRING,
        permit2Signature
      );
    } else {
      revert UnauthorizedRelayer(msg.sender);
    }

    return _settleExecution(order);
  }

  /// @inheritdoc IKSAllowanceHubV2
  function fulfillOrderWithDelegatedAuthentication(
    FulfillmentOrder calldata order,
    address authenticator,
    bytes calldata authenticationData,
    FulfillmentSolution calldata solution,
    bytes calldata solutionSignature,
    bool usePermit2Allowances
  )
    external
    payable
    whenNotPaused
    checkDeadline(order.deadline)
    checkDeadline(solution.deadline)
    checkLengths(solution.erc20Targets.length, order.erc20Allowances.length)
    checkLengths(solution.erc721Targets.length, order.erc721Approvals.length)
    lock(order.owner)
    checkDelegation(order.owner, authenticator)
    guardNativeSpend
    returns (bytes[] memory results)
  {
    bytes32 orderHash = order.hash();
    // Being the caller is the owner's own authentication; anyone else must present a credential
    if (msg.sender != order.owner) {
      if (msg.sender != order.solver && order.solver != DEAD_ADDRESS) {
        revert UnauthorizedSolver(msg.sender);
      }
      IOrderAuthenticator(authenticator)
        .authenticateFulfillment(order, orderHash, authenticationData);
    }

    // The sentinel means the order.owner accepted any route, so there is no approval to check
    if (order.solutionApprover != DEAD_ADDRESS) {
      _approveSolution(order.solutionApprover, orderHash, solution, solutionSignature);
    }

    // Snapshot before anything moves, so a validator measures the whole order and not just its tail
    bytes[] memory beforeExecutionOutputs = order.validationParams.beforeExecution();

    _announceFulfillment(order, orderHash, solution);
    _transferERC20s(order.owner, order.erc20Allowances, solution.erc20Targets, usePermit2Allowances);
    return _settleFulfillment(order, solution, beforeExecutionOutputs);
  }

  /// @inheritdoc IKSAllowanceHubV2
  function fulfillOrderWithPermit2Signature(
    FulfillmentOrder calldata order,
    bytes calldata permit2Signature,
    FulfillmentSolution calldata solution,
    bytes calldata solutionSignature
  )
    external
    payable
    whenNotPaused
    checkDeadline(order.deadline)
    checkDeadline(solution.deadline)
    checkLengths(solution.erc20Targets.length, order.erc20Allowances.length)
    checkLengths(solution.erc721Targets.length, order.erc721Approvals.length)
    lock(order.owner)
    guardNativeSpend
    returns (bytes[] memory results)
  {
    bytes32 orderHash = order.hash();
    // The sentinel means the order.owner accepted any route, so there is no approval to check
    if (order.solutionApprover != DEAD_ADDRESS) {
      _approveSolution(order.solutionApprover, orderHash, solution, solutionSignature);
    }

    // Snapshot before anything moves, so a validator measures the whole order and not just its tail
    bytes[] memory beforeExecutionOutputs = order.validationParams.beforeExecution();

    _announceFulfillment(order, orderHash, solution);

    ISignatureTransfer.PermitBatchTransferFrom memory permit =
      order.erc20Allowances.toPermitBatchTransferFrom(order.nonce, order.deadline);
    ISignatureTransfer.SignatureTransferDetails[] memory details =
      order.erc20Allowances.toSignatureTransferDetails(solution.erc20Targets);

    // Self-submitted: nothing to bind, since the order.owner is already the caller. Relayed: the
    // order is bound in as the witness, so a solver cannot alter it
    if (msg.sender == order.owner) {
      _permitTransferFrom(order.owner, permit, details, permit2Signature);
    } else if (msg.sender == order.solver || order.solver == DEAD_ADDRESS) {
      bytes32 witness = FulfillmentWitnessLib.hash(
        order.solver,
        order.erc721Approvals,
        order.ownerCalls,
        order.validationParams,
        order.solutionApprover
      );

      _permitWitnessTransferFrom(
        order.owner,
        permit,
        details,
        witness,
        FulfillmentWitnessLib.FULFILLMENT_WITNESS_PERMIT2_TYPE_STRING,
        permit2Signature
      );
    } else {
      revert UnauthorizedSolver(msg.sender);
    }

    return _settleFulfillment(order, solution, beforeExecutionOutputs);
  }

  /// @dev {TransferTokens} for an execution, whose legs are emitted from calldata as signed
  function _announceExecution(ExecutionOrder calldata order, bytes32 orderHash) internal {
    emit TransferTokens(
      msg.sender,
      order.owner,
      orderHash,
      order.erc20Transfers,
      order.erc721Transfers,
      order.genericCalls.toNativeTransfers()
    );
  }

  /// @dev {TransferTokens} for a fulfillment, with each leg paired with the target the solution
  /// names for it
  function _announceFulfillment(
    FulfillmentOrder calldata order,
    bytes32 orderHash,
    FulfillmentSolution calldata solution
  ) internal {
    emit TransferTokens(
      msg.sender,
      order.owner,
      orderHash,
      order.erc20Allowances.toTransfers(solution.erc20Targets),
      order.erc721Approvals.toTransfers(solution.erc721Targets),
      solution.solverCalls.toNativeTransfers(order.ownerCalls)
    );
  }

  /// @dev Permit2 signature transfer by the owner themselves, so there is nothing to witness
  function _permitTransferFrom(
    address owner,
    ISignatureTransfer.PermitBatchTransferFrom memory permit,
    ISignatureTransfer.SignatureTransferDetails[] memory details,
    bytes calldata signature
  ) internal {
    ISignatureTransfer(PERMIT2).permitTransferFrom(permit, details, owner, signature);
  }

  /// @dev Permit2 signature transfer for a relayed order, with the order bound in as the witness
  function _permitWitnessTransferFrom(
    address owner,
    ISignatureTransfer.PermitBatchTransferFrom memory permit,
    ISignatureTransfer.SignatureTransferDetails[] memory details,
    bytes32 witness,
    string memory witnessTypeString,
    bytes calldata signature
  ) internal {
    ISignatureTransfer(PERMIT2)
      .permitWitnessTransferFrom(permit, details, owner, witness, witnessTypeString, signature);
  }

  /// @dev Checks that the approver the order named signed `solution` for the order
  function _approveSolution(
    address solutionApprover,
    bytes32 orderHash,
    FulfillmentSolution calldata solution,
    bytes calldata solutionSignature
  ) internal view {
    bytes32 digest = _hashTypedDataV4(SolutionApprovalLib.hash(orderHash, solution));
    if (!SignatureChecker.isValidSignatureNow(solutionApprover, digest, solutionSignature)) {
      revert InvalidSolutionSignature();
    }
  }

  /// @dev Pulls the ERC20s over Permit2's allowance rail, or over a plain approval to this hub
  function _transferERC20s(
    address owner,
    ERC20Transfer[] calldata erc20Transfers,
    bool usePermit2Allowances
  ) internal {
    if (usePermit2Allowances) {
      IAllowanceTransfer.AllowanceTransferDetails[] memory details =
        erc20Transfers.toAllowanceTransferDetails(owner);
      IAllowanceTransfer(PERMIT2).transferFrom(details);
    } else {
      erc20Transfers.execute(owner);
    }
  }

  /// @dev As {_transferERC20s}, for a fulfillment's allowances and the targets its solution names
  function _transferERC20s(
    address owner,
    ERC20Allowance[] calldata erc20Allowances,
    address[] calldata targets,
    bool usePermit2Allowances
  ) internal {
    if (usePermit2Allowances) {
      IAllowanceTransfer.AllowanceTransferDetails[] memory details =
        erc20Allowances.toAllowanceTransferDetails(owner, targets);
      IAllowanceTransfer(PERMIT2).transferFrom(details);
    } else {
      erc20Allowances.execute(owner, targets);
    }
  }

  /**
   * @dev Shared tail of both execution rails: the NFT leg, then the order's calls. The ERC20s
   * have already moved by this point, and that is the only difference between the two rails.
   */
  function _settleExecution(ExecutionOrder calldata order)
    internal
    returns (bytes[] memory results)
  {
    order.erc721Transfers.execute(order.owner);

    results = order.genericCalls.length.mallocBytes();
    _executeCalls(order.genericCalls, results, 0);
  }

  /// @dev Shared tail of both fulfillment rails, as {_settleExecution} is for an execution
  function _settleFulfillment(
    FulfillmentOrder calldata order,
    FulfillmentSolution calldata solution,
    bytes[] memory beforeExecutionOutputs
  ) internal returns (bytes[] memory results) {
    order.erc721Approvals.execute(order.owner, solution.erc721Targets);

    results = (solution.solverCalls.length + order.ownerCalls.length).mallocBytes();
    _executeCalls(solution.solverCalls, results, 0);

    // The validators bound what the solver did, so they run before the owner's own tail
    order.validationParams.afterExecution(beforeExecutionOutputs);

    _executeCalls(order.ownerCalls, results, solution.solverCalls.length);
  }

  /// @dev Runs one call list into `results` from `offset`, checking each router role in turn
  function _executeCalls(GenericCall[] calldata calls, bytes[] memory results, uint256 offset)
    internal
  {
    for (uint256 i = 0; i < calls.length; i++) {
      _checkRole(WHITELISTED_ROUTER_ROLE, calls[i].router);
      results[offset + i] = calls[i].execute();
    }
  }
}
