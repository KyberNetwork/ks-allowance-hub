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

import {ManagementSimple} from 'ks-common-sc/src/base/ManagementSimple.sol';

import {IAllowanceTransfer} from 'ks-common-sc/src/interfaces/IAllowanceTransfer.sol';
import {ISignatureTransfer} from 'ks-common-sc/src/interfaces/ISignatureTransfer.sol';

import {KSRoles} from 'ks-common-sc/src/libraries/KSRoles.sol';
import {CalldataDecoder} from 'ks-common-sc/src/libraries/calldata/CalldataDecoder.sol';
import {TokenHelper} from 'ks-common-sc/src/libraries/token/TokenHelper.sol';

import {
  SignatureChecker
} from 'openzeppelin-contracts/contracts/utils/cryptography/SignatureChecker.sol';

/**
 * @title KSAllowanceHubV2
 * @notice Single approval target for KyberSwap. It transfers an owner's ERC20 and ERC721 tokens
 * and calls whitelisted routers in one transaction, so that the owner approves this contract
 * instead of each router.
 * @dev The owner signs an {ExecutionOrder} or a {FulfillmentOrder}. Both name the assets that may
 * leave the owner and the account that may submit the order. An execution order also names the
 * target of each leg and the exact router calls; a fulfillment order leaves both to a
 * {FulfillmentSolution} and constrains the result with validators.
 *
 * An order is authorised either by the owner's Permit2 signature, which signs the order as its
 * witness, or by an {IOrderAuthenticator} the owner has delegated through {AuthDelegator}. An
 * owner who submits their own order needs no witness and no authenticator.
 *
 * While an order settles, {msgSender} returns its owner, and no other order may settle.
 */
contract KSAllowanceHubV2 is
  IKSAllowanceHubV2,
  ManagementSimple,
  AuthDelegator,
  CallsForwarder,
  MsgSender
{
  using CalldataDecoder for bytes;
  using DynamicArrayLibExt for uint256;
  using ERC20AllowanceLib for ERC20Allowance[];
  using ERC20TransferLib for ERC20Transfer[];
  using ERC721ApprovalLib for ERC721Approval[];
  using ERC721TransferLib for ERC721Transfer[];
  using GenericCallLib for GenericCall[];
  using TokenHelper for address;
  using ValidationParamsLib for ValidationParams[];

  /// @notice Role a router must hold to be called by an order
  bytes32 internal constant WHITELISTED_ROUTER_ROLE = keccak256('WHITELISTED_ROUTER_ROLE');

  /**
   * @notice Value of `relayer` or `solver` that allows any caller to submit the order, and of
   * `solutionApprover` that accepts any solution without an approval
   */
  address internal constant DEAD_ADDRESS = 0x000000000000000000000000000000000000dEaD;

  address internal immutable PERMIT2;

  /**
   * @param initialAdmin Holder of the default admin role
   * @param initialGuardians Accounts that may pause the hub and revoke routers
   * @param initialRescuers Accounts that may transfer assets held by the hub
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
    ManagementSimple(initialAdmin, initialGuardians)
    AuthDelegator('KyberSwap Allowance Hub', '2.0.0')
  {
    _batchGrantRole(KSRoles.RESCUER_ROLE, initialRescuers);

    _batchGrantRole(WHITELISTED_ROUTER_ROLE, initialWhitelistedRouters);
    // Guardians may revoke a router without the admin
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
    // The owner's call is its own authentication; any other caller needs the authenticator's
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

    ISignatureTransfer.PermitBatchTransferFrom memory permit =
      order.erc20Transfers.toPermitBatchTransferFrom(order.nonce, order.deadline);
    ISignatureTransfer.SignatureTransferDetails[] memory details =
      order.erc20Transfers.toSignatureTransferDetails();

    // The owner signs the permit alone; for any other caller the order is signed as the witness
    if (msg.sender == order.owner) {
      _permitTransferFrom(order.owner, permit, details, permit2Signature);
    } else if (msg.sender == order.relayer || order.relayer == DEAD_ADDRESS) {
      bytes32 witness = ExecutionWitnessLib.hash(
        order.relayer,
        order.erc20Transfers.targetsHash(),
        order.erc721Transfers,
        order.genericCalls,
        order.metadata
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
    // The owner's call is its own authentication; any other caller needs the authenticator's
    if (msg.sender != order.owner) {
      if (msg.sender != order.solver && order.solver != DEAD_ADDRESS) {
        revert UnauthorizedSolver(msg.sender);
      }
      IOrderAuthenticator(authenticator)
        .authenticateFulfillment(order, orderHash, authenticationData);
    }

    // A dead-address approver accepts any solution
    if (order.solutionApprover != DEAD_ADDRESS) {
      _approveSolution(order.solutionApprover, orderHash, solution, solutionSignature);
    }

    // Run before any asset moves, so that each validator observes the state before settlement
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
    // A dead-address approver accepts any solution
    if (order.solutionApprover != DEAD_ADDRESS) {
      _approveSolution(order.solutionApprover, orderHash, solution, solutionSignature);
    }

    // Run before any asset moves, so that each validator observes the state before settlement
    bytes[] memory beforeExecutionOutputs = order.validationParams.beforeExecution();

    _announceFulfillment(order, orderHash, solution);

    ISignatureTransfer.PermitBatchTransferFrom memory permit =
      order.erc20Allowances.toPermitBatchTransferFrom(order.nonce, order.deadline);
    ISignatureTransfer.SignatureTransferDetails[] memory details =
      order.erc20Allowances.toSignatureTransferDetails(solution.erc20Targets);

    // The owner signs the permit alone; for any other caller the order is signed as the witness
    if (msg.sender == order.owner) {
      _permitTransferFrom(order.owner, permit, details, permit2Signature);
    } else if (msg.sender == order.solver || order.solver == DEAD_ADDRESS) {
      bytes32 witness = FulfillmentWitnessLib.hash(
        order.solver,
        order.erc721Approvals,
        order.ownerCalls,
        order.validationParams,
        order.solutionApprover,
        order.metadata
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

  /// @inheritdoc IKSAllowanceHubV2
  function rescueTokens(
    ERC20Transfer[] calldata erc20Transfers,
    ERC721Transfer[] calldata erc721Transfers
  ) external onlyRoleOrDefaultAdmin(KSRoles.RESCUER_ROLE) {
    for (uint256 i = 0; i < erc20Transfers.length; i++) {
      ERC20Transfer calldata transfer = erc20Transfers[i];
      uint256 amount = transfer.amount == 0 ? transfer.token.selfBalance() : transfer.amount;
      transfer.token.safeTransfer(transfer.target, amount);
    }
    erc721Transfers.execute(address(this));

    emit RescueTokens(erc20Transfers, erc721Transfers);
  }

  /// @dev Emits {TransferTokens} for an execution order
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

  /// @dev Emits {TransferTokens} for a fulfillment order, pairing each leg with the target the
  /// solution names for it
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

  /// @dev Transfers the ERC20 legs through a Permit2 permit signed without a witness
  function _permitTransferFrom(
    address owner,
    ISignatureTransfer.PermitBatchTransferFrom memory permit,
    ISignatureTransfer.SignatureTransferDetails[] memory details,
    bytes calldata signature
  ) internal {
    ISignatureTransfer(PERMIT2).permitTransferFrom(permit, details, owner, signature);
  }

  /// @dev Transfers the ERC20 legs through a Permit2 permit that also signs `witness`
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

  /// @dev Reverts unless `solutionApprover` signed `solution` for the order with hash `orderHash`
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

  /// @dev Transfers the ERC20 legs from `owner` through Permit2 allowances or allowances to this hub
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

  /// @dev Transfers the ERC721 legs and runs the router calls of an execution order
  function _settleExecution(ExecutionOrder calldata order)
    internal
    returns (bytes[] memory results)
  {
    order.erc721Transfers.execute(order.owner);

    results = order.genericCalls.length.mallocBytes();
    _executeCalls(order.genericCalls, results, 0);
  }

  /**
   * @dev Transfers the ERC721 legs, runs the solver's calls, runs the validators' `afterExecution`
   * and runs the owner's calls of a fulfillment order
   */
  function _settleFulfillment(
    FulfillmentOrder calldata order,
    FulfillmentSolution calldata solution,
    bytes[] memory beforeExecutionOutputs
  ) internal returns (bytes[] memory results) {
    order.erc721Approvals.execute(order.owner, solution.erc721Targets);

    results = (solution.solverCalls.length + order.ownerCalls.length).mallocBytes();
    _executeCalls(solution.solverCalls, results, 0);

    // The validators check the result of the solver's calls, before the owner's calls run
    order.validationParams.afterExecution(beforeExecutionOutputs);

    _executeCalls(order.ownerCalls, results, solution.solverCalls.length);
  }

  /// @dev Runs `calls` in order, writing their return data to `results` from `offset`; each router
  /// must hold the whitelisted router role
  function _executeCalls(GenericCall[] calldata calls, bytes[] memory results, uint256 offset)
    internal
  {
    for (uint256 i = 0; i < calls.length; i++) {
      _checkRole(WHITELISTED_ROUTER_ROLE, calls[i].router);
      results[offset + i] = calls[i].execute();
    }
  }
}
