// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

import {MsgSender} from './base/MsgSender.sol';

import {Constants} from './libraries/Constants.sol';

import {PackedBits} from './types/base/PackedBits.sol';

import {AuthDelegator} from './base/AuthDelegator.sol';
import {Multicall} from './base/Multicall.sol';

import {ICallsForwarder} from './interfaces/ICallsForwarder.sol';
import {IKSAllowanceHubV2} from './interfaces/IKSAllowanceHubV2.sol';
import {IOrderAuthenticator} from './interfaces/authenticators/IOrderAuthenticator.sol';

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

import {ISignatureTransfer} from 'ks-common-sc/src/interfaces/ISignatureTransfer.sol';

import {KSRoles} from 'ks-common-sc/src/libraries/KSRoles.sol';
import {CalldataDecoder} from 'ks-common-sc/src/libraries/calldata/CalldataDecoder.sol';
import {TokenHelper} from 'ks-common-sc/src/libraries/token/TokenHelper.sol';

import {
  SignatureChecker
} from 'openzeppelin-contracts/contracts/utils/cryptography/SignatureChecker.sol';

import {EfficientHashLib} from 'solady/utils/EfficientHashLib.sol';

/**
 * @title KSAllowanceHubV2
 * @notice Single approval target for KyberSwap. It transfers an owner's ERC20 and ERC721 tokens
 * and calls whitelisted routers in one transaction, so that the owner approves this contract
 * instead of each router.
 * @dev The owner signs an {ExecutionOrder} or a {FulfillmentOrder}. Both specify the assets that
 * may leave the owner and the account that may submit the order. An execution order also specifies
 * the target of each transfer and the exact router calls; a fulfillment order leaves both to a
 * {FulfillmentSolution} and constrains the result with validators.
 *
 * An order is authorised either by the owner's Permit2 signature, which signs the order as its
 * witness, or by an {IOrderAuthenticator} the owner has delegated through {AuthDelegator}. An
 * owner who submits their own order needs no witness and no authenticator.
 *
 * While an order settles, {msgSender} returns its owner. A router call of an order may settle
 * another order of either type, and {msgSender} returns the outer order's owner again once it
 * returns.
 */
contract KSAllowanceHubV2 is
  IKSAllowanceHubV2,
  ManagementSimple,
  AuthDelegator,
  Multicall,
  MsgSender
{
  using CalldataDecoder for bytes;
  using DynamicArrayLibExt for uint256;
  using EfficientHashLib for bytes;
  using ERC20AllowanceLib for ERC20Allowance[];
  using ERC20TransferLib for ERC20Transfer[];
  using ERC721ApprovalLib for ERC721Approval[];
  using ERC721TransferLib for ERC721Transfer[];
  using GenericCallLib for GenericCall[];
  using TokenHelper for address;
  using ValidationParamsLib for ValidationParams[];

  address internal immutable PERMIT2;

  address internal immutable CALLS_FORWARDER;

  /// @dev Runs {FulfillmentOrderLib-checkFulfillment} before the function body
  modifier checkFulfillment(
    FulfillmentOrder calldata order,
    FulfillmentSolution calldata solution
  ) {
    order.checkFulfillment(solution);
    _;
  }

  /**
   * @param initialAdmin Holder of the default admin role
   * @param initialGuardians Accounts that may pause the hub and revoke routers
   * @param initialRescuers Accounts that may transfer assets held by the hub
   * @param initialWhitelistedRouters Routers callable from the start
   * @param permit2 The canonical Permit2 deployment
   * @param callsForwarder The {CallsForwarder} that {forwardCalls} relays through
   */
  constructor(
    address initialAdmin,
    address[] memory initialGuardians,
    address[] memory initialRescuers,
    address[] memory initialWhitelistedRouters,
    address permit2,
    address callsForwarder
  )
    ManagementSimple(initialAdmin, initialGuardians)
    AuthDelegator('KyberSwap Allowance Hub', '2.0.0')
  {
    _batchGrantRole(KSRoles.RESCUER_ROLE, initialRescuers);

    _batchGrantRole(Constants.WHITELISTED_ROUTER_ROLE, initialWhitelistedRouters);
    // Guardians may revoke a router without the admin
    _setRoleRevoker(Constants.WHITELISTED_ROUTER_ROLE, KSRoles.GUARDIAN_ROLE);

    PERMIT2 = permit2;
    CALLS_FORWARDER = callsForwarder;
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
    checkDeadline(order.expiration)
    checkDelegation(order.owner, authenticator)
    setMsgSender(order.owner)
    guardNativeSpend
    returns (bytes[] memory results)
  {
    bytes32 orderHash = order.hash();
    // The owner's call is its own authentication; any other caller needs the authenticator's
    if (msg.sender != order.owner) {
      if (msg.sender != order.relayer && order.relayer != Constants.DEAD_ADDRESS) {
        revert CallerNotRelayer(msg.sender);
      }
      IOrderAuthenticator(authenticator).authenticateExecution(order, orderHash, authenticationData);
    }

    order.announce(orderHash);

    if (usePermit2Allowances) {
      order.erc20Transfers.executePermit2(order.owner, PERMIT2);
    } else {
      order.erc20Transfers.execute(order.owner);
    }

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
    checkDeadline(order.expiration)
    setMsgSender(order.owner)
    guardNativeSpend
    returns (bytes[] memory results)
  {
    (
      bytes32 orderHash,
      bytes32 erc721TransfersHash,
      bytes32 genericCallsHash,
      bytes32 extraDataHash,
      bytes32 clientDataHash
    ) = order.membersHash();
    order.announce(orderHash);

    ISignatureTransfer.PermitBatchTransferFrom memory permit =
      order.erc20Transfers.toPermitBatchTransferFrom(order.nonce, order.expiration);
    ISignatureTransfer.SignatureTransferDetails[] memory details =
      order.erc20Transfers.toSignatureTransferDetails();

    // The owner signs the permit alone; for any other caller the order is signed as the witness
    if (msg.sender == order.owner) {
      ISignatureTransfer(PERMIT2).permitTransferFrom(permit, details, order.owner, permit2Signature);
    } else if (msg.sender == order.relayer || order.relayer == Constants.DEAD_ADDRESS) {
      bytes32 witness = ExecutionWitnessLib.hash(
        order.relayer,
        order.erc20Transfers.targetsHash(),
        erc721TransfersHash,
        genericCallsHash,
        extraDataHash,
        clientDataHash
      );

      ISignatureTransfer(PERMIT2)
        .permitWitnessTransferFrom(
          permit,
          details,
          order.owner,
          witness,
          ExecutionWitnessLib.EXECUTION_WITNESS_PERMIT2_TYPE_STRING,
          permit2Signature
        );
    } else {
      revert CallerNotRelayer(msg.sender);
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
    checkFulfillment(order, solution)
    checkDelegation(order.owner, authenticator)
    setMsgSender(order.owner)
    guardNativeSpend
    returns (bytes[] memory results)
  {
    bytes32 orderHash = order.hash();
    // The owner's call is its own authentication and approves its own solution; any other caller
    // needs the authenticator's authentication and, unless the approver is the dead address, the
    // solution approval
    if (msg.sender != order.owner) {
      if (msg.sender != order.solver && order.solver != Constants.DEAD_ADDRESS) {
        revert CallerNotSolver(msg.sender);
      }
      IOrderAuthenticator(authenticator)
        .authenticateFulfillment(order, orderHash, solution, authenticationData);
      if (order.solutionApprover != Constants.DEAD_ADDRESS) {
        _checkSolutionApproval(order.solutionApprover, orderHash, solution, solutionSignature);
      }
    }

    // Run before any asset moves, so that each validator observes the state before settlement
    bytes[] memory beforeExecutionOutputs = order.validationParams.beforeExecution();

    order.announce(orderHash, solution);

    if (usePermit2Allowances) {
      order.erc20Allowances
        .executePermit2(order.owner, solution.erc20Targets, solution.erc20Amounts, PERMIT2);
    } else {
      order.erc20Allowances.execute(order.owner, solution.erc20Targets, solution.erc20Amounts);
    }

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
    checkFulfillment(order, solution)
    setMsgSender(order.owner)
    guardNativeSpend
    returns (bytes[] memory results)
  {
    (
      bytes32 orderHash,
      bytes32 erc721ApprovalsHash,
      bytes32 validationParamsHash,
      bytes32 ownerCallsHash,
      bytes32 extraDataHash,
      bytes32 clientDataHash
    ) = order.membersHash();

    // The owner's call approves its own solution, and a dead-address approver accepts any solution
    if (msg.sender != order.owner && order.solutionApprover != Constants.DEAD_ADDRESS) {
      _checkSolutionApproval(order.solutionApprover, orderHash, solution, solutionSignature);
    }

    // Run before any asset moves, so that each validator observes the state before settlement
    bytes[] memory beforeExecutionOutputs = order.validationParams.beforeExecution();

    order.announce(orderHash, solution);

    ISignatureTransfer.PermitBatchTransferFrom memory permit =
      order.erc20Allowances.toPermitBatchTransferFrom(order.nonce, order.expiration);
    ISignatureTransfer.SignatureTransferDetails[] memory details =
      order.erc20Allowances.toSignatureTransferDetails(solution.erc20Targets, solution.erc20Amounts);

    // The owner signs the permit alone; for any other caller the order is signed as the witness
    if (msg.sender == order.owner) {
      ISignatureTransfer(PERMIT2).permitTransferFrom(permit, details, order.owner, permit2Signature);
    } else if (msg.sender == order.solver || order.solver == Constants.DEAD_ADDRESS) {
      bytes32 witness = FulfillmentWitnessLib.hash(
        order.solver,
        erc721ApprovalsHash,
        ownerCallsHash,
        validationParamsHash,
        order.solutionApprover,
        extraDataHash,
        clientDataHash
      );

      ISignatureTransfer(PERMIT2)
        .permitWitnessTransferFrom(
          permit,
          details,
          order.owner,
          witness,
          FulfillmentWitnessLib.FULFILLMENT_WITNESS_PERMIT2_TYPE_STRING,
          permit2Signature
        );
    } else {
      revert CallerNotSolver(msg.sender);
    }

    return _settleFulfillment(order, solution, beforeExecutionOutputs);
  }

  /// @inheritdoc IKSAllowanceHubV2
  function forwardCalls(address[] calldata targets, bytes[] calldata data, PackedBits allowFailure)
    external
    payable
    returns (bytes[] memory results)
  {
    return ICallsForwarder(CALLS_FORWARDER).forwardCalls(targets, data, allowFailure);
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

  /// @dev Reverts unless `solutionApprover` signed `solution` for the order with hash `orderHash`,
  /// and spends `solution.nonce` in the approver's namespace
  function _checkSolutionApproval(
    address solutionApprover,
    bytes32 orderHash,
    FulfillmentSolution calldata solution,
    bytes calldata solutionSignature
  ) internal {
    _useUnorderedNonce(solutionApprover, solution.nonce);

    bytes32 digest = _hashTypedDataV4(SolutionApprovalLib.hash(orderHash, solution));
    if (!SignatureChecker.isValidSignatureNow(solutionApprover, digest, solutionSignature)) {
      revert InvalidSolutionSignature();
    }
  }

  /// @dev Executes the ERC721 transfers and runs the router calls of an execution order
  function _settleExecution(ExecutionOrder calldata order)
    internal
    returns (bytes[] memory results)
  {
    order.erc721Transfers.execute(order.owner);

    results = order.genericCalls.length.mallocBytes();
    _executeCalls(order.genericCalls, results, 0);
  }

  /**
   * @dev Executes the ERC721 transfers, runs the solver's calls, runs the validators'
   * `afterExecution` and runs the owner's calls of a fulfillment order
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
      _checkRole(Constants.WHITELISTED_ROUTER_ROLE, calls[i].router);
      results[offset + i] = calls[i].execute();
    }
  }
}
