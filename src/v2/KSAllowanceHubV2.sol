// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {IKSAllowanceHubV2} from './interfaces/IKSAllowanceHubV2.sol';
import {IOrderAuthenticator} from './interfaces/IOrderAuthenticator.sol';

import {MsgSender} from '../base/MsgSender.sol';

import {AuthDelegator} from './AuthDelegator.sol';
import {CallsForwarder} from './CallsForwarder.sol';

import {ERC20Transfer, ERC20TransferLib} from './types/ERC20Transfer.sol';
import {ERC721Transfer, ERC721TransferLib} from './types/ERC721Transfer.sol';
import {ExecutionOrder} from './types/ExecutionOrder.sol';
import {ExecutionWitnessLib} from './types/ExecutionWitness.sol';
import {FulfillmentOrder} from './types/FulfillmentOrder.sol';
import {FulfillmentSolution} from './types/FulfillmentSolution.sol';
import {FulfillmentWitnessLib} from './types/FulfillmentWitness.sol';
import {GenericCall, GenericCallLib} from './types/GenericCall.sol';
import {NativeTransfer} from './types/NativeTransfer.sol';
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
 * @notice Single approval target for KyberSwap: pulls a user's ERC20s and ERC721s and hands them
 * to whitelisted routers in one transaction, so users approve this hub instead of every router.
 * @dev The owner signs one order struct — {ExecutionOrder} or {FulfillmentOrder} — which pins what
 * may move, where to, and the `relayer` or `solver` who may submit it. Only the ERC20 pull rail is
 * the submitter's: the delegated entry points take it as an argument, and the Permit2-signature ones
 * have no choice to make.
 *
 * An order is authenticated either by the owner's own Permit2 signature, which carries the order
 * as its witness, or by an {IOrderAuthenticator} the owner delegated through {AuthDelegator}. An
 * owner submitting on their own behalf needs no authenticator; on the Permit2 rails they still
 * sign, with no witness to bind.
 *
 * A fulfillment splits in two: the owner fixes `ownerCalls` and the validators, while a
 * {FulfillmentSolution} supplies the route, approved by the `solutionApprover` the order names.
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
  using ERC20TransferLib for ERC20Transfer[];
  using ERC721TransferLib for ERC721Transfer[];
  using GenericCallLib for GenericCall[];
  using ValidationParamsLib for ValidationParams[];
  using CalldataDecoder for bytes;

  /// @notice Only routers holding this role may be called by a settled order
  bytes32 internal constant WHITELISTED_ROUTER_ROLE = keccak256('WHITELISTED_ROUTER_ROLE');

  /**
   * @notice Stands in for "the owner named nobody": any caller may submit the order, and on
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
    // Guardians can drop a compromised router without waiting on the admin
    _setRoleRevoker(WHITELISTED_ROUTER_ROLE, KSRoles.GUARDIAN_ROLE);

    PERMIT2 = permit2;
  }

  /// @inheritdoc IKSAllowanceHubV2
  function executeOrderWithDelegatedAuthentication(
    address owner,
    ExecutionOrder calldata order,
    address authenticator,
    bytes calldata authenticationData,
    bool usePermit2Allowances
  )
    external
    payable
    whenNotPaused
    checkDeadline(order.deadline)
    lock(owner)
    guardNativeSpend
    checkDelegation(owner, authenticator)
    returns (bytes[] memory results)
  {
    // Being the caller is the owner's own authentication; anyone else must present a credential
    if (msg.sender != owner) {
      IOrderAuthenticator(authenticator).authenticateExecution(owner, order, authenticationData);
    }

    _announceTransfers(
      owner,
      order.hash(),
      order.erc20Transfers,
      order.erc721Transfers,
      order.genericCalls.toNativeTransfers()
    );

    _transferERC20s(owner, order.erc20Transfers, usePermit2Allowances);
    return _settleExecution(owner, order);
  }

  /// @inheritdoc IKSAllowanceHubV2
  function executeOrderWithPermit2Signature(
    address owner,
    ExecutionOrder calldata order,
    bytes calldata permit2Signature
  )
    external
    payable
    whenNotPaused
    checkDeadline(order.deadline)
    lock(owner)
    guardNativeSpend
    returns (bytes[] memory results)
  {
    _announceTransfers(
      owner,
      order.hash(),
      order.erc20Transfers,
      order.erc721Transfers,
      order.genericCalls.toNativeTransfers()
    );

    // Self-submitted: nothing to bind, since the owner is already the caller. Relayed: the order
    // goes in as the witness, which is what stops a relayer altering it
    if (msg.sender == owner) {
      _permitTransferFrom(
        owner, order.erc20Transfers, order.nonce, order.deadline, permit2Signature
      );
    } else if (msg.sender == order.relayer || order.relayer == DEAD_ADDRESS) {
      bytes32 witness = ExecutionWitnessLib.hash(
        order.relayer,
        order.erc20Transfers.extractTargets(),
        order.erc721Transfers,
        order.genericCalls
      );

      _permitWitnessTransferFrom(
        owner,
        order.erc20Transfers,
        order.nonce,
        order.deadline,
        witness,
        ExecutionWitnessLib.EXECUTION_WITNESS_PERMIT2_TYPE_STRING,
        permit2Signature
      );
    } else {
      revert UnauthorizedRelayer(msg.sender, order.relayer);
    }

    return _settleExecution(owner, order);
  }

  /// @inheritdoc IKSAllowanceHubV2
  function fulfillOrderWithDelegatedAuthentication(
    address owner,
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
    lock(owner)
    guardNativeSpend
    checkDelegation(owner, authenticator)
    returns (bytes[] memory results)
  {
    // Being the caller is the owner's own authentication; anyone else must present a credential
    if (msg.sender != owner) {
      IOrderAuthenticator(authenticator).authenticateFulfillment(owner, order, authenticationData);
    }

    bytes32 orderHash = order.hash();
    // The sentinel means the owner accepted any route, so there is no approval to check
    if (order.solutionApprover != DEAD_ADDRESS) {
      _approveSolution(owner, order.solutionApprover, orderHash, solution, solutionSignature);
    }

    // Snapshot before anything moves, so a validator measures the whole order and not just its tail
    bytes[] memory beforeExecutionOutputs = order.validationParams.beforeExecution();

    _announceTransfers(
      owner,
      orderHash,
      order.erc20Transfers,
      order.erc721Transfers,
      solution.solverCalls.toNativeTransfers(order.ownerCalls)
    );

    _transferERC20s(owner, order.erc20Transfers, usePermit2Allowances);
    return _settleFulfillment(owner, order, solution, beforeExecutionOutputs);
  }

  /// @inheritdoc IKSAllowanceHubV2
  function fulfillOrderWithPermit2Signature(
    address owner,
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
    lock(owner)
    guardNativeSpend
    returns (bytes[] memory results)
  {
    bytes32 orderHash = order.hash();
    // The sentinel means the owner accepted any route, so there is no approval to check
    if (order.solutionApprover != DEAD_ADDRESS) {
      _approveSolution(owner, order.solutionApprover, orderHash, solution, solutionSignature);
    }

    // Snapshot before anything moves, so a validator measures the whole order and not just its tail
    bytes[] memory beforeExecutionOutputs = order.validationParams.beforeExecution();

    _announceTransfers(
      owner,
      orderHash,
      order.erc20Transfers,
      order.erc721Transfers,
      solution.solverCalls.toNativeTransfers(order.ownerCalls)
    );

    // Self-submitted: nothing to bind, since the owner is already the caller. Relayed: the order
    // goes in as the witness, which is what stops a solver altering it
    if (msg.sender == owner) {
      _permitTransferFrom(
        owner, order.erc20Transfers, order.nonce, order.deadline, permit2Signature
      );
    } else if (msg.sender == order.solver || order.solver == DEAD_ADDRESS) {
      bytes32 witness = FulfillmentWitnessLib.hash(
        order.solver,
        order.erc20Transfers.extractTargets(),
        order.erc721Transfers,
        order.ownerCalls,
        order.validationParams,
        order.solutionApprover
      );

      _permitWitnessTransferFrom(
        owner,
        order.erc20Transfers,
        order.nonce,
        order.deadline,
        witness,
        FulfillmentWitnessLib.FULFILLMENT_WITNESS_PERMIT2_TYPE_STRING,
        permit2Signature
      );
    } else {
      revert UnauthorizedSolver(msg.sender, order.solver);
    }

    return _settleFulfillment(owner, order, solution, beforeExecutionOutputs);
  }

  /// @dev The one {TransferTokens} emit site, so neither rail carries its own copy of the encoder
  function _announceTransfers(
    address owner,
    bytes32 orderHash,
    ERC20Transfer[] calldata erc20Transfers,
    ERC721Transfer[] calldata erc721Transfers,
    NativeTransfer[] memory nativeTransfers
  ) internal {
    emit TransferTokens(
      msg.sender, owner, orderHash, erc20Transfers, erc721Transfers, nativeTransfers
    );
  }

  /// @dev Permit2 signature transfer by the owner themselves, so there is nothing to witness
  function _permitTransferFrom(
    address owner,
    ERC20Transfer[] calldata erc20Transfers,
    uint256 nonce,
    uint256 deadline,
    bytes calldata signature
  ) internal {
    ISignatureTransfer.PermitBatchTransferFrom memory permit =
      erc20Transfers.toPermitBatchTransferFrom(nonce, deadline);
    ISignatureTransfer.SignatureTransferDetails[] memory details =
      erc20Transfers.toSignatureTransferDetails();

    ISignatureTransfer(PERMIT2).permitTransferFrom(permit, details, owner, signature);
  }

  /// @dev Permit2 signature transfer for a relayed order, with the order bound in as the witness
  function _permitWitnessTransferFrom(
    address owner,
    ERC20Transfer[] calldata erc20Transfers,
    uint256 nonce,
    uint256 deadline,
    bytes32 witness,
    string memory witnessTypeString,
    bytes calldata signature
  ) internal {
    ISignatureTransfer.PermitBatchTransferFrom memory permit =
      erc20Transfers.toPermitBatchTransferFrom(nonce, deadline);
    ISignatureTransfer.SignatureTransferDetails[] memory details =
      erc20Transfers.toSignatureTransferDetails();

    ISignatureTransfer(PERMIT2)
      .permitWitnessTransferFrom(permit, details, owner, witness, witnessTypeString, signature);
  }

  /// @dev Recovers the solution approver and checks it is the one the order named
  function _approveSolution(
    address owner,
    address solutionApprover,
    bytes32 orderHash,
    FulfillmentSolution calldata solution,
    bytes calldata solutionSignature
  ) internal {
    _useUnorderedNonce(owner, solution.nonce);

    bytes32 digest = _hashTypedDataV4(SolutionApprovalLib.hash(owner, orderHash, solution));
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

  /**
   * @dev Shared tail of both execution rails: the NFT leg, then the order's calls. The ERC20s
   * have already moved by here, which is the only thing the two rails do differently.
   */
  function _settleExecution(address owner, ExecutionOrder calldata order)
    internal
    returns (bytes[] memory results)
  {
    order.erc721Transfers.execute(owner);

    results = new bytes[](order.genericCalls.length);
    _executeCalls(order.genericCalls, results, 0);
  }

  /// @dev Shared tail of both fulfillment rails, as {_settleExecution} is for an execution
  function _settleFulfillment(
    address owner,
    FulfillmentOrder calldata order,
    FulfillmentSolution calldata solution,
    bytes[] memory beforeExecutionOutputs
  ) internal returns (bytes[] memory results) {
    order.erc721Transfers.execute(owner);

    // The validators bound what the solver did, so they run before the owner's tail acts on it
    results = new bytes[](solution.solverCalls.length + order.ownerCalls.length);
    _executeCalls(solution.solverCalls, results, 0);
    order.validationParams.afterExecution(beforeExecutionOutputs);
    _executeCalls(order.ownerCalls, results, solution.solverCalls.length);
  }

  /// @dev Runs one call list into `results` from `offset`, checking each router role as it goes
  function _executeCalls(GenericCall[] calldata calls, bytes[] memory results, uint256 offset)
    internal
  {
    for (uint256 i = 0; i < calls.length; i++) {
      _checkRole(WHITELISTED_ROUTER_ROLE, calls[i].router);
      results[offset + i] = calls[i].execute();
    }
  }
}
