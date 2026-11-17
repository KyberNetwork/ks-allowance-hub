// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

import {IKSAllowanceHubV2} from './interfaces/IKSAllowanceHubV2.sol';
import {IAHV2Authenticator} from './interfaces/base/IAHV2Authenticator.sol';

import {AuthDelegator} from './base/AuthDelegator.sol';
import {MsgSender} from './base/MsgSender.sol';
import {Multicall} from './base/Multicall.sol';

import {Constants} from './libraries/Constants.sol';
import {DynamicArrayLibExt} from './libraries/DynamicArrayLibExt.sol';

import {AHV2Order} from './types/AHV2Order.sol';
import {AHV2Solution} from './types/AHV2Solution.sol';
import {AHV2WitnessLib} from './types/AHV2Witness.sol';
import {CallParams, CallParamsLib} from './types/CallParams.sol';
import {ERC20Allowance, ERC20AllowanceLib} from './types/ERC20Allowance.sol';
import {ERC20Transfer} from './types/ERC20Transfer.sol';
import {ERC721Approval, ERC721ApprovalLib} from './types/ERC721Approval.sol';
import {ERC721Transfer, ERC721TransferLib} from './types/ERC721Transfer.sol';
import {HookParams, HookParamsLib} from './types/HookParams.sol';
import {SolutionApprovalLib} from './types/SolutionApproval.sol';

import {IMulticall3} from 'forge-std/interfaces/IMulticall3.sol';

import {ManagementSimple} from 'ks-common-sc/src/base/ManagementSimple.sol';

import {ISignatureTransfer} from 'ks-common-sc/src/interfaces/ISignatureTransfer.sol';

import {KSRoles} from 'ks-common-sc/src/libraries/KSRoles.sol';
import {TokenHelper} from 'ks-common-sc/src/libraries/token/TokenHelper.sol';

import {
  SignatureChecker
} from 'openzeppelin-contracts/contracts/utils/cryptography/SignatureChecker.sol';

/**
 * @title KSAllowanceHubV2
 * @notice Single approval target for KyberSwap. It transfers an owner's ERC20 and ERC721 tokens
 * and calls whitelisted callees in one transaction. The owner approves this contract instead of
 * each callee.
 * @dev The owner signs an {AHV2Order}, which specifies the assets that may leave the owner, the
 * account that may submit the order, the hooks that constrain the result and the callee calls the
 * owner fixes. An {AHV2Solution} supplies the targets and amounts of the transfers, the callee
 * calls of the route and the data of each owner call. The solution is not signed by the owner; the
 * order's solution approver may be required to approve it.
 *
 * A settlement calls each hook's `beforeSettlement` before any asset moves, moves the assets, calls
 * the callees of the solution through {IAHV2SolverCallee-solverCall}, calls the callees of the
 * order through {IAHV2OwnerCallee-ownerCall}, and calls each hook's `afterSettlement`.
 *
 * An order is authorized either by the owner's Permit2 signature, which signs the order as its
 * witness, or by an {IAHV2Authenticator} the owner has delegated through {AuthDelegator}. An
 * owner who submits their own order needs no witness and no authenticator.
 *
 * While an order settles, {msgSender} returns its owner. A callee call of an order may settle
 * another order, and {msgSender} returns the outer order's owner again once it returns.
 */
contract KSAllowanceHubV2 is
  IKSAllowanceHubV2,
  ManagementSimple,
  AuthDelegator,
  Multicall,
  MsgSender
{
  using CallParamsLib for CallParams[];
  using DynamicArrayLibExt for uint256;
  using ERC20AllowanceLib for ERC20Allowance[];
  using ERC721ApprovalLib for ERC721Approval[];
  using ERC721TransferLib for ERC721Transfer[];
  using HookParamsLib for HookParams[];
  using TokenHelper for address;

  address internal immutable PERMIT2;

  address internal immutable MULTICALL3;

  /// @dev Runs {AHV2OrderLib-checkSettlement} before the function body
  modifier checkSettlement(AHV2Order calldata order, AHV2Solution calldata solution) {
    order.checkSettlement(solution);
    _;
  }

  /**
   * @param initialAdmin Holder of the default admin role
   * @param initialGuardians Accounts that may pause the hub and revoke callees
   * @param initialRescuers Accounts that may transfer assets held by the hub
   * @param initialWhitelistedCallees Callees callable from the start
   * @param permit2 The canonical Permit2 deployment
   * @param multicall3 The Multicall3 deployment that {forwardCalls} calls
   */
  constructor(
    address initialAdmin,
    address[] memory initialGuardians,
    address[] memory initialRescuers,
    address[] memory initialWhitelistedCallees,
    address permit2,
    address multicall3
  )
    ManagementSimple(initialAdmin, initialGuardians)
    AuthDelegator('KyberSwap Allowance Hub', '2.0.0')
  {
    _batchGrantRole(KSRoles.RESCUER_ROLE, initialRescuers);

    _batchGrantRole(Constants.WHITELISTED_CALLEE_ROLE, initialWhitelistedCallees);
    // Guardians may revoke a callee without the admin
    _setRoleRevoker(Constants.WHITELISTED_CALLEE_ROLE, KSRoles.GUARDIAN_ROLE);

    PERMIT2 = permit2;
    MULTICALL3 = multicall3;
  }

  /// @inheritdoc IKSAllowanceHubV2
  function settleOrderWithDelegatedAuthentication(
    AHV2Order calldata order,
    address authenticator,
    bytes calldata authenticationData,
    AHV2Solution calldata solution,
    bytes calldata solutionSignature,
    bool usePermit2Allowances
  )
    external
    payable
    whenNotPaused
    checkSettlement(order, solution)
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
      if (msg.sender != order.exclusiveCaller && order.exclusiveCaller != Constants.DEAD_ADDRESS) {
        revert NotExclusiveCaller(msg.sender);
      }

      IAHV2Authenticator(authenticator).authenticate(order, orderHash, solution, authenticationData);

      if (order.solutionApprover != Constants.DEAD_ADDRESS) {
        _checkSolutionApproval(order.solutionApprover, orderHash, solution, solutionSignature);
      }
    }

    // Runs before any asset moves; each hook reads the state before settlement
    bytes[] memory beforeSettlementResults =
      order.hooks.beforeSettlement(order, orderHash, solution);

    order.announce(orderHash, solution);

    if (usePermit2Allowances) {
      order.erc20Allowances
        .executePermit2(order.owner, solution.erc20Targets, solution.erc20Amounts, PERMIT2);
    } else {
      order.erc20Allowances.execute(order.owner, solution.erc20Targets, solution.erc20Amounts);
    }

    return _settle(order, orderHash, solution, beforeSettlementResults);
  }

  /// @inheritdoc IKSAllowanceHubV2
  function settleOrderWithPermit2Signature(
    AHV2Order calldata order,
    bytes calldata permit2Signature,
    AHV2Solution calldata solution,
    bytes calldata solutionSignature
  )
    external
    payable
    whenNotPaused
    checkSettlement(order, solution)
    setMsgSender(order.owner)
    guardNativeSpend
    returns (bytes[] memory results)
  {
    (
      bytes32 orderHash,
      bytes32 erc721ApprovalsHash,
      bytes32 hooksHash,
      bytes32 ownerCallsHash,
      bytes32 clientDataHash
    ) = order.membersHash();

    // The owner's call approves its own solution, and a dead-address approver accepts any solution
    if (msg.sender != order.owner && order.solutionApprover != Constants.DEAD_ADDRESS) {
      _checkSolutionApproval(order.solutionApprover, orderHash, solution, solutionSignature);
    }

    // Runs before any asset moves; each hook reads the state before settlement
    bytes[] memory beforeSettlementResults =
      order.hooks.beforeSettlement(order, orderHash, solution);

    order.announce(orderHash, solution);

    ISignatureTransfer.PermitBatchTransferFrom memory permit =
      order.erc20Allowances.toPermitBatchTransferFrom(order.nonce, order.expiration);
    ISignatureTransfer.SignatureTransferDetails[] memory details =
      order.erc20Allowances.toSignatureTransferDetails(solution.erc20Targets, solution.erc20Amounts);

    // The owner signs the permit alone; for any other caller the order is signed as the witness
    if (msg.sender == order.owner) {
      ISignatureTransfer(PERMIT2).permitTransferFrom(permit, details, order.owner, permit2Signature);
    } else if (
      msg.sender == order.exclusiveCaller || order.exclusiveCaller == Constants.DEAD_ADDRESS
    ) {
      bytes32 witness = AHV2WitnessLib.hash(
        order.exclusiveCaller,
        erc721ApprovalsHash,
        hooksHash,
        ownerCallsHash,
        order.solutionApprover,
        clientDataHash
      );

      ISignatureTransfer(PERMIT2)
        .permitWitnessTransferFrom(
          permit,
          details,
          order.owner,
          witness,
          AHV2WitnessLib.AHV2_WITNESS_PERMIT2_TYPE_STRING,
          permit2Signature
        );
    } else {
      revert NotExclusiveCaller(msg.sender);
    }

    return _settle(order, orderHash, solution, beforeSettlementResults);
  }

  /// @inheritdoc IKSAllowanceHubV2
  function forwardCalls(IMulticall3.Call3[] calldata calls)
    external
    payable
    returns (IMulticall3.Result[] memory results)
  {
    return IMulticall3(MULTICALL3).aggregate3(calls);
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
    AHV2Solution calldata solution,
    bytes calldata solutionSignature
  ) internal {
    _useUnorderedNonce(solutionApprover, solution.nonce);

    bytes32 digest = _hashTypedDataV4(SolutionApprovalLib.hash(orderHash, solution));
    if (!SignatureChecker.isValidSignatureNow(solutionApprover, digest, solutionSignature)) {
      revert InvalidSolutionSignature();
    }
  }

  /**
   * @dev Makes the ERC721 transfers, runs the solver's calls, runs the owner's calls and runs
   * the hooks' `afterSettlement`
   */
  function _settle(
    AHV2Order calldata order,
    bytes32 orderHash,
    AHV2Solution calldata solution,
    bytes[] memory beforeSettlementResults
  ) internal returns (bytes[] memory results) {
    order.erc721Approvals.execute(order.owner, solution.erc721Targets);

    results = (solution.solverCalls.length + order.ownerCalls.length).mallocBytes();
    _executeSolverCalls(solution.solverCalls, results);
    _executeOwnerCalls(order.ownerCalls, solution.solverData, results, solution.solverCalls.length);

    // The hooks check the result of the solver's and the owner's calls
    order.hooks.afterSettlement(order, orderHash, solution, beforeSettlementResults);
  }

  /// @dev Runs `calls` through `solverCall`, writing their return data to `results`; each callee
  /// must hold the whitelisted callee role
  function _executeSolverCalls(CallParams[] calldata calls, bytes[] memory results) internal {
    for (uint256 i = 0; i < calls.length; i++) {
      _checkRole(Constants.WHITELISTED_CALLEE_ROLE, calls[i].callee);
      results[i] = calls[i].executeSolverCall();
    }
  }

  /// @dev Runs `calls` through `ownerCall` with the matching entry of `solverData`, writing their
  /// return data to `results` from `offset`; each callee must hold the whitelisted callee role
  function _executeOwnerCalls(
    CallParams[] calldata calls,
    bytes[] calldata solverData,
    bytes[] memory results,
    uint256 offset
  ) internal {
    for (uint256 i = 0; i < calls.length; i++) {
      _checkRole(Constants.WHITELISTED_CALLEE_ROLE, calls[i].callee);
      results[offset + i] = calls[i].executeOwnerCall(solverData[i]);
    }
  }
}
