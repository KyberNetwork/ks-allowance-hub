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
import {ERC721Transfer} from './types/ERC721Transfer.sol';
import {HookParams, HookParamsLib} from './types/HookParams.sol';
import {SolutionApprovalLib} from './types/SolutionApproval.sol';

import {IMulticall3} from 'forge-std/interfaces/IMulticall3.sol';

import {ManagementSimple} from 'ks-common-sc/src/base/ManagementSimple.sol';

import {ISignatureTransfer} from 'ks-common-sc/src/interfaces/ISignatureTransfer.sol';

import {KSRoles} from 'ks-common-sc/src/libraries/KSRoles.sol';
import {TokenHelper} from 'ks-common-sc/src/libraries/token/TokenHelper.sol';

import {IERC721} from 'openzeppelin-contracts/contracts/token/ERC721/IERC721.sol';
import {
  SignatureChecker
} from 'openzeppelin-contracts/contracts/utils/cryptography/SignatureChecker.sol';

/**
 * @title KSAllowanceHubV2
 * @notice Single approval target for KyberSwap. It transfers an owner's ERC20 and ERC721 tokens
 * and calls whitelisted callees in one transaction. The owner approves this contract instead of
 * each callee.
 * @dev The owner signs an {AHV2Order}, and a solver supplies an {AHV2Solution} for it. The
 * order's `authenticator` selects how it is authorized: by the owner's signature over the order,
 * by the owner's Permit2 signature, or by an {IAHV2Authenticator} the owner has delegated through
 * {AuthDelegator}.
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
  using HookParamsLib for HookParams[];
  using TokenHelper for address;

  address internal immutable PERMIT2;

  address internal immutable MULTICALL3;

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
  function settleOrder(
    AHV2Order calldata order,
    bytes calldata authenticationData,
    AHV2Solution calldata solution,
    bytes calldata solutionSignature,
    bool usePermit2Allowances
  )
    external
    payable
    whenNotPaused
    setMsgSender(order.owner)
    guardNativeSpend
    returns (bytes[] memory results)
  {
    // The order and the solution must not have expired, and the solution must fit the order
    order.checkSettlement(solution);

    (
      bytes32 orderHash,
      bytes32 erc721ApprovalsHash,
      bytes32 hooksHash,
      bytes32 ownerCallsHash,
      bytes32 clientDataHash
    ) = order.membersHash();

    // The owner's call is its own authorization and approves its own solution: no signature is
    // checked, no delegation is required, no authenticator is called, `order.exclusiveCaller` is
    // ignored and no nonce is spent, so the owner may settle the same order more than once. On the
    // Permit2 flow, the owner's Permit2 signature still authorizes the ERC20 transfers below.
    if (msg.sender != order.owner) {
      // Any other caller must be the exclusive caller, or any account when the exclusive caller is
      // the zero address
      if (msg.sender != order.exclusiveCaller && order.exclusiveCaller != Constants.ADDRESS_ZERO) {
        revert NotExclusiveCaller(msg.sender);
      }

      if (order.authenticator == Constants.ADDRESS_ZERO) {
        // The owner's signature over the order spends `order.nonce` in the owner's namespace, so
        // each signed order settles at most once
        _useUnorderedNonce(order.owner, order.nonce);
        if (!SignatureChecker.isValidSignatureNow(
            order.owner, _hashTypedDataV4(orderHash), authenticationData
          )) {
          revert InvalidOrderSignature();
        }
      } else if (order.authenticator != PERMIT2) {
        // The owner must have delegated the authenticator. The hub spends no `order.nonce`, so the
        // authenticator determines whether an order may be settled more than once. The owner has
        // not signed `solution`, so the authenticator reads it here when it needs to.
        if (!authDelegated[order.owner][order.authenticator]) {
          revert AuthenticatorNotDelegated(order.authenticator);
        }
        IAHV2Authenticator(order.authenticator)
          .authenticate(order, orderHash, solution, authenticationData);
      }
      // On the Permit2 flow, Permit2 checks the owner's signature when the ERC20 tokens move

      // The approval is not required when the approver is the zero address. Otherwise it spends
      // `solution.nonce` in the approver's namespace, so each approval settles at most once.
      if (order.solutionApprover != Constants.ADDRESS_ZERO) {
        _checkSolutionApproval(order.solutionApprover, orderHash, solution, solutionSignature);
      }
    }

    // Runs before any asset moves, and on the Permit2 flow before Permit2 checks the owner's
    // signature; each hook reads the state before settlement
    bytes[] memory beforeSettlementResults =
      order.hooks.beforeSettlement(order, orderHash, solution);

    // Emitted before the assets move and the calls run
    order.announce(orderHash, solution);

    // Each ERC20 transfer sends `solution.erc20Amounts[i]`, at most its allowance
    if (order.authenticator == PERMIT2) {
      _transferWithPermit2Signature(
        order,
        solution,
        authenticationData,
        erc721ApprovalsHash,
        hooksHash,
        ownerCallsHash,
        clientDataHash
      );
    } else if (usePermit2Allowances) {
      order.erc20Allowances
        .executePermit2(order.owner, solution.erc20Targets, solution.erc20Amounts, PERMIT2);
    } else {
      order.erc20Allowances.execute(order.owner, solution.erc20Targets, solution.erc20Amounts);
    }

    // The ERC721 transfers precede the solver's calls, the solver's calls precede the owner's
    // calls, and the hooks' `afterSettlement` runs last
    order.erc721Approvals.execute(order.owner, solution.erc721Targets);

    // Return data of the solver's calls first, then of the owner's calls
    results = (solution.solverCalls.length + order.ownerCalls.length).mallocBytes();
    _executeSolverCalls(solution.solverCalls, results);
    _executeOwnerCalls(order.ownerCalls, solution.solverData, results, solution.solverCalls.length);

    order.hooks.afterSettlement(order, orderHash, solution, beforeSettlementResults);
  }

  /// @inheritdoc IKSAllowanceHubV2
  function forwardCalls(IMulticall3.Call3[] calldata calls)
    external
    payable
    returns (IMulticall3.Result[] memory results)
  {
    // Lets a {multicall} batch include calls to other contracts. Neither the pause state nor the
    // caller is checked, and native value sent with the call remains in the hub.
    return IMulticall3(MULTICALL3).aggregate3(calls);
  }

  /// @inheritdoc IKSAllowanceHubV2
  function rescueTokens(
    ERC20Transfer[] calldata erc20Transfers,
    ERC721Transfer[] calldata erc721Transfers
  ) external onlyRoleOrDefaultAdmin(KSRoles.RESCUER_ROLE) {
    for (uint256 i = 0; i < erc20Transfers.length; i++) {
      ERC20Transfer calldata transfer = erc20Transfers[i];
      // A token that is the native-token address or the zero address transfers native value, and
      // a zero `amount` transfers the whole balance. A zero `target` is not refused.
      uint256 amount = transfer.amount == 0 ? transfer.token.selfBalance() : transfer.amount;
      transfer.token.safeTransfer(transfer.target, amount);
    }

    for (uint256 i = 0; i < erc721Transfers.length; i++) {
      ERC721Transfer calldata transfer = erc721Transfers[i];
      IERC721(transfer.token).safeTransferFrom(address(this), transfer.target, transfer.tokenId);
    }

    emit RescueTokens(erc20Transfers, erc721Transfers);
  }

  /// @dev Transfers the order's ERC20 tokens to the solution's targets with the owner's Permit2
  /// signature; the signature also covers the order's witness when the caller is not the owner
  function _transferWithPermit2Signature(
    AHV2Order calldata order,
    AHV2Solution calldata solution,
    bytes calldata permit2Signature,
    bytes32 erc721ApprovalsHash,
    bytes32 hooksHash,
    bytes32 ownerCallsHash,
    bytes32 clientDataHash
  ) internal {
    // The permit's nonce is `order.nonce` and its deadline is `order.expiration`, so Permit2
    // provides the replay protection. Its permitted amounts are the order's allowances.
    ISignatureTransfer.PermitBatchTransferFrom memory permit =
      order.erc20Allowances.toPermitBatchTransferFrom(order.nonce, order.expiration);
    ISignatureTransfer.SignatureTransferDetails[] memory details =
      order.erc20Allowances.toSignatureTransferDetails(solution.erc20Targets, solution.erc20Amounts);

    // The owner's signature covers the permit alone when the owner calls, and also the order's
    // witness when another account calls
    if (msg.sender == order.owner) {
      ISignatureTransfer(PERMIT2).permitTransferFrom(permit, details, order.owner, permit2Signature);
    } else {
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
    }
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

  /// @dev Runs `calls` as the solver's calls, writing their return data to `results`; each callee
  /// must hold the whitelisted callee role
  function _executeSolverCalls(CallParams[] calldata calls, bytes[] memory results) internal {
    for (uint256 i = 0; i < calls.length; i++) {
      _checkRole(Constants.WHITELISTED_CALLEE_ROLE, calls[i].callee);
      results[i] = calls[i].executeSolverCall();
    }
  }

  /// @dev Runs `calls` as the owner's calls with the matching entry of `solverData`, writing their
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
