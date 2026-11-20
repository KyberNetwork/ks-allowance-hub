// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

import {IKSAllowanceHubV2} from './interfaces/IKSAllowanceHubV2.sol';
import {IAHV2Authenticator} from './interfaces/base/IAHV2Authenticator.sol';

import {AuthDelegator} from './base/AuthDelegator.sol';
import {Multicall} from './base/Multicall.sol';
import {SettlementContext} from './base/SettlementContext.sol';

import {Constants} from './libraries/Constants.sol';
import {DynamicArrayLibExt} from './libraries/DynamicArrayLibExt.sol';

import {AHV2Order} from './types/AHV2Order.sol';
import {AHV2Solution} from './types/AHV2Solution.sol';
import {CallParams, CallParamsLib} from './types/CallParams.sol';
import {ERC20Allowance, ERC20AllowanceLib} from './types/ERC20Allowance.sol';
import {ERC20Transfer} from './types/ERC20Transfer.sol';
import {ERC721Approval, ERC721ApprovalLib} from './types/ERC721Approval.sol';
import {ERC721Transfer} from './types/ERC721Transfer.sol';
import {HookParams, HookParamsLib} from './types/HookParams.sol';
import {SolutionApprovalLib} from './types/SolutionApproval.sol';

import {IMulticall3} from 'forge-std/interfaces/IMulticall3.sol';

import {ManagementSimple} from 'ks-common-sc/src/base/ManagementSimple.sol';

import {KSRoles} from 'ks-common-sc/src/libraries/KSRoles.sol';
import {TokenHelper} from 'ks-common-sc/src/libraries/token/TokenHelper.sol';

import {IERC721} from 'openzeppelin-contracts/contracts/token/ERC721/IERC721.sol';

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
contract KSAllowanceHubV2 is IKSAllowanceHubV2, AuthDelegator, Multicall, SettlementContext {
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
    setSettlementContext(order.owner)
    guardNativeSpend
    returns (bytes[] memory results)
  {
    order.checkSettlement(solution);

    bytes32 orderHash = order.hash();

    // The owner bypasses `order.exclusiveCaller`, and the zero address allows any caller
    if (
      msg.sender != order.owner && msg.sender != order.exclusiveCaller
        && order.exclusiveCaller != Constants.ADDRESS_ZERO
    ) {
      revert NotExclusiveCallerOrOwner(msg.sender);
    }

    // The zero address requires the owner's EIP-712 signature over the order, the Permit2 address
    // the owner's Permit2 signature, and any other address a delegated {IAHV2Authenticator}
    if (order.authenticator == Constants.ADDRESS_ZERO) {
      if (msg.sender == order.owner) {
        // The owner's own call needs no signature. A zero nonce is not spent, so the order may
        // settle more than once.
        if (authenticationData.length != 0) {
          revert UnexpectedSignature();
        }
        if (order.nonce != 0) {
          _useUnorderedNonce(order.owner, order.nonce);
        }
      } else {
        // The owner's signature over the order spends `order.nonce` in the owner's namespace, so
        // each signed order settles at most once
        if (!_verifySignature(order.owner, order.nonce, orderHash, authenticationData)) {
          revert InvalidOrderSignature();
        }
      }
    } else {
      if (order.authenticator != PERMIT2) {
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
    }

    // Required from every caller when `order.solutionApprover` is set. The approval spends
    // `solution.nonce` in the approver's namespace.
    if (order.solutionApprover != Constants.ADDRESS_ZERO) {
      bytes32 approvalHash = SolutionApprovalLib.hash(orderHash, solution);
      if (!_verifySignature(
          order.solutionApprover, solution.nonce, approvalHash, solutionSignature
        )) {
        revert InvalidSolutionSignature();
      }
    }

    // On the Permit2 flow the hooks run before Permit2 checks the owner's signature
    bytes[] memory beforeSettlementResults =
      order.hooks.beforeSettlement(order, orderHash, solution);

    emit SettleOrder(
      msg.sender,
      order.owner,
      orderHash,
      order.erc20Allowances.toTransfers(solution.erc20Targets, solution.erc20Amounts),
      order.erc721Approvals.toTransfers(solution.erc721Targets),
      order.calls.toNativeTransfers(solution.callValues),
      order.clientData
    );

    // On the Permit2 flow, the permit's nonce is `order.nonce` and its deadline is
    // `order.expiration`, so Permit2 provides the replay protection. When another account calls,
    // the owner's signature also covers the order.
    if (order.authenticator == PERMIT2) {
      order.executeSignatureTransfer(orderHash, solution, authenticationData, PERMIT2);
    } else if (usePermit2Allowances) {
      order.erc20Allowances
        .executeAllowanceTransfer(
          order.owner, solution.erc20Targets, solution.erc20Amounts, PERMIT2
        );
    } else {
      order.erc20Allowances
        .executeERC20Transfer(order.owner, solution.erc20Targets, solution.erc20Amounts);
    }

    order.erc721Approvals.execute(order.owner, solution.erc721Targets);

    results = order.calls.length.mallocBytes();
    for (uint256 i = 0; i < order.calls.length; i++) {
      _checkRole(Constants.WHITELISTED_CALLEE_ROLE, order.calls[i].callee);
      results[i] = order.calls[i].execute(solution.callValues[i], solution.solverData[i]);
    }

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
}
