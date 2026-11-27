// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

import {IKSAllowanceHubV2} from './interfaces/IKSAllowanceHubV2.sol';
import {IAHV2Authenticator} from './interfaces/base/IAHV2Authenticator.sol';

import {AuthDelegator} from './base/AuthDelegator.sol';
import {Multicall} from './base/Multicall.sol';
import {SettlementContext} from './base/SettlementContext.sol';

import {Constants} from './libraries/Constants.sol';
import {MallocBytesLib} from './libraries/MallocBytesLib.sol';

import {AHV2Order} from './types/AHV2Order.sol';
import {AHV2Solution} from './types/AHV2Solution.sol';
import {CallParams, CallParamsLib} from './types/CallParams.sol';
import {ERC20Allowance, ERC20AllowanceLib} from './types/ERC20Allowance.sol';
import {ERC20Transfer} from './types/ERC20Transfer.sol';
import {ERC721Approval, ERC721ApprovalLib} from './types/ERC721Approval.sol';
import {ERC721Transfer} from './types/ERC721Transfer.sol';
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
  using ERC20AllowanceLib for ERC20Allowance[];
  using ERC721ApprovalLib for ERC721Approval[];
  using MallocBytesLib for uint256;
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
    bytes calldata solutionSignature
  )
    external
    payable
    whenNotPaused
    setSettlementContext(order.owner)
    guardNativeSpend
    returns (bytes[] memory results)
  {
    _checkExpiration(order, solution);

    bytes32 orderHash = order.hash();

    // The owner bypasses `order.exclusiveCaller`, and the zero address allows any caller
    if (
      msg.sender != order.owner && msg.sender != order.exclusiveCaller
        && order.exclusiveCaller != Constants.ADDRESS_ZERO
    ) {
      revert NotExclusiveCallerOrOwner(msg.sender);
    }

    // The zero address requires the owner's EIP-712 signature over the order. The Permit2 address
    // requires the owner's Permit2 signature. Any other address must be an {IAHV2Authenticator}
    // that the owner has delegated.
    if (order.authenticator == Constants.ADDRESS_ZERO) {
      if (msg.sender == order.owner && authenticationData.length == 0) {
        // The owner may call without a signature. A non-zero nonce is then spent and a zero nonce
        // is not, so an order with a zero nonce may settle more than once.
        if (order.nonce != 0) {
          _useUnorderedNonce(order.owner, order.nonce);
        }
      } else {
        // A caller other than the owner, or the owner passing data, must give the owner's
        // signature over the order. The check spends `order.nonce` in the owner's namespace, so
        // each signed order settles at most once.
        if (!_verifySignature(order.owner, order.nonce, orderHash, authenticationData)) {
          revert InvalidOrderSignature();
        }
      }
    } else {
      if (order.authenticator != PERMIT2) {
        // The owner must have delegated the authenticator. The hub spends no `order.nonce`, so the
        // authenticator determines whether an order may be settled more than once. The owner has
        // not signed `solution`, so the hub passes it to the authenticator for checking.
        if (!authDelegated[order.owner][order.authenticator]) {
          revert AuthenticatorNotDelegated(order.authenticator);
        }
        IAHV2Authenticator(order.authenticator)
          .authenticate(order, orderHash, solution, authenticationData);
      }
      // On the Permit2 signature transfer flow, Permit2 checks the owner's signature when the ERC20
      // tokens move
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

    // On the Permit2 signature transfer flow the hooks run before Permit2 checks the owner's
    // signature
    bytes[] memory beforeSettlementResults = order.beforeSettlement(orderHash, solution);

    emit SettleOrder(
      msg.sender,
      order.owner,
      orderHash,
      order.erc20Allowances.toTransfers(solution.erc20Targets, solution.erc20Amounts),
      order.erc721Approvals.toTransfers(solution.erc721Targets),
      order.calls.toNativeTransfers(solution.callValues),
      order.clientData
    );

    // On the Permit2 signature transfer flow, the permit's nonce is `order.nonce` and its deadline
    // is `order.expiration`, so Permit2 provides the replay protection. When another account calls,
    // the owner's signature also covers the order.
    if (order.authenticator == PERMIT2) {
      order.executeSignatureTransfer(orderHash, solution, authenticationData, PERMIT2);
    } else {
      // The high byte of `order.flags` divides the ERC20 transfers between the owner's Permit2
      // allowance and the owner's allowance to the hub
      order.erc20Allowances
        .execute(
          order.owner,
          solution.erc20Targets,
          solution.erc20Amounts,
          order.flags >> Constants.PERMIT2_TRANSFERS_OFFSET,
          PERMIT2
        );
    }

    order.erc721Approvals.execute(order.owner, solution.erc721Targets);

    // One `solverData` entry for each call.
    if (solution.solverData.length != order.calls.length) {
      revert MismatchedArrayLengths();
    }

    results = order.calls.length.mallocBytes();
    for (uint256 i = 0; i < order.calls.length; i++) {
      _checkRole(Constants.WHITELISTED_CALLEE_ROLE, order.calls[i].callee);
      results[i] = order.calls[i].execute(solution.callValues[i], solution.solverData[i]);
    }

    order.afterSettlement(orderHash, solution, beforeSettlementResults);
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
    ERC20Transfer[] memory erc20Transfers,
    ERC721Transfer[] calldata erc721Transfers
  ) external onlyRoleOrDefaultAdmin(KSRoles.RESCUER_ROLE) {
    for (uint256 i = 0; i < erc20Transfers.length; i++) {
      ERC20Transfer memory transfer = erc20Transfers[i];
      // A `token` of the native-token address or the zero address transfers native value. A zero
      // `amount` transfers the whole balance of `token`. A zero `target` is not refused.
      if (transfer.amount == 0) {
        transfer.amount = transfer.token.selfBalance();
      }
      transfer.token.safeTransfer(transfer.target, transfer.amount);
    }

    for (uint256 i = 0; i < erc721Transfers.length; i++) {
      ERC721Transfer calldata transfer = erc721Transfers[i];
      IERC721(transfer.token).safeTransferFrom(address(this), transfer.target, transfer.tokenId);
    }

    emit RescueTokens(erc20Transfers, erc721Transfers);
  }

  /// @dev Reverts when the expiration of `order` or of `solution` has passed
  function _checkExpiration(AHV2Order calldata order, AHV2Solution calldata solution)
    internal
    view
  {
    // A call at the expiration is accepted
    if (block.timestamp > order.expiration) {
      revert OrderExpired(order.expiration, block.timestamp);
    }
    if (block.timestamp > solution.expiration) {
      revert SolutionExpired(solution.expiration, block.timestamp);
    }
  }
}
