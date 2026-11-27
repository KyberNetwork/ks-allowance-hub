// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IKSAllowanceHubV2} from '../interfaces/IKSAllowanceHubV2.sol';
import {IAHV2Hook} from '../interfaces/base/IAHV2Hook.sol';

import {Constants} from '../libraries/Constants.sol';
import {MallocBytesLib} from '../libraries/MallocBytesLib.sol';

import {AHV2Solution} from './AHV2Solution.sol';
import {CallParams, CallParamsLib} from './CallParams.sol';
import {ERC20Allowance, ERC20AllowanceLib} from './ERC20Allowance.sol';
import {ERC721Approval, ERC721ApprovalLib} from './ERC721Approval.sol';
import {HookParams, HookParamsLib} from './HookParams.sol';

import {ISignatureTransfer} from 'ks-common-sc/src/interfaces/ISignatureTransfer.sol';

import {EfficientHashLib} from 'solady/utils/EfficientHashLib.sol';

/**
 * @notice An owner's order to transfer assets and call callees, settled with data a solver
 * chooses
 * @dev An {AHV2Solution} supplies the targets of the order's transfers, the amounts of its ERC20
 * transfers and the solver data of its calls. The hooks constrain the result of the solution.
 * When `solutionApprover` is set, it must approve the solution.
 * @param owner Account the assets are transferred from
 * @param authenticator How the order is authorized. The zero address requires the owner's EIP-712
 * signature over the order, unless the owner submits the order without one. The Permit2 address
 * requires the owner's Permit2 signature. Any other address is an {IAHV2Authenticator} the owner
 * delegated, called for every submitter.
 * @param exclusiveCaller Account that may submit the order besides the owner; the zero address
 * allows any account
 * @param erc20Allowances ERC20 transfers from the owner. Each goes to the target and in the amount
 * the solution specifies for it, at most the entry's `amount`. Outside the Permit2 signature
 * transfer flow, an order has at most 255 of them.
 * @param erc721Approvals ERC721 transfers, each sent from the owner to the target the solution
 * specifies for it
 * @param hooks At most 64 hooks, called before the assets move and after the calls
 * @param calls Callee calls fixed by the owner, each run with the solution's `callValues` and
 * `solverData` entries
 * @param flags The high byte is the number of leading `erc20Allowances` drawn from the owner's
 * Permit2 allowance. The rest are drawn from the owner's allowance to the hub. The number is at
 * most the number of entries, and the Permit2 signature transfer flow neither uses nor checks it.
 * Bits `j` and `64 + j` select {IAHV2Hook-beforeSettlement} and {IAHV2Hook-afterSettlement} for
 * hook `j`. Other bits are ignored.
 * @param solutionApprover Account whose signature the solution requires; the zero address requires
 * none
 * @param nonce When `authenticator` is the zero address, the hub spends it in the owner's
 * namespace, except when the owner calls with empty authentication data and the nonce is zero.
 * When `authenticator` is the Permit2 address, it is the Permit2 nonce. Otherwise the
 * authenticator spends it.
 * @param expiration Last timestamp at which the order may settle
 * @param clientData Data for off-chain clients, emitted in {IKSAllowanceHubV2-SettleOrder}
 */
struct AHV2Order {
  address owner;
  address authenticator;
  address exclusiveCaller;
  ERC20Allowance[] erc20Allowances;
  ERC721Approval[] erc721Approvals;
  HookParams[] hooks;
  CallParams[] calls;
  uint256 flags;
  address solutionApprover;
  uint256 nonce;
  uint256 expiration;
  bytes clientData;
}

/**
 * @notice The struct Permit2 hashes for a permit that also covers an order
 * @param permitted Tokens and amounts the permit covers
 * @param spender Account that may transfer them
 * @param nonce Permit2 nonce
 * @param deadline Last timestamp at which the permit may be used
 * @param order The order
 */
struct PermitBatchWitnessTransferFrom {
  ISignatureTransfer.TokenPermissions[] permitted;
  address spender;
  uint256 nonce;
  uint256 deadline;
  AHV2Order order;
}

using AHV2OrderLib for AHV2Order global;

library AHV2OrderLib {
  using CallParamsLib for CallParams[];
  using EfficientHashLib for bytes;
  using ERC20AllowanceLib for ERC20Allowance[];
  using ERC721ApprovalLib for ERC721Approval[];
  using HookParamsLib for HookParams[];
  using MallocBytesLib for uint256;

  // forgefmt: disable-next-item
  bytes32 internal constant AHV2_ORDER_TYPEHASH = keccak256(
    'AHV2Order(address owner,address authenticator,address exclusiveCaller'
    ',ERC20Allowance[] erc20Allowances,ERC721Approval[] erc721Approvals,HookParams[] hooks'
    ',CallParams[] calls,uint256 flags,address solutionApprover,uint256 nonce,uint256 expiration'
    ',bytes clientData)'
    'CallParams(address callee,bytes ownerData)'
    'ERC20Allowance(address token,uint160 amount)'
    'ERC721Approval(address token,uint256 tokenId)'
    'HookParams(address hook,bytes data)'
  );

  // forgefmt: disable-next-item
  /// @dev Completes Permit2's `PermitBatchWitnessTransferFrom` type stub with the order
  string internal constant PERMIT2_ORDER_TYPE_STRING =
    'AHV2Order order)'
    'AHV2Order(address owner,address authenticator,address exclusiveCaller'
    ',ERC20Allowance[] erc20Allowances,ERC721Approval[] erc721Approvals,HookParams[] hooks'
    ',CallParams[] calls,uint256 flags,address solutionApprover,uint256 nonce,uint256 expiration'
    ',bytes clientData)'
    'CallParams(address callee,bytes ownerData)'
    'ERC20Allowance(address token,uint160 amount)'
    'ERC721Approval(address token,uint256 tokenId)'
    'HookParams(address hook,bytes data)'
    'TokenPermissions(address token,uint256 amount)';

  /// @dev EIP-712 hash of the order
  function hash(AHV2Order calldata order) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(
        AHV2_ORDER_TYPEHASH,
        order.owner,
        order.authenticator,
        order.exclusiveCaller,
        order.erc20Allowances.hash(),
        order.erc721Approvals.hash(),
        order.hooks.hash(),
        order.calls.hash(),
        order.flags,
        order.solutionApprover,
        order.nonce,
        order.expiration,
        order.clientData.hashCalldata()
      )
    );
  }

  /**
   * @dev Transfers the order's ERC20 tokens as `solution` specifies, through a Permit2 signature
   * transfer at `permit2`. `signature` is the owner's signature over the permit. When the caller
   * is not the owner, the permit also covers the order that has hash `orderHash`.
   */
  function executeSignatureTransfer(
    AHV2Order calldata order,
    bytes32 orderHash,
    AHV2Solution calldata solution,
    bytes calldata signature,
    address permit2
  ) internal {
    ISignatureTransfer.PermitBatchTransferFrom memory permit =
      order.erc20Allowances.toPermitBatchTransferFrom(order.nonce, order.expiration);
    ISignatureTransfer.SignatureTransferDetails[] memory details =
      order.erc20Allowances.toSignatureTransferDetails(solution.erc20Targets, solution.erc20Amounts);

    if (msg.sender == order.owner) {
      ISignatureTransfer(permit2).permitTransferFrom(permit, details, order.owner, signature);
    } else {
      ISignatureTransfer(permit2)
        .permitWitnessTransferFrom(
          permit, details, order.owner, orderHash, PERMIT2_ORDER_TYPE_STRING, signature
        );
    }
  }

  /// @dev Calls `beforeSettlement` on each hook whose bit is set in `order.flags`. Returns the
  /// results in hook order, with an empty result for each other hook. Reverts when the order
  /// has more than 64 hooks.
  function beforeSettlement(
    AHV2Order calldata order,
    bytes32 orderHash,
    AHV2Solution calldata solution
  ) internal returns (bytes[] memory results) {
    HookParams[] calldata hooks = order.hooks;
    if (hooks.length > Constants.MAX_HOOKS) {
      revert IKSAllowanceHubV2.TooManyHooks(hooks.length);
    }
    uint256 flags = order.flags;
    results = hooks.length.mallocBytes();

    for (uint256 i = 0; i < hooks.length; i++) {
      HookParams calldata params = hooks[i];
      if ((flags >> i) & 1 != 0) {
        results[i] = IAHV2Hook(params.hook).beforeSettlement(order, orderHash, solution, i);
      } else {
        results[i] = new bytes(0);
      }
    }
  }

  /// @dev Calls `afterSettlement` on each hook whose bit is set in `order.flags`, passing the
  /// result of that hook's `beforeSettlement`
  function afterSettlement(
    AHV2Order calldata order,
    bytes32 orderHash,
    AHV2Solution calldata solution,
    bytes[] memory beforeSettlementResults
  ) internal {
    HookParams[] calldata hooks = order.hooks;
    uint256 flags = order.flags >> Constants.AFTER_SETTLEMENT_HOOKS_OFFSET;

    for (uint256 i = 0; i < hooks.length; i++) {
      HookParams calldata params = hooks[i];
      if ((flags >> i) & 1 != 0) {
        IAHV2Hook(params.hook)
          .afterSettlement(order, orderHash, solution, i, beforeSettlementResults[i]);
      }
    }
  }
}
