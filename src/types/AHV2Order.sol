// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IKSAllowanceHubV2} from '../interfaces/IKSAllowanceHubV2.sol';

import {AHV2Solution} from './AHV2Solution.sol';
import {CallParams, CallParamsLib} from './CallParams.sol';
import {ERC20Allowance, ERC20AllowanceLib} from './ERC20Allowance.sol';
import {ERC721Approval, ERC721ApprovalLib} from './ERC721Approval.sol';
import {HookParams, HookParamsLib} from './HookParams.sol';

import {ICommon} from 'ks-common-sc/src/interfaces/ICommon.sol';
import {ISignatureTransfer} from 'ks-common-sc/src/interfaces/ISignatureTransfer.sol';

import {EfficientHashLib} from 'solady/utils/EfficientHashLib.sol';

/**
 * @notice An owner's order to transfer assets and call callees, settled with data a solver
 * chooses
 * @dev The order specifies neither the targets of its transfers, nor the amounts of its ERC20
 * transfers, nor the solver data of its calls; an {AHV2Solution} supplies them. The hooks
 * constrain the result of the solution, and `solutionApprover` may be required to approve it. When
 * `owner` submits the order, `exclusiveCaller` and `solutionApprover` do not apply.
 * @param owner Account the assets are transferred from
 * @param authenticator How the order is authorized when another account submits it: the zero
 * address requires the owner's EIP-712 signature over the order, the Permit2 address requires the
 * owner's Permit2 signature, and any other address is an {IAHV2Authenticator} the owner delegated
 * @param exclusiveCaller Account that may submit the order besides the owner; the zero address
 * allows any account
 * @param erc20Allowances ERC20 transfers, each of at most its `amount`, sent from the owner to the
 * target and in the amount the solution specifies for it
 * @param erc721Approvals ERC721 transfers, each sent from the owner to the target the solution
 * specifies for it
 * @param hooks Hooks called before the assets move and after the calls
 * @param calls Callee calls fixed by the owner, each run with the solution's `callValues` and
 * `solverData` entries
 * @param solutionApprover Account whose signature the solution requires when the owner does not
 * submit the order; the zero address requires none
 * @param nonce Spent in the owner's namespace of the hub's nonces when `authenticator` is the zero
 * address, used as the Permit2 nonce when it is the Permit2 address, and for the authenticator to
 * spend otherwise
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

  bytes32 internal constant AHV2_ORDER_TYPEHASH = keccak256(
    'AHV2Order(address owner,address authenticator,address exclusiveCaller,ERC20Allowance[] erc20Allowances,ERC721Approval[] erc721Approvals,HookParams[] hooks,CallParams[] calls,address solutionApprover,uint256 nonce,uint256 expiration,bytes clientData)'
    'CallParams(address callee,bytes ownerData)' 'ERC20Allowance(address token,uint160 amount)'
    'ERC721Approval(address token,uint256 tokenId)'
    'HookParams(address hook,bytes32 flags,bytes data)'
  );

  /// @dev Completes Permit2's `PermitBatchWitnessTransferFrom` type stub with the order
  string internal constant PERMIT2_ORDER_TYPE_STRING = 'AHV2Order order)'
    'AHV2Order(address owner,address authenticator,address exclusiveCaller,ERC20Allowance[] erc20Allowances,ERC721Approval[] erc721Approvals,HookParams[] hooks,CallParams[] calls,address solutionApprover,uint256 nonce,uint256 expiration,bytes clientData)'
    'CallParams(address callee,bytes ownerData)' 'ERC20Allowance(address token,uint160 amount)'
    'ERC721Approval(address token,uint256 tokenId)'
    'HookParams(address hook,bytes32 flags,bytes data)'
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
        order.solutionApprover,
        order.nonce,
        order.expiration,
        order.clientData.hashCalldata()
      )
    );
  }

  /// @dev Checks the expirations of the order and `solution`, and that `solution` fits the order
  function checkSettlement(AHV2Order calldata order, AHV2Solution calldata solution) internal view {
    // A call at the expiration is accepted
    if (block.timestamp > order.expiration) {
      revert IKSAllowanceHubV2.OrderExpired(order.expiration, block.timestamp);
    }
    if (block.timestamp > solution.expiration) {
      revert IKSAllowanceHubV2.SolutionExpired(solution.expiration, block.timestamp);
    }

    // One target and one amount for each ERC20 transfer, one target for each ERC721 transfer and
    // one `callValues` and one `solverData` entry for each call
    _checkLengths(solution.erc20Targets.length, order.erc20Allowances.length);
    _checkLengths(solution.erc20Amounts.length, order.erc20Allowances.length);
    _checkLengths(solution.erc721Targets.length, order.erc721Approvals.length);
    _checkLengths(solution.callValues.length, order.calls.length);
    _checkLengths(solution.solverData.length, order.calls.length);
  }

  /**
   * @dev Transfers the order's ERC20 tokens as `solution` specifies, through a Permit2 signature
   * transfer at `permit2`, with `signature` by the owner over the permit. When the caller is not
   * the owner, the permit also covers the order, of hash `orderHash`.
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

  /// @dev Reverts when `length1` and `length2` differ
  function _checkLengths(uint256 length1, uint256 length2) private pure {
    if (length1 != length2) {
      revert ICommon.MismatchedArrayLengths();
    }
  }
}
