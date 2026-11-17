// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IKSAllowanceHubV2} from '../interfaces/IKSAllowanceHubV2.sol';

import {DeadlineChecker} from '../base/DeadlineChecker.sol';

import {AHV2Solution} from './AHV2Solution.sol';
import {CallParams, CallParamsLib} from './CallParams.sol';
import {ERC20Allowance, ERC20AllowanceLib} from './ERC20Allowance.sol';
import {ERC721Approval, ERC721ApprovalLib} from './ERC721Approval.sol';
import {HookParams, HookParamsLib} from './HookParams.sol';

import {ICommon} from 'ks-common-sc/src/interfaces/ICommon.sol';

import {EfficientHashLib} from 'solady/utils/EfficientHashLib.sol';

/**
 * @notice An owner's order to transfer assets along a route chosen by a solver
 * @dev The order specifies neither the route, nor the targets of its transfers, nor the amounts of
 * its ERC20 transfers; an {AHV2Solution} supplies them. The hooks constrain the result of the
 * solution, and `solutionApprover` may be required to approve it. When `owner` submits the order,
 * `exclusiveCaller` and `solutionApprover` do not apply.
 * @param owner Account the assets are transferred from
 * @param exclusiveCaller Account that may submit the order besides the owner; the zero address
 * allows any account
 * @param erc20Allowances ERC20 transfers, each of at most its `amount`, sent from the owner to the
 * target and in the amount the solution specifies for it
 * @param erc721Approvals ERC721 transfers, each sent from the owner to the target the solution
 * specifies for it
 * @param hooks Hooks called before the assets move and after the owner's calls
 * @param ownerCalls Callee calls fixed by the owner, run after the solver's calls
 * @param solutionApprover Account whose signature the solution requires when the owner does not
 * submit the order; the zero address requires none
 * @param nonce Permit2 nonce on the Permit2 entry points; on the delegated entry points, for the
 * authenticator to spend
 * @param expiration Last timestamp at which the order may settle
 * @param clientData Data for off-chain clients, emitted in {IKSAllowanceHubV2-TransferTokens}
 */
struct AHV2Order {
  address owner;
  address exclusiveCaller;
  ERC20Allowance[] erc20Allowances;
  ERC721Approval[] erc721Approvals;
  HookParams[] hooks;
  CallParams[] ownerCalls;
  address solutionApprover;
  uint256 nonce;
  uint256 expiration;
  bytes clientData;
}

using AHV2OrderLib for AHV2Order global;

library AHV2OrderLib {
  using CallParamsLib for CallParams[];
  using EfficientHashLib for bytes;
  using ERC20AllowanceLib for ERC20Allowance[];
  using ERC721ApprovalLib for ERC721Approval[];
  using HookParamsLib for HookParams[];

  bytes32 internal constant AHV2_ORDER_TYPEHASH = keccak256(
    'AHV2Order(address owner,address exclusiveCaller,ERC20Allowance[] erc20Allowances,ERC721Approval[] erc721Approvals,HookParams[] hooks,CallParams[] ownerCalls,address solutionApprover,uint256 nonce,uint256 expiration,bytes clientData)'
    'CallParams(address callee,uint256 value,bytes data)'
    'ERC20Allowance(address token,uint160 amount)' 'ERC721Approval(address token,uint256 tokenId)'
    'HookParams(address hook,bytes32 flags,bytes data)'
  );

  /// @dev EIP-712 hash of the order
  function hash(AHV2Order calldata order) internal pure returns (bytes32) {
    return hash(
      order,
      order.erc721Approvals.hash(),
      order.hooks.hash(),
      order.ownerCalls.hash(),
      order.clientData.hashCalldata()
    );
  }

  /// @dev As {hash}, from the already computed hashes of `erc721Approvals`, `hooks`, `ownerCalls`
  /// and `clientData`
  function hash(
    AHV2Order calldata order,
    bytes32 erc721ApprovalsHash,
    bytes32 hooksHash,
    bytes32 ownerCallsHash,
    bytes32 clientDataHash
  ) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(
        AHV2_ORDER_TYPEHASH,
        order.owner,
        order.exclusiveCaller,
        order.erc20Allowances.hash(),
        erc721ApprovalsHash,
        hooksHash,
        ownerCallsHash,
        order.solutionApprover,
        order.nonce,
        order.expiration,
        clientDataHash
      )
    );
  }

  /// @dev As {hash}, also returning the hashes of the members the order's witness covers
  function membersHash(AHV2Order calldata order)
    internal
    pure
    returns (
      bytes32 orderHash,
      bytes32 erc721ApprovalsHash,
      bytes32 hooksHash,
      bytes32 ownerCallsHash,
      bytes32 clientDataHash
    )
  {
    erc721ApprovalsHash = order.erc721Approvals.hash();
    hooksHash = order.hooks.hash();
    ownerCallsHash = order.ownerCalls.hash();
    clientDataHash = order.clientData.hashCalldata();
    orderHash = hash(order, erc721ApprovalsHash, hooksHash, ownerCallsHash, clientDataHash);
  }

  /**
   * @dev Emits {IKSAllowanceHubV2-TransferTokens} for the order with hash `orderHash`, pairing
   * each transfer with the target and amount `solution` specifies for it
   */
  function announce(AHV2Order calldata order, bytes32 orderHash, AHV2Solution calldata solution)
    internal
  {
    emit IKSAllowanceHubV2.TransferTokens(
      msg.sender,
      order.owner,
      orderHash,
      order.erc20Allowances.toTransfers(solution.erc20Targets, solution.erc20Amounts),
      order.erc721Approvals.toTransfers(solution.erc721Targets),
      solution.solverCalls.toNativeTransfers(order.ownerCalls),
      order.clientData
    );
  }

  /// @dev Checks the expirations of the order and `solution`, and that `solution` fits the order
  function checkSettlement(AHV2Order calldata order, AHV2Solution calldata solution) internal view {
    // A call at the expiration is accepted
    _checkDeadline(order.expiration);
    _checkDeadline(solution.expiration);
    // One target and one amount for each ERC20 transfer, one target for each ERC721 transfer and
    // one `solverData` entry for each owner call
    _checkLengths(solution.erc20Targets.length, order.erc20Allowances.length);
    _checkLengths(solution.erc20Amounts.length, order.erc20Allowances.length);
    _checkLengths(solution.erc721Targets.length, order.erc721Approvals.length);
    _checkLengths(solution.solverData.length, order.ownerCalls.length);
  }

  /// @dev Reverts when the current block timestamp is later than `deadline`
  function _checkDeadline(uint256 deadline) private view {
    if (block.timestamp > deadline) {
      revert DeadlineChecker.DeadlinePassed(deadline, block.timestamp);
    }
  }

  /// @dev Reverts when `length1` and `length2` differ
  function _checkLengths(uint256 length1, uint256 length2) private pure {
    if (length1 != length2) {
      revert ICommon.MismatchedArrayLengths();
    }
  }
}
