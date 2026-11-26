// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IKSAllowanceHubV2} from '../interfaces/IKSAllowanceHubV2.sol';

import {Constants} from '../libraries/Constants.sol';

import {ERC20Transfer} from './ERC20Transfer.sol';

import {IAllowanceTransfer} from 'ks-common-sc/src/interfaces/IAllowanceTransfer.sol';
import {ICommon} from 'ks-common-sc/src/interfaces/ICommon.sol';
import {ISignatureTransfer} from 'ks-common-sc/src/interfaces/ISignatureTransfer.sol';

import {TokenHelper} from 'ks-common-sc/src/libraries/token/TokenHelper.sol';

import {EfficientHashLib} from 'solady/utils/EfficientHashLib.sol';

/**
 * @notice One ERC20 transfer of an order: an amount of `token` that leaves the owner
 * @dev The order does not specify the target or the amount of the transfer. The
 * {AHV2Solution} specifies a target and an amount for each transfer, and the amount
 * transferred is at most `amount`.
 * @param token The ERC20 token
 * @param amount Largest amount the transfer sends in one settlement, with the width of a Permit2
 * allowance
 */
struct ERC20Allowance {
  address token;
  uint160 amount;
}

using ERC20AllowanceLib for ERC20Allowance global;

library ERC20AllowanceLib {
  using EfficientHashLib for *;
  using TokenHelper for address;

  bytes32 internal constant ERC20_ALLOWANCE_TYPEHASH =
    keccak256('ERC20Allowance(address token,uint160 amount)');

  /// @dev EIP-712 hash of one allowance
  function hash(ERC20Allowance calldata self) internal pure returns (bytes32 digest) {
    bytes32 typehash = ERC20_ALLOWANCE_TYPEHASH;
    assembly ('memory-safe') {
      let fmp := mload(0x40)
      mstore(fmp, typehash)
      calldatacopy(add(fmp, 0x20), self, 0x40)
      digest := keccak256(fmp, 0x60)
    }
  }

  /// @dev EIP-712 hash of the array: its member hashes, concatenated and hashed
  function hash(ERC20Allowance[] calldata allowances) internal pure returns (bytes32) {
    bytes32[] memory allowanceHashes = allowances.length.malloc();
    for (uint256 i = 0; i < allowances.length; i++) {
      allowanceHashes[i] = hash(allowances[i]);
    }

    return allowanceHashes.hash();
  }

  /// @dev Transfers `amounts[i]` of each allowance from `owner` to `targets[i]`, the first
  /// `numPermit2Transfers`, at most the number of allowances, through the owner's Permit2
  /// allowances at `permit2` and the rest from the owner's allowances to this contract; reverts
  /// above 255 allowances, above a count of the number of allowances, or when an amount exceeds
  /// its allowance
  function execute(
    ERC20Allowance[] calldata allowances,
    address owner,
    address[] calldata targets,
    uint160[] calldata amounts,
    uint256 numPermit2Transfers,
    address permit2
  ) internal {
    if (allowances.length > Constants.MAX_ERC20S) {
      revert IKSAllowanceHubV2.TooManyERC20s(allowances.length);
    }
    if (numPermit2Transfers > allowances.length) {
      revert IKSAllowanceHubV2.TooManyPermit2Transfers(numPermit2Transfers, allowances.length);
    }

    // The leading allowances move in one Permit2 call, which is not made when there are none
    if (numPermit2Transfers > 0) {
      IAllowanceTransfer.AllowanceTransferDetails[] memory details;
      bytes32[] memory buffer = numPermit2Transfers.malloc();
      assembly ('memory-safe') {
        details := buffer
      }

      for (uint256 i = 0; i < numPermit2Transfers; i++) {
        ERC20Allowance calldata allowance = allowances[i];
        _checkAmount(i, amounts[i], allowance.amount);

        details[i] = IAllowanceTransfer.AllowanceTransferDetails({
          from: owner, to: targets[i], token: allowance.token, amount: amounts[i]
        });
      }

      IAllowanceTransfer(permit2).transferFrom(details);
    }

    for (uint256 i = numPermit2Transfers; i < allowances.length; i++) {
      ERC20Allowance calldata allowance = allowances[i];
      _checkAmount(i, amounts[i], allowance.amount);

      allowance.token.safeTransferFrom(owner, targets[i], amounts[i]);
    }
  }

  /// @dev The allowances as transfers, each paired with `targets[i]` and `amounts[i]`; reverts
  /// unless there is one target and one amount for each allowance
  function toTransfers(
    ERC20Allowance[] calldata allowances,
    address[] calldata targets,
    uint160[] calldata amounts
  ) internal pure returns (ERC20Transfer[] memory transfers) {
    if (targets.length != allowances.length || amounts.length != allowances.length) {
      revert ICommon.MismatchedArrayLengths();
    }

    bytes32[] memory buffer = allowances.length.malloc();
    assembly ('memory-safe') {
      transfers := buffer
    }
    for (uint256 i = 0; i < allowances.length; i++) {
      transfers[i] =
        ERC20Transfer({token: allowances[i].token, target: targets[i], amount: amounts[i]});
    }
  }

  /// @dev Converts the allowances into a Permit2 batch permit
  function toPermitBatchTransferFrom(
    ERC20Allowance[] calldata allowances,
    uint256 nonce,
    uint256 deadline
  ) internal pure returns (ISignatureTransfer.PermitBatchTransferFrom memory permit) {
    ISignatureTransfer.TokenPermissions[] memory permitted;
    bytes32[] memory buffer = allowances.length.malloc();
    assembly ('memory-safe') {
      permitted := buffer
    }
    permit.permitted = permitted;
    permit.nonce = nonce;
    permit.deadline = deadline;

    for (uint256 i = 0; i < allowances.length; i++) {
      ERC20Allowance calldata allowance = allowances[i];
      permit.permitted[i] =
        ISignatureTransfer.TokenPermissions({token: allowance.token, amount: allowance.amount});
    }
  }

  /// @dev Converts the allowances into Permit2 signature-transfer details, each requesting
  /// `amounts[i]` to `targets[i]`; reverts when an amount exceeds its allowance
  function toSignatureTransferDetails(
    ERC20Allowance[] calldata allowances,
    address[] calldata targets,
    uint160[] calldata amounts
  ) internal pure returns (ISignatureTransfer.SignatureTransferDetails[] memory details) {
    bytes32[] memory buffer = allowances.length.malloc();
    assembly ('memory-safe') {
      details := buffer
    }
    for (uint256 i = 0; i < allowances.length; i++) {
      _checkAmount(i, amounts[i], allowances[i].amount);
      details[i] =
        ISignatureTransfer.SignatureTransferDetails({to: targets[i], requestedAmount: amounts[i]});
    }
  }

  /// @dev Reverts when the amount at `index` exceeds the allowance of its transfer
  function _checkAmount(uint256 index, uint160 amount, uint160 allowance) private pure {
    if (amount > allowance) {
      revert IKSAllowanceHubV2.ERC20AllowanceExceeded(index, amount, allowance);
    }
  }
}
