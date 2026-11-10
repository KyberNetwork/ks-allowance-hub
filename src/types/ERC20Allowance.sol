// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {DynamicArrayLibExt} from '../libraries/DynamicArrayLibExt.sol';

import {ERC20Transfer} from './ERC20Transfer.sol';

import {IKSAllowanceHubV2} from '../interfaces/IKSAllowanceHubV2.sol';

import {IAllowanceTransfer} from 'ks-common-sc/src/interfaces/IAllowanceTransfer.sol';
import {ISignatureTransfer} from 'ks-common-sc/src/interfaces/ISignatureTransfer.sol';

import {TokenHelper} from 'ks-common-sc/src/libraries/token/TokenHelper.sol';

import {EfficientHashLib} from 'solady/utils/EfficientHashLib.sol';

/**
 * @notice One ERC20 transfer of a fulfillment order: an amount of `token` that leaves the owner
 * @dev The order does not specify the target or the amount of the transfer. The
 * {FulfillmentSolution} specifies a target and an amount for each transfer, and the amount
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
  using DynamicArrayLibExt for uint256;
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

  /// @dev As {hash}, for an allowance already in memory
  function hashMemory(ERC20Allowance memory self) internal pure returns (bytes32) {
    return keccak256(abi.encode(ERC20_ALLOWANCE_TYPEHASH, self.token, self.amount));
  }

  /// @dev EIP-712 hash of the array: its member hashes, concatenated and hashed
  function hash(ERC20Allowance[] calldata allowances) internal pure returns (bytes32) {
    bytes32[] memory allowanceHashes = allowances.length.malloc();
    for (uint256 i = 0; i < allowances.length; i++) {
      allowanceHashes[i] = hash(allowances[i]);
    }

    return allowanceHashes.hash();
  }

  /// @dev As {hash}, for an array already in memory
  function hashMemory(ERC20Allowance[] memory allowances) internal pure returns (bytes32) {
    bytes32[] memory allowanceHashes = allowances.length.malloc();
    for (uint256 i = 0; i < allowances.length; i++) {
      allowanceHashes[i] = hashMemory(allowances[i]);
    }

    return allowanceHashes.hash();
  }

  /// @dev Transfers `amounts[i]` of each allowance from `owner` to `targets[i]`; reverts when an
  /// amount exceeds its allowance
  function execute(
    ERC20Allowance[] calldata allowances,
    address owner,
    address[] calldata targets,
    uint160[] calldata amounts
  ) internal {
    for (uint256 i = 0; i < allowances.length; i++) {
      ERC20Allowance calldata allowance = allowances[i];
      _checkAmount(i, amounts[i], allowance.amount);
      allowance.token.safeTransferFrom(owner, targets[i], amounts[i]);
    }
  }

  /// @dev As {execute}, through the Permit2 allowances of `owner` at `permit2`
  function executePermit2(
    ERC20Allowance[] calldata allowances,
    address owner,
    address[] calldata targets,
    uint160[] calldata amounts,
    address permit2
  ) internal {
    IAllowanceTransfer.AllowanceTransferDetails[] memory details =
      toAllowanceTransferDetails(allowances, owner, targets, amounts);
    IAllowanceTransfer(permit2).transferFrom(details);
  }

  /// @dev Converts the allowances into a Permit2 batch permit
  function toPermitBatchTransferFrom(
    ERC20Allowance[] calldata allowances,
    uint256 nonce,
    uint256 deadline
  ) internal pure returns (ISignatureTransfer.PermitBatchTransferFrom memory permit) {
    permit.permitted = allowances.length.mallocTokenPermissions();
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
    details = allowances.length.mallocSignatureTransferDetails();
    for (uint256 i = 0; i < allowances.length; i++) {
      _checkAmount(i, amounts[i], allowances[i].amount);
      details[i] =
        ISignatureTransfer.SignatureTransferDetails({to: targets[i], requestedAmount: amounts[i]});
    }
  }

  /// @dev Converts the allowances into Permit2 allowance-transfer details, all drawn from `owner`,
  /// each moving `amounts[i]` to `targets[i]`; reverts when an amount exceeds its allowance
  function toAllowanceTransferDetails(
    ERC20Allowance[] calldata allowances,
    address owner,
    address[] calldata targets,
    uint160[] calldata amounts
  ) internal pure returns (IAllowanceTransfer.AllowanceTransferDetails[] memory details) {
    details = allowances.length.mallocAllowanceTransferDetails();
    for (uint256 i = 0; i < allowances.length; i++) {
      ERC20Allowance calldata allowance = allowances[i];
      _checkAmount(i, amounts[i], allowance.amount);
      details[i] = IAllowanceTransfer.AllowanceTransferDetails({
        from: owner, to: targets[i], token: allowance.token, amount: amounts[i]
      });
    }
  }

  /// @dev The allowances as transfers, each paired with `targets[i]` and `amounts[i]`
  function toTransfers(
    ERC20Allowance[] calldata allowances,
    address[] calldata targets,
    uint160[] calldata amounts
  ) internal pure returns (ERC20Transfer[] memory transfers) {
    transfers = allowances.length.mallocERC20Transfers();
    for (uint256 i = 0; i < allowances.length; i++) {
      transfers[i] =
        ERC20Transfer({token: allowances[i].token, target: targets[i], amount: amounts[i]});
    }
  }

  /// @dev Reverts when the amount at `index` exceeds the allowance of its transfer
  function _checkAmount(uint256 index, uint160 amount, uint160 allowance) private pure {
    if (amount > allowance) {
      revert IKSAllowanceHubV2.ERC20AllowanceExceeded(index, amount, allowance);
    }
  }
}
