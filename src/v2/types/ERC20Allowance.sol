// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {DynamicArrayLibExt} from '../libraries/DynamicArrayLibExt.sol';

import {ERC20Transfer} from './ERC20Transfer.sol';

import {IAllowanceTransfer} from 'ks-common-sc/src/interfaces/IAllowanceTransfer.sol';
import {ISignatureTransfer} from 'ks-common-sc/src/interfaces/ISignatureTransfer.sol';

import {TokenHelper} from 'ks-common-sc/src/libraries/token/TokenHelper.sol';

import {EfficientHashLib} from 'solady/utils/EfficientHashLib.sol';

/**
 * @notice One ERC20 leg of a fulfillment order: how much of `token` may leave the owner
 * @dev The destination is not part of the order. The solver names one target per leg in its
 * {FulfillmentSolution}, and the whole `amount` moves to it. `amount` is `uint160` to match
 * Permit2's allowance width.
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

  /// @dev Pulls each allowance in full from `owner` to the target at the same index
  function execute(ERC20Allowance[] calldata allowances, address owner, address[] calldata targets)
    internal
  {
    for (uint256 i = 0; i < allowances.length; i++) {
      ERC20Allowance calldata allowance = allowances[i];
      allowance.token.safeTransferFrom(owner, targets[i], allowance.amount);
    }
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

  /// @dev Converts the allowances into Permit2 signature-transfer details, each to its target
  function toSignatureTransferDetails(
    ERC20Allowance[] calldata allowances,
    address[] calldata targets
  ) internal pure returns (ISignatureTransfer.SignatureTransferDetails[] memory details) {
    details = allowances.length.mallocSignatureTransferDetails();
    for (uint256 i = 0; i < allowances.length; i++) {
      details[i] = ISignatureTransfer.SignatureTransferDetails({
        to: targets[i], requestedAmount: allowances[i].amount
      });
    }
  }

  /// @dev Converts the allowances into Permit2 allowance-transfer details, all drawn from `owner`
  function toAllowanceTransferDetails(
    ERC20Allowance[] calldata allowances,
    address owner,
    address[] calldata targets
  ) internal pure returns (IAllowanceTransfer.AllowanceTransferDetails[] memory details) {
    details = allowances.length.mallocAllowanceTransferDetails();
    for (uint256 i = 0; i < allowances.length; i++) {
      ERC20Allowance calldata allowance = allowances[i];
      details[i] = IAllowanceTransfer.AllowanceTransferDetails({
        from: owner, to: targets[i], token: allowance.token, amount: allowance.amount
      });
    }
  }

  /// @dev The transfers the allowances become once each is paired with its target
  function toTransfers(ERC20Allowance[] calldata allowances, address[] calldata targets)
    internal
    pure
    returns (ERC20Transfer[] memory transfers)
  {
    transfers = allowances.length.mallocERC20Transfers();
    for (uint256 i = 0; i < allowances.length; i++) {
      ERC20Allowance calldata allowance = allowances[i];
      transfers[i] =
        ERC20Transfer({token: allowance.token, target: targets[i], amount: allowance.amount});
    }
  }
}
