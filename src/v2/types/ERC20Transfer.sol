// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {DynamicArrayLibExt} from '../libraries/DynamicArrayLibExt.sol';

import {IAllowanceTransfer} from 'ks-common-sc/src/interfaces/IAllowanceTransfer.sol';
import {ISignatureTransfer} from 'ks-common-sc/src/interfaces/ISignatureTransfer.sol';

import {TokenHelper} from 'ks-common-sc/src/libraries/token/TokenHelper.sol';

import {EfficientHashLib} from 'solady/utils/EfficientHashLib.sol';

/**
 * @notice One ERC20 leg of an execution order: an amount of `token` transferred from the owner to
 * `target`
 * @dev In {IKSAllowanceHubV2-rescueTokens}, the entry is a transfer from the hub: a zero `amount`
 * transfers the hub's entire balance, and a `token` of the native-token address or the zero
 * address transfers native value.
 * @param token The ERC20 token
 * @param target Account the amount is transferred to
 * @param amount Amount transferred, with the width of a Permit2 allowance
 */
struct ERC20Transfer {
  address token;
  address target;
  uint160 amount;
}

using ERC20TransferLib for ERC20Transfer global;

library ERC20TransferLib {
  using DynamicArrayLibExt for uint256;
  using EfficientHashLib for *;
  using TokenHelper for address;

  bytes32 internal constant ERC20_TRANSFER_TYPEHASH =
    keccak256('ERC20Transfer(address token,address target,uint160 amount)');

  /// @dev EIP-712 hash of one transfer
  function hash(ERC20Transfer calldata self) internal pure returns (bytes32 digest) {
    bytes32 typehash = ERC20_TRANSFER_TYPEHASH;
    assembly ('memory-safe') {
      let fmp := mload(0x40)
      mstore(fmp, typehash)
      calldatacopy(add(fmp, 0x20), self, 0x60)
      digest := keccak256(fmp, 0x80)
    }
  }

  /// @dev As {hash}, for a transfer already in memory
  function hashMemory(ERC20Transfer memory self) internal pure returns (bytes32) {
    return keccak256(abi.encode(ERC20_TRANSFER_TYPEHASH, self.token, self.target, self.amount));
  }

  /// @dev EIP-712 hash of the array: its member hashes, concatenated and hashed
  function hash(ERC20Transfer[] calldata transfers) internal pure returns (bytes32) {
    bytes32[] memory transferHashes = transfers.length.malloc();
    for (uint256 i = 0; i < transfers.length; i++) {
      transferHashes[i] = hash(transfers[i]);
    }

    return transferHashes.hash();
  }

  /// @dev As {hash}, for an array already in memory
  function hashMemory(ERC20Transfer[] memory transfers) internal pure returns (bytes32) {
    bytes32[] memory transferHashes = transfers.length.malloc();
    for (uint256 i = 0; i < transfers.length; i++) {
      transferHashes[i] = hashMemory(transfers[i]);
    }

    return transferHashes.hash();
  }

  /// @dev Transfers each leg from `owner` to its target
  function execute(ERC20Transfer[] calldata transfers, address owner) internal {
    for (uint256 i = 0; i < transfers.length; i++) {
      ERC20Transfer calldata transfer = transfers[i];
      transfer.token.safeTransferFrom(owner, transfer.target, transfer.amount);
    }
  }

  /// @dev Converts the transfers into a Permit2 batch permit
  function toPermitBatchTransferFrom(
    ERC20Transfer[] calldata transfers,
    uint256 nonce,
    uint256 deadline
  ) internal pure returns (ISignatureTransfer.PermitBatchTransferFrom memory permit) {
    permit.permitted = transfers.length.mallocTokenPermissions();
    permit.nonce = nonce;
    permit.deadline = deadline;

    for (uint256 i = 0; i < transfers.length; i++) {
      ERC20Transfer calldata transfer = transfers[i];
      permit.permitted[i] =
        ISignatureTransfer.TokenPermissions({token: transfer.token, amount: transfer.amount});
    }
  }

  /// @dev Converts the transfers into Permit2 signature-transfer details
  function toSignatureTransferDetails(ERC20Transfer[] calldata transfers)
    internal
    pure
    returns (ISignatureTransfer.SignatureTransferDetails[] memory details)
  {
    details = transfers.length.mallocSignatureTransferDetails();
    for (uint256 i = 0; i < transfers.length; i++) {
      ERC20Transfer calldata transfer = transfers[i];
      details[i] = ISignatureTransfer.SignatureTransferDetails({
        to: transfer.target, requestedAmount: transfer.amount
      });
    }
  }

  /// @dev EIP-712 hash of the legs' targets, in order, encoded as an `address[]`
  function targetsHash(ERC20Transfer[] calldata transfers) internal pure returns (bytes32) {
    bytes32[] memory targetWords = transfers.length.malloc();
    for (uint256 i = 0; i < transfers.length; i++) {
      targetWords[i] = bytes32(uint256(uint160(transfers[i].target)));
    }

    return targetWords.hash();
  }

  /// @dev Converts the transfers into Permit2 allowance-transfer details, all drawn from `owner`
  function toAllowanceTransferDetails(ERC20Transfer[] calldata transfers, address owner)
    internal
    pure
    returns (IAllowanceTransfer.AllowanceTransferDetails[] memory details)
  {
    details = transfers.length.mallocAllowanceTransferDetails();
    for (uint256 i = 0; i < transfers.length; i++) {
      ERC20Transfer calldata transfer = transfers[i];
      details[i] = IAllowanceTransfer.AllowanceTransferDetails({
        from: owner, to: transfer.target, token: transfer.token, amount: transfer.amount
      });
    }
  }
}
