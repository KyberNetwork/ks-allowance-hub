// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IAllowanceTransfer} from 'ks-common-sc/src/interfaces/IAllowanceTransfer.sol';
import {ISignatureTransfer} from 'ks-common-sc/src/interfaces/ISignatureTransfer.sol';
import {TokenHelper} from 'ks-common-sc/src/libraries/token/TokenHelper.sol';

/**
 * @notice One ERC20 leg of an order: how much of `token` leaves the owner for `target`
 * @dev `amount` is `uint160` to match Permit2's allowance width, so the same struct feeds both the
 * Permit2 rails and a plain approval to the hub.
 */
struct ERC20Transfer {
  address token;
  address target;
  uint160 amount;
}

using ERC20TransferLibrary for ERC20Transfer global;

library ERC20TransferLibrary {
  using TokenHelper for address;

  bytes32 internal constant ERC20_TRANSFER_TYPEHASH =
    keccak256('ERC20Transfer(address token,address target,uint160 amount)');

  /// @dev EIP-712 hash of one transfer
  function hash(ERC20Transfer calldata self) internal pure returns (bytes32) {
    return keccak256(abi.encode(ERC20_TRANSFER_TYPEHASH, self.token, self.target, self.amount));
  }

  /// @dev As {hash}, for a transfer already in memory
  function hashMemory(ERC20Transfer memory self) internal pure returns (bytes32) {
    return keccak256(abi.encode(ERC20_TRANSFER_TYPEHASH, self.token, self.target, self.amount));
  }

  /// @dev EIP-712 hash of the array: its member hashes, concatenated and hashed
  function hash(ERC20Transfer[] calldata transfers) internal pure returns (bytes32) {
    bytes32[] memory hashes = new bytes32[](transfers.length);
    for (uint256 i = 0; i < transfers.length; i++) {
      hashes[i] = hash(transfers[i]);
    }
    return keccak256(abi.encodePacked(hashes));
  }

  /// @dev As {hash}, for an array already in memory
  function hashMemory(ERC20Transfer[] memory transfers) internal pure returns (bytes32) {
    bytes32[] memory hashes = new bytes32[](transfers.length);
    for (uint256 i = 0; i < transfers.length; i++) {
      hashes[i] = hashMemory(transfers[i]);
    }
    return keccak256(abi.encodePacked(hashes));
  }

  /// @dev Pulls each transfer from `owner` straight to its target
  function execute(ERC20Transfer[] calldata transfers, address owner) internal {
    for (uint256 i = 0; i < transfers.length; i++) {
      ERC20Transfer calldata transfer = transfers[i];
      transfer.token.safeTransferFrom(owner, transfer.target, transfer.amount);
    }
  }

  /// @dev Shapes the transfers as a Permit2 batch permit
  function toPermitBatchTransferFrom(
    ERC20Transfer[] calldata transfers,
    uint256 nonce,
    uint256 deadline
  ) internal pure returns (ISignatureTransfer.PermitBatchTransferFrom memory permit) {
    permit.permitted = new ISignatureTransfer.TokenPermissions[](transfers.length);
    permit.nonce = nonce;
    permit.deadline = deadline;

    for (uint256 i = 0; i < transfers.length; i++) {
      ERC20Transfer memory transfer = transfers[i];
      permit.permitted[i] =
        ISignatureTransfer.TokenPermissions({token: transfer.token, amount: transfer.amount});
    }
  }

  /// @dev As {toPermitBatchTransferFrom}, for an array already in memory
  function toPermitBatchTransferFromMemory(
    ERC20Transfer[] memory transfers,
    uint256 nonce,
    uint256 deadline
  ) internal pure returns (ISignatureTransfer.PermitBatchTransferFrom memory permit) {
    permit.permitted = new ISignatureTransfer.TokenPermissions[](transfers.length);
    permit.nonce = nonce;
    permit.deadline = deadline;

    for (uint256 i = 0; i < transfers.length; i++) {
      ERC20Transfer memory transfer = transfers[i];
      permit.permitted[i] =
        ISignatureTransfer.TokenPermissions({token: transfer.token, amount: transfer.amount});
    }
  }

  /// @dev Shapes the transfers as Permit2 signature-transfer details
  function toSignatureTransferDetails(ERC20Transfer[] calldata transfers)
    internal
    pure
    returns (ISignatureTransfer.SignatureTransferDetails[] memory details)
  {
    details = new ISignatureTransfer.SignatureTransferDetails[](transfers.length);
    for (uint256 i = 0; i < transfers.length; i++) {
      ERC20Transfer memory transfer = transfers[i];
      details[i] = ISignatureTransfer.SignatureTransferDetails({
        to: transfer.target, requestedAmount: transfer.amount
      });
    }
  }

  /// @dev As {toSignatureTransferDetails}, for an array already in memory
  function toSignatureTransferDetailsMemory(ERC20Transfer[] memory transfers)
    internal
    pure
    returns (ISignatureTransfer.SignatureTransferDetails[] memory details)
  {
    details = new ISignatureTransfer.SignatureTransferDetails[](transfers.length);
    for (uint256 i = 0; i < transfers.length; i++) {
      ERC20Transfer memory transfer = transfers[i];
      details[i] = ISignatureTransfer.SignatureTransferDetails({
        to: transfer.target, requestedAmount: transfer.amount
      });
    }
  }

  /// @dev The target of each transfer, in order; this is what a witness binds
  function toTargets(ERC20Transfer[] calldata transfers)
    internal
    pure
    returns (address[] memory targets)
  {
    targets = new address[](transfers.length);
    for (uint256 i = 0; i < transfers.length; i++) {
      targets[i] = transfers[i].target;
    }
  }

  /// @dev As {toTargets}, for an array already in memory
  function toTargetsMemory(ERC20Transfer[] memory transfers)
    internal
    pure
    returns (address[] memory targets)
  {
    targets = new address[](transfers.length);
    for (uint256 i = 0; i < transfers.length; i++) {
      targets[i] = transfers[i].target;
    }
  }

  /// @dev Shapes the transfers as Permit2 allowance-transfer details, all drawn from `owner`
  function toAllowanceTransferDetails(ERC20Transfer[] calldata transfers, address owner)
    internal
    pure
    returns (IAllowanceTransfer.AllowanceTransferDetails[] memory details)
  {
    details = new IAllowanceTransfer.AllowanceTransferDetails[](transfers.length);
    for (uint256 i = 0; i < transfers.length; i++) {
      ERC20Transfer memory transfer = transfers[i];
      details[i] = IAllowanceTransfer.AllowanceTransferDetails({
        from: owner, to: transfer.target, token: transfer.token, amount: transfer.amount
      });
    }
  }

  /// @dev As {toAllowanceTransferDetails}, for an array already in memory
  function toAllowanceTransferDetailsMemory(ERC20Transfer[] memory transfers, address owner)
    internal
    pure
    returns (IAllowanceTransfer.AllowanceTransferDetails[] memory details)
  {
    details = new IAllowanceTransfer.AllowanceTransferDetails[](transfers.length);
    for (uint256 i = 0; i < transfers.length; i++) {
      ERC20Transfer memory transfer = transfers[i];
      details[i] = IAllowanceTransfer.AllowanceTransferDetails({
        from: owner, to: transfer.target, token: transfer.token, amount: transfer.amount
      });
    }
  }
}
