// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IAllowanceTransfer} from 'ks-common-sc/src/interfaces/IAllowanceTransfer.sol';
import {ISignatureTransfer} from 'ks-common-sc/src/interfaces/ISignatureTransfer.sol';
import {TokenHelper} from 'ks-common-sc/src/libraries/token/TokenHelper.sol';

import {DynamicArrayLib} from 'solady/utils/DynamicArrayLib.sol';
import {EfficientHashLib} from 'solady/utils/EfficientHashLib.sol';

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

using ERC20TransferLib for ERC20Transfer global;

library ERC20TransferLib {
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

  /**
   * @dev EIP-712 hash of the array: its member hashes, concatenated and hashed. Word-sized members
   * already sit in memory exactly as `abi.encodePacked` would lay them out, so the digest is taken
   * over the array's own data and nothing is copied to reach it.
   */
  function hash(ERC20Transfer[] calldata transfers) internal pure returns (bytes32) {
    bytes32[] memory hashes = EfficientHashLib.malloc(transfers.length);
    for (uint256 i = 0; i < transfers.length; i++) {
      hashes[i] = hash(transfers[i]);
    }

    return EfficientHashLib.hash(hashes);
  }

  /// @dev As {hash}, for an array already in memory
  function hashMemory(ERC20Transfer[] memory transfers) internal pure returns (bytes32) {
    bytes32[] memory hashes = EfficientHashLib.malloc(transfers.length);
    for (uint256 i = 0; i < transfers.length; i++) {
      hashes[i] = hashMemory(transfers[i]);
    }

    return EfficientHashLib.hash(hashes);
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
    permit.permitted = _mallocTokenPermissions(transfers.length);
    permit.nonce = nonce;
    permit.deadline = deadline;

    for (uint256 i = 0; i < transfers.length; i++) {
      ERC20Transfer calldata transfer = transfers[i];
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
    permit.permitted = _mallocTokenPermissions(transfers.length);
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
    details = _mallocSignatureTransferDetails(transfers.length);
    for (uint256 i = 0; i < transfers.length; i++) {
      ERC20Transfer calldata transfer = transfers[i];
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
    details = _mallocSignatureTransferDetails(transfers.length);
    for (uint256 i = 0; i < transfers.length; i++) {
      ERC20Transfer memory transfer = transfers[i];
      details[i] = ISignatureTransfer.SignatureTransferDetails({
        to: transfer.target, requestedAmount: transfer.amount
      });
    }
  }

  /// @dev The target of each transfer, in order; this is what a witness binds
  function extractTargets(ERC20Transfer[] calldata transfers)
    internal
    pure
    returns (address[] memory targets)
  {
    targets = DynamicArrayLib.asAddressArray(DynamicArrayLib.malloc(transfers.length));
    for (uint256 i = 0; i < transfers.length; i++) {
      targets[i] = transfers[i].target;
    }
  }

  /// @dev As {extractTargets}, for an array already in memory
  function extractTargetsMemory(ERC20Transfer[] memory transfers)
    internal
    pure
    returns (address[] memory targets)
  {
    targets = DynamicArrayLib.asAddressArray(DynamicArrayLib.malloc(transfers.length));
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
    details = _mallocAllowanceTransferDetails(transfers.length);
    for (uint256 i = 0; i < transfers.length; i++) {
      ERC20Transfer calldata transfer = transfers[i];
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
    details = _mallocAllowanceTransferDetails(transfers.length);
    for (uint256 i = 0; i < transfers.length; i++) {
      ERC20Transfer memory transfer = transfers[i];
      details[i] = IAllowanceTransfer.AllowanceTransferDetails({
        from: owner, to: transfer.target, token: transfer.token, amount: transfer.amount
      });
    }
  }

  /**
   * @dev The three allocators below hand back pointer slots and nothing else. Assigning a struct
   * to a memory array element writes a pointer to a freshly built struct, so the bodies `new`
   * allocates and zeroes are discarded unread; every slot is written before anything reads one.
   */
  function _mallocTokenPermissions(uint256 length)
    private
    pure
    returns (ISignatureTransfer.TokenPermissions[] memory array)
  {
    uint256[] memory buffer = DynamicArrayLib.malloc(length);
    assembly ('memory-safe') {
      array := buffer
    }
  }

  /// @dev As {_mallocTokenPermissions}, for Permit2's signature-transfer details
  function _mallocSignatureTransferDetails(uint256 length)
    private
    pure
    returns (ISignatureTransfer.SignatureTransferDetails[] memory array)
  {
    uint256[] memory buffer = DynamicArrayLib.malloc(length);
    assembly ('memory-safe') {
      array := buffer
    }
  }

  /// @dev As {_mallocTokenPermissions}, for Permit2's allowance-transfer details
  function _mallocAllowanceTransferDetails(uint256 length)
    private
    pure
    returns (IAllowanceTransfer.AllowanceTransferDetails[] memory array)
  {
    uint256[] memory buffer = DynamicArrayLib.malloc(length);
    assembly ('memory-safe') {
      array := buffer
    }
  }
}
