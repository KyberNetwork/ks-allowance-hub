// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {DynamicArrayLibExt} from '../libraries/DynamicArrayLibExt.sol';

import {ERC721Transfer} from './ERC721Transfer.sol';

import {IERC721} from 'openzeppelin-contracts/contracts/token/ERC721/IERC721.sol';

import {EfficientHashLib} from 'solady/utils/EfficientHashLib.sol';

/**
 * @notice One ERC721 leg of a fulfillment order: a token that may leave the owner
 * @dev The destination is not part of the order. The solver names one target per leg in its
 * {FulfillmentSolution}.
 */
struct ERC721Approval {
  address token;
  uint256 tokenId;
}

using ERC721ApprovalLib for ERC721Approval global;

library ERC721ApprovalLib {
  using DynamicArrayLibExt for uint256;
  using EfficientHashLib for *;

  bytes32 internal constant ERC721_APPROVAL_TYPEHASH =
    keccak256('ERC721Approval(address token,uint256 tokenId)');

  /// @dev EIP-712 hash of one approval
  function hash(ERC721Approval calldata self) internal pure returns (bytes32 digest) {
    bytes32 typehash = ERC721_APPROVAL_TYPEHASH;
    assembly ('memory-safe') {
      let fmp := mload(0x40)
      mstore(fmp, typehash)
      calldatacopy(add(fmp, 0x20), self, 0x40)
      digest := keccak256(fmp, 0x60)
    }
  }

  /// @dev As {hash}, for an approval already in memory
  function hashMemory(ERC721Approval memory self) internal pure returns (bytes32) {
    return keccak256(abi.encode(ERC721_APPROVAL_TYPEHASH, self.token, self.tokenId));
  }

  /// @dev EIP-712 hash of the array: its member hashes, concatenated and hashed
  function hash(ERC721Approval[] calldata approvals) internal pure returns (bytes32) {
    bytes32[] memory approvalHashes = approvals.length.malloc();
    for (uint256 i = 0; i < approvals.length; i++) {
      approvalHashes[i] = hash(approvals[i]);
    }

    return approvalHashes.hash();
  }

  /// @dev As {hash}, for an array already in memory
  function hashMemory(ERC721Approval[] memory approvals) internal pure returns (bytes32) {
    bytes32[] memory approvalHashes = approvals.length.malloc();
    for (uint256 i = 0; i < approvals.length; i++) {
      approvalHashes[i] = hashMemory(approvals[i]);
    }

    return approvalHashes.hash();
  }

  /// @dev Moves each token from `owner` to the target at the same index
  function execute(ERC721Approval[] calldata approvals, address owner, address[] calldata targets)
    internal
  {
    for (uint256 i = 0; i < approvals.length; i++) {
      ERC721Approval calldata approval = approvals[i];
      IERC721(approval.token).safeTransferFrom(owner, targets[i], approval.tokenId);
    }
  }

  /// @dev The transfers the approvals become once each is paired with its target
  function toTransfers(ERC721Approval[] calldata approvals, address[] calldata targets)
    internal
    pure
    returns (ERC721Transfer[] memory transfers)
  {
    transfers = approvals.length.mallocERC721Transfers();
    for (uint256 i = 0; i < approvals.length; i++) {
      ERC721Approval calldata approval = approvals[i];
      transfers[i] =
        ERC721Transfer({token: approval.token, tokenId: approval.tokenId, target: targets[i]});
    }
  }
}
