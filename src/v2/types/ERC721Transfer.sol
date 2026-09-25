// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IERC721} from 'openzeppelin-contracts/contracts/token/ERC721/IERC721.sol';

/// @notice One ERC721 leg of an order, moved directly from the owner to `target`
struct ERC721Transfer {
  address token;
  uint256 tokenId;
  address target;
}

using ERC721TransferLibrary for ERC721Transfer global;

library ERC721TransferLibrary {
  bytes32 internal constant ERC721_TRANSFER_TYPEHASH =
    keccak256('ERC721Transfer(address token,uint256 tokenId,address target)');

  /// @dev EIP-712 hash of one transfer
  function hash(ERC721Transfer calldata self) internal pure returns (bytes32) {
    return keccak256(abi.encode(ERC721_TRANSFER_TYPEHASH, self.token, self.tokenId, self.target));
  }

  /// @dev As {hash}, for a transfer already in memory
  function hashMemory(ERC721Transfer memory self) internal pure returns (bytes32) {
    return keccak256(abi.encode(ERC721_TRANSFER_TYPEHASH, self.token, self.tokenId, self.target));
  }

  /// @dev EIP-712 hash of the array: its member hashes, concatenated and hashed
  function hash(ERC721Transfer[] calldata transfers) internal pure returns (bytes32) {
    bytes32[] memory hashes = new bytes32[](transfers.length);
    for (uint256 i = 0; i < transfers.length; i++) {
      hashes[i] = hash(transfers[i]);
    }
    return keccak256(abi.encodePacked(hashes));
  }

  /// @dev As {hash}, for an array already in memory
  function hashMemory(ERC721Transfer[] memory transfers) internal pure returns (bytes32) {
    bytes32[] memory hashes = new bytes32[](transfers.length);
    for (uint256 i = 0; i < transfers.length; i++) {
      hashes[i] = hashMemory(transfers[i]);
    }
    return keccak256(abi.encodePacked(hashes));
  }

  /// @dev Moves each token from `owner` to its target, so the hub never holds the NFT
  function execute(ERC721Transfer[] calldata transfers, address owner) internal {
    for (uint256 i = 0; i < transfers.length; i++) {
      ERC721Transfer calldata transfer = transfers[i];
      IERC721(transfer.token).safeTransferFrom(owner, transfer.target, transfer.tokenId);
    }
  }
}
