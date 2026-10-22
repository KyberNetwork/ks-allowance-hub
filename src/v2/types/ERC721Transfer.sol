// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IERC721} from 'openzeppelin-contracts/contracts/token/ERC721/IERC721.sol';

import {EfficientHashLib} from 'solady/utils/EfficientHashLib.sol';

/**
 * @notice One ERC721 leg of an execution order, transferred from the owner to `target`
 * @dev In {IKSAllowanceHubV2-rescueTokens}, the entry is a transfer from the hub.
 */
struct ERC721Transfer {
  address token;
  uint256 tokenId;
  address target;
}

using ERC721TransferLib for ERC721Transfer global;

library ERC721TransferLib {
  using EfficientHashLib for *;

  bytes32 internal constant ERC721_TRANSFER_TYPEHASH =
    keccak256('ERC721Transfer(address token,uint256 tokenId,address target)');

  /// @dev EIP-712 hash of one transfer
  function hash(ERC721Transfer calldata self) internal pure returns (bytes32 digest) {
    bytes32 typehash = ERC721_TRANSFER_TYPEHASH;
    assembly ('memory-safe') {
      let fmp := mload(0x40)
      mstore(fmp, typehash)
      calldatacopy(add(fmp, 0x20), self, 0x60)
      digest := keccak256(fmp, 0x80)
    }
  }

  /// @dev As {hash}, for a transfer already in memory
  function hashMemory(ERC721Transfer memory self) internal pure returns (bytes32) {
    return keccak256(abi.encode(ERC721_TRANSFER_TYPEHASH, self.token, self.tokenId, self.target));
  }

  /// @dev EIP-712 hash of the array: its member hashes, concatenated and hashed
  function hash(ERC721Transfer[] calldata transfers) internal pure returns (bytes32) {
    bytes32[] memory transferHashes = transfers.length.malloc();
    for (uint256 i = 0; i < transfers.length; i++) {
      transferHashes[i] = hash(transfers[i]);
    }

    return transferHashes.hash();
  }

  /// @dev As {hash}, for an array already in memory
  function hashMemory(ERC721Transfer[] memory transfers) internal pure returns (bytes32) {
    bytes32[] memory transferHashes = transfers.length.malloc();
    for (uint256 i = 0; i < transfers.length; i++) {
      transferHashes[i] = hashMemory(transfers[i]);
    }

    return transferHashes.hash();
  }

  /// @dev Transfers each token from `owner` to its target
  function execute(ERC721Transfer[] calldata transfers, address owner) internal {
    for (uint256 i = 0; i < transfers.length; i++) {
      ERC721Transfer calldata transfer = transfers[i];
      IERC721(transfer.token).safeTransferFrom(owner, transfer.target, transfer.tokenId);
    }
  }
}
