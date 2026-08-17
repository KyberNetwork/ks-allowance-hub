// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ERC721Params} from './ERC721Params.sol';

/**
 * @notice A single ERC721 token movement, as signed in a witness and reported in `TransferTokens`
 * @param token The address of the collection
 * @param tokenId The token ID transferred
 * @param target The address the token was transferred to
 */
struct ERC721Transfer {
  address token;
  uint256 tokenId;
  address target;
}

using ERC721TransferLibrary for ERC721Transfer global;

/// @notice Contains functions for working with ERC721Transfer
library ERC721TransferLibrary {
  /// @dev The EIP-712 type hash of `ERC721Transfer`
  bytes32 internal constant ERC721_TRANSFER_TYPEHASH =
    keccak256('ERC721Transfer(address token,uint256 tokenId,address target)');

  /**
   * @notice Hashes a transfer following EIP-712 struct encoding
   * @param self The transfer to hash
   * @return The EIP-712 hash of the transfer
   */
  function hash(ERC721Transfer memory self) internal pure returns (bytes32) {
    return keccak256(abi.encode(ERC721_TRANSFER_TYPEHASH, self.token, self.tokenId, self.target));
  }

  /**
   * @notice Reduces the collection parameters to the movements they produce
   * @dev Drops `permitData`, which authorises the transfer but is not part of what is signed.
   * @param params The ERC721 tokens being collected
   * @return transfers The resulting movements, index-aligned with `params`
   */
  function toTransfers(ERC721Params[] calldata params)
    internal
    pure
    returns (ERC721Transfer[] memory transfers)
  {
    transfers = new ERC721Transfer[](params.length);
    for (uint256 i = 0; i < params.length; i++) {
      transfers[i] = ERC721Transfer({
        token: params[i].token, tokenId: params[i].tokenId, target: params[i].target
      });
    }
  }
}
