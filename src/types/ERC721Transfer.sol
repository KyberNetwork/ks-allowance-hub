// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ERC721Params} from './ERC721Params.sol';

/**
 * @notice Indicates an ERC721 token transfer
 * @param token The address of the token
 * @param tokenId The token ID
 * @param target The address of the target
 */
struct ERC721Transfer {
  address token;
  uint256 tokenId;
  address target;
}

library ERC721TransferLibrary {
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
