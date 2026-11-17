// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IERC721} from 'openzeppelin-contracts/contracts/token/ERC721/IERC721.sol';

/**
 * @notice An ERC721 transfer as {IKSAllowanceHubV2-TransferTokens} reports it, from the owner to
 * `target`
 * @dev In {IKSAllowanceHubV2-rescueTokens}, the entry is a transfer from the hub.
 * @param token The ERC721 contract
 * @param tokenId The token transferred
 * @param target Account the token is transferred to
 */
struct ERC721Transfer {
  address token;
  uint256 tokenId;
  address target;
}

using ERC721TransferLib for ERC721Transfer global;

library ERC721TransferLib {
  /// @dev Transfers each token from `owner` to its target
  function execute(ERC721Transfer[] calldata transfers, address owner) internal {
    for (uint256 i = 0; i < transfers.length; i++) {
      ERC721Transfer calldata transfer = transfers[i];
      IERC721(transfer.token).safeTransferFrom(owner, transfer.target, transfer.tokenId);
    }
  }
}
