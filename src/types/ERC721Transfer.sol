// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

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
