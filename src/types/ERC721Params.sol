// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {PermitHelper} from 'ks-common-sc/src/libraries/token/PermitHelper.sol';

import {IERC721} from 'openzeppelin-contracts/contracts/interfaces/IERC721.sol';

/**
 * @notice Parameters for collecting a single ERC721 token from its owner
 * @param token The address of the collection
 * @param tokenId The token ID to collect
 * @param target The address to transfer the token to
 * @param permitData The ERC721 permit to run before transferring, empty to skip
 */
struct ERC721Params {
  address token;
  uint256 tokenId;
  address target;
  bytes permitData;
}

using ERC721ParamsLibrary for ERC721Params global;

/// @notice Contains functions for working with ERC721Params
library ERC721ParamsLibrary {
  using PermitHelper for address;

  /**
   * @notice Permits and transfers an ERC721 token from `owner` to the target
   * @dev `safeTransferFrom` hands control to `target` if it is a contract, so callers must be
   * reentrancy-safe at this point.
   * @param self The parameters of the token to collect
   * @param owner The current owner of the token
   */
  function permitTransfer(ERC721Params calldata self, address owner) internal {
    // Establishes the approval if one was signed, otherwise relies on an existing one
    self.token.callERC721Permit(self.tokenId, self.permitData);

    IERC721(self.token).safeTransferFrom(owner, self.target, self.tokenId);
  }
}
