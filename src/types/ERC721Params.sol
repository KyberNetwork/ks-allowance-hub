// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {PermitHelper} from 'ks-common-sc/src/libraries/token/PermitHelper.sol';

import {IERC721} from 'openzeppelin-contracts/contracts/interfaces/IERC721.sol';

/**
 * @notice Parameters for collecting an ERC721 token from `msg.sender`
 * @param token The address of the token to collect
 * @param tokenId The token ID to collect
 * @param target The address to transfer the token to
 * @param permitData The permit data for the token
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

  /// @notice Collects an ERC721 token from `msg.sender`
  function collect(ERC721Params calldata self) internal {
    /// @dev Permits the token if needed
    self.token.callERC721Permit(self.tokenId, self.permitData);

    /// @dev Transfers the token to the target
    IERC721(self.token).transferFrom(msg.sender, self.target, self.tokenId);
  }
}
