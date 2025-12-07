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

  bytes32 internal constant ERC721_PARAMS_TYPE_HASH =
    keccak256('ERC721Params(address token,uint256 tokenId,address target,bytes permitData)');

  /// @notice Permits and collects an ERC721 token from the owner
  function process(ERC721Params calldata self, address owner) internal {
    /// @dev Permits the token if provided
    self.token.callERC721Permit(self.tokenId, self.permitData);

    /// @dev Transfers the token to the target
    IERC721(self.token).transferFrom(owner, self.target, self.tokenId);
  }

  function hash(ERC721Params calldata self) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(
        ERC721_PARAMS_TYPE_HASH, self.token, self.tokenId, self.target, keccak256(self.permitData)
      )
    );
  }
}
