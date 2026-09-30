// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title IEIP712Base
/// @notice Interface of {EIP712Base}
interface IEIP712Base {
  /**
   * @notice EIP-712 domain separator every signature this contract checks is scoped to
   * @dev Rebuilt when the chain id or this contract's address differs from deployment, so a
   * signature cannot be replayed onto another chain or another deployment.
   * @return The domain separator
   */
  function DOMAIN_SEPARATOR() external view returns (bytes32);
}
