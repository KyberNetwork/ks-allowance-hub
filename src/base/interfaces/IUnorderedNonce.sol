// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title IUnorderedNonce
/// @notice Interface of {UnorderedNonce}
interface IUnorderedNonce {
  error NonceAlreadyUsed();

  /**
   * @notice Spent-nonce bitmap, keyed by owner and by the nonce's word index
   * @param owner Account whose nonces these are
   * @param word The nonce's top bits, i.e. `nonce >> 8`
   */
  function nonces(address owner, uint256 word) external view returns (uint256);

  /**
   * @notice Burns one of the caller's own nonces, cancelling a signature that has not been used
   * @param nonce The nonce to spend
   */
  function revokeNonce(uint256 nonce) external payable;
}
