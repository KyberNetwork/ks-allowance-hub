// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title IUnorderedNonce
/// @notice Interface of {UnorderedNonce}
interface IUnorderedNonce {
  /// @notice This nonce has already been spent, or was revoked by its owner
  error NonceAlreadyUsed();

  /**
   * @notice Spent-nonce bitmap, keyed by signer namespace and by the nonce's word index
   * @param signer Namespace the nonces belong to: whoever signed the data they guard, as an
   * address widened to a word or as the hash of a signing key
   * @param word The nonce's top bits, i.e. `nonce >> 8`
   */
  function nonces(bytes32 signer, uint256 word) external view returns (uint256);

  /**
   * @notice Burns one of the caller's own nonces, cancelling a signature that has not been used
   * @param nonce The nonce to spend
   */
  function revokeNonce(uint256 nonce) external payable;
}
