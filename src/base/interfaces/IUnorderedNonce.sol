// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title IUnorderedNonce
/// @notice Interface of {UnorderedNonce}
interface IUnorderedNonce {
  /// @notice The nonce has already been spent in this namespace
  error NonceAlreadyUsed(bytes32 namespace, uint256 nonce);

  /**
   * @notice One word of the spent-nonce bitmap of a namespace
   * @param namespace An account's address as a 32-byte word, or a key's credential hash
   * @param word The nonce's word index, `nonce >> 8`
   * @return The bitmap word, in which bit `nonce & 0xff` is set when the nonce is spent
   */
  function nonces(bytes32 namespace, uint256 word) external view returns (uint256);

  /**
   * @notice Spends a nonce in the caller's address namespace, invalidating the caller's unused
   * signature that carries it
   * @param nonce The nonce to spend
   */
  function revokeNonce(uint256 nonce) external payable;
}
