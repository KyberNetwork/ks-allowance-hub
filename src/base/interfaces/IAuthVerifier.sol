// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title IAuthVerifier
/// @notice Interface every authorisation verifier used by {AuthDelegator} must implement
interface IAuthVerifier {
  error NotAllowanceHub();

  /**
   * @notice Records or replaces the owner's authorisation material
   * @dev An empty `signature` is only meaningful from a caller that is already authenticated —
   * the owner themselves, or an allowance hub that forwards one only after authenticating them —
   * and lets the verifier accept `data` as-is. A non-empty one must be verified by the
   * implementation, which also owns replay protection for it.
   * @param owner Account the material belongs to
   * @param data Verifier-specific payload
   * @param nonce For the implementation to consume, when it checks the signature
   * @param deadline Last timestamp at which the update is valid
   * @param signature Owner's authorisation, or empty when the hub already authenticated them
   */
  function updateAuth(
    address owner,
    bytes calldata data,
    uint256 nonce,
    uint256 deadline,
    bytes calldata signature
  ) external;

  /**
   * @notice Checks that `signature` authorises `data` on behalf of `owner`
   * @dev Must revert when it does not; returning normally is read as success. Implementations
   * must bind `nonce` and `deadline` into the digest they verify and consume the nonce, since the
   * hub enforces neither on this path.
   * @param owner Account the order draws on
   * @param data The order, as the hub encoded it; its last byte marks which entry point built it
   * @param nonce Must be bound into the digest and consumed
   * @param deadline Must be bound into the digest
   * @param key Identifies which of the owner's credentials signed
   * @param signature The credential's signature over the order
   */
  function verifyAuth(
    address owner,
    bytes calldata data,
    uint256 nonce,
    uint256 deadline,
    bytes calldata key,
    bytes calldata signature
  ) external;
}
