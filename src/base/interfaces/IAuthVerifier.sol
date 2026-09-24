// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title IAuthVerifier
/// @notice Interface every authorisation verifier used by {AuthDelegator} must implement
interface IAuthVerifier {
  error NotAllowanceHub();

  /**
   * @notice Records the owner's first authorisation material, as the hub delegates this verifier
   * @dev Carries no signature, nonce or deadline, so an implementation must accept it only from a
   * hub it trusts: {AuthDelegator-updateDelegation} authenticates the owner before calling, and
   * this selector is deliberately absent from {ICallsForwarder-forward}'s allowlist, so it cannot
   * be relayed on anyone's behalf.
   * @param owner Account the material belongs to
   * @param data Verifier-specific payload
   */
  function initAuth(address owner, bytes calldata data) external;

  /**
   * @notice Records, replaces or withdraws the owner's authorisation material
   * @dev Anyone may reach this, including through {ICallsForwarder-forward}, which relays it from
   * any caller and leaves the hub as `msg.sender`. An implementation must therefore treat only
   * `msg.sender == owner` as authentication and verify `signature` in every other case; reading
   * "called by the hub" as proof the owner was authenticated would let anyone install material
   * for anyone. Replay protection belongs to the implementation.
   * @param owner Account the material belongs to
   * @param data Verifier-specific payload
   * @param nonce For the implementation to consume, when it checks the signature
   * @param deadline Last timestamp at which the update is valid
   * @param signature Owner's authorisation, needed unless the owner is the caller
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
