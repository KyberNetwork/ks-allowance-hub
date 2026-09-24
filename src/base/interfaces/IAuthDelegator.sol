// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title IAuthDelegator
/// @notice Interface of {AuthDelegator}
interface IAuthDelegator {
  error InvalidDelegationSignature();

  error NotDelegatedVerifier();

  /**
   * @notice Whether `owner` has authorised `verifier` to approve orders on their behalf
   * @param owner Account whose assets the verifier may authorise
   * @param verifier Contract that checks the owner's authorisations
   */
  function authDelegated(address owner, address verifier) external view returns (bool);

  /**
   * @notice Delegates authorisation to `verifier`, or withdraws it
   * @dev `data` reaches the verifier only when delegating, so withdrawing cannot be blocked by a
   * verifier that reverts. Withdrawing leaves the verifier's own state alone; drop it first with
   * {updateAuth} when both should go.
   * @param owner Account whose orders the verifier may approve
   * @param verifier Contract that will check future authorisations
   * @param delegated True to delegate the verifier, false to withdraw it
   * @param data Verifier-specific payload, opaque here and ignored when withdrawing
   * @param nonce Consumed only when someone other than the owner submits
   * @param deadline Last timestamp at which the delegation may be submitted
   * @param signature The owner's `AuthDelegation` signature, or empty when the owner is the caller
   */
  function updateDelegation(
    address owner,
    address verifier,
    bool delegated,
    bytes calldata data,
    uint256 nonce,
    uint256 deadline,
    bytes calldata signature
  ) external payable;

  /**
   * @notice Replaces the owner's material at an already delegated verifier
   * @dev A non-owner caller must supply a signature, so an empty one always means this contract
   * authenticated the owner itself. The verifier checks the signature and its own replay rules.
   * @param owner Account whose material is being replaced
   * @param verifier The already-delegated verifier to forward to
   * @param data Verifier-specific payload, opaque here
   * @param nonce Passed through for the verifier to consume
   * @param deadline Last timestamp at which the update may be submitted
   * @param signature Owner's authorisation, or empty when the owner is the caller
   */
  function updateAuth(
    address owner,
    address verifier,
    bytes calldata data,
    uint256 nonce,
    uint256 deadline,
    bytes calldata signature
  ) external payable;
}
