// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title IAuthDelegator
/// @notice Interface of {AuthDelegator}
interface IAuthDelegator {
  /// @notice The signature does not authorise this decision on the owner's behalf
  error InvalidDelegationSignature();

  /// @notice The owner has not delegated the authenticator being asked to authenticate the order
  error NotDelegatedAuthenticator(address owner, address authenticator);

  /**
   * @notice Whether `owner` has authorised `authenticator` to approve orders on their behalf
   * @param owner Account whose assets the authenticator may authorise
   * @param authenticator Contract that authenticates the owner's orders
   * @return Whether the delegation is in place
   */
  function authDelegated(address owner, address authenticator) external view returns (bool);

  /**
   * @notice Delegates authentication to `authenticator`, or withdraws it
   * @dev `data` reaches the authenticator only when delegating, so withdrawing cannot be blocked
   * by one that reverts. Withdrawing leaves the authenticator's own state untouched; withdraw that
   * separately through {ICallsForwarder-forwardCalls} when both are to be removed.
   * @param owner Account whose orders the authenticator may approve
   * @param authenticator Contract that will authenticate future orders
   * @param delegated True to delegate the authenticator, false to withdraw it
   * @param data Authenticator-specific payload, opaque here and ignored when withdrawing
   * @param nonce Consumed only when someone other than the owner submits
   * @param deadline Last timestamp at which the delegation may be submitted
   * @param signature The owner's `AuthDelegation` signature, or empty when the owner is the caller
   */
  function updateDelegation(
    address owner,
    address authenticator,
    bool delegated,
    bytes calldata data,
    uint256 nonce,
    uint256 deadline,
    bytes calldata signature
  ) external payable;
}
