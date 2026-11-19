// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title IAuthDelegator
/// @notice Interface of {AuthDelegator}
interface IAuthDelegator {
  /// @notice The signature is not the owner's signature over the delegation
  error InvalidDelegationSignature();

  /// @notice The owner called directly, which takes an empty signature, and gave a signature
  error UnexpectedSignature();

  /// @notice The delegation's deadline has passed
  error DeadlinePassed(uint256 deadline, uint256 currentTime);

  /// @notice The order's owner has not delegated this authenticator
  error AuthenticatorNotDelegated(address authenticator);

  /// @notice Emitted when `owner` delegates `authenticator` or withdraws its delegation
  event UpdateDelegation(address indexed owner, address indexed authenticator, bool delegated);

  /**
   * @notice Whether `owner` has delegated `authenticator` to authenticate their orders
   * @param owner Account whose orders the authenticator may authenticate
   * @param authenticator Authenticator contract
   * @return Whether the delegation is in place
   */
  function authDelegated(address owner, address authenticator) external view returns (bool);

  /**
   * @notice Delegates `authenticator` to authenticate `owner`'s orders, or withdraws the delegation
   * @dev The owner's own call needs no signature and spends no nonce. Any other caller needs the
   * owner's signature over the {AuthDelegation}.
   * @param owner Account whose orders the authenticator may authenticate
   * @param authenticator Authenticator contract
   * @param delegated True to delegate, false to withdraw
   * @param data Initial authentication material for the authenticator; ignored when withdrawing
   * @param nonce Nonce of the signature; unused when the caller is `owner`
   * @param deadline Last timestamp at which the call is accepted
   * @param signature The owner's signature over the {AuthDelegation}, or empty when the caller is
   * `owner`
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
