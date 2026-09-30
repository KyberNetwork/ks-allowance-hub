// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title ISessionAuthVerifier
/// @notice Interface of {SessionAuthVerifier}
interface ISessionAuthVerifier {
  /// @notice The presented signature does not authorise what it was checked against
  error InvalidApprovalSignature();

  /// @notice The owner has not approved the session key presented with the order
  error SessionKeyNotDelegated();

  /// @notice The session key's expiry is in the past
  error SessionKeyExpired();

  /**
   * @notice Whether `owner` has approved the session key with this hash
   * @param owner Account the key may sign for
   * @param keyHash EIP-712 hash of the key, covering its public half, scheme and expiry
   */
  function approvedKeys(address owner, bytes32 keyHash) external view returns (bool);
}
