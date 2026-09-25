// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title ISessionAuthVerifier
/// @notice Interface of {SessionAuthVerifier}
interface ISessionAuthVerifier {
  error InvalidApprovalSignature();

  error SessionKeyNotDelegated();

  error SessionKeyExpired();

  /**
   * @notice Whether `owner` has approved the session key with this hash
   * @param owner Account the key may sign for
   * @param keyHash EIP-712 hash of the key, covering its public half, scheme and expiry
   */
  function approvedKeys(address owner, bytes32 keyHash) external view returns (bool);
}
