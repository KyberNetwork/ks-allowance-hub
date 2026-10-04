// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {SessionKey} from '../types/SessionKey.sol';

/// @title ISessionOrderAuthenticator
/// @notice Interface of {SessionOrderAuthenticator}
interface ISessionOrderAuthenticator {
  /// @notice The owner's signature does not approve the session key it was presented with
  error InvalidApprovalSignature();

  /// @notice The session key's signature does not authenticate the order it was presented with
  error InvalidAuthenticationSignature();

  /// @notice The owner has not approved the session key presented with the order
  error SessionKeyNotApproved(address owner, SessionKey key);

  /// @notice The session key's expiry is in the past
  error SessionKeyExpired(uint256 currentTime, uint256 expiration);

  /**
   * @notice Whether `owner` has approved the session key with this hash
   * @param owner Account the key may sign for
   * @param keyHash EIP-712 hash of the key, covering its public half, scheme and expiry
   * @return Whether the owner approved it
   */
  function approvedKeys(address owner, bytes32 keyHash) external view returns (bool);
}
