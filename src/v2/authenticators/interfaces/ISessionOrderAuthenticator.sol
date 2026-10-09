// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {AuthKey} from '../types/AuthKey.sol';

/// @title ISessionOrderAuthenticator
/// @notice Interface of {SessionOrderAuthenticator}
interface ISessionOrderAuthenticator {
  /// @notice The signature does not approve the key it was presented with
  error InvalidApprovalSignature();

  /// @notice The key's signature does not authenticate the order it was presented with
  error InvalidAuthenticationSignature();

  /// @notice The key is not approved for this owner, or the master key behind it no longer is
  error AuthKeyNotApproved(address owner, AuthKey key);

  /// @notice The key's expiry is in the past
  error AuthKeyExpired(uint256 currentTime, uint256 expiration);

  /// @notice A master key may not speak about a session key that outlives it
  error SessionKeyOutlivesMasterKey(uint256 sessionKeyExpiration, uint256 masterKeyExpiration);

  /**
   * @notice Whether `owner` approved this key themselves, which is what makes it a master key
   * @param owner Account the key may sign for
   * @param keyHash EIP-712 hash of the key, covering its public half, scheme and expiry
   * @return Whether the owner approved it
   */
  function masterKeys(address owner, bytes32 keyHash) external view returns (bool);

  /**
   * @notice Which master key approved this session key, for `owner`
   * @param owner Account the key may sign for
   * @param keyHash EIP-712 hash of the key, covering its public half, scheme and expiry
   * @return Hash of the master key behind it, or zero when no master key approved it
   */
  function sessionKeyMaster(address owner, bytes32 keyHash) external view returns (bytes32);
}
