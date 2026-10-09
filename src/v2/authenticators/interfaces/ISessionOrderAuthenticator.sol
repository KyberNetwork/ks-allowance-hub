// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {AuthKey} from '../types/AuthKey.sol';

/// @title ISessionOrderAuthenticator
/// @notice Interface of {SessionOrderAuthenticator}
interface ISessionOrderAuthenticator {
  /// @notice The signature does not authorise this decision about the key
  error InvalidApprovalSignature();

  /// @notice The key's signature does not authenticate the order it was presented with
  error InvalidAuthenticationSignature();

  /// @notice The key presented as a master key has not been approved by the owner
  error MasterKeyNotApproved(address owner, AuthKey masterKey);

  /// @notice The session key's own grant remains, but the master key it names does not
  error SessionKeyNotApproved(address owner, AuthKey sessionKey, bytes32 masterKeyHash);

  /// @notice The key's expiry is in the past
  error AuthKeyExpired(uint256 currentTime, uint256 expiration);

  /// @notice A session key may not outlive the master key that approves it
  error SessionKeyOutlivesMasterKey(uint256 sessionKeyExpiration, uint256 masterKeyExpiration);

  /**
   * @notice Whether `owner` approved this key themselves
   * @param owner Account the key may sign for
   * @param keyHash EIP-712 hash of the key, covering its public half, scheme and expiry
   * @return Whether it is one of their master keys
   */
  function masterKeys(address owner, bytes32 keyHash) external view returns (bool);

  /**
   * @notice Which master key approved `owner`'s session key with this hash
   * @param owner Account the key may sign for
   * @param keyHash EIP-712 hash of the key, covering its public half, scheme and expiry
   * @return Hash of the master key that approved it, or zero when none did
   */
  function sessionKeyMaster(address owner, bytes32 keyHash) external view returns (bytes32);
}
