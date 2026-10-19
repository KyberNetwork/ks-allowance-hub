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

  /// @notice The signature does not authorise this key's revocation of the nonce
  error InvalidRevocationSignature();

  /// @notice The owner has not approved this master key, or has revoked it
  error MasterKeyNotApproved(bytes32 masterKeyHash);

  /// @notice No master key stands behind this session key
  error SessionKeyNotApproved(bytes32 sessionKeyHash);

  /// @notice The key's expiry is in the past
  error AuthKeyExpired(uint256 expiration, uint256 currentTime);

  /// @notice Another master key approved this session key, and only it may approve or revoke it
  error SessionKeyApprovedByAnother(
    bytes32 sessionKeyHash, bytes32 masterKeyHash, bytes32 expectedMasterKeyHash
  );

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

  /**
   * @notice Spends one of a key's own nonces, cancelling a signature of that key that has not been used
   * @dev The key's counterpart of {IUnorderedNonce-revokeNonce}, which spends only the caller's
   * address namespace and so cannot reach a key that is not an account. The key signs the
   * revocation instead, and anyone may submit it.
   * @param key The key whose namespace the nonce belongs to
   * @param nonce The nonce to spend
   * @param deadline Last timestamp at which the revocation may be submitted
   * @param signature The key's signature over the `NonceRevocation`
   */
  function revokeNonce(
    AuthKey calldata key,
    uint256 nonce,
    uint256 deadline,
    bytes calldata signature
  ) external;
}
