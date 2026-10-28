// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {AuthKey} from '../../../base/types/AuthKey.sol';

/// @title ISessionOrderAuthenticator
/// @notice Interface of {SessionOrderAuthenticator}
interface ISessionOrderAuthenticator {
  /// @notice The signature is not a valid approval of this key by the required signer
  error InvalidApprovalSignature();

  /// @notice The owner called directly, which takes an empty signature, and gave a signature
  error UnexpectedSignature();

  /// @notice The key's signature over the order is not valid
  error InvalidOrderSignature();

  /// @notice The key's signature over the nonce revocation is not valid
  error InvalidRevocationSignature();

  /// @notice The owner has not approved this master key, or has revoked it
  error MasterKeyNotApproved(bytes32 masterKeyHash);

  /// @notice No master key has approved this session key, or its approval was revoked
  error SessionKeyNotApproved(bytes32 sessionKeyHash);

  /// @notice The key has expired
  error AuthKeyExpired(uint256 expiration, uint256 currentTime);

  /// @notice Another master key approved this session key; only that master key may change it
  error SessionKeyAlreadyApproved(
    bytes32 sessionKeyHash, bytes32 masterKeyHash, bytes32 expectedMasterKeyHash
  );

  /// @notice The session key expires after the master key that approves it
  error SessionKeyOutlivesMasterKey(uint256 sessionKeyExpiration, uint256 masterKeyExpiration);

  /**
   * @notice Whether `owner` has approved the key with this hash as a master key
   * @param owner Account the key may sign for
   * @param keyHash EIP-712 hash of the key, covering its public key, type and expiry
   * @return Whether the key is an approved master key of `owner`
   */
  function masterKeys(address owner, bytes32 keyHash) external view returns (bool);

  /**
   * @notice The master key that approved `owner`'s session key with this hash
   * @param owner Account the key may sign for
   * @param keyHash EIP-712 hash of the key, covering its public key, type and expiry
   * @return Hash of the approving master key, or zero when no master key approved it
   */
  function sessionKeyMaster(address owner, bytes32 keyHash) external view returns (bytes32);

  /**
   * @notice Spends a nonce under a key's credential, invalidating the key's unused signature that
   * carries it
   * @dev {IUnorderedNonce-revokeNonce} spends only in the caller's address namespace. This function
   * spends under a key's credential instead, on the key's signature, and any account may submit it.
   * @param key The key whose credential the nonce is spent under
   * @param nonce The nonce to spend
   * @param deadline Last timestamp at which the call is accepted
   * @param signature The key's signature over the {NonceRevocation}
   */
  function revokeNonce(
    AuthKey calldata key,
    uint256 nonce,
    uint256 deadline,
    bytes calldata signature
  ) external;
}
