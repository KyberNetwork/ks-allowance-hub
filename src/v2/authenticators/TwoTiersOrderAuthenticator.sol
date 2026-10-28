// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {DeadlineChecker} from '../../base/DeadlineChecker.sol';
import {UnorderedNonce} from '../../base/UnorderedNonce.sol';

import {AuthKey} from '../../base/types/AuthKey.sol';

import {IOrderAuthenticator} from '../interfaces/IOrderAuthenticator.sol';

import {ExecutionOrder} from '../types/ExecutionOrder.sol';
import {FulfillmentOrder} from '../types/FulfillmentOrder.sol';

import {OrderAuthenticatorBase} from './OrderAuthenticatorBase.sol';

import {ITwoTiersOrderAuthenticator} from './interfaces/ITwoTiersOrderAuthenticator.sol';

import {MasterKeyApprovalLib} from './types/MasterKeyApproval.sol';
import {NonceRevocationLib} from './types/NonceRevocation.sol';
import {SessionKeyApprovalLib} from './types/SessionKeyApproval.sol';

import {CalldataDecoder} from 'ks-common-sc/src/libraries/calldata/CalldataDecoder.sol';

import {EIP712} from 'openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol';
import {
  SignatureChecker
} from 'openzeppelin-contracts/contracts/utils/cryptography/SignatureChecker.sol';

/**
 * @title TwoTiersOrderAuthenticator
 * @notice Authenticates allowance-hub orders signed by keys the owner has approved, so that orders
 * can be signed without the owner's wallet. A key has an expiry and is a Secp256k1, P256,
 * WebAuthn, RSA, ERC-1271 or ERC-7913 key.
 * @dev Keys have two tiers. The owner approves master keys, and only a master key may approve
 * other keys. A master key approves session keys for the same owner. Both tiers may sign orders.
 * A session key may not expire after its master key, and is not accepted once its master key is
 * revoked.
 *
 * Every signature this contract verifies spends a nonce in the signer's namespace: the owner's
 * address for the owner's approvals, and the key's credential hash for anything a key signs. The
 * credential hash excludes the expiry, so all approvals of one credential share its nonces.
 */
contract TwoTiersOrderAuthenticator is
  ITwoTiersOrderAuthenticator,
  OrderAuthenticatorBase,
  DeadlineChecker,
  UnorderedNonce,
  EIP712
{
  using CalldataDecoder for bytes;

  /// @inheritdoc ITwoTiersOrderAuthenticator
  mapping(address owner => mapping(bytes32 keyHash => bool)) public masterKeys;

  /// @inheritdoc ITwoTiersOrderAuthenticator
  mapping(address owner => mapping(bytes32 keyHash => bytes32)) public sessionKeyMaster;

  /// @param allowanceHub The only hub whose authentication requests this one answers
  constructor(address allowanceHub)
    OrderAuthenticatorBase(allowanceHub)
    EIP712('KyberSwap Two Tiers Order Authenticator', '1.0.0')
  {}

  /**
   * @inheritdoc IOrderAuthenticator
   * @dev `data` is `abi.encode(AuthKey masterKey)`, which is approved as a master key
   */
  function initAuthentication(address owner, bytes calldata data) external onlyAllowanceHub {
    AuthKey calldata masterKey = _decodeKey(data, 0);
    _checkNotExpired(masterKey);

    masterKeys[owner][masterKey.hash()] = true;
  }

  /**
   * @inheritdoc IOrderAuthenticator
   * @dev `data` takes one of two encodings, distinguished by the offset of its first key:
   *
   * - `abi.encode(AuthKey masterKey, bool approved)` approves or revokes a master key. When the
   *   caller is `owner`, `signature` must be empty and no nonce is spent; otherwise `signature`
   *   must be the owner's signature over a {MasterKeyApproval}, which spends `nonce` in the owner's
   *   namespace.
   * - `abi.encode(AuthKey sessionKey, AuthKey masterKey, bool approved)` approves or revokes a
   *   session key. `signature` must be the master key's signature over a {SessionKeyApproval},
   *   which spends `nonce` under the master key's credential, whoever the caller is. The master key
   *   must be approved, and may act only on a session key that it approved or that no master key
   *   has approved.
   *
   * A key's expiry is checked only when approving, so an expired key can still be revoked.
   */
  function updateAuthentication(
    address owner,
    bytes calldata data,
    uint256 nonce,
    uint256 deadline,
    bytes calldata signature
  ) external checkDeadline(deadline) {
    if (data.decodeUint256(0) <= 0x40) {
      AuthKey calldata masterKey = _decodeKey(data, 0);
      // Read as a word, so any non-zero value approves
      bool approved = data.decodeUint256(1) != 0;
      if (approved) {
        _checkNotExpired(masterKey);
      }

      bytes32 masterKeyHash = masterKey.hash();

      // Any caller other than the owner, the hub included, must present the owner's signature
      if (msg.sender != owner) {
        _useUnorderedNonce(owner, nonce);

        bytes32 digest = _hashTypedDataV4(
          MasterKeyApprovalLib.hash(owner, masterKeyHash, approved, nonce, deadline)
        );
        if (!SignatureChecker.isValidSignatureNow(owner, digest, signature)) {
          revert InvalidApprovalSignature();
        }
      } else if (signature.length != 0) {
        revert UnexpectedSignature();
      }

      masterKeys[owner][masterKeyHash] = approved;
    } else {
      AuthKey calldata sessionKey = _decodeKey(data, 0);
      AuthKey calldata masterKey = _decodeKey(data, 1);
      bool approved = data.decodeUint256(2) != 0;
      // A session key that expires no later than its master key is live only while the master
      // key is live
      if (approved) {
        if (sessionKey.expiration > masterKey.expiration) {
          revert SessionKeyOutlivesMasterKey(sessionKey.expiration, masterKey.expiration);
        }
        _checkNotExpired(sessionKey);
      }

      bytes32 masterKeyHash = masterKey.hash();
      // Only a master key may approve a session key
      if (!masterKeys[owner][masterKeyHash]) {
        revert MasterKeyNotApproved(masterKeyHash);
      }

      bytes32 sessionKeyHash = sessionKey.hash();
      // A master key may act only on a session key it approved, or on one with no approval
      bytes32 approvedBy = sessionKeyMaster[owner][sessionKeyHash];
      if (approvedBy != bytes32(0) && approvedBy != masterKeyHash) {
        revert SessionKeyAlreadyApproved(sessionKeyHash, masterKeyHash, approvedBy);
      }

      _useUnorderedNonce(masterKey.credentialHash(), nonce);

      bytes32 digest = _hashTypedDataV4(
        SessionKeyApprovalLib.hash(owner, masterKeyHash, sessionKeyHash, approved, nonce, deadline)
      );
      if (!masterKey.verify(digest, signature)) {
        revert InvalidApprovalSignature();
      }

      sessionKeyMaster[owner][sessionKeyHash] = approved ? masterKeyHash : bytes32(0);
    }
  }

  /**
   * @inheritdoc IOrderAuthenticator
   * @dev `data` is `abi.encode(AuthKey key, bool isSessionKey, bytes signature)`. `signature` is
   * the key's signature over the EIP-712 digest of the order under this contract's domain, and
   * `order.nonce` is spent under the key's credential.
   */
  function authenticateExecution(
    ExecutionOrder calldata order,
    bytes32 orderHash,
    bytes calldata data
  ) external onlyAllowanceHub {
    _authenticate(order.owner, order.nonce, orderHash, data);
  }

  /**
   * @inheritdoc IOrderAuthenticator
   * @dev `data` is encoded as for {authenticateExecution}
   */
  function authenticateFulfillment(
    FulfillmentOrder calldata order,
    bytes32 orderHash,
    bytes calldata data
  ) external onlyAllowanceHub {
    _authenticate(order.owner, order.nonce, orderHash, data);
  }

  /**
   * @inheritdoc ITwoTiersOrderAuthenticator
   * @dev Neither the key's expiry nor its approval is checked, so an expired or revoked key can
   * still cancel its unused signatures.
   */
  function revokeNonce(
    AuthKey calldata key,
    uint256 nonce,
    uint256 deadline,
    bytes calldata signature
  ) external checkDeadline(deadline) {
    _useUnorderedNonce(key.credentialHash(), nonce);

    bytes32 digest = _hashTypedDataV4(NonceRevocationLib.hash(key, nonce, deadline));
    if (!key.verify(digest, signature)) {
      revert InvalidRevocationSignature();
    }
  }

  /**
   * @dev Verifies that the key in `data` may sign for `owner` and signed the order with hash
   * `orderHash`, and spends `nonce` under the key's credential. `isSessionKey` selects the tier the
   * key is checked under; a key presented under a tier it does not hold has no approval there and
   * is refused.
   */
  function _authenticate(address owner, uint256 nonce, bytes32 orderHash, bytes calldata data)
    private
  {
    AuthKey calldata key = _decodeKey(data, 0);
    _checkNotExpired(key);

    bytes32 keyHash = key.hash();
    if (data.decodeUint256(1) != 0) {
      // A session key is accepted only while the master key that approved it is approved
      bytes32 masterKeyHash = sessionKeyMaster[owner][keyHash];
      if (masterKeyHash == bytes32(0)) {
        revert SessionKeyNotApproved(keyHash);
      }
      if (!masterKeys[owner][masterKeyHash]) {
        revert MasterKeyNotApproved(masterKeyHash);
      }
    } else if (!masterKeys[owner][keyHash]) {
      revert MasterKeyNotApproved(keyHash);
    }

    _useUnorderedNonce(key.credentialHash(), nonce);

    bytes32 digest = _hashTypedDataV4(orderHash);
    bytes calldata signature = data.decodeBytes(2);
    if (!key.verify(digest, signature)) {
      revert InvalidOrderSignature();
    }
  }

  /// @dev The key located at the offset stored in word `index` of `data`
  function _decodeKey(bytes calldata data, uint256 index)
    private
    pure
    returns (AuthKey calldata key)
  {
    assembly ('memory-safe') {
      key := add(data.offset, calldataload(add(data.offset, shl(5, index))))
    }
  }

  /// @dev Reverts when `key` has expired
  function _checkNotExpired(AuthKey calldata key) private view {
    if (block.timestamp > key.expiration) {
      revert AuthKeyExpired(key.expiration, block.timestamp);
    }
  }
}
