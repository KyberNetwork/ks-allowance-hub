// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {IOrderAuthenticator} from '../interfaces/IOrderAuthenticator.sol';

import {ISessionOrderAuthenticator} from './interfaces/ISessionOrderAuthenticator.sol';

import {OrderAuthenticatorBase} from './OrderAuthenticatorBase.sol';

import {DeadlineChecker} from '../../base/DeadlineChecker.sol';
import {EIP712Base} from '../../base/EIP712Base.sol';
import {UnorderedNonce} from '../../base/UnorderedNonce.sol';

import {AuthKey} from './types/AuthKey.sol';
import {MasterKeyApprovalLib} from './types/MasterKeyApproval.sol';
import {SessionKeyApprovalLib} from './types/SessionKeyApproval.sol';

import {ExecutionOrder} from '../types/ExecutionOrder.sol';
import {FulfillmentOrder} from '../types/FulfillmentOrder.sol';

import {CalldataDecoder} from 'ks-common-sc/src/libraries/calldata/CalldataDecoder.sol';

import {
  SignatureChecker
} from 'openzeppelin-contracts/contracts/utils/cryptography/SignatureChecker.sol';

/**
 * @title SessionOrderAuthenticator
 * @notice Authenticates allowance-hub orders against keys an owner has approved, in place of their
 * main wallet. Each key carries its own expiry and may be Secp256k1, P256, WebAuthn or RSA, so a
 * passkey or a local key may sign orders without involving the wallet.
 * @dev Keys form two tiers. The owner approves master keys, the only tier permitted to approve
 * further keys; a master key approves session keys beneath it, which allows a passkey to issue
 * short-lived local keys without a wallet prompt. Both tiers may sign orders. A session key may
 * not outlive the master key it names, and does not survive its revocation.
 *
 * Replay protection belongs to this contract rather than the hub: every verification spends a
 * nonce in the namespace of the key or account that signed, and the nonce and deadline are bound
 * into the digest.
 */
contract SessionOrderAuthenticator is
  ISessionOrderAuthenticator,
  OrderAuthenticatorBase,
  DeadlineChecker,
  UnorderedNonce,
  EIP712Base
{
  using CalldataDecoder for bytes;

  /// @inheritdoc ISessionOrderAuthenticator
  mapping(address owner => mapping(bytes32 keyHash => bool)) public masterKeys;

  /// @inheritdoc ISessionOrderAuthenticator
  mapping(address owner => mapping(bytes32 keyHash => bytes32)) public sessionKeyMaster;

  /// @param allowanceHub The only hub whose authentication requests this one answers
  constructor(address allowanceHub)
    OrderAuthenticatorBase(allowanceHub)
    EIP712Base('KyberSwap Session Order Authenticator', '1.0.0')
  {}

  /**
   * @inheritdoc IOrderAuthenticator
   * @dev `data` is `abi.encode(AuthKey masterKey)`; approval is the only direction on this path
   */
  function initAuthentication(address owner, bytes calldata data) external onlyAllowanceHub {
    AuthKey calldata masterKey;
    assembly ('memory-safe') {
      masterKey := add(data.offset, calldataload(data.offset))
    }

    masterKeys[owner][masterKey.hash()] = true;
  }

  /**
   * @inheritdoc IOrderAuthenticator
   * @dev `data` is `abi.encode(AuthKey masterKey, bool approved)` for the owner's own decision, or
   * `abi.encode(AuthKey sessionKey, AuthKey masterKey, bool approved)` for a master key's,
   * distinguished by the offset of the first key. Only the owner's rail may approve a master key,
   * and a master key's reaches no further than a session key beneath it.
   */
  function updateAuthentication(
    address owner,
    bytes calldata data,
    uint256 nonce,
    uint256 deadline,
    bytes calldata signature
  ) external checkDeadline(deadline) {
    if (data.decodeUint256(0) <= 0x40) {
      AuthKey calldata masterKey;
      assembly ('memory-safe') {
        masterKey := add(data.offset, calldataload(data.offset))
      }

      bytes32 masterKeyHash = masterKey.hash();
      // Read as a word and narrowed here, so the direction does not depend on the caller having
      // written a canonical bool, nor on the compiler cleaning one that assembly produced
      bool approved = data.decodeUint256(1) != 0;

      // Only the owner authenticates themselves by calling; anyone else, the hub included, must
      // present a signature, because `forwardCalls` relays this from any caller
      if (msg.sender != owner) {
        _useUnorderedNonce(owner, nonce);

        bytes32 digest =
          _hashTypedDataV4(MasterKeyApprovalLib.hash(masterKeyHash, approved, nonce, deadline));
        if (!SignatureChecker.isValidSignatureNow(owner, digest, signature)) {
          revert InvalidApprovalSignature();
        }
      }

      masterKeys[owner][masterKeyHash] = approved;
    } else {
      AuthKey calldata sessionKey;
      AuthKey calldata masterKey;
      assembly ('memory-safe') {
        sessionKey := add(data.offset, calldataload(data.offset))
        masterKey := add(data.offset, calldataload(add(data.offset, 0x20)))
      }

      bytes32 masterKeyHash = masterKey.hash();
      // A session key may only be granted by a key the owner approved themselves
      if (!masterKeys[owner][masterKeyHash]) {
        revert MasterKeyNotApproved(owner, masterKey);
      }
      // Applied in both directions, so a master key may only address keys it could have approved
      if (sessionKey.expiration > masterKey.expiration) {
        revert SessionKeyOutlivesMasterKey(sessionKey.expiration, masterKey.expiration);
      }

      bytes32 sessionKeyHash = sessionKey.hash();
      bool approved = data.decodeUint256(2) != 0;

      _useUnorderedNonce(masterKeyHash, nonce);

      bytes32 digest = _hashTypedDataV4(
        SessionKeyApprovalLib.hash(owner, masterKeyHash, sessionKeyHash, approved, nonce, deadline)
      );
      if (!masterKey.verify(digest, signature)) {
        revert InvalidApprovalSignature();
      }

      sessionKeyMaster[owner][sessionKeyHash] = approved ? masterKeyHash : bytes32(0);
    }
  }

  /// @inheritdoc IOrderAuthenticator
  function authenticateExecution(ExecutionOrder calldata order, bytes calldata data)
    external
    onlyAllowanceHub
  {
    _authenticate(order.owner, order.nonce, order.hash(), data);
  }

  /// @inheritdoc IOrderAuthenticator
  function authenticateFulfillment(FulfillmentOrder calldata order, bytes calldata data)
    external
    onlyAllowanceHub
  {
    _authenticate(order.owner, order.nonce, order.hash(), data);
  }

  /// @dev Verifies that the key in `abi.encode(AuthKey key, bytes signature)` may still sign for
  /// `owner` and did sign `orderHash`, and spends `nonce` in that key's namespace
  function _authenticate(address owner, uint256 nonce, bytes32 orderHash, bytes calldata data)
    private
  {
    AuthKey calldata key;
    assembly ('memory-safe') {
      key := add(data.offset, calldataload(data.offset))
    }

    if (block.timestamp > key.expiration) {
      revert AuthKeyExpired(block.timestamp, key.expiration);
    }

    bytes32 keyHash = key.hash();
    // A key with no master key recorded is judged on its own approval; a session key is judged on
    // the master key it names, so revoking that key withdraws every session key it approved
    bytes32 masterKeyHash = sessionKeyMaster[owner][keyHash];
    if (masterKeyHash == bytes32(0)) {
      if (!masterKeys[owner][keyHash]) {
        revert MasterKeyNotApproved(owner, key);
      }
    } else if (!masterKeys[owner][masterKeyHash]) {
      revert SessionKeyNotApproved(owner, key, masterKeyHash);
    }

    _useUnorderedNonce(keyHash, nonce);

    bytes32 digest = _hashTypedDataV4(orderHash);
    bytes calldata signature = data.decodeBytes(1);
    if (!key.verify(digest, signature)) {
      revert InvalidAuthenticationSignature();
    }
  }
}
