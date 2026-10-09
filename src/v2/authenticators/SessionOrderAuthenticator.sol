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
 * @notice Lets an owner approve a key once and then authenticate allowance-hub orders with that key
 * instead of their main wallet. Keys carry their own expiry and may be Secp256k1, P256, WebAuthn or
 * RSA, so a passkey or a hot key can sign orders the wallet never touches.
 * @dev The owner approves master keys, which are the only tier that may approve anything; a
 * master key approves session keys of its own, so a passkey hands out short-lived local keys with
 * no wallet prompt. Both tiers sign orders, and a session key may neither outlive the master key
 * behind it nor survive its revocation.
 *
 * Replay protection lives here rather than in the hub: every verification burns a nonce in the
 * namespace of whatever signed it, and the nonce and deadline are bound into the digest.
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
   * @dev `data` is `abi.encode(AuthKey masterKey)`; approving is the only direction on this path
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
   * `abi.encode(AuthKey sessionKey, AuthKey masterKey, bool approved)` for a master key's, told
   * apart by the first key's offset. Only the owner's rail makes a key a master key.
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

      // Only the owner authenticates themselves by calling; anyone else, the hub included, has to
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
      // Checked in both directions, so a master key only decides keys it could have minted
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

  /// @dev Checks that the key in `abi.encode(AuthKey key, bytes signature)` may still sign for
  /// `owner` and did sign `orderHash`, spending `nonce` in that key's namespace
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
    // A key with no master key behind it stands on its own approval; a session key stands on that
    // master key, so revoking it takes every session key it minted
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
