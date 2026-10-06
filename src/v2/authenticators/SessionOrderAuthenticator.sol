// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {IOrderAuthenticator} from '../interfaces/IOrderAuthenticator.sol';

import {ISessionOrderAuthenticator} from './interfaces/ISessionOrderAuthenticator.sol';

import {OrderAuthenticatorBase} from './OrderAuthenticatorBase.sol';

import {DeadlineChecker} from '../../base/DeadlineChecker.sol';
import {EIP712Base} from '../../base/EIP712Base.sol';
import {UnorderedNonce} from '../../base/UnorderedNonce.sol';

import {SessionApprovalLib} from './types/SessionApproval.sol';
import {SessionKey} from './types/SessionKey.sol';

import {ExecutionOrder} from '../types/ExecutionOrder.sol';
import {FulfillmentOrder} from '../types/FulfillmentOrder.sol';

import {CalldataDecoder} from 'ks-common-sc/src/libraries/calldata/CalldataDecoder.sol';

import {
  SignatureChecker
} from 'openzeppelin-contracts/contracts/utils/cryptography/SignatureChecker.sol';

/**
 * @title SessionOrderAuthenticator
 * @notice Lets an owner approve a session key once and then authenticate allowance-hub orders with
 * that key instead of their main wallet. Keys carry their own expiry and may be Secp256k1, P256,
 * WebAuthn or RSA, so a passkey or a hot key can sign orders the wallet never touches.
 * @dev Replay protection lives here rather than in the hub: every verification burns one of the
 * owner's nonces, and the nonce and deadline are bound into the digest the key signs.
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
  mapping(address => mapping(bytes32 keyHash => bool)) public approvedKeys;

  /// @param allowanceHub The only hub whose authentication requests this one answers
  constructor(address allowanceHub)
    OrderAuthenticatorBase(allowanceHub)
    EIP712Base('KyberSwap Session Order Authenticator', '1.0.0')
  {}

  /**
   * @inheritdoc IOrderAuthenticator
   * @dev `data` is `abi.encode(SessionKey key)`; approving is the only direction on this path
   */
  function initAuthentication(address owner, bytes calldata data) external onlyAllowanceHub {
    SessionKey calldata key;
    assembly ('memory-safe') {
      key := add(data.offset, calldataload(data.offset))
    }

    approvedKeys[owner][key.hash()] = true;
  }

  /**
   * @inheritdoc IOrderAuthenticator
   * @dev `data` is `abi.encode(SessionKey key, bool approved)`: word 0 points at the key, word 1
   * says whether to approve or revoke it
   */
  function updateAuthentication(
    address owner,
    bytes calldata data,
    uint256 nonce,
    uint256 deadline,
    bytes calldata signature
  ) external checkDeadline(deadline) {
    SessionKey calldata key;
    assembly ('memory-safe') {
      key := add(data.offset, calldataload(data.offset))
    }

    bytes32 keyHash = key.hash();
    // Read as a word and narrowed here, so the direction does not depend on the caller having
    // written a canonical bool, nor on the compiler cleaning one that assembly produced
    bool approved = data.decodeUint256(1) != 0;

    // Only the owner authenticates themselves by calling; anyone else, the hub included, has to
    // present a signature, because `forwardCalls` relays this from any caller
    if (msg.sender != owner) {
      _useUnorderedNonce(owner, nonce);

      bytes32 digest = _hashTypedDataV4(SessionApprovalLib.hash(keyHash, approved, nonce, deadline));
      if (!SignatureChecker.isValidSignatureNow(owner, digest, signature)) {
        revert InvalidApprovalSignature();
      }
    }

    approvedKeys[owner][keyHash] = approved;
  }

  /// @inheritdoc IOrderAuthenticator
  function authenticateExecution(address owner, ExecutionOrder calldata order, bytes calldata data)
    external
    onlyAllowanceHub
  {
    SessionKey calldata key;
    assembly ('memory-safe') {
      key := add(data.offset, calldataload(data.offset))
    }

    if (block.timestamp > key.expiration) {
      revert SessionKeyExpired(block.timestamp, key.expiration);
    }
    if (!approvedKeys[owner][key.hash()]) {
      revert SessionKeyNotApproved(owner, key);
    }

    _useUnorderedNonce(owner, order.nonce);

    bytes32 digest = _hashTypedDataV4(order.hash());
    bytes calldata signature = data.decodeBytes(1);
    if (!key.verify(digest, signature)) {
      revert InvalidAuthenticationSignature();
    }
  }

  /// @inheritdoc IOrderAuthenticator
  function authenticateFulfillment(
    address owner,
    FulfillmentOrder calldata order,
    bytes calldata data
  ) external onlyAllowanceHub {
    SessionKey calldata key;
    assembly ('memory-safe') {
      key := add(data.offset, calldataload(data.offset))
    }

    if (block.timestamp > key.expiration) {
      revert SessionKeyExpired(block.timestamp, key.expiration);
    }
    if (!approvedKeys[owner][key.hash()]) {
      revert SessionKeyNotApproved(owner, key);
    }

    _useUnorderedNonce(owner, order.nonce);

    bytes32 digest = _hashTypedDataV4(order.hash());
    bytes calldata signature = data.decodeBytes(1);
    if (!key.verify(digest, signature)) {
      revert InvalidAuthenticationSignature();
    }
  }
}
