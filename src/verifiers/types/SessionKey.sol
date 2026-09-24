// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {KeyType} from './KeyType.sol';

import {CalldataDecoder} from 'ks-common-sc/src/libraries/calldata/CalldataDecoder.sol';

import {P256} from 'openzeppelin-contracts/contracts/utils/cryptography/P256.sol';
import {RSA} from 'openzeppelin-contracts/contracts/utils/cryptography/RSA.sol';
import {
  SignatureChecker
} from 'openzeppelin-contracts/contracts/utils/cryptography/SignatureChecker.sol';
import {WebAuthn} from 'openzeppelin-contracts/contracts/utils/cryptography/WebAuthn.sol';

/**
 * @notice A credential an owner has approved to sign orders on their behalf until `expiration`
 * @dev `publicKey` is encoded per `keyType`: a 32-byte ABI-encoded address for Secp256k1 (which
 * also accepts an ERC-1271 contract), `abi.encodePacked(qx, qy)` for P256 and WebAuthn, and
 * `abi.encode(bytes e, bytes n)` for RSA.
 */
struct SessionKey {
  bytes publicKey;
  KeyType keyType;
  uint256 expiration;
}

using SessionKeyLibrary for SessionKey global;

library SessionKeyLibrary {
  using CalldataDecoder for bytes;

  bytes32 internal constant SESSION_KEY_TYPEHASH =
    keccak256('SessionKey(bytes publicKey,uint8 keyType,uint256 expiration)');

  /// @dev EIP-712 hash identifying the key: its public half, scheme and expiry together
  function hash(SessionKey calldata sessionKey) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(
        SESSION_KEY_TYPEHASH,
        keccak256(sessionKey.publicKey),
        sessionKey.keyType,
        sessionKey.expiration
      )
    );
  }

  /**
   * @notice Checks `signature` over `digest` under this key's scheme
   * @dev The final branch is RSA and also catches any keyType outside the enum, which the raw
   * calldata pointer in the verifier makes reachable.
   */
  function verify(SessionKey calldata key, bytes32 digest, bytes calldata signature)
    internal
    view
    returns (bool)
  {
    if (key.keyType == KeyType.Secp256k1) {
      address signer = key.publicKey.decodeAddress();
      return SignatureChecker.isValidSignatureNowCalldata(signer, digest, signature);
    } else if (key.keyType == KeyType.P256) {
      bytes32 qx = key.publicKey.decodeBytes32(0);
      bytes32 qy = key.publicKey.decodeBytes32(1);
      bytes32 r = signature.decodeBytes32(0);
      bytes32 s = signature.decodeBytes32(1);
      return P256.verify(digest, r, s, qx, qy);
    } else if (key.keyType == KeyType.WebAuthn) {
      (bool decodeSuccess, WebAuthn.WebAuthnAuth calldata auth) = WebAuthn.tryDecodeAuth(signature);
      if (!decodeSuccess) {
        return false;
      }

      bytes32 qx = key.publicKey.decodeBytes32(0);
      bytes32 qy = key.publicKey.decodeBytes32(1);
      return WebAuthn.verify(abi.encodePacked(digest), auth, qx, qy);
    } else {
      bytes calldata e = key.publicKey.decodeBytes(0);
      bytes calldata n = key.publicKey.decodeBytes(1);
      return RSA.pkcs1Sha256(digest, signature, e, n);
    }
  }
}
