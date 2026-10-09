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
 * @notice A credential approved to sign for an account until `expiration`
 * @dev `publicKey` is encoded per `keyType`: a 32-byte ABI-encoded address for Secp256k1 (which
 * also accepts an ERC-1271 contract), `abi.encodePacked(qx, qy)` for P256 and WebAuthn, and
 * `abi.encode(bytes e, bytes n)` for RSA.
 */
struct AuthKey {
  bytes publicKey;
  KeyType keyType;
  uint256 expiration;
}

using AuthKeyLib for AuthKey global;

library AuthKeyLib {
  using CalldataDecoder for bytes;

  bytes32 internal constant AUTH_KEY_TYPEHASH =
    keccak256('AuthKey(bytes publicKey,uint8 keyType,uint256 expiration)');

  /**
   * @dev EIP-712 hash identifying the key: its public half, scheme and expiry together. The raw
   * `publicKey` bytes are hashed, so two encodings that differ only in padding are two different
   * keys here even when they resolve to the same signer — an approval, and a revocation, is per
   * encoding rather than per signer.
   */
  function hash(AuthKey calldata key) internal pure returns (bytes32) {
    return
      keccak256(
        abi.encode(AUTH_KEY_TYPEHASH, keccak256(key.publicKey), key.keyType, key.expiration)
      );
  }

  /**
   * @notice Checks `signature` over `digest` under this key's scheme
   * @dev `signature` is encoded per `keyType`, mirroring `publicKey`: a 65-byte ECDSA signature or
   * an ERC-1271 blob for Secp256k1, `abi.encodePacked(r, s)` for P256, an encoded
   * `WebAuthn.WebAuthnAuth` for WebAuthn, and a PKCS#1 v1.5 signature for RSA. The P256 words are
   * read without a length check, so a short signature reads whatever follows it in calldata and
   * fails verification rather than reverting.
   */
  function verify(AuthKey calldata key, bytes32 digest, bytes calldata signature)
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
