// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {KeyType} from './KeyType.sol';

import {CalldataDecoder} from 'ks-common-sc/src/libraries/calldata/CalldataDecoder.sol';

import {IERC7913SignatureVerifier} from 'openzeppelin-contracts/contracts/interfaces/IERC7913.sol';
import {ECDSA} from 'openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol';
import {P256} from 'openzeppelin-contracts/contracts/utils/cryptography/P256.sol';
import {RSA} from 'openzeppelin-contracts/contracts/utils/cryptography/RSA.sol';
import {
  SignatureChecker
} from 'openzeppelin-contracts/contracts/utils/cryptography/SignatureChecker.sol';
import {WebAuthn} from 'openzeppelin-contracts/contracts/utils/cryptography/WebAuthn.sol';

/**
 * @notice A key that may sign for an account until `expiration`
 * @dev `publicKey` is encoded according to `keyType`: an ABI-encoded address for Secp256k1 and
 * ERC1271, `abi.encodePacked(qx, qy)` for P256 and WebAuthn, `abi.encode(bytes e, bytes n)` for
 * RSA, and `abi.encodePacked(verifier, key)` for ERC7913. Approvals identify a key by its hash,
 * which includes the expiry; nonces are spent under its credential hash, which does not.
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

  /// @dev EIP-712 hash of the key, covering its public key, type and expiry
  function hash(AuthKey calldata key) internal pure returns (bytes32) {
    return
      keccak256(
        abi.encode(AUTH_KEY_TYPEHASH, keccak256(key.publicKey), key.keyType, key.expiration)
      );
  }

  /// @dev As {hash}, for a key already in memory
  function hashMemory(AuthKey memory key) internal pure returns (bytes32) {
    return
      keccak256(
        abi.encode(AUTH_KEY_TYPEHASH, keccak256(key.publicKey), key.keyType, key.expiration)
      );
  }

  /// @dev Hash of the key's type and public key, without its expiry, under which its nonces are
  /// spent
  function credentialHash(AuthKey calldata key) internal pure returns (bytes32) {
    return keccak256(abi.encodePacked(key.keyType, key.publicKey));
  }

  /**
   * @notice Whether `signature` is a valid signature of `digest` by this key
   * @dev `signature` is encoded according to `keyType`: a 65-byte ECDSA signature for Secp256k1,
   * `abi.encodePacked(r, s)` for P256, an ABI-encoded `WebAuthn.WebAuthnAuth` for WebAuthn, a
   * PKCS#1 v1.5 signature for RSA, and the encoding the contract or verifier accepts for ERC1271
   * and ERC7913.
   *
   * Returns false, without reverting, when `publicKey` is not 32 bytes for Secp256k1 and ERC1271,
   * not 64 bytes for P256 and WebAuthn, shorter than 64 bytes for RSA, or not longer than 20 bytes
   * for ERC7913, and when a Secp256k1 or ERC1271 key has any of its top 12 bytes set. A P256
   * signature is read without a length check; a short one fails verification.
   *
   * Secp256k1 keys are verified by ECDSA recovery only, and ERC1271 keys by the contract only.
   * ERC7913 keys are verified by a static call to the verifier; a verifier that reverts, has no
   * code or returns anything other than the `verify` selector fails verification.
   * @param key The key
   * @param digest The signed digest
   * @param signature The signature
   * @return result Whether the signature is valid
   */
  function verify(AuthKey calldata key, bytes32 digest, bytes calldata signature)
    internal
    view
    returns (bool result)
  {
    if (key.keyType == KeyType.Secp256k1 || key.keyType == KeyType.ERC1271) {
      if (key.publicKey.length != 32 || (key.publicKey.decodeUint256()) >> 160 != 0) {
        return false;
      }

      address signer = key.publicKey.decodeAddress();
      if (key.keyType == KeyType.Secp256k1) {
        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecoverCalldata(digest, signature);
        return err == ECDSA.RecoverError.NoError && recovered == signer;
      }

      return SignatureChecker.isValidERC1271SignatureNow(signer, digest, signature);
    } else if (key.keyType == KeyType.P256) {
      if (key.publicKey.length != 64) {
        return false;
      }

      bytes32 qx = key.publicKey.decodeBytes32(0);
      bytes32 qy = key.publicKey.decodeBytes32(1);
      bytes32 r = signature.decodeBytes32(0);
      bytes32 s = signature.decodeBytes32(1);
      return P256.verify(digest, r, s, qx, qy);
    } else if (key.keyType == KeyType.WebAuthn) {
      if (key.publicKey.length != 64) {
        return false;
      }

      (bool decodeSuccess, WebAuthn.WebAuthnAuth calldata auth) = WebAuthn.tryDecodeAuth(signature);
      if (!decodeSuccess) {
        return false;
      }

      bytes32 qx = key.publicKey.decodeBytes32(0);
      bytes32 qy = key.publicKey.decodeBytes32(1);
      return WebAuthn.verify(abi.encodePacked(digest), auth, qx, qy);
    } else if (key.keyType == KeyType.RSA) {
      if (key.publicKey.length < 0x40) {
        return false;
      }

      bytes calldata e = key.publicKey.decodeBytes(0);
      bytes calldata n = key.publicKey.decodeBytes(1);
      return RSA.pkcs1Sha256(digest, signature, e, n);
    } else {
      // The verifier's address must be followed by a key for it to check against
      if (key.publicKey.length <= 20) {
        return false;
      }

      address verifier = address(bytes20(key.publicKey[:20]));
      bytes4 selector = IERC7913SignatureVerifier.verify.selector;
      bytes memory callData =
        abi.encodeWithSelector(selector, key.publicKey[20:], digest, signature);

      assembly ('memory-safe') {
        let success := staticcall(gas(), verifier, add(callData, 0x20), mload(callData), 0x00, 0x20)
        result := and(success, and(gt(returndatasize(), 0x1f), eq(mload(0x00), selector)))
      }
    }
  }
}
