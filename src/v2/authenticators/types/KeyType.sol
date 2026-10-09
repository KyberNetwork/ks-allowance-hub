// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @notice Signature scheme of an {AuthKey}; determines how {AuthKeyLib-verify} reads its public
/// key
enum KeyType {
  Secp256k1,
  P256,
  WebAuthn,
  RSA
}
