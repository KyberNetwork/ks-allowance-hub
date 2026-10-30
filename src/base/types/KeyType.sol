// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @notice Signature scheme of an {AuthKey}, which determines how {AuthKeyLib-verify} reads its
/// public key and signature
enum KeyType {
  Secp256k1,
  P256,
  WebAuthn,
  RSA,
  ERC1271,
  ERC7913
}
