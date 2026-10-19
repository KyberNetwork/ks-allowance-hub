// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {AuthKey} from './AuthKey.sol';

/// @notice A key's decision to spend one of its own nonces, cancelling the signature carrying it
struct NonceRevocation {
  AuthKey key;
  uint256 nonce;
  uint256 deadline;
}

library NonceRevocationLib {
  bytes32 internal constant NONCE_REVOCATION_TYPEHASH = keccak256(
    'NonceRevocation(AuthKey key,uint256 nonce,uint256 deadline)'
    'AuthKey(bytes publicKey,uint8 keyType,uint256 expiration)'
  );

  /// @dev EIP-712 hash of a key's revocation of one of its nonces
  function hash(AuthKey calldata key, uint256 nonce, uint256 deadline)
    internal
    pure
    returns (bytes32)
  {
    return keccak256(abi.encode(NONCE_REVOCATION_TYPEHASH, key.hash(), nonce, deadline));
  }

  /// @dev As {hash}, for a key already in memory
  function hashMemory(AuthKey memory key, uint256 nonce, uint256 deadline)
    internal
    pure
    returns (bytes32)
  {
    return keccak256(abi.encode(NONCE_REVOCATION_TYPEHASH, key.hashMemory(), nonce, deadline));
  }
}
