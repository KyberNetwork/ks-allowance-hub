// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {SessionKey} from './SessionKey.sol';

/**
 * @notice An owner's EIP-712 decision about one session key, signed under the verifier's own
 * domain
 * @dev `approved` carries the direction: true approves the key, false revokes it
 */
struct SessionApproval {
  SessionKey sessionKey;
  bool approved;
  uint256 nonce;
  uint256 deadline;
}

library SessionApprovalLibrary {
  bytes32 internal constant SESSION_APPROVAL_TYPEHASH = keccak256(
    'SessionApproval(SessionKey sessionKey,bool approved,uint256 nonce,uint256 deadline)'
    'SessionKey(bytes publicKey,uint8 keyType,uint256 expiration)'
  );

  /// @dev EIP-712 hash of the owner's decision about one session key
  function hash(bytes32 keyHash, bool approved, uint256 nonce, uint256 deadline)
    internal
    pure
    returns (bytes32)
  {
    return keccak256(abi.encode(SESSION_APPROVAL_TYPEHASH, keyHash, approved, nonce, deadline));
  }
}
