// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {AuthKey} from './AuthKey.sol';

/**
 * @notice An owner's decision about one master key
 * @dev `approved` carries the direction: true approves the key, false revokes it
 */
struct MasterKeyApproval {
  AuthKey masterKey;
  bool approved;
  uint256 nonce;
  uint256 deadline;
}

library MasterKeyApprovalLib {
  bytes32 internal constant MASTER_KEY_APPROVAL_TYPEHASH = keccak256(
    'MasterKeyApproval(AuthKey masterKey,bool approved,uint256 nonce,uint256 deadline)'
    'AuthKey(bytes publicKey,uint8 keyType,uint256 expiration)'
  );

  /// @dev EIP-712 hash of the owner's decision about one master key
  function hash(bytes32 masterKeyHash, bool approved, uint256 nonce, uint256 deadline)
    internal
    pure
    returns (bytes32)
  {
    return keccak256(
      abi.encode(MASTER_KEY_APPROVAL_TYPEHASH, masterKeyHash, approved, nonce, deadline)
    );
  }
}
