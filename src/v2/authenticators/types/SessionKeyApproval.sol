// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {AuthKey} from './AuthKey.sol';

/**
 * @notice A master key's signed decision to approve or revoke one session key for `owner`
 * @dev `approved` is true to approve and false to revoke. The master key signs the decision
 * whoever submits it, and `nonce` is spent under the master key's credential. A master key may
 * decide only about a session key it approved or one that no master key has approved.
 */
struct SessionKeyApproval {
  address owner;
  AuthKey masterKey;
  AuthKey sessionKey;
  bool approved;
  uint256 nonce;
  uint256 deadline;
}

library SessionKeyApprovalLib {
  bytes32 internal constant SESSION_KEY_APPROVAL_TYPEHASH = keccak256(
    'SessionKeyApproval(address owner,AuthKey masterKey,AuthKey sessionKey,bool approved,'
    'uint256 nonce,uint256 deadline)' 'AuthKey(bytes publicKey,uint8 keyType,uint256 expiration)'
  );

  /// @dev EIP-712 hash of a master key's decision about one session key
  function hash(
    address owner,
    bytes32 masterKeyHash,
    bytes32 sessionKeyHash,
    bool approved,
    uint256 nonce,
    uint256 deadline
  ) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(
        SESSION_KEY_APPROVAL_TYPEHASH,
        owner,
        masterKeyHash,
        sessionKeyHash,
        approved,
        nonce,
        deadline
      )
    );
  }
}
