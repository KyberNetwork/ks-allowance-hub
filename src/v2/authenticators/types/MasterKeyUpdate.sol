// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {AuthKey} from '../../../base/types/AuthKey.sol';

/**
 * @notice An owner's signed decision to approve or revoke one master key, required when the
 * decision is submitted by another account
 * @param owner Account the key may sign for
 * @param masterKey The master key
 * @param approved True to approve, false to revoke
 * @param nonce Nonce spent in the owner's namespace
 * @param deadline Last timestamp at which the decision may be submitted
 */
struct MasterKeyUpdate {
  address owner;
  AuthKey masterKey;
  bool approved;
  uint256 nonce;
  uint256 deadline;
}

library MasterKeyUpdateLib {
  bytes32 internal constant MASTER_KEY_UPDATE_TYPEHASH = keccak256(
    'MasterKeyUpdate(address owner,AuthKey masterKey,bool approved,uint256 nonce,uint256 deadline)'
    'AuthKey(bytes publicKey,uint8 keyType,uint256 expiration)'
  );

  /// @dev EIP-712 hash of the owner's decision about one master key
  function hash(
    address owner,
    bytes32 masterKeyHash,
    bool approved,
    uint256 nonce,
    uint256 deadline
  ) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(MASTER_KEY_UPDATE_TYPEHASH, owner, masterKeyHash, approved, nonce, deadline)
    );
  }
}
