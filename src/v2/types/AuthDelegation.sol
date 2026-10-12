// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @notice An owner's decision to delegate an authenticator or withdraw it, needed only when
 * someone else submits it on their behalf
 * @dev `delegated` carries the direction: true delegates the authenticator, false withdraws it.
 * `data` reaches the authenticator only when delegating.
 */
struct AuthDelegation {
  address authenticator;
  bool delegated;
  bytes data;
  uint256 nonce;
  uint256 deadline;
}

using AuthDelegationLib for AuthDelegation global;

library AuthDelegationLib {
  bytes32 internal constant AUTH_DELEGATION_TYPEHASH = keccak256(
    'AuthDelegation(address authenticator,bool delegated,bytes data,uint256 nonce,uint256 deadline)'
  );

  /// @dev EIP-712 hash of a delegation the owner signs
  function hash(
    address authenticator,
    bool delegated,
    bytes memory data,
    uint256 nonce,
    uint256 deadline
  ) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(
        AUTH_DELEGATION_TYPEHASH, authenticator, delegated, keccak256(data), nonce, deadline
      )
    );
  }

  /// @dev As {hash}, taking the struct rather than its fields
  function hash(AuthDelegation memory self) internal pure returns (bytes32) {
    return hash(self.authenticator, self.delegated, self.data, self.nonce, self.deadline);
  }
}
