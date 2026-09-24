// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @notice An owner's EIP-712 decision to delegate a verifier or withdraw it, used when a third
 * party submits the decision on their behalf
 * @dev `delegated` carries the direction: true delegates the verifier, false withdraws it
 */
struct AuthDelegation {
  address verifier;
  bool delegated;
  bytes data;
  uint256 nonce;
  uint256 deadline;
}

using AuthDelegationLibrary for AuthDelegation global;

library AuthDelegationLibrary {
  bytes32 internal constant AUTH_DELEGATION_TYPEHASH = keccak256(
    'AuthDelegation(address verifier,bool delegated,bytes data,uint256 nonce,uint256 deadline)'
  );

  /// @dev EIP-712 hash of a delegation the owner signs
  function hash(
    address verifier,
    bool delegated,
    bytes memory data,
    uint256 nonce,
    uint256 deadline
  ) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(AUTH_DELEGATION_TYPEHASH, verifier, delegated, keccak256(data), nonce, deadline)
    );
  }

  /// @dev As {hash}, taking the struct rather than its fields
  function hash(AuthDelegation memory self) internal pure returns (bytes32) {
    return hash(self.verifier, self.delegated, self.data, self.nonce, self.deadline);
  }
}
