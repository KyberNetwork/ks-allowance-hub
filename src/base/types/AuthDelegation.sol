// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @notice An owner's EIP-712 authorisation to delegate a verifier, used when a third party submits
 * the delegation on their behalf
 */
struct AuthDelegation {
  address verifier;
  bytes data;
  uint256 nonce;
  uint256 deadline;
}

using AuthDelegationLibrary for AuthDelegation global;

library AuthDelegationLibrary {
  bytes32 internal constant AUTH_DELEGATION_TYPEHASH =
    keccak256('AuthDelegation(address verifier,bytes data,uint256 nonce,uint256 deadline)');

  /// @dev EIP-712 hash of a delegation the owner signs
  function hash(address verifier, bytes memory data, uint256 nonce, uint256 deadline)
    internal
    pure
    returns (bytes32)
  {
    return
      keccak256(abi.encode(AUTH_DELEGATION_TYPEHASH, verifier, keccak256(data), nonce, deadline));
  }

  /// @dev As {hash}, taking the struct rather than its fields
  function hash(AuthDelegation memory self) internal pure returns (bytes32) {
    return hash(self.verifier, self.data, self.nonce, self.deadline);
  }
}
