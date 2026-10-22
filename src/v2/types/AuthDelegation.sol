// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @notice An owner's signed decision to delegate an authenticator or withdraw it, required when the
 * decision is submitted by another account
 * @dev `delegated` is true to delegate and false to withdraw. `data` is passed to the
 * authenticator only when delegating. When the owner submits the decision, no signature is given
 * and `nonce` is not spent.
 */
struct AuthDelegation {
  address owner;
  address authenticator;
  bool delegated;
  bytes data;
  uint256 nonce;
  uint256 deadline;
}

using AuthDelegationLib for AuthDelegation global;

library AuthDelegationLib {
  bytes32 internal constant AUTH_DELEGATION_TYPEHASH = keccak256(
    'AuthDelegation(address owner,address authenticator,bool delegated,bytes data,uint256 nonce,uint256 deadline)'
  );

  /// @dev EIP-712 hash of a delegation the owner signs
  function hash(
    address owner,
    address authenticator,
    bool delegated,
    bytes memory data,
    uint256 nonce,
    uint256 deadline
  ) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(
        AUTH_DELEGATION_TYPEHASH, owner, authenticator, delegated, keccak256(data), nonce, deadline
      )
    );
  }

  /// @dev As {hash}, for a delegation held as a struct
  function hash(AuthDelegation memory self) internal pure returns (bytes32) {
    return
      hash(self.owner, self.authenticator, self.delegated, self.data, self.nonce, self.deadline);
  }
}
