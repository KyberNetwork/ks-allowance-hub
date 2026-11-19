// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IAHV2Authenticator} from '../interfaces/base/IAHV2Authenticator.sol';
import {IAuthDelegator} from '../interfaces/base/IAuthDelegator.sol';

import {UnorderedNonce} from './UnorderedNonce.sol';

import {AuthDelegationLib} from '../types/AuthDelegation.sol';

import {EIP712} from 'openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol';
import {
  SignatureChecker
} from 'openzeppelin-contracts/contracts/utils/cryptography/SignatureChecker.sol';

/**
 * @title AuthDelegator
 * @notice Records which {IAHV2Authenticator} contracts each owner has delegated to authenticate
 * their orders
 * @dev An authenticator is trusted by the owner who delegates it. This contract checks only that
 * the delegation is in place.
 */
abstract contract AuthDelegator is IAuthDelegator, UnorderedNonce, EIP712 {
  /// @inheritdoc IAuthDelegator
  mapping(address owner => mapping(address authenticator => bool)) public authDelegated;

  /**
   * @param name EIP-712 domain name of every signature this contract checks
   * @param version EIP-712 domain version
   */
  constructor(string memory name, string memory version) EIP712(name, version) {}

  /// @inheritdoc IAuthDelegator
  function updateDelegation(
    address owner,
    address authenticator,
    bool delegated,
    bytes calldata data,
    uint256 nonce,
    uint256 deadline,
    bytes calldata signature
  ) external payable {
    if (block.timestamp > deadline) {
      revert DeadlinePassed(deadline, block.timestamp);
    }

    // The owner's call is its own authorization: `signature` must be empty and no nonce is spent.
    // Any other caller, including Multicall3 relaying the call through `forwardCalls`, needs the
    // owner's signature over the {AuthDelegation}, which spends `nonce` in the owner's namespace.
    if (owner != msg.sender) {
      bytes32 delegationHash =
        AuthDelegationLib.hash(owner, authenticator, delegated, data, nonce, deadline);
      if (!_verifySignature(owner, nonce, delegationHash, signature)) {
        revert InvalidDelegationSignature();
      }
    } else if (signature.length != 0) {
      revert UnexpectedSignature();
    }

    // Delegating with non-empty `data` passes it to `initAuthentication`, which takes no signature
    // and relies on the owner having been authenticated above. Withdrawing calls no authenticator,
    // so an authenticator that reverts cannot prevent it, and leaves the authenticator's own state
    // unchanged.
    if (delegated && data.length > 0) {
      IAHV2Authenticator(authenticator).initAuthentication(owner, data);
    }
    authDelegated[owner][authenticator] = delegated;

    emit UpdateDelegation(owner, authenticator, delegated);
  }

  /// @dev Spends `nonce` in the namespace of `signer` and returns whether `signature` by `signer`
  /// is valid for the EIP-712 digest of `structHash`
  function _verifySignature(
    address signer,
    uint256 nonce,
    bytes32 structHash,
    bytes calldata signature
  ) internal returns (bool) {
    _useUnorderedNonce(signer, nonce);

    return SignatureChecker.isValidSignatureNow(signer, _hashTypedDataV4(structHash), signature);
  }
}
