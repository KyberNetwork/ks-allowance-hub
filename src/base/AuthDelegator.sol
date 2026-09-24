// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IAuthDelegator} from './interfaces/IAuthDelegator.sol';
import {IAuthVerifier} from './interfaces/IAuthVerifier.sol';

import {DeadlineChecker} from './DeadlineChecker.sol';
import {UnorderedNonce} from './UnorderedNonce.sol';

import {AuthDelegationLibrary} from './types/AuthDelegation.sol';

import {EIP712} from 'openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol';
import {
  SignatureChecker
} from 'openzeppelin-contracts/contracts/utils/cryptography/SignatureChecker.sol';

/**
 * @title AuthDelegator
 * @notice Lets an owner nominate an {IAuthVerifier} once and afterwards authorise orders with
 * whatever credential that verifier understands, instead of signing each order here.
 * @dev The verifier is trusted by the owner, not by this contract: all that is checked is that
 * the owner delegated it. An empty signature forwarded to a verifier is the signal that this
 * contract already authenticated the owner.
 */
abstract contract AuthDelegator is IAuthDelegator, DeadlineChecker, UnorderedNonce, EIP712 {
  /// @inheritdoc IAuthDelegator
  mapping(address owner => mapping(address verifier => bool)) public authDelegated;

  /**
   * @param name EIP-712 domain name, which scopes every signature this contract checks
   * @param version EIP-712 domain version
   */
  constructor(string memory name, string memory version) EIP712(name, version) {}

  /// @inheritdoc IAuthDelegator
  function updateDelegation(
    address owner,
    address verifier,
    bool delegated,
    bytes calldata data,
    uint256 nonce,
    uint256 deadline,
    bytes calldata signature
  ) external payable checkDeadline(deadline) {
    if (owner != msg.sender) {
      _useUnorderedNonce(owner, nonce);

      bytes32 hash =
        _hashTypedDataV4(AuthDelegationLibrary.hash(verifier, delegated, data, nonce, deadline));
      if (!SignatureChecker.isValidSignatureNow(owner, hash, signature)) {
        revert InvalidDelegationSignature();
      }
    }

    // Forwarded only when delegating, so a verifier that reverts cannot trap the owner in a
    // delegation. Empty signature: the owner is either the caller or was checked just above
    if (delegated) {
      IAuthVerifier(verifier).updateAuth(owner, data, 0, deadline, '');
    }
    authDelegated[owner][verifier] = delegated;
  }

  /// @inheritdoc IAuthDelegator
  function updateAuth(
    address owner,
    address verifier,
    bytes calldata data,
    uint256 nonce,
    uint256 deadline,
    bytes calldata signature
  ) external payable checkDeadline(deadline) {
    if (!authDelegated[owner][verifier]) {
      revert NotDelegatedVerifier();
    }

    // Keeps "empty signature means already authenticated" true on this path as well
    if (msg.sender != owner && signature.length == 0) {
      revert InvalidDelegationSignature();
    }
    IAuthVerifier(verifier).updateAuth(owner, data, nonce, deadline, signature);
  }
}
