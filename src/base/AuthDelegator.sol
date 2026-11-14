// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {DeadlineChecker} from './DeadlineChecker.sol';
import {UnorderedNonce} from './UnorderedNonce.sol';

import {IOrderAuthenticator} from '../interfaces/authenticators/IOrderAuthenticator.sol';
import {IAuthDelegator} from '../interfaces/base/IAuthDelegator.sol';

import {AuthDelegationLib} from '../types/AuthDelegation.sol';

import {EIP712} from 'openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol';
import {
  SignatureChecker
} from 'openzeppelin-contracts/contracts/utils/cryptography/SignatureChecker.sol';

/**
 * @title AuthDelegator
 * @notice Records which {IOrderAuthenticator} contracts each owner has delegated to authenticate
 * their orders
 * @dev An authenticator is trusted by the owner who delegates it. This contract checks only that
 * the delegation is in place.
 */
abstract contract AuthDelegator is IAuthDelegator, DeadlineChecker, UnorderedNonce, EIP712 {
  /// @inheritdoc IAuthDelegator
  mapping(address owner => mapping(address authenticator => bool)) public authDelegated;

  /**
   * @param name EIP-712 domain name of every signature this contract checks
   * @param version EIP-712 domain version
   */
  constructor(string memory name, string memory version) EIP712(name, version) {}

  /// @dev Reverts unless `authenticator` is the zero address or is delegated by `owner`
  modifier checkDelegation(address owner, address authenticator) {
    if (authenticator != address(0) && !authDelegated[owner][authenticator]) {
      revert AuthenticatorNotDelegated(authenticator);
    }
    _;
  }

  /// @inheritdoc IAuthDelegator
  function updateDelegation(
    address owner,
    address authenticator,
    bool delegated,
    bytes calldata data,
    uint256 nonce,
    uint256 deadline,
    bytes calldata signature
  ) external payable checkDeadline(deadline) {
    if (owner != msg.sender) {
      _useUnorderedNonce(owner, nonce);

      bytes32 hash = _hashTypedDataV4(
        AuthDelegationLib.hash(owner, authenticator, delegated, data, nonce, deadline)
      );
      if (!SignatureChecker.isValidSignatureNow(owner, hash, signature)) {
        revert InvalidDelegationSignature();
      }
    } else if (signature.length != 0) {
      revert UnexpectedSignature();
    }

    // Not called on withdrawal, so that an authenticator that reverts cannot prevent it. The owner
    // has been authenticated above, since `initAuthentication` takes no signature
    if (delegated && data.length > 0) {
      IOrderAuthenticator(authenticator).initAuthentication(owner, data);
    }
    authDelegated[owner][authenticator] = delegated;

    emit UpdateDelegation(owner, authenticator, delegated);
  }
}
