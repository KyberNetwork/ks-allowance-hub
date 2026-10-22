// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {DeadlineChecker} from '../base/DeadlineChecker.sol';
import {UnorderedNonce} from '../base/UnorderedNonce.sol';

import {IAuthDelegator} from './interfaces/IAuthDelegator.sol';
import {IOrderAuthenticator} from './interfaces/IOrderAuthenticator.sol';

import {AuthDelegationLib} from './types/AuthDelegation.sol';

import {EIP712} from 'openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol';
import {
  SignatureChecker
} from 'openzeppelin-contracts/contracts/utils/cryptography/SignatureChecker.sol';

/**
 * @title AuthDelegator
 * @notice Allows an owner to nominate an {IOrderAuthenticator} once and thereafter authenticate
 * orders with whatever credential that authenticator understands, instead of signing each order
 * here.
 * @dev The authenticator is trusted by the owner, not by this contract: the only check is that the
 * owner delegated it.
 */
abstract contract AuthDelegator is IAuthDelegator, DeadlineChecker, UnorderedNonce, EIP712 {
  /// @inheritdoc IAuthDelegator
  mapping(address owner => mapping(address authenticator => bool)) public authDelegated;

  /**
   * @param name EIP-712 domain name, which scopes every signature this contract checks
   * @param version EIP-712 domain version
   */
  constructor(string memory name, string memory version) EIP712(name, version) {}

  modifier checkDelegation(address owner, address authenticator) {
    _checkDelegation(owner, authenticator);
    _;
  }

  /// @dev Held in one place rather than inlined at every use of the modifier
  function _checkDelegation(address owner, address authenticator) internal view {
    if (authenticator != address(0) && !authDelegated[owner][authenticator]) {
      revert AuthenticatorNotDelegated(authenticator);
    }
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
    // `forwardCalls` reaches this with the hub as the caller, which never authenticates as an owner
    if (owner != msg.sender || msg.sender == address(this)) {
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

    // Forwarded only when delegating, so an authenticator that reverts cannot trap the owner in
    // delegation. It takes no signature, so the owner must already have been authenticated here
    if (delegated && data.length > 0) {
      IOrderAuthenticator(authenticator).initAuthentication(owner, data);
    }
    authDelegated[owner][authenticator] = delegated;
  }
}
