// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IAuthDelegator} from './interfaces/IAuthDelegator.sol';
import {IOrderAuthenticator} from './interfaces/IOrderAuthenticator.sol';

import {DeadlineChecker} from '../base/DeadlineChecker.sol';
import {EIP712Base} from '../base/EIP712Base.sol';
import {UnorderedNonce} from '../base/UnorderedNonce.sol';

import {AuthDelegationLib} from './types/AuthDelegation.sol';

import {
  SignatureChecker
} from 'openzeppelin-contracts/contracts/utils/cryptography/SignatureChecker.sol';

/**
 * @title AuthDelegator
 * @notice Lets an owner nominate an {IOrderAuthenticator} once and afterwards authenticate orders
 * whatever credential that authenticator understands, instead of signing each order here.
 * @dev The authenticator is trusted by the owner, not by this contract: all that is checked is
 * the owner delegated it.
 */
abstract contract AuthDelegator is IAuthDelegator, DeadlineChecker, UnorderedNonce, EIP712Base {
  /// @inheritdoc IAuthDelegator
  mapping(address owner => mapping(address authenticator => bool)) public authDelegated;

  /**
   * @param name EIP-712 domain name, which scopes every signature this contract checks
   * @param version EIP-712 domain version
   */
  constructor(string memory name, string memory version) EIP712Base(name, version) {}

  modifier checkDelegation(address owner, address authenticator) {
    _checkDelegation(owner, authenticator);
    _;
  }

  /// @dev The check itself, held in one place rather than inlined at every modifier use
  function _checkDelegation(address owner, address authenticator) internal view {
    if (authenticator != address(0) && !authDelegated[owner][authenticator]) {
      revert NotDelegatedAuthenticator(owner, authenticator);
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
    if (owner != msg.sender) {
      _useUnorderedNonce(owner, nonce);

      bytes32 hash =
        _hashTypedDataV4(AuthDelegationLib.hash(authenticator, delegated, data, nonce, deadline));
      if (!SignatureChecker.isValidSignatureNow(owner, hash, signature)) {
        revert InvalidDelegationSignature();
      }
    }

    // Forwarded only when delegating, so an authenticator that reverts cannot trap the owner in
    // delegation. It takes no signature, so the owner must have been authenticated by here
    if (delegated && data.length > 0) {
      IOrderAuthenticator(authenticator).initAuthentication(owner, data);
    }
    authDelegated[owner][authenticator] = delegated;
  }
}
