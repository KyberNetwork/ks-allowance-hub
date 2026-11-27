// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IAHV2Authenticator} from '../interfaces/base/IAHV2Authenticator.sol';
import {IAuthDelegator} from '../interfaces/base/IAuthDelegator.sol';

import {EIP712Nonce} from './EIP712Nonce.sol';

import {AuthDelegationLib} from '../types/AuthDelegation.sol';

import {ManagementSimple} from 'ks-common-sc/src/base/ManagementSimple.sol';

import {EIP712} from 'openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol';

/**
 * @title AuthDelegator
 * @notice Records which {IAHV2Authenticator} contracts each owner has delegated to authenticate
 * their orders
 * @dev An authenticator is trusted by the owner who delegates it. This contract checks only that
 * the delegation is in place.
 */
abstract contract AuthDelegator is IAuthDelegator, EIP712Nonce, ManagementSimple {
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
  ) external payable whenNotPaused {
    if (block.timestamp > deadline) {
      revert DeadlinePassed(deadline, block.timestamp);
    }

    // The owner may pass an empty signature, which spends no nonce. Every other caller, including
    // Multicall3 relaying the call through `forwardCalls`, must give the owner's signature over
    // the {AuthDelegation}. Any non-empty signature, also one given by the owner, is checked as
    // that signature and spends `nonce` in the owner's namespace.
    if (signature.length != 0 || owner != msg.sender) {
      bytes32 delegationHash =
        AuthDelegationLib.hash(owner, authenticator, delegated, data, nonce, deadline);
      if (!_verifySignature(owner, nonce, delegationHash, signature)) {
        revert InvalidDelegationSignature();
      }
    }

    // Delegating with non-empty `data` passes it to `initAuthentication`, which takes no
    // signature because the owner was authenticated above. Withdrawing calls no authenticator.
    // An authenticator that reverts therefore cannot prevent a withdrawal, and a withdrawal
    // leaves the authenticator's own state unchanged.
    if (delegated && data.length > 0) {
      IAHV2Authenticator(authenticator).initAuthentication(owner, data);
    }
    authDelegated[owner][authenticator] = delegated;

    emit UpdateDelegation(owner, authenticator, delegated);
  }
}
