// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IOrderAuthenticator} from '../interfaces/IOrderAuthenticator.sol';

/**
 * @title OrderAuthenticatorBase
 * @notice Restricts an authenticator's caller-only functions to the one address it was deployed
 * for
 * @dev The authorized caller is the allowance hub, or another authenticator that calls this one
 * in a chain.
 */
abstract contract OrderAuthenticatorBase is IOrderAuthenticator {
  address internal immutable AUTHORIZED_CALLER;

  /// @param authorizedCaller The only address that may call the caller-only functions
  constructor(address authorizedCaller) {
    AUTHORIZED_CALLER = authorizedCaller;
  }

  modifier onlyAuthorizedCaller() {
    if (msg.sender != AUTHORIZED_CALLER) {
      revert CallerNotAuthorized(msg.sender);
    }
    _;
  }
}
