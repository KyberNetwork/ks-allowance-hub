// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IAHV2Authenticator} from '../interfaces/base/IAHV2Authenticator.sol';

/**
 * @title AHV2AuthenticatorBase
 * @notice Restricts the functions of an authenticator marked {onlyAuthorizedCaller} to one address
 * set at construction
 * @dev The authorized caller is the allowance hub, or another authenticator that calls this one.
 */
abstract contract AHV2AuthenticatorBase is IAHV2Authenticator {
  /// @notice The caller is not the authorized caller set at construction
  error CallerNotAuthorized(address caller);

  address internal immutable AUTHORIZED_CALLER;

  /// @param authorizedCaller The only address {onlyAuthorizedCaller} accepts
  constructor(address authorizedCaller) {
    AUTHORIZED_CALLER = authorizedCaller;
  }

  /// @dev Restricts the function to the authorized caller
  modifier onlyAuthorizedCaller() {
    if (msg.sender != AUTHORIZED_CALLER) {
      revert CallerNotAuthorized(msg.sender);
    }
    _;
  }
}
