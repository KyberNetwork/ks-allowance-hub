// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IOrderAuthenticator} from '../interfaces/IOrderAuthenticator.sol';

/**
 * @title OrderAuthenticatorBase
 * @notice Restricts an authenticator's hub-only functions to the allowance hub it was deployed for
 */
abstract contract OrderAuthenticatorBase is IOrderAuthenticator {
  address internal immutable ALLOWANCE_HUB;

  /// @param allowanceHub The allowance hub this authenticator serves
  constructor(address allowanceHub) {
    ALLOWANCE_HUB = allowanceHub;
  }

  modifier onlyAllowanceHub() {
    if (msg.sender != ALLOWANCE_HUB) {
      revert CallerNotAllowanceHub(msg.sender);
    }
    _;
  }
}
