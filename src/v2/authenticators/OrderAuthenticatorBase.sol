// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IOrderAuthenticator} from '../interfaces/IOrderAuthenticator.sol';

/**
 * @title OrderAuthenticatorBase
 * @notice Ties an authenticator to one allowance hub. Authentication is only meaningful when the
 * asks for it, since the hub is what pairs an order with the owner whose assets it moves.
 */
abstract contract OrderAuthenticatorBase is IOrderAuthenticator {
  address internal immutable ALLOWANCE_HUB;

  /// @param allowanceHub The only contract whose authentication requests this one answers
  constructor(address allowanceHub) {
    ALLOWANCE_HUB = allowanceHub;
  }

  modifier onlyAllowanceHub() {
    if (msg.sender != ALLOWANCE_HUB) {
      revert NotAllowanceHub();
    }
    _;
  }
}
