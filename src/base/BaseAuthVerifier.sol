// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IAuthVerifier} from './interfaces/IAuthVerifier.sol';

/// @title BaseAuthVerifier
/**
 * @notice Ties a verifier to one allowance hub. Verification is only meaningful when the hub asks
 * for it, since the hub is what pairs an order with the owner whose assets it moves.
 */
abstract contract BaseAuthVerifier is IAuthVerifier {
  address internal immutable ALLOWANCE_HUB;

  /// @param allowanceHub The only contract whose verification requests this verifier answers
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
