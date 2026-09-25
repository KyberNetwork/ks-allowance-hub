// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {PermitHelper} from 'ks-common-sc/src/libraries/token/PermitHelper.sol';
import {TokenHelper} from 'ks-common-sc/src/libraries/token/TokenHelper.sol';

import {ICommon} from 'ks-common-sc/src/interfaces/ICommon.sol';

/**
 * @notice Parameters for collecting ERC20 tokens from `msg.sender`
 * @param token The address of the tokens to collect
 * @param targets The addresses to transfer the tokens to
 * @param amounts The amounts to transfer to each target
 * @param permitData The permit data for the tokens
 */
struct ERC20Params {
  address token;
  address[] targets;
  uint256[] amounts;
  bytes permitData;
}

using ERC20ParamsLibrary for ERC20Params global;

/// @notice Contains functions for working with ERC20Params
library ERC20ParamsLibrary {
  using PermitHelper for address;
  using TokenHelper for address;

  /// @notice Permits and transfers ERC20 tokens from `msg.sender`
  function permitTransfer(ERC20Params calldata self) internal {
    if (self.targets.length != self.amounts.length) {
      revert ICommon.MismatchedArrayLengths();
    }

    if (self.token.isNative()) {
      for (uint256 i = 0; i < self.targets.length; i++) {
        self.targets[i].safeTransferNative(self.amounts[i]);
      }
    } else {
      /// @dev Permits the tokens if provided
      self.token.callERC20Permit(msg.sender, self.permitData);

      /// @dev Transfers the tokens to the targets
      for (uint256 i = 0; i < self.targets.length; i++) {
        self.token.safeTransferFrom(msg.sender, self.targets[i], self.amounts[i]);
      }
    }
  }
}
