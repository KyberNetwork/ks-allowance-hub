// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ICommon} from 'ks-common-sc/src/interfaces/ICommon.sol';
import {PermitHelper} from 'ks-common-sc/src/libraries/token/PermitHelper.sol';
import {TokenHelper} from 'ks-common-sc/src/libraries/token/TokenHelper.sol';

/**
 * @notice Parameters for collecting one ERC20 token from `msg.sender` and fanning it out
 * @param token The address of the token to collect, or the native token sentinel
 * @param targets The addresses to transfer the token to
 * @param amounts The amount to transfer to each target, index-aligned with `targets`
 * @param permitData The EIP-2612 permit to run before transferring, empty to skip
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

  /**
   * @notice Permits and transfers an ERC20 token from `msg.sender` to each target
   * @dev Pulls from `msg.sender`, so this may only be used on a flow where the caller is the token
   * owner. Native amounts are paid out of the hub's balance and must be covered by `msg.value`.
   * @param self The parameters of the token to collect
   */
  function permitTransfer(ERC20Params calldata self) internal {
    if (self.targets.length != self.amounts.length) {
      revert ICommon.MismatchedArrayLengths();
    }

    if (self.token.isNative()) {
      for (uint256 i = 0; i < self.targets.length; i++) {
        self.targets[i].safeTransferNative(self.amounts[i]);
      }
    } else {
      // Establishes the allowance if one was signed, otherwise relies on an existing one
      self.token.callERC20Permit(msg.sender, self.permitData);

      for (uint256 i = 0; i < self.targets.length; i++) {
        self.token.safeTransferFrom(msg.sender, self.targets[i], self.amounts[i]);
      }
    }
  }
}
