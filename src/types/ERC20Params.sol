// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {PermitHelper} from 'ks-common-sc/src/libraries/token/PermitHelper.sol';
import {TokenHelper} from 'ks-common-sc/src/libraries/token/TokenHelper.sol';

import {IAllowanceTransfer} from 'ks-common-sc/src/interfaces/IAllowanceTransfer.sol';
import {ICommon} from 'ks-common-sc/src/interfaces/ICommon.sol';

import {SafeCast} from 'openzeppelin-contracts/contracts/utils/math/SafeCast.sol';

/**
 * @notice Parameters for collecting ERC20 tokens from `msg.sender`
 * @param token The address of the token to collect
 * @param targets The addresses to transfer tokens to
 * @param amounts The amounts of tokens to transfer to each target
 * @param permitData The permit data for the token
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
  using SafeCast for uint256;

  /// @notice Collects ERC20 tokens from `msg.sender`
  function collect(ERC20Params calldata self, IAllowanceTransfer permit2) internal {
    if (self.targets.length != self.amounts.length) {
      revert ICommon.MismatchedArrayLengths();
    }

    if (self.permitData.length == 0) {
      /// @dev Collects token through `PERMIT2` contract
      IAllowanceTransfer.AllowanceTransferDetails[] memory details =
        new IAllowanceTransfer.AllowanceTransferDetails[](self.targets.length);

      for (uint256 i = 0; i < self.targets.length; i++) {
        details[i] = IAllowanceTransfer.AllowanceTransferDetails({
          from: msg.sender, to: self.targets[i], amount: self.amounts[i].toUint160(), token: self.token
        });
      }

      permit2.transferFrom(details);
    } else {
      /// @dev Permits tokens if needed
      self.token.callERC20Permit(msg.sender, self.permitData);

      /// @dev Collects tokens using normal method
      for (uint256 i = 0; i < self.targets.length; i++) {
        self.token.safeTransferFrom(msg.sender, self.targets[i], self.amounts[i]);
      }
    }
  }
}
