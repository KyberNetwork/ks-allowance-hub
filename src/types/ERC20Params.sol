// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {PermitHelper} from 'ks-common-sc/src/libraries/token/PermitHelper.sol';
import {TokenHelper} from 'ks-common-sc/src/libraries/token/TokenHelper.sol';

import {ICommon} from 'ks-common-sc/src/interfaces/ICommon.sol';
import {ISignatureTransfer} from 'ks-common-sc/src/interfaces/ISignatureTransfer.sol';
import {CalldataDecoder} from 'ks-common-sc/src/libraries/calldata/CalldataDecoder.sol';

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
  using CalldataDecoder for bytes;

  /// @notice Collects ERC20 tokens from `msg.sender`
  function collect(ERC20Params calldata self, ISignatureTransfer permit2) internal {
    if (self.targets.length != self.amounts.length) {
      revert ICommon.MismatchedArrayLengths();
    }

    if (self.permitData.length == 32 * 7) {
      /// @dev Collects token through `PERMIT2` contract
      ISignatureTransfer.PermitBatchTransferFrom memory permit =
        ISignatureTransfer.PermitBatchTransferFrom({
          permitted: new ISignatureTransfer.TokenPermissions[](self.targets.length),
          nonce: self.permitData.decodeUint256(0),
          deadline: self.permitData.decodeUint256(1)
        });

      ISignatureTransfer.SignatureTransferDetails[] memory details =
        new ISignatureTransfer.SignatureTransferDetails[](self.targets.length);

      for (uint256 i = 0; i < self.targets.length; i++) {
        permit.permitted[i] =
          ISignatureTransfer.TokenPermissions({token: self.token, amount: self.amounts[i]});
        details[i] = ISignatureTransfer.SignatureTransferDetails({
          to: self.targets[i], requestedAmount: self.amounts[i]
        });
      }

      bytes calldata signature = self.permitData.decodeBytes(2);
      permit2.permitTransferFrom(permit, details, msg.sender, signature);
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
