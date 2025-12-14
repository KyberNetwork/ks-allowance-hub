// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ERC20Params} from './ERC20Params.sol';
import {ISignatureTransfer} from 'ks-common-sc/src/interfaces/ISignatureTransfer.sol';

/**
 * @notice Indicates an ERC20 token transfer
 * @param token The address of the token
 * @param target The address of the target
 * @param amount The amount of tokens to transfer
 */
struct ERC20Transfer {
  address token;
  address target;
  uint256 amount;
}

library ERC20TransferLibrary {
  function toTransfers(ERC20Params[] calldata params)
    internal
    pure
    returns (ERC20Transfer[] memory transfers)
  {
    uint256 length = 0;
    for (uint256 i = 0; i < params.length; i++) {
      length += params[i].targets.length;
    }

    transfers = new ERC20Transfer[](length);
    for (uint256 i = 0; i < params.length; i++) {
      for (uint256 j = 0; j < params[i].targets.length; j++) {
        transfers[--length] = ERC20Transfer({
          token: params[i].token, target: params[i].targets[j], amount: params[i].amounts[j]
        });
      }
    }
  }

  function toTransfers(
    ISignatureTransfer.TokenPermissions[] calldata permitted,
    address[] calldata targets
  ) internal pure returns (ERC20Transfer[] memory transfers) {
    transfers = new ERC20Transfer[](permitted.length);
    for (uint256 i = 0; i < permitted.length; i++) {
      transfers[i] =
        ERC20Transfer({token: permitted[i].token, target: targets[i], amount: permitted[i].amount});
    }
  }
}
