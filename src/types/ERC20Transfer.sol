// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ERC20Params} from './ERC20Params.sol';

import {ISignatureTransfer} from 'ks-common-sc/src/interfaces/ISignatureTransfer.sol';

/**
 * @notice A single ERC20 token movement, as reported in the `TransferTokens` event
 * @param token The address of the token
 * @param target The address the token was transferred to
 * @param amount The amount transferred
 */
struct ERC20Transfer {
  address token;
  address target;
  uint256 amount;
}

/// @notice Contains functions for working with ERC20Transfer
library ERC20TransferLibrary {
  /**
   * @notice Flattens the per-token parameters into one movement per target
   * @param params The ERC20 tokens being collected
   * @return transfers The resulting movements, in parameter then target order
   */
  function toTransfers(ERC20Params[] calldata params)
    internal
    pure
    returns (ERC20Transfer[] memory transfers)
  {
    // Each entry fans out to as many movements as it has targets, so size the array first
    uint256 length = 0;
    for (uint256 i = 0; i < params.length; i++) {
      length += params[i].targets.length;
    }

    uint256 index = 0;
    transfers = new ERC20Transfer[](length);

    for (uint256 i = 0; i < params.length; i++) {
      ERC20Params calldata _params = params[i];
      for (uint256 j = 0; j < params[i].targets.length; j++) {
        transfers[index++] = ERC20Transfer({
          token: _params.token, target: _params.targets[j], amount: _params.amounts[j]
        });
      }
    }
  }

  /**
   * @notice Pairs the Permit2 permitted tokens with the targets they are transferred to
   * @dev Assumes `targets` and `permitted` are the same length; the caller enforces that.
   * @param permitted The tokens and amounts covered by the Permit2 signature
   * @param targets The addresses each permitted token is transferred to
   * @return transfers The resulting movements, index-aligned with `permitted`
   */
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
