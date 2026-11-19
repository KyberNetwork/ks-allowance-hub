// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @notice An ERC20 transfer as {IKSAllowanceHubV2-SettleOrder} reports it, from the owner to
 * `target`
 * @dev In {IKSAllowanceHubV2-rescueTokens}, the entry is a transfer from the hub: a zero `amount`
 * transfers the hub's entire balance, and a `token` of the native-token address or the zero
 * address transfers native value.
 * @param token The ERC20 token
 * @param target Account the amount is transferred to
 * @param amount Amount transferred, with the width of a Permit2 allowance
 */
struct ERC20Transfer {
  address token;
  address target;
  uint160 amount;
}
