// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title ISettlementContext
/// @notice Interface of {SettlementContext}
interface ISettlementContext {
  /**
   * @notice The account the current call is acting for
   * @return The owner of the innermost order being settled, or the zero address when no order is
   * being settled
   */
  function msgSender() external view returns (address);

  /**
   * @notice The caller of the {IKSAllowanceHubV2-settleOrder} call settling the current order
   * @return The `msg.sender` of the innermost {IKSAllowanceHubV2-settleOrder} call, or the zero
   * address when no order is being settled
   */
  function solver() external view returns (address);
}
