// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Constants
/// @notice Constants shared by the hub, its base contracts and its authenticators
library Constants {
  /// @dev Role a callee must hold to be called by an order
  bytes32 internal constant WHITELISTED_CALLEE_ROLE = keccak256('WHITELISTED_CALLEE_ROLE');

  /// @dev The zero address
  address internal constant ADDRESS_ZERO = address(0);

  /// @dev Transient slot of {SettlementContext-msgSender}
  bytes32 internal constant MSG_SENDER_SLOT = bytes32(erc7201('ks-allowance-hub.msg-sender'));

  /// @dev Transient slot of {SettlementContext-solver}
  bytes32 internal constant SOLVER_SLOT = bytes32(erc7201('ks-allowance-hub.solver'));

  /// @dev Bit of {HookParams-flags} that selects {IAHV2Hook-beforeSettlement}
  bytes32 internal constant BEFORE_SETTLEMENT_HOOK_FLAG = bytes32(uint256(0x01));

  /// @dev Bit of {HookParams-flags} that selects {IAHV2Hook-afterSettlement}
  bytes32 internal constant AFTER_SETTLEMENT_HOOK_FLAG = bytes32(uint256(0x02));
}
