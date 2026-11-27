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

  /// @dev Largest number of ERC20 transfers in an order outside the Permit2 signature transfer flow
  uint256 internal constant MAX_ERC20S = 255;

  /// @dev Largest number of hooks in an order
  uint256 internal constant MAX_HOOKS = 64;

  /// @dev Offset in {AHV2Order-flags} of the bits that select {IAHV2Hook-afterSettlement}
  uint256 internal constant AFTER_SETTLEMENT_HOOKS_OFFSET = 64;

  /// @dev Offset of the high byte of {AHV2Order-flags}. The byte is the number of leading ERC20
  /// transfers drawn from the owner's Permit2 allowance.
  uint256 internal constant PERMIT2_TRANSFERS_OFFSET = 248;
}
