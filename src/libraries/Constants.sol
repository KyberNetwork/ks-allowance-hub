// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Constants
/// @notice Constants shared by the hub, its base contracts and its authenticators
library Constants {
  /// @dev Role a router must hold to be called by an order
  bytes32 internal constant WHITELISTED_ROUTER_ROLE = keccak256('WHITELISTED_ROUTER_ROLE');

  /// @dev Value of `relayer` or `solver` that allows any caller to submit the order, and of
  /// `solutionApprover` that accepts any solution without an approval
  address internal constant DEAD_ADDRESS = 0x000000000000000000000000000000000000dEaD;

  /// @dev Transient slot of {MsgSender}, holding the account a call is acting for
  bytes32 internal constant MSG_SENDER_SLOT = bytes32(erc7201('ks-allowance-hub.msg-sender'));
}
