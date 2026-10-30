// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IMsgSender} from './interfaces/IMsgSender.sol';

import {TransientSlot} from 'openzeppelin-contracts/contracts/utils/TransientSlot.sol';

/**
 * @title MsgSender
 * @notice Records the account a call is acting for, so that a contract it calls can identify that
 * account. A call that sets the account may run inside another, and the account set before it is
 * restored when it returns. No call that sets the account may run inside a locked one.
 * @dev The slot holds the account in its low 160 bits and the lock in bit 160.
 */
abstract contract MsgSender is IMsgSender {
  using TransientSlot for *;

  bytes32 internal constant MSG_SENDER_SLOT = bytes32(erc7201('ks-allowance-hub.msg-sender'));

  uint256 internal constant LOCKED_FLAG = 1 << 160;

  /// @dev Sets `sender` as {msgSender} for the call
  modifier setMsgSender(address sender) {
    uint256 previous = _setMsgSender(uint160(sender));
    _;
    MSG_SENDER_SLOT.asUint256().tstore(previous);
  }

  /// @dev Sets `sender` as {msgSender} for the call, and holds the lock until it returns
  modifier setMsgSenderAndLock(address sender) {
    uint256 previous = _setMsgSender(LOCKED_FLAG | uint160(sender));
    _;
    MSG_SENDER_SLOT.asUint256().tstore(previous);
  }

  /**
   * @dev Stores `value` in the slot and returns the value stored before it, reverting while the
   * lock is held
   */
  function _setMsgSender(uint256 value) internal returns (uint256 previous) {
    TransientSlot.Uint256Slot slot = MSG_SENDER_SLOT.asUint256();
    previous = slot.tload();
    if (previous & LOCKED_FLAG != 0) {
      revert AlreadyLocked(address(uint160(previous)));
    }

    slot.tstore(value);
  }

  /// @inheritdoc IMsgSender
  function msgSender() public view returns (address sender) {
    return address(uint160(MSG_SENDER_SLOT.asUint256().tload()));
  }
}
