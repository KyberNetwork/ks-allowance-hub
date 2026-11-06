// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IMsgSender} from './interfaces/IMsgSender.sol';

import {Constants} from './libraries/Constants.sol';

import {TransientSlot} from 'openzeppelin-contracts/contracts/utils/TransientSlot.sol';

/**
 * @title MsgSender
 * @notice Records the account a call is acting for, so that a contract it calls can identify that
 * account. A call that sets the account may run inside another, and the account set before it is
 * restored when it returns.
 */
abstract contract MsgSender is IMsgSender {
  using TransientSlot for *;

  /// @dev Sets `sender` as {msgSender} for the call
  modifier setMsgSender(address sender) {
    TransientSlot.AddressSlot slot = Constants.MSG_SENDER_SLOT.asAddress();
    address previous = slot.tload();
    slot.tstore(sender);
    _;
    slot.tstore(previous);
  }

  /// @inheritdoc IMsgSender
  function msgSender() public view returns (address sender) {
    return Constants.MSG_SENDER_SLOT.asAddress().tload();
  }
}
