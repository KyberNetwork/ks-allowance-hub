// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IMsgSender} from './interfaces/IMsgSender.sol';

import {TransientSlot} from 'openzeppelin-contracts/contracts/utils/TransientSlot.sol';

/// @title MsgSender
/**
 * @notice Publishes whose behalf the contract is acting on, so a callee that sees this contract as
 * its `msg.sender` can still identify the user, and doubles as the reentrancy guard.
 */
abstract contract MsgSender is IMsgSender {
  using TransientSlot for *;

  bytes32 internal constant LOCKER_SLOT = bytes32(erc7201('ks-allowance-hub.locker'));

  /// @dev Holds the asset owner, not the caller, so relayed and direct orders look alike downstream
  modifier lock(address locker) {
    TransientSlot.AddressSlot slot = LOCKER_SLOT.asAddress();
    if (slot.tload() != address(0)) {
      revert AlreadyLocked();
    }

    slot.tstore(locker);
    _;
    slot.tstore(address(0));
  }

  /// @inheritdoc IMsgSender
  function msgSender() public view returns (address locker) {
    return LOCKER_SLOT.asAddress().tload();
  }
}
