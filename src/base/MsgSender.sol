// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IMsgSender} from './interfaces/IMsgSender.sol';

import {TransientSlot} from 'openzeppelin-contracts/contracts/utils/TransientSlot.sol';

/**
 * @title MsgSender
 * @notice Records the account a call is acting for, so that a contract it calls can identify that
 * account, and rejects a second locked call while one is in progress
 */
abstract contract MsgSender is IMsgSender {
  using TransientSlot for *;

  bytes32 internal constant LOCKER_SLOT = bytes32(erc7201('ks-allowance-hub.locker'));

  modifier lock(address locker) {
    _lock(locker);
    _;
    LOCKER_SLOT.asAddress().tstore(address(0));
  }

  /// @dev Records `locker`, reverting when another account is already recorded
  function _lock(address locker) internal {
    TransientSlot.AddressSlot slot = LOCKER_SLOT.asAddress();
    address _locker = slot.tload();
    if (_locker != address(0)) {
      revert AlreadyLocked(_locker);
    }

    slot.tstore(locker);
  }

  /// @inheritdoc IMsgSender
  function msgSender() public view returns (address locker) {
    return LOCKER_SLOT.asAddress().tload();
  }
}
