// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ISettlementContext} from '../interfaces/base/ISettlementContext.sol';

import {Constants} from '../libraries/Constants.sol';

import {TransientSlot} from 'openzeppelin-contracts/contracts/utils/TransientSlot.sol';

/**
 * @title SettlementContext
 * @notice Records the owner and the solver of the order being settled, for the contracts its
 * settlement calls
 * @dev A settlement may run inside another, and the values set before it are restored when it
 * returns.
 */
abstract contract SettlementContext is ISettlementContext {
  using TransientSlot for *;

  /// @dev Sets `owner` as {msgSender} and the caller as {solver} for the call
  modifier setSettlementContext(address owner) {
    TransientSlot.AddressSlot ownerSlot = Constants.MSG_SENDER_SLOT.asAddress();
    TransientSlot.AddressSlot solverSlot = Constants.SOLVER_SLOT.asAddress();
    address previousOwner = ownerSlot.tload();
    address previousSolver = solverSlot.tload();
    ownerSlot.tstore(owner);
    solverSlot.tstore(msg.sender);
    _;
    ownerSlot.tstore(previousOwner);
    solverSlot.tstore(previousSolver);
  }

  /// @inheritdoc ISettlementContext
  function msgSender() public view returns (address sender) {
    return Constants.MSG_SENDER_SLOT.asAddress().tload();
  }

  /// @inheritdoc ISettlementContext
  function solver() public view returns (address) {
    return Constants.SOLVER_SLOT.asAddress().tload();
  }
}
