// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IAHV2Hook} from '../../src/interfaces/base/IAHV2Hook.sol';
import {ISettlementContext} from '../../src/interfaces/base/ISettlementContext.sol';

import {AHV2Order} from '../../src/types/AHV2Order.sol';
import {AHV2Solution} from '../../src/types/AHV2Solution.sol';

import {IERC20} from 'openzeppelin-contracts/contracts/token/ERC20/IERC20.sol';

/// @notice Hook spy: records call order, the index and data it was given, and the result of its
/// before call that reaches its after call.
contract HookMock is IAHV2Hook {
  /// @dev Appended to by every call, so a test can assert the whole sequence in one place
  string[] public sequence;

  uint256 public beforeCount;
  uint256 public afterCount;

  bytes32 public lastOrderHash;
  uint256 public lastBeforeIndex;

  /// @dev `order.hooks[index].data` as read by each call
  bytes public beforeData;
  bytes public afterData;

  /// @dev The `beforeSettlementResult` the after call received
  bytes public receivedBeforeResult;

  /// @dev {msgSender} of the hub as read during each call
  address public seenMsgSenderBefore;
  address public seenMsgSenderAfter;
  address public seenSolverBefore;
  address public seenSolverAfter;

  /// @dev Returned by the before call
  bytes public beforeResult;
  bool public revertOnBefore;
  bool public revertOnAfter;

  /// @dev Records when each call ran, by reading a balance at the time
  address public observedToken;
  address public observedAccount;
  uint256 public balanceAtBefore;
  uint256 public balanceAtAfter;
  bool private observing;

  function observe(address token, address account) external {
    observedToken = token;
    observedAccount = account;
    observing = true;
  }

  /// @dev Gives two hooks distinguishable results
  function setBeforeResult(bytes calldata value) external {
    beforeResult = value;
  }

  function setReverts(bool onBefore, bool onAfter) external {
    revertOnBefore = onBefore;
    revertOnAfter = onAfter;
  }

  function sequenceLength() external view returns (uint256) {
    return sequence.length;
  }

  function beforeSettlement(
    AHV2Order calldata order,
    bytes32 orderHash,
    AHV2Solution calldata,
    uint256 index
  ) external returns (bytes memory) {
    if (revertOnBefore) {
      revert('before');
    }

    sequence.push('before');
    beforeCount++;
    lastOrderHash = orderHash;
    lastBeforeIndex = index;
    beforeData = order.hooks[index].data;
    seenMsgSenderBefore = ISettlementContext(msg.sender).msgSender();
    seenSolverBefore = ISettlementContext(msg.sender).solver();
    if (observing) {
      balanceAtBefore = IERC20(observedToken).balanceOf(observedAccount);
    }

    return beforeResult;
  }

  function afterSettlement(
    AHV2Order calldata order,
    bytes32 orderHash,
    AHV2Solution calldata,
    uint256 index,
    bytes calldata beforeSettlementResult
  ) external {
    if (revertOnAfter) {
      revert('after');
    }

    sequence.push('after');
    afterCount++;
    lastOrderHash = orderHash;
    afterData = order.hooks[index].data;
    receivedBeforeResult = beforeSettlementResult;
    seenMsgSenderAfter = ISettlementContext(msg.sender).msgSender();
    seenSolverAfter = ISettlementContext(msg.sender).solver();
    if (observing) {
      balanceAtAfter = IERC20(observedToken).balanceOf(observedAccount);
    }
  }
}
