// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IAHV2Callee} from '../../src/interfaces/base/IAHV2Callee.sol';
import {ISettlementContext} from '../../src/interfaces/base/ISettlementContext.sol';

import {IERC20} from 'openzeppelin-contracts/contracts/token/ERC20/IERC20.sol';
import {ERC721Holder} from 'openzeppelin-contracts/contracts/token/ERC721/utils/ERC721Holder.sol';

/// @notice Callee that records what the hub passed it, so tests can assert identity and ordering.
contract CalleeMock is IAHV2Callee, ERC721Holder {
  /// @dev Read inside the call, where {msgSender} still returns the owner of the order settling
  address public seenMsgSender;
  /// @dev Read inside the call, where {solver} returns the caller of `settleOrder`
  address public seenSolver;
  /// @dev Counts the calls
  uint256 public callCount;
  uint256 public lastValue;
  /// @dev The `ownerData` of the last call
  bytes public lastData;
  /// @dev The `solverData` of the last call
  bytes public lastSolverData;

  /// @dev Set by a test to have the callee pay a token out, proving the funds arrived
  address public payoutToken;
  address public payoutTo;
  uint256 public payoutAmount;

  receive() external payable {}

  function setPayout(address token, address to, uint256 amount) external {
    payoutToken = token;
    payoutTo = to;
    payoutAmount = amount;
  }

  /// @dev Records the call
  function execute(bytes calldata ownerData, bytes calldata solverData)
    external
    payable
    returns (bytes memory)
  {
    lastSolverData = solverData;
    return _record(ownerData);
  }

  function _record(bytes calldata data) private returns (bytes memory) {
    seenMsgSender = ISettlementContext(msg.sender).msgSender();
    seenSolver = ISettlementContext(msg.sender).solver();
    callCount++;
    lastValue = msg.value;
    lastData = data;

    if (payoutAmount != 0) {
      IERC20(payoutToken).transfer(payoutTo, payoutAmount);
    }

    return abi.encode(callCount);
  }
}

/// @notice Callee that calls back into the hub, and records {msgSender} and {solver} on either side of the call.
contract ReentrantCalleeMock is IAHV2Callee, ERC721Holder {
  address public immutable HUB;
  bytes public reentryCalldata;

  /// @dev {msgSender} on entry to a call
  address public seenBefore;
  /// @dev {msgSender} after the reentry call has returned
  address public seenAfter;
  /// @dev {solver} on entry to a call
  address public seenSolverBefore;
  /// @dev {solver} after the reentry call has returned
  address public seenSolverAfter;

  constructor(address hub) {
    HUB = hub;
  }

  receive() external payable {}

  function setReentry(bytes calldata data) external {
    reentryCalldata = data;
  }

  function execute(bytes calldata, bytes calldata) external payable returns (bytes memory) {
    return _reenter();
  }

  function _reenter() private returns (bytes memory) {
    seenBefore = ISettlementContext(HUB).msgSender();
    seenSolverBefore = ISettlementContext(HUB).solver();
    (bool ok, bytes memory ret) = HUB.call(reentryCalldata);
    seenAfter = ISettlementContext(HUB).msgSender();
    seenSolverAfter = ISettlementContext(HUB).solver();
    if (!ok) {
      assembly ('memory-safe') {
        revert(add(ret, 0x20), mload(ret))
      }
    }
    return ret;
  }
}

/// @notice Callee that returns its own identity and the data it was given, so results pin call
/// order.
/// @dev {CalleeMock} returns a per-callee counter, which cannot distinguish two callees
/// interleaved in one order; this one can.
contract EchoCalleeMock is IAHV2Callee {
  /// @dev Returns the callee, `ownerData` and `solverData`
  function execute(bytes calldata ownerData, bytes calldata solverData)
    external
    payable
    returns (bytes memory)
  {
    return abi.encode(address(this), ownerData, solverData);
  }
}

/**
 * @notice Callee whose calls can see each other's work, so a test can pin the order they ran in.
 * @dev A call built by {produce} stores its payload; one built by {observe} appends the payload as
 * it stood at that moment to {observations} and returns it. An observer that ran before a producer
 * therefore records empty bytes, which separates the fact that the calls ran from the order in
 * which they ran.
 */
contract ObservingCalleeMock is IAHV2Callee, ERC721Holder {
  bytes1 private constant PRODUCE = 0x01;
  bytes1 private constant OBSERVE = 0x02;

  bytes public product;
  bytes[] public observations;

  receive() external payable {}

  /// @dev Call data that stores `value` as the product
  function produce(bytes memory value) external pure returns (bytes memory) {
    return abi.encodePacked(PRODUCE, value);
  }

  /// @dev Call data that records the product as it stands when the call runs
  function observe() external pure returns (bytes memory) {
    return abi.encodePacked(OBSERVE);
  }

  function observationCount() external view returns (uint256) {
    return observations.length;
  }

  function execute(bytes calldata ownerData, bytes calldata)
    external
    payable
    returns (bytes memory)
  {
    return _run(ownerData);
  }

  function _run(bytes calldata data) private returns (bytes memory) {
    if (data.length != 0 && data[0] == PRODUCE) {
      product = data[1:];
      return product;
    }

    observations.push(product);
    return product;
  }
}
