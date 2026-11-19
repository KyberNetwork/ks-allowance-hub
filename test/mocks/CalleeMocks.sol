// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IAHV2Callee} from '../../src/interfaces/base/IAHV2Callee.sol';
import {IMsgSender} from '../../src/interfaces/base/IMsgSender.sol';

import {IERC20} from 'openzeppelin-contracts/contracts/token/ERC20/IERC20.sol';
import {ERC721Holder} from 'openzeppelin-contracts/contracts/token/ERC721/utils/ERC721Holder.sol';

/// @notice Callee that records what the hub passed it, so tests can assert identity and ordering.
contract CalleeMock is IAHV2Callee, ERC721Holder {
  /// @dev Read inside either call, where {msgSender} still returns the owner of the order settling
  address public seenMsgSender;
  /// @dev Counts solver calls and owner calls together
  uint256 public callCount;
  uint256 public ownerCallCount;
  uint256 public lastValue;
  /// @dev The `solverData` of a solver call, or the `ownerData` of an owner call
  bytes public lastData;
  /// @dev The `solverData` of the last owner call
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

  /// @dev A call with empty `ownerData` is a solver call; any other is an owner call
  function execute(bytes calldata ownerData, bytes calldata solverData)
    external
    payable
    returns (bytes memory)
  {
    if (ownerData.length == 0) {
      return _record(solverData);
    }

    ownerCallCount++;
    lastSolverData = solverData;
    return _record(ownerData);
  }

  function _record(bytes calldata data) private returns (bytes memory) {
    seenMsgSender = IMsgSender(msg.sender).msgSender();
    callCount++;
    lastValue = msg.value;
    lastData = data;

    if (payoutAmount != 0) {
      IERC20(payoutToken).transfer(payoutTo, payoutAmount);
    }

    return abi.encode(callCount);
  }
}

/// @notice Callee that calls back into the hub, and records {msgSender} on either side of the call.
contract ReentrantCalleeMock is IAHV2Callee, ERC721Holder {
  address public immutable HUB;
  bytes public reentryCalldata;

  /// @dev {msgSender} on entry to a call
  address public seenBefore;
  /// @dev {msgSender} after the reentry call has returned
  address public seenAfter;

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
    seenBefore = IMsgSender(HUB).msgSender();
    (bool ok, bytes memory ret) = HUB.call(reentryCalldata);
    seenAfter = IMsgSender(HUB).msgSender();
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
  /// @dev With empty `ownerData` returns the callee and `solverData`; otherwise returns the
  /// callee, `ownerData` and `solverData`
  function execute(bytes calldata ownerData, bytes calldata solverData)
    external
    payable
    returns (bytes memory)
  {
    if (ownerData.length == 0) {
      return abi.encode(address(this), solverData);
    }

    return abi.encode(address(this), ownerData, solverData);
  }
}

/**
 * @notice Callee whose calls can see each other's work, so a test can pin the order they ran in.
 * @dev A call built by {produce} stores its payload; one built by {observe} appends the payload as
 * it stood at that moment to {observations} and returns it. An observer that ran before a producer
 * therefore records empty bytes, which separates the fact that both lists ran from the order in
 * which they ran. A solver call acts on its `solverData` and an owner call on its `ownerData`.
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

  function execute(bytes calldata ownerData, bytes calldata solverData)
    external
    payable
    returns (bytes memory)
  {
    return _run(ownerData.length == 0 ? solverData : ownerData);
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
