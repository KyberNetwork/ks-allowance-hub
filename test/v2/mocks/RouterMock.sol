// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {IKSGenericRouter} from 'src/base/interfaces/IKSGenericRouter.sol';
import {IMsgSender} from 'src/base/interfaces/IMsgSender.sol';

import {IERC20} from 'openzeppelin-contracts/contracts/token/ERC20/IERC20.sol';
import {ERC721Holder} from 'openzeppelin-contracts/contracts/token/ERC721/utils/ERC721Holder.sol';

/// @notice Router that records what the hub showed it, so tests can assert identity and ordering.
contract RouterMock is IKSGenericRouter, ERC721Holder {
  /// @dev Read inside `ksExecute`, which is the only point where the hub's lock is still held
  address public seenMsgSender;
  uint256 public callCount;
  uint256 public lastValue;
  bytes public lastData;

  /// @dev Set by a test to have the router pay a token out, proving the funds actually arrived
  address public payoutToken;
  address public payoutTo;
  uint256 public payoutAmount;

  receive() external payable {}

  function setPayout(address token, address to, uint256 amount) external {
    payoutToken = token;
    payoutTo = to;
    payoutAmount = amount;
  }

  function ksExecute(bytes calldata data) external payable returns (bytes memory) {
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

/// @notice Router that calls back into the hub, to prove the reentrancy lock holds.
contract ReentrantRouterMock is IKSGenericRouter, ERC721Holder {
  address public immutable HUB;
  bytes public reentryCalldata;

  constructor(address hub) {
    HUB = hub;
  }

  receive() external payable {}

  function setReentry(bytes calldata data) external {
    reentryCalldata = data;
  }

  function ksExecute(bytes calldata) external payable returns (bytes memory) {
    (bool ok, bytes memory ret) = HUB.call(reentryCalldata);
    if (!ok) {
      assembly ('memory-safe') {
        revert(add(ret, 0x20), mload(ret))
      }
    }
    return ret;
  }
}

/// @notice Router that refuses native, so a failed payout is observable.
contract NativeRejectorRouterMock is IKSGenericRouter {
  function ksExecute(bytes calldata) external payable returns (bytes memory) {
    revert('no native');
  }
}

/// @notice Router that hands back who it is and what it was given, so results pin call order.
/// @dev {RouterMock} returns a per-router counter, which cannot distinguish two routers
/// interleaved in one order; this one can.
contract EchoRouterMock is IKSGenericRouter {
  function ksExecute(bytes calldata data) external payable returns (bytes memory) {
    return abi.encode(address(this), data);
  }
}

/**
 * @notice Router whose calls can see each other's work, so a test can pin the order they ran in.
 * @dev A call built by {produce} stores its payload; one built by {observe} appends the payload as
 * it stood at that moment to {observations} and returns it. An observer that ran before a producer
 * therefore records empty bytes, which is what separates "both lists ran" from "they ran in this
 * order".
 */
contract ObservingRouterMock is IKSGenericRouter, ERC721Holder {
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

  function ksExecute(bytes calldata data) external payable returns (bytes memory) {
    if (data.length != 0 && data[0] == PRODUCE) {
      product = data[1:];
      return product;
    }

    observations.push(product);
    return product;
  }
}
