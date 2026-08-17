// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IMsgSenderHub} from './IMsgSenderHub.sol';
import {IKSGenericRouter} from 'src/interfaces/IKSGenericRouter.sol';

import {IERC20} from 'openzeppelin-contracts/contracts/interfaces/IERC20.sol';

/// @notice Shared monotonic sequence recorder, letting tests assert cross-contract call ordering
contract CallOrderRecorderMock {
  /// @notice The tags recorded so far, in call order
  string[] public sequence;

  function record(string calldata tag) external {
    sequence.push(tag);
  }

  function length() external view returns (uint256) {
    return sequence.length;
  }

  function all() external view returns (string[] memory) {
    return sequence;
  }
}

/**
 * @notice Whitelistable router standing in for a real KyberSwap router
 * @dev Records what the hub passed it, including the `msgSender()` it observed, so tests can assert
 * the transient owner is published for the whole execution.
 */
contract GenericRouterMock is IKSGenericRouter {
  /// @notice Thrown when the router is configured to fail
  error RouterFailed();

  struct Call {
    address caller;
    uint256 value;
    bytes data;
    address observedMsgSender;
    uint256 hubBalanceDuringCall;
  }

  Call[] internal _calls;

  IMsgSenderHub public immutable HUB;
  CallOrderRecorderMock public immutable RECORDER;
  string internal _tag;

  bytes public returnData;
  bool public shouldRevert;

  constructor(address hub, address recorder, string memory tag) {
    HUB = IMsgSenderHub(hub);
    RECORDER = CallOrderRecorderMock(recorder);
    _tag = tag;
    returnData = abi.encode(uint256(1));
  }

  function setReturnData(bytes calldata data) external {
    returnData = data;
  }

  function setShouldRevert(bool value) external {
    shouldRevert = value;
  }

  /// @inheritdoc IKSGenericRouter
  function ksExecute(bytes calldata data) external payable returns (bytes memory) {
    if (shouldRevert) revert RouterFailed();

    _calls.push(
      Call({
        caller: msg.sender,
        value: msg.value,
        data: data,
        observedMsgSender: HUB.msgSender(),
        hubBalanceDuringCall: address(HUB).balance
      })
    );

    if (address(RECORDER) != address(0)) RECORDER.record(_tag);

    return returnData;
  }

  /// @notice Pulls tokens the hub routed here onward, modelling a router consuming its input
  function sweep(address token, address to, uint256 amount) external {
    IERC20(token).transfer(to, amount);
  }

  function callCount() external view returns (uint256) {
    return _calls.length;
  }

  function callAt(uint256 index) external view returns (Call memory) {
    return _calls[index];
  }

  receive() external payable {}
}

/// @notice Router that calls back into the hub, used to prove the transient lock rejects reentry
contract ReentrantRouterMock is IKSGenericRouter {
  IMsgSenderHub public immutable HUB;

  bytes public reentrantCalldata;
  bool public captureRevert;

  /// @notice Whether the reentrant call reverted, and the raw revert data it produced
  bool public reentrantCallReverted;
  bytes public reentrantRevertData;

  constructor(address hub) {
    HUB = IMsgSenderHub(hub);
  }

  function setReentrantCalldata(bytes calldata data, bool capture) external {
    reentrantCalldata = data;
    captureRevert = capture;
  }

  /// @inheritdoc IKSGenericRouter
  function ksExecute(bytes calldata) external payable returns (bytes memory) {
    if (captureRevert) {
      (bool ok, bytes memory ret) = address(HUB).call(reentrantCalldata);
      reentrantCallReverted = !ok;
      reentrantRevertData = ret;
    } else {
      (bool ok, bytes memory ret) = address(HUB).call(reentrantCalldata);
      if (!ok) {
        assembly ('memory-safe') {
          revert(add(ret, 0x20), mload(ret))
        }
      }
    }
    return '';
  }

  receive() external payable {}
}
