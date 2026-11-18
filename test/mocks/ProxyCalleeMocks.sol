// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IMsgSender} from '../../src/interfaces/base/IMsgSender.sol';

/**
 * @title ProxyCalleeMock
 * @notice Callee for the {AHV2ProxyCallee} tests, which runs by delegatecall and keeps no storage
 * @dev `TAG` is an immutable and so lives in the code, which identifies the callee that ran when
 * the proxy executes it. Every selector the mock does not implement reaches {fallback}, which
 * echoes the calldata.
 */
contract ProxyCalleeMock {
  /// @notice Emitted by {fallback}, from the context the mock runs in
  event Delegated(bytes32 tag, address sender, uint256 value, bytes data);

  /// @notice Emitted by {recordOwner}
  event Owner(bytes32 tag, address owner);

  /// @notice Reverted with by {revertCustom}
  error CalleeFailed(bytes32 tag, uint256 code);

  bytes32 public immutable TAG;

  constructor(bytes32 tag) {
    TAG = tag;
  }

  fallback(bytes calldata data) external payable returns (bytes memory) {
    emit Delegated(TAG, msg.sender, msg.value, data);
    return abi.encode(TAG, data);
  }

  /// @dev Succeeds only when called without native value
  function nonPayable() external {}

  /// @dev Returns nothing and emits nothing
  function noReturn() external payable {}

  function revertCustom(uint256 code) external payable {
    revert CalleeFailed(TAG, code);
  }

  function revertString() external payable {
    revert('callee failed');
  }

  function revertEmpty() external payable {
    assembly {
      revert(0, 0)
    }
  }

  function divideByZero() external payable returns (uint256) {
    uint256 zero;
    return 1 / zero;
  }

  /// @dev Emits the account the caller acts for, read from the caller's {IMsgSender-msgSender}
  function recordOwner() external payable {
    emit Owner(TAG, IMsgSender(msg.sender).msgSender());
  }

  /// @dev Sends `value` from the running context to itself with empty calldata
  function sendToSelf(uint256 value) external payable {
    (bool ok,) = address(this).call{value: value}('');
    require(ok, 'send failed');
  }

  /// @dev Calls the running context with `cd`, returning or reverting with the raw return data
  function callBack(bytes calldata cd) external payable {
    _callBack(cd);
  }

  /// @dev Calls the running context with `proxyCall`, which must succeed, then as {callBack}
  function nest(bytes calldata proxyCall, bytes calldata cd) external payable {
    (bool ok, bytes memory ret) = address(this).call(proxyCall);
    if (!ok) {
      assembly {
        revert(add(ret, 0x20), mload(ret))
      }
    }
    _callBack(cd);
  }

  /// @dev As {nest}, ignoring a failure of `proxyCall`
  function tryNest(bytes calldata proxyCall, bytes calldata cd) external payable {
    address(this).call(proxyCall);
    _callBack(cd);
  }

  function _callBack(bytes calldata cd) private {
    (bool ok, bytes memory ret) = address(this).call(cd);
    assembly {
      if ok {
        return(add(ret, 0x20), mload(ret))
      }
      revert(add(ret, 0x20), mload(ret))
    }
  }
}
