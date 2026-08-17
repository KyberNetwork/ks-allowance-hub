// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {CallOrderRecorderMock} from './RouterMocks.sol';

import {IKSActionValidator} from 'ks-action-validator-sc/src/interfaces/IKSActionValidator.sol';

import {IERC20} from 'openzeppelin-contracts/contracts/interfaces/IERC20.sol';

/**
 * @notice Validator standing in for a real KS action validator
 * @dev Records exactly what the hub passed to each hook and, when configured with a watched token
 * and account, snapshots that balance so tests can prove `beforeExecution` runs after the funding
 * transfers and before the generic calls.
 */
contract ActionValidatorMock is IKSActionValidator {
  /// @notice Thrown when the validator is configured to reject the transition
  error ValidationFailed();

  struct BeforeCall {
    address caller;
    bytes32 action;
    bytes input;
    uint256 watchedBalance;
  }

  struct AfterCall {
    address caller;
    bytes32 action;
    bytes beforeInput;
    bytes beforeOutput;
    bytes afterInput;
    uint256 watchedBalance;
  }

  BeforeCall[] internal _beforeCalls;
  AfterCall[] internal _afterCalls;

  CallOrderRecorderMock public immutable RECORDER;
  string internal _tag;

  bytes public beforeExecutionOutput;
  bool public revertOnBefore;
  bool public revertOnAfter;

  address public watchedToken;
  address public watchedAccount;

  constructor(address recorder, string memory tag) {
    RECORDER = CallOrderRecorderMock(recorder);
    _tag = tag;
    beforeExecutionOutput = abi.encode(uint256(0xB4));
  }

  function setBeforeExecutionOutput(bytes calldata output) external {
    beforeExecutionOutput = output;
  }

  function setRevertOnBefore(bool value) external {
    revertOnBefore = value;
  }

  function setRevertOnAfter(bool value) external {
    revertOnAfter = value;
  }

  function setWatched(address token, address account) external {
    watchedToken = token;
    watchedAccount = account;
  }

  /// @inheritdoc IKSActionValidator
  function beforeExecution(bytes32 action, bytes calldata _beforeExecutionInput)
    external
    returns (bytes memory)
  {
    if (revertOnBefore) revert ValidationFailed();

    _beforeCalls.push(
      BeforeCall({
        caller: msg.sender,
        action: action,
        input: _beforeExecutionInput,
        watchedBalance: _watchedBalance()
      })
    );

    if (address(RECORDER) != address(0)) {
      RECORDER.record(string.concat(_tag, ':before'));
    }

    return beforeExecutionOutput;
  }

  /// @inheritdoc IKSActionValidator
  function afterExecution(
    bytes32 action,
    bytes calldata _beforeExecutionInput,
    bytes calldata _beforeExecutionOutput,
    bytes calldata _afterExecutionInput
  ) external {
    if (revertOnAfter) revert ValidationFailed();

    _afterCalls.push(
      AfterCall({
        caller: msg.sender,
        action: action,
        beforeInput: _beforeExecutionInput,
        beforeOutput: _beforeExecutionOutput,
        afterInput: _afterExecutionInput,
        watchedBalance: _watchedBalance()
      })
    );

    if (address(RECORDER) != address(0)) {
      RECORDER.record(string.concat(_tag, ':after'));
    }
  }

  function beforeCallCount() external view returns (uint256) {
    return _beforeCalls.length;
  }

  function afterCallCount() external view returns (uint256) {
    return _afterCalls.length;
  }

  function beforeCallAt(uint256 index) external view returns (BeforeCall memory) {
    return _beforeCalls[index];
  }

  function afterCallAt(uint256 index) external view returns (AfterCall memory) {
    return _afterCalls[index];
  }

  function _watchedBalance() internal view returns (uint256) {
    if (watchedToken == address(0) || watchedAccount == address(0)) return 0;
    return IERC20(watchedToken).balanceOf(watchedAccount);
  }
}
