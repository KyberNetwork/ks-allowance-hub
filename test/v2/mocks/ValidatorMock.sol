// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {IKSActionValidator} from 'ks-action-validator-sc/src/interfaces/IKSActionValidator.sol';

import {IERC20} from 'openzeppelin-contracts/contracts/token/ERC20/IERC20.sol';

/// @notice Validator spy: records call order and proves each snapshot comes back to its own validator.
contract ValidatorMock is IKSActionValidator {
  /// @dev Appended to by every hook, so a test can assert the whole sequence in one place
  string[] public sequence;

  bytes32 public beforeAction;
  bytes public beforeInput;
  bytes public afterBeforeOutput;
  bytes public afterInput;

  bytes public snapshot;
  bool public revertOnBefore;
  bool public revertOnAfter;

  /// @dev Lets a test prove WHEN each hook ran, by having the spy read a balance at the time
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

  /// @dev Lets a test give two validators distinguishable outputs
  function setSnapshot(bytes calldata value) external {
    snapshot = value;
  }

  function setReverts(bool onBefore, bool onAfter) external {
    revertOnBefore = onBefore;
    revertOnAfter = onAfter;
  }

  function sequenceLength() external view returns (uint256) {
    return sequence.length;
  }

  function beforeExecution(bytes32 action, bytes calldata input)
    external
    returns (bytes memory output)
  {
    if (revertOnBefore) revert('before');

    sequence.push('before');
    beforeAction = action;
    beforeInput = input;
    if (observing) balanceAtBefore = IERC20(observedToken).balanceOf(observedAccount);

    return snapshot;
  }

  function afterExecution(
    bytes32 action,
    bytes calldata input,
    bytes calldata beforeOutput,
    bytes calldata afterExecutionInput
  ) external {
    if (revertOnAfter) revert('after');

    sequence.push('after');
    if (observing) balanceAtAfter = IERC20(observedToken).balanceOf(observedAccount);
    beforeAction = action;
    beforeInput = input;
    afterBeforeOutput = beforeOutput;
    afterInput = afterExecutionInput;
  }
}
