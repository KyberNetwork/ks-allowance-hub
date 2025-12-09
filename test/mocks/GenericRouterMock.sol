// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IKSAllowanceHub} from 'src/interfaces/IKSAllowanceHub.sol';
import {IKSGenericRouter} from 'src/interfaces/IKSGenericRouter.sol';

import {TokenHelper} from 'ks-common-sc/src/libraries/token/TokenHelper.sol';

contract GenericRouterMock is IKSGenericRouter {
  using TokenHelper for address;

  error InvalidSender();

  function ksExecute(bytes calldata data) external payable returns (bytes memory) {
    if (data.length == 32 * 3) {
      (address token, uint256 amount, address recipient) =
        abi.decode(data, (address, uint256, address));
      token.safeTransfer(recipient, amount);
    } else if (data.length == 32) {
      address expectedSender = abi.decode(data, (address));
      if (expectedSender != IKSAllowanceHub(msg.sender).msgSender()) {
        revert InvalidSender();
      }
    }
  }
}
