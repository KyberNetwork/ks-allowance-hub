// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IKSGenericRouter} from 'src/interfaces/IKSGenericRouter.sol';

contract GenericRouterMock is IKSGenericRouter {
  function ksExecute(bytes calldata data) external payable returns (bytes memory) {
    return data;
  }
}
