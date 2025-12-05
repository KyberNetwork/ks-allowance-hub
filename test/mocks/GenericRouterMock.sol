// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IGenericRouter} from 'src/interfaces/IGenericRouter.sol';

contract GenericRouterMock is IGenericRouter {
  function execute(bytes calldata data) external payable returns (bytes memory) {
    return data;
  }
}
