// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IKSUniversalRouter} from './interfaces/IKSUniversalRouter.sol';

import {RouterParams} from './types/RouterParams.sol';

import {ManagementBase} from 'ks-common-sc/src/base/ManagementBase.sol';
import {ManagementPausable} from 'ks-common-sc/src/base/ManagementPausable.sol';
import {ManagementRescuable} from 'ks-common-sc/src/base/ManagementRescuable.sol';
import {IAllowanceTransfer} from 'ks-common-sc/src/interfaces/IAllowanceTransfer.sol';

import {PermitHelper} from 'ks-common-sc/src/libraries/token/PermitHelper.sol';
import {KSRoles} from 'ks-common-sc/src/libraries/KSRoles.sol';

contract KSUniversalRouter is IKSUniversalRouter, ManagementPausable, ManagementRescuable {
  using PermitHelper for IAllowanceTransfer;

  /// @inheritdoc IKSUniversalRouter
  IAllowanceTransfer public immutable PERMIT2;

  constructor(
    address initialAdmin,
    address[] memory initialGuardians,
    address[] memory initialRescuers,
    address permit2
  ) ManagementBase(0, initialAdmin) {
    _batchGrantRole(KSRoles.GUARDIAN_ROLE, initialGuardians);
    _batchGrantRole(KSRoles.RESCUER_ROLE, initialRescuers);

    PERMIT2 = IAllowanceTransfer(permit2);
  }

  /// @inheritdoc IKSUniversalRouter
  function execute(RouterParams calldata params) external payable returns (bytes[] memory results) {
    /// @dev Calls PERMIT2 if needed
    if (params.permit2Data.length > 0) {
      PERMIT2.callPermit2(msg.sender, params.permit2Data);
    }

    /// @dev Collects the ERC20 tokens
    for (uint256 i = 0; i < params.erc20Params.length; i++) {
      params.erc20Params[i].collect(PERMIT2);
    }

    /// @dev Collects the ERC721 tokens
    for (uint256 i = 0; i < params.erc721Params.length; i++) {
      params.erc721Params[i].collect();
    }

    /// @dev Calls the executors
    results = new bytes[](params.executorCalls.length);
    for (uint256 i = 0; i < params.executorCalls.length; i++) {
      results[i] = params.executorCalls[i].call();
    }
  }
}
