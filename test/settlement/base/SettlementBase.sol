// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {SignerAuthenticatorBase} from 'test/base/SignerAuthenticatorBase.sol';

import {AHV2Order} from 'src/types/AHV2Order.sol';
import {CallParams} from 'src/types/CallParams.sol';
import {ERC20Allowance} from 'src/types/ERC20Allowance.sol';
import {ERC721Approval} from 'src/types/ERC721Approval.sol';
import {HookParams} from 'src/types/HookParams.sol';

import {IERC20} from 'openzeppelin-contracts/contracts/token/ERC20/IERC20.sol';

/**
 * @title SettlementBase
 * @notice Contract base for the settlement test files: the helpers more than one of them uses
 */
abstract contract SettlementBase is SignerAuthenticatorBase {
  /// @dev An empty list of calls
  function _noCalls() internal pure returns (CallParams[] memory) {
    return new CallParams[](0);
  }

  /// @dev An empty list of hooks
  function _noHooks() internal pure returns (HookParams[] memory) {
    return new HookParams[](0);
  }

  /// @dev An empty list of ERC721 approvals
  function _noNfts() internal pure returns (ERC721Approval[] memory) {
    return new ERC721Approval[](0);
  }

  /// @dev The balance of `token18` held by the callee that receives the transfers
  function _calleeBalance() internal view returns (uint256) {
    return IERC20(token18).balanceOf(address(callee));
  }

  /// @dev The balance of `token18` held by `account`
  function _balance(address account) internal view returns (uint256) {
    return IERC20(token18).balanceOf(account);
  }

  /// @dev Delegates `signer` and returns the authentication data of `order` for a submitter other
  /// than the owner
  function _authOf(AHV2Order memory order) internal returns (bytes memory) {
    _delegateSignerThroughHub(signer);
    return _orderAuthData(order, signer, signerPk);
  }

  /**
   * @dev An order owned by `orderOwner` with no transfers, no hooks and no calls, so it
   * takes the owner path when `orderOwner` submits it
   */
  function _ownedOrder(address orderOwner) internal view returns (AHV2Order memory order) {
    order = _openAhv2Order(
      new ERC20Allowance[](0),
      new HookParams[](0),
      new CallParams[](0),
      0,
      vm.getBlockTimestamp() + 1 hours
    );
    order.owner = orderOwner;
  }
}
