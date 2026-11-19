// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {SignerAuthenticatorBase} from 'test/base/SignerAuthenticatorBase.sol';

import {IKSAllowanceHubV2} from 'src/interfaces/IKSAllowanceHubV2.sol';

import {AHV2Order} from 'src/types/AHV2Order.sol';
import {CallParams} from 'src/types/CallParams.sol';
import {HookParams} from 'src/types/HookParams.sol';

/**
 * @title CalldataHygieneTest
 * @notice DIRTY-01..04 — an order hash is taken from unmasked calldata on every settlement path
 * @dev The leaf hashes copy their struct's calldata words without masking them, which is only
 * sound because settling the order reads the same fields through Solidity, and that read rejects a
 * word carrying dirty high bits. These cases hold that: a path that stopped reading the
 * fields, or only needed the digest, would let a dirty payload through and fail here.
 */
contract CalldataHygieneTest is SignerAuthenticatorBase {
  uint160 internal constant AMOUNT = 5 ether;

  /// DIRTY-01 — a dirty token address word is refused for the zero authenticator, owner submitted
  function test_DIRTY_01_delegatedOwnerSubmitted() public {
    AHV2Order memory order = _order(address(0), 90, vm.getBlockTimestamp() + 1 hours);

    _assertDirtyTokenWordIsRefused(
      owner,
      abi.encodeCall(
        IKSAllowanceHubV2.settleOrder,
        (order, '', _route(order, _calls(_calleeCall(0, hex'01'))), '', false)
      )
    );
  }

  /**
   * DIRTY-02 — a dirty token address word is refused for the Permit2 authenticator, witnessed
   * @dev The witness binds the same order members.
   */
  function test_DIRTY_02_permit2Witnessed() public {
    AHV2Order memory order = _order(permit2, 91, vm.getBlockTimestamp() + 1 hours);

    _assertDirtyTokenWordIsRefused(
      relayer,
      abi.encodeCall(
        IKSAllowanceHubV2.settleOrder,
        (order, _signWitness(order), _route(order, _calls(_calleeCall(0, hex'01'))), '', false)
      )
    );
  }

  /// DIRTY-03 — a dirty token address word is refused for a delegated authenticator
  function test_DIRTY_03_delegatedAuthenticated() public {
    _delegateSignerThroughHub(signer);
    AHV2Order memory order = _order(address(authenticator), 92, vm.getBlockTimestamp() + 1 hours);

    _assertDirtyTokenWordIsRefused(
      relayer,
      abi.encodeCall(
        IKSAllowanceHubV2.settleOrder,
        (
          order,
          _orderAuthData(order, signer, signerPk),
          _route(order, _calls(_calleeCall(0, hex'01'))),
          '',
          false
        )
      )
    );
  }

  /// DIRTY-04 — a dirty token address word is refused for the Permit2 authenticator, owner
  /// submitted
  function test_DIRTY_04_permit2OwnerSubmitted() public {
    AHV2Order memory order = _order(permit2, 93, vm.getBlockTimestamp() + 1 hours);

    _assertDirtyTokenWordIsRefused(
      owner,
      abi.encodeCall(
        IKSAllowanceHubV2.settleOrder,
        (
          order,
          _signPlainPermit(order.erc20Allowances, order.nonce, order.expiration),
          _route(order, _calls(_calleeCall(0, hex'02'))),
          '',
          false
        )
      )
    );
  }

  /// @dev The sentinel approver, so no approval signature stands between the settlement and the
  /// hash
  function _order(address orderAuthenticator, uint256 nonce, uint256 expiration)
    internal
    view
    returns (AHV2Order memory)
  {
    return _openAhv2Order(
      orderAuthenticator,
      _allowances(_tokenAllowance(AMOUNT)),
      new HookParams[](0),
      new CallParams[](0),
      nonce,
      expiration
    );
  }
}
