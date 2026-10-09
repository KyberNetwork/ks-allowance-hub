// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AuthenticatorBase} from 'test/v2/authenticators/base/AuthenticatorBase.sol';

import {AuthKey} from 'src/v2/authenticators/types/AuthKey.sol';
import {IKSAllowanceHubV2} from 'src/v2/interfaces/IKSAllowanceHubV2.sol';
import {ERC721Transfer} from 'src/v2/types/ERC721Transfer.sol';
import {ExecutionOrder} from 'src/v2/types/ExecutionOrder.sol';
import {FulfillmentOrder} from 'src/v2/types/FulfillmentOrder.sol';
import {GenericCall} from 'src/v2/types/GenericCall.sol';
import {ValidationParams} from 'src/v2/types/ValidationParams.sol';

/**
 * @title CalldataHygieneTest
 * @notice DIRTY-01..04 — an order hash is taken from unmasked calldata on every rail
 * @dev The leaf hashes copy their struct's calldata words without masking them, which is only
 * sound because settling the order reads the same fields through Solidity, and that read rejects a
 * word carrying dirty high bits. These cases hold that: a rail that stopped reading the fields, or
 * only needed the digest, would let a dirty payload through and fail here.
 */
contract CalldataHygieneTest is AuthenticatorBase {
  uint160 internal constant AMOUNT = 5 ether;

  AuthKey internal key;

  function setUp() public override {
    super.setUp();
    key = _secpKey(masterSigner, block.timestamp + 30 days);
  }

  /// DIRTY-01 — the delegated execution rail
  function test_DIRTY_01_delegatedExecution() public {
    _assertDirtyTokenWordIsRefused(
      owner,
      abi.encodeCall(
        IKSAllowanceHubV2.executeOrderWithDelegatedAuthentication,
        (
          _openExecutionOrder(
            _erc20s(_tokenTransfer(AMOUNT)), _calls(_routerCall(0, hex'01')), 90, block.timestamp
          ),
          address(0),
          '',
          false
        )
      )
    );
  }

  /// DIRTY-02 — the Permit2-signature execution rail, where the witness binds the same transfers
  function test_DIRTY_02_permit2Execution() public {
    uint256 deadline = block.timestamp + 1 hours;
    ExecutionOrder memory order = _executionOrder(
      ANY,
      _erc20s(_tokenTransfer(AMOUNT)),
      new ERC721Transfer[](0),
      _calls(_routerCall(0, hex'01')),
      91,
      deadline
    );

    _assertDirtyTokenWordIsRefused(
      relayer,
      abi.encodeCall(
        IKSAllowanceHubV2.executeOrderWithPermit2Signature, (order, _signExecutionWitness(order))
      )
    );
  }

  /// DIRTY-03 — the delegated fulfillment rail
  function test_DIRTY_03_delegatedFulfillment() public {
    _delegateKeyThroughHub(key);
    uint256 deadline = block.timestamp + 1 hours;
    FulfillmentOrder memory order = _order(92, deadline);

    _assertDirtyTokenWordIsRefused(
      relayer,
      abi.encodeCall(
        IKSAllowanceHubV2.fulfillOrderWithDelegatedAuthentication,
        (
          order,
          address(authenticator),
          _fulfillmentAuthData(order, key, masterKeyPk),
          _solution(_calls(_routerCall(0, hex'01')), 1, deadline),
          '',
          false
        )
      )
    );
  }

  /// DIRTY-04 — the Permit2-signature fulfillment rail
  function test_DIRTY_04_permit2Fulfillment() public {
    uint256 deadline = block.timestamp + 1 hours;
    FulfillmentOrder memory order = _order(93, deadline);

    _assertDirtyTokenWordIsRefused(
      owner,
      abi.encodeCall(
        IKSAllowanceHubV2.fulfillOrderWithPermit2Signature,
        (
          order,
          _signPlainPermit(_erc20s(_tokenTransfer(AMOUNT)), 93, deadline),
          _solution(_calls(_routerCall(0, hex'02')), 2, deadline),
          ''
        )
      )
    );
  }

  /// @dev The sentinel approver, so no approval signature stands between the rail and the hash
  function _order(uint256 nonce, uint256 deadline) internal view returns (FulfillmentOrder memory) {
    return _fulfillmentOrder(
      ANY,
      _erc20s(_tokenTransfer(AMOUNT)),
      new ERC721Transfer[](0),
      new ValidationParams[](0),
      new GenericCall[](0),
      ANY,
      nonce,
      deadline
    );
  }
}
