// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AuthenticatorBase} from 'test/v2/authenticators/base/AuthenticatorBase.sol';

import {SessionKey} from 'src/v2/authenticators/types/SessionKey.sol';
import {ERC20Transfer} from 'src/v2/types/ERC20Transfer.sol';
import {ERC721Transfer} from 'src/v2/types/ERC721Transfer.sol';
import {ExecutionOrder} from 'src/v2/types/ExecutionOrder.sol';
import {FulfillmentOrder} from 'src/v2/types/FulfillmentOrder.sol';
import {FulfillmentSolution} from 'src/v2/types/FulfillmentSolution.sol';
import {GenericCall} from 'src/v2/types/GenericCall.sol';
import {ValidationParams} from 'src/v2/types/ValidationParams.sol';

import {IERC20} from 'openzeppelin-contracts/contracts/token/ERC20/IERC20.sol';

/**
 * @title NonceNamespaceTest
 * @notice NONCE-06..07 — a nonce belongs to whoever signed the data it guards
 * @dev One contract holds signed data of more than one kind, verified against more than one
 * signer, and each kind carries a number its signer chose. While every kind shared the account the
 * data acted upon, those numbers collided: spending one blocked an unrelated signature that
 * happened to pick the same number. Each case here spends a number in the owner's namespace and
 * then settles data signed by somebody else carrying that same number, which does not compile into
 * anything meaningful unless the namespaces are separate.
 */
contract NonceNamespaceTest is AuthenticatorBase {
  uint160 internal constant AMOUNT = 1 ether;

  SessionKey internal key;

  address internal approver;
  uint256 internal approverKey;

  function setUp() public override {
    super.setUp();
    key = _secpKey(sessionSigner, block.timestamp + 30 days);
    (approver, approverKey) = makeAddrAndKey('solution approver');
  }

  /// NONCE-06 — in the authenticator, the owner's approvals and a session key's orders are separate
  function test_NONCE_06_approvalAndOrderNumbersDoNotCollide() public {
    _delegateKeyThroughHub(key);

    // Spend 7 in the owner's namespace, which is where a relayed session approval would land
    vm.prank(owner);
    authenticator.revokeNonce(7);

    ExecutionOrder memory order = _openExecutionOrder(
      _erc20s(_wethTransfer(AMOUNT)), new GenericCall[](0), 7, block.timestamp + 1 hours
    );

    uint256 before = IERC20(WETH).balanceOf(address(router));
    vm.prank(relayer);
    hub.executeOrderWithDelegatedAuthentication(
      owner, order, address(authenticator), _executionAuthData(order, key, sessionKeyPk), false
    );

    assertEq(
      IERC20(WETH).balanceOf(address(router)) - before,
      AMOUNT,
      'the order settled on a number the owner had already spent'
    );
    assertEq(authenticator.nonces(lNonceKey(owner), 0), 1 << 7, 'the owner spent 7');
    assertEq(authenticator.nonces(_keyHash(key), 0), 1 << 7, 'and the key spent its own 7');
  }

  /// NONCE-07 — in the hub, the owner's delegations and an approver's routes are separate
  function test_NONCE_07_delegationAndRouteNumbersDoNotCollide() public {
    // Spend 9 in the owner's namespace, which is where a relayed delegation would land
    vm.prank(owner);
    hub.revokeNonce(9);

    uint256 deadline = block.timestamp + 1 hours;
    FulfillmentOrder memory order = _fulfillmentOrder(
      ANY,
      _erc20s(_wethTransfer(AMOUNT)),
      new ERC721Transfer[](0),
      new ValidationParams[](0),
      new GenericCall[](0),
      approver,
      9,
      deadline
    );
    FulfillmentSolution memory route = _solution(_calls(_routerCall(0, hex'01')), 9, deadline);
    bytes memory approval =
      _signSolutionApproval(approverKey, owner, lFulfillmentOrderHash(order), route);

    uint256 before = IERC20(WETH).balanceOf(address(router));
    vm.prank(owner);
    hub.fulfillOrderWithDelegatedAuthentication(
      owner, order, address(0), '', route, approval, false
    );

    assertEq(
      IERC20(WETH).balanceOf(address(router)) - before,
      AMOUNT,
      'the route settled on a number the owner had already spent'
    );
    assertEq(hub.nonces(lNonceKey(owner), 0), 1 << 9, 'the owner spent 9');
    assertEq(hub.nonces(lNonceKey(approver), 0), 1 << 9, 'and the approver spent their own 9');
  }
}
