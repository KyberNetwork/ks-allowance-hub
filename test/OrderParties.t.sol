// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {AuthenticatorBase} from 'test/authenticators/base/AuthenticatorBase.sol';

import {IKSAllowanceHubV2} from 'src/interfaces/IKSAllowanceHubV2.sol';
import {
  ITwoTiersOrderAuthenticator
} from 'src/interfaces/authenticators/ITwoTiersOrderAuthenticator.sol';
import {ERC20Allowance} from 'src/types/ERC20Allowance.sol';
import {ERC20Transfer} from 'src/types/ERC20Transfer.sol';
import {ERC721Approval} from 'src/types/ERC721Approval.sol';
import {ERC721Transfer} from 'src/types/ERC721Transfer.sol';
import {ExecutionOrder} from 'src/types/ExecutionOrder.sol';
import {FulfillmentOrder} from 'src/types/FulfillmentOrder.sol';
import {GenericCall} from 'src/types/GenericCall.sol';
import {ValidationParams} from 'src/types/ValidationParams.sol';
import {AuthKey} from 'src/types/base/AuthKey.sol';

import {IERC20} from 'openzeppelin-contracts/contracts/token/ERC20/IERC20.sol';

/**
 * @title OrderPartiesTest
 * @notice ORD-02b..04 — the delegated rails honour the parties the order specifies
 * @dev `relayer` and `solver` say who may submit an order on every rail, not only the Permit2 ones
 * that `ORD-02` and `ORD-03` cover. A credential authenticates the owner; it does not say who may
 * submit the order, so an authenticator that checked nothing of the sort would leave the field
 * unenforced. The last step of each case shows the exemption still holds: the owner is not subject
 * to a field that exists to bound everybody else. `ORD-04` covers the remaining party,
 * the account the order draws on.
 *
 */
contract OrderPartiesTest is AuthenticatorBase {
  uint160 internal constant AMOUNT = 1 ether;

  AuthKey internal key;

  function setUp() public override {
    super.setUp();
    key = _secpKey(masterSigner, vm.getBlockTimestamp() + 30 days);
    _delegateKeyThroughHub(key);
  }

  function _routerWeth() private view returns (uint256) {
    return IERC20(token18).balanceOf(address(router));
  }

  /// ORD-02b — the delegated execution rail refuses a submitter the order did not specify
  function test_ORD_02b_delegatedExecutionHonoursTheNamedRelayer() public {
    ERC20Transfer[] memory erc20s = _erc20s(_tokenTransfer(AMOUNT));
    ERC721Transfer[] memory noNfts = new ERC721Transfer[](0);
    GenericCall[] memory noCalls = new GenericCall[](0);
    uint256 expiration = vm.getBlockTimestamp() + 1 hours;

    ExecutionOrder memory pinned = _executionOrder(relayer, erc20s, noNfts, noCalls, 70, expiration);
    uint256 before = _routerWeth();
    vm.prank(relayer);
    hub.executeOrderWithDelegatedAuthentication(
      pinned, address(authenticator), _executionAuthData(pinned, key, masterKeyPk), false
    );
    assertEq(_routerWeth() - before, AMOUNT, 'the named relayer may submit');

    ExecutionOrder memory again = _executionOrder(relayer, erc20s, noNfts, noCalls, 71, expiration);
    vm.prank(solver);
    vm.expectRevert(abi.encodeWithSelector(IKSAllowanceHubV2.CallerNotRelayer.selector, solver));
    hub.executeOrderWithDelegatedAuthentication(
      again, address(authenticator), _executionAuthData(again, key, masterKeyPk), false
    );

    // The pin is read before the credential, so an unnamed submitter is refused as such even when
    // the credential it presents could never have passed
    ExecutionOrder memory third = _executionOrder(relayer, erc20s, noNfts, noCalls, 72, expiration);
    vm.prank(solver);
    vm.expectRevert(abi.encodeWithSelector(IKSAllowanceHubV2.CallerNotRelayer.selector, solver));
    hub.executeOrderWithDelegatedAuthentication(
      third, address(authenticator), _authData(key, hex'00'), false
    );

    // The same stranger settles an order that specifies no relayer, so the refusals were about the
    // pin
    ExecutionOrder memory open = _openExecutionOrder(erc20s, noCalls, 73, expiration);
    before = _routerWeth();
    vm.prank(solver);
    hub.executeOrderWithDelegatedAuthentication(
      open, address(authenticator), _executionAuthData(open, key, masterKeyPk), false
    );
    assertEq(_routerWeth() - before, AMOUNT, 'the sentinel leaves it open to anyone');

    // The owner is not bound by the field, exactly as on the Permit2 rail
    ExecutionOrder memory byOwner =
      _executionOrder(relayer, erc20s, noNfts, noCalls, 74, expiration);
    before = _routerWeth();
    vm.prank(owner);
    hub.executeOrderWithDelegatedAuthentication(byOwner, address(0), '', false);
    assertEq(_routerWeth() - before, AMOUNT, 'the owner may submit an order naming someone else');
  }

  /**
   * ORD-04 — an order repointed to another owner who approved the same key reverts
   * @dev A key may be approved by more than one account, and the digest carries no second place
   * for the submitter to point it. The two steps are the same signature against the account it
   * specifies and against another that approved the same key.
   */
  function test_ORD_04_delegatedExecutionDrawsOnTheNamedOwner() public {
    address other = makeAddr('other owner');
    deal(token18, other, 100 ether);
    vm.prank(other);
    IERC20(token18).approve(address(hub), type(uint256).max);
    vm.prank(other);
    hub.updateDelegation(
      other, address(authenticator), true, _encodeKey(key), 0, vm.getBlockTimestamp() + 1 days, ''
    );

    ExecutionOrder memory order = _openExecutionOrder(
      _erc20s(_tokenTransfer(AMOUNT)), new GenericCall[](0), 75, vm.getBlockTimestamp() + 1 hours
    );
    bytes memory authData = _executionAuthData(order, key, masterKeyPk);

    // Repointed first, because the refusal rolls back the nonce the authenticator burns ahead of
    // the signature check, leaving the second step the same number to spend
    order.owner = other;
    vm.prank(relayer);
    vm.expectRevert(ITwoTiersOrderAuthenticator.InvalidOrderSignature.selector);
    hub.executeOrderWithDelegatedAuthentication(order, address(authenticator), authData, false);

    order.owner = owner;
    uint256 before = _routerWeth();
    uint256 otherBefore = IERC20(token18).balanceOf(other);
    vm.prank(relayer);
    hub.executeOrderWithDelegatedAuthentication(order, address(authenticator), authData, false);
    assertEq(_routerWeth() - before, AMOUNT, 'the named account paid');
    assertEq(IERC20(token18).balanceOf(other), otherBefore, 'and the other one did not');
  }

  /// ORD-03b — the delegated fulfillment rail refuses a submitter the order did not specify
  function test_ORD_03b_delegatedFulfillmentHonoursTheNamedSolver() public {
    ERC20Allowance[] memory erc20s = _allowances(_tokenAllowance(AMOUNT));
    ERC721Approval[] memory noNfts = new ERC721Approval[](0);
    ValidationParams[] memory noValidators = new ValidationParams[](0);
    GenericCall[] memory noOwnerCalls = new GenericCall[](0);
    uint256 expiration = vm.getBlockTimestamp() + 1 hours;

    FulfillmentOrder memory pinned =
      _fulfillmentOrder(solver, erc20s, noNfts, noValidators, noOwnerCalls, ANY, 80, expiration);
    uint256 before = _routerWeth();
    vm.prank(solver);
    hub.fulfillOrderWithDelegatedAuthentication(
      pinned,
      address(authenticator),
      _fulfillmentAuthData(pinned, key, masterKeyPk),
      _route(pinned, _calls(_routerCall(0, hex'01'))),
      '',
      false
    );
    assertEq(_routerWeth() - before, AMOUNT, 'the named solver may submit');

    FulfillmentOrder memory again =
      _fulfillmentOrder(solver, erc20s, noNfts, noValidators, noOwnerCalls, ANY, 81, expiration);
    vm.prank(relayer);
    vm.expectRevert(abi.encodeWithSelector(IKSAllowanceHubV2.CallerNotSolver.selector, relayer));
    hub.fulfillOrderWithDelegatedAuthentication(
      again,
      address(authenticator),
      _fulfillmentAuthData(again, key, masterKeyPk),
      _route(again, _calls(_routerCall(0, hex'01'))),
      '',
      false
    );

    // As on the execution rail, the pin is read before the credential
    FulfillmentOrder memory third =
      _fulfillmentOrder(solver, erc20s, noNfts, noValidators, noOwnerCalls, ANY, 82, expiration);
    vm.prank(relayer);
    vm.expectRevert(abi.encodeWithSelector(IKSAllowanceHubV2.CallerNotSolver.selector, relayer));
    hub.fulfillOrderWithDelegatedAuthentication(
      third,
      address(authenticator),
      _authData(key, hex'00'),
      _route(third, _calls(_routerCall(0, hex'01'))),
      '',
      false
    );

    FulfillmentOrder memory open =
      _openFulfillmentOrder(erc20s, noValidators, noOwnerCalls, 83, expiration);
    before = _routerWeth();
    vm.prank(relayer);
    hub.fulfillOrderWithDelegatedAuthentication(
      open,
      address(authenticator),
      _fulfillmentAuthData(open, key, masterKeyPk),
      _route(open, _calls(_routerCall(0, hex'01'))),
      '',
      false
    );
    assertEq(_routerWeth() - before, AMOUNT, 'the sentinel leaves it open to anyone');

    FulfillmentOrder memory byOwner =
      _fulfillmentOrder(solver, erc20s, noNfts, noValidators, noOwnerCalls, ANY, 84, expiration);
    before = _routerWeth();
    vm.prank(owner);
    hub.fulfillOrderWithDelegatedAuthentication(
      byOwner, address(0), '', _route(byOwner, _calls(_routerCall(0, hex'01'))), '', false
    );
    assertEq(_routerWeth() - before, AMOUNT, 'the owner may submit an order naming someone else');
  }
}
