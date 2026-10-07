// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AuthenticatorBase} from 'test/v2/authenticators/base/AuthenticatorBase.sol';

import {SessionKey} from 'src/v2/authenticators/types/SessionKey.sol';
import {IKSAllowanceHubV2} from 'src/v2/interfaces/IKSAllowanceHubV2.sol';
import {ERC20Transfer} from 'src/v2/types/ERC20Transfer.sol';
import {ERC721Transfer} from 'src/v2/types/ERC721Transfer.sol';
import {ExecutionOrder} from 'src/v2/types/ExecutionOrder.sol';
import {FulfillmentOrder} from 'src/v2/types/FulfillmentOrder.sol';
import {GenericCall} from 'src/v2/types/GenericCall.sol';
import {ValidationParams} from 'src/v2/types/ValidationParams.sol';

import {IERC20} from 'openzeppelin-contracts/contracts/token/ERC20/IERC20.sol';

/**
 * @title SubmitterPinningTest
 * @notice ORD-02b..03b — the delegated rails honour the submitter the order names
 * @dev `relayer` and `solver` say who may submit an order on every rail, not only the Permit2 ones
 * that `ORD-02` and `ORD-03` cover. A credential authenticates the owner; it does not say who may
 * carry the order, so an authenticator that checked nothing of the sort would leave the field
 * unenforced. The last leg of each case is what keeps the carve-out honest: the owner is still not
 * subject to a field that exists to bound everybody else.
 *
 * These live in a file of their own because `FulfillOrderTest` produces a solc internal compiler
 * error under `via_ir` when another case joins it.
 */
contract SubmitterPinningTest is AuthenticatorBase {
  uint160 internal constant AMOUNT = 1 ether;

  SessionKey internal key;

  function setUp() public override {
    super.setUp();
    key = _secpKey(sessionSigner, block.timestamp + 30 days);
    _delegateKeyThroughHub(key);
  }

  function _routerWeth() private view returns (uint256) {
    return IERC20(WETH).balanceOf(address(router));
  }

  /// ORD-02b — the delegated execution rail refuses a submitter the order did not name
  function test_ORD_02b_delegatedExecutionHonoursTheNamedRelayer() public {
    ERC20Transfer[] memory erc20s = _erc20s(_wethTransfer(AMOUNT));
    ERC721Transfer[] memory noNfts = new ERC721Transfer[](0);
    GenericCall[] memory noCalls = new GenericCall[](0);
    uint256 deadline = block.timestamp + 1 hours;

    ExecutionOrder memory pinned = _executionOrder(relayer, erc20s, noNfts, noCalls, 70, deadline);
    uint256 before = _routerWeth();
    vm.prank(relayer);
    hub.executeOrderWithDelegatedAuthentication(
      owner, pinned, address(authenticator), _executionAuthData(pinned, key, sessionKeyPk), false
    );
    assertEq(_routerWeth() - before, AMOUNT, 'the named relayer may submit');

    ExecutionOrder memory again = _executionOrder(relayer, erc20s, noNfts, noCalls, 71, deadline);
    vm.prank(solver);
    vm.expectRevert(
      abi.encodeWithSelector(IKSAllowanceHubV2.UnauthorizedRelayer.selector, solver, relayer)
    );
    hub.executeOrderWithDelegatedAuthentication(
      owner, again, address(authenticator), _executionAuthData(again, key, sessionKeyPk), false
    );

    // The pin is read before the credential, so an unnamed submitter is refused as such even when
    // the credential it presents could never have passed
    ExecutionOrder memory third = _executionOrder(relayer, erc20s, noNfts, noCalls, 72, deadline);
    vm.prank(solver);
    vm.expectRevert(
      abi.encodeWithSelector(IKSAllowanceHubV2.UnauthorizedRelayer.selector, solver, relayer)
    );
    hub.executeOrderWithDelegatedAuthentication(
      owner, third, address(authenticator), _authData(key, hex'00'), false
    );

    // The same stranger settles an order that names nobody, so the refusals were about the pin
    ExecutionOrder memory open = _openExecutionOrder(erc20s, noCalls, 73, deadline);
    before = _routerWeth();
    vm.prank(solver);
    hub.executeOrderWithDelegatedAuthentication(
      owner, open, address(authenticator), _executionAuthData(open, key, sessionKeyPk), false
    );
    assertEq(_routerWeth() - before, AMOUNT, 'the sentinel leaves it open to anyone');

    // The owner is not bound by the field, exactly as on the Permit2 rail
    ExecutionOrder memory byOwner = _executionOrder(relayer, erc20s, noNfts, noCalls, 74, deadline);
    before = _routerWeth();
    vm.prank(owner);
    hub.executeOrderWithDelegatedAuthentication(owner, byOwner, address(0), '', false);
    assertEq(_routerWeth() - before, AMOUNT, 'the owner may submit an order naming someone else');
  }

  /// ORD-03b — the delegated fulfillment rail refuses a submitter the order did not name
  function test_ORD_03b_delegatedFulfillmentHonoursTheNamedSolver() public {
    ERC20Transfer[] memory erc20s = _erc20s(_wethTransfer(AMOUNT));
    ERC721Transfer[] memory noNfts = new ERC721Transfer[](0);
    ValidationParams[] memory noValidators = new ValidationParams[](0);
    GenericCall[] memory noOwnerCalls = new GenericCall[](0);
    uint256 deadline = block.timestamp + 1 hours;

    FulfillmentOrder memory pinned =
      _fulfillmentOrder(solver, erc20s, noNfts, noValidators, noOwnerCalls, ANY, 80, deadline);
    uint256 before = _routerWeth();
    vm.prank(solver);
    hub.fulfillOrderWithDelegatedAuthentication(
      owner,
      pinned,
      address(authenticator),
      _fulfillmentAuthData(pinned, key, sessionKeyPk),
      _route(_calls(_routerCall(0, hex'01'))),
      '',
      false
    );
    assertEq(_routerWeth() - before, AMOUNT, 'the named solver may submit');

    FulfillmentOrder memory again =
      _fulfillmentOrder(solver, erc20s, noNfts, noValidators, noOwnerCalls, ANY, 81, deadline);
    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(IKSAllowanceHubV2.UnauthorizedSolver.selector, relayer, solver)
    );
    hub.fulfillOrderWithDelegatedAuthentication(
      owner,
      again,
      address(authenticator),
      _fulfillmentAuthData(again, key, sessionKeyPk),
      _route(_calls(_routerCall(0, hex'01'))),
      '',
      false
    );

    // As on the execution rail, the pin is read before the credential
    FulfillmentOrder memory third =
      _fulfillmentOrder(solver, erc20s, noNfts, noValidators, noOwnerCalls, ANY, 82, deadline);
    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(IKSAllowanceHubV2.UnauthorizedSolver.selector, relayer, solver)
    );
    hub.fulfillOrderWithDelegatedAuthentication(
      owner,
      third,
      address(authenticator),
      _authData(key, hex'00'),
      _route(_calls(_routerCall(0, hex'01'))),
      '',
      false
    );

    FulfillmentOrder memory open =
      _openFulfillmentOrder(erc20s, noValidators, noOwnerCalls, 83, deadline);
    before = _routerWeth();
    vm.prank(relayer);
    hub.fulfillOrderWithDelegatedAuthentication(
      owner,
      open,
      address(authenticator),
      _fulfillmentAuthData(open, key, sessionKeyPk),
      _route(_calls(_routerCall(0, hex'01'))),
      '',
      false
    );
    assertEq(_routerWeth() - before, AMOUNT, 'the sentinel leaves it open to anyone');

    FulfillmentOrder memory byOwner =
      _fulfillmentOrder(solver, erc20s, noNfts, noValidators, noOwnerCalls, ANY, 84, deadline);
    before = _routerWeth();
    vm.prank(owner);
    hub.fulfillOrderWithDelegatedAuthentication(
      owner, byOwner, address(0), '', _route(_calls(_routerCall(0, hex'01'))), '', false
    );
    assertEq(_routerWeth() - before, AMOUNT, 'the owner may submit an order naming someone else');
  }
}
