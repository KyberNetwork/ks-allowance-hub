// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AuthenticatorBase} from 'test/v2/authenticators/base/AuthenticatorBase.sol';

import {ReentrantRouterMock} from 'test/v2/mocks/RouterMock.sol';

import {NativeSpendGuard} from 'src/base/NativeSpendGuard.sol';
import {IMsgSender} from 'src/base/interfaces/IMsgSender.sol';

import {IAuthDelegator} from 'src/v2/interfaces/IAuthDelegator.sol';
import {IKSAllowanceHubV2} from 'src/v2/interfaces/IKSAllowanceHubV2.sol';
import {IOrderAuthenticator} from 'src/v2/interfaces/IOrderAuthenticator.sol';
import {ERC20Transfer} from 'src/v2/types/ERC20Transfer.sol';
import {ExecutionOrder} from 'src/v2/types/ExecutionOrder.sol';
import {FulfillmentOrder} from 'src/v2/types/FulfillmentOrder.sol';
import {FulfillmentSolution} from 'src/v2/types/FulfillmentSolution.sol';
import {GenericCall} from 'src/v2/types/GenericCall.sol';
import {ValidationParams} from 'src/v2/types/ValidationParams.sol';

import {IManagementBase} from 'ks-common-sc/src/interfaces/IManagementBase.sol';

import {IAccessControl} from 'openzeppelin-contracts/contracts/access/IAccessControl.sol';
import {IERC20} from 'openzeppelin-contracts/contracts/token/ERC20/IERC20.sol';
import {Pausable} from 'openzeppelin-contracts/contracts/utils/Pausable.sol';

/**
 * @notice Authenticator that only records, so `updateDelegation` can be exercised alone.
 * @dev One counter per entry point. A single counter shared between `initAuthentication` and
 * `updateAuthentication` could not say which of the two a delegation reached, so an assertion on it
 * would hold either way and prove nothing.
 */
contract OrderAuthenticatorMock is IOrderAuthenticator {
  bytes public lastInitData;
  uint256 public initCount;

  bytes public lastUpdateData;
  uint256 public updateCount;

  function initAuthentication(address, bytes calldata data) external {
    lastInitData = data;
    initCount++;
  }

  function updateAuthentication(address, bytes calldata data, uint256, uint256, bytes calldata)
    external
  {
    lastUpdateData = data;
    updateCount++;
  }

  function authenticateExecution(ExecutionOrder calldata, bytes calldata) external {}

  function authenticateFulfillment(FulfillmentOrder calldata, bytes calldata) external {}
}

/**
 * @notice `GUARD-01..06`, `GATE-01`, `MC-01..06` and `MC-FUZZ` — pause, deadline, native spend, the
 * reentrancy lock and the batching surface.
 * @dev Role identifiers are written out rather than imported, so a changed production constant
 * cannot agree with the expectation undetected.
 *
 * The native-spend boundary is derived from {NativeSpendGuard}: the modifier compares
 * `balance + msg.value` against a `balanceBefore` that already contains `msg.value`, which
 * reduces to "revert iff the call spent strictly more than the value it was sent". Reaching the
 * over-spend leg therefore needs the hub to hold native of its own beforehand, or there is
 * nothing left to over-spend.
 *
 * The four entry points carry twenty modifier applications between them. `GUARD-*` takes the
 * execution rail, `GATE-01` takes `fulfillOrderWithPermit2Signature` and `GATE-02` takes the
 * applications neither of those reaches, so every one of the twenty is observed somewhere.
 */
contract GuardsTest is AuthenticatorBase {
  uint160 internal constant AMOUNT = 1 ether;

  bytes32 internal constant GUARDIAN = keccak256('GUARDIAN_ROLE');
  bytes32 internal constant DEFAULT_ADMIN = bytes32(0);
  bytes32 internal constant ROUTER_ROLE = keccak256('WHITELISTED_ROUTER_ROLE');

  /// @dev The float the hub holds before a call, so `msg.value + 1` is payable
  uint256 internal constant PREFUND = 1 ether;
  uint256 internal constant VALUE = 1 ether;

  // -----------------------------------------------------------------------------------------
  // GUARD — pause
  // -----------------------------------------------------------------------------------------

  /// GUARD-01 — `paused()` tracks both transitions, and each one announces itself
  function test_GUARD_01_pauseUnpauseRoundTrip() public {
    assertFalse(hub.paused(), 'starts live');

    vm.expectEmit(true, true, true, true, address(hub));
    emit Pausable.Paused(guardian);
    vm.prank(guardian);
    hub.pause();

    assertTrue(hub.paused(), 'paused');

    vm.expectEmit(true, true, true, true, address(hub));
    emit Pausable.Unpaused(admin);
    vm.prank(admin);
    hub.unpause();

    assertFalse(hub.paused(), 'live again');
  }

  /// GUARD-02 — a pause closes the order entry points but leaves delegation open
  function test_GUARD_02_pauseClosesOrdersNotDelegation() public {
    OrderAuthenticatorMock mock = new OrderAuthenticatorMock();

    ERC20Transfer[] memory erc20s = _erc20s(_wethTransfer(AMOUNT));
    uint256 deadline = block.timestamp + 1 hours;

    ExecutionOrder memory execOrder =
      _openExecutionOrder(erc20s, new GenericCall[](0), 90, deadline);
    bytes memory permitSig = _signExecutionWitness(execOrder);
    FulfillmentOrder memory fulfillOrder =
      _openFulfillmentOrder(erc20s, new ValidationParams[](0), new GenericCall[](0), 0, deadline);

    vm.prank(guardian);
    hub.pause();

    vm.prank(owner);
    vm.expectRevert(Pausable.EnforcedPause.selector);
    hub.executeOrderWithDelegatedAuthentication(execOrder, address(0), '', false);

    vm.prank(relayer);
    vm.expectRevert(Pausable.EnforcedPause.selector);
    hub.executeOrderWithPermit2Signature(execOrder, permitSig);

    vm.prank(owner);
    vm.expectRevert(Pausable.EnforcedPause.selector);
    hub.fulfillOrderWithDelegatedAuthentication(
      fulfillOrder, address(0), '', _route(new GenericCall[](0)), '', false
    );

    // Delegation carries no assets, so the pause does not reach it
    vm.prank(owner);
    hub.updateDelegation(owner, address(mock), true, hex'1234', 0, block.timestamp, '');

    assertTrue(hub.authDelegated(owner, address(mock)), 'delegation still works');
    assertEq(mock.initCount(), 1, 'and reached the authenticator');
    assertEq(mock.lastInitData(), hex'1234', 'carrying the payload the owner gave');
    assertEq(mock.updateCount(), 0, 'over the init path, not the update one');
    assertTrue(hub.paused(), 'the hub is still paused');
  }

  /// GUARD-03 — pausing needs the guardian or the admin, unpausing needs the admin alone
  function test_GUARD_03_pauseRolesAreEnforced() public {
    bytes32[] memory needed = new bytes32[](2);
    needed[0] = GUARDIAN;
    needed[1] = DEFAULT_ADMIN;

    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(IManagementBase.UnauthorizedAccount.selector, relayer, needed)
    );
    hub.pause();

    assertFalse(hub.paused(), 'a stranger changed nothing');

    vm.prank(guardian);
    hub.pause();
    assertTrue(hub.paused(), 'the guardian may pause');

    // The guardian's authority is one-way: lifting a pause is the admin's call
    vm.prank(guardian);
    vm.expectRevert(
      abi.encodeWithSelector(
        IAccessControl.AccessControlUnauthorizedAccount.selector, guardian, DEFAULT_ADMIN
      )
    );
    hub.unpause();

    assertTrue(hub.paused(), 'and the pause survives the attempt');
  }

  // -----------------------------------------------------------------------------------------
  // GUARD — deadline
  // -----------------------------------------------------------------------------------------

  /// GUARD-04 — the deadline block itself still settles; the one before it does not
  function test_GUARD_04_deadlineBoundaryOnTheOrderEntryPoints() public {
    uint256 t = block.timestamp;

    _executeAtDeadline(t - 1, false);
    _executeAtDeadline(t, true);
    _executeAtDeadline(t + 1, true);

    _fulfillAtDeadline(t - 1, false);
    _fulfillAtDeadline(t, true);
    _fulfillAtDeadline(t + 1, true);

    // the Permit2 rail carries the same deadline into the permit, so the hub's own modifier has to
    // be the one that fires: a stale order must not reach Permit2 at all
    ExecutionOrder memory stale =
      _openExecutionOrder(_erc20s(_wethTransfer(AMOUNT)), new GenericCall[](0), 91, t - 1);
    bytes memory staleSig = _signExecutionWitness(stale);

    vm.prank(relayer);
    vm.expectRevert(_deadlinePassed(t - 1));
    hub.executeOrderWithPermit2Signature(stale, staleSig);
  }

  /// GUARD-05 — when both guards would fire, the pause wins, because it is the outer modifier
  function test_GUARD_05_pauseTakesPrecedenceOverTheDeadline() public {
    vm.prank(guardian);
    hub.pause();

    vm.prank(owner);
    vm.expectRevert(Pausable.EnforcedPause.selector);
    hub.executeOrderWithDelegatedAuthentication(
      _openExecutionOrder(
        _erc20s(_wethTransfer(AMOUNT)), new GenericCall[](0), 0, block.timestamp - 1
      ),
      address(0),
      '',
      false
    );

    vm.prank(owner);
    vm.expectRevert(Pausable.EnforcedPause.selector);
    hub.fulfillOrderWithDelegatedAuthentication(
      _openFulfillmentOrder(
        _erc20s(_wethTransfer(AMOUNT)),
        new ValidationParams[](0),
        new GenericCall[](0),
        0,
        block.timestamp - 1
      ),
      address(0),
      '',
      _route(new GenericCall[](0)),
      '',
      false
    );
  }

  // -----------------------------------------------------------------------------------------
  // GUARD — native spend
  // -----------------------------------------------------------------------------------------

  /// GUARD-06 — an order may spend up to the value it was sent, and not one wei more
  function test_GUARD_06_nativeSpendBoundary() public {
    _nativeSpendLeg(VALUE - 1, true);
    _nativeSpendLeg(VALUE, true);
    _nativeSpendLeg(VALUE + 1, false);
  }

  // -----------------------------------------------------------------------------------------
  // GATE-01 — the four modifiers on `fulfillOrderWithPermit2Signature`
  // -----------------------------------------------------------------------------------------

  /**
   * GATE-01 — the fulfillment Permit2 rail is pausable, deadline-checked, locked and native-guarded
   * @dev Four modifiers, one leg each, on the entry point they were added to. The control at the
   * top is what makes the four refusals evidence: the same shape of order settles when none of them
   * fires, so each leg differs from a settling order in exactly the one thing its modifier reads.
   */
  function test_GATE_01_fulfillPermit2CarriesTheFourModifiers() public {
    uint256 deadline = block.timestamp + 1 hours;
    ERC20Transfer[] memory erc20s = _erc20s(_wethTransfer(AMOUNT));

    // control
    uint256 before = IERC20(WETH).balanceOf(address(router));
    FulfillmentOrder memory control =
      _openFulfillmentOrder(erc20s, new ValidationParams[](0), new GenericCall[](0), 100, deadline);
    bytes memory controlSig = _signFulfillmentWitness(control);

    vm.prank(solver);
    hub.fulfillOrderWithPermit2Signature(
      control, controlSig, _route(_calls(_routerCall(0, hex'01'))), ''
    );
    assertEq(IERC20(WETH).balanceOf(address(router)) - before, AMOUNT, 'the control settled');

    // whenNotPaused
    FulfillmentOrder memory paused =
      _openFulfillmentOrder(erc20s, new ValidationParams[](0), new GenericCall[](0), 101, deadline);
    bytes memory pausedSig = _signFulfillmentWitness(paused);

    vm.prank(guardian);
    hub.pause();

    vm.prank(solver);
    vm.expectRevert(Pausable.EnforcedPause.selector);
    hub.fulfillOrderWithPermit2Signature(
      paused, pausedSig, _route(_calls(_routerCall(0, hex'01'))), ''
    );

    vm.prank(admin);
    hub.unpause();

    // checkDeadline
    FulfillmentOrder memory stale = _openFulfillmentOrder(
      erc20s, new ValidationParams[](0), new GenericCall[](0), 102, block.timestamp - 1
    );
    bytes memory staleSig = _signFulfillmentWitness(stale);

    vm.prank(solver);
    vm.expectRevert(_deadlinePassed(block.timestamp - 1));
    hub.fulfillOrderWithPermit2Signature(
      stale, staleSig, _route(_calls(_routerCall(0, hex'01'))), ''
    );

    // lock
    ReentrantRouterMock evil = new ReentrantRouterMock(address(hub));
    vm.prank(admin);
    hub.grantRole(ROUTER_ROLE, address(evil));

    FulfillmentOrder memory locked =
      _openFulfillmentOrder(erc20s, new ValidationParams[](0), new GenericCall[](0), 103, deadline);
    bytes memory lockedSig = _signFulfillmentWitness(locked);
    evil.setReentry(
      abi.encodeCall(
        IKSAllowanceHubV2.executeOrderWithDelegatedAuthentication,
        (
          _openExecutionOrder(new ERC20Transfer[](0), new GenericCall[](0), 0, deadline),
          address(0),
          '',
          false
        )
      )
    );
    FulfillmentSolution memory reentrantRoute =
      _route(_calls(GenericCall({router: address(evil), value: 0, data: hex''})));

    vm.prank(solver);
    vm.expectRevert(IMsgSender.AlreadyLocked.selector);
    hub.fulfillOrderWithPermit2Signature(locked, lockedSig, reentrantRoute, '');

    // guardNativeSpend
    vm.deal(address(hub), PREFUND);
    vm.deal(solver, VALUE);

    FulfillmentOrder memory overSpending =
      _openFulfillmentOrder(erc20s, new ValidationParams[](0), new GenericCall[](0), 104, deadline);
    bytes memory overSpendingSig = _signFulfillmentWitness(overSpending);
    FulfillmentSolution memory greedyRoute = _route(_calls(_routerCall(VALUE + 1, hex'01')));

    vm.prank(solver);
    vm.expectRevert(NativeSpendGuard.NativeOverSpent.selector);
    hub.fulfillOrderWithPermit2Signature{value: VALUE}(
      overSpending, overSpendingSig, greedyRoute, ''
    );

    assertEq(address(hub).balance, PREFUND, "the hub's own float is intact");
  }

  /**
   * GATE-02 — the modifier applications no other case watches
   * @dev One leg each for `guardNativeSpend` on `executeOrderWithPermit2Signature`, and for the
   * lock, the native guard and `checkDelegation` on `fulfillOrderWithDelegatedAuthentication`. Each
   * leg is written so that only its own modifier can produce the result; the lock is observed
   * through what the router saw, because an absent lock leaves `msgSender()` empty rather than
   * reverting.
   */
  function test_GATE_02_theUnwatchedModifierApplications() public {
    uint256 deadline = block.timestamp + 1 hours;
    ERC20Transfer[] memory erc20s = _erc20s(_wethTransfer(AMOUNT));

    // guardNativeSpend on executeOrderWithPermit2Signature
    vm.deal(address(hub), PREFUND);
    vm.deal(relayer, VALUE);

    ExecutionOrder memory greedy = _openExecutionOrder(
      new ERC20Transfer[](0), _calls(_routerCall(VALUE + 1, hex'01')), 110, deadline
    );
    bytes memory greedySig = _signExecutionWitness(greedy);

    vm.prank(relayer);
    vm.expectRevert(NativeSpendGuard.NativeOverSpent.selector);
    hub.executeOrderWithPermit2Signature{value: VALUE}(greedy, greedySig);

    assertEq(address(hub).balance, PREFUND, "the execute rail kept the hub's float");

    // checkDelegation on fulfillOrderWithDelegatedAuthentication
    FulfillmentOrder memory undelegated =
      _openFulfillmentOrder(erc20s, new ValidationParams[](0), new GenericCall[](0), 111, deadline);

    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(
        IAuthDelegator.NotDelegatedAuthenticator.selector, owner, address(authenticator)
      )
    );
    hub.fulfillOrderWithDelegatedAuthentication(
      undelegated, address(authenticator), '', _route(new GenericCall[](0)), '', false
    );

    // guardNativeSpend on fulfillOrderWithDelegatedAuthentication
    vm.deal(address(hub), PREFUND);
    vm.deal(owner, VALUE);

    FulfillmentOrder memory overSpending = _openFulfillmentOrder(
      new ERC20Transfer[](0), new ValidationParams[](0), new GenericCall[](0), 112, deadline
    );

    vm.prank(owner);
    vm.expectRevert(NativeSpendGuard.NativeOverSpent.selector);
    hub.fulfillOrderWithDelegatedAuthentication{value: VALUE}(
      overSpending, address(0), '', _route(_calls(_routerCall(VALUE + 1, hex'01'))), '', false
    );

    assertEq(address(hub).balance, PREFUND, "the fulfill rail kept the hub's float");

    // lock(owner) on fulfillOrderWithDelegatedAuthentication, seen from inside the route
    FulfillmentOrder memory locked =
      _openFulfillmentOrder(erc20s, new ValidationParams[](0), new GenericCall[](0), 113, deadline);

    vm.prank(owner);
    hub.fulfillOrderWithDelegatedAuthentication(
      locked, address(0), '', _route(_calls(_routerCall(0, hex'01'))), '', false
    );

    assertEq(router.seenMsgSender(), owner, 'the route ran under a lock naming the owner');
    assertEq(hub.msgSender(), address(0), 'and the lock was released afterwards');
  }

  function _executeAtDeadline(uint256 deadline, bool shouldSettle) internal {
    uint256 routerBefore = IERC20(WETH).balanceOf(address(router));

    ExecutionOrder memory order =
      _openExecutionOrder(_erc20s(_wethTransfer(AMOUNT)), new GenericCall[](0), 0, deadline);

    vm.prank(owner);
    if (!shouldSettle) vm.expectRevert(_deadlinePassed(deadline));
    hub.executeOrderWithDelegatedAuthentication(order, address(0), '', false);

    assertEq(
      IERC20(WETH).balanceOf(address(router)) - routerBefore,
      shouldSettle ? AMOUNT : 0,
      'the execution rail moved assets only inside the deadline'
    );
  }

  function _fulfillAtDeadline(uint256 deadline, bool shouldSettle) internal {
    uint256 routerBefore = IERC20(WETH).balanceOf(address(router));

    FulfillmentOrder memory order = _openFulfillmentOrder(
      _erc20s(_wethTransfer(AMOUNT)), new ValidationParams[](0), new GenericCall[](0), 0, deadline
    );
    FulfillmentSolution memory route = _route(new GenericCall[](0));

    vm.prank(owner);
    if (!shouldSettle) vm.expectRevert(_deadlinePassed(deadline));
    hub.fulfillOrderWithDelegatedAuthentication(order, address(0), '', route, '', false);

    assertEq(
      IERC20(WETH).balanceOf(address(router)) - routerBefore,
      shouldSettle ? AMOUNT : 0,
      'the fulfillment rail moved assets only inside the deadline'
    );
  }

  function _nativeSpendLeg(uint256 spend, bool shouldSettle) internal {
    vm.deal(address(hub), PREFUND);
    vm.deal(owner, VALUE);

    uint256 routerBefore = address(router).balance;
    GenericCall[] memory calls = _calls(_routerCall(spend, hex'01'));

    ExecutionOrder memory order =
      _openExecutionOrder(new ERC20Transfer[](0), calls, 0, block.timestamp);

    vm.prank(owner);
    if (!shouldSettle) vm.expectRevert(NativeSpendGuard.NativeOverSpent.selector);
    hub.executeOrderWithDelegatedAuthentication{value: VALUE}(order, address(0), '', false);

    if (shouldSettle) {
      assertEq(address(router).balance - routerBefore, spend, 'the router was paid exactly');
      assertEq(address(hub).balance, PREFUND + VALUE - spend, 'the hub kept float plus change');
    } else {
      assertEq(address(router).balance, routerBefore, 'nothing left the hub');
      assertEq(address(hub).balance, PREFUND, 'and its float is intact');
      assertEq(owner.balance, VALUE, 'the value went back to the sender');
    }
  }
}
