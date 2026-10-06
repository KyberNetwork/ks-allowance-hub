// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AuthenticatorBase} from 'test/v2/authenticators/base/AuthenticatorBase.sol';

import {ReentrantRouterMock, RouterMock} from 'test/v2/mocks/RouterMock.sol';

import {
  ISessionOrderAuthenticator
} from 'src/v2/authenticators/interfaces/ISessionOrderAuthenticator.sol';
import {SessionKey} from 'src/v2/authenticators/types/SessionKey.sol';

import {NativeSpendGuard} from 'src/base/NativeSpendGuard.sol';
import {IMsgSender} from 'src/base/interfaces/IMsgSender.sol';
import {IUnorderedNonce} from 'src/base/interfaces/IUnorderedNonce.sol';
import {PackedBits} from 'src/base/types/PackedBits.sol';

import {IAuthDelegator} from 'src/v2/interfaces/IAuthDelegator.sol';
import {ICallsForwarder} from 'src/v2/interfaces/ICallsForwarder.sol';
import {IKSAllowanceHubV2} from 'src/v2/interfaces/IKSAllowanceHubV2.sol';
import {IOrderAuthenticator} from 'src/v2/interfaces/IOrderAuthenticator.sol';
import {ERC20Transfer} from 'src/v2/types/ERC20Transfer.sol';
import {ERC721Transfer} from 'src/v2/types/ERC721Transfer.sol';
import {ExecutionOrder} from 'src/v2/types/ExecutionOrder.sol';
import {FulfillmentOrder} from 'src/v2/types/FulfillmentOrder.sol';
import {FulfillmentSolution} from 'src/v2/types/FulfillmentSolution.sol';
import {GenericCall} from 'src/v2/types/GenericCall.sol';
import {ValidationParams} from 'src/v2/types/ValidationParams.sol';

import {IManagementBase} from 'ks-common-sc/src/interfaces/IManagementBase.sol';

import {IAccessControl} from 'openzeppelin-contracts/contracts/access/IAccessControl.sol';
import {IERC20} from 'openzeppelin-contracts/contracts/token/ERC20/IERC20.sol';
import {
  IERC20Permit
} from 'openzeppelin-contracts/contracts/token/ERC20/extensions/IERC20Permit.sol';
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

  function authenticateExecution(address, ExecutionOrder calldata, bytes calldata) external {}

  function authenticateFulfillment(address, FulfillmentOrder calldata, bytes calldata) external {}
}

/**
 * @notice `GUARD-01..06`, `GATE-01`, `MC-01..06` and `MC-FUZZ` — pause, deadline, native spend, the
 * reentrancy lock and the batching surface.
 * @dev Role identifiers are written out rather than imported, so a changed production constant
 * cannot quietly agree with the expectation.
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

  /// @dev Transcribed from {IOrderAuthenticator}: the allowlist entry MC-06 relays
  string internal constant S_UPDATE_AUTHENTICATION =
    'updateAuthentication(address,bytes,uint256,uint256,bytes)';

  bytes32 internal constant GUARDIAN = keccak256('GUARDIAN_ROLE');
  bytes32 internal constant DEFAULT_ADMIN = bytes32(0);
  bytes32 internal constant ROUTER_ROLE = keccak256('WHITELISTED_ROUTER_ROLE');

  /// @dev The float the hub holds before a call, so `msg.value + 1` is actually payable
  uint256 internal constant PREFUND = 1 ether;
  uint256 internal constant VALUE = 1 ether;

  /// @dev EIP-2612, transcribed rather than imported from any token or helper
  bytes32 internal constant L_PERMIT_TYPEHASH =
    keccak256('Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)');

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
    hub.executeOrderWithDelegatedAuthentication(owner, execOrder, address(0), '', false);

    vm.prank(relayer);
    vm.expectRevert(Pausable.EnforcedPause.selector);
    hub.executeOrderWithPermit2Signature(owner, execOrder, permitSig);

    vm.prank(owner);
    vm.expectRevert(Pausable.EnforcedPause.selector);
    hub.fulfillOrderWithDelegatedAuthentication(
      owner, fulfillOrder, address(0), '', _route(new GenericCall[](0)), '', false
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
    hub.executeOrderWithPermit2Signature(owner, stale, staleSig);
  }

  /// GUARD-05 — when both guards would fire, the pause wins, because it is the outer modifier
  function test_GUARD_05_pauseTakesPrecedenceOverTheDeadline() public {
    vm.prank(guardian);
    hub.pause();

    vm.prank(owner);
    vm.expectRevert(Pausable.EnforcedPause.selector);
    hub.executeOrderWithDelegatedAuthentication(
      owner,
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
      owner,
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
   * @dev Four modifiers, one leg each, on the entry point they were added to. The control at the top
   * is what makes the four refusals evidence: the same shape of order settles when none of them
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
      owner, control, controlSig, _route(_calls(_routerCall(0, hex'01'))), ''
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
      owner, paused, pausedSig, _route(_calls(_routerCall(0, hex'01'))), ''
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
      owner, stale, staleSig, _route(_calls(_routerCall(0, hex'01'))), ''
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
          owner,
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
    hub.fulfillOrderWithPermit2Signature(owner, locked, lockedSig, reentrantRoute, '');

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
      owner, overSpending, overSpendingSig, greedyRoute, ''
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
    hub.executeOrderWithPermit2Signature{value: VALUE}(owner, greedy, greedySig);

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
      owner, undelegated, address(authenticator), '', _route(new GenericCall[](0)), '', false
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
      owner,
      overSpending,
      address(0),
      '',
      _route(_calls(_routerCall(VALUE + 1, hex'01'))),
      '',
      false
    );

    assertEq(address(hub).balance, PREFUND, "the fulfill rail kept the hub's float");

    // lock(owner) on fulfillOrderWithDelegatedAuthentication, seen from inside the route
    FulfillmentOrder memory locked =
      _openFulfillmentOrder(erc20s, new ValidationParams[](0), new GenericCall[](0), 113, deadline);

    vm.prank(owner);
    hub.fulfillOrderWithDelegatedAuthentication(
      owner, locked, address(0), '', _route(_calls(_routerCall(0, hex'01'))), '', false
    );

    assertEq(router.seenMsgSender(), owner, 'the route ran under a lock naming the owner');
    assertEq(hub.msgSender(), address(0), 'and the lock was released afterwards');
  }

  // -----------------------------------------------------------------------------------------
  // MC — the batching surface
  // -----------------------------------------------------------------------------------------

  /// MC-01 — a permit and the order that uses the approval share one transaction, with value
  function test_MC_01_permitAndOrderInOneBatch() public {
    uint256 permitValue = 1234e6;
    uint256 deadline = block.timestamp + 1 hours;

    address[] memory tokens = new address[](1);
    tokens[0] = USDC;
    bytes[] memory permits = new bytes[](1);
    permits[0] = _usdcPermitCall(address(hub), permitValue, deadline);

    ERC20Transfer[] memory erc20s = _erc20s(_wethTransfer(AMOUNT));
    GenericCall[] memory calls = _calls(_routerCall(0.5 ether, hex'01'));

    bytes[] memory batch = new bytes[](2);
    batch[0] =
      abi.encodeCall(ICallsForwarder.forwardCalls, (tokens, permits, PackedBits.wrap(bytes32(0))));
    batch[1] = abi.encodeCall(
      IKSAllowanceHubV2.executeOrderWithDelegatedAuthentication,
      (owner, _openExecutionOrder(erc20s, calls, 0, deadline), address(0), '', false)
    );

    uint256 routerWethBefore = IERC20(WETH).balanceOf(address(router));
    uint256 routerNativeBefore = address(router).balance;
    vm.deal(owner, VALUE);

    vm.prank(owner);
    (bytes[] memory results, uint256[] memory gasUsages) = hub.multicall{value: VALUE}(batch);

    assertEq(results.length, 2, 'one result per sub-call');
    assertEq(IERC20(USDC).allowance(owner, address(hub)), permitValue, 'the permit was relayed');
    assertEq(
      IERC20(WETH).balanceOf(address(router)) - routerWethBefore, AMOUNT, 'the order settled'
    );
    assertEq(address(router).balance - routerNativeBefore, 0.5 ether, 'the native leg was paid');
    assertEq(address(hub).balance, VALUE - 0.5 ether, 'the unspent half stayed behind');

    bytes[] memory inner = abi.decode(results[1], (bytes[]));
    assertEq(inner.length, 1, 'the order reported its own call');
    assertEq(gasUsages.length, 2, 'one gas figure per sub-call');
    assertGt(gasUsages[1], 0, 'and the order reported the gas it spent');
  }

  /// MC-02 — each sub-call may spend the value, but the batch as a whole may not spend it twice
  function test_MC_02_batchIsBoundedAsAWhole() public {
    vm.deal(address(hub), 2 * VALUE);
    vm.deal(owner, VALUE);

    GenericCall[] memory calls = _calls(_routerCall(VALUE, hex'01'));
    bytes memory order = abi.encodeCall(
      IKSAllowanceHubV2.executeOrderWithDelegatedAuthentication,
      (
        owner,
        _openExecutionOrder(new ERC20Transfer[](0), calls, 0, block.timestamp),
        address(0),
        '',
        false
      )
    );

    bytes[] memory batch = new bytes[](2);
    batch[0] = order;
    batch[1] = order;

    uint256 routerBefore = address(router).balance;

    vm.prank(owner);
    vm.expectRevert(NativeSpendGuard.NativeOverSpent.selector);
    hub.multicall{value: VALUE}(batch);

    assertEq(address(hub).balance, 2 * VALUE, "the hub's own float is untouched");
    assertEq(address(router).balance, routerBefore, 'and the router was paid nothing');
    assertEq(router.callCount(), 0, 'the whole batch rolled back');
  }

  /// MC-03 — a sub-call's revert arrives at the caller with its arguments intact
  function test_MC_03_subCallRevertBubbles() public {
    RouterMock stranger = new RouterMock();

    GenericCall[] memory calls =
      _calls(GenericCall({router: address(stranger), value: 0, data: hex'01'}));

    bytes[] memory batch = new bytes[](1);
    batch[0] = abi.encodeCall(
      IKSAllowanceHubV2.executeOrderWithDelegatedAuthentication,
      (
        owner,
        _openExecutionOrder(new ERC20Transfer[](0), calls, 0, block.timestamp),
        address(0),
        '',
        false
      )
    );

    vm.prank(owner);
    vm.expectRevert(
      abi.encodeWithSelector(
        IAccessControl.AccessControlUnauthorizedAccount.selector, address(stranger), ROUTER_ROLE
      )
    );
    hub.multicall(batch);
  }

  /// MC-04 — two independent orders in one batch both settle, in the order given
  function test_MC_04_twoOrdersInOneBatch() public {
    bytes[] memory batch = new bytes[](2);
    batch[0] = _orderCalldata(1 ether, hex'a1');
    batch[1] = _orderCalldata(2 ether, hex'b2');

    uint256 routerWethBefore = IERC20(WETH).balanceOf(address(router));

    vm.prank(owner);
    (bytes[] memory results,) = hub.multicall(batch);

    assertEq(results.length, 2, 'two results');
    assertEq(
      IERC20(WETH).balanceOf(address(router)) - routerWethBefore, 3 ether, 'both legs pulled'
    );
    assertEq(router.callCount(), 2, 'both calls ran');
    assertEq(router.lastData(), hex'b2', 'the second order ran last');

    bytes[] memory innerFirst = abi.decode(results[0], (bytes[]));
    bytes[] memory innerSecond = abi.decode(results[1], (bytes[]));
    assertEq(abi.decode(innerFirst[0], (uint256)), 1, 'first sub-call saw the first router call');
    assertEq(abi.decode(innerSecond[0], (uint256)), 2, 'and the second saw the second');
  }

  /**
   * MC-07 — each entry is measured on its own, not given a running total of the batch
   * @dev The same two entries are run in both orders, and the order-settling one has to be the
   * dearer of the two either way. That is what separates a per-entry figure from a cumulative one:
   * a running total only ever grows, so it reports the *second* entry as dearer whichever entry it
   * is, and the reversed arrangement catches it. Cold-storage costs fall on whichever entry runs
   * first, so they work against the assertion in one arrangement and for it in the other. An empty
   * `forwardCalls` is the cheap entry — it runs no sub-call at all.
   */
  function test_MC_07_gasIsMeasuredPerEntry() public {
    bytes memory cheap = abi.encodeCall(
      ICallsForwarder.forwardCalls, (new address[](0), new bytes[](0), PackedBits.wrap(bytes32(0)))
    );

    bytes[] memory cheapFirst = new bytes[](2);
    cheapFirst[0] = cheap;
    cheapFirst[1] = _orderCalldata(1 ether, hex'c1');

    uint256 available = gasleft();

    vm.prank(owner);
    (bytes[] memory results, uint256[] memory gasUsages) = hub.multicall(cheapFirst);

    assertEq(results.length, 2, 'one result per entry');
    assertEq(gasUsages.length, 2, 'and one gas figure per entry');
    assertGt(gasUsages[0], 0, 'even the empty entry costs something');
    assertGt(gasUsages[1], gasUsages[0], 'the entry that settled an order cost more');
    assertLt(gasUsages[0] + gasUsages[1], available, 'never more than the caller had left');

    bytes[] memory orderFirst = new bytes[](2);
    orderFirst[0] = _orderCalldata(1 ether, hex'c2');
    orderFirst[1] = cheap;

    vm.prank(owner);
    (, uint256[] memory reversed) = hub.multicall(orderFirst);

    assertGt(reversed[0], reversed[1], 'and still cost more when it ran first');
  }

  /// MC-05 — the hub has no `receive`, so a bare transfer cannot strand native in it
  function test_MC_05_plainNativeTransferIsRefused() public {
    vm.deal(owner, 1);

    vm.prank(owner);
    (bool ok,) = address(hub).call{value: 1}('');

    assertFalse(ok, 'there is nothing to receive it');
    assertEq(address(hub).balance, 0, 'the hub holds nothing');
    assertEq(owner.balance, 1, 'and the wei stayed with the sender');
  }

  /**
   * MC-06 — one batch approves a session key at an authenticator and then spends on it
   * @dev The capability the refactor exists for, end to end. The relayer submits both halves and
   * signs neither: `forwardCalls` relays the owner's `updateAuthentication` — the authenticator sees the
   * hub as `msg.sender`, so the owner's own approval signature is what authorises it — and the order
   * in the next slot settles on the key that call has just approved, over the delegated rail, with
   * the session key signing rather than the wallet. Nothing outside the batch approves the key,
   * which the pre-state assertion fixes; the delegation put in place beforehand carries no key of
   * its own, so the hub's gate is open while the authenticator still knows nothing.
   */
  function test_MC_06_approveASessionKeyAndSpendOnItInOneBatch() public {
    SessionKey memory key = _secpKey(sessionSigner, block.timestamp + 30 days);
    bytes32 keyHash = _keyHash(key);

    uint256 deadline = block.timestamp + 1 hours;
    uint256 approvalNonce = 70;
    uint256 orderNonce = 71;

    vm.prank(owner);
    hub.updateDelegation(owner, address(authenticator), true, '', 0, deadline, '');
    assertFalse(authenticator.approvedKeys(owner, keyHash), 'the authenticator holds no key yet');

    ERC20Transfer[] memory erc20s = _erc20s(_wethTransfer(AMOUNT));
    GenericCall[] memory calls = _calls(_routerCall(0, hex'01'));

    ExecutionOrder memory order = _openExecutionOrder(erc20s, calls, orderNonce, deadline);
    bytes memory approvalSig = _signSessionApproval(key, true, approvalNonce, deadline);
    bytes memory orderAuth = _executionAuthData(order, key, sessionKeyPk);

    address[] memory targets = new address[](1);
    targets[0] = address(authenticator);

    bytes[] memory relayed = new bytes[](1);
    relayed[0] = abi.encodeWithSignature(
      S_UPDATE_AUTHENTICATION, owner, _approveKey(key), approvalNonce, deadline, approvalSig
    );

    bytes[] memory batch = new bytes[](2);
    batch[0] =
      abi.encodeCall(ICallsForwarder.forwardCalls, (targets, relayed, PackedBits.wrap(bytes32(0))));
    batch[1] = abi.encodeCall(
      IKSAllowanceHubV2.executeOrderWithDelegatedAuthentication,
      (owner, order, address(authenticator), orderAuth, false)
    );

    // the second half on its own is refused, so the batch below is evidence that the first half
    // did the approving rather than that the order never needed one
    bytes[] memory orderOnly = new bytes[](1);
    orderOnly[0] = batch[1];

    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(ISessionOrderAuthenticator.SessionKeyNotApproved.selector, owner, key)
    );
    hub.multicall(orderOnly);

    uint256 routerWethBefore = IERC20(WETH).balanceOf(address(router));

    vm.prank(relayer);
    (bytes[] memory results,) = hub.multicall(batch);

    assertEq(results.length, 2, 'one result per sub-call');
    assertTrue(authenticator.approvedKeys(owner, keyHash), 'the batch approved the key');
    assertEq(
      IERC20(WETH).balanceOf(address(router)) - routerWethBefore,
      AMOUNT,
      'and the order spent on it in the same transaction'
    );
    assertEq(router.callCount(), 1, 'the router leg ran once');
    assertEq(router.seenMsgSender(), owner, 'for the owner, not for the relayer who submitted');
    assertEq(
      authenticator.nonces(owner, 0),
      (1 << approvalNonce) | (1 << orderNonce),
      'one authenticator nonce for the approval and one for the order'
    );
    assertEq(hub.nonces(owner, 0), 0, 'and the hub burned none of its own');
  }

  struct BatchFuzz {
    uint8 itemCount;
    uint96 msgValue;
    uint8 payableMask;
  }

  /**
   * MC-FUZZ — value survives a batch exactly when every selector in it is payable
   * @dev Every sub-call is a `delegatecall`, so each one sees the outer `msg.value`; a
   * non-payable selector therefore rejects the whole batch on its own dispatcher check.
   */
  function testFuzz_MC_FUZZ_valueNeedsAnAllPayableBatch(BatchFuzz memory f) public {
    uint256 count = bound(f.itemCount, 1, 5);
    uint256 value = bound(f.msgValue, 0, 1 ether);

    bytes[] memory batch = new bytes[](count);
    bool allPayable = true;
    uint256 expectedBitmap;

    for (uint256 i = 0; i < count; i++) {
      if (_isPayableItem(f.payableMask, i)) {
        // `revokeNonce` is payable and leaves a bit behind, so the run is observable
        batch[i] = abi.encodeCall(IUnorderedNonce.revokeNonce, (i));
        expectedBitmap |= 1 << i;
      } else {
        allPayable = false;
        batch[i] = abi.encodeWithSignature('paused()');
      }
    }

    vm.deal(owner, value);

    if (value > 0 && !allPayable) {
      // The non-payable guard reverts with no data and `multicall` bubbles what it was handed, so
      // the batch surfaces an empty revert. `bytes('')` matches that and nothing carrying data
      vm.prank(owner);
      vm.expectRevert(bytes(''));
      hub.multicall{value: value}(batch);

      assertEq(hub.nonces(owner, 0), 0, 'the whole batch rolled back');
      assertEq(address(hub).balance, 0, 'and none of the value stuck');
      assertEq(owner.balance, value, 'which is back with the sender');
      return;
    }

    vm.prank(owner);
    (bytes[] memory results,) = hub.multicall{value: value}(batch);

    assertEq(results.length, count, 'one result per sub-call');
    for (uint256 i = 0; i < count; i++) {
      if (_isPayableItem(f.payableMask, i)) {
        assertEq(results[i].length, 0, 'revokeNonce returns nothing');
      } else {
        assertEq(results[i], abi.encode(false), 'paused() returns false');
      }
    }

    assertEq(hub.nonces(owner, 0), expectedBitmap, 'exactly the payable indices burned a nonce');
    assertEq(address(hub).balance, value, 'a payable batch keeps whatever it did not spend');
  }

  // -----------------------------------------------------------------------------------------
  // Helpers
  // -----------------------------------------------------------------------------------------

  function _isPayableItem(uint8 mask, uint256 index) internal pure returns (bool) {
    return (uint256(mask) >> index) & 1 == 1;
  }

  function _orderCalldata(uint160 amount, bytes memory data) internal view returns (bytes memory) {
    return abi.encodeCall(
      IKSAllowanceHubV2.executeOrderWithDelegatedAuthentication,
      (
        owner,
        _openExecutionOrder(
          _erc20s(_wethTransfer(amount)), _calls(_routerCall(0, data)), 0, block.timestamp
        ),
        address(0),
        '',
        false
      )
    );
  }

  function _executeAtDeadline(uint256 deadline, bool shouldSettle) internal {
    uint256 routerBefore = IERC20(WETH).balanceOf(address(router));

    ExecutionOrder memory order =
      _openExecutionOrder(_erc20s(_wethTransfer(AMOUNT)), new GenericCall[](0), 0, deadline);

    vm.prank(owner);
    if (!shouldSettle) vm.expectRevert(_deadlinePassed(deadline));
    hub.executeOrderWithDelegatedAuthentication(owner, order, address(0), '', false);

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
    hub.fulfillOrderWithDelegatedAuthentication(owner, order, address(0), '', route, '', false);

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
    hub.executeOrderWithDelegatedAuthentication{value: VALUE}(owner, order, address(0), '', false);

    if (shouldSettle) {
      assertEq(address(router).balance - routerBefore, spend, 'the router was paid exactly');
      assertEq(address(hub).balance, PREFUND + VALUE - spend, 'the hub kept float plus change');
    } else {
      assertEq(address(router).balance, routerBefore, 'nothing left the hub');
      assertEq(address(hub).balance, PREFUND, 'and its float is intact');
      assertEq(owner.balance, VALUE, 'the value went back to the sender');
    }
  }

  /// @dev A whole EIP-2612 `permit` call for {ICallsForwarder-forwardCalls} to relay to USDC
  function _usdcPermitCall(address spender, uint256 value, uint256 deadline)
    internal
    returns (bytes memory)
  {
    bytes32 structHash = keccak256(
      abi.encode(L_PERMIT_TYPEHASH, owner, spender, value, _usdcNonce(owner), deadline)
    );
    (uint8 v, bytes32 r, bytes32 s) =
      vm.sign(ownerKey, lTypedDataHash(_usdcDomainSeparator(), structHash));

    return abi.encodeCall(IERC20Permit.permit, (owner, spender, value, deadline, v, r, s));
  }

  /// @dev Read off the deployed token, which is an external dependency rather than code under test
  function _usdcDomainSeparator() internal view returns (bytes32) {
    (bool ok, bytes memory data) = USDC.staticcall(abi.encodeWithSignature('DOMAIN_SEPARATOR()'));
    require(ok, 'usdc domain');
    return abi.decode(data, (bytes32));
  }

  function _usdcNonce(address account) internal view returns (uint256) {
    (bool ok, bytes memory data) =
      USDC.staticcall(abi.encodeWithSignature('nonces(address)', account));
    require(ok, 'usdc nonce');
    return abi.decode(data, (uint256));
  }
}
