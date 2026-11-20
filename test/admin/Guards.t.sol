// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {SignerAuthenticatorBase} from 'test/base/SignerAuthenticatorBase.sol';

import {IAHV2Authenticator} from 'src/interfaces/base/IAHV2Authenticator.sol';
import {IAuthDelegator} from 'src/interfaces/base/IAuthDelegator.sol';

import {NativeSpendGuard} from 'src/base/NativeSpendGuard.sol';

import {AHV2Order} from 'src/types/AHV2Order.sol';
import {AHV2Solution} from 'src/types/AHV2Solution.sol';
import {CallParams} from 'src/types/CallParams.sol';
import {ERC20Allowance} from 'src/types/ERC20Allowance.sol';

import {IManagementSimple} from 'ks-common-sc/src/interfaces/IManagementSimple.sol';

import {IAccessControl} from 'openzeppelin-contracts/contracts/access/IAccessControl.sol';
import {Pausable} from 'openzeppelin-contracts/contracts/utils/Pausable.sol';

/**
 * @notice Authenticator that only records, so `updateDelegation` can be exercised alone.
 * @dev One counter per entry point. A single counter shared between `initAuthentication` and
 * `updateAuthentication` could not say which of the two a delegation reached, so an assertion on it
 * would hold either way and prove nothing.
 */
contract AHV2AuthenticatorStub is IAHV2Authenticator {
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

  function authenticate(AHV2Order calldata, bytes32, AHV2Solution calldata, bytes calldata)
    external {}
}

/**
 * @notice `GUARD-01..06`, `GATE-01..02` — pause, expiration and native spend.
 * @dev Role identifiers are written out rather than imported, so a changed production constant
 * cannot agree with the expectation undetected.
 *
 * The native-spend boundary is derived from {NativeSpendGuard}: the modifier compares
 * `balance + msg.value` against a `balanceBefore` that already contains `msg.value`, which
 * reduces to "revert iff the call spent strictly more than the value it was sent". Reaching the
 * over-spend step therefore needs the hub to hold native of its own beforehand, or there is
 * nothing left to over-spend.
 *
 * `settleOrder` carries three modifiers and the inline delegation check. `GUARD-*` takes the
 * owner-submitted path, `GATE-01` takes the Permit2 path and `GATE-02` takes the guards neither of
 * those reaches. `NEST-03` of {NestingTest} observes `setMsgSender`.
 */
contract GuardsTest is SignerAuthenticatorBase {
  uint160 internal constant AMOUNT = 1 ether;

  bytes32 internal constant GUARDIAN = keccak256('GUARDIAN_ROLE');
  bytes32 internal constant DEFAULT_ADMIN = bytes32(0);

  /// @dev The native balance the hub holds before a call, so `msg.value + 1` is payable
  uint256 internal constant PREFUND = 1 ether;
  uint256 internal constant VALUE = 1 ether;

  // -----------------------------------------------------------------------------------------
  // GUARD — pause
  // -----------------------------------------------------------------------------------------

  /// GUARD-01 — pause and unpause set `paused()` and emit `Paused` and `Unpaused`
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

  /// GUARD-02 — a pause closes both settlement paths but leaves delegation open
  function test_GUARD_02_pauseClosesOrdersNotDelegation() public {
    AHV2AuthenticatorStub mock = new AHV2AuthenticatorStub();

    AHV2Order memory order = _openOrder(90, vm.getBlockTimestamp() + 1 hours);
    AHV2Order memory permitOrder = _permit2Order(90, vm.getBlockTimestamp() + 1 hours, _noCalls());
    bytes memory permitSig = _signPermit2Order(permitOrder);

    vm.prank(guardian);
    hub.pause();

    vm.prank(owner);
    vm.expectRevert(Pausable.EnforcedPause.selector);
    hub.settleOrder(order, '', _defaultSolution(order), '', false);

    vm.prank(relayer);
    vm.expectRevert(Pausable.EnforcedPause.selector);
    hub.settleOrder(permitOrder, permitSig, _defaultSolution(permitOrder), '', false);

    // Delegation carries no assets, so the pause does not reach it
    vm.prank(owner);
    hub.updateDelegation(owner, address(mock), true, hex'1234', 0, vm.getBlockTimestamp(), '');

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
      abi.encodeWithSelector(IManagementSimple.UnauthorizedAccount.selector, relayer, needed)
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
  // GUARD — expiration
  // -----------------------------------------------------------------------------------------

  /// GUARD-04 — the expiration block itself still settles; the one before it does not
  function test_GUARD_04_expirationBoundaryOnTheOrderEntryPoints() public {
    uint256 t = vm.getBlockTimestamp();

    _settleAtExpiration(t - 1, false);
    _settleAtExpiration(t, true);
    _settleAtExpiration(t + 1, true);

    // the Permit2 path carries the same expiration into the permit, so the hub's own
    // modifier has to be the one that fires: a stale order must not reach Permit2 at all
    AHV2Order memory stale = _permit2Order(91, t - 1, _noCalls());
    bytes memory staleSig = _signPermit2Order(stale);

    vm.prank(relayer);
    vm.expectRevert(_orderExpired(t - 1));
    hub.settleOrder(stale, staleSig, _defaultSolution(stale), '', false);
  }

  /// GUARD-05 — when both guards would fire, the pause wins, because it is the outer modifier
  function test_GUARD_05_pauseTakesPrecedenceOverTheExpiration() public {
    AHV2Order memory stale = _permit2Order(0, vm.getBlockTimestamp() - 1, _noCalls());
    AHV2Order memory ownerStale = _openOrder(0, vm.getBlockTimestamp() - 1);
    bytes memory staleSig = _signPermit2Order(stale);

    vm.prank(guardian);
    hub.pause();

    vm.prank(relayer);
    vm.expectRevert(Pausable.EnforcedPause.selector);
    hub.settleOrder(stale, staleSig, _defaultSolution(stale), '', false);

    vm.prank(owner);
    vm.expectRevert(Pausable.EnforcedPause.selector);
    hub.settleOrder(ownerStale, '', _defaultSolution(ownerStale), '', false);
  }

  // -----------------------------------------------------------------------------------------
  // GUARD — native spend
  // -----------------------------------------------------------------------------------------

  /**
   * GUARD-06 — the calls may spend up to the value the order was sent with, and not one wei more
   * @dev Each step splits the spend across two calls, so the guard compares their sum
   */
  function test_GUARD_06_nativeSpendBoundary() public {
    _nativeSpendTransfer(VALUE - 1, true);
    _nativeSpendTransfer(VALUE, true);
    _nativeSpendTransfer(VALUE + 1, false);
  }

  // -----------------------------------------------------------------------------------------
  // GATE-01 — the three modifiers on the Permit2 path of `settleOrder`
  // -----------------------------------------------------------------------------------------

  /**
   * GATE-01 — the Permit2 path is pausable, expiration-checked and native-guarded
   * @dev Three modifiers, one step each. The control at the top is what makes the three refusals
   * evidence: the same shape of order settles when none of them fires, so each step differs from a
   * settling order in exactly the one thing its modifier reads.
   */
  function test_GATE_01_permit2EntryPointCarriesTheThreeModifiers() public {
    uint256 expiration = vm.getBlockTimestamp() + 1 hours;

    // control
    uint256 before = _calleeBalance();
    AHV2Order memory control = _permit2Order(100, expiration, _calls(_calleeCall(hex'01')));

    vm.prank(solver);
    hub.settleOrder(control, _signPermit2Order(control), _defaultSolution(control), '', false);
    assertEq(_calleeBalance() - before, AMOUNT, 'the control settled');

    // whenNotPaused
    AHV2Order memory paused = _permit2Order(101, expiration, _calls(_calleeCall(hex'01')));
    bytes memory pausedSig = _signPermit2Order(paused);

    vm.prank(guardian);
    hub.pause();

    vm.prank(solver);
    vm.expectRevert(Pausable.EnforcedPause.selector);
    hub.settleOrder(paused, pausedSig, _defaultSolution(paused), '', false);

    vm.prank(admin);
    hub.unpause();

    // checkSettlement
    AHV2Order memory stale =
      _permit2Order(102, vm.getBlockTimestamp() - 1, _calls(_calleeCall(hex'01')));
    bytes memory staleSig = _signPermit2Order(stale);

    vm.prank(solver);
    vm.expectRevert(_orderExpired(vm.getBlockTimestamp() - 1));
    hub.settleOrder(stale, staleSig, _defaultSolution(stale), '', false);

    // guardNativeSpend
    vm.deal(address(hub), PREFUND);
    vm.deal(solver, VALUE);

    AHV2Order memory overSpending = _permit2Order(104, expiration, _calls(_calleeCall(hex'01')));
    bytes memory overSpendingSig = _signPermit2Order(overSpending);
    AHV2Solution memory greedyRoute = _defaultSolution(overSpending);
    greedyRoute.callValues = _values(VALUE + 1);

    vm.prank(solver);
    vm.expectRevert(
      abi.encodeWithSelector(NativeSpendGuard.NativeOverspent.selector, VALUE + 1, VALUE)
    );
    hub.settleOrder{value: VALUE}(overSpending, overSpendingSig, greedyRoute, '', false);

    assertEq(address(hub).balance, PREFUND, "the hub's own native balance is intact");
  }

  /**
   * GATE-02 — an undelegated authenticator and overspent native are refused by `settleOrder`
   * @dev These are the guards no other case watches. One step each for the inline delegation
   * check and for `guardNativeSpend` on `settleOrder`. Each step is written so that only its own
   * guard can produce the result.
   */
  function test_GATE_02_theUnwatchedGuards() public {
    uint256 deadline = vm.getBlockTimestamp() + 1 hours;

    // delegation check
    AHV2Order memory undelegated = _openOrder(111, deadline);
    undelegated.authenticator = address(authenticator);

    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(
        IAuthDelegator.AuthenticatorNotDelegated.selector, address(authenticator)
      )
    );
    hub.settleOrder(undelegated, '', _defaultSolution(undelegated), '', false);

    // guardNativeSpend
    vm.deal(address(hub), PREFUND);
    vm.deal(owner, VALUE);

    AHV2Order memory overSpending = _openAhv2Order(
      new ERC20Allowance[](0), _noHooks(), _calls(_calleeCall(hex'01')), 112, deadline
    );
    AHV2Solution memory greedySolution = _defaultSolution(overSpending);
    greedySolution.callValues = _values(VALUE + 1);

    vm.prank(owner);
    vm.expectRevert(
      abi.encodeWithSelector(NativeSpendGuard.NativeOverspent.selector, VALUE + 1, VALUE)
    );
    hub.settleOrder{value: VALUE}(overSpending, '', greedySolution, '', false);

    assertEq(address(hub).balance, PREFUND, 'the hub kept its native balance');
  }

  /// @dev An order open to any submitter that draws `AMOUNT` of the token and calls nothing
  function _openOrder(uint256 nonce, uint256 expiration) internal view returns (AHV2Order memory) {
    return
      _openAhv2Order(
        _allowances(_tokenAllowance(AMOUNT)), _noHooks(), _noCalls(), nonce, expiration
      );
  }

  /// @dev As {_openOrder}, authorized through Permit2
  function _permit2Order(uint256 nonce, uint256 expiration, CallParams[] memory calls)
    internal
    view
    returns (AHV2Order memory order)
  {
    order = _openOrder(nonce, expiration);
    order.calls = calls;
    order.authenticator = permit2;
  }

  function _settleAtExpiration(uint256 expiration, bool shouldSettle) internal {
    uint256 calleeBefore = _calleeBalance();

    AHV2Order memory order = _openOrder(0, expiration);
    AHV2Solution memory solution = _defaultSolution(order);

    vm.prank(owner);
    if (!shouldSettle) {
      vm.expectRevert(_orderExpired(expiration));
    }
    hub.settleOrder(order, '', solution, '', false);

    assertEq(
      _calleeBalance() - calleeBefore,
      shouldSettle ? AMOUNT : 0,
      'the owner-submitted path moved assets only up to the expiration'
    );
  }

  function _nativeSpendTransfer(uint256 spend, bool shouldSettle) internal {
    vm.deal(address(hub), PREFUND);
    vm.deal(owner, VALUE);

    uint256 calleeBefore = address(callee).balance;

    AHV2Order memory order = _openAhv2Order(
      new ERC20Allowance[](0),
      _noHooks(),
      _calls(_calleeCall(hex'01'), _calleeCall(hex'02')),
      0,
      vm.getBlockTimestamp()
    );
    AHV2Solution memory solution = _defaultSolution(order);
    solution.callValues = _values(spend / 2, spend - spend / 2);

    vm.prank(owner);
    if (!shouldSettle) {
      vm.expectRevert(
        abi.encodeWithSelector(NativeSpendGuard.NativeOverspent.selector, spend, VALUE)
      );
    }
    hub.settleOrder{value: VALUE}(order, '', solution, '', false);

    if (shouldSettle) {
      assertEq(address(callee).balance - calleeBefore, spend, 'the callee was paid exactly');
      assertEq(
        address(hub).balance,
        PREFUND + VALUE - spend,
        'the hub kept its native balance plus the unspent value'
      );
    } else {
      assertEq(address(callee).balance, calleeBefore, 'nothing left the hub');
      assertEq(address(hub).balance, PREFUND, 'and its native balance is intact');
      assertEq(owner.balance, VALUE, 'the value went back to the sender');
    }
  }
}
