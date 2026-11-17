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
import {HookParams} from 'src/types/HookParams.sol';

import {IManagementSimple} from 'ks-common-sc/src/interfaces/IManagementSimple.sol';

import {IAccessControl} from 'openzeppelin-contracts/contracts/access/IAccessControl.sol';
import {IERC20} from 'openzeppelin-contracts/contracts/token/ERC20/IERC20.sol';
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
 * The two entry points carry nine modifier applications between them. `GUARD-*` takes the
 * delegated entry point, `GATE-01` takes `settleOrderWithPermit2Signature` and `GATE-02` takes the
 * applications neither of those reaches. `NEST-03` of {NestingTest} observes `setMsgSender` on
 * both, so every one of the nine is observed somewhere.
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

  /// GUARD-02 — a pause closes both order entry points but leaves delegation open
  function test_GUARD_02_pauseClosesOrdersNotDelegation() public {
    AHV2AuthenticatorStub mock = new AHV2AuthenticatorStub();

    AHV2Order memory order = _openOrder(90, vm.getBlockTimestamp() + 1 hours);
    bytes memory permitSig = _signWitness(order);

    vm.prank(guardian);
    hub.pause();

    vm.prank(owner);
    vm.expectRevert(Pausable.EnforcedPause.selector);
    hub.settleOrderWithDelegatedAuthentication(
      order, address(0), '', _route(order, new CallParams[](0)), '', false
    );

    vm.prank(relayer);
    vm.expectRevert(Pausable.EnforcedPause.selector);
    hub.settleOrderWithPermit2Signature(order, permitSig, _route(order, new CallParams[](0)), '');

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

    // the Permit2 entry point carries the same expiration into the permit, so the hub's own
    // modifier has to be the one that fires: a stale order must not reach Permit2 at all
    AHV2Order memory stale = _openOrder(91, t - 1);
    bytes memory staleSig = _signWitness(stale);

    vm.prank(relayer);
    vm.expectRevert(_deadlinePassed(t - 1));
    hub.settleOrderWithPermit2Signature(stale, staleSig, _route(stale, new CallParams[](0)), '');
  }

  /// GUARD-05 — when both guards would fire, the pause wins, because it is the outer modifier
  function test_GUARD_05_pauseTakesPrecedenceOverTheExpiration() public {
    AHV2Order memory stale = _openOrder(0, vm.getBlockTimestamp() - 1);
    bytes memory staleSig = _signWitness(stale);

    vm.prank(guardian);
    hub.pause();

    vm.prank(relayer);
    vm.expectRevert(Pausable.EnforcedPause.selector);
    hub.settleOrderWithPermit2Signature(stale, staleSig, _route(stale, new CallParams[](0)), '');

    vm.prank(owner);
    vm.expectRevert(Pausable.EnforcedPause.selector);
    hub.settleOrderWithDelegatedAuthentication(
      stale, address(0), '', _route(stale, new CallParams[](0)), '', false
    );
  }

  // -----------------------------------------------------------------------------------------
  // GUARD — native spend
  // -----------------------------------------------------------------------------------------

  /// GUARD-06 — a solver call may spend up to the value the order was sent with, and not one wei more
  function test_GUARD_06_nativeSpendBoundary() public {
    _nativeSpendTransfer(VALUE - 1, true);
    _nativeSpendTransfer(VALUE, true);
    _nativeSpendTransfer(VALUE + 1, false);
  }

  // -----------------------------------------------------------------------------------------
  // GATE-01 — the three modifiers on `settleOrderWithPermit2Signature`
  // -----------------------------------------------------------------------------------------

  /**
   * GATE-01 — the Permit2 entry point is pausable, expiration-checked and native-guarded
   * @dev Three modifiers, one step each. The control at the top is what makes the three refusals
   * evidence: the same shape of order settles when none of them fires, so each step differs from a
   * settling order in exactly the one thing its modifier reads.
   */
  function test_GATE_01_permit2EntryPointCarriesTheThreeModifiers() public {
    uint256 expiration = vm.getBlockTimestamp() + 1 hours;

    // control
    uint256 before = IERC20(token18).balanceOf(address(callee));
    AHV2Order memory control = _openOrder(100, expiration);

    vm.prank(solver);
    hub.settleOrderWithPermit2Signature(
      control, _signWitness(control), _route(control, _calls(_calleeCall(0, hex'01'))), ''
    );
    assertEq(IERC20(token18).balanceOf(address(callee)) - before, AMOUNT, 'the control settled');

    // whenNotPaused
    AHV2Order memory paused = _openOrder(101, expiration);
    bytes memory pausedSig = _signWitness(paused);

    vm.prank(guardian);
    hub.pause();

    vm.prank(solver);
    vm.expectRevert(Pausable.EnforcedPause.selector);
    hub.settleOrderWithPermit2Signature(
      paused, pausedSig, _route(paused, _calls(_calleeCall(0, hex'01'))), ''
    );

    vm.prank(admin);
    hub.unpause();

    // checkSettlement
    AHV2Order memory stale = _openOrder(102, vm.getBlockTimestamp() - 1);
    bytes memory staleSig = _signWitness(stale);

    vm.prank(solver);
    vm.expectRevert(_deadlinePassed(vm.getBlockTimestamp() - 1));
    hub.settleOrderWithPermit2Signature(
      stale, staleSig, _route(stale, _calls(_calleeCall(0, hex'01'))), ''
    );

    // guardNativeSpend
    vm.deal(address(hub), PREFUND);
    vm.deal(solver, VALUE);

    AHV2Order memory overSpending = _openOrder(104, expiration);
    bytes memory overSpendingSig = _signWitness(overSpending);
    AHV2Solution memory greedyRoute = _route(overSpending, _calls(_calleeCall(VALUE + 1, hex'01')));

    vm.prank(solver);
    vm.expectRevert(
      abi.encodeWithSelector(NativeSpendGuard.NativeOverspent.selector, VALUE + 1, VALUE)
    );
    hub.settleOrderWithPermit2Signature{value: VALUE}(
      overSpending, overSpendingSig, greedyRoute, ''
    );

    assertEq(address(hub).balance, PREFUND, "the hub's own native balance is intact");
  }

  /**
   * GATE-02 — an undelegated authenticator and overspent native are refused on the delegated
   * entry point
   * @dev These are the modifier applications no other case watches. One step each for
   * `checkDelegation` and `guardNativeSpend` on `settleOrderWithDelegatedAuthentication`. Each
   * step is written so that only its own modifier can produce the result.
   */
  function test_GATE_02_theUnwatchedModifierApplications() public {
    uint256 deadline = vm.getBlockTimestamp() + 1 hours;

    // checkDelegation
    AHV2Order memory undelegated = _openOrder(111, deadline);

    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(
        IAuthDelegator.AuthenticatorNotDelegated.selector, address(authenticator)
      )
    );
    hub.settleOrderWithDelegatedAuthentication(
      undelegated, address(authenticator), '', _route(undelegated, new CallParams[](0)), '', false
    );

    // guardNativeSpend
    vm.deal(address(hub), PREFUND);
    vm.deal(owner, VALUE);

    AHV2Order memory overSpending = _openAhv2Order(
      new ERC20Allowance[](0), new HookParams[](0), new CallParams[](0), 112, deadline
    );

    vm.prank(owner);
    vm.expectRevert(
      abi.encodeWithSelector(NativeSpendGuard.NativeOverspent.selector, VALUE + 1, VALUE)
    );
    hub.settleOrderWithDelegatedAuthentication{value: VALUE}(
      overSpending,
      address(0),
      '',
      _route(overSpending, _calls(_calleeCall(VALUE + 1, hex'01'))),
      '',
      false
    );

    assertEq(address(hub).balance, PREFUND, 'the hub kept its native balance');
  }

  /// @dev An order open to any submitter that draws `AMOUNT` of the token and calls nothing
  function _openOrder(uint256 nonce, uint256 expiration) internal view returns (AHV2Order memory) {
    return _openAhv2Order(
      _allowances(_tokenAllowance(AMOUNT)),
      new HookParams[](0),
      new CallParams[](0),
      nonce,
      expiration
    );
  }

  function _settleAtExpiration(uint256 expiration, bool shouldSettle) internal {
    uint256 calleeBefore = IERC20(token18).balanceOf(address(callee));

    AHV2Order memory order = _openOrder(0, expiration);
    AHV2Solution memory route = _route(order, new CallParams[](0));

    vm.prank(owner);
    if (!shouldSettle) {
      vm.expectRevert(_deadlinePassed(expiration));
    }
    hub.settleOrderWithDelegatedAuthentication(order, address(0), '', route, '', false);

    assertEq(
      IERC20(token18).balanceOf(address(callee)) - calleeBefore,
      shouldSettle ? AMOUNT : 0,
      'the delegated entry point moved assets only up to the expiration'
    );
  }

  function _nativeSpendTransfer(uint256 spend, bool shouldSettle) internal {
    vm.deal(address(hub), PREFUND);
    vm.deal(owner, VALUE);

    uint256 calleeBefore = address(callee).balance;
    CallParams[] memory calls = _calls(_calleeCall(spend, hex'01'));

    AHV2Order memory order = _openAhv2Order(
      new ERC20Allowance[](0), new HookParams[](0), new CallParams[](0), 0, vm.getBlockTimestamp()
    );

    vm.prank(owner);
    if (!shouldSettle) {
      vm.expectRevert(
        abi.encodeWithSelector(NativeSpendGuard.NativeOverspent.selector, spend, VALUE)
      );
    }
    hub.settleOrderWithDelegatedAuthentication{value: VALUE}(
      order, address(0), '', _route(order, calls), '', false
    );

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
