// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {SignerAuthenticatorBase} from 'test/base/SignerAuthenticatorBase.sol';

import {CalleeMock} from 'test/mocks/CalleeMocks.sol';
import {SignerAuthenticatorMock} from 'test/mocks/SignerAuthenticatorMock.sol';

import {IKSAllowanceHubV2} from 'src/interfaces/IKSAllowanceHubV2.sol';
import {IAHV2Authenticator} from 'src/interfaces/base/IAHV2Authenticator.sol';
import {IAuthDelegator} from 'src/interfaces/base/IAuthDelegator.sol';
import {IUnorderedNonce} from 'src/interfaces/base/IUnorderedNonce.sol';

import {NativeSpendGuard} from 'src/base/NativeSpendGuard.sol';

import {AHV2Order} from 'src/types/AHV2Order.sol';
import {AHV2Solution} from 'src/types/AHV2Solution.sol';
import {CallParams} from 'src/types/CallParams.sol';
import {ERC20Allowance} from 'src/types/ERC20Allowance.sol';

import {IAccessControl} from 'openzeppelin-contracts/contracts/access/IAccessControl.sol';
import {IERC20} from 'openzeppelin-contracts/contracts/token/ERC20/IERC20.sol';
import {
  IERC20Permit
} from 'openzeppelin-contracts/contracts/token/ERC20/extensions/IERC20Permit.sol';

/**
 * @title MulticallTest
 * @notice MC-01..07, MC-09 and MC-FUZZ — the batching surface
 * @dev `multicall` runs each entry under the same guards as a direct call and limits the batch as
 * a whole, so one refusal reverts every entry. The native-value cases test this limit: a batch may
 * spend only the value the caller sent, and the hub's own native balance must remain unchanged.
 */
contract MulticallTest is SignerAuthenticatorBase {
  uint160 internal constant AMOUNT = 1 ether;

  bytes32 internal constant CALLEE_ROLE = keccak256('WHITELISTED_CALLEE_ROLE');

  /// @dev The native balance the hub holds before a call, so `msg.value + 1` is payable
  uint256 internal constant PREFUND = 1 ether;
  uint256 internal constant VALUE = 1 ether;

  // -----------------------------------------------------------------------------------------
  // MC — the batching surface
  // -----------------------------------------------------------------------------------------

  /// MC-01 — a permit and the order that uses the approval share one transaction, with value
  function test_MC_01_permitAndOrderInOneBatch() public {
    uint256 permitValue = 1234e6;
    uint256 deadline = vm.getBlockTimestamp() + 1 hours;

    address[] memory tokens = new address[](1);
    tokens[0] = token6;
    bytes[] memory permits = new bytes[](1);
    permits[0] = _erc2612PermitCall(
      'Token Six', token6, address(hub), permitValue, IERC20Permit(token6).nonces(owner), deadline
    );

    AHV2Order memory order =
      _openAhv2Order(_allowances(_tokenAllowance(AMOUNT)), _noHooks(), _noCalls(), 0, deadline);

    bytes[] memory batch = new bytes[](2);
    batch[0] = abi.encodeCall(IKSAllowanceHubV2.forwardCalls, (_call3s(tokens, permits, 0)));
    batch[1] = _settleCalldata(order, _calls(_calleeCall(hex'01')), _values(0.5 ether));

    uint256 calleeWethBefore = _calleeBalance();
    uint256 calleeNativeBefore = address(callee).balance;
    vm.deal(owner, VALUE);

    vm.prank(owner);
    (bytes[] memory results, uint256[] memory gasUsages) = hub.multicall{value: VALUE}(batch);

    assertEq(results.length, 2, 'one result per sub-call');
    assertEq(IERC20(token6).allowance(owner, address(hub)), permitValue, 'the permit was relayed');
    assertEq(_calleeBalance() - calleeWethBefore, AMOUNT, 'the order settled');
    assertEq(
      address(callee).balance - calleeNativeBefore, 0.5 ether, 'the native transfer was paid'
    );
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

    bytes memory order =
      _settleCalldata(_emptyOrder(0), _calls(_calleeCall(hex'01')), _values(VALUE));

    bytes[] memory batch = new bytes[](2);
    batch[0] = order;
    batch[1] = order;

    uint256 calleeBefore = address(callee).balance;

    vm.prank(owner);
    vm.expectRevert(
      abi.encodeWithSelector(NativeSpendGuard.NativeOverspent.selector, 2 * VALUE, VALUE)
    );
    hub.multicall{value: VALUE}(batch);

    assertEq(address(hub).balance, 2 * VALUE, "the hub's own native balance is unchanged");
    assertEq(address(callee).balance, calleeBefore, 'and the callee was paid nothing');
    assertEq(callee.callCount(), 0, 'the whole batch rolled back');
  }

  /// MC-03 — a sub-call's revert arrives at the caller with its arguments intact
  function test_MC_03_subCallRevertBubbles() public {
    CalleeMock stranger = new CalleeMock();

    CallParams[] memory calls = _calls(CallParams({callee: address(stranger), ownerData: hex'01'}));

    bytes[] memory batch = new bytes[](1);
    batch[0] = _settleCalldata(_emptyOrder(0), calls);

    vm.prank(owner);
    vm.expectRevert(
      abi.encodeWithSelector(
        IAccessControl.AccessControlUnauthorizedAccount.selector, address(stranger), CALLEE_ROLE
      )
    );
    hub.multicall(batch);
  }

  /// MC-04 — two independent orders in one batch both settle, in the order given
  function test_MC_04_twoOrdersInOneBatch() public {
    bytes[] memory batch = new bytes[](2);
    batch[0] = _orderCalldata(1 ether, hex'a1');
    batch[1] = _orderCalldata(2 ether, hex'b2');

    uint256 calleeWethBefore = _calleeBalance();

    vm.prank(owner);
    (bytes[] memory results,) = hub.multicall(batch);

    assertEq(results.length, 2, 'two results');
    assertEq(_calleeBalance() - calleeWethBefore, 3 ether, 'both transfers pulled');
    assertEq(callee.callCount(), 2, 'both calls ran');
    assertEq(callee.lastData(), hex'b2', 'the second order ran last');

    bytes[] memory innerFirst = abi.decode(results[0], (bytes[]));
    bytes[] memory innerSecond = abi.decode(results[1], (bytes[]));
    assertEq(abi.decode(innerFirst[0], (uint256)), 1, 'first sub-call saw the first callee call');
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
      IKSAllowanceHubV2.forwardCalls, (_call3s(new address[](0), new bytes[](0), 0))
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
   * MC-09 — a delegation relayed through `forwardCalls` with `allowFailure` set survives being
   * front-run, so the order batched after it still settles
   * @dev The front-runner submits the same signed delegation first, which spends its nonce. The
   * relayer's copy then reverts; with `allowFailure` false that unwinds the whole batch, with it
   * true the batch carries on, and the delegation is in place either way.
   */
  function test_MC_09_aFrontRunDelegationDoesNotUnwindTheBatch() public {
    uint256 deadline = vm.getBlockTimestamp() + 1 hours;
    uint256 delegationNonce = 80;

    bytes memory delegationSig = _signAuthDelegation(
      ownerKey,
      owner,
      address(authenticator),
      true,
      _encodeSigner(signer),
      delegationNonce,
      deadline
    );
    AHV2Order memory order = _openAhv2Order(
      address(authenticator),
      _allowances(_tokenAllowance(AMOUNT)),
      _noHooks(),
      _calls(_calleeCall(hex'01')),
      81,
      deadline
    );
    AHV2Solution memory solution = _defaultSolution(order);
    bytes memory orderAuth = _orderAuthData(order, signer, signerPk);

    bytes[] memory relayed = new bytes[](1);
    relayed[0] = abi.encodeCall(
      IAuthDelegator.updateDelegation,
      (
        owner,
        address(authenticator),
        true,
        _encodeSigner(signer),
        delegationNonce,
        deadline,
        delegationSig
      )
    );
    address[] memory targets = new address[](1);
    targets[0] = address(hub);

    bytes[] memory batch = new bytes[](2);
    batch[1] =
      abi.encodeCall(IKSAllowanceHubV2.settleOrder, (order, orderAuth, solution, '', false));

    // the front-runner lands the same signed delegation first
    vm.prank(recipient);
    hub.updateDelegation(
      owner,
      address(authenticator),
      true,
      _encodeSigner(signer),
      delegationNonce,
      deadline,
      delegationSig
    );

    // with `allowFailure` false, the spent nonce unwinds the batch
    batch[0] = abi.encodeCall(IKSAllowanceHubV2.forwardCalls, (_call3s(targets, relayed, 0)));
    vm.prank(relayer);
    vm.expectRevert(abi.encodeWithSignature('Error(string)', 'Multicall3: call failed'));
    hub.multicall(batch);

    // with it true, the batch carries past the delegation and settles the order
    batch[0] = abi.encodeCall(IKSAllowanceHubV2.forwardCalls, (_call3s(targets, relayed, 1)));
    uint256 calleeBefore = _calleeBalance();

    vm.prank(relayer);
    hub.multicall(batch);

    assertTrue(hub.authDelegated(owner, address(authenticator)), 'delegated by the front-runner');
    assertEq(_calleeBalance() - calleeBefore, AMOUNT, 'the order settled');
  }

  /**
   * MC-06 — one batch approves a signer at an authenticator and then spends on it
   * @dev The relayer submits both halves and signs neither: `forwardCalls` relays the owner's
   * `updateAuthentication` (the authenticator sees the hub as `msg.sender`, so the owner's own
   * approval signature is what authorises it), and the order in the next slot settles on the signer
   * that call has just approved, over the delegated entry point, with the signer signing rather than the
   * wallet. Nothing outside the batch approves the signer, which the pre-state assertion fixes; the
   * delegation put in place beforehand carries no payload, so the hub's gate is open while the
   * authenticator still knows nothing.
   */
  function test_MC_06_approveASignerAndSpendOnItInOneBatch() public {
    uint256 deadline = vm.getBlockTimestamp() + 1 hours;
    uint256 approvalNonce = 70;
    uint256 orderNonce = 71;

    vm.prank(owner);
    hub.updateDelegation(owner, address(authenticator), true, '', 0, deadline, '');
    assertFalse(
      authenticator.approvedSigners(owner, signer), 'the authenticator approves no signer yet'
    );

    AHV2Order memory order = _openAhv2Order(
      address(authenticator),
      _allowances(_tokenAllowance(AMOUNT)),
      _noHooks(),
      _calls(_calleeCall(hex'01')),
      orderNonce,
      deadline
    );
    AHV2Solution memory solution = _defaultSolution(order);
    bytes memory approvalSig = _signSignerUpdate(signer, true, approvalNonce, deadline);
    bytes memory orderAuth = _orderAuthData(order, signer, signerPk);

    address[] memory targets = new address[](1);
    targets[0] = address(authenticator);

    bytes[] memory relayed = new bytes[](1);
    relayed[0] = abi.encodeCall(
      IAHV2Authenticator.updateAuthentication,
      (owner, _approveSigner(signer), approvalNonce, deadline, approvalSig)
    );

    bytes[] memory batch = new bytes[](2);
    batch[0] = abi.encodeCall(IKSAllowanceHubV2.forwardCalls, (_call3s(targets, relayed, 0)));
    batch[1] =
      abi.encodeCall(IKSAllowanceHubV2.settleOrder, (order, orderAuth, solution, '', false));

    // the second half on its own is refused, so the batch below is evidence that the first half
    // did the approving rather than that the order never needed one
    bytes[] memory orderOnly = new bytes[](1);
    orderOnly[0] = batch[1];

    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(SignerAuthenticatorMock.SignerNotApproved.selector, owner, signer)
    );
    hub.multicall(orderOnly);

    uint256 calleeWethBefore = _calleeBalance();

    vm.prank(relayer);
    (bytes[] memory results,) = hub.multicall(batch);

    assertEq(results.length, 2, 'one result per sub-call');
    assertTrue(authenticator.approvedSigners(owner, signer), 'the batch approved the signer');
    assertEq(
      _calleeBalance() - calleeWethBefore,
      AMOUNT,
      'and the order spent on it in the same transaction'
    );
    assertEq(callee.callCount(), 1, 'the callee call ran once');
    assertEq(callee.seenMsgSender(), owner, 'for the owner, not for the relayer who submitted');
    assertEq(callee.seenSolver(), relayer, 'the delegatecall keeps the multicall caller as solver');
    assertEq(
      authenticator.nonces(lNonceKey(owner), 0),
      1 << approvalNonce,
      'the approval spent a nonce of the owner, who signed it'
    );
    assertEq(
      authenticator.nonces(lNonceKey(signer), 0),
      1 << orderNonce,
      'the order spent a nonce of the signer, which signed it'
    );
    assertEq(hub.nonces(lNonceKey(owner), 0), 0, 'and the hub spent none of its own');
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
      // The non-payable guard reverts with no data and `multicall` bubbles what it received, so
      // the batch surfaces an empty revert. `bytes('')` matches that and nothing carrying data
      vm.prank(owner);
      vm.expectRevert(bytes(''));
      hub.multicall{value: value}(batch);

      assertEq(hub.nonces(lNonceKey(owner), 0), 0, 'the whole batch rolled back');
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

    assertEq(
      hub.nonces(lNonceKey(owner), 0), expectedBitmap, 'exactly the payable indices burned a nonce'
    );
    assertEq(address(hub).balance, value, 'a payable batch keeps whatever it did not spend');
  }

  // -----------------------------------------------------------------------------------------
  // Helpers
  // -----------------------------------------------------------------------------------------

  function _isPayableItem(uint8 mask, uint256 index) internal pure returns (bool) {
    return (uint256(mask) >> index) & 1 == 1;
  }

  /// @dev An order of `owner` that draws `amount` of `token18` and calls the callee once
  function _orderCalldata(uint160 amount, bytes memory data) internal view returns (bytes memory) {
    AHV2Order memory order = _openAhv2Order(
      _allowances(_tokenAllowance(amount)),
      _noHooks(),
      _calls(_calleeCall(data)),
      0,
      vm.getBlockTimestamp()
    );

    return _settleCalldata(order, order.calls);
  }

  /// @dev An order of `owner` with no transfers, no hooks and no calls
  function _emptyOrder(uint256 nonce) internal view returns (AHV2Order memory) {
    return
      _openAhv2Order(new ERC20Allowance[](0), _noHooks(), _noCalls(), nonce, vm.getBlockTimestamp());
  }

  /// @dev The call that `owner` makes to settle `order` after its calls are set to `calls`
  function _settleCalldata(AHV2Order memory order, CallParams[] memory calls)
    internal
    view
    returns (bytes memory)
  {
    return _settleCalldata(order, calls, new uint256[](calls.length));
  }

  /// @dev As above, with the solution's `callValues` set to `callValues`
  function _settleCalldata(
    AHV2Order memory order,
    CallParams[] memory calls,
    uint256[] memory callValues
  ) internal view returns (bytes memory) {
    order.calls = calls;
    AHV2Solution memory solution = _defaultSolution(order);
    solution.callValues = callValues;
    return abi.encodeCall(IKSAllowanceHubV2.settleOrder, (order, '', solution, '', false));
  }
}
