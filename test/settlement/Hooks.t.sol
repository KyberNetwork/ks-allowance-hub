// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {SchemaHash} from 'test/base/SchemaHash.sol';

import {HookMock} from 'test/mocks/HookMock.sol';
import {SignerAuthenticatorMock} from 'test/mocks/SignerAuthenticatorMock.sol';

import {SettlementBase} from 'test/settlement/base/SettlementBase.sol';

import {IAHV2Hook} from 'src/interfaces/base/IAHV2Hook.sol';

import {AHV2Order} from 'src/types/AHV2Order.sol';
import {AHV2Solution} from 'src/types/AHV2Solution.sol';
import {CallParams} from 'src/types/CallParams.sol';
import {ERC20Allowance} from 'src/types/ERC20Allowance.sol';
import {HookParams} from 'src/types/HookParams.sol';

/**
 * @title HooksTest
 * @notice `HOOK-01..10` — the hooks around the settlement
 * @dev The hooks bracket the solver calls and the owner calls on both entry points.
 */
contract HooksTest is SettlementBase {
  uint160 internal constant AMOUNT = 5 ether;

  /// @dev Permit2 does not expose this in the vendored interface, so it is written out here
  bytes4 internal constant PERMIT2_INVALID_SIGNER = bytes4(keccak256('InvalidSigner()'));

  /// @dev Written out rather than imported: a role read from the hub would agree with a wrong one
  bytes32 internal constant CALLEE_ROLE = keccak256('WHITELISTED_CALLEE_ROLE');

  // -------------------------------------------------------------------------------------------
  // HOOK — the hooks around the settlement
  // -------------------------------------------------------------------------------------------

  /**
   * HOOK-01 — the hooks bracket the whole order on the delegated entry point, each reading its
   * own entry
   * @dev The spy reads the callee's balance inside each hook, which is what orders the hooks
   * against the transfer and the callee call: `beforeSettlement` must see the pre-pull balance
   * and `afterSettlement` the balance after both the pull and the callee call. Each hook reads
   * the data of its own entry, receives the hash of the order and returns a result that reaches
   * its own `afterSettlement`. The hooks hold no callee role.
   */
  function test_HOOK_01_hooksRunAroundTheSettlementOnTheDelegatedEntryPoint() public {
    hook.setBeforeResult(hex'aaaa');
    hook2.setBeforeResult(hex'bbbb');
    hook.observe(token18, address(callee));

    uint160 amount = 4 ether;
    uint256 payout = 1 ether;
    uint256 calleeBefore = _calleeBalance();

    // the callee pays part of it away while it runs, so the balance changes during the callee
    // call. Without this the after hook would read the same value whether it ran before or after
    // the callee, and the ordering assertion below would be vacuous.
    callee.setPayout(token18, recipient, payout);

    AHV2Order memory order = _openAhv2Order(
      _allowances(_tokenAllowance(amount)),
      _hooks(_hook(hook, HOOK_BOTH, hex'11'), _hook(hook2, HOOK_BOTH, hex'22')),
      _noCalls(),
      0,
      vm.getBlockTimestamp()
    );

    vm.prank(owner);
    hub.settleOrder(order, '', _route(order, _calls(_calleeCall(0, hex'01'))), '', false);

    assertEq(hook.sequenceLength(), 2, 'both calls ran');
    assertEq(hook.sequence(0), 'before');
    assertEq(hook.sequence(1), 'after');

    // ordering, established by what each hook could see rather than by call order alone
    assertEq(hook.balanceAtBefore(), calleeBefore, 'beforeSettlement ran before the pull');
    assertEq(
      hook.balanceAtAfter(),
      calleeBefore + amount - payout,
      'afterSettlement ran after the callee call, not merely after the pull'
    );

    // each hook's afterSettlement received the result its own beforeSettlement returned
    assertEq(hook.receivedBeforeResult(), hex'aaaa', 'hook 1 before result');
    assertEq(hook2.receivedBeforeResult(), hex'bbbb', 'hook 2 before result');

    // each hook read its own entry, by the index it was given
    assertEq(hook.beforeData(), hex'11', 'hook 1 read its own data before');
    assertEq(hook.afterData(), hex'11', 'hook 1 read its own data after');
    assertEq(hook2.beforeData(), hex'22', 'hook 2 read its own data before');
    assertEq(hook2.afterData(), hex'22', 'hook 2 read its own data after');
    assertEq(hook.lastBeforeIndex(), 0, 'hook 1 index');
    assertEq(hook2.lastBeforeIndex(), 1, 'hook 2 index');

    bytes32 orderHash = SchemaHash.ahv2Order(order);
    assertEq(hook.lastOrderHash(), orderHash, 'hook 1 received the order hash');
    assertEq(hook2.lastOrderHash(), orderHash, 'hook 2 received the order hash');

    assertFalse(hub.hasRole(CALLEE_ROLE, address(hook)), 'a hook holds no callee role');
    assertFalse(hub.hasRole(CALLEE_ROLE, address(hook2)), 'a hook holds no callee role');
    assertEq(callee.callCount(), 1);
  }

  /**
   * HOOK-02 — the hooks bracket the Permit2 entry point, the after hook following the owner calls
   * @dev The ERC20s move inside Permit2 rather than through the hub's own transfer, and
   * `beforeSettlement` is called before that permit. Both ends are established by what the hook
   * could see rather than by call order. The solver call and the owner call each pay the same
   * amount away, so the after hook's reading distinguishes "after the solver call" from "after
   * the owner call": a hook that ran between them would read one payout higher.
   */
  function test_HOOK_02_hooksRunAroundThePermit2EntryPoint() public {
    hook.observe(token18, address(callee));

    uint160 amount = 4 ether;
    uint256 payout = 1 ether;
    uint256 deadline = vm.getBlockTimestamp() + 1 hours;
    uint256 calleeBefore = _calleeBalance();

    callee.setPayout(token18, recipient, payout);

    AHV2Order memory order = _ahv2Order(
      permit2,
      ANY,
      _allowances(_tokenAllowance(amount)),
      _noNfts(),
      _hooks(_hook(hook, HOOK_BOTH)),
      _calls(_calleeCall(0, hex'99')),
      ANY,
      80,
      deadline
    );
    bytes memory signature = _signWitness(order);

    vm.prank(solver);
    hub.settleOrder(order, signature, _route(order, _calls(_calleeCall(0, hex'01'))), '', false);

    assertEq(hook.sequenceLength(), 2, 'both calls ran');
    assertEq(
      hook.balanceAtBefore(), calleeBefore, 'beforeSettlement ran before Permit2 moved anything'
    );
    assertEq(
      hook.balanceAtAfter(),
      calleeBefore + amount - 2 * payout,
      'afterSettlement ran after the solver call and the owner call'
    );
    assertEq(hook.beforeData(), hex'11', 'the hook read its own entry before');
    assertEq(hook.afterData(), hex'11', 'the hook read its own entry after');
    assertEq(hook.lastOrderHash(), SchemaHash.ahv2Order(order), 'the hook received the order hash');
    assertEq(callee.callCount(), 2, 'one solver call and one owner call');
  }

  /**
   * HOOK-03 — a reverting hook reverts the order
   * @dev A reverting before hook leaves nothing moved. A reverting after hook reverts the callee
   * calls and the transfer that preceded them, and the before call that preceded it. The last
   * step is the control: with both hooks accepting, the same order settles.
   */
  function test_HOOK_03_aRevertingHookRevertsTheOrder() public {
    AHV2Order memory order = _openAhv2Order(
      _allowances(_tokenAllowance(AMOUNT)),
      _hooks(_hook(hook, HOOK_BOTH)),
      _noCalls(),
      0,
      vm.getBlockTimestamp()
    );
    AHV2Solution memory route = _route(order, _calls(_calleeCall(0, hex'01')));
    uint256 before = _calleeBalance();

    hook.setReverts(true, false);
    vm.prank(owner);
    vm.expectRevert(bytes('before'));
    hub.settleOrder(order, '', route, '', false);

    assertEq(_calleeBalance(), before, 'the refused order moved nothing');
    assertEq(callee.callCount(), 0, 'and ran no callee call');

    hook.setReverts(false, true);
    vm.prank(owner);
    vm.expectRevert(bytes('after'));
    hub.settleOrder(order, '', route, '', false);

    assertEq(_calleeBalance(), before, 'the transfer rolled back');
    assertEq(callee.callCount(), 0, 'callee call rolled back');
    assertEq(hook.beforeCount(), 0, 'and so did the before call');

    hook.setReverts(false, false);
    vm.prank(owner);
    hub.settleOrder(order, '', route, '', false);

    assertEq(_calleeBalance() - before, AMOUNT, 'the same order settles once the hook accepts');
    assertEq(callee.callCount(), 1);
  }

  /// HOOK-04 — an order with no hooks settles and runs its callee call
  function test_HOOK_04_noHooks() public {
    AHV2Order memory order =
      _openAhv2Order(new ERC20Allowance[](0), _noHooks(), _noCalls(), 0, vm.getBlockTimestamp());

    vm.prank(owner);
    hub.settleOrder(order, '', _route(order, _calls(_calleeCall(0, hex'01'))), '', false);

    assertEq(callee.callCount(), 1);
  }

  /**
   * HOOK-05 — the flags select which of the two calls a hook receives
   * @dev Four hooks, one per flag value. The hook selected for `afterSettlement` alone receives an
   * empty result although it is configured to return one, and the hook selected for both receives
   * what its own before call returned.
   */
  function test_HOOK_05_flagsSelectTheCalls() public {
    HookMock beforeOnly = new HookMock();
    HookMock afterOnly = new HookMock();
    HookMock both = new HookMock();
    HookMock neither = new HookMock();
    beforeOnly.setBeforeResult(hex'ff');
    afterOnly.setBeforeResult(hex'ff');
    both.setBeforeResult(hex'ff');
    neither.setBeforeResult(hex'ff');

    HookParams[] memory hooks = new HookParams[](4);
    hooks[0] = _hook(beforeOnly, bytes32(uint256(1)));
    hooks[1] = _hook(afterOnly, bytes32(uint256(2)));
    hooks[2] = _hook(both, bytes32(uint256(3)));
    hooks[3] = _hook(neither, bytes32(0));

    _settleWithHooks(hooks);

    assertEq(beforeOnly.beforeCount(), 1, 'flag 1 selects the before call');
    assertEq(beforeOnly.afterCount(), 0, 'and not the after call');

    assertEq(afterOnly.beforeCount(), 0, 'flag 2 does not select the before call');
    assertEq(afterOnly.afterCount(), 1, 'and selects the after call');
    assertEq(afterOnly.receivedBeforeResult(), '', 'which receives an empty before result');

    assertEq(both.beforeCount(), 1, 'flag 3 selects the before call');
    assertEq(both.afterCount(), 1, 'and the after call');
    assertEq(both.receivedBeforeResult(), hex'ff', 'which receives the before result');

    assertEq(neither.beforeCount(), 0, 'flag 0 selects no call');
    assertEq(neither.afterCount(), 0, 'of either kind');
  }

  /**
   * HOOK-06 — only the two lowest bits of the flags select calls
   * @dev The counts equal bit 0 and bit 1 of the drawn flags, and the after call receives the
   * before result exactly when the before call ran.
   */
  function testFuzz_HOOK_06_flagsSelectTheCalls(bytes32 flags) public {
    HookMock spy = new HookMock();
    spy.setBeforeResult(hex'ff');

    HookParams[] memory hooks = _hooks(_hook(spy, flags));
    _settleWithHooks(hooks);

    bool runsBefore = uint256(flags) & 1 == 1;
    bool runsAfter = (uint256(flags) >> 1) & 1 == 1;

    assertEq(spy.beforeCount(), runsBefore ? 1 : 0, 'bit 0 selects the before call');
    assertEq(spy.afterCount(), runsAfter ? 1 : 0, 'bit 1 selects the after call');
    if (runsAfter) {
      assertEq(
        spy.receivedBeforeResult(),
        runsBefore ? bytes(hex'ff') : bytes(''),
        'the before result reaches the after call only when the before call ran'
      );
    }
  }

  /**
   * HOOK-07 — a hook receives the order, its hash, the solution and the index of its entry
   * @dev Two hooks, so the indices are 0 and 1. The expected calldata is assembled from the hook
   * interface and the order hash from the bound schema, and each hook's after call carries the
   * result its own before call returned.
   */
  function test_HOOK_07_hooksReceiveTheOrderTheSolutionAndTheirIndex() public {
    hook.setBeforeResult(hex'a0');
    hook2.setBeforeResult(hex'a1');

    AHV2Order memory order = _openAhv2Order(
      new ERC20Allowance[](0),
      _hooks(_hook(hook, HOOK_BOTH, hex'11'), _hook(hook2, HOOK_BOTH, hex'22')),
      _noCalls(),
      0,
      vm.getBlockTimestamp()
    );
    AHV2Solution memory solution = _route(order, _calls(_calleeCall(0, hex'01')));
    bytes32 orderHash = SchemaHash.ahv2Order(order);

    vm.expectCall(
      address(hook), abi.encodeCall(IAHV2Hook.beforeSettlement, (order, orderHash, solution, 0)), 1
    );
    vm.expectCall(
      address(hook2), abi.encodeCall(IAHV2Hook.beforeSettlement, (order, orderHash, solution, 1)), 1
    );
    vm.expectCall(
      address(hook),
      abi.encodeCall(IAHV2Hook.afterSettlement, (order, orderHash, solution, 0, hex'a0')),
      1
    );
    vm.expectCall(
      address(hook2),
      abi.encodeCall(IAHV2Hook.afterSettlement, (order, orderHash, solution, 1, hex'a1')),
      1
    );

    vm.prank(owner);
    hub.settleOrder(order, '', solution, '', false);

    assertEq(hook.sequenceLength(), 2, 'both calls reached the first hook');
    assertEq(hook2.sequenceLength(), 2, 'and the second');
  }

  /**
   * HOOK-08 — the hooks run while `msgSender` returns the owner
   * @dev A relayer submits, so the owner is not the caller of the hub.
   */
  function test_HOOK_08_hooksRunWhileMsgSenderIsTheOwner() public {
    AHV2Order memory order = _openAhv2Order(
      address(authenticator),
      new ERC20Allowance[](0),
      _hooks(_hook(hook, HOOK_BOTH)),
      _noCalls(),
      0,
      vm.getBlockTimestamp() + 1 hours
    );
    bytes memory auth = _authOf(order);

    vm.prank(relayer);
    hub.settleOrder(order, auth, _route(order, _noCalls()), '', false);

    assertEq(hook.seenMsgSenderBefore(), owner, 'the before call saw the owner');
    assertEq(hook.seenMsgSenderAfter(), owner, 'and so did the after call');
  }

  /**
   * HOOK-09 — both signatures bind the hooks
   * @dev On the Permit2 entry point the flags of an entry changed after signing give Permit2's
   * refusal, and on the delegated entry point the data of an entry changed after signing gives the
   * authenticator's. Each step is preceded by its control: the order as signed settles.
   */
  function test_HOOK_09_signaturesBindTheHooks() public {
    _delegateSignerThroughHub(signer);

    ERC20Allowance[] memory erc20s = _allowances(_tokenAllowance(AMOUNT));
    uint256 expiration = vm.getBlockTimestamp() + 1 hours;

    // Permit2 entry point, flags
    AHV2Order memory signedPermit =
      _openAhv2Order(permit2, erc20s, _hooks(_hook(hook, HOOK_BOTH)), _noCalls(), 100, expiration);

    vm.prank(solver);
    hub.settleOrder(
      signedPermit, _signWitness(signedPermit), _route(signedPermit, _noCalls()), '', false
    );
    assertEq(hook.sequenceLength(), 2, 'the order as signed settled');

    AHV2Order memory signedFlags =
      _openAhv2Order(permit2, erc20s, _hooks(_hook(hook, HOOK_BOTH)), _noCalls(), 101, expiration);
    bytes memory signature = _signWitness(signedFlags);
    AHV2Order memory changedFlags =
      _openAhv2Order(permit2, erc20s, _hooks(_hook(hook, HOOK_AFTER)), _noCalls(), 101, expiration);
    AHV2Solution memory changedFlagsRoute = _route(changedFlags, _noCalls());

    vm.prank(solver);
    vm.expectRevert(PERMIT2_INVALID_SIGNER);
    hub.settleOrder(changedFlags, signature, changedFlagsRoute, '', false);

    // delegated entry point, data
    AHV2Order memory signedAuthenticated = _openAhv2Order(
      address(authenticator),
      erc20s,
      _hooks(_hook(hook, HOOK_BOTH, hex'11')),
      _noCalls(),
      102,
      expiration
    );
    bytes memory controlAuth = _orderAuthData(signedAuthenticated, signer, signerPk);

    vm.prank(relayer);
    hub.settleOrder(
      signedAuthenticated, controlAuth, _route(signedAuthenticated, _noCalls()), '', false
    );
    assertEq(hook.sequenceLength(), 4, 'the authenticated order as signed settled');

    AHV2Order memory signedData = _openAhv2Order(
      address(authenticator),
      erc20s,
      _hooks(_hook(hook, HOOK_BOTH, hex'11')),
      _noCalls(),
      103,
      expiration
    );
    bytes memory dataAuth = _orderAuthData(signedData, signer, signerPk);
    AHV2Order memory changedData = _openAhv2Order(
      address(authenticator),
      erc20s,
      _hooks(_hook(hook, HOOK_BOTH, hex'22')),
      _noCalls(),
      103,
      expiration
    );
    AHV2Solution memory changedDataRoute = _route(changedData, _noCalls());

    vm.prank(relayer);
    vm.expectRevert(SignerAuthenticatorMock.InvalidOrderSignature.selector);
    hub.settleOrder(changedData, dataAuth, changedDataRoute, '', false);
  }

  /**
   * HOOK-10 — the after hook observes the effects of the owner calls
   * @dev The solver call goes to a callee that pays nothing, and the owner call to the callee that
   * holds the tokens and pays part of them away. The after hook's balance reading includes that
   * payout, so `afterSettlement` ran after the owner call, and the hook's own sequence shows the
   * before call first and the after call last.
   */
  function test_HOOK_10_theAfterHookSeesTheOwnerCalls() public {
    hook.observe(token18, address(callee));

    uint160 amount = 4 ether;
    uint256 payout = 1 ether;
    uint256 calleeBefore = _calleeBalance();

    callee.setPayout(token18, recipient, payout);

    AHV2Order memory order = _openAhv2Order(
      _allowances(_tokenAllowance(amount)),
      _hooks(_hook(hook, HOOK_BOTH)),
      _calls(_calleeCall(0, hex'99')),
      0,
      vm.getBlockTimestamp()
    );
    CallParams[] memory solverCalls =
      _calls(CallParams({callee: address(callee2), value: 0, data: hex'01'}));

    vm.prank(owner);
    hub.settleOrder(order, '', _route(order, solverCalls), '', false);

    assertEq(callee.ownerCallCount(), 1, 'the owner call ran');
    assertEq(callee2.callCount(), 1, 'and so did the solver call');
    assertEq(hook.balanceAtBefore(), calleeBefore, 'the before call saw no transfer');
    assertEq(
      hook.balanceAtAfter(),
      calleeBefore + amount - payout,
      'the after call saw the payout of the owner call'
    );
    assertEq(hook.sequenceLength(), 2, 'both calls ran');
    assertEq(hook.sequence(0), 'before');
    assertEq(hook.sequence(1), 'after');
  }

  // -------------------------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------------------------

  /// @dev An owner-submitted order with `hooks` and nothing else
  function _settleWithHooks(HookParams[] memory hooks) private {
    AHV2Order memory order =
      _openAhv2Order(new ERC20Allowance[](0), hooks, _noCalls(), 0, vm.getBlockTimestamp());

    vm.prank(owner);
    hub.settleOrder(order, '', _route(order, _noCalls()), '', false);
  }
}
