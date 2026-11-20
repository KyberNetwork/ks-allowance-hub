// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Vm} from 'forge-std/Vm.sol';

import {SchemaHash} from 'test/base/SchemaHash.sol';

import {ReentrantCalleeMock} from 'test/mocks/CalleeMocks.sol';
import {ReentrantReceiverMock} from 'test/mocks/TokenMocks.sol';

import {SettlementBase} from 'test/settlement/base/SettlementBase.sol';

import {IKSAllowanceHubV2} from 'src/interfaces/IKSAllowanceHubV2.sol';
import {IUnorderedNonce} from 'src/interfaces/base/IUnorderedNonce.sol';

import {NativeSpendGuard} from 'src/base/NativeSpendGuard.sol';

import {AHV2Order} from 'src/types/AHV2Order.sol';
import {AHV2Solution} from 'src/types/AHV2Solution.sol';
import {CallParams} from 'src/types/CallParams.sol';
import {ERC20Allowance} from 'src/types/ERC20Allowance.sol';
import {ERC20Transfer} from 'src/types/ERC20Transfer.sol';
import {ERC721Transfer} from 'src/types/ERC721Transfer.sol';
import {NativeTransfer} from 'src/types/NativeTransfer.sol';

/**
 * @title NestingTest
 * @notice `NEST-01..05` — an order settling inside another
 * @dev The transient message sender identifies the order owner to a callee, and an order may settle
 * inside a call of another. The role constant is written out rather than imported: a role read from
 * the hub would agree with a wrong one.
 */
contract NestingTest is SettlementBase {
  /// @dev Written out rather than imported: a role read from the hub would agree with a wrong one
  bytes32 internal constant CALLEE_ROLE = keccak256('WHITELISTED_CALLEE_ROLE');

  /// @dev The native balance the hub holds before a call, so a nested order has native value to
  /// overspend
  uint256 internal constant PREFUND = 1 ether;

  uint256 internal constant VALUE = 1 ether;

  /// @dev Inputs of {testFuzz_NEST_01_nestedOrdersRestoreEachOwner}
  struct NestingParams {
    uint256 depth;
    bool topViaPermit2;
  }

  /// @dev Inputs of {testFuzz_NEST_03_anOrderSettlesInsideAnotherOnEveryEntryPoint}
  struct NestedEntryParams {
    bool outerViaPermit2;
    bool nestedViaPermit2;
    bool wrapped;
  }

  // -----------------------------------------------------------------------------------------
  // NEST — the transient msg sender identifies the order owner to a callee, and an order may settle
  // inside another
  // -----------------------------------------------------------------------------------------

  /**
   * NEST-01 — orders nested inside calls settle, and each level sees its owner
   * @dev Level 0 is `owner`'s order, submitted by `owner` on the delegated entry point or by
   * `relayer` on the Permit2 entry point. Level `k` below the innermost calls `evils[k]`, which
   * settles level `k + 1` as an order it owns. The innermost level calls `callee`. Each `evils[k]`
   * reads {msgSender} before and after its nested order, and level 0 calls `callee2` last, so a
   * level that did not restore its predecessor's sender is detected at the next read.
   */
  function testFuzz_NEST_01_nestedOrdersRestoreEachOwner(NestingParams memory p) public {
    uint256 depth = bound(p.depth, 1, 6);

    ReentrantCalleeMock[] memory evils = new ReentrantCalleeMock[](depth);
    for (uint256 i = 0; i < depth; i++) {
      evils[i] = _newReentrantCallee();
    }

    (AHV2Order memory top, bytes32[] memory hashes) = _buildChain(evils, p.topViaPermit2);

    address topSubmitter = p.topViaPermit2 ? relayer : owner;

    AHV2Solution memory topSolution = _defaultSolution(top);
    bytes memory signature = p.topViaPermit2 ? _signPermit2Order(top) : bytes('');

    vm.recordLogs();

    vm.prank(topSubmitter);
    if (p.topViaPermit2) {
      hub.settleOrder(top, signature, topSolution, '', false);
    } else {
      hub.settleOrder(top, '', topSolution, '', false);
    }

    for (uint256 k = 0; k < depth; k++) {
      address levelOwner = k == 0 ? owner : address(evils[k - 1]);
      assertEq(evils[k].seenBefore(), levelOwner, 'a callee sees its level owner on entry');
      assertEq(evils[k].seenAfter(), levelOwner, 'and again once the nested order returned');
    }

    assertEq(callee.callCount(), 1, 'the innermost callee ran once');
    assertEq(callee.seenMsgSender(), address(evils[depth - 1]), 'the innermost owner');
    assertEq(callee2.callCount(), 1, 'the trailing call of level 0 ran once');
    assertEq(callee2.seenMsgSender(), owner, 'level 0 owner was restored after the whole chain');

    Vm.Log[] memory logs = _settleOrderLogs();
    assertEq(logs.length, depth + 1, 'one SettleOrder per level');
    _assertEmptySettlement(logs[0], topSubmitter, owner, hashes[0]);
    for (uint256 k = 1; k <= depth; k++) {
      address levelOwner = address(evils[k - 1]);
      _assertEmptySettlement(logs[k], levelOwner, levelOwner, hashes[k]);
    }

    assertEq(hub.msgSender(), address(0), 'nothing is recorded after the call');
  }

  /**
   * NEST-02 — the ERC721 receiver hook of an order may settle an order
   * @dev The NFT target of the outer order is a receiver whose hook settles an order it owns and
   * that calls `callee` once. The hub emits `SettleOrder` for an order before it moves any asset
   * of it, so the outer order's log precedes the log of the order settled by the hook.
   */
  function test_NEST_02_receiverHookSettlesAnOrderInsideAnOrder() public {
    ReentrantReceiverMock receiver = new ReentrantReceiverMock(address(hub));
    AHV2Order memory nested = _ownedOrder(address(receiver));
    receiver.setReentry(_settleCall(nested, _calls(_calleeCall(0, hex'01'))));

    AHV2Order memory order = _ahv2Order(
      ANY,
      new ERC20Allowance[](0),
      _approvals(_nftApproval()),
      _noHooks(),
      _noCalls(),
      ANY,
      0,
      vm.getBlockTimestamp() + 1 hours
    );
    AHV2Solution memory solution = _solution(
      new address[](0),
      new uint160[](0),
      _addresses(address(receiver)),
      vm.getBlockTimestamp() + 1 hours
    );

    vm.recordLogs();

    vm.prank(owner);
    hub.settleOrder(order, '', solution, '', false);

    assertEq(nft.ownerOf(NFT_ID), address(receiver), 'the NFT moved to the receiver');
    assertEq(callee.callCount(), 1, 'the callee call of the nested order ran');
    assertEq(callee.seenMsgSender(), address(receiver), 'under the nested owner');

    // The outer order announces itself before it moves the NFT, and the hook runs during the move
    Vm.Log[] memory logs = _settleOrderLogs();
    assertEq(logs.length, 2, 'one SettleOrder per order');
    assertEq(logs[0].topics.length, 4, 'caller, owner and the order hash are indexed');
    assertEq(_topicAddress(logs[0].topics[1]), owner, 'the outer order caller');
    assertEq(_topicAddress(logs[0].topics[2]), owner, 'the outer order owner');
    assertEq(logs[0].topics[3], SchemaHash.ahv2Order(order), 'the outer order hash');
    _assertEmptySettlement(
      logs[1], address(receiver), address(receiver), SchemaHash.ahv2Order(nested)
    );

    assertEq(hub.msgSender(), address(0), 'nothing is recorded after the call');
  }

  /**
   * NEST-03 — an order settles inside another on both entry points, as outer and as nested order
   * @dev The outer order's single call is `evil`, which settles the nested order. On the
   * delegated entry point the outer order is owned and submitted by `evilOuter`. On the Permit2
   * entry point it is owned by `owner`, signed open to any submitter and submitted by `evilOuter`.
   * With `wrapped`, an order of `owner` calls `evilOuter`, which submits the outer order from inside
   * it.
   *
   * The nested order calls `callee` once and is submitted by `evil`. On the delegated entry point it
   * is owned by `evil`. On the Permit2 entry point it is owned by `nestedOwner` and signed by its
   * own signer. No order moves a token, so Permit2 verifies the signature and spends the nonce of an
   * empty batch. The owner of the outer order and the owner of the nested order differ in every
   * combination.
   * @param p The entry point of the outer order, the entry point of the nested order, and whether
   * the outer order is wrapped
   */
  function testFuzz_NEST_03_anOrderSettlesInsideAnotherOnEveryEntryPoint(NestedEntryParams memory p)
    public
  {
    ReentrantCalleeMock evil = _newReentrantCallee();
    ReentrantCalleeMock evilOuter = _newReentrantCallee();
    (address nestedOwner, uint256 nestedOwnerKey) = makeAddrAndKey('nestedOwner');

    address outerOwner = p.outerViaPermit2 ? owner : address(evilOuter);
    address nestedOrderOwner = p.nestedViaPermit2 ? nestedOwner : address(evil);
    assertNotEq(outerOwner, nestedOrderOwner, 'the two owners differ');

    (bytes memory nestedCall, bytes32 nestedHash) = _orderCall(
      p.nestedViaPermit2, nestedOrderOwner, nestedOwnerKey, 2, _calls(_calleeCall(0, hex'01'))
    );
    evil.setReentry(nestedCall);

    (bytes memory outerCall, bytes32 outerHash) =
      _orderCall(p.outerViaPermit2, outerOwner, ownerKey, 1, _calls(_callTo(address(evil))));

    address submitter = address(evilOuter);
    bytes memory submitted = outerCall;
    bytes32 topHash;
    if (p.wrapped) {
      AHV2Order memory top = _ownedOrder(owner);
      evilOuter.setReentry(outerCall);
      submitter = owner;
      submitted = _settleCall(top, _calls(_callTo(address(evilOuter))));
      topHash = SchemaHash.ahv2Order(top);
    }

    vm.recordLogs();

    vm.prank(submitter);
    (bool ok,) = address(hub).call(submitted);
    assertTrue(ok, 'the outer order settled');

    assertEq(evil.seenBefore(), outerOwner, 'the callee is called under the outer owner');
    assertEq(evil.seenAfter(), outerOwner, 'and the outer owner is restored');
    if (p.wrapped) {
      assertEq(evilOuter.seenBefore(), owner, 'the wrapping call runs under its owner');
      assertEq(evilOuter.seenAfter(), owner, 'and its owner is restored');
    }
    assertEq(callee.callCount(), 1, 'the nested callee ran once');
    assertEq(callee.seenMsgSender(), nestedOrderOwner, 'under the nested owner');

    Vm.Log[] memory logs = _settleOrderLogs();
    uint256 base = p.wrapped ? 1 : 0;
    assertEq(logs.length, base + 2, 'one SettleOrder per order');
    if (p.wrapped) {
      _assertEmptySettlement(logs[0], owner, owner, topHash);
    }
    _assertEmptySettlement(logs[base], address(evilOuter), outerOwner, outerHash);
    _assertEmptySettlement(logs[base + 1], address(evil), nestedOrderOwner, nestedHash);

    assertEq(hub.msgSender(), address(0), 'nothing is recorded after the call');
  }

  /**
   * NEST-04 — a callee's `revokeNonce` inside an order spends the nonce in the callee's namespace
   * @dev A callee may call `revokeNonce` inside an order. The nonce is spent in the callee's
   * namespace, not the owner's.
   */
  function test_NEST_04_revokeNonceIsReachableFromInsideAnOrder() public {
    ReentrantCalleeMock evil = _newReentrantCallee();

    evil.setReentry(abi.encodeCall(IUnorderedNonce.revokeNonce, (7)));

    AHV2Order memory order = _ownedOrder(owner);
    order.calls = _calls(_callTo(address(evil)));

    vm.prank(owner);
    bytes[] memory results = hub.settleOrder(order, '', _defaultSolution(order), '', false);

    assertEq(results.length, 1, 'the order settled');
    assertEq(results[0].length, 0, 'revokeNonce returns nothing');
    assertEq(
      hub.nonces(lNonceKey(address(evil)), 0), 1 << 7, "burned against the callee's own bitmap"
    );
    assertEq(hub.nonces(lNonceKey(owner), 0), 0, "and not against the owner's");
    assertEq(hub.msgSender(), address(0), 'nothing is recorded after the call');
  }

  /**
   * NEST-05 — a nested order cannot spend the outer order's value
   * @dev With the hub holding a native balance, the outer order may spend its own value after
   * a nested order returned, but a nested order sent no value cannot spend the outer order's.
   */
  function test_NEST_05_nestedOrderCannotSpendTheOuterValue() public {
    ReentrantCalleeMock evil = _newReentrantCallee();
    vm.deal(address(hub), PREFUND);
    uint256 calleeBalanceBefore = address(callee).balance;

    // (a) the nested order spends nothing and the outer order spends its value afterwards
    evil.setReentry(_settleCall(_ownedOrder(address(evil)), _noCalls()));
    AHV2Order memory outer = _ownedOrder(owner);
    outer.calls = _calls(_callTo(address(evil)), _calleeCall(VALUE, hex'01'));
    vm.deal(owner, VALUE);

    vm.prank(owner);
    hub.settleOrder{value: VALUE}(outer, '', _defaultSolution(outer), '', false);

    assertEq(callee.callCount(), 1, 'the outer callee call ran');
    assertEq(callee.lastValue(), VALUE, 'with the outer value');
    assertEq(address(callee).balance - calleeBalanceBefore, VALUE, 'and the value landed');
    assertEq(address(hub).balance, PREFUND, "the hub's native balance is intact");

    // (b) the nested order tries to spend the value the outer order was sent
    evil.setReentry(_settleCall(_ownedOrder(address(evil)), _calls(_calleeCall(VALUE, hex'02'))));
    AHV2Order memory outerB = _ownedOrder(owner);
    outerB.calls = _calls(_callTo(address(evil)));
    vm.deal(owner, VALUE);

    vm.prank(owner);
    vm.expectRevert(abi.encodeWithSelector(NativeSpendGuard.NativeOverspent.selector, VALUE, 0));
    hub.settleOrder{value: VALUE}(outerB, '', _defaultSolution(outerB), '', false);

    assertEq(callee.callCount(), 1, 'the nested callee call rolled back');
    assertEq(address(hub).balance, PREFUND, "the hub's native balance is intact");
    assertEq(owner.balance, VALUE, 'the value went back to the sender');
  }

  // -------------------------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------------------------

  /// @dev A callee that may be called by the hub and calls back into it
  function _newReentrantCallee() internal returns (ReentrantCalleeMock evil) {
    evil = new ReentrantCalleeMock(address(hub));
    vm.prank(admin);
    hub.grantRole(CALLEE_ROLE, address(evil));
  }

  /// @dev A call to `target` with no value and no data
  function _callTo(address target) internal pure returns (CallParams memory) {
    return CallParams({callee: target, value: 0, data: hex''});
  }

  /// @dev The call by the owner that settles `order` after its calls are set to `calls`
  function _settleCall(AHV2Order memory order, CallParams[] memory calls)
    internal
    view
    returns (bytes memory)
  {
    order.calls = calls;
    return
      abi.encodeCall(IKSAllowanceHubV2.settleOrder, (order, '', _defaultSolution(order), '', false));
  }

  /**
   * @dev The call of an order owned by `orderOwner` with its order hash, whose calls are
   * `calls`. The call is made by the owner, or carries the open witness signature of `signerKey`
   * for the Permit2 entry point, where the order moves no token and spends `nonce`.
   */
  function _orderCall(
    bool viaPermit2,
    address orderOwner,
    uint256 signerKey,
    uint256 nonce,
    CallParams[] memory calls
  ) internal view returns (bytes memory data, bytes32 orderHash) {
    AHV2Order memory order = _ownedOrder(orderOwner);
    order.nonce = nonce;
    order.calls = calls;
    if (viaPermit2) {
      order.authenticator = permit2;
    }
    orderHash = SchemaHash.ahv2Order(order);

    if (viaPermit2) {
      data = abi.encodeCall(
        IKSAllowanceHubV2.settleOrder,
        (order, _signPermit2Order(order, signerKey), _defaultSolution(order), '', false)
      );
    } else {
      data = _settleCall(order, calls);
    }
  }

  /**
   * @dev Builds the nested orders of {testFuzz_NEST_01_nestedOrdersRestoreEachOwner} and arms each
   * of `evils` to settle the next level, returning level 0 and the order hash of every
   * level. Level 0 is authorized through Permit2 when `topViaPermit2` is set.
   */
  function _buildChain(ReentrantCalleeMock[] memory evils, bool topViaPermit2)
    internal
    returns (AHV2Order memory top, bytes32[] memory hashes)
  {
    uint256 depth = evils.length;
    hashes = new bytes32[](depth + 1);

    // The innermost level is owned by the last callee and calls `callee`
    AHV2Order memory inner = _ownedOrder(address(evils[depth - 1]));
    bytes memory reentry = _settleCall(inner, _calls(_calleeCall(0, hex'01')));
    hashes[depth] = SchemaHash.ahv2Order(inner);

    // Level `level` is owned by the callee above it and calls the callee at its own index
    for (uint256 level = depth - 1; level >= 1; level--) {
      evils[level].setReentry(reentry);
      AHV2Order memory order = _ownedOrder(address(evils[level - 1]));
      reentry = _settleCall(order, _calls(_callTo(address(evils[level]))));
      hashes[level] = SchemaHash.ahv2Order(order);
    }
    evils[0].setReentry(reentry);

    top = _ownedOrder(owner);
    top.calls = _calls(
      _callTo(address(evils[0])), CallParams({callee: address(callee2), value: 0, data: hex'02'})
    );
    if (topViaPermit2) {
      top.authenticator = permit2;
    }
    hashes[0] = SchemaHash.ahv2Order(top);
  }

  /// @dev Every `SettleOrder` the hub emitted, in emission order
  function _settleOrderLogs() internal view returns (Vm.Log[] memory logs) {
    Vm.Log[] memory entries = vm.getRecordedLogs();

    uint256 found;
    logs = new Vm.Log[](entries.length);
    for (uint256 i = 0; i < entries.length; i++) {
      if (entries[i].emitter != address(hub)) {
        continue;
      }
      if (entries[i].topics.length == 0) {
        continue;
      }
      if (entries[i].topics[0] != SETTLE_ORDER_TOPIC) {
        continue;
      }

      logs[found++] = entries[i];
    }

    assembly ('memory-safe') {
      mstore(logs, found)
    }
  }

  /**
   * @dev Asserts a `SettleOrder` of an order that moves nothing, owned by `orderOwner` and
   * submitted by `submitter`
   */
  function _assertEmptySettlement(
    Vm.Log memory entry,
    address submitter,
    address orderOwner,
    bytes32 orderHash
  ) internal pure {
    assertEq(entry.topics.length, 4, 'caller, owner and the order hash are indexed');
    assertEq(_topicAddress(entry.topics[1]), submitter, 'the submitter');
    assertEq(_topicAddress(entry.topics[2]), orderOwner, 'the owner');
    assertEq(entry.topics[3], orderHash, 'the order hash');
    assertEq(
      entry.data,
      abi.encode(
        new ERC20Transfer[](0), new ERC721Transfer[](0), new NativeTransfer[](0), bytes('')
      ),
      'nothing moved'
    );
  }
}
