// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Vm} from 'forge-std/Vm.sol';

import {SchemaHash} from 'test/base/SchemaHash.sol';

import {HubBase} from 'test/v2/base/HubBase.sol';

import {EchoRouterMock, ReentrantRouterMock, RouterMock} from 'test/v2/mocks/RouterMock.sol';
import {ReentrantReceiverMock} from 'test/v2/mocks/TokenMocks.sol';

import {NativeSpendGuard} from 'src/base/NativeSpendGuard.sol';
import {IKSGenericRouter} from 'src/base/interfaces/IKSGenericRouter.sol';
import {IMsgSender} from 'src/base/interfaces/IMsgSender.sol';
import {IUnorderedNonce} from 'src/base/interfaces/IUnorderedNonce.sol';
import {IKSAllowanceHubV2} from 'src/v2/interfaces/IKSAllowanceHubV2.sol';
import {ERC20Allowance} from 'src/v2/types/ERC20Allowance.sol';
import {ERC20Transfer} from 'src/v2/types/ERC20Transfer.sol';
import {ERC721Approval} from 'src/v2/types/ERC721Approval.sol';
import {ERC721Transfer} from 'src/v2/types/ERC721Transfer.sol';
import {ExecutionOrder} from 'src/v2/types/ExecutionOrder.sol';
import {FulfillmentOrder} from 'src/v2/types/FulfillmentOrder.sol';
import {FulfillmentSolution} from 'src/v2/types/FulfillmentSolution.sol';
import {GenericCall} from 'src/v2/types/GenericCall.sol';
import {NativeTransfer} from 'src/v2/types/NativeTransfer.sol';
import {ValidationParams} from 'src/v2/types/ValidationParams.sol';

import {IAccessControl} from 'openzeppelin-contracts/contracts/access/IAccessControl.sol';
import {IERC20} from 'openzeppelin-contracts/contracts/token/ERC20/IERC20.sol';

/**
 * @notice `SET-01..04`, `OWN-07`, `ROUTER-01..03` and `LOCK-02..07` — the settlement tail shared by
 * all four entry points.
 * @dev The role constant, the `TransferTokens` topic and the router's own function signature are
 * written out rather than imported: an expected value taken from the contract under test would
 * agree with a wrong one. The topic lives in {HubBase}, which is where the log picker needs it.
 */
contract SettlementTest is HubBase {
  uint160 internal constant AMOUNT = 5 ether;

  bytes32 internal constant ROUTER_ROLE = keccak256('WHITELISTED_ROUTER_ROLE');

  /// @dev The float the hub holds before a call, so a nested order has native to over-spend
  uint256 internal constant PREFUND = 1 ether;
  uint256 internal constant VALUE = 1 ether;

  /// @dev Inputs of {testFuzz_LOCK_02_nestedOrdersRestoreEachOwner}
  struct NestingParams {
    uint256 depth;
    bool innermostIsFulfillment;
    bool topViaPermit2;
  }

  /// @dev Inputs of {testFuzz_LOCK_06_noOrderSettlesInsideAFulfillment}
  struct LockedReentryParams {
    uint256 entry;
    bool viaExecution;
  }

  /// @dev Transcribed from {IKSGenericRouter}, so a wrong production selector cannot agree with it
  // -----------------------------------------------------------------------------------------
  // SET — the settlement event and the results array
  // -----------------------------------------------------------------------------------------

  /**
   * SET-01 — the whole `TransferTokens` payload of a relayed order, byte for byte
   * @dev `orderHash` is indexed, so there are four topics, and the third is compared against the
   * order hash rebuilt from the independent oracle.
   */
  function test_SET_01_transferTokensPayload() public {
    ERC20Transfer[] memory erc20s = _erc20s(_tokenTransfer(AMOUNT));
    ERC721Transfer[] memory nfts = _erc721s(_nftTransfer(address(router)));
    GenericCall[] memory calls = _calls(_routerCall(0, hex'abcd'));
    uint256 deadline = block.timestamp + 1 hours;

    ExecutionOrder memory order = _executionOrder(ANY, erc20s, nfts, calls, 11, deadline);
    bytes memory signature = _signExecutionWitness(order);

    vm.recordLogs();

    vm.prank(relayer);
    hub.executeOrderWithPermit2Signature(order, signature);

    Vm.Log memory entry = _settlementLog();

    assertEq(entry.topics.length, 4, 'caller, owner and the order hash are indexed');
    assertEq(_topicAddress(entry.topics[1]), relayer, 'caller is the submitter, not the owner');
    assertEq(_topicAddress(entry.topics[2]), owner, 'owner is the account the assets came from');
    assertEq(entry.topics[3], SchemaHash.executionOrder(order), 'the order hash the owner signed');
    // No call carries value, so the native leg is empty
    assertEq(entry.data, abi.encode(erc20s, nfts, new NativeTransfer[](0)), 'payload');
  }

  /// SET-02 — `[v=0, v=1, v=0]` reaches the event as a single-entry native list
  function test_SET_02_nativeTransfersAreTruncatedToValuedCalls() public {
    GenericCall[] memory calls = new GenericCall[](3);
    calls[0] = _routerCall(0, hex'01');
    calls[1] = _routerCall(1, hex'02');
    calls[2] = _routerCall(0, hex'03');

    NativeTransfer[] memory expected = new NativeTransfer[](1);
    expected[0] = NativeTransfer({target: address(router), amount: 1});

    uint256 routerBalanceBefore = address(router).balance;
    vm.deal(owner, 1);

    vm.recordLogs();

    vm.prank(owner);
    hub.executeOrderWithDelegatedAuthentication{value: 1}(
      _openExecutionOrder(new ERC20Transfer[](0), calls, 0, block.timestamp), address(0), '', false
    );

    Vm.Log memory entry = _settlementLog();

    assertEq(
      entry.data,
      abi.encode(new ERC20Transfer[](0), new ERC721Transfer[](0), expected),
      'only the valued call is listed'
    );
    assertEq(router.callCount(), 3, 'all three calls still ran');
    assertEq(address(router).balance - routerBalanceBefore, 1, 'the one wei landed');
    assertEq(address(hub).balance, 0, 'nothing stranded in the hub');
  }

  /// SET-03 — an order that moves nothing and calls nobody still settles and still emits
  function test_SET_03_emptyOrderStillEmits() public {
    ERC20Transfer[] memory noErc20s = new ERC20Transfer[](0);
    ERC721Transfer[] memory noNfts = new ERC721Transfer[](0);

    vm.recordLogs();

    vm.prank(owner);
    bytes[] memory results = hub.executeOrderWithDelegatedAuthentication(
      _openExecutionOrder(noErc20s, new GenericCall[](0), 0, block.timestamp), address(0), '', false
    );

    assertEq(results.length, 0, 'no calls, no results');

    Vm.Log memory entry = _settlementLog();
    assertEq(
      entry.data, abi.encode(noErc20s, noNfts, new NativeTransfer[](0)), 'three empty arrays'
    );
  }

  /// SET-04 — `results[i]` belongs to `genericCalls[i]`, across two interleaved routers
  function test_SET_04_resultsFollowCallOrder() public {
    EchoRouterMock echoA = new EchoRouterMock();
    EchoRouterMock echoB = new EchoRouterMock();

    vm.startPrank(admin);
    hub.grantRole(ROUTER_ROLE, address(echoA));
    hub.grantRole(ROUTER_ROLE, address(echoB));
    vm.stopPrank();

    GenericCall[] memory calls = new GenericCall[](3);
    calls[0] = GenericCall({router: address(echoA), value: 0, data: hex'aa'});
    calls[1] = GenericCall({router: address(echoB), value: 0, data: hex'bb'});
    calls[2] = GenericCall({router: address(echoA), value: 0, data: hex'cc'});

    vm.prank(owner);
    bytes[] memory results = hub.executeOrderWithDelegatedAuthentication(
      _openExecutionOrder(new ERC20Transfer[](0), calls, 0, block.timestamp), address(0), '', false
    );

    assertEq(results.length, 3, 'one result per call');
    for (uint256 i = 0; i < 3; i++) {
      (address seenRouter, bytes memory seenData) = abi.decode(results[i], (address, bytes));
      assertEq(seenRouter, calls[i].router, 'result came from the router at the same index');
      assertEq(seenData, calls[i].data, 'and carries the data sent to it');
    }
  }

  /**
   * OWN-07 — the native leg of the event spans both call lists, solver's route first
   * @dev Four calls, two of them valued, one from each list and neither at the end of its own.
   * A merge that reversed the two lists, or that walked one of them only, or that kept the
   * zero-value entries, produces a different array from the one written out here — and the two
   * entries differ in both target and amount, so nothing about the expectation is symmetric. The
   * order hash in the topic is the fulfillment's, which is a different type from an execution's.
   */
  function test_OWN_07_eventCoversBothLists() public {
    GenericCall[] memory solverCalls = new GenericCall[](2);
    solverCalls[0] = _routerCall(0, hex'01');
    solverCalls[1] = _routerCall(1, hex'02');

    GenericCall[] memory ownerCalls = new GenericCall[](2);
    ownerCalls[0] = GenericCall({router: address(router2), value: 2, data: hex'03'});
    ownerCalls[1] = GenericCall({router: address(router2), value: 0, data: hex'04'});

    NativeTransfer[] memory expected = new NativeTransfer[](2);
    expected[0] = NativeTransfer({target: address(router), amount: 1});
    expected[1] = NativeTransfer({target: address(router2), amount: 2});

    uint256 routerBefore = address(router).balance;
    uint256 router2Before = address(router2).balance;
    vm.deal(owner, 3);

    FulfillmentOrder memory order = _openFulfillmentOrder(
      new ERC20Allowance[](0), new ValidationParams[](0), ownerCalls, 0, block.timestamp
    );

    vm.recordLogs();

    vm.prank(owner);
    hub.fulfillOrderWithDelegatedAuthentication{value: 3}(
      order, address(0), '', _route(order, solverCalls), '', false
    );

    Vm.Log memory entry = _settlementLog();

    assertEq(entry.topics[3], SchemaHash.fulfillmentOrder(order), 'the fulfillment order hash');
    assertEq(
      entry.data,
      abi.encode(new ERC20Transfer[](0), new ERC721Transfer[](0), expected),
      'solver leg then owner leg, zero-value calls dropped'
    );

    // the listed amounts are what moved, so the event is not a claim about nothing
    assertEq(address(router).balance - routerBefore, 1, "the solver call's wei landed");
    assertEq(address(router2).balance - router2Before, 2, "the owner call's wei landed");
    assertEq(address(hub).balance, 0, 'nothing stranded in the hub');
    assertEq(router.callCount(), 2, 'both solver calls ran');
    assertEq(router2.callCount(), 2, 'both owner calls ran');
  }

  // -----------------------------------------------------------------------------------------
  // ROUTER — the per-call whitelist gate
  // -----------------------------------------------------------------------------------------

  /// ROUTER-01 — a router without the role is refused, and the order rolls back whole
  function test_ROUTER_01_unwhitelistedRouterIsRejected() public {
    RouterMock stranger = new RouterMock();

    ERC20Transfer[] memory erc20s =
      _erc20s(ERC20Transfer({token: token18, target: address(stranger), amount: AMOUNT}));
    GenericCall[] memory calls =
      _calls(GenericCall({router: address(stranger), value: 0, data: hex'01'}));

    uint256 ownerBalanceBefore = IERC20(token18).balanceOf(owner);

    vm.prank(owner);
    vm.expectRevert(
      abi.encodeWithSelector(
        IAccessControl.AccessControlUnauthorizedAccount.selector, address(stranger), ROUTER_ROLE
      )
    );
    hub.executeOrderWithDelegatedAuthentication(
      _openExecutionOrder(erc20s, calls, 0, block.timestamp), address(0), '', false
    );

    assertEq(stranger.callCount(), 0, 'never called');
    assertEq(IERC20(token18).balanceOf(owner), ownerBalanceBefore, 'the ERC20 leg rolled back too');
    assertEq(IERC20(token18).balanceOf(address(stranger)), 0, 'nothing reached it');
  }

  /// ROUTER-02 — a guardian can drop a router, and the very next order stops working
  function test_ROUTER_02_guardianRevokeStopsTheNextOrder() public {
    GenericCall[] memory calls = _calls(_routerCall(0, hex'01'));

    assertTrue(hub.hasRole(ROUTER_ROLE, address(router)), 'whitelisted at deploy');

    vm.prank(owner);
    hub.executeOrderWithDelegatedAuthentication(
      _openExecutionOrder(new ERC20Transfer[](0), calls, 0, block.timestamp), address(0), '', false
    );
    assertEq(router.callCount(), 1, 'the first order went through');

    vm.prank(guardian);
    hub.revokeRole(ROUTER_ROLE, address(router));
    assertFalse(hub.hasRole(ROUTER_ROLE, address(router)), 'role gone');

    vm.prank(owner);
    vm.expectRevert(
      abi.encodeWithSelector(
        IAccessControl.AccessControlUnauthorizedAccount.selector, address(router), ROUTER_ROLE
      )
    );
    hub.executeOrderWithDelegatedAuthentication(
      _openExecutionOrder(new ERC20Transfer[](0), calls, 0, block.timestamp), address(0), '', false
    );

    assertEq(router.callCount(), 1, 'and no second call happened');
  }

  /// ROUTER-03 — every whitelisted router in the list is called exactly once, with its own data
  function test_ROUTER_03_eachRouterCalledOnce() public {
    bytes memory dataA = hex'a1';
    bytes memory dataB = hex'b2';

    GenericCall[] memory calls = new GenericCall[](2);
    calls[0] = GenericCall({router: address(router), value: 0, data: dataA});
    calls[1] = GenericCall({router: address(router2), value: 0, data: dataB});

    vm.expectCall(address(router), 0, abi.encodeCall(IKSGenericRouter.ksExecute, (dataA)), 1);
    vm.expectCall(address(router2), 0, abi.encodeCall(IKSGenericRouter.ksExecute, (dataB)), 1);

    vm.prank(owner);
    hub.executeOrderWithDelegatedAuthentication(
      _openExecutionOrder(new ERC20Transfer[](0), calls, 0, block.timestamp), address(0), '', false
    );

    assertEq(router.callCount(), 1, 'router once');
    assertEq(router2.callCount(), 1, 'router2 once');
    assertEq(router.lastData(), dataA, 'router got its own payload');
    assertEq(router2.lastData(), dataB, 'router2 got its own payload');
  }

  // -----------------------------------------------------------------------------------------
  // LOCK — the transient msg sender, which is both the identity channel and the fulfillment lock
  // -----------------------------------------------------------------------------------------

  /**
   * LOCK-02 — orders nested inside execution router calls settle, and each level sees its owner
   * @dev Level 0 is `owner`'s execution, submitted by `owner` on the delegated rail or by
   * `relayer` on the Permit2 rail. Level `k` below the innermost calls `evils[k]`, which settles
   * level `k + 1` as an order it owns. The innermost level is an execution or a fulfillment and
   * calls `router`. Each `evils[k]` reads {msgSender} before and after its nested order, and level
   * 0 calls `router2` last, so a level that did not restore its predecessor's sender shows at the
   * next read.
   */
  function testFuzz_LOCK_02_nestedOrdersRestoreEachOwner(NestingParams memory p) public {
    uint256 depth = bound(p.depth, 1, 6);

    ReentrantRouterMock[] memory evils = new ReentrantRouterMock[](depth);
    for (uint256 i = 0; i < depth; i++) {
      evils[i] = _newReentrantRouter();
    }

    (ExecutionOrder memory top, bytes32[] memory hashes) =
      _buildChain(evils, p.innermostIsFulfillment);

    address topSubmitter = p.topViaPermit2 ? relayer : owner;
    bytes memory signature = p.topViaPermit2 ? _signExecutionWitness(top) : bytes('');

    vm.recordLogs();

    vm.prank(topSubmitter);
    if (p.topViaPermit2) {
      hub.executeOrderWithPermit2Signature(top, signature);
    } else {
      hub.executeOrderWithDelegatedAuthentication(top, address(0), '', false);
    }

    for (uint256 k = 0; k < depth; k++) {
      address levelOwner = k == 0 ? owner : address(evils[k - 1]);
      assertEq(evils[k].seenBefore(), levelOwner, 'a router sees its level owner on entry');
      assertEq(evils[k].seenAfter(), levelOwner, 'and again once the nested order returned');
    }

    assertEq(router.callCount(), 1, 'the innermost router ran once');
    assertEq(router.seenMsgSender(), address(evils[depth - 1]), 'the innermost owner');
    assertEq(router2.callCount(), 1, 'the trailing call of level 0 ran once');
    assertEq(router2.seenMsgSender(), owner, 'level 0 owner was restored after the whole chain');

    Vm.Log[] memory logs = _transferTokensLogs();
    assertEq(logs.length, depth + 1, 'one TransferTokens per level');
    _assertEmptySettlement(logs[0], topSubmitter, owner, hashes[0]);
    for (uint256 k = 1; k <= depth; k++) {
      address levelOwner = address(evils[k - 1]);
      _assertEmptySettlement(logs[k], levelOwner, levelOwner, hashes[k]);
    }

    assertEq(hub.msgSender(), address(0), 'nothing is recorded after the call');
  }

  /// LOCK-03 — the ERC721 receiver hook of a fulfillment cannot settle an order
  function test_LOCK_03_receiverHookIsRefusedInsideAFulfillment() public {
    ReentrantReceiverMock receiver = new ReentrantReceiverMock(address(hub));
    receiver.setReentry(_executionCall(_ownedExecution(address(receiver), new GenericCall[](0))));

    ERC721Approval[] memory approvals = new ERC721Approval[](1);
    approvals[0] = _nftApproval();
    address[] memory erc721Targets = new address[](1);
    erc721Targets[0] = address(receiver);

    FulfillmentOrder memory order = _fulfillmentOrder(
      ANY,
      new ERC20Allowance[](0),
      approvals,
      new ValidationParams[](0),
      new GenericCall[](0),
      ANY,
      0,
      block.timestamp + 1 hours
    );
    FulfillmentSolution memory solution =
      _solution(new address[](0), erc721Targets, new GenericCall[](0), block.timestamp + 1 hours);

    vm.prank(owner);
    vm.expectRevert(abi.encodeWithSelector(IMsgSender.AlreadyLocked.selector, owner));
    hub.fulfillOrderWithDelegatedAuthentication(order, address(0), '', solution, '', false);

    assertEq(nft.ownerOf(NFT_ID), owner, 'the NFT never moved');
  }

  /**
   * LOCK-04 — `revokeNonce` is outside the lock, so a router can reach it mid-order
   * @dev Recorded deliberately: the nonce is burned against the router, not the owner, so the
   * surface is reachable but does not let a router spend the owner's nonces.
   */
  function test_LOCK_04_revokeNonceIsReachableFromInsideAnOrder() public {
    ReentrantRouterMock evil = new ReentrantRouterMock(address(hub));
    vm.prank(admin);
    hub.grantRole(ROUTER_ROLE, address(evil));

    evil.setReentry(abi.encodeCall(IUnorderedNonce.revokeNonce, (7)));

    GenericCall[] memory calls = _calls(GenericCall({router: address(evil), value: 0, data: hex''}));

    vm.prank(owner);
    bytes[] memory results = hub.executeOrderWithDelegatedAuthentication(
      _openExecutionOrder(new ERC20Transfer[](0), calls, 0, block.timestamp), address(0), '', false
    );

    assertEq(results.length, 1, 'the order settled');
    assertEq(results[0].length, 0, 'revokeNonce returns nothing');
    assertEq(
      hub.nonces(lNonceKey(address(evil)), 0), 1 << 7, "burned against the router's own bitmap"
    );
    assertEq(hub.nonces(lNonceKey(owner), 0), 0, "and not against the owner's");
    assertEq(hub.msgSender(), address(0), 'the lock still released cleanly');
  }

  /**
   * LOCK-05 — a fulfillment nested in an execution releases its lock for the next sibling
   * @dev `evilA` settles a fulfillment and `evilB` then settles an execution, both inside the one
   * execution of `owner`. Both routers read {msgSender} as `owner` on either side of their nested
   * order, and the fulfillment's router sees `evilA`.
   */
  function test_LOCK_05_fulfillmentLockIsReleasedForTheNextSibling() public {
    ReentrantRouterMock evilA = _newReentrantRouter();
    ReentrantRouterMock evilB = _newReentrantRouter();

    FulfillmentOrder memory fulfillment = _ownedFulfillment(address(evilA));
    evilA.setReentry(_fulfillmentCall(fulfillment, _calls(_routerCall(0, hex'01'))));

    ExecutionOrder memory sibling = _ownedExecution(address(evilB), new GenericCall[](0));
    evilB.setReentry(_executionCall(sibling));

    GenericCall[] memory calls = new GenericCall[](3);
    calls[0] = _callTo(address(evilA));
    calls[1] = _callTo(address(evilB));
    calls[2] = GenericCall({router: address(router2), value: 0, data: hex'02'});
    ExecutionOrder memory top = _ownedExecution(owner, calls);

    vm.recordLogs();

    vm.prank(owner);
    hub.executeOrderWithDelegatedAuthentication(top, address(0), '', false);

    assertEq(router.seenMsgSender(), address(evilA), 'the fulfillment router sees its owner');
    assertEq(evilA.seenBefore(), owner, 'evilA is called under owner');
    assertEq(evilA.seenAfter(), owner, 'and owner is restored after its fulfillment');
    assertEq(evilB.seenBefore(), owner, 'evilB is called under owner');
    assertEq(evilB.seenAfter(), owner, 'and its execution settled after the fulfillment released');
    assertEq(router2.seenMsgSender(), owner, 'the trailing call runs under owner');

    Vm.Log[] memory logs = _transferTokensLogs();
    assertEq(logs.length, 3, 'one TransferTokens per order');
    _assertEmptySettlement(logs[0], owner, owner, SchemaHash.executionOrder(top));
    _assertEmptySettlement(
      logs[1], address(evilA), address(evilA), SchemaHash.fulfillmentOrder(fulfillment)
    );
    _assertEmptySettlement(
      logs[2], address(evilB), address(evilB), SchemaHash.executionOrder(sibling)
    );

    assertEq(hub.msgSender(), address(0), 'nothing is recorded after the call');
  }

  /**
   * LOCK-06 — no entry point settles an order inside a fulfillment, at depth one or two
   * @dev The refusal names the owner of the fulfillment in progress, never the reentering order's.
   * Through an execution, that fulfillment is the nested one owned by `evilOuter`.
   */
  function testFuzz_LOCK_06_noOrderSettlesInsideAFulfillment(LockedReentryParams memory p) public {
    uint256 entry = bound(p.entry, 0, 3);
    ReentrantRouterMock evil = _newReentrantRouter();
    evil.setReentry(_wellFormedCall(entry, address(evil)));
    GenericCall[] memory solverCalls = _calls(_callTo(address(evil)));

    if (!p.viaExecution) {
      vm.prank(owner);
      vm.expectRevert(abi.encodeWithSelector(IMsgSender.AlreadyLocked.selector, owner));
      hub.fulfillOrderWithDelegatedAuthentication(
        _ownedFulfillment(owner),
        address(0),
        '',
        _route(_ownedFulfillment(owner), solverCalls),
        '',
        false
      );
      return;
    }

    ReentrantRouterMock evilOuter = _newReentrantRouter();
    evilOuter.setReentry(_fulfillmentCall(_ownedFulfillment(address(evilOuter)), solverCalls));

    vm.prank(owner);
    vm.expectRevert(abi.encodeWithSelector(IMsgSender.AlreadyLocked.selector, address(evilOuter)));
    hub.executeOrderWithDelegatedAuthentication(
      _ownedExecution(owner, _calls(_callTo(address(evilOuter)))), address(0), '', false
    );
  }

  /**
   * LOCK-07 — a nested order spends only value the nested call was sent
   * @dev With the hub holding a float, the outer execution may spend its own value after a nested
   * order returned, but a nested order sent no value cannot spend the outer order's.
   */
  function test_LOCK_07_nestedOrderCannotSpendTheOuterValue() public {
    ReentrantRouterMock evil = _newReentrantRouter();
    vm.deal(address(hub), PREFUND);
    uint256 routerBalanceBefore = address(router).balance;

    // (a) the nested order spends nothing and the outer order spends its value afterwards
    evil.setReentry(_executionCall(_ownedExecution(address(evil), new GenericCall[](0))));
    GenericCall[] memory outerCalls = new GenericCall[](2);
    outerCalls[0] = _callTo(address(evil));
    outerCalls[1] = _routerCall(VALUE, hex'01');
    vm.deal(owner, VALUE);

    vm.prank(owner);
    hub.executeOrderWithDelegatedAuthentication{value: VALUE}(
      _ownedExecution(owner, outerCalls), address(0), '', false
    );

    assertEq(router.callCount(), 1, 'the outer router call ran');
    assertEq(router.lastValue(), VALUE, 'with the outer value');
    assertEq(address(router).balance - routerBalanceBefore, VALUE, 'and the value landed');
    assertEq(address(hub).balance, PREFUND, "the hub's float is intact");

    // (b) the nested order tries to spend the value the outer order was sent
    evil.setReentry(
      _executionCall(_ownedExecution(address(evil), _calls(_routerCall(VALUE, hex'02'))))
    );
    vm.deal(owner, VALUE);

    vm.prank(owner);
    vm.expectRevert(abi.encodeWithSelector(NativeSpendGuard.NativeOverspent.selector, VALUE, 0));
    hub.executeOrderWithDelegatedAuthentication{value: VALUE}(
      _ownedExecution(owner, _calls(_callTo(address(evil)))), address(0), '', false
    );

    assertEq(router.callCount(), 1, 'the nested router call rolled back');
    assertEq(address(hub).balance, PREFUND, "the hub's float is intact");
    assertEq(owner.balance, VALUE, 'the value went back to the sender');
  }

  // -----------------------------------------------------------------------------------------
  // Helpers
  // -----------------------------------------------------------------------------------------

  /// @dev A router that may be called by the hub and calls back into it
  function _newReentrantRouter() internal returns (ReentrantRouterMock evil) {
    evil = new ReentrantRouterMock(address(hub));
    vm.prank(admin);
    hub.grantRole(ROUTER_ROLE, address(evil));
  }

  /// @dev A call to `target` with no value and no data
  function _callTo(address target) internal pure returns (GenericCall memory) {
    return GenericCall({router: target, value: 0, data: hex''});
  }

  /**
   * @dev An execution order owned by `orderOwner`, with no transfers, so it takes the owner path
   * when `orderOwner` submits it
   */
  function _ownedExecution(address orderOwner, GenericCall[] memory calls)
    internal
    view
    returns (ExecutionOrder memory order)
  {
    order = _openExecutionOrder(new ERC20Transfer[](0), calls, 0, block.timestamp + 1 hours);
    order.owner = orderOwner;
  }

  /// @dev As {_ownedExecution}, for a fulfillment order with no legs and no owner calls
  function _ownedFulfillment(address orderOwner)
    internal
    view
    returns (FulfillmentOrder memory order)
  {
    order = _openFulfillmentOrder(
      new ERC20Allowance[](0),
      new ValidationParams[](0),
      new GenericCall[](0),
      0,
      block.timestamp + 1 hours
    );
    order.owner = orderOwner;
  }

  function _executionCall(ExecutionOrder memory order) internal pure returns (bytes memory) {
    return abi.encodeCall(
      IKSAllowanceHubV2.executeOrderWithDelegatedAuthentication, (order, address(0), '', false)
    );
  }

  function _fulfillmentCall(FulfillmentOrder memory order, GenericCall[] memory solverCalls)
    internal
    view
    returns (bytes memory)
  {
    return abi.encodeCall(
      IKSAllowanceHubV2.fulfillOrderWithDelegatedAuthentication,
      (order, address(0), '', _route(order, solverCalls), '', false)
    );
  }

  /**
   * @dev A well-formed order owned by `orderOwner` for settlement entry point `entry`: 0 and 1 are
   * the execution rails, 2 and 3 the fulfillment rails, each pair delegated then Permit2. Only the
   * lock can refuse it.
   */
  function _wellFormedCall(uint256 entry, address orderOwner) internal view returns (bytes memory) {
    ExecutionOrder memory execution = _ownedExecution(orderOwner, new GenericCall[](0));
    FulfillmentOrder memory fulfillment = _ownedFulfillment(orderOwner);
    FulfillmentSolution memory solution = _route(fulfillment, new GenericCall[](0));

    if (entry == 0) return _executionCall(execution);
    if (entry == 1) {
      return abi.encodeCall(IKSAllowanceHubV2.executeOrderWithPermit2Signature, (execution, ''));
    }
    if (entry == 2) return _fulfillmentCall(fulfillment, new GenericCall[](0));
    return abi.encodeCall(
      IKSAllowanceHubV2.fulfillOrderWithPermit2Signature, (fulfillment, '', solution, '')
    );
  }

  /**
   * @dev Builds the nested orders of {testFuzz_LOCK_02_nestedOrdersRestoreEachOwner} and arms each
   * of `evils` to settle the next level, returning level 0 and the order hash of every level
   */
  function _buildChain(ReentrantRouterMock[] memory evils, bool innermostIsFulfillment)
    internal
    returns (ExecutionOrder memory top, bytes32[] memory hashes)
  {
    uint256 depth = evils.length;
    hashes = new bytes32[](depth + 1);

    // The innermost level is owned by the last router and calls `router`
    bytes memory reentry;
    if (innermostIsFulfillment) {
      FulfillmentOrder memory inner = _ownedFulfillment(address(evils[depth - 1]));
      hashes[depth] = SchemaHash.fulfillmentOrder(inner);
      reentry = _fulfillmentCall(inner, _calls(_routerCall(0, hex'01')));
    } else {
      ExecutionOrder memory inner =
        _ownedExecution(address(evils[depth - 1]), _calls(_routerCall(0, hex'01')));
      hashes[depth] = SchemaHash.executionOrder(inner);
      reentry = _executionCall(inner);
    }

    // Level `level` is owned by the router above it and calls the router at its own index
    for (uint256 level = depth - 1; level >= 1; level--) {
      evils[level].setReentry(reentry);
      ExecutionOrder memory order =
        _ownedExecution(address(evils[level - 1]), _calls(_callTo(address(evils[level]))));
      hashes[level] = SchemaHash.executionOrder(order);
      reentry = _executionCall(order);
    }
    evils[0].setReentry(reentry);

    GenericCall[] memory calls = new GenericCall[](2);
    calls[0] = _callTo(address(evils[0]));
    calls[1] = GenericCall({router: address(router2), value: 0, data: hex'02'});
    top = _ownedExecution(owner, calls);
    hashes[0] = SchemaHash.executionOrder(top);
  }

  /// @dev Every `TransferTokens` the hub emitted, in emission order
  function _transferTokensLogs() internal returns (Vm.Log[] memory logs) {
    Vm.Log[] memory entries = vm.getRecordedLogs();

    uint256 found;
    logs = new Vm.Log[](entries.length);
    for (uint256 i = 0; i < entries.length; i++) {
      if (entries[i].emitter != address(hub)) continue;
      if (entries[i].topics.length == 0) continue;
      if (entries[i].topics[0] != TRANSFER_TOKENS_TOPIC) continue;

      logs[found++] = entries[i];
    }

    assembly ('memory-safe') {
      mstore(logs, found)
    }
  }

  /**
   * @dev Asserts a `TransferTokens` of an order that moves nothing, owned by `orderOwner` and
   * submitted by `submitter`
   */
  function _assertEmptySettlement(
    Vm.Log memory entry,
    address submitter,
    address orderOwner,
    bytes32 orderHash
  ) internal view {
    assertEq(entry.topics.length, 4, 'caller, owner and the order hash are indexed');
    assertEq(_topicAddress(entry.topics[1]), submitter, 'the submitter');
    assertEq(_topicAddress(entry.topics[2]), orderOwner, 'the owner');
    assertEq(entry.topics[3], orderHash, 'the order hash');
    assertEq(
      entry.data,
      abi.encode(new ERC20Transfer[](0), new ERC721Transfer[](0), new NativeTransfer[](0)),
      'nothing moved'
    );
  }
}
