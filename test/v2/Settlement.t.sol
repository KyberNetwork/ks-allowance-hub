// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Vm} from 'forge-std/Vm.sol';

import {HubBase} from 'test/v2/base/HubBase.sol';

import {EchoRouterMock, ReentrantRouterMock, RouterMock} from 'test/v2/mocks/RouterMock.sol';
import {ReentrantReceiverMock} from 'test/v2/mocks/TokenMocks.sol';

import {IMsgSender} from 'src/base/interfaces/IMsgSender.sol';
import {IUnorderedNonce} from 'src/base/interfaces/IUnorderedNonce.sol';

import {IKSAllowanceHubV2} from 'src/v2/interfaces/IKSAllowanceHubV2.sol';
import {ERC20Transfer} from 'src/v2/types/ERC20Transfer.sol';
import {ERC721Transfer} from 'src/v2/types/ERC721Transfer.sol';
import {ExecutionOrder} from 'src/v2/types/ExecutionOrder.sol';
import {FulfillmentOrder} from 'src/v2/types/FulfillmentOrder.sol';
import {GenericCall} from 'src/v2/types/GenericCall.sol';
import {NativeTransfer} from 'src/v2/types/NativeTransfer.sol';
import {ValidationParams} from 'src/v2/types/ValidationParams.sol';

import {IAccessControl} from 'openzeppelin-contracts/contracts/access/IAccessControl.sol';
import {IERC20} from 'openzeppelin-contracts/contracts/token/ERC20/IERC20.sol';

/**
 * @notice `SET-01..04`, `OWN-07`, `ROUTER-01..03` and `LOCK-01..04` — the settlement tail shared by
 * all four entry points.
 * @dev The role constant, the `TransferTokens` topic and the router's own function signature are
 * written out rather than imported: an expected value taken from the contract under test would agree
 * with a wrong one. The topic lives in {HubBase}, which is where the log picker needs it.
 */
contract SettlementTest is HubBase {
  uint160 internal constant AMOUNT = 5 ether;

  bytes32 internal constant ROUTER_ROLE = keccak256('WHITELISTED_ROUTER_ROLE');

  /// @dev Transcribed from {IKSGenericRouter}, so a wrong production selector cannot agree with it
  string internal constant S_KS_EXECUTE = 'ksExecute(bytes)';

  // -----------------------------------------------------------------------------------------
  // SET — the settlement event and the results array
  // -----------------------------------------------------------------------------------------

  /**
   * SET-01 — the whole `TransferTokens` payload of a relayed order, byte for byte
   * @dev `orderHash` joined the indexed fields in the restructure, so there are four topics now and
   * the third is compared against the order hash rebuilt from the hand-written literals.
   */
  function test_SET_01_transferTokensPayload() public {
    ERC20Transfer[] memory erc20s = _erc20s(_wethTransfer(AMOUNT));
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
    assertEq(entry.topics[3], lExecutionOrderHash(order), 'the order hash the owner signed');
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
      new ERC20Transfer[](0), new ValidationParams[](0), ownerCalls, 0, block.timestamp
    );

    vm.recordLogs();

    vm.prank(owner);
    hub.fulfillOrderWithDelegatedAuthentication{value: 3}(
      order, address(0), '', _route(solverCalls), '', false
    );

    Vm.Log memory entry = _settlementLog();

    assertEq(entry.topics[3], lFulfillmentOrderHash(order), 'the fulfillment order hash');
    assertEq(
      entry.data,
      abi.encode(new ERC20Transfer[](0), new ERC721Transfer[](0), expected),
      'solver leg then owner leg, zero-value calls dropped'
    );

    // the listed amounts are what actually moved, so the event is not a claim about nothing
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
      _erc20s(ERC20Transfer({token: WETH, target: address(stranger), amount: AMOUNT}));
    GenericCall[] memory calls =
      _calls(GenericCall({router: address(stranger), value: 0, data: hex'01'}));

    uint256 ownerBalanceBefore = IERC20(WETH).balanceOf(owner);

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
    assertEq(IERC20(WETH).balanceOf(owner), ownerBalanceBefore, 'the ERC20 leg rolled back too');
    assertEq(IERC20(WETH).balanceOf(address(stranger)), 0, 'nothing reached it');
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

    vm.expectCall(address(router), 0, abi.encodeWithSignature(S_KS_EXECUTE, dataA), 1);
    vm.expectCall(address(router2), 0, abi.encodeWithSignature(S_KS_EXECUTE, dataB), 1);

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
  // LOCK — the transient locker, which is both the identity channel and the reentrancy guard
  // -----------------------------------------------------------------------------------------

  /**
   * LOCK-01 — a router sees the asset owner, not the submitter, and only while the order runs
   * @dev The inside-the-call reading is taken from {RouterMock-seenMsgSender} rather than from a
   * second transaction, because CI runs `--isolate` and transient storage does not survive one.
   */
  function test_LOCK_01_routerSeesTheOwner() public {
    ERC20Transfer[] memory erc20s = _erc20s(_wethTransfer(AMOUNT));
    GenericCall[] memory calls = _calls(_routerCall(0, hex'01'));
    uint256 deadline = block.timestamp + 1 hours;

    ExecutionOrder memory order = _openExecutionOrder(erc20s, calls, 12, deadline);
    bytes memory signature = _signExecutionWitness(order);

    assertEq(hub.msgSender(), address(0), 'no locker before the order');

    vm.prank(relayer);
    hub.executeOrderWithPermit2Signature(order, signature);

    assertEq(router.seenMsgSender(), owner, 'the router was shown the owner');
    assertTrue(router.seenMsgSender() != relayer, 'and not the relayer that submitted');
    assertEq(hub.msgSender(), address(0), 'the lock is released again');
  }

  /// LOCK-02 — a router that calls back into an entry point is stopped by the lock
  function test_LOCK_02_routerReentryIsLocked() public {
    ReentrantRouterMock evil = new ReentrantRouterMock(address(hub));
    vm.prank(admin);
    hub.grantRole(ROUTER_ROLE, address(evil));

    uint256 deadline = block.timestamp + 1 hours;
    evil.setReentry(_emptyOrderCalldata(deadline));

    GenericCall[] memory calls = _calls(GenericCall({router: address(evil), value: 0, data: hex''}));

    vm.prank(owner);
    vm.expectRevert(IMsgSender.AlreadyLocked.selector);
    hub.executeOrderWithDelegatedAuthentication(
      _openExecutionOrder(new ERC20Transfer[](0), calls, 0, deadline), address(0), '', false
    );
  }

  /// LOCK-03 — the same guard covers the ERC721 leg, where the receiver hook is the way back in
  function test_LOCK_03_erc721ReceiverReentryIsLocked() public {
    ReentrantReceiverMock receiver = new ReentrantReceiverMock(address(hub));

    uint256 deadline = block.timestamp + 1 hours;
    receiver.setReentry(_emptyOrderCalldata(deadline));

    ERC721Transfer[] memory nfts = _erc721s(_nftTransfer(address(receiver)));

    vm.prank(owner);
    vm.expectRevert(IMsgSender.AlreadyLocked.selector);
    hub.executeOrderWithDelegatedAuthentication(
      _executionOrder(ANY, new ERC20Transfer[](0), nfts, new GenericCall[](0), 0, deadline),
      address(0),
      '',
      false
    );

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

  // -----------------------------------------------------------------------------------------
  // Helpers
  // -----------------------------------------------------------------------------------------

  /// @dev The reentry payload both mocks use: a well-formed order that only the lock can refuse
  function _emptyOrderCalldata(uint256 deadline) internal view returns (bytes memory) {
    return abi.encodeCall(
      IKSAllowanceHubV2.executeOrderWithDelegatedAuthentication,
      (
        _openExecutionOrder(new ERC20Transfer[](0), new GenericCall[](0), 0, deadline),
        address(0),
        '',
        false
      )
    );
  }
}
