// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Vm} from 'forge-std/Vm.sol';

import {HubBase} from 'test/v2/base/HubBase.sol';

import {ReentrantRouterMock, RouterMock} from 'test/v2/mocks/RouterMock.sol';
import {ReentrantReceiverMock} from 'test/v2/mocks/TokenMocks.sol';

import {IKSGenericRouter} from 'src/base/interfaces/IKSGenericRouter.sol';
import {IMsgSender} from 'src/base/interfaces/IMsgSender.sol';
import {IUnorderedNonce} from 'src/base/interfaces/IUnorderedNonce.sol';

import {IKSAllowanceHubV2} from 'src/v2/interfaces/IKSAllowanceHubV2.sol';
import {ERC20Transfer} from 'src/v2/types/ERC20Transfer.sol';
import {ERC721Transfer} from 'src/v2/types/ERC721Transfer.sol';
import {GenericCall} from 'src/v2/types/GenericCall.sol';
import {NativeTransfer} from 'src/v2/types/NativeTransfer.sol';

import {IAccessControl} from 'openzeppelin-contracts/contracts/access/IAccessControl.sol';
import {IERC20} from 'openzeppelin-contracts/contracts/token/ERC20/IERC20.sol';

/// @notice Router that hands back who it is and what it was given, so results pin call order.
/// @dev {RouterMock} returns a per-router counter, which cannot distinguish two routers
/// interleaved in one order; this one can, which is what `SET-04` needs.
contract EchoRouterMock is IKSGenericRouter {
  function ksExecute(bytes calldata data) external payable returns (bytes memory) {
    return abi.encode(address(this), data);
  }
}

/**
 * @notice SET-01..04, ROUTER-01..03, LOCK-01..04 — the settlement tail of both entry points.
 * @dev The role constant and the `TransferTokens` signature are written out here rather than
 * imported: an expected value taken from the contract under test would agree with a wrong one.
 */
contract SettlementTest is HubBase {
  uint160 internal constant AMOUNT = 5 ether;

  /// @dev Transcribed from {IKSAllowanceHubV2-TransferTokens}, never imported
  bytes32 internal constant TRANSFER_TOKENS_TOPIC = keccak256(
    'TransferTokens(address,address,(address,address,uint160)[],(address,uint256,address)[],(address,uint256)[])'
  );

  bytes32 internal constant ROUTER_ROLE = keccak256('WHITELISTED_ROUTER_ROLE');

  // -----------------------------------------------------------------------------------------
  // SET — the settlement event and the results array
  // -----------------------------------------------------------------------------------------

  /// SET-01 — the whole `TransferTokens` payload of a relayed order, byte for byte
  function test_SET_01_transferTokensPayload() public {
    ERC20Transfer[] memory erc20s = _erc20s(_wethTransfer(AMOUNT));
    ERC721Transfer[] memory nfts = _erc721s(_nftTransfer(address(router)));
    GenericCall[] memory calls = _calls(_routerCall(0, hex'abcd'));
    uint256 deadline = block.timestamp + 1 hours;

    bytes memory signature = _signExecutionOrder(erc20s, nfts, calls, ANY, 11, deadline);

    vm.recordLogs();

    vm.prank(relayer);
    hub.transferAndExecute(
      owner,
      erc20s,
      nfts,
      calls,
      deadline,
      _flags(true, false, false),
      _permit2AuthData(11, signature)
    );

    Vm.Log memory entry = _settlementLog();

    assertEq(entry.topics.length, 3, 'caller and owner are indexed');
    assertEq(_topicAddress(entry.topics[1]), relayer, 'caller is the submitter, not the owner');
    assertEq(_topicAddress(entry.topics[2]), owner, 'owner is the account the assets came from');
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
    hub.transferAndExecute{value: 1}(
      owner,
      new ERC20Transfer[](0),
      new ERC721Transfer[](0),
      calls,
      block.timestamp,
      _flags(false, false, false),
      ''
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

  /// SET-03 — an order that moves nothing and calls nobody still settles and still reports
  function test_SET_03_emptyOrderStillEmits() public {
    ERC20Transfer[] memory noErc20s = new ERC20Transfer[](0);
    ERC721Transfer[] memory noNfts = new ERC721Transfer[](0);

    vm.recordLogs();

    vm.prank(owner);
    (bytes[] memory results, uint256 gasUsed) = hub.transferAndExecute(
      owner,
      noErc20s,
      noNfts,
      new GenericCall[](0),
      block.timestamp,
      _flags(false, false, false),
      ''
    );

    assertEq(results.length, 0, 'no calls, no results');
    assertGt(gasUsed, 0, 'gas is measured');
    assertLt(gasUsed, 1_000_000, 'and it is the inner cost, not the block gas limit');

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
    (bytes[] memory results,) = hub.transferAndExecute(
      owner,
      new ERC20Transfer[](0),
      new ERC721Transfer[](0),
      calls,
      block.timestamp,
      _flags(false, false, false),
      ''
    );

    assertEq(results.length, 3, 'one result per call');
    for (uint256 i = 0; i < 3; i++) {
      (address seenRouter, bytes memory seenData) = abi.decode(results[i], (address, bytes));
      assertEq(seenRouter, calls[i].router, 'result came from the router at the same index');
      assertEq(seenData, calls[i].data, 'and carries the data sent to it');
    }
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
    hub.transferAndExecute(
      owner,
      erc20s,
      new ERC721Transfer[](0),
      calls,
      block.timestamp,
      _flags(false, false, false),
      ''
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
    hub.transferAndExecute(
      owner,
      new ERC20Transfer[](0),
      new ERC721Transfer[](0),
      calls,
      block.timestamp,
      _flags(false, false, false),
      ''
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
    hub.transferAndExecute(
      owner,
      new ERC20Transfer[](0),
      new ERC721Transfer[](0),
      calls,
      block.timestamp,
      _flags(false, false, false),
      ''
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
    hub.transferAndExecute(
      owner,
      new ERC20Transfer[](0),
      new ERC721Transfer[](0),
      calls,
      block.timestamp,
      _flags(false, false, false),
      ''
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

    bytes memory signature =
      _signExecutionOrder(erc20s, new ERC721Transfer[](0), calls, ANY, 12, deadline);

    assertEq(hub.msgSender(), address(0), 'no locker before the order');

    vm.prank(relayer);
    hub.transferAndExecute(
      owner,
      erc20s,
      new ERC721Transfer[](0),
      calls,
      deadline,
      _flags(true, false, false),
      _permit2AuthData(12, signature)
    );

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
    hub.transferAndExecute(
      owner,
      new ERC20Transfer[](0),
      new ERC721Transfer[](0),
      calls,
      deadline,
      _flags(false, false, false),
      ''
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
    hub.transferAndExecute(
      owner,
      new ERC20Transfer[](0),
      nfts,
      new GenericCall[](0),
      deadline,
      _flags(false, false, false),
      ''
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
    (bytes[] memory results,) = hub.transferAndExecute(
      owner,
      new ERC20Transfer[](0),
      new ERC721Transfer[](0),
      calls,
      block.timestamp,
      _flags(false, false, false),
      ''
    );

    assertEq(results.length, 1, 'the order settled');
    assertEq(results[0].length, 0, 'revokeNonce returns nothing');
    assertEq(hub.nonces(address(evil), 0), 1 << 7, "burned against the router's own bitmap");
    assertEq(hub.nonces(owner, 0), 0, "and not against the owner's");
    assertEq(hub.msgSender(), address(0), 'the lock still released cleanly');
  }

  // -----------------------------------------------------------------------------------------
  // Helpers
  // -----------------------------------------------------------------------------------------

  /// @dev The reentry payload both mocks use: a well-formed order that only the lock can refuse
  function _emptyOrderCalldata(uint256 deadline) internal view returns (bytes memory) {
    return abi.encodeCall(
      IKSAllowanceHubV2.transferAndExecute,
      (
        owner,
        new ERC20Transfer[](0),
        new ERC721Transfer[](0),
        new GenericCall[](0),
        deadline,
        _flags(false, false, false),
        ''
      )
    );
  }

  /// @dev Picks the single `TransferTokens` the hub emitted out of the whole fork's log stream
  function _settlementLog() internal returns (Vm.Log memory entry) {
    Vm.Log[] memory entries = vm.getRecordedLogs();

    uint256 found;
    for (uint256 i = 0; i < entries.length; i++) {
      if (entries[i].emitter != address(hub)) continue;
      if (entries[i].topics.length == 0) continue;
      if (entries[i].topics[0] != TRANSFER_TOKENS_TOPIC) continue;

      entry = entries[i];
      found++;
    }

    assertEq(found, 1, 'exactly one TransferTokens per order');
  }

  function _topicAddress(bytes32 topic) internal pure returns (address) {
    return address(uint160(uint256(topic)));
  }
}
