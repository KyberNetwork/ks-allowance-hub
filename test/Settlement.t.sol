// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Vm} from 'forge-std/Vm.sol';

import {SchemaHash} from 'test/base/SchemaHash.sol';

import {AuthenticatorBase} from 'test/authenticators/base/AuthenticatorBase.sol';

import {EchoRouterMock, ReentrantRouterMock, RouterMock} from 'test/mocks/RouterMock.sol';
import {ReentrantReceiverMock} from 'test/mocks/TokenMocks.sol';

import {NativeSpendGuard} from 'src/base/NativeSpendGuard.sol';
import {IKSAllowanceHubV2} from 'src/interfaces/IKSAllowanceHubV2.sol';
import {
  ITwoTiersOrderAuthenticator
} from 'src/interfaces/authenticators/ITwoTiersOrderAuthenticator.sol';
import {IKSGenericRouter} from 'src/interfaces/base/IKSGenericRouter.sol';
import {IUnorderedNonce} from 'src/interfaces/base/IUnorderedNonce.sol';
import {ERC20Allowance} from 'src/types/ERC20Allowance.sol';
import {ERC20Transfer} from 'src/types/ERC20Transfer.sol';
import {ERC721Approval} from 'src/types/ERC721Approval.sol';
import {ERC721Transfer} from 'src/types/ERC721Transfer.sol';
import {ExecutionOrder} from 'src/types/ExecutionOrder.sol';
import {FulfillmentOrder} from 'src/types/FulfillmentOrder.sol';
import {FulfillmentSolution} from 'src/types/FulfillmentSolution.sol';
import {GenericCall} from 'src/types/GenericCall.sol';
import {NativeTransfer} from 'src/types/NativeTransfer.sol';
import {ValidationParams} from 'src/types/ValidationParams.sol';
import {AuthKey} from 'src/types/base/AuthKey.sol';

import {IAccessControl} from 'openzeppelin-contracts/contracts/access/IAccessControl.sol';
import {IERC20} from 'openzeppelin-contracts/contracts/token/ERC20/IERC20.sol';

/**
 * @notice `SET-01..04`, `CLIENT-01..02`, `OWN-07`, `ROUTER-01..03` and `NEST-01..05` — the final
 * settlement steps shared by all four entry points.
 * @dev The role constant, the `TransferTokens` topic and the router's own function signature are
 * written out rather than imported: an expected value taken from the contract under test would
 * agree with a wrong one. The topic lives in {HubBase}, which is where the log picker needs it.
 */
contract SettlementTest is AuthenticatorBase {
  uint160 internal constant AMOUNT = 5 ether;

  bytes32 internal constant ROUTER_ROLE = keccak256('WHITELISTED_ROUTER_ROLE');

  /// @dev The native balance the hub holds before a call, so a nested order has native value to
  /// overspend
  uint256 internal constant PREFUND = 1 ether;
  uint256 internal constant VALUE = 1 ether;

  /// @dev Permit2 does not expose this in the vendored interface, so it is written out here
  bytes4 internal constant PERMIT2_INVALID_SIGNER = bytes4(keccak256('InvalidSigner()'));

  AuthKey internal key;

  /// @dev Inputs of {testFuzz_CLIENT_01_clientDataIsEmittedAsGiven} and
  /// {testFuzz_CLIENT_02_clientDataIsCoveredByTheSignature}; `entryPoint` is bounded to `[0, 3]`
  struct ClientDataFuzz {
    uint8 entryPoint;
    bytes clientData;
  }

  /// @dev Inputs of {testFuzz_NEST_01_nestedOrdersRestoreEachOwner}
  struct NestingParams {
    uint256 depth;
    bool innermostIsFulfillment;
    bool topViaPermit2;
  }

  /// @dev Inputs of {testFuzz_NEST_03_anOrderSettlesInsideAnotherOnEveryEntryPoint}
  struct NestedEntryParams {
    bool outerIsFulfillment;
    bool outerViaPermit2;
    uint256 nestedEntry;
    bool wrapped;
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
    uint256 expiration = vm.getBlockTimestamp() + 1 hours;

    ExecutionOrder memory order = _executionOrder(ANY, erc20s, nfts, calls, 11, expiration);
    bytes memory signature = _signExecutionWitness(order);

    vm.recordLogs();

    vm.prank(relayer);
    hub.executeOrderWithPermit2Signature(order, signature);

    Vm.Log memory entry = _settlementLog();

    assertEq(entry.topics.length, 4, 'caller, owner and the order hash are indexed');
    assertEq(_topicAddress(entry.topics[1]), relayer, 'caller is the submitter, not the owner');
    assertEq(_topicAddress(entry.topics[2]), owner, 'owner is the account the assets came from');
    assertEq(entry.topics[3], SchemaHash.executionOrder(order), 'the order hash the owner signed');
    // No call carries value, so the native transfers are empty
    assertEq(entry.data, abi.encode(erc20s, nfts, new NativeTransfer[](0), bytes('')), 'payload');
  }

  function setUp() public override {
    super.setUp();
    key = _secpKey(masterSigner, vm.getBlockTimestamp() + 30 days);
  }

  // -----------------------------------------------------------------------------------------
  // CLIENT — the order's client data
  // -----------------------------------------------------------------------------------------

  /**
   * CLIENT-01 — the `TransferTokens` of a settled order carries exactly the order's client data
   * @dev Over the four entry points, and over any client data drawn: delegated execution and
   * Permit2 execution submitted by the relayer, delegated fulfillment and Permit2 fulfillment
   * submitted by the solver.
   */
  function testFuzz_CLIENT_01_clientDataIsEmittedAsGiven(ClientDataFuzz memory p) public {
    uint8 entry = uint8(bound(p.entryPoint, 0, 3));

    uint256 before = IERC20(token18).balanceOf(address(router));

    _submitWithClientData(entry, p.clientData, p.clientData, 0);

    assertEq(IERC20(token18).balanceOf(address(router)) - before, AMOUNT, 'the order settled');
  }

  /**
   * CLIENT-02 — the owner's signature covers the order's client data
   * @dev The order is authenticated, or its witness signed, with client data A and submitted with
   * A and one more byte. Each entry point refuses it with the error of its own check and nothing
   * moves.
   */
  function testFuzz_CLIENT_02_clientDataIsCoveredByTheSignature(ClientDataFuzz memory p) public {
    uint8 entry = uint8(bound(p.entryPoint, 0, 3));
    bytes memory submitted = abi.encodePacked(p.clientData, uint8(0x01));

    uint256 before = IERC20(token18).balanceOf(address(router));
    uint256 ownerBefore = IERC20(token18).balanceOf(owner);

    _submitWithClientData(entry, p.clientData, submitted, 1);

    assertEq(IERC20(token18).balanceOf(address(router)), before, 'nothing reached the router');
    assertEq(IERC20(token18).balanceOf(owner), ownerBefore, 'nothing left the owner');
  }

  /// @dev CLIENT-02 with empty signed client data on every entry point, the case a fuzzed draw
  /// reaches only by chance
  function test_CLIENT_02b_emptyClientDataIsCoveredByTheSignature() public {
    for (uint8 entry = 0; entry < 4; entry++) {
      uint256 snapshot = vm.snapshotState();

      _submitWithClientData(entry, '', hex'01', 1);

      vm.revertToState(snapshot);
    }
  }

  /**
   * @dev Authenticates or signs an order carrying `signedData`, and submits the same order carrying
   * `submittedData` on the entry point `entry`. When the two are equal the call is expected to emit
   * `TransferTokens` with that data; otherwise it is expected to revert with the error of the
   * entry point's own check.
   */
  function _submitWithClientData(
    uint8 entry,
    bytes memory signedData,
    bytes memory submittedData,
    uint256 nonce
  ) internal {
    bool matches = keccak256(signedData) == keccak256(submittedData);
    uint256 expiration = vm.getBlockTimestamp() + 1 hours;
    ERC20Transfer[] memory erc20s = _erc20s(_tokenTransfer(AMOUNT));

    if (entry < 2) {
      ExecutionOrder memory signed =
        _openExecutionOrder(erc20s, new GenericCall[](0), nonce, expiration);
      signed.clientData = signedData;
      ExecutionOrder memory order =
        _openExecutionOrder(erc20s, new GenericCall[](0), nonce, expiration);
      order.clientData = submittedData;

      if (entry == 0) {
        _delegateKeyThroughHub(key);
        bytes memory auth = _executionAuthData(signed, key, masterKeyPk);
        _expectClientData(
          matches,
          ITwoTiersOrderAuthenticator.InvalidOrderSignature.selector,
          relayer,
          SchemaHash.executionOrder(order),
          erc20s,
          submittedData
        );
        vm.prank(relayer);
        hub.executeOrderWithDelegatedAuthentication(order, address(authenticator), auth, false);
      } else {
        bytes memory signature = _signExecutionWitness(signed);
        _expectClientData(
          matches,
          PERMIT2_INVALID_SIGNER,
          relayer,
          SchemaHash.executionOrder(order),
          erc20s,
          submittedData
        );
        vm.prank(relayer);
        hub.executeOrderWithPermit2Signature(order, signature);
      }
    } else {
      ERC20Allowance[] memory allowances = _allowances(_tokenAllowance(AMOUNT));
      GenericCall[] memory solverCalls = _calls(_routerCall(0, hex'01'));
      FulfillmentOrder memory signed = _openFulfillmentOrder(
        allowances, new ValidationParams[](0), new GenericCall[](0), nonce, expiration
      );
      signed.clientData = signedData;
      FulfillmentOrder memory order = _openFulfillmentOrder(
        allowances, new ValidationParams[](0), new GenericCall[](0), nonce, expiration
      );
      order.clientData = submittedData;
      FulfillmentSolution memory route = _route(order, solverCalls);

      if (entry == 2) {
        _delegateKeyThroughHub(key);
        bytes memory auth = _fulfillmentAuthData(signed, key, masterKeyPk);
        _expectClientData(
          matches,
          ITwoTiersOrderAuthenticator.InvalidOrderSignature.selector,
          solver,
          SchemaHash.fulfillmentOrder(order),
          erc20s,
          submittedData
        );
        vm.prank(solver);
        hub.fulfillOrderWithDelegatedAuthentication(
          order, address(authenticator), auth, route, '', false
        );
      } else {
        bytes memory signature = _signFulfillmentWitness(signed);
        _expectClientData(
          matches,
          PERMIT2_INVALID_SIGNER,
          solver,
          SchemaHash.fulfillmentOrder(order),
          erc20s,
          submittedData
        );
        vm.prank(solver);
        hub.fulfillOrderWithPermit2Signature(order, signature, route, '');
      }
    }
  }

  /// @dev Expects the full `TransferTokens` payload when `matches`, and `refusal` otherwise
  function _expectClientData(
    bool matches,
    bytes4 refusal,
    address caller,
    bytes32 orderHash,
    ERC20Transfer[] memory erc20s,
    bytes memory clientData
  ) internal {
    if (matches) {
      vm.expectEmit(true, true, true, true, address(hub));
      emit IKSAllowanceHubV2.TransferTokens(
        caller,
        owner,
        orderHash,
        erc20s,
        new ERC721Transfer[](0),
        new NativeTransfer[](0),
        clientData
      );
    } else {
      vm.expectRevert(refusal);
    }
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
      _openExecutionOrder(new ERC20Transfer[](0), calls, 0, vm.getBlockTimestamp()),
      address(0),
      '',
      false
    );

    Vm.Log memory entry = _settlementLog();

    assertEq(
      entry.data,
      abi.encode(new ERC20Transfer[](0), new ERC721Transfer[](0), expected, bytes('')),
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
      _openExecutionOrder(noErc20s, new GenericCall[](0), 0, vm.getBlockTimestamp()),
      address(0),
      '',
      false
    );

    assertEq(results.length, 0, 'no calls, no results');

    Vm.Log memory entry = _settlementLog();
    assertEq(
      entry.data,
      abi.encode(noErc20s, noNfts, new NativeTransfer[](0), bytes('')),
      'three empty arrays'
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
      _openExecutionOrder(new ERC20Transfer[](0), calls, 0, vm.getBlockTimestamp()),
      address(0),
      '',
      false
    );

    assertEq(results.length, 3, 'one result per call');
    for (uint256 i = 0; i < 3; i++) {
      (address seenRouter, bytes memory seenData) = abi.decode(results[i], (address, bytes));
      assertEq(seenRouter, calls[i].router, 'result came from the router at the same index');
      assertEq(seenData, calls[i].data, 'and carries the data sent to it');
    }
  }

  /**
   * OWN-07 — the native transfers of the event span both call lists, solver's route first
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
      new ERC20Allowance[](0), new ValidationParams[](0), ownerCalls, 0, vm.getBlockTimestamp()
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
      abi.encode(new ERC20Transfer[](0), new ERC721Transfer[](0), expected, bytes('')),
      'solver calls then owner calls, zero-value calls dropped'
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
      _openExecutionOrder(erc20s, calls, 0, vm.getBlockTimestamp()), address(0), '', false
    );

    assertEq(stranger.callCount(), 0, 'never called');
    assertEq(
      IERC20(token18).balanceOf(owner), ownerBalanceBefore, 'the ERC20 transfer rolled back too'
    );
    assertEq(IERC20(token18).balanceOf(address(stranger)), 0, 'nothing reached it');
  }

  /// ROUTER-02 — a guardian can drop a router, and the very next order stops working
  function test_ROUTER_02_guardianRevokeStopsTheNextOrder() public {
    GenericCall[] memory calls = _calls(_routerCall(0, hex'01'));

    assertTrue(hub.hasRole(ROUTER_ROLE, address(router)), 'whitelisted at deploy');

    vm.prank(owner);
    hub.executeOrderWithDelegatedAuthentication(
      _openExecutionOrder(new ERC20Transfer[](0), calls, 0, vm.getBlockTimestamp()),
      address(0),
      '',
      false
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
      _openExecutionOrder(new ERC20Transfer[](0), calls, 0, vm.getBlockTimestamp()),
      address(0),
      '',
      false
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
      _openExecutionOrder(new ERC20Transfer[](0), calls, 0, vm.getBlockTimestamp()),
      address(0),
      '',
      false
    );

    assertEq(router.callCount(), 1, 'router once');
    assertEq(router2.callCount(), 1, 'router2 once');
    assertEq(router.lastData(), dataA, 'router got its own payload');
    assertEq(router2.lastData(), dataB, 'router2 got its own payload');
  }

  // -----------------------------------------------------------------------------------------
  // NEST — the transient msg sender identifies the order owner to a router, and an order may settle
  // inside another
  // -----------------------------------------------------------------------------------------

  /**
   * NEST-01 — orders nested inside execution router calls settle, and each level sees its owner
   * @dev Level 0 is `owner`'s execution, submitted by `owner` on the delegated rail or by
   * `relayer` on the Permit2 rail. Level `k` below the innermost calls `evils[k]`, which settles
   * level `k + 1` as an order it owns. The innermost level is an execution or a fulfillment and
   * calls `router`. Each `evils[k]` reads {msgSender} before and after its nested order, and level
   * 0 calls `router2` last, so a level that did not restore its predecessor's sender is detected at
   * the next read.
   */
  function testFuzz_NEST_01_nestedOrdersRestoreEachOwner(NestingParams memory p) public {
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

  /**
   * NEST-02 — the ERC721 receiver hook of a fulfillment may settle an order
   * @dev The NFT target of the fulfillment is a receiver whose hook settles an execution it owns
   * and that calls `router` once. The hub emits `TransferTokens` for an order before it moves any
   * asset of it, so the fulfillment's log precedes the log of the order settled by the hook.
   */
  function test_NEST_02_receiverHookSettlesAnOrderInsideAFulfillment() public {
    ReentrantReceiverMock receiver = new ReentrantReceiverMock(address(hub));
    ExecutionOrder memory nested =
      _ownedExecution(address(receiver), _calls(_routerCall(0, hex'01')));
    receiver.setReentry(_executionCall(nested));

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
      vm.getBlockTimestamp() + 1 hours
    );
    FulfillmentSolution memory solution = _solution(
      new address[](0),
      new uint160[](0),
      erc721Targets,
      new GenericCall[](0),
      vm.getBlockTimestamp() + 1 hours
    );

    vm.recordLogs();

    vm.prank(owner);
    hub.fulfillOrderWithDelegatedAuthentication(order, address(0), '', solution, '', false);

    assertEq(nft.ownerOf(NFT_ID), address(receiver), 'the NFT moved to the receiver');
    assertEq(router.callCount(), 1, 'the router call of the nested order ran');
    assertEq(router.seenMsgSender(), address(receiver), 'under the nested owner');

    // The fulfillment announces itself before it moves the NFT, and the hook runs during the move
    Vm.Log[] memory logs = _transferTokensLogs();
    assertEq(logs.length, 2, 'one TransferTokens per order');
    assertEq(logs[0].topics.length, 4, 'caller, owner and the order hash are indexed');
    assertEq(_topicAddress(logs[0].topics[1]), owner, 'the fulfillment caller');
    assertEq(_topicAddress(logs[0].topics[2]), owner, 'the fulfillment owner');
    assertEq(logs[0].topics[3], SchemaHash.fulfillmentOrder(order), 'the fulfillment order hash');
    _assertEmptySettlement(
      logs[1], address(receiver), address(receiver), SchemaHash.executionOrder(nested)
    );

    assertEq(hub.msgSender(), address(0), 'nothing is recorded after the call');
  }

  /**
   * NEST-03 — an order settles inside another on every entry point, as outer and as nested order
   * @dev The outer order is an execution or a fulfillment whose single call is `evil`, which
   * settles the nested order. On the delegated rail the outer order is owned and submitted by
   * `evilOuter`. On the Permit2 rail it is owned by `owner`, signed open to any submitter and
   * submitted by `evilOuter`. With `wrapped`, an execution of `owner` calls `evilOuter`, which
   * submits the outer order from inside it.
   *
   * The nested order calls `router` once and is submitted by `evil`. Entry 0 is an execution and
   * entry 2 a fulfillment on the delegated rail, owned by `evil`. Entries 1 and 3 are the same on
   * the Permit2 rail, owned by `nestedOwner` and signed with its key. No order moves a token, so
   * Permit2 verifies the signature and spends the nonce of an empty batch. The owner of the outer
   * order and the owner of the nested order differ in every combination.
   * @param p The type and rail of the outer order, the nested entry point, and whether the outer
   * order is wrapped
   */
  function testFuzz_NEST_03_anOrderSettlesInsideAnotherOnEveryEntryPoint(NestedEntryParams memory p)
    public
  {
    uint256 entry = bound(p.nestedEntry, 0, 3);

    ReentrantRouterMock evil = _newReentrantRouter();
    ReentrantRouterMock evilOuter = _newReentrantRouter();
    (address nestedOwner, uint256 nestedOwnerKey) = makeAddrAndKey('nestedOwner');

    address outerOwner = p.outerViaPermit2 ? owner : address(evilOuter);
    address nestedOrderOwner = entry % 2 == 1 ? nestedOwner : address(evil);
    assertNotEq(outerOwner, nestedOrderOwner, 'the two owners differ');

    (bytes memory nestedCall, bytes32 nestedHash) = _orderCall(
      entry >= 2,
      entry % 2 == 1,
      nestedOrderOwner,
      nestedOwnerKey,
      2,
      _calls(_routerCall(0, hex'01'))
    );
    evil.setReentry(nestedCall);

    (bytes memory outerCall, bytes32 outerHash) = _orderCall(
      p.outerIsFulfillment,
      p.outerViaPermit2,
      outerOwner,
      ownerKey,
      1,
      _calls(_callTo(address(evil)))
    );

    address submitter = address(evilOuter);
    bytes memory submitted = outerCall;
    bytes32 topHash;
    if (p.wrapped) {
      ExecutionOrder memory top = _ownedExecution(owner, _calls(_callTo(address(evilOuter))));
      topHash = SchemaHash.executionOrder(top);
      evilOuter.setReentry(outerCall);
      submitter = owner;
      submitted = _executionCall(top);
    }

    vm.recordLogs();

    vm.prank(submitter);
    (bool ok,) = address(hub).call(submitted);
    assertTrue(ok, 'the outer order settled');

    assertEq(evil.seenBefore(), outerOwner, 'the router is called under the outer owner');
    assertEq(evil.seenAfter(), outerOwner, 'and the outer owner is restored');
    if (p.wrapped) {
      assertEq(evilOuter.seenBefore(), owner, 'the wrapping call runs under its owner');
      assertEq(evilOuter.seenAfter(), owner, 'and its owner is restored');
    }
    assertEq(router.callCount(), 1, 'the nested router ran once');
    assertEq(router.seenMsgSender(), nestedOrderOwner, 'under the nested owner');

    Vm.Log[] memory logs = _transferTokensLogs();
    uint256 base = p.wrapped ? 1 : 0;
    assertEq(logs.length, base + 2, 'one TransferTokens per order');
    if (p.wrapped) {
      _assertEmptySettlement(logs[0], owner, owner, topHash);
    }
    _assertEmptySettlement(logs[base], address(evilOuter), outerOwner, outerHash);
    _assertEmptySettlement(logs[base + 1], address(evil), nestedOrderOwner, nestedHash);

    assertEq(hub.msgSender(), address(0), 'nothing is recorded after the call');
  }

  /**
   * NEST-04 — `revokeNonce` is reachable from inside an order
   * @dev A router may call `revokeNonce` inside an order. The nonce is spent in the router's
   * namespace, not the owner's.
   */
  function test_NEST_04_revokeNonceIsReachableFromInsideAnOrder() public {
    ReentrantRouterMock evil = new ReentrantRouterMock(address(hub));
    vm.prank(admin);
    hub.grantRole(ROUTER_ROLE, address(evil));

    evil.setReentry(abi.encodeCall(IUnorderedNonce.revokeNonce, (7)));

    GenericCall[] memory calls = _calls(GenericCall({router: address(evil), value: 0, data: hex''}));
    ExecutionOrder memory order =
      _openExecutionOrder(new ERC20Transfer[](0), calls, 0, vm.getBlockTimestamp());

    vm.prank(owner);
    bytes[] memory results =
      hub.executeOrderWithDelegatedAuthentication(order, address(0), '', false);

    assertEq(results.length, 1, 'the order settled');
    assertEq(results[0].length, 0, 'revokeNonce returns nothing');
    assertEq(
      hub.nonces(lNonceKey(address(evil)), 0), 1 << 7, "burned against the router's own bitmap"
    );
    assertEq(hub.nonces(lNonceKey(owner), 0), 0, "and not against the owner's");
    assertEq(hub.msgSender(), address(0), 'nothing is recorded after the call');
  }

  /**
   * NEST-05 — a nested order cannot spend the outer order's value
   * @dev With the hub holding a native balance, the outer execution may spend its own value after
   * a nested order returned, but a nested order sent no value cannot spend the outer order's.
   */
  function test_NEST_05_nestedOrderCannotSpendTheOuterValue() public {
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
    assertEq(address(hub).balance, PREFUND, "the hub's native balance is intact");

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
    assertEq(address(hub).balance, PREFUND, "the hub's native balance is intact");
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
   * @dev An execution order owned by `orderOwner` with no transfers, so it takes the owner path
   * when `orderOwner` submits it
   */
  function _ownedExecution(address orderOwner, GenericCall[] memory calls)
    internal
    view
    returns (ExecutionOrder memory order)
  {
    order = _openExecutionOrder(new ERC20Transfer[](0), calls, 0, vm.getBlockTimestamp() + 1 hours);
    order.owner = orderOwner;
  }

  /// @dev As {_ownedExecution}, for a fulfillment order with no transfers and no owner calls
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
      vm.getBlockTimestamp() + 1 hours
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
   * @dev The call of an order owned by `orderOwner` with its order hash: an execution or a
   * fulfillment whose router calls or solver calls are `calls`. The call is delegated, or carries
   * the open witness signature of `signerKey` for the Permit2 rail, where the order moves no token
   * and spends `nonce`.
   */
  function _orderCall(
    bool isFulfillment,
    bool viaPermit2,
    address orderOwner,
    uint256 signerKey,
    uint256 nonce,
    GenericCall[] memory calls
  ) internal view returns (bytes memory data, bytes32 orderHash) {
    if (isFulfillment) {
      FulfillmentOrder memory fulfillment = _ownedFulfillment(orderOwner);
      fulfillment.nonce = nonce;
      orderHash = SchemaHash.fulfillmentOrder(fulfillment);
      data = viaPermit2
        ? abi.encodeCall(
          IKSAllowanceHubV2.fulfillOrderWithPermit2Signature,
          (
            fulfillment,
            _signFulfillmentWitness(fulfillment, signerKey),
            _route(fulfillment, calls),
            ''
          )
        )
        : _fulfillmentCall(fulfillment, calls);
    } else {
      ExecutionOrder memory execution = _ownedExecution(orderOwner, calls);
      execution.nonce = nonce;
      orderHash = SchemaHash.executionOrder(execution);
      data = viaPermit2
        ? abi.encodeCall(
          IKSAllowanceHubV2.executeOrderWithPermit2Signature,
          (execution, _signExecutionWitness(execution, signerKey))
        )
        : _executionCall(execution);
    }
  }

  /**
   * @dev Builds the nested orders of {testFuzz_NEST_01_nestedOrdersRestoreEachOwner} and arms each
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
  function _transferTokensLogs() internal view returns (Vm.Log[] memory logs) {
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
      if (entries[i].topics[0] != TRANSFER_TOKENS_TOPIC) {
        continue;
      }

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
