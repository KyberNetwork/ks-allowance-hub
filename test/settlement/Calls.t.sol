// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Vm} from 'forge-std/Vm.sol';

import {SchemaHash} from 'test/base/SchemaHash.sol';

import {CalleeMock, EchoCalleeMock, ObservingCalleeMock} from 'test/mocks/CalleeMocks.sol';
import {SignerAuthenticatorMock} from 'test/mocks/SignerAuthenticatorMock.sol';

import {SettlementBase} from 'test/settlement/base/SettlementBase.sol';

import {IAHV2Callee} from 'src/interfaces/base/IAHV2Callee.sol';

import {AHV2Order} from 'src/types/AHV2Order.sol';
import {AHV2Solution} from 'src/types/AHV2Solution.sol';
import {CallParams} from 'src/types/CallParams.sol';
import {ERC20Allowance} from 'src/types/ERC20Allowance.sol';
import {ERC20Transfer} from 'src/types/ERC20Transfer.sol';
import {ERC721Transfer} from 'src/types/ERC721Transfer.sol';
import {HookParams} from 'src/types/HookParams.sol';
import {NativeTransfer} from 'src/types/NativeTransfer.sol';

import {IAccessControl} from 'openzeppelin-contracts/contracts/access/IAccessControl.sol';
import {IERC20} from 'openzeppelin-contracts/contracts/token/ERC20/IERC20.sol';

/**
 * @title CallsTest
 * @notice `OWN-01..07` and `CALLEE-01..04` — the owner calls and the whitelist every
 * callee passes
 * @dev The owner fixes `ownerCalls`, which run after the solver calls. The role constant is written
 * out rather than imported: a role read from the hub would agree with a wrong one.
 */
contract CallsTest is SettlementBase {
  uint160 internal constant AMOUNT = 5 ether;

  /// @dev Permit2 does not expose this in the vendored interface, so it is written out here
  bytes4 internal constant PERMIT2_INVALID_SIGNER = bytes4(keccak256('InvalidSigner()'));

  /// @dev Written out rather than imported: a role read from the hub would agree with a wrong one
  bytes32 internal constant CALLEE_ROLE = keccak256('WHITELISTED_CALLEE_ROLE');

  // -------------------------------------------------------------------------------------------
  // OWN — the owner calls
  // -------------------------------------------------------------------------------------------

  /**
   * OWN-01 — the owner calls run after the solver calls, not merely alongside them
   * @dev Both observers are the same callee, so this is about when they ran and not about who was
   * called. The one at the head of the solver list finds nothing, the signature of having run
   * before the producers, and that is what stops the second assertion being satisfiable by an
   * implementation that ran the owner calls first. The owner's observer finds the last of the two
   * products, so it ran after every solver call rather than merely after the first.
   */
  function test_OWN_01_ownerCallsRunAfterSolverCalls() public {
    ObservingCalleeMock ledger = new ObservingCalleeMock();
    vm.prank(admin);
    hub.grantRole(CALLEE_ROLE, address(ledger));

    bytes memory nothing = '';
    bytes memory firstProduct = hex'a1';
    bytes memory lastProduct = hex'b2';

    CallParams[] memory solverCalls = new CallParams[](3);
    solverCalls[0] = CallParams({callee: address(ledger), value: 0, data: ledger.observe()});
    solverCalls[1] =
      CallParams({callee: address(ledger), value: 0, data: ledger.produce(firstProduct)});
    solverCalls[2] =
      CallParams({callee: address(ledger), value: 0, data: ledger.produce(lastProduct)});

    CallParams[] memory ownerCalls = new CallParams[](1);
    ownerCalls[0] = CallParams({callee: address(ledger), value: 0, data: ledger.observe()});

    vm.prank(owner);
    bytes[] memory results = _settleWithTail(ownerCalls, solverCalls);

    assertEq(ledger.observationCount(), 2, 'both observers ran');
    assertEq(ledger.observations(0), nothing, 'the solver observer ran before either producer');
    assertEq(ledger.observations(1), lastProduct, 'the owner call ran after every solver call');
    assertEq(results[3], lastProduct, 'and its return carries what it found');
  }

  /**
   * OWN-02 — the Permit2 witness pins the owner calls the owner signed
   * @dev The first step is the control: the same order with the owner calls left alone settles,
   * so the refusal in the second is evidence about the witness covering `ownerCalls` rather than
   * about a signature that was never going to be accepted. Only one byte of call data separates
   * them.
   */
  function test_OWN_02_witnessBindsOwnerCalls() public {
    ERC20Allowance[] memory erc20s = _allowances(_tokenAllowance(AMOUNT));
    CallParams[] memory solverCalls = _calls(_calleeCall(0, hex'01'));
    CallParams[] memory signedTail = _calls(_calleeCall(0, hex'aa'));
    CallParams[] memory swappedTail = _calls(_calleeCall(0, hex'bb'));
    uint256 expiration = vm.getBlockTimestamp() + 1 hours;

    uint256 before = _calleeBalance();

    AHV2Order memory control =
      _ahv2Order(ANY, erc20s, _noNfts(), _noHooks(), signedTail, ANY, 70, expiration);

    vm.prank(solver);
    hub.settleOrderWithPermit2Signature(
      control, _signWitness(control), _route(control, solverCalls), ''
    );

    assertEq(_calleeBalance() - before, AMOUNT, 'the signed owner call settled');
    assertEq(callee.callCount(), 2, 'one solver call and one owner call');

    AHV2Order memory signed =
      _ahv2Order(ANY, erc20s, _noNfts(), _noHooks(), signedTail, ANY, 71, expiration);
    bytes memory signature = _signWitness(signed);

    AHV2Order memory tampered =
      _ahv2Order(ANY, erc20s, _noNfts(), _noHooks(), swappedTail, ANY, 71, expiration);

    vm.prank(solver);
    vm.expectRevert(PERMIT2_INVALID_SIGNER);
    hub.settleOrderWithPermit2Signature(tampered, signature, _route(tampered, solverCalls), '');
  }

  /**
   * OWN-03 — owner calls swapped after the authenticator's signature are refused on the delegated
   * entry point
   * @dev Carries a hook as well as owner calls, so both of those signed members are exercised. As
   * in OWN-02 the first step is the control.
   */
  function test_OWN_03_authenticationBindsOwnerCalls() public {
    _delegateSignerThroughHub(signer);

    ERC20Allowance[] memory erc20s = _allowances(_tokenAllowance(AMOUNT));
    HookParams[] memory hooks = _hooks(_hook(hook, HOOK_BOTH));
    CallParams[] memory solverCalls = _calls(_calleeCall(0, hex'01'));
    CallParams[] memory signedTail = _calls(_calleeCall(0, hex'aa'));
    CallParams[] memory swappedTail = _calls(_calleeCall(0, hex'bb'));
    uint256 expiration = vm.getBlockTimestamp() + 1 hours;

    uint256 before = _calleeBalance();

    AHV2Order memory control =
      _ahv2Order(ANY, erc20s, _noNfts(), hooks, signedTail, ANY, 72, expiration);
    bytes memory controlAuth = _orderAuthData(control, signer, signerPk);

    vm.prank(relayer);
    hub.settleOrderWithDelegatedAuthentication(
      control, address(authenticator), controlAuth, _route(control, solverCalls), '', false
    );

    assertEq(_calleeBalance() - before, AMOUNT, 'the signed owner call settled');
    assertEq(callee.callCount(), 2, 'one solver call and one owner call');
    assertEq(hook.sequenceLength(), 2, 'the hook still bracketed the order');

    AHV2Order memory signed =
      _ahv2Order(ANY, erc20s, _noNfts(), hooks, signedTail, ANY, 73, expiration);
    bytes memory signedAuth = _orderAuthData(signed, signer, signerPk);

    AHV2Order memory tampered =
      _ahv2Order(ANY, erc20s, _noNfts(), hooks, swappedTail, ANY, 73, expiration);

    vm.prank(relayer);
    vm.expectRevert(SignerAuthenticatorMock.InvalidOrderSignature.selector);
    hub.settleOrderWithDelegatedAuthentication(
      tampered, address(authenticator), signedAuth, _route(tampered, solverCalls), '', false
    );
  }

  /**
   * OWN-04 — an owner call to a callee without the role reverts, as a solver call does
   * @dev The first step also shows the refusal unwinds the solver calls that had already run. The
   * last step is the control: granting the role and changing nothing else lets the very same
   * owner call through, so the two refusals are about the role rather than about the callee.
   */
  function test_OWN_04_ownerCallCalleeMustBeWhitelisted() public {
    CalleeMock stranger = new CalleeMock();

    CallParams[] memory strangerCalls =
      _calls(CallParams({callee: address(stranger), value: 0, data: hex'01'}));
    CallParams[] memory solverCalls = _calls(_calleeCall(0, hex'02'));

    bytes memory expectedError = abi.encodeWithSelector(
      IAccessControl.AccessControlUnauthorizedAccount.selector, address(stranger), CALLEE_ROLE
    );

    vm.prank(owner);
    vm.expectRevert(expectedError);
    _settleWithTail(strangerCalls, solverCalls);

    vm.prank(owner);
    vm.expectRevert(expectedError);
    _settleWithTail(_noCalls(), strangerCalls);

    assertEq(stranger.callCount(), 0, 'never called from either list');
    assertEq(callee.callCount(), 0, 'and the solver calls of the first order rolled back with it');

    vm.prank(admin);
    hub.grantRole(CALLEE_ROLE, address(stranger));

    vm.prank(owner);
    _settleWithTail(strangerCalls, solverCalls);

    assertEq(stranger.callCount(), 1, 'the owner call reached it once whitelisted');
    assertEq(callee.callCount(), 1, 'and the solver call ran too');
  }

  /**
   * OWN-05 — empty owner calls run no extra call and return no extra result
   * @dev An order without owner calls costs no call and no result beyond its solver calls.
   */
  function test_OWN_05_emptyOwnerCallsRunNoExtraCall() public {
    CallParams[] memory solverCalls = new CallParams[](2);
    solverCalls[0] = _calleeCall(0, hex'01');
    solverCalls[1] = _calleeCall(0, hex'02');

    vm.prank(owner);
    bytes[] memory results = _settleWithTail(_noCalls(), solverCalls);

    assertEq(results.length, 2, 'one result per solver call and no more');
    assertEq(callee.callCount(), 2, 'nothing beyond the solver calls ran');
    assertEq(callee.ownerCallCount(), 0, 'no owner call was made');
    assertEq(callee2.callCount(), 0, 'and no other callee was touched');
    assertEq(hub.nonces(lNonceKey(owner), 0), 0, 'the hub burned no nonce of its own');
  }

  /**
   * OWN-06 — `results` is the solver calls then the owner calls, one entry per call
   * @dev The two callees are interleaved across the lists, and each echoes back its own identity
   * and payload, so neither swapping the lists nor reversing one of them would reproduce the
   * expected sequence. An owner call also echoes the `solverData` entry it was given. OWN-01 is
   * the separate statement about when the calls ran; this is about where their return data lands.
   */
  function test_OWN_06_resultsAreSolverThenOwner() public {
    EchoCalleeMock echoA = new EchoCalleeMock();
    EchoCalleeMock echoB = new EchoCalleeMock();

    vm.startPrank(admin);
    hub.grantRole(CALLEE_ROLE, address(echoA));
    hub.grantRole(CALLEE_ROLE, address(echoB));
    vm.stopPrank();

    CallParams[] memory solverCalls = new CallParams[](2);
    solverCalls[0] = CallParams({callee: address(echoA), value: 0, data: hex'aa'});
    solverCalls[1] = CallParams({callee: address(echoB), value: 0, data: hex'bb'});

    CallParams[] memory ownerCalls = new CallParams[](2);
    ownerCalls[0] = CallParams({callee: address(echoB), value: 0, data: hex'cc'});
    ownerCalls[1] = CallParams({callee: address(echoA), value: 0, data: hex'dd'});

    AHV2Order memory order =
      _openAhv2Order(new ERC20Allowance[](0), _noHooks(), ownerCalls, 0, vm.getBlockTimestamp());
    AHV2Solution memory solution = _route(order, solverCalls);
    solution.solverData[0] = hex'e1';
    solution.solverData[1] = hex'e2e2';

    vm.prank(owner);
    bytes[] memory results =
      hub.settleOrderWithDelegatedAuthentication(order, address(0), '', solution, '', false);

    assertEq(results.length, 4, 'one result per call across both lists');

    // the expectation is the two lists written out in the order they are claimed to run
    for (uint256 i = 0; i < solverCalls.length; i++) {
      (address seenCallee, bytes memory seenData) = abi.decode(results[i], (address, bytes));
      assertEq(seenCallee, solverCalls[i].callee, 'result came from the callee at that position');
      assertEq(seenData, solverCalls[i].data, 'and carries the data sent to it');
    }
    for (uint256 i = 0; i < ownerCalls.length; i++) {
      (address seenCallee, bytes memory seenData, bytes memory seenSolverData) =
        abi.decode(results[solverCalls.length + i], (address, bytes, bytes));
      assertEq(seenCallee, ownerCalls[i].callee, 'owner result came from the callee of its call');
      assertEq(seenData, ownerCalls[i].data, 'and carries the data sent to it');
      assertEq(seenSolverData, solution.solverData[i], 'and the solver data of its own index');
    }
  }

  /**
   * OWN-07 — the native transfers of the event span both call lists, solver's route first
   * @dev Four calls, two of them valued, one from each list and neither at the end of its own.
   * A merge that reversed the two lists, or that walked one of them only, or that kept the
   * zero-value entries, produces a different array from the one written out here — and the two
   * entries differ in both target and amount, so nothing about the expectation is symmetric.
   */
  function test_OWN_07_eventCoversBothLists() public {
    CallParams[] memory solverCalls = new CallParams[](2);
    solverCalls[0] = _calleeCall(0, hex'01');
    solverCalls[1] = _calleeCall(1, hex'02');

    CallParams[] memory ownerCalls = new CallParams[](2);
    ownerCalls[0] = CallParams({callee: address(callee2), value: 2, data: hex'03'});
    ownerCalls[1] = CallParams({callee: address(callee2), value: 0, data: hex'04'});

    NativeTransfer[] memory expected = new NativeTransfer[](2);
    expected[0] = NativeTransfer({target: address(callee), amount: 1});
    expected[1] = NativeTransfer({target: address(callee2), amount: 2});

    uint256 calleeBefore = address(callee).balance;
    uint256 callee2Before = address(callee2).balance;
    vm.deal(owner, 3);

    AHV2Order memory order = _openAhv2Order(
      new ERC20Allowance[](0), new HookParams[](0), ownerCalls, 0, vm.getBlockTimestamp()
    );

    vm.recordLogs();

    vm.prank(owner);
    hub.settleOrderWithDelegatedAuthentication{value: 3}(
      order, address(0), '', _route(order, solverCalls), '', false
    );

    Vm.Log memory entry = _settlementLog();

    assertEq(entry.topics[3], SchemaHash.ahv2Order(order), 'the order hash');
    assertEq(
      entry.data,
      abi.encode(new ERC20Transfer[](0), new ERC721Transfer[](0), expected, bytes('')),
      'solver calls then owner calls, zero-value calls dropped'
    );

    // the listed amounts are what moved, so the event is not a claim about nothing
    assertEq(address(callee).balance - calleeBefore, 1, "the solver call's wei landed");
    assertEq(address(callee2).balance - callee2Before, 2, "the owner call's wei landed");
    assertEq(address(hub).balance, 0, 'nothing stranded in the hub');
    assertEq(callee.callCount(), 2, 'both solver calls ran');
    assertEq(callee2.callCount(), 2, 'both owner calls ran');
  }

  // -----------------------------------------------------------------------------------------
  // CALLEE — the per-call whitelist gate
  // -----------------------------------------------------------------------------------------

  /// CALLEE-01 — a callee without the role is refused, and the order rolls back whole
  function test_CALLEE_01_unwhitelistedCalleeIsRejected() public {
    CalleeMock stranger = new CalleeMock();

    AHV2Order memory order = _openAhv2Order(
      _allowances(_tokenAllowance(AMOUNT)),
      new HookParams[](0),
      new CallParams[](0),
      0,
      vm.getBlockTimestamp() + 1 hours
    );
    AHV2Solution memory solution = _solution(
      _addresses(address(stranger)),
      _amounts(AMOUNT),
      new address[](0),
      _calls(CallParams({callee: address(stranger), value: 0, data: hex'01'})),
      vm.getBlockTimestamp() + 1 hours
    );

    uint256 ownerBalanceBefore = IERC20(token18).balanceOf(owner);

    vm.prank(owner);
    vm.expectRevert(
      abi.encodeWithSelector(
        IAccessControl.AccessControlUnauthorizedAccount.selector, address(stranger), CALLEE_ROLE
      )
    );
    hub.settleOrderWithDelegatedAuthentication(order, address(0), '', solution, '', false);

    assertEq(stranger.callCount(), 0, 'never called');
    assertEq(
      IERC20(token18).balanceOf(owner), ownerBalanceBefore, 'the ERC20 transfer rolled back too'
    );
    assertEq(IERC20(token18).balanceOf(address(stranger)), 0, 'nothing reached it');
  }

  /// CALLEE-02 — a guardian can drop a callee, and the very next order stops working
  function test_CALLEE_02_guardianRevokeStopsTheNextOrder() public {
    AHV2Order memory order = _ownedOrder(owner);
    CallParams[] memory calls = _calls(_calleeCall(0, hex'01'));

    assertTrue(hub.hasRole(CALLEE_ROLE, address(callee)), 'whitelisted at deploy');

    vm.prank(owner);
    hub.settleOrderWithDelegatedAuthentication(
      order, address(0), '', _route(order, calls), '', false
    );
    assertEq(callee.callCount(), 1, 'the first order went through');

    vm.prank(guardian);
    hub.revokeRole(CALLEE_ROLE, address(callee));
    assertFalse(hub.hasRole(CALLEE_ROLE, address(callee)), 'role gone');

    vm.prank(owner);
    vm.expectRevert(
      abi.encodeWithSelector(
        IAccessControl.AccessControlUnauthorizedAccount.selector, address(callee), CALLEE_ROLE
      )
    );
    hub.settleOrderWithDelegatedAuthentication(
      order, address(0), '', _route(order, calls), '', false
    );

    assertEq(callee.callCount(), 1, 'and no second call happened');
  }

  /// CALLEE-03 — every whitelisted callee in the list is called exactly once, with its own data
  function test_CALLEE_03_eachCalleeCalledOnce() public {
    bytes memory dataA = hex'a1';
    bytes memory dataB = hex'b2';

    CallParams[] memory calls = new CallParams[](2);
    calls[0] = CallParams({callee: address(callee), value: 0, data: dataA});
    calls[1] = CallParams({callee: address(callee2), value: 0, data: dataB});

    vm.expectCall(address(callee), 0, abi.encodeCall(IAHV2Callee.execute, ('', dataA)), 1);
    vm.expectCall(address(callee2), 0, abi.encodeCall(IAHV2Callee.execute, ('', dataB)), 1);

    AHV2Order memory order = _ownedOrder(owner);

    vm.prank(owner);
    hub.settleOrderWithDelegatedAuthentication(
      order, address(0), '', _route(order, calls), '', false
    );

    assertEq(callee.callCount(), 1, 'callee once');
    assertEq(callee2.callCount(), 1, 'callee2 once');
    assertEq(callee.lastData(), dataA, 'callee got its own payload');
    assertEq(callee2.lastData(), dataB, 'callee2 got its own payload');
  }

  /**
   * CALLEE-04 — a solver call passes empty owner data and its data as solver data; an owner call
   * passes its data as owner data with the solution's solver data
   * @dev One solver call goes to `callee` and one owner call to `callee2`, with a non-empty entry
   * of `solverData`. Each callee receives the arguments of its own kind of call and never those of
   * the other.
   */
  function test_CALLEE_04_callKindsFillTheirOwnArguments() public {
    bytes memory solverCallData = hex'a1';
    bytes memory ownerCallData = hex'b2';
    bytes memory solverData = hex'5e';

    AHV2Order memory order = _openAhv2Order(
      new ERC20Allowance[](0),
      new HookParams[](0),
      _calls(CallParams({callee: address(callee2), value: 0, data: ownerCallData})),
      0,
      vm.getBlockTimestamp() + 1 hours
    );
    AHV2Solution memory solution = _route(order, _calls(_calleeCall(0, solverCallData)));
    solution.solverData[0] = solverData;

    vm.expectCall(address(callee), 0, abi.encodeCall(IAHV2Callee.execute, ('', solverCallData)), 1);
    vm.expectCall(
      address(callee), 0, abi.encodeCall(IAHV2Callee.execute, (solverCallData, solverData)), 0
    );
    vm.expectCall(
      address(callee2), 0, abi.encodeCall(IAHV2Callee.execute, (ownerCallData, solverData)), 1
    );
    vm.expectCall(address(callee2), 0, abi.encodeCall(IAHV2Callee.execute, ('', ownerCallData)), 0);

    vm.prank(owner);
    hub.settleOrderWithDelegatedAuthentication(order, address(0), '', solution, '', false);

    assertEq(callee.callCount(), 1, 'the solver callee ran once');
    assertEq(callee.ownerCallCount(), 0, 'and never as an owner callee');
    assertEq(callee.lastData(), solverCallData, 'with the solver call data');
    assertEq(callee2.callCount(), 1, 'the owner callee ran once');
    assertEq(callee2.ownerCallCount(), 1, 'as an owner callee');
    assertEq(callee2.lastData(), ownerCallData, 'with the owner call data');
    assertEq(callee2.lastSolverData(), solverData, 'and the solver data of its index');
  }

  // -------------------------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------------------------

  /// @dev An owner-submitted order carrying both call lists and nothing else
  function _settleWithTail(CallParams[] memory ownerCalls, CallParams[] memory solverCalls)
    private
    returns (bytes[] memory results)
  {
    AHV2Order memory order = _openAhv2Order(
      new ERC20Allowance[](0), _noHooks(), ownerCalls, 0, vm.getBlockTimestamp()
    );
    results = hub.settleOrderWithDelegatedAuthentication(
      order, address(0), '', _route(order, solverCalls), '', false
    );
  }
}
