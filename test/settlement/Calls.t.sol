// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Vm} from 'forge-std/Vm.sol';

import {SchemaHash} from 'test/base/SchemaHash.sol';

import {CalleeMock, ObservingCalleeMock} from 'test/mocks/CalleeMocks.sol';
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
 * @notice `OWN-01..07` and `CALLEE-01..03` — the order's calls and the whitelist every callee
 * passes
 * @dev The order fixes `calls`, which run in the order listed. The role constant is written out
 * rather than imported: a role read from the hub would agree with a wrong one.
 */
contract CallsTest is SettlementBase {
  /// @dev Permit2 does not expose this in the vendored interface, so it is written out here
  bytes4 internal constant PERMIT2_INVALID_SIGNER = bytes4(keccak256('InvalidSigner()'));

  /// @dev Written out rather than imported: a role read from the hub would agree with a wrong one
  bytes32 internal constant CALLEE_ROLE = keccak256('WHITELISTED_CALLEE_ROLE');

  // -------------------------------------------------------------------------------------------
  // OWN — the order's calls
  // -------------------------------------------------------------------------------------------

  /**
   * OWN-01 — the calls run in the order listed
   * @dev All four calls go to one callee, so this is about when they ran and not about who was
   * called. The observer at the head of the list finds nothing, which a list run in reverse order
   * would not. The last observer finds the last of the two products, so it ran after both
   * producers rather than merely after the first.
   */
  function test_OWN_01_callsRunInOrder() public {
    ObservingCalleeMock ledger = new ObservingCalleeMock();
    vm.prank(admin);
    hub.grantRole(CALLEE_ROLE, address(ledger));

    bytes memory nothing = '';
    bytes memory firstProduct = hex'a1';
    bytes memory lastProduct = hex'b2';

    CallParams[] memory calls = new CallParams[](4);
    calls[0] = CallParams({callee: address(ledger), value: 0, data: ledger.observe()});
    calls[1] = CallParams({callee: address(ledger), value: 0, data: ledger.produce(firstProduct)});
    calls[2] = CallParams({callee: address(ledger), value: 0, data: ledger.produce(lastProduct)});
    calls[3] = CallParams({callee: address(ledger), value: 0, data: ledger.observe()});

    AHV2Order memory order =
      _openAhv2Order(new ERC20Allowance[](0), _noHooks(), calls, 0, vm.getBlockTimestamp());

    vm.prank(owner);
    bytes[] memory results = hub.settleOrder(order, '', _defaultSolution(order), '', false);

    assertEq(ledger.observationCount(), 2, 'both observers ran');
    assertEq(ledger.observations(0), nothing, 'the first observer ran before either producer');
    assertEq(ledger.observations(1), lastProduct, 'the last observer ran after both producers');
    assertEq(results.length, 4, 'one result per call');
    assertEq(results[3], lastProduct, 'and its return carries what it found');
  }

  /**
   * OWN-02 — the Permit2 witness pins the calls the owner signed
   * @dev The first step is the control: the same order with the calls left alone settles, so the
   * refusal in the second is evidence about the witness covering `calls` rather than about a
   * signature that was never going to be accepted. Only one byte of call data separates them.
   */
  function test_OWN_02_witnessBindsCalls() public {
    ERC20Allowance[] memory erc20s = _allowances(_tokenAllowance(AMOUNT));
    CallParams[] memory signedCalls = _calls(_calleeCall(0, hex'aa'));
    CallParams[] memory swappedCalls = _calls(_calleeCall(0, hex'bb'));
    uint256 expiration = vm.getBlockTimestamp() + 1 hours;

    uint256 before = _calleeBalance();

    AHV2Order memory control =
      _ahv2Order(permit2, ANY, erc20s, _noNfts(), _noHooks(), signedCalls, ANY, 70, expiration);

    vm.prank(solver);
    hub.settleOrder(control, _signPermit2Order(control), _defaultSolution(control), '', false);

    assertEq(_calleeBalance() - before, AMOUNT, 'the signed call settled');
    assertEq(callee.callCount(), 1, 'the signed call ran once');

    AHV2Order memory signed =
      _ahv2Order(permit2, ANY, erc20s, _noNfts(), _noHooks(), signedCalls, ANY, 71, expiration);
    bytes memory signature = _signPermit2Order(signed);

    AHV2Order memory tampered =
      _ahv2Order(permit2, ANY, erc20s, _noNfts(), _noHooks(), swappedCalls, ANY, 71, expiration);

    vm.prank(solver);
    vm.expectRevert(PERMIT2_INVALID_SIGNER);
    hub.settleOrder(tampered, signature, _defaultSolution(tampered), '', false);
  }

  /**
   * OWN-03 — calls swapped after the authenticator's signature are refused on the delegated entry
   * point
   * @dev Carries a hook as well as calls, so both of those signed members are exercised. As
   * in OWN-02 the first step is the control.
   */
  function test_OWN_03_authenticationBindsCalls() public {
    _delegateSignerThroughHub(signer);

    ERC20Allowance[] memory erc20s = _allowances(_tokenAllowance(AMOUNT));
    HookParams[] memory hooks = _hooks(_hook(hook, HOOK_BOTH));
    CallParams[] memory signedCalls = _calls(_calleeCall(0, hex'aa'));
    CallParams[] memory swappedCalls = _calls(_calleeCall(0, hex'bb'));
    uint256 expiration = vm.getBlockTimestamp() + 1 hours;

    uint256 before = _calleeBalance();

    AHV2Order memory control = _ahv2Order(
      address(authenticator), ANY, erc20s, _noNfts(), hooks, signedCalls, ANY, 72, expiration
    );
    bytes memory controlAuth = _orderAuthData(control, signer, signerPk);

    vm.prank(relayer);
    hub.settleOrder(control, controlAuth, _defaultSolution(control), '', false);

    assertEq(_calleeBalance() - before, AMOUNT, 'the signed call settled');
    assertEq(callee.callCount(), 1, 'the signed call ran once');
    assertEq(hook.sequenceLength(), 2, 'the hook still bracketed the order');

    AHV2Order memory signed = _ahv2Order(
      address(authenticator), ANY, erc20s, _noNfts(), hooks, signedCalls, ANY, 73, expiration
    );
    bytes memory signedAuth = _orderAuthData(signed, signer, signerPk);

    AHV2Order memory tampered = _ahv2Order(
      address(authenticator), ANY, erc20s, _noNfts(), hooks, swappedCalls, ANY, 73, expiration
    );

    vm.prank(relayer);
    vm.expectRevert(SignerAuthenticatorMock.InvalidOrderSignature.selector);
    hub.settleOrder(tampered, signedAuth, _defaultSolution(tampered), '', false);
  }

  /**
   * OWN-07 — the event lists the value of each call with a value, in order
   * @dev Four calls to two callees, two of them valued, neither at the end of the list. A walk
   * that reversed the list or kept the zero-value entries produces a different array from the one
   * written out here, and the two entries differ in both target and amount, so nothing about the
   * expectation is symmetric.
   */
  function test_OWN_07_eventListsTheValueOfEachCall() public {
    CallParams[] memory calls = new CallParams[](4);
    calls[0] = _calleeCall(0, hex'01');
    calls[1] = _calleeCall(1, hex'02');
    calls[2] = CallParams({callee: address(callee2), value: 2, data: hex'03'});
    calls[3] = CallParams({callee: address(callee2), value: 0, data: hex'04'});

    NativeTransfer[] memory expected = new NativeTransfer[](2);
    expected[0] = NativeTransfer({target: address(callee), amount: 1});
    expected[1] = NativeTransfer({target: address(callee2), amount: 2});

    uint256 calleeBefore = address(callee).balance;
    uint256 callee2Before = address(callee2).balance;
    vm.deal(owner, 3);

    AHV2Order memory order =
      _openAhv2Order(new ERC20Allowance[](0), _noHooks(), calls, 0, vm.getBlockTimestamp());

    vm.recordLogs();

    vm.prank(owner);
    hub.settleOrder{value: 3}(order, '', _defaultSolution(order), '', false);

    Vm.Log memory entry = _settlementLog();

    assertEq(entry.topics[3], SchemaHash.ahv2Order(order), 'the order hash');
    assertEq(
      entry.data,
      abi.encode(new ERC20Transfer[](0), new ERC721Transfer[](0), expected, bytes('')),
      'the valued calls in order, zero-value calls dropped'
    );

    // the listed amounts are what moved, so the event is not a claim about nothing
    assertEq(address(callee).balance - calleeBefore, 1, 'the first valued call transferred 1 wei');
    assertEq(address(callee2).balance - callee2Before, 2, 'the second valued call transferred 2');
    assertEq(address(hub).balance, 0, 'the hub holds no native balance');
    assertEq(callee.callCount(), 2, 'both calls to callee ran');
    assertEq(callee2.callCount(), 2, 'both calls to callee2 ran');
  }

  // -----------------------------------------------------------------------------------------
  // CALLEE — the per-call whitelist gate
  // -----------------------------------------------------------------------------------------

  /// CALLEE-01 — a callee without the role is refused, and the order rolls back whole, earlier
  /// calls included
  function test_CALLEE_01_unwhitelistedCalleeIsRejected() public {
    CalleeMock stranger = new CalleeMock();

    AHV2Order memory order = _openAhv2Order(
      _allowances(_tokenAllowance(AMOUNT)),
      _noHooks(),
      _calls(
        _calleeCall(0, hex'01'), CallParams({callee: address(stranger), value: 0, data: hex'01'})
      ),
      0,
      vm.getBlockTimestamp() + 1 hours
    );
    AHV2Solution memory solution = _solution(
      _addresses(address(stranger)),
      _amounts(AMOUNT),
      new address[](0),
      vm.getBlockTimestamp() + 1 hours
    );
    solution.solverData = _solverData(2);

    uint256 ownerBalanceBefore = IERC20(token18).balanceOf(owner);

    vm.prank(owner);
    vm.expectRevert(
      abi.encodeWithSelector(
        IAccessControl.AccessControlUnauthorizedAccount.selector, address(stranger), CALLEE_ROLE
      )
    );
    hub.settleOrder(order, '', solution, '', false);

    assertEq(callee.callCount(), 0, 'the earlier call rolled back');
    assertEq(stranger.callCount(), 0, 'never called');
    assertEq(
      IERC20(token18).balanceOf(owner), ownerBalanceBefore, 'the ERC20 transfer rolled back too'
    );
    assertEq(IERC20(token18).balanceOf(address(stranger)), 0, 'nothing reached it');

    vm.prank(admin);
    hub.grantRole(CALLEE_ROLE, address(stranger));

    vm.prank(owner);
    hub.settleOrder(order, '', solution, '', false);

    assertEq(callee.callCount(), 1, 'the earlier call ran once the role was granted');
    assertEq(stranger.callCount(), 1, 'the call reached it once whitelisted');
    assertEq(IERC20(token18).balanceOf(address(stranger)), AMOUNT, 'and the transfer reached it');
  }

  /// CALLEE-02 — a guardian can drop a callee, and the very next order stops working
  function test_CALLEE_02_guardianRevokeStopsTheNextOrder() public {
    AHV2Order memory order = _ownedOrder(owner);
    order.calls = _calls(_calleeCall(0, hex'01'));

    assertTrue(hub.hasRole(CALLEE_ROLE, address(callee)), 'whitelisted at deploy');

    vm.prank(owner);
    hub.settleOrder(order, '', _defaultSolution(order), '', false);
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
    hub.settleOrder(order, '', _defaultSolution(order), '', false);

    assertEq(callee.callCount(), 1, 'and no second call happened');
  }

  /// CALLEE-03 — every whitelisted callee in the list is called exactly once, with its own data
  function test_CALLEE_03_eachCalleeCalledOnce() public {
    bytes memory dataA = hex'a1';
    bytes memory dataB = hex'b2';

    CallParams[] memory calls = new CallParams[](2);
    calls[0] = CallParams({callee: address(callee), value: 0, data: dataA});
    calls[1] = CallParams({callee: address(callee2), value: 0, data: dataB});

    vm.expectCall(address(callee), 0, abi.encodeCall(IAHV2Callee.execute, (dataA, '')), 1);
    vm.expectCall(address(callee2), 0, abi.encodeCall(IAHV2Callee.execute, (dataB, '')), 1);

    AHV2Order memory order = _ownedOrder(owner);
    order.calls = calls;

    vm.prank(owner);
    hub.settleOrder(order, '', _defaultSolution(order), '', false);

    assertEq(callee.callCount(), 1, 'callee once');
    assertEq(callee2.callCount(), 1, 'callee2 once');
    assertEq(callee.lastData(), dataA, 'callee got its own payload');
    assertEq(callee2.lastData(), dataB, 'callee2 got its own payload');
  }
}
