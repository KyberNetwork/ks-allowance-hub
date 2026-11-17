// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {SchemaHash} from 'test/base/SchemaHash.sol';

import {SettlementBase} from 'test/settlement/base/SettlementBase.sol';

import {IKSAllowanceHubV2} from 'src/interfaces/IKSAllowanceHubV2.sol';
import {IUnorderedNonce} from 'src/interfaces/base/IUnorderedNonce.sol';

import {AHV2Order} from 'src/types/AHV2Order.sol';
import {AHV2Solution} from 'src/types/AHV2Solution.sol';
import {CallParams} from 'src/types/CallParams.sol';
import {ERC20Allowance} from 'src/types/ERC20Allowance.sol';

/**
 * @title SolutionApprovalTest
 * @notice `SOL-01..12` and `OWNER-APR-01..02` — the approval of a solution by the approver the order
 * names
 * @dev The `solutionApprover` the order specifies is who may approve the solution a solver submits.
 * An approval is bound to one order and spends a nonce of the approver's namespace. The owner's own
 * call is not subject to it.
 */
contract SolutionApprovalTest is SettlementBase {
  uint160 internal constant AMOUNT = 5 ether;

  /// @dev A solution nonce away from word 0 and bit 0, so a wrong word or bit is observable
  uint256 internal constant SOLUTION_NONCE = 0x107;

  address internal approver;
  uint256 internal approverKey;

  function setUp() public override {
    super.setUp();
    (approver, approverKey) = makeAddrAndKey('solution approver');
  }

  // -------------------------------------------------------------------------------------------
  // SOL — the solution approval
  // -------------------------------------------------------------------------------------------

  /**
   * SOL-01 — one approval binds one order, `ownerCalls` included
   * @dev `SolutionApproval` carries `orderHash`, and the order hash covers the owner calls, so an
   * approver who signed a solution for one order has not approved the same solution under
   * different owner calls. The two orders differ in that one member and nothing else, so the
   * refusal is about the binding. The second step presents the first order's approval, of the
   * very same solution, with the second order. The first step is the control.
   */
  function test_SOL_01_oneApprovalBindsOneOrder() public {
    CallParams[] memory solverCalls = _calls(_calleeCall(0, hex'01'));
    uint256 deadline = vm.getBlockTimestamp() + 1 hours;

    AHV2Order memory withTailA = _orderWithTail(_calls(_calleeCall(0, hex'aa')), 60, deadline);
    AHV2Solution memory route = _solution(withTailA, solverCalls, deadline);
    bytes32 hashA = SchemaHash.ahv2Order(withTailA);
    bytes memory approvalA = _signSolutionApproval(approverKey, withTailA, route);

    uint256 before = _calleeBalance();

    bytes memory authA = _authOf(withTailA);
    vm.prank(relayer);
    bytes[] memory results = hub.settleOrderWithDelegatedAuthentication(
      withTailA, address(authenticator), authA, route, approvalA, false
    );

    assertEq(_calleeBalance() - before, AMOUNT, 'the approved order settled');
    assertEq(results.length, 2, 'solver call and owner call both ran');

    AHV2Order memory withTailB = _orderWithTail(_calls(_calleeCall(0, hex'bb')), 63, deadline);
    assertTrue(SchemaHash.ahv2Order(withTailB) != hashA, 'the two orders really do differ');

    // a fresh solution nonce, as the first approval spent nonce 0
    AHV2Solution memory routeB = _solution(withTailB, solverCalls, 1, deadline);
    bytes memory approvalOfAForB = _signSolutionApproval(approverKey, withTailA, routeB);

    bytes memory authB = _authOf(withTailB);
    vm.prank(relayer);
    vm.expectRevert(IKSAllowanceHubV2.InvalidSolutionSignature.selector);
    hub.settleOrderWithDelegatedAuthentication(
      withTailB, address(authenticator), authB, routeB, approvalOfAForB, false
    );

    assertEq(callee.callCount(), 2, 'the refused order ran nothing');

    // the same order with its own approval does settle, so the refusal was the approval's doing
    bytes memory approvalB = _signSolutionApproval(approverKey, withTailB, routeB);

    vm.prank(relayer);
    hub.settleOrderWithDelegatedAuthentication(
      withTailB, address(authenticator), authB, routeB, approvalB, false
    );
    assertEq(callee.callCount(), 4, 'solver call and owner call ran for the second order too');
  }

  /**
   * SOL-05 — a solution past its own expiration is refused on both entry points under any
   * approver
   * @dev The check is a modifier, not part of the approval, so it binds even under the sentinel
   * approver where no approval is presented at all. Inclusive at the boundary, like the order's
   * own expiration: the expiration second itself still settles, and the second after it does not.
   */
  function test_SOL_05_theSolutionExpirationIsEnforced() public {
    uint256 orderExpiration = vm.getBlockTimestamp() + 1 days;
    CallParams[] memory solverCalls = _calls(_calleeCall(0, hex'01'));

    AHV2Order memory open = _openAhv2Order(
      _allowances(_tokenAllowance(AMOUNT)), _noHooks(), _noCalls(), 70, orderExpiration
    );

    uint256 before = _calleeBalance();
    vm.prank(owner);
    hub.settleOrderWithDelegatedAuthentication(
      open, address(0), '', _solution(open, solverCalls, vm.getBlockTimestamp()), '', false
    );
    assertEq(_calleeBalance() - before, AMOUNT, 'the expiration second itself still settles');

    vm.warp(vm.getBlockTimestamp() + 1);
    uint256 stale = vm.getBlockTimestamp() - 1;

    vm.prank(owner);
    vm.expectRevert(_deadlinePassed(stale));
    hub.settleOrderWithDelegatedAuthentication(
      open, address(0), '', _solution(open, solverCalls, stale), '', false
    );

    // and the same on the Permit2 entry point, whose modifier stack is written out separately
    AHV2Order memory forRelay = _openAhv2Order(
      _allowances(_tokenAllowance(AMOUNT)), _noHooks(), _noCalls(), 72, orderExpiration
    );
    bytes memory witness = _signWitness(forRelay);

    vm.prank(relayer);
    vm.expectRevert(_deadlinePassed(stale));
    hub.settleOrderWithPermit2Signature(
      forRelay, witness, _solution(forRelay, solverCalls, stale), ''
    );
  }

  /**
   * SOL-06 — an approval is spent when it settles, so it settles at most once
   * @dev The hub spends `solution.nonce` in the approver's namespace once the signature checks.
   * Relayed over Permit2, a second submission of the same order and approval is refused by the
   * approver's nonce before Permit2 sees its own nonce again.
   */
  function test_SOL_06_anApprovalSettlesOnce() public {
    uint256 deadline = vm.getBlockTimestamp() + 1 hours;

    AHV2Order memory named = _ahv2Order(
      ANY,
      _allowances(_tokenAllowance(AMOUNT)),
      _noNfts(),
      _noHooks(),
      _noCalls(),
      approver,
      80,
      deadline
    );
    AHV2Solution memory route =
      _solution(named, _calls(_calleeCall(0, hex'01')), SOLUTION_NONCE, deadline);
    bytes memory approval = _signSolutionApproval(approverKey, named, route);
    bytes memory witness = _signWitness(named);

    uint256 before = _calleeBalance();
    vm.prank(relayer);
    hub.settleOrderWithPermit2Signature(named, witness, route, approval);
    assertEq(_calleeBalance() - before, AMOUNT, 'the order settled');
    assertEq(
      hub.nonces(lNonceKey(approver), SOLUTION_NONCE >> 8),
      1 << (SOLUTION_NONCE & 0xff),
      "exactly the solution nonce is spent in the approver's namespace"
    );

    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(
        IUnorderedNonce.NonceAlreadyUsed.selector, lNonceKey(approver), SOLUTION_NONCE
      )
    );
    hub.settleOrderWithPermit2Signature(named, witness, route, approval);
  }

  /**
   * SOL-02 — the sentinel approver accepts any solution, with no signature to present
   * @dev Two different solutions settle under the same order, which is the meaning of "any
   * solution", and neither carries an approval. The last step is the contrast: a specified
   * approver on the otherwise identical order does demand one from a submitter other than the
   * owner.
   */
  function test_SOL_02_sentinelApproverAcceptsAnySolution() public {
    uint256 expiration = vm.getBlockTimestamp() + 1 hours;

    AHV2Order memory open =
      _openAhv2Order(new ERC20Allowance[](0), _noHooks(), _noCalls(), 0, expiration);

    vm.prank(owner);
    bytes[] memory results = hub.settleOrderWithDelegatedAuthentication(
      open, address(0), '', _route(open, _calls(_calleeCall(0, hex'01'))), '', false
    );

    assertEq(results.length, 1, 'the solution ran');
    assertEq(callee.callCount(), 1, 'once');
    assertEq(hub.nonces(lNonceKey(owner), 0), 0, 'the sentinel approver burns no nonce');

    vm.prank(owner);
    hub.settleOrderWithDelegatedAuthentication(
      open, address(0), '', _route(open, _calls(_calleeCall(0, hex'02'))), '', false
    );

    assertEq(callee.callCount(), 2, 'and a different solution under the same order ran as well');
    assertEq(callee.lastData(), hex'02', 'the second solution is the one that ran last');

    AHV2Order memory withApprover = _ahv2Order(
      ANY, new ERC20Allowance[](0), _noNfts(), _noHooks(), _noCalls(), approver, 0, expiration
    );

    bytes memory auth = _authOf(withApprover);
    vm.prank(relayer);
    vm.expectRevert(IKSAllowanceHubV2.InvalidSolutionSignature.selector);
    hub.settleOrderWithDelegatedAuthentication(
      withApprover,
      address(authenticator),
      auth,
      _route(withApprover, _calls(_calleeCall(0, hex'01'))),
      '',
      false
    );
  }

  /**
   * SOL-03 — a malformed approval is refused rather than read as "no approver specified"
   * @dev The sentinel is the only thing that waives the check, and it lives in the signed order.
   * A signature too short to recover from must therefore fail the check rather than skip it.
   */
  function test_SOL_03_malformedApprovalSignature() public {
    uint256 expiration = vm.getBlockTimestamp() + 1 hours;

    AHV2Order memory order = _ahv2Order(
      ANY, new ERC20Allowance[](0), _noNfts(), _noHooks(), _noCalls(), approver, 0, expiration
    );

    bytes memory auth = _authOf(order);
    vm.prank(relayer);
    vm.expectRevert(IKSAllowanceHubV2.InvalidSolutionSignature.selector);
    hub.settleOrderWithDelegatedAuthentication(
      order,
      address(authenticator),
      auth,
      _route(order, _calls(_calleeCall(0, hex'01'))),
      hex'1234',
      false
    );

    assertEq(callee.callCount(), 0, 'and nothing ran');
  }

  /**
   * SOL-04 — one authenticated order settles at most once
   * @dev The order nonce is burned by the authenticator, which refuses identical calldata a
   * second time before the solution approval is checked.
   */
  function test_SOL_04_anAuthenticatedOrderCannotSettleTwice() public {
    _delegateSignerThroughHub(signer);

    uint256 expiration = vm.getBlockTimestamp() + 1 hours;

    AHV2Order memory order = _ahv2Order(
      ANY,
      _allowances(_tokenAllowance(AMOUNT)),
      _noNfts(),
      _noHooks(),
      _noCalls(),
      ANY,
      21,
      expiration
    );
    bytes memory authData = _orderAuthData(order, signer, signerPk);
    AHV2Solution memory route = _route(order, _calls(_calleeCall(0, hex'01')));

    vm.prank(relayer);
    hub.settleOrderWithDelegatedAuthentication(
      order, address(authenticator), authData, route, '', false
    );

    assertEq(authenticator.nonces(lNonceKey(signer), 0), 1 << 21, 'the order nonce burned');
    assertEq(callee.callCount(), 1, 'the solution ran once');

    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(IUnorderedNonce.NonceAlreadyUsed.selector, lNonceKey(signer), 21)
    );
    hub.settleOrderWithDelegatedAuthentication(
      order, address(authenticator), authData, route, '', false
    );

    assertEq(callee.callCount(), 1, 'and not a second time');
  }

  /**
   * SOL-07 — an approval nonce settles once for its approver, whichever order it approves
   * @dev Two orders share one solution nonce. The approval of the second is refused with the
   * nonce the first spent, and an approval of the same solution with another nonce settles.
   */
  function test_SOL_07_anApprovalNonceCannotBeReusedForAnotherOrder() public {
    CallParams[] memory calls = _calls(_calleeCall(0, hex'01'));
    AHV2Order memory first = _approverOrder(90);
    AHV2Solution memory route = _route(first, calls, 4);
    bytes memory approval = _signSolutionApproval(approverKey, first, route);
    bytes memory firstAuth = _authOf(first);

    vm.prank(relayer);
    hub.settleOrderWithDelegatedAuthentication(
      first, address(authenticator), firstAuth, route, approval, false
    );
    assertEq(callee.callCount(), 1, 'the first settlement ran');

    AHV2Order memory second = _approverOrder(96);
    AHV2Solution memory reused = _route(second, calls, 4);
    bytes memory reusedApproval = _signSolutionApproval(approverKey, second, reused);
    bytes memory secondAuth = _authOf(second);
    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(IUnorderedNonce.NonceAlreadyUsed.selector, lNonceKey(approver), 4)
    );
    hub.settleOrderWithDelegatedAuthentication(
      second, address(authenticator), secondAuth, reused, reusedApproval, false
    );
    assertEq(callee.callCount(), 1, 'the reuse ran nothing');

    AHV2Solution memory fresh = _route(second, calls, 5);
    bytes memory freshApproval = _signSolutionApproval(approverKey, second, fresh);
    vm.prank(relayer);
    hub.settleOrderWithDelegatedAuthentication(
      second, address(authenticator), secondAuth, fresh, freshApproval, false
    );
    assertEq(callee.callCount(), 2, 'an approval with a fresh nonce settles');
    assertEq(hub.nonces(lNonceKey(approver), 0), (1 << 4) | (1 << 5), 'both nonces are spent');
  }

  /// SOL-08 — the approver revokes an unused approval with `revokeNonce`
  function test_SOL_08_theApproverRevokesAnApproval() public {
    AHV2Order memory order = _approverOrder(91);
    AHV2Solution memory route = _route(order, _calls(_calleeCall(0, hex'01')), 9);
    bytes memory approval = _signSolutionApproval(approverKey, order, route);

    vm.expectEmit(address(hub));
    emit IUnorderedNonce.RevokeNonce(lNonceKey(approver), 9);
    vm.prank(approver);
    hub.revokeNonce(9);

    bytes memory auth = _authOf(order);
    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(IUnorderedNonce.NonceAlreadyUsed.selector, lNonceKey(approver), 9)
    );
    hub.settleOrderWithDelegatedAuthentication(
      order, address(authenticator), auth, route, approval, false
    );
    assertEq(callee.callCount(), 0, 'the revoked approval ran nothing');
  }

  /// SOL-09 — the dead-address approver spends no nonce, so the same nonce repeats
  function test_SOL_09_theSentinelApproverSpendsNothing() public {
    AHV2Order memory open = _openAhv2Order(
      new ERC20Allowance[](0), _noHooks(), _noCalls(), 0, vm.getBlockTimestamp() + 1 hours
    );
    AHV2Solution memory route = _route(open, _calls(_calleeCall(0, hex'01')), 7);

    vm.startPrank(owner);
    hub.settleOrderWithDelegatedAuthentication(open, address(0), '', route, '', false);
    hub.settleOrderWithDelegatedAuthentication(open, address(0), '', route, '', false);
    vm.stopPrank();

    assertEq(callee.callCount(), 2, 'both settlements ran with the same nonce');
    assertEq(hub.nonces(lNonceKey(ANY), 0), 0, "the dead address's namespace is untouched");
  }

  /// SOL-10 — the Permit2 entry point spends the approval nonce as the delegated one does
  function test_SOL_10_thePermit2EntryPointSpendsTheApprovalNonce() public {
    uint256 deadline = vm.getBlockTimestamp() + 1 hours;
    AHV2Order memory order = _ahv2Order(
      ANY,
      _allowances(_tokenAllowance(AMOUNT)),
      _noNfts(),
      _noHooks(),
      _noCalls(),
      approver,
      92,
      deadline
    );
    AHV2Solution memory route = _route(order, _calls(_calleeCall(0, hex'01')), 6);
    bytes memory approval = _signSolutionApproval(approverKey, order, route);
    bytes memory permitSig = _signWitness(order);

    assertEq(hub.nonces(lNonceKey(approver), 0), 0, 'nothing is spent before the settlement');

    vm.prank(solver);
    hub.settleOrderWithPermit2Signature(order, permitSig, route, approval);

    assertEq(hub.nonces(lNonceKey(approver), 0), 1 << 6, "the approver's bit is set");
  }

  /**
   * SOL-11 — exactly the solution nonce is spent, and a replay reports it
   * @dev The word and the bit are derived from the drawn nonce with plain shifts, so a wrong word
   * or bit shows as a different namespace state.
   */
  function testFuzz_SOL_11_exactlyTheSolutionNonceIsSpent(SolutionNonceFuzz memory f) public {
    AHV2Order memory order = _approverOrder(93);
    AHV2Solution memory route = _route(order, _calls(_calleeCall(0, hex'01')), f.nonce);
    bytes memory approval = _signSolutionApproval(approverKey, order, route);
    bytes memory auth = _authOf(order);

    vm.prank(relayer);
    hub.settleOrderWithDelegatedAuthentication(
      order, address(authenticator), auth, route, approval, false
    );

    assertEq(
      hub.nonces(lNonceKey(approver), f.nonce >> 8),
      1 << (f.nonce & 0xff),
      "exactly the solution nonce is set in the approver's namespace"
    );

    AHV2Order memory other = _approverOrder(95);
    AHV2Solution memory replay = _route(other, _calls(_calleeCall(0, hex'01')), f.nonce);
    bytes memory replayApproval = _signSolutionApproval(approverKey, other, replay);
    bytes memory otherAuth = _authOf(other);

    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(
        IUnorderedNonce.NonceAlreadyUsed.selector, lNonceKey(approver), f.nonce
      )
    );
    hub.settleOrderWithDelegatedAuthentication(
      other, address(authenticator), otherAuth, replay, replayApproval, false
    );
  }

  /**
   * SOL-12 — the approver's namespace is shared with its `updateDelegation` nonces
   * @dev The approver, acting as an owner, spends nonce 11 on a relayed delegation update. An
   * approval with the same nonce is then refused.
   */
  function test_SOL_12_theApproverNamespaceIsSharedWithDelegationNonces() public {
    uint256 deadline = vm.getBlockTimestamp() + 1 hours;
    bytes memory sig =
      _signAuthDelegation(approverKey, approver, address(authenticator), false, '', 11, deadline);
    vm.prank(relayer);
    hub.updateDelegation(approver, address(authenticator), false, '', 11, deadline, sig);
    assertEq(hub.nonces(lNonceKey(approver), 0), 1 << 11, 'the delegation spent nonce 11');

    AHV2Order memory order = _approverOrder(94);
    AHV2Solution memory route = _route(order, _calls(_calleeCall(0, hex'01')), 11);
    bytes memory approval = _signSolutionApproval(approverKey, order, route);

    bytes memory auth = _authOf(order);
    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(IUnorderedNonce.NonceAlreadyUsed.selector, lNonceKey(approver), 11)
    );
    hub.settleOrderWithDelegatedAuthentication(
      order, address(authenticator), auth, route, approval, false
    );
  }

  // -------------------------------------------------------------------------------------------
  // OWNER-APR — the owner's call is not subject to the solution approval
  // -------------------------------------------------------------------------------------------

  /**
   * OWNER-APR-01 — the owner settles under a named approver with a garbage approval
   * @dev The signature is not read and the solution nonce is not spent, on both entry points.
   */
  function testFuzz_OWNER_APR_01_ownerSettlesWithoutAnApproval(OwnerApprovalFuzz memory f) public {
    (AHV2Order memory order, AHV2Solution memory route, ERC20Allowance[] memory erc20s) =
      _namedApproverSettlement(98);
    bytes memory garbage = f.emptySignature ? bytes('') : bytes(hex'dead');
    uint256 before = _calleeBalance();

    if (f.viaPermit2) {
      bytes memory permitSig = _signPlainPermit(erc20s, 98, order.expiration);
      vm.prank(owner);
      hub.settleOrderWithPermit2Signature(order, permitSig, route, garbage);
    } else {
      vm.prank(owner);
      hub.settleOrderWithDelegatedAuthentication(order, address(0), '', route, garbage, false);
    }

    assertEq(_calleeBalance() - before, AMOUNT, 'the owner settled');
    assertEq(
      hub.nonces(lNonceKey(approver), route.nonce >> 8), 0, "the approver's namespace is untouched"
    );
  }

  /**
   * OWNER-APR-02 — the solver submitting the same order and approval is refused
   * @dev The authentication or the witness is valid, so the approval check is the one reached.
   */
  function testFuzz_OWNER_APR_02_solverIsRefusedWithoutAnApproval(OwnerApprovalFuzz memory f)
    public
  {
    (AHV2Order memory order, AHV2Solution memory route,) = _namedApproverSettlement(99);
    bytes memory garbage = f.emptySignature ? bytes('') : bytes(hex'dead');
    uint256 before = _calleeBalance();

    if (f.viaPermit2) {
      bytes memory witnessSig = _signWitness(order);
      vm.prank(solver);
      vm.expectRevert(IKSAllowanceHubV2.InvalidSolutionSignature.selector);
      hub.settleOrderWithPermit2Signature(order, witnessSig, route, garbage);
    } else {
      bytes memory auth = _authOf(order);
      vm.prank(solver);
      vm.expectRevert(IKSAllowanceHubV2.InvalidSolutionSignature.selector);
      hub.settleOrderWithDelegatedAuthentication(
        order, address(authenticator), auth, route, garbage, false
      );
    }

    assertEq(_calleeBalance(), before, 'nothing moved');
  }

  // -------------------------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------------------------

  /// @dev Parameters of the OWNER-APR fuzz: the entry point and the form of the garbage approval
  struct OwnerApprovalFuzz {
    bool viaPermit2;
    bool emptySignature;
  }

  /// @dev Parameters of the SOL-11 fuzz
  struct SolutionNonceFuzz {
    uint256 nonce;
  }

  /// @dev An order moving `AMOUNT` to the callee under the named `approver`, and a solution with
  /// the nonce `SOLUTION_NONCE`
  function _namedApproverSettlement(uint256 nonce)
    private
    view
    returns (AHV2Order memory, AHV2Solution memory, ERC20Allowance[] memory erc20s)
  {
    erc20s = _allowances(_tokenAllowance(AMOUNT));
    AHV2Order memory order = _ahv2Order(
      ANY,
      erc20s,
      _noNfts(),
      _noHooks(),
      _noCalls(),
      approver,
      nonce,
      vm.getBlockTimestamp() + 1 hours
    );
    return (order, _route(order, _calls(_calleeCall(0, hex'01')), SOLUTION_NONCE), erc20s);
  }

  /// @dev An order with no transfers whose approver is `approver`, valid for an hour
  function _approverOrder(uint256 nonce) private view returns (AHV2Order memory) {
    return _ahv2Order(
      ANY,
      new ERC20Allowance[](0),
      _noNfts(),
      _noHooks(),
      _noCalls(),
      approver,
      nonce,
      vm.getBlockTimestamp() + 1 hours
    );
  }

  /// @dev The SOL-01 pair: one order shape, varying only in the owner calls
  function _orderWithTail(CallParams[] memory ownerCalls, uint256 nonce, uint256 expiration)
    private
    view
    returns (AHV2Order memory)
  {
    return _ahv2Order(
      ANY,
      _allowances(_tokenAllowance(AMOUNT)),
      _noNfts(),
      _noHooks(),
      ownerCalls,
      approver,
      nonce,
      expiration
    );
  }
}
