// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {SchemaHash} from 'test/base/SchemaHash.sol';

import {SignerAuthenticatorMock} from 'test/mocks/SignerAuthenticatorMock.sol';

import {SettlementBase} from 'test/settlement/base/SettlementBase.sol';

import {IKSAllowanceHubV2} from 'src/interfaces/IKSAllowanceHubV2.sol';
import {IAHV2Authenticator} from 'src/interfaces/base/IAHV2Authenticator.sol';
import {IAuthDelegator} from 'src/interfaces/base/IAuthDelegator.sol';

import {AHV2Order} from 'src/types/AHV2Order.sol';
import {AHV2Solution} from 'src/types/AHV2Solution.sol';
import {CallParams} from 'src/types/CallParams.sol';
import {ERC20Allowance} from 'src/types/ERC20Allowance.sol';
import {ERC721Approval} from 'src/types/ERC721Approval.sol';
import {HookParams} from 'src/types/HookParams.sol';

import {IERC20} from 'openzeppelin-contracts/contracts/token/ERC20/IERC20.sol';

/**
 * @title AuthenticationTest
 * @notice `AUTH-01b`, `AUTH-04`, `AUTH-06..08`, `AUTH-13`, `AUTH-18..21` and `ORD-01..04` — how a settlement is
 * authenticated on each entry point, and the parties an order names
 * @dev An owner submitting their own order needs no Permit2 witness and no solution approval, and a
 * delegated authenticator still authenticates it. Any other submitter carries the
 * owner's Permit2 witness signature or the data of a delegated authenticator. The exclusive caller
 * says who may submit an order on every entry point. An approved signer authenticates the owner; it
 * does not say who may submit the order, so an authenticator that checked nothing of the sort would
 * leave the field unenforced. `ORD-03b` shows the owner is not subject to a field that exists to
 * bound everybody else, and `ORD-04` covers the account the order draws on.
 */
contract AuthenticationTest is SettlementBase {
  /// @dev The amount moved by the cases of `ORD-03b` and `ORD-04`
  uint160 internal constant PARTY_AMOUNT = 1 ether;

  /// @dev Permit2 does not expose this in the vendored interface, so it is written out here
  bytes4 internal constant PERMIT2_INVALID_SIGNER = bytes4(keccak256('InvalidSigner()'));

  // -------------------------------------------------------------------------------------------
  // AUTH-01b / AUTH-04 / AUTH-07 — the Permit2 signature entry point
  // -------------------------------------------------------------------------------------------

  /**
   * AUTH-01b — the owner submits their own order, so the permit witnesses nothing and the approval
   * is still checked
   * @dev An owner submitting for themselves skips the witness entirely, so the hooks and the
   * approver the order specifies are bound by no signature. The approval is checked: the first
   * step settles with a valid approval and spends its nonce, and the second presents an approval
   * of a solution other than the one submitted and is refused.
   */
  function test_AUTH_01b_permit2SelfSubmittedChecksTheApproval() public {
    ERC20Allowance[] memory erc20s = _allowances(_tokenAllowance(AMOUNT));
    HookParams[] memory hooks = _hooks(_hook(hook));
    uint256 deadline = vm.getBlockTimestamp() + 1 hours;

    AHV2Order memory order = _ahv2Order(
      permit2, ANY, erc20s, _noNfts(), hooks, _calls(_calleeCall(hex'01')), approver, 61, deadline
    );
    AHV2Solution memory solution = _solution(order, deadline);

    bytes memory permitSig = _signPlainPermit(erc20s, 61, deadline);
    bytes memory approval = _signSolutionApproval(approverKey, order, solution);

    uint256 before = _calleeBalance();

    vm.prank(owner);
    bytes[] memory results = hub.settleOrder(order, permitSig, solution, approval);

    assertEq(_calleeBalance() - before, AMOUNT, 'erc20 transfer');
    assertEq(results.length, 1, 'one callee result');
    assertEq(hook.sequenceLength(), 2, 'the hook bracketed the order');
    assertEq(hub.nonces(lNonceKey(approver), 0), 1, 'the approval nonce is spent');

    AHV2Order memory again = _ahv2Order(
      permit2, ANY, erc20s, _noNfts(), hooks, _calls(_calleeCall(hex'02')), approver, 62, deadline
    );
    // a fresh solution nonce, so the approval does not fit the solution
    AHV2Solution memory otherRoute = _solution(again, 1, deadline);
    bytes memory permitSig2 = _signPlainPermit(erc20s, 62, deadline);

    vm.prank(owner);
    vm.expectRevert(IKSAllowanceHubV2.InvalidSolutionSignature.selector);
    hub.settleOrder(again, permitSig2, otherRoute, approval);

    assertEq(_calleeBalance() - before, AMOUNT, 'nothing moved by the second step');
  }

  /**
   * AUTH-04 — the exclusive caller the owner specified is part of what the witness binds
   * @dev `order.exclusiveCaller` is read twice: the hub compares it against the submitter, and the
   * witness carries it. ORD-03 is the comparison; this is the witness. The first step is the
   * control, so the refusal in the second is evidence about the binding rather than about a
   * signature that was never going to be accepted: the owner signed a witness specifying the
   * solver, the order submitted specifies no exclusive caller, and the hub rebuilds a different
   * witness from it.
   */
  function test_AUTH_04_witnessPinsTheExclusiveCaller() public {
    ERC20Allowance[] memory erc20s = _allowances(_tokenAllowance(AMOUNT));
    uint256 expiration = vm.getBlockTimestamp() + 1 hours;

    AHV2Order memory pinned =
      _ahv2Order(permit2, solver, erc20s, _noNfts(), _noHooks(), _noCalls(), ANY, 3, expiration);
    bytes memory matching = _signPermit2Order(pinned);

    uint256 before = _calleeBalance();

    vm.prank(solver);
    hub.settleOrder(pinned, matching, _defaultSolution(pinned), '');
    assertEq(_calleeBalance() - before, AMOUNT, 'the matching order settled');

    AHV2Order memory openOrder =
      _openAhv2Order(permit2, erc20s, _noHooks(), _noCalls(), 4, expiration);
    bytes memory forTheSolver = _signPermit2Order(
      _ahv2Order(permit2, solver, erc20s, _noNfts(), _noHooks(), _noCalls(), ANY, 4, expiration)
    );
    AHV2Solution memory solution = _defaultSolution(openOrder);

    vm.prank(solver);
    vm.expectRevert(PERMIT2_INVALID_SIGNER);
    hub.settleOrder(openOrder, forTheSolver, solution, '');
  }

  /**
   * AUTH-07 — a solver settles a witnessed order under the sentinel approver with its own solution
   * @dev The witness specifies who may choose the solution, not the solution.
   */
  function test_AUTH_07_permit2Witness() public {
    ERC20Allowance[] memory erc20s = _allowances(_tokenAllowance(AMOUNT));
    HookParams[] memory hooks = _hooks(_hook(hook));
    uint256 expiration = vm.getBlockTimestamp() + 1 hours;

    // the sentinel approver, so the owner is signing "any solution the solver picks"
    AHV2Order memory order = _ahv2Order(
      permit2, ANY, erc20s, _noNfts(), hooks, _calls(_calleeCall(hex'01')), ANY, 30, expiration
    );
    bytes memory signature = _signPermit2Order(order);

    uint256 before = _calleeBalance();

    vm.prank(solver);
    bytes[] memory results = hub.settleOrder(order, signature, _defaultSolution(order), '');

    assertEq(_calleeBalance() - before, AMOUNT, 'erc20 transfer');
    assertEq(results.length, 1, 'one callee result');
    assertEq(hook.sequenceLength(), 2, 'the hook saw both calls');
  }

  /**
   * AUTH-07b — the solver cannot swap in a different approver than the one the owner signed
   * @dev `solutionApprover` is read twice: the hub asks it to approve the solution, and the
   * witness carries it. The second step presents a perfectly valid approval from an approver of
   * the solver's choosing, so the refusal is Permit2's and is about the witness rather than about
   * the approval. The first step is the control.
   */
  function test_AUTH_07b_solutionApproverIsBoundByTheWitness() public {
    ERC20Allowance[] memory erc20s = _allowances(_tokenAllowance(AMOUNT));
    CallParams[] memory calls = _calls(_calleeCall(hex'01'));
    uint256 deadline = vm.getBlockTimestamp() + 1 hours;

    AHV2Order memory named =
      _ahv2Order(permit2, ANY, erc20s, _noNfts(), _noHooks(), calls, approver, 31, deadline);
    AHV2Solution memory solution = _solution(named, deadline);
    bytes memory approval = _signSolutionApproval(approverKey, named, solution);
    bytes memory matchingWitness = _signPermit2Order(named);

    uint256 before = _calleeBalance();

    vm.prank(solver);
    hub.settleOrder(named, matchingWitness, solution, approval);
    assertEq(_calleeBalance() - before, AMOUNT, 'the matching order settled');

    AHV2Order memory swapped =
      _ahv2Order(permit2, ANY, erc20s, _noNfts(), _noHooks(), calls, approver, 32, deadline);
    AHV2Solution memory solution2 = _solution(swapped, 1, deadline);
    bytes memory approval2 = _signSolutionApproval(approverKey, swapped, solution2);
    // the owner signed a witness that specifies no approver, so the approver in the order is not
    // the one signed
    bytes memory openWitness = _signPermit2Order(
      _ahv2Order(permit2, ANY, erc20s, _noNfts(), _noHooks(), calls, ANY, 32, deadline)
    );

    vm.prank(solver);
    vm.expectRevert(PERMIT2_INVALID_SIGNER);
    hub.settleOrder(swapped, openWitness, solution2, approval2);
  }

  /**
   * ORD-03 — only the named exclusive caller may submit a Permit2 settlement, the sentinel admits
   * anyone
   * @dev The witness binds `exclusiveCaller` as the order specifies it, not as the caller
   * presents itself, so the hub's own comparison is the only thing between a stranger and a
   * settled order here. The comparison runs before Permit2 pulls anything, so the middle step's
   * refusal is the hub's error and reports the submitter. The last step is what makes the middle
   * one about the pin rather than about the submitter.
   */
  function test_ORD_03_exclusiveCallerPinningAndTheOpenSentinel() public {
    ERC20Allowance[] memory erc20s = _allowances(_tokenAllowance(AMOUNT));
    AHV2Solution memory solution = _solution(
      _addresses(address(callee)),
      _amounts(AMOUNT),
      new address[](0),
      vm.getBlockTimestamp() + 1 hours
    );
    solution.callValues = new uint256[](1);
    solution.solverData = _solverData(1);
    uint256 expiration = vm.getBlockTimestamp() + 1 hours;

    AHV2Order memory pinned = _ahv2Order(
      permit2,
      solver,
      erc20s,
      _noNfts(),
      _noHooks(),
      _calls(_calleeCall(hex'01')),
      ANY,
      61,
      expiration
    );
    bytes memory pinnedSig = _signPermit2Order(pinned);

    uint256 before = _calleeBalance();
    vm.prank(solver);
    hub.settleOrder(pinned, pinnedSig, solution, '');
    assertEq(_calleeBalance() - before, AMOUNT, 'the named exclusive caller may submit');

    AHV2Order memory pinnedAgain = _ahv2Order(
      permit2,
      solver,
      erc20s,
      _noNfts(),
      _noHooks(),
      _calls(_calleeCall(hex'01')),
      ANY,
      62,
      expiration
    );
    bytes memory againSig = _signPermit2Order(pinnedAgain);

    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(IKSAllowanceHubV2.NotExclusiveCallerOrOwner.selector, relayer)
    );
    hub.settleOrder(pinnedAgain, againSig, solution, '');

    assertEq(
      _permit2NonceBitmap(owner, 62 >> 8) & (1 << 62),
      0,
      'the refused order burned no Permit2 nonce'
    );

    AHV2Order memory openOrder =
      _openAhv2Order(permit2, erc20s, _noHooks(), _calls(_calleeCall(hex'01')), 63, expiration);
    bytes memory openSig = _signPermit2Order(openOrder);

    before = _calleeBalance();
    vm.prank(relayer);
    hub.settleOrder(openOrder, openSig, solution, '');
    assertEq(
      _calleeBalance() - before, AMOUNT, 'the sentinel opened submission to the very same stranger'
    );
  }

  // -------------------------------------------------------------------------------------------
  // AUTH-06 / AUTH-08 / AUTH-13 / AUTH-18..21 / ORD-01 — the delegated authentication entry point
  // -------------------------------------------------------------------------------------------

  /// AUTH-06 — an owner acting for themselves with no authenticator needs no authentication
  function test_AUTH_06_ownerCallerNeedsNoAuthentication() public {
    AHV2Order memory order = _openAhv2Order(
      _allowances(_tokenAllowance(AMOUNT)),
      _noHooks(),
      _noCalls(),
      0,
      vm.getBlockTimestamp() + 1 hours
    );
    AHV2Solution memory solution = _defaultSolution(order);
    uint256 before = _calleeBalance();

    vm.prank(owner);
    hub.settleOrder(order, '', solution, '');

    assertEq(_calleeBalance() - before, AMOUNT, 'no authenticator at all');
  }

  /// AUTH-06b — an owner's own call without an authenticator draws on the Permit2 allowance
  function test_AUTH_06b_ownerCallerViaPermit2Allowance() public {
    _grantPermit2Allowance(token18, 100 ether);

    uint256 before = _calleeBalance();
    uint160 allowanceBefore = _permit2Allowance(token18);

    AHV2Order memory order = _openAhv2Order(
      _allowances(_tokenAllowance(AMOUNT)),
      _noHooks(),
      _noCalls(),
      0,
      vm.getBlockTimestamp() + 1 hours
    );
    _withPermit2Transfers(order, order.erc20Allowances.length);

    vm.prank(owner);
    hub.settleOrder(order, '', _defaultSolution(order), '');

    assertEq(_calleeBalance() - before, AMOUNT);
    assertEq(allowanceBefore - _permit2Allowance(token18), AMOUNT, 'drawn on the Permit2 allowance');
  }

  /**
   * AUTH-08 — an authenticator the owner never delegated is refused before it is ever called
   * @dev The authenticator receives no call of any kind.
   */
  function test_AUTH_08_undelegatedAuthenticatorRefused() public {
    AHV2Order memory order = _openAhv2Order(
      address(authenticator),
      _allowances(_tokenAllowance(AMOUNT)),
      _noHooks(),
      _noCalls(),
      0,
      vm.getBlockTimestamp() + 1 hours
    );
    AHV2Solution memory solution = _defaultSolution(order);
    bytes memory authData = _authData(signer, hex'00');

    vm.expectCall(
      address(authenticator), abi.encodeWithSelector(IAHV2Authenticator.authenticate.selector), 0
    );
    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(
        IAuthDelegator.AuthenticatorNotDelegated.selector, address(authenticator)
      )
    );
    hub.settleOrder(order, authData, solution, '');
  }

  /**
   * ORD-01 — the asset source is selected by the order flags, and the same order shape settles
   * either way
   * @dev The number of Permit2 transfers is part of the signed order, so the pull path is fixed by
   * what the owner signed. The two steps here are the same order shape and the same amount, and
   * each step asserts that the source it did not select went untouched.
   */
  function test_ORD_01_theAssetSourceIsSelectedByTheOrderFlags() public {
    _delegateSignerThroughHub(signer);
    _grantPermit2Allowance(token18, 100 ether);

    uint256 expiration = vm.getBlockTimestamp() + 1 hours;
    ERC20Allowance[] memory erc20s = _allowances(_tokenAllowance(AMOUNT));

    AHV2Order memory plainOrder =
      _openAhv2Order(address(authenticator), erc20s, _noHooks(), _noCalls(), 40, expiration);
    bytes memory plainAuth = _orderAuthData(plainOrder, signer, signerPk);

    uint256 before = _calleeBalance();
    uint160 allowanceBefore = _permit2Allowance(token18);

    vm.prank(relayer);
    hub.settleOrder(plainOrder, plainAuth, _defaultSolution(plainOrder), '');

    assertEq(_calleeBalance() - before, AMOUNT, 'plain allowance path');
    assertEq(_permit2Allowance(token18), allowanceBefore, 'and it left the Permit2 allowance alone');

    AHV2Order memory permit2Order = _withPermit2Transfers(
      _openAhv2Order(address(authenticator), erc20s, _noHooks(), _noCalls(), 41, expiration), 1
    );
    bytes memory permit2Auth = _orderAuthData(permit2Order, signer, signerPk);

    before = _calleeBalance();

    vm.prank(relayer);
    hub.settleOrder(permit2Order, permit2Auth, _defaultSolution(permit2Order), '');

    assertEq(_calleeBalance() - before, AMOUNT, 'permit2 allowance path');
    assertEq(allowanceBefore - _permit2Allowance(token18), AMOUNT, 'and that path did claim it');
  }

  /**
   * ORD-01b — the Permit2 signature entry point takes no source argument and claims neither
   * allowance
   * @dev That entry point pulls with `permitWitnessTransferFrom`, a signature transfer, which
   * consults no allowance at all. Shown from both sides, because each alone would be weak: the
   * owner's plain allowance to the hub is revoked outright and the order still settles, and the
   * Permit2 allowance is left live and finite so that a draw on it would be visible. The setup's
   * plain allowance is infinite, so asserting it merely went unchanged would prove nothing;
   * revoking it is what gives this force.
   */
  function test_ORD_01b_thePermit2SignatureEntryPointConsultsNoAllowance() public {
    _grantPermit2Allowance(token18, 100 ether);

    // the one allowance this entry point could have drawn on, taken away
    vm.prank(owner);
    IERC20(token18).approve(address(hub), 0);

    uint256 expiration = vm.getBlockTimestamp() + 1 hours;
    AHV2Order memory order = _openAhv2Order(
      permit2, _allowances(_tokenAllowance(AMOUNT)), _noHooks(), _noCalls(), 44, expiration
    );
    bytes memory witness = _signPermit2Order(order);

    uint160 permit2Before = _permit2Allowance(token18);
    uint256 before = _calleeBalance();

    vm.prank(relayer);
    hub.settleOrder(order, witness, _defaultSolution(order), '');

    assertEq(_calleeBalance() - before, AMOUNT, 'the signature transfer ran');
    assertEq(
      IERC20(token18).allowance(owner, address(hub)), 0, 'with no plain allowance to draw on'
    );
    assertEq(_permit2Allowance(token18), permit2Before, 'and the Permit2 allowance went untouched');
  }

  /**
   * AUTH-13 — authentication data too short to settle is rejected, on whichever gate it reaches
   * @dev A single word and a payload truncated by one word fail the authenticator's ABI decoding,
   * which reverts with empty data. A well-formed payload with an empty signature fails
   * verification with the authenticator's error, which the hub returns unchanged.
   */
  function test_AUTH_13_malformedAuthenticationDataRejected() public {
    _delegateSignerThroughHub(signer);

    AHV2Order memory order = _openAhv2Order(
      address(authenticator),
      _allowances(_tokenAllowance(AMOUNT)),
      _noHooks(),
      _noCalls(),
      0,
      vm.getBlockTimestamp() + 1 hours
    );
    AHV2Solution memory solution = _defaultSolution(order);

    vm.prank(relayer);
    vm.expectRevert(bytes(''));
    hub.settleOrder(order, _encodeSigner(signer), solution, '');

    vm.prank(relayer);
    vm.expectRevert(SignerAuthenticatorMock.InvalidOrderSignature.selector);
    hub.settleOrder(order, _authData(signer, ''), solution, '');

    bytes memory whole = _orderAuthData(order, signer, signerPk);
    bytes memory truncated = new bytes(whole.length - 32);
    for (uint256 i = 0; i < truncated.length; i++) {
      truncated[i] = whole[i];
    }

    vm.prank(relayer);
    vm.expectRevert(bytes(''));
    hub.settleOrder(order, truncated, solution, '');
  }

  /**
   * AUTH-18 — the authenticator receives the order, its hash, the solution and the data,
   * unaltered
   * @dev The solution is submitted beside the order and the owner has not signed it, so the hub
   * passes the struct it received. The solution pays less than the allowance and the order carries
   * a call, so a hub that substituted a default or a rebuilt solution would send different
   * calldata. The expected calldata is assembled from the interface and the order hash from the
   * bound schema. The settlement assertion rules out a vacuous pass.
   */
  function test_AUTH_18_authenticatorReceivesTheOrderAndTheSolution() public {
    _delegateSignerThroughHub(signer);

    ERC20Allowance[] memory erc20s = _allowances(_tokenAllowance(AMOUNT));
    uint256 deadline = vm.getBlockTimestamp() + 1 hours;

    AHV2Order memory order = _openAhv2Order(
      address(authenticator), erc20s, _noHooks(), _calls(_calleeCall(hex'01')), 37, deadline
    );
    bytes memory authData = _orderAuthData(order, signer, signerPk);

    uint160 paid = AMOUNT - 1 ether;
    AHV2Solution memory solution =
      _solution(_addresses(address(callee)), _amounts(paid), new address[](0), deadline - 1);
    solution.callValues = new uint256[](1);
    solution.solverData = _solverData(1);

    bytes memory expectedCall = abi.encodeCall(
      IAHV2Authenticator.authenticate, (order, SchemaHash.ahv2Order(order), solution, authData)
    );

    uint256 before = _calleeBalance();

    vm.expectCall(address(authenticator), expectedCall, 1);

    vm.prank(relayer);
    hub.settleOrder(order, authData, solution, '');

    assertEq(_calleeBalance() - before, paid, 'and the order settled by the solution');
  }

  /**
   * AUTH-19 — an owner submitting an order with a delegated authenticator is authenticated
   * @dev `authenticate` is called once with the order, its hash, the solution and the data.
   */
  function test_AUTH_19_ownerWithDelegatedAuthenticatorIsAuthenticated() public {
    _delegateSignerThroughHub(signer);
    uint256 deadline = vm.getBlockTimestamp() + 1 hours;
    AHV2Order memory order = _openAhv2Order(
      address(authenticator),
      _allowances(_tokenAllowance(AMOUNT)),
      _noHooks(),
      _noCalls(),
      38,
      deadline
    );
    AHV2Solution memory solution = _defaultSolution(order);
    bytes memory authData = _orderAuthData(order, signer, signerPk);
    uint256 before = _calleeBalance();

    vm.expectCall(
      address(authenticator),
      abi.encodeCall(
        IAHV2Authenticator.authenticate, (order, SchemaHash.ahv2Order(order), solution, authData)
      ),
      1
    );
    vm.prank(owner);
    hub.settleOrder(order, authData, solution, '');

    assertEq(_calleeBalance() - before, AMOUNT, 'the owner settled');
  }

  /// AUTH-20 — an owner is refused when the delegated authenticator rejects the data
  function test_AUTH_20_ownerWithRejectedAuthenticationDataIsRefused() public {
    _delegateSignerThroughHub(signer);
    AHV2Order memory order = _openAhv2Order(
      address(authenticator),
      _allowances(_tokenAllowance(AMOUNT)),
      _noHooks(),
      _noCalls(),
      39,
      vm.getBlockTimestamp() + 1 hours
    );
    uint256 before = _calleeBalance();

    vm.prank(owner);
    vm.expectRevert(SignerAuthenticatorMock.InvalidOrderSignature.selector);
    hub.settleOrder(order, _authData(signer, hex'00'), _defaultSolution(order), '');

    assertEq(_calleeBalance(), before, 'nothing moved');
  }

  /**
   * AUTH-21 — an owner with a delegated authenticator is exempt from the exclusive caller
   * @dev The order names another exclusive caller.
   */
  function test_AUTH_21_ownerWithDelegatedAuthenticatorSkipsTheExclusiveCaller() public {
    _delegateSignerThroughHub(signer);
    uint256 deadline = vm.getBlockTimestamp() + 1 hours;
    AHV2Order memory order = _ahv2Order(
      address(authenticator),
      solver,
      _allowances(_tokenAllowance(AMOUNT)),
      _noNfts(),
      _noHooks(),
      _noCalls(),
      ANY,
      40,
      deadline
    );
    bytes memory authData = _orderAuthData(order, signer, signerPk);
    uint256 before = _calleeBalance();

    vm.prank(owner);
    hub.settleOrder(order, authData, _defaultSolution(order), '');

    assertEq(_calleeBalance() - before, AMOUNT, 'the owner settled');
  }

  // -------------------------------------------------------------------------------------------
  // ORD-03b / ORD-04 — the parties the order names, on the delegated entry point
  // -------------------------------------------------------------------------------------------

  /**
   * ORD-04 — an order repointed to another owner who approved the same signer reverts
   * @dev A signer may be approved by more than one account, and the digest carries no second place
   * for the submitter to point it. The two steps are the same signature against the account it
   * specifies and against another that approved the same signer.
   */
  function test_ORD_04_delegatedEntryPointDrawsOnTheNamedOwner() public {
    _delegateSignerThroughHub(signer);
    address other = makeAddr('other owner');
    deal(token18, other, 100 ether);
    vm.prank(other);
    IERC20(token18).approve(address(hub), type(uint256).max);
    vm.prank(other);
    hub.updateDelegation(
      other,
      address(authenticator),
      true,
      _encodeSigner(signer),
      0,
      vm.getBlockTimestamp() + 1 days,
      ''
    );

    AHV2Order memory order = _openAhv2Order(
      address(authenticator),
      _allowances(_tokenAllowance(PARTY_AMOUNT)),
      _noHooks(),
      _noCalls(),
      75,
      vm.getBlockTimestamp() + 1 hours
    );
    bytes memory authData = _orderAuthData(order, signer, signerPk);

    // Repointed first, because the refusal rolls back the nonce the authenticator burns ahead of
    // the signature check, leaving the second step the same number to spend
    order.owner = other;
    vm.prank(relayer);
    vm.expectRevert(SignerAuthenticatorMock.InvalidOrderSignature.selector);
    hub.settleOrder(order, authData, _defaultSolution(order), '');

    order.owner = owner;
    uint256 before = _calleeBalance();
    uint256 otherBefore = IERC20(token18).balanceOf(other);
    vm.prank(relayer);
    hub.settleOrder(order, authData, _defaultSolution(order), '');
    assertEq(_calleeBalance() - before, PARTY_AMOUNT, 'the named account paid');
    assertEq(IERC20(token18).balanceOf(other), otherBefore, 'and the other one did not');
  }

  /// ORD-03b — the delegated entry point refuses a submitter the order did not specify
  function test_ORD_03b_delegatedEntryPointHonoursTheExclusiveCaller() public {
    _delegateSignerThroughHub(signer);
    ERC20Allowance[] memory allowances = _allowances(_tokenAllowance(PARTY_AMOUNT));
    ERC721Approval[] memory noNfts = _noNfts();
    HookParams[] memory noHooks = _noHooks();
    CallParams[] memory calls = _calls(_calleeCall(hex'01'));
    uint256 expiration = vm.getBlockTimestamp() + 1 hours;

    AHV2Order memory pinned = _ahv2Order(
      address(authenticator), solver, allowances, noNfts, noHooks, calls, ANY, 80, expiration
    );
    uint256 before = _calleeBalance();
    vm.prank(solver);
    hub.settleOrder(pinned, _orderAuthData(pinned, signer, signerPk), _defaultSolution(pinned), '');
    assertEq(_calleeBalance() - before, PARTY_AMOUNT, 'the named solver may submit');

    AHV2Order memory again = _ahv2Order(
      address(authenticator), solver, allowances, noNfts, noHooks, calls, ANY, 81, expiration
    );
    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(IKSAllowanceHubV2.NotExclusiveCallerOrOwner.selector, relayer)
    );
    hub.settleOrder(again, _orderAuthData(again, signer, signerPk), _defaultSolution(again), '');

    // The pin is read before the signature, so an unnamed submitter is refused as such even when
    // the signature it presents could never have passed
    AHV2Order memory third = _ahv2Order(
      address(authenticator), solver, allowances, noNfts, noHooks, calls, ANY, 82, expiration
    );
    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(IKSAllowanceHubV2.NotExclusiveCallerOrOwner.selector, relayer)
    );
    hub.settleOrder(third, _authData(signer, hex'00'), _defaultSolution(third), '');

    // The same stranger settles an order that specifies no exclusive caller, so the refusals were
    // about the pin
    AHV2Order memory open =
      _openAhv2Order(address(authenticator), allowances, noHooks, calls, 83, expiration);
    before = _calleeBalance();
    vm.prank(relayer);
    hub.settleOrder(open, _orderAuthData(open, signer, signerPk), _defaultSolution(open), '');
    assertEq(_calleeBalance() - before, PARTY_AMOUNT, 'the sentinel leaves it open to anyone');

    AHV2Order memory byOwner =
      _ahv2Order(solver, allowances, noNfts, noHooks, calls, ANY, 84, expiration);
    before = _calleeBalance();
    vm.prank(owner);
    hub.settleOrder(byOwner, '', _defaultSolution(byOwner), '');
    assertEq(
      _calleeBalance() - before, PARTY_AMOUNT, 'the owner may submit an order naming someone else'
    );
  }
}
