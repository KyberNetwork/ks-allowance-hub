// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Vm} from 'forge-std/Vm.sol';

import {AuthenticatorBase} from 'test/v2/authenticators/base/AuthenticatorBase.sol';

import {EchoRouterMock, ObservingRouterMock, RouterMock} from 'test/v2/mocks/RouterMock.sol';

import {IUnorderedNonce} from 'src/base/interfaces/IUnorderedNonce.sol';
import {
  ISessionOrderAuthenticator
} from 'src/v2/authenticators/interfaces/ISessionOrderAuthenticator.sol';
import {SessionKey} from 'src/v2/authenticators/types/SessionKey.sol';
import {IKSAllowanceHubV2} from 'src/v2/interfaces/IKSAllowanceHubV2.sol';
import {ERC20Transfer} from 'src/v2/types/ERC20Transfer.sol';
import {ERC721Transfer} from 'src/v2/types/ERC721Transfer.sol';
import {FulfillmentOrder} from 'src/v2/types/FulfillmentOrder.sol';
import {FulfillmentSolution} from 'src/v2/types/FulfillmentSolution.sol';
import {GenericCall} from 'src/v2/types/GenericCall.sol';
import {ValidationParams} from 'src/v2/types/ValidationParams.sol';

import {IAccessControl} from 'openzeppelin-contracts/contracts/access/IAccessControl.sol';
import {IERC20} from 'openzeppelin-contracts/contracts/token/ERC20/IERC20.sol';

/**
 * @notice `AUTH-01b`, `AUTH-07..07b`, `SOL-01..04`, `OWN-01..06` and `VAL-01..04` — both fulfillment
 * rails, the solution approval and the validator bracket.
 * @dev A fulfillment splits in two: the owner fixes `ownerCalls` and the validators, a solver
 * supplies the {FulfillmentSolution}, and the `solutionApprover` the order names is who may approve
 * that route. The validators run between the two call lists.
 */
contract FulfillOrderTest is AuthenticatorBase {
  uint160 internal constant AMOUNT = 5 ether;

  /// @dev Permit2 does not expose this in the vendored interface, so it is written out here
  bytes4 internal constant PERMIT2_INVALID_SIGNER = bytes4(keccak256('InvalidSigner()'));

  /// @dev Written out rather than imported: a role read from the hub would agree with a wrong one
  bytes32 internal constant ROUTER_ROLE = keccak256('WHITELISTED_ROUTER_ROLE');

  SessionKey internal key;

  address internal approver;
  uint256 internal approverKey;

  function setUp() public override {
    super.setUp();
    key = _secpKey(sessionSigner, block.timestamp + 30 days);

    (approver, approverKey) = makeAddrAndKey('solution approver');
    _asEoa(approver);
  }

  // -------------------------------------------------------------------------------------------
  // AUTH-01b / AUTH-07 — the Permit2 signature rail
  // -------------------------------------------------------------------------------------------

  /**
   * AUTH-01b — the owner submits their own fulfillment, so the permit witnesses nothing
   * @dev Worth its own case beyond the branch: an owner submitting for themselves skips the witness
   * entirely, so the validators, their own tail and the approver they named are bound by no
   * signature at all — yet the approval is still demanded and still has to be over this order. The
   * second leg is what says so: the same approval against a route the approver did not sign is
   * refused even though the owner is the caller.
   */
  function test_AUTH_01b_fulfillmentPermit2SelfSubmitted() public {
    ERC20Transfer[] memory erc20s = _erc20s(_wethTransfer(AMOUNT));
    ValidationParams[] memory vs = _validations(_validation(validator));
    uint256 deadline = block.timestamp + 1 hours;

    FulfillmentOrder memory order = _fulfillmentOrder(
      ANY, erc20s, new ERC721Transfer[](0), vs, new GenericCall[](0), approver, 61, deadline
    );
    FulfillmentSolution memory route = _solution(_calls(_routerCall(0, hex'01')), 1, deadline);

    bytes memory permitSig = _signPlainPermit(erc20s, 61, deadline);
    bytes memory approval =
      _signSolutionApproval(approverKey, owner, lFulfillmentOrderHash(order), route);

    uint256 before = IERC20(WETH).balanceOf(address(router));

    vm.prank(owner);
    (bytes[] memory results,) =
      hub.fulfillOrderWithPermit2Signature(owner, order, permitSig, route, approval);

    assertEq(IERC20(WETH).balanceOf(address(router)) - before, AMOUNT, 'erc20 leg');
    assertEq(results.length, 1, 'one router result');
    assertEq(validator.sequenceLength(), 2, 'validator bracketed the order');

    FulfillmentOrder memory again = _fulfillmentOrder(
      ANY, erc20s, new ERC721Transfer[](0), vs, new GenericCall[](0), approver, 62, deadline
    );
    // a route nonce of its own: the hub burns the first leg's, so reusing 1 would be refused
    FulfillmentSolution memory otherRoute = _solution(_calls(_routerCall(0, hex'02')), 2, deadline);
    bytes memory permitSig2 = _signPlainPermit(erc20s, 62, deadline);

    vm.prank(owner);
    vm.expectRevert(IKSAllowanceHubV2.InvalidSolutionSignature.selector);
    hub.fulfillOrderWithPermit2Signature(owner, again, permitSig2, otherRoute, approval);
  }

  /// AUTH-07 — a solver submits, and the witness names who may choose the route, not the route
  function test_AUTH_07_fulfillmentPermit2Witness() public {
    ERC20Transfer[] memory erc20s = _erc20s(_wethTransfer(AMOUNT));
    ValidationParams[] memory vs = _validations(_validation(validator));
    uint256 deadline = block.timestamp + 1 hours;

    // the sentinel approver, so the owner is signing "any route the solver picks"
    FulfillmentOrder memory order = _fulfillmentOrder(
      ANY, erc20s, new ERC721Transfer[](0), vs, new GenericCall[](0), ANY, 30, deadline
    );
    bytes memory signature = _signFulfillmentWitness(order);

    uint256 before = IERC20(WETH).balanceOf(address(router));

    vm.prank(solver);
    (bytes[] memory results,) = hub.fulfillOrderWithPermit2Signature(
      owner, order, signature, _route(_calls(_routerCall(0, hex'01'))), ''
    );

    assertEq(IERC20(WETH).balanceOf(address(router)) - before, AMOUNT, 'erc20 leg');
    assertEq(results.length, 1, 'one router result');
    assertEq(validator.sequenceLength(), 2, 'validator saw both hooks');
  }

  /**
   * AUTH-07b — the solver cannot swap in a different approver than the one the owner signed
   * @dev `solutionApprover` is read twice, as `order.relayer` is on the execute rail: the hub asks
   * it to approve the route, and the witness carries it as `callsSigner`. The second leg presents a
   * perfectly valid approval from an approver of the solver's choosing, so the refusal is Permit2's
   * and is about the witness rather than about the approval. The first leg is the control.
   */
  function test_AUTH_07b_solutionApproverIsBoundByTheWitness() public {
    ERC20Transfer[] memory erc20s = _erc20s(_wethTransfer(AMOUNT));
    GenericCall[] memory solverCalls = _calls(_routerCall(0, hex'01'));
    uint256 deadline = block.timestamp + 1 hours;

    FulfillmentOrder memory named = _fulfillmentOrder(
      ANY,
      erc20s,
      new ERC721Transfer[](0),
      new ValidationParams[](0),
      new GenericCall[](0),
      approver,
      31,
      deadline
    );
    FulfillmentSolution memory route = _solution(solverCalls, 1, deadline);
    bytes memory approval =
      _signSolutionApproval(approverKey, owner, lFulfillmentOrderHash(named), route);
    bytes memory matchingWitness = _signFulfillmentWitness(named);

    uint256 before = IERC20(WETH).balanceOf(address(router));

    vm.prank(solver);
    hub.fulfillOrderWithPermit2Signature(owner, named, matchingWitness, route, approval);
    assertEq(IERC20(WETH).balanceOf(address(router)) - before, AMOUNT, 'the matching order settled');

    FulfillmentOrder memory swapped = _fulfillmentOrder(
      ANY,
      erc20s,
      new ERC721Transfer[](0),
      new ValidationParams[](0),
      new GenericCall[](0),
      approver,
      32,
      deadline
    );
    FulfillmentSolution memory route2 = _solution(solverCalls, 2, deadline);
    bytes memory approval2 =
      _signSolutionApproval(approverKey, owner, lFulfillmentOrderHash(swapped), route2);
    // the owner signed a witness naming nobody, so the approver in the order is not the one signed
    bytes memory openWitness =
      _signFulfillmentWitness(swapped, swapped.solver, swapped.ownerCalls, ANY);

    vm.prank(solver);
    vm.expectRevert(PERMIT2_INVALID_SIGNER);
    hub.fulfillOrderWithPermit2Signature(owner, swapped, openWitness, route2, approval2);
  }

  /**
   * ORD-03 — `solver` says who may submit a fulfillment, and the sentinel says anybody may
   * @dev The mirror of `ORD-02` on this family, and it has to exist separately: the witness binds
   * `solver` as the order names it, not as the caller names itself, so the hub's own gate is the
   * only thing between a stranger and a settled order here. The gate runs before Permit2, so the
   * middle leg's refusal is the hub's error and names both addresses. The last leg is what makes
   * the middle one about the pin rather than about the submitter.
   */
  function test_ORD_03_solverPinningAndTheOpenSentinel() public {
    ERC20Transfer[] memory erc20s = _erc20s(_wethTransfer(AMOUNT));
    FulfillmentSolution memory route = _route(_calls(_routerCall(0, hex'01')));
    uint256 deadline = block.timestamp + 1 hours;

    FulfillmentOrder memory pinned = _fulfillmentOrder(
      solver,
      erc20s,
      new ERC721Transfer[](0),
      new ValidationParams[](0),
      new GenericCall[](0),
      ANY,
      61,
      deadline
    );

    bytes memory pinnedSig = _signFulfillmentWitness(pinned);

    uint256 before = IERC20(WETH).balanceOf(address(router));
    vm.prank(solver);
    hub.fulfillOrderWithPermit2Signature(owner, pinned, pinnedSig, route, '');
    assertEq(
      IERC20(WETH).balanceOf(address(router)) - before, AMOUNT, 'the named solver may submit'
    );

    FulfillmentOrder memory pinnedAgain = _fulfillmentOrder(
      solver,
      erc20s,
      new ERC721Transfer[](0),
      new ValidationParams[](0),
      new GenericCall[](0),
      ANY,
      62,
      deadline
    );
    bytes memory againSig = _signFulfillmentWitness(pinnedAgain);

    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(IKSAllowanceHubV2.UnauthorizedSolver.selector, relayer, solver)
    );
    hub.fulfillOrderWithPermit2Signature(owner, pinnedAgain, againSig, route, '');

    assertEq(
      _permit2NonceBitmap(owner, 62 >> 8) & (1 << 62),
      0,
      'the refused order burned no Permit2 nonce'
    );

    FulfillmentOrder memory openOrder =
      _openFulfillmentOrder(erc20s, new ValidationParams[](0), new GenericCall[](0), 63, deadline);

    bytes memory openSig = _signFulfillmentWitness(openOrder);

    before = IERC20(WETH).balanceOf(address(router));
    vm.prank(relayer);
    hub.fulfillOrderWithPermit2Signature(owner, openOrder, openSig, route, '');
    assertEq(
      IERC20(WETH).balanceOf(address(router)) - before,
      AMOUNT,
      'the sentinel opened submission to the very same stranger'
    );
  }

  // -------------------------------------------------------------------------------------------
  // SOL — the solution approval
  // -------------------------------------------------------------------------------------------

  /**
   * SOL-01 — one approval binds one order, `ownerCalls` included
   * @dev `SolutionApproval` carries `orderHash`, and the order hash covers the owner's tail, so an
   * approver who signed a route for one order has not approved the same route under a different
   * tail. The two orders differ in that one member and nothing else, so the refusal is about the
   * binding. The second leg carries its own route nonce and an approval genuinely signed over that
   * route, because the hub burns `solution.nonce` — otherwise the refusal would be the nonce
   * guard rather than the binding. The first leg is the control.
   */
  function test_SOL_01_oneApprovalBindsOneOrder() public {
    ERC20Transfer[] memory erc20s = _erc20s(_wethTransfer(AMOUNT));
    GenericCall[] memory solverCalls = _calls(_routerCall(0, hex'01'));
    uint256 deadline = block.timestamp + 1 hours;

    FulfillmentSolution memory route = _solution(solverCalls, 7, deadline);

    FulfillmentOrder memory withTailA = _orderWithTail(_calls(_routerCall(0, hex'aa')), deadline);
    bytes32 hashA = lFulfillmentOrderHash(withTailA);
    bytes memory approvalA = _signSolutionApproval(approverKey, owner, hashA, route);

    uint256 before = IERC20(WETH).balanceOf(address(router));

    vm.prank(owner);
    (bytes[] memory results,) = hub.fulfillOrderWithDelegatedAuthentication(
      owner, withTailA, address(0), '', route, approvalA, false
    );

    assertEq(IERC20(WETH).balanceOf(address(router)) - before, AMOUNT, 'the approved order settled');
    assertEq(results.length, 2, 'route and tail both ran');
    assertEq(hub.nonces(owner, 0), 1 << 7, 'and the approval burned exactly the route nonce');

    FulfillmentOrder memory withTailB = _orderWithTail(_calls(_routerCall(0, hex'bb')), deadline);
    assertTrue(lFulfillmentOrderHash(withTailB) != hashA, 'the two orders really do differ');

    FulfillmentSolution memory routeB = _solution(solverCalls, 8, deadline);
    bytes memory approvalAB = _signSolutionApproval(approverKey, owner, hashA, routeB);

    vm.prank(owner);
    vm.expectRevert(IKSAllowanceHubV2.InvalidSolutionSignature.selector);
    hub.fulfillOrderWithDelegatedAuthentication(
      owner, withTailB, address(0), '', routeB, approvalAB, false
    );

    assertEq(router.callCount(), 2, 'the refused order ran nothing');

    // the same order with its own approval does settle, so the refusal was the approval's doing.
    // A third route nonce, since the first two are spent and the point here is not the nonce guard
    FulfillmentSolution memory routeC = _solution(solverCalls, 9, deadline);
    bytes memory approvalB =
      _signSolutionApproval(approverKey, owner, lFulfillmentOrderHash(withTailB), routeC);

    vm.prank(owner);
    hub.fulfillOrderWithDelegatedAuthentication(
      owner, withTailB, address(0), '', routeC, approvalB, false
    );
    assertEq(router.callCount(), 4, 'route and tail ran for the second order too');
  }

  /**
   * SOL-05 — the route carries its own deadline, checked on both rails whatever the approver
   * @dev The check is a modifier, not part of the approval, so it binds even under the sentinel
   * approver where no approval is presented at all. Inclusive at the boundary, like the order's own
   * deadline: the deadline second itself still settles, and the second after it does not.
   */
  function test_SOL_05_theRouteDeadlineIsEnforced() public {
    uint256 orderDeadline = block.timestamp + 1 days;
    GenericCall[] memory solverCalls = _calls(_routerCall(0, hex'01'));

    FulfillmentOrder memory open = _openFulfillmentOrder(
      _erc20s(_wethTransfer(AMOUNT)),
      new ValidationParams[](0),
      new GenericCall[](0),
      70,
      orderDeadline
    );

    uint256 before = IERC20(WETH).balanceOf(address(router));
    vm.prank(owner);
    hub.fulfillOrderWithDelegatedAuthentication(
      owner, open, address(0), '', _solution(solverCalls, 70, block.timestamp), '', false
    );
    assertEq(
      IERC20(WETH).balanceOf(address(router)) - before,
      AMOUNT,
      'the deadline second itself still settles'
    );

    vm.warp(block.timestamp + 1);
    uint256 stale = block.timestamp - 1;

    vm.prank(owner);
    vm.expectRevert(_deadlinePassed(stale));
    hub.fulfillOrderWithDelegatedAuthentication(
      owner, open, address(0), '', _solution(solverCalls, 71, stale), '', false
    );

    // and the same on the Permit2 rail, whose modifier stack is written out separately
    FulfillmentOrder memory forRelay = _openFulfillmentOrder(
      _erc20s(_wethTransfer(AMOUNT)),
      new ValidationParams[](0),
      new GenericCall[](0),
      72,
      orderDeadline
    );
    bytes memory witness = _signFulfillmentWitness(forRelay);

    vm.prank(relayer);
    vm.expectRevert(_deadlinePassed(stale));
    hub.fulfillOrderWithPermit2Signature(
      owner, forRelay, witness, _solution(solverCalls, 73, stale), ''
    );
  }

  /**
   * SOL-06 — a named approver's route is spent once, and the sentinel's is not spent at all
   * @dev The hub burns `solution.nonce` inside the approval path, so the burn happens only when the
   * order names an approver. The third leg records that asymmetry rather than assuming it: under the
   * sentinel the very same nonce settles twice, so a route approved for nobody in particular carries
   * no replay bound of its own.
   */
  function test_SOL_06_theRouteNonceIsSpentOnlyUnderANamedApprover() public {
    uint256 deadline = block.timestamp + 1 hours;
    GenericCall[] memory solverCalls = _calls(_routerCall(0, hex'01'));
    FulfillmentSolution memory route = _solution(solverCalls, 80, deadline);

    FulfillmentOrder memory named = _fulfillmentOrder(
      ANY,
      _erc20s(_wethTransfer(AMOUNT)),
      new ERC721Transfer[](0),
      new ValidationParams[](0),
      new GenericCall[](0),
      approver,
      80,
      deadline
    );
    bytes memory approval =
      _signSolutionApproval(approverKey, owner, lFulfillmentOrderHash(named), route);

    vm.prank(owner);
    hub.fulfillOrderWithDelegatedAuthentication(
      owner, named, address(0), '', route, approval, false
    );
    assertEq(hub.nonces(owner, 0), 1 << 80, 'the hub burned exactly the route nonce');

    vm.prank(owner);
    vm.expectRevert(IUnorderedNonce.NonceAlreadyUsed.selector);
    hub.fulfillOrderWithDelegatedAuthentication(
      owner, named, address(0), '', route, approval, false
    );

    // the sentinel path never reaches the burn, so this nonce stays spendable twice over
    FulfillmentOrder memory open = _openFulfillmentOrder(
      _erc20s(_wethTransfer(AMOUNT)), new ValidationParams[](0), new GenericCall[](0), 81, deadline
    );
    FulfillmentSolution memory openRoute = _solution(solverCalls, 81, deadline);

    uint256 before = IERC20(WETH).balanceOf(address(router));
    vm.prank(owner);
    hub.fulfillOrderWithDelegatedAuthentication(owner, open, address(0), '', openRoute, '', false);
    vm.prank(owner);
    hub.fulfillOrderWithDelegatedAuthentication(owner, open, address(0), '', openRoute, '', false);

    assertEq(
      IERC20(WETH).balanceOf(address(router)) - before, 2 * AMOUNT, 'the sentinel route ran twice'
    );
    assertEq(hub.nonces(owner, 0), 1 << 80, 'and burned nothing of its own');
  }

  /**
   * SOL-02 — the sentinel approver accepts any route, with no signature to present
   * @dev Two different routes settle under the very same order, which is what "any route" means, and
   * neither carries an approval. The last leg is the contrast: a named approver on the otherwise
   * identical order does demand one.
   */
  function test_SOL_02_sentinelApproverAcceptsAnyRoute() public {
    uint256 deadline = block.timestamp + 1 hours;

    FulfillmentOrder memory open = _openFulfillmentOrder(
      new ERC20Transfer[](0), new ValidationParams[](0), new GenericCall[](0), 0, deadline
    );

    vm.prank(owner);
    (bytes[] memory results,) = hub.fulfillOrderWithDelegatedAuthentication(
      owner, open, address(0), '', _route(_calls(_routerCall(0, hex'01'))), '', false
    );

    assertEq(results.length, 1, 'the route ran');
    assertEq(router.callCount(), 1, 'once');
    assertEq(hub.nonces(owner, 0), 0, 'the sentinel route burns no nonce');

    vm.prank(owner);
    hub.fulfillOrderWithDelegatedAuthentication(
      owner, open, address(0), '', _route(_calls(_routerCall(0, hex'02'))), '', false
    );

    assertEq(router.callCount(), 2, 'and a different route under the same order ran as well');
    assertEq(router.lastData(), hex'02', 'the second route is the one that ran last');

    FulfillmentOrder memory withApprover = _fulfillmentOrder(
      ANY,
      new ERC20Transfer[](0),
      new ERC721Transfer[](0),
      new ValidationParams[](0),
      new GenericCall[](0),
      approver,
      0,
      deadline
    );

    vm.prank(owner);
    vm.expectRevert(IKSAllowanceHubV2.InvalidSolutionSignature.selector);
    hub.fulfillOrderWithDelegatedAuthentication(
      owner, withApprover, address(0), '', _route(_calls(_routerCall(0, hex'01'))), '', false
    );
  }

  /**
   * SOL-03 — a malformed approval is refused rather than read as "no approver named"
   * @dev The sentinel is the only thing that waives the check, and it lives in the signed order. A
   * signature too short to recover from must therefore fail the check rather than skip it.
   */
  function test_SOL_03_malformedApprovalSignature() public {
    uint256 deadline = block.timestamp + 1 hours;

    FulfillmentOrder memory order = _fulfillmentOrder(
      ANY,
      new ERC20Transfer[](0),
      new ERC721Transfer[](0),
      new ValidationParams[](0),
      new GenericCall[](0),
      approver,
      0,
      deadline
    );

    vm.prank(owner);
    vm.expectRevert(IKSAllowanceHubV2.InvalidSolutionSignature.selector);
    hub.fulfillOrderWithDelegatedAuthentication(
      owner, order, address(0), '', _route(_calls(_routerCall(0, hex'01'))), hex'1234', false
    );

    assertEq(router.callCount(), 0, 'and nothing ran');
  }

  /**
   * SOL-04 — one authenticated fulfillment settles at most once
   * @dev The approval itself carries no nonce; replay is bounded by the order nonce, which the
   * authenticator burns. Identical calldata a second time is refused there.
   */
  function test_SOL_04_anAuthenticatedFulfillmentCannotSettleTwice() public {
    _delegateKeyThroughHub(key);

    ERC20Transfer[] memory erc20s = _erc20s(_wethTransfer(AMOUNT));
    uint256 deadline = block.timestamp + 1 hours;

    FulfillmentOrder memory order = _fulfillmentOrder(
      ANY,
      erc20s,
      new ERC721Transfer[](0),
      new ValidationParams[](0),
      new GenericCall[](0),
      ANY,
      21,
      deadline
    );
    bytes memory authData = _fulfillmentAuthData(order, key, sessionKeyPk);
    FulfillmentSolution memory route = _route(_calls(_routerCall(0, hex'01')));

    vm.prank(relayer);
    hub.fulfillOrderWithDelegatedAuthentication(
      owner, order, address(authenticator), authData, route, '', false
    );

    assertEq(authenticator.nonces(owner, 0), 1 << 21, 'the order nonce burned');
    assertEq(router.callCount(), 1, 'the route ran once');

    vm.prank(relayer);
    vm.expectRevert(IUnorderedNonce.NonceAlreadyUsed.selector);
    hub.fulfillOrderWithDelegatedAuthentication(
      owner, order, address(authenticator), authData, route, '', false
    );

    assertEq(router.callCount(), 1, 'and not a second time');
  }

  // -------------------------------------------------------------------------------------------
  // OWN — the owner's call tail
  // -------------------------------------------------------------------------------------------

  /**
   * OWN-01 — the tail runs after the solver's route, not merely alongside it
   * @dev Both observers are the same router, so this is about when they ran and not about who was
   * called. The one at the head of the solver list finds nothing, which is what "ran before the
   * producers" looks like here and is what stops the second assertion being satisfiable by an
   * implementation that ran the tail first. The owner's observer finds the LAST of the two
   * products, so it ran after every solver call rather than merely after the first.
   */
  function test_OWN_01_ownerCallsRunAfterSolverCalls() public {
    ObservingRouterMock ledger = new ObservingRouterMock();
    vm.prank(admin);
    hub.grantRole(ROUTER_ROLE, address(ledger));

    bytes memory nothing = '';
    bytes memory firstProduct = hex'a1';
    bytes memory lastProduct = hex'b2';

    GenericCall[] memory solverCalls = new GenericCall[](3);
    solverCalls[0] = GenericCall({router: address(ledger), value: 0, data: ledger.observe()});
    solverCalls[1] =
      GenericCall({router: address(ledger), value: 0, data: ledger.produce(firstProduct)});
    solverCalls[2] =
      GenericCall({router: address(ledger), value: 0, data: ledger.produce(lastProduct)});

    GenericCall[] memory ownerCalls = new GenericCall[](1);
    ownerCalls[0] = GenericCall({router: address(ledger), value: 0, data: ledger.observe()});

    vm.prank(owner);
    bytes[] memory results = _fulfillWithTail(ownerCalls, solverCalls);

    assertEq(ledger.observationCount(), 2, 'both observers ran');
    assertEq(ledger.observations(0), nothing, 'the solver observer ran before either producer');
    assertEq(ledger.observations(1), lastProduct, "the owner's tail ran after every solver call");
    assertEq(results[3], lastProduct, 'and its return carries what it found');
  }

  /**
   * OWN-02 — the Permit2 witness pins the tail the owner signed
   * @dev The first leg is the control: the same order with the tail left alone settles, so the
   * refusal in the second is evidence about the witness covering `ownerCalls` rather than about a
   * signature that was never going to be accepted. Only one byte of call data separates them.
   */
  function test_OWN_02_witnessBindsOwnerCalls() public {
    ERC20Transfer[] memory erc20s = _erc20s(_wethTransfer(AMOUNT));
    GenericCall[] memory solverCalls = _calls(_routerCall(0, hex'01'));
    GenericCall[] memory signedTail = _calls(_routerCall(0, hex'aa'));
    GenericCall[] memory swappedTail = _calls(_routerCall(0, hex'bb'));
    uint256 deadline = block.timestamp + 1 hours;

    uint256 before = IERC20(WETH).balanceOf(address(router));

    FulfillmentOrder memory control = _fulfillmentOrder(
      ANY, erc20s, new ERC721Transfer[](0), new ValidationParams[](0), signedTail, ANY, 70, deadline
    );

    vm.prank(solver);
    hub.fulfillOrderWithPermit2Signature(
      owner, control, _signFulfillmentWitness(control), _route(solverCalls), ''
    );

    assertEq(IERC20(WETH).balanceOf(address(router)) - before, AMOUNT, 'the signed tail settled');
    assertEq(router.callCount(), 2, 'one solver call and one owner call');

    FulfillmentOrder memory signed = _fulfillmentOrder(
      ANY, erc20s, new ERC721Transfer[](0), new ValidationParams[](0), signedTail, ANY, 71, deadline
    );
    bytes memory signature = _signFulfillmentWitness(signed);

    FulfillmentOrder memory tampered = _fulfillmentOrder(
      ANY,
      erc20s,
      new ERC721Transfer[](0),
      new ValidationParams[](0),
      swappedTail,
      ANY,
      71,
      deadline
    );

    vm.prank(solver);
    vm.expectRevert(PERMIT2_INVALID_SIGNER);
    hub.fulfillOrderWithPermit2Signature(owner, tampered, signature, _route(solverCalls), '');
  }

  /**
   * OWN-03 — the same binding on the delegated rail, through the order the authenticator is handed
   * @dev Carries validators as well as a tail, so both of the members the restructure moved into the
   * signed order are exercised. As in OWN-02 the first leg is the control.
   */
  function test_OWN_03_authenticationBindsOwnerCalls() public {
    _delegateKeyThroughHub(key);

    ERC20Transfer[] memory erc20s = _erc20s(_wethTransfer(AMOUNT));
    ValidationParams[] memory vs = _validations(_validation(validator));
    GenericCall[] memory solverCalls = _calls(_routerCall(0, hex'01'));
    GenericCall[] memory signedTail = _calls(_routerCall(0, hex'aa'));
    GenericCall[] memory swappedTail = _calls(_routerCall(0, hex'bb'));
    uint256 deadline = block.timestamp + 1 hours;

    uint256 before = IERC20(WETH).balanceOf(address(router));

    FulfillmentOrder memory control =
      _fulfillmentOrder(ANY, erc20s, new ERC721Transfer[](0), vs, signedTail, ANY, 72, deadline);
    bytes memory controlAuth = _fulfillmentAuthData(control, key, sessionKeyPk);

    vm.prank(relayer);
    hub.fulfillOrderWithDelegatedAuthentication(
      owner, control, address(authenticator), controlAuth, _route(solverCalls), '', false
    );

    assertEq(IERC20(WETH).balanceOf(address(router)) - before, AMOUNT, 'the signed tail settled');
    assertEq(router.callCount(), 2, 'one solver call and one owner call');
    assertEq(validator.sequenceLength(), 2, 'the validators still bracketed the order');

    FulfillmentOrder memory signed =
      _fulfillmentOrder(ANY, erc20s, new ERC721Transfer[](0), vs, signedTail, ANY, 73, deadline);
    bytes memory signedAuth = _fulfillmentAuthData(signed, key, sessionKeyPk);

    FulfillmentOrder memory tampered =
      _fulfillmentOrder(ANY, erc20s, new ERC721Transfer[](0), vs, swappedTail, ANY, 73, deadline);

    vm.prank(relayer);
    vm.expectRevert(ISessionOrderAuthenticator.InvalidAuthenticationSignature.selector);
    hub.fulfillOrderWithDelegatedAuthentication(
      owner, tampered, address(authenticator), signedAuth, _route(solverCalls), '', false
    );
  }

  /**
   * OWN-04 — the whitelist gate covers the tail exactly as it covers the route
   * @dev The first leg also shows the refusal unwinds the solver calls that had already run. The
   * last leg is the control: granting the role and changing nothing else lets the very same tail
   * through, so the two refusals are about the role rather than about the router.
   */
  function test_OWN_04_ownerCallRouterMustBeWhitelisted() public {
    RouterMock stranger = new RouterMock();

    GenericCall[] memory strangerCalls =
      _calls(GenericCall({router: address(stranger), value: 0, data: hex'01'}));
    GenericCall[] memory routeCalls = _calls(_routerCall(0, hex'02'));

    bytes memory expectedError = abi.encodeWithSelector(
      IAccessControl.AccessControlUnauthorizedAccount.selector, address(stranger), ROUTER_ROLE
    );

    vm.prank(owner);
    vm.expectRevert(expectedError);
    _fulfillWithTail(strangerCalls, routeCalls);

    vm.prank(owner);
    vm.expectRevert(expectedError);
    _fulfillWithTail(new GenericCall[](0), strangerCalls);

    assertEq(stranger.callCount(), 0, 'never called from either list');
    assertEq(router.callCount(), 0, 'and the solver leg of the first order rolled back with it');

    vm.prank(admin);
    hub.grantRole(ROUTER_ROLE, address(stranger));

    vm.prank(owner);
    _fulfillWithTail(strangerCalls, routeCalls);

    assertEq(stranger.callCount(), 1, "the owner's tail reached it once whitelisted");
    assertEq(router.callCount(), 1, 'and the solver leg ran too');
  }

  /**
   * OWN-05 — an empty tail adds nothing
   * @dev What is left to say here is that an empty tail costs no call and no result, and that the
   * route settles as it does through the entry point that has no tail at all.
   */
  function test_OWN_05_emptyOwnerCallsIsThePriorBehaviour() public {
    GenericCall[] memory solverCalls = new GenericCall[](2);
    solverCalls[0] = _routerCall(0, hex'01');
    solverCalls[1] = _routerCall(0, hex'02');

    vm.prank(owner);
    bytes[] memory results = _fulfillWithTail(new GenericCall[](0), solverCalls);

    assertEq(results.length, 2, 'one result per solver call and no more');
    assertEq(router.callCount(), 2, 'nothing beyond the solver route ran');
    assertEq(router2.callCount(), 0, 'and no other router was touched');
    assertEq(hub.nonces(owner, 0), 0, 'the hub burned no nonce of its own');

    vm.prank(owner);
    (bytes[] memory executeResults,) = hub.executeOrderWithDelegatedAuthentication(
      owner,
      _openExecutionOrder(new ERC20Transfer[](0), solverCalls, 0, block.timestamp),
      address(0),
      '',
      false
    );

    assertEq(executeResults.length, results.length, 'the same route, the same shape either way');
    assertEq(router.callCount(), 4, 'and the second order ran its two calls as well');
  }

  /**
   * OWN-06 — `results` is the route then the tail, one entry per call
   * @dev The two routers are interleaved across the lists, and each echoes back its own identity
   * and payload, so neither swapping the lists nor reversing one of them would reproduce the
   * expected sequence. OWN-01 is the separate statement about when the calls ran; this is about
   * where their return data lands.
   */
  function test_OWN_06_resultsAreSolverThenOwner() public {
    EchoRouterMock echoA = new EchoRouterMock();
    EchoRouterMock echoB = new EchoRouterMock();

    vm.startPrank(admin);
    hub.grantRole(ROUTER_ROLE, address(echoA));
    hub.grantRole(ROUTER_ROLE, address(echoB));
    vm.stopPrank();

    GenericCall[] memory solverCalls = new GenericCall[](2);
    solverCalls[0] = GenericCall({router: address(echoA), value: 0, data: hex'aa'});
    solverCalls[1] = GenericCall({router: address(echoB), value: 0, data: hex'bb'});

    GenericCall[] memory ownerCalls = new GenericCall[](2);
    ownerCalls[0] = GenericCall({router: address(echoB), value: 0, data: hex'cc'});
    ownerCalls[1] = GenericCall({router: address(echoA), value: 0, data: hex'dd'});

    vm.prank(owner);
    bytes[] memory results = _fulfillWithTail(ownerCalls, solverCalls);

    // the expectation is the two lists written out in the order they are claimed to run
    GenericCall[] memory expected = new GenericCall[](4);
    expected[0] = solverCalls[0];
    expected[1] = solverCalls[1];
    expected[2] = ownerCalls[0];
    expected[3] = ownerCalls[1];

    assertEq(results.length, expected.length, 'one result per call across both lists');

    for (uint256 i = 0; i < expected.length; i++) {
      (address seenRouter, bytes memory seenData) = abi.decode(results[i], (address, bytes));
      assertEq(seenRouter, expected[i].router, 'result came from the router at that position');
      assertEq(seenData, expected[i].data, 'and carries the data sent to it');
    }
  }

  // -------------------------------------------------------------------------------------------
  // VAL — the validator hooks
  // -------------------------------------------------------------------------------------------

  /**
   * VAL-01 — the hooks bracket the whole order on the delegated rail, each snapshot to its owner
   * @dev The spy reads the router's balance inside each hook, which is what actually orders the
   * hooks against the transfer and the router call: `beforeExecution` must see the pre-pull
   * balance and `afterExecution` the balance after both the pull and the router leg.
   */
  function test_VAL_01_hookOrderingAndSnapshotPairing() public {
    validator.setSnapshot(hex'aaaa');
    validator2.setSnapshot(hex'bbbb');
    validator.observe(WETH, address(router));

    uint160 amount = 4 ether;
    uint256 payout = 1 ether;
    uint256 routerBefore = IERC20(WETH).balanceOf(address(router));

    // the router pays part of it away while it runs, so the balance changes DURING the call leg.
    // Without this the after-hook would read the same value whether it ran before or after the
    // router, and the ordering assertion below would be vacuous.
    router.setPayout(WETH, recipient, payout);

    ValidationParams[] memory vs = new ValidationParams[](2);
    vs[0] = _validation(validator);
    vs[1] = _validation(validator2);

    FulfillmentOrder memory order = _openFulfillmentOrder(
      _erc20s(_wethTransfer(amount)), vs, new GenericCall[](0), 0, block.timestamp
    );

    vm.prank(owner);
    hub.fulfillOrderWithDelegatedAuthentication(
      owner, order, address(0), '', _route(_calls(_routerCall(0, hex'01'))), '', false
    );

    assertEq(validator.sequenceLength(), 2, 'both hooks ran');
    assertEq(validator.sequence(0), 'before');
    assertEq(validator.sequence(1), 'after');

    // ordering, established by what each hook could see rather than by call order alone
    assertEq(validator.balanceAtBefore(), routerBefore, 'beforeExecution ran before the pull');
    assertEq(
      validator.balanceAtAfter(),
      routerBefore + amount - payout,
      'afterExecution ran after the router leg, not merely after the pull'
    );

    // each validator's afterExecution received the snapshot its own beforeExecution returned
    assertEq(validator.afterBeforeOutput(), hex'aaaa', 'validator 1 snapshot');
    assertEq(validator2.afterBeforeOutput(), hex'bbbb', 'validator 2 snapshot');

    assertEq(router.callCount(), 1);
  }

  /**
   * VAL-02 — on the Permit2 rail too, the pre-hook runs before any asset moves and the post-hook
   * between the two call lists
   * @dev The rail matters: here the ERC20s move inside Permit2 rather than through the hub's own
   * transfer, and `beforeExecution()` is called before that permit. Both ends are established by
   * what the hook could see rather than by call order. The owner's tail pays the same amount away
   * again, so the post-hook's reading distinguishes "after the solver's route" from "after
   * everything" — a hook that ran at the very end would read one payout lower.
   */
  function test_VAL_02_hooksBracketThePermit2Rail() public {
    validator.observe(WETH, address(router));

    uint160 amount = 4 ether;
    uint256 payout = 1 ether;
    uint256 deadline = block.timestamp + 1 hours;
    uint256 routerBefore = IERC20(WETH).balanceOf(address(router));

    router.setPayout(WETH, recipient, payout);

    ERC20Transfer[] memory erc20s = _erc20s(_wethTransfer(amount));
    FulfillmentOrder memory order = _fulfillmentOrder(
      ANY,
      erc20s,
      new ERC721Transfer[](0),
      _validations(_validation(validator)),
      _calls(_routerCall(0, hex'99')),
      ANY,
      80,
      deadline
    );
    bytes memory signature = _signFulfillmentWitness(order);

    vm.prank(solver);
    hub.fulfillOrderWithPermit2Signature(
      owner, order, signature, _route(_calls(_routerCall(0, hex'01'))), ''
    );

    assertEq(validator.sequenceLength(), 2, 'both hooks ran');
    assertEq(
      validator.balanceAtBefore(), routerBefore, 'beforeExecution ran before Permit2 moved anything'
    );
    assertEq(
      validator.balanceAtAfter(),
      routerBefore + amount - payout,
      "afterExecution ran after the solver's route and before the owner's tail"
    );
    assertEq(
      IERC20(WETH).balanceOf(address(router)),
      routerBefore + amount - 2 * payout,
      'and the tail did run afterwards, paying the second time'
    );
    assertEq(router.callCount(), 2, 'one solver call and one owner call');
  }

  /// VAL-03 — a validator that rejects the outcome reverts the whole order
  function test_VAL_03_revertingAfterExecutionUnwinds() public {
    validator.setReverts(false, true);

    FulfillmentOrder memory order = _openFulfillmentOrder(
      new ERC20Transfer[](0),
      _validations(_validation(validator)),
      new GenericCall[](0),
      0,
      block.timestamp
    );

    vm.prank(owner);
    vm.expectRevert(bytes('after'));
    hub.fulfillOrderWithDelegatedAuthentication(
      owner, order, address(0), '', _route(_calls(_routerCall(0, hex'01'))), '', false
    );

    assertEq(router.callCount(), 0, 'router call rolled back');
  }

  /// VAL-04 — no validators is a legal order
  function test_VAL_04_noValidators() public {
    FulfillmentOrder memory order = _openFulfillmentOrder(
      new ERC20Transfer[](0), new ValidationParams[](0), new GenericCall[](0), 0, block.timestamp
    );

    vm.prank(owner);
    hub.fulfillOrderWithDelegatedAuthentication(
      owner, order, address(0), '', _route(_calls(_routerCall(0, hex'01'))), '', false
    );

    assertEq(router.callCount(), 1);
  }

  // -------------------------------------------------------------------------------------------
  // FU-FUZZ — one property per fulfill entry point
  // -------------------------------------------------------------------------------------------

  /// @dev One named struct for the fulfill family, per the frozen plan's fuzz contract
  struct FulfillFuzz {
    uint160 amount;
    uint8 solverCallCount;
    uint8 ownerCallCount;
    uint256 deadlineOffset;
    bool moveNft;
    bool usePermit2Allowances;
    bool pinSubmitter;
    bool approveSolution;
    uint256 nonce;
  }

  /**
   * FU-FUZZ — `fulfillOrderWithDelegatedAuthentication` over a relayed session-key credential
   * @dev Both call lists range over empty and non-empty, and they go to different routers so each
   * has a counter of its own. `approveSolution` switches between a named approver with a real
   * approval and the sentinel; `usePermit2Allowances` picks the pull rail; `pinSubmitter` and the
   * nonce are covered by the order hash the event reports and by the authenticator's bitmap.
   */
  function testFuzz_FU_FUZZ_delegatedRail(FulfillFuzz memory f) public {
    _delegateKeyThroughHub(key);

    f.amount = uint160(bound(f.amount, 0, 100 ether));
    f.solverCallCount = uint8(bound(f.solverCallCount, 0, 3));
    f.ownerCallCount = uint8(bound(f.ownerCallCount, 0, 3));
    f.deadlineOffset = bound(f.deadlineOffset, 0, 30 days);
    if (f.usePermit2Allowances) _grantPermit2Allowance(WETH, uint160(100 ether));

    (FulfillmentOrder memory order, FulfillmentSolution memory route) = _fuzzOrder(f, relayer);
    bytes memory authData = _fulfillmentAuthData(order, key, sessionKeyPk);
    bytes memory approval = f.approveSolution
      ? _signSolutionApproval(approverKey, owner, lFulfillmentOrderHash(order), route)
      : bytes('');

    uint256 before = IERC20(WETH).balanceOf(address(router));

    vm.recordLogs();

    vm.prank(relayer);
    (bytes[] memory results,) = hub.fulfillOrderWithDelegatedAuthentication(
      owner, order, address(authenticator), authData, route, approval, false
    );

    _assertFuzzSettled(f, order, results, before);
    assertEq(
      authenticator.nonces(owner, f.nonce >> 8),
      1 << (f.nonce & 0xff),
      'the authenticator burned exactly the order nonce'
    );
    assertEq(
      hub.nonces(owner, f.nonce >> 8),
      f.approveSolution ? 1 << (f.nonce & 0xff) : 0,
      'and the hub burned the route nonce exactly when an approver was named'
    );
  }

  /**
   * FU-FUZZ — `fulfillOrderWithPermit2Signature`, relayed, where the witness is the binding
   * @dev `pinSubmitter` is live control flow here: it decides whether the gate compares the
   * submitter against a named solver or against the sentinel, and it changes the witness either
   * way. The Permit2 nonce is the replay oracle.
   */
  function testFuzz_FU_FUZZ_permit2Rail(FulfillFuzz memory f) public {
    f.amount = uint160(bound(f.amount, 0, 100 ether));
    f.solverCallCount = uint8(bound(f.solverCallCount, 0, 3));
    f.ownerCallCount = uint8(bound(f.ownerCallCount, 0, 3));
    f.deadlineOffset = bound(f.deadlineOffset, 0, 30 days);

    (FulfillmentOrder memory order, FulfillmentSolution memory route) = _fuzzOrder(f, solver);
    bytes memory signature = _signFulfillmentWitness(order);
    bytes memory approval = f.approveSolution
      ? _signSolutionApproval(approverKey, owner, lFulfillmentOrderHash(order), route)
      : bytes('');

    uint256 before = IERC20(WETH).balanceOf(address(router));
    uint256 bitmapBefore = _permit2NonceBitmap(owner, f.nonce >> 8);

    vm.recordLogs();

    vm.prank(solver);
    (bytes[] memory results,) =
      hub.fulfillOrderWithPermit2Signature(owner, order, signature, route, approval);

    _assertFuzzSettled(f, order, results, before);
    assertEq(
      _permit2NonceBitmap(owner, f.nonce >> 8),
      bitmapBefore | (1 << (f.nonce & 0xff)),
      'Permit2 burned exactly the signed nonce'
    );
  }

  // -------------------------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------------------------

  /// @dev An owner-submitted fulfillment carrying both call lists and nothing else
  function _fulfillWithTail(GenericCall[] memory ownerCalls, GenericCall[] memory solverCalls)
    private
    returns (bytes[] memory results)
  {
    (results,) = hub.fulfillOrderWithDelegatedAuthentication(
      owner,
      _openFulfillmentOrder(
        new ERC20Transfer[](0), new ValidationParams[](0), ownerCalls, 0, block.timestamp
      ),
      address(0),
      '',
      _route(solverCalls),
      '',
      false
    );
  }

  /// @dev The SOL-01 pair: one order shape, varying only in the owner's tail
  function _orderWithTail(GenericCall[] memory ownerCalls, uint256 deadline)
    private
    view
    returns (FulfillmentOrder memory)
  {
    return _fulfillmentOrder(
      ANY,
      _erc20s(_wethTransfer(AMOUNT)),
      new ERC721Transfer[](0),
      new ValidationParams[](0),
      ownerCalls,
      approver,
      60,
      deadline
    );
  }

  function _fuzzOrder(FulfillFuzz memory f, address submitter)
    private
    view
    returns (FulfillmentOrder memory order, FulfillmentSolution memory route)
  {
    GenericCall[] memory solverCalls = new GenericCall[](f.solverCallCount);
    for (uint256 i = 0; i < f.solverCallCount; i++) {
      solverCalls[i] = _routerCall(0, abi.encodePacked(uint8(i)));
    }

    // the owner's tail goes to the second router, so each list has a counter of its own
    GenericCall[] memory ownerCalls = new GenericCall[](f.ownerCallCount);
    for (uint256 i = 0; i < f.ownerCallCount; i++) {
      ownerCalls[i] =
        GenericCall({router: address(router2), value: 0, data: abi.encodePacked(uint8(i))});
    }

    order = _fulfillmentOrder(
      f.pinSubmitter ? submitter : ANY,
      _erc20s(_wethTransfer(f.amount)),
      f.moveNft ? _erc721s(_nftTransfer(address(router2))) : new ERC721Transfer[](0),
      _validations(_validation(validator)),
      ownerCalls,
      f.approveSolution ? approver : ANY,
      f.nonce,
      block.timestamp + f.deadlineOffset
    );
    route = _solution(solverCalls, f.nonce, block.timestamp + f.deadlineOffset);
  }

  function _assertFuzzSettled(
    FulfillFuzz memory f,
    FulfillmentOrder memory order,
    bytes[] memory results,
    uint256 routerWethBefore
  ) private {
    assertEq(
      IERC20(WETH).balanceOf(address(router)) - routerWethBefore, f.amount, 'exact amount moved'
    );
    assertEq(results.length, uint256(f.solverCallCount) + f.ownerCallCount, 'one result per call');
    assertEq(router.callCount(), f.solverCallCount, 'the solver list ran here');
    assertEq(router2.callCount(), f.ownerCallCount, "and the owner's tail there");
    assertEq(validator.sequenceLength(), 2, 'validator bracketed the order');
    if (f.moveNft) assertEq(nft.ownerOf(NFT_ID), address(router2), 'nft leg');

    Vm.Log memory entry = _settlementLog();
    assertEq(entry.topics[3], lFulfillmentOrderHash(order), 'the event reports this exact order');
  }
}
