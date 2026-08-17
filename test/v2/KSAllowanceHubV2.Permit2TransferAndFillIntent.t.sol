// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {KSAllowanceHubV2Base} from './base/KSAllowanceHubV2Base.sol';

import {ArrayHelper} from '../libraries/ArrayHelper.sol';

import {ActionValidatorMock} from '../mocks/ActionValidatorMock.sol';
import {Permit2Mock} from '../mocks/Permit2Mock.sol';
import {GenericRouterMock} from '../mocks/RouterMocks.sol';

import {IKSAllowanceHubV2} from 'src/interfaces/IKSAllowanceHubV2.sol';

import {ERC20Params} from 'src/types/ERC20Params.sol';
import {ERC20Transfer} from 'src/types/ERC20Transfer.sol';
import {ERC721Params} from 'src/types/ERC721Params.sol';
import {ERC721Transfer} from 'src/types/ERC721Transfer.sol';
import {GenericCall} from 'src/types/GenericCall.sol';
import {NativeTransfer} from 'src/types/NativeTransfer.sol';
import {SolverWitnessLibrary} from 'src/types/SolverWitness.sol';
import {ValidationParams} from 'src/types/ValidationParams.sol';

import {ICommon} from 'ks-common-sc/src/interfaces/ICommon.sol';
import {ISignatureTransfer} from 'ks-common-sc/src/interfaces/ISignatureTransfer.sol';

import {IAccessControl} from 'openzeppelin-contracts/contracts/access/IAccessControl.sol';
import {Pausable} from 'openzeppelin-contracts/contracts/utils/Pausable.sol';

/**
 * @notice Batch C — `KSAllowanceHubV2.permit2TransferAndFillIntent`
 * @dev Covers the fill flow itself (funding, validator hooks, event payload, results), the
 * `SolverWitness` binding surface — including the deliberate omission of `genericCalls` — and the
 * regression lock for the `whenNotPaused / lock / notOverspentNative / checkLengths` modifier set
 * added to this entrypoint.
 *
 * `SolverWitnessLibrary` is imported for signing only. Batch D pins the typehash and type string
 * against hand-written literals, so this batch never asserts the witness hash value itself.
 */
contract KSAllowanceHubV2Permit2TransferAndFillIntentTest is KSAllowanceHubV2Base {
  using ArrayHelper for *;

  bytes32 private constant ACTION_A = keccak256('ACTION_A');
  bytes32 private constant ACTION_B = keccak256('ACTION_B');

  /// @dev FIL-24 fuzz inputs, kept in one ABI-encodable struct
  struct FillFuzz {
    uint96 amount;
    uint96 msgValue;
    uint8 validatorCount;
    bool revertAfter;
  }

  /* ------------------------------------------------------------ FIL-01/14 */

  /// @dev FIL-01 + FIL-14 (group G5: the event payload rides the happy path, no event-only test)
  function test_happyFill_movesFunds_emitsExactEvent_returnsResults() public {
    _fundERC20(tokenA, owner, 10 ether);
    _fundERC20(tokenB, owner, 10 ether);
    _approvePermit2(tokenA, owner, type(uint256).max);
    _approvePermit2(tokenB, owner, type(uint256).max);
    vm.deal(solver, 1 ether);

    routerA.setReturnData(hex'11');
    routerB.setReturnData(hex'22');

    address[] memory targets = [address(routerA), address(routerB)].toMemoryArray();
    ISignatureTransfer.PermitBatchTransferFrom memory permit = _permitBatch(
      [address(tokenA), address(tokenB)].toMemoryArray(),
      [uint256(3 ether), uint256(5 ether)].toMemoryArray(),
      0
    );
    ValidationParams[] memory vps =
      _validationParamsArray(_validationParams(address(validatorA), ACTION_A, hex'a1', hex'a2'));
    // Only the second call carries value, so the native array must be truncated to one entry
    GenericCall[] memory calls = _genericCallArray(
      _genericCall(address(routerA), 0, hex'aa'), _genericCall(address(routerB), 1 ether, hex'bb')
    );
    bytes memory sig = _solverSig(permit, solver, targets, _noErc721Transfers(), vps);

    ERC20Transfer[] memory expectedErc20 = new ERC20Transfer[](2);
    expectedErc20[0] =
      ERC20Transfer({token: address(tokenA), target: address(routerA), amount: 3 ether});
    expectedErc20[1] =
      ERC20Transfer({token: address(tokenB), target: address(routerB), amount: 5 ether});

    NativeTransfer[] memory expectedNative = new NativeTransfer[](1);
    expectedNative[0] = NativeTransfer({target: address(routerB), amount: 1 ether});

    vm.expectEmit(true, true, true, true, address(hub));
    emit TransferTokens(solver, owner, 1 ether, expectedErc20, _noErc721Transfers(), expectedNative);

    vm.prank(solver);
    (bytes[] memory results,) = hub.permit2TransferAndFillIntent{value: 1 ether}(
      permit, targets, _noErc721Params(), vps, calls, owner, sig
    );

    assertEq(tokenA.balanceOf(address(routerA)), 3 ether, 'routerA funded with tokenA');
    assertEq(tokenA.balanceOf(owner), 7 ether, 'owner debited tokenA');
    assertEq(tokenB.balanceOf(address(routerB)), 5 ether, 'routerB funded with tokenB');
    assertEq(tokenB.balanceOf(owner), 5 ether, 'owner debited tokenB');

    assertEq(results.length, 2, 'one result per generic call');
    assertEq(results[0], hex'11', 'routerA return data');
    assertEq(results[1], hex'22', 'routerB return data');

    assertEq(routerA.callAt(0).value, 0, 'routerA received no value');
    assertEq(routerB.callAt(0).value, 1 ether, 'routerB received the forwarded value');
    assertEq(address(routerB).balance, 1 ether, 'value landed on routerB');

    assertEq(validatorA.beforeCallCount(), 1, 'beforeExecution ran once');
    assertEq(validatorA.afterCallCount(), 1, 'afterExecution ran once');
  }

  /* --------------------------------------------------------------- FIL-02 */

  /// @dev FIL-02 — every generic call sits between the single validator's two hooks
  function test_hookOrdering_beforeThenAllCallsThenAfter() public {
    ISignatureTransfer.PermitBatchTransferFrom memory permit = _fundAndPermit(2 ether, 0);
    ValidationParams[] memory vps = _oneValidator();
    GenericCall[] memory calls = _genericCallArray(
      _genericCall(address(routerA), 0, hex'01'), _genericCall(address(routerB), 0, hex'02')
    );

    _fill(permit, _targetsA(), _noErc721Params(), vps, calls);

    string[] memory expected = new string[](4);
    expected[0] = 'validatorA:before';
    expected[1] = 'routerA';
    expected[2] = 'routerB';
    expected[3] = 'validatorA:after';
    _assertSequence(expected);
  }

  /* --------------------------------------------------------------- FIL-03 */

  /// @dev FIL-03 — `beforeExecution` runs after the funding transfers, so its snapshot sees them
  function test_beforeExecution_snapshotsPostFundingState() public {
    ISignatureTransfer.PermitBatchTransferFrom memory permit = _fundAndPermit(4 ether, 0);
    validatorA.setWatched(address(tokenA), address(routerA));

    assertEq(tokenA.balanceOf(address(routerA)), 0, 'target starts empty');

    ValidationParams[] memory vps = _oneValidator();
    _fill(permit, _targetsA(), _noErc721Params(), vps, _oneCallToRouterA());

    ActionValidatorMock.BeforeCall memory beforeCall = validatorA.beforeCallAt(0);
    assertEq(beforeCall.watchedBalance, 4 ether, 'snapshot already reflects the funding transfer');
    assertEq(beforeCall.caller, address(hub), 'hub is the validator caller');
    assertEq(validatorA.afterCallAt(0).watchedBalance, 4 ether, 'balance unchanged across the fill');
  }

  /* --------------------------------------------------------------- FIL-04 */

  /// @dev FIL-04 — every hook argument, including the before-output, is forwarded verbatim
  function test_beforeExecutionOutput_pipedVerbatimIntoAfterExecution() public {
    ISignatureTransfer.PermitBatchTransferFrom memory permit = _fundAndPermit(1 ether, 0);
    bytes memory snapshot = hex'cafebabedeadbeef';
    validatorA.setBeforeExecutionOutput(snapshot);

    ValidationParams[] memory vps = _validationParamsArray(
      _validationParams(address(validatorA), ACTION_A, hex'b1b1', hex'a2a2')
    );
    _fill(permit, _targetsA(), _noErc721Params(), vps, _oneCallToRouterA());

    ActionValidatorMock.BeforeCall memory beforeCall = validatorA.beforeCallAt(0);
    assertEq(beforeCall.action, ACTION_A, 'before action forwarded');
    assertEq(beforeCall.input, hex'b1b1', 'beforeExecutionInput forwarded');

    ActionValidatorMock.AfterCall memory afterCall = validatorA.afterCallAt(0);
    assertEq(afterCall.caller, address(hub), 'hub is the validator caller');
    assertEq(afterCall.action, ACTION_A, 'after action forwarded');
    assertEq(afterCall.beforeInput, hex'b1b1', 'beforeExecutionInput forwarded again');
    assertEq(afterCall.beforeOutput, snapshot, 'before-output piped verbatim');
    assertEq(afterCall.afterInput, hex'a2a2', 'afterExecutionInput forwarded');
  }

  /* --------------------------------------------------------------- FIL-05 */

  /// @dev FIL-05 — `beforeExecutionOutputs[i]` reaches `validationParams[i]`, never a neighbour
  function test_twoValidators_outputIndexAlignmentAndOrdering() public {
    ISignatureTransfer.PermitBatchTransferFrom memory permit = _fundAndPermit(1 ether, 0);

    bytes memory outputA = hex'aaaaaaaa';
    bytes memory outputB = hex'bbbbbbbb';
    validatorA.setBeforeExecutionOutput(outputA);
    validatorB.setBeforeExecutionOutput(outputB);

    ValidationParams[] memory vps = _validationParamsArray(
      _validationParams(address(validatorA), ACTION_A, hex'a0', hex'a1'),
      _validationParams(address(validatorB), ACTION_B, hex'b0', hex'b1')
    );
    _fill(permit, _targetsA(), _noErc721Params(), vps, _oneCallToRouterA());

    assertEq(validatorA.afterCallAt(0).beforeOutput, outputA, 'validatorA got its own output');
    assertEq(validatorB.afterCallAt(0).beforeOutput, outputB, 'validatorB got its own output');
    assertEq(validatorA.afterCallAt(0).action, ACTION_A, 'validatorA got its own action');
    assertEq(validatorB.afterCallAt(0).action, ACTION_B, 'validatorB got its own action');

    string[] memory expected = new string[](5);
    expected[0] = 'validatorA:before';
    expected[1] = 'validatorB:before';
    expected[2] = 'routerA';
    expected[3] = 'validatorA:after';
    expected[4] = 'validatorB:after';
    _assertSequence(expected);
  }

  /* --------------------------------------------------------------- FIL-06 */

  /// @dev FIL-06 — a rejecting `beforeExecution` reverts the whole fill, funding included
  function test_beforeExecutionRevert_rollsBackEverything() public {
    ISignatureTransfer.PermitBatchTransferFrom memory permit = _fundAndPermit(6 ether, 0);
    validatorA.setRevertOnBefore(true);

    ValidationParams[] memory vps = _oneValidator();
    bytes memory sig = _solverSig(permit, solver, _targetsA(), _noErc721Transfers(), vps);

    uint256 ownerBefore = tokenA.balanceOf(owner);

    vm.prank(solver);
    vm.expectRevert(ActionValidatorMock.ValidationFailed.selector);
    hub.permit2TransferAndFillIntent(
      permit, _targetsA(), _noErc721Params(), vps, _oneCallToRouterA(), owner, sig
    );

    assertEq(tokenA.balanceOf(owner), ownerBefore, 'owner funding rolled back');
    assertEq(tokenA.balanceOf(address(routerA)), 0, 'target funding rolled back');
    assertEq(permit2.nonceBitmap(owner, 0), 0, 'permit2 nonce not consumed');
    assertEq(routerA.callCount(), 0, 'no generic call survived');
  }

  /* --------------------------------------------------------------- FIL-07 */

  /// @dev FIL-07 — a rejecting `afterExecution` unwinds the generic calls that already ran
  function test_afterExecutionRevert_rollsBackRouterEffects() public {
    ISignatureTransfer.PermitBatchTransferFrom memory permit = _fundAndPermit(6 ether, 0);
    validatorA.setRevertOnAfter(true);

    ValidationParams[] memory vps = _oneValidator();
    bytes memory sig = _solverSig(permit, solver, _targetsA(), _noErc721Transfers(), vps);

    uint256 ownerBefore = tokenA.balanceOf(owner);

    vm.prank(solver);
    vm.expectRevert(ActionValidatorMock.ValidationFailed.selector);
    hub.permit2TransferAndFillIntent(
      permit, _targetsA(), _noErc721Params(), vps, _oneCallToRouterA(), owner, sig
    );

    // The router was reached before the rejection, so a surviving record would prove a leak
    assertEq(routerA.callCount(), 0, 'router effects rolled back');
    assertEq(recorder.length(), 0, 'recorder rolled back');
    assertEq(tokenA.balanceOf(owner), ownerBefore, 'owner funding rolled back');
    assertEq(tokenA.balanceOf(address(routerA)), 0, 'target funding rolled back');
    assertEq(permit2.nonceBitmap(owner, 0), 0, 'permit2 nonce not consumed');
  }

  /* --------------------------------------------------------------- FIL-08 */

  /// @dev FIL-08 — an empty `validationParams` leaves the fill documented-unconstrained
  function test_emptyValidationParams_succeedsWithNoValidatorCalls() public {
    ISignatureTransfer.PermitBatchTransferFrom memory permit = _fundAndPermit(2 ether, 0);
    ValidationParams[] memory vps = _noValidationParams();

    _fill(permit, _targetsA(), _noErc721Params(), vps, _oneCallToRouterA());

    assertEq(tokenA.balanceOf(address(routerA)), 2 ether, 'fill still funded the target');
    assertEq(validatorA.beforeCallCount(), 0, 'no beforeExecution');
    assertEq(validatorA.afterCallCount(), 0, 'no afterExecution');
    assertEq(validatorB.beforeCallCount(), 0, 'no beforeExecution on the second validator');

    string[] memory expected = new string[](1);
    expected[0] = 'routerA';
    _assertSequence(expected);
  }

  /* --------------------------------------------------------------- FIL-09 */

  /// @dev FIL-09 — the witness pins `msg.sender`, so only the signed solver can submit
  function test_witnessBindsSolver_otherSubmitterRejected() public {
    ISignatureTransfer.PermitBatchTransferFrom memory permit = _fundAndPermit(2 ether, 0);
    ValidationParams[] memory vps = _oneValidator();
    bytes memory sig = _solverSig(permit, solver, _targetsA(), _noErc721Transfers(), vps);

    vm.prank(relayer);
    vm.expectRevert(Permit2Mock.InvalidSigner.selector);
    hub.permit2TransferAndFillIntent(
      permit, _targetsA(), _noErc721Params(), vps, _oneCallToRouterA(), owner, sig
    );

    assertEq(permit2.nonceBitmap(owner, 0), 0, 'nonce untouched by the rejected submission');
  }

  /* --------------------------------------------------------------- FIL-10 */

  /// @dev FIL-10 — the witness pins the ERC20 targets
  function test_witnessBindsTargets_alteredTargetRejected() public {
    ISignatureTransfer.PermitBatchTransferFrom memory permit = _fundAndPermit(2 ether, 0);
    ValidationParams[] memory vps = _oneValidator();
    bytes memory sig = _solverSig(permit, solver, _targetsA(), _noErc721Transfers(), vps);

    address[] memory tamperedTargets = [address(routerB)].toMemoryArray();

    vm.prank(solver);
    vm.expectRevert(Permit2Mock.InvalidSigner.selector);
    hub.permit2TransferAndFillIntent(
      permit, tamperedTargets, _noErc721Params(), vps, _oneCallToRouterA(), owner, sig
    );

    assertEq(tokenA.balanceOf(address(routerB)), 0, 'redirected target never funded');
  }

  /* --------------------------------------------------------------- FIL-11 */

  /// @dev FIL-11 — the witness pins every ERC721 movement, target and tokenId alike
  function test_witnessBindsErc721Transfers_alteredTargetOrTokenIdRejected() public {
    ISignatureTransfer.PermitBatchTransferFrom memory permit = _fundAndPermit(2 ether, 0);
    nft.mint(owner, 7);
    nft.mint(owner, 8);
    vm.prank(owner);
    nft.setApprovalForAll(address(hub), true);

    ValidationParams[] memory vps = _oneValidator();
    ERC721Transfer[] memory signedTransfers = new ERC721Transfer[](1);
    signedTransfers[0] =
      ERC721Transfer({token: address(nft), tokenId: 7, target: address(nftReceiver)});
    bytes memory sig = _solverSig(permit, solver, _targetsA(), signedTransfers, vps);

    // Same tokenId, redirected target
    ERC721Params[] memory tamperedTarget =
      _erc721ParamsArray(_erc721Params(address(nft), 7, recipient, ''));
    vm.prank(solver);
    vm.expectRevert(Permit2Mock.InvalidSigner.selector);
    hub.permit2TransferAndFillIntent(
      permit, _targetsA(), tamperedTarget, vps, _oneCallToRouterA(), owner, sig
    );

    // Signed target, different tokenId
    ERC721Params[] memory tamperedId =
      _erc721ParamsArray(_erc721Params(address(nft), 8, address(nftReceiver), ''));
    vm.prank(solver);
    vm.expectRevert(Permit2Mock.InvalidSigner.selector);
    hub.permit2TransferAndFillIntent(
      permit, _targetsA(), tamperedId, vps, _oneCallToRouterA(), owner, sig
    );

    assertEq(nft.ownerOf(7), owner, 'token 7 never moved');
    assertEq(nft.ownerOf(8), owner, 'token 8 never moved');
  }

  /* --------------------------------------------------------------- FIL-12 */

  /// @dev FIL-12 — the witness pins the acceptance criteria: validator, action and both inputs
  function test_witnessBindsValidationParams_anyAlterationRejected() public {
    ISignatureTransfer.PermitBatchTransferFrom memory permit = _fundAndPermit(2 ether, 0);
    ValidationParams[] memory signed =
      _validationParamsArray(_validationParams(address(validatorA), ACTION_A, hex'b0', hex'a0'));
    bytes memory sig = _solverSig(permit, solver, _targetsA(), _noErc721Transfers(), signed);

    ValidationParams[] memory swappedValidator =
      _validationParamsArray(_validationParams(address(validatorB), ACTION_A, hex'b0', hex'a0'));
    ValidationParams[] memory swappedAction =
      _validationParamsArray(_validationParams(address(validatorA), ACTION_B, hex'b0', hex'a0'));
    ValidationParams[] memory swappedInput =
      _validationParamsArray(_validationParams(address(validatorA), ACTION_A, hex'b0', hex'a1'));

    vm.prank(solver);
    vm.expectRevert(Permit2Mock.InvalidSigner.selector);
    hub.permit2TransferAndFillIntent(
      permit, _targetsA(), _noErc721Params(), swappedValidator, _oneCallToRouterA(), owner, sig
    );

    vm.prank(solver);
    vm.expectRevert(Permit2Mock.InvalidSigner.selector);
    hub.permit2TransferAndFillIntent(
      permit, _targetsA(), _noErc721Params(), swappedAction, _oneCallToRouterA(), owner, sig
    );

    vm.prank(solver);
    vm.expectRevert(Permit2Mock.InvalidSigner.selector);
    hub.permit2TransferAndFillIntent(
      permit, _targetsA(), _noErc721Params(), swappedInput, _oneCallToRouterA(), owner, sig
    );

    assertEq(validatorA.beforeCallCount(), 0, 'no validation ever ran');
    assertEq(validatorB.beforeCallCount(), 0, 'no validation ever ran on the substitute');
  }

  /* --------------------------------------------------------------- FIL-13 */

  /**
   * @dev FIL-13 — `genericCalls` is deliberately NOT part of the `SolverWitness`. The owner signs
   * the funding and the acceptance criteria; the solver picks the path. This is the documented
   * design asymmetry against `permit2TransferAndExecute`, where the relayer witness DOES bind them.
   */
  function test_genericCallsNotBound_unrelatedWhitelistedCallsSucceed() public {
    ISignatureTransfer.PermitBatchTransferFrom memory permit = _fundAndPermit(2 ether, 0);
    ValidationParams[] memory vps = _oneValidator();

    // Nothing about the calls below reaches the witness: `hash` takes no `genericCalls` argument
    bytes memory sig = _solverSig(permit, solver, _targetsA(), _noErc721Transfers(), vps);

    GenericCall[] memory unrelatedCalls = _genericCallArray(
      _genericCall(address(routerB), 0, hex'99999999'),
      _genericCall(address(routerA), 0, hex'88888888')
    );

    vm.prank(solver);
    (bytes[] memory results,) = hub.permit2TransferAndFillIntent(
      permit, _targetsA(), _noErc721Params(), vps, unrelatedCalls, owner, sig
    );

    assertEq(results.length, 2, 'both unsigned calls executed');
    assertEq(routerB.callAt(0).data, hex'99999999', 'routerB ran the submitted payload');
    assertEq(routerA.callAt(0).data, hex'88888888', 'routerA ran the submitted payload');
    assertEq(tokenA.balanceOf(address(routerA)), 2 ether, 'funding still followed the signature');
    assertEq(validatorA.afterCallCount(), 1, 'the signed criteria still judged the fill');
  }

  /* --------------------------------------------------------------- FIL-15 */

  /// @dev FIL-15 — routers read back the token owner, not the solver that submitted the fill
  function test_routerObservesOwnerAsMsgSender() public {
    ISignatureTransfer.PermitBatchTransferFrom memory permit = _fundAndPermit(2 ether, 0);
    ValidationParams[] memory vps = _oneValidator();

    _fill(permit, _targetsA(), _noErc721Params(), vps, _oneCallToRouterA());

    assertTrue(solver != owner, 'the submitter is not the owner');
    assertEq(routerA.callAt(0).observedMsgSender, owner, 'router sees the token owner');
    assertEq(routerA.callAt(0).caller, address(hub), 'the hub is the router caller');
  }

  /* --------------------------------------------------------------- FIL-16 */

  /// @dev FIL-16 — ERC721s are pulled from `owner`, not from the submitting solver
  function test_erc721PulledFromOwner() public {
    ISignatureTransfer.PermitBatchTransferFrom memory permit = _fundAndPermit(2 ether, 0);
    nft.mint(owner, 7);
    vm.prank(owner);
    nft.setApprovalForAll(address(hub), true);
    assertEq(nft.ownerOf(7), owner, 'token starts on the owner');

    ValidationParams[] memory vps = _oneValidator();
    ERC721Params[] memory erc721Params =
      _erc721ParamsArray(_erc721Params(address(nft), 7, address(nftReceiver), ''));

    ERC721Transfer[] memory expectedErc721 = new ERC721Transfer[](1);
    expectedErc721[0] =
      ERC721Transfer({token: address(nft), tokenId: 7, target: address(nftReceiver)});

    ERC20Transfer[] memory expectedErc20 = new ERC20Transfer[](1);
    expectedErc20[0] =
      ERC20Transfer({token: address(tokenA), target: address(routerA), amount: 2 ether});

    bytes memory sig = _solverSig(permit, solver, _targetsA(), expectedErc721, vps);

    vm.expectEmit(true, true, true, true, address(hub));
    emit TransferTokens(solver, owner, 0, expectedErc20, expectedErc721, new NativeTransfer[](0));

    vm.prank(solver);
    hub.permit2TransferAndFillIntent(
      permit, _targetsA(), erc721Params, vps, _oneCallToRouterA(), owner, sig
    );

    assertEq(nft.ownerOf(7), address(nftReceiver), 'token routed to the signed target');
    assertEq(nft.balanceOf(owner), 0, 'owner is the account that paid the token');
  }

  /* --------------------------------------------------------------- FIL-17 */

  /// @dev FIL-17 — the whitelist keeps the hub's allowances out of reach of arbitrary callees
  function test_nonWhitelistedRouter_reverts() public {
    ISignatureTransfer.PermitBatchTransferFrom memory permit = _fundAndPermit(2 ether, 0);
    ValidationParams[] memory vps = _oneValidator();
    bytes memory sig = _solverSig(permit, solver, _targetsA(), _noErc721Transfers(), vps);

    GenericCall[] memory calls =
      _genericCallArray(_genericCall(address(unlistedRouter), 0, hex'01'));

    vm.prank(solver);
    vm.expectRevert(
      abi.encodeWithSelector(
        IAccessControl.AccessControlUnauthorizedAccount.selector,
        address(unlistedRouter),
        WHITELIST_ROUTER_ROLE
      )
    );
    hub.permit2TransferAndFillIntent(permit, _targetsA(), _noErc721Params(), vps, calls, owner, sig);

    assertEq(unlistedRouter.callCount(), 0, 'unlisted router never reached');
  }

  /* --------------------------------------------------------------- FIL-18 */

  /// @dev FIL-18 — a failing router bubbles its own error out of the fill
  function test_routerRevert_bubblesUp() public {
    ISignatureTransfer.PermitBatchTransferFrom memory permit = _fundAndPermit(2 ether, 0);
    ValidationParams[] memory vps = _oneValidator();
    bytes memory sig = _solverSig(permit, solver, _targetsA(), _noErc721Transfers(), vps);

    routerA.setShouldRevert(true);

    vm.prank(solver);
    vm.expectRevert(GenericRouterMock.RouterFailed.selector);
    hub.permit2TransferAndFillIntent(
      permit, _targetsA(), _noErc721Params(), vps, _oneCallToRouterA(), owner, sig
    );

    assertEq(tokenA.balanceOf(address(routerA)), 0, 'funding rolled back with the router');
    assertEq(validatorA.afterCallCount(), 0, 'afterExecution never reached');
  }

  /* ---------------------------------------------- FIL-20 (fix regression) */

  /// @dev FIL-20 — regression lock for the `whenNotPaused` modifier added this session
  function test_pausedHubRejectsFill() public {
    ISignatureTransfer.PermitBatchTransferFrom memory permit = _fundAndPermit(2 ether, 0);
    ValidationParams[] memory vps = _oneValidator();
    bytes memory sig = _solverSig(permit, solver, _targetsA(), _noErc721Transfers(), vps);

    vm.prank(guardian);
    hub.pause();

    vm.prank(solver);
    vm.expectRevert(Pausable.EnforcedPause.selector);
    hub.permit2TransferAndFillIntent(
      permit, _targetsA(), _noErc721Params(), vps, _oneCallToRouterA(), owner, sig
    );

    assertEq(tokenA.balanceOf(address(routerA)), 0, 'nothing moved while paused');
    assertEq(permit2.nonceBitmap(owner, 0), 0, 'nonce untouched while paused');
  }

  /* --------------------------------------------- FIL-21a (fix regression) */

  /// @dev FIL-21a — regression lock for the `lock` modifier: same-entrypoint reentry
  function test_reentryFromFillIntoFill_reverts() public {
    ISignatureTransfer.PermitBatchTransferFrom memory permit = _fundAndPermit(2 ether, 0);
    ValidationParams[] memory vps = _oneValidator();
    bytes memory sig = _solverSig(permit, solver, _targetsA(), _noErc721Transfers(), vps);

    // Bubble the inner revert so it surfaces as the outer call's failure
    reentrantRouter.setReentrantCalldata(_innerFillCalldata(), false);
    GenericCall[] memory calls = _genericCallArray(_genericCall(address(reentrantRouter), 0, hex''));

    vm.prank(solver);
    vm.expectRevert(IKSAllowanceHubV2.AlreadyLocked.selector);
    hub.permit2TransferAndFillIntent(permit, _targetsA(), _noErc721Params(), vps, calls, owner, sig);
  }

  /* --------------------------------------------- FIL-21b (fix regression) */

  /**
   * @dev FIL-21b — regression lock for the cross-entrypoint impersonation vector. While
   * `permitTransferAndExecute` holds the lock with the outer owner published in `msgSender()`, a
   * whitelisted router reenters `permit2TransferAndFillIntent`. Before the modifiers were added to
   * that entrypoint the inner call would have executed against the outer owner's identity.
   */
  function test_reentryFromPermitTransferAndExecuteIntoFill_reverts() public {
    reentrantRouter.setReentrantCalldata(_innerFillCalldata(), true);
    GenericCall[] memory calls = _genericCallArray(_genericCall(address(reentrantRouter), 0, hex''));

    vm.prank(owner);
    hub.permitTransferAndExecute(_noErc20Params(), _noErc721Params(), calls);

    assertTrue(reentrantRouter.reentrantCallReverted(), 'the reentrant fill was rejected');

    bytes memory revertData = reentrantRouter.reentrantRevertData();
    assertEq(revertData.length, 4, 'a bare custom-error selector came back');
    assertEq(
      bytes4(revertData), IKSAllowanceHubV2.AlreadyLocked.selector, 'rejected with AlreadyLocked'
    );
    assertEq(hub.msgSender(), address(0), 'lock released after the outer call');
  }

  /* ---------------------------------------------- FIL-22 (fix regression) */

  /// @dev FIL-22 — regression lock for `notOverspentNative`: overspend rejected, equality allowed
  function test_nativeOverspendRejected_equalBoundaryAllowed() public {
    ISignatureTransfer.PermitBatchTransferFrom memory permit = _fundAndPermit(2 ether, 0);
    ValidationParams[] memory vps = _oneValidator();
    bytes memory sig = _solverSig(permit, solver, _targetsA(), _noErc721Transfers(), vps);

    // Native the hub already holds must stay out of reach of the call
    vm.deal(address(hub), 5 ether);
    vm.deal(solver, 10 ether);

    GenericCall[] memory calls = _genericCallArray(_genericCall(address(routerA), 1 ether, hex'01'));

    vm.prank(solver);
    vm.expectRevert(IKSAllowanceHubV2.NativeTokenOverspent.selector);
    hub.permit2TransferAndFillIntent{value: 0.5 ether}(
      permit, _targetsA(), _noErc721Params(), vps, calls, owner, sig
    );

    assertEq(address(hub).balance, 5 ether, 'pre-funding untouched by the rejected call');
    assertEq(permit2.nonceBitmap(owner, 0), 0, 'nonce untouched by the rejected call');

    // Exactly `msg.value` spent: the boundary is inclusive, and the signature still applies
    vm.prank(solver);
    hub.permit2TransferAndFillIntent{value: 1 ether}(
      permit, _targetsA(), _noErc721Params(), vps, calls, owner, sig
    );

    assertEq(address(routerA).balance, 1 ether, 'the boundary call forwarded its value');
    assertEq(address(hub).balance, 5 ether, 'hub still holds exactly its pre-funding');
    assertEq(tokenA.balanceOf(address(routerA)), 2 ether, 'boundary call funded the target');
  }

  /* ---------------------------------------------- FIL-23 (fix regression) */

  /// @dev FIL-23 — regression lock for `checkLengths(targets.length, permit.permitted.length)`
  function test_mismatchedTargetAndPermittedLengths_revert() public {
    ISignatureTransfer.PermitBatchTransferFrom memory permit = _fundAndPermit(2 ether, 0);
    ValidationParams[] memory vps = _oneValidator();
    bytes memory sig = _solverSig(permit, solver, _targetsA(), _noErc721Transfers(), vps);

    address[] memory tooManyTargets = [address(routerA), address(routerB)].toMemoryArray();

    vm.prank(solver);
    vm.expectRevert(ICommon.MismatchedArrayLengths.selector);
    hub.permit2TransferAndFillIntent(
      permit, tooManyTargets, _noErc721Params(), vps, _oneCallToRouterA(), owner, sig
    );

    // Same guard in the other direction: two permitted tokens, one target
    ISignatureTransfer.PermitBatchTransferFrom memory twoTokenPermit = _permitBatch(
      [address(tokenA), address(tokenB)].toMemoryArray(),
      [uint256(1 ether), uint256(1 ether)].toMemoryArray(),
      1
    );

    vm.prank(solver);
    vm.expectRevert(ICommon.MismatchedArrayLengths.selector);
    hub.permit2TransferAndFillIntent(
      twoTokenPermit, _targetsA(), _noErc721Params(), vps, _oneCallToRouterA(), owner, sig
    );

    assertEq(permit2.nonceBitmap(owner, 0), 0, 'no nonce consumed by either rejection');
  }

  /* --------------------------------------------------------------- FIL-24 */

  /**
   * @dev FIL-24 — branch-split property. On success every configured validator recorded both
   * hooks and the funding moved by exactly `amount`, with the unspent `msg.value` stranded in the
   * hub. On rejection the recorder and the validator arrays are rolled back with everything else,
   * so the surviving observable is that the balances are identical to the pre-call state.
   */
  function testFuzz_fillOutcomeIsAllOrNothing(FillFuzz memory p) public {
    uint256 amount = bound(uint256(p.amount), 1, 1e30);
    uint256 msgValue = bound(uint256(p.msgValue), 0, 100 ether);
    uint256 validatorCount = bound(uint256(p.validatorCount), 1, 4);

    _fundERC20(tokenA, owner, amount);
    _approvePermit2(tokenA, owner, type(uint256).max);
    vm.deal(solver, msgValue);

    ValidationParams[] memory vps = new ValidationParams[](validatorCount);
    uint256 expectedA;
    uint256 expectedB;
    for (uint256 i = 0; i < validatorCount; i++) {
      bool isA = i % 2 == 0;
      if (isA) expectedA++;
      else expectedB++;
      vps[i] = _validationParams(
        isA ? address(validatorA) : address(validatorB),
        bytes32(i + 1),
        abi.encode(i),
        abi.encode(i, isA)
      );
    }

    if (p.revertAfter) {
      validatorA.setRevertOnAfter(true);
      validatorB.setRevertOnAfter(true);
    }

    ISignatureTransfer.PermitBatchTransferFrom memory permit =
      _permitBatch([address(tokenA)].toMemoryArray(), [amount].toMemoryArray(), 0);
    bytes memory sig = _solverSig(permit, solver, _targetsA(), _noErc721Transfers(), vps);

    uint256 ownerBefore = tokenA.balanceOf(owner);
    uint256 targetBefore = tokenA.balanceOf(address(routerA));

    if (p.revertAfter) {
      vm.prank(solver);
      vm.expectRevert(ActionValidatorMock.ValidationFailed.selector);
      hub.permit2TransferAndFillIntent{value: msgValue}(
        permit, _targetsA(), _noErc721Params(), vps, _oneCallToRouterA(), owner, sig
      );

      assertEq(tokenA.balanceOf(owner), ownerBefore, 'owner balance identical after rejection');
      assertEq(
        tokenA.balanceOf(address(routerA)), targetBefore, 'target balance identical after rejection'
      );
      assertEq(address(hub).balance, 0, 'no native retained by a rejected fill');
    } else {
      vm.prank(solver);
      hub.permit2TransferAndFillIntent{value: msgValue}(
        permit, _targetsA(), _noErc721Params(), vps, _oneCallToRouterA(), owner, sig
      );

      assertEq(tokenA.balanceOf(owner), ownerBefore - amount, 'owner debited exactly amount');
      assertEq(
        tokenA.balanceOf(address(routerA)), targetBefore + amount, 'target credited exactly amount'
      );
      assertEq(validatorA.beforeCallCount(), expectedA, 'validatorA before hooks');
      assertEq(validatorA.afterCallCount(), expectedA, 'validatorA after hooks');
      assertEq(validatorB.beforeCallCount(), expectedB, 'validatorB before hooks');
      assertEq(validatorB.afterCallCount(), expectedB, 'validatorB after hooks');
      // The hub has no `receive()` and no refund path, so unspent value stays put
      assertEq(address(hub).balance, msgValue, 'unspent msg.value stranded in the hub');
    }
  }

  /* -------------------------------------------------------------- helpers */

  /// @dev Mints, approves Permit2 and builds a single-token batch permit for `owner`
  function _fundAndPermit(uint256 amount, uint256 nonce)
    private
    returns (ISignatureTransfer.PermitBatchTransferFrom memory permit)
  {
    _fundERC20(tokenA, owner, amount);
    _approvePermit2(tokenA, owner, type(uint256).max);
    permit = _permitBatch([address(tokenA)].toMemoryArray(), [amount].toMemoryArray(), nonce);
  }

  /**
   * @dev Signs the Permit2 batch over the `SolverWitness` the hub will rebuild. Uses the production
   * library for the hash only; batch D independently pins the typehash and type string.
   */
  function _solverSig(
    ISignatureTransfer.PermitBatchTransferFrom memory permit,
    address expectedSolver,
    address[] memory targets,
    ERC721Transfer[] memory erc721Transfers,
    ValidationParams[] memory validationParams
  ) private view returns (bytes memory) {
    bytes32 witness = SolverWitnessLibrary.hash(
      expectedSolver, targets, erc721Transfers, validationParams
    );
    return _signPermit2WithWitness(
      ownerWallet,
      permit,
      address(hub),
      witness,
      SolverWitnessLibrary.SOLVER_WITNESS_PERMIT2_TYPE_STRING
    );
  }

  /// @dev Signs and submits a fill as `solver`
  function _fill(
    ISignatureTransfer.PermitBatchTransferFrom memory permit,
    address[] memory targets,
    ERC721Params[] memory erc721Params,
    ValidationParams[] memory validationParams,
    GenericCall[] memory genericCalls
  ) private returns (bytes[] memory results) {
    ERC721Transfer[] memory erc721Transfers = _toErc721Transfers(erc721Params);
    bytes memory sig = _solverSig(permit, solver, targets, erc721Transfers, validationParams);

    vm.prank(solver);
    (results,) = hub.permit2TransferAndFillIntent(
      permit, targets, erc721Params, validationParams, genericCalls, owner, sig
    );
  }

  /// @dev Memory-side projection of `ERC721TransferLibrary.toTransfers`, which takes calldata
  function _toErc721Transfers(ERC721Params[] memory params)
    private
    pure
    returns (ERC721Transfer[] memory transfers)
  {
    transfers = new ERC721Transfer[](params.length);
    for (uint256 i = 0; i < params.length; i++) {
      transfers[i] = ERC721Transfer({
        token: params[i].token, tokenId: params[i].tokenId, target: params[i].target
      });
    }
  }

  /// @dev A reentrant fill whose arguments are irrelevant: `lock` rejects it before the body
  function _innerFillCalldata() private view returns (bytes memory) {
    ISignatureTransfer.PermitBatchTransferFrom memory permit;
    permit.permitted = new ISignatureTransfer.TokenPermissions[](0);
    permit.deadline = DEFAULT_DEADLINE;

    return abi.encodeCall(
      hub.permit2TransferAndFillIntent,
      (
        permit,
        new address[](0),
        _noErc721Params(),
        _noValidationParams(),
        _noGenericCalls(),
        address(1),
        ''
      )
    );
  }

  function _targetsA() private view returns (address[] memory) {
    return [address(routerA)].toMemoryArray();
  }

  function _oneValidator() private view returns (ValidationParams[] memory) {
    return
      _validationParamsArray(_validationParams(address(validatorA), ACTION_A, hex'b0', hex'a0'));
  }

  function _oneCallToRouterA() private view returns (GenericCall[] memory) {
    return _genericCallArray(_genericCall(address(routerA), 0, hex'01'));
  }

  function _noErc721Transfers() private pure returns (ERC721Transfer[] memory) {
    return new ERC721Transfer[](0);
  }

  function _assertSequence(string[] memory expected) private view {
    string[] memory actual = recorder.all();
    assertEq(actual.length, expected.length, 'recorded call count');
    for (uint256 i = 0; i < expected.length; i++) {
      assertEq(actual[i], expected[i], string.concat('recorder entry ', vm.toString(i)));
    }
  }
}
