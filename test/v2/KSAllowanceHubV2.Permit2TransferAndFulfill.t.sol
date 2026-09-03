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
 * @notice Batch C — `KSAllowanceHubV2.permit2TransferAndFulfill`
 * @dev Covers the fill flow itself (funding, validator hooks, event payload, results), the
 * `SolverWitness` binding surface — including the deliberate omission of `genericCalls` — and the
 * regression lock for the `whenNotPaused / lock / notOverspentNative / checkLengths` modifier set
 * added to this entrypoint.
 *
 * `SolverWitnessLibrary` is imported for signing only. Batch D pins the typehash and type string
 * against hand-written literals, so this batch never asserts the witness hash value itself.
 */
contract KSAllowanceHubV2Permit2TransferAndFulfillTest is KSAllowanceHubV2Base {
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
    (bytes[] memory results,) = hub.permit2TransferAndFulfill{value: 1 ether}(
      permit, targets, _noErc721Params(), vps, owner, false, sig, calls, ''
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
    hub.permit2TransferAndFulfill(
      permit, _targetsA(), _noErc721Params(), vps, owner, false, sig, _oneCallToRouterA(), ''
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
    hub.permit2TransferAndFulfill(
      permit, _targetsA(), _noErc721Params(), vps, owner, false, sig, _oneCallToRouterA(), ''
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
    hub.permit2TransferAndFulfill(
      permit, _targetsA(), _noErc721Params(), vps, owner, false, sig, _oneCallToRouterA(), ''
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
    hub.permit2TransferAndFulfill(
      permit, tamperedTargets, _noErc721Params(), vps, owner, false, sig, _oneCallToRouterA(), ''
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
    hub.permit2TransferAndFulfill(
      permit, _targetsA(), tamperedTarget, vps, owner, false, sig, _oneCallToRouterA(), ''
    );

    // Signed target, different tokenId
    ERC721Params[] memory tamperedId =
      _erc721ParamsArray(_erc721Params(address(nft), 8, address(nftReceiver), ''));
    vm.prank(solver);
    vm.expectRevert(Permit2Mock.InvalidSigner.selector);
    hub.permit2TransferAndFulfill(
      permit, _targetsA(), tamperedId, vps, owner, false, sig, _oneCallToRouterA(), ''
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
    hub.permit2TransferAndFulfill(
      permit,
      _targetsA(),
      _noErc721Params(),
      swappedValidator,
      owner,
      false,
      sig,
      _oneCallToRouterA(),
      ''
    );

    vm.prank(solver);
    vm.expectRevert(Permit2Mock.InvalidSigner.selector);
    hub.permit2TransferAndFulfill(
      permit,
      _targetsA(),
      _noErc721Params(),
      swappedAction,
      owner,
      false,
      sig,
      _oneCallToRouterA(),
      ''
    );

    vm.prank(solver);
    vm.expectRevert(Permit2Mock.InvalidSigner.selector);
    hub.permit2TransferAndFulfill(
      permit,
      _targetsA(),
      _noErc721Params(),
      swappedInput,
      owner,
      false,
      sig,
      _oneCallToRouterA(),
      ''
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
    (bytes[] memory results,) = hub.permit2TransferAndFulfill(
      permit, _targetsA(), _noErc721Params(), vps, owner, false, sig, unrelatedCalls, ''
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
    hub.permit2TransferAndFulfill(
      permit, _targetsA(), erc721Params, vps, owner, false, sig, _oneCallToRouterA(), ''
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
    hub.permit2TransferAndFulfill(
      permit, _targetsA(), _noErc721Params(), vps, owner, false, sig, calls, ''
    );

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
    hub.permit2TransferAndFulfill(
      permit, _targetsA(), _noErc721Params(), vps, owner, false, sig, _oneCallToRouterA(), ''
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
    hub.permit2TransferAndFulfill(
      permit, _targetsA(), _noErc721Params(), vps, owner, false, sig, _oneCallToRouterA(), ''
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
    hub.permit2TransferAndFulfill(
      permit, _targetsA(), _noErc721Params(), vps, owner, false, sig, calls, ''
    );
  }

  /* --------------------------------------------- FIL-21b (fix regression) */

  /**
   * @dev FIL-21b — regression lock for the cross-entrypoint impersonation vector. While
   * `permitTransferAndExecute` holds the lock with the outer owner published in `msgSender()`, a
   * whitelisted router reenters `permit2TransferAndFulfill`. Before the modifiers were added to
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
    hub.permit2TransferAndFulfill{value: 0.5 ether}(
      permit, _targetsA(), _noErc721Params(), vps, owner, false, sig, calls, ''
    );

    assertEq(address(hub).balance, 5 ether, 'pre-funding untouched by the rejected call');
    assertEq(permit2.nonceBitmap(owner, 0), 0, 'nonce untouched by the rejected call');

    // Exactly `msg.value` spent: the boundary is inclusive, and the signature still applies
    vm.prank(solver);
    hub.permit2TransferAndFulfill{value: 1 ether}(
      permit, _targetsA(), _noErc721Params(), vps, owner, false, sig, calls, ''
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
    hub.permit2TransferAndFulfill(
      permit, tooManyTargets, _noErc721Params(), vps, owner, false, sig, _oneCallToRouterA(), ''
    );

    // Same guard in the other direction: two permitted tokens, one target
    ISignatureTransfer.PermitBatchTransferFrom memory twoTokenPermit = _permitBatch(
      [address(tokenA), address(tokenB)].toMemoryArray(),
      [uint256(1 ether), uint256(1 ether)].toMemoryArray(),
      1
    );

    vm.prank(solver);
    vm.expectRevert(ICommon.MismatchedArrayLengths.selector);
    hub.permit2TransferAndFulfill(
      twoTokenPermit,
      _targetsA(),
      _noErc721Params(),
      vps,
      owner,
      false,
      sig,
      _oneCallToRouterA(),
      ''
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
      hub.permit2TransferAndFulfill{value: msgValue}(
        permit, _targetsA(), _noErc721Params(), vps, owner, false, sig, _oneCallToRouterA(), ''
      );

      assertEq(tokenA.balanceOf(owner), ownerBefore, 'owner balance identical after rejection');
      assertEq(
        tokenA.balanceOf(address(routerA)), targetBefore, 'target balance identical after rejection'
      );
      assertEq(address(hub).balance, 0, 'no native retained by a rejected fill');
    } else {
      vm.prank(solver);
      hub.permit2TransferAndFulfill{value: msgValue}(
        permit, _targetsA(), _noErc721Params(), vps, owner, false, sig, _oneCallToRouterA(), ''
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

  /* ------------------------------------------- anySolver fulfillment */

  /**
   * @dev The owner signs `ANY_ADDRESS` in place of a solver, so an address that appears nowhere in
   * the signature can fulfill the intent. The funding, the validators and the published token owner
   * are unchanged; only the submitter is free.
   */
  function test_anySolverFill_callerNamedNowhereInTheSignatureSucceeds() public {
    ISignatureTransfer.PermitBatchTransferFrom memory permit = _fundAndPermit(2 ether, 0);
    ValidationParams[] memory vps = _oneValidator();
    bytes memory sig = _anySolverSig(permit, _targetsA(), _noErc721Transfers(), vps);

    assertTrue(outsider != owner, 'the submitter is not the owner');
    assertTrue(outsider != solver, 'the submitter is not the solver the other tests sign for');

    ERC20Transfer[] memory expectedErc20 = new ERC20Transfer[](1);
    expectedErc20[0] =
      ERC20Transfer({token: address(tokenA), target: address(routerA), amount: 2 ether});

    // The event reports the actual submitter as `caller` and the signer as `owner`
    vm.expectEmit(true, true, true, true, address(hub));
    emit TransferTokens(
      outsider, owner, 0, expectedErc20, _noErc721Transfers(), new NativeTransfer[](0)
    );

    vm.prank(outsider);
    hub.permit2TransferAndFulfill(
      permit, _targetsA(), _noErc721Params(), vps, owner, true, sig, _oneCallToRouterA(), ''
    );

    assertEq(tokenA.balanceOf(address(routerA)), 2 ether, 'target funded by the anonymous fill');
    assertEq(tokenA.balanceOf(owner), 0, 'owner debited in full');
    assertEq(routerA.callAt(0).observedMsgSender, owner, 'router still sees the token owner');
    assertEq(permit2.nonceBitmap(owner, 0), 1, 'nonce consumed');

    string[] memory expected = new string[](3);
    expected[0] = 'validatorA:before';
    expected[1] = 'routerA';
    expected[2] = 'validatorA:after';
    _assertSequence(expected);
  }

  /**
   * @dev Two unrelated addresses each fulfill their own `ANY_ADDRESS` signature on separate nonces,
   * proving the signature is bound to no particular solver.
   */
  function test_anySolverFill_competingSubmittersEachFulfillTheirOwnSignature() public {
    _fundERC20(tokenA, owner, 5 ether);
    _approvePermit2(tokenA, owner, type(uint256).max);

    address[] memory targetsB = [address(routerB)].toMemoryArray();
    ValidationParams[] memory vps = _oneValidator();

    ISignatureTransfer.PermitBatchTransferFrom memory firstPermit =
      _permitBatch([address(tokenA)].toMemoryArray(), [uint256(2 ether)].toMemoryArray(), 0);
    ISignatureTransfer.PermitBatchTransferFrom memory secondPermit =
      _permitBatch([address(tokenA)].toMemoryArray(), [uint256(3 ether)].toMemoryArray(), 1);

    bytes memory firstSig = _anySolverSig(firstPermit, _targetsA(), _noErc721Transfers(), vps);
    bytes memory secondSig = _anySolverSig(secondPermit, targetsB, _noErc721Transfers(), vps);

    vm.prank(outsider);
    hub.permit2TransferAndFulfill(
      firstPermit,
      _targetsA(),
      _noErc721Params(),
      vps,
      owner,
      true,
      firstSig,
      _oneCallToRouterA(),
      ''
    );

    vm.prank(relayer);
    hub.permit2TransferAndFulfill(
      secondPermit,
      targetsB,
      _noErc721Params(),
      vps,
      owner,
      true,
      secondSig,
      _genericCallArray(_genericCall(address(routerB), 0, hex'02')),
      ''
    );

    assertEq(tokenA.balanceOf(address(routerA)), 2 ether, 'first submitter funded routerA');
    assertEq(tokenA.balanceOf(address(routerB)), 3 ether, 'second submitter funded routerB');
    assertEq(tokenA.balanceOf(owner), 0, 'owner debited by both fills');
    assertEq(permit2.nonceBitmap(owner, 0), 3, 'nonces 0 and 1 both consumed');
    assertEq(validatorA.beforeCallCount(), 2, 'each fill ran its own beforeExecution');
    assertEq(validatorA.afterCallCount(), 2, 'each fill ran its own afterExecution');
    assertEq(routerA.callAt(0).observedMsgSender, owner, 'routerA saw the token owner');
    assertEq(routerB.callAt(0).observedMsgSender, owner, 'routerB saw the token owner');
  }

  /**
   * @dev The flag is not signed, but it cannot be forged upward: a solver-bound witness names
   * `msg.sender`, so submitting it with `anySolver = true` rebuilds the `ANY_ADDRESS` digest the
   * owner never signed. The named solver on the caller-bound path is the positive control.
   */
  function test_anySolverFlagCannotBeForgedOnASolverBoundSignature() public {
    ISignatureTransfer.PermitBatchTransferFrom memory permit = _fundAndPermit(2 ether, 0);
    ValidationParams[] memory vps = _oneValidator();
    bytes memory sig = _solverSig(permit, solver, _targetsA(), _noErc721Transfers(), vps);

    vm.prank(outsider);
    vm.expectRevert(Permit2Mock.InvalidSigner.selector);
    hub.permit2TransferAndFulfill(
      permit, _targetsA(), _noErc721Params(), vps, owner, true, sig, _oneCallToRouterA(), ''
    );

    assertEq(tokenA.balanceOf(address(routerA)), 0, 'the forged flag funded nothing');
    assertEq(permit2.nonceBitmap(owner, 0), 0, 'nonce untouched by the forged submission');
    assertEq(validatorA.beforeCallCount(), 0, 'no validation ran');

    // Positive control: the same signature on the path it was actually signed for
    vm.prank(solver);
    hub.permit2TransferAndFulfill(
      permit, _targetsA(), _noErc721Params(), vps, owner, false, sig, _oneCallToRouterA(), ''
    );

    assertEq(tokenA.balanceOf(address(routerA)), 2 ether, 'the signed solver still fills');
    assertEq(permit2.nonceBitmap(owner, 0), 1, 'the accepted fill consumed the nonce');
  }

  /**
   * @dev The mirror image: an `ANY_ADDRESS` witness submitted with `anySolver = false` rebuilds
   * a digest naming the submitter, which the owner never signed. The identical signature with the
   * flag set is the positive control.
   */
  function test_anySolverFlagCannotBeDroppedOnAnAnyCallerSignature() public {
    ISignatureTransfer.PermitBatchTransferFrom memory permit = _fundAndPermit(2 ether, 0);
    ValidationParams[] memory vps = _oneValidator();
    bytes memory sig = _anySolverSig(permit, _targetsA(), _noErc721Transfers(), vps);

    vm.prank(outsider);
    vm.expectRevert(Permit2Mock.InvalidSigner.selector);
    hub.permit2TransferAndFulfill(
      permit, _targetsA(), _noErc721Params(), vps, owner, false, sig, _oneCallToRouterA(), ''
    );

    assertEq(tokenA.balanceOf(address(routerA)), 0, 'the dropped flag funded nothing');
    assertEq(permit2.nonceBitmap(owner, 0), 0, 'nonce untouched by the rejected submission');
    assertEq(validatorA.beforeCallCount(), 0, 'no validation ran');

    // Positive control: byte-identical signature, flag restored
    vm.prank(outsider);
    hub.permit2TransferAndFulfill(
      permit, _targetsA(), _noErc721Params(), vps, owner, true, sig, _oneCallToRouterA(), ''
    );

    assertEq(tokenA.balanceOf(address(routerA)), 2 ether, 'the same signature fills with the flag');
    assertEq(permit2.nonceBitmap(owner, 0), 1, 'the accepted fill consumed the nonce');
  }

  /**
   * @dev Opening the fill to any caller does not loosen the rest of the witness: the ERC20 targets,
   * the ERC721 movements and every `validationParams` field stay pinned.
   */
  function test_anySolverStillBindsTargetsErc721TransfersAndValidationParams() public {
    ISignatureTransfer.PermitBatchTransferFrom memory permit = _fundAndPermit(2 ether, 0);
    nft.mint(owner, 7);
    nft.mint(owner, 8);
    vm.prank(owner);
    nft.setApprovalForAll(address(hub), true);

    ValidationParams[] memory vps = _oneValidator();
    ERC721Params[] memory erc721Params =
      _erc721ParamsArray(_erc721Params(address(nft), 7, address(nftReceiver), ''));
    bytes memory sig = _anySolverSig(permit, _targetsA(), _toErc721Transfers(erc721Params), vps);

    // Redirected ERC20 funding
    vm.prank(outsider);
    vm.expectRevert(Permit2Mock.InvalidSigner.selector);
    hub.permit2TransferAndFulfill(
      permit,
      [address(routerB)].toMemoryArray(),
      erc721Params,
      vps,
      owner,
      true,
      sig,
      _oneCallToRouterA(),
      ''
    );

    // Different ERC721 tokenId
    vm.prank(outsider);
    vm.expectRevert(Permit2Mock.InvalidSigner.selector);
    hub.permit2TransferAndFulfill(
      permit,
      _targetsA(),
      _erc721ParamsArray(_erc721Params(address(nft), 8, address(nftReceiver), '')),
      vps,
      owner,
      true,
      sig,
      _oneCallToRouterA(),
      ''
    );

    // Substituted validator
    vm.prank(outsider);
    vm.expectRevert(Permit2Mock.InvalidSigner.selector);
    hub.permit2TransferAndFulfill(
      permit,
      _targetsA(),
      erc721Params,
      _validationParamsArray(_validationParams(address(validatorB), ACTION_A, hex'b0', hex'a0')),
      owner,
      true,
      sig,
      _oneCallToRouterA(),
      ''
    );

    assertEq(tokenA.balanceOf(address(routerB)), 0, 'redirected ERC20 target never funded');
    assertEq(nft.ownerOf(7), owner, 'token 7 never moved');
    assertEq(nft.ownerOf(8), owner, 'token 8 never moved');
    assertEq(permit2.nonceBitmap(owner, 0), 0, 'no rejection consumed the nonce');
    assertEq(validatorB.beforeCallCount(), 0, 'the substitute validator never ran');

    // Positive control: the signed shape, same anonymous caller
    vm.prank(outsider);
    hub.permit2TransferAndFulfill(
      permit, _targetsA(), erc721Params, vps, owner, true, sig, _oneCallToRouterA(), ''
    );

    assertEq(tokenA.balanceOf(address(routerA)), 2 ether, 'signed ERC20 target funded');
    assertEq(nft.ownerOf(7), address(nftReceiver), 'signed ERC721 movement performed');
    assertEq(validatorA.afterCallCount(), 1, 'the signed validator judged the fill');
    assertEq(permit2.nonceBitmap(owner, 0), 1, 'the accepted fill consumed the nonce');
  }

  /**
   * @dev The documented worst case: `anySolver` plus an empty `validationParams`. An arbitrary
   * caller takes the owner funding, routes it through whitelisted calls of its own choosing, and
   * nothing checks the outcome. Pinned so a reviewer can see exactly what the combination allows.
   */
  function test_anySolverWithEmptyValidationParams_isCompletelyUnconstrained() public {
    ISignatureTransfer.PermitBatchTransferFrom memory permit = _fundAndPermit(2 ether, 0);
    ValidationParams[] memory vps = _noValidationParams();
    bytes memory sig = _anySolverSig(permit, _targetsA(), _noErc721Transfers(), vps);

    GenericCall[] memory callerChosen = _genericCallArray(
      _genericCall(address(routerB), 0, hex'01'), _genericCall(address(routerA), 0, hex'02')
    );

    vm.prank(outsider);
    (bytes[] memory results,) = hub.permit2TransferAndFulfill(
      permit, _targetsA(), _noErc721Params(), vps, owner, true, sig, callerChosen, ''
    );

    assertEq(results.length, 2, 'both caller-chosen calls executed');
    assertEq(tokenA.balanceOf(owner), 0, 'owner paid in full');
    assertEq(
      tokenA.balanceOf(address(routerA)), 2 ether, 'funding left the owner on a stranger request'
    );
    assertEq(validatorA.beforeCallCount(), 0, 'nothing judged the outcome');
    assertEq(validatorA.afterCallCount(), 0, 'nothing judged the outcome');
    assertEq(validatorB.beforeCallCount(), 0, 'nothing judged the outcome');
    assertEq(permit2.nonceBitmap(owner, 0), 1, 'nonce consumed');

    string[] memory expected = new string[](2);
    expected[0] = 'routerB';
    expected[1] = 'routerA';
    _assertSequence(expected);
  }

  /**
   * @dev AnySolver widens who may submit, not how often. The Permit2 nonce is still single
   * use, so a second caller replaying the same permit and signature is rejected. Nonce 260 lives in
   * word 1, bit 4, so the consumed bitmap word is `1 << 4`.
   */
  function test_anySolverFillIsNotReplayableByASecondCaller() public {
    uint256 nonce = 260;
    ISignatureTransfer.PermitBatchTransferFrom memory permit = _fundAndPermit(2 ether, nonce);
    // Funds a second fill over, so only the nonce can stop the replay
    _fundERC20(tokenA, owner, 2 ether);

    ValidationParams[] memory vps = _oneValidator();
    bytes memory sig = _anySolverSig(permit, _targetsA(), _noErc721Transfers(), vps);

    vm.prank(outsider);
    hub.permit2TransferAndFulfill(
      permit, _targetsA(), _noErc721Params(), vps, owner, true, sig, _oneCallToRouterA(), ''
    );

    assertEq(permit2.nonceBitmap(owner, nonce >> 8), 16, 'the nonce 260 bit was consumed');
    assertEq(permit2.nonceBitmap(owner, 0), 0, 'no other nonce word touched');

    vm.prank(relayer);
    vm.expectRevert(Permit2Mock.InvalidNonce.selector);
    hub.permit2TransferAndFulfill(
      permit, _targetsA(), _noErc721Params(), vps, owner, true, sig, _oneCallToRouterA(), ''
    );

    assertEq(permit2.nonceBitmap(owner, nonce >> 8), 16, 'nonce bit consumed exactly once');
    assertEq(tokenA.balanceOf(address(routerA)), 2 ether, 'the replay moved nothing more');
    assertEq(tokenA.balanceOf(owner), 2 ether, 'owner keeps the remainder the replay wanted');
    assertEq(validatorA.afterCallCount(), 1, 'the intent was judged exactly once');
  }

  /* -------------------------------------------------------------- helpers */

  /// @dev Mints, approves Permit2 and builds a single-token batch permit for `owner`
  /// @dev Signs a witness that commits to a specific `callsSigner` rather than leaving calls open
  function _solverSigWithCallsSigner(
    ISignatureTransfer.PermitBatchTransferFrom memory permit,
    address expectedSolver,
    address committedCallsSigner,
    address[] memory targets,
    ValidationParams[] memory validationParams
  ) private view returns (bytes memory) {
    bytes32 witness = SolverWitnessLibrary.hash(
      expectedSolver, committedCallsSigner, targets, _noErc721Transfers(), validationParams
    );
    return _signPermit2WithWitness(
      ownerWallet,
      permit,
      address(hub),
      witness,
      SolverWitnessLibrary.SOLVER_WITNESS_PERMIT2_TYPE_STRING
    );
  }

  /// @dev A whitelisted call the owner never authorised, used as the "solver went off-script" case
  function _oneCallToRouterB() private view returns (GenericCall[] memory) {
    return _genericCallArray(_genericCall(address(routerB), 0, hex'99999999'));
  }

  /* ------------------------------------------------- callsSigner gating */

  /**
   * @dev The permit deadline is hashed into the authorisation, so a signature made for one intent
   * cannot be lifted onto another that carries the same calls but a different validity window.
   */
  function test_callsAuthorisationIsBoundToThePermitDeadline() public {
    ISignatureTransfer.PermitBatchTransferFrom memory permit = _fundAndPermit(2 ether, 0);
    ValidationParams[] memory vps = _oneValidator();
    GenericCall[] memory calls = _oneCallToRouterA();

    bytes memory sig =
      _solverSigWithCallsSigner(permit, solver, callsSignerWallet.addr, _targetsA(), vps);

    // Same signer, same calls, but authorised against a different deadline.
    bytes memory staleSig = _signCalls(callsSignerWallet, calls, permit.deadline - 1);

    vm.expectRevert(Permit2Mock.InvalidSigner.selector);
    vm.prank(solver);
    hub.permit2TransferAndFulfill(
      permit, _targetsA(), _noErc721Params(), vps, owner, false, sig, calls, staleSig
    );

    assertEq(permit2.nonceBitmap(owner, 0), 0, 'rejected before Permit2 was reached');

    // The authorisation for this permit's own deadline is accepted.
    vm.prank(solver);
    hub.permit2TransferAndFulfill(
      permit,
      _targetsA(),
      _noErc721Params(),
      vps,
      owner,
      false,
      sig,
      calls,
      _signCalls(callsSignerWallet, calls, permit.deadline)
    );

    assertEq(tokenA.balanceOf(address(routerA)), 2 ether, 'the matching deadline was accepted');
  }

  /**
   * @dev Pins the preimage itself rather than mirroring it: a signature over a hash that omits the
   * chain id, or omits the deadline, must be rejected. If either field were dropped from the
   * production preimage, the matching signature below would start being accepted.
   */
  function test_callsAuthorisationPreimageCoversChainIdAndDeadline() public {
    ISignatureTransfer.PermitBatchTransferFrom memory permit = _fundAndPermit(2 ether, 0);
    ValidationParams[] memory vps = _oneValidator();
    GenericCall[] memory calls = _oneCallToRouterA();

    bytes memory sig =
      _solverSigWithCallsSigner(permit, solver, callsSignerWallet.addr, _targetsA(), vps);

    // Chain id omitted from the preimage.
    vm.expectRevert(Permit2Mock.InvalidSigner.selector);
    vm.prank(solver);
    hub.permit2TransferAndFulfill(
      permit,
      _targetsA(),
      _noErc721Params(),
      vps,
      owner,
      false,
      sig,
      calls,
      _signHash(callsSignerWallet.privateKey, keccak256(abi.encode(calls, permit.deadline)))
    );

    // Deadline omitted from the preimage.
    vm.expectRevert(Permit2Mock.InvalidSigner.selector);
    vm.prank(solver);
    hub.permit2TransferAndFulfill(
      permit,
      _targetsA(),
      _noErc721Params(),
      vps,
      owner,
      false,
      sig,
      calls,
      _signHash(callsSignerWallet.privateKey, keccak256(abi.encode(block.chainid, calls)))
    );

    // Nothing else omitted: the full preimage is accepted.
    vm.prank(solver);
    hub.permit2TransferAndFulfill(
      permit,
      _targetsA(),
      _noErc721Params(),
      vps,
      owner,
      false,
      sig,
      calls,
      _signHash(
        callsSignerWallet.privateKey, keccak256(abi.encode(block.chainid, calls, permit.deadline))
      )
    );

    assertEq(tokenA.balanceOf(address(routerA)), 2 ether, 'the full preimage was accepted');
  }

  /// @dev Signs a raw digest, letting a test spell out the exact preimage it wants to authorise
  function _signHash(uint256 privateKey, bytes32 digest) private pure returns (bytes memory) {
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
    return abi.encodePacked(r, s, v);
  }

  /// @dev A committed `callsSigner` lets exactly the authorised call list through
  function test_committedCallsSignerAuthorisesExactlyTheSignedCalls() public {
    ISignatureTransfer.PermitBatchTransferFrom memory permit = _fundAndPermit(2 ether, 0);
    ValidationParams[] memory vps = _oneValidator();
    GenericCall[] memory calls = _oneCallToRouterA();

    bytes memory sig =
      _solverSigWithCallsSigner(permit, solver, callsSignerWallet.addr, _targetsA(), vps);
    bytes memory callsSig = _signCalls(callsSignerWallet, calls, permit.deadline);

    vm.prank(solver);
    hub.permit2TransferAndFulfill(
      permit, _targetsA(), _noErc721Params(), vps, owner, false, sig, calls, callsSig
    );

    assertEq(tokenA.balanceOf(address(routerA)), 2 ether, 'authorised calls funded the target');
    assertEq(routerA.callCount(), 1, 'the signed call executed');
    assertEq(validatorA.afterCallCount(), 1, 'the validator still judged the fulfillment');
  }

  /// @dev Swapping the call list invalidates the calls signature, before anything moves
  function test_aTamperedCallListRecoversADifferentSignerAndIsRejected() public {
    ISignatureTransfer.PermitBatchTransferFrom memory permit = _fundAndPermit(2 ether, 0);
    ValidationParams[] memory vps = _oneValidator();

    bytes memory sig =
      _solverSigWithCallsSigner(permit, solver, callsSignerWallet.addr, _targetsA(), vps);
    bytes memory callsSig = _signCalls(callsSignerWallet, _oneCallToRouterA(), permit.deadline);

    vm.expectRevert(Permit2Mock.InvalidSigner.selector);
    vm.prank(solver);
    hub.permit2TransferAndFulfill(
      permit, _targetsA(), _noErc721Params(), vps, owner, false, sig, _oneCallToRouterB(), callsSig
    );

    assertEq(tokenA.balanceOf(owner), 2 ether, 'owner untouched');
    assertEq(permit2.nonceBitmap(owner, 0), 0, 'rejected before Permit2 was reached');
    assertEq(routerB.callCount(), 0, 'no call executed');
  }

  /// @dev Only the committed signer counts; another wallet's signature over the same calls fails
  function test_callsSignatureFromAnotherWalletIsRejected() public {
    ISignatureTransfer.PermitBatchTransferFrom memory permit = _fundAndPermit(2 ether, 0);
    ValidationParams[] memory vps = _oneValidator();
    GenericCall[] memory calls = _oneCallToRouterA();

    bytes memory sig =
      _solverSigWithCallsSigner(permit, solver, callsSignerWallet.addr, _targetsA(), vps);

    vm.expectRevert(Permit2Mock.InvalidSigner.selector);
    vm.prank(solver);
    hub.permit2TransferAndFulfill(
      permit,
      _targetsA(),
      _noErc721Params(),
      vps,
      owner,
      false,
      sig,
      calls,
      _signCalls(otherWallet, calls, permit.deadline)
    );

    assertEq(permit2.nonceBitmap(owner, 0), 0, 'nonce untouched');
  }

  /**
   * @dev The gate cannot be sidestepped by claiming the calls are unconstrained. `callsSigner` is
   * part of the owner's witness, so downgrading it to `ANY_ADDRESS` rebuilds a digest the owner
   * never signed. Both directions are pinned.
   */
  function test_callsSignerCommitmentHoldsInBothDirections() public {
    ISignatureTransfer.PermitBatchTransferFrom memory permit = _fundAndPermit(2 ether, 0);
    ValidationParams[] memory vps = _oneValidator();

    // Owner committed to a real signer; the solver omits the signature to claim the calls
    // were left open, which recovers ANY_ADDRESS and no longer matches the witness.
    bytes memory committedSig =
      _solverSigWithCallsSigner(permit, solver, callsSignerWallet.addr, _targetsA(), vps);

    vm.expectRevert(Permit2Mock.InvalidSigner.selector);
    vm.prank(solver);
    hub.permit2TransferAndFulfill(
      permit,
      _targetsA(),
      _noErc721Params(),
      vps,
      owner,
      false,
      committedSig,
      _oneCallToRouterB(),
      ''
    );

    // And the converse: an open witness cannot be presented as if a signer had vouched for it.
    bytes memory openSig = _solverSigWithCallsSigner(permit, solver, ANY_ADDRESS, _targetsA(), vps);
    GenericCall[] memory calls = _oneCallToRouterA();

    vm.expectRevert(Permit2Mock.InvalidSigner.selector);
    vm.prank(solver);
    hub.permit2TransferAndFulfill(
      permit,
      _targetsA(),
      _noErc721Params(),
      vps,
      owner,
      false,
      openSig,
      calls,
      _signCalls(callsSignerWallet, calls, permit.deadline)
    );

    assertEq(permit2.nonceBitmap(owner, 0), 0, 'neither attempt consumed the nonce');
    assertEq(tokenA.balanceOf(owner), 2 ether, 'owner untouched throughout');
  }

  /**
   * @dev The combination that makes anySolver fulfilment safe: ANY_ADDRESS may submit, but only
   * with a call list the committed signer authorised.
   */
  function test_anySolverFulfilmentStillObeysTheCommittedCallsSigner() public {
    ISignatureTransfer.PermitBatchTransferFrom memory permit = _fundAndPermit(2 ether, 0);
    ValidationParams[] memory vps = _oneValidator();
    GenericCall[] memory calls = _oneCallToRouterA();

    bytes memory sig =
      _solverSigWithCallsSigner(permit, ANY_ADDRESS, callsSignerWallet.addr, _targetsA(), vps);

    // An address named nowhere in the signature cannot substitute its own calls.
    vm.expectRevert(Permit2Mock.InvalidSigner.selector);
    vm.prank(outsider);
    hub.permit2TransferAndFulfill(
      permit,
      _targetsA(),
      _noErc721Params(),
      vps,
      owner,
      true,
      sig,
      _oneCallToRouterB(),
      _signCalls(callsSignerWallet, calls, permit.deadline)
    );

    // The same anonymous submitter succeeds with the authorised list.
    vm.prank(outsider);
    hub.permit2TransferAndFulfill(
      permit,
      _targetsA(),
      _noErc721Params(),
      vps,
      owner,
      true,
      sig,
      calls,
      _signCalls(callsSignerWallet, calls, permit.deadline)
    );

    assertEq(tokenA.balanceOf(address(routerA)), 2 ether, 'anonymous submitter filled it');
    assertEq(routerB.callCount(), 0, 'the unauthorised route never ran');
    assertEq(routerA.callAt(0).observedMsgSender, owner, 'router still sees the token owner');
  }

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
      expectedSolver, ANY_ADDRESS, targets, erc721Transfers, validationParams
    );
    return _signPermit2WithWitness(
      ownerWallet,
      permit,
      address(hub),
      witness,
      SolverWitnessLibrary.SOLVER_WITNESS_PERMIT2_TYPE_STRING
    );
  }

  /**
   * @dev Signs the same witness with `ANY_ADDRESS` in the solver slot, which is what the hub rebuilds
   * when it is called with `anySolver = true`. Read from the hub so the sentinel is never
   * hardcoded here.
   */
  function _anySolverSig(
    ISignatureTransfer.PermitBatchTransferFrom memory permit,
    address[] memory targets,
    ERC721Transfer[] memory erc721Transfers,
    ValidationParams[] memory validationParams
  ) private view returns (bytes memory) {
    return _solverSig(permit, ANY_ADDRESS, targets, erc721Transfers, validationParams);
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
    (results,) = hub.permit2TransferAndFulfill(
      permit, targets, erc721Params, validationParams, owner, false, sig, genericCalls, ''
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
      hub.permit2TransferAndFulfill,
      (
        permit,
        new address[](0),
        _noErc721Params(),
        _noValidationParams(),
        address(1),
        false,
        '',
        _noGenericCalls(),
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
