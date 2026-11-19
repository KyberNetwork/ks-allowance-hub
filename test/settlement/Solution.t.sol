// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Vm} from 'forge-std/Vm.sol';

import {SchemaHash} from 'test/base/SchemaHash.sol';

import {EchoCalleeMock} from 'test/mocks/CalleeMocks.sol';
import {ERC20Mock} from 'test/mocks/TokenMocks.sol';

import {SettlementBase} from 'test/settlement/base/SettlementBase.sol';

import {IKSAllowanceHubV2} from 'src/interfaces/IKSAllowanceHubV2.sol';

import {AHV2Order} from 'src/types/AHV2Order.sol';
import {AHV2Solution} from 'src/types/AHV2Solution.sol';
import {CallParams} from 'src/types/CallParams.sol';
import {ERC20Allowance} from 'src/types/ERC20Allowance.sol';
import {ERC20Transfer} from 'src/types/ERC20Transfer.sol';
import {ERC721Approval} from 'src/types/ERC721Approval.sol';
import {ERC721Transfer} from 'src/types/ERC721Transfer.sol';
import {HookParams} from 'src/types/HookParams.sol';
import {NativeTransfer} from 'src/types/NativeTransfer.sol';

import {ICommon} from 'ks-common-sc/src/interfaces/ICommon.sol';
import {IERC20} from 'openzeppelin-contracts/contracts/token/ERC20/IERC20.sol';

/**
 * @title SolutionTest
 * @notice `TGT-01..04` with `LEN-01..02`, `APR-01`, `AMT-01..05` with `AMT-FUZZ`, and `SD-01..04` — what the solver specifies in
 * the solution
 * @dev The order specifies only what may leave the owner; the solution specifies one target per
 * transfer, one amount per ERC20 transfer and the `solverData` entry of each call. Every
 * target case sends the transfers somewhere no order signed: `solverWallet` for an ERC20 transfer
 * and `nftRecipient` for the NFT, neither of them a callee.
 */
contract SolutionTest is SettlementBase {
  uint160 internal constant AMOUNT = 5 ether;

  /// @dev Written out rather than imported: a role read from the hub would agree with a wrong one
  bytes32 internal constant CALLEE_ROLE = keccak256('WHITELISTED_CALLEE_ROLE');

  address internal approver;
  uint256 internal approverKey;
  address internal solverWallet;
  address internal nftRecipient;

  function setUp() public override {
    super.setUp();
    (approver, approverKey) = makeAddrAndKey('solution approver');
    solverWallet = makeAddr('solver wallet');
    nftRecipient = makeAddr('nft recipient');
  }

  // -------------------------------------------------------------------------------------------
  // TGT-01..04 — the solver's targets receive the transfers, on every pull branch
  // -------------------------------------------------------------------------------------------

  /**
   * TGT-01 / LEN-01 — delegated entry point: mismatched target counts revert, matching counts
   * settle
   * @dev First the four solutions without exactly one target per transfer — 0 or 2 ERC20 targets,
   * then 0 or 2 NFT targets — are each refused, moving nothing; then the solution with one each
   * settles, so the refusals were about the counts.
   */
  function test_TGT_01_solverChoosesTheTargetsOnTheDelegatedEntryPoint() public {
    AHV2Order memory order = _bothTransfers(ANY, 0);
    uint256 ownerBefore = _balance(owner);
    uint256 calleeBefore = _balance(address(callee));

    for (uint256 i = 0; i < 4; i++) {
      vm.prank(owner);
      vm.expectRevert(ICommon.MismatchedArrayLengths.selector);
      hub.settleOrder(order, '', _mismatched(i), '', false);
    }
    assertEq(_balance(owner), ownerBefore, 'no refused solution moved the ERC20');
    assertEq(nft.ownerOf(NFT_ID), owner, 'or the NFT');

    vm.prank(owner);
    hub.settleOrder(order, '', _toSolverAndRecipient(), '', false);

    _assertLanded(ownerBefore);
    assertEq(_balance(address(callee)), calleeBefore, 'no callee received the transfer');
  }

  /// TGT-02 — on the delegated entry point, a Permit2 allowance pull pays the targets the solution
  /// names
  function test_TGT_02_solverTargetsOnThePermit2AllowancePull() public {
    _grantPermit2Allowance(token18, AMOUNT);
    AHV2Order memory order = _bothTransfers(ANY, 0);
    uint256 ownerBefore = _balance(owner);

    vm.prank(owner);
    hub.settleOrder(order, '', _toSolverAndRecipient(), '', true);

    _assertLanded(ownerBefore);
    assertEq(_permit2Allowance(token18), 0, 'the Permit2 allowance paid for the transfer');
  }

  /**
   * TGT-03 / LEN-02 — over Permit2, one witness accepts any ERC20 targets; wrong counts revert
   * @dev The four solutions without exactly one target per transfer are refused first, ahead of the
   * permit. Then one witness signature settles the order once with the transfers sent one way and,
   * from the same pre-state, once with them sent another, so nothing the owner signed specifies a
   * target.
   */
  function test_TGT_03_witnessDoesNotBindTheErc20Targets() public {
    AHV2Order memory order = _bothTransfers(ANY, 1);
    order.authenticator = permit2;
    bytes memory witness = _signWitness(order);
    uint256 ownerBefore = _balance(owner);

    for (uint256 i = 0; i < 4; i++) {
      vm.prank(solver);
      vm.expectRevert(ICommon.MismatchedArrayLengths.selector);
      hub.settleOrder(order, witness, _mismatched(i), '', false);
    }
    assertEq(_balance(owner), ownerBefore, 'no refused solution moved the ERC20');
    assertEq(nft.ownerOf(NFT_ID), owner, 'or the NFT');

    uint256 snapshot = vm.snapshotState();

    vm.prank(solver);
    hub.settleOrder(order, witness, _toSolverAndRecipient(), '', false);
    _assertLanded(ownerBefore);

    vm.revertToState(snapshot);

    vm.prank(solver);
    hub.settleOrder(
      order,
      witness,
      _solution(
        _addresses(address(callee2)),
        _amounts(AMOUNT),
        _addresses(solverWallet),
        vm.getBlockTimestamp() + 1 hours
      ),
      '',
      false
    );
    assertEq(_balance(address(callee2)), AMOUNT, 'the same witness, another ERC20 target');
    assertEq(nft.ownerOf(NFT_ID), solverWallet, 'and another NFT target');
  }

  /// TGT-04 — the owner submits over Permit2 with a plain permit, and still picks the targets
  function test_TGT_04_ownerSubmitsWithTargetsOfTheirChoice() public {
    AHV2Order memory order = _bothTransfers(ANY, 2);
    order.authenticator = permit2;
    bytes memory permit = _signPlainPermit(order.erc20Allowances, 2, order.expiration);
    uint256 ownerBefore = _balance(owner);

    vm.prank(owner);
    hub.settleOrder(order, permit, _toSolverAndRecipient(), '', false);

    _assertLanded(ownerBefore);
  }

  // -------------------------------------------------------------------------------------------
  // APR-01 — the approver signs the targets
  // -------------------------------------------------------------------------------------------

  /**
   * APR-01 — an approval of one set of targets does not approve another
   * @dev The two solutions differ only in where the transfers go, so the
   * refusal is about the targets. The second step is the control.
   */
  function test_APR_01_theApprovalBindsTheTargets() public {
    AHV2Order memory order = _bothTransfers(approver, 0);
    order.authenticator = address(authenticator);
    AHV2Solution memory toCallees = _solution(
      _addresses(address(callee)),
      _amounts(AMOUNT),
      _addresses(address(callee2)),
      vm.getBlockTimestamp() + 1 hours
    );
    AHV2Solution memory toSolver = _toSolverAndRecipient();
    bytes memory calleesApproval = _signSolutionApproval(approverKey, order, toCallees);
    uint256 ownerBefore = _balance(owner);

    // The refused attempt reverts, so the solution nonce it carries stays unspent for the valid one
    bytes memory auth = _authOf(order);
    vm.prank(relayer);
    vm.expectRevert(IKSAllowanceHubV2.InvalidSolutionSignature.selector);
    hub.settleOrder(order, auth, toSolver, calleesApproval, false);

    bytes memory solverApproval = _signSolutionApproval(approverKey, order, toSolver);
    vm.prank(relayer);
    hub.settleOrder(order, auth, toSolver, solverApproval, false);
    _assertLanded(ownerBefore);
  }

  // -------------------------------------------------------------------------------------------
  // AMT-01..05 — the solver chooses how much each transfer moves, up to its allowance
  // -------------------------------------------------------------------------------------------

  /**
   * AMT-01 — an amount below the allowance moves exactly that amount, on each pull branch
   * @dev The branches are the hub's allowance, the owner's Permit2 allowance and a Permit2
   * signature. On each, the owner and the target change by the chosen amount, and the event lists
   * it. On the Permit2 allowance branch, the allowance falls by it.
   */
  function test_AMT_01_amountBelowTheAllowanceMovesExactlyThatAmount() public {
    uint160 chosen = 2 ether;

    for (uint8 path = 0; path < 3; path++) {
      AHV2Order memory order = _amountOrder(AMOUNT, 1);
      AHV2Solution memory solution = _amountSolution(chosen);
      bytes memory permit = _preparePath(path, order);
      uint256 ownerBefore = _balance(owner);
      uint256 targetBefore = _balance(solverWallet);
      uint160 permit2Before = _permit2Allowance(token18);

      vm.recordLogs();
      _submit(path, order, permit, solution);
      Vm.Log memory entry = _settlementLog();

      assertEq(ownerBefore - _balance(owner), chosen, 'the owner paid the chosen amount');
      assertEq(_balance(solverWallet) - targetBefore, chosen, 'and the target received it');
      assertEq(entry.topics[3], SchemaHash.ahv2Order(order), 'the event names the order');

      ERC20Transfer[] memory expected = new ERC20Transfer[](1);
      expected[0] = ERC20Transfer({token: token18, target: solverWallet, amount: chosen});
      assertEq(
        entry.data,
        abi.encode(expected, new ERC721Transfer[](0), new NativeTransfer[](0), bytes('')),
        'the event lists the chosen amount'
      );
      if (path == PATH_PERMIT2_ALLOWANCE) {
        assertEq(permit2Before - _permit2Allowance(token18), chosen, 'the allowance fell by it');
      }
    }
  }

  /**
   * AMT-02 — an amount equal to the allowance settles, and one above it is refused with its index
   * @dev Two transfers of different tokens. On each pull branch, the second transfer and then the
   * first transfer exceed their allowance by 1, and each is refused with the index and values of
   * that transfer. The allowances are exact on the third attempt, which settles.
   */
  function test_AMT_02_amountAboveTheAllowanceIsRefusedWithItsIndex() public {
    uint160 sixAllowance = 7e6;

    for (uint8 path = 0; path < 3; path++) {
      AHV2Order memory order = _twoTransferOrder(AMOUNT, sixAllowance, 1);
      bytes memory permit = _preparePath(path, order);

      vm.expectRevert(_exceeds(1, uint256(sixAllowance) + 1, sixAllowance));
      _submit(path, order, permit, _twoTransferSolution(AMOUNT, sixAllowance + 1));

      vm.expectRevert(_exceeds(0, uint256(AMOUNT) + 1, AMOUNT));
      _submit(path, order, permit, _twoTransferSolution(AMOUNT + 1, sixAllowance));

      uint256 ownerBefore = _balance(owner);
      uint256 sixBefore = IERC20(token6).balanceOf(solverWallet);
      _submit(path, order, permit, _twoTransferSolution(AMOUNT, sixAllowance));
      assertEq(ownerBefore - _balance(owner), AMOUNT, 'the first transfer moved its allowance');
      assertEq(IERC20(token6).balanceOf(solverWallet) - sixBefore, sixAllowance, 'and the second');
    }
  }

  /// AMT-03 — an amount of 0 settles and moves nothing on its transfer
  function test_AMT_03_amountZeroMovesNothingOnItsTransfer() public {
    uint160 sixAllowance = 7e6;
    AHV2Order memory order = _twoTransferOrder(AMOUNT, sixAllowance, 1);
    uint256 ownerBefore = _balance(owner);
    uint256 targetBefore = _balance(solverWallet);
    uint256 sixBefore = IERC20(token6).balanceOf(solverWallet);

    vm.recordLogs();
    _submit(PATH_HUB, order, '', _twoTransferSolution(0, sixAllowance));
    Vm.Log memory entry = _settlementLog();

    assertEq(_balance(owner), ownerBefore, 'the first transfer left the owner untouched');
    assertEq(_balance(solverWallet), targetBefore, 'and its target');
    assertEq(IERC20(token6).balanceOf(solverWallet) - sixBefore, sixAllowance, 'the second moved');

    ERC20Transfer[] memory expected = new ERC20Transfer[](2);
    expected[0] = ERC20Transfer({token: token18, target: solverWallet, amount: 0});
    expected[1] = ERC20Transfer({token: token6, target: solverWallet, amount: sixAllowance});
    assertEq(
      entry.data,
      abi.encode(expected, new ERC721Transfer[](0), new NativeTransfer[](0), bytes('')),
      'the event lists the zero amount'
    );
  }

  /**
   * AMT-04 — amounts of a length other than the transfers are refused on both entry points
   * @dev The targets are right and the amounts are one short, then one long. A solution with
   * the right length settles afterwards.
   */
  function test_AMT_04_amountsOfTheWrongLengthAreRefused() public {
    uint160 sixAllowance = 7e6;
    AHV2Order memory order = _twoTransferOrder(AMOUNT, sixAllowance, 1);
    AHV2Order memory permitOrder = _twoTransferOrder(AMOUNT, sixAllowance, 1);
    bytes memory permit = _preparePath(PATH_PERMIT2_SIGNATURE, permitOrder);

    for (uint256 length = 1; length <= 3; length += 2) {
      AHV2Solution memory solution = _twoTransferSolution(AMOUNT, sixAllowance);
      solution.erc20Amounts = new uint160[](length);

      vm.prank(owner);
      vm.expectRevert(ICommon.MismatchedArrayLengths.selector);
      hub.settleOrder(order, '', solution, '', false);

      vm.prank(solver);
      vm.expectRevert(ICommon.MismatchedArrayLengths.selector);
      hub.settleOrder(permitOrder, permit, solution, '', false);
    }

    uint256 ownerBefore = _balance(owner);
    _submit(PATH_HUB, order, '', _twoTransferSolution(AMOUNT, sixAllowance));
    assertEq(ownerBefore - _balance(owner), AMOUNT, 'amounts of the right length settle');
  }

  /**
   * AMT-05 — an approval signed for amounts of 5 ether is refused for a solution with 2 ether
   * @dev The approver signs amounts of 5 ether. The same solution with 2 ether is refused, and the
   * one it signed settles.
   */
  function test_AMT_05_theApprovalBindsTheAmounts() public {
    AHV2Order memory order = _amountOrder(AMOUNT, 1);
    order.solutionApprover = approver;
    order.authenticator = address(authenticator);
    AHV2Solution memory approved = _amountSolution(AMOUNT);
    AHV2Solution memory lower = _amountSolution(2 ether);
    bytes memory approval = _signSolutionApproval(approverKey, order, approved);

    // The refused attempt reverts, so the solution nonce it carries stays unspent for the valid one
    bytes memory auth = _authOf(order);
    vm.prank(relayer);
    vm.expectRevert(IKSAllowanceHubV2.InvalidSolutionSignature.selector);
    hub.settleOrder(order, auth, lower, approval, false);

    uint256 ownerBefore = _balance(owner);
    vm.prank(relayer);
    hub.settleOrder(order, auth, approved, approval, false);
    assertEq(ownerBefore - _balance(owner), AMOUNT, 'the approved amounts settle');
  }

  // -------------------------------------------------------------------------------------------
  // AMT-FUZZ
  // -------------------------------------------------------------------------------------------

  /// @dev The fields {testFuzz_AMT_FUZZ_solverAmount} draws, one parameter struct for the family
  struct AmountFuzz {
    uint160 allowance;
    uint160 amount;
    uint8 path;
  }

  /**
   * AMT-FUZZ — the solver's amount moves exactly, or is refused above the allowance
   * @dev The allowance ranges over [1, 1e30] and the amount over [0, 2 * allowance], on every pull
   * branch. An amount up to the allowance moves exactly that amount. Any other amount is refused
   * with the index of the transfer, the amount and the allowance, and moves nothing.
   */
  function testFuzz_AMT_FUZZ_solverAmount(AmountFuzz memory f) public {
    f.allowance = uint160(bound(f.allowance, 1, 1e30));
    f.amount = uint160(bound(f.amount, 0, 2 * uint256(f.allowance)));
    uint8 path = uint8(bound(f.path, 0, 2));
    ERC20Mock(token18).mint(owner, 2 * uint256(f.allowance));

    AHV2Order memory order = _amountOrder(f.allowance, 1);
    bytes memory permit = _preparePath(path, order);
    uint256 ownerBefore = _balance(owner);
    uint256 targetBefore = _balance(solverWallet);

    if (f.amount > f.allowance) {
      vm.expectRevert(_exceeds(0, f.amount, f.allowance));
    }
    _submit(path, order, permit, _amountSolution(f.amount));

    uint256 moved = f.amount > f.allowance ? 0 : f.amount;
    assertEq(ownerBefore - _balance(owner), moved, 'the owner paid exactly the moved amount');
    assertEq(_balance(solverWallet) - targetBefore, moved, 'and the target received it');
  }

  // -------------------------------------------------------------------------------------------
  // SD — the solver data
  // -------------------------------------------------------------------------------------------

  /**
   * SD-01 — each call receives the `solverData` entry of its own index
   * @dev Three calls go to three callees that echo what they receive, and the entries are
   * distinct, one of them empty, so a shifted or reused entry would show in the results.
   */
  function test_SD_01_eachCallReceivesItsOwnSolverData() public {
    EchoCalleeMock[3] memory echoes =
      [new EchoCalleeMock(), new EchoCalleeMock(), new EchoCalleeMock()];
    bytes[3] memory solverEntries = [bytes(hex'5a'), bytes(''), bytes(hex'5c5c')];

    CallParams[] memory calls = new CallParams[](3);
    vm.startPrank(admin);
    for (uint256 i = 0; i < 3; i++) {
      hub.grantRole(CALLEE_ROLE, address(echoes[i]));
      calls[i] =
        CallParams({callee: address(echoes[i]), value: 0, data: abi.encodePacked(uint8(i + 1))});
    }
    vm.stopPrank();

    AHV2Order memory order =
      _openAhv2Order(new ERC20Allowance[](0), _noHooks(), calls, 0, vm.getBlockTimestamp());
    AHV2Solution memory solution = _defaultSolution(order);
    for (uint256 i = 0; i < 3; i++) {
      solution.solverData[i] = solverEntries[i];
    }

    vm.prank(owner);
    bytes[] memory results = hub.settleOrder(order, '', solution, '', false);

    assertEq(results.length, 3, 'one result per call');
    for (uint256 i = 0; i < 3; i++) {
      (address seenCallee, bytes memory seenData, bytes memory seenSolverData) =
        abi.decode(results[i], (address, bytes, bytes));
      assertEq(seenCallee, address(echoes[i]), 'the result came from the callee of that index');
      assertEq(seenData, calls[i].data, 'with the data of its own call');
      assertEq(seenSolverData, solverEntries[i], 'and the solver data of its own index');
    }
  }

  /**
   * SD-02 — a `solverData` list of the wrong length is refused on both entry points
   * @dev The order has two calls. Lengths 0, 1 and 3 are refused with nothing moved, and
   * length 2 settles.
   */
  function test_SD_02_solverDataLengthMustMatchTheCalls() public {
    CallParams[] memory calls = _calls(_calleeCall(0, hex'01'), _calleeCall(0, hex'02'));
    uint256 expiration = vm.getBlockTimestamp() + 1 hours;

    AHV2Order memory delegated =
      _openAhv2Order(_allowances(_tokenAllowance(AMOUNT)), _noHooks(), calls, 0, expiration);
    AHV2Order memory relayed =
      _openAhv2Order(_allowances(_tokenAllowance(AMOUNT)), _noHooks(), calls, 110, expiration);
    relayed.authenticator = permit2;
    bytes memory witness = _signWitness(relayed);

    AHV2Solution memory delegatedSolution = _defaultSolution(delegated);
    AHV2Solution memory relayedSolution = _defaultSolution(relayed);
    uint256 before = _calleeBalance();

    uint256[3] memory wrongLengths = [uint256(0), 1, 3];
    for (uint256 i = 0; i < wrongLengths.length; i++) {
      delegatedSolution.solverData = _solverData(wrongLengths[i]);
      relayedSolution.solverData = _solverData(wrongLengths[i]);

      vm.prank(owner);
      vm.expectRevert(ICommon.MismatchedArrayLengths.selector);
      hub.settleOrder(delegated, '', delegatedSolution, '', false);

      vm.prank(relayer);
      vm.expectRevert(ICommon.MismatchedArrayLengths.selector);
      hub.settleOrder(relayed, witness, relayedSolution, '', false);

      assertEq(_calleeBalance(), before, 'a refused order moved nothing');
      assertEq(callee.callCount(), 0, 'and ran no call');
    }

    delegatedSolution.solverData = _solverData(2);
    relayedSolution.solverData = _solverData(2);

    vm.prank(owner);
    hub.settleOrder(delegated, '', delegatedSolution, '', false);
    vm.prank(relayer);
    hub.settleOrder(relayed, witness, relayedSolution, '', false);

    assertEq(_calleeBalance() - before, 2 * AMOUNT, 'a list of the right length settles');
    assertEq(callee.callCount(), 4, 'and runs both calls of both orders');
  }

  /**
   * SD-03 — the solution approval binds `solverData`
   * @dev An approval of the entry `hex'aa'` presented with the entry `hex'bb'` is refused, and the
   * same approval presented with the entry it signed settles.
   */
  function test_SD_03_theSolutionApprovalBindsSolverData() public {
    uint256 expiration = vm.getBlockTimestamp() + 1 hours;
    AHV2Order memory order = _ahv2Order(
      address(authenticator),
      ANY,
      new ERC20Allowance[](0),
      _noNfts(),
      _noHooks(),
      _calls(_calleeCall(0, hex'01')),
      approver,
      0,
      expiration
    );

    AHV2Solution memory approved = _defaultSolution(order);
    approved.solverData[0] = hex'aa';
    AHV2Solution memory presented = _defaultSolution(order);
    presented.solverData[0] = hex'bb';

    bytes memory approval = _signSolutionApproval(approverKey, order, approved);
    bytes memory auth = _authOf(order);

    vm.prank(relayer);
    vm.expectRevert(IKSAllowanceHubV2.InvalidSolutionSignature.selector);
    hub.settleOrder(order, auth, presented, approval, false);
    assertEq(callee.callCount(), 0, 'the refused order ran nothing');

    vm.prank(relayer);
    hub.settleOrder(order, auth, approved, approval, false);
    assertEq(callee.lastSolverData(), hex'aa', 'the control settled with the approved entry');
  }

  /**
   * SD-04 — the owner's signature does not bind `solverData`
   * @dev With the sentinel approver, one witness settles with either of two lists. Each run starts
   * from the same snapshot, so the second is not a replay of the first.
   */
  function test_SD_04_theOwnersSignatureDoesNotBindSolverData() public {
    AHV2Order memory order = _openAhv2Order(
      new ERC20Allowance[](0),
      _noHooks(),
      _calls(_calleeCall(0, hex'01')),
      111,
      vm.getBlockTimestamp() + 1 hours
    );
    order.authenticator = permit2;
    bytes memory witness = _signWitness(order);

    AHV2Solution memory solutionA = _defaultSolution(order);
    solutionA.solverData[0] = hex'aa';
    AHV2Solution memory solutionB = _defaultSolution(order);
    solutionB.solverData[0] = hex'bb';

    uint256 snapshot = vm.snapshotState();

    vm.prank(solver);
    hub.settleOrder(order, witness, solutionA, '', false);
    assertEq(callee.lastSolverData(), hex'aa', 'the witness settled with the first list');

    vm.revertToState(snapshot);

    vm.prank(solver);
    hub.settleOrder(order, witness, solutionB, '', false);
    assertEq(callee.lastSolverData(), hex'bb', 'and with the second');
  }

  // -------------------------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------------------------

  /// @dev Pull branches of the settlement: the hub's allowance, the owner's Permit2 allowance and
  /// a Permit2 signature
  uint8 private constant PATH_HUB = 0;
  uint8 private constant PATH_PERMIT2_ALLOWANCE = 1;
  uint8 private constant PATH_PERMIT2_SIGNATURE = 2;

  /// @dev One ERC20 transfer of `AMOUNT` and the NFT, open to any submitter, with no calls
  function _bothTransfers(address solutionApprover, uint256 nonce)
    private
    view
    returns (AHV2Order memory)
  {
    return _ahv2Order(
      ANY,
      _allowances(_tokenAllowance(AMOUNT)),
      _approvals(_nftApproval()),
      new HookParams[](0),
      new CallParams[](0),
      solutionApprover,
      nonce,
      vm.getBlockTimestamp() + 1 hours
    );
  }

  /// @dev The ERC20 transfer to `solverWallet` and the NFT to `nftRecipient`
  function _toSolverAndRecipient() private view returns (AHV2Solution memory) {
    return _solution(
      _addresses(solverWallet),
      _amounts(AMOUNT),
      _addresses(nftRecipient),
      vm.getBlockTimestamp() + 1 hours
    );
  }

  /**
   * @dev For the one-ERC20, one-NFT order of {_bothTransfers}: partition `i` gives 0 or 2 ERC20
   * targets (i = 0, 1) or 0 or 2 NFT targets (i = 2, 3), with the other array right
   */
  function _mismatched(uint256 i) private view returns (AHV2Solution memory) {
    address[] memory none = new address[](0);
    address[] memory two = new address[](2);
    two[0] = solverWallet;
    two[1] = nftRecipient;
    address[] memory one = _addresses(solverWallet);
    address[] memory nftOne = _addresses(nftRecipient);

    address[] memory erc20Targets = i == 0 ? none : i == 1 ? two : one;
    address[] memory erc721Targets = i == 2 ? none : i == 3 ? two : nftOne;
    return
      _solution(erc20Targets, _amounts(AMOUNT), erc721Targets, vm.getBlockTimestamp() + 1 hours);
  }

  /// @dev One ERC20 transfer of `allowance`, open to any submitter
  function _amountOrder(uint160 allowance, uint256 nonce) private view returns (AHV2Order memory) {
    return _ahv2Order(
      ANY,
      _allowances(_tokenAllowance(allowance)),
      new ERC721Approval[](0),
      new HookParams[](0),
      new CallParams[](0),
      ANY,
      nonce,
      vm.getBlockTimestamp() + 1 hours
    );
  }

  /// @dev Two ERC20 transfers, of token18 and token6, open to any submitter
  function _twoTransferOrder(uint160 allowance18, uint160 allowance6, uint256 nonce)
    private
    view
    returns (AHV2Order memory)
  {
    ERC20Allowance[] memory allowances = new ERC20Allowance[](2);
    allowances[0] = _tokenAllowance(allowance18);
    allowances[1] = ERC20Allowance({token: token6, amount: allowance6});
    return _ahv2Order(
      ANY,
      allowances,
      new ERC721Approval[](0),
      new HookParams[](0),
      new CallParams[](0),
      ANY,
      nonce,
      vm.getBlockTimestamp() + 1 hours
    );
  }

  /// @dev `amount` of the one transfer to `solverWallet`
  function _amountSolution(uint160 amount) private view returns (AHV2Solution memory) {
    return _solution(
      _addresses(solverWallet), _amounts(amount), new address[](0), vm.getBlockTimestamp() + 1 hours
    );
  }

  /// @dev The amounts of the transfers of {_twoTransferOrder}, both to `solverWallet`
  function _twoTransferSolution(uint160 amount18, uint160 amount6)
    private
    view
    returns (AHV2Solution memory)
  {
    address[] memory targets = new address[](2);
    targets[0] = solverWallet;
    targets[1] = solverWallet;
    uint160[] memory amounts = new uint160[](2);
    amounts[0] = amount18;
    amounts[1] = amount6;
    return _solution(targets, amounts, new address[](0), vm.getBlockTimestamp() + 1 hours);
  }

  /**
   * @dev Prepares what `path` needs before the submission: a Permit2 allowance of twice each
   * transfer for the allowance branch, so that Permit2 does not refuse an amount first, and the
   * owner's witness signature for the signature branch, for which `order` is set to the Permit2
   * authenticator before it is signed
   */
  function _preparePath(uint8 path, AHV2Order memory order) private returns (bytes memory permit) {
    if (path == PATH_PERMIT2_ALLOWANCE) {
      for (uint256 i = 0; i < order.erc20Allowances.length; i++) {
        _grantPermit2Allowance(order.erc20Allowances[i].token, 2 * order.erc20Allowances[i].amount);
      }
    } else if (path == PATH_PERMIT2_SIGNATURE) {
      order.authenticator = permit2;
      permit = _signWitness(order);
    }
  }

  /// @dev The owner submits on the first two branches, and `solver` on the Permit2 signature
  function _submit(
    uint8 path,
    AHV2Order memory order,
    bytes memory permit,
    AHV2Solution memory solution
  ) private {
    if (path == PATH_PERMIT2_SIGNATURE) {
      vm.prank(solver);
      hub.settleOrder(order, permit, solution, '', false);
    } else {
      vm.prank(owner);
      hub.settleOrder(order, '', solution, '', path == PATH_PERMIT2_ALLOWANCE);
    }
  }

  function _exceeds(uint256 index, uint256 amount, uint256 allowance)
    private
    pure
    returns (bytes memory)
  {
    return abi.encodeWithSelector(
      IKSAllowanceHubV2.ERC20AllowanceExceeded.selector, index, amount, allowance
    );
  }

  /// @dev The ERC20 transfer left the owner for `solverWallet`, and the NFT reached `nftRecipient`
  function _assertLanded(uint256 ownerBefore) private view {
    assertEq(ownerBefore - _balance(owner), AMOUNT, 'the owner paid the transfer');
    assertEq(_balance(solverWallet), AMOUNT, "the solver's target received it");
    assertEq(nft.ownerOf(NFT_ID), nftRecipient, 'the NFT reached its target');
  }
}
