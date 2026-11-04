// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Vm} from 'forge-std/Vm.sol';

import {SchemaHash} from 'test/base/SchemaHash.sol';

import {AuthenticatorBase} from 'test/v2/authenticators/base/AuthenticatorBase.sol';

import {ERC20Mock} from 'test/v2/mocks/TokenMocks.sol';

import {AuthKey} from 'src/base/types/AuthKey.sol';
import {IKSAllowanceHubV2} from 'src/v2/interfaces/IKSAllowanceHubV2.sol';
import {ERC20Allowance, ERC20AllowanceLib} from 'src/v2/types/ERC20Allowance.sol';
import {ERC20Transfer} from 'src/v2/types/ERC20Transfer.sol';
import {ERC721Approval} from 'src/v2/types/ERC721Approval.sol';
import {ERC721Transfer} from 'src/v2/types/ERC721Transfer.sol';
import {FulfillmentOrder} from 'src/v2/types/FulfillmentOrder.sol';
import {FulfillmentSolution} from 'src/v2/types/FulfillmentSolution.sol';
import {GenericCall} from 'src/v2/types/GenericCall.sol';
import {NativeTransfer} from 'src/v2/types/NativeTransfer.sol';
import {ValidationParams} from 'src/v2/types/ValidationParams.sol';

import {ICommon} from 'ks-common-sc/src/interfaces/ICommon.sol';

import {IERC20} from 'openzeppelin-contracts/contracts/token/ERC20/IERC20.sol';

/**
 * @notice `TGT-01..04` with `LEN-01..02`, `APR-01` and `EVT-01`, and `AMT-01..05` with `AMT-FUZZ`:
 * the solver chooses where each transfer of a fulfillment goes, and how much each ERC20 transfer
 * moves
 * @dev The order specifies only what may leave the owner; the solution specifies one target per
 * transfer and one amount per ERC20 transfer. Every case sends the transfers somewhere no order
 * signed: `solverWallet` for an ERC20 transfer and `nftRecipient` for the NFT, neither of them a
 * router.
 */
contract FulfillTargetsTest is AuthenticatorBase {
  uint160 internal constant AMOUNT = 5 ether;

  AuthKey internal key;

  address internal approver;
  uint256 internal approverKey;
  address internal solverWallet;
  address internal nftRecipient;

  function setUp() public override {
    super.setUp();
    key = _secpKey(masterSigner, vm.getBlockTimestamp() + 30 days);
    (approver, approverKey) = makeAddrAndKey('solution approver');
    solverWallet = makeAddr('solver wallet');
    nftRecipient = makeAddr('nft recipient');
  }

  // -------------------------------------------------------------------------------------------
  // TGT-01..04 — the solver's targets receive the transfers, on every pull branch
  // -------------------------------------------------------------------------------------------

  /**
   * TGT-01 / LEN-01 — the delegated rail, submitted by the owner, pulled on the plain approval
   * @dev First the four solutions without exactly one target per transfer — 0 or 2 ERC20 targets,
   * then 0 or 2 NFT targets — are each refused, moving nothing; then the solution with one each
   * settles, so the refusals were about the counts.
   */
  function test_TGT_01_solverChoosesTheTargetsOnTheDelegatedRail() public {
    FulfillmentOrder memory order = _bothTransfers(ANY, 0);
    uint256 ownerBefore = _balance(owner);
    uint256 routerBefore = _balance(address(router));

    for (uint256 i = 0; i < 4; i++) {
      vm.prank(owner);
      vm.expectRevert(ICommon.MismatchedArrayLengths.selector);
      hub.fulfillOrderWithDelegatedAuthentication(order, address(0), '', _mismatched(i), '', false);
    }
    assertEq(_balance(owner), ownerBefore, 'no refused solution moved the ERC20');
    assertEq(nft.ownerOf(NFT_ID), owner, 'or the NFT');

    vm.prank(owner);
    hub.fulfillOrderWithDelegatedAuthentication(
      order, address(0), '', _toSolverAndRecipient(), '', false
    );

    _assertLanded(ownerBefore);
    assertEq(_balance(address(router)), routerBefore, 'no router received the transfer');
  }

  /// TGT-02 — the same, pulled through the owner's Permit2 allowance
  function test_TGT_02_solverTargetsOnThePermit2AllowancePull() public {
    _grantPermit2Allowance(token18, AMOUNT);
    FulfillmentOrder memory order = _bothTransfers(ANY, 0);
    uint256 ownerBefore = _balance(owner);

    vm.prank(owner);
    hub.fulfillOrderWithDelegatedAuthentication(
      order, address(0), '', _toSolverAndRecipient(), '', true
    );

    _assertLanded(ownerBefore);
    assertEq(_permit2Allowance(token18), 0, 'the Permit2 allowance paid for the transfer');
  }

  /**
   * TGT-03 / LEN-02 — relayed over Permit2: the owner's witness carries no ERC20 target
   * @dev The four solutions without exactly one target per transfer are refused first, ahead of the
   * permit. Then one witness signature settles the order once with the transfers sent one way and,
   * from the same pre-state, once with them sent another, so nothing the owner signed specifies a
   * target.
   */
  function test_TGT_03_witnessDoesNotBindTheErc20Targets() public {
    FulfillmentOrder memory order = _bothTransfers(ANY, 1);
    bytes memory witness = _signFulfillmentWitness(order);
    uint256 ownerBefore = _balance(owner);

    for (uint256 i = 0; i < 4; i++) {
      vm.prank(solver);
      vm.expectRevert(ICommon.MismatchedArrayLengths.selector);
      hub.fulfillOrderWithPermit2Signature(order, witness, _mismatched(i), '');
    }
    assertEq(_balance(owner), ownerBefore, 'no refused solution moved the ERC20');
    assertEq(nft.ownerOf(NFT_ID), owner, 'or the NFT');

    uint256 snapshot = vm.snapshotState();

    vm.prank(solver);
    hub.fulfillOrderWithPermit2Signature(order, witness, _toSolverAndRecipient(), '');
    _assertLanded(ownerBefore);

    vm.revertToState(snapshot);

    vm.prank(solver);
    hub.fulfillOrderWithPermit2Signature(
      order,
      witness,
      _solution(
        _addresses(address(router2)),
        _amounts(AMOUNT),
        _addresses(solverWallet),
        _calls(_routerCall(0, hex'01')),
        vm.getBlockTimestamp() + 1 hours
      ),
      ''
    );
    assertEq(_balance(address(router2)), AMOUNT, 'the same witness, another ERC20 target');
    assertEq(nft.ownerOf(NFT_ID), solverWallet, 'and another NFT target');
  }

  /// TGT-04 — the owner submits over Permit2 with a plain permit, and still picks the targets
  function test_TGT_04_ownerSubmitsWithTargetsOfTheirChoice() public {
    FulfillmentOrder memory order = _bothTransfers(ANY, 2);
    bytes memory permit = _signPlainPermit(order.erc20Allowances, 2, order.expiration);
    uint256 ownerBefore = _balance(owner);

    vm.prank(owner);
    hub.fulfillOrderWithPermit2Signature(order, permit, _toSolverAndRecipient(), '');

    _assertLanded(ownerBefore);
  }

  // -------------------------------------------------------------------------------------------
  // APR-01 — the approver signs the targets
  // -------------------------------------------------------------------------------------------

  /**
   * APR-01 — an approval of one set of targets does not approve another
   * @dev The two solutions share the route and differ only in where the transfers go, so the
   * refusal is about the targets. The second step is the control.
   */
  function test_APR_01_theApprovalBindsTheTargets() public {
    FulfillmentOrder memory order = _bothTransfers(approver, 0);
    FulfillmentSolution memory toRouters = _solution(
      _addresses(address(router)),
      _amounts(AMOUNT),
      _addresses(address(router2)),
      _calls(_routerCall(0, hex'01')),
      vm.getBlockTimestamp() + 1 hours
    );
    FulfillmentSolution memory toSolver = _toSolverAndRecipient();
    bytes memory routersApproval = _signSolutionApproval(approverKey, order, toRouters);
    uint256 ownerBefore = _balance(owner);

    vm.prank(owner);
    vm.expectRevert(IKSAllowanceHubV2.InvalidSolutionSignature.selector);
    hub.fulfillOrderWithDelegatedAuthentication(
      order, address(0), '', toSolver, routersApproval, false
    );

    bytes memory solverApproval = _signSolutionApproval(approverKey, order, toSolver);
    vm.prank(owner);
    hub.fulfillOrderWithDelegatedAuthentication(
      order, address(0), '', toSolver, solverApproval, false
    );
    _assertLanded(ownerBefore);
  }

  // -------------------------------------------------------------------------------------------
  // EVT-01 — the event pairs each transfer with its target
  // -------------------------------------------------------------------------------------------

  /**
   * EVT-01 — `TransferTokens` lists the transfers that happened, each with the solution's target
   * @dev Two ERC20 transfers of different tokens and amounts go to two different targets, so the
   * pairing cannot come out right by symmetry.
   */
  function test_EVT_01_fulfillmentEventPairsTransfersWithTargets() public {
    uint160 sixAmount = 7e6;
    ERC20Allowance[] memory allowances = new ERC20Allowance[](2);
    allowances[0] = _tokenAllowance(AMOUNT);
    allowances[1] = ERC20Allowance({token: token6, amount: sixAmount});
    FulfillmentOrder memory order = _fulfillmentOrder(
      ANY,
      allowances,
      _approvals(_nftApproval()),
      new ValidationParams[](0),
      new GenericCall[](0),
      ANY,
      0,
      vm.getBlockTimestamp() + 1 hours
    );
    address[] memory erc20Targets = new address[](2);
    erc20Targets[0] = address(router2);
    erc20Targets[1] = solverWallet;
    uint160[] memory erc20Amounts = new uint160[](2);
    erc20Amounts[0] = AMOUNT;
    erc20Amounts[1] = sixAmount;
    FulfillmentSolution memory solution = _solution(
      erc20Targets,
      erc20Amounts,
      _addresses(nftRecipient),
      new GenericCall[](0),
      vm.getBlockTimestamp() + 1 hours
    );

    ERC20Transfer[] memory expectedErc20s = new ERC20Transfer[](2);
    expectedErc20s[0] = ERC20Transfer({token: token18, target: address(router2), amount: AMOUNT});
    expectedErc20s[1] = ERC20Transfer({token: token6, target: solverWallet, amount: sixAmount});
    ERC721Transfer[] memory expectedNfts = new ERC721Transfer[](1);
    expectedNfts[0] = ERC721Transfer({token: address(nft), tokenId: NFT_ID, target: nftRecipient});

    vm.recordLogs();
    vm.prank(owner);
    hub.fulfillOrderWithDelegatedAuthentication(order, address(0), '', solution, '', false);
    Vm.Log memory entry = _settlementLog();

    assertEq(_topicAddress(entry.topics[1]), owner, 'the caller');
    assertEq(_topicAddress(entry.topics[2]), owner, 'the owner');
    assertEq(entry.topics[3], SchemaHash.fulfillmentOrder(order), 'the fulfillment order hash');
    assertEq(
      entry.data,
      abi.encode(expectedErc20s, expectedNfts, new NativeTransfer[](0)),
      'each transfer with its target'
    );

    // the listed transfers are what moved
    assertEq(_balance(address(router2)), AMOUNT, 'the first transfer');
    assertEq(IERC20(token6).balanceOf(solverWallet), sixAmount, 'the second transfer');
    assertEq(nft.ownerOf(NFT_ID), nftRecipient, 'the NFT transfer');
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
      FulfillmentOrder memory order = _amountOrder(AMOUNT, 1);
      FulfillmentSolution memory solution = _amountSolution(chosen);
      bytes memory permit = _preparePath(path, order);
      uint256 ownerBefore = _balance(owner);
      uint256 targetBefore = _balance(solverWallet);
      uint160 permit2Before = _permit2Allowance(token18);

      vm.recordLogs();
      _submit(path, order, permit, solution);
      Vm.Log memory entry = _settlementLog();

      assertEq(ownerBefore - _balance(owner), chosen, 'the owner paid the chosen amount');
      assertEq(_balance(solverWallet) - targetBefore, chosen, 'and the target received it');
      assertEq(entry.topics[3], SchemaHash.fulfillmentOrder(order), 'the event names the order');

      ERC20Transfer[] memory expected = new ERC20Transfer[](1);
      expected[0] = ERC20Transfer({token: token18, target: solverWallet, amount: chosen});
      assertEq(
        entry.data,
        abi.encode(expected, new ERC721Transfer[](0), new NativeTransfer[](0)),
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
      FulfillmentOrder memory order = _twoTransferOrder(AMOUNT, sixAllowance, 1);
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
    FulfillmentOrder memory order = _twoTransferOrder(AMOUNT, sixAllowance, 1);
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
      abi.encode(expected, new ERC721Transfer[](0), new NativeTransfer[](0)),
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
    FulfillmentOrder memory order = _twoTransferOrder(AMOUNT, sixAllowance, 1);
    bytes memory permit = _preparePath(PATH_PERMIT2_SIGNATURE, order);

    for (uint256 length = 1; length <= 3; length += 2) {
      FulfillmentSolution memory solution = _twoTransferSolution(AMOUNT, sixAllowance);
      solution.erc20Amounts = new uint160[](length);

      vm.prank(owner);
      vm.expectRevert(ICommon.MismatchedArrayLengths.selector);
      hub.fulfillOrderWithDelegatedAuthentication(order, address(0), '', solution, '', false);

      vm.prank(solver);
      vm.expectRevert(ICommon.MismatchedArrayLengths.selector);
      hub.fulfillOrderWithPermit2Signature(order, permit, solution, '');
    }

    uint256 ownerBefore = _balance(owner);
    _submit(PATH_HUB, order, '', _twoTransferSolution(AMOUNT, sixAllowance));
    assertEq(ownerBefore - _balance(owner), AMOUNT, 'amounts of the right length settle');
  }

  /**
   * AMT-05 — the approval covers the amounts
   * @dev The approver signs amounts of 5 ether. The same solution with 2 ether is refused, and the
   * one it signed settles.
   */
  function test_AMT_05_theApprovalBindsTheAmounts() public {
    FulfillmentOrder memory order = _amountOrder(AMOUNT, 1);
    order.solutionApprover = approver;
    FulfillmentSolution memory approved = _amountSolution(AMOUNT);
    FulfillmentSolution memory lower = _amountSolution(2 ether);
    bytes memory approval = _signSolutionApproval(approverKey, order, approved);

    vm.prank(owner);
    vm.expectRevert(IKSAllowanceHubV2.InvalidSolutionSignature.selector);
    hub.fulfillOrderWithDelegatedAuthentication(order, address(0), '', lower, approval, false);

    uint256 ownerBefore = _balance(owner);
    vm.prank(owner);
    hub.fulfillOrderWithDelegatedAuthentication(order, address(0), '', approved, approval, false);
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

    FulfillmentOrder memory order = _amountOrder(f.allowance, 1);
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
  // helpers
  // -------------------------------------------------------------------------------------------

  /// @dev One ERC20 transfer of `AMOUNT` and the NFT, open to any submitter, with no route of its
  /// own
  function _bothTransfers(address solutionApprover, uint256 nonce)
    private
    view
    returns (FulfillmentOrder memory)
  {
    return _fulfillmentOrder(
      ANY,
      _allowances(_tokenAllowance(AMOUNT)),
      _approvals(_nftApproval()),
      new ValidationParams[](0),
      new GenericCall[](0),
      solutionApprover,
      nonce,
      vm.getBlockTimestamp() + 1 hours
    );
  }

  /// @dev The ERC20 transfer to `solverWallet` and the NFT to `nftRecipient`
  function _toSolverAndRecipient() private view returns (FulfillmentSolution memory) {
    return _solution(
      _addresses(solverWallet),
      _amounts(AMOUNT),
      _addresses(nftRecipient),
      _calls(_routerCall(0, hex'01')),
      vm.getBlockTimestamp() + 1 hours
    );
  }

  /**
   * @dev For the one-ERC20, one-NFT order of {_bothTransfers}: partition `i` gives 0 or 2 ERC20
   * targets (i = 0, 1) or 0 or 2 NFT targets (i = 2, 3), with the other array right
   */
  function _mismatched(uint256 i) private view returns (FulfillmentSolution memory) {
    address[] memory none = new address[](0);
    address[] memory two = new address[](2);
    two[0] = solverWallet;
    two[1] = nftRecipient;
    address[] memory one = _addresses(solverWallet);
    address[] memory nftOne = _addresses(nftRecipient);

    address[] memory erc20Targets = i == 0 ? none : i == 1 ? two : one;
    address[] memory erc721Targets = i == 2 ? none : i == 3 ? two : nftOne;
    return _solution(
      erc20Targets,
      _amounts(AMOUNT),
      erc721Targets,
      _calls(_routerCall(0, hex'01')),
      vm.getBlockTimestamp() + 1 hours
    );
  }

  /// @dev Pull branches of the fulfillment: the hub's allowance, the owner's Permit2 allowance and
  /// a Permit2 signature
  uint8 private constant PATH_HUB = 0;
  uint8 private constant PATH_PERMIT2_ALLOWANCE = 1;
  uint8 private constant PATH_PERMIT2_SIGNATURE = 2;

  /// @dev One ERC20 transfer of `allowance`, open to any submitter
  function _amountOrder(uint160 allowance, uint256 nonce)
    private
    view
    returns (FulfillmentOrder memory)
  {
    return _fulfillmentOrder(
      ANY,
      _allowances(_tokenAllowance(allowance)),
      new ERC721Approval[](0),
      new ValidationParams[](0),
      new GenericCall[](0),
      ANY,
      nonce,
      vm.getBlockTimestamp() + 1 hours
    );
  }

  /// @dev Two ERC20 transfers, of token18 and token6, open to any submitter
  function _twoTransferOrder(uint160 allowance18, uint160 allowance6, uint256 nonce)
    private
    view
    returns (FulfillmentOrder memory)
  {
    ERC20Allowance[] memory allowances = new ERC20Allowance[](2);
    allowances[0] = _tokenAllowance(allowance18);
    allowances[1] = ERC20Allowance({token: token6, amount: allowance6});
    return _fulfillmentOrder(
      ANY,
      allowances,
      new ERC721Approval[](0),
      new ValidationParams[](0),
      new GenericCall[](0),
      ANY,
      nonce,
      vm.getBlockTimestamp() + 1 hours
    );
  }

  /// @dev `amount` of the one transfer to `solverWallet`
  function _amountSolution(uint160 amount) private view returns (FulfillmentSolution memory) {
    return _solution(
      _addresses(solverWallet),
      _amounts(amount),
      new address[](0),
      new GenericCall[](0),
      vm.getBlockTimestamp() + 1 hours
    );
  }

  /// @dev The amounts of the transfers of {_twoTransferOrder}, both to `solverWallet`
  function _twoTransferSolution(uint160 amount18, uint160 amount6)
    private
    view
    returns (FulfillmentSolution memory)
  {
    address[] memory targets = new address[](2);
    targets[0] = solverWallet;
    targets[1] = solverWallet;
    uint160[] memory amounts = new uint160[](2);
    amounts[0] = amount18;
    amounts[1] = amount6;
    return _solution(
      targets, amounts, new address[](0), new GenericCall[](0), vm.getBlockTimestamp() + 1 hours
    );
  }

  /**
   * @dev Prepares what `path` needs before the submission: a Permit2 allowance of twice each
   * transfer for the allowance branch, so that Permit2 does not refuse an amount first, and the
   * owner's witness signature for the signature branch
   */
  function _preparePath(uint8 path, FulfillmentOrder memory order)
    private
    returns (bytes memory permit)
  {
    if (path == PATH_PERMIT2_ALLOWANCE) {
      for (uint256 i = 0; i < order.erc20Allowances.length; i++) {
        _grantPermit2Allowance(order.erc20Allowances[i].token, 2 * order.erc20Allowances[i].amount);
      }
    } else if (path == PATH_PERMIT2_SIGNATURE) {
      permit = _signFulfillmentWitness(order);
    }
  }

  /// @dev The owner submits on the first two branches, and `solver` on the Permit2 signature
  function _submit(
    uint8 path,
    FulfillmentOrder memory order,
    bytes memory permit,
    FulfillmentSolution memory solution
  ) private {
    if (path == PATH_PERMIT2_SIGNATURE) {
      vm.prank(solver);
      hub.fulfillOrderWithPermit2Signature(order, permit, solution, '');
    } else {
      vm.prank(owner);
      hub.fulfillOrderWithDelegatedAuthentication(
        order, address(0), '', solution, '', path == PATH_PERMIT2_ALLOWANCE
      );
    }
  }

  function _exceeds(uint256 index, uint256 amount, uint256 allowance)
    private
    pure
    returns (bytes memory)
  {
    return abi.encodeWithSelector(
      ERC20AllowanceLib.ERC20AllowanceExceeded.selector, index, amount, allowance
    );
  }

  function _balance(address account) private view returns (uint256) {
    return IERC20(token18).balanceOf(account);
  }

  /// @dev The ERC20 transfer left the owner for `solverWallet`, and the NFT reached `nftRecipient`
  function _assertLanded(uint256 ownerBefore) private view {
    assertEq(ownerBefore - _balance(owner), AMOUNT, 'the owner paid the transfer');
    assertEq(_balance(solverWallet), AMOUNT, "the solver's target received it");
    assertEq(nft.ownerOf(NFT_ID), nftRecipient, 'the NFT reached its target');
  }
}
