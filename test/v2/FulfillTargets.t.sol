// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Vm} from 'forge-std/Vm.sol';

import {SchemaHash} from 'test/base/SchemaHash.sol';

import {AuthenticatorBase} from 'test/v2/authenticators/base/AuthenticatorBase.sol';

import {ERC20Mock} from 'test/v2/mocks/TokenMocks.sol';

import {IKSAllowanceHubV2} from 'src/v2/interfaces/IKSAllowanceHubV2.sol';
import {ERC20Allowance} from 'src/v2/types/ERC20Allowance.sol';
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
 * @notice `TGT-01..04` with `LEN-01..02`, `APR-01` and `EVT-01` — the solver chooses where each
 * leg of a fulfillment goes
 * @dev The order names only what may leave the owner; the solution names one target per leg. Every
 * case sends the legs somewhere no order signed: `solverWallet` for an ERC20 leg and `nftRecipient`
 * for the NFT, neither of them a router.
 */
contract FulfillTargetsTest is AuthenticatorBase {
  uint160 internal constant AMOUNT = 5 ether;

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
  // TGT-01..04 — the solver's targets receive the legs, on every pull branch
  // -------------------------------------------------------------------------------------------

  /**
   * TGT-01 / LEN-01 — the delegated rail, submitted by the owner, pulled on the plain approval
   * @dev First the four solutions without exactly one target per leg — 0 or 2 ERC20 targets, then
   * 0 or 2 NFT targets — are each refused, moving nothing; then the solution with one each settles,
   * so the refusals were about the counts.
   */
  function test_TGT_01_solverChoosesTheTargetsOnTheDelegatedRail() public {
    FulfillmentOrder memory order = _bothLegs(ANY, 0);
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
    assertEq(_balance(address(router)), routerBefore, 'no router received the leg');
  }

  /// TGT-02 — the same, pulled through the owner's Permit2 allowance
  function test_TGT_02_solverTargetsOnThePermit2AllowancePull() public {
    _grantPermit2Allowance(token18, AMOUNT);
    FulfillmentOrder memory order = _bothLegs(ANY, 0);
    uint256 ownerBefore = _balance(owner);

    vm.prank(owner);
    hub.fulfillOrderWithDelegatedAuthentication(
      order, address(0), '', _toSolverAndRecipient(), '', true
    );

    _assertLanded(ownerBefore);
    assertEq(_permit2Allowance(token18), 0, 'the Permit2 allowance paid for the leg');
  }

  /**
   * TGT-03 / LEN-02 — relayed over Permit2: the owner's witness carries no ERC20 target
   * @dev The four solutions without exactly one target per leg are refused first, ahead of the
   * permit. Then one witness signature settles the order once with the legs sent one way and, from
   * the same pre-state, once with them sent another, so nothing the owner signed names a target.
   */
  function test_TGT_03_witnessDoesNotBindTheErc20Targets() public {
    FulfillmentOrder memory order = _bothLegs(ANY, 1);
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
        _addresses(solverWallet),
        _calls(_routerCall(0, hex'01')),
        block.timestamp + 1 hours
      ),
      ''
    );
    assertEq(_balance(address(router2)), AMOUNT, 'the same witness, another ERC20 target');
    assertEq(nft.ownerOf(NFT_ID), solverWallet, 'and another NFT target');
  }

  /// TGT-04 — the owner submits over Permit2 with a plain permit, and still picks the targets
  function test_TGT_04_ownerSubmitsWithTargetsOfTheirChoice() public {
    FulfillmentOrder memory order = _bothLegs(ANY, 2);
    bytes memory permit = _signPlainPermit(order.erc20Allowances, 2, order.deadline);
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
   * @dev The two solutions share the route and differ only in where the legs go, so the refusal is
   * about the targets. The second leg is the control.
   */
  function test_APR_01_theApprovalBindsTheTargets() public {
    FulfillmentOrder memory order = _bothLegs(approver, 0);
    FulfillmentSolution memory toRouters = _solution(
      _addresses(address(router)),
      _addresses(address(router2)),
      _calls(_routerCall(0, hex'01')),
      block.timestamp + 1 hours
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
  // EVT-01 — the event pairs each leg with its target
  // -------------------------------------------------------------------------------------------

  /**
   * EVT-01 — `TransferTokens` lists the transfers that happened, each leg with the solution's target
   * @dev Two ERC20 legs of different tokens and amounts go to two different targets, so the pairing
   * cannot come out right by symmetry.
   */
  function test_EVT_01_fulfillmentEventPairsLegsWithTargets() public {
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
      block.timestamp + 1 hours
    );
    address[] memory erc20Targets = new address[](2);
    erc20Targets[0] = address(router2);
    erc20Targets[1] = solverWallet;
    FulfillmentSolution memory solution = _solution(
      erc20Targets, _addresses(nftRecipient), new GenericCall[](0), block.timestamp + 1 hours
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
      'each leg with its target'
    );

    // the listed transfers are what moved
    assertEq(_balance(address(router2)), AMOUNT, 'the first leg');
    assertEq(IERC20(token6).balanceOf(solverWallet), sixAmount, 'the second leg');
    assertEq(nft.ownerOf(NFT_ID), nftRecipient, 'the NFT leg');
  }

  // -------------------------------------------------------------------------------------------
  // helpers
  // -------------------------------------------------------------------------------------------

  /// @dev One ERC20 leg of `AMOUNT` and the NFT, open to any submitter, with no route of its own
  function _bothLegs(address solutionApprover, uint256 nonce)
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
      block.timestamp + 1 hours
    );
  }

  /// @dev The ERC20 leg to `solverWallet` and the NFT to `nftRecipient`
  function _toSolverAndRecipient() private view returns (FulfillmentSolution memory) {
    return _solution(
      _addresses(solverWallet),
      _addresses(nftRecipient),
      _calls(_routerCall(0, hex'01')),
      block.timestamp + 1 hours
    );
  }

  /**
   * @dev For the one-ERC20, one-NFT order of {_bothLegs}: partition `i` gives 0 or 2 ERC20 targets
   * (i = 0, 1) or 0 or 2 NFT targets (i = 2, 3), with the other array right
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
      erc20Targets, erc721Targets, _calls(_routerCall(0, hex'01')), block.timestamp + 1 hours
    );
  }

  function _balance(address account) private view returns (uint256) {
    return IERC20(token18).balanceOf(account);
  }

  /// @dev The ERC20 leg left the owner for `solverWallet`, and the NFT reached `nftRecipient`
  function _assertLanded(uint256 ownerBefore) private view {
    assertEq(ownerBefore - _balance(owner), AMOUNT, 'the owner paid the leg');
    assertEq(_balance(solverWallet), AMOUNT, "the solver's target received it");
    assertEq(nft.ownerOf(NFT_ID), nftRecipient, 'the NFT reached its target');
  }
}
