// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Vm} from 'forge-std/Vm.sol';

import {SchemaHash} from 'test/base/SchemaHash.sol';

import {SignerAuthenticatorMock} from 'test/mocks/SignerAuthenticatorMock.sol';

import {SettlementBase} from 'test/settlement/base/SettlementBase.sol';

import {IKSAllowanceHubV2} from 'src/interfaces/IKSAllowanceHubV2.sol';

import {AHV2Order} from 'src/types/AHV2Order.sol';
import {AHV2Solution} from 'src/types/AHV2Solution.sol';
import {ERC20Allowance} from 'src/types/ERC20Allowance.sol';
import {ERC20Transfer} from 'src/types/ERC20Transfer.sol';
import {ERC721Transfer} from 'src/types/ERC721Transfer.sol';
import {NativeTransfer} from 'src/types/NativeTransfer.sol';

import {IERC20} from 'openzeppelin-contracts/contracts/token/ERC20/IERC20.sol';

/**
 * @title EventsTest
 * @notice `SET-01`, `SET-03`, `CLIENT-01..02` and `EVT-01` — the `SettleOrder` event and the
 * results array
 * @dev The `SettleOrder` topic is written out in {HubBase} rather than imported: an expected
 * value taken from the contract under test would agree with a wrong one.
 */
contract EventsTest is SettlementBase {
  /// @dev Permit2 does not expose this in the vendored interface, so it is written out here
  bytes4 internal constant PERMIT2_INVALID_SIGNER = bytes4(keccak256('InvalidSigner()'));

  address internal solverWallet;
  address internal nftRecipient;

  function setUp() public override {
    super.setUp();
    solverWallet = makeAddr('solver wallet');
    nftRecipient = makeAddr('nft recipient');
  }

  /// @dev Inputs of {testFuzz_CLIENT_01_clientDataIsEmittedAsGiven} and
  /// {testFuzz_CLIENT_02_clientDataIsCoveredByTheSignature}; `entryPoint` is bounded to `[0, 1]`
  struct ClientDataFuzz {
    uint8 entryPoint;
    bytes clientData;
  }

  // -----------------------------------------------------------------------------------------
  // SET — the settlement event and the results array
  // -----------------------------------------------------------------------------------------

  /**
   * SET-01 — the whole `SettleOrder` payload of a relayed order, byte for byte
   * @dev `orderHash` is indexed, so there are four topics, and the third is compared against the
   * order hash rebuilt from the independent oracle. The order carries an allowance and an NFT
   * approval, which the solution routes to `callee` and `callee2`.
   */
  function test_SET_01_settleOrderPayload() public {
    uint256 expiration = vm.getBlockTimestamp() + 1 hours;
    ERC20Transfer[] memory erc20s = _erc20s(_tokenTransfer(AMOUNT));
    ERC721Transfer[] memory nfts = _erc721s(_nftTransfer(address(callee2)));

    AHV2Order memory order = _ahv2Order(
      permit2,
      ANY,
      _allowances(_tokenAllowance(AMOUNT)),
      _approvals(_nftApproval()),
      _noHooks(),
      _calls(_calleeCall(hex'abcd')),
      ANY,
      11,
      expiration
    );
    AHV2Solution memory solution = _defaultSolution(order);
    bytes memory signature = _signPermit2Order(order);

    vm.recordLogs();

    vm.prank(relayer);
    hub.settleOrder(order, signature, solution, '', false);

    Vm.Log memory entry = _settlementLog();

    assertEq(entry.topics.length, 4, 'caller, owner and the order hash are indexed');
    assertEq(_topicAddress(entry.topics[1]), relayer, 'caller is the submitter, not the owner');
    assertEq(_topicAddress(entry.topics[2]), owner, 'owner is the account the assets came from');
    assertEq(entry.topics[3], SchemaHash.ahv2Order(order), 'the order hash the owner signed');
    // No call carries value, so the native transfers are empty
    assertEq(entry.data, abi.encode(erc20s, nfts, new NativeTransfer[](0), bytes('')), 'payload');
  }

  /// SET-03 — an order that moves nothing and calls nobody still settles and still emits
  function test_SET_03_emptyOrderStillEmits() public {
    ERC20Transfer[] memory noErc20s = new ERC20Transfer[](0);
    ERC721Transfer[] memory noNfts = new ERC721Transfer[](0);

    AHV2Order memory order = _ownedOrder(owner);

    vm.recordLogs();

    vm.prank(owner);
    bytes[] memory results = hub.settleOrder(order, '', _defaultSolution(order), '', false);

    assertEq(results.length, 0, 'no calls, no results');
    assertEq(callee.callCount(), 0, 'no callee was called');

    Vm.Log memory entry = _settlementLog();
    assertEq(
      entry.data,
      abi.encode(noErc20s, noNfts, new NativeTransfer[](0), bytes('')),
      'three empty arrays'
    );
  }

  // -----------------------------------------------------------------------------------------
  // CLIENT — the order's client data
  // -----------------------------------------------------------------------------------------

  /**
   * CLIENT-01 — the `SettleOrder` of a settled order carries exactly the order's client data
   * @dev Over both entry points, and over any client data drawn: delegated authentication and
   * the Permit2 signature, each submitted by the solver.
   */
  function testFuzz_CLIENT_01_clientDataIsEmittedAsGiven(ClientDataFuzz memory p) public {
    uint8 entry = uint8(bound(p.entryPoint, 0, 1));

    uint256 before = _calleeBalance();

    _submitWithClientData(entry, p.clientData, p.clientData, 0);

    assertEq(_calleeBalance() - before, AMOUNT, 'the order settled');
  }

  /**
   * CLIENT-02 — the owner's signature covers the order's client data
   * @dev The order is authenticated, or its witness signed, with client data A and submitted with
   * A and one more byte. Each entry point refuses it with the error of its own check and nothing
   * moves.
   */
  function testFuzz_CLIENT_02_clientDataIsCoveredByTheSignature(ClientDataFuzz memory p) public {
    uint8 entry = uint8(bound(p.entryPoint, 0, 1));
    bytes memory submitted = abi.encodePacked(p.clientData, uint8(0x01));

    uint256 before = _calleeBalance();
    uint256 ownerBefore = IERC20(token18).balanceOf(owner);

    _submitWithClientData(entry, p.clientData, submitted, 1);

    assertEq(_calleeBalance(), before, 'nothing reached the callee');
    assertEq(IERC20(token18).balanceOf(owner), ownerBefore, 'nothing left the owner');
  }

  /**
   * CLIENT-02b — client data submitted against empty signed client data reverts on every entry
   * @dev CLIENT-02 with empty signed client data on every entry point, the case a fuzzed draw
   * reaches only by chance
   */
  function test_CLIENT_02b_emptyClientDataIsCoveredByTheSignature() public {
    for (uint8 entry = 0; entry < 2; entry++) {
      uint256 snapshot = vm.snapshotState();

      _submitWithClientData(entry, '', hex'01', 1);

      vm.revertToState(snapshot);
    }
  }

  /**
   * @dev Authenticates or signs an order carrying `signedData`, and submits the same order carrying
   * `submittedData` on the entry point `entry`, from the solver. When the two are equal the call is
   * expected to emit `SettleOrder` with that data; otherwise it is expected to revert with the
   * error of the entry point's own check.
   */
  function _submitWithClientData(
    uint8 entry,
    bytes memory signedData,
    bytes memory submittedData,
    uint256 nonce
  ) internal {
    bool matches = keccak256(signedData) == keccak256(submittedData);

    address orderAuthenticator = entry == 0 ? address(authenticator) : permit2;
    AHV2Order memory signed = _clientDataOrder(orderAuthenticator, nonce, signedData);
    AHV2Order memory order = _clientDataOrder(orderAuthenticator, nonce, submittedData);
    AHV2Solution memory solution = _defaultSolution(order);

    if (entry == 0) {
      _delegateSignerThroughHub(signer);
      bytes memory auth = _orderAuthData(signed, signer, signerPk);
      _expectClientData(
        matches, SignerAuthenticatorMock.InvalidOrderSignature.selector, order, submittedData
      );
      vm.prank(solver);
      hub.settleOrder(order, auth, solution, '', false);
    } else {
      bytes memory signature = _signPermit2Order(signed);
      _expectClientData(matches, PERMIT2_INVALID_SIGNER, order, submittedData);
      vm.prank(solver);
      hub.settleOrder(order, signature, solution, '', false);
    }
  }

  /// @dev An order open to any submitter that draws {AMOUNT} of `token18`, carrying `clientData`
  /// and authorized through `orderAuthenticator`
  function _clientDataOrder(address orderAuthenticator, uint256 nonce, bytes memory clientData)
    internal
    view
    returns (AHV2Order memory order)
  {
    order = _openAhv2Order(
      orderAuthenticator,
      _allowances(_tokenAllowance(AMOUNT)),
      _noHooks(),
      _calls(_calleeCall(hex'01')),
      nonce,
      vm.getBlockTimestamp() + 1 hours
    );
    order.clientData = clientData;
  }

  /// @dev Expects the full `SettleOrder` payload of `order` from the solver when `matches`, and
  /// `refusal` otherwise
  function _expectClientData(
    bool matches,
    bytes4 refusal,
    AHV2Order memory order,
    bytes memory clientData
  ) internal {
    if (matches) {
      vm.expectEmit(true, true, true, true, address(hub));
      emit IKSAllowanceHubV2.SettleOrder(
        solver,
        owner,
        SchemaHash.ahv2Order(order),
        _erc20s(_tokenTransfer(AMOUNT)),
        new ERC721Transfer[](0),
        new NativeTransfer[](0),
        clientData
      );
    } else {
      vm.expectRevert(refusal);
    }
  }

  // -------------------------------------------------------------------------------------------
  // EVT-01 — the event pairs each transfer with its target
  // -------------------------------------------------------------------------------------------

  /**
   * EVT-01 — `SettleOrder` lists the transfers that happened, each with the solution's target
   * @dev Two ERC20 transfers of different tokens and amounts go to two different targets, so the
   * pairing cannot come out right by symmetry.
   */
  function test_EVT_01_eventPairsTransfersWithTargets() public {
    uint160 sixAmount = 7e6;
    ERC20Allowance[] memory allowances = new ERC20Allowance[](2);
    allowances[0] = _tokenAllowance(AMOUNT);
    allowances[1] = ERC20Allowance({token: token6, amount: sixAmount});
    AHV2Order memory order = _ahv2Order(
      ANY,
      allowances,
      _approvals(_nftApproval()),
      _noHooks(),
      _noCalls(),
      ANY,
      0,
      vm.getBlockTimestamp() + 1 hours
    );
    address[] memory erc20Targets = new address[](2);
    erc20Targets[0] = address(callee2);
    erc20Targets[1] = solverWallet;
    uint160[] memory erc20Amounts = new uint160[](2);
    erc20Amounts[0] = AMOUNT;
    erc20Amounts[1] = sixAmount;
    AHV2Solution memory solution = _solution(
      erc20Targets, erc20Amounts, _addresses(nftRecipient), vm.getBlockTimestamp() + 1 hours
    );

    ERC20Transfer[] memory expectedErc20s = new ERC20Transfer[](2);
    expectedErc20s[0] = ERC20Transfer({token: token18, target: address(callee2), amount: AMOUNT});
    expectedErc20s[1] = ERC20Transfer({token: token6, target: solverWallet, amount: sixAmount});
    ERC721Transfer[] memory expectedNfts = new ERC721Transfer[](1);
    expectedNfts[0] = ERC721Transfer({token: address(nft), tokenId: NFT_ID, target: nftRecipient});

    vm.recordLogs();
    vm.prank(owner);
    hub.settleOrder(order, '', solution, '', false);
    Vm.Log memory entry = _settlementLog();

    assertEq(_topicAddress(entry.topics[1]), owner, 'the caller');
    assertEq(_topicAddress(entry.topics[2]), owner, 'the owner');
    assertEq(entry.topics[3], SchemaHash.ahv2Order(order), 'the order hash');
    assertEq(
      entry.data,
      abi.encode(expectedErc20s, expectedNfts, new NativeTransfer[](0), bytes('')),
      'each transfer with its target'
    );

    // the listed transfers are what moved
    assertEq(_balance(address(callee2)), AMOUNT, 'the first transfer');
    assertEq(IERC20(token6).balanceOf(solverWallet), sixAmount, 'the second transfer');
    assertEq(nft.ownerOf(NFT_ID), nftRecipient, 'the NFT transfer');
  }
}
