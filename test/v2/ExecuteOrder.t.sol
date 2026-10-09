// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Vm} from 'forge-std/Vm.sol';

import {AuthenticatorBase} from 'test/v2/authenticators/base/AuthenticatorBase.sol';

import {
  ISessionOrderAuthenticator
} from 'src/v2/authenticators/interfaces/ISessionOrderAuthenticator.sol';
import {AuthKey} from 'src/v2/authenticators/types/AuthKey.sol';
import {IAuthDelegator} from 'src/v2/interfaces/IAuthDelegator.sol';
import {IKSAllowanceHubV2} from 'src/v2/interfaces/IKSAllowanceHubV2.sol';
import {ERC20Transfer} from 'src/v2/types/ERC20Transfer.sol';
import {ERC721Transfer} from 'src/v2/types/ERC721Transfer.sol';
import {ExecutionOrder} from 'src/v2/types/ExecutionOrder.sol';
import {GenericCall} from 'src/v2/types/GenericCall.sol';

import {IERC20} from 'openzeppelin-contracts/contracts/token/ERC20/IERC20.sol';
import {IOrderAuthenticator} from 'src/v2/interfaces/IOrderAuthenticator.sol';

/**
 * @notice `AUTH-01..13`, `ORD-01..02` and the two execute-rail fuzz properties — every
 * authentication route into {KSAllowanceHubV2-executeOrderWithPermit2Signature} and
 * {KSAllowanceHubV2-executeOrderWithDelegatedAuthentication}.
 * @dev The two rails are separate functions now, so the differences are per entry point rather than
 * per flag: the Permit2 rail binds the order as a witness and gates on `order.relayer`, while the
 * delegated rail hands the whole order to an {IOrderAuthenticator} the owner nominated.
 */
contract ExecuteOrderTest is AuthenticatorBase {
  uint160 internal constant AMOUNT = 5 ether;

  /// @dev Permit2 does not expose this in the vendored interface, so it is written out here
  bytes4 internal constant PERMIT2_INVALID_SIGNER = bytes4(keccak256('InvalidSigner()'));

  /// @dev Raised by the calldata decoder, which declares it in a library rather than in an ABI
  bytes4 internal constant SLICE_OUT_OF_BOUNDS = bytes4(keccak256('SliceOutOfBounds()'));

  /**
   * @dev Transcribed from {IOrderAuthenticator}, with {ExecutionOrder} expanded to its tuple. A
   * selector taken from the production interface would agree with a wrong signature there.
   */
  AuthKey internal key;

  function setUp() public override {
    super.setUp();
    key = _secpKey(masterSigner, block.timestamp + 30 days);
  }

  // -------------------------------------------------------------------------------------------
  // AUTH-01..05 — the Permit2 signature rail
  // -------------------------------------------------------------------------------------------

  /// AUTH-01 — the owner submits their own Permit2 order, so nothing is witnessed
  function test_AUTH_01_permit2SelfSubmitted() public {
    ERC20Transfer[] memory erc20s = _erc20s(_tokenTransfer(AMOUNT));
    uint256 deadline = block.timestamp + 1 hours;

    ExecutionOrder memory order = _openExecutionOrder(erc20s, new GenericCall[](0), 0, deadline);
    bytes memory signature = _signPlainPermit(erc20s, 0, deadline);

    uint256 balanceBefore = IERC20(token18).balanceOf(address(router));

    vm.prank(owner);
    hub.executeOrderWithPermit2Signature(order, signature);

    assertEq(IERC20(token18).balanceOf(address(router)) - balanceBefore, AMOUNT);
  }

  /// AUTH-02 — a relayer submits, and the witness carries everything the permit does not
  function test_AUTH_02_permit2RelayedWithWitness() public {
    ERC20Transfer[] memory erc20s = _erc20s(_tokenTransfer(AMOUNT));
    ERC721Transfer[] memory nfts = _erc721s(_nftTransfer(address(router)));
    GenericCall[] memory calls = _calls(_routerCall(0, hex'01'));
    uint256 deadline = block.timestamp + 1 hours;

    ExecutionOrder memory order = _executionOrder(ANY, erc20s, nfts, calls, 1, deadline);
    bytes memory signature = _signExecutionWitness(order);

    uint256 balanceBefore = IERC20(token18).balanceOf(address(router));

    vm.prank(relayer);
    bytes[] memory results = hub.executeOrderWithPermit2Signature(order, signature);

    assertEq(IERC20(token18).balanceOf(address(router)) - balanceBefore, AMOUNT, 'erc20 leg');
    assertEq(nft.ownerOf(NFT_ID), address(router), 'erc721 leg');
    assertEq(router.callCount(), 1, 'router called once');
    assertEq(results.length, 1, 'one result');
    assertEq(abi.decode(results[0], (uint256)), 1, 'result is the router return');
  }

  /// AUTH-03 — mutating a byte of the signed call list invalidates the order
  function test_AUTH_03_witnessPinsTheCallList() public {
    ERC20Transfer[] memory erc20s = _erc20s(_tokenTransfer(AMOUNT));
    uint256 deadline = block.timestamp + 1 hours;

    ExecutionOrder memory signed =
      _openExecutionOrder(erc20s, _calls(_routerCall(0, hex'01')), 2, deadline);
    bytes memory signature = _signExecutionWitness(signed);

    // same order, one byte of call data changed
    ExecutionOrder memory tampered =
      _openExecutionOrder(erc20s, _calls(_routerCall(0, hex'02')), 2, deadline);

    vm.prank(relayer);
    vm.expectRevert(PERMIT2_INVALID_SIGNER);
    hub.executeOrderWithPermit2Signature(tampered, signature);
  }

  /**
   * AUTH-04 — the relayer the owner named is part of what the witness binds
   * @dev `order.relayer` is read twice: the gate compares it against the submitter, and the witness
   * carries it. ORD-02 is the gate; this is the witness. The first leg is the control, so the
   * refusal in the second is evidence about the binding rather than about a signature that was
   * never going to be accepted — the two orders differ in that one field alone.
   */
  function test_AUTH_04_witnessPinsTheNamedRelayer() public {
    ERC20Transfer[] memory erc20s = _erc20s(_tokenTransfer(AMOUNT));
    uint256 deadline = block.timestamp + 1 hours;

    ExecutionOrder memory pinned =
      _executionOrder(relayer, erc20s, new ERC721Transfer[](0), new GenericCall[](0), 3, deadline);
    bytes memory matching = _signExecutionWitness(pinned);

    uint256 before = IERC20(token18).balanceOf(address(router));

    vm.prank(relayer);
    hub.executeOrderWithPermit2Signature(pinned, matching);
    assertEq(
      IERC20(token18).balanceOf(address(router)) - before, AMOUNT, 'the matching order settled'
    );

    // the owner signed a witness naming the relayer; the order submitted names nobody, so the hub
    // rebuilds a different witness from it
    ExecutionOrder memory openOrder =
      _executionOrder(ANY, erc20s, new ERC721Transfer[](0), new GenericCall[](0), 4, deadline);
    bytes memory forTheRelayer = _signExecutionWitness(openOrder, relayer);

    vm.prank(relayer);
    vm.expectRevert(PERMIT2_INVALID_SIGNER);
    hub.executeOrderWithPermit2Signature(openOrder, forTheRelayer);
  }

  /**
   * ORD-02 — `relayer` says who may submit, and the sentinel says anybody may
   * @dev The gate runs before Permit2, so the middle leg's refusal is the hub's own error and names
   * both addresses. The last leg is what makes the middle one about the pin rather than about the
   * submitter: the same stranger settles an order that names nobody.
   */
  function test_ORD_02_relayerPinningAndTheOpenSentinel() public {
    ERC20Transfer[] memory erc20s = _erc20s(_tokenTransfer(AMOUNT));
    ERC721Transfer[] memory noNfts = new ERC721Transfer[](0);
    GenericCall[] memory noCalls = new GenericCall[](0);
    uint256 deadline = block.timestamp + 1 hours;

    ExecutionOrder memory pinned = _executionOrder(relayer, erc20s, noNfts, noCalls, 50, deadline);
    bytes memory pinnedSig = _signExecutionWitness(pinned);

    uint256 before = IERC20(token18).balanceOf(address(router));
    vm.prank(relayer);
    hub.executeOrderWithPermit2Signature(pinned, pinnedSig);
    assertEq(
      IERC20(token18).balanceOf(address(router)) - before, AMOUNT, 'the named relayer may submit'
    );

    ExecutionOrder memory pinnedAgain =
      _executionOrder(relayer, erc20s, noNfts, noCalls, 51, deadline);
    bytes memory pinnedAgainSig = _signExecutionWitness(pinnedAgain);

    vm.prank(solver);
    vm.expectRevert(
      abi.encodeWithSelector(IKSAllowanceHubV2.UnauthorizedRelayer.selector, solver, relayer)
    );
    hub.executeOrderWithPermit2Signature(pinnedAgain, pinnedAgainSig);

    assertEq(
      _permit2NonceBitmap(owner, 51 >> 8) & (1 << 51),
      0,
      'the refused order burned no Permit2 nonce'
    );

    ExecutionOrder memory openOrder = _executionOrder(ANY, erc20s, noNfts, noCalls, 52, deadline);
    bytes memory openSig = _signExecutionWitness(openOrder);

    before = IERC20(token18).balanceOf(address(router));
    vm.prank(solver);
    hub.executeOrderWithPermit2Signature(openOrder, openSig);
    assertEq(
      IERC20(token18).balanceOf(address(router)) - before,
      AMOUNT,
      'the sentinel opened submission to the very same stranger'
    );
  }

  // -------------------------------------------------------------------------------------------
  // AUTH-06 — an owner acting for themselves
  // -------------------------------------------------------------------------------------------

  /// AUTH-06 — an owner acting for themselves needs no authenticator at all
  function test_AUTH_06_ownerCallerNeedsNoAuthentication() public {
    ERC20Transfer[] memory erc20s = _erc20s(_tokenTransfer(AMOUNT));
    uint256 balanceBefore = IERC20(token18).balanceOf(address(router));

    ExecutionOrder memory order =
      _openExecutionOrder(erc20s, new GenericCall[](0), 0, block.timestamp);

    vm.prank(owner);
    hub.executeOrderWithDelegatedAuthentication(order, address(0), '', false);

    assertEq(IERC20(token18).balanceOf(address(router)) - balanceBefore, AMOUNT);
  }

  /// AUTH-06b — the same, pulled through the owner's Permit2 allowance instead
  function test_AUTH_06b_ownerCallerViaPermit2Allowance() public {
    _grantPermit2Allowance(token18, 100 ether);

    ERC20Transfer[] memory erc20s = _erc20s(_tokenTransfer(AMOUNT));
    uint256 balanceBefore = IERC20(token18).balanceOf(address(router));
    uint160 allowanceBefore = _permit2Allowance(token18);

    ExecutionOrder memory order = _executionOrder(
      ANY, erc20s, new ERC721Transfer[](0), new GenericCall[](0), 0, block.timestamp
    );

    vm.prank(owner);
    hub.executeOrderWithDelegatedAuthentication(order, address(0), '', true);

    assertEq(IERC20(token18).balanceOf(address(router)) - balanceBefore, AMOUNT);
    assertEq(allowanceBefore - _permit2Allowance(token18), AMOUNT, 'drawn on the Permit2 allowance');
  }

  // -------------------------------------------------------------------------------------------
  // AUTH-08..13 and ORD-01 — the delegated authentication rail
  // -------------------------------------------------------------------------------------------

  /// AUTH-08 — an authenticator the owner never delegated is refused before it is ever called
  function test_AUTH_08_undelegatedAuthenticatorRefused() public {
    ExecutionOrder memory order = _openExecutionOrder(
      _erc20s(_tokenTransfer(AMOUNT)), new GenericCall[](0), 0, block.timestamp
    );
    bytes memory authData = _authData(key, hex'00');

    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(
        IAuthDelegator.NotDelegatedAuthenticator.selector, owner, address(authenticator)
      )
    );
    hub.executeOrderWithDelegatedAuthentication(order, address(authenticator), authData, false);
  }

  /**
   * ORD-01 — the asset source is the submitter's parameter, and the same order settles either way
   * @dev `usePermit2Allowances` is an argument of the delegated entry points rather than a member
   * of the order, so one signed order settles on either pull rail and the submitter chooses. What
   * bounds the submitter is the rest of the order, which is signed — the two legs here
   * are the same order shape and the same amount, and each leg asserts that the source it did *not*
   * name went untouched, so this is about the argument and not about the transfer.
   */
  function test_ORD_01_theAssetSourceIsTheSubmittersArgument() public {
    _delegateKeyThroughHub(key);
    _grantPermit2Allowance(token18, 100 ether);

    uint256 deadline = block.timestamp + 1 hours;
    ERC20Transfer[] memory erc20s = _erc20s(_tokenTransfer(AMOUNT));

    ExecutionOrder memory plainRail =
      _executionOrder(ANY, erc20s, new ERC721Transfer[](0), new GenericCall[](0), 40, deadline);
    bytes memory plainAuth = _executionAuthData(plainRail, key, masterKeyPk);

    uint256 before = IERC20(token18).balanceOf(address(router));
    uint160 allowanceBefore = _permit2Allowance(token18);

    vm.prank(relayer);
    hub.executeOrderWithDelegatedAuthentication(plainRail, address(authenticator), plainAuth, false);

    assertEq(IERC20(token18).balanceOf(address(router)) - before, AMOUNT, 'plain allowance rail');
    assertEq(_permit2Allowance(token18), allowanceBefore, 'and it left the Permit2 allowance alone');

    ExecutionOrder memory permit2Rail =
      _executionOrder(ANY, erc20s, new ERC721Transfer[](0), new GenericCall[](0), 41, deadline);
    bytes memory permit2Auth = _executionAuthData(permit2Rail, key, masterKeyPk);

    before = IERC20(token18).balanceOf(address(router));

    vm.prank(relayer);
    hub.executeOrderWithDelegatedAuthentication(
      permit2Rail, address(authenticator), permit2Auth, true
    );

    assertEq(IERC20(token18).balanceOf(address(router)) - before, AMOUNT, 'permit2 allowance rail');
    assertEq(allowanceBefore - _permit2Allowance(token18), AMOUNT, 'and that rail did claim it');
  }

  /**
   * ORD-01b — the Permit2-signature rail takes no source argument and claims neither allowance
   * @dev Why the argument is absent there: that rail pulls with `permitWitnessTransferFrom`, a
   * signature transfer, which consults no allowance at all. Shown from both sides, because each
   * alone would be weak: the owner's plain allowance to the hub is revoked outright and the order
   * still settles, and the Permit2 allowance is left live and finite so that a draw on it would be
   * visible. The setup's plain allowance is infinite, so asserting it merely went unchanged would
   * prove nothing — revoking it is what gives this force.
   */
  function test_ORD_01b_thePermit2SignatureRailConsultsNoAllowance() public {
    _grantPermit2Allowance(token18, 100 ether);

    // the one allowance this rail could have leant on, taken away
    vm.prank(owner);
    IERC20(token18).approve(address(hub), 0);

    uint256 deadline = block.timestamp + 1 hours;
    ERC20Transfer[] memory erc20s = _erc20s(_tokenTransfer(AMOUNT));
    ExecutionOrder memory order =
      _executionOrder(ANY, erc20s, new ERC721Transfer[](0), new GenericCall[](0), 44, deadline);
    bytes memory witness = _signExecutionWitness(order);

    uint160 permit2Before = _permit2Allowance(token18);
    uint256 before = IERC20(token18).balanceOf(address(router));

    vm.prank(relayer);
    hub.executeOrderWithPermit2Signature(order, witness);

    assertEq(
      IERC20(token18).balanceOf(address(router)) - before, AMOUNT, 'the signature transfer ran'
    );
    assertEq(
      IERC20(token18).allowance(owner, address(hub)), 0, 'with no plain allowance to draw on'
    );
    assertEq(_permit2Allowance(token18), permit2Before, 'and the Permit2 allowance went untouched');
  }

  /**
   * AUTH-11 — the authenticator receives the whole order, unaltered, with the data it was given
   * @dev The hub forwards the struct rather than repackaging it into a payload of its own.
   * The expected calldata is assembled from a function signature written out in this file, so a
   * mistyped signature would produce a selector the hub never sends and the expectation would fail
   * rather than agree with itself. The settlement assertion is what rules out a vacuous pass.
   */
  function test_AUTH_11_authenticatorReceivesTheWholeOrder() public {
    _delegateKeyThroughHub(key);

    ERC20Transfer[] memory erc20s = _erc20s(_tokenTransfer(AMOUNT));
    GenericCall[] memory calls = _calls(_routerCall(0, hex'01'));
    uint256 deadline = block.timestamp + 1 hours;

    ExecutionOrder memory order =
      _executionOrder(ANY, erc20s, new ERC721Transfer[](0), calls, 43, deadline);
    bytes memory authData = _executionAuthData(order, key, masterKeyPk);

    bytes memory expectedCall =
      abi.encodeCall(IOrderAuthenticator.authenticateExecution, (order, authData));

    uint256 before = IERC20(token18).balanceOf(address(router));

    vm.expectCall(address(authenticator), expectedCall, 1);

    vm.prank(relayer);
    hub.executeOrderWithDelegatedAuthentication(order, address(authenticator), authData, false);

    assertEq(IERC20(token18).balanceOf(address(router)) - before, AMOUNT, 'and the order settled');
  }

  /// AUTH-13 — authentication data too short to hold a signature is rejected by the decoder
  function test_AUTH_13_malformedAuthenticationDataRejected() public {
    _delegateKeyThroughHub(key);

    ExecutionOrder memory order = _openExecutionOrder(
      _erc20s(_tokenTransfer(AMOUNT)), new GenericCall[](0), 0, block.timestamp
    );

    // the key alone: word 0 reaches it, word 1 is read as the signature's offset and runs off
    vm.prank(relayer);
    vm.expectRevert(SLICE_OUT_OF_BOUNDS);
    hub.executeOrderWithDelegatedAuthentication(
      order, address(authenticator), _encodeKey(key), false
    );
  }

  // -------------------------------------------------------------------------------------------
  // EX-FUZZ — one property per execute entry point
  // -------------------------------------------------------------------------------------------

  /// @dev One named struct for the execute family, per the frozen plan's fuzz contract
  struct ExecuteFuzz {
    uint160 amount;
    uint8 callCount;
    bool usePermit2Allowances;
    uint256 deadlineOffset;
    uint96 msgValue;
    bool moveNft;
    bool pinSubmitter;
    uint256 nonce;
  }

  /**
   * EX-FUZZ — `executeOrderWithDelegatedAuthentication` over a relayed session-key credential
   * @dev `pinSubmitter` and `usePermit2Allowances` are never read as control flow on this rail, but
   * both sit inside `order.hash()`, so the emitted order hash is what makes them matter: a hub that
   * reported a hash over anything but the order it settled would fail here.
   */
  function testFuzz_EX_FUZZ_delegatedRail(ExecuteFuzz memory f) public {
    _delegateKeyThroughHub(key);

    f.amount = uint160(bound(f.amount, 0, 100 ether));
    f.callCount = uint8(bound(f.callCount, 0, 3));
    f.deadlineOffset = bound(f.deadlineOffset, 0, 30 days);
    f.msgValue = uint96(bound(f.msgValue, 0, 5 ether));
    if (f.usePermit2Allowances) _grantPermit2Allowance(token18, uint160(100 ether));

    // the whole value goes to the first call, so the guard sees an exactly-spent batch
    GenericCall[] memory calls = new GenericCall[](f.callCount);
    for (uint256 i = 0; i < f.callCount; i++) {
      calls[i] = _routerCall(i == 0 ? f.msgValue : 0, abi.encodePacked(uint8(i)));
    }
    uint256 value = f.callCount == 0 ? 0 : f.msgValue;

    ExecutionOrder memory order = _executionOrder(
      f.pinSubmitter ? relayer : ANY,
      _erc20s(_tokenTransfer(f.amount)),
      f.moveNft ? _erc721s(_nftTransfer(address(router2))) : new ERC721Transfer[](0),
      calls,
      f.nonce,
      block.timestamp + f.deadlineOffset
    );
    bytes memory authData = _executionAuthData(order, key, masterKeyPk);

    uint256 before = IERC20(token18).balanceOf(address(router));
    uint256 routerNative = address(router).balance;
    uint256 untouched = IERC20(token18).balanceOf(recipient);
    vm.deal(relayer, value);

    vm.recordLogs();

    vm.prank(relayer);
    bytes[] memory results = hub.executeOrderWithDelegatedAuthentication{value: value}(
      order, address(authenticator), authData, false
    );

    assertEq(IERC20(token18).balanceOf(address(router)) - before, f.amount, 'exact amount moved');
    assertEq(address(router).balance - routerNative, value, 'native forwarded, none stranded');
    assertEq(results.length, f.callCount, 'one result per call');
    assertEq(router.callCount(), f.callCount, 'router called once per entry');
    assertEq(IERC20(token18).balanceOf(recipient), untouched, 'unnamed account untouched');
    if (f.moveNft) assertEq(nft.ownerOf(NFT_ID), address(router2), 'nft leg');

    assertEq(
      authenticator.nonces(_keyHash(key), f.nonce >> 8),
      1 << (f.nonce & 0xff),
      'the authenticator burned exactly the order nonce'
    );
    assertEq(hub.nonces(lNonceKey(owner), f.nonce >> 8), 0, 'and the hub burned none of its own');

    Vm.Log memory entry = _settlementLog();
    assertEq(entry.topics[3], lExecutionOrderHash(order), 'the event reports this exact order');
  }

  /**
   * EX-FUZZ — `executeOrderWithPermit2Signature`, relayed, where the witness is the binding
   * @dev `pinSubmitter` is live control flow here: it decides whether the gate compares the
   * submitter against a named relayer or against the sentinel, and it changes the witness either
   * way. The Permit2 nonce is the replay oracle.
   */
  function testFuzz_EX_FUZZ_permit2Rail(ExecuteFuzz memory f) public {
    f.amount = uint160(bound(f.amount, 0, 100 ether));
    f.callCount = uint8(bound(f.callCount, 0, 3));
    f.deadlineOffset = bound(f.deadlineOffset, 0, 30 days);
    f.msgValue = uint96(bound(f.msgValue, 0, 5 ether));

    GenericCall[] memory calls = new GenericCall[](f.callCount);
    for (uint256 i = 0; i < f.callCount; i++) {
      calls[i] = _routerCall(i == 0 ? f.msgValue : 0, abi.encodePacked(uint8(i)));
    }
    uint256 value = f.callCount == 0 ? 0 : f.msgValue;

    ExecutionOrder memory order = _executionOrder(
      f.pinSubmitter ? relayer : ANY,
      _erc20s(_tokenTransfer(f.amount)),
      f.moveNft ? _erc721s(_nftTransfer(address(router2))) : new ERC721Transfer[](0),
      calls,
      f.nonce,
      block.timestamp + f.deadlineOffset
    );
    bytes memory signature = _signExecutionWitness(order);

    uint256 before = IERC20(token18).balanceOf(address(router));
    uint256 routerNative = address(router).balance;
    uint256 bitmapBefore = _permit2NonceBitmap(owner, f.nonce >> 8);
    vm.deal(relayer, value);

    vm.recordLogs();

    vm.prank(relayer);
    bytes[] memory results = hub.executeOrderWithPermit2Signature{value: value}(order, signature);

    assertEq(IERC20(token18).balanceOf(address(router)) - before, f.amount, 'exact amount moved');
    assertEq(address(router).balance - routerNative, value, 'native forwarded, none stranded');
    assertEq(results.length, f.callCount, 'one result per call');
    if (f.moveNft) assertEq(nft.ownerOf(NFT_ID), address(router2), 'nft leg');

    assertEq(
      _permit2NonceBitmap(owner, f.nonce >> 8),
      bitmapBefore | (1 << (f.nonce & 0xff)),
      'Permit2 burned exactly the signed nonce'
    );

    Vm.Log memory entry = _settlementLog();
    assertEq(entry.topics[3], lExecutionOrderHash(order), 'the event reports this exact order');
  }
}
