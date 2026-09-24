// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {VerifierBase} from 'test/verifiers/base/VerifierBase.sol';

import {IAuthDelegator} from 'src/base/interfaces/IAuthDelegator.sol';
import {IAuthVerifier} from 'src/base/interfaces/IAuthVerifier.sol';
import {AuthFlags} from 'src/v2/types/AuthFlags.sol';
import {ERC20Transfer} from 'src/v2/types/ERC20Transfer.sol';
import {ERC721Transfer} from 'src/v2/types/ERC721Transfer.sol';
import {GenericCall} from 'src/v2/types/GenericCall.sol';
import {ValidationParams} from 'src/v2/types/ValidationParams.sol';
import {SessionKey} from 'src/verifiers/types/SessionKey.sol';

import {IERC20} from 'openzeppelin-contracts/contracts/token/ERC20/IERC20.sol';

/// @notice AUTH-01..13 — every authorisation rail of both entry points.
contract AuthTest is VerifierBase {
  uint160 internal constant AMOUNT = 5 ether;

  /// @dev Permit2 does not expose this in the vendored interface, so it is written out here
  bytes4 internal constant PERMIT2_INVALID_SIGNER = bytes4(keccak256('InvalidSigner()'));

  /// @dev Raised by the calldata decoder, which declares it in a library rather than in an ABI
  bytes4 internal constant SLICE_OUT_OF_BOUNDS = bytes4(keccak256('SliceOutOfBounds()'));

  SessionKey internal key;

  function setUp() public override {
    super.setUp();
    key = _secpKey(sessionSigner, block.timestamp + 30 days);
  }

  /// AUTH-01 — the owner submits their own Permit2 order, so nothing is witnessed
  function test_AUTH_01_permit2SelfSubmitted() public {
    ERC20Transfer[] memory erc20s = _erc20s(_wethTransfer(AMOUNT));
    uint256 deadline = block.timestamp + 1 hours;

    bytes memory signature = _signPlainPermit(erc20s, 0, deadline);

    uint256 balanceBefore = IERC20(WETH).balanceOf(address(router));

    vm.prank(owner);
    hub.transferAndExecute(
      owner,
      erc20s,
      new ERC721Transfer[](0),
      new GenericCall[](0),
      deadline,
      _flags(true, false, false),
      _permit2AuthData(0, signature)
    );

    assertEq(IERC20(WETH).balanceOf(address(router)) - balanceBefore, AMOUNT);
  }

  /**
   * AUTH-01b — the same rail on the fulfillment entry point, which no other case reaches.
   * @dev Worth its own case beyond the branch: an owner submitting for themselves skips the
   * witness entirely, so `callsSigner`, `validationParams` and the NFT leg are bound by no
   * signature at all — yet `_callsSigner` still runs first and still burns the owner's nonce.
   */
  function test_AUTH_01b_fulfillmentPermit2SelfSubmitted() public {
    ERC20Transfer[] memory erc20s = _erc20s(_wethTransfer(AMOUNT));
    ValidationParams[] memory vs = _validations(_validation(validator));
    GenericCall[] memory calls = _calls(_routerCall(0, hex'01'));
    uint256 deadline = block.timestamp + 1 hours;
    uint256 callsNonce = 60;

    bytes memory permitSig = _signPlainPermit(erc20s, 61, deadline);
    bytes memory callsSig = _signCallsApproval(ownerKey, owner, calls, callsNonce, deadline);

    uint256 before = IERC20(WETH).balanceOf(address(router));

    vm.prank(owner);
    (bytes[] memory results,) = hub.transferAndFulfill(
      owner,
      erc20s,
      new ERC721Transfer[](0),
      vs,
      deadline,
      _flags(true, false, false),
      _permit2AuthData(61, permitSig),
      calls,
      callsNonce,
      callsSig
    );

    assertEq(IERC20(WETH).balanceOf(address(router)) - before, AMOUNT, 'erc20 leg');
    assertEq(results.length, 1, 'one router result');
    assertEq(validator.sequenceLength(), 2, 'validator bracketed the order');

    // the nonce is spent even though nothing in the Permit2 signature covered the call list
    assertEq(
      hub.nonces(owner, callsNonce >> 8),
      1 << (callsNonce & 0xff),
      'calls nonce burned on a rail that witnesses nothing'
    );
  }

  /// AUTH-02 — a relayer submits, and the witness carries everything the permit does not
  function test_AUTH_02_permit2RelayedWithWitness() public {
    ERC20Transfer[] memory erc20s = _erc20s(_wethTransfer(AMOUNT));
    ERC721Transfer[] memory nfts = _erc721s(_nftTransfer(address(router)));
    GenericCall[] memory calls = _calls(_routerCall(0, hex'01'));
    uint256 deadline = block.timestamp + 1 hours;

    bytes memory signature = _signExecutionOrder(erc20s, nfts, calls, ANY, 1, deadline);

    uint256 balanceBefore = IERC20(WETH).balanceOf(address(router));

    vm.prank(relayer);
    (bytes[] memory results,) = hub.transferAndExecute(
      owner,
      erc20s,
      nfts,
      calls,
      deadline,
      _flags(true, false, false),
      _permit2AuthData(1, signature)
    );

    assertEq(IERC20(WETH).balanceOf(address(router)) - balanceBefore, AMOUNT, 'erc20 leg');
    assertEq(nft.ownerOf(NFT_ID), address(router), 'erc721 leg');
    assertEq(router.callCount(), 1, 'router called once');
    assertEq(results.length, 1, 'one result');
    assertEq(abi.decode(results[0], (uint256)), 1, 'result is the router return');
  }

  /// AUTH-03 — mutating a byte of the signed call list invalidates the order
  function test_AUTH_03_witnessPinsTheCallList() public {
    ERC20Transfer[] memory erc20s = _erc20s(_wethTransfer(AMOUNT));
    ERC721Transfer[] memory nfts = new ERC721Transfer[](0);
    GenericCall[] memory calls = _calls(_routerCall(0, hex'01'));
    uint256 deadline = block.timestamp + 1 hours;

    bytes memory signature = _signExecutionOrder(erc20s, nfts, calls, ANY, 2, deadline);

    // same order, one byte of call data changed
    GenericCall[] memory tampered = _calls(_routerCall(0, hex'02'));

    vm.prank(relayer);
    vm.expectRevert(PERMIT2_INVALID_SIGNER);
    hub.transferAndExecute(
      owner,
      erc20s,
      nfts,
      tampered,
      deadline,
      _flags(true, false, false),
      _permit2AuthData(2, signature)
    );
  }

  /// AUTH-04 — the caller identity in the digest is either the dead address or msg.sender
  function test_AUTH_04_pinnedCallerMustMatch() public {
    ERC20Transfer[] memory erc20s = _erc20s(_wethTransfer(AMOUNT));
    ERC721Transfer[] memory nfts = new ERC721Transfer[](0);
    GenericCall[] memory calls = new GenericCall[](0);
    uint256 deadline = block.timestamp + 1 hours;

    // owner names the relayer specifically
    bytes memory signature = _signExecutionOrder(erc20s, nfts, calls, relayer, 3, deadline);

    // the named relayer, with the pin flag set, succeeds
    vm.prank(relayer);
    hub.transferAndExecute(
      owner,
      erc20s,
      nfts,
      calls,
      deadline,
      _flags(true, false, true),
      _permit2AuthData(3, signature)
    );

    // a different submitter rebuilds a different digest
    bytes memory signature2 = _signExecutionOrder(erc20s, nfts, calls, relayer, 4, deadline);

    vm.prank(solver);
    vm.expectRevert(PERMIT2_INVALID_SIGNER);
    hub.transferAndExecute(
      owner,
      erc20s,
      nfts,
      calls,
      deadline,
      _flags(true, false, true),
      _permit2AuthData(4, signature2)
    );
  }

  /// AUTH-05 — an order signed for anyone cannot be submitted as a pinned one
  function test_AUTH_05_flagMustMatchTheSignedCaller() public {
    ERC20Transfer[] memory erc20s = _erc20s(_wethTransfer(AMOUNT));
    uint256 deadline = block.timestamp + 1 hours;

    bytes memory signature =
      _signExecutionOrder(erc20s, new ERC721Transfer[](0), new GenericCall[](0), ANY, 5, deadline);

    vm.prank(relayer);
    vm.expectRevert(PERMIT2_INVALID_SIGNER);
    hub.transferAndExecute(
      owner,
      erc20s,
      new ERC721Transfer[](0),
      new GenericCall[](0),
      deadline,
      _flags(true, false, true), // pinned, but the owner signed the open form
      _permit2AuthData(5, signature)
    );
  }

  /// AUTH-06 — an owner acting for themselves needs no signature at all
  function test_AUTH_06_ownerCallerNeedsNoAuth() public {
    ERC20Transfer[] memory erc20s = _erc20s(_wethTransfer(AMOUNT));
    uint256 balanceBefore = IERC20(WETH).balanceOf(address(router));

    vm.prank(owner);
    hub.transferAndExecute(
      owner,
      erc20s,
      new ERC721Transfer[](0),
      new GenericCall[](0),
      block.timestamp,
      _flags(false, false, false),
      ''
    );

    assertEq(IERC20(WETH).balanceOf(address(router)) - balanceBefore, AMOUNT);
  }

  /// AUTH-06b — the same, pulled through the owner's Permit2 allowance instead
  function test_AUTH_06b_ownerCallerViaPermit2Allowance() public {
    // the owner grants the hub a Permit2 allowance rather than a direct one
    vm.prank(owner);
    (bool ok,) = PERMIT2.call(
      abi.encodeWithSignature(
        'approve(address,address,uint160,uint48)',
        WETH,
        address(hub),
        type(uint160).max,
        uint48(block.timestamp + 1 days)
      )
    );
    assertTrue(ok);

    ERC20Transfer[] memory erc20s = _erc20s(_wethTransfer(AMOUNT));
    uint256 balanceBefore = IERC20(WETH).balanceOf(address(router));

    vm.prank(owner);
    hub.transferAndExecute(
      owner,
      erc20s,
      new ERC721Transfer[](0),
      new GenericCall[](0),
      block.timestamp,
      _flags(false, true, false),
      ''
    );

    assertEq(IERC20(WETH).balanceOf(address(router)) - balanceBefore, AMOUNT);
  }

  // -------------------------------------------------------------------------------------------
  // AUTH-07 — the fulfillment entry point over the Permit2 witness rail
  // -------------------------------------------------------------------------------------------

  /// @dev The witness names who may choose the calls rather than the calls themselves
  function test_AUTH_07_fulfillmentPermit2Witness() public {
    ERC20Transfer[] memory erc20s = _erc20s(_wethTransfer(AMOUNT));
    ERC721Transfer[] memory nfts = new ERC721Transfer[](0);
    ValidationParams[] memory vs = _validations(_validation(validator));
    GenericCall[] memory calls = _calls(_routerCall(0, hex'01'));
    uint256 deadline = block.timestamp + 1 hours;

    // no calls signature, so the owner is signing "any calls the solver picks"
    bytes memory signature = _signFulfillmentOrder(erc20s, nfts, vs, ANY, ANY, 30, deadline);

    uint256 before = IERC20(WETH).balanceOf(address(router));

    vm.prank(solver);
    (bytes[] memory results,) = hub.transferAndFulfill(
      owner,
      erc20s,
      nfts,
      vs,
      deadline,
      _flags(true, false, false),
      _permit2AuthData(30, signature),
      calls,
      0,
      ''
    );

    assertEq(IERC20(WETH).balanceOf(address(router)) - before, AMOUNT, 'erc20 leg');
    assertEq(results.length, 1, 'one router result');
    assertEq(validator.sequenceLength(), 2, 'validator saw both hooks');
  }

  /// AUTH-07b — the solver cannot swap in a different calls signer than the one signed
  function test_AUTH_07b_callsSignerIsBound() public {
    ERC20Transfer[] memory erc20s = _erc20s(_wethTransfer(AMOUNT));
    GenericCall[] memory calls = _calls(_routerCall(0, hex'01'));
    uint256 deadline = block.timestamp + 1 hours;

    // owner signs for an open call list
    bytes memory signature = _signFulfillmentOrder(
      erc20s, new ERC721Transfer[](0), new ValidationParams[](0), ANY, ANY, 31, deadline
    );

    // the solver instead presents a signed call list, which changes callsSigner in the witness
    bytes memory callsSig = _signCallsApproval(ownerKey, owner, calls, 31, deadline);

    vm.prank(solver);
    vm.expectRevert(PERMIT2_INVALID_SIGNER);
    hub.transferAndFulfill(
      owner,
      erc20s,
      new ERC721Transfer[](0),
      new ValidationParams[](0),
      deadline,
      _flags(true, false, false),
      _permit2AuthData(31, signature),
      calls,
      31,
      callsSig
    );
  }

  // -------------------------------------------------------------------------------------------
  // AUTH-08..13 — the delegated verifier rail
  // -------------------------------------------------------------------------------------------

  /// AUTH-08 — a verifier the owner never delegated is refused before it is ever called
  function test_AUTH_08_undelegatedVerifierRefused() public {
    vm.prank(relayer);
    vm.expectRevert(IAuthDelegator.NotDelegatedVerifier.selector);
    hub.transferAndExecute(
      owner,
      _erc20s(_wethTransfer(AMOUNT)),
      new ERC721Transfer[](0),
      new GenericCall[](0),
      block.timestamp,
      _flags(false, false, false),
      _verifierAuthData(address(verifier), 0, _encodeKey(key), hex'00')
    );
  }

  /// AUTH-09 — bit 1 is not signed, so the submitter picks which allowance the pull comes from
  function test_AUTH_09_allowanceRailIsSubmitterChosen() public {
    _delegateKeyThroughHub(key);
    _grantPermit2Allowance();

    uint256 deadline = block.timestamp + 1 hours;

    // identical orders, distinct nonces, differing only in the unsigned bit 1
    uint256 directBefore = IERC20(WETH).balanceOf(address(router));
    _executeOnVerifierRail(40, deadline, false);
    assertEq(IERC20(WETH).balanceOf(address(router)) - directBefore, AMOUNT, 'direct approval');

    uint256 permit2Before = IERC20(WETH).balanceOf(address(router));
    _executeOnVerifierRail(41, deadline, true);
    assertEq(IERC20(WETH).balanceOf(address(router)) - permit2Before, AMOUNT, 'permit2 allowance');
  }

  /// AUTH-11 — the exact bytes handed to the verifier, discriminator byte included
  function test_AUTH_11_verifierReceivesExactPayload() public {
    _delegateKeyThroughHub(key);

    ERC20Transfer[] memory erc20s = _erc20s(_wethTransfer(AMOUNT));
    ERC721Transfer[] memory nfts = new ERC721Transfer[](0);
    GenericCall[] memory calls = _calls(_routerCall(0, hex'01'));
    uint256 nonce = 42;
    uint256 deadline = block.timestamp + 1 hours;

    // rebuilt here rather than read from the hub: abi.encode(...) plus one trailing false byte
    bytes memory expected = abi.encodePacked(abi.encode(ANY, erc20s, nfts, calls), false);

    bytes memory sig = _sign(
      sessionKeyPk,
      lTypedDataHash(
        _verifierDomain(), lExecutionApproval(ANY, erc20s, nfts, calls, nonce, deadline)
      )
    );
    bytes memory authData = _verifierAuthData(address(verifier), nonce, _encodeKey(key), sig);

    vm.expectCall(
      address(verifier),
      abi.encodeCall(
        IAuthVerifier.verifyAuth, (owner, expected, nonce, deadline, _encodeKey(key), sig)
      )
    );

    vm.prank(relayer);
    hub.transferAndExecute(
      owner, erc20s, nfts, calls, deadline, _flags(false, false, false), authData
    );
  }

  /// AUTH-12 — only the low three bits are read, so higher bits change nothing
  function test_AUTH_12_higherFlagBitsAreIgnored() public {
    _delegateKeyThroughHub(key);

    uint256 deadline = block.timestamp + 1 hours;
    uint256 before = IERC20(WETH).balanceOf(address(router));

    // every bit above the third set, plus the same low bits as a plain verifier-rail order
    bytes32 raw = bytes32(type(uint256).max << 3);

    _executeOnVerifierRailWithFlags(43, deadline, AuthFlags.wrap(raw));

    assertEq(IERC20(WETH).balanceOf(address(router)) - before, AMOUNT, 'behaves as flags 0');
  }

  /// AUTH-13 — authData too short to hold a signature is rejected by the decoder
  function test_AUTH_13_malformedAuthDataRejected() public {
    _delegateKeyThroughHub(key);

    vm.prank(relayer);
    vm.expectRevert(SLICE_OUT_OF_BOUNDS);
    hub.transferAndExecute(
      owner,
      _erc20s(_wethTransfer(AMOUNT)),
      new ERC721Transfer[](0),
      new GenericCall[](0),
      block.timestamp,
      _flags(false, false, false),
      abi.encode(address(verifier), uint256(0))
    );
  }

  // -------------------------------------------------------------------------------------------
  // EX-FUZZ / FU-FUZZ
  // -------------------------------------------------------------------------------------------

  struct OrderFuzz {
    uint160 amount;
    uint8 callCount;
    bool usePermit2Allowance;
    uint256 deadlineOffset;
    uint96 msgValue;
    bool moveNft;
  }

  /// @dev `transferAndFulfill` reads a different set of dimensions, so it gets its own shape
  struct FulfillFuzz {
    uint160 amount;
    uint8 callCount;
    uint256 deadlineOffset;
    bool moveNft;
  }

  struct RelayedFuzz {
    uint160 amount;
    uint8 callCount;
    bool pinCaller;
    uint256 deadlineOffset;
    uint256 permitNonce;
  }

  function testFuzz_EX_FUZZ_ownerRail(OrderFuzz memory f) public {
    f.amount = uint160(bound(f.amount, 0, 100 ether));
    f.callCount = uint8(bound(f.callCount, 0, 3));
    f.deadlineOffset = bound(f.deadlineOffset, 0, 30 days);
    f.msgValue = uint96(bound(f.msgValue, 0, 5 ether));
    if (f.usePermit2Allowance) _grantPermit2Allowance();

    // the whole value goes to the first call, so the guard sees an exactly-spent batch
    GenericCall[] memory calls = new GenericCall[](f.callCount);
    for (uint256 i = 0; i < f.callCount; i++) {
      calls[i] = _routerCall(i == 0 ? f.msgValue : 0, abi.encodePacked(uint8(i)));
    }
    uint256 value = f.callCount == 0 ? 0 : f.msgValue;

    ERC721Transfer[] memory nfts =
      f.moveNft ? _erc721s(_nftTransfer(address(router2))) : new ERC721Transfer[](0);

    uint256 before = IERC20(WETH).balanceOf(address(router));
    uint256 routerNative = address(router).balance;
    uint256 untouched = IERC20(WETH).balanceOf(recipient);
    vm.deal(owner, value);

    uint256 gasBudget = gasleft();

    vm.prank(owner);
    (bytes[] memory results, uint256 gasUsed) = hub.transferAndExecute{value: value}(
      owner,
      _erc20s(_wethTransfer(f.amount)),
      nfts,
      calls,
      block.timestamp + f.deadlineOffset,
      _flags(false, f.usePermit2Allowance, false),
      ''
    );

    assertEq(IERC20(WETH).balanceOf(address(router)) - before, f.amount, 'exact amount moved');
    assertEq(address(router).balance - routerNative, value, 'native forwarded, none stranded');
    assertEq(results.length, f.callCount, 'one result per call');
    assertEq(router.callCount(), f.callCount, 'router called once per entry');
    assertEq(IERC20(WETH).balanceOf(recipient), untouched, 'unnamed account untouched');
    if (f.moveNft) assertEq(nft.ownerOf(NFT_ID), address(router2), 'nft leg');
    assertGt(gasUsed, 0, 'gasUsed is reported');
    assertLt(gasUsed, gasBudget, 'gasUsed cannot exceed what was available');
  }

  /// @dev The relayed Permit2 rail, where the caller-pinning flag is actually meaningful
  function testFuzz_EX_FUZZ_relayedPermit2Rail(RelayedFuzz memory f) public {
    f.amount = uint160(bound(f.amount, 0, 100 ether));
    f.callCount = uint8(bound(f.callCount, 0, 3));
    f.deadlineOffset = bound(f.deadlineOffset, 1, 30 days);
    uint256 deadline = block.timestamp + f.deadlineOffset;

    GenericCall[] memory calls = new GenericCall[](f.callCount);
    for (uint256 i = 0; i < f.callCount; i++) {
      calls[i] = _routerCall(0, abi.encodePacked(uint8(i)));
    }

    ERC20Transfer[] memory erc20s = _erc20s(_wethTransfer(f.amount));
    address signedCaller = f.pinCaller ? relayer : ANY;

    bytes memory signature = _signExecutionOrder(
      erc20s, new ERC721Transfer[](0), calls, signedCaller, f.permitNonce, deadline
    );

    uint256 before = IERC20(WETH).balanceOf(address(router));

    vm.prank(relayer);
    (bytes[] memory results,) = hub.transferAndExecute(
      owner,
      erc20s,
      new ERC721Transfer[](0),
      calls,
      deadline,
      _flags(true, false, f.pinCaller),
      _permit2AuthData(f.permitNonce, signature)
    );

    assertEq(IERC20(WETH).balanceOf(address(router)) - before, f.amount, 'exact amount moved');
    assertEq(results.length, f.callCount, 'one result per call');
  }

  function testFuzz_FU_FUZZ_ownerRail(FulfillFuzz memory f) public {
    f.amount = uint160(bound(f.amount, 0, 100 ether));
    f.callCount = uint8(bound(f.callCount, 0, 3));
    f.deadlineOffset = bound(f.deadlineOffset, 0, 30 days);

    GenericCall[] memory calls = new GenericCall[](f.callCount);
    for (uint256 i = 0; i < f.callCount; i++) {
      calls[i] = _routerCall(0, abi.encodePacked(uint8(i)));
    }

    ERC721Transfer[] memory nfts =
      f.moveNft ? _erc721s(_nftTransfer(address(router2))) : new ERC721Transfer[](0);

    uint256 before = IERC20(WETH).balanceOf(address(router));

    vm.prank(owner);
    (bytes[] memory results,) = hub.transferAndFulfill(
      owner,
      _erc20s(_wethTransfer(f.amount)),
      nfts,
      _validations(_validation(validator)),
      block.timestamp + f.deadlineOffset,
      _flags(false, false, false),
      '',
      calls,
      0,
      ''
    );

    assertEq(IERC20(WETH).balanceOf(address(router)) - before, f.amount, 'exact amount moved');
    assertEq(results.length, f.callCount, 'one result per call');
    assertEq(validator.sequenceLength(), 2, 'validator bracketed the order');
    if (f.moveNft) assertEq(nft.ownerOf(NFT_ID), address(router2), 'nft leg');
  }

  // -------------------------------------------------------------------------------------------

  function _grantPermit2Allowance() private {
    vm.prank(owner);
    (bool ok,) = PERMIT2.call(
      abi.encodeWithSignature(
        'approve(address,address,uint160,uint48)',
        WETH,
        address(hub),
        type(uint160).max,
        uint48(block.timestamp + 30 days)
      )
    );
    assertTrue(ok, 'permit2 approve');
  }

  function _executeOnVerifierRail(uint256 nonce, uint256 deadline, bool permit2Allowance) private {
    _executeOnVerifierRailWithFlags(nonce, deadline, _flags(false, permit2Allowance, false));
  }

  function _executeOnVerifierRailWithFlags(uint256 nonce, uint256 deadline, AuthFlags flags)
    private
  {
    ERC20Transfer[] memory erc20s = _erc20s(_wethTransfer(AMOUNT));
    GenericCall[] memory calls = new GenericCall[](0);

    bytes memory sig = _sign(
      sessionKeyPk,
      lTypedDataHash(
        _verifierDomain(),
        lExecutionApproval(ANY, erc20s, new ERC721Transfer[](0), calls, nonce, deadline)
      )
    );

    vm.prank(relayer);
    hub.transferAndExecute(
      owner,
      erc20s,
      new ERC721Transfer[](0),
      calls,
      deadline,
      flags,
      _verifierAuthData(address(verifier), nonce, _encodeKey(key), sig)
    );
  }
}
