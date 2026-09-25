// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {VerifierBase} from 'test/verifiers/base/VerifierBase.sol';

import {
  ERC20PermitMock,
  ERC721PermitV3Mock,
  ERC721PermitV4Mock,
  ReentrantPermitMock
} from 'test/v2/mocks/PermitTokenMocks.sol';

import {IAuthVerifier} from 'src/base/interfaces/IAuthVerifier.sol';
import {ICallsForwarder} from 'src/base/interfaces/ICallsForwarder.sol';
import {PackedBits} from 'src/base/types/PackedBits.sol';

import {IKSAllowanceHubV2} from 'src/v2/interfaces/IKSAllowanceHubV2.sol';
import {ERC20Transfer} from 'src/v2/types/ERC20Transfer.sol';
import {ERC721Transfer} from 'src/v2/types/ERC721Transfer.sol';
import {GenericCall} from 'src/v2/types/GenericCall.sol';

import {ISessionAuthVerifier} from 'src/verifiers/interfaces/ISessionAuthVerifier.sol';
import {SessionKey} from 'src/verifiers/types/SessionKey.sol';

import {IAllowanceTransfer} from 'ks-common-sc/src/interfaces/IAllowanceTransfer.sol';
import {ICommon} from 'ks-common-sc/src/interfaces/ICommon.sol';

import {IERC20} from 'openzeppelin-contracts/contracts/token/ERC20/IERC20.sol';
import {ERC20Permit} from 'openzeppelin-contracts/contracts/token/ERC20/extensions/ERC20Permit.sol';
import {Pausable} from 'openzeppelin-contracts/contracts/utils/Pausable.sol';

/**
 * @title PermitsTest
 * @notice B5 — `PF-01..09`, `PF-FUZZ` and `FWD-13..19`: the self-authorising calls
 * {ICallsForwarder-forward} relays, its selector allowlist, its per-entry failure bits and the
 * things it deliberately does not guard.
 * @dev `forward` makes a plain `call` per entry, so the observable oracle is never the return
 * value: it is the allowance, approval or nonce the target holds afterwards. Every digest here is
 * built from a type string written out in this file from EIP-2612, the DAI permit and the ERC-721
 * permit drafts, and every relayed call is assembled from a hand-written function signature — no
 * production constant, and in particular no production selector, appears on the expected side of
 * any assertion.
 */
contract PermitsTest is VerifierBase {
  // -----------------------------------------------------------------------------------------------
  // Literal type strings
  // -----------------------------------------------------------------------------------------------

  string internal constant L_EIP2612_PERMIT =
    'Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)';
  string internal constant L_DAI_PERMIT =
    'Permit(address holder,address spender,uint256 nonce,uint256 expiry,bool allowed)';
  string internal constant L_ERC721_PERMIT =
    'Permit(address spender,uint256 tokenId,uint256 nonce,uint256 deadline)';
  string internal constant L_PERMIT2_DETAILS =
    'PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)';
  string internal constant L_PERMIT2_BATCH_STUB =
    'PermitBatch(PermitDetails[] details,address spender,uint256 sigDeadline)';
  /// @dev The batch stub's sibling, for the other Permit2 overload on the allowlist
  string internal constant L_PERMIT2_SINGLE_STUB =
    'PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)';

  // -----------------------------------------------------------------------------------------------
  // Literal function signatures, transcribed from the same sources
  // -----------------------------------------------------------------------------------------------

  string internal constant S_EIP2612_PERMIT =
    'permit(address,address,uint256,uint256,uint8,bytes32,bytes32)';
  string internal constant S_DAI_PERMIT =
    'permit(address,address,uint256,uint256,bool,uint8,bytes32,bytes32)';
  string internal constant S_ERC721_V3_PERMIT =
    'permit(address,uint256,uint256,uint8,bytes32,bytes32)';
  string internal constant S_ERC721_V4_PERMIT = 'permit(address,uint256,uint256,uint256,bytes)';
  string internal constant S_PERMIT2_BATCH_PERMIT =
    'permit(address,((address,uint160,uint48,uint48)[],address,uint256),bytes)';
  string internal constant S_PERMIT2_SINGLE_PERMIT =
    'permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)';

  /// @dev The seventh entry on the allowlist, transcribed from {IAuthVerifier}
  string internal constant S_UPDATE_AUTH = 'updateAuth(address,bytes,uint256,uint256,bytes)';

  /// @dev Its two neighbours on the same interface, which the allowlist must NOT carry
  string internal constant S_INIT_AUTH = 'initAuth(address,bytes)';
  string internal constant S_VERIFY_AUTH = 'verifyAuth(address,bytes,uint256,uint256,bytes,bytes)';

  /// @dev Anything outside the allowlist; the forwarder must refuse it by name
  string internal constant S_ERC20_TRANSFER = 'transfer(address,uint256)';

  /// @dev The canonical DAI, which is the reference implementation of the seven-word permit
  address internal constant DAI = 0x6B175474E89094C44Da98b954EedeAC495271d0F;

  uint256 internal constant PERMIT_NFT_ID = 7;

  ERC20PermitMock internal permitToken;
  ERC20PermitMock internal permitToken2;
  ERC721PermitV3Mock internal nftV3;
  ERC721PermitV4Mock internal nftV4;

  struct PermitFuzz {
    uint8 entryCount;
    uint8 validMask;
    uint256 allowFailure;
    uint256 deadlineOffset;
  }

  function setUp() public override {
    super.setUp();

    permitToken = new ERC20PermitMock('Permit Token');
    permitToken2 = new ERC20PermitMock('Permit Token Two');
    permitToken.mint(owner, 1000 ether);
    permitToken2.mint(owner, 1000 ether);

    nftV3 = new ERC721PermitV3Mock();
    nftV4 = new ERC721PermitV4Mock();
    nftV3.mint(owner, PERMIT_NFT_ID);
    nftV4.mint(owner, PERMIT_NFT_ID);
  }

  // -----------------------------------------------------------------------------------------------
  // PF-01..05 — one case per selector on the allowlist that a token or Permit2 answers
  // -----------------------------------------------------------------------------------------------

  /// PF-01 — an EIP-2612 permit is relayed to the token and lands as an allowance
  function test_PF_01_eip2612PermitForwarded() public {
    uint256 value = 123 ether;
    uint256 deadline = block.timestamp + 1 hours;

    bytes[] memory data = new bytes[](1);
    data[0] = _erc2612Call('Permit Token', address(permitToken), address(hub), value, 0, deadline);

    // anyone may relay someone else's permit: the signature inside is the authorisation, and the
    // forwarder — not the relayer — is the `msg.sender` the token sees
    vm.prank(relayer);
    bytes[] memory results = hub.forward(_one(address(permitToken)), data, _bits(0));

    assertEq(permitToken.allowance(owner, address(hub)), value, 'allowance');
    assertEq(permitToken.nonces(owner), 1, 'nonce consumed');
    assertEq(results.length, 1, 'one result per entry');
    assertEq(results[0].length, 0, 'an EIP-2612 permit returns nothing');
  }

  /// PF-02 — the DAI-flavoured permit, against the real DAI on the fork
  function test_PF_02_daiStylePermitForwarded() public {
    uint256 nonce = _daiNonce(owner);
    uint256 expiry = block.timestamp + 1 hours;

    bytes32 structHash = keccak256(
      abi.encode(keccak256(bytes(L_DAI_PERMIT)), owner, address(hub), nonce, expiry, true)
    );
    (uint8 v, bytes32 r, bytes32 s) =
      vm.sign(ownerKey, lTypedDataHash(_daiDomainSeparator(), structHash));

    bytes[] memory data = new bytes[](1);
    data[0] =
      abi.encodeWithSignature(S_DAI_PERMIT, owner, address(hub), nonce, expiry, true, v, r, s);

    vm.prank(relayer);
    hub.forward(_one(DAI), data, _bits(0));

    // DAI reads `allowed` as all-or-nothing rather than as an amount
    assertEq(_daiAllowance(owner, address(hub)), type(uint256).max, 'allowance');
    assertEq(_daiNonce(owner), nonce + 1, 'nonce consumed');
  }

  /// PF-03 — the ERC-721 permit as Uniswap v3 shipped it, with the signature split into v/r/s
  function test_PF_03_erc721V3PermitForwarded() public {
    uint256 deadline = block.timestamp + 1 hours;

    bytes32 structHash = keccak256(
      abi.encode(
        keccak256(bytes(L_ERC721_PERMIT)), address(hub), PERMIT_NFT_ID, uint256(0), deadline
      )
    );
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(
      ownerKey, lTypedDataHash(lDomainSeparator('V3 Permit NFT', '1', address(nftV3)), structHash)
    );

    bytes[] memory data = new bytes[](1);
    data[0] =
      abi.encodeWithSignature(S_ERC721_V3_PERMIT, address(hub), PERMIT_NFT_ID, deadline, v, r, s);

    vm.prank(relayer);
    hub.forward(_one(address(nftV3)), data, _bits(0));

    assertEq(nftV3.getApproved(PERMIT_NFT_ID), address(hub), 'approval');
    assertEq(nftV3.nonces(PERMIT_NFT_ID), 1, 'nonce consumed');
  }

  /// PF-04 — and as v4 shipped it, with an unordered nonce and a packed signature
  function test_PF_04_erc721V4PermitForwarded() public {
    uint256 deadline = block.timestamp + 1 hours;
    uint256 nonce = 99;

    bytes[] memory data = new bytes[](1);
    data[0] = _erc721V4Call(address(hub), deadline, nonce);

    vm.prank(relayer);
    hub.forward(_one(address(nftV4)), data, _bits(0));

    assertEq(nftV4.getApproved(PERMIT_NFT_ID), address(hub), 'approval');
    assertTrue(nftV4.nonceUsed(owner, nonce), 'nonce consumed');
  }

  /// PF-05 — Permit2's batch `permit`, one of the two overloads written out in the allowlist
  function test_PF_05_permit2BatchPermitForwarded() public {
    uint160 amount = 42 ether;
    uint48 expiration = uint48(block.timestamp + 1 days);
    uint256 sigDeadline = block.timestamp + 1 hours;

    IAllowanceTransfer.PermitBatch memory batch =
      _permit2Batch(WETH, amount, expiration, 0, address(hub), sigDeadline);
    bytes memory signature = _sign(ownerKey, _permit2BatchDigest(batch));

    bytes[] memory data = new bytes[](1);
    data[0] = abi.encodeWithSignature(S_PERMIT2_BATCH_PERMIT, owner, batch, signature);

    vm.prank(relayer);
    hub.forward(_one(PERMIT2), data, _bits(0));

    (uint160 allowed, uint48 storedExpiration, uint48 storedNonce) =
      IAllowanceTransfer(PERMIT2).allowance(owner, WETH, address(hub));

    assertEq(allowed, amount, 'allowance');
    assertEq(storedExpiration, expiration, 'expiration');
    assertEq(storedNonce, 1, 'nonce bumped');
  }

  // -----------------------------------------------------------------------------------------------
  // PF-06..07 — the two guards that refuse a batch outright
  // -----------------------------------------------------------------------------------------------

  /**
   * PF-06 — a selector outside the allowlist is refused by name, whatever its failure bit says
   * @dev The allowlist is the whole of the forwarder's safety, because the forwarder is the
   * `msg.sender` every target sees. So the refusal has to come before the call, and it has to be
   * unconditional: `allowFailure` only covers a call that was made and reverted.
   */
  function test_PF_06_unsupportedSelectorRefused() public {
    bytes[] memory data = new bytes[](1);
    data[0] = abi.encodeWithSignature(S_ERC20_TRANSFER, relayer, uint256(1));

    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(
        ICallsForwarder.NotSupportedSelector.selector, bytes4(keccak256(bytes(S_ERC20_TRANSFER)))
      )
    );
    hub.forward(_one(address(permitToken)), data, _bits(0));

    // a set failure bit does not turn the refusal into a skipped entry
    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(
        ICallsForwarder.NotSupportedSelector.selector, bytes4(keccak256(bytes(S_ERC20_TRANSFER)))
      )
    );
    hub.forward(_one(address(permitToken)), data, _bits(type(uint256).max));

    // a payload too short to hold a selector reads as zero, which matches nothing
    bytes[] memory empty = new bytes[](1);
    empty[0] = '';

    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(ICallsForwarder.NotSupportedSelector.selector, bytes4(0))
    );
    hub.forward(_one(address(permitToken)), empty, _bits(0));
  }

  /// PF-06b — the refusal unwinds the entries that already ran ahead of it
  function test_PF_06b_unsupportedSelectorUnwindsTheBatch() public {
    uint256 value = 11 ether;
    uint256 deadline = block.timestamp + 1 hours;

    address[] memory targets = new address[](2);
    targets[0] = address(permitToken);
    targets[1] = address(permitToken);

    bytes[] memory data = new bytes[](2);
    data[0] = _erc2612Call('Permit Token', address(permitToken), address(hub), value, 0, deadline);
    data[1] = abi.encodeWithSignature(S_ERC20_TRANSFER, relayer, uint256(1));

    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(
        ICallsForwarder.NotSupportedSelector.selector, bytes4(keccak256(bytes(S_ERC20_TRANSFER)))
      )
    );
    hub.forward(targets, data, _bits(0));

    assertEq(permitToken.allowance(owner, address(hub)), 0, 'the earlier permit rolled back');
    assertEq(permitToken.nonces(owner), 0, 'and burned nothing');
  }

  /// PF-07 — the two arrays are walked in step, so a mismatch is refused before any call
  function test_PF_07_mismatchedArrayLengths() public {
    address[] memory twoTargets = new address[](2);
    twoTargets[0] = address(permitToken);
    twoTargets[1] = address(permitToken2);

    vm.expectRevert(ICommon.MismatchedArrayLengths.selector);
    hub.forward(twoTargets, new bytes[](1), _bits(0));

    vm.expectRevert(ICommon.MismatchedArrayLengths.selector);
    hub.forward(_one(address(permitToken)), new bytes[](2), _bits(0));
  }

  // -----------------------------------------------------------------------------------------------
  // PF-08..09 — the two directions of a failure bit
  // -----------------------------------------------------------------------------------------------

  /// PF-08 — with its bit clear, a failing call bubbles its own revert and takes the batch with it
  function test_PF_08_failingCallBubblesWhenNotAllowed() public {
    uint256 value = 7 ether;
    uint256 expired = block.timestamp - 1;

    (address[] memory targets, bytes[] memory data) = _goodThenExpired(value, expired);

    vm.prank(relayer);
    vm.expectRevert(abi.encodeWithSelector(ERC20Permit.ERC2612ExpiredSignature.selector, expired));
    hub.forward(targets, data, _bits(0));

    assertEq(permitToken.allowance(owner, address(hub)), 0, 'the good permit rolled back too');
    assertEq(permitToken.nonces(owner), 0, 'nothing consumed');
  }

  /// PF-09 — with its bit set, the same failure is recorded as a result and the batch carries on
  function test_PF_09_failingCallIsCarriedPastWhenAllowed() public {
    uint256 value = 7 ether;
    uint256 expired = block.timestamp - 1;

    (address[] memory targets, bytes[] memory data) = _goodThenExpired(value, expired);

    vm.prank(relayer);
    bytes[] memory results = hub.forward(targets, data, _bits(1 << 1));

    assertEq(permitToken.allowance(owner, address(hub)), value, 'the good permit landed');
    assertEq(permitToken.nonces(owner), 1, 'and consumed exactly its own nonce');

    assertEq(results.length, 2, 'one result per entry');
    assertEq(results[0].length, 0, 'the permit that worked returned nothing');
    assertEq(
      results[1],
      abi.encodeWithSelector(ERC20Permit.ERC2612ExpiredSignature.selector, expired),
      'the one that failed returned its revert data'
    );
  }

  // -----------------------------------------------------------------------------------------------
  // PF-FUZZ
  // -----------------------------------------------------------------------------------------------

  /**
   * PF-FUZZ — a batch settles exactly when every entry that fails has its own bit set
   * @dev Each entry is an EIP-2612 permit against the same token: a valid one carries the next
   * sequential nonce, an invalid one is past its deadline and so consumes nothing, which keeps
   * that sequence intact whichever entries are skipped. The token's own allowance and nonce
   * counter are the oracle, never the call's return.
   */
  function testFuzz_PF_FUZZ_allowFailureBits(PermitFuzz memory f) public {
    uint256 count = bound(f.entryCount, 1, 4);
    uint256 deadline = block.timestamp + bound(f.deadlineOffset, 1, 30 days);
    uint256 expired = block.timestamp - 1;
    PackedBits allowFailure = _bits(f.allowFailure);

    address[] memory targets = new address[](count);
    bytes[] memory data = new bytes[](count);

    uint256 validCount;
    uint256 lastValidValue;
    bool bubbles;

    for (uint256 i = 0; i < count; i++) {
      targets[i] = address(permitToken);
      bool valid = (uint256(f.validMask) >> i) & 1 == 1;

      if (valid) {
        uint256 value = (i + 1) * 1 ether;
        data[i] = _erc2612Call(
          'Permit Token', address(permitToken), address(hub), value, validCount, deadline
        );
        validCount++;
        lastValidValue = value;
      } else {
        data[i] =
          _erc2612Call('Permit Token', address(permitToken), address(hub), 1 ether, 0, expired);
        // the first unallowed failure is what the whole batch reverts with
        if (!allowFailure.pos(i)) bubbles = true;
      }
    }

    if (bubbles) {
      vm.prank(relayer);
      vm.expectRevert(abi.encodeWithSelector(ERC20Permit.ERC2612ExpiredSignature.selector, expired));
      hub.forward(targets, data, allowFailure);

      assertEq(permitToken.allowance(owner, address(hub)), 0, 'the whole batch rolled back');
      assertEq(permitToken.nonces(owner), 0, 'and burned no nonce');
      return;
    }

    vm.prank(relayer);
    bytes[] memory results = hub.forward(targets, data, allowFailure);

    assertEq(results.length, count, 'one result per entry');
    assertEq(permitToken.nonces(owner), validCount, 'one nonce per permit that worked');
    assertEq(
      permitToken.allowance(owner, address(hub)),
      lastValidValue,
      'the last permit that worked is the allowance that stands'
    );

    for (uint256 i = 0; i < count; i++) {
      bool valid = (uint256(f.validMask) >> i) & 1 == 1;
      if (valid) {
        assertEq(results[i].length, 0, 'a permit that worked returns nothing');
      } else {
        assertEq(
          results[i],
          abi.encodeWithSelector(ERC20Permit.ERC2612ExpiredSignature.selector, expired),
          'a skipped entry carries its revert data'
        );
      }
    }
  }

  // -----------------------------------------------------------------------------------------------
  // FWD-13..16 — the `updateAuth` arm of the allowlist, and the two neighbours it must not carry
  // -----------------------------------------------------------------------------------------------

  /**
   * FWD-13 — a relayed `updateAuth` approves a session key, on the verifier's own nonce
   * @dev The seventh selector is not a token permit at all: it is the owner telling a verifier
   * which credential may sign for them, relayed so the approval and the order that uses it fit in
   * one transaction. The verifier owns the replay protection for it, so its bitmap moves and the
   * hub's does not — the hub is only the postman here and burns nothing of its own.
   */
  function test_FWD_13_updateAuthIsRelayedAndApprovesTheKey() public {
    SessionKey memory fresh = _secpKey(sessionSigner, block.timestamp + 30 days);
    uint256 nonce = 300;
    uint256 deadline = block.timestamp + 1 hours;

    bytes32 freshHash = _keyHash(fresh);
    bytes memory approvalSig = _signSessionApproval(fresh, true, nonce, deadline);

    bytes[] memory data = new bytes[](1);
    data[0] = abi.encodeWithSignature(
      S_UPDATE_AUTH, owner, _approveKey(fresh), nonce, deadline, approvalSig
    );

    vm.prank(relayer);
    bytes[] memory results = hub.forward(_one(address(verifier)), data, _bits(0));

    assertTrue(verifier.approvedKeys(owner, freshHash), 'the key is approved');
    assertEq(
      verifier.nonces(owner, nonce >> 8), 1 << (nonce & 0xff), 'the verifier burned that nonce'
    );
    assertEq(hub.nonces(owner, nonce >> 8), 0, 'and the hub burned nothing on this route');
    assertEq(results[0].length, 0, 'updateAuth returns nothing');
  }

  /**
   * FWD-14 — the same call with an empty signature is refused even when the owner sends it
   * @dev `forward` does `targets[i].call(...)`, so the `msg.sender` the verifier sees is the hub,
   * never the account that submitted the transaction. The verifier's owner branch is therefore out
   * of reach from here, and the empty signature that branch would have accepted is checked instead
   * — and fails. This is the line that stops the hub being a trusted authenticator for anybody:
   * if the verifier took the hub's word for who the owner was, this call would approve a key for
   * `owner` on nothing but the say-so of whoever paid for the gas.
   */
  function test_FWD_14_emptySignatureIsRefusedEvenFromTheOwner() public {
    SessionKey memory fresh = _secpKey(recipient, block.timestamp + 30 days);
    uint256 nonce = 301;
    uint256 deadline = block.timestamp + 1 hours;

    bytes32 freshHash = _keyHash(fresh);
    bytes memory noSignature = '';

    bytes[] memory data = new bytes[](1);
    data[0] = abi.encodeWithSignature(
      S_UPDATE_AUTH, owner, _approveKey(fresh), nonce, deadline, noSignature
    );
    address[] memory targets = _one(address(verifier));

    vm.prank(owner);
    vm.expectRevert(ISessionAuthVerifier.InvalidApprovalSignature.selector);
    hub.forward(targets, data, _bits(0));

    assertFalse(verifier.approvedKeys(owner, freshHash), 'nothing was approved');

    // the same instruction, from the same account, straight at the verifier: there the owner IS
    // `msg.sender` and the empty signature is accepted, which is what makes the refusal above
    // evidence about the hop through the hub rather than about the payload
    vm.prank(owner);
    verifier.updateAuth(owner, _approveKey(fresh), nonce, deadline, noSignature);
    assertTrue(verifier.approvedKeys(owner, freshHash), 'accepted when the owner calls directly');
  }

  /**
   * FWD-15 — `forward` reaches a verifier the owner never delegated
   * @dev Deliberate, and worth pinning because the order rails do gate on the delegation: the
   * hub's `_verifyAuth` refuses an undelegated verifier outright. The forwarder has no such gate
   * and needs none — `updateAuth` carries the owner's own signature, so a verifier the owner has
   * not delegated is simply a verifier whose opinion the hub will never ask for.
   */
  function test_FWD_15_forwardReachesAnUndelegatedVerifier() public {
    SessionKey memory fresh = _secpKey(sessionSigner, block.timestamp + 30 days);
    uint256 nonce = 302;
    uint256 deadline = block.timestamp + 1 hours;

    assertFalse(hub.authDelegated(owner, address(verifier)), 'the owner never delegated it');

    bytes32 freshHash = _keyHash(fresh);
    bytes memory approvalSig = _signSessionApproval(fresh, true, nonce, deadline);

    bytes[] memory data = new bytes[](1);
    data[0] = abi.encodeWithSignature(
      S_UPDATE_AUTH, owner, _approveKey(fresh), nonce, deadline, approvalSig
    );

    vm.prank(relayer);
    hub.forward(_one(address(verifier)), data, _bits(0));

    assertTrue(verifier.approvedKeys(owner, freshHash), 'the key was approved anyway');
    assertFalse(hub.authDelegated(owner, address(verifier)), 'and still nothing is delegated');
  }

  /**
   * FWD-16 — `initAuth` and `verifyAuth` are not on the allowlist, and must never be
   * @dev The security-critical half of the allowlist. `initAuth` takes no signature, nonce or
   * deadline: it trusts its caller absolutely, and the hub is the caller every forwarded call
   * arrives as. Were its selector relayable, anyone could hand a verifier an arbitrary key for an
   * arbitrary owner and then sign that owner's orders with it. `verifyAuth` is the same shape of
   * hazard pointed at the order rails. Both selectors are rebuilt here from signature strings
   * written out by hand, because deriving them from the production interface would let a wrong
   * signature there agree with a wrong expectation here.
   */
  function test_FWD_16_initAuthAndVerifyAuthAreNotForwardable() public {
    SessionKey memory victimKey = _secpKey(relayer, block.timestamp + 30 days);
    bytes32 victimHash = _keyHash(victimKey);
    bytes memory payload = _encodeKey(victimKey);

    address[] memory targets = _one(address(verifier));

    bytes[] memory initData = new bytes[](1);
    initData[0] = abi.encodeWithSignature(S_INIT_AUTH, owner, payload);

    bytes[] memory verifyData = new bytes[](1);
    verifyData[0] = abi.encodeWithSignature(
      S_VERIFY_AUTH, owner, payload, uint256(0), block.timestamp, payload, payload
    );

    // First, that the two strings above really do name those entry points. Both the calldata and
    // the expected selector below are derived from them, so a mistyped signature would agree with
    // itself and the refusals would prove nothing. Sent straight at the verifier they reach its
    // hub-only gate and come back with its error — which a selector matching no function could
    // not do, since the verifier has no fallback and would revert with nothing at all.
    (bool initOk, bytes memory initRet) = address(verifier).call(initData[0]);
    assertFalse(initOk, 'initAuth refused the call');
    assertEq(
      initRet,
      abi.encodeWithSelector(IAuthVerifier.NotAllowanceHub.selector),
      'and refused it at the hub-only gate, so the selector reached the real initAuth'
    );

    (bool verifyOk, bytes memory verifyRet) = address(verifier).call(verifyData[0]);
    assertFalse(verifyOk, 'verifyAuth refused the call');
    assertEq(
      verifyRet,
      abi.encodeWithSelector(IAuthVerifier.NotAllowanceHub.selector),
      'likewise, so that selector reached the real verifyAuth'
    );

    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(
        ICallsForwarder.NotSupportedSelector.selector, bytes4(keccak256(bytes(S_INIT_AUTH)))
      )
    );
    hub.forward(targets, initData, _bits(0));

    assertFalse(verifier.approvedKeys(owner, victimHash), 'no key was planted on the owner');

    // a set failure bit does not downgrade the refusal into a skipped entry: the check runs
    // before the call, and `allowFailure` only ever covers a call that was made and reverted
    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(
        ICallsForwarder.NotSupportedSelector.selector, bytes4(keccak256(bytes(S_INIT_AUTH)))
      )
    );
    hub.forward(targets, initData, _bits(type(uint256).max));

    // and the verification entry point is refused by the same list
    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(
        ICallsForwarder.NotSupportedSelector.selector, bytes4(keccak256(bytes(S_VERIFY_AUTH)))
      )
    );
    hub.forward(targets, verifyData, _bits(0));

    // the control: on the same target, in the same shape, the one selector that IS listed goes
    // through — so the two refusals above are about those selectors and not about the verifier
    uint256 nonce = 303;
    uint256 deadline = block.timestamp + 1 hours;
    bytes memory approvalSig = _signSessionApproval(victimKey, true, nonce, deadline);

    bytes[] memory updateData = new bytes[](1);
    updateData[0] = abi.encodeWithSignature(
      S_UPDATE_AUTH, owner, _approveKey(victimKey), nonce, deadline, approvalSig
    );

    vm.prank(relayer);
    hub.forward(targets, updateData, _bits(0));
    assertTrue(verifier.approvedKeys(owner, victimHash), 'updateAuth is the listed way in');
  }

  // -----------------------------------------------------------------------------------------------
  // FWD-17..19 — the rest of the allowlist, and the shape of a batch
  // -----------------------------------------------------------------------------------------------

  /**
   * FWD-17 — Permit2's single `permit`, the other overload written out in the allowlist
   * @dev The two overloads differ only in whether `details` is an array, so they hash to different
   * selectors that no `.selector` expression can tell apart. PF-05 covers the batch; this is the
   * one that would silently drop out of the list if the two strings were ever transposed.
   */
  function test_FWD_17_permit2SinglePermitForwarded() public {
    uint160 amount = 17 ether;
    uint48 expiration = uint48(block.timestamp + 2 days);
    uint256 sigDeadline = block.timestamp + 1 hours;

    IAllowanceTransfer.PermitSingle memory single = IAllowanceTransfer.PermitSingle({
      details: IAllowanceTransfer.PermitDetails({
        token: USDC, amount: amount, expiration: expiration, nonce: 0
      }),
      spender: address(hub),
      sigDeadline: sigDeadline
    });

    bytes memory signature = _sign(ownerKey, _permit2SingleDigest(single));

    bytes[] memory data = new bytes[](1);
    data[0] = abi.encodeWithSignature(S_PERMIT2_SINGLE_PERMIT, owner, single, signature);

    vm.prank(relayer);
    hub.forward(_one(PERMIT2), data, _bits(0));

    (uint160 allowed, uint48 storedExpiration, uint48 storedNonce) =
      IAllowanceTransfer(PERMIT2).allowance(owner, USDC, address(hub));

    assertEq(allowed, amount, 'allowance');
    assertEq(storedExpiration, expiration, 'expiration');
    assertEq(storedNonce, 1, 'nonce bumped');
  }

  /// FWD-18 — an empty batch is a legal no-op rather than an error
  function test_FWD_18_emptyBatchIsANoOp() public {
    vm.prank(relayer);
    bytes[] memory results = hub.forward(new address[](0), new bytes[](0), _bits(0));

    assertEq(results.length, 0, 'no entries, no results');

    // the length check passes on two empties, so the failure bits are never consulted either
    vm.prank(relayer);
    bytes[] memory withBits =
      hub.forward(new address[](0), new bytes[](0), _bits(type(uint256).max));
    assertEq(withBits.length, 0, 'and the bits change nothing about that');
  }

  /**
   * FWD-19 — a failure bit set on a call that succeeds is inert
   * @dev The bit is only ever read after the call returns, so setting it on an entry that works
   * must not skip it, soften it or replace what it returned. The second leg is what gives the
   * zero-length result its meaning: revert data under the same bit is never empty, so the two
   * cases are distinguishable and the first assertion is not simply reading an unset array slot.
   */
  function test_FWD_19_failureBitOnASucceedingCallIsInert() public {
    uint256 value = 19 ether;
    uint256 deadline = block.timestamp + 1 hours;

    bytes[] memory data = new bytes[](1);
    data[0] = _erc2612Call('Permit Token', address(permitToken), address(hub), value, 0, deadline);

    vm.prank(relayer);
    bytes[] memory results = hub.forward(_one(address(permitToken)), data, _bits(type(uint256).max));

    assertEq(permitToken.allowance(owner, address(hub)), value, 'the state change still landed');
    assertEq(permitToken.nonces(owner), 1, 'and the nonce was still consumed');
    assertEq(results[0].length, 0, "results[0] is the permit's own empty return");

    uint256 expired = block.timestamp - 1;
    bytes[] memory failing = new bytes[](1);
    failing[0] = _erc2612Call('Permit Token', address(permitToken), address(hub), value, 1, expired);

    vm.prank(relayer);
    bytes[] memory failedResults =
      hub.forward(_one(address(permitToken)), failing, _bits(type(uint256).max));

    assertEq(
      failedResults[0],
      abi.encodeWithSelector(ERC20Permit.ERC2612ExpiredSignature.selector, expired),
      'a skipped entry carries revert data, which is never empty'
    );
    assertEq(permitToken.allowance(owner, address(hub)), value, 'and it changed nothing');
    assertEq(permitToken.nonces(owner), 1, 'nor burned a nonce');
  }

  // -----------------------------------------------------------------------------------------------
  // FWD-PAUSE / FWD-VALUE / FWD-REENTRY — the guards `forward` deliberately does without
  // -----------------------------------------------------------------------------------------------

  /**
   * FWD-PAUSE-01 — a pause does not close the forwarder
   * @dev Intended: relaying a permit moves nobody's assets, it only records an allowance, and an
   * allowance granted during a pause cannot be spent while the pause holds — both order entry
   * points are shut, which the second half of this case shows on the same paused hub. Keeping
   * `forward` open means a user mid-flow can still land the approval half of their transaction.
   */
  function test_FWD_PAUSE_01_forwardStillWorksWhilePaused() public {
    uint256 value = 5 ether;
    uint256 deadline = block.timestamp + 1 hours;

    bytes[] memory data = new bytes[](1);
    data[0] = _erc2612Call('Permit Token', address(permitToken), address(hub), value, 0, deadline);

    vm.prank(guardian);
    hub.pause();

    vm.prank(relayer);
    hub.forward(_one(address(permitToken)), data, _bits(0));

    assertTrue(hub.paused(), 'the hub is still paused');
    assertEq(permitToken.allowance(owner, address(hub)), value, 'and the permit was relayed');

    // the allowance it granted is unspendable until the pause lifts
    vm.prank(owner);
    vm.expectRevert(Pausable.EnforcedPause.selector);
    hub.transferAndExecute(
      owner,
      _erc20s(_wethTransfer(1 ether)),
      new ERC721Transfer[](0),
      new GenericCall[](0),
      block.timestamp,
      _flags(false, false, false),
      ''
    );
  }

  /**
   * FWD-VALUE-01 — value sent with `forward` is stranded in the hub
   * @dev `forward` is payable and carries no native-spend guard, because none of the seven calls
   * it relays takes value: it forwards `data` only, never `msg.value`. So anything attached simply
   * stays, with no `receive` and no refund to send it back. Not a loss of user funds — a rescuer
   * sweeps it — but it is the contract's behaviour and a caller should not expect change.
   */
  function test_FWD_VALUE_01_valueSentWithForwardIsStranded() public {
    uint256 value = 5 ether;
    uint256 deadline = block.timestamp + 1 hours;

    bytes[] memory data = new bytes[](1);
    data[0] = _erc2612Call('Permit Token', address(permitToken), address(hub), value, 0, deadline);

    vm.deal(relayer, 1 ether);
    assertEq(address(hub).balance, 0, 'the hub starts empty');

    vm.prank(relayer);
    hub.forward{value: 1 ether}(_one(address(permitToken)), data, _bits(0));

    assertEq(address(hub).balance, 1 ether, 'every wei of it stayed behind');
    assertEq(relayer.balance, 0, 'and none came back to the sender');
    assertEq(permitToken.allowance(owner, address(hub)), value, 'the permit itself still landed');
  }

  /**
   * FWD-REENTRY-01 — a relayed permit may reenter the hub and start an order
   * @dev Confirmed-intended behaviour, pinned rather than fixed. `forward` takes no lock: it moves
   * no assets of its own, and the lock that matters is the one {KSAllowanceHubV2-transferAndExecute}
   * takes for the duration of an order. So a target called from inside a batch is free to open
   * one, and the order it opens is authorised on its own merits — here the owner's Permit2
   * signature over an open-caller witness, which is what lets the token contract submit it at all.
   * The assertion is that the reentrant order actually settled, not merely that nothing reverted.
   */
  function test_FWD_REENTRY_01_relayedPermitMayReenterTheHub() public {
    ReentrantPermitMock reentrant = new ReentrantPermitMock(address(hub));

    uint160 amount = 6 ether;
    uint256 nonce = 310;
    uint256 deadline = block.timestamp + 1 hours;

    ERC20Transfer[] memory erc20s = _erc20s(_wethTransfer(amount));
    GenericCall[] memory calls = _calls(_routerCall(0, hex'01'));
    bytes memory permitSig =
      _signExecutionOrder(erc20s, new ERC721Transfer[](0), calls, ANY, nonce, deadline);

    reentrant.setReentry(
      abi.encodeCall(
        IKSAllowanceHubV2.transferAndExecute,
        (
          owner,
          erc20s,
          new ERC721Transfer[](0),
          calls,
          deadline,
          _flags(true, false, false),
          _permit2AuthData(nonce, permitSig)
        )
      )
    );

    // a well-formed EIP-2612 payload, so the allowlist lets it through; the mock ignores the
    // arguments and calls back instead of checking them
    bytes[] memory data = new bytes[](1);
    data[0] = abi.encodeWithSignature(
      S_EIP2612_PERMIT, owner, address(hub), uint256(1), deadline, uint8(27), bytes32(0), bytes32(0)
    );

    uint256 before = IERC20(WETH).balanceOf(address(router));

    vm.prank(relayer);
    hub.forward(_one(address(reentrant)), data, _bits(0));

    assertEq(reentrant.permitCount(), 1, 'the forwarder did relay the permit');
    assertEq(
      IERC20(WETH).balanceOf(address(router)) - before, amount, 'the reentrant order settled'
    );
    assertEq(router.callCount(), 1, 'and its router leg ran');
    assertEq(router.seenMsgSender(), owner, 'holding the lock for the owner while it did');
  }

  // -----------------------------------------------------------------------------------------------
  // Helpers
  // -----------------------------------------------------------------------------------------------

  /// @dev Permit2's single-allowance digest, rebuilt from the literals above
  function _permit2SingleDigest(IAllowanceTransfer.PermitSingle memory single)
    internal
    view
    returns (bytes32)
  {
    bytes32 detailsHash = keccak256(
      abi.encode(
        keccak256(bytes(L_PERMIT2_DETAILS)),
        single.details.token,
        single.details.amount,
        single.details.expiration,
        single.details.nonce
      )
    );

    bytes32 structHash = keccak256(
      abi.encode(
        keccak256(abi.encodePacked(L_PERMIT2_SINGLE_STUB, L_PERMIT2_DETAILS)),
        detailsHash,
        single.spender,
        single.sigDeadline
      )
    );

    return lTypedDataHash(_permit2DomainSeparator(), structHash);
  }

  /// @dev A good permit followed by one that is past its deadline, sharing one target
  function _goodThenExpired(uint256 value, uint256 expired)
    internal
    returns (address[] memory targets, bytes[] memory data)
  {
    targets = new address[](2);
    targets[0] = address(permitToken);
    targets[1] = address(permitToken);

    data = new bytes[](2);
    data[0] = _erc2612Call(
      'Permit Token', address(permitToken), address(hub), value, 0, block.timestamp + 1 hours
    );
    data[1] = _erc2612Call('Permit Token', address(permitToken), address(hub), value, 1, expired);
  }

  function _bits(uint256 raw) internal pure returns (PackedBits) {
    return PackedBits.wrap(bytes32(raw));
  }

  function _erc2612Digest(
    string memory name,
    address token,
    address tokenOwner,
    address spender,
    uint256 value,
    uint256 nonce,
    uint256 deadline
  ) internal view returns (bytes32) {
    bytes32 structHash = keccak256(
      abi.encode(keccak256(bytes(L_EIP2612_PERMIT)), tokenOwner, spender, value, nonce, deadline)
    );
    // OpenZeppelin's ERC20Permit names its domain after the token and versions it '1'
    return lTypedDataHash(lDomainSeparator(name, '1', token), structHash);
  }

  /// @dev A whole EIP-2612 `permit` call, ready for the forwarder to relay
  function _erc2612Call(
    string memory name,
    address token,
    address spender,
    uint256 value,
    uint256 nonce,
    uint256 deadline
  ) internal returns (bytes memory) {
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(
      ownerKey, _erc2612Digest(name, token, owner, spender, value, nonce, deadline)
    );
    return abi.encodeWithSignature(S_EIP2612_PERMIT, owner, spender, value, deadline, v, r, s);
  }

  function _erc721V4Call(address spender, uint256 deadline, uint256 nonce)
    internal
    returns (bytes memory)
  {
    bytes32 structHash = keccak256(
      abi.encode(keccak256(bytes(L_ERC721_PERMIT)), spender, PERMIT_NFT_ID, nonce, deadline)
    );
    bytes memory signature = _sign(
      ownerKey, lTypedDataHash(lDomainSeparator('V4 Permit NFT', '1', address(nftV4)), structHash)
    );
    return
      abi.encodeWithSignature(
        S_ERC721_V4_PERMIT, spender, PERMIT_NFT_ID, deadline, nonce, signature
      );
  }

  /// @dev Permit2's allowance-rail batch digest, rebuilt from the literals above
  function _permit2BatchDigest(IAllowanceTransfer.PermitBatch memory batch)
    internal
    view
    returns (bytes32)
  {
    bytes32[] memory detailHashes = new bytes32[](batch.details.length);
    for (uint256 i = 0; i < batch.details.length; i++) {
      detailHashes[i] = keccak256(
        abi.encode(
          keccak256(bytes(L_PERMIT2_DETAILS)),
          batch.details[i].token,
          batch.details[i].amount,
          batch.details[i].expiration,
          batch.details[i].nonce
        )
      );
    }

    bytes32 structHash = keccak256(
      abi.encode(
        keccak256(abi.encodePacked(L_PERMIT2_BATCH_STUB, L_PERMIT2_DETAILS)),
        keccak256(abi.encodePacked(detailHashes)),
        batch.spender,
        batch.sigDeadline
      )
    );

    return lTypedDataHash(_permit2DomainSeparator(), structHash);
  }

  function _permit2Batch(
    address token,
    uint160 amount,
    uint48 expiration,
    uint48 nonce,
    address spender,
    uint256 sigDeadline
  ) internal pure returns (IAllowanceTransfer.PermitBatch memory batch) {
    IAllowanceTransfer.PermitDetails[] memory details = new IAllowanceTransfer.PermitDetails[](1);
    details[0] = IAllowanceTransfer.PermitDetails({
      token: token, amount: amount, expiration: expiration, nonce: nonce
    });
    batch = IAllowanceTransfer.PermitBatch({
      details: details, spender: spender, sigDeadline: sigDeadline
    });
  }

  function _daiDomainSeparator() internal view returns (bytes32) {
    (bool ok, bytes memory data) = DAI.staticcall(abi.encodeWithSignature('DOMAIN_SEPARATOR()'));
    require(ok, 'dai domain');
    return abi.decode(data, (bytes32));
  }

  function _daiNonce(address holder) internal view returns (uint256) {
    (bool ok, bytes memory data) =
      DAI.staticcall(abi.encodeWithSignature('nonces(address)', holder));
    require(ok, 'dai nonce');
    return abi.decode(data, (uint256));
  }

  function _daiAllowance(address holder, address spender) internal view returns (uint256) {
    (bool ok, bytes memory data) =
      DAI.staticcall(abi.encodeWithSignature('allowance(address,address)', holder, spender));
    require(ok, 'dai allowance');
    return abi.decode(data, (uint256));
  }

  function _one(address a) internal pure returns (address[] memory out) {
    out = new address[](1);
    out[0] = a;
  }
}
