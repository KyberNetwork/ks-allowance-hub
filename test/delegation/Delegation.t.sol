// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {SignerAuthenticatorBase} from 'test/base/SignerAuthenticatorBase.sol';

import {SignerAuthenticatorMock} from 'test/mocks/SignerAuthenticatorMock.sol';
import {ERC1271WalletMock} from 'test/mocks/TokenMocks.sol';

import {IAHV2Authenticator} from 'src/interfaces/base/IAHV2Authenticator.sol';
import {IAuthDelegator} from 'src/interfaces/base/IAuthDelegator.sol';
import {IUnorderedNonce} from 'src/interfaces/base/IUnorderedNonce.sol';

import {AHV2AuthenticatorBase} from 'src/base/AHV2AuthenticatorBase.sol';

import {AHV2Order} from 'src/types/AHV2Order.sol';
import {AHV2Solution} from 'src/types/AHV2Solution.sol';

/// @notice Authenticator that can be switched to reverting, to show a withdrawal never calls it
contract RevertingAuthenticator is IAHV2Authenticator {
  error Nope();

  bool public reverting;

  /// @dev Counts the calls that got through, so a step can be shown never to have made one
  uint256 public initCount;

  function setReverting(bool value) external {
    reverting = value;
  }

  function initAuthentication(address, bytes calldata) external {
    if (reverting) {
      revert Nope();
    }
    initCount++;
  }

  function updateAuthentication(address, bytes calldata, uint256, uint256, bytes calldata)
    external
    view
  {
    if (reverting) {
      revert Nope();
    }
  }

  function authenticate(AHV2Order calldata, bytes32, AHV2Solution calldata, bytes calldata)
    external
    view
  {
    if (reverting) {
      revert Nope();
    }
  }
}

/// @notice `DEL-*` and `NONCE-*` — nominating and withdrawing an authenticator, and the hub's
/// unordered nonce bitmap.
contract DelegationTest is SignerAuthenticatorBase {
  /// @dev One struct per entry-point domain, per the frozen plan's fuzz contract
  struct DelegationFuzz {
    uint256 nonce;
    uint256 deadlineOffset;
  }

  // -------------------------------------------------------------------------------------------
  // DEL — delegating an authenticator
  // -------------------------------------------------------------------------------------------

  /**
   * DEL-01 — the owner delegates for themselves: no nonce is spent and the authenticator is
   * trusted
   * @dev The authenticator's `UpdateSigner` precedes the hub's `UpdateDelegation`, since the
   * hub emits after the authenticator returns.
   */
  function test_DEL_01_selfDelegationSpendsNoNonce() public {
    uint256 word = 0;

    vm.expectEmit(address(authenticator));
    emit SignerAuthenticatorMock.UpdateSigner(owner, signer, true);
    vm.expectEmit(address(hub));
    emit IAuthDelegator.UpdateDelegation(owner, address(authenticator), true);
    vm.prank(owner);
    hub.updateDelegation(
      owner,
      address(authenticator),
      true,
      _encodeSigner(signer),
      0,
      vm.getBlockTimestamp() + 1 days,
      ''
    );

    assertTrue(hub.authDelegated(owner, address(authenticator)), 'delegated');
    assertTrue(authenticator.approvedSigners(owner, signer), 'signer approved without a signature');
    assertEq(hub.nonces(lNonceKey(owner), word), 0, 'no hub nonce consumed');
  }

  /// DEL-02 — a third party may submit the delegation when it carries the owner's signature
  function test_DEL_02_relayedDelegationConsumesNonce() public {
    uint256 nonce = 5;
    uint256 deadline = vm.getBlockTimestamp() + 1 days;
    bytes memory sig = _signAuthDelegation(
      ownerKey, owner, address(authenticator), true, _encodeSigner(signer), nonce, deadline
    );

    vm.expectEmit(address(hub));
    emit IAuthDelegator.UpdateDelegation(owner, address(authenticator), true);
    _expectNoRevokeNonce();
    vm.prank(relayer);
    hub.updateDelegation(
      owner, address(authenticator), true, _encodeSigner(signer), nonce, deadline, sig
    );

    assertTrue(hub.authDelegated(owner, address(authenticator)));
    assertEq(hub.nonces(lNonceKey(owner), nonce >> 8), 1 << (nonce & 0xff), 'exact bit set');

    // NONCE-02 — the same nonce cannot be spent twice
    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(IUnorderedNonce.NonceAlreadyUsed.selector, lNonceKey(owner), nonce)
    );
    hub.updateDelegation(
      owner, address(authenticator), true, _encodeSigner(signer), nonce, deadline, sig
    );
  }

  /// DEL-03 — changing any signed field invalidates the delegation
  function test_DEL_03_tamperedDelegationRejected() public {
    uint256 deadline = vm.getBlockTimestamp() + 1 days;
    bytes memory sig = _signAuthDelegation(
      ownerKey, owner, address(authenticator), true, _encodeSigner(signer), 1, deadline
    );

    vm.prank(relayer);
    vm.expectRevert(IAuthDelegator.InvalidDelegationSignature.selector);
    hub.updateDelegation(
      owner, address(authenticator), true, _encodeSigner(relayer), 1, deadline, sig
    );
  }

  /// DEL-04 — an ERC-1271 owner's signature delegates, and a wrong magic value reverts
  function test_DEL_04_erc1271Owner() public {
    (address walletSigner, uint256 walletSignerKey) = makeAddrAndKey('wallet signer');
    ERC1271WalletMock wallet = new ERC1271WalletMock(walletSigner);

    uint256 deadline = vm.getBlockTimestamp() + 1 days;
    bytes memory sig = _signAuthDelegation(
      walletSignerKey,
      address(wallet),
      address(authenticator),
      true,
      _encodeSigner(signer),
      2,
      deadline
    );

    vm.prank(relayer);
    hub.updateDelegation(
      address(wallet), address(authenticator), true, _encodeSigner(signer), 2, deadline, sig
    );
    assertTrue(hub.authDelegated(address(wallet), address(authenticator)));

    // and a wallet that returns the wrong magic value is rejected
    wallet.setReturnWrongMagic(true);
    bytes memory sig2 = _signAuthDelegation(
      walletSignerKey,
      address(wallet),
      address(authenticator),
      true,
      _encodeSigner(signer),
      3,
      deadline
    );

    vm.prank(relayer);
    vm.expectRevert(IAuthDelegator.InvalidDelegationSignature.selector);
    hub.updateDelegation(
      address(wallet), address(authenticator), true, _encodeSigner(signer), 3, deadline, sig2
    );
  }

  /// DEL-05 — a relayed delegation past its deadline reverts with `DeadlinePassed`
  function test_DEL_05_expiredDelegation() public {
    uint256 deadline = vm.getBlockTimestamp() - 1;
    bytes memory sig = _signAuthDelegation(
      ownerKey, owner, address(authenticator), true, _encodeSigner(signer), 4, deadline
    );

    vm.prank(relayer);
    vm.expectRevert(_deadlinePassed(deadline));
    hub.updateDelegation(
      owner, address(authenticator), true, _encodeSigner(signer), 4, deadline, sig
    );
  }

  /**
   * DEL-06 — withdrawing stops the hub accepting that authenticator, while the signer stays approved
   * @dev The owner needs no signature, exactly as when delegating: being `msg.sender` is the
   * authentication. `data` is ignored on this direction, so the signer it specifies is left alone.
   */
  function test_DEL_06_withdrawDelegation() public {
    _delegateSignerThroughHub(signer);
    assertTrue(hub.authDelegated(owner, address(authenticator)));

    vm.expectEmit(address(hub));
    emit IAuthDelegator.UpdateDelegation(owner, address(authenticator), false);
    vm.prank(owner);
    hub.updateDelegation(
      owner, address(authenticator), false, '', 0, vm.getBlockTimestamp() + 1 days, ''
    );
    assertFalse(hub.authDelegated(owner, address(authenticator)));

    // the authenticator still holds the approval, which is why re-delegating re-arms it
    assertTrue(authenticator.approvedSigners(owner, signer));
  }

  /**
   * DEL-08 — a withdrawal never reaches the authenticator, so one that reverts cannot trap the
   * owner
   * @dev Withdrawal must work unconditionally; an authenticator the owner could not
   * withdraw would keep authenticating orders forever. Every step carries the same non-empty
   * `data`, without which the authenticator is not reached at all: with an empty payload
   * `initAuthentication` is skipped on both directions and the contrast would be between two calls
   * that never happened.
   */
  function test_DEL_08_withdrawalDoesNotCallTheAuthenticator() public {
    RevertingAuthenticator bad = new RevertingAuthenticator();
    uint256 deadline = vm.getBlockTimestamp() + 1 days;

    vm.prank(owner);
    hub.updateDelegation(owner, address(bad), true, hex'1234', 0, deadline, '');
    assertTrue(hub.authDelegated(owner, address(bad)), 'delegated while it still answered');
    assertEq(bad.initCount(), 1, 'and that payload did reach it');

    bad.setReverting(true);

    // the control: the same payload on the delegate direction now fails at the authenticator, so
    // the withdrawal below is evidence about the direction rather than about the payload
    vm.prank(owner);
    vm.expectRevert(RevertingAuthenticator.Nope.selector);
    hub.updateDelegation(owner, address(bad), true, hex'1234', 0, deadline, '');

    vm.prank(owner);
    hub.updateDelegation(owner, address(bad), false, hex'1234', 0, deadline, '');
    assertFalse(hub.authDelegated(owner, address(bad)), 'withdrawn despite the revert');
    assertEq(bad.initCount(), 1, 'and the withdrawal never called it');
  }

  /// DEL-09 — a relayed withdrawal needs the owner's signature over the same direction
  function test_DEL_09_relayedWithdrawal() public {
    _delegateSignerThroughHub(signer);
    uint256 deadline = vm.getBlockTimestamp() + 1 days;

    // the direction is signed, so a delegation signature cannot be submitted as a withdrawal
    bytes memory delegateSig =
      _signAuthDelegation(ownerKey, owner, address(authenticator), true, '', 5, deadline);
    vm.prank(relayer);
    vm.expectRevert(IAuthDelegator.InvalidDelegationSignature.selector);
    hub.updateDelegation(owner, address(authenticator), false, '', 5, deadline, delegateSig);

    // the same signature under its own direction is accepted, so the refusal is evidence
    vm.prank(relayer);
    hub.updateDelegation(owner, address(authenticator), true, '', 5, deadline, delegateSig);
    assertTrue(hub.authDelegated(owner, address(authenticator)), 'delegated on its own direction');

    bytes memory withdrawSig =
      _signAuthDelegation(ownerKey, owner, address(authenticator), false, '', 6, deadline);
    vm.prank(relayer);
    hub.updateDelegation(owner, address(authenticator), false, '', 6, deadline, withdrawSig);

    assertFalse(hub.authDelegated(owner, address(authenticator)), 'withdrawn by the relayer');
    assertEq(
      hub.nonces(lNonceKey(owner), 0), (1 << 5) | (1 << 6), 'one hub nonce per accepted decision'
    );
  }

  // -------------------------------------------------------------------------------------------
  // DEL-12 — only the hub reaches `initAuthentication`
  // -------------------------------------------------------------------------------------------

  /**
   * DEL-12 — `initAuthentication` answers the hub alone, and being the owner is not a way in
   * @dev It takes no signature, no nonce and no deadline: it trusts its caller completely, so the
   * caller check is the whole of its security. The owner step matters as much as the stranger's,
   * because "the owner may do it anyway" is exactly the reasoning that would justify relaxing the
   * modifier — and the owner already has a route, through {AuthDelegator-updateDelegation}.
   */
  function test_DEL_12_initAuthenticationIsHubOnly() public {
    bytes memory payload = _encodeSigner(signer);

    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(AHV2AuthenticatorBase.CallerNotAuthorized.selector, relayer)
    );
    authenticator.initAuthentication(owner, payload);

    vm.prank(owner);
    vm.expectRevert(
      abi.encodeWithSelector(AHV2AuthenticatorBase.CallerNotAuthorized.selector, owner)
    );
    authenticator.initAuthentication(owner, payload);

    assertFalse(authenticator.approvedSigners(owner, signer), 'nothing was approved either time');
  }

  // -------------------------------------------------------------------------------------------
  // DEL-13..15 — the guard on the forwarded `initAuthentication` is a conjunction
  // -------------------------------------------------------------------------------------------

  /**
   * DEL-13 — an empty payload skips the authenticator, even on the delegate direction
   * @dev The authenticator is set to revert, so merely not reverting is already suggestive — but
   * only suggestive: one that had been called and answered would satisfy that just as well. The
   * expectation of zero calls with the exact calldata is the oracle, and the calldata is built from
   * a signature string written out in this file rather than from the production interface.
   */
  function test_DEL_13_emptyPayloadNeverCallsInitAuthentication() public {
    RevertingAuthenticator bad = new RevertingAuthenticator();
    bad.setReverting(true);

    bytes memory empty = '';
    bytes memory expectedCall =
      abi.encodeCall(IAHV2Authenticator.initAuthentication, (owner, empty));

    vm.expectCall(address(bad), expectedCall, 0);

    vm.prank(owner);
    hub.updateDelegation(owner, address(bad), true, empty, 0, vm.getBlockTimestamp() + 1 days, '');

    assertTrue(
      hub.authDelegated(owner, address(bad)), 'delegated without touching the authenticator'
    );
    assertEq(bad.initCount(), 0, 'and it counted no call');
  }

  /**
   * DEL-14 — the guard reads the payload's length, not the direction alone
   * @dev One byte apart from DEL-13, same direction, same authenticator. A single zero byte is
   * enough to cross the guard, which isolates `data.length > 0` from any notion of the payload
   * being meaningful. The first step also fixes the exact calldata the hub forwards, whose absence
   * is what the zero-call expectations in DEL-13 and DEL-15 assert: a signature string
   * that specified nothing would make those two pass vacuously, and would fail here.
   */
  function test_DEL_14_nonEmptyPayloadDoesCallInitAuthentication() public {
    RevertingAuthenticator bad = new RevertingAuthenticator();
    uint256 deadline = vm.getBlockTimestamp() + 1 days;

    bytes memory payload = hex'00';
    bytes memory expectedCall =
      abi.encodeCall(IAHV2Authenticator.initAuthentication, (owner, payload));

    // twice: once below while the authenticator still answers, and once on the refused attempt at
    // the end, which reaches it just as far before being turned away
    vm.expectCall(address(bad), expectedCall, 2);

    vm.prank(owner);
    hub.updateDelegation(owner, address(bad), true, payload, 0, deadline, '');
    assertEq(bad.initCount(), 1, 'one byte of payload is enough to reach the authenticator');

    // and once it refuses, the refusal is the owner's problem: the delegation does not stand
    bad.setReverting(true);

    vm.prank(owner);
    hub.updateDelegation(owner, address(bad), false, '', 0, deadline, '');
    assertFalse(hub.authDelegated(owner, address(bad)), 'cleared, so the next step is a transition');

    vm.prank(owner);
    vm.expectRevert(RevertingAuthenticator.Nope.selector);
    hub.updateDelegation(owner, address(bad), true, payload, 0, deadline, '');

    assertFalse(hub.authDelegated(owner, address(bad)), 'the delegation rolled back with it');
    assertEq(bad.initCount(), 1, 'and the refused call left its counter alone');
  }

  /**
   * DEL-15 — a withdrawal skips the authenticator whatever the payload says
   * @dev DEL-13 held the direction and emptied the payload; this holds a payload DEL-14 has just
   * shown does reach an authenticator and flips the direction instead. Between the three the guard
   * is pinned as the conjunction it is written as. Nothing is delegated here beforehand, so the
   * withdrawal is not even undoing anything — and still must not call out, because the escape hatch
   * has to work against an authenticator that has started refusing every call.
   */
  function test_DEL_15_withdrawalSkipsTheAuthenticatorWhateverThePayload() public {
    RevertingAuthenticator bad = new RevertingAuthenticator();
    bad.setReverting(true);

    bytes memory payload = hex'00';
    bytes memory expectedCall =
      abi.encodeCall(IAHV2Authenticator.initAuthentication, (owner, payload));

    vm.expectCall(address(bad), expectedCall, 0);

    vm.prank(owner);
    hub.updateDelegation(
      owner, address(bad), false, payload, 0, vm.getBlockTimestamp() + 1 days, ''
    );

    assertFalse(hub.authDelegated(owner, address(bad)), 'withdrawn');
    assertEq(bad.initCount(), 0, 'and the authenticator was never called');
  }

  /**
   * DEL-16 — a delegation signed for one account is refused for another account of one signer
   * @dev Two ERC-1271 wallets sharing one signer accept the same signatures, so only the signed
   * `owner` tells them apart.
   */
  function test_DEL_16_delegationIsBoundToItsOwner() public {
    (address sharedSigner, uint256 sharedSignerKey) = makeAddrAndKey('shared signer');
    address walletA = address(new ERC1271WalletMock(sharedSigner));
    address walletB = address(new ERC1271WalletMock(sharedSigner));

    uint256 deadline = vm.getBlockTimestamp() + 1 days;
    bytes memory sig = _signAuthDelegation(
      sharedSignerKey, walletA, address(authenticator), true, _encodeSigner(signer), 7, deadline
    );

    vm.prank(relayer);
    vm.expectRevert(IAuthDelegator.InvalidDelegationSignature.selector);
    hub.updateDelegation(
      walletB, address(authenticator), true, _encodeSigner(signer), 7, deadline, sig
    );
    assertFalse(hub.authDelegated(walletB, address(authenticator)), 'B not delegated');

    // the same signature on the account it specifies is accepted, so the refusal is evidence
    vm.prank(relayer);
    hub.updateDelegation(
      walletA, address(authenticator), true, _encodeSigner(signer), 7, deadline, sig
    );
    assertTrue(hub.authDelegated(walletA, address(authenticator)), 'A delegated');
  }

  /**
   * DEL-17 — a signature on the owner's own delegation call reverts with `UnexpectedSignature`
   * @dev A signed delegation the owner submits never leaves its nonce unspent for a later replay.
   */
  function test_DEL_17_ownerCallTakesNoSignature() public {
    uint256 deadline = vm.getBlockTimestamp() + 1 days;
    bytes memory sig =
      _signAuthDelegation(ownerKey, owner, address(authenticator), true, '', 9, deadline);

    vm.prank(owner);
    vm.expectRevert(IAuthDelegator.UnexpectedSignature.selector);
    hub.updateDelegation(owner, address(authenticator), true, '', 9, deadline, sig);

    vm.prank(owner);
    hub.updateDelegation(owner, address(authenticator), true, '', 9, deadline, '');
    assertTrue(hub.authDelegated(owner, address(authenticator)), 'delegated on the empty signature');
    assertEq(hub.nonces(lNonceKey(owner), 0), 0, 'no nonce spent');
  }

  /// DEL-FUZZ — a relayed delegation sets the delegation and exactly its nonce bit
  function testFuzz_DEL_FUZZ_relayedDelegation(DelegationFuzz memory f) public {
    uint256 nonce = f.nonce;
    uint256 deadline = vm.getBlockTimestamp() + bound(f.deadlineOffset, 0, 30 days);

    bytes memory sig = _signAuthDelegation(
      ownerKey, owner, address(authenticator), true, _encodeSigner(signer), nonce, deadline
    );

    vm.expectEmit(address(hub));
    emit IAuthDelegator.UpdateDelegation(owner, address(authenticator), true);
    vm.prank(relayer);
    hub.updateDelegation(
      owner, address(authenticator), true, _encodeSigner(signer), nonce, deadline, sig
    );

    assertTrue(hub.authDelegated(owner, address(authenticator)));
    assertEq(
      hub.nonces(lNonceKey(owner), nonce >> 8), 1 << (nonce & 0xff), 'exact bit for this nonce'
    );
  }
}
