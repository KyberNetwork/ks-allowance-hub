// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AuthenticatorBase} from 'test/v2/authenticators/base/AuthenticatorBase.sol';

import {KeyFixtures} from 'test/v2/authenticators/mocks/KeyFixtures.sol';

import {IUnorderedNonce} from 'src/base/interfaces/IUnorderedNonce.sol';
import {
  ISessionOrderAuthenticator
} from 'src/v2/authenticators/interfaces/ISessionOrderAuthenticator.sol';
import {AuthKey} from 'src/v2/authenticators/types/AuthKey.sol';
import {KeyType} from 'src/v2/authenticators/types/KeyType.sol';
import {IOrderAuthenticator} from 'src/v2/interfaces/IOrderAuthenticator.sol';
import {ERC20Transfer} from 'src/v2/types/ERC20Transfer.sol';
import {ERC721Transfer} from 'src/v2/types/ERC721Transfer.sol';
import {ExecutionOrder} from 'src/v2/types/ExecutionOrder.sol';
import {FulfillmentOrder} from 'src/v2/types/FulfillmentOrder.sol';
import {GenericCall} from 'src/v2/types/GenericCall.sol';
import {ValidationParams} from 'src/v2/types/ValidationParams.sol';

import {IERC20} from 'openzeppelin-contracts/contracts/token/ERC20/IERC20.sol';

/// @notice `SV-*` — session key approval, the hub-only gate, expiry, replay and every key scheme.
contract SessionOrderAuthenticatorTest is AuthenticatorBase {
  /// @dev One struct per entry-point domain, per the frozen plan's fuzz contract
  struct SessionFuzz {
    uint8 keyType;
    uint256 expirationOffset;
    uint256 nonce;
    uint256 deadlineOffset;
    bool approved;
  }

  /// @dev Verification must produce a signature the key accepts, so this shape omits `keyType`
  struct SessionVerifyFuzz {
    uint256 nonce;
    uint256 deadlineOffset;
    uint256 expirationOffset;
  }

  /// @dev The master key rail's domain: two expiries, since one bounds the other
  struct TierFuzz {
    uint256 nonce;
    uint256 deadlineOffset;
    uint256 masterExpirationOffset;
    uint256 sessionExpirationOffset;
    bool approved;
  }

  uint160 internal constant AMOUNT = 3 ether;

  AuthKey internal key;

  function setUp() public override {
    super.setUp();
    key = _secpKey(masterSigner, block.timestamp + 30 days);
  }

  // -------------------------------------------------------------------------------------------
  // SV-01 — the happy path: a session key authenticates a relayed order
  // -------------------------------------------------------------------------------------------

  function test_SV_01_sessionKeyAuthenticatesRelayedOrder() public {
    _delegateKeyThroughHub(key);

    uint256 nonce = 7;
    uint256 deadline = block.timestamp + 1 hours;
    uint256 before = IERC20(token18).balanceOf(address(router));

    _executeViaAuthenticator(key, masterKeyPk, nonce, deadline, true);

    assertEq(IERC20(token18).balanceOf(address(router)) - before, AMOUNT, 'tokens moved');
    assertEq(
      authenticator.nonces(_keyHash(key), nonce >> 8),
      1 << (nonce & 0xff),
      'authenticator nonce spent'
    );
    assertEq(hub.nonces(lNonceKey(owner), 0), 0, 'hub nonce untouched on this rail');
  }

  // -------------------------------------------------------------------------------------------
  // SV-02..04 — approving a key by calling the authenticator directly
  // -------------------------------------------------------------------------------------------

  /**
   * SV-02 — the owner may approve a key at the authenticator directly, with no signature to check
   * @dev Being `msg.sender` is the authentication here, exactly as it is on the hub's
   * `updateDelegation`. No nonce is spent, because no signature was presented to replay.
   */
  function test_SV_02_ownerApprovesDirectlyWithoutSignature() public {
    AuthKey memory fresh = _secpKey(recipient, block.timestamp + 10 days);

    vm.prank(owner);
    authenticator.updateAuthentication(owner, _approveKey(fresh), 0, block.timestamp + 1 days, '');

    assertTrue(authenticator.masterKeys(owner, _keyHash(fresh)), 'approved');
    assertEq(authenticator.nonces(lNonceKey(owner), 0), 0, 'no nonce spent without a signature');
  }

  /// SV-02b — but not on someone else's behalf
  function test_SV_02b_strangerCannotApproveWithoutSignature() public {
    AuthKey memory fresh = _secpKey(recipient, block.timestamp + 10 days);

    vm.prank(relayer);
    vm.expectRevert(ISessionOrderAuthenticator.InvalidApprovalSignature.selector);
    authenticator.updateAuthentication(owner, _approveKey(fresh), 0, block.timestamp + 1 days, '');
  }

  /// SV-03 — a signature from anyone but the owner is rejected
  function test_SV_03_directApprovalWrongSigner() public {
    AuthKey memory fresh = _secpKey(recipient, block.timestamp + 10 days);
    uint256 deadline = block.timestamp + 1 days;

    bytes32 digest = lTypedDataHash(
      _authenticatorDomain(), lMasterKeyApproval(_keyHash(fresh), true, 4, deadline)
    );
    bytes memory sig = _sign(masterKeyPk, digest); // the session key, not the owner

    vm.prank(relayer);
    vm.expectRevert(ISessionOrderAuthenticator.InvalidApprovalSignature.selector);
    authenticator.updateAuthentication(owner, _approveKey(fresh), 4, deadline, sig);
  }

  /// SV-04 — the approval deadline is enforced by the authenticator itself
  function test_SV_04_directApprovalExpired() public {
    AuthKey memory fresh = _secpKey(recipient, block.timestamp + 10 days);
    uint256 deadline = block.timestamp - 1;
    bytes memory sig = _signMasterKeyApproval(fresh, true, 5, deadline);

    vm.prank(relayer);
    vm.expectRevert(_deadlinePassed(deadline));
    authenticator.updateAuthentication(owner, _approveKey(fresh), 5, deadline, sig);
  }

  // -------------------------------------------------------------------------------------------
  // SV-REV-01..05 — revoking a key, which is the same call with the direction flipped
  // -------------------------------------------------------------------------------------------

  /// SV-REV-01 — the owner revokes directly, and a key that had been authenticating orders stops
  function test_SV_REV_01_ownerRevokesDirectly() public {
    _delegateKeyThroughHub(key);
    _executeViaAuthenticator(key, masterKeyPk, 30, block.timestamp + 1 hours, true);

    vm.prank(owner);
    authenticator.updateAuthentication(owner, _revokeKey(key), 0, block.timestamp + 1 days, '');

    assertFalse(authenticator.masterKeys(owner, _keyHash(key)), 'revoked');
    assertTrue(hub.authDelegated(owner, address(authenticator)), 'the delegation itself survives');

    vm.expectRevert(_masterKeyNotApproved(key));
    _executeViaAuthenticator(key, masterKeyPk, 31, block.timestamp + 1 hours, false);
  }

  /// SV-REV-02 — a relayed revocation carrying the owner's signature spends an authenticator nonce
  function test_SV_REV_02_relayedRevocation() public {
    _delegateKeyThroughHub(key);

    uint256 deadline = block.timestamp + 1 days;
    bytes memory sig = _signMasterKeyApproval(key, false, 32, deadline);

    vm.prank(relayer);
    authenticator.updateAuthentication(owner, _revokeKey(key), 32, deadline, sig);

    assertFalse(authenticator.masterKeys(owner, _keyHash(key)), 'revoked');
    assertEq(authenticator.nonces(lNonceKey(owner), 0), 1 << 32, 'nonce spent');
  }

  /**
   * SV-REV-03 — neither instruction can be submitted as the other
   * @dev Each half submits one signature twice: once under the flipped direction, which must be
   * refused, and then under its own, which must succeed on the same nonce. The second submission
   * is what makes the first one evidence about the direction — a signature that had simply been
   * invalid would fail both times.
   */
  function test_SV_REV_03_directionCannotBeFlipped() public {
    _delegateKeyThroughHub(key);

    uint256 deadline = block.timestamp + 1 days;
    AuthKey memory fresh = _secpKey(recipient, block.timestamp + 10 days);

    // an approval, submitted as a revocation
    bytes memory approval = _signMasterKeyApproval(fresh, true, 33, deadline);
    vm.prank(relayer);
    vm.expectRevert(ISessionOrderAuthenticator.InvalidApprovalSignature.selector);
    authenticator.updateAuthentication(owner, _revokeKey(fresh), 33, deadline, approval);
    assertEq(authenticator.nonces(lNonceKey(owner), 0), 0, 'a refused update burns nothing');

    // the same signature, submitted as what the owner signed
    vm.prank(relayer);
    authenticator.updateAuthentication(owner, _approveKey(fresh), 33, deadline, approval);
    assertTrue(authenticator.masterKeys(owner, _keyHash(fresh)), 'approved on its own direction');

    // and the mirror: a revocation, submitted as an approval
    bytes memory revocation = _signMasterKeyApproval(key, false, 34, deadline);
    vm.prank(relayer);
    vm.expectRevert(ISessionOrderAuthenticator.InvalidApprovalSignature.selector);
    authenticator.updateAuthentication(owner, _approveKey(key), 34, deadline, revocation);
    assertTrue(authenticator.masterKeys(owner, _keyHash(key)), 'still approved after the refusal');

    vm.prank(relayer);
    authenticator.updateAuthentication(owner, _revokeKey(key), 34, deadline, revocation);
    assertFalse(authenticator.masterKeys(owner, _keyHash(key)), 'revoked on its own direction');

    assertEq(
      authenticator.nonces(lNonceKey(owner), 0),
      (1 << 33) | (1 << 34),
      'one nonce per accepted update'
    );
  }

  /// SV-REV-04 — revocation is not permanent: the same key may be approved again afterwards
  function test_SV_REV_04_reapprovalAfterRevocation() public {
    _delegateKeyThroughHub(key);

    vm.prank(owner);
    authenticator.updateAuthentication(owner, _revokeKey(key), 0, block.timestamp + 1 days, '');
    assertFalse(authenticator.masterKeys(owner, _keyHash(key)), 'revoked');

    vm.prank(owner);
    authenticator.updateAuthentication(owner, _approveKey(key), 0, block.timestamp + 1 days, '');
    assertTrue(authenticator.masterKeys(owner, _keyHash(key)), 'approved again');

    _executeViaAuthenticator(key, masterKeyPk, 35, block.timestamp + 1 hours, true);
  }

  /**
   * SV-REV-05 — a direction word that is neither 0 nor 1 is narrowed to true
   * @dev Hand-packed, because `abi.encode` cannot produce a non-canonical bool. The signature is
   * over `true`, so this also shows the narrowed value is the one hashed: carrying the raw word
   * into the digest instead would not match.
   */
  function test_SV_REV_05_nonCanonicalDirectionIsNarrowed() public {
    AuthKey memory fresh = _secpKey(recipient, block.timestamp + 10 days);
    uint256 deadline = block.timestamp + 1 days;

    bytes memory data = _approveKey(fresh);
    // word 1 of the payload is the direction; 2 is a value no ABI encoder would write there
    assembly ('memory-safe') {
      mstore(add(data, 0x40), 2)
    }

    bytes memory sig = _signMasterKeyApproval(fresh, true, 36, deadline);

    vm.prank(relayer);
    authenticator.updateAuthentication(owner, data, 36, deadline, sig);

    assertTrue(authenticator.masterKeys(owner, _keyHash(fresh)), 'narrowed to true');
  }

  // -------------------------------------------------------------------------------------------
  // SV-UPD-01 — what the owner branch of `updateAuthentication` does with what it does not read
  // -------------------------------------------------------------------------------------------

  /**
   * SV-UPD-01 — on the owner's own call the signature and the nonce are both ignored
   * @dev Deliberate, and pinned as-is rather than reported: being `msg.sender` IS the
   * authentication on this branch, exactly as it is on the hub's `updateDelegation`, so
   * `updateAuthentication` never looks at `signature` and never burns `nonce`. Two consequences
   * follow, and both are asserted below so that a future reader meets them here instead of
   * discovering them in production. A signature on this path proves nothing — an obviously bogus
   * one is accepted as readily as a real one, because neither is examined. And the call carries no
   * replay protection of its own: identical calldata settles again, with effect, as many times as
   * it is submitted. Neither is exploitable, because no one but the owner can be `msg.sender` here
   * and an owner replaying their own instruction is just the owner repeating themselves. What would
   * be a finding is the reverse reading — treating a signature accepted on this path as having been
   * checked, or expecting the named nonce to have been spent.
   */
  function test_SV_UPD_01_ownerBranchIgnoresTheSignatureAndTheNonce() public {
    AuthKey memory fresh = _secpKey(recipient, block.timestamp + 10 days);
    bytes32 freshHash = _keyHash(fresh);
    uint256 nonce = 40;
    uint256 deadline = block.timestamp + 1 days;

    // 65 bytes shaped like an ECDSA signature, over nothing, recovering to nobody in particular
    bytes memory garbage = abi.encodePacked(bytes32(uint256(1)), bytes32(uint256(2)), uint8(27));
    bytes memory approve = _approveKey(fresh);

    vm.prank(owner);
    authenticator.updateAuthentication(owner, approve, nonce, deadline, garbage);

    assertTrue(authenticator.masterKeys(owner, freshHash), 'approved on a signature over nothing');
    assertEq(
      authenticator.nonces(lNonceKey(owner), nonce >> 8),
      0,
      'and the nonce it named was never burned'
    );

    // the same calldata a second time, byte for byte: it settles again, which is the replay the
    // untouched bitmap implies
    vm.prank(owner);
    authenticator.updateAuthentication(owner, approve, nonce, deadline, garbage);
    assertTrue(authenticator.masterKeys(owner, freshHash), 'still approved');
    assertEq(authenticator.nonces(lNonceKey(owner), nonce >> 8), 0, 'still nothing burned');

    // and with an effect the third time, so "it settles again" is more than an idempotent write:
    // the state is moved away in between and the identical call moves it back
    vm.prank(owner);
    authenticator.updateAuthentication(owner, _revokeKey(fresh), nonce, deadline, garbage);
    assertFalse(authenticator.masterKeys(owner, freshHash), 'revoked, on the same dead signature');

    vm.prank(owner);
    authenticator.updateAuthentication(owner, approve, nonce, deadline, garbage);
    assertTrue(
      authenticator.masterKeys(owner, freshHash), 'and the very same call approves it again'
    );
    assertEq(
      authenticator.nonces(lNonceKey(owner), nonce >> 8),
      0,
      'across all four calls, no nonce was spent'
    );

    // the contrast that makes the above about the branch and not about the signature: the same
    // bogus bytes from anyone else are examined, and rejected
    vm.prank(relayer);
    vm.expectRevert(ISessionOrderAuthenticator.InvalidApprovalSignature.selector);
    authenticator.updateAuthentication(owner, approve, nonce, deadline, garbage);
  }

  // -------------------------------------------------------------------------------------------
  // SV-05..09 — the authentication gate
  // -------------------------------------------------------------------------------------------

  /**
   * SV-05 — only the hub it was bound to may ask for an authentication, on either entry point
   * @dev There are two of them now where there was one `verifyAuth`, and the gate is the whole of
   * their security, so each one is asserted separately.
   */
  function test_SV_05_onlyAllowanceHubMayAuthenticate() public {
    ExecutionOrder memory execOrder = _standardOrder(0, block.timestamp);
    FulfillmentOrder memory fulfillOrder = _openFulfillmentOrder(
      new ERC20Transfer[](0), new ValidationParams[](0), new GenericCall[](0), 0, block.timestamp
    );
    bytes memory data = _authData(key, hex'00');

    vm.prank(relayer);
    vm.expectRevert(IOrderAuthenticator.NotAllowanceHub.selector);
    authenticator.authenticateExecution(execOrder, data);

    vm.prank(relayer);
    vm.expectRevert(IOrderAuthenticator.NotAllowanceHub.selector);
    authenticator.authenticateFulfillment(fulfillOrder, data);
  }

  /// SV-06 — a key the owner never approved cannot authenticate anything
  function test_SV_06_unapprovedKeyRejected() public {
    _delegateKeyThroughHub(key);

    AuthKey memory stranger = _secpKey(relayer, block.timestamp + 30 days);

    vm.expectRevert(_masterKeyNotApproved(stranger));
    _executeViaAuthenticator(stranger, masterKeyPk, 8, block.timestamp + 1 hours, false);
  }

  /// SV-07 — expiry is inclusive: the expiry second itself still works, the one after it does not
  function test_SV_07_expiryBoundary() public {
    uint256 t = block.timestamp + 1 days;

    AuthKey memory expiring = _secpKey(masterSigner, t);
    _delegateKeyThroughHub(expiring);

    vm.warp(t);
    _executeViaAuthenticator(expiring, masterKeyPk, 9, t + 1 hours, true);

    vm.warp(t + 1);
    vm.expectRevert(
      abi.encodeWithSelector(ISessionOrderAuthenticator.AuthKeyExpired.selector, block.timestamp, t)
    );
    _executeViaAuthenticator(expiring, masterKeyPk, 10, t + 1 hours, false);
  }

  /// SV-08 — an approved key still has to have signed this particular order
  function test_SV_08_wrongSignatureRejected() public {
    _delegateKeyThroughHub(key);

    (, uint256 impostorKey) = makeAddrAndKey('impostor');

    vm.expectRevert(ISessionOrderAuthenticator.InvalidAuthenticationSignature.selector);
    _executeViaAuthenticator(key, impostorKey, 11, block.timestamp + 1 hours, false);
  }

  /// SV-09 — the authenticator's nonce makes an authentication single-use
  function test_SV_09_nonceReplayRejected() public {
    _delegateKeyThroughHub(key);

    uint256 nonce = 12;
    uint256 deadline = block.timestamp + 1 hours;

    _executeViaAuthenticator(key, masterKeyPk, nonce, deadline, true);

    vm.expectRevert(IUnorderedNonce.NonceAlreadyUsed.selector);
    _executeViaAuthenticator(key, masterKeyPk, nonce, deadline, false);
  }

  // -------------------------------------------------------------------------------------------
  // SV-10 — the two order typehashes keep the two entry points apart
  // -------------------------------------------------------------------------------------------

  /**
   * SV-10 — a signature over an execution order cannot authenticate a fulfillment
   * @dev `ExecutionOrder` and `FulfillmentOrder` are different EIP-712 types, so the digest a key
   * signs for one is not the digest the other entry point rebuilds. SV-10b is the control: the
   * fulfillment shape over the same order does settle.
   */
  function test_SV_10_executionSignatureCannotSettleAFulfillment() public {
    _delegateKeyThroughHub(key);

    uint256 nonce = 13;
    uint256 deadline = block.timestamp + 1 hours;

    ERC20Transfer[] memory erc20s = _erc20s(_tokenTransfer(AMOUNT));
    FulfillmentOrder memory fulfillOrder = _openFulfillmentOrder(
      erc20s, new ValidationParams[](0), new GenericCall[](0), nonce, deadline
    );

    // signed as an execution, then submitted through the fulfillment entry point
    bytes memory sig = _sign(masterKeyPk, _executionDigest(_standardOrder(nonce, deadline)));

    vm.prank(relayer);
    vm.expectRevert(ISessionOrderAuthenticator.InvalidAuthenticationSignature.selector);
    hub.fulfillOrderWithDelegatedAuthentication(
      fulfillOrder,
      address(authenticator),
      _authData(key, sig),
      _route(_calls(_routerCall(0, hex'01'))),
      '',
      false
    );
  }

  /// SV-10b — and the fulfillment shape is what that entry point does accept
  function test_SV_10b_fulfillmentSignatureSettlesAFulfillment() public {
    _delegateKeyThroughHub(key);

    uint256 nonce = 14;
    uint256 deadline = block.timestamp + 1 hours;

    ERC20Transfer[] memory erc20s = _erc20s(_tokenTransfer(AMOUNT));
    FulfillmentOrder memory fulfillOrder = _openFulfillmentOrder(
      erc20s, new ValidationParams[](0), new GenericCall[](0), nonce, deadline
    );
    uint256 before = IERC20(token18).balanceOf(address(router));

    vm.prank(relayer);
    hub.fulfillOrderWithDelegatedAuthentication(
      fulfillOrder,
      address(authenticator),
      _fulfillmentAuthData(fulfillOrder, key, masterKeyPk),
      _route(_calls(_routerCall(0, hex'01'))),
      '',
      false
    );

    assertEq(IERC20(token18).balanceOf(address(router)) - before, AMOUNT);
  }

  /**
   * SV-06b — the approval gate guards the fulfillment path too, not just the execution one
   * @dev Both entry points share one `_authenticate`, so what this constrains beyond `SV-06` is the
   * hub-side wiring: that the fulfillment path reaches it at all, over the fulfillment shape. The
   * second leg is the control — the same order shape under the approved key settles.
   */
  function test_SV_06b_unapprovedKeyRejectedOnTheFulfillmentPath() public {
    _delegateKeyThroughHub(key);

    AuthKey memory stranger = _secpKey(relayer, block.timestamp + 30 days);

    vm.expectRevert(_masterKeyNotApproved(stranger));
    _fulfillViaAuthenticator(stranger, masterKeyPk, 60, block.timestamp + 1 hours);

    uint256 before = IERC20(token18).balanceOf(address(router));
    _fulfillViaAuthenticator(key, masterKeyPk, 61, block.timestamp + 1 hours);
    assertEq(
      IERC20(token18).balanceOf(address(router)) - before, AMOUNT, 'the approved key still settles'
    );
  }

  /**
   * SV-07b — expiry is enforced on the fulfillment path, inclusively, as on the execution one
   * @dev The mirror of `SV-07`, for the same reason `SV-06b` exists: the expiry check on this path
   * is a separate copy of the one `SV-07` covers. The expiry second itself still works, so the
   * refusal one second later is about the boundary and not about the key.
   */
  function test_SV_07b_expiryBoundaryOnTheFulfillmentPath() public {
    uint256 t = block.timestamp + 1 days;

    AuthKey memory expiring = _secpKey(masterSigner, t);
    _delegateKeyThroughHub(expiring);

    vm.warp(t);
    uint256 before = IERC20(token18).balanceOf(address(router));
    _fulfillViaAuthenticator(expiring, masterKeyPk, 62, t + 1 hours);
    assertEq(
      IERC20(token18).balanceOf(address(router)) - before,
      AMOUNT,
      'the expiry second itself settles'
    );

    vm.warp(t + 1);
    vm.expectRevert(
      abi.encodeWithSelector(ISessionOrderAuthenticator.AuthKeyExpired.selector, block.timestamp, t)
    );
    _fulfillViaAuthenticator(expiring, masterKeyPk, 63, t + 1 hours);
  }

  // -------------------------------------------------------------------------------------------
  // SV-11 — the approval binds the whole key, not just its public half
  // -------------------------------------------------------------------------------------------

  function test_SV_11_changingExpiryBreaksTheApproval() public {
    _delegateKeyThroughHub(key);

    // same signer, later expiry: a different key as far as the approval is concerned
    AuthKey memory stretched = _secpKey(masterSigner, key.expiration + 1);

    vm.expectRevert(_masterKeyNotApproved(stretched));
    _executeViaAuthenticator(stretched, masterKeyPk, 15, block.timestamp + 1 hours, false);
  }

  // -------------------------------------------------------------------------------------------
  // SV-KEY-* — every signature scheme
  // -------------------------------------------------------------------------------------------

  /// SV-KEY-SECP-01 is covered by SV-01; this is the ERC-1271 half
  function test_SV_KEY_SECP_02_contractSigner() public {
    // a session key naming a contract: SignatureChecker falls through to ERC-1271
    AuthKey memory walletKey = AuthKey({
      publicKey: abi.encode(address(_wallet())),
      keyType: KeyType.Secp256k1,
      expiration: block.timestamp + 30 days
    });
    _delegateKeyThroughHub(walletKey);

    uint256 before = IERC20(token18).balanceOf(address(router));
    _executeViaAuthenticator(walletKey, _walletSignerKey, 16, block.timestamp + 1 hours, true);
    assertEq(IERC20(token18).balanceOf(address(router)) - before, AMOUNT);
  }

  /// SV-KEY-P256-01 / -02 — a canonical signature is accepted, its malleable twin is not
  function test_SV_KEY_P256() public {
    AuthKey memory p256 = AuthKey({
      publicKey: KeyFixtures.p256PublicKey(),
      keyType: KeyType.P256,
      expiration: block.timestamp + 30 days
    });
    _delegateKeyThroughHub(p256);

    uint256 nonce = 17;
    uint256 deadline = block.timestamp + 1 hours;
    bytes32 digest = _executionDigest(_standardOrder(nonce, deadline));

    bytes memory signature = KeyFixtures.p256Sign(digest);
    assertLe(KeyFixtures.sOf(signature), KeyFixtures.P256_HALF_N, 'fixture is canonical');

    uint256 before = IERC20(token18).balanceOf(address(router));
    _submitExecution(p256, signature, nonce, deadline);
    assertEq(IERC20(token18).balanceOf(address(router)) - before, AMOUNT, 'P256 accepted');

    // the same signature with s replaced by N - s must not verify
    bytes32 digest2 = _executionDigest(_standardOrder(18, deadline));
    bytes memory malleable = KeyFixtures.flipS(KeyFixtures.p256Sign(digest2));
    assertGt(KeyFixtures.sOf(malleable), KeyFixtures.P256_HALF_N, 'twin is non-canonical');

    vm.prank(relayer);
    vm.expectRevert(ISessionOrderAuthenticator.InvalidAuthenticationSignature.selector);
    _submitExecutionRaw(p256, malleable, 18, deadline);
  }

  /// SV-KEY-WEBAUTHN-01..03
  function test_SV_KEY_WebAuthn() public {
    AuthKey memory wa = AuthKey({
      publicKey: KeyFixtures.p256PublicKey(),
      keyType: KeyType.WebAuthn,
      expiration: block.timestamp + 30 days
    });
    _delegateKeyThroughHub(wa);

    uint256 deadline = block.timestamp + 1 hours;

    // -01 a user-verified assertion is accepted
    bytes32 digest = _executionDigest(_standardOrder(19, deadline));
    uint256 before = IERC20(token18).balanceOf(address(router));
    _submitExecution(wa, KeyFixtures.webAuthnAssertion(digest, true), 19, deadline);
    assertEq(IERC20(token18).balanceOf(address(router)) - before, AMOUNT, 'webauthn accepted');

    // -02 the authenticator requires user verification, so a UP-only assertion fails.
    // The assertion is built BEFORE the cheatcodes: it makes external calls of its own, and a
    // helper in argument position would consume the expectRevert instead of the hub call.
    bytes32 digest2 = _executionDigest(_standardOrder(20, deadline));
    bytes memory upOnly = KeyFixtures.webAuthnAssertion(digest2, false);

    vm.prank(relayer);
    vm.expectRevert(ISessionOrderAuthenticator.InvalidAuthenticationSignature.selector);
    _submitExecutionRaw(wa, upOnly, 20, deadline);

    // -03 an assertion that does not decode at all is rejected rather than reverting oddly
    vm.prank(relayer);
    vm.expectRevert(ISessionOrderAuthenticator.InvalidAuthenticationSignature.selector);
    _submitExecutionRaw(wa, hex'deadbeef', 21, deadline);
  }

  /**
   * SV-KEY-RSA-01 / -02 — a 2048-bit modulus verifies, a short one is refused
   * @dev Exercised at the library level against a checked-in vector. The signature must be made
   * with the private exponent, which is far too expensive to compute on-chain; verification uses
   * the public exponent and is what the contract performs.
   */
  function test_SV_KEY_Rsa() public {
    AuthKeyHarness harness = new AuthKeyHarness();

    AuthKey memory rsa = AuthKey({
      publicKey: KeyFixtures.rsaPublicKey(),
      keyType: KeyType.RSA,
      expiration: block.timestamp + 30 days
    });

    assertTrue(
      harness.verify(rsa, KeyFixtures.RSA_FIXED_DIGEST, KeyFixtures.rsaSignatureForFixedDigest()),
      'valid RSA signature accepted'
    );

    // a different digest must not verify under the same signature
    assertFalse(
      harness.verify(rsa, keccak256('other'), KeyFixtures.rsaSignatureForFixedDigest()),
      'signature is bound to its digest'
    );

    // OZ refuses a modulus below the 2048-bit floor, whatever the signature says
    AuthKey memory shortRsa = AuthKey({
      publicKey: KeyFixtures.rsaPublicKeyWithShortModulus(),
      keyType: KeyType.RSA,
      expiration: block.timestamp + 30 days
    });

    assertFalse(
      harness.verify(
        shortRsa, KeyFixtures.RSA_FIXED_DIGEST, KeyFixtures.rsaSignatureForFixedDigest()
      ),
      'short modulus refused'
    );
  }

  // -------------------------------------------------------------------------------------------
  // SV-DOMAIN / SV-FUZZ
  // -------------------------------------------------------------------------------------------

  /// @dev The separator itself, and that it differs from the hub's, is `DOM-01` in Management
  function test_SV_DOMAIN_matchesTheWrittenOutDomain() public view {
    (, string memory name, string memory version, uint256 chainId, address verifyingContract,,) =
      authenticator.eip712Domain();

    assertEq(name, 'KyberSwap Session Order Authenticator');
    assertEq(version, '1.0.0');
    assertEq(chainId, block.chainid);
    assertEq(verifyingContract, address(authenticator));
  }

  /**
   * SV-FUZZ-UPD — updating a key directly, across every scheme, expiry, nonce and direction
   * @dev Subsumes the relayed half of SV-02: same rail, same call, and both of that case's
   * assertions appear below over a wider domain. The update path never verifies signature material
   * against the key, only its hash, so the key type can be fuzzed across all four arms here even
   * though only Secp256k1 can be signed for in {testFuzz_SV_FUZZ_VER_nonceAndDeadline}. The
   * pre-state is set to the opposite of the fuzzed direction, so every run is a transition rather
   * than a no-op.
   */
  function testFuzz_SV_FUZZ_UPD_directUpdate(SessionFuzz memory f) public {
    KeyType keyType = KeyType(bound(f.keyType, 0, 3));
    uint256 expiration = block.timestamp + bound(f.expirationOffset, 0, 365 days);
    uint256 deadline = block.timestamp + bound(f.deadlineOffset, 0, 30 days);

    AuthKey memory fresh =
      AuthKey({publicKey: abi.encode(recipient), keyType: keyType, expiration: expiration});

    // SV-02's route, used here to establish the opposite pre-state without spending a nonce
    vm.prank(owner);
    authenticator.updateAuthentication(owner, _updateData(fresh, !f.approved), 0, deadline, '');
    assertEq(authenticator.masterKeys(owner, _keyHash(fresh)), !f.approved, 'pre-state');
    assertEq(authenticator.nonces(lNonceKey(owner), 0), 0, 'no nonce spent without a signature');

    bytes memory sig = _signMasterKeyApproval(fresh, f.approved, f.nonce, deadline);

    vm.prank(relayer);
    authenticator.updateAuthentication(
      owner, _updateData(fresh, f.approved), f.nonce, deadline, sig
    );

    assertEq(authenticator.masterKeys(owner, _keyHash(fresh)), f.approved, 'direction applied');
    assertEq(
      authenticator.nonces(lNonceKey(owner), f.nonce >> 8), 1 << (f.nonce & 0xff), 'nonce spent'
    );

    // the approval binds the whole key, so a different scheme over the same bytes is a different
    // key
    AuthKey memory other = AuthKey({
      publicKey: abi.encode(recipient),
      keyType: KeyType((uint8(keyType) + 1) % 4),
      expiration: expiration
    });
    assertFalse(
      authenticator.masterKeys(owner, _keyHash(other)), 'key type is part of the identity'
    );
  }

  function testFuzz_SV_FUZZ_VER_nonceAndDeadline(SessionVerifyFuzz memory f) public {
    uint256 nonce = f.nonce;
    uint256 deadline = block.timestamp + bound(f.deadlineOffset, 0, 30 days);

    // the key's own expiry is a live dimension: it must outlast the order for it to settle
    AuthKey memory fuzzKey =
      _secpKey(masterSigner, block.timestamp + bound(f.expirationOffset, 0, 365 days));
    _delegateKeyThroughHub(fuzzKey);

    uint256 before = IERC20(token18).balanceOf(address(router));
    _executeViaAuthenticator(fuzzKey, masterKeyPk, nonce, deadline, true);

    assertEq(IERC20(token18).balanceOf(address(router)) - before, AMOUNT);
    assertEq(
      authenticator.nonces(_keyHash(fuzzKey), nonce >> 8), 1 << (nonce & 0xff), 'exact nonce bit'
    );
  }

  // -------------------------------------------------------------------------------------------
  // SV-TIER-01..10 — the second tier: a master key granting session keys of its own
  // -------------------------------------------------------------------------------------------

  /**
   * SV-TIER-01 — a master key grants a session key, which then signs an order
   * @dev The flow a passkey exists for: the owner's wallet approves the passkey once, and the
   * passkey issues local keys with no wallet prompt. The grant lands in `sessionKeyMaster`
   * under the master key's hash, and leaves `masterKeys` alone.
   */
  function test_SV_TIER_01_masterKeyGrantsASessionKeyThatSignsAnOrder() public {
    _delegateKeyThroughHub(key);
    AuthKey memory sessionKey = _secpKey(sessionSigner, key.expiration);

    vm.prank(relayer);
    _approveSessionKey(key, sessionKey, 1, block.timestamp + 1 days, masterKeyPk);

    assertEq(
      authenticator.sessionKeyMaster(owner, _keyHash(sessionKey)),
      _keyHash(key),
      'granted under the master key'
    );
    assertFalse(
      authenticator.masterKeys(owner, _keyHash(sessionKey)), 'and not as a master key itself'
    );

    uint256 before = IERC20(token18).balanceOf(address(router));
    _executeViaAuthenticator(sessionKey, sessionKeyPk, 2, block.timestamp + 1 hours, true, true);
    assertEq(
      IERC20(token18).balanceOf(address(router)) - before, AMOUNT, 'the session key settled it'
    );
  }

  /// SV-TIER-01b — and on the fulfillment rail, which reaches the same check from the other side
  function test_SV_TIER_01b_sessionKeySignsAFulfillment() public {
    _delegateKeyThroughHub(key);
    AuthKey memory sessionKey = _secpKey(sessionSigner, key.expiration);

    vm.prank(relayer);
    _approveSessionKey(key, sessionKey, 1, block.timestamp + 1 days, masterKeyPk);

    uint256 before = IERC20(token18).balanceOf(address(router));
    _fulfillViaAuthenticator(sessionKey, sessionKeyPk, 3, block.timestamp + 1 hours, true);
    assertEq(IERC20(token18).balanceOf(address(router)) - before, AMOUNT, 'the fulfillment settled');
  }

  /**
   * SV-TIER-02 — a session key cannot grant another, so the chain is two deep and no more
   * @dev One read enforces this: the rail asks whether the key presented as the approver is one
   * the owner approved themselves, and a session key never is.
   */
  function test_SV_TIER_02_aSessionKeyCannotGrantAnother() public {
    _delegateKeyThroughHub(key);
    AuthKey memory sessionKey = _secpKey(sessionSigner, key.expiration);

    uint256 deadline = block.timestamp + 1 days;
    vm.prank(relayer);
    _approveSessionKey(key, sessionKey, 1, deadline, masterKeyPk);

    AuthKey memory grandchild = _secpKey(recipient, key.expiration);
    bytes memory sig =
      _signSessionKeyApproval(sessionKey, grandchild, true, 4, deadline, sessionKeyPk);

    vm.prank(relayer);
    vm.expectRevert(_masterKeyNotApproved(sessionKey));
    authenticator.updateAuthentication(
      owner, _sessionKeyData(grandchild, sessionKey, true), 4, deadline, sig
    );

    assertEq(
      authenticator.sessionKeyMaster(owner, _keyHash(grandchild)), bytes32(0), 'nothing granted'
    );
    assertFalse(authenticator.masterKeys(owner, _keyHash(grandchild)), 'and nothing promoted');
  }

  /// SV-TIER-03 — nor can a key the owner never approved at all
  function test_SV_TIER_03_anUnapprovedKeyCannotGrant() public {
    _delegateKeyThroughHub(key);

    (address strangerSigner, uint256 strangerPk) = makeAddrAndKey('stranger key');
    AuthKey memory stranger = _secpKey(strangerSigner, block.timestamp + 30 days);
    AuthKey memory sessionKey = _secpKey(sessionSigner, block.timestamp + 1 days);

    uint256 deadline = block.timestamp + 1 days;
    bytes memory sig = _signSessionKeyApproval(stranger, sessionKey, true, 5, deadline, strangerPk);

    vm.prank(relayer);
    vm.expectRevert(_masterKeyNotApproved(stranger));
    authenticator.updateAuthentication(
      owner, _sessionKeyData(sessionKey, stranger, true), 5, deadline, sig
    );
  }

  /**
   * SV-TIER-04 — revoking a master key takes every session key under it
   * @dev The grant row itself is left standing, so the owner re-approving the identical credential
   * revives the keys that master had minted. The refusal in between names the master key rather
   * than the session key, because the master is the thing no longer approved.
   */
  function test_SV_TIER_04_revokingTheMasterKeyTakesItsSessionKeys() public {
    _delegateKeyThroughHub(key);
    AuthKey memory sessionKey = _secpKey(sessionSigner, key.expiration);

    uint256 deadline = block.timestamp + 1 days;
    vm.prank(relayer);
    _approveSessionKey(key, sessionKey, 1, deadline, masterKeyPk);
    _executeViaAuthenticator(sessionKey, sessionKeyPk, 10, block.timestamp + 1 hours, true, true);

    vm.prank(owner);
    authenticator.updateAuthentication(owner, _revokeKey(key), 0, deadline, '');

    assertFalse(authenticator.masterKeys(owner, _keyHash(key)), 'the master key is gone');
    assertEq(
      authenticator.sessionKeyMaster(owner, _keyHash(sessionKey)),
      _keyHash(key),
      'the grant itself is untouched'
    );

    vm.expectRevert(_masterKeyNotApproved(key));
    _executeViaAuthenticator(sessionKey, sessionKeyPk, 11, block.timestamp + 1 hours, false, true);

    vm.prank(owner);
    authenticator.updateAuthentication(owner, _approveKey(key), 0, deadline, '');
    _executeViaAuthenticator(sessionKey, sessionKeyPk, 12, block.timestamp + 1 hours, true, true);
  }

  /**
   * SV-TIER-05 — a session key may not outlive the master key granting it
   * @dev Both legs run on nonce 20: the refusal happens before the burn, so the number is still
   * there for the leg that succeeds.
   */
  function test_SV_TIER_05_aSessionKeyMayNotOutliveItsMaster() public {
    _delegateKeyThroughHub(key);
    uint256 deadline = block.timestamp + 1 days;

    AuthKey memory tooLong = _secpKey(sessionSigner, key.expiration + 1);
    bytes memory sig = _signSessionKeyApproval(key, tooLong, true, 20, deadline, masterKeyPk);

    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(
        ISessionOrderAuthenticator.SessionKeyOutlivesMasterKey.selector,
        key.expiration + 1,
        key.expiration
      )
    );
    authenticator.updateAuthentication(
      owner, _sessionKeyData(tooLong, key, true), 20, deadline, sig
    );

    AuthKey memory equal = _secpKey(sessionSigner, key.expiration);
    vm.prank(relayer);
    _approveSessionKey(key, equal, 20, deadline, masterKeyPk);

    assertEq(
      authenticator.sessionKeyMaster(owner, _keyHash(equal)),
      _keyHash(key),
      'the same second as its master is allowed'
    );
  }

  /// SV-TIER-06 — the signature has to be the granting key's, not the granted key's
  function test_SV_TIER_06_theMasterKeyMustHaveSignedIt() public {
    _delegateKeyThroughHub(key);
    AuthKey memory sessionKey = _secpKey(sessionSigner, key.expiration);

    uint256 deadline = block.timestamp + 1 days;
    bytes memory sig = _signSessionKeyApproval(key, sessionKey, true, 21, deadline, sessionKeyPk);

    vm.prank(relayer);
    vm.expectRevert(ISessionOrderAuthenticator.InvalidApprovalSignature.selector);
    authenticator.updateAuthentication(
      owner, _sessionKeyData(sessionKey, key, true), 21, deadline, sig
    );
  }

  /**
   * SV-TIER-07 — the approval names the account it is for
   * @dev The same credential can be a master key for two accounts, so the decision carries the
   * owner. The second leg submits the very same signature for the account it does name, so the
   * refusal is evidence about `owner` rather than about a bad signature.
   */
  function test_SV_TIER_07_theApprovalNamesTheAccountItIsFor() public {
    _delegateKeyThroughHub(key);
    AuthKey memory sessionKey = _secpKey(sessionSigner, key.expiration);

    uint256 deadline = block.timestamp + 1 days;
    vm.prank(recipient);
    authenticator.updateAuthentication(recipient, _approveKey(key), 0, deadline, '');

    bytes memory sig =
      _signSessionKeyApproval(recipient, key, sessionKey, true, 22, deadline, masterKeyPk);

    vm.prank(relayer);
    vm.expectRevert(ISessionOrderAuthenticator.InvalidApprovalSignature.selector);
    authenticator.updateAuthentication(
      owner, _sessionKeyData(sessionKey, key, true), 22, deadline, sig
    );

    vm.prank(relayer);
    authenticator.updateAuthentication(
      recipient, _sessionKeyData(sessionKey, key, true), 22, deadline, sig
    );

    assertEq(
      authenticator.sessionKeyMaster(recipient, _keyHash(sessionKey)),
      _keyHash(key),
      'granted for the account it names'
    );
    assertEq(
      authenticator.sessionKeyMaster(owner, _keyHash(sessionKey)), bytes32(0), 'and for no other'
    );
  }

  /**
   * SV-TIER-08 — the nonce burns in the master key's namespace, because the master key signed
   * @dev Three namespaces are in play for one number: the owner's, the master key's and the
   * session key's. Spending it as the master key must leave the other two alone, or an owner
   * approving at nonce 9 would silently block their passkey's ninth grant.
   */
  function test_SV_TIER_08_theNonceBurnsInTheMasterKeysNamespace() public {
    _delegateKeyThroughHub(key);
    AuthKey memory sessionKey = _secpKey(sessionSigner, key.expiration);

    uint256 deadline = block.timestamp + 1 days;
    uint256 nonce = 9;

    vm.prank(relayer);
    _approveSessionKey(key, sessionKey, nonce, deadline, masterKeyPk);

    assertEq(authenticator.nonces(_keyHash(key), 0), 1 << nonce, 'the master key spent it');
    assertEq(authenticator.nonces(lNonceKey(owner), 0), 0, "the owner's namespace is untouched");
    assertEq(authenticator.nonces(_keyHash(sessionKey), 0), 0, "and so is the session key's");

    AuthKey memory other = _secpKey(recipient, key.expiration);
    bytes memory replay = _signSessionKeyApproval(key, other, true, nonce, deadline, masterKeyPk);
    vm.prank(relayer);
    vm.expectRevert(IUnorderedNonce.NonceAlreadyUsed.selector);
    authenticator.updateAuthentication(
      owner, _sessionKeyData(other, key, true), nonce, deadline, replay
    );

    bytes memory ownerSig = _signMasterKeyApproval(other, true, nonce, deadline);
    vm.prank(relayer);
    authenticator.updateAuthentication(owner, _approveKey(other), nonce, deadline, ownerSig);
    assertTrue(authenticator.masterKeys(owner, _keyHash(other)), 'the owner still has that number');

    _executeViaAuthenticator(sessionKey, sessionKeyPk, nonce, block.timestamp + 1 hours, true, true);
  }

  /// SV-TIER-09 — a master key revokes a session key it granted, and the key stops signing
  function test_SV_TIER_09_aMasterKeyRevokesItsSessionKey() public {
    _delegateKeyThroughHub(key);
    AuthKey memory sessionKey = _secpKey(sessionSigner, key.expiration);

    uint256 deadline = block.timestamp + 1 days;
    vm.prank(relayer);
    _approveSessionKey(key, sessionKey, 40, deadline, masterKeyPk);
    _executeViaAuthenticator(sessionKey, sessionKeyPk, 41, block.timestamp + 1 hours, true, true);

    bytes memory sig = _signSessionKeyApproval(key, sessionKey, false, 42, deadline, masterKeyPk);
    vm.prank(relayer);
    authenticator.updateAuthentication(
      owner, _sessionKeyData(sessionKey, key, false), 42, deadline, sig
    );

    assertEq(
      authenticator.sessionKeyMaster(owner, _keyHash(sessionKey)),
      bytes32(0),
      'the grant is cleared'
    );
    vm.expectRevert(_sessionKeyNotApproved(sessionKey));
    _executeViaAuthenticator(sessionKey, sessionKeyPk, 43, block.timestamp + 1 hours, false, true);
  }

  /**
   * SV-TIER-10 — a key holding both grants may be presented under either
   * @dev Nothing stops one credential from holding the owner's grant and a master key's at once,
   * and the tier it is presented as decides which one settles it. Each therefore stands on its own:
   * revoking the master key closes the session route — a refusal naming that master — and leaves
   * the owner's grant; revoking the owner's closes that one and leaves the session route. A master key granting itself resolves to
   * its own approval either way, which is the same rule rather than an exception to it.
   */
  function test_SV_TIER_10_eachGrantIsUsableOnItsOwnTier() public {
    _delegateKeyThroughHub(key);
    AuthKey memory both = _secpKey(sessionSigner, key.expiration);
    uint256 deadline = block.timestamp + 1 days;

    vm.prank(relayer);
    _approveSessionKey(key, both, 50, deadline, masterKeyPk);
    vm.prank(owner);
    authenticator.updateAuthentication(owner, _approveKey(both), 0, deadline, '');

    // either tier settles an order while both grants stand
    _executeViaAuthenticator(both, sessionKeyPk, 51, block.timestamp + 1 hours, true, true);
    _executeViaAuthenticator(both, sessionKeyPk, 52, block.timestamp + 1 hours, true, false);

    // revoking the master key closes the session route, and leaves the owner's grant alone
    vm.prank(owner);
    authenticator.updateAuthentication(owner, _revokeKey(key), 0, deadline, '');

    vm.expectRevert(_masterKeyNotApproved(key));
    _executeViaAuthenticator(both, sessionKeyPk, 53, block.timestamp + 1 hours, false, true);
    _executeViaAuthenticator(both, sessionKeyPk, 54, block.timestamp + 1 hours, true, false);

    // and revoking the owner's grant closes the remaining route
    vm.prank(owner);
    authenticator.updateAuthentication(owner, _revokeKey(both), 0, deadline, '');

    vm.expectRevert(_masterKeyNotApproved(both));
    _executeViaAuthenticator(both, sessionKeyPk, 55, block.timestamp + 1 hours, false, false);
  }

  /// SV-TIER-10b — a master key that grants itself still signs, on either tier
  function test_SV_TIER_10b_aMasterKeyMayGrantItself() public {
    _delegateKeyThroughHub(key);
    uint256 deadline = block.timestamp + 1 days;

    bytes memory selfSig = _signSessionKeyApproval(key, key, true, 56, deadline, masterKeyPk);
    vm.prank(relayer);
    authenticator.updateAuthentication(
      owner, _sessionKeyData(key, key, true), 56, deadline, selfSig
    );

    assertEq(
      authenticator.sessionKeyMaster(owner, _keyHash(key)), _keyHash(key), 'granted to itself'
    );
    _executeViaAuthenticator(key, masterKeyPk, 57, block.timestamp + 1 hours, true, true);
    _executeViaAuthenticator(key, masterKeyPk, 58, block.timestamp + 1 hours, true, false);
  }

  /**
   * SV-TIER-11 — the tier hint is trusted for nothing
   * @dev It picks which mapping settles the key, so naming the wrong one finds no approval there
   * and is refused. A master key offered as a session key has no master key behind it; a session
   * key offered as a master key holds no grant of its own. Both legs then settle under the tier
   * they do hold, so the refusals are about the hint and not about the keys.
   */
  function test_SV_TIER_11_theWrongTierIsRefused() public {
    _delegateKeyThroughHub(key);
    AuthKey memory sessionKey = _secpKey(sessionSigner, key.expiration);

    vm.prank(relayer);
    _approveSessionKey(key, sessionKey, 60, block.timestamp + 1 days, masterKeyPk);

    vm.expectRevert(_sessionKeyNotApproved(key));
    _executeViaAuthenticator(key, masterKeyPk, 61, block.timestamp + 1 hours, false, true);

    vm.expectRevert(_masterKeyNotApproved(sessionKey));
    _executeViaAuthenticator(sessionKey, sessionKeyPk, 62, block.timestamp + 1 hours, false, false);

    _executeViaAuthenticator(key, masterKeyPk, 61, block.timestamp + 1 hours, true, false);
    _executeViaAuthenticator(sessionKey, sessionKeyPk, 62, block.timestamp + 1 hours, true, true);
  }

  /**
   * SV-TIER-12 — an approval will not record a key that has already expired
   * @dev Without this the call succeeds and writes a key no order can ever present, so the holder
   * learns of it only when a settlement is refused. Checked on the way in only: a key that has
   * expired must still be clearable, or stale state could never be tidied.
   */
  function test_SV_TIER_12_anExpiredKeyCannotBeApproved() public {
    _delegateKeyThroughHub(key);

    uint256 deadline = block.timestamp + 365 days;
    AuthKey memory stale = _secpKey(sessionSigner, block.timestamp + 1 hours);
    bytes32 staleHash = _keyHash(stale);

    vm.warp(stale.expiration + 1);

    // the owner's rail refuses it, and still revokes it
    vm.prank(owner);
    vm.expectRevert(
      abi.encodeWithSelector(
        ISessionOrderAuthenticator.AuthKeyExpired.selector, block.timestamp, stale.expiration
      )
    );
    authenticator.updateAuthentication(owner, _approveKey(stale), 0, deadline, '');

    vm.prank(owner);
    authenticator.updateAuthentication(owner, _revokeKey(stale), 0, deadline, '');
    assertFalse(authenticator.masterKeys(owner, staleHash), 'revoking an expired key still works');

    // the hub's delegation path reaches `initAuthentication`, which refuses it too
    vm.prank(owner);
    vm.expectRevert(
      abi.encodeWithSelector(
        ISessionOrderAuthenticator.AuthKeyExpired.selector, block.timestamp, stale.expiration
      )
    );
    hub.updateDelegation(owner, address(authenticator), true, _encodeKey(stale), 0, deadline, '');
  }

  /**
   * SV-TIER-12b — nor will a master key grant one, and an expired master key can grant nothing
   * @dev The expiry bound and this check together leave an expired master key no reachable grant:
   * a session key inside its bound is expired as well, and one outside it breaks the bound. So the
   * master key needs no expiry check of its own.
   */
  function test_SV_TIER_12b_anExpiredMasterKeyCanGrantNothing() public {
    AuthKey memory master = _secpKey(masterSigner, block.timestamp + 2 hours);
    _delegateKeyThroughHub(master);

    uint256 deadline = block.timestamp + 365 days;
    AuthKey memory stale = _secpKey(sessionSigner, master.expiration);
    AuthKey memory fresh = _secpKey(recipient, master.expiration + 1);

    vm.warp(master.expiration + 1);

    // inside the bound, and therefore expired with it
    bytes memory staleSig = _signSessionKeyApproval(master, stale, true, 70, deadline, masterKeyPk);
    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(
        ISessionOrderAuthenticator.AuthKeyExpired.selector, block.timestamp, stale.expiration
      )
    );
    authenticator.updateAuthentication(
      owner, _sessionKeyData(stale, master, true), 70, deadline, staleSig
    );

    // outside the bound, and therefore refused by it
    bytes memory freshSig = _signSessionKeyApproval(master, fresh, true, 71, deadline, masterKeyPk);
    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(
        ISessionOrderAuthenticator.SessionKeyOutlivesMasterKey.selector,
        fresh.expiration,
        master.expiration
      )
    );
    authenticator.updateAuthentication(
      owner, _sessionKeyData(fresh, master, true), 71, deadline, freshSig
    );

    // revoking through an expired master key still works
    bytes memory revokeSig =
      _signSessionKeyApproval(master, stale, false, 72, deadline, masterKeyPk);
    vm.prank(relayer);
    authenticator.updateAuthentication(
      owner, _sessionKeyData(stale, master, false), 72, deadline, revokeSig
    );
    assertEq(
      authenticator.sessionKeyMaster(owner, _keyHash(stale)), bytes32(0), 'revocation still lands'
    );
  }

  /// SV-FUZZ-TIER — the master key rail over its whole domain
  function testFuzz_SV_FUZZ_TIER_masterKeyRail(TierFuzz memory f) public {
    uint256 masterExpiration = block.timestamp + bound(f.masterExpirationOffset, 1 hours, 365 days);
    uint256 sessionExpiration =
      block.timestamp + bound(f.sessionExpirationOffset, 1, masterExpiration - block.timestamp);
    uint256 deadline = block.timestamp + bound(f.deadlineOffset, 1, 365 days);
    uint256 nonce = bound(f.nonce, 0, type(uint64).max);

    AuthKey memory masterKey = _secpKey(masterSigner, masterExpiration);
    AuthKey memory sessionKey = _secpKey(sessionSigner, sessionExpiration);
    _delegateKeyThroughHub(masterKey);

    bytes memory sig =
      _signSessionKeyApproval(masterKey, sessionKey, f.approved, nonce, deadline, masterKeyPk);

    vm.prank(relayer);
    authenticator.updateAuthentication(
      owner, _sessionKeyData(sessionKey, masterKey, f.approved), nonce, deadline, sig
    );

    assertEq(
      authenticator.sessionKeyMaster(owner, _keyHash(sessionKey)),
      f.approved ? _keyHash(masterKey) : bytes32(0),
      'the direction decides the grant'
    );
    assertEq(
      authenticator.nonces(_keyHash(masterKey), nonce >> 8),
      1 << (nonce & 0xff),
      'the master key spends the nonce'
    );
    assertEq(authenticator.nonces(lNonceKey(owner), nonce >> 8), 0, 'and the owner does not');
  }

  // -------------------------------------------------------------------------------------------
  // helpers
  // -------------------------------------------------------------------------------------------

  address private _walletAddr;
  uint256 internal _walletSignerKey;

  function _wallet() private returns (address) {
    if (_walletAddr == address(0)) {
      address signer;
      (signer, _walletSignerKey) = makeAddrAndKey('wallet key');
      _walletAddr = address(new ERC1271WalletLocal(signer));
    }
    return _walletAddr;
  }

  /// @dev The error for a key presented as a master key that the owner never approved, payload
  /// and all
  function _masterKeyNotApproved(AuthKey memory masterKey) private view returns (bytes memory) {
    return abi.encodeWithSelector(
      ISessionOrderAuthenticator.MasterKeyNotApproved.selector, owner, _keyHash(masterKey)
    );
  }

  /// @dev The error for a session key with no master key the owner still holds behind it
  function _sessionKeyNotApproved(AuthKey memory sessionKey) private view returns (bytes memory) {
    return abi.encodeWithSelector(
      ISessionOrderAuthenticator.SessionKeyNotApproved.selector, owner, _keyHash(sessionKey)
    );
  }

  /// @dev The one-transfer, one-call order every SV case submits
  function _standardOrder(uint256 nonce, uint256 deadline)
    private
    view
    returns (ExecutionOrder memory)
  {
    return _executionOrder(
      ANY,
      _erc20s(_tokenTransfer(AMOUNT)),
      new ERC721Transfer[](0),
      _calls(_routerCall(0, hex'01')),
      nonce,
      deadline
    );
  }

  function _executeViaAuthenticator(
    AuthKey memory key,
    uint256 signerKey,
    uint256 nonce,
    uint256 deadline,
    bool expectSuccess
  ) private {
    _executeViaAuthenticator(key, signerKey, nonce, deadline, expectSuccess, false);
  }

  /// @dev As above, naming the tier the key is presented as
  function _executeViaAuthenticator(
    AuthKey memory key,
    uint256 signerKey,
    uint256 nonce,
    uint256 deadline,
    bool expectSuccess,
    bool isSessionKey
  ) private {
    bytes memory sig = _sign(signerKey, _executionDigest(_standardOrder(nonce, deadline)));
    if (expectSuccess) {
      vm.prank(relayer);
    }
    _submitExecutionRaw(key, sig, nonce, deadline, isSessionKey);
  }

  /// @dev The fulfillment counterpart of {_executeViaAuthenticator}, open route and no approver
  function _fulfillViaAuthenticator(
    AuthKey memory key,
    uint256 signerKey,
    uint256 nonce,
    uint256 deadline
  ) private {
    _fulfillViaAuthenticator(key, signerKey, nonce, deadline, false);
  }

  /// @dev As above, naming the tier the key is presented as
  function _fulfillViaAuthenticator(
    AuthKey memory sessionKey,
    uint256 signerKey,
    uint256 nonce,
    uint256 deadline,
    bool isSessionKey
  ) private {
    FulfillmentOrder memory order = _openFulfillmentOrder(
      _erc20s(_tokenTransfer(AMOUNT)),
      new ValidationParams[](0),
      new GenericCall[](0),
      nonce,
      deadline
    );
    bytes memory data = _fulfillmentAuthData(order, sessionKey, signerKey, isSessionKey);

    vm.prank(relayer);
    hub.fulfillOrderWithDelegatedAuthentication(
      order, address(authenticator), data, _route(_calls(_routerCall(0, hex'01'))), '', false
    );
  }

  function _submitExecution(
    AuthKey memory key,
    bytes memory signature,
    uint256 nonce,
    uint256 deadline
  ) private {
    vm.prank(relayer);
    _submitExecutionRaw(key, signature, nonce, deadline, false);
  }

  function _submitExecutionRaw(
    AuthKey memory key,
    bytes memory signature,
    uint256 nonce,
    uint256 deadline
  ) private {
    _submitExecutionRaw(key, signature, nonce, deadline, false);
  }

  function _submitExecutionRaw(
    AuthKey memory key,
    bytes memory signature,
    uint256 nonce,
    uint256 deadline,
    bool isSessionKey
  ) private {
    hub.executeOrderWithDelegatedAuthentication(
      _standardOrder(nonce, deadline),
      address(authenticator),
      _authData(key, signature, isSessionKey),
      false
    );
  }
}

/// @dev Exposes the library's calldata `verify` so a key scheme can be checked without the hub
contract AuthKeyHarness {
  function verify(AuthKey calldata key, bytes32 digest, bytes calldata signature)
    external
    view
    returns (bool)
  {
    return key.verify(digest, signature);
  }
}

/// @dev Local ERC-1271 wallet, kept out of the shared mocks so this batch owns its fixture
contract ERC1271WalletLocal {
  address private immutable SIGNER;

  constructor(address signer) {
    SIGNER = signer;
  }

  function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
    (address recovered,,) = _tryRecover(hash, signature);
    return recovered == SIGNER ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
  }

  function _tryRecover(bytes32 hash, bytes calldata signature)
    private
    pure
    returns (address, uint8, bytes32)
  {
    if (signature.length != 65) return (address(0), 0, 0);
    bytes32 r = bytes32(signature[0:32]);
    bytes32 s = bytes32(signature[32:64]);
    uint8 v = uint8(signature[64]);
    return (ecrecover(hash, v, r, s), v, r);
  }
}
