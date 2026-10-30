// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AuthenticatorBase} from 'test/v2/authenticators/base/AuthenticatorBase.sol';

import {KeyFixtures} from 'test/v2/authenticators/mocks/KeyFixtures.sol';

import {IUnorderedNonce} from 'src/base/interfaces/IUnorderedNonce.sol';
import {AuthKey} from 'src/base/types/AuthKey.sol';
import {KeyType} from 'src/base/types/KeyType.sol';
import {
  ITwoTiersOrderAuthenticator
} from 'src/v2/authenticators/interfaces/ITwoTiersOrderAuthenticator.sol';
import {IOrderAuthenticator} from 'src/v2/interfaces/IOrderAuthenticator.sol';
import {ERC20Allowance} from 'src/v2/types/ERC20Allowance.sol';
import {ERC20Transfer} from 'src/v2/types/ERC20Transfer.sol';
import {ERC721Transfer} from 'src/v2/types/ERC721Transfer.sol';
import {ExecutionOrder} from 'src/v2/types/ExecutionOrder.sol';
import {FulfillmentOrder} from 'src/v2/types/FulfillmentOrder.sol';
import {GenericCall} from 'src/v2/types/GenericCall.sol';
import {ValidationParams} from 'src/v2/types/ValidationParams.sol';

import {IERC20} from 'openzeppelin-contracts/contracts/token/ERC20/IERC20.sol';
import {
  ERC7913P256Verifier
} from 'openzeppelin-contracts/contracts/utils/cryptography/verifiers/ERC7913P256Verifier.sol';

/// @notice `SV-*` — session key approval, the hub-only gate, expiry, replay and every key scheme.
contract TwoTiersOrderAuthenticatorTest is AuthenticatorBase {
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

    vm.recordLogs();
    _executeViaAuthenticator(key, masterKeyPk, nonce, deadline, true);
    _assertNoRevokeNonce(vm.getRecordedLogs());

    assertEq(IERC20(token18).balanceOf(address(router)) - before, AMOUNT, 'tokens moved');
    assertEq(
      authenticator.nonces(_credentialHash(key), nonce >> 8),
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

    vm.expectEmit(address(authenticator));
    emit ITwoTiersOrderAuthenticator.UpdateMasterKey(owner, _keyHash(fresh), fresh, true);
    vm.prank(owner);
    authenticator.updateAuthentication(owner, _approveKey(fresh), 0, block.timestamp + 1 days, '');

    assertTrue(authenticator.masterKeys(owner, _keyHash(fresh)), 'approved');
    assertEq(authenticator.nonces(lNonceKey(owner), 0), 0, 'no nonce spent without a signature');
  }

  /// SV-02b — but not on someone else's behalf
  function test_SV_02b_strangerCannotApproveWithoutSignature() public {
    AuthKey memory fresh = _secpKey(recipient, block.timestamp + 10 days);

    vm.prank(relayer);
    vm.expectRevert(ITwoTiersOrderAuthenticator.InvalidUpdateSignature.selector);
    authenticator.updateAuthentication(owner, _approveKey(fresh), 0, block.timestamp + 1 days, '');
  }

  /// SV-03 — a signature from anyone but the owner is rejected
  function test_SV_03_directApprovalWrongSigner() public {
    AuthKey memory fresh = _secpKey(recipient, block.timestamp + 10 days);
    uint256 deadline = block.timestamp + 1 days;

    bytes32 digest =
      lTypedDataHash(_authenticatorDomain(), lMasterKeyUpdate(owner, fresh, true, 4, deadline));
    bytes memory sig = _sign(masterKeyPk, digest); // the session key, not the owner

    vm.prank(relayer);
    vm.expectRevert(ITwoTiersOrderAuthenticator.InvalidUpdateSignature.selector);
    authenticator.updateAuthentication(owner, _approveKey(fresh), 4, deadline, sig);
  }

  /// SV-04 — the approval deadline is enforced by the authenticator itself
  function test_SV_04_directApprovalExpired() public {
    AuthKey memory fresh = _secpKey(recipient, block.timestamp + 10 days);
    uint256 deadline = block.timestamp - 1;
    bytes memory sig = _signMasterKeyUpdate(fresh, true, 5, deadline);

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

    vm.expectEmit(address(authenticator));
    emit ITwoTiersOrderAuthenticator.UpdateMasterKey(owner, _keyHash(key), key, false);
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
    bytes memory sig = _signMasterKeyUpdate(key, false, 32, deadline);

    vm.recordLogs();
    vm.expectEmit(address(authenticator));
    emit ITwoTiersOrderAuthenticator.UpdateMasterKey(owner, _keyHash(key), key, false);
    vm.prank(relayer);
    authenticator.updateAuthentication(owner, _revokeKey(key), 32, deadline, sig);
    _assertNoRevokeNonce(vm.getRecordedLogs());

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
    bytes memory approval = _signMasterKeyUpdate(fresh, true, 33, deadline);
    vm.prank(relayer);
    vm.expectRevert(ITwoTiersOrderAuthenticator.InvalidUpdateSignature.selector);
    authenticator.updateAuthentication(owner, _revokeKey(fresh), 33, deadline, approval);
    assertEq(authenticator.nonces(lNonceKey(owner), 0), 0, 'a refused update burns nothing');

    // the same signature, submitted as what the owner signed
    vm.expectEmit(address(authenticator));
    emit ITwoTiersOrderAuthenticator.UpdateMasterKey(owner, _keyHash(fresh), fresh, true);
    vm.prank(relayer);
    authenticator.updateAuthentication(owner, _approveKey(fresh), 33, deadline, approval);
    assertTrue(authenticator.masterKeys(owner, _keyHash(fresh)), 'approved on its own direction');

    // and the mirror: a revocation, submitted as an approval
    bytes memory revocation = _signMasterKeyUpdate(key, false, 34, deadline);
    vm.prank(relayer);
    vm.expectRevert(ITwoTiersOrderAuthenticator.InvalidUpdateSignature.selector);
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

    bytes memory sig = _signMasterKeyUpdate(fresh, true, 36, deadline);

    vm.prank(relayer);
    authenticator.updateAuthentication(owner, data, 36, deadline, sig);

    assertTrue(authenticator.masterKeys(owner, _keyHash(fresh)), 'narrowed to true');
  }

  // -------------------------------------------------------------------------------------------
  // SV-UPD-01 — the owner's own call takes no signature
  // -------------------------------------------------------------------------------------------

  /**
   * SV-UPD-01 — on the owner's own call a signature is refused, and an empty one approves without
   * spending the nonce
   * @dev Being `msg.sender` is the authentication on this branch, so a signature here would not be
   * checked and its nonce would stay unspent, leaving it to be replayed by anyone later. The same
   * bytes from anyone else are checked and refused.
   */
  function test_SV_UPD_01_ownerBranchTakesNoSignature() public {
    AuthKey memory fresh = _secpKey(recipient, block.timestamp + 10 days);
    bytes32 freshHash = _keyHash(fresh);
    uint256 nonce = 40;
    uint256 deadline = block.timestamp + 1 days;

    bytes memory sig = _signMasterKeyUpdate(fresh, true, nonce, deadline);
    bytes memory approve = _approveKey(fresh);

    vm.prank(owner);
    vm.expectRevert(ITwoTiersOrderAuthenticator.UnexpectedSignature.selector);
    authenticator.updateAuthentication(owner, approve, nonce, deadline, sig);

    vm.prank(owner);
    authenticator.updateAuthentication(owner, approve, nonce, deadline, '');
    assertTrue(authenticator.masterKeys(owner, freshHash), 'approved on the empty signature');
    assertEq(authenticator.nonces(lNonceKey(owner), nonce >> 8), 0, 'no nonce spent');

    // the signature the owner could not pass is still good for anyone else, on its nonce
    vm.prank(relayer);
    authenticator.updateAuthentication(owner, approve, nonce, deadline, sig);
    assertEq(
      authenticator.nonces(lNonceKey(owner), nonce >> 8), 1 << (nonce & 0xff), 'relayed, spent'
    );
  }

  /**
   * SV-UPD-02 — an update that writes the value already stored still emits
   * @dev The master-key rail approves a key that is already approved, and the session-key rail
   * revokes a session key that no master key approved. Both leave the state unchanged and emit
   * the same event as a transition.
   */
  function test_SV_UPD_02_anUnchangedWriteStillEmits() public {
    _delegateKeyThroughHub(key);
    uint256 deadline = block.timestamp + 1 days;

    vm.expectEmit(address(authenticator));
    emit ITwoTiersOrderAuthenticator.UpdateMasterKey(owner, _keyHash(key), key, true);
    vm.prank(owner);
    authenticator.updateAuthentication(owner, _approveKey(key), 0, deadline, '');
    assertTrue(authenticator.masterKeys(owner, _keyHash(key)), 'still approved');

    AuthKey memory sessionKey = _secpKey(sessionSigner, key.expiration);
    bytes memory sig = _signSessionKeyUpdate(key, sessionKey, false, 90, deadline, masterKeyPk);

    vm.expectEmit(address(authenticator));
    emit ITwoTiersOrderAuthenticator.UpdateSessionKey(
      owner, _keyHash(sessionKey), _keyHash(key), sessionKey, false
    );
    vm.prank(relayer);
    authenticator.updateAuthentication(
      owner, _sessionKeyData(sessionKey, key, false), 90, deadline, sig
    );
    assertEq(
      authenticator.sessionKeyMaster(owner, _keyHash(sessionKey)), bytes32(0), 'still unapproved'
    );
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
      new ERC20Allowance[](0), new ValidationParams[](0), new GenericCall[](0), 0, block.timestamp
    );
    bytes memory data = _authData(key, hex'00');

    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(IOrderAuthenticator.CallerNotAllowanceHub.selector, relayer)
    );
    authenticator.authenticateExecution(execOrder, bytes32(0), data);

    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(IOrderAuthenticator.CallerNotAllowanceHub.selector, relayer)
    );
    authenticator.authenticateFulfillment(fulfillOrder, bytes32(0), data);
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
      abi.encodeWithSelector(
        ITwoTiersOrderAuthenticator.AuthKeyExpired.selector, t, vm.getBlockTimestamp()
      )
    );
    _executeViaAuthenticator(expiring, masterKeyPk, 10, t + 1 hours, false);
  }

  /// SV-08 — an approved key still has to have signed this particular order
  function test_SV_08_wrongSignatureRejected() public {
    _delegateKeyThroughHub(key);

    (, uint256 impostorKey) = makeAddrAndKey('impostor');

    vm.expectRevert(ITwoTiersOrderAuthenticator.InvalidOrderSignature.selector);
    _executeViaAuthenticator(key, impostorKey, 11, block.timestamp + 1 hours, false);
  }

  /// SV-09 — the authenticator's nonce makes an authentication single-use
  function test_SV_09_nonceReplayRejected() public {
    _delegateKeyThroughHub(key);

    uint256 nonce = 12;
    uint256 deadline = block.timestamp + 1 hours;

    _executeViaAuthenticator(key, masterKeyPk, nonce, deadline, true);

    vm.expectRevert(
      abi.encodeWithSelector(IUnorderedNonce.NonceAlreadyUsed.selector, _credentialHash(key), nonce)
    );
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

    ERC20Allowance[] memory erc20s = _allowances(_tokenAllowance(AMOUNT));
    FulfillmentOrder memory fulfillOrder = _openFulfillmentOrder(
      erc20s, new ValidationParams[](0), new GenericCall[](0), nonce, deadline
    );

    // signed as an execution, then submitted through the fulfillment entry point
    bytes memory sig = _sign(masterKeyPk, _executionDigest(_standardOrder(nonce, deadline)));

    vm.prank(relayer);
    vm.expectRevert(ITwoTiersOrderAuthenticator.InvalidOrderSignature.selector);
    hub.fulfillOrderWithDelegatedAuthentication(
      fulfillOrder,
      address(authenticator),
      _authData(key, sig),
      _route(fulfillOrder, _calls(_routerCall(0, hex'01'))),
      '',
      false
    );
  }

  /// SV-10b — and the fulfillment shape is what that entry point does accept
  function test_SV_10b_fulfillmentSignatureSettlesAFulfillment() public {
    _delegateKeyThroughHub(key);

    uint256 nonce = 14;
    uint256 deadline = block.timestamp + 1 hours;

    ERC20Allowance[] memory erc20s = _allowances(_tokenAllowance(AMOUNT));
    FulfillmentOrder memory fulfillOrder = _openFulfillmentOrder(
      erc20s, new ValidationParams[](0), new GenericCall[](0), nonce, deadline
    );
    uint256 before = IERC20(token18).balanceOf(address(router));

    vm.prank(relayer);
    hub.fulfillOrderWithDelegatedAuthentication(
      fulfillOrder,
      address(authenticator),
      _fulfillmentAuthData(fulfillOrder, key, masterKeyPk),
      _route(fulfillOrder, _calls(_routerCall(0, hex'01'))),
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
      abi.encodeWithSelector(
        ITwoTiersOrderAuthenticator.AuthKeyExpired.selector, t, vm.getBlockTimestamp()
      )
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

  /**
   * SV-13 — a master-key approval signed for one account is refused for another account the same
   * signer controls: two ERC-1271 wallets sharing one signer accept the same signatures, so only
   * the signed `owner` tells them apart.
   */
  function test_SV_13_masterKeyUpdateIsBoundToItsOwner() public {
    (address sharedSigner, uint256 sharedSignerKey) = makeAddrAndKey('shared signer');
    address walletA = address(new ERC1271WalletLocal(sharedSigner));
    address walletB = address(new ERC1271WalletLocal(sharedSigner));

    AuthKey memory fresh = _secpKey(recipient, block.timestamp + 10 days);
    uint256 deadline = block.timestamp + 1 days;
    bytes memory sig = _sign(
      sharedSignerKey,
      lTypedDataHash(_authenticatorDomain(), lMasterKeyUpdate(walletA, fresh, true, 8, deadline))
    );

    vm.prank(relayer);
    vm.expectRevert(ITwoTiersOrderAuthenticator.InvalidUpdateSignature.selector);
    authenticator.updateAuthentication(walletB, _approveKey(fresh), 8, deadline, sig);
    assertFalse(authenticator.masterKeys(walletB, _keyHash(fresh)), 'B has no master key');

    // the same signature on the account it names is accepted, so the refusal is evidence
    vm.prank(relayer);
    authenticator.updateAuthentication(walletA, _approveKey(fresh), 8, deadline, sig);
    assertTrue(authenticator.masterKeys(walletA, _keyHash(fresh)), 'A has the master key');
  }

  // -------------------------------------------------------------------------------------------
  // SV-KEY-* — every signature scheme
  // -------------------------------------------------------------------------------------------

  /**
   * SV-KEY-SECP-02 — a Secp256k1 key naming a contract verifies nothing, even a signature the
   * contract accepts through ERC-1271, while an ERC1271 key over the same bytes accepts it
   */
  function test_SV_KEY_SECP_02_aContractIsNotASecp256k1Signer() public {
    address wallet = _wallet();
    bytes32 digest = keccak256('a digest');
    bytes memory sig = _sign(_walletSignerKey, digest);

    AuthKey memory asSecp = AuthKey({
      publicKey: abi.encode(wallet), keyType: KeyType.Secp256k1, expiration: block.timestamp + 1
    });
    AuthKey memory as1271 = AuthKey({
      publicKey: abi.encode(wallet), keyType: KeyType.ERC1271, expiration: block.timestamp + 1
    });

    assertFalse(_verifyWithKeyTail(asSecp, '', digest, sig), 'Secp256k1 does not call ERC-1271');
    assertTrue(_verifyWithKeyTail(as1271, '', digest, sig), 'ERC1271 does');
  }

  /// SV-KEY-1271-01 — an ERC1271 key authenticates an order through its contract
  function test_SV_KEY_1271_01_contractSigner() public {
    AuthKey memory walletKey = AuthKey({
      publicKey: abi.encode(_wallet()),
      keyType: KeyType.ERC1271,
      expiration: block.timestamp + 30 days
    });
    _delegateKeyThroughHub(walletKey);

    uint256 before = IERC20(token18).balanceOf(address(router));
    _executeViaAuthenticator(walletKey, _walletSignerKey, 16, block.timestamp + 1 hours, true);
    assertEq(IERC20(token18).balanceOf(address(router)) - before, AMOUNT);
  }

  /// SV-KEY-1271-02 — an ERC1271 key naming an account without code verifies nothing, even that
  /// account's own ECDSA signature
  function test_SV_KEY_1271_02_anEoaIsNotAnErc1271Signer() public {
    bytes32 digest = keccak256('a digest');
    bytes memory sig = _sign(masterKeyPk, digest);

    AuthKey memory as1271 = AuthKey({
      publicKey: abi.encode(masterSigner), keyType: KeyType.ERC1271, expiration: block.timestamp + 1
    });
    AuthKey memory asSecp = AuthKey({
      publicKey: abi.encode(masterSigner),
      keyType: KeyType.Secp256k1,
      expiration: block.timestamp + 1
    });

    assertFalse(_verifyWithKeyTail(as1271, '', digest, sig), 'ERC1271 does not recover');
    assertTrue(_verifyWithKeyTail(asSecp, '', digest, sig), 'Secp256k1 does');
  }

  /**
   * SV-KEY-7913-01 — an ERC7913 key authenticates an order through its verifier, and a signature
   * over another digest is refused
   */
  function test_SV_KEY_7913_01_verifierSigner() public {
    AuthKey memory verifierKey = AuthKey({
      publicKey: abi.encodePacked(address(new ERC7913P256Verifier()), KeyFixtures.p256PublicKey()),
      keyType: KeyType.ERC7913,
      expiration: block.timestamp + 30 days
    });
    _delegateKeyThroughHub(verifierKey);

    uint256 deadline = block.timestamp + 1 hours;
    bytes memory signature = KeyFixtures.p256Sign(_executionDigest(_standardOrder(19, deadline)));

    uint256 before = IERC20(token18).balanceOf(address(router));
    _submitExecution(verifierKey, signature, 19, deadline);
    assertEq(IERC20(token18).balanceOf(address(router)) - before, AMOUNT, 'ERC7913 accepted');

    vm.prank(relayer);
    vm.expectRevert(ITwoTiersOrderAuthenticator.InvalidOrderSignature.selector);
    _submitExecutionRaw(verifierKey, signature, 20, deadline);
  }

  /**
   * SV-KEY-7913-02 — an ERC7913 key with nothing after the verifier's address verifies nothing,
   * even through a verifier that accepts every key, and neither does one whose verifier has no code
   */
  function test_SV_KEY_7913_02_aKeylessVerifierIsRefused() public {
    bytes32 digest = keccak256('a digest');
    address permissive = address(new PermissiveVerifier());

    AuthKey memory bare = AuthKey({
      publicKey: abi.encodePacked(permissive), keyType: KeyType.ERC7913, expiration: block.timestamp
    });
    assertFalse(_verifyWithKeyTail(bare, '', digest, ''), 'no key refused');

    AuthKey memory oneByte = AuthKey({
      publicKey: abi.encodePacked(permissive, hex'01'),
      keyType: KeyType.ERC7913,
      expiration: block.timestamp
    });
    assertTrue(_verifyWithKeyTail(oneByte, '', digest, ''), 'a one-byte key reaches the verifier');

    AuthKey memory noCode = AuthKey({
      publicKey: abi.encodePacked(masterSigner, KeyFixtures.p256PublicKey()),
      keyType: KeyType.ERC7913,
      expiration: block.timestamp
    });
    assertFalse(
      _verifyWithKeyTail(noCode, '', digest, KeyFixtures.p256Sign(digest)), 'codeless verifier'
    );
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
    vm.expectRevert(ITwoTiersOrderAuthenticator.InvalidOrderSignature.selector);
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
    vm.expectRevert(ITwoTiersOrderAuthenticator.InvalidOrderSignature.selector);
    _submitExecutionRaw(wa, upOnly, 20, deadline);

    // -03 an assertion that does not decode at all is rejected rather than reverting oddly
    vm.prank(relayer);
    vm.expectRevert(ITwoTiersOrderAuthenticator.InvalidOrderSignature.selector);
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
  // SV-KEY-LEN-01..05 — a key of the wrong length verifies nothing
  // -------------------------------------------------------------------------------------------

  /**
   * SV-KEY-LEN-01 — an empty Secp256k1 key, approved by mistake, does not sign for anyone
   * @dev The key's hash covers only its own bytes. The forged payload places the attacker's address
   * in the word after the empty key, where the signer would be read from if the length went
   * unchecked.
   */
  function test_SV_KEY_LEN_01_anEmptySecp256k1KeySignsNothing() public {
    (address attacker, uint256 attackerPk) = makeAddrAndKey('attacker');
    AuthKey memory empty =
      AuthKey({publicKey: '', keyType: KeyType.Secp256k1, expiration: block.timestamp + 30 days});
    _delegateKeyThroughHub(empty);

    uint256 nonce = 130;
    uint256 deadline = block.timestamp + 1 hours;
    bytes memory sig = _sign(attackerPk, _executionDigest(_standardOrder(nonce, deadline)));
    bytes memory forged = _authDataWithKeyTail(empty, abi.encode(attacker), sig);

    vm.prank(relayer);
    vm.expectRevert(ITwoTiersOrderAuthenticator.InvalidOrderSignature.selector);
    hub.executeOrderWithDelegatedAuthentication(
      _standardOrder(nonce, deadline), address(authenticator), forged, false
    );
  }

  /**
   * SV-KEY-LEN-02 — a Secp256k1 key one byte short is refused, even when the byte after it would
   * complete the signer's address
   */
  function test_SV_KEY_LEN_02_aShortSecp256k1KeyIsRefused() public {
    bytes memory full = abi.encode(masterSigner);
    bytes32 digest = keccak256('a digest');
    bytes memory sig = _sign(masterKeyPk, digest);

    AuthKey memory short_ = AuthKey({
      publicKey: _prefix(full, 31), keyType: KeyType.Secp256k1, expiration: block.timestamp + 1 days
    });
    assertFalse(_verifyWithKeyTail(short_, _suffix(full, 31), digest, sig), 'short key refused');

    AuthKey memory exact =
      AuthKey({publicKey: full, keyType: KeyType.Secp256k1, expiration: block.timestamp + 1 days});
    assertTrue(_verifyWithKeyTail(exact, '', digest, sig), 'the full key verifies');
  }

  /// SV-KEY-LEN-03 — a P256 key one byte short is refused, even when completed from after it
  function test_SV_KEY_LEN_03_aShortP256KeyIsRefused() public {
    bytes memory full = KeyFixtures.p256PublicKey();
    bytes32 digest = keccak256('a digest');
    bytes memory sig = KeyFixtures.p256Sign(digest);

    AuthKey memory short_ = AuthKey({
      publicKey: _prefix(full, 63), keyType: KeyType.P256, expiration: block.timestamp + 1 days
    });
    assertFalse(_verifyWithKeyTail(short_, _suffix(full, 63), digest, sig), 'short key refused');

    AuthKey memory exact =
      AuthKey({publicKey: full, keyType: KeyType.P256, expiration: block.timestamp + 1 days});
    assertTrue(_verifyWithKeyTail(exact, '', digest, sig), 'the full key verifies');
  }

  /// SV-KEY-LEN-04 — and a WebAuthn key the same
  function test_SV_KEY_LEN_04_aShortWebAuthnKeyIsRefused() public {
    bytes memory full = KeyFixtures.p256PublicKey();
    bytes32 digest = keccak256('a digest');
    bytes memory assertion = KeyFixtures.webAuthnAssertion(digest, true);

    AuthKey memory short_ = AuthKey({
      publicKey: _prefix(full, 63), keyType: KeyType.WebAuthn, expiration: block.timestamp + 1 days
    });
    assertFalse(
      _verifyWithKeyTail(short_, _suffix(full, 63), digest, assertion), 'short key refused'
    );

    AuthKey memory exact =
      AuthKey({publicKey: full, keyType: KeyType.WebAuthn, expiration: block.timestamp + 1 days});
    assertTrue(_verifyWithKeyTail(exact, '', digest, assertion), 'the full key verifies');
  }

  /**
   * SV-KEY-LEN-05 — an RSA key shorter than its two head words is refused
   * @dev The forged call places a genuine `e` and `n` before the empty key, and two words after it
   * that, read as head words, point back at them; `decodeBytes` checks only where a part ends, and
   * both end before the key does.
   */
  function test_SV_KEY_LEN_05_anRsaKeyWithoutItsHeadWordsIsRefused() public {
    (bytes memory e, bytes memory n) = abi.decode(KeyFixtures.rsaPublicKey(), (bytes, bytes));
    bytes memory eBlob = _blob(e);
    bytes memory nBlob = _blob(n);

    uint256 posE = 0x60;
    uint256 posN = posE + eBlob.length;
    uint256 posKey = posN + nBlob.length;
    uint256 posKeyBytes = posKey + 0x80;
    uint256 posSig = posKeyBytes + 0x40;

    bytes memory args;
    unchecked {
      args = abi.encodePacked(
        abi.encodePacked(posKey, KeyFixtures.RSA_FIXED_DIGEST, posSig),
        eBlob,
        nBlob,
        abi.encode(uint256(0x60), KeyType.RSA, block.timestamp + 1 days, uint256(0)),
        abi.encodePacked(posE - posKeyBytes, posN - posKeyBytes),
        _blob(KeyFixtures.rsaSignatureForFixedDigest())
      );
    }
    assertFalse(_rawVerify(args), 'the empty key verified nothing');
  }

  // -------------------------------------------------------------------------------------------
  // SV-CRED-01..04 — a key's nonces are spent under its credential, not one approval of it
  // -------------------------------------------------------------------------------------------

  /**
   * SV-CRED-01 — an order settled under one approval of a key cannot settle again under another
   * @dev The owner renews `key` by approving the same credential with a later expiry, and leaves the
   * first approval in place. The order signature names no key, so both approvals accept it; the
   * nonce they share refuses the second settlement.
   */
  function test_SV_CRED_01_aRenewedKeyCannotReplayAnOrder() public {
    AuthKey memory renewed = _secpKey(masterSigner, key.expiration + 30 days);
    _delegateKeyThroughHub(key);
    vm.prank(owner);
    authenticator.updateAuthentication(owner, _approveKey(renewed), 0, block.timestamp + 1, '');
    assertEq(_credentialHash(key), _credentialHash(renewed), 'one credential, two approvals');

    uint256 nonce = 140;
    uint256 deadline = block.timestamp + 1 hours;
    bytes memory sig = _sign(masterKeyPk, _executionDigest(_standardOrder(nonce, deadline)));

    _submitExecution(key, sig, nonce, deadline);

    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(
        IUnorderedNonce.NonceAlreadyUsed.selector, _credentialHash(renewed), nonce
      )
    );
    _submitExecutionRaw(renewed, sig, nonce, deadline);
  }

  /// SV-CRED-02 — the same holds across tiers: a key settled as a session key is spent as a master
  function test_SV_CRED_02_theNonceIsSharedAcrossTiers() public {
    _delegateKeyThroughHub(key);
    AuthKey memory asSession = _secpKey(sessionSigner, key.expiration);
    AuthKey memory asMaster = _secpKey(sessionSigner, key.expiration - 1);
    vm.prank(relayer);
    _approveSessionKey(key, asSession, 149, block.timestamp + 1 days, masterKeyPk);
    vm.prank(owner);
    authenticator.updateAuthentication(owner, _approveKey(asMaster), 0, block.timestamp + 1, '');

    uint256 nonce = 150;
    uint256 deadline = block.timestamp + 1 hours;
    _executeViaAuthenticator(asSession, sessionKeyPk, nonce, deadline, true, true);

    vm.expectRevert(
      abi.encodeWithSelector(
        IUnorderedNonce.NonceAlreadyUsed.selector, _credentialHash(asMaster), nonce
      )
    );
    _executeViaAuthenticator(asMaster, sessionKeyPk, nonce, deadline, false, false);
  }

  /// SV-CRED-03 — a revocation signed under one approval cancels the nonce under every other
  function test_SV_CRED_03_aRevocationCoversEveryApproval() public {
    AuthKey memory renewed = _secpKey(masterSigner, key.expiration + 30 days);
    _delegateKeyThroughHub(renewed);

    uint256 nonce = 160;
    uint256 deadline = block.timestamp + 1 hours;
    authenticator.revokeNonce(
      key, nonce, deadline, _signNonceRevocation(key, nonce, deadline, masterKeyPk)
    );

    vm.expectRevert(
      abi.encodeWithSelector(
        IUnorderedNonce.NonceAlreadyUsed.selector, _credentialHash(renewed), nonce
      )
    );
    _executeViaAuthenticator(renewed, masterKeyPk, nonce, deadline, false);
  }

  /**
   * SV-CRED-04 — a Secp256k1 or ERC1271 key with any of its top 12 bytes set verifies nothing
   * @dev Such a key would resolve to the same signer as its clean encoding under a separate
   * credential.
   */
  function test_SV_CRED_04_aNonCanonicalAddressKeyIsRefused() public {
    bytes32 digest = keccak256('a digest');
    _assertOnlyCleanEncodingVerifies(KeyType.Secp256k1, masterSigner, _sign(masterKeyPk, digest));
    _assertOnlyCleanEncodingVerifies(KeyType.ERC1271, _wallet(), _sign(_walletSignerKey, digest));
  }

  // -------------------------------------------------------------------------------------------
  // SV-DOMAIN / SV-FUZZ
  // -------------------------------------------------------------------------------------------

  /// @dev The separator itself, and that it differs from the hub's, is `DOM-01` in Management
  function test_SV_DOMAIN_matchesTheWrittenOutDomain() public view {
    (, string memory name, string memory version, uint256 chainId, address verifyingContract,,) =
      authenticator.eip712Domain();

    assertEq(name, 'KyberSwap Two Tiers Order Authenticator');
    assertEq(version, '1.0.0');
    assertEq(chainId, block.chainid);
    assertEq(verifyingContract, address(authenticator));
  }

  /**
   * SV-FUZZ-UPD — updating a key directly, across every scheme, expiry, nonce and direction
   * @dev Subsumes the relayed half of SV-02: same rail, same call, and both of that case's
   * assertions appear below over a wider domain. The update path never verifies signature material
   * against the key, only its hash, so the key type can be fuzzed across every arm here even
   * though only Secp256k1 can be signed for in {testFuzz_SV_FUZZ_VER_nonceAndDeadline}. The
   * pre-state is set to the opposite of the fuzzed direction, so every run is a transition rather
   * than a no-op.
   */
  function testFuzz_SV_FUZZ_UPD_directUpdate(SessionFuzz memory f) public {
    KeyType keyType = KeyType(bound(f.keyType, 0, 5));
    uint256 expiration = block.timestamp + bound(f.expirationOffset, 0, 365 days);
    uint256 deadline = block.timestamp + bound(f.deadlineOffset, 0, 30 days);

    AuthKey memory fresh =
      AuthKey({publicKey: abi.encode(recipient), keyType: keyType, expiration: expiration});

    // SV-02's route, used here to establish the opposite pre-state without spending a nonce
    vm.expectEmit(address(authenticator));
    emit ITwoTiersOrderAuthenticator.UpdateMasterKey(owner, _keyHash(fresh), fresh, !f.approved);
    vm.prank(owner);
    authenticator.updateAuthentication(owner, _updateData(fresh, !f.approved), 0, deadline, '');
    assertEq(authenticator.masterKeys(owner, _keyHash(fresh)), !f.approved, 'pre-state');
    assertEq(authenticator.nonces(lNonceKey(owner), 0), 0, 'no nonce spent without a signature');

    bytes memory sig = _signMasterKeyUpdate(fresh, f.approved, f.nonce, deadline);

    vm.expectEmit(address(authenticator));
    emit ITwoTiersOrderAuthenticator.UpdateMasterKey(owner, _keyHash(fresh), fresh, f.approved);
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
      keyType: KeyType((uint8(keyType) + 1) % 6),
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
      authenticator.nonces(_credentialHash(fuzzKey), nonce >> 8),
      1 << (nonce & 0xff),
      'exact nonce bit'
    );
  }

  // -------------------------------------------------------------------------------------------
  // SV-TIER-01..10 — the second tier: a master key approving session keys of its own
  // -------------------------------------------------------------------------------------------

  /**
   * SV-TIER-01 — a master key approves a session key, which then signs an order
   * @dev The flow a passkey exists for: the owner's wallet approves the passkey once, and the
   * passkey issues local keys with no wallet prompt. The approval lands in `sessionKeyMaster`
   * under the master key's hash, and leaves `masterKeys` alone.
   */
  function test_SV_TIER_01_masterKeyApprovesASessionKeyThatSignsAnOrder() public {
    _delegateKeyThroughHub(key);
    AuthKey memory sessionKey = _secpKey(sessionSigner, key.expiration);

    vm.expectEmit(address(authenticator));
    emit ITwoTiersOrderAuthenticator.UpdateSessionKey(
      owner, _keyHash(sessionKey), _keyHash(key), sessionKey, true
    );
    vm.prank(relayer);
    _approveSessionKey(key, sessionKey, 1, block.timestamp + 1 days, masterKeyPk);

    assertEq(
      authenticator.sessionKeyMaster(owner, _keyHash(sessionKey)),
      _keyHash(key),
      'approved under the master key'
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
   * SV-TIER-02 — a session key cannot approve another, so the chain is two deep and no more
   * @dev One read enforces this: the rail asks whether the key presented as the approver is one
   * the owner approved themselves, and a session key never is.
   */
  function test_SV_TIER_02_aSessionKeyCannotApproveAnother() public {
    _delegateKeyThroughHub(key);
    AuthKey memory sessionKey = _secpKey(sessionSigner, key.expiration);

    uint256 deadline = block.timestamp + 1 days;
    vm.prank(relayer);
    _approveSessionKey(key, sessionKey, 1, deadline, masterKeyPk);

    AuthKey memory grandchild = _secpKey(recipient, key.expiration);
    bytes memory sig =
      _signSessionKeyUpdate(sessionKey, grandchild, true, 4, deadline, sessionKeyPk);

    vm.prank(relayer);
    vm.expectRevert(_masterKeyNotApproved(sessionKey));
    authenticator.updateAuthentication(
      owner, _sessionKeyData(grandchild, sessionKey, true), 4, deadline, sig
    );

    assertEq(
      authenticator.sessionKeyMaster(owner, _keyHash(grandchild)), bytes32(0), 'nothing approved'
    );
    assertFalse(authenticator.masterKeys(owner, _keyHash(grandchild)), 'and nothing promoted');
  }

  /// SV-TIER-03 — nor can a key the owner never approved at all
  function test_SV_TIER_03_anUnapprovedKeyCannotApprove() public {
    _delegateKeyThroughHub(key);

    (address strangerSigner, uint256 strangerPk) = makeAddrAndKey('stranger key');
    AuthKey memory stranger = _secpKey(strangerSigner, block.timestamp + 30 days);
    AuthKey memory sessionKey = _secpKey(sessionSigner, block.timestamp + 1 days);

    uint256 deadline = block.timestamp + 1 days;
    bytes memory sig = _signSessionKeyUpdate(stranger, sessionKey, true, 5, deadline, strangerPk);

    vm.prank(relayer);
    vm.expectRevert(_masterKeyNotApproved(stranger));
    authenticator.updateAuthentication(
      owner, _sessionKeyData(sessionKey, stranger, true), 5, deadline, sig
    );
  }

  /**
   * SV-TIER-04 — revoking a master key takes every session key under it
   * @dev The approval row itself is left standing, so the owner re-approving the identical
   * credential revives the keys that master had minted. The refusal in between names the master key
   * rather than the session key, because the master is the thing no longer approved.
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
      'the approval itself is untouched'
    );

    vm.expectRevert(_masterKeyNotApproved(key));
    _executeViaAuthenticator(sessionKey, sessionKeyPk, 11, block.timestamp + 1 hours, false, true);

    vm.prank(owner);
    authenticator.updateAuthentication(owner, _approveKey(key), 0, deadline, '');
    _executeViaAuthenticator(sessionKey, sessionKeyPk, 12, block.timestamp + 1 hours, true, true);
  }

  /**
   * SV-TIER-05 — a session key may not outlive the master key approving it
   * @dev Both legs run on nonce 20: the refusal happens before the burn, so the number is still
   * there for the leg that succeeds.
   */
  function test_SV_TIER_05_aSessionKeyMayNotOutliveItsMaster() public {
    _delegateKeyThroughHub(key);
    uint256 deadline = block.timestamp + 1 days;

    AuthKey memory tooLong = _secpKey(sessionSigner, key.expiration + 1);
    bytes memory sig = _signSessionKeyUpdate(key, tooLong, true, 20, deadline, masterKeyPk);

    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(
        ITwoTiersOrderAuthenticator.SessionKeyOutlivesMasterKey.selector,
        tooLong.expiration,
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

    // the bound applies on the way in only, so the key it refused can still be revoked
    bytes memory revokeSig = _signSessionKeyUpdate(key, tooLong, false, 22, deadline, masterKeyPk);
    vm.prank(relayer);
    authenticator.updateAuthentication(
      owner, _sessionKeyData(tooLong, key, false), 22, deadline, revokeSig
    );
    assertEq(authenticator.sessionKeyMaster(owner, _keyHash(tooLong)), bytes32(0), 'revoked');
  }

  /// SV-TIER-06 — the signature has to be the approving key's, not the approved key's
  function test_SV_TIER_06_theMasterKeyMustHaveSignedIt() public {
    _delegateKeyThroughHub(key);
    AuthKey memory sessionKey = _secpKey(sessionSigner, key.expiration);

    uint256 deadline = block.timestamp + 1 days;
    bytes memory sig = _signSessionKeyUpdate(key, sessionKey, true, 21, deadline, sessionKeyPk);

    vm.prank(relayer);
    vm.expectRevert(ITwoTiersOrderAuthenticator.InvalidUpdateSignature.selector);
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
      _signSessionKeyUpdate(recipient, key, sessionKey, true, 22, deadline, masterKeyPk);

    vm.prank(relayer);
    vm.expectRevert(ITwoTiersOrderAuthenticator.InvalidUpdateSignature.selector);
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
      'approved for the account it names'
    );
    assertEq(
      authenticator.sessionKeyMaster(owner, _keyHash(sessionKey)), bytes32(0), 'and for no other'
    );
  }

  /**
   * SV-TIER-08 — the nonce burns in the master key's namespace, because the master key signed
   * @dev Three namespaces are in play for one number: the owner's, the master key's and the
   * session key's. Spending it as the master key must leave the other two alone, or an owner
   * approving at nonce 9 would silently block their passkey's ninth approval.
   */
  function test_SV_TIER_08_theNonceBurnsInTheMasterKeysNamespace() public {
    _delegateKeyThroughHub(key);
    AuthKey memory sessionKey = _secpKey(sessionSigner, key.expiration);

    uint256 deadline = block.timestamp + 1 days;
    uint256 nonce = 9;

    vm.prank(relayer);
    _approveSessionKey(key, sessionKey, nonce, deadline, masterKeyPk);

    assertEq(authenticator.nonces(_credentialHash(key), 0), 1 << nonce, 'the master key spent it');
    assertEq(authenticator.nonces(lNonceKey(owner), 0), 0, "the owner's namespace is untouched");
    assertEq(authenticator.nonces(_credentialHash(sessionKey), 0), 0, "and so is the session key's");

    AuthKey memory other = _secpKey(recipient, key.expiration);
    bytes memory replay = _signSessionKeyUpdate(key, other, true, nonce, deadline, masterKeyPk);
    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(IUnorderedNonce.NonceAlreadyUsed.selector, _credentialHash(key), nonce)
    );
    authenticator.updateAuthentication(
      owner, _sessionKeyData(other, key, true), nonce, deadline, replay
    );

    bytes memory ownerSig = _signMasterKeyUpdate(other, true, nonce, deadline);
    vm.prank(relayer);
    authenticator.updateAuthentication(owner, _approveKey(other), nonce, deadline, ownerSig);
    assertTrue(authenticator.masterKeys(owner, _keyHash(other)), 'the owner still has that number');

    _executeViaAuthenticator(sessionKey, sessionKeyPk, nonce, block.timestamp + 1 hours, true, true);
  }

  /// SV-TIER-09 — a master key revokes a session key it approved, and the key stops signing
  function test_SV_TIER_09_aMasterKeyRevokesItsSessionKey() public {
    _delegateKeyThroughHub(key);
    AuthKey memory sessionKey = _secpKey(sessionSigner, key.expiration);

    uint256 deadline = block.timestamp + 1 days;
    vm.prank(relayer);
    _approveSessionKey(key, sessionKey, 40, deadline, masterKeyPk);
    _executeViaAuthenticator(sessionKey, sessionKeyPk, 41, block.timestamp + 1 hours, true, true);

    bytes memory sig = _signSessionKeyUpdate(key, sessionKey, false, 42, deadline, masterKeyPk);
    vm.expectEmit(address(authenticator));
    emit ITwoTiersOrderAuthenticator.UpdateSessionKey(
      owner, _keyHash(sessionKey), _keyHash(key), sessionKey, false
    );
    vm.prank(relayer);
    authenticator.updateAuthentication(
      owner, _sessionKeyData(sessionKey, key, false), 42, deadline, sig
    );

    assertEq(
      authenticator.sessionKeyMaster(owner, _keyHash(sessionKey)),
      bytes32(0),
      'the approval is cleared'
    );
    vm.expectRevert(_sessionKeyNotApproved(sessionKey));
    _executeViaAuthenticator(sessionKey, sessionKeyPk, 43, block.timestamp + 1 hours, false, true);
  }

  /**
   * SV-TIER-10 — a key holding both approvals may be presented under either
   * @dev Nothing stops one credential from holding the owner's approval and a master key's at once,
   * and the tier it is presented as decides which one settles it. Each therefore stands on its own:
   * revoking the master key closes the session route — a refusal naming that master — and leaves
   * the owner's approval; revoking the owner's closes that one and leaves the session route.
   */
  function test_SV_TIER_10_eachApprovalIsUsableOnItsOwnTier() public {
    _delegateKeyThroughHub(key);
    AuthKey memory both = _secpKey(sessionSigner, key.expiration);
    uint256 deadline = block.timestamp + 1 days;

    vm.prank(relayer);
    _approveSessionKey(key, both, 50, deadline, masterKeyPk);
    vm.prank(owner);
    authenticator.updateAuthentication(owner, _approveKey(both), 0, deadline, '');

    // either tier settles an order while both approvals stand
    _executeViaAuthenticator(both, sessionKeyPk, 51, block.timestamp + 1 hours, true, true);
    _executeViaAuthenticator(both, sessionKeyPk, 52, block.timestamp + 1 hours, true, false);

    // revoking the master key closes the session route, and leaves the owner's approval alone
    vm.prank(owner);
    authenticator.updateAuthentication(owner, _revokeKey(key), 0, deadline, '');

    vm.expectRevert(_masterKeyNotApproved(key));
    _executeViaAuthenticator(both, sessionKeyPk, 53, block.timestamp + 1 hours, false, true);
    _executeViaAuthenticator(both, sessionKeyPk, 54, block.timestamp + 1 hours, true, false);

    // and revoking the owner's approval closes the remaining route
    vm.prank(owner);
    authenticator.updateAuthentication(owner, _revokeKey(both), 0, deadline, '');

    vm.expectRevert(_masterKeyNotApproved(both));
    _executeViaAuthenticator(both, sessionKeyPk, 55, block.timestamp + 1 hours, false, false);
  }

  /// SV-TIER-10b — a master key that approves itself still signs, on either tier
  function test_SV_TIER_10b_aMasterKeyMayApproveItself() public {
    _delegateKeyThroughHub(key);
    uint256 deadline = block.timestamp + 1 days;

    bytes memory selfSig = _signSessionKeyUpdate(key, key, true, 56, deadline, masterKeyPk);
    vm.prank(relayer);
    authenticator.updateAuthentication(
      owner, _sessionKeyData(key, key, true), 56, deadline, selfSig
    );

    assertEq(
      authenticator.sessionKeyMaster(owner, _keyHash(key)), _keyHash(key), 'approved by itself'
    );
    _executeViaAuthenticator(key, masterKeyPk, 57, block.timestamp + 1 hours, true, true);
    _executeViaAuthenticator(key, masterKeyPk, 58, block.timestamp + 1 hours, true, false);
  }

  /**
   * SV-TIER-11 — the tier hint is trusted for nothing
   * @dev It picks which mapping settles the key, so naming the wrong one finds no approval there
   * and is refused. A master key offered as a session key has no master key behind it; a session
   * key offered as a master key holds no approval of its own. Both legs then settle under the tier
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
        ITwoTiersOrderAuthenticator.AuthKeyExpired.selector,
        stale.expiration,
        vm.getBlockTimestamp()
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
        ITwoTiersOrderAuthenticator.AuthKeyExpired.selector,
        stale.expiration,
        vm.getBlockTimestamp()
      )
    );
    hub.updateDelegation(owner, address(authenticator), true, _encodeKey(stale), 0, deadline, '');
  }

  /**
   * SV-TIER-12b — nor will a master key approve one, and an expired master key can approve nothing
   * @dev The expiry bound and this check together leave an expired master key no reachable
   * approval: a session key inside its bound is expired as well, and one outside it breaks the
   * bound. So the master key needs no expiry check of its own.
   */
  function test_SV_TIER_12b_anExpiredMasterKeyCanApproveNothing() public {
    AuthKey memory master = _secpKey(masterSigner, block.timestamp + 2 hours);
    _delegateKeyThroughHub(master);

    uint256 deadline = block.timestamp + 365 days;
    AuthKey memory stale = _secpKey(sessionSigner, master.expiration);
    AuthKey memory fresh = _secpKey(recipient, master.expiration + 1);

    vm.warp(master.expiration + 1);

    // inside the bound, and therefore expired with it
    bytes memory staleSig = _signSessionKeyUpdate(master, stale, true, 70, deadline, masterKeyPk);
    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(
        ITwoTiersOrderAuthenticator.AuthKeyExpired.selector,
        stale.expiration,
        vm.getBlockTimestamp()
      )
    );
    authenticator.updateAuthentication(
      owner, _sessionKeyData(stale, master, true), 70, deadline, staleSig
    );

    // outside the bound, and therefore refused by it
    bytes memory freshSig = _signSessionKeyUpdate(master, fresh, true, 71, deadline, masterKeyPk);
    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(
        ITwoTiersOrderAuthenticator.SessionKeyOutlivesMasterKey.selector,
        fresh.expiration,
        master.expiration
      )
    );
    authenticator.updateAuthentication(
      owner, _sessionKeyData(fresh, master, true), 71, deadline, freshSig
    );

    // revoking through an expired master key still works
    bytes memory revokeSig = _signSessionKeyUpdate(master, stale, false, 72, deadline, masterKeyPk);
    vm.prank(relayer);
    authenticator.updateAuthentication(
      owner, _sessionKeyData(stale, master, false), 72, deadline, revokeSig
    );
    assertEq(
      authenticator.sessionKeyMaster(owner, _keyHash(stale)), bytes32(0), 'revocation still lands'
    );
  }

  /**
   * SV-TIER-13 — a master key speaks only for the session keys it approved
   * @dev Another master key may neither take an approval over by approving the key under itself nor
   * clear it by revoking. The last leg has the approving master revoke the same key, so the
   * refusals are about who holds the approval and not about the key.
   */
  function test_SV_TIER_13_aMasterKeyActsOnlyOnKeysItApproved() public {
    (address otherSigner, uint256 otherPk) = makeAddrAndKey('other master signer');
    AuthKey memory other = _secpKey(otherSigner, key.expiration);
    AuthKey memory sessionKey = _secpKey(sessionSigner, key.expiration);
    uint256 deadline = block.timestamp + 1 days;

    _delegateKeyThroughHub(key);
    vm.prank(owner);
    authenticator.updateAuthentication(owner, _approveKey(other), 0, deadline, '');

    vm.prank(relayer);
    _approveSessionKey(key, sessionKey, 80, deadline, masterKeyPk);

    bytes memory expected = abi.encodeWithSelector(
      ITwoTiersOrderAuthenticator.SessionKeyAlreadyApproved.selector,
      _keyHash(sessionKey),
      _keyHash(other),
      _keyHash(key)
    );

    bytes memory takeOver = _signSessionKeyUpdate(other, sessionKey, true, 81, deadline, otherPk);
    vm.prank(relayer);
    vm.expectRevert(expected);
    authenticator.updateAuthentication(
      owner, _sessionKeyData(sessionKey, other, true), 81, deadline, takeOver
    );

    bytes memory clear = _signSessionKeyUpdate(other, sessionKey, false, 82, deadline, otherPk);
    vm.prank(relayer);
    vm.expectRevert(expected);
    authenticator.updateAuthentication(
      owner, _sessionKeyData(sessionKey, other, false), 82, deadline, clear
    );

    assertEq(
      authenticator.sessionKeyMaster(owner, _keyHash(sessionKey)),
      _keyHash(key),
      'the approval is still the approving master key\'s'
    );

    bytes memory own = _signSessionKeyUpdate(key, sessionKey, false, 83, deadline, masterKeyPk);
    vm.prank(relayer);
    authenticator.updateAuthentication(
      owner, _sessionKeyData(sessionKey, key, false), 83, deadline, own
    );
    assertEq(
      authenticator.sessionKeyMaster(owner, _keyHash(sessionKey)),
      bytes32(0),
      'its own revocation lands'
    );
  }

  // -------------------------------------------------------------------------------------------
  // SV-ORD-01..03 — an expired key is refused as expired, before anything else is checked
  // -------------------------------------------------------------------------------------------

  /**
   * SV-ORD-01 — on the owner's rail, ahead of the owner's signature
   * @dev The second leg presents the same bad signature for a live key and is refused for the
   * signature, so the first leg's refusal is about the order of the checks.
   */
  function test_SV_ORD_01_expiryComesBeforeTheOwnersSignature() public {
    AuthKey memory stale = _secpKey(sessionSigner, block.timestamp + 1 hours);
    AuthKey memory live = _secpKey(sessionSigner, block.timestamp + 30 days);
    uint256 deadline = block.timestamp + 365 days;

    vm.warp(stale.expiration + 1);

    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(
        ITwoTiersOrderAuthenticator.AuthKeyExpired.selector,
        stale.expiration,
        vm.getBlockTimestamp()
      )
    );
    authenticator.updateAuthentication(owner, _approveKey(stale), 90, deadline, hex'00');

    vm.prank(relayer);
    vm.expectRevert(ITwoTiersOrderAuthenticator.InvalidUpdateSignature.selector);
    authenticator.updateAuthentication(owner, _approveKey(live), 90, deadline, hex'00');
  }

  /**
   * SV-ORD-02 — on the master key's rail, ahead of the master key's own approval
   * @dev `key` is never approved here. A live session key under it is refused for that, so the
   * expired one's refusal is about the order of the checks.
   */
  function test_SV_ORD_02_expiryComesBeforeTheMasterKeysApproval() public {
    AuthKey memory stale = _secpKey(sessionSigner, block.timestamp + 1 hours);
    AuthKey memory live = _secpKey(recipient, block.timestamp + 2 hours);
    uint256 deadline = block.timestamp + 365 days;

    vm.warp(stale.expiration + 1);

    bytes memory staleSig = _signSessionKeyUpdate(key, stale, true, 91, deadline, masterKeyPk);
    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(
        ITwoTiersOrderAuthenticator.AuthKeyExpired.selector,
        stale.expiration,
        vm.getBlockTimestamp()
      )
    );
    authenticator.updateAuthentication(
      owner, _sessionKeyData(stale, key, true), 91, deadline, staleSig
    );

    bytes memory liveSig = _signSessionKeyUpdate(key, live, true, 91, deadline, masterKeyPk);
    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(
        ITwoTiersOrderAuthenticator.MasterKeyNotApproved.selector, _keyHash(key)
      )
    );
    authenticator.updateAuthentication(
      owner, _sessionKeyData(live, key, true), 91, deadline, liveSig
    );
  }

  /**
   * SV-ORD-03 — on the authentication path, ahead of the key's approval
   * @dev Neither key is approved for the owner. The live one is refused for that, so the expired
   * one's refusal is about the order of the checks.
   */
  function test_SV_ORD_03_expiryComesBeforeTheKeysApproval() public {
    _delegateKeyThroughHub(key);
    AuthKey memory stale = _secpKey(sessionSigner, block.timestamp + 1 hours);
    AuthKey memory live = _secpKey(recipient, block.timestamp + 30 days);

    vm.warp(stale.expiration + 1);
    uint256 deadline = vm.getBlockTimestamp() + 1 hours;

    vm.expectRevert(
      abi.encodeWithSelector(
        ITwoTiersOrderAuthenticator.AuthKeyExpired.selector,
        stale.expiration,
        vm.getBlockTimestamp()
      )
    );
    _executeViaAuthenticator(stale, sessionKeyPk, 92, deadline, false, false);

    vm.expectRevert(_masterKeyNotApproved(live));
    _executeViaAuthenticator(live, sessionKeyPk, 92, deadline, false, false);
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
      _signSessionKeyUpdate(masterKey, sessionKey, f.approved, nonce, deadline, masterKeyPk);

    vm.expectEmit(address(authenticator));
    emit ITwoTiersOrderAuthenticator.UpdateSessionKey(
      owner, _keyHash(sessionKey), _keyHash(masterKey), sessionKey, f.approved
    );
    vm.prank(relayer);
    authenticator.updateAuthentication(
      owner, _sessionKeyData(sessionKey, masterKey, f.approved), nonce, deadline, sig
    );

    assertEq(
      authenticator.sessionKeyMaster(owner, _keyHash(sessionKey)),
      f.approved ? _keyHash(masterKey) : bytes32(0),
      'the direction decides the approval'
    );
    assertEq(
      authenticator.nonces(_credentialHash(masterKey), nonce >> 8),
      1 << (nonce & 0xff),
      'the master key spends the nonce'
    );
    assertEq(authenticator.nonces(lNonceKey(owner), nonce >> 8), 0, 'and the owner does not');
  }

  // -------------------------------------------------------------------------------------------
  // SV-NREV-01..08 — a key spends one of its own nonces with a signature
  // -------------------------------------------------------------------------------------------

  /**
   * SV-NREV-01 — a key revokes a nonce, and an order it signed at that nonce is refused
   * @dev Anyone may submit the revocation. Only the key's namespace is touched: the owner's own
   * nonce of the same number stays free, and the next nonce of the key still settles an order.
   */
  function test_SV_NREV_01_aKeyRevokesANonceOfItsOwn() public {
    _delegateKeyThroughHub(key);
    uint256 nonce = 60;
    uint256 deadline = block.timestamp + 1 hours;

    bytes memory orderSig = _sign(masterKeyPk, _executionDigest(_standardOrder(nonce, deadline)));

    vm.prank(makeAddr('anyone'));
    authenticator.revokeNonce(
      key, nonce, deadline, _signNonceRevocation(key, nonce, deadline, masterKeyPk)
    );

    assertEq(authenticator.nonces(_credentialHash(key), 0), 1 << nonce, 'the key spent it');
    assertEq(authenticator.nonces(lNonceKey(owner), 0), 0, "the owner's namespace is untouched");

    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(IUnorderedNonce.NonceAlreadyUsed.selector, _credentialHash(key), nonce)
    );
    _submitExecutionRaw(key, orderSig, nonce, deadline);

    _executeViaAuthenticator(key, masterKeyPk, nonce + 1, deadline, true);
  }

  /// SV-NREV-02 — a master key cancels a session key approval it signed and has not seen used
  function test_SV_NREV_02_aMasterKeyCancelsAPendingApproval() public {
    _delegateKeyThroughHub(key);
    AuthKey memory sessionKey = _secpKey(sessionSigner, key.expiration);
    uint256 nonce = 70;
    uint256 deadline = block.timestamp + 1 days;

    bytes memory approval =
      _signSessionKeyUpdate(key, sessionKey, true, nonce, deadline, masterKeyPk);
    authenticator.revokeNonce(
      key, nonce, deadline, _signNonceRevocation(key, nonce, deadline, masterKeyPk)
    );

    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(IUnorderedNonce.NonceAlreadyUsed.selector, _credentialHash(key), nonce)
    );
    authenticator.updateAuthentication(
      owner, _sessionKeyData(sessionKey, key, true), nonce, deadline, approval
    );
    assertEq(
      authenticator.sessionKeyMaster(owner, _keyHash(sessionKey)), bytes32(0), 'never approved'
    );
  }

  /// SV-NREV-03 — a session key revokes in its own namespace, not its master key's
  function test_SV_NREV_03_aSessionKeyRevokesANonceOfItsOwn() public {
    _delegateKeyThroughHub(key);
    AuthKey memory sessionKey = _secpKey(sessionSigner, key.expiration);
    vm.prank(relayer);
    _approveSessionKey(key, sessionKey, 79, block.timestamp + 1 days, masterKeyPk);

    uint256 nonce = 80;
    uint256 deadline = block.timestamp + 1 hours;
    authenticator.revokeNonce(
      sessionKey, nonce, deadline, _signNonceRevocation(sessionKey, nonce, deadline, sessionKeyPk)
    );
    assertEq(
      authenticator.nonces(_credentialHash(key), 0), 1 << 79, "the master key's is untouched"
    );

    vm.expectRevert(
      abi.encodeWithSelector(
        IUnorderedNonce.NonceAlreadyUsed.selector, _credentialHash(sessionKey), nonce
      )
    );
    _executeViaAuthenticator(sessionKey, sessionKeyPk, nonce, deadline, false, true);

    _executeViaAuthenticator(key, masterKeyPk, nonce, deadline, true);
  }

  /// SV-NREV-04 — the revocation must be signed by the key, for the nonce and deadline it names
  function test_SV_NREV_04_theKeyMustHaveSignedThisNonce() public {
    uint256 nonce = 90;
    uint256 deadline = block.timestamp + 1 hours;

    vm.expectRevert(ITwoTiersOrderAuthenticator.InvalidRevocationSignature.selector);
    authenticator.revokeNonce(
      key, nonce, deadline, _signNonceRevocation(key, nonce, deadline, sessionKeyPk)
    );

    vm.expectRevert(ITwoTiersOrderAuthenticator.InvalidRevocationSignature.selector);
    authenticator.revokeNonce(
      key, nonce, deadline, _signNonceRevocation(key, nonce + 1, deadline, masterKeyPk)
    );

    vm.expectRevert(ITwoTiersOrderAuthenticator.InvalidRevocationSignature.selector);
    authenticator.revokeNonce(
      key, nonce, deadline, _signNonceRevocation(key, nonce, deadline + 1, masterKeyPk)
    );

    AuthKey memory other = _secpKey(masterSigner, key.expiration + 1);
    vm.expectRevert(ITwoTiersOrderAuthenticator.InvalidRevocationSignature.selector);
    authenticator.revokeNonce(
      key, nonce, deadline, _signNonceRevocation(other, nonce, deadline, masterKeyPk)
    );

    assertEq(authenticator.nonces(_credentialHash(key), 0), 0, 'nothing was spent');
  }

  /// SV-NREV-05 — a revocation spends its nonce, so it cannot be submitted twice
  function test_SV_NREV_05_aRevocationCannotBeReplayed() public {
    uint256 nonce = 100;
    uint256 deadline = block.timestamp + 1 hours;
    bytes memory sig = _signNonceRevocation(key, nonce, deadline, masterKeyPk);
    authenticator.revokeNonce(key, nonce, deadline, sig);

    vm.expectRevert(
      abi.encodeWithSelector(IUnorderedNonce.NonceAlreadyUsed.selector, _credentialHash(key), nonce)
    );
    authenticator.revokeNonce(key, nonce, deadline, sig);
  }

  /**
   * SV-NREV-06 — a key revokes regardless of its approval or expiry
   * @dev A key that was never approved, one whose approval was withdrawn, and one that has expired
   * all keep the means to cancel what they signed.
   */
  function test_SV_NREV_06_neitherApprovalNorExpiryIsRequired() public {
    uint256 deadline = block.timestamp + 365 days;

    AuthKey memory never = _secpKey(sessionSigner, block.timestamp + 30 days);
    authenticator.revokeNonce(
      never, 1, deadline, _signNonceRevocation(never, 1, deadline, sessionKeyPk)
    );
    assertEq(authenticator.nonces(_credentialHash(never), 0), 1 << 1, 'never approved');

    _delegateKeyThroughHub(key);
    vm.prank(owner);
    authenticator.updateAuthentication(owner, _revokeKey(key), 0, block.timestamp + 1 days, '');
    authenticator.revokeNonce(key, 2, deadline, _signNonceRevocation(key, 2, deadline, masterKeyPk));
    assertEq(authenticator.nonces(_credentialHash(key), 0), 1 << 2, 'approval withdrawn');

    (address staleSigner, uint256 staleKeyPk) = makeAddrAndKey('stale signer');
    AuthKey memory stale = _secpKey(staleSigner, block.timestamp + 1 hours);
    vm.warp(stale.expiration + 1);
    authenticator.revokeNonce(
      stale, 3, deadline, _signNonceRevocation(stale, 3, deadline, staleKeyPk)
    );
    assertEq(authenticator.nonces(_credentialHash(stale), 0), 1 << 3, 'expired');
  }

  /// SV-NREV-07 — a passkey revokes: the signature is checked by the key's own scheme
  function test_SV_NREV_07_aP256KeyRevokes() public {
    AuthKey memory p256 = AuthKey({
      publicKey: KeyFixtures.p256PublicKey(),
      keyType: KeyType.P256,
      expiration: block.timestamp + 30 days
    });
    uint256 nonce = 110;
    uint256 deadline = block.timestamp + 1 hours;

    vm.expectRevert(ITwoTiersOrderAuthenticator.InvalidRevocationSignature.selector);
    authenticator.revokeNonce(
      p256,
      nonce,
      deadline,
      KeyFixtures.p256Sign(
        lTypedDataHash(_authenticatorDomain(), lNonceRevocation(p256, nonce + 1, deadline))
      )
    );

    authenticator.revokeNonce(
      p256,
      nonce,
      deadline,
      KeyFixtures.p256Sign(
        lTypedDataHash(_authenticatorDomain(), lNonceRevocation(p256, nonce, deadline))
      )
    );
    assertEq(authenticator.nonces(_credentialHash(p256), 0), 1 << nonce, 'the passkey spent it');
  }

  /**
   * SV-NREV-08 — the deadline is inclusive, and a revocation submitted after it is refused
   * @dev The refused revocation leaves the nonce free, so a signature the key later makes at that
   * nonce is not cancelled by it.
   */
  function test_SV_NREV_08_deadlineBoundary() public {
    _delegateKeyThroughHub(key);
    uint256 nonce = 120;
    uint256 deadline = block.timestamp + 1 hours;
    bytes memory sig = _signNonceRevocation(key, nonce, deadline, masterKeyPk);

    vm.warp(deadline + 1);
    vm.expectRevert(_deadlinePassed(deadline));
    authenticator.revokeNonce(key, nonce, deadline, sig);
    _executeViaAuthenticator(key, masterKeyPk, nonce, vm.getBlockTimestamp() + 1 hours, true);

    uint256 nonce2 = nonce + 1;
    uint256 deadline2 = vm.getBlockTimestamp() + 1 hours;
    bytes memory sig2 = _signNonceRevocation(key, nonce2, deadline2, masterKeyPk);
    vm.warp(deadline2);
    authenticator.revokeNonce(key, nonce2, deadline2, sig2);
    assertEq(
      authenticator.nonces(_credentialHash(key), 0), 3 << nonce, 'spent at the deadline itself'
    );
  }

  /// SV-FUZZ-NREV — a revocation spends exactly the nonce it names, in the key's namespace
  function testFuzz_SV_FUZZ_NREV_revokeNonce(uint256 nonce, uint256 deadlineOffset) public {
    uint256 deadline = block.timestamp + bound(deadlineOffset, 0, 365 days);
    bytes memory sig = _signNonceRevocation(key, nonce, deadline, masterKeyPk);

    vm.expectEmit(address(authenticator));
    emit IUnorderedNonce.RevokeNonce(_credentialHash(key), nonce);
    authenticator.revokeNonce(key, nonce, deadline, sig);

    assertEq(authenticator.nonces(_credentialHash(key), nonce >> 8), 1 << (nonce & 0xff), 'one bit');
    assertEq(authenticator.nonces(lNonceKey(owner), nonce >> 8), 0, 'in the key namespace only');
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

  /// @dev `b` behind its length word, padded to a whole number of words, as `abi.encode` lays it
  function _blob(bytes memory b) private pure returns (bytes memory) {
    return abi.encodePacked(b.length, b, new bytes((32 - (b.length % 32)) % 32));
  }

  function _prefix(bytes memory b, uint256 length) private pure returns (bytes memory out) {
    out = new bytes(length);
    for (uint256 i = 0; i < length; i++) {
      out[i] = b[i];
    }
  }

  function _suffix(bytes memory b, uint256 from) private pure returns (bytes memory out) {
    out = new bytes(b.length - from);
    for (uint256 i = from; i < b.length; i++) {
      out[i - from] = b[i];
    }
  }

  /**
   * @dev `key`, encoded with `tail` written straight after its `publicKey` bytes rather than zero
   * padding, so a read past the key's length finds `tail`
   */
  function _encodeKeyWithTail(AuthKey memory key, bytes memory tail)
    private
    pure
    returns (bytes memory)
  {
    bytes memory region = abi.encodePacked(key.publicKey, tail);
    return abi.encodePacked(
      abi.encode(uint256(0x60), key.keyType, key.expiration, key.publicKey.length),
      region,
      new bytes((32 - (region.length % 32)) % 32)
    );
  }

  /// @dev `abi.encode(key, false, signature)`, with `tail` after the key's bytes
  function _authDataWithKeyTail(AuthKey memory key, bytes memory tail, bytes memory signature)
    private
    pure
    returns (bytes memory)
  {
    bytes memory encodedKey = _encodeKeyWithTail(key, tail);
    return abi.encodePacked(
      abi.encode(uint256(0x60), false, 0x60 + encodedKey.length), encodedKey, _blob(signature)
    );
  }

  /// @dev Checks that `signer` encoded as a `keyType` key verifies `signature` over the digest
  /// SV-CRED-04 signs, and that the same key with a high bit set does not
  function _assertOnlyCleanEncodingVerifies(KeyType keyType, address signer, bytes memory signature)
    private
  {
    bytes32 digest = keccak256('a digest');
    AuthKey memory clean =
      AuthKey({publicKey: abi.encode(signer), keyType: keyType, expiration: block.timestamp + 1});
    AuthKey memory dirty = AuthKey({
      publicKey: abi.encode(uint256(uint160(signer)) | (1 << 200)),
      keyType: keyType,
      expiration: block.timestamp + 1
    });

    assertTrue(_verifyWithKeyTail(clean, '', digest, signature), 'the clean encoding verifies');
    assertFalse(_verifyWithKeyTail(dirty, '', digest, signature), 'the dirty encoding does not');
  }

  /// @dev {AuthKeyHarness-verify} on `key`, with `tail` after the key's bytes
  function _verifyWithKeyTail(
    AuthKey memory key,
    bytes memory tail,
    bytes32 digest,
    bytes memory signature
  ) private returns (bool) {
    bytes memory encodedKey = _encodeKeyWithTail(key, tail);
    return _rawVerify(
      abi.encodePacked(
        abi.encode(uint256(0x60), digest, 0x60 + encodedKey.length), encodedKey, _blob(signature)
      )
    );
  }

  /// @dev {AuthKeyHarness-verify} on arguments encoded by hand
  function _rawVerify(bytes memory args) private returns (bool) {
    (bool success, bytes memory result) = address(new AuthKeyHarness())
      .staticcall(abi.encodePacked(AuthKeyHarness.verify.selector, args));
    assertTrue(success, 'verify does not revert');
    return abi.decode(result, (bool));
  }

  /// @dev The error for a key presented as a master key that the owner never approved, payload
  /// and all
  function _masterKeyNotApproved(AuthKey memory masterKey) private view returns (bytes memory) {
    return abi.encodeWithSelector(
      ITwoTiersOrderAuthenticator.MasterKeyNotApproved.selector, _keyHash(masterKey)
    );
  }

  /// @dev The error for a session key with no master key the owner still holds behind it
  function _sessionKeyNotApproved(AuthKey memory sessionKey) private view returns (bytes memory) {
    return abi.encodeWithSelector(
      ITwoTiersOrderAuthenticator.SessionKeyNotApproved.selector, _keyHash(sessionKey)
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
      _allowances(_tokenAllowance(AMOUNT)),
      new ValidationParams[](0),
      new GenericCall[](0),
      nonce,
      deadline
    );
    bytes memory data = _fulfillmentAuthData(order, sessionKey, signerKey, isSessionKey);

    vm.prank(relayer);
    hub.fulfillOrderWithDelegatedAuthentication(
      order, address(authenticator), data, _route(order, _calls(_routerCall(0, hex'01'))), '', false
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

/// @dev ERC-7913 verifier that accepts every key and signature
contract PermissiveVerifier {
  function verify(bytes calldata, bytes32, bytes calldata) external pure returns (bytes4) {
    return PermissiveVerifier.verify.selector;
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
