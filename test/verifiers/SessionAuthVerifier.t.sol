// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {VerifierBase} from 'test/verifiers/base/VerifierBase.sol';

import {KeyFixtures} from 'test/verifiers/mocks/KeyFixtures.sol';

import {DeadlineChecker} from 'src/base/DeadlineChecker.sol';
import {IAuthVerifier} from 'src/base/interfaces/IAuthVerifier.sol';
import {IUnorderedNonce} from 'src/base/interfaces/IUnorderedNonce.sol';
import {ERC20Transfer} from 'src/v2/types/ERC20Transfer.sol';
import {ERC721Transfer} from 'src/v2/types/ERC721Transfer.sol';
import {GenericCall} from 'src/v2/types/GenericCall.sol';
import {ValidationParams} from 'src/v2/types/ValidationParams.sol';
import {ISessionAuthVerifier} from 'src/verifiers/interfaces/ISessionAuthVerifier.sol';
import {KeyType} from 'src/verifiers/types/KeyType.sol';
import {SessionKey} from 'src/verifiers/types/SessionKey.sol';

import {IERC20} from 'openzeppelin-contracts/contracts/token/ERC20/IERC20.sol';

/// @notice SV-* — session key approval, the hub-only gate, expiry, replay and every key scheme.
contract SessionAuthVerifierTest is VerifierBase {
  /// @dev One struct per entry-point domain, per the frozen plan's fuzz contract
  struct SessionFuzz {
    uint8 keyType;
    uint256 expirationOffset;
    uint256 nonce;
    uint256 deadlineOffset;
  }

  /// @dev Verification must produce a signature the key accepts, so this shape omits `keyType`
  struct SessionVerifyFuzz {
    uint256 nonce;
    uint256 deadlineOffset;
    uint256 expirationOffset;
  }

  uint160 internal constant AMOUNT = 3 ether;

  SessionKey internal key;

  function setUp() public override {
    super.setUp();
    key = _secpKey(sessionSigner, block.timestamp + 30 days);
  }

  // -------------------------------------------------------------------------------------------
  // SV-01 — the happy path: a session key authorises a relayed order
  // -------------------------------------------------------------------------------------------

  function test_SV_01_sessionKeyAuthorisesRelayedOrder() public {
    _delegateKeyThroughHub(key);

    uint256 nonce = 7;
    uint256 deadline = block.timestamp + 1 hours;
    uint256 before = IERC20(WETH).balanceOf(address(router));

    _executeViaVerifier(key, sessionKeyPk, nonce, deadline, true);

    assertEq(IERC20(WETH).balanceOf(address(router)) - before, AMOUNT, 'tokens moved');
    assertEq(verifier.nonces(owner, nonce >> 8), 1 << (nonce & 0xff), 'verifier nonce spent');
    assertEq(hub.nonces(owner, 0), 0, 'hub nonce untouched on this rail');
  }

  // -------------------------------------------------------------------------------------------
  // SV-02..04 — approving a key by calling the verifier directly
  // -------------------------------------------------------------------------------------------

  /// SV-02 — the owner may approve a key at the verifier directly, with no signature to check
  /**
   * @dev Being `msg.sender` is the authentication here, exactly as it is on the hub's own
   * `updateAuth`. No nonce is spent, because no signature was presented to replay.
   */
  function test_SV_02_ownerApprovesDirectlyWithoutSignature() public {
    SessionKey memory fresh = _secpKey(recipient, block.timestamp + 10 days);

    vm.prank(owner);
    verifier.updateAuth(owner, _encodeKey(fresh), 0, block.timestamp + 1 days, '');

    assertTrue(verifier.approvedKeys(owner, _keyHash(fresh)), 'approved');
    assertEq(verifier.nonces(owner, 0), 0, 'no nonce spent without a signature');
  }

  /// SV-02b — but not on someone else's behalf
  function test_SV_02b_strangerCannotApproveWithoutSignature() public {
    SessionKey memory fresh = _secpKey(recipient, block.timestamp + 10 days);

    vm.prank(relayer);
    vm.expectRevert(ISessionAuthVerifier.InvalidApprovalSignature.selector);
    verifier.updateAuth(owner, _encodeKey(fresh), 0, block.timestamp + 1 days, '');
  }

  /// SV-03 — a signature from anyone but the owner is rejected
  function test_SV_03_directApprovalWrongSigner() public {
    SessionKey memory fresh = _secpKey(recipient, block.timestamp + 10 days);
    uint256 deadline = block.timestamp + 1 days;

    bytes32 digest =
      lTypedDataHash(_verifierDomain(), lSessionApproval(_keyHash(fresh), 4, deadline));
    bytes memory sig = _sign(sessionKeyPk, digest); // the session key, not the owner

    vm.prank(relayer);
    vm.expectRevert(ISessionAuthVerifier.InvalidApprovalSignature.selector);
    verifier.updateAuth(owner, _encodeKey(fresh), 4, deadline, sig);
  }

  /// SV-04 — the approval deadline is enforced by the verifier itself
  function test_SV_04_directApprovalExpired() public {
    SessionKey memory fresh = _secpKey(recipient, block.timestamp + 10 days);
    uint256 deadline = block.timestamp - 1;
    bytes memory sig = _signSessionApproval(fresh, 5, deadline);

    vm.prank(relayer);
    vm.expectRevert(DeadlineChecker.DeadlinePassed.selector);
    verifier.updateAuth(owner, _encodeKey(fresh), 5, deadline, sig);
  }

  // -------------------------------------------------------------------------------------------
  // SV-05..09 — the verification gate
  // -------------------------------------------------------------------------------------------

  /// SV-05 — only the hub it was bound to may ask for a verification
  function test_SV_05_onlyAllowanceHubMayVerify() public {
    vm.prank(relayer);
    vm.expectRevert(IAuthVerifier.NotAllowanceHub.selector);
    verifier.verifyAuth(owner, hex'00', 0, block.timestamp, _encodeKey(key), hex'00');
  }

  /// SV-06 — a key the owner never approved cannot authorise anything
  function test_SV_06_unapprovedKeyRejected() public {
    _delegateKeyThroughHub(key);

    SessionKey memory stranger = _secpKey(relayer, block.timestamp + 30 days);

    vm.expectRevert(ISessionAuthVerifier.SessionKeyNotDelegated.selector);
    _executeViaVerifier(stranger, sessionKeyPk, 8, block.timestamp + 1 hours, false);
  }

  /// SV-07 — expiry is inclusive: the expiry second itself still works, the one before it does not
  function test_SV_07_expiryBoundary() public {
    uint256 t = block.timestamp + 1 days;

    SessionKey memory expiring = _secpKey(sessionSigner, t);
    _delegateKeyThroughHub(expiring);

    vm.warp(t);
    _executeViaVerifier(expiring, sessionKeyPk, 9, t + 1 hours, true);

    vm.warp(t + 1);
    vm.expectRevert(ISessionAuthVerifier.SessionKeyExpired.selector);
    _executeViaVerifier(expiring, sessionKeyPk, 10, t + 1 hours, false);
  }

  /// SV-08 — an approved key still has to have signed this particular order
  function test_SV_08_wrongSignatureRejected() public {
    _delegateKeyThroughHub(key);

    (, uint256 impostorKey) = makeAddrAndKey('impostor');

    vm.expectRevert(ISessionAuthVerifier.InvalidApprovalSignature.selector);
    _executeViaVerifier(key, impostorKey, 11, block.timestamp + 1 hours, false);
  }

  /// SV-09 — the verifier's nonce makes an authorisation single-use
  function test_SV_09_nonceReplayRejected() public {
    _delegateKeyThroughHub(key);

    uint256 nonce = 12;
    uint256 deadline = block.timestamp + 1 hours;

    _executeViaVerifier(key, sessionKeyPk, nonce, deadline, true);

    vm.expectRevert(IUnorderedNonce.NonceAlreadyUsed.selector);
    _executeViaVerifier(key, sessionKeyPk, nonce, deadline, false);
  }

  // -------------------------------------------------------------------------------------------
  // SV-10 — the trailing discriminator byte keeps the two entry points apart
  // -------------------------------------------------------------------------------------------

  function test_SV_10_executionApprovalCannotSettleAFulfillment() public {
    _delegateKeyThroughHub(key);

    uint256 nonce = 13;
    uint256 deadline = block.timestamp + 1 hours;

    ERC20Transfer[] memory erc20s = _erc20s(_wethTransfer(AMOUNT));
    GenericCall[] memory calls = _calls(_routerCall(0, hex'01'));

    // signed as an execution, then submitted through the fulfillment entry point
    bytes32 digest = lTypedDataHash(
      _verifierDomain(),
      lExecutionApproval(ANY, erc20s, new ERC721Transfer[](0), calls, nonce, deadline)
    );
    bytes memory sig = _sign(sessionKeyPk, digest);

    vm.prank(relayer);
    vm.expectRevert(ISessionAuthVerifier.InvalidApprovalSignature.selector);
    hub.transferAndFulfill(
      owner,
      erc20s,
      new ERC721Transfer[](0),
      new ValidationParams[](0),
      deadline,
      _flags(false, false, false),
      _verifierAuthData(address(verifier), nonce, _encodeKey(key), sig),
      calls,
      0,
      ''
    );
  }

  /// SV-10b — and the fulfillment shape is what that entry point does accept
  function test_SV_10b_fulfillmentApprovalSettlesAFulfillment() public {
    _delegateKeyThroughHub(key);

    uint256 nonce = 14;
    uint256 deadline = block.timestamp + 1 hours;

    ERC20Transfer[] memory erc20s = _erc20s(_wethTransfer(AMOUNT));
    GenericCall[] memory calls = _calls(_routerCall(0, hex'01'));
    uint256 before = IERC20(WETH).balanceOf(address(router));

    bytes32 digest = lTypedDataHash(
      _verifierDomain(),
      lFulfillmentApproval(
        ANY, erc20s, new ERC721Transfer[](0), new ValidationParams[](0), ANY, nonce, deadline
      )
    );
    bytes memory sig = _sign(sessionKeyPk, digest);

    vm.prank(relayer);
    hub.transferAndFulfill(
      owner,
      erc20s,
      new ERC721Transfer[](0),
      new ValidationParams[](0),
      deadline,
      _flags(false, false, false),
      _verifierAuthData(address(verifier), nonce, _encodeKey(key), sig),
      calls,
      0,
      ''
    );

    assertEq(IERC20(WETH).balanceOf(address(router)) - before, AMOUNT);
  }

  // -------------------------------------------------------------------------------------------
  // SV-11 — the approval binds the whole key, not just its public half
  // -------------------------------------------------------------------------------------------

  function test_SV_11_changingExpiryBreaksTheApproval() public {
    _delegateKeyThroughHub(key);

    // same signer, later expiry: a different key as far as the approval is concerned
    SessionKey memory stretched = _secpKey(sessionSigner, key.expiration + 1);

    vm.expectRevert(ISessionAuthVerifier.SessionKeyNotDelegated.selector);
    _executeViaVerifier(stretched, sessionKeyPk, 15, block.timestamp + 1 hours, false);
  }

  // -------------------------------------------------------------------------------------------
  // SV-KEY-* — every signature scheme
  // -------------------------------------------------------------------------------------------

  /// SV-KEY-SECP-01 is covered by SV-01; this is the ERC-1271 half
  function test_SV_KEY_SECP_02_contractSigner() public {
    // a session key naming a contract: SignatureChecker falls through to ERC-1271
    SessionKey memory walletKey = SessionKey({
      publicKey: abi.encode(address(_wallet())),
      keyType: KeyType.Secp256k1,
      expiration: block.timestamp + 30 days
    });
    _delegateKeyThroughHub(walletKey);

    uint256 before = IERC20(WETH).balanceOf(address(router));
    _executeViaVerifier(walletKey, _walletSignerKey, 16, block.timestamp + 1 hours, true);
    assertEq(IERC20(WETH).balanceOf(address(router)) - before, AMOUNT);
  }

  /// SV-KEY-P256-01 / -02 — a canonical signature is accepted, its malleable twin is not
  function test_SV_KEY_P256() public {
    SessionKey memory p256 = SessionKey({
      publicKey: KeyFixtures.p256PublicKey(),
      keyType: KeyType.P256,
      expiration: block.timestamp + 30 days
    });
    _delegateKeyThroughHub(p256);

    uint256 nonce = 17;
    uint256 deadline = block.timestamp + 1 hours;
    bytes32 digest = _executionDigest(nonce, deadline);

    bytes memory signature = KeyFixtures.p256Sign(digest);
    assertLe(KeyFixtures.sOf(signature), KeyFixtures.P256_HALF_N, 'fixture is canonical');

    uint256 before = IERC20(WETH).balanceOf(address(router));
    _submitExecution(p256, signature, nonce, deadline);
    assertEq(IERC20(WETH).balanceOf(address(router)) - before, AMOUNT, 'P256 accepted');

    // the same signature with s replaced by N - s must not verify
    bytes32 digest2 = _executionDigest(18, deadline);
    bytes memory malleable = KeyFixtures.flipS(KeyFixtures.p256Sign(digest2));
    assertGt(KeyFixtures.sOf(malleable), KeyFixtures.P256_HALF_N, 'twin is non-canonical');

    vm.prank(relayer);
    vm.expectRevert(ISessionAuthVerifier.InvalidApprovalSignature.selector);
    _submitExecutionRaw(p256, malleable, 18, deadline);
  }

  /// SV-KEY-WEBAUTHN-01..03
  function test_SV_KEY_WebAuthn() public {
    SessionKey memory wa = SessionKey({
      publicKey: KeyFixtures.p256PublicKey(),
      keyType: KeyType.WebAuthn,
      expiration: block.timestamp + 30 days
    });
    _delegateKeyThroughHub(wa);

    uint256 deadline = block.timestamp + 1 hours;

    // -01 a user-verified assertion is accepted
    bytes32 digest = _executionDigest(19, deadline);
    uint256 before = IERC20(WETH).balanceOf(address(router));
    _submitExecution(wa, KeyFixtures.webAuthnAssertion(digest, true), 19, deadline);
    assertEq(IERC20(WETH).balanceOf(address(router)) - before, AMOUNT, 'webauthn accepted');

    // -02 the verifier requires user verification, so a UP-only assertion fails.
    // The assertion is built BEFORE the cheatcodes: it makes external calls of its own, and a
    // helper in argument position would consume the expectRevert instead of the hub call.
    bytes32 digest2 = _executionDigest(20, deadline);
    bytes memory upOnly = KeyFixtures.webAuthnAssertion(digest2, false);

    vm.prank(relayer);
    vm.expectRevert(ISessionAuthVerifier.InvalidApprovalSignature.selector);
    _submitExecutionRaw(wa, upOnly, 20, deadline);

    // -03 an assertion that does not decode at all is rejected rather than reverting oddly
    vm.prank(relayer);
    vm.expectRevert(ISessionAuthVerifier.InvalidApprovalSignature.selector);
    _submitExecutionRaw(wa, hex'deadbeef', 21, deadline);
  }

  /// SV-KEY-RSA-01 / -02 — a 2048-bit modulus verifies, a short one is refused
  /**
   * @dev Exercised at the library level against a checked-in vector. The signature must be made
   * with the private exponent, which is far too expensive to compute on-chain; verification uses
   * the public exponent and is what the contract actually performs.
   */
  function test_SV_KEY_Rsa() public {
    SessionKeyHarness harness = new SessionKeyHarness();

    SessionKey memory rsa = SessionKey({
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
    SessionKey memory shortRsa = SessionKey({
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
  // SV-DOMAIN / SV-FUZZ-VER
  // -------------------------------------------------------------------------------------------

  function test_SV_DOMAIN_matchesTheWrittenOutDomain() public view {
    (, string memory name, string memory version, uint256 chainId, address verifyingContract,,) =
      verifier.eip712Domain();

    assertEq(name, 'KyberSwap Session Auth Verifier');
    assertEq(version, '1.0.0');
    assertEq(chainId, block.chainid);
    assertEq(verifyingContract, address(verifier));
  }

  /// SV-FUZZ-UPD — approving a key directly, across every scheme, expiry and nonce
  /// @dev Subsumes SV-02 (relayed approval carrying the owner's signature): same rail, same call,
  /// and both of that case's assertions appear below over a wider domain.
  /**
   * @dev The approval path never verifies signature material against the key, only its hash, so
   * the key type can be fuzzed across all four arms here even though only Secp256k1 can be signed
   * for in {testFuzz_SV_FUZZ_VER_nonceAndDeadline}.
   */
  function testFuzz_SV_FUZZ_UPD_directApproval(SessionFuzz memory f) public {
    KeyType keyType = KeyType(bound(f.keyType, 0, 3));
    uint256 expiration = block.timestamp + bound(f.expirationOffset, 0, 365 days);
    uint256 deadline = block.timestamp + bound(f.deadlineOffset, 0, 30 days);

    SessionKey memory fresh =
      SessionKey({publicKey: abi.encode(recipient), keyType: keyType, expiration: expiration});

    bytes memory sig = _signSessionApproval(fresh, f.nonce, deadline);

    vm.prank(relayer);
    verifier.updateAuth(owner, _encodeKey(fresh), f.nonce, deadline, sig);

    assertTrue(verifier.approvedKeys(owner, _keyHash(fresh)), 'approved');
    assertEq(verifier.nonces(owner, f.nonce >> 8), 1 << (f.nonce & 0xff), 'nonce spent');

    // the approval binds the whole key, so a different scheme over the same bytes is a different key
    SessionKey memory other = SessionKey({
      publicKey: abi.encode(recipient),
      keyType: KeyType((uint8(keyType) + 1) % 4),
      expiration: expiration
    });
    assertFalse(verifier.approvedKeys(owner, _keyHash(other)), 'key type is part of the identity');
  }

  function testFuzz_SV_FUZZ_VER_nonceAndDeadline(SessionVerifyFuzz memory f) public {
    uint256 nonce = f.nonce;
    uint256 deadline = block.timestamp + bound(f.deadlineOffset, 0, 30 days);

    // the key's own expiry is a live dimension: it must outlast the order for it to settle
    SessionKey memory fuzzKey =
      _secpKey(sessionSigner, block.timestamp + bound(f.expirationOffset, 0, 365 days));
    _delegateKeyThroughHub(fuzzKey);

    uint256 before = IERC20(WETH).balanceOf(address(router));
    _executeViaVerifier(fuzzKey, sessionKeyPk, nonce, deadline, true);

    assertEq(IERC20(WETH).balanceOf(address(router)) - before, AMOUNT);
    assertEq(verifier.nonces(owner, nonce >> 8), 1 << (nonce & 0xff), 'exact nonce bit');
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
      _asEoa(signer);
      _walletAddr = address(new ERC1271WalletLocal(signer));
    }
    return _walletAddr;
  }

  /// @dev The digest the hub will make the verifier rebuild for a one-transfer, one-call order
  function _executionDigest(uint256 nonce, uint256 deadline) private view returns (bytes32) {
    return lTypedDataHash(
      _verifierDomain(),
      lExecutionApproval(
        ANY,
        _erc20s(_wethTransfer(AMOUNT)),
        new ERC721Transfer[](0),
        _calls(_routerCall(0, hex'01')),
        nonce,
        deadline
      )
    );
  }

  function _executeViaVerifier(
    SessionKey memory sessionKey,
    uint256 signerKey,
    uint256 nonce,
    uint256 deadline,
    bool expectSuccess
  ) private {
    bytes memory sig = _sign(signerKey, _executionDigest(nonce, deadline));
    if (expectSuccess) {
      _submitExecution(sessionKey, sig, nonce, deadline);
    } else {
      vm.prank(relayer);
      _submitExecutionRaw(sessionKey, sig, nonce, deadline);
    }
  }

  function _submitExecution(
    SessionKey memory sessionKey,
    bytes memory signature,
    uint256 nonce,
    uint256 deadline
  ) private {
    vm.prank(relayer);
    _submitExecutionRaw(sessionKey, signature, nonce, deadline);
  }

  function _submitExecutionRaw(
    SessionKey memory sessionKey,
    bytes memory signature,
    uint256 nonce,
    uint256 deadline
  ) private {
    hub.transferAndExecute(
      owner,
      _erc20s(_wethTransfer(AMOUNT)),
      new ERC721Transfer[](0),
      _calls(_routerCall(0, hex'01')),
      deadline,
      _flags(false, false, false),
      _verifierAuthData(address(verifier), nonce, _encodeKey(sessionKey), signature)
    );
  }
}

/// @dev Exposes the library's calldata `verify` so a key scheme can be checked without the hub
contract SessionKeyHarness {
  function verify(SessionKey calldata key, bytes32 digest, bytes calldata signature)
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
