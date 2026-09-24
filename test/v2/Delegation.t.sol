// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {VerifierBase} from 'test/verifiers/base/VerifierBase.sol';

import {ERC1271WalletMock} from 'test/v2/mocks/TokenMocks.sol';

import {DeadlineChecker} from 'src/base/DeadlineChecker.sol';
import {IAuthDelegator} from 'src/base/interfaces/IAuthDelegator.sol';
import {IAuthVerifier} from 'src/base/interfaces/IAuthVerifier.sol';
import {IUnorderedNonce} from 'src/base/interfaces/IUnorderedNonce.sol';
import {ERC20Transfer} from 'src/v2/types/ERC20Transfer.sol';
import {ERC721Transfer} from 'src/v2/types/ERC721Transfer.sol';
import {GenericCall} from 'src/v2/types/GenericCall.sol';
import {ValidationParams} from 'src/v2/types/ValidationParams.sol';

import {IERC20} from 'openzeppelin-contracts/contracts/token/ERC20/IERC20.sol';
import {SessionKey} from 'src/verifiers/types/SessionKey.sol';

import {ECDSA} from 'openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol';

/// @notice DEL-*, NONCE-*, CALLS-* and VAL-* — delegation, nonces, calls approval, validators.
/// @notice Verifier that can be switched to reverting, to show a withdrawal never calls it
contract RevertingVerifier is IAuthVerifier {
  error Nope();

  bool public reverting;

  /// @dev Counts the calls that got through, so a leg can be shown never to have made one
  uint256 public initCount;

  function setReverting(bool value) external {
    reverting = value;
  }

  function initAuth(address, bytes calldata) external {
    if (reverting) revert Nope();
    initCount++;
  }

  function updateAuth(address, bytes calldata, uint256, uint256, bytes calldata) external view {
    if (reverting) revert Nope();
  }

  function verifyAuth(address, bytes calldata, uint256, uint256, bytes calldata, bytes calldata)
    external
    view
  {
    if (reverting) revert Nope();
  }
}

contract DelegationTest is VerifierBase {
  /// @dev One struct per entry-point domain, per the frozen plan's fuzz contract
  struct DelegationFuzz {
    uint256 nonce;
    uint256 deadlineOffset;
  }

  /// @dev Transcribed from {IAuthVerifier}, so production cannot vouch for its own signature
  string internal constant S_INIT_AUTH = 'initAuth(address,bytes)';

  SessionKey internal key;

  function setUp() public override {
    super.setUp();
    key = _secpKey(sessionSigner, block.timestamp + 30 days);
  }

  // -------------------------------------------------------------------------------------------
  // DEL — delegating a verifier
  // -------------------------------------------------------------------------------------------

  /// DEL-01 — the owner delegates for themselves: no nonce is spent and the verifier is trusted
  function test_DEL_01_selfDelegationSpendsNoNonce() public {
    uint256 word = 0;

    vm.prank(owner);
    hub.updateDelegation(
      owner, address(verifier), true, _encodeKey(key), 0, block.timestamp + 1 days, ''
    );

    assertTrue(hub.authDelegated(owner, address(verifier)), 'delegated');
    assertTrue(verifier.approvedKeys(owner, _keyHash(key)), 'key approved without a signature');
    assertEq(hub.nonces(owner, word), 0, 'no hub nonce consumed');
  }

  /// DEL-02 — a third party may submit the delegation when it carries the owner's signature
  function test_DEL_02_relayedDelegationConsumesNonce() public {
    uint256 nonce = 5;
    uint256 deadline = block.timestamp + 1 days;
    bytes memory sig =
      _signAuthDelegation(ownerKey, address(verifier), true, _encodeKey(key), nonce, deadline);

    vm.prank(relayer);
    hub.updateDelegation(owner, address(verifier), true, _encodeKey(key), nonce, deadline, sig);

    assertTrue(hub.authDelegated(owner, address(verifier)));
    assertEq(hub.nonces(owner, nonce >> 8), 1 << (nonce & 0xff), 'exact bit set');

    // NONCE-02 — the same nonce cannot be spent twice
    vm.prank(relayer);
    vm.expectRevert(IUnorderedNonce.NonceAlreadyUsed.selector);
    hub.updateDelegation(owner, address(verifier), true, _encodeKey(key), nonce, deadline, sig);
  }

  /// DEL-03 — changing any signed field invalidates the delegation
  function test_DEL_03_tamperedDelegationRejected() public {
    uint256 deadline = block.timestamp + 1 days;
    bytes memory sig =
      _signAuthDelegation(ownerKey, address(verifier), true, _encodeKey(key), 1, deadline);

    SessionKey memory otherKey = _secpKey(relayer, block.timestamp + 30 days);

    vm.prank(relayer);
    vm.expectRevert(IAuthDelegator.InvalidDelegationSignature.selector);
    hub.updateDelegation(owner, address(verifier), true, _encodeKey(otherKey), 1, deadline, sig);
  }

  /// DEL-04 — a contract owner authorises through ERC-1271
  function test_DEL_04_erc1271Owner() public {
    (address walletSigner, uint256 walletSignerKey) = makeAddrAndKey('wallet signer');
    _asEoa(walletSigner);
    ERC1271WalletMock wallet = new ERC1271WalletMock(walletSigner);

    uint256 deadline = block.timestamp + 1 days;
    bytes memory sig =
      _signAuthDelegation(walletSignerKey, address(verifier), true, _encodeKey(key), 2, deadline);

    vm.prank(relayer);
    hub.updateDelegation(
      address(wallet), address(verifier), true, _encodeKey(key), 2, deadline, sig
    );
    assertTrue(hub.authDelegated(address(wallet), address(verifier)));

    // and a wallet that returns the wrong magic value is rejected
    wallet.setReturnWrongMagic(true);
    bytes memory sig2 =
      _signAuthDelegation(walletSignerKey, address(verifier), true, _encodeKey(key), 3, deadline);

    vm.prank(relayer);
    vm.expectRevert(IAuthDelegator.InvalidDelegationSignature.selector);
    hub.updateDelegation(
      address(wallet), address(verifier), true, _encodeKey(key), 3, deadline, sig2
    );
  }

  /// DEL-05 — the delegation deadline is enforced
  function test_DEL_05_expiredDelegation() public {
    uint256 deadline = block.timestamp - 1;
    bytes memory sig =
      _signAuthDelegation(ownerKey, address(verifier), true, _encodeKey(key), 4, deadline);

    vm.prank(relayer);
    vm.expectRevert(DeadlineChecker.DeadlinePassed.selector);
    hub.updateDelegation(owner, address(verifier), true, _encodeKey(key), 4, deadline, sig);
  }

  /**
   * DEL-06 — withdrawing stops the hub accepting that verifier, while the key stays approved
   * @dev The owner needs no signature, exactly as when delegating: being `msg.sender` is the
   * authentication. `data` is ignored on this direction, so the key it names is left alone.
   */
  function test_DEL_06_withdrawDelegation() public {
    _delegateKeyThroughHub(key);
    assertTrue(hub.authDelegated(owner, address(verifier)));

    vm.prank(owner);
    hub.updateDelegation(owner, address(verifier), false, '', 0, block.timestamp + 1 days, '');
    assertFalse(hub.authDelegated(owner, address(verifier)));

    // the verifier still holds the approval, which is why re-delegating re-arms it; dropping the
    // key itself is a separate instruction to the verifier, covered by SV-REV-01
    assertTrue(verifier.approvedKeys(owner, _keyHash(key)));
  }

  /**
   * DEL-08 — a withdrawal never reaches the verifier, so one that reverts cannot trap the owner
   * @dev The safety valve has to work unconditionally; a verifier the owner can no longer get out
   * of would keep authorising orders forever. Every leg carries the same non-empty `data`, which
   * is what makes the verifier reachable at all: with an empty payload `initAuth` is skipped on
   * both directions and the contrast would be between two calls that never happened.
   */
  function test_DEL_08_withdrawalDoesNotCallTheVerifier() public {
    RevertingVerifier bad = new RevertingVerifier();
    uint256 deadline = block.timestamp + 1 days;

    vm.prank(owner);
    hub.updateDelegation(owner, address(bad), true, hex'1234', 0, deadline, '');
    assertTrue(hub.authDelegated(owner, address(bad)), 'delegated while it still answered');
    assertEq(bad.initCount(), 1, 'and that payload did reach it');

    bad.setReverting(true);

    // the control: the same payload on the delegate direction now fails at the verifier, so the
    // withdrawal below is evidence about the direction rather than about the payload
    vm.prank(owner);
    vm.expectRevert(RevertingVerifier.Nope.selector);
    hub.updateDelegation(owner, address(bad), true, hex'1234', 0, deadline, '');

    vm.prank(owner);
    hub.updateDelegation(owner, address(bad), false, hex'1234', 0, deadline, '');
    assertFalse(hub.authDelegated(owner, address(bad)), 'withdrawn despite the revert');
    assertEq(bad.initCount(), 1, 'and the withdrawal never called it');
  }

  /// DEL-09 — a relayed withdrawal needs the owner's signature over the same direction
  function test_DEL_09_relayedWithdrawal() public {
    _delegateKeyThroughHub(key);
    uint256 deadline = block.timestamp + 1 days;

    // the direction is signed, so a delegation signature cannot be submitted as a withdrawal
    bytes memory delegateSig =
      _signAuthDelegation(ownerKey, address(verifier), true, '', 5, deadline);
    vm.prank(relayer);
    vm.expectRevert(IAuthDelegator.InvalidDelegationSignature.selector);
    hub.updateDelegation(owner, address(verifier), false, '', 5, deadline, delegateSig);

    // the same signature under its own direction is accepted, which is what makes that evidence
    vm.prank(relayer);
    hub.updateDelegation(owner, address(verifier), true, '', 5, deadline, delegateSig);
    assertTrue(hub.authDelegated(owner, address(verifier)), 'delegated on its own direction');

    bytes memory withdrawSig =
      _signAuthDelegation(ownerKey, address(verifier), false, '', 6, deadline);
    vm.prank(relayer);
    hub.updateDelegation(owner, address(verifier), false, '', 6, deadline, withdrawSig);

    assertFalse(hub.authDelegated(owner, address(verifier)), 'withdrawn by the relayer');
    assertEq(hub.nonces(owner, 0), (1 << 5) | (1 << 6), 'one hub nonce per accepted decision');
  }

  // -------------------------------------------------------------------------------------------
  // DEL-10..12 — `initAuth` is not `updateAuth`, and only the hub may reach it
  // -------------------------------------------------------------------------------------------

  /**
   * DEL-10 — `initAuth` ignores the direction word, so a "revoke" payload still approves
   * @dev The two verifier entry points read the same bytes differently: `updateAuth` takes word 1
   * as the direction, while `initAuth` follows word 0 to the key and stops. Delegating therefore
   * has one direction only — the payload cannot ask it to revoke — and the second half here is
   * what makes that a statement about `initAuth` rather than about the payload, since the very
   * same bytes through `updateAuth` do the opposite.
   */
  function test_DEL_10_initAuthIgnoresTheDirectionWord() public {
    uint256 deadline = block.timestamp + 1 days;
    bytes32 keyHash = _keyHash(key);
    bytes memory revokeShaped = _revokeKey(key);

    vm.prank(owner);
    hub.updateDelegation(owner, address(verifier), true, revokeShaped, 0, deadline, '');

    assertTrue(verifier.approvedKeys(owner, keyHash), 'approved despite the false direction');

    vm.prank(owner);
    verifier.updateAuth(owner, revokeShaped, 0, deadline, '');
    assertFalse(verifier.approvedKeys(owner, keyHash), 'and updateAuth reads it as a revocation');
  }

  /**
   * DEL-11 — both payload shapes name the same key
   * @dev `initAuth` follows a relative offset out of word 0 rather than assuming the struct starts
   * at a fixed place, so `abi.encode(key)` and `abi.encode(key, anything)` land on the same bytes
   * and hash to the same key. The revocation between the two legs is what stops the second one
   * being a no-op against a key that was already approved.
   */
  function test_DEL_11_bothPayloadShapesNameTheSameKey() public {
    uint256 deadline = block.timestamp + 1 days;
    bytes32 keyHash = _keyHash(key);
    bytes memory keyOnly = _encodeKey(key);
    bytes memory keyPlusNoise = abi.encode(key, keccak256('noise'));

    vm.prank(owner);
    hub.updateDelegation(owner, address(verifier), true, keyOnly, 0, deadline, '');
    assertTrue(verifier.approvedKeys(owner, keyHash), 'the bare key shape approves it');

    vm.prank(owner);
    verifier.updateAuth(owner, _revokeKey(key), 0, deadline, '');
    assertFalse(verifier.approvedKeys(owner, keyHash), 'cleared again');

    vm.prank(owner);
    hub.updateDelegation(owner, address(verifier), true, keyPlusNoise, 0, deadline, '');
    assertTrue(verifier.approvedKeys(owner, keyHash), 'and so does the same key with a word after');
  }

  /**
   * DEL-12 — `initAuth` answers the hub alone, and being the owner is not a way in
   * @dev It takes no signature, no nonce and no deadline: it trusts its caller completely, so the
   * caller check is the whole of its security. The owner leg matters as much as the stranger's,
   * because "the owner may do it anyway" is exactly the reasoning that would justify relaxing the
   * modifier — and the owner already has a route, through {AuthDelegator-updateDelegation}.
   */
  function test_DEL_12_initAuthIsHubOnly() public {
    bytes memory payload = _encodeKey(key);
    bytes32 keyHash = _keyHash(key);

    vm.prank(relayer);
    vm.expectRevert(IAuthVerifier.NotAllowanceHub.selector);
    verifier.initAuth(owner, payload);

    vm.prank(owner);
    vm.expectRevert(IAuthVerifier.NotAllowanceHub.selector);
    verifier.initAuth(owner, payload);

    assertFalse(verifier.approvedKeys(owner, keyHash), 'nothing was approved either time');
  }

  // -------------------------------------------------------------------------------------------
  // DEL-13..15 — the guard on the forwarded `initAuth` is a conjunction
  // -------------------------------------------------------------------------------------------

  /**
   * DEL-13 — an empty payload skips the verifier, even on the delegate direction
   * @dev The verifier is set to revert, so merely not reverting is already suggestive — but only
   * suggestive: a verifier that had been called and answered would satisfy that just as well. The
   * expectation of zero calls with the exact calldata is the oracle, and the calldata is built
   * from a signature string written out in this file rather than from the production interface.
   */
  function test_DEL_13_emptyPayloadNeverCallsInitAuth() public {
    RevertingVerifier bad = new RevertingVerifier();
    bad.setReverting(true);

    bytes memory empty = '';
    bytes memory expectedCall = abi.encodeWithSignature(S_INIT_AUTH, owner, empty);

    vm.expectCall(address(bad), expectedCall, 0);

    vm.prank(owner);
    hub.updateDelegation(owner, address(bad), true, empty, 0, block.timestamp + 1 days, '');

    assertTrue(hub.authDelegated(owner, address(bad)), 'delegated without touching the verifier');
    assertEq(bad.initCount(), 0, 'and it counted no call');
  }

  /**
   * DEL-14 — the guard reads the payload's length, not the direction alone
   * @dev One byte apart from DEL-13, same direction, same verifier. A single zero byte is enough
   * to cross the guard, which isolates `data.length > 0` from any notion of the payload being
   * meaningful. The first leg also fixes the exact calldata the hub forwards, which is what the
   * zero-call expectations in DEL-13 and DEL-15 are asserting the absence of: a signature string
   * that named nothing would make those two pass vacuously, and would fail here.
   */
  function test_DEL_14_nonEmptyPayloadDoesCallInitAuth() public {
    RevertingVerifier bad = new RevertingVerifier();
    uint256 deadline = block.timestamp + 1 days;

    bytes memory payload = hex'00';
    bytes memory expectedCall = abi.encodeWithSignature(S_INIT_AUTH, owner, payload);

    // twice: once below while the verifier still answers, and once on the refused attempt at the
    // end, which reaches it just as far before being turned away
    vm.expectCall(address(bad), expectedCall, 2);

    vm.prank(owner);
    hub.updateDelegation(owner, address(bad), true, payload, 0, deadline, '');
    assertEq(bad.initCount(), 1, 'one byte of payload is enough to reach the verifier');

    // and once it refuses, the refusal is the owner's problem: the delegation does not stand
    bad.setReverting(true);

    vm.prank(owner);
    hub.updateDelegation(owner, address(bad), false, '', 0, deadline, '');
    assertFalse(hub.authDelegated(owner, address(bad)), 'cleared, so the next leg is a transition');

    vm.prank(owner);
    vm.expectRevert(RevertingVerifier.Nope.selector);
    hub.updateDelegation(owner, address(bad), true, payload, 0, deadline, '');

    assertFalse(hub.authDelegated(owner, address(bad)), 'the delegation rolled back with it');
    assertEq(bad.initCount(), 1, 'and the refused call left its counter alone');
  }

  /**
   * DEL-15 — a withdrawal skips the verifier whatever the payload says
   * @dev DEL-13 held the direction and emptied the payload; this holds a payload DEL-14 has just
   * shown does reach a verifier and flips the direction instead. Between the three the guard is
   * pinned as the conjunction it is written as. Nothing is delegated here beforehand, so the
   * withdrawal is not even undoing anything — and still must not call out, because the escape
   * hatch has to work against a verifier that has started refusing every call.
   */
  function test_DEL_15_withdrawalSkipsTheVerifierWhateverThePayload() public {
    RevertingVerifier bad = new RevertingVerifier();
    bad.setReverting(true);

    bytes memory payload = hex'00';
    bytes memory expectedCall = abi.encodeWithSignature(S_INIT_AUTH, owner, payload);

    vm.expectCall(address(bad), expectedCall, 0);

    vm.prank(owner);
    hub.updateDelegation(owner, address(bad), false, payload, 0, block.timestamp + 1 days, '');

    assertFalse(hub.authDelegated(owner, address(bad)), 'withdrawn');
    assertEq(bad.initCount(), 0, 'and the verifier was never called');
  }

  /// DEL-FUZZ — the delegation nonce bitmap behaves across its whole domain
  function testFuzz_DEL_FUZZ_relayedDelegation(DelegationFuzz memory f) public {
    uint256 nonce = f.nonce;
    uint256 deadline = block.timestamp + bound(f.deadlineOffset, 0, 30 days);

    bytes memory sig =
      _signAuthDelegation(ownerKey, address(verifier), true, _encodeKey(key), nonce, deadline);

    vm.prank(relayer);
    hub.updateDelegation(owner, address(verifier), true, _encodeKey(key), nonce, deadline, sig);

    assertTrue(hub.authDelegated(owner, address(verifier)));
    assertEq(hub.nonces(owner, nonce >> 8), 1 << (nonce & 0xff), 'exact bit for this nonce');
  }

  // -------------------------------------------------------------------------------------------
  // NONCE — the unordered bitmap
  // -------------------------------------------------------------------------------------------

  /// NONCE-01 / NONCE-FUZZ — a nonce lands on exactly one bit, at the position it names
  function testFuzz_NONCE_FUZZ_revokeSetsExactlyOneBit(uint256 nonce) public {
    vm.prank(owner);
    hub.revokeNonce(nonce);

    assertEq(hub.nonces(owner, nonce >> 8), 1 << (nonce & 0xff), 'exact bit');
    // a neighbouring word is untouched
    assertEq(hub.nonces(owner, (nonce >> 8) + 1), 0, 'neighbouring word clean');
  }

  /// NONCE-01 — the documented boundaries
  function test_NONCE_01_bitmapBoundaries() public {
    uint256[4] memory nonces = [uint256(0), 255, 256, type(uint256).max];

    for (uint256 i = 0; i < nonces.length; i++) {
      vm.prank(owner);
      hub.revokeNonce(nonces[i]);

      // nonces 0 and 255 share word 0, so assert the bit rather than the whole word
      uint256 bit = 1 << (nonces[i] & 0xff);
      assertEq(hub.nonces(owner, nonces[i] >> 8) & bit, bit, 'boundary bit set');
    }

    // 0 and 256 share a bit position but live in different words
    assertEq(hub.nonces(owner, 0), (1 << 0) | (1 << 255), 'word 0 holds 0 and 255');
    assertEq(hub.nonces(owner, 1), 1 << 0, 'word 1 holds 256');
  }

  /// NONCE-04 — revoking twice reverts
  function test_NONCE_04_doubleRevoke() public {
    vm.startPrank(owner);
    hub.revokeNonce(9);
    vm.expectRevert(IUnorderedNonce.NonceAlreadyUsed.selector);
    hub.revokeNonce(9);
    vm.stopPrank();
  }

  /// NONCE-05 — the hub and the verifier keep separate bitmaps
  function test_NONCE_05_hubAndVerifierAreIndependent() public {
    vm.prank(owner);
    hub.revokeNonce(3);

    vm.prank(owner);
    verifier.revokeNonce(3);

    assertEq(hub.nonces(owner, 0), 1 << 3);
    assertEq(verifier.nonces(owner, 0), 1 << 3);

    // spending it on one side does not spend it on the other
    vm.prank(owner);
    vm.expectRevert(IUnorderedNonce.NonceAlreadyUsed.selector);
    hub.revokeNonce(3);
  }

  // -------------------------------------------------------------------------------------------
  // CALLS — approving the call list of a fulfillment
  // -------------------------------------------------------------------------------------------

  /// CALLS-01 — an empty approval means "any calls" and spends no nonce
  function test_CALLS_01_emptySignatureSpendsNoNonce() public {
    _delegateKeyThroughHub(key);

    GenericCall[] memory calls = _calls(_routerCall(0, hex'01'));
    uint256 deadline = block.timestamp + 1 hours;

    _fulfillAsOwner(calls, 0, '', deadline);

    assertEq(hub.nonces(owner, 0), 0, 'calls nonce untouched');
  }

  /// CALLS-02 / CALLS-03 — a real approval spends the owner's nonce, once
  function test_CALLS_02_approvalSpendsOwnerNonce() public {
    _delegateKeyThroughHub(key);

    GenericCall[] memory calls = _calls(_routerCall(0, hex'01'));
    uint256 deadline = block.timestamp + 1 hours;
    uint256 callsNonce = 21;

    bytes memory callsSig = _signCallsApproval(ownerKey, owner, calls, callsNonce, deadline);

    _fulfillAsOwner(calls, callsNonce, callsSig, deadline);
    assertEq(hub.nonces(owner, 0), 1 << 21, 'calls nonce spent');

    // CALLS-03 — the same approval cannot settle twice
    vm.prank(owner);
    vm.expectRevert(IUnorderedNonce.NonceAlreadyUsed.selector);
    hub.transferAndFulfill(
      owner,
      new ERC20Transfer[](0),
      new ERC721Transfer[](0),
      new ValidationParams[](0),
      deadline,
      _flags(false, false, false),
      '',
      calls,
      callsNonce,
      callsSig
    );
  }

  /// CALLS-04 — a malformed approval signature is rejected by ECDSA rather than ignored
  function test_CALLS_04_malformedSignature() public {
    _delegateKeyThroughHub(key);

    GenericCall[] memory calls = _calls(_routerCall(0, hex'01'));

    vm.prank(owner);
    vm.expectRevert(abi.encodeWithSelector(ECDSA.ECDSAInvalidSignatureLength.selector, 2));
    hub.transferAndFulfill(
      owner,
      new ERC20Transfer[](0),
      new ERC721Transfer[](0),
      new ValidationParams[](0),
      block.timestamp,
      _flags(false, false, false),
      '',
      calls,
      1,
      hex'1234'
    );
  }

  // -------------------------------------------------------------------------------------------
  // VAL — the validator hooks
  // -------------------------------------------------------------------------------------------

  /**
   * VAL-01 / VAL-02 — the hooks bracket the whole order, and each snapshot returns to its owner
   * @dev The spy reads the router's balance inside each hook, which is what actually orders the
   * hooks against the transfer and the router call: `beforeExecution` must see the pre-pull
   * balance and `afterExecution` the balance after both the pull and the router leg.
   */
  function test_VAL_01_hookOrderingAndSnapshotPairing() public {
    validator.setSnapshot(hex'aaaa');
    validator2.setSnapshot(hex'bbbb');
    validator.observe(WETH, address(router));

    uint160 amount = 4 ether;
    uint256 payout = 1 ether;
    uint256 routerBefore = IERC20(WETH).balanceOf(address(router));

    // the router pays part of it away while it runs, so the balance changes DURING the call leg.
    // Without this the after-hook would read the same value whether it ran before or after the
    // router, and the ordering assertion below would be vacuous.
    router.setPayout(WETH, recipient, payout);

    ValidationParams[] memory vs = new ValidationParams[](2);
    vs[0] = _validation(validator);
    vs[1] = _validation(validator2);

    GenericCall[] memory calls = _calls(_routerCall(0, hex'01'));

    vm.prank(owner);
    hub.transferAndFulfill(
      owner,
      _erc20s(_wethTransfer(amount)),
      new ERC721Transfer[](0),
      vs,
      block.timestamp,
      _flags(false, false, false),
      '',
      calls,
      0,
      ''
    );

    assertEq(validator.sequenceLength(), 2, 'both hooks ran');
    assertEq(validator.sequence(0), 'before');
    assertEq(validator.sequence(1), 'after');

    // ordering, established by what each hook could see rather than by call order alone
    assertEq(validator.balanceAtBefore(), routerBefore, 'beforeExecution ran before the pull');
    assertEq(
      validator.balanceAtAfter(),
      routerBefore + amount - payout,
      'afterExecution ran after the router leg, not merely after the pull'
    );

    // each validator's afterExecution received the snapshot its own beforeExecution returned
    assertEq(validator.afterBeforeOutput(), hex'aaaa', 'validator 1 snapshot');
    assertEq(validator2.afterBeforeOutput(), hex'bbbb', 'validator 2 snapshot');

    assertEq(router.callCount(), 1);
  }

  /// VAL-03 — a validator that rejects the outcome reverts the whole order
  function test_VAL_03_revertingAfterExecutionUnwinds() public {
    validator.setReverts(false, true);

    ValidationParams[] memory vs = _validations(_validation(validator));
    GenericCall[] memory calls = _calls(_routerCall(0, hex'01'));

    vm.prank(owner);
    vm.expectRevert(bytes('after'));
    hub.transferAndFulfill(
      owner,
      new ERC20Transfer[](0),
      new ERC721Transfer[](0),
      vs,
      block.timestamp,
      _flags(false, false, false),
      '',
      calls,
      0,
      ''
    );

    assertEq(router.callCount(), 0, 'router call rolled back');
  }

  /// VAL-04 — no validators is a legal order
  function test_VAL_04_noValidators() public {
    GenericCall[] memory calls = _calls(_routerCall(0, hex'01'));

    vm.prank(owner);
    hub.transferAndFulfill(
      owner,
      new ERC20Transfer[](0),
      new ERC721Transfer[](0),
      new ValidationParams[](0),
      block.timestamp,
      _flags(false, false, false),
      '',
      calls,
      0,
      ''
    );

    assertEq(router.callCount(), 1);
  }

  // -------------------------------------------------------------------------------------------

  function _fulfillAsOwner(
    GenericCall[] memory calls,
    uint256 callsNonce,
    bytes memory callsSig,
    uint256 deadline
  ) private {
    vm.prank(owner);
    hub.transferAndFulfill(
      owner,
      new ERC20Transfer[](0),
      new ERC721Transfer[](0),
      new ValidationParams[](0),
      deadline,
      _flags(false, false, false),
      '',
      calls,
      callsNonce,
      callsSig
    );
  }
}
