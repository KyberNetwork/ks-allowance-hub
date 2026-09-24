// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {VerifierBase} from 'test/verifiers/base/VerifierBase.sol';

import {ERC1271WalletMock} from 'test/v2/mocks/TokenMocks.sol';

import {DeadlineChecker} from 'src/base/DeadlineChecker.sol';
import {IAuthDelegator} from 'src/base/interfaces/IAuthDelegator.sol';
import {IUnorderedNonce} from 'src/base/interfaces/IUnorderedNonce.sol';
import {ERC20Transfer} from 'src/v2/types/ERC20Transfer.sol';
import {ERC721Transfer} from 'src/v2/types/ERC721Transfer.sol';
import {GenericCall} from 'src/v2/types/GenericCall.sol';
import {ValidationParams} from 'src/v2/types/ValidationParams.sol';

import {IERC20} from 'openzeppelin-contracts/contracts/token/ERC20/IERC20.sol';
import {SessionKey} from 'src/verifiers/types/SessionKey.sol';

import {ECDSA} from 'openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol';

/// @notice DEL-*, UPD-*, NONCE-*, CALLS-* and VAL-* — delegation, nonces, calls approval, validators.
contract DelegationTest is VerifierBase {
  /// @dev One struct per entry-point domain, per the frozen plan's fuzz contract
  struct DelegationFuzz {
    uint256 nonce;
    uint256 deadlineOffset;
    bool selfSubmit;
  }

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
    hub.delegateAuth(owner, address(verifier), _encodeKey(key), 0, block.timestamp + 1 days, '');

    assertTrue(hub.authDelegated(owner, address(verifier)), 'delegated');
    assertTrue(verifier.approvedKeys(owner, _keyHash(key)), 'key approved without a signature');
    assertEq(hub.nonces(owner, word), 0, 'no hub nonce consumed');
  }

  /// DEL-02 — a third party may submit the delegation when it carries the owner's signature
  function test_DEL_02_relayedDelegationConsumesNonce() public {
    uint256 nonce = 5;
    uint256 deadline = block.timestamp + 1 days;
    bytes memory sig =
      _signAuthDelegation(ownerKey, address(verifier), _encodeKey(key), nonce, deadline);

    vm.prank(relayer);
    hub.delegateAuth(owner, address(verifier), _encodeKey(key), nonce, deadline, sig);

    assertTrue(hub.authDelegated(owner, address(verifier)));
    assertEq(hub.nonces(owner, nonce >> 8), 1 << (nonce & 0xff), 'exact bit set');

    // NONCE-02 — the same nonce cannot be spent twice
    vm.prank(relayer);
    vm.expectRevert(IUnorderedNonce.NonceAlreadyUsed.selector);
    hub.delegateAuth(owner, address(verifier), _encodeKey(key), nonce, deadline, sig);
  }

  /// DEL-03 — changing any signed field invalidates the delegation
  function test_DEL_03_tamperedDelegationRejected() public {
    uint256 deadline = block.timestamp + 1 days;
    bytes memory sig =
      _signAuthDelegation(ownerKey, address(verifier), _encodeKey(key), 1, deadline);

    SessionKey memory otherKey = _secpKey(relayer, block.timestamp + 30 days);

    vm.prank(relayer);
    vm.expectRevert(IAuthDelegator.InvalidDelegationSignature.selector);
    hub.delegateAuth(owner, address(verifier), _encodeKey(otherKey), 1, deadline, sig);
  }

  /// DEL-04 — a contract owner authorises through ERC-1271
  function test_DEL_04_erc1271Owner() public {
    (address walletSigner, uint256 walletSignerKey) = makeAddrAndKey('wallet signer');
    _asEoa(walletSigner);
    ERC1271WalletMock wallet = new ERC1271WalletMock(walletSigner);

    uint256 deadline = block.timestamp + 1 days;
    bytes memory sig =
      _signAuthDelegation(walletSignerKey, address(verifier), _encodeKey(key), 2, deadline);

    vm.prank(relayer);
    hub.delegateAuth(address(wallet), address(verifier), _encodeKey(key), 2, deadline, sig);
    assertTrue(hub.authDelegated(address(wallet), address(verifier)));

    // and a wallet that returns the wrong magic value is rejected
    wallet.setReturnWrongMagic(true);
    bytes memory sig2 =
      _signAuthDelegation(walletSignerKey, address(verifier), _encodeKey(key), 3, deadline);

    vm.prank(relayer);
    vm.expectRevert(IAuthDelegator.InvalidDelegationSignature.selector);
    hub.delegateAuth(address(wallet), address(verifier), _encodeKey(key), 3, deadline, sig2);
  }

  /// DEL-05 — the delegation deadline is enforced
  function test_DEL_05_expiredDelegation() public {
    uint256 deadline = block.timestamp - 1;
    bytes memory sig =
      _signAuthDelegation(ownerKey, address(verifier), _encodeKey(key), 4, deadline);

    vm.prank(relayer);
    vm.expectRevert(DeadlineChecker.DeadlinePassed.selector);
    hub.delegateAuth(owner, address(verifier), _encodeKey(key), 4, deadline, sig);
  }

  /// DEL-06 — revoking stops the hub accepting that verifier, while the key stays approved
  function test_DEL_06_revokeDelegation() public {
    _delegateKeyThroughHub(key);
    assertTrue(hub.authDelegated(owner, address(verifier)));

    vm.prank(owner);
    hub.revokeDelegation(address(verifier));
    assertFalse(hub.authDelegated(owner, address(verifier)));

    // the verifier still holds the approval, which is why re-delegating re-arms it (BUG-04,
    // pinned rather than endorsed — revocation is planned but not yet implemented)
    assertTrue(verifier.approvedKeys(owner, _keyHash(key)));
  }

  /// DEL-FUZZ — the delegation nonce bitmap behaves across its whole domain
  function testFuzz_DEL_FUZZ_relayedDelegation(DelegationFuzz memory f) public {
    uint256 nonce = f.nonce;
    uint256 deadline = block.timestamp + bound(f.deadlineOffset, 0, 30 days);

    bytes memory sig =
      _signAuthDelegation(ownerKey, address(verifier), _encodeKey(key), nonce, deadline);

    vm.prank(relayer);
    hub.delegateAuth(owner, address(verifier), _encodeKey(key), nonce, deadline, sig);

    assertTrue(hub.authDelegated(owner, address(verifier)));
    assertEq(hub.nonces(owner, nonce >> 8), 1 << (nonce & 0xff), 'exact bit for this nonce');
  }

  // -------------------------------------------------------------------------------------------
  // UPD — replacing material at an already delegated verifier
  // -------------------------------------------------------------------------------------------

  /// UPD-02 — nothing can be updated before a delegation exists
  function test_UPD_02_requiresDelegation() public {
    vm.prank(owner);
    vm.expectRevert(IAuthDelegator.NotDelegatedVerifier.selector);
    hub.updateAuth(owner, address(verifier), _encodeKey(key), 0, block.timestamp, '');
  }

  /// UPD-03 — a third party cannot update with an empty signature
  function test_UPD_03_relayedEmptySignatureRejected() public {
    _delegateKeyThroughHub(key);

    vm.prank(relayer);
    vm.expectRevert(IAuthDelegator.InvalidDelegationSignature.selector);
    hub.updateAuth(owner, address(verifier), _encodeKey(key), 1, block.timestamp, '');
  }

  /// UPD-01 — the owner updates with no signature, because the hub has authenticated them
  function test_UPD_01_ownerUpdateIsTrusted() public {
    _delegateKeyThroughHub(key);

    SessionKey memory newKey = _secpKey(relayer, block.timestamp + 10 days);

    vm.prank(owner);
    hub.updateAuth(owner, address(verifier), _encodeKey(newKey), 0, block.timestamp, '');

    assertTrue(verifier.approvedKeys(owner, _keyHash(newKey)), 'new key approved');
  }

  /// UPD-04 / UPD-05 — a signature routes to the verifier's own check, whoever submits
  function test_UPD_04_signedUpdateFromRelayerAndOwner() public {
    _delegateKeyThroughHub(key);

    SessionKey memory newKey = _secpKey(recipient, block.timestamp + 10 days);
    uint256 deadline = block.timestamp + 1 days;

    bytes memory sig = _signSessionApproval(newKey, 11, deadline);

    vm.prank(relayer);
    hub.updateAuth(owner, address(verifier), _encodeKey(newKey), 11, deadline, sig);
    assertTrue(verifier.approvedKeys(owner, _keyHash(newKey)), 'relayed signed update');

    // UPD-05 — the owner supplying a signature takes the same verifier branch
    SessionKey memory thirdKey = _secpKey(guardian, block.timestamp + 10 days);
    bytes memory sig2 = _signSessionApproval(thirdKey, 12, deadline);

    vm.prank(owner);
    hub.updateAuth(owner, address(verifier), _encodeKey(thirdKey), 12, deadline, sig2);
    assertTrue(verifier.approvedKeys(owner, _keyHash(thirdKey)), 'owner signed update');
    assertEq(verifier.nonces(owner, 0), (1 << 11) | (1 << 12), 'both verifier nonces spent');
  }

  /// UPD-FUZZ — a signed update is accepted from any submitter across the nonce/deadline domain
  function testFuzz_UPD_FUZZ_signedUpdate(DelegationFuzz memory f) public {
    _delegateKeyThroughHub(key);
    uint256 nonce = f.nonce;
    uint256 deadline = block.timestamp + bound(f.deadlineOffset, 0, 30 days);

    SessionKey memory fresh = _secpKey(recipient, block.timestamp + 10 days);
    bytes memory sig = _signSessionApproval(fresh, nonce, deadline);

    vm.prank(f.selfSubmit ? owner : relayer);
    hub.updateAuth(owner, address(verifier), _encodeKey(fresh), nonce, deadline, sig);

    assertTrue(verifier.approvedKeys(owner, _keyHash(fresh)), 'key approved');
    assertEq(verifier.nonces(owner, nonce >> 8), 1 << (nonce & 0xff), 'verifier nonce spent');
    assertEq(hub.nonces(owner, nonce >> 8), 0, 'hub nonce untouched by updateAuth');
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
