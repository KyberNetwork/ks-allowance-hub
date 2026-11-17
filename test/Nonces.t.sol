// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {SignerAuthenticatorBase} from 'test/base/SignerAuthenticatorBase.sol';

import {IUnorderedNonce} from 'src/interfaces/base/IUnorderedNonce.sol';

/**
 * @title NoncesTest
 * @notice NONCE-01..05 and NONCE-FUZZ — the unordered bitmap
 * @dev A nonce is a word index in its top bits and a bit position in its low byte, spent in any
 * order. The boundary cases pin the split between word and bit.
 */
contract NoncesTest is SignerAuthenticatorBase {
  // -------------------------------------------------------------------------------------------
  // NONCE — the unordered bitmap
  // -------------------------------------------------------------------------------------------

  /// NONCE-01 / NONCE-FUZZ — revoking any nonce sets exactly the bit at its position
  function testFuzz_NONCE_FUZZ_revokeSetsExactlyOneBit(uint256 nonce) public {
    vm.expectEmit(address(hub));
    emit IUnorderedNonce.RevokeNonce(lNonceKey(owner), nonce);
    vm.prank(owner);
    hub.revokeNonce(nonce);

    assertEq(hub.nonces(lNonceKey(owner), nonce >> 8), 1 << (nonce & 0xff), 'exact bit');
    // a neighbouring word is untouched
    assertEq(hub.nonces(lNonceKey(owner), (nonce >> 8) + 1), 0, 'neighbouring word clean');
  }

  /// NONCE-01 — revoking nonces 0, 255, 256 and the maximum sets one bit each in the right word
  function test_NONCE_01_bitmapBoundaries() public {
    uint256[4] memory nonces = [uint256(0), 255, 256, type(uint256).max];

    for (uint256 i = 0; i < nonces.length; i++) {
      vm.prank(owner);
      hub.revokeNonce(nonces[i]);

      // nonces 0 and 255 share word 0, so assert the bit rather than the whole word
      uint256 bit = 1 << (nonces[i] & 0xff);
      assertEq(hub.nonces(lNonceKey(owner), nonces[i] >> 8) & bit, bit, 'boundary bit set');
    }

    // 0 and 256 share a bit position but live in different words
    assertEq(hub.nonces(lNonceKey(owner), 0), (1 << 0) | (1 << 255), 'word 0 holds 0 and 255');
    assertEq(hub.nonces(lNonceKey(owner), 1), 1 << 0, 'word 1 holds 256');
  }

  /// NONCE-04 — revoking twice reverts
  function test_NONCE_04_doubleRevoke() public {
    vm.startPrank(owner);
    hub.revokeNonce(9);
    vm.expectRevert(
      abi.encodeWithSelector(IUnorderedNonce.NonceAlreadyUsed.selector, lNonceKey(owner), 9)
    );
    hub.revokeNonce(9);
    vm.stopPrank();
  }

  /// NONCE-05 — the hub and the authenticator keep separate bitmaps
  function test_NONCE_05_hubAndAuthenticatorAreIndependent() public {
    vm.expectEmit(address(hub));
    emit IUnorderedNonce.RevokeNonce(lNonceKey(owner), 3);
    vm.prank(owner);
    hub.revokeNonce(3);

    vm.expectEmit(address(authenticator));
    emit IUnorderedNonce.RevokeNonce(lNonceKey(owner), 3);
    vm.prank(owner);
    authenticator.revokeNonce(3);

    assertEq(hub.nonces(lNonceKey(owner), 0), 1 << 3);
    assertEq(authenticator.nonces(lNonceKey(owner), 0), 1 << 3);

    // spending it on one side does not spend it on the other
    vm.prank(owner);
    vm.expectRevert(
      abi.encodeWithSelector(IUnorderedNonce.NonceAlreadyUsed.selector, lNonceKey(owner), 3)
    );
    hub.revokeNonce(3);
  }
}
