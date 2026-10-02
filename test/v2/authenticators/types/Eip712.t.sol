// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {V2TestBase} from 'test/base/V2TestBase.sol';

import {KeyType} from 'src/v2/authenticators/types/KeyType.sol';
import {SessionApprovalLib} from 'src/v2/authenticators/types/SessionApproval.sol';
import {SessionKey, SessionKeyLib} from 'src/v2/authenticators/types/SessionKey.sol';

/**
 * @notice T712-09..10 — the two authenticator-side EIP-712 types.
 * @dev The production constants are the values under test; every expected value is built from the
 * literals in {V2TestBase}, which were transcribed from the struct definitions. Together with
 * `test/v2/types/Eip712.t.sol` this is the only place a production type string or typehash may be
 * read, and there it is never the expected side.
 *
 * Each row also pins the struct encoding, not only the typehash. No contract is under test here, so
 * this batch inherits the global base directly.
 */
contract AuthenticatorEip712Test is V2TestBase {
  // -------------------------------------------------------------------------------------------
  // T712-09 — SessionKey
  // -------------------------------------------------------------------------------------------

  function test_T712_09_sessionKeyTypehashAndStructHash() public view {
    assertEq(SessionKeyLib.SESSION_KEY_TYPEHASH, lSessionKeyTypehash(), 'typehash');

    SessionKey memory key = _sampleKey();

    assertEq(
      this.extHashSessionKey(key),
      lSessionKeyHash(key.publicKey, uint8(key.keyType), key.expiration),
      'struct hash'
    );
  }

  // -------------------------------------------------------------------------------------------
  // T712-10 — SessionApproval
  // -------------------------------------------------------------------------------------------

  function test_T712_10_sessionApprovalTypehashAndStructHash() public pure {
    assertEq(SessionApprovalLib.SESSION_APPROVAL_TYPEHASH, lSessionApprovalTypehash(), 'typehash');

    bytes32 keyHash = keccak256('an arbitrary key hash');

    assertEq(
      SessionApprovalLib.hash(keyHash, true, 7, 99),
      lSessionApproval(keyHash, true, 7, 99),
      'approval struct hash'
    );
    assertEq(
      SessionApprovalLib.hash(keyHash, false, 7, 99),
      lSessionApproval(keyHash, false, 7, 99),
      'revocation struct hash'
    );
    assertTrue(
      SessionApprovalLib.hash(keyHash, true, 7, 99)
        != SessionApprovalLib.hash(keyHash, false, 7, 99),
      'the direction changes the digest'
    );
  }

  // -------------------------------------------------------------------------------------------

  /// @dev An external wrapper so the calldata hasher is reachable from a memory-built fixture
  function extHashSessionKey(SessionKey calldata key) external pure returns (bytes32) {
    return key.hash();
  }

  function _sampleKey() private pure returns (SessionKey memory) {
    return SessionKey({
      publicKey: hex'c0ffee00c0ffee11', keyType: KeyType.WebAuthn, expiration: 1_700_000_000
    });
  }
}
