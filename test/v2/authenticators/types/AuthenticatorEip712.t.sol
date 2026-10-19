// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {V2TestBase} from 'test/base/V2TestBase.sol';

import {AuthKey} from 'src/v2/authenticators/types/AuthKey.sol';
import {KeyType} from 'src/v2/authenticators/types/KeyType.sol';
import {MasterKeyApprovalLib} from 'src/v2/authenticators/types/MasterKeyApproval.sol';
import {NonceRevocationLib} from 'src/v2/authenticators/types/NonceRevocation.sol';
import {SessionKeyApprovalLib} from 'src/v2/authenticators/types/SessionKeyApproval.sol';

/**
 * @notice T712-09..12 — the four authenticator-side EIP-712 types.
 * @dev The production hashers are the values under test; every expected value is built from the
 * schemas `forge bind-json` derived from the struct definitions. These rows pin the struct
 * encoding; `SchemaAudit.t.sol` pins the typehashes themselves. No contract is under test here, so
 * this batch inherits the global base directly.
 */
contract AuthenticatorEip712Test is V2TestBase {
  // -------------------------------------------------------------------------------------------
  // T712-09 — AuthKey
  // -------------------------------------------------------------------------------------------

  function test_T712_09_authKeyStructHash() public view {
    AuthKey memory key = _sampleKey();

    bytes32 expected = lAuthKeyHash(key.publicKey, uint8(key.keyType), key.expiration);
    assertEq(this.extHashAuthKey(key), expected, 'calldata hasher');
    assertEq(key.hashMemory(), expected, 'memory hasher');
  }

  // -------------------------------------------------------------------------------------------
  // T712-10 — MasterKeyApproval
  // -------------------------------------------------------------------------------------------

  function test_T712_10_masterKeyApprovalStructHash() public pure {
    AuthKey memory key = _sampleKey();
    bytes32 keyHash = key.hashMemory();

    assertEq(
      MasterKeyApprovalLib.hash(keyHash, true, 7, 99),
      lMasterKeyApproval(key, true, 7, 99),
      'approval struct hash'
    );
    assertEq(
      MasterKeyApprovalLib.hash(keyHash, false, 7, 99),
      lMasterKeyApproval(key, false, 7, 99),
      'revocation struct hash'
    );
    assertTrue(
      MasterKeyApprovalLib.hash(keyHash, true, 7, 99)
        != MasterKeyApprovalLib.hash(keyHash, false, 7, 99),
      'the direction changes the digest'
    );
  }

  // -------------------------------------------------------------------------------------------
  // T712-11 — SessionKeyApproval
  // -------------------------------------------------------------------------------------------

  /// @dev The two keys and the account are all distinct members, so each must move the digest
  function test_T712_11_sessionKeyApprovalStructHash() public pure {
    AuthKey memory masterKey = _sampleKey();
    AuthKey memory sessionKey = _otherKey();
    bytes32 masterKeyHash = masterKey.hashMemory();
    bytes32 sessionKeyHash = sessionKey.hashMemory();
    address keyOwner = address(uint160(uint256(keccak256('an arbitrary owner'))));
    address otherOwner = address(uint160(uint256(keccak256('a different owner'))));

    assertEq(
      SessionKeyApprovalLib.hash(keyOwner, masterKeyHash, sessionKeyHash, true, 7, 99),
      lSessionKeyApproval(keyOwner, masterKey, sessionKey, true, 7, 99),
      'approval struct hash'
    );
    assertEq(
      SessionKeyApprovalLib.hash(keyOwner, masterKeyHash, sessionKeyHash, false, 7, 99),
      lSessionKeyApproval(keyOwner, masterKey, sessionKey, false, 7, 99),
      'revocation struct hash'
    );
    assertTrue(
      SessionKeyApprovalLib.hash(keyOwner, masterKeyHash, sessionKeyHash, true, 7, 99)
        != SessionKeyApprovalLib.hash(keyOwner, masterKeyHash, sessionKeyHash, false, 7, 99),
      'the direction changes the digest'
    );
    assertTrue(
      SessionKeyApprovalLib.hash(keyOwner, masterKeyHash, sessionKeyHash, true, 7, 99)
        != SessionKeyApprovalLib.hash(otherOwner, masterKeyHash, sessionKeyHash, true, 7, 99),
      'the account changes the digest'
    );
    assertTrue(
      SessionKeyApprovalLib.hash(keyOwner, masterKeyHash, sessionKeyHash, true, 7, 99)
        != SessionKeyApprovalLib.hash(keyOwner, sessionKeyHash, masterKeyHash, true, 7, 99),
      'the two keys are not interchangeable'
    );
  }

  // -------------------------------------------------------------------------------------------
  // T712-12 — NonceRevocation
  // -------------------------------------------------------------------------------------------

  function test_T712_12_nonceRevocationStructHash() public pure {
    AuthKey memory key = _sampleKey();
    bytes32 revocation = NonceRevocationLib.hashMemory(key, 7, 99);

    assertEq(revocation, lNonceRevocation(key, 7, 99), 'struct hash');
    assertTrue(
      revocation != NonceRevocationLib.hashMemory(_otherKey(), 7, 99), 'the key changes the digest'
    );
    assertTrue(
      revocation != NonceRevocationLib.hashMemory(key, 8, 99), 'the nonce changes the digest'
    );
    assertTrue(
      revocation != NonceRevocationLib.hashMemory(key, 7, 100), 'the deadline changes the digest'
    );
  }

  // -------------------------------------------------------------------------------------------

  /// @dev An external wrapper so the calldata hasher is reachable from a memory-built fixture
  function extHashAuthKey(AuthKey calldata key) external pure returns (bytes32) {
    return key.hash();
  }

  function _otherKey() private pure returns (AuthKey memory) {
    return AuthKey({
      publicKey: hex'0000000000000000000000000000000000000000000000000000000000000001',
      keyType: KeyType.Secp256k1,
      expiration: 1_800_000_000
    });
  }

  function _sampleKey() private pure returns (AuthKey memory) {
    return AuthKey({
      publicKey: hex'c0ffee00c0ffee11', keyType: KeyType.WebAuthn, expiration: 1_700_000_000
    });
  }
}
