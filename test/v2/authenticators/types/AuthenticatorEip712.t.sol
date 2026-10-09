// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {V2TestBase} from 'test/base/V2TestBase.sol';

import {AuthKey} from 'src/v2/authenticators/types/AuthKey.sol';
import {KeyType} from 'src/v2/authenticators/types/KeyType.sol';
import {MasterKeyApprovalLib} from 'src/v2/authenticators/types/MasterKeyApproval.sol';
import {SessionKeyApprovalLib} from 'src/v2/authenticators/types/SessionKeyApproval.sol';

/**
 * @notice T712-09..11 — the three authenticator-side EIP-712 types.
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

    assertEq(
      this.extHashAuthKey(key),
      lAuthKeyHash(key.publicKey, uint8(key.keyType), key.expiration),
      'struct hash'
    );
  }

  // -------------------------------------------------------------------------------------------
  // T712-10 — MasterKeyApproval
  // -------------------------------------------------------------------------------------------

  function test_T712_10_masterKeyApprovalStructHash() public pure {
    bytes32 keyHash = keccak256('an arbitrary key hash');

    assertEq(
      MasterKeyApprovalLib.hash(keyHash, true, 7, 99),
      lMasterKeyApproval(keyHash, true, 7, 99),
      'approval struct hash'
    );
    assertEq(
      MasterKeyApprovalLib.hash(keyHash, false, 7, 99),
      lMasterKeyApproval(keyHash, false, 7, 99),
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
    bytes32 masterKeyHash = keccak256('an arbitrary master key hash');
    bytes32 sessionKeyHash = keccak256('an arbitrary session key hash');
    address keyOwner = address(uint160(uint256(keccak256('an arbitrary owner'))));
    address otherOwner = address(uint160(uint256(keccak256('a different owner'))));

    assertEq(
      SessionKeyApprovalLib.hash(keyOwner, masterKeyHash, sessionKeyHash, true, 7, 99),
      lSessionKeyApproval(keyOwner, masterKeyHash, sessionKeyHash, true, 7, 99),
      'approval struct hash'
    );
    assertEq(
      SessionKeyApprovalLib.hash(keyOwner, masterKeyHash, sessionKeyHash, false, 7, 99),
      lSessionKeyApproval(keyOwner, masterKeyHash, sessionKeyHash, false, 7, 99),
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

  /// @dev An external wrapper so the calldata hasher is reachable from a memory-built fixture
  function extHashAuthKey(AuthKey calldata key) external pure returns (bytes32) {
    return key.hash();
  }

  function _sampleKey() private pure returns (AuthKey memory) {
    return AuthKey({
      publicKey: hex'c0ffee00c0ffee11', keyType: KeyType.WebAuthn, expiration: 1_700_000_000
    });
  }
}
