// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {HubBase} from 'test/v2/base/HubBase.sol';

import {SessionAuthVerifier} from 'src/verifiers/SessionAuthVerifier.sol';
import {KeyType} from 'src/verifiers/types/KeyType.sol';
import {SessionKey} from 'src/verifiers/types/SessionKey.sol';

/**
 * @title VerifierBase
 * @notice Contract base for the {SessionAuthVerifier} batches: deploys the verifier against the
 * hub and builds session keys and their approvals.
 * @dev As in {HubBase}, every digest is assembled from the literals in {V2TestBase}.
 */
abstract contract VerifierBase is HubBase {
  SessionAuthVerifier internal verifier;

  address internal sessionSigner;
  uint256 internal sessionKeyPk;

  function setUp() public virtual override {
    super.setUp();

    verifier = new SessionAuthVerifier(address(hub));
    vm.label(address(verifier), 'verifier');

    (sessionSigner, sessionKeyPk) = makeAddrAndKey('session signer');
    _asEoa(sessionSigner);
  }

  // ---------------------------------------------------------------------------------------------
  // Session keys
  // ---------------------------------------------------------------------------------------------

  /// @dev A Secp256k1 key is an ABI-encoded address, so the whole word is the public key
  function _secpKey(address signer, uint256 expiration) internal pure returns (SessionKey memory) {
    return
      SessionKey({
        publicKey: abi.encode(signer), keyType: KeyType.Secp256k1, expiration: expiration
      });
  }

  function _keyHash(SessionKey memory key) internal pure returns (bytes32) {
    return lSessionKeyHash(key.publicKey, uint8(key.keyType), key.expiration);
  }

  /// @dev The `key` argument of `verifyAuth`, which names a credential and carries no direction
  function _encodeKey(SessionKey memory key) internal pure returns (bytes memory) {
    return abi.encode(key);
  }

  /// @dev The `data` argument of `updateAuth`: the key, plus the direction to apply to it
  function _updateData(SessionKey memory key, bool approved) internal pure returns (bytes memory) {
    return abi.encode(key, approved);
  }

  /// @dev `updateAuth` payload that approves `key`
  function _approveKey(SessionKey memory key) internal pure returns (bytes memory) {
    return _updateData(key, true);
  }

  /// @dev `updateAuth` payload that revokes `key`
  function _revokeKey(SessionKey memory key) internal pure returns (bytes memory) {
    return _updateData(key, false);
  }

  function _verifierDomain() internal view returns (bytes32) {
    return lDomainSeparator('KyberSwap Session Auth Verifier', '1.0.0', address(verifier));
  }

  /// @dev Approves a key through the hub, which is the route that carries no signature
  function _delegateKeyThroughHub(SessionKey memory key) internal {
    vm.prank(owner);
    hub.updateDelegation(
      owner, address(verifier), true, _approveKey(key), 0, block.timestamp + 1 days, ''
    );
  }

  function _signSessionApproval(
    SessionKey memory key,
    bool approved,
    uint256 nonce,
    uint256 deadline
  ) internal returns (bytes memory) {
    bytes32 digest = lTypedDataHash(
      _verifierDomain(), lSessionApproval(_keyHash(key), approved, nonce, deadline)
    );
    return _sign(ownerKey, digest);
  }
}
