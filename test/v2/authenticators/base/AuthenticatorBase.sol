// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {HubBase} from 'test/v2/base/HubBase.sol';

import {SessionOrderAuthenticator} from 'src/v2/authenticators/SessionOrderAuthenticator.sol';
import {KeyType} from 'src/v2/authenticators/types/KeyType.sol';
import {SessionKey} from 'src/v2/authenticators/types/SessionKey.sol';
import {ExecutionOrder} from 'src/v2/types/ExecutionOrder.sol';
import {FulfillmentOrder} from 'src/v2/types/FulfillmentOrder.sol';

/**
 * @title AuthenticatorBase
 * @notice Contract base for the {SessionOrderAuthenticator} batches and for every hub batch that
 * reaches the hub over the delegated-authentication rail: deploys the authenticator against the
 * hub and builds session keys, their approvals and the order signatures they carry.
 * @dev As in {HubBase}, every digest is assembled from the literals in {V2TestBase}.
 */
abstract contract AuthenticatorBase is HubBase {
  SessionOrderAuthenticator internal authenticator;

  address internal sessionSigner;
  uint256 internal sessionKeyPk;

  function setUp() public virtual override {
    super.setUp();

    authenticator = new SessionOrderAuthenticator(address(hub));
    vm.label(address(authenticator), 'authenticator');

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

  /// @dev The key alone: the payload `initAuthentication` reads
  function _encodeKey(SessionKey memory key) internal pure returns (bytes memory) {
    return abi.encode(key);
  }

  /// @dev The `data` argument of `updateAuthentication`: the key, plus the direction for it
  function _updateData(SessionKey memory key, bool approved) internal pure returns (bytes memory) {
    return abi.encode(key, approved);
  }

  /// @dev `updateAuthentication` payload that approves `key`
  function _approveKey(SessionKey memory key) internal pure returns (bytes memory) {
    return _updateData(key, true);
  }

  /// @dev `updateAuthentication` payload that revokes `key`
  function _revokeKey(SessionKey memory key) internal pure returns (bytes memory) {
    return _updateData(key, false);
  }

  function _authenticatorDomain() internal view returns (bytes32) {
    return
      lDomainSeparator('KyberSwap Session Order Authenticator', '1.0.0', address(authenticator));
  }

  /// @dev Approves a key through the hub, which reaches the authenticator as `initAuthentication`
  function _delegateKeyThroughHub(SessionKey memory key) internal {
    vm.prank(owner);
    hub.updateDelegation(
      owner, address(authenticator), true, _encodeKey(key), 0, block.timestamp + 1 days, ''
    );
  }

  function _signSessionApproval(
    SessionKey memory key,
    bool approved,
    uint256 nonce,
    uint256 deadline
  ) internal returns (bytes memory) {
    bytes32 digest = lTypedDataHash(
      _authenticatorDomain(), lSessionApproval(_keyHash(key), approved, nonce, deadline)
    );
    return _sign(ownerKey, digest);
  }

  // ---------------------------------------------------------------------------------------------
  // Authentication data
  // ---------------------------------------------------------------------------------------------

  /**
   * @dev The `authenticationData` the authenticator reads: word 0 points at the key, word 1 at the
   * signature. The hub passes these bytes through untouched.
   */
  function _authData(SessionKey memory key, bytes memory signature)
    internal
    pure
    returns (bytes memory)
  {
    return abi.encode(key, signature);
  }

  /// @dev The digest a session key signs for an execution: the order, under the authenticator domain
  function _executionDigest(ExecutionOrder memory order) internal view returns (bytes32) {
    return lTypedDataHash(_authenticatorDomain(), lExecutionOrderHash(order));
  }

  function _fulfillmentDigest(FulfillmentOrder memory order) internal view returns (bytes32) {
    return lTypedDataHash(_authenticatorDomain(), lFulfillmentOrderHash(order));
  }

  /// @dev `authenticationData` whose signature is `signerKey`'s over `order`
  function _executionAuthData(ExecutionOrder memory order, SessionKey memory key, uint256 signerKey)
    internal
    returns (bytes memory)
  {
    return _authData(key, _sign(signerKey, _executionDigest(order)));
  }

  function _fulfillmentAuthData(
    FulfillmentOrder memory order,
    SessionKey memory key,
    uint256 signerKey
  ) internal returns (bytes memory) {
    return _authData(key, _sign(signerKey, _fulfillmentDigest(order)));
  }
}
