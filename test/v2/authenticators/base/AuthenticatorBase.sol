// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {SchemaHash} from 'test/base/SchemaHash.sol';

import {HubBase} from 'test/v2/base/HubBase.sol';

import {AuthKey} from 'src/base/types/AuthKey.sol';
import {KeyType} from 'src/base/types/KeyType.sol';
import {TwoTiersOrderAuthenticator} from 'src/v2/authenticators/TwoTiersOrderAuthenticator.sol';
import {ExecutionOrder} from 'src/v2/types/ExecutionOrder.sol';
import {FulfillmentOrder} from 'src/v2/types/FulfillmentOrder.sol';

/**
 * @title AuthenticatorBase
 * @notice Contract base for the {TwoTiersOrderAuthenticator} batches and for every hub batch that
 * reaches the hub over the delegated-authentication rail: deploys the authenticator against the
 * hub and builds both tiers of key, their approvals and the order signatures they carry.
 * @dev As in {HubBase}, every digest is assembled from the literals in {V2TestBase}.
 */
abstract contract AuthenticatorBase is HubBase {
  TwoTiersOrderAuthenticator internal authenticator;

  address internal masterSigner;
  uint256 internal masterKeyPk;

  address internal sessionSigner;
  uint256 internal sessionKeyPk;

  function setUp() public virtual override {
    super.setUp();

    authenticator = new TwoTiersOrderAuthenticator(address(hub));
    vm.label(address(authenticator), 'authenticator');

    (masterSigner, masterKeyPk) = makeAddrAndKey('master signer');

    (sessionSigner, sessionKeyPk) = makeAddrAndKey('session signer');
  }

  // ---------------------------------------------------------------------------------------------
  // Keys
  // ---------------------------------------------------------------------------------------------

  /// @dev A Secp256k1 key is an ABI-encoded address, so the whole word is the public key
  function _secpKey(address signer, uint256 expiration) internal pure returns (AuthKey memory) {
    return
      AuthKey({publicKey: abi.encode(signer), keyType: KeyType.Secp256k1, expiration: expiration});
  }

  function _keyHash(AuthKey memory key) internal pure returns (bytes32) {
    return lAuthKeyHash(key.publicKey, uint8(key.keyType), key.expiration);
  }

  /// @dev The namespace a key's nonces are spent in: its scheme and public half, without expiry
  function _credentialHash(AuthKey memory key) internal pure returns (bytes32) {
    return keccak256(abi.encodePacked(uint8(key.keyType), key.publicKey));
  }

  /// @dev The key alone: the payload `initAuthentication` reads
  function _encodeKey(AuthKey memory key) internal pure returns (bytes memory) {
    return abi.encode(key);
  }

  /// @dev The `data` argument of the owner's rail: the master key, plus the direction for it
  function _updateData(AuthKey memory key, bool approved) internal pure returns (bytes memory) {
    return abi.encode(key, approved);
  }

  /// @dev `updateAuthentication` payload that approves `key`
  function _approveKey(AuthKey memory key) internal pure returns (bytes memory) {
    return _updateData(key, true);
  }

  /// @dev `updateAuthentication` payload that revokes `key`
  function _revokeKey(AuthKey memory key) internal pure returns (bytes memory) {
    return _updateData(key, false);
  }

  function _authenticatorDomain() internal view returns (bytes32) {
    return
      lDomainSeparator('KyberSwap Two Tiers Order Authenticator', '1.0.0', address(authenticator));
  }

  /// @dev Approves a key through the hub, which reaches the authenticator as `initAuthentication`
  function _delegateKeyThroughHub(AuthKey memory key) internal {
    vm.prank(owner);
    hub.updateDelegation(
      owner, address(authenticator), true, _encodeKey(key), 0, block.timestamp + 1 days, ''
    );
  }

  /// @dev The `data` argument of the master-key rail: the key being decided, the key deciding, and
  /// the direction
  function _sessionKeyData(AuthKey memory sessionKey, AuthKey memory masterKey, bool approved)
    internal
    pure
    returns (bytes memory)
  {
    return abi.encode(sessionKey, masterKey, approved);
  }

  /// @dev As {_signSessionKeyUpdate}, for this base's own `owner`
  function _signSessionKeyUpdate(
    AuthKey memory masterKey,
    AuthKey memory sessionKey,
    bool approved,
    uint256 nonce,
    uint256 deadline,
    uint256 signerPk
  ) internal returns (bytes memory) {
    return _signSessionKeyUpdate(owner, masterKey, sessionKey, approved, nonce, deadline, signerPk);
  }

  /// @dev A master key's decision about one session key, signed by `signerPk`
  function _signSessionKeyUpdate(
    address keyOwner,
    AuthKey memory masterKey,
    AuthKey memory sessionKey,
    bool approved,
    uint256 nonce,
    uint256 deadline,
    uint256 signerPk
  ) internal returns (bytes memory) {
    bytes32 digest = lTypedDataHash(
      _authenticatorDomain(),
      lSessionKeyUpdate(keyOwner, masterKey, sessionKey, approved, nonce, deadline)
    );
    return _sign(signerPk, digest);
  }

  /// @dev Approves `sessionKey` under `masterKey` for `owner`, as a passkey approves a local key
  function _approveSessionKey(
    AuthKey memory masterKey,
    AuthKey memory sessionKey,
    uint256 nonce,
    uint256 deadline,
    uint256 signerPk
  ) internal {
    authenticator.updateAuthentication(
      owner,
      _sessionKeyData(sessionKey, masterKey, true),
      nonce,
      deadline,
      _signSessionKeyUpdate(masterKey, sessionKey, true, nonce, deadline, signerPk)
    );
  }

  /// @dev A key's revocation of one of its nonces, signed by `signerPk`
  function _signNonceRevocation(
    AuthKey memory key,
    uint256 nonce,
    uint256 deadline,
    uint256 signerPk
  ) internal returns (bytes memory) {
    return _sign(
      signerPk, lTypedDataHash(_authenticatorDomain(), lNonceRevocation(key, nonce, deadline))
    );
  }

  function _signMasterKeyUpdate(AuthKey memory key, bool approved, uint256 nonce, uint256 deadline)
    internal
    returns (bytes memory)
  {
    bytes32 digest = lTypedDataHash(
      _authenticatorDomain(), lMasterKeyUpdate(owner, key, approved, nonce, deadline)
    );
    return _sign(ownerKey, digest);
  }

  // ---------------------------------------------------------------------------------------------
  // Authentication data
  // ---------------------------------------------------------------------------------------------

  /**
   * @dev The `authenticationData` the authenticator reads: word 0 points at the key, word 1 says
   * which tier it is presented as, and word 2 points at the signature. The hub passes these bytes
   * through untouched.
   */
  function _authData(AuthKey memory key, bytes memory signature, bool isSessionKey)
    internal
    pure
    returns (bytes memory)
  {
    return abi.encode(key, isSessionKey, signature);
  }

  /// @dev As {_authData}, for a key presented as a master key
  function _authData(AuthKey memory key, bytes memory signature)
    internal
    pure
    returns (bytes memory)
  {
    return _authData(key, signature, false);
  }

  /// @dev The digest a key signs for an execution: the order, under the authenticator domain
  function _executionDigest(ExecutionOrder memory order) internal view returns (bytes32) {
    return lTypedDataHash(_authenticatorDomain(), SchemaHash.executionOrder(order));
  }

  function _fulfillmentDigest(FulfillmentOrder memory order) internal view returns (bytes32) {
    return lTypedDataHash(_authenticatorDomain(), SchemaHash.fulfillmentOrder(order));
  }

  /// @dev `authenticationData` whose signature is `signerKey`'s over `order`, for a master key
  function _executionAuthData(ExecutionOrder memory order, AuthKey memory key, uint256 signerKey)
    internal
    returns (bytes memory)
  {
    return _authData(key, _sign(signerKey, _executionDigest(order)), false);
  }

  /// @dev As {_executionAuthData}, naming the tier the key is presented as
  function _executionAuthData(
    ExecutionOrder memory order,
    AuthKey memory key,
    uint256 signerKey,
    bool isSessionKey
  ) internal returns (bytes memory) {
    return _authData(key, _sign(signerKey, _executionDigest(order)), isSessionKey);
  }

  function _fulfillmentAuthData(
    FulfillmentOrder memory order,
    AuthKey memory key,
    uint256 signerKey
  ) internal returns (bytes memory) {
    return _authData(key, _sign(signerKey, _fulfillmentDigest(order)), false);
  }

  /// @dev As {_fulfillmentAuthData}, naming the tier the key is presented as
  function _fulfillmentAuthData(
    FulfillmentOrder memory order,
    AuthKey memory key,
    uint256 signerKey,
    bool isSessionKey
  ) internal returns (bytes memory) {
    return _authData(key, _sign(signerKey, _fulfillmentDigest(order)), isSessionKey);
  }
}
