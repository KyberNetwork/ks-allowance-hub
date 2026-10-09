// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {HubBase} from 'test/v2/base/HubBase.sol';

import {SessionOrderAuthenticator} from 'src/v2/authenticators/SessionOrderAuthenticator.sol';
import {AuthKey} from 'src/v2/authenticators/types/AuthKey.sol';
import {KeyType} from 'src/v2/authenticators/types/KeyType.sol';
import {ExecutionOrder} from 'src/v2/types/ExecutionOrder.sol';
import {FulfillmentOrder} from 'src/v2/types/FulfillmentOrder.sol';

/**
 * @title AuthenticatorBase
 * @notice Contract base for the {SessionOrderAuthenticator} batches and for every hub batch that
 * reaches the hub over the delegated-authentication rail: deploys the authenticator against the
 * hub and builds both tiers of key, their approvals and the order signatures they carry.
 * @dev As in {HubBase}, every digest is assembled from the literals in {V2TestBase}.
 */
abstract contract AuthenticatorBase is HubBase {
  SessionOrderAuthenticator internal authenticator;

  address internal masterSigner;
  uint256 internal masterKeyPk;

  address internal sessionSigner;
  uint256 internal sessionKeyPk;

  function setUp() public virtual override {
    super.setUp();

    authenticator = new SessionOrderAuthenticator(address(hub));
    vm.label(address(authenticator), 'authenticator');

    (masterSigner, masterKeyPk) = makeAddrAndKey('master signer');
    _asEoa(masterSigner);

    (sessionSigner, sessionKeyPk) = makeAddrAndKey('session signer');
    _asEoa(sessionSigner);
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
      lDomainSeparator('KyberSwap Session Order Authenticator', '1.0.0', address(authenticator));
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

  /// @dev As {_signSessionKeyApproval}, for this base's own `owner`
  function _signSessionKeyApproval(
    AuthKey memory masterKey,
    AuthKey memory sessionKey,
    bool approved,
    uint256 nonce,
    uint256 deadline,
    uint256 signerPk
  ) internal returns (bytes memory) {
    return _signSessionKeyApproval(
      owner, masterKey, sessionKey, approved, nonce, deadline, signerPk
    );
  }

  /// @dev A master key's decision about one session key, signed by `signerPk`
  function _signSessionKeyApproval(
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
      lSessionKeyApproval(
        keyOwner, _keyHash(masterKey), _keyHash(sessionKey), approved, nonce, deadline
      )
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
      _signSessionKeyApproval(masterKey, sessionKey, true, nonce, deadline, signerPk)
    );
  }

  function _signMasterKeyApproval(
    AuthKey memory key,
    bool approved,
    uint256 nonce,
    uint256 deadline
  ) internal returns (bytes memory) {
    bytes32 digest = lTypedDataHash(
      _authenticatorDomain(), lMasterKeyApproval(_keyHash(key), approved, nonce, deadline)
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
  function _authData(AuthKey memory key, bytes memory signature)
    internal
    pure
    returns (bytes memory)
  {
    return abi.encode(key, signature);
  }

  /// @dev The digest a key signs for an execution: the order, under the authenticator domain
  function _executionDigest(ExecutionOrder memory order) internal view returns (bytes32) {
    return lTypedDataHash(_authenticatorDomain(), lExecutionOrderHash(order));
  }

  function _fulfillmentDigest(FulfillmentOrder memory order) internal view returns (bytes32) {
    return lTypedDataHash(_authenticatorDomain(), lFulfillmentOrderHash(order));
  }

  /// @dev `authenticationData` whose signature is `signerKey`'s over `order`
  function _executionAuthData(ExecutionOrder memory order, AuthKey memory key, uint256 signerKey)
    internal
    returns (bytes memory)
  {
    return _authData(key, _sign(signerKey, _executionDigest(order)));
  }

  function _fulfillmentAuthData(
    FulfillmentOrder memory order,
    AuthKey memory key,
    uint256 signerKey
  ) internal returns (bytes memory) {
    return _authData(key, _sign(signerKey, _fulfillmentDigest(order)));
  }
}
