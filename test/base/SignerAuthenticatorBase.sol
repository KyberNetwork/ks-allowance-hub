// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {HubBase} from './HubBase.sol';
import {SchemaHash} from './SchemaHash.sol';

import {SignerAuthenticatorMock} from '../mocks/SignerAuthenticatorMock.sol';

import {ExecutionOrder} from '../../src/types/ExecutionOrder.sol';
import {FulfillmentOrder} from '../../src/types/FulfillmentOrder.sol';

/**
 * @title SignerAuthenticatorBase
 * @notice Contract base for the hub batches that reach the hub over the delegated-authentication
 * rail: deploys {SignerAuthenticatorMock} against the hub and builds the approvals and order
 * signatures it accepts
 * @dev As in {HubBase}, every digest is assembled from literals written out here.
 */
abstract contract SignerAuthenticatorBase is HubBase {
  /// @dev Transcribed from {SignerAuthenticatorMock}, never imported
  bytes32 internal constant SIGNER_UPDATE_TYPEHASH =
    keccak256('SignerUpdate(address owner,bytes data,uint256 nonce,uint256 deadline)');

  SignerAuthenticatorMock internal authenticator;

  /// @dev The account the owner approves at the authenticator, and its private key
  address internal signer;
  uint256 internal signerPk;

  function setUp() public virtual override {
    super.setUp();

    authenticator = new SignerAuthenticatorMock(address(hub));
    vm.label(address(authenticator), 'authenticator');

    (signer, signerPk) = makeAddrAndKey('signer');
  }

  /// @dev The EIP-712 domain separator of the authenticator
  function _authenticatorDomain() internal view returns (bytes32) {
    return lDomainSeparator('AHV2 Signer Authenticator Mock', '1', address(authenticator));
  }

  /// @dev The payload `initAuthentication` reads
  function _encodeSigner(address orderSigner) internal pure returns (bytes memory) {
    return abi.encode(orderSigner);
  }

  /// @dev The `updateAuthentication` payload that approves `orderSigner`
  function _approveSigner(address orderSigner) internal pure returns (bytes memory) {
    return abi.encode(orderSigner, true);
  }

  /// @dev The owner's signature over a decision about `orderSigner`
  function _signSignerUpdate(address orderSigner, bool approved, uint256 nonce, uint256 deadline)
    internal
    view
    returns (bytes memory)
  {
    return _sign(
      ownerKey,
      lTypedDataHash(
        _authenticatorDomain(),
        keccak256(
          abi.encode(
            SIGNER_UPDATE_TYPEHASH,
            owner,
            keccak256(abi.encode(orderSigner, approved)),
            nonce,
            deadline
          )
        )
      )
    );
  }

  /// @dev Approves `orderSigner` through the hub, which reaches the authenticator as
  /// `initAuthentication`
  function _delegateSignerThroughHub(address orderSigner) internal {
    vm.prank(owner);
    hub.updateDelegation(
      owner,
      address(authenticator),
      true,
      _encodeSigner(orderSigner),
      0,
      vm.getBlockTimestamp() + 1 days,
      ''
    );
  }

  /// @dev The `authenticationData` the authenticator reads
  function _authData(address orderSigner, bytes memory signature)
    internal
    pure
    returns (bytes memory)
  {
    return abi.encode(orderSigner, signature);
  }

  /// @dev The authentication data for an execution order signed with `signingKey`
  function _executionAuthData(ExecutionOrder memory order, address orderSigner, uint256 signingKey)
    internal
    view
    returns (bytes memory)
  {
    return _authData(
      orderSigner,
      _sign(signingKey, lTypedDataHash(_authenticatorDomain(), SchemaHash.executionOrder(order)))
    );
  }

  /// @dev The authentication data for a fulfillment order signed with `signingKey`
  function _fulfillmentAuthData(
    FulfillmentOrder memory order,
    address orderSigner,
    uint256 signingKey
  ) internal view returns (bytes memory) {
    return _authData(
      orderSigner,
      _sign(signingKey, lTypedDataHash(_authenticatorDomain(), SchemaHash.fulfillmentOrder(order)))
    );
  }
}
