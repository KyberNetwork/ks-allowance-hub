// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IAHV2Authenticator} from '../../src/interfaces/base/IAHV2Authenticator.sol';

import {AHV2AuthenticatorBase} from '../../src/base/AHV2AuthenticatorBase.sol';
import {DeadlineChecker} from '../../src/base/DeadlineChecker.sol';
import {UnorderedNonce} from '../../src/base/UnorderedNonce.sol';

import {AHV2Order} from '../../src/types/AHV2Order.sol';
import {AHV2Solution} from '../../src/types/AHV2Solution.sol';

import {EIP712} from 'openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol';
import {
  SignatureChecker
} from 'openzeppelin-contracts/contracts/utils/cryptography/SignatureChecker.sol';

/**
 * @title SignerAuthenticatorMock
 * @notice Test authenticator that accepts an order signed by an address the order's owner has
 * approved
 * @dev Signatures are verified over EIP-712 digests under this contract's domain. An order spends
 * `order.nonce` in the signer's address namespace, and a signed update spends `nonce` in the
 * owner's address namespace.
 */
contract SignerAuthenticatorMock is AHV2AuthenticatorBase, DeadlineChecker, UnorderedNonce, EIP712 {
  bytes32 internal constant SIGNER_UPDATE_TYPEHASH =
    keccak256('SignerUpdate(address owner,bytes data,uint256 nonce,uint256 deadline)');

  /// @notice The owner's signature over the update is not valid
  error InvalidUpdateSignature();

  /// @notice The signer's signature over the order is not valid
  error InvalidOrderSignature();

  /// @notice The owner has not approved the signer, or has revoked it
  error SignerNotApproved(address owner, address signer);

  /// @notice Emitted when `owner` approves or revokes `signer`
  event UpdateSigner(address indexed owner, address indexed signer, bool approved);

  /// @notice Whether `owner` has approved `signer` to sign its orders
  mapping(address owner => mapping(address signer => bool)) public approvedSigners;

  /// @param hub The only address whose authentication requests this one answers
  constructor(address hub)
    AHV2AuthenticatorBase(hub)
    EIP712('AHV2 Signer Authenticator Mock', '1')
  {}

  /**
   * @inheritdoc IAHV2Authenticator
   * @dev `data` is `abi.encode(address signer)`, which is approved
   */
  function initAuthentication(address owner, bytes calldata data) external onlyAuthorizedCaller {
    _updateSigner(owner, abi.decode(data, (address)), true);
  }

  /**
   * @inheritdoc IAHV2Authenticator
   * @dev `data` is `abi.encode(address signer, bool approved)`. When the caller is not `owner`,
   * `signature` must be the owner's signature over
   * `SignerUpdate(address owner,bytes data,uint256 nonce,uint256 deadline)`, and `nonce` is spent
   * in the owner's namespace. When the caller is `owner`, `signature` is not read.
   */
  function updateAuthentication(
    address owner,
    bytes calldata data,
    uint256 nonce,
    uint256 deadline,
    bytes calldata signature
  ) external checkDeadline(deadline) {
    (address signer, bool approved) = abi.decode(data, (address, bool));
    if (msg.sender != owner) {
      _useUnorderedNonce(owner, nonce);
      bytes32 digest = _hashTypedDataV4(
        keccak256(abi.encode(SIGNER_UPDATE_TYPEHASH, owner, keccak256(data), nonce, deadline))
      );
      if (!SignatureChecker.isValidSignatureNow(owner, digest, signature)) {
        revert InvalidUpdateSignature();
      }
    }
    _updateSigner(owner, signer, approved);
  }

  /**
   * @inheritdoc IAHV2Authenticator
   * @dev `data` is `abi.encode(address signer, bytes signature)`. The solution is not read.
   */
  function authenticate(
    AHV2Order calldata order,
    bytes32 orderHash,
    AHV2Solution calldata,
    bytes calldata data
  ) external onlyAuthorizedCaller {
    _authenticate(order.owner, order.nonce, orderHash, data);
  }

  /// @dev Records the owner's decision about one signer
  function _updateSigner(address owner, address signer, bool approved) private {
    approvedSigners[owner][signer] = approved;
    emit UpdateSigner(owner, signer, approved);
  }

  /// @dev Checks that the signer in `data` is approved for `owner` and signed the order with hash
  /// `orderHash`, and spends `nonce` in the signer's namespace
  function _authenticate(address owner, uint256 nonce, bytes32 orderHash, bytes calldata data)
    private
  {
    (address signer, bytes memory signature) = abi.decode(data, (address, bytes));
    if (!approvedSigners[owner][signer]) {
      revert SignerNotApproved(owner, signer);
    }
    _useUnorderedNonce(signer, nonce);
    if (!SignatureChecker.isValidSignatureNow(signer, _hashTypedDataV4(orderHash), signature)) {
      revert InvalidOrderSignature();
    }
  }
}
