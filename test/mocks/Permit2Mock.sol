// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {PermitHash} from '../libraries/PermitHash.sol';

import {ISignatureTransfer} from 'ks-common-sc/src/interfaces/ISignatureTransfer.sol';

import {IERC20} from 'openzeppelin-contracts/contracts/interfaces/IERC20.sol';

/**
 * @notice Local stand-in for Permit2's SignatureTransfer surface
 * @dev Mirrors the real contract's EIP-712 domain, unordered nonce bitmap, deadline handling and
 * amount checks so signature binding is genuinely verified rather than stubbed. Only EOA
 * signatures are supported; the hub never relies on EIP-1271.
 */
contract Permit2Mock is ISignatureTransfer {
  /// @notice Thrown when the permit deadline has passed
  error SignatureExpired(uint256 signatureDeadline);

  /// @notice Thrown when the nonce has already been used by the owner
  error InvalidNonce();

  /// @notice Thrown when the signature does not recover to the claimed owner
  error InvalidSigner();

  bytes32 private constant _EIP712_DOMAIN_TYPEHASH =
    keccak256('EIP712Domain(string name,uint256 chainId,address verifyingContract)');

  bytes32 private constant _NAME_HASH = keccak256('Permit2');

  /// @inheritdoc ISignatureTransfer
  mapping(address owner => mapping(uint256 wordPos => uint256 bitmap)) public nonceBitmap;

  /// @notice Returns the EIP-712 domain separator, matching the real Permit2 layout
  function DOMAIN_SEPARATOR() public view returns (bytes32) {
    return keccak256(abi.encode(_EIP712_DOMAIN_TYPEHASH, _NAME_HASH, block.chainid, address(this)));
  }

  /// @inheritdoc ISignatureTransfer
  function permitTransferFrom(
    PermitBatchTransferFrom memory permit,
    SignatureTransferDetails[] calldata transferDetails,
    address owner,
    bytes calldata signature
  ) external {
    _permitTransferFrom(
      permit, transferDetails, owner, PermitHash.hash(permit, msg.sender), signature
    );
  }

  /// @inheritdoc ISignatureTransfer
  function permitWitnessTransferFrom(
    PermitBatchTransferFrom memory permit,
    SignatureTransferDetails[] calldata transferDetails,
    address owner,
    bytes32 witness,
    string calldata witnessTypeString,
    bytes calldata signature
  ) external {
    _permitTransferFrom(
      permit,
      transferDetails,
      owner,
      PermitHash.hashWithWitness(permit, msg.sender, witness, witnessTypeString),
      signature
    );
  }

  /// @inheritdoc ISignatureTransfer
  function permitTransferFrom(
    PermitTransferFrom memory,
    SignatureTransferDetails calldata,
    address,
    bytes calldata
  ) external pure {
    revert('Permit2Mock: single transfer unused');
  }

  /// @inheritdoc ISignatureTransfer
  function permitWitnessTransferFrom(
    PermitTransferFrom memory,
    SignatureTransferDetails calldata,
    address,
    bytes32,
    string calldata,
    bytes calldata
  ) external pure {
    revert('Permit2Mock: single transfer unused');
  }

  /// @inheritdoc ISignatureTransfer
  function invalidateUnorderedNonces(uint256 wordPos, uint256 mask) external {
    nonceBitmap[msg.sender][wordPos] |= mask;
    emit UnorderedNonceInvalidation(msg.sender, wordPos, mask);
  }

  function _permitTransferFrom(
    PermitBatchTransferFrom memory permit,
    SignatureTransferDetails[] calldata transferDetails,
    address owner,
    bytes32 dataHash,
    bytes calldata signature
  ) private {
    if (block.timestamp > permit.deadline) {
      revert SignatureExpired(permit.deadline);
    }
    if (permit.permitted.length != transferDetails.length) revert LengthMismatch();

    _useUnorderedNonce(owner, permit.nonce);
    _verify(dataHash, owner, signature);

    for (uint256 i = 0; i < permit.permitted.length; i++) {
      uint256 requestedAmount = transferDetails[i].requestedAmount;
      if (requestedAmount > permit.permitted[i].amount) {
        revert InvalidAmount(permit.permitted[i].amount);
      }
      if (requestedAmount != 0) {
        IERC20(permit.permitted[i].token)
          .transferFrom(owner, transferDetails[i].to, requestedAmount);
      }
    }
  }

  function _useUnorderedNonce(address from, uint256 nonce) private {
    uint256 bit = 1 << uint8(nonce);
    uint256 flipped = nonceBitmap[from][nonce >> 8] ^= bit;
    if (flipped & bit == 0) revert InvalidNonce();
  }

  function _verify(bytes32 dataHash, address claimedSigner, bytes calldata signature) private view {
    if (signature.length != 65) revert InvalidSigner();

    bytes32 digest = keccak256(abi.encodePacked('\x19\x01', DOMAIN_SEPARATOR(), dataHash));

    bytes32 r = bytes32(signature[0:32]);
    bytes32 s = bytes32(signature[32:64]);
    uint8 v = uint8(signature[64]);

    address signer = ecrecover(digest, v, r, s);
    if (signer == address(0) || signer != claimedSigner) revert InvalidSigner();
  }
}
