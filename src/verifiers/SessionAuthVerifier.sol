// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {IAuthVerifier} from '../base/interfaces/IAuthVerifier.sol';

import {BaseAuthVerifier} from '../base/BaseAuthVerifier.sol';
import {DeadlineChecker} from '../base/DeadlineChecker.sol';
import {UnorderedNonce} from '../base/UnorderedNonce.sol';

import {ISessionAuthVerifier} from './interfaces/ISessionAuthVerifier.sol';

import {ExecutionApprovalLibrary} from './types/ExecutionApproval.sol';
import {FulfillmentApprovalLibrary} from './types/FulfillmentApproval.sol';
import {SessionApprovalLibrary} from './types/SessionApproval.sol';
import {SessionKey} from './types/SessionKey.sol';

import {ERC20Transfer} from '../v2/types/ERC20Transfer.sol';
import {ERC721Transfer} from '../v2/types/ERC721Transfer.sol';
import {GenericCall} from '../v2/types/GenericCall.sol';
import {ValidationParams} from '../v2/types/ValidationParams.sol';

import {CalldataDecoder} from 'ks-common-sc/src/libraries/calldata/CalldataDecoder.sol';

import {EIP712} from 'openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol';
import {
  SignatureChecker
} from 'openzeppelin-contracts/contracts/utils/cryptography/SignatureChecker.sol';

/// @title SessionAuthVerifier
/**
 * @notice Lets an owner approve a session key once and then authorise allowance-hub orders with
 * that key instead of their main wallet. Keys carry their own expiry and may be Secp256k1, P256,
 * WebAuthn or RSA, so a passkey or a hot key can sign orders the wallet never touches.
 * @dev Replay protection lives here rather than in the hub: every verification burns one of the
 * owner's nonces, and the nonce and deadline are bound into the digest the key signs.
 */
contract SessionAuthVerifier is
  IAuthVerifier,
  ISessionAuthVerifier,
  BaseAuthVerifier,
  DeadlineChecker,
  UnorderedNonce,
  EIP712
{
  using CalldataDecoder for bytes;

  /// @inheritdoc ISessionAuthVerifier
  mapping(address => mapping(bytes32 keyHash => bool)) public approvedKeys;

  /// @param allowanceHub The only hub whose verification requests this verifier answers
  constructor(address allowanceHub)
    BaseAuthVerifier(allowanceHub)
    EIP712('KyberSwap Session Auth Verifier', '1.0.0')
  {}

  /// @inheritdoc IAuthVerifier
  function updateAuth(
    address owner,
    bytes calldata data,
    uint256 nonce,
    uint256 deadline,
    bytes calldata signature
  ) external checkDeadline(deadline) {
    // Untrusted pointer: the hash below is what makes it safe, since only material the owner
    // approved can produce an approved key hash
    SessionKey calldata key;
    assembly ('memory-safe') {
      key := add(data.offset, calldataload(data.offset))
    }

    bytes32 keyHash = key.hash();

    // An empty signature is trusted only from someone already authenticated: the owner
    // themselves, or the hub, which never forwards one until it has authenticated them
    if ((msg.sender != owner && msg.sender != ALLOWANCE_HUB) || signature.length != 0) {
      _useUnorderedNonce(owner, nonce);

      bytes32 digest = _hashTypedDataV4(SessionApprovalLibrary.hash(keyHash, nonce, deadline));
      if (!SignatureChecker.isValidSignatureNow(owner, digest, signature)) {
        revert InvalidApprovalSignature();
      }
    }

    approvedKeys[owner][keyHash] = true;
  }

  /// @inheritdoc IAuthVerifier
  function verifyAuth(
    address owner,
    bytes calldata data,
    uint256 nonce,
    uint256 deadline,
    bytes calldata key,
    bytes calldata signature
  ) external onlyAllowanceHub checkDeadline(deadline) {
    _useUnorderedNonce(owner, nonce);

    // Untrusted pointer, as in updateAuth: every field read below is covered by the key hash
    SessionKey calldata sessionKey;
    assembly ('memory-safe') {
      sessionKey := add(key.offset, calldataload(key.offset))
    }

    if (!approvedKeys[owner][sessionKey.hash()]) {
      revert SessionKeyNotDelegated();
    }
    if (sessionKey.expiration < block.timestamp) {
      revert SessionKeyExpired();
    }

    address signedCaller = data.decodeAddress(0);
    ERC20Transfer[] calldata erc20Transfers = _decodeERC20Transfers(data);
    ERC721Transfer[] calldata erc721Transfers = _decodeERC721Transfers(data);

    bytes32 digest;
    if (_isFulfillment(data)) {
      ValidationParams[] calldata validationParams = _decodeValidationParams(data);
      address callsSigner = data.decodeAddress(4);

      digest = _hashTypedDataV4(
        FulfillmentApprovalLibrary.hash(
          signedCaller,
          erc20Transfers,
          erc721Transfers,
          validationParams,
          callsSigner,
          nonce,
          deadline
        )
      );
    } else {
      GenericCall[] calldata genericCalls = _decodeGenericCalls(data);

      digest = _hashTypedDataV4(
        ExecutionApprovalLibrary.hash(
          signedCaller, erc20Transfers, erc721Transfers, genericCalls, nonce, deadline
        )
      );
    }

    if (!sessionKey.verify(digest, signature)) {
      revert InvalidApprovalSignature();
    }
  }

  /// @dev The hub appends one byte to say which entry point built `data`
  function _isFulfillment(bytes calldata data) internal pure returns (bool) {
    return data[data.length - 1] != 0;
  }

  /// @dev Reads the ERC20 legs out of the hub's payload
  function _decodeERC20Transfers(bytes calldata data)
    internal
    pure
    returns (ERC20Transfer[] calldata erc20Transfers)
  {
    (uint256 length, uint256 offset) = data.decodeLengthOffset(1);
    assembly ('memory-safe') {
      erc20Transfers.length := length
      erc20Transfers.offset := offset
    }
  }

  /// @dev Reads the ERC721 legs out of the hub's payload
  function _decodeERC721Transfers(bytes calldata data)
    internal
    pure
    returns (ERC721Transfer[] calldata erc721Transfers)
  {
    (uint256 length, uint256 offset) = data.decodeLengthOffset(2);
    assembly ('memory-safe') {
      erc721Transfers.length := length
      erc721Transfers.offset := offset
    }
  }

  /// @dev Reads the call list out of the hub's payload, at word 3
  function _decodeGenericCalls(bytes calldata data)
    internal
    pure
    returns (GenericCall[] calldata genericCalls)
  {
    (uint256 length, uint256 offset) = data.decodeLengthOffset(3);
    assembly ('memory-safe') {
      genericCalls.length := length
      genericCalls.offset := offset
    }
  }

  /// @dev Also word 3: in a fulfillment payload that slot holds the validators, not the calls
  function _decodeValidationParams(bytes calldata data)
    internal
    pure
    returns (ValidationParams[] calldata validationParams)
  {
    (uint256 length, uint256 offset) = data.decodeLengthOffset(3);
    assembly ('memory-safe') {
      validationParams.length := length
      validationParams.offset := offset
    }
  }
}
