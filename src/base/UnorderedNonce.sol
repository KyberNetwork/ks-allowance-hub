// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IUnorderedNonce} from './interfaces/IUnorderedNonce.sol';

/**
 * @title UnorderedNonce
 * @notice Bitmap of spent nonces in the manner of Permit2, so that nonces may be spent in any order
 * @dev Nonces are grouped by namespace, which identifies the signer of the data a nonce protects:
 * an account's address as a 32-byte word, or a key's credential hash. Each contract that inherits
 * this keeps its own bitmap.
 */
abstract contract UnorderedNonce is IUnorderedNonce {
  /// @inheritdoc IUnorderedNonce
  mapping(bytes32 namespace => mapping(uint256 word => uint256 bitmap)) public nonces;

  /// @dev As {_useUnorderedNonce}, in the namespace of an account
  function _useUnorderedNonce(address account, uint256 nonce) internal {
    _useUnorderedNonce(bytes32(uint256(uint160(account))), nonce);
  }

  /// @dev A nonce is a word index in its top bits and a bit position in its low byte
  function _useUnorderedNonce(bytes32 namespace, uint256 nonce) internal {
    uint256 wordPos = nonce >> 8;
    uint256 bitPos = uint8(nonce);

    uint256 bit = 1 << bitPos;
    // The XOR clears a bit that was already set, which identifies a spent nonce
    uint256 flipped = nonces[namespace][wordPos] ^= bit;
    if (flipped & bit == 0) revert NonceAlreadyUsed(namespace, nonce);
  }

  /// @inheritdoc IUnorderedNonce
  function revokeNonce(uint256 nonce) external payable {
    _useUnorderedNonce(msg.sender, nonce);
  }
}
