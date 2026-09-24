// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IUnorderedNonce} from './interfaces/IUnorderedNonce.sol';

/**
 * @title UnorderedNonce
 * @notice Permit2-style nonce bitmap: signatures can be consumed in any order, and each contract
 * inheriting this keeps its own namespace, so the same number is independent across contracts.
 */
abstract contract UnorderedNonce is IUnorderedNonce {
  /// @inheritdoc IUnorderedNonce
  mapping(address owner => mapping(uint256 word => uint256 bitmap)) public nonces;

  /// @dev A nonce is a word index in its top bits and a bit position in its low byte
  function _useUnorderedNonce(address owner, uint256 nonce) internal {
    uint256 wordPos = nonce >> 8;
    uint256 bitPos = uint8(nonce);

    uint256 bit = 1 << bitPos;
    // Flipping turns the bit off again when it was already spent, which is how reuse is caught
    uint256 flipped = nonces[owner][wordPos] ^= bit;
    if (flipped & bit == 0) revert NonceAlreadyUsed();
  }

  /// @inheritdoc IUnorderedNonce
  function revokeNonce(uint256 nonce) external payable {
    _useUnorderedNonce(msg.sender, nonce);
  }
}
