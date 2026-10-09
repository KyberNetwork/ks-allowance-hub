// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IUnorderedNonce} from './interfaces/IUnorderedNonce.sol';

/**
 * @title UnorderedNonce
 * @notice Permit2-style nonce bitmap: signatures can be consumed in any order, and each contract
 * inheriting this keeps its own namespace, so the same number is independent across contracts.
 * @dev A namespace belongs to whoever signed the data the nonce guards, not to the account the
 * data acts upon: a session key signing orders for an owner receives a namespace of its own.
 */
abstract contract UnorderedNonce is IUnorderedNonce {
  /// @inheritdoc IUnorderedNonce
  mapping(bytes32 signer => mapping(uint256 word => uint256 bitmap)) public nonces;

  /// @dev As {_useUnorderedNonce}, for a signer that is a plain account
  function _useUnorderedNonce(address signer, uint256 nonce) internal {
    _useUnorderedNonce(bytes32(uint256(uint160(signer))), nonce);
  }

  /// @dev A nonce is a word index in its top bits and a bit position in its low byte
  function _useUnorderedNonce(bytes32 signer, uint256 nonce) internal {
    uint256 wordPos = nonce >> 8;
    uint256 bitPos = uint8(nonce);

    uint256 bit = 1 << bitPos;
    // Flipping clears a bit that was already spent, so reuse is detected
    uint256 flipped = nonces[signer][wordPos] ^= bit;
    if (flipped & bit == 0) revert NonceAlreadyUsed();
  }

  /// @inheritdoc IUnorderedNonce
  function revokeNonce(uint256 nonce) external payable {
    _useUnorderedNonce(msg.sender, nonce);
  }
}
