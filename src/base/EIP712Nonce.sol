// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {UnorderedNonce} from './UnorderedNonce.sol';

import {EIP712} from 'openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol';
import {
  SignatureChecker
} from 'openzeppelin-contracts/contracts/utils/cryptography/SignatureChecker.sol';

/// @title EIP712Nonce
/// @notice Verifies EIP-712 signatures that each spend an unordered nonce of their signer
abstract contract EIP712Nonce is UnorderedNonce, EIP712 {
  /// @dev Spends `nonce` in the namespace of `signer` and returns whether `signature` by `signer`
  /// is valid for the EIP-712 digest of `structHash`
  function _verifySignature(
    address signer,
    uint256 nonce,
    bytes32 structHash,
    bytes calldata signature
  ) internal returns (bool) {
    _useUnorderedNonce(signer, nonce);

    return SignatureChecker.isValidSignatureNow(signer, _hashTypedDataV4(structHash), signature);
  }
}
