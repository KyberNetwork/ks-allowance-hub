// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IPermitForwarder} from './interfaces/IPermitForwarder.sol';

import {Common} from 'ks-common-sc/src/base/Common.sol';
import {IAllowanceTransfer} from 'ks-common-sc/src/interfaces/IAllowanceTransfer.sol';
import {IDaiLikePermit} from 'ks-common-sc/src/interfaces/IDaiLikePermit.sol';
import {IERC721Permit_v3} from 'ks-common-sc/src/interfaces/IERC721Permit_v3.sol';
import {IERC721Permit_v4} from 'ks-common-sc/src/interfaces/IERC721Permit_v4.sol';
import {CalldataDecoder} from 'ks-common-sc/src/libraries/calldata/CalldataDecoder.sol';

import {
  IERC20Permit
} from 'openzeppelin-contracts/contracts/token/ERC20/extensions/IERC20Permit.sol';

/**
 * @title PermitForwarder
 * @notice Relays token permits on a user's behalf so an approval and the spend that follows fit in
 * one transaction. Anyone may relay anyone's permit: the signature inside is the authorisation.
 * @dev Every permit is attempted inside try/catch, so one already-used or front-run permit cannot
 * fail the batch.
 */
abstract contract PermitForwarder is IPermitForwarder, Common {
  using CalldataDecoder for bytes;

  /// @inheritdoc IPermitForwarder
  address public immutable PERMIT2;

  /// @param permit2 The canonical Permit2 deployment this contract relays approvals to
  constructor(address permit2) {
    PERMIT2 = permit2;
  }

  /// @inheritdoc IPermitForwarder
  function erc20Permit(address owner, address[] calldata tokens, bytes[] calldata permitData)
    external
    payable
    checkLengths(tokens.length, permitData.length)
  {
    for (uint256 i = 0; i < tokens.length; i++) {
      bytes calldata data = permitData[i];

      // Length is the discriminator: 6 words is EIP-2612, 7 is DAI-style, anything else is skipped
      if (data.length == 32 * 6) {
        (address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) =
          _decodeERC20PermitData(data);

        try IERC20Permit(tokens[i]).permit(owner, spender, value, deadline, v, r, s) {} catch {}
      } else if (data.length == 32 * 7) {
        (
          address spender,
          uint256 nonce,
          uint256 expiry,
          bool allowed,
          uint8 v,
          bytes32 r,
          bytes32 s
        ) = _decodeDaiLikePermitData(data);

        try IDaiLikePermit(tokens[i]).permit(owner, spender, nonce, expiry, allowed, v, r, s) {}
          catch {}
      }
    }
  }

  /// @inheritdoc IPermitForwarder
  function erc721Permit(
    address[] calldata tokens,
    uint256[] calldata tokenIds,
    bytes[] calldata permitData
  )
    external
    payable
    checkLengths(tokens.length, tokenIds.length)
    checkLengths(tokens.length, permitData.length)
  {
    for (uint256 i = 0; i < tokens.length; i++) {
      bytes calldata data = permitData[i];

      if (data.length == 32 * 5) {
        (address spender, uint256 deadline, uint8 v, bytes32 r, bytes32 s) =
          _decodeERC721PermitV3Data(data);

        try IERC721Permit_v3(tokens[i]).permit(spender, tokenIds[i], deadline, v, r, s) {} catch {}
      } else {
        (address spender, uint256 deadline, uint256 nonce, bytes calldata signature) =
          _decodeERC721PermitV4Data(data);

        try IERC721Permit_v4(tokens[i]).permit(spender, tokenIds[i], deadline, nonce, signature) {}
          catch {}
      }
    }
  }

  /// @inheritdoc IPermitForwarder
  function permit2Permit(
    address owner,
    IAllowanceTransfer.PermitBatch calldata permitBatch,
    bytes calldata signature
  ) external payable {
    try IAllowanceTransfer(PERMIT2).permit(owner, permitBatch, signature) {} catch {}
  }

  /// @dev Reads the six-word EIP-2612 payload
  function _decodeERC20PermitData(bytes calldata data)
    internal
    pure
    returns (address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s)
  {
    spender = data.decodeAddress(0);
    value = data.decodeUint256(1);
    deadline = data.decodeUint256(2);
    v = uint8(data.decodeUint256(3));
    r = data.decodeBytes32(4);
    s = data.decodeBytes32(5);
  }

  /// @dev Reads the seven-word DAI-style payload, whose `allowed` flag replaces an amount
  function _decodeDaiLikePermitData(bytes calldata data)
    internal
    pure
    returns (
      address spender,
      uint256 nonce,
      uint256 expiry,
      bool allowed,
      uint8 v,
      bytes32 r,
      bytes32 s
    )
  {
    spender = data.decodeAddress(0);
    nonce = data.decodeUint256(1);
    expiry = data.decodeUint256(2);
    allowed = data.decodeBool(3);
    v = uint8(data.decodeUint256(4));
    r = data.decodeBytes32(5);
    s = data.decodeBytes32(6);
  }

  /// @dev Reads the five-word Uniswap v3 position-manager payload
  function _decodeERC721PermitV3Data(bytes calldata data)
    internal
    pure
    returns (address spender, uint256 deadline, uint8 v, bytes32 r, bytes32 s)
  {
    spender = data.decodeAddress(0);
    deadline = data.decodeUint256(1);
    v = uint8(data.decodeUint256(2));
    r = data.decodeBytes32(3);
    s = data.decodeBytes32(4);
  }

  /**
   * @dev Reads the Uniswap v4 payload, whose signature is a dynamic `bytes`.
   * The decode sits outside the caller's try/catch, so a payload too short to hold it reverts
   * the whole batch rather than being skipped.
   */
  function _decodeERC721PermitV4Data(bytes calldata data)
    internal
    pure
    returns (address spender, uint256 deadline, uint256 nonce, bytes calldata signature)
  {
    spender = data.decodeAddress(0);
    deadline = data.decodeUint256(1);
    nonce = data.decodeUint256(2);
    signature = data.decodeBytes(3);
  }
}
