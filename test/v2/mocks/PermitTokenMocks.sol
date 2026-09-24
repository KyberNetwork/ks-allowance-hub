// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {ERC1155Mock} from 'test/v2/mocks/TokenMocks.sol';

import {ERC20} from 'openzeppelin-contracts/contracts/token/ERC20/ERC20.sol';
import {ERC20Permit} from 'openzeppelin-contracts/contracts/token/ERC20/extensions/ERC20Permit.sol';
import {ERC721} from 'openzeppelin-contracts/contracts/token/ERC721/ERC721.sol';
import {ECDSA} from 'openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol';
import {EIP712} from 'openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol';
import {
  SignatureChecker
} from 'openzeppelin-contracts/contracts/utils/cryptography/SignatureChecker.sol';

/**
 * @title PermitTokenMocks
 * @notice Tokens for the {PermitForwarder} branches. Each `permit` here recovers a real EIP-712
 * signature over its arguments in a fixed order, so a forwarder that decoded the payload words in
 * the wrong order would recover a different signer and fail rather than quietly pass.
 * @dev The type strings below are transcribed from EIP-2612 and the ERC-721 permit drafts; the
 * tests sign against their own copies, never against these.
 */

/// @notice EIP-2612 token, six payload words
contract ERC20PermitMock is ERC20, ERC20Permit {
  constructor(string memory name) ERC20(name, 'PT') ERC20Permit(name) {}

  function mint(address to, uint256 amount) external {
    _mint(to, amount);
  }
}

/// @notice ERC-721 permit as Uniswap v3 shipped it: `(spender, tokenId, deadline, v, r, s)`
contract ERC721PermitV3Mock is ERC721, EIP712 {
  error PermitExpired();
  error InvalidPermitSignature();

  bytes32 private constant PERMIT_TYPEHASH =
    keccak256('Permit(address spender,uint256 tokenId,uint256 nonce,uint256 deadline)');

  /// @dev One counter per token, as the v3 position manager does
  mapping(uint256 tokenId => uint256) public nonces;

  constructor() ERC721('V3 Permit NFT', 'V3P') EIP712('V3 Permit NFT', '1') {}

  function mint(address to, uint256 tokenId) external {
    _mint(to, tokenId);
  }

  function permit(address spender, uint256 tokenId, uint256 deadline, uint8 v, bytes32 r, bytes32 s)
    external
    payable
  {
    require(block.timestamp <= deadline, PermitExpired());

    address tokenOwner = ownerOf(tokenId);
    bytes32 digest = _hashTypedDataV4(
      keccak256(abi.encode(PERMIT_TYPEHASH, spender, tokenId, nonces[tokenId]++, deadline))
    );

    require(ECDSA.recover(digest, v, r, s) == tokenOwner, InvalidPermitSignature());

    _approve(spender, tokenId, address(0));
  }
}

/// @notice ERC-721 permit as Uniswap v4 shipped it: `(spender, tokenId, deadline, nonce, signature)`
contract ERC721PermitV4Mock is ERC721, EIP712 {
  error PermitExpired();
  error NonceAlreadyUsed();
  error InvalidPermitSignature();

  bytes32 private constant PERMIT_TYPEHASH =
    keccak256('Permit(address spender,uint256 tokenId,uint256 nonce,uint256 deadline)');

  /// @dev Unordered nonces per owner, so the payload carries one rather than reading a counter
  mapping(address owner => mapping(uint256 nonce => bool)) public nonceUsed;

  constructor() ERC721('V4 Permit NFT', 'V4P') EIP712('V4 Permit NFT', '1') {}

  function mint(address to, uint256 tokenId) external {
    _mint(to, tokenId);
  }

  function permit(
    address spender,
    uint256 tokenId,
    uint256 deadline,
    uint256 nonce,
    bytes calldata signature
  ) external payable {
    require(block.timestamp <= deadline, PermitExpired());

    address tokenOwner = ownerOf(tokenId);
    require(!nonceUsed[tokenOwner][nonce], NonceAlreadyUsed());
    nonceUsed[tokenOwner][nonce] = true;

    bytes32 digest =
      _hashTypedDataV4(keccak256(abi.encode(PERMIT_TYPEHASH, spender, tokenId, nonce, deadline)));

    require(
      SignatureChecker.isValidSignatureNow(tokenOwner, digest, signature), InvalidPermitSignature()
    );

    _approve(spender, tokenId, address(0));
  }
}

/**
 * @notice ERC-1155 that can be seeded onto a contract holding no receiver hook
 * @dev {ERC1155-_mint} runs the acceptance check and would revert against the hub, so the only way
 * balance can end up stranded there — and the only way a rescue path can be reached — is an update
 * that skips the check, which is exactly what a non-standard token or a direct storage write does.
 */
contract ERC1155SeedMock is ERC1155Mock {
  function mintUnchecked(address to, uint256 id, uint256 amount) external {
    uint256[] memory ids = new uint256[](1);
    uint256[] memory values = new uint256[](1);
    ids[0] = id;
    values[0] = amount;
    _update(address(0), to, ids, values);
  }
}
