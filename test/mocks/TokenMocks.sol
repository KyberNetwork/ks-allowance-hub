// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ERC20} from 'openzeppelin-contracts/contracts/token/ERC20/ERC20.sol';
import {ERC20Permit} from 'openzeppelin-contracts/contracts/token/ERC20/extensions/ERC20Permit.sol';
import {ERC721} from 'openzeppelin-contracts/contracts/token/ERC721/ERC721.sol';
import {EIP712} from 'openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol';

/// @notice ERC20 supporting EIP-2612 permit, used for the permit-carrying paths
contract ERC20PermitMock is ERC20, ERC20Permit {
  constructor(string memory name_, string memory symbol_)
    ERC20(name_, symbol_)
    ERC20Permit(name_)
  {}

  function mint(address to, uint256 amount) external {
    _mint(to, amount);
  }
}

/// @notice ERC20 without permit, used to exercise the empty and malformed permitData branches
contract ERC20NoPermitMock is ERC20 {
  constructor(string memory name_, string memory symbol_) ERC20(name_, symbol_) {}

  function mint(address to, uint256 amount) external {
    _mint(to, amount);
  }
}

/// @notice ERC721 exposing the v3-style permit surface that `PermitHelper.callERC721Permit` calls
contract ERC721PermitMock is ERC721, EIP712 {
  /// @notice Thrown when the permit deadline has passed
  error PermitExpired();

  /// @notice Thrown when the permit signature does not recover to the token owner
  error PermitUnauthorized();

  bytes32 public constant PERMIT_TYPEHASH =
    keccak256('Permit(address spender,uint256 tokenId,uint256 nonce,uint256 deadline)');

  /// @notice Per-token permit nonce
  mapping(uint256 tokenId => uint256 nonce) public nonces;

  constructor(string memory name_, string memory symbol_)
    ERC721(name_, symbol_)
    EIP712(name_, '1')
  {}

  function mint(address to, uint256 tokenId) external {
    _mint(to, tokenId);
  }

  function DOMAIN_SEPARATOR() external view returns (bytes32) {
    return _domainSeparatorV4();
  }

  function permit(address spender, uint256 tokenId, uint256 deadline, uint8 v, bytes32 r, bytes32 s)
    external
    payable
  {
    if (block.timestamp > deadline) revert PermitExpired();

    address owner = ownerOf(tokenId);
    bytes32 digest = _hashTypedDataV4(
      keccak256(abi.encode(PERMIT_TYPEHASH, spender, tokenId, nonces[tokenId]++, deadline))
    );

    address signer = ecrecover(digest, v, r, s);
    if (signer == address(0) || signer != owner) revert PermitUnauthorized();

    _approve(spender, tokenId, owner);
  }
}

/// @notice ERC721 with no permit surface, used to exercise the swallowed-permit branch
contract ERC721NoPermitMock is ERC721 {
  constructor(string memory name_, string memory symbol_) ERC721(name_, symbol_) {}

  function mint(address to, uint256 tokenId) external {
    _mint(to, tokenId);
  }
}

/**
 * @notice ERC721 exposing the v4-style permit surface (7-word permitData branch)
 * @dev `PermitHelper.callERC721Permit` selects this branch on a 224-byte payload.
 */
contract ERC721PermitV4Mock is ERC721, EIP712 {
  /// @notice Thrown when the permit deadline has passed
  error SignatureDeadlineExpired();

  /// @notice Thrown when the permit signature does not recover to the token owner
  error Unauthorized();

  bytes32 public constant PERMIT_TYPEHASH =
    keccak256('Permit(address spender,uint256 tokenId,uint256 nonce,uint256 deadline)');

  mapping(uint256 tokenId => uint256 nonce) public nonces;

  constructor(string memory name_, string memory symbol_)
    ERC721(name_, symbol_)
    EIP712(name_, '1')
  {}

  function mint(address to, uint256 tokenId) external {
    _mint(to, tokenId);
  }

  function DOMAIN_SEPARATOR() external view returns (bytes32) {
    return _domainSeparatorV4();
  }

  function permit(
    address spender,
    uint256 tokenId,
    uint256 deadline,
    uint256 nonce,
    bytes calldata signature
  ) external payable {
    if (block.timestamp > deadline) revert SignatureDeadlineExpired();
    if (nonce != nonces[tokenId]) revert Unauthorized();
    nonces[tokenId]++;

    address tokenOwner = ownerOf(tokenId);
    bytes32 digest =
      _hashTypedDataV4(keccak256(abi.encode(PERMIT_TYPEHASH, spender, tokenId, nonce, deadline)));

    if (signature.length != 65) revert Unauthorized();
    bytes32 r = bytes32(signature[0:32]);
    bytes32 s = bytes32(signature[32:64]);
    uint8 v = uint8(signature[64]);

    address signer = ecrecover(digest, v, r, s);
    if (signer == address(0) || signer != tokenOwner) revert Unauthorized();

    _approve(spender, tokenId, tokenOwner);
  }
}
