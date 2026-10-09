// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {IERC1271} from 'openzeppelin-contracts/contracts/interfaces/IERC1271.sol';
import {ERC1155} from 'openzeppelin-contracts/contracts/token/ERC1155/ERC1155.sol';
import {ERC20} from 'openzeppelin-contracts/contracts/token/ERC20/ERC20.sol';
import {ERC20Permit} from 'openzeppelin-contracts/contracts/token/ERC20/extensions/ERC20Permit.sol';
import {ERC721} from 'openzeppelin-contracts/contracts/token/ERC721/ERC721.sol';
import {ECDSA} from 'openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol';

/**
 * @notice The suite's ERC20, carrying EIP-2612 so the forwarder has a real permit to relay
 * @dev The width is a constructor argument because the rails are indifferent to it while two of
 * the cases are not: the rescue case moves two tokens of different widths, and a 6-decimal amount
 * reads differently from an 18-decimal one in an event payload.
 */
contract ERC20Mock is ERC20, ERC20Permit {
  uint8 private immutable DECIMALS;

  constructor(string memory name, string memory symbol, uint8 width)
    ERC20(name, symbol)
    ERC20Permit(name)
  {
    DECIMALS = width;
  }

  function decimals() public view override returns (uint8) {
    return DECIMALS;
  }

  function mint(address to, uint256 amount) external {
    _mint(to, amount);
  }
}

contract ERC721Mock is ERC721('Mock NFT', 'MNFT') {
  function mint(address to, uint256 tokenId) external {
    _mint(to, tokenId);
  }
}

contract ERC1155Mock is ERC1155('') {
  function mint(address to, uint256 id, uint256 amount) external {
    _mint(to, id, amount, '');
  }
}

/// @notice Smart-account owner, so the ERC-1271 branch of `SignatureChecker` is exercised.
contract ERC1271WalletMock is IERC1271 {
  address public immutable SIGNER;
  bool public returnWrongMagic;

  constructor(address signer) {
    SIGNER = signer;
  }

  function setReturnWrongMagic(bool value) external {
    returnWrongMagic = value;
  }

  function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4) {
    if (returnWrongMagic) return 0xffffffff;
    return ECDSA.recover(hash, signature) == SIGNER ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
  }
}

/// @notice ERC721 receiver that reenters the hub from `onERC721Received`.
contract ReentrantReceiverMock {
  address public immutable HUB;
  bytes public reentryCalldata;

  constructor(address hub) {
    HUB = hub;
  }

  function setReentry(bytes calldata data) external {
    reentryCalldata = data;
  }

  function onERC721Received(address, address, uint256, bytes calldata) external returns (bytes4) {
    (bool ok, bytes memory ret) = HUB.call(reentryCalldata);
    if (!ok) {
      assembly ('memory-safe') {
        revert(add(ret, 0x20), mload(ret))
      }
    }
    return this.onERC721Received.selector;
  }
}
