// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ERC20Transfer} from '../types/ERC20Transfer.sol';
import {ERC721Transfer} from '../types/ERC721Transfer.sol';
import {NativeTransfer} from '../types/NativeTransfer.sol';

import {IAllowanceTransfer} from 'ks-common-sc/src/interfaces/IAllowanceTransfer.sol';
import {ISignatureTransfer} from 'ks-common-sc/src/interfaces/ISignatureTransfer.sol';

import {DynamicArrayLib} from 'solady/utils/DynamicArrayLib.sol';

/**
 * @title DynamicArrayLibExt
 * @notice Allocates typed memory arrays without zeroing their elements, for the element types
 * {DynamicArrayLib} does not cover
 * @dev The caller must write every element before reading any, since an unwritten element holds
 * whatever memory the allocator returned.
 */
library DynamicArrayLibExt {
  using DynamicArrayLib for *;

  /// @dev A `bytes[]` of `length` unwritten elements
  function mallocBytes(uint256 length) internal pure returns (bytes[] memory array) {
    uint256[] memory buffer = length.malloc();
    assembly ('memory-safe') {
      array := buffer
    }
  }

  /**
   * @dev As {mallocBytes}, for native transfers. The caller may write fewer elements than it
   * allocates and shorten the array to those it wrote.
   */
  function mallocNativeTransfers(uint256 length)
    internal
    pure
    returns (NativeTransfer[] memory array)
  {
    uint256[] memory buffer = length.malloc();
    assembly ('memory-safe') {
      array := buffer
    }
  }

  /// @dev As {mallocBytes}, for Permit2's token permissions
  function mallocTokenPermissions(uint256 length)
    internal
    pure
    returns (ISignatureTransfer.TokenPermissions[] memory array)
  {
    uint256[] memory buffer = length.malloc();
    assembly ('memory-safe') {
      array := buffer
    }
  }

  /// @dev As {mallocBytes}, for Permit2's signature-transfer details
  function mallocSignatureTransferDetails(uint256 length)
    internal
    pure
    returns (ISignatureTransfer.SignatureTransferDetails[] memory array)
  {
    uint256[] memory buffer = length.malloc();
    assembly ('memory-safe') {
      array := buffer
    }
  }

  /// @dev As {mallocBytes}, for Permit2's allowance-transfer details
  function mallocAllowanceTransferDetails(uint256 length)
    internal
    pure
    returns (IAllowanceTransfer.AllowanceTransferDetails[] memory array)
  {
    uint256[] memory buffer = length.malloc();
    assembly ('memory-safe') {
      array := buffer
    }
  }

  /// @dev As {mallocBytes}, for ERC20 transfers
  function mallocERC20Transfers(uint256 length)
    internal
    pure
    returns (ERC20Transfer[] memory array)
  {
    uint256[] memory buffer = length.malloc();
    assembly ('memory-safe') {
      array := buffer
    }
  }

  /// @dev As {mallocBytes}, for ERC721 transfers
  function mallocERC721Transfers(uint256 length)
    internal
    pure
    returns (ERC721Transfer[] memory array)
  {
    uint256[] memory buffer = length.malloc();
    assembly ('memory-safe') {
      array := buffer
    }
  }
}
