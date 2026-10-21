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
 * @notice Allocation of typed arrays without the zeroing that `new` performs, completing
 * {DynamicArrayLib}
 * @dev Only for an array whose every slot is written before anything reads one, since an unwritten
 * slot holds whatever the allocator returned. {DynamicArrayLib} has casts for the word-sized
 * element types but none for arrays of `bytes` or of structs. For a struct array, `new` would also
 * allocate and zero a body behind every slot; assigning a struct to an element writes a pointer to
 * a freshly built one, so those bodies would be discarded unread.
 */
library DynamicArrayLibExt {
  using DynamicArrayLib for *;

  /// @dev A `bytes[]` of `length` slots, none of them written
  function mallocBytes(uint256 length) internal pure returns (bytes[] memory array) {
    uint256[] memory buffer = length.malloc();
    assembly ('memory-safe') {
      array := buffer
    }
  }

  /**
   * @dev As {mallocBytes}, for native transfers. A caller may write fewer slots than it allocates
   * and truncate the array to those it wrote.
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

  /// @dev An `address[]` of `length` slots, none of them written
  function mallocAddresses(uint256 length) internal pure returns (address[] memory) {
    return length.malloc().asAddressArray();
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
