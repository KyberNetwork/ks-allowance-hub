// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ERC20Transfer, ERC20TransferLibrary} from '../../v2/types/ERC20Transfer.sol';
import {ERC721Transfer, ERC721TransferLibrary} from '../../v2/types/ERC721Transfer.sol';
import {ValidationParams, ValidationParamsLibrary} from '../../v2/types/ValidationParams.sol';

/**
 * @notice What a session key signs to authorise a `transferAndFulfill` order
 * @dev Names the calls signer rather than the calls, leaving the route to the solver and the
 * bounds to the validators.
 */
struct FulfillmentApproval {
  address solver;
  ERC20Transfer[] erc20Transfers;
  ERC721Transfer[] erc721Transfers;
  ValidationParams[] validationParams;
  address callsSigner;
  uint256 nonce;
  uint256 deadline;
}

using FulfillmentApprovalLibrary for FulfillmentApproval global;

library FulfillmentApprovalLibrary {
  using ERC20TransferLibrary for ERC20Transfer[];
  using ERC721TransferLibrary for ERC721Transfer[];
  using ValidationParamsLibrary for ValidationParams[];

  bytes32 internal constant FULFILLMENT_APPROVAL_TYPEHASH = keccak256(
    'FulfillmentApproval(address solver,ERC20Transfer[] erc20Transfers,ERC721Transfer[] erc721Transfers,ValidationParams[] validationParams,address callsSigner,uint256 nonce,uint256 deadline)'
    'ERC20Transfer(address token,address target,uint160 amount)'
    'ERC721Transfer(address token,uint256 tokenId,address target)'
    'ValidationParams(address validator,bytes32 action,bytes beforeExecutionInput,bytes afterExecutionInput)'
  );

  /// @dev EIP-712 hash of what a session key signs to authorise a fulfillment
  function hash(
    address solver,
    ERC20Transfer[] calldata erc20Transfers,
    ERC721Transfer[] calldata erc721Transfers,
    ValidationParams[] calldata validationParams,
    address callsSigner,
    uint256 nonce,
    uint256 deadline
  ) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(
        FULFILLMENT_APPROVAL_TYPEHASH,
        solver,
        erc20Transfers.hash(),
        erc721Transfers.hash(),
        validationParams.hash(),
        callsSigner,
        nonce,
        deadline
      )
    );
  }

  /// @dev As {hash}, for arrays already in memory
  function hashMemory(
    address solver,
    ERC20Transfer[] memory erc20Transfers,
    ERC721Transfer[] memory erc721Transfers,
    ValidationParams[] memory validationParams,
    address callsSigner,
    uint256 nonce,
    uint256 deadline
  ) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(
        FULFILLMENT_APPROVAL_TYPEHASH,
        solver,
        erc20Transfers.hashMemory(),
        erc721Transfers.hashMemory(),
        validationParams.hashMemory(),
        callsSigner,
        nonce,
        deadline
      )
    );
  }
}
