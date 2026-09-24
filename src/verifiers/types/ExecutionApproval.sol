// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ERC20Transfer, ERC20TransferLibrary} from '../../v2/types/ERC20Transfer.sol';
import {ERC721Transfer, ERC721TransferLibrary} from '../../v2/types/ERC721Transfer.sol';
import {GenericCall, GenericCallLibrary} from '../../v2/types/GenericCall.sol';

/**
 * @notice What a session key signs to authorise a `transferAndExecute` order
 * @dev Unlike the Permit2 witness, this covers the ERC20 legs in full, since no permit signature
 * covers them on this rail. The nonce and deadline are signed here and consumed by the verifier.
 */
struct ExecutionApproval {
  address relayer;
  ERC20Transfer[] erc20Transfers;
  ERC721Transfer[] erc721Transfers;
  GenericCall[] genericCalls;
  uint256 nonce;
  uint256 deadline;
}

using ExecutionApprovalLibrary for ExecutionApproval global;

library ExecutionApprovalLibrary {
  using ERC20TransferLibrary for ERC20Transfer[];
  using ERC721TransferLibrary for ERC721Transfer[];
  using GenericCallLibrary for GenericCall[];

  bytes32 internal constant EXECUTION_APPROVAL_TYPEHASH = keccak256(
    'ExecutionApproval(address relayer,ERC20Transfer[] erc20Transfers,ERC721Transfer[] erc721Transfers,GenericCall[] genericCalls,uint256 nonce,uint256 deadline)'
    'ERC20Transfer(address token,address target,uint160 amount)'
    'ERC721Transfer(address token,uint256 tokenId,address target)'
    'GenericCall(address router,uint256 value,bytes data)'
  );

  /// @dev EIP-712 hash of what a session key signs to authorise an execution
  function hash(
    address relayer,
    ERC20Transfer[] calldata erc20Transfers,
    ERC721Transfer[] calldata erc721Transfers,
    GenericCall[] calldata genericCalls,
    uint256 nonce,
    uint256 deadline
  ) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(
        EXECUTION_APPROVAL_TYPEHASH,
        relayer,
        erc20Transfers.hash(),
        erc721Transfers.hash(),
        genericCalls.hash(),
        nonce,
        deadline
      )
    );
  }

  /// @dev As {hash}, for arrays already in memory
  function hashMemory(
    address relayer,
    ERC20Transfer[] memory erc20Transfers,
    ERC721Transfer[] memory erc721Transfers,
    GenericCall[] memory genericCalls,
    uint256 nonce,
    uint256 deadline
  ) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(
        EXECUTION_APPROVAL_TYPEHASH,
        relayer,
        erc20Transfers.hashMemory(),
        erc721Transfers.hashMemory(),
        genericCalls.hashMemory(),
        nonce,
        deadline
      )
    );
  }
}
