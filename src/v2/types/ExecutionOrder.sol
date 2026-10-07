// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ERC20Transfer, ERC20TransferLib} from './ERC20Transfer.sol';
import {ERC721Transfer, ERC721TransferLib} from './ERC721Transfer.sol';
import {GenericCall, GenericCallLib} from './GenericCall.sol';

import {IAllowanceTransfer} from 'ks-common-sc/src/interfaces/IAllowanceTransfer.sol';

/**
 * @notice An owner's signed order to move assets and run an exact list of router calls
 * @dev Pins the calls themselves, so the owner signs what will run.
 * @param owner Account the assets come from
 * @param relayer Who may submit this order; the dead-address sentinel leaves it open to anyone
 * @param erc20Transfers ERC20 legs, moved from the owner to their targets
 * @param erc721Transfers ERC721 legs, moved from the owner to their targets
 * @param genericCalls Router calls to run once the assets have moved
 * @param nonce Burned against the owner, so one order settles at most once
 * @param deadline Last timestamp at which the order may settle
 */
struct ExecutionOrder {
  address owner;
  address relayer;
  ERC20Transfer[] erc20Transfers;
  ERC721Transfer[] erc721Transfers;
  GenericCall[] genericCalls;
  uint256 nonce;
  uint256 deadline;
}

using ExecutionOrderLib for ExecutionOrder global;

library ExecutionOrderLib {
  using ERC20TransferLib for ERC20Transfer[];
  using ERC721TransferLib for ERC721Transfer[];
  using GenericCallLib for GenericCall[];

  bytes32 internal constant EXECUTION_ORDER_TYPEHASH = keccak256(
    'ExecutionOrder(address owner,address relayer,ERC20Transfer[] erc20Transfers,ERC721Transfer[] erc721Transfers,GenericCall[] genericCalls,uint256 nonce,uint256 deadline)'
    'ERC20Transfer(address token,address target,uint160 amount)'
    'ERC721Transfer(address token,uint256 tokenId,address target)'
    'GenericCall(address router,uint256 value,bytes data)'
  );

  /// @dev EIP-712 hash of the order the owner signs
  function hash(ExecutionOrder calldata order) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(
        EXECUTION_ORDER_TYPEHASH,
        order.owner,
        order.relayer,
        order.erc20Transfers.hash(),
        order.erc721Transfers.hash(),
        order.genericCalls.hash(),
        order.nonce,
        order.deadline
      )
    );
  }

  /// @dev As {hash}, for an order already in memory
  function hashMemory(ExecutionOrder memory order) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(
        EXECUTION_ORDER_TYPEHASH,
        order.owner,
        order.relayer,
        order.erc20Transfers.hashMemory(),
        order.erc721Transfers.hashMemory(),
        order.genericCalls.hashMemory(),
        order.nonce,
        order.deadline
      )
    );
  }
}
