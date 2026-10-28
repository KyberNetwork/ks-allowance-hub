// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ERC20Transfer, ERC20TransferLib} from './ERC20Transfer.sol';
import {ERC721Transfer, ERC721TransferLib} from './ERC721Transfer.sol';
import {GenericCall, GenericCallLib} from './GenericCall.sol';

import {IAllowanceTransfer} from 'ks-common-sc/src/interfaces/IAllowanceTransfer.sol';

/**
 * @notice An owner's order to transfer assets to named targets and run a fixed list of router calls
 * @dev When `owner` submits the order, `relayer` does not apply and no authentication is required
 * beyond the call itself, except that a Permit2 entry point still requires the owner's permit
 * signature, without a witness. On a delegated entry point the owner's own submission spends no
 * nonce, so the same order may settle more than once.
 * @param owner Account the assets are transferred from
 * @param relayer Account that may submit the order besides the owner; the dead address allows any
 * account
 * @param erc20Transfers ERC20 legs, each transferred from the owner to its target
 * @param erc721Transfers ERC721 legs, each transferred from the owner to its target
 * @param genericCalls Router calls run after the legs are transferred
 * @param nonce Permit2 nonce on the Permit2 entry points; on the delegated entry points, for the
 * authenticator to spend
 * @param deadline Last timestamp at which the order may settle
 * @param metadata Data the hub does not read, covered by the order's signature
 */
struct ExecutionOrder {
  address owner;
  address relayer;
  ERC20Transfer[] erc20Transfers;
  ERC721Transfer[] erc721Transfers;
  GenericCall[] genericCalls;
  uint256 nonce;
  uint256 deadline;
  string metadata;
}

using ExecutionOrderLib for ExecutionOrder global;

library ExecutionOrderLib {
  using ERC20TransferLib for ERC20Transfer[];
  using ERC721TransferLib for ERC721Transfer[];
  using GenericCallLib for GenericCall[];

  bytes32 internal constant EXECUTION_ORDER_TYPEHASH = keccak256(
    'ExecutionOrder(address owner,address relayer,ERC20Transfer[] erc20Transfers,ERC721Transfer[] erc721Transfers,GenericCall[] genericCalls,uint256 nonce,uint256 deadline,string metadata)'
    'ERC20Transfer(address token,address target,uint160 amount)'
    'ERC721Transfer(address token,uint256 tokenId,address target)'
    'GenericCall(address router,uint256 value,bytes data)'
  );

  /// @dev EIP-712 hash of the order
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
        order.deadline,
        keccak256(bytes(order.metadata))
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
        order.deadline,
        keccak256(bytes(order.metadata))
      )
    );
  }
}
