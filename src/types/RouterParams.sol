// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ERC20Params} from './ERC20Params.sol';
import {ERC721Params} from './ERC721Params.sol';
import {ExecutorCall} from './ExecutorCall.sol';

/**
 * @notice Parameters for interacting with the router
 * @param erc20Params The parameters for collecting ERC20 tokens
 * @param erc721Params The parameters for collecting ERC721 tokens
 * @param executorCalls The calls to make with the executors
 * @param permit2Data The permit data for the PERMIT2 contract
 * @param deadline The deadline for the execution
 */
struct RouterParams {
  ERC20Params[] erc20Params;
  ERC721Params[] erc721Params;
  ExecutorCall[] executorCalls;
  bytes permit2Data;
  uint256 deadline;
}
