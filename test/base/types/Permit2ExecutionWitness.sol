// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {ExecutionWitness} from 'src/v2/types/ExecutionWitness.sol';

import {TokenPermissions} from './TokenPermissions.sol';

/// @dev Permit2 names the signed type `PermitBatchWitnessTransferFrom` whatever the witness is, so
/// the execution and fulfillment variants collide and have to sit in separate files
struct PermitBatchWitnessTransferFrom {
  TokenPermissions[] permitted;
  address spender;
  uint256 nonce;
  uint256 deadline;
  ExecutionWitness witness;
}
