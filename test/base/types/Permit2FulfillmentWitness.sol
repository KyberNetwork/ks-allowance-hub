// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {FulfillmentWitness} from 'src/v2/types/FulfillmentWitness.sol';

import {TokenPermissions} from './TokenPermissions.sol';

/// @dev The fulfillment half of the collision described in {Permit2ExecutionWitness}
struct PermitBatchWitnessTransferFrom {
  TokenPermissions[] permitted;
  address spender;
  uint256 nonce;
  uint256 deadline;
  FulfillmentWitness witness;
}
