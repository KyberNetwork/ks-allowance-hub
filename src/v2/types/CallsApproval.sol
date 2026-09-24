// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {GenericCall, GenericCallLibrary} from './GenericCall.sol';

/**
 * @notice A signer's approval of one specific call list for one owner's order
 * @dev Signed under the hub's own EIP-712 domain, not as a Permit2 witness, and recovered by
 * {KSAllowanceHubV2} to fill `callsSigner` in the fulfillment witness.
 */
struct CallsApproval {
  address owner;
  GenericCall[] genericCalls;
  uint256 nonce;
  uint256 deadline;
}

using CallsApprovalLibrary for CallsApproval global;

library CallsApprovalLibrary {
  using GenericCallLibrary for GenericCall[];

  bytes32 internal constant CALLS_APPROVAL_TYPEHASH = keccak256(
    'CallsApproval(address owner,GenericCall[] genericCalls,uint256 nonce,uint256 deadline)'
    'GenericCall(address router,uint256 value,bytes data)'
  );

  /// @dev EIP-712 hash of the approval the calls signer produces
  function hash(address owner, GenericCall[] calldata genericCalls, uint256 nonce, uint256 deadline)
    internal
    pure
    returns (bytes32)
  {
    return
      keccak256(abi.encode(CALLS_APPROVAL_TYPEHASH, owner, genericCalls.hash(), nonce, deadline));
  }

  /// @dev As {hash}, for calls already in memory
  function hashMemory(
    address owner,
    GenericCall[] memory genericCalls,
    uint256 nonce,
    uint256 deadline
  ) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(CALLS_APPROVAL_TYPEHASH, owner, genericCalls.hashMemory(), nonce, deadline)
    );
  }

  /// @dev As {hash}, taking the struct rather than its fields
  function hash(CallsApproval calldata self) internal pure returns (bytes32) {
    return hash(self.owner, self.genericCalls, self.nonce, self.deadline);
  }
}
