// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {AHV2Order} from '../../types/AHV2Order.sol';
import {AHV2Solution} from '../../types/AHV2Solution.sol';

/// @title IAHV2Authenticator
/// @notice Interface an authenticator must implement to be delegated through {AuthDelegator}
interface IAHV2Authenticator {
  /**
   * @notice Records the owner's initial authentication material when the owner delegates this
   * authenticator
   * @dev Takes no signature, nonce or deadline, so an implementation must accept it only from the
   * hub. The hub calls it only from {AuthDelegator-updateDelegation}, after authenticating the
   * owner.
   * @param owner Account the material belongs to
   * @param data Implementation-specific payload
   */
  function initAuthentication(address owner, bytes calldata data) external;

  /**
   * @notice Records, replaces or withdraws the owner's authentication material
   * @dev Any account may call this, and {IKSAllowanceHubV2-forwardCalls} relays it with
   * Multicall3 as `msg.sender`. An implementation must therefore accept only `msg.sender == owner`
   * as authentication without a signature, and must verify `signature` for every other caller,
   * including Multicall3 and the hub. The implementation determines which signer may authorize
   * an update, and is responsible for replay protection.
   * @param owner Account the material belongs to
   * @param data Implementation-specific payload
   * @param nonce Nonce of the signature, for the implementation to spend
   * @param deadline Last timestamp at which the call is accepted
   * @param signature Authorization for the update; not required when the caller is `owner`
   */
  function updateAuthentication(
    address owner,
    bytes calldata data,
    uint256 nonce,
    uint256 deadline,
    bytes calldata signature
  ) external;

  /**
   * @notice Checks that `data` authenticates `order` on behalf of its owner
   * @dev Must revert when it does not; a normal return is treated as success. The hub calls this
   * only when the caller is not the owner, after checking both expirations, the lengths of the
   * solution's arrays and `order.exclusiveCaller`. The hub does not spend `order.nonce` and keeps
   * no record of settled orders, so replay protection, including whether an order may settle more
   * than once, is the implementation's responsibility. `orderHash` is computed by the hub from
   * `order`.
   * The owner has not signed `solution`, so an implementation that accepts or refuses an order by
   * its solution must read it here.
   * @param order The order to authenticate
   * @param orderHash EIP-712 struct hash of `order`
   * @param solution The solution submitted with the order
   * @param data Credential and signature, in the encoding the implementation reads
   */
  function authenticate(
    AHV2Order calldata order,
    bytes32 orderHash,
    AHV2Solution calldata solution,
    bytes calldata data
  ) external;
}
