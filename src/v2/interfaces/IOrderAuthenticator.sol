// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ExecutionOrder} from '../types/ExecutionOrder.sol';
import {FulfillmentOrder} from '../types/FulfillmentOrder.sol';

/// @title IOrderAuthenticator
/// @notice Interface an authenticator must implement to be delegated through {AuthDelegator}
interface IOrderAuthenticator {
  /// @notice The caller is not the allowance hub this authenticator was deployed for
  error CallerNotAllowanceHub(address caller);

  /**
   * @notice Records the owner's initial authentication material when the owner delegates this
   * authenticator
   * @dev Takes no signature, nonce or deadline, so an implementation must accept it only from the
   * hub. {AuthDelegator-updateDelegation} authenticates the owner before calling it, and
   * {ICallsForwarder-forwardCalls} does not relay this selector.
   * @param owner Account the material belongs to
   * @param data Implementation-specific payload
   */
  function initAuthentication(address owner, bytes calldata data) external;

  /**
   * @notice Records, replaces or withdraws the owner's authentication material
   * @dev Any account may call this, and {ICallsForwarder-forwardCalls} relays it with the hub as
   * `msg.sender`. An implementation must therefore accept only `msg.sender == owner` as
   * authentication without a signature, and must verify `signature` for every other caller,
   * including the hub. The implementation determines which signer may authorise an update, and
   * is responsible for replay protection.
   * @param owner Account the material belongs to
   * @param data Implementation-specific payload
   * @param nonce Nonce of the signature, for the implementation to spend
   * @param deadline Last timestamp at which the call is accepted
   * @param signature Authorisation for the update; not required when the caller is `owner`
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
   * only when the caller is not the owner, after checking `order.deadline` and the submitter. The
   * hub does not spend `order.nonce`, so replay protection is the implementation's. `orderHash` is
   * computed by the hub from `order`.
   * @param order The order to authenticate
   * @param orderHash EIP-712 struct hash of `order`
   * @param data Credential and signature, in the encoding the implementation reads
   */
  function authenticateExecution(
    ExecutionOrder calldata order,
    bytes32 orderHash,
    bytes calldata data
  ) external;

  /**
   * @notice Checks that `data` authenticates `order` on behalf of its owner
   * @dev As {authenticateExecution}, for a fulfillment order
   * @param order The order to authenticate
   * @param orderHash EIP-712 struct hash of `order`
   * @param data Credential and signature, in the encoding the implementation reads
   */
  function authenticateFulfillment(
    FulfillmentOrder calldata order,
    bytes32 orderHash,
    bytes calldata data
  ) external;
}
