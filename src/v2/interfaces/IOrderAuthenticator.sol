// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ExecutionOrder} from '../types/ExecutionOrder.sol';
import {FulfillmentOrder} from '../types/FulfillmentOrder.sol';

/// @title IOrderAuthenticator
/// @notice Interface every order authenticator used by {AuthDelegator} must implement
interface IOrderAuthenticator {
  /// @notice Only the allowance hub this authenticator was bound to at deployment may call this
  error NotAllowanceHub();

  /**
   * @notice Records the owner's first authentication material, as the hub delegates this one
   * @dev Carries no signature, nonce or deadline, so an implementation must accept it only from a
   * hub it trusts: {AuthDelegator-updateDelegation} authenticates the owner before calling, and
   * this selector is deliberately absent from {ICallsForwarder-forwardCalls}'s allowlist, so it cannot
   * be relayed on anyone's behalf.
   * @param owner Account the material belongs to
   * @param data Verifier-specific payload
   */
  function initAuthentication(address owner, bytes calldata data) external;

  /**
   * @notice Records, replaces or withdraws the owner's authentication material
   * @dev Anyone may reach this, including through {ICallsForwarder-forwardCalls}, which relays it from
   * any caller and leaves the hub as `msg.sender`. An implementation must therefore treat only
   * `msg.sender == owner` as authentication and verify `signature` in every other case; reading
   * "called by the hub" as proof the owner was authenticated would let anyone install material
   * for anyone. Replay protection belongs to the implementation.
   * @param owner Account the material belongs to
   * @param data Verifier-specific payload
   * @param nonce For the implementation to consume, when it checks the signature
   * @param deadline Last timestamp at which the update is valid
   * @param signature Owner's authentication, needed unless the owner is the caller
   */
  function updateAuthentication(
    address owner,
    bytes calldata data,
    uint256 nonce,
    uint256 deadline,
    bytes calldata signature
  ) external;

  /**
   * @notice Checks that `data` authenticates `order` as the owner's
   * @dev Must revert when it does not; returning normally is read as success. The hub enforces
   * `order.deadline` before calling but never touches `order.nonce`, so an implementation owns
   * replay protection.
   * @param order The order to authenticate
   * @param data Credential and signature, in whatever shape the implementation reads
   */
  function authenticateExecution(ExecutionOrder calldata order, bytes calldata data) external;

  /**
   * @notice Checks that `data` authenticates `order` as the owner's
   * @dev As {authenticateExecution}, over the fulfillment shape
   * @param order The order to authenticate
   * @param data Credential and signature, in whatever shape the implementation reads
   */
  function authenticateFulfillment(FulfillmentOrder calldata order, bytes calldata data) external;
}
