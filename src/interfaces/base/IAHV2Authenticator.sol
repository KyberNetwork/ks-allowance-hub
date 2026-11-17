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
   * hub.
   * @param owner Account the material belongs to
   * @param data Implementation-specific payload
   */
  function initAuthentication(address owner, bytes calldata data) external;

  /**
   * @notice Records, replaces or withdraws the owner's authentication material
   * @dev Any account may call this. An implementation must accept only `msg.sender == owner`
   * without a signature, and must verify `signature` for every other caller, including Multicall3
   * and the hub. It determines which signer may authorize an update and provides replay
   * protection.
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
   * only when the caller is not the owner. Replay protection is the implementation's
   * responsibility, and `solution` is not signed by the owner.
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
