// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ERC20Transfer} from '../types/ERC20Transfer.sol';
import {ERC721Transfer} from '../types/ERC721Transfer.sol';
import {ExecutionOrder} from '../types/ExecutionOrder.sol';
import {FulfillmentOrder} from '../types/FulfillmentOrder.sol';
import {FulfillmentSolution} from '../types/FulfillmentSolution.sol';
import {NativeTransfer} from '../types/NativeTransfer.sol';

/// @title IKSAllowanceHubV2
/// @notice Interface of {KSAllowanceHubV2}
interface IKSAllowanceHubV2 {
  /// @notice The order named a different relayer than the one submitting it
  error UnauthorizedRelayer(address caller, address relayer);

  /// @notice The order named a different solver than the one submitting it
  error UnauthorizedSolver(address caller, address solver);

  /// @notice The solution was not approved by the `solutionApprover` the order names
  error InvalidSolutionSignature();

  /**
   * @notice Emitted once per order, before its transfers and calls run
   * @dev `nativeTransfers` lists only the calls carrying value, so an order with none emits an
   * empty array rather than a run of zeros.
   */
  event TransferTokens(
    address indexed caller,
    address indexed owner,
    bytes32 indexed orderHash,
    ERC20Transfer[] erc20Transfers,
    ERC721Transfer[] erc721Transfers,
    NativeTransfer[] nativeTransfers
  );

  /**
   * @notice Pulls the owner's assets and runs the order's calls, authenticated by a delegated
   * {IOrderAuthenticator} rather than by a Permit2 signature
   * @dev The hub checks that `owner` delegated `authenticator` and that the caller is the
   * `order.relayer`, the owner themselves, or anyone when the order leaves the field open; the
   * authenticator must revert when `authenticationData` does not authenticate the order, and owns
   * its own replay protection. A credential states that the owner authorised the order, not who
   * may submit it, so the hub enforces that itself rather than leaving it to the authenticator.
   * @param order What the owner signed, including who may submit it
   * @param authenticator The delegated authenticator to consult
   * @param authenticationData Credential and signature, in whatever shape that authenticator reads
   * @param usePermit2Allowances Draw the ERC20 legs on the owner's Permit2 allowance rather than on
   * a plain allowance to this hub
   * @return results Return data of each router call, in order
   */
  function executeOrderWithDelegatedAuthentication(
    ExecutionOrder calldata order,
    address authenticator,
    bytes calldata authenticationData,
    bool usePermit2Allowances
  ) external payable returns (bytes[] memory results);

  /**
   * @notice Pulls the owner's assets and runs the order's calls, funded by the owner's Permit2
   * signature
   * @param order What the owner signed
   * @param permit2Signature The owner's Permit2 signature over the permit, and over the order as
   * its witness when relayed
   * @return results Return data of each router call, in order
   */
  function executeOrderWithPermit2Signature(
    ExecutionOrder calldata order,
    bytes calldata permit2Signature
  ) external payable returns (bytes[] memory results);

  /**
   * @notice Settles a fulfillment authenticated by a delegated {IOrderAuthenticator}: a solver
   * supplies the route, the owner's validators bound it, and the owner's own tail runs after
   * @dev The validators run between the two call lists, so they measure the solver's work before
   * `order.ownerCalls` acts on it. The owner's tail is not validated, by design. As on the
   * execution rail, the caller must be the `order.solver`, the owner themselves, or anyone when the
   * order leaves the field open.
   * @param order What the owner signed, including the validators, their own tail and which
   * account may solve it
   * @param authenticator The delegated authenticator to consult
   * @param authenticationData Credential and signature, in whatever shape that authenticator reads
   * @param solution The route the solver chose
   * @param solutionSignature Approval of `solution` by the `solutionApprover` the order names
   * @param usePermit2Allowances Draw the ERC20 legs on the owner's Permit2 allowance rather than on
   * a plain allowance to this hub
   * @return results Return data of every router call, the solution's first then the owner's
   */
  function fulfillOrderWithDelegatedAuthentication(
    FulfillmentOrder calldata order,
    address authenticator,
    bytes calldata authenticationData,
    FulfillmentSolution calldata solution,
    bytes calldata solutionSignature,
    bool usePermit2Allowances
  ) external payable returns (bytes[] memory results);

  /**
   * @notice As {fulfillOrderWithDelegatedAuthentication}, but funded by the owner's Permit2
   * signature
   * @param order What the owner signed
   * @param permit2Signature The owner's Permit2 signature over the permit, and over the order as
   * its witness when relayed
   * @param solution The route the solver chose
   * @param solutionSignature Approval of `solution` by the `solutionApprover` the order names
   * @return results Return data of every router call, the solution's first then the owner's
   */
  function fulfillOrderWithPermit2Signature(
    FulfillmentOrder calldata order,
    bytes calldata permit2Signature,
    FulfillmentSolution calldata solution,
    bytes calldata solutionSignature
  ) external payable returns (bytes[] memory results);
}
