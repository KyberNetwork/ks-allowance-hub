// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {PackedBits} from '../../base/types/PackedBits.sol';

import {ERC20Transfer} from '../types/ERC20Transfer.sol';
import {ERC721Transfer} from '../types/ERC721Transfer.sol';
import {ExecutionOrder} from '../types/ExecutionOrder.sol';
import {FulfillmentOrder} from '../types/FulfillmentOrder.sol';
import {FulfillmentSolution} from '../types/FulfillmentSolution.sol';
import {NativeTransfer} from '../types/NativeTransfer.sol';

/// @title IKSAllowanceHubV2
/// @notice Interface of {KSAllowanceHubV2}
interface IKSAllowanceHubV2 {
  /// @notice The caller is neither the order's owner nor its relayer, and the order names a relayer
  error UnauthorizedRelayer(address caller);

  /// @notice The caller is neither the order's owner nor its solver, and the order names a solver
  error UnauthorizedSolver(address caller);

  /// @notice The solution signature is not valid for the `solutionApprover` the order names
  error InvalidSolutionSignature();

  /**
   * @notice Emitted once for each settled order, before its assets move and its calls run
   * @dev For a fulfillment, each ERC20 and ERC721 entry pairs a leg of the order with the target
   * the solution names for it. `nativeTransfers` lists only the calls that carry native value, the
   * solver's calls before the owner's, and is empty when no call carries value.
   *
   * An order settled by a router call of an execution emits its event after the execution's and
   * before the execution's remaining calls run.
   */
  event TransferTokens(
    address indexed caller,
    address indexed owner,
    bytes32 indexed orderHash,
    ERC20Transfer[] erc20Transfers,
    ERC721Transfer[] erc721Transfers,
    NativeTransfer[] nativeTransfers
  );

  /// @notice Emitted when assets held by the hub are transferred out, with the entries as given
  event RescueTokens(ERC20Transfer[] erc20Transfers, ERC721Transfer[] erc721Transfers);

  /**
   * @notice Settles an execution order authenticated by an {IOrderAuthenticator} the owner has
   * delegated
   * @dev `authenticator` must be delegated by `order.owner`, or be the zero address.
   *
   * When the caller is `order.owner`, the call is the authentication: the authenticator is not
   * called, `authenticationData` is ignored, `order.relayer` does not apply and no nonce is spent,
   * so the owner may settle the same order more than once.
   *
   * Any other caller must be `order.relayer`, or any account when `order.relayer` is the dead
   * address, and the authenticator must accept `authenticationData` for the order. The hub does
   * not spend `order.nonce`; replay protection is the authenticator's.
   * @param order The order to settle
   * @param authenticator The authenticator that checks `authenticationData`
   * @param authenticationData Credential and signature, in the encoding the authenticator reads
   * @param usePermit2Allowances Whether the ERC20 legs are drawn from the owner's Permit2
   * allowances instead of the owner's allowances to this hub
   * @return results Return data of each router call, in order
   */
  function executeOrderWithDelegatedAuthentication(
    ExecutionOrder calldata order,
    address authenticator,
    bytes calldata authenticationData,
    bool usePermit2Allowances
  ) external payable returns (bytes[] memory results);

  /**
   * @notice Settles an execution order authorised by the owner's Permit2 signature
   * @dev The ERC20 legs are transferred through a Permit2 batch permit whose nonce is
   * `order.nonce` and whose deadline is `order.deadline`.
   *
   * When the caller is `order.owner`, `permit2Signature` signs the permit alone. Any other caller
   * must be `order.relayer`, or any account when `order.relayer` is the dead address, and
   * `permit2Signature` must also sign the order's {ExecutionWitness}.
   * @param order The order to settle
   * @param permit2Signature The owner's Permit2 signature
   * @return results Return data of each router call, in order
   */
  function executeOrderWithPermit2Signature(
    ExecutionOrder calldata order,
    bytes calldata permit2Signature
  ) external payable returns (bytes[] memory results);

  /**
   * @notice Settles a fulfillment order authenticated by an {IOrderAuthenticator} the owner has
   * delegated, along the route in `solution`
   * @dev The settlement runs in this order: the solution approval is checked, each validator's
   * `beforeExecution` runs, the legs move to the targets `solution` names, `solution.solverCalls`
   * run, each validator's `afterExecution` runs, and `order.ownerCalls` run. The validators do not
   * observe the effects of `order.ownerCalls`.
   *
   * `solution` must name one target for each leg and must not have passed its own deadline. The
   * approval is checked against `order.solutionApprover`, and is not required when that is the
   * dead address. The approval carries no nonce, so it remains valid until the settlement of its
   * order.
   *
   * The caller and the authenticator are treated as in {executeOrderWithDelegatedAuthentication},
   * with `order.solver` in place of `order.relayer`. When the caller is `order.owner`, the solution
   * approval is still required.
   * @param order The order to settle
   * @param authenticator The authenticator that checks `authenticationData`
   * @param authenticationData Credential and signature, in the encoding the authenticator reads
   * @param solution The route and the leg targets the solver chose
   * @param solutionSignature The `solutionApprover`'s signature over the {SolutionApproval}
   * @param usePermit2Allowances Whether the ERC20 legs are drawn from the owner's Permit2
   * allowances instead of the owner's allowances to this hub
   * @return results Return data of each router call, the solver's calls first
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
   * @notice Settles a fulfillment order authorised by the owner's Permit2 signature, along the
   * route in `solution`
   * @dev The settlement and the solution approval are as in
   * {fulfillOrderWithDelegatedAuthentication}. The ERC20 legs are transferred through a Permit2
   * batch permit whose nonce is `order.nonce` and whose deadline is `order.deadline`.
   *
   * When the caller is `order.owner`, `permit2Signature` signs the permit alone. Any other caller
   * must be `order.solver`, or any account when `order.solver` is the dead address, and
   * `permit2Signature` must also sign the order's {FulfillmentWitness}.
   * @param order The order to settle
   * @param permit2Signature The owner's Permit2 signature
   * @param solution The route and the leg targets the solver chose
   * @param solutionSignature The `solutionApprover`'s signature over the {SolutionApproval}
   * @return results Return data of each router call, the solver's calls first
   */
  function fulfillOrderWithPermit2Signature(
    FulfillmentOrder calldata order,
    bytes calldata permit2Signature,
    FulfillmentSolution calldata solution,
    bytes calldata solutionSignature
  ) external payable returns (bytes[] memory results);

  /**
   * @notice Calls {ICallsForwarder-forwardCalls} on the forwarder set at deployment, so that it can
   * run in a {IMulticall-multicall} batch
   * @dev Native value sent with the call remains in the hub. Accepted while the hub is paused.
   * @param targets Passed to the forwarder unchanged
   * @param data Passed to the forwarder unchanged
   * @param allowFailure Passed to the forwarder unchanged
   * @return results The forwarder's results
   */
  function forwardCalls(address[] calldata targets, bytes[] calldata data, PackedBits allowFailure)
    external
    payable
    returns (bytes[] memory results);

  /**
   * @notice Transfers assets held by the hub to the given targets; callable by an account with the
   * rescuer role or by the default admin
   * @dev An ERC20 entry with a zero `amount` transfers the hub's entire balance of `token`. An entry
   * whose `token` is the native-token address or the zero address transfers native value. A zero
   * `target` is not refused.
   * @param erc20Transfers ERC20 and native entries
   * @param erc721Transfers ERC721 entries
   */
  function rescueTokens(
    ERC20Transfer[] calldata erc20Transfers,
    ERC721Transfer[] calldata erc721Transfers
  ) external;
}
