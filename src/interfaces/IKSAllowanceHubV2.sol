// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {AHV2Order} from '../types/AHV2Order.sol';
import {AHV2Solution} from '../types/AHV2Solution.sol';
import {ERC20Transfer} from '../types/ERC20Transfer.sol';
import {ERC721Transfer} from '../types/ERC721Transfer.sol';
import {NativeTransfer} from '../types/NativeTransfer.sol';

import {IMulticall3} from 'forge-std/interfaces/IMulticall3.sol';

/// @title IKSAllowanceHubV2
/// @notice Interface of {KSAllowanceHubV2}
interface IKSAllowanceHubV2 {
  /// @notice The caller is neither the order's owner nor its exclusive caller, and the order
  /// specifies an exclusive caller
  error NotExclusiveCaller(address caller);

  /// @notice The solution signature is not valid for the `solutionApprover` the order specifies
  error InvalidSolutionSignature();

  /// @notice The amount the solution specifies for an ERC20 transfer exceeds its allowance
  error ERC20AllowanceExceeded(uint256 index, uint256 amount, uint256 allowance);

  /**
   * @notice Emitted once for each settled order, before its assets move and its calls run
   * @dev Each ERC20 and ERC721 entry pairs a transfer of the order with the target the solution
   * specifies for it. `nativeTransfers` lists only the calls that carry native value, the
   * solver's calls before the owner's, and is empty when no call carries value. `clientData` is
   * the order's client data.
   *
   * An order settled by a callee call of another order emits its event after the other order's
   * and before that order's remaining calls run.
   */
  event TransferTokens(
    address indexed caller,
    address indexed owner,
    bytes32 indexed orderHash,
    ERC20Transfer[] erc20Transfers,
    ERC721Transfer[] erc721Transfers,
    NativeTransfer[] nativeTransfers,
    bytes clientData
  );

  /// @notice Emitted when assets held by the hub are transferred out, with the entries as given
  event RescueTokens(ERC20Transfer[] erc20Transfers, ERC721Transfer[] erc721Transfers);

  /**
   * @notice Settles an order authenticated by an {IAHV2Authenticator} the owner has delegated,
   * along the route in `solution`
   * @dev `authenticator` must be delegated by `order.owner`, or be the zero address.
   *
   * The settlement runs in this order: the exclusive caller and the authentication are checked,
   * the solution approval, when required, is checked, each hook's `beforeSettlement` runs when its
   * flags select it, the assets move to the targets `solution` specifies, `solution.solverCalls`
   * run through `solverCall`, `order.ownerCalls` run through `ownerCall` with the matching entry
   * of `solution.solverData`, and each hook's `afterSettlement` runs when its flags select it.
   *
   * When the caller is `order.owner`, the call is the authentication: the authenticator is not
   * called, `authenticationData` is ignored, `order.exclusiveCaller` and the solution approval do
   * not apply and no nonce is spent, so the owner may settle the same order more than once. Any
   * other caller must be `order.exclusiveCaller`, or any account when `order.exclusiveCaller` is
   * the dead address, and the authenticator must accept `authenticationData` for the order. The
   * hub does not spend `order.nonce` and keeps no record of settled orders, so the authenticator
   * determines whether an order may be settled more than once.
   *
   * `solution` must specify one target and one amount for each transfer, one entry of
   * `solverData` for each owner call, and must not have passed its own expiration. Each ERC20
   * transfer sends `solution.erc20Amounts[i]`, at most its allowance. The approval is checked
   * against `order.solutionApprover`, and is not required when that is the dead address or the
   * caller is `order.owner`. The approval spends `solution.nonce` in the namespace of
   * `order.solutionApprover`, so each approval settles at most once. No nonce is spent when no
   * approval is required.
   * @param order The order to settle
   * @param authenticator The authenticator that checks `authenticationData`
   * @param authenticationData Credential and signature, in the encoding the authenticator reads
   * @param solution The route, the target of each transfer, the amount of each ERC20 transfer and
   * the data of each owner call the solver chose
   * @param solutionSignature The `solutionApprover`'s signature over the {SolutionApproval}; not
   * read when the caller is `order.owner` or `order.solutionApprover` is the dead address
   * @param usePermit2Allowances Whether the ERC20 transfers are drawn from the owner's Permit2
   * allowances instead of the owner's allowances to this hub
   * @return results Return data of each callee call, the solver's calls first
   */
  function settleOrderWithDelegatedAuthentication(
    AHV2Order calldata order,
    address authenticator,
    bytes calldata authenticationData,
    AHV2Solution calldata solution,
    bytes calldata solutionSignature,
    bool usePermit2Allowances
  ) external payable returns (bytes[] memory results);

  /**
   * @notice Settles an order authorized by the owner's Permit2 signature, along the route in
   * `solution`
   * @dev The settlement and the solution approval are as in
   * {settleOrderWithDelegatedAuthentication}. The ERC20 transfers are made through a Permit2
   * batch permit whose nonce is `order.nonce` and whose deadline is `order.expiration`. The
   * permit's permitted amounts are the order's allowances, and its requested amounts are
   * `solution.erc20Amounts`.
   *
   * When the caller is `order.owner`, `permit2Signature` signs the permit alone. Any other caller
   * must be `order.exclusiveCaller`, or any account when `order.exclusiveCaller` is the dead
   * address, and `permit2Signature` must also sign the order's {AHV2Witness}.
   * @param order The order to settle
   * @param permit2Signature The owner's Permit2 signature
   * @param solution The route, the target of each transfer, the amount of each ERC20 transfer and
   * the data of each owner call the solver chose
   * @param solutionSignature The `solutionApprover`'s signature over the {SolutionApproval}; not
   * read when the caller is `order.owner` or `order.solutionApprover` is the dead address
   * @return results Return data of each callee call, the solver's calls first
   */
  function settleOrderWithPermit2Signature(
    AHV2Order calldata order,
    bytes calldata permit2Signature,
    AHV2Solution calldata solution,
    bytes calldata solutionSignature
  ) external payable returns (bytes[] memory results);

  /**
   * @notice Calls {IMulticall3-aggregate3} with `calls`
   * @dev Includes calls to other contracts in a {IMulticall-multicall} batch. Native value sent
   * with the call remains in the hub. Accepted while the hub is paused.
   * @param calls Calls for Multicall3 to make
   * @return results Result of each call
   */
  function forwardCalls(IMulticall3.Call3[] calldata calls)
    external
    payable
    returns (IMulticall3.Result[] memory results);

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
