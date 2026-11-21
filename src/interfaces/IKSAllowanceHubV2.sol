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
  error NotExclusiveCallerOrOwner(address caller);

  /// @notice The order's expiration has passed
  error OrderExpired(uint256 expiration, uint256 currentTime);

  /// @notice The solution's expiration has passed
  error SolutionExpired(uint256 expiration, uint256 currentTime);

  /// @notice The owner's signature is not valid for the order
  error InvalidOrderSignature();

  /// @notice The solution signature is not valid for the `solutionApprover` the order specifies
  error InvalidSolutionSignature();

  /// @notice The amount the solution specifies for an ERC20 transfer exceeds its allowance
  error ERC20AllowanceExceeded(uint256 index, uint256 amount, uint256 allowance);

  /**
   * @notice Emitted once for each settled order, before its assets move and its calls run
   * @dev Each ERC20 and ERC721 entry pairs a transfer of the order with the target the solution
   * specifies for it. `nativeTransfers` lists only the calls to which the solution's `callValues`
   * give native value, in order, and is empty when it gives none.
   *
   * An order settled by a callee call of another order emits its event after the other order's
   * and before that order's remaining calls run.
   */
  event SettleOrder(
    address indexed caller,
    address indexed owner,
    bytes32 indexed orderHash,
    ERC20Transfer[] erc20Transfers,
    ERC721Transfer[] erc721Transfers,
    NativeTransfer[] nativeTransfers,
    bytes clientData
  );

  /// @notice Emitted when assets held by the hub are transferred out, with the amount each ERC20
  /// entry transferred
  event RescueTokens(ERC20Transfer[] erc20Transfers, ERC721Transfer[] erc721Transfers);

  /**
   * @notice Settles an order with the targets, amounts and solver data in `solution`, authorized
   * as `order.authenticator` specifies
   * @dev The owner's own call bypasses `order.exclusiveCaller`, and with the zero address as
   * `order.authenticator` does not spend a zero `order.nonce`.
   * @param order The order to settle
   * @param authenticationData The owner's signature over the order, the owner's Permit2 signature,
   * or the credential the authenticator reads
   * @param solution The target of each transfer, the amount of each ERC20 transfer and the data of
   * each call the solver chose
   * @param solutionSignature The `solutionApprover`'s signature over the {SolutionApproval}
   * @param usePermit2Allowances Whether the ERC20 transfers are drawn from the owner's Permit2
   * allowances instead of the owner's allowances to this hub
   * @return results Return data of each call, in order
   */
  function settleOrder(
    AHV2Order calldata order,
    bytes calldata authenticationData,
    AHV2Solution calldata solution,
    bytes calldata solutionSignature,
    bool usePermit2Allowances
  ) external payable returns (bytes[] memory results);

  /**
   * @notice Calls {IMulticall3-aggregate3} with `calls`
   * @dev Accepted while the hub is paused. Native value sent with the call remains in the hub.
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
   * @dev An ERC20 entry with a zero `amount` transfers the hub's whole balance of `token`.
   * @param erc20Transfers ERC20 and native entries
   * @param erc721Transfers ERC721 entries
   */
  function rescueTokens(
    ERC20Transfer[] calldata erc20Transfers,
    ERC721Transfer[] calldata erc721Transfers
  ) external;
}
