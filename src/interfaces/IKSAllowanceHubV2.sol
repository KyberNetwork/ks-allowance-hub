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
   * @dev `authenticator` must be delegated by `order.owner`, or be the zero address. The owner's
   * own call needs no authentication and spends no nonce.
   * @param order The order to settle
   * @param authenticator The authenticator that checks `authenticationData`
   * @param authenticationData Credential and signature, in the encoding the authenticator reads
   * @param solution The route, the target of each transfer, the amount of each ERC20 transfer and
   * the data of each owner call the solver chose
   * @param solutionSignature The `solutionApprover`'s signature over the {SolutionApproval}; not
   * read when the caller is `order.owner` or `order.solutionApprover` is the zero address
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
   * @dev `permit2Signature` must also sign the order's {AHV2Witness} unless the caller is the
   * owner.
   * @param order The order to settle
   * @param permit2Signature The owner's Permit2 signature
   * @param solution The route, the target of each transfer, the amount of each ERC20 transfer and
   * the data of each owner call the solver chose
   * @param solutionSignature The `solutionApprover`'s signature over the {SolutionApproval}; not
   * read when the caller is `order.owner` or `order.solutionApprover` is the zero address
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
