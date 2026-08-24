// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ERC20Params} from '../types/ERC20Params.sol';
import {ERC20Transfer} from '../types/ERC20Transfer.sol';
import {ERC721Params} from '../types/ERC721Params.sol';
import {ERC721Transfer} from '../types/ERC721Transfer.sol';
import {GenericCall} from '../types/GenericCall.sol';
import {NativeTransfer} from '../types/NativeTransfer.sol';
import {ValidationParams} from '../types/ValidationParams.sol';

import {ISignatureTransfer} from 'ks-common-sc/src/interfaces/ISignatureTransfer.sol';

/**
 * @title IKSAllowanceHubV2
 * @notice Interface for the KS Allowance Hub V2
 */
interface IKSAllowanceHubV2 {
  /// @notice Thrown when a call spends more native token than the `msg.value` it was sent with
  error NativeTokenOverspent();

  /// @notice Thrown when a locking entrypoint is entered while another one is still executing
  error AlreadyLocked();

  /**
   * @notice Emitted once per entrypoint call, before the generic calls are executed
   * @param caller The address that invoked the hub
   * @param owner The address the tokens are pulled from
   * @param msgValue The native token amount sent along with the call
   * @param erc20Transfers The ERC20 transfers performed on behalf of `owner`
   * @param erc721Transfers The ERC721 transfers performed on behalf of `owner`
   * @param nativeTransfers The native token amounts forwarded to each generic call
   */
  event TransferTokens(
    address indexed caller,
    address indexed owner,
    uint256 msgValue,
    ERC20Transfer[] erc20Transfers,
    ERC721Transfer[] erc721Transfers,
    NativeTransfer[] nativeTransfers
  );

  /**
   * @notice Relays ERC20 permits that approve Permit2 on the signers' behalf
   * @dev Batch with the flow itself through `multicall` to spare the owner a transaction. A
   * reverting permit is skipped, since another submitter may already have applied it.
   * @param tokens The tokens to permit, index-aligned with `permitData`
   * @param owner The address whose permits these are
   * @param permitData EIP-2612 (5 words) or DAI-style (6 words) permit payloads
   */
  function permitTokensToPermit2(
    address[] calldata tokens,
    address owner,
    bytes[] calldata permitData
  ) external;

  /**
   * @notice Permits and transfers ERC20 and ERC721 tokens from `msg.sender`, then executes the
   * generic calls
   * @dev Tokens are pulled from `msg.sender`, so the caller is always the token owner here.
   * Requires either a permit in `permitData` or a pre-existing allowance to the hub.
   * @param erc20Params The ERC20 tokens to permit and transfer
   * @param erc721Params The ERC721 tokens to permit and transfer
   * @param genericCalls The generic calls to execute
   * @return results The return data of each generic call, in the same order
   * @return gasUsed The gas consumed by the body of the call
   */
  function permitTransferAndExecute(
    ERC20Params[] calldata erc20Params,
    ERC721Params[] calldata erc721Params,
    GenericCall[] calldata genericCalls
  ) external payable returns (bytes[] memory results, uint256 gasUsed);

  /**
   * @notice Transfers ERC20 tokens from `owner` via Permit2, permits and transfers ERC721 tokens,
   * then executes the generic calls on behalf of `owner`
   * @dev When the owner is the caller its own transaction pins everything, so no witness is used
   * and `permissionless` is ignored. Otherwise the signature must also cover a `RelayerWitness`
   * pinning the submitter, the ERC20 targets, the ERC721 transfers and the generic calls; setting
   * `permissionless` names `ANY_ADDRESS` there so anyone may relay a batch that stays fully pinned.
   * @param permit The Permit2 batch permit covering the ERC20 tokens to transfer
   * @param targets The addresses to transfer each permitted ERC20 token to, index-aligned with
   * `permit.permitted`
   * @param erc721Params The ERC721 tokens to permit and transfer
   * @param genericCalls The generic calls to execute
   * @param owner The owner of the tokens
   * @param permissionless Whether the witness names `ANY_ADDRESS` rather than a specific relayer,
   * ignored when the owner is the caller
   * @param signature The owner's Permit2 signature
   * @return results The return data of each generic call, in the same order
   * @return gasUsed The gas consumed by the body of the call
   */
  function permit2TransferAndExecute(
    ISignatureTransfer.PermitBatchTransferFrom calldata permit,
    address[] calldata targets,
    ERC721Params[] calldata erc721Params,
    GenericCall[] calldata genericCalls,
    address owner,
    bool permissionless,
    bytes calldata signature
  ) external payable returns (bytes[] memory results, uint256 gasUsed);

  /**
   * @notice Transfers the owner's tokens to a solver via Permit2, then lets the solver fulfill
   * the intent with generic calls whose outcome is enforced by the signed validators
   * @dev Unlike `permit2TransferAndExecute`, the `SolverWitness` does NOT cover `genericCalls`: the
   * owner signs the funding and the acceptance criteria, and the solver chooses the path.
   * @dev The witness pins the solver and the calls signer, both of which the owner may set to
   * `ANY_ADDRESS` to leave open. Leaving both open, with no `validationParams`, lets any caller
   * take the funding and do as it likes.
   * @param permit The Permit2 batch permit covering the ERC20 tokens to transfer
   * @param targets The addresses to transfer each permitted ERC20 token to, index-aligned with
   * `permit.permitted`
   * @param erc721Params The ERC721 tokens to permit and transfer
   * @param validationParams The validators enforcing the intent's outcome
   * @param owner The owner of the tokens
   * @param permissionless Whether the witness names `ANY_ADDRESS` rather than a specific solver
   * @param ownerSignature The owner's Permit2 signature over the `SolverWitness`
   * @param genericCalls The generic calls the solver uses to fulfill the intent
   * @param callsSignature A signature over
   * `keccak256(abi.encode(block.chainid, genericCalls, permit.deadline))`, or empty to leave the
   * call list open. The recovered signer must match the witness
   * @return results The return data of each generic call, in the same order
   * @return gasUsed The gas consumed by the body of the call
   */
  function permit2TransferAndFulfill(
    ISignatureTransfer.PermitBatchTransferFrom calldata permit,
    address[] calldata targets,
    ERC721Params[] calldata erc721Params,
    ValidationParams[] calldata validationParams,
    address owner,
    bool permissionless,
    bytes calldata ownerSignature,
    GenericCall[] calldata genericCalls,
    bytes calldata callsSignature
  ) external payable returns (bytes[] memory results, uint256 gasUsed);

  /// @notice Returns the address of the Permit2 contract
  function PERMIT2() external view returns (ISignatureTransfer);

  /**
   * @notice Returns the owner of the tokens being spent by the call currently in progress
   * @dev Routers call this to identify the user on whose behalf they are executing, since the hub
   * — not the user — is their `msg.sender`.
   * @return The token owner while a locking entrypoint is executing, `address(0)` otherwise
   */
  function msgSender() external view returns (address);
}
