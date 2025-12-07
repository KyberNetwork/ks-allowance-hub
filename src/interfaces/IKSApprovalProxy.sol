// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ERC20Params} from '../types/ERC20Params.sol';
import {ERC721Params} from '../types/ERC721Params.sol';
import {GenericCall} from '../types/GenericCall.sol';

import {ISignatureTransfer} from 'ks-common-sc/src/interfaces/ISignatureTransfer.sol';

/// @title IKSApprovalProxy
/// @notice Interface for the KSApprovalProxy
interface IKSApprovalProxy {
  /// @notice Thrown when the deadline is passed
  error DeadlinePassed(uint256 deadline, uint256 blockTimestamp);

  /// @notice Permits, transfers ERC20 and ERC721 tokens, executes generic calls
  function permitTransferAndExecute(
    ERC20Params[] calldata erc20Params,
    ERC721Params[] calldata erc721Params,
    GenericCall[] calldata genericCalls
  ) external payable returns (bytes[] memory results);

  /// @notice Transfers ERC20 tokens using Permit2, permits and transfers ERC721 tokens, executes generic calls
  function permit2TransferAndExecute(
    ISignatureTransfer.PermitBatchTransferFrom calldata permit,
    address[] calldata targets,
    ERC721Params[] calldata erc721Params,
    GenericCall[] calldata genericCalls,
    bytes calldata signature
  ) external payable returns (bytes[] memory results);

  /// @notice Relays Permit2 transfer and generic calls execution on behalf of the owner
  function relayPermit2TransferAndExecute(
    ISignatureTransfer.PermitBatchTransferFrom memory permit,
    address[] calldata targets,
    ERC721Params[] calldata erc721Params,
    GenericCall[] calldata genericCalls,
    address owner,
    bytes calldata signature
  ) external payable returns (bytes[] memory results);

  /// @notice Returns the address of the Permit2 contract
  function PERMIT2() external view returns (ISignatureTransfer);
}
