// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ERC20Params} from '../types/ERC20Params.sol';
import {ERC721Params} from '../types/ERC721Params.sol';
import {GenericCall} from '../types/GenericCall.sol';

import {ISignatureTransfer} from 'ks-common-sc/src/interfaces/ISignatureTransfer.sol';

/// @title IKSAllowanceHub
/// @notice Interface for the KSAllowanceHub
interface IKSAllowanceHub {
  /// @notice Thrown when the native tokens are overspent
  error NativeTokenOverspent();

  /**
   * @notice Permits, transfers ERC20 and ERC721 tokens, executes generic calls
   * @param erc20Params The ERC20 tokens to transfer
   * @param erc721Params The ERC721 tokens to transfer
   * @param genericCalls The generic calls to execute
   * @return results The results of the generic calls
   */
  function permitTransferAndExecute(
    ERC20Params[] calldata erc20Params,
    ERC721Params[] calldata erc721Params,
    GenericCall[] calldata genericCalls
  ) external payable returns (bytes[] memory results);

  /**
   * @notice Transfers ERC20 tokens using Permit2
   * @notice Permits and transfers ERC721 tokens
   * @notice Executes generic calls on behalf of the owner
   * @param permit The permit data for transferring the ERC20 tokens
   * @param targets The addresses to transfer the tokens to
   * @param erc721Params The ERC721 tokens to transfer
   * @param genericCalls The generic calls to execute
   * @param owner The owner of the tokens
   * @param signature The signature of the owner
   * @return results The results of the generic calls
   */
  function permit2TransferAndExecute(
    ISignatureTransfer.PermitBatchTransferFrom calldata permit,
    address[] calldata targets,
    ERC721Params[] calldata erc721Params,
    GenericCall[] calldata genericCalls,
    address owner,
    bytes calldata signature
  ) external payable returns (bytes[] memory results);

  /// @notice Returns the address of the Permit2 contract
  function PERMIT2() external view returns (ISignatureTransfer);
}
