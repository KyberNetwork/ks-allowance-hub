// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {PackedBits} from '../../base/types/PackedBits.sol';
import {ERC20Transfer} from '../types/ERC20Transfer.sol';
import {ERC721Transfer} from '../types/ERC721Transfer.sol';
import {GenericCall} from '../types/GenericCall.sol';
import {NativeTransfer} from '../types/NativeTransfer.sol';
import {ValidationParams} from '../types/ValidationParams.sol';

import {ISignatureTransfer} from 'ks-common-sc/src/interfaces/ISignatureTransfer.sol';

/// @title IKSAllowanceHubV2
/// @notice Interface of {KSAllowanceHubV2}
interface IKSAllowanceHubV2 {
  /**
   * @notice Emitted once per settled order, before the router calls run
   * @dev `nativeTransfers` lists only the calls carrying value, so an order with none emits an
   * empty array.
   */
  event TransferTokens(
    address indexed caller,
    address indexed owner,
    ERC20Transfer[] erc20Transfers,
    ERC721Transfer[] erc721Transfers,
    NativeTransfer[] nativeTransfers
  );

  /**
   * @notice Pulls the owner's assets and runs a call list the owner has already approved
   * @param owner Account the assets come from; when it is the caller, no extra authorisation is needed
   * @param erc20Transfers ERC20 legs, moved from the owner to their targets
   * @param erc721Transfers ERC721 legs, moved from the owner to their targets
   * @param genericCalls Router calls to run, each bound by the owner's signature
   * @param deadline Last timestamp at which the order may settle
   * @param authFlags Selects the authorisation rail; bit layout in {KSAllowanceHubV2}
   * @param authData `abi.encode(nonce, signature)` for Permit2, otherwise
   * `abi.encode(verifier, nonce, key, signature)`
   * @return results Return data of each router call, in order
   * @return gasUsed Gas spent inside this call, excluding intrinsic and calldata cost
   */
  function transferAndExecute(
    address owner,
    ERC20Transfer[] calldata erc20Transfers,
    ERC721Transfer[] calldata erc721Transfers,
    GenericCall[] calldata genericCalls,
    uint256 deadline,
    PackedBits authFlags,
    bytes calldata authData
  ) external payable returns (bytes[] memory results, uint256 gasUsed);

  /**
   * @notice Pulls the owner's assets and lets a solver choose the calls, with validators bounding
   * the outcome instead of the owner signing the calls themselves
   * @param owner Account the assets come from
   * @param erc20Transfers ERC20 legs, moved from the owner to their targets
   * @param erc721Transfers ERC721 legs, moved from the owner to their targets
   * @param validationParams Validators run before and after execution; they are what the owner relies on
   * @param deadline Last timestamp at which the order may settle
   * @param authFlags Selects the authorisation rail; bit layout in {KSAllowanceHubV2}
   * @param authData Packed as for {transferAndExecute}
   * @param genericCalls Router calls chosen by the solver, covered by `callsSignature` when one is given
   * @param callsNonce Burned against `owner`, so one approval settles at most once
   * @param callsSignature Approval of `genericCalls`; empty means the owner allowed any calls
   * @return results Return data of each router call, in order
   * @return gasUsed Gas spent inside this call, excluding intrinsic and calldata cost
   */
  function transferAndFulfill(
    address owner,
    ERC20Transfer[] calldata erc20Transfers,
    ERC721Transfer[] calldata erc721Transfers,
    ValidationParams[] calldata validationParams,
    uint256 deadline,
    PackedBits authFlags,
    bytes calldata authData,
    GenericCall[] calldata genericCalls,
    uint256 callsNonce,
    bytes calldata callsSignature
  ) external payable returns (bytes[] memory results, uint256 gasUsed);
}
