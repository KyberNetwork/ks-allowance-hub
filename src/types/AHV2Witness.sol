// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {CallParams, CallParamsLib} from './CallParams.sol';
import {ERC721Approval, ERC721ApprovalLib} from './ERC721Approval.sol';
import {HookParams, HookParamsLib} from './HookParams.sol';

import {ISignatureTransfer} from 'ks-common-sc/src/interfaces/ISignatureTransfer.sol';

import {EfficientHashLib} from 'solady/utils/EfficientHashLib.sol';

/**
 * @notice Witness the owner's Permit2 signature covers when another account submits
 * {IKSAllowanceHubV2-settleOrderWithPermit2Signature}
 * @dev Covers the parts of the order the permit does not; the permit covers the ERC20 tokens and
 * amounts. The route and the targets of the transfers are not covered; the witness specifies the
 * exclusive caller, the hooks and the solution approver instead.
 * @param exclusiveCaller Account that may submit the order; the dead address allows any account
 * @param erc721Approvals ERC721 transfers
 * @param hooks Hooks of the order
 * @param ownerCalls Callee calls fixed by the owner
 * @param solutionApprover Account whose signature the solution requires; the dead address requires
 * none
 * @param clientData The order's client data
 */
struct AHV2Witness {
  address exclusiveCaller;
  ERC721Approval[] erc721Approvals;
  HookParams[] hooks;
  CallParams[] ownerCalls;
  address solutionApprover;
  bytes clientData;
}

/**
 * @notice The struct Permit2 hashes for an order's witness permit
 * @param permitted Tokens and amounts the permit covers
 * @param spender Account that may transfer them
 * @param nonce Permit2 nonce
 * @param deadline Last timestamp at which the permit may be used
 * @param witness The order's witness
 */
struct PermitBatchWitnessTransferFrom {
  ISignatureTransfer.TokenPermissions[] permitted;
  address spender;
  uint256 nonce;
  uint256 deadline;
  AHV2Witness witness;
}

library AHV2WitnessLib {
  using CallParamsLib for CallParams[];
  using EfficientHashLib for bytes;
  using ERC721ApprovalLib for ERC721Approval[];
  using HookParamsLib for HookParams[];

  string internal constant AHV2_WITNESS_PERMIT2_TYPE_STRING = 'AHV2Witness witness)'
    'AHV2Witness(address exclusiveCaller,ERC721Approval[] erc721Approvals,HookParams[] hooks,CallParams[] ownerCalls,address solutionApprover,bytes clientData)'
    'CallParams(address callee,uint256 value,bytes data)'
    'ERC721Approval(address token,uint256 tokenId)'
    'HookParams(address hook,bytes32 flags,bytes data)'
    'TokenPermissions(address token,uint256 amount)';

  bytes32 internal constant AHV2_WITNESS_TYPEHASH = keccak256(
    'AHV2Witness(address exclusiveCaller,ERC721Approval[] erc721Approvals,HookParams[] hooks,CallParams[] ownerCalls,address solutionApprover,bytes clientData)'
    'CallParams(address callee,uint256 value,bytes data)'
    'ERC721Approval(address token,uint256 tokenId)'
    'HookParams(address hook,bytes32 flags,bytes data)'
  );

  /// @dev EIP-712 hash of the witness
  function hash(
    address exclusiveCaller,
    ERC721Approval[] calldata erc721Approvals,
    HookParams[] calldata hooks,
    CallParams[] calldata ownerCalls,
    address solutionApprover,
    bytes calldata clientData
  ) internal pure returns (bytes32) {
    return hash(
      exclusiveCaller,
      erc721Approvals.hash(),
      hooks.hash(),
      ownerCalls.hash(),
      solutionApprover,
      clientData.hashCalldata()
    );
  }

  /// @dev As {hash}, from the already computed hashes of the array and bytes members
  function hash(
    address exclusiveCaller,
    bytes32 erc721ApprovalsHash,
    bytes32 hooksHash,
    bytes32 ownerCallsHash,
    address solutionApprover,
    bytes32 clientDataHash
  ) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(
        AHV2_WITNESS_TYPEHASH,
        exclusiveCaller,
        erc721ApprovalsHash,
        hooksHash,
        ownerCallsHash,
        solutionApprover,
        clientDataHash
      )
    );
  }
}
