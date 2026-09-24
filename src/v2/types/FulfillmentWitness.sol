// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ERC721Transfer, ERC721TransferLibrary} from './ERC721Transfer.sol';
import {ValidationParams, ValidationParamsLibrary} from './ValidationParams.sol';

/**
 * @notice Attached to the owner's Permit2 signature on a relayed {KSAllowanceHubV2-transferAndFulfill}
 * @dev Deliberately does not pin the calls: it names who may choose them (`callsSigner`) and the
 * validators that bound the result, leaving the route to the solver.
 */
struct FulfillmentWitness {
  address solver;
  address[] erc20Targets;
  ERC721Transfer[] erc721Transfers;
  ValidationParams[] validationParams;
  address callsSigner;
}

using FulfillmentWitnessLibrary for FulfillmentWitness global;

library FulfillmentWitnessLibrary {
  using ERC721TransferLibrary for ERC721Transfer[];
  using ValidationParamsLibrary for ValidationParams[];

  string internal constant FULFILLMENT_WITNESS_PERMIT2_TYPE_STRING = 'FulfillmentWitness witness)'
    'ERC721Transfer(address token,uint256 tokenId,address target)'
    'FulfillmentWitness(address solver,address[] erc20Targets,ERC721Transfer[] erc721Transfers,ValidationParams[] validationParams,address callsSigner)'
    'TokenPermissions(address token,uint256 amount)'
    'ValidationParams(address validator,bytes32 action,bytes beforeExecutionInput,bytes afterExecutionInput)';

  bytes32 internal constant FULFILLMENT_WITNESS_TYPEHASH = keccak256(
    'FulfillmentWitness(address solver,address[] erc20Targets,ERC721Transfer[] erc721Transfers,ValidationParams[] validationParams,address callsSigner)'
    'ERC721Transfer(address token,uint256 tokenId,address target)'
    'ValidationParams(address validator,bytes32 action,bytes beforeExecutionInput,bytes afterExecutionInput)'
  );

  /// @dev EIP-712 hash of the witness attached to the owner's Permit2 signature
  function hash(
    address solver,
    address[] memory erc20Targets,
    ERC721Transfer[] calldata erc721Transfers,
    ValidationParams[] calldata validationParams,
    address callsSigner
  ) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(
        FULFILLMENT_WITNESS_TYPEHASH,
        solver,
        keccak256(abi.encodePacked(erc20Targets)),
        erc721Transfers.hash(),
        validationParams.hash(),
        callsSigner
      )
    );
  }

  /// @dev As {hash}, for arrays already in memory
  function hashMemory(
    address solver,
    address[] memory erc20Targets,
    ERC721Transfer[] memory erc721Transfers,
    ValidationParams[] memory validationParams,
    address callsSigner
  ) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(
        FULFILLMENT_WITNESS_TYPEHASH,
        solver,
        keccak256(abi.encodePacked(erc20Targets)),
        erc721Transfers.hashMemory(),
        validationParams.hashMemory(),
        callsSigner
      )
    );
  }
}
