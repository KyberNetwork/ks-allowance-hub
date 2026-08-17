// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ERC721Transfer} from './ERC721Transfer.sol';
import {ValidationParams} from './ValidationParams.sol';

/**
 * @notice The extra data an owner signs when a solver fills their intent, pinning the solver, the
 * funding it receives and the criteria its fill is judged by
 * @dev Deliberately carries no generic calls: the owner signs the outcome it wants, and the solver
 * chooses how to reach it. `validationParams` is therefore the only constraint on the fill.
 * @param solver The only address allowed to submit the signature
 * @param targets The addresses the permitted ERC20 tokens must be transferred to
 * @param erc721Transfers The ERC721 movements funding the fill
 * @param validationParams The acceptance criteria the fill must satisfy
 */
struct SolverWitness {
  address solver;
  address[] targets;
  ERC721Transfer[] erc721Transfers;
  ValidationParams[] validationParams;
}

using SolverWitnessLibrary for SolverWitness global;

/// @notice Contains functions for working with SolverWitness
library SolverWitnessLibrary {
  /// @dev The Permit2 witness type string, with the referenced structs sorted alphabetically
  string internal constant SOLVER_WITNESS_PERMIT2_TYPE_STRING =
    'SolverWitness witness)ERC721Transfer(address token,uint256 tokenId,address target)SolverWitness(address solver,address[] targets,ERC721Transfer[] erc721Transfers,ValidationParams[] validationParams)TokenPermissions(address token,uint256 amount)ValidationParams(address validator,bytes32 action,bytes beforeExecutionInput,bytes afterExecutionInput)';

  /// @dev The EIP-712 type hash of `SolverWitness`, including its referenced struct definitions
  bytes32 internal constant SOLVER_WITNESS_TYPEHASH = keccak256(
    'SolverWitness(address solver,address[] targets,ERC721Transfer[] erc721Transfers,ValidationParams[] validationParams)ERC721Transfer(address token,uint256 tokenId,address target)ValidationParams(address validator,bytes32 action,bytes beforeExecutionInput,bytes afterExecutionInput)'
  );

  /**
   * @notice Hashes the witness fields following EIP-712 struct encoding
   * @dev Takes the fields loose rather than as a struct so callers can hash what they already hold
   * without copying it into one.
   * @param solver The only address allowed to submit the signature
   * @param targets The addresses the permitted ERC20 tokens must be transferred to
   * @param erc721Transfers The ERC721 movements funding the fill
   * @param validationParams The acceptance criteria the fill must satisfy
   * @return The EIP-712 hash of the witness
   */
  function hash(
    address solver,
    address[] memory targets,
    ERC721Transfer[] memory erc721Transfers,
    ValidationParams[] memory validationParams
  ) internal pure returns (bytes32) {
    // EIP-712 encodes an array of structs as the hash of its concatenated member hashes
    bytes32[] memory erc721TransfersHashes = new bytes32[](erc721Transfers.length);
    for (uint256 i = 0; i < erc721Transfers.length; i++) {
      erc721TransfersHashes[i] = erc721Transfers[i].hash();
    }

    bytes32[] memory validationParamsHashes = new bytes32[](validationParams.length);
    for (uint256 i = 0; i < validationParams.length; i++) {
      validationParamsHashes[i] = validationParams[i].hash();
    }

    return keccak256(
      abi.encode(
        SOLVER_WITNESS_TYPEHASH,
        solver,
        keccak256(abi.encodePacked(targets)),
        keccak256(abi.encodePacked(erc721TransfersHashes)),
        keccak256(abi.encodePacked(validationParamsHashes))
      )
    );
  }

  /**
   * @notice Hashes a witness following EIP-712 struct encoding
   * @param self The witness to hash
   * @return The EIP-712 hash of the witness
   */
  function hash(SolverWitness memory self) internal pure returns (bytes32) {
    return hash(self.solver, self.targets, self.erc721Transfers, self.validationParams);
  }
}
