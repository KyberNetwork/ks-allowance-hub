// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {CalldataHashLib} from '../libraries/CalldataHashLib.sol';

/**
 * @notice The target of each transfer, the amount of each ERC20 transfer, and the native value and
 * data of each call a solver chose for an {AHV2Order}
 * @dev The order's `solutionApprover` approves the solution instead of the owner signing it, so
 * the solution may be chosen after the order is signed. `erc20Targets[i]` receives
 * `erc20Amounts[i]` of `order.erc20Allowances[i]`, and `erc721Targets[i]` receives
 * `order.erc721Approvals[i]`. `erc20Targets`, `erc20Amounts` and `erc721Targets` must each have
 * one entry per transfer. `callValues` and `solverData` have one entry per call. No approval is
 * required when the order's `solutionApprover` is the zero address.
 * @param erc20Targets Target of each ERC20 transfer, in order
 * @param erc20Amounts Amount of each ERC20 transfer, in order; each is at most its allowance
 * @param erc721Targets Target of each ERC721 transfer, in order
 * @param callValues Native value sent with each of the order's calls, in order, paid from the
 * native value sent with the order
 * @param solverData Data the solver passes with each of the order's calls, as the `solverData`
 * argument of {IAHV2Callee-execute}, with one entry per call. The owner does not sign it. The
 * solution approval covers it when an approval is required.
 * @param nonce Nonce of the solution approval. The hub spends it in the `solutionApprover`'s
 * namespace when it checks the approval, and ignores it otherwise.
 * @param expiration Last timestamp at which the solution may settle
 */
struct AHV2Solution {
  address[] erc20Targets;
  uint160[] erc20Amounts;
  address[] erc721Targets;
  uint256[] callValues;
  bytes[] solverData;
  uint256 nonce;
  uint256 expiration;
}

using AHV2SolutionLib for AHV2Solution global;

library AHV2SolutionLib {
  using CalldataHashLib for address[];
  using CalldataHashLib for bytes[];
  using CalldataHashLib for uint160[];
  using CalldataHashLib for uint256[];

  // forgefmt: disable-next-item
  bytes32 internal constant AHV2_SOLUTION_TYPEHASH = keccak256(
    'AHV2Solution(address[] erc20Targets,uint160[] erc20Amounts,address[] erc721Targets'
    ',uint256[] callValues,bytes[] solverData,uint256 nonce,uint256 expiration)'
  );

  /// @dev EIP-712 hash of the solution
  function hash(AHV2Solution calldata self) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(
        AHV2_SOLUTION_TYPEHASH,
        self.erc20Targets.hash(),
        self.erc20Amounts.hash(),
        self.erc721Targets.hash(),
        self.callValues.hash(),
        self.solverData.hash(),
        self.nonce,
        self.expiration
      )
    );
  }
}
