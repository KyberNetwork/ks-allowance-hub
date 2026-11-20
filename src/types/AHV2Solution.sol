// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {EfficientHashLibExt} from '../libraries/EfficientHashLibExt.sol';

/**
 * @notice The target of each transfer, the amount of each ERC20 transfer, and the native value and
 * data of each call a solver chose for an {AHV2Order}
 * @dev Approved by the order's `solutionApprover` rather than signed by the owner, so it may be
 * chosen after the order is signed. `erc20Targets[i]` receives `erc20Amounts[i]` of
 * `order.erc20Allowances[i]` and `erc721Targets[i]` receives `order.erc721Approvals[i]`. The
 * solution specifies a target and an amount for each ERC20 transfer and a target for each ERC721
 * transfer, so each target array and `erc20Amounts` must have one entry per transfer. `callValues`
 * and `solverData` have one entry per call. No approval is required when the order's
 * `solutionApprover` is the zero address or the order's owner submits it.
 * @param erc20Targets Target of each ERC20 transfer, in order
 * @param erc20Amounts Amount of each ERC20 transfer, in order; each is at most its allowance
 * @param erc721Targets Target of each ERC721 transfer, in order
 * @param callValues Native value sent with each of the order's calls, in order, paid from the
 * native value sent with the order
 * @param solverData Data the solver passes with each of the order's calls, as the `solverData`
 * argument of {IAHV2Callee-execute}; one entry per call. The owner does not sign it; the solution
 * approval covers it when one is required.
 * @param nonce Nonce of the solution approval, spent in the `solutionApprover`'s namespace of the
 * hub's nonces when the approval is checked; ignored when it is not
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
  using EfficientHashLibExt for address[];
  using EfficientHashLibExt for bytes[];
  using EfficientHashLibExt for uint160[];
  using EfficientHashLibExt for uint256[];

  bytes32 internal constant AHV2_SOLUTION_TYPEHASH = keccak256(
    'AHV2Solution(address[] erc20Targets,uint160[] erc20Amounts,address[] erc721Targets,uint256[] callValues,bytes[] solverData,uint256 nonce,uint256 expiration)'
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
