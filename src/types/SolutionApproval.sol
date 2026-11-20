// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {AHV2Order} from './AHV2Order.sol';
import {AHV2Solution} from './AHV2Solution.sol';

/**
 * @notice A solution approver's approval of one {AHV2Solution} for one {AHV2Order}
 * @dev The approval is spent with `solution.nonce` in the approver's namespace, so each approval
 * settles at most once. The approver revokes an unused approval with {UnorderedNonce-revokeNonce}.
 * @param order The order the solution settles
 * @param solution The approved solution
 */
struct SolutionApproval {
  AHV2Order order;
  AHV2Solution solution;
}

library SolutionApprovalLib {
  bytes32 internal constant SOLUTION_APPROVAL_TYPEHASH = keccak256(
    'SolutionApproval(AHV2Order order,AHV2Solution solution)'
    'AHV2Order(address owner,address authenticator,address exclusiveCaller,ERC20Allowance[] erc20Allowances,ERC721Approval[] erc721Approvals,HookParams[] hooks,CallParams[] calls,address solutionApprover,uint256 nonce,uint256 expiration,bytes clientData)'
    'AHV2Solution(address[] erc20Targets,uint160[] erc20Amounts,address[] erc721Targets,uint256[] callValues,bytes[] solverData,uint256 nonce,uint256 expiration)'
    'CallParams(address callee,bytes ownerData)' 'ERC20Allowance(address token,uint160 amount)'
    'ERC721Approval(address token,uint256 tokenId)'
    'HookParams(address hook,bytes32 flags,bytes data)'
  );

  /// @dev EIP-712 hash of the approval, taking the order by its struct hash
  function hash(bytes32 orderHash, AHV2Solution calldata solution) internal pure returns (bytes32) {
    return keccak256(abi.encode(SOLUTION_APPROVAL_TYPEHASH, orderHash, solution.hash()));
  }
}
