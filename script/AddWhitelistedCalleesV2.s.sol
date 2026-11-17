// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import 'ks-common-sc/script/Base.s.sol';

import {IAccessControl} from 'openzeppelin-contracts/contracts/access/IAccessControl.sol';

import {IMulticall} from 'src/interfaces/base/IMulticall.sol';

contract AddWhitelistedCalleesV2Script is BaseScript {
  /// @dev Must match KSAllowanceHubV2.WHITELISTED_CALLEE_ROLE
  bytes32 internal constant WHITELISTED_CALLEE_ROLE = keccak256('WHITELISTED_CALLEE_ROLE');

  function run(string[] memory chainIds) public multiChain(chainIds) {
    address allowanceHubV2 = _readAddress('allowance-hub-v2');
    address[] memory whitelistedCallees = _readAddressArray('whitelisted-callees');

    /// @dev Only grant the role to callees that do not already have it
    uint256 count;
    bytes[] memory grants = new bytes[](whitelistedCallees.length);
    for (uint256 i = 0; i < whitelistedCallees.length; i++) {
      if (!IAccessControl(allowanceHubV2).hasRole(WHITELISTED_CALLEE_ROLE, whitelistedCallees[i])) {
        grants[count++] = abi.encodeCall(
          IAccessControl.grantRole, (WHITELISTED_CALLEE_ROLE, whitelistedCallees[i])
        );
      }
    }

    if (count == 0) {
      return;
    }

    // Shrinks the array to the number of callees to grant
    assembly {
      mstore(grants, count)
    }

    // The hub's multicall delegates each grant to itself, so they all go in one transaction
    IMulticall(allowanceHubV2).multicall(grants);
  }
}
