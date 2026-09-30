// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import 'ks-common-sc/script/Base.s.sol';
import {IManagementBase} from 'ks-common-sc/src/interfaces/IManagementBase.sol';
import {IAccessControl} from 'openzeppelin-contracts/contracts/access/IAccessControl.sol';

contract AddWhitelistedRoutersV2Script is BaseScript {
  /// @dev Must match KSAllowanceHubV2.WHITELISTED_ROUTER_ROLE, which is NOT v1's
  /// `WHITELIST_ROUTER_ROLE` — the two hash differently, so the v1 script cannot be pointed here
  bytes32 internal constant WHITELISTED_ROUTER_ROLE = keccak256('WHITELISTED_ROUTER_ROLE');

  function run(string[] memory chainIds) public multiChain(chainIds) {
    address allowanceHubV2 = _readAddress('allowance-hub-v2');
    address[] memory whitelistedRouters = _readAddressArray('whitelisted-routers');

    /// @dev Only grant the role to routers that do not already have it
    uint256 count;
    address[] memory toGrant = new address[](whitelistedRouters.length);
    for (uint256 i = 0; i < whitelistedRouters.length; i++) {
      if (!IAccessControl(allowanceHubV2).hasRole(WHITELISTED_ROUTER_ROLE, whitelistedRouters[i])) {
        toGrant[count++] = whitelistedRouters[i];
      }
    }

    if (count == 0) {
      return;
    }

    // Shrinks the array to the number of routers to grant
    assembly {
      mstore(toGrant, count)
    }

    IManagementBase(allowanceHubV2).batchGrantRole(WHITELISTED_ROUTER_ROLE, toGrant);
  }
}
