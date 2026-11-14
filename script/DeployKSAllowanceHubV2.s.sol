// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import 'ks-common-sc/script/Base.s.sol';
import 'src/KSAllowanceHubV2.sol';

contract DeployKSAllowanceHubV2Script is BaseScript {
  /// @dev Part of the CREATE3 salt, so changing it changes the deployed address on every chain
  string salt = '250926';

  function run(string[] memory chainIds) public multiChain(chainIds) {
    address admin = _readAddress('admin');
    address[] memory guardians = _readAddressArray('guardians');
    address[] memory rescuers = _readAddressArray('rescuers');
    address[] memory whitelistedRouters = _readAddressArray('whitelisted-routers');
    address permit2 = _readAddress('permit2');
    address multicall3 = _readAddress('multicall3');
    _requireDeployed('permit2', permit2);
    _requireDeployed('multicall3', multicall3);

    bytes memory creationCode = abi.encodePacked(
      type(KSAllowanceHubV2).creationCode,
      abi.encode(admin, guardians, rescuers, whitelistedRouters, permit2, multicall3)
    );

    (address allowanceHubV2,) =
      _create3Deploy(keccak256(bytes(string.concat('KSAllowanceHubV2_', salt))), creationCode);
    if (vm.isContext(VmSafe.ForgeContext.ScriptBroadcast)) {
      _writeAddress('allowance-hub-v2', allowanceHubV2);
    }
  }

  /// @dev Reverts when no code is deployed at `target` on the current chain
  function _requireDeployed(string memory name, address target) internal view {
    if (target.code.length == 0) {
      revert(
        string.concat(
          name,
          ' is not deployed at ',
          vm.toString(target),
          ' on chain ',
          vm.toString(block.chainid)
        )
      );
    }
  }
}
