// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import 'ks-common-sc/script/Base.s.sol';
import 'src/v2/authenticators/SessionOrderAuthenticator.sol';

contract DeploySessionOrderAuthenticatorScript is BaseScript {
  /// @dev Part of the CREATE3 salt, so changing it changes the deployed address on every chain
  string salt = '261020_1';

  function run(string[] memory chainIds) public multiChain(chainIds) {
    address allowanceHubV2 = _readAddress('allowance-hub-v2');

    bytes memory creationCode =
      abi.encodePacked(type(SessionOrderAuthenticator).creationCode, abi.encode(allowanceHubV2));

    (address authenticator,) = _create3Deploy(
      keccak256(bytes(string.concat('SessionOrderAuthenticator_', salt))), creationCode
    );
    if (vm.isContext(VmSafe.ForgeContext.ScriptBroadcast)) {
      _writeAddress('session-order-authenticator', authenticator);
    }
  }
}
