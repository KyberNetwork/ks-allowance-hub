// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import 'ks-common-sc/script/Base.s.sol';
import 'src/v2/CallsForwarder.sol';

contract DeployCallsForwarderScript is BaseScript {
  /// @dev Part of the CREATE3 salt, so changing it changes the deployed address on every chain
  string salt = '261020';

  function run(string[] memory chainIds) public multiChain(chainIds) {
    bytes memory creationCode = type(CallsForwarder).creationCode;

    (address callsForwarder,) =
      _create3Deploy(keccak256(bytes(string.concat('CallsForwarder_', salt))), creationCode);
    if (vm.isContext(VmSafe.ForgeContext.ScriptBroadcast)) {
      _writeAddress('calls-forwarder', callsForwarder);
    }
  }
}
