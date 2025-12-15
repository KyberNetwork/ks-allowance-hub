// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import 'ks-common-sc/script/Base.s.sol';
import 'src/KSAllowanceHub.sol';

contract DeployKSAllowanceHubScript is BaseScript {
  string salt = '251215_1';

  function run(string[] memory chainIds) public multiChain(chainIds) {
    address admin = _readAddress('admin');
    address[] memory guardians = _readAddressArray('guardians');
    address[] memory rescuers = _readAddressArray('rescuers');
    address permit2 = _readAddress('permit2');

    bytes memory creationCode = abi.encodePacked(
      type(KSAllowanceHub).creationCode, abi.encode(admin, guardians, rescuers, permit2)
    );

    address allowanceHub =
      _create3Deploy(keccak256(bytes(string.concat('KSAllowanceHub_', salt))), creationCode);
    _writeAddress('allowance-hub', allowanceHub);
  }
}
