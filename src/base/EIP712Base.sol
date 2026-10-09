// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IEIP712Base} from './interfaces/IEIP712Base.sol';

import {EIP712} from 'openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol';

/**
 * @title EIP712Base
 * @notice OpenZeppelin's {EIP712} with the domain separator exposed under the name signing tools
 * expect
 * @dev ERC-5267's `eip712Domain()` already describes the domain, but `DOMAIN_SEPARATOR()` is what
 * ERC-2612 tooling expects, and {EIP712} does not declare it. Inherit this rather than {EIP712} so
 * every signing domain in the codebase publishes its separator the same way.
 */
abstract contract EIP712Base is IEIP712Base, EIP712 {
  /**
   * @param name EIP-712 domain name, which scopes every signature this contract checks
   * @param version EIP-712 domain version
   */
  constructor(string memory name, string memory version) EIP712(name, version) {}

  /// @inheritdoc IEIP712Base
  function DOMAIN_SEPARATOR() external view returns (bytes32) {
    return _domainSeparatorV4();
  }
}
