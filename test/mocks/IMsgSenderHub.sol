// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @notice The slice of the hub surface the mocks actually depend on
 * @dev Both `KSAllowanceHub` and `KSAllowanceHubV2` expose `msgSender()` identically, so typing the
 * mocks against this instead of a specific hub interface lets one set of mocks serve both suites.
 */
interface IMsgSenderHub {
  function msgSender() external view returns (address);
}
