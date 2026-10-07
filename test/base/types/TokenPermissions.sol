// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

/// @dev Permit2's own leaf type, redeclared so `forge bind-json` derives its `encodeType` from a
/// struct rather than from a string transcribed into the suite
struct TokenPermissions {
  address token;
  uint256 amount;
}
