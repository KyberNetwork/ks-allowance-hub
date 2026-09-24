// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @notice Packed authorisation switches for {KSAllowanceHubV2}, read from the low three bits:
 * bit 0 selects the Permit2 signature-transfer rail, bit 1 the Permit2 allowance rail, and bit 2
 * whether the caller was named in the owner's signature. Higher bits are ignored.
 */
type AuthFlags is bytes32;

using AuthFlagsLibrary for AuthFlags global;

library AuthFlagsLibrary {
  /// @notice Stands in for "the owner did not name a caller", so anyone may submit the order
  address internal constant DEAD_ADDRESS = 0x000000000000000000000000000000000000dEaD;

  /// @notice Pull the ERC20s with an owner-signed Permit2 transfer rather than a standing approval
  function usePermit2SignatureTransfer(AuthFlags authFlags) internal pure returns (bool flag) {
    assembly ('memory-safe') {
      flag := and(authFlags, 0x1)
    }
  }

  /// @notice Pull the ERC20s through the owner's Permit2 allowance rather than an approval to the hub
  function usePermit2AllowanceTransfer(AuthFlags authFlags) internal pure returns (bool flag) {
    assembly ('memory-safe') {
      flag := and(shr(1, authFlags), 0x1)
    }
  }

  /**
   * @notice The caller identity that goes into the signed payload
   * @dev The flag only decides which value is rebuilt; the owner's signature is what makes it
   * binding, so a mismatched flag simply fails verification.
   */
  function signedCaller(AuthFlags authFlags) internal view returns (address signer) {
    assembly ('memory-safe') {
      switch and(shr(2, authFlags), 0x1)
      case 0 {
        signer := DEAD_ADDRESS
      }
      default {
        signer := caller()
      }
    }
  }
}
