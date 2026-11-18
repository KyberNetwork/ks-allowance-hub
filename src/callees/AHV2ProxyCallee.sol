// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

import {IAHV2OwnerCallee} from '../interfaces/base/IAHV2OwnerCallee.sol';
import {IAHV2SolverCallee} from '../interfaces/base/IAHV2SolverCallee.sol';

import {Constants} from '../libraries/Constants.sol';

import {ManagementSimple} from 'ks-common-sc/src/base/ManagementSimple.sol';

import {ICommon} from 'ks-common-sc/src/interfaces/ICommon.sol';

import {KSRoles} from 'ks-common-sc/src/libraries/KSRoles.sol';
import {CalldataDecoder} from 'ks-common-sc/src/libraries/calldata/CalldataDecoder.sol';

import {Address} from 'openzeppelin-contracts/contracts/utils/Address.sol';
import {TransientSlot} from 'openzeppelin-contracts/contracts/utils/TransientSlot.sol';

/**
 * @title AHV2ProxyCallee
 * @notice Callee that delegatecalls a list of whitelisted callees in order, for one solver's call
 * or one owner's call of the allowance hub
 * @dev When the hub calls this contract, a callee reads the account it acts for from the hub's
 * {IMsgSender-msgSender}. A call this contract receives while a callee runs, such as a callback,
 * is delegatecalled to that callee, which must check who made it.
 */
contract AHV2ProxyCallee is IAHV2SolverCallee, IAHV2OwnerCallee, ManagementSimple {
  using Address for address;
  using CalldataDecoder for bytes;
  using TransientSlot for *;

  /// @notice A call reached the fallback while no callee is being delegatecalled
  error NoActiveCallee();

  /**
   * @dev Every callee must hold {Constants-WHITELISTED_CALLEE_ROLE} on this contract. The whitelist
   * is independent of the hub's, and guardians may revoke a callee from it.
   * @param initialAdmin Account granted the default admin role
   * @param initialGuardians Accounts granted the guardian role
   * @param initialWhitelistedCallees Callees granted {Constants-WHITELISTED_CALLEE_ROLE}
   */
  constructor(
    address initialAdmin,
    address[] memory initialGuardians,
    address[] memory initialWhitelistedCallees
  ) ManagementSimple(initialAdmin, initialGuardians) {
    _batchGrantRole(Constants.WHITELISTED_CALLEE_ROLE, initialWhitelistedCallees);
    // Guardians may revoke a callee without the admin
    _setRoleRevoker(Constants.WHITELISTED_CALLEE_ROLE, KSRoles.GUARDIAN_ROLE);
  }

  /// @notice Delegatecalls the callee being delegatecalled with the same calldata
  fallback() external payable {
    address callee = Constants.ACTIVE_CALLEE_SLOT.asAddress().tload();
    if (callee == Constants.ADDRESS_ZERO) {
      revert NoActiveCallee();
    }

    assembly {
      calldatacopy(0, 0, calldatasize())
      let success := delegatecall(gas(), callee, 0, calldatasize(), 0, 0)
      returndatacopy(0, 0, returndatasize())
      if success {
        return(0, returndatasize())
      }
      revert(0, returndatasize())
    }
  }

  /// @notice Accepts native value
  receive() external payable {}

  /**
   * @notice Delegatecalls each callee with its calldata, in order
   * @dev A callee that spends native value spends it from the balance of this contract.
   * @param data `abi.encode(address[] callees, bytes[] callData)`, where each element of
   * `callData` is the complete calldata for the callee at the same index
   * @return `abi.encode(bytes[] results)`, holding the return data of each delegatecall
   */
  function solverCall(bytes calldata data) external payable whenNotPaused returns (bytes memory) {
    // Every delegatecall sees the full `msg.value`
    address[] calldata callees = data.decodeAddressArray(0);
    bytes[] calldata callData = data.decodeBytesArray(1);
    if (callees.length != callData.length) {
      revert ICommon.MismatchedArrayLengths();
    }

    bytes[] memory results = new bytes[](callees.length);
    for (uint256 i = 0; i < callees.length; i++) {
      results[i] = _delegateCall(callees[i], callData[i]);
    }

    return abi.encode(results);
  }

  /**
   * @notice Delegatecalls each callee in order, with the owner's calldata, or with
   * {IAHV2OwnerCallee-ownerCall} when the solver supplies data for the callee
   * @dev A callee without solver data receives its element of `ownerData` as the complete
   * calldata.
   * @param proxyOwnerData `abi.encode(address[] callees, bytes[] ownerData)`
   * @param proxySolverData Empty, or `abi.encode(bytes[] solverData)` with one element per callee
   * @return `abi.encode(bytes[] results)`, holding the return data of each delegatecall
   */
  function ownerCall(bytes calldata proxyOwnerData, bytes calldata proxySolverData)
    external
    payable
    whenNotPaused
    returns (bytes memory)
  {
    // Every delegatecall sees the full `msg.value`
    address[] calldata callees = proxyOwnerData.decodeAddressArray(0);
    bytes[] calldata ownerData = proxyOwnerData.decodeBytesArray(1);
    if (callees.length != ownerData.length) {
      revert ICommon.MismatchedArrayLengths();
    }

    bytes[] memory results = new bytes[](callees.length);
    // When `proxySolverData` is empty, every callee is delegatecalled with its element of
    // `ownerData` as the complete calldata
    if (proxySolverData.length == 0) {
      for (uint256 i = 0; i < callees.length; i++) {
        results[i] = _delegateCall(callees[i], ownerData[i]);
      }
    } else {
      bytes[] calldata solverData = proxySolverData.decodeBytesArray(0);
      if (solverData.length != callees.length) {
        revert ICommon.MismatchedArrayLengths();
      }

      // A callee whose element of `solverData` is empty is delegatecalled as above; any other
      // callee is delegatecalled with `ownerCall(ownerData[i], solverData[i])`
      for (uint256 i = 0; i < callees.length; i++) {
        if (solverData[i].length == 0) {
          results[i] = _delegateCall(callees[i], ownerData[i]);
        } else {
          results[i] = _delegateCall(
            callees[i], abi.encodeCall(IAHV2OwnerCallee.ownerCall, (ownerData[i], solverData[i]))
          );
        }
      }
    }

    return abi.encode(results);
  }

  /// @dev Delegatecalls `callee` with `data` while recording it as the active callee
  function _delegateCall(address callee, bytes memory data) internal returns (bytes memory result) {
    _checkRole(Constants.WHITELISTED_CALLEE_ROLE, callee);

    // The previous callee is restored afterwards, for a callee that calls this contract again
    TransientSlot.AddressSlot slot = Constants.ACTIVE_CALLEE_SLOT.asAddress();
    address previous = slot.tload();
    slot.tstore(callee);
    result = callee.functionDelegateCall(data);
    slot.tstore(previous);
  }
}
