// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IAllowanceTransfer} from 'ks-common-sc/src/interfaces/IAllowanceTransfer.sol';
import {ISignatureTransfer} from 'ks-common-sc/src/interfaces/ISignatureTransfer.sol';

import {console} from 'forge-std/console.sol';

library PermitHash {
  bytes32 public constant _PERMIT_DETAILS_TYPEHASH =
    keccak256('PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)');

  bytes32 public constant _PERMIT_SINGLE_TYPEHASH = keccak256(
    'PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)'
  );

  bytes32 public constant _PERMIT_BATCH_TYPEHASH = keccak256(
    'PermitBatch(PermitDetails[] details,address spender,uint256 sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)'
  );

  bytes32 public constant _TOKEN_PERMISSIONS_TYPEHASH =
    keccak256('TokenPermissions(address token,uint256 amount)');

  bytes32 public constant _PERMIT_TRANSFER_FROM_TYPEHASH = keccak256(
    'PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)'
  );

  bytes32 public constant _PERMIT_BATCH_TRANSFER_FROM_TYPEHASH = keccak256(
    'PermitBatchTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)'
  );

  string public constant _TOKEN_PERMISSIONS_TYPESTRING =
    'TokenPermissions(address token,uint256 amount)';

  string public constant _PERMIT_TRANSFER_FROM_WITNESS_TYPEHASH_STUB =
    'PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,';

  string public constant _PERMIT_BATCH_WITNESS_TRANSFER_FROM_TYPEHASH_STUB =
    'PermitBatchWitnessTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline,';

  function hash(IAllowanceTransfer.PermitBatch memory permitBatch) internal pure returns (bytes32) {
    uint256 numPermits = permitBatch.details.length;
    bytes32[] memory permitHashes = new bytes32[](numPermits);
    for (uint256 i = 0; i < numPermits; ++i) {
      permitHashes[i] = _hashPermitDetails(permitBatch.details[i]);
    }
    return keccak256(
      abi.encode(
        _PERMIT_BATCH_TYPEHASH,
        keccak256(abi.encodePacked(permitHashes)),
        permitBatch.spender,
        permitBatch.sigDeadline
      )
    );
  }

  function hash(ISignatureTransfer.PermitBatchTransferFrom memory permit, address spender)
    internal
    pure
    returns (bytes32)
  {
    uint256 numPermitted = permit.permitted.length;
    bytes32[] memory tokenPermissionHashes = new bytes32[](numPermitted);

    for (uint256 i = 0; i < numPermitted; ++i) {
      tokenPermissionHashes[i] = _hashTokenPermissions(permit.permitted[i]);
    }

    return keccak256(
      abi.encode(
        _PERMIT_BATCH_TRANSFER_FROM_TYPEHASH,
        keccak256(abi.encodePacked(tokenPermissionHashes)),
        spender,
        permit.nonce,
        permit.deadline
      )
    );
  }

  function hashWithWitness(
    ISignatureTransfer.PermitBatchTransferFrom memory permit,
    address spender,
    bytes32 witness,
    string memory witnessTypeString
  ) internal pure returns (bytes32) {
    bytes32 typeHash = keccak256(
      abi.encodePacked(_PERMIT_BATCH_WITNESS_TRANSFER_FROM_TYPEHASH_STUB, witnessTypeString)
    );

    uint256 numPermitted = permit.permitted.length;
    bytes32[] memory tokenPermissionHashes = new bytes32[](numPermitted);

    for (uint256 i = 0; i < numPermitted; ++i) {
      tokenPermissionHashes[i] = _hashTokenPermissions(permit.permitted[i]);
    }

    return keccak256(
      abi.encode(
        typeHash,
        keccak256(abi.encodePacked(tokenPermissionHashes)),
        spender,
        permit.nonce,
        permit.deadline,
        witness
      )
    );
  }

  function _hashPermitDetails(IAllowanceTransfer.PermitDetails memory details)
    private
    pure
    returns (bytes32)
  {
    return keccak256(abi.encode(_PERMIT_DETAILS_TYPEHASH, details));
  }

  function _hashTokenPermissions(ISignatureTransfer.TokenPermissions memory permitted)
    private
    pure
    returns (bytes32)
  {
    return keccak256(abi.encode(_TOKEN_PERMISSIONS_TYPEHASH, permitted));
  }
}
