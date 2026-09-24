// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {IAuthVerifier} from '../base/interfaces/IAuthVerifier.sol';
import {IKSAllowanceHubV2} from './interfaces/IKSAllowanceHubV2.sol';

import {AuthDelegator} from '../base/AuthDelegator.sol';
import {CallsForwarder} from '../base/CallsForwarder.sol';
import {MsgSender} from '../base/MsgSender.sol';

import {PackedBits} from '../base/types/PackedBits.sol';

import {CallsApprovalLibrary} from './types/CallsApproval.sol';
import {ERC20Transfer, ERC20TransferLibrary} from './types/ERC20Transfer.sol';
import {ERC721Transfer, ERC721TransferLibrary} from './types/ERC721Transfer.sol';
import {ExecutionWitnessLibrary} from './types/ExecutionWitness.sol';
import {FulfillmentWitnessLibrary} from './types/FulfillmentWitness.sol';
import {GenericCall, GenericCallLibrary} from './types/GenericCall.sol';
import {ValidationParams, ValidationParamsLibrary} from './types/ValidationParams.sol';

import {ManagementBase} from 'ks-common-sc/src/base/ManagementBase.sol';
import {ManagementPausable} from 'ks-common-sc/src/base/ManagementPausable.sol';
import {ManagementRescuable} from 'ks-common-sc/src/base/ManagementRescuable.sol';
import {IAllowanceTransfer} from 'ks-common-sc/src/interfaces/IAllowanceTransfer.sol';
import {ISignatureTransfer} from 'ks-common-sc/src/interfaces/ISignatureTransfer.sol';
import {KSRoles} from 'ks-common-sc/src/libraries/KSRoles.sol';
import {CalldataDecoder} from 'ks-common-sc/src/libraries/calldata/CalldataDecoder.sol';

import {ECDSA} from 'openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol';

/**
 * @title KSAllowanceHubV2
 * @notice Single approval target for KyberSwap: pulls a user's ERC20s and ERC721s and hands them
 * to whitelisted routers in one transaction, so users approve this hub instead of every router.
 * @dev Assets are authorised over one of two rails, selected by `authFlags`:
 * - Permit2, where the owner's Permit2 signature carries a witness binding the rest of the order;
 * - a delegated {IAuthVerifier}, pre-authorised through {AuthDelegator}, which checks an owner
 *   signature over the order.
 * An owner acting on their own behalf needs neither. `authData` is packed per rail:
 * `abi.encode(nonce, signature)` for Permit2, `abi.encode(verifier, nonce, key, signature)` for a
 * verifier.
 *
 * `authFlags` carries three switches, and higher bits are ignored:
 * - bit 0: pull the ERC20s with an owner-signed Permit2 transfer, not a standing approval;
 * - bit 1: pull them through the owner's Permit2 allowance, not an approval to this hub;
 * - bit 2: the owner named `msg.sender` in what they signed, rather than leaving it open.
 */
contract KSAllowanceHubV2 is
  IKSAllowanceHubV2,
  ManagementPausable,
  ManagementRescuable,
  AuthDelegator,
  CallsForwarder,
  MsgSender
{
  using ERC20TransferLibrary for ERC20Transfer[];
  using ERC721TransferLibrary for ERC721Transfer[];
  using GenericCallLibrary for GenericCall[];
  using ValidationParamsLibrary for ValidationParams[];
  using CalldataDecoder for bytes;

  /// @notice Only routers holding this role may be called by {transferAndExecute} / {transferAndFulfill}
  bytes32 internal constant WHITELISTED_ROUTER_ROLE = keccak256('WHITELISTED_ROUTER_ROLE');

  /// @notice Stands in for "the owner did not name a caller", so anyone may submit the order
  address internal constant DEAD_ADDRESS = 0x000000000000000000000000000000000000dEaD;

  address internal immutable PERMIT2;

  /**
   * @param initialAdmin Holder of the default admin role
   * @param initialGuardians Accounts that may pause the hub and revoke routers
   * @param initialRescuers Accounts that may sweep assets stranded in the hub
   * @param initialWhitelistedRouters Routers callable from the start
   * @param permit2 The canonical Permit2 deployment
   */
  constructor(
    address initialAdmin,
    address[] memory initialGuardians,
    address[] memory initialRescuers,
    address[] memory initialWhitelistedRouters,
    address permit2
  )
    ManagementBase(0, initialAdmin)
    ManagementPausable(initialGuardians)
    ManagementRescuable(initialRescuers)
    AuthDelegator('KyberSwap Allowance Hub', '2.0.0')
  {
    _batchGrantRole(WHITELISTED_ROUTER_ROLE, initialWhitelistedRouters);
    // Guardians can drop a compromised router without waiting on the admin
    _setRoleRevoker(WHITELISTED_ROUTER_ROLE, KSRoles.GUARDIAN_ROLE);

    PERMIT2 = permit2;
  }

  /// @inheritdoc IKSAllowanceHubV2
  function transferAndExecute(
    address owner,
    ERC20Transfer[] calldata erc20Transfers,
    ERC721Transfer[] calldata erc721Transfers,
    GenericCall[] calldata genericCalls,
    uint256 deadline,
    PackedBits authFlags,
    bytes calldata authData
  )
    external
    payable
    whenNotPaused
    checkDeadline(deadline)
    lock(owner)
    guardNativeSpend
    returns (bytes[] memory results, uint256 gasUsed)
  {
    uint256 gasStart = gasleft();

    // Bit 0: the Permit2 signature-transfer rail
    if (authFlags.pos(0)) {
      if (msg.sender == owner) {
        _permitTransferFrom(owner, erc20Transfers, deadline, authData);
      } else {
        // The permit covers only tokens and amounts, so the witness binds the rest of what the
        // owner agreed to: who may submit, where the tokens land, the NFTs and the calls
        bytes32 witness = ExecutionWitnessLibrary.hash(
          _signedCaller(authFlags), erc20Transfers.toTargets(), erc721Transfers, genericCalls
        );

        _permitWitnessTransferFrom(
          owner,
          erc20Transfers,
          deadline,
          authData,
          witness,
          ExecutionWitnessLibrary.EXECUTION_WITNESS_PERMIT2_TYPE_STRING
        );
      }
    } else {
      if (msg.sender != owner) {
        bytes memory data =
          abi.encode(_signedCaller(authFlags), erc20Transfers, erc721Transfers, genericCalls);
        // Trailing `false` tells the verifier which payload shape to decode
        _verifyAuth(owner, abi.encodePacked(data, false), deadline, authData);
      }

      _transferERC20s(owner, erc20Transfers, authFlags);
    }

    results = _settleAndExecute(owner, erc20Transfers, erc721Transfers, genericCalls);

    unchecked {
      gasUsed = gasStart - gasleft();
    }
  }

  /// @inheritdoc IKSAllowanceHubV2
  function transferAndFulfill(
    address owner,
    ERC20Transfer[] calldata erc20Transfers,
    ERC721Transfer[] calldata erc721Transfers,
    ValidationParams[] calldata validationParams,
    uint256 deadline,
    PackedBits authFlags,
    bytes calldata authData,
    GenericCall[] calldata genericCalls,
    uint256 callsNonce,
    bytes calldata callsSignature
  )
    external
    payable
    whenNotPaused
    checkDeadline(deadline)
    lock(owner)
    guardNativeSpend
    returns (bytes[] memory results, uint256 gasUsed)
  {
    uint256 gasStart = gasleft();

    // Snapshot first, so the validators measure the whole transaction and not just its tail
    bytes[] memory beforeExecutionOutputs = validationParams.beforeExecution();
    address callsSigner = _callsSigner(owner, genericCalls, callsNonce, deadline, callsSignature);

    // Bit 0: the Permit2 signature-transfer rail
    if (authFlags.pos(0)) {
      if (msg.sender == owner) {
        _permitTransferFrom(owner, erc20Transfers, deadline, authData);
      } else {
        // Here the owner signs *who* may choose the calls, not the calls themselves; the
        // validators are what bound the outcome
        bytes32 witness = FulfillmentWitnessLibrary.hash(
          _signedCaller(authFlags),
          erc20Transfers.toTargets(),
          erc721Transfers,
          validationParams,
          callsSigner
        );

        _permitWitnessTransferFrom(
          owner,
          erc20Transfers,
          deadline,
          authData,
          witness,
          FulfillmentWitnessLibrary.FULFILLMENT_WITNESS_PERMIT2_TYPE_STRING
        );
      }
    } else {
      if (msg.sender != owner) {
        bytes memory data = abi.encode(
          _signedCaller(authFlags), erc20Transfers, erc721Transfers, validationParams, callsSigner
        );
        // Trailing `true` tells the verifier which payload shape to decode
        _verifyAuth(owner, abi.encodePacked(data, true), deadline, authData);
      }

      _transferERC20s(owner, erc20Transfers, authFlags);
    }

    results = _settleAndExecute(owner, erc20Transfers, erc721Transfers, genericCalls);
    validationParams.afterExecution(beforeExecutionOutputs);

    unchecked {
      gasUsed = gasStart - gasleft();
    }
  }

  /// @dev Permit2 signature transfer by the owner themselves, so there is nothing to witness
  function _permitTransferFrom(
    address owner,
    ERC20Transfer[] calldata erc20Transfers,
    uint256 deadline,
    bytes calldata authData
  ) internal {
    (
      ISignatureTransfer.PermitBatchTransferFrom memory permit,
      ISignatureTransfer.SignatureTransferDetails[] memory details
    ) = _toPermitAndDetails(erc20Transfers, deadline, authData);

    bytes calldata signature = authData.decodeBytes(1);
    ISignatureTransfer(PERMIT2).permitTransferFrom(permit, details, owner, signature);
  }

  /// @dev Permit2 signature transfer for a relayed order, with the order bound in as the witness
  function _permitWitnessTransferFrom(
    address owner,
    ERC20Transfer[] calldata erc20Transfers,
    uint256 deadline,
    bytes calldata authData,
    bytes32 witness,
    string memory witnessTypeString
  ) internal {
    (
      ISignatureTransfer.PermitBatchTransferFrom memory permit,
      ISignatureTransfer.SignatureTransferDetails[] memory details
    ) = _toPermitAndDetails(erc20Transfers, deadline, authData);

    bytes calldata signature = authData.decodeBytes(1);
    ISignatureTransfer(PERMIT2)
      .permitWitnessTransferFrom(permit, details, owner, witness, witnessTypeString, signature);
  }

  /**
   * @dev Hands the order to a verifier the owner delegated through {AuthDelegator}. The verifier
   * must revert when the signature does not authorise `data`; returning normally means success.
   * Expects `authData` as `abi.encode(verifier, nonce, key, signature)`.
   */
  function _verifyAuth(address owner, bytes memory data, uint256 deadline, bytes calldata authData)
    internal
  {
    address verifier = authData.decodeAddress(0);
    if (!authDelegated[owner][verifier]) {
      revert NotDelegatedVerifier();
    }

    uint256 nonce = authData.decodeUint256(1);
    bytes calldata key = authData.decodeBytes(2);
    bytes calldata signature = authData.decodeBytes(3);
    IAuthVerifier(verifier).verifyAuth(owner, data, nonce, deadline, key, signature);
  }

  /**
   * @dev The caller identity that goes into the signed payload, per `authFlags` bit 2. The flag
   * only decides which value is rebuilt; the owner's signature is what makes it binding, so a
   * mismatched flag simply fails verification.
   */
  function _signedCaller(PackedBits authFlags) internal view returns (address signer) {
    assembly ('memory-safe') {
      switch and(shr(2, authFlags), 0x1)
      case 0 { signer := DEAD_ADDRESS }
      default { signer := caller() }
    }
  }

  /// @dev Pulls the ERC20s over Permit2's allowance rail, or over a plain approval to this hub
  function _transferERC20s(
    address owner,
    ERC20Transfer[] calldata erc20Transfers,
    PackedBits authFlags
  ) internal {
    // Bit 1: the Permit2 allowance rail
    if (authFlags.pos(1)) {
      IAllowanceTransfer.AllowanceTransferDetails[] memory details =
        erc20Transfers.toAllowanceTransferDetails(owner);
      IAllowanceTransfer(PERMIT2).transferFrom(details);
    } else {
      erc20Transfers.execute(owner);
    }
  }

  /// @dev Shared tail of both entry points: the NFT leg, the event, then the router calls
  function _settleAndExecute(
    address owner,
    ERC20Transfer[] calldata erc20Transfers,
    ERC721Transfer[] calldata erc721Transfers,
    GenericCall[] calldata genericCalls
  ) internal returns (bytes[] memory results) {
    erc721Transfers.execute(owner);

    emit TransferTokens(
      msg.sender, owner, erc20Transfers, erc721Transfers, genericCalls.toNativeTransfers()
    );

    results = new bytes[](genericCalls.length);
    for (uint256 i = 0; i < genericCalls.length; i++) {
      _checkRole(WHITELISTED_ROUTER_ROLE, genericCalls[i].router);
      results[i] = genericCalls[i].execute();
    }
  }

  /// @dev Shapes the ERC20 legs into the permit and transfer details Permit2 expects
  function _toPermitAndDetails(
    ERC20Transfer[] calldata erc20Transfers,
    uint256 deadline,
    bytes calldata authData
  )
    internal
    pure
    returns (
      ISignatureTransfer.PermitBatchTransferFrom memory permit,
      ISignatureTransfer.SignatureTransferDetails[] memory details
    )
  {
    uint256 nonce = authData.decodeUint256(0);
    permit = erc20Transfers.toPermitBatchTransferFrom(nonce, deadline);
    details = erc20Transfers.toSignatureTransferDetails();
  }

  /**
   * @dev Recovers who approved `genericCalls`, or {DEAD_ADDRESS} when no
   * signature is given, which an owner's signature naming that address reads as "any calls".
   * The nonce is burned against the owner, so one approval cannot be settled twice.
   */
  function _callsSigner(
    address owner,
    GenericCall[] calldata genericCalls,
    uint256 callsNonce,
    uint256 deadline,
    bytes calldata callsSignature
  ) internal returns (address) {
    if (callsSignature.length == 0) {
      return DEAD_ADDRESS;
    }

    _useUnorderedNonce(owner, callsNonce);

    bytes32 digest =
      _hashTypedDataV4(CallsApprovalLibrary.hash(owner, genericCalls, callsNonce, deadline));
    return ECDSA.recover(digest, callsSignature);
  }
}
