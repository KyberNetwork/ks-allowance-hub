// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Test} from 'forge-std/Test.sol';

import {PermitHash} from 'test/libraries/PermitHash.sol';

import {SchemaHash} from 'test/base/SchemaHash.sol';

import {ISignatureTransfer} from 'ks-common-sc/src/interfaces/ISignatureTransfer.sol';
import {
  PermitBatchWitnessTransferFrom as Permit2ExecutionWitness
} from 'src/v2/types/ExecutionWitness.sol';
import {
  PermitBatchWitnessTransferFrom as Permit2FulfillmentWitness
} from 'src/v2/types/FulfillmentWitness.sol';

import {KeyType} from 'src/v2/authenticators/types/KeyType.sol';
import {SessionKey} from 'src/v2/authenticators/types/SessionKey.sol';
import {AuthDelegation} from 'src/v2/types/AuthDelegation.sol';
import {ERC20Transfer} from 'src/v2/types/ERC20Transfer.sol';
import {ERC721Transfer} from 'src/v2/types/ERC721Transfer.sol';
import {ExecutionOrder} from 'src/v2/types/ExecutionOrder.sol';
import {ExecutionWitness} from 'src/v2/types/ExecutionWitness.sol';
import {FulfillmentOrder} from 'src/v2/types/FulfillmentOrder.sol';
import {FulfillmentSolution} from 'src/v2/types/FulfillmentSolution.sol';
import {FulfillmentWitness} from 'src/v2/types/FulfillmentWitness.sol';
import {GenericCall} from 'src/v2/types/GenericCall.sol';
import {SolutionApproval} from 'src/v2/types/SolutionApproval.sol';
import {ValidationParams} from 'src/v2/types/ValidationParams.sol';

/**
 * @title V2TestBase
 * @notice Global base for the V2 suite.
 * @dev Every typehash and struct hash below is derived from the Solidity struct definitions, by
 * {SchemaHash} over the `forge bind-json` schemas. Nothing here may import a production constant or
 * hashing library: Permit2 derives its typehash from the string the hub passes it, so a test that
 * signs with the same production constant agrees with a wrong type string just as happily as with a
 * right one. The schemas are the independent oracle, and `test/v2/types/SchemaAudit.t.sol` compares
 * the production constants against them.
 *
 * The struct types are imported for their ABI shape only. Each one carries a `using ... global`
 * attachment, so the production hashers are reachable from any file that imports them — they are
 * never to appear on the expected side of an assertion.
 */

abstract contract V2TestBase is Test {
  address internal constant PERMIT2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;
  address internal constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
  address internal constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;

  uint256 internal constant FORK_BLOCK = 23_932_050;

  /// @dev Sentinel the hub uses for "the owner named nobody"; written out, never imported
  address internal constant ANY = 0x000000000000000000000000000000000000dEaD;

  // ---------------------------------------------------------------------------------------------
  // Literal type strings, transcribed from the structs in src/**/types
  // ---------------------------------------------------------------------------------------------

  // ---------------------------------------------------------------------------------------------
  // Actors
  // ---------------------------------------------------------------------------------------------

  address internal admin = makeAddr('admin');
  address internal guardian = makeAddr('guardian');
  address internal rescuer = makeAddr('rescuer');
  address internal relayer = makeAddr('relayer');
  address internal solver = makeAddr('solver');
  address internal recipient = makeAddr('recipient');

  address internal owner;
  uint256 internal ownerKey;

  /**
   * @dev Strips any code at `account` so it behaves as a plain EOA.
   * Well-known test keys have EIP-7702 delegations on mainnet, so at a post-Pectra fork block an
   * address from `makeAddrAndKey` can arrive carrying an `0xef0100..` indicator. Permit2 and
   * `SignatureChecker` then take the ERC-1271 branch and a perfectly good ECDSA signature fails.
   */
  function _asEoa(address account) internal {
    vm.etch(account, '');
  }

  function _forkMainnet() internal {
    vm.createSelectFork('mainnet', FORK_BLOCK);
  }

  // ---------------------------------------------------------------------------------------------
  // Hand-written member and array hashing
  // ---------------------------------------------------------------------------------------------

  // ---------------------------------------------------------------------------------------------
  // Hand-written struct hashes
  // ---------------------------------------------------------------------------------------------

  function lExecutionOrderHash(ExecutionOrder memory order) internal pure returns (bytes32) {
    return SchemaHash.executionOrder(order);
  }

  function lFulfillmentOrderHash(FulfillmentOrder memory order) internal pure returns (bytes32) {
    return SchemaHash.fulfillmentOrder(order);
  }

  function lFulfillmentSolutionHash(FulfillmentSolution memory solution)
    internal
    pure
    returns (bytes32)
  {
    return SchemaHash.fulfillmentSolution(solution);
  }

  function lSolutionApproval(
    address approvalOwner,
    bytes32 orderHash,
    FulfillmentSolution memory solution
  ) internal pure returns (bytes32) {
    return SchemaHash.solutionApproval(
      SolutionApproval({owner: approvalOwner, orderHash: orderHash, solution: solution})
    );
  }

  function lExecutionWitness(
    address signedCaller,
    address[] memory targets,
    ERC721Transfer[] memory erc721Transfers,
    GenericCall[] memory genericCalls
  ) internal pure returns (bytes32) {
    return SchemaHash.executionWitness(
      ExecutionWitness({
        relayer: signedCaller,
        erc20Targets: targets,
        erc721Transfers: erc721Transfers,
        genericCalls: genericCalls
      })
    );
  }

  function lFulfillmentWitness(
    address signedCaller,
    address[] memory targets,
    ERC721Transfer[] memory erc721Transfers,
    GenericCall[] memory ownerCalls,
    ValidationParams[] memory validationParams,
    address callsSigner
  ) internal pure returns (bytes32) {
    return SchemaHash.fulfillmentWitness(
      FulfillmentWitness({
        solver: signedCaller,
        erc20Targets: targets,
        erc721Transfers: erc721Transfers,
        ownerCalls: ownerCalls,
        validationParams: validationParams,
        callsSigner: callsSigner
      })
    );
  }

  function lAuthDelegation(
    address authenticator,
    bool delegated,
    bytes memory data,
    uint256 nonce,
    uint256 deadline
  ) internal pure returns (bytes32) {
    return SchemaHash.authDelegation(
      AuthDelegation({
        authenticator: authenticator,
        delegated: delegated,
        data: data,
        nonce: nonce,
        deadline: deadline
      })
    );
  }

  function lSessionKeyHash(bytes memory publicKey, uint8 keyType, uint256 expiration)
    internal
    pure
    returns (bytes32)
  {
    return SchemaHash.sessionKey(
      SessionKey({publicKey: publicKey, keyType: KeyType(keyType), expiration: expiration})
    );
  }

  function lSessionApproval(bytes32 keyHash, bool approved, uint256 nonce, uint256 deadline)
    internal
    pure
    returns (bytes32)
  {
    return
      keccak256(
        abi.encode(SchemaHash.sessionApprovalTypehash(), keyHash, approved, nonce, deadline)
      );
  }

  // ---------------------------------------------------------------------------------------------
  // Permit2 digest, rebuilt rather than imported
  // ---------------------------------------------------------------------------------------------

  /// @dev Permit2's `permitted` array, built from the order's ERC-20 legs
  function lTokenPermissions(address[] memory tokens, uint256[] memory amounts)
    internal
    pure
    returns (ISignatureTransfer.TokenPermissions[] memory permitted)
  {
    permitted = new ISignatureTransfer.TokenPermissions[](tokens.length);
    for (uint256 i = 0; i < tokens.length; i++) {
      permitted[i] = ISignatureTransfer.TokenPermissions({token: tokens[i], amount: amounts[i]});
    }
  }

  /// @dev The digest the owner signs for a relayed execution, hashed from the Permit2 struct
  function lPermit2ExecutionWitnessDigest(
    address[] memory tokens,
    uint256[] memory amounts,
    address spender,
    uint256 nonce,
    uint256 deadline,
    ExecutionWitness memory witness
  ) internal view returns (bytes32) {
    return lPermit2Digest(
      SchemaHash.permit2ExecutionWitness(
        Permit2ExecutionWitness({
          permitted: lTokenPermissions(tokens, amounts),
          spender: spender,
          nonce: nonce,
          deadline: deadline,
          witness: witness
        })
      )
    );
  }

  /// @dev The fulfillment counterpart of {lPermit2ExecutionWitnessDigest}
  function lPermit2FulfillmentWitnessDigest(
    address[] memory tokens,
    uint256[] memory amounts,
    address spender,
    uint256 nonce,
    uint256 deadline,
    FulfillmentWitness memory witness
  ) internal view returns (bytes32) {
    return lPermit2Digest(
      SchemaHash.permit2FulfillmentWitness(
        Permit2FulfillmentWitness({
          permitted: lTokenPermissions(tokens, amounts),
          spender: spender,
          nonce: nonce,
          deadline: deadline,
          witness: witness
        })
      )
    );
  }

  /// @dev Binds a Permit2 `structHash` to Permit2's own domain
  function lPermit2Digest(bytes32 structHash) internal view returns (bytes32) {
    return keccak256(abi.encodePacked('\x19\x01', _permit2DomainSeparator(), structHash));
  }

  /// @dev The witness-free batch permit, for orders the owner submits themselves
  function lPermit2BatchDigest(
    address[] memory tokens,
    uint256[] memory amounts,
    address spender,
    uint256 nonce,
    uint256 deadline
  ) internal view returns (bytes32) {
    bytes32[] memory permitted = new bytes32[](tokens.length);
    for (uint256 i = 0; i < tokens.length; i++) {
      permitted[i] =
        keccak256(abi.encode(PermitHash._TOKEN_PERMISSIONS_TYPEHASH, tokens[i], amounts[i]));
    }

    bytes32 structHash = keccak256(
      abi.encode(
        PermitHash._PERMIT_BATCH_TRANSFER_FROM_TYPEHASH,
        keccak256(abi.encodePacked(permitted)),
        spender,
        nonce,
        deadline
      )
    );

    return keccak256(abi.encodePacked('\x19\x01', _permit2DomainSeparator(), structHash));
  }

  /// @dev Read from the deployed Permit2, which is an external dependency rather than code under test
  function _permit2DomainSeparator() internal view returns (bytes32 separator) {
    (bool ok, bytes memory data) = PERMIT2.staticcall(abi.encodeWithSignature('DOMAIN_SEPARATOR()'));
    require(ok, 'permit2 domain');
    separator = abi.decode(data, (bytes32));
  }

  /// @dev Permit2's signature-transfer nonce bitmap, read off the deployed contract
  function _permit2NonceBitmap(address account, uint256 word) internal view returns (uint256) {
    (bool ok, bytes memory data) =
      PERMIT2.staticcall(abi.encodeWithSignature('nonceBitmap(address,uint256)', account, word));
    require(ok, 'permit2 nonceBitmap');
    return abi.decode(data, (uint256));
  }

  /// @dev Builds a domain separator from parts, so a test never reuses the contract's own value
  function lDomainSeparator(string memory name, string memory version, address verifyingContract)
    internal
    view
    returns (bytes32)
  {
    return keccak256(
      abi.encode(
        keccak256(
          'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'
        ),
        keccak256(bytes(name)),
        keccak256(bytes(version)),
        block.chainid,
        verifyingContract
      )
    );
  }

  function lTypedDataHash(bytes32 domainSeparator, bytes32 structHash)
    internal
    pure
    returns (bytes32)
  {
    return keccak256(abi.encodePacked('\x19\x01', domainSeparator, structHash));
  }

  function _sign(uint256 key, bytes32 digest) internal returns (bytes memory) {
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
    return abi.encodePacked(r, s, v);
  }

  // ---------------------------------------------------------------------------------------------
  // Array builders
  // ---------------------------------------------------------------------------------------------

  /// @dev The nonce namespace of a plain account, transcribed from {UnorderedNonce}
  function lNonceKey(address signer) internal pure returns (bytes32) {
    return bytes32(uint256(uint160(signer)));
  }

  function _erc20s(ERC20Transfer memory a) internal pure returns (ERC20Transfer[] memory out) {
    out = new ERC20Transfer[](1);
    out[0] = a;
  }

  function _erc721s(ERC721Transfer memory a) internal pure returns (ERC721Transfer[] memory out) {
    out = new ERC721Transfer[](1);
    out[0] = a;
  }

  function _calls(GenericCall memory a) internal pure returns (GenericCall[] memory out) {
    out = new GenericCall[](1);
    out[0] = a;
  }

  function _validations(ValidationParams memory a)
    internal
    pure
    returns (ValidationParams[] memory out)
  {
    out = new ValidationParams[](1);
    out[0] = a;
  }

  function _targets(ERC20Transfer[] memory transfers) internal pure returns (address[] memory out) {
    out = new address[](transfers.length);
    for (uint256 i = 0; i < transfers.length; i++) {
      out[i] = transfers[i].target;
    }
  }

  function _tokensAndAmounts(ERC20Transfer[] memory transfers)
    internal
    pure
    returns (address[] memory tokens, uint256[] memory amounts)
  {
    tokens = new address[](transfers.length);
    amounts = new uint256[](transfers.length);
    for (uint256 i = 0; i < transfers.length; i++) {
      tokens[i] = transfers[i].token;
      amounts[i] = transfers[i].amount;
    }
  }
}
