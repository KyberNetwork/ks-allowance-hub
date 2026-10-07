// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Test} from 'forge-std/Test.sol';

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
 * @dev Every EIP-712 string, typehash and struct hash below is hand-written from the Solidity
 * struct definitions. Nothing here may import a production constant or hashing library: Permit2
 * derives its typehash from the string the hub passes it, so a test that signs with the same
 * production constant agrees with a wrong type string just as happily as with a right one. These
 * literals are the independent oracle, and `test/v2/types/Eip712.t.sol` compares the production
 * constants against them.
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

  string internal constant L_ERC20_TRANSFER =
    'ERC20Transfer(address token,address target,uint160 amount)';
  string internal constant L_ERC721_TRANSFER =
    'ERC721Transfer(address token,uint256 tokenId,address target)';
  string internal constant L_GENERIC_CALL = 'GenericCall(address router,uint256 value,bytes data)';
  string internal constant L_VALIDATION_PARAMS =
    'ValidationParams(address validator,bytes32 action,bytes beforeExecutionInput,bytes afterExecutionInput)';
  string internal constant L_TOKEN_PERMISSIONS = 'TokenPermissions(address token,uint256 amount)';

  string internal constant L_EXECUTION_ORDER =
    'ExecutionOrder(address relayer,ERC20Transfer[] erc20Transfers,ERC721Transfer[] erc721Transfers,GenericCall[] genericCalls,uint256 nonce,uint256 deadline)';
  string internal constant L_FULFILLMENT_ORDER =
    'FulfillmentOrder(address solver,ERC20Transfer[] erc20Transfers,ERC721Transfer[] erc721Transfers,ValidationParams[] validationParams,GenericCall[] ownerCalls,address solutionApprover,uint256 nonce,uint256 deadline)';
  string internal constant L_FULFILLMENT_SOLUTION =
    'FulfillmentSolution(GenericCall[] solverCalls,uint256 nonce,uint256 deadline)';
  string internal constant L_SOLUTION_APPROVAL =
    'SolutionApproval(address owner,bytes32 orderHash,FulfillmentSolution solution)';

  string internal constant L_EXECUTION_WITNESS =
    'ExecutionWitness(address relayer,address[] erc20Targets,ERC721Transfer[] erc721Transfers,GenericCall[] genericCalls)';
  string internal constant L_FULFILLMENT_WITNESS =
    'FulfillmentWitness(address solver,address[] erc20Targets,ERC721Transfer[] erc721Transfers,GenericCall[] ownerCalls,ValidationParams[] validationParams,address callsSigner)';
  string internal constant L_AUTH_DELEGATION =
    'AuthDelegation(address authenticator,bool delegated,bytes data,uint256 nonce,uint256 deadline)';

  string internal constant L_SESSION_KEY =
    'SessionKey(bytes publicKey,uint8 keyType,uint256 expiration)';
  string internal constant L_SESSION_APPROVAL =
    'SessionApproval(SessionKey sessionKey,bool approved,uint256 nonce,uint256 deadline)';

  /// @dev Permit2 prepends this and hashes the concatenation, so the witness string closes its paren
  string internal constant L_PERMIT2_BATCH_WITNESS_STUB =
    'PermitBatchWitnessTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline,';

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
  // Hand-written EIP-712 typehashes
  // ---------------------------------------------------------------------------------------------

  /// @dev Referenced types follow the primary type in alphabetical order, per EIP-712
  /// @dev The EIP-712 `encodeType` string: the type and its referenced types, in order
  function lExecutionOrderEncodeType() internal pure returns (string memory) {
    return string(
      abi.encodePacked(L_EXECUTION_ORDER, L_ERC20_TRANSFER, L_ERC721_TRANSFER, L_GENERIC_CALL)
    );
  }

  function lExecutionOrderTypehash() internal pure returns (bytes32) {
    return keccak256(bytes(lExecutionOrderEncodeType()));
  }

  /// @dev Sorted: ERC20Transfer, ERC721Transfer, GenericCall, ValidationParams
  /// @dev The EIP-712 `encodeType` string: the type and its referenced types, in order
  function lFulfillmentOrderEncodeType() internal pure returns (string memory) {
    return string(
      abi.encodePacked(
        L_FULFILLMENT_ORDER,
        L_ERC20_TRANSFER,
        L_ERC721_TRANSFER,
        L_GENERIC_CALL,
        L_VALIDATION_PARAMS
      )
    );
  }

  function lFulfillmentOrderTypehash() internal pure returns (bytes32) {
    return keccak256(bytes(lFulfillmentOrderEncodeType()));
  }

  /// @dev The EIP-712 `encodeType` string: the type and its referenced types, in order
  function lFulfillmentSolutionEncodeType() internal pure returns (string memory) {
    return string(abi.encodePacked(L_FULFILLMENT_SOLUTION, L_GENERIC_CALL));
  }

  function lFulfillmentSolutionTypehash() internal pure returns (bytes32) {
    return keccak256(bytes(lFulfillmentSolutionEncodeType()));
  }

  /// @dev Sorted: FulfillmentSolution, GenericCall
  /// @dev The EIP-712 `encodeType` string: the type and its referenced types, in order
  function lSolutionApprovalEncodeType() internal pure returns (string memory) {
    return string(abi.encodePacked(L_SOLUTION_APPROVAL, L_FULFILLMENT_SOLUTION, L_GENERIC_CALL));
  }

  function lSolutionApprovalTypehash() internal pure returns (bytes32) {
    return keccak256(bytes(lSolutionApprovalEncodeType()));
  }

  /// @dev The EIP-712 `encodeType` string: the type and its referenced types, in order
  function lExecutionWitnessEncodeType() internal pure returns (string memory) {
    return string(abi.encodePacked(L_EXECUTION_WITNESS, L_ERC721_TRANSFER, L_GENERIC_CALL));
  }

  function lExecutionWitnessTypehash() internal pure returns (bytes32) {
    return keccak256(bytes(lExecutionWitnessEncodeType()));
  }

  /// @dev The EIP-712 `encodeType` string: the type and its referenced types, in order
  function lFulfillmentWitnessEncodeType() internal pure returns (string memory) {
    return string(
      abi.encodePacked(
        L_FULFILLMENT_WITNESS, L_ERC721_TRANSFER, L_GENERIC_CALL, L_VALIDATION_PARAMS
      )
    );
  }

  function lFulfillmentWitnessTypehash() internal pure returns (bytes32) {
    return keccak256(bytes(lFulfillmentWitnessEncodeType()));
  }

  /// @dev `ExecutionWitness witness)` + referenced types, sorted: ERC721Transfer, ExecutionWitness,
  /// GenericCall, TokenPermissions
  function lExecutionWitnessTypeString() internal pure returns (string memory) {
    return string(
      abi.encodePacked(
        'ExecutionWitness witness)',
        L_ERC721_TRANSFER,
        L_EXECUTION_WITNESS,
        L_GENERIC_CALL,
        L_TOKEN_PERMISSIONS
      )
    );
  }

  /// @dev Sorted: ERC721Transfer, FulfillmentWitness, GenericCall, TokenPermissions,
  /// ValidationParams
  function lFulfillmentWitnessTypeString() internal pure returns (string memory) {
    return string(
      abi.encodePacked(
        'FulfillmentWitness witness)',
        L_ERC721_TRANSFER,
        L_FULFILLMENT_WITNESS,
        L_GENERIC_CALL,
        L_TOKEN_PERMISSIONS,
        L_VALIDATION_PARAMS
      )
    );
  }

  function lSessionKeyTypehash() internal pure returns (bytes32) {
    return keccak256(bytes(L_SESSION_KEY));
  }

  function lSessionApprovalTypehash() internal pure returns (bytes32) {
    return keccak256(abi.encodePacked(L_SESSION_APPROVAL, L_SESSION_KEY));
  }

  // ---------------------------------------------------------------------------------------------
  // Hand-written member and array hashing
  // ---------------------------------------------------------------------------------------------

  // ---------------------------------------------------------------------------------------------
  // Hand-written struct hashes
  // ---------------------------------------------------------------------------------------------

  function lExecutionOrderHash(ExecutionOrder memory order) internal pure returns (bytes32) {
    return vm.eip712HashStruct(lExecutionOrderEncodeType(), abi.encode(order));
  }

  function lFulfillmentOrderHash(FulfillmentOrder memory order) internal pure returns (bytes32) {
    return vm.eip712HashStruct(lFulfillmentOrderEncodeType(), abi.encode(order));
  }

  function lFulfillmentSolutionHash(FulfillmentSolution memory solution)
    internal
    pure
    returns (bytes32)
  {
    return vm.eip712HashStruct(lFulfillmentSolutionEncodeType(), abi.encode(solution));
  }

  function lSolutionApproval(
    address approvalOwner,
    bytes32 orderHash,
    FulfillmentSolution memory solution
  ) internal pure returns (bytes32) {
    return vm.eip712HashStruct(
      lSolutionApprovalEncodeType(),
      abi.encode(SolutionApproval({owner: approvalOwner, orderHash: orderHash, solution: solution}))
    );
  }

  function lExecutionWitness(
    address signedCaller,
    address[] memory targets,
    ERC721Transfer[] memory erc721Transfers,
    GenericCall[] memory genericCalls
  ) internal pure returns (bytes32) {
    return vm.eip712HashStruct(
      lExecutionWitnessEncodeType(),
      abi.encode(
        ExecutionWitness({
          relayer: signedCaller,
          erc20Targets: targets,
          erc721Transfers: erc721Transfers,
          genericCalls: genericCalls
        })
      )
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
    return vm.eip712HashStruct(
      lFulfillmentWitnessEncodeType(),
      abi.encode(
        FulfillmentWitness({
          solver: signedCaller,
          erc20Targets: targets,
          erc721Transfers: erc721Transfers,
          ownerCalls: ownerCalls,
          validationParams: validationParams,
          callsSigner: callsSigner
        })
      )
    );
  }

  function lAuthDelegation(
    address authenticator,
    bool delegated,
    bytes memory data,
    uint256 nonce,
    uint256 deadline
  ) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(
        keccak256(bytes(L_AUTH_DELEGATION)),
        authenticator,
        delegated,
        keccak256(data),
        nonce,
        deadline
      )
    );
  }

  function lSessionKeyHash(bytes memory publicKey, uint8 keyType, uint256 expiration)
    internal
    pure
    returns (bytes32)
  {
    return keccak256(abi.encode(lSessionKeyTypehash(), keccak256(publicKey), keyType, expiration));
  }

  function lSessionApproval(bytes32 keyHash, bool approved, uint256 nonce, uint256 deadline)
    internal
    pure
    returns (bytes32)
  {
    return keccak256(abi.encode(lSessionApprovalTypehash(), keyHash, approved, nonce, deadline));
  }

  // ---------------------------------------------------------------------------------------------
  // Permit2 digest, rebuilt rather than imported
  // ---------------------------------------------------------------------------------------------

  /**
   * @dev Mirrors Permit2's `PermitBatchWitnessTransferFrom` hashing from its published layout.
   * `witnessTypeString` is supplied by the caller and must be a literal from this file.
   */
  function lPermit2BatchWitnessDigest(
    address[] memory tokens,
    uint256[] memory amounts,
    address spender,
    uint256 nonce,
    uint256 deadline,
    bytes32 witness,
    string memory witnessTypeString
  ) internal view returns (bytes32) {
    bytes32[] memory permitted = new bytes32[](tokens.length);
    for (uint256 i = 0; i < tokens.length; i++) {
      permitted[i] =
        keccak256(abi.encode(keccak256(bytes(L_TOKEN_PERMISSIONS)), tokens[i], amounts[i]));
    }

    bytes32 typeHash = keccak256(abi.encodePacked(L_PERMIT2_BATCH_WITNESS_STUB, witnessTypeString));

    bytes32 structHash = keccak256(
      abi.encode(
        typeHash, keccak256(abi.encodePacked(permitted)), spender, nonce, deadline, witness
      )
    );

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
        keccak256(abi.encode(keccak256(bytes(L_TOKEN_PERMISSIONS)), tokens[i], amounts[i]));
    }

    bytes32 typeHash = keccak256(
      abi.encodePacked(
        'PermitBatchTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline)',
        L_TOKEN_PERMISSIONS
      )
    );

    bytes32 structHash = keccak256(
      abi.encode(typeHash, keccak256(abi.encodePacked(permitted)), spender, nonce, deadline)
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
