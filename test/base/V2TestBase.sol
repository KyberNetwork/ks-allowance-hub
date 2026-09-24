// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Test} from 'forge-std/Test.sol';

import {ERC20Transfer} from 'src/v2/types/ERC20Transfer.sol';
import {ERC721Transfer} from 'src/v2/types/ERC721Transfer.sol';
import {GenericCall} from 'src/v2/types/GenericCall.sol';
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

  string internal constant L_EXECUTION_WITNESS =
    'ExecutionWitness(address relayer,address[] erc20Targets,ERC721Transfer[] erc721Transfers,GenericCall[] genericCalls)';
  string internal constant L_FULFILLMENT_WITNESS =
    'FulfillmentWitness(address solver,address[] erc20Targets,ERC721Transfer[] erc721Transfers,ValidationParams[] validationParams,address callsSigner)';
  string internal constant L_CALLS_APPROVAL =
    'CallsApproval(address owner,GenericCall[] genericCalls,uint256 nonce,uint256 deadline)';
  string internal constant L_AUTH_DELEGATION =
    'AuthDelegation(address verifier,bytes data,uint256 nonce,uint256 deadline)';

  string internal constant L_SESSION_KEY =
    'SessionKey(bytes publicKey,uint8 keyType,uint256 expiration)';
  string internal constant L_SESSION_APPROVAL =
    'SessionApproval(SessionKey sessionKey,uint256 nonce,uint256 deadline)';
  string internal constant L_EXECUTION_APPROVAL =
    'ExecutionApproval(address relayer,ERC20Transfer[] erc20Transfers,ERC721Transfer[] erc721Transfers,GenericCall[] genericCalls,uint256 nonce,uint256 deadline)';
  string internal constant L_FULFILLMENT_APPROVAL =
    'FulfillmentApproval(address solver,ERC20Transfer[] erc20Transfers,ERC721Transfer[] erc721Transfers,ValidationParams[] validationParams,address callsSigner,uint256 nonce,uint256 deadline)';

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
  // Hand-written EIP-712 encodings
  // ---------------------------------------------------------------------------------------------

  /// @dev Referenced types follow the primary type in alphabetical order, per EIP-712
  function lExecutionWitnessTypehash() internal pure returns (bytes32) {
    return keccak256(abi.encodePacked(L_EXECUTION_WITNESS, L_ERC721_TRANSFER, L_GENERIC_CALL));
  }

  function lFulfillmentWitnessTypehash() internal pure returns (bytes32) {
    return
      keccak256(abi.encodePacked(L_FULFILLMENT_WITNESS, L_ERC721_TRANSFER, L_VALIDATION_PARAMS));
  }

  function lCallsApprovalTypehash() internal pure returns (bytes32) {
    return keccak256(abi.encodePacked(L_CALLS_APPROVAL, L_GENERIC_CALL));
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

  /// @dev Sorted: ERC721Transfer, FulfillmentWitness, TokenPermissions, ValidationParams
  function lFulfillmentWitnessTypeString() internal pure returns (string memory) {
    return string(
      abi.encodePacked(
        'FulfillmentWitness witness)',
        L_ERC721_TRANSFER,
        L_FULFILLMENT_WITNESS,
        L_TOKEN_PERMISSIONS,
        L_VALIDATION_PARAMS
      )
    );
  }

  function lHashErc721(ERC721Transfer memory t) internal pure returns (bytes32) {
    return keccak256(abi.encode(keccak256(bytes(L_ERC721_TRANSFER)), t.token, t.tokenId, t.target));
  }

  function lHashCall(GenericCall memory c) internal pure returns (bytes32) {
    return
      keccak256(abi.encode(keccak256(bytes(L_GENERIC_CALL)), c.router, c.value, keccak256(c.data)));
  }

  function lHashValidation(ValidationParams memory v) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(
        keccak256(bytes(L_VALIDATION_PARAMS)),
        v.validator,
        v.action,
        keccak256(v.beforeExecutionInput),
        keccak256(v.afterExecutionInput)
      )
    );
  }

  /// @dev EIP-712 hashes an array of structs as the hash of its concatenated member hashes
  function lHashErc721Array(ERC721Transfer[] memory ts) internal pure returns (bytes32) {
    bytes32[] memory h = new bytes32[](ts.length);
    for (uint256 i = 0; i < ts.length; i++) {
      h[i] = lHashErc721(ts[i]);
    }
    return keccak256(abi.encodePacked(h));
  }

  function lHashCallArray(GenericCall[] memory cs) internal pure returns (bytes32) {
    bytes32[] memory h = new bytes32[](cs.length);
    for (uint256 i = 0; i < cs.length; i++) {
      h[i] = lHashCall(cs[i]);
    }
    return keccak256(abi.encodePacked(h));
  }

  function lHashValidationArray(ValidationParams[] memory vs) internal pure returns (bytes32) {
    bytes32[] memory h = new bytes32[](vs.length);
    for (uint256 i = 0; i < vs.length; i++) {
      h[i] = lHashValidation(vs[i]);
    }
    return keccak256(abi.encodePacked(h));
  }

  function lExecutionWitness(
    address signedCaller,
    address[] memory targets,
    ERC721Transfer[] memory erc721Transfers,
    GenericCall[] memory genericCalls
  ) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(
        lExecutionWitnessTypehash(),
        signedCaller,
        keccak256(abi.encodePacked(targets)),
        lHashErc721Array(erc721Transfers),
        lHashCallArray(genericCalls)
      )
    );
  }

  function lFulfillmentWitness(
    address signedCaller,
    address[] memory targets,
    ERC721Transfer[] memory erc721Transfers,
    ValidationParams[] memory validationParams,
    address callsSigner
  ) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(
        lFulfillmentWitnessTypehash(),
        signedCaller,
        keccak256(abi.encodePacked(targets)),
        lHashErc721Array(erc721Transfers),
        lHashValidationArray(validationParams),
        callsSigner
      )
    );
  }

  function lCallsApproval(
    address callsOwner,
    GenericCall[] memory genericCalls,
    uint256 nonce,
    uint256 deadline
  ) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(
        lCallsApprovalTypehash(), callsOwner, lHashCallArray(genericCalls), nonce, deadline
      )
    );
  }

  function lAuthDelegation(address verifier, bytes memory data, uint256 nonce, uint256 deadline)
    internal
    pure
    returns (bytes32)
  {
    return keccak256(
      abi.encode(keccak256(bytes(L_AUTH_DELEGATION)), verifier, keccak256(data), nonce, deadline)
    );
  }

  function lSessionKeyTypehash() internal pure returns (bytes32) {
    return keccak256(bytes(L_SESSION_KEY));
  }

  function lSessionApprovalTypehash() internal pure returns (bytes32) {
    return keccak256(abi.encodePacked(L_SESSION_APPROVAL, L_SESSION_KEY));
  }

  function lExecutionApprovalTypehash() internal pure returns (bytes32) {
    return keccak256(
      abi.encodePacked(L_EXECUTION_APPROVAL, L_ERC20_TRANSFER, L_ERC721_TRANSFER, L_GENERIC_CALL)
    );
  }

  function lFulfillmentApprovalTypehash() internal pure returns (bytes32) {
    return keccak256(
      abi.encodePacked(
        L_FULFILLMENT_APPROVAL, L_ERC20_TRANSFER, L_ERC721_TRANSFER, L_VALIDATION_PARAMS
      )
    );
  }

  function lHashErc20(ERC20Transfer memory t) internal pure returns (bytes32) {
    return keccak256(abi.encode(keccak256(bytes(L_ERC20_TRANSFER)), t.token, t.target, t.amount));
  }

  function lHashErc20Array(ERC20Transfer[] memory ts) internal pure returns (bytes32) {
    bytes32[] memory h = new bytes32[](ts.length);
    for (uint256 i = 0; i < ts.length; i++) {
      h[i] = lHashErc20(ts[i]);
    }
    return keccak256(abi.encodePacked(h));
  }

  function lSessionKeyHash(bytes memory publicKey, uint8 keyType, uint256 expiration)
    internal
    pure
    returns (bytes32)
  {
    return keccak256(abi.encode(lSessionKeyTypehash(), keccak256(publicKey), keyType, expiration));
  }

  function lSessionApproval(bytes32 keyHash, uint256 nonce, uint256 deadline)
    internal
    pure
    returns (bytes32)
  {
    return keccak256(abi.encode(lSessionApprovalTypehash(), keyHash, nonce, deadline));
  }

  function lExecutionApproval(
    address signedCaller,
    ERC20Transfer[] memory erc20Transfers,
    ERC721Transfer[] memory erc721Transfers,
    GenericCall[] memory genericCalls,
    uint256 nonce,
    uint256 deadline
  ) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(
        lExecutionApprovalTypehash(),
        signedCaller,
        lHashErc20Array(erc20Transfers),
        lHashErc721Array(erc721Transfers),
        lHashCallArray(genericCalls),
        nonce,
        deadline
      )
    );
  }

  function lFulfillmentApproval(
    address signedCaller,
    ERC20Transfer[] memory erc20Transfers,
    ERC721Transfer[] memory erc721Transfers,
    ValidationParams[] memory validationParams,
    address callsSigner,
    uint256 nonce,
    uint256 deadline
  ) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(
        lFulfillmentApprovalTypehash(),
        signedCaller,
        lHashErc20Array(erc20Transfers),
        lHashErc721Array(erc721Transfers),
        lHashValidationArray(validationParams),
        callsSigner,
        nonce,
        deadline
      )
    );
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
