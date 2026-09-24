// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {V2TestBase} from 'test/base/V2TestBase.sol';

import {ERC20Transfer} from 'src/v2/types/ERC20Transfer.sol';
import {ERC721Transfer} from 'src/v2/types/ERC721Transfer.sol';
import {GenericCall} from 'src/v2/types/GenericCall.sol';
import {ValidationParams} from 'src/v2/types/ValidationParams.sol';

import {ExecutionApprovalLibrary} from 'src/verifiers/types/ExecutionApproval.sol';
import {FulfillmentApprovalLibrary} from 'src/verifiers/types/FulfillmentApproval.sol';
import {KeyType} from 'src/verifiers/types/KeyType.sol';
import {SessionApprovalLibrary} from 'src/verifiers/types/SessionApproval.sol';
import {SessionKey, SessionKeyLibrary} from 'src/verifiers/types/SessionKey.sol';

/**
 * @notice T712-09..12 — the four verifier-side EIP-712 types.
 * @dev The production constants are the values under test; every expected value is built from the
 * literals in {V2TestBase}, which were transcribed from the struct definitions. Together with
 * `test/v2/types/Eip712.t.sol` this is the only place a production type string or typehash may be
 * read, and there it is never the expected side.
 *
 * Each row also pins the struct encoding, not only the typehash, and the two approval rows pin the
 * calldata and memory hashers against the same literal so the pair can never drift apart. No
 * contract is under test here, so this batch inherits the global base directly.
 */
contract VerifierEip712Test is V2TestBase {
  // -------------------------------------------------------------------------------------------
  // T712-09 — SessionKey
  // -------------------------------------------------------------------------------------------

  function test_T712_09_sessionKeyTypehashAndStructHash() public view {
    assertEq(SessionKeyLibrary.SESSION_KEY_TYPEHASH, lSessionKeyTypehash(), 'typehash');

    SessionKey memory key = _sampleKey();

    assertEq(
      this.extHashSessionKey(key),
      lSessionKeyHash(key.publicKey, uint8(key.keyType), key.expiration),
      'struct hash'
    );
  }

  // -------------------------------------------------------------------------------------------
  // T712-10 — SessionApproval
  // -------------------------------------------------------------------------------------------

  function test_T712_10_sessionApprovalTypehashAndStructHash() public pure {
    assertEq(
      SessionApprovalLibrary.SESSION_APPROVAL_TYPEHASH, lSessionApprovalTypehash(), 'typehash'
    );

    bytes32 keyHash = keccak256('an arbitrary key hash');

    assertEq(
      SessionApprovalLibrary.hash(keyHash, 7, 99), lSessionApproval(keyHash, 7, 99), 'struct hash'
    );
  }

  // -------------------------------------------------------------------------------------------
  // T712-11 — ExecutionApproval
  // -------------------------------------------------------------------------------------------

  function test_T712_11_executionApprovalTypehashAndStructHash() public view {
    assertEq(
      ExecutionApprovalLibrary.EXECUTION_APPROVAL_TYPEHASH, lExecutionApprovalTypehash(), 'typehash'
    );

    (ERC20Transfer[] memory erc20s, ERC721Transfer[] memory nfts) = _sampleTransfers();
    GenericCall[] memory calls = _sampleCalls();

    bytes32 expected = lExecutionApproval(ANY, erc20s, nfts, calls, 11, 1234);

    assertEq(
      ExecutionApprovalLibrary.hashMemory(ANY, erc20s, nfts, calls, 11, 1234),
      expected,
      'memory hasher'
    );
    assertEq(
      this.extHashExecutionApproval(ANY, erc20s, nfts, calls, 11, 1234), expected, 'calldata hasher'
    );
  }

  // -------------------------------------------------------------------------------------------
  // T712-12 — FulfillmentApproval
  // -------------------------------------------------------------------------------------------

  function test_T712_12_fulfillmentApprovalTypehashAndStructHash() public view {
    assertEq(
      FulfillmentApprovalLibrary.FULFILLMENT_APPROVAL_TYPEHASH,
      lFulfillmentApprovalTypehash(),
      'typehash'
    );

    (ERC20Transfer[] memory erc20s, ERC721Transfer[] memory nfts) = _sampleTransfers();
    ValidationParams[] memory validations = _sampleValidations();
    address callsSigner = address(0xBEEF);

    bytes32 expected = lFulfillmentApproval(ANY, erc20s, nfts, validations, callsSigner, 12, 5678);

    assertEq(
      FulfillmentApprovalLibrary.hashMemory(ANY, erc20s, nfts, validations, callsSigner, 12, 5678),
      expected,
      'memory hasher'
    );
    assertEq(
      this.extHashFulfillmentApproval(ANY, erc20s, nfts, validations, callsSigner, 12, 5678),
      expected,
      'calldata hasher'
    );
  }

  // -------------------------------------------------------------------------------------------
  // external wrappers so the calldata overloads are reachable from memory-built fixtures
  // -------------------------------------------------------------------------------------------

  function extHashSessionKey(SessionKey calldata key) external pure returns (bytes32) {
    return key.hash();
  }

  function extHashExecutionApproval(
    address relayerAddress,
    ERC20Transfer[] calldata erc20Transfers,
    ERC721Transfer[] calldata erc721Transfers,
    GenericCall[] calldata genericCalls,
    uint256 nonce,
    uint256 deadline
  ) external pure returns (bytes32) {
    return ExecutionApprovalLibrary.hash(
      relayerAddress, erc20Transfers, erc721Transfers, genericCalls, nonce, deadline
    );
  }

  function extHashFulfillmentApproval(
    address solverAddress,
    ERC20Transfer[] calldata erc20Transfers,
    ERC721Transfer[] calldata erc721Transfers,
    ValidationParams[] calldata validationParams,
    address callsSigner,
    uint256 nonce,
    uint256 deadline
  ) external pure returns (bytes32) {
    return FulfillmentApprovalLibrary.hash(
      solverAddress, erc20Transfers, erc721Transfers, validationParams, callsSigner, nonce, deadline
    );
  }

  // -------------------------------------------------------------------------------------------

  function _sampleKey() private pure returns (SessionKey memory) {
    return SessionKey({
      publicKey: hex'c0ffee00c0ffee11', keyType: KeyType.WebAuthn, expiration: 1_700_000_000
    });
  }

  function _sampleTransfers()
    private
    pure
    returns (ERC20Transfer[] memory erc20s, ERC721Transfer[] memory nfts)
  {
    erc20s = new ERC20Transfer[](2);
    erc20s[0] = ERC20Transfer({token: address(0xAAA1), target: address(0xBBB1), amount: 1000});
    erc20s[1] = ERC20Transfer({token: address(0xAAA2), target: address(0xBBB2), amount: 0});

    nfts = new ERC721Transfer[](1);
    nfts[0] = ERC721Transfer({token: address(0xCCC1), tokenId: 42, target: address(0xDDD1)});
  }

  function _sampleCalls() private pure returns (GenericCall[] memory calls) {
    calls = new GenericCall[](2);
    calls[0] = GenericCall({router: address(0xE001), value: 1 ether, data: hex'deadbeef'});
    calls[1] = GenericCall({router: address(0xE002), value: 0, data: ''});
  }

  function _sampleValidations() private pure returns (ValidationParams[] memory validations) {
    validations = new ValidationParams[](2);
    validations[0] = ValidationParams({
      validator: address(0xF001),
      action: keccak256('ACTION_ONE'),
      beforeExecutionInput: hex'01',
      afterExecutionInput: hex'02'
    });
    validations[1] = ValidationParams({
      validator: address(0xF002),
      action: bytes32(0),
      beforeExecutionInput: '',
      afterExecutionInput: hex'03'
    });
  }
}
