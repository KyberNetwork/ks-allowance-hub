// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {V2TestBase} from 'test/base/V2TestBase.sol';

import {AuthDelegationLibrary} from 'src/base/types/AuthDelegation.sol';
import {CallsApprovalLibrary} from 'src/v2/types/CallsApproval.sol';
import {ERC20Transfer, ERC20TransferLibrary} from 'src/v2/types/ERC20Transfer.sol';
import {ERC721Transfer, ERC721TransferLibrary} from 'src/v2/types/ERC721Transfer.sol';
import {ExecutionWitnessLibrary} from 'src/v2/types/ExecutionWitness.sol';
import {FulfillmentWitnessLibrary} from 'src/v2/types/FulfillmentWitness.sol';
import {GenericCall, GenericCallLibrary} from 'src/v2/types/GenericCall.sol';
import {ValidationParams, ValidationParamsLibrary} from 'src/v2/types/ValidationParams.sol';

/**
 * @notice T712-01..08 plus the calldata/memory differential and the array-encoding anchor.
 * @dev The production constants are the values under test here; every expected value is built from
 * the literals in {V2TestBase}, which were transcribed from the struct definitions. This is the
 * only batch allowed to read a production type string or typehash.
 */
contract Eip712Test is V2TestBase {
  // -------------------------------------------------------------------------------------------
  // T712-01..08 — production constants against hand-written literals
  // -------------------------------------------------------------------------------------------

  function test_T712_01_executionWitnessTypehash() public pure {
    assertEq(ExecutionWitnessLibrary.EXECUTION_WITNESS_TYPEHASH, lExecutionWitnessTypehash());
  }

  function test_T712_01b_executionWitnessPermit2TypeString() public pure {
    assertEq(
      ExecutionWitnessLibrary.EXECUTION_WITNESS_PERMIT2_TYPE_STRING, lExecutionWitnessTypeString()
    );
  }

  function test_T712_02_fulfillmentWitnessTypehash() public pure {
    assertEq(FulfillmentWitnessLibrary.FULFILLMENT_WITNESS_TYPEHASH, lFulfillmentWitnessTypehash());
  }

  function test_T712_02b_fulfillmentWitnessPermit2TypeString() public pure {
    assertEq(
      FulfillmentWitnessLibrary.FULFILLMENT_WITNESS_PERMIT2_TYPE_STRING,
      lFulfillmentWitnessTypeString()
    );
  }

  function test_T712_03_callsApprovalTypehash() public pure {
    assertEq(CallsApprovalLibrary.CALLS_APPROVAL_TYPEHASH, lCallsApprovalTypehash());
  }

  function test_T712_04_validationParamsTypehash() public pure {
    assertEq(
      ValidationParamsLibrary.VALIDATION_PARAMS_TYPEHASH, keccak256(bytes(L_VALIDATION_PARAMS))
    );
  }

  function test_T712_05_erc20TransferTypehash() public pure {
    assertEq(ERC20TransferLibrary.ERC20_TRANSFER_TYPEHASH, keccak256(bytes(L_ERC20_TRANSFER)));
  }

  function test_T712_06_erc721TransferTypehash() public pure {
    assertEq(ERC721TransferLibrary.ERC721_TRANSFER_TYPEHASH, keccak256(bytes(L_ERC721_TRANSFER)));
  }

  function test_T712_07_genericCallTypehash() public pure {
    assertEq(GenericCallLibrary.GENERIC_CALL_TYPEHASH, keccak256(bytes(L_GENERIC_CALL)));
  }

  function test_T712_08_authDelegationTypehash() public pure {
    assertEq(AuthDelegationLibrary.AUTH_DELEGATION_TYPEHASH, keccak256(bytes(L_AUTH_DELEGATION)));
  }

  // -------------------------------------------------------------------------------------------
  // Struct hashing agrees with the independent encoding, not just the typehash
  // -------------------------------------------------------------------------------------------

  function test_T712_executionWitnessStructHash() public pure {
    (address[] memory targets, ERC721Transfer[] memory nfts, GenericCall[] memory calls) = _sample();

    assertEq(
      ExecutionWitnessLibrary.hashMemory(ANY, targets, nfts, calls),
      lExecutionWitness(ANY, targets, nfts, calls)
    );
  }

  function test_T712_fulfillmentWitnessStructHash() public pure {
    (address[] memory targets, ERC721Transfer[] memory nfts,) = _sample();
    ValidationParams[] memory vs = _sampleValidations();

    assertEq(
      FulfillmentWitnessLibrary.hashMemory(ANY, targets, nfts, vs, address(0xBEEF)),
      lFulfillmentWitness(ANY, targets, nfts, vs, address(0xBEEF))
    );
  }

  function test_T712_callsApprovalStructHash() public pure {
    (,, GenericCall[] memory calls) = _sample();

    assertEq(
      CallsApprovalLibrary.hashMemory(address(0xA11CE), calls, 7, 99),
      lCallsApproval(address(0xA11CE), calls, 7, 99)
    );
  }

  // -------------------------------------------------------------------------------------------
  // T712-ARRAY — the packed address encoding equals the per-element encoding
  // -------------------------------------------------------------------------------------------

  function test_T712_ARRAY_addressArrayEncoding() public pure {
    address a0 = address(0x1111111111111111111111111111111111111111);
    address a1 = address(0x2222222222222222222222222222222222222222);
    address a2 = address(0x3333333333333333333333333333333333333333);

    address[] memory arr = new address[](3);
    arr[0] = a0;
    arr[1] = a1;
    arr[2] = a2;

    // expected side is written out element by element, not with abi.encodePacked on the array
    assertEq(keccak256(abi.encodePacked(arr)), keccak256(abi.encode(a0, a1, a2)));
  }

  // -------------------------------------------------------------------------------------------
  // T712-DIFF — the calldata and memory variants must never drift apart
  // -------------------------------------------------------------------------------------------

  function testFuzz_T712_DIFF_genericCall(GenericCall memory c) public view {
    assertEq(this.extHashCall(c), c.hashMemory());
  }

  function testFuzz_T712_DIFF_erc20Transfer(ERC20Transfer memory t) public view {
    assertEq(this.extHashErc20(t), t.hashMemory());
  }

  function testFuzz_T712_DIFF_erc721Transfer(ERC721Transfer memory t) public view {
    assertEq(this.extHashErc721(t), t.hashMemory());
  }

  function testFuzz_T712_DIFF_validationParams(ValidationParams memory v) public view {
    assertEq(this.extHashValidation(v), v.hashMemory());
  }

  // external wrappers so the calldata overloads are reachable from a memory-built fixture
  function extHashCall(GenericCall calldata c) external pure returns (bytes32) {
    return c.hash();
  }

  function extHashErc20(ERC20Transfer calldata t) external pure returns (bytes32) {
    return t.hash();
  }

  function extHashErc721(ERC721Transfer calldata t) external pure returns (bytes32) {
    return t.hash();
  }

  function extHashValidation(ValidationParams calldata v) external pure returns (bytes32) {
    return v.hash();
  }

  // -------------------------------------------------------------------------------------------

  function _sample()
    private
    pure
    returns (address[] memory targets, ERC721Transfer[] memory nfts, GenericCall[] memory calls)
  {
    targets = new address[](2);
    targets[0] = address(0xAAA1);
    targets[1] = address(0xAAA2);

    nfts = new ERC721Transfer[](1);
    nfts[0] = ERC721Transfer({token: address(0xBADD), tokenId: 42, target: address(0xBBB1)});

    calls = new GenericCall[](2);
    calls[0] = GenericCall({router: address(0xCCC1), value: 1 ether, data: hex'deadbeef'});
    calls[1] = GenericCall({router: address(0xCCC2), value: 0, data: ''});
  }

  function _sampleValidations() private pure returns (ValidationParams[] memory vs) {
    vs = new ValidationParams[](2);
    vs[0] = ValidationParams({
      validator: address(0xDDD1),
      action: keccak256('ACTION_ONE'),
      beforeExecutionInput: hex'01',
      afterExecutionInput: hex'02'
    });
    vs[1] = ValidationParams({
      validator: address(0xDDD2),
      action: bytes32(0),
      beforeExecutionInput: '',
      afterExecutionInput: hex'03'
    });
  }
}
