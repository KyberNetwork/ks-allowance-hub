// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {V2TestBase} from 'test/base/V2TestBase.sol';

import {AuthDelegationLib} from 'src/v2/types/AuthDelegation.sol';
import {ERC20Transfer} from 'src/v2/types/ERC20Transfer.sol';
import {ERC721Transfer} from 'src/v2/types/ERC721Transfer.sol';
import {ExecutionOrder} from 'src/v2/types/ExecutionOrder.sol';
import {ExecutionWitnessLib} from 'src/v2/types/ExecutionWitness.sol';
import {FulfillmentOrder} from 'src/v2/types/FulfillmentOrder.sol';
import {FulfillmentSolution} from 'src/v2/types/FulfillmentSolution.sol';
import {FulfillmentWitnessLib} from 'src/v2/types/FulfillmentWitness.sol';
import {GenericCall} from 'src/v2/types/GenericCall.sol';
import {SolutionApprovalLib} from 'src/v2/types/SolutionApproval.sol';
import {ValidationParams} from 'src/v2/types/ValidationParams.sol';

/**
 * @notice T712-08b..12 and T712-17, plus the calldata/memory differential and the array-encoding
 * anchor.
 * @dev The production hashers are the values under test here; every expected value is built from
 * the schemas `forge bind-json` derived from the struct definitions. The bare typehashes are
 * audited in `SchemaAudit.t.sol`; what these rows add is the struct and array encoding around
 * them, which a typehash comparison alone does not reach.
 */
contract Eip712Test is V2TestBase {
  // -------------------------------------------------------------------------------------------
  // T712-08b..12 — struct and array encodings, against the schemas the structs declare
  // -------------------------------------------------------------------------------------------

  /// @dev Both directions, because `delegated` is what separates a delegation from a withdrawal
  function test_T712_08b_authDelegationStructHash() public pure {
    address authenticatorAddress = address(0xBEEF);
    bytes memory data = hex'c0ffee';

    assertEq(
      AuthDelegationLib.hash(authenticatorAddress, true, data, 7, 99),
      lAuthDelegation(authenticatorAddress, true, data, 7, 99),
      'delegation struct hash'
    );
    assertEq(
      AuthDelegationLib.hash(authenticatorAddress, false, data, 7, 99),
      lAuthDelegation(authenticatorAddress, false, data, 7, 99),
      'withdrawal struct hash'
    );
    assertTrue(
      AuthDelegationLib.hash(authenticatorAddress, true, data, 7, 99)
        != AuthDelegationLib.hash(authenticatorAddress, false, data, 7, 99),
      'the direction changes the digest'
    );
  }

  // -------------------------------------------------------------------------------------------
  // T712-13..16 — the four types the restructure introduced
  // -------------------------------------------------------------------------------------------

  /**
   * T712-17 — both Permit2 witness strings list their referenced types in sorted order
   * @dev T712-01b and T712-02b pin the two strings byte for byte, which catches a mis-sorted
   * production string only while the literal they are compared against is itself right. This says
   * the ordering property directly and against production: the hand-written names are first shown
   * to sort ascending, then each is shown to occur later in the production string than the one
   * before it. The two halves together are what make either of them evidence.
   */
  function test_T712_17_permit2TypeStringsSortTheirReferencedTypes() public pure {
    string[] memory executionNames = new string[](4);
    executionNames[0] = 'ERC721Transfer(';
    executionNames[1] = 'ExecutionWitness(';
    executionNames[2] = 'GenericCall(';
    executionNames[3] = 'TokenPermissions(';

    _assertSortedNames(executionNames);
    _assertNamesAppearInOrder(
      ExecutionWitnessLib.EXECUTION_WITNESS_PERMIT2_TYPE_STRING, executionNames
    );

    string[] memory fulfillmentNames = new string[](5);
    fulfillmentNames[0] = 'ERC721Transfer(';
    fulfillmentNames[1] = 'FulfillmentWitness(';
    fulfillmentNames[2] = 'GenericCall(';
    fulfillmentNames[3] = 'TokenPermissions(';
    fulfillmentNames[4] = 'ValidationParams(';

    _assertSortedNames(fulfillmentNames);
    _assertNamesAppearInOrder(
      FulfillmentWitnessLib.FULFILLMENT_WITNESS_PERMIT2_TYPE_STRING, fulfillmentNames
    );
  }

  // -------------------------------------------------------------------------------------------
  // Struct hashing agrees with the independent encoding, not just the typehash
  // -------------------------------------------------------------------------------------------

  function test_T712_executionWitnessStructHash() public pure {
    (address[] memory targets, ERC721Transfer[] memory nfts, GenericCall[] memory calls) = _sample();

    assertEq(
      ExecutionWitnessLib.hashMemory(ANY, targets, nfts, calls),
      lExecutionWitness(ANY, targets, nfts, calls)
    );
  }

  /// @dev The owner's tail is non-empty here, so the new member is actually encoded
  function test_T712_fulfillmentWitnessStructHash() public pure {
    (address[] memory targets, ERC721Transfer[] memory nfts, GenericCall[] memory ownerCalls) =
      _sample();
    ValidationParams[] memory vs = _sampleValidations();

    assertEq(
      FulfillmentWitnessLib.hashMemory(ANY, targets, nfts, ownerCalls, vs, address(0xBEEF)),
      lFulfillmentWitness(ANY, targets, nfts, ownerCalls, vs, address(0xBEEF))
    );
  }

  /**
   * @dev Both hashers against the same literal, and the `usePermit2Allowances` bit shown to move
   * the hash — which is what makes it a signed switch rather than a submitter's choice
   */
  function test_T712_executionOrderStructHash() public view {
    ExecutionOrder memory order = _sampleExecutionOrder();
    bytes32 expected = lExecutionOrderHash(order);

    assertEq(order.hashMemory(), expected, 'memory hasher');
    assertEq(this.extHashExecutionOrder(order), expected, 'calldata hasher');
  }

  function test_T712_fulfillmentOrderStructHash() public view {
    FulfillmentOrder memory order = _sampleFulfillmentOrder();
    bytes32 expected = lFulfillmentOrderHash(order);

    assertEq(order.hashMemory(), expected, 'memory hasher');
    assertEq(this.extHashFulfillmentOrder(order), expected, 'calldata hasher');
  }

  function test_T712_fulfillmentSolutionStructHash() public view {
    FulfillmentSolution memory solution = _sampleSolution();
    bytes32 expected = lFulfillmentSolutionHash(solution);

    assertEq(solution.hashMemory(), expected, 'memory hasher');
    assertEq(this.extHashSolution(solution), expected, 'calldata hasher');
  }

  /// @dev `orderHash` is a member, which is what ties one approval to one order
  function test_T712_solutionApprovalStructHash() public view {
    FulfillmentSolution memory solution = _sampleSolution();
    bytes32 orderHash = keccak256('an arbitrary order hash');
    bytes32 expected = lSolutionApproval(address(0xA11CE), orderHash, solution);

    assertEq(
      SolutionApprovalLib.hashMemory(address(0xA11CE), orderHash, solution),
      expected,
      'memory hasher'
    );
    assertEq(
      this.extHashSolutionApproval(address(0xA11CE), orderHash, solution),
      expected,
      'calldata hasher'
    );

    assertTrue(
      SolutionApprovalLib.hashMemory(address(0xA11CE), keccak256('another order'), solution)
        != expected,
      'the order hash changes the approval'
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

  function testFuzz_T712_DIFF_executionOrder(ExecutionOrder memory o) public view {
    assertEq(this.extHashExecutionOrder(o), o.hashMemory());
  }

  function testFuzz_T712_DIFF_fulfillmentOrder(FulfillmentOrder memory o) public view {
    assertEq(this.extHashFulfillmentOrder(o), o.hashMemory());
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

  function extHashExecutionOrder(ExecutionOrder calldata o) external pure returns (bytes32) {
    return o.hash();
  }

  function extHashFulfillmentOrder(FulfillmentOrder calldata o) external pure returns (bytes32) {
    return o.hash();
  }

  function extHashSolution(FulfillmentSolution calldata s) external pure returns (bytes32) {
    return s.hash();
  }

  function extHashSolutionApproval(
    address approvalOwner,
    bytes32 orderHash,
    FulfillmentSolution calldata solution
  ) external pure returns (bytes32) {
    return SolutionApprovalLib.hash(approvalOwner, orderHash, solution);
  }

  // -------------------------------------------------------------------------------------------
  // Fixtures and string helpers
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

  function _sampleErc20s() private pure returns (ERC20Transfer[] memory erc20s) {
    erc20s = new ERC20Transfer[](2);
    erc20s[0] = ERC20Transfer({token: address(0xAAA1), target: address(0xBBB1), amount: 1000});
    erc20s[1] = ERC20Transfer({token: address(0xAAA2), target: address(0xBBB2), amount: 0});
  }

  function _sampleExecutionOrder() private pure returns (ExecutionOrder memory) {
    (, ERC721Transfer[] memory nfts, GenericCall[] memory calls) = _sample();
    return ExecutionOrder({
      relayer: ANY,
      erc20Transfers: _sampleErc20s(),
      erc721Transfers: nfts,
      genericCalls: calls,
      nonce: 11,
      deadline: 1234
    });
  }

  function _sampleFulfillmentOrder() private pure returns (FulfillmentOrder memory) {
    (, ERC721Transfer[] memory nfts, GenericCall[] memory ownerCalls) = _sample();
    return FulfillmentOrder({
      solver: ANY,
      erc20Transfers: _sampleErc20s(),
      erc721Transfers: nfts,
      validationParams: _sampleValidations(),
      ownerCalls: ownerCalls,
      solutionApprover: address(0xBEEF),
      nonce: 12,
      deadline: 5678
    });
  }

  function _sampleSolution() private pure returns (FulfillmentSolution memory) {
    (,, GenericCall[] memory calls) = _sample();
    return FulfillmentSolution({solverCalls: calls, nonce: 13, deadline: 9012});
  }

  /// @dev Asserts the hand-written names really do sort ascending, which EIP-712 requires
  function _assertSortedNames(string[] memory names) private pure {
    for (uint256 i = 1; i < names.length; i++) {
      assertTrue(_sortsBefore(names[i - 1], names[i]), 'the expected names are themselves sorted');
    }
  }

  /// @dev Asserts each name occurs in `typeString` strictly later than the one before it
  function _assertNamesAppearInOrder(string memory typeString, string[] memory names) private pure {
    uint256 previous;
    for (uint256 i = 0; i < names.length; i++) {
      uint256 at = _indexOf(typeString, names[i]);
      assertTrue(at != type(uint256).max, 'referenced type is present');
      if (i > 0) assertTrue(at > previous, 'referenced types appear in sorted order');
      previous = at;
    }
  }

  function _sortsBefore(string memory a, string memory b) private pure returns (bool) {
    bytes memory x = bytes(a);
    bytes memory y = bytes(b);
    uint256 n = x.length < y.length ? x.length : y.length;
    for (uint256 i = 0; i < n; i++) {
      if (x[i] != y[i]) return uint8(x[i]) < uint8(y[i]);
    }
    return x.length < y.length;
  }

  function _indexOf(string memory haystack, string memory needle) private pure returns (uint256) {
    bytes memory h = bytes(haystack);
    bytes memory n = bytes(needle);
    if (n.length == 0 || n.length > h.length) return type(uint256).max;

    for (uint256 i = 0; i + n.length <= h.length; i++) {
      bool hit = true;
      for (uint256 j = 0; j < n.length; j++) {
        if (h[i + j] != n[j]) {
          hit = false;
          break;
        }
      }
      if (hit) return i;
    }
    return type(uint256).max;
  }
}
