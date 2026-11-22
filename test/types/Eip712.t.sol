// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {SchemaHash} from 'test/base/SchemaHash.sol';
import {V2TestBase} from 'test/base/V2TestBase.sol';

import {CalldataHashLib} from 'src/libraries/CalldataHashLib.sol';

import {AHV2Order, AHV2OrderLib} from 'src/types/AHV2Order.sol';
import {AHV2Solution} from 'src/types/AHV2Solution.sol';
import {AuthDelegation, AuthDelegationLib} from 'src/types/AuthDelegation.sol';
import {CallParams} from 'src/types/CallParams.sol';
import {ERC20Allowance} from 'src/types/ERC20Allowance.sol';
import {ERC721Approval} from 'src/types/ERC721Approval.sol';
import {HookParams} from 'src/types/HookParams.sol';
import {SolutionApproval, SolutionApprovalLib} from 'src/types/SolutionApproval.sol';

/**
 * @notice T712-08b..12 and T712-17, plus the fuzzed struct hashes and the array-encoding anchors.
 * @dev The production hashers are the values under test here; every expected value is built from
 * the schemas `forge bind-json` derived from the struct definitions. The bare typehashes are
 * audited in `SchemaAudit.t.sol`; what these rows add is the struct and array encoding around
 * them, which a typehash comparison alone does not reach.
 */
contract Eip712Test is V2TestBase {
  bytes internal constant CLIENT_DATA = 'client-ref:91c2';

  // -------------------------------------------------------------------------------------------
  // T712-08b..12 — struct and array encodings, against the schemas the structs declare
  // -------------------------------------------------------------------------------------------

  /**
   * T712-08b — the {AuthDelegation} hash matches the independent hash and moves with its inputs
   * @dev Both directions, because `delegated` is what separates a delegation from a withdrawal, and
   * both owners, because `owner` is what ties the decision to one account
   */
  function test_T712_08b_authDelegationStructHash() public pure {
    address delegator = address(0xA11CE);
    address authenticatorAddress = address(0xBEEF);
    bytes memory data = hex'c0ffee';
    AuthDelegation memory delegation = AuthDelegation({
      owner: delegator,
      authenticator: authenticatorAddress,
      delegated: true,
      data: data,
      nonce: 7,
      deadline: 99
    });
    AuthDelegation memory withdrawal = AuthDelegation({
      owner: delegator,
      authenticator: authenticatorAddress,
      delegated: false,
      data: data,
      nonce: 7,
      deadline: 99
    });

    assertEq(
      AuthDelegationLib.hash(delegator, authenticatorAddress, true, data, 7, 99),
      SchemaHash.authDelegation(delegation),
      'delegation struct hash'
    );
    assertEq(
      AuthDelegationLib.hash(delegator, authenticatorAddress, false, data, 7, 99),
      SchemaHash.authDelegation(withdrawal),
      'withdrawal struct hash'
    );
    assertEq(
      AuthDelegationLib.hash(delegation),
      SchemaHash.authDelegation(delegation),
      'the struct form hashes as the field form'
    );
    assertTrue(
      AuthDelegationLib.hash(delegator, authenticatorAddress, true, data, 7, 99)
        != AuthDelegationLib.hash(delegator, authenticatorAddress, false, data, 7, 99),
      'the direction changes the digest'
    );
    assertTrue(
      AuthDelegationLib.hash(delegator, authenticatorAddress, true, data, 7, 99)
        != AuthDelegationLib.hash(address(0xB0B), authenticatorAddress, true, data, 7, 99),
      'the owner changes the digest'
    );
  }

  // -------------------------------------------------------------------------------------------
  // T712-13..16 — further signed types
  // -------------------------------------------------------------------------------------------

  /**
   * T712-17 — the Permit2 witness string lists its referenced types in sorted order
   * @dev T712-01b pins the string byte for byte, which catches a mis-sorted production string only
   * while the literal it is compared against is itself right. This says the ordering property
   * directly and against production: the hand-written names are first shown to sort ascending,
   * then each is shown to occur later in the production string than the one before it. Neither
   * half is evidence without the other.
   */
  function test_T712_17_permit2TypeStringSortsItsReferencedTypes() public pure {
    string[] memory names = new string[](6);
    names[0] = 'AHV2Order(';
    names[1] = 'CallParams(';
    names[2] = 'ERC20Allowance(';
    names[3] = 'ERC721Approval(';
    names[4] = 'HookParams(';
    names[5] = 'TokenPermissions(';

    _assertSortedNames(names);
    _assertNamesAppearInOrder(AHV2OrderLib.PERMIT2_ORDER_TYPE_STRING, names);
  }

  // -------------------------------------------------------------------------------------------
  // Struct hashing agrees with the independent encoding, not just the typehash
  // -------------------------------------------------------------------------------------------

  /// The hashes of the sample {CallParams} and {HookParams} entries match {SchemaHash}
  function test_T712_callAndHookStructHash() public view {
    CallParams[] memory calls = _sampleCalls();
    for (uint256 i = 0; i < calls.length; i++) {
      bytes32 expected = SchemaHash.callParams(calls[i]);
      assertEq(this.extHashCall(calls[i]), expected, 'call hasher');
    }

    HookParams[] memory hooks = _sampleHooks();
    for (uint256 i = 0; i < hooks.length; i++) {
      bytes32 expected = SchemaHash.hookParams(hooks[i]);
      assertEq(this.extHashHook(hooks[i]), expected, 'hook hasher');
    }
  }

  /// The order hash matches {SchemaHash}
  function test_T712_orderStructHash() public view {
    AHV2Order memory order = _sampleOrder();
    bytes32 expected = SchemaHash.ahv2Order(order);

    assertEq(this.extHashOrder(order), expected, 'hasher');
  }

  /**
   * The order hash matches {SchemaHash} with client data, and clearing it moves the hash
   * @dev The order hasher with non-empty client data, and the client data moves the hash
   */
  function test_T712_orderClientDataStructHash() public view {
    AHV2Order memory order = _sampleOrder();
    assertEq(order.clientData, CLIENT_DATA);

    bytes32 expected = SchemaHash.ahv2Order(order);
    assertEq(this.extHashOrder(order), expected, 'with client data');

    order.clientData = '';
    bytes32 cleared = SchemaHash.ahv2Order(order);
    assertEq(this.extHashOrder(order), cleared, 'cleared');
    assertTrue(cleared != expected, 'client data is signed');
  }

  /**
   * T712-DIFF — the authenticator alone moves the order hash and the approval hash
   * @dev The two orders differ only in `authenticator`, and the production hashers agree with
   * {SchemaHash} on both.
   */
  function test_T712_DIFF_authenticatorMovesOrderAndApprovalHash() public view {
    AHV2Order memory order = _sampleOrder();
    AHV2Solution memory solution = _sampleSolution();
    AHV2Order memory other = _sampleOrder();
    other.authenticator = address(0xAD8);

    bytes32 orderHash = SchemaHash.ahv2Order(order);
    bytes32 otherHash = SchemaHash.ahv2Order(other);
    assertTrue(orderHash != otherHash, 'the authenticator is in the order hash');
    assertEq(this.extHashOrder(order), orderHash, 'order hasher');
    assertEq(this.extHashOrder(other), otherHash, 'other order hasher');

    bytes32 approval = _approvalHash(order, solution);
    bytes32 otherApproval = _approvalHash(other, solution);
    assertTrue(approval != otherApproval, 'the authenticator is in the approval hash');
    assertEq(this.extHashSolutionApproval(orderHash, solution), approval, 'approval hasher');
    assertEq(this.extHashSolutionApproval(otherHash, solution), otherApproval, 'other hasher');
  }

  /**
   * The solution hash matches {SchemaHash}, and the nonce, `callValues` and `solverData` move the
   * hash
   * @dev The `solverData` is changed in one entry, then in length, so both its elements and its
   * count are encoded.
   */
  function test_T712_solutionStructHash() public view {
    AHV2Solution memory solution = _sampleSolution();
    bytes32 expected = SchemaHash.ahv2Solution(solution);

    assertEq(this.extHashSolution(solution), expected, 'hasher');

    AHV2Solution memory otherNonce = _sampleSolution();
    otherNonce.nonce += 1;
    bytes32 changed = SchemaHash.ahv2Solution(otherNonce);
    assertTrue(changed != expected, 'the nonce changes the solution hash');
    assertEq(this.extHashSolution(otherNonce), changed, 'changed nonce');

    AHV2Solution memory otherValue = _sampleSolution();
    otherValue.callValues[1] += 1;
    changed = SchemaHash.ahv2Solution(otherValue);
    assertTrue(changed != expected, 'an entry of callValues changes the solution hash');
    assertEq(this.extHashSolution(otherValue), changed, 'changed value');

    AHV2Solution memory longerValues = _sampleSolution();
    longerValues.callValues = new uint256[](3);
    longerValues.callValues[0] = 1 ether;
    changed = SchemaHash.ahv2Solution(longerValues);
    assertTrue(changed != expected, 'the count of callValues changes the solution hash');
    assertEq(this.extHashSolution(longerValues), changed, 'longer callValues');

    AHV2Solution memory otherData = _sampleSolution();
    otherData.solverData[0] = hex'5e';
    changed = SchemaHash.ahv2Solution(otherData);
    assertTrue(changed != expected, 'an entry of solverData changes the solution hash');
    assertEq(this.extHashSolution(otherData), changed, 'changed entry');

    AHV2Solution memory longerData = _sampleSolution();
    longerData.solverData = new bytes[](3);
    longerData.solverData[0] = hex'5d';
    changed = SchemaHash.ahv2Solution(longerData);
    assertTrue(changed != expected, 'the count of solverData changes the solution hash');
    assertEq(this.extHashSolution(longerData), changed, 'longer solverData');
  }

  /**
   * The approval hash matches the independent encoding, and the order, targets, callValues,
   * solverData and nonce move it
   * @dev The whole order is a member, encoded by its own struct hash, so the production hasher
   * takes that hash and the expected side nests the order. One approval ties to one order and to
   * the targets, `callValues` and `solverData` it specifies.
   */
  function test_T712_solutionApprovalStructHash() public view {
    AHV2Order memory order = _sampleOrder();
    AHV2Solution memory solution = _sampleSolution();
    bytes32 orderHash = SchemaHash.ahv2Order(order);
    bytes32 expected = _approvalHash(order, solution);

    assertEq(this.extHashSolutionApproval(orderHash, solution), expected, 'hasher');

    AHV2Order memory otherOrder = _sampleOrder();
    otherOrder.owner = address(0xB0B);
    assertTrue(_approvalHash(otherOrder, solution) != expected, 'the order changes the approval');

    AHV2Solution memory otherTargets = _sampleSolution();
    otherTargets.erc20Targets[0] = address(0xBBB9);
    assertTrue(_approvalHash(order, otherTargets) != expected, 'the targets change the approval');

    AHV2Solution memory otherValue = _sampleSolution();
    otherValue.callValues[0] += 1;
    bytes32 changed = _approvalHash(order, otherValue);
    assertTrue(changed != expected, 'callValues changes the approval');
    assertEq(this.extHashSolutionApproval(orderHash, otherValue), changed, 'new value');

    AHV2Solution memory otherData = _sampleSolution();
    otherData.solverData[0] = hex'5e';
    changed = _approvalHash(order, otherData);
    assertTrue(changed != expected, 'solverData changes the approval');
    assertEq(this.extHashSolutionApproval(orderHash, otherData), changed, 'new data');

    AHV2Solution memory otherNonce = _sampleSolution();
    otherNonce.nonce += 1;
    changed = _approvalHash(order, otherNonce);
    assertTrue(changed != expected, 'the nonce changes the approval');
    assertEq(this.extHashSolutionApproval(orderHash, otherNonce), changed, 'new nonce');
  }

  /**
   * The hash of each sample {ERC20Allowance} matches {SchemaHash}
   * @dev An allowance carries no target, so its two members are all the struct encodes
   */
  function test_T712_erc20AllowanceStructHash() public view {
    ERC20Allowance[] memory allowances = _sampleAllowances();
    for (uint256 i = 0; i < allowances.length; i++) {
      bytes32 expected = SchemaHash.erc20Allowance(allowances[i]);
      assertEq(this.extHashAllowance(allowances[i]), expected, 'hasher');
    }
  }

  /// The hash of a sample {ERC721Approval} matches {SchemaHash}
  function test_T712_erc721ApprovalStructHash() public view {
    ERC721Approval memory approval = _sampleApprovals()[0];
    bytes32 expected = SchemaHash.erc721Approval(approval);

    assertEq(this.extHashApproval(approval), expected, 'hasher');
  }

  // -------------------------------------------------------------------------------------------
  // T712-ARRAY — the packed address encoding equals the per-element encoding
  // -------------------------------------------------------------------------------------------

  /// T712-ARRAY — the packed encoding of an address array equals the per-element encoding
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

  /**
   * T712-ARRAY — the address array hash equals the hash of the words encoded one by one
   * @dev {CalldataHashLib} against the words of the array, written one by one
   */
  function testFuzz_T712_ARRAY_efficientHashLibExt(address[] memory arr) public view {
    bytes memory words;
    for (uint256 i = 0; i < arr.length; i++) {
      words = bytes.concat(words, abi.encode(arr[i]));
    }
    bytes32 expected = keccak256(words);

    assertEq(this.extHashAddresses(arr), expected, 'hasher');
  }

  /**
   * T712-ARRAY — the `bytes[]` hash equals the hash of the element hashes concatenated
   * @dev {CalldataHashLib} against the concatenation of the hash of each element,
   * written one by one
   */
  function testFuzz_T712_ARRAY_bytesArrayHash(bytes[] memory arr) public view {
    bytes memory hashes;
    for (uint256 i = 0; i < arr.length; i++) {
      hashes = bytes.concat(hashes, keccak256(arr[i]));
    }
    bytes32 expected = keccak256(hashes);

    assertEq(this.extHashBytesArray(arr), expected, 'hasher');
  }

  // -------------------------------------------------------------------------------------------
  // T712-FUZZ — the production hashers against the independent struct hashes
  // -------------------------------------------------------------------------------------------

  /// T712-FUZZ — the {CallParams} hash equals its EIP-712 struct hash
  function testFuzz_T712_FUZZ_callParamsStructHash(CallParams memory c) public view {
    assertEq(this.extHashCall(c), SchemaHash.callParams(c));
  }

  /// T712-FUZZ — the {ERC20Allowance} hash equals its EIP-712 struct hash
  function testFuzz_T712_FUZZ_erc20AllowanceStructHash(ERC20Allowance memory a) public view {
    assertEq(this.extHashAllowance(a), SchemaHash.erc20Allowance(a));
  }

  /// T712-FUZZ — the {ERC721Approval} hash equals its EIP-712 struct hash
  function testFuzz_T712_FUZZ_erc721ApprovalStructHash(ERC721Approval memory a) public view {
    assertEq(this.extHashApproval(a), SchemaHash.erc721Approval(a));
  }

  /// T712-FUZZ — the {HookParams} hash equals its EIP-712 struct hash
  function testFuzz_T712_FUZZ_hookParamsStructHash(HookParams memory h) public view {
    assertEq(this.extHashHook(h), SchemaHash.hookParams(h));
  }

  /// T712-FUZZ — the {AHV2Order} hash equals its EIP-712 struct hash
  function testFuzz_T712_FUZZ_orderStructHash(AHV2Order memory o) public view {
    assertEq(this.extHashOrder(o), SchemaHash.ahv2Order(o));
  }

  /// T712-FUZZ — the {AHV2Solution} hash equals its EIP-712 struct hash
  function testFuzz_T712_FUZZ_solutionStructHash(AHV2Solution memory s) public view {
    assertEq(this.extHashSolution(s), SchemaHash.ahv2Solution(s));
  }

  // external wrappers so the calldata overloads are reachable from a memory-built fixture
  function extHashCall(CallParams calldata c) external pure returns (bytes32) {
    return c.hash();
  }

  function extHashHook(HookParams calldata h) external pure returns (bytes32) {
    return h.hash();
  }

  function extHashAllowance(ERC20Allowance calldata a) external pure returns (bytes32) {
    return a.hash();
  }

  function extHashApproval(ERC721Approval calldata a) external pure returns (bytes32) {
    return a.hash();
  }

  function extHashAddresses(address[] calldata a) external pure returns (bytes32) {
    return CalldataHashLib.hash(a);
  }

  function extHashBytesArray(bytes[] calldata a) external pure returns (bytes32) {
    return CalldataHashLib.hash(a);
  }

  function extHashOrder(AHV2Order calldata o) external pure returns (bytes32) {
    return o.hash();
  }

  function extHashSolution(AHV2Solution calldata s) external pure returns (bytes32) {
    return s.hash();
  }

  function extHashSolutionApproval(bytes32 orderHash, AHV2Solution calldata solution)
    external
    pure
    returns (bytes32)
  {
    return SolutionApprovalLib.hash(orderHash, solution);
  }

  // -------------------------------------------------------------------------------------------
  // Fixtures and string helpers
  // -------------------------------------------------------------------------------------------

  function _approvalHash(AHV2Order memory order, AHV2Solution memory solution)
    private
    pure
    returns (bytes32)
  {
    return SchemaHash.solutionApproval(SolutionApproval({order: order, solution: solution}));
  }

  function _sampleCalls() private pure returns (CallParams[] memory calls) {
    calls = new CallParams[](2);
    calls[0] = CallParams({callee: address(0xCCC1), ownerData: hex'deadbeef'});
    calls[1] = CallParams({callee: address(0xCCC2), ownerData: ''});
  }

  function _sampleHooks() private pure returns (HookParams[] memory hooks) {
    hooks = new HookParams[](2);
    hooks[0] = HookParams({hook: address(0xDDD1), flags: bytes32(uint256(3)), data: hex'01'});
    hooks[1] = HookParams({hook: address(0xDDD2), flags: bytes32(0), data: ''});
  }

  function _sampleAllowances() private pure returns (ERC20Allowance[] memory allowances) {
    allowances = new ERC20Allowance[](2);
    allowances[0] = ERC20Allowance({token: address(0xAAA1), amount: 1000});
    allowances[1] = ERC20Allowance({token: address(0xAAA2), amount: 0});
  }

  function _sampleApprovals() private pure returns (ERC721Approval[] memory approvals) {
    approvals = new ERC721Approval[](1);
    approvals[0] = ERC721Approval({token: address(0xBADD), tokenId: 42});
  }

  function _sampleOrder() private pure returns (AHV2Order memory) {
    return AHV2Order({
      owner: address(0xA11CE),
      authenticator: address(0xAD7),
      exclusiveCaller: ANY,
      erc20Allowances: _sampleAllowances(),
      erc721Approvals: _sampleApprovals(),
      hooks: _sampleHooks(),
      calls: _sampleCalls(),
      solutionApprover: address(0xBEEF),
      nonce: 12,
      expiration: 5678,
      clientData: CLIENT_DATA
    });
  }

  /// @dev One target and amount per ERC20 transfer, one target per NFT transfer and one
  /// `callValues` and `solverData` entry per call of {_sampleOrder}, none of the targets a callee
  function _sampleSolution() private pure returns (AHV2Solution memory) {
    address[] memory erc20Targets = new address[](2);
    erc20Targets[0] = address(0xBBB1);
    erc20Targets[1] = address(0xBBB2);
    uint160[] memory erc20Amounts = new uint160[](2);
    erc20Amounts[0] = 1000;
    erc20Amounts[1] = 2000;
    address[] memory erc721Targets = new address[](1);
    erc721Targets[0] = address(0xBBB3);
    uint256[] memory callValues = new uint256[](2);
    callValues[0] = 1 ether;
    callValues[1] = 0;
    bytes[] memory solverData = new bytes[](2);
    solverData[0] = hex'5d';
    solverData[1] = '';
    return AHV2Solution({
      erc20Targets: erc20Targets,
      erc20Amounts: erc20Amounts,
      erc721Targets: erc721Targets,
      callValues: callValues,
      solverData: solverData,
      nonce: 3456,
      expiration: 9012
    });
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
      if (i > 0) {
        assertTrue(at > previous, 'referenced types appear in sorted order');
      }
      previous = at;
    }
  }

  function _sortsBefore(string memory a, string memory b) private pure returns (bool) {
    bytes memory x = bytes(a);
    bytes memory y = bytes(b);
    uint256 n = x.length < y.length ? x.length : y.length;
    for (uint256 i = 0; i < n; i++) {
      if (x[i] != y[i]) {
        return uint8(x[i]) < uint8(y[i]);
      }
    }
    return x.length < y.length;
  }

  function _indexOf(string memory haystack, string memory needle) private pure returns (uint256) {
    bytes memory h = bytes(haystack);
    bytes memory n = bytes(needle);
    if (n.length == 0 || n.length > h.length) {
      return type(uint256).max;
    }

    for (uint256 i = 0; i + n.length <= h.length; i++) {
      bool hit = true;
      for (uint256 j = 0; j < n.length; j++) {
        if (h[i + j] != n[j]) {
          hit = false;
          break;
        }
      }
      if (hit) {
        return i;
      }
    }
    return type(uint256).max;
  }
}
