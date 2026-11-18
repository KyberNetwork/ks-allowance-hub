// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Vm} from 'forge-std/Vm.sol';

import {HubBase} from '../base/HubBase.sol';

import {ProxyCalleeMock} from '../mocks/ProxyCalleeMocks.sol';

import {AHV2ProxyCallee} from '../../src/callees/AHV2ProxyCallee.sol';

import {AHV2Order} from '../../src/types/AHV2Order.sol';
import {AHV2Solution} from '../../src/types/AHV2Solution.sol';
import {CallParams} from '../../src/types/CallParams.sol';
import {ERC20Allowance} from '../../src/types/ERC20Allowance.sol';
import {HookParams} from '../../src/types/HookParams.sol';

import {IAccessControl} from 'openzeppelin-contracts/contracts/access/IAccessControl.sol';
import {Pausable} from 'openzeppelin-contracts/contracts/utils/Pausable.sol';

/**
 * @title AHV2ProxyCalleeTest
 * @notice PX-01..16 and PX-FUZZ — constructor wiring, the proxy's own whitelist and pause, the two
 * entry points, the fallback that reaches the active callee, and settlement through the hub.
 * @dev Selectors, role hashes and event topics on the expected side are written out. A callee is a
 * {ProxyCalleeMock}, which the proxy executes by delegatecall and which echoes any calldata it
 * does not implement together with its tag, so the callee that ran is visible in the result.
 */
contract AHV2ProxyCalleeTest is HubBase {
  struct SolverFuzz {
    bytes[] callData;
    uint256 calleeMask;
    uint96 value;
  }

  struct OwnerFuzz {
    bytes[] ownerData;
    bytes[] solverData;
    bool encodeSolverData;
    uint96 value;
  }

  struct ConstructorFuzz {
    address admin;
    address[] guardians;
    address[] callees;
  }

  struct LengthFuzz {
    uint8 callees;
    uint8 data;
  }

  /// @dev One `Delegated` event emitted by the proxy
  struct Seen {
    bytes32 tag;
    address sender;
    uint256 value;
    bytes data;
  }

  // Role hashes, written out rather than imported
  bytes32 internal constant CALLEE_ROLE = keccak256('WHITELISTED_CALLEE_ROLE');
  bytes32 internal constant GUARDIAN_ROLE = keccak256('GUARDIAN_ROLE');
  bytes32 internal constant ADMIN_ROLE = bytes32(0);

  // Error selectors, written out rather than imported
  bytes4 internal constant NO_ACTIVE_CALLEE = 0xb4fbdf72;
  bytes4 internal constant FAILED_CALL = 0xd6bda275;
  bytes4 internal constant SLICE_OUT_OF_BOUNDS = 0x3b99b53d;
  bytes4 internal constant MISMATCHED_ARRAY_LENGTHS = 0x568efce2;
  bytes4 internal constant ENFORCED_PAUSE = 0xd93c0665;
  bytes4 internal constant ADDRESS_EMPTY_CODE = 0x9996b315;
  bytes4 internal constant OWNABLE_INVALID_OWNER = 0x1e4fbdf7;
  bytes4 internal constant ACCESS_CONTROL_UNAUTHORIZED = 0xe2517d3f;
  bytes4 internal constant UNAUTHORIZED_ACCOUNT = 0xd0acb6ac;
  bytes4 internal constant ERROR_STRING = 0x08c379a0;
  bytes4 internal constant PANIC = 0x4e487b71;

  // Event topics, written out
  bytes32 internal constant DELEGATED_TOPIC = keccak256('Delegated(bytes32,address,uint256,bytes)');
  bytes32 internal constant OWNERSHIP_TRANSFERRED_TOPIC =
    keccak256('OwnershipTransferred(address,address)');
  bytes32 internal constant ROLE_GRANTED_TOPIC = keccak256('RoleGranted(bytes32,address,address)');
  bytes32 internal constant ROLE_REVOKER_CHANGED_TOPIC =
    keccak256('RoleRevokerChanged(bytes32,bytes32,bytes32)');

  bytes32 internal constant TAG_A = bytes32('A');
  bytes32 internal constant TAG_B = bytes32('B');
  bytes32 internal constant TAG_C = bytes32('C');

  AHV2ProxyCallee internal proxy;
  ProxyCalleeMock internal calleeA;
  ProxyCalleeMock internal calleeB;
  ProxyCalleeMock internal calleeC;

  /// @dev Whitelisted on the proxy and without code
  address internal eoaCallee = makeAddr('eoaCallee');
  address internal stranger = makeAddr('stranger');

  function setUp() public override {
    super.setUp();

    calleeA = new ProxyCalleeMock(TAG_A);
    calleeB = new ProxyCalleeMock(TAG_B);
    calleeC = new ProxyCalleeMock(TAG_C);

    proxy =
      new AHV2ProxyCallee(admin, _addresses(guardian), _pair(address(calleeA), address(calleeB)));
    vm.prank(admin);
    proxy.grantRole(CALLEE_ROLE, eoaCallee);

    vm.deal(address(this), type(uint128).max);
    vm.label(address(proxy), 'proxy');
    vm.label(address(calleeA), 'calleeA');
    vm.label(address(calleeB), 'calleeB');
    vm.label(address(calleeC), 'calleeC');
  }

  // ---------------------------------------------------------------------------------------------
  // Constructor, whitelist and pause
  // ---------------------------------------------------------------------------------------------

  /**
   * PX-01 — the constructor grants the roles and the revoker, in order, and refuses a zero admin
   * @dev The log stream is pinned in full: ownership, the guardian, each callee, then the revoker.
   */
  function test_PX_01_constructorWiring() public {
    vm.recordLogs();
    AHV2ProxyCallee fresh =
      new AHV2ProxyCallee(admin, _addresses(guardian), _pair(address(calleeA), address(calleeB)));
    Vm.Log[] memory logs = vm.getRecordedLogs();

    assertEq(fresh.owner(), admin, 'the admin owns the proxy');
    assertTrue(fresh.hasRole(ADMIN_ROLE, admin), 'and holds the default admin role');
    assertTrue(fresh.hasRole(GUARDIAN_ROLE, guardian), 'the guardian holds its role');
    assertTrue(fresh.hasRole(CALLEE_ROLE, address(calleeA)), 'callee A is whitelisted');
    assertTrue(fresh.hasRole(CALLEE_ROLE, address(calleeB)), 'callee B is whitelisted');
    assertFalse(fresh.hasRole(CALLEE_ROLE, address(calleeC)), 'callee C is not');
    assertEq(fresh.roleRevokers(CALLEE_ROLE), GUARDIAN_ROLE, 'guardians revoke callees');
    assertEq(fresh.roleRevokers(GUARDIAN_ROLE), bytes32(0), 'no other role has a revoker');
    assertFalse(fresh.paused(), 'the proxy starts unpaused');

    assertEq(logs.length, 5, 'ownership, three grants and the revoker');
    _assertLog(logs[0], OWNERSHIP_TRANSFERRED_TOPIC, bytes32(0), bytes32(uint256(uint160(admin))));
    _assertLog(logs[1], ROLE_GRANTED_TOPIC, GUARDIAN_ROLE, _word(guardian), _word(address(this)));
    _assertLog(
      logs[2], ROLE_GRANTED_TOPIC, CALLEE_ROLE, _word(address(calleeA)), _word(address(this))
    );
    _assertLog(
      logs[3], ROLE_GRANTED_TOPIC, CALLEE_ROLE, _word(address(calleeB)), _word(address(this))
    );
    assertEq(logs[4].topics.length, 4, 'the revoker event indexes three fields');
    assertEq(logs[4].topics[0], ROLE_REVOKER_CHANGED_TOPIC, 'RoleRevokerChanged');
    assertEq(logs[4].topics[1], CALLEE_ROLE, 'for the callee role');
    assertEq(logs[4].topics[2], bytes32(0), 'from no previous revoker');
    assertEq(logs[4].topics[3], GUARDIAN_ROLE, 'to the guardian role');
    for (uint256 i = 0; i < logs.length; i++) {
      assertEq(logs[i].emitter, _created(logs), 'every event is the new proxy');
    }

    vm.expectRevert(abi.encodeWithSelector(OWNABLE_INVALID_OWNER, address(0)));
    new AHV2ProxyCallee(address(0), _addresses(guardian), _addresses(address(calleeA)));
  }

  /// PX-FUZZ-C — any admin, guardians and callees are granted exactly what they are given
  function testFuzz_PX_FUZZ_constructor(ConstructorFuzz memory f) public {
    vm.assume(f.admin != address(0));
    address[] memory guardians = _truncated(f.guardians, 3);
    address[] memory callees = _truncated(f.callees, 3);

    AHV2ProxyCallee fresh = new AHV2ProxyCallee(f.admin, guardians, callees);

    assertEq(fresh.owner(), f.admin, 'the admin owns the proxy');
    for (uint256 i = 0; i < guardians.length; i++) {
      assertTrue(fresh.hasRole(GUARDIAN_ROLE, guardians[i]), 'a guardian holds its role');
    }
    for (uint256 i = 0; i < callees.length; i++) {
      assertTrue(fresh.hasRole(CALLEE_ROLE, callees[i]), 'a callee is whitelisted');
    }
    assertEq(fresh.roleRevokers(CALLEE_ROLE), GUARDIAN_ROLE, 'guardians revoke callees');
  }

  /**
   * PX-05 — only a whitelisted callee runs, at any index; guardians revoke and the admin grants
   * @dev The list `[A, C]` shows the check is made per callee and not for the first one only.
   */
  function test_PX_05_onlyWhitelistedCalleesRun() public {
    bytes memory call = hex'aabbccdd01';
    bytes memory unlisted =
      abi.encodeWithSelector(ACCESS_CONTROL_UNAUTHORIZED, address(calleeC), CALLEE_ROLE);

    vm.expectRevert(unlisted);
    proxy.solverCall(_payload(_addresses(address(calleeC)), _bytesList(call)));
    vm.expectRevert(unlisted);
    proxy.solverCall(_payload(_pair(address(calleeA), address(calleeC)), _bytesList(call, call)));
    vm.expectRevert(unlisted);
    proxy.ownerCall(_payload(_pair(address(calleeA), address(calleeC)), _bytesList(call, call)), '');

    vm.expectEmit(true, true, true, false, address(proxy));
    emit IAccessControl.RoleRevoked(CALLEE_ROLE, address(calleeA), guardian);
    vm.prank(guardian);
    proxy.revokeRole(CALLEE_ROLE, address(calleeA));
    assertFalse(proxy.hasRole(CALLEE_ROLE, address(calleeA)), 'the guardian revoked callee A');

    bytes memory revoked =
      abi.encodeWithSelector(ACCESS_CONTROL_UNAUTHORIZED, address(calleeA), CALLEE_ROLE);
    vm.expectRevert(revoked);
    proxy.solverCall(_payload(_addresses(address(calleeA)), _bytesList(call)));
    vm.expectRevert(revoked);
    proxy.ownerCall(_payload(_addresses(address(calleeA)), _bytesList(call)), '');

    bytes32[] memory needed = new bytes32[](2);
    needed[0] = GUARDIAN_ROLE;
    needed[1] = ADMIN_ROLE;
    vm.expectRevert(abi.encodeWithSelector(UNAUTHORIZED_ACCOUNT, stranger, needed));
    vm.prank(stranger);
    proxy.revokeRole(CALLEE_ROLE, address(calleeB));
    assertTrue(proxy.hasRole(CALLEE_ROLE, address(calleeB)), 'a stranger revoked nothing');

    vm.expectEmit(true, true, true, false, address(proxy));
    emit IAccessControl.RoleGranted(CALLEE_ROLE, address(calleeA), admin);
    vm.prank(admin);
    proxy.grantRole(CALLEE_ROLE, address(calleeA));

    bytes memory results =
      proxy.solverCall(_payload(_addresses(address(calleeA)), _bytesList(call)));
    assertEq(results, _results(_bytesList(_echo(TAG_A, call))), 'callee A runs again');
  }

  /// PX-FUZZ-W — any callee outside the whitelist is refused on both entry points
  function testFuzz_PX_FUZZ_unwhitelistedCalleeRefused(address callee) public {
    vm.assume(callee != address(calleeA) && callee != address(calleeB) && callee != eoaCallee);

    bytes memory expected = abi.encodeWithSelector(ACCESS_CONTROL_UNAUTHORIZED, callee, CALLEE_ROLE);
    bytes memory payload = _payload(_addresses(callee), _bytesList(hex'aabbccdd'));

    vm.expectRevert(expected);
    proxy.solverCall(payload);
    vm.expectRevert(expected);
    proxy.ownerCall(payload, '');
  }

  /// PX-06 — a guardian pauses both entry points; the fallback and value receipt are not gated
  function test_PX_06_pauseStopsBothEntryPoints() public {
    bytes memory payload = _payload(_addresses(address(calleeA)), _bytesList(hex'aabbccdd01'));

    bytes32[] memory needed = new bytes32[](2);
    needed[0] = GUARDIAN_ROLE;
    needed[1] = ADMIN_ROLE;
    vm.expectRevert(abi.encodeWithSelector(UNAUTHORIZED_ACCOUNT, stranger, needed));
    vm.prank(stranger);
    proxy.pause();
    assertFalse(proxy.paused(), 'a stranger paused nothing');

    vm.expectEmit(false, false, false, true, address(proxy));
    emit Pausable.Paused(guardian);
    vm.prank(guardian);
    proxy.pause();
    assertTrue(proxy.paused(), 'the guardian paused the proxy');

    vm.expectRevert(abi.encodeWithSelector(ENFORCED_PAUSE));
    proxy.solverCall(payload);
    vm.expectRevert(abi.encodeWithSelector(ENFORCED_PAUSE));
    proxy.ownerCall(payload, '');

    (bool ok, bytes memory ret) = address(proxy).call(hex'12345678');
    assertFalse(ok, 'the fallback still refuses with no active callee');
    assertEq(ret, abi.encodePacked(NO_ACTIVE_CALLEE), 'and does so for that reason');

    uint256 before = address(proxy).balance;
    (ok,) = address(proxy).call{value: 1}('');
    assertTrue(ok, 'native value is accepted while paused');
    assertEq(address(proxy).balance, before + 1, 'and kept');

    vm.expectEmit(false, false, false, true, address(proxy));
    emit Pausable.Unpaused(admin);
    vm.prank(admin);
    proxy.unpause();
    assertFalse(proxy.paused(), 'the admin unpaused the proxy');

    assertEq(
      proxy.solverCall(payload),
      _results(_bytesList(_echo(TAG_A, hex'aabbccdd01'))),
      'the entry points run again'
    );
  }

  // ---------------------------------------------------------------------------------------------
  // solverCall and ownerCall
  // ---------------------------------------------------------------------------------------------

  /**
   * PX-02 — each callee runs in order, sees the whole value, and the value is not spent twice
   * @dev Both callees see 3 wei and the proxy gains 3 wei, not 6.
   */
  function test_PX_02_solverCallDelegatesEachCalleeInOrder() public {
    bytes memory d0 = hex'aabbccdd01';
    bytes memory d1 = hex'11223344';
    uint256 before = address(proxy).balance;

    vm.recordLogs();
    bytes memory results = proxy.solverCall{value: 3}(
      _payload(_pair(address(calleeA), address(calleeB)), _bytesList(d0, d1))
    );
    Seen[] memory seen = _seen();

    assertEq(seen.length, 2, 'two callees ran');
    _assertSeen(seen[0], TAG_A, address(this), 3, d0);
    _assertSeen(seen[1], TAG_B, address(this), 3, d1);
    assertEq(
      results,
      abi.encode(_bytesList(abi.encode(TAG_A, d0), abi.encode(TAG_B, d1))),
      'the result holds each return in order'
    );
    assertEq(address(proxy).balance, before + 3, 'the value was received once');
  }

  /// PX-FUZZ-S — one to four callees, each delegatecalled with its calldata and the value
  function testFuzz_PX_FUZZ_solverCall(SolverFuzz memory f) public {
    uint256 count = f.callData.length < 4 ? f.callData.length : 4;
    address[] memory callees = new address[](count);
    bytes[] memory callData = _prefixed(f.callData, count, hex'ff');
    bytes[] memory expected = new bytes[](count);
    for (uint256 i = 0; i < count; i++) {
      callees[i] = _fuzzCallee(f.calleeMask, i);
      expected[i] = abi.encode(_tagOf(callees[i]), callData[i]);
    }
    uint256 before = address(proxy).balance;

    vm.recordLogs();
    bytes memory results = proxy.solverCall{value: f.value}(_payload(callees, callData));
    Seen[] memory seen = _seen();

    assertEq(results, abi.encode(expected), 'the result holds each return in order');
    assertEq(seen.length, count, 'every callee ran');
    for (uint256 i = 0; i < count; i++) {
      _assertSeen(seen[i], _tagOf(callees[i]), address(this), f.value, callData[i]);
    }
    assertEq(address(proxy).balance, before + f.value, 'the value was received once');
  }

  /// PX-03 — no callees runs nothing and keeps the value, on both entry points
  function test_PX_03_emptyCalleeListKeepsTheValue() public {
    bytes memory empty = abi.encode(new bytes[](0));
    bytes memory payload = _payload(new address[](0), new bytes[](0));
    uint256 before = address(proxy).balance;

    vm.recordLogs();
    assertEq(proxy.solverCall{value: 5}(payload), empty, 'solverCall returns no results');
    assertEq(proxy.ownerCall(payload, ''), empty, 'ownerCall without solver data');
    assertEq(
      proxy.ownerCall(payload, abi.encode(new bytes[](0))),
      empty,
      'ownerCall with empty solver data'
    );
    assertEq(_seen().length, 0, 'nothing ran');
    assertEq(address(proxy).balance, before + 5, 'the value stays in the proxy');
  }

  /// PX-04 — the three lists of `ownerCall` must agree in length
  function test_PX_04_lengthsMustMatch() public {
    bytes memory o0 = hex'aabbccdd01';
    bytes memory o1 = hex'11223344';
    address[] memory two = _pair(address(calleeA), address(calleeB));

    vm.expectRevert(abi.encodeWithSelector(MISMATCHED_ARRAY_LENGTHS));
    proxy.ownerCall(_payload(_addresses(address(calleeA)), _bytesList(o0, o1)), '');

    vm.expectRevert(abi.encodeWithSelector(MISMATCHED_ARRAY_LENGTHS));
    proxy.ownerCall(_payload(two, _bytesList(o0, o1)), abi.encode(_bytesList(hex'5d')));

    vm.expectRevert(abi.encodeWithSelector(MISMATCHED_ARRAY_LENGTHS));
    proxy.ownerCall(
      _payload(two, _bytesList(o0, o1)), abi.encode(_bytesList(hex'5d', hex'5e', hex'5f'))
    );
  }

  /// PX-FUZZ-L — `solverCall` refuses lists of different lengths
  function testFuzz_PX_FUZZ_solverCallLengthsMustMatch(LengthFuzz memory f) public {
    uint256 callees = bound(f.callees, 0, 4);
    uint256 data = bound(f.data, 0, 4);
    vm.assume(callees != data);

    address[] memory targets = new address[](callees);
    for (uint256 i = 0; i < callees; i++) {
      targets[i] = address(calleeA);
    }

    vm.expectRevert(abi.encodeWithSelector(MISMATCHED_ARRAY_LENGTHS));
    proxy.solverCall(_payload(targets, new bytes[](data)));
  }

  /**
   * PX-08 — a failing callee reverts the call with the revert data of the callee
   * @dev A custom error, a string and a panic pass through unchanged. An empty revert, and a
   * call with value to a callee that is not payable, revert with `FailedCall`. Without value the
   * non-payable callee succeeds.
   */
  function test_PX_08_calleeRevertsBubble() public {
    address[] memory a = _addresses(address(calleeA));

    vm.expectRevert(
      abi.encodeWithSelector(ProxyCalleeMock.CalleeFailed.selector, TAG_A, uint256(7))
    );
    proxy.solverCall(_payload(a, _bytesList(abi.encodeCall(ProxyCalleeMock.revertCustom, (7)))));

    vm.expectRevert(abi.encodeWithSelector(ERROR_STRING, 'callee failed'));
    proxy.solverCall(_payload(a, _bytesList(abi.encodeCall(ProxyCalleeMock.revertString, ()))));

    vm.expectRevert(abi.encodeWithSelector(FAILED_CALL));
    proxy.solverCall(_payload(a, _bytesList(abi.encodeCall(ProxyCalleeMock.revertEmpty, ()))));

    vm.expectRevert(abi.encodeWithSelector(PANIC, uint256(0x12)));
    proxy.solverCall(_payload(a, _bytesList(abi.encodeCall(ProxyCalleeMock.divideByZero, ()))));

    bytes memory nonPayable = abi.encodeCall(ProxyCalleeMock.nonPayable, ());
    vm.expectRevert(abi.encodeWithSelector(FAILED_CALL));
    proxy.solverCall{value: 1}(_payload(a, _bytesList(nonPayable)));

    assertEq(
      proxy.solverCall(_payload(a, _bytesList(nonPayable))),
      _results(_bytesList('')),
      'without value the non-payable callee succeeds'
    );
  }

  /// PX-09 — a whitelisted callee without code is refused rather than treated as a success
  function test_PX_09_aCalleeWithoutCodeIsRefused() public {
    vm.expectRevert(abi.encodeWithSelector(ADDRESS_EMPTY_CODE, eoaCallee));
    proxy.solverCall(_payload(_addresses(eoaCallee), _bytesList(hex'12345678')));
  }

  /**
   * PX-10 — `ownerCall` wraps a callee's data only when the solver supplied data for it
   * @dev Five patterns of solver data: absent, all empty, empty then set, set then empty, all set.
   */
  function test_PX_10_ownerCallWrapsOnlyWithSolverData() public {
    bytes memory o0 = hex'aabbccdd01';
    bytes memory o1 = hex'11223344ee';
    bytes memory s0 = hex'5d';
    bytes memory s1 = hex'5e5f';
    bytes memory w0 = abi.encodeWithSignature('ownerCall(bytes,bytes)', o0, s0);
    bytes memory w1 = abi.encodeWithSignature('ownerCall(bytes,bytes)', o1, s1);

    _assertOwnerRun(o0, o1, '', o0, o1);
    _assertOwnerRun(o0, o1, abi.encode(_bytesList('', '')), o0, o1);
    _assertOwnerRun(o0, o1, abi.encode(_bytesList('', s1)), o0, w1);
    _assertOwnerRun(o0, o1, abi.encode(_bytesList(s0, '')), w0, o1);
    _assertOwnerRun(o0, o1, abi.encode(_bytesList(s0, s1)), w0, w1);
  }

  /// PX-FUZZ-O — each callee gets the raw owner data, or the wrapped call when solver data is set
  function testFuzz_PX_FUZZ_ownerCall(OwnerFuzz memory f) public {
    uint256 count = f.ownerData.length < 4 ? f.ownerData.length : 4;
    address[] memory callees = new address[](count);
    bytes[] memory ownerData = _prefixed(f.ownerData, count, hex'ff');
    bytes[] memory solverData = new bytes[](count);
    bytes[] memory received = new bytes[](count);
    bytes[] memory expected = new bytes[](count);
    for (uint256 i = 0; i < count; i++) {
      callees[i] = i % 2 == 0 ? address(calleeA) : address(calleeB);
      solverData[i] = i < f.solverData.length ? f.solverData[i] : bytes('');
      received[i] = !f.encodeSolverData || solverData[i].length == 0
        ? ownerData[i]
        : abi.encodeWithSignature('ownerCall(bytes,bytes)', ownerData[i], solverData[i]);
      expected[i] = abi.encode(_tagOf(callees[i]), received[i]);
    }
    uint256 before = address(proxy).balance;

    vm.recordLogs();
    bytes memory results = proxy.ownerCall{value: f.value}(
      _payload(callees, ownerData), f.encodeSolverData ? abi.encode(solverData) : bytes('')
    );
    Seen[] memory seen = _seen();

    assertEq(results, abi.encode(expected), 'the result holds each return in order');
    assertEq(seen.length, count, 'every callee ran');
    for (uint256 i = 0; i < count; i++) {
      _assertSeen(seen[i], _tagOf(callees[i]), address(this), f.value, received[i]);
    }
    assertEq(address(proxy).balance, before + f.value, 'the value was received once');
  }

  /**
   * PX-11 — payloads that do not decode are refused with `SliceOutOfBounds`
   * @dev (a) no data, (b) a `bytes[]` offset beyond the end, (c) the same offset in the owner data, (d) a solver data offset beyond the end.
   */
  function test_PX_11_malformedPayloadsAreRefused() public {
    bytes memory emptyPair = _payload(new address[](0), new bytes[](0));

    vm.expectRevert(abi.encodeWithSelector(SLICE_OUT_OF_BOUNDS));
    proxy.solverCall('');

    vm.expectRevert(abi.encodeWithSelector(SLICE_OUT_OF_BOUNDS));
    proxy.solverCall(abi.encodePacked(uint256(0x40), uint256(0x1000), uint256(0)));

    vm.expectRevert(abi.encodeWithSelector(SLICE_OUT_OF_BOUNDS));
    proxy.ownerCall(abi.encodePacked(uint256(0x40), uint256(0x1000), uint256(0)), '');

    vm.expectRevert(abi.encodeWithSelector(SLICE_OUT_OF_BOUNDS));
    proxy.ownerCall(emptyPair, abi.encodePacked(uint256(0xff)));
  }

  // ---------------------------------------------------------------------------------------------
  // Fallback and receive
  // ---------------------------------------------------------------------------------------------

  /// PX-12 — a call to the proxy with no callee running is refused with `NoActiveCallee`
  function test_PX_12_fallbackWithoutActiveCalleeReverts() public {
    uint256 before = address(proxy).balance;

    (bool ok, bytes memory ret) = address(proxy).call(hex'12345678');
    assertFalse(ok, 'an unknown selector is refused');
    assertEq(ret, abi.encodePacked(NO_ACTIVE_CALLEE), 'with NoActiveCallee');

    (ok, ret) = address(proxy).call(hex'01');
    assertFalse(ok, 'one byte of calldata is refused');
    assertEq(ret, abi.encodePacked(NO_ACTIVE_CALLEE), 'with NoActiveCallee');

    (ok, ret) = address(proxy).call{value: 1}(hex'12345678');
    assertFalse(ok, 'an unknown selector with value is refused');
    assertEq(ret, abi.encodePacked(NO_ACTIVE_CALLEE), 'with NoActiveCallee');

    assertEq(address(proxy).balance, before, 'no value was kept');
  }

  /**
   * PX-13 — a call the running callee makes to the proxy is delegatecalled to that callee
   * @dev The callback of a callee reverting with data, reverting empty, returning nothing and
   * calling a selector the proxy implements itself.
   */
  function test_PX_13_fallbackReachesTheActiveCallee() public {
    address[] memory a = _addresses(address(calleeA));

    vm.expectRevert(
      abi.encodeWithSelector(ProxyCalleeMock.CalleeFailed.selector, TAG_A, uint256(9))
    );
    proxy.solverCall(
      _payload(a, _bytesList(_callBack(abi.encodeCall(ProxyCalleeMock.revertCustom, (9)))))
    );

    vm.expectRevert(abi.encodeWithSelector(FAILED_CALL));
    proxy.solverCall(
      _payload(a, _bytesList(_callBack(abi.encodeCall(ProxyCalleeMock.revertEmpty, ()))))
    );

    vm.recordLogs();
    assertEq(
      proxy.solverCall(
        _payload(a, _bytesList(_callBack(abi.encodeCall(ProxyCalleeMock.noReturn, ()))))
      ),
      _results(_bytesList('')),
      'a callback returning nothing returns an empty result'
    );
    assertEq(_seen().length, 0, 'the callback emitted no event');

    vm.recordLogs();
    assertEq(
      proxy.solverCall(_payload(a, _bytesList(_callBack(abi.encodeWithSignature('owner()'))))),
      _results(_bytesList(abi.encode(admin))),
      'the proxy answers a selector it implements'
    );
    assertEq(_seen().length, 0, 'and does not forward it');
  }

  /// PX-FUZZ-F — any calldata the callee sends to the proxy reaches the callee unchanged
  function testFuzz_PX_FUZZ_fallbackForwardsAnyCalldata(bytes memory cd) public {
    bytes memory forwarded = bytes.concat(hex'fe', cd);

    vm.recordLogs();
    bytes memory results =
      proxy.solverCall(_payload(_addresses(address(calleeA)), _bytesList(_callBack(forwarded))));
    Seen[] memory seen = _seen();

    assertEq(results, _results(_bytesList(abi.encode(TAG_A, forwarded))), 'the echo is returned');
    assertEq(seen.length, 1, 'the callee ran once through the fallback');
    _assertSeen(seen[0], TAG_A, address(proxy), 0, forwarded);
  }

  /**
   * PX-14 — a nested call restores the outer callee, after returning and after a caught revert
   * @dev (1) a callback inside a nested call reaches the nested callee, a later one the outer
   * callee; (2) a nested call that reverts after it became active leaves the outer callee active.
   */
  function test_PX_14_nestedCallsRestoreTheOuterCallee() public {
    address[] memory a = _addresses(address(calleeA));
    address[] memory b = _addresses(address(calleeB));

    bytes memory nested =
      abi.encodeCall(proxy.solverCall, (_payload(b, _bytesList(_callBack(hex'beef0001')))));
    vm.recordLogs();
    bytes memory results = proxy.solverCall(
      _payload(a, _bytesList(abi.encodeCall(ProxyCalleeMock.nest, (nested, hex'beef0002'))))
    );
    Seen[] memory seen = _seen();
    assertEq(seen.length, 2, 'two callbacks reached a callee');
    _assertSeen(seen[0], TAG_B, address(proxy), 0, hex'beef0001');
    _assertSeen(seen[1], TAG_A, address(proxy), 0, hex'beef0002');
    assertEq(
      results, _results(_bytesList(abi.encode(TAG_A, hex'beef0002'))), 'the outer callee answers'
    );

    nested = abi.encodeCall(
      proxy.solverCall, (_payload(b, _bytesList(abi.encodeCall(ProxyCalleeMock.revertCustom, (1)))))
    );
    vm.recordLogs();
    results = proxy.solverCall(
      _payload(a, _bytesList(abi.encodeCall(ProxyCalleeMock.tryNest, (nested, hex'beef0003'))))
    );
    seen = _seen();
    assertEq(seen.length, 1, 'one callback reached a callee');
    _assertSeen(seen[0], TAG_A, address(proxy), 0, hex'beef0003');
    assertEq(
      results,
      _results(_bytesList(abi.encode(TAG_A, hex'beef0003'))),
      'the caught revert did not leave callee B active'
    );

    (bool ok, bytes memory ret) = address(proxy).call(hex'beef0004');
    assertFalse(ok, 'no callee is active afterwards');
    assertEq(ret, abi.encodePacked(NO_ACTIVE_CALLEE), 'NoActiveCallee');
  }

  /// PX-15 — empty calldata sent while a callee runs reaches `receive`, not the callee
  function test_PX_15_receiveKeepsValueEvenDuringACallee() public {
    vm.deal(address(proxy), 2);

    vm.recordLogs();
    bytes memory results = proxy.solverCall(
      _payload(
        _addresses(address(calleeA)), _bytesList(abi.encodeCall(ProxyCalleeMock.sendToSelf, (2)))
      )
    );

    assertEq(_seen().length, 0, 'the callee was not called back');
    assertEq(results, _results(_bytesList('')), 'sendToSelf returned nothing');
    assertEq(address(proxy).balance, 2, 'the proxy kept the value');
  }

  /// PX-FUZZ-R — plain native value of any size is accepted and kept without events
  function testFuzz_PX_FUZZ_receiveAcceptsAnyValue(uint96 value) public {
    uint256 before = address(proxy).balance;

    vm.recordLogs();
    (bool ok, bytes memory ret) = address(proxy).call{value: value}('');

    assertTrue(ok, 'the value is accepted');
    assertEq(ret.length, 0, 'with no return data');
    assertEq(address(proxy).balance, before + value, 'and kept');
    assertEq(vm.getRecordedLogs().length, 0, 'without events');
  }

  // ---------------------------------------------------------------------------------------------
  // Settlement through the hub
  // ---------------------------------------------------------------------------------------------

  /**
   * PX-16 — the hub settles an order through the proxy, and a callee reads the order owner
   * @dev The owner submits on the delegated entry point with the zero authenticator. Built with
   * {_openAhv2Order}, {_route}, {_calls}, {_addresses} and {_solverData}. (a) an owner call with
   * empty solver data reaches the callee raw; (b) with solver data it reaches the callee as
   * `ownerCall`, which the mock does not implement and echoes; (c) the same call as a solver call.
   */
  function test_PX_16_hubSettlesThroughTheProxy() public {
    vm.prank(admin);
    hub.grantRole(CALLEE_ROLE, address(proxy));

    bytes memory recordOwner = abi.encodeCall(ProxyCalleeMock.recordOwner, ());
    bytes memory proxyData = _payload(_addresses(address(calleeA)), _bytesList(recordOwner));
    CallParams memory proxyCall = CallParams({callee: address(proxy), value: 0, data: proxyData});

    // (a) an owner call, raw
    AHV2Order memory order = _openAhv2Order(
      new ERC20Allowance[](0), new HookParams[](0), _calls(proxyCall), 0, vm.getBlockTimestamp()
    );
    AHV2Solution memory route = _route(order, new CallParams[](0));
    vm.expectEmit(false, false, false, true, address(proxy));
    emit ProxyCalleeMock.Owner(TAG_A, owner);
    vm.prank(owner);
    bytes[] memory results =
      hub.settleOrderWithDelegatedAuthentication(order, address(0), '', route, '', false);
    assertEq(results.length, 1, 'one owner call ran');
    assertEq(results[0], _results(_bytesList('')), 'recordOwner returned nothing');

    // (b) an owner call with solver data, wrapped
    route.solverData = _bytesList(abi.encode(_bytesList(hex'5d')));
    vm.expectEmit(false, false, false, true, address(proxy));
    emit ProxyCalleeMock.Delegated(
      TAG_A,
      address(hub),
      0,
      abi.encodeWithSignature('ownerCall(bytes,bytes)', recordOwner, hex'5d')
    );
    vm.prank(owner);
    results = hub.settleOrderWithDelegatedAuthentication(order, address(0), '', route, '', false);
    assertEq(
      results[0],
      _results(
        _bytesList(
          abi.encode(TAG_A, abi.encodeWithSignature('ownerCall(bytes,bytes)', recordOwner, hex'5d'))
        )
      ),
      'the callee received the wrapped call'
    );

    // (c) a solver call
    order = _openAhv2Order(
      new ERC20Allowance[](0), new HookParams[](0), new CallParams[](0), 0, vm.getBlockTimestamp()
    );
    route = _route(order, _calls(proxyCall));
    vm.expectEmit(false, false, false, true, address(proxy));
    emit ProxyCalleeMock.Owner(TAG_A, owner);
    vm.prank(owner);
    results = hub.settleOrderWithDelegatedAuthentication(order, address(0), '', route, '', false);
    assertEq(results.length, 1, 'one solver call ran');
    assertEq(results[0], _results(_bytesList('')), 'recordOwner returned nothing');
  }

  // ---------------------------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------------------------

  /// @dev `abi.encode(callees, callData)`, the payload of both entry points
  function _payload(address[] memory callees, bytes[] memory callData)
    internal
    pure
    returns (bytes memory)
  {
    return abi.encode(callees, callData);
  }

  /// @dev `abi.encode(results)`, the return of both entry points
  function _results(bytes[] memory results) internal pure returns (bytes memory) {
    return abi.encode(results);
  }

  /// @dev What a {ProxyCalleeMock} returns from its fallback
  function _echo(bytes32 tag, bytes memory data) internal pure returns (bytes memory) {
    return abi.encode(tag, data);
  }

  /// @dev The calldata of `callBack(cd)` on a {ProxyCalleeMock}
  function _callBack(bytes memory cd) internal pure returns (bytes memory) {
    return abi.encodeCall(ProxyCalleeMock.callBack, (cd));
  }

  function _pair(address a, address b) internal pure returns (address[] memory out) {
    out = new address[](2);
    out[0] = a;
    out[1] = b;
  }

  function _bytesList(bytes memory a) internal pure returns (bytes[] memory out) {
    out = new bytes[](1);
    out[0] = a;
  }

  function _bytesList(bytes memory a, bytes memory b) internal pure returns (bytes[] memory out) {
    out = new bytes[](2);
    out[0] = a;
    out[1] = b;
  }

  function _bytesList(bytes memory a, bytes memory b, bytes memory c)
    internal
    pure
    returns (bytes[] memory out)
  {
    out = new bytes[](3);
    out[0] = a;
    out[1] = b;
    out[2] = c;
  }

  function _word(address account) internal pure returns (bytes32) {
    return bytes32(uint256(uint160(account)));
  }

  /// @dev The first `count` elements of `src`, each with `prefix` in front, so that its calldata
  /// selects the fallback of a {ProxyCalleeMock}
  function _prefixed(bytes[] memory src, uint256 count, bytes1 prefix)
    internal
    pure
    returns (bytes[] memory out)
  {
    out = new bytes[](count);
    for (uint256 i = 0; i < count; i++) {
      out[i] = bytes.concat(prefix, src[i]);
    }
  }

  /// @dev The first `max` elements of `src`
  function _truncated(address[] memory src, uint256 max)
    internal
    pure
    returns (address[] memory out)
  {
    out = new address[](src.length < max ? src.length : max);
    for (uint256 i = 0; i < out.length; i++) {
      out[i] = src[i];
    }
  }

  /// @dev Callee A when bit `i` of `mask` is clear, callee B otherwise
  function _fuzzCallee(uint256 mask, uint256 i) internal view returns (address) {
    return (mask >> i) & 1 == 0 ? address(calleeA) : address(calleeB);
  }

  function _tagOf(address callee) internal view returns (bytes32) {
    return callee == address(calleeA) ? TAG_A : TAG_B;
  }

  /// @dev The address every event of `logs` was emitted by, which is the contract it created
  function _created(Vm.Log[] memory logs) internal pure returns (address) {
    return logs[0].emitter;
  }

  function _assertLog(Vm.Log memory log, bytes32 topic0, bytes32 topic1, bytes32 topic2)
    internal
    pure
  {
    assertEq(log.topics.length, 3, 'two indexed fields');
    assertEq(log.topics[0], topic0, 'event signature');
    assertEq(log.topics[1], topic1, 'first indexed field');
    assertEq(log.topics[2], topic2, 'second indexed field');
  }

  function _assertLog(
    Vm.Log memory log,
    bytes32 topic0,
    bytes32 topic1,
    bytes32 topic2,
    bytes32 topic3
  ) internal pure {
    assertEq(log.topics.length, 4, 'three indexed fields');
    assertEq(log.topics[0], topic0, 'event signature');
    assertEq(log.topics[1], topic1, 'first indexed field');
    assertEq(log.topics[2], topic2, 'second indexed field');
    assertEq(log.topics[3], topic3, 'third indexed field');
  }

  /// @dev The `Delegated` events the proxy emitted since the logs were last read, in order
  function _seen() internal returns (Seen[] memory out) {
    Vm.Log[] memory logs = vm.getRecordedLogs();

    uint256 found;
    for (uint256 i = 0; i < logs.length; i++) {
      if (logs[i].emitter == address(proxy) && logs[i].topics[0] == DELEGATED_TOPIC) {
        found++;
      }
    }

    out = new Seen[](found);
    found = 0;
    for (uint256 i = 0; i < logs.length; i++) {
      if (logs[i].emitter == address(proxy) && logs[i].topics[0] == DELEGATED_TOPIC) {
        (out[found].tag, out[found].sender, out[found].value, out[found].data) =
          abi.decode(logs[i].data, (bytes32, address, uint256, bytes));
        found++;
      }
    }
  }

  function _assertSeen(
    Seen memory seen,
    bytes32 tag,
    address sender,
    uint256 value,
    bytes memory data
  ) internal pure {
    assertEq(seen.tag, tag, 'the callee that ran');
    assertEq(seen.sender, sender, 'saw this caller');
    assertEq(seen.value, value, 'and this value');
    assertEq(seen.data, data, 'and this calldata');
  }

  /// @dev Runs `ownerCall` on callees A and B and checks the calldata each of them received
  function _assertOwnerRun(
    bytes memory o0,
    bytes memory o1,
    bytes memory solverData,
    bytes memory received0,
    bytes memory received1
  ) internal {
    vm.recordLogs();
    bytes memory results = proxy.ownerCall(
      _payload(_pair(address(calleeA), address(calleeB)), _bytesList(o0, o1)), solverData
    );
    Seen[] memory seen = _seen();

    assertEq(seen.length, 2, 'both callees ran');
    _assertSeen(seen[0], TAG_A, address(this), 0, received0);
    _assertSeen(seen[1], TAG_B, address(this), 0, received1);
    assertEq(
      results,
      _results(_bytesList(_echo(TAG_A, received0), _echo(TAG_B, received1))),
      'the result holds each return in order'
    );
  }
}
