// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {HubBase} from 'test/v2/base/HubBase.sol';

import {RouterMock} from 'test/v2/mocks/RouterMock.sol';

import {NativeSpendGuard} from 'src/base/NativeSpendGuard.sol';
import {IAuthVerifier} from 'src/base/interfaces/IAuthVerifier.sol';
import {IPermitForwarder} from 'src/base/interfaces/IPermitForwarder.sol';
import {IUnorderedNonce} from 'src/base/interfaces/IUnorderedNonce.sol';

import {DeadlineChecker} from 'src/base/DeadlineChecker.sol';

import {IKSAllowanceHubV2} from 'src/v2/interfaces/IKSAllowanceHubV2.sol';
import {ERC20Transfer} from 'src/v2/types/ERC20Transfer.sol';
import {ERC721Transfer} from 'src/v2/types/ERC721Transfer.sol';
import {GenericCall} from 'src/v2/types/GenericCall.sol';
import {ValidationParams} from 'src/v2/types/ValidationParams.sol';

import {SessionAuthVerifier} from 'src/verifiers/SessionAuthVerifier.sol';
import {ISessionAuthVerifier} from 'src/verifiers/interfaces/ISessionAuthVerifier.sol';
import {KeyType} from 'src/verifiers/types/KeyType.sol';
import {SessionKey} from 'src/verifiers/types/SessionKey.sol';

import {IManagementBase} from 'ks-common-sc/src/interfaces/IManagementBase.sol';

import {IAccessControl} from 'openzeppelin-contracts/contracts/access/IAccessControl.sol';
import {IERC20} from 'openzeppelin-contracts/contracts/token/ERC20/IERC20.sol';
import {Pausable} from 'openzeppelin-contracts/contracts/utils/Pausable.sol';

/// @notice Verifier that only records, so `delegateAuth` / `updateAuth` can be exercised alone.
contract AuthVerifierMock is IAuthVerifier {
  bytes public lastUpdateData;
  uint256 public updateCount;

  function updateAuth(address, bytes calldata data, uint256, uint256, bytes calldata) external {
    lastUpdateData = data;
    updateCount++;
  }

  function verifyAuth(address, bytes calldata, uint256, uint256, bytes calldata, bytes calldata)
    external {}
}

/// @notice GUARD-01..08 and MC-01..05 / MC-FUZZ — pause, deadline, native spend and batching.
/**
 * @dev Role identifiers are written out rather than imported, so a changed production constant
 * cannot quietly agree with the expectation.
 *
 * The native-spend boundary is derived from {NativeSpendGuard}: the modifier compares
 * `balance + msg.value` against a `balanceBefore` that already contains `msg.value`, which
 * reduces to "revert iff the call spent strictly more than the value it was sent". Reaching the
 * over-spend leg therefore needs the hub to hold native of its own beforehand, or there is
 * nothing left to over-spend.
 */
contract GuardsTest is HubBase {
  uint160 internal constant AMOUNT = 1 ether;

  bytes32 internal constant GUARDIAN = keccak256('GUARDIAN_ROLE');
  bytes32 internal constant DEFAULT_ADMIN = bytes32(0);
  bytes32 internal constant ROUTER_ROLE = keccak256('WHITELISTED_ROUTER_ROLE');

  /// @dev The float the hub holds before a call, so `msg.value + 1` is actually payable
  uint256 internal constant PREFUND = 1 ether;
  uint256 internal constant VALUE = 1 ether;

  /// @dev EIP-2612, transcribed rather than imported from any token or helper
  bytes32 internal constant L_PERMIT_TYPEHASH =
    keccak256('Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)');

  // -----------------------------------------------------------------------------------------
  // GUARD — pause
  // -----------------------------------------------------------------------------------------

  /// GUARD-01 — `paused()` tracks both transitions, and each one announces itself
  function test_GUARD_01_pauseUnpauseRoundTrip() public {
    assertFalse(hub.paused(), 'starts live');

    vm.expectEmit(true, true, true, true, address(hub));
    emit Pausable.Paused(guardian);
    vm.prank(guardian);
    hub.pause();

    assertTrue(hub.paused(), 'paused');

    vm.expectEmit(true, true, true, true, address(hub));
    emit Pausable.Unpaused(admin);
    vm.prank(admin);
    hub.unpause();

    assertFalse(hub.paused(), 'live again');
  }

  /// GUARD-02 — a pause closes both order entry points but leaves delegation open
  function test_GUARD_02_pauseClosesOrdersNotDelegation() public {
    AuthVerifierMock mockVerifier = new AuthVerifierMock();

    vm.prank(guardian);
    hub.pause();

    ERC20Transfer[] memory erc20s = _erc20s(_wethTransfer(AMOUNT));

    vm.prank(owner);
    vm.expectRevert(Pausable.EnforcedPause.selector);
    hub.transferAndExecute(
      owner,
      erc20s,
      new ERC721Transfer[](0),
      new GenericCall[](0),
      block.timestamp,
      _flags(false, false, false),
      ''
    );

    vm.prank(owner);
    vm.expectRevert(Pausable.EnforcedPause.selector);
    hub.transferAndFulfill(
      owner,
      erc20s,
      new ERC721Transfer[](0),
      new ValidationParams[](0),
      block.timestamp,
      _flags(false, false, false),
      '',
      new GenericCall[](0),
      0,
      ''
    );

    // Delegation carries no assets, so the pause does not reach it
    vm.prank(owner);
    hub.delegateAuth(owner, address(mockVerifier), hex'1234', 0, block.timestamp, '');

    assertTrue(hub.authDelegated(owner, address(mockVerifier)), 'delegation still works');
    assertEq(mockVerifier.updateCount(), 1, 'and reached the verifier');
    assertTrue(hub.paused(), 'the hub is still paused');
  }

  /// GUARD-03 — pausing needs the guardian or the admin, unpausing needs the admin alone
  function test_GUARD_03_pauseRolesAreEnforced() public {
    bytes32[] memory needed = new bytes32[](2);
    needed[0] = GUARDIAN;
    needed[1] = DEFAULT_ADMIN;

    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(IManagementBase.UnauthorizedAccount.selector, relayer, needed)
    );
    hub.pause();

    assertFalse(hub.paused(), 'a stranger changed nothing');

    vm.prank(guardian);
    hub.pause();
    assertTrue(hub.paused(), 'the guardian may pause');

    // The guardian's authority is one-way: lifting a pause is the admin's call
    vm.prank(guardian);
    vm.expectRevert(
      abi.encodeWithSelector(
        IAccessControl.AccessControlUnauthorizedAccount.selector, guardian, DEFAULT_ADMIN
      )
    );
    hub.unpause();

    assertTrue(hub.paused(), 'and the pause survives the attempt');
  }

  // -----------------------------------------------------------------------------------------
  // GUARD — deadline
  // -----------------------------------------------------------------------------------------

  /// GUARD-04 — the deadline block itself still settles; the one before it does not
  function test_GUARD_04_deadlineBoundaryOnBothEntryPoints() public {
    uint256 t = block.timestamp;

    _executeAtDeadline(t - 1, false);
    _executeAtDeadline(t, true);
    _executeAtDeadline(t + 1, true);

    _fulfillAtDeadline(t - 1, false);
    _fulfillAtDeadline(t, true);
    _fulfillAtDeadline(t + 1, true);
  }

  /// GUARD-05 — when both guards would fire, the pause wins, because it is the outer modifier
  function test_GUARD_05_pauseTakesPrecedenceOverTheDeadline() public {
    vm.prank(guardian);
    hub.pause();

    vm.prank(owner);
    vm.expectRevert(Pausable.EnforcedPause.selector);
    hub.transferAndExecute(
      owner,
      _erc20s(_wethTransfer(AMOUNT)),
      new ERC721Transfer[](0),
      new GenericCall[](0),
      block.timestamp - 1,
      _flags(false, false, false),
      ''
    );

    vm.prank(owner);
    vm.expectRevert(Pausable.EnforcedPause.selector);
    hub.transferAndFulfill(
      owner,
      _erc20s(_wethTransfer(AMOUNT)),
      new ERC721Transfer[](0),
      new ValidationParams[](0),
      block.timestamp - 1,
      _flags(false, false, false),
      '',
      new GenericCall[](0),
      0,
      ''
    );
  }

  // -----------------------------------------------------------------------------------------
  // GUARD — native spend
  // -----------------------------------------------------------------------------------------

  /// GUARD-06 — an order may spend up to the value it was sent, and not one wei more
  function test_GUARD_06_nativeSpendBoundary() public {
    _nativeSpendLeg(VALUE - 1, true);
    _nativeSpendLeg(VALUE, true);
    _nativeSpendLeg(VALUE + 1, false);
  }

  // -----------------------------------------------------------------------------------------
  // GUARD — deadline on the delegation surfaces
  // -----------------------------------------------------------------------------------------

  /// GUARD-08 — `updateAuth` and a verifier's `verifyAuth` enforce the same deadline rule
  function test_GUARD_08_deadlineOnUpdateAuthAndVerifyAuth() public {
    AuthVerifierMock mockVerifier = new AuthVerifierMock();

    // The modifier runs before the delegation check, so an expired call never reaches the body
    vm.prank(owner);
    vm.expectRevert(DeadlineChecker.DeadlinePassed.selector);
    hub.updateAuth(owner, address(mockVerifier), hex'01', 0, block.timestamp - 1, '');
    assertFalse(hub.authDelegated(owner, address(mockVerifier)), 'nothing was delegated');

    vm.prank(owner);
    hub.delegateAuth(owner, address(mockVerifier), hex'01', 0, block.timestamp, '');

    vm.prank(owner);
    hub.updateAuth(owner, address(mockVerifier), hex'02', 0, block.timestamp, '');
    assertEq(mockVerifier.lastUpdateData(), hex'02', 'the deadline block itself is accepted');
    assertEq(mockVerifier.updateCount(), 2, 'delegation plus the update');

    // The verifier's own gate: stand in as its allowance hub so `onlyAllowanceHub` is satisfied
    SessionAuthVerifier standalone = new SessionAuthVerifier(address(this));
    SessionKey memory key = SessionKey({
      publicKey: abi.encode(relayer),
      keyType: KeyType.Secp256k1,
      expiration: block.timestamp + 1 days
    });
    bytes memory encodedKey = abi.encode(key);
    bytes memory payload = abi.encodePacked(abi.encode(address(0)), false);

    vm.expectRevert(DeadlineChecker.DeadlinePassed.selector);
    standalone.verifyAuth(owner, payload, 1, block.timestamp - 1, encodedKey, '');

    // One second later the deadline is satisfied and the next gate is what refuses
    vm.expectRevert(ISessionAuthVerifier.SessionKeyNotDelegated.selector);
    standalone.verifyAuth(owner, payload, 1, block.timestamp, encodedKey, '');

    assertEq(standalone.nonces(owner, 0), 0, 'neither attempt burned a nonce');
  }

  // -----------------------------------------------------------------------------------------
  // MC — the batching surface
  // -----------------------------------------------------------------------------------------

  /// MC-01 — a permit and the order that uses the approval share one transaction, with value
  function test_MC_01_permitAndOrderInOneBatch() public {
    uint256 permitValue = 1234e6;
    uint256 deadline = block.timestamp + 1 hours;

    address[] memory tokens = new address[](1);
    tokens[0] = USDC;
    bytes[] memory permits = new bytes[](1);
    permits[0] = _usdcPermitData(address(hub), permitValue, deadline);

    ERC20Transfer[] memory erc20s = _erc20s(_wethTransfer(AMOUNT));
    GenericCall[] memory calls = _calls(_routerCall(0.5 ether, hex'01'));

    bytes[] memory batch = new bytes[](2);
    batch[0] = abi.encodeCall(IPermitForwarder.erc20Permit, (owner, tokens, permits));
    batch[1] = abi.encodeCall(
      IKSAllowanceHubV2.transferAndExecute,
      (owner, erc20s, new ERC721Transfer[](0), calls, deadline, _flags(false, false, false), '')
    );

    uint256 routerWethBefore = IERC20(WETH).balanceOf(address(router));
    uint256 routerNativeBefore = address(router).balance;
    vm.deal(owner, VALUE);

    vm.prank(owner);
    bytes[] memory results = hub.multicall{value: VALUE}(batch);

    assertEq(results.length, 2, 'one result per sub-call');
    assertEq(IERC20(USDC).allowance(owner, address(hub)), permitValue, 'the permit was relayed');
    assertEq(
      IERC20(WETH).balanceOf(address(router)) - routerWethBefore, AMOUNT, 'the order settled'
    );
    assertEq(address(router).balance - routerNativeBefore, 0.5 ether, 'the native leg was paid');
    assertEq(address(hub).balance, VALUE - 0.5 ether, 'the unspent half stayed behind');

    (bytes[] memory inner, uint256 gasUsed) = abi.decode(results[1], (bytes[], uint256));
    assertEq(inner.length, 1, 'the order reported its own call');
    assertGt(gasUsed, 0, 'and its own gas');
  }

  /// MC-02 — each sub-call may spend the value, but the batch as a whole may not spend it twice
  function test_MC_02_batchIsBoundedAsAWhole() public {
    vm.deal(address(hub), 2 * VALUE);
    vm.deal(owner, VALUE);

    GenericCall[] memory calls = _calls(_routerCall(VALUE, hex'01'));
    bytes memory order = abi.encodeCall(
      IKSAllowanceHubV2.transferAndExecute,
      (
        owner,
        new ERC20Transfer[](0),
        new ERC721Transfer[](0),
        calls,
        block.timestamp,
        _flags(false, false, false),
        ''
      )
    );

    bytes[] memory batch = new bytes[](2);
    batch[0] = order;
    batch[1] = order;

    uint256 routerBefore = address(router).balance;

    vm.prank(owner);
    vm.expectRevert(NativeSpendGuard.NativeOverSpent.selector);
    hub.multicall{value: VALUE}(batch);

    assertEq(address(hub).balance, 2 * VALUE, "the hub's own float is untouched");
    assertEq(address(router).balance, routerBefore, 'and the router was paid nothing');
    assertEq(router.callCount(), 0, 'the whole batch rolled back');
  }

  /// MC-03 — a sub-call's revert arrives at the caller with its arguments intact
  function test_MC_03_subCallRevertBubbles() public {
    RouterMock stranger = new RouterMock();

    GenericCall[] memory calls =
      _calls(GenericCall({router: address(stranger), value: 0, data: hex'01'}));

    bytes[] memory batch = new bytes[](1);
    batch[0] = abi.encodeCall(
      IKSAllowanceHubV2.transferAndExecute,
      (
        owner,
        new ERC20Transfer[](0),
        new ERC721Transfer[](0),
        calls,
        block.timestamp,
        _flags(false, false, false),
        ''
      )
    );

    vm.prank(owner);
    vm.expectRevert(
      abi.encodeWithSelector(
        IAccessControl.AccessControlUnauthorizedAccount.selector, address(stranger), ROUTER_ROLE
      )
    );
    hub.multicall(batch);
  }

  /// MC-04 — two independent orders in one batch both settle, in the order given
  function test_MC_04_twoOrdersInOneBatch() public {
    bytes[] memory batch = new bytes[](2);
    batch[0] = _orderCalldata(1 ether, hex'a1');
    batch[1] = _orderCalldata(2 ether, hex'b2');

    uint256 routerWethBefore = IERC20(WETH).balanceOf(address(router));

    vm.prank(owner);
    bytes[] memory results = hub.multicall(batch);

    assertEq(results.length, 2, 'two results');
    assertEq(
      IERC20(WETH).balanceOf(address(router)) - routerWethBefore, 3 ether, 'both legs pulled'
    );
    assertEq(router.callCount(), 2, 'both calls ran');
    assertEq(router.lastData(), hex'b2', 'the second order ran last');

    (bytes[] memory innerFirst,) = abi.decode(results[0], (bytes[], uint256));
    (bytes[] memory innerSecond,) = abi.decode(results[1], (bytes[], uint256));
    assertEq(abi.decode(innerFirst[0], (uint256)), 1, 'first sub-call saw the first router call');
    assertEq(abi.decode(innerSecond[0], (uint256)), 2, 'and the second saw the second');
  }

  /// MC-05 — the hub has no `receive`, so a bare transfer cannot strand native in it
  function test_MC_05_plainNativeTransferIsRefused() public {
    vm.deal(owner, 1);

    vm.prank(owner);
    (bool ok,) = address(hub).call{value: 1}('');

    assertFalse(ok, 'there is nothing to receive it');
    assertEq(address(hub).balance, 0, 'the hub holds nothing');
    assertEq(owner.balance, 1, 'and the wei stayed with the sender');
  }

  struct BatchFuzz {
    uint8 itemCount;
    uint96 msgValue;
    uint8 payableMask;
  }

  /// MC-FUZZ — value survives a batch exactly when every selector in it is payable
  /**
   * @dev Every sub-call is a `delegatecall`, so each one sees the outer `msg.value`; a
   * non-payable selector therefore rejects the whole batch on its own dispatcher check.
   */
  function testFuzz_MC_FUZZ_valueNeedsAnAllPayableBatch(BatchFuzz memory f) public {
    uint256 count = bound(f.itemCount, 1, 5);
    uint256 value = bound(f.msgValue, 0, 1 ether);

    bytes[] memory batch = new bytes[](count);
    bool allPayable = true;
    uint256 expectedBitmap;

    for (uint256 i = 0; i < count; i++) {
      if (_isPayableItem(f.payableMask, i)) {
        // `revokeNonce` is payable and leaves a bit behind, so the run is observable
        batch[i] = abi.encodeCall(IUnorderedNonce.revokeNonce, (i));
        expectedBitmap |= 1 << i;
      } else {
        allPayable = false;
        batch[i] = abi.encodeWithSignature('paused()');
      }
    }

    vm.deal(owner, value);

    if (value > 0 && !allPayable) {
      vm.prank(owner);
      vm.expectRevert(bytes(''));
      hub.multicall{value: value}(batch);

      assertEq(hub.nonces(owner, 0), 0, 'the whole batch rolled back');
      assertEq(address(hub).balance, 0, 'and none of the value stuck');
      assertEq(owner.balance, value, 'which is back with the sender');
      return;
    }

    vm.prank(owner);
    bytes[] memory results = hub.multicall{value: value}(batch);

    assertEq(results.length, count, 'one result per sub-call');
    for (uint256 i = 0; i < count; i++) {
      if (_isPayableItem(f.payableMask, i)) {
        assertEq(results[i].length, 0, 'revokeNonce returns nothing');
      } else {
        assertEq(results[i], abi.encode(false), 'paused() returns false');
      }
    }

    assertEq(hub.nonces(owner, 0), expectedBitmap, 'exactly the payable indices burned a nonce');
    assertEq(address(hub).balance, value, 'a payable batch keeps whatever it did not spend');
  }

  // -----------------------------------------------------------------------------------------
  // Helpers
  // -----------------------------------------------------------------------------------------

  function _isPayableItem(uint8 mask, uint256 index) internal pure returns (bool) {
    return (uint256(mask) >> index) & 1 == 1;
  }

  function _orderCalldata(uint160 amount, bytes memory data) internal view returns (bytes memory) {
    return abi.encodeCall(
      IKSAllowanceHubV2.transferAndExecute,
      (
        owner,
        _erc20s(_wethTransfer(amount)),
        new ERC721Transfer[](0),
        _calls(_routerCall(0, data)),
        block.timestamp,
        _flags(false, false, false),
        ''
      )
    );
  }

  function _executeAtDeadline(uint256 deadline, bool shouldSettle) internal {
    uint256 routerBefore = IERC20(WETH).balanceOf(address(router));

    vm.prank(owner);
    if (!shouldSettle) vm.expectRevert(DeadlineChecker.DeadlinePassed.selector);
    hub.transferAndExecute(
      owner,
      _erc20s(_wethTransfer(AMOUNT)),
      new ERC721Transfer[](0),
      new GenericCall[](0),
      deadline,
      _flags(false, false, false),
      ''
    );

    assertEq(
      IERC20(WETH).balanceOf(address(router)) - routerBefore,
      shouldSettle ? AMOUNT : 0,
      'transferAndExecute moved assets only inside the deadline'
    );
  }

  function _fulfillAtDeadline(uint256 deadline, bool shouldSettle) internal {
    uint256 routerBefore = IERC20(WETH).balanceOf(address(router));

    vm.prank(owner);
    if (!shouldSettle) vm.expectRevert(DeadlineChecker.DeadlinePassed.selector);
    hub.transferAndFulfill(
      owner,
      _erc20s(_wethTransfer(AMOUNT)),
      new ERC721Transfer[](0),
      new ValidationParams[](0),
      deadline,
      _flags(false, false, false),
      '',
      new GenericCall[](0),
      0,
      ''
    );

    assertEq(
      IERC20(WETH).balanceOf(address(router)) - routerBefore,
      shouldSettle ? AMOUNT : 0,
      'transferAndFulfill moved assets only inside the deadline'
    );
  }

  function _nativeSpendLeg(uint256 spend, bool shouldSettle) internal {
    vm.deal(address(hub), PREFUND);
    vm.deal(owner, VALUE);

    uint256 routerBefore = address(router).balance;
    GenericCall[] memory calls = _calls(_routerCall(spend, hex'01'));

    vm.prank(owner);
    if (!shouldSettle) vm.expectRevert(NativeSpendGuard.NativeOverSpent.selector);
    hub.transferAndExecute{value: VALUE}(
      owner,
      new ERC20Transfer[](0),
      new ERC721Transfer[](0),
      calls,
      block.timestamp,
      _flags(false, false, false),
      ''
    );

    if (shouldSettle) {
      assertEq(address(router).balance - routerBefore, spend, 'the router was paid exactly');
      assertEq(address(hub).balance, PREFUND + VALUE - spend, 'the hub kept float plus change');
    } else {
      assertEq(address(router).balance, routerBefore, 'nothing left the hub');
      assertEq(address(hub).balance, PREFUND, 'and its float is intact');
      assertEq(owner.balance, VALUE, 'the value went back to the sender');
    }
  }

  /// @dev EIP-2612 blob for {PermitForwarder-erc20Permit}: six words, built from the literal above
  function _usdcPermitData(address spender, uint256 value, uint256 deadline)
    internal
    returns (bytes memory)
  {
    bytes32 structHash = keccak256(
      abi.encode(L_PERMIT_TYPEHASH, owner, spender, value, _usdcNonce(owner), deadline)
    );
    (uint8 v, bytes32 r, bytes32 s) =
      vm.sign(ownerKey, lTypedDataHash(_usdcDomainSeparator(), structHash));

    return abi.encode(spender, value, deadline, uint256(v), r, s);
  }

  /// @dev Read off the deployed token, which is an external dependency rather than code under test
  function _usdcDomainSeparator() internal view returns (bytes32) {
    (bool ok, bytes memory data) = USDC.staticcall(abi.encodeWithSignature('DOMAIN_SEPARATOR()'));
    require(ok, 'usdc domain');
    return abi.decode(data, (bytes32));
  }

  function _usdcNonce(address account) internal view returns (uint256) {
    (bool ok, bytes memory data) =
      USDC.staticcall(abi.encodeWithSignature('nonces(address)', account));
    require(ok, 'usdc nonce');
    return abi.decode(data, (uint256));
  }
}
