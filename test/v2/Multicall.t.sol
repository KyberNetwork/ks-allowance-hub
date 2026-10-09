// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AuthenticatorBase} from 'test/v2/authenticators/base/AuthenticatorBase.sol';

import {RouterMock} from 'test/v2/mocks/RouterMock.sol';

import {
  ISessionOrderAuthenticator
} from 'src/v2/authenticators/interfaces/ISessionOrderAuthenticator.sol';
import {AuthKey} from 'src/v2/authenticators/types/AuthKey.sol';

import {NativeSpendGuard} from 'src/base/NativeSpendGuard.sol';
import {IUnorderedNonce} from 'src/base/interfaces/IUnorderedNonce.sol';
import {PackedBits} from 'src/base/types/PackedBits.sol';

import {ICallsForwarder} from 'src/v2/interfaces/ICallsForwarder.sol';
import {IKSAllowanceHubV2} from 'src/v2/interfaces/IKSAllowanceHubV2.sol';
import {IOrderAuthenticator} from 'src/v2/interfaces/IOrderAuthenticator.sol';
import {ERC20Transfer} from 'src/v2/types/ERC20Transfer.sol';
import {ExecutionOrder} from 'src/v2/types/ExecutionOrder.sol';
import {GenericCall} from 'src/v2/types/GenericCall.sol';

import {IAccessControl} from 'openzeppelin-contracts/contracts/access/IAccessControl.sol';
import {IERC20} from 'openzeppelin-contracts/contracts/token/ERC20/IERC20.sol';
import {
  IERC20Permit
} from 'openzeppelin-contracts/contracts/token/ERC20/extensions/IERC20Permit.sol';

/**
 * @title MulticallTest
 * @notice MC-01..07 and MC-FUZZ — the batching surface
 * @dev `multicall` runs each entry under the same guards a direct call meets, and bounds the batch
 * as a whole, so one refusal rolls back every entry. The native-value cases are what make that
 * concrete: a batch may spend only what the caller sent, and the hub's own float must survive.
 */
contract MulticallTest is AuthenticatorBase {
  uint160 internal constant AMOUNT = 1 ether;

  bytes32 internal constant ROUTER_ROLE = keccak256('WHITELISTED_ROUTER_ROLE');

  /// @dev The float the hub holds before a call, so `msg.value + 1` is payable
  uint256 internal constant PREFUND = 1 ether;
  uint256 internal constant VALUE = 1 ether;

  /// @dev EIP-2612, transcribed rather than imported from any token or helper
  bytes32 internal constant L_PERMIT_TYPEHASH =
    keccak256('Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)');

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
    permits[0] = _usdcPermitCall(address(hub), permitValue, deadline);

    ERC20Transfer[] memory erc20s = _erc20s(_wethTransfer(AMOUNT));
    GenericCall[] memory calls = _calls(_routerCall(0.5 ether, hex'01'));

    bytes[] memory batch = new bytes[](2);
    batch[0] =
      abi.encodeCall(ICallsForwarder.forwardCalls, (tokens, permits, PackedBits.wrap(bytes32(0))));
    batch[1] = abi.encodeCall(
      IKSAllowanceHubV2.executeOrderWithDelegatedAuthentication,
      (_openExecutionOrder(erc20s, calls, 0, deadline), address(0), '', false)
    );

    uint256 routerWethBefore = IERC20(WETH).balanceOf(address(router));
    uint256 routerNativeBefore = address(router).balance;
    vm.deal(owner, VALUE);

    vm.prank(owner);
    (bytes[] memory results, uint256[] memory gasUsages) = hub.multicall{value: VALUE}(batch);

    assertEq(results.length, 2, 'one result per sub-call');
    assertEq(IERC20(USDC).allowance(owner, address(hub)), permitValue, 'the permit was relayed');
    assertEq(
      IERC20(WETH).balanceOf(address(router)) - routerWethBefore, AMOUNT, 'the order settled'
    );
    assertEq(address(router).balance - routerNativeBefore, 0.5 ether, 'the native leg was paid');
    assertEq(address(hub).balance, VALUE - 0.5 ether, 'the unspent half stayed behind');

    bytes[] memory inner = abi.decode(results[1], (bytes[]));
    assertEq(inner.length, 1, 'the order reported its own call');
    assertEq(gasUsages.length, 2, 'one gas figure per sub-call');
    assertGt(gasUsages[1], 0, 'and the order reported the gas it spent');
  }

  /// MC-02 — each sub-call may spend the value, but the batch as a whole may not spend it twice
  function test_MC_02_batchIsBoundedAsAWhole() public {
    vm.deal(address(hub), 2 * VALUE);
    vm.deal(owner, VALUE);

    GenericCall[] memory calls = _calls(_routerCall(VALUE, hex'01'));
    bytes memory order = abi.encodeCall(
      IKSAllowanceHubV2.executeOrderWithDelegatedAuthentication,
      (
        _openExecutionOrder(new ERC20Transfer[](0), calls, 0, block.timestamp),
        address(0),
        '',
        false
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
      IKSAllowanceHubV2.executeOrderWithDelegatedAuthentication,
      (
        _openExecutionOrder(new ERC20Transfer[](0), calls, 0, block.timestamp),
        address(0),
        '',
        false
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
    (bytes[] memory results,) = hub.multicall(batch);

    assertEq(results.length, 2, 'two results');
    assertEq(
      IERC20(WETH).balanceOf(address(router)) - routerWethBefore, 3 ether, 'both legs pulled'
    );
    assertEq(router.callCount(), 2, 'both calls ran');
    assertEq(router.lastData(), hex'b2', 'the second order ran last');

    bytes[] memory innerFirst = abi.decode(results[0], (bytes[]));
    bytes[] memory innerSecond = abi.decode(results[1], (bytes[]));
    assertEq(abi.decode(innerFirst[0], (uint256)), 1, 'first sub-call saw the first router call');
    assertEq(abi.decode(innerSecond[0], (uint256)), 2, 'and the second saw the second');
  }

  /**
   * MC-07 — each entry is measured on its own, not given a running total of the batch
   * @dev The same two entries are run in both orders, and the order-settling one has to be the
   * dearer of the two either way. That is what separates a per-entry figure from a cumulative one:
   * a running total only ever grows, so it reports the *second* entry as dearer whichever entry it
   * is, and the reversed arrangement catches it. Cold-storage costs fall on whichever entry runs
   * first, so they work against the assertion in one arrangement and for it in the other. An empty
   * `forwardCalls` is the cheap entry — it runs no sub-call at all.
   */
  function test_MC_07_gasIsMeasuredPerEntry() public {
    bytes memory cheap = abi.encodeCall(
      ICallsForwarder.forwardCalls, (new address[](0), new bytes[](0), PackedBits.wrap(bytes32(0)))
    );

    bytes[] memory cheapFirst = new bytes[](2);
    cheapFirst[0] = cheap;
    cheapFirst[1] = _orderCalldata(1 ether, hex'c1');

    uint256 available = gasleft();

    vm.prank(owner);
    (bytes[] memory results, uint256[] memory gasUsages) = hub.multicall(cheapFirst);

    assertEq(results.length, 2, 'one result per entry');
    assertEq(gasUsages.length, 2, 'and one gas figure per entry');
    assertGt(gasUsages[0], 0, 'even the empty entry costs something');
    assertGt(gasUsages[1], gasUsages[0], 'the entry that settled an order cost more');
    assertLt(gasUsages[0] + gasUsages[1], available, 'never more than the caller had left');

    bytes[] memory orderFirst = new bytes[](2);
    orderFirst[0] = _orderCalldata(1 ether, hex'c2');
    orderFirst[1] = cheap;

    vm.prank(owner);
    (, uint256[] memory reversed) = hub.multicall(orderFirst);

    assertGt(reversed[0], reversed[1], 'and still cost more when it ran first');
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

  /**
   * MC-06 — one batch approves a session key at an authenticator and then spends on it
   * @dev The capability the refactor exists for, end to end. The relayer submits both halves and
   * signs neither: `forwardCalls` relays the owner's `updateAuthentication` — the authenticator
   * sees the hub as `msg.sender`, so the owner's own approval signature is what authorises it — and
   * the order in the next slot settles on the key that call has just approved, over the delegated
   * rail, with the session key signing rather than the wallet. Nothing outside the batch approves
   * the key, which the pre-state assertion fixes; the delegation put in place beforehand carries no
   * key of its own, so the hub's gate is open while the authenticator still knows nothing.
   */
  function test_MC_06_approveAMasterKeyAndSpendOnItInOneBatch() public {
    AuthKey memory key = _secpKey(masterSigner, block.timestamp + 30 days);
    bytes32 keyHash = _keyHash(key);

    uint256 deadline = block.timestamp + 1 hours;
    uint256 approvalNonce = 70;
    uint256 orderNonce = 71;

    vm.prank(owner);
    hub.updateDelegation(owner, address(authenticator), true, '', 0, deadline, '');
    assertFalse(authenticator.masterKeys(owner, keyHash), 'the authenticator holds no key yet');

    ERC20Transfer[] memory erc20s = _erc20s(_wethTransfer(AMOUNT));
    GenericCall[] memory calls = _calls(_routerCall(0, hex'01'));

    ExecutionOrder memory order = _openExecutionOrder(erc20s, calls, orderNonce, deadline);
    bytes memory approvalSig = _signMasterKeyApproval(key, true, approvalNonce, deadline);
    bytes memory orderAuth = _executionAuthData(order, key, masterKeyPk);

    address[] memory targets = new address[](1);
    targets[0] = address(authenticator);

    bytes[] memory relayed = new bytes[](1);
    relayed[0] = abi.encodeCall(
      IOrderAuthenticator.updateAuthentication,
      (owner, _approveKey(key), approvalNonce, deadline, approvalSig)
    );

    bytes[] memory batch = new bytes[](2);
    batch[0] =
      abi.encodeCall(ICallsForwarder.forwardCalls, (targets, relayed, PackedBits.wrap(bytes32(0))));
    batch[1] = abi.encodeCall(
      IKSAllowanceHubV2.executeOrderWithDelegatedAuthentication,
      (order, address(authenticator), orderAuth, false)
    );

    // the second half on its own is refused, so the batch below is evidence that the first half
    // did the approving rather than that the order never needed one
    bytes[] memory orderOnly = new bytes[](1);
    orderOnly[0] = batch[1];

    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(ISessionOrderAuthenticator.MasterKeyNotApproved.selector, owner, key)
    );
    hub.multicall(orderOnly);

    uint256 routerWethBefore = IERC20(WETH).balanceOf(address(router));

    vm.prank(relayer);
    (bytes[] memory results,) = hub.multicall(batch);

    assertEq(results.length, 2, 'one result per sub-call');
    assertTrue(authenticator.masterKeys(owner, keyHash), 'the batch approved the key');
    assertEq(
      IERC20(WETH).balanceOf(address(router)) - routerWethBefore,
      AMOUNT,
      'and the order spent on it in the same transaction'
    );
    assertEq(router.callCount(), 1, 'the router leg ran once');
    assertEq(router.seenMsgSender(), owner, 'for the owner, not for the relayer who submitted');
    assertEq(
      authenticator.nonces(lNonceKey(owner), 0),
      1 << approvalNonce,
      'the approval burned a nonce of the owner, who signed it'
    );
    assertEq(
      authenticator.nonces(keyHash, 0),
      1 << orderNonce,
      'and the order burned one of the session key, which signed that'
    );
    assertEq(hub.nonces(lNonceKey(owner), 0), 0, 'and the hub burned none of its own');
  }

  /**
   * MC-08 — one batch mints an ephemeral key from a master key and spends on it
   * @dev MC-06 with the wallet out of the loop. The only signatures are the master key's, over the
   * grant, and the ephemeral key's, over the order; the owner signs nothing and submits nothing,
   * which is the purpose of the second tier. The order on its own is refused first, so the batch
   * is evidence that slot 0 is what let it through.
   */
  function test_MC_08_masterKeyMintsAnEphemeralKeyAndSpendsOnItInOneBatch() public {
    AuthKey memory masterKey = _secpKey(masterSigner, block.timestamp + 30 days);
    AuthKey memory ephemeral = _secpKey(sessionSigner, block.timestamp + 10 minutes);

    uint256 deadline = block.timestamp + 1 hours;
    uint256 grantNonce = 80;
    uint256 orderNonce = 81;

    vm.prank(owner);
    hub.updateDelegation(
      owner, address(authenticator), true, _encodeKey(masterKey), 0, deadline, ''
    );
    assertEq(
      authenticator.sessionKeyMaster(owner, _keyHash(ephemeral)), bytes32(0), 'no ephemeral key yet'
    );

    ExecutionOrder memory order = _openExecutionOrder(
      _erc20s(_wethTransfer(AMOUNT)), _calls(_routerCall(0, hex'01')), orderNonce, deadline
    );
    bytes memory grantSig =
      _signSessionKeyApproval(masterKey, ephemeral, true, grantNonce, deadline, masterKeyPk);
    bytes memory orderAuth = _executionAuthData(order, ephemeral, sessionKeyPk);

    address[] memory targets = new address[](1);
    targets[0] = address(authenticator);

    bytes[] memory relayed = new bytes[](1);
    relayed[0] = abi.encodeCall(
      IOrderAuthenticator.updateAuthentication,
      (owner, _sessionKeyData(ephemeral, masterKey, true), grantNonce, deadline, grantSig)
    );

    bytes[] memory batch = new bytes[](2);
    batch[0] =
      abi.encodeCall(ICallsForwarder.forwardCalls, (targets, relayed, PackedBits.wrap(bytes32(0))));
    batch[1] = abi.encodeCall(
      IKSAllowanceHubV2.executeOrderWithDelegatedAuthentication,
      (order, address(authenticator), orderAuth, false)
    );

    bytes[] memory orderOnly = new bytes[](1);
    orderOnly[0] = batch[1];

    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(
        ISessionOrderAuthenticator.MasterKeyNotApproved.selector, owner, ephemeral
      )
    );
    hub.multicall(orderOnly);

    uint256 routerWethBefore = IERC20(WETH).balanceOf(address(router));

    vm.prank(relayer);
    hub.multicall(batch);

    assertEq(
      authenticator.sessionKeyMaster(owner, _keyHash(ephemeral)),
      _keyHash(masterKey),
      'the batch minted the ephemeral key'
    );
    assertEq(
      IERC20(WETH).balanceOf(address(router)) - routerWethBefore,
      AMOUNT,
      'and it spent on it in the same transaction'
    );
    assertEq(
      authenticator.nonces(lNonceKey(owner), 0), 0, "the owner's namespace is untouched throughout"
    );
  }

  struct BatchFuzz {
    uint8 itemCount;
    uint96 msgValue;
    uint8 payableMask;
  }

  /**
   * MC-FUZZ — value survives a batch exactly when every selector in it is payable
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
      // The non-payable guard reverts with no data and `multicall` bubbles what it received, so
      // the batch surfaces an empty revert. `bytes('')` matches that and nothing carrying data
      vm.prank(owner);
      vm.expectRevert(bytes(''));
      hub.multicall{value: value}(batch);

      assertEq(hub.nonces(lNonceKey(owner), 0), 0, 'the whole batch rolled back');
      assertEq(address(hub).balance, 0, 'and none of the value stuck');
      assertEq(owner.balance, value, 'which is back with the sender');
      return;
    }

    vm.prank(owner);
    (bytes[] memory results,) = hub.multicall{value: value}(batch);

    assertEq(results.length, count, 'one result per sub-call');
    for (uint256 i = 0; i < count; i++) {
      if (_isPayableItem(f.payableMask, i)) {
        assertEq(results[i].length, 0, 'revokeNonce returns nothing');
      } else {
        assertEq(results[i], abi.encode(false), 'paused() returns false');
      }
    }

    assertEq(
      hub.nonces(lNonceKey(owner), 0), expectedBitmap, 'exactly the payable indices burned a nonce'
    );
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
      IKSAllowanceHubV2.executeOrderWithDelegatedAuthentication,
      (
        _openExecutionOrder(
          _erc20s(_wethTransfer(amount)), _calls(_routerCall(0, data)), 0, block.timestamp
        ),
        address(0),
        '',
        false
      )
    );
  }

  /// @dev A whole EIP-2612 `permit` call for {ICallsForwarder-forwardCalls} to relay to USDC
  function _usdcPermitCall(address spender, uint256 value, uint256 deadline)
    internal
    returns (bytes memory)
  {
    bytes32 structHash = keccak256(
      abi.encode(L_PERMIT_TYPEHASH, owner, spender, value, _usdcNonce(owner), deadline)
    );
    (uint8 v, bytes32 r, bytes32 s) =
      vm.sign(ownerKey, lTypedDataHash(_usdcDomainSeparator(), structHash));

    return abi.encodeCall(IERC20Permit.permit, (owner, spender, value, deadline, v, r, s));
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
