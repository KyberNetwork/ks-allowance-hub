// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {SchemaHash} from 'test/base/SchemaHash.sol';

import {AuthenticatorBase} from 'test/v2/authenticators/base/AuthenticatorBase.sol';

import {IUnorderedNonce} from 'src/base/interfaces/IUnorderedNonce.sol';
import {AuthKey} from 'src/base/types/AuthKey.sol';
import {PackedBits} from 'src/base/types/PackedBits.sol';
import {IKSAllowanceHubV2} from 'src/v2/interfaces/IKSAllowanceHubV2.sol';
import {ERC721Approval} from 'src/v2/types/ERC721Approval.sol';
import {ERC721Transfer} from 'src/v2/types/ERC721Transfer.sol';
import {ExecutionOrder} from 'src/v2/types/ExecutionOrder.sol';
import {FulfillmentOrder} from 'src/v2/types/FulfillmentOrder.sol';
import {FulfillmentSolution} from 'src/v2/types/FulfillmentSolution.sol';
import {GenericCall} from 'src/v2/types/GenericCall.sol';
import {ValidationParams} from 'src/v2/types/ValidationParams.sol';

import {IERC20} from 'openzeppelin-contracts/contracts/token/ERC20/IERC20.sol';

/**
 * @notice `RO-01..07`, `CAN-01..08` and `CAN-FUZZ`: reusable orders, whose nonce is 0, and their
 * cancellation
 * @dev An order with nonce 0 spends no nonce on the delegated rails, so it settles for as long as
 * its authentication holds and the owner has not cancelled it. The cancellation is consulted for
 * a submitter other than the owner on the delegated rails only. Every order here pins its
 * submitter, `relayer` for an execution and `solver` for a fulfillment, and every expected order
 * hash is taken from the schema oracle.
 */
contract ReusableOrdersTest is AuthenticatorBase {
  uint160 internal constant AMOUNT = 5 ether;

  /// @dev Permit2's refusal of a nonce it has already spent
  bytes4 internal constant PERMIT2_INVALID_NONCE = bytes4(keccak256('InvalidNonce()'));

  /// @dev The fields {testFuzz_CAN_FUZZ_cancel} draws, one named struct for the family
  struct CancelFuzz {
    bool callerIsOwner;
    address other;
    bool reusable;
    uint256 nonce;
    bool fulfillment;
    uint256 extraDataSeed;
  }

  AuthKey internal key;

  function setUp() public override {
    super.setUp();
    key = _secpKey(masterSigner, block.timestamp + 30 days);
  }

  // -------------------------------------------------------------------------------------------
  // RO-01..04 — a reusable order settles repeatedly and spends no nonce
  // -------------------------------------------------------------------------------------------

  /// RO-01 — a reusable execution order settles twice under a master key, and no nonce is spent
  function test_RO_01_reusableExecutionSettlesTwiceUnderAMasterKey() public {
    _delegateKeyThroughHub(key);
    ExecutionOrder memory order = _execution(0, '');
    bytes memory authData = _executionAuthData(order, key, masterKeyPk);
    uint256 routerBefore = _routerBalance();
    uint256 ownerBefore = _ownerBalance();

    _expectNoRevokeNonce();
    _executeAs(relayer, order, authData);
    _expectNoRevokeNonce();
    _executeAs(relayer, order, authData);

    assertEq(authenticator.nonces(_credentialHash(key), 0), 0, 'the key spent no nonce');
    assertEq(authenticator.nonces(lNonceKey(owner), 0), 0, 'the owner namespace is untouched');
    assertEq(_routerBalance() - routerBefore, 2 * AMOUNT, 'two settlements reached the router');
    assertEq(ownerBefore - _ownerBalance(), 2 * AMOUNT, 'and left the owner');
    assertEq(router.callCount(), 2, 'the route ran twice');
  }

  /// RO-02 — a reusable fulfillment order settles twice under a master key, and no nonce is spent
  function test_RO_02_reusableFulfillmentSettlesTwiceUnderAMasterKey() public {
    _delegateKeyThroughHub(key);
    FulfillmentOrder memory order = _fulfillment(0, '');
    bytes memory authData = _fulfillmentAuthData(order, key, masterKeyPk);
    uint256 routerBefore = _routerBalance();
    uint256 ownerBefore = _ownerBalance();

    _expectNoRevokeNonce();
    _fulfillAs(solver, order, authData);
    _expectNoRevokeNonce();
    _fulfillAs(solver, order, authData);

    assertEq(authenticator.nonces(_credentialHash(key), 0), 0, 'the key spent no nonce');
    assertEq(authenticator.nonces(lNonceKey(owner), 0), 0, 'the owner namespace is untouched');
    assertEq(_routerBalance() - routerBefore, 2 * AMOUNT, 'two settlements reached the router');
    assertEq(ownerBefore - _ownerBalance(), 2 * AMOUNT, 'and left the owner');
    assertEq(router.callCount(), 2, 'the route ran twice');
  }

  /**
   * RO-03 — a reusable order of either type settles twice on the owner's signature
   * @dev The authenticator is delegated with no key, so only the owner rail can authenticate.
   */
  function test_RO_03_reusableOrdersSettleTwiceOnTheOwnerSignature() public {
    _delegateWithoutKey();
    ExecutionOrder memory execution = _execution(0, '');
    FulfillmentOrder memory fulfillment = _fulfillment(0, '');
    bytes memory executionData = _executionOwnerAuthData(execution);
    bytes memory fulfillmentData = _fulfillmentOwnerAuthData(fulfillment);
    uint256 routerBefore = _routerBalance();
    uint256 ownerBefore = _ownerBalance();

    _expectNoRevokeNonce();
    _executeAs(relayer, execution, executionData);
    _expectNoRevokeNonce();
    _executeAs(relayer, execution, executionData);
    assertEq(_routerBalance() - routerBefore, 2 * AMOUNT, 'two executions settled');

    _expectNoRevokeNonce();
    _fulfillAs(solver, fulfillment, fulfillmentData);
    _expectNoRevokeNonce();
    _fulfillAs(solver, fulfillment, fulfillmentData);

    assertEq(authenticator.nonces(lNonceKey(owner), 0), 0, 'the owner spent no nonce');
    assertEq(_routerBalance() - routerBefore, 4 * AMOUNT, 'and two fulfillments settled');
    assertEq(ownerBefore - _ownerBalance(), 4 * AMOUNT, 'all four left the owner');
    assertEq(router.callCount(), 4, 'the route ran four times');
  }

  /// RO-04 — a session key authenticates a reusable fulfillment twice
  function test_RO_04_sessionKeyAuthenticatesAReusableFulfillmentTwice() public {
    _delegateKeyThroughHub(key);
    AuthKey memory sessionKey = _secpKey(sessionSigner, key.expiration);
    _approveSessionKey(key, sessionKey, 1, block.timestamp + 1 days, masterKeyPk);

    FulfillmentOrder memory order = _fulfillment(0, '');
    bytes memory authData = _fulfillmentAuthData(order, sessionKey, sessionKeyPk, true);
    uint256 routerBefore = _routerBalance();

    _expectNoRevokeNonce();
    _fulfillAs(solver, order, authData);
    _expectNoRevokeNonce();
    _fulfillAs(solver, order, authData);

    assertEq(authenticator.nonces(_credentialHash(sessionKey), 0), 0, 'the session key spent none');
    assertEq(authenticator.nonces(_credentialHash(key), 0), 1 << 1, 'only the approval spent one');
    assertEq(_routerBalance() - routerBefore, 2 * AMOUNT, 'two settlements reached the router');
    assertEq(router.callCount(), 2, 'the route ran twice');
  }

  // -------------------------------------------------------------------------------------------
  // RO-05..07 — nonce 0 cannot be revoked, and every other nonce is spent
  // -------------------------------------------------------------------------------------------

  /**
   * RO-05 — revoking nonce 0 does not stop a reusable order
   * @dev Both namespaces have bit 0 set by an explicit revocation. A reusable order of either type
   * still settles on the key rail and on the owner rail, and the bit is neither read nor cleared.
   */
  function test_RO_05_revokingNonceZeroDoesNotStopAReusableOrder() public {
    _delegateKeyThroughHub(key);
    uint256 deadline = block.timestamp + 1 hours;

    vm.prank(owner);
    authenticator.revokeNonce(0);
    authenticator.revokeNonce(key, 0, deadline, _signNonceRevocation(key, 0, deadline, masterKeyPk));
    assertEq(authenticator.nonces(lNonceKey(owner), 0), 1, 'bit 0 is set in the owner namespace');
    assertEq(authenticator.nonces(_credentialHash(key), 0), 1, 'and in the credential namespace');

    ExecutionOrder memory execution = _execution(0, '');
    FulfillmentOrder memory fulfillment = _fulfillment(0, '');
    uint256 routerBefore = _routerBalance();

    _executeAs(relayer, execution, _executionAuthData(execution, key, masterKeyPk));
    _executeAs(relayer, execution, _executionOwnerAuthData(execution));
    _fulfillAs(solver, fulfillment, _fulfillmentAuthData(fulfillment, key, masterKeyPk));
    _fulfillAs(solver, fulfillment, _fulfillmentOwnerAuthData(fulfillment));

    assertEq(_routerBalance() - routerBefore, 4 * AMOUNT, 'all four settled');
    assertEq(authenticator.nonces(lNonceKey(owner), 0), 1, 'the owner bit is as it was');
    assertEq(authenticator.nonces(_credentialHash(key), 0), 1, 'and so is the credential bit');
  }

  /**
   * RO-06 — on the Permit2 signature rail a reusable order settles once
   * @dev Permit2 spends the nonce 0 of the permit, so a second submission is refused by Permit2.
   */
  function test_RO_06_permit2SignatureRailSettlesAReusableOrderOnce() public {
    FulfillmentOrder memory order = _fulfillment(0, '');
    bytes memory permit = _signFulfillmentWitness(order);
    uint256 routerBefore = _routerBalance();

    vm.prank(solver);
    hub.fulfillOrderWithPermit2Signature(order, permit, _route(order, _routerCalls()), '');

    assertEq(_routerBalance() - routerBefore, AMOUNT, 'the first submission settled');
    assertEq(_permit2NonceBitmap(owner, 0), 1, 'Permit2 spent nonce 0');

    FulfillmentSolution memory again = _route(order, _routerCalls());
    vm.prank(solver);
    vm.expectRevert(PERMIT2_INVALID_NONCE);
    hub.fulfillOrderWithPermit2Signature(order, permit, again, '');

    assertEq(_routerBalance() - routerBefore, AMOUNT, 'and the second moved nothing');
  }

  /// RO-07 — a non-reusable execution order still spends its nonce, and its replay is refused
  function test_RO_07_nonReusableExecutionSpendsItsNonce() public {
    _delegateKeyThroughHub(key);
    ExecutionOrder memory order = _execution(5, '');
    bytes memory authData = _executionAuthData(order, key, masterKeyPk);

    _executeAs(relayer, order, authData);
    assertEq(authenticator.nonces(_credentialHash(key), 0), 1 << 5, 'nonce 5 is spent');

    vm.expectRevert(
      abi.encodeWithSelector(IUnorderedNonce.NonceAlreadyUsed.selector, _credentialHash(key), 5)
    );
    _executeAs(relayer, order, authData);
    assertEq(router.callCount(), 1, 'the route ran once');
  }

  /// RO-07b — the same for a fulfillment order
  function test_RO_07b_nonReusableFulfillmentSpendsItsNonce() public {
    _delegateKeyThroughHub(key);
    FulfillmentOrder memory order = _fulfillment(5, '');
    bytes memory authData = _fulfillmentAuthData(order, key, masterKeyPk);

    _fulfillAs(solver, order, authData);
    assertEq(authenticator.nonces(_credentialHash(key), 0), 1 << 5, 'nonce 5 is spent');

    vm.expectRevert(
      abi.encodeWithSelector(IUnorderedNonce.NonceAlreadyUsed.selector, _credentialHash(key), 5)
    );
    _fulfillAs(solver, order, authData);
    assertEq(router.callCount(), 1, 'the route ran once');
  }

  // -------------------------------------------------------------------------------------------
  // CAN-01..03 — the owner cancels a reusable order
  // -------------------------------------------------------------------------------------------

  /**
   * CAN-01 — a cancelled reusable execution order is refused for a relayer, not for the owner
   * @dev The relayer is refused before the authenticator is called: the authentication data is
   * empty, which the authenticator would refuse with its own error.
   */
  function test_CAN_01_cancelledReusableExecutionIsRefusedForARelayer() public {
    _delegateKeyThroughHub(key);
    ExecutionOrder memory order = _execution(0, '');
    bytes32 orderHash = SchemaHash.executionOrder(order);
    bytes memory authData = _executionAuthData(order, key, masterKeyPk);

    _executeAs(relayer, order, authData);
    assertFalse(hub.cancelledOrders(orderHash), 'not cancelled at first');

    _expectCancelOrder(orderHash);
    vm.prank(owner);
    hub.cancelReusableExecutionOrder(order);
    assertTrue(hub.cancelledOrders(orderHash), 'cancelled');

    bytes memory refusal =
      abi.encodeWithSelector(IKSAllowanceHubV2.OrderCancelled.selector, orderHash);
    vm.expectRevert(refusal);
    _executeAs(relayer, order, authData);
    vm.expectRevert(refusal);
    _executeAs(relayer, order, '');

    assertEq(router.callCount(), 1, 'only the first submission ran');
    assertEq(authenticator.nonces(_credentialHash(key), 0), 0, 'the authenticator spent nothing');

    uint256 routerBefore = _routerBalance();
    vm.prank(owner);
    hub.executeOrderWithDelegatedAuthentication(order, address(0), '', false);
    assertEq(_routerBalance() - routerBefore, AMOUNT, 'the owner still settles the order');
    assertEq(router.callCount(), 2, 'and its route ran');
  }

  /// CAN-02 — a cancelled reusable fulfillment order is refused for a solver, not for the owner
  function test_CAN_02_cancelledReusableFulfillmentIsRefusedForASolver() public {
    _delegateKeyThroughHub(key);
    FulfillmentOrder memory order = _fulfillment(0, '');
    bytes32 orderHash = SchemaHash.fulfillmentOrder(order);
    bytes memory authData = _fulfillmentAuthData(order, key, masterKeyPk);

    _fulfillAs(solver, order, authData);
    assertFalse(hub.cancelledOrders(orderHash), 'not cancelled at first');

    _expectCancelOrder(orderHash);
    vm.prank(owner);
    hub.cancelReusableFulfillmentOrder(order);
    assertTrue(hub.cancelledOrders(orderHash), 'cancelled');

    bytes memory refusal =
      abi.encodeWithSelector(IKSAllowanceHubV2.OrderCancelled.selector, orderHash);
    vm.expectRevert(refusal);
    _fulfillAs(solver, order, authData);
    vm.expectRevert(refusal);
    _fulfillAs(solver, order, '');

    assertEq(router.callCount(), 1, 'only the first submission ran');
    assertEq(authenticator.nonces(_credentialHash(key), 0), 0, 'the authenticator spent nothing');

    uint256 routerBefore = _routerBalance();
    vm.prank(owner);
    hub.fulfillOrderWithDelegatedAuthentication(
      order, address(0), '', _route(order, _routerCalls()), '', false
    );
    assertEq(_routerBalance() - routerBefore, AMOUNT, 'the owner still settles the order');
    assertEq(router.callCount(), 2, 'and its route ran');
  }

  /// CAN-03 — cancelling an order again succeeds and emits again
  function test_CAN_03_cancellingTwiceSucceedsAndEmitsTwice() public {
    ExecutionOrder memory execution = _execution(0, '');
    FulfillmentOrder memory fulfillment = _fulfillment(0, '');
    bytes32 executionHash = SchemaHash.executionOrder(execution);
    bytes32 fulfillmentHash = SchemaHash.fulfillmentOrder(fulfillment);

    for (uint256 i = 0; i < 2; i++) {
      _expectCancelOrder(executionHash);
      vm.prank(owner);
      hub.cancelReusableExecutionOrder(execution);
      assertTrue(hub.cancelledOrders(executionHash), 'the execution order stays cancelled');
    }
    for (uint256 i = 0; i < 2; i++) {
      _expectCancelOrder(fulfillmentHash);
      vm.prank(owner);
      hub.cancelReusableFulfillmentOrder(fulfillment);
      assertTrue(hub.cancelledOrders(fulfillmentHash), 'the fulfillment order stays cancelled');
    }
  }

  // -------------------------------------------------------------------------------------------
  // CAN-04..05 — who may cancel, and what
  // -------------------------------------------------------------------------------------------

  /**
   * CAN-04 — only the owner may cancel, and the caller is checked before the nonce
   * @dev The orders of the second round have a non-zero nonce, which would be refused as not
   * reusable if the nonce were checked first.
   */
  function test_CAN_04_onlyTheOwnerMayCancel() public {
    bytes memory refusal =
      abi.encodeWithSelector(IKSAllowanceHubV2.CallerNotOwner.selector, relayer);

    for (uint256 nonce = 0; nonce < 2; nonce++) {
      ExecutionOrder memory execution = _execution(nonce, '');
      FulfillmentOrder memory fulfillment = _fulfillment(nonce, '');

      vm.prank(relayer);
      vm.expectRevert(refusal);
      hub.cancelReusableExecutionOrder(execution);
      assertFalse(hub.cancelledOrders(SchemaHash.executionOrder(execution)), 'execution stays');

      vm.prank(relayer);
      vm.expectRevert(refusal);
      hub.cancelReusableFulfillmentOrder(fulfillment);
      assertFalse(
        hub.cancelledOrders(SchemaHash.fulfillmentOrder(fulfillment)), 'fulfillment stays'
      );
    }
  }

  /// CAN-05 — the owner cannot cancel an order whose nonce is not 0
  function test_CAN_05_ownerCannotCancelANonReusableOrder() public {
    uint256[2] memory nonces = [uint256(1), type(uint256).max];

    for (uint256 i = 0; i < nonces.length; i++) {
      bytes memory refusal =
        abi.encodeWithSelector(IKSAllowanceHubV2.OrderNotReusable.selector, nonces[i]);
      ExecutionOrder memory execution = _execution(nonces[i], '');
      FulfillmentOrder memory fulfillment = _fulfillment(nonces[i], '');

      vm.prank(owner);
      vm.expectRevert(refusal);
      hub.cancelReusableExecutionOrder(execution);
      assertFalse(hub.cancelledOrders(SchemaHash.executionOrder(execution)), 'execution stays');

      vm.prank(owner);
      vm.expectRevert(refusal);
      hub.cancelReusableFulfillmentOrder(fulfillment);
      assertFalse(
        hub.cancelledOrders(SchemaHash.fulfillmentOrder(fulfillment)), 'fulfillment stays'
      );
    }
  }

  // -------------------------------------------------------------------------------------------
  // CAN-06 — one cancellation cancels one order
  // -------------------------------------------------------------------------------------------

  /**
   * CAN-06 — cancelling a reusable fulfillment order leaves the other orders of the owner alone
   * @dev The other orders are a reusable execution order and a reusable fulfillment order that
   * differs from the cancelled one in `extraData` only. Both still settle for their submitters.
   */
  function test_CAN_06_cancellationIsolatesOneOrder() public {
    _delegateKeyThroughHub(key);
    FulfillmentOrder memory cancelled = _fulfillment(0, 'first');
    FulfillmentOrder memory sibling = _fulfillment(0, 'second');
    ExecutionOrder memory execution = _execution(0, 'first');
    bytes32 cancelledHash = SchemaHash.fulfillmentOrder(cancelled);
    bytes32 siblingHash = SchemaHash.fulfillmentOrder(sibling);
    bytes32 executionHash = SchemaHash.executionOrder(execution);

    vm.prank(owner);
    hub.cancelReusableFulfillmentOrder(cancelled);

    assertTrue(hub.cancelledOrders(cancelledHash), 'the chosen order is cancelled');
    assertFalse(hub.cancelledOrders(siblingHash), 'the order differing in extra data is not');
    assertFalse(hub.cancelledOrders(executionHash), 'the execution order is not');

    bytes memory cancelledData = _fulfillmentAuthData(cancelled, key, masterKeyPk);
    vm.expectRevert(
      abi.encodeWithSelector(IKSAllowanceHubV2.OrderCancelled.selector, cancelledHash)
    );
    _fulfillAs(solver, cancelled, cancelledData);

    uint256 routerBefore = _routerBalance();
    _fulfillAs(solver, sibling, _fulfillmentAuthData(sibling, key, masterKeyPk));
    _executeAs(relayer, execution, _executionAuthData(execution, key, masterKeyPk));
    assertEq(_routerBalance() - routerBefore, 2 * AMOUNT, 'both other orders settled');
    assertEq(router.callCount(), 2, 'and ran their routes');
  }

  // -------------------------------------------------------------------------------------------
  // CAN-07 — the caller that cancels
  // -------------------------------------------------------------------------------------------

  /**
   * CAN-07 — a cancellation in `multicall` is the owner's, and one relayed by `forwardCalls` is not
   * @dev The forwarder calls the hub as itself. Its revert data is returned by the hub unchanged,
   * and with the failure bit set it is the entry's result instead.
   */
  function test_CAN_07_multicallKeepsTheCallerAndForwardingDoesNot() public {
    ExecutionOrder memory execution = _execution(0, '');
    FulfillmentOrder memory fulfillment = _fulfillment(0, '');
    bytes32 executionHash = SchemaHash.executionOrder(execution);
    bytes32 fulfillmentHash = SchemaHash.fulfillmentOrder(fulfillment);

    bytes[] memory batch = new bytes[](2);
    batch[0] = abi.encodeCall(IKSAllowanceHubV2.cancelReusableExecutionOrder, (execution));
    batch[1] = abi.encodeCall(IKSAllowanceHubV2.cancelReusableFulfillmentOrder, (fulfillment));

    bytes[] memory forwarded = new bytes[](1);
    forwarded[0] = batch[0];
    bytes memory refusal =
      abi.encodeWithSelector(IKSAllowanceHubV2.CallerNotOwner.selector, address(callsForwarder));

    vm.prank(owner);
    vm.expectRevert(refusal);
    hub.forwardCalls(_addresses(address(hub)), forwarded, PackedBits.wrap(bytes32(0)));

    vm.prank(owner);
    bytes[] memory results =
      hub.forwardCalls(_addresses(address(hub)), forwarded, PackedBits.wrap(bytes32(uint256(1))));
    assertEq(results[0], refusal, 'with the failure bit set the refusal is the entry result');
    assertFalse(hub.cancelledOrders(executionHash), 'the forwarded cancellation did nothing');

    _expectCancelOrder(executionHash);
    _expectCancelOrder(fulfillmentHash);
    vm.prank(owner);
    hub.multicall(batch);
    assertTrue(hub.cancelledOrders(executionHash), 'the batched execution cancellation applied');
    assertTrue(hub.cancelledOrders(fulfillmentHash), 'and so did the fulfillment cancellation');
  }

  // -------------------------------------------------------------------------------------------
  // CAN-08 — the Permit2 signature rail ignores cancellation
  // -------------------------------------------------------------------------------------------

  /// CAN-08 — a cancelled reusable fulfillment order still settles once over a Permit2 signature
  function test_CAN_08_cancellationDoesNotApplyToThePermit2SignatureRail() public {
    FulfillmentOrder memory order = _fulfillment(0, '');
    bytes memory permit = _signFulfillmentWitness(order);

    vm.prank(owner);
    hub.cancelReusableFulfillmentOrder(order);
    assertTrue(hub.cancelledOrders(SchemaHash.fulfillmentOrder(order)), 'cancelled');

    uint256 routerBefore = _routerBalance();
    vm.prank(solver);
    hub.fulfillOrderWithPermit2Signature(order, permit, _route(order, _routerCalls()), '');
    assertEq(_routerBalance() - routerBefore, AMOUNT, 'the Permit2 signature settled it');

    FulfillmentSolution memory again = _route(order, _routerCalls());
    vm.prank(solver);
    vm.expectRevert(PERMIT2_INVALID_NONCE);
    hub.fulfillOrderWithPermit2Signature(order, permit, again, '');
  }

  /// CAN-08b — the same for a cancelled reusable execution order
  function test_CAN_08b_cancelledExecutionStillSettlesOverAPermit2Signature() public {
    ExecutionOrder memory order = _execution(0, '');
    bytes memory permit = _signExecutionWitness(order);

    vm.prank(owner);
    hub.cancelReusableExecutionOrder(order);
    assertTrue(hub.cancelledOrders(SchemaHash.executionOrder(order)), 'cancelled');

    uint256 routerBefore = _routerBalance();
    vm.prank(relayer);
    hub.executeOrderWithPermit2Signature(order, permit);
    assertEq(_routerBalance() - routerBefore, AMOUNT, 'the Permit2 signature settled it');
  }

  // -------------------------------------------------------------------------------------------
  // CAN-FUZZ
  // -------------------------------------------------------------------------------------------

  /**
   * CAN-FUZZ — a cancellation is refused for a caller other than the owner, then for a nonce
   * other than 0
   * @dev Otherwise it succeeds, emits and sets the mapping for that order only.
   */
  function testFuzz_CAN_FUZZ_cancel(CancelFuzz memory f) public {
    address caller = f.callerIsOwner
      ? owner
      : address(uint160(bound(uint256(uint160(f.other)), 1, type(uint160).max)));
    vm.assume(f.callerIsOwner || caller != owner);
    uint256 nonce = f.reusable ? 0 : bound(f.nonce, 1, type(uint256).max);
    bytes memory extraData = bytes(vm.toString(f.extraDataSeed));

    ExecutionOrder memory execution = _execution(nonce, extraData);
    FulfillmentOrder memory fulfillment = _fulfillment(nonce, extraData);
    bytes32 orderHash = f.fulfillment
      ? SchemaHash.fulfillmentOrder(fulfillment)
      : SchemaHash.executionOrder(execution);
    bytes32 otherHash = f.fulfillment
      ? SchemaHash.executionOrder(execution)
      : SchemaHash.fulfillmentOrder(fulfillment);

    if (caller != owner) {
      vm.expectRevert(abi.encodeWithSelector(IKSAllowanceHubV2.CallerNotOwner.selector, caller));
    } else if (nonce != 0) {
      vm.expectRevert(abi.encodeWithSelector(IKSAllowanceHubV2.OrderNotReusable.selector, nonce));
    } else {
      _expectCancelOrder(orderHash);
    }
    vm.prank(caller);
    if (f.fulfillment) {
      hub.cancelReusableFulfillmentOrder(fulfillment);
    } else {
      hub.cancelReusableExecutionOrder(execution);
    }

    assertEq(
      hub.cancelledOrders(orderHash), caller == owner && nonce == 0, 'set only by a valid cancel'
    );
    assertFalse(hub.cancelledOrders(otherHash), 'the other order type is never set');
  }

  // -------------------------------------------------------------------------------------------
  // helpers
  // -------------------------------------------------------------------------------------------

  /// @dev An execution order of `AMOUNT` to the router that only `relayer` may submit
  function _execution(uint256 nonce, bytes memory extraData)
    private
    view
    returns (ExecutionOrder memory order)
  {
    order = _executionOrder(
      relayer,
      _erc20s(_tokenTransfer(AMOUNT)),
      new ERC721Transfer[](0),
      _routerCalls(),
      nonce,
      block.timestamp + 1 hours
    );
    order.extraData = extraData;
  }

  /// @dev A fulfillment order of `AMOUNT` that only `solver` may submit, with any route accepted
  function _fulfillment(uint256 nonce, bytes memory extraData)
    private
    view
    returns (FulfillmentOrder memory order)
  {
    order = _fulfillmentOrder(
      solver,
      _allowances(_tokenAllowance(AMOUNT)),
      new ERC721Approval[](0),
      new ValidationParams[](0),
      new GenericCall[](0),
      ANY,
      nonce,
      block.timestamp + 1 hours
    );
    order.extraData = extraData;
  }

  function _routerCalls() private view returns (GenericCall[] memory) {
    return _calls(_routerCall(0, hex'01'));
  }

  function _executeAs(address caller, ExecutionOrder memory order, bytes memory authData) private {
    vm.prank(caller);
    hub.executeOrderWithDelegatedAuthentication(order, address(authenticator), authData, false);
  }

  function _fulfillAs(address caller, FulfillmentOrder memory order, bytes memory authData)
    private
  {
    vm.prank(caller);
    hub.fulfillOrderWithDelegatedAuthentication(
      order, address(authenticator), authData, _route(order, _routerCalls()), '', false
    );
  }

  /// @dev Delegates the authenticator with no master key, so that only the owner rail applies
  function _delegateWithoutKey() private {
    vm.prank(owner);
    hub.updateDelegation(owner, address(authenticator), true, '', 0, block.timestamp + 1 days, '');
  }

  function _expectCancelOrder(bytes32 orderHash) private {
    vm.expectEmit(true, true, true, true, address(hub));
    emit IKSAllowanceHubV2.CancelOrder(owner, orderHash);
  }

  function _routerBalance() private view returns (uint256) {
    return IERC20(token18).balanceOf(address(router));
  }

  function _ownerBalance() private view returns (uint256) {
    return IERC20(token18).balanceOf(owner);
  }
}
