// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AuthenticatorBase} from 'test/v2/authenticators/base/AuthenticatorBase.sol';

import {AuthKey} from 'src/v2/authenticators/types/AuthKey.sol';
import {ERC721Transfer} from 'src/v2/types/ERC721Transfer.sol';
import {ExecutionOrder} from 'src/v2/types/ExecutionOrder.sol';
import {FulfillmentOrder} from 'src/v2/types/FulfillmentOrder.sol';
import {FulfillmentSolution} from 'src/v2/types/FulfillmentSolution.sol';
import {GenericCall} from 'src/v2/types/GenericCall.sol';
import {ValidationParams} from 'src/v2/types/ValidationParams.sol';

import {IERC20} from 'openzeppelin-contracts/contracts/token/ERC20/IERC20.sol';

/**
 * @title NonceNamespaceTest
 * @notice NONCE-06..07 — a nonce belongs to whoever signed the data it guards
 * @dev One contract holds signed data of more than one kind, verified against more than one
 * signer, and each kind carries a number its signer chose. While every kind shared the account the
 * data acted upon, those numbers collided: spending one blocked an unrelated signature that
 * happened to pick the same number. Each case here spends a number in the owner's namespace and
 * then settles data signed by somebody else carrying that same number, which does not compile into
 * anything meaningful unless the namespaces are separate.
 */
import {IUnorderedNonce} from 'src/base/interfaces/IUnorderedNonce.sol';

/**
 * @title NoncesTest
 * @notice NONCE-01..07 and NONCE-FUZZ — the unordered bitmap
 * @dev A nonce is a word index in its top bits and a bit position in its low byte, spent in any
 * order, and a namespace belongs to whoever signed the data the nonce guards. The boundary cases
 * pin the split between word and bit; the namespace cases pin that two kinds of signed data in one
 * contract cannot collide on a number.
 */
contract NoncesTest is AuthenticatorBase {
  uint160 internal constant AMOUNT = 1 ether;

  AuthKey internal key;

  address internal approver;
  uint256 internal approverKey;

  function setUp() public override {
    super.setUp();
    key = _secpKey(masterSigner, block.timestamp + 30 days);
    (approver, approverKey) = makeAddrAndKey('solution approver');
  }

  /// NONCE-06 — in the authenticator, the owner's approvals and a session key's orders are separate
  function test_NONCE_06_approvalAndOrderNumbersDoNotCollide() public {
    _delegateKeyThroughHub(key);

    // Spend 7 in the owner's namespace, which is where a relayed session approval would land
    vm.prank(owner);
    authenticator.revokeNonce(7);

    ExecutionOrder memory order = _openExecutionOrder(
      _erc20s(_wethTransfer(AMOUNT)), new GenericCall[](0), 7, block.timestamp + 1 hours
    );

    uint256 before = IERC20(WETH).balanceOf(address(router));
    vm.prank(relayer);
    hub.executeOrderWithDelegatedAuthentication(
      order, address(authenticator), _executionAuthData(order, key, masterKeyPk), false
    );

    assertEq(
      IERC20(WETH).balanceOf(address(router)) - before,
      AMOUNT,
      'the order settled on a number the owner had already spent'
    );
    assertEq(authenticator.nonces(lNonceKey(owner), 0), 1 << 7, 'the owner spent 7');
    assertEq(authenticator.nonces(_keyHash(key), 0), 1 << 7, 'and the key spent its own 7');
  }

  /// NONCE-07 — in the hub, the owner's delegations and an approver's routes are separate
  function test_NONCE_07_delegationAndRouteNumbersDoNotCollide() public {
    // Spend 9 in the owner's namespace, which is where a relayed delegation would land
    vm.prank(owner);
    hub.revokeNonce(9);

    uint256 deadline = block.timestamp + 1 hours;
    FulfillmentOrder memory order = _fulfillmentOrder(
      ANY,
      _erc20s(_wethTransfer(AMOUNT)),
      new ERC721Transfer[](0),
      new ValidationParams[](0),
      new GenericCall[](0),
      approver,
      9,
      deadline
    );
    FulfillmentSolution memory route = _solution(_calls(_routerCall(0, hex'01')), 9, deadline);
    bytes memory approval = _signSolutionApproval(approverKey, lFulfillmentOrderHash(order), route);

    uint256 before = IERC20(WETH).balanceOf(address(router));
    vm.prank(owner);
    hub.fulfillOrderWithDelegatedAuthentication(order, address(0), '', route, approval, false);

    assertEq(
      IERC20(WETH).balanceOf(address(router)) - before,
      AMOUNT,
      'the route settled on a number the owner had already spent'
    );
    assertEq(hub.nonces(lNonceKey(owner), 0), 1 << 9, 'the owner spent 9');
    assertEq(hub.nonces(lNonceKey(approver), 0), 1 << 9, 'and the approver spent their own 9');
  }

  // -------------------------------------------------------------------------------------------
  // NONCE — the unordered bitmap
  // -------------------------------------------------------------------------------------------

  /// NONCE-01 / NONCE-FUZZ — a nonce lands on exactly one bit, at the position it names
  function testFuzz_NONCE_FUZZ_revokeSetsExactlyOneBit(uint256 nonce) public {
    vm.prank(owner);
    hub.revokeNonce(nonce);

    assertEq(hub.nonces(lNonceKey(owner), nonce >> 8), 1 << (nonce & 0xff), 'exact bit');
    // a neighbouring word is untouched
    assertEq(hub.nonces(lNonceKey(owner), (nonce >> 8) + 1), 0, 'neighbouring word clean');
  }

  /// NONCE-01 — the documented boundaries
  function test_NONCE_01_bitmapBoundaries() public {
    uint256[4] memory nonces = [uint256(0), 255, 256, type(uint256).max];

    for (uint256 i = 0; i < nonces.length; i++) {
      vm.prank(owner);
      hub.revokeNonce(nonces[i]);

      // nonces 0 and 255 share word 0, so assert the bit rather than the whole word
      uint256 bit = 1 << (nonces[i] & 0xff);
      assertEq(hub.nonces(lNonceKey(owner), nonces[i] >> 8) & bit, bit, 'boundary bit set');
    }

    // 0 and 256 share a bit position but live in different words
    assertEq(hub.nonces(lNonceKey(owner), 0), (1 << 0) | (1 << 255), 'word 0 holds 0 and 255');
    assertEq(hub.nonces(lNonceKey(owner), 1), 1 << 0, 'word 1 holds 256');
  }

  /// NONCE-04 — revoking twice reverts
  function test_NONCE_04_doubleRevoke() public {
    vm.startPrank(owner);
    hub.revokeNonce(9);
    vm.expectRevert(IUnorderedNonce.NonceAlreadyUsed.selector);
    hub.revokeNonce(9);
    vm.stopPrank();
  }

  /// NONCE-05 — the hub and the authenticator keep separate bitmaps
  function test_NONCE_05_hubAndAuthenticatorAreIndependent() public {
    vm.prank(owner);
    hub.revokeNonce(3);

    vm.prank(owner);
    authenticator.revokeNonce(3);

    assertEq(hub.nonces(lNonceKey(owner), 0), 1 << 3);
    assertEq(authenticator.nonces(lNonceKey(owner), 0), 1 << 3);

    // spending it on one side does not spend it on the other
    vm.prank(owner);
    vm.expectRevert(IUnorderedNonce.NonceAlreadyUsed.selector);
    hub.revokeNonce(3);
  }
}
