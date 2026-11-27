// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {SettlementBase} from 'test/settlement/base/SettlementBase.sol';

import {ERC1271WalletMock} from 'test/mocks/TokenMocks.sol';

import {IKSAllowanceHubV2} from 'src/interfaces/IKSAllowanceHubV2.sol';
import {IAHV2Authenticator} from 'src/interfaces/base/IAHV2Authenticator.sol';
import {IAHV2Hook} from 'src/interfaces/base/IAHV2Hook.sol';
import {IAuthDelegator} from 'src/interfaces/base/IAuthDelegator.sol';
import {IUnorderedNonce} from 'src/interfaces/base/IUnorderedNonce.sol';

import {AHV2Order} from 'src/types/AHV2Order.sol';
import {AHV2Solution} from 'src/types/AHV2Solution.sol';
import {ERC20Allowance} from 'src/types/ERC20Allowance.sol';

import {IERC20} from 'openzeppelin-contracts/contracts/token/ERC20/IERC20.sol';

/**
 * @title OrderSignatureTest
 * @notice `SIG-01..13`, `SIG-FUZZ` and `DISP-01..06` — the owner's signature over an order with
 * the zero authenticator, and the dispatch on `order.authenticator`
 * @dev A non-owner submitter of an order with the zero authenticator carries the owner's EIP-712
 * signature over the order, which spends `order.nonce` in the owner's namespace of the hub. The
 * Permit2 address and any other authenticator select the Permit2 signature flow and the delegated
 * flow respectively.
 */
contract OrderSignatureTest is SettlementBase {
  /// @dev Permit2 does not expose these in the vendored interface, so they are written out here
  bytes4 internal constant PERMIT2_INVALID_SIGNER = bytes4(keccak256('InvalidSigner()'));
  bytes4 internal constant PERMIT2_INVALID_SIGNATURE_LENGTH =
    bytes4(keccak256('InvalidSignatureLength()'));

  /// @dev The batch and the single-token forms of the two signature transfers of Permit2
  bytes4 internal constant PERMIT_TRANSFER_BATCH = bytes4(
    keccak256(
      'permitTransferFrom(((address,uint256)[],uint256,uint256),(address,uint256)[],address,bytes)'
    )
  );
  bytes4 internal constant PERMIT_TRANSFER_SINGLE = bytes4(
    keccak256(
      'permitTransferFrom(((address,uint256),uint256,uint256),(address,uint256),address,bytes)'
    )
  );
  bytes4 internal constant PERMIT_WITNESS_TRANSFER_BATCH = bytes4(
    keccak256(
      'permitWitnessTransferFrom(((address,uint256)[],uint256,uint256),(address,uint256)[],address,bytes32,string,bytes)'
    )
  );
  bytes4 internal constant PERMIT_WITNESS_TRANSFER_SINGLE = bytes4(
    keccak256(
      'permitWitnessTransferFrom(((address,uint256),uint256,uint256),(address,uint256),address,bytes32,string,bytes)'
    )
  );

  /// @dev The parameters of {testFuzz_SIG_FUZZ_ownerNonce}
  struct OwnerNonceFuzz {
    uint256 nonce;
    bool withData;
  }

  /// @dev The parameters of {testFuzz_SIG_FUZZ_relayedSignedOrderSettlesExactly}
  struct SignedOrderFuzz {
    address submitter;
    uint256 nonce;
    uint160 amount;
    uint32 ttl;
  }

  /// @dev An order of the owner with the zero authenticator and the given nonce
  function _ownerOrder(uint256 nonce) internal view returns (AHV2Order memory) {
    return _openAhv2Order(
      _allowances(_tokenAllowance(AMOUNT)),
      _noHooks(),
      _noCalls(),
      nonce,
      vm.getBlockTimestamp() + 1 hours
    );
  }

  // -------------------------------------------------------------------------------------------
  // SIG-01..13 / SIG-FUZZ — the owner's signature over the order
  // -------------------------------------------------------------------------------------------

  /**
   * SIG-01 — a relayer settles an order signed by the owner, which spends its nonce once
   * @dev The nonce bit is read from the owner's namespace. The replay reverts with that namespace
   * and nonce.
   */
  function test_SIG_01_relayedSignedOrderSettlesAndSpendsItsNonce() public {
    AHV2Order memory order = _openAhv2Order(
      _allowances(_tokenAllowance(AMOUNT)),
      _noHooks(),
      _noCalls(),
      7,
      vm.getBlockTimestamp() + 1 hours
    );
    AHV2Solution memory solution = _defaultSolution(order);
    bytes memory signature = _signOrder(order);

    uint256 before = _calleeBalance();
    uint256 ownerBefore = _balance(owner);

    vm.prank(relayer);
    hub.settleOrder(order, signature, solution, '');

    assertEq(_calleeBalance() - before, AMOUNT, 'the callee received the allowance');
    assertEq(ownerBefore - _balance(owner), AMOUNT, 'the owner paid it');
    assertEq(hub.nonces(lNonceKey(owner), 0), 1 << 7, 'exactly bit 7 of the owner namespace');

    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(IUnorderedNonce.NonceAlreadyUsed.selector, lNonceKey(owner), 7)
    );
    hub.settleOrder(order, signature, solution, '');

    assertEq(_calleeBalance() - before, AMOUNT, 'the replay moved nothing');
  }

  /**
   * SIG-02 — an ERC-1271 owner is authenticated through its wallet
   * @dev The nonce is spent in the namespace of the wallet. A signature of another key reverts.
   */
  function test_SIG_02_erc1271OwnerAuthenticatesThroughItsWallet() public {
    (address walletSigner, uint256 walletSignerKey) = makeAddrAndKey('wallet signer');
    ERC1271WalletMock wallet = new ERC1271WalletMock(walletSigner);
    deal(token18, address(wallet), 100 ether);
    vm.prank(address(wallet));
    IERC20(token18).approve(address(hub), type(uint256).max);

    AHV2Order memory order = _openAhv2Order(
      _allowances(_tokenAllowance(AMOUNT)),
      _noHooks(),
      _noCalls(),
      3,
      vm.getBlockTimestamp() + 1 hours
    );
    order.owner = address(wallet);
    AHV2Solution memory solution = _defaultSolution(order);

    vm.prank(relayer);
    vm.expectRevert(IKSAllowanceHubV2.InvalidOrderSignature.selector);
    hub.settleOrder(order, _signOrder(order, signerPk), solution, '');

    uint256 before = _calleeBalance();
    vm.prank(relayer);
    hub.settleOrder(order, _signOrder(order, walletSignerKey), solution, '');

    assertEq(_calleeBalance() - before, AMOUNT, 'the wallet paid');
    assertEq(_balance(address(wallet)), 100 ether - AMOUNT, 'from its own balance');
    assertEq(hub.nonces(lNonceKey(address(wallet)), 0), 1 << 3, "the wallet's namespace");
    assertEq(hub.nonces(lNonceKey(owner), 0), 0, "and not the owner's");
  }

  /**
   * SIG-03 — a signature that does not cover the order as submitted is refused
   * @dev Each step is refused with `InvalidOrderSignature` and leaves the nonce it presented
   * unspent: a wrong key, a signature over an order that differed in the exclusive caller, the
   * nonce, the client data or the data of a call, and an empty signature. The last step is the control that the
   * unsigned order settles with a correct signature.
   */
  function test_SIG_03_signatureNotCoveringTheOrderIsRefused() public {
    uint256 expiration = vm.getBlockTimestamp() + 1 hours;
    ERC20Allowance[] memory erc20s = _allowances(_tokenAllowance(AMOUNT));

    AHV2Order memory order =
      _openAhv2Order(erc20s, _noHooks(), _calls(_calleeCall(hex'01')), 10, expiration);
    AHV2Solution memory solution = _defaultSolution(order);

    vm.prank(relayer);
    vm.expectRevert(IKSAllowanceHubV2.InvalidOrderSignature.selector);
    hub.settleOrder(order, _signOrder(order, signerPk), solution, '');
    assertEq(hub.nonces(lNonceKey(owner), 0) & (1 << 10), 0, 'wrong key: nonce unspent');

    bytes memory signature = _signOrder(order);

    order.exclusiveCaller = relayer;
    vm.prank(relayer);
    vm.expectRevert(IKSAllowanceHubV2.InvalidOrderSignature.selector);
    hub.settleOrder(order, signature, solution, '');
    assertEq(hub.nonces(lNonceKey(owner), 0) & (1 << 10), 0, 'exclusive caller: nonce unspent');
    order.exclusiveCaller = ANY;

    order.nonce = 11;
    vm.prank(relayer);
    vm.expectRevert(IKSAllowanceHubV2.InvalidOrderSignature.selector);
    hub.settleOrder(order, signature, solution, '');
    assertEq(hub.nonces(lNonceKey(owner), 0) & (1 << 11), 0, 'nonce: nonce unspent');
    order.nonce = 10;

    order.clientData = hex'01';
    vm.prank(relayer);
    vm.expectRevert(IKSAllowanceHubV2.InvalidOrderSignature.selector);
    hub.settleOrder(order, signature, solution, '');
    assertEq(hub.nonces(lNonceKey(owner), 0) & (1 << 10), 0, 'client data: nonce unspent');
    order.clientData = '';

    order.calls[0].ownerData = hex'02';
    vm.prank(relayer);
    vm.expectRevert(IKSAllowanceHubV2.InvalidOrderSignature.selector);
    hub.settleOrder(order, signature, solution, '');
    assertEq(hub.nonces(lNonceKey(owner), 0) & (1 << 10), 0, 'call data: nonce unspent');
    order.calls[0].ownerData = hex'01';

    vm.prank(relayer);
    vm.expectRevert(IKSAllowanceHubV2.InvalidOrderSignature.selector);
    hub.settleOrder(order, '', solution, '');
    assertEq(hub.nonces(lNonceKey(owner), 0) & (1 << 10), 0, 'empty signature: nonce unspent');

    uint256 before = _calleeBalance();
    vm.prank(relayer);
    hub.settleOrder(order, signature, solution, '');
    assertEq(_calleeBalance() - before, AMOUNT, 'the signed order settles');
    assertEq(callee.lastData(), hex'01', 'with the signed call data');
    assertEq(hub.nonces(lNonceKey(owner), 0), 1 << 10, 'and spends only its own nonce');
  }

  /**
   * SIG-04 — the owner submits an order with the zero authenticator and nonce 0
   * @dev Nonce 0 is not spent, so the same call settles again, and the nonce word of the owner
   * is unchanged.
   */
  function test_SIG_04_ownerSubmitsWithZeroNonceAndSpendsNothing() public {
    AHV2Order memory order = _ownerOrder(0);
    AHV2Solution memory solution = _defaultSolution(order);
    uint256 before = _calleeBalance();

    vm.prank(owner);
    hub.settleOrder(order, '', solution, '');

    assertEq(_calleeBalance() - before, AMOUNT, 'the first call settled');
    assertEq(hub.nonces(lNonceKey(owner), 0), 0, 'no nonce is spent');

    vm.prank(owner);
    hub.settleOrder(order, '', solution, '');

    assertEq(_calleeBalance() - before, 2 * AMOUNT, 'the identical second call settled');
    assertEq(hub.nonces(lNonceKey(owner), 0), 0, 'still no nonce is spent');
  }

  /**
   * SIG-05 — the order signature does not bind the solution, and a non-zero approver does
   * @dev With the sentinel approver, two orders carrying the same call are settled with solutions
   * that differ in their solver data and no approval; each spends its own nonce. With a named
   * approver, an empty approval is refused.
   */
  function test_SIG_05_solutionIsFreeWithSentinelApproverAndBoundByANamedOne() public {
    uint256 expiration = vm.getBlockTimestamp() + 1 hours;
    ERC20Allowance[] memory erc20s = _allowances(_tokenAllowance(AMOUNT));

    AHV2Order memory first =
      _openAhv2Order(erc20s, _noHooks(), _calls(_calleeCall(hex'01')), 1, expiration);
    AHV2Order memory second =
      _openAhv2Order(erc20s, _noHooks(), _calls(_calleeCall(hex'01')), 2, expiration);
    AHV2Solution memory solutionA = _defaultSolution(first);
    solutionA.solverData[0] = hex'0a';
    AHV2Solution memory solutionB = _defaultSolution(second);
    solutionB.solverData[0] = hex'0b';

    uint256 before = _calleeBalance();

    vm.prank(relayer);
    hub.settleOrder(first, _signOrder(first), solutionA, '');
    assertEq(callee.lastSolverData(), hex'0a', 'the first solution ran');
    vm.prank(relayer);
    hub.settleOrder(second, _signOrder(second), solutionB, '');
    assertEq(callee.lastSolverData(), hex'0b', 'the second solution ran');

    assertEq(_calleeBalance() - before, 2 * AMOUNT, 'both solutions settled');
    assertEq(hub.nonces(lNonceKey(owner), 0), (1 << 1) | (1 << 2), 'each spent its own nonce');

    AHV2Order memory named = _ahv2Order(
      ANY, erc20s, _noNfts(), _noHooks(), _calls(_calleeCall(hex'01')), approver, 3, expiration
    );
    AHV2Solution memory solutionC = _defaultSolution(named);
    bytes memory signature = _signOrder(named);

    vm.prank(relayer);
    vm.expectRevert(IKSAllowanceHubV2.InvalidSolutionSignature.selector);
    hub.settleOrder(named, signature, solutionC, '');
    assertEq(hub.nonces(lNonceKey(owner), 0) & (1 << 3), 0, 'the refusal spent no nonce');

    vm.prank(relayer);
    hub.settleOrder(
      named, signature, solutionC, _signSolutionApproval(approverKey, named, solutionC)
    );
    assertEq(_calleeBalance() - before, 3 * AMOUNT, 'with the approval it settles');
  }

  /**
   * SIG-06 — a nonce already spent in the owner's namespace refuses the order
   * @dev The first step spends nonce 8 with `revokeNonce` of the owner, the second spends nonce 9
   * with a relayed delegation signed by the owner.
   */
  function test_SIG_06_nonceSpentByRevocationOrDelegationRefusesTheOrder() public {
    uint256 expiration = vm.getBlockTimestamp() + 1 hours;
    ERC20Allowance[] memory erc20s = _allowances(_tokenAllowance(AMOUNT));

    AHV2Order memory revoked = _openAhv2Order(erc20s, _noHooks(), _noCalls(), 8, expiration);
    bytes memory revokedSig = _signOrder(revoked);
    vm.prank(owner);
    hub.revokeNonce(8);

    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(IUnorderedNonce.NonceAlreadyUsed.selector, lNonceKey(owner), 8)
    );
    hub.settleOrder(revoked, revokedSig, _defaultSolution(revoked), '');

    AHV2Order memory delegated = _openAhv2Order(erc20s, _noHooks(), _noCalls(), 9, expiration);
    bytes memory delegatedSig = _signOrder(delegated);
    bytes memory delegation =
      _signAuthDelegation(ownerKey, owner, address(authenticator), true, '', 9, expiration);
    vm.prank(relayer);
    hub.updateDelegation(owner, address(authenticator), true, '', 9, expiration, delegation);

    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(IUnorderedNonce.NonceAlreadyUsed.selector, lNonceKey(owner), 9)
    );
    hub.settleOrder(delegated, delegatedSig, _defaultSolution(delegated), '');

    assertEq(_calleeBalance(), 0, 'nothing moved');
  }

  /**
   * SIG-07 — only the exclusive caller may submit, and that is checked before the signature
   * @dev A stranger with a valid signature and a stranger with an empty one are refused with the
   * same error. The exclusive caller settles with the valid signature.
   */
  function test_SIG_07_exclusiveCallerIsCheckedBeforeTheSignature() public {
    AHV2Order memory order = _ahv2Order(
      solver,
      _allowances(_tokenAllowance(AMOUNT)),
      _noNfts(),
      _noHooks(),
      _noCalls(),
      ANY,
      4,
      vm.getBlockTimestamp() + 1 hours
    );
    AHV2Solution memory solution = _defaultSolution(order);
    bytes memory signature = _signOrder(order);

    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(IKSAllowanceHubV2.NotExclusiveCallerOrOwner.selector, relayer)
    );
    hub.settleOrder(order, signature, solution, '');

    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(IKSAllowanceHubV2.NotExclusiveCallerOrOwner.selector, relayer)
    );
    hub.settleOrder(order, '', solution, '');

    uint256 before = _calleeBalance();
    vm.prank(solver);
    hub.settleOrder(order, signature, solution, '');
    assertEq(_calleeBalance() - before, AMOUNT, 'the exclusive caller settled');
  }

  /**
   * SIG-08 — a spent nonce is refused before the signature is verified
   * @dev The owner revokes nonce 8, and a relayer submits the order with a signature of another
   * key. The error is `NonceAlreadyUsed` and not `InvalidOrderSignature`.
   */
  function test_SIG_08_spentNonceIsRefusedBeforeTheSignature() public {
    AHV2Order memory order = _openAhv2Order(
      _allowances(_tokenAllowance(AMOUNT)),
      _noHooks(),
      _noCalls(),
      8,
      vm.getBlockTimestamp() + 1 hours
    );
    AHV2Solution memory solution = _defaultSolution(order);
    bytes memory wrongKeySignature = _signOrder(order, signerPk);

    vm.prank(owner);
    hub.revokeNonce(8);

    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(IUnorderedNonce.NonceAlreadyUsed.selector, lNonceKey(owner), 8)
    );
    hub.settleOrder(order, wrongKeySignature, solution, '');

    assertEq(_calleeBalance(), 0, 'nothing moved');
  }

  /**
   * SIG-09 — the exclusive caller is checked before the nonce
   * @dev The order is pinned to the relayer and its nonce 9 is revoked. A stranger submitting it
   * with an empty signature is refused with `NotExclusiveCallerOrOwner`.
   */
  function test_SIG_09_exclusiveCallerIsCheckedBeforeTheNonce() public {
    AHV2Order memory order = _ahv2Order(
      relayer,
      _allowances(_tokenAllowance(AMOUNT)),
      _noNfts(),
      _noHooks(),
      _noCalls(),
      ANY,
      9,
      vm.getBlockTimestamp() + 1 hours
    );
    AHV2Solution memory solution = _defaultSolution(order);

    vm.prank(owner);
    hub.revokeNonce(9);

    vm.prank(solver);
    vm.expectRevert(
      abi.encodeWithSelector(IKSAllowanceHubV2.NotExclusiveCallerOrOwner.selector, solver)
    );
    hub.settleOrder(order, '', solution, '');

    assertEq(_calleeBalance(), 0, 'nothing moved');
  }

  /**
   * SIG-10 — the owner settles an order with a non-zero nonce once, which spends that nonce
   * @dev The bit is set in the namespace of the owner, and the second call reverts with it.
   */
  function test_SIG_10_ownerNonZeroNonceIsSpentOnce() public {
    AHV2Order memory order = _ownerOrder(5);
    AHV2Solution memory solution = _defaultSolution(order);

    vm.prank(owner);
    hub.settleOrder(order, '', solution, '');

    assertEq(_calleeBalance(), AMOUNT, 'the order settled');
    assertEq(hub.nonces(lNonceKey(owner), 0), 1 << 5, 'exactly bit 5 is spent');

    vm.prank(owner);
    vm.expectRevert(
      abi.encodeWithSelector(IUnorderedNonce.NonceAlreadyUsed.selector, lNonceKey(owner), 5)
    );
    hub.settleOrder(order, '', solution, '');

    assertEq(_calleeBalance(), AMOUNT, 'the second call moved nothing');
  }

  /**
   * SIG-11 — a nonce the owner revoked refuses the order of the owner
   * @dev The revocation sets bit 5, and the owner call reverts with `NonceAlreadyUsed`.
   */
  function test_SIG_11_ownerRevokedNonceRefusesTheOwner() public {
    AHV2Order memory order = _ownerOrder(5);

    vm.prank(owner);
    hub.revokeNonce(5);

    vm.prank(owner);
    vm.expectRevert(
      abi.encodeWithSelector(IUnorderedNonce.NonceAlreadyUsed.selector, lNonceKey(owner), 5)
    );
    hub.settleOrder(order, '', _defaultSolution(order), '');

    assertEq(_calleeBalance(), 0, 'nothing moved');
    assertEq(hub.nonces(lNonceKey(owner), 0), 1 << 5, 'only the revocation is set');
  }

  /**
   * SIG-12 — authentication data on the owner's own call is checked as the owner's signature
   * @dev A single byte and a signature by another key revert with `InvalidOrderSignature` and leave
   * the nonce unspent. The owner's signature settles the order and spends nonce 5, and a replay
   * reverts with `NonceAlreadyUsed`.
   */
  function test_SIG_12_ownerAuthenticationDataIsChecked() public {
    AHV2Order memory order = _ownerOrder(5);
    AHV2Solution memory solution = _defaultSolution(order);
    bytes[2] memory invalid = [bytes(hex'01'), _signOrder(order, signerPk)];

    for (uint256 i = 0; i < invalid.length; i++) {
      vm.prank(owner);
      vm.expectRevert(IKSAllowanceHubV2.InvalidOrderSignature.selector);
      hub.settleOrder(order, invalid[i], solution, '');
    }
    assertEq(_calleeBalance(), 0, 'nothing moved');
    assertEq(hub.nonces(lNonceKey(owner), 0), 0, 'the nonce is unspent');

    bytes memory signature = _signOrder(order);
    vm.prank(owner);
    hub.settleOrder(order, signature, solution, '');
    assertEq(_calleeBalance(), AMOUNT, 'the order settled');
    assertEq(hub.nonces(lNonceKey(owner), 0), 1 << 5, 'nonce 5 is spent');

    vm.prank(owner);
    vm.expectRevert(
      abi.encodeWithSelector(IUnorderedNonce.NonceAlreadyUsed.selector, lNonceKey(owner), 5)
    );
    hub.settleOrder(order, signature, solution, '');
  }

  /**
   * SIG-13 — authentication data on the owner's own call spends the nonce before it is checked
   * @dev With nonce 5 revoked and one byte of data, the error is `NonceAlreadyUsed` and not
   * `InvalidOrderSignature`.
   */
  function test_SIG_13_ownerAuthenticationDataSpendsTheNonceFirst() public {
    AHV2Order memory order = _ownerOrder(5);

    vm.prank(owner);
    hub.revokeNonce(5);

    vm.prank(owner);
    vm.expectRevert(
      abi.encodeWithSelector(IUnorderedNonce.NonceAlreadyUsed.selector, lNonceKey(owner), 5)
    );
    hub.settleOrder(order, hex'01', _defaultSolution(order), '');

    assertEq(_calleeBalance(), 0, 'nothing moved');
  }

  /**
   * SIG-FUZZ — any submitter settles a signed order for any nonce, amount and lifetime
   * @dev The transfer is exact and exactly the order's nonce bit is set. The submitter is an
   * account without code, so the prank and the hub's accounts are not involved.
   */
  function testFuzz_SIG_FUZZ_relayedSignedOrderSettlesExactly(SignedOrderFuzz memory f) public {
    vm.assume(f.submitter != owner && f.submitter != address(0));
    vm.assume(f.submitter.code.length == 0 && uint160(f.submitter) > 0xff);
    f.amount = uint160(bound(f.amount, 1, _balance(owner)));
    f.ttl = uint32(bound(f.ttl, 0, 30 days));

    AHV2Order memory order = _openAhv2Order(
      _allowances(_tokenAllowance(f.amount)),
      _noHooks(),
      _noCalls(),
      f.nonce,
      vm.getBlockTimestamp() + f.ttl
    );
    AHV2Solution memory solution = _defaultSolution(order);
    bytes memory signature = _signOrder(order);

    uint256 before = _calleeBalance();
    uint256 ownerBefore = _balance(owner);

    vm.prank(f.submitter);
    hub.settleOrder(order, signature, solution, '');

    assertEq(_calleeBalance() - before, f.amount, 'the callee received the amount');
    assertEq(ownerBefore - _balance(owner), f.amount, 'the owner paid it');
    assertEq(
      hub.nonces(lNonceKey(owner), f.nonce >> 8),
      1 << (f.nonce & 0xff),
      'exactly the order nonce bit is set'
    );
  }

  /**
   * SIG-FUZZ — the owner's own call spends a signed nonce, and an unsigned one unless zero
   * @dev With the owner's signature the nonce bit is set for every nonce. With empty data it is set
   * exactly for a non-zero nonce.
   */
  function testFuzz_SIG_FUZZ_ownerNonce(OwnerNonceFuzz memory f) public {
    AHV2Order memory order = _ownerOrder(f.nonce);
    AHV2Solution memory solution = _defaultSolution(order);
    bytes memory data = f.withData ? _signOrder(order) : bytes('');

    vm.prank(owner);
    hub.settleOrder(order, data, solution, '');
    assertEq(_calleeBalance(), AMOUNT, 'the order settled');
    assertEq(
      hub.nonces(lNonceKey(owner), f.nonce >> 8),
      f.withData || f.nonce != 0 ? 1 << (f.nonce & 0xff) : 0,
      'a signed or non-zero nonce is spent, and an unsigned zero one is not'
    );
  }

  // -------------------------------------------------------------------------------------------
  // DISP-01..06 — dispatch on `order.authenticator`
  // -------------------------------------------------------------------------------------------

  /**
   * DISP-01 — the Permit2 address as authenticator is never called, even when delegated
   * @dev The owner delegates Permit2 as an authenticator. The order still settles through the
   * witness permit, and `authenticate` is not called on Permit2.
   */
  function test_DISP_01_delegatedPermit2IsNotCalledAsAnAuthenticator() public {
    vm.prank(owner);
    hub.updateDelegation(owner, permit2, true, '', 0, vm.getBlockTimestamp() + 1 days, '');
    assertTrue(hub.authDelegated(owner, permit2), 'Permit2 is delegated');

    AHV2Order memory order = _openAhv2Order(
      permit2,
      _allowances(_tokenAllowance(AMOUNT)),
      _noHooks(),
      _noCalls(),
      21,
      vm.getBlockTimestamp() + 1 hours
    );
    bytes memory witness = _signPermit2Order(order);
    uint256 before = _calleeBalance();

    vm.expectCall(permit2, abi.encodeWithSelector(IAHV2Authenticator.authenticate.selector), 0);
    vm.prank(relayer);
    hub.settleOrder(order, witness, _defaultSolution(order), '');

    assertEq(_calleeBalance() - before, AMOUNT, 'settled through Permit2');
  }

  /**
   * DISP-02 — a delegated authenticator never reaches the signature transfers of Permit2
   * @dev Neither the batch nor the single-token form of either transfer is called.
   */
  function test_DISP_02_delegatedAuthenticatorCallsNoPermit2SignatureTransfer() public {
    AHV2Order memory order = _openAhv2Order(
      address(authenticator),
      _allowances(_tokenAllowance(AMOUNT)),
      _noHooks(),
      _noCalls(),
      22,
      vm.getBlockTimestamp() + 1 hours
    );
    bytes memory authData = _authOf(order);
    uint256 before = _calleeBalance();

    vm.expectCall(permit2, abi.encodeWithSelector(PERMIT_WITNESS_TRANSFER_BATCH), 0);
    vm.expectCall(permit2, abi.encodeWithSelector(PERMIT_WITNESS_TRANSFER_SINGLE), 0);
    vm.expectCall(permit2, abi.encodeWithSelector(PERMIT_TRANSFER_BATCH), 0);
    vm.expectCall(permit2, abi.encodeWithSelector(PERMIT_TRANSFER_SINGLE), 0);
    vm.prank(relayer);
    hub.settleOrder(order, authData, _defaultSolution(order), '');

    assertEq(_calleeBalance() - before, AMOUNT, 'settled through the authenticator');
  }

  /**
   * DISP-03 — the Permit2 authenticator pulls with the signature, not the owner's allowance
   * @dev The order sets the number of Permit2 transfers, which the Permit2 signature transfer flow
   * ignores, and the owner's Permit2 allowance is unchanged.
   */
  function test_DISP_03_permit2FlowIgnoresPermit2Transfers() public {
    _grantPermit2Allowance(token18, 100 ether);

    AHV2Order memory order = _openAhv2Order(
      permit2,
      _allowances(_tokenAllowance(AMOUNT)),
      _noHooks(),
      _noCalls(),
      23,
      vm.getBlockTimestamp() + 1 hours
    );
    _withPermit2Transfers(order, order.erc20Allowances.length);
    bytes memory witness = _signPermit2Order(order);
    uint256 before = _calleeBalance();

    vm.prank(relayer);
    hub.settleOrder(order, witness, _defaultSolution(order), '');

    assertEq(_calleeBalance() - before, AMOUNT, 'the tokens moved');
    assertEq(_permit2Allowance(token18), 100 ether, 'the Permit2 allowance is unchanged');
  }

  /**
   * DISP-04 — the owner is refused with an authenticator that was never delegated
   * @dev `authenticate` is not called and nothing moves.
   */
  function test_DISP_04_ownerWithAnUndelegatedAuthenticatorIsRefused() public {
    AHV2Order memory order = _openAhv2Order(
      address(authenticator),
      _allowances(_tokenAllowance(AMOUNT)),
      _noHooks(),
      _noCalls(),
      24,
      vm.getBlockTimestamp() + 1 hours
    );
    uint256 before = _calleeBalance();

    vm.expectCall(
      address(authenticator), abi.encodeWithSelector(IAHV2Authenticator.authenticate.selector), 0
    );
    vm.prank(owner);
    vm.expectRevert(
      abi.encodeWithSelector(
        IAuthDelegator.AuthenticatorNotDelegated.selector, address(authenticator)
      )
    );
    hub.settleOrder(order, '', _defaultSolution(order), '');

    assertEq(_calleeBalance(), before, 'nothing moved');
  }

  /**
   * DISP-05 — a relayer on the Permit2 signature transfer flow needs the witness signature
   * @dev The plain permit signature is refused with `InvalidSigner` and an empty signature with
   * `InvalidSignatureLength`, both by Permit2.
   */
  function test_DISP_05_permit2FlowRefusesPlainPermitAndEmptySignature() public {
    ERC20Allowance[] memory erc20s = _allowances(_tokenAllowance(AMOUNT));
    uint256 expiration = vm.getBlockTimestamp() + 1 hours;
    AHV2Order memory order = _openAhv2Order(permit2, erc20s, _noHooks(), _noCalls(), 25, expiration);
    AHV2Solution memory solution = _defaultSolution(order);

    bytes memory plain = _signPlainPermit(erc20s, 25, expiration);
    vm.prank(relayer);
    vm.expectRevert(PERMIT2_INVALID_SIGNER);
    hub.settleOrder(order, plain, solution, '');

    vm.prank(relayer);
    vm.expectRevert(PERMIT2_INVALID_SIGNATURE_LENGTH);
    hub.settleOrder(order, '', solution, '');

    uint256 before = _calleeBalance();
    vm.prank(relayer);
    hub.settleOrder(order, _signPermit2Order(order), solution, '');
    assertEq(_calleeBalance() - before, AMOUNT, 'the witness signature settles');
  }

  /**
   * DISP-06 — the exclusive caller is checked before the approval and the hooks, on every rail
   * @dev Each order is pinned to the relayer, names an approver and carries a hook with the
   * before flag. A stranger submits it with the credential valid for its rail and an empty
   * approval, which is refused with `NotExclusiveCallerOrOwner`. The hook is not called and no nonce is
   * spent in the namespace of the approver.
   */
  function test_DISP_06_exclusiveCallerIsCheckedBeforeApprovalAndHooks() public {
    vm.expectCall(address(hook), abi.encodeWithSelector(IAHV2Hook.beforeSettlement.selector), 0);
    _assertExclusiveCallerFirst(address(0), 26);
    _assertExclusiveCallerFirst(permit2, 27);
    _assertExclusiveCallerFirst(address(authenticator), 28);
  }

  /// @dev Submits an order of the rail `railAuthenticator` as a stranger with its valid credential
  function _assertExclusiveCallerFirst(address railAuthenticator, uint256 nonce) internal {
    AHV2Order memory order = _ahv2Order(
      railAuthenticator,
      relayer,
      _allowances(_tokenAllowance(AMOUNT)),
      _noNfts(),
      _hooks(_hook(hook)),
      _noCalls(),
      approver,
      nonce,
      vm.getBlockTimestamp() + 1 hours
    );
    order.flags = _hookFlags(0, true, false);
    AHV2Solution memory solution = _defaultSolution(order);

    bytes memory credential;
    if (railAuthenticator == address(0)) {
      credential = _signOrder(order);
    } else if (railAuthenticator == permit2) {
      credential = _signPermit2Order(order);
    } else {
      credential = _authOf(order);
    }
    uint256 approverWord = hub.nonces(lNonceKey(approver), 0);

    vm.prank(solver);
    vm.expectRevert(
      abi.encodeWithSelector(IKSAllowanceHubV2.NotExclusiveCallerOrOwner.selector, solver)
    );
    hub.settleOrder(order, credential, solution, '');

    assertEq(hub.nonces(lNonceKey(approver), 0), approverWord, 'the approver namespace is intact');
    assertEq(_calleeBalance(), 0, 'nothing moved');
  }
}
