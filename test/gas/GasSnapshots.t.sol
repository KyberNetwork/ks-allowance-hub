// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {SettlementBase} from 'test/settlement/base/SettlementBase.sol';

import {AHV2Order} from 'src/types/AHV2Order.sol';
import {AHV2Solution} from 'src/types/AHV2Solution.sol';

/**
 * @title GasSnapshotsTest
 * @notice Gas of each settlement and delegation path, recorded in `snapshots/`
 */
contract GasSnapshotsTest is SettlementBase {
  uint160 internal constant AMOUNT = 5 ether;

  string internal constant SETTLE_GROUP = 'settleOrder';
  string internal constant DELEGATION_GROUP = 'updateDelegation';

  address internal approver;
  uint256 internal approverKey;

  function setUp() public override {
    super.setUp();
    (approver, approverKey) = makeAddrAndKey('solution approver');
  }

  /// @dev The owner submits an order drawing on the allowance to the hub
  function test_GAS_01_ownerTransfer() public {
    AHV2Order memory order = _order(address(0), 0);
    AHV2Solution memory solution = _defaultSolution(order);
    uint256 before = _calleeBalance();

    vm.prank(owner);
    hub.settleOrder(order, '', solution, '', false);
    vm.snapshotGasLastFrame(SETTLE_GROUP, 'ownerTransfer');

    assertEq(_calleeBalance() - before, AMOUNT, 'the callee received the allowance');
  }

  /// @dev The owner submits an order drawing on the Permit2 allowance
  function test_GAS_02_ownerPermit2Allowance() public {
    AHV2Order memory order = _order(address(0), 0);
    AHV2Solution memory solution = _defaultSolution(order);
    _grantPermit2Allowance(token18, AMOUNT);
    uint256 before = _calleeBalance();

    vm.prank(owner);
    hub.settleOrder(order, '', solution, '', true);
    vm.snapshotGasLastFrame(SETTLE_GROUP, 'ownerPermit2Allowance');

    assertEq(_calleeBalance() - before, AMOUNT, 'the callee received the allowance');
  }

  /// @dev The owner submits an order on the Permit2 flow with a plain permit signature
  function test_GAS_03_ownerPermit2Signature() public {
    AHV2Order memory order = _order(permit2, 61);
    AHV2Solution memory solution = _defaultSolution(order);
    bytes memory permitSig = _signPlainPermit(order.erc20Allowances, order.nonce, order.expiration);
    uint256 before = _calleeBalance();

    vm.prank(owner);
    hub.settleOrder(order, permitSig, solution, '', false);
    vm.snapshotGasLastFrame(SETTLE_GROUP, 'ownerPermit2Signature');

    assertEq(_calleeBalance() - before, AMOUNT, 'the callee received the allowance');
  }

  /// @dev A relayer submits an order with the owner's EIP-712 order signature
  function test_GAS_04_relayedOrderSignature() public {
    AHV2Order memory order = _order(address(0), 7);
    AHV2Solution memory solution = _defaultSolution(order);
    bytes memory signature = _signOrder(order);
    uint256 before = _calleeBalance();

    vm.prank(relayer);
    hub.settleOrder(order, signature, solution, '', false);
    vm.snapshotGasLastFrame(SETTLE_GROUP, 'relayedOrderSignature');

    assertEq(_calleeBalance() - before, AMOUNT, 'the callee received the allowance');
  }

  /// @dev A relayer submits an order on the Permit2 flow with the witness signature
  function test_GAS_05_relayedPermit2Witness() public {
    AHV2Order memory order = _order(permit2, 61);
    AHV2Solution memory solution = _defaultSolution(order);
    bytes memory witnessSig = _signWitness(order);
    uint256 before = _calleeBalance();

    vm.prank(relayer);
    hub.settleOrder(order, witnessSig, solution, '', false);
    vm.snapshotGasLastFrame(SETTLE_GROUP, 'relayedPermit2Witness');

    assertEq(_calleeBalance() - before, AMOUNT, 'the callee received the allowance');
  }

  /// @dev A relayer submits an order authenticated by the delegated signer authenticator
  function test_GAS_06_relayedDelegatedAuthenticator() public {
    AHV2Order memory order = _order(address(authenticator), 7);
    AHV2Solution memory solution = _defaultSolution(order);
    bytes memory authData = _authOf(order);
    uint256 before = _calleeBalance();

    vm.prank(relayer);
    hub.settleOrder(order, authData, solution, '', false);
    vm.snapshotGasLastFrame(SETTLE_GROUP, 'relayedDelegatedAuthenticator');

    assertEq(_calleeBalance() - before, AMOUNT, 'the callee received the allowance');
  }

  /// @dev As the relayed order signature, with a solution approval from the order's approver
  function test_GAS_07_relayedOrderSignatureWithSolutionApproval() public {
    AHV2Order memory order = _ahv2Order(
      address(0),
      ANY,
      _allowances(_tokenAllowance(AMOUNT)),
      _noNfts(),
      _noHooks(),
      _noCalls(),
      approver,
      7,
      vm.getBlockTimestamp() + 1 hours
    );
    AHV2Solution memory solution = _defaultSolution(order);
    bytes memory signature = _signOrder(order);
    bytes memory approval = _signSolutionApproval(approverKey, order, solution);
    uint256 before = _calleeBalance();

    vm.prank(relayer);
    hub.settleOrder(order, signature, solution, approval, false);
    vm.snapshotGasLastFrame(SETTLE_GROUP, 'relayedOrderSignatureWithSolutionApproval');

    assertEq(_calleeBalance() - before, AMOUNT, 'the callee received the allowance');
  }

  /// @dev The owner submits an order with one ERC721 approval and one callee call
  function test_GAS_08_ownerTransferWithNftAndCall() public {
    AHV2Order memory order = _ahv2Order(
      ANY,
      _allowances(_tokenAllowance(AMOUNT)),
      _approvals(_nftApproval()),
      _noHooks(),
      _calls(_calleeCall(0, hex'01')),
      ANY,
      0,
      vm.getBlockTimestamp() + 1 hours
    );
    AHV2Solution memory solution = _defaultSolution(order);
    uint256 before = _calleeBalance();

    vm.prank(owner);
    hub.settleOrder(order, '', solution, '', false);
    vm.snapshotGasLastFrame(SETTLE_GROUP, 'ownerTransferWithNftAndCall');

    assertEq(_calleeBalance() - before, AMOUNT, 'the callee received the allowance');
    assertEq(callee.callCount(), 1, 'the call ran');
  }

  /// @dev The owner submits an order with one hook run before and after settlement
  function test_GAS_09_ownerTransferWithHooks() public {
    AHV2Order memory order = _openAhv2Order(
      _allowances(_tokenAllowance(AMOUNT)),
      _hooks(_hook(hook, HOOK_BOTH)),
      _noCalls(),
      0,
      vm.getBlockTimestamp() + 1 hours
    );
    AHV2Solution memory solution = _defaultSolution(order);
    uint256 before = _calleeBalance();

    vm.prank(owner);
    hub.settleOrder(order, '', solution, '', false);
    vm.snapshotGasLastFrame(SETTLE_GROUP, 'ownerTransferWithHooks');

    assertEq(_calleeBalance() - before, AMOUNT, 'the callee received the allowance');
    assertEq(hook.sequenceLength(), 2, 'the hook ran before and after');
  }

  /// @dev The owner delegates the signer authenticator in a call of their own
  function test_GAS_10_ownerDelegates() public {
    bytes memory data = _encodeSigner(signer);
    uint256 deadline = vm.getBlockTimestamp() + 1 days;

    vm.prank(owner);
    hub.updateDelegation(owner, address(authenticator), true, data, 0, deadline, '');
    vm.snapshotGasLastFrame(DELEGATION_GROUP, 'ownerDelegates');

    assertTrue(hub.authDelegated(owner, address(authenticator)), 'delegated');
  }

  /// @dev A relayer submits the owner's signed delegation of the signer authenticator
  function test_GAS_11_relayedDelegation() public {
    bytes memory data = _encodeSigner(signer);
    uint256 nonce = 5;
    uint256 deadline = vm.getBlockTimestamp() + 1 days;
    bytes memory signature =
      _signAuthDelegation(ownerKey, owner, address(authenticator), true, data, nonce, deadline);

    vm.prank(relayer);
    hub.updateDelegation(owner, address(authenticator), true, data, nonce, deadline, signature);
    vm.snapshotGasLastFrame(DELEGATION_GROUP, 'relayedDelegation');

    assertTrue(hub.authDelegated(owner, address(authenticator)), 'delegated');
  }

  /// @dev An order open to any submitter, with the one ERC20 allowance every scenario shares
  function _order(address orderAuthenticator, uint256 nonce)
    internal
    view
    returns (AHV2Order memory)
  {
    return _openAhv2Order(
      orderAuthenticator,
      _allowances(_tokenAllowance(AMOUNT)),
      _noHooks(),
      _noCalls(),
      nonce,
      vm.getBlockTimestamp() + 1 hours
    );
  }
}
