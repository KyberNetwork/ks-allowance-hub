// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Vm} from 'forge-std/Vm.sol';

import {SchemaHash} from 'test/base/SchemaHash.sol';

import {SettlementBase} from 'test/settlement/base/SettlementBase.sol';

import {AHV2Order} from 'src/types/AHV2Order.sol';
import {AHV2Solution} from 'src/types/AHV2Solution.sol';
import {CallParams} from 'src/types/CallParams.sol';

import {IERC20} from 'openzeppelin-contracts/contracts/token/ERC20/IERC20.sol';

/**
 * @title SettleFuzzTest
 * @notice `ORDER-FUZZ` — one successful settlement property per entry point
 * @dev Each property draws the order, the solution and the submitter through one struct.
 */
contract SettleFuzzTest is SettlementBase {
  address internal approver;
  uint256 internal approverKey;

  function setUp() public override {
    super.setUp();
    (approver, approverKey) = makeAddrAndKey('solution approver');
  }

  // -------------------------------------------------------------------------------------------
  // ORDER-FUZZ — one property per entry point
  // -------------------------------------------------------------------------------------------

  /// @dev One parameter struct for the settlement fuzz tests
  struct OrderFuzz {
    uint160 amount;
    uint8 solverCallCount;
    uint8 ownerCallCount;
    uint256 expirationOffset;
    uint96 msgValue;
    bool moveNft;
    bool usePermit2Allowances;
    bool pinSubmitter;
    bool approveSolution;
    uint256 nonce;
    address erc20Target;
    address erc721Target;
  }

  /**
   * ORDER-FUZZ — a relayed order authenticated by an approved signer settles for any drawn order
   * and spends no hub nonce
   * @dev Entry point `settleOrderWithDelegatedAuthentication`. Both call lists range over empty
   * and non-empty, and they go to different callees so each has a counter of its own.
   * `approveSolution` switches between a specified approver with a real approval and the
   * sentinel; `usePermit2Allowances` picks the pull path; `pinSubmitter` and the nonce are
   * covered by the order hash the event reports and by the authenticator's bitmap. The solution's
   * targets are drawn and receive the transfers, and the drawn native value is placed on the
   * first solver call.
   */
  function testFuzz_ORDER_FUZZ_delegatedEntryPoint(OrderFuzz memory f) public {
    _delegateSignerThroughHub(signer);

    _boundFuzz(f);
    if (f.usePermit2Allowances) {
      _grantPermit2Allowance(token18, uint160(100 ether));
    }

    (AHV2Order memory order, AHV2Solution memory route, uint256 value) = _fuzzOrder(f, relayer);
    bytes memory authData = _orderAuthData(order, signer, signerPk);
    bytes memory approval =
      f.approveSolution ? _signSolutionApproval(approverKey, order, route) : bytes('');

    uint256 before = IERC20(token18).balanceOf(f.erc20Target);
    uint256 nativeBefore = address(callee).balance;
    vm.deal(relayer, value);

    vm.recordLogs();

    vm.prank(relayer);
    bytes[] memory results = hub.settleOrderWithDelegatedAuthentication{value: value}(
      order, address(authenticator), authData, route, approval, f.usePermit2Allowances
    );

    _assertFuzzSettled(f, order, results, before, nativeBefore, value);
    assertEq(
      authenticator.nonces(lNonceKey(signer), f.nonce >> 8),
      1 << (f.nonce & 0xff),
      'the authenticator burned exactly the order nonce'
    );
    assertEq(hub.nonces(lNonceKey(owner), f.nonce >> 8), 0, 'and the hub burned none of its own');
    assertEq(
      hub.nonces(lNonceKey(approver), 0),
      f.approveSolution ? 1 : 0,
      "and the approval spent solution nonce 0 of the approver's namespace, unless waived"
    );
  }

  /**
   * ORDER-FUZZ — a relayed Permit2 order settles for any drawn order and spends its nonce
   * @dev Entry point `settleOrderWithPermit2Signature`, where the witness is the binding.
   * `pinSubmitter` is live control flow here: it decides whether the hub compares the submitter
   * against a specified exclusive caller or against the sentinel, and it changes the witness
   * either way. The Permit2 nonce is the replay oracle.
   */
  function testFuzz_ORDER_FUZZ_permit2EntryPoint(OrderFuzz memory f) public {
    _boundFuzz(f);

    (AHV2Order memory order, AHV2Solution memory route, uint256 value) = _fuzzOrder(f, solver);
    bytes memory signature = _signWitness(order);
    bytes memory approval =
      f.approveSolution ? _signSolutionApproval(approverKey, order, route) : bytes('');

    uint256 before = IERC20(token18).balanceOf(f.erc20Target);
    uint256 nativeBefore = address(callee).balance;
    uint256 bitmapBefore = _permit2NonceBitmap(owner, f.nonce >> 8);
    vm.deal(solver, value);

    vm.recordLogs();

    vm.prank(solver);
    bytes[] memory results =
      hub.settleOrderWithPermit2Signature{value: value}(order, signature, route, approval);

    _assertFuzzSettled(f, order, results, before, nativeBefore, value);
    assertEq(
      _permit2NonceBitmap(owner, f.nonce >> 8),
      bitmapBefore | (1 << (f.nonce & 0xff)),
      'Permit2 burned exactly the signed nonce'
    );
  }

  // -------------------------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------------------------

  /**
   * @dev Bounds the drawn values. The targets range over every account that can receive both
   * transfers and shows the move: non-zero, since both mocks refuse it; without code, since a
   * contract target would need an ERC-721 receiver hook; and not the owner, whose balance would
   * net to zero
   */
  function _boundFuzz(OrderFuzz memory f) private view {
    f.amount = uint160(bound(f.amount, 0, 100 ether));
    f.solverCallCount = uint8(bound(f.solverCallCount, 0, 3));
    f.ownerCallCount = uint8(bound(f.ownerCallCount, 0, 3));
    f.expirationOffset = bound(f.expirationOffset, 0, 30 days);
    f.msgValue = uint96(bound(f.msgValue, 0, 5 ether));

    vm.assume(f.erc20Target != address(0) && f.erc20Target.code.length == 0);
    vm.assume(f.erc20Target != owner);
    vm.assume(f.erc721Target != address(0) && f.erc721Target.code.length == 0);
    vm.assume(f.erc721Target != owner);
  }

  /// @dev The drawn order and solution, and the native value the submitter sends: the drawn
  /// value goes to the first solver call, and is zero when there is none
  function _fuzzOrder(OrderFuzz memory f, address submitter)
    private
    view
    returns (AHV2Order memory order, AHV2Solution memory route, uint256 value)
  {
    value = f.solverCallCount == 0 ? 0 : f.msgValue;

    CallParams[] memory solverCalls = new CallParams[](f.solverCallCount);
    for (uint256 i = 0; i < f.solverCallCount; i++) {
      solverCalls[i] = _calleeCall(i == 0 ? f.msgValue : 0, abi.encodePacked(uint8(i)));
    }

    // the owner calls go to the second callee, so each list has a counter of its own
    CallParams[] memory ownerCalls = new CallParams[](f.ownerCallCount);
    for (uint256 i = 0; i < f.ownerCallCount; i++) {
      ownerCalls[i] =
        CallParams({callee: address(callee2), value: 0, data: abi.encodePacked(uint8(i))});
    }

    order = _ahv2Order(
      f.pinSubmitter ? submitter : ANY,
      _allowances(_tokenAllowance(f.amount)),
      f.moveNft ? _approvals(_nftApproval()) : _noNfts(),
      _hooks(_hook(hook, HOOK_BOTH)),
      ownerCalls,
      f.approveSolution ? approver : ANY,
      f.nonce,
      vm.getBlockTimestamp() + f.expirationOffset
    );
    route = _solution(
      _addresses(f.erc20Target),
      _amounts(f.amount),
      f.moveNft ? _addresses(f.erc721Target) : new address[](0),
      solverCalls,
      vm.getBlockTimestamp() + f.expirationOffset
    );
    route.solverData = _solverData(f.ownerCallCount);
  }

  function _assertFuzzSettled(
    OrderFuzz memory f,
    AHV2Order memory order,
    bytes[] memory results,
    uint256 targetBefore,
    uint256 nativeBefore,
    uint256 value
  ) private view {
    assertEq(
      IERC20(token18).balanceOf(f.erc20Target) - targetBefore,
      f.amount,
      'exact amount moved to the drawn target'
    );
    assertEq(address(callee).balance - nativeBefore, value, 'native forwarded, none stranded');
    assertEq(results.length, uint256(f.solverCallCount) + f.ownerCallCount, 'one result per call');
    assertEq(callee.callCount(), f.solverCallCount, 'the solver list ran here');
    assertEq(callee2.callCount(), f.ownerCallCount, 'and the owner calls there');
    assertEq(hook.sequenceLength(), 2, 'the hook bracketed the order');
    if (f.moveNft) {
      assertEq(nft.ownerOf(NFT_ID), f.erc721Target, 'nft transfer to the drawn target');
    }

    Vm.Log memory entry = _settlementLog();
    assertEq(entry.topics[3], SchemaHash.ahv2Order(order), 'the event reports this exact order');
  }
}
