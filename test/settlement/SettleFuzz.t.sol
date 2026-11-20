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
 * @notice `ORDER-FUZZ` — one successful settlement property per authorization rail
 * @dev Each property draws the order, the solution and the submitter through one struct.
 */
contract SettleFuzzTest is SettlementBase {
  // -------------------------------------------------------------------------------------------
  // ORDER-FUZZ — one property per authorization rail
  // -------------------------------------------------------------------------------------------

  /// @dev One parameter struct for the settlement fuzz tests
  struct OrderFuzz {
    uint160 amount;
    uint8 callCount;
    uint256 expirationOffset;
    uint96 msgValue;
    bool moveNft;
    bool usePermit2Allowances;
    bool pinSubmitter;
    bool approveSolution;
    uint8 rail;
    uint256 nonce;
    address erc20Target;
    address erc721Target;
  }

  /**
   * ORDER-FUZZ — a relayed order settles for any drawn order on each of the three authenticator
   * flows
   * @dev `rail % 3` selects the authenticator: the zero address, with the owner's EIP-712 signature
   * over the order spending the order nonce in the owner's namespace of the hub; the Permit2
   * address, with a witness signature spending the Permit2 nonce; or an approved signer through the
   * delegated authenticator, which spends the order nonce in its own bitmap. The call list ranges
   * over empty and non-empty. `approveSolution` switches between a specified approver with a real
   * approval and the sentinel; `usePermit2Allowances` picks the pull path of the zero and the
   * delegated rail, and the Permit2 rail ignores it; `pinSubmitter` and the nonce are covered by
   * the order hash the event reports and by the signature of the rail. The solution's targets are
   * drawn and receive the transfers, and the drawn native value is placed on the first call.
   */
  function testFuzz_ORDER_FUZZ_settleOrder(OrderFuzz memory f) public {
    uint8 rail = f.rail % 3;

    _delegateSignerThroughHub(signer);

    _boundFuzz(f);
    if (f.usePermit2Allowances) {
      _grantPermit2Allowance(token18, uint160(100 ether));
    }

    address orderAuthenticator =
      rail == 0 ? address(0) : rail == 1 ? permit2 : address(authenticator);
    (AHV2Order memory order, AHV2Solution memory solution, uint256 value) =
      _fuzzOrder(f, relayer, orderAuthenticator);
    bytes memory authData = rail == 0
      ? _signOrder(order)
      : rail == 1 ? _signPermit2Order(order) : _orderAuthData(order, signer, signerPk);
    bytes memory approval =
      f.approveSolution ? _signSolutionApproval(approverKey, order, solution) : bytes('');

    uint256 before = IERC20(token18).balanceOf(f.erc20Target);
    uint256 nativeBefore = address(callee).balance;
    uint256 permit2BitmapBefore = _permit2NonceBitmap(owner, f.nonce >> 8);
    vm.deal(relayer, value);

    vm.recordLogs();

    vm.prank(relayer);
    bytes[] memory results =
      hub.settleOrder{value: value}(order, authData, solution, approval, f.usePermit2Allowances);

    _assertFuzzSettled(f, order, results, before, nativeBefore, value);
    assertEq(
      hub.nonces(lNonceKey(approver), 0),
      f.approveSolution ? 1 : 0,
      "the approval spent solution nonce 0 of the approver's namespace, unless waived"
    );

    uint256 nonceBit = 1 << (f.nonce & 0xff);
    assertEq(
      hub.nonces(lNonceKey(owner), f.nonce >> 8),
      rail == 0 ? nonceBit : 0,
      'the hub burned the order nonce only for the zero authenticator'
    );
    assertEq(
      authenticator.nonces(lNonceKey(signer), f.nonce >> 8),
      rail == 2 ? nonceBit : 0,
      'the authenticator burned the order nonce only on its own rail'
    );
    assertEq(
      _permit2NonceBitmap(owner, f.nonce >> 8),
      rail == 1 ? permit2BitmapBefore | nonceBit : permit2BitmapBefore,
      'Permit2 burned the order nonce only on its own rail'
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
    f.callCount = uint8(bound(f.callCount, 0, 6));
    f.expirationOffset = bound(f.expirationOffset, 0, 30 days);
    f.msgValue = uint96(bound(f.msgValue, 0, 5 ether));

    vm.assume(f.erc20Target != address(0) && f.erc20Target.code.length == 0);
    vm.assume(f.erc20Target != owner);
    vm.assume(f.erc721Target != address(0) && f.erc721Target.code.length == 0);
    vm.assume(f.erc721Target != owner);
  }

  /// @dev The drawn order, authorized through `orderAuthenticator`, and solution, and the native
  /// value the submitter sends: the drawn value is placed on the first call, and is zero when
  /// there is none
  function _fuzzOrder(OrderFuzz memory f, address submitter, address orderAuthenticator)
    private
    view
    returns (AHV2Order memory order, AHV2Solution memory solution, uint256 value)
  {
    value = f.callCount == 0 ? 0 : f.msgValue;

    CallParams[] memory calls = new CallParams[](f.callCount);
    for (uint256 i = 0; i < f.callCount; i++) {
      calls[i] = CallParams({callee: address(callee), ownerData: abi.encodePacked(uint8(i))});
    }

    order = _ahv2Order(
      orderAuthenticator,
      f.pinSubmitter ? submitter : ANY,
      _allowances(_tokenAllowance(f.amount)),
      f.moveNft ? _approvals(_nftApproval()) : _noNfts(),
      _hooks(_hook(hook, HOOK_BOTH)),
      calls,
      f.approveSolution ? approver : ANY,
      f.nonce,
      vm.getBlockTimestamp() + f.expirationOffset
    );
    solution = _solution(
      _addresses(f.erc20Target),
      _amounts(f.amount),
      f.moveNft ? _addresses(f.erc721Target) : new address[](0),
      vm.getBlockTimestamp() + f.expirationOffset
    );
    solution.callValues = new uint256[](f.callCount);
    if (f.callCount > 0) {
      solution.callValues[0] = f.msgValue;
    }
    solution.solverData = _solverData(f.callCount);
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
    assertEq(results.length, f.callCount, 'one result per call');
    assertEq(callee.callCount(), f.callCount, 'every call ran');
    assertEq(hook.sequenceLength(), 2, 'the hook bracketed the order');
    if (f.moveNft) {
      assertEq(nft.ownerOf(NFT_ID), f.erc721Target, 'nft transfer to the drawn target');
    }

    Vm.Log memory entry = _settlementLog();
    assertEq(entry.topics[3], SchemaHash.ahv2Order(order), 'the event reports this exact order');
  }
}
