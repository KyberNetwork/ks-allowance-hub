// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {HookMock} from 'test/mocks/HookMock.sol';

import {SettlementBase} from 'test/settlement/base/SettlementBase.sol';

import {IKSAllowanceHubV2} from 'src/interfaces/IKSAllowanceHubV2.sol';

import {AHV2Order} from 'src/types/AHV2Order.sol';
import {AHV2Solution} from 'src/types/AHV2Solution.sol';
import {ERC20Allowance} from 'src/types/ERC20Allowance.sol';
import {HookParams} from 'src/types/HookParams.sol';

import {IAllowanceTransfer} from 'ks-common-sc/src/interfaces/IAllowanceTransfer.sol';

import {IERC20} from 'openzeppelin-contracts/contracts/token/ERC20/IERC20.sol';

/**
 * @title FlagsTest
 * @notice `FLG-01..07` — the `flags` of an order: the Permit2 transfer count and the hook bits
 * @dev A Permit2 pull lowers the owner's Permit2 allowance to the hub and leaves the owner's
 * allowance of the token to the hub unchanged, and a hub pull does the opposite. Both allowances
 * are finite here so that either change is visible.
 */
contract FlagsTest is SettlementBase {
  /// @dev Written out rather than imported: the batch overload of Permit2's `transferFrom`
  bytes4 internal constant PERMIT2_BATCH_TRANSFER_FROM =
    bytes4(keccak256('transferFrom((address,address,uint160,address)[])'));

  uint160 internal constant PERMIT2_LIMIT18 = 100 ether;
  uint160 internal constant PERMIT2_LIMIT6 = 100e6;
  uint256 internal constant HUB_LIMIT18 = 200 ether;
  uint256 internal constant HUB_LIMIT6 = 200e6;

  /// @dev Amounts of the three-entry order of {test_FLG_01_mixedSplit}
  uint160 internal constant A = 3 ether;
  uint160 internal constant B = 2e6;
  uint160 internal constant C = 4 ether;

  address internal target0 = makeAddr('target0');
  address internal target1 = makeAddr('target1');
  address internal target2 = makeAddr('target2');

  function setUp() public override {
    super.setUp();

    vm.startPrank(owner);
    IERC20(token18).approve(address(hub), HUB_LIMIT18);
    IERC20(token6).approve(address(hub), HUB_LIMIT6);
    vm.stopPrank();

    _grantPermit2Allowance(token18, PERMIT2_LIMIT18);
    _grantPermit2Allowance(token6, PERMIT2_LIMIT6);
  }

  /**
   * FLG-01 — the first entries are pulled through Permit2 in one batch, the rest from the hub
   * allowance
   * @dev Three entries (`token18`, `token6`, `token18`) with a count of 2: one Permit2 batch with
   * entries 0 and 1 in order, and entry 2 through the owner's allowance to the hub.
   */
  function test_FLG_01_mixedSplit() public {
    AHV2Order memory order = _order3(2);
    AHV2Solution memory solution = _solutionFor(order, _targets3());

    IAllowanceTransfer.AllowanceTransferDetails[] memory details =
      new IAllowanceTransfer.AllowanceTransferDetails[](2);
    details[0] = _details(token18, target0, A);
    details[1] = _details(token6, target1, B);
    vm.expectCall(permit2, abi.encodeWithSelector(PERMIT2_BATCH_TRANSFER_FROM, details), 1);

    vm.prank(owner);
    hub.settleOrder(order, '', solution, '');

    assertEq(IERC20(token18).balanceOf(target0), A, 'entry 0 reached its target');
    assertEq(IERC20(token6).balanceOf(target1), B, 'entry 1 reached its target');
    assertEq(IERC20(token18).balanceOf(target2), C, 'entry 2 reached its target');

    assertEq(_permit2Allowance(token18), PERMIT2_LIMIT18 - A, 'entry 0 drew on Permit2');
    assertEq(_permit2Allowance(token6), PERMIT2_LIMIT6 - B, 'entry 1 drew on Permit2');
    assertEq(IERC20(token18).allowance(owner, address(hub)), HUB_LIMIT18 - C, 'entry 2 via hub');
    assertEq(IERC20(token6).allowance(owner, address(hub)), HUB_LIMIT6, 'entry 1 spared the hub');
  }

  /**
   * FLG-02a — a count of 0 makes no Permit2 call
   * @dev Two entries of `token18` and `token6`, both through the owner's allowance to the hub.
   */
  function test_FLG_02a_countZeroMakesNoPermit2Call() public {
    AHV2Order memory order = _order2(0);
    AHV2Solution memory solution = _solutionFor(order, _targets3());

    vm.expectCall(permit2, abi.encodePacked(PERMIT2_BATCH_TRANSFER_FROM), 0);
    vm.prank(owner);
    hub.settleOrder(order, '', solution, '');

    assertEq(IERC20(token18).balanceOf(target0), A, 'entry 0 reached its target');
    assertEq(IERC20(token6).balanceOf(target1), B, 'entry 1 reached its target');
    assertEq(_permit2Allowance(token18), PERMIT2_LIMIT18, 'the Permit2 allowance is unchanged');
    assertEq(_permit2Allowance(token6), PERMIT2_LIMIT6, 'for token6 too');
    assertEq(IERC20(token18).allowance(owner, address(hub)), HUB_LIMIT18 - A, 'entry 0 via hub');
    assertEq(IERC20(token6).allowance(owner, address(hub)), HUB_LIMIT6 - B, 'entry 1 drew on hub');
  }

  /**
   * FLG-02b — a count equal to the number of entries pulls all of them in one Permit2 batch
   * @dev The owner's allowance to the hub is unchanged.
   */
  function test_FLG_02b_countOfAllEntriesLeavesTheHubAllowanceUntouched() public {
    AHV2Order memory order = _order2(2);
    AHV2Solution memory solution = _solutionFor(order, _targets3());

    IAllowanceTransfer.AllowanceTransferDetails[] memory details =
      new IAllowanceTransfer.AllowanceTransferDetails[](2);
    details[0] = _details(token18, target0, A);
    details[1] = _details(token6, target1, B);
    vm.expectCall(permit2, abi.encodeWithSelector(PERMIT2_BATCH_TRANSFER_FROM, details), 1);
    vm.prank(owner);
    hub.settleOrder(order, '', solution, '');

    assertEq(IERC20(token18).balanceOf(target0), A, 'entry 0 reached its target');
    assertEq(IERC20(token6).balanceOf(target1), B, 'entry 1 reached its target');
    assertEq(_permit2Allowance(token18), PERMIT2_LIMIT18 - A, 'Permit2 paid entry 0');
    assertEq(_permit2Allowance(token6), PERMIT2_LIMIT6 - B, 'Permit2 paid entry 1');
    assertEq(IERC20(token18).allowance(owner, address(hub)), HUB_LIMIT18, 'the hub allowance');
    assertEq(IERC20(token6).allowance(owner, address(hub)), HUB_LIMIT6, 'and for token6');
  }

  /**
   * FLG-03 — the Permit2 signature transfer flow ignores the count
   * @dev A relayer submits with the witness signature and a count equal to the entries. The tokens
   * move by signature transfer, and neither the owner's Permit2 allowance nor the allowance to the
   * hub changes.
   */
  function test_FLG_03_permit2SignatureFlowIgnoresTheCount() public {
    AHV2Order memory order = _order2(2);
    order.authenticator = permit2;
    order.nonce = 61;
    bytes memory witness = _signPermit2Order(order);
    AHV2Solution memory solution = _solutionFor(order, _targets3());

    vm.expectCall(permit2, abi.encodePacked(PERMIT2_BATCH_TRANSFER_FROM), 0);
    vm.prank(relayer);
    hub.settleOrder(order, witness, solution, '');

    assertEq(IERC20(token18).balanceOf(target0), A, 'entry 0 reached its target');
    assertEq(IERC20(token6).balanceOf(target1), B, 'entry 1 reached its target');
    assertEq(_permit2Allowance(token18), PERMIT2_LIMIT18, 'the Permit2 allowance is unchanged');
    assertEq(_permit2Allowance(token6), PERMIT2_LIMIT6, 'for token6 too');
    assertEq(IERC20(token18).allowance(owner, address(hub)), HUB_LIMIT18, 'the hub allowance too');
    assertEq(IERC20(token6).allowance(owner, address(hub)), HUB_LIMIT6, 'and for token6');
  }

  /**
   * FLG-03b — a count above the number of entries is refused where the count is used
   * @dev Two entries and a count of 3. The zero-authenticator owner flow reverts with nothing
   * moved. The Permit2 signature transfer flow neither uses nor checks the count, so the same order
   * settles there by signature transfer.
   */
  function test_FLG_03b_countAboveTheEntriesIsRefusedWhereUsed() public {
    AHV2Order memory order = _order2(3);
    AHV2Solution memory solution = _solutionFor(order, _targets3());

    vm.prank(owner);
    vm.expectRevert(
      abi.encodeWithSelector(IKSAllowanceHubV2.TooManyPermit2Transfers.selector, 3, 2)
    );
    hub.settleOrder(order, '', solution, '');

    assertEq(IERC20(token18).balanceOf(target0), 0, 'nothing moved of token18');
    assertEq(IERC20(token6).balanceOf(target1), 0, 'nothing moved of token6');
    assertEq(_permit2Allowance(token18), PERMIT2_LIMIT18, 'the Permit2 allowance is unchanged');
    assertEq(IERC20(token18).allowance(owner, address(hub)), HUB_LIMIT18, 'and the hub allowance');

    AHV2Order memory permit2Order = _order2(3);
    permit2Order.authenticator = permit2;
    permit2Order.nonce = 62;
    bytes memory witness = _signPermit2Order(permit2Order);
    AHV2Solution memory permit2Solution = _solutionFor(permit2Order, _targets3());

    vm.prank(relayer);
    hub.settleOrder(permit2Order, witness, permit2Solution, '');

    assertEq(IERC20(token18).balanceOf(target0), A, 'entry 0 moved by signature transfer');
    assertEq(IERC20(token6).balanceOf(target1), B, 'entry 1 moved by signature transfer');
    assertEq(
      _permit2Allowance(token18), PERMIT2_LIMIT18, 'the Permit2 allowance is still unchanged'
    );
    assertEq(IERC20(token18).allowance(owner, address(hub)), HUB_LIMIT18, 'and the hub allowance');
  }

  /**
   * FLG-04 — at most 255 ERC20 entries
   * @dev 256 entries are refused with their length, and 255 settle through the hub allowance.
   */
  function test_FLG_04_erc20EntryLimit() public {
    AHV2Order memory order = _manyEntries(256);
    AHV2Solution memory solution = _manySolution(256);

    vm.prank(owner);
    vm.expectRevert(abi.encodeWithSelector(IKSAllowanceHubV2.TooManyERC20s.selector, 256));
    hub.settleOrder(order, '', solution, '');

    assertEq(IERC20(token18).balanceOf(target0), 0, 'nothing moved');

    order = _manyEntries(255);
    solution = _manySolution(255);

    vm.prank(owner);
    hub.settleOrder(order, '', solution, '');

    assertEq(IERC20(token18).balanceOf(target0), 255, 'every entry reached the target');
    assertEq(IERC20(token18).allowance(owner, address(hub)), HUB_LIMIT18 - 255, 'through the hub');
    assertEq(_permit2Allowance(token18), PERMIT2_LIMIT18, 'and not through Permit2');
  }

  /**
   * FLG-05 — at most 64 hooks, and the bits of the last hook select its calls
   * @dev 65 hooks are refused with their length. Of 64 hooks of one mock, with the index in the
   * data of each, only bits 63 and 127 are set: one before call and one after call, both of
   * index 63.
   */
  function test_FLG_05_hookLimit() public {
    AHV2Order memory order = _openAhv2Order(
      new ERC20Allowance[](0), _manyHooks(65), _noCalls(), 0, vm.getBlockTimestamp()
    );

    vm.prank(owner);
    vm.expectRevert(abi.encodeWithSelector(IKSAllowanceHubV2.TooManyHooks.selector, 65));
    hub.settleOrder(order, '', _defaultSolution(order), '');
    assertEq(hook.sequenceLength(), 0, 'no hook ran');

    order = _openAhv2Order(
      new ERC20Allowance[](0), _manyHooks(64), _noCalls(), 0, vm.getBlockTimestamp()
    );
    order.flags = _hookFlags(63, true, true);

    vm.prank(owner);
    hub.settleOrder(order, '', _defaultSolution(order), '');

    assertEq(hook.beforeCount(), 1, 'one before call');
    assertEq(hook.afterCount(), 1, 'one after call');
    assertEq(hook.lastBeforeIndex(), 63, 'the before call has index 63');
    assertEq(hook.beforeData(), abi.encode(uint256(63)), 'the before call read entry 63');
    assertEq(hook.afterData(), abi.encode(uint256(63)), 'the after call read entry 63');
  }

  /**
   * FLG-06 — the bits of an absent hook and bits 128..247 are ignored
   * @dev One hook. Bits 1 and 65 and every bit from 128 to 247 are set and the hook receives no
   * call. With only bit 64 set it receives an after call with an empty before result although it
   * is configured to return one.
   */
  function test_FLG_06_ignoredBits() public {
    HookMock spy = new HookMock();
    spy.setBeforeResult(hex'ff');
    HookParams[] memory hooks = _hooks(_hook(spy));

    uint256 upperBits = ((uint256(1) << 120) - 1) << 128;
    _settleOwner(hooks, (1 << 1) | (1 << 65) | upperBits);

    assertEq(spy.beforeCount(), 0, 'no before call');
    assertEq(spy.afterCount(), 0, 'no after call');

    _settleOwner(hooks, 1 << 64);

    assertEq(spy.beforeCount(), 0, 'bit 64 does not select the before call');
    assertEq(spy.afterCount(), 1, 'bit 64 selects the after call');
    assertEq(spy.receivedBeforeResult(), '', 'with an empty before result');
  }

  /**
   * FLG-07 — the order hash covers the flags
   * @dev A relayer submits an order signed by the owner. With a hook bit flipped after signing the
   * signature is refused, and the order as signed settles.
   */
  function test_FLG_07_orderHashCoversTheFlags() public {
    AHV2Order memory order = _openAhv2Order(
      _allowances(_tokenAllowance(AMOUNT)),
      _hooks(_hook(hook)),
      _noCalls(),
      7,
      vm.getBlockTimestamp() + 1 hours
    );
    bytes memory signature = _signOrder(order);
    AHV2Solution memory solution = _defaultSolution(order);

    AHV2Order memory changed = _openAhv2Order(
      _allowances(_tokenAllowance(AMOUNT)),
      _hooks(_hook(hook)),
      _noCalls(),
      7,
      vm.getBlockTimestamp() + 1 hours
    );
    changed.flags ^= 1;

    vm.prank(relayer);
    vm.expectRevert(IKSAllowanceHubV2.InvalidOrderSignature.selector);
    hub.settleOrder(changed, signature, solution, '');
    assertEq(hook.sequenceLength(), 0, 'no hook ran');

    vm.prank(relayer);
    hub.settleOrder(order, signature, solution, '');
    assertEq(hook.sequenceLength(), 2, 'the order as signed settled');
  }

  /// @dev One named struct for {testFuzz_FLG_FUZZ_flagsSelectPathsAndCalls}
  struct FlagsFuzz {
    uint8 entryCount;
    uint8 numPermit2Transfers;
    uint64 beforeMask;
    uint64 afterMask;
    uint120 ignoredBits;
  }

  /**
   * FLG-FUZZ — the flags select the pull path of every entry and the calls of every hook
   * @dev One to three entries of `token18` with amounts 1, 2 and 4 ether, so the sum of the Permit2
   * allowance drawn identifies the entries that went through Permit2. Three hooks, each with its
   * own mock. The flags combine the count, the drawn ignored bits and the two masks; the masks
   * select calls only by their three lowest bits.
   */
  function testFuzz_FLG_FUZZ_flagsSelectPathsAndCalls(FlagsFuzz memory f) public {
    f.entryCount = uint8(bound(f.entryCount, 1, 3));
    f.numPermit2Transfers = uint8(bound(f.numPermit2Transfers, 0, f.entryCount));

    HookMock[3] memory mocks = [new HookMock(), new HookMock(), new HookMock()];
    HookParams[] memory hooks = new HookParams[](3);
    for (uint256 i = 0; i < 3; i++) {
      hooks[i] = _hook(mocks[i]);
    }

    ERC20Allowance[] memory allowances = new ERC20Allowance[](f.entryCount);
    address[] memory targets = new address[](f.entryCount);
    uint160[] memory amounts = new uint160[](f.entryCount);
    for (uint256 i = 0; i < f.entryCount; i++) {
      amounts[i] = uint160(1 ether) << i;
      allowances[i] = ERC20Allowance({token: token18, amount: amounts[i]});
      targets[i] = makeAddr(string.concat('fuzzTarget', vm.toString(i)));
    }

    AHV2Order memory order =
      _openAhv2Order(allowances, hooks, _noCalls(), 0, vm.getBlockTimestamp() + 1 hours);
    order.flags = (uint256(f.numPermit2Transfers) << 248) | (uint256(f.ignoredBits) << 128)
      | (uint256(f.afterMask) << 64) | uint256(f.beforeMask);
    AHV2Solution memory solution =
      _solution(targets, amounts, new address[](0), vm.getBlockTimestamp() + 1 hours);

    vm.prank(owner);
    hub.settleOrder(order, '', solution, '');

    uint256 viaPermit2;
    uint256 viaHub;
    for (uint256 i = 0; i < f.entryCount; i++) {
      assertEq(IERC20(token18).balanceOf(targets[i]), amounts[i], 'the entry reached its target');
      if (i < f.numPermit2Transfers) {
        viaPermit2 += amounts[i];
      } else {
        viaHub += amounts[i];
      }
    }
    assertEq(_permit2Allowance(token18), PERMIT2_LIMIT18 - viaPermit2, 'the leading entries drew');
    assertEq(
      IERC20(token18).allowance(owner, address(hub)), HUB_LIMIT18 - viaHub, 'the rest drew on hub'
    );

    for (uint256 i = 0; i < 3; i++) {
      assertEq(
        mocks[i].beforeCount(), uint256(f.beforeMask >> i) & 1, 'bit i selects the before call'
      );
      assertEq(
        mocks[i].afterCount(), uint256(f.afterMask >> i) & 1, 'bit 64 + i selects the after call'
      );
    }
  }

  // -------------------------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------------------------

  /// @dev The details of one Permit2 batch entry drawn from the owner
  function _details(address token, address to, uint160 amount)
    private
    view
    returns (IAllowanceTransfer.AllowanceTransferDetails memory)
  {
    return IAllowanceTransfer.AllowanceTransferDetails({
      from: owner, to: to, amount: amount, token: token
    });
  }

  /// @dev An open order of `token18` `A` and `token6` `B` with `count` Permit2 transfers
  function _order2(uint256 count) private view returns (AHV2Order memory order) {
    ERC20Allowance[] memory allowances = new ERC20Allowance[](2);
    allowances[0] = ERC20Allowance({token: token18, amount: A});
    allowances[1] = ERC20Allowance({token: token6, amount: B});
    order = _openAhv2Order(allowances, _noHooks(), _noCalls(), 0, vm.getBlockTimestamp() + 1 hours);
    _withPermit2Transfers(order, count);
  }

  /// @dev As above, with a third entry of `token18` `C`
  function _order3(uint256 count) private view returns (AHV2Order memory order) {
    ERC20Allowance[] memory allowances = new ERC20Allowance[](3);
    allowances[0] = ERC20Allowance({token: token18, amount: A});
    allowances[1] = ERC20Allowance({token: token6, amount: B});
    allowances[2] = ERC20Allowance({token: token18, amount: C});
    order = _openAhv2Order(allowances, _noHooks(), _noCalls(), 0, vm.getBlockTimestamp() + 1 hours);
    _withPermit2Transfers(order, count);
  }

  function _targets3() private view returns (address[] memory targets) {
    targets = new address[](3);
    targets[0] = target0;
    targets[1] = target1;
    targets[2] = target2;
  }

  /// @dev The solution sending the full amount of each entry of `order` to the first targets
  function _solutionFor(AHV2Order memory order, address[] memory targets)
    private
    view
    returns (AHV2Solution memory)
  {
    address[] memory used = new address[](order.erc20Allowances.length);
    uint160[] memory amounts = new uint160[](used.length);
    for (uint256 i = 0; i < used.length; i++) {
      used[i] = targets[i];
      amounts[i] = order.erc20Allowances[i].amount;
    }
    return _solution(used, amounts, new address[](0), vm.getBlockTimestamp() + 1 hours);
  }

  /// @dev An owner-submitted order of `count` entries of one unit of `token18`
  function _manyEntries(uint256 count) private view returns (AHV2Order memory) {
    ERC20Allowance[] memory allowances = new ERC20Allowance[](count);
    for (uint256 i = 0; i < count; i++) {
      allowances[i] = ERC20Allowance({token: token18, amount: 1});
    }
    return _openAhv2Order(allowances, _noHooks(), _noCalls(), 0, vm.getBlockTimestamp() + 1 hours);
  }

  /// @dev The solution of {_manyEntries}, sending every unit to `target0`
  function _manySolution(uint256 count) private view returns (AHV2Solution memory) {
    address[] memory targets = new address[](count);
    uint160[] memory amounts = new uint160[](count);
    for (uint256 i = 0; i < count; i++) {
      targets[i] = target0;
      amounts[i] = 1;
    }
    return _solution(targets, amounts, new address[](0), vm.getBlockTimestamp() + 1 hours);
  }

  /// @dev `count` entries of {hook}, the data of entry `i` being the encoding of `i`
  function _manyHooks(uint256 count) private view returns (HookParams[] memory hooks) {
    hooks = new HookParams[](count);
    for (uint256 i = 0; i < count; i++) {
      hooks[i] = _hook(hook, abi.encode(i));
    }
  }

  /// @dev Settles an owner-submitted order of `hooks` and nothing else, with the flags `flags`
  function _settleOwner(HookParams[] memory hooks, uint256 flags) private {
    AHV2Order memory order =
      _openAhv2Order(new ERC20Allowance[](0), hooks, _noCalls(), 0, vm.getBlockTimestamp());
    order.flags = flags;

    vm.prank(owner);
    hub.settleOrder(order, '', _defaultSolution(order), '');
  }
}
