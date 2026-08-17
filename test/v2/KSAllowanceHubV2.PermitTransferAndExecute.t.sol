// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {KSAllowanceHubV2Base} from './base/KSAllowanceHubV2Base.sol';

import {ArrayHelper} from '../libraries/ArrayHelper.sol';

import {NativeRejectorMock} from '../mocks/ReceiverMocks.sol';
import {GenericRouterMock} from '../mocks/RouterMocks.sol';

import {IKSAllowanceHubV2} from 'src/interfaces/IKSAllowanceHubV2.sol';

import {ERC20Params} from 'src/types/ERC20Params.sol';
import {ERC20Transfer} from 'src/types/ERC20Transfer.sol';
import {ERC721Params} from 'src/types/ERC721Params.sol';
import {ERC721Transfer} from 'src/types/ERC721Transfer.sol';
import {GenericCall} from 'src/types/GenericCall.sol';
import {NativeTransfer} from 'src/types/NativeTransfer.sol';

import {ICommon} from 'ks-common-sc/src/interfaces/ICommon.sol';
import {CustomRevert} from 'ks-common-sc/src/libraries/CustomRevert.sol';
import {TokenHelper} from 'ks-common-sc/src/libraries/token/TokenHelper.sol';

import {IAccessControl} from 'openzeppelin-contracts/contracts/access/IAccessControl.sol';
import {IERC20} from 'openzeppelin-contracts/contracts/interfaces/IERC20.sol';
import {IERC20Errors} from 'openzeppelin-contracts/contracts/interfaces/draft-IERC6093.sol';
import {Pausable} from 'openzeppelin-contracts/contracts/utils/Pausable.sol';

import {Vm} from 'forge-std/Test.sol';

/**
 * @notice Batch A — `KSAllowanceHubV2.permitTransferAndExecute`
 * @dev Covers PTE-01..PTE-30 of the frozen plan. Tokens on this entrypoint are always pulled from
 * `msg.sender`, so `owner` is both the signer and the caller throughout.
 */
contract KSAllowanceHubV2PermitTransferAndExecuteTest is KSAllowanceHubV2Base {
  using ArrayHelper for *;

  /// @dev Fuzz inputs for PTE-26; one ABI-encodable struct, every field bounded before use
  struct ConservationFuzz {
    uint96 amountA;
    uint96 amountB;
    uint96 msgValue;
    uint8 targetCount;
  }

  /// @dev `Transfer(address,address,uint256)`, the ERC20 event PTE-25 proves is never emitted
  bytes32 internal constant ERC20_TRANSFER_TOPIC = keccak256('Transfer(address,address,uint256)');

  /* ------------------------------------------------------------- PTE-01 */

  /// @notice PTE-01 one ERC20, one target, pre-existing allowance
  function test_singleTokenSingleTarget_movesExactAmount() public {
    uint256 amount = 4 ether;
    _fundERC20(tokenA, owner, 10 ether);
    _approveHub(tokenA, owner, 10 ether);

    uint256 ownerBefore = tokenA.balanceOf(owner);
    uint256 targetBefore = tokenA.balanceOf(address(routerA));

    ERC20Params[] memory erc20Params = _erc20ParamsArray(
      _erc20Params(
        address(tokenA), [address(routerA)].toMemoryArray(), [amount].toMemoryArray(), ''
      )
    );

    vm.prank(owner);
    hub.permitTransferAndExecute(erc20Params, _noErc721Params(), _noGenericCalls());

    assertEq(tokenA.balanceOf(address(routerA)), targetBefore + amount, 'target credited');
    assertEq(tokenA.balanceOf(owner), ownerBefore - amount, 'owner debited');
    assertEq(tokenA.balanceOf(address(hub)), 0, 'hub keeps nothing');
    assertEq(tokenA.allowance(owner, address(hub)), 10 ether - amount, 'allowance consumed');
  }

  /* ------------------------------------------------------------- PTE-02 */

  /// @notice PTE-02 one ERC20 fanned out to three targets with distinct amounts
  function test_singleTokenFannedToThreeTargets_creditsEachExactly() public {
    _fundERC20(tokenA, owner, 10 ether);
    _approveHub(tokenA, owner, 10 ether);

    address[] memory targets = [address(routerA), address(routerB), recipient].toMemoryArray();
    uint256[] memory amounts =
      [uint256(1 ether), uint256(2 ether), uint256(3 ether)].toMemoryArray();

    ERC20Params[] memory erc20Params =
      _erc20ParamsArray(_erc20Params(address(tokenA), targets, amounts, ''));

    vm.prank(owner);
    hub.permitTransferAndExecute(erc20Params, _noErc721Params(), _noGenericCalls());

    assertEq(tokenA.balanceOf(address(routerA)), 1 ether, 'first target');
    assertEq(tokenA.balanceOf(address(routerB)), 2 ether, 'second target');
    assertEq(tokenA.balanceOf(recipient), 3 ether, 'third target');
    assertEq(tokenA.balanceOf(owner), 4 ether, 'owner debited by the sum');
    assertEq(tokenA.allowance(owner, address(hub)), 4 ether, 'allowance consumed by the sum');
  }

  /* ------------------------------------------------------------- PTE-03 */

  /// @notice PTE-03 two `ERC20Params` entries flatten param-major then target-major
  function test_twoParamsEntries_flattenParamMajorThenTargetMajor() public {
    _fundERC20(tokenA, owner, 10 ether);
    _approveHub(tokenA, owner, 10 ether);
    _fundERC20(tokenB, owner, 10 ether);
    _approveHub(tokenB, owner, 10 ether);

    ERC20Params[] memory erc20Params = _erc20ParamsArray(
      _erc20Params(
        address(tokenA),
        [address(routerA), address(routerB)].toMemoryArray(),
        [uint256(1 ether), uint256(2 ether)].toMemoryArray(),
        ''
      ),
      _erc20Params(
        address(tokenB), [recipient].toMemoryArray(), [uint256(3 ether)].toMemoryArray(), ''
      )
    );

    vm.recordLogs();
    vm.prank(owner);
    hub.permitTransferAndExecute(erc20Params, _noErc721Params(), _noGenericCalls());

    (,,, ERC20Transfer[] memory erc20Transfers,,) = _readTransferTokens(vm.getRecordedLogs());

    assertEq(erc20Transfers.length, 3, 'one movement per target');

    assertEq(erc20Transfers[0].token, address(tokenA), '[0] token');
    assertEq(erc20Transfers[0].target, address(routerA), '[0] target');
    assertEq(erc20Transfers[0].amount, 1 ether, '[0] amount');

    assertEq(erc20Transfers[1].token, address(tokenA), '[1] token');
    assertEq(erc20Transfers[1].target, address(routerB), '[1] target');
    assertEq(erc20Transfers[1].amount, 2 ether, '[1] amount');

    assertEq(erc20Transfers[2].token, address(tokenB), '[2] token');
    assertEq(erc20Transfers[2].target, recipient, '[2] target');
    assertEq(erc20Transfers[2].amount, 3 ether, '[2] amount');

    assertEq(tokenA.balanceOf(address(routerA)), 1 ether, 'routerA funded');
    assertEq(tokenA.balanceOf(address(routerB)), 2 ether, 'routerB funded');
    assertEq(tokenB.balanceOf(recipient), 3 ether, 'recipient funded');
  }

  /* ------------------------------------------------------------- PTE-04 */

  /// @notice PTE-04 both native sentinels are honoured, in one execution
  function test_bothNativeSentinels_payOutOfMsgValue() public {
    assertTrue(NATIVE != address(0), 'the two sentinels are distinct addresses');
    assertEq(recipient.balance, 0, 'recipient starts empty');
    assertEq(outsider.balance, 0, 'outsider starts empty');

    ERC20Params[] memory erc20Params = _erc20ParamsArray(
      _erc20Params(NATIVE, [recipient].toMemoryArray(), [uint256(1 ether)].toMemoryArray(), ''),
      _erc20Params(address(0), [outsider].toMemoryArray(), [uint256(2 ether)].toMemoryArray(), '')
    );

    vm.deal(owner, 3 ether);
    vm.prank(owner);
    hub.permitTransferAndExecute{value: 3 ether}(erc20Params, _noErc721Params(), _noGenericCalls());

    assertEq(recipient.balance, 1 ether, 'NATIVE_ADDRESS sentinel paid out');
    assertEq(outsider.balance, 2 ether, 'address(0) sentinel paid out');
    assertEq(address(hub).balance, 0, 'msg.value fully forwarded');
  }

  /* ------------------------------------------------------------- PTE-06 */

  /// @notice PTE-06 a valid 160-byte EIP-2612 payload establishes the allowance on the fly
  function test_erc2612PermitData_establishesAllowance() public {
    _fundERC20(tokenA, owner, 10 ether);

    assertEq(tokenA.allowance(owner, address(hub)), 0, 'no allowance beforehand');
    assertEq(tokenA.nonces(owner), 0, 'permit nonce unused beforehand');

    bytes memory permitData = _erc20PermitData(ownerWallet, tokenA, 6 ether, DEFAULT_DEADLINE);
    assertEq(permitData.length, 160, 'five-word EIP-2612 payload');

    ERC20Params[] memory erc20Params = _erc20ParamsArray(
      _erc20Params(
        address(tokenA),
        [address(routerA)].toMemoryArray(),
        [uint256(4 ether)].toMemoryArray(),
        permitData
      )
    );

    vm.prank(owner);
    hub.permitTransferAndExecute(erc20Params, _noErc721Params(), _noGenericCalls());

    assertEq(tokenA.balanceOf(address(routerA)), 4 ether, 'target funded without a prior approve');
    assertEq(tokenA.allowance(owner, address(hub)), 2 ether, 'permit granted 6, transfer spent 4');
    assertEq(tokenA.nonces(owner), 1, 'permit nonce consumed exactly once');
  }

  /* ------------------------------------------------------------- PTE-07 */

  /// @notice PTE-07 empty and malformed ERC20 permitData both fall through to the prior approve
  function test_emptyAndMalformedPermitData_fallThroughToPriorApproval() public {
    _fundERC20(tokenA, owner, 10 ether);
    _approveHub(tokenA, owner, 10 ether);
    _fundERC20(tokenB, owner, 10 ether);
    _approveHub(tokenB, owner, 10 ether);

    // Three words: neither the 5-word EIP-2612 shape nor the 6-word DAI shape, so a silent no-op
    bytes memory malformed = new bytes(96);
    assertEq(malformed.length, 96, 'malformed payload has an unhandled length');

    ERC20Params[] memory erc20Params = _erc20ParamsArray(
      _erc20Params(
        address(tokenA), [address(routerA)].toMemoryArray(), [uint256(1 ether)].toMemoryArray(), ''
      ),
      _erc20Params(
        address(tokenB),
        [address(routerB)].toMemoryArray(),
        [uint256(2 ether)].toMemoryArray(),
        malformed
      )
    );

    vm.prank(owner);
    hub.permitTransferAndExecute(erc20Params, _noErc721Params(), _noGenericCalls());

    assertEq(tokenA.balanceOf(address(routerA)), 1 ether, 'empty payload still transferred');
    assertEq(tokenB.balanceOf(address(routerB)), 2 ether, 'malformed payload still transferred');
    assertEq(tokenA.allowance(owner, address(hub)), 9 ether, 'tokenA spent the prior allowance');
    assertEq(tokenB.allowance(owner, address(hub)), 8 ether, 'tokenB spent the prior allowance');
    assertEq(tokenA.nonces(owner), 0, 'no permit ran for the empty payload');
    assertEq(tokenB.nonces(owner), 0, 'no permit ran for the malformed payload');
  }

  /* ------------------------------------------------------------- PTE-09 */

  /// @notice PTE-09 a well-shaped but wrongly signed permit is swallowed, then the transfer fails
  function test_badPermitSignature_isSwallowedThenTransferFails() public {
    _fundERC20(tokenA, owner, 10 ether);

    // Signed by a different wallet, so the token recovers a signer that is not the permit owner
    bytes memory badPermit = _erc20PermitData(otherWallet, tokenA, 6 ether, DEFAULT_DEADLINE);
    assertEq(badPermit.length, 160, 'still the five-word EIP-2612 shape');

    ERC20Params[] memory erc20Params = _erc20ParamsArray(
      _erc20Params(
        address(tokenA),
        [address(routerA)].toMemoryArray(),
        [uint256(4 ether)].toMemoryArray(),
        badPermit
      )
    );

    bytes memory reason = abi.encodeWithSelector(
      IERC20Errors.ERC20InsufficientAllowance.selector, address(hub), uint256(0), uint256(4 ether)
    );

    vm.prank(owner);
    // The permit revert never surfaces: what bubbles is the later `transferFrom` failure
    vm.expectRevert(
      abi.encodeWithSelector(
        CustomRevert.WrappedError.selector,
        address(tokenA),
        IERC20.transferFrom.selector,
        reason,
        abi.encodePacked(TokenHelper.ERC20TransferFailed.selector)
      )
    );
    hub.permitTransferAndExecute(erc20Params, _noErc721Params(), _noGenericCalls());

    assertEq(tokenA.allowance(owner, address(hub)), 0, 'no allowance was established');
    assertEq(tokenA.balanceOf(address(routerA)), 0, 'nothing moved');
  }

  /* ------------------------------------------------------------- PTE-10 */

  /// @notice PTE-10 a 128-byte v3 ERC721 permit approves the hub and the token moves
  function test_erc721PermitV3_movesToken() public {
    nft.mint(owner, 1);

    bytes memory permitData = _erc721PermitData(ownerWallet, nft, 1, DEFAULT_DEADLINE);
    assertEq(permitData.length, 128, 'four-word v3 payload');
    assertEq(nft.nonces(1), 0, 'permit nonce unused beforehand');
    assertFalse(nft.isApprovedForAll(owner, address(hub)), 'no standing operator approval');

    ERC721Params[] memory erc721Params =
      _erc721ParamsArray(_erc721Params(address(nft), 1, recipient, permitData));

    vm.prank(owner);
    hub.permitTransferAndExecute(_noErc20Params(), erc721Params, _noGenericCalls());

    assertEq(nft.ownerOf(1), recipient, 'token delivered to the target');
    assertEq(nft.nonces(1), 1, 'permit nonce consumed exactly once');
  }

  /* ------------------------------------------------------------- PTE-11 */

  /// @notice PTE-11 a swallowed permit and an absent permit both fall back on `setApprovalForAll`
  function test_erc721PermitNoOpBranches_fallBackOnOperatorApproval() public {
    plainNft.mint(owner, 7);
    nft.mint(owner, 8);

    vm.startPrank(owner);
    plainNft.setApprovalForAll(address(hub), true);
    nft.setApprovalForAll(address(hub), true);
    vm.stopPrank();

    // Correctly shaped for the 4-word branch, but the collection has no permit entrypoint at all,
    // so the call reverts inside `callERC721Permit`'s try/catch and is swallowed
    bytes memory shapedButUnsupported =
      abi.encode(uint256(DEFAULT_DEADLINE), uint256(27), bytes32(uint256(1)), bytes32(uint256(2)));
    assertEq(shapedButUnsupported.length, 128, 'four-word payload against a permit-less token');

    ERC721Params[] memory erc721Params = _erc721ParamsArray(
      _erc721Params(address(plainNft), 7, recipient, shapedButUnsupported),
      _erc721Params(address(nft), 8, recipient, '')
    );

    vm.prank(owner);
    hub.permitTransferAndExecute(_noErc20Params(), erc721Params, _noGenericCalls());

    assertEq(plainNft.ownerOf(7), recipient, 'swallowed permit still transferred');
    assertEq(nft.ownerOf(8), recipient, 'absent permit still transferred');
    assertEq(nft.nonces(8), 0, 'no permit was consumed');
    assertTrue(nft.isApprovedForAll(owner, address(hub)), 'the operator approval was the authority');
  }

  /* ------------------------------------------------------------- PTE-13 */

  /// @notice PTE-13 `targets.length != amounts.length` is rejected
  function test_mismatchedTargetsAndAmounts_reverts() public {
    _fundERC20(tokenA, owner, 10 ether);
    _approveHub(tokenA, owner, 10 ether);

    ERC20Params[] memory erc20Params = _erc20ParamsArray(
      _erc20Params(
        address(tokenA),
        [address(routerA)].toMemoryArray(),
        [uint256(1 ether), uint256(2 ether)].toMemoryArray(),
        ''
      )
    );

    vm.prank(owner);
    vm.expectRevert(ICommon.MismatchedArrayLengths.selector);
    hub.permitTransferAndExecute(erc20Params, _noErc721Params(), _noGenericCalls());

    assertEq(tokenA.balanceOf(address(routerA)), 0, 'nothing moved');
  }

  /* ------------------------------------------------------------- PTE-14 */

  /// @notice PTE-14 the exact `TransferTokens` payload, including native-call filtering
  function test_transferTokensPayload_isExact() public {
    _fundERC20(tokenA, owner, 10 ether);
    _approveHub(tokenA, owner, 10 ether);
    _fundERC20(tokenB, owner, 10 ether);
    _approveHub(tokenB, owner, 10 ether);
    nft.mint(owner, 5);
    vm.prank(owner);
    nft.setApprovalForAll(address(hub), true);

    ERC20Params[] memory erc20Params = _erc20ParamsArray(
      _erc20Params(
        address(tokenA),
        [address(routerA), address(routerB)].toMemoryArray(),
        [uint256(1 ether), uint256(2 ether)].toMemoryArray(),
        ''
      ),
      _erc20Params(
        address(tokenB), [recipient].toMemoryArray(), [uint256(3 ether)].toMemoryArray(), ''
      )
    );

    ERC721Params[] memory erc721Params =
      _erc721ParamsArray(_erc721Params(address(nft), 5, recipient, ''));

    GenericCall[] memory genericCalls = new GenericCall[](3);
    genericCalls[0] = _genericCall(address(routerA), 0, hex'a1');
    genericCalls[1] = _genericCall(address(routerB), 1 ether, hex'b2');
    genericCalls[2] = _genericCall(address(routerA), 2 ether, hex'c3');

    ERC20Transfer[] memory expected20 = new ERC20Transfer[](3);
    expected20[0] = ERC20Transfer(address(tokenA), address(routerA), 1 ether);
    expected20[1] = ERC20Transfer(address(tokenA), address(routerB), 2 ether);
    expected20[2] = ERC20Transfer(address(tokenB), recipient, 3 ether);

    ERC721Transfer[] memory expected721 = new ERC721Transfer[](1);
    expected721[0] = ERC721Transfer(address(nft), 5, recipient);

    // Only the two value-bearing calls are reported, in call order
    NativeTransfer[] memory expectedNative = new NativeTransfer[](2);
    expectedNative[0] = NativeTransfer(address(routerB), 1 ether);
    expectedNative[1] = NativeTransfer(address(routerA), 2 ether);

    vm.deal(owner, 3 ether);
    vm.expectEmit(true, true, false, true, address(hub));
    emit TransferTokens(owner, owner, 3 ether, expected20, expected721, expectedNative);

    vm.prank(owner);
    hub.permitTransferAndExecute{value: 3 ether}(erc20Params, erc721Params, genericCalls);
  }

  /* ------------------------------------------------------------- PTE-15 */

  /// @notice PTE-15 `results` mirrors each router's configured return data, in call order
  function test_results_matchRouterReturnDataInOrder() public {
    routerA.setReturnData(hex'deadbeef');
    routerB.setReturnData(hex'c0ffee');

    GenericCall[] memory genericCalls = _genericCallArray(
      _genericCall(address(routerB), 0, hex'1111'), _genericCall(address(routerA), 0, hex'2222')
    );

    vm.prank(owner);
    (bytes[] memory results,) =
      hub.permitTransferAndExecute(_noErc20Params(), _noErc721Params(), genericCalls);

    assertEq(results.length, 2, 'one result per call');
    assertEq(results[0], hex'c0ffee', 'first result is routerB');
    assertEq(results[1], hex'deadbeef', 'second result is routerA');
    assertEq(routerB.callAt(0).data, hex'1111', 'routerB received its own payload');
    assertEq(routerA.callAt(0).data, hex'2222', 'routerA received its own payload');
  }

  /* ------------------------------------------------------------- PTE-16 */

  /// @notice PTE-16 the router reads the token owner back through `msgSender()`
  function test_routerObservesMsgSender() public {
    GenericCall[] memory genericCalls =
      _genericCallArray(_genericCall(address(routerA), 0, hex'01'));

    vm.prank(owner);
    hub.permitTransferAndExecute(_noErc20Params(), _noErc721Params(), genericCalls);

    assertEq(routerA.callCount(), 1, 'router called once');
    assertEq(routerA.callAt(0).observedMsgSender, owner, 'msgSender() is the token owner');
    assertEq(routerA.callAt(0).caller, address(hub), 'the hub is the router msg.sender');
  }

  /* ------------------------------------------------------------- PTE-17 */

  /// @notice PTE-17 `gasUsed` is non-zero and bounded by the gas available at the call site
  function test_gasUsed_isPositiveAndBoundedByAvailableGas() public {
    _fundERC20(tokenA, owner, 10 ether);
    _approveHub(tokenA, owner, 10 ether);

    ERC20Params[] memory erc20Params = _erc20ParamsArray(
      _erc20Params(
        address(tokenA), [address(routerA)].toMemoryArray(), [uint256(1 ether)].toMemoryArray(), ''
      )
    );
    GenericCall[] memory genericCalls =
      _genericCallArray(_genericCall(address(routerA), 0, hex'01'));

    vm.prank(owner);
    uint256 gasAtCallSite = gasleft();
    (, uint256 gasUsed) = hub.permitTransferAndExecute(erc20Params, _noErc721Params(), genericCalls);

    assertGt(gasUsed, 0, 'the body consumed gas');
    assertLt(gasUsed, gasAtCallSite, 'the body cannot consume more than was available');
  }

  /* ------------------------------------------------------------- PTE-18 */

  /// @notice PTE-18 a paused hub rejects the entrypoint
  function test_paused_reverts() public {
    vm.prank(guardian);
    hub.pause();

    vm.prank(owner);
    vm.expectRevert(Pausable.EnforcedPause.selector);
    hub.permitTransferAndExecute(_noErc20Params(), _noErc721Params(), _noGenericCalls());
  }

  /* ------------------------------------------------------------- PTE-19 */

  /// @notice PTE-19 spending more native token than `msg.value` is rejected
  function test_genericCallValueAboveMsgValue_reverts() public {
    vm.deal(address(hub), 5 ether);
    vm.deal(owner, 1 ether);

    GenericCall[] memory genericCalls =
      _genericCallArray(_genericCall(address(routerA), 2 ether, hex'01'));

    vm.prank(owner);
    vm.expectRevert(IKSAllowanceHubV2.NativeTokenOverspent.selector);
    hub.permitTransferAndExecute{value: 1 ether}(_noErc20Params(), _noErc721Params(), genericCalls);

    assertEq(address(hub).balance, 5 ether, 'the pre-existing balance is untouched');
    assertEq(address(routerA).balance, 0, 'the router kept nothing');
  }

  /* ------------------------------------------------------------- PTE-20 */

  /// @notice PTE-20 spending exactly `msg.value` is the accepted boundary
  function test_genericCallValuesEqualMsgValue_succeeds() public {
    vm.deal(address(hub), 5 ether);
    vm.deal(owner, 3 ether);

    GenericCall[] memory genericCalls = _genericCallArray(
      _genericCall(address(routerA), 1 ether, hex'01'),
      _genericCall(address(routerB), 2 ether, hex'02')
    );

    vm.prank(owner);
    hub.permitTransferAndExecute{value: 3 ether}(_noErc20Params(), _noErc721Params(), genericCalls);

    assertEq(address(routerA).balance, 1 ether, 'first call funded');
    assertEq(address(routerB).balance, 2 ether, 'second call funded');
    assertEq(address(hub).balance, 5 ether, 'the pre-existing balance is untouched');
  }

  /* ------------------------------------------------------------- PTE-21 */

  /// @notice PTE-21 a router without `WHITELIST_ROUTER_ROLE` cannot be called
  function test_nonWhitelistedRouter_reverts() public {
    GenericCall[] memory genericCalls =
      _genericCallArray(_genericCall(address(unlistedRouter), 0, hex'01'));

    assertFalse(
      hub.hasRole(WHITELIST_ROUTER_ROLE, address(unlistedRouter)), 'router is not whitelisted'
    );

    vm.prank(owner);
    vm.expectRevert(
      abi.encodeWithSelector(
        IAccessControl.AccessControlUnauthorizedAccount.selector,
        address(unlistedRouter),
        WHITELIST_ROUTER_ROLE
      )
    );
    hub.permitTransferAndExecute(_noErc20Params(), _noErc721Params(), genericCalls);

    assertEq(unlistedRouter.callCount(), 0, 'the router was never reached');
  }

  /* ------------------------------------------------------------- PTE-22 */

  /// @notice PTE-22 a reverting router bubbles its own error up unchanged
  function test_routerRevert_bubblesUp() public {
    routerA.setShouldRevert(true);

    GenericCall[] memory genericCalls =
      _genericCallArray(_genericCall(address(routerA), 0, hex'01'));

    vm.prank(owner);
    vm.expectRevert(GenericRouterMock.RouterFailed.selector);
    hub.permitTransferAndExecute(_noErc20Params(), _noErc721Params(), genericCalls);
  }

  /* ------------------------------------------------------------- PTE-23 */

  /// @notice PTE-23 a router reentering the entrypoint hits the transient lock
  function test_reentrantRouter_reverts() public {
    reentrantRouter.setReentrantCalldata(_emptyEntrypointCalldata(), false);

    GenericCall[] memory genericCalls =
      _genericCallArray(_genericCall(address(reentrantRouter), 0, hex'01'));

    vm.prank(owner);
    vm.expectRevert(IKSAllowanceHubV2.AlreadyLocked.selector);
    hub.permitTransferAndExecute(_noErc20Params(), _noErc721Params(), genericCalls);
  }

  /* ------------------------------------------------------------- PTE-24 */

  /// @notice PTE-24 an entirely empty call still succeeds and reports empty arrays
  function test_allArraysEmpty_succeeds() public {
    vm.expectEmit(true, true, false, true, address(hub));
    emit TransferTokens(
      owner, owner, 0, new ERC20Transfer[](0), new ERC721Transfer[](0), new NativeTransfer[](0)
    );

    vm.prank(owner);
    (bytes[] memory results,) =
      hub.permitTransferAndExecute(_noErc20Params(), _noErc721Params(), _noGenericCalls());

    assertEq(results.length, 0, 'no results');
  }

  /* ------------------------------------------------------------- PTE-25 */

  /// @notice PTE-25 a zero amount short-circuits in `TokenHelper` but is still reported
  function test_zeroAmount_skipsTransferButIsStillReported() public {
    _fundERC20(tokenA, owner, 10 ether);
    _approveHub(tokenA, owner, 10 ether);

    ERC20Params[] memory erc20Params = _erc20ParamsArray(
      _erc20Params(
        address(tokenA), [address(routerA)].toMemoryArray(), [uint256(0)].toMemoryArray(), ''
      )
    );

    vm.recordLogs();
    vm.prank(owner);
    hub.permitTransferAndExecute(erc20Params, _noErc721Params(), _noGenericCalls());

    Vm.Log[] memory logs = vm.getRecordedLogs();

    for (uint256 i = 0; i < logs.length; i++) {
      if (logs[i].emitter != address(tokenA)) continue;
      if (logs[i].topics.length == 0) continue;
      assertTrue(logs[i].topics[0] != ERC20_TRANSFER_TOPIC, 'no ERC20 Transfer was emitted');
    }

    (,,, ERC20Transfer[] memory erc20Transfers,,) = _readTransferTokens(logs);
    assertEq(erc20Transfers.length, 1, 'the entry is still reported');
    assertEq(erc20Transfers[0].token, address(tokenA), 'reported token');
    assertEq(erc20Transfers[0].target, address(routerA), 'reported target');
    assertEq(erc20Transfers[0].amount, 0, 'reported amount');

    assertEq(tokenA.allowance(owner, address(hub)), 10 ether, '`transferFrom` never ran');
    assertEq(tokenA.balanceOf(owner), 10 ether, 'owner untouched');
    assertEq(tokenA.balanceOf(address(routerA)), 0, 'target untouched');
  }

  /* ------------------------------------------------------------- PTE-26 */

  /// @notice PTE-26 ERC20 conservation, and the hub stranding whatever `msg.value` is left over
  function testFuzz_conservationAndStrandedNative(ConservationFuzz memory f) public {
    uint256 amountA = bound(uint256(f.amountA), 1, 1e30);
    uint256 amountB = bound(uint256(f.amountB), 1, 1e30);
    uint256 msgValue = bound(uint256(f.msgValue), 0, 100 ether);
    uint256 targetCount = bound(uint256(f.targetCount), 1, 4);

    address[] memory targets = new address[](targetCount);
    uint256[] memory amounts = new uint256[](targetCount);
    uint256 totalA = 0;
    for (uint256 i = 0; i < targetCount; i++) {
      targets[i] = address(uint160(0xA0000 + i));
      // Distinct per-target amounts, so the sum is not a multiple of a single figure
      amounts[i] = amountA + i;
      totalA += amounts[i];
    }
    address targetB = address(uint160(0xB0000));

    _fundERC20(tokenA, owner, totalA);
    _approveHub(tokenA, owner, totalA);
    _fundERC20(tokenB, owner, amountB);
    _approveHub(tokenB, owner, amountB);

    ERC20Params[] memory erc20Params = _erc20ParamsArray(
      _erc20Params(address(tokenA), targets, amounts, ''),
      _erc20Params(address(tokenB), [targetB].toMemoryArray(), [amountB].toMemoryArray(), '')
    );

    // Spends only part of `msg.value`, so the remainder has to stay in the hub
    uint256 spend = msgValue / 2;
    GenericCall[] memory genericCalls =
      _genericCallArray(_genericCall(address(routerA), spend, hex'01'));

    vm.deal(address(hub), 1 ether);
    vm.deal(owner, msgValue);

    uint256 hubNativeBefore = address(hub).balance;
    uint256 ownerABefore = tokenA.balanceOf(owner);
    uint256 ownerBBefore = tokenB.balanceOf(owner);

    vm.prank(owner);
    hub.permitTransferAndExecute{value: msgValue}(erc20Params, _noErc721Params(), genericCalls);

    // (a) every unit the owner lost landed on a target
    uint256 sumTargetDeltaA = 0;
    for (uint256 i = 0; i < targetCount; i++) {
      sumTargetDeltaA += tokenA.balanceOf(targets[i]);
    }
    assertEq(sumTargetDeltaA, ownerABefore - tokenA.balanceOf(owner), 'tokenA conserved');
    assertEq(tokenB.balanceOf(targetB), ownerBBefore - tokenB.balanceOf(owner), 'tokenB conserved');
    assertEq(tokenA.balanceOf(address(hub)), 0, 'hub holds no tokenA');
    assertEq(tokenB.balanceOf(address(hub)), 0, 'hub holds no tokenB');

    // (b) the hub has no refund path, so unspent `msg.value` is stranded rather than returned
    assertEq(
      address(hub).balance, hubNativeBefore + msgValue - spend, 'unspent msg.value is stranded'
    );
    assertEq(address(routerA).balance, spend, 'the call received its value');
  }

  /* ------------------------------------------------------------- PTE-27 */

  /// @notice PTE-27 a 224-byte v4 ERC721 permit takes the 7-word branch
  function test_erc721PermitV4_movesToken() public {
    nftV4.mint(owner, 3);

    bytes memory permitData = _erc721PermitDataV4(ownerWallet, nftV4, 3, DEFAULT_DEADLINE);
    assertEq(permitData.length, 224, 'seven-word v4 payload');
    assertEq(nftV4.nonces(3), 0, 'permit nonce unused beforehand');
    assertFalse(nftV4.isApprovedForAll(owner, address(hub)), 'no standing operator approval');

    ERC721Params[] memory erc721Params =
      _erc721ParamsArray(_erc721Params(address(nftV4), 3, recipient, permitData));

    vm.prank(owner);
    hub.permitTransferAndExecute(_noErc20Params(), erc721Params, _noGenericCalls());

    assertEq(nftV4.ownerOf(3), recipient, 'token delivered to the target');
    assertEq(nftV4.nonces(3), 1, 'permit nonce consumed exactly once');
  }

  /* ------------------------------------------------------------- PTE-28 */

  /// @notice PTE-28 the lock already holds at the ERC721 receiver hook, before any generic call
  function test_reentryFromErc721Receiver_isLocked() public {
    nft.mint(owner, 9);
    vm.prank(owner);
    nft.setApprovalForAll(address(hub), true);

    reentrantNftReceiver.setReentrantCalldata(_emptyEntrypointCalldata());

    ERC721Params[] memory erc721Params =
      _erc721ParamsArray(_erc721Params(address(nft), 9, address(reentrantNftReceiver), ''));
    GenericCall[] memory genericCalls =
      _genericCallArray(_genericCall(address(routerA), 0, hex'01'));

    vm.prank(owner);
    hub.permitTransferAndExecute(_noErc20Params(), erc721Params, genericCalls);

    assertTrue(reentrantNftReceiver.observedCallback(), 'the receiver hook actually fired');
    assertTrue(reentrantNftReceiver.reentrantCallReverted(), 'the reentrant call was rejected');
    assertEq(
      reentrantNftReceiver.reentrantRevertData(),
      abi.encodePacked(IKSAllowanceHubV2.AlreadyLocked.selector),
      'rejected with AlreadyLocked'
    );
    assertEq(nft.ownerOf(9), address(reentrantNftReceiver), 'the outer transfer still completed');
    assertEq(routerA.callCount(), 1, 'the outer generic call ran after the hook');
  }

  /* ------------------------------------------------------------- PTE-29 */

  /// @notice PTE-29 a target that rejects native token fails the whole call
  function test_nativeTargetRejects_reverts() public {
    ERC20Params[] memory erc20Params = _erc20ParamsArray(
      _erc20Params(
        NATIVE, [address(nativeRejector)].toMemoryArray(), [uint256(1 ether)].toMemoryArray(), ''
      )
    );

    vm.deal(owner, 1 ether);
    vm.prank(owner);
    vm.expectRevert(
      abi.encodeWithSelector(
        CustomRevert.WrappedError.selector,
        address(nativeRejector),
        bytes4(0),
        abi.encodePacked(NativeRejectorMock.NativeRejected.selector),
        abi.encodePacked(TokenHelper.NativeTransferFailed.selector)
      )
    );
    hub.permitTransferAndExecute{value: 1 ether}(erc20Params, _noErc721Params(), _noGenericCalls());

    assertEq(address(nativeRejector).balance, 0, 'nothing was delivered');
  }

  /* ------------------------------------------------------------- PTE-30 */

  /// @notice PTE-30 the transient owner slot is rolled back on every revert path
  function test_transientOwnerCleared_afterEveryRevert() public {
    bytes4 selector = hub.permitTransferAndExecute.selector;

    // (1) mismatched array lengths — reverts inside the body, after `lock` wrote the slot
    ERC20Params[] memory mismatched = _erc20ParamsArray(
      _erc20Params(
        address(tokenA),
        [address(routerA)].toMemoryArray(),
        [uint256(1 ether), uint256(2 ether)].toMemoryArray(),
        ''
      )
    );
    vm.prank(owner);
    (bool ok, bytes memory ret) = address(hub)
      .call(abi.encodeWithSelector(selector, mismatched, _noErc721Params(), _noGenericCalls()));
    assertFalse(ok, 'mismatched lengths revert');
    assertEq(ret, abi.encodePacked(ICommon.MismatchedArrayLengths.selector), 'length revert reason');
    assertEq(hub.msgSender(), address(0), 'slot cleared after the length revert');

    // (2) the router reverts mid-execution
    routerA.setShouldRevert(true);
    GenericCall[] memory failingCall = _genericCallArray(_genericCall(address(routerA), 0, hex'01'));
    vm.prank(owner);
    (ok, ret) = address(hub)
      .call(abi.encodeWithSelector(selector, _noErc20Params(), _noErc721Params(), failingCall));
    assertFalse(ok, 'router revert bubbles');
    assertEq(ret, abi.encodePacked(GenericRouterMock.RouterFailed.selector), 'router revert reason');
    assertEq(hub.msgSender(), address(0), 'slot cleared after the router revert');
    routerA.setShouldRevert(false);

    // (3) native overspend — rejected by the outermost modifier, after the body ran
    vm.deal(address(hub), 5 ether);
    vm.deal(owner, 1 ether);
    GenericCall[] memory overspending =
      _genericCallArray(_genericCall(address(routerA), 2 ether, hex'01'));
    vm.prank(owner);
    (ok, ret) = address(hub).call{value: 1 ether}(
      abi.encodeWithSelector(selector, _noErc20Params(), _noErc721Params(), overspending)
    );
    assertFalse(ok, 'overspend reverts');
    assertEq(
      ret,
      abi.encodePacked(IKSAllowanceHubV2.NativeTokenOverspent.selector),
      'overspend revert reason'
    );
    assertEq(hub.msgSender(), address(0), 'slot cleared after the overspend revert');

    // (4) paused — rejected before `lock` ever runs
    vm.prank(guardian);
    hub.pause();
    vm.prank(owner);
    (ok, ret) = address(hub)
      .call(
        abi.encodeWithSelector(selector, _noErc20Params(), _noErc721Params(), _noGenericCalls())
      );
    assertFalse(ok, 'paused reverts');
    assertEq(ret, abi.encodePacked(Pausable.EnforcedPause.selector), 'pause revert reason');
    assertEq(hub.msgSender(), address(0), 'slot cleared after the pause revert');
  }

  /* ---------------------------------------------------------- local helpers */

  /// @dev Calldata for an entirely empty `permitTransferAndExecute`, used as a reentry probe
  function _emptyEntrypointCalldata() private view returns (bytes memory) {
    return abi.encodeWithSelector(
      hub.permitTransferAndExecute.selector, _noErc20Params(), _noErc721Params(), _noGenericCalls()
    );
  }

  /// @dev Locates the hub's single `TransferTokens` log and decodes it
  function _readTransferTokens(Vm.Log[] memory logs)
    private
    view
    returns (
      address caller,
      address tokensOwner,
      uint256 msgValue,
      ERC20Transfer[] memory erc20Transfers,
      ERC721Transfer[] memory erc721Transfers,
      NativeTransfer[] memory nativeTransfers
    )
  {
    bool found = false;
    for (uint256 i = 0; i < logs.length; i++) {
      if (logs[i].emitter != address(hub)) continue;
      if (logs[i].topics.length != 3) continue;
      if (logs[i].topics[0] != TransferTokens.selector) continue;

      assertFalse(found, 'exactly one TransferTokens log');
      found = true;

      caller = address(uint160(uint256(logs[i].topics[1])));
      tokensOwner = address(uint160(uint256(logs[i].topics[2])));
      (msgValue, erc20Transfers, erc721Transfers, nativeTransfers) =
        abi.decode(logs[i].data, (uint256, ERC20Transfer[], ERC721Transfer[], NativeTransfer[]));
    }
    assertTrue(found, 'TransferTokens was emitted');
  }
}
