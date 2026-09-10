// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {KSAllowanceHubV2Base} from './base/KSAllowanceHubV2Base.sol';

import {IKSAllowanceHubV2} from 'src/interfaces/IKSAllowanceHubV2.sol';
import {ERC721Transfer} from 'src/types/ERC721Transfer.sol';
import {GenericCall} from 'src/types/GenericCall.sol';
import {RelayerWitnessLibrary} from 'src/types/RelayerWitness.sol';

import {ICommon} from 'ks-common-sc/src/interfaces/ICommon.sol';
import {ISignatureTransfer} from 'ks-common-sc/src/interfaces/ISignatureTransfer.sol';

import {Pausable} from 'openzeppelin-contracts/contracts/utils/Pausable.sol';

import {ArrayHelper} from '../libraries/ArrayHelper.sol';

/**
 * @notice `permitTokensToPermit2` and the `multicall` batching it exists to serve
 * @dev Together these make a permit2 flow gasless for the owner: a relayer relays the owner's
 * ERC20 permits so Permit2 gains the allowance, then runs the flow, all in one transaction the
 * owner never signs for.
 */
contract KSAllowanceHubV2PermitToPermit2Test is KSAllowanceHubV2Base {
  using ArrayHelper for *;

  /* ----------------------------------------------------------- relaying */

  /// @dev Permits are relayed for Permit2, not for the hub, which is what the permit2 paths need
  function test_relaysPermitsGrantingAllowanceToPermit2NotTheHub() public {
    _fundERC20(tokenA, owner, 10 ether);
    _fundERC20(tokenB, owner, 10 ether);

    bytes[] memory permits = new bytes[](2);
    permits[0] =
      _erc20PermitDataFor(ownerWallet, tokenA, address(permit2), 4 ether, DEFAULT_DEADLINE);
    permits[1] =
      _erc20PermitDataFor(ownerWallet, tokenB, address(permit2), 6 ether, DEFAULT_DEADLINE);

    // Anyone may submit; the owner never sends a transaction.
    vm.prank(outsider);
    hub.permitTokensToPermit2([address(tokenA), address(tokenB)].toMemoryArray(), owner, permits);

    assertEq(tokenA.allowance(owner, address(permit2)), 4 ether, 'tokenA allowance to permit2');
    assertEq(tokenB.allowance(owner, address(permit2)), 6 ether, 'tokenB allowance to permit2');
    assertEq(tokenA.allowance(owner, address(hub)), 0, 'the hub itself gains no allowance');
    assertEq(tokenB.allowance(owner, address(hub)), 0, 'the hub itself gains no allowance');
    assertEq(tokenA.nonces(owner), 1, 'permit nonce consumed');
  }

  /// @dev A payload of an unsupported length is skipped rather than reverting the batch
  function test_unsupportedPayloadLengthIsSkipped() public {
    _fundERC20(tokenA, owner, 10 ether);

    bytes[] memory permits = new bytes[](2);
    permits[0] = hex'0102'; // neither 5 nor 6 words
    permits[1] =
      _erc20PermitDataFor(ownerWallet, tokenB, address(permit2), 6 ether, DEFAULT_DEADLINE);

    vm.prank(outsider);
    hub.permitTokensToPermit2([address(tokenA), address(tokenB)].toMemoryArray(), owner, permits);

    assertEq(tokenA.allowance(owner, address(permit2)), 0, 'skipped payload granted nothing');
    assertEq(tokenA.nonces(owner), 0, 'skipped payload consumed no nonce');
    assertEq(tokenB.allowance(owner, address(permit2)), 6 ether, 'the valid one still applied');
  }

  /**
   * @dev A permit that reverts is swallowed, so one already applied by somebody else — or simply
   * malformed — cannot brick a batch. The missing allowance surfaces later, as a transfer failure.
   */
  function test_revertingPermitIsSwallowedAndLeavesNoAllowance() public {
    _fundERC20(tokenA, owner, 10 ether);

    // Correctly shaped, but signed by the wrong wallet.
    bytes[] memory permits = new bytes[](1);
    permits[0] =
      _erc20PermitDataFor(otherWallet, tokenA, address(permit2), 4 ether, DEFAULT_DEADLINE);

    vm.prank(outsider);
    hub.permitTokensToPermit2([address(tokenA)].toMemoryArray(), owner, permits);

    assertEq(tokenA.allowance(owner, address(permit2)), 0, 'no allowance granted');
    assertEq(tokenA.nonces(owner), 0, 'no nonce consumed');
  }

  /// @dev Replaying an already-applied permit is a no-op rather than a revert
  function test_replayingAnAppliedPermitDoesNotRevert() public {
    _fundERC20(tokenA, owner, 10 ether);

    bytes[] memory permits = new bytes[](1);
    permits[0] =
      _erc20PermitDataFor(ownerWallet, tokenA, address(permit2), 4 ether, DEFAULT_DEADLINE);

    vm.prank(outsider);
    hub.permitTokensToPermit2([address(tokenA)].toMemoryArray(), owner, permits);

    vm.prank(relayer);
    hub.permitTokensToPermit2([address(tokenA)].toMemoryArray(), owner, permits);

    assertEq(
      tokenA.allowance(owner, address(permit2)), 4 ether, 'allowance unchanged by the replay'
    );
    assertEq(tokenA.nonces(owner), 1, 'the nonce was consumed exactly once');
  }

  function test_mismatchedTokensAndPermitDataRevert() public {
    bytes[] memory permits = new bytes[](1);
    permits[0] =
      _erc20PermitDataFor(ownerWallet, tokenA, address(permit2), 4 ether, DEFAULT_DEADLINE);

    vm.expectRevert(ICommon.MismatchedArrayLengths.selector);
    hub.permitTokensToPermit2([address(tokenA), address(tokenB)].toMemoryArray(), owner, permits);
  }

  function test_pausedHubRelaysNothing() public {
    _fundERC20(tokenA, owner, 10 ether);
    bytes[] memory permits = new bytes[](1);
    permits[0] =
      _erc20PermitDataFor(ownerWallet, tokenA, address(permit2), 4 ether, DEFAULT_DEADLINE);

    vm.prank(guardian);
    hub.pause();

    vm.expectRevert(Pausable.EnforcedPause.selector);
    hub.permitTokensToPermit2([address(tokenA)].toMemoryArray(), owner, permits);
  }

  /* ---------------------------------------------------------- multicall */

  /**
   * @dev The reason the relay exists: one relayer transaction permits Permit2 and then runs the
   * permit2 flow. The owner holds no allowance beforehand and sends no transaction.
   */
  function test_multicallPermitsThenFulfilsInOneRelayerTransaction() public {
    _fundERC20(tokenA, owner, 10 ether);
    assertEq(tokenA.allowance(owner, address(permit2)), 0, 'no allowance to start with');

    bytes[] memory permits = new bytes[](1);
    permits[0] =
      _erc20PermitDataFor(ownerWallet, tokenA, address(permit2), 3 ether, DEFAULT_DEADLINE);

    ISignatureTransfer.PermitBatchTransferFrom memory permit =
      _permitBatch([address(tokenA)].toMemoryArray(), [uint256(3 ether)].toMemoryArray(), 0);
    bytes memory sig = _relayerSig(permit, relayer, [address(routerA)].toMemoryArray());

    bytes[] memory batch = new bytes[](2);
    batch[0] = abi.encodeCall(
      hub.permitTokensToPermit2, ([address(tokenA)].toMemoryArray(), owner, permits)
    );
    batch[1] = abi.encodeCall(
      hub.permit2TransferAndExecute,
      (
        permit,
        [address(routerA)].toMemoryArray(),
        _noErc721Params(),
        _noGenericCalls(),
        owner,
        false,
        sig
      )
    );

    vm.prank(relayer);
    hub.multicall(batch);

    assertEq(tokenA.balanceOf(address(routerA)), 3 ether, 'target funded in one relayer tx');
    assertEq(tokenA.balanceOf(owner), 7 ether, 'owner debited');
    assertEq(permit2.nonceBitmap(owner, 0), 1, 'permit2 nonce consumed');
    assertEq(hub.msgSender(), address(0), 'transient owner cleared after the batch');
  }

  /// @dev Each sub-call takes and releases the lock in turn, so two flows can share one batch
  function test_multicallRunsTwoLockedEntrypointsInSequence() public {
    _fundERC20(tokenA, owner, 10 ether);
    _approvePermit2(tokenA, owner, type(uint256).max);

    ISignatureTransfer.PermitBatchTransferFrom memory first =
      _permitBatch([address(tokenA)].toMemoryArray(), [uint256(2 ether)].toMemoryArray(), 0);
    ISignatureTransfer.PermitBatchTransferFrom memory second =
      _permitBatch([address(tokenA)].toMemoryArray(), [uint256(3 ether)].toMemoryArray(), 1);

    bytes[] memory batch = new bytes[](2);
    batch[0] = abi.encodeCall(
      hub.permit2TransferAndExecute,
      (
        first,
        [address(routerA)].toMemoryArray(),
        _noErc721Params(),
        _noGenericCalls(),
        owner,
        false,
        _relayerSig(first, relayer, [address(routerA)].toMemoryArray())
      )
    );
    batch[1] = abi.encodeCall(
      hub.permit2TransferAndExecute,
      (
        second,
        [address(routerB)].toMemoryArray(),
        _noErc721Params(),
        _noGenericCalls(),
        owner,
        false,
        _relayerSig(second, relayer, [address(routerB)].toMemoryArray())
      )
    );

    vm.prank(relayer);
    hub.multicall(batch);

    assertEq(tokenA.balanceOf(address(routerA)), 2 ether, 'first flow settled');
    assertEq(tokenA.balanceOf(address(routerB)), 3 ether, 'second flow settled');
    assertEq(permit2.nonceBitmap(owner, 0), 3, 'both nonces consumed');
  }

  /// @dev A reverting sub-call takes the whole batch down, so a batch is all-or-nothing
  function test_multicallIsAllOrNothing() public {
    _fundERC20(tokenA, owner, 10 ether);
    _approvePermit2(tokenA, owner, type(uint256).max);

    ISignatureTransfer.PermitBatchTransferFrom memory permit =
      _permitBatch([address(tokenA)].toMemoryArray(), [uint256(2 ether)].toMemoryArray(), 0);

    bytes[] memory batch = new bytes[](2);
    batch[0] = abi.encodeCall(
      hub.permit2TransferAndExecute,
      (
        permit,
        [address(routerA)].toMemoryArray(),
        _noErc721Params(),
        _noGenericCalls(),
        owner,
        false,
        _relayerSig(permit, relayer, [address(routerA)].toMemoryArray())
      )
    );
    // Same nonce again: Permit2 rejects the replay.
    batch[1] = batch[0];

    vm.expectRevert();
    vm.prank(relayer);
    hub.multicall(batch);

    assertEq(tokenA.balanceOf(owner), 10 ether, 'the successful leg was rolled back too');
    assertEq(permit2.nonceBitmap(owner, 0), 0, 'no nonce survived');
  }

  /**
   * @dev Signs a `RelayerWitness` naming `expectedRelayer`, which is what a relayer-submitted
   * permit2 flow needs. The library is used for the hash only; the types batch pins its typehash.
   */
  function _relayerSig(
    ISignatureTransfer.PermitBatchTransferFrom memory permit,
    address expectedRelayer,
    address[] memory targets
  ) private view returns (bytes memory) {
    bytes32 witness = RelayerWitnessLibrary.hash(
      expectedRelayer, targets, new ERC721Transfer[](0), new GenericCall[](0)
    );
    return _signPermit2WithWitness(
      ownerWallet,
      permit,
      address(hub),
      witness,
      RelayerWitnessLibrary.RELAYER_WITNESS_PERMIT2_TYPE_STRING
    );
  }

  /// @dev A native payout to an arbitrary target, the cheapest way to spend hub balance
  function _nativePayout(uint256 amount) private view returns (bytes memory) {
    return abi.encodeCall(
      hub.permitTransferAndExecute,
      (
        _erc20ParamsArray(
          _erc20Params(NATIVE, [recipient].toMemoryArray(), [amount].toMemoryArray(), '')
        ),
        _noErc721Params(),
        _noGenericCalls()
      )
    );
  }

  /**
   * @dev Every sub-call is a `delegatecall` and so sees the same `msg.value`, though the native
   * token arrived once. The batch is therefore bounded as a whole: one sub-call may spend the
   * value, two may not spend it twice.
   */
  function test_multicallBoundsNativeSpendAcrossTheWholeBatch() public {
    vm.deal(address(hub), 5 ether); // balance stranded by earlier over-sends
    vm.deal(relayer, 2 ether);

    bytes[] memory one = new bytes[](1);
    one[0] = _nativePayout(1 ether);

    vm.prank(relayer);
    hub.multicall{value: 1 ether}(one);

    assertEq(recipient.balance, 1 ether, 'the batch spent its own value');
    assertEq(address(hub).balance, 5 ether, 'the stranded balance was untouched');

    // The same payout twice would spend one `msg.value` two times over.
    bytes[] memory two = new bytes[](2);
    two[0] = one[0];
    two[1] = one[0];

    vm.expectRevert(IKSAllowanceHubV2.NativeTokenOverspent.selector);
    vm.prank(relayer);
    hub.multicall{value: 1 ether}(two);

    assertEq(address(hub).balance, 5 ether, 'nothing was drained');
    assertEq(recipient.balance, 1 ether, 'the recipient gained nothing further');
  }

  /**
   * @dev The outer batch is the backstop: each nested batch passes its own check, yet together they
   * exceed the value that actually arrived, and the outermost measurement catches it.
   */
  function test_nestedMulticallCannotExceedTheOuterBound() public {
    vm.deal(address(hub), 5 ether);
    vm.deal(relayer, 2 ether);

    bytes[] memory inner = new bytes[](1);
    inner[0] = _nativePayout(1 ether);

    // A single nested batch is within bounds.
    bytes[] memory outerOk = new bytes[](1);
    outerOk[0] = abi.encodeCall(hub.multicall, (inner));

    vm.prank(relayer);
    hub.multicall{value: 1 ether}(outerOk);
    assertEq(recipient.balance, 1 ether, 'one nested batch settled');

    // Two of them each pass their own check, but together spend the value twice.
    bytes[] memory outerBad = new bytes[](2);
    outerBad[0] = outerOk[0];
    outerBad[1] = outerOk[0];

    vm.expectRevert(IKSAllowanceHubV2.NativeTokenOverspent.selector);
    vm.prank(relayer);
    hub.multicall{value: 1 ether}(outerBad);

    assertEq(address(hub).balance, 5 ether, 'the stranded balance survived the nesting');
  }
}
