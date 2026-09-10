// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {KSAllowanceHubBase} from './base/KSAllowanceHubBase.sol';

import {ArrayHelper} from '../libraries/ArrayHelper.sol';

import {Permit2Mock} from '../mocks/Permit2Mock.sol';
import {ERC20PermitMock} from '../mocks/TokenMocks.sol';

import {IKSAllowanceHub} from 'src/interfaces/IKSAllowanceHub.sol';

import {ERC20Transfer} from 'src/types/ERC20Transfer.sol';
import {ERC721Transfer} from 'src/types/ERC721Transfer.sol';
import {GenericCall} from 'src/types/GenericCall.sol';
import {RelayerWitnessLibrary} from 'src/types/RelayerWitness.sol';

import {ICommon} from 'ks-common-sc/src/interfaces/ICommon.sol';
import {ISignatureTransfer} from 'ks-common-sc/src/interfaces/ISignatureTransfer.sol';

import {IAccessControl} from 'openzeppelin-contracts/contracts/access/IAccessControl.sol';
import {Pausable} from 'openzeppelin-contracts/contracts/utils/Pausable.sol';

import {Vm} from 'forge-std/Test.sol';

/**
 * @notice `permit2TransferAndExecute` on the legacy `KSAllowanceHub`
 * @dev The witness path is only taken when `owner != msg.sender` (`KSAllowanceHub.sol:176`), so the
 * self-submitted cases sign a plain Permit2 batch and the relayer cases sign one carrying a
 * `RelayerWitness`. `RelayerWitnessLibrary` is imported for signing only: its constants are pinned
 * independently against hand-written EIP-712 literals elsewhere, so nothing here asserts a hash
 * against the same library that produced it.
 *
 * The legacy `TransferTokens` carries five members — it has no `nativeTransfers` array, unlike the
 * V2 hub's — so the payload assertions below are against the five-field shape.
 */
contract KSAllowanceHubPermit2TransferAndExecuteTest is KSAllowanceHubBase {
  using ArrayHelper for *;

  /// @dev Hand-written canonical signature of the legacy `TransferTokens`, used to find it in logs
  bytes32 private constant TRANSFER_TOKENS_TOPIC = keccak256(
    'TransferTokens(address,address,uint256,(address,address,uint256)[],(address,uint256,address)[])'
  );

  /// @dev Fuzz inputs, kept in one ABI-encodable struct
  struct TransferFuzzParams {
    uint96 amountA;
    uint96 amountB;
    bool viaRelayer;
    uint96 msgValue;
  }

  /* --------------------------------------------------------------- self path */

  /// @notice The owner submitting for itself takes the witness-free branch and reports it exactly
  function test_selfPath_transfersToTargetAndEmitsExactPayload() public {
    _fundOwner(tokenA, 10 ether);

    ISignatureTransfer.PermitBatchTransferFrom memory permit =
      _permitBatch([address(tokenA)].toMemoryArray(), [uint256(3 ether)].toMemoryArray(), 0);
    // Signed without any witness: had the hub taken the witness branch the digest would differ
    bytes memory signature = _signPermit2(ownerWallet, permit, address(hub));

    address[] memory targets = [address(routerA)].toMemoryArray();
    GenericCall[] memory calls = _genericCallArray(_genericCall(address(routerA), 0, hex'a1'));

    ERC20Transfer[] memory expectedErc20 = new ERC20Transfer[](1);
    expectedErc20[0] =
      ERC20Transfer({token: address(tokenA), target: address(routerA), amount: 3 ether});

    vm.expectEmit(true, true, true, true, address(hub));
    emit TransferTokens(owner, owner, 0, expectedErc20, _noErc721Transfers());

    vm.prank(owner);
    (bytes[] memory results,) =
      hub.permit2TransferAndExecute(permit, targets, _noErc721Params(), calls, owner, signature);

    assertEq(tokenA.balanceOf(address(routerA)), 3 ether, 'target funded');
    assertEq(tokenA.balanceOf(owner), 7 ether, 'owner debited');
    assertEq(results.length, 1, 'one result');
    assertEq(results[0], routerA.returnData(), 'router return data returned verbatim');
    assertEq(routerA.callAt(0).caller, address(hub), 'router called by the hub');
    assertEq(routerA.callAt(0).value, 0, 'no native forwarded');
  }

  /* ------------------------------------------------------------ relayer path */

  /// @notice A relayer spending the owner's tokens signs a witness and is reported as the caller
  function test_relayerPath_witnessSignedTransferAndExactPayload() public {
    _fundOwner(tokenA, 10 ether);
    vm.deal(relayer, 5 ether);

    ISignatureTransfer.PermitBatchTransferFrom memory permit =
      _permitBatch([address(tokenA)].toMemoryArray(), [uint256(4 ether)].toMemoryArray(), 0);

    address[] memory targets = [address(routerA)].toMemoryArray();
    GenericCall[] memory calls = _genericCallArray(_genericCall(address(routerB), 1 ether, hex'b2'));

    bytes memory signature =
      _signRelayerWitness(permit, relayer, targets, _noErc721Transfers(), calls);

    ERC20Transfer[] memory expectedErc20 = new ERC20Transfer[](1);
    expectedErc20[0] =
      ERC20Transfer({token: address(tokenA), target: address(routerA), amount: 4 ether});

    // The legacy event reports `msgValue` but never the per-call native movements
    vm.expectEmit(true, true, true, true, address(hub));
    emit TransferTokens(relayer, owner, 1 ether, expectedErc20, _noErc721Transfers());

    vm.prank(relayer);
    hub.permit2TransferAndExecute{value: 1 ether}(
      permit, targets, _noErc721Params(), calls, owner, signature
    );

    assertEq(tokenA.balanceOf(address(routerA)), 4 ether, 'target funded from the owner');
    assertEq(tokenA.balanceOf(owner), 6 ether, 'owner debited, not the relayer');
    assertEq(tokenA.balanceOf(relayer), 0, 'relayer never holds the tokens');
    assertEq(address(routerB).balance, 1 ether, 'native forwarded to the call');
    assertEq(routerB.callAt(0).value, 1 ether, 'router saw the forwarded value');
  }

  /* ------------------------------------------------------------ witness binds */

  /// @notice The witness pins `msg.sender`, so a different submitter cannot replay the signature
  function test_witnessBindsRelayer_otherSubmitterReverts() public {
    _fundOwner(tokenA, 10 ether);

    ISignatureTransfer.PermitBatchTransferFrom memory permit =
      _permitBatch([address(tokenA)].toMemoryArray(), [uint256(2 ether)].toMemoryArray(), 0);

    address[] memory targets = [address(routerA)].toMemoryArray();
    GenericCall[] memory calls = _genericCallArray(_genericCall(address(routerA), 0, hex'c3'));

    bytes memory signature =
      _signRelayerWitness(permit, relayer, targets, _noErc721Transfers(), calls);

    vm.expectRevert(Permit2Mock.InvalidSigner.selector);
    vm.prank(outsider);
    hub.permit2TransferAndExecute(permit, targets, _noErc721Params(), calls, owner, signature);

    // Positive control: the very same submission from the signed relayer goes through
    vm.prank(relayer);
    hub.permit2TransferAndExecute(permit, targets, _noErc721Params(), calls, owner, signature);

    assertEq(tokenA.balanceOf(address(routerA)), 2 ether, 'the signed relayer still succeeds');
    assertEq(tokenA.balanceOf(owner), 8 ether, 'owner debited exactly once');
  }

  /// @notice The witness pins the ERC20 targets, so an altered target list is rejected
  function test_witnessBindsTargets_alteredTargetReverts() public {
    _fundOwner(tokenA, 10 ether);

    ISignatureTransfer.PermitBatchTransferFrom memory permit =
      _permitBatch([address(tokenA)].toMemoryArray(), [uint256(2 ether)].toMemoryArray(), 0);

    address[] memory signedTargets = [address(routerA)].toMemoryArray();
    // Whitelisted as well, so the whitelist cannot be what rejects the call
    address[] memory alteredTargets = [address(routerB)].toMemoryArray();
    GenericCall[] memory calls = _genericCallArray(_genericCall(address(routerA), 0, hex'd4'));

    bytes memory signature =
      _signRelayerWitness(permit, relayer, signedTargets, _noErc721Transfers(), calls);

    vm.expectRevert(Permit2Mock.InvalidSigner.selector);
    vm.prank(relayer);
    hub.permit2TransferAndExecute(
      permit, alteredTargets, _noErc721Params(), calls, owner, signature
    );

    // Positive control: only the target list differed above
    vm.prank(relayer);
    hub.permit2TransferAndExecute(permit, signedTargets, _noErc721Params(), calls, owner, signature);

    assertEq(tokenA.balanceOf(address(routerB)), 0, 'no tokens reached the altered target');
    assertEq(tokenA.balanceOf(address(routerA)), 2 ether, 'the signed target was funded');
  }

  /// @notice The witness pins the ERC721 movements, so an altered id or target is rejected
  function test_witnessBindsErc721Transfers_alteredTokenIdOrTargetReverts() public {
    _fundOwner(tokenA, 10 ether);
    nft.mint(owner, 1);
    nft.mint(owner, 2);
    vm.prank(owner);
    nft.setApprovalForAll(address(hub), true);

    ISignatureTransfer.PermitBatchTransferFrom memory permit =
      _permitBatch([address(tokenA)].toMemoryArray(), [uint256(1 ether)].toMemoryArray(), 0);

    address[] memory targets = [address(routerA)].toMemoryArray();
    GenericCall[] memory calls = _noGenericCalls();

    ERC721Transfer[] memory signedErc721 =
      _erc721TransferArray(ERC721Transfer({token: address(nft), tokenId: 1, target: recipient}));
    bytes memory signature = _signRelayerWitness(permit, relayer, targets, signedErc721, calls);

    // Altered token id
    vm.expectRevert(Permit2Mock.InvalidSigner.selector);
    vm.prank(relayer);
    hub.permit2TransferAndExecute(
      permit,
      targets,
      _erc721ParamsArray(_erc721Params(address(nft), 2, recipient, '')),
      calls,
      owner,
      signature
    );

    // Altered target
    vm.expectRevert(Permit2Mock.InvalidSigner.selector);
    vm.prank(relayer);
    hub.permit2TransferAndExecute(
      permit,
      targets,
      _erc721ParamsArray(_erc721Params(address(nft), 1, outsider, '')),
      calls,
      owner,
      signature
    );

    // Positive control: exactly what was signed goes through, so approvals were never the blocker
    vm.prank(relayer);
    hub.permit2TransferAndExecute(
      permit,
      targets,
      _erc721ParamsArray(_erc721Params(address(nft), 1, recipient, '')),
      calls,
      owner,
      signature
    );

    assertEq(nft.ownerOf(1), recipient, 'signed ERC721 movement executed');
    assertEq(nft.ownerOf(2), owner, 'unsigned token untouched');
    assertEq(tokenA.balanceOf(address(routerA)), 1 ether, 'ERC20 leg executed once');
  }

  /// @notice The witness pins every generic-call field: router, value and data
  function test_witnessBindsGenericCalls_alteredRouterValueOrDataReverts() public {
    _fundOwner(tokenA, 10 ether);
    vm.deal(relayer, 5 ether);

    ISignatureTransfer.PermitBatchTransferFrom memory permit =
      _permitBatch([address(tokenA)].toMemoryArray(), [uint256(1 ether)].toMemoryArray(), 0);
    address[] memory targets = [address(routerA)].toMemoryArray();

    GenericCall[] memory signedCalls = _genericCallArray(_genericCall(address(routerA), 0, hex'e5'));
    bytes memory signature =
      _signRelayerWitness(permit, relayer, targets, _noErc721Transfers(), signedCalls);

    // Altered data
    vm.expectRevert(Permit2Mock.InvalidSigner.selector);
    vm.prank(relayer);
    hub.permit2TransferAndExecute(
      permit,
      targets,
      _noErc721Params(),
      _genericCallArray(_genericCall(address(routerA), 0, hex'e6')),
      owner,
      signature
    );

    // Altered router — routerB is whitelisted too, so only the witness can reject this
    vm.expectRevert(Permit2Mock.InvalidSigner.selector);
    vm.prank(relayer);
    hub.permit2TransferAndExecute(
      permit,
      targets,
      _noErc721Params(),
      _genericCallArray(_genericCall(address(routerB), 0, hex'e5')),
      owner,
      signature
    );

    // Altered value
    vm.expectRevert(Permit2Mock.InvalidSigner.selector);
    vm.prank(relayer);
    hub.permit2TransferAndExecute{value: 1 wei}(
      permit,
      targets,
      _noErc721Params(),
      _genericCallArray(_genericCall(address(routerA), 1 wei, hex'e5')),
      owner,
      signature
    );

    // Positive control: the exact signed call executes
    vm.prank(relayer);
    hub.permit2TransferAndExecute(permit, targets, _noErc721Params(), signedCalls, owner, signature);

    assertEq(routerA.callCount(), 1, 'only the signed call ever ran');
    assertEq(routerB.callCount(), 0, 'the altered router was never reached');
    assertEq(routerA.callAt(0).data, hex'e5', 'the signed calldata was delivered');
    assertEq(tokenA.balanceOf(address(routerA)), 1 ether, 'the ERC20 leg ran exactly once');
  }

  /* ------------------------------------------------------------- input guards */

  /// @notice `checkLengths` is the hub's own guard, distinct from Permit2's `LengthMismatch`
  function test_revertsWhenTargetsAndPermittedLengthsDiffer() public {
    _fundOwner(tokenA, 10 ether);

    ISignatureTransfer.PermitBatchTransferFrom memory permit =
      _permitBatch([address(tokenA)].toMemoryArray(), [uint256(1 ether)].toMemoryArray(), 0);
    bytes memory signature = _signPermit2(ownerWallet, permit, address(hub));

    address[] memory targets = [address(routerA), address(routerB)].toMemoryArray();

    vm.expectRevert(ICommon.MismatchedArrayLengths.selector);
    vm.prank(owner);
    hub.permit2TransferAndExecute(
      permit, targets, _noErc721Params(), _noGenericCalls(), owner, signature
    );

    assertEq(tokenA.balanceOf(owner), 10 ether, 'nothing moved');
    assertEq(permit2.nonceBitmap(owner, 0), 0, 'the nonce was never reached');
  }

  /// @notice Permit2 rejects a permit whose deadline has already passed
  function test_revertsOnExpiredDeadline() public {
    _fundOwner(tokenA, 10 ether);
    vm.warp(1000);

    ISignatureTransfer.PermitBatchTransferFrom memory permit =
      _permitBatch([address(tokenA)].toMemoryArray(), [uint256(1 ether)].toMemoryArray(), 0);
    permit.deadline = block.timestamp - 1;
    bytes memory signature = _signPermit2(ownerWallet, permit, address(hub));

    vm.expectRevert(
      abi.encodeWithSelector(Permit2Mock.SignatureExpired.selector, block.timestamp - 1)
    );
    vm.prank(owner);
    hub.permit2TransferAndExecute(
      permit,
      [address(routerA)].toMemoryArray(),
      _noErc721Params(),
      _noGenericCalls(),
      owner,
      signature
    );

    assertEq(tokenA.balanceOf(owner), 10 ether, 'nothing moved');
  }

  /// @notice The unordered nonce cannot be spent twice
  function test_revertsOnNonceReuse() public {
    _fundOwner(tokenA, 10 ether);

    ISignatureTransfer.PermitBatchTransferFrom memory permit =
      _permitBatch([address(tokenA)].toMemoryArray(), [uint256(3 ether)].toMemoryArray(), 7);
    bytes memory signature = _signPermit2(ownerWallet, permit, address(hub));
    address[] memory targets = [address(routerA)].toMemoryArray();

    vm.prank(owner);
    hub.permit2TransferAndExecute(
      permit, targets, _noErc721Params(), _noGenericCalls(), owner, signature
    );
    assertEq(tokenA.balanceOf(address(routerA)), 3 ether, 'first use succeeds');

    vm.expectRevert(Permit2Mock.InvalidNonce.selector);
    vm.prank(owner);
    hub.permit2TransferAndExecute(
      permit, targets, _noErc721Params(), _noGenericCalls(), owner, signature
    );

    assertEq(tokenA.balanceOf(address(routerA)), 3 ether, 'replay moved nothing');
    assertEq(tokenA.balanceOf(owner), 7 ether, 'owner debited only once');
  }

  /// @notice A signature from another wallet does not recover to the claimed owner
  function test_revertsOnSignatureFromWrongWallet() public {
    _fundOwner(tokenA, 10 ether);

    ISignatureTransfer.PermitBatchTransferFrom memory permit =
      _permitBatch([address(tokenA)].toMemoryArray(), [uint256(1 ether)].toMemoryArray(), 0);
    bytes memory signature = _signPermit2(otherWallet, permit, address(hub));

    vm.expectRevert(Permit2Mock.InvalidSigner.selector);
    vm.prank(owner);
    hub.permit2TransferAndExecute(
      permit,
      [address(routerA)].toMemoryArray(),
      _noErc721Params(),
      _noGenericCalls(),
      owner,
      signature
    );

    assertEq(tokenA.balanceOf(owner), 10 ether, 'nothing moved');
  }

  /* ---------------------------------------------------------------- routing */

  /// @notice Each permitted token goes to its index-aligned target, at its own amount
  function test_multiTokenBatchPairsEachTokenWithItsTarget() public {
    _fundOwner(tokenA, 10 ether);
    _fundOwner(tokenB, 10 ether);

    ISignatureTransfer.PermitBatchTransferFrom memory permit = _permitBatch(
      [address(tokenA), address(tokenB)].toMemoryArray(),
      [uint256(2 ether), uint256(5 ether)].toMemoryArray(),
      0
    );
    bytes memory signature = _signPermit2(ownerWallet, permit, address(hub));

    vm.prank(owner);
    hub.permit2TransferAndExecute(
      permit,
      [address(routerA), address(routerB)].toMemoryArray(),
      _noErc721Params(),
      _noGenericCalls(),
      owner,
      signature
    );

    assertEq(tokenA.balanceOf(address(routerA)), 2 ether, 'tokenA to routerA');
    assertEq(tokenB.balanceOf(address(routerB)), 5 ether, 'tokenB to routerB');
    assertEq(tokenA.balanceOf(address(routerB)), 0, 'tokenA did not leak to routerB');
    assertEq(tokenB.balanceOf(address(routerA)), 0, 'tokenB did not leak to routerA');
    assertEq(tokenA.balanceOf(owner), 8 ether, 'owner debited tokenA');
    assertEq(tokenB.balanceOf(owner), 5 ether, 'owner debited tokenB');
  }

  /// @notice `erc721Params[i].permitTransfer(owner)` pulls from the owner, not from the submitter
  function test_erc721IsPulledFromOwnerNotCaller() public {
    _fundOwner(tokenA, 10 ether);
    nft.mint(owner, 42);
    nft.mint(relayer, 43);
    vm.prank(owner);
    nft.setApprovalForAll(address(hub), true);
    // The relayer approves too, so nothing but the `owner` argument decides whose token moves
    vm.prank(relayer);
    nft.setApprovalForAll(address(hub), true);

    ISignatureTransfer.PermitBatchTransferFrom memory permit =
      _permitBatch([address(tokenA)].toMemoryArray(), [uint256(1 ether)].toMemoryArray(), 0);
    address[] memory targets = [address(routerA)].toMemoryArray();

    ERC721Transfer[] memory erc721Transfers =
      _erc721TransferArray(ERC721Transfer({token: address(nft), tokenId: 42, target: recipient}));
    bytes memory signature =
      _signRelayerWitness(permit, relayer, targets, erc721Transfers, _noGenericCalls());

    vm.prank(relayer);
    hub.permit2TransferAndExecute(
      permit,
      targets,
      _erc721ParamsArray(_erc721Params(address(nft), 42, recipient, '')),
      _noGenericCalls(),
      owner,
      signature
    );

    assertEq(nft.ownerOf(42), recipient, "the owner's token moved");
    assertEq(nft.ownerOf(43), relayer, "the relayer's own token was untouched");
    assertEq(tokenA.balanceOf(address(routerA)), 1 ether, 'ERC20 leg also pulled from the owner');
    assertEq(tokenA.balanceOf(owner), 9 ether, 'owner debited');
  }

  /// @notice Every router reads the owner back through `msgSender()`, even on the relayer path
  function test_publishesOwnerAsMsgSenderToEveryRouter() public {
    _fundOwner(tokenA, 10 ether);

    ISignatureTransfer.PermitBatchTransferFrom memory permit =
      _permitBatch([address(tokenA)].toMemoryArray(), [uint256(1 ether)].toMemoryArray(), 0);
    address[] memory targets = [address(routerA)].toMemoryArray();

    GenericCall[] memory calls = _genericCallArray(
      _genericCall(address(routerA), 0, hex'01'), _genericCall(address(routerB), 0, hex'02')
    );
    bytes memory signature =
      _signRelayerWitness(permit, relayer, targets, _noErc721Transfers(), calls);

    assertEq(hub.msgSender(), address(0), 'no owner published before the call');

    vm.prank(relayer);
    hub.permit2TransferAndExecute(permit, targets, _noErc721Params(), calls, owner, signature);

    assertEq(routerA.callAt(0).observedMsgSender, owner, 'routerA observed the owner');
    assertEq(routerB.callAt(0).observedMsgSender, owner, 'routerB observed the owner');
    assertEq(routerA.callAt(0).caller, address(hub), 'the hub is still the EVM caller');
    assertEq(routerB.callAt(0).caller, address(hub), 'the hub is still the EVM caller');
    assertEq(hub.msgSender(), address(0), 'owner cleared after the call');
  }

  /* ------------------------------------------------------------ hub guards */

  /// @notice `whenNotPaused` is the outermost modifier
  function test_revertsWhenPaused() public {
    _fundOwner(tokenA, 10 ether);

    ISignatureTransfer.PermitBatchTransferFrom memory permit =
      _permitBatch([address(tokenA)].toMemoryArray(), [uint256(1 ether)].toMemoryArray(), 0);
    bytes memory signature = _signPermit2(ownerWallet, permit, address(hub));

    vm.prank(guardian);
    hub.pause();

    vm.expectRevert(Pausable.EnforcedPause.selector);
    vm.prank(owner);
    hub.permit2TransferAndExecute(
      permit,
      [address(routerA)].toMemoryArray(),
      _noErc721Params(),
      _noGenericCalls(),
      owner,
      signature
    );

    assertEq(tokenA.balanceOf(owner), 10 ether, 'nothing moved while paused');

    // Unpausing restores the exact same call, so `whenNotPaused` was the only blocker
    vm.prank(admin);
    hub.unpause();
    vm.prank(owner);
    hub.permit2TransferAndExecute(
      permit,
      [address(routerA)].toMemoryArray(),
      _noErc721Params(),
      _noGenericCalls(),
      owner,
      signature
    );
    assertEq(tokenA.balanceOf(address(routerA)), 1 ether, 'the same call succeeds once unpaused');
  }

  /// @notice A call may spend its whole `msg.value` but none of the hub's pre-existing balance
  function test_nativeOverspendRevertsAndEqualBoundarySucceeds() public {
    _fundOwner(tokenA, 10 ether);
    vm.deal(owner, 10 ether);
    // The legacy hub has no `receive()`, so its balance can only be seeded this way
    vm.deal(address(hub), 5 ether);

    address[] memory targets = [address(routerA)].toMemoryArray();
    GenericCall[] memory calls = _genericCallArray(_genericCall(address(routerA), 2 ether, hex'01'));

    ISignatureTransfer.PermitBatchTransferFrom memory overspendPermit =
      _permitBatch([address(tokenA)].toMemoryArray(), [uint256(1 ether)].toMemoryArray(), 0);
    bytes memory overspendSignature = _signPermit2(ownerWallet, overspendPermit, address(hub));

    vm.expectRevert(IKSAllowanceHub.NativeTokenOverspent.selector);
    vm.prank(owner);
    hub.permit2TransferAndExecute{value: 1 ether}(
      overspendPermit, targets, _noErc721Params(), calls, owner, overspendSignature
    );

    ISignatureTransfer.PermitBatchTransferFrom memory boundaryPermit =
      _permitBatch([address(tokenA)].toMemoryArray(), [uint256(1 ether)].toMemoryArray(), 1);
    bytes memory boundarySignature = _signPermit2(ownerWallet, boundaryPermit, address(hub));

    vm.prank(owner);
    hub.permit2TransferAndExecute{value: 2 ether}(
      boundaryPermit, targets, _noErc721Params(), calls, owner, boundarySignature
    );

    assertEq(address(routerA).balance, 2 ether, 'the boundary call forwarded its whole msg.value');
    assertEq(address(hub).balance, 5 ether, 'the hub kept its pre-existing balance');
    assertEq(tokenA.balanceOf(address(routerA)), 1 ether, 'only the boundary call moved tokens');
    assertEq(owner.balance, 8 ether, 'only the boundary call debited the owner');
  }

  /// @notice `_executeGenericCalls` role-checks every router before calling it
  function test_revertsOnNonWhitelistedRouter() public {
    _fundOwner(tokenA, 10 ether);

    ISignatureTransfer.PermitBatchTransferFrom memory permit =
      _permitBatch([address(tokenA)].toMemoryArray(), [uint256(1 ether)].toMemoryArray(), 0);
    bytes memory signature = _signPermit2(ownerWallet, permit, address(hub));

    vm.expectRevert(
      abi.encodeWithSelector(
        IAccessControl.AccessControlUnauthorizedAccount.selector,
        address(unlistedRouter),
        WHITELIST_ROUTER_ROLE
      )
    );
    vm.prank(owner);
    hub.permit2TransferAndExecute(
      permit,
      [address(routerA)].toMemoryArray(),
      _noErc721Params(),
      _genericCallArray(_genericCall(address(unlistedRouter), 0, hex'01')),
      owner,
      signature
    );

    assertEq(unlistedRouter.callCount(), 0, 'the unlisted router was never called');
    assertEq(tokenA.balanceOf(address(routerA)), 0, 'the whole call was rolled back');
  }

  /// @notice The transient lock rejects a reentrant entrypoint call
  function test_revertsOnReentry() public {
    _fundOwner(tokenA, 10 ether);

    ISignatureTransfer.PermitBatchTransferFrom memory innerPermit;
    innerPermit.permitted = new ISignatureTransfer.TokenPermissions[](0);
    innerPermit.nonce = 99;
    innerPermit.deadline = DEFAULT_DEADLINE;

    reentrantRouter.setReentrantCalldata(
      abi.encodeCall(
        hub.permit2TransferAndExecute,
        (innerPermit, new address[](0), _noErc721Params(), _noGenericCalls(), owner, hex'')
      ),
      false
    );

    ISignatureTransfer.PermitBatchTransferFrom memory permit =
      _permitBatch([address(tokenA)].toMemoryArray(), [uint256(1 ether)].toMemoryArray(), 0);
    bytes memory signature = _signPermit2(ownerWallet, permit, address(hub));

    vm.expectRevert(IKSAllowanceHub.AlreadyLocked.selector);
    vm.prank(owner);
    hub.permit2TransferAndExecute(
      permit,
      [address(routerA)].toMemoryArray(),
      _noErc721Params(),
      _genericCallArray(_genericCall(address(reentrantRouter), 0, hex'01')),
      owner,
      signature
    );

    assertEq(tokenA.balanceOf(owner), 10 ether, 'the outer call was rolled back');
    assertEq(hub.msgSender(), address(0), 'the lock is clear after the reverted call');
  }

  /// @notice Permit2 skips a zero requested amount, but the hub still reports the entry
  function test_zeroPermittedAmountSkipsTransferButIsStillReported() public {
    _fundOwner(tokenA, 5 ether);
    _fundOwner(tokenB, 5 ether);

    ISignatureTransfer.PermitBatchTransferFrom memory permit = _permitBatch(
      [address(tokenA), address(tokenB)].toMemoryArray(),
      [uint256(0), uint256(2 ether)].toMemoryArray(),
      0
    );
    bytes memory signature = _signPermit2(ownerWallet, permit, address(hub));

    vm.recordLogs();
    vm.prank(owner);
    hub.permit2TransferAndExecute(
      permit,
      [address(routerA), address(routerB)].toMemoryArray(),
      _noErc721Params(),
      _noGenericCalls(),
      owner,
      signature
    );
    Vm.Log[] memory logs = vm.getRecordedLogs();

    bool foundTransferTokens;
    for (uint256 i = 0; i < logs.length; i++) {
      assertTrue(logs[i].emitter != address(tokenA), 'the zero-amount token emitted nothing');

      if (logs[i].topics[0] == TRANSFER_TOKENS_TOPIC && logs[i].emitter == address(hub)) {
        foundTransferTokens = true;
        // The legacy payload decodes as three members, with no trailing native array
        (, ERC20Transfer[] memory erc20Transfers,) =
          abi.decode(logs[i].data, (uint256, ERC20Transfer[], ERC721Transfer[]));

        assertEq(erc20Transfers.length, 2, 'both entries reported');
        assertEq(erc20Transfers[0].token, address(tokenA), 'zero entry token reported');
        assertEq(erc20Transfers[0].target, address(routerA), 'zero entry target reported');
        assertEq(erc20Transfers[0].amount, 0, 'zero entry amount reported');
        assertEq(erc20Transfers[1].amount, 2 ether, 'funded entry reported');
      }
    }

    assertTrue(foundTransferTokens, 'TransferTokens emitted');
    assertEq(tokenA.balanceOf(owner), 5 ether, 'no tokenA left the owner');
    assertEq(tokenA.balanceOf(address(routerA)), 0, 'the zero-amount target received nothing');
    assertEq(tokenB.balanceOf(address(routerB)), 2 ether, 'the funded leg still executed');
  }

  /* -------------------------------------------------------------------- fuzz */

  /// @notice Owner debits equal the permitted amounts and the nonce bit is consumed exactly once
  function testFuzz_ownerDebitMatchesPermittedAndNonceConsumedOnce(TransferFuzzParams memory params)
    public
  {
    uint256 amountA = bound(params.amountA, 1, 1e30);
    uint256 amountB = bound(params.amountB, 1, 1e30);
    uint256 msgValue = bound(params.msgValue, 0, 100 ether);
    uint256 nonce = 300; // spans a non-zero word position of the nonce bitmap

    _fundOwner(tokenA, amountA);
    _fundOwner(tokenB, amountB);

    ISignatureTransfer.PermitBatchTransferFrom memory permit = _permitBatch(
      [address(tokenA), address(tokenB)].toMemoryArray(), [amountA, amountB].toMemoryArray(), nonce
    );
    address[] memory targets = [address(routerA), address(routerB)].toMemoryArray();

    // `viaRelayer` selects the witness branch against the witness-free one
    address caller = params.viaRelayer ? relayer : owner;
    bytes memory signature = params.viaRelayer
      ? _signRelayerWitness(permit, relayer, targets, _noErc721Transfers(), _noGenericCalls())
      : _signPermit2(ownerWallet, permit, address(hub));

    uint256 wordPos = nonce >> 8;
    uint256 bit = 1 << uint8(nonce);
    assertEq(permit2.nonceBitmap(owner, wordPos), 0, 'nonce word untouched before');

    uint256 ownerBalanceABefore = tokenA.balanceOf(owner);
    uint256 ownerBalanceBBefore = tokenB.balanceOf(owner);
    uint256 hubNativeBefore = address(hub).balance;

    vm.deal(caller, msgValue);
    vm.prank(caller);
    hub.permit2TransferAndExecute{value: msgValue}(
      permit, targets, _noErc721Params(), _noGenericCalls(), owner, signature
    );

    assertEq(ownerBalanceABefore - tokenA.balanceOf(owner), amountA, 'tokenA debit == permitted');
    assertEq(ownerBalanceBBefore - tokenB.balanceOf(owner), amountB, 'tokenB debit == permitted');
    assertEq(tokenA.balanceOf(address(routerA)), amountA, 'tokenA credited to its target');
    assertEq(tokenB.balanceOf(address(routerB)), amountB, 'tokenB credited to its target');
    assertEq(permit2.nonceBitmap(owner, wordPos), bit, 'exactly one nonce bit consumed');
    assertEq(
      address(hub).balance, hubNativeBefore + msgValue, 'unconsumed msg.value stays in the hub'
    );
  }

  /* --------------------------------------------------------- local helpers */

  /// @dev Mints to the owner and points the Permit2 allowance at the stand-in
  function _fundOwner(ERC20PermitMock token, uint256 amount) private {
    _fundERC20(token, owner, amount);
    _approvePermit2(token, owner, type(uint256).max);
  }

  /// @dev Signs the batch with the `RelayerWitness` the hub rebuilds from its own calldata
  function _signRelayerWitness(
    ISignatureTransfer.PermitBatchTransferFrom memory permit,
    address witnessRelayer,
    address[] memory targets,
    ERC721Transfer[] memory erc721Transfers,
    GenericCall[] memory genericCalls
  ) private view returns (bytes memory) {
    bytes32 witness = RelayerWitnessLibrary.hash(
      witnessRelayer, targets, erc721Transfers, genericCalls
    );
    return _signPermit2WithWitness(
      ownerWallet,
      permit,
      address(hub),
      witness,
      RelayerWitnessLibrary.RELAYER_WITNESS_PERMIT2_TYPE_STRING
    );
  }

  function _erc721TransferArray(ERC721Transfer memory a)
    private
    pure
    returns (ERC721Transfer[] memory arr)
  {
    arr = new ERC721Transfer[](1);
    arr[0] = a;
  }

  function _noErc721Transfers() private pure returns (ERC721Transfer[] memory) {
    return new ERC721Transfer[](0);
  }
}
