// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {KSAllowanceHubV2Base} from './base/KSAllowanceHubV2Base.sol';

import {ArrayHelper} from '../libraries/ArrayHelper.sol';

import {Permit2Mock} from '../mocks/Permit2Mock.sol';
import {ERC20PermitMock} from '../mocks/TokenMocks.sol';

import {IKSAllowanceHubV2} from 'src/interfaces/IKSAllowanceHubV2.sol';

import {ERC20Transfer} from 'src/types/ERC20Transfer.sol';
import {ERC721Transfer} from 'src/types/ERC721Transfer.sol';
import {GenericCall} from 'src/types/GenericCall.sol';
import {NativeTransfer} from 'src/types/NativeTransfer.sol';
import {RelayerWitnessLibrary} from 'src/types/RelayerWitness.sol';

import {ICommon} from 'ks-common-sc/src/interfaces/ICommon.sol';
import {ISignatureTransfer} from 'ks-common-sc/src/interfaces/ISignatureTransfer.sol';

import {IAccessControl} from 'openzeppelin-contracts/contracts/access/IAccessControl.sol';
import {Pausable} from 'openzeppelin-contracts/contracts/utils/Pausable.sol';

import {Vm} from 'forge-std/Test.sol';

/**
 * @notice Batch B — `permit2TransferAndExecute`, cases P2E-01..P2E-20 plus the `anyRelayer`
 * flag
 * @dev The plain (witness-free) path is only taken when `!anyRelayer && owner == msg.sender`
 * (`KSAllowanceHubV2.sol:190`), so the self-submitted cases sign a plain Permit2 batch and every
 * other case signs one carrying a `RelayerWitness`. That witness pins
 * `_witnessCaller(anyRelayer)`: `msg.sender` when the flag is false, `ANY_ADDRESS` when it is
 * true — and since `msg.sender` is never the zero address the two digests can never collide, so
 * the flag authenticates itself.
 * `RelayerWitnessLibrary` is imported for signing only: its constants are pinned independently
 * against hand-written EIP-712 literals by the TYP batch, so nothing here asserts a hash against
 * the same library that produced it.
 */
contract KSAllowanceHubV2Permit2TransferAndExecuteTest is KSAllowanceHubV2Base {
  using ArrayHelper for *;

  /// @dev Hand-written canonical signature of `TransferTokens`, used to find it among raw logs
  bytes32 private constant TRANSFER_TOKENS_TOPIC = keccak256(
    'TransferTokens(address,address,uint256,(address,address,uint256)[],(address,uint256,address)[],(address,uint256)[])'
  );

  /// @dev Fuzz inputs for P2E-20, kept in one ABI-encodable struct
  struct TransferFuzzParams {
    uint96 amountA;
    uint96 amountB;
    bool viaRelayer;
    uint96 msgValue;
  }

  /* ---------------------------------------------------------- P2E-01 / 13 */

  /// @dev P2E-01 plus the self-path half of P2E-13 (group G5: no event-only test)
  function test_selfPath_transfersToTargetAndEmitsExactPayload() public {
    _fundOwner(tokenA, 10 ether);

    ISignatureTransfer.PermitBatchTransferFrom memory permit =
      _permitBatch([address(tokenA)].toMemoryArray(), [uint256(3 ether)].toMemoryArray(), 0);
    bytes memory signature = _signPermit2(ownerWallet, permit, address(hub));

    address[] memory targets = [address(routerA)].toMemoryArray();
    GenericCall[] memory calls = _genericCallArray(_genericCall(address(routerA), 0, hex'a1'));

    ERC20Transfer[] memory expectedErc20 = new ERC20Transfer[](1);
    expectedErc20[0] =
      ERC20Transfer({token: address(tokenA), target: address(routerA), amount: 3 ether});

    vm.expectEmit(true, true, true, true, address(hub));
    emit TransferTokens(
      owner, owner, 0, expectedErc20, _noErc721Transfers(), new NativeTransfer[](0)
    );

    vm.prank(owner);
    (bytes[] memory results,) = hub.permit2TransferAndExecute(
      permit, targets, _noErc721Params(), calls, owner, false, signature
    );

    assertEq(tokenA.balanceOf(address(routerA)), 3 ether, 'target funded');
    assertEq(tokenA.balanceOf(owner), 7 ether, 'owner debited');
    assertEq(results.length, 1, 'one result');
    assertEq(results[0], routerA.returnData(), 'router return data returned verbatim');
    assertEq(routerA.callAt(0).caller, address(hub), 'router called by the hub');
    assertEq(routerA.callAt(0).value, 0, 'no native forwarded');
  }

  /* ---------------------------------------------------------- P2E-02 / 13 */

  /// @dev P2E-02 plus the relayer-path half of P2E-13
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

    NativeTransfer[] memory expectedNative = new NativeTransfer[](1);
    expectedNative[0] = NativeTransfer({target: address(routerB), amount: 1 ether});

    vm.expectEmit(true, true, true, true, address(hub));
    emit TransferTokens(
      relayer, owner, 1 ether, expectedErc20, _noErc721Transfers(), expectedNative
    );

    vm.prank(relayer);
    hub.permit2TransferAndExecute{value: 1 ether}(
      permit, targets, _noErc721Params(), calls, owner, false, signature
    );

    assertEq(tokenA.balanceOf(address(routerA)), 4 ether, 'target funded from the owner');
    assertEq(tokenA.balanceOf(owner), 6 ether, 'owner debited, not the relayer');
    assertEq(tokenA.balanceOf(relayer), 0, 'relayer never holds the tokens');
    assertEq(address(routerB).balance, 1 ether, 'native forwarded to the call');
    assertEq(routerB.callAt(0).value, 1 ether, 'router saw the forwarded value');
  }

  /* -------------------------------------------------------------- P2E-03 */

  /// @dev P2E-03 — the witness pins `msg.sender`, so another submitter cannot replay it
  function test_witnessBindsRelayer_otherSubmitterReverts() public {
    _fundOwner(tokenA, 10 ether);

    ISignatureTransfer.PermitBatchTransferFrom memory permit =
      _permitBatch([address(tokenA)].toMemoryArray(), [uint256(2 ether)].toMemoryArray(), 0);

    address[] memory targets = [address(routerA)].toMemoryArray();
    GenericCall[] memory calls = _genericCallArray(_genericCall(address(routerA), 0, hex'c3'));

    bytes memory signature =
      _signRelayerWitness(permit, relayer, targets, _noErc721Transfers(), calls);

    // The signed relayer can spend it
    vm.expectRevert(Permit2Mock.InvalidSigner.selector);
    vm.prank(outsider);
    hub.permit2TransferAndExecute(
      permit, targets, _noErc721Params(), calls, owner, false, signature
    );

    vm.prank(relayer);
    hub.permit2TransferAndExecute(
      permit, targets, _noErc721Params(), calls, owner, false, signature
    );
    assertEq(tokenA.balanceOf(address(routerA)), 2 ether, 'the signed relayer still succeeds');
  }

  /* -------------------------------------------------------------- P2E-04 */

  /// @dev P2E-04 — only the ERC20 targets differ from what was signed
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
      permit, alteredTargets, _noErc721Params(), calls, owner, false, signature
    );

    // The signed target list is otherwise identical, so only the witness rejected the call above
    vm.prank(relayer);
    hub.permit2TransferAndExecute(
      permit, signedTargets, _noErc721Params(), calls, owner, false, signature
    );

    assertEq(tokenA.balanceOf(address(routerB)), 0, 'no tokens reached the altered target');
    assertEq(tokenA.balanceOf(address(routerA)), 2 ether, 'the signed target was funded');
  }

  /* -------------------------------------------------------------- P2E-05 */

  /// @dev P2E-05 — only the ERC721 movement differs; the approval is in place either way
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
      false,
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
      false,
      signature
    );

    // Exactly what was signed goes through, proving the approvals were never the blocker
    vm.prank(relayer);
    hub.permit2TransferAndExecute(
      permit,
      targets,
      _erc721ParamsArray(_erc721Params(address(nft), 1, recipient, '')),
      calls,
      owner,
      false,
      signature
    );
    assertEq(nft.ownerOf(1), recipient, 'signed ERC721 movement executed');
    assertEq(nft.ownerOf(2), owner, 'unsigned token untouched');
  }

  /* -------------------------------------------------------------- P2E-06 */

  /// @dev P2E-06 — only the generic calls differ, one field at a time
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
      false,
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
      false,
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
      false,
      signature
    );

    // The exact signed call executes
    vm.prank(relayer);
    hub.permit2TransferAndExecute(
      permit, targets, _noErc721Params(), signedCalls, owner, false, signature
    );
    assertEq(routerA.callCount(), 1, 'only the signed call ever ran');
    assertEq(routerB.callCount(), 0, 'the altered router was never reached');
  }

  /* -------------------------------------------------------------- P2E-07 */

  /// @dev P2E-07 — `checkLengths` is the innermost modifier, so this is the hub's own error
  function test_revertsWhenTargetsAndPermittedLengthsDiffer() public {
    _fundOwner(tokenA, 10 ether);

    ISignatureTransfer.PermitBatchTransferFrom memory permit =
      _permitBatch([address(tokenA)].toMemoryArray(), [uint256(1 ether)].toMemoryArray(), 0);
    bytes memory signature = _signPermit2(ownerWallet, permit, address(hub));

    address[] memory targets = [address(routerA), address(routerB)].toMemoryArray();

    vm.expectRevert(ICommon.MismatchedArrayLengths.selector);
    vm.prank(owner);
    hub.permit2TransferAndExecute(
      permit, targets, _noErc721Params(), _noGenericCalls(), owner, false, signature
    );
  }

  /* -------------------------------------------------------------- P2E-08 */

  /// @dev P2E-08 — Permit2 rejects a permit whose deadline has passed
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
      false,
      signature
    );
  }

  /* -------------------------------------------------------------- P2E-09 */

  /// @dev P2E-09 — the unordered nonce cannot be spent twice
  function test_revertsOnNonceReuse() public {
    _fundOwner(tokenA, 10 ether);

    ISignatureTransfer.PermitBatchTransferFrom memory permit =
      _permitBatch([address(tokenA)].toMemoryArray(), [uint256(3 ether)].toMemoryArray(), 7);
    bytes memory signature = _signPermit2(ownerWallet, permit, address(hub));
    address[] memory targets = [address(routerA)].toMemoryArray();

    vm.prank(owner);
    hub.permit2TransferAndExecute(
      permit, targets, _noErc721Params(), _noGenericCalls(), owner, false, signature
    );
    assertEq(tokenA.balanceOf(address(routerA)), 3 ether, 'first use succeeds');

    vm.expectRevert(Permit2Mock.InvalidNonce.selector);
    vm.prank(owner);
    hub.permit2TransferAndExecute(
      permit, targets, _noErc721Params(), _noGenericCalls(), owner, false, signature
    );

    assertEq(tokenA.balanceOf(address(routerA)), 3 ether, 'replay moved nothing');
  }

  /* -------------------------------------------------------------- P2E-10 */

  /// @dev P2E-10 — a signature from another wallet does not recover to the claimed owner
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
      false,
      signature
    );
  }

  /* -------------------------------------------------------------- P2E-11 */

  /// @dev P2E-11 — each permitted token goes to the index-aligned target, at its own amount
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
      false,
      signature
    );

    assertEq(tokenA.balanceOf(address(routerA)), 2 ether, 'tokenA to routerA');
    assertEq(tokenB.balanceOf(address(routerB)), 5 ether, 'tokenB to routerB');
    assertEq(tokenA.balanceOf(address(routerB)), 0, 'tokenA did not leak to routerB');
    assertEq(tokenB.balanceOf(address(routerA)), 0, 'tokenB did not leak to routerA');
    assertEq(tokenA.balanceOf(owner), 8 ether, 'owner debited tokenA');
    assertEq(tokenB.balanceOf(owner), 5 ether, 'owner debited tokenB');
  }

  /* -------------------------------------------------------------- P2E-12 */

  /// @dev P2E-12 — `erc721Params[i].permitTransfer(owner)` pulls from the owner, not the submitter
  function test_erc721IsPulledFromOwnerNotCaller() public {
    _fundOwner(tokenA, 10 ether);
    nft.mint(owner, 42);
    nft.mint(relayer, 43);
    vm.prank(owner);
    nft.setApprovalForAll(address(hub), true);
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
      false,
      signature
    );

    assertEq(nft.ownerOf(42), recipient, "the owner's token moved");
    assertEq(nft.ownerOf(43), relayer, "the relayer's own token was untouched");
    assertEq(tokenA.balanceOf(address(routerA)), 1 ether, 'ERC20 leg also pulled from the owner');
    assertEq(tokenA.balanceOf(owner), 9 ether, 'owner debited');
  }

  /* -------------------------------------------------------------- P2E-14 */

  /// @dev P2E-14 — every router in the batch reads the owner back, even on the relayer path
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
    hub.permit2TransferAndExecute(
      permit, targets, _noErc721Params(), calls, owner, false, signature
    );

    assertEq(routerA.callAt(0).observedMsgSender, owner, 'routerA observed the owner');
    assertEq(routerB.callAt(0).observedMsgSender, owner, 'routerB observed the owner');
    assertEq(routerA.callAt(0).caller, address(hub), 'the hub is still the EVM caller');
    assertEq(routerB.callAt(0).caller, address(hub), 'the hub is still the EVM caller');
    assertEq(hub.msgSender(), address(0), 'owner cleared after the call');
  }

  /* -------------------------------------------------------------- P2E-15 */

  /// @dev P2E-15 — `whenNotPaused` is the outermost modifier
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
      false,
      signature
    );
  }

  /* -------------------------------------------------------------- P2E-16 */

  /// @dev P2E-16 — a call may spend its whole `msg.value` but none of the hub's own balance
  function test_nativeOverspendRevertsAndEqualBoundarySucceeds() public {
    _fundOwner(tokenA, 10 ether);
    vm.deal(owner, 10 ether);
    // Pre-existing hub balance; the hub has no receive(), so it can only be funded this way
    vm.deal(address(hub), 5 ether);

    address[] memory targets = [address(routerA)].toMemoryArray();
    GenericCall[] memory calls = _genericCallArray(_genericCall(address(routerA), 2 ether, hex'01'));

    ISignatureTransfer.PermitBatchTransferFrom memory overspendPermit =
      _permitBatch([address(tokenA)].toMemoryArray(), [uint256(1 ether)].toMemoryArray(), 0);
    bytes memory overspendSignature = _signPermit2(ownerWallet, overspendPermit, address(hub));

    vm.expectRevert(IKSAllowanceHubV2.NativeTokenOverspent.selector);
    vm.prank(owner);
    hub.permit2TransferAndExecute{value: 1 ether}(
      overspendPermit, targets, _noErc721Params(), calls, owner, false, overspendSignature
    );

    ISignatureTransfer.PermitBatchTransferFrom memory boundaryPermit =
      _permitBatch([address(tokenA)].toMemoryArray(), [uint256(1 ether)].toMemoryArray(), 1);
    bytes memory boundarySignature = _signPermit2(ownerWallet, boundaryPermit, address(hub));

    vm.prank(owner);
    hub.permit2TransferAndExecute{value: 2 ether}(
      boundaryPermit, targets, _noErc721Params(), calls, owner, false, boundarySignature
    );

    assertEq(address(routerA).balance, 2 ether, 'the boundary call forwarded its whole msg.value');
    assertEq(address(hub).balance, 5 ether, 'the hub kept its pre-existing balance');
    assertEq(tokenA.balanceOf(address(routerA)), 1 ether, 'only the boundary call moved tokens');
  }

  /* -------------------------------------------------------------- P2E-17 */

  /// @dev P2E-17 — `_executeGenericCalls` role-checks every router
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
      false,
      signature
    );

    assertEq(unlistedRouter.callCount(), 0, 'the unlisted router was never called');
  }

  /* -------------------------------------------------------------- P2E-18 */

  /// @dev P2E-18 — the transient lock rejects a reentrant entrypoint call
  function test_revertsOnReentry() public {
    _fundOwner(tokenA, 10 ether);

    ISignatureTransfer.PermitBatchTransferFrom memory innerPermit;
    innerPermit.permitted = new ISignatureTransfer.TokenPermissions[](0);
    innerPermit.nonce = 99;
    innerPermit.deadline = DEFAULT_DEADLINE;

    reentrantRouter.setReentrantCalldata(
      abi.encodeCall(
        hub.permit2TransferAndExecute,
        (innerPermit, new address[](0), _noErc721Params(), _noGenericCalls(), owner, false, hex'')
      ),
      false
    );

    ISignatureTransfer.PermitBatchTransferFrom memory permit =
      _permitBatch([address(tokenA)].toMemoryArray(), [uint256(1 ether)].toMemoryArray(), 0);
    bytes memory signature = _signPermit2(ownerWallet, permit, address(hub));

    vm.expectRevert(IKSAllowanceHubV2.AlreadyLocked.selector);
    vm.prank(owner);
    hub.permit2TransferAndExecute(
      permit,
      [address(routerA)].toMemoryArray(),
      _noErc721Params(),
      _genericCallArray(_genericCall(address(reentrantRouter), 0, hex'01')),
      owner,
      false,
      signature
    );
  }

  /* -------------------------------------------------------------- P2E-19 */

  /// @dev P2E-19 — Permit2 skips a zero requested amount, but the hub still reports the entry
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
      false,
      signature
    );
    Vm.Log[] memory logs = vm.getRecordedLogs();

    bool foundTransferTokens;
    for (uint256 i = 0; i < logs.length; i++) {
      assertTrue(logs[i].emitter != address(tokenA), 'the zero-amount token emitted nothing');

      if (logs[i].topics[0] == TRANSFER_TOKENS_TOPIC && logs[i].emitter == address(hub)) {
        foundTransferTokens = true;
        (, ERC20Transfer[] memory erc20Transfers,,) =
          abi.decode(logs[i].data, (uint256, ERC20Transfer[], ERC721Transfer[], NativeTransfer[]));

        assertEq(erc20Transfers.length, 2, 'both entries reported');
        assertEq(erc20Transfers[0].token, address(tokenA), 'zero entry token reported');
        assertEq(erc20Transfers[0].target, address(routerA), 'zero entry target reported');
        assertEq(erc20Transfers[0].amount, 0, 'zero entry amount reported');
        assertEq(erc20Transfers[1].amount, 2 ether, 'funded entry reported');
      }
    }

    assertTrue(foundTransferTokens, 'TransferTokens emitted');
    assertEq(tokenA.balanceOf(owner), 5 ether, 'no tokenA left the owner');
    assertEq(tokenB.balanceOf(address(routerB)), 2 ether, 'the funded leg still executed');
  }

  /* -------------------------------------------------------------- P2E-20 */

  /// @dev P2E-20 — owner debits equal the permitted amounts and the nonce bit is consumed once
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
      permit, targets, _noErc721Params(), _noGenericCalls(), owner, false, signature
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

  /* --------------------------------------------------- anyRelayer flag */

  /// @dev An owner that signed for `ANY_ADDRESS` can be relayed by an address it never named
  function test_anyRelayerRelay_unnamedSubmitterExecutesSignedBatch() public {
    _fundOwner(tokenA, 10 ether);

    ISignatureTransfer.PermitBatchTransferFrom memory permit =
      _permitBatch([address(tokenA)].toMemoryArray(), [uint256(3 ether)].toMemoryArray(), 0);

    address[] memory targets = [address(routerA)].toMemoryArray();
    GenericCall[] memory calls = _genericCallArray(_genericCall(address(routerA), 0, hex'f1'));

    bytes memory signature =
      _signRelayerWitness(permit, ANY_ADDRESS, targets, _noErc721Transfers(), calls);

    ERC20Transfer[] memory expectedErc20 = new ERC20Transfer[](1);
    expectedErc20[0] =
      ERC20Transfer({token: address(tokenA), target: address(routerA), amount: 3 ether});

    // `outsider` is neither the owner nor named anywhere in what the owner signed
    vm.expectEmit(true, true, true, true, address(hub));
    emit TransferTokens(
      outsider, owner, 0, expectedErc20, _noErc721Transfers(), new NativeTransfer[](0)
    );

    vm.prank(outsider);
    hub.permit2TransferAndExecute(permit, targets, _noErc721Params(), calls, owner, true, signature);

    assertEq(tokenA.balanceOf(address(routerA)), 3 ether, 'the signed target was funded');
    assertEq(tokenA.balanceOf(owner), 7 ether, 'the owner paid, not the submitter');
    assertEq(tokenA.balanceOf(outsider), 0, 'the submitter never holds the tokens');
    assertEq(routerA.callAt(0).observedMsgSender, owner, 'the router observed the owner');
    assertEq(routerA.callAt(0).caller, address(hub), 'the hub is still the EVM caller');
  }

  /// @dev Two unrelated submitters each ride their own `ANY_ADDRESS` signature, so it binds no one
  function test_anyRelayerSignatureIsNotBoundToASingleSubmitter() public {
    _fundOwner(tokenA, 10 ether);

    address submitterOne = makeAddr('submitterOne');
    address submitterTwo = makeAddr('submitterTwo');

    address[] memory targets = [address(routerA)].toMemoryArray();
    GenericCall[] memory calls = _noGenericCalls();

    ISignatureTransfer.PermitBatchTransferFrom memory permitOne =
      _permitBatch([address(tokenA)].toMemoryArray(), [uint256(2 ether)].toMemoryArray(), 11);
    bytes memory signatureOne =
      _signRelayerWitness(permitOne, ANY_ADDRESS, targets, _noErc721Transfers(), calls);

    ISignatureTransfer.PermitBatchTransferFrom memory permitTwo =
      _permitBatch([address(tokenA)].toMemoryArray(), [uint256(5 ether)].toMemoryArray(), 12);
    bytes memory signatureTwo =
      _signRelayerWitness(permitTwo, ANY_ADDRESS, targets, _noErc721Transfers(), calls);

    vm.prank(submitterOne);
    hub.permit2TransferAndExecute(
      permitOne, targets, _noErc721Params(), calls, owner, true, signatureOne
    );
    assertEq(tokenA.balanceOf(address(routerA)), 2 ether, 'the first submitter moved its batch');

    vm.prank(submitterTwo);
    hub.permit2TransferAndExecute(
      permitTwo, targets, _noErc721Params(), calls, owner, true, signatureTwo
    );

    assertEq(tokenA.balanceOf(address(routerA)), 7 ether, 'the second submitter moved its batch');
    assertEq(tokenA.balanceOf(owner), 3 ether, 'the owner funded both batches');
    assertEq(tokenA.balanceOf(submitterOne), 0, 'the first submitter never holds the tokens');
    assertEq(tokenA.balanceOf(submitterTwo), 0, 'the second submitter never holds the tokens');
    assertEq(
      permit2.nonceBitmap(owner, 0), (1 << 11) | (1 << 12), 'one nonce bit consumed per batch'
    );
  }

  /// @dev A caller-bound signature cannot be upgraded into a anyRelayer one by the submitter
  function test_anyRelayerFlagCannotBeForgedUpward() public {
    _fundOwner(tokenA, 10 ether);

    ISignatureTransfer.PermitBatchTransferFrom memory permit =
      _permitBatch([address(tokenA)].toMemoryArray(), [uint256(2 ether)].toMemoryArray(), 0);
    address[] memory targets = [address(routerA)].toMemoryArray();
    GenericCall[] memory calls = _genericCallArray(_genericCall(address(routerA), 0, hex'f3'));

    // Bound to `relayer`, so the anyRelayer digest is one the owner never signed
    bytes memory signature =
      _signRelayerWitness(permit, relayer, targets, _noErc721Transfers(), calls);

    vm.expectRevert(Permit2Mock.InvalidSigner.selector);
    vm.prank(outsider);
    hub.permit2TransferAndExecute(permit, targets, _noErc721Params(), calls, owner, true, signature);

    assertEq(tokenA.balanceOf(address(routerA)), 0, 'the forged submission moved nothing');
    assertEq(permit2.nonceBitmap(owner, 0), 0, 'the forged submission consumed no nonce');

    // Positive control: the named relayer on the caller-bound flag still goes through
    vm.prank(relayer);
    hub.permit2TransferAndExecute(
      permit, targets, _noErc721Params(), calls, owner, false, signature
    );

    assertEq(tokenA.balanceOf(address(routerA)), 2 ether, 'the named relayer still succeeds');
    assertEq(tokenA.balanceOf(owner), 8 ether, 'the owner was debited exactly once');
    assertEq(routerA.callCount(), 1, 'the call ran only on the accepted submission');
    assertEq(permit2.nonceBitmap(owner, 0), 1, 'exactly one nonce bit consumed');
  }

  /// @dev A anyRelayer signature is equally unusable with the flag dropped
  function test_anyRelayerFlagCannotBeDropped() public {
    _fundOwner(tokenA, 10 ether);

    ISignatureTransfer.PermitBatchTransferFrom memory permit =
      _permitBatch([address(tokenA)].toMemoryArray(), [uint256(4 ether)].toMemoryArray(), 0);
    address[] memory targets = [address(routerA)].toMemoryArray();
    GenericCall[] memory calls = _genericCallArray(_genericCall(address(routerA), 0, hex'f4'));

    bytes memory signature =
      _signRelayerWitness(permit, ANY_ADDRESS, targets, _noErc721Transfers(), calls);

    vm.expectRevert(Permit2Mock.InvalidSigner.selector);
    vm.prank(outsider);
    hub.permit2TransferAndExecute(
      permit, targets, _noErc721Params(), calls, owner, false, signature
    );

    assertEq(tokenA.balanceOf(address(routerA)), 0, 'dropping the flag moved nothing');
    assertEq(permit2.nonceBitmap(owner, 0), 0, 'dropping the flag consumed no nonce');

    // Positive control: the identical signature and submitter, with the flag kept
    vm.prank(outsider);
    hub.permit2TransferAndExecute(permit, targets, _noErc721Params(), calls, owner, true, signature);

    assertEq(tokenA.balanceOf(address(routerA)), 4 ether, 'the same signature succeeds with it');
    assertEq(tokenA.balanceOf(owner), 6 ether, 'the owner was debited exactly once');
    assertEq(routerA.callCount(), 1, 'the call ran only on the accepted submission');
    assertEq(permit2.nonceBitmap(owner, 0), 1, 'exactly one nonce bit consumed');
  }

  /// @dev AnyRelayer relay stays safe because the witness still pins the whole payload
  function test_anyRelayerStillBindsTargetsErc721AndGenericCalls() public {
    _fundOwner(tokenA, 10 ether);
    nft.mint(owner, 1);
    nft.mint(owner, 2);
    vm.prank(owner);
    nft.setApprovalForAll(address(hub), true);

    ISignatureTransfer.PermitBatchTransferFrom memory permit =
      _permitBatch([address(tokenA)].toMemoryArray(), [uint256(1 ether)].toMemoryArray(), 0);

    address[] memory signedTargets = [address(routerA)].toMemoryArray();
    ERC721Transfer[] memory signedErc721 =
      _erc721TransferArray(ERC721Transfer({token: address(nft), tokenId: 1, target: recipient}));
    GenericCall[] memory signedCalls = _genericCallArray(_genericCall(address(routerA), 0, hex'f5'));

    bytes memory signature =
      _signRelayerWitness(permit, ANY_ADDRESS, signedTargets, signedErc721, signedCalls);

    // Altered ERC20 target — routerB is whitelisted too, so only the witness can reject this
    vm.expectRevert(Permit2Mock.InvalidSigner.selector);
    vm.prank(outsider);
    hub.permit2TransferAndExecute(
      permit,
      [address(routerB)].toMemoryArray(),
      _erc721ParamsArray(_erc721Params(address(nft), 1, recipient, '')),
      signedCalls,
      owner,
      true,
      signature
    );

    // Altered ERC721 movement — token 2 is covered by the same blanket approval as token 1
    vm.expectRevert(Permit2Mock.InvalidSigner.selector);
    vm.prank(outsider);
    hub.permit2TransferAndExecute(
      permit,
      signedTargets,
      _erc721ParamsArray(_erc721Params(address(nft), 2, recipient, '')),
      signedCalls,
      owner,
      true,
      signature
    );

    // Altered generic call
    vm.expectRevert(Permit2Mock.InvalidSigner.selector);
    vm.prank(outsider);
    hub.permit2TransferAndExecute(
      permit,
      signedTargets,
      _erc721ParamsArray(_erc721Params(address(nft), 1, recipient, '')),
      _genericCallArray(_genericCall(address(routerB), 0, hex'f5')),
      owner,
      true,
      signature
    );

    // Positive control: exactly what was signed, from the same anonymous submitter
    vm.prank(outsider);
    hub.permit2TransferAndExecute(
      permit,
      signedTargets,
      _erc721ParamsArray(_erc721Params(address(nft), 1, recipient, '')),
      signedCalls,
      owner,
      true,
      signature
    );

    assertEq(tokenA.balanceOf(address(routerA)), 1 ether, 'the signed ERC20 target was funded');
    assertEq(tokenA.balanceOf(address(routerB)), 0, 'no tokens reached the altered target');
    assertEq(nft.ownerOf(1), recipient, 'the signed ERC721 movement executed');
    assertEq(nft.ownerOf(2), owner, 'the unsigned token stayed with the owner');
    assertEq(routerA.callCount(), 1, 'only the signed call ever ran');
    assertEq(routerB.callCount(), 0, 'the altered router was never reached');
  }

  /**
   * @dev `owner == msg.sender` decides the branch on its own: the owner's transaction already pins
   * everything, so no witness is used and `anyRelayer` is ignored either way.
   */
  function test_ownerAsCallerTakesThePlainPathAndIgnoresAnyRelayer() public {
    _fundOwner(tokenA, 10 ether);

    address[] memory targets = [address(routerA)].toMemoryArray();
    GenericCall[] memory calls = _genericCallArray(_genericCall(address(routerA), 0, hex'f6'));

    // A plain, witness-free signature is accepted with the flag set...
    ISignatureTransfer.PermitBatchTransferFrom memory first =
      _permitBatch([address(tokenA)].toMemoryArray(), [uint256(3 ether)].toMemoryArray(), 0);
    // Signed before the prank: `_signPermit2` makes an external call that would consume it.
    bytes memory firstSignature = _signPermit2(ownerWallet, first, address(hub));
    vm.prank(owner);
    hub.permit2TransferAndExecute(
      first, targets, _noErc721Params(), calls, owner, true, firstSignature
    );

    // ...and equally with it cleared, because the flag never reaches the branch.
    ISignatureTransfer.PermitBatchTransferFrom memory second =
      _permitBatch([address(tokenA)].toMemoryArray(), [uint256(1 ether)].toMemoryArray(), 1);
    bytes memory secondSignature = _signPermit2(ownerWallet, second, address(hub));
    vm.prank(owner);
    hub.permit2TransferAndExecute(
      second, targets, _noErc721Params(), calls, owner, false, secondSignature
    );

    assertEq(tokenA.balanceOf(address(routerA)), 4 ether, 'both batches funded the target');
    assertEq(tokenA.balanceOf(owner), 6 ether, 'the owner was debited by both');
    assertEq(routerA.callCount(), 2, 'one call per batch');
    assertEq(permit2.nonceBitmap(owner, 0), 3, 'one nonce bit per batch');

    // An `ANY_ADDRESS` witness signature is useless to the owner: the plain path never rebuilds it.
    ISignatureTransfer.PermitBatchTransferFrom memory third =
      _permitBatch([address(tokenA)].toMemoryArray(), [uint256(1 ether)].toMemoryArray(), 2);
    bytes memory witnessSignature =
      _signRelayerWitness(third, ANY_ADDRESS, targets, _noErc721Transfers(), calls);

    vm.expectRevert(Permit2Mock.InvalidSigner.selector);
    vm.prank(owner);
    hub.permit2TransferAndExecute(
      third, targets, _noErc721Params(), calls, owner, true, witnessSignature
    );

    // That same anyRelayer signature is still good when somebody else relays it.
    vm.prank(outsider);
    hub.permit2TransferAndExecute(
      third, targets, _noErc721Params(), calls, owner, true, witnessSignature
    );

    assertEq(tokenA.balanceOf(address(routerA)), 5 ether, 'the relayed batch settled');
  }

  /// @dev Being submittable by ANY_ADDRESS does not make it submittable twice
  function test_anyRelayerSubmissionIsNotReplayable() public {
    _fundOwner(tokenA, 10 ether);

    uint256 nonce = 300; // spans a non-zero word position of the nonce bitmap
    uint256 wordPos = nonce >> 8;
    uint256 bit = 1 << uint8(nonce);

    ISignatureTransfer.PermitBatchTransferFrom memory permit =
      _permitBatch([address(tokenA)].toMemoryArray(), [uint256(2 ether)].toMemoryArray(), nonce);
    address[] memory targets = [address(routerA)].toMemoryArray();
    GenericCall[] memory calls = _noGenericCalls();

    bytes memory signature =
      _signRelayerWitness(permit, ANY_ADDRESS, targets, _noErc721Transfers(), calls);

    assertEq(permit2.nonceBitmap(owner, wordPos), 0, 'nonce word untouched before');

    address firstSubmitter = makeAddr('firstSubmitter');
    address secondSubmitter = makeAddr('secondSubmitter');

    vm.prank(firstSubmitter);
    hub.permit2TransferAndExecute(permit, targets, _noErc721Params(), calls, owner, true, signature);

    assertEq(tokenA.balanceOf(address(routerA)), 2 ether, 'the first submission went through');
    assertEq(permit2.nonceBitmap(owner, wordPos), bit, 'exactly one nonce bit consumed');

    // A second, unrelated caller cannot ride the same anyRelayer signature
    vm.expectRevert(Permit2Mock.InvalidNonce.selector);
    vm.prank(secondSubmitter);
    hub.permit2TransferAndExecute(permit, targets, _noErc721Params(), calls, owner, true, signature);

    assertEq(tokenA.balanceOf(address(routerA)), 2 ether, 'the replay moved nothing');
    assertEq(tokenA.balanceOf(owner), 8 ether, 'the owner was debited exactly once');
    assertEq(permit2.nonceBitmap(owner, wordPos), bit, 'the nonce bit was consumed exactly once');
  }

  /* ------------------------------------------------------- local helpers */

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
