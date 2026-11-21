// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Vm} from 'forge-std/Vm.sol';
import {IMulticall3} from 'forge-std/interfaces/IMulticall3.sol';

import {SchemaHash} from './SchemaHash.sol';
import {V2TestBase} from './V2TestBase.sol';

import {PermitHash} from '../libraries/PermitHash.sol';
import {CalleeMock} from '../mocks/CalleeMocks.sol';
import {HookMock} from '../mocks/HookMock.sol';
import {ERC20Mock, ERC721Mock} from '../mocks/TokenMocks.sol';

import {KSAllowanceHubV2} from '../../src/KSAllowanceHubV2.sol';

import {IKSAllowanceHubV2} from '../../src/interfaces/IKSAllowanceHubV2.sol';

import {IAuthDelegator} from '../../src/interfaces/base/IAuthDelegator.sol';
import {IUnorderedNonce} from '../../src/interfaces/base/IUnorderedNonce.sol';

import {
  AHV2Order,
  PermitBatchWitnessTransferFrom as Permit2Order
} from '../../src/types/AHV2Order.sol';
import {AHV2Solution} from '../../src/types/AHV2Solution.sol';
import {AuthDelegation} from '../../src/types/AuthDelegation.sol';
import {CallParams} from '../../src/types/CallParams.sol';
import {ERC20Allowance} from '../../src/types/ERC20Allowance.sol';
import {ERC20Transfer} from '../../src/types/ERC20Transfer.sol';
import {ERC721Approval} from '../../src/types/ERC721Approval.sol';
import {ERC721Transfer} from '../../src/types/ERC721Transfer.sol';
import {HookParams} from '../../src/types/HookParams.sol';
import {SolutionApproval} from '../../src/types/SolutionApproval.sol';

import {IERC20} from 'openzeppelin-contracts/contracts/token/ERC20/IERC20.sol';

/**
 * @title HubBase
 * @notice Contract base for the {KSAllowanceHubV2} batches: deploys the hub against the real
 * Permit2 on a mainnet fork, wires the mocks, and builds and signs orders.
 * @dev Every signature here is produced from the literals in {V2TestBase}. Nothing in this file may
 * use a production type string, typehash or hashing library, or the suite would only prove
 * that the hub agrees with itself.
 */
abstract contract HubBase is V2TestBase {
  KSAllowanceHubV2 internal hub;

  CalleeMock internal callee;
  CalleeMock internal callee2;
  ERC721Mock internal nft;
  HookMock internal hook;
  HookMock internal hook2;

  uint256 internal constant NFT_ID = 1;

  /// @dev Hook flags, written out rather than imported
  bytes32 internal constant HOOK_BEFORE = bytes32(uint256(1));
  bytes32 internal constant HOOK_AFTER = bytes32(uint256(2));
  bytes32 internal constant HOOK_BOTH = bytes32(uint256(3));

  /// @dev The canonical Multicall3 address, written out rather than imported
  address internal multicall3 = 0xcA11bde05977b3631167028862bE2a173976CA11;

  function setUp() public virtual {
    permit2 = _deployPermit2();
    token18 = address(new ERC20Mock('Token Eighteen', 'T18', 18));
    token6 = address(new ERC20Mock('Token Six', 'T6', 6));

    (owner, ownerKey) = makeAddrAndKey('owner');

    callee = new CalleeMock();
    callee2 = new CalleeMock();
    nft = new ERC721Mock();
    hook = new HookMock();
    hook2 = new HookMock();

    address[] memory guardians = new address[](1);
    guardians[0] = guardian;
    address[] memory rescuers = new address[](1);
    rescuers[0] = rescuer;
    address[] memory callees = new address[](2);
    callees[0] = address(callee);
    callees[1] = address(callee2);

    vm.etch(multicall3, vm.getDeployedCode(string.concat(_artifactsDir(), 'Multicall3.json')));
    hub = new KSAllowanceHubV2(admin, guardians, rescuers, callees, permit2, multicall3);

    _fundOwner();

    vm.label(address(hub), 'hub');
    vm.label(multicall3, 'multicall3');
    vm.label(address(callee), 'callee');
    vm.label(address(callee2), 'callee2');
    vm.label(address(hook), 'hook');
    vm.label(address(hook2), 'hook2');
    vm.label(permit2, 'permit2');
    vm.label(token18, 'token18');
    vm.label(token6, 'token6');
  }

  /// @dev One {IMulticall3-Call3} per target and payload; the entry at index `i` allows failure
  /// when bit `i` of `allowFailureMask` is set
  function _call3s(address[] memory targets, bytes[] memory data, uint256 allowFailureMask)
    internal
    pure
    returns (IMulticall3.Call3[] memory out)
  {
    out = new IMulticall3.Call3[](targets.length);
    for (uint256 i = 0; i < targets.length; i++) {
      out[i] = IMulticall3.Call3({
        target: targets[i], allowFailure: (allowFailureMask >> i) & 1 == 1, callData: data[i]
      });
    }
  }

  function _fundOwner() internal {
    ERC20Mock(token18).mint(owner, 1000 ether);
    ERC20Mock(token6).mint(owner, 1_000_000e6);
    nft.mint(owner, NFT_ID);

    vm.startPrank(owner);
    IERC20(token18).approve(permit2, type(uint256).max);
    IERC20(token6).approve(permit2, type(uint256).max);
    IERC20(token18).approve(address(hub), type(uint256).max);
    IERC20(token6).approve(address(hub), type(uint256).max);
    nft.setApprovalForAll(address(hub), true);
    vm.stopPrank();
  }

  /**
   * @dev The owner's Permit2 allowance to the hub, which `usePermit2Allowances` draws on. The
   * amount is finite because Permit2 does not decrement `type(uint160).max`, so an unlimited
   * allowance could not distinguish the two pull rails.
   */
  function _grantPermit2Allowance(address token, uint160 amount) internal {
    vm.prank(owner);
    (bool ok,) = permit2.call(
      abi.encodeWithSignature(
        'approve(address,address,uint160,uint48)',
        token,
        address(hub),
        amount,
        uint48(vm.getBlockTimestamp() + 30 days)
      )
    );
    assertTrue(ok, 'permit2 approve');
  }

  /// @dev How much of `token` the hub may still pull over the owner's Permit2 allowance
  function _permit2Allowance(address token) internal view returns (uint160 allowed) {
    (bool ok, bytes memory data) = permit2.staticcall(
      abi.encodeWithSignature('allowance(address,address,address)', owner, token, address(hub))
    );
    require(ok, 'permit2 allowance');
    (allowed,,) = abi.decode(data, (uint160, uint48, uint48));
  }

  /**
   * @dev The whole {IAuthDelegator-DeadlinePassed} payload, with the argument order written out
   * here. The error carries values, so a selector-only expectation would not match it.
   */
  function _deadlinePassed(uint256 deadline) internal view returns (bytes memory) {
    return abi.encodeWithSelector(
      IAuthDelegator.DeadlinePassed.selector, deadline, vm.getBlockTimestamp()
    );
  }

  /// @dev The whole {IKSAllowanceHubV2-OrderExpired} payload
  function _orderExpired(uint256 expiration) internal view returns (bytes memory) {
    return abi.encodeWithSelector(
      IKSAllowanceHubV2.OrderExpired.selector, expiration, vm.getBlockTimestamp()
    );
  }

  /// @dev The whole {IKSAllowanceHubV2-SolutionExpired} payload
  function _solutionExpired(uint256 expiration) internal view returns (bytes memory) {
    return abi.encodeWithSelector(
      IKSAllowanceHubV2.SolutionExpired.selector, expiration, vm.getBlockTimestamp()
    );
  }

  /// @dev Selects the single `SettleOrder` the hub emitted from the fork's log stream
  function _settlementLog() internal view returns (Vm.Log memory entry) {
    Vm.Log[] memory entries = vm.getRecordedLogs();

    uint256 found;
    for (uint256 i = 0; i < entries.length; i++) {
      if (entries[i].emitter != address(hub)) {
        continue;
      }
      if (entries[i].topics.length == 0) {
        continue;
      }
      if (entries[i].topics[0] != IKSAllowanceHubV2.SettleOrder.selector) {
        continue;
      }

      entry = entries[i];
      found++;
    }

    assertEq(found, 1, 'exactly one SettleOrder per order');
  }

  /// @dev Expects the next call to emit no `RevokeNonce` from any contract
  function _expectNoRevokeNonce() internal {
    vm.expectEmit(false, false, false, false, 0);
    emit IUnorderedNonce.RevokeNonce(bytes32(0), 0);
  }

  function _topicAddress(bytes32 topic) internal pure returns (address) {
    return address(uint160(uint256(topic)));
  }

  // ---------------------------------------------------------------------------------------------
  // Order pieces
  // ---------------------------------------------------------------------------------------------

  function _tokenTransfer(uint160 amount) internal view returns (ERC20Transfer memory) {
    return ERC20Transfer({token: token18, target: address(callee), amount: amount});
  }

  function _nftTransfer(address target) internal view returns (ERC721Transfer memory) {
    return ERC721Transfer({token: address(nft), tokenId: NFT_ID, target: target});
  }

  /// @dev An order's ERC20 allowance: the amount that may leave the owner, with no target
  function _tokenAllowance(uint160 amount) internal view returns (ERC20Allowance memory) {
    return ERC20Allowance({token: token18, amount: amount});
  }

  /// @dev An order's NFT approval
  function _nftApproval() internal view returns (ERC721Approval memory) {
    return ERC721Approval({token: address(nft), tokenId: NFT_ID});
  }

  function _calleeCall(bytes memory ownerData) internal view returns (CallParams memory) {
    return CallParams({callee: address(callee), ownerData: ownerData});
  }

  /// @dev A hook entry with data `hex'11'`
  function _hook(HookMock h, bytes32 flags) internal pure returns (HookParams memory) {
    return _hook(h, flags, hex'11');
  }

  function _hook(HookMock h, bytes32 flags, bytes memory data)
    internal
    pure
    returns (HookParams memory)
  {
    return HookParams({hook: address(h), flags: flags, data: data});
  }

  // ---------------------------------------------------------------------------------------------
  // Order building
  // ---------------------------------------------------------------------------------------------

  /// @dev An order with the zero authenticator
  function _ahv2Order(
    address orderExclusiveCaller,
    ERC20Allowance[] memory erc20Allowances,
    ERC721Approval[] memory erc721Approvals,
    HookParams[] memory hooks,
    CallParams[] memory orderCalls,
    address solutionApprover,
    uint256 nonce,
    uint256 expiration
  ) internal view returns (AHV2Order memory) {
    return _ahv2Order(
      address(0),
      orderExclusiveCaller,
      erc20Allowances,
      erc721Approvals,
      hooks,
      orderCalls,
      solutionApprover,
      nonce,
      expiration
    );
  }

  /// @dev As above, with the authenticator `orderAuthenticator`
  function _ahv2Order(
    address orderAuthenticator,
    address orderExclusiveCaller,
    ERC20Allowance[] memory erc20Allowances,
    ERC721Approval[] memory erc721Approvals,
    HookParams[] memory hooks,
    CallParams[] memory orderCalls,
    address solutionApprover,
    uint256 nonce,
    uint256 expiration
  ) internal view returns (AHV2Order memory) {
    return AHV2Order({
      owner: owner,
      authenticator: orderAuthenticator,
      exclusiveCaller: orderExclusiveCaller,
      erc20Allowances: erc20Allowances,
      erc721Approvals: erc721Approvals,
      hooks: hooks,
      calls: orderCalls,
      solutionApprover: solutionApprover,
      nonce: nonce,
      expiration: expiration,
      clientData: ''
    });
  }

  /// @dev Open to any submitter, any solution, plain ERC20 allowance, no NFT approval, zero
  /// authenticator
  function _openAhv2Order(
    ERC20Allowance[] memory erc20Allowances,
    HookParams[] memory hooks,
    CallParams[] memory orderCalls,
    uint256 nonce,
    uint256 expiration
  ) internal view returns (AHV2Order memory) {
    return _openAhv2Order(address(0), erc20Allowances, hooks, orderCalls, nonce, expiration);
  }

  /// @dev As above, with the authenticator `orderAuthenticator`
  function _openAhv2Order(
    address orderAuthenticator,
    ERC20Allowance[] memory erc20Allowances,
    HookParams[] memory hooks,
    CallParams[] memory orderCalls,
    uint256 nonce,
    uint256 expiration
  ) internal view returns (AHV2Order memory) {
    return _ahv2Order(
      orderAuthenticator,
      ANY,
      erc20Allowances,
      new ERC721Approval[](0),
      hooks,
      orderCalls,
      ANY,
      nonce,
      expiration
    );
  }

  function _amounts(uint160 a) internal pure returns (uint160[] memory out) {
    out = new uint160[](1);
    out[0] = a;
  }

  /// @dev A solution with nonce 0
  function _solution(
    address[] memory erc20Targets,
    uint160[] memory erc20Amounts,
    address[] memory erc721Targets,
    uint256 expiration
  ) internal pure returns (AHV2Solution memory) {
    return _solution(erc20Targets, erc20Amounts, erc721Targets, 0, expiration);
  }

  /// @dev A solution with nonce `nonce`
  function _solution(
    address[] memory erc20Targets,
    uint160[] memory erc20Amounts,
    address[] memory erc721Targets,
    uint256 nonce,
    uint256 expiration
  ) internal pure returns (AHV2Solution memory) {
    return AHV2Solution({
      erc20Targets: erc20Targets,
      erc20Amounts: erc20Amounts,
      erc721Targets: erc721Targets,
      callValues: new uint256[](0),
      solverData: new bytes[](0),
      nonce: nonce,
      expiration: expiration
    });
  }

  /**
   * @dev As above, sending the full allowance of every ERC20 transfer of `order` to `callee` and
   * every NFT transfer to `callee2`, with one zero `callValues` entry and one empty `solverData` entry
   * per call
   */
  function _solution(AHV2Order memory order, uint256 nonce, uint256 expiration)
    internal
    view
    returns (AHV2Solution memory)
  {
    address[] memory erc20Targets = new address[](order.erc20Allowances.length);
    uint160[] memory erc20Amounts = new uint160[](order.erc20Allowances.length);
    for (uint256 i = 0; i < erc20Targets.length; i++) {
      erc20Targets[i] = address(callee);
      erc20Amounts[i] = order.erc20Allowances[i].amount;
    }
    address[] memory erc721Targets = new address[](order.erc721Approvals.length);
    for (uint256 i = 0; i < erc721Targets.length; i++) {
      erc721Targets[i] = address(callee2);
    }
    AHV2Solution memory solution =
      _solution(erc20Targets, erc20Amounts, erc721Targets, nonce, expiration);
    solution.callValues = new uint256[](order.calls.length);
    solution.solverData = _solverData(order.calls.length);
    return solution;
  }

  /// @dev As above, with solution nonce 0
  function _solution(AHV2Order memory order, uint256 expiration)
    internal
    view
    returns (AHV2Solution memory)
  {
    return _solution(order, 0, expiration);
  }

  /// @dev The solution for `order` with its default targets, valid for an hour
  function _defaultSolution(AHV2Order memory order) internal view returns (AHV2Solution memory) {
    return _defaultSolution(order, 0);
  }

  /// @dev As above, with the solution nonce `nonce`
  function _defaultSolution(AHV2Order memory order, uint256 nonce)
    internal
    view
    returns (AHV2Solution memory)
  {
    return _solution(order, nonce, vm.getBlockTimestamp() + 1 hours);
  }

  // ---------------------------------------------------------------------------------------------
  // Signatures, built from the independent oracle only
  // ---------------------------------------------------------------------------------------------

  /// @dev An empty list of calls
  function _noCalls() internal pure returns (CallParams[] memory) {
    return new CallParams[](0);
  }

  /// @dev An empty list of hooks
  function _noHooks() internal pure returns (HookParams[] memory) {
    return new HookParams[](0);
  }

  /// @dev An empty list of ERC721 approvals
  function _noNfts() internal pure returns (ERC721Approval[] memory) {
    return new ERC721Approval[](0);
  }

  /// @dev The balance of `token18` held by the callee that receives the transfers
  function _calleeBalance() internal view returns (uint256) {
    return IERC20(token18).balanceOf(address(callee));
  }

  function _hubDomain() internal view returns (bytes32) {
    return lDomainSeparator('KyberSwap Allowance Hub', '2.0.0', address(hub));
  }

  /// @dev Permit2 signature by `signerKey` over a permit that also covers `order`, for another
  /// account to submit
  function _signPermit2Order(AHV2Order memory order, uint256 signerKey)
    internal
    view
    returns (bytes memory)
  {
    (address[] memory tokens, uint256[] memory amounts) = _tokensAndAmounts(order.erc20Allowances);
    bytes32 structHash = SchemaHash.permit2Order(
      Permit2Order({
        permitted: lTokenPermissions(tokens, amounts),
        spender: address(hub),
        nonce: order.nonce,
        deadline: order.expiration,
        order: order
      })
    );
    return _sign(signerKey, lTypedDataHash(_permit2DomainSeparator(), structHash));
  }

  /// @dev As above, signed by the owner
  function _signPermit2Order(AHV2Order memory order) internal view returns (bytes memory) {
    return _signPermit2Order(order, ownerKey);
  }

  /// @dev The owner's Permit2 signature over a permit that does not cover an order, for the owner
  /// to submit
  function _signPlainPermit(
    ERC20Allowance[] memory erc20Allowances,
    uint256 nonce,
    uint256 deadline
  ) internal view returns (bytes memory) {
    (address[] memory tokens, uint256[] memory amounts) = _tokensAndAmounts(erc20Allowances);
    bytes32[] memory permitted = new bytes32[](tokens.length);
    for (uint256 i = 0; i < tokens.length; i++) {
      permitted[i] =
        keccak256(abi.encode(PermitHash._TOKEN_PERMISSIONS_TYPEHASH, tokens[i], amounts[i]));
    }
    bytes32 structHash = keccak256(
      abi.encode(
        PermitHash._PERMIT_BATCH_TRANSFER_FROM_TYPEHASH,
        keccak256(abi.encodePacked(permitted)),
        address(hub),
        nonce,
        deadline
      )
    );
    return _sign(ownerKey, lTypedDataHash(_permit2DomainSeparator(), structHash));
  }

  /// @dev The signature of the account holding `key` over `order` for the zero-authenticator flow
  function _signOrder(AHV2Order memory order, uint256 key) internal view returns (bytes memory) {
    return _sign(key, lTypedDataHash(_hubDomain(), SchemaHash.ahv2Order(order)));
  }

  /// @dev As above, signed by the owner
  function _signOrder(AHV2Order memory order) internal view returns (bytes memory) {
    return _signOrder(order, ownerKey);
  }

  /// @dev The solution approval lives under the hub's own EIP-712 domain
  function _signSolutionApproval(
    uint256 signerKey,
    AHV2Order memory order,
    AHV2Solution memory solution
  ) internal view returns (bytes memory) {
    return _sign(
      signerKey,
      lTypedDataHash(
        _hubDomain(),
        SchemaHash.solutionApproval(SolutionApproval({order: order, solution: solution}))
      )
    );
  }

  function _signAuthDelegation(
    uint256 signerKey,
    address delegator,
    address authenticator,
    bool delegated,
    bytes memory data,
    uint256 nonce,
    uint256 deadline
  ) internal view returns (bytes memory) {
    return _sign(
      signerKey,
      lTypedDataHash(
        _hubDomain(),
        SchemaHash.authDelegation(
          AuthDelegation({
            owner: delegator,
            authenticator: authenticator,
            delegated: delegated,
            data: data,
            nonce: nonce,
            deadline: deadline
          })
        )
      )
    );
  }

  /**
   * @dev Submits `callData` with the top 96 bits of the word holding the token set, then submits it
   * as given. The order hash reads those words directly from calldata without masking them, so the
   * dirty payload must be refused by the field reads that settle the order. Dirty first and clean
   * second, so the clean step settling proves the payload was refused for the dirtying and not for
   * anything else it carried.
   */
  function _assertDirtyTokenWordIsRefused(address submitter, bytes memory callData) internal {
    uint256 word = type(uint256).max;
    for (uint256 i = 4; i + 32 <= callData.length; i += 32) {
      bytes32 w;
      assembly {
        w := mload(add(add(callData, 0x20), i))
      }
      if (uint256(w) == uint256(uint160(token18))) {
        word = i;
      }
    }
    assertTrue(word != type(uint256).max, 'the token word is in the payload');

    bytes memory dirty = new bytes(callData.length);
    for (uint256 i = 0; i < callData.length; i++) {
      dirty[i] = callData[i];
    }
    for (uint256 i = word; i < word + 12; i++) {
      dirty[i] = 0xff;
    }

    vm.prank(submitter);
    (bool dirtyAccepted,) = address(hub).call(dirty);
    assertFalse(dirtyAccepted, 'a dirty token word is refused');

    vm.prank(submitter);
    (bool cleanAccepted,) = address(hub).call(callData);
    assertTrue(cleanAccepted, 'and the same payload settles once the word is clean');
  }
}
