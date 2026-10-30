// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Vm} from 'forge-std/Vm.sol';

import {V2TestBase} from 'test/base/V2TestBase.sol';

import {RouterMock} from 'test/v2/mocks/RouterMock.sol';
import {ERC20Mock, ERC721Mock} from 'test/v2/mocks/TokenMocks.sol';
import {ValidatorMock} from 'test/v2/mocks/ValidatorMock.sol';

import {DeadlineChecker} from 'src/base/DeadlineChecker.sol';
import {CallsForwarder} from 'src/v2/CallsForwarder.sol';
import {KSAllowanceHubV2} from 'src/v2/KSAllowanceHubV2.sol';
import {ERC20Allowance} from 'src/v2/types/ERC20Allowance.sol';
import {ERC20Transfer} from 'src/v2/types/ERC20Transfer.sol';
import {ERC721Approval} from 'src/v2/types/ERC721Approval.sol';
import {ERC721Transfer} from 'src/v2/types/ERC721Transfer.sol';
import {ExecutionOrder} from 'src/v2/types/ExecutionOrder.sol';
import {ExecutionWitness} from 'src/v2/types/ExecutionWitness.sol';
import {FulfillmentOrder} from 'src/v2/types/FulfillmentOrder.sol';
import {FulfillmentSolution} from 'src/v2/types/FulfillmentSolution.sol';
import {FulfillmentWitness} from 'src/v2/types/FulfillmentWitness.sol';
import {GenericCall} from 'src/v2/types/GenericCall.sol';
import {ValidationParams} from 'src/v2/types/ValidationParams.sol';

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
  CallsForwarder internal callsForwarder;

  RouterMock internal router;
  RouterMock internal router2;
  ERC721Mock internal nft;
  ValidatorMock internal validator;
  ValidatorMock internal validator2;

  uint256 internal constant NFT_ID = 1;

  /**
   * @dev Transcribed from {IKSAllowanceHubV2-TransferTokens}, never imported: an expected topic
   * taken from the contract under test would agree with a wrong one.
   */
  bytes32 internal constant TRANSFER_TOKENS_TOPIC = keccak256(
    'TransferTokens(address,address,bytes32,(address,address,uint160)[],(address,uint256,address)[],(address,uint256)[])'
  );

  function setUp() public virtual {
    permit2 = _deployPermit2();
    token18 = address(new ERC20Mock('Token Eighteen', 'T18', 18));
    token6 = address(new ERC20Mock('Token Six', 'T6', 6));

    (owner, ownerKey) = makeAddrAndKey('owner');

    router = new RouterMock();
    router2 = new RouterMock();
    nft = new ERC721Mock();
    validator = new ValidatorMock();
    validator2 = new ValidatorMock();

    address[] memory guardians = new address[](1);
    guardians[0] = guardian;
    address[] memory rescuers = new address[](1);
    rescuers[0] = rescuer;
    address[] memory routers = new address[](2);
    routers[0] = address(router);
    routers[1] = address(router2);

    callsForwarder = new CallsForwarder();
    hub =
      new KSAllowanceHubV2(admin, guardians, rescuers, routers, permit2, address(callsForwarder));

    _fundOwner();

    vm.label(address(hub), 'hub');
    vm.label(address(callsForwarder), 'callsForwarder');
    vm.label(address(router), 'router');
    vm.label(permit2, 'permit2');
    vm.label(token18, 'token18');
    vm.label(token6, 'token6');
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
        uint48(block.timestamp + 30 days)
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
   * @dev The whole {DeadlineChecker-DeadlinePassed} payload, with the argument order written out
   * here. The error carries values, so a selector-only expectation would not match it.
   */
  function _deadlinePassed(uint256 deadline) internal view returns (bytes memory) {
    return
      abi.encodeWithSelector(DeadlineChecker.DeadlinePassed.selector, deadline, block.timestamp);
  }

  /// @dev Selects the single `TransferTokens` the hub emitted from the fork's log stream
  function _settlementLog() internal returns (Vm.Log memory entry) {
    Vm.Log[] memory entries = vm.getRecordedLogs();

    uint256 found;
    for (uint256 i = 0; i < entries.length; i++) {
      if (entries[i].emitter != address(hub)) continue;
      if (entries[i].topics.length == 0) continue;
      if (entries[i].topics[0] != TRANSFER_TOKENS_TOPIC) continue;

      entry = entries[i];
      found++;
    }

    assertEq(found, 1, 'exactly one TransferTokens per order');
  }

  function _topicAddress(bytes32 topic) internal pure returns (address) {
    return address(uint160(uint256(topic)));
  }

  // ---------------------------------------------------------------------------------------------
  // Order pieces
  // ---------------------------------------------------------------------------------------------

  function _tokenTransfer(uint160 amount) internal view returns (ERC20Transfer memory) {
    return ERC20Transfer({token: token18, target: address(router), amount: amount});
  }

  function _nftTransfer(address target) internal view returns (ERC721Transfer memory) {
    return ERC721Transfer({token: address(nft), tokenId: NFT_ID, target: target});
  }

  /// @dev A fulfillment's ERC20 leg: the amount that may leave the owner, with no target
  function _tokenAllowance(uint160 amount) internal view returns (ERC20Allowance memory) {
    return ERC20Allowance({token: token18, amount: amount});
  }

  /// @dev A fulfillment's NFT leg, with no target
  function _nftApproval() internal view returns (ERC721Approval memory) {
    return ERC721Approval({token: address(nft), tokenId: NFT_ID});
  }

  function _routerCall(uint256 value, bytes memory data)
    internal
    view
    returns (GenericCall memory)
  {
    return GenericCall({router: address(router), value: value, data: data});
  }

  function _validation(ValidatorMock v) internal pure returns (ValidationParams memory) {
    return ValidationParams({
      validator: address(v),
      action: keccak256('TEST_ACTION'),
      beforeExecutionInput: hex'11',
      afterExecutionInput: hex'22'
    });
  }

  // ---------------------------------------------------------------------------------------------
  // Order building
  // ---------------------------------------------------------------------------------------------

  function _executionOrder(
    address orderRelayer,
    ERC20Transfer[] memory erc20Transfers,
    ERC721Transfer[] memory erc721Transfers,
    GenericCall[] memory genericCalls,
    uint256 nonce,
    uint256 deadline
  ) internal view returns (ExecutionOrder memory) {
    return ExecutionOrder({
      owner: owner,
      relayer: orderRelayer,
      erc20Transfers: erc20Transfers,
      erc721Transfers: erc721Transfers,
      genericCalls: genericCalls,
      nonce: nonce,
      deadline: deadline,
      metadata: ''
    });
  }

  /// @dev The commonest shape: open to any submitter, plain ERC20 allowance, no NFT leg
  function _openExecutionOrder(
    ERC20Transfer[] memory erc20Transfers,
    GenericCall[] memory genericCalls,
    uint256 nonce,
    uint256 deadline
  ) internal view returns (ExecutionOrder memory) {
    return _executionOrder(
      ANY, erc20Transfers, new ERC721Transfer[](0), genericCalls, nonce, deadline
    );
  }

  function _fulfillmentOrder(
    address orderSolver,
    ERC20Allowance[] memory erc20Allowances,
    ERC721Approval[] memory erc721Approvals,
    ValidationParams[] memory validationParams,
    GenericCall[] memory ownerCalls,
    address solutionApprover,
    uint256 nonce,
    uint256 deadline
  ) internal view returns (FulfillmentOrder memory) {
    return FulfillmentOrder({
      owner: owner,
      solver: orderSolver,
      erc20Allowances: erc20Allowances,
      erc721Approvals: erc721Approvals,
      validationParams: validationParams,
      ownerCalls: ownerCalls,
      solutionApprover: solutionApprover,
      nonce: nonce,
      deadline: deadline,
      metadata: ''
    });
  }

  /// @dev Open to any submitter, any route, plain ERC20 allowance, no NFT leg
  function _openFulfillmentOrder(
    ERC20Allowance[] memory erc20Allowances,
    ValidationParams[] memory validationParams,
    GenericCall[] memory ownerCalls,
    uint256 nonce,
    uint256 deadline
  ) internal view returns (FulfillmentOrder memory) {
    return _fulfillmentOrder(
      ANY,
      erc20Allowances,
      new ERC721Approval[](0),
      validationParams,
      ownerCalls,
      ANY,
      nonce,
      deadline
    );
  }

  function _solution(
    address[] memory erc20Targets,
    address[] memory erc721Targets,
    GenericCall[] memory solverCalls,
    uint256 deadline
  ) internal pure returns (FulfillmentSolution memory) {
    return FulfillmentSolution({
      erc20Targets: erc20Targets,
      erc721Targets: erc721Targets,
      solverCalls: solverCalls,
      deadline: deadline
    });
  }

  /**
   * @dev As above, sending every ERC20 leg of `order` to `router` and every NFT leg to `router2`,
   * the targets the suite's orders used before the solver chose them
   */
  function _solution(
    FulfillmentOrder memory order,
    GenericCall[] memory solverCalls,
    uint256 deadline
  ) internal view returns (FulfillmentSolution memory) {
    address[] memory erc20Targets = new address[](order.erc20Allowances.length);
    for (uint256 i = 0; i < erc20Targets.length; i++) {
      erc20Targets[i] = address(router);
    }
    address[] memory erc721Targets = new address[](order.erc721Approvals.length);
    for (uint256 i = 0; i < erc721Targets.length; i++) {
      erc721Targets[i] = address(router2);
    }
    return _solution(erc20Targets, erc721Targets, solverCalls, deadline);
  }

  /// @dev The route a solver supplies for `order` when the owner pinned nothing, valid for an hour
  function _route(FulfillmentOrder memory order, GenericCall[] memory solverCalls)
    internal
    view
    returns (FulfillmentSolution memory)
  {
    return _solution(order, solverCalls, block.timestamp + 1 hours);
  }

  // ---------------------------------------------------------------------------------------------
  // Signatures, built from the independent oracle only
  // ---------------------------------------------------------------------------------------------

  function _hubDomain() internal view returns (bytes32) {
    return lDomainSeparator('KyberSwap Allowance Hub', '2.0.0', address(hub));
  }

  /**
   * @dev The owner's Permit2 signature for a relayed execution: the permit covers tokens and
   * amounts, the witness everything else the order pins. `witnessRelayer` is passed separately so a
   * test can sign a witness that disagrees with the order it submits.
   */
  function _signExecutionWitness(ExecutionOrder memory order, address witnessRelayer)
    internal
    returns (bytes memory)
  {
    ExecutionWitness memory witness = ExecutionWitness({
      relayer: witnessRelayer,
      erc20Targets: _targets(order.erc20Transfers),
      erc721Transfers: order.erc721Transfers,
      genericCalls: order.genericCalls,
      metadata: order.metadata
    });

    (address[] memory tokens, uint256[] memory amounts) = _tokensAndAmounts(order.erc20Transfers);

    return _sign(
      ownerKey,
      lPermit2ExecutionWitnessDigest(
        tokens, amounts, address(hub), order.nonce, order.deadline, witness
      )
    );
  }

  /// @dev As {_signExecutionWitness}, with the witness naming the relayer the order names
  function _signExecutionWitness(ExecutionOrder memory order) internal returns (bytes memory) {
    return _signExecutionWitness(order, order.relayer);
  }

  /// @dev The fulfillment witness pins who may choose the route rather than the route itself
  function _signFulfillmentWitness(
    FulfillmentOrder memory order,
    address witnessSolver,
    GenericCall[] memory witnessOwnerCalls,
    address witnessApprover
  ) internal returns (bytes memory) {
    FulfillmentWitness memory witness = FulfillmentWitness({
      solver: witnessSolver,
      erc721Approvals: order.erc721Approvals,
      ownerCalls: witnessOwnerCalls,
      validationParams: order.validationParams,
      callsSigner: witnessApprover,
      metadata: order.metadata
    });

    (address[] memory tokens, uint256[] memory amounts) = _tokensAndAmounts(order.erc20Allowances);

    return _sign(
      ownerKey,
      lPermit2FulfillmentWitnessDigest(
        tokens, amounts, address(hub), order.nonce, order.deadline, witness
      )
    );
  }

  /// @dev As above, with the witness agreeing with the order in every member
  function _signFulfillmentWitness(FulfillmentOrder memory order) internal returns (bytes memory) {
    return _signFulfillmentWitness(order, order.solver, order.ownerCalls, order.solutionApprover);
  }

  /// @dev Permit2 self-transfer: the owner submits, so there is no witness to bind
  function _signPlainPermit(ERC20Transfer[] memory erc20Transfers, uint256 nonce, uint256 deadline)
    internal
    returns (bytes memory)
  {
    (address[] memory tokens, uint256[] memory amounts) = _tokensAndAmounts(erc20Transfers);
    return _sign(ownerKey, lPermit2BatchDigest(tokens, amounts, address(hub), nonce, deadline));
  }

  /// @dev As {_signPlainPermit}, for a fulfillment order's allowances
  function _signPlainPermit(
    ERC20Allowance[] memory erc20Allowances,
    uint256 nonce,
    uint256 deadline
  ) internal returns (bytes memory) {
    (address[] memory tokens, uint256[] memory amounts) = _tokensAndAmounts(erc20Allowances);
    return _sign(ownerKey, lPermit2BatchDigest(tokens, amounts, address(hub), nonce, deadline));
  }

  /// @dev The solution approval lives under the hub's own EIP-712 domain
  function _signSolutionApproval(
    uint256 signerKey,
    FulfillmentOrder memory order,
    FulfillmentSolution memory solution
  ) internal returns (bytes memory) {
    return _sign(signerKey, lTypedDataHash(_hubDomain(), lSolutionApproval(order, solution)));
  }

  function _signAuthDelegation(
    uint256 signerKey,
    address delegator,
    address authenticator,
    bool delegated,
    bytes memory data,
    uint256 nonce,
    uint256 deadline
  ) internal returns (bytes memory) {
    return _sign(
      signerKey,
      lTypedDataHash(
        _hubDomain(), lAuthDelegation(delegator, authenticator, delegated, data, nonce, deadline)
      )
    );
  }

  /**
   * @dev Submits `callData` with the top 96 bits of the word holding the token set, then submits it
   * as given. The order hash reads those words directly from calldata without masking them, so the
   * dirty payload must be refused by the field reads that settle the order. Dirty first and clean
   * second, so the clean leg settling proves the payload was refused for the dirtying and not for
   * anything else it carried.
   */
  function _assertDirtyTokenWordIsRefused(address submitter, bytes memory callData) internal {
    uint256 word = type(uint256).max;
    for (uint256 i = 4; i + 32 <= callData.length; i += 32) {
      bytes32 w;
      assembly {
        w := mload(add(add(callData, 0x20), i))
      }
      if (uint256(w) == uint256(uint160(token18))) word = i;
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
