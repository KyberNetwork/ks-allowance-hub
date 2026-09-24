// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {V2TestBase} from 'test/base/V2TestBase.sol';

import {RouterMock} from 'test/v2/mocks/RouterMock.sol';
import {ERC721Mock} from 'test/v2/mocks/TokenMocks.sol';
import {ValidatorMock} from 'test/v2/mocks/ValidatorMock.sol';

import {KSAllowanceHubV2} from 'src/v2/KSAllowanceHubV2.sol';
import {AuthFlags} from 'src/v2/types/AuthFlags.sol';
import {ERC20Transfer} from 'src/v2/types/ERC20Transfer.sol';
import {ERC721Transfer} from 'src/v2/types/ERC721Transfer.sol';
import {GenericCall} from 'src/v2/types/GenericCall.sol';
import {ValidationParams} from 'src/v2/types/ValidationParams.sol';

import {IERC20} from 'openzeppelin-contracts/contracts/token/ERC20/IERC20.sol';

/**
 * @title HubBase
 * @notice Contract base for the {KSAllowanceHubV2} batches: deploys the hub against the real
 * Permit2 on a mainnet fork, wires the mocks, and builds orders.
 * @dev Every signature here is produced from the literals in {V2TestBase}. Nothing in this file may
 * reach for a production type string, typehash or hashing library, or the suite would only prove
 * that the hub agrees with itself.
 */
abstract contract HubBase is V2TestBase {
  KSAllowanceHubV2 internal hub;

  RouterMock internal router;
  RouterMock internal router2;
  ERC721Mock internal nft;
  ValidatorMock internal validator;
  ValidatorMock internal validator2;

  uint256 internal constant NFT_ID = 1;

  function setUp() public virtual {
    _forkMainnet();

    (owner, ownerKey) = makeAddrAndKey('owner');
    _asEoa(owner);
    _asEoa(relayer);
    _asEoa(solver);

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

    hub = new KSAllowanceHubV2(admin, guardians, rescuers, routers, PERMIT2);

    _fundOwner();

    vm.label(address(hub), 'hub');
    vm.label(address(router), 'router');
    vm.label(PERMIT2, 'permit2');
    vm.label(WETH, 'WETH');
    vm.label(USDC, 'USDC');
  }

  function _fundOwner() internal {
    deal(WETH, owner, 1000 ether);
    deal(USDC, owner, 1_000_000e6);
    nft.mint(owner, NFT_ID);

    vm.startPrank(owner);
    IERC20(WETH).approve(PERMIT2, type(uint256).max);
    IERC20(USDC).approve(PERMIT2, type(uint256).max);
    IERC20(WETH).approve(address(hub), type(uint256).max);
    IERC20(USDC).approve(address(hub), type(uint256).max);
    nft.setApprovalForAll(address(hub), true);
    vm.stopPrank();
  }

  // ---------------------------------------------------------------------------------------------
  // Flags and authData
  // ---------------------------------------------------------------------------------------------

  /// @dev bit 0 Permit2 signature rail, bit 1 Permit2 allowance rail, bit 2 caller is pinned
  function _flags(bool permit2Signature, bool permit2Allowance, bool pinCaller)
    internal
    pure
    returns (AuthFlags)
  {
    uint256 raw;
    if (permit2Signature) raw |= 1;
    if (permit2Allowance) raw |= 1 << 1;
    if (pinCaller) raw |= 1 << 2;
    return AuthFlags.wrap(bytes32(raw));
  }

  function _permit2AuthData(uint256 nonce, bytes memory signature)
    internal
    pure
    returns (bytes memory)
  {
    return abi.encode(nonce, signature);
  }

  function _verifierAuthData(
    address verifier,
    uint256 nonce,
    bytes memory key,
    bytes memory signature
  ) internal pure returns (bytes memory) {
    return abi.encode(verifier, nonce, key, signature);
  }

  // ---------------------------------------------------------------------------------------------
  // Order building
  // ---------------------------------------------------------------------------------------------

  function _wethTransfer(uint160 amount) internal view returns (ERC20Transfer memory) {
    return ERC20Transfer({token: WETH, target: address(router), amount: amount});
  }

  function _nftTransfer(address target) internal view returns (ERC721Transfer memory) {
    return ERC721Transfer({token: address(nft), tokenId: NFT_ID, target: target});
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
  // Permit2 signatures, built from the literal type strings only
  // ---------------------------------------------------------------------------------------------

  function _signExecutionOrder(
    ERC20Transfer[] memory erc20Transfers,
    ERC721Transfer[] memory erc721Transfers,
    GenericCall[] memory genericCalls,
    address signedCaller,
    uint256 nonce,
    uint256 deadline
  ) internal returns (bytes memory) {
    bytes32 witness = lExecutionWitness(
      signedCaller, _targets(erc20Transfers), erc721Transfers, genericCalls
    );

    (address[] memory tokens, uint256[] memory amounts) = _tokensAndAmounts(erc20Transfers);

    bytes32 digest = lPermit2BatchWitnessDigest(
      tokens, amounts, address(hub), nonce, deadline, witness, lExecutionWitnessTypeString()
    );

    return _sign(ownerKey, digest);
  }

  function _signFulfillmentOrder(
    ERC20Transfer[] memory erc20Transfers,
    ERC721Transfer[] memory erc721Transfers,
    ValidationParams[] memory validationParams,
    address callsSigner,
    address signedCaller,
    uint256 nonce,
    uint256 deadline
  ) internal returns (bytes memory) {
    bytes32 witness = lFulfillmentWitness(
      signedCaller, _targets(erc20Transfers), erc721Transfers, validationParams, callsSigner
    );

    (address[] memory tokens, uint256[] memory amounts) = _tokensAndAmounts(erc20Transfers);

    bytes32 digest = lPermit2BatchWitnessDigest(
      tokens, amounts, address(hub), nonce, deadline, witness, lFulfillmentWitnessTypeString()
    );

    return _sign(ownerKey, digest);
  }

  /// @dev Permit2 self-transfer: the owner submits, so there is no witness to bind
  function _signPlainPermit(ERC20Transfer[] memory erc20Transfers, uint256 nonce, uint256 deadline)
    internal
    returns (bytes memory)
  {
    (address[] memory tokens, uint256[] memory amounts) = _tokensAndAmounts(erc20Transfers);
    return _sign(ownerKey, lPermit2BatchDigest(tokens, amounts, address(hub), nonce, deadline));
  }

  /// @dev The calls approval lives under the hub's own EIP-712 domain
  function _signCallsApproval(
    uint256 signerKey,
    address callsOwner,
    GenericCall[] memory genericCalls,
    uint256 nonce,
    uint256 deadline
  ) internal returns (bytes memory) {
    bytes32 domain = lDomainSeparator('KyberSwap Allowance Hub', '2.0.0', address(hub));
    bytes32 digest =
      lTypedDataHash(domain, lCallsApproval(callsOwner, genericCalls, nonce, deadline));
    return _sign(signerKey, digest);
  }

  function _signAuthDelegation(
    uint256 signerKey,
    address verifier,
    bool delegated,
    bytes memory data,
    uint256 nonce,
    uint256 deadline
  ) internal returns (bytes memory) {
    bytes32 domain = lDomainSeparator('KyberSwap Allowance Hub', '2.0.0', address(hub));
    bytes32 digest =
      lTypedDataHash(domain, lAuthDelegation(verifier, delegated, data, nonce, deadline));
    return _sign(signerKey, digest);
  }
}
