// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ActionValidatorMock} from '../../mocks/ActionValidatorMock.sol';
import {Permit2Mock} from '../../mocks/Permit2Mock.sol';
import {
  ERC721ReceiverMock,
  NativeRejectorMock,
  ReentrantERC721ReceiverMock
} from '../../mocks/ReceiverMocks.sol';
import {
  CallOrderRecorderMock,
  GenericRouterMock,
  ReentrantRouterMock
} from '../../mocks/RouterMocks.sol';
import {
  ERC20NoPermitMock,
  ERC20PermitMock,
  ERC721NoPermitMock,
  ERC721PermitMock,
  ERC721PermitV4Mock
} from '../../mocks/TokenMocks.sol';
import {TypeLibraryHarness} from '../../mocks/TypeLibraryHarness.sol';

import {ArrayHelper} from '../../libraries/ArrayHelper.sol';
import {PermitHash} from '../../libraries/PermitHash.sol';

import {KSAllowanceHubV2} from 'src/KSAllowanceHubV2.sol';

import {ERC20Params} from 'src/types/ERC20Params.sol';
import {ERC20Transfer} from 'src/types/ERC20Transfer.sol';
import {ERC721Params} from 'src/types/ERC721Params.sol';
import {ERC721Transfer} from 'src/types/ERC721Transfer.sol';
import {GenericCall} from 'src/types/GenericCall.sol';
import {NativeTransfer} from 'src/types/NativeTransfer.sol';
import {ValidationParams} from 'src/types/ValidationParams.sol';

import {ISignatureTransfer} from 'ks-common-sc/src/interfaces/ISignatureTransfer.sol';
import {TokenHelper} from 'ks-common-sc/src/libraries/token/TokenHelper.sol';

import {Test, Vm} from 'forge-std/Test.sol';

/**
 * @notice Shared fixture for every KSAllowanceHubV2 batch
 * @dev Deploys the hub against a local Permit2 stand-in and exposes the signing and struct-building
 * helpers the batches need. Holds no test functions so Foundry does not rediscover them per child.
 */
abstract contract KSAllowanceHubV2Base is Test {
  using ArrayHelper for *;

  /* ---------------------------------------------------------------- events */

  event TransferTokens(
    address indexed caller,
    address indexed owner,
    uint256 msgValue,
    ERC20Transfer[] erc20Transfers,
    ERC721Transfer[] erc721Transfers,
    NativeTransfer[] nativeTransfers
  );

  /* --------------------------------------------------------------- actors */

  Vm.Wallet internal ownerWallet;
  Vm.Wallet internal otherWallet;

  address internal owner;
  address internal other;

  address internal admin = makeAddr('admin');
  address internal guardian = makeAddr('guardian');
  address internal rescuer = makeAddr('rescuer');
  address internal relayer = makeAddr('relayer');
  address internal solver = makeAddr('solver');
  address internal outsider = makeAddr('outsider');
  address internal recipient = makeAddr('recipient');

  /* ------------------------------------------------------------ contracts */

  KSAllowanceHubV2 internal hub;
  Permit2Mock internal permit2;
  CallOrderRecorderMock internal recorder;

  GenericRouterMock internal routerA;
  GenericRouterMock internal routerB;
  GenericRouterMock internal unlistedRouter;
  ReentrantRouterMock internal reentrantRouter;

  ActionValidatorMock internal validatorA;
  ActionValidatorMock internal validatorB;

  ERC20PermitMock internal tokenA;
  ERC20PermitMock internal tokenB;
  ERC20NoPermitMock internal plainToken;
  ERC721PermitMock internal nft;
  ERC721PermitV4Mock internal nftV4;
  ERC721NoPermitMock internal plainNft;

  TypeLibraryHarness internal types;
  ERC721ReceiverMock internal nftReceiver;
  ReentrantERC721ReceiverMock internal reentrantNftReceiver;
  NativeRejectorMock internal nativeRejector;

  address internal constant NATIVE = TokenHelper.NATIVE_ADDRESS;

  bytes32 internal constant WHITELIST_ROUTER_ROLE = keccak256('WHITELIST_ROUTER_ROLE');

  uint256 internal constant DEFAULT_DEADLINE = 4_102_444_800; // 2100-01-01

  function setUp() public virtual {
    ownerWallet = vm.createWallet('owner');
    otherWallet = vm.createWallet('other');
    owner = ownerWallet.addr;
    other = otherWallet.addr;

    permit2 = new Permit2Mock();
    recorder = new CallOrderRecorderMock();

    address[] memory guardians = [guardian].toMemoryArray();
    address[] memory rescuers = [rescuer].toMemoryArray();

    // Routers are deployed after the hub because they read `msgSender()` back from it, so the
    // whitelist is granted post-deployment through the admin rather than in the constructor.
    hub = new KSAllowanceHubV2(admin, guardians, rescuers, new address[](0), address(permit2));

    routerA = new GenericRouterMock(address(hub), address(recorder), 'routerA');
    routerB = new GenericRouterMock(address(hub), address(recorder), 'routerB');
    unlistedRouter = new GenericRouterMock(address(hub), address(recorder), 'unlisted');
    reentrantRouter = new ReentrantRouterMock(address(hub));

    validatorA = new ActionValidatorMock(address(recorder), 'validatorA');
    validatorB = new ActionValidatorMock(address(recorder), 'validatorB');

    vm.prank(admin);
    hub.batchGrantRole(
      WHITELIST_ROUTER_ROLE,
      [address(routerA), address(routerB), address(reentrantRouter)].toMemoryArray()
    );

    tokenA = new ERC20PermitMock('Token A', 'TKA');
    tokenB = new ERC20PermitMock('Token B', 'TKB');
    plainToken = new ERC20NoPermitMock('Plain', 'PLN');
    nft = new ERC721PermitMock('NFT', 'NFT');
    nftV4 = new ERC721PermitV4Mock('NFT V4', 'NFT4');
    plainNft = new ERC721NoPermitMock('Plain NFT', 'PNFT');

    types = new TypeLibraryHarness();
    nftReceiver = new ERC721ReceiverMock();
    reentrantNftReceiver = new ReentrantERC721ReceiverMock(address(hub));
    nativeRejector = new NativeRejectorMock();

    vm.label(address(hub), 'hub');
    vm.label(address(permit2), 'permit2');
    vm.label(address(routerA), 'routerA');
    vm.label(address(routerB), 'routerB');
    vm.label(owner, 'owner');
  }

  /* -------------------------------------------------------- token funding */

  function _fundERC20(ERC20PermitMock token, address to, uint256 amount) internal {
    token.mint(to, amount);
  }

  /// @dev Approves the hub directly, standing in for an allowance established outside a permit
  function _approveHub(ERC20PermitMock token, address from, uint256 amount) internal {
    vm.prank(from);
    token.approve(address(hub), amount);
  }

  function _approvePermit2(ERC20PermitMock token, address from, uint256 amount) internal {
    vm.prank(from);
    token.approve(address(permit2), amount);
  }

  /* ------------------------------------------------------ permit2 signing */

  function _permitBatch(address[] memory tokens, uint256[] memory amounts, uint256 nonce)
    internal
    pure
    returns (ISignatureTransfer.PermitBatchTransferFrom memory permit)
  {
    permit.permitted = new ISignatureTransfer.TokenPermissions[](tokens.length);
    for (uint256 i = 0; i < tokens.length; i++) {
      permit.permitted[i] =
        ISignatureTransfer.TokenPermissions({token: tokens[i], amount: amounts[i]});
    }
    permit.nonce = nonce;
    permit.deadline = DEFAULT_DEADLINE;
  }

  function _signPermit2(
    Vm.Wallet memory wallet,
    ISignatureTransfer.PermitBatchTransferFrom memory permit,
    address spender
  ) internal view returns (bytes memory) {
    return _sign(wallet, PermitHash.hash(permit, spender));
  }

  function _signPermit2WithWitness(
    Vm.Wallet memory wallet,
    ISignatureTransfer.PermitBatchTransferFrom memory permit,
    address spender,
    bytes32 witness,
    string memory witnessTypeString
  ) internal view returns (bytes memory) {
    return _sign(wallet, PermitHash.hashWithWitness(permit, spender, witness, witnessTypeString));
  }

  function _sign(Vm.Wallet memory wallet, bytes32 dataHash) internal view returns (bytes memory) {
    bytes32 digest = keccak256(abi.encodePacked('\x19\x01', permit2.DOMAIN_SEPARATOR(), dataHash));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(wallet.privateKey, digest);
    return abi.encodePacked(r, s, v);
  }

  /* ------------------------------------------------- token permit signing */

  /// @dev Encodes an EIP-2612 permit the way `PermitHelper.callERC20Permit` decodes it (5 words)
  function _erc20PermitData(
    Vm.Wallet memory wallet,
    ERC20PermitMock token,
    uint256 value,
    uint256 deadline
  ) internal view returns (bytes memory) {
    bytes32 structHash = keccak256(
      abi.encode(
        keccak256(
          'Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)'
        ),
        wallet.addr,
        address(hub),
        value,
        token.nonces(wallet.addr),
        deadline
      )
    );
    bytes32 digest = keccak256(abi.encodePacked('\x19\x01', token.DOMAIN_SEPARATOR(), structHash));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(wallet.privateKey, digest);
    return abi.encode(value, deadline, uint256(v), r, s);
  }

  /// @dev Encodes a v3 ERC721 permit the way `PermitHelper.callERC721Permit` decodes it (4 words)
  function _erc721PermitData(
    Vm.Wallet memory wallet,
    ERC721PermitMock token,
    uint256 tokenId,
    uint256 deadline
  ) internal view returns (bytes memory) {
    bytes32 structHash = keccak256(
      abi.encode(token.PERMIT_TYPEHASH(), address(hub), tokenId, token.nonces(tokenId), deadline)
    );
    bytes32 digest = keccak256(abi.encodePacked('\x19\x01', token.DOMAIN_SEPARATOR(), structHash));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(wallet.privateKey, digest);
    return abi.encode(deadline, uint256(v), r, s);
  }

  /// @dev Encodes a v4 ERC721 permit the way `PermitHelper.callERC721Permit` decodes it (7 words)
  function _erc721PermitDataV4(
    Vm.Wallet memory wallet,
    ERC721PermitV4Mock token,
    uint256 tokenId,
    uint256 deadline
  ) internal view returns (bytes memory) {
    uint256 nonce = token.nonces(tokenId);
    bytes32 structHash =
      keccak256(abi.encode(token.PERMIT_TYPEHASH(), address(hub), tokenId, nonce, deadline));
    bytes32 digest = keccak256(abi.encodePacked('\x19\x01', token.DOMAIN_SEPARATOR(), structHash));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(wallet.privateKey, digest);
    return abi.encode(deadline, nonce, abi.encodePacked(r, s, v));
  }

  /* ------------------------------------------------------ struct builders */

  function _erc20Params(
    address token,
    address[] memory targets,
    uint256[] memory amounts,
    bytes memory permitData
  ) internal pure returns (ERC20Params memory) {
    return ERC20Params({token: token, targets: targets, amounts: amounts, permitData: permitData});
  }

  function _erc721Params(address token, uint256 tokenId, address target, bytes memory permitData)
    internal
    pure
    returns (ERC721Params memory)
  {
    return ERC721Params({token: token, tokenId: tokenId, target: target, permitData: permitData});
  }

  function _genericCall(address router, uint256 value, bytes memory data)
    internal
    pure
    returns (GenericCall memory)
  {
    return GenericCall({router: router, value: value, data: data});
  }

  function _validationParams(
    address validator,
    bytes32 action,
    bytes memory beforeInput,
    bytes memory afterInput
  ) internal pure returns (ValidationParams memory) {
    return ValidationParams({
      validator: validator,
      action: action,
      beforeExecutionInput: beforeInput,
      afterExecutionInput: afterInput
    });
  }

  /* --------------------------------------------------- array constructors */

  function _erc20ParamsArray(ERC20Params memory a)
    internal
    pure
    returns (ERC20Params[] memory arr)
  {
    arr = new ERC20Params[](1);
    arr[0] = a;
  }

  function _erc20ParamsArray(ERC20Params memory a, ERC20Params memory b)
    internal
    pure
    returns (ERC20Params[] memory arr)
  {
    arr = new ERC20Params[](2);
    arr[0] = a;
    arr[1] = b;
  }

  function _erc721ParamsArray(ERC721Params memory a)
    internal
    pure
    returns (ERC721Params[] memory arr)
  {
    arr = new ERC721Params[](1);
    arr[0] = a;
  }

  function _erc721ParamsArray(ERC721Params memory a, ERC721Params memory b)
    internal
    pure
    returns (ERC721Params[] memory arr)
  {
    arr = new ERC721Params[](2);
    arr[0] = a;
    arr[1] = b;
  }

  function _genericCallArray(GenericCall memory a)
    internal
    pure
    returns (GenericCall[] memory arr)
  {
    arr = new GenericCall[](1);
    arr[0] = a;
  }

  function _genericCallArray(GenericCall memory a, GenericCall memory b)
    internal
    pure
    returns (GenericCall[] memory arr)
  {
    arr = new GenericCall[](2);
    arr[0] = a;
    arr[1] = b;
  }

  function _validationParamsArray(ValidationParams memory a)
    internal
    pure
    returns (ValidationParams[] memory arr)
  {
    arr = new ValidationParams[](1);
    arr[0] = a;
  }

  function _validationParamsArray(ValidationParams memory a, ValidationParams memory b)
    internal
    pure
    returns (ValidationParams[] memory arr)
  {
    arr = new ValidationParams[](2);
    arr[0] = a;
    arr[1] = b;
  }

  function _noErc20Params() internal pure returns (ERC20Params[] memory) {
    return new ERC20Params[](0);
  }

  function _noErc721Params() internal pure returns (ERC721Params[] memory) {
    return new ERC721Params[](0);
  }

  function _noGenericCalls() internal pure returns (GenericCall[] memory) {
    return new GenericCall[](0);
  }

  function _noValidationParams() internal pure returns (ValidationParams[] memory) {
    return new ValidationParams[](0);
  }
}
