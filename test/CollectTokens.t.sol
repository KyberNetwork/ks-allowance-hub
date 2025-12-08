// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import 'forge-std/Test.sol';

import 'src/KSAllowanceHub.sol';
import 'src/types/ERC20Params.sol';
import 'src/types/ERC721Params.sol';
import 'src/types/GenericCall.sol';
import 'src/types/RelayerWitness.sol';

import 'test/libraries/ArrayHelper.sol';
import 'test/libraries/PermitHash.sol';
import 'test/mocks/GenericRouterMock.sol';

import 'openzeppelin-contracts/contracts/interfaces/IERC721.sol';
import 'openzeppelin-contracts/contracts/token/ERC20/extensions/IERC20Permit.sol';
import 'openzeppelin-contracts/contracts/utils/cryptography/MessageHashUtils.sol';

import 'ks-common-sc/src/libraries/token/TokenHelper.sol';

contract CollectTokensTest is Test {
  using TokenHelper for address;
  using ArrayHelper for *;

  address PERMIT2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;
  address WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
  address USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;

  IERC721 BAYC_NFT = IERC721(0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D);
  IERC721 UNISWAP_V3_NFT = IERC721(0xC36442b4a4522E871399CD717aBDD847Ab11FE88);
  IERC721 UNISWAP_V4_NFT = IERC721(0xbD216513d74C8cf14cf4747E6AaA6420FF64ee9e);
  uint256 tokenId = 10;

  bytes32 ERC20_PERMIT_TYPEHASH =
    keccak256('Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)');

  bytes32 ERC721_PERMIT_TYPEHASH =
    keccak256('Permit(address spender,uint256 tokenId,uint256 nonce,uint256 deadline)');

  KSAllowanceHub approvalProxy;
  GenericRouterMock genericRouter;

  address sender;
  uint256 senderPrivateKey;
  address recipient;
  address relayer;

  function setUp() public {
    vm.createSelectFork('mainnet', 23_932_050);

    approvalProxy = new KSAllowanceHub(address(this), new address[](0), new address[](0), PERMIT2);
    genericRouter = new GenericRouterMock();

    (sender, senderPrivateKey) = makeAddrAndKey('sender wallet');
    recipient = makeAddr('recipient wallet');
    relayer = makeAddr('relayer wallet');
  }

  function test_permitTransferAndExecute(uint256 wethAmount, uint256 usdcAmount) public {
    wethAmount = bound(wethAmount, 1, type(uint128).max);
    usdcAmount = bound(usdcAmount, 1, type(uint128).max);

    ERC20Params[] memory erc20Params = _prepareERC20Params(wethAmount, usdcAmount);
    ERC721Params[] memory erc721Params = _prepareERC721Params();
    GenericCall[] memory genericCalls = _prepareGenericCalls();

    vm.prank(sender);
    approvalProxy.permitTransferAndExecute(erc20Params, erc721Params, genericCalls);

    assertEq(WETH.balanceOf(recipient), wethAmount);
    assertEq(USDC.balanceOf(recipient), usdcAmount);
    assertEq(BAYC_NFT.ownerOf(tokenId), recipient);
    assertEq(UNISWAP_V3_NFT.ownerOf(tokenId), recipient);
    assertEq(UNISWAP_V4_NFT.ownerOf(tokenId), recipient);
  }

  function test_permit2TransferAndExecute_direct(uint256 wethAmount, uint256 usdcAmount) public {
    wethAmount = bound(wethAmount, 1, type(uint128).max);
    usdcAmount = bound(usdcAmount, 1, type(uint128).max);

    vm.startPrank(sender);
    WETH.forceApprove(address(PERMIT2), wethAmount);
    USDC.forceApprove(address(PERMIT2), usdcAmount);
    vm.stopPrank();

    deal(WETH, sender, wethAmount);
    deal(USDC, sender, usdcAmount);

    ISignatureTransfer.PermitBatchTransferFrom memory permit =
      ISignatureTransfer.PermitBatchTransferFrom({
        permitted: new ISignatureTransfer.TokenPermissions[](2),
        nonce: 0,
        deadline: block.timestamp + 1 days
      });

    permit.permitted[0] = ISignatureTransfer.TokenPermissions({token: WETH, amount: wethAmount});
    permit.permitted[1] = ISignatureTransfer.TokenPermissions({token: USDC, amount: usdcAmount});

    bytes32 structHash = PermitHash.hash(permit, address(approvalProxy));
    bytes32 hash = MessageHashUtils.toTypedDataHash(
      IERC20Permit(address(PERMIT2)).DOMAIN_SEPARATOR(), structHash
    );

    (uint8 v, bytes32 r, bytes32 s) = vm.sign(senderPrivateKey, hash);
    bytes memory signature = abi.encodePacked(r, s, v);

    ERC721Params[] memory erc721Params = _prepareERC721Params();
    GenericCall[] memory genericCalls = _prepareGenericCalls();

    vm.prank(sender);
    approvalProxy.permit2TransferAndExecute(
      permit, [recipient, recipient].toMemoryArray(), erc721Params, genericCalls, sender, signature
    );
  }

  function test_permit2TransferAndExecute_relayed(uint256 wethAmount, uint256 usdcAmount) public {
    wethAmount = bound(wethAmount, 1, type(uint128).max);
    usdcAmount = bound(usdcAmount, 1, type(uint128).max);

    vm.startPrank(sender);
    WETH.forceApprove(address(PERMIT2), wethAmount);
    USDC.forceApprove(address(PERMIT2), usdcAmount);
    vm.stopPrank();

    deal(WETH, sender, wethAmount);
    deal(USDC, sender, usdcAmount);

    ERC721Params[] memory erc721Params = _prepareERC721Params();
    GenericCall[] memory genericCalls = _prepareGenericCalls();

    ISignatureTransfer.PermitBatchTransferFrom memory permit =
      ISignatureTransfer.PermitBatchTransferFrom({
        permitted: new ISignatureTransfer.TokenPermissions[](2),
        nonce: 0,
        deadline: block.timestamp + 1 days
      });

    permit.permitted[0] = ISignatureTransfer.TokenPermissions({token: WETH, amount: wethAmount});
    permit.permitted[1] = ISignatureTransfer.TokenPermissions({token: USDC, amount: usdcAmount});

    RelayerWitness memory witness = RelayerWitness({
      relayer: relayer,
      targets: [recipient, recipient].toMemoryArray(),
      erc721Params: erc721Params,
      genericCalls: genericCalls
    });

    bytes32 structHash = PermitHash.hashWithWitness(
      permit,
      address(approvalProxy),
      this._hash(witness),
      RelayerWitnessLibrary.RELAYER_WITNESS_PERMIT2_TYPE_STRING
    );
    bytes32 hash = MessageHashUtils.toTypedDataHash(
      IERC20Permit(address(PERMIT2)).DOMAIN_SEPARATOR(), structHash
    );

    (uint8 v, bytes32 r, bytes32 s) = vm.sign(senderPrivateKey, hash);
    bytes memory signature = abi.encodePacked(r, s, v);

    vm.prank(relayer);
    approvalProxy.permit2TransferAndExecute(
      permit, [recipient, recipient].toMemoryArray(), erc721Params, genericCalls, sender, signature
    );
  }

  function _prepareERC20Params(uint256 wethAmount, uint256 usdcAmount)
    internal
    returns (ERC20Params[] memory erc20Params)
  {
    erc20Params = new ERC20Params[](2);

    deal(WETH, sender, wethAmount);
    deal(USDC, sender, usdcAmount);

    vm.prank(sender);
    WETH.safeApprove(address(approvalProxy), wethAmount);
    erc20Params[0] = ERC20Params({
      token: WETH,
      targets: [recipient].toMemoryArray(),
      amounts: [wethAmount].toMemoryArray(),
      permitData: ''
    });

    {
      bytes32 structHash = keccak256(
        abi.encode(
          ERC20_PERMIT_TYPEHASH,
          sender,
          address(approvalProxy),
          usdcAmount,
          0,
          block.timestamp + 1 days
        )
      );
      bytes32 hash =
        MessageHashUtils.toTypedDataHash(IERC20Permit(USDC).DOMAIN_SEPARATOR(), structHash);

      (uint8 v, bytes32 r, bytes32 s) = vm.sign(senderPrivateKey, hash);
      erc20Params[1] = ERC20Params({
        token: USDC,
        targets: [recipient].toMemoryArray(),
        amounts: [usdcAmount].toMemoryArray(),
        permitData: abi.encode(usdcAmount, block.timestamp + 1 days, v, r, s)
      });
    }
  }

  function _prepareERC721Params() internal returns (ERC721Params[] memory erc721Params) {
    erc721Params = new ERC721Params[](3);

    address owner = BAYC_NFT.ownerOf(tokenId);
    vm.prank(owner);
    BAYC_NFT.transferFrom(owner, sender, tokenId);

    vm.prank(sender);
    BAYC_NFT.approve(address(approvalProxy), tokenId);
    erc721Params[0] =
      ERC721Params({token: address(BAYC_NFT), tokenId: tokenId, target: recipient, permitData: ''});

    owner = UNISWAP_V3_NFT.ownerOf(tokenId);
    vm.prank(owner);
    UNISWAP_V3_NFT.transferFrom(owner, sender, tokenId);

    {
      bytes32 structHash = keccak256(
        abi.encode(
          ERC721_PERMIT_TYPEHASH, address(approvalProxy), tokenId, 0, block.timestamp + 1 days
        )
      );
      bytes32 hash = MessageHashUtils.toTypedDataHash(
        IERC20Permit(address(UNISWAP_V3_NFT)).DOMAIN_SEPARATOR(), structHash
      );

      (uint8 v, bytes32 r, bytes32 s) = vm.sign(senderPrivateKey, hash);
      erc721Params[1] = ERC721Params({
        token: address(UNISWAP_V3_NFT),
        tokenId: tokenId,
        target: recipient,
        permitData: abi.encode(block.timestamp + 1 days, v, r, s)
      });
    }

    owner = UNISWAP_V4_NFT.ownerOf(tokenId);
    vm.prank(owner);
    UNISWAP_V4_NFT.transferFrom(owner, sender, tokenId);

    {
      bytes32 structHash = keccak256(
        abi.encode(
          ERC721_PERMIT_TYPEHASH, address(approvalProxy), tokenId, 0, block.timestamp + 1 days
        )
      );
      bytes32 hash = MessageHashUtils.toTypedDataHash(
        IERC20Permit(address(UNISWAP_V4_NFT)).DOMAIN_SEPARATOR(), structHash
      );

      (uint8 v, bytes32 r, bytes32 s) = vm.sign(senderPrivateKey, hash);
      erc721Params[2] = ERC721Params({
        token: address(UNISWAP_V4_NFT),
        tokenId: tokenId,
        target: recipient,
        permitData: abi.encode(block.timestamp + 1 days, 0, abi.encodePacked(r, s, v))
      });
    }
  }

  function _prepareGenericCalls() internal view returns (GenericCall[] memory genericCalls) {
    genericCalls = new GenericCall[](1);

    genericCalls[0] = GenericCall({router: address(genericRouter), value: 0, data: ''});
  }

  function _hash(RelayerWitness calldata witness) public pure returns (bytes32) {
    return RelayerWitnessLibrary.hash(witness);
  }
}
