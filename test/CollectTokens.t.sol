// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import 'forge-std/Test.sol';

import 'src/KSUniversalRouter.sol';
import 'src/types/RouterParams.sol';

import 'test/libraries/PermitHash.sol';

import 'openzeppelin-contracts/contracts/interfaces/IERC721.sol';
import 'openzeppelin-contracts/contracts/token/ERC20/extensions/IERC20Permit.sol';
import 'openzeppelin-contracts/contracts/utils/cryptography/MessageHashUtils.sol';

import 'ks-common-sc/src/libraries/token/TokenHelper.sol';

contract CollectTokensTest is Test {
  using TokenHelper for address;

  address PERMIT2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;
  address USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;

  IERC721 UNISWAP_V3_NFT = IERC721(0xC36442b4a4522E871399CD717aBDD847Ab11FE88);
  IERC721 UNISWAP_V4_NFT = IERC721(0xbD216513d74C8cf14cf4747E6AaA6420FF64ee9e);

  bytes32 ERC20_PERMIT_TYPEHASH =
    keccak256('Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)');

  bytes32 ERC721_PERMIT_TYPEHASH =
    keccak256('Permit(address spender,uint256 tokenId,uint256 nonce,uint256 deadline)');

  KSUniversalRouter universalRouter;

  address sender;
  uint256 senderPrivateKey;

  function setUp() public {
    vm.createSelectFork('mainnet', 23_932_050);

    universalRouter =
      new KSUniversalRouter(address(this), new address[](0), new address[](0), PERMIT2);

    (sender, senderPrivateKey) = makeAddrAndKey('sender wallet');
  }

  function test_collecterc20Params(uint256 mode, uint160 amount) public {
    vm.startPrank(sender);

    mode = bound(mode, 0, 2);

    RouterParams memory routerParams = RouterParams({
      erc20Params: new ERC20Params[](1),
      erc721Params: new ERC721Params[](0),
      executorCalls: new ExecutorCall[](0),
      deadline: block.timestamp + 1 days
    });

    routerParams.erc20Params[0] = ERC20Params({
      token: USDC, targets: new address[](1), amounts: new uint256[](1), permitData: ''
    });
    routerParams.erc20Params[0].targets[0] = address(this);
    routerParams.erc20Params[0].amounts[0] = amount;

    if (mode == 0) {
      USDC.safeApprove(address(universalRouter), amount);

      routerParams.erc20Params[0].permitData = 'random permit data';
    } else if (mode == 1) {
      bytes32 structHash = keccak256(
        abi.encode(
          ERC20_PERMIT_TYPEHASH,
          sender,
          address(universalRouter),
          amount,
          0,
          block.timestamp + 1 days
        )
      );
      bytes32 hash =
        MessageHashUtils.toTypedDataHash(IERC20Permit(USDC).DOMAIN_SEPARATOR(), structHash);

      (uint8 v, bytes32 r, bytes32 s) = vm.sign(senderPrivateKey, hash);
      routerParams.erc20Params[0].permitData = abi.encode(amount, block.timestamp + 1 days, v, r, s);
    } else {
      USDC.safeApprove(PERMIT2, type(uint256).max);

      ISignatureTransfer.PermitBatchTransferFrom memory permit =
        ISignatureTransfer.PermitBatchTransferFrom({
          permitted: new ISignatureTransfer.TokenPermissions[](1),
          nonce: 0,
          deadline: block.timestamp + 1 days
        });
      permit.permitted[0] = ISignatureTransfer.TokenPermissions({token: USDC, amount: amount});

      bytes32 hash = MessageHashUtils.toTypedDataHash(
        IERC20Permit(PERMIT2).DOMAIN_SEPARATOR(), PermitHash.hash(permit, address(universalRouter))
      );

      (uint8 v, bytes32 r, bytes32 s) = vm.sign(senderPrivateKey, hash);
      routerParams.erc20Params[0].permitData =
        abi.encode(0, block.timestamp + 1 days, abi.encodePacked(r, s, v));
    }

    deal(USDC, sender, amount);
    universalRouter.execute(routerParams);

    assertEq(USDC.balanceOf(address(this)), amount);
  }

  function test_collecterc721Params(uint256 v3Mode, uint256 v4Mode) public {
    v3Mode = bound(v3Mode, 0, 1);
    v4Mode = bound(v4Mode, 0, 1);

    uint256 v3TokenId = 100;
    uint256 v4TokenId = 100;

    address v3Owner = UNISWAP_V3_NFT.ownerOf(v3TokenId);
    vm.prank(v3Owner);
    UNISWAP_V3_NFT.transferFrom(v3Owner, sender, v3TokenId);

    address v4Owner = UNISWAP_V4_NFT.ownerOf(v4TokenId);
    vm.prank(v4Owner);
    UNISWAP_V4_NFT.transferFrom(v4Owner, sender, v4TokenId);

    vm.startPrank(sender);

    RouterParams memory routerParams = RouterParams({
      erc20Params: new ERC20Params[](0),
      erc721Params: new ERC721Params[](2),
      executorCalls: new ExecutorCall[](0),
      deadline: block.timestamp + 1 days
    });

    routerParams.erc721Params[0] = ERC721Params({
      token: address(UNISWAP_V3_NFT), tokenId: v3TokenId, target: address(this), permitData: ''
    });

    if (v3Mode == 0) {
      UNISWAP_V3_NFT.approve(address(universalRouter), v3TokenId);
    } else {
      bytes32 structHash = keccak256(
        abi.encode(
          ERC721_PERMIT_TYPEHASH, address(universalRouter), v3TokenId, 0, block.timestamp + 1 days
        )
      );
      bytes32 hash = MessageHashUtils.toTypedDataHash(
        IERC20Permit(address(UNISWAP_V3_NFT)).DOMAIN_SEPARATOR(), structHash
      );

      (uint8 v, bytes32 r, bytes32 s) = vm.sign(senderPrivateKey, hash);
      routerParams.erc721Params[0].permitData = abi.encode(block.timestamp + 1 days, v, r, s);
    }

    routerParams.erc721Params[1] = ERC721Params({
      token: address(UNISWAP_V4_NFT), tokenId: v4TokenId, target: address(this), permitData: ''
    });

    if (v4Mode == 0) {
      UNISWAP_V4_NFT.approve(address(universalRouter), v4TokenId);
    } else {
      bytes32 structHash = keccak256(
        abi.encode(
          ERC721_PERMIT_TYPEHASH, address(universalRouter), v4TokenId, 0, block.timestamp + 1 days
        )
      );
      bytes32 hash = MessageHashUtils.toTypedDataHash(
        IERC20Permit(address(UNISWAP_V4_NFT)).DOMAIN_SEPARATOR(), structHash
      );

      (uint8 v, bytes32 r, bytes32 s) = vm.sign(senderPrivateKey, hash);
      routerParams.erc721Params[1].permitData =
        abi.encode(block.timestamp + 1 days, 0, abi.encodePacked(r, s, v));
    }

    universalRouter.execute(routerParams);

    assertEq(UNISWAP_V3_NFT.ownerOf(v3TokenId), address(this));
    assertEq(UNISWAP_V4_NFT.ownerOf(v4TokenId), address(this));
  }
}
