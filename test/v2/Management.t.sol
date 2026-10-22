// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AuthenticatorBase} from 'test/v2/authenticators/base/AuthenticatorBase.sol';

import {KSAllowanceHubV2} from 'src/v2/KSAllowanceHubV2.sol';
import {IKSAllowanceHubV2} from 'src/v2/interfaces/IKSAllowanceHubV2.sol';
import {ERC20Transfer} from 'src/v2/types/ERC20Transfer.sol';
import {ERC721Transfer} from 'src/v2/types/ERC721Transfer.sol';

import {IManagementSimple} from 'ks-common-sc/src/interfaces/IManagementSimple.sol';

import {IAccessControl} from 'openzeppelin-contracts/contracts/access/IAccessControl.sol';
import {Ownable} from 'openzeppelin-contracts/contracts/access/Ownable.sol';
import {IERC20Errors} from 'openzeppelin-contracts/contracts/interfaces/draft-IERC6093.sol';
import {IERC20} from 'openzeppelin-contracts/contracts/token/ERC20/IERC20.sol';

import {Vm} from 'forge-std/Vm.sol';

/**
 * @title ManagementTest
 * @notice `MGMT-01..11` and `DOM-01`: constructor wiring, both EIP-712 domains, ERC-165, the role
 * admin surface, ownership and the rescue path.
 * @dev Every role hash, interface id and domain field on the expected side of an assertion is
 * written out here rather than imported, so the suite disagrees with the hub whenever the hub is
 * wrong. Interface ids are rebuilt by xor-ing selectors transcribed from the interface source.
 */
contract ManagementTest is AuthenticatorBase {
  // Role hashes, written out rather than imported
  bytes32 internal constant ROUTER_ROLE = keccak256('WHITELISTED_ROUTER_ROLE');
  bytes32 internal constant GUARDIAN_ROLE = keccak256('GUARDIAN_ROLE');
  bytes32 internal constant RESCUER_ROLE = keccak256('RESCUER_ROLE');
  bytes32 internal constant ADMIN_ROLE = bytes32(0);
  bytes32 internal constant TEST_ROLE = keccak256('TEST_ROLE');

  /// @dev The sentinel {TokenHelper} treats as native, written out
  address internal constant NATIVE = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

  uint256 internal constant STRANDED_NFT_ID = 77;

  // -----------------------------------------------------------------------------------------------
  // MGMT-01..03 — deploy-time state and the read surface
  // -----------------------------------------------------------------------------------------------

  /**
   * MGMT-12 / DOM-01 — both signing domains publish a separator, each its own and each chain-scoped
   * @dev The two contracts now inherit the same {EIP712Base}, so one statement covers both. Each
   * separator must match the domain written out from its own name, version and address; the two
   * must differ from each other, since the hub and the authenticator scope their signatures
   * separately; and each must be rebuilt once the chain id has moved, so a signature cannot be
   * replayed onto another chain. Without the third leg the first would only mirror the contract.
   */
  function test_DOM_01_bothDomainSeparators() public {
    bytes32 expectedHub = lDomainSeparator('KyberSwap Allowance Hub', '2.0.0', address(hub));
    bytes32 expectedAuthenticator = _authenticatorDomain();

    assertEq(hub.DOMAIN_SEPARATOR(), expectedHub, "the hub's matches its hand-written domain");
    assertEq(
      authenticator.DOMAIN_SEPARATOR(), expectedAuthenticator, "the authenticator's matches its own"
    );
    assertTrue(expectedHub != expectedAuthenticator, 'and the two domains are not the same');

    vm.chainId(block.chainid + 1);
    assertTrue(
      hub.DOMAIN_SEPARATOR() != expectedHub, 'a different chain gives the hub a new separator'
    );
    assertTrue(
      authenticator.DOMAIN_SEPARATOR() != expectedAuthenticator, 'and the authenticator one too'
    );
  }

  /// MGMT-01 — everything the constructor is responsible for, including its one event
  function test_MGMT_01_constructorWiring() public {
    // `permit2` is an internal immutable with no getter, so the constructor argument is only
    // observable through the rails that use it, which the AUTH-* cases exercise
    assertTrue(hub.hasRole(ROUTER_ROLE, address(router)), 'router whitelisted');
    assertTrue(hub.hasRole(ROUTER_ROLE, address(router2)), 'second router whitelisted');
    assertTrue(hub.hasRole(GUARDIAN_ROLE, guardian), 'guardian');
    assertTrue(hub.hasRole(RESCUER_ROLE, rescuer), 'rescuer');
    assertFalse(hub.hasRole(ROUTER_ROLE, relayer), 'nobody else is whitelisted');

    assertEq(hub.owner(), admin, 'owner');
    assertTrue(hub.hasRole(ADMIN_ROLE, admin), 'the owner holds the default admin role');
    assertFalse(hub.hasRole(ADMIN_ROLE, guardian), 'and nobody else does');

    assertEq(hub.roleRevokers(ROUTER_ROLE), GUARDIAN_ROLE, 'guardians may drop a router');
    assertEq(hub.roleRevokers(GUARDIAN_ROLE), ADMIN_ROLE, 'an unset revoker reads as the admin');

    // The construction event is only observable on a fresh deployment
    vm.recordLogs();
    new KSAllowanceHubV2(admin, _one(guardian), _one(rescuer), _one(address(router)), permit2);
    Vm.Log[] memory logs = vm.getRecordedLogs();

    bytes32 topic = keccak256('RoleRevokerChanged(bytes32,bytes32,bytes32)');
    bool found;
    for (uint256 i = 0; i < logs.length; i++) {
      if (logs[i].topics.length != 4 || logs[i].topics[0] != topic) continue;
      assertEq(logs[i].topics[1], ROUTER_ROLE, 'role');
      assertEq(logs[i].topics[2], ADMIN_ROLE, 'previous revoker');
      assertEq(logs[i].topics[3], GUARDIAN_ROLE, 'new revoker');
      found = true;
    }
    assertTrue(found, 'RoleRevokerChanged emitted once at deploy');
  }

  /// MGMT-02 — the EIP-712 domain the order signatures live under
  function test_MGMT_02_eip712Domain() public view {
    (
      bytes1 fields,
      string memory name,
      string memory version,
      uint256 chainId,
      address verifyingContract,
      bytes32 salt,
      uint256[] memory extensions
    ) = hub.eip712Domain();

    assertEq(fields, hex'0f', 'name, version, chainId and verifyingContract are present');
    assertEq(name, 'KyberSwap Allowance Hub', 'name');
    assertEq(version, '2.0.0', 'version');
    assertEq(chainId, block.chainid, 'chain id');
    assertEq(verifyingContract, address(hub), 'verifying contract');
    assertEq(salt, bytes32(0), 'no salt');
    assertEq(extensions.length, 0, 'no extensions');
  }

  /// MGMT-03 — ERC-165, against interface ids rebuilt from hand-written selectors
  function test_MGMT_03_supportsInterface() public view {
    bytes4 erc165 = bytes4(keccak256('supportsInterface(bytes4)'));

    bytes4 accessControl = bytes4(keccak256('hasRole(bytes32,address)'))
      ^ bytes4(keccak256('getRoleAdmin(bytes32)')) ^ bytes4(keccak256('grantRole(bytes32,address)'))
      ^ bytes4(keccak256('revokeRole(bytes32,address)'))
      ^ bytes4(keccak256('renounceRole(bytes32,address)'));

    bytes4 adminRules = bytes4(keccak256('defaultAdmin()'))
      ^ bytes4(keccak256('pendingDefaultAdmin()')) ^ bytes4(keccak256('defaultAdminDelay()'))
      ^ bytes4(keccak256('pendingDefaultAdminDelay()'))
      ^ bytes4(keccak256('beginDefaultAdminTransfer(address)'))
      ^ bytes4(keccak256('cancelDefaultAdminTransfer()'))
      ^ bytes4(keccak256('acceptDefaultAdminTransfer()'))
      ^ bytes4(keccak256('changeDefaultAdminDelay(uint48)'))
      ^ bytes4(keccak256('rollbackDefaultAdminDelay()'))
      ^ bytes4(keccak256('defaultAdminDelayIncreaseWait()'));

    // The published ids, as a second opinion on the selector lists above
    assertEq(erc165, bytes4(0x01ffc9a7), 'ERC-165 id');
    assertEq(accessControl, bytes4(0x7965db0b), 'IAccessControl id');
    assertEq(adminRules, bytes4(0x31498786), 'IAccessControlDefaultAdminRules id');

    assertTrue(hub.supportsInterface(erc165), 'ERC-165');
    assertTrue(hub.supportsInterface(accessControl), 'IAccessControl');
    assertFalse(hub.supportsInterface(adminRules), 'the delayed admin rules are not claimed');

    assertFalse(hub.supportsInterface(0xffffffff), 'the ERC-165 invalid id');
    assertFalse(hub.supportsInterface(bytes4(keccak256('nothing()'))), 'an unrelated id');
  }

  // -----------------------------------------------------------------------------------------------
  // MGMT-05..07 — the role admin surface and ownership
  // -----------------------------------------------------------------------------------------------

  /// MGMT-05 — no self-revoker and no revoker for the admin role; anything else is recorded
  function test_MGMT_05_setRoleRevoker() public {
    vm.prank(admin);
    vm.expectRevert(IManagementSimple.SelfRoleRevokerNotAllowed.selector);
    hub.setRoleRevoker(TEST_ROLE, TEST_ROLE);

    vm.prank(admin);
    vm.expectRevert(IManagementSimple.DefaultAdminRoleActionNotAllowed.selector);
    hub.setRoleRevoker(ADMIN_ROLE, GUARDIAN_ROLE);

    assertEq(hub.roleRevokers(TEST_ROLE), ADMIN_ROLE, 'rejected change left no trace');
    assertEq(hub.roleRevokers(ADMIN_ROLE), ADMIN_ROLE, 'and neither did the second');

    vm.expectEmit(true, true, true, true, address(hub));
    emit IManagementSimple.RoleRevokerChanged(TEST_ROLE, ADMIN_ROLE, GUARDIAN_ROLE);

    vm.prank(admin);
    hub.setRoleRevoker(TEST_ROLE, GUARDIAN_ROLE);

    assertEq(hub.roleRevokers(TEST_ROLE), GUARDIAN_ROLE, 'revoker recorded');
  }

  /// MGMT-06 — `revokeRole` names both roles it would have accepted
  function test_MGMT_06_revokeRoleNeedsRevokerOrAdmin() public {
    bytes32[] memory neededRoles = new bytes32[](2);
    neededRoles[0] = GUARDIAN_ROLE; // the nominated revoker
    neededRoles[1] = ADMIN_ROLE; // the role's admin

    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(IManagementSimple.UnauthorizedAccount.selector, relayer, neededRoles)
    );
    hub.revokeRole(ROUTER_ROLE, address(router));

    assertTrue(hub.hasRole(ROUTER_ROLE, address(router)), 'role intact after the refusal');

    // the role's admin is the second of the two accepted callers
    vm.prank(admin);
    hub.revokeRole(ROUTER_ROLE, address(router2));

    assertFalse(hub.hasRole(ROUTER_ROLE, address(router2)), 'admin may revoke');
  }

  /// MGMT-07 — the default admin role follows ownership, which moves in one step
  function test_MGMT_07_transferOwnership() public {
    address newAdmin = makeAddr('newAdmin');

    vm.prank(relayer);
    vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, relayer));
    hub.transferOwnership(newAdmin);

    vm.prank(admin);
    vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableInvalidOwner.selector, address(0)));
    hub.transferOwnership(address(0));

    vm.expectEmit(true, true, true, true, address(hub));
    emit Ownable.OwnershipTransferred(admin, newAdmin);

    vm.prank(admin);
    hub.transferOwnership(newAdmin);

    assertEq(hub.owner(), newAdmin, 'owner moved');
    assertTrue(hub.hasRole(ADMIN_ROLE, newAdmin), 'new admin holds the role');
    assertFalse(hub.hasRole(ADMIN_ROLE, admin), 'old admin gave it up');
  }

  /// MGMT-07b — renouncing ownership leaves no default admin
  function test_MGMT_07b_renounceOwnership() public {
    vm.prank(admin);
    hub.renounceOwnership();

    assertEq(hub.owner(), address(0), 'no owner');
    assertFalse(hub.hasRole(ADMIN_ROLE, admin), 'the former owner lost the role');
    assertFalse(hub.hasRole(ADMIN_ROLE, address(0)), 'and the zero address does not hold it');

    vm.prank(admin);
    vm.expectRevert(
      abi.encodeWithSelector(
        IAccessControl.AccessControlUnauthorizedAccount.selector, admin, ADMIN_ROLE
      )
    );
    hub.grantRole(TEST_ROLE, relayer);
  }

  // -----------------------------------------------------------------------------------------------
  // MGMT-08..09 — the rescue path
  // -----------------------------------------------------------------------------------------------

  /// MGMT-08a — each ERC20 leg goes to its target; a zero amount sends the whole balance
  function test_MGMT_08a_rescueErc20s() public {
    deal(token18, address(hub), 3 ether);
    deal(token6, address(hub), 500e6);

    ERC20Transfer[] memory erc20s = new ERC20Transfer[](2);
    erc20s[0] = ERC20Transfer({token: token18, target: recipient, amount: 0});
    erc20s[1] = ERC20Transfer({token: token6, target: solver, amount: 100e6});

    vm.expectEmit(address(hub));
    emit IKSAllowanceHubV2.RescueTokens(erc20s, new ERC721Transfer[](0));

    vm.prank(rescuer);
    hub.rescueTokens(erc20s, new ERC721Transfer[](0));

    assertEq(IERC20(token18).balanceOf(recipient), 3 ether, 'the zero amount swept the balance');
    assertEq(IERC20(token18).balanceOf(address(hub)), 0, 'nothing left of it');
    assertEq(IERC20(token6).balanceOf(solver), 100e6, 'the second leg, to its own target');
    assertEq(IERC20(token6).balanceOf(address(hub)), 400e6, 'the rest stays put');
  }

  /// MGMT-08b — native leaves under either native sentinel
  function test_MGMT_08b_rescueStrandedNative() public {
    // The hub has no `receive`, so native can only be planted on it — by a coinbase payment, a
    // selfdestruct, or the cheatcode standing in for either
    vm.deal(address(hub), 3 ether);
    uint256 recipientBefore = recipient.balance;
    uint256 solverBefore = solver.balance;

    ERC20Transfer[] memory erc20s = new ERC20Transfer[](2);
    erc20s[0] = ERC20Transfer({token: NATIVE, target: recipient, amount: 2 ether});
    erc20s[1] = ERC20Transfer({token: address(0), target: solver, amount: 0});

    vm.prank(rescuer);
    hub.rescueTokens(erc20s, new ERC721Transfer[](0));

    assertEq(recipient.balance - recipientBefore, 2 ether, 'under the native-token address');
    assertEq(solver.balance - solverBefore, 1 ether, 'and the rest under the zero address');
    assertEq(address(hub).balance, 0, 'hub drained');
  }

  /// MGMT-08c — only a rescuer or the default admin may rescue
  function test_MGMT_08c_rescueGuards() public {
    deal(token18, address(hub), 2 ether);
    ERC20Transfer[] memory erc20s = new ERC20Transfer[](1);
    erc20s[0] = ERC20Transfer({token: token18, target: recipient, amount: 1 ether});

    bytes32[] memory neededRoles = new bytes32[](2);
    neededRoles[0] = RESCUER_ROLE;
    neededRoles[1] = ADMIN_ROLE;

    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(IManagementSimple.UnauthorizedAccount.selector, relayer, neededRoles)
    );
    hub.rescueTokens(erc20s, new ERC721Transfer[](0));
    assertEq(IERC20(token18).balanceOf(address(hub)), 2 ether, 'nothing moved');

    ERC20Transfer[] memory toZero = new ERC20Transfer[](1);
    toZero[0] = ERC20Transfer({token: token18, target: address(0), amount: 1 ether});
    // TokenHelper wraps the token's refusal as ERC-7751 describes, naming the call that failed
    vm.prank(rescuer);
    vm.expectRevert(
      abi.encodeWithSelector(
        bytes4(keccak256('WrappedError(address,bytes4,bytes,bytes)')),
        token18,
        bytes4(keccak256('transfer(address,uint256)')),
        abi.encodeWithSelector(IERC20Errors.ERC20InvalidReceiver.selector, address(0)),
        abi.encodeWithSelector(bytes4(keccak256('ERC20TransferFailed()')))
      )
    );
    hub.rescueTokens(toZero, new ERC721Transfer[](0));

    // the default admin is the other accepted caller
    vm.prank(admin);
    hub.rescueTokens(erc20s, new ERC721Transfer[](0));
    assertEq(IERC20(token18).balanceOf(recipient), 1 ether, 'the admin rescued');
  }

  /// MGMT-09 — an NFT can only be stranded by an unsafe transfer, since the hub has no hook
  function test_MGMT_09_rescueErc721s() public {
    nft.mint(owner, STRANDED_NFT_ID);

    // `safeTransferFrom` would revert on the hub: it implements no `onERC721Received`
    vm.prank(owner);
    nft.transferFrom(owner, address(hub), STRANDED_NFT_ID);
    assertEq(nft.ownerOf(STRANDED_NFT_ID), address(hub), 'stranded');

    ERC721Transfer[] memory nfts = new ERC721Transfer[](1);
    nfts[0] = ERC721Transfer({token: address(nft), tokenId: STRANDED_NFT_ID, target: recipient});

    vm.expectEmit(address(hub));
    emit IKSAllowanceHubV2.RescueTokens(new ERC20Transfer[](0), nfts);

    vm.prank(rescuer);
    hub.rescueTokens(new ERC20Transfer[](0), nfts);

    assertEq(nft.ownerOf(STRANDED_NFT_ID), recipient, 'recovered');
    assertEq(nft.ownerOf(NFT_ID), owner, 'the owner keeps what was never stranded');
  }

  // -----------------------------------------------------------------------------------------------
  // MGMT-11 — grantRole
  // -----------------------------------------------------------------------------------------------

  /// MGMT-11 — an ordinary role is granted by its admin
  function test_MGMT_11_grantRole() public {
    vm.expectEmit(true, true, true, true, address(hub));
    emit IAccessControl.RoleGranted(ROUTER_ROLE, relayer, admin);

    vm.prank(admin);
    hub.grantRole(ROUTER_ROLE, relayer);

    assertTrue(hub.hasRole(ROUTER_ROLE, relayer), 'granted');
    assertEq(hub.getRoleAdmin(ROUTER_ROLE), ADMIN_ROLE, 'administered by the default admin');
  }

  /// MGMT-11b — the default admin role cannot be granted, revoked or renounced
  function test_MGMT_11b_defaultAdminRoleFollowsOwnershipOnly() public {
    vm.startPrank(admin);
    vm.expectRevert(IManagementSimple.DefaultAdminRoleActionNotAllowed.selector);
    hub.grantRole(ADMIN_ROLE, relayer);

    vm.expectRevert(IManagementSimple.DefaultAdminRoleActionNotAllowed.selector);
    hub.revokeRole(ADMIN_ROLE, admin);

    vm.expectRevert(IManagementSimple.DefaultAdminRoleActionNotAllowed.selector);
    hub.renounceRole(ADMIN_ROLE, admin);
    vm.stopPrank();

    assertFalse(hub.hasRole(ADMIN_ROLE, relayer), 'nothing granted');
    assertTrue(hub.hasRole(ADMIN_ROLE, admin), 'nothing revoked');
    assertEq(hub.owner(), admin, 'owner unchanged');
  }

  // -----------------------------------------------------------------------------------------------
  // Helpers
  // -----------------------------------------------------------------------------------------------

  function _one(address a) internal pure returns (address[] memory out) {
    out = new address[](1);
    out[0] = a;
  }
}
