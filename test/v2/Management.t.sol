// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {HubBase} from 'test/v2/base/HubBase.sol';

import {ERC1155SeedMock} from 'test/v2/mocks/PermitTokenMocks.sol';

import {KSAllowanceHubV2} from 'src/v2/KSAllowanceHubV2.sol';

import {ICommon} from 'ks-common-sc/src/interfaces/ICommon.sol';
import {IManagementBase} from 'ks-common-sc/src/interfaces/IManagementBase.sol';
import {IManagementRescuable} from 'ks-common-sc/src/interfaces/IManagementRescuable.sol';

import {IAccessControl} from 'openzeppelin-contracts/contracts/access/IAccessControl.sol';
import {
  IAccessControlDefaultAdminRules
} from 'openzeppelin-contracts/contracts/access/extensions/IAccessControlDefaultAdminRules.sol';
import {IERC1155} from 'openzeppelin-contracts/contracts/token/ERC1155/IERC1155.sol';
import {IERC20} from 'openzeppelin-contracts/contracts/token/ERC20/IERC20.sol';
import {IERC721} from 'openzeppelin-contracts/contracts/token/ERC721/IERC721.sol';

import {Vm} from 'forge-std/Vm.sol';

/**
 * @title ManagementTest
 * @notice B6 — `MGMT-01..11`: constructor wiring, the EIP-712 domain, ERC-165, the role admin
 * surface and all three rescue paths.
 * @dev Every role hash, interface id and domain field on the expected side of an assertion is
 * written out here rather than imported, so the suite disagrees with the hub whenever the hub is
 * wrong. Interface ids are rebuilt by xor-ing selectors transcribed from the interface source.
 */
contract ManagementTest is HubBase {
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

  /// MGMT-01 — everything the constructor is responsible for, including its one event
  function test_MGMT_01_constructorWiring() public {
    assertEq(hub.PERMIT2(), PERMIT2, 'permit2');

    assertTrue(hub.hasRole(ROUTER_ROLE, address(router)), 'router whitelisted');
    assertTrue(hub.hasRole(ROUTER_ROLE, address(router2)), 'second router whitelisted');
    assertTrue(hub.hasRole(GUARDIAN_ROLE, guardian), 'guardian');
    assertTrue(hub.hasRole(RESCUER_ROLE, rescuer), 'rescuer');
    assertFalse(hub.hasRole(ROUTER_ROLE, relayer), 'nobody else is whitelisted');

    assertEq(hub.defaultAdmin(), admin, 'default admin');
    assertEq(hub.owner(), admin, 'owner mirrors the default admin');
    assertEq(hub.defaultAdminDelay(), 0, 'the admin hand-over is one step');

    assertEq(hub.roleRevokers(ROUTER_ROLE), GUARDIAN_ROLE, 'guardians may drop a router');
    assertEq(hub.roleRevokers(GUARDIAN_ROLE), ADMIN_ROLE, 'an unset revoker reads as the admin');

    // The construction event is only observable on a fresh deployment
    vm.recordLogs();
    new KSAllowanceHubV2(admin, _one(guardian), _one(rescuer), _one(address(router)), PERMIT2);
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
    assertTrue(hub.supportsInterface(adminRules), 'IAccessControlDefaultAdminRules');

    assertFalse(hub.supportsInterface(0xffffffff), 'the ERC-165 invalid id');
    assertFalse(hub.supportsInterface(bytes4(keccak256('nothing()'))), 'an unrelated id');
  }

  // -----------------------------------------------------------------------------------------------
  // MGMT-04..07 — the role admin surface
  // -----------------------------------------------------------------------------------------------

  /// MGMT-04 — the batch grant and revoke round trip, with one event per account
  function test_MGMT_04_batchGrantAndRevokeRole() public {
    address[] memory accounts = new address[](2);
    accounts[0] = relayer;
    accounts[1] = solver;

    vm.expectEmit(true, true, true, true, address(hub));
    emit IAccessControl.RoleGranted(TEST_ROLE, relayer, admin);
    vm.expectEmit(true, true, true, true, address(hub));
    emit IAccessControl.RoleGranted(TEST_ROLE, solver, admin);

    vm.prank(admin);
    hub.batchGrantRole(TEST_ROLE, accounts);

    assertTrue(hub.hasRole(TEST_ROLE, relayer), 'relayer granted');
    assertTrue(hub.hasRole(TEST_ROLE, solver), 'solver granted');

    vm.expectEmit(true, true, true, true, address(hub));
    emit IAccessControl.RoleRevoked(TEST_ROLE, relayer, admin);
    vm.expectEmit(true, true, true, true, address(hub));
    emit IAccessControl.RoleRevoked(TEST_ROLE, solver, admin);

    vm.prank(admin);
    hub.batchRevokeRole(TEST_ROLE, accounts);

    assertFalse(hub.hasRole(TEST_ROLE, relayer), 'relayer revoked');
    assertFalse(hub.hasRole(TEST_ROLE, solver), 'solver revoked');

    // the batch helpers are gated on the role's admin, not on the role itself
    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(
        IAccessControl.AccessControlUnauthorizedAccount.selector, relayer, ADMIN_ROLE
      )
    );
    hub.batchGrantRole(TEST_ROLE, accounts);
  }

  /// MGMT-05 — a role may not be its own revoker; anything else is recorded and announced
  function test_MGMT_05_setRoleRevoker() public {
    vm.prank(admin);
    vm.expectRevert(IManagementBase.InvalidRoleRevoker.selector);
    hub.setRoleRevoker(TEST_ROLE, TEST_ROLE);

    assertEq(hub.roleRevokers(TEST_ROLE), ADMIN_ROLE, 'rejected change left no trace');

    vm.expectEmit(true, true, true, true, address(hub));
    emit IManagementBase.RoleRevokerChanged(TEST_ROLE, ADMIN_ROLE, GUARDIAN_ROLE);

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
      abi.encodeWithSelector(IManagementBase.UnauthorizedAccount.selector, relayer, neededRoles)
    );
    hub.revokeRole(ROUTER_ROLE, address(router));

    assertTrue(hub.hasRole(ROUTER_ROLE, address(router)), 'role intact after the refusal');

    // the role's admin is the second of the two accepted callers
    vm.prank(admin);
    hub.revokeRole(ROUTER_ROLE, address(router2));

    assertFalse(hub.hasRole(ROUTER_ROLE, address(router2)), 'admin may revoke');
  }

  /// MGMT-07 — ownership moves in one step, because the configured delay is zero
  function test_MGMT_07_transferOwnership() public {
    address newAdmin = makeAddr('newAdmin');

    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(
        IAccessControl.AccessControlUnauthorizedAccount.selector, relayer, ADMIN_ROLE
      )
    );
    hub.transferOwnership(newAdmin);

    vm.prank(admin);
    hub.transferOwnership(newAdmin);

    assertEq(hub.defaultAdmin(), newAdmin, 'default admin moved');
    assertEq(hub.owner(), newAdmin, 'owner moved');
    assertTrue(hub.hasRole(ADMIN_ROLE, newAdmin), 'new admin holds the role');
    assertFalse(hub.hasRole(ADMIN_ROLE, admin), 'old admin gave it up');

    (address pending, uint48 schedule) = hub.pendingDefaultAdmin();
    assertEq(pending, address(0), 'nothing left pending');
    assertEq(schedule, 0, 'no schedule');
  }

  // -----------------------------------------------------------------------------------------------
  // MGMT-08..10 — the rescue paths
  // -----------------------------------------------------------------------------------------------

  /// MGMT-08a — a zero amount means "everything", and the event carries what was resolved
  function test_MGMT_08a_rescueErc20s() public {
    deal(WETH, address(hub), 3 ether);
    deal(USDC, address(hub), 500e6);

    address[] memory tokens = new address[](2);
    tokens[0] = WETH;
    tokens[1] = USDC;

    uint256[] memory amounts = new uint256[](2);
    amounts[0] = 0; // sweep
    amounts[1] = 100e6; // exactly this much

    uint256[] memory resolved = new uint256[](2);
    resolved[0] = 3 ether;
    resolved[1] = 100e6;

    vm.expectEmit(address(hub));
    emit IManagementRescuable.RescueERC20s(tokens, resolved, recipient);

    vm.prank(rescuer);
    hub.rescueERC20s(tokens, amounts, recipient);

    assertEq(IERC20(WETH).balanceOf(recipient), 3 ether, 'swept balance');
    assertEq(IERC20(WETH).balanceOf(address(hub)), 0, 'nothing left behind');
    assertEq(IERC20(USDC).balanceOf(recipient), 100e6, 'named amount');
    assertEq(IERC20(USDC).balanceOf(address(hub)), 400e6, 'the rest stays put');
  }

  /// MGMT-08b — native arrives through the same entry point, under the native sentinel
  function test_MGMT_08b_rescueStrandedNative() public {
    // The hub has no `receive`, so native can only be planted on it — by a coinbase payment, a
    // selfdestruct, or the cheatcode standing in for either
    _asEoa(recipient);
    vm.deal(address(hub), 2 ether);
    uint256 balanceBefore = recipient.balance;

    address[] memory tokens = _one(NATIVE);
    uint256[] memory amounts = new uint256[](1);

    uint256[] memory resolved = _oneAmount(2 ether);

    vm.expectEmit(address(hub));
    emit IManagementRescuable.RescueERC20s(tokens, resolved, recipient);

    vm.prank(rescuer);
    hub.rescueERC20s(tokens, amounts, recipient);

    assertEq(recipient.balance - balanceBefore, 2 ether, 'native recovered');
    assertEq(address(hub).balance, 0, 'hub drained');
  }

  /// MGMT-08c — the recipient is checked, and so is the caller
  function test_MGMT_08c_rescueGuards() public {
    deal(WETH, address(hub), 1 ether);

    address[] memory tokens = _one(WETH);
    uint256[] memory amounts = new uint256[](1);

    vm.prank(rescuer);
    vm.expectRevert(ICommon.InvalidAddress.selector);
    hub.rescueERC20s(tokens, amounts, address(0));

    bytes32[] memory neededRoles = new bytes32[](2);
    neededRoles[0] = RESCUER_ROLE;
    neededRoles[1] = ADMIN_ROLE;

    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(IManagementBase.UnauthorizedAccount.selector, relayer, neededRoles)
    );
    hub.rescueERC20s(tokens, amounts, recipient);

    // lengths are guarded here too
    vm.prank(rescuer);
    vm.expectRevert(ICommon.MismatchedArrayLengths.selector);
    hub.rescueERC20s(tokens, new uint256[](2), recipient);

    assertEq(IERC20(WETH).balanceOf(address(hub)), 1 ether, 'nothing moved');
  }

  /// MGMT-09 — an NFT can only be stranded by an unsafe transfer, since the hub has no hook
  function test_MGMT_09_rescueErc721s() public {
    nft.mint(owner, STRANDED_NFT_ID);

    // `safeTransferFrom` would revert on the hub: it implements no `onERC721Received`
    vm.prank(owner);
    nft.transferFrom(owner, address(hub), STRANDED_NFT_ID);
    assertEq(nft.ownerOf(STRANDED_NFT_ID), address(hub), 'stranded');

    IERC721[] memory tokens = new IERC721[](1);
    tokens[0] = IERC721(address(nft));
    uint256[] memory tokenIds = _oneAmount(STRANDED_NFT_ID);

    vm.expectEmit(address(hub));
    emit IManagementRescuable.RescueERC721s(tokens, tokenIds, recipient);

    vm.prank(rescuer);
    hub.rescueERC721s(tokens, tokenIds, recipient);

    assertEq(nft.ownerOf(STRANDED_NFT_ID), recipient, 'recovered');
    assertEq(nft.ownerOf(NFT_ID), owner, 'the owner keeps what was never stranded');
  }

  /// MGMT-10 — the ERC1155 path resolves a zero amount but reports the caller's array untouched
  function test_MGMT_10_rescueErc1155s() public {
    ERC1155SeedMock multi = new ERC1155SeedMock();
    multi.mintUnchecked(address(hub), 1, 10);
    multi.mintUnchecked(address(hub), 2, 20);

    IERC1155[] memory tokens = new IERC1155[](2);
    tokens[0] = IERC1155(address(multi));
    tokens[1] = IERC1155(address(multi));

    uint256[] memory tokenIds = new uint256[](2);
    tokenIds[0] = 1;
    tokenIds[1] = 2;

    uint256[] memory amounts = new uint256[](2);
    amounts[0] = 0; // sweep
    amounts[1] = 5; // exactly this much

    bytes[] memory datas = new bytes[](2);

    // Unlike the ERC20 path, `amounts` is calldata here, so the event reports the zero rather than
    // the balance the sweep resolved to
    vm.expectEmit(address(hub));
    emit IManagementRescuable.RescueERC1155s(tokens, tokenIds, amounts, recipient);

    vm.prank(rescuer);
    hub.rescueERC1155s(tokens, tokenIds, amounts, datas, recipient);

    assertEq(multi.balanceOf(recipient, 1), 10, 'swept');
    assertEq(multi.balanceOf(address(hub), 1), 0, 'nothing left behind');
    assertEq(multi.balanceOf(recipient, 2), 5, 'named amount');
    assertEq(multi.balanceOf(address(hub), 2), 15, 'the rest stays put');
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

  /// MGMT-11b — the default admin role is not grantable, even by the default admin
  function test_MGMT_11b_grantRoleRejectsDefaultAdmin() public {
    vm.prank(admin);
    vm.expectRevert(IAccessControlDefaultAdminRules.AccessControlEnforcedDefaultAdminRules.selector);
    hub.grantRole(ADMIN_ROLE, relayer);

    assertFalse(hub.hasRole(ADMIN_ROLE, relayer), 'nothing granted');
    assertEq(hub.defaultAdmin(), admin, 'admin unchanged');
  }

  // -----------------------------------------------------------------------------------------------
  // Helpers
  // -----------------------------------------------------------------------------------------------

  function _one(address a) internal pure returns (address[] memory out) {
    out = new address[](1);
    out[0] = a;
  }

  function _oneAmount(uint256 a) internal pure returns (uint256[] memory out) {
    out = new uint256[](1);
    out[0] = a;
  }
}
