// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {KSAllowanceHubBase} from './base/KSAllowanceHubBase.sol';

import {ArrayHelper} from '../libraries/ArrayHelper.sol';

import {KSAllowanceHub} from 'src/KSAllowanceHub.sol';

import {ERC20Params} from 'src/types/ERC20Params.sol';
import {GenericCall} from 'src/types/GenericCall.sol';

import {IManagementBase} from 'ks-common-sc/src/interfaces/IManagementBase.sol';
import {KSRoles} from 'ks-common-sc/src/libraries/KSRoles.sol';

import {IAccessControl} from 'openzeppelin-contracts/contracts/access/IAccessControl.sol';

/**
 * @notice Deployment, role lifecycle and transient-owner cases for the legacy `KSAllowanceHub`
 * @dev Only the wiring this hub performs on the inherited `ks-common-sc` management bases is
 * asserted here; the bases' own mechanics are covered upstream. Note the three distinct
 * authorisation errors in play: `pause` uses `onlyRoleOrDefaultAdmin` (`UnauthorizedAccount`),
 * `unpause` uses `onlyRole` (`AccessControlUnauthorizedAccount`), and `revokeRole` builds its own
 * `UnauthorizedAccount` from `[roleRevokers[role], getRoleAdmin(role)]`.
 */
contract KSAllowanceHubLifecycleTest is KSAllowanceHubBase {
  using ArrayHelper for *;

  /* ---------------------------------------------- locally declared events */
  // Declared here rather than inherited so `vm.expectEmit` has a matching signature in scope.

  event Paused(address account);
  event Unpaused(address account);
  event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);
  event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);
  event RescueERC20s(address[] tokens, uint256[] amounts, address recipient);

  bytes32 internal constant DEFAULT_ADMIN_ROLE = bytes32(0);

  /* ---------------------------------------------------------- construction */

  /// @notice The constructor wires Permit2, the admin, guardians, rescuers and the routers
  function test_constructorWiring() public {
    // The fixture hub is deployed with an EMPTY `initialWhitelistedRouters`, so a second hub is
    // needed to exercise that constructor argument at all.
    address[] memory guardians = [guardian, outsider].toMemoryArray();
    address[] memory rescuers = [rescuer].toMemoryArray();
    address[] memory routers = [address(routerA), address(routerB)].toMemoryArray();

    KSAllowanceHub seeded =
      new KSAllowanceHub(admin, guardians, rescuers, routers, address(permit2));
    KSAllowanceHub empty =
      new KSAllowanceHub(admin, guardians, rescuers, new address[](0), address(permit2));

    assertEq(address(seeded.PERMIT2()), address(permit2), 'seeded permit2');
    assertEq(address(hub.PERMIT2()), address(permit2), 'fixture permit2');

    assertTrue(seeded.hasRole(DEFAULT_ADMIN_ROLE, admin), 'admin holds default admin role');
    assertEq(seeded.defaultAdmin(), admin, 'defaultAdmin');
    assertFalse(seeded.hasRole(DEFAULT_ADMIN_ROLE, outsider), 'outsider is not admin');

    assertTrue(seeded.hasRole(KSRoles.GUARDIAN_ROLE, guardian), 'guardian[0]');
    assertTrue(seeded.hasRole(KSRoles.GUARDIAN_ROLE, outsider), 'guardian[1]');
    assertFalse(seeded.hasRole(KSRoles.GUARDIAN_ROLE, relayer), 'non-guardian');

    assertTrue(seeded.hasRole(KSRoles.RESCUER_ROLE, rescuer), 'rescuer[0]');
    assertFalse(seeded.hasRole(KSRoles.RESCUER_ROLE, relayer), 'non-rescuer');

    assertTrue(seeded.hasRole(WHITELIST_ROUTER_ROLE, address(routerA)), 'routerA whitelisted');
    assertTrue(seeded.hasRole(WHITELIST_ROUTER_ROLE, address(routerB)), 'routerB whitelisted');
    assertFalse(
      seeded.hasRole(WHITELIST_ROUTER_ROLE, address(unlistedRouter)), 'unlisted not whitelisted'
    );

    // The contrast hub proves the grants above come from the constructor argument and nowhere else
    assertFalse(empty.hasRole(WHITELIST_ROUTER_ROLE, address(routerA)), 'empty seeds no router');
    assertFalse(empty.hasRole(WHITELIST_ROUTER_ROLE, address(routerB)), 'empty seeds no router B');
    assertTrue(empty.hasRole(KSRoles.GUARDIAN_ROLE, guardian), 'empty still seeds guardians');

    assertFalse(seeded.paused(), 'starts unpaused');
    assertEq(seeded.msgSender(), address(0), 'no transient owner at deployment');
  }

  /// @notice The constructor sets `GUARDIAN_ROLE` as the revoker of `WHITELIST_ROUTER_ROLE`
  function test_whitelistRouterRoleRevokerIsGuardian() public view {
    assertEq(hub.roleRevokers(WHITELIST_ROUTER_ROLE), KSRoles.GUARDIAN_ROLE, 'revoker is guardian');

    // Every other role keeps the default revoker, so the mapping was set for this role specifically
    assertEq(hub.roleRevokers(KSRoles.GUARDIAN_ROLE), DEFAULT_ADMIN_ROLE, 'guardian keeps default');
    assertEq(hub.roleRevokers(KSRoles.RESCUER_ROLE), DEFAULT_ADMIN_ROLE, 'rescuer keeps default');
    assertEq(hub.roleRevokers(DEFAULT_ADMIN_ROLE), DEFAULT_ADMIN_ROLE, 'admin keeps default');
  }

  /* --------------------------------------------------------- role lifecycle */

  /// @notice A guardian can drop a router, after which calling it is rejected
  function test_guardianRevokesRouter() public {
    assertTrue(hub.hasRole(WHITELIST_ROUTER_ROLE, address(routerA)), 'routerA starts whitelisted');

    vm.expectEmit(true, true, true, true, address(hub));
    emit RoleRevoked(WHITELIST_ROUTER_ROLE, address(routerA), guardian);
    vm.prank(guardian);
    hub.revokeRole(WHITELIST_ROUTER_ROLE, address(routerA));

    assertFalse(hub.hasRole(WHITELIST_ROUTER_ROLE, address(routerA)), 'routerA dropped');
    assertTrue(hub.hasRole(WHITELIST_ROUTER_ROLE, address(routerB)), 'routerB untouched');

    _fundAndApproveHub(1 ether);
    vm.expectRevert(
      abi.encodeWithSelector(
        IAccessControl.AccessControlUnauthorizedAccount.selector,
        address(routerA),
        WHITELIST_ROUTER_ROLE
      )
    );
    vm.prank(owner);
    hub.permitTransferAndExecute(
      _erc20To(address(routerA), 1 ether), _noErc721Params(), _callTo(address(routerA))
    );

    assertEq(routerA.callCount(), 0, 'dropped router never called');
    assertEq(tokenA.balanceOf(owner), 1 ether, 'the rejected call moved nothing');
  }

  /// @notice The admin can also revoke `WHITELIST_ROUTER_ROLE`
  function test_adminCanRevokeRouterRole() public {
    assertTrue(hub.hasRole(WHITELIST_ROUTER_ROLE, address(routerB)), 'routerB starts whitelisted');

    vm.expectEmit(true, true, true, true, address(hub));
    emit RoleRevoked(WHITELIST_ROUTER_ROLE, address(routerB), admin);
    vm.prank(admin);
    hub.revokeRole(WHITELIST_ROUTER_ROLE, address(routerB));

    assertFalse(hub.hasRole(WHITELIST_ROUTER_ROLE, address(routerB)), 'routerB dropped by admin');
    assertTrue(hub.hasRole(WHITELIST_ROUTER_ROLE, address(routerA)), 'routerA untouched');
  }

  /// @notice An account that is neither a guardian nor the admin cannot revoke the router role
  function test_nonGuardianNonAdminCannotRevokeRouterRole() public {
    // `ManagementBase.revokeRole` reports `[roleRevokers[role], getRoleAdmin(role)]`
    bytes32[] memory neededRoles = new bytes32[](2);
    neededRoles[0] = KSRoles.GUARDIAN_ROLE;
    neededRoles[1] = DEFAULT_ADMIN_ROLE;

    vm.expectRevert(
      abi.encodeWithSelector(IManagementBase.UnauthorizedAccount.selector, outsider, neededRoles)
    );
    vm.prank(outsider);
    hub.revokeRole(WHITELIST_ROUTER_ROLE, address(routerA));

    // Holding some other role is not enough either
    vm.expectRevert(
      abi.encodeWithSelector(IManagementBase.UnauthorizedAccount.selector, rescuer, neededRoles)
    );
    vm.prank(rescuer);
    hub.revokeRole(WHITELIST_ROUTER_ROLE, address(routerA));

    assertTrue(hub.hasRole(KSRoles.RESCUER_ROLE, rescuer), 'rescuer really holds a role');
    assertTrue(hub.hasRole(WHITELIST_ROUTER_ROLE, address(routerA)), 'routerA still whitelisted');
  }

  /// @notice The admin can whitelist a new router, which then executes successfully
  function test_adminGrantsRouterRole() public {
    assertFalse(
      hub.hasRole(WHITELIST_ROUTER_ROLE, address(unlistedRouter)), 'router starts unlisted'
    );

    vm.expectEmit(true, true, true, true, address(hub));
    emit RoleGranted(WHITELIST_ROUTER_ROLE, address(unlistedRouter), admin);
    vm.prank(admin);
    hub.grantRole(WHITELIST_ROUTER_ROLE, address(unlistedRouter));

    assertTrue(hub.hasRole(WHITELIST_ROUTER_ROLE, address(unlistedRouter)), 'router whitelisted');

    _fundAndApproveHub(1 ether);
    vm.prank(owner);
    (bytes[] memory results,) = hub.permitTransferAndExecute(
      _erc20To(address(unlistedRouter), 1 ether),
      _noErc721Params(),
      _callTo(address(unlistedRouter))
    );

    assertEq(unlistedRouter.callCount(), 1, 'newly whitelisted router executed');
    assertEq(results.length, 1, 'one result');
    assertEq(results[0], unlistedRouter.returnData(), 'router return data forwarded');
    assertEq(tokenA.balanceOf(address(unlistedRouter)), 1 ether, 'router funded');
  }

  /* ------------------------------------------------------------ pause rules */

  /// @notice Guardian and admin can both pause, but only the admin can unpause
  function test_pauseAuthority() public {
    assertFalse(hub.paused(), 'starts unpaused');

    // Guardian can pause
    vm.expectEmit(true, true, true, true, address(hub));
    emit Paused(guardian);
    vm.prank(guardian);
    hub.pause();
    assertTrue(hub.paused(), 'guardian paused');

    // Guardian cannot unpause: `unpause` is `onlyRole(DEFAULT_ADMIN_ROLE)`, which produces the
    // OpenZeppelin error rather than the `UnauthorizedAccount` used by `onlyRoleOrDefaultAdmin`
    vm.expectRevert(
      abi.encodeWithSelector(
        IAccessControl.AccessControlUnauthorizedAccount.selector, guardian, DEFAULT_ADMIN_ROLE
      )
    );
    vm.prank(guardian);
    hub.unpause();
    assertTrue(hub.paused(), 'still paused after the rejected unpause');

    // Admin can unpause
    vm.expectEmit(true, true, true, true, address(hub));
    emit Unpaused(admin);
    vm.prank(admin);
    hub.unpause();
    assertFalse(hub.paused(), 'admin unpaused');

    // Admin can pause
    vm.expectEmit(true, true, true, true, address(hub));
    emit Paused(admin);
    vm.prank(admin);
    hub.pause();
    assertTrue(hub.paused(), 'admin paused');

    vm.prank(admin);
    hub.unpause();
    assertFalse(hub.paused(), 'admin unpaused again');
  }

  /// @notice Nobody but a guardian or the admin can pause the hub
  function testFuzz_onlyGuardianOrAdminCanPause(address caller) public {
    // Bound the caller away from the two authorised accounts instead of filtering with `assume`
    if (caller == guardian || caller == admin) caller = address(uint160(caller) ^ 1);
    if (caller == guardian || caller == admin) caller = address(uint160(caller) ^ 2);

    // `pause` is `onlyRoleOrDefaultAdmin(GUARDIAN_ROLE)`, which reports both acceptable roles
    bytes32[] memory neededRoles = new bytes32[](2);
    neededRoles[0] = KSRoles.GUARDIAN_ROLE;
    neededRoles[1] = DEFAULT_ADMIN_ROLE;

    vm.expectRevert(
      abi.encodeWithSelector(IManagementBase.UnauthorizedAccount.selector, caller, neededRoles)
    );
    vm.prank(caller);
    hub.pause();

    assertFalse(hub.paused(), 'hub stays unpaused');

    // The authorised pair is still able to pause after the rejected attempt
    vm.prank(guardian);
    hub.pause();
    assertTrue(hub.paused(), 'guardian can still pause');
  }

  /* ------------------------------------------------------- transient owner */

  /// @notice The transient owner reads as zero outside a call and is cleared afterwards
  function test_msgSenderZeroOutsideCall() public {
    assertEq(hub.msgSender(), address(0), 'zero before any call');

    _fundAndApproveHub(1 ether);
    vm.prank(owner);
    hub.permitTransferAndExecute(
      _erc20To(address(routerA), 1 ether), _noErc721Params(), _callTo(address(routerA))
    );

    // The router observed a non-zero owner mid-call, so the zero below is a real cleanup, not a
    // call that never published anything
    assertEq(routerA.callCount(), 1, 'router executed');
    assertEq(routerA.callAt(0).observedMsgSender, owner, 'owner published during the call');
    assertEq(hub.msgSender(), address(0), 'zero after the call');
  }

  /// @notice The lock is released at the end of a call, so a second call succeeds
  function test_lockReleasesBetweenCalls() public {
    _fundAndApproveHub(3 ether);

    vm.prank(owner);
    hub.permitTransferAndExecute(
      _erc20To(address(routerA), 1 ether), _noErc721Params(), _callTo(address(routerA))
    );

    // A stuck lock would make this revert `AlreadyLocked`
    vm.prank(owner);
    hub.permitTransferAndExecute(
      _erc20To(address(routerB), 2 ether), _noErc721Params(), _callTo(address(routerB))
    );

    assertEq(routerA.callCount(), 1, 'first call executed');
    assertEq(routerB.callCount(), 1, 'second call executed');
    assertEq(tokenA.balanceOf(address(routerA)), 1 ether, 'first transfer landed');
    assertEq(tokenA.balanceOf(address(routerB)), 2 ether, 'second transfer landed');
    assertEq(hub.msgSender(), address(0), 'lock released');
  }

  /* ---------------------------------------------------------- stuck native */

  /// @notice Unspent `msg.value` is stranded in the hub and only recoverable by a rescuer
  function test_strandedNativeIsStuckThenRescued() public {
    uint256 sent = 1 ether;
    uint256 spent = 0.4 ether;
    uint256 stranded = sent - spent;

    vm.deal(owner, sent);
    uint256 hubBalanceBefore = address(hub).balance;

    GenericCall[] memory calls =
      _genericCallArray(_genericCall(address(routerA), spent, hex'c0ffee'));

    vm.prank(owner);
    hub.permitTransferAndExecute{value: sent}(_noErc20Params(), _noErc721Params(), calls);

    // The hub has no refund path, so everything the generic calls did not consume stays behind
    assertEq(owner.balance, 0, 'owner paid the full msg.value');
    assertEq(address(routerA).balance, spent, 'router received its value');
    assertEq(address(hub).balance, hubBalanceBefore + stranded, 'residue stranded in the hub');

    // Independent proof that the hub exposes no `receive()`/`fallback()`: a plain value send fails
    vm.deal(address(this), 1 ether);
    (bool sendOk,) = address(hub).call{value: 1 wei}('');
    assertFalse(sendOk, 'hub rejects a bare value transfer');
    assertEq(address(hub).balance, hubBalanceBefore + stranded, 'balance untouched by the attempt');

    // The native sentinel plus amount 0 sweeps the whole balance
    address[] memory tokens = [NATIVE].toMemoryArray();
    uint256[] memory amounts = [uint256(0)].toMemoryArray();
    uint256[] memory expectedAmounts = [hubBalanceBefore + stranded].toMemoryArray();

    vm.expectEmit(true, true, true, true, address(hub));
    emit RescueERC20s(tokens, expectedAmounts, recipient);
    vm.prank(rescuer);
    hub.rescueERC20s(tokens, amounts, recipient);

    assertEq(recipient.balance, hubBalanceBefore + stranded, 'recipient received the residue');
    assertEq(address(hub).balance, 0, 'hub swept clean');
  }

  /* -------------------------------------------------------------- helpers */

  function _fundAndApproveHub(uint256 amount) private {
    _fundERC20(tokenA, owner, amount);
    _approveHub(tokenA, owner, amount);
  }

  function _erc20To(address target, uint256 amount) private view returns (ERC20Params[] memory) {
    return _erc20ParamsArray(
      _erc20Params(address(tokenA), [target].toMemoryArray(), [amount].toMemoryArray(), '')
    );
  }

  function _callTo(address router) private pure returns (GenericCall[] memory) {
    return _genericCallArray(_genericCall(router, 0, hex'1234'));
  }
}
