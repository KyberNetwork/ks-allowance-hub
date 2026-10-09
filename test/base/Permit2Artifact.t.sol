// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Test} from 'forge-std/Test.sol';

/**
 * @title Permit2ArtifactTest
 * @notice `ART-01` — the checked-in Permit2 creation code is the canonical deployment's
 * @dev The suite runs the real Permit2 from `test/artifacts/Permit2.json` rather than forking for
 * it, which is only sound while those bytes are the ones deployed at Permit2's address. Permit2 was
 * created by the deterministic deployer, so its address is a CREATE2 of that deployer, the salt and
 * the creation code: recomputing the address from the artifact ties the two together, offline.
 */
contract Permit2ArtifactTest is Test {
  /// @dev Deployer of Permit2, written out rather than imported
  address internal constant DETERMINISTIC_DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

  /// @dev Salt the deployment transaction passed ahead of the creation code
  bytes32 internal constant PERMIT2_SALT =
    0x0000000000000000000000000000000000000000d3af2663da51c10215000000;

  address internal constant CANONICAL_PERMIT2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;

  function test_ART_01_artifactIsTheCanonicalPermit2() public view {
    bytes memory creationCode = vm.getCode('test/artifacts/Permit2.json');

    assertEq(
      vm.computeCreate2Address(PERMIT2_SALT, keccak256(creationCode), DETERMINISTIC_DEPLOYER),
      CANONICAL_PERMIT2,
      'the artifact is the code deployed at Permit2'
    );
  }

  /// @dev ART-02 — deploying it locally gives a working contract with a domain of its own
  function test_ART_02_deploysAndScopesItsOwnDomain() public {
    address permit2 = vm.deployCode('test/artifacts/Permit2.json');

    assertGt(permit2.code.length, 0, 'deployed');
    (bool ok, bytes memory data) = permit2.staticcall(abi.encodeWithSignature('DOMAIN_SEPARATOR()'));
    assertTrue(ok, 'the separator is readable');
    assertTrue(abi.decode(data, (bytes32)) != bytes32(0), 'the constructor computed one');
  }
}
