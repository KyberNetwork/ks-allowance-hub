// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from 'forge-std/Test.sol';

import {CallParams} from '../../src/types/CallParams.sol';
import {ERC20Allowance} from '../../src/types/ERC20Allowance.sol';
import {ERC20Transfer} from '../../src/types/ERC20Transfer.sol';
import {ERC721Approval} from '../../src/types/ERC721Approval.sol';
import {ERC721Transfer} from '../../src/types/ERC721Transfer.sol';
import {HookParams} from '../../src/types/HookParams.sol';

import {ISignatureTransfer} from 'ks-common-sc/src/interfaces/ISignatureTransfer.sol';

import {
  IERC20Permit
} from 'openzeppelin-contracts/contracts/token/ERC20/extensions/IERC20Permit.sol';

/**
 * @title V2TestBase
 * @notice Global base for the V2 suite.
 * @dev Struct hashes come from {SchemaHash}, which derives them from the Solidity struct
 * definitions through the `forge bind-json` schemas. This contract assembles digests from those
 * struct hashes: the hub and Permit2 domains, the typed-data envelope and the Permit2 permit
 * structures. Nothing here may import a production constant or hashing library: Permit2 derives
 * its typehash from the string the hub passes it, so a test that signs with the same production
 * constant would agree with a wrong type string as readily as with a right one.
 * `test/types/SchemaAudit.t.sol` compares the production constants against the schemas.
 *
 * The struct types are imported for their ABI shape only. Each one carries a `using ... global`
 * attachment, so the production hashers are reachable from any file that imports them. They are
 * never to appear on the expected side of an assertion.
 */

abstract contract V2TestBase is Test {
  /// @dev The real Permit2, deployed from its checked-in creation code
  address internal permit2;

  /// @dev The suite's two ERC20s, 18 decimals and 6
  address internal token18;
  address internal token6;

  /// @dev Sentinel the hub uses for an order that specifies no counterparty: the zero address,
  /// written out, never imported
  address internal constant ANY = address(0);

  // ---------------------------------------------------------------------------------------------
  // Actors
  // ---------------------------------------------------------------------------------------------

  address internal admin = makeAddr('admin');
  address internal guardian = makeAddr('guardian');
  address internal rescuer = makeAddr('rescuer');
  address internal relayer = makeAddr('relayer');
  address internal solver = makeAddr('solver');
  address internal recipient = makeAddr('recipient');

  address internal owner;
  uint256 internal ownerKey;

  /// @dev Directory of the checked-in Permit2 and Multicall3 artifacts, relative to the project root
  function _artifactsDir() internal pure virtual returns (string memory) {
    return 'test/artifacts/';
  }

  /// @dev Deploys the real Permit2 on whatever chain the test is running, constructor and all, so
  /// it scopes its EIP-712 domain to this deployment
  function _deployPermit2() internal returns (address) {
    return vm.deployCode(string.concat(_artifactsDir(), 'Permit2.json'));
  }

  // ---------------------------------------------------------------------------------------------
  // Permit2 digest, rebuilt rather than imported
  // ---------------------------------------------------------------------------------------------

  /// @dev Permit2's `permitted` array, built from the order's ERC-20 allowances
  function lTokenPermissions(address[] memory tokens, uint256[] memory amounts)
    internal
    pure
    returns (ISignatureTransfer.TokenPermissions[] memory permitted)
  {
    permitted = new ISignatureTransfer.TokenPermissions[](tokens.length);
    for (uint256 i = 0; i < tokens.length; i++) {
      permitted[i] = ISignatureTransfer.TokenPermissions({token: tokens[i], amount: amounts[i]});
    }
  }

  /// @dev Read from the deployed Permit2, which is an external dependency rather than code under
  /// test
  function _permit2DomainSeparator() internal view returns (bytes32 separator) {
    (bool ok, bytes memory data) = permit2.staticcall(abi.encodeWithSignature('DOMAIN_SEPARATOR()'));
    require(ok, 'permit2 domain');
    separator = abi.decode(data, (bytes32));
  }

  /// @dev Permit2's signature-transfer nonce bitmap, read off the deployed contract
  function _permit2NonceBitmap(address account, uint256 word) internal view returns (uint256) {
    return ISignatureTransfer(permit2).nonceBitmap(account, word);
  }

  /// @dev Calldata of an EIP-2612 `permit` of `token`, named `name`, signed by the owner
  function _erc2612PermitCall(
    string memory name,
    address token,
    address spender,
    uint256 value,
    uint256 nonce,
    uint256 deadline
  ) internal view returns (bytes memory) {
    bytes32 structHash = keccak256(
      abi.encode(
        keccak256(
          'Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)'
        ),
        owner,
        spender,
        value,
        nonce,
        deadline
      )
    );
    // OpenZeppelin's ERC20Permit takes its domain name from the token and versions it '1'
    (uint8 v, bytes32 r, bytes32 s) =
      vm.sign(ownerKey, lTypedDataHash(lDomainSeparator(name, '1', token), structHash));
    return abi.encodeCall(IERC20Permit.permit, (owner, spender, value, deadline, v, r, s));
  }

  /// @dev Builds a domain separator from parts, so a test never reuses the contract's own value
  function lDomainSeparator(string memory name, string memory version, address verifyingContract)
    internal
    view
    returns (bytes32)
  {
    return keccak256(
      abi.encode(
        keccak256(
          'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'
        ),
        keccak256(bytes(name)),
        keccak256(bytes(version)),
        vm.getChainId(),
        verifyingContract
      )
    );
  }

  function lTypedDataHash(bytes32 domainSeparator, bytes32 structHash)
    internal
    pure
    returns (bytes32)
  {
    return keccak256(abi.encodePacked('\x19\x01', domainSeparator, structHash));
  }

  function _sign(uint256 key, bytes32 digest) internal pure returns (bytes memory) {
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
    return abi.encodePacked(r, s, v);
  }

  // ---------------------------------------------------------------------------------------------
  // Array builders
  // ---------------------------------------------------------------------------------------------

  /// @dev The nonce namespace of a plain account, transcribed from {UnorderedNonce}
  function lNonceKey(address signer) internal pure returns (bytes32) {
    return bytes32(uint256(uint160(signer)));
  }

  function _erc20s(ERC20Transfer memory a) internal pure returns (ERC20Transfer[] memory out) {
    out = new ERC20Transfer[](1);
    out[0] = a;
  }

  function _erc721s(ERC721Transfer memory a) internal pure returns (ERC721Transfer[] memory out) {
    out = new ERC721Transfer[](1);
    out[0] = a;
  }

  function _allowances(ERC20Allowance memory a)
    internal
    pure
    returns (ERC20Allowance[] memory out)
  {
    out = new ERC20Allowance[](1);
    out[0] = a;
  }

  function _approvals(ERC721Approval memory a) internal pure returns (ERC721Approval[] memory out) {
    out = new ERC721Approval[](1);
    out[0] = a;
  }

  function _addresses(address a) internal pure returns (address[] memory out) {
    out = new address[](1);
    out[0] = a;
  }

  function _calls(CallParams memory a) internal pure returns (CallParams[] memory out) {
    out = new CallParams[](1);
    out[0] = a;
  }

  function _calls(CallParams memory a, CallParams memory b)
    internal
    pure
    returns (CallParams[] memory out)
  {
    out = new CallParams[](2);
    out[0] = a;
    out[1] = b;
  }

  function _hooks(HookParams memory a) internal pure returns (HookParams[] memory out) {
    out = new HookParams[](1);
    out[0] = a;
  }

  function _hooks(HookParams memory a, HookParams memory b)
    internal
    pure
    returns (HookParams[] memory out)
  {
    out = new HookParams[](2);
    out[0] = a;
    out[1] = b;
  }

  /// @dev `count` empty entries, one per call
  function _solverData(uint256 count) internal pure returns (bytes[] memory) {
    return new bytes[](count);
  }

  /// @dev Splits allowances into the token and amount arrays of a Permit2 batch
  function _tokensAndAmounts(ERC20Allowance[] memory allowances)
    internal
    pure
    returns (address[] memory tokens, uint256[] memory amounts)
  {
    tokens = new address[](allowances.length);
    amounts = new uint256[](allowances.length);
    for (uint256 i = 0; i < allowances.length; i++) {
      tokens[i] = allowances[i].token;
      amounts[i] = allowances[i].amount;
    }
  }
}
