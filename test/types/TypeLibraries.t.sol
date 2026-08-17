// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {TypeLibraryHarness} from '../mocks/TypeLibraryHarness.sol';

import {ERC20Params} from 'src/types/ERC20Params.sol';
import {ERC20Transfer} from 'src/types/ERC20Transfer.sol';
import {ERC721Params} from 'src/types/ERC721Params.sol';
import {ERC721Transfer} from 'src/types/ERC721Transfer.sol';
import {GenericCall} from 'src/types/GenericCall.sol';
import {NativeTransfer} from 'src/types/NativeTransfer.sol';
import {RelayerWitness} from 'src/types/RelayerWitness.sol';
import {SolverWitness} from 'src/types/SolverWitness.sol';
import {ValidationParams} from 'src/types/ValidationParams.sol';

import {ISignatureTransfer} from 'ks-common-sc/src/interfaces/ISignatureTransfer.sol';

import {Test} from 'forge-std/Test.sol';

/**
 * @notice Unit cases for the `src/types` libraries, reached through `TypeLibraryHarness`
 * @dev These libraries are shared verbatim by `KSAllowanceHub` and `KSAllowanceHubV2`, so this
 * batch belongs to neither version and deploys no hub at all — the addresses below are arbitrary
 * struct payloads, not live contracts.
 * @dev This is the suite's ORACLE INDEPENDENCE ANCHOR.
 * Every expected typehash, type string and struct hash below is written out from the EIP-712 rules
 * and the Solidity struct declarations by hand. This file therefore deliberately imports the
 * `src/types` STRUCTS only, never the libraries, and never reads a production constant to build an
 * expected value — the production constants are only ever the value under test, read back through
 * the harness. Without that separation the witness cases in the Permit2 batches would prove nothing
 * but self-consistency, because they sign with the very constants they check.
 */
contract TypeLibrariesTest is Test {
  TypeLibraryHarness internal types;

  // Arbitrary, distinct addresses used purely as struct field values.
  address internal tokenA = makeAddr('tokenA');
  address internal tokenB = makeAddr('tokenB');
  address internal nft = makeAddr('nft');
  address internal nftV4 = makeAddr('nftV4');
  address internal plainNft = makeAddr('plainNft');
  address internal plainToken = makeAddr('plainToken');
  address internal routerA = makeAddr('routerA');
  address internal routerB = makeAddr('routerB');
  address internal validatorA = makeAddr('validatorA');
  address internal validatorB = makeAddr('validatorB');
  address internal unlistedRouter = makeAddr('unlistedRouter');
  address internal reentrantRouter = makeAddr('reentrantRouter');
  address internal recipient = makeAddr('recipient');
  address internal other = makeAddr('other');
  address internal relayer = makeAddr('relayer');
  address internal solver = makeAddr('solver');

  function setUp() public {
    types = new TypeLibraryHarness();
  }

  /* ------------------------------------ hand-written EIP-712 type strings */
  // Transcribed from the struct declarations in `src/types/*.sol`, not from the library constants.

  string private constant ERC721_TRANSFER_TYPE =
    'ERC721Transfer(address token,uint256 tokenId,address target)';

  string private constant GENERIC_CALL_TYPE =
    'GenericCall(address router,uint256 value,bytes data)';

  string private constant VALIDATION_PARAMS_TYPE =
    'ValidationParams(address validator,bytes32 action,bytes beforeExecutionInput,bytes afterExecutionInput)';

  string private constant RELAYER_WITNESS_TYPE =
    'RelayerWitness(address relayer,address[] targets,ERC721Transfer[] erc721Transfers,GenericCall[] genericCalls)';

  string private constant SOLVER_WITNESS_TYPE =
    'SolverWitness(address solver,address[] targets,ERC721Transfer[] erc721Transfers,ValidationParams[] validationParams)';

  /// @dev Part of the Permit2 outer type, never of a witness typehash
  string private constant TOKEN_PERMISSIONS_TYPE = 'TokenPermissions(address token,uint256 amount)';

  /* ------------------------------------------------------- fuzz containers */

  struct RelayerWitnessFuzz {
    address relayer;
    address target;
    address nftToken;
    uint256 nftTokenId;
    address nftTarget;
    address router;
    uint96 callValue;
    bytes callData;
  }

  struct SolverWitnessFuzz {
    address solver;
    address target;
    address nftToken;
    uint256 nftTokenId;
    address nftTarget;
    address validator;
    bytes32 action;
    bytes beforeInput;
    bytes afterInput;
  }

  /// @dev Result of pulling a Permit2 witness type string apart, so the test can assert each part
  struct TypeStringParts {
    bool hasWitnessStub;
    bool sortedAlphabetically;
    bool hasTokenPermissions;
    bytes typehashString;
  }

  /* --------------------------------------------------------------- TYP-01 */

  /// @notice TYP-01 `NativeTransferLibrary.toTransfers` keeps value-bearing calls and truncates
  function test_nativeTransferTruncation() public view {
    // Mixed: the assembly `mstore` truncation actually has to shrink the array here
    GenericCall[] memory mixed = new GenericCall[](4);
    mixed[0] = GenericCall({router: routerA, value: 0, data: hex'01'});
    mixed[1] = GenericCall({router: routerB, value: 5 ether, data: hex'02'});
    mixed[2] = GenericCall({router: unlistedRouter, value: 0, data: hex'03'});
    mixed[3] = GenericCall({router: reentrantRouter, value: 7, data: hex'04'});

    NativeTransfer[] memory out = types.nativeTransfers(mixed);
    assertEq(out.length, 2, 'mixed length');
    assertEq(out[0].target, routerB, 'mixed[0] target');
    assertEq(out[0].amount, 5 ether, 'mixed[0] amount');
    assertEq(out[1].target, reentrantRouter, 'mixed[1] target');
    assertEq(out[1].amount, 7, 'mixed[1] amount');

    // All zero: every entry is dropped, so the array is truncated to nothing
    GenericCall[] memory allZero = new GenericCall[](3);
    allZero[0] = GenericCall({router: routerA, value: 0, data: ''});
    allZero[1] = GenericCall({router: routerB, value: 0, data: hex'aa'});
    allZero[2] = GenericCall({router: unlistedRouter, value: 0, data: hex'bb'});

    assertEq(types.nativeTransfers(allZero).length, 0, 'all-zero length');

    // All non-zero: nothing is truncated and call order is preserved
    GenericCall[] memory allValued = new GenericCall[](3);
    allValued[0] = GenericCall({router: routerA, value: 1, data: ''});
    allValued[1] = GenericCall({router: routerB, value: 2, data: ''});
    allValued[2] = GenericCall({router: unlistedRouter, value: 3, data: ''});

    NativeTransfer[] memory full = types.nativeTransfers(allValued);
    assertEq(full.length, 3, 'all-valued length');
    for (uint256 i = 0; i < full.length; i++) {
      assertEq(full[i].target, allValued[i].router, 'all-valued target');
      assertEq(full[i].amount, allValued[i].value, 'all-valued amount');
    }

    assertEq(types.nativeTransfers(new GenericCall[](0)).length, 0, 'empty input');
  }

  /* --------------------------------------------------------------- TYP-02 */

  /// @notice TYP-02 `ERC20TransferLibrary.toTransfers` flattens param-major then target-major
  function test_erc20ParamsFlattening() public view {
    // The two entries carry a DIFFERENT number of targets, so an inverted loop order would show up
    address[] memory targetsA = new address[](3);
    targetsA[0] = routerA;
    targetsA[1] = routerB;
    targetsA[2] = recipient;
    uint256[] memory amountsA = new uint256[](3);
    amountsA[0] = 1 ether;
    amountsA[1] = 2 ether;
    amountsA[2] = 3 ether;

    address[] memory targetsB = new address[](1);
    targetsB[0] = unlistedRouter;
    uint256[] memory amountsB = new uint256[](1);
    amountsB[0] = 4 ether;

    ERC20Params[] memory params = new ERC20Params[](2);
    params[0] =
      ERC20Params({token: tokenA, targets: targetsA, amounts: amountsA, permitData: hex'de'});
    params[1] = ERC20Params({token: tokenB, targets: targetsB, amounts: amountsB, permitData: ''});

    ERC20Transfer[] memory out = types.erc20Transfers(params);

    assertEq(out.length, 4, 'flattened length is the sum of the target counts');

    assertEq(out[0].token, tokenA, 'out[0] token');
    assertEq(out[0].target, routerA, 'out[0] target');
    assertEq(out[0].amount, 1 ether, 'out[0] amount');

    assertEq(out[1].token, tokenA, 'out[1] token');
    assertEq(out[1].target, routerB, 'out[1] target');
    assertEq(out[1].amount, 2 ether, 'out[1] amount');

    assertEq(out[2].token, tokenA, 'out[2] token');
    assertEq(out[2].target, recipient, 'out[2] target');
    assertEq(out[2].amount, 3 ether, 'out[2] amount');

    assertEq(out[3].token, tokenB, 'out[3] token');
    assertEq(out[3].target, unlistedRouter, 'out[3] target');
    assertEq(out[3].amount, 4 ether, 'out[3] amount');

    assertEq(types.erc20Transfers(new ERC20Params[](0)).length, 0, 'no params, no transfers');
  }

  /* --------------------------------------------------------------- TYP-03 */

  /// @notice TYP-03 the Permit2 overload pairs each permitted token with the target at its index
  function test_permittedTargetPairing() public view {
    ISignatureTransfer.TokenPermissions[] memory permitted =
      new ISignatureTransfer.TokenPermissions[](3);
    permitted[0] = ISignatureTransfer.TokenPermissions({token: tokenA, amount: 10});
    permitted[1] = ISignatureTransfer.TokenPermissions({token: tokenB, amount: 20});
    permitted[2] = ISignatureTransfer.TokenPermissions({token: plainToken, amount: 30});

    address[] memory targets = new address[](3);
    targets[0] = routerA;
    targets[1] = recipient;
    targets[2] = routerB;

    ERC20Transfer[] memory out = types.erc20Transfers(permitted, targets);

    assertEq(out.length, 3, 'one transfer per permitted token');
    for (uint256 i = 0; i < out.length; i++) {
      assertEq(out[i].token, permitted[i].token, 'token index alignment');
      assertEq(out[i].amount, permitted[i].amount, 'amount index alignment');
      assertEq(out[i].target, targets[i], 'target index alignment');
    }

    assertEq(
      types.erc20Transfers(new ISignatureTransfer.TokenPermissions[](0), new address[](0)).length,
      0,
      'empty permitted, no transfers'
    );
  }

  /* --------------------------------------------------------------- TYP-04 */

  /// @notice TYP-04 ERC721 projection drops `permitData`, and its hash matches the hand-written type
  function test_erc721TransferProjectionAndHash() public view {
    ERC721Params[] memory params = new ERC721Params[](2);
    params[0] = ERC721Params({token: nft, tokenId: 7, target: recipient, permitData: hex'deadbeef'});
    params[1] = ERC721Params({token: plainNft, tokenId: 99, target: routerA, permitData: ''});

    ERC721Transfer[] memory out = types.erc721Transfers(params);
    assertEq(out.length, 2, 'one transfer per param');
    for (uint256 i = 0; i < out.length; i++) {
      assertEq(out[i].token, params[i].token, 'token');
      assertEq(out[i].tokenId, params[i].tokenId, 'tokenId');
      assertEq(out[i].target, params[i].target, 'target');
    }

    // `permitData` authorises the move but is not part of what is projected or signed
    ERC721Params[] memory rePermitted = new ERC721Params[](1);
    rePermitted[0] =
      ERC721Params({token: nft, tokenId: 7, target: recipient, permitData: hex'00112233'});
    ERC721Transfer[] memory reprojected = types.erc721Transfers(rePermitted);
    assertEq(
      types.hashErc721Transfer(reprojected[0]),
      types.hashErc721Transfer(out[0]),
      'permitData does not reach the hash'
    );

    assertEq(
      types.erc721TransferTypehash(),
      keccak256(bytes(ERC721_TRANSFER_TYPE)),
      'ERC721Transfer typehash'
    );
    assertEq(types.hashErc721Transfer(out[0]), _handErc721TransferHash(out[0]), 'hash[0]');
    assertEq(types.hashErc721Transfer(out[1]), _handErc721TransferHash(out[1]), 'hash[1]');
    assertTrue(
      types.hashErc721Transfer(out[0]) != types.hashErc721Transfer(out[1]), 'distinct transfers'
    );
  }

  /* --------------------------------------------------------------- TYP-05 */

  /// @notice TYP-05 `GenericCallLibrary.hash` matches the hand-written type, with `data` hashed
  function test_genericCallHash() public view {
    assertEq(
      types.genericCallTypehash(), keccak256(bytes(GENERIC_CALL_TYPE)), 'GenericCall typehash'
    );

    GenericCall memory call = GenericCall({router: routerA, value: 12 ether, data: hex'a1b2c3d4e5'});
    assertEq(types.hashGenericCall(call), _handGenericCallHash(call), 'non-empty data');

    // The dynamic `bytes` member is encoded as `keccak256(data)`, so the empty payload still hashes
    GenericCall memory emptyData = GenericCall({router: routerB, value: 0, data: ''});
    assertEq(types.hashGenericCall(emptyData), _handGenericCallHash(emptyData), 'empty data');

    assertTrue(
      types.hashGenericCall(call) != types.hashGenericCall(emptyData), 'distinct calls differ'
    );
  }

  /* --------------------------------------------------------------- TYP-06 */

  /// @notice TYP-06 `ValidationParamsLibrary.hash` hashes both `bytes` members, distinctly
  function test_validationParamsHash() public view {
    assertEq(
      types.validationParamsTypehash(),
      keccak256(bytes(VALIDATION_PARAMS_TYPE)),
      'ValidationParams typehash'
    );

    ValidationParams memory params = ValidationParams({
      validator: validatorA,
      action: keccak256('SWAP'),
      beforeExecutionInput: hex'0011',
      afterExecutionInput: hex'2233445566'
    });
    assertEq(types.hashValidationParams(params), _handValidationParamsHash(params), 'hand-computed');

    // Swapping the two payloads must move the hash, so neither member is dropped or conflated
    ValidationParams memory swapped = ValidationParams({
      validator: params.validator,
      action: params.action,
      beforeExecutionInput: params.afterExecutionInput,
      afterExecutionInput: params.beforeExecutionInput
    });
    assertTrue(
      types.hashValidationParams(swapped) != types.hashValidationParams(params),
      'before/after inputs are not interchangeable'
    );

    ValidationParams memory emptyInputs = ValidationParams({
      validator: validatorB, action: bytes32(0), beforeExecutionInput: '', afterExecutionInput: ''
    });
    assertEq(
      types.hashValidationParams(emptyInputs),
      _handValidationParamsHash(emptyInputs),
      'empty inputs'
    );
  }

  /* --------------------------------------------------------------- TYP-07 */

  /// @notice TYP-07 both `RelayerWitnessLibrary.hash` overloads agree with the hand-computed hash
  function test_relayerWitnessHash() public view {
    address[] memory targets = new address[](2);
    targets[0] = routerA;
    targets[1] = recipient;

    ERC721Transfer[] memory transfers = new ERC721Transfer[](2);
    transfers[0] = ERC721Transfer({token: nft, tokenId: 1, target: routerA});
    transfers[1] = ERC721Transfer({token: plainNft, tokenId: 2, target: recipient});

    GenericCall[] memory calls = new GenericCall[](2);
    calls[0] = GenericCall({router: routerA, value: 1 ether, data: hex'1122'});
    calls[1] = GenericCall({router: routerB, value: 0, data: ''});

    bytes32 expected = _handRelayerWitnessHash(relayer, targets, transfers, calls);
    bytes32 fromFields = types.hashRelayerWitnessFields(relayer, targets, transfers, calls);
    assertEq(fromFields, expected, 'loose-args overload matches the hand-computed hash');

    RelayerWitness memory witness = RelayerWitness({
      relayer: relayer, targets: targets, erc721Transfers: transfers, genericCalls: calls
    });
    assertEq(types.hashRelayerWitness(witness), expected, 'struct overload matches');

    // Both inner loops must also degrade correctly to zero iterations
    address[] memory noTargets = new address[](0);
    ERC721Transfer[] memory noTransfers = new ERC721Transfer[](0);
    GenericCall[] memory noCalls = new GenericCall[](0);
    bytes32 emptyExpected = _handRelayerWitnessHash(relayer, noTargets, noTransfers, noCalls);
    assertEq(
      types.hashRelayerWitnessFields(relayer, noTargets, noTransfers, noCalls),
      emptyExpected,
      'empty arrays, loose args'
    );
    assertEq(
      types.hashRelayerWitness(
        RelayerWitness({
          relayer: relayer, targets: noTargets, erc721Transfers: noTransfers, genericCalls: noCalls
        })
      ),
      emptyExpected,
      'empty arrays, struct'
    );
    assertTrue(emptyExpected != expected, 'populated and empty witnesses differ');
  }

  /* --------------------------------------------------------------- TYP-08 */

  /// @notice TYP-08 both `SolverWitnessLibrary.hash` overloads agree with the hand-computed hash
  function test_solverWitnessHash() public view {
    address[] memory targets = new address[](2);
    targets[0] = routerB;
    targets[1] = recipient;

    ERC721Transfer[] memory transfers = new ERC721Transfer[](2);
    transfers[0] = ERC721Transfer({token: nft, tokenId: 3, target: routerB});
    transfers[1] = ERC721Transfer({token: nftV4, tokenId: 4, target: recipient});

    ValidationParams[] memory params = new ValidationParams[](2);
    params[0] = ValidationParams({
      validator: validatorA,
      action: keccak256('MIN_OUT'),
      beforeExecutionInput: hex'aabb',
      afterExecutionInput: hex'ccdd'
    });
    params[1] = ValidationParams({
      validator: validatorB,
      action: bytes32(uint256(7)),
      beforeExecutionInput: '',
      afterExecutionInput: hex'ee'
    });

    bytes32 expected = _handSolverWitnessHash(solver, targets, transfers, params);
    assertEq(
      types.hashSolverWitnessFields(solver, targets, transfers, params),
      expected,
      'loose-args overload matches the hand-computed hash'
    );

    SolverWitness memory witness = SolverWitness({
      solver: solver, targets: targets, erc721Transfers: transfers, validationParams: params
    });
    assertEq(types.hashSolverWitness(witness), expected, 'struct overload matches');

    address[] memory noTargets = new address[](0);
    ERC721Transfer[] memory noTransfers = new ERC721Transfer[](0);
    ValidationParams[] memory noParams = new ValidationParams[](0);
    bytes32 emptyExpected = _handSolverWitnessHash(solver, noTargets, noTransfers, noParams);
    assertEq(
      types.hashSolverWitnessFields(solver, noTargets, noTransfers, noParams),
      emptyExpected,
      'empty arrays, loose args'
    );
    assertEq(
      types.hashSolverWitness(
        SolverWitness({
          solver: solver,
          targets: noTargets,
          erc721Transfers: noTransfers,
          validationParams: noParams
        })
      ),
      emptyExpected,
      'empty arrays, struct'
    );
    assertTrue(emptyExpected != expected, 'populated and empty witnesses differ');
  }

  /* --------------------------------------------------------------- TYP-09 */

  /**
   * @notice TYP-09 each Permit2 witness type string is consistent with its own typehash
   * @dev The type string carries the referenced struct definitions sorted alphabetically and
   * includes `TokenPermissions`, which belongs to the Permit2 outer type. The typehash carries the
   * SAME definitions with the witness struct hoisted to the front and `TokenPermissions` removed.
   * The test rebuilds one from the other, so any EIP-712 struct-ordering drift between the two
   * production constants fails here even though both are hashed consistently on their own.
   */
  function test_relayerTypeStringMatchesTypehash() public view {
    TypeStringParts memory parts =
      _decomposeTypeString(types.relayerWitnessTypeString(), 'RelayerWitness');

    assertTrue(parts.hasWitnessStub, 'type string opens with `RelayerWitness witness)`');
    assertTrue(parts.sortedAlphabetically, 'referenced struct definitions are sorted');
    assertTrue(parts.hasTokenPermissions, 'type string carries the TokenPermissions definition');

    assertEq(
      string(parts.typehashString),
      string.concat(RELAYER_WITNESS_TYPE, ERC721_TRANSFER_TYPE, GENERIC_CALL_TYPE),
      'reconstructed typehash string'
    );
    assertEq(
      types.relayerWitnessTypehash(),
      keccak256(parts.typehashString),
      'typehash is the hash of the string derived from the type string'
    );
  }

  /// @notice TYP-09 the same consistency requirement for the solver witness
  function test_solverTypeStringMatchesTypehash() public view {
    TypeStringParts memory parts =
      _decomposeTypeString(types.solverWitnessTypeString(), 'SolverWitness');

    assertTrue(parts.hasWitnessStub, 'type string opens with `SolverWitness witness)`');
    assertTrue(parts.sortedAlphabetically, 'referenced struct definitions are sorted');
    assertTrue(parts.hasTokenPermissions, 'type string carries the TokenPermissions definition');

    assertEq(
      string(parts.typehashString),
      string.concat(SOLVER_WITNESS_TYPE, ERC721_TRANSFER_TYPE, VALIDATION_PARAMS_TYPE),
      'reconstructed typehash string'
    );
    assertEq(
      types.solverWitnessTypehash(),
      keccak256(parts.typehashString),
      'typehash is the hash of the string derived from the type string'
    );
  }

  /* --------------------------------------------------------------- TYP-10 */

  /// @notice TYP-10 every `RelayerWitness` member is bound: changing one alone moves the hash
  function testFuzz_relayerWitnessInjectivity(RelayerWitnessFuzz memory f) public view {
    bytes32 base = _relayerHash(f);

    f.relayer = address(uint160(f.relayer) ^ 1);
    assertTrue(_relayerHash(f) != base, 'relayer is bound');
    f.relayer = address(uint160(f.relayer) ^ 1);

    f.target = address(uint160(f.target) ^ 1);
    assertTrue(_relayerHash(f) != base, 'targets are bound');
    f.target = address(uint160(f.target) ^ 1);

    f.nftToken = address(uint160(f.nftToken) ^ 1);
    assertTrue(_relayerHash(f) != base, 'erc721 token is bound');
    f.nftToken = address(uint160(f.nftToken) ^ 1);

    f.nftTokenId = f.nftTokenId ^ 1;
    assertTrue(_relayerHash(f) != base, 'erc721 tokenId is bound');
    f.nftTokenId = f.nftTokenId ^ 1;

    f.nftTarget = address(uint160(f.nftTarget) ^ 1);
    assertTrue(_relayerHash(f) != base, 'erc721 target is bound');
    f.nftTarget = address(uint160(f.nftTarget) ^ 1);

    f.router = address(uint160(f.router) ^ 1);
    assertTrue(_relayerHash(f) != base, 'generic call router is bound');
    f.router = address(uint160(f.router) ^ 1);

    f.callValue = f.callValue ^ 1;
    assertTrue(_relayerHash(f) != base, 'generic call value is bound');
    f.callValue = f.callValue ^ 1;

    bytes memory originalData = f.callData;
    f.callData = bytes.concat(originalData, hex'00');
    assertTrue(_relayerHash(f) != base, 'generic call data is bound');
    f.callData = originalData;

    // Proves every mutation above was actually undone, so each assertion isolated one member
    assertEq(_relayerHash(f), base, 'witness restored to its original value');
  }

  /// @notice TYP-10 every `SolverWitness` member is bound: changing one alone moves the hash
  function testFuzz_solverWitnessInjectivity(SolverWitnessFuzz memory f) public view {
    bytes32 base = _solverHash(f);

    f.solver = address(uint160(f.solver) ^ 1);
    assertTrue(_solverHash(f) != base, 'solver is bound');
    f.solver = address(uint160(f.solver) ^ 1);

    f.target = address(uint160(f.target) ^ 1);
    assertTrue(_solverHash(f) != base, 'targets are bound');
    f.target = address(uint160(f.target) ^ 1);

    f.nftToken = address(uint160(f.nftToken) ^ 1);
    assertTrue(_solverHash(f) != base, 'erc721 token is bound');
    f.nftToken = address(uint160(f.nftToken) ^ 1);

    f.nftTokenId = f.nftTokenId ^ 1;
    assertTrue(_solverHash(f) != base, 'erc721 tokenId is bound');
    f.nftTokenId = f.nftTokenId ^ 1;

    f.nftTarget = address(uint160(f.nftTarget) ^ 1);
    assertTrue(_solverHash(f) != base, 'erc721 target is bound');
    f.nftTarget = address(uint160(f.nftTarget) ^ 1);

    f.validator = address(uint160(f.validator) ^ 1);
    assertTrue(_solverHash(f) != base, 'validator is bound');
    f.validator = address(uint160(f.validator) ^ 1);

    f.action = f.action ^ bytes32(uint256(1));
    assertTrue(_solverHash(f) != base, 'action is bound');
    f.action = f.action ^ bytes32(uint256(1));

    bytes memory originalBefore = f.beforeInput;
    f.beforeInput = bytes.concat(originalBefore, hex'00');
    assertTrue(_solverHash(f) != base, 'beforeExecutionInput is bound');
    f.beforeInput = originalBefore;

    bytes memory originalAfter = f.afterInput;
    f.afterInput = bytes.concat(originalAfter, hex'00');
    assertTrue(_solverHash(f) != base, 'afterExecutionInput is bound');
    f.afterInput = originalAfter;

    assertEq(_solverHash(f), base, 'witness restored to its original value');
  }

  /* -------------------------------------------- hand-computed EIP-712 hashes */

  function _handErc721TransferHash(ERC721Transfer memory transfer) private pure returns (bytes32) {
    return keccak256(
      abi.encode(
        keccak256(bytes(ERC721_TRANSFER_TYPE)), transfer.token, transfer.tokenId, transfer.target
      )
    );
  }

  function _handGenericCallHash(GenericCall memory call) private pure returns (bytes32) {
    return keccak256(
      abi.encode(keccak256(bytes(GENERIC_CALL_TYPE)), call.router, call.value, keccak256(call.data))
    );
  }

  function _handValidationParamsHash(ValidationParams memory params)
    private
    pure
    returns (bytes32)
  {
    return keccak256(
      abi.encode(
        keccak256(bytes(VALIDATION_PARAMS_TYPE)),
        params.validator,
        params.action,
        keccak256(params.beforeExecutionInput),
        keccak256(params.afterExecutionInput)
      )
    );
  }

  function _handRelayerWitnessHash(
    address relayer_,
    address[] memory targets,
    ERC721Transfer[] memory erc721Transfers,
    GenericCall[] memory genericCalls
  ) private pure returns (bytes32) {
    // EIP-712: primary type first, then every referenced type in alphabetical order
    bytes32 typehash = keccak256(
      bytes(string.concat(RELAYER_WITNESS_TYPE, ERC721_TRANSFER_TYPE, GENERIC_CALL_TYPE))
    );

    bytes32[] memory transferHashes = new bytes32[](erc721Transfers.length);
    for (uint256 i = 0; i < erc721Transfers.length; i++) {
      transferHashes[i] = _handErc721TransferHash(erc721Transfers[i]);
    }

    bytes32[] memory callHashes = new bytes32[](genericCalls.length);
    for (uint256 i = 0; i < genericCalls.length; i++) {
      callHashes[i] = _handGenericCallHash(genericCalls[i]);
    }

    return keccak256(
      abi.encode(
        typehash,
        relayer_,
        keccak256(abi.encodePacked(targets)),
        keccak256(abi.encodePacked(transferHashes)),
        keccak256(abi.encodePacked(callHashes))
      )
    );
  }

  function _handSolverWitnessHash(
    address solver_,
    address[] memory targets,
    ERC721Transfer[] memory erc721Transfers,
    ValidationParams[] memory validationParams
  ) private pure returns (bytes32) {
    bytes32 typehash = keccak256(
      bytes(string.concat(SOLVER_WITNESS_TYPE, ERC721_TRANSFER_TYPE, VALIDATION_PARAMS_TYPE))
    );

    bytes32[] memory transferHashes = new bytes32[](erc721Transfers.length);
    for (uint256 i = 0; i < erc721Transfers.length; i++) {
      transferHashes[i] = _handErc721TransferHash(erc721Transfers[i]);
    }

    bytes32[] memory paramsHashes = new bytes32[](validationParams.length);
    for (uint256 i = 0; i < validationParams.length; i++) {
      paramsHashes[i] = _handValidationParamsHash(validationParams[i]);
    }

    return keccak256(
      abi.encode(
        typehash,
        solver_,
        keccak256(abi.encodePacked(targets)),
        keccak256(abi.encodePacked(transferHashes)),
        keccak256(abi.encodePacked(paramsHashes))
      )
    );
  }

  /* --------------------------------------------------- fuzz witness builders */

  function _relayerHash(RelayerWitnessFuzz memory f) private view returns (bytes32) {
    address[] memory targets = new address[](1);
    targets[0] = f.target;

    ERC721Transfer[] memory transfers = new ERC721Transfer[](1);
    transfers[0] = ERC721Transfer({token: f.nftToken, tokenId: f.nftTokenId, target: f.nftTarget});

    GenericCall[] memory calls = new GenericCall[](1);
    calls[0] = GenericCall({router: f.router, value: f.callValue, data: f.callData});

    return types.hashRelayerWitnessFields(f.relayer, targets, transfers, calls);
  }

  function _solverHash(SolverWitnessFuzz memory f) private view returns (bytes32) {
    address[] memory targets = new address[](1);
    targets[0] = f.target;

    ERC721Transfer[] memory transfers = new ERC721Transfer[](1);
    transfers[0] = ERC721Transfer({token: f.nftToken, tokenId: f.nftTokenId, target: f.nftTarget});

    ValidationParams[] memory params = new ValidationParams[](1);
    params[0] = ValidationParams({
      validator: f.validator,
      action: f.action,
      beforeExecutionInput: f.beforeInput,
      afterExecutionInput: f.afterInput
    });

    return types.hashSolverWitnessFields(f.solver, targets, transfers, params);
  }

  /* ------------------------------------------------- type-string decomposition */

  /**
   * @dev Splits a Permit2 witness type string into the parts EIP-712 requires, and rebuilds the
   * string the corresponding typehash must be computed over.
   * @param typeString The production `X witness)...` string under test
   * @param structName The name of the witness struct, e.g. `RelayerWitness`
   */
  function _decomposeTypeString(string memory typeString, string memory structName)
    private
    pure
    returns (TypeStringParts memory parts)
  {
    bytes memory raw = bytes(typeString);
    bytes memory stub = bytes(string.concat(structName, ' witness)'));

    parts.hasWitnessStub = _startsWith(raw, stub, 0);
    if (!parts.hasWitnessStub) return parts;

    bytes[] memory defs = _splitStructDefs(raw, stub.length);

    parts.sortedAlphabetically = true;
    for (uint256 i = 1; i < defs.length; i++) {
      if (!_lexLte(defs[i - 1], defs[i])) parts.sortedAlphabetically = false;
    }

    bytes32 tokenPermissions = keccak256(bytes(TOKEN_PERMISSIONS_TYPE));
    bytes memory primaryPrefix = bytes(string.concat(structName, '('));

    bytes memory primary;
    bytes memory referenced;
    for (uint256 i = 0; i < defs.length; i++) {
      if (keccak256(defs[i]) == tokenPermissions) {
        parts.hasTokenPermissions = true;
        continue;
      }
      if (_startsWith(defs[i], primaryPrefix, 0)) {
        primary = defs[i];
        continue;
      }
      referenced = bytes.concat(referenced, defs[i]);
    }

    parts.typehashString = bytes.concat(primary, referenced);
  }

  /// @dev Splits `raw[start:]` after each `)`; the struct definitions contain no nested parentheses
  function _splitStructDefs(bytes memory raw, uint256 start)
    private
    pure
    returns (bytes[] memory defs)
  {
    uint256 count = 0;
    for (uint256 i = start; i < raw.length; i++) {
      if (raw[i] == ')') count++;
    }

    defs = new bytes[](count);
    uint256 index = 0;
    uint256 from = start;
    for (uint256 i = start; i < raw.length; i++) {
      if (raw[i] == ')') {
        defs[index++] = _slice(raw, from, i + 1);
        from = i + 1;
      }
    }
  }

  function _slice(bytes memory raw, uint256 from, uint256 to)
    private
    pure
    returns (bytes memory out)
  {
    out = new bytes(to - from);
    for (uint256 i = 0; i < out.length; i++) {
      out[i] = raw[from + i];
    }
  }

  function _startsWith(bytes memory raw, bytes memory prefix, uint256 offset)
    private
    pure
    returns (bool)
  {
    if (raw.length < offset + prefix.length) return false;
    for (uint256 i = 0; i < prefix.length; i++) {
      if (raw[offset + i] != prefix[i]) return false;
    }
    return true;
  }

  function _lexLte(bytes memory a, bytes memory b) private pure returns (bool) {
    uint256 shortest = a.length < b.length ? a.length : b.length;
    for (uint256 i = 0; i < shortest; i++) {
      if (a[i] != b[i]) return uint8(a[i]) < uint8(b[i]);
    }
    return a.length <= b.length;
  }
}
