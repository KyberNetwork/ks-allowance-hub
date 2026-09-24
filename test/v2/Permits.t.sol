// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {HubBase} from 'test/v2/base/HubBase.sol';

import {
  ERC20PermitMock,
  ERC721PermitV3Mock,
  ERC721PermitV4Mock
} from 'test/v2/mocks/PermitTokenMocks.sol';

import {IAllowanceTransfer} from 'ks-common-sc/src/interfaces/IAllowanceTransfer.sol';
import {ICommon} from 'ks-common-sc/src/interfaces/ICommon.sol';
import {CalldataDecoder} from 'ks-common-sc/src/libraries/calldata/CalldataDecoder.sol';

/// @title PermitsTest
/**
 * @notice B5 — `PF-01..09` and `PF-FUZZ`: every payload-length branch of {PermitForwarder}.
 * @dev The forwarder dispatches purely on `permitData[i].length` and swallows whatever the token
 * does, so the observable oracle is never the call's return: it is the allowance and nonce the
 * token holds afterwards. Every digest here is built from a type string written out in this file
 * from EIP-2612, the DAI permit and the ERC-721 permit drafts — no production constant appears on
 * the expected side of any assertion.
 */
contract PermitsTest is HubBase {
  // -----------------------------------------------------------------------------------------------
  // Literal type strings
  // -----------------------------------------------------------------------------------------------

  string internal constant L_EIP2612_PERMIT =
    'Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)';
  string internal constant L_DAI_PERMIT =
    'Permit(address holder,address spender,uint256 nonce,uint256 expiry,bool allowed)';
  string internal constant L_ERC721_PERMIT =
    'Permit(address spender,uint256 tokenId,uint256 nonce,uint256 deadline)';
  string internal constant L_PERMIT2_DETAILS =
    'PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)';
  string internal constant L_PERMIT2_BATCH_STUB =
    'PermitBatch(PermitDetails[] details,address spender,uint256 sigDeadline)';

  /// @dev The canonical DAI, which is the reference implementation of the seven-word permit
  address internal constant DAI = 0x6B175474E89094C44Da98b954EedeAC495271d0F;

  uint256 internal constant PERMIT_NFT_ID = 7;

  ERC20PermitMock internal permitToken;
  ERC20PermitMock internal permitToken2;
  ERC721PermitV3Mock internal nftV3;
  ERC721PermitV4Mock internal nftV4;

  struct PermitFuzz {
    uint8 tokenCount;
    uint8 lengthSelector;
    uint256 value;
    uint256 deadlineOffset;
  }

  function setUp() public override {
    super.setUp();

    permitToken = new ERC20PermitMock('Permit Token');
    permitToken2 = new ERC20PermitMock('Permit Token Two');
    permitToken.mint(owner, 1000 ether);
    permitToken2.mint(owner, 1000 ether);

    nftV3 = new ERC721PermitV3Mock();
    nftV4 = new ERC721PermitV4Mock();
    nftV3.mint(owner, PERMIT_NFT_ID);
    nftV4.mint(owner, PERMIT_NFT_ID);
  }

  // -----------------------------------------------------------------------------------------------
  // PF-01..04, PF-09 — the ERC20 rail
  // -----------------------------------------------------------------------------------------------

  /// PF-01 — a six-word payload is read as EIP-2612 and lands as an allowance
  function test_PF_01_eip2612PermitForwarded() public {
    uint256 value = 123 ether;
    uint256 deadline = block.timestamp + 1 hours;

    address[] memory tokens = _one(address(permitToken));
    bytes[] memory blobs = new bytes[](1);
    blobs[0] = _erc2612Blob('Permit Token', address(permitToken), address(hub), value, 0, deadline);

    assertEq(blobs[0].length, 32 * 6, 'six words selects EIP-2612');

    // anyone may relay someone else's permit: the signature inside is the authorisation
    vm.prank(relayer);
    hub.erc20Permit(owner, tokens, blobs);

    assertEq(permitToken.allowance(owner, address(hub)), value, 'allowance');
    assertEq(permitToken.nonces(owner), 1, 'nonce consumed');
  }

  /// PF-02 — a permit the token rejects is swallowed and does not stop the rest of the batch
  function test_PF_02_failingPermitIsSwallowed() public {
    (, uint256 strangerKey) = makeAddrAndKey('stranger');

    uint256 value = 7 ether;
    uint256 deadline = block.timestamp + 1 hours;
    uint256 expired = block.timestamp - 1;

    address[] memory tokens = new address[](3);
    tokens[0] = address(permitToken);
    tokens[1] = address(permitToken2);
    tokens[2] = address(permitToken);

    bytes[] memory blobs = new bytes[](3);
    // well-signed but past its deadline
    blobs[0] = _erc2612Blob('Permit Token', address(permitToken), address(hub), value, 0, expired);
    // valid, and sits behind the first failure
    blobs[1] =
      _erc2612Blob('Permit Token Two', address(permitToken2), address(hub), value, 0, deadline);
    // in date, but signed by somebody who owns nothing
    blobs[2] = _erc2612BlobSignedBy(
      strangerKey, 'Permit Token', address(permitToken), address(hub), value, 0, deadline
    );

    vm.prank(relayer);
    hub.erc20Permit(owner, tokens, blobs);

    assertEq(permitToken.allowance(owner, address(hub)), 0, 'rejected permits change nothing');
    assertEq(permitToken.nonces(owner), 0, 'no nonce burned on failure');
    assertEq(permitToken2.allowance(owner, address(hub)), value, 'the batch carried on');
    assertEq(permitToken2.nonces(owner), 1, 'and consumed only its own nonce');
  }

  /// PF-03 — a seven-word payload is read as a DAI-style permit, against the real DAI
  function test_PF_03_daiStylePermitForwarded() public {
    uint256 nonce = _daiNonce(owner);
    uint256 expiry = block.timestamp + 1 hours;

    bytes32 structHash = keccak256(
      abi.encode(keccak256(bytes(L_DAI_PERMIT)), owner, address(hub), nonce, expiry, true)
    );
    (uint8 v, bytes32 r, bytes32 s) =
      vm.sign(ownerKey, lTypedDataHash(_daiDomainSeparator(), structHash));

    address[] memory tokens = _one(DAI);
    bytes[] memory blobs = new bytes[](1);
    blobs[0] = abi.encode(address(hub), nonce, expiry, true, v, r, s);

    assertEq(blobs[0].length, 32 * 7, 'seven words selects the DAI flavour');

    vm.prank(relayer);
    hub.erc20Permit(owner, tokens, blobs);

    // DAI reads `allowed` as all-or-nothing rather than as an amount
    assertEq(_daiAllowance(owner, address(hub)), type(uint256).max, 'allowance');
    assertEq(_daiNonce(owner), nonce + 1, 'nonce consumed');
  }

  /// PF-04 — every array pair the forwarder guards
  function test_PF_04_mismatchedArrayLengths() public {
    address[] memory twoTokens = new address[](2);
    twoTokens[0] = address(permitToken);
    twoTokens[1] = address(permitToken2);

    vm.expectRevert(ICommon.MismatchedArrayLengths.selector);
    hub.erc20Permit(owner, twoTokens, new bytes[](1));

    // erc721Permit carries two guards, one per companion array
    vm.expectRevert(ICommon.MismatchedArrayLengths.selector);
    hub.erc721Permit(twoTokens, new uint256[](1), new bytes[](2));

    vm.expectRevert(ICommon.MismatchedArrayLengths.selector);
    hub.erc721Permit(twoTokens, new uint256[](2), new bytes[](1));
  }

  /// PF-09 — a length the ERC20 rail does not recognise is skipped in silence
  function test_PF_09_unrecognisedErc20LengthIsSkipped() public {
    uint256 value = 4 ether;
    uint256 deadline = block.timestamp + 1 hours;

    bytes memory valid =
      _erc2612Blob('Permit Token', address(permitToken), address(hub), value, 0, deadline);

    address[] memory tokens = new address[](3);
    tokens[0] = address(permitToken);
    tokens[1] = address(permitToken);
    tokens[2] = address(permitToken);

    bytes[] memory blobs = new bytes[](3);
    blobs[0] = ''; // zero words
    blobs[1] = _truncate(valid, 32 * 5); // five words: the ERC721 v3 width, meaningless here
    blobs[2] = abi.encodePacked(valid, bytes32(0), bytes32(0)); // eight words

    assertEq(blobs[1].length, 32 * 5, 'five words');
    assertEq(blobs[2].length, 32 * 8, 'eight words');

    vm.prank(relayer);
    hub.erc20Permit(owner, tokens, blobs);

    assertEq(permitToken.allowance(owner, address(hub)), 0, 'nothing forwarded');
    assertEq(permitToken.nonces(owner), 0, 'nothing consumed');
  }

  // -----------------------------------------------------------------------------------------------
  // PF-05..07 — the ERC721 rail
  // -----------------------------------------------------------------------------------------------

  /// PF-05 — five words are forwarded as the v3 permit
  function test_PF_05_erc721V3PermitForwarded() public {
    uint256 deadline = block.timestamp + 1 hours;

    bytes32 structHash = keccak256(
      abi.encode(
        keccak256(bytes(L_ERC721_PERMIT)), address(hub), PERMIT_NFT_ID, uint256(0), deadline
      )
    );
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(
      ownerKey, lTypedDataHash(lDomainSeparator('V3 Permit NFT', '1', address(nftV3)), structHash)
    );

    bytes[] memory blobs = new bytes[](1);
    blobs[0] = abi.encode(address(hub), deadline, v, r, s);

    assertEq(blobs[0].length, 32 * 5, 'five words selects v3');

    vm.prank(relayer);
    hub.erc721Permit(_one(address(nftV3)), _oneId(PERMIT_NFT_ID), blobs);

    assertEq(nftV3.getApproved(PERMIT_NFT_ID), address(hub), 'approval');
    assertEq(nftV3.nonces(PERMIT_NFT_ID), 1, 'nonce consumed');
  }

  /// PF-06 — eight words are forwarded as the v4 permit, and succeed
  function test_PF_06_erc721V4PermitForwarded() public {
    uint256 deadline = block.timestamp + 1 hours;
    uint256 nonce = 99;

    bytes[] memory blobs = new bytes[](1);
    blobs[0] = _erc721V4Blob(address(hub), deadline, nonce);

    assertEq(blobs[0].length, 32 * 8, 'a 65-byte signature makes the payload eight words');

    vm.prank(relayer);
    hub.erc721Permit(_one(address(nftV4)), _oneId(PERMIT_NFT_ID), blobs);

    assertEq(nftV4.getApproved(PERMIT_NFT_ID), address(hub), 'approval');
    assertTrue(nftV4.nonceUsed(owner, nonce), 'nonce consumed');
  }

  /// PF-07 — the v4 payload is decoded outside the try/catch, so a malformed one is not swallowed
  function test_PF_07_malformedV4PayloadReverts() public {
    uint256 deadline = block.timestamp + 1 hours;
    bytes memory blob = _erc721V4Blob(address(hub), deadline, 1);

    // word 3 is the offset of the trailing `bytes`; push it past the end of the payload
    assembly ('memory-safe') {
      mstore(add(blob, 0x80), 0xffffffff)
    }

    bytes[] memory blobs = new bytes[](1);
    blobs[0] = blob;

    vm.prank(relayer);
    vm.expectRevert(CalldataDecoder.SliceOutOfBounds.selector);
    hub.erc721Permit(_one(address(nftV4)), _oneId(PERMIT_NFT_ID), blobs);

    assertEq(nftV4.getApproved(PERMIT_NFT_ID), address(0), 'nothing approved');
  }

  // -----------------------------------------------------------------------------------------------
  // PF-08 — the Permit2 rail
  // -----------------------------------------------------------------------------------------------

  /// PF-08a — a good batch signature reaches Permit2 and sets the allowance
  function test_PF_08a_permit2PermitForwarded() public {
    uint160 amount = 42 ether;
    uint48 expiration = uint48(block.timestamp + 1 days);
    uint256 sigDeadline = block.timestamp + 1 hours;

    IAllowanceTransfer.PermitBatch memory batch =
      _permit2Batch(WETH, amount, expiration, 0, address(hub), sigDeadline);
    bytes memory signature = _sign(ownerKey, _permit2BatchDigest(batch));

    vm.prank(relayer);
    hub.permit2Permit(owner, batch, signature);

    (uint160 allowed, uint48 storedExpiration, uint48 storedNonce) =
      IAllowanceTransfer(PERMIT2).allowance(owner, WETH, address(hub));

    assertEq(allowed, amount, 'allowance');
    assertEq(storedExpiration, expiration, 'expiration');
    assertEq(storedNonce, 1, 'nonce bumped');
  }

  /// PF-08b — a signature Permit2 rejects is swallowed, exactly as the token permits are
  function test_PF_08b_permit2PermitFailureIsSwallowed() public {
    (, uint256 strangerKey) = makeAddrAndKey('stranger');

    uint160 amount = 42 ether;
    uint48 expiration = uint48(block.timestamp + 1 days);
    uint256 sigDeadline = block.timestamp + 1 hours;

    IAllowanceTransfer.PermitBatch memory batch =
      _permit2Batch(WETH, amount, expiration, 0, address(hub), sigDeadline);
    bytes memory signature = _sign(strangerKey, _permit2BatchDigest(batch));

    vm.prank(relayer);
    hub.permit2Permit(owner, batch, signature);

    (uint160 allowed, uint48 storedExpiration, uint48 storedNonce) =
      IAllowanceTransfer(PERMIT2).allowance(owner, WETH, address(hub));

    assertEq(allowed, 0, 'no allowance');
    assertEq(storedExpiration, 0, 'no expiration');
    assertEq(storedNonce, 0, 'no nonce burned');
  }

  // -----------------------------------------------------------------------------------------------
  // PF-FUZZ
  // -----------------------------------------------------------------------------------------------

  /**
   * PF-FUZZ — across the four payload widths the forwarder knows about, only six words reaches an
   * EIP-2612 token, and repeats of a consumed permit never revert the call.
   */
  function testFuzz_PF_FUZZ_lengthDispatch(PermitFuzz memory f) public {
    uint256 tokenCount = bound(f.tokenCount, 0, 3);
    uint256 selector = bound(f.lengthSelector, 0, 3); // 0 -> 5 words .. 3 -> 8 words
    uint256 deadline = block.timestamp + bound(f.deadlineOffset, 0, 30 days);

    (uint8 v, bytes32 r, bytes32 s) = vm.sign(
      ownerKey,
      _erc2612Digest(
        'Permit Token', address(permitToken), owner, address(hub), f.value, 0, deadline
      )
    );

    address[] memory tokens = new address[](tokenCount);
    bytes[] memory blobs = new bytes[](tokenCount);

    for (uint256 i = 0; i < tokenCount; i++) {
      tokens[i] = address(permitToken);

      if (selector == 0) {
        blobs[i] = abi.encodePacked(
          bytes32(uint256(uint160(address(hub)))),
          bytes32(f.value),
          bytes32(deadline),
          bytes32(uint256(v)),
          r
        );
      } else if (selector == 1) {
        blobs[i] = abi.encode(address(hub), f.value, deadline, v, r, s);
      } else if (selector == 2) {
        // the DAI shape, aimed at a token that has no DAI permit
        blobs[i] = abi.encode(address(hub), uint256(0), deadline, true, v, r, s);
      } else {
        blobs[i] = abi.encode(address(hub), f.value, deadline, uint256(0), v, r, s, bytes32(0));
      }

      assertEq(blobs[i].length, 32 * (selector + 5), 'payload width');
    }

    vm.prank(relayer);
    hub.erc20Permit(owner, tokens, blobs);

    bool lands = tokenCount > 0 && selector == 1;

    assertEq(permitToken.allowance(owner, address(hub)), lands ? f.value : 0, 'allowance');
    assertEq(permitToken.nonces(owner), lands ? 1 : 0, 'at most one nonce consumed');
  }

  // -----------------------------------------------------------------------------------------------
  // Helpers
  // -----------------------------------------------------------------------------------------------

  function _erc2612Digest(
    string memory name,
    address token,
    address tokenOwner,
    address spender,
    uint256 value,
    uint256 nonce,
    uint256 deadline
  ) internal view returns (bytes32) {
    bytes32 structHash = keccak256(
      abi.encode(keccak256(bytes(L_EIP2612_PERMIT)), tokenOwner, spender, value, nonce, deadline)
    );
    // OpenZeppelin's ERC20Permit names its domain after the token and versions it '1'
    return lTypedDataHash(lDomainSeparator(name, '1', token), structHash);
  }

  function _erc2612Blob(
    string memory name,
    address token,
    address spender,
    uint256 value,
    uint256 nonce,
    uint256 deadline
  ) internal returns (bytes memory) {
    return _erc2612BlobSignedBy(ownerKey, name, token, spender, value, nonce, deadline);
  }

  function _erc2612BlobSignedBy(
    uint256 signerKey,
    string memory name,
    address token,
    address spender,
    uint256 value,
    uint256 nonce,
    uint256 deadline
  ) internal returns (bytes memory) {
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(
      signerKey, _erc2612Digest(name, token, owner, spender, value, nonce, deadline)
    );
    return abi.encode(spender, value, deadline, v, r, s);
  }

  function _erc721V4Blob(address spender, uint256 deadline, uint256 nonce)
    internal
    returns (bytes memory)
  {
    bytes32 structHash = keccak256(
      abi.encode(keccak256(bytes(L_ERC721_PERMIT)), spender, PERMIT_NFT_ID, nonce, deadline)
    );
    bytes memory signature = _sign(
      ownerKey, lTypedDataHash(lDomainSeparator('V4 Permit NFT', '1', address(nftV4)), structHash)
    );
    return abi.encode(spender, deadline, nonce, signature);
  }

  /// @dev Permit2's allowance-rail batch digest, rebuilt from the literals above
  function _permit2BatchDigest(IAllowanceTransfer.PermitBatch memory batch)
    internal
    view
    returns (bytes32)
  {
    bytes32[] memory detailHashes = new bytes32[](batch.details.length);
    for (uint256 i = 0; i < batch.details.length; i++) {
      detailHashes[i] = keccak256(
        abi.encode(
          keccak256(bytes(L_PERMIT2_DETAILS)),
          batch.details[i].token,
          batch.details[i].amount,
          batch.details[i].expiration,
          batch.details[i].nonce
        )
      );
    }

    bytes32 structHash = keccak256(
      abi.encode(
        keccak256(abi.encodePacked(L_PERMIT2_BATCH_STUB, L_PERMIT2_DETAILS)),
        keccak256(abi.encodePacked(detailHashes)),
        batch.spender,
        batch.sigDeadline
      )
    );

    return lTypedDataHash(_permit2DomainSeparator(), structHash);
  }

  function _permit2Batch(
    address token,
    uint160 amount,
    uint48 expiration,
    uint48 nonce,
    address spender,
    uint256 sigDeadline
  ) internal pure returns (IAllowanceTransfer.PermitBatch memory batch) {
    IAllowanceTransfer.PermitDetails[] memory details = new IAllowanceTransfer.PermitDetails[](1);
    details[0] = IAllowanceTransfer.PermitDetails({
      token: token, amount: amount, expiration: expiration, nonce: nonce
    });
    batch = IAllowanceTransfer.PermitBatch({
      details: details, spender: spender, sigDeadline: sigDeadline
    });
  }

  function _daiDomainSeparator() internal view returns (bytes32) {
    (bool ok, bytes memory data) = DAI.staticcall(abi.encodeWithSignature('DOMAIN_SEPARATOR()'));
    require(ok, 'dai domain');
    return abi.decode(data, (bytes32));
  }

  function _daiNonce(address holder) internal view returns (uint256) {
    (bool ok, bytes memory data) =
      DAI.staticcall(abi.encodeWithSignature('nonces(address)', holder));
    require(ok, 'dai nonce');
    return abi.decode(data, (uint256));
  }

  function _daiAllowance(address holder, address spender) internal view returns (uint256) {
    (bool ok, bytes memory data) =
      DAI.staticcall(abi.encodeWithSignature('allowance(address,address)', holder, spender));
    require(ok, 'dai allowance');
    return abi.decode(data, (uint256));
  }

  function _truncate(bytes memory input, uint256 length) internal pure returns (bytes memory out) {
    out = new bytes(length);
    for (uint256 i = 0; i < length; i++) {
      out[i] = input[i];
    }
  }

  function _one(address a) internal pure returns (address[] memory out) {
    out = new address[](1);
    out[0] = a;
  }

  function _oneId(uint256 id) internal pure returns (uint256[] memory out) {
    out = new uint256[](1);
    out[0] = id;
  }

  // -------------------------------------------------------------------------------------------
  // PF-FUZZ-721 / PF-FUZZ-P2 — the two forwarders the fixed cases left unfuzzed
  // -------------------------------------------------------------------------------------------

  struct Permit721Fuzz {
    uint8 lengthSelector;
    uint256 deadlineOffset;
    uint256 nonce;
    bool mismatchLengths;
  }

  /**
   * @dev Drives `erc721Permit` across its length dispatch and its two `checkLengths` guards.
   * A recognised length must forward and approve; an unrecognised one must be a silent no-op;
   * a mismatched array must revert before any token is touched.
   */
  function testFuzz_PF_FUZZ_721_dispatch(Permit721Fuzz memory f) public {
    uint256 selector = bound(f.lengthSelector, 0, 3);
    uint256 deadline = block.timestamp + bound(f.deadlineOffset, 1, 30 days);

    // The dispatch has only two arms: exactly five words is v3, EVERYTHING else is v4. A v4 blob
    // that is too short to hold its signature reverts inside the decoder, outside the try/catch.
    bytes[] memory blobs = new bytes[](1);
    bool forwards;
    bool decoderReverts;

    if (selector == 0) {
      blobs[0] = _erc721V4Blob(address(hub), deadline, f.nonce); // 8 words -> v4, forwards
      forwards = true;
    } else if (selector == 1) {
      blobs[0] = abi.encode(address(hub), deadline, uint256(0), uint256(0), uint256(0)); // 5 -> v3
    } else if (selector == 2) {
      blobs[0] = abi.encode(address(hub), deadline); // 2 words -> v4 arm, decode out of bounds
      decoderReverts = true;
    } else {
      blobs[0] = ''; // empty -> v4 arm, decode out of bounds
      decoderReverts = true;
    }

    if (f.mismatchLengths) {
      vm.prank(relayer);
      vm.expectRevert(ICommon.MismatchedArrayLengths.selector);
      hub.erc721Permit(_one(address(nftV4)), new uint256[](2), blobs);
      return;
    }

    address beforeApproval = nftV4.getApproved(PERMIT_NFT_ID);

    if (decoderReverts) {
      vm.prank(relayer);
      vm.expectRevert(CalldataDecoder.SliceOutOfBounds.selector);
      hub.erc721Permit(_one(address(nftV4)), _oneId(PERMIT_NFT_ID), blobs);
      return;
    }

    vm.prank(relayer);
    hub.erc721Permit(_one(address(nftV4)), _oneId(PERMIT_NFT_ID), blobs);

    if (forwards) {
      assertEq(nftV4.getApproved(PERMIT_NFT_ID), address(hub), 'v4 payload approves');
      assertTrue(nftV4.nonceUsed(owner, f.nonce), 'v4 nonce consumed');
    } else {
      // a v3-shaped blob aimed at a v4 token fails inside the try/catch and is swallowed
      assertEq(nftV4.getApproved(PERMIT_NFT_ID), beforeApproval, 'no approval granted');
    }
  }

  struct Permit2Fuzz {
    uint160 amount;
    uint48 expiration;
    bool validSignature;
  }

  /// @dev `permit2Permit` swallows every failure, so the allowance itself is the only oracle
  function testFuzz_PF_FUZZ_P2_allowance(Permit2Fuzz memory f) public {
    f.amount = uint160(bound(f.amount, 0, type(uint160).max));
    uint48 expiration = uint48(bound(f.expiration, block.timestamp + 1, type(uint48).max));
    uint48 nonce = 0; // Permit2 requires the current nonce, so this is fixed rather than fuzzed

    IAllowanceTransfer.PermitBatch memory batch =
      _permit2Batch(WETH, f.amount, expiration, nonce, address(hub), block.timestamp + 1 hours);

    bytes memory signature = f.validSignature
      ? _sign(ownerKey, _permit2BatchDigest(batch))
      : _sign(ownerKey, keccak256('a digest Permit2 never asked for'));

    vm.prank(relayer);
    hub.permit2Permit(owner, batch, signature);

    (uint160 allowed,,) = IAllowanceTransfer(PERMIT2).allowance(owner, WETH, address(hub));
    assertEq(allowed, f.validSignature ? f.amount : 0, 'allowance set only on a valid signature');
  }
}
