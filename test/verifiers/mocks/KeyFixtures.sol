// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Vm} from 'forge-std/Vm.sol';

/// @title KeyFixtures
/**
 * @notice Session-key material for the P256, WebAuthn and RSA branches of `SessionKeyLibrary`.
 * @dev Every vector here is produced without reading the contract under test. P256 points and
 * signatures come from Foundry's own secp256r1 cheatcodes; the WebAuthn assertion is assembled
 * byte by byte from the W3C layout, with a base64url encoder written out below rather than
 * borrowed; the RSA signature is raised from a checked-in 2048-bit private key with the modexp
 * precompile and a hand-written PKCS#1 v1.5 padding. A fixture that reused the verifier's own
 * decoding would agree with a broken decoder exactly as happily as with a correct one — which is
 * how the `decodeBytes32` word-index bug survived until now.
 */
library KeyFixtures {
  Vm private constant VM = Vm(address(uint160(uint256(keccak256('hevm cheat code')))));

  // -----------------------------------------------------------------------------------------
  // secp256r1 (P256)
  // -----------------------------------------------------------------------------------------

  /// @dev Order of the secp256r1 base point, transcribed from SEC 2 v2 / NIST FIPS 186-4
  uint256 internal constant P256_N =
    0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;

  /// @dev The malleability boundary: a signature is canonical only while `s` stays at or below it
  uint256 internal constant P256_HALF_N = P256_N >> 1;

  /// @dev Arbitrary scalar in [1, N-1]; the matching point is derived, never written out
  uint256 internal constant P256_PRIVATE_KEY =
    0x6c4b9a1f3d8e27b5a0c1d2e3f4051627384950a1b2c3d4e5f60718293a4b5c6d;

  /// @dev `abi.encodePacked(qx, qy)`, the layout {SessionKey} documents for P256 and WebAuthn
  function p256PublicKey() internal view returns (bytes memory) {
    (uint256 qx, uint256 qy) = VM.publicKeyP256(P256_PRIVATE_KEY);
    return abi.encodePacked(bytes32(qx), bytes32(qy));
  }

  /// @dev `abi.encodePacked(r, s)` with `s` normalised into the lower half of the order
  function p256Sign(bytes32 digest) internal view returns (bytes memory) {
    (bytes32 r, bytes32 s) = _signP256Low(digest);
    return abi.encodePacked(r, s);
  }

  /// @dev The same signature with `s` replaced by `N - s`: the twin P256 verification rejects
  function flipS(bytes memory signature) internal pure returns (bytes memory) {
    bytes32 r;
    bytes32 s;
    assembly ('memory-safe') {
      r := mload(add(signature, 0x20))
      s := mload(add(signature, 0x40))
    }
    return abi.encodePacked(r, bytes32(P256_N - uint256(s)));
  }

  /// @dev Reads the `s` half of an `abi.encodePacked(r, s)` signature, so a test can state its side
  function sOf(bytes memory signature) internal pure returns (uint256 s) {
    assembly ('memory-safe') {
      s := mload(add(signature, 0x40))
    }
  }

  // -----------------------------------------------------------------------------------------
  // WebAuthn
  // -----------------------------------------------------------------------------------------

  /// @dev Offsets of `"type"` and `"challenge"` inside the client data built below, counted out
  uint256 internal constant WEBAUTHN_TYPE_INDEX = 1;
  uint256 internal constant WEBAUTHN_CHALLENGE_INDEX = 23;

  /// @dev Authenticator data flags: bit 0 User Present, bit 2 User Verified
  bytes1 private constant FLAG_USER_PRESENT = 0x01;
  bytes1 private constant FLAG_USER_VERIFIED = 0x04;

  /**
   * @notice A WebAuthn `get` assertion over `challenge`, encoded as the flat six-member tuple
   * `WebAuthn.tryDecodeAuth` expects — not `abi.encode(struct)`, which would prepend an offset
   * @param userVerified whether the UV flag is set; clearing it is the only difference in the
   * negative case, so the rejection cannot be blamed on anything else
   */
  function webAuthnAssertion(bytes32 challenge, bool userVerified)
    internal
    view
    returns (bytes memory)
  {
    bytes1 flags = userVerified ? FLAG_USER_PRESENT | FLAG_USER_VERIFIED : FLAG_USER_PRESENT;

    // 32-byte rpIdHash, one flags byte, four-byte signature counter: the 37-byte minimum
    bytes memory authenticatorData =
      abi.encodePacked(keccak256('kyberswap.test'), flags, bytes4(uint32(1)));

    string memory clientDataJSON = string.concat(
      '{"type":"webauthn.get","challenge":"',
      base64Url(abi.encodePacked(challenge)),
      '","origin":"https://kyberswap.test"}'
    );

    bytes32 messageHash = sha256(abi.encodePacked(authenticatorData, sha256(bytes(clientDataJSON))));
    (bytes32 r, bytes32 s) = _signP256Low(messageHash);

    return abi.encode(
      r, s, WEBAUTHN_CHALLENGE_INDEX, WEBAUTHN_TYPE_INDEX, authenticatorData, clientDataJSON
    );
  }

  /**
   * @notice RFC 4648 §5 base64url, unpadded
   * @dev Written out rather than imported: the verification path base64-encodes the challenge
   * itself, so a shared encoder would make the comparison self-referential.
   */
  function base64Url(bytes memory data) internal pure returns (string memory) {
    bytes memory alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

    bytes memory out = new bytes((data.length * 8 + 5) / 6);
    uint256 buffer;
    uint256 bits;
    uint256 written;

    for (uint256 i = 0; i < data.length; i++) {
      buffer = (buffer << 8) | uint8(data[i]);
      bits += 8;
      while (bits >= 6) {
        bits -= 6;
        out[written++] = alphabet[(buffer >> bits) & 0x3f];
      }
    }
    if (bits > 0) {
      out[written++] = alphabet[(buffer << (6 - bits)) & 0x3f];
    }

    return string(out);
  }

  // -----------------------------------------------------------------------------------------
  // RSA
  // -----------------------------------------------------------------------------------------

  /// @dev 65537, the exponent OpenSSL and NIST both default to
  bytes internal constant RSA_EXPONENT = hex'010001';

  /// @dev 2048-bit modulus of a throwaway key generated outside this repository
  bytes internal constant RSA_MODULUS = hex'd028eb86b4b08356c3de936eb68bdd8101537ce4db5a581ee76acaeaa35497d8'
    hex'35323bb748a56d6b520d9b7831c57fd51721497b537a8746d75216b2d4160347'
    hex'05ff6a6af28d61363538dc4a57726e4efd8bcf1bf3c4bf9440fb897b7c7820b1'
    hex'fe5eea26e187241cd0bb6f25ffaead7896e582648ac7e73eb9aa3e096b01f389'
    hex'018ccb3295474ba7a7898d255139807a826da6e90e10619bf2f1e498196129bd'
    hex'e895951e21611c6c6470340b2086be7debae831f0f81f6c5fe2c657793bae30d'
    hex'0879c2eab94b2c33e4c2496c991f74bf157b9d44a8d67750779a7d3e6bc8037a'
    hex'b8b5b9f604acd052e16da111644516a0c815bde12c7ad086518a5be0413577fb';

  /// @dev Matching private exponent; only this file ever sees it
  bytes internal constant RSA_PRIVATE_EXPONENT = hex'5e5915bbc61d354277dfe3d22c1243f10b71546c049233dbba0758f6b5d60b46'
    hex'f7818fb878c8664a5cf406f219190be2412c18bab9b1112c863ed243f6c60d71'
    hex'3d2232114c63d15a79100f24f0f2d055a42d20cfea12d4c4b5196d8c9773795a'
    hex'43d1b06eb40d054cbc3d20594844dba28b3e7675ecc343a8560df8355b979452'
    hex'44e771f6e716c9e9171e61d59903763af6257b91baf19db7839199fc8804812e'
    hex'68225e342f7118f786a053d0c043fe59eec816f7a9c6402f6cf78d963438454a'
    hex'49e37f5fd2bd597c6ab57e60c6b9df001ed4168d2f5900e998d3d0d4b8ac7614'
    hex'f4ab50516a367f97a354dc93610293489b529400a25903b0ea38ad6ad83ee6c5';

  uint256 internal constant RSA_MODULUS_BYTES = 0x100;

  /// @dev `abi.encode(bytes e, bytes n)`, the layout {SessionKey} documents for RSA
  function rsaPublicKey() internal pure returns (bytes memory) {
    return abi.encode(RSA_EXPONENT, RSA_MODULUS);
  }

  /// @dev The same key with the modulus one byte under the 2048-bit floor RSA verification enforces
  function rsaPublicKeyWithShortModulus() internal pure returns (bytes memory) {
    return abi.encode(RSA_EXPONENT, truncate(RSA_MODULUS, RSA_MODULUS_BYTES - 1));
  }

  /**
   * @dev The one digest the checked-in RSA signature covers.
   * Signing on-chain would need a modexp with the 2048-bit private exponent, which is far too
   * expensive to run inside a test, so the vector below was produced outside the repository and
   * verified against the modulus. Verification itself uses the public exponent and stays cheap,
   * which is what the contract under test actually does.
   */
  bytes32 internal constant RSA_FIXED_DIGEST =
    0xa1b2c3d4e5f60718293a4b5c6d7e8f9011223344556677889900112233445566;

  /// @dev `RSASP1(EMSA-PKCS1-v1_5(RSA_FIXED_DIGEST))`, i.e. `em^d mod n`
  function rsaSignatureForFixedDigest() internal pure returns (bytes memory) {
    return abi.encodePacked(
      hex'98c96666c684a4d1603b84a178e5c1dfdbad96d901013aa806ed30e0ac831ab4',
      hex'f3b3168a6d59a6c5414a3c06af5e748a1c06914a40b10d75d41d6eaa5f16c591',
      hex'be7bf48eaa61ac0f9defcbe4055b1b6198391c791bf51959ff7c232d3a36ff69',
      hex'0478b37fe43e2f08ea5fc5b42b4af280e2a21febb1dd9ece5388d55cd898b18e',
      hex'61d01896c9e3d3b685c88fc710401501a7ddd9daa18b40e7ddf1d4e909dd9183',
      hex'2fc1d10f961a4dd643ddd5b47479265e6f3887367920809ff6c864d4fa83c2d3',
      hex'f2c788f1be87cbe9e282d9eab5919cd0d172127621fbced2096a388bb19f41a4',
      hex'6557cf05f0856f91bb30c20b7a5417bfaf69a3c6b103a2bee3528f9b59c229ba'
    );
  }

  // -----------------------------------------------------------------------------------------
  // Shared helpers
  // -----------------------------------------------------------------------------------------

  function truncate(bytes memory data, uint256 length) internal pure returns (bytes memory out) {
    out = new bytes(length);
    for (uint256 i = 0; i < length; i++) {
      out[i] = data[i];
    }
  }

  /// @dev Foundry does not promise a canonical `s`, so normalise before handing a vector out
  function _signP256Low(bytes32 digest) private view returns (bytes32 r, bytes32 s) {
    (r, s) = VM.signP256(P256_PRIVATE_KEY, digest);
    if (uint256(s) > P256_HALF_N) {
      s = bytes32(P256_N - uint256(s));
    }
  }

  /// @dev `0x00 || 0x01 || 0xFF.. || 0x00 || DigestInfo(SHA-256) || H`, per RFC 8017 §9.2
  /// Kept because it documents exactly what the checked-in vector was computed over.
  function _pkcs1v15Sha256(bytes32 digest) private pure returns (bytes memory) {
    // SEQUENCE(SEQUENCE(OID sha256, NULL), OCTET STRING) with explicit NULL parameters
    bytes memory digestInfo = abi.encodePacked(hex'3031300d060960864801650304020105000420', digest);

    bytes memory padding = new bytes(RSA_MODULUS_BYTES - 3 - digestInfo.length);
    for (uint256 i = 0; i < padding.length; i++) {
      padding[i] = 0xff;
    }

    return abi.encodePacked(hex'0001', padding, hex'00', digestInfo);
  }

  function _modExp(bytes memory base, bytes memory exponent, bytes memory modulus)
    private
    view
    returns (bytes memory)
  {
    (bool ok, bytes memory output) = address(0x05)
      .staticcall(
        abi.encodePacked(base.length, exponent.length, modulus.length, base, exponent, modulus)
      );
    require(ok, 'modexp precompile');
    return output;
  }
}
