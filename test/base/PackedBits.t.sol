// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Test} from 'forge-std/Test.sol';

import {PackedBits} from 'src/base/types/PackedBits.sol';

/**
 * @title PackedBitsTest
 * @notice PB-01..02 — the one-word bitfield that carries `allowFailure` and `authFlags`.
 * @dev The oracle is arithmetic written out here, not a second copy of the shift: a position is
 * read by dividing the word down and taking the remainder, which is the same value by a different
 * route. The words under test are held in storage so the optimiser cannot fold the call away and
 * answer from the source text instead of from the compiled library.
 */
contract PackedBitsTest is Test {
  bytes32 internal allSetWord;
  bytes32 internal noneSetWord;
  bytes32 internal allButZeroWord;

  function setUp() public {
    allSetWord = bytes32(type(uint256).max);
    noneSetWord = bytes32(0);
    allButZeroWord = bytes32(~uint256(1));
  }

  // -----------------------------------------------------------------------------------------------
  // PB-01 — which positions exist
  // -----------------------------------------------------------------------------------------------

  /**
   * PB-01 — every position below 256 exists, and nothing at or above it does
   * @dev The shift is unmasked, so the EVM's own `SHR` is what answers for an out-of-range index:
   * it yields zero for any shift of 256 or more. A caller that walks a batch longer than 256
   * entries therefore sees `false` from entry 256 onwards rather than wrapping back to bit 0 —
   * which is the safe direction, since a cleared failure bit bubbles the revert.
   */
  function test_PB_01_positionsThatExistAndPositionsThatDoNot() public view {
    PackedBits allSet = PackedBits.wrap(allSetWord);

    assertTrue(allSet.pos(0), 'bit 0');
    assertTrue(allSet.pos(1), 'bit 1');
    assertTrue(allSet.pos(255), 'bit 255, the last one there is');

    assertFalse(allSet.pos(256), 'bit 256 does not exist');
    assertFalse(allSet.pos(257), 'nor 257');
    assertFalse(allSet.pos(type(uint256).max), 'nor the largest index expressible');

    // the same positions on an empty word, so the answers above are about the word and not
    // about the positions
    PackedBits noneSet = PackedBits.wrap(noneSetWord);
    assertFalse(noneSet.pos(0), 'bit 0 of an empty word');
    assertFalse(noneSet.pos(255), 'and bit 255 of it');
  }

  /**
   * PB-01b — the whole domain, against the same value reached by division
   * @dev `word / 2**i % 2` is the definition a shift implements, computed without shifting, so a
   * broken mask or a wrong shift direction cannot agree with it. Indices of 256 and above have no
   * divisor inside a word, which is exactly why they must read as false.
   */
  function testFuzz_PB_01b_everyPositionAgreesWithTheWord(bytes32 word, uint256 index) public pure {
    bool expected;
    if (index < 256) {
      expected = (uint256(word) / (2 ** index)) % 2 == 1;
    }

    assertEq(PackedBits.wrap(word).pos(index), expected, 'position matches the word');
  }

  // -----------------------------------------------------------------------------------------------
  // PB-02 — what kind of bool comes back
  // -----------------------------------------------------------------------------------------------

  /**
   * PB-02 — the result is a canonical bool, not merely a truthy word
   * @dev `pos` is `internal`, so it is inlined and nothing between the library and the caller
   * cleans the value: the `and(..., 0x1)` is the only thing that does. Both halves matter. The
   * first fails outright if the mask is dropped — a `bool` carrying `~1` is truthy, and
   * `assertFalse` rejects it. The second reads the raw stack slot, which is what a caller storing
   * the answer into a `bool` field or comparing it against another `bool` would actually keep.
   */
  function test_PB_02_resultIsACanonicalBool() public view {
    // every bit set except bit 0: an unmasked shift would hand back a very loud non-zero word
    PackedBits allButZero = PackedBits.wrap(allButZeroWord);
    assertFalse(allButZero.pos(0), 'bit 0 is clear however loud its neighbours are');
    assertTrue(allButZero.pos(1), 'and those neighbours really are set');

    bool set = PackedBits.wrap(allSetWord).pos(1);
    uint256 rawSet;
    assembly ('memory-safe') {
      rawSet := set
    }
    assertEq(rawSet, 1, 'a set bit is exactly 1, with no high bits riding along');

    bool clear = PackedBits.wrap(noneSetWord).pos(1);
    uint256 rawClear;
    assembly ('memory-safe') {
      rawClear := clear
    }
    assertEq(rawClear, 0, 'and a clear bit is exactly 0');
  }
}
