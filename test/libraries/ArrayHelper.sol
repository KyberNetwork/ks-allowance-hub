// SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity ^0.8.0;

/// @notice Library of helper functions to convert fixed-sized array types to dynamic arrays in tests.
library ArrayHelper {
  function toMemoryArray(address[1] memory array) internal pure returns (address[] memory) {
    address[] memory ret = new address[](1);
    ret[0] = array[0];
    return ret;
  }

  function toMemoryArray(address[2] memory array) internal pure returns (address[] memory) {
    address[] memory ret = new address[](2);
    ret[0] = array[0];
    ret[1] = array[1];
    return ret;
  }

  function toMemoryArray(address[3] memory array) internal pure returns (address[] memory) {
    address[] memory ret = new address[](3);
    ret[0] = array[0];
    ret[1] = array[1];
    ret[2] = array[2];
    return ret;
  }

  function toMemoryArray(address payable[1] memory array) internal pure returns (address[] memory) {
    address[] memory ret = new address[](1);
    ret[0] = array[0];
    return ret;
  }

  function toMemoryArray(address payable[2] memory array) internal pure returns (address[] memory) {
    address[] memory ret = new address[](2);
    ret[0] = array[0];
    ret[1] = array[1];
    return ret;
  }

  function toMemoryArray(address payable[3] memory array) internal pure returns (address[] memory) {
    address[] memory ret = new address[](3);
    ret[0] = array[0];
    ret[1] = array[1];
    ret[2] = array[2];
    return ret;
  }

  function toMemoryArray(uint256[1] memory array) internal pure returns (uint256[] memory) {
    uint256[] memory ret = new uint256[](1);
    ret[0] = array[0];
    return ret;
  }

  function toMemoryArray(uint256[2] memory array) internal pure returns (uint256[] memory) {
    uint256[] memory ret = new uint256[](2);
    ret[0] = array[0];
    ret[1] = array[1];
    return ret;
  }

  function toMemoryArray(int256[2] memory array) internal pure returns (int256[] memory) {
    int256[] memory ret = new int256[](2);
    ret[0] = array[0];
    ret[1] = array[1];
    return ret;
  }

  function toMemoryArray(uint256[3] memory array) internal pure returns (uint256[] memory) {
    uint256[] memory ret = new uint256[](3);
    ret[0] = array[0];
    ret[1] = array[1];
    ret[2] = array[2];
    return ret;
  }

  function toMemoryArray(bytes4[1] memory array) internal pure returns (bytes4[] memory) {
    bytes4[] memory ret = new bytes4[](1);
    ret[0] = array[0];
    return ret;
  }

  function toMemoryArray(bytes4[2] memory array) internal pure returns (bytes4[] memory) {
    bytes4[] memory ret = new bytes4[](2);
    ret[0] = array[0];
    ret[1] = array[1];
    return ret;
  }

  function toMemoryArray(bytes4[3] memory array) internal pure returns (bytes4[] memory) {
    bytes4[] memory ret = new bytes4[](3);
    ret[0] = array[0];
    ret[1] = array[1];
    ret[2] = array[2];
    return ret;
  }

  function toMemoryArray(uint8[1] memory array) internal pure returns (uint8[] memory) {
    uint8[] memory ret = new uint8[](1);
    ret[0] = array[0];
    return ret;
  }

  function toMemoryArray(uint8[2] memory array) internal pure returns (uint8[] memory) {
    uint8[] memory ret = new uint8[](2);
    ret[0] = array[0];
    ret[1] = array[1];
    return ret;
  }

  function toMemoryArray(uint8[3] memory array) internal pure returns (uint8[] memory) {
    uint8[] memory ret = new uint8[](3);
    ret[0] = array[0];
    ret[1] = array[1];
    ret[2] = array[2];
    return ret;
  }

  function toMemoryArray(bool[1] memory array) internal pure returns (bool[] memory) {
    bool[] memory ret = new bool[](1);
    ret[0] = array[0];
    return ret;
  }

  function toMemoryArray(bool[2] memory array) internal pure returns (bool[] memory) {
    bool[] memory ret = new bool[](2);
    ret[0] = array[0];
    ret[1] = array[1];
    return ret;
  }

  function toMemoryArray(bool[3] memory array) internal pure returns (bool[] memory) {
    bool[] memory ret = new bool[](3);
    ret[0] = array[0];
    ret[1] = array[1];
    ret[2] = array[2];
    return ret;
  }
}
