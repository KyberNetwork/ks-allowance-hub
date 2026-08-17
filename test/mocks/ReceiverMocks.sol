// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IMsgSenderHub} from './IMsgSenderHub.sol';

import {IERC721Receiver} from 'openzeppelin-contracts/contracts/token/ERC721/IERC721Receiver.sol';

/**
 * @notice ERC721 recipient that reenters the hub from `onERC721Received`
 * @dev `ERC721Params.permitTransfer` hands control to the target mid-flow, strictly earlier than
 * the generic calls, so this is the earliest reentry point the hub exposes.
 */
contract ReentrantERC721ReceiverMock is IERC721Receiver {
  IMsgSenderHub public immutable HUB;

  bytes public reentrantCalldata;

  /// @notice Whether the reentrant call reverted, and the raw revert data it produced
  bool public reentrantCallReverted;
  bytes public reentrantRevertData;
  bool public observedCallback;

  constructor(address hub) {
    HUB = IMsgSenderHub(hub);
  }

  function setReentrantCalldata(bytes calldata data) external {
    reentrantCalldata = data;
  }

  /// @inheritdoc IERC721Receiver
  function onERC721Received(address, address, uint256, bytes calldata) external returns (bytes4) {
    observedCallback = true;

    if (reentrantCalldata.length != 0) {
      (bool ok, bytes memory ret) = address(HUB).call(reentrantCalldata);
      reentrantCallReverted = !ok;
      reentrantRevertData = ret;
    }

    return IERC721Receiver.onERC721Received.selector;
  }
}

/// @notice Plain ERC721 recipient that accepts tokens without reentering
contract ERC721ReceiverMock is IERC721Receiver {
  /// @inheritdoc IERC721Receiver
  function onERC721Received(address, address, uint256, bytes calldata)
    external
    pure
    returns (bytes4)
  {
    return IERC721Receiver.onERC721Received.selector;
  }
}

/// @notice Address that rejects native transfers, driving `TokenHelper.NativeTransferFailed`
contract NativeRejectorMock {
  /// @notice Thrown whenever this contract is sent value
  error NativeRejected();

  receive() external payable {
    revert NativeRejected();
  }
}
