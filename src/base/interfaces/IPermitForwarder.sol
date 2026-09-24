// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IAllowanceTransfer} from 'ks-common-sc/src/interfaces/IAllowanceTransfer.sol';

/// @title IPermitForwarder
/// @notice Interface of {PermitForwarder}
interface IPermitForwarder {
  /// @notice The canonical Permit2 deployment every permit on this contract is relayed to
  function PERMIT2() external view returns (address);

  /**
   * @notice Relays ERC20 permits so a batch can be approved and spent in one transaction
   * @dev One `permitData` blob per token; its length selects the permit flavour, and an
   * unrecognised length is skipped. Failures are swallowed so a front-run permit cannot grief the
   * batch, which means callers must check the allowance rather than trust a successful return.
   * @param owner Account granting the approvals
   * @param tokens One token per permit
   * @param permitData One payload per token, paired by index
   */
  function erc20Permit(address owner, address[] calldata tokens, bytes[] calldata permitData)
    external
    payable;

  /**
   * @notice Relays ERC721 permits, with the same length dispatch and failure handling
   * @param tokens One collection per permit
   * @param tokenIds The token each permit covers, paired by index
   * @param permitData One payload per token, paired by index
   */
  function erc721Permit(
    address[] calldata tokens,
    uint256[] calldata tokenIds,
    bytes[] calldata permitData
  ) external payable;

  /**
   * @notice Relays a Permit2 batch approval; failures are swallowed as above
   * @param owner Account granting the approvals
   * @param permitBatch The Permit2 batch the owner signed
   * @param signature The owner's signature over that batch
   */
  function permit2Permit(
    address owner,
    IAllowanceTransfer.PermitBatch calldata permitBatch,
    bytes calldata signature
  ) external payable;
}
