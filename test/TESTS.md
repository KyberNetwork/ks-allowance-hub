# Tests

The suite has 184 tests in 14 contracts. Each row links to a test and gives the
first sentence of its documentation, or of the section heading above it. A test with neither
takes its ID and description from its name.

## CalldataHygieneTest

[`CalldataHygiene.t.sol`](CalldataHygiene.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| DIRTY-01 | [`test_DIRTY_01_delegatedExecution`](CalldataHygiene.t.sol#L27) | A dirty token address word is refused on the delegated execution rail |
| DIRTY-02 | [`test_DIRTY_02_permit2Execution`](CalldataHygiene.t.sol#L51) | A dirty token address word is refused on the Permit2-signature execution rail |
| DIRTY-03 | [`test_DIRTY_03_delegatedFulfillment`](CalldataHygiene.t.sol#L71) | A dirty token address word is refused on the delegated fulfillment rail |
| DIRTY-04 | [`test_DIRTY_04_permit2Fulfillment`](CalldataHygiene.t.sol#L93) | A dirty token address word is refused on the Permit2-signature fulfillment rail |

## DelegationTest

[`Delegation.t.sol`](Delegation.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| DEL-01 | [`test_DEL_01_selfDelegationSpendsNoNonce`](Delegation.t.sol#L85) | The owner delegates for themselves: no nonce is spent and the authenticator is trusted |
| DEL-02 | [`test_DEL_02_relayedDelegationConsumesNonce`](Delegation.t.sol#L109) | A third party may submit the delegation when it carries the owner's signature |
| DEL-03 | [`test_DEL_03_tamperedDelegationRejected`](Delegation.t.sol#L138) | Changing any signed field invalidates the delegation |
| DEL-04 | [`test_DEL_04_erc1271Owner`](Delegation.t.sol#L152) | An ERC-1271 owner's signature delegates, and a wrong magic value reverts |
| DEL-05 | [`test_DEL_05_expiredDelegation`](Delegation.t.sol#L193) | A relayed delegation past its deadline reverts with `DeadlinePassed` |
| DEL-06 | [`test_DEL_06_withdrawDelegation`](Delegation.t.sol#L211) | Withdrawing stops the hub accepting that authenticator, while the signer stays approved |
| DEL-08 | [`test_DEL_08_withdrawalDoesNotCallTheAuthenticator`](Delegation.t.sol#L236) | A withdrawal never reaches the authenticator, so one that reverts cannot trap the owner |
| DEL-09 | [`test_DEL_09_relayedWithdrawal`](Delegation.t.sol#L260) | A relayed withdrawal needs the owner's signature over the same direction |
| DEL-12 | [`test_DEL_12_initAuthenticationIsHubOnly`](Delegation.t.sol#L298) | `initAuthentication` answers the hub alone, and being the owner is not a way in |
| DEL-13 | [`test_DEL_13_emptyPayloadNeverCallsInitAuthentication`](Delegation.t.sol#L327) | An empty payload skips the authenticator, even on the delegate direction |
| DEL-14 | [`test_DEL_14_nonEmptyPayloadDoesCallInitAuthentication`](Delegation.t.sol#L354) | The guard reads the payload's length, not the direction alone |
| DEL-15 | [`test_DEL_15_withdrawalSkipsTheAuthenticatorWhateverThePayload`](Delegation.t.sol#L393) | A withdrawal skips the authenticator whatever the payload says |
| DEL-16 | [`test_DEL_16_delegationIsBoundToItsOwner`](Delegation.t.sol#L417) | A delegation signed for one account is refused for another account of one signer |
| DEL-17 | [`test_DEL_17_ownerCallTakesNoSignature`](Delegation.t.sol#L446) | A signature on the owner's own delegation call reverts with `UnexpectedSignature` |
| DEL-FUZZ | [`testFuzz_DEL_FUZZ_relayedDelegation`](Delegation.t.sol#L462) | A relayed delegation sets the delegation and exactly its nonce bit |

## ExecuteOrderTest

[`ExecuteOrder.t.sol`](ExecuteOrder.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| AUTH-01 | [`test_AUTH_01_permit2SelfSubmitted`](ExecuteOrder.t.sol#L41) | The owner submits their own Permit2 order, so nothing is witnessed |
| AUTH-02 | [`test_AUTH_02_permit2RelayedWithWitness`](ExecuteOrder.t.sol#L60) | A relayer submits a Permit2-signed order and its transfers and call execute |
| AUTH-03 | [`test_AUTH_03_witnessPinsTheCallList`](ExecuteOrder.t.sol#L82) | Mutating a byte of the signed call list invalidates the order |
| AUTH-04 | [`test_AUTH_04_witnessPinsTheNamedRelayer`](ExecuteOrder.t.sol#L106) | The relayer the owner specified is part of what the witness binds |
| ORD-02 | [`test_ORD_02_relayerPinningAndTheOpenSentinel`](ExecuteOrder.t.sol#L140) | `relayer` says who may submit, and the sentinel says anybody may |
| AUTH-06 | [`test_AUTH_06_ownerCallerNeedsNoAuthentication`](ExecuteOrder.t.sol#L188) | An owner acting for themselves needs no authenticator at all |
| AUTH-06b | [`test_AUTH_06b_ownerCallerViaPermit2Allowance`](ExecuteOrder.t.sol#L202) | An owner's own call without an authenticator draws on the Permit2 allowance |
| AUTH-08 | [`test_AUTH_08_undelegatedAuthenticatorRefused`](ExecuteOrder.t.sol#L225) | An authenticator the owner never delegated is refused before it is ever called |
| ORD-01 | [`test_ORD_01_theAssetSourceIsTheSubmittersArgument`](ExecuteOrder.t.sol#L248) | The asset source is the submitter's parameter, and the same order settles either way |
| ORD-01b | [`test_ORD_01b_thePermit2SignatureRailConsultsNoAllowance`](ExecuteOrder.t.sol#L292) | The Permit2-signature rail takes no source argument and claims neither allowance |
| AUTH-11 | [`test_AUTH_11_authenticatorReceivesTheWholeOrder`](ExecuteOrder.t.sol#L328) | The authenticator receives the whole order, unaltered, with the data it was given |
| AUTH-13 | [`test_AUTH_13_malformedAuthenticationDataRejected`](ExecuteOrder.t.sol#L359) | Authentication data too short to settle is rejected, on whichever gate it reaches |
| AUTH-14 | [`test_AUTH_14_authenticationBindsExtraData`](ExecuteOrder.t.sol#L395) | The authenticator's signature covers the order's extra data |
| AUTH-15 | [`test_AUTH_15_witnessPinsExtraData`](ExecuteOrder.t.sol#L430) | The witness covers the order's extra data |
| EX-FUZZ | [`testFuzz_EX_FUZZ_delegatedRail`](ExecuteOrder.t.sol#L480) | `executeOrderWithDelegatedAuthentication` settles a relayed order signed by an approved signer |
| EX-FUZZ | [`testFuzz_EX_FUZZ_permit2Rail`](ExecuteOrder.t.sol#L548) | `executeOrderWithPermit2Signature` settles a relayed order and spends its nonce |

## ForwarderTest

[`Forwarder.t.sol`](Forwarder.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| PF-01 | [`test_PF_01_eip2612PermitForwarded`](Forwarder.t.sol#L122) | A relayed EIP-2612 permit sets the token allowance and spends the permit nonce |
| PF-02 | [`test_PF_02_daiStylePermitForwarded`](Forwarder.t.sol#L145) | A relayed DAI-style permit sets the maximum allowance and spends the permit nonce |
| PF-03 | [`test_PF_03_erc721V3PermitForwarded`](Forwarder.t.sol#L168) | A relayed Uniswap v3 ERC-721 permit with a v/r/s signature sets the approval |
| PF-04 | [`test_PF_04_erc721V4PermitForwarded`](Forwarder.t.sol#L192) | A relayed Uniswap v4 ERC-721 permit with an unordered nonce sets the approval |
| PF-05 | [`test_PF_05_permit2BatchPermitForwarded`](Forwarder.t.sol#L210) | A relayed Permit2 batch `permit` sets the allowance, expiration and nonce |
| PF-06 | [`test_PF_06_relayedCallWithoutAuthorityIsRefusedByItsTarget`](Forwarder.t.sol#L245) | A relayed call that proves no authority is refused by its target |
| PF-06b | [`test_PF_06b_failingTransferUnwindsTheBatch`](Forwarder.t.sol#L290) | A relayed call that fails on its target unwinds the entries that already ran |
| PF-08 | [`test_PF_08_failingCallRevertsWithMulticall3ErrorWhenNotAllowed`](Forwarder.t.sol#L315) | With `allowFailure` false, a failing call reverts the batch with Multicall3's error |
| PF-09 | [`test_PF_09_failingCallIsCarriedPastWhenAllowed`](Forwarder.t.sol#L330) | With `allowFailure` true, a failing call is recorded and the batch continues |
| PF-FUZZ | [`testFuzz_PF_FUZZ_allowFailureBits`](Forwarder.t.sol#L364) | A batch settles exactly when every entry that fails has `allowFailure` true |
| FWD-13 | [`test_FWD_13_updateAuthenticationIsRelayedAndApprovesTheSigner`](Forwarder.t.sol#L447) | A relayed `updateAuthentication` approves a signer, on the authenticator's nonce |
| FWD-14 | [`test_FWD_14_emptySignatureIsRefusedEvenFromTheOwner`](Forwarder.t.sol#L487) | A relayed `updateAuthentication` with an empty signature is refused for an owner |
| FWD-21 | [`test_FWD_21_updateDelegationIsRelayed`](Forwarder.t.sol#L524) | A relayed `updateDelegation` delegates on the owner's signature and the hub's nonce |
| FWD-22 | [`test_FWD_22_relayedDelegationNeedsTheOwnersSignature`](Forwarder.t.sol#L550) | A relayed `updateDelegation` needs the owner's signature even when the owner relays it |
| FWD-16 | [`test_FWD_16_authenticatorRefusesMulticall3OnHubOnlyCalls`](Forwarder.t.sol#L577) | Multicall3 relays `initAuthentication` and the `authenticate*` calls, and the authenticator refuses it as the caller because it is not the hub |
| FWD-17 | [`test_FWD_17_permit2SinglePermitForwarded`](Forwarder.t.sol#L647) | A relayed Permit2 single `permit` sets the allowance |
| FWD-18 | [`test_FWD_18_emptyBatchIsANoOp`](Forwarder.t.sol#L677) | An empty batch is a legal no-op rather than an error |
| FWD-PAUSE-01 | [`test_FWD_PAUSE_01_forwardStillWorksWhilePaused`](Forwarder.t.sol#L694) | A pause does not close `forwardCalls` |
| FWD-VALUE-01 | [`test_FWD_VALUE_01_valueSentWithForwardIsStranded`](Forwarder.t.sol#L718) | Value sent with `forwardCalls` remains in the hub, not Multicall3 |
| FWD-REENTRY-01 | [`test_FWD_REENTRY_01_relayedPermitMayReenterTheHub`](Forwarder.t.sol#L746) | A relayed permit may reenter the hub and start an order |
| FWD-23 | [`test_FWD_23_multicall3RelaysWhenCalledDirectly`](Forwarder.t.sol#L784) | Multicall3 relays a permit and a failing call alike when called directly |
| FWD-24 | [`test_FWD_24_hubForwardsThroughMulticall3`](Forwarder.t.sol#L817) | `hub.forwardCalls` calls the target with Multicall3 as the caller |

## FulfillOrderTest

[`FulfillOrder.t.sol`](FulfillOrder.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| AUTH-01b | [`test_AUTH_01b_fulfillmentPermit2SelfSubmittedChecksNoApproval`](FulfillOrder.t.sol#L69) | The owner submits their own fulfillment, so the permit witnesses nothing and no approval is checked |
| AUTH-07 | [`test_AUTH_07_fulfillmentPermit2Witness`](FulfillOrder.t.sol#L112) | A solver settles a witnessed order under the sentinel approver with its own route |
| AUTH-07b | [`test_AUTH_07b_solutionApproverIsBoundByTheWitness`](FulfillOrder.t.sol#L143) | The solver cannot swap in a different approver than the one the owner signed |
| AUTH-16 | [`test_AUTH_16_witnessPinsExtraData`](FulfillOrder.t.sol#L197) | The witness covers the order's extra data |
| AUTH-17 | [`test_AUTH_17_authenticationBindsExtraData`](FulfillOrder.t.sol#L234) | The authenticator's signature covers the order's extra data |
| AUTH-18 | [`test_AUTH_18_authenticatorReceivesTheOrderAndTheSolution`](FulfillOrder.t.sol#L281) | The authenticator receives the order, its hash, the solution and the data, unaltered |
| ORD-03 | [`test_ORD_03_solverPinningAndTheOpenSentinel`](FulfillOrder.t.sol#L327) | Only the named `solver` may submit a Permit2 fulfillment, the sentinel admits anyone |
| SOL-01 | [`test_SOL_01_oneApprovalBindsOneOrder`](FulfillOrder.t.sol#L408) | One approval binds one order, `ownerCalls` included |
| SOL-05 | [`test_SOL_05_theRouteExpirationIsEnforced`](FulfillOrder.t.sol#L470) | A route past its own expiration is refused on both rails under any approver |
| SOL-06 | [`test_SOL_06_anApprovalSettlesOnce`](FulfillOrder.t.sol#L525) | An approval is spent when it settles, so it settles at most once |
| SOL-02 | [`test_SOL_02_sentinelApproverAcceptsAnyRoute`](FulfillOrder.t.sol#L574) | The sentinel approver accepts any route, with no signature to present |
| SOL-03 | [`test_SOL_03_malformedApprovalSignature`](FulfillOrder.t.sol#L627) | A malformed approval is refused rather than read as "no approver specified" |
| SOL-04 | [`test_SOL_04_anAuthenticatedFulfillmentCannotSettleTwice`](FulfillOrder.t.sol#L661) | One authenticated fulfillment settles at most once |
| SOL-07 | [`test_SOL_07_anApprovalNonceCannotBeReusedForAnotherOrder`](FulfillOrder.t.sol#L704) | An approval nonce settles once for its approver, whichever order it approves |
| SOL-08 | [`test_SOL_08_theApproverRevokesAnApproval`](FulfillOrder.t.sol#L741) | The approver revokes an unused approval with `revokeNonce` |
| SOL-09 | [`test_SOL_09_theSentinelApproverSpendsNothing`](FulfillOrder.t.sol#L763) | The dead-address approver spends no nonce, so the same nonce repeats |
| SOL-10 | [`test_SOL_10_thePermit2RailSpendsTheApprovalNonce`](FulfillOrder.t.sol#L783) | The Permit2 rail spends the approval nonce as the delegated rail does |
| SOL-11 | [`testFuzz_SOL_11_exactlyTheSolutionNonceIsSpent`](FulfillOrder.t.sol#L813) | Exactly the solution nonce is spent, and a replay reports it |
| SOL-12 | [`test_SOL_12_theApproverNamespaceIsSharedWithDelegationNonces`](FulfillOrder.t.sol#L851) | The approver's namespace is shared with its `updateDelegation` nonces |
| OWNER-APR-01 | [`testFuzz_OWNER_APR_01_ownerSettlesWithoutAnApproval`](FulfillOrder.t.sol#L881) | The owner settles under a named approver with a garbage approval |
| OWNER-APR-02 | [`testFuzz_OWNER_APR_02_solverIsRefusedWithoutAnApproval`](FulfillOrder.t.sol#L909) | The solver submitting the same order and approval is refused |
| OWN-01 | [`test_OWN_01_ownerCallsRunAfterSolverCalls`](FulfillOrder.t.sol#L946) | The tail runs after the solver's route, not merely alongside it |
| OWN-02 | [`test_OWN_02_witnessBindsOwnerCalls`](FulfillOrder.t.sol#L980) | The Permit2 witness pins the tail the owner signed |
| OWN-03 | [`test_OWN_03_authenticationBindsOwnerCalls`](FulfillOrder.t.sol#L1041) | A tail swapped after the authenticator's signature is refused on the delegated rail |
| OWN-04 | [`test_OWN_04_ownerCallRouterMustBeWhitelisted`](FulfillOrder.t.sol#L1086) | A tail call to a router without the role reverts, as a route call does |
| OWN-05 | [`test_OWN_05_emptyOwnerCallsIsThePriorBehaviour`](FulfillOrder.t.sol#L1123) | An empty tail runs no extra call and returns no extra result |
| OWN-06 | [`test_OWN_06_resultsAreSolverThenOwner`](FulfillOrder.t.sol#L1155) | `results` is the route then the tail, one entry per call |
| VAL-01 | [`test_VAL_01_hookOrderingAndSnapshotPairing`](FulfillOrder.t.sol#L1201) | The hooks bracket the whole order on the delegated rail, each snapshot to its owner |
| VAL-02 | [`test_VAL_02_hooksBracketThePermit2Rail`](FulfillOrder.t.sol#L1255) | On the Permit2 rail, the pre-hook precedes the pull and the post-hook the tail |
| VAL-03 | [`test_VAL_03_revertingAfterExecutionUnwinds`](FulfillOrder.t.sol#L1301) | A validator that rejects the outcome reverts the whole order |
| VAL-04 | [`test_VAL_04_noValidators`](FulfillOrder.t.sol#L1322) | An order with no validators settles and runs its router call |
| FU-FUZZ | [`testFuzz_FU_FUZZ_delegatedRail`](FulfillOrder.t.sol#L1368) | A relayed fulfillment signed by an approved signer settles for any drawn order and spends its nonce |
| FU-FUZZ | [`testFuzz_FU_FUZZ_permit2Rail`](FulfillOrder.t.sol#L1414) | A relayed Permit2 fulfillment settles for any drawn order and spends its nonce |

## FulfillTargetsTest

[`FulfillTargets.t.sol`](FulfillTargets.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| TGT-01 / LEN-01 | [`test_TGT_01_solverChoosesTheTargetsOnTheDelegatedRail`](FulfillTargets.t.sol#L61) | Delegated rail: mismatched target counts revert, matching counts settle |
| TGT-02 | [`test_TGT_02_solverTargetsOnThePermit2AllowancePull`](FulfillTargets.t.sol#L84) | On the delegated rail, a Permit2 allowance pull pays the targets the solution names |
| TGT-03 / LEN-02 | [`test_TGT_03_witnessDoesNotBindTheErc20Targets`](FulfillTargets.t.sol#L105) | Over Permit2, one witness accepts any ERC20 targets; wrong counts revert |
| TGT-04 | [`test_TGT_04_ownerSubmitsWithTargetsOfTheirChoice`](FulfillTargets.t.sol#L144) | The owner submits over Permit2 with a plain permit, and still picks the targets |
| APR-01 | [`test_APR_01_theApprovalBindsTheTargets`](FulfillTargets.t.sol#L164) | An approval of one set of targets does not approve another |
| EVT-01 | [`test_EVT_01_fulfillmentEventPairsTransfersWithTargets`](FulfillTargets.t.sol#L202) | `TransferTokens` lists the transfers that happened, each with the solution's target |
| AMT-01 | [`test_AMT_01_amountBelowTheAllowanceMovesExactlyThatAmount`](FulfillTargets.t.sol#L267) | An amount below the allowance moves exactly that amount, on each pull branch |
| AMT-02 | [`test_AMT_02_amountAboveTheAllowanceIsRefusedWithItsIndex`](FulfillTargets.t.sol#L305) | An amount equal to the allowance settles, and one above it is refused with its index |
| AMT-03 | [`test_AMT_03_amountZeroMovesNothingOnItsTransfer`](FulfillTargets.t.sol#L327) | An amount of 0 settles and moves nothing on its transfer |
| AMT-04 | [`test_AMT_04_amountsOfTheWrongLengthAreRefused`](FulfillTargets.t.sol#L357) | Amounts of a length other than the transfers are refused on both entry points |
| AMT-05 | [`test_AMT_05_theApprovalBindsTheAmounts`](FulfillTargets.t.sol#L385) | An approval signed for amounts of 5 ether is refused for a solution with 2 ether |
| AMT-FUZZ | [`testFuzz_AMT_FUZZ_solverAmount`](FulfillTargets.t.sol#L425) | The solver's amount moves exactly, or is refused above the allowance |

## GuardsTest

[`Guards.t.sol`](Guards.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| GUARD-01 | [`test_GUARD_01_pauseUnpauseRoundTrip`](Guards.t.sol#L93) | Pause and unpause set `paused()` and emit `Paused` and `Unpaused` |
| GUARD-02 | [`test_GUARD_02_pauseClosesOrdersNotDelegation`](Guards.t.sol#L112) | A pause closes the order entry points but leaves delegation open |
| GUARD-03 | [`test_GUARD_03_pauseRolesAreEnforced`](Guards.t.sol#L155) | Pausing needs the guardian or the admin, unpausing needs the admin alone |
| GUARD-04 | [`test_GUARD_04_expirationBoundaryOnTheOrderEntryPoints`](Guards.t.sol#L189) | The expiration block itself still settles; the one before it does not |
| GUARD-05 | [`test_GUARD_05_pauseTakesPrecedenceOverTheExpiration`](Guards.t.sol#L212) | When both guards would fire, the pause wins, because it is the outer modifier |
| GUARD-06 | [`test_GUARD_06_nativeSpendBoundary`](Guards.t.sol#L247) | An order may spend up to the value it was sent, and not one wei more |
| GATE-01 | [`test_GATE_01_fulfillPermit2CarriesTheThreeModifiers`](Guards.t.sol#L263) | The fulfillment Permit2 rail is pausable, expiration-checked and native-guarded |
| GATE-02 | [`test_GATE_02_theUnwatchedModifierApplications`](Guards.t.sol#L339) | Overspent native and an undelegated authenticator are refused on three entry points |

## ManagementTest

[`Management.t.sol`](Management.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| DOM-01 | [`test_DOM_01_bothDomainsAreChainScoped`](Management.t.sol#L56) | The hub and the authenticator sign under domains of their own, each scoped to the chain |
| MGMT-01 | [`test_MGMT_01_constructorWiring`](Management.t.sol#L87) | The constructor grants the initial roles, sets the owner and emits one event |
| MGMT-02 | [`test_MGMT_02_eip712Domain`](Management.t.sol#L128) | `eip712Domain()` returns the hub's name, version, chain id and address, no salt |
| MGMT-03 | [`test_MGMT_03_supportsInterface`](Management.t.sol#L152) | `supportsInterface` accepts the ERC-165 and AccessControl ids, not the admin rules |
| MGMT-05 | [`test_MGMT_05_setRoleRevoker`](Management.t.sol#L188) | No self-revoker and no revoker for the admin role; anything else is recorded |
| MGMT-06 | [`test_MGMT_06_revokeRoleNeedsRevokerOrAdmin`](Management.t.sol#L210) | `revokeRole` by a stranger reverts with both accepted roles, the admin may revoke |
| MGMT-07 | [`test_MGMT_07_transferOwnership`](Management.t.sol#L231) | The default admin role follows ownership, which moves in one step |
| MGMT-07b | [`test_MGMT_07b_renounceOwnership`](Management.t.sol#L254) | Renouncing ownership leaves no default admin |
| MGMT-08a | [`test_MGMT_08a_rescueErc20s`](Management.t.sol#L276) | Each ERC20 transfer goes to its target; a zero amount sends the whole balance |
| MGMT-08b | [`test_MGMT_08b_rescueStrandedNative`](Management.t.sol#L297) | `rescueTokens` sends native balance under both native sentinels |
| MGMT-08c | [`test_MGMT_08c_rescueGuards`](Management.t.sol#L317) | Only a rescuer or the default admin may rescue |
| MGMT-09 | [`test_MGMT_09_rescueErc721s`](Management.t.sol#L358) | An NFT sent to the hub by `transferFrom` is recovered by `rescueTokens` |
| MGMT-11 | [`test_MGMT_11_grantRole`](Management.t.sol#L384) | An ordinary role is granted by its admin |
| MGMT-11b | [`test_MGMT_11b_defaultAdminRoleFollowsOwnershipOnly`](Management.t.sol#L396) | The default admin role cannot be granted, revoked or renounced |

## MulticallTest

[`Multicall.t.sol`](Multicall.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| MC-01 | [`test_MC_01_permitAndOrderInOneBatch`](Multicall.t.sol#L51) | A permit and the order that uses the approval share one transaction, with value |
| MC-02 | [`test_MC_02_batchIsBoundedAsAWhole`](Multicall.t.sol#L94) | Each sub-call may spend the value, but the batch as a whole may not spend it twice |
| MC-03 | [`test_MC_03_subCallRevertBubbles`](Multicall.t.sol#L127) | A sub-call's revert arrives at the caller with its arguments intact |
| MC-04 | [`test_MC_04_twoOrdersInOneBatch`](Multicall.t.sol#L154) | Two independent orders in one batch both settle, in the order given |
| MC-07 | [`test_MC_07_gasIsMeasuredPerEntry`](Multicall.t.sol#L188) | Each entry is measured on its own, not given a running total of the batch |
| MC-05 | [`test_MC_05_plainNativeTransferIsRefused`](Multicall.t.sol#L219) | The hub has no `receive`, so a bare transfer cannot strand native in it |
| MC-09 | [`test_MC_09_aFrontRunDelegationDoesNotUnwindTheBatch`](Multicall.t.sol#L237) | A delegation relayed through `forwardCalls` with `allowFailure` set survives being front-run, so the order batched after it still settles |
| MC-06 | [`test_MC_06_approveASignerAndSpendOnItInOneBatch`](Multicall.t.sol#L316) | One batch approves a signer at an authenticator and then spends on it |
| MC-FUZZ | [`testFuzz_MC_FUZZ_valueNeedsAnAllPayableBatch`](Multicall.t.sol#L399) | Value survives a batch exactly when every selector in it is payable |

## NoncesTest

[`Nonces.t.sol`](Nonces.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| NONCE-01 / NONCE-FUZZ | [`testFuzz_NONCE_FUZZ_revokeSetsExactlyOneBit`](Nonces.t.sol#L20) | Revoking any nonce sets exactly the bit at its position |
| NONCE-01 | [`test_NONCE_01_bitmapBoundaries`](Nonces.t.sol#L32) | Revoking nonces 0, 255, 256 and the maximum sets one bit each in the right word |
| NONCE-04 | [`test_NONCE_04_doubleRevoke`](Nonces.t.sol#L50) | Revoking twice reverts |
| NONCE-05 | [`test_NONCE_05_hubAndAuthenticatorAreIndependent`](Nonces.t.sol#L61) | The hub and the authenticator keep separate bitmaps |

## OrderPartiesTest

[`OrderParties.t.sol`](OrderParties.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| ORD-02b | [`test_ORD_02b_delegatedExecutionHonoursTheNamedRelayer`](OrderParties.t.sol#L45) | The delegated execution rail refuses a submitter the order did not specify |
| ORD-04 | [`test_ORD_04_delegatedExecutionDrawsOnTheNamedOwner`](OrderParties.t.sol#L100) | An order repointed to another owner who approved the same signer reverts |
| ORD-03b | [`test_ORD_03b_delegatedFulfillmentHonoursTheNamedSolver`](OrderParties.t.sol#L138) | The delegated fulfillment rail refuses a submitter the order did not specify |

## SettlementTest

[`Settlement.t.sol`](Settlement.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| SET-01 | [`test_SET_01_transferTokensPayload`](Settlement.t.sol#L85) | The whole `TransferTokens` payload of a relayed order, byte for byte |
| CLIENT-01 | [`testFuzz_CLIENT_01_clientDataIsEmittedAsGiven`](Settlement.t.sol#L119) | The `TransferTokens` of a settled order carries exactly the order's client data |
| CLIENT-02 | [`testFuzz_CLIENT_02_clientDataIsCoveredByTheSignature`](Settlement.t.sol#L135) | The owner's signature covers the order's client data |
| CLIENT-02b | [`test_CLIENT_02b_emptyClientDataIsCoveredByTheSignature`](Settlement.t.sol#L153) | Client data submitted against empty signed client data reverts on every entry |
| SET-02 | [`test_SET_02_nativeTransfersAreTruncatedToValuedCalls`](Settlement.t.sol#L283) | `[v=0, v=1, v=0]` reaches the event as a single-entry native list |
| SET-03 | [`test_SET_03_emptyOrderStillEmits`](Settlement.t.sol#L318) | An order that moves nothing and calls nobody still settles and still emits |
| SET-04 | [`test_SET_04_resultsFollowCallOrder`](Settlement.t.sol#L343) | `results[i]` belongs to `genericCalls[i]`, across two interleaved routers |
| OWN-07 | [`test_OWN_07_eventCoversBothLists`](Settlement.t.sol#L381) | The native transfers of the event span both call lists, solver's route first |
| ROUTER-01 | [`test_ROUTER_01_unwhitelistedRouterIsRejected`](Settlement.t.sol#L431) | A router without the role is refused, and the order rolls back whole |
| ROUTER-02 | [`test_ROUTER_02_guardianRevokeStopsTheNextOrder`](Settlement.t.sol#L459) | A guardian can drop a router, and the very next order stops working |
| ROUTER-03 | [`test_ROUTER_03_eachRouterCalledOnce`](Settlement.t.sol#L494) | Every whitelisted router in the list is called exactly once, with its own data |
| NEST-01 | [`testFuzz_NEST_01_nestedOrdersRestoreEachOwner`](Settlement.t.sol#L533) | Orders nested inside execution router calls settle, and each level sees its owner |
| NEST-02 | [`test_NEST_02_receiverHookSettlesAnOrderInsideAFulfillment`](Settlement.t.sol#L584) | The ERC721 receiver hook of a fulfillment may settle an order |
| NEST-03 | [`testFuzz_NEST_03_anOrderSettlesInsideAnotherOnEveryEntryPoint`](Settlement.t.sol#L652) | An order settles inside another on every entry point, as outer and as nested order |
| NEST-04 | [`test_NEST_04_revokeNonceIsReachableFromInsideAnOrder`](Settlement.t.sol#L727) | A router's `revokeNonce` inside an order spends the nonce in the router's namespace |
| NEST-05 | [`test_NEST_05_nestedOrderCannotSpendTheOuterValue`](Settlement.t.sol#L756) | A nested order cannot spend the outer order's value |

## Eip712Test

[`types/Eip712.t.sol`](types/Eip712.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| T712-08b | [`test_T712_08b_authDelegationStructHash`](types/Eip712.t.sol#L44) | The {AuthDelegation} hash matches the independent hash and moves with its inputs |
| T712-17 | [`test_T712_17_permit2TypeStringsSortTheirReferencedTypes`](types/Eip712.t.sol#L83) | Both Permit2 witness strings list their referenced types in sorted order |
| T712 | [`test_T712_executionWitnessStructHash`](types/Eip712.t.sol#L113) | The execution witness hash matches the independent encoding with empty extra and client data |
| T712 | [`test_T712_fulfillmentWitnessStructHash`](types/Eip712.t.sol#L126) | The fulfillment witness hash matches the independent encoding with empty extra and client data |
| T712 | [`test_T712_executionWitnessExtraDataStructHash`](types/Eip712.t.sol#L142) | Both execution witness hashers match the independent encoding, and extra data moves the hash |
| T712 | [`test_T712_fulfillmentWitnessExtraDataStructHash`](types/Eip712.t.sol#L161) | Both fulfillment witness hashers match the independent encoding, and extra data moves the hash |
| T712 | [`test_T712_ordersExtraDataStructHash`](types/Eip712.t.sol#L186) | Both order hashers match {SchemaHash} with extra data, and clearing it moves the hash |
| T712 | [`test_T712_witnessClientDataStructHash`](types/Eip712.t.sol#L215) | Both hashers of each witness match the independent encoding, and client data moves the hash |
| T712 | [`test_T712_ordersClientDataStructHash`](types/Eip712.t.sol#L263) | Both order hashers match {SchemaHash} with client data, and clearing it moves the hash |
| T712 | [`test_T712_executionOrderStructHash`](types/Eip712.t.sol#L289) | The memory and calldata hashers of the execution order match {SchemaHash} |
| T712 | [`test_T712_fulfillmentOrderStructHash`](types/Eip712.t.sol#L298) | The memory and calldata hashers of the fulfillment order match {SchemaHash} |
| T712 | [`test_T712_fulfillmentSolutionStructHash`](types/Eip712.t.sol#L307) | Both solution hashers match {SchemaHash}, and a changed nonce moves the hash |
| T712 | [`test_T712_solutionApprovalStructHash`](types/Eip712.t.sol#L328) | Both approval hashers match the independent encoding, and the order, targets and nonce move it |
| T712 | [`test_T712_erc20AllowanceStructHash`](types/Eip712.t.sol#L361) | Both hashers of each sample {ERC20Allowance} match {SchemaHash} |
| T712 | [`test_T712_erc721ApprovalStructHash`](types/Eip712.t.sol#L371) | Both hashers of a sample {ERC721Approval} match {SchemaHash} |
| T712-ARRAY | [`test_T712_ARRAY_addressArrayEncoding`](types/Eip712.t.sol#L384) | The packed encoding of an address array equals the per-element encoding |
| T712-ARRAY | [`testFuzz_T712_ARRAY_efficientHashLibExt`](types/Eip712.t.sol#L402) | Both address array hashers equal the hash of the words encoded one by one |
| T712-DIFF | [`testFuzz_T712_DIFF_genericCall`](types/Eip712.t.sol#L418) | The calldata and memory hashers of {GenericCall} return the same hash |
| T712-DIFF | [`testFuzz_T712_DIFF_erc20Transfer`](types/Eip712.t.sol#L423) | The calldata and memory hashers of {ERC20Transfer} return the same hash |
| T712-DIFF | [`testFuzz_T712_DIFF_erc721Transfer`](types/Eip712.t.sol#L428) | The calldata and memory hashers of {ERC721Transfer} return the same hash |
| T712-DIFF | [`testFuzz_T712_DIFF_erc20Allowance`](types/Eip712.t.sol#L433) | The calldata and memory hashers of {ERC20Allowance} return the same hash |
| T712-DIFF | [`testFuzz_T712_DIFF_erc721Approval`](types/Eip712.t.sol#L438) | The calldata and memory hashers of {ERC721Approval} return the same hash |
| T712-DIFF | [`testFuzz_T712_DIFF_validationParams`](types/Eip712.t.sol#L443) | The calldata and memory hashers of {ValidationParams} return the same hash |
| T712-DIFF | [`testFuzz_T712_DIFF_executionOrder`](types/Eip712.t.sol#L448) | The calldata and memory hashers of {ExecutionOrder} return the same hash |
| T712-DIFF | [`testFuzz_T712_DIFF_fulfillmentOrder`](types/Eip712.t.sol#L453) | The calldata and memory hashers of {FulfillmentOrder} return the same hash |

## SchemaAuditTest

[`types/SchemaAudit.t.sol`](types/SchemaAudit.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| T712-SCHEMA | [`test_T712_SCHEMA_typehashesMatchTheirStructs`](types/SchemaAudit.t.sol#L38) | Each typehash equals the hash of the schema derived from its struct |
| T712-SCHEMA-PERMIT2 | [`test_T712_SCHEMA_PERMIT2_witnessTypeStringsMatchTheirStructs`](types/SchemaAudit.t.sol#L113) | The Permit2 stub plus each witness type string equals its struct schema |
| T712-SCHEMA | [`test_T712_SCHEMA_clientDataTypeStringsWrittenOut`](types/SchemaAudit.t.sol#L141) | The four typehashes carrying client data match their written-out strings |
