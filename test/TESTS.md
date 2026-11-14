# Tests

The suite has 280 tests in 16 contracts. Each row links to a test and gives the
first sentence of its documentation, or of the section heading above it. A test with neither
takes its ID and description from its name.

## CalldataHygieneTest

[`CalldataHygiene.t.sol`](CalldataHygiene.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| DIRTY-01 | [`test_DIRTY_01_delegatedExecution`](CalldataHygiene.t.sol#L34) | A dirty token address word is refused on the delegated execution rail |
| DIRTY-02 | [`test_DIRTY_02_permit2Execution`](CalldataHygiene.t.sol#L58) | A dirty token address word is refused on the Permit2-signature execution rail |
| DIRTY-03 | [`test_DIRTY_03_delegatedFulfillment`](CalldataHygiene.t.sol#L78) | A dirty token address word is refused on the delegated fulfillment rail |
| DIRTY-04 | [`test_DIRTY_04_permit2Fulfillment`](CalldataHygiene.t.sol#L100) | A dirty token address word is refused on the Permit2-signature fulfillment rail |

## DelegationTest

[`Delegation.t.sol`](Delegation.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| DEL-01 | [`test_DEL_01_selfDelegationSpendsNoNonce`](Delegation.t.sol#L92) | The owner delegates for themselves: no nonce is spent and the authenticator is trusted |
| DEL-02 | [`test_DEL_02_relayedDelegationConsumesNonce`](Delegation.t.sol#L110) | A third party may submit the delegation when it carries the owner's signature |
| DEL-03 | [`test_DEL_03_tamperedDelegationRejected`](Delegation.t.sol#L135) | Changing any signed field invalidates the delegation |
| DEL-04 | [`test_DEL_04_erc1271Owner`](Delegation.t.sol#L151) | An ERC-1271 owner's signature delegates, and a wrong magic value reverts |
| DEL-05 | [`test_DEL_05_expiredDelegation`](Delegation.t.sol#L180) | A relayed delegation past its deadline reverts with `DeadlinePassed` |
| DEL-06 | [`test_DEL_06_withdrawDelegation`](Delegation.t.sol#L196) | Withdrawing stops the hub accepting that authenticator, while the key stays approved |
| DEL-08 | [`test_DEL_08_withdrawalDoesNotCallTheAuthenticator`](Delegation.t.sol#L222) | A withdrawal never reaches the authenticator, so one that reverts cannot trap the owner |
| DEL-09 | [`test_DEL_09_relayedWithdrawal`](Delegation.t.sol#L246) | A relayed withdrawal needs the owner's signature over the same direction |
| DEL-10 | [`test_DEL_10_initAuthenticationIgnoresTheDirectionWord`](Delegation.t.sol#L286) | `initAuthentication` ignores the direction word, so a "revoke" payload still approves |
| DEL-11 | [`test_DEL_11_bothPayloadShapesNameTheSameKey`](Delegation.t.sol#L310) | Both payload shapes specify the same key |
| DEL-12 | [`test_DEL_12_initAuthenticationIsHubOnly`](Delegation.t.sol#L338) | `initAuthentication` answers the hub alone, and being the owner is not a way in |
| DEL-13 | [`test_DEL_13_emptyPayloadNeverCallsInitAuthentication`](Delegation.t.sol#L366) | An empty payload skips the authenticator, even on the delegate direction |
| DEL-14 | [`test_DEL_14_nonEmptyPayloadDoesCallInitAuthentication`](Delegation.t.sol#L393) | The guard reads the payload's length, not the direction alone |
| DEL-15 | [`test_DEL_15_withdrawalSkipsTheAuthenticatorWhateverThePayload`](Delegation.t.sol#L432) | A withdrawal skips the authenticator whatever the payload says |
| DEL-16 | [`test_DEL_16_delegationIsBoundToItsOwner`](Delegation.t.sol#L456) | A delegation signed for one account is refused for another account of one signer |
| DEL-17 | [`test_DEL_17_ownerCallTakesNoSignature`](Delegation.t.sol#L481) | A signature on the owner's own delegation call reverts with `UnexpectedSignature` |
| DEL-FUZZ | [`testFuzz_DEL_FUZZ_relayedDelegation`](Delegation.t.sol#L497) | A relayed delegation sets the delegation and exactly its nonce bit |

## ExecuteOrderTest

[`ExecuteOrder.t.sol`](ExecuteOrder.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| AUTH-01 | [`test_AUTH_01_permit2SelfSubmitted`](ExecuteOrder.t.sol#L57) | The owner submits their own Permit2 order, so nothing is witnessed |
| AUTH-02 | [`test_AUTH_02_permit2RelayedWithWitness`](ExecuteOrder.t.sol#L76) | A relayer submits a Permit2-signed order and its transfers and call execute |
| AUTH-03 | [`test_AUTH_03_witnessPinsTheCallList`](ExecuteOrder.t.sol#L98) | Mutating a byte of the signed call list invalidates the order |
| AUTH-04 | [`test_AUTH_04_witnessPinsTheNamedRelayer`](ExecuteOrder.t.sol#L122) | The relayer the owner specified is part of what the witness binds |
| ORD-02 | [`test_ORD_02_relayerPinningAndTheOpenSentinel`](ExecuteOrder.t.sol#L156) | `relayer` says who may submit, and the sentinel says anybody may |
| AUTH-06 | [`test_AUTH_06_ownerCallerNeedsNoAuthentication`](ExecuteOrder.t.sol#L204) | An owner acting for themselves needs no authenticator at all |
| AUTH-06b | [`test_AUTH_06b_ownerCallerViaPermit2Allowance`](ExecuteOrder.t.sol#L218) | An owner's own call without an authenticator draws on the Permit2 allowance |
| AUTH-08 | [`test_AUTH_08_undelegatedAuthenticatorRefused`](ExecuteOrder.t.sol#L241) | An authenticator the owner never delegated is refused before it is ever called |
| ORD-01 | [`test_ORD_01_theAssetSourceIsTheSubmittersArgument`](ExecuteOrder.t.sol#L264) | The asset source is the submitter's parameter, and the same order settles either way |
| ORD-01b | [`test_ORD_01b_thePermit2SignatureRailConsultsNoAllowance`](ExecuteOrder.t.sol#L308) | The Permit2-signature rail takes no source argument and claims neither allowance |
| AUTH-11 | [`test_AUTH_11_authenticatorReceivesTheWholeOrder`](ExecuteOrder.t.sol#L344) | The authenticator receives the whole order, unaltered, with the data it was given |
| AUTH-13 | [`test_AUTH_13_malformedAuthenticationDataRejected`](ExecuteOrder.t.sol#L378) | Authentication data too short to settle is rejected, on whichever gate it reaches |
| AUTH-14 | [`test_AUTH_14_authenticationBindsExtraData`](ExecuteOrder.t.sol#L414) | The authenticator's signature covers the order's extra data |
| AUTH-15 | [`test_AUTH_15_witnessPinsExtraData`](ExecuteOrder.t.sol#L449) | The witness covers the order's extra data |
| EX-FUZZ | [`testFuzz_EX_FUZZ_delegatedRail`](ExecuteOrder.t.sol#L499) | `executeOrderWithDelegatedAuthentication` settles a relayed session-key order |
| EX-FUZZ | [`testFuzz_EX_FUZZ_permit2Rail`](ExecuteOrder.t.sol#L567) | `executeOrderWithPermit2Signature` settles a relayed order and spends its nonce |

## ForwarderTest

[`Forwarder.t.sol`](Forwarder.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| PF-01 | [`test_PF_01_eip2612PermitForwarded`](Forwarder.t.sol#L121) | A relayed EIP-2612 permit sets the token allowance and spends the permit nonce |
| PF-02 | [`test_PF_02_daiStylePermitForwarded`](Forwarder.t.sol#L144) | A relayed DAI-style permit sets the maximum allowance and spends the permit nonce |
| PF-03 | [`test_PF_03_erc721V3PermitForwarded`](Forwarder.t.sol#L167) | A relayed Uniswap v3 ERC-721 permit with a v/r/s signature sets the approval |
| PF-04 | [`test_PF_04_erc721V4PermitForwarded`](Forwarder.t.sol#L191) | A relayed Uniswap v4 ERC-721 permit with an unordered nonce sets the approval |
| PF-05 | [`test_PF_05_permit2BatchPermitForwarded`](Forwarder.t.sol#L209) | A relayed Permit2 batch `permit` sets the allowance, expiration and nonce |
| PF-06 | [`test_PF_06_relayedCallWithoutAuthorityIsRefusedByItsTarget`](Forwarder.t.sol#L244) | A relayed call that proves no authority is refused by its target |
| PF-06b | [`test_PF_06b_failingTransferUnwindsTheBatch`](Forwarder.t.sol#L289) | A relayed call that fails on its target unwinds the entries that already ran |
| PF-08 | [`test_PF_08_failingCallRevertsWithMulticall3ErrorWhenNotAllowed`](Forwarder.t.sol#L314) | With `allowFailure` false, a failing call reverts the batch with Multicall3's error |
| PF-09 | [`test_PF_09_failingCallIsCarriedPastWhenAllowed`](Forwarder.t.sol#L329) | With `allowFailure` true, a failing call is recorded and the batch continues |
| PF-FUZZ | [`testFuzz_PF_FUZZ_allowFailureBits`](Forwarder.t.sol#L363) | A batch settles exactly when every entry that fails has `allowFailure` true |
| FWD-13 | [`test_FWD_13_updateAuthenticationIsRelayedAndApprovesTheKey`](Forwarder.t.sol#L446) | A relayed `updateAuthentication` approves a session key, on the authenticator's nonce |
| FWD-20 | [`test_FWD_20_updateAuthenticationIsRelayedOnTheMasterKeyRail`](Forwarder.t.sol#L485) | A relayed `updateAuthentication` signed by a master key approves a session key |
| FWD-14 | [`test_FWD_14_emptySignatureIsRefusedEvenFromTheOwner`](Forwarder.t.sol#L526) | A relayed `updateAuthentication` with an empty signature is refused for an owner |
| FWD-21 | [`test_FWD_21_updateDelegationIsRelayed`](Forwarder.t.sol#L561) | A relayed `updateDelegation` delegates on the owner's signature and the hub's nonce |
| FWD-22 | [`test_FWD_22_relayedDelegationNeedsTheOwnersSignature`](Forwarder.t.sol#L587) | A relayed `updateDelegation` needs the owner's signature even when the owner relays it |
| FWD-16 | [`test_FWD_16_authenticatorRefusesMulticall3OnHubOnlyCalls`](Forwarder.t.sol#L614) | Multicall3 relays `initAuthentication` and the `authenticate*` calls, and the authenticator refuses it as the caller because it is not the hub |
| FWD-17 | [`test_FWD_17_permit2SinglePermitForwarded`](Forwarder.t.sol#L684) | A relayed Permit2 single `permit` sets the allowance |
| FWD-18 | [`test_FWD_18_emptyBatchIsANoOp`](Forwarder.t.sol#L714) | An empty batch is a legal no-op rather than an error |
| FWD-PAUSE-01 | [`test_FWD_PAUSE_01_forwardStillWorksWhilePaused`](Forwarder.t.sol#L731) | A pause does not close `forwardCalls` |
| FWD-VALUE-01 | [`test_FWD_VALUE_01_valueSentWithForwardIsStranded`](Forwarder.t.sol#L755) | Value sent with `forwardCalls` remains in the hub, not Multicall3 |
| FWD-REENTRY-01 | [`test_FWD_REENTRY_01_relayedPermitMayReenterTheHub`](Forwarder.t.sol#L783) | A relayed permit may reenter the hub and start an order |
| FWD-23 | [`test_FWD_23_multicall3RelaysWhenCalledDirectly`](Forwarder.t.sol#L821) | Multicall3 relays a permit and a failing call alike when called directly |
| FWD-24 | [`test_FWD_24_hubForwardsThroughMulticall3`](Forwarder.t.sol#L854) | `hub.forwardCalls` calls the target with Multicall3 as the caller |

## FulfillOrderTest

[`FulfillOrder.t.sol`](FulfillOrder.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| AUTH-01b | [`test_AUTH_01b_fulfillmentPermit2SelfSubmittedChecksNoApproval`](FulfillOrder.t.sol#L76) | The owner submits their own fulfillment, so the permit witnesses nothing and no approval is checked |
| AUTH-07 | [`test_AUTH_07_fulfillmentPermit2Witness`](FulfillOrder.t.sol#L119) | A solver settles a witnessed order under the sentinel approver with its own route |
| AUTH-07b | [`test_AUTH_07b_solutionApproverIsBoundByTheWitness`](FulfillOrder.t.sol#L150) | The solver cannot swap in a different approver than the one the owner signed |
| AUTH-16 | [`test_AUTH_16_witnessPinsExtraData`](FulfillOrder.t.sol#L204) | The witness covers the order's extra data |
| AUTH-17 | [`test_AUTH_17_authenticationBindsExtraData`](FulfillOrder.t.sol#L241) | The authenticator's signature covers the order's extra data |
| AUTH-18 | [`test_AUTH_18_authenticatorReceivesTheOrderAndTheSolution`](FulfillOrder.t.sol#L288) | The authenticator receives the order, its hash, the solution and the data, unaltered |
| ORD-03 | [`test_ORD_03_solverPinningAndTheOpenSentinel`](FulfillOrder.t.sol#L334) | Only the named `solver` may submit a Permit2 fulfillment, the sentinel admits anyone |
| SOL-01 | [`test_SOL_01_oneApprovalBindsOneOrder`](FulfillOrder.t.sol#L415) | One approval binds one order, `ownerCalls` included |
| SOL-05 | [`test_SOL_05_theRouteExpirationIsEnforced`](FulfillOrder.t.sol#L477) | A route past its own expiration is refused on both rails under any approver |
| SOL-06 | [`test_SOL_06_anApprovalSettlesOnce`](FulfillOrder.t.sol#L532) | An approval is spent when it settles, so it settles at most once |
| SOL-02 | [`test_SOL_02_sentinelApproverAcceptsAnyRoute`](FulfillOrder.t.sol#L581) | The sentinel approver accepts any route, with no signature to present |
| SOL-03 | [`test_SOL_03_malformedApprovalSignature`](FulfillOrder.t.sol#L634) | A malformed approval is refused rather than read as "no approver specified" |
| SOL-04 | [`test_SOL_04_anAuthenticatedFulfillmentCannotSettleTwice`](FulfillOrder.t.sol#L668) | One authenticated fulfillment settles at most once |
| SOL-07 | [`test_SOL_07_anApprovalNonceCannotBeReusedForAnotherOrder`](FulfillOrder.t.sol#L711) | An approval nonce settles once for its approver, whichever order it approves |
| SOL-08 | [`test_SOL_08_theApproverRevokesAnApproval`](FulfillOrder.t.sol#L748) | The approver revokes an unused approval with `revokeNonce` |
| SOL-09 | [`test_SOL_09_theSentinelApproverSpendsNothing`](FulfillOrder.t.sol#L770) | The dead-address approver spends no nonce, so the same nonce repeats |
| SOL-10 | [`test_SOL_10_thePermit2RailSpendsTheApprovalNonce`](FulfillOrder.t.sol#L790) | The Permit2 rail spends the approval nonce as the delegated rail does |
| SOL-11 | [`testFuzz_SOL_11_exactlyTheSolutionNonceIsSpent`](FulfillOrder.t.sol#L820) | Exactly the solution nonce is spent, and a replay reports it |
| SOL-12 | [`test_SOL_12_theApproverNamespaceIsSharedWithDelegationNonces`](FulfillOrder.t.sol#L858) | The approver's namespace is shared with its `updateDelegation` nonces |
| OWNER-APR-01 | [`testFuzz_OWNER_APR_01_ownerSettlesWithoutAnApproval`](FulfillOrder.t.sol#L888) | The owner settles under a named approver with a garbage approval |
| OWNER-APR-02 | [`testFuzz_OWNER_APR_02_solverIsRefusedWithoutAnApproval`](FulfillOrder.t.sol#L916) | The solver submitting the same order and approval is refused |
| OWN-01 | [`test_OWN_01_ownerCallsRunAfterSolverCalls`](FulfillOrder.t.sol#L953) | The tail runs after the solver's route, not merely alongside it |
| OWN-02 | [`test_OWN_02_witnessBindsOwnerCalls`](FulfillOrder.t.sol#L987) | The Permit2 witness pins the tail the owner signed |
| OWN-03 | [`test_OWN_03_authenticationBindsOwnerCalls`](FulfillOrder.t.sol#L1048) | A tail swapped after the authenticator's signature is refused on the delegated rail |
| OWN-04 | [`test_OWN_04_ownerCallRouterMustBeWhitelisted`](FulfillOrder.t.sol#L1093) | A tail call to a router without the role reverts, as a route call does |
| OWN-05 | [`test_OWN_05_emptyOwnerCallsIsThePriorBehaviour`](FulfillOrder.t.sol#L1130) | An empty tail runs no extra call and returns no extra result |
| OWN-06 | [`test_OWN_06_resultsAreSolverThenOwner`](FulfillOrder.t.sol#L1162) | `results` is the route then the tail, one entry per call |
| VAL-01 | [`test_VAL_01_hookOrderingAndSnapshotPairing`](FulfillOrder.t.sol#L1208) | The hooks bracket the whole order on the delegated rail, each snapshot to its owner |
| VAL-02 | [`test_VAL_02_hooksBracketThePermit2Rail`](FulfillOrder.t.sol#L1262) | On the Permit2 rail, the pre-hook precedes the pull and the post-hook the tail |
| VAL-03 | [`test_VAL_03_revertingAfterExecutionUnwinds`](FulfillOrder.t.sol#L1308) | A validator that rejects the outcome reverts the whole order |
| VAL-04 | [`test_VAL_04_noValidators`](FulfillOrder.t.sol#L1329) | An order with no validators settles and runs its router call |
| FU-FUZZ | [`testFuzz_FU_FUZZ_delegatedRail`](FulfillOrder.t.sol#L1374) | A relayed session-key fulfillment settles for any drawn order and spends its nonce |
| FU-FUZZ | [`testFuzz_FU_FUZZ_permit2Rail`](FulfillOrder.t.sol#L1420) | A relayed Permit2 fulfillment settles for any drawn order and spends its nonce |

## FulfillTargetsTest

[`FulfillTargets.t.sol`](FulfillTargets.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| TGT-01 / LEN-01 | [`test_TGT_01_solverChoosesTheTargetsOnTheDelegatedRail`](FulfillTargets.t.sol#L65) | Delegated rail: mismatched target counts revert, matching counts settle |
| TGT-02 | [`test_TGT_02_solverTargetsOnThePermit2AllowancePull`](FulfillTargets.t.sol#L88) | On the delegated rail, a Permit2 allowance pull pays the targets the solution names |
| TGT-03 / LEN-02 | [`test_TGT_03_witnessDoesNotBindTheErc20Targets`](FulfillTargets.t.sol#L109) | Over Permit2, one witness accepts any ERC20 targets; wrong counts revert |
| TGT-04 | [`test_TGT_04_ownerSubmitsWithTargetsOfTheirChoice`](FulfillTargets.t.sol#L148) | The owner submits over Permit2 with a plain permit, and still picks the targets |
| APR-01 | [`test_APR_01_theApprovalBindsTheTargets`](FulfillTargets.t.sol#L168) | An approval of one set of targets does not approve another |
| EVT-01 | [`test_EVT_01_fulfillmentEventPairsTransfersWithTargets`](FulfillTargets.t.sol#L206) | `TransferTokens` lists the transfers that happened, each with the solution's target |
| AMT-01 | [`test_AMT_01_amountBelowTheAllowanceMovesExactlyThatAmount`](FulfillTargets.t.sol#L271) | An amount below the allowance moves exactly that amount, on each pull branch |
| AMT-02 | [`test_AMT_02_amountAboveTheAllowanceIsRefusedWithItsIndex`](FulfillTargets.t.sol#L309) | An amount equal to the allowance settles, and one above it is refused with its index |
| AMT-03 | [`test_AMT_03_amountZeroMovesNothingOnItsTransfer`](FulfillTargets.t.sol#L331) | An amount of 0 settles and moves nothing on its transfer |
| AMT-04 | [`test_AMT_04_amountsOfTheWrongLengthAreRefused`](FulfillTargets.t.sol#L361) | Amounts of a length other than the transfers are refused on both entry points |
| AMT-05 | [`test_AMT_05_theApprovalBindsTheAmounts`](FulfillTargets.t.sol#L389) | An approval signed for amounts of 5 ether is refused for a solution with 2 ether |
| AMT-FUZZ | [`testFuzz_AMT_FUZZ_solverAmount`](FulfillTargets.t.sol#L429) | The solver's amount moves exactly, or is refused above the allowance |

## GuardsTest

[`Guards.t.sol`](Guards.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| GUARD-01 | [`test_GUARD_01_pauseUnpauseRoundTrip`](Guards.t.sol#L91) | Pause and unpause set `paused()` and emit `Paused` and `Unpaused` |
| GUARD-02 | [`test_GUARD_02_pauseClosesOrdersNotDelegation`](Guards.t.sol#L110) | A pause closes the order entry points but leaves delegation open |
| GUARD-03 | [`test_GUARD_03_pauseRolesAreEnforced`](Guards.t.sol#L153) | Pausing needs the guardian or the admin, unpausing needs the admin alone |
| GUARD-04 | [`test_GUARD_04_expirationBoundaryOnTheOrderEntryPoints`](Guards.t.sol#L187) | The expiration block itself still settles; the one before it does not |
| GUARD-05 | [`test_GUARD_05_pauseTakesPrecedenceOverTheExpiration`](Guards.t.sol#L210) | When both guards would fire, the pause wins, because it is the outer modifier |
| GUARD-06 | [`test_GUARD_06_nativeSpendBoundary`](Guards.t.sol#L245) | An order may spend up to the value it was sent, and not one wei more |
| GATE-01 | [`test_GATE_01_fulfillPermit2CarriesTheThreeModifiers`](Guards.t.sol#L261) | The fulfillment Permit2 rail is pausable, expiration-checked and native-guarded |
| GATE-02 | [`test_GATE_02_theUnwatchedModifierApplications`](Guards.t.sol#L337) | Overspent native and an undelegated authenticator are refused on three entry points |

## ManagementTest

[`Management.t.sol`](Management.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| DOM-01 | [`test_DOM_01_bothDomainsAreChainScoped`](Management.t.sol#L56) | The hub and the authenticator sign under domains of their own, each scoped to the chain |
| MGMT-01 | [`test_MGMT_01_constructorWiring`](Management.t.sol#L88) | The constructor grants the initial roles, sets the owner and emits one event |
| MGMT-02 | [`test_MGMT_02_eip712Domain`](Management.t.sol#L129) | `eip712Domain()` returns the hub's name, version, chain id and address, no salt |
| MGMT-03 | [`test_MGMT_03_supportsInterface`](Management.t.sol#L153) | `supportsInterface` accepts the ERC-165 and AccessControl ids, not the admin rules |
| MGMT-05 | [`test_MGMT_05_setRoleRevoker`](Management.t.sol#L189) | No self-revoker and no revoker for the admin role; anything else is recorded |
| MGMT-06 | [`test_MGMT_06_revokeRoleNeedsRevokerOrAdmin`](Management.t.sol#L211) | `revokeRole` by a stranger reverts with both accepted roles, the admin may revoke |
| MGMT-07 | [`test_MGMT_07_transferOwnership`](Management.t.sol#L232) | The default admin role follows ownership, which moves in one step |
| MGMT-07b | [`test_MGMT_07b_renounceOwnership`](Management.t.sol#L255) | Renouncing ownership leaves no default admin |
| MGMT-08a | [`test_MGMT_08a_rescueErc20s`](Management.t.sol#L277) | Each ERC20 transfer goes to its target; a zero amount sends the whole balance |
| MGMT-08b | [`test_MGMT_08b_rescueStrandedNative`](Management.t.sol#L298) | `rescueTokens` sends native balance under both native sentinels |
| MGMT-08c | [`test_MGMT_08c_rescueGuards`](Management.t.sol#L318) | Only a rescuer or the default admin may rescue |
| MGMT-09 | [`test_MGMT_09_rescueErc721s`](Management.t.sol#L359) | An NFT sent to the hub by `transferFrom` is recovered by `rescueTokens` |
| MGMT-11 | [`test_MGMT_11_grantRole`](Management.t.sol#L385) | An ordinary role is granted by its admin |
| MGMT-11b | [`test_MGMT_11b_defaultAdminRoleFollowsOwnershipOnly`](Management.t.sol#L397) | The default admin role cannot be granted, revoked or renounced |

## MulticallTest

[`Multicall.t.sol`](Multicall.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| MC-01 | [`test_MC_01_permitAndOrderInOneBatch`](Multicall.t.sol#L52) | A permit and the order that uses the approval share one transaction, with value |
| MC-02 | [`test_MC_02_batchIsBoundedAsAWhole`](Multicall.t.sol#L95) | Each sub-call may spend the value, but the batch as a whole may not spend it twice |
| MC-03 | [`test_MC_03_subCallRevertBubbles`](Multicall.t.sol#L128) | A sub-call's revert arrives at the caller with its arguments intact |
| MC-04 | [`test_MC_04_twoOrdersInOneBatch`](Multicall.t.sol#L155) | Two independent orders in one batch both settle, in the order given |
| MC-07 | [`test_MC_07_gasIsMeasuredPerEntry`](Multicall.t.sol#L189) | Each entry is measured on its own, not given a running total of the batch |
| MC-05 | [`test_MC_05_plainNativeTransferIsRefused`](Multicall.t.sol#L220) | The hub has no `receive`, so a bare transfer cannot strand native in it |
| MC-09 | [`test_MC_09_aFrontRunDelegationDoesNotUnwindTheBatch`](Multicall.t.sol#L238) | A delegation relayed through `forwardCalls` with `allowFailure` set survives being front-run, so the order batched after it still settles |
| MC-06 | [`test_MC_06_approveAMasterKeyAndSpendOnItInOneBatch`](Multicall.t.sol#L306) | One batch approves a session key at an authenticator and then spends on it |
| MC-08 | [`test_MC_08_masterKeyMintsAnEphemeralKeyAndSpendsOnItInOneBatch`](Multicall.t.sol#L386) | One batch mints an ephemeral key from a master key and spends on it |
| MC-FUZZ | [`testFuzz_MC_FUZZ_valueNeedsAnAllPayableBatch`](Multicall.t.sol#L467) | Value survives a batch exactly when every selector in it is payable |

## NoncesTest

[`Nonces.t.sol`](Nonces.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| NONCE-06 | [`test_NONCE_06_approvalAndOrderNumbersDoNotCollide`](Nonces.t.sol#L33) | In the authenticator, the owner's approvals and a session key's orders are separate |
| NONCE-01 / NONCE-FUZZ | [`testFuzz_NONCE_FUZZ_revokeSetsExactlyOneBit`](Nonces.t.sol#L64) | Revoking any nonce sets exactly the bit at its position |
| NONCE-01 | [`test_NONCE_01_bitmapBoundaries`](Nonces.t.sol#L76) | Revoking nonces 0, 255, 256 and the maximum sets one bit each in the right word |
| NONCE-04 | [`test_NONCE_04_doubleRevoke`](Nonces.t.sol#L94) | Revoking twice reverts |
| NONCE-05 | [`test_NONCE_05_hubAndAuthenticatorAreIndependent`](Nonces.t.sol#L105) | The hub and the authenticator keep separate bitmaps |

## OrderPartiesTest

[`OrderParties.t.sol`](OrderParties.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| ORD-02b | [`test_ORD_02b_delegatedExecutionHonoursTheNamedRelayer`](OrderParties.t.sol#L49) | The delegated execution rail refuses a submitter the order did not specify |
| ORD-04 | [`test_ORD_04_delegatedExecutionDrawsOnTheNamedOwner`](OrderParties.t.sol#L104) | An order repointed to another owner who approved the same key reverts |
| ORD-03b | [`test_ORD_03b_delegatedFulfillmentHonoursTheNamedSolver`](OrderParties.t.sol#L136) | The delegated fulfillment rail refuses a submitter the order did not specify |

## SettlementTest

[`Settlement.t.sol`](Settlement.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| SET-01 | [`test_SET_01_transferTokensPayload`](Settlement.t.sol#L89) | The whole `TransferTokens` payload of a relayed order, byte for byte |
| CLIENT-01 | [`testFuzz_CLIENT_01_clientDataIsEmittedAsGiven`](Settlement.t.sol#L128) | The `TransferTokens` of a settled order carries exactly the order's client data |
| CLIENT-02 | [`testFuzz_CLIENT_02_clientDataIsCoveredByTheSignature`](Settlement.t.sol#L144) | The owner's signature covers the order's client data |
| CLIENT-02b | [`test_CLIENT_02b_emptyClientDataIsCoveredByTheSignature`](Settlement.t.sol#L162) | Client data submitted against empty signed client data reverts on every entry |
| SET-02 | [`test_SET_02_nativeTransfersAreTruncatedToValuedCalls`](Settlement.t.sol#L292) | `[v=0, v=1, v=0]` reaches the event as a single-entry native list |
| SET-03 | [`test_SET_03_emptyOrderStillEmits`](Settlement.t.sol#L327) | An order that moves nothing and calls nobody still settles and still emits |
| SET-04 | [`test_SET_04_resultsFollowCallOrder`](Settlement.t.sol#L352) | `results[i]` belongs to `genericCalls[i]`, across two interleaved routers |
| OWN-07 | [`test_OWN_07_eventCoversBothLists`](Settlement.t.sol#L390) | The native transfers of the event span both call lists, solver's route first |
| ROUTER-01 | [`test_ROUTER_01_unwhitelistedRouterIsRejected`](Settlement.t.sol#L440) | A router without the role is refused, and the order rolls back whole |
| ROUTER-02 | [`test_ROUTER_02_guardianRevokeStopsTheNextOrder`](Settlement.t.sol#L468) | A guardian can drop a router, and the very next order stops working |
| ROUTER-03 | [`test_ROUTER_03_eachRouterCalledOnce`](Settlement.t.sol#L503) | Every whitelisted router in the list is called exactly once, with its own data |
| NEST-01 | [`testFuzz_NEST_01_nestedOrdersRestoreEachOwner`](Settlement.t.sol#L542) | Orders nested inside execution router calls settle, and each level sees its owner |
| NEST-02 | [`test_NEST_02_receiverHookSettlesAnOrderInsideAFulfillment`](Settlement.t.sol#L593) | The ERC721 receiver hook of a fulfillment may settle an order |
| NEST-03 | [`testFuzz_NEST_03_anOrderSettlesInsideAnotherOnEveryEntryPoint`](Settlement.t.sol#L661) | An order settles inside another on every entry point, as outer and as nested order |
| NEST-04 | [`test_NEST_04_revokeNonceIsReachableFromInsideAnOrder`](Settlement.t.sol#L736) | A router's `revokeNonce` inside an order spends the nonce in the router's namespace |
| NEST-05 | [`test_NEST_05_nestedOrderCannotSpendTheOuterValue`](Settlement.t.sol#L765) | A nested order cannot spend the outer order's value |

## TwoTiersOrderAuthenticatorTest

[`authenticators/TwoTiersOrderAuthenticator.t.sol`](authenticators/TwoTiersOrderAuthenticator.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| SV-01 | [`test_SV_01_sessionKeyAuthenticatesRelayedOrder`](authenticators/TwoTiersOrderAuthenticator.t.sol#L86) | A relayed order signed by a delegated session key moves tokens and spends its nonce |
| SV-02 | [`test_SV_02_ownerApprovesDirectlyWithoutSignature`](authenticators/TwoTiersOrderAuthenticator.t.sol#L114) | The owner may approve a key at the authenticator directly, with no signature to check |
| SV-02b | [`test_SV_02b_strangerCannotApproveWithoutSignature`](authenticators/TwoTiersOrderAuthenticator.t.sol#L129) | An empty signature from a non-owner reverts with `InvalidUpdateSignature` |
| SV-03 | [`test_SV_03_directApprovalWrongSigner`](authenticators/TwoTiersOrderAuthenticator.t.sol#L140) | A signature from anyone but the owner is rejected |
| SV-04 | [`test_SV_04_directApprovalExpired`](authenticators/TwoTiersOrderAuthenticator.t.sol#L157) | An approval submitted after its deadline reverts with `DeadlinePassed` |
| SV-REV-01 | [`test_SV_REV_01_ownerRevokesDirectly`](authenticators/TwoTiersOrderAuthenticator.t.sol#L172) | The owner revokes directly, and a key that had been authenticating orders stops |
| SV-REV-02 | [`test_SV_REV_02_relayedRevocation`](authenticators/TwoTiersOrderAuthenticator.t.sol#L191) | A relayed revocation carrying the owner's signature spends an authenticator nonce |
| SV-REV-03 | [`test_SV_REV_03_directionCannotBeFlipped`](authenticators/TwoTiersOrderAuthenticator.t.sol#L214) | A signature is refused when submitted under the opposite direction |
| SV-REV-04 | [`test_SV_REV_04_reapprovalAfterRevocation`](authenticators/TwoTiersOrderAuthenticator.t.sol#L253) | Revocation is not permanent: the same key may be approved again afterwards |
| SV-REV-05 | [`test_SV_REV_05_nonCanonicalDirectionIsNarrowed`](authenticators/TwoTiersOrderAuthenticator.t.sol#L277) | A direction word that is neither 0 nor 1 is narrowed to true |
| SV-UPD-01 | [`test_SV_UPD_01_ownerBranchTakesNoSignature`](authenticators/TwoTiersOrderAuthenticator.t.sol#L306) | On the owner's own call a signature is refused, and an empty one approves without spending the nonce |
| SV-UPD-02 | [`test_SV_UPD_02_anUnchangedWriteStillEmits`](authenticators/TwoTiersOrderAuthenticator.t.sol#L338) | An update writing the stored value again still emits its update event |
| SV-05 | [`test_SV_05_onlyTheAuthorizedCallerMayAuthenticate`](authenticators/TwoTiersOrderAuthenticator.t.sol#L373) | Only the authorized caller, here the hub, may ask for an authentication, on either entry point |
| SV-06 | [`test_SV_06_unapprovedKeyRejected`](authenticators/TwoTiersOrderAuthenticator.t.sol#L399) | A key the owner never approved cannot authenticate anything |
| SV-07 | [`test_SV_07_expiryBoundary`](authenticators/TwoTiersOrderAuthenticator.t.sol#L409) | Expiry is inclusive: the expiry second itself still works, the one after it does not |
| SV-08 | [`test_SV_08_wrongSignatureRejected`](authenticators/TwoTiersOrderAuthenticator.t.sol#L424) | An approved key still has to have signed this particular order |
| SV-09 | [`test_SV_09_nonceReplayRejected`](authenticators/TwoTiersOrderAuthenticator.t.sol#L434) | The authenticator's nonce makes an authentication single-use |
| SV-10 | [`test_SV_10_executionSignatureCannotSettleAFulfillment`](authenticators/TwoTiersOrderAuthenticator.t.sol#L458) | A signature over an execution order cannot authenticate a fulfillment |
| SV-10b | [`test_SV_10b_fulfillmentSignatureSettlesAFulfillment`](authenticators/TwoTiersOrderAuthenticator.t.sol#L485) | A signature over the fulfillment shape settles a fulfillment |
| SV-06b | [`test_SV_06b_unapprovedKeyRejectedOnTheFulfillmentPath`](authenticators/TwoTiersOrderAuthenticator.t.sol#L516) | An unapproved key is refused on the fulfillment path as on the execution path |
| SV-07b | [`test_SV_07b_expiryBoundaryOnTheFulfillmentPath`](authenticators/TwoTiersOrderAuthenticator.t.sol#L537) | Expiry is enforced on the fulfillment path, inclusively, as on the execution one |
| SV-11 | [`test_SV_11_changingExpiryBreaksTheApproval`](authenticators/TwoTiersOrderAuthenticator.t.sol#L562) | A key with the approved signer and a later expiry is refused as not approved |
| SV-13 | [`test_SV_13_masterKeyUpdateIsBoundToItsOwner`](authenticators/TwoTiersOrderAuthenticator.t.sol#L577) | A master-key approval signed for one account is refused for another account the same signer controls: two ERC-1271 wallets sharing one signer accept the same signatures, so only the signed `owner` tells them apart. |
| SV-KEY-SECP-02 | [`test_SV_KEY_SECP_02_aContractIsNotASecp256k1Signer`](authenticators/TwoTiersOrderAuthenticator.t.sol#L608) | A Secp256k1 key whose address is a contract verifies nothing, even a signature the contract accepts through ERC-1271, while an ERC1271 key over the same bytes accepts it |
| SV-KEY-1271-01 | [`test_SV_KEY_1271_01_contractSigner`](authenticators/TwoTiersOrderAuthenticator.t.sol#L629) | An ERC1271 key authenticates an order through its contract |
| SV-KEY-1271-02 | [`test_SV_KEY_1271_02_anEoaIsNotAnErc1271Signer`](authenticators/TwoTiersOrderAuthenticator.t.sol#L646) | An ERC1271 key whose account has no code verifies nothing, even that account's own ECDSA signature |
| SV-KEY-7913-01 | [`test_SV_KEY_7913_01_verifierSigner`](authenticators/TwoTiersOrderAuthenticator.t.sol#L669) | An ERC7913 key authenticates an order through its verifier, and a signature over another digest is refused |
| SV-KEY-7913-02 | [`test_SV_KEY_7913_02_aKeylessVerifierIsRefused`](authenticators/TwoTiersOrderAuthenticator.t.sol#L693) | An ERC7913 key with nothing after the verifier's address verifies nothing, even through a verifier that accepts every key, and neither does one whose verifier has no code |
| SV-KEY-P256-01 / -02 | [`test_SV_KEY_P256`](authenticators/TwoTiersOrderAuthenticator.t.sol#L722) | A canonical signature is accepted, its malleable twin is not |
| SV-KEY-WEBAUTHN-01..03 | [`test_SV_KEY_WebAuthn`](authenticators/TwoTiersOrderAuthenticator.t.sol#L753) | A user-verified assertion settles; a presence-only or undecodable one reverts with `InvalidOrderSignature` |
| SV-KEY-RSA-01 / -02 | [`test_SV_KEY_Rsa`](authenticators/TwoTiersOrderAuthenticator.t.sol#L791) | A 2048-bit modulus verifies, a short one is refused |
| SV-KEY-LEN-01 | [`test_SV_KEY_LEN_01_anEmptySecp256k1KeySignsNothing`](authenticators/TwoTiersOrderAuthenticator.t.sol#L836) | An empty Secp256k1 key, approved by mistake, does not sign for anyone |
| SV-KEY-LEN-02 | [`test_SV_KEY_LEN_02_aShortSecp256k1KeyIsRefused`](authenticators/TwoTiersOrderAuthenticator.t.sol#L859) | A Secp256k1 key one byte short is refused, even when the byte after it would complete the signer's address |
| SV-KEY-LEN-03 | [`test_SV_KEY_LEN_03_aShortP256KeyIsRefused`](authenticators/TwoTiersOrderAuthenticator.t.sol#L878) | A P256 key one byte short is refused, even when completed from after it |
| SV-KEY-LEN-04 | [`test_SV_KEY_LEN_04_aShortWebAuthnKeyIsRefused`](authenticators/TwoTiersOrderAuthenticator.t.sol#L897) | A WebAuthn key one byte short is refused, even when completed from after it |
| SV-KEY-LEN-05 | [`test_SV_KEY_LEN_05_anRsaKeyWithoutItsHeadWordsIsRefused`](authenticators/TwoTiersOrderAuthenticator.t.sol#L923) | An RSA key shorter than its two head words is refused |
| SV-CRED-01 | [`test_SV_CRED_01_aRenewedKeyCannotReplayAnOrder`](authenticators/TwoTiersOrderAuthenticator.t.sol#L958) | An order settled under one approval of a key cannot settle again under another |
| SV-CRED-02 | [`test_SV_CRED_02_theNonceIsSharedAcrossTiers`](authenticators/TwoTiersOrderAuthenticator.t.sol#L983) | A nonce spent as a session key reverts with `NonceAlreadyUsed` as a master key |
| SV-CRED-03 | [`test_SV_CRED_03_aRevocationCoversEveryApproval`](authenticators/TwoTiersOrderAuthenticator.t.sol#L1007) | A revocation signed under one approval cancels the nonce under every other |
| SV-CRED-04 | [`test_SV_CRED_04_aNonCanonicalAddressKeyIsRefused`](authenticators/TwoTiersOrderAuthenticator.t.sol#L1030) | A Secp256k1 or ERC1271 key with any of its top 12 bytes set verifies nothing |
| SV-DOMAIN | [`test_SV_DOMAIN_matchesTheWrittenOutDomain`](authenticators/TwoTiersOrderAuthenticator.t.sol#L1044) | The EIP-712 domain returns the written-out name, version, chain and contract |
| SV-FUZZ-UPD | [`testFuzz_SV_FUZZ_UPD_directUpdate`](authenticators/TwoTiersOrderAuthenticator.t.sol#L1063) | Updating a key directly, across every scheme, expiry, nonce and direction |
| SV-FUZZ-VER | [`testFuzz_SV_FUZZ_VER_nonceAndDeadline`](authenticators/TwoTiersOrderAuthenticator.t.sol#L1106) | A fuzzed nonce, deadline and expiry settle and spend the exact nonce bit |
| SV-TIER-01 | [`test_SV_TIER_01_masterKeyApprovesASessionKeyThatSignsAnOrder`](authenticators/TwoTiersOrderAuthenticator.t.sol#L1136) | A master key approves a session key, which then signs an order |
| SV-TIER-01b | [`test_SV_TIER_01b_sessionKeySignsAFulfillment`](authenticators/TwoTiersOrderAuthenticator.t.sol#L1166) | A session key approved by a master key signs a fulfillment that settles |
| SV-TIER-02 | [`test_SV_TIER_02_aSessionKeyCannotApproveAnother`](authenticators/TwoTiersOrderAuthenticator.t.sol#L1183) | A session key cannot approve another, so the chain is two deep and no more |
| SV-TIER-03 | [`test_SV_TIER_03_anUnapprovedKeyCannotApprove`](authenticators/TwoTiersOrderAuthenticator.t.sol#L1208) | An unapproved key approving a session key reverts with `MasterKeyNotApproved` |
| SV-TIER-04 | [`test_SV_TIER_04_revokingTheMasterKeyTakesItsSessionKeys`](authenticators/TwoTiersOrderAuthenticator.t.sol#L1231) | Revoking a master key takes every session key under it |
| SV-TIER-05 | [`test_SV_TIER_05_aSessionKeyMayNotOutliveItsMaster`](authenticators/TwoTiersOrderAuthenticator.t.sol#L1269) | A session key may not outlive the master key approving it |
| SV-TIER-06 | [`test_SV_TIER_06_theMasterKeyMustHaveSignedIt`](authenticators/TwoTiersOrderAuthenticator.t.sol#L1308) | The signature has to be the approving key's, not the approved key's |
| SV-TIER-07 | [`test_SV_TIER_07_theApprovalNamesTheAccountItIsFor`](authenticators/TwoTiersOrderAuthenticator.t.sol#L1328) | A master-key approval signed for one account reverts when submitted for another |
| SV-TIER-08 | [`test_SV_TIER_08_theNonceBurnsInTheMasterKeysNamespace`](authenticators/TwoTiersOrderAuthenticator.t.sol#L1366) | The nonce burns in the master key's namespace, because the master key signed |
| SV-TIER-09 | [`test_SV_TIER_09_aMasterKeyRevokesItsSessionKey`](authenticators/TwoTiersOrderAuthenticator.t.sol#L1401) | A master key revokes a session key it approved, and the key stops signing |
| SV-TIER-10 | [`test_SV_TIER_10_eachApprovalIsUsableOnItsOwnTier`](authenticators/TwoTiersOrderAuthenticator.t.sol#L1440) | A key holding both approvals may be presented under either |
| SV-TIER-10b | [`test_SV_TIER_10b_aMasterKeyMayApproveItself`](authenticators/TwoTiersOrderAuthenticator.t.sol#L1471) | A master key that approves itself still signs, on either tier |
| SV-TIER-11 | [`test_SV_TIER_11_theWrongTierIsRefused`](authenticators/TwoTiersOrderAuthenticator.t.sol#L1495) | A key presented under the tier it does not hold is refused |
| SV-TIER-12 | [`test_SV_TIER_12_anExpiredKeyCannotBeApproved`](authenticators/TwoTiersOrderAuthenticator.t.sol#L1522) | An approval will not record a key that has already expired |
| SV-TIER-12b | [`test_SV_TIER_12b_anExpiredMasterKeyCanApproveNothing`](authenticators/TwoTiersOrderAuthenticator.t.sol#L1552) | An expired master key approves no session key but still revokes one |
| SV-TIER-13 | [`test_SV_TIER_13_aMasterKeyActsOnlyOnKeysItApproved`](authenticators/TwoTiersOrderAuthenticator.t.sol#L1601) | A master key speaks only for the session keys it approved |
| SV-ORD-01 | [`test_SV_ORD_01_expiryComesBeforeTheOwnersSignature`](authenticators/TwoTiersOrderAuthenticator.t.sol#L1662) | An expired key reverts with `DeadlinePassed` before the owner's signature check |
| SV-ORD-02 | [`test_SV_ORD_02_expiryComesBeforeTheMasterKeysApproval`](authenticators/TwoTiersOrderAuthenticator.t.sol#L1683) | An expired key reverts with `DeadlinePassed` before the master key's approval |
| SV-ORD-03 | [`test_SV_ORD_03_expiryComesBeforeTheKeysApproval`](authenticators/TwoTiersOrderAuthenticator.t.sol#L1714) | An expired key reverts with `DeadlinePassed` before its own approval is checked |
| SV-FUZZ-TIER | [`testFuzz_SV_FUZZ_TIER_masterKeyRail`](authenticators/TwoTiersOrderAuthenticator.t.sol#L1730) | A master key sets a session key's approval for any nonce, deadline and expiry |
| SV-NREV-01 | [`test_SV_NREV_01_aKeyRevokesANonceOfItsOwn`](authenticators/TwoTiersOrderAuthenticator.t.sol#L1776) | A key revokes a nonce, and an order it signed at that nonce is refused |
| SV-NREV-02 | [`test_SV_NREV_02_aMasterKeyCancelsAPendingApproval`](authenticators/TwoTiersOrderAuthenticator.t.sol#L1801) | A master key cancels a session key approval it signed and has not seen used |
| SV-NREV-03 | [`test_SV_NREV_03_aSessionKeyRevokesANonceOfItsOwn`](authenticators/TwoTiersOrderAuthenticator.t.sol#L1826) | A session key revokes in its own namespace, not its master key's |
| SV-NREV-04 | [`test_SV_NREV_04_theKeyMustHaveSignedThisNonce`](authenticators/TwoTiersOrderAuthenticator.t.sol#L1852) | The revocation must be signed by the key, for the nonce and deadline it specifies |
| SV-NREV-05 | [`test_SV_NREV_05_aRevocationCannotBeReplayed`](authenticators/TwoTiersOrderAuthenticator.t.sol#L1881) | A revocation spends its nonce, so it cannot be submitted twice |
| SV-NREV-06 | [`test_SV_NREV_06_neitherApprovalNorExpiryIsRequired`](authenticators/TwoTiersOrderAuthenticator.t.sol#L1898) | A key revokes regardless of its approval or expiry |
| SV-NREV-07 | [`test_SV_NREV_07_aP256KeyRevokes`](authenticators/TwoTiersOrderAuthenticator.t.sol#L1925) | A passkey revokes: the signature is checked by the key's own scheme |
| SV-NREV-08 | [`test_SV_NREV_08_deadlineBoundary`](authenticators/TwoTiersOrderAuthenticator.t.sol#L1960) | The deadline is inclusive, and a revocation submitted after it is refused |
| SV-FUZZ-NREV | [`testFuzz_SV_FUZZ_NREV_revokeNonce`](authenticators/TwoTiersOrderAuthenticator.t.sol#L1982) | A revocation spends exactly the nonce it specifies, in the key's namespace |
| SV-OWN-01 | [`test_SV_OWN_01_ownerSignatureAuthenticatesAnExecution`](authenticators/TwoTiersOrderAuthenticator.t.sol#L2004) | The owner's signature authenticates an execution relayed through the hub |
| SV-OWN-02 | [`test_SV_OWN_02_ownerSignatureAuthenticatesAFulfillment`](authenticators/TwoTiersOrderAuthenticator.t.sol#L2026) | The owner's signature authenticates a relayed fulfillment |
| SV-OWN-03 | [`test_SV_OWN_03_erc1271OwnerAuthenticatesAndMayRefuse`](authenticators/TwoTiersOrderAuthenticator.t.sol#L2050) | An ERC-1271 owner authenticates through its wallet, and the wallet may refuse |
| SV-OWN-04 | [`test_SV_OWN_04_anotherAccountsSignatureIsRefused`](authenticators/TwoTiersOrderAuthenticator.t.sol#L2082) | A signature by another account is refused, an approved key's included |
| SV-OWN-05 | [`test_SV_OWN_05_replayIsRefused`](authenticators/TwoTiersOrderAuthenticator.t.sol#L2108) | An owner-signed order cannot be replayed, nor settled again as a fulfillment |
| SV-OWN-06 | [`test_SV_OWN_06_ownerNamespaceIsSharedWithMasterKeyUpdates`](authenticators/TwoTiersOrderAuthenticator.t.sol#L2136) | The owner's namespace is the one `MasterKeyUpdate` signatures spend |
| SV-OWN-06b | [`test_SV_OWN_06b_ownerRevocationCancelsAnOutstandingOrder`](authenticators/TwoTiersOrderAuthenticator.t.sol#L2169) | The owner revokes the nonce of an outstanding owner-signed order, and it is refused |
| SV-OWN-06c | [`test_SV_OWN_06c_aKeyNonceDoesNotBlockTheOwnersRail`](authenticators/TwoTiersOrderAuthenticator.t.sol#L2187) | A nonce spent by a key leaves the same nonce usable on the owner's rail |
| SV-OWN-07 | [`test_SV_OWN_07_signatureIsBoundToTheAuthenticatorsDomain`](authenticators/TwoTiersOrderAuthenticator.t.sol#L2208) | The signature is bound to the authenticator's domain |
| SV-OWN-08 | [`test_SV_OWN_08_ownerRailConsultsNoKeys`](authenticators/TwoTiersOrderAuthenticator.t.sol#L2235) | The owner's rail consults no key, and the key rail is unchanged |
| SV-OWN-09 | [`test_SV_OWN_09_firstWord0x20IsTheOwnersRail`](authenticators/TwoTiersOrderAuthenticator.t.sol#L2267) | A first word of `0x20` takes the owner's rail, and the signature needs no padding |
| SV-OWN-09b | [`test_SV_OWN_09b_firstWord0x00ReadsAnEmptySignature`](authenticators/TwoTiersOrderAuthenticator.t.sol#L2292) | A first word of `0x00` is `<= 0x20`, so it takes the owner's rail and reads no signature |
| SV-OWN-09c | [`test_SV_OWN_09c_aTruncatedPayloadIsASliceError`](authenticators/TwoTiersOrderAuthenticator.t.sol#L2310) | A payload that is too short for its length word reverts with the decoder's slice error |
| SV-OWN-09d | [`test_SV_OWN_09d_firstWordAbove0x20IsTheKeyRail`](authenticators/TwoTiersOrderAuthenticator.t.sol#L2334) | A first word above `0x20` takes the key rail, wherever the key is placed |
| SV-OWN-FUZZ | [`testFuzz_SV_OWN_FUZZ_ownerSignedOrder`](authenticators/TwoTiersOrderAuthenticator.t.sol#L2360) | An owner-signed order settles for any owner, nonce, deadline and entry point |

## AuthenticatorEip712Test

[`authenticators/types/AuthenticatorEip712.t.sol`](authenticators/types/AuthenticatorEip712.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| T712-09 | [`test_T712_09_authKeyStructHash`](authenticators/types/AuthenticatorEip712.t.sol#L25) | Both hashers of an {AuthKey} return the independent struct hash |
| T712-10 | [`test_T712_10_masterKeyUpdateStructHash`](authenticators/types/AuthenticatorEip712.t.sol#L38) | The {MasterKeyUpdate} hash matches the independent hash and moves with its inputs |
| T712-11 | [`test_T712_11_sessionKeyUpdateStructHash`](authenticators/types/AuthenticatorEip712.t.sol#L73) | The {SessionKeyUpdate} hash matches the independent hash and moves with its inputs |
| T712-12 | [`test_T712_12_nonceRevocationStructHash`](authenticators/types/AuthenticatorEip712.t.sol#L113) | The {NonceRevocation} hash matches the independent hash and moves with its inputs |

## Eip712Test

[`types/Eip712.t.sol`](types/Eip712.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| T712-08b | [`test_T712_08b_authDelegationStructHash`](types/Eip712.t.sol#L43) | The {AuthDelegation} hash matches the independent hash and moves with its inputs |
| T712-17 | [`test_T712_17_permit2TypeStringsSortTheirReferencedTypes`](types/Eip712.t.sol#L82) | Both Permit2 witness strings list their referenced types in sorted order |
| T712 | [`test_T712_executionWitnessStructHash`](types/Eip712.t.sol#L112) | The execution witness hash matches the independent encoding with empty extra and client data |
| T712 | [`test_T712_fulfillmentWitnessStructHash`](types/Eip712.t.sol#L125) | The fulfillment witness hash matches the independent encoding with empty extra and client data |
| T712 | [`test_T712_executionWitnessExtraDataStructHash`](types/Eip712.t.sol#L141) | Both execution witness hashers match the independent encoding, and extra data moves the hash |
| T712 | [`test_T712_fulfillmentWitnessExtraDataStructHash`](types/Eip712.t.sol#L160) | Both fulfillment witness hashers match the independent encoding, and extra data moves the hash |
| T712 | [`test_T712_ordersExtraDataStructHash`](types/Eip712.t.sol#L185) | Both order hashers match {SchemaHash} with extra data, and clearing it moves the hash |
| T712 | [`test_T712_witnessClientDataStructHash`](types/Eip712.t.sol#L214) | Both hashers of each witness match the independent encoding, and client data moves the hash |
| T712 | [`test_T712_ordersClientDataStructHash`](types/Eip712.t.sol#L262) | Both order hashers match {SchemaHash} with client data, and clearing it moves the hash |
| T712 | [`test_T712_executionOrderStructHash`](types/Eip712.t.sol#L288) | The memory and calldata hashers of the execution order match {SchemaHash} |
| T712 | [`test_T712_fulfillmentOrderStructHash`](types/Eip712.t.sol#L297) | The memory and calldata hashers of the fulfillment order match {SchemaHash} |
| T712 | [`test_T712_fulfillmentSolutionStructHash`](types/Eip712.t.sol#L306) | Both solution hashers match {SchemaHash}, and a changed nonce moves the hash |
| T712 | [`test_T712_solutionApprovalStructHash`](types/Eip712.t.sol#L327) | Both approval hashers match the independent encoding, and the order, targets and nonce move it |
| T712 | [`test_T712_erc20AllowanceStructHash`](types/Eip712.t.sol#L360) | Both hashers of each sample {ERC20Allowance} match {SchemaHash} |
| T712 | [`test_T712_erc721ApprovalStructHash`](types/Eip712.t.sol#L370) | Both hashers of a sample {ERC721Approval} match {SchemaHash} |
| T712-ARRAY | [`test_T712_ARRAY_addressArrayEncoding`](types/Eip712.t.sol#L383) | The packed encoding of an address array equals the per-element encoding |
| T712-ARRAY | [`testFuzz_T712_ARRAY_efficientHashLibExt`](types/Eip712.t.sol#L401) | Both address array hashers equal the hash of the words encoded one by one |
| T712-DIFF | [`testFuzz_T712_DIFF_genericCall`](types/Eip712.t.sol#L417) | The calldata and memory hashers of {GenericCall} return the same hash |
| T712-DIFF | [`testFuzz_T712_DIFF_erc20Transfer`](types/Eip712.t.sol#L422) | The calldata and memory hashers of {ERC20Transfer} return the same hash |
| T712-DIFF | [`testFuzz_T712_DIFF_erc721Transfer`](types/Eip712.t.sol#L427) | The calldata and memory hashers of {ERC721Transfer} return the same hash |
| T712-DIFF | [`testFuzz_T712_DIFF_erc20Allowance`](types/Eip712.t.sol#L432) | The calldata and memory hashers of {ERC20Allowance} return the same hash |
| T712-DIFF | [`testFuzz_T712_DIFF_erc721Approval`](types/Eip712.t.sol#L437) | The calldata and memory hashers of {ERC721Approval} return the same hash |
| T712-DIFF | [`testFuzz_T712_DIFF_validationParams`](types/Eip712.t.sol#L442) | The calldata and memory hashers of {ValidationParams} return the same hash |
| T712-DIFF | [`testFuzz_T712_DIFF_executionOrder`](types/Eip712.t.sol#L447) | The calldata and memory hashers of {ExecutionOrder} return the same hash |
| T712-DIFF | [`testFuzz_T712_DIFF_fulfillmentOrder`](types/Eip712.t.sol#L452) | The calldata and memory hashers of {FulfillmentOrder} return the same hash |

## SchemaAuditTest

[`types/SchemaAudit.t.sol`](types/SchemaAudit.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| T712-SCHEMA | [`test_T712_SCHEMA_typehashesMatchTheirStructs`](types/SchemaAudit.t.sol#L42) | Each typehash equals the hash of the schema derived from its struct |
| T712-SCHEMA-PERMIT2 | [`test_T712_SCHEMA_PERMIT2_witnessTypeStringsMatchTheirStructs`](types/SchemaAudit.t.sol#L133) | The Permit2 stub plus each witness type string equals its struct schema |
| T712-SCHEMA | [`test_T712_SCHEMA_clientDataTypeStringsWrittenOut`](types/SchemaAudit.t.sol#L161) | The four typehashes carrying client data match their written-out strings |
