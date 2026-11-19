# Tests

The suite has 176 tests in 17 contracts. Each row links to a test and gives the
first sentence of its documentation, or of the section heading above it. A test with neither
takes its ID and description from its name.

## GuardsTest

[`admin/Guards.t.sol`](admin/Guards.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| GUARD-01 | [`test_GUARD_01_pauseUnpauseRoundTrip`](admin/Guards.t.sol#L83) | Pause and unpause set `paused()` and emit `Paused` and `Unpaused` |
| GUARD-02 | [`test_GUARD_02_pauseClosesOrdersNotDelegation`](admin/Guards.t.sol#L102) | A pause closes both order entry points but leaves delegation open |
| GUARD-03 | [`test_GUARD_03_pauseRolesAreEnforced`](admin/Guards.t.sol#L133) | Pausing needs the guardian or the admin, unpausing needs the admin alone |
| GUARD-04 | [`test_GUARD_04_expirationBoundaryOnTheOrderEntryPoints`](admin/Guards.t.sol#L167) | The expiration block itself still settles; the one before it does not |
| GUARD-05 | [`test_GUARD_05_pauseTakesPrecedenceOverTheExpiration`](admin/Guards.t.sol#L185) | When both guards would fire, the pause wins, because it is the outer modifier |
| GUARD-06 | [`test_GUARD_06_nativeSpendBoundary`](admin/Guards.t.sol#L208) | A solver call may spend up to the value the order was sent with, and not one wei more |
| GATE-01 | [`test_GATE_01_permit2EntryPointCarriesTheThreeModifiers`](admin/Guards.t.sol#L224) | The Permit2 entry point is pausable, expiration-checked and native-guarded |
| GATE-02 | [`test_GATE_02_theUnwatchedModifierApplications`](admin/Guards.t.sol#L289) | An undelegated authenticator and overspent native are refused on the delegated entry point |

## ManagementTest

[`admin/Management.t.sol`](admin/Management.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| DOM-01 | [`test_DOM_01_bothDomainsAreChainScoped`](admin/Management.t.sol#L56) | The hub and the authenticator sign under domains of their own, each scoped to the chain |
| MGMT-01 | [`test_MGMT_01_constructorWiring`](admin/Management.t.sol#L87) | The constructor grants the initial roles, sets the owner and emits one event |
| MGMT-02 | [`test_MGMT_02_eip712Domain`](admin/Management.t.sol#L128) | `eip712Domain()` returns the hub's name, version, chain id and address, no salt |
| MGMT-03 | [`test_MGMT_03_supportsInterface`](admin/Management.t.sol#L152) | `supportsInterface` accepts the ERC-165 and AccessControl ids, not the admin rules |
| MGMT-05 | [`test_MGMT_05_setRoleRevoker`](admin/Management.t.sol#L188) | No self-revoker and no revoker for the admin role; anything else is recorded |
| MGMT-06 | [`test_MGMT_06_revokeRoleNeedsRevokerOrAdmin`](admin/Management.t.sol#L210) | `revokeRole` by a stranger reverts with both accepted roles, the admin may revoke |
| MGMT-07 | [`test_MGMT_07_transferOwnership`](admin/Management.t.sol#L231) | The default admin role follows ownership, which moves in one step |
| MGMT-07b | [`test_MGMT_07b_renounceOwnership`](admin/Management.t.sol#L254) | Renouncing ownership leaves no default admin |
| MGMT-08a | [`test_MGMT_08a_rescueErc20s`](admin/Management.t.sol#L276) | Each ERC20 transfer goes to its target; a zero amount sends the whole balance |
| MGMT-08b | [`test_MGMT_08b_rescueStrandedNative`](admin/Management.t.sol#L297) | `rescueTokens` sends native balance under both native sentinels |
| MGMT-08c | [`test_MGMT_08c_rescueGuards`](admin/Management.t.sol#L317) | Only a rescuer or the default admin may rescue |
| MGMT-09 | [`test_MGMT_09_rescueErc721s`](admin/Management.t.sol#L358) | An NFT sent to the hub by `transferFrom` is recovered by `rescueTokens` |
| MGMT-11 | [`test_MGMT_11_grantRole`](admin/Management.t.sol#L384) | An ordinary role is granted by its admin |
| MGMT-11b | [`test_MGMT_11b_defaultAdminRoleFollowsOwnershipOnly`](admin/Management.t.sol#L396) | The default admin role cannot be granted, revoked or renounced |

## ForwarderTest

[`batching/Forwarder.t.sol`](batching/Forwarder.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| PF-01 | [`test_PF_01_eip2612PermitForwarded`](batching/Forwarder.t.sol#L120) | A relayed EIP-2612 permit sets the token allowance and spends the permit nonce |
| PF-02 | [`test_PF_02_daiStylePermitForwarded`](batching/Forwarder.t.sol#L143) | A relayed DAI-style permit sets the maximum allowance and spends the permit nonce |
| PF-03 | [`test_PF_03_erc721V3PermitForwarded`](batching/Forwarder.t.sol#L166) | A relayed Uniswap v3 ERC-721 permit with a v/r/s signature sets the approval |
| PF-04 | [`test_PF_04_erc721V4PermitForwarded`](batching/Forwarder.t.sol#L190) | A relayed Uniswap v4 ERC-721 permit with an unordered nonce sets the approval |
| PF-05 | [`test_PF_05_permit2BatchPermitForwarded`](batching/Forwarder.t.sol#L208) | A relayed Permit2 batch `permit` sets the allowance, expiration and nonce |
| PF-06 | [`test_PF_06_relayedCallWithoutAuthorityIsRefusedByItsTarget`](batching/Forwarder.t.sol#L243) | A relayed call that proves no authority is refused by its target |
| PF-06b | [`test_PF_06b_failingTransferUnwindsTheBatch`](batching/Forwarder.t.sol#L288) | A relayed call that fails on its target unwinds the entries that already ran |
| PF-08 | [`test_PF_08_failingCallRevertsWithMulticall3ErrorWhenNotAllowed`](batching/Forwarder.t.sol#L313) | With `allowFailure` false, a failing call reverts the batch with Multicall3's error |
| PF-09 | [`test_PF_09_failingCallIsCarriedPastWhenAllowed`](batching/Forwarder.t.sol#L328) | With `allowFailure` true, a failing call is recorded and the batch continues |
| PF-FUZZ | [`testFuzz_PF_FUZZ_allowFailureBits`](batching/Forwarder.t.sol#L362) | A batch settles exactly when every entry that fails has `allowFailure` true |
| FWD-13 | [`test_FWD_13_updateAuthenticationIsRelayedAndApprovesTheSigner`](batching/Forwarder.t.sol#L445) | A relayed `updateAuthentication` approves a signer, on the authenticator's nonce |
| FWD-14 | [`test_FWD_14_emptySignatureIsRefusedEvenFromTheOwner`](batching/Forwarder.t.sol#L485) | A relayed `updateAuthentication` with an empty signature is refused for an owner |
| FWD-21 | [`test_FWD_21_updateDelegationIsRelayed`](batching/Forwarder.t.sol#L522) | A relayed `updateDelegation` delegates on the owner's signature and the hub's nonce |
| FWD-22 | [`test_FWD_22_relayedDelegationNeedsTheOwnersSignature`](batching/Forwarder.t.sol#L548) | A relayed `updateDelegation` needs the owner's signature even when the owner relays it |
| FWD-16 | [`test_FWD_16_authenticatorRefusesMulticall3OnHubOnlyCalls`](batching/Forwarder.t.sol#L574) | Multicall3 relays `initAuthentication` and `authenticate`, and the authenticator refuses it as the caller because it is not the hub |
| FWD-17 | [`test_FWD_17_permit2SinglePermitForwarded`](batching/Forwarder.t.sol#L628) | A relayed Permit2 single `permit` sets the allowance |
| FWD-18 | [`test_FWD_18_emptyBatchIsANoOp`](batching/Forwarder.t.sol#L658) | An empty batch is a legal no-op rather than an error |
| FWD-PAUSE-01 | [`test_FWD_PAUSE_01_forwardStillWorksWhilePaused`](batching/Forwarder.t.sol#L675) | A pause does not close `forwardCalls` |
| FWD-VALUE-01 | [`test_FWD_VALUE_01_valueSentWithForwardIsStranded`](batching/Forwarder.t.sol#L699) | Value sent with `forwardCalls` remains in the hub, not Multicall3 |
| FWD-REENTRY-01 | [`test_FWD_REENTRY_01_relayedPermitMayReenterTheHub`](batching/Forwarder.t.sol#L727) | A relayed permit may reenter the hub and start an order |
| FWD-23 | [`test_FWD_23_multicall3RelaysWhenCalledDirectly`](batching/Forwarder.t.sol#L770) | Multicall3 relays a permit and a failing call alike when called directly |
| FWD-24 | [`test_FWD_24_hubForwardsThroughMulticall3`](batching/Forwarder.t.sol#L803) | `hub.forwardCalls` calls the target with Multicall3 as the caller |

## MulticallTest

[`batching/Multicall.t.sol`](batching/Multicall.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| MC-01 | [`test_MC_01_permitAndOrderInOneBatch`](batching/Multicall.t.sol#L53) | A permit and the order that uses the approval share one transaction, with value |
| MC-02 | [`test_MC_02_batchIsBoundedAsAWhole`](batching/Multicall.t.sol#L94) | Each sub-call may spend the value, but the batch as a whole may not spend it twice |
| MC-03 | [`test_MC_03_subCallRevertBubbles`](batching/Multicall.t.sol#L118) | A sub-call's revert arrives at the caller with its arguments intact |
| MC-04 | [`test_MC_04_twoOrdersInOneBatch`](batching/Multicall.t.sol#L137) | Two independent orders in one batch both settle, in the order given |
| MC-07 | [`test_MC_07_gasIsMeasuredPerEntry`](batching/Multicall.t.sol#L171) | Each entry is measured on its own, not given a running total of the batch |
| MC-05 | [`test_MC_05_plainNativeTransferIsRefused`](batching/Multicall.t.sol#L202) | The hub has no `receive`, so a bare transfer cannot strand native in it |
| MC-09 | [`test_MC_09_aFrontRunDelegationDoesNotUnwindTheBatch`](batching/Multicall.t.sol#L220) | A delegation relayed through `forwardCalls` with `allowFailure` set survives being front-run, so the order batched after it still settles |
| MC-06 | [`test_MC_06_approveASignerAndSpendOnItInOneBatch`](batching/Multicall.t.sol#L300) | One batch approves a signer at an authenticator and then spends on it |
| MC-FUZZ | [`testFuzz_MC_FUZZ_valueNeedsAnAllPayableBatch`](batching/Multicall.t.sol#L387) | Value survives a batch exactly when every selector in it is payable |

## DelegationTest

[`delegation/Delegation.t.sol`](delegation/Delegation.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| DEL-01 | [`test_DEL_01_selfDelegationSpendsNoNonce`](delegation/Delegation.t.sol#L76) | The owner delegates for themselves: no nonce is spent and the authenticator is trusted |
| DEL-02 | [`test_DEL_02_relayedDelegationConsumesNonce`](delegation/Delegation.t.sol#L100) | A third party may submit the delegation when it carries the owner's signature |
| DEL-03 | [`test_DEL_03_tamperedDelegationRejected`](delegation/Delegation.t.sol#L129) | Changing any signed field invalidates the delegation |
| DEL-04 | [`test_DEL_04_erc1271Owner`](delegation/Delegation.t.sol#L143) | An ERC-1271 owner's signature delegates, and a wrong magic value reverts |
| DEL-05 | [`test_DEL_05_expiredDelegation`](delegation/Delegation.t.sol#L184) | A relayed delegation past its deadline reverts with `DeadlinePassed` |
| DEL-06 | [`test_DEL_06_withdrawDelegation`](delegation/Delegation.t.sol#L202) | Withdrawing stops the hub accepting that authenticator, while the signer stays approved |
| DEL-08 | [`test_DEL_08_withdrawalDoesNotCallTheAuthenticator`](delegation/Delegation.t.sol#L227) | A withdrawal never reaches the authenticator, so one that reverts cannot trap the owner |
| DEL-09 | [`test_DEL_09_relayedWithdrawal`](delegation/Delegation.t.sol#L251) | A relayed withdrawal needs the owner's signature over the same direction |
| DEL-12 | [`test_DEL_12_initAuthenticationIsHubOnly`](delegation/Delegation.t.sol#L289) | `initAuthentication` answers the hub alone, and being the owner is not a way in |
| DEL-13 | [`test_DEL_13_emptyPayloadNeverCallsInitAuthentication`](delegation/Delegation.t.sol#L318) | An empty payload skips the authenticator, even on the delegate direction |
| DEL-14 | [`test_DEL_14_nonEmptyPayloadDoesCallInitAuthentication`](delegation/Delegation.t.sol#L345) | The guard reads the payload's length, not the direction alone |
| DEL-15 | [`test_DEL_15_withdrawalSkipsTheAuthenticatorWhateverThePayload`](delegation/Delegation.t.sol#L384) | A withdrawal skips the authenticator whatever the payload says |
| DEL-16 | [`test_DEL_16_delegationIsBoundToItsOwner`](delegation/Delegation.t.sol#L408) | A delegation signed for one account is refused for another account of one signer |
| DEL-17 | [`test_DEL_17_ownerCallTakesNoSignature`](delegation/Delegation.t.sol#L437) | A signature on the owner's own delegation call reverts with `UnexpectedSignature` |
| DEL-FUZZ | [`testFuzz_DEL_FUZZ_relayedDelegation`](delegation/Delegation.t.sol#L453) | A relayed delegation sets the delegation and exactly its nonce bit |

## NoncesTest

[`delegation/Nonces.t.sol`](delegation/Nonces.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| NONCE-01 / NONCE-FUZZ | [`testFuzz_NONCE_FUZZ_revokeSetsExactlyOneBit`](delegation/Nonces.t.sol#L20) | Revoking any nonce sets exactly the bit at its position |
| NONCE-01 | [`test_NONCE_01_bitmapBoundaries`](delegation/Nonces.t.sol#L32) | Revoking nonces 0, 255, 256 and the maximum sets one bit each in the right word |
| NONCE-04 | [`test_NONCE_04_doubleRevoke`](delegation/Nonces.t.sol#L50) | Revoking twice reverts |
| NONCE-05 | [`test_NONCE_05_hubAndAuthenticatorAreIndependent`](delegation/Nonces.t.sol#L61) | The hub and the authenticator keep separate bitmaps |

## AuthenticationTest

[`settlement/Authentication.t.sol`](settlement/Authentication.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| AUTH-01b | [`test_AUTH_01b_permit2SelfSubmittedChecksNoApproval`](settlement/Authentication.t.sol#L63) | The owner submits their own order, so the permit witnesses nothing and no approval is checked |
| AUTH-04 | [`test_AUTH_04_witnessPinsTheExclusiveCaller`](settlement/Authentication.t.sol#L106) | The exclusive caller the owner specified is part of what the witness binds |
| AUTH-07 | [`test_AUTH_07_permit2Witness`](settlement/Authentication.t.sol#L133) | A solver settles a witnessed order under the sentinel approver with its own solution |
| AUTH-07b | [`test_AUTH_07b_solutionApproverIsBoundByTheWitness`](settlement/Authentication.t.sol#L162) | The solver cannot swap in a different approver than the one the owner signed |
| ORD-03 | [`test_ORD_03_exclusiveCallerPinningAndTheOpenSentinel`](settlement/Authentication.t.sol#L202) | Only the named exclusive caller may submit a Permit2 settlement, the sentinel admits anyone |
| AUTH-06 | [`test_AUTH_06_ownerCallerNeedsNoAuthentication`](settlement/Authentication.t.sol#L257) | An owner acting for themselves needs no authenticator at all |
| AUTH-06b | [`test_AUTH_06b_ownerCallerViaPermit2Allowance`](settlement/Authentication.t.sol#L287) | An owner's own call without an authenticator draws on the Permit2 allowance |
| AUTH-08 | [`test_AUTH_08_undelegatedAuthenticatorRefused`](settlement/Authentication.t.sol#L314) | An authenticator the owner never delegated is refused before it is ever called |
| ORD-01 | [`test_ORD_01_theAssetSourceIsTheSubmittersArgument`](settlement/Authentication.t.sol#L347) | The asset source is the submitter's parameter, and the same order settles either way |
| ORD-01b | [`test_ORD_01b_thePermit2SignatureEntryPointConsultsNoAllowance`](settlement/Authentication.t.sol#L392) | The Permit2 signature entry point takes no source argument and claims neither allowance |
| AUTH-13 | [`test_AUTH_13_malformedAuthenticationDataRejected`](settlement/Authentication.t.sol#L423) | Authentication data too short to settle is rejected, on whichever gate it reaches |
| AUTH-18 | [`test_AUTH_18_authenticatorReceivesTheOrderAndTheSolution`](settlement/Authentication.t.sol#L469) | The authenticator receives the order, its hash, the solution and the data, unaltered |
| ORD-04 | [`test_ORD_04_delegatedEntryPointDrawsOnTheNamedOwner`](settlement/Authentication.t.sol#L513) | An order repointed to another owner who approved the same signer reverts |
| ORD-03b | [`test_ORD_03b_delegatedEntryPointHonoursTheExclusiveCaller`](settlement/Authentication.t.sol#L560) | The delegated entry point refuses a submitter the order did not specify |

## CalldataHygieneTest

[`settlement/CalldataHygiene.t.sol`](settlement/CalldataHygiene.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| DIRTY-01 | [`test_DIRTY_01_delegatedOwnerSubmitted`](settlement/CalldataHygiene.t.sol#L24) | A dirty token address word is refused on the delegated entry point, owner submitted |
| DIRTY-02 | [`test_DIRTY_02_permit2Witnessed`](settlement/CalldataHygiene.t.sol#L40) | A dirty token address word is refused on the Permit2 entry point, witnessed |
| DIRTY-03 | [`test_DIRTY_03_delegatedAuthenticated`](settlement/CalldataHygiene.t.sol#L53) | A dirty token address word is refused on the delegated entry point, authenticated |
| DIRTY-04 | [`test_DIRTY_04_permit2OwnerSubmitted`](settlement/CalldataHygiene.t.sol#L74) | A dirty token address word is refused on the Permit2 entry point, owner submitted |

## CallsTest

[`settlement/Calls.t.sol`](settlement/Calls.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| OWN-01 | [`test_OWN_01_ownerCallsRunAfterSolverCalls`](settlement/Calls.t.sol#L55) | The owner calls run after the solver calls, not merely alongside them |
| OWN-02 | [`test_OWN_02_witnessBindsOwnerCalls`](settlement/Calls.t.sol#L90) | The Permit2 witness pins the owner calls the owner signed |
| OWN-03 | [`test_OWN_03_authenticationBindsOwnerCalls`](settlement/Calls.t.sol#L128) | Owner calls swapped after the authenticator's signature are refused on the delegated entry point |
| OWN-04 | [`test_OWN_04_ownerCallCalleeMustBeWhitelisted`](settlement/Calls.t.sol#L173) | An owner call to a callee without the role reverts, as a solver call does |
| OWN-05 | [`test_OWN_05_emptyOwnerCallsRunNoExtraCall`](settlement/Calls.t.sol#L209) | Empty owner calls run no extra call and return no extra result |
| OWN-06 | [`test_OWN_06_resultsAreSolverThenOwner`](settlement/Calls.t.sol#L231) | `results` is the solver calls then the owner calls, one entry per call |
| OWN-07 | [`test_OWN_07_eventCoversBothLists`](settlement/Calls.t.sol#L282) | The native transfers of the event span both call lists, solver's route first |
| CALLEE-01 | [`test_CALLEE_01_unwhitelistedCalleeIsRejected`](settlement/Calls.t.sol#L332) | A callee without the role is refused, and the order rolls back whole |
| CALLEE-02 | [`test_CALLEE_02_guardianRevokeStopsTheNextOrder`](settlement/Calls.t.sol#L368) | A guardian can drop a callee, and the very next order stops working |
| CALLEE-03 | [`test_CALLEE_03_eachCalleeCalledOnce`](settlement/Calls.t.sol#L398) | Every whitelisted callee in the list is called exactly once, with its own data |
| CALLEE-04 | [`test_CALLEE_04_callKindsFillTheirOwnArguments`](settlement/Calls.t.sol#L429) | A solver call passes empty owner data and its data as solver data; an owner call passes its data as owner data with the solution's solver data |

## EventsTest

[`settlement/Events.t.sol`](settlement/Events.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| SET-01 | [`test_SET_01_transferTokensPayload`](settlement/Events.t.sol#L64) | The whole `TransferTokens` payload of a relayed order, byte for byte |
| SET-03 | [`test_SET_03_emptyOrderStillEmits`](settlement/Events.t.sol#L98) | An order that moves nothing and calls nobody still settles and still emits |
| CLIENT-01 | [`testFuzz_CLIENT_01_clientDataIsEmittedAsGiven`](settlement/Events.t.sol#L130) | The `TransferTokens` of a settled order carries exactly the order's client data |
| CLIENT-02 | [`testFuzz_CLIENT_02_clientDataIsCoveredByTheSignature`](settlement/Events.t.sol#L146) | The owner's signature covers the order's client data |
| CLIENT-02b | [`test_CLIENT_02b_emptyClientDataIsCoveredByTheSignature`](settlement/Events.t.sol#L164) | Client data submitted against empty signed client data reverts on every entry |
| EVT-01 | [`test_EVT_01_eventPairsTransfersWithTargets`](settlement/Events.t.sol#L259) | `TransferTokens` lists the transfers that happened, each with the solution's target |

## HooksTest

[`settlement/Hooks.t.sol`](settlement/Hooks.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| HOOK-01 | [`test_HOOK_01_hooksRunAroundTheSettlementOnTheDelegatedEntryPoint`](settlement/Hooks.t.sol#L46) | The hooks bracket the whole order on the delegated entry point, each reading its own entry |
| HOOK-02 | [`test_HOOK_02_hooksRunAroundThePermit2EntryPoint`](settlement/Hooks.t.sol#L114) | The hooks bracket the Permit2 entry point, the after hook following the owner calls |
| HOOK-03 | [`test_HOOK_03_aRevertingHookRevertsTheOrder`](settlement/Hooks.t.sol#L162) | A reverting hook reverts the order |
| HOOK-04 | [`test_HOOK_04_noHooks`](settlement/Hooks.t.sol#L199) | An order with no hooks settles and runs its callee call |
| HOOK-05 | [`test_HOOK_05_flagsSelectTheCalls`](settlement/Hooks.t.sol#L217) | The flags select which of the two calls a hook receives |
| HOOK-06 | [`testFuzz_HOOK_06_flagsSelectTheCalls`](settlement/Hooks.t.sol#L255) | Only the two lowest bits of the flags select calls |
| HOOK-07 | [`test_HOOK_07_hooksReceiveTheOrderTheSolutionAndTheirIndex`](settlement/Hooks.t.sol#L282) | A hook receives the order, its hash, the solution and the index of its entry |
| HOOK-08 | [`test_HOOK_08_hooksRunWhileMsgSenderIsTheOwner`](settlement/Hooks.t.sol#L324) | The hooks run while `msgSender` returns the owner |
| HOOK-09 | [`test_HOOK_09_signaturesBindTheHooks`](settlement/Hooks.t.sol#L349) | Both signatures bind the hooks |
| HOOK-10 | [`test_HOOK_10_theAfterHookSeesTheOwnerCalls`](settlement/Hooks.t.sol#L413) | The after hook observes the effects of the owner calls |

## NestingTest

[`settlement/Nesting.t.sol`](settlement/Nesting.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| NEST-01 | [`testFuzz_NEST_01_nestedOrdersRestoreEachOwner`](settlement/Nesting.t.sol#L70) | Orders nested inside solver calls settle, and each level sees its owner |
| NEST-02 | [`test_NEST_02_receiverHookSettlesAnOrderInsideAnOrder`](settlement/Nesting.t.sol#L123) | The ERC721 receiver hook of an order may settle an order |
| NEST-03 | [`testFuzz_NEST_03_anOrderSettlesInsideAnotherOnEveryEntryPoint`](settlement/Nesting.t.sol#L185) | An order settles inside another on both entry points, as outer and as nested order |
| NEST-04 | [`test_NEST_04_revokeNonceIsReachableFromInsideAnOrder`](settlement/Nesting.t.sol#L247) | A callee's `revokeNonce` inside an order spends the nonce in the callee's namespace |
| NEST-05 | [`test_NEST_05_nestedOrderCannotSpendTheOuterValue`](settlement/Nesting.t.sol#L273) | A nested order cannot spend the outer order's value |

## SettleFuzzTest

[`settlement/SettleFuzz.t.sol`](settlement/SettleFuzz.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| ORDER-FUZZ | [`testFuzz_ORDER_FUZZ_delegatedEntryPoint`](settlement/SettleFuzz.t.sol#L61) | A relayed order authenticated by an approved signer settles for any drawn order and spends no hub nonce |
| ORDER-FUZZ | [`testFuzz_ORDER_FUZZ_permit2EntryPoint`](settlement/SettleFuzz.t.sol#L106) | A relayed Permit2 order settles for any drawn order and spends its nonce |

## SolutionTest

[`settlement/Solution.t.sol`](settlement/Solution.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| TGT-01 / LEN-01 | [`test_TGT_01_solverChoosesTheTargetsOnTheDelegatedEntryPoint`](settlement/Solution.t.sol#L66) | Delegated entry point: mismatched target counts revert, matching counts settle |
| TGT-02 | [`test_TGT_02_solverTargetsOnThePermit2AllowancePull`](settlement/Solution.t.sol#L90) | On the delegated entry point, a Permit2 allowance pull pays the targets the solution names |
| TGT-03 / LEN-02 | [`test_TGT_03_witnessDoesNotBindTheErc20Targets`](settlement/Solution.t.sol#L111) | Over Permit2, one witness accepts any ERC20 targets; wrong counts revert |
| TGT-04 | [`test_TGT_04_ownerSubmitsWithTargetsOfTheirChoice`](settlement/Solution.t.sol#L150) | The owner submits over Permit2 with a plain permit, and still picks the targets |
| APR-01 | [`test_APR_01_theApprovalBindsTheTargets`](settlement/Solution.t.sol#L170) | An approval of one set of targets does not approve another |
| AMT-01 | [`test_AMT_01_amountBelowTheAllowanceMovesExactlyThatAmount`](settlement/Solution.t.sol#L209) | An amount below the allowance moves exactly that amount, on each pull branch |
| AMT-02 | [`test_AMT_02_amountAboveTheAllowanceIsRefusedWithItsIndex`](settlement/Solution.t.sol#L247) | An amount equal to the allowance settles, and one above it is refused with its index |
| AMT-03 | [`test_AMT_03_amountZeroMovesNothingOnItsTransfer`](settlement/Solution.t.sol#L269) | An amount of 0 settles and moves nothing on its transfer |
| AMT-04 | [`test_AMT_04_amountsOfTheWrongLengthAreRefused`](settlement/Solution.t.sol#L299) | Amounts of a length other than the transfers are refused on both entry points |
| AMT-05 | [`test_AMT_05_theApprovalBindsTheAmounts`](settlement/Solution.t.sol#L327) | An approval signed for amounts of 5 ether is refused for a solution with 2 ether |
| AMT-FUZZ | [`testFuzz_AMT_FUZZ_solverAmount`](settlement/Solution.t.sol#L367) | The solver's amount moves exactly, or is refused above the allowance |
| SD-01 | [`test_SD_01_eachOwnerCallReceivesItsOwnSolverData`](settlement/Solution.t.sol#L397) | Each owner call receives the `solverData` entry of its own index |
| SD-02 | [`test_SD_02_solverDataLengthMustMatchTheOwnerCalls`](settlement/Solution.t.sol#L437) | A `solverData` list of the wrong length is refused on both entry points |
| SD-03 | [`test_SD_03_theSolutionApprovalBindsSolverData`](settlement/Solution.t.sol#L489) | The solution approval binds `solverData` |
| SD-04 | [`test_SD_04_theOwnersSignatureDoesNotBindSolverData`](settlement/Solution.t.sol#L529) | The owner's signature does not bind `solverData` |

## SolutionApprovalTest

[`settlement/SolutionApproval.t.sol`](settlement/SolutionApproval.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| SOL-01 | [`test_SOL_01_oneApprovalBindsOneOrder`](settlement/SolutionApproval.t.sol#L50) | One approval binds one order, `ownerCalls` included |
| SOL-05 | [`test_SOL_05_theSolutionExpirationIsEnforced`](settlement/SolutionApproval.t.sol#L103) | A solution past its own expiration is refused on both entry points under any approver |
| SOL-06 | [`test_SOL_06_anApprovalSettlesOnce`](settlement/SolutionApproval.t.sol#L146) | An approval is spent when it settles, so it settles at most once |
| SOL-02 | [`test_SOL_02_sentinelApproverAcceptsAnySolution`](settlement/SolutionApproval.t.sol#L190) | The sentinel approver accepts any solution, with no signature to present |
| SOL-03 | [`test_SOL_03_malformedApprovalSignature`](settlement/SolutionApproval.t.sol#L235) | A malformed approval is refused rather than read as "no approver specified" |
| SOL-04 | [`test_SOL_04_anAuthenticatedOrderCannotSettleTwice`](settlement/SolutionApproval.t.sol#L262) | One authenticated order settles at most once |
| SOL-07 | [`test_SOL_07_anApprovalNonceCannotBeReusedForAnotherOrder`](settlement/SolutionApproval.t.sol#L304) | An approval nonce settles once for its approver, whichever order it approves |
| SOL-08 | [`test_SOL_08_theApproverRevokesAnApproval`](settlement/SolutionApproval.t.sol#L341) | The approver revokes an unused approval with `revokeNonce` |
| SOL-09 | [`test_SOL_09_theSentinelApproverSpendsNothing`](settlement/SolutionApproval.t.sol#L363) | The dead-address approver spends no nonce, so the same nonce repeats |
| SOL-10 | [`test_SOL_10_thePermit2EntryPointSpendsTheApprovalNonce`](settlement/SolutionApproval.t.sol#L379) | The Permit2 entry point spends the approval nonce as the delegated one does |
| SOL-11 | [`testFuzz_SOL_11_exactlyTheSolutionNonceIsSpent`](settlement/SolutionApproval.t.sol#L408) | Exactly the solution nonce is spent, and a replay reports it |
| SOL-12 | [`test_SOL_12_theApproverNamespaceIsSharedWithDelegationNonces`](settlement/SolutionApproval.t.sol#L446) | The approver's namespace is shared with its `updateDelegation` nonces |
| OWNER-APR-01 | [`testFuzz_OWNER_APR_01_ownerSettlesWithoutAnApproval`](settlement/SolutionApproval.t.sol#L476) | The owner settles under a named approver with a garbage approval |
| OWNER-APR-02 | [`testFuzz_OWNER_APR_02_solverIsRefusedWithoutAnApproval`](settlement/SolutionApproval.t.sol#L501) | The solver submitting the same order and approval is refused |

## Eip712Test

[`types/Eip712.t.sol`](types/Eip712.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| T712-08b | [`test_T712_08b_authDelegationStructHash`](types/Eip712.t.sol#L38) | The {AuthDelegation} hash matches the independent hash and moves with its inputs |
| T712-17 | [`test_T712_17_permit2TypeStringSortsItsReferencedTypes`](types/Eip712.t.sol#L98) | The Permit2 witness string lists its referenced types in sorted order |
| T712 | [`test_T712_callAndHookStructHash`](types/Eip712.t.sol#L115) | The hashes of the sample {CallParams} and {HookParams} entries match {SchemaHash} |
| T712 | [`test_T712_witnessStructHash`](types/Eip712.t.sol#L133) | The witness hash matches the independent encoding with empty client data |
| T712 | [`test_T712_witnessClientDataStructHash`](types/Eip712.t.sol#L156) | The witness hash matches the independent encoding, and client data moves the hash |
| T712 | [`test_T712_orderStructHash`](types/Eip712.t.sol#L179) | The order hash matches {SchemaHash} |
| T712 | [`test_T712_orderClientDataStructHash`](types/Eip712.t.sol#L190) | The order hash matches {SchemaHash} with client data, and clearing it moves the hash |
| T712 | [`test_T712_solutionStructHash`](types/Eip712.t.sol#L207) | The solution hash matches {SchemaHash}, and the nonce and `solverData` move the hash |
| T712 | [`test_T712_solutionApprovalStructHash`](types/Eip712.t.sol#L240) | The approval hash matches the independent encoding, and the order, targets, solverData and nonce move it |
| T712 | [`test_T712_erc20AllowanceStructHash`](types/Eip712.t.sol#L273) | The hash of each sample {ERC20Allowance} matches {SchemaHash} |
| T712 | [`test_T712_erc721ApprovalStructHash`](types/Eip712.t.sol#L282) | The hash of a sample {ERC721Approval} matches {SchemaHash} |
| T712-ARRAY | [`test_T712_ARRAY_addressArrayEncoding`](types/Eip712.t.sol#L294) | The packed encoding of an address array equals the per-element encoding |
| T712-ARRAY | [`testFuzz_T712_ARRAY_efficientHashLibExt`](types/Eip712.t.sol#L312) | The address array hash equals the hash of the words encoded one by one |
| T712-ARRAY | [`testFuzz_T712_ARRAY_bytesArrayHash`](types/Eip712.t.sol#L327) | The `bytes[]` hash equals the hash of the element hashes concatenated |
| T712-FUZZ | [`testFuzz_T712_FUZZ_callParamsStructHash`](types/Eip712.t.sol#L342) | The {CallParams} hash equals its EIP-712 struct hash |
| T712-FUZZ | [`testFuzz_T712_FUZZ_erc20AllowanceStructHash`](types/Eip712.t.sol#L347) | The {ERC20Allowance} hash equals its EIP-712 struct hash |
| T712-FUZZ | [`testFuzz_T712_FUZZ_erc721ApprovalStructHash`](types/Eip712.t.sol#L352) | The {ERC721Approval} hash equals its EIP-712 struct hash |
| T712-FUZZ | [`testFuzz_T712_FUZZ_hookParamsStructHash`](types/Eip712.t.sol#L357) | The {HookParams} hash equals its EIP-712 struct hash |
| T712-FUZZ | [`testFuzz_T712_FUZZ_orderStructHash`](types/Eip712.t.sol#L362) | The {AHV2Order} hash equals its EIP-712 struct hash |
| T712-FUZZ | [`testFuzz_T712_FUZZ_solutionStructHash`](types/Eip712.t.sol#L367) | The {AHV2Solution} hash equals its EIP-712 struct hash |

## SchemaAuditTest

[`types/SchemaAudit.t.sol`](types/SchemaAudit.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| T712-SCHEMA | [`test_T712_SCHEMA_typehashesMatchTheirStructs`](types/SchemaAudit.t.sol#L34) | Each typehash equals the hash of the schema derived from its struct |
| T712-SCHEMA-PERMIT2 | [`test_T712_SCHEMA_PERMIT2_witnessTypeStringMatchesItsStruct`](types/SchemaAudit.t.sol#L85) | The Permit2 stub plus the witness type string equals its struct schema |
| T712-SCHEMA | [`test_T712_SCHEMA_typeStringsWrittenOut`](types/SchemaAudit.t.sol#L103) | The typehashes of the order, solution, witness and approval match their written-out strings |
