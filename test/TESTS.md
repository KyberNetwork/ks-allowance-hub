# Tests

The suite has 209 tests in 19 contracts. Each row links to a test and gives the
first sentence of its documentation, or of the section heading above it. A test with neither
takes its ID and description from its name.

## GuardsTest

[`admin/Guards.t.sol`](admin/Guards.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| GUARD-01 | [`test_GUARD_01_pauseUnpauseRoundTrip`](admin/Guards.t.sol#L80) | Pause and unpause set `paused()` and emit `Paused` and `Unpaused` |
| GUARD-02 | [`test_GUARD_02_pauseClosesOrdersAndDelegation`](admin/Guards.t.sol#L99) | A pause closes both settlement paths and delegation |
| GUARD-03 | [`test_GUARD_03_pauseRolesAreEnforced`](admin/Guards.t.sol#L127) | Pausing needs the guardian or the admin, unpausing needs the admin alone |
| GUARD-04 | [`test_GUARD_04_expirationBoundaryOnTheOrderEntryPoints`](admin/Guards.t.sol#L161) | The expiration block itself still settles; the one before it does not |
| GUARD-05 | [`test_GUARD_05_pauseTakesPrecedenceOverTheExpiration`](admin/Guards.t.sol#L179) | When both guards would fire, the pause wins, because it is the outer modifier |
| GUARD-06 | [`test_GUARD_06_nativeSpendBoundary`](admin/Guards.t.sol#L204) | The calls may spend up to the value the order was sent with, and not one wei more |
| GATE-01 | [`test_GATE_01_permit2EntryPointCarriesTheThreeModifiers`](admin/Guards.t.sol#L220) | The Permit2 path is pausable, expiration-checked and native-guarded |
| GATE-02 | [`test_GATE_02_theUnwatchedGuards`](admin/Guards.t.sol#L278) | An undelegated authenticator and overspent native are refused by `settleOrder` |

## ManagementTest

[`admin/Management.t.sol`](admin/Management.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| DOM-01 | [`test_DOM_01_bothDomainsAreChainScoped`](admin/Management.t.sol#L56) | The hub and the authenticator sign under domains of their own, each scoped to the chain |
| MGMT-01 | [`test_MGMT_01_constructorWiring`](admin/Management.t.sol#L87) | The constructor grants the initial roles, sets the owner and emits one event |
| MGMT-02 | [`test_MGMT_02_eip712Domain`](admin/Management.t.sol#L133) | `eip712Domain()` returns the hub's name, version, chain id and address, no salt |
| MGMT-03 | [`test_MGMT_03_supportsInterface`](admin/Management.t.sol#L157) | `supportsInterface` accepts the ERC-165 and AccessControl ids, not the admin rules |
| MGMT-05 | [`test_MGMT_05_setRoleRevoker`](admin/Management.t.sol#L193) | No self-revoker and no revoker for the admin role; anything else is recorded |
| MGMT-06 | [`test_MGMT_06_revokeRoleNeedsRevokerOrAdmin`](admin/Management.t.sol#L215) | `revokeRole` by a stranger reverts with both accepted roles, the admin may revoke |
| MGMT-07 | [`test_MGMT_07_transferOwnership`](admin/Management.t.sol#L236) | The default admin role follows ownership, which moves in one step |
| MGMT-07b | [`test_MGMT_07b_renounceOwnership`](admin/Management.t.sol#L259) | Renouncing ownership leaves no default admin |
| MGMT-08a | [`test_MGMT_08a_rescueErc20s`](admin/Management.t.sol#L281) | Each ERC20 transfer goes to its target; a zero amount sends the whole balance |
| MGMT-08b | [`test_MGMT_08b_rescueStrandedNative`](admin/Management.t.sol#L302) | `rescueTokens` sends native balance under both native sentinels |
| MGMT-08c | [`test_MGMT_08c_rescueGuards`](admin/Management.t.sol#L322) | Only a rescuer or the default admin may rescue |
| MGMT-09 | [`test_MGMT_09_rescueErc721s`](admin/Management.t.sol#L363) | An NFT sent to the hub by `transferFrom` is recovered by `rescueTokens` |
| MGMT-11 | [`test_MGMT_11_grantRole`](admin/Management.t.sol#L389) | An ordinary role is granted by its admin |
| MGMT-11b | [`test_MGMT_11b_defaultAdminRoleFollowsOwnershipOnly`](admin/Management.t.sol#L401) | The default admin role cannot be granted, revoked or renounced |

## ForwarderTest

[`batching/Forwarder.t.sol`](batching/Forwarder.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| PF-01 | [`test_PF_01_eip2612PermitForwarded`](batching/Forwarder.t.sol#L124) | A relayed EIP-2612 permit sets the token allowance and spends the permit nonce |
| PF-02 | [`test_PF_02_daiStylePermitForwarded`](batching/Forwarder.t.sol#L148) | A relayed DAI-style permit sets the maximum allowance and spends the permit nonce |
| PF-03 | [`test_PF_03_erc721V3PermitForwarded`](batching/Forwarder.t.sol#L172) | A relayed Uniswap v3 ERC-721 permit with a v/r/s signature sets the approval |
| PF-04 | [`test_PF_04_erc721V4PermitForwarded`](batching/Forwarder.t.sol#L197) | A relayed Uniswap v4 ERC-721 permit with an unordered nonce sets the approval |
| PF-05 | [`test_PF_05_permit2BatchPermitForwarded`](batching/Forwarder.t.sol#L216) | A relayed Permit2 batch `permit` sets the allowance, expiration and nonce |
| PF-06 | [`test_PF_06_relayedCallWithoutAuthorityIsRefusedByItsTarget`](batching/Forwarder.t.sol#L251) | A relayed call that proves no authority is refused by its target |
| PF-06b | [`test_PF_06b_failingTransferUnwindsTheBatch`](batching/Forwarder.t.sol#L296) | A relayed call that fails on its target unwinds the entries that already ran |
| PF-08 | [`test_PF_08_failingCallRevertsWithMulticall3ErrorWhenNotAllowed`](batching/Forwarder.t.sol#L322) | With `allowFailure` false, a failing call reverts the batch with Multicall3's error |
| PF-09 | [`test_PF_09_failingCallIsCarriedPastWhenAllowed`](batching/Forwarder.t.sol#L337) | With `allowFailure` true, a failing call is recorded and the batch continues |
| PF-FUZZ | [`testFuzz_PF_FUZZ_allowFailureBits`](batching/Forwarder.t.sol#L371) | A batch settles exactly when every entry that fails has `allowFailure` true |
| FWD-13 | [`test_FWD_13_updateAuthenticationIsRelayedAndApprovesTheSigner`](batching/Forwarder.t.sol#L455) | A relayed `updateAuthentication` approves a signer, on the authenticator's nonce |
| FWD-14 | [`test_FWD_14_emptySignatureIsRefusedEvenFromTheOwner`](batching/Forwarder.t.sol#L495) | A relayed `updateAuthentication` with an empty signature is refused for an owner |
| FWD-21 | [`test_FWD_21_updateDelegationIsRelayed`](batching/Forwarder.t.sol#L532) | A relayed `updateDelegation` delegates on the owner's signature and the hub's nonce |
| FWD-22 | [`test_FWD_22_relayedDelegationNeedsTheOwnersSignature`](batching/Forwarder.t.sol#L558) | A relayed `updateDelegation` needs the owner's signature even when the owner relays it |
| FWD-16 | [`test_FWD_16_authenticatorRefusesMulticall3OnHubOnlyCalls`](batching/Forwarder.t.sol#L585) | Multicall3 relays `initAuthentication` and `authenticate`, and the authenticator refuses it as the caller because it is not the hub |
| FWD-17 | [`test_FWD_17_permit2SinglePermitForwarded`](batching/Forwarder.t.sol#L638) | A relayed Permit2 single `permit` sets the allowance |
| FWD-18 | [`test_FWD_18_emptyBatchIsANoOp`](batching/Forwarder.t.sol#L668) | An empty batch is a legal no-op rather than an error |
| FWD-PAUSE-01 | [`test_FWD_PAUSE_01_forwardStillWorksWhilePaused`](batching/Forwarder.t.sol#L685) | A pause does not close `forwardCalls` |
| FWD-VALUE-01 | [`test_FWD_VALUE_01_valueSentWithForwardIsStranded`](batching/Forwarder.t.sol#L710) | Value sent with `forwardCalls` remains in the hub, not Multicall3 |
| FWD-REENTRY-01 | [`test_FWD_REENTRY_01_relayedPermitMayReenterTheHub`](batching/Forwarder.t.sol#L739) | A relayed permit may reenter the hub and start an order |
| FWD-23 | [`test_FWD_23_multicall3RelaysWhenCalledDirectly`](batching/Forwarder.t.sol#L782) | Multicall3 relays a permit and a failing call alike when called directly |
| FWD-24 | [`test_FWD_24_hubForwardsThroughMulticall3`](batching/Forwarder.t.sol#L816) | `hub.forwardCalls` calls the target with Multicall3 as the caller |

## MulticallTest

[`batching/Multicall.t.sol`](batching/Multicall.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| MC-01 | [`test_MC_01_permitAndOrderInOneBatch`](batching/Multicall.t.sol#L48) | A permit and the order that uses the approval share one transaction, with value |
| MC-02 | [`test_MC_02_batchIsBoundedAsAWhole`](batching/Multicall.t.sol#L88) | Each sub-call may spend the value, but the batch as a whole may not spend it twice |
| MC-03 | [`test_MC_03_subCallRevertBubbles`](batching/Multicall.t.sol#L113) | A sub-call's revert arrives at the caller with its arguments intact |
| MC-04 | [`test_MC_04_twoOrdersInOneBatch`](batching/Multicall.t.sol#L131) | Two independent orders in one batch both settle, in the order given |
| MC-07 | [`test_MC_07_gasIsMeasuredPerEntry`](batching/Multicall.t.sol#L161) | Each entry is measured on its own, not given a running total of the batch |
| MC-05 | [`test_MC_05_plainNativeTransferIsRefused`](batching/Multicall.t.sol#L192) | The hub has no `receive`, so a bare transfer cannot strand native in it |
| MC-09 | [`test_MC_09_aFrontRunDelegationDoesNotUnwindTheBatch`](batching/Multicall.t.sol#L210) | A delegation relayed through `forwardCalls` with `allowFailure` set survives being front-run, so the order batched after it still settles |
| MC-06 | [`test_MC_06_approveASignerAndSpendOnItInOneBatch`](batching/Multicall.t.sol#L293) | One batch approves a signer at an authenticator and then spends on it |
| MC-FUZZ | [`testFuzz_MC_FUZZ_valueNeedsAnAllPayableBatch`](batching/Multicall.t.sol#L380) | Value survives a batch exactly when every selector in it is payable |

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

## GasSnapshotsTest

[`gas/GasSnapshots.t.sol`](gas/GasSnapshots.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| GAS-01 | [`test_GAS_01_ownerTransfer`](gas/GasSnapshots.t.sol#L18) | The owner submits an order drawing on the allowance to the hub |
| GAS-02 | [`test_GAS_02_ownerPermit2Allowance`](gas/GasSnapshots.t.sol#L31) | The owner submits an order drawing on the Permit2 allowance |
| GAS-03 | [`test_GAS_03_ownerPermit2Signature`](gas/GasSnapshots.t.sol#L45) | The owner submits an order on the Permit2 flow with a plain permit signature |
| GAS-04 | [`test_GAS_04_relayedOrderSignature`](gas/GasSnapshots.t.sol#L59) | A relayer submits an order with the owner's EIP-712 order signature |
| GAS-05 | [`test_GAS_05_relayedPermit2Witness`](gas/GasSnapshots.t.sol#L73) | A relayer submits an order on the Permit2 flow with the witness signature |
| GAS-06 | [`test_GAS_06_relayedDelegatedAuthenticator`](gas/GasSnapshots.t.sol#L87) | A relayer submits an order authenticated by the delegated signer authenticator |
| GAS-07 | [`test_GAS_07_relayedOrderSignatureWithSolutionApproval`](gas/GasSnapshots.t.sol#L101) | As the relayed order signature, with a solution approval from the order's approver |
| GAS-08 | [`test_GAS_08_ownerTransferWithNftAndCall`](gas/GasSnapshots.t.sol#L126) | The owner submits an order with one ERC721 approval and one callee call |
| GAS-09 | [`test_GAS_09_ownerTransferWithHooks`](gas/GasSnapshots.t.sol#L149) | The owner submits an order with one hook run before and after settlement |
| GAS-10 | [`test_GAS_10_ownerDelegates`](gas/GasSnapshots.t.sol#L169) | The owner delegates the signer authenticator in a call of their own |
| GAS-11 | [`test_GAS_11_relayedDelegation`](gas/GasSnapshots.t.sol#L181) | A relayer submits the owner's signed delegation of the signer authenticator |

## AuthenticationTest

[`settlement/Authentication.t.sol`](settlement/Authentication.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| AUTH-01b | [`test_AUTH_01b_permit2SelfSubmittedChecksTheApproval`](settlement/Authentication.t.sol#L54) | The owner submits their own order, so the permit witnesses nothing and the approval is still checked |
| AUTH-04 | [`test_AUTH_04_witnessPinsTheExclusiveCaller`](settlement/Authentication.t.sol#L100) | The exclusive caller the owner specified is part of what the witness binds |
| AUTH-07 | [`test_AUTH_07_permit2Witness`](settlement/Authentication.t.sol#L130) | A solver settles a witnessed order under the sentinel approver with its own solution |
| AUTH-07b | [`test_AUTH_07b_solutionApproverIsBoundByTheWitness`](settlement/Authentication.t.sol#L158) | The solver cannot swap in a different approver than the one the owner signed |
| ORD-03 | [`test_ORD_03_exclusiveCallerPinningAndTheOpenSentinel`](settlement/Authentication.t.sol#L199) | Only the named exclusive caller may submit a Permit2 settlement, the sentinel admits anyone |
| AUTH-06 | [`test_AUTH_06_ownerCallerNeedsNoAuthentication`](settlement/Authentication.t.sol#L271) | An owner acting for themselves with no authenticator needs no authentication |
| AUTH-06b | [`test_AUTH_06b_ownerCallerViaPermit2Allowance`](settlement/Authentication.t.sol#L289) | An owner's own call without an authenticator draws on the Permit2 allowance |
| AUTH-08 | [`test_AUTH_08_undelegatedAuthenticatorRefused`](settlement/Authentication.t.sol#L314) | An authenticator the owner never delegated is refused before it is ever called |
| ORD-01 | [`test_ORD_01_theAssetSourceIsTheSubmittersArgument`](settlement/Authentication.t.sol#L346) | The asset source is the submitter's parameter, and the same order settles either way |
| ORD-01b | [`test_ORD_01b_thePermit2SignatureEntryPointConsultsNoAllowance`](settlement/Authentication.t.sol#L389) | The Permit2 signature entry point takes no source argument and claims neither allowance |
| AUTH-13 | [`test_AUTH_13_malformedAuthenticationDataRejected`](settlement/Authentication.t.sol#L421) | Authentication data too short to settle is rejected, on whichever gate it reaches |
| AUTH-18 | [`test_AUTH_18_authenticatorReceivesTheOrderAndTheSolution`](settlement/Authentication.t.sol#L462) | The authenticator receives the order, its hash, the solution and the data, unaltered |
| AUTH-19 | [`test_AUTH_19_ownerWithDelegatedAuthenticatorIsAuthenticated`](settlement/Authentication.t.sol#L497) | An owner submitting an order with a delegated authenticator is authenticated |
| AUTH-20 | [`test_AUTH_20_ownerWithRejectedAuthenticationDataIsRefused`](settlement/Authentication.t.sol#L526) | An owner is refused when the delegated authenticator rejects the data |
| AUTH-21 | [`test_AUTH_21_ownerWithDelegatedAuthenticatorSkipsTheExclusiveCaller`](settlement/Authentication.t.sol#L549) | An owner with a delegated authenticator is exempt from the exclusive caller |
| ORD-04 | [`test_ORD_04_delegatedEntryPointDrawsOnTheNamedOwner`](settlement/Authentication.t.sol#L582) | An order repointed to another owner who approved the same signer reverts |
| ORD-03b | [`test_ORD_03b_delegatedEntryPointHonoursTheExclusiveCaller`](settlement/Authentication.t.sol#L626) | The delegated entry point refuses a submitter the order did not specify |

## CalldataHygieneTest

[`settlement/CalldataHygiene.t.sol`](settlement/CalldataHygiene.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| DIRTY-01 | [`test_DIRTY_01_delegatedOwnerSubmitted`](settlement/CalldataHygiene.t.sol#L21) | A dirty token address word is refused for the zero authenticator, owner submitted |
| DIRTY-02 | [`test_DIRTY_02_permit2Witnessed`](settlement/CalldataHygiene.t.sol#L35) | A dirty token address word is refused for the Permit2 authenticator, witnessed |
| DIRTY-03 | [`test_DIRTY_03_delegatedAuthenticated`](settlement/CalldataHygiene.t.sol#L49) | A dirty token address word is refused for a delegated authenticator |
| DIRTY-04 | [`test_DIRTY_04_permit2OwnerSubmitted`](settlement/CalldataHygiene.t.sol#L66) | A dirty token address word is refused for the Permit2 authenticator, owner submitted |

## CallsTest

[`settlement/Calls.t.sol`](settlement/Calls.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| OWN-01 | [`test_OWN_01_callsRunInOrder`](settlement/Calls.t.sol#L52) | The calls run in the order listed |
| OWN-02 | [`test_OWN_02_witnessBindsCalls`](settlement/Calls.t.sol#L86) | The Permit2 witness pins the calls the owner signed |
| OWN-03 | [`test_OWN_03_authenticationBindsCalls`](settlement/Calls.t.sol#L121) | Calls swapped after the authenticator's signature are refused on the delegated entry point |
| OWN-07 | [`test_OWN_07_eventListsTheValueOfEachCall`](settlement/Calls.t.sol#L167) | The event lists the value of each call with a value, in order |
| CALLEE-01 | [`test_CALLEE_01_unwhitelistedCalleeIsRejected`](settlement/Calls.t.sol#L217) | A callee without the role is refused, and the order rolls back whole, earlier calls included |
| CALLEE-02 | [`test_CALLEE_02_guardianRevokeStopsTheNextOrder`](settlement/Calls.t.sol#L265) | A guardian can drop a callee, and the very next order stops working |
| CALLEE-03 | [`test_CALLEE_03_eachCalleeCalledOnce`](settlement/Calls.t.sol#L291) | Every whitelisted callee in the list is called exactly once, with its own data |

## EventsTest

[`settlement/Events.t.sol`](settlement/Events.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| SET-01 | [`test_SET_01_settleOrderPayload`](settlement/Events.t.sol#L60) | The whole `SettleOrder` payload of a relayed order, byte for byte |
| SET-03 | [`test_SET_03_emptyOrderStillEmits`](settlement/Events.t.sol#L95) | An order that moves nothing and calls nobody still settles and still emits |
| CLIENT-01 | [`testFuzz_CLIENT_01_clientDataIsEmittedAsGiven`](settlement/Events.t.sol#L126) | The `SettleOrder` of a settled order carries exactly the order's client data |
| CLIENT-02 | [`testFuzz_CLIENT_02_clientDataIsCoveredByTheSignature`](settlement/Events.t.sol#L142) | The owner's signature covers the order's client data |
| CLIENT-02b | [`test_CLIENT_02b_emptyClientDataIsCoveredByTheSignature`](settlement/Events.t.sol#L160) | Client data submitted against empty signed client data reverts on every entry |
| EVT-01 | [`test_EVT_01_eventPairsTransfersWithTargets`](settlement/Events.t.sol#L256) | `SettleOrder` lists the transfers that happened, each with the solution's target |

## HooksTest

[`settlement/Hooks.t.sol`](settlement/Hooks.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| HOOK-01 | [`test_HOOK_01_hooksRunAroundTheSettlementOnTheDelegatedEntryPoint`](settlement/Hooks.t.sol#L44) | The hooks bracket the whole order on the delegated entry point, each reading its own entry |
| HOOK-02 | [`test_HOOK_02_hooksRunAroundThePermit2EntryPoint`](settlement/Hooks.t.sol#L110) | The hooks bracket the Permit2 entry point, the after hook following the calls |
| HOOK-03 | [`test_HOOK_03_aRevertingHookRevertsTheOrder`](settlement/Hooks.t.sol#L157) | A reverting hook reverts the order |
| HOOK-04 | [`test_HOOK_04_noHooks`](settlement/Hooks.t.sol#L194) | An order with no hooks settles and runs its callee call |
| HOOK-05 | [`test_HOOK_05_flagsSelectTheCalls`](settlement/Hooks.t.sol#L211) | The flags select which of the two calls a hook receives |
| HOOK-06 | [`testFuzz_HOOK_06_flagsSelectTheCalls`](settlement/Hooks.t.sol#L249) | Only the two lowest bits of the flags select calls |
| HOOK-07 | [`test_HOOK_07_hooksReceiveTheOrderTheSolutionAndTheirIndex`](settlement/Hooks.t.sol#L276) | A hook receives the order, its hash, the solution and the index of its entry |
| HOOK-08 | [`test_HOOK_08_hooksRunWhileMsgSenderIsTheOwner`](settlement/Hooks.t.sol#L318) | The hooks run while `msgSender` returns the owner and `solver` the submitter |
| HOOK-09 | [`test_HOOK_09_signaturesBindTheHooks`](settlement/Hooks.t.sol#L344) | Both signatures bind the hooks |
| HOOK-10 | [`test_HOOK_10_theAfterHookSeesTheCalls`](settlement/Hooks.t.sol#L418) | The after hook observes the effects of the calls |

## NestingTest

[`settlement/Nesting.t.sol`](settlement/Nesting.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| NEST-01 | [`testFuzz_NEST_01_nestedOrdersRestoreEachOwner`](settlement/Nesting.t.sol#L69) | Orders nested inside calls settle, and each level sees its owner |
| NEST-02 | [`test_NEST_02_receiverHookSettlesAnOrderInsideAnOrder`](settlement/Nesting.t.sol#L129) | The ERC721 receiver hook of an order may settle an order |
| NEST-03 | [`testFuzz_NEST_03_anOrderSettlesInsideAnotherOnEveryEntryPoint`](settlement/Nesting.t.sol#L192) | An order settles inside another on both entry points, as outer and as nested order |
| NEST-04 | [`test_NEST_04_revokeNonceIsReachableFromInsideAnOrder`](settlement/Nesting.t.sol#L258) | A callee's `revokeNonce` inside an order spends the nonce in the callee's namespace |
| NEST-05 | [`test_NEST_05_nestedOrderCannotSpendTheOuterValue`](settlement/Nesting.t.sol#L284) | A nested order cannot spend the outer order's value |

## OrderSignatureTest

[`settlement/OrderSignature.t.sol`](settlement/OrderSignature.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| SIG-01 | [`test_SIG_01_relayedSignedOrderSettlesAndSpendsItsNonce`](settlement/OrderSignature.t.sol#L91) | A relayer settles an order signed by the owner, which spends its nonce once |
| SIG-02 | [`test_SIG_02_erc1271OwnerAuthenticatesThroughItsWallet`](settlement/OrderSignature.t.sol#L125) | An ERC-1271 owner is authenticated through its wallet |
| SIG-03 | [`test_SIG_03_signatureNotCoveringTheOrderIsRefused`](settlement/OrderSignature.t.sol#L163) | A signature that does not cover the order as submitted is refused |
| SIG-04 | [`test_SIG_04_ownerSubmitsWithZeroNonceAndSpendsNothing`](settlement/OrderSignature.t.sol#L224) | The owner submits an order with the zero authenticator and nonce 0 |
| SIG-05 | [`test_SIG_05_solutionIsFreeWithSentinelApproverAndBoundByANamedOne`](settlement/OrderSignature.t.sol#L248) | The order signature does not bind the solution, and a non-zero approver does |
| SIG-06 | [`test_SIG_06_nonceSpentByRevocationOrDelegationRefusesTheOrder`](settlement/OrderSignature.t.sol#L296) | A nonce already spent in the owner's namespace refuses the order |
| SIG-07 | [`test_SIG_07_exclusiveCallerIsCheckedBeforeTheSignature`](settlement/OrderSignature.t.sol#L332) | Only the exclusive caller may submit, and that is checked before the signature |
| SIG-08 | [`test_SIG_08_spentNonceIsRefusedBeforeTheSignature`](settlement/OrderSignature.t.sol#L369) | A spent nonce is refused before the signature is verified |
| SIG-09 | [`test_SIG_09_exclusiveCallerIsCheckedBeforeTheNonce`](settlement/OrderSignature.t.sol#L397) | The exclusive caller is checked before the nonce |
| SIG-10 | [`test_SIG_10_ownerNonZeroNonceIsSpentOnce`](settlement/OrderSignature.t.sol#L426) | The owner settles an order with a non-zero nonce once, which spends that nonce |
| SIG-11 | [`test_SIG_11_ownerRevokedNonceRefusesTheOwner`](settlement/OrderSignature.t.sol#L449) | A nonce the owner revoked refuses the order of the owner |
| SIG-12 | [`test_SIG_12_ownerWithAuthenticationDataIsRefused`](settlement/OrderSignature.t.sol#L470) | The owner passing authentication data with the zero authenticator is refused |
| SIG-13 | [`test_SIG_13_ownerUnexpectedSignatureIsCheckedBeforeTheNonce`](settlement/OrderSignature.t.sol#L490) | For the owner, authentication data is refused before the nonce is spent |
| SIG-FUZZ | [`testFuzz_SIG_FUZZ_relayedSignedOrderSettlesExactly`](settlement/OrderSignature.t.sol#L508) | Any submitter settles a signed order for any nonce, amount and lifetime |
| SIG-FUZZ | [`testFuzz_SIG_FUZZ_ownerNonce`](settlement/OrderSignature.t.sol#L544) | The owner spends a non-zero nonce and not a zero one, and data is refused |
| DISP-01 | [`test_DISP_01_delegatedPermit2IsNotCalledAsAnAuthenticator`](settlement/OrderSignature.t.sol#L575) | The Permit2 address as authenticator is never called, even when delegated |
| DISP-02 | [`test_DISP_02_delegatedAuthenticatorCallsNoPermit2SignatureTransfer`](settlement/OrderSignature.t.sol#L602) | A delegated authenticator never reaches the signature transfers of Permit2 |
| DISP-03 | [`test_DISP_03_permit2FlowIgnoresUsePermit2Allowances`](settlement/OrderSignature.t.sol#L629) | The Permit2 authenticator pulls with the signature, not the owner's allowance |
| DISP-04 | [`test_DISP_04_ownerWithAnUndelegatedAuthenticatorIsRefused`](settlement/OrderSignature.t.sol#L654) | The owner is refused with an authenticator that was never delegated |
| DISP-05 | [`test_DISP_05_permit2FlowRefusesPlainPermitAndEmptySignature`](settlement/OrderSignature.t.sol#L684) | A relayer on the Permit2 flow needs the witness signature |
| DISP-06 | [`test_DISP_06_exclusiveCallerIsCheckedBeforeApprovalAndHooks`](settlement/OrderSignature.t.sol#L712) | The exclusive caller is checked before the approval and the hooks, on every rail |

## SettleFuzzTest

[`settlement/SettleFuzz.t.sol`](settlement/SettleFuzz.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| ORDER-FUZZ | [`testFuzz_ORDER_FUZZ_settleOrder`](settlement/SettleFuzz.t.sol#L55) | A relayed order settles for any drawn order on each of the three authenticator flows |

## SolutionTest

[`settlement/Solution.t.sol`](settlement/Solution.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| TGT-01 / LEN-01 | [`test_TGT_01_solverChoosesTheTargetsOnTheDelegatedEntryPoint`](settlement/Solution.t.sol#L59) | Delegated entry point: mismatched target counts revert, matching counts settle |
| TGT-02 | [`test_TGT_02_solverTargetsOnThePermit2AllowancePull`](settlement/Solution.t.sol#L81) | On the delegated entry point, a Permit2 allowance pull pays the targets the solution names |
| TGT-03 / LEN-02 | [`test_TGT_03_witnessDoesNotBindTheErc20Targets`](settlement/Solution.t.sol#L100) | Over Permit2, one witness accepts any ERC20 targets; wrong counts revert |
| TGT-04 | [`test_TGT_04_ownerSubmitsWithTargetsOfTheirChoice`](settlement/Solution.t.sol#L140) | The owner submits over Permit2 with a plain permit, and still picks the targets |
| APR-01 | [`test_APR_01_theApprovalBindsTheTargets`](settlement/Solution.t.sol#L161) | An approval of one set of targets does not approve another |
| AMT-01 | [`test_AMT_01_amountBelowTheAllowanceMovesExactlyThatAmount`](settlement/Solution.t.sol#L196) | An amount below the allowance moves exactly that amount, on each pull branch |
| AMT-02 | [`test_AMT_02_amountAboveTheAllowanceIsRefusedWithItsIndex`](settlement/Solution.t.sol#L234) | An amount equal to the allowance settles, and one above it is refused with its index |
| AMT-03 | [`test_AMT_03_amountZeroMovesNothingOnItsTransfer`](settlement/Solution.t.sol#L256) | An amount of 0 settles and moves nothing on its transfer |
| AMT-04 | [`test_AMT_04_amountsOfTheWrongLengthAreRefused`](settlement/Solution.t.sol#L286) | Amounts of a length other than the transfers are refused on both entry points |
| AMT-05 | [`test_AMT_05_theApprovalBindsTheAmounts`](settlement/Solution.t.sol#L315) | An approval signed for amounts of 5 ether is refused for a solution with 2 ether |
| AMT-FUZZ | [`testFuzz_AMT_FUZZ_solverAmount`](settlement/Solution.t.sol#L352) | The solver's amount moves exactly, or is refused above the allowance |
| SD-01 | [`test_SD_01_eachCallReceivesItsOwnSolverData`](settlement/Solution.t.sol#L382) | Each call receives the `solverData` entry of its own index |
| SD-02 | [`test_SD_02_solverDataLengthMustMatchTheCalls`](settlement/Solution.t.sol#L420) | A `solverData` list of the wrong length is refused on both entry points |
| SD-03 | [`test_SD_03_theSolutionApprovalBindsSolverData`](settlement/Solution.t.sol#L469) | The solution approval binds `solverData` |
| SD-04 | [`test_SD_04_theOwnersSignatureDoesNotBindSolverData`](settlement/Solution.t.sol#L506) | The owner's signature does not bind `solverData` |
| SD-05 | [`test_SD_05_callValuesLengthMustMatchTheCalls`](settlement/Solution.t.sol#L539) | A `callValues` list of the wrong length is refused on both entry points |
| SD-06 | [`test_SD_06_theSolutionApprovalBindsCallValues`](settlement/Solution.t.sol#L577) | The solution approval binds `callValues` |
| SD-07 | [`test_SD_07_theOwnersSignatureDoesNotBindCallValues`](settlement/Solution.t.sol#L615) | The owner's signature does not bind `callValues` |

## SolutionApprovalTest

[`settlement/SolutionApproval.t.sol`](settlement/SolutionApproval.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| SOL-01 | [`test_SOL_01_oneApprovalBindsOneOrder`](settlement/SolutionApproval.t.sol#L40) | One approval binds one order, `calls` included |
| SOL-05 | [`test_SOL_05_theSolutionExpirationIsEnforced`](settlement/SolutionApproval.t.sol#L86) | A solution past its own expiration is refused on both entry points under any approver |
| SOL-06 | [`test_SOL_06_anApprovalSettlesOnce`](settlement/SolutionApproval.t.sol#L130) | An approval is spent when it settles, so it settles at most once |
| SOL-02 | [`test_SOL_02_sentinelApproverAcceptsAnySolution`](settlement/SolutionApproval.t.sol#L174) | The sentinel approver accepts any solution, with no signature to present |
| SOL-03 | [`test_SOL_03_malformedApprovalSignature`](settlement/SolutionApproval.t.sol#L222) | A malformed approval is refused rather than read as "no approver specified" |
| SOL-04 | [`test_SOL_04_anAuthenticatedOrderCannotSettleTwice`](settlement/SolutionApproval.t.sol#L250) | One authenticated order settles at most once |
| SOL-07 | [`test_SOL_07_anApprovalNonceCannotBeReusedForAnotherOrder`](settlement/SolutionApproval.t.sol#L289) | An approval nonce settles once for its approver, whichever order it approves |
| SOL-08 | [`test_SOL_08_theApproverRevokesAnApproval`](settlement/SolutionApproval.t.sol#L319) | The approver revokes an unused approval with `revokeNonce` |
| SOL-09 | [`test_SOL_09_theSentinelApproverSpendsNothing`](settlement/SolutionApproval.t.sol#L339) | The dead-address approver spends no nonce, so the same nonce repeats |
| SOL-10 | [`test_SOL_10_thePermit2EntryPointSpendsTheApprovalNonce`](settlement/SolutionApproval.t.sol#L359) | The Permit2 entry point spends the approval nonce as the delegated one does |
| SOL-11 | [`testFuzz_SOL_11_exactlyTheSolutionNonceIsSpent`](settlement/SolutionApproval.t.sol#L389) | Exactly the solution nonce is spent, and a replay reports it |
| SOL-12 | [`test_SOL_12_theApproverNamespaceIsSharedWithDelegationNonces`](settlement/SolutionApproval.t.sol#L423) | The approver's namespace is shared with its `updateDelegation` nonces |
| OWNER-APR-01 | [`test_OWNER_APR_01_ownerSettlesWithAValidApproval`](settlement/SolutionApproval.t.sol#L452) | The owner under a named approver settles with a valid approval |
| OWNER-APR-03 | [`test_OWNER_APR_03_ownerIsRefusedWithoutAnApproval`](settlement/SolutionApproval.t.sol#L462) | The owner under a named approver is refused without an approval |
| OWNER-APR-02 | [`testFuzz_OWNER_APR_02_solverIsRefusedWithoutAnApproval`](settlement/SolutionApproval.t.sol#L472) | The solver submitting the same order and approval is refused |

## Eip712Test

[`types/Eip712.t.sol`](types/Eip712.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| T712-08b | [`test_T712_08b_authDelegationStructHash`](types/Eip712.t.sol#L37) | The {AuthDelegation} hash matches the independent hash and moves with its inputs |
| T712-17 | [`test_T712_17_permit2TypeStringSortsItsReferencedTypes`](types/Eip712.t.sol#L97) | The Permit2 witness string lists its referenced types in sorted order |
| T712 | [`test_T712_callAndHookStructHash`](types/Eip712.t.sol#L115) | The hashes of the sample {CallParams} and {HookParams} entries match {SchemaHash} |
| T712 | [`test_T712_orderStructHash`](types/Eip712.t.sol#L130) | The order hash matches {SchemaHash} |
| T712 | [`test_T712_orderClientDataStructHash`](types/Eip712.t.sol#L141) | The order hash matches {SchemaHash} with client data, and clearing it moves the hash |
| T712-DIFF | [`test_T712_DIFF_authenticatorMovesOrderAndApprovalHash`](types/Eip712.t.sol#L159) | The authenticator alone moves the order hash and the approval hash |
| T712 | [`test_T712_solutionStructHash`](types/Eip712.t.sol#L184) | The solution hash matches {SchemaHash}, and the nonce, `callValues` and `solverData` move the hash |
| T712 | [`test_T712_solutionApprovalStructHash`](types/Eip712.t.sol#L230) | The approval hash matches the independent encoding, and the order, targets, callValues, solverData and nonce move it |
| T712 | [`test_T712_erc20AllowanceStructHash`](types/Eip712.t.sol#L269) | The hash of each sample {ERC20Allowance} matches {SchemaHash} |
| T712 | [`test_T712_erc721ApprovalStructHash`](types/Eip712.t.sol#L278) | The hash of a sample {ERC721Approval} matches {SchemaHash} |
| T712-ARRAY | [`test_T712_ARRAY_addressArrayEncoding`](types/Eip712.t.sol#L290) | The packed encoding of an address array equals the per-element encoding |
| T712-ARRAY | [`testFuzz_T712_ARRAY_efficientHashLibExt`](types/Eip712.t.sol#L308) | The address array hash equals the hash of the words encoded one by one |
| T712-ARRAY | [`testFuzz_T712_ARRAY_bytesArrayHash`](types/Eip712.t.sol#L323) | The `bytes[]` hash equals the hash of the element hashes concatenated |
| T712-FUZZ | [`testFuzz_T712_FUZZ_callParamsStructHash`](types/Eip712.t.sol#L338) | The {CallParams} hash equals its EIP-712 struct hash |
| T712-FUZZ | [`testFuzz_T712_FUZZ_erc20AllowanceStructHash`](types/Eip712.t.sol#L343) | The {ERC20Allowance} hash equals its EIP-712 struct hash |
| T712-FUZZ | [`testFuzz_T712_FUZZ_erc721ApprovalStructHash`](types/Eip712.t.sol#L348) | The {ERC721Approval} hash equals its EIP-712 struct hash |
| T712-FUZZ | [`testFuzz_T712_FUZZ_hookParamsStructHash`](types/Eip712.t.sol#L353) | The {HookParams} hash equals its EIP-712 struct hash |
| T712-FUZZ | [`testFuzz_T712_FUZZ_orderStructHash`](types/Eip712.t.sol#L358) | The {AHV2Order} hash equals its EIP-712 struct hash |
| T712-FUZZ | [`testFuzz_T712_FUZZ_solutionStructHash`](types/Eip712.t.sol#L363) | The {AHV2Solution} hash equals its EIP-712 struct hash |

## SchemaAuditTest

[`types/SchemaAudit.t.sol`](types/SchemaAudit.t.sol)

| ID | Test | Description |
| --- | --- | --- |
| T712-SCHEMA | [`test_T712_SCHEMA_typehashesMatchTheirStructs`](types/SchemaAudit.t.sol#L33) | Each typehash equals the hash of the schema derived from its struct |
| T712-SCHEMA-PERMIT2 | [`test_T712_SCHEMA_PERMIT2_witnessTypeStringMatchesItsStruct`](types/SchemaAudit.t.sol#L79) | The Permit2 stub plus the witness type string equals its struct schema |
| T712-SCHEMA | [`test_T712_SCHEMA_typeStringsWrittenOut`](types/SchemaAudit.t.sol#L97) | The typehashes of the order, solution and approval match their written-out strings |
