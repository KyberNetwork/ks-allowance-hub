# Developer testing checklist

## Run `20260923T173600Z`

Scope: first test suite for the V2 contracts — `src/v2/KSAllowanceHubV2.sol`, the `src/base/**`
building blocks and `src/verifiers/SessionAuthVerifier.sol`. New tests live under `test/base/**`,
`test/v2/**` and `test/verifiers/**`. `src/v1/**` and `test/v1/**` are out of scope and unchanged.

| Implemented and verified | Developer reviewed | Review ID | Contract / flow and coverage summary | Case IDs and test files / functions | Passing command or blocker |
|---|---|---|---|---|---|
| - [x] | - [ ] | `20260923T173600Z/FLOW-01` | Authorisation matrix: Permit2 signature rail vs delegated verifier, owner-called vs relayed, witness binding, caller pinning, entry-point discriminator byte, ignored high flag bits, malformed `authData` | `AUTH-01..09`, `AUTH-11..13` (+`-01b/-06b/-07b`), `EX-FUZZ`, `FU-FUZZ`, relayed-rail fuzz — `test/v2/Auth.t.sol`. `AUTH-10` forward half is `SV-10`; reverse half deliberately not written. | `forge test` — 146 passed, 0 failed (also 146 under CI's `--isolate`) |
| - [x] | - [ ] | `20260923T173600Z/FLOW-02` | Settlement: ERC721 leg, `TransferTokens` payload incl. native truncation, per-call router role gate, call ordering, `msgSender()` seen by routers, reentrancy lock | `SET-01..04`, `ROUTER-01..03`, `LOCK-01..04` — `test/v2/Settlement.t.sol` | `forge test` — 146 passed, 0 failed (also 146 under CI's `--isolate`) |
| - [x] | - [ ] | `20260923T173600Z/EDGE-01` | Guards: pause, deadline on all four guarded functions, native-spend boundary against a pre-funded hub, multicall whole-batch bound, payable/non-payable batching, no `receive` | `GUARD-01..08`, `MC-01..05`, `MC-FUZZ` — `test/v2/Guards.t.sol` | `forge test` — 146 passed, 0 failed (also 146 under CI's `--isolate`) |
| - [x] | - [ ] | `20260923T173600Z/FLOW-03` | Delegation, nonces, calls approval and validators: `delegateAuth` self/relayed/ERC-1271, `updateAuth` access rules incl. owner-with-signature, bitmap boundaries, validator ordering and index pairing | `DEL-*`, `UPD-*`, `NONCE-*`, `CALLS-*`, `VAL-01..04` — `test/v2/Delegation.t.sol` | `forge test` — 146 passed, 0 failed (also 146 under CI's `--isolate`) |
| - [x] | - [ ] | `20260923T173600Z/EDGE-02` | Permit forwarding: every payload-length branch incl. the silent fall-through, swallowed failures, uncaught `SliceOutOfBounds` | `PF-01..09`, `PF-FUZZ`, `PF-FUZZ-721`, `PF-FUZZ-P2` — `test/v2/Permits.t.sol` | `forge test` — 146 passed, 0 failed (also 146 under CI's `--isolate`) |
| - [x] | - [ ] | `20260923T173600Z/OBS-01` | Management: constructor wiring, EIP-712 domain, `supportsInterface`, role admin surface, all three rescue paths incl. native and the seeding they require | `MGMT-01..11` — `test/v2/Management.t.sol` | `forge test` — 146 passed, 0 failed (also 146 under CI's `--isolate`) |
| - [x] | - [ ] | `20260923T173600Z/FLOW-04` | `SessionAuthVerifier`: approval routes, hub-only gate, expiry, nonce replay, execute/fulfill discriminator, all four `KeyType` branches incl. P256 malleability | `SV-01`, `SV-03..11` (+`-10b`), `SV-KEY-*`, `SV-DOMAIN`, `SV-FUZZ-UPD/VER` — `test/verifiers/SessionAuthVerifier.t.sol`. `SV-02`/`SV-02b` cover the owner-calls-directly branch added mid-run; the earlier SV-02 (relayed, signed) was folded into `SV-FUZZ-UPD`. | `forge test` — 146 passed, 0 failed (also 146 under CI's `--isolate`) |
| - [x] | - [ ] | `20260923T173600Z/OBS-02` | EIP-712 oracle independence: hand-written type strings and typehashes for all twelve types, both Permit2 witness strings, `hash` vs `hashMemory` equivalence, array encoding | `T712-01..12`, `T712-DIFF`, `T712-ARRAY` — `test/v2/types/Eip712.t.sol`, `test/verifiers/types/Eip712.t.sol` | `forge test` — 146 passed, 0 failed (also 146 under CI's `--isolate`) |

Notes for the reviewer:

- **Oracle rule:** no production constant, type string, typehash or hashing helper appears on the
  expected side of any assertion, including inside the signing helpers. The `T712-*` rows are the
  single place production constants appear, and there they are the value under test. This is what
  makes a wrong EIP-712 type string visible; the mainnet fork alone does not, because Permit2
  derives its typehash from the string the hub hands it.
- Tests run against a mainnet fork at block 23,932,050 with the **real** Permit2.
- `test/libraries/PermitHash.sol` supplies the Permit2 constants the signing helpers need — its
  stub, its leaf typehash, its witness-free batch typehash — because those are Permit2's own spec
  and name no hub type. Its hashing functions stay unused: `hashWithWitness` takes the witness type
  string as a parameter, which reintroduces exactly that circularity.
- Two production bugs found during discovery were fixed by the author before implementation: the
  P256/WebAuthn `decodeBytes32` word index, and the `AuthFlags` byte mask that produced
  non-canonical bools. `SV-KEY-P256-*`, `SV-KEY-WEBAUTHN-*`, `AUTH-09` and `AUTH-12` are their
  regressions.
- An independent coverage-gap audit found one real semantic gap — `transferAndFulfill` on the
  owner-self-submitted Permit2 rail, where no witness binds the calls yet the calls nonce is still
  burned. Closed by `AUTH-01b`; hub branch coverage is now 100%.
- Two findings are deferred by the author and are **pinned, not blessed**: the calls nonce is burned
  before it is authenticated (`CALLS-01..03`), and session-key approvals cannot yet be revoked
  (`DEL-06`).
- This file is listed in `.gitignore`, so it will not appear in a diff or PR review.

## Run `20260924T000000Z`

Scope: migrating the suite to the `CallsForwarder` refactor and covering the behaviour it added.
`PermitForwarder`, `GuardedMulticall` and the `AuthFlags` type are gone; permits and verifier
updates now go through `CallsForwarder.forward`, `authFlags` is a `PackedBits`, delegation runs
through `updateDelegation`, and verifiers gained `initAuth`. `src/v1/**` and `test/v1/**` remain
out of scope and unchanged. 168 tests, up from 146.

| Implemented and verified | Developer reviewed | Review ID | Contract / flow and coverage summary | Case IDs and test files / functions | Passing command or blocker |
|---|---|---|---|---|---|
| - [x] | - [ ] | `20260924T000000Z/FWD-01` | `CallsForwarder.forward`: the six permit selectors relayed against real tokens and the real Permit2, both overloads; selector allowlist refusals; array-length guard; both `allowFailure` directions; empty batch | `PF-01..09`, `PF-FUZZ`, `FWD-17..19` — `test/v2/Permits.t.sol` | `forge test` — 168 passed, 0 failed (also 168 under CI's `--isolate`) |
| - [x] | - [ ] | `20260924T000000Z/FWD-02` | The `updateAuth` arm of the allowlist: relayed approval burns the verifier nonce and not the hub's; an empty signature is refused even when the owner sends the transaction; an undelegated verifier is still reachable; `initAuth` and `verifyAuth` are **not** forwardable | `FWD-13..16` — `test/v2/Permits.t.sol` | `forge test` — 168 passed, 0 failed |
| - [x] | - [ ] | `20260924T000000Z/FWD-03` | `forward`'s unguarded edges, each pinned as intended: relaying while paused, value stranded with no native-spend guard, and a relayed permit reentering `transferAndExecute` because there is no lock | `FWD-PAUSE-01`, `FWD-VALUE-01`, `FWD-REENTRY-01` — `test/v2/Permits.t.sol` | `forge test` — 168 passed, 0 failed |
| - [x] | - [ ] | `20260924T000000Z/DEL-01` | `initAuth` vs `updateAuth`: the direction word is ignored on the delegation path, both payload shapes resolve to one key hash, `onlyAllowanceHub` holds against relayer and owner alike, and the `data.length > 0` guard is exercised on all three legs | `DEL-10..15` — `test/v2/Delegation.t.sol` | `forge test` — 168 passed, 0 failed |
| - [x] | - [ ] | `20260924T000000Z/SV-01` | The owner arm of `SessionAuthVerifier.updateAuth`, pinned as author-confirmed: a signature from the owner is ignored, burns no nonce and is infinitely repeatable | `SV-UPD-01` — `test/verifiers/SessionAuthVerifier.t.sol` | `forge test` — 168 passed, 0 failed |
| - [x] | - [ ] | `20260924T000000Z/PB-01` | `PackedBits.pos`: positions 0/1/255, everything at or above 256 reading false, and the canonical-bool mask | `PB-01`, `PB-01b`, `PB-02` — `test/base/PackedBits.t.sol` | `forge test` — 168 passed, 0 failed |
| - [x] | - [ ] | `20260924T000000Z/E2E-01` | End to end: one `multicall` approving a session key through `forward` and spending on it via the verifier rail, plus bit 2 of `authFlags` alone selecting the signed caller through the hub's raw-assembly path | `MC-06`, `AUTH-12b` — `test/v2/Guards.t.sol`, `test/v2/Auth.t.sol` | `forge test` — 168 passed, 0 failed |

### Notes for this run

- Tests deleted rather than contorted, their premise having been removed: the whole `UPD-*` block
  and `DEL-07` (`test/v2/Delegation.t.sol`), `GUARD-08` (`test/v2/Guards.t.sol`), and all thirteen
  old length-dispatch `PF-*` cases (`test/v2/Permits.t.sol`).
- Two tests were passing while asserting nothing and were repaired: `DEL-08` delegated with empty
  `data`, so `initAuth` never ran on either leg, and `AuthVerifierMock` counted `initAuth` and
  `updateAuth` into one field, so `GUARD-02` could not tell them apart.
- Six mutations were run against the new assertions and all were caught: `initAuth` honouring the
  direction word (`DEL-10`), dropping the `data.length` guard (`DEL-13`), removing the `PackedBits`
  canonical mask (`PB-02`), `_signedCaller` reading bit 3 (`AUTH-12b`), `updateAuth` verifying the
  owner's signature (`SV-UPD-01`), and adding `initAuth` to the `forward` allowlist (`FWD-16`).
- **Open production concern, documentation only:** `forward` relays `updateAuth` to an arbitrary
  target with the hub as `msg.sender`. `SessionAuthVerifier` is safe because it trusts only
  `msg.sender == owner`, and `FWD-14` pins that, but any third-party verifier written to the old
  `IAuthVerifier` NatSpec would have been compromised. The interface doc has been corrected; the
  allowlist has not been narrowed.
- This file is no longer listed in `.gitignore`, so it now appears in diffs and PR review.

## Run `20260925T110339Z`

Scope: the `ownerCalls` addition to `KSAllowanceHubV2.transferAndFulfill` and the
`genericCalls` → `solverCalls` rename. `ownerCalls` is a tail the owner signs exactly and which
runs after the solver's route, for effects no validator can check on this chain. Three EIP-712
typehashes change with it: `FulfillmentWitness`, `FulfillmentApproval`, `CallsApproval`.
`transferAndExecute`, `src/v1/**` and `test/v1/**` are out of scope and unchanged.

| Implemented and verified | Developer reviewed | Review ID | Contract / flow and coverage summary | Case IDs and test files / functions | Passing command or blocker |
|---|---|---|---|---|---|
| - [x] | - [ ] | `20260925T110339Z/OWN-EXEC` | Execution order and results: the owner's tail runs after every solver call and observes what they produced; `results` is the solver's returns then the owner's | `OWN-01` `test_OWN_01_ownerCallsRunAfterSolverCalls`, `OWN-06` `test_OWN_06_resultsAreSolverThenOwner` — `test/v2/Delegation.t.sol`; ordering instrument `ObservingRouterMock`, results instrument `EchoRouterMock` — `test/v2/mocks/RouterMock.sol` | `forge test`, `forge test --isolate` — 176 passed. Non-vacuity: handing the two lists to the entry point the other way round fails both (`0x != 0xb2`; router at position 2 wrong) |
| - [x] | - [ ] | `20260925T110339Z/OWN-BIND` | Authorisation: `ownerCalls` is bound by the Permit2 witness and by the verifier's `FulfillmentApproval`, each with a control leg proving the refusal is about binding. `OWN-03` also carries validators, so it pins both words the verifier payload moved | `OWN-02` `test_OWN_02_witnessBindsOwnerCalls`, `OWN-03` `test_OWN_03_approvalBindsOwnerCalls`, `OWN-08` `test_OWN_08_callsApprovalDoesNotCoverOwnerCalls` — `test/v2/Delegation.t.sol` | `forge test`, `forge test --isolate` — 176 passed. Each case settles its control leg before the expected `InvalidSigner()` / `InvalidApprovalSignature()` |
| - [x] | - [ ] | `20260925T110339Z/OWN-GATE` | The router role gate and the settlement event both span the two lists; an empty owner tail reproduces the prior behaviour | `OWN-04` `test_OWN_04_ownerCallRouterMustBeWhitelisted`, `OWN-05` `test_OWN_05_emptyOwnerCallsIsThePriorBehaviour` — `test/v2/Delegation.t.sol`; `OWN-07` `test_OWN_07_eventCoversBothLists` — `test/v2/Settlement.t.sol` | `forge test`, `forge test --isolate` — 176 passed. Non-vacuity: swapping the two lists in `OWN-07` fails on the exact event payload |
| - [x] | - [ ] | `20260925T110339Z/OWN-712` | The three changed typehashes and struct hashes against hand-written literals, including `GenericCall` joining two `encodeType`s. Both struct-hash rows now pass a non-empty tail, so the new member is actually encoded | `T712-02`, `T712-02b`, `T712-03`, `test_T712_fulfillmentWitnessStructHash`, `test_T712_callsApprovalStructHash` — `test/v2/types/Eip712.t.sol`; `T712-12` — `test/verifiers/types/Eip712.t.sol` | `forge test`, `forge test --isolate` — 176 passed |
| - [x] | - [ ] | `20260925T110339Z/OWN-BASE` | Signature migration across the suite with every prior assertion preserved; the relayed-fulfillment fuzz domain extended to the new list, which is why `results.length` there is now the sum of the two | 16 `transferAndFulfill` / `_signFulfillmentOrder` / `lFulfillmentApproval` call sites — `test/v2/Auth.t.sol`, `test/v2/Delegation.t.sol`, `test/v2/Guards.t.sol`, `test/verifiers/SessionAuthVerifier.t.sol`, both `Eip712.t.sol`; `FU-FUZZ` `testFuzz_FU_FUZZ_ownerRail` — `test/v2/Auth.t.sol` | `forge build` clean (was 19 errors), `forge fmt test/`, `forge test`, `forge test --isolate` — 176 passed, 168 baseline preserved plus the 8 `OWN-*` |

Unresolved gate, pre-existing and not introduced by this run: `forge coverage` fails
stack-too-deep and `--ir-minimum` fails in the solar analyser on the `erc7201` builtin at
`src/base/MsgSender.sol:16`, at `HEAD` as well as with this diff. Closure for the rows above is
argued from the non-vacuity checks recorded in each, not from a coverage report.

## Run `20261002T032856Z`

Scope: reshaping the suite onto the v2 restructure. `src/base/**` moved under `src/v2/**`, the
verifier surface became `IOrderAuthenticator` / `OrderAuthenticatorBase` /
`SessionOrderAuthenticator` under `src/v2/authenticators/`, the witness and approval types gave way
to `ExecutionOrder` / `FulfillmentOrder` / `FulfillmentSolution` / `SolutionApproval`, two entry
points became four, and `authFlags` moved inside the signed order. The test files are reorganised to
mirror that shape rather than re-pointed in place. `test/v1/**` is frozen.

Standing item, out of scope by the user's instruction: the hub's size. At the `src/` state this run
was implemented against it is **no longer over EIP-170** — `forge build --sizes` reports
`KSAllowanceHubV2` at 22,505 runtime bytes with 2,071 to spare, under the `runs-500`
`compilation_restrictions` entry that `foundry.toml` pins for it. It deploys, so no test is shaped
around the limit, and none is shaped around the margin either.

| Implemented and verified | Developer reviewed | Review ID | Contract / flow and coverage summary | Case IDs and test files / functions | Passing command or blocker |
|---|---|---|---|---|---|
| - [x] | - [ ] | `20261002T032856Z/MIG-01` | Reshape: every baseline assertion carried onto the new surface, files reorganised to mirror `src/`. `Auth.t.sol` split into `ExecuteOrder.t.sol` / `FulfillOrder.t.sol`; `test/verifiers/**` moved to `test/v2/authenticators/**`; `VerifierBase` became `AuthenticatorBase` and is now the base for every batch that reaches the delegated rail | every pre-existing case ID — `test/v2/**`, `test/base/**`. Retired with their premise and named in the report: `AUTH-05` (merged into `AUTH-04`), `AUTH-09` (inverted into `ORD-01`), `AUTH-12`, `AUTH-12b`, `CALLS-01..03`, `OWN-08`, `SV-12`, `T712-03`, `T712-11`, `T712-12` | `forge build` clean (was 31 errors), `forge fmt --check test/` clean, `forge test` and `forge test --isolate` — **188 passed, 0 failed**. Arithmetic, as verified against `git show HEAD:` by the final integrity review: 178 baseline, less **13** genuinely retired (39 test functions disappeared by name, but 26 of those are 1:1 renames onto the new surface), plus **23** genuinely new — 21 from the reshape and `ORD-03`, then `SV-06b` and `SV-07b`. `MGMT-12` belongs in the retired list above, subsumed by `DOM-01`; `CALLS-03` never had a function of its own and lived inside `CALLS-02`'s body |
| - [x] | - [ ] | `20261002T032856Z/ORD-01` | The signed order carries its own switches: `usePermit2Allowances` is covered by the signature on the delegated rail — the Permit2 witnesses do not carry it, so on those rails it is bound only through the emitted order hash — and the `relayer` pin is enforced by the hub's own gate, with the dead-address sentinel opening submission to anyone | `ORD-01` `test_ORD_01_usePermit2AllowancesIsSigned`, `ORD-02` `test_ORD_02_relayerPinningAndTheOpenSentinel`, plus `AUTH-04` `test_AUTH_04_witnessPinsTheNamedRelayer` — `test/v2/ExecuteOrder.t.sol` | `forge test`, `forge test --isolate` — 185 passed. Non-vacuity: submitting the order the key actually signed makes `ORD-01`'s third leg's `expectRevert` fail; transposing `UnauthorizedRelayer`'s two arguments fails `ORD-02` |
| - [x] | - [ ] | `20261002T032856Z/SOL-01` | Solution approval: one approval binds one order including its `ownerCalls`, the sentinel approver accepts any route with no signature, a malformed approval is refused rather than read as "nobody named", and replay is bounded by the order nonce | `SOL-01` `test_SOL_01_oneApprovalBindsOneOrder`, `SOL-02` `test_SOL_02_sentinelApproverAcceptsAnyRoute`, `SOL-03` `test_SOL_03_malformedApprovalSignature`, `SOL-04` `test_SOL_04_anAuthenticatedFulfillmentCannotSettleTwice` — `test/v2/FulfillOrder.t.sol` | `forge test`, `forge test --isolate` — 185 passed. Non-vacuity: giving `SOL-01`'s second order the same tail as the first makes its `expectRevert` fail |
| - [x] | - [ ] | `20261002T032856Z/GATE-01` | `fulfillOrderWithPermit2Signature` carries all four modifiers, one leg each behind a settling control; and the validators bracket that rail — the pre-hook before Permit2 moves anything, the post-hook between the solver's route and the owner's tail | `GATE-01` `test_GATE_01_fulfillPermit2CarriesTheFourModifiers` — `test/v2/Guards.t.sol`; `VAL-02` `test_VAL_02_hooksBracketThePermit2Rail` — `test/v2/FulfillOrder.t.sol` (`VAL-01` is the same bracket on the delegated rail) | `forge test`, `forge test --isolate` — 185 passed. Non-vacuity: a route that does not reenter fails `GATE-01`'s lock leg; expecting the post-hook to have run after the owner's tail fails `VAL-02` |
| - [x] | - [ ] | `20261002T032856Z/712-01` | Four new typehashes and both Permit2 witness type strings against hand-written literals, plus the referenced types shown to be in sorted order inside the production strings, and both order struct hashes against the literal encoding with `usePermit2Allowances` shown to move the hash | `T712-13`..`T712-17`, `test_T712_executionOrderStructHash`, `test_T712_fulfillmentOrderStructHash`, `test_T712_fulfillmentSolutionStructHash`, `test_T712_solutionApprovalStructHash`, `testFuzz_T712_DIFF_executionOrder`, `testFuzz_T712_DIFF_fulfillmentOrder` — `test/v2/types/Eip712.t.sol` | `forge test`, `forge test --isolate` — 185 passed. Non-vacuity: transposing two of the expected referenced-type names fails `T712-17` |
| - [x] | - [ ] | `20261002T032856Z/DOM-01` | Both signing domains publish a separator: each matches the domain written out from its own name, version and address, the two differ from each other, and each is rebuilt once the chain id moves. Subsumes the former `MGMT-12` and `SV-12` | `DOM-01` `test_DOM_01_bothDomainSeparators` — `test/v2/Management.t.sol`; the ERC-5267 field-by-field reads stay separate as `MGMT-02` and `SV-DOMAIN` | `forge test`, `forge test --isolate` — 185 passed |
| - [x] | - [ ] | `20261002T032856Z/FUZZ-01` | One successful fuzz property per entry point over a nontrivial domain, through one named struct per family. Every field is live: the pull rail and the submitter pin reach an assertion through the `orderHash` the settlement event now carries, and the nonce through the authenticator's or Permit2's bitmap | `ExecuteFuzz` — `testFuzz_EX_FUZZ_delegatedRail`, `testFuzz_EX_FUZZ_permit2Rail` (`test/v2/ExecuteOrder.t.sol`); `FulfillFuzz` — `testFuzz_FU_FUZZ_delegatedRail`, `testFuzz_FU_FUZZ_permit2Rail` (`test/v2/FulfillOrder.t.sol`) | `forge test`, `forge test --isolate` — 185 passed; all four also pass at 2,048 runs (`FOUNDRY_FUZZ_RUNS`), no counterexamples. Non-vacuity: building the expected order hash with `usePermit2Allowances` flipped fails `testFuzz_EX_FUZZ_permit2Rail` |

| - [x] | - [ ] | `20261002T032856Z/ORD-03` | The fulfillment rail's submitter pin: the named solver settles, a stranger is refused by the hub's own error naming both addresses and burns no Permit2 nonce, and the dead-address sentinel then opens that same order to that same stranger. Added after the plan was frozen — main-thread mutation verification found `UnauthorizedSolver` reachable but untested, the mirror of a site `ORD-02` already covered | `ORD-03` `test_ORD_03_solverPinningAndTheOpenSentinel` — `test/v2/FulfillOrder.t.sol` | `forge test`, `forge test --isolate` — 186 passed. Kills the pass's only surviving mutant: replacing the gate with `true` fails this row and nothing else. Non-vacuity: transposing `UnauthorizedSolver`'s two arguments fails it |

| - [x] | - [ ] | `20261002T032856Z/SV-06b` | Both session-key gates on the **fulfillment** authentication path: a key the owner never approved, and an expired key at the inclusive boundary. `authenticateFulfillment` duplicates `authenticateExecution` rather than sharing it, so `SV-06` and `SV-07` left this copy unconstrained — deleting either check here kept all 186 tests green. Found by the final integrity review, not by the five-leg mutation pass | `SV-06b` `test_SV_06b_unapprovedKeyRejectedOnTheFulfillmentPath`, `SV-07b` `test_SV_07b_expiryBoundaryOnTheFulfillmentPath` — `test/v2/authenticators/SessionOrderAuthenticator.sol` | `forge test`, `forge test --isolate` — 188 passed. Deleting both checks at once fails exactly these two tests and nothing else; each carries a settling control leg |

| - [x] | - [ ] | `20261002T032856Z/SOL-05` | The owner's fix to `FulfillmentSolution`: the route's own `deadline` is checked on both fulfill rails by a modifier, inclusively at the boundary and independently of the approver, and `solution.nonce` is burned — but inside the approval path, so a sentinel-approver route is spent not at all and stays replayable. Three baseline expectations moved with the fix: `SOL-01` and the delegated fuzz property asserted the hub burned no nonce, which is now false, and `AUTH-01b` needed a route nonce of its own | `SOL-05` `test_SOL_05_theRouteDeadlineIsEnforced`, `SOL-06` `test_SOL_06_theRouteNonceIsSpentOnlyUnderANamedApprover` — `test/v2/FulfillOrder.t.sol`; helper `HubBase._route` now hands out a live deadline and a fresh nonce per route | `forge test`, `forge test --isolate` — 190 passed. Mutation: deleting `checkDeadline(solution.deadline)` from both rails fails `SOL-05` alone; deleting the nonce burn fails `SOL-06`, `SOL-01` and the delegated fuzz property |

| - [x] | - [ ] | `20261002T032856Z/ORD-01b` | The asset source moved out of both signed orders and onto the two delegated entry points as a `bool` parameter; the Permit2-signature rails take none, because `permitWitnessTransferFrom` consults no allowance. One signed order now settles on either pull rail at the submitter's choice, bounded by the rest of the order, which is still signed. `ORD-01`'s old property — the flag is covered by the signature — is retired with its premise: the member no longer exists. The two `T712` legs that showed the bit moving the order hash go with it | `ORD-01` `test_ORD_01_theAssetSourceIsTheSubmittersArgument`, `ORD-01b` `test_ORD_01b_thePermit2SignatureRailConsultsNoAllowance` — `test/v2/ExecuteOrder.t.sol`; both order typehash literals in `test/base/V2TestBase.sol` and the two transcribed authenticator signatures in `ExecuteOrder.t.sol`/`Relay.t.sol` lost the `bool` | `forge test`, `forge test --isolate` — 191 passed. Mutation: forcing the source to Permit2 regardless of the argument fails 28 tests. Non-vacuity: `ORD-01b` revokes the plain allowance outright rather than asserting an infinite one went unchanged, which would have proved nothing |

| - [x] | - [ ] | `20261002T032856Z/MC-07` | Gas accounting moved from the four entry points to `multicall`, which reports one figure per entry as `uint256[] gasUsages`; the entry points return only their results. `CallsForwarder` implements `multicall` itself rather than inheriting Solady's, whose return type a Solidity override cannot change, over `Address.functionDelegateCall`; it is declared in `ICallsForwarder` alongside `forwardCalls`, which this run renamed from `forward`. Two baseline gas legs retired with their premise (`SET-03`, `EX-FUZZ`), and `MC-04`'s inner decode corrected: it read `(bytes[], uint256)` off a single-array return, which did not revert but took the array's length for the gas figure | `MC-07` `test_MC_07_gasIsMeasuredPerEntry`, plus the `MC-01` legs — `test/v2/Guards.t.sol` | `forge test`, `forge test --isolate` — 193 passed. Mutation: a constant per entry fails `MC-07`, and so does a running batch total, which an earlier version of this row's oracle did **not** catch. Non-vacuity: the two entries run in both orders, since a cumulative figure always names the second entry the dearer one; cold-storage cost falls on whichever entry runs first, so it works against the assertion in one arrangement |

### Notes for this run

Gas reporting then moved to `multicall`, per entry. Dropping Solady's `Multicallable` for an
`address(this).delegatecall` loop — the form `forward` already uses — cost nothing: the hub went from
22,560 to **22,381**, because four entry points stopped computing and returning a figure.
`Address.functionDelegateCall` was then adopted at the owner's direction: it bubbles a sub-call's
revert data exactly as the hand-written form did, and the one divergence — a **data-less** revert
surfacing as `Errors.FailedCall()` rather than empty — is the clearer error of the two.
`MC-FUZZ`'s expectation moved from `bytes('')` to that selector, which is the only baseline it
touched. It costs 103 bytes, leaving the hub at **22,484** with 2,092 spare. Suite: **193**.

The owner then moved `usePermit2Allowances` out of the signed orders and onto the delegated entry
points, the Permit2-signature rails taking no such argument. Authority: the owner's instruction, and
*"permit2 signature entrypoints do not need it"* for the asymmetry. This is the production-side
resolution of finding E1 — the flag is no longer in the emitted order hash, so there is nothing left
to flip. 51 delegated call sites, both order typehashes, both hand-written literal type strings and
two transcribed authenticator signatures moved with it. The hub measured 22,505 before and
**22,560** after: dropping a struct member did not shrink it.

The owner then fixed `FulfillmentSolution.nonce`/`.deadline` mid-run (finding E2 above). Authority
for the three realigned expectations: the owner's instruction *"fixed solution nonce and deadline"*
plus the live source. All three were assertions that the fields were **not** enforced, so each moved
to the new truth rather than being dropped; none was weakened. Suite: **190**.

Coverage: `forge coverage --ir-minimum --no-match-coverage 'script|test'` **runs again** — 87.10%
lines (412/473), 88.24% branches. Iteration 0 recorded it blocked in both modes, so the unresolved
coverage gate carried by the three earlier runs is closed here. Plain coverage stays blocked by
stack-too-deep inside `ks-common-sc`, a dependency limit. Every uncovered in-scope line is
reconciled in the run's scratch ledger: all but two files are `--ir-minimum` attribution artifacts
(declarations, `assembly` blocks, modifier bodies, constructor lines, inlined call sites), proved
for the most suspicious one — `KSAllowanceHubV2.sol:392` — by replacing it with `revert()` and
watching 43 tests fail.

Main-thread mutation pass, five legs: four killed, one survived and is now closed by `ORD-03`.
Counts recorded per row above were taken before `ORD-03` existed; the suite is **186** tests.

Dead code found while reconciling coverage, left for the owner to decide: the four `*Memory`
helpers in `src/v2/types/ERC20Transfer.sol` and `hash(AuthDelegation memory)` in
`src/v2/types/AuthDelegation.sol` have no caller anywhere in `src/`.

- **Reshape, not re-point.** The user licensed refactoring the files rather than mechanically
  updating them, so `Auth.t.sol` — organised around two entry points and two rails — was split into
  `ExecuteOrder.t.sol` and `FulfillOrder.t.sol`, which is where the four entry points' differences
  actually live. `test/verifiers/**` moved to `test/v2/authenticators/**` to keep the mirror of
  `src/`. The licence covered organisation only; every retired case is named below with the premise
  that is gone.
- **Oracle rule.** `test/base/V2TestBase.sol` gained hand-written literals for `ExecutionOrder`,
  `FulfillmentOrder`, `FulfillmentSolution` and `SolutionApproval`, and `AuthDelegation`'s first
  member was re-transcribed as `address authenticator`. The three deleted approval types' literals
  and builders went with them. No production type string, typehash or hashing helper appears on the
  expected side of any assertion outside the two `types/Eip712.t.sol` files, and the dispatch
  selectors the suite depends on — `initAuthentication`, `updateAuthentication`,
  `authenticateExecution`, `authenticateFulfillment`, `ksExecute`, and the `TransferTokens` topic —
  are all hand-written signature strings.
- **Cases retired, premise by premise.** `AUTH-05` (no `authFlags` for a submitter to mismatch;
  the surviving witness/relayer binding is `AUTH-04`), `AUTH-09` (its claim that the submitter picks
  the allowance rail is now false — `ORD-01` asserts the opposite and keeps both of its rails
  working), `AUTH-12` and `AUTH-12b` (`authFlags` and `_signedCaller` are gone), `CALLS-01..03`
  (the hub burns no nonce for a solution approval any more; the live halves are `SOL-02` and
  `SOL-04`), `OWN-08` (`SolutionApproval` covers `orderHash`, so the approval now *does* reach the
  tail — `SOL-01` asserts the new truth, `AUTH-07b` the approver binding), `SV-12` (subsumed by
  `DOM-01`), `T712-03`, `T712-11`, `T712-12` (`CallsApproval`, `ExecutionApproval` and
  `FulfillmentApproval` are deleted; `T712-16`, `T712-13` and `T712-14` replace them).
- **Baselines re-pointed with their claim intact but their error payload changed.**
  `DeadlineChecker.DeadlinePassed` gained `(uint256 currentTime, uint256 deadline)` in this diff, so
  four expectations moved from a bare selector to the full payload, which is a strengthening.
  `CALLS-04`'s expected error moved from `ECDSAInvalidSignatureLength` to
  `InvalidSolutionSignature`, because the hub now reaches `SignatureChecker`, which returns false
  rather than reverting. Both rest on `AUTH-DIFF-RESTRUCTURE` plus the staged `src/` diff.
- `SET-01` now asserts four topics and compares the third against the order hash rebuilt from the
  literals; `OWN-07` does the same for the fulfillment hash. The log picker and the hand-written
  `TransferTokens` topic moved into `HubBase` so the fuzz properties can share them.
- Eight non-vacuity checks were run by perturbing the **test** side only and confirming each case
  fails; all eight did. They are listed in the rows above.
- Coverage, corrected in the main thread after the implementation shard reported: plain
  `forge coverage` does still fail stack-too-deep in
  `lib/ks-common-sc/src/base/ManagementRescuable.sol`, but
  `forge coverage --ir-minimum --no-match-coverage 'script|test'` **succeeds** and is the command
  this run's numbers come from. The shard's report that `--ir-minimum` fails on
  `src/interfaces/ICREATE3Factory.sol` via `lib/ks-common-sc/script/Base.s.sol` does not reproduce
  once the script path is excluded. Closure for the rows above rests on the non-vacuity checks and
  the mutation pass, with the coverage report as corroboration.

## Run `20261006T083553Z`

Scope: no reshaping. Every case ID carries over and the suite's shape is unchanged; this run
re-verifies it against the `src/` and build changes below, and corrects two things recorded at run
`20261002T032856Z`. `src/v1/**` and `test/v1/**` remain frozen.

The standing size item moved. `optimizer_runs` for `src/v2/KSAllowanceHubV2.sol` is now **2000**,
not 500. At 2000 the hub was 24,628 runtime bytes — **52 over** EIP-170 — before the work in this
run, and is now **23,954** with **622** to spare. Every size figure here is of code alone:
`bytecode_hash` and `cbor_metadata` are off, so solc appends no metadata trailer, which is itself
worth 54 bytes. No test is shaped around any of these figures, and none is shaped around the
margin.

| Implemented and verified | Developer reviewed | Review ID | Contract / flow and coverage summary | Case IDs and test files / functions | Passing command or blocker |
|---|---|---|---|---|---|
| - [x] | - [ ] | `20261006T083553Z/REG-01` | `multicall` is back on `address(this).delegatecall` with `LowLevelCall.bubbleRevert`, reversing the `Address.functionDelegateCall` note below. A sub-call's revert data still bubbles byte for byte; the one divergence is that a **data-less** revert bubbles empty rather than becoming `Errors.FailedCall()`, so `MC-FUZZ`'s expectation returns to `bytes('')` | `MC-03` `test_MC_03_subCallRevertBubbles`, `MC-FUZZ` `testFuzz_MC_FUZZ_valueNeedsAnAllPayableBatch` — `test/v2/Guards.t.sol`. The only baseline assertion this run touches | `forge test`, `forge test --isolate` — **193 passed, 0 failed**. Non-vacuity: `bytes('')` is strict rather than a wildcard — a throwaway probe confirmed it accepts an empty revert and rejects one carrying data (`WithData(1) != EvmError: Revert`), so the case still separates the two shapes |
| - [x] | - [ ] | `20261006T083553Z/OBS-01` | Twelve array digests are taken over the array's own data through Solady's `EfficientHashLib` instead of `keccak256(abi.encodePacked(...))`: the eight member-hash arrays and the four `address[] erc20Targets` in the witness libraries. `abi.encodePacked` pads array members to a word, so a word-sized member array already holds exactly those bytes — but the oracle, not that reasoning, is what establishes the digests are unchanged | `T712-DIFF` `testFuzz_T712_DIFF_*` (six properties), `T712-ARRAY` `test_T712_ARRAY_addressArrayEncoding` — `test/v2/types/Eip712.t.sol` | `forge test` — **28 passed** in the EIP-712 suite, 193 overall. Non-vacuity: the `T712-DIFF` properties compare production hashing against the hand-written literal encoding, so any digest change fails them; they were run against every variant below, accepted and rejected alike |
| - [x] | - [ ] | `20261006T083553Z/ALLOC-01` | Sixteen allocations no longer pay for zeroing they never used: eight via `EfficientHashLib.malloc`, three via `DynamicArrayLib.malloc` (`extractTargets` and `gasUsages`), and five `bytes[]` via `DynamicArrayLibExt.malloc`, a one-function library in `src/base/libraries/` holding the only hand-written assembly added here, since Solady has no `bytes[]` cast. The safety property is that **every slot is written before anything reads one**, checked per site: notably `forwardCalls` reverts on an unsupported selector rather than skipping, and `_executeCalls` covers both ranges of the fulfillment results array | no case ID changes — the whole suite is the check, since a slot left unwritten would surface as a corrupt digest, result or snapshot | `forge test`, `forge test --isolate` — **193 passed, 0 failed**. The eight remaining `new T[]` sites are struct arrays, left alone: `new T[](n)` also allocates and wires `n` struct pointers, so skipping that needs a custom allocator rather than a library call |
| - [x] | - [ ] | `20261006T083553Z/BUILD-01` | Behaviour-preserving `src/` changes re-verified with no test edits: the shared modifier bodies (`checkDeadline`, `checkDelegation`, `lock`'s acquire half) moved into internal functions, and `TransferTokens` moved to a single emit site ahead of an order's transfers. CI runs build, lint and test as three GitHub-hosted jobs on `foundry-toolchain` pinned to `v1.8.1` | no case ID changes | `forge test`, `forge test --isolate` — **193 passed**; `forge fmt --check` clean. CI green on the same tree at **forge 1.8.1**, 193 passed, which also clears the earlier red run: that was the unpinned toolchain drifting to 1.8.4 and failing the test build with `Variable _2 is 3 too deep in the stack`, not anything in `src/` |

### Notes for this run

**How gas was measured, and a warning about how it was measured before.** Only the 161
deterministic cases are read for gas here. Fuzz means are not comparable across builds: a control
that added an unused import — byte-identical contract, no semantic change — still moved 18 cases,
14 of them fuzz, by up to 1,813 gas, because the fuzzer's inputs vary with the compiled artifact and
different inputs mean different array lengths. Any gas figure in an earlier run section that rests
on a `*_FUZZ_*` mean should be re-measured before it is trusted.

**Correction to run `20261002T032856Z`, first item.** That run recorded
`Address.functionDelegateCall` as adopted at the owner's direction, on the grounds that a data-less
revert surfacing as `Errors.FailedCall()` is the clearer of the two errors, and recorded
`MC-FUZZ`'s expectation moving from `bytes('')` to that selector. The owner has reversed both. The
note stays in place because this file is append-only; `REG-01` above is the live statement.

**Correction to run `20261002T032856Z`, second item.** Fourteen `hashMemory` overloads and the four
`*Memory` converters were listed as dead code whose deletion would not shrink the hub. That remains
true, and they are now load-bearing for a second reason: the `T712-DIFF` properties that police
`OBS-01` and `ALLOC-01` hash through them.

**A behaviour change with no case pinning it.** `TransferTokens` now fires before any of an order's
transfers rather than after both legs, so a log consumer can attribute the `Transfer` events that
follow to an `orderHash` without buffering them, which `multicall` batching is what makes worth
having. Nothing in the suite reads the event's *position* in the log stream: the existing assertions
check its payload and that it is emitted once per order, and both hold at either position. Pinning
the order would be new coverage, not a carried baseline, and is not claimed here.

**One regression, named rather than rounded away.** `test_AUTH_03_witnessPinsTheCallList` costs 13
more gas than before this run. It is the residue of `malloc` being shared rather than inlined once
it gained call sites; every other deterministic case is unchanged or cheaper.

**Measured and rejected.** Each was verified against the `T712-DIFF` oracle first, so correctness
was never the reason:

- `optimizer_runs` above 2000. At 3000 the hub grows 194 bytes and
  `test_OWN_04_ownerCallRouterMustBeWhitelisted` costs **5.19%** more; 4000 and 6000 are worse
  again. The order paths move by −0.05% to −0.01%, so there is nothing to buy.
- `EfficientHashLib.free` on the hash arrays. Costs 100 bytes and returns ~34,600 gas of what
  `malloc` won: its guard only resets the free pointer when the buffer is still the top allocation,
  and the inner leaf hashes allocate above it during the loop, so it correctly declines to free
  while the guard is paid for on every call.
- Hand-writing the per-struct leaf hashes in place of `abi.encode`. Costs every rail between 1.4%
  and 3%, since an assembly block stops those small functions being inlined at call sites that run
  once per array member. The win in `OBS-01` is that an array hash runs once per array.
- `unchecked` on the 26 loop counters. Changes **nothing**: with metadata stripped the executable
  code is byte-identical, because `via_ir` already proves `i + 1` cannot overflow from `i < length`.

**These changes do not compose, so combinations were measured rather than summed.** `extractTargets`
and `gasUsages` each save bytes alone and cost 86 together; the five `bytes[]` sites regressed
fourteen order-path cases while inline and none once routed through one shared helper. In every
instance the cause was solc's inliner spending its budget differently, not the edited code: adding a
second `malloc` call site turned it from inlined into a shared function, and every caller then paid
a jump. Any further change here needs re-measuring as a whole.

## Run `20261006T134124Z`

Scope: no reshaping, no case ID changes. Two more allocation changes in `src/v2/types/**` and a
third measurement of the optimizer setting. `src/v1/**` and `test/v1/**` remain frozen.

The hub is **23,642** runtime bytes with **934** to spare, from 23,954 at the previous run. Code
alone, as before: no metadata trailer.

| Implemented and verified | Developer reviewed | Review ID | Contract / flow and coverage summary | Case IDs and test files / functions | Passing command or blocker |
|---|---|---|---|---|---|
| - [x] | - [ ] | `20261006T134124Z/ALLOC-02` | The eight struct-array allocations drop `new` as well. A memory array of structs holds a pointer per element, and assigning a struct to an element builds a fresh struct and writes its pointer, so the bodies `new T[](n)` allocates and zeroes are discarded unread — the waste is per element, not merely the slot. Four private allocators hand back pointer slots: three in `ERC20TransferLib` for Permit2's shapes, one in `GenericCallLib` for `NativeTransfer`. They sit with their types rather than in `src/base/libraries/`, which must not import a Permit2 interface or a `src/v2` type | no case ID changes. `toPermitBatchTransferFrom` and `toSignatureTransferDetails` run on every Permit2 rail and `toAllowanceTransferDetails` on the delegated rail, so the whole suite is the check, against the **real Permit2** on the fork rather than a mock | `forge test`, `forge test --isolate` — **193 passed, 0 failed**; EIP-712 suite **28 passed**. 260 bytes freed and 57,252 gas off 63 of the 161 deterministic cases, none regressed. The premise was read off the optimised IR first: the element assignment compiles to `mstore(index_access(...), freshBody)`, a pointer write, not a copy into the pre-allocated body |
| - [x] | - [ ] | `20261006T134124Z/CD-01` | Three loops over a `calldata` array bound each element to a `memory` local, which copies the struct out of calldata per element to read two of its fields. They bind `calldata` now, as every other loop in `src/v2/types/**` already did | no case ID changes — `toPermitBatchTransferFrom`, `toSignatureTransferDetails` and `toAllowanceTransferDetails` in `src/v2/types/ERC20Transfer.sol`. The `*Memory` twins are untouched: their source is already memory, so the binding copies a pointer and not a struct | `forge test`, `forge test --isolate` — **193 passed, 0 failed**. 52 bytes freed and 15,741 gas net: the Permit2 rails drop 1,200 to 1,820 each, against 19 cases on the delegated and native paths costing 34 to 51 more |

### Notes for this run

**Why the struct arrays were passed over at the previous run, and why that was wrong.** They were
recorded as needing a custom allocator to wire `n` struct pointers. No wiring is needed: the
assignment writes its own pointer, so an allocator that returns bare slots is sufficient and the
pre-allocated bodies were never read. That made these the most wasteful of the allocations rather
than the hardest, and they were the largest single win of either run.

**The memory layout rule this turns on,** since it is not what the ABI encoding suggests. In memory
an element is stored inline only when it is a value type that fits a word: `uint256[]`, `bytes32[]`
and `address[]` are flattened, which is what lets `OBS-01` hash the data region in place and
`asAddressArray` cast for free. A struct is a reference type there and stored by pointer **even when
every field is static and its size is known at compile time**. Calldata and storage flatten such a
struct; memory does not. A probe confirmed it: for `uint256[]` and `bytes32[]` the slot holds the
value, while for a two-word static struct the slot holds a memory offset and the value is one hop
away. One consequence worth keeping: ABI-encoded bytes cannot be reinterpreted as a `T[] memory` of
structs, which is why `abi.decode` must walk the encoding, and why staying in `calldata` — `CD-01` —
costs nothing.

**The optimizer setting was measured a third time and still holds at 2000.** With 934 bytes spare
size is no longer the constraint, so this is a gas choice. At 3000 the deterministic cases cost
202,646 more gas and `OWN-04` 5.20% more, at 4000 500,357 and 5.17%, while the order paths move
between −0.05% and −0.01%. Three sweeps across three quite different states of `src/` have now
agreed, so 2000 reads as an optimum rather than an artifact of one of them. A 6000 leg reported an
implausible test count and wrote no snapshot; it was not pursued, 3000 and 4000 being decisive.

**`new T[](` no longer appears anywhere in `src/v2`.** Every allocation goes through an allocator
that leaves memory the code is about to overwrite alone: eight `EfficientHashLib.malloc`, three
`DynamicArrayLib.malloc`, five `DynamicArrayLibExt.malloc`, and the eight struct slots above.

## Run `20261006T172638Z`

Scope: no change to `src/**` or `test/**`. This run corrects the evidence recorded for the
optimizer setting at run `20261006T134124Z` and records which instrument to use for gas in this
repository. The hub is unchanged at **23,642** runtime bytes with **934** to spare, and the suite
unchanged at **193**.

| Implemented and verified | Developer reviewed | Review ID | Contract / flow and coverage summary | Case IDs and test files / functions | Passing command or blocker |
|---|---|---|---|---|---|
| - [x] | - [ ] | `20261006T172638Z/MEAS-01` | The optimizer setting re-measured from the hub's own per-entry gas rather than from test totals. `multicall` returns `gasUsages`, taken inside the hub as `gasStart - gasleft()` around one delegatecall, so it cannot see mock deployment, harness framing or fuzz inputs. Against that, 500 to 2000 is worth 351 gas on a cold execution order and 84 on an empty `forwardCalls`; above 2000 the hub saves 39 gas at 3000 and 54 at 4000, and 6000 is identical to 4000. **2000 holds**, now because the remaining gain is 0.03% of an order against 194 to 495 bytes, not because higher settings cost gas | `MC-07` `test_MC_07_gasIsMeasuredPerEntry` — `test/v2/Guards.t.sol` — is the standing case for the figures themselves. The measurement above used a throwaway probe batching an empty `forwardCalls` with two execution orders, read at five settings and then removed | `forge test`, `forge test --isolate` — **193 passed, 0 failed** at 500, 2000, 3000, 4000 and 6000. Sizes: 21,747 / 23,642 / 23,836 / 23,987 / 24,137 |

### Notes for this run

**Correction to run `20261006T134124Z`.** Its optimizer note records 3000 as costing 202,646 more
deterministic gas with `OWN-04` 5.20% worse. Both figures are of the test harness, not the hub.
`compilation_restrictions` pins `src/v2/KSAllowanceHubV2.sol` to the `runs-N` profile, and that
profile reaches every file that imports the hub — which is the whole test tree and its mocks. At
3000 `RouterMock` deploys 2,151 bytes rather than 1,900, and each in-body deployment pays the
difference at 200 gas per byte. Tracing `ROUTER-01` at both settings shows it exactly: every
sub-call flat, the hub call itself 77,265 against 77,259 — six gas **cheaper** at 3000 — and
`new RouterMock` 462,839 against 515,393, which is 52,554 of the 52,588 the case moved. The
conclusion of that note survives; its evidence does not.

**`forge test --gas-report` is not comparable across builds either, unless the fuzz cases are
excluded.** Over the whole suite it reported `executeOrderWithPermit2Signature`'s median falling
60,755 gas between 2000 and 3000 while its min moved 0 and its max 141, which no uniform shift can
produce: the fuzz cases contribute most of the calls and their inputs vary with the artifact. Run
with `--no-match-test 'Fuzz|FUZZ'`, call counts identical, the four entry points move between 15 and
45 gas.

**So three instruments each have a failure mode, and only one of them does not.** A test's total gas
carries mock deployment cost, which moves with the hub's own size. A fuzz mean is not comparable
between builds at all. A gas report inherits the fuzz problem unless those cases are excluded. The
figures `multicall` already returns carry none of this, and are what gas accounting was moved into
`multicall` for. Any gas claim in an earlier run section that rests on a test total or a fuzz mean
should be re-measured against them before it is relied on.

## Run `20261007T032617Z`

Scope: the two all-static leaf hashes read their struct's calldata words directly, four new cases
hold the invariant that makes that sound, and the optimizer setting moves to 3000. `src/v1/**` and
`test/v1/**` remain frozen. The hub is **23,717** runtime bytes with **859** to spare.

| Implemented and verified | Developer reviewed | Review ID | Contract / flow and coverage summary | Case IDs and test files / functions | Passing command or blocker |
|---|---|---|---|---|---|
| - [x] | - [ ] | `20261007T032617Z/HASH-01` | `ERC20TransferLib.hash` and `ERC721TransferLib.hash` take their three member words straight from calldata with one `calldatacopy` instead of `abi.encode`. For a struct whose members are all static the calldata region already **is** the EIP-712 member encoding, so the digest is unchanged — established by the oracle, not the reasoning. The words are copied **unmasked**, where `abi.encode` masks each field on read, and that read is also what rejects a word carrying dirty high bits | `T712-DIFF` `testFuzz_T712_DIFF_erc20Transfer` / `_erc721Transfer` reach the calldata variant through an external call, so they compare it against the memory variant on every input — which is why both `*Memory` twins stay on `abi.encode` rather than being converted with them | `forge test`, `forge test --isolate` — **197 passed, 0 failed**; EIP-712 suite **28 passed**. 132 bytes freed; 413 gas per ERC20 or ERC721 leg, flat from 1 leg to 20 |
| - [x] | - [ ] | `20261007T032617Z/DIRTY-01` | What makes `HASH-01` sound is that settling an order reads the same fields through Solidity, and Solidity validates a calldata `address` **on access** rather than at decode: a parameter behind a `calldata` struct or array is checked the moment a field is read, and not at all if none is. A revert anywhere unwinds the frame, so a digest taken from dirty words is never observable — but only while some reader remains. These four cases hold that on every rail, submitting the dirty payload first and the identical clean payload second, so the refusal is attributable to the dirtied word rather than to anything else the payload carried | `DIRTY-01..04` — `test/v2/DirtyCalldata.t.sol`, one per rail, over `_assertDirtyTokenWordIsRefused` in `test/v2/base/HubBase.sol` | `forge test`, `forge test --isolate` — **4 passed**, 197 overall. Non-vacuity: each case's clean leg settles, so a case cannot pass by submitting a payload that was malformed anyway |
| - [x] | - [ ] | `20261007T032617Z/BUILD-02` | `optimizer_runs` for the hub moves from 2000 to 3000, and `cbor_metadata` is no longer disabled | no case ID changes | `forge test`, `forge test --isolate` — **197 passed** at 3000. Costs 207 bytes — 194 for the setting and 13 for the metadata trailer returning — against **39 gas** per execution order, measured from the figures `multicall` returns |

### Notes for this run

**Where the 413 gas comes from.** Three reads of a calldata field each repeat the index bounds
check, the offset arithmetic, the `calldataload` and the validation, and the compiler shares almost
none of it: reading one slot five times costs 344 gas against 421 for five different slots, so only
about 18% is eliminated. Calldata is immutable for the life of a call, so every check after the
first is provably redundant; solc simply does not remove them. About 15 gas of the 413 is instead
the memory `abi.encode` grows for a buffer it hashes once and never reclaims, which is why the
saving creeps from 413 at one leg to 415 at twenty rather than staying exactly flat.

**Why the free memory pointer and not the scratch space.** A four-word hash spans `0x00`–`0x80`, and
only `0x00`–`0x40` is scratch, so the alternative writes the free memory pointer and the zero slot
and must restore both. That is sound — Solady's `ECDSA.recover` does exactly it under
`memory-safe-assembly` — but it costs 14 bytes more than reading `mload(0x40)` and leaving it alone,
because the save and restore cost about what the load saved. Writing those slots **without**
restoring them, and dropping the annotation to make that honest, costs 876 bytes: the annotation is
what lets solc keep optimising memory across the contract. `EfficientHashLib` draws the same line,
using the scratch space only while a hash fits in two words.

**A compiler limit worth knowing about.** Adding both fulfillment cases to `FulfillOrderTest`
produces a solc **internal compiler error** under `via_ir`. Either alone compiles; both together do
not, and the error names no source location. That contract is at a limit, which is why
`DIRTY-01..04` live in a file of their own rather than beside the rails they exercise. The next case
added to `FulfillOrderTest` may hit the same wall with nothing to go on.

**Measured and not taken.** `GenericCallLib.hash` can copy its two static words and keep
`keccak256(self.data)` for the third, worth 46 bytes and 243 gas per router call. It is left out
because `router` and `value` would stop being masked by the hash while no case dirties a `router`
word — the invariant would be argued rather than held. It wants a `DIRTY-05` first.

## Run `20261007T110305Z`

Scope: the struct is now the source of truth for every signed type, Permit2's included, and no hand-
written EIP-712 type string for a hub type remains in the suite. `src/v1/**` and `test/v1/**` remain
frozen. No production code changed: `forge build src` reports no change, and the hub is still 23,717
runtime bytes.

| Implemented and verified | Developer reviewed | Review ID | Contract / flow and coverage summary | Case IDs and test files / functions | Passing command or blocker |
|---|---|---|---|---|---|
| - [x] | - [ ] | `20261007T110305Z/712-02` | The Permit2 signed type is declared as a struct and hashed from the schema `forge bind-json` derives from it, replacing the hand-rolled mirror of Permit2's layout. `PermitBatchWitnessTransferFrom` is declared twice, once per witness, because Permit2 gives both variants the same type name | `T712-SCHEMA-PERMIT2` in `test/v2/types/SchemaAudit.t.sol`; `test/base/types/Permit2{Execution,Fulfillment}Witness.sol`, `test/base/types/TokenPermissions.sol`, `SchemaHash.permit2{Execution,Fulfillment}Witness` | `forge test` |
| - [x] | - [ ] | `20261007T110305Z/712-03` | The last seven hand-written type strings are gone. `AuthDelegation` and `SessionKey` hash from their schemas; `SessionApproval` takes its typehash from its schema, keeping the field signature production uses. Five `T712-*` rows that compared a production typehash against a transcription are deleted as duplicates of the schema audit, which covers all thirteen | `T712-08b`, `T712-09`, `T712-10` reshaped; `T712-04..08` deleted; `test/base/V2TestBase.sol` 425 -> 383 lines | `forge test` |
| - [x] | - [ ] | `20261007T110305Z/BIND-01` | `forge bind-json` regeneration is a fixed point, not a one-shot, and the `[bind_json] include` set in `foundry.toml` is what makes it reproducible. The CI guard added in `ecf7df5` is sound because the committed bindings already sit at the fixed point | no case ID changes; `utils/JsonBindings.sol` at 17 schemas | `forge bind-json && git diff --exit-code utils/JsonBindings.sol` |

### Notes for this run

**`forge bind-json` converges rather than completing.** The generated file is itself compiled and
imports the types it binds, so a type added to the include set appears only on the *following* run:
the first run compiles a tree in which nothing imports it yet. Deleting `utils/JsonBindings.sol`
before regenerating makes this worse, because that removes a project file the types are reached
through, and the run then emits a subset. Run it twice after changing the set, leave the output in
place, and the result is byte-identical on every run after that — verified 6/6 on the previous set
and 3/3 on this one. An earlier reading of this behaviour as nondeterminism in the tool was wrong,
and was an artefact of deleting the file between runs.

**The colliding type name is handled, not dropped.** Permit2 hardcodes the name
`PermitBatchWitnessTransferFrom` for both witness variants, so the two declarations collide. `bind-
json` suffixes them `_0` and `_1` in discovery order and emits both. Which suffix is which is not
assumed: `T712-SCHEMA-PERMIT2` asserts each against the stub Permit2 prepends plus the witness
string the hub passes, so a swap fails there, and swapping them by hand was confirmed to fail.

**Why Permit2's own constants are on the expected side and its functions are not.** The signing
helpers read `_PERMIT_BATCH_WITNESS_TRANSFER_FROM_TYPEHASH_STUB`, `_TOKEN_PERMISSIONS_TYPEHASH` and
`_PERMIT_BATCH_TRANSFER_FROM_TYPEHASH` from the vendored `test/libraries/PermitHash.sol`. Those are
Permit2's spec and name no hub type, so they carry no circularity. `hashWithWitness` still does,
because the witness type string is its parameter, and stays unused.

**`SessionApproval` keeps a typehash rather than a struct hash.** Production hashes it from a key
that is already hashed, and `T712-10` uses a key hash of its own choosing that is no real key's
hash. Hashing the struct through the cheatcode would have forced that case to supply a real
`SessionKey` and quietly narrowed what it pins, so only the typehash is derived.

**Replacing an oracle is where coverage disappears quietly, so each conversion was mutation-
tested.** Reordering the referenced types inside the production witness type string fails
`T712-SCHEMA-PERMIT2`; swapping `nonce` and `deadline` in `AuthDelegationLib.hash` fails `T712-08b`;
hashing a session key's `publicKey` length instead of its content fails `T712-09`. The deleted
`T712-04..08` rows were duplicates in the strict sense that the schema audit asserts the same
equality with a mechanically derived string in place of a transcribed one.

## Run `20261007T111320Z`

Scope: `relayer` and `solver` are enforced on the delegated rails, which is where they were declared
but never read. One production change, in `KSAllowanceHubV2` only. `src/v1/**` and `test/v1/**`
remain frozen. The hub is **23,921** runtime bytes with **655** to spare, up 204 from the fix.

| Implemented and verified | Developer reviewed | Review ID | Contract / flow and coverage summary | Case IDs and test files / functions | Passing command or blocker |
|---|---|---|---|---|---|
| - [x] | - [ ] | `20261007T111320Z/SUBMIT-01` | **Production fix.** The two delegated entry points now refuse a caller who is neither the `relayer`/`solver` the order names nor the owner, unless the order left the field open. The pin was enforced on the Permit2 rails only, so an order naming one relayer could be submitted by anyone holding a valid credential | `ORD-02b`, `ORD-03b` in `test/v2/SubmitterPinning.t.sol` | `forge test` |

### Notes for this run

**What the gap was.** `ExecutionOrder.relayer` and `FulfillmentOrder.solver` are documented as who
may submit an order, without qualification, and the struct field is covered by the order hash either
way. `executeOrderWithPermit2Signature` and `fulfillOrderWithPermit2Signature` read it; the two
delegated entry points never did. The field was therefore advisory on half the surface: an owner who
named one relayer got no narrowing at all from naming it, as long as the submitter could satisfy the
authenticator.

**Why the authenticator cannot be the place this is checked.** It receives the whole order, so a
particular authenticator could compare the submitter itself, and `SessionOrderAuthenticator` does
not. Leaving it there would make the guarantee a property of whichever authenticator an owner
happened to delegate rather than of the hub, and `IOrderAuthenticator` is an open interface. The hub
reads the pin itself, and the interface NatSpec now says so — it previously claimed the hub checks
only the delegation.

**The owner is not bound by the field.** `msg.sender == owner` short-circuits ahead of the check,
which is what the Permit2 rails already do. The field exists to bound everybody else, and an owner
acting for themselves has nothing to be bound to. The last leg of each new case settles an owner-
submitted order that names a different relayer, so this carve-out is pinned rather than assumed.

**The gate is read before the credential,** so an unnamed submitter is refused as such even when the
credential it presents could never have passed. The third leg of each case submits a one-byte
signature and still expects `UnauthorizedRelayer`/`UnauthorizedSolver`, which is what fixes the
ordering rather than leaving it to whichever check happens to run first.

**Both new cases fail against the pre-fix hub** with `next call did not revert as expected` — the
stranger settled the pinned order — and pass after. That direction was checked explicitly, because
the rest of the suite passes unchanged either way: nothing existing exercised a pinned relayer on a
delegated rail, which is how the gap survived `ORD-02` and `ORD-03`.

**A codeless authenticator is not a bypass.** `_checkDelegation` permits `address(0)`, and a
stranger passing it would reach `IOrderAuthenticator(address(0)).authenticateExecution`. That
reverts: solc emits an `extcodesize` check for the call, so it fails with `call to non-contract
address` rather than succeeding on empty returndata. Verified against both the pre-fix and post-fix
trees before this fix was written, since the fix would otherwise have been the only thing standing
between a stranger and an open order.

**`GenericCallLib.hash`'s partial `calldatacopy` is dropped,** not deferred. The previous run
recorded it as wanting a `DIRTY-05` first; it is no longer intended, and the 46 bytes and 243 gas
per router call it was worth are left on the table.

**These cases live in `test/v2/SubmitterPinning.t.sol`** rather than beside `ORD-02` and `ORD-03`,
because `FulfillOrderTest` produces a solc internal compiler error under `via_ir` when another case
joins it, as the previous run recorded.

## Run `20261007T114314Z`

Scope: a nonce belongs to the signer of the data it guards. `UnorderedNonce` keys by namespace and
keeps an address overload, so the call sites that were already right read as they did and the diff
is the two that moved: `KSAllowanceHubV2` and `SessionOrderAuthenticator`. `src/v1/**` and
`test/v1/**` remain frozen and do not use this base. The hub is **23,907** runtime bytes with
**669** to spare, 14 fewer than before the change.

| Implemented and verified | Developer reviewed | Review ID | Contract / flow and coverage summary | Case IDs and test files / functions | Passing command or blocker |
|---|---|---|---|---|---|
| - [x] | - [ ] | `20261007T114314Z/NONCE-06` | **Production change.** `UnorderedNonce` keys its bitmap by a `bytes32` signer namespace rather than by an address, and each nonce now burns against whoever signed the data it guards: the approver for a route, the session key for an order, the owner for a delegation or a key approval. Two kinds of signed data in one contract no longer collide on a number | `NONCE-06`, `NONCE-07` in `test/v2/NonceNamespace.t.sol`; `MC-06` split in two | `forge test` |

### Notes for this run

**Where each nonce now lands, and who signs.** `AuthDelegation` and `SessionApproval` are verified
against the owner and keep the owner's namespace, which is what they always had. `SolutionApproval`
is verified against `order.solutionApprover` and moves there. Both order types are verified against
the session key and move to its hash, which the two `authenticate*` paths already had in hand for
the approval lookup.

**The collision this removes.** Each contract held two kinds of signed data under one owner-keyed
bitmap, so unrelated signatures competed for the same numbers: spending 7 as the owner blocked a
session key's order with nonce 7, and spending 9 as the owner blocked an approver's route with nonce
9. `NONCE-06` and `NONCE-07` spend the number in the owner's namespace first and then settle
somebody else's signature carrying it. Keying either one back to the owner fails them with
`NonceAlreadyUsed()`, so they pin the collision rather than restating the mapping.

**An order nonce is now spendable once per session key, and that is intended.** The order digest
does not include the key, so two approved keys sign the same digest and each has a namespace of its
own; the identical order settles once per key, where one owner-keyed bitmap used to stop the second.
An approved key already acts on the account with the owner's authority, so a second key authorising
the same transfer is the owner authorising it twice. This is a property of approving a key, not of
how the nonce is keyed.

**The owner can no longer revoke a single pending key-signed order,** because `revokeNonce` reaches
only the caller's own namespace. That follows from the same thing: the lever against a key is the
key, and revoking it withdraws the authority behind every order it signed.

**`MC-06` splits in two,** which is the clearest statement of the change in the suite: the batch's
session approval and its order used to be one assertion over one bitmap, and are now one assertion
per namespace — the approval against the owner, the order against the key.

## Run `20261007T125149Z`

Scope: the bound Permit2 declarations move into the two witness files, which makes the `[bind_json]`
file set two `src` patterns and nothing else. No behaviour changes and no code is emitted: the hub
is still **23,907** runtime bytes with **669** to spare.

| Implemented and verified | Developer reviewed | Review ID | Contract / flow and coverage summary | Case IDs and test files / functions | Passing command or blocker |
|---|---|---|---|---|---|
| - [x] | - [ ] | `20261007T125149Z/BIND-02` | The two `PermitBatchWitnessTransferFrom` declarations move from `test/base/types/` to the witness files they wrap, and `TokenPermissions` comes from `ISignatureTransfer` instead of a redeclaration. Supersedes the file paths named in run `20261007T110305Z/712-02` | `T712-SCHEMA-PERMIT2` unchanged; declarations now in `src/v2/types/{Execution,Fulfillment}Witness.sol` | `forge test` |

### Notes for this run

**Why the declarations moved.** The bindings guard failed on CI and nowhere else: the runner's
regenerated file came back without `schema_TokenPermissions` or either
`schema_PermitBatchWitnessTransferFrom` variant, which are exactly the three that were declared
under `test/`. Eliminated with evidence: stale local artifacts (a pristine tracked-only checkout
emits all of them), an uncompiled test tree (the check was moved into the test job, which had
already run the suite, and it still failed), missing or ignored files (committed, and the suite
imports them), toolchain drift (`forge 1.8.3` on the runner), and local environment overrides
(none). What remains is that `**/test/base/types/*.sol` matches nothing there while the two `src`
patterns match, or that the whole `include` is ignored there and the surviving schemas come from a
fallback over `src`. Both are answered by declaring the types under `src`, which is why this was
preferred over guessing at glob forms, each of which costs a CI round trip to test.

**Where they live now.** Each variant sits beside the witness it wraps, so the collision that forced
two files is resolved by files that already had to exist. The suffixes still follow discovery order
and still come out `_0` for execution and `_1` for fulfillment, and `T712-SCHEMA-PERMIT2` pins which
is which rather than trusting it.

**`TokenPermissions` carries no schema and needs none.** It belongs to `ISignatureTransfer`, which
the hub already imports, so redeclaring it was redundant; being outside the bound file set it gets
no constant of its own. Both Permit2 schemas quote its `encodeType` in full as a referenced type, so
the two assertions that compare those complete strings are what pin it. The standalone assertion
against `PermitHash._TOKEN_PERMISSIONS_TYPEHASH` is dropped with it; that constant is Permit2's own
and the witness-free rail exercises it against the real Permit2 on the fork.

**The guard runs in the build job.** Every bound type is under `src`, which `forge build src
--sizes` compiles, so the check sits directly after it. It passed through the lint job, which
compiles nothing, and the test job, which compiles far more than the bindings need; the build job is
the one whose output the bindings are derived from. Verified by running that job's two steps against
a pristine tree with nothing pre-built.

**Struct declarations emit no code,** so the hub's size is unchanged at 23,907 bytes. Regeneration
is idempotent and a pristine tracked-only tree reproduces the committed file byte for byte at 16
schemas.

## Run `20261007T180905Z`

Scope: the order carries the account it draws on. `KSAllowanceHubV2`, both order types,
`SolutionApproval`, `IOrderAuthenticator` and `SessionOrderAuthenticator`. `src/v1/**` and
`test/v1/**` remain frozen. The hub is **24,081** runtime bytes with **495** to spare, 174 more than
before.

| Implemented and verified | Developer reviewed | Review ID | Contract / flow and coverage summary | Case IDs and test files / functions | Passing command or blocker |
|---|---|---|---|---|---|
| - [x] | - [ ] | `20261007T180905Z/ORDER-01` | **Production change.** `owner` becomes the first member of {ExecutionOrder} and {FulfillmentOrder}, so the signed order names the account it draws on. The four order entry points lose their `owner` argument, as do `IOrderAuthenticator`'s two `authenticate*` functions and the hub's `_settleExecution`, `_settleFulfillment` and `_approveSolution` | no case ID changes; 106 call sites, 4 struct literals, 2 authenticator mocks and 3 hand-written ABI signature strings updated | `forge test` |
| - [x] | - [ ] | `20261007T180905Z/ORDER-02` | `SolutionApproval` drops its own `owner` member, which `orderHash` covers. `checkDelegation` moves ahead of `guardNativeSpend` on both delegated entry points | `T712-09`, `T712-SCHEMA` unchanged; `SolutionApprovalLib.hash` and `hashMemory` lose a parameter | `forge test` |

### Notes for this run

**What the 174 bytes buy, and where they went.** Adding the member and dropping the argument cost
254. Hoisting `order.owner` into a local recovered only 10, so the cost is the extra member in two
typehashes and the calldata offsets rather than repeated loads, and the local was not kept. Dropping
the redundant `owner` parameters from the authenticator interface and the three hub helpers
recovered 60, and `SolutionApproval` losing its own member another 20.

**The Permit2 witness type strings are untouched.** {ExecutionWitness} and {FulfillmentWitness} are
projections of an order rather than the order itself, so neither their `encodeType` nor the strings
the hub hands Permit2 move.

**`ORD-04` covers the member on the delegated rail,** beside the submitter cases: the same signature
is refused against another account that approved the same key, then settles against the one it
names. The repointed leg runs first, because the authenticator burns its nonce ahead of the
signature check and the refusal rolls that back, leaving the second leg the same number to spend.

**`checkDelegation` runs before `guardNativeSpend`,** so an authenticator the owner never delegated
is refused before any native-spend accounting is set up.

## Run `20261007T181946Z`

Scope: test files only. No production code and no case was added, removed or changed; the suite is
the same 191 cases before and after. Every file is now named for what it holds, and no two share a
name.

| Implemented and verified | Developer reviewed | Review ID | Contract / flow and coverage summary | Case IDs and test files / functions | Passing command or blocker |
|---|---|---|---|---|---|
| - [x] | - [ ] | `20261007T181946Z/GROUP-01` | Four renames: `Relay`→`Forwarder` (holds `FWD`/`PF`), `SubmitterPinning`→`OrderParties` (`ORD-02b..04`), `DirtyCalldata`→`CalldataHygiene` (`DIRTY`), and `authenticators/types/Eip712`→`AuthenticatorEip712`, which ends two files sharing the name `Eip712.t.sol` | no case ID changes | `forge test` |
| - [x] | - [ ] | `20261007T181946Z/GROUP-02` | Two splits: `MC` leaves `Guards.t.sol` for `Multicall.t.sol`, and `NONCE` leaves `Delegation.t.sol` for `Nonces.t.sol`, which absorbs `NonceNamespace.t.sol` | no case ID changes | `forge test` |

### Notes for this run

**What the names were hiding.** `Guards.t.sol` held the whole batching surface, which is not a
guard; `Delegation.t.sol` held the nonce bitmap, which has nothing to do with delegating;
`Relay.t.sol` named no entry point, while holding `forwardCalls` and permit forwarding; and two
different files were both called `Eip712.t.sol`, so a stack trace naming one was ambiguous.

**Which helpers moved with `MC`.** The USDC permit chain — `_usdcPermitCall`,
`_usdcDomainSeparator`, `_usdcNonce` and `L_PERMIT_TYPEHASH` — turned out to be reachable only from
`MC-01`, as did `S_UPDATE_AUTHENTICATION`, `_orderCalldata`, `_isPayableItem` and the `BatchFuzz`
struct, so all of them moved. `_executeAtDeadline`, `_fulfillAtDeadline` and `_nativeSpendLeg`
belong to `GUARD` and stayed. `AMOUNT`, `PREFUND`, `VALUE` and `ROUTER_ROLE` are one-line literals
both files need and are now declared in each.

**Two families are still split, by design.** `ORD` sits in `ExecuteOrder`, `FulfillOrder` and
`OrderParties`, which is a split by rail and then by the parties an order names. `T712` sits in
`types/Eip712`, `types/SchemaAudit` and `authenticators/types/AuthenticatorEip712`, which is a split
by subject. Neither is the accident that `NONCE` and `MC` were.

**`OrderParties.t.sol` is the file the earlier runs call `SubmitterPinning.t.sol`,** and
`CalldataHygiene.t.sol` the one they call `DirtyCalldata.t.sol`. Both still exist as separate files
for the reason those runs record: `FulfillOrderTest` produces a solc internal compiler error under
`via_ir` when another case joins it.

## Run `20261007T183512Z`

Scope: test files only, no case added or removed. Five hand-written function signatures give way to
`abi.encodeCall` and `.selector` on the interfaces that declare them.

| Implemented and verified | Developer reviewed | Review ID | Contract / flow and coverage summary | Case IDs and test files / functions | Passing command or blocker |
|---|---|---|---|---|---|
| - [x] | - [ ] | `20261007T183512Z/ABI-01` | `initAuthentication`, `updateAuthentication`, `authenticateExecution`, `authenticateFulfillment`, `ksExecute` and `transfer` are named through their interfaces instead of transcribed signature strings. The six `permit` signatures stay literal | no case ID changes; `DEL-13..15`, `MC-06`, `AUTH-11`, `FWD-*`, `SET-*` | `forge test` |

### Notes for this run

**A transcribed signature only earns its keep when the name is ambiguous.** The six `permit`
constants share one name across six interfaces, so a selector there has to be named by its argument
list. Every other entry point in the suite has a unique name, and `abi.encodeCall(IFace.fn, (...))`
is checked by the compiler against the declaration. The two `authenticate*` strings carried the
whole order tuple and had to be hand-edited when the order gained a member, which is the failure the
transcription invited.

**This does not make the refusals circular.** `FWD-16` asserts that `forwardCalls` refuses these
selectors, so a selector the hub wrongly allowlisted would not revert and the case would fail,
wherever the expected value came from. What the transcription used to guard — that the string names
a function that exists — the compiler now guarantees, which is why the three
`_assertReachesTheHubOnlyGate` legs no longer carry that argument and state only what they still
hold: the refusal is the forwarder's own.

## Run `20261007T183815Z`

Scope: a coverage check. No code changed and no case was added; this run exists to replace what
earlier runs record as an unresolved coverage gate.

| Implemented and verified | Developer reviewed | Review ID | Contract / flow and coverage summary | Case IDs and test files / functions | Passing command or blocker |
|---|---|---|---|---|---|
| - [x] | - [ ] | `20261007T183815Z/COV-01` | `forge coverage --ir-minimum` runs. The hub reports **100% branch** (17/17) and **100% function** (13/13) coverage; `AuthDelegator` is 100% throughout and `CallsForwarder` 100% on branches and functions | no case ID changes | `forge coverage --ir-minimum --report summary` |

### Notes for this run

**The gate is closed, with a caveat.** Earlier runs record `forge coverage` as not running at all.
Plain mode still fails, with stack-too-deep in `lib/ks-common-
sc/src/base/ManagementRescuable.sol:63`, which is a vendored dependency. `--ir-minimum` now
completes, where it previously failed in the analyser on the `erc7201` builtin.

**Its line attribution is not trustworthy here, so the line percentages should not be read as
gaps.** `--ir-minimum` compiles with different codegen from the profile the suite runs under, and
the mapping drifts: it reports `KSAllowanceHubV2`'s constructor body uncovered though every `setUp`
deploys the hub, the first statements of `forwardCalls` and `multicall` uncovered though 29 cases
call them, `PackedBits.pos` uncovered though `PB-02` pins it, and the whole of
`SessionOrderAuthenticator.constructor` uncovered though the authenticator is deployed in every
authenticator case. Branch and function counts held up under spot checks; line counts did not.

**The only functions nothing calls are the four `*Memory` conversions in `ERC20Transfer.sol`** —
`toPermitBatchTransferFromMemory`, `toSignatureTransferDetailsMemory`, `extractTargetsMemory` and
`toAllowanceTransferDetailsMemory`. They are the integration surface for a caller holding an order
in memory, they are `internal` and uncalled so they carry no bytecode, and they are deliberately not
covered: a test over code no production path reaches would raise the percentage without testing
anything. They are why `ERC20Transfer.sol` reads 56%.


## Run `20261009T042147Z`

Scope: the two-tier key rails in `SessionOrderAuthenticator`. The owner's rail keeps its payload and
every existing case, so this run is additive: it covers the new master-key rail of
`updateAuthentication` and session-key resolution in `authenticate*`.

| Implemented and verified | Developer reviewed | Review ID | Contract / flow and coverage summary | Case IDs and test files / functions | Passing command or blocker |
|---|---|---|---|---|---|
| - [x] | - [ ] | `20261009T042147Z/TIER-01` | A master key approves a session key, which then authenticates on both order rails; the grant lands in `sessionKeyMaster` and not in `masterKeys`, and a master's revocation of its own session key clears it | `SV-TIER-01`, `SV-TIER-01b`, `SV-TIER-09`, `SV-FUZZ-TIER`; `test/v2/authenticators/SessionOrderAuthenticator.t.sol` |`forge test --match-path 'test/v2/authenticators/SessionOrderAuthenticator.t.sol'` |
| - [x] | - [ ] | `20261009T042147Z/TIER-02` | Who may grant a session key, and how far: a session key and an unapproved key are both refused `MasterKeyNotApproved`, and `SessionKeyOutlivesMasterKey` holds at the expiry boundary — equal passes, one second longer does not | `SV-TIER-02`, `SV-TIER-03`, `SV-TIER-05`; same file |`forge test --match-path 'test/v2/authenticators/SessionOrderAuthenticator.t.sol'` |
| - [x] | - [ ] | `20261009T042147Z/TIER-03` | The cascade: revoking a master refuses every session key under it with `SessionKeyNotApproved` and re-approving the identical credential revives them; a key holding both grants resolves through its master | `SV-TIER-04`, `SV-TIER-10`; same file |`forge test --match-path 'test/v2/authenticators/SessionOrderAuthenticator.t.sol'` |
| - [x] | - [ ] | `20261009T042147Z/TIER-04` | What the master's signature covers and where its nonce lands: a wrong signer and an approval bound to another owner are both refused, and the nonce burns in the master key's namespace rather than the owner's or the session key's | `SV-TIER-06`, `SV-TIER-07`, `SV-TIER-08`; same file |`forge test --match-path 'test/v2/authenticators/SessionOrderAuthenticator.t.sol'` |
| - [x] | - [ ] | `20261009T042147Z/OBS-01` | `SessionKeyApproval`, the type a master key signs, against the `encodeType` its own struct declares | `T712-11`; `test/v2/authenticators/types/AuthenticatorEip712.t.sol`, `test/v2/types/SchemaAudit.t.sol` |`forge test --match-path 'test/v2/authenticators/types/AuthenticatorEip712.t.sol'` |
| - [x] | - [ ] | `20261009T042147Z/FLOW-01` | The no-signing flow end to end: a relayed master-rail approval through `forwardCalls`, and one `multicall` batch that mints a fresh ephemeral key and spends on it in the same transaction | `FWD-20`, `MC-08`; `test/v2/Forwarder.t.sol`, `test/v2/Multicall.t.sol` |`forge test --match-test 'test_MC_08|test_FWD_20'` |

### Notes for this run

**The owner's rail did not move, which is why every earlier case still stands.** Its payload is
still `abi.encode(key, approved)`; the master key's rail adds a third member and is told apart by
the first key's offset, so the 191 cases from earlier runs pass unchanged against the new source.
No task-start assertion or input domain was altered.

**`SV-06b`'s rationale was corrected, not its assertions.** It used to say the two `authenticate*`
entry points duplicate each other; they now share one private `_authenticate`, so what the
fulfillment case constrains beyond `SV-06` is the hub-side wiring. The case and its oracles are
unchanged.

**Coverage reports two misses on the authenticator, and both are attribution artifacts.**
`--ir-minimum` gives 90% branches (9/10) and 83% functions (5/6), naming the `verify` arm at
`SessionOrderAuthenticator.sol:136` and the constructor. Deleting that arm's body makes `SV-TIER-06`
and `SV-TIER-07` fail, so it executes; `SV-DOMAIN` asserts the EIP-712 name and version that only
the constructor writes, so the constructor runs. The 65% line figure for this file is the same
mis-attribution the `20261007T183815Z/COV-01` notes record for the hub — the assembly key decode at
lines 65 and 114, `_useUnorderedNonce(owner, nonce)` at line 100, and `data.decodeBytes(1)` at line
184 are all reported uncovered though every case in the batch runs them.

**Each new case was mutation-checked against the production line it is there for.** Writing the
grant into `masterKeys` instead of `sessionKeyMaster` fails `SV-TIER-01` and `SV-TIER-02`; dropping
the expiry bound fails `SV-TIER-05`; ignoring `sessionKeyMaster` in `_authenticate` fails
`SV-TIER-01` and `SV-TIER-01b`; burning the nonce against the owner fails `SV-TIER-08`.

**The refusal says which tier failed.** `AuthKeyNotApproved` split into `MasterKeyNotApproved`, for
a key presented as a master key that the owner never approved, and `SessionKeyNotApproved`, for a
session key whose own grant stands while the master key it names does not. The latter carries that
master key's hash, so the refusal says which credential to re-approve rather than leaving the
holder to read `sessionKeyMaster` for it. Both are pinned, not merely raised: swapping the two
reverts fails 18 cases on the payload, and naming the session key's own hash in place of its
master's fails `SV-TIER-04` and `SV-TIER-10`. A master key's revocation of its own session key clears the grant, so that key
then reads as `MasterKeyNotApproved` — it has no standing of any kind left.

## Run `20261009T100830Z`

Scope: the V2 fixture stops forking mainnet. Permit2 is deployed from its checked-in creation code
and the four mainnet tokens give way to mocks, so the suite makes no network call. No case was
added or removed beyond the two that guard the artifact.

| Implemented and verified | Developer reviewed | Review ID | Contract / flow and coverage summary | Case IDs and test files / functions | Passing command or blocker |
|---|---|---|---|---|---|
| - [x] | - [ ] | `20261009T100830Z/ART-01` | The checked-in Permit2 creation code is the canonical deployment's: Permit2 was created by the deterministic deployer, so recomputing CREATE2 over the deployer, the salt and the artifact reproduces `0x0000...22D473`. Deploying it locally yields a working contract that scopes its own EIP-712 domain | `ART-01`, `ART-02`; `test/base/Permit2Artifact.t.sol` | `forge test --match-path 'test/base/Permit2Artifact.t.sol'` |
| - [x] | - [ ] | `20261009T100830Z/FIX-01` | Every V2 batch runs on a local chain: `_deployPermit2` replaces `_forkMainnet`, `token18` and `token6` replace WETH and USDC, and a DAI-flavoured mock replaces the real DAI that `PF-02` relayed a permit to. `_asEoa` is gone with the fork that needed it | no case ID changes; all 195 V2 cases | `forge test --no-match-path 'test/v1/*'` |

### Notes for this run

**Permit2 is still the real contract.** `cast artifact` reconstructs creation code rather than
runtime code, so `vm.deployCode` runs the constructor and Permit2 computes its cached domain
separator and chain id for the local deployment — which `vm.etch` of mainnet's runtime code would
not have done. Generating the artifact with `cast artifact` needs an RPC tier that serves
`trace_transaction`, because Permit2 was CREATE2-deployed and its creation code sits in an
internal call; the deterministic deployer's transaction input is the salt followed by that code, so
`cast tx <hash> input` reaches it without tracing. `test/artifacts/README.md` records the recipe.

**The artifact needs no CI guard, because the suite proves it offline.** Permit2's address is a
CREATE2 of the deterministic deployer, a known salt and the creation code, so `ART-01` recomputing
that address from the checked-in bytes is a proof that they are the deployed code. A regeneration
job diffing against mainnet could not do better and would put the network back in CI.

**What the mocks cost.** The tokens were real WETH, USDC and DAI; they are now two
`ERC20Mock`s of 18 and 6 decimals and an `ERC20DaiPermitMock`. The rails never used any of them
as more than an ERC20, so nothing in the hub is less exercised — but `PF-02` and `MC-01` now
relay a permit to the suite's own transcription of the DAI and EIP-2612 flavours rather than to the
reference implementations. The signature still has to verify; what is lost is that the verifier is
somebody else's code. `PF-03` and `PF-04` already made this trade for both ERC-721 flavours.

**One ERC20 mock, not two.** A permit token behaves like a plain one, so `ERC20Mock` carries
EIP-2612 and a width of its own and serves every ERC20 the suite needs, the forwarder's permit
tokens included. `PermitTokenMocks` keeps only the flavours that are not plain EIP-2612: the DAI
permit, both ERC-721 drafts, the reentrant permit and the ERC-1155 seed.

**V1 is unchanged and still forks.** It keeps its own addresses and its own
`vm.createSelectFork`, so `RPC_1` remains a CI requirement for that batch alone.

## Run `20261009T103550Z`

Scope: the authentication payload gains a tier hint, and the two refusals carry a key hash rather
than a key. Behaviour changes on one point — a key holding both grants — so the case that pinned the
old precedence is reshaped rather than extended.

| Implemented and verified | Developer reviewed | Review ID | Contract / flow and coverage summary | Case IDs and test files / functions | Passing command or blocker |
|---|---|---|---|---|---|
| - [x] | - [ ] | `20261009T103550Z/HINT-01` | `isSessionKey` in the authentication payload picks which mapping settles the key, so a master key costs one look-up instead of two. The hint is trusted for nothing: a key offered as the tier it does not hold finds no approval there and is refused, and both legs then settle under the tier they do hold | `SV-TIER-11`; `test/v2/authenticators/SessionOrderAuthenticator.t.sol` | `forge test --match-test test_SV_TIER_11` |
| - [x] | - [ ] | `20261009T103550Z/HINT-02` | Each grant stands on its own tier: a key holding both is settled by whichever it is presented as, so revoking one route leaves the other, and the key dies only when both are gone. A master key granting itself resolves to its own approval on either tier | `SV-TIER-10`, `SV-TIER-10b`; same file | `forge test --match-test 'test_SV_TIER_10'` |
| - [x] | - [ ] | `20261009T103550Z/HINT-03` | The refusals say which key is at fault and carry its hash: `SessionKeyNotApproved` when nothing stands behind the presented key, and `MasterKeyNotApproved` naming the master when that master is the thing revoked | `SV-TIER-04`, `SV-TIER-09`, `MC-08` reshaped | `forge test` |
| - [x] | - [ ] | `20261009T103550Z/EXP-01` | An approval will not record a key whose expiry has already passed, on any of the three ways in — the hub's delegation path, the owner's rail and a master key's. Revocation of an expired key still lands, so stale state stays clearable. An expired master key can grant nothing: a session key inside its bound is expired with it, and one outside it breaks the bound | `SV-TIER-12`, `SV-TIER-12b`; `test/v2/authenticators/SessionOrderAuthenticator.t.sol` | `forge test --match-test 'test_SV_TIER_12'` |
| - [x] | - [ ] | `20261009T103550Z/EXP-02` | A short authentication payload is refused on whichever gate it reaches: the key alone lands on the session tier and finds no master, the key with a tier reads a zero-length signature out of the key's own body, and only a whole payload truncated reaches the decoder's bounds check | `AUTH-13` reshaped; `test/v2/ExecuteOrder.t.sol` | `forge test --match-test test_AUTH_13` |

### Notes for this run

**What the hint saves, measured.** A master key authenticating an order went from 391,285 to
389,063 gas — one cold `SLOAD` and change. A session key pays 22 more for reading the flag. The
contract shrank 303 bytes to 12,451, because the two refusals now carry a `bytes32` rather than an
`AuthKey`, so neither revert path ABI-encodes a dynamic struct.

**The hint changes one behaviour, and improves it.** The caller names the tier, so a key holding
both the owner's grant and a master key's is settled by whichever it is presented as. Each grant
therefore stands on its own, where before the session grant took precedence and a master key could
mask a key the owner had approved directly. `SV-TIER-10` pinned the old precedence and now pins
the new independence.

**A revoked session key reads correctly now.** Earlier runs record that a session key whose master
had cleared its grant reported `MasterKeyNotApproved`, which was accurate but not the error a
holder would guess. With the tier named, that key reports `SessionKeyNotApproved` and a key whose
master was revoked reports `MasterKeyNotApproved` for that master.

**Mutation check.** Dropping the master look-up from the session branch — trusting the hint —
fails `SV-TIER-04` and `SV-TIER-10`, the two cases that cover a revoked master. The zero-grant
legs are unaffected by that mutation and are covered separately by `SV-TIER-11` and `MC-08`.

**Approving a key now checks its expiry, which it did not.** The call used to succeed and write a
key no order could ever present, so the holder learned of it only when a settlement was refused.
`_checkNotExpired` guards all four paths — the two approval rails, `initAuthentication`, and the
authentication path that already held the check inline. It sits behind the direction on both
approval rails, because an expired key must stay clearable. The master key needs no check of its
own: the bound on a session key's expiry, with this check, proves the master is live too.

**The tier flag sits between the key and the signature**, so the payload is
`abi.encode(AuthKey key, bool isSessionKey, bytes signature)`. That moved what word 1 means, which
`AUTH-13` had been reading as the signature's offset — see `EXP-02` for the three distinct ways a
short payload now fails.

## Run `20261019T050419Z`

Scope: the master-key rail's ordering and scoping, and the error payloads across V2. Two cases
change shape, one is added, and the expectations of the reshaped errors — in 46 cases — now
assert the whole payload.

| Implemented and verified | Developer reviewed | Review ID | Contract / flow and coverage summary | Case IDs and test files / functions | Passing command or blocker |
|---|---|---|---|---|---|
| - [x] | - [ ] | `20261019T050419Z/SCOPE-01` | A master key may approve or revoke only a session key it approved, or one no key has approved yet. Another master key is refused both when approving the key under itself and when revoking it, with `SessionKeyApprovedByAnother` naming the presented and the expected master key; the approving master's own revocation then lands | `SV-TIER-13`; `test/v2/authenticators/SessionOrderAuthenticator.t.sol` | `forge test --match-test test_SV_TIER_13` |
| - [x] | - [ ] | `20261019T050419Z/SCOPE-02` | The bound keeping a session key inside its master key's life applies on approval only. A key the bound refused on the way in can still be revoked through the same master | `SV-TIER-05` gains a revocation leg; same file | `forge test --match-test test_SV_TIER_05` |
| - [x] | - [ ] | `20261019T050419Z/ERR-01` | Every V2 error names its object, then the object's offending value, then what it was held against; values decoded from opaque bytes are always shown, fields the caller passed in plainly are not, and the four signature errors stay bare. Every expectation of those errors asserts the full payload | `AUTH-08`, `AUTH-13`, `DEL-02`, `DEL-05`, `DEL-12`, `FWD-16`, `GATE-01`, `GATE-02`, `GUARD-04`, `GUARD-06`, `LOCK-02`, `LOCK-03`, `MC-02`, `MC-06`, `MC-08`, `NONCE-04`, `NONCE-05`, `ORD-02`, `ORD-02b`, `ORD-03`, `ORD-03b`, `PF-06`, `PF-06b`, `SOL-04`, `SOL-05`, `SOL-06`, `SV-04`, `SV-05`, `SV-06`, `SV-06b`, `SV-07`, `SV-07b`, `SV-09`, `SV-11`, `SV-REV-01`, `SV-TIER-02`, `SV-TIER-03`, `SV-TIER-04`, `SV-TIER-05`, `SV-TIER-08`, `SV-TIER-09`, `SV-TIER-10`, `SV-TIER-11`, `SV-TIER-12`, `SV-TIER-12b`, `SV-TIER-13` | `forge test` |
| - [x] | - [ ] | `20261019T050419Z/ORD-01` | Every path checks a key's expiry straight after decoding it, before any hashing, storage read, nonce or signature, so an expired key is refused as expired whatever else is wrong with the call. Each case pairs the expired key with a second fault and then presents that same fault on a live key, which is refused for the fault; so the first refusal is about the order of the checks | `SV-ORD-01` owner's rail, ahead of a bad owner signature; `SV-ORD-02` master key's rail, ahead of an unapproved master key; `SV-ORD-03` authentication, ahead of an unapproved key; `test/v2/authenticators/SessionOrderAuthenticator.t.sol` | `forge test --match-test test_SV_ORD` |

### Notes for this run

**A master key's reach is now its own approvals.** `sessionKeyMaster` was written without reading
it, so any approved master key could revoke another's session key, and could take one over by
approving it under itself. One read before the nonce closes both, on the master-key rail only; the
order-signing path is untouched. Removing the check fails `SV-TIER-13`.

**With that, the bound needs no check on revocation.** A master key can only revoke a session key it
approved, and the bound held when it did, since both expiries are part of the key hashes. Putting
the bound back on the revocation path fails `SV-TIER-05` on its new leg.

**The error payloads.** The rule came in two steps: show only what the caller did not pass in, and
always show the object of the error. Applied together, `owner`, `relayer` and `solver` leave
every payload they sat in, being plain parameters or decoded struct fields, while expiries and the
forwarder's selector stay because they are read out of opaque bytes. Errors that carried nothing now
name their object: the nonce and its namespace, the lock holder, the caller, the authenticator, the
amount overspent. The two expiry errors keep only the decoded expiries and no key hash, so neither
revert path hashes the key. The hub ends at 24,076 bytes, five under where this run began, the
dropped fields paying for the added ones; the authenticator is 12,609.

**The tests became stricter as a consequence.** Foundry matches an error with arguments only on its
whole payload, so every selector-only expectation of a reshaped error had to state its values, each
taken from the case's own variables and, for nonce namespaces, from `lNonceKey` and `_keyHash`.
Those expectations now pin which namespace collided, whose order held the lock and which entry the
forwarder refused, where before they pinned only that something did.

**Two notices were wrong and are fixed.** `NativeOverSpent` read "drawing on the contract's own"
with its noun missing, and `NonceAlreadyUsed` said a nonce is revoked "by its owner", which stopped
being true when namespaces became the signer's.

**Vocabulary.** Session keys are *approved*, not *granted*, throughout the source and the
`SV-TIER-*` cases; seven test functions are renamed to match, and every case ID is unchanged.
Role grants and Permit2 allowances keep the word, being the established terms for those.

**The order of the expiry checks is pinned.** Restoring each check to where it stood before this run
fails exactly its own case and no other: after the signature on the owner's rail fails `SV-ORD-01`,
after the master key's approval read fails `SV-ORD-02`, and after the tier lookup in authentication
fails `SV-ORD-03`.

**After `vm.warp`, the time is read with `vm.getBlockTimestamp()`.** Under `via_ir` the compiler
may fold `block.timestamp` across the warp: in `SV-ORD-03`, `block.timestamp + 1 hours` written
after the warp was folded into the identical expression computed before it, and the order went out
already past its deadline. The cheatcode is an external call the compiler cannot fold. All nine
other reads of `block.timestamp` after a warp, in `SOL-05`, `SV-07`, `SV-07b`, `SV-TIER-12`,
`SV-TIER-12b` and `SV-ORD-01..03`, passed only because those expressions happened not to be folded,
and now go through the cheatcode too.

## Run `20261019T073557Z`

Scope: `revokeNonce(AuthKey, uint256, uint256, bytes)` on the authenticator, through which a key spends one
of its own nonces by signing a `NonceRevocation`. The base `revokeNonce(uint256)` spends only the
caller's address namespace, which a key that is not an account cannot be.

| Implemented and verified | Developer reviewed | Review ID | Contract / flow and coverage summary | Case IDs and test files / functions | Passing command or blocker |
|---|---|---|---|---|---|
| - [x] | - [ ] | `20261019T073557Z/NREV-01` | A key's signed revocation, submitted by anyone, spends the nonce in that key's namespace only. An order the key signed at that nonce is refused `NonceAlreadyUsed(keyHash, nonce)`; the owner's namespace is untouched and the key's next nonce still settles | `SV-NREV-01`; `test/v2/authenticators/SessionOrderAuthenticator.t.sol` | `forge test --match-test test_SV_NREV_01` |
| - [x] | - [ ] | `20261019T073557Z/NREV-02` | A master key cancels a session key approval it signed and has not seen used, and the session key is never approved. A session key revokes in its own namespace, cancelling an order it signed, and leaves its master key's namespace alone | `SV-NREV-02`, `SV-NREV-03`; same file | `forge test --match-test 'test_SV_NREV_0[23]'` |
| - [x] | - [ ] | `20261019T073557Z/NREV-03` | The revocation must be signed by the key it names, for the nonce and deadline it names: another signer, a signature for another nonce, for another deadline, and a signature naming another key are each refused `InvalidRevocationSignature`, spending nothing. A submitted revocation cannot be submitted again | `SV-NREV-04`, `SV-NREV-05`; same file | `forge test --match-test 'test_SV_NREV_0[45]'` |
| - [x] | - [ ] | `20261019T073557Z/NREV-04` | A key revokes whether it was never approved, has had its approval withdrawn or has expired. A P256 key revokes through its own scheme, and a P256 signature for another nonce is refused | `SV-NREV-06`, `SV-NREV-07`; same file | `forge test --match-test 'test_SV_NREV_0[67]'` |
| - [x] | - [ ] | `20261019T073557Z/NREV-05` | Over the whole nonce domain, a revocation sets exactly the bit it names, in the key's namespace and not the owner's | `SV-FUZZ-NREV`; same file | `forge test --match-test testFuzz_SV_FUZZ_NREV` |
| - [x] | - [ ] | `20261019T073557Z/NREV-06` | The deadline is inclusive: a revocation submitted at its deadline spends the nonce, and one submitted a second later is refused `DeadlinePassed(deadline, currentTime)` and leaves the nonce free, so an order the key signs at that nonce afterwards settles | `SV-NREV-08`; same file | `forge test --match-test test_SV_NREV_08` |
| - [x] | - [ ] | `20261019T073557Z/T712-12` | `NonceRevocationLib.hash` matches the struct hash built from the bound schema, and the key, the nonce and the deadline each move the digest. `SchemaAudit` pins the typehash to `schema_NonceRevocation` | `T712-12` in `test/v2/authenticators/types/AuthenticatorEip712.t.sol`; `T712-SCHEMA` in `test/v2/types/SchemaAudit.t.sol` | `forge test --match-test 'T712_12\|T712_SCHEMA'` |

### Notes for this run

**Mutation checks.** Each mutant fails at least one case and was reverted: skipping the signature
check fails `SV-NREV-04` and `-07`; spending the caller's namespace instead of the key's fails
every `SV-NREV-*` case but `-04`; hashing a constant in place of the nonce, or in place of the key
hash, fails every case that submits a valid revocation. Dropping the deadline check fails `SV-NREV-08`, and
hashing a constant in place of the deadline fails every case that submits a valid revocation.

**The deadline bounds when a signed revocation may be submitted.** Without one, a revocation the key
signed but never submitted would stay usable, and anyone holding it could cancel a later signature
of the key at the same nonce. A second use is prevented by the nonce, as for every other signature.

**No expiry or approval check.** A key that has expired or lost its approval can still revoke, which
`SV-NREV-06` pins.

**The authenticator types are hashed as structs on the expected side.** `SchemaHash` hashes
`MasterKeyApproval`, `SessionKeyApproval` and `NonceRevocation` through `vm.eip712HashStruct`
from their bound schemas, as it does every hub type, so the `l*` helpers take whole keys and the
nested `AuthKey` encoding is checked with the outer one. T712-10..12 feed production the key hash
it computes itself. Reordering the `MasterKeyApproval` type string, swapping the nonce and the
deadline in `NonceRevocationLib.hash`, and dropping `owner` from `SessionKeyApprovalLib.hash`
each fail their T712 row.

The authenticator is 12,943 bytes; the hub is unchanged at 24,076. 226 tests pass.

## Run `20261019T085443Z`

Scope: `FulfillmentSolution` loses its `nonce`, and the hub no longer spends one in the solution
approver's namespace. The approval names `orderHash`, so it settles only its own order and at most
as often as that order does.

| Implemented and verified | Developer reviewed | Review ID | Contract / flow and coverage summary | Case IDs and test files / functions | Passing command or blocker |
|---|---|---|---|---|---|
| - [x] | - [ ] | `20261019T085443Z/SOL-06` | An approved route spends no nonce of the approver's. Relayed over Permit2, the order settles once and the approver's namespace in the hub is untouched; a second submission of the same order and approval is refused by Permit2's `InvalidNonce` | `SOL-06` (renamed `test_SOL_06_anApprovalIsSpentWithItsOrder`); `test/v2/FulfillOrder.t.sol` | `forge test --match-test test_SOL_06` |
| - [x] | - [ ] | `20261019T085443Z/SOL-01` | The first order's approval, of the very same route, is refused with a second order that differs only in its tail; the second order's own approval of that route settles | `SOL-01`; same file | `forge test --match-test test_SOL_01` |
| - [x] | - [ ] | `20261019T085443Z/FU-FUZZ` | Over the delegated rail's domain, the approver's namespace stays empty whether or not an approver is named | `testFuzz_FU_FUZZ_delegatedRail`; same file | `forge test --match-test testFuzz_FU_FUZZ_delegatedRail` |
| - [x] | - [ ] | `20261019T085443Z/T712-SOL` | `FulfillmentSolution` and `SolutionApproval` type strings and their bound schemas agree without the member | `T712-SCHEMA` in `test/v2/types/SchemaAudit.t.sol`; the `FulfillmentSolution` and `SolutionApproval` rows in `test/v2/types/Eip712.t.sol` | `forge test --match-path test/v2/types/*` |

### Notes for this run

**`NONCE-07` is retired.** It showed that a delegation and a route kept separate numbers in the
hub; routes no longer have numbers.

**Mutation check.** Putting a burn back in `_approveSolution` fails `SOL-06` and
`testFuzz_FU_FUZZ_delegatedRail` on the approver's namespace, and turns the expected refusals of
`SOL-01`, `AUTH-01b` and `AUTH-07b` into `NonceAlreadyUsed`.

**An owner submitting their own order on the delegated rail spends no nonce,** so the owner can
settle the same order, with the same approval, more than once. The owner is the caller and the
assets are their own; the approval cannot reach any other order.

The hub is 24,153 bytes, 77 more than before the change; 225 tests pass.

## Run `20261019T093159Z`

Scope: `AuthKeyLib.verify` refuses a key of the wrong length. The key's hash covers only the bytes
within its length, while `verify` read fixed words from its start, so the bytes after an empty or
short key, which the submitter lays out, were read as part of it. A malformed key, once approved,
verified whatever signer the submitter chose.

| Implemented and verified | Developer reviewed | Review ID | Contract / flow and coverage summary | Case IDs and test files / functions | Passing command or blocker |
|---|---|---|---|---|---|
| - [x] | - [ ] | `20261019T093159Z/LEN-01` | An empty Secp256k1 key, approved through the hub, does not authenticate an order signed by the address placed after it in the payload: `InvalidAuthenticationSignature` | `SV-KEY-LEN-01`; `test/v2/authenticators/SessionOrderAuthenticator.t.sol` | `forge test --match-test test_SV_KEY_LEN_01` |
| - [x] | - [ ] | `20261019T093159Z/LEN-02` | A Secp256k1, P256 or WebAuthn key one byte short is refused even when the byte after it completes the genuine key, and the full key verifies the same signature | `SV-KEY-LEN-02..04`; same file | `forge test --match-test 'test_SV_KEY_LEN_0[234]'` |
| - [x] | - [ ] | `20261019T093159Z/LEN-03` | An empty RSA key is refused when a genuine `e` and `n` lie before it in calldata and the two words after it, read as head words, wrap back to them; `decodeBytes` checks only where a part ends | `SV-KEY-LEN-05`; same file | `forge test --match-test test_SV_KEY_LEN_05` |

### Notes for this run

**Each check is pinned by its own case.** Removing the Secp256k1 check fails `SV-KEY-LEN-01` and
`-02` (the first by letting the forged order settle); removing the P256, WebAuthn or RSA check
fails `-03`, `-04` or `-05` respectively, and nothing else.

**The premise is an approved malformed key.** Only the owner or a master key can approve one; a
well-formed key is never read beyond its length. The checks turn an encoding mistake in a client
from a key anyone can sign for into a key nobody can.

**What the RSA check covers.** With at least 64 bytes, the head words are within the hashed bytes.
A key whose own head word points outside it would still be read outside it; that needs the key's
bytes to be wrong, not short.

The authenticator is 13,012 bytes. 230 tests pass.

## Run `20261019T095620Z`

Scope: a key's nonces are spent under its credential, `keccak256(abi.encodePacked(keyType,
publicKey))`, rather than under the hash of one approval of it. An order signature names no key, so
two approvals of the same credential, such as a key renewed with a later expiry while the first
approval stands, each accepted the same signature in a namespace of its own, and the hub settled
the order twice. Secp256k1 keys must also be canonical, with their top 12 bytes clear.

| Implemented and verified | Developer reviewed | Review ID | Contract / flow and coverage summary | Case IDs and test files / functions | Passing command or blocker |
|---|---|---|---|---|---|
| - [x] | - [ ] | `20261019T095620Z/CRED-01` | An order settled under one approval of a key is refused under a renewal of the same credential with `NonceAlreadyUsed(credentialHash, nonce)` | `SV-CRED-01`; `test/v2/authenticators/SessionOrderAuthenticator.t.sol` | `forge test --match-test test_SV_CRED_01` |
| - [x] | - [ ] | `20261019T095620Z/CRED-02` | The namespace is shared across tiers: an order settled by a credential as a session key is refused when presented by the same credential as a master key | `SV-CRED-02`; same file | `forge test --match-test test_SV_CRED_02` |
| - [x] | - [ ] | `20261019T095620Z/CRED-03` | A revocation signed under one approval spends the nonce for every approval of the credential | `SV-CRED-03`; same file | `forge test --match-test test_SV_CRED_03` |
| - [x] | - [ ] | `20261019T095620Z/CRED-04` | A Secp256k1 key with a top byte set does not verify, while its clean encoding does, with an ERC-1271 wallet as the signer | `SV-CRED-04`; same file | `forge test --match-test test_SV_CRED_04` |
| - [x] | - [ ] | `20261019T095620Z/CRED-NS` | Every assertion of a key's nonce namespace, in the authenticator and hub batches, reads the credential namespace from the test-side `_credentialHash` | 26 assertions across `SessionOrderAuthenticator.t.sol`, `FulfillOrder.t.sol`, `ExecuteOrder.t.sol`, `Forwarder.t.sol`, `Multicall.t.sol`, `Nonces.t.sol` | `forge test` |

### Notes for this run

**Mutation checks.** Spending an order's nonce under the key hash fails `SV-CRED-01..03`; the
revocation's alone fails `SV-CRED-03`; the master-key rail's fails `SV-TIER-08`, `SV-NREV-02`,
`-03`, `FWD-20` and the tier fuzz. Adding the expiry to the credential fails `SV-CRED-01..03`, and
dropping the canonical Secp256k1 check fails `SV-CRED-04`.

**What stays per approval.** Approvals, and every signed type that names a key, still use the
key hash with its expiry. Two byte encodings of one RSA key remain two credentials.

**`SV-NREV-06`** gives its expired key a signer of its own, so its nonce does not land in the
namespace `key` already spent in.

The authenticator is 13,172 bytes. 234 tests pass.

## Run `20261021T091104Z`

Scope: the fulfillment order names what may leave the owner — `ERC20Allowance(address token,uint160 amount)` and `ERC721Approval(address token,uint256 tokenId)` legs, no targets — and the `FulfillmentSolution` names one target per leg in `erc20Targets` and `erc721Targets`. The witness no longer carries ERC20 targets and takes `ERC721Approval[]`; `SolutionApproval` nests the whole order; both fulfill entry points refuse a solution without exactly one target per leg (`MismatchedArrayLengths`). Existing fulfillment cases keep their IDs and assertions on the new shapes.

| Implemented and verified | Developer reviewed | Review ID | Contract / flow and coverage summary | Case IDs and test files / functions | Passing command or blocker |
|---|---|---|---|---|---|
| - [x] | - [ ] | `20261021T091104Z/MIG-01` | Every existing fulfillment case runs on the new order and solution shapes with its assertions intact: orders built from allowances and approvals, routes defaulting each ERC20 leg to `router` and each NFT leg to `router2`, witness and approval signed over the new types | `AUTH-*`, `SOL-*`, `OWN-*`, `VAL-*`, `GUARD-*`, `GATE-*`, `ORD-*`, `DIRTY-*`, `SV-*` fulfillment legs, `SET-*`/`OWN-07`; `test/v2/**` | `forge test --isolate` — 245 passed |
| - [x] | - [ ] | `20261021T091104Z/TGT-01` | The solver chooses each leg's target, on every pull branch: owner-submitted plain pull, Permit2 allowance pull, relayed Permit2 witness, owner-submitted Permit2 permit. ERC20 and ERC721 legs land at the chosen targets, not at any target the owner signed; the witness carries no ERC20 target | `TGT-01..04`; `test/v2/FulfillTargets.t.sol` `test_TGT_01..04_*` | `forge test --match-path test/v2/FulfillTargets.t.sol` |
| - [x] | - [ ] | `20261021T091104Z/LEN-01` | Both fulfill entry points revert `MismatchedArrayLengths()` when `erc20Targets` or `erc721Targets` has 0 or 2 entries for 1 leg, with nothing moved; one target per leg settles | `LEN-01` in `test_TGT_01_solverChoosesTheTargetsOnTheDelegatedRail`, `LEN-02` in `test_TGT_03_witnessDoesNotBindTheErc20Targets`, whose settling legs are their controls; `test/v2/FulfillTargets.t.sol` | `forge test --match-test 'test_TGT_0[13]'` |
| - [x] | - [ ] | `20261021T091104Z/APR-01` | A named approver's signature covers the targets: an approval of one set of targets is refused with `InvalidSolutionSignature` for another, and the approval of that other set settles | `APR-01`; `test/v2/FulfillTargets.t.sol` `test_APR_01_theApprovalBindsTheTargets` | `forge test --match-test test_APR_01` |
| - [x] | - [ ] | `20261021T091104Z/EVT-01` | `TransferTokens` on a fulfillment lists each leg paired with the target the solution named, for two ERC20 legs and one NFT leg, and the balances follow it | `EVT-01`; `test/v2/FulfillTargets.t.sol` `test_EVT_01_fulfillmentEventPairsLegsWithTargets` | `forge test --match-test test_EVT_01` |
| - [x] | - [ ] | `20261021T091104Z/FUZZ-01` | The fulfillment fuzz cases draw the ERC20 and NFT targets, and assert the drawn targets receive the legs | `FU-FUZZ`; `test/v2/FulfillOrder.t.sol` `testFuzz_FU_FUZZ_delegatedRail`, `testFuzz_FU_FUZZ_permit2Rail` | `forge test --match-test FU_FUZZ` |
| - [x] | - [ ] | `20261021T091104Z/T712-01` | Struct hashes of `ERC20Allowance`, `ERC721Approval` and the changed `FulfillmentOrder`, `FulfillmentSolution`, `FulfillmentWitness`, `SolutionApproval` against their bound schemas, calldata and memory; the typehashes in `SchemaAudit`; `EfficientHashLibExt` against the word-by-word encoding | `T712-*` incl. `test_T712_erc20AllowanceStructHash`, `test_T712_erc721ApprovalStructHash`, `testFuzz_T712_DIFF_erc20Allowance`, `testFuzz_T712_DIFF_erc721Approval`, `testFuzz_T712_ARRAY_efficientHashLibExt`; `T712-SCHEMA` rows; `test/v2/types/*` | `forge test --match-path 'test/v2/types/*'` |

### Notes for this run

**Shared helpers.** `_solution(order, calls, deadline)` and `_route(order, calls)` send every ERC20 leg
of the order to `router` and every NFT leg to `router2`, the targets the suite's orders named before,
so the existing cases keep their balance assertions unchanged. `_solution(erc20Targets,
erc721Targets, calls, deadline)` names targets explicitly. `_tokenAllowance`, `_nftApproval`,
`_allowances`, `_approvals` and `_addresses` build the new legs.

**The new cases live in `FulfillTargets.t.sol`,** beside `FulfillOrder.t.sol`, which is at the
`via_ir` compiler limit noted in the PR. `LEN-01` and `LEN-02` are folded into `TGT-01` and `TGT-03`:
their controls were the same settlement those tests make.

**Mutation checks.** Sending the plain pull, the Permit2 allowance pull, the Permit2 signature pull
or the NFT to a fixed address instead of the solution's target fails the `TGT` cases and every
existing case on that branch. Dropping either `checkLengths` on either entry point fails `TGT-01` or
`TGT-03`. Hashing constants in place of the targets in `FulfillmentSolution` fails `APR-01`, `SOL-01`,
`SOL-06`, `AUTH-01b`, `AUTH-07b` and the two `T712` rows. Dropping either target from the event fails
`EVT-01`. Typing the approval's order member as `bytes32` fails `APR-01`, the `SOL` cases, `T712` and
`T712-SCHEMA`.

**Coverage, `--ir-minimum`.** Every reported miss in the changed files was checked: the assembly
bodies, the allocator calls and both `_transferERC20s` overloads are attribution artifacts. The
functions report as hit, and a trace of `TGT-02` shows `permit2::transferFrom` paying the solver's
target. The constructor lines run in every `setUp`.

The hub is 24,360 bytes, 216 under the limit. 245 tests pass.

## Run `20261021T125107Z`

Scope: `TransferTokens` has two emit sites again. `_announceExecution` takes the execution order's
ERC20 and ERC721 arrays as `calldata` and emits them as signed, without copying them to memory;
`_announceFulfillment` emits the transfers it builds by pairing each leg with the solution's target.

| Implemented and verified | Developer reviewed | Review ID | Contract / flow and coverage summary | Case IDs and test files / functions | Passing command or blocker |
|---|---|---|---|---|---|
| - [x] | - [ ] | `20261021T125107Z/EVT-01` | The event payload is unchanged on every rail: the execution cases assert it from the order's own arrays, the fulfillment cases from the legs paired with their targets | `SET-01..03`, `OWN-07`, `EVT-01`, `EX-FUZZ`, `FU-FUZZ`; `test/v2/**` | `forge test --isolate` — 245 passed |

### Notes for this run

The hub is 23,931 bytes, 429 fewer. Over the 206 deterministic V2 cases the total is 62,211 gas
lower: an execution order saves about 800 to 2,500 gas, a fulfillment up to about 600, and the seven
cases that rose did so by 9 gas or less.

## Run `20261021T174529Z`

Scope: `IOrderAuthenticator.authenticateExecution` and `authenticateFulfillment` take the order's
EIP-712 hash, `(order, orderHash, data)`. The hub hashes the order once, before authentication, and
uses that hash for the authenticator, the solution approval and the event; `SessionOrderAuthenticator`
signs over it instead of hashing the order again.

| Implemented and verified | Developer reviewed | Review ID | Contract / flow and coverage summary | Case IDs and test files / functions | Passing command or blocker |
|---|---|---|---|---|---|
| - [x] | - [ ] | `20261021T174529Z/AUTH-01` | The hub passes the order, its hash and the data unaltered: `AUTH-11` expects the exact call, the hash taken from the bound schema; every authenticated order on both rails settles only when the passed hash is the one the key signed | `AUTH-11` (`test/v2/ExecuteOrder.t.sol`), `SV-*`, `MC-06`, `MC-08`, `ORD-03b`, `OWN-03`, `DIRTY-01`, `DIRTY-03`; `test/v2/**` | `forge test --isolate` — 245 passed |
| - [x] | - [ ] | `20261021T174529Z/AUTH-02` | The hub-only gate holds on both entry points with the new signatures, sent directly and relayed through the forwarder | `SV-05`, `FWD-16`; mocks in `Delegation.t.sol` and `Guards.t.sol` | same |

### Notes for this run

**Gas and size.** An authenticated order that settles saves about 1,700 to 7,600 gas, growing with
the order's size; the authenticator suite is 68,774 gas lower, and the 206 deterministic V2 cases
88,038 lower in all. An order refused by its authenticator now pays for the hub's hash before the
refusal, so those cases rise by up to about 600 gas, and the forwarder case that sends both calls
directly by 1,501. `SessionOrderAuthenticator` is 11,677 bytes, 1,837 fewer; the hub is 23,969, 38
more.

**Mutation checks.** Passing a hash with one bit flipped fails 58 cases on the execution rail,
`AUTH-11` among them, and 18 on the fulfillment rail.

## Run `20261021T175259Z`

Scope: `ERC20TransferLib.targetsHash` replaces `extractTargets`, hashing the targets as an
`address[]` without building that array, and `ExecutionWitnessLib.hash` takes that hash. The four
uncalled `*Memory` conversions in `ERC20Transfer.sol` are removed, with
`DynamicArrayLibExt.mallocAddresses`, which only they used.

| Implemented and verified | Developer reviewed | Review ID | Contract / flow and coverage summary | Case IDs and test files / functions | Passing command or blocker |
|---|---|---|---|---|---|
| - [x] | - [ ] | `20261021T175259Z/WIT-01` | The execution witness is unchanged: every relayed Permit2 execution still settles against the real Permit2's witness check, and `T712` holds the witness's memory hasher against the bound schema | `AUTH-02..04`, `ORD-02`, `DIRTY-02`, `EX-FUZZ`, `T712-*`; `test/v2/**` | `forge test --isolate` — 245 passed |

### Notes for this run

Ten relayed executions save 23 to 46 gas each, 266 in all; the hub is 23,961 bytes, 8 fewer.

## Run `20261022T085037Z`

Scope: the hub inherits `ManagementSimple` in place of `ManagementPausable` and
`ManagementRescuable`: the default admin role follows `Ownable` ownership, and
`rescueTokens(ERC20Transfer[], ERC721Transfer[])` replaces the three rescue functions.

| Implemented and verified | Developer reviewed | Review ID | Contract / flow and coverage summary | Case IDs and test files / functions | Passing command or blocker |
|---|---|---|---|---|---|
| - [x] | - [ ] | `20261022T085037Z/MGMT-01` | Ownership holds the default admin role: deploy wiring, one-step transfer with the zero owner refused, renouncing leaves no admin, and the role cannot be granted, revoked or renounced; the delayed-admin interface is no longer claimed | `MGMT-01`, `MGMT-03`, `MGMT-05`, `MGMT-06`, `MGMT-07`, `MGMT-07b`, `MGMT-11b`; `test/v2/Management.t.sol` | `forge test --isolate` — 244 passed |
| - [x] | - [ ] | `20261022T085037Z/RESCUE-01` | `rescueTokens` sends each ERC20 leg to its target, a zero amount sweeping the balance, native under either sentinel, and each NFT leg; only a rescuer or the default admin may call it, and a token leg to the zero address surfaces the token's wrapped refusal | `MGMT-08a..c`, `MGMT-09`; same file | same |

### Notes for this run

`MGMT-04` (the external batch grant and revoke) and `MGMT-10` (ERC-1155 rescue) are retired: neither
function exists any more. A native leg to the zero address is not refused, and burns the ether.
Removing the full-balance sweep fails `MGMT-08a` and `MGMT-08b`; removing the caller check fails
`MGMT-08c`. The hub is 20,045 bytes.

## Run `20261022T092125Z`

Scope: `AuthDelegation` and `MasterKeyApproval` sign `owner` as their first member, so a
signature for one account cannot be submitted for another account the same signer controls.

| Implemented and verified | Developer reviewed | Review ID | Contract / flow and coverage summary | Case IDs and test files / functions | Passing command or blocker |
|---|---|---|---|---|---|
| - [x] | - [ ] | `20261022T092125Z/OWN-BIND-01` | Both struct hashes match their bound schemas with `owner` included, and changing `owner` changes each digest | `T712-08b` — `test/v2/types/Eip712.t.sol`; `T712-10` — `test/v2/authenticators/types/AuthenticatorEip712.t.sol` | `forge test --isolate` — 246 passed |
| - [x] | - [ ] | `20261022T092125Z/OWN-BIND-02` | Two ERC-1271 wallets sharing one signer: a delegation or master-key approval signed for wallet A is refused for wallet B and accepted for A | `DEL-16` — `test/v2/Delegation.t.sol`; `SV-13` — `test/v2/authenticators/SessionOrderAuthenticator.t.sol` | same |

### Notes for this run

Removing `owner` from both the production hashes and the test oracle fails exactly `DEL-16`,
`SV-13`, `T712-08b` and `T712-10`. Every other signing helper now passes the account it signs
for. The hub is 22,396 bytes and the authenticator 11,683.

## Run `20261022T093411Z`

Scope: `KeyType` gains `ERC1271` and `ERC7913`. `Secp256k1` verifies by ECDSA recovery alone,
`ERC1271` by the named contract alone, and `ERC7913` by calling its verifier's `verify`
directly, with a non-empty key after the verifier's address.

| Implemented and verified | Developer reviewed | Review ID | Contract / flow and coverage summary | Case IDs and test files / functions | Passing command or blocker |
|---|---|---|---|---|---|
| - [x] | - [ ] | `20261022T093411Z/KEY-1271-01` | A Secp256k1 key naming a contract refuses a signature the contract accepts; an ERC1271 key over the same bytes accepts it, authenticates an order end to end, and refuses an account without code | `SV-KEY-SECP-02`, `SV-KEY-1271-01`, `SV-KEY-1271-02` — `test/v2/authenticators/SessionOrderAuthenticator.t.sol` | `forge test --isolate` — 250 passed |
| - [x] | - [ ] | `20261022T093411Z/KEY-7913-01` | An ERC7913 key authenticates an order through OpenZeppelin's `ERC7913P256Verifier` and refuses a signature over another digest; a key with nothing after the verifier's address, even through a verifier that accepts every key, and a verifier without code verify nothing | `SV-KEY-7913-01`, `SV-KEY-7913-02`; same file | same |
| - [x] | - [ ] | `20261022T093411Z/KEY-CANON-01` | A Secp256k1 or ERC1271 key with any of its top 12 bytes set verifies nothing; the direct-update fuzz covers all six key types | `SV-CRED-04`, `SV-FUZZ-UPD`; same file | same |

### Notes for this run

`SV-KEY-SECP-02` is repurposed: the contract-signer case it held moved to `SV-KEY-1271-01` under
the `ERC1271` type. Mutations, each failing exactly its case: Secp256k1 falling back to ERC-1271
(`SV-KEY-SECP-02`), ERC1271 falling back to ECDSA (`SV-KEY-1271-02`), ERC7913 accepting a 20-byte
key (`SV-KEY-7913-02`), ERC7913 verifying nothing or ignoring the word the verifier returns
(`SV-KEY-7913-01`), dropping the canonical address check (`SV-CRED-04`). The authenticator is
12,070 bytes.

## Run `20261022T105959Z`

Scope: `forwardCalls` relays `updateDelegation`, so a relayer can carry past a delegation someone
else submitted first. `updateDelegation` never takes the hub, its caller on that route, for the
owner. The owner's own call to `updateDelegation` or to the authenticator's owner rail refuses a
non-empty signature with `UnexpectedSignature`.

| Implemented and verified | Developer reviewed | Review ID | Contract / flow and coverage summary | Case IDs and test files / functions | Passing command or blocker |
|---|---|---|---|---|---|
| - [x] | - [ ] | `20261022T105959Z/FWD-DEL-01` | A relayed delegation settles on the owner's signature and the hub's nonce; after a front-runner submits the same delegation, the relayer's batch unwinds with the failure bit clear and settles its order with it set | `FWD-21` — `test/v2/Forwarder.t.sol`; `MC-09` — `test/v2/Multicall.t.sol` | `forge test --isolate` — 254 passed |
| - [x] | - [ ] | `20261022T105959Z/FWD-DEL-02` | A forwarded delegation naming the hub as owner, or the owner with no signature, is refused | `FWD-22` — `test/v2/Forwarder.t.sol` | same |
| - [x] | - [ ] | `20261022T105959Z/SELF-SIG-01` | The owner's own call refuses a signature and accepts an empty one without spending the nonce, on the hub and on the authenticator | `DEL-17` — `test/v2/Delegation.t.sol`; `SV-UPD-01` — `test/v2/authenticators/SessionOrderAuthenticator.t.sol` | same |

### Notes for this run

`SV-UPD-01` is rewritten: it pinned that the owner's call ignored a signature. Mutations, each
failing exactly its cases: dropping the selector from the allowlist (`FWD-21`, `FWD-22`,
`MC-09`), dropping the hub-as-caller guard (`FWD-22`), and accepting a signature on the owner's
call in the hub (`DEL-17`) or the authenticator (`SV-UPD-01`). The hub is 22,493 bytes and the
authenticator 12,104.

## Run `20261022T175036Z`

Scope: errors renamed, behaviour unchanged. `NotDelegatedAuthenticator` →
`AuthenticatorNotDelegated`, `NotAllowanceHub` → `CallerNotAllowanceHub`, `NotSupportedSelector`
→ `UnsupportedSelector`, `NativeOverSpent` → `NativeOverspent`, `InvalidAuthenticationSignature`
→ `InvalidOrderSignature`, `SessionKeyApprovedByAnother` → `SessionKeyAlreadyApproved`. The
nonce bitmap's key, `NonceAlreadyUsed`'s first argument and `_useUnorderedNonce`'s word argument
are named `namespace`.

| Implemented and verified | Developer reviewed | Review ID | Contract / flow and coverage summary | Case IDs and test files / functions | Passing command or blocker |
|---|---|---|---|---|---|
| - [x] | - [ ] | `20261022T175036Z/ERR-01` | Every case asserting one of the renamed errors expects it under its new name | every case naming those errors; `test/v2/**` | `forge test --isolate` — 254 passed |

### Notes for this run

Earlier runs above keep the names that held when they ran.

## Run `20261022T180646Z`

Scope: `EIP712Base` and `IEIP712Base` are removed. `AuthDelegator` and
`SessionOrderAuthenticator` inherit OpenZeppelin's `EIP712` directly, so neither exposes
`DOMAIN_SEPARATOR()`; ERC-5267's `eip712Domain()` describes each domain.

| Implemented and verified | Developer reviewed | Review ID | Contract / flow and coverage summary | Case IDs and test files / functions | Passing command or blocker |
|---|---|---|---|---|---|
| - [x] | - [ ] | `20261022T180646Z/DOM-02` | The hub and the authenticator sign under different domains; after the chain id moves, a delegation and a master-key approval signed for the old chain are refused and the same decisions signed for the new chain are accepted | `DOM-01` `test_DOM_01_bothDomainsAreChainScoped` — `test/v2/Management.t.sol`; the published fields stay `MGMT-02` and `SV-DOMAIN` | `forge test --isolate` — 254 passed |

### Notes for this run

`DOM-01` is rewritten: it read `DOMAIN_SEPARATOR()` and now observes the separator through the
signatures it accepts. The hub is 22,994 bytes and the authenticator 12,029.

## Run `20261029T120000Z`

Scope: `ExecutionOrder`, `FulfillmentOrder`, `ExecutionWitness` and `FulfillmentWitness` gain a
last member `string metadata`, encoded as `keccak256(bytes(metadata))`. The hub passes
`order.metadata` to both witness hashers. The `SolutionApproval` type string carries the new
`FulfillmentOrder` definition.

| Implemented and verified | Developer reviewed | Review ID | Contract / flow and coverage summary | Case IDs and test files / functions | Passing command or blocker |
|---|---|---|---|---|---|
| - [x] | - [ ] | `20261029T120000Z/META-01` | An execution order authenticated for metadata A settles; the same signature with metadata B is refused by the authenticator | `AUTH-14` `test_AUTH_14_authenticationBindsMetadata` — `test/v2/ExecuteOrder.t.sol` | `forge test --isolate` — 261 passed |
| - [x] | - [ ] | `20261029T120000Z/META-02` | A Permit2 execution witness signed with metadata A settles with a relayer; submitted with metadata B, Permit2 refuses it | `AUTH-15` `test_AUTH_15_witnessPinsMetadata` — `test/v2/ExecuteOrder.t.sol` | same |
| - [x] | - [ ] | `20261029T120000Z/META-03` | A Permit2 fulfillment witness signed with metadata A settles with a solver; submitted with metadata B, Permit2 refuses it | `AUTH-16` `test_AUTH_16_witnessPinsMetadata` — `test/v2/FulfillOrder.t.sol` | same |
| - [x] | - [ ] | `20261029T120000Z/META-04` | A fulfillment authenticated for metadata A settles; the same signature with metadata B is refused by the authenticator | `AUTH-17` `test_AUTH_17_authenticationBindsMetadata` — `test/v2/FulfillOrder.t.sol` | same |
| - [x] | - [ ] | `20261029T120000Z/META-05` | Both hashers of each order and each witness, with non-empty metadata, equal the bind-json oracle, and empty metadata gives a different hash | `T712-metadata` `test_T712_executionWitnessMetadataStructHash`, `test_T712_fulfillmentWitnessMetadataStructHash`, `test_T712_ordersMetadataStructHash` — `test/v2/types/Eip712.t.sol` | same |

### Notes for this run

The sample orders in `Eip712.t.sol` carry non-empty metadata; the default orders in the hub suites
carry `''`. Mutations, each failing exactly its cases: dropping `keccak256(bytes(order.metadata))`
from `ExecutionOrderLib.hash` (`AUTH-14`, `test_T712_executionOrderStructHash`,
`test_T712_ordersMetadataStructHash`, `testFuzz_T712_DIFF_executionOrder`), the same in
`FulfillmentOrderLib.hash` (`AUTH-17`, `test_T712_fulfillmentOrderStructHash`,
`test_T712_ordersMetadataStructHash`, `testFuzz_T712_DIFF_fulfillmentOrder`), the hub passing an
empty string to `ExecutionWitnessLib.hash` (`AUTH-15`) and to `FulfillmentWitnessLib.hash`
(`AUTH-16`). The hub is 23,092 bytes and the authenticator 12,030.

## Run `20261029T150000Z`

Scope: `SessionOrderAuthenticator` is renamed `TwoTiersOrderAuthenticator`, with its interface,
suite, deploy script and EIP-712 domain name (`KyberSwap Two Tiers Order Authenticator`). The
deploy script's CREATE3 salt prefix and config key change with it. No behaviour changes.

- `forge test --isolate`: 261 passed, 0 failed.
- `DOM-01` and the authenticator's `eip712Domain` case assert the new domain name.

## Run `20261030T043718Z`

Scope: `MsgSender` sets the account an order acts for with `setMsgSender` (executions) or
`setMsgSenderAndLock` (fulfillments), in one transient slot whose bit 160 is the lock. An order may
settle inside a router call of an execution, and `msgSender()` is restored when it returns. No order
may settle inside a fulfillment, at any depth.

| Implemented and verified | Developer reviewed | Review ID | Contract / flow and coverage summary | Case IDs and test files / functions | Passing command or blocker |
|---|---|---|---|---|---|
| - [x] | - [ ] | `20261030T043718Z/NEST-01` | Chains of 1 to 6 nested orders under a top-level execution on either rail, innermost an execution or a fulfillment: every router sees its own level's owner before and after the nested order, `TransferTokens` is emitted once per level in level order, `msgSender()` is zero afterwards | `LOCK-02` `testFuzz_LOCK_02_nestedOrdersRestoreEachOwner` — `test/v2/Settlement.t.sol` | `forge test --isolate` — 264 passed; `deep` profile 10,000 runs |
| - [x] | - [ ] | `20261030T043718Z/NEST-02` | A fulfillment nested in an execution releases the lock on return, so a later router call of the same execution settles another order | `LOCK-05` `test_LOCK_05_fulfillmentLockIsReleasedForTheNextSibling` — `test/v2/Settlement.t.sol` | same |
| - [x] | - [ ] | `20261030T043718Z/REFUSE-01` | Inside a fulfillment, each of the four settlement entry points reverts `AlreadyLocked(<fulfillment owner>)`, reached from a solver call directly or through an execution, and from an ERC721 receiver hook | `LOCK-03` `test_LOCK_03_receiverHookIsRefusedInsideAFulfillment`, `LOCK-06` `testFuzz_LOCK_06_noOrderSettlesInsideAFulfillment` — `test/v2/Settlement.t.sol` | same; `deep` profile 10,000 runs |
| - [x] | - [ ] | `20261030T043718Z/NATIVE-01` | An execution spends its value after a nested order returns; a nested zero-value order cannot spend the outer order's unspent value (`NativeOverspent(VALUE, 0)`) | `LOCK-07` `test_LOCK_07_nestedOrderCannotSpendTheOuterValue` — `test/v2/Settlement.t.sol` | same |

### Notes for this run

`test_LOCK_02_routerReentryIsLocked` and `test_LOCK_03_erc721ReceiverReentryIsLocked` are replaced:
an order settling inside an execution's router call now succeeds, so the refusal is asserted inside
a fulfillment instead. The receiver-hook path inside an execution goes through the same
`setMsgSender` as LOCK-02 and has no case of its own. Under `--isolate` the closing
`msgSender() == address(0)` assertions hold trivially; the restoration oracles are the readings
taken inside the call (`seenBefore`, `seenAfter`, `router2`).

Mutations, each failing the listed cases: dropping `LOCKED_FLAG` (`GATE-01`, `LOCK-03`, `LOCK-06`);
`setMsgSender` storing zero on exit (`LOCK-02`, `LOCK-05`); `setMsgSenderAndLock` storing zero on
exit (`LOCK-02`, `LOCK-05`); `AlreadyLocked` naming the new sender (`LOCK-03`, `LOCK-06`); the
execution rails using `setMsgSenderAndLock` (`LOCK-02`, `LOCK-05`, `LOCK-06`, `LOCK-07`); the
Permit2 execution rail alone using it (`LOCK-02`). The hub is 23,277 bytes.
