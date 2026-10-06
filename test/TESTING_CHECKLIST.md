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
- `test/libraries/PermitHash.sol` is deliberately not reused: it takes the witness type string as a
  parameter, which reintroduces exactly that circularity.
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
