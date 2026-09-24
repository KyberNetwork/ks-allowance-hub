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
