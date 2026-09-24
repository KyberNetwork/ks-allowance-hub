# KS Allowance Hub

Separates token approval from execution. Users grant their allowance once — to the hub, or to
Permit2 — instead of to every router they interact with. Each entrypoint pulls the tokens straight
to the routers that will consume them, then calls those routers.

Only whitelisted routers can be called, so `WHITELISTED_ROUTER_ROLE` is what keeps the hub's
standing allowances out of reach of arbitrary callees. Guardians can revoke that role without
waiting on the admin.

Two contracts are deployable side by side:

| Contract | Entrypoints |
|---|---|
| `KSAllowanceHub` | the legacy hub, still live |
| `KSAllowanceHubV2` | adds solver-fulfilled intents, delegated verifiers and open submission |

## Entrypoints (V2)

| Function | What the owner signs |
|---|---|
| `transferAndExecute` | the funding **and** the exact generic calls |
| `transferAndFulfill` | the funding and the acceptance criteria, not the calls |

Both pull ERC20s and ERC721s from `owner` and forward them to the routers named in the transfers,
then call those routers. `multicall` (Solady) batches them into one transaction, bounded as a whole
for native spend.

Routers read `msgSender()` to learn whose behalf they act on, since the hub — not the user — is
their `msg.sender`. It holds the **owner**, is transient, and doubles as the reentrancy guard.

### Authorisation

`authFlags` is a `bytes32` read as three low bits, and it selects the rail rather than granting
anything:

| Bit | Set | Effect |
|---|---|---|
| 0 | Permit2 signature transfer | the owner's Permit2 signature funds the order |
| 1 | Permit2 allowance transfer | pull through the owner's standing Permit2 allowance |
| 2 | caller is pinned | the owner named `msg.sender`; unset means anyone may submit |

`authData` is packed to match:

```
Permit2 rail    abi.encode(uint256 nonce, bytes signature)
verifier rail   abi.encode(address verifier, uint256 nonce, bytes key, bytes signature)
```

An owner calling on their own behalf needs neither rail's signature — `msg.sender == owner` is the
authorisation.

### Signing model

When someone other than the owner submits over Permit2, the signature must also cover a **witness**:

```
ExecutionWitness(address relayer,address[] targets,ERC721Transfer[] erc721Transfers,GenericCall[] genericCalls)
FulfillmentWitness(address solver,address[] targets,ERC721Transfer[] erc721Transfers,ValidationParams[] validationParams,address callsSigner)
```

`ExecutionWitness` pins the calls themselves, so a relayer can only execute exactly what was signed.
`FulfillmentWitness` deliberately does not: the owner signs the outcome it wants and the solver
chooses the path, bounded by `validationParams` and by `callsSigner`.

Two slots may be left open by signing `0x…dEaD` into them:

- **the submitter** — leave bit 2 of `authFlags` clear and anyone may submit. The flag is not
  signed and does not need to be: it only selects which digest the hub rebuilds, and the wrong
  choice rebuilds one the owner never signed.
- **the calls signer** — the hub recovers it from `callsSignature` over an EIP-712
  `CallsApproval(address owner,GenericCall[] genericCalls,uint256 nonce,uint256 deadline)` and puts
  the result in the witness. Pass an empty signature to leave the call list to the solver; a
  non-empty one burns `callsNonce` against the owner, so an approval settles at most once.

Leaving both open **and** supplying no `validationParams` lets any caller take the funding and do
whatever a whitelisted router permits.

### Delegated verifiers

Instead of a Permit2 signature, an owner can delegate an `IAuthVerifier` once through
`delegateAuth`, and afterwards authorise orders with whatever credential that verifier
understands. The hub checks only that the verifier is delegated; the verifier must revert when a
signature does not authorise the order, and owns its own replay protection.

An empty signature reaching a verifier means the hub already authenticated the owner — either the
owner called `delegateAuth` themselves, or it carried their EIP-712 `AuthDelegation` signature.

`SessionAuthVerifier` is the reference implementation: the owner approves a `SessionKey`
(`Secp256k1`, `P256`, `WebAuthn` or `RSA`, with an expiry) and that key then signs orders. Note
that key approvals are additive — `revokeDelegation` disarms the verifier as a whole, but
re-delegating re-arms every key previously approved.

### Gasless flows

`erc20Permit`, `erc721Permit` and `permit2Permit` relay the owner's permits, and every helper on
the hub is `payable`, so a permit and a swap compose inside one `multicall` even when it carries
value. The owner signs messages and sends no transaction:

```solidity
hub.multicall([
  abi.encodeCall(hub.erc20Permit, (owner, tokens, permitData)),
  abi.encodeCall(hub.transferAndExecute, (owner, erc20Transfers, …, authFlags, authData))
]);
```

Two things to know when integrating:

- A relayer-submitted flow needs a **witness signature**, not a self-permit one. Under `multicall`
  the delegatecall preserves `msg.sender` as the relayer, so `owner != msg.sender`.
- `multicall` is **payable**, and bounded as a whole: every sub-call is a `delegatecall` and sees
  the same `msg.value` though it arrived once, so the batch may spend that value in total, not once
  per call. Nested batches are covered by the same outer bound.
- The hub has no `receive`, so a router cannot refund native to it. Unspent `msg.value` stays in
  the hub and is recoverable only by a rescuer.

## Layout

```
src/
  base/        building blocks shared by the hub and verifiers
  v1/          legacy hub
  v2/          KSAllowanceHubV2 and its types
  verifiers/   SessionAuthVerifier
test/
  v1/          legacy hub suite, mainnet fork
  libraries/   shared helpers
script/        deploy + router whitelisting, per hub
```

## Testing

```shell
forge test                                 # the whole suite
forge test --match-path 'test/v1/*'        # legacy hub
FOUNDRY_PROFILE=deep forge test            # 10,000 fuzz runs per property
forge coverage --report summary --ir-minimum --no-match-coverage 'lib|script'
```

The v1 suite forks mainnet, so `RPC_1` must be set — locally through `.env`, in CI through
repository secrets. CI runs `forge test -vvv --isolate`, which executes every top-level call as its
own transaction: transient state such as the `msgSender()` lock is cleared between calls, so it has
to be observed from inside a router callback rather than across two calls.

### Known tooling issues

- **Coverage needs `--ir-minimum`.** The project builds with `via_ir` and a high optimizer run
  count; plain `forge coverage` recompiles without them. `--ir-minimum` recompiles differently from
  the artifacts CI builds, so treat reported misses on assembly-bodied code as diagnostic and
  reconcile them against `forge test -vvvv` traces.
- **Cheatcodes are consumed by external calls in argument position.** `vm.prank` /
  `vm.expectRevert` apply to the *next* call, and a helper that reads from a contract while
  building an argument is that call. Hoist such values into a local first.

## Deployment

Scripts use CREATE3 and read `script/config/*.json` per chain.

```shell
forge script script/DeployKSAllowanceHub.s.sol --sig 'run(string[])' '[1,56]' --broadcast
forge script script/AddWhitelistedRoutersV2.s.sol --sig 'run(string[])' '[1,56]' --broadcast
```

Deployed addresses land in `allowance-hub.json` and `allowance-hub-v2.json`. There is no V2 deploy
script yet — `AddWhitelistedRoutersV2` reads `allowance-hub-v2`, which stays empty until one exists.

CI needs a `GH_PAT` repository secret with read access to the private `ks-action-validator-sc`
submodule, which `actions/checkout` cannot clone with the default token.
