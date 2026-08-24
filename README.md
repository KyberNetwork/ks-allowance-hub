# KS Allowance Hub

Separates token approval from execution. Users grant their allowance once — to the hub, or to
Permit2 — instead of to every router they interact with. Each entrypoint pulls the tokens straight
to the routers that will consume them, then calls those routers.

Only whitelisted routers can be called, so `WHITELIST_ROUTER_ROLE` is what keeps the hub's standing
allowances out of reach of arbitrary callees.

Two contracts are deployable side by side:

| Contract | Entrypoints |
|---|---|
| `KSAllowanceHub` | the legacy hub, still live |
| `KSAllowanceHubV2` | adds solver-fulfilled intents, permissionless submission and permit relaying |

## Entrypoints (V2)

| Function | Tokens pulled from | What the owner signs |
|---|---|---|
| `permitTransferAndExecute` | `msg.sender` | nothing — the caller is the owner |
| `permit2TransferAndExecute` | `owner`, via Permit2 | the funding **and** the exact generic calls |
| `permit2TransferAndFulfill` | `owner`, via Permit2 | the funding and the acceptance criteria, not the calls |
| `permitTokensToPermit2` | — | ERC20 permits, relayed so Permit2 gains the allowance |

`multicall` (OpenZeppelin) batches these into one transaction.

Routers read `msgSender()` to learn whose behalf they act on, since the hub — not the user — is
their `msg.sender`. It is transient, and doubles as the reentrancy guard.

### Signing model

When someone other than the owner submits, the Permit2 signature must also cover a **witness**:

```
RelayerWitness(address relayer,address[] targets,ERC721Transfer[] erc721Transfers,GenericCall[] genericCalls)
SolverWitness(address solver,address callsSigner,address[] targets,ERC721Transfer[] erc721Transfers,ValidationParams[] validationParams)
```

`RelayerWitness` pins the calls themselves, so a relayer can only execute exactly what was signed.
`SolverWitness` deliberately does not: the owner signs the outcome it wants and the solver chooses
the path, bounded by `validationParams` and by `callsSigner`.

Two slots may be left open by signing `ANY_ADDRESS` into them:

- **the submitter** — set `permissionless` when submitting, and anyone may relay or fulfil. The flag
  is not signed and does not need to be: it only selects which digest the hub rebuilds, and the
  wrong choice rebuilds one the owner never signed.
- **the calls signer** — the hub recovers it from `callsSignature` over
  `keccak256(abi.encode(block.chainid, genericCalls, permit.deadline))` and puts the result in the
  witness. Pass an empty signature to leave the call list to the solver.

Leaving both open **and** supplying no `validationParams` lets any caller take the funding and do
whatever a whitelisted router permits.

### Gasless flows

`permitTokensToPermit2` relays the owner's ERC20 permits so **Permit2** gains the allowance, then
`multicall` runs the flow in the same transaction. The owner signs messages and sends no
transaction:

```solidity
hub.multicall([
  abi.encodeCall(hub.permitTokensToPermit2, (tokens, owner, permitData)),
  abi.encodeCall(hub.permit2TransferAndExecute, (permit, targets, …, owner, false, ownerSignature))
]);
```

Two things to know when integrating:

- A relayer-submitted flow needs a **`RelayerWitness` signature**, not a self-permit one. Under
  `multicall` the delegatecall preserves `msg.sender` as the relayer, so `owner != msg.sender`.
- `multicall` is **non-payable**, so no native value can reach a sub-call through it. Send
  value-bearing calls directly.

## Layout

```
src/
  KSAllowanceHub.sol       legacy hub
  KSAllowanceHubV2.sol
  types/                   shared by both hubs
test/
  v1/  v2/                 one folder per hub, each with its own base
  types/                   version-neutral library tests
  mocks/  libraries/       shared fixtures
script/                    deploy + router whitelisting, per hub
```

## Testing

```shell
forge test                                 # 180 tests
forge test --match-path 'test/v1/*'        # legacy hub, 57
forge test --match-path 'test/v2/*'        # V2, 111
forge test --match-path 'test/types/*'     # shared libraries, 12
FOUNDRY_PROFILE=deep forge test            # 10,000 fuzz runs per property
```

`Permit2Mock` is a faithful local stand-in — real EIP-712 domain, unordered nonce bitmap, ECDSA
recovery, deadline and amount checks — so witness binding is genuinely verified rather than stubbed.

`test/types/` is the suite's oracle-independence anchor: it hand-writes every EIP-712 type string
and never imports a production constant to build an expected value. The Permit2 batches sign with
those production constants, so without it they would prove only self-consistency.

### Known tooling issues

- **`forge coverage` does not run.** It force-disables the optimizer and `via_ir` that this project
  requires, hitting stack-too-deep in `ManagementRescuable`; `--ir-minimum` hits it inside
  `permit2TransferAndFulfill`. Branch coverage is reconciled from `forge test -vvvv` traces instead.
- **Mutation testing needs `forge build --force`.** `forge test` does not always rebuild after a
  `src/` edit, so a mutation can silently run against stale artifacts and look undetected.
- **Cheatcodes are consumed by external calls in argument position.** `vm.prank` / `vm.expectRevert`
  apply to the *next* call, and a helper that reads from a contract while building an argument is
  that call. Hoist such values into a local first.

## Deployment

Scripts use CREATE3 and read `script/config/*.json` per chain.

```shell
forge script script/DeployKSAllowanceHubV2.s.sol --sig 'run(string[])' '[1,56]' --broadcast
forge script script/AddWhitelistedRoutersV2.s.sol --sig 'run(string[])' '[1,56]' --broadcast
```

The V1 equivalents are `DeployKSAllowanceHub.s.sol` and `AddWhitelistedRouters.s.sol`; deployed
addresses land in `allowance-hub.json` and `allowance-hub-v2.json`.

CI needs a `GH_PAT` repository secret with read access to the private `ks-action-validator-sc`
submodule, which `actions/checkout` cannot clone with the default token.
