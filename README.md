# KS Allowance Hub

The allowance hub separates token approval from execution. An owner approves the hub, or Permit2,
once instead of approving each router. The hub transfers the owner's tokens to the targets of an
order and then calls whitelisted routers.

Only routers holding `WHITELISTED_ROUTER_ROLE` can be called, so no other contract can reach the
owners' allowances to the hub. Guardians can revoke that role without the admin.

Two hubs can be deployed side by side:

| Contract | Description |
|---|---|
| `KSAllowanceHub` | The legacy hub |
| `KSAllowanceHubV2` | Signed orders, solver fulfillment, delegated authentication and relayed approvals |

## KSAllowanceHubV2

### Orders

The owner signs one of two order types. Both name the assets that may leave the owner and the
account that may submit the order.

| Order | The owner signs | The submitter chooses |
|---|---|---|
| `ExecutionOrder` | the legs, their targets and the exact router calls | nothing |
| `FulfillmentOrder` | the legs, the validators and the owner's own router calls | a `FulfillmentSolution`: the target of each leg and the solver's router calls |

```
ExecutionOrder(address owner,address relayer,ERC20Transfer[] erc20Transfers,ERC721Transfer[] erc721Transfers,GenericCall[] genericCalls,uint256 nonce,uint256 deadline,string metadata)
FulfillmentOrder(address owner,address solver,ERC20Allowance[] erc20Allowances,ERC721Approval[] erc721Approvals,ValidationParams[] validationParams,GenericCall[] ownerCalls,address solutionApprover,uint256 nonce,uint256 deadline,string metadata)
FulfillmentSolution(address[] erc20Targets,address[] erc721Targets,GenericCall[] solverCalls,uint256 deadline)
```

`relayer` or `solver` is the account that may submit the order besides the owner. The dead address
`0x…dEaD` allows any account to submit.

A fulfillment settles in this order:

1. the solution approval is checked, unless `solutionApprover` is the dead address;
2. each validator's `beforeExecution` runs;
3. each leg is transferred to the target the solution names for it;
4. `solution.solverCalls` run;
5. each validator's `afterExecution` runs;
6. `order.ownerCalls` run.

The validators do not observe the effects of `ownerCalls`. The solution approval is an EIP-712
`SolutionApproval(FulfillmentOrder order,FulfillmentSolution solution)` signed by
`solutionApprover`. It carries no nonce, so it is valid for every settlement of its order.

An order with no validators and a dead-address `solutionApprover` places no constraint on the
solver: the solver chooses every target and every router call.

### Entry points

| Function | Authorisation |
|---|---|
| `executeOrderWithPermit2Signature` | the owner's Permit2 signature |
| `executeOrderWithDelegatedAuthentication` | an authenticator the owner delegated |
| `fulfillOrderWithPermit2Signature` | the owner's Permit2 signature |
| `fulfillOrderWithDelegatedAuthentication` | an authenticator the owner delegated |

On the **Permit2 entry points**, the ERC20 legs are transferred through a Permit2 batch permit whose
nonce is `order.nonce` and whose deadline is `order.deadline`. When another account submits, the
owner's signature must also cover a witness:

```
ExecutionWitness(address relayer,address[] erc20Targets,ERC721Transfer[] erc721Transfers,GenericCall[] genericCalls,string metadata)
FulfillmentWitness(address solver,ERC721Approval[] erc721Approvals,GenericCall[] ownerCalls,ValidationParams[] validationParams,address callsSigner,string metadata)
```

The two witnesses have distinct type names, so a signature for one entry point is not valid for the
other.

On the **delegated entry points**, the owner must have delegated the authenticator, the caller must
be the order's submitter, and the authenticator must accept `authenticationData` for the order. The
hub does not spend `order.nonce`; replay protection is the authenticator's. The ERC20 legs are drawn
from the owner's allowances to the hub, or from the owner's Permit2 allowances when
`usePermit2Allowances` is set.

### Orders submitted by the owner

When the caller is `order.owner`, the call itself authorises the order:

- `relayer` and `solver` do not apply;
- on the Permit2 entry points, the owner signs the permit without a witness, and the Permit2 nonce
  is still spent;
- on the delegated entry points, the authenticator is not called, `authenticationData` is ignored
  and no nonce is spent, so the same order may settle more than once. `authenticator` may be the
  zero address in this case only;
- a fulfillment still requires its solution approval.

### Delegation

```
AuthDelegation(address owner,address authenticator,bool delegated,bytes data,uint256 nonce,uint256 deadline)
```

`updateDelegation` delegates an `IOrderAuthenticator` or withdraws it. When the owner calls it, the
signature must be empty and no nonce is spent. Any other caller must present the owner's signature
over the `AuthDelegation`, which spends `nonce` in the owner's namespace. When delegating with
non-empty `data`, the hub passes `data` to the authenticator's `initAuthentication`. Withdrawing
calls no authenticator and leaves the authenticator's own state unchanged.

An authenticator has two update functions:

- `initAuthentication(owner, data)` takes no signature. Only the hub may call it, and the hub
  calls it only from `updateDelegation`.
- `updateAuthentication(owner, data, nonce, deadline, signature)` can be called by any account,
  including the calls forwarder. An authenticator must therefore accept only `msg.sender == owner`
  without a signature.

### TwoTiersOrderAuthenticator

The reference authenticator. The owner approves keys, and the keys sign orders without the owner's
wallet.

```
AuthKey(bytes publicKey,uint8 keyType,uint256 expiration)
MasterKeyUpdate(address owner,AuthKey masterKey,bool approved,uint256 nonce,uint256 deadline)
SessionKeyUpdate(address owner,AuthKey masterKey,AuthKey sessionKey,bool approved,uint256 nonce,uint256 deadline)
NonceRevocation(AuthKey key,uint256 nonce,uint256 deadline)
```

| `keyType` | `publicKey` | Verification |
|---|---|---|
| `Secp256k1` | `abi.encode(address)` | ECDSA recovery |
| `P256` | `abi.encodePacked(qx, qy)` | P-256 |
| `WebAuthn` | `abi.encodePacked(qx, qy)` | WebAuthn assertion with user verification |
| `RSA` | `abi.encode(bytes e, bytes n)` | PKCS#1 v1.5 with SHA-256 |
| `ERC1271` | `abi.encode(address)` | the contract's `isValidSignature` |
| `ERC7913` | `abi.encodePacked(verifier, key)` | the verifier's `verify` |

Keys have two tiers. The owner approves **master keys**, through `initAuthentication` when
delegating or through `updateAuthentication` afterwards. A master key approves **session keys** for
the same owner, so a passkey can issue short-lived local keys without the wallet. Both tiers sign
orders.

- A session key may not expire after its master key, and is not accepted once its master key is
  revoked.
- A master key may change only a session key it approved, or one that no master key has approved.
- A key's expiry is checked only when approving, so an expired key can still be revoked.

`updateAuthentication` takes `abi.encode(AuthKey masterKey, bool approved)` for the owner's
decision, or `abi.encode(AuthKey sessionKey, AuthKey masterKey, bool approved)` for a master key's.
The owner's decision needs no signature when the owner calls; a master key's decision is always
signed by the master key. Orders are authenticated with
`abi.encode(AuthKey key, bool isSessionKey, bytes signature)`, where `signature` is the key's
signature over the order's EIP-712 digest under the authenticator's domain.

Every signature spends a nonce in its signer's namespace: the owner's address for the owner's
approvals, and the key's credential hash, `keccak256(abi.encodePacked(keyType, publicKey))`, for
anything a key signs. The credential hash excludes the expiry, so all approvals of one key share
its nonces. `revokeNonce(AuthKey, nonce, deadline, signature)` spends a key's nonce on the key's
signature, whether or not the key is still approved or unexpired.

### Relayed approvals

`CallsForwarder` is a separate contract whose `forwardCalls(targets, data, allowFailure)` relays
any call. It holds no allowance, role or asset, so a relayed call carries no authority beyond what
its own payload proves: a token permit, a signed delegation, a signed authenticator update. No
contract may grant the forwarder authority.

The hub's `forwardCalls` calls the forwarder set at deployment, so that the relayed calls can run
in a hub `multicall` beside the order that uses them, with the relayer still the order's
`msg.sender`. A reverting call reverts the batch unless its bit in `allowFailure` is set. A relayer
that batches a signed permit or delegation with the order using it should set that bit, so that
another account submitting the same signature first does not revert the batch. Native value sent
with `forwardCalls` is not forwarded and remains in the hub.

```solidity
hub.multicall([
  abi.encodeCall(hub.forwardCalls, (targets, permitCalls, allowFailure)),
  abi.encodeCall(hub.executeOrderWithDelegatedAuthentication, (order, authenticator, authData, false))
]);
```

### Routers and native value

While an order settles, `msgSender()` returns its owner, so a router called by the hub can identify
the owner. A router call of an execution may settle other orders, and `msgSender()` returns the
execution's owner again once each returns. No order may settle while a fulfillment is in progress,
so its validators observe that fulfillment alone. Each router call may spend native value
only from the `msg.value` sent with the order. The hub has no `receive` function, so a router cannot
refund native value to it; unspent `msg.value` remains in the hub.

### Management

The hub inherits `ManagementSimple` from `ks-common-sc`. The owner holds the default admin role,
transferable in one step with `transferOwnership`. Guardians pause the hub and revoke routers.
Rescuers, or the default admin, call `rescueTokens(erc20Transfers, erc721Transfers)` to transfer
assets held by the hub. An ERC20 entry with a zero amount transfers the hub's entire balance, and a
token of `0xEeee…EEeE` or the zero address transfers native value.

### Signing domains

| Contract | EIP-712 name | Version |
|---|---|---|
| `KSAllowanceHubV2` | `KyberSwap Allowance Hub` | `2.0.0` |
| `TwoTiersOrderAuthenticator` | `KyberSwap Two Tiers Order Authenticator` | `1.0.0` |

Each domain is published through ERC-5267's `eip712Domain()`.

## Layout

```
src/
  base/            contracts shared by both hubs
  v1/              KSAllowanceHub
  v2/              KSAllowanceHubV2, its delegator and multicall, CallsForwarder, types and libraries
  v2/authenticators/  TwoTiersOrderAuthenticator and its key types
test/
  base/            shared test base, EIP-712 oracles and the Permit2 artifact check
  v1/              KSAllowanceHub suite, on a mainnet fork
  v2/              KSAllowanceHubV2 and TwoTiersOrderAuthenticator suites, on a local chain
  libraries/       Permit2 hashing and array helpers
  artifacts/       Permit2 creation code
script/
  v1/, v2/         deployment and router whitelisting
```

## Testing

```shell
forge test                                 # the whole suite
forge test --match-path 'test/v1/*'        # KSAllowanceHub only
FOUNDRY_PROFILE=deep forge test            # 10,000 fuzz runs per property
forge coverage --ir-minimum --report summary
```

The V1 suite forks mainnet and requires `RPC_1`, through `.env` locally and repository secrets in
CI. The V2 suite deploys Permit2 from `test/artifacts/Permit2.json` and needs no RPC.

CI runs `forge test -vvv --isolate`, which executes each top-level call as its own transaction.
Transient state such as the `msgSender()` lock is cleared between calls, so it can only be observed
from inside a router call.

The EIP-712 type strings are checked against the struct declarations through `forge bind-json`,
which generates `utils/JsonBindings.sol`. Run it twice after changing a bound struct; CI fails when
the regenerated file differs.

### Known tooling issues

- **Coverage requires `--ir-minimum`.** Plain `forge coverage` compiles without `via_ir` and fails
  with stack-too-deep. `--ir-minimum` compiles differently from the build the tests run against, so
  some covered branches are reported as missed.
- **Cheatcodes apply to the next external call, including one made while building an argument.**
  Read such values into a local before `vm.prank` or `vm.expectRevert`.

## Documentation

`forge doc` generates a [Vocs](https://vocs.dev) site from the NatSpec into `docs/`, which is not
committed. The dependencies `forge doc` declares do not currently install cleanly, so each run of
`forge doc` is followed by an install that pins working versions:

```shell
forge doc
cd docs
npm install --save-exact --legacy-peer-deps \
  vocs@2.10.3 \
  waku@1.0.0-rc.4 \
  react@19.3.1 \
  react-dom@19.3.1
npm run dev      # serve locally
npm run build    # build the static site
```

See [Foundry's contract documentation guide](https://www.getfoundry.sh/forge/documentation#contract-documentation).

## Deployment

The scripts deploy with CREATE3 and read `script/config/*.json` per chain.

```shell
forge script script/v1/DeployKSAllowanceHub.s.sol             --sig 'run(string[])' '[1,56]' --broadcast
forge script script/v1/AddWhitelistedRouters.s.sol            --sig 'run(string[])' '[1,56]' --broadcast

forge script script/v2/DeployCallsForwarder.s.sol             --sig 'run(string[])' '[1,56]' --broadcast
forge script script/v2/DeployKSAllowanceHubV2.s.sol           --sig 'run(string[])' '[1,56]' --broadcast
forge script script/v2/DeployTwoTiersOrderAuthenticator.s.sol  --sig 'run(string[])' '[1,56]' --broadcast
forge script script/v2/AddWhitelistedRoutersV2.s.sol          --sig 'run(string[])' '[1,56]' --broadcast
```

`DeployCallsForwarder` writes the forwarder's address to `calls-forwarder.json`, which
`DeployKSAllowanceHubV2` reads, so the forwarder is deployed first. `DeployKSAllowanceHubV2` writes
the hub's address to `allowance-hub-v2.json`, which `DeployTwoTiersOrderAuthenticator` and
`AddWhitelistedRoutersV2` read.
`AddWhitelistedRoutersV2` grants the missing routers in one transaction through the hub's
`multicall`.

The two hubs use different router roles: V1 grants `WHITELIST_ROUTER_ROLE` and V2 grants
`WHITELISTED_ROUTER_ROLE`, so their scripts are not interchangeable.

Each deploy script's `salt` is part of the CREATE3 salt, so changing it changes the deployed address
on every chain.

CI requires a `GH_PAT` repository secret with read access to the private `ks-action-validator-sc`
submodule.
