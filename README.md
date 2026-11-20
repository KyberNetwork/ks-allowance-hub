# KS Allowance Hub

The allowance hub separates token approval from execution. An owner approves the hub, or Permit2,
once instead of approving each callee. The hub transfers the owner's tokens to the targets of an
order and then calls whitelisted callees.

Only callees holding `WHITELISTED_CALLEE_ROLE` can be called, so no other contract can reach the
owners' allowances to the hub. Guardians can revoke that role without the admin.

## KSAllowanceHubV2

### Orders

The owner authorises an `AHV2Order`, which names the assets that may leave the owner, how another
account's submission is authenticated, the account that may submit the order, the hooks that
constrain the result and the callee calls the order makes. A solver supplies an `AHV2Solution`,
which the owner does not sign: the target and the amount of each ERC20 transfer, the target of
each ERC721 transfer and the solver data of each call.

```
AHV2Order(address owner,address authenticator,address exclusiveCaller,ERC20Allowance[] erc20Allowances,ERC721Approval[] erc721Approvals,HookParams[] hooks,CallParams[] calls,address solutionApprover,uint256 nonce,uint256 expiration,bytes clientData)
AHV2Solution(address[] erc20Targets,uint160[] erc20Amounts,address[] erc721Targets,uint256[] callValues,bytes[] solverData,uint256 nonce,uint256 expiration)
CallParams(address callee,bytes ownerData)
HookParams(address hook,bytes32 flags,bytes data)
SolutionApproval(AHV2Order order,AHV2Solution solution)
```

`exclusiveCaller` is the account that may submit the order besides the owner. The dead address
`0x…dEaD` allows any account to submit, and as `solutionApprover` it accepts any solution without
an approval.

The hub reverts when either `expiration` has passed, or when the solution does not have one
`erc20Targets` entry and one `erc20Amounts` entry per ERC20 transfer, one `erc721Targets` entry per
ERC721 transfer and one `callValues` entry and one `solverData` entry per call. An ERC20 transfer
sends `solution.erc20Amounts[i]`, at most its allowance.

A settlement runs in this order:

1. the expirations and the lengths of the solution's arrays are checked;
2. the caller is checked against `exclusiveCaller` and authenticated, as `order.authenticator`
   requires;
3. the solution approval is checked, unless `solutionApprover` is the dead address or the caller is
   the owner;
4. each hook's `beforeSettlement` runs when its flags select it;
5. the `SettleOrder` event is emitted;
6. the ERC20 tokens are pulled to the targets of the solution;
7. the ERC721 tokens are transferred to the targets of the solution;
8. `order.calls` run in order through `IAHV2Callee.execute(ownerData, solverData)`, with the
   `ownerData` of the call, `solution.callValues[i]` as native value and `solution.solverData[i]`
   as `solverData`;
9. each hook's `afterSettlement` runs when its flags select it.

The results list the return data of each call, in order.

The solution approval is an EIP-712 `SolutionApproval` signed by `solutionApprover`. It spends
`solution.nonce` in the approver's namespace, so each approval settles at most once. No nonce is
spent when no approval is checked.

An order with no hooks, no calls and a dead-address `solutionApprover` places no constraint on the
solver: the solver chooses every target and every ERC20 amount up to the allowance.

### Hooks

```
HookParams(address hook,bytes32 flags,bytes data)
```

Flag `0x01` selects `beforeSettlement` and flag `0x02` selects `afterSettlement`. Other bits are
ignored. Any address may be a hook, and no role is required.

The hub calls `IAHV2Hook` with the order, its hash, the solution and the index of the hook's entry
in `order.hooks`. The hook reads its own `data` from the order at that index. The result of
`beforeSettlement` is passed to `afterSettlement` as `beforeSettlementResult`, which is empty when
the entry's flags do not select `beforeSettlement`. A hook reverts to refuse the order.

When `order.authenticator` is the Permit2 address, the before hooks run before the permit signature
is checked.

### `solverData`

`solution.solverData` has one entry per call, and the hub reverts when the lengths differ. The
solution approval covers it, when one is required. The owner's signature does not, so a call treats
`solverData` as untrusted input within the limits that `ownerData` sets.

### Authorisation

`settleOrder(order, authenticationData, solution, solutionSignature, usePermit2Allowances)` is the
only entry point. `order.authenticator` selects how an order that another account submits is
authorised:

| `order.authenticator` | Authorisation |
|---|---|
| the zero address | the owner's EIP-712 signature over the order, passed as `authenticationData` |
| the Permit2 address | the owner's Permit2 signature, passed as `authenticationData` |
| any other address | an authenticator the owner delegated, which accepts `authenticationData` |

When another account submits, an authenticator other than the zero address and the Permit2 address
must have been delegated by the owner, and the hub reverts with `AuthenticatorNotDelegated`
otherwise. The owner's own call requires no delegation.

When `order.authenticator` is the zero address, the signature is an EIP-712 signature over the
`AHV2Order` under the hub's domain, made by the owner or validated through ERC-1271 when the owner
is a contract. The hub spends `order.nonce` in the owner's namespace, so a signed order settles at
most once, and reverts with `InvalidOrderSignature` when the signature is not valid. The ERC20
transfers are drawn from the owner's allowances to the hub, or from the owner's Permit2 allowances
when `usePermit2Allowances` is set.

When `order.authenticator` is the Permit2 address, the ERC20 transfers are executed through a
Permit2 batch permit whose nonce is `order.nonce` and whose deadline is `order.expiration`. The
permitted amounts are the order's allowances, and the requested amounts are
`solution.erc20Amounts`. `usePermit2Allowances` is ignored. When another account submits, the
permit also covers the order, so the owner's signature covers the `AHV2Order` as well. The type
string the hub passes to Permit2 is:

```
AHV2Order order)AHV2Order(address owner,address authenticator,address exclusiveCaller,ERC20Allowance[] erc20Allowances,ERC721Approval[] erc721Approvals,HookParams[] hooks,CallParams[] calls,address solutionApprover,uint256 nonce,uint256 expiration,bytes clientData)CallParams(address callee,bytes ownerData)ERC20Allowance(address token,uint160 amount)ERC721Approval(address token,uint256 tokenId)HookParams(address hook,bytes32 flags,bytes data)TokenPermissions(address token,uint256 amount)
```

When `order.authenticator` is a delegated authenticator, the caller must be the order's
`exclusiveCaller`, and the authenticator must accept `authenticationData` for the order. The hub
does not spend `order.nonce` and keeps no record of settled orders, so whether an order may be
settled more than once is the authenticator's decision. The ERC20 transfers are drawn from the
owner's allowances to the hub, or from the owner's Permit2 allowances when `usePermit2Allowances`
is set.

### Orders submitted by the owner

When the caller is `order.owner`, the call itself authorises the order:

- `exclusiveCaller` does not apply;
- when `order.authenticator` is the Permit2 address, the owner signs a permit that does not cover
  the order, and the Permit2 nonce is still spent;
- otherwise no signature is checked, no authenticator is called, `authenticationData` is ignored and
  no nonce is spent, so the same order may settle more than once. The owner submits an order with
  the zero address as `order.authenticator` to avoid delegating an authenticator;
- an authenticator other than the zero address and the Permit2 address must still be delegated;
- `solutionApprover` does not apply: no solution approval is checked and no approval nonce is spent.

### Delegation

```
AuthDelegation(address owner,address authenticator,bool delegated,bytes data,uint256 nonce,uint256 deadline)
```

`updateDelegation` delegates an `IAHV2Authenticator` or withdraws it. When the owner calls it, the
signature must be empty and no nonce is spent. Any other caller must present the owner's signature
over the `AuthDelegation`, which spends `nonce` in the owner's namespace. When delegating with
non-empty `data`, the hub passes `data` to the authenticator's `initAuthentication`. Withdrawing
calls no authenticator and leaves the authenticator's own state unchanged.

An authenticator has two update functions:

- `initAuthentication(owner, data)` takes no signature. Only the hub may call it, and the hub
  calls it only from `updateDelegation`.
- `updateAuthentication(owner, data, nonce, deadline, signature)` can be called by any account,
  including Multicall3 relaying it through the hub's `forwardCalls`. An authenticator must
  therefore accept only `msg.sender == owner` without a signature.

The hub spends a solution approval's `solution.nonce` in the `solutionApprover`'s address namespace
in the hub, shared with that address's `updateDelegation` nonces. The approver revokes an unused
approval with the hub's `revokeNonce(nonce)`.

### Authenticators

`HierarchicalAuthKeyAHV2Authenticator`, in
[ks-ahv2-authenticator-sc](https://github.com/KyberNetwork/ks-ahv2-authenticator-sc), is an
authenticator in which the owner approves master keys, a master key approves session keys, and
both kinds of key sign orders without the owner's wallet.

### Relayed approvals

The hub's `forwardCalls(calls)` passes `calls` unchanged to `aggregate3` of the Multicall3
deployment set at deployment, `0xcA11bde05977b3631167028862bE2a173976CA11` on most chains.
Multicall3 holds no allowance, role or asset of the hub, so a relayed call carries no authority
beyond what its own payload proves: a token permit, a signed delegation, a signed authenticator
update.

The relayed calls run in a hub `multicall` beside the order that uses them, with the relayer still
the order's `msg.sender`. A failing call whose `allowFailure` is false reverts the batch with
Multicall3's error `Multicall3: call failed`, not with the call's own revert data. A relayer that
batches a signed permit or delegation with the order using it should set `allowFailure`, so that
another account submitting the same signature first does not revert the batch. Native value sent
with `forwardCalls` is not forwarded and remains in the hub.

```solidity
hub.multicall([
  abi.encodeCall(hub.forwardCalls, (permitCalls)),
  abi.encodeCall(
    hub.settleOrder, (order, authData, solution, solutionSignature, false)
  )
]);
```

### Callees

```solidity
interface IAHV2Callee {
  function execute(bytes calldata ownerData, bytes calldata solverData)
    external
    payable
    returns (bytes memory);
}
```

Each callee must hold `WHITELISTED_CALLEE_ROLE` when its call runs. `AHV2Solution.callValues` holds
the native value of each call, chosen by the solver and paid from the `msg.value` sent with the
order. The hub reverts when the order spends more native value than it was sent. The hub has no
`receive` function, so a callee cannot refund native value to it; unspent `msg.value` remains in the
hub.

While an order settles, `msgSender()` returns its owner, so a callee called by the hub can identify
the owner. A callee treats `solverData` as untrusted input, because the owner does not sign it.

A callee call of an order may settle another order of any authenticator, and `msgSender()` returns
the outer order's owner again once it returns. The hub refuses no order for settling inside another.

### Reentrancy and hooks

Reentrancy is a design choice of the hub: a callee call of an order may settle another order, and
the hub does not refuse it. A hook that compares balances before and after the order's calls also
counts the assets that a nested order delivers in the same interval. Two orders with the same
recipient can each pass a hook that checks the recipient's balance increase, while the recipient
receives the output of only one of them.

An order therefore protects the owner's intent by combining hooks with its calls, not by hooks
alone. In a swap, a call executes the route in its `solverData` and delivers the output to an
account the order specifies, and the last call in `calls` transfers the output from that account
to the recipient. The owner signs that transfer and its amount, so the funds the recipient
receives are moved by this order's own call. Each such transfer removes its amount from the
account, so the output of another order with the same recipient cannot satisfy it.

### Management

The hub inherits `ManagementSimple` from `ks-common-sc`. The owner holds the default admin role,
transferable in one step with `transferOwnership`. Guardians pause the hub and revoke callees.
Rescuers, or the default admin, call `rescueTokens(erc20Transfers, erc721Transfers)` to transfer
assets held by the hub. An ERC20 entry with a zero amount transfers the hub's entire balance, and a
token of `0xEeee…EEeE` or the zero address transfers native value.

### Signing domains

| Contract | EIP-712 name | Version |
|---|---|---|
| `KSAllowanceHubV2` | `KyberSwap Allowance Hub` | `2.0.0` |

The domain is published through ERC-5267's `eip712Domain()`.

## Layout

```
src/
  KSAllowanceHubV2.sol
  base/            AHV2AuthenticatorBase, AuthDelegator, EIP712Nonce, MsgSender, Multicall,
                   NativeSpendGuard, UnorderedNonce
  interfaces/      IKSAllowanceHubV2; base/ holds the interfaces of the base contracts, IAHV2Hook,
                   IAHV2Authenticator and IAHV2Callee
  libraries/       Constants, DynamicArrayLibExt, EfficientHashLibExt
  types/           AHV2Order, AHV2Solution, AuthDelegation, CallParams, HookParams,
                   SolutionApproval, ERC20Allowance, ERC20Transfer, ERC721Approval, ERC721Transfer,
                   NativeTransfer
test/
  settlement/      Authentication, CalldataHygiene, Calls, Events, Hooks, Nesting, SettleFuzz,
                   Solution and SolutionApproval suites; base/ holds the helpers they share
  delegation/      Delegation and Nonces suites
  batching/        Forwarder and Multicall suites
  admin/           Guards and Management suites
  base/            HubBase, SchemaHash, SignerAuthenticatorBase, V2TestBase
  mocks/           callee, hook, permit token, signer authenticator and token mocks
  types/           Eip712 and SchemaAudit suites
  libraries/       ArrayHelper, PermitHash
  artifacts/       Multicall3 and Permit2 creation code
script/
  DeployKSAllowanceHubV2.s.sol, AddWhitelistedCalleesV2.s.sol
  config/          per-chain deployment parameters
```

## Testing

```shell
forge test                                 # the whole suite
FOUNDRY_PROFILE=deep forge test            # 10,000 fuzz runs per property
forge coverage --ir-minimum --report summary
```

The suite deploys Permit2 from `test/artifacts/Permit2.json` and needs no RPC.

The files under `test/base`, `test/mocks` and `test/libraries` import with relative paths, so that
a repository holding this one as a submodule can inherit them. Such a repository overrides
`V2TestBase._artifactsDir()` with the path of `test/artifacts/` inside the submodule.

CI runs `forge test -vvv --isolate`, which executes each top-level call as its own transaction.
Transient state such as the account `msgSender()` returns is cleared between calls, so it can only
be observed from inside a callee call.

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
forge script script/DeployKSAllowanceHubV2.s.sol           --sig 'run(string[])' '[1,56]' --broadcast
forge script script/AddWhitelistedCalleesV2.s.sol          --sig 'run(string[])' '[1,56]' --broadcast
```

`DeployKSAllowanceHubV2` reads the Multicall3 address from `multicall3.json`, which holds the
canonical address by default; a chain where Multicall3 is deployed elsewhere needs its own entry. It
passes the addresses in `whitelisted-callees.json` to the constructor as
`initialWhitelistedCallees`, and writes the hub's address to `allowance-hub-v2.json`, which
`AddWhitelistedCalleesV2` reads.

`AddWhitelistedCalleesV2` grants `WHITELISTED_CALLEE_ROLE` to the callees in
`whitelisted-callees.json` that do not hold it, in one transaction through the hub's `multicall`.

Each deploy script's `salt` is part of the CREATE3 salt, so changing it changes the deployed address
on every chain.
