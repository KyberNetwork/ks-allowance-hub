# Checked-in artifacts

`Permit2.json` holds the creation bytecode of the canonical Permit2 deployment, so the suite can
run the real contract on a local chain instead of forking mainnet for it.

To regenerate, read the creation code out of the deployment transaction, whose input to the
deterministic deployer is the 32-byte salt followed by the creation code:

```bash
cast tx 0xf2f1fe96c16ee674bb7fcee166be52465a418927d124f5f1d231b36eae65d377 input --rpc-url "$RPC_1"
```

Drop the leading `0x` and the first 64 hex characters, then write the remainder as
`bytecode.object`. `cast artifact <address>` produces the same file from an address alone, but it
reads the deployment trace and so needs an RPC tier that serves `trace_transaction`.

`Multicall3.json` holds the runtime code of the canonical Multicall3 deployment at
`0xcA11bde05977b3631167028862bE2a173976CA11`, so the suite can place the real contract at its
address with `vm.etch` instead of forking mainnet for it.

To regenerate, read the runtime code from any chain that carries the deployment and write it as
`deployedBytecode.object`:

```bash
cast code 0xcA11bde05977b3631167028862bE2a173976CA11 --rpc-url "$RPC_1"
```
