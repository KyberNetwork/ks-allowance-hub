# Checked-in artifacts

`Permit2.json` holds the creation bytecode of the canonical Permit2 deployment, so the suite can
run the real contract on a local chain instead of forking mainnet for it.

`ART-01` in `test/base/Permit2Artifact.t.sol` proves the bytes are that deployment: Permit2 was
created by the deterministic deployer, so its address is a CREATE2 of the deployer, the salt and
this creation code. The case recomputes that address and compares it with
`0x000000000022D473030F116dDEE9F6B43aC78BA3`. The proof needs no network.

To regenerate, read the creation code out of the deployment transaction, whose input to the
deterministic deployer is the 32-byte salt followed by the creation code:

```bash
cast tx 0xf2f1fe96c16ee674bb7fcee166be52465a418927d124f5f1d231b36eae65d377 input --rpc-url "$RPC_1"
```

Drop the leading `0x` and the first 64 hex characters, then write the remainder as
`bytecode.object`. `cast artifact <address>` produces the same file from an address alone, but it
reads the deployment trace and so needs an RPC tier that serves `trace_transaction`.
