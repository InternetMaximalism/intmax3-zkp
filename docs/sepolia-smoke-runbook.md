# Sepolia smoke-deploy runbook — IntmaxRollup

End-to-end smoke of the **real** on-chain validity path on Sepolia:

```
deploy (MleVerifier + IntmaxRollup, real MLE VK degreeBits=13)
  → postBlockAndSubmit empty block #1 (blob tx, 1 ether stake)
  → finalize submission 0 (real ValidityPublicInputs + real MleProof + real MLE/WHIR verification)
```

This is the same sequence the passing Forge test `contracts/test/MleFinalizeE2E.t.sol`
exercises in one EVM run, split here into broadcast scripts + a `cast` blob tx.

**Sepolia is post-Pectra**, so EIP-4844 blobs and the EIP-2537 BLS precompiles
(used by the KZG blob check) are both available — the same precompiles revm/anvil
provide, which is why the rehearsal below works locally.

> The commands below were **rehearsed end-to-end on a local anvil** (secret-free,
> using anvil's throwaway dev account). Going to Sepolia only swaps the `--rpc-url`
> and the signing key (`--private-key <anvil dev key>` → `--account smoke-deployer`).
> See "Local anvil rehearsal" at the bottom for the exact transcript.

---

## ✅ Resolved: MleVerifier now fits under the EIP-170 24 KB code-size limit

`MleVerifier` deployed bytecode was **53,975 bytes**, over the **24,576-byte**
EIP-170 limit (it inlined the gate-evaluation and WHIR-verification subtrees).
**Resolved** by externalizing the two coarse, once-called entry points
`Plonky2GateEvaluator.evalCombinedFlat` and `SpongefishWhirVerify.verifyWhirProof`
from `internal pure` to `external pure` (polygon-plonky2 submodule commit
`2a1f5028`), so they deploy as separate delegatecall-linked libraries:

- `MleVerifier` 53,975 → **14,030 bytes** (margin +10,546).
- Extracted libraries: `Plonky2GateEvaluator` 21,911 B, `SpongefishWhirVerify`
  22,218 B — both under the limit.
- Confirmed: deploy now succeeds on `anvil --hardfork prague` **without**
  `--disable-code-size-limit`, i.e. under real EIP-170 enforcement.

The change is strictly behavior-preserving (both functions are `pure`; no
storage/context/transcript state crosses the boundary; ABI-lossless). Verified by
the submodule's 79/79 suite (incl. tamper/boundary-reject tests), parent
`MleE2E` + `MleFinalizeE2E`, and an independent adversarial review.

**Deploy-trust note:** the two libraries are linked at deploy time via Forge's
auto-deploy/auto-link (`new MleVerifier()` in `script/Deploy.s.sol`). The library
address is fixed in immutable code, not attacker-controllable. Do NOT hand-specify
a `[libraries]` address in `foundry.toml` for a real deploy — always use the
auto-link path so a malicious delegatecall target cannot be substituted.

---

## Prerequisites

- Foundry **1.5.1** (`forge`/`cast`/`anvil --version`). Blob flag is `--path` (see below).
- `cd contracts && forge install` already run; `forge build` clean.
- A Sepolia RPC URL and a funded deployer EOA (needs > 1 ETH for the stake + gas).

Copy the env template and fill it in (`.env` is git-ignored):

```bash
cd contracts
cp .env.example .env
# edit .env: SEPOLIA_RPC_URL=...   (ETHERSCAN_API_KEY / FRAUD_TREASURY optional)
```

Import the deployer key **once** into Foundry's encrypted keystore — the key is
typed at an interactive prompt, never pasted on a CLI or written to a file:

```bash
cast wallet import smoke-deployer --interactive
# paste the private key at the prompt; choose a keystore password
# every command below then uses `--account smoke-deployer` (Foundry asks for the
# keystore password at run time). NO private key ever touches a file or the shell.
```

---

## Ordered smoke commands (Sepolia)

All commands run from `contracts/`. `sepolia` resolves to `$SEPOLIA_RPC_URL`
via `foundry.toml [rpc_endpoints]`.

### 1. (Re)generate the fixtures

From the repo root:

```bash
cargo run --bin generate_e2e_fixture --release
```

This refreshes `contracts/test/data/{mle_fixture,vpi_fixture,block_fixture}.json`,
which the scripts parse for every constructor arg, the SubBlock, the
ValidityPublicInputs and the MleProof.

### 2. Deploy MleVerifier + IntmaxRollup

```bash
forge script script/Deploy.s.sol \
  --rpc-url sepolia \
  --account smoke-deployer \
  --broadcast
```

> Forge auto-deploys and links the two external libraries (`Plonky2GateEvaluator`,
> `SpongefishWhirVerify`) before `MleVerifier`. No `--disable-code-size-limit` is
> needed — all contracts are under EIP-170 (see the resolved section above).

Record the printed `IntmaxRollup` address and set it in your env:

```bash
export ROLLUP_ADDR=0x...        # the IntmaxRollup address from the deploy logs
```

(If you set `FRAUD_TREASURY` in `.env` it is used; otherwise the broadcaster
address is used as the fraud treasury.)

### 3. postBlockAndSubmit empty block #1 (blob tx, 1 ether stake)

`postBlockAndSubmit` is **payable** (requires exactly `1 ether` POST_BLOCK_STAKE)
and **requires a blob** — it reads `blobhash(0)` and reverts `NoBlobAttached` if
zero. Forge scripts cannot attach EIP-4844 blobs, so this step uses `cast send`.

Make exactly one blob (128 KB of zeros — content is irrelevant here, only its
presence is checked):

```bash
head -c 131072 /dev/zero > blob.bin    # 131072 = 128 KiB = exactly 1 blob
```

Send it (arg values come straight from `block_fixture.json`):

```bash
cast send $ROLLUP_ADDR \
  "postBlockAndSubmit((uint32,uint64,bytes32,uint32[])[],bytes32,uint32,bytes32)" \
  "[(1,1,0x0000000000000000000000000000000000000000000000000000000000000000,[0,0])]" \
  0x0000000000000000000000000000000000000000000000004362d402885f19f1 \
  202704 \
  0x2cfa6af8d4c60fb00b2002506dcc5631b06689e74e43cca96730f88058a215b3 \
  --value 1ether \
  --blob --path blob.bin \
  --rpc-url sepolia \
  --account smoke-deployer
```

> **Blob flag for Foundry 1.5.1:** the blob file is passed with **`--path <file>`**
> together with `--blob`. (There is **no** `--blob-file` flag in this version —
> `cast send --help` lists `--blob` + `--path <BLOB_DATA_PATH>`.)

Arg meaning (from `block_fixture.json`):
- SubBlock: `channelId=1, timestamp=1, txTreeRoot=0x00…00, keyIds=[0,0]`
- `proofHash  = 0x0000000000000000000000000000000000000000000000004362d402885f19f1`
- `proofLength = 202704`
- `stateRoot  = finalStateRoot = 0x2cfa6af8d4c60fb00b2002506dcc5631b06689e74e43cca96730f88058a215b3`
- `--value 1ether` = the POST_BLOCK_STAKE

Confirm it mined (`status 1`) and the recomputed block-hash chain matches the
Rust-proved `final_block_chain`:

```bash
cast call $ROLLUP_ADDR "blockHashChainAt(uint64)(bytes32)" 1 --rpc-url sepolia
# expect: 0x3ed44a28fc0c21371feee564ee3ce682ea7a32b4b78819d32b0d50251c3e089f
```

### 4. finalize submission 0

```bash
ROLLUP_ADDR=$ROLLUP_ADDR forge script script/Finalize.s.sol \
  --rpc-url sepolia \
  --account smoke-deployer \
  --broadcast
```

The script reconstructs the real `ValidityPublicInputs` + `MleProof` and calls
`finalize(0, finalStateRoot, vpis, mleProof)` (a normal calldata call — no blob).
It `require`s the call to return `true`. Confirm the finalized root:

```bash
cast call $ROLLUP_ADDR "latestFinalizedStateRoot()(bytes32)" --rpc-url sepolia
# expect: 0x2cfa6af8d4c60fb00b2002506dcc5631b06689e74e43cca96730f88058a215b3
```

### 5. (Optional) verify contracts on Etherscan

With `ETHERSCAN_API_KEY` set in `.env`, re-run the deploy with `--verify`, or
verify after the fact:

```bash
forge verify-contract <MleVerifierAddr> src/../MleVerifier.sol:MleVerifier \
  --chain sepolia --etherscan-api-key "$ETHERSCAN_API_KEY"
forge verify-contract $ROLLUP_ADDR src/IntmaxRollup.sol:IntmaxRollup \
  --chain sepolia --etherscan-api-key "$ETHERSCAN_API_KEY" \
  --constructor-args <abi-encoded-args>
```

---

## Local anvil rehearsal (secret-free — the proof this all works)

This is the **main deliverable**: the full sequence run against a local anvil
using only anvil's built-in throwaway dev account. No real key, no external RPC.

```bash
# Terminal A — start anvil (Prague hardfork for blobs + EIP-2537). No
# --disable-code-size-limit: all contracts are under EIP-170 now, so this
# rehearsal runs under the same size enforcement as a real Sepolia node.
anvil --hardfork prague

# Terminal B — from contracts/. ANVIL0 is anvil account[0]'s well-known dev key
# (a public throwaway, safe to put on the CLI; NEVER do this with a real key).
ANVIL0=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
RPC=http://127.0.0.1:8545

# 1. deploy (auto-deploys + links the 2 external verifier libraries)
forge script script/Deploy.s.sol --rpc-url $RPC --private-key $ANVIL0 \
  --broadcast
# → capture the printed IntmaxRollup address, e.g.:
ROLLUP=0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512

# 2. postBlockAndSubmit (blob tx)
head -c 131072 /dev/zero > blob.bin
cast send $ROLLUP \
  "postBlockAndSubmit((uint32,uint64,bytes32,uint32[])[],bytes32,uint32,bytes32)" \
  "[(1,1,0x0000000000000000000000000000000000000000000000000000000000000000,[0,0])]" \
  0x0000000000000000000000000000000000000000000000004362d402885f19f1 \
  202704 \
  0x2cfa6af8d4c60fb00b2002506dcc5631b06689e74e43cca96730f88058a215b3 \
  --value 1ether --blob --path blob.bin \
  --private-key $ANVIL0 --rpc-url $RPC
# → status 1; then:
cast call $ROLLUP "blockHashChainAt(uint64)(bytes32)" 1 --rpc-url $RPC
# → 0x3ed44a28fc0c21371feee564ee3ce682ea7a32b4b78819d32b0d50251c3e089f  ✓

# 3. finalize
ROLLUP_ADDR=$ROLLUP forge script script/Finalize.s.sol --rpc-url $RPC \
  --private-key $ANVIL0 --broadcast
# → "finalize returned: true"; then:
cast call $ROLLUP "latestFinalizedStateRoot()(bytes32)" --rpc-url $RPC
# → 0x2cfa6af8d4c60fb00b2002506dcc5631b06689e74e43cca96730f88058a215b3  ✓
```

Observed rehearsal result (Foundry 1.5.1, anvil Prague):

| step | result |
|------|--------|
| deploy | MleVerifier `0x5FbD…0aa3`, IntmaxRollup `0xe7f1…0512`, degreeBits 13, genesis `0x5accf1e4…43c7` |
| postBlock | tx `status 1`, `blockHashChainAt(1)` = `0x3ed44a28…089f` ✓ |
| finalize | `finalize returned: true`, `latestFinalizedStateRoot()` = `0x2cfa6af8…215b3` ✓ |

Both assert-values match the Rust-proved fixtures, and the **real MLE/WHIR proof
verification ran on-chain** in the finalize step (`mleVk.degreeBits = 13`, i.e.
verification is ON). The EIP-2537 / blob precompiles were present on anvil — no
precompile gap was found.

Clean up: `rm blob.bin` and stop anvil when done.

---

## Real Sepolia deployment record (2026-06-14)

The full smoke was executed on live **Sepolia (chainId 11155111)**, deployer
`0x2C0BF10558adafDd21296CbF71dd6FE88c782C80`, public RPC
`https://ethereum-sepolia-rpc.publicnode.com`.

| Step | Result |
|------|--------|
| MleVerifier | `0x4154a4A27Ad06dc57Dab86e3a696e2454a62d871` — 14,030 B on-chain, accepted under **real EIP-170 enforcement** (the size fix works on a consensus node, not just `--disable-code-size-limit` anvil) |
| IntmaxRollup | `0xBa057F093765a0AA4c4001d8deC5171E836A0af0` — `latestFinalizedStateRoot` initialized to genesis `0x5accf1e4…43c7` |
| postBlock (type-3 blob tx `0xb106e2d2…afc7`) | status 1; `blockHashChainAt(1)` = `0x3ed44a28…089f` = Rust fixture ✓ |
| finalize (`0x766a6fa4…07a7`) | `finalize returned: true`; `latestFinalizedStateRoot` = `0x2cfa6af8…215b3`, `blockNumber` = 1; real MLE/WHIR verified on-chain (degreeBits=13). 1 ETH stake credited to `pendingWithdrawals` (recoverable). |

Gas notes for a tight balance: the blob tx needed an explicit
`--blob-gas-price 20gwei` (cast's auto cap fell just under the live blob base
fee). `finalize` was broadcast with `--with-gas-price 25gwei
--gas-estimate-multiplier 115` so `gasLimit × maxFeePerGas` stayed within the
deployer balance (forge's default estimate reserved 18M × ~47 gwei ≈ 0.85 ETH).
The whole smoke (deploy + 1 ETH postBlock stake + finalize) fit in ~1.95 ETH
with the stake recoverable; budget more headroom or run at low gas next time.
