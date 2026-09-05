# MLE/WHIR wire-v3 fixture regeneration + clean redeploy runbook

> **RELEASE STATUS (2026-09-03): NO-GO.** The commit-before-challenge MLE/WHIR wire-v3
> implementation and its compact proof boundary are integrated, but the independent
> cryptographic review required by `doc/audit/mle-whir-pcs-repair-handoff.md` is not recorded.
> `IntmaxRollup.releaseRuntime` is pinned to the deployment chain (`deploymentChainId`, set from
> the adapters pinned with `MLE_VERIFIER_CHAIN_ID`); this runbook's acceptance runs stay on `31337`.
> Do not open deposits, publish blocks, finalize, withdraw, or move settlement value on a public
> chain. Passing local tests, a Forge dry-run, or a deployment whose constructors accept a
> non-31337 chain does not constitute that approval. The separate NO-GO items in
> `doc/audit/audit30-08-2026-final-security-closure.md` also remain in force.
>
> **Clean cutover only.** Wire v3 is a new proof/VK/config identity. The historical `V2` suffixes
> on Rust APIs, Solidity class names, and test filenames are implementation-generation names; they
> do not mean that wire-v2 bytes are accepted. Do not reuse a V1/v2 verifier, proof,
> fixture, deployment manifest, publisher journal, pending submission, pending close, or bond.
> Resolve/refund/retire old pending state under the exact old deployment before cutover, or deploy
> a separately audited migration. Old bytes must never be decoded or evaluated as wire v3.

The authoritative wire-v3 order is:

```text
generate proof-free configs
  -> deploy/predict six distinct (MleVerifierV2 core, PinnedMleVerifierV2 adapter) pairs
  -> bind Rollup and settlement parents to those immutable adapters
  -> obtain the exact Manager address
  -> regenerate every full proof fixture, with close withdrawal recipient = that Manager
  -> run the complete Rust/Solidity/DA/gas/size matrix
  -> independent cryptographic review
  -> only then make a separate decision about removing releaseRuntime containment
```

This ordering is security-critical. Deployment consumes `*_mle_config.json`, which contains no
witness or proof. Full proof fixtures are generated only after the Manager recipient exists. This
removes the old proof-first circle (proof embeds Manager recipient -> deploy needs proof/VK ->
Manager address is not yet known). Each of the six statement circuits has a distinct immutable
adapter and core: validity, withdrawal, close, withdrawal claim, post-close claim, and cancel
close. There is no mutable `initialize*Vk` step.

Written 2026-07-06; extended 2026-07-27 for the multitoken (§N) regeneration.
This is the critical path that makes the mainnet-blocker fixes (#1
block-producer whitelist, #2b `to_hash_out` canonicity) and the §N multi-token
preimage/PI changes actually effective on-chain. Heavy (hours of real proof
generation) + currently uses a chain-31337 acceptance network — a maintainer-run step. Fixtures are NOT
byte-reproducible (MLE/WHIR ZK blinding); verify by MEANING (tests pass), not
by diff.

## Historical multitoken context (2026-07-27)

The facts below still explain why the descriptor families must be regenerated together, but any
V1/VK-initializer workflow formerly associated with them is historical. The V2 procedure starts at
Step 0 below.

- **Every close/claim fixture predating §N is invalid** (close PI 95→103 w/
  `token_funds_digest`; claim PI 48→50 w/ tokenSlot/tokenIndex; post-close PI
  56→57 w/ tokenIndex; IMCH/IMCI/IMW2/IMB2/IMS2 preimage widenings; IMI2/TFD new
  domains) and the `IntmaxRollup`/`ChannelSettlementManager` initcode changed →
  NEW CREATE2 manager address baked into the close fixtures.
- **Descriptors are per-token now.** `close_intent.json` (fixture bin AND the
  CLI `close`) carries `channel_fund_amounts[10]` / `token_registry[10]` /
  `token_count` (+ the legacy `channel_fund_amount` scalar); the claim
  descriptor carries `token_slot`/`token_index`; the post-close descriptor
  carries `token_index`. `RunClose.s.sol` / `CloseLifecycleE2E` parse them
  verbatim (the Phase-3 genesis-token embedding is retired).
- **Close fixture co-generation.** `generate_close_fixture` derives its
  signing keys from `ChannelMemberKeys::deterministic(1)` — the SAME derivation
  `generate_withdrawal_fixture` registers — and (signer-independent exit, 2026-09)
  builds the whole close family from ONE `close_` lifecycle (deposit 6 / withdraw 3):
  the close intent over that lifecycle's finalized root with the single-lane
  remaining vector `{ETH -> 3}` and the whole-vector `CloseAssetBacking` proof over
  the same final balance proof. `CloseLifecycleE2E`'s close-intent section
  therefore RUNS (member-set commitment matches) and HARD-FAILS on any
  stale/mixed fixture set: always regenerate the unprefixed set, the close family
  and the claim fixtures in ONE batch.
- **ERC-20 withdrawal lane.** `build_channel_withdrawal` (and the CLI
  `withdraw`) can add a second, ERC-20 lane: `WD_ERC20_TOKEN` /
  `WD_ERC20_AMOUNT` / `WD_ERC20_TOKEN_ADDR` env → a second deposit in the
  deposit block (on-chain: approve + `deposit()` ERC-20 branch, balanceOf-delta
  checked) and a SECOND single-leaf withdrawal chain paid via `withdrawERC20`
  (`RunClose.withdrawErc20Step`), then `pullChannelTokenFunds(t)`.
- **Two-token anvil E2E:** after regenerating the close-stack fixtures, run
  `cargo test --release --test two_token_cli_e2e -- --ignored --nocapture`.

## Why regen is needed — what each change invalidated

- **#2b (circuit change).** `tx_settlement.rs` and `single_withdrawal_circuit.rs`
  now use `to_hash_out` instead of bare `reduce_to_hash_out`. `tx_settlement` is
  in the balance core (`send_tx_circuit`, `receive_transfer_circuit`);
  `single_withdrawal` is in the withdrawal core (`withdrawal_step`,
  `withdrawal_chain_circuit`). Adding a constraint changes these circuits'
  digests, so **their VKs change**, cascading to essentially ALL proof fixtures
  and their VKs (validity, withdrawal, close, withdrawal-claim, post-close-claim,
  cancel-close, c2c, e2e, wasm). Old fixtures will FAIL to verify under
  regenerated VKs and vice-versa — they must be regenerated together.
- **#1 (contract change).** New `isBlockProducer` mapping + `setBlockProducer` +
  the `postBlockAndSubmit` gate change `IntmaxRollup` bytecode, hence its CREATE2
  address and the derived manager address baked into the CLOSE fixtures. This is
  the pre-existing `CloseLifecycleE2E` address-mismatch (also needs close-fixture
  regen). No VK changes from #1 (VKs are circuit-, not contract-, derived).

## Step 0 — preconditions
- **CO-SIGNER KEY MATERIAL (fail-closed; provision FIRST).** `channel_member` refuses to run
  unless exactly one of these is set:
  - `INTMAX_COSIGNER_KEYFILE=/path/to/cosigner.key` — **production**. A 0600, gitignored file with
    >= 32 bytes of hex. Create once per host with `umask 077; openssl rand -hex 32 >
    .claude/cosigner.key`, then **back it up**: keys are derived from it, so losing it makes every
    channel derived from it permanently unclosable. The CLI rejects a group/world-readable file,
    a short file, and an all-zero file. Never `cat`, echo, log, or commit it.
  - `INTMAX_INSECURE_DETERMINISTIC_KEYS=1` — **tests / local anvil only**. Prints a red banner on
    every invocation. Every key it produces is computable by anyone from this public repo.

  Setting **both** is a hard error (a provisioned host cannot be silently downgraded); setting
  neither is a hard error. Do not put the insecure flag in any systemd unit, Dockerfile `ENV`, or
  `.env` — `api/lib/cli.js:47` spreads `process.env` into every CLI child, so it would silently
  apply to every channel the API creates.

  **Every channel created before this fix has publicly derivable co-signer keys and must be
  drained and retired, not merely redeployed** — see `doc/tasks/cosigner-key-provenance.md` §2.
- **STALE CLI STATE (TM-16): do NOT reuse pre-TM-16 `cli_state.json` files.** The
  TM-16 change re-keyed the CLI replay ledgers (`applied_tx_identities` /
  `spent_tx_identities`, token-free replay identities) and the descriptor wire
  format gained token fields; old state files deserialize with EMPTY ledgers
  (serde default), silently losing replay protection for previously-credited
  transfers. Delete every stale per-channel state directory (`cli_state.json`
  and siblings) before driving any post-TM-16 flow — the v3 reset assumes fresh
  state everywhere.
- Build native release once: `cargo build --release --locked`.
- Contracts build: `cd contracts && forge build --offline`.
- Before generating any artifact, verify that the hand-maintained protocol source, generated Rust
  and Solidity constants, canonical WHIR profiles, and proof layout are one generation:

  ```bash
  ( cd contracts/lib/polygon-plonky2 && \
    cargo test -p plonky2_mle --test protocol_schema_codegen --locked --offline && \
    cargo test -p plonky2_mle --test protocol_schema_v2_codegen --locked --offline && \
    cargo test -p plonky2_mle --test whir_profile_v2_codegen --locked --offline )
  ```

  If an intentional schema change makes either drift test fail, regenerate only through that
  test's documented write guard, review the generated diff, and rerun both read-only tests before
  continuing. Never patch generated constants or profile tables by hand.
- For the current acceptance run, use chain 31337. A future independently approved public run must
  set `.env` (see `contracts/.env.example` and
  `api/env.example`): `FRAUD_TREASURY`, `BLOCK_PRODUCER`, `INTMAX_L1_ACCOUNT`,
  `ETH_PASSWORD` (an absolute root-only password-file path, not password text),
  `INTMAX_COSIGNER_KEYFILE`, `INTMAX_API_TOKEN`, `INTMAX_ALLOWED_ORIGINS`.
  On every non-31337 chain the Rust CLI and API reject `INTMAX_DEPOSIT_KEY` and require the named
  encrypted Foundry keystore; only `--account <name>` reaches child argv.

## Step 1 — atomically stage the complete proof-free wire-v3 config cohort

Run from the repository root with the pinned lockfile. This phase constructs circuits and verifier
data only; it must not construct a witness or proof. The writer refuses to replace a config with a
different circuit identity, which catches a mixed build rather than silently continuing.

Configs are create-once/compare-later artifacts: an existing config is accepted only when the
writer reproduces it byte-for-byte from the current circuit and WHIR profile, and a different
circuit identity is refused instead of overwritten. The retired target-133 switch
(`MLE_WHIR_133_CONFIG_CUTOVER`) no longer exists; a WHIR profile change is a fresh cohort (remove
the retired config artifacts first, in a dedicated clean staging worktree with deployments and
publishers stopped).

`MLE_ALLOW_WIRE_V3_CONFIG_CUTOVER=1` is the only cutover permission and applies solely to a
canonical retired wire-v2/PoW-20 -> wire-v3/PoW-22 migration. Per-file atomicity is not cohort
atomicity: do not deploy, copy, publish, or commit a partial config cohort. Even after the independent
16-config gate passes, keep the config-only state as an unpublished checkpoint in this staging
worktree. It must not be merged, pushed, tagged, released, or handed to an operator independently of
the full cutover cohort defined in Step 4. If any command or gate fails, restore the entire 16-config
set from the pre-cutover commit and restart this phase; do not retry from a mixed directory.

An absent config is also crash-safe: the writer first writes and fsyncs a unique same-directory
staging file, then publishes the complete inode with an atomic no-clobber hard link, fsyncs the
directory, removes the staging name, and fsyncs the directory again. A racing writer is accepted
only if the already-published target is a regular file with byte-identical canonical contents. A
crash before publication can leave only a hidden `.*.create-*.tmp` staging file, never a partial
target. Treat any such residue as evidence of an interrupted run: keep deployment stopped, inspect
it, remove it, and restart the complete 16-config phase from the pre-cutover commit.

```bash
set -euo pipefail
cargo run --release --locked \
  --bin generate_e2e_fixture -- --mle-config-only
cargo run --release --locked \
  --bin generate_withdrawal_fixture -- --mle-config-only
WD_OUT_PREFIX=sepolia_ cargo run --release --locked \
  --bin generate_withdrawal_fixture -- --mle-config-only
cargo run --release --locked \
  --bin generate_burn_withdrawal_fixture -- --mle-config-only
cargo run --release --locked \
  --bin generate_c2c_fixture -- --mle-config-only
# The close-family co-generator owns four configs: close_intent, close_asset_backing (the
# materializer's whole-vector statement) and the close_ lifecycle/withdrawal aliases.
# `WD_OUT_PREFIX=close_ generate_withdrawal_fixture` is refused.
cargo run --release --locked --features close-fixture-bin \
  --bin generate_close_fixture -- --mle-config-only
cargo run --release --locked \
  --features withdrawal-claim-fixture-bin \
  --bin generate_withdrawal_claim_fixture -- --mle-config-only
cargo run --release --locked \
  --features post-close-claim-fixture-bin \
  --bin generate_post_close_claim_fixture -- --mle-config-only
cargo run --release --locked \
  --features cancel-close-fixture-bin \
  --bin generate_cancel_close_fixture -- --mle-config-only

# This test intentionally does not parse any full proof. It is the deployment boundary while
# full proofs are still stale: exact 16-file manifest, strict current schema/version/magic/PoW,
# complete PI wire maps, alias identity, and seven distinct production statement identities.
cargo test --release --locked --test mle_v2_fixture_release \
  all_proof_free_configs_form_one_complete_current_generation_cohort -- --exact --nocapture
```

The seven production circuit configs used by a full close-capable deployment are:

```text
mle_fixture_config.json                    validity
withdrawal_mle_config.json                 withdrawal
close_intent_mle_config.json               close
withdrawal_claim_mle_config.json           withdrawal claim
post_close_claim_mle_config.json           post-close claim
cancel_close_mle_config.json               cancel close
close_asset_backing_mle_config.json        whole-vector CloseAssetBacking (materializer)
```

`close_lifecycle_validity_mle_config.json` and `close_withdrawal_mle_config.json` are the
close-workflow aliases consumed when attaching the settlement stack. They must describe the same
validity/withdrawal circuit identities as the base configs; they are not eighth or ninth shared
verifiers.

Every config must be canonical schema `plonky2-mle-v3-solidity-config`, schema/protocol version 3,
WHIR PoW 22, compact encoding `MLEWHIR3`, and must contain an exact three-byte-per-public-input
`verificationKey.publicInputWireMap` plus an exact
`abi.encode(MleVerifierV2.VerificationConfig)` whose hash equals the pinned verification-config
digest. Reject a missing field, unknown field, digest mismatch, non-canonical Goldilocks limb, or
config copied from another statement family.

## Step 2 — deploy/predict immutable V2 identities, then obtain the Manager address

Each config creates exactly one `MleVerifierV2` core and one `PinnedMleVerifierV2` adapter. The
Rollup constructor receives the distinct validity and withdrawal adapters. The settlement verifier
constructor receives four further distinct adapters in this order: close, withdrawal claim,
post-close claim, cancel close. The `CloseFundingMaterializer` constructor receives the
CloseAssetBacking adapter. Verify all 14 addresses are distinct and every adapter's `core()`,
`allowedChainId()`, configuration digest, circuit-config digest, WHIR-parameters digest,
64-byte protocol ID, and session ID against the config artifacts.

For a future approved production attach, `channel_member deploy-settlement <rpc>` runs from the
channel work directory with `EXISTING_ROLLUP` supplied by the driver. Do not broadcast that path on
a public chain while this runbook is NO-GO; inspect it locally/dry-run only. The existing-Rollup
branch reads only the
seven config files, the staged `close_asset_backing_{manifest,mle,mle_config,public_inputs}.json`
bundle and the authenticated `cli_reg_record.json`; it does not read
`close_lifecycle.json` or any witness-derived proof fixture. The accepted broadcast core is:

```text
(MleVerifierV2 core, PinnedMleVerifierV2 adapter)   CloseAssetBacking
CloseFundingMaterializer(rollup, backing adapter)
4 x (MleVerifierV2 core, PinnedMleVerifierV2 adapter)
ChannelSettlementVerifier
registerChannel
ChannelSettlementManager
registerSettlementManager
```

That is 15 core transactions after any canonical CREATE2 library prelude. A fresh Rollup has
already deployed the other two core/adapter pairs in its own constructor plan. There is no
post-deploy VK initializer, no shared mutable VK, and no proof tuple in any constructor.

Record the exact Manager address from the validated broadcast artifact/finalized read-back. For a
local lifecycle fixture test, use the address printer in the same test/deployment context; do not
reuse an address produced by a different script or test contract. Any bytecode, linked-library,
nonce, constructor, or transaction-order change invalidates the prediction evidence and requires
this step to be repeated.

`IntmaxRollup.releaseRuntime` is pinned to `deploymentChainId`: the chain both pinned adapters name
(`MLE_VERIFIER_CHAIN_ID` at deploy time, an explicit opt-in off 31337). A Rollup whose code or state
is moved to any other chain refuses deposits, posting, finalization, withdrawals and value movement.
The pin is a containment mechanism, not a release approval: opening value on a public chain remains
a separate reviewed decision after the independent cryptographic review is recorded.

## Step 3 — regenerate all full wire-v3 proof fixtures after the Manager is fixed

Run the heavy proof phase as one pinned batch. The close withdrawal proof must use the Manager from
Step 2 as its recipient.

```bash
# The packed-v1 fixtures below remain an intentionally separate legacy-conformance cohort. They
# are not wire-v3 deployment artifacts, but their cross-language/golden consumers are part of the
# same reviewed submodule revision. Regenerate them before their derived transcript trace.
( cd contracts/lib/polygon-plonky2 && MLE_WRITE_FIXTURES=1 \
  cargo test -p plonky2_mle --test generate_fixtures --locked --offline \
  generate_and_verify_all_fixtures -- --exact --nocapture )
( cd contracts/lib/polygon-plonky2 && MLE_WRITE_TRANSCRIPT_TRACE=1 \
  cargo test -p plonky2_mle --test transcript_e2e_trace --locked --offline \
  test_v1_transcript_golden_trace -- --exact --nocapture )
( cd contracts/lib/polygon-plonky2 && MLE_WRITE_HISTORICAL_PCS_FIXTURE=1 \
  cargo test -p plonky2_mle --lib --locked --offline \
  commitment::whir_pcs::tests::test_historical_frozen_triples_reach_packed_v1_pcs_rejection \
  -- --exact --nocapture )

# Submodule canonical cross-language proof and maximum admitted resource proof. A schema-only
# mutation is forbidden: both must be freshly proved under the wire-v3 transcript and WHIR profile.
( cd contracts/lib/polygon-plonky2 && MLE_WRITE_V2_FIXTURE=1 \
  cargo test -p plonky2_mle --test v2_cross_language_fixture --locked --offline \
  regenerate_v2_cross_language_fixture -- --ignored --exact --nocapture )
( cd contracts/lib/polygon-plonky2 && MLE_WRITE_V2_RESOURCE_FIXTURE=1 \
  cargo test --release -p plonky2_mle --test v2_resource_envelope \
  generate_real_max_row_profile_fixture --locked --offline -- --ignored --exact --nocapture )

cargo run --release --locked --bin generate_e2e_fixture
cargo run --release --locked --bin generate_withdrawal_fixture
# Seed the close_ lifecycle names from the fresh plain set so the printer's cross-check sees one
# fixture generation (the co-generator below overwrites them).
cp contracts/test/data/lifecycle.json contracts/test/data/close_lifecycle.json
cp contracts/test/data/lifecycle_validity_mle.json contracts/test/data/close_lifecycle_validity_mle.json
```

The Manager address comes from `forge test --match-test test_printCloseManagerAddress -vv`
(`CLOSE_MANAGER_ADDRESS`; the same printer also prints `CLOSE_ROLLUP_ADDRESS`). The printer reads
the committed `close_` set's genesis and registration, which the close family's own proving does
not touch, so run it before the co-generator; if it rejects a mixed fixture generation because the
plain set changed shape, the `cp` above (plain → `close_` names) is what fixes it.

The close family is co-generated by ONE binary (signer-independent exit, 2026-09):
`generate_close_fixture` builds the `close_` lifecycle itself (channel 1, deposit 6 / withdraw 3,
withdrawal recipient = `WD_RECIPIENT`, the four `close_lifecycle*.json` / `close_withdrawal_*.json`
files that `WD_OUT_PREFIX=close_ generate_withdrawal_fixture` used to write), then closes THAT
lifecycle's final balance proof (`intmax_state_root` = its finalized `final_state_root`, the
single-lane vector `{ETH -> 3}`) into `close_intent_mle.json` + `close_intent.json`, and proves the
whole-vector `CloseAssetBacking` proof over the same balance proof into
`close_asset_backing_{mle,public_inputs,manifest}.json`. `submitCloseIntent` requires the finalized
root AND an attested backing proof with the same `(settled_tx_chain, token_funds_digest)`, so the
three are only valid together, and every cross-binding is asserted inside the generator. The
generator refuses to run without `WD_RECIPIENT`. There is no separate aux-bound `close_` withdrawal
pass any more: `pullChannelFunds` no longer checks a close-funding aux value (cooperative close
funding is retired, `CooperativeCloseFundingDeprecated`); the payout is released by
`materializeSignedHead` against the attested backing proof instead.

```bash
WD_OUT_PREFIX=sepolia_ cargo run --release --locked --bin generate_withdrawal_fixture
cargo run --release --locked --bin generate_burn_withdrawal_fixture
# The close family (close_ lifecycle + close intent + whole-vector backing proof) in one run.
WD_RECIPIENT=0x<exact-manager-address> \
  cargo run --release --locked --features close-fixture-bin --bin generate_close_fixture
# Require: the printer still reports the same Manager and Rollup addresses, and
# `forge test --match-contract CloseLifecycleE2ETest` passes against the family.
cargo run --release --locked --features withdrawal-claim-fixture-bin \
  --bin generate_withdrawal_claim_fixture
cargo run --release --locked --features post-close-claim-fixture-bin \
  --bin generate_post_close_claim_fixture
cargo run --release --locked --features cancel-close-fixture-bin \
  --bin generate_cancel_close_fixture
cargo run --release --locked --bin generate_c2c_fixture
cargo run --release --locked --bin generate_wasm_fixtures

# Rebuild both distributable WASM packages from the same final protocol source. Never reuse a
# pre-cutover pkg/ or pkg-node/ directory in release staging. The Node build is intentionally
# sequential; the browser build is the separate threaded target.
test ! -e pkg
test ! -e pkg-node
bash hosting/build-wallet-node-wasm.sh
bash hosting/build-wallet-wasm.sh

# Canonical producer for pw_close_intent_mle.json. This is not a fixture binary: the release E2E
# first deploys from the proof-free configs, mirrors the live registration/deposit in the Rust
# block generator, posts its four blocks to anvil as EIP-4844 blob transactions, attests the
# proof DA and finalizes them with a real 4-block validity MLE proof, attests the whole-vector
# CloseAssetBacking proof of the post-burn head, then builds a real CloseProver proof, wraps it,
# proves and self-verifies MLE/WHIR wire v3, writes pw_reg.json / pw_submit.json /
# pw_close_intent_mle.json, and consumes that exact proof on the fresh anvil chain (its other
# artifacts go to the gitignored proof-da-output/pw-e2e/). Requires anvil, forge and cast on PATH.
cargo test --release --locked --test partial_withdrawal_e2e \
  partial_withdrawal_e2e_anvil -- --nocapture
```

`generate_wasm_fixtures` writes the ignored local circuit-serialization inputs under
`tests/fixtures/*.bin`. They are neither MLE full proofs nor proof-free verifier configs, so they
must be regenerated/tested for WASM compatibility but must not be relabelled or admitted to either
wire-v3 JSON manifest.

Every full MLE fixture must be canonical schema `plonky2-mle-v3-solidity`, protocol version 3, and
must match its config-only artifact. The only on-chain/proof-DA representation is the exact
`.compactProof.bytes` stream: nonempty, `MLEWHIR3` magic, exact recorded length/hash, strict shape,
canonical re-encoding, and within the generated compact cap. `solidityAbiProof` is a redundant
cross-view checked by tooling; it is never calldata and never a substitute DA payload.

The tracked generator-owned JSON cutover is exactly 53 files. The non-skipping release test scans
the directory and rejects missing, extra, duplicate-owned, cross-class, unknown-field, or mixed
artifacts:

```text
16 configs:
  mle_fixture_config.json
  lifecycle_validity_mle_config.json  withdrawal_mle_config.json
  close_lifecycle_validity_mle_config.json  close_withdrawal_mle_config.json
  close_asset_backing_mle_config.json
  sepolia_lifecycle_validity_mle_config.json  sepolia_withdrawal_mle_config.json
  burn_lifecycle_validity_mle_config.json  burn_withdrawal_mle_config.json
  c2c_lifecycle_validity_mle_config.json  c2c_withdrawal_mle_config.json
  close_intent_mle_config.json  withdrawal_claim_mle_config.json
  post_close_claim_mle_config.json  cancel_close_mle_config.json

17 full proofs:
  mle_fixture.json
  lifecycle_validity_mle.json  withdrawal_mle.json
  close_lifecycle_validity_mle.json  close_withdrawal_mle.json
  close_asset_backing_mle.json
  sepolia_lifecycle_validity_mle.json  sepolia_withdrawal_mle.json
  burn_lifecycle_validity_mle.json  burn_withdrawal_mle.json
  c2c_lifecycle_validity_mle.json  c2c_withdrawal_mle.json
  close_intent_mle.json  withdrawal_claim_mle.json
  post_close_claim_mle.json  cancel_close_mle.json  pw_close_intent_mle.json

20 companions:
  block_fixture.json  vpi_fixture.json
  lifecycle.json  withdrawal_payout.json
  close_lifecycle.json  close_withdrawal_payout.json
  close_asset_backing_public_inputs.json  close_asset_backing_manifest.json
  sepolia_lifecycle.json  sepolia_withdrawal_payout.json
  burn_lifecycle.json  burn_withdrawal_payout.json
  c2c_lifecycle.json  c2c_withdrawal_payout.json
  close_intent.json  withdrawal_claim.json  post_close_claim.json  cancel_close.json
  pw_reg.json  pw_submit.json
```

The four explicitly non-generator-owned root JSON files
`cli_reg_record_guard.json`, `e2e_fixture.json`, `e2e_groth16.json`, and `pw_reg_guard.json` are
separate exceptions, not part of the 53-file cohort. The three WASM circuit binaries
`spend_circuit.bin`, `balance_processor.bin`, and `single_withdrawal_circuit.bin` are likewise a
separate binary cohort and must never satisfy or bypass the JSON gate.

The pinned submodule revision has a second, exact conformance/data manifest which the parent
release gate scans independently of those 53 live files:

```text
7 packed-v1 Solidity conformance proofs:
  small_mul.json  medium_mul.json  large_mul.json  huge_mul.json
  poseidon_hash.json  recursive_verify.json  coset_recursive_verify.json

2 packed-v1 derived records:
  transcript_v1_trace.json  historical_pcs_triples.json

2 current wire-v3 Solidity proofs:
  v2_cross_language.json  v2_max_resource.json

2 mle/testdata records:
  gate_ext3_vectors.json  historical_wire_v2_compact.json
```

The `V2` filenames in the current pair are implementation-generation names. The seven packed-v1
proofs and their derived records are deliberately quarantined conformance/history inputs and are
never deployment fixtures. The retired `xlarge_mul.json` must remain absent; its reappearance, or
any other missing/extra file in either submodule fixture directory, fails the release gate. Change
this submodule manifest, its generated protocol outputs, and the top-level 53-file cohort only in
the same reviewed atomic release unit.

## Step 4 — acceptance before any release decision

```bash
# Submodule Rust + Solidity
( cd contracts/lib/polygon-plonky2 && cargo test -p plonky2_mle --all-targets --locked )
( cd contracts/lib/polygon-plonky2/mle/contracts && forge test --offline )

# Parent differential, full Rust, full Solidity, production sizes
cargo test --release --locked --test mle_onchain_e2e -- --nocapture
cargo test --release --locked --test mle_v2_fixture_release -- --nocapture
cargo check --all-targets --locked
( cd node && npm ci --ignore-scripts && npm test )
( cd contracts && forge test --offline --match-contract V2FixtureCompletenessTest )
# `forge test` exits zero for `vm.skip(true)`. The repository guard preserves offline mode while
# rejecting every skipped/failed test and pinning the security-critical suite/count floors.
FORGE_TEST_ARGS="--offline" .github/ci/forge-test-guard.sh
( cd contracts && forge build --sizes --offline )
git diff --check
git submodule status
```

Only after every gate above passes may the migration become a reviewed release candidate. The
atomic tracked unit is one top-level commit that pins the exact reviewed submodule commit and also
contains all 15 proof-free configs, all 16 parent full proofs, both current submodule full fixtures,
the frozen genuine-wire-v2 negative fixture, all seven packed-v1 Solidity fixtures, the packed-v1
transcript trace and historical PCS triples, the validated gate-extension-vector snapshot, every
generator-overwritten DA/lifecycle/payout/claim descriptor, and every updated resource/hash
snapshot. The packed-v1 files are conformance/history inputs, not deployment-wire aliases; their
presence does not authorize a v1/v2 proof on a wire-v3 verifier. A standalone submodule commit must
exist first so the parent can pin it and may have to be pushed so CI can fetch it, but it is never a
release unit: do not tag, deploy, publish, or hand it to an operator before the complete top-level
commit pins it. Do not merge, push, tag, deploy, publish, or copy any parent config-only or
proof-only intermediate. Build `pkg/` and `pkg-node/` from that exact final source, record hashes of
the emitted JS/WASM files in the deployment evidence, and deploy only those recorded outputs;
these ignored directories are not substitutes for the tracked atomic cohort.

Also run every statement-family Rust/Solidity E2E, compact proof-DA round trip, gas/resource bound,
frozen-forgery/generalized-kernel mutation, root/order/shape/limb/point mutation, old/new-version
rejection, C2C, WASM, close, cancel-close, withdrawal, withdrawal-claim and post-close-claim test.
Record actual gas and production runtime sizes from this exact build; do not copy historical numbers
from this document. An aggregate `forge build --sizes` failure caused only by a test harness does not
replace explicit production-contract size reporting.

The PCS Critical remains NO-GO until an independent cryptographic reviewer approves the complete
transcript ordering, commitment format, malicious-prover model, written >=128-bit PCS budget, and
Rust/Solidity parity. Parent recursion also uses the default Goldilocks Poseidon configuration whose
concrete estimate recorded by this repository is approximately 95-bit security, so do not represent
the whole system as 128-bit merely because the local PCS work-factor target is 128. Keep all release
containment and every separate final-audit blocker.

## Historical deployment defects (do not reproduce)

Older deployments used mutable `initialize*Vk` calls and could omit withdrawal, cancel-close, or
post-close-claim VKs. That design is retired. V2 constructors atomically bind distinct adapters and
fail when an adapter/core is missing, duplicated, on the wrong chain, or inconsistent with its
configuration. Never attempt to repair an old deployment by feeding it a V2 config or compact proof.

The challenge-period and settlement-manager-registration fixes remain required: the Manager rejects
an off-devnet challenge period below 86,400 seconds, and the exact Manager must be registered with
the bound Rollup. Build/deploy with `--locked`; authorize the intended block producer explicitly.

<details>
<summary>Historical pre-V2 deployment defects (reference only; do not execute)</summary>

The section below records why the mutable-VK deployment was unsafe. It describes retired V1
contracts and is not an alternative to Steps 1-4 above.

## Historical: deploy + mutable VK initialization
Deploy scripts already wire the new guards: they authorize `BLOCK_PRODUCER`
(#1), require `FRAUD_TREASURY` on non-anvil chains (#6), and set the KZG
satellite. The per-statement VKs are initialized IN the deploy scripts from the
regenerated fixtures. **Which script initializes what — verified, do not
assume:**

| script | VKs initialized | real-network? |
|---|---|---|
| `DeployCloseCli.s.sol` (CLI/prod path — rollup **+** settlement stack) | withdrawal, close, withdrawalClaim, **postCloseClaim**, **cancelClose** — all five, **plus `registerSettlementManager(manager)`** (2026-08-13) | YES (needs `FRAUD_TREASURY` and a staged `cli_reg_record.json`) |
| `Deploy.s.sol` (rollup ONLY — no settlement stack) | validity (constructor) + **withdrawal** | YES (needs `FRAUD_TREASURY`) |
| `DeployTestnetBlockProducer.s.sol` (rollup ONLY, posting restricted to an admin) | validity (constructor) + **withdrawal** | YES (needs `FRAUD_TREASURY`) |
| `DeployC2C.s.sol` (rollup ONLY; header: "NOTHING else") | validity (constructor) + **withdrawal** | YES (needs `FRAUD_TREASURY`), but C2C-fixture-specific |
| `DeployClose.s.sol` | withdrawal only | **NO — and since 2026-08-13 that is ENFORCED**, not documented: `run()` opens with `require(block.chainid == SETTLEMENT_LOCAL_DEVNET_CHAIN_ID, ...)`. It deploys a settlement stack and keys NONE of its four VKs, so a channel it creates can be frozen by `requestClose()` and then never closed (`CloseVkNotSet()`) or un-frozen (`CancelCloseVkNotSet()`), and its `sepolia_*` fixtures are one circuit generation stale, so keying the VKs could not have made it work either. Devnet demo / manager-address dry run only. |
| `DeployWalletSettlement.s.sol`, `DeployPartialWithdrawalE2E.s.sol` | close, cancelClose, **withdrawalClaim, postCloseClaim** (the last two added 2026-08-13 — without them the wallet demo's own `claim` step reverted `WithdrawalClaimVkNotSet()`), + `registerSettlementManager` | anvil-gated (`chainid == 31337`, hard `require`) |

**What the chain-id checks actually gate — verified by reading each script, because two different
checks read alike:**
- `DeployWalletSettlement.s.sol:40` and `DeployPartialWithdrawalE2E.s.sol:44` are TRUE gates: a bare
  `require(block.chainid == 31337, …)` at the top of `run()`. They install an always-true mock MLE
  verifier, so they must never reach a public chain, and they cannot.
- The `require(block.chainid == 31337, "FRAUD_TREASURY must be set for non-local deploys")` in
  `Deploy.s.sol`, `DeployTestnetBlockProducer.s.sol`, `DeployClose.s.sol` and `DeployCloseCli.s.sol`
  is **not** an anvil gate — it sits inside `if (fraudTreasury == address(0))`. Set `FRAUD_TREASURY`
  and these scripts run on any chain. `DeployCloseCli.s.sol` is therefore a real-network-capable
  full settlement deployer; it is simply not reachable from the CLI/API surface (see the gap below).

**Withdrawal VK — FIXED 2026-08-13, was the same defect class as the A-M4 history below.**
`Deploy.s.sol` and `DeployTestnetBlockProducer.s.sol` never called `initializeWithdrawalVk`, so
every rollup they produced accepted deposits (`deposit()` is ungated) and reverted
`WithdrawalVkNotSet()` on both `withdrawNative` and `withdrawERC20` forever
(`IntmaxRollup.sol:1619`, shared by both payout entry points). The `Deploy.s.sol` row above used to
read "rollup-only smoke / YES", and `doc/docs/deploy-runbook.md` uses that script for the live
Sepolia deploy — "smoke" was doing load-bearing work no operator would decode. Both scripts now
install the VK from `withdrawal_mle.json` (read BEFORE `startBroadcast`, so a missing fixture aborts
before anything is on chain) and `require(rollup.withdrawalVkInitialized())` afterwards. Covered by
`contracts/test/DeployGuards.t.sol`, which executes the scripts on chain id 11155111.

**Challenge period — FIXED 2026-08-13.** Every script that constructed a
`ChannelSettlementManager` hardcoded `CHALLENGE_PERIOD = 1` second while
`ChannelSettlementManager.CHALLENGE_PERIOD_SECS = 86_400` (documented, spec-referenced) was read by
nothing, and every test used 1 day — so the value that actually shipped was exercised by no test.
`finalizeCloseGuarded(bytes32,uint64)` is permissionless at the deadline and both remedies (`cancelClose`, a newer
`submitCloseIntent`) require minutes of MLE proving, so the deployed window made a stale close
unchallengeable: fund MIS-ALLOCATION among members, not a liveness inconvenience. Now:
- `script/DeployConfig.sol` resolves the value — the protocol constant off-devnet, 1 second on
  chain id 31337 (the anvil E2Es drive a real node and cannot wait a day);
- the manager's **constructor** independently rejects anything below the floor off-devnet
  (`ChallengePeriodTooShort`), so no deploy tooling — script, factory or hand-rolled — can ship a
  short window to a public chain.

⚠️ **Consequence for this runbook: changing `ChannelSettlementManager`'s bytecode moves its CREATE2
address, so the close fixture set must be regenerated** (`close_withdrawal_payout.json` /
`close_withdrawal_mle.json` bake the manager address as the withdrawal recipient, inside the proof).
Until that is done, `CloseLifecycleE2E.t.sol::test_closeLifecycle_endToEnd` fails with
`manager CREATE2 address != close payout fixture recipient (stale fixtures -- regenerate)` — the
intended signal, per Step 2 above. Get the new address from
`forge test --match-test test_printCloseManagerAddress -vv`, then rerun Step 3's
`WD_RECIPIENT=<addr> cargo run --release --features close-fixture-bin --bin generate_close_fixture`
(the close-family co-generator: `close_` lifecycle + close intent + backing proof in one run).

**Settlement-manager registration — FIXED 2026-08-13.** `DeployCloseCli.s.sol` did not call
`rollup.registerSettlementManager(manager)`; its only callers were the two anvil-gated scripts. That
gates `finalizePartialWithdrawal` (`IntmaxRollup.sol` `NotRegisteredSettlementManager`); full-close
withdrawal leaves carry `auxData == 0` and skip it, so full close was unaffected.

**This was NOT moot, and the prior text claiming it was is retracted.** That text said "the CLI's
`cmd_partial_withdraw` is unimplemented and `pw-finalize` deliberately `exit(1)`s before payout" —
`cmd_partial_withdraw` is a command name that does not exist, so the grep behind that claim could
only ever come back empty. The real commands are `pw-submit` (`src/bin/channel_member.rs:5706`) and
`pw-finalize` (`:5893`), both implemented, both driven by `api/routes/partial-withdrawal.js:67,80`,
and `tests/partial_withdrawal_e2e.rs` exercises them. On a real deployment the revert landed at
FINALIZE — after the member had submitted the intent and waited out the entire challenge period.
The call is now step 6 of the script, followed by a read-back `require`, and covered by
`contracts/test/DeployGuards.t.sol` (which executes the script at chain id 11155111 and asserts the
deployed manager can actually call `authorizePartialWithdrawal`, while a stranger still cannot).
*Lesson: a "this path is dead so the gap is moot" argument must name the live entry points it
searched for and show they are absent — a negative grep for the wrong identifier is not evidence.*

**HISTORY — this text was an OVERCLAIM until 2026-08-12.** `DeployCloseCli.s.sol`
called only `initializeCloseVk` and `initializeWithdrawalClaimVk`;
`initializePostCloseClaimVk` was called by NO script anywhere in the repo, and
`initializeCancelCloseVk` only by the two anvil-gated scripts. So every REAL
deployment shipped with both unset, and:
- `ChannelSettlementVerifier.sol:1111` reverted `PostCloseClaimVkNotSet()` →
  the `post-close-claim` CLI command (`channel_member.rs:2152-2184`) could
  never succeed;
- `ChannelSettlementVerifier.sol:1050` reverted `CancelCloseVkNotSet()` →
  `cancel-close` (`channel_member.rs:1988-2025`), the ONLY on-chain remedy
  against a stale close, was unavailable.

Reported as audit622 **A-M4** ("MEDIUM, liveness bricking") on 2026-06-22 and
open until the two calls were added (steps 3b/3c in the script). SECURITY: the
fix supplies the VKs the reverts were correctly demanding; no fail-closed check
was weakened.

This is the SAME CLASS as the gate-8 defect — a fail-closed check that is
soundness-safe (it never accepts a bad proof) while making an HONEST user's
path impossible. A threat model that only asks "can an adversary get a false
statement accepted?" cannot see either one. When editing this runbook, state
what the scripts DO, verified by reading them — not what they ought to do.
Build/deploy with `--locked` (dependency pin, #14). After deploy, authorize the
block producer if the posting key differs from the deployer:
`BLOCK_PRODUCER=0x<poster-addr>` (deploy reads it) — the whitelist is otherwise
empty (fail-closed).

</details>

## Post-review network operations (currently blocked by NO-GO)

### Register ERC-20 tokens (after a future approved Rollup deploy, before any ERC-20 deposit)

The base `tokenIndex → ERC-20` registry is **set-once per index** (§N-7 / TM-10b) and
`deposit()` reverts for an unregistered nonzero index, so this step must run **after** the rollup
exists and **before** any ERC-20 deposit (incl. the `WD_ERC20_*` withdrawal lane above and the
two-token E2E). It is a standalone script — it does **not** run from `Deploy*.s.sol`.

```bash
# 1) write the per-deployment manifest (template: node/tokens.example.json). `rollup` MUST be the
#    address just deployed and `chainId` the target chain — the script and the node both refuse to
#    proceed when either disagrees.
$EDITOR deploy-staging/ch7/tokens.json

# 2) register (idempotent: a re-run with the same manifest is a no-op; a manifest that disagrees
#    with an already-set index REVERTS — set-once is never an "update")
cd contracts && TOKENS_MANIFEST=../deploy-staging/ch7/tokens.json \
  forge script script/RegisterTokens.s.sol --rpc-url "$RPC_URL" \
  --account "$INTMAX_L1_ACCOUNT" --broadcast --slow

# 3) confirm (the script also reads back `tokenAddressOf` itself and reverts on a mismatch)
cast call <rollup> "tokenAddressOf(uint32)(address)" 5 --rpc-url "$RPC_URL"
```

**Ship `tokens.json` alongside `channel_backing.json`** — same propagation as the rest of the
backing artifacts, into each channel's work dir on the relay/api box:

```bash
# deploy-staging/ch{7,8}/{channel_backing.json,channel_attestation.bin,balance_vd.bin,tokens.json}
#   → <box>:~/relay/wallet-live-work/ch{7,8}/
```

The relay / api / node programs then load it and **verify every entry against the on-chain
`tokenAddressOf`** before serving any symbol. Display metadata (symbol/name/decimals) carries ZERO
authority — a mislabelled token is a user-funds attack — so an unverified or unregistered entry is
served with `null` metadata and the wallet falls back to the raw base index. A manifest that
CONTRADICTS the chain (address/chainId/rollup mismatch) is a hard startup failure by design; fix
the file rather than working around it. See `node/DESIGN.md` §2.5 for the full policy table.

### Testnet $ITX faucet (optional; currently anvil-only)

Gives new browser users an in-channel balance of a test ERC-20 (`$ITX`) so they can try a transfer
without funding anything. Runs **after token registration** (the faucet token is just another registered base
token) and **after** the channel exists (`init`). Skip the whole step on any deployment that should
not dispense value — the relay endpoint is off unless explicitly enabled.

**Model.** A designated CLI **faucet member** holds an in-channel `$ITX` balance and the relay
sends new users an ordinary in-channel transfer at the ITX token position. No new protocol path.
The supply is ONE real L1 deposit imported once, so the faucet **cannot mint**: it can only run
dry, and every dripped balance stays backed by `channel_fund.amounts[t]` and stays claimable.

**Scale.** In-channel balances are **u64 base units**, so a position tops out at
`u64::MAX / 10**decimals` whole tokens. `$ITX` uses **6 decimals** precisely for this: the ceiling
is ~18.4 trillion ITX (it would be ~18.44 at 18 decimals). The contract constant, the manifest
`decimals`, the faucet env and the E2E constants must move TOGETHER — the relay/node read
`decimals()` back from the token at startup and **refuse to run on a mismatch**.

```bash
export RPC_URL=http://127.0.0.1:8545       # or "$SEPOLIA_RPC_URL"
export CHANNEL=7
export ROLLUP=0x…                          # this channel's IntmaxRollup (channel_backing.json .rollup)
export ITX_TOKEN_INDEX=1                   # base index reserved for $ITX — MUST be nonzero
export ITX_SUPPLY=1000000000000000         # L1 supply: 1,000,000,000 ITX @ 6dp (uint256, unconstrained)
export FAUCET_SUPPLY=1000000000000         # imported into the channel: 1,000,000 ITX  (< 2^64!)
export FAUCET_SLOT=2                       # a CLI CO-SIGNING member slot (0..INTMAX_CLI_COSIGNERS-1);
                                           # avoid slot 0, which is the BP/builder slot
WORK=wallet-live-work/ch$CHANNEL           # on the EC2 box: ~/relay/wallet-live-work/ch$CHANNEL
CLI=$PWD/target/release/channel_member

# 1) deploy $ITX. TESTNET-ONLY contract — it lives under contracts/test/ on purpose and must never
#    be referenced from contracts/src/ or a mainnet script. Fixed supply, no mint entry point.
( cd contracts && forge create test/tokens/IntmaxTestTokenITX.sol:IntmaxTestTokenITX \
    --rpc-url "$RPC_URL" --account "$INTMAX_L1_ACCOUNT" --broadcast \
    --constructor-args "$ITX_SUPPLY" )     # prints `Deployed to: 0x…`
export ITX=0x…

# 2) register it on the rollup's SET-ONCE registry, through the manifest (Step 3b machinery).
#    Add to deploy-staging/ch$CHANNEL/tokens.json (template: node/tokens.example.json):
#      { "tokenIndex": 1, "symbol": "ITX", "name": "Intmax Test Token", "decimals": 6,
#        "address": "<ITX>" }
( cd contracts && TOKENS_MANIFEST=../deploy-staging/ch$CHANNEL/tokens.json \
    forge script script/RegisterTokens.s.sol --rpc-url "$RPC_URL" \
    --account "$INTMAX_L1_ACCOUNT" --broadcast --slow )
cast call "$ROLLUP" "tokenAddressOf(uint32)(address)" "$ITX_TOKEN_INDEX" --rpc-url "$RPC_URL"

# 3) give ITX a LOCAL slot in the channel: an append-only, N-of-N-cosigned TokenRegister.
#    Prints "registered at local slot <t>". The relay resolves <t> itself from the SIGNED
#    snapshot at request time — it is not configured anywhere.
( cd $WORK && INTMAX_CHANNEL=$CHANNEL "$CLI" register-token "$ITX_TOKEN_INDEX" token_register.json )

# 4) escrow the faucet supply on L1. msg.value MUST be 0 for a nonzero tokenIndex; the rollup
#    credits a MEASURED balanceOf delta (fee-on-transfer tokens fail closed here).
DEPOSIT_RECIPIENT=$(jq -r .deposit_recipient $WORK/channel_backing.json)
cast send "$ITX" "approve(address,uint256)" "$ROLLUP" "$FAUCET_SUPPLY" \
  --rpc-url "$RPC_URL" --account "$INTMAX_L1_ACCOUNT"
# Capture the REAL deposit tx hash — the import is verified against this transaction's on-chain
# `Deposited` log (doc/tasks/deposit-import-threat-model.md).
DEPOSIT_TX=$(cast send "$ROLLUP" "deposit(bytes32,uint32,uint256,bytes32)" \
  "$DEPOSIT_RECIPIENT" "$ITX_TOKEN_INDEX" "$FAUCET_SUPPLY" \
  0x0000000000000000000000000000000000000000000000000000000000000000 \
  --value 0 --rpc-url "$RPC_URL" --account "$INTMAX_L1_ACCOUNT" --json | jq -r .transactionHash)

# 5) import the deposit to the FAUCET member (cosigned). The amount, depositor and base
#    token_index are READ FROM THE CHAIN — they are no longer arguments, so they cannot be
#    misstated. The token index still resolves against the channel's signed registry (an
#    unregistered index is refused fail-closed, TM-7).
#
#    --allow-unbound-depositor is needed ONLY here: the faucet slot's B-1b bound exit address is
#    the synthetic per-(channel, slot) address, not the operator's deployer account. It does NOT
#    weaken the check that blocks redirecting another MEMBER's deposit — that refusal is
#    unconditional. Never pass this flag on a user deposit, and never wire it into a relay.
#
#    On a public chain the import also waits for 12 confirmations by default; append a smaller
#    depth as the 5th positional argument if you knowingly want less (0 is not permitted).
( cd $WORK && INTMAX_CHANNEL=$CHANNEL "$CLI" cosign-l1-deposit-import \
    "$FAUCET_SLOT" "$DEPOSIT_TX" "$RPC_URL" itx_import.json --allow-unbound-depositor )

# 6) sanity: make the faucet position spendable once, up front. A homomorphically credited
#    position (which is what an import produces) has pending_adds > 0 and no local encryption
#    witness — `refresh` re-encrypts it value-preservingly (RefreshAir, re-verified by every
#    co-signer). The relay ALSO runs this before every drip, so this is only a smoke check.
( cd $WORK && INTMAX_CHANNEL=$CHANNEL "$CLI" refresh "$FAUCET_SLOT" <t> )

# 7) enable the relay endpoint (systemd Environment= on EC2). ALL of these are required —
#    the faucet stays off, and POST /api/faucet 404s, unless the whole set is coherent.
FAUCET_ENABLED=1 \
FAUCET_SLOT=$FAUCET_SLOT \
ITX_TOKEN_INDEX=$ITX_TOKEN_INDEX \
FAUCET_DRIP=100000000 \
FAUCET_CHANNEL_CAP=100000000000 \
FAUCET_COOLDOWN_MS=5000 \
#    Amounts are BASE UNITS (6 decimals): 100000000 = 100 ITX, 100000000000 = 100,000 ITX.
#    Hard ceilings in faucet-policy.js refuse anything above 1,000 ITX per claim / 10,000,000 ITX
#    per channel, so a mistyped digit disables the faucet (404 + a logged reason) instead of
#    handing out orders of magnitude too much. Raising a ceiling needs a code change.
  node hosting/wallet/wallet-relay.js       # (EC2: wallet-relay-ec2.js under systemd)
```

Verify: `curl -s https://<host>/api/faucet` → `{"enabled":true,"tokenIndex":1,"amount":"100000000",…}`
(and `{"enabled":false}` when it is off). A browser join then logs `faucet: received 100 ITX` and
the per-token balance row appears once the manifest entry is chain-verified (address AND
`decimals()` both read back equal — a `decimals` disagreement is a hard startup failure, and a
token with no readable `decimals()` is shown in raw base units rather than a guessed scale).

**Security notes for the operator** (see `hosting/wallet/wallet-relay*.js` and
`node/common/faucet-policy.js` for the enforced rules):
- The endpoint is **public and unauthenticated**. It is off by default; `FAUCET_ENABLED=1` without
  a valid `FAUCET_SLOT`/`ITX_TOKEN_INDEX` logs a warning and stays off. `ITX_TOKEN_INDEX=0` is
  rejected outright — index 0 is native ETH, i.e. the channel's own deposit backing.
- One drip per balance slot, **for ever**, plus a per-channel cap and a cooldown. The record is
  written BEFORE the transfer, so a crash costs a drip instead of paying twice; a failed drip is
  NOT retried automatically. Ledger: `wallet-live-work/ch<N>/faucet_state.json` — a corrupt file
  makes the endpoint fail closed (500), and deleting it **re-opens the faucet to everyone who
  already drank**. Treat it as state, not cache.
- The recipient slot is the only request-controlled value and is checked against the channel's own
  signed `member_count + delegate_count`; the amount and token are server-side config only. There
  is **no ownership proof** on that slot — an anonymous caller may request a drip for any active
  account, which lands with the legitimate owner but consumes the channel allowance (residual risk
  R-1 in `doc/tasks/itx-faucet-threat-model.md`).
- **DEPLOYMENT INVARIANT (D-1): exactly ONE writer process per channel directory.** Every
  single-use ledger in `wallet-live-work/ch<N>/` is a plain JSON file guarded by an IN-PROCESS
  mutex, not a file lock — the faucet drip ledger (`faucet_state.json`), the imported-deposit
  ledger (`CliState.imported_deposits`, see `doc/tasks/deposit-import-threat-model.md`) and the
  pre-existing inter-channel spent/applied ledgers. Two processes sharing one directory can both
  pass a membership check and both commit: a double drip, or the SAME L1 deposit credited twice.
  Note this is not only "two relays" — the api service, the relay and the node co-signer can all
  be pointed at the same work dir. Run one writer per channel; if that ever changes, these ledgers
  need a real file lock BEFORE the faucet or browser deposit import is re-enabled.

## Post-review Option B (1024-slot) redeploy (#12)
Option B circuits/fixtures are already present on this branch (constants
`MAX_COSIGNERS=16`, `MAX_CHANNEL_MEMBERS=1024`). The LIVE network still runs
pre-Option-B params, so a fresh deploy with the regenerated Option-B fixtures/VKs
is required. Also complete the one-key member-model validity-path registration
follow-up (tracked with the Option B work).

## Verification checklist before opening deposits

- [ ] Every old V1/v2 pending submission, close, claim, journal and bond was resolved or retired;
      no old state is being reinterpreted under wire v3.
- [ ] All 15 proof-free configs were generated first in an isolated no-deploy window and the
      config-only cohort gate passed; that intermediate was never merged, pushed, tagged, released,
      or handed to an operator on its own.
- [ ] One reviewed top-level cutover commit pins the exact reviewed submodule commit and contains
      the complete current-generation config, full-proof, DA/lifecycle/claim companion and snapshot
      cohort; both WASM packages were rebuilt from that exact source and their deployed hashes were
      recorded.
- [ ] Six distinct adapter/core pairs and their config/circuit/WHIR/protocol/session identities were
      checked from constructor inputs and finalized runtime code.
- [ ] The exact Manager address was fixed before all full fixtures were regenerated in one run.
- [ ] Every consumer submits the exact strict `.compactProof.bytes`; no tuple/proof-object fallback
      or alternate proof-DA encoding remains.
- [ ] The complete Step 4 Rust, Solidity, adversarial, DA, gas and production-size matrix is green.
- [ ] Deploy used `--locked`; `FRAUD_TREASURY` + `BLOCK_PRODUCER` were set explicitly.
- [ ] Post-deploy: `isBlockProducer[poster] == true`; Rollup adapters are distinct; settlement
      adapters are distinct; every adapter's `core()` and immutable digests match its config.
- [ ] A real close/withdraw lifecycle passes on the target network after public-chain acceptance is
      authorized.
- [ ] An independent cryptographic reviewer approved the wire-v3 transcript, commitment, malicious-
      prover argument, written soundness budget and Rust/Solidity parity.
- [ ] The separate final-audit NO-GO items are closed and a reviewed change explicitly removes the
      `releaseRuntime` chain-31337 containment. Until then this checklist cannot authorize deposits.
- [ ] `RegisterTokens.s.sol` run for every ERC-20 the deployment will accept, BEFORE the first
      ERC-20 deposit; `tokenAddressOf(idx)` reads back the expected address for each.
- [ ] `tokens.json` shipped alongside `channel_backing.json` into every channel work dir, and the
      relay/api logged every entry as `verified` (an unverified entry silently degrades the UI to
      raw base indices; a contradicting entry refuses to start).
