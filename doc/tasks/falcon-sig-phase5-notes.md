# falcon-sig Phase 5 — fixtures, end-to-end, deploy prep

Branch `feat/falcon-poseidon-sig`, on top of `2436aa1` (Phase 4). **Not committed.**

Scope: enumerate and regenerate the fixture set invalidated by Phases 2/2.6/3/4, validate it
SEMANTICALLY (MLE/WHIR proofs are non-deterministic — never by byte comparison), run every suite to
green, decide the Phase-4 INFO-7 carried item, and register the new domain constants in
`detail2.md`.

---

## 1. Fixture regeneration set — ENUMERATED (not assumed)

### 1.1 What invalidates what

Two independent invalidation vectors:

- **VK-derived** — the Falcon migration changed the list VK (Phase 3), therefore the validity chain
  VK, and swapped the close/cancel aggregation VK (Phases 2/2.6). Every wrapper proof that bakes one
  of those inner VKs has a new `circuitDigest`.
- **Key-derived** — every member `pk_g` VALUE changed TWICE: once in Phase 3
  (`pk_g = Poseidon(IMFK‖encode(h))` instead of `Poseidon(IMPG‖sk_g)`) and again in Phase 4, when the
  CLI/fixture cosigner identities moved from the dedicated `falcon_seed_for` (tag `0xfc`) derivation
  onto `MemberKeys::generate`'s RNG stream. Everything that folds a `pk_g` — the registration keccak
  chain, `MemberTree` roots, the IMCM member-set commitment, the validity block chain, close/cancel
  PIs — moves with it.

### 1.2 Producer → file map (evidence: `fs::write` sites in `src/bin/generate_*.rs`)

`contracts/test/data/` holds **31** JSON files. **27** are generator output; **4** are not.

| generator (`src/bin/…`) | files written | invalidated by |
|---|---|---|
| `generate_e2e_fixture.rs` | `mle_fixture.json`, `vpi_fixture.json`, `block_fixture.json` | VK (validity) |
| `generate_withdrawal_fixture.rs` (no prefix) | `withdrawal_mle.json`, `lifecycle_validity_mle.json`, `lifecycle.json`, `withdrawal_payout.json` | VK + KEY |
| …same binary, `WD_OUT_PREFIX=close_` | `close_withdrawal_mle.json`, `close_lifecycle_validity_mle.json`, `close_lifecycle.json`, `close_withdrawal_payout.json` | VK + KEY |
| …same binary, `WD_OUT_PREFIX=sepolia_` | `sepolia_*` (4) | VK + KEY — **NOT regenerated, see §1.4** |
| `generate_c2c_fixture.rs` | `c2c_lifecycle.json`, `c2c_lifecycle_validity_mle.json`, `c2c_withdrawal_mle.json`, `c2c_withdrawal_payout.json` | VK + KEY |
| `generate_close_fixture.rs` (feat `close-fixture-bin`) | `close_intent_mle.json`, `close_intent.json` | VK (agg) + KEY |
| `generate_cancel_close_fixture.rs` (feat `cancel-close-fixture-bin`) | `cancel_close_mle.json`, `cancel_close.json` | VK (agg) + KEY |
| `generate_withdrawal_claim_fixture.rs` (feat `withdrawal-claim-fixture-bin`) | `withdrawal_claim_mle.json`, `withdrawal_claim.json` | VK (wrapper only) |
| `generate_post_close_claim_fixture.rs` (feat `post-close-claim-fixture-bin`) | `post_close_claim_mle.json`, `post_close_claim.json` | VK (wrapper only) |
| `generate_wasm_fixtures.rs` | `tests/fixtures/*` (NOT under `contracts/test/data/`) | VK |

The **4 non-generator** files, with evidence:

| file | what it is | disposition |
|---|---|---|
| `e2e_fixture.json` | Groth16 proof + VK (`groth16_proof`/`verifying_key`/`pi_hash`) | **DEAD.** `grep` over `*.sol`/`*.rs`/`*.js` finds ZERO consumers and ZERO producers — the gnark fixture test was removed with the MLE-only switch (CLAUDE.md). Not regenerated; nothing can regenerate it. |
| `e2e_groth16.json` | ditto | **DEAD**, same evidence. `generate_e2e_fixture.rs:94` explicitly says Groth16 fixtures are "managed separately"; no code path reads it. |
| `pw_reg.json` | `member_pk_gs`/`member_pk_bs`/`recipients` for the partial-withdrawal deploy script | **KEY-derived and stale, but self-refreshing**: written at RUN TIME by `tests/partial_withdrawal_e2e.rs:308` and by `bin/channel_member.rs:3950`, read only by `script/DeployPartialWithdrawalE2E.s.sol` / `DeployWalletSettlement.s.sol` (never by `forge test`). The committed copy is a stale by-product; running the Rust E2E rewrites it. |
| `pw_submit.json` | close/withdrawal fields for `SubmitPartialWithdrawal.s.sol` | same — written by `tests/partial_withdrawal_e2e.rs:491` / `channel_member.rs:4657`. |

### 1.3 Which files carry key-derived vs VK-derived values (evidence: JSON key structure)

- **KEY-derived**: `lifecycle*.json` → `registration.member_pk_gs` (+ everything folding it:
  `final_state_root`, `vpis.final_block_chain`, `vpis.final_ext_commitment`, `proof_hash`);
  `close_intent.json` → `member_pk_gs`, `member_set_commitment`, `close_intent_digest`,
  `final_channel_state_digest`, `final_balance_state_h1`; `cancel_close.json` → same family;
  `pw_reg.json` → `member_pk_gs`.
- **VK-derived**: every `*_mle.json` → `circuitDigest` (+ `preprocessedCommitmentRoot`, `gates`,
  `whirParams`, and the whole proof body).
- **NEITHER (synthetic vectors)**: `withdrawal_claim.json` (`member_pk_g =
  0x0000000a0000000b…`) and `post_close_claim.json` (`receiver_pk_g = 0x0000000b0000000c…`) are
  ARBITRARY pinned 32-byte digests — the claim circuits consume `pk_g` as an opaque digest and
  verify no signature. Their descriptors are correctly UNCHANGED by the migration; only their
  wrapper proofs regenerate. (Confirmed empirically: both files are byte-identical after
  regeneration while their `*_mle.json` siblings changed.)

### 1.4 `sepolia_*` — deliberately NOT regenerated

The four committed `sepolia_*` files are read **only by `contracts/script/`** (`DeployClose.s.sol`,
`RunClose.s.sol`) — `grep` over `contracts/test/**.sol` finds zero references. They are the LIVE
DEPLOYMENT artifact set, and eight more `sepolia_*` files the scripts reference do not exist in the
tree at all (the CLI stages them at deploy time). Regenerating them requires a target-network
`WD_RECIPIENT` (the manager CREATE2 address on that chain), i.e. a deploy decision, not a test
input. `tests/close_lifecycle_cli_e2e.rs` and `tests/two_token_cli_e2e.rs` overwrite them during a
run and restore them via a Drop guard.

**They are STALE and must be regenerated as part of the v3 reset/redeploy** —
`doc/tasks/regen-and-redeploy-runbook.md` Step 1 + Step 3. Recorded as STOP point 1.

### 1.5 What was regenerated (runbook order, one heavy process at a time)

| step | command | wall | peak RSS |
|---|---|---|---|
| 1 | `generate_e2e_fixture` | 50 s | 5.97 GB |
| 2 | `generate_withdrawal_fixture` (plain) | 134 s | 7.16 GB |
| 3 | `forge test --match-test test_printCloseManagerAddress -vv` → `CLOSE_MANAGER_ADDRESS = 0x0B193Ed789C50C205A19E265eA4F78C6c331ABAC` | — | — |
| 4 | `WD_RECIPIENT=0x0B19…ABAC WD_OUT_PREFIX=close_ generate_withdrawal_fixture` | 128 s | 9.05 GB |
| 5 | `generate_close_fixture` | 77 s | 7.91 GB |
| 6 | `generate_withdrawal_claim_fixture` | ~170 s | (peak footprint 39 GB — see STOP 4) |
| 7 | `generate_post_close_claim_fixture` | 168 s | 26.29 GB |
| 8 | `generate_cancel_close_fixture` | 35 s | 5.45 GB |
| 9 | `generate_c2c_fixture` | 119 s | 11.92 GB |
| 10 | `generate_wasm_fixtures` | 36 s | 9.03 GB |

Total 27 files rewritten; 20 changed content, 3 (`vpi_fixture.json`, `withdrawal_claim.json`,
`post_close_claim.json`) are legitimately byte-identical (§1.3 and §2.2), and the 4 `sepolia_*` were
not touched.

---

## 2. Semantic validation (never byte comparison)

Per `project_mle_whir_nondeterministic`: MLE/WHIR proofs carry ZK blinding, so a regenerated fixture
is NEVER byte-reproducible. Validation is by MEANING.

### 2.1 The VK cascade landed exactly where the design predicts

`circuitDigest` before vs after, per wrapper fixture:

| fixture | circuitDigest | publicInputs | reading |
|---|---|---|---|
| `lifecycle_validity_mle.json`, `close_lifecycle_validity_mle.json`, `c2c_lifecycle_validity_mle.json`, `mle_fixture.json` | **CHANGED** | changed (except `mle_fixture`, §2.2) | list VK → validity VK → wrapper digest. As designed. |
| `close_intent_mle.json`, `cancel_close_mle.json` | **CHANGED** | same length (103 / 27) | the `FalconAggCircuit` VK replaced `AggLevelCircuit`'s inside the close/cancel circuits. As designed. |
| `withdrawal_mle.json`, `close_withdrawal_mle.json`, `c2c_withdrawal_mle.json` | **same** | **CHANGED** | correct: the withdrawal circuit family verifies no signature, so its VK is untouched; only its PI values move because the block chain / ext commitment fold the new `pk_g`. |
| `withdrawal_claim_mle.json`, `post_close_claim_mle.json` | same | same | correct: the claim circuits are signature-free AND driven by synthetic `pk_g` vectors (§1.3). Only the (blinded) proof body differs. |

No PI **length** changed anywhere — the migration is value-only, layouts stable (TM-C7). This is the
falsifiable form of "layouts do not change, only values".

### 2.2 The key change is visible and correctly scoped

`git diff contracts/test/data/lifecycle.json`:

- `registration.member_pk_gs` — all three CHANGED (new Falcon identities);
- `registration.member_pk_bs` — **UNCHANGED** (BabyBear `pk_b` is out of scope — exactly the
  designed blast radius);
- `final_state_root`, `vpis.final_block_chain`, `vpis.final_ext_commitment` — CHANGED (they fold
  `pk_g`);
- `genesis_state_root` — UNCHANGED (pre-registration).

`block_fixture.json` / `vpi_fixture.json` / `mle_fixture.json` PIs are unchanged because the e2e
chain that produces them contains **no channel registration**, so it folds no `pk_g`; only the proof
body changed. That is a consistency check, not an omission: `block_fixture.initial/final_block_chain`
and `vpi_fixture` agree with each other and with `mle_fixture.publicInputs`, all unchanged, while
`proof_hash`/`proof_length` moved.

### 2.3 The strongest semantic gate: the on-chain close lifecycle

`CloseLifecycleE2ETest.test_closeLifecycle_endToEnd` **PASSED and did NOT skip** (80.0 M gas). It
hard-asserts (`CloseLifecycleE2E.t.sol:181`) that the close fixture's `member_set_commitment` equals
the manager's `registeredMemberSetCommitment` derived from `close_lifecycle.json`'s registration.
That single assertion closes the loop Rust `MemberKeys` → Falcon `h` → `Poseidon(IMFK‖encode(h))` →
registration keccak → Solidity, over independently generated fixtures — a stale or mixed-run set
fails it. It also asserts `address(manager) == bakedRecipient`, validating step 3/4 of §1.5.

---

<!--RESULTS-->

---
