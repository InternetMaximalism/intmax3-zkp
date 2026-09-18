# Line-by-line Lean formalization of the whole implementation — resumption guide as of 2026-09-08

This is written so that the work can be resumed from this document alone. It does not presuppose any memory of the conversation.

## 0. Where we are (in one line)

The line correspondence for the 71 core files and the main parts of the dependency side is complete, the fund conservation of every entrypoint has been composed into a single theorem, and
the unproved premises have been collected into 13 named fields. **This is neither overall completion nor a release approval.**

## 1. Location and state

```text
worktree : /Users/andropov/repos/intmax3-zkp/.claude/worktrees/mle-plonky2-proof-completion-48398c
branch   : codex/implementation-linewise-lean-20260906
HEAD     : b3e19c2  feat(lean): accept the pinned MLE submodule as a named trust assumption
base     : 59 commits from 680146f to this HEAD
submodule: contracts/lib/polygon-plonky2 = 3a20a05fb99d2653c4d37debb4f1ead2f422dfb2 (clean)
push     : **not done**. Local commits only. No push until instructed.
```

The working tree is clean. Nothing appearing in `git status` is the normal state on resumption.

**Record of an important accident.** This work was previously done in a worktree under `/private/tmp`, and a macOS reboot
took the whole worktree with it (21 uncommitted modules and more than 30 correspondence tables were lost and had to be rebuilt).
The current worktree is on a persistent volume. **Do not put work in `/private/tmp`.**
It is safer to run `doc/audit/zkp/agent-tools/autocommit.sh`, which makes a WIP commit of agent output every 10 minutes.

## 2. Verification commands (all should pass right after resuming)

```sh
cd /Users/andropov/repos/intmax3-zkp/.claude/worktrees/mle-plonky2-proof-completion-48398c
export PATH=/Users/andropov/.elan/bin:$PATH        # pinned Lean 4.10.0. Do not use another lean
bash .github/ci/lean-safety-guard.sh               # → PASS
python3 -B .github/ci/lean-line-coverage.py        # → PASS
python3 -B .github/ci/lean-line-coverage.py --require-complete   # → exit 1 is correct
python3 -B .github/ci/test-lean-safety-guard.py    # 29 tests OK
python3 -B .github/ci/test-lean-line-coverage.py   # 22 tests OK
python3 -B .github/ci/test-lean-fixture-parity.py  # 40 tests OK
python3 -B .github/ci/test-check-ledger-writers.py  # 6 tests OK
python3 -B .github/ci/check-ledger-writers.py       # → PASS (inventory of Solidity write sites)
python3 -B .github/ci/lean-fixture-parity.py       # 18 fixtures / 177 fields / 0 FAIL
git diff --check
```

Expected values: the main guard reports **132 Lean modules / 79 current modules / 497 reviewed-source hashes / 1 submodule pin** (after the 4th loop of 2026-09-11),
the line guard reports **169 source maps**, and the line classification is
`translated 31,095 / dependency-boundary 10,850 / non-executable 9,828 / test-only 25,892 / untranslated 41,784` (after the 4th loop's test-only probe insertion).

Running `lake build` over everything takes about 10 minutes. For an individual module use
`cd doc/audit/zkp && lake build Zkp.Implementation.<Name>`.

## 3. Working tooling (in the repository, under version control)

It lives in `doc/audit/zkp/agent-tools/`. It has no absolute-path dependencies and derives the repo root from its own location.

| File | Purpose |
|---|---|
| `module-README.md` | Instructions for an agent writing a new module. Includes the CI rules and the proof pitfalls (kernel timeout poisoning and others) |
| `linemap-README.md` | The schema of the line-map JSON and the honesty rules |
| `validate-linemap.py` | Validates one correspondence table. Fix until `PROBE OK` appears. `--no-probe` skips starting Lean |
| `register2.py` | Registers unregistered modules in bulk (Zkp.lean import / guard CURRENT / manifest / inventory). It also regenerates the theorem list of already-registered modules, so use it for the hash update after adding theorems too. Idempotent with no arguments |
| `tmo.py` | A substitute for the `timeout` that macOS lacks. `python3 tmo.py 300 lake env lean <file>` |
| `autocommit.sh` | Insurance that WIP-commits agent output every 10 minutes. Run it in the background |

When instructing an agent, replace `<root>` in the README with the actual absolute worktree path before passing it on.

## 4. What is proved and what is a premise

### 4.1 Proved with no premises (`Zkp.Implementation.SystemSafety`)

For any finite trace (the 12 `Step`s covering Rollup deposit, withdrawNative / withdrawERC20, materializer credit, Manager pull,
submitClaim, claimCredit payout, close request / cancel / finalize, and rollback):

- `trace_conserves_per_token` — per-token conservation law.
- `trace_channel_attribution` — the Manager's `received` does not exceed its own channel's cap, the cap is not rewritten,
  and materialization is retained once latched.
- `trace_nullifier_single_use` — persistence of a consumed nullifier and failure of resubmission.
- `trace_paid_bounded` — conservation of `paid ≤ received` and the paid / unspent decomposition.

### 4.2 Premises derived from the implementation (no longer assumptions)

- **nullifier freshness**: `IndexedMerkleTree.accepted_insertion_implies_key_absent`.
  An accepted insertion proof implies the absence of the key. The premises are only three: collision resistance of Poseidon
  (injectivity of the leaf's 18-word encoding is proved, so only the hash itself remains), the ordered-set invariant
  (holds for the empty tree, preserved by insertion), and the range of the key. `insert_fails_iff_key_present` holds even without the hash assumption.
- **Semantics of the selection circuit**: `UtilGadgets.select_vec_one_hot_selects_candidate`.
  The 4-term sum-of-products selection that SwitchBoard had assumed is now proved from the implementation. One-hotness, however, is not enforced.

### 4.3 Agreement between circuit and Solidity (4 of them)

`DepositChain.chain_matches_rollup_fold`, `ChannelRegChain.chain_matches_rollup_fold`,
`ValidityChain.circuit_pi_layout_matches_solidity_preimage`,
`WithdrawalChain.circuit_layout_matches_rollup_verifier`.
None of these is a comparison between two hand-written models; each derives that the circuit-side word / byte sequence
agrees with the computation of the model of the Solidity implementation.

### 4.4 The 23 named premises (`Zkp.Implementation.TrustBoundary`)

`mleVerifierSoundness` (a0) / `closePrimitiveLowering` (a) / `withdrawalPrimitiveLowering` (b1) /
`postClosePrimitiveLowering` (b2) /
`materializerViewIsManagerState` (c0) / `managerFundsDigestIsReference` (c0b) / `backingVerifierSoundness` (c1) /
`backingPrimitiveLowering` (c2) / `backingKeccakIsReference` (c3a) / `backingTokenFundsHashBinding` (c3b) /
`finalizedBalanceIsBacked` (c4) /
`aggregateRecursiveVerifierSoundness` (d0) / `levelRecursionSoundness` (d0') /
`aggregatePrimitiveLowering` (d1') / `falconUnforgeability` (d3) /
`solidityKeccakIsReference` (e1a) / `circuitKeccakIsReference` (e1b) / `tokenFundsHashBinding` (e2) /
`finalizedRootObservation` (f1) / `finalizedHeightObservation` (f2) /
`ledgerWritersAreInventoried` (g1') / `latchWritersAreInventoried` (g2') / `sourceRefinement` (h).

**In the 4th loop of 2026-09-11 (c) was decomposed into 7 and (d2') became a theorem** (`NttCorrectness`).
What remains is (c4) `finalizedBalanceIsBacked` (an invariant of the L2 ledger; composing the validity chain is the next project).
The public document is `PRACTICAL-SAFETY-PROOF.md`; the mechanical faithfulness evidence is in `evidence/` and `src/faithfulness.rs`.

**In the 3rd loop of 2026-09-11 we replaced (d1)(d2)(g1)(g2).** The aggregation stack (agg.rs leaf/level, gadget.rs) has become
the instruction sequences `FalconAggProgram` and `FalconGadgetProgram`, and there is no longer any field that assumes a whole circuit.
(g1)(g2) are reduced to a source refinement over the write-site inventory of `LedgerWriters` (checked by CI's `check-ledger-writers.py`).
The `cap t = cap s` clause of the old (g1) was refuted by `finalizeCloseGuarded`, so it has been corrected to the monotone form
(`durable_nullifier_ledger_of_boundary`).

**In the 2nd loop of 2026-09-11 we decomposed (d)(e1)(e2).** The conclusions of the old (d)(e1)(e2) are now theorems, as
`signature_validity_of_boundary`, `circuit_keccak_is_solidity_keccak_of_boundary` and
`token_funds_hash_binding_of_boundary`. The reference Keccak-256 is `Keccak256`
(4 vectors proved in the kernel); the bridge on the signature side is `CloseSignatureBridge`. What cannot be discharged:
(d3) the lattice assumption, (e2) collision resistance, (e1a) EVM semantics, (d2') NTT = negacyclic product (provable but not yet started).

**Since 2026-09-11, (a)(b1)(b2) are "per-instruction lowering" rather than "lowering of the whole circuit".**
Each circuit's `program_satisfied_implies_gates` proves `ProgramSatisfied constructorProgram a ⇒ CircuitGates` with no premises,
so what remains is only two points: (i) that each case of `BuildOp.holds` agrees with the plonky2 primitive, and
(ii) that the pinned digest is the digest of `constructorProgram`
(`TrustBoundary.*_gap_is_now_per_primitive`, `*PinnedDigestIsProgramDigest`).

**`mleVerifierSoundness` (premise a0) is a trust assumption accepted by operator judgement.** It is on a par with the KZG ceremony.
We trust, rather than translate, the pinned MLE/WHIR submodule (limited to commit `3a20a05f`).
What this buys is `mle_assumption_reduces_close_soundness_to_gate_lowering` (the gap on the close path becomes a single step of
`CloseStatementLowering`); what it does not buy is shown by counterexamples in
`SystemSafety.mle_assumption_does_not_imply_fund_safety` and
`mle_assumption_alone_does_not_yield_close_gate_soundness`.
MLE's 68 files and 33,974 lines remain **untranslated** in the inventory and are not counted as verified.

**Where the remaining gap sits** is made explicit by `SystemSafety.close_vector_backing_is_exactly_premise_c`.
Because the Rollup escrow is pooled, the part that ties the cap to the channel's own deposits remains premise (c).

## 5. What to do next (in priority order)

1. ~~Fix the unreachable canonicality check in `ChannelRegRecord::validate`~~ **Done (`150bb19`).**
2. ~~Update the 2 stale tests in `balance_state`~~ **Done (`150bb19`).** One stale test in `wallet_core`
   was also updated in `31aaf6c`.
3. ~~Add `cargo test --lib` to CI~~ **Done (`150bb19`, 240 tests with `regev::` added).**
   The full run of all 711 lib tests was also completed on 2026-09-10 and all passed (see the same-day section of the progress document). `wallet_core::` /
   `circuits::` / `falcon_sig::` are kept out of the routine step because they do not fit on a 16 GB runner.
4. **Reducing the remaining premises.** ~~`CloseStatementLowering` and the claim-side (b1, b2) lowering~~ were
   narrowed to per-instruction on 2026-09-11. ~~The hash bindings (e1, e2) and signature validity (d)~~ were also decomposed in the 2nd loop that day
   (see the same-day section of the progress document). ~~Making (d1) per-instruction, the gate-by-gate check of gadget.rs for (d2), and inventorying (g1)(g2)~~
   were likewise completed in the 3rd loop that day. Every remaining premise is one of (i) per-instruction plonky2 faithfulness and digest pinning,
   (ii) the complexity assumptions (d3)(e2), (iii) the environment semantics (e1a)(f)(g')(h), or (iv) the design gap (c), and
   ~~(d2') the correctness of NTT~~ was proved in the 4th loop. In the 4th loop (c) was also reattached to materialization and
   decomposed into 7, with the remainder (c4) being an L2 ledger invariant (the composition of BalanceCircuit → SwitchBoard → ValidityChain →
   DepositChain/WithdrawalChain). The next project is that composition together with the mechanical checking of the faithfulness of the
   arithmetic and gadget semantics that remain in `not-static` (`evidence/README.md`).
5. **The 41,783 untranslated lines** are MLE's 33,974 lines (accepted) plus about 7,800 more (the f64 FFT of the falcon vendor,
   and the portions each module explicitly marks as untranslated). Do not force them over into translated.

## 6. Findings requiring human judgement

All of them are fixed as theorems. They are not demonstrations of vulnerabilities. The numbers correspond to the progress document.

**An actual defect (1 item, fixed 2026-09-09)**
- The rejection of non-canonical identities in `ChannelRegRecord::validate` was **unreachable**.
  This was because the round-trip check of `PoseidonHashOut::try_from(Bytes32)` never fired, since `reduce_to_hash_out` and the reverse conversion are
  strict inverses. The repository's own test
  `common::channel_registration::tests::test_channel_reg_validate_rejects_noncanonical_identity_encodings`
  was actually failing.
  **Fix**: prepend to `try_from` an explicit canonicality check against the Goldilocks order, and
  add the error variant `PoseidonHashOutError::NonCanonicalElement(usize)`. `reduce_to_hash_out` and
  `From<PoseidonHashOut> for Bytes32` are unchanged, so callers that use the many-to-one reading are unaffected.
  The Lean side has followed suit (`H1Gadget.native_try_from_requires_canonical_elements`,
  `ChannelRegChain.non_goldilocks_record_rejected`, `BlockTypes.non_canonical_pk_g_rejection_is_reachable`).
  That half of the round trip is still unreachable is retained as
  `ChannelRegChain.byte_round_trip_alone_cannot_reject`.

**Stale tests (2 items, updated 2026-09-09)**
- `common::balance_state::tests::balance_state_validate_multi_n` and
  `balance_state_delegate_count_regions_and_h1` asserted that member_count 16 passes.
  Since `fd467ea` (restricting the sig-cluster to 8), 2..=8 is correct. They were updated to use `MAX_SIG_CLUSTER`, and
  the 3 negative tests that were built from the invalid base 16 were fixed to use a valid base so that they actually exercise the intended check.

**Design observations**
- **The channel tree does not enforce fund conservation across blocks.** `ChannelLeaf` has no fund vector, and
  the public root is unchanged even if the IMCH preimage is substituted (`UpdateChannelTree.native_account_root_ignores_channel_state_fields`).
- **No signature is verified at all in `update_channel_tree.rs`.** Only the fold into `bp_sig_chain`.
- **Matching up inter-channel transfers is not done on the block side.** `destination_channel_id` is never read by anything.
- **The Falcon verifier does not exist in the vendor tree.** The coefficient range of the decoder does not imply a norm bound
  (`FalconVendor.decode_range_does_not_imply_norm_bound`).
- **Whether the circuit gadget verifies a signature depends on a single wire that the gadget itself does not constrain.**
  If the wire is 0, the norm-bound check is replaced by a range check on the constant 0 (`FalconCore.padding_slot_norm_gate_is_trivial`).
- **An accepted aggregate proof shows neither distinctness of the signers nor membership in the member set.**
- **`range_check(count_minus_one, 4)` at `agg_list.rs:329` allows a signer count of 1 to 16.** The upper bound of 8 comes from the structure.
- **A hash signature is a replayable token.** There is neither a nonce nor an expiry in the public values. Soundness depends on the relying side
  resolving `pk_b` from a registered leaf and accepting an IMPA digest at most once.
- **`validate()` in `channel.rs` constrains structure only.** It passes even if the entire key set is substituted while keeping both roots
  (`ChannelTypes.validate_accepts_substituted_member_set`). The signature verifier does not react to the blob contents.
- **There is no domain separation between leaves and nodes**, and the roots of an empty SendTree and an empty TxV2Tree of height 32 agree without any hash assumption.
- **`test_utils` is a public module without cfg(test)**. The harness's deterministic Falcon key derivation is reachable from production.
- **The domain non-collision check is test-only and disabled in release.**
- **`U32LimbTargetTrait::get_witness` silently truncates a field wire at 2^32.**
- **`U63Target::enforce_ge` is not an ordering check in the window at the top end (exactly `2^32 - 2` values).** The 32-bit version is sound.
- **An out-of-range index update on a sparse tree records the leaf while leaving the root unchanged.**
- **Mismatch between documentation and implementation**: `channel_tree.rs` says the member root is 1024 slots, but it is actually 8 slots at height 3.
  `agg.rs` says `AGG_LEVELS = 4` / 137 public inputs, but the code says 3 and 73 (the assert message at
  `batch.rs:695` still says 137 as well — the wording an operator reads when the assert fires).

## 7. Prohibitions (carried over from the predecessor, still in force)

- Do not reclassify untranslated spans as translated without grounds in order to make `--require-complete` pass.
- Do not treat the success of a callback as proof soundness / ownership / freshness.
- Do not treat `root != oldRoot` as freshness. Do not treat `paid ≤ received` as a proof of non-crossing between channels.
- Do not treat a cluster signature as the legitimacy of user assets.
- Do not extend the MLE trust assumption to other unproved dependencies. It extends only to commit `3a20a05f`.
- Do not change the runtime, proof parameters or proof format without benchmark confirmation
  (the diff in `src` / `contracts` / `Cargo.toml` / `Cargo.lock` against the runtime baseline `05ec7ae` is currently zero).
- Do not reset / check out / delete the main checkout or the MLE submodule.
- Do not launch more than 20 agents in parallel (a hard limit). If the credits run out, every agent dies at once.
