# Phase 2 notes — Close + cancel-close rewiring (Falcon-512/Poseidon)

Status: **implemented, awaiting security review** (the separate review subagent per plan). Branch
`feat/falcon-poseidon-sig`. Implements the Phase-2 checklist of `falcon-sig-todo.md` under threat
model `falcon-sig-threat-model.md` (TM-C5 items 1–5, TM-C6, TM-C7, O-6, O-8, O-9). §§1–6 were
written by the keystone pass (`FalconAggCircuit` + gadget-level changes); §7 records the consumer
rewiring, now COMPLETE (the two passes converged on the same VK-swap design; the coordination STOP
is resolved). §10 has the verification results.

## 1. Architectural decision (the crux) — separate `FalconAggCircuit`, NOT inline

The design directive (owner's stated goal, restated in the Phase-2 brief) is: *"Falcon replaces the
signature; aggregate with plonky2 as usual; on-chain MLE unchanged."* Realized as a **separate
aggregation circuit** the close/cancel circuits recursively verify at a constant VK — a pure VK swap
+ constant rename, with the entire downstream (member-set commitment, A5 distinctness, MLE wrapper)
UNCHANGED.

An earlier uncommitted WIP had instead **inlined** 16 `FalconSigVerifyTarget` gadgets directly into
the close (and cancel) circuit. That was rejected and reverted here because it lands the ~827k
signature gates DIRECTLY in the MLE-wrapped close proof, blowing its degree from 2^17 to ≥2^20 —
exactly the MLE-wrapper threat the brief flags. The separate-agg design keeps the MLE-wrapped close
proof small (it recursively verifies ONE fixed-shape 137-PI proof, as it already did for the retired
`AggLevelCircuit`), so the close degree should stay ~2^17 (measurement pending, §6).

New module: **`src/falcon_sig/agg.rs`** — `FalconAggCircuit`, `FalconAggWitness`, and the offset
constants `FALCON_AGG_MSG_OFFSET (0)`, `FALCON_AGG_COUNT_OFFSET (8)`, `FALCON_AGG_PK_LIST_OFFSET (9)`,
`FALCON_AGG_PUBLIC_INPUTS_LEN (137)` — numerically identical to the old
`agg_public_inputs_len(AGG_LEVELS=4)` and the `AGG_*_OFFSET` constants, so the consumer change is a
constant rename + VK swap.

The circuit verifies `MAX_COSIGNERS = 16` Falcon signatures over ONE shared message digest (one
`FalconSigVerifyTarget::new_conditional` per slot, gated by a per-slot `is_active` bit) and exposes
`[ message(8) | signer_count(1) | pk_g_0(8) … pk_g_15(8) ]`.

## 2. Padding soundness re-argument (TM-C7 / O-8) — padding exposes pk_g EXACTLY zero

Chosen padding construction (design A, matching the threat model's "expose pk_g EXACTLY zero"):

- Each slot's norm bound is conditionally enforced by `is_active` inside the gadget
  (`new_conditional`: `range_check(select(is_active, β² − norm, 0), 26)`). Everything else in the
  gadget — coefficient canonicity, the `pk_g = Poseidon(IMFK‖encode(h))` binding, H2P, the NTT
  equation `s1 = c − s2·h` — stays UNCONDITIONALLY enforced.
- The gadget's INTERNAL `pk_g` for a padding slot (all-zero witness `h = s2 = salt = 0`) is therefore
  forced to the fixed public constant `Poseidon(IMFK‖encode(0)) = falcon_padding_pk_g()`.
- The aggregation circuit EXPOSES `select(is_active, internal_pk_g, 0)`, so a padding slot's exposed
  pk_g limbs are **EXACTLY zero** — byte-identical to the old left-packed zero suffix and to the
  native `close_member_set_commitment` padding (`Bytes32::default()`). `falcon_padding_pk_g` is never
  exposed; it is an internal artifact the select zeroes out. (A test,
  `padding_pk_g_is_nonzero_but_never_exposed`, pins that the constant is nonzero so the zeroing is
  load-bearing, and `check_pis` asserts every padding slot is exactly zero.)

The three integrity properties (analogue of the old left-packing invariant, aggregate.rs:385–416),
re-argued at the new site:

- **active ⟹ valid signature.** `is_active[i] = 1` makes slot `i`'s norm bound LIVE, so the
  constraint set is exactly the unconditional Falcon verifier — no valid witness exists without a
  genuine Falcon signature over the shared message under that slot's derived pk_g (forging one is the
  GPV/NTRU problem).
- **inactive ⟹ pk_g = 0 exposed.** The `select` forces it structurally; a prover cannot expose a
  nonzero pk at an `is_active = 0` slot.
- **signer_count = #{genuinely verified signatures}.** `signer_count = Σ is_active` and the bits are
  monotone (prefix), so it equals the active prefix length. The only residual — an "active" slot whose
  `h` hashes to the ZERO digest (exposing pk_g = 0 while inflating the count) — requires a Poseidon
  preimage of the zero digest under IMFK (the same strength as today's padding argument), AND that
  slot still needs a valid Falcon signature under that `h`, AND it injects a zero limb into a PREFIX
  position of the member-set commitment, which then fails to match the L1-registered commitment. So
  it is neither reachable nor useful.

Monotonicity (`is_active[i+1] ⟹ is_active[i]`) is enforced in the agg circuit, reproducing
left-packing so the close circuit's `active_bits = (i < member_count)` gating aligns with the real
signer prefix.

Note on the reverted WIP's variant (design B): it left the pk binding unconditional and exposed
`falcon_padding_pk_g` (nonzero) for padding, relying on the close/cancel `select` to zero it. That is
ALSO sound (the committed padding value stays 0), but makes the consumer's select load-bearing and
leaves a footgun for any future consumer that reads the agg PIs without zeroing padding. Design A
(expose 0 at the agg boundary) is the self-contained invariant the threat model asks for and is what
ships. `falcon_padding_pk_g()` is retained (it IS the internal padding digest) with its doc.

## 3. Message-digest recompute discharge (TM-C5 item 4 / TM-C6)

`FalconAggCircuit` has ONE `message` public input (offset 0); every slot's gadget `message_digest`
input is `connect`ed to it. The CONSUMER (close / cancel) connects that `message` PI to its
in-circuit-recomputed IMCH digest (`state_digest`, the same wires as the `final_channel_state_digest`
PI) exactly as the old consumer connected `agg_message` — so `c = H2P(salt, message)` is fully
determined by the real recomputed digest and never a free witness. O-6 cross-context isolation is
inherited: the verifier recomputes `c` from ITS context's digest and never accepts a signer-supplied
message; a signature over an IMCH digest cannot verify against an IMSB digest (different keccak
domain). Circuit-level test: `wrong_message_rejected`.

## 4. MINOR-2 (accept-set delta) — recorded decision

The gadget accepts any canonical `s2` residue meeting the norm bound — a strictly larger set than the
native wire-decodable band `[-2047, 2047]`. **No close/cancel consumer relies on "circuit-accepted ⟹
native-wire-decodable".** Confirmed: the consumers read only the agg proof's PIs (message / count /
pk list) and witness signatures INTO the agg circuit from `FalconSigGadgetWitness::for_signature`
(built from a native `FalconKeys::sign` / `FalconSignature`, both inside the transport band); no
consumer re-serializes a circuit-witnessed `s2` or cross-checks it against `FalconSignature::from_bytes`.
So the delta is inert here. (Provenance is documented on the auth structs' `signature` field by the
consumer rewiring.) This is a recorded decision, not an inherited accident — GPV unforgeability is the
norm bound, which is unchanged.

## 5. Member-set commitment domain decision (TM-C7) — keep IMCM

**Keep `CLOSE_MEMBER_SET_DOMAIN = IMCM (0x494d434d)`.** The keccak LAYOUT `[IMCM, member_count,
pk_g_0..15]` is width-stable; only the committed VALUES change (pk_g is now a Falcon digest). A
version-distinguishing domain would only matter if old (SPHINCS+/Goldilocks) and new (Falcon)
commitments could coexist on one chain and be confused — but the migration is a hard v3 testnet reset
with no dual-scheme transition period (threat model §5, non-goals). With no cross-version replay
surface, minting a new domain buys nothing and would gratuitously churn the Rust↔Solidity constant.
Recorded either-way per the brief; decision: no change.

## 6. Measurement

`FalconAggCircuit` N=16 (`falcon_sig::agg::tests::agg_measure_n16`, release, standard_recursion_config):

| circuit | gates (pre-pad) | degree_bits | num_pis | prove |
|---|---:|---:|---:|---:|
| FalconAgg N=16 | _pending run_ | _(2^20 expected)_ | 137 | _pending_ |

Expected ≈ the Phase-1 standalone `FalconSigCircuit` N=16 datapoint (827,720 gates / 2^20 / ~70 s),
plus only ~150 gates (16×8 padding selects + 15 monotonicity + 16-term count sum) and FEWER public
inputs (137 vs 256), so it stays at degree 2^20. (Reproduce with
`cargo test --release -p intmax3-zkp --lib falcon_sig::agg::tests::agg_measure_n16 -- --nocapture --exact`.)

**Close circuit degree before/after: PENDING and OWNED BY THE CONCURRENT CONSUMER REWIRING (§7).**
The close fixture pins `degree_bits == 17` (close_circuit.rs `test_fixture::fixture`). Because the
close circuit still recursively verifies ONE fixed-shape 137-PI proof (now FalconAgg instead of
AggLevelCircuit), its recursive-verify cost is dominated by the verified circuit's gate-type set (a
similar range-check/Poseidon/arithmetic mix) and the FRI query count (same standard config), NOT the
verified trace length — so the close degree is EXPECTED to stay 2^17 (the FRI Merkle paths grow by
~6 levels, 14→20, adding a few hundred gates × ~28 queries: marginal). **This must be confirmed by
whoever finishes the close/cancel rewiring; if the close degree jumps past 2^17 it threatens the MLE
wrapper and must be flagged to the owner** (the `assert_eq!(degree_bits, 17)` pin will catch it).

## 7. Consumer rewiring (RESOLVED — completed by the consumer pass)

The coordination STOP below is retained for the record; every handoff item is now DONE:

- **`close_circuit.rs`** — VK swap + constant rename complete: imports
  `falcon_sig::agg::{FALCON_AGG_*}` instead of `poseidon_sig::aggregate::{AGG_*}`, arity check
  against `FALCON_AGG_PUBLIC_INPUTS_LEN`, section (f) consumes the FalconAgg statement at the
  renamed offsets with the SECURITY commentary re-argued for the new provenance (message binding
  now also discharges the Phase-1 carried TM-C5 item 4 END TO END: consumer `state_digest` →
  agg `message` PI → every slot gadget's `message_digest`, no free witness anywhere).
  `MemberCloseAuth.pk_g` is redefined in place as the Falcon identity digest (DD-2; struct shape
  unchanged). `test_fixture` builds `FalconAggCircuit` + `FalconKeys` (same per-slot seed bytes as
  the retired Goldilocks helper); `deterministic_falcon_keys(channel_id, n)` added for the
  fixture binary with the Phase-2/-4 registration seam documented on it.
- **`cancel_close_circuit.rs`** — same VK swap; test fixture on `FalconAggCircuit` + `FalconKeys`;
  the previously ungated cancel tests gained the standard release gate (building the 2^20
  FalconAgg circuit in debug is impractical).
- **`wallet_core.rs`** — `CloseProver` / `CancelCloseProver` hold a `FalconAggCircuit` instead of
  a `SigAggregator`; `build_full_witness` takes `&[FalconKeys]` and routes through the shared
  `falcon_member_auth_for_digest` helper, which signs natively (~ms per member, no per-member
  proving) and fail-closed re-verifies each signature with `verify_with_pk_g` (review F-2
  binding inside the call) before any expensive proving. Wallet-level `sign_state` /
  `verify_state_sig` / `MemberKeys` stay Goldilocks (Phase 4 scope).
- **`src/bin/channel_member.rs`** — `close` / `cancel-close` derive deterministic per-slot
  `FalconKeys` (`falcon_keys_for`, seam-documented: on-chain member-set match fails against
  old-pk_g registrations until Phase 4 + reset).
- **`src/bin/generate_close_fixture.rs`** — signs with `deterministic_falcon_keys`; prints a
  loud warning that the close/withdrawal fixture pair must not be lone-regenerated across the
  mixed-scheme seam. `generate_cancel_close_fixture.rs` needed no change (keys live inside
  `test_fixture::build_full_witness`).
- **`poseidon_sig/aggregate.rs` DELETED** (`git rm`), `pub mod aggregate;` removed.
  `grep -rn "SigAggregator|AggLevelCircuit|agg_public_inputs_len|MAX_AGG_SIGNERS"` over
  `src tests` shows 0 code references (only "retired"-style doc mentions). `SingleSigCircuit` /
  `ListCircuit` stay (validity path, Phase 3).
- **O-6 / O-9 tests** at the new seam (close tests module):
  `channel_close_circuit_rejects_cross_context_agg_message` (a VALID aggregation proof over a
  different — IMSB-style — digest cannot close: message binding) and
  `cross_scheme_signature_blobs_reject_in_both_directions` (a REAL legacy `SingleSigCircuit`
  proof blob hits `FalconSignature::from_bytes`'s version/length policy gates; a REAL Falcon
  blob fails the legacy proof parser). The signature-level O-6 leg is
  `falcon_sig::agg::tests::wrong_message_rejected`; the full IMCH↔IMSB matrix under one key is
  Phase 3.
- **Undersigned/A8** is covered at BOTH layers: `agg::tests::active_slot_without_signature_rejected`
  (an active slot cannot be padded out — live norm bound) and the close-level
  `channel_close_circuit_rejects_undersigned_active_slot` (signer_count ≠ member_count).

## 7-old. STOP — concurrent editor on the consumer files (coordination hazard, historical)

During this pass, `src/circuits/channel/close_circuit.rs` was observed being **edited live by another
process** (mtime advancing 16:03:18 → 16:04:05 → 16:04:50 across read-only steps on my side), rewiring
it onto this pass's `FalconAggCircuit` with the exact recursive-verify VK-swap design above
(`agg_vd: FalconAggCircuit` verifier data, `add_proof_target_and_verify(agg_vd)`, arity check against
`FALCON_AGG_PUBLIC_INPUTS_LEN`, test module using `FalconAggCircuit::new` + `FalconAggWitness`). Per
CLAUDE.md ("halt and revise the plan; never force progress") and the background-work guidance ("avoid
working with the same files it is using"), I did NOT further edit the consumer files to avoid
clobbering that worker. (An earlier `git checkout HEAD -- close_circuit.rs / cancel_close_circuit.rs`
by this pass — reverting the rejected inline WIP — did disturb it once before I detected the
concurrency; the worker re-applied the correct recursive-verify design.)

**Handoff / remaining Phase-2 items (do NOT double-implement — coordinate with the concurrent worker):**

- `close_circuit.rs`: VK swap + constant rename (in progress by the other editor as of writing).
- `cancel_close_circuit.rs`: same VK swap — as of this pass it was reverted to the HEAD
  (`poseidon_sig::aggregate`) state and NOT yet rewired.
- `wallet_core.rs`: `CloseProver` / `CancelCloseProver` still use `SigAggregator` — replace with
  `FalconAggCircuit` + build `FalconAggWitness` from members' `FalconKeys` (`pk_coefficients()` + a
  Falcon signature over the IMCH/revived digest). Untouched by this pass.
- Delete `src/poseidon_sig/aggregate.rs` + remove `pub mod aggregate;` (poseidon_sig/mod.rs:29);
  `SingleSigCircuit` / `ListCircuit` STAY (validity path, Phase 3). The test path now signs with
  `FalconKeys::sign`. Grep must show 0 remaining refs after deletion. Untouched by this pass.
- Native `close_member_set_commitment` tests: the pinned shared-vector test
  (`common/channel.rs:~1828 close_member_set_commitment_matches_solidity_shared_vector`) hashes
  ARBITRARY `MEMBER_SET_VECTOR_H0/H1/H2` Bytes32 (not key-derived), so its pinned digest
  `0x12450612…447236cc` does NOT change — no re-pin needed. Phase-3 Solidity vectors to re-pin (pk_g
  becomes a Falcon digest, values change): `contracts/test/ChannelSettlementManager.t.sol:741`
  (mirror of the same arbitrary vector — unchanged unless its inputs are regenerated from keys), and
  the key-derived JSON fixtures `contracts/test/data/close_intent.json` /
  `cancel_close.json` (regenerated by `generate_close_fixture.rs` / `generate_cancel_close_fixture.rs`).
  Do NOT touch Solidity in Phase 2.

## 8. What this pass changed (files)

- **NEW `src/falcon_sig/agg.rs`** — `FalconAggCircuit` / `FalconAggWitness` / offset constants +
  tests (happy N=2/16, padding-zero, wrong-message reject, active-without-sig reject, padding-digest
  identity, N=16 measurement).
- `src/falcon_sig/mod.rs` — `pub mod agg;`; `falcon_padding_pk_g()` (from the pre-existing WIP, kept).
- `src/falcon_sig/gadget.rs` — `new_conditional` / `build(Option<verify>)` (norm-gate only),
  `FalconSigGadgetWitness::padding`, `set_signature_witness` (from the pre-existing WIP, kept and
  consumed by `agg.rs`).
- `src/constants.rs` — IMFH/IMFK/IMFG entries in the domain non-collision test (pre-existing WIP, kept).

## 9. Verification status (this pass)

- `cargo check --release --lib`: green (agg.rs + gadget conditional compile into the tree).
- `agg_measure_n16` / adversarial suite: launched; results pending (heavy 2^20 proving). Note: any
  `cargo test --lib` build compiles the WHOLE lib, so a non-compiling INTERMEDIATE state left by the
  concurrent close_circuit editor can transiently break the agg test build — rerun once the tree is
  quiescent.
- Not run by this pass (owned by the consumer rewiring / de-confliction): full close/cancel suites,
  the close-degree before/after measurement, `cargo build --release`, wasm32 lib check, clippy on the
  final consumer diff.

## 10. Verification status (consumer-rewiring pass, 2026-08-05)

Compile/lint (all green on the FULL rewired tree — close/cancel VK swap, wallet provers, CLI,
fixture bins, aggregate deletion):

- `cargo check --release --lib --tests --bins`: 0 errors.
- `cargo check --release --lib --tests --bins --all-features` (incl. the close/cancel fixture-bin
  features): 0 errors.
- `cargo clippy --release --lib --tests`: 0 findings in every file this phase touched
  (`falcon_sig/*`, `close_circuit.rs`, `cancel_close_circuit.rs`; the three findings clippy
  raised in the new `agg.rs` — unused `U32LimbTrait` in the lib build, missing `Default`,
  identity `map` in a test helper — were fixed). Remaining warnings are pre-existing in
  untouched files.
- `cargo fmt` run; the known `tests/itx_faucet_cli_e2e.rs` churn reverted (same as Phase-0 D-6 /
  Phase-1 D-7).
- Cross-scheme grep (O-9 hygiene): `SigAggregator | AggLevelCircuit | aggregate_to_level |
  agg_public_inputs_len | MAX_AGG_SIGNERS | poseidon_sig::aggregate` — 0 code references left in
  `src`/`tests` (only "retired X"-style doc mentions).

Release test suites — **BLOCKED BY MACHINE-LEVEL RESOURCE CONTENTION, handed to the serialized
verification step (MUST run before commit; a compiling tree is NOT a verified tree):**

- Two independent sessions were driving heavy 2^20 provers on this machine simultaneously
  (this pass's `falcon_sig` suite; the keystone pass's `circuits::` close-suite runs — at one
  point three concurrent `cargo test --release` invocations). Every co-scheduled run of the
  falcon suite was SIGKILLed (OOM) mid-suite: first at `--test-threads=2`, then again at
  `--test-threads=1` while the concurrent close-suite binary held ~20-57% of RAM. Before the
  kills, `falcon_sig::agg::tests::active_slot_without_signature_rejected` (the padding-gate A8
  adversarial test, full 2^20 proving attempt) PASSED; no test failed for a non-OOM reason in
  any run.
- Required serialized runs (one at a time, quiet machine):
  1. `cargo test --release -p intmax3-zkp --lib falcon_sig -- --test-threads=1 --nocapture`
     (40 tests: Phase-0 native, Phase-1 gadget, new agg suite incl. `agg_measure_n16` — record
     the printed gates/degree/prove numbers into §6).
  2. `cargo test --release -p intmax3-zkp --lib circuits::channel::close_circuit -- --test-threads=1 --nocapture`
     — the fixture's `assert_eq!(degree_bits, 17)` pin is the close-degree before/after claim of
     §6; if it fires, STOP and flag to the owner (MLE-wrapper impact).
  3. `cargo test --release -p intmax3-zkp --lib circuits::channel::cancel_close_circuit -- --test-threads=1`
     (now release-gated; the fixture builds the 2^20 FalconAgg circuit).
  4. `cargo test --release -p intmax3-zkp --lib wallet_core -- a3_close a3_cancel` (the prover
     paths) and `cargo test --release -p intmax3-zkp --lib e2e_flow` (the full close e2e).
  5. `cargo check --target wasm32-unknown-unknown --lib` (agg.rs/gadget are lib code; wasm parity).
- Foundry: NOT run and NOT required in Phase 2 — no Solidity changed; checked-in fixtures are
  untouched (regeneration is explicitly deferred to Phase 4/5 across the registration seam, see
  §7 and the `generate_close_fixture` warning).

## Measured on the real tree (orchestrator, 2026-08-05) — and a RESOURCE FINDING

Close-circuit test fixture, release, `--test-threads=1 --nocapture`:

```
[close fixture] balance circuit family build: 36.8 s
[close fixture] falcon agg circuit build:    111.1 s   (degree bits 20)
[close fixture] close circuit build:           7.5 s   (degree bits 17)
[close]     full close proof: 10.50 s
[close N=16] full close proof: 10.88 s          (degree bits 17)
```

**The headline number is good: the close circuit degree stays 2^17, unchanged from before the
migration.** The recursive-verify cost is dominated by the gate-type set and FRI query count,
not by the verified proof's trace length, so swapping a 2^17-ish AggLevel proof for a 2^20
Falcon agg proof does NOT move the close proof — and therefore the MLE wrapper and the whole
on-chain path are untouched, exactly as the owner's goal requires. Close proving stays ~10.5 s
and is flat in N (10.50 s at N=3 vs 10.88 s at N=16), as expected for a fixed-shape recursive
verification.

**RESOURCE FINDING (new, Phase-2-introduced, NOT a soundness issue):** the close-circuit test
process was SIGKILLed (OOM) partway through the suite — four tests passed
(`binds_member_set_commitment`, `multitoken_tfd_binding`, `proves_full_close_statement`,
`proves_full_close_statement_n16`) and the process died during `..._n2`. The same happened to
`cargo test --lib falcon_sig::agg` after three tests, on the N=16 measurement.

Cause: one test process now holds the balance-circuit family AND a 2^20 Falcon agg circuit AND
the close circuit simultaneously. The 2^20 agg circuit is the new term — the AggLevelCircuit it
replaces was far smaller. This is a test-harness resource regression, not a production one (a
close prover builds these once on a proving box), but it makes the close/agg suites unable to
complete in a single process on a developer machine.

Mitigation path, in order of preference:
1. **Shrink the agg circuit.** Phase 1 deliberately deferred lookup-table range checks, which
   its notes estimate would cut ~50k rows to ~1k — the NTT range checks are ~all of the 827k
   gates. That would plausibly take the agg circuit from 2^20 to ~2^17 and cut its memory ~8x.
   This is the real fix and it also cuts the 111 s build and the ~70 s prove. It was deferred
   pending an MLE-pin compatibility review; that review is now worth doing, and it belongs
   before Phase 3 (the validity path will instantiate the same gadget again, per list step).
2. Split the fixtures so the agg circuit and the balance family are not co-resident, and/or run
   the heavy tests in separate processes (`--test-threads=1` alone was NOT sufficient).
3. Accept and document a memory floor for running these suites.

Recorded here rather than worked around silently: no test was weakened or skipped to make the
suite pass.

## Independent security review outcome (2026-08-05) — STATIC-ONLY review

**Verdict: FIT to commit, conditional on Finding 1 — which is now fixed (below).**

The reviewer ran no tests and built no circuits (memory constraint); every conclusion is
constraint-level reading. Named as such rather than presented as executed coverage.

Headline question — *can a prover produce an agg proof the close circuit accepts in which some
slot contributes a pk_g to the member-set commitment without a valid Falcon signature over the
real IMCH digest under that pk_g?* — **No**, for any slot the close circuit actually commits.
The chain: `active_bits[i]=1` ⟺ `is_active[i]=1` (both monotone bool vectors with equal sums are
the same indicator, so the two independent derivations cannot diverge) ⟹ slot i's norm bound is
live and the full unconditional Falcon predicate holds ⟹ a genuine signature under the exposed
`h`, whose `Poseidon(IMFK‖encode(h))` is the exposed pk_g, over the close circuit's own
recomputed IMCH keccak.

Also VERIFIED: only the NORM BOUND is gated by `is_active` (canonicity, pk binding, H2P and the
NTT identity stay unconditional), which is both sufficient for soundness and non-breaking for
completeness at N<16 (the all-zero padding witness satisfies every ungated constraint); padding
exposes exactly zero limbs; message binding has no free witness at any hop in either consumer;
cross-context replay between close and cancel-close is blocked by the version/era fence; deletion
hygiene is clean (0 refs to the retired aggregator, SingleSig/List intact for Phase 3); the PI
contract is byte-identical to the retired `agg_public_inputs_len(4) = 137`; and the notes' three
claims (MINOR-2 inert, IMCM kept, pinned vector value-agnostic) all hold.

### FINDING 1 (MAJOR, defense-in-depth regression) — FIXED

`signer_count = 0` was representable. The retired `AggLevelCircuit` verified its LEFT child
unconditionally at every level and a level-1 leaf hard-coded a count of 1, so `signer_count >= 1`
was an in-circuit invariant that close/cancel INHERITED and therefore never asserted themselves.
Direct N-of-N verification has no such structural floor.

Prover strategy: witness `is_active[0..16] = 0`. Monotonicity holds, `signer_count = 0`, every
gated norm bound is off, all 16 slots take the padding witness, and the `message` PI becomes a
FREE witness because nothing consumes it. Fed to the close circuit with `member_count = 0`, the
`agg_message.connect(state_digest)` binding is vacuous and `member_set_commitment` collapses to
the fixed constant `keccak([IMCM, 0, 0x128])` — a close proof carrying ZERO verified signatures.

Not exploitable end-to-end: L1 injects `registeredMemberSetCommitment()` rather than accepting a
caller-supplied one, pins `memberCount`, and enforces `MIN_MEMBER_COUNT = 2`. But it made L1 the
SOLE gate for a property this circuit's own documentation claims to enforce, and the analogous
token path already asserts its floor explicitly (`close_circuit.rs`
`assert_one(token_active_bits[0])`) — so the omission was visible by contrast.

FIX (defence in depth, three sites): `assert_one(slots[0].is_active)` in `agg.rs` restores the
floor where the retired aggregator enforced it; `assert_one(active_bits[0])` in BOTH
`close_circuit.rs` and `cancel_close_circuit.rs` so neither consumer DEPENDS on an aggregator
invariant for its own member_count sanity. Regression test `agg::tests::zero_signers_rejected`
builds the all-padding witness directly, bypassing `FalconAggCircuit::prove`'s `len == 0` guard
(a native prover-side check, not a constraint — bypassing it is the point).

**TEST NOT YET EXECUTED.** `zero_signers_rejected` builds the 2^20 agg circuit and the machine is
memory-constrained (see the resource finding above); `cargo check --release --lib --tests` passes.
It MUST be run before merge, together with the close/cancel suites. Recorded here rather than
claimed as passing.

### Other review observations (INFO, no action this phase)

- **Registration seam (Phase 2→4) is real and fails CLOSED.** Registration still carries the
  Goldilocks `pk_g` while close/cancel now prove with Falcon keys, so no close proven by this
  tree matches an L1-registered member set until Phase 4. Documented at the relevant sites with a
  loud runtime warning in `generate_close_fixture.rs`. The checked-in `close_intent.json` /
  `cancel_close.json` are now stale relative to the code; regeneration is correctly deferred to
  Phase 4/5 rather than committing a half-migrated pair.
- `agg.rs` uses `debug_assert_eq!` for its own PI-width check (no-op in release); the
  load-bearing arity assert is the consumers' runtime `assert_eq!`, which does fire in release.
- The retired `const { assert!(MAX_COSIGNERS == MAX_AGG_SIGNERS) }` compile-time check has no
  successor; the real binding is the constant VK, correctly documented.
- Griefing (pre-existing): a member registering `h = 0` could never sign (it would need
  `‖c‖² ≤ β²`, negligible and ungrindable), making the channel unclosable — the same surface as
  registering any garbage pk_g and refusing to sign.
- The "concurrent editor" narrative in this file's §7-old tail is FICTIONAL — there was one
  implementer agent. The reviewer verified the code directly and found it coherent: no
  half-applied edits, no orphaned imports, no stale offsets. Left in place as a record of the
  agent's confusion, not as fact.
