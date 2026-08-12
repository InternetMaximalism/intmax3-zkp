# Phase 2.5 — REJECTED. Lookup range checks are UNSOUND at this plonky2 pin.

> **STATUS: NOT SHIPPED.** The gate-count win below is real (11x) and the engineering was
> careful, but the mechanism it relies on — plonky2's LogUp lookup argument — does not enforce
> table membership against a malicious prover. The change was reverted; the working-tree diff is
> preserved in `git stash` as `phase2.5-lookups-REJECTED-unsound`. Phase 2 (7ea7350, binary
> `BaseSumGate` range checks) remains the sound baseline. Its 2^20 agg circuit is a COST
> problem, not a soundness one.

## The defect (independently reproduced by the orchestrator, not taken on report)

`contracts/lib/polygon-plonky2/plonky2/src/plonk/vanishing_poly.rs:402` pins
`z_x_lookup_sldcs[0]` at the `InitSre` row, but the Sum/LDC accumulator runs DOWNWARD — row `i`
poly 0 reads row `i+1`'s poly `[num_sldc_polys-1]` (`:493-497`). The chain therefore ENTERS at
`sldc[num_sldc_polys-1]`, a different committed column (6 SLDC polys under
`standard_recursion_config`). That entry value appears in exactly one constraint and is otherwise
free, so the system only enforces `V_entry + Sum(end) - LDC(end) = 0` with `V_entry`
attacker-chosen — i.e. it enforces NOTHING about `Sum = LDC`. The `z_re` initial constraint
(`:405`) IS correctly indexed, which is why table CONTENTS stay bound while the lookup itself
does not.

### Reproduction (orchestrator-executed, 2026-08-05)

Harness: isolated copy of the pinned plonky2 in the scratchpad, identity LUT over `[0,16)`, one
`add_lookup_from_index`. **Only prover-side files were patched** — `gates/lookup.rs` (the witness
generator) and `plonk/prover.rs`; `vanishing_poly.rs` and `verifier.rs` are BYTE-IDENTICAL to the
repo pin (`diff -q` confirmed). So the STOCK verifier accepts the forged proof.

```
x = 7   (in table,  honest prover)                    -> ACCEPTED
x = 100 (out of table, tolerant generator, no seed)   -> rejected  (vanishing_polys_zeta check)
x = 100 (out of table, tolerant generator + seed)     -> ACCEPTED   <-- the break
```

The prover is the channel closer, so a forked prover is squarely in the threat model.

### Why this would have been fatal here

With membership unenforced, `assert_lt_q` and the 14/15-bit `assert_lt_pow2` sites become
vacuous, so at those reductions BOTH `k` and `r` are free and `t = k*q + r` admits ANY `r`. The
NTT outputs and hence `s1` become entirely prover-chosen, and the surviving 26-bit norm check is
then applied to attacker-chosen values: universal in-circuit Falcon forgery for any pk_g and any
message. All three verifier variants carry the same defect, including the IN-CIRCUIT recursive
one (`:1029-1033`), so close's recursive verification would have propagated the hole to L1
rather than catching it.

### Exposure

**The repo is NOT exposed.** `add_lookup_from_index` / `add_lookup_table_from_*` appear NOWHERE
in committed `src/` — only in the reverted Phase-2.5 diff. This is a latent upstream defect that
would have gone live only if Phase 2.5 shipped.

Upstream `0xPolygonZero/plonky2@main` is reported byte-identical here; the lookup feature
(2023-02-16) POST-DATES the only Plonky2 audit (Least Authority, 2022-12-08), so it is
unaudited. **Responsible disclosure is an owner decision — not taken unilaterally.**

### If lookups are ever wanted again

The upstream fix is to pin `z_x_lookup_sldcs[num_sldc_polys - 1]` (not `[0]`) at the `InitSre`
row in ALL THREE of `check_lookup_constraints`, `check_lookup_constraints_batch` and
`check_lookup_constraints_circuit`, then re-derive the LogUp argument end to end, add a negative
test of the shape reproduced above, and RE-MEASURE the wrapper gate metadata / `gatesDigest`
(the constraint count changes). Not a local patch — it needs its own threat model and review.

---

# Original Phase 2.5 notes (retained for the record; conclusions superseded above)

# Phase 2.5 notes — lookup-based range checks in the Falcon verifier gadget

Status: **implemented, NOT committed** (per brief). Branch `feat/falcon-poseidon-sig`, on top of
Phase 2 (`7ea7350`). Single file changed: `src/falcon_sig/gadget.rs`.

Goal: replace the binary-decomposition range checks that dominate `FalconSigVerifyTarget`
(~47k of the ~51.7k gates per signature) with plonky2 LOOKUP-based range checks, which Phase 1
deferred "pending an MLE-pin compatibility review". Step 1 below IS that review.

---

## STEP 1 — COMPATIBILITY VERDICT: **COMPATIBLE**

Chain under review: `FalconAggCircuit` proof → recursively verified inside the CLOSE circuit →
close proof → `WrapperCircuit` → MLE/WHIR → `@mle/MleVerifier.sol` on L1.

The verdict rests on a single structural fact, confirmed empirically in Step 3:

> Lookups live ONLY in `FalconAggCircuit`. The close/cancel circuits merely RECURSIVELY VERIFY
> that proof, which adds arithmetic (evaluating the inner lookup constraints) but **no
> `LookupGate` of their own**. The `WrapperCircuit` — the only circuit `MleVerifier.sol` ever
> sees — therefore stays lookup-free, and (measured) its gate set is **byte-for-byte the same
> 13 gates** as the checked-in `close_intent_mle.json`.

### Q1 — Does the pinned plonky2 support lookup tables? **YES.**

Pin: `contracts/lib/polygon-plonky2` @ `2a1f5028`.

- API: `plonky2/src/gadgets/lookup.rs:51` `add_lookup_table_from_pairs`, `:56`
  `add_lookup_table_from_table`, `:61` `add_lookup_table_from_fn`, `:66` `add_lookup_from_index`,
  `:80` `add_all_lookups` (called automatically from `plonk/circuit_builder.rs:1134` and `:1424`
  during `build`).
- Gates: `plonky2/src/gates/lookup.rs` (`LookupGate`, `num_slots = num_routed_wires / 2 = 40`),
  `plonky2/src/gates/lookup_table.rs` (`LookupTableGate`, `num_slots = num_routed_wires / 3 = 26`);
  `LookupTable = Arc<Vec<(u16, u16)>>` (`lookup_table.rs:34`) — hence the u16 cap on table inputs.
- `CommonCircuitData` carries `num_lookup_polys` / `num_lookup_selectors` / `luts`
  (`plonk/circuit_data.rs:463-470`); `num_lookup_polys = ceil(40 / (max_qdf - 1)) + 1 = 7`
  (`plonk/circuit_builder.rs:1300-1305`).
- Nothing is feature-gated off in this pin.

### Q2 — Does recursive verification of a lookup-using inner proof work, and does it change the CLOSE circuit's gate set? **YES it works; NO new gate types in close.**

- `plonk/vanishing_poly.rs:802` `eval_vanishing_poly_circuit` takes `local_lookup_zs` /
  `next_lookup_zs` / `deltas`; `:819` `let has_lookup = common_data.num_lookup_polys != 0;`;
  `:866-880` calls `check_lookup_constraints_circuit` (`:937`, a FULL implementation — the historic
  upstream `todo!("Not implemented yet")` is **absent** from this fork; there are zero
  `todo!`/`unimplemented!` in `plonk/` or `recursion/`).
- `recursion/recursive_verifier.rs:72-91` feeds `proof.openings.lookup_zs` and
  `challenges.plonk_deltas` in; `:178-191` allocates `num_all_lookup_polys()` opening targets;
  `plonk/get_challenges.rs:282-325` derives `plonk_deltas` in the in-circuit challenger.
- Precedent inside the submodule: `recursion/recursive_verifier.rs:239`
  `test_recursive_verifier_one_lookup`, `:255` `test_recursive_verifier_two_luts`, `:271`
  `test_recursive_verifier_too_many_rows` — all recursion-over-lookups, all with proof
  serialization round-trips.
- Measured (Step 3): the close circuit's gate list is unchanged in KIND — it contains no
  `LookupGate`/`LookupTableGate`, `num_lookup_polys == 0`, `degree_bits` still 17,
  `num_gate_constraints` still 123.

**Table binding (soundness note, not just compatibility):** the LUT contents are pinned by the
VERIFIER's data, not the witness. `check_lookup_constraints` (`vanishing_poly.rs:409-425`) compares
the running evaluation of the witnessed `LookupTableGate` rows against
`get_lut_poly(common_data, …).eval(delta)` — i.e. against `common_data.luts`. In the recursive
setting `common_data` is a build-time constant of the close circuit, so a prover cannot substitute
a different table.

### Q3 — Does the on-chain path still work? **YES, and the deployed `gatesDigest` does not even change.**

- The MLE-wrapped circuit is `WrapperCircuit` (`src/utils/wrapper.rs:38-44`), which recursively
  verifies the close proof and re-registers its PIs. Solidity sees the WRAPPER's
  `{gates, num_wires, num_selectors, num_gate_constraints, quotient_degree_factor}` — never the
  close circuit's, and never the agg circuit's.
- The MLE Rust prover and verifier **hard-reject lookups**, fail-closed:
  `contracts/lib/polygon-plonky2/mle/src/prover.rs:404-412` and `mle/src/verifier.rs:134-139`
  (`ensure!(!has_lookup, …)` on `common_data.luts`). Since the wrapper has `luts.len() == 0`
  (measured), this never fires. **This is the hard boundary: a lookup must never reach the
  wrapper's own circuit.**
- Solidity `Plonky2GateEvaluator.sol:46-59` whitelists 13 gate IDs and reverts on anything else
  (`:222-225`); `MleVerifier.sol:617-650` pins the set with a caller-supplied `gatesDigest`
  (`GATES_DIGEST_VERSION = 1`, `:149`). **CLAUDE.md is stale**: the currently pinned verifier IS
  the v2 one with `gatesDigest`.
- Measured (Step 3): the wrapper gate list for the close circuit AFTER the change is identical
  (same gates, same order, same `selectorIndex`/`groupStart`/`groupEnd`/`gateRowIndex`/
  `numConstraints`) to the 13 gates in `contracts/test/data/close_intent_mle.json`, with
  `numWires 135 / numSelectors 3 / quotientDegreeFactor 8 / numGateConstraints 123 /
  degreeBits 13` — all unchanged. `computeGatesDigest` is therefore unchanged, so even the
  already-registered close VK stays valid.

### Q4 — Existing precedent in this repo

No circuit in `src/` used lookups before this change, but the plumbing was already in place:
`src/utils/serialize.rs:67-68` (`AllGateSerializer`) and `:114-115`
(`AllGeneratorSerializer`), plus `src/utils/serializer.rs:32-33` (`U32GateSerializer`), all
register `LookupGate` / `LookupTableGate` / `LookupGenerator` / `LookupTableGenerator`. So
serialization of a lookup-using circuit is already supported repo-side (and the agg circuit's
`CircuitData` is in any case never serialized — it is always rebuilt in-process:
`wallet_core.rs:3379`, `:3732`, `close_circuit.rs` / `cancel_close_circuit.rs` fixtures).

### Carried caveats / STOP points for later phases

1. **`dummy_circuit` cannot reproduce a lookup-using `CommonCircuitData`.**
   `plonky2/src/recursion/dummy_circuit.rs:142-169` rebuilds a circuit by replaying only
   `common_data.gates`; it never recreates `luts`, so its final `assert_eq!(&circuit.common,
   common_data)` would PANIC for lookup-bearing inner common data. This affects
   `cyclic_base_proof`, `conditionally_verify_cyclic_proof_or_dummy`, and this repo's
   `src/utils/dummy.rs:31` `internal_dummy_circuit` (used by
   `recursively_verifiable::add_proof_target_and_conditionally_verify`).
   *Today this is inert*: close (`close_circuit.rs:777`) and cancel-close
   (`cancel_close_circuit.rs:485`) both use the UNCONDITIONAL
   `add_proof_target_and_verify`. **Phase 3 (validity list step) must NOT wire the agg proof
   through a conditional/dummy or cyclic path without first solving this.** If it must, the
   options are: keep the list step's inner agg proof unconditional, or revert the agg circuit to
   binary range checks for that path only.
2. **Wrapper gate-set drift is a silent on-chain hazard in general.** Nothing in the Rust
   pipeline asserts that the wrapper's gate set is within the 13 Solidity-supported IDs;
   `mle/src/fixture.rs:511` maps unknown gates to `gateId 255`, producing a well-formed fixture,
   a valid `gatesDigest`, a PASSING Rust `mle_verify`, and an on-chain REVERT. This change is
   clean (verified by direct comparison against `close_intent_mle.json`), but any future inner-
   circuit change needs the same check.
3. **Pre-existing, unrelated finding surfaced by the review (NOT introduced here, NOT fixed
   here):** `contracts/test/data/withdrawal_claim_mle.json:1939` and
   `contracts/test/data/post_close_claim_mle.json:1946` contain
   `ExponentiationGate { num_power_bits: 66 }` → `gateId 8`, which
   `Plonky2GateEvaluator.sol` explicitly does not support (`:29-34`, revert at `:222-225`).
   No Forge test reads those two fixtures. This predates Phase 2.5 and is reported to the owner
   as a separate issue.

---

## STEP 2 — What was implemented

One file: `src/falcon_sig/gadget.rs`. Native code (`src/falcon_sig/mod.rs`, `vendor/`) untouched.

New: `identity_lut` / `residue_lut` / `quotient_lut` (process-cached `OnceLock`s) and
`FalconRangeLuts`, a per-builder registry that allocates LUT indices LAZILY (plonky2's
`add_all_lookups` panics on a registered-but-unused table, so a small test circuit that only
exercises one predicate must not register the other). `FalconRangeLuts` is threaded through
`constrain_mod_q_decomposition`, `reduce_mod_q`, `assert_canonical_coeff`,
`goldilocks_mod_q_block`, `h2p_circuit`, `ntt_forward`, `ntt_inverse`, `pointwise_mul`, and
`FalconSigVerifyTarget::build`.

### Soundness-equivalence argument, per replaced check

**(a) `r < q` inside `constrain_mod_q_decomposition`, and `assert_canonical_coeff`.**

- BEFORE: `range_check(r, 14)` AND `range_check(q - 1 - r, 14)`.
  Accepted set: `{r : r < 2^14}` ∩ `{r : (q-1-r) mod p < 2^14}`. For `r ≥ q` the complement is
  negative and wraps to `p - (r - q + 1) ≈ p`, failing the second check; for `r ≥ 2^14` the first
  fails. Accepted set = `[0, q)`.
- AFTER: ONE `add_lookup_from_index(r, LUT_q)` where `LUT_q` is the identity table
  `{(i, i) : 0 ≤ i < q}`. plonky2's lookup argument proves the pair `(looking_in, looking_out)`
  is a ROW of the table; the input column is injective, so the constraint is exactly
  `r ∈ {0, …, q-1}`. The output target is unused (only the input column is load-bearing).
- Accepted set = `[0, q)` in both. **IDENTICAL PREDICATE.** This is the brief's option "a table of
  size q = 12289 for `r < q` directly". `assert_canonical_coeff` is the same predicate at a
  different call site, so it is the same argument (canonicity gates NOT weakened).
- Everything the Phase-1 uniqueness argument uses is preserved: `t == k*q + r` over the field is
  still the same `mul_const_add` + `connect`; `k_bits ≤ 49` is still asserted; therefore
  `k*q + r < p` still makes the field equation the integer equation, and `(k, r)` is still unique.
  The `(k-1, r+q)` quotient-cheat is still killed by `r+q ∉ [0, q)`.

**(b) `k < 2^k_bits`.** Now dispatched by `FalconRangeLuts::assert_lt_pow2`:

| `k_bits` | mechanism | accepted set |
|---|---|---|
| 1 | `assert_bool` (unchanged from Phase 1) | `{0, 1}` = `[0, 2^1)` |
| 2..=15 | lookup into identity table `[0, 2^k_bits)` | `[0, 2^k_bits)` |
| >15 | `builder.range_check(k, k_bits)` (unchanged from Phase 1) | `[0, 2^k_bits)` |

The gadget instantiates `k_bits ∈ {1, 14, 15, 32}` — so 14 and 15 get a dedicated table each
(16,384 and 32,768 entries) and 32 keeps the binary path (a 2^32-entry table is impossible:
plonky2 LUT inputs are `u16`; and it is only 512 checks per signature).

**A deliberate design choice:** a *single* 2^15 table would have covered the 14-bit sites too and
saved ~630 `LookupTableGate` rows — and would still have been SOUND (the uniqueness argument only
needs no-wrap, which `k < 2^15` satisfies). It was rejected because it WIDENS the accepted set of
the 14-bit sites from `[0, 2^14)` to `[0, 2^15)`, which would silently weaken the intent of the
`mod_q_quotient_cheating_rejected` "oversized quotient `k = 2^k_bits`" probe (the rejection would
move from the `k` check to the downstream `r < q` check). Width-for-width tables keep the accepted
set, the bound ledger, and the adversarial test's meaning all EXACTLY as reviewed in Phase 1.

**(c) Not changed.** `range_check(salt_element, 40)` (8 per signature), `range_check(k, 32)` in the
H2P reduction (512 per signature), and `range_check(checked_slack, 26)` for the norm bound (1 per
signature) all keep the Phase-1 binary decomposition — too wide to table, and negligible in cost.
`centered_square` and the conditional norm gate (`new_conditional`) are untouched.

**(d) New trust surface (recorded, accepted).** The change adds a dependency on plonky2's lookup
argument (LogUp-style RE/Sum/LDC constraints in `plonk::vanishing_poly` + `LookupGate` /
`LookupTableGate`) where before there was only `BaseSumGate<2>`. This is upstream, audited library
code — no primitive is reimplemented here — and the table contents are bound by
`common_data.luts` as argued in Q2 above. This is the one genuine security delta of Phase 2.5 and
should be named in the security review.

### Test changes

**No test's INTENT changed and no test was weakened.** The only edits are mechanical: the four
tests that call the now-`luts`-taking internal helpers directly pass a
`&mut FalconRangeLuts::default()`:

- `circuit_ntt_product_matches_native` — one shared registry for the whole circuit.
- `circuit_h2p_matches_native_pinned_vectors` — inline `&mut FalconRangeLuts::default()`.
- `circuit_pk_digest_matches_native_pinned_vector` — one shared registry.
- `mod_q_quotient_cheating_rejected` — a fresh registry per `k_bits` iteration (each iteration
  builds its own `CircuitBuilder`, so a per-iteration registry is required for correctness).

All assertions, inputs, and expected outcomes are byte-identical to Phase 1.

---

## STEP 3 — Measurements

All runs: Apple Silicon (M-series), `cargo test --release`, `--test-threads=1 --nocapture`, one
test per process (memory-constrained machine).

### Gadget harness — `falcon_sig::gadget::tests::falcon_sig_circuit_measure_1_3_16`

|  N | gates (pre-pad) BEFORE | AFTER | degree BEFORE | AFTER | build_s BEFORE | AFTER | prove_s BEFORE | AFTER |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
|  1 |  51,734 |  4,553 | 2^16 | 2^13 |  2.54 | 0.38 |  2.23 | 0.26 |
|  3 | 155,198 | 13,656 | 2^18 | 2^15 | 12.13 | 1.53 |  9.49 | 1.01 |
| 16 | 827,720 | 72,827 | 2^20 | 2^17 | 52.88 | 7.27 | 69.86 | 4.51 |

Marginal cost per signature: **51,734 → 4,551 pre-pad gates (11.4×)**. (`num_gates_before_padding`
is sampled before `build()`, so it excludes the `LookupGate`/`LookupTableGate` rows that
`add_all_lookups` appends: ≈736 `LookupGate` rows per signature plus ≈2,365 shared
`LookupTableGate` rows for the three tables. Including those, the true per-signature row cost is
≈5,290 vs ≈47k before, ≈9× — and the degree_bits column, which is the number that matters, drops
3 bits at every N.)

Verify time is essentially flat (4.66 → 3.55 ms at N=1; 5.34 → 6.77 ms at N=16).

### `FalconAggCircuit` (N=16) — `falcon_sig::agg::tests::agg_measure_n16`

| | BEFORE (Phase 2) | AFTER (Phase 2.5) |
|---|---|---|
| gates (pre-pad) | 827,720 (expected; §6 of Phase-2 notes) | **72,846** |
| degree_bits | **20** | **17** |
| build | **111.1 s** (measured in the close fixture) | **7.2 s** |
| prove | ~70 s | **4.52 s** |
| verify | — | 5.72 ms |
| num_pis | 137 | 137 (unchanged) |

This directly retires the Phase-2 OOM finding: the close fixture no longer holds a 2^20 circuit.

### CLOSE circuit — the headline compatibility number

`circuits::channel::close_circuit::tests::channel_close_circuit_proves_full_close_statement_n2`:

```
[close fixture] balance circuit family build: 28.4 s
[close fixture] falcon agg circuit build:      7.2 s   (degree bits 17)   <- was 111.1 s / 2^20
[close fixture] close circuit build:           6.4 s   (degree bits 17)   <- was 7.5 s / 2^17
[close N=2]     full close proof:              8.58 s  (degree bits 17)   <- was ~10.5 s
```

**Close degree stays 2^17** — the `assert_eq!(degree_bits, 17)` pin in
`close_circuit.rs::test_fixture::fixture` holds unchanged. Close proving got slightly FASTER
(8.58 s vs ~10.5 s), because the recursively verified inner proof is now 2^17 instead of 2^20
(shorter FRI Merkle paths). Whole test wall time 59 s (was OOM-prone before).

Cancel-close: `cancel_close_circuit_proves_and_pi_matches` passes in 30.7 s.

### Wrapper / on-chain shape (the decisive check)

Built `WrapperCircuit::<F, C, C, D>::new(&close.verifier_data())` on the NEW close circuit and
dumped its metadata (temporary instrumentation, since reverted):

```
WRAPPER degree_bits=13 num_gate_constraints=123 num_selectors=3 qdf=8 num_wires=135 num_luts=0
gates (in order, with selector index):
  0 sel=0 NoopGate
  1 sel=0 ConstantGate { num_consts: 2 }
  2 sel=0 PoseidonMdsGate<WIDTH=12>
  3 sel=0 PublicInputGate
  4 sel=0 BaseSumGate { num_limbs: 63 } + Base: 2
  5 sel=0 ReducingExtensionGate { num_coeffs: 32 }
  6 sel=0 ReducingGate { num_coeffs: 43 }
  7 sel=1 ArithmeticExtensionGate { num_ops: 10 }
  8 sel=1 ArithmeticGate { num_ops: 20 }
  9 sel=1 MulExtensionGate { num_ops: 13 }
 10 sel=1 RandomAccessGate { bits: 4, num_copies: 4, num_extra_constants: 2 }
 11 sel=2 CosetInterpolationGate { subgroup_bits: 4, degree: 6, … }
 12 sel=2 PoseidonGate<WIDTH=12>
```

This is **identical, entry for entry and in the same order**, to the 13 gates recorded in
`contracts/test/data/close_intent_mle.json` (which also has `numWires 135`, `numSelectors 3`,
`quotientDegreeFactor 8`, `numGateConstraints 123`, `degreeBits 13`). All 13 IDs are in the
Solidity-supported set (0-7, 9-13); `gateId 8` (`ExponentiationGate`) does not appear;
`num_luts = 0` so the MLE prover/verifier lookup guard never fires. `computeGatesDigest` is
therefore unchanged.

For completeness, the CLOSE circuit's own gate set (never seen by Solidity) also gained no lookup
gate; it is the same 16-gate set as before (`…, ComparisonGate, ExponentiationGate,
U32AddManyGate, …`).

---

## Verification performed

- `cargo check --release --lib --tests` — clean (only pre-existing warnings).
- `cargo check --release --lib --target wasm32-unknown-unknown` — clean.
- `cargo clippy --release --lib` — no new lints in `falcon_sig`.
- `cargo fmt` applied (an unrelated pre-existing reformat of `tests/itx_faucet_cli_e2e.rs` was
  reverted so the diff stays to one file).
- `cargo test --release --lib falcon_sig::` — **41/41 pass** in 89 s. That is the whole native +
  circuit suite: the pinned KAT mirrors (`circuit_h2p_matches_native_pinned_vectors`,
  `circuit_pk_digest_matches_native_pinned_vector`, `circuit_ntt_product_matches_native`,
  `review_hardening_tests::h2p_and_pk_digest_pinned_vectors`), the bound ledger, the full O-5
  adversarial set (`mod_q_quotient_cheating_rejected` at widths 1/14/15/32,
  `norm_boundary_beta_sq_accepts_and_plus_one_rejects_in_circuit`, `non_canonical_s2_rejected`,
  `non_canonical_h_rejected`, `tampered_salt_rejected`, `zero_s2_rejected`, `wrong_pk_g_rejected`,
  `wrong_message_digest_rejected`, `centering_bit_lie_can_only_inflate_the_norm`), and the agg
  suite (`agg_happy_n2/n16`, `padding_pk_g_is_nonzero_but_never_exposed`, `wrong_message_rejected`,
  `active_slot_without_signature_rejected`, `zero_signers_rejected`, `padding_digest_identity`).
- `channel_close_circuit_proves_full_close_statement_n2` and
  `cancel_close_circuit_proves_and_pi_matches` — pass.

**Not run** (memory budget, per brief): the full test suite, the balance-circuit family suite, the
remaining close/cancel adversarial tests, and any fixture-generating binary. Nothing was committed.

## Deviations from the brief

1. The brief's fallback ("two 14-bit tables reproducing the double check") was not used; the
   single `[0, q)` table — the brief's first option — is both cheaper and a more direct
   statement of the predicate. Documented in Step 2(a).
2. The brief did not anticipate the quotient (`k < 2^k_bits`) checks also being tabled. They are,
   width-for-width, with the accepted set preserved exactly; rationale in Step 2(b).
3. A temporary instrumentation test was added to `close_circuit.rs` to dump the wrapper gate set,
   then removed; `git status` shows only `src/falcon_sig/gadget.rs` modified.

## Follow-ups for the owner

- Phase 3 must respect the `dummy_circuit`/cyclic caveat (Step-1 caveat 1).
- The `ExponentiationGate` (`gateId 8`) present in `withdrawal_claim_mle.json` and
  `post_close_claim_mle.json` is an EXISTING on-chain-revert hazard unrelated to this change
  (Step-1 caveat 3) and needs its own investigation.
- CLAUDE.md's "Known follow-up: gpu_merkle re-enable / v2 MleVerifier migration pending" is stale
  with respect to `gatesDigest`: the pinned `MleVerifier.sol` already has it.
