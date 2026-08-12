# falcon-sig Phase 2.6 — restore the binary-tree aggregator (memory fix)

Branch `feat/falcon-poseidon-sig`, on top of `a5efa10`. **Not committed.**

## 0. Why

Phase 2 replaced the retired `poseidon_sig::aggregate` binary tree with a FLAT `FalconAggCircuit`
that verified all `MAX_COSIGNERS = 16` Falcon signatures in ONE circuit. Falcon-512/Poseidon is
~51.7k gates per signature, so the flat circuit landed at degree **2^20** and needed **22.3 GB peak
RSS** to build + prove (measured with `/usr/bin/time -l`). That is the whole reason the close /
cancel-close suites OOM'd on a 36 GB machine.

Plonky2 memory is essentially linear in circuit DEGREE (every polynomial is stored at 8x its degree
— LDE blowup — across ~220 polynomials). So the fix is structural, not micro-optimisation: split the
16 signatures across 16 SMALL leaf circuits and recombine them with 4 SMALL recursion levels, and
prove one circuit at a time.

## 1. MEASUREMENT (the deliverable)

Apple Silicon (M-series), 36 GB, release build, `standard_recursion_config`, 2026-08-05.
Peak RSS is `/usr/bin/time -l` "maximum resident set size" (bytes), each row from a run of exactly
one test in a fresh process.

### 1.1 Circuits

| circuit                 | gates (pre-pad) | degree | num_pis | build   | prove   | peak RSS |
|-------------------------|----------------:|-------:|--------:|--------:|--------:|---------:|
| leaf, 1 sig/leaf        |          51,735 | 2^16   |      17 |  2.15 s |  1.83 s | **3.29 GB** |
| leaf, 2 sigs/leaf (alt) |         103,468 | 2^17   |      25 |  4.52 s |  3.80 s | **6.08 GB** |
| level 1 (2 slots)       |           9,204 | 2^14   |      25 |  7.01 s | ~0.54 s | — |
| level 2 (4 slots)       |           8,687 | 2^14   |      41 |  1.99 s | ~0.54 s | — |
| level 3 (8 slots)       |           8,691 | 2^14   |      73 |  2.02 s | ~0.54 s | — |
| level 4 (16 slots, TOP) |           8,701 | 2^14   |     137 |  1.98 s | ~0.54 s | — |

(Level-1's longer build is the one-off `DummyProof::new` over the 2^16 leaf common data. Level prove
times are the residual of the end-to-end run divided over the 15 level proofs — individually they are
too small to measure meaningfully.)

### 1.2 End-to-end 16-signature aggregation (the headline)

| design                       | max degree | build (all circuits) | prove (16 sigs) | **peak RSS** |
|------------------------------|-----------:|---------------------:|----------------:|-------------:|
| Phase 2 FLAT (previous)      | 2^20       | ~111 s               | ~70 s           | **22.3 GB**  |
| Phase 2.6 TREE (this)        | 2^16       | ~15.4 s              | **36.9 s**      | **4.99 GB**  |

**4.5x less memory, ~1.9x faster proving, ~7x faster circuit build.** Top-proof verify 3.0 ms.
The full `falcon_sig::agg` test suite (15 tests, single process, `--test-threads=1`, includes the
shared tree AND the two extra measurement circuits alive simultaneously) peaks at 7.57 GB / 177 s.

### 1.3 Close circuit (the constraint that must not move)

| test (fresh process)                              | close degree | close prove | peak RSS |
|---------------------------------------------------|-------------:|------------:|---------:|
| `channel_close_circuit_proves_full_close_statement_n2`  | **2^17** | 8.04 s | 10.30 GB |
| `channel_close_circuit_proves_full_close_statement_n16` | **2^17** | 8.46 s | 10.24 GB |

Close degree is **unchanged at 2^17** — the fixture's `assert_eq!(degree_bits, 17)` pin passes.
Close proving got FASTER (8.0–8.5 s vs the 10.88 s Phase 2 measured) because the agg proof it
recursively verifies is now a 2^14 proof instead of a 2^20 one (shallower FRI Merkle paths). Peak RSS
of those runs is dominated by the balance circuit family, not by aggregation. `channel_close_circuit_*
_n16` previously OOM'd; it now completes.

`cancel_close_circuit_proves_and_pi_matches` (no balance family): 33 s, 5.38 GB.

Full suites (single process, `--test-threads=1`):

| suite                                    | result       | wall  | peak RSS |
|------------------------------------------|--------------|------:|---------:|
| `circuits::channel::close_circuit`        | **15/15 pass** | 321 s | 10.91 GB |
| `circuits::channel::cancel_close_circuit` | **7/7 pass**   | 111 s |  5.98 GB |

### 1.4 1 sig/leaf vs 2 sigs/leaf — recommendation: **keep 1 sig/leaf**

Two signatures per leaf would drop one tree level (leaf becomes the "level 1" layout, tree becomes
leaf2 → level2 → level3 → level4), saving 8 of the 15 level proofs ≈ 4.3 s (~12% of end-to-end).
It costs:

- leaf degree 2^16 → **2^17**, and peak RSS 3.29 GB → **6.08 GB** (+85%) — memory is the whole point
  of this phase, and the leaf is the memory-dominant circuit;
- prove time per signature is NOT better (3.80 s for two vs 2 × 1.83 = 3.66 s for two);
- the leaf loses its structural simplicity: slot 1 must be a `new_conditional` gadget with its own
  presence flag, gated pk_g exposure and `count = 1 + is_second` — i.e. it re-imports the padding
  logic that the level circuits already implement and that has to be re-argued at a second site.

Verdict: 1 sig/leaf. The 2-sig leaf is retained ONLY as a measurement test
(`falcon_sig::agg::tests::leaf_measure_2sig`) so the number is reproducible.

## 2. What was mirrored from the retired design

Source of truth: `git show e0dec8b:src/poseidon_sig/aggregate.rs`. Mirrored essentially verbatim
into `src/falcon_sig/agg.rs`:

- binary tree, a node's exposed signer list = `left.list || right.list`;
- **LEFT child verified UNCONDITIONALLY** (`add_proof_target_and_verify`);
- **RIGHT child via `add_proof_target_and_conditionally_verify`** with an
  `add_virtual_bool_target_safe` flag `is_right_present`; when absent the prover supplies
  `DummyProof::new(&child_vd.common)`;
- every read of the right child gated: `pk_slot = is_right_present * right.pk_limb`,
  `signer_count = left.count + is_right_present * right.count`,
  `is_right_present * (left.m_limb - right.m_limb) == 0`;
- LEFT-PACKING rule `is_right_present ⟹ count_l == 2^{level-1}` (the adversarial-review fix in the
  retired file — kept, verbatim reasoning);
- `add_const_gate` at the end of every circuit so the next level's dummy-circuit reconstruction
  matches the child's common data exactly;
- prover-side driver `aggregate` / `aggregate_to_level` (the lift-to-fixed-level trick that lets a
  consumer bake a single constant VK) and `top_level_for`;
- the module's SECURITY commentary, re-argued for Falcon provenance.

## 3. What differs from the retired design (deviations)

- **D-1 (simplification). Uniform leaf layout.** The retired leaf (`SingleSigCircuit`) exposed
  `[pk(8), m(8)]`, which forced a `level == 1` special case in `child_pis`. The Falcon leaf exposes
  the canonical layout at level 0: `[message(8), signer_count = 1, pk_g(8)]` (17 PIs =
  `falcon_agg_public_inputs_len(0)`). Every level now parses its children identically. This is the
  layout the Phase 2.6 brief specified. Net effect on security: strictly positive — one fewer
  special case, and the leaf's `signer_count` is an explicit CONSTANT 1 rather than an implicit one
  injected by the level-1 circuit.
- **D-2. The leaf gadget is `FalconSigVerifyTarget::new` (UNCONDITIONAL), not `new_conditional`.**
  There is no `verify` gate wire at the leaf at all, so the norm bound — the sole accept/reject
  decision of Falcon — is always live. `new_conditional` is used NOWHERE in the production tree
  (only in the 2-sig-leaf measurement test). The gadget itself is untouched.
- **D-3. Facade preserved, `data` became a method.** `FalconAggCircuit` keeps its Phase-2
  consumer-facing API (`new()`, `verifier_data()`, `prove(&FalconAggWitness)` → 137-PI top proof), so
  close / cancel-close / `wallet_core`'s `CloseProver` / `CancelCloseProver` need **no logic change
  at all** — only a recomputed VK. The single mechanical exception: the struct can no longer own a
  `data` field (the top-level `CircuitData` lives inside `levels[3]`), so `agg.data` became
  `agg.data()`. Four call sites in TEST code were updated; no production code changed.
- **D-4. Prover-side same-message precheck** in `FalconAggCircuit::prove` (every active witness's
  `message_digest` must equal `witness.message`). Convenience only — fail early with a clear error;
  the binding check remains the in-circuit gated message equality.
- **D-5. Consumer-side floor asserts KEPT.** `close_circuit.rs:538` / `cancel_close_circuit.rs:346`
  `assert_one(active_bits[0])` (which, via `connect(signer_count, member_count)`, forces
  `signer_count >= 1`) are left in place as defence in depth even though the tree makes the floor
  structural. They cost one gate. Only the surrounding SECURITY COMMENTS were updated, because they
  described the flat circuit's internals ("monotone `is_active` prefix", "sum of 16 bools") and
  would otherwise have become misleading. **No consumer logic was touched.**
- **D-6. No lookups anywhere.** Phase 2.5's lookup approach stays rejected
  (`doc/tasks/falcon-sig-phase2_5-notes.md`); the dummy-proof reconstruction path depends on the
  gadget's binary range checks.

## 4. Security-invariant re-argument

### 4.1 `signer_count >= 1` — now STRUCTURAL again

Induction over tree levels.
*Base:* a leaf proof's `signer_count` PI is the CONSTANT `1` (a `ConstantGate`-backed wire, not a
witness), and the leaf's Falcon gadget is unconditional, so a leaf proof exists only if a genuine
Falcon signature over the exposed `message` under the exposed `pk_g` exists.
*Step:* a level-`k` node computes `signer_count = count_l + is_right_present * count_r`, where the
LEFT child proof is verified against the real child VK unconditionally. There is no witness that can
turn the left child off. Hence `count >= count_l >= 1`.

This is exactly the invariant the flat Phase-2 design lost and had to restore with
`builder.assert_one(slots[0].is_active)`. The regression test `zero_signers_rejected` is kept and
strengthened: it still asserts an empty aggregate is rejected, and additionally pins that the
smallest reachable top-level statement carries `signer_count == 1` (there is no witness path to 0).

### 4.2 Left-packing / padding is EXACTLY zero

`is_right_present = 0` ⟹ every exposed right-half limb is `0 * right_limb = 0` — a wired product, not
a select over a nonzero constant. So padding slots are literally the field zero, byte-identical to
what native `close_member_set_commitment` pads with (the tree never even materialises
`falcon_padding_pk_g`; there is no padding-slot gadget). Combined with the rule "right present ⟹ left
child FULL (`count_l == 2^{level-1}`)", induction gives: the nonzero pk_g slots are exactly the first
`signer_count` slots and the zeros are strictly a suffix. This is what the consumers' `active_bits =
(i < member_count)` gating relies on. Test: `non_left_packed_aggregation_is_unprovable`.

Converse direction (a real signer smuggled in as a zero slot): a leaf's pk_g is
`Poseidon(IMFK || encode(h))` computed inside the gadget, so a zero pk_g requires a Poseidon preimage
of the all-zero digest — the same argument the retired design and Phase 2 both relied on. Unchanged.

### 4.3 Message binding

A leaf's `message` PI **is** the gadget's `message_digest` input wire — the wire the norm bound is
computed against (via `c = H2P(salt, message_digest)`). It is registered directly as PI 0..8, so
there is no free witness between "what was signed" and "what is exposed". Each level copies
`message` from its LEFT child (verbatim wires) and forces a present right child to agree limb by
limb. Therefore the top proof's `message` is one digest that EVERY counted leaf signature was
verified against. The consumer (close / cancel-close) connects that PI to its in-circuit-recomputed
IMCH/IMSB digest — unchanged code, unchanged obligation. Tests: `wrong_message_rejected`,
`mixed_message_children_cannot_be_aggregated`.

### 4.4 Verifier-data binding (A7) and the dummy path

Each level bakes the child's `verifier_only` data in via `builder.constant_verifier_data`, so only
genuine child proofs aggregate. With `is_right_present = 1` the in-circuit `select_verifier_data`
picks the REAL child VK, so a dummy proof flagged present fails — a prover cannot inflate
`signer_count` without a genuine subtree. Test:
`dummy_right_child_flagged_present_is_rejected`.

### 4.5 No witnessed freedom in the exposed statement

A level's only witnesses are the two child proofs and the boolean flag; `message`, `signer_count` and
every pk_g slot are wired functions of verified child PIs. Test:
`forged_public_input_list_fails_verification` flips every one of the 25 PI limbs of a level-1 proof
and requires each forgery to fail verification.

### 4.6 Unchanged consumer obligations

Signer DISTINCTNESS is still NOT enforced by the aggregator (duplicate slots are accepted by design,
each independently verified); A5 distinctness, the member-set commitment and the L1 registered-set
match are unchanged consumer obligations in close / cancel-close. Their code is untouched.

## 5. Files changed

- `src/falcon_sig/agg.rs` — rewritten: `FalconLeafCircuit`, `FalconAggLevelCircuit`, tree facade
  `FalconAggCircuit`, 15 tests.
- `src/circuits/channel/close_circuit.rs` — comments only + 3 `agg.data` → `agg.data()` (test code).
- `src/circuits/channel/cancel_close_circuit.rs` — comments only + 1 `agg.data` → `agg.data()`
  (test code).
- `src/falcon_sig/mod.rs`, `src/falcon_sig/gadget.rs`, `vendor/`, `wallet_core.rs` — **untouched.**

## 6. Verification performed

- `cargo check --release --lib --tests` — clean.
- `cargo clippy --release --lib --tests` — no warnings attributable to `src/falcon_sig/agg.rs`.
- `cargo fmt` — applied.
- `cargo check --release --lib --target wasm32-unknown-unknown` — clean.
- `falcon_sig::agg` suite: **15/15 pass** (177 s, 7.57 GB peak).
- `circuits::channel::close_circuit` `_n2` and `_n16`: pass, close degree pinned at 2^17.
- Full `circuits::channel::close_circuit` suite: **15/15 pass** (321 s, 10.91 GB peak).
- Full `circuits::channel::cancel_close_circuit` suite: **7/7 pass** (111 s, 5.98 GB peak).

NOT run (deliberately, memory/scope): `falcon_sig::gadget`'s `falcon_sig_circuit_measure_1_3_16`
(builds the 2^20 N=16 harness — that is the 22 GB circuit this phase exists to avoid), the balance /
validity / e2e suites, and anything Groth16/MLE.

## 7. STOP points / open items for the owner

1. **VK CHANGE.** Every baked artefact derived from the aggregation verifier data changes: the close
   and cancel-close circuit digests change, therefore so do their proofs and any on-chain-pinned
   verifier constants / fixtures downstream of them. Nothing in this phase regenerates fixtures. If
   any committed fixture pins a close/cancel VK or circuit digest, it must be regenerated before
   merge.
2. **Phase seam unchanged.** The known Phase-2 seam is still open: the wallet join/registration path
   still registers the GOLDILOCKS `pk_g`, so a Falcon-proven close only matches a channel whose
   registered member set already carries Falcon `pk_g` digests. Phase 4 territory; untouched here.
3. **Review boundary.** This session implemented; per CLAUDE.md it must NOT also security-review its
   own work. The `signer_count >= 1`, left-packing and message-binding arguments in §4 should be
   re-derived by an independent reviewer / attacker subagent before merge — in particular the claim
   that the leaf's `signer_count` constant `1` is genuinely constrained (a `ConstantGate` wire) and
   not a routable free witness.
4. **Level-1 build time (7 s) is `DummyProof::new` over the 2^16 leaf common data**, i.e. it builds a
   2^16-row NoopGate circuit and proves it once. It is a one-off per process and cheap in memory, but
   it is the only place the tree touches a 2^16 dummy; if leaf degree ever grows this grows with it.
5. **Prove time is now sequential-by-construction** (16 leaves then 15 level proofs, one circuit at a
   time). Leaf proving is embarrassingly parallel and could be batched across processes/threads if
   36.9 s ever matters — but doing so multiplies peak RSS by the parallelism factor, which is exactly
   the trade this phase reversed. Not done; flagged only.

## Independent security review outcome (2026-08-05) — FIT to commit

**Headline question answered NO**: the reviewer could construct no prover strategy producing a
top-level proof in which a slot contributes a `pk_g` without a valid Falcon signature over the
exposed `message`, or in which `signer_count` exceeds the number of genuinely verified
signatures. The induction closes on the joint invariant, verified per level: (a) `count <= 2^k`;
(b) every slot with index `>= count` is EXACTLY field zero; (c) every slot with index `< count`
is the `pk_g` of an independently, unconditionally verified Falcon signature over the exposed
message.

Key confirmations (the item the implementer itself flagged for scrutiny first):

- **The leaf's `signer_count = 1` is a genuine verifier-enforced constant**, traced into this
  plonky2 fork: `builder.one()` is materialised at `build()` into a `ConstantGate` row whose value
  lives in the constants polynomial committed in `constants_sigmas_cap` — i.e. in the VK — and the
  target is copy-constrained to it. Not a routable free witness. Had this been free, the entire
  count induction would have collapsed.
- **Every right-child read is gated by a wired product on the SAME boolean that selects the VK**
  (message equality, count, pk slots) — the reviewer enumerated all occurrences and found no
  ungated read. With the flag set, `select_verifier_data` picks the REAL child VK so a dummy
  cannot pass; with it clear, the right child's PIs are untrusted but cannot influence anything.
- **The level circuit is a constraint-for-constraint copy of the retired aggregator.** A
  comment-stripped mechanical diff against `e0dec8b:src/poseidon_sig/aggregate.rs:206-284` shows
  ZERO constraint-level differences; the only deltas are a `child_pis` signature change, an added
  `num_gates_before_padding` field, and a renamed length function.
- Executed: `falcon_sig::agg` 15/15 (peak 7.49 GB); `channel_close_circuit_..._n16` PASSES with
  the fixture's hard `assert_eq!(degree_bits, 17)` firing — **close degree unchanged at 2^17**,
  and the case that previously OOM'd now completes at 10.33 GB.

### Findings addressed here

- **MINOR-1 (fixed)** — the count constant moved from a local check to a cross-circuit invariant:
  `child_pis` reads a child's count from PI 8, where the retired design injected `builder.one()`
  inside the level-1 circuit. Equivalent only while the LEAF's PI 8 really is that constant, and
  the existing build-time guard only checked child PI ARITY — a future leaf edit keeping 17 PIs
  but relocating or freeing the count slot would have silently broken the induction base with no
  signal. Added a `const` layout pin at the level constructor plus
  `leaf_signer_count_is_a_verifier_enforced_constant_one`, which asserts a proved leaf exposes
  count 1 AND that forging any other value on the same proof fails verification.
- **INFO-1 (fixed)** — `agg.rs`'s own PI-arity self-checks were `debug_assert_eq!`, compiled out
  of every release build (all tests run release), leaving the 137-element contract guarded solely
  by the consumers' asserts. Both are now `assert_eq!`.

### Findings recorded, NOT fixed (tracked)

- **INFO-4(a)** — no test pins the converse smuggling direction (a REAL child proof presented
  with `is_right_present = 0`). Sound by construction (it can only LOWER the count, which the
  consumer pins to `member_count`) and harmless in effect, but unpinned.
- **INFO-4(b)** — `forged_public_input_list_fails_verification` tampers a LEVEL-1 (25-limb)
  proof; the 137-limb top-level statement the consumers actually verify is not covered by that
  pin. Same mechanism, weaker coverage than the production surface. Adding it costs a full 16-sig
  aggregation (~37 s) per run — deferred deliberately, not overlooked.
- **INFO-2** — `signer_count` counts VERIFICATIONS, not distinct keys (the same leaf proof may
  occupy two slots). By design and unchanged from Phase 2; both consumers convert it via the
  indexed-Merkle distinctness chain over the active set. The only route to "count > distinct
  signers", and entirely a consumer obligation.
- **INFO-3 (pre-existing)** — `src/utils/dummy.rs` comments out plonky2's `zero_knowledge`
  assert in `internal_dummy_circuit`. Inert under `standard_recursion_config`
  (`zero_knowledge: false`); a degree mismatch would still trip the `common` equality assert.
- **INFO-5** — `FalconAggCircuit::leaf` / `::levels` are `pub`, so callers can mint
  intermediate-level proofs (Phase 2's facade was opaque). Not a soundness issue: consumers
  verify only at the top VK.

### Reviewer-declared UNVERIFIED (named, not omitted)

Full `close_circuit` (15) and `cancel_close_circuit` (7) suites were NOT re-run by the reviewer
(only `_n16`); clippy and the wasm32 check were not run by it. The implementer reported 15/15 and
7/7. Suite after the fixes above: `falcon_sig::agg` **16/16**, peak RSS 17.2 GB for the whole
suite in one process (the 16-signature aggregation alone is 4.99 GB).

### GATES MERGE (owner action)

The aggregation VK changes, hence the close / cancel-close circuit digests and any downstream
baked fixture or on-chain-pinned constant derived from them. Nothing in this phase regenerates
fixtures; that is Phase 4/5 work and must happen before merge.
