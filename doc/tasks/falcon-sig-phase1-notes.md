# Phase 1 notes — In-circuit Falcon-512/Poseidon verifier gadget (plonky2)

Status: implemented, all checks green, NOT committed (awaiting the separate security review per
plan). Branch `feat/falcon-poseidon-sig`. Implements exactly the Phase-1 checklist of
`falcon-sig-todo.md` under threat model `falcon-sig-threat-model.md` (TM-C5 all five items,
O-2, O-5). No STOP points — every check was implementable soundly.

## What was built

New module `src/falcon_sig/gadget.rs` (nothing wired into existing consumers; no existing
circuit touched):

- **`FalconSigVerifyTarget`** — the per-signature gadget. Constraint satisfaction is exactly
  the native `verify_with_pk_g` predicate:
  1. canonicity gates: salt elements `< 2^40` (8×5-LE-byte packing, injective), `h` and `s2`
     coefficients `< q` (two 14-bit checks each);
  2. `pk_g == Poseidon(IMFK ‖ encode(h))` — recomputed and connected INSIDE the gadget
     (review F-2 pattern; callers cannot forget the binding). `encode(h)` is the native
     4×14-bit-lane Horner packing over the range-checked coefficients (injectivity = the
     canonicity gate, TM-C5 item 5);
  3. `c = H2P(salt, digest)`: 1 absorb + 64 squeeze Poseidon permutations (native plonky2
     `builder.permute::<PoseidonHash>` gates), capacity initialized `[IMFH,0,0,0]` (domain in
     the CAPACITY — the Phase-0 convention, pinned by KAT test), each output element reduced
     mod q from the FULL canonical 64-bit value (O-1);
  4. `s1 = c − s2·h` in `Z_q[X]/(X^512+1)` via in-circuit negacyclic NTT mod 12289
     (Cooley–Tukey forward / Gentleman–Sande inverse, ψ = 49, bit-reversed twiddle tables with
     build-time primitivity asserts), all values canonical `< q` at every step, every
     reduction range-checked (TM-C5 item 2);
  5. `‖(s1,s2)‖² ≤ β² = 34_034_726` over centered values; the sum is ≤ 1024·6144² < 2^36 (no
     field wrap; pinned by the bound-ledger test); comparison via a 26-bit range check of
     `β² − norm` (β² < 2^26).
- **Input representation** (the Phase-2 connection contract):
  - `pk_g: Bytes32Target` (8 canonical u32-limb targets) — chosen because member `pk_g`
    values flow through the close circuit exactly in this form (`MemberAuth.pk_g: Bytes32`,
    keccak member-set commitment limbs); Phase 2 connects with zero conversion.
  - `message_digest: Bytes32Target` — the IMCH/IMSB keccak digest limbs. Documented gadget
    contract (TM-C5 item 4): consumers MUST connect it to a digest recomputed in-circuit for
    their own context; it is never a free witness at the consumer level.
- **The single reduction primitive** `constrain_mod_q_decomposition(t, k, r, k_bits)`:
  `t = k·q + r`, `k` range-checked to `k_bits ≤ 49` (build-time assert; no-wrap cap), `r < q`
  via two 14-bit checks. Uniqueness/no-wrap argument in the module doc; per-call-site `t_max`
  bounds documented at each call. Split into a constraint layer (witnessable `k`/`r`, used by
  the quotient-cheat adversarial test) and `reduce_mod_q` (allocates + honest generator).
- **Goldilocks→Z_q reduction of sponge outputs**: two-stage — unique canonical 32/32 split
  (reusing the audited `Bytes32Target::from_hash_out` safe split), then
  `t = hi·(2^32 mod q) + lo < 2^46` with a 32-bit quotient. See "Deviations" D-3 for why the
  brief's direct ~2^50-quotient form was NOT used.
- **Centered norm**: per coefficient a prover-free boolean `b` and square `(v − b·q)²`.
  SECURITY argument (in module doc): the minimum of the two choices is the true centered
  square, so a lying prover can only INCREASE the computed norm — the bound stays sound, and
  the honest generator makes it exact.
- **`FalconSigCircuit`** — standalone harness verifying N independent signatures
  (`standard_recursion_config`; public inputs per signature: pk_g limbs ‖ digest limbs), plus
  `FalconSigGadgetWitness` (raw u64 witness form; `for_signature` builds it honestly from a
  native `FalconSignature` via the new `s2_coefficients()` accessor).
- Two small `SimpleGenerator`s (mod-q decomposition, centering bit) — completeness only;
  soundness rests entirely on the constraints.

Tree changes outside `gadget.rs`: `src/falcon_sig/mod.rs` gains `pub mod gadget;` and the
`FalconSignature::s2_coefficients()` accessor (sanctioned "pub accessor" change; no semantics
touched). Nothing else; vendor/ untouched; no existing test modified; no config changes.

## Measurement (THE Phase-1 deliverable for the owner)

`falcon_sig_circuit_measure_1_3_16`, run in isolation
(`cargo test --release -p intmax3-zkp --lib falcon_sig::gadget::tests::falcon_sig_circuit_measure_1_3_16 -- --nocapture`),
Apple Silicon (M-series), release, `standard_recursion_config`, 2026-08-05:

|  N |   gates | degree_bits | build_s | prove_s | verify_ms |
|---:|--------:|------------:|--------:|--------:|----------:|
|  1 |  51,734 |          16 |    2.54 |    2.23 |      4.66 |
|  3 | 155,198 |          18 |   12.13 |    9.49 |      4.95 |
| 16 | 827,720 |          20 |   52.88 |   69.86 |      5.34 |

- ~51.7k gates per signature, dominated by range-check rows (`BaseSumGate<2>`) from the NTT
  (3 transforms × 2304 butterflies + 512 pointwise/scaling reductions); H2P is only 82
  Poseidon-gate rows + ~2.6k reduction rows.
- N=1 fits degree 2^16; N=16 lands at 2^20 with ~27% slack (827,720 of 1,048,576) — i.e. a
  16-cosigner close-circuit's signature part alone is a 2^20 circuit at ~70 s proving on this
  machine. `standard_recursion_config` was sufficient everywhere; no config change was needed.
- Deliberately NOT taken (security over speed; note for the sizing discussion): plonky2
  lookup tables would collapse the `r < q` checks (~50k rows → ~1k) but their interaction
  with the current MLE-verifier pin is unverified (close proofs are MLE-wrapped on-chain), and
  hand-rolled packed range checks are the classic soundness-bug habitat. Both are possible
  follow-ups AFTER a dedicated review, if Phase-2 sizing demands it.

## Test coverage (all release-gated; suite: 32 passed / 0 failed incl. the 17 Phase-0 tests)

Mirror tests (O-2):
- `reduction_bound_ledger` — pins every arithmetic bound the reduction discipline quotes
  (no-wrap cap, per-site t_max, norm no-wrap, β² width, 2^32 mod q).
- `ntt_algorithm_matches_schoolbook_and_vendor` — the circuit's NTT algorithm (native u64
  mirror, same tables/loops) vs an O(n²) schoolbook negacyclic oracle AND the vendored exact
  FFT (double oracle), random polynomials.
- `circuit_ntt_product_matches_native` — the in-circuit product s2·h exposed as 512 public
  inputs equals the native product.
- `circuit_h2p_matches_native_pinned_vectors` — in-circuit H2P on the pinned Phase-0 KAT
  (salt 0..39, msg limbs 0..7): all 512 coefficients equal native, plus the pinned
  prefix/suffix/fold anchors from `h2p_and_pk_digest_pinned_vectors`.
- `circuit_pk_digest_matches_native_pinned_vector` — in-circuit pk digest equals native for
  the pinned `from_seed([42;32])` pk_g and a second key.
- `honest_signatures_prove_across_seeds_and_messages` — randomized completeness: real
  `FalconKeys::sign` signatures (two keys, multiple messages) satisfy the full gadget (plus
  the mixed-key N∈{1,3,16} batches in the measurement test).

Adversarial suite (O-5; each rejected at witness-gen, proving, or verification — the repo's
close-circuit negative idiom extended with a verify check):
- `norm_boundary_beta_sq_accepts_and_plus_one_rejects_in_circuit` — FULL-pipeline boundary:
  with s2 = 1 (constant polynomial) and attacker-chosen h = c − s1_target, the circuit's s1
  is exactly s1_target; norm β² accepts, β²+1 rejects (native predicate cross-checked at both
  points).
- `non_canonical_s2_rejected` — s2[0] = q; s2[0] = q+1 (mod-q-equivalent second encoding);
  s2[0] = p−1 (field-negative centered confusion); plus a canonical-but-tampered control.
- `non_canonical_h_rejected` — h[0]+q WITH the matching forged digest (the sharp
  two-digests-one-key case), and h[100] = q.
- `tampered_salt_rejected` — passes the 40-bit gate, rejected by the H2P/norm algebra.
- `zero_s2_rejected`, `wrong_pk_g_rejected` (both directions: victim pk_g + attacker sig, and
  valid sig + wrong claimed pk_g), `wrong_message_digest_rejected`.
- `mod_q_quotient_cheating_rejected` — drives the decomposition constraint layer with
  directly-witnessed (t, k, r) for k_bits ∈ {1, 14}: honest proves; `(k−1, r+q)` (integer
  identity intact — only the r < q checks catch it, the classic hand-rolled-reduction hole),
  `(k+1, r−q)`, and an oversized wrap-attempt quotient all reject.

## Verification results (2026-08-05, Apple Silicon, release)

- `cargo test --release -p intmax3-zkp --lib falcon_sig`: **32 passed / 0 failed** (17
  existing Phase-0 + 15 new).
- `cargo clippy --release --lib --tests`: zero findings in the new code (remaining warnings
  pre-existing in untouched files).
- `cargo fmt` run (see D-7); `cargo check --target wasm32-unknown-unknown --lib`: green, no
  falcon_sig warnings.
- `cargo build --release` (full tree incl. bins): green. `git status`: only
  `src/falcon_sig/mod.rs` modified + `src/falcon_sig/gadget.rs` added.

## Deviations from the brief (with justification)

- **D-1 s2 in-circuit representation**: canonical residue `[0, q)` (one encoding per residue
  class) + the prover-free centering bit for the norm — instead of the brief's suggested
  offset encoding `s2 + q/2`. Rationale: the NTT consumes the canonical residue directly, the
  centering-bit treatment is then UNIFORM between s2 and the computed s1, and the offset form
  would add a second conversion layer with no soundness gain. Canonicity (TM-C5 item 1) is
  the same `< q` double range check either way.
- **D-2 accepted-set vs the native wire band**: the circuit accepts any s2 residue satisfying
  the verification equation + norm bound, i.e. exactly the native `verify` predicate on mod-q
  classes. The native `[-2047, 2047]` restriction is a TRANSPORT property enforced by
  `FalconSignature::from_bytes` before native verify, not part of the verification predicate
  (GPV unforgeability is the norm bound; any coefficient with |centered| > 5833 fails the
  norm anyway). Phase-2 witnesses decoder-produced s2, so completeness is exact. Documented
  in the module doc ("Accepted-set equivalence").
- **D-3 H2P mod-q reduction shape**: the brief suggested a direct quotient witness with bound
  ~2^50. That form is NOT unique: covering all of `[0, p)` needs k up to ⌊(p−1)/q⌋ ≈ 2^50.4,
  and with a 51-bit quotient check `k·q + r` can exceed p and wrap — giving sponge outputs
  x < 5287 a second (grindable, ~2^42 salt-grind) representation `r' = x + 7002`. Implemented
  instead: unique canonical 32/32 split (audited `safe_split` path via
  `Bytes32Target::from_hash_out`) then `t = hi·10952 + lo < 2^46` with a 32-bit quotient —
  unique end to end. The wrap fact is pinned by `reduction_bound_ledger`.
- **D-4 NTT(h) computed in-circuit** (the brief offered witnessed-and-verified as an option):
  verifying a witnessed NTT(h) needs an inverse transform of identical constraint cost, so
  the in-circuit forward NTT is strictly simpler with no extra witness surface.
- **D-5 H2P KAT comparison via public inputs**: the 512 in-circuit coefficients are exposed as
  public inputs of a test-only circuit and compared coefficient-for-coefficient against
  native (stronger than the digest-compare alternative the brief allowed).
- **D-6 quotient-cheat test level**: in the full gadget the quotients are generator-driven, so
  overriding them is a witness-set conflict (tests nothing about range checks). The
  constraint layer is exposed with witnessable k/r and attacked directly — the exact
  soundness surface, per the brief's intent.
- **D-7 fmt scope**: repo-wide `cargo fmt` again reformatted the pre-existing unformatted
  `tests/itx_faucet_cli_e2e.rs`; the churn was reverted (same as Phase-0 D-6).
- **D-8 negative-proof idiom**: the close-circuit `catch_unwind + prove().is_err()`
  disjunction, extended with "or `verify()` fails" — release-mode plonky2 skips in-prover
  constraint asserts (`debug_assert`), so a violating witness can yield an
  invalid-but-produced proof; the verify leg makes every rejection path airtight.

## Open items handed to later phases

- Phase 2: conditional/padding-slot strategy (the gadget verifies unconditionally; padding
  slots need either gating or a fixed valid dummy signature — decide with the close-circuit
  rewiring), and the pk_g `Bytes32Target` connection into the member-set commitment.
- Sizing follow-up IF needed: lookup-table range checks (verify MLE-pin compatibility first)
  or packed multi-value range checks (dedicated review required) — see the measurement notes.
- IMFH/IMFK/IMFG registry merge and detail2 §G-2 registration (Phase 2, unchanged from
  Phase 0's list).


## Independent security review outcome (2026-08-05)

**Verdict: FIT to commit. No CRITICAL, no MAJOR. No forgery path found.**

The reviewer's central conclusions, each independently derived rather than taken from these
notes: the mod-q reduction is UNIQUE at all eight instantiation sites (the `r < q` double check
kills +-q quotient shifts; the global `k_bits <= 49` cap makes a mod-p wrap arithmetically
impossible, so the field equation IS the integer equation); **no part of `s1` is free witness** —
every intermediate from `(salt, digest, h, s2)` through H2P, both forward NTTs, the pointwise
product, the inverse NTT and the final subtraction is fixed wiring composed with uniquely
determined reductions; the centering-bit monotonicity argument is airtight (the achievable set
is exactly `{v^2, (q-v)^2}` and its minimum is the native value, so a lie can only inflate); the
canonicity gates forbid `v = q`, `v = q+1` and field-negative encodings at the CONSTRAINT level;
and `pk_digest_circuit` and `ntt_forward` consume the IDENTICAL `h` target vector, so no
split-`h` attack exists.

Attacks attempted and defeated: `(k-1, r+q)` / `(k+1, r-q)` / oversized-`k` mod-p wrap at every
reduction site; second decomposition of the 32/32 split (closed by `is_hi_max * lo == 0`);
non-canonical `prod`/`c` injection; norm-sum field wrap; slack range-check wrap; H2P capacity
and domain manipulation; non-boolean centering bit; twiddle-table manipulation.

Findings, all addressed in this phase except the two carried forward:

| ID | Severity | Disposition |
|---|---|---|
| INFO-1 | INFO | FIXED — the naive-quotient non-uniqueness range is ~half the field, not `x < 5287` (that figure is only the sub-case where `x + (p mod q)` does not itself wrap). Module comment corrected; the design decision is right a fortiori. |
| MINOR-1 | MINOR | FIXED — the no-wrap ledger pinned the HONEST max `1024*6144^2 < 2^36`; the adversarial max is `1024*q^2 < 2^38` (a prover may set the centering bit on `v = 0`). Both are ~8 orders below p, so the conclusion stands, but the ledger now pins the right worst case. |
| INFO-2 | INFO | FIXED — `centering_bit_lie_can_only_inflate_the_norm` gives the monotonicity argument its first empirical probe (achievable-set minimum == native square for all q residues; non-boolean bit rejected; flipping the bit proves but strictly inflates; `v = 0` reaches exactly `q^2`). |
| INFO-3 | INFO | FIXED — quotient-cheat test extended from `k_bits in {1,14}` to every instantiated width `{1,14,15,32}`, including the widest (H2P) site. |
| MINOR-2 | MINOR | CARRIED to Phase 2 (see todo) — circuit accept set is strictly larger than the native wire-decodable set (`s2` transport band). Not a forgery vector; must be a recorded decision, not an inherited accident. |

Reviewer-declared UNVERIFIED items, all subsequently executed by the orchestrator and green:
`cargo check --target wasm32-unknown-unknown --lib`; `cargo clippy --release --lib --tests`
(zero falcon_sig findings); the measurement table reproduced with `--nocapture` (gate counts
identical: 51,734 / 155,198 / 827,720; proving times vary run to run: 2.19/8.95/59.07 s).
The reviewer also stated plainly that its negative-test load-bearing checks were
trace-verified, not execution-verified — recorded here rather than presented as coverage.

Suite after hardening: 33/33 (release).
