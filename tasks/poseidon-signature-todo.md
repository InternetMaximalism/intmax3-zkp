# Task: Replace SPHINCS+ with a Poseidon2-preimage ZK signature

Status: P1 + **P2a COMPLETE** (2026-06-15). P1 = Goldilocks primitive. P2a = standalone `SingleSigCircuit`
+ recursive `ListCircuit` (reuses `CyclicChainCircuit`). 21/21 `poseidon_sig` tests green; independent
security review found no soundness break (chaining / VK-pinning / hash-equivalence / message-binding /
degenerate-sk all enforced). **P2b NOT started** = the high-risk surgery: two-key identity swap +
validity/close SPHINCS+ removal → list-proof wiring.

P2 is split: **P2a** (single-sig + list circuits, standalone, no live-circuit change — DONE) and **P2b**
(identity swap + validity/close wiring — the risky part, awaiting go-ahead).
Branch: `paymentchannel-delegate`. Threat model: `tasks/poseidon-signature-threat-model.md`.
Design line: detail2.md (enshrined-paymentchannel).

Approved decisions: D1 **two keys per member, each native to its proof system** (final 2026-06-15 —
Goldilocks key for Plonky2 channel-state/close/intmax-tx signing; BabyBear key for the Plonky3
in-channel sender authorization; **no field emulation**) · D2 256-bit/128-bit-PQ (both keys) · D3 unify
all Plonky2 signature verification into a recursive list proof · D4 phased PRs.

Each phase: implement (impl subagent) → security review (separate subagent) → attacker pass (§3 of
threat model) → green tests → summary. No phase merges with a failing or weakened security check.

---

## Phase 1 — New signature primitive (purely additive; no circuit/identity change)

Goal: introduce the new key/primitive ALONGSIDE the existing SPHINCS+, with zero behaviour change, so
tests stay trivially green. The identity rename + SPHINCS+-verification removal is **deferred to P2**
because those two must change atomically to stay consistent. Falsifiable items:

P1 scope = the **Goldilocks** primitive only (it is what P2 consumes). The BabyBear primitive ships in
P3 alongside its native AIR. Falsifiable items:

- [x] Pin `sk_g` / digest width ≥256-bit over Goldilocks (4 limbs secret; Bytes32 digest = 4 limbs);
      `docs/poseidon-sig-entropy.md` written. [Open item #1]
- [x] Domain constants `DOMAIN_PK_G=IMPG (0x494d5047)`, `DOMAIN_SIG_G=IMSG (0x494d5347)`; non-collision
      test against the codebase domain set. [Open item #2] (detail2 §G mirror — TODO, deferred to P2's
      identity swap so it lands with the rest of the §G deltas.)
- [x] New `src/poseidon_sig/mod.rs`: `GoldilocksSecretKey` (`sk=[u64;4]`) from_seed/from_limbs/rand
      (`CryptoRng`-bound), `public_key()->Bytes32`, `sign(m)->Bytes32` (witness-only). Reuses
      `PoseidonHashOut` (audited Goldilocks Poseidon; no scratch). Redacted `Debug`; no `Serialize`/
      `Display` on the secret (leak-by-default avoided). `pub mod poseidon_sig;` in `src/lib.rs`.
- [x] Tests (11): determinism, key/message distinctness, `DOMAIN_PK_G`≠`DOMAIN_SIG_G`, Bytes32
      round-trip, redacted Debug, domain non-collision, CSPRNG bound, boundary (all-zero/max-field),
      message-aliases-domain, pk≠sig arity non-collision.

Exit criteria MET: `cargo test --release -p intmax3-zkp --lib poseidon_sig` → 11/11 green; primitive +
constants + entropy doc landed; **no existing type, circuit, or identity field changed.**

### P1 assessment
- Independent security review (separate agent) found **no live soundness or secret-leak bug** (module is
  additive, no external consumer, all constructors canonicalize). Hardening applied from the review:
  dropped secret-key `Serialize`/`Deserialize`, `CryptoRng` bound on `rand`, encoding-injectivity
  `// SECURITY:` notes + arity-collision test, expanded domain non-collision list, boundary/adversarial
  tests, canonical-limb invariant comment.
- Carried to P2: non-degenerate-`sk` witness/keygen check (A1); `Signature` newtype to make witness-only
  enforceable (A6); detail2 §G domain-constant mirror (with the identity swap).

Deferred to P2 (atomic with verification swap): rename `*sphincs_pubkey_hash*` identity plumbing to the
new member identity across `common/channel.rs`, channel-tx member fields, close PIs, `MemberSignature`,
`ChannelRecord`, MemberTree leaf, `member_set_commitment`. The Goldilocks `pk_g` is a bytes32 digest as
today (Plonky2/L1 paths unchanged in width); the member leaf additionally carries `pk_b` (anchored in
P2, verified in P3) — so registration commits to the key **pair** (A11).

## Phase 2a — single-sig + recursive list circuits (standalone) — DONE

Decisions locked: `sig` witness-only (`m` bound as public input); list = **order-sensitive Poseidon
hash chain** reusing `CyclicChainCircuit`.

- [x] `SingleSigCircuit` (`src/poseidon_sig/circuit.rs`): PI `[pk(8), m(8)]`, witness `sk`; proves
      `pk=H(DOMAIN_PK_G‖sk)`, `m` bound as public input, `sig=H(DOMAIN_SIG_G‖sk‖m)` witness-only
      defense-in-depth, non-degenerate-`sk` (not all-zero) asserted in-circuit. [A1, A2, A10]
- [x] `ListStepCircuit` + `ListCircuit` (`src/poseidon_sig/list.rs`): per-step verifies a SingleSig
      proof, folds `leaf=Poseidon([LIST_LEAF_DOMAIN]‖m‖pk)` into `C_i=Poseidon(C_{i-1}‖leaf)`; recursion
      via `CyclicChainCircuit` (constant-VD self-reference, `C_0==0`, `prev==prev C` enforced). Native
      `list_commitment()` for consumers to rebuild. [A7, A8]
- [x] Tests (10 circuit/list): happy path, tampered pk/m, all-zero-sk reject, recursive-matches-native,
      wrong-prev_chain reject, first-step-nonzero reject, duplicate-allowed-at-list-level (boundary).
- [x] Independent security review (separate agent): no soundness break; nice-to-have tests + `// SECURITY`
      notes (`_sig_hash` not the binding mechanism; VK constant-pinning) applied.

### P2a→P2b carried obligations (consumer-side, the reviewer's must-fix)
- Consumer MUST compare the list `C` against a recomputed `list_commitment` AND enforce pubkey
  **distinctness** + **all-required-members-present** + **pk ∈ registered member set** (A4/A5/A8). The
  list circuit alone proves only "these ordered (m,pk) were each signed" — duplicates pass at list level.
- Exact-`m` + exact-`pk` + message-domain separation so an IMSB entry can't satisfy a close predicate (A4).

## Phase 2b — two-key identity swap + validity/close wiring (NOT STARTED)

- [ ] Enforce **non-degenerate `sk_g`** in keygen too (circuit already rejects all-zero). [A1]
- [ ] Consider a `Signature` newtype (no `Serialize`/`Display`) so witness-only `sig` is compiler-enforced. [A6]
- [ ] detail2 §G mirror of `DOMAIN_PK_G` / `DOMAIN_SIG_G` / `LIST_LEAF_DOMAIN`.
- [ ] Two-key registration: identity rename + commit `(pk_g, pk_b)` per member in MemberTree /
      `member_set_commitment` / `ChannelRecord` / Solidity; `pk_b` anchored now, verified in P3. Add a
      mismatched-pair rejection test. [Open item #4, A11]
- [ ] Wire **validity** (`update_channel_tree`): remove inline `verify_circuit()`; consume the list
      proof; retain pk ∈ `member_pubkeys_root` slot binding + `tx_tree_root` (`≠0` inter-channel)
      constraints. Exact-`m` + exact-`pk` consumer checks. [A4, A9, §2.4.3]
- [ ] Wire **close** (`close_circuit`): remove inline `verify_circuit()`; consume the list proof for
      N-of-N over IMCH; distinctness over the active pk set; member_set_commitment reconciliation. [A5]
- [ ] Measure removed SPHINCS+ vs added native-Poseidon single-sig + list gate count (expect large net
      reduction; Plonky2 side has no emulation). [Open item #4]
- [ ] Tests: happy path, malformed single-sig (wrong sk/pk/m), forged-append attempt, foreign-circuit
      substitution, duplicate-key N-of-N, cross-consumer replay (IMSB↔IMCH), property/randomized.
- [ ] Attacker subagent pass (§3) + separate security review.
- [ ] Assessment + lessons.

Exit criteria: validity + close use the recursive list proof; SPHINCS+ no longer verified in Plonky2;
full e2e green.

## Phase 3 — Plonky3 sender-sig embedding + SPHINCS+ removal

Goal: sender authorization inside the update ZKP using the **native BabyBear key** (no emulation).
Falsifiable items:

- [ ] BabyBear primitive: pin `sk_b` width for ≥256-bit (~9 BabyBear limbs); `DOMAIN_PK_B`,
      `DOMAIN_SIG_B`; native `pk_b = Poseidon2_BabyBear([DOMAIN_PK_B] ++ sk_b)`,
      `sig_b = Poseidon2_BabyBear([DOMAIN_SIG_B] ++ sk_b ++ m)` reference (reuse `p3-poseidon2`; no scratch).
      [Open item #5]
- [ ] Native Poseidon2-BabyBear hash-sig AIR columns added to `DualKeyTransferAir` (E-1); public-input
      layout extended (sender `pk_b` digest + channel-tx message limbs).
- [ ] In-circuit equality: AIR-computed `pk_b` == native BabyBear reference `pk_b` over hundreds of
      random `sk_b`.
- [ ] Constraint: the hash-sig witness `sk_b` is the **same** owner whose balance the range proof debits
      (atomic authorization ⟷ subtraction); `pk_b` bound to the registered member set paired with `pk_g`. [§4, A11]
- [ ] `wallet_core` sender flow: produce the in-channel proof carrying the embedded sig; remove the
      out-of-ZKP SPHINCS+ `sender_signature` path.
- [ ] Remove `sphincsplus-{circuits,params,poseidon}` deps; delete SPHINCS+ test_utils signer; confirm
      WASM circuit-size reduction.
- [ ] Tests: sender cannot prove a debit without the owner sig; wrong-owner sig rejected; e2e
      (register → deposit → in-channel transfer → inter-channel → close) green; WASM build green.
- [ ] Attacker subagent pass + separate security review.
- [ ] Update detail2 / detail2-implementation-notes with the signature-scheme delta.
- [ ] Assessment + lessons.

Exit criteria: SPHINCS+ fully removed; all four flows + WASM green; detail2 updated.

---

## Notes / risks carried from the threat model
- Security basis changes from standardized SPHINCS+ to bespoke Poseidon-preimage (approved). Keep D2
  parameters (both keys); never weaken silently.
- D1 (two native keys) **eliminates field emulation** — the former cross-field correctness risk (A3) is
  retired. The remaining top risk is **two-key binding (A11)**: `(pk_g, pk_b)` must be inseparably tied
  to one member at registration; gate it with the mismatched-pair rejection test.
