# Threat Model — Poseidon2-preimage ZK signature (replacing SPHINCS+)

Status: Draft for approval (no code written yet).
Branch: `paymentchannel-delegate`.
Scope: Replace SPHINCS+ (Poseidon) member signatures with a ZK-friendly "Poseidon2-preimage
signature" verified only inside ZK proofs, on the detail2.md (enshrined-paymentchannel) design line.

This document is a prerequisite per CLAUDE.md ("for any change touching proof logic / cryptographic
protocols, write a full threat model before writing any code"). It records the agreed design
decisions, the security argument, the adversarial attack enumeration, and the open items that must
be pinned before the corresponding implementation phase.

---

## 0. Agreed design decisions (user-approved 2026-06-15)

| # | Decision | Choice |
|---|---|---|
| D1 | Cross-field key strategy | **Two keys per member, each native to its proof system** (final, revised 2026-06-15 — supersedes both the BabyBear-emulate-in-Plonky2 and Goldilocks-emulate-in-Plonky3 proposals; **no field emulation anywhere**). (a) **BabyBear key** `pk_b = Poseidon2_BabyBear(sk_b)` — verified **natively in Plonky3** for the in-channel sender authorization embedded in the update ZKP. (b) **Goldilocks key** `pk_g = Poseidon_Goldilocks(sk_g)` — verified **natively in Plonky2** for channel-state signing, channel close, and intmax-tx (small-block IMSB) signing, including the single-sig + recursive list proofs. Hashes are **not unified**; each uses its proof system's native Poseidon. The two keys are bound inseparably to one member at registration (key-binding requirement — see A11). |
| D2 | Secret-key entropy / forgery basis | **256-bit classical / 128-bit quantum** preimage security. `sk` and the Poseidon2 digest must each carry ≥256 bits. Exact limb count pinned in P1 (see §6 Open items). |
| D3 | Recursive list-proof scope | **Unify all signature verification.** A recursive Plonky2 "single-sig list proof" accumulates `(message, signer_pubkey)` pairs; **both** the validity per-slot check (`update_channel_tree`) **and** the close N-of-N check consume it. Inline `verify_circuit()` (SPHINCS+) sites are removed. |
| D4 | Delivery | **Phased PRs** (P1 identity/key plumbing + this threat model; P2 Plonky2 single-sig + recursive list proof + validity/close wiring; P3 Plonky3 sender-sig embedding). Each phase ships green tests. |

---

## 1. The signature scheme

### 1.1 Definitions

Each member holds **two independent keypairs**, one per proof system (D1). For key kind `k ∈ {g, b}`
with hash `H_k` (`H_g = Poseidon_Goldilocks`, `H_b = Poseidon2_BabyBear`) over field `𝔽_k`:

- Secret key `sk_k ∈ 𝔽_k^{L_k}` (`L_k` pinned for ≥256-bit entropy — see §6).
- Public key `pk_k = H_k(DOMAIN_PK_k ‖ sk_k)`.
- "Signature" over message `m`: a **ZK proof of knowledge** of `sk_k` such that
  `pk_k = H_k(DOMAIN_PK_k ‖ sk_k)` **and** `sig_k = H_k(DOMAIN_SIG_k ‖ sk_k ‖ m)`, with `pk_k` and `m`
  as **public inputs** and `sk_k`, `sig_k` as **private witnesses**. The proof itself is the signature.

Role split:
- **Goldilocks key (`g`)** signs channel-state agreement (IMCH), channel close (IMCH final, N-of-N),
  intmax-tx / small-block (IMSB). Verified natively in Plonky2 (single-sig → recursive list → validity/close).
- **BabyBear key (`b`)** signs the in-channel sender authorization over the channel-tx message (IMPA),
  verified natively inside the Plonky3 update ZKP.

`m` is always an existing domain-separated signing digest (IMSB / IMCH / IMPA / IMCI …, keccak
`Bytes32`, 8×u32 limbs), encoded into the field of the verifying proof system. No new message format.

### 1.2 Why `sig = H(sk, m)` is included

Unforgeability already follows from `pk = H(sk)` plus binding `m` into the proof's public inputs
(§2.1). The `sig = H(sk, m)` constraint is **defense-in-depth**: it forces `m` to be consumed by the
secret key inside the circuit, so the statement cannot be satisfied for a chosen `m` without the
witness `sk`, independent of any public-input malleability in the proof system.

`sig` is **kept as an internal wire — NOT a public output** (default). The recursive list proof
accumulates `(m, pk)`, never `sig`. This avoids exposing a deterministic per-(key, message) tag and
its attendant linkability / PRF-leakage surface. Exposing `sig` is an explicit opt-in, out of scope
unless a dedup/nullifier need arises (then it requires a Poseidon2 PRF-security argument — §3, A6).

### 1.3 Per-field verification (both native — no emulation)

- **Plonky3 (BabyBear, native):** sender in-channel authorization with the **BabyBear key**. A
  Poseidon2-BabyBear hash-sig gadget is embedded into the existing `DualKeyTransferAir` (E-1,
  `transfer_stark.rs`) so that the **same** ZKP proves (a) the debited owner's range proof (already
  present, ripple-carry) **and** (b) the owner's hash-signature `pk_b = H_b(sk_b)` / `sig_b = H_b(sk_b,m)`
  over the channel-tx message. Atomic: a valid balance-reduction proof cannot be produced without the
  owner's BabyBear signature.
- **Plonky2 (Goldilocks, native):** the single-sig proof with the **Goldilocks key** for co-sign /
  small-block (IMSB) / close (IMCH), and the recursive list proof. `Poseidon_Goldilocks` is native.

Because each proof system verifies a key in **its own native field/hash**, there is **no foreign-field
emulation anywhere** — the cross-field emulation correctness risk (former A3) is eliminated. The new
obligation is **inseparable key-binding** (A11): the two keys must be bound to one member so that
`pk_g` of member X cannot be paired with `pk_b` of member Y.

---

## 2. Security argument

### 2.1 Unforgeability (soundness)

To forge a signature on `(pk_k*, m*)` an adversary must produce a proof of knowledge of `sk_k*` with
`pk_k* = H_k(DOMAIN_PK_k ‖ sk_k*)`. Without `sk_k*` they cannot build the witness; producing `sk_k*`
from `pk_k*` is a **preimage** computation on `H_k` (Poseidon-Goldilocks for `g`, Poseidon2-BabyBear
for `b`). With D2 (≥256-bit), classical work is `2^256`, quantum (Grover) `2^128`. Forgery reduces to
the preimage resistance of the respective Poseidon at the chosen parameters. **This is the security
basis change vs SPHINCS+** (standardized, conservative hash-based signature) → a bespoke
"preimage-as-signature" on an algebraic hash. Approved by the user; the trade-off (cheaper in-circuit,
smaller proofs, still plausibly post-quantum) is documented and accepted. SECURITY (approved): do not
weaken D2 silently (CLAUDE.md general rule).

### 2.2 Message binding & replay

`sig = H(sk, m)` and `m`-as-public-input bind the proof to exactly `m`. `m` is a domain-separated
signing digest already containing channel_id + a monotone counter (state_version / small_block_number
/ nonce / prev_digest), so the same `(sk, m)` cannot be validly reused in a different context. The
keccak signing-digest domains (IMSB ≠ IMCH ≠ IMPA …) prevent a proof minted for one consumer from
satisfying another (§2.4, A4).

### 2.3 Two-key binding (D1, final)

There is **no field emulation** — each proof system verifies its own native key. The replacement
obligation is **inseparable key-binding**: the member's `(pk_g, pk_b)` (and `regev_pk`) must be bound
together at registration so an adversary cannot pair member X's Goldilocks key with member Y's BabyBear
key (A11). Concretely:
- The in-circuit **MemberTree** leaf binds `{pk_g, pk_b, regev_pk_digest}` (Poseidon), and the channel
  member-set root commits to it. The in-channel sender ZKP exposes `pk_b` as a public input; the
  co-signers (and any circuit that consumes the update) check that `pk_b` belongs to the registered
  member set **paired with the same member's** `pk_g`.
- Registration (`registerChannel` / `ChannelRecord` / `member_set_commitment`) carries **both** keys
  (a contained growth of the registration surface vs the prior one-key assumption — Solidity stores a
  per-member commitment over the pair rather than a single hash).
Mitigation/testing: registration round-trip + a "mismatched-pair rejected" test (X's `pk_g` with Y's
`pk_b` must fail set membership). Each Poseidon (Goldilocks, BabyBear) uses its **audited** constants
(no re-derivation from scratch — CLAUDE.md).

### 2.4 Recursive list-proof soundness (D3)

The list proof is a cyclic Plonky2 circuit holding a commitment to an ordered list of `(m, pk)`
pairs. Each step ingests one single-sig proof and appends its `(m, pk)`.

Invariants that MUST hold:
1. **Self-reference:** previous-list verification uses constant verifier data (cyclic IVC,
   `recursively_verifiable.rs` / `cyclic_chain_circuit.rs`); only proofs from *this* circuit extend
   the list — no foreign-circuit substitution.
2. **Backed append:** the appended `(m, pk)` equals the verified single-sig proof's public inputs; no
   pair enters the list without a valid single-sig proof.
3. **Consumer predicate (the critical step):** because the list is generic, each consumer MUST check
   *both* the exact `m` and the exact `pk` it requires, and bind `pk` to the registered member set:
   - **validity:** for each small block, `(IMSB_digest, bp_pk)` ∈ list, and `bp_pk` ∈ the channel's
     Poseidon `member_pubkeys_root` at the bp slot, and `IMSB.tx_tree_root` matches / `≠ 0` on the
     inter-channel path (existing §F-2 constraints retained).
   - **close:** `(IMCH_final_digest, pk_i)` ∈ list for **all** active members `i`, the pk set equals
     the registered member set (`member_set_commitment` keccak reconciliation), and the members are
     **distinct** (no single key counted N times to fake N-of-N).
4. **No cross-consumer replay:** domain separation in `m` (IMSB vs IMCH) prevents a close entry from
   satisfying validity and vice versa.

### 2.5 Identity migration

The member identity becomes the pair `(pk_g, pk_b)` (Goldilocks + BabyBear digests) plus `regev_pk`,
replacing the single SPHINCS+ pubkey hash across: `MemberTree` leaf, `member_pubkeys_root` (in-circuit
Poseidon binding), `member_set_commitment` (L1 keccak), `ChannelRecord.member_*`, `MemberSignature`,
all channel-tx member fields, all close PIs, and the Solidity registration
(`ChannelSettlementManager`). Solidity stores/reconciles a per-member `bytes32` commitment; with two
keys it commits over the **pair** (`pk_g`, `pk_b`) rather than a single hash — a contained growth of
the registration surface. The Plonky2 close/validity paths consume `pk_g` (their on-chain-anchored
identity); `pk_b` is anchored in the MemberTree leaf for the off-chain-verified in-channel ZKP.
RegevPk authenticity (pre-existing open item) is unchanged.

---

## 3. Adversarial enumeration (attacker-subagent mandate)

A dedicated adversarial review MUST be run (separate subagent from the implementer, per CLAUDE.md)
against each phase. Initial enumeration:

- **A1 — Small/structured `sk`:** `sk` with insufficient entropy (e.g. single limb) → brute-force pk.
  Guard: D2 limb count + a witness range/format check that `sk` occupies the full claimed space.
- **A2 — Domain confusion `pk` vs `sig`:** if `DOMAIN_PK` and `DOMAIN_SIG` collide, a `sig` could be
  passed off as a `pk` or vice versa. Guard: distinct, documented domain constants; non-collision test.
- **A3 — (RETIRED)** Cross-field emulation divergence no longer applies: D1 (two native keys) removes
  all field emulation. Superseded by A11 (key-binding).
- **A4 — Cross-consumer / cross-message replay:** reuse a list entry for the wrong predicate. Guard:
  exact-`m` + exact-`pk` consumer checks (§2.4.3) + message-digest domain separation.
- **A5 — Fake N-of-N via duplicate key:** close accepts the same `pk` counted across multiple slots.
  Guard: distinctness check over the active pk set (already present for SPHINCS+ member-set; retain).
- **A6 — `sig` reveal leakage:** if `sig` is ever surfaced, linkability + algebraic-attack surface on
  a keyed Poseidon2. Guard: `sig` stays witness-only by default (§1.2).
- **A7 — List-proof foreign circuit / non-cyclic:** substitute a different verifier key to append
  arbitrary pairs. Guard: cyclic IVC constant-VD binding (§2.4.1).
- **A8 — Missing append / truncated list:** consumer believes a member signed when their pair was
  never appended. Guard: consumer counts required pairs; close requires all active members present.
- **A9 — Wrong-field pk binding:** the `pk_g` used by Plonky2 and the `pk_b` used by Plonky3 are
  distinct digests in distinct fields. Guard: each must be committed in the MemberTree leaf / registration
  for the **same** member so neither can be swapped for another member's key (see A11).
- **A11 — Two-key mix-and-match (D1):** an adversary pairs member X's `pk_g` with member Y's `pk_b`
  (or registers a `pk_b` not tied to their `pk_g`) to authorize a debit they could not otherwise sign.
  Guard: registration binds `{pk_g, pk_b, regev_pk}` per member in one leaf; the update-consuming check
  verifies `pk_b` belongs to the member set **paired** with the acting `pk_g`. Test: mismatched pair
  rejected (§2.3).
- **A10 — Transcript / Fiat-Shamir:** `m` and `pk` must be absorbed before any challenge in both the
  Plonky3 STARK and the Plonky2 proof; verify no value is used as a challenge before derivation.

---

## 4. CLAUDE.md cryptographic-invariant checklist (to confirm per phase)

- [ ] Fiat-Shamir: `m`, `pk` absorbed in correct order; transcript domain-separated; no pre-derivation.
- [ ] Commitment binding: the Plonky3 hash-sig shares the **same** witness `sk` as the range proof
      (one circuit) — owner of the reduced balance is the signer.
- [ ] Permutation/copy: every digest wire is fully constrained in its native field (no unconstrained
      limbs); BabyBear sender witness `sk_b` range/format-checked.
- [ ] No primitive from scratch: Poseidon-Goldilocks **and** Poseidon2-BabyBear constants/rounds reused
      from their audited instances.
- [ ] Key-binding (A11): `(pk_g, pk_b)` committed for the same member; mismatched-pair test present.
- [ ] Randomness: `sk` entropy source documented (wallet keygen), ≥256-bit.
- [ ] Security parameters (D2) documented and approved, never changed silently.

---

## 5. Blast radius (from the surface map)

- **Rust circuits:** remove inline `verify_circuit()` at `update_channel_tree.rs:719-942` and
  `close_circuit.rs:543-619`; add native-Goldilocks single-sig + recursive list circuits (Plonky2);
  embed a native Poseidon2-BabyBear hash-sig into `DualKeyTransferAir` (Plonky3).
- **Identity plumbing:** ~58 `sphincs_pubkey_hash` sites in `common/channel.rs` + circuits + test_utils;
  member identity becomes the pair `(pk_g, pk_b)` — registration carries both keys.
- **Solidity:** `ChannelSettlementManager.sol` member registration / `member_set_commitment` — the
  per-member commitment now covers the key pair (a contained surface growth).
- **Deps:** `sphincsplus-{circuits,params,poseidon}` removable in P3; `p3-poseidon2` (already present)
  used for the BabyBear key. (WASM circuit-size win.)
- **Reusable:** `recursively_verifiable.rs`, `cyclic_chain_circuit.rs`, 3 hash-chain accumulators.

---

## 6. Open items (pin before the relevant phase)

1. **P1 — Goldilocks `sk_g` / digest width** for ≥256-bit (Goldilocks ~64 usable bits → 4 limbs for
   the secret; the Poseidon-Goldilocks digest is a Bytes32 = 4 limbs ≈ 256-bit). Document in a short
   entropy note (mirror of `doc/docs/regev-noise-analysis.md` style).
2. **P1 — Goldilocks domain constants** `DOMAIN_PK_G`, `DOMAIN_SIG_G` (non-collision with existing
   IMxx / Poseidon domains); add to the §G constant table in detail2.
3. **P2 — list-proof shape**: ordered list vs multiset commitment; max length / padding; how validity
   and close index into it.
4. **P2 — two-key registration**: how `(pk_g, pk_b)` are jointly committed in `ChannelRecord` /
   MemberTree / `member_set_commitment` / Solidity (A11 binding); when `pk_b` is anchored even though
   its verification is deferred to P3.
5. **P3 — BabyBear `sk_b` / digest width** for ≥256-bit (BabyBear ~31 bits → ~9 limbs); native
   Poseidon2-BabyBear hash-sig AIR columns added to `DualKeyTransferAir`; BabyBear domain constants
   `DOMAIN_PK_B`, `DOMAIN_SIG_B`; public-input layout extension (sender `pk_b` digest + channel-tx
   message limbs). No emulation (native BabyBear).
6. Whether to ever surface `sig` (default: no) — revisit only if a nullifier need appears.

---

## 7. Process guardrails

- Implementer subagent and security-review subagent are **separate** (CLAUDE.md §2).
- An explicit attacker subagent runs §3 against each phase before merge.
- Unexpected test results are treated as security problems first (CLAUDE.md §5); no test is modified
  to pass, no security check is weakened to make progress.
- This is the detail2.md line: when a new field is added, mirror it into detail2 / detail2-impl-notes
  as an intentional delta if it diverges from abstract2.
