# Phase B threat model — real verifyWithdrawalClaim / verifyPostCloseClaim

Status: **THREAT MODEL — design-fork decision needed before any circuit code.**
Spec source: investigation 2026-06-18 (see doc/tasks/close-verifier-a1-plan.md §scope).

## What must be proven on-chain (the statements)
- **Withdrawal claim (§E-3, withdrawClaimZKP):** member i's slot ciphertext inside the FINALIZED
  `final_balance_state_h1` decrypts to the PUBLIC `amount` under member i's registered RegevPk; bound to
  channel_id, member_pk_g, recipient, and a withdrawal nullifier = keccak(IMCW, close_intent_digest, pk_g).
- **Post-close claim (§3.5.5, claimLateTx):** a late inbound `InterChannelTx`'s receiver-delta ciphertext
  decrypts to PUBLIC `amount` under receiver pk; bound to incoming_tx_hash, receiver_pk_g, recipient,
  shared_native_nullifier.

## The crux: Regev decryption has NO plonky2 implementation — it is a BabyBear Plonky3 STARK today
The decryption guarantee lives only in `DecryptionAir` (`src/regev/transfer_stark.rs`), verified natively in
Rust inside `*Witness::to_public_inputs`. Re-expressing it as a Goldilocks plonky2 circuit is a **from-scratch
cryptographic circuit**, NOT a wiring job. Regev params: q=2_013_265_921 (BabyBear, 2³¹−2²⁷+1), n=128,
Δ=15·2¹⁹, plaintext 1 bit/coeff over 64 low coeffs, decryption v = c2 − c1·s mod (x¹²⁸+1) then digit-extract.

### Soundness hazards (all must be discharged; from adversarial spec review)
1. **Ring-product overflow (HIGH):** c1(z)·s(z) is a 128-coeff negacyclic convolution; Σ of 128 coeff·coeff
   products ≈ 2⁶⁹ > Goldilocks p (2⁶⁴). The Plonky3 AIR avoids this via BabyBear-extension SZ-at-z. A plonky2
   re-expression must either reduce mod q after partial products (range-check heavy) OR replicate SZ-at-z with
   a challenge from a LARGE Goldilocks extension and a RE-DERIVED soundness error bound 2n/|EF|. A base-field z
   is unsound.
2. **Explicit mod-q reductions (HIGH):** q is not Goldilocks-friendly; every reduction needs a witnessed
   quotient + remainder range-checked < q, else ciphertext-malleability (two reps of one coeff) reappears.
3. **Load-bearing non-power-of-two range Δ=15·2¹⁹ (HIGH):** ns ∈ [0,Δ) via lo(19b)+(u+v)·2¹⁹, u,v∈[0,7].
   A naive 23-bit range admits digit-0↔digit-255 aliasing (255·Δ+2²³ > q) → forged amounts.
4. **Rounding / negative-noise mod-q wrap (MED):** digit extraction is a field equation mod q; must keep
   mod-q (not integer) semantics at the boundary |noise|=Δ/2.
5. **Carry width 254, not 127 (MED):** ripple carry needs 8 bool cols for adversarial digits near 255.
6. **Smallness encodings (MED):** s∈{−1,0,1} centered-in-field; CBD halves ∈{0,1,2}; consistent neg encoding.
7. **Two amount splits (MED):** STARK uses 4×16-bit; PI struct uses 2×32-bit — must bind amount consistently
   to BOTH the decryption bit-polynomial and the PI limb vector.
8. **`shared_native_nullifier` is UNBOUND today (MED):** PostCloseIncomingClaim carries it opaquely; nothing
   derives it in-circuit (unlike the withdrawal nullifier). Double-claim / cross-channel-replay surface — the
   new circuit SHOULD bind it to (close_intent_digest, incoming_tx_hash, receiver_pk_g).
9. **Privacy (MED):** the message/bit eval is E-3-PUBLIC but refresh-PRIVATE; exposing it on refresh would be a
   plaintext-confirmation oracle. Re-expression must preserve the per-purpose exposure flag.

## Bindings that DO have plonky2 precedent (reuse, mostly extract-from-inline)
- H1 recompute (`close_circuit.rs:453-478`), recursive balance-proof verify (`:549-559`), close_intent IMCI
  digest (`:519-547`) — all inline in the close circuit; extractable into shared fns.
- In-circuit RegevCiphertext digest (IMRC keccak): NONE — new gadget needed.

## On-chain shape (same as Phase A close)
New circuits register raw PI limbs (withdrawal 48 / post-close 40, `to_u64_vec` order). The verifier mirrors
`verifyCloseIntent`: `_bind*LimbsStrict` (length, strict eq, <2³², no mask) + `MleVerifier.verify` against a
per-statement set-once VK. Manager already gates payout with `totalWithdrawn ≤ finalizedChannelFundAmount` and
the `receivedChannelFunds` solvency ceiling (cross-channel theft already blocked; the gap Phase B closes is
INTRA-channel: a member forging a claim for an amount their slot doesn't actually hold).

## DESIGN FORK (decision needed — do not start coding until chosen)
- **Option A — hand-build Regev decryption in plonky2 (Goldilocks emulation).** Direct; but re-derives a subtle
  extension-field AIR's soundness in a new field and hand-rolls lattice crypto (tension with CLAUDE.md "no
  primitive from scratch / use audited libraries"). Highest audit burden; all 9 hazards in-scope.
- **Option B — recursively verify the EXISTING Plonky3 Regev STARK inside plonky2.** Reuses the tested AIR, but
  needs a Plonky3-FRI(BabyBear)-verifier expressed as a plonky2 circuit — also large; no in-repo precedent
  (plonky2 `starky` recursion can't verify a Plonky3 proof).
- **Option C — revisit the deferred 31-bit WHIR rail (sol-spartan-whir) for THESE statements only.** Lattice/
  31-bit work is exactly what 31-bit WHIR targets; close stays on the plonky2 @mle rail. Cost: integrate a
  research-grade unaudited verifier + R1CS/field reconciliation (previously deferred).
- **Option D — scope Phase B to the cheap bindings first** (H1-slot inclusion, member/recipient, nullifier
  incl. fixing #8) as a plonky2 circuit, and treat the decryption as a SEPARATE sub-phase once the approach is
  chosen — delivers partial hardening (binds WHICH slot/amount-claimed to the finalized state) while the
  decryption core is designed.

## Recommendation
Lead with the honest trade-off: the decryption core is the hard, audit-heavy part regardless of rail (this is
why the original design left it as an off-chain STARK + the receivedChannelFunds cap). Recommend **NOT**
hand-rolling lattice decryption blind (Option A) without a written soundness argument + dedicated review.

## DECISION (user, 2026-06-18): Option D — harden the cheap bindings first
Phase B-D scope = two NEW plonky2 binding circuits (PoseidonGoldilocks, D=2), MLE/WHIR-wrapped on the @mle
rail, replacing the two `_matches` stubs. They prove EVERYTHING EXCEPT the decryption:
- **WithdrawalClaimCircuit (48-limb PI):** bind `close_intent_digest`, `channel_id`; recompute
  `final_balance_state_h1` from witnessed slot data (reuse/extract the close circuit's H1 gadget) and assert it
  equals the PI `final_balance_state_h1` (manager supplies the FINALIZED value); prove `member_index` is in the
  active region and `user_amount_ct.digest() == enc_balance_digests[member_index]` (= PI `user_amount_digest`);
  bind `member_pk_g`, `recipient`; derive `withdrawal_nullifier = keccak(IMCW, close_intent_digest, pk_g)`
  IN-CIRCUIT. `amount` is a range-checked u64 witness PI — **NOT constrained to the ciphertext (decryption is
  deferred).**
- **PostCloseClaimCircuit (40-limb PI):** bind `close_intent_digest`, `receiver_channel_id`,
  `incoming_tx_hash`; prove receiver-delta inclusion (`receiver_pk_g` + `receiver_amount` ct ∈
  `source_tx.receiver_deltas`); bind `recipient`; **FIX hazard #8** — derive `shared_native_nullifier` IN-CIRCUIT
  from `(domain, close_intent_digest, incoming_tx_hash, receiver_pk_g)` and recompute the SAME value on-chain in
  the manager (today it is opaque). `amount` range-checked u64 PI, NOT decryption-bound.
- On-chain: mirror `verifyCloseIntent` — per-statement set-once VK (`initializeWithdrawalClaimVk` /
  `initializePostCloseClaimVk`), `_bind{Withdrawal,PostClose}LimbsStrict` (length 48/40, strict eq, <2³², no
  mask) + `MleVerifier.verify`; remove the two `_matches` paths. Manager `submitWithdrawalClaim` /
  `submitPostCloseClaim` take `MleVerifier.MleProof`.

### RESIDUAL after Phase B-D (DOCUMENT LOUDLY — not silently; sharpened per independent review)
- **Over-claim NOT closed (withdrawal):** `amount` is not proven to equal the plaintext of the slot ciphertext.
  The cap `totalWithdrawn ≤ finalizedChannelFundAmount` is **per-channel and SHARED across all withdrawal +
  post-close claims — NOT per-member/per-slot**. So a single member can over-claim up to the ENTIRE finalized
  channel fund (bounded only by that cap + the `receivedChannelFunds` ETH ceiling).
- **Post-close inclusion is VACUOUS (sharpened):** the receiver-delta is NOT anchored to any signed/committed
  source tx — the circuit connects two prover-chosen witnesses to each other, proving nothing about a real
  signed `InterChannelTx`. A claimant knowing a valid `(close_intent_digest, incoming_tx_hash, receiver_pk_g)`
  triple can produce an accepting proof for an arbitrary amount for a delta that never existed. This is NOT a
  new surface (the old stub proved nothing) and is bounded by the cap, but the precise residual is "delta not
  anchored to a signed tx," not merely "amount unbound." Closing BOTH requires the **decryption + source-tx
  anchoring sub-phase** (approach A/B/C, re-decide with a written soundness argument + dedicated review).
- What D DOES close vs the stub: forging a withdrawal claim against a ct NOT in the finalized state (H1-slot
  one-hot bind); nullifier #8 double-claim/cross-channel replay (post-close, now derived in-circuit + manager);
  unbound close_intent/channel/recipient; per-statement set-once VKs + strict limb binding.
- Cross-channel theft remains blocked by `receivedChannelFunds` throughout.

### Phase B-D — DONE & independently security-reviewed SOUND (2026-06-18)
Implementer + SEPARATE adversarial reviewer (CLAUDE.md §2). Verdict: SOUND within Option-D scope; no CRITICAL,
no new theft surface (strictly stronger than the stub on every axis). 2 HIGH = the documented residuals above.
- New circuits: `withdrawal_claim_circuit.rs` (48-limb), `post_close_claim_circuit.rs` (40-limb),
  shared `h1_gadget.rs` (extracted from close, NO drift — close n2 still proves).
- #8 fixed: `POST_CLOSE_NULLIFIER_DOMAIN=0x494d434b` ("IMCK", unique), derived identically in circuit/native/
  manager; manager keys `usedSharedNativeNullifiers` on the RECOMPUTED value (struct field removed).
- Verifier: per-statement set-once VKs (no disable seam), `_expected*Limbs` match `to_u64_vec()` (golden-pinned),
  `_bindLimbsStrict` (len/strict/≥2³²/no-mask), `_matches` removed from both; bytecode 19,218 B (<24,576).
- cargo check + forge build pass; 122 forge pass / 1 skip; circuit + golden tests pass.
- USER ACTION (heavy proving):
  `cargo run --release --features withdrawal-claim-fixture-bin --bin generate_withdrawal_claim_fixture`
  `cargo run --release --features post-close-claim-fixture-bin --bin generate_post_close_claim_fixture`
- Recommended non-blocking hardening (from review): add an independent boolean assertion on `selected_active`
  (`withdrawal_claim_circuit.rs:279-285`) as defense-in-depth (sound today via the Σ=1 one-hot).
