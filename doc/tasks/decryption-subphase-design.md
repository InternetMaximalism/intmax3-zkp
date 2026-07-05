# Decryption sub-phase — design + soundness findings (BLOCKED on a pk-binding protocol change)

Status: **DESIGN REVIEWED — NOT ready to implement. CRITICAL blocker + must-fixes below.**
Goal: bind the withdrawal/post-close claim `amount` to the plaintext of the slot/delta ciphertext
(close the over-claim residual of Phase B-D) via a plonky2 (Goldilocks) Regev-decryption circuit.
Reviewed by a design agent + a dedicated adversarial reviewer (CLAUDE.md §2). Both converge on the blocker.

## What IS sound / designable (good news)
- **Ternary-s construction kills the worst hazard.** `s ∈ {−1,0,1}`, so the ring products `a·s`, `c1·s`
  in Z_q[x]/(x¹²⁸+1) are signed-selection sums (each output coeff = Σ of ≤128 terms ±coeff, magnitude
  < 128q ≈ 2³⁷ ≪ Goldilocks p), checked DIRECTLY per-coefficient — no Schwartz–Zippel/extension challenge,
  no quotient polynomials. This eliminates hazard #1 (the 2⁶⁹ overflow).
- mod-q reduction per coeff via a witnessed quotient κ∈[−128,128] + remainder pinned **strictly < q** is
  unique/sound (no κ off-by-one aliasing) — discharges #2 GIVEN strict <q.
- Digit extraction (`v+Δ/2 = Δ·d+ns`), the load-bearing `ns∈[0,Δ)` gadget (lo19 + (u+v)·2¹⁹, u,v∈[0,7]),
  carry width 8 (≤254), and amount-bit binding all carry over from the AIR — discharge #3/#4/#5/#7.
- Constraint estimate ~55–90k flat arithmetic gates, degree ≤3 — feasible on the existing @mle rail
  (comparable to one extra keccak block; no new on-chain verifier).

## CRITICAL BLOCKER — the witnessed Regev pk=(a,b) is NOT bound to the finalized member record
Both agents, independently:
- The decryption plaintext is `c2 − c1·s` — a function of `(ct, s)` ONLY; `pk` is decorative unless `s` is
  forced to be the secret behind the member's REGISTERED RegevPk.
- Phase B-D pins the **ciphertext** to the finalized slot (`user_amount_digest == enc_digests[member_index]`),
  but pinning ct does NOT constrain the amount (s is free). `(a,b)` and `s` are prover-supplied witnesses.
- **Attack:** a malicious member takes the victim's real H1-pinned slot ct, picks an arbitrary ternary `s*`,
  computes `v* = c2 − c1·s*` honestly (passes every per-coeff/κ/digit gate), reads off an attacker-chosen
  `amount*`, and manufactures a matching `pk*=(a*,b*)` with `b*=a*·s*+e_pk*`. The circuit accepts. Over-claim
  is bounded only by the per-channel `finalizedChannelFundAmount` cap → one member drains the whole fund.
- **The Regev pk is committed in the repo** (`MemberLeaf.regev_pk_digest = RegevPk::poseidon_digest`,
  `member_pubkeys_root`, `regev_pk_root` "IMRR") — but ONLY on the validity/account-tree side. It is NOT in
  `BalanceState::h1`, `CloseIntent`, or anything the close/claim circuits or `ChannelSettlementManager`
  consume. Native `WithdrawalClaimWitness.user_pk` is a TRUSTED witness validated against nothing on this path.

### ⇒ The decryption sub-phase REQUIRES a pk-binding protocol-data change (one of):
- **Option 1 — commit per-slot `regev_pk_digest` into `BalanceState`/H1.** Cleanest in-circuit (reuse the
  one-hot select), but MUTATES the signed H1 preimage → re-signs every state, breaks all baked fixtures + the
  Solidity H1 mirror / `h1_gadget`.
- **Option 2 — thread `member_pubkeys_root`/`regev_pk_root` through `CloseIntent`** (finalized on L1) and open a
  `MemberLeaf{pk_g,pk_b,regev_pk_digest}` Merkle inclusion at the claimant's slot in the claim circuit (binds
  the same `member_pk_g` already in the PIs to the same `(a,b)` the decryption uses). Reuses existing
  MemberTree/A11 + the already-anchored `regev_pk_root`; does NOT disturb signed H1. Still extends `CloseIntent`
  (Rust + Solidity `CloseIntent`/`PendingClose` + `submitCloseIntent`) + an in-circuit Merkle opening.

## MUST-FIX list before any implementation (ordered)
1. **CRITICAL:** bind witnessed `(a,b)` to the member's registered RegevPk (Option 1 or 2) AND tie `s` to it via
   the key-binding constraint. Without this the whole circuit is trivially forgeable.
2. **HIGH:** range-check every reduced remainder STRICTLY `< q = 2,013,265,921` (decryption `v` AND key-binding
   `a·s` remainder), via a non-power-of-two range gadget. `< 2³¹` is a silent malleability hole (window ≈2²⁷).
3. **HIGH:** enforce `e_pk` halves exactly `{0,1,2}` / `e_pk∈[−2,2]` (degree-3 gate); reject `a=0`/`c1=0`
   (degenerate key-binding/decryption) at registration/inclusion.
4. **HIGH:** written line-level proof that the negacyclic wrap (x¹²⁸=−1) index/sign matches the ring, + a
   randomized DIFFERENTIAL test vs `negacyclic_mul_with_quotient` (transfer_stark.rs:1716-1726). Do NOT rely on
   "every coeff checked ⇒ zero error" — the per-coeff form moves the risk to wrap-indexing, it is NOT
   "strictly stronger than the AIR."
5. **MED:** if an explicit `wrap_i` boolean is used in digit extraction, constrain it as a DERIVED value, not a
   free witness (a free wrap is an extra adversarial DOF the AIR lacks); or eliminate it.
6. **MED:** keep `ns∈[0,Δ)` exact, `d<256` strict, 8-bit carries with `c_0=0` + final-carry-0; bind the 64
   decryption bits to the PI amount limbs with ONE consistent identity (resolve 4×16 vs 2×32 — bind to the
   repo's 2×32 U64 form; do not port the 4×16 STARK split).
7. **Process:** hand-rolled lattice relation ("no primitive from scratch" tension) ⇒ separate implementer/
   reviewer + full written soundness argument + property tests vs native `decrypt_amount` (incl. wrong-s,
   near-boundary noise, non-canonical-but-range-passing coeffs) before merge.

## Post-close ALSO needs source-tx anchoring (separate sub-design)
The decryption core closes "amount ≠ plaintext" but NOT "the receiver-delta ct was never in a signed tx"
(post-close vacuous-inclusion residual). `InterChannelTx::signing_digest` already commits the receiver_deltas +
`tx_inclusion_proof` + `signed_small_block`; anchoring = recompute the tx signing digest in-circuit + Merkle/
signature inclusion. Larger than the decryption core; its own design + threat model. Withdrawal claim does NOT
need this (its slot is pinned to finalized H1).

## DECISION (user, 2026-06-18): Option 1 — commit Regev pk into the signed state-channel H1
User reversed the earlier "don't disturb H1" stance: "state channel で登録してください。H1 の署名対象も変更
してしまっていい。" So pk-binding = commit each member's Regev pk into `BalanceState`/`h1()` (the signed
preimage), and the claim circuit binds the witnessed `(a,b)` to the H1-committed value via the SAME one-hot
select already used for `enc_balance_digests[member_index]`. Strongest trust (bound to the cryptographically
signed H1, no deployer-trust for the Regev pk). Cost: the signed H1 preimage changes → ripples everything that
computes/signs/mirrors H1.

### STAGED IMPLEMENTATION PLAN
- **Stage 1 — H1 Regev-pk commitment (prerequisite, self-contained).** Add per-slot `regev_pk_digests[MAX]`
  (Poseidon digests, pad-to-MAX zeroed) to `BalanceState`; fold into native `BalanceState::h1()` AND the shared
  `h1_gadget::recompute_h1` (so close + withdrawal circuits agree); update any Solidity H1 mirror; populate from
  the channel's registered member Regev pks; regenerate signing flows + fixtures. Pin native↔circuit↔Solidity
  with a golden vector. Phase A close circuit recomputes H1 via h1_gadget ⇒ its H1 value changes (PI LAYOUT
  unchanged, 87 limbs) ⇒ re-pin close golden H1 + regenerate close fixture. NO over-claim benefit yet (amount
  still free) — pure prerequisite.
- **Stage 1 — DONE & independently reviewed SOUND (2026-06-18).** `regev_pk_digests[MAX]` added to
  `BalanceState`, folded into native `h1()` + circuit `h1_gadget::recompute_h1` (byte-identical, randomized
  native↔circuit proving test passes), encoding `Bytes32::from(poseidon_digest).to_u32_vec()` (injective, matches
  MemberLeaf convention so Stage 2 can bind), padding canonicality enforced in `validate()` at the import
  boundary, all production signing sites populated (genesis from real keys; non-genesis carry `..prev`), Phase A
  close circuit still proves. LOW: serde break (intended); close test-fixture uses all-default digests
  (self-consistent, test-gated). USER ACTION: regenerate fixtures — `cargo run -r --features close-fixture-bin
  --bin generate_close_fixture` + `... --features withdrawal-claim-fixture-bin --bin generate_withdrawal_claim_fixture`.
- **Stage 2 — decryption core + integration.** Build the `decryption_core` gadget (ternary-s, §design) with ALL
  must-fixes (#1 pk-binding now satisfiable via the H1 one-hot select on regev_pk_digests; #2 strict <q; #3
  e_pk/a≠0/c1≠0; #4 wrap proof+differential test; #5 wrap_i derived; #6 ns/d/carry/amount-split). Integrate into
  withdrawal_claim_circuit + post_close_claim_circuit: witness (a,b), prove poseidon_digest(a,b) ==
  regev_pk_digests[member_index] (one-hot, H1-bound), key-binding + decryption, bind `amount`. This is the change
  that CLOSES over-claim.
- **Stage 3 — post-close source-tx anchoring** (separate sub-design + threat model): recompute
  `InterChannelTx::signing_digest` in-circuit + Merkle/signature inclusion so the receiver-delta isn't vacuous.
- Each stage: separate implementer/reviewer + differential/property tests vs native `decrypt_amount` (incl.
  wrong-s, near-boundary noise, non-canonical-but-range-passing coeffs) BEFORE merge.

## RECOMMENDATION / escalation
The decryption sub-phase is designable and the core arithmetic is sound (ternary-s + strict <q), BUT it cannot
be made sound without a **pk-binding protocol-data change** (CRITICAL #1), and it is a **hand-rolled lattice
circuit** requiring a written soundness proof + differential/property tests + dedicated review. This is a
materially larger, higher-risk change than Phases A/B. Escalate to the user: (a) take on the protocol change
(Option 1 vs 2) and proceed with the full must-fix discipline, OR (b) pause the decryption sub-phase here with
this design on record and keep over-claim bounded by the `finalizedChannelFundAmount`/`receivedChannelFunds`
caps, OR (c) reconsider rail (B recurse STARK / C 31-bit WHIR) for the lattice part specifically.
