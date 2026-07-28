/-
# ChannelSafetyMT.lean — Machine-checked safety proofs for multi-token channels
(detail2.md §N, threat model doc/tasks/multitoken-threat-model.md TM-1..TM-15)

Phase 0 formal model for the multi-token channel feature: generalizes the
single-token channel state of `ChannelSafety2.lean` (solo transfers) and
`ChannelSafety21.lean` (v2.1b batches) from one balance scalar per member to
one balance per (member, token slot), with up to `MAX_CHANNEL_TOKENS = 10`
tokens per channel (§N-2 fixed 10-wide ciphertext vector, owner decision 2).

The generalization axis is TOKENS ONLY. The member set stays the fixed
3-member model of ChannelSafety2 (`Member = {m0, m1, m2}`); `Ct` (a Regev
ciphertext abstracted to its plaintext `.pt : Int`, assumption A5) is reused
unchanged — one independent ciphertext per (member, token), exactly the §N-2
design ("each token position is an independent Regev ciphertext").

What is proved (per token slot t, for every step kind):
  * P2 per-token conservation — `total t = provenTotal t` is an invariant of
    solo transfers (§N-3), batches (§N-3 / TM-14), L1 deposit imports (§N-5),
    and TokenRegister (§N-1); no step moves value between t and t'.
  * TM-6 inter-channel (C2C) transfers move ONE base token end-to-end: the
    descriptor carries the BASE `token_index`, each channel resolves it
    against its OWN signed registry (`ResolvesMT`), the two channels'
    resolved-slot totals are jointly conserved (`c2cMT_conservation`), all
    other slots are framed on both sides, and a concrete counterexample
    (`sampleC2C_misresolution_breaks_conservation`) shows the resolution
    hypothesis is load-bearing.
  * The Lean analogue of P1 / TM-2's "other 9 positions unchanged": frame
    theorems showing each step changes balances only at its own token slot
    (and, for batches, only at the (member, token) pairs actually touched).
  * TM-1 registry injectivity is preserved by `TokenRegister` (given the
    freshness side condition the in-circuit duplicate check provides), and
    TokenRegister is header-only (balances/totals untouched).
  * A top-level no-cross-token corollary over all four step kinds (§N-9 P2).

Trust base: A1–A6 inherited from ChannelSafety2 (the ZKP soundness contracts
enter as the `*ProvenMT` / `*VerifiedMT` hypotheses; the wrapper constraints
of TM-2/TM-6/TM-7 are what make those hypotheses checkable). Signature-layer
modeling (H1 header, close game) is NOT duplicated here — the registry and
`tokenCount` ride in the state to model TM-9's "both inside the signed H1
header" (any signed state carries them), and the close game applies via the
same projection argument as ChannelSafety21 §7 once claims become
per-(member, token); that composition is out of scope for this phase-0 file.

OUT OF SCOPE for this phase-0 file (each deferred to its implementation
phase per doc/tasks/multitoken-todo.md):
  (i)   settledTxChain / hash-chain step lemmas — no MT analogue yet of
        ChannelSafety21's `bulk_send_chain_step`, `l1_deposit_chain_step`,
        or the close composition `end_to_end_close_safety21`; the
        cross-batch nullifier/replay story is deferred to the close/claims
        phase.
  (ii)  per-(slot, token) `pending_adds` / noise-budget counters (TM-13) —
        deferred to the leaf-widening phase.
  (iii) per-(slot, token) claim nullifiers (TM-5) — deferred to the
        close/claims phase.
  (iv)  the rollup-side per-base-token escrow ceiling `escrowed[t]` (TM-1
        mitigation layer (b)) — deferred to the L1 phase; layer (a),
        registry injectivity, IS modeled here.
  (v)   refresh transitions (RefreshAir; value-neutral by design) —
        deferred to the leaf-widening phase.

SECURITY DISCLOSURE (TM-8 / review finding M5): `ValidEncStateMT` alone does
NOT pin inactive slots to zero. WITHOUT `InactiveZero` as a maintained
system invariant, a `TokenRegister` could "reveal" pre-existing value
sitting in the newly activated slot (value creation at activation).
`step_preserves_inactiveZero` shows the §N-2 validate() fail-close maintains
it across every step kind, and `tokenRegister_fresh_slot_zero` derives that
a freshly activated slot starts empty.

Checked with: Lean 4.10.0, core library only (same toolchain as the sibling
files). Build: `lake build ChannelSafetyMT` in this directory.
-/

import ChannelSafety2

namespace ChannelSafetyMT

open ChannelSafety
open ChannelSafety2

/-! ## §1 Token slots, per-token state, and the 2-argument update helper
(detail2.md §N-1, §N-2) -/

/-- §N-1 `MAX_CHANNEL_TOKENS = 10`: channel-local token slots. -/
abbrev TokenSlot := Fin 10

/-- §N-2: the multi-token encrypted balance state. `encBal m t` is member
    `m`'s balance for local token slot `t`, one independent Regev ciphertext
    per (member, token) (A5). `provenTotal t` is the per-token channel total
    certified by the balance proof (A2). `registry`/`tokenCount` model the
    §N-1 channel-local token registry (local slot → BASE `token_index`),
    which rides in the signed H1 header (TM-9) — hence part of the state. -/
structure EncBalanceStateMT where
  encBal : Member → TokenSlot → Ct
  provenTotal : TokenSlot → Int
  version : Nat
  registry : TokenSlot → Nat
  tokenCount : Nat

/-- Plaintext semantics of one (member, token) encrypted balance (A5). -/
def EncBalanceStateMT.bal (s : EncBalanceStateMT) (m : Member) (t : TokenSlot) : Int :=
  (s.encBal m t).pt

/-- Per-token channel total over the three fixed members. -/
def EncBalanceStateMT.total (s : EncBalanceStateMT) (t : TokenSlot) : Int :=
  s.bal .m0 t + s.bal .m1 t + s.bal .m2 t

/-- §N-1: token slot `t` is active iff below the signed `tokenCount`
    boundary (TM-8: `token_slot < token_count` is checked in-circuit). -/
def ActiveToken (s : EncBalanceStateMT) (t : TokenSlot) : Prop :=
  t.val < s.tokenCount

/-- TM-8: `1 <= token_count <= 10`, enforced at init and preserved by
    `TokenRegister` (see `tokenRegister_preserves_bounded`). -/
def TokenCountBounded (s : EncBalanceStateMT) : Prop :=
  1 ≤ s.tokenCount ∧ s.tokenCount ≤ 10

/-- What honest members check before signing (the per-token generalization of
    ChannelSafety2's `ValidEncState`): every (member, token) balance is
    non-negative, and for EVERY token slot the plaintexts sum to that token's
    certified total (P2). -/
def ValidEncStateMT (s : EncBalanceStateMT) : Prop :=
  (∀ (m : Member) (t : TokenSlot), 0 ≤ s.bal m t)
  ∧ (∀ t : TokenSlot, s.total t = s.provenTotal t)

/-- §N-4 / TM-6: local slot `t` is active AND the channel's OWN signed
    registry maps it to base index `X`. This is the in-circuit
    registry-resolution contract used by the C2C transfer (§6, both sides:
    `registry[local_slot] == token_index ∧ local_slot < token_count`) and by
    the L1 deposit import's three-way binding, leg (c) (§3, TM-7). -/
def ResolvesMT (s : EncBalanceStateMT) (X : Nat) (t : TokenSlot) : Prop :=
  ActiveToken s t ∧ s.registry t = X

/-- TM-1: the registry is injective on base `token_index` over the ACTIVE
    slots — what per-token L1 isolation stands on (a duplicate base index at
    two local slots would double-count one escrow pool). -/
def RegistryInjective (s : EncBalanceStateMT) : Prop :=
  ∀ t1 t2 : TokenSlot, ActiveToken s t1 → ActiveToken s t2 →
    s.registry t1 = s.registry t2 → t1 = t2

/-- TM-8 / §N-2 `validate()` fail-close, state level: every INACTIVE slot
    (`t.val ≥ tokenCount`) holds zero in every member position and a zero
    certified total. SECURITY: this is a SYSTEM INVARIANT that must be
    threaded through every step (`step_preserves_inactiveZero`, §7); WITHOUT
    it, a `TokenRegister` could "reveal" whatever value happened to sit in
    the newly activated slot — see `tokenRegister_fresh_slot_zero`. -/
def InactiveZero (s : EncBalanceStateMT) : Prop :=
  ∀ t : TokenSlot, ¬ ActiveToken s t →
    (∀ m : Member, s.bal m t = 0) ∧ s.provenTotal t = 0

/-! ### Per-BASE-token totals (TM-6)

`total t` is a LOCAL-slot quantity. TM-6's "token-X value is conserved
across channels" must be stated against the BASE index: `baseTotal s X` sums
`total t` over every active slot whose registry entry is `X`. With an
injective registry the resolved slot is the UNIQUE contributor
(`baseTotal_eq_total_of_resolves`), which is what lets the §6 C2C theorems
speak about base-token value rather than prover-chosen local slots. -/

/-- Sum of a per-slot quantity over all 10 slots. -/
def sumSlots (f : TokenSlot → Int) : Int :=
  f 0 + f 1 + f 2 + f 3 + f 4 + f 5 + f 6 + f 7 + f 8 + f 9

/-- Total channel value held in BASE token `X` (decidable raw form of the
    `ActiveToken ∧ registry = X` guard). -/
def baseTotal (s : EncBalanceStateMT) (X : Nat) : Int :=
  sumSlots fun t => if t.val < s.tokenCount ∧ s.registry t = X then s.total t else 0

theorem sumSlots_congr (f g : TokenSlot → Int) (h : ∀ t, f t = g t) :
    sumSlots f = sumSlots g := by
  simp only [sumSlots, h]

theorem sumSlots_indicator (t : TokenSlot) (c : Int) :
    sumSlots (fun u => if u = t then c else 0) = c := by
  obtain ⟨n, hn⟩ := t
  have hcase : n = 0 ∨ n = 1 ∨ n = 2 ∨ n = 3 ∨ n = 4 ∨ n = 5 ∨ n = 6 ∨ n = 7
      ∨ n = 8 ∨ n = 9 := by omega
  rcases hcase with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;>
    simp [sumSlots] <;> omega

theorem sumSlots_single (f : TokenSlot → Int) (t : TokenSlot)
    (h : ∀ u : TokenSlot, u ≠ t → f u = 0) : sumSlots f = f t := by
  have h' : ∀ u : TokenSlot, f u = if u = t then f t else 0 := by
    intro u
    by_cases hu : u = t
    · subst hu; simp
    · simp [hu, h u hu]
  rw [sumSlots_congr f (fun u => if u = t then f t else 0) h',
      sumSlots_indicator t (f t)]

/-- **TM-6/TM-1 bridge.** With an injective registry, the slot resolving
    base `X` is the UNIQUE contributor to `baseTotal`: base-token value and
    resolved-local-slot value coincide. Injectivity is load-bearing — with a
    duplicate registration (the TM-1 attack) `baseTotal` would double-count
    and this equality would fail. -/
theorem baseTotal_eq_total_of_resolves (s : EncBalanceStateMT) (X : Nat)
    (t : TokenSlot) (hres : ResolvesMT s X t) (hinj : RegistryInjective s) :
    baseTotal s X = s.total t := by
  obtain ⟨hact, hreg⟩ := hres
  have hact' : t.val < s.tokenCount := hact
  have huniq : ∀ u : TokenSlot, u ≠ t →
      (if u.val < s.tokenCount ∧ s.registry u = X then s.total u else 0) = 0 := by
    intro u hu
    by_cases hg : u.val < s.tokenCount ∧ s.registry u = X
    · exact absurd (hinj u t hg.1 hact (hg.2.trans hreg.symm)) hu
    · rw [if_neg hg]
  show sumSlots (fun u => if u.val < s.tokenCount ∧ s.registry u = X
      then s.total u else 0) = s.total t
  rw [sumSlots_single _ t huniq]
  show (if t.val < s.tokenCount ∧ s.registry t = X then s.total t else 0)
      = s.total t
  rw [if_pos (And.intro hact' hreg)]

/-- Header-equality transport for `ResolvesMT` (registry and tokenCount ride
    in the signed header; steps that do not touch the header keep every
    resolution fact). -/
theorem resolvesMT_of_header_eq (s s' : EncBalanceStateMT) (X : Nat)
    (t : TokenSlot)
    (hreg : ∀ u : TokenSlot, s'.registry u = s.registry u)
    (hcnt : s'.tokenCount = s.tokenCount)
    (h : ResolvesMT s X t) : ResolvesMT s' X t :=
  ⟨show t.val < s'.tokenCount by rw [hcnt]; exact h.1,
   by rw [hreg t]; exact h.2⟩

/-- Header-equality transport for `RegistryInjective`. -/
theorem registryInjective_of_header_eq (s s' : EncBalanceStateMT)
    (hreg : ∀ u : TokenSlot, s'.registry u = s.registry u)
    (hcnt : s'.tokenCount = s.tokenCount)
    (hinj : RegistryInjective s) : RegistryInjective s' := by
  intro t1 t2 h1 h2 heq
  have h1' : ActiveToken s t1 := by
    show t1.val < s.tokenCount
    rw [← hcnt]; exact h1
  have h2' : ActiveToken s t2 := by
    show t2.val < s.tokenCount
    rw [← hcnt]; exact h2
  refine hinj t1 t2 h1' h2' ?_
  rw [← hreg t1, ← hreg t2]
  exact heq

/-- Base totals agree between two states whose registry headers agree and
    whose totals agree on the slots the registry maps to `Y`. -/
theorem baseTotal_congr (s s' : EncBalanceStateMT) (Y : Nat)
    (hreg : ∀ t : TokenSlot, s'.registry t = s.registry t)
    (hcnt : s'.tokenCount = s.tokenCount)
    (htot : ∀ t : TokenSlot, t.val < s.tokenCount → s.registry t = Y →
        s'.total t = s.total t) :
    baseTotal s' Y = baseTotal s Y := by
  show sumSlots (fun t => if t.val < s'.tokenCount ∧ s'.registry t = Y
      then s'.total t else 0)
    = sumSlots (fun t => if t.val < s.tokenCount ∧ s.registry t = Y
      then s.total t else 0)
  apply sumSlots_congr
  intro t
  rw [hreg t, hcnt]
  by_cases hg : t.val < s.tokenCount ∧ s.registry t = Y
  · rw [if_pos hg, if_pos hg]
    exact htot t hg.1 hg.2
  · rw [if_neg hg, if_neg hg]

/-- Homomorphic single-point update on a (member, token)-indexed balance map:
    add `d` at exactly (m, t), leave every other point untouched. The
    2-dimensional analogue of ChannelSafety2's `updCt`. -/
def updCt2 (f : Member → TokenSlot → Ct) (m : Member) (t : TokenSlot) (d : Ct) :
    Member → TokenSlot → Ct :=
  fun j u => if j = m ∧ u = t then ⟨(f j u).pt + d.pt⟩ else f j u

/-- Replace-point update (a debit installs a fresh `after` ciphertext): the
    2-dimensional analogue of ChannelSafety21's `setCt`. -/
def setCt2 (f : Member → TokenSlot → Ct) (m : Member) (t : TokenSlot) (c : Ct) :
    Member → TokenSlot → Ct :=
  fun j u => if j = m ∧ u = t then c else f j u

theorem updCt2_same (f : Member → TokenSlot → Ct) (m : Member) (t : TokenSlot)
    (d : Ct) : updCt2 f m t d m t = ⟨(f m t).pt + d.pt⟩ := by
  simp [updCt2]

theorem updCt2_not (f : Member → TokenSlot → Ct) (m : Member) (t : TokenSlot)
    (d : Ct) (j : Member) (u : TokenSlot) (h : ¬(j = m ∧ u = t)) :
    updCt2 f m t d j u = f j u := by
  simp [updCt2, h]

theorem updCt2_diff_member (f : Member → TokenSlot → Ct) (m : Member)
    (t : TokenSlot) (d : Ct) (j : Member) (u : TokenSlot) (hj : j ≠ m) :
    updCt2 f m t d j u = f j u := by
  simp [updCt2, hj]

theorem updCt2_diff_token (f : Member → TokenSlot → Ct) (m : Member)
    (t : TokenSlot) (d : Ct) (j : Member) (u : TokenSlot) (hu : u ≠ t) :
    updCt2 f m t d j u = f j u := by
  simp [updCt2, hu]

theorem setCt2_same (f : Member → TokenSlot → Ct) (m : Member) (t : TokenSlot)
    (c : Ct) : setCt2 f m t c m t = c := by
  simp [setCt2]

theorem setCt2_not (f : Member → TokenSlot → Ct) (m : Member) (t : TokenSlot)
    (c : Ct) (j : Member) (u : TokenSlot) (h : ¬(j = m ∧ u = t)) :
    setCt2 f m t c j u = f j u := by
  simp [setCt2, h]

theorem setCt2_ne (f : Member → TokenSlot → Ct) (m : Member) (t : TokenSlot)
    (c : Ct) (j : Member) (u : TokenSlot) (h : j ≠ m ∨ u ≠ t) :
    setCt2 f m t c j u = f j u :=
  setCt2_not f m t c j u (fun hc => h.elim (fun hn => hn hc.1) (fun hn => hn hc.2))

theorem updCt2_ne (f : Member → TokenSlot → Ct) (m : Member) (t : TokenSlot)
    (d : Ct) (j : Member) (u : TokenSlot) (h : j ≠ m ∨ u ≠ t) :
    updCt2 f m t d j u = f j u :=
  updCt2_not f m t d j u (fun hc => h.elim (fun hn => hn hc.1) (fun hn => hn hc.2))

/-- Per-token column total of a raw balance map (the fold-friendly form of
    `EncBalanceStateMT.total`). -/
def mapTotal2 (f : Member → TokenSlot → Ct) (t : TokenSlot) : Int :=
  (f .m0 t).pt + (f .m1 t).pt + (f .m2 t).pt

theorem EncBalanceStateMT.total_eq_mapTotal (s : EncBalanceStateMT)
    (t : TokenSlot) : s.total t = mapTotal2 s.encBal t := rfl

/-- A homomorphic add at (m, t) changes ONLY column t's total (by `d.pt`);
    every other column total is untouched. This is the arithmetic core of all
    per-token conservation and frame theorems below (P1/P2, TM-2). -/
theorem updCt2_mapTotal (f : Member → TokenSlot → Ct) (m : Member)
    (t : TokenSlot) (d : Ct) (u : TokenSlot) :
    mapTotal2 (updCt2 f m t d) u
      = mapTotal2 f u + (if u = t then d.pt else 0) := by
  by_cases hu : u = t
  · subst hu
    cases m <;> simp [mapTotal2, updCt2] <;> omega
  · simp [mapTotal2, updCt2, hu]

/-- A replace at (m, t) changes ONLY column t's total (by the difference);
    every other column total is untouched. -/
theorem setCt2_mapTotal (f : Member → TokenSlot → Ct) (m : Member)
    (t : TokenSlot) (c : Ct) (u : TokenSlot) :
    mapTotal2 (setCt2 f m t c) u
      = mapTotal2 f u + (if u = t then c.pt - (f m t).pt else 0) := by
  by_cases hu : u = t
  · subst hu
    cases m <;> simp [mapTotal2, setCt2] <;> omega
  · simp [mapTotal2, setCt2, hu]

/-! ## §2 Solo intra-channel transfer, per token (detail2.md §N-3, TM-2/TM-8) -/

/-- §N-3: `ChannelTx` gains `token_slot`. `encAmount` is the transfer amount
    encrypted under the recipient's key; `.pt` its plaintext semantics (A5). -/
structure TransferMT where
  sender : Member
  recipient : Member
  tokenSlot : TokenSlot
  encAmount : Ct

/-- §N-3 channelTxZKP soundness contract per token (A2 + the TM-2 binding
    triple): the signed `tokenSlot` is active (TM-8), the amount is
    non-negative, and the sender's balance AT THAT TOKEN covers it. -/
def TransferProvenMT (tx : TransferMT) (s : EncBalanceStateMT) : Prop :=
  ActiveToken s tx.tokenSlot
  ∧ 0 ≤ tx.encAmount.pt
  ∧ tx.encAmount.pt ≤ s.bal tx.sender tx.tokenSlot

/-- §N-3: sender's position-`tokenSlot` ciphertext decreases, recipient's
    position-`tokenSlot` ciphertext increases homomorphically; ALL other
    (member, token) positions untouched by construction (the TM-2 mitigation
    made structural); per-token `provenTotal` unchanged; version + 1;
    registry header unchanged. -/
def applyTransferMT (s : EncBalanceStateMT) (tx : TransferMT) : EncBalanceStateMT where
  encBal := updCt2 (updCt2 s.encBal tx.sender tx.tokenSlot ⟨-tx.encAmount.pt⟩)
              tx.recipient tx.tokenSlot tx.encAmount
  provenTotal := s.provenTotal
  version := s.version + 1
  registry := s.registry
  tokenCount := s.tokenCount

/-- **P2 / §N-3, solo half — TM-2.** With a verified per-token channelTxZKP,
    a solo transfer preserves the multi-token invariant: every (member,
    token) balance stays non-negative and EVERY token's total still equals
    its certified `provenTotal` (the transferred token conserves internally;
    the other 9 are untouched — see `transferMT_frame_bal`). -/
theorem transferMT_preserves_validity (s : EncBalanceStateMT) (tx : TransferMT)
    (hvalid : ValidEncStateMT s) (ht : TransferProvenMT tx s) :
    ValidEncStateMT (applyTransferMT s tx) := by
  obtain ⟨hnn, htot⟩ := hvalid
  obtain ⟨_hactive, hpos, hsolv⟩ := ht
  have hsolv' : tx.encAmount.pt ≤ (s.encBal tx.sender tx.tokenSlot).pt := hsolv
  constructor
  · intro j u
    show 0 ≤ (updCt2 (updCt2 s.encBal tx.sender tx.tokenSlot ⟨-tx.encAmount.pt⟩)
                tx.recipient tx.tokenSlot tx.encAmount j u).pt
    have hnj : 0 ≤ (s.encBal j u).pt := hnn j u
    have hns : 0 ≤ (s.encBal tx.sender tx.tokenSlot).pt := hnn tx.sender tx.tokenSlot
    have hnr : 0 ≤ (s.encBal tx.recipient tx.tokenSlot).pt :=
      hnn tx.recipient tx.tokenSlot
    by_cases hu : u = tx.tokenSlot
    · subst hu
      by_cases hr : j = tx.recipient
      · subst hr
        by_cases hrs : tx.recipient = tx.sender
        · simp [updCt2, hrs] <;> omega
        · simp [updCt2, hrs] <;> omega
      · by_cases hs : j = tx.sender
        · subst hs
          simp [updCt2, hr] <;> omega
        · simp [updCt2, hr, hs] <;> omega
    · simp [updCt2, hu] <;> omega
  · intro u
    have h1 := updCt2_mapTotal (updCt2 s.encBal tx.sender tx.tokenSlot
        ⟨-tx.encAmount.pt⟩) tx.recipient tx.tokenSlot tx.encAmount u
    have h2 := updCt2_mapTotal s.encBal tx.sender tx.tokenSlot
        ⟨-tx.encAmount.pt⟩ u
    have htot' : mapTotal2 s.encBal u = s.provenTotal u := htot u
    show mapTotal2 (updCt2 (updCt2 s.encBal tx.sender tx.tokenSlot
            ⟨-tx.encAmount.pt⟩) tx.recipient tx.tokenSlot tx.encAmount) u
        = s.provenTotal u
    by_cases hu : u = tx.tokenSlot
    · subst hu
      simp at h1 h2
      omega
    · simp [hu] at h1 h2
      omega

/-- **Frame, pointwise — the Lean analogue of TM-2's "other 9 positions
    proven unchanged" (§N-3 binding triple, clause 2).** For every member and
    every token OTHER than the transferred one, the balance is bit-for-bit
    the old balance: a solo transfer cannot move token t' value, for any
    t' ≠ tokenSlot, no matter who sends or receives. -/
theorem transferMT_frame_bal (s : EncBalanceStateMT) (tx : TransferMT)
    (m : Member) (t : TokenSlot) (ht : t ≠ tx.tokenSlot) :
    (applyTransferMT s tx).bal m t = s.bal m t := by
  simp [applyTransferMT, EncBalanceStateMT.bal, updCt2, ht]

/-- **Frame, bystander — TM-2 companion.** A member who is neither sender nor
    recipient keeps every token balance unchanged (all 10 positions). -/
theorem transferMT_frame_bystander (s : EncBalanceStateMT) (tx : TransferMT)
    (m : Member) (t : TokenSlot)
    (hs : m ≠ tx.sender) (hr : m ≠ tx.recipient) :
    (applyTransferMT s tx).bal m t = s.bal m t := by
  simp [applyTransferMT, EncBalanceStateMT.bal, updCt2, hs, hr]

/-- **Frame, per-token totals — P2 / TM-2.** Every token other than the
    transferred one keeps its exact channel total. -/
theorem transferMT_frame_total (s : EncBalanceStateMT) (tx : TransferMT)
    (t : TokenSlot) (ht : t ≠ tx.tokenSlot) :
    (applyTransferMT s tx).total t = s.total t := by
  show (applyTransferMT s tx).bal .m0 t + (applyTransferMT s tx).bal .m1 t
      + (applyTransferMT s tx).bal .m2 t
      = s.bal .m0 t + s.bal .m1 t + s.bal .m2 t
  rw [transferMT_frame_bal s tx .m0 t ht, transferMT_frame_bal s tx .m1 t ht,
      transferMT_frame_bal s tx .m2 t ht]

/-- Solo transfers never touch any token's certified total (intra-channel:
    `provenTotal` is per-token invariant). -/
theorem transferMT_provenTotal (s : EncBalanceStateMT) (tx : TransferMT)
    (t : TokenSlot) : (applyTransferMT s tx).provenTotal t = s.provenTotal t :=
  rfl

/-! ## §3 L1 deposit import, per token (detail2.md §N-5, TM-7) -/

/-- §N-5 three-way binding contract (TM-7, A2 + A4), ALL THREE legs: (a) the
    credited fund/certified total is `tokenSlot`'s (built into
    `applyL1DepositImportMT`); (b) the credited ciphertext is the depositor
    leaf's position-`tokenSlot` ciphertext (ditto); (c) the base deposit's
    `tokenIndex` resolves via the channel's OWN signed registry to exactly
    that ACTIVE local slot (`ResolvesMT` — this clause is what ties legs
    (a)/(b) to the L1 asset). Plus: the amount is non-negative and the
    ciphertext encrypts exactly that amount. -/
def L1DepositImportVerifiedMT (s : EncBalanceStateMT) (amount : Int)
    (tokenIndex : Nat) (tokenSlot : TokenSlot) (recipientDelta : Ct) : Prop :=
  ResolvesMT s tokenIndex tokenSlot ∧ 0 ≤ amount ∧ recipientDelta.pt = amount

/-- §N-5: credit the depositor's position-`tokenSlot` ciphertext AND bump
    `provenTotal tokenSlot` (`channel_fund[t] += amount`) — the same token
    slot on both sides, which is exactly TM-7's (a)↔(b) binding. All other
    token positions and totals untouched by construction. -/
def applyL1DepositImportMT (s : EncBalanceStateMT) (recipient : Member)
    (amount : Int) (tokenSlot : TokenSlot) (recipientDelta : Ct) :
    EncBalanceStateMT where
  encBal := updCt2 s.encBal recipient tokenSlot recipientDelta
  provenTotal := fun u => if u = tokenSlot then s.provenTotal u + amount
                          else s.provenTotal u
  version := s.version + 1
  registry := s.registry
  tokenCount := s.tokenCount

/-- **P2 / §N-5 — TM-7.** A verified L1 deposit import preserves the
    multi-token invariant, and grows exactly the imported token's certified
    total by exactly the deposited amount. -/
theorem l1_depositMT_preserves_validity (s : EncBalanceStateMT)
    (recipient : Member) (amount : Int) (tokenIndex : Nat)
    (tokenSlot : TokenSlot) (recipientDelta : Ct)
    (hvalid : ValidEncStateMT s)
    (hd : L1DepositImportVerifiedMT s amount tokenIndex tokenSlot recipientDelta) :
    ValidEncStateMT (applyL1DepositImportMT s recipient amount tokenSlot recipientDelta)
    ∧ (applyL1DepositImportMT s recipient amount tokenSlot recipientDelta).provenTotal
        tokenSlot = s.provenTotal tokenSlot + amount := by
  obtain ⟨hnn, htot⟩ := hvalid
  obtain ⟨_hres, hamt, hrd⟩ := hd
  refine ⟨⟨?_, ?_⟩, by simp [applyL1DepositImportMT]⟩
  · intro j u
    show 0 ≤ (updCt2 s.encBal recipient tokenSlot recipientDelta j u).pt
    have hnj : 0 ≤ (s.encBal j u).pt := hnn j u
    by_cases hj : j = recipient ∧ u = tokenSlot
    · obtain ⟨h1, h2⟩ := hj
      subst h1; subst h2
      simp [updCt2] <;> omega
    · rw [updCt2_not _ _ _ _ _ _ hj]
      exact hnj
  · intro u
    have h1 := updCt2_mapTotal s.encBal recipient tokenSlot recipientDelta u
    have htot' : mapTotal2 s.encBal u = s.provenTotal u := htot u
    show mapTotal2 (updCt2 s.encBal recipient tokenSlot recipientDelta) u
        = (if u = tokenSlot then s.provenTotal u + amount else s.provenTotal u)
    by_cases hu : u = tokenSlot
    · subst hu
      simp at h1 ⊢
      omega
    · simp [hu] at h1 ⊢
      omega

/-- **Frame — TM-7 / P2.** For every token other than the imported one, BOTH
    the channel total AND the certified `provenTotal` are unchanged: a
    deposit of token t cannot create or destroy token t' value or claim
    capacity. -/
theorem l1_depositMT_frame (s : EncBalanceStateMT) (recipient : Member)
    (amount : Int) (tokenSlot : TokenSlot) (recipientDelta : Ct)
    (t : TokenSlot) (ht : t ≠ tokenSlot) :
    (applyL1DepositImportMT s recipient amount tokenSlot recipientDelta).total t
        = s.total t
    ∧ (applyL1DepositImportMT s recipient amount tokenSlot recipientDelta).provenTotal t
        = s.provenTotal t := by
  constructor
  · have h1 := updCt2_mapTotal s.encBal recipient tokenSlot recipientDelta t
    show mapTotal2 (updCt2 s.encBal recipient tokenSlot recipientDelta) t
        = mapTotal2 s.encBal t
    simp [ht] at h1
    exact h1
  · show (if t = tokenSlot then s.provenTotal t + amount else s.provenTotal t)
        = s.provenTotal t
    rw [if_neg ht]

/-- **Frame, pointwise — TM-7.** Every (member, token) position other than
    (recipient, tokenSlot) keeps its exact ciphertext plaintext. -/
theorem l1_depositMT_frame_bal (s : EncBalanceStateMT) (recipient : Member)
    (amount : Int) (tokenSlot : TokenSlot) (recipientDelta : Ct)
    (j : Member) (u : TokenSlot) (h : ¬(j = recipient ∧ u = tokenSlot)) :
    (applyL1DepositImportMT s recipient amount tokenSlot recipientDelta).bal j u
        = s.bal j u := by
  show (updCt2 s.encBal recipient tokenSlot recipientDelta j u).pt
      = (s.encBal j u).pt
  rw [updCt2_not _ _ _ _ _ _ h]

/-- **TM-7 at the BASE-token level (M2).** With an injective registry, a
    verified import raises `baseTotal` of exactly the deposited base token by
    exactly the deposited amount, and leaves every OTHER base token's
    `baseTotal` unchanged: L1 escrow of token `tokenIndex` and the channel's
    token-`tokenIndex` value move in lockstep, and no other asset moves. -/
theorem l1_depositMT_baseTotal (s : EncBalanceStateMT) (recipient : Member)
    (amount : Int) (tokenIndex : Nat) (tokenSlot : TokenSlot)
    (recipientDelta : Ct)
    (hinj : RegistryInjective s)
    (hd : L1DepositImportVerifiedMT s amount tokenIndex tokenSlot recipientDelta) :
    baseTotal (applyL1DepositImportMT s recipient amount tokenSlot recipientDelta)
        tokenIndex
      = baseTotal s tokenIndex + amount
    ∧ ∀ Y : Nat, Y ≠ tokenIndex →
        baseTotal (applyL1DepositImportMT s recipient amount tokenSlot recipientDelta) Y
          = baseTotal s Y := by
  obtain ⟨hres, _hamt, hrd⟩ := hd
  have hres' := resolvesMT_of_header_eq s
    (applyL1DepositImportMT s recipient amount tokenSlot recipientDelta)
    tokenIndex tokenSlot (fun _ => rfl) rfl hres
  have hinj' := registryInjective_of_header_eq s
    (applyL1DepositImportMT s recipient amount tokenSlot recipientDelta)
    (fun _ => rfl) rfl hinj
  constructor
  · have hb1 := baseTotal_eq_total_of_resolves
      (applyL1DepositImportMT s recipient amount tokenSlot recipientDelta)
      tokenIndex tokenSlot hres' hinj'
    have hb2 := baseTotal_eq_total_of_resolves s tokenIndex tokenSlot hres hinj
    have h3 : (applyL1DepositImportMT s recipient amount tokenSlot
        recipientDelta).total tokenSlot = s.total tokenSlot + amount := by
      have h := updCt2_mapTotal s.encBal recipient tokenSlot recipientDelta
        tokenSlot
      show mapTotal2 (updCt2 s.encBal recipient tokenSlot recipientDelta)
          tokenSlot = mapTotal2 s.encBal tokenSlot + amount
      simp at h
      omega
    omega
  · intro Y hY
    refine baseTotal_congr s
      (applyL1DepositImportMT s recipient amount tokenSlot recipientDelta) Y
      (fun _ => rfl) rfl ?_
    intro t' _hlt hregt
    have hne : t' ≠ tokenSlot := by
      intro h
      subst h
      exact hY (hregt.symm.trans hres.2)
    exact (l1_depositMT_frame s recipient amount tokenSlot recipientDelta
      t' hne).1

/-! ## §4 TokenRegister (detail2.md §N-1, TM-1/TM-8/TM-9) -/

/-- §N-1 `ChannelTransitionKind::TokenRegister`: append `baseIndex` at
    position `tokenCount`, increment `tokenCount`, bump the version. Leaves
    are UNTOUCHED (header-only change): `encBal` and `provenTotal` are
    carried over verbatim. -/
def applyTokenRegister (s : EncBalanceStateMT) (baseIndex : Nat) :
    EncBalanceStateMT where
  encBal := s.encBal
  provenTotal := s.provenTotal
  version := s.version + 1
  registry := fun u => if u.val = s.tokenCount then baseIndex else s.registry u
  tokenCount := s.tokenCount + 1

/-- **TM-1 (in-circuit duplicate rejection).** If the appended base index is
    fresh (not the base index of any currently active slot — the check the
    `TokenRegister` circuit performs), registry injectivity is preserved.
    Together with an injective initial registry this maintains TM-1's
    invariant inductively across any sequence of registrations. -/
theorem tokenRegister_preserves_injectivity (s : EncBalanceStateMT)
    (baseIndex : Nat)
    (hinj : RegistryInjective s)
    (hfresh : ∀ t : TokenSlot, ActiveToken s t → s.registry t ≠ baseIndex) :
    RegistryInjective (applyTokenRegister s baseIndex) := by
  intro t1 t2 h1 h2 heq
  have h1' : t1.val < s.tokenCount + 1 := h1
  have h2' : t2.val < s.tokenCount + 1 := h2
  show t1 = t2
  simp only [applyTokenRegister] at heq
  by_cases e1 : t1.val = s.tokenCount
  · by_cases e2 : t2.val = s.tokenCount
    · exact Fin.eq_of_val_eq (e1.trans e2.symm)
    · exfalso
      have ha2 : ActiveToken s t2 := by
        show t2.val < s.tokenCount
        omega
      rw [if_pos e1, if_neg e2] at heq
      exact hfresh t2 ha2 heq.symm
  · by_cases e2 : t2.val = s.tokenCount
    · exfalso
      have ha1 : ActiveToken s t1 := by
        show t1.val < s.tokenCount
        omega
      rw [if_neg e1, if_pos e2] at heq
      exact hfresh t1 ha1 heq
    · have ha1 : ActiveToken s t1 := by
        show t1.val < s.tokenCount
        omega
      have ha2 : ActiveToken s t2 := by
        show t2.val < s.tokenCount
        omega
      rw [if_neg e1, if_neg e2] at heq
      exact hinj t1 t2 ha1 ha2 heq

/-- **§N-1 "header-only state change".** TokenRegister touches no balance, no
    per-token total, and no certified total: registering a token cannot move
    or create value in ANY token (the strongest form of the no-cross-token
    property for this step kind). -/
theorem tokenRegister_preserves_balances (s : EncBalanceStateMT) (baseIndex : Nat) :
    (∀ (m : Member) (t : TokenSlot),
        (applyTokenRegister s baseIndex).bal m t = s.bal m t)
    ∧ (∀ t : TokenSlot, (applyTokenRegister s baseIndex).total t = s.total t)
    ∧ (∀ t : TokenSlot,
        (applyTokenRegister s baseIndex).provenTotal t = s.provenTotal t) :=
  ⟨fun _ _ => rfl, fun _ => rfl, fun _ => rfl⟩

/-- TokenRegister preserves the multi-token validity invariant (immediate
    from `tokenRegister_preserves_balances`). -/
theorem tokenRegister_preserves_validity (s : EncBalanceStateMT)
    (baseIndex : Nat) (hvalid : ValidEncStateMT s) :
    ValidEncStateMT (applyTokenRegister s baseIndex) :=
  hvalid

/-- TM-8: registering below the 10-slot capacity keeps `tokenCount` in
    `[1, 10]`. -/
theorem tokenRegister_preserves_bounded (s : EncBalanceStateMT)
    (baseIndex : Nat) (hb : TokenCountBounded s) (hcap : s.tokenCount < 10) :
    TokenCountBounded (applyTokenRegister s baseIndex) := by
  obtain ⟨hlo, _⟩ := hb
  exact ⟨by show 1 ≤ s.tokenCount + 1; omega,
         by show s.tokenCount + 1 ≤ 10; omega⟩

/-- §N-1 "no removal, no reorder — local index stability": every previously
    active slot keeps its exact base `token_index` (historical ciphertexts
    keep a stable meaning). -/
theorem tokenRegister_frame_registry (s : EncBalanceStateMT) (baseIndex : Nat)
    (t : TokenSlot) (ht : ActiveToken s t) :
    (applyTokenRegister s baseIndex).registry t = s.registry t := by
  have htv : t.val < s.tokenCount := ht
  have hne : t.val ≠ s.tokenCount := by omega
  show (if t.val = s.tokenCount then baseIndex else s.registry t) = s.registry t
  rw [if_neg hne]

/-- §N-1 append semantics: the new slot (position `tokenCount`) carries the
    appended base index and becomes active. -/
theorem tokenRegister_appends (s : EncBalanceStateMT) (baseIndex : Nat)
    (t : TokenSlot) (htv : t.val = s.tokenCount) :
    (applyTokenRegister s baseIndex).registry t = baseIndex
    ∧ ActiveToken (applyTokenRegister s baseIndex) t := by
  constructor
  · show (if t.val = s.tokenCount then baseIndex else s.registry t) = baseIndex
    rw [if_pos htv]
  · show t.val < s.tokenCount + 1
    omega

/-! ## §5 Batched intra-channel transfer, mixed-token (detail2.md §N-3 slim
wire / v2.1b generalization, TM-14)

The v2.1b batch of `ChannelSafety21.lean` §8, with the token dimension:
each batch tx carries its own `tokenSlot` (mixed-token batches allowed,
§N-3), the R1 single-debit rule becomes per (sender, tokenSlot) PAIR, and
the canonical debit-then-credit fold is per (member, token) position. TM-14's
obligation — every cosigner's per-tx check covers the FULL binding triple
over all 10 positions — enters as `BatchTxProvenMT` per tx. -/

/-- One tx of a v2.1b batch, per token: `amount` is the plaintext amount,
    `encAmount` its recipient-key encryption, `afterCt` the sender's fresh
    post-debit ciphertext at `tokenSlot` — all stated against the ANCHOR
    state (§M-2 binding refinement, generalized per token). -/
structure BatchTxMT where
  sender : Member
  recipient : Member
  tokenSlot : TokenSlot
  amount : Int
  encAmount : Ct
  afterCt : Ct

/-- channelTxZKP statement of one batch tx against the anchor state `s`,
    per token (TM-14): active slot, non-negative amount, `encAmount`
    encrypts it, and `afterCt` encrypts the sender's anchor balance AT THAT
    TOKEN minus the amount, non-negative. -/
def BatchTxProvenMT (s : EncBalanceStateMT) (tx : BatchTxMT) : Prop :=
  ActiveToken s tx.tokenSlot
  ∧ 0 ≤ tx.amount
  ∧ tx.encAmount.pt = tx.amount
  ∧ tx.afterCt.pt = s.bal tx.sender tx.tokenSlot - tx.amount
  ∧ 0 ≤ tx.afterCt.pt

/-- R1 per (sender, token): the debited (member, token) PAIRS are pairwise
    distinct — the same member may debit two different tokens in one batch,
    but no (member, token) position is debited twice. -/
def sendersDistinctMT : List BatchTxMT → Prop
  | [] => True
  | tx :: rest =>
      (∀ v ∈ rest, v.sender ≠ tx.sender ∨ v.tokenSlot ≠ tx.tokenSlot)
      ∧ sendersDistinctMT rest

/-- What every co-signer checks before signing a mixed-token batch (§N-3 /
    TM-14): every tx's full per-token obligation, plus R1 per (slot, token). -/
def BatchProvenMT (s : EncBalanceStateMT) (txs : List BatchTxMT) : Prop :=
  (∀ tx ∈ txs, BatchTxProvenMT s tx) ∧ sendersDistinctMT txs

/-- Debit pass of the canonical fold: install each tx's fresh `after`
    ciphertext at its (sender, tokenSlot) position. -/
def debitFoldMT (f : Member → TokenSlot → Ct) :
    List BatchTxMT → (Member → TokenSlot → Ct)
  | [] => f
  | tx :: rest => debitFoldMT (setCt2 f tx.sender tx.tokenSlot tx.afterCt) rest

/-- Credit pass of the canonical fold: homomorphically add each tx's
    `encAmount` at its (recipient, tokenSlot) position. -/
def creditFoldMT (f : Member → TokenSlot → Ct) :
    List BatchTxMT → (Member → TokenSlot → Ct)
  | [] => f
  | tx :: rest => creditFoldMT (updCt2 f tx.recipient tx.tokenSlot tx.encAmount) rest

/-- §N-3 canonical fold, per (member, token): debits first (against the
    anchor), then credits. ONE version bump for the whole batch; every
    token's `provenTotal` unchanged (intra-channel); registry unchanged. -/
def applyBatchMT (s : EncBalanceStateMT) (txs : List BatchTxMT) :
    EncBalanceStateMT where
  encBal := creditFoldMT (debitFoldMT s.encBal txs) txs
  provenTotal := s.provenTotal
  version := s.version + 1
  registry := s.registry
  tokenCount := s.tokenCount

/-- Sum of the amounts a batch moves WITHIN token `t` (mixed-token batches
    contribute only their token-`t` txs). -/
def amtSumAt (t : TokenSlot) : List BatchTxMT → Int
  | [] => 0
  | tx :: rest => (if tx.tokenSlot = t then tx.amount else 0) + amtSumAt t rest

/-- Credits add exactly the encrypted amounts, token by token. -/
theorem creditFoldMT_total (txs : List BatchTxMT) (f : Member → TokenSlot → Ct)
    (hprf : ∀ tx ∈ txs, tx.encAmount.pt = tx.amount) (u : TokenSlot) :
    mapTotal2 (creditFoldMT f txs) u = mapTotal2 f u + amtSumAt u txs := by
  induction txs generalizing f with
  | nil => simp [creditFoldMT, amtSumAt]
  | cons tx rest ih =>
    have ht := hprf tx (List.mem_cons_self _ _)
    have ihr := ih (updCt2 f tx.recipient tx.tokenSlot tx.encAmount)
      (fun v hv => hprf v (List.mem_cons_of_mem _ hv))
    simp only [creditFoldMT, amtSumAt]
    rw [ihr, updCt2_mapTotal]
    by_cases hu : u = tx.tokenSlot
    · subst hu
      simp [ht] <;> omega
    · simp [hu, Ne.symm hu] <;> omega

/-- Debits remove exactly the amounts, token by token, provided each debit
    still sees the ANCHOR ciphertext of its (sender, token) position —
    guaranteed by R1: earlier debits in the fold touch other positions. -/
theorem debitFoldMT_total (s : EncBalanceStateMT) (txs : List BatchTxMT)
    (f : Member → TokenSlot → Ct)
    (hagree : ∀ tx ∈ txs,
        f tx.sender tx.tokenSlot = s.encBal tx.sender tx.tokenSlot)
    (hdist : sendersDistinctMT txs)
    (hprf : ∀ tx ∈ txs, BatchTxProvenMT s tx) (u : TokenSlot) :
    mapTotal2 (debitFoldMT f txs) u = mapTotal2 f u - amtSumAt u txs := by
  induction txs generalizing f with
  | nil => simp [debitFoldMT, amtSumAt]
  | cons tx rest ih =>
    obtain ⟨hhead, hrest⟩ := hdist
    obtain ⟨_, _, _, hafter, _⟩ := hprf tx (List.mem_cons_self _ _)
    have hat : f tx.sender tx.tokenSlot = s.encBal tx.sender tx.tokenSlot :=
      hagree tx (List.mem_cons_self _ _)
    have hat' : (f tx.sender tx.tokenSlot).pt
        = (s.encBal tx.sender tx.tokenSlot).pt := by rw [hat]
    have hbal : s.bal tx.sender tx.tokenSlot
        = (s.encBal tx.sender tx.tokenSlot).pt := rfl
    have hagree' : ∀ v ∈ rest,
        (setCt2 f tx.sender tx.tokenSlot tx.afterCt) v.sender v.tokenSlot
          = s.encBal v.sender v.tokenSlot := by
      intro v hv
      rw [setCt2_ne _ _ _ _ _ _ (hhead v hv)]
      exact hagree v (List.mem_cons_of_mem _ hv)
    have ihr := ih (setCt2 f tx.sender tx.tokenSlot tx.afterCt) hagree' hrest
      (fun v hv => hprf v (List.mem_cons_of_mem _ hv))
    simp only [debitFoldMT, amtSumAt]
    rw [ihr, setCt2_mapTotal]
    by_cases hu : u = tx.tokenSlot
    · subst hu
      simp <;> omega
    · simp [hu, Ne.symm hu] <;> omega

/-- Pointwise: credits never decrease any (member, token) position. -/
theorem creditFoldMT_ge (txs : List BatchTxMT) (f : Member → TokenSlot → Ct)
    (hnn : ∀ tx ∈ txs, 0 ≤ tx.encAmount.pt) (j : Member) (u : TokenSlot) :
    (f j u).pt ≤ (creditFoldMT f txs j u).pt := by
  induction txs generalizing f with
  | nil => simp [creditFoldMT]
  | cons tx rest ih =>
    have ht := hnn tx (List.mem_cons_self _ _)
    have h2 := ih (updCt2 f tx.recipient tx.tokenSlot tx.encAmount)
      (fun v hv => hnn v (List.mem_cons_of_mem _ hv))
    have step : (f j u).pt
        ≤ (updCt2 f tx.recipient tx.tokenSlot tx.encAmount j u).pt := by
      by_cases hj : j = tx.recipient ∧ u = tx.tokenSlot
      · obtain ⟨h1, h2'⟩ := hj
        subst h1; subst h2'
        simp [updCt2] <;> omega
      · rw [updCt2_not _ _ _ _ _ _ hj]
        omega
    simp only [creditFoldMT]
    omega

/-- Pointwise: after all debits every (member, token) position is still
    non-negative (each installed `afterCt` is proven non-negative). -/
theorem debitFoldMT_nonneg (s : EncBalanceStateMT) (txs : List BatchTxMT)
    (f : Member → TokenSlot → Ct)
    (hf : ∀ (j : Member) (u : TokenSlot), 0 ≤ (f j u).pt)
    (hprf : ∀ tx ∈ txs, BatchTxProvenMT s tx) (j : Member) (u : TokenSlot) :
    0 ≤ (debitFoldMT f txs j u).pt := by
  induction txs generalizing f with
  | nil => exact hf j u
  | cons tx rest ih =>
    obtain ⟨_, _, _, _, hpos⟩ := hprf tx (List.mem_cons_self _ _)
    have hf' : ∀ (k : Member) (w : TokenSlot),
        0 ≤ ((setCt2 f tx.sender tx.tokenSlot tx.afterCt) k w).pt := by
      intro k w
      by_cases hk : k = tx.sender ∧ w = tx.tokenSlot
      · obtain ⟨h1, h2⟩ := hk
        subst h1; subst h2
        simp [setCt2] <;> omega
      · rw [setCt2_not _ _ _ _ _ _ hk]
        exact hf k w
    exact ih (setCt2 f tx.sender tx.tokenSlot tx.afterCt) hf'
      (fun v hv => hprf v (List.mem_cons_of_mem _ hv))

/-- **P2 / TM-14: per-token conservation of a mixed-token batch.** For EVERY
    token slot t, a proven batch conserves the channel's token-t total (each
    tx debits and credits within its own token; tokens never mix). -/
theorem batchMT_conserves_total (s : EncBalanceStateMT) (txs : List BatchTxMT)
    (h : BatchProvenMT s txs) (t : TokenSlot) :
    (applyBatchMT s txs).total t = s.total t := by
  obtain ⟨hprf, hdist⟩ := h
  have henc : ∀ tx ∈ txs, tx.encAmount.pt = tx.amount :=
    fun tx htx => (hprf tx htx).2.2.1
  have hd := debitFoldMT_total s txs s.encBal (fun _ _ => rfl) hdist hprf t
  have hc := creditFoldMT_total txs (debitFoldMT s.encBal txs) henc t
  show mapTotal2 (creditFoldMT (debitFoldMT s.encBal txs) txs) t
      = mapTotal2 s.encBal t
  omega

/-- **§N-3 / TM-14 main batch theorem.** A proven mixed-token batch (R1 per
    (slot, token); sender-as-recipient allowed) preserves the multi-token
    invariant and leaves every token's `provenTotal` untouched. -/
theorem batchMT_preserves_validity (s : EncBalanceStateMT)
    (txs : List BatchTxMT) (hvalid : ValidEncStateMT s)
    (h : BatchProvenMT s txs) :
    ValidEncStateMT (applyBatchMT s txs)
    ∧ (∀ t : TokenSlot, (applyBatchMT s txs).provenTotal t = s.provenTotal t) := by
  obtain ⟨hnn, htot⟩ := hvalid
  obtain ⟨hprf, hdist⟩ := h
  refine ⟨⟨?_, ?_⟩, fun _ => rfl⟩
  · intro j u
    have hmid := debitFoldMT_nonneg s txs s.encBal (fun k w => hnn k w) hprf j u
    have hge := creditFoldMT_ge txs (debitFoldMT s.encBal txs)
      (fun tx htx => by
        obtain ⟨_, hamt, henc, _, _⟩ := hprf tx htx
        omega) j u
    show 0 ≤ (creditFoldMT (debitFoldMT s.encBal txs) txs j u).pt
    omega
  · intro u
    have hcons := batchMT_conserves_total s txs ⟨hprf, hdist⟩ u
    have htot' : s.total u = s.provenTotal u := htot u
    show (applyBatchMT s txs).total u = s.provenTotal u
    omega

/-! ### Mixed-token frame (TM-2 × TM-14) -/

/-- Tx `tx` touches position (m, t) iff (m, t) is its debit point or its
    credit point. -/
def TouchesMT (tx : BatchTxMT) (m : Member) (t : TokenSlot) : Prop :=
  (m = tx.sender ∧ t = tx.tokenSlot) ∨ (m = tx.recipient ∧ t = tx.tokenSlot)

theorem debitFoldMT_untouched (txs : List BatchTxMT)
    (f : Member → TokenSlot → Ct) (m : Member) (t : TokenSlot)
    (h : ∀ tx ∈ txs, ¬(m = tx.sender ∧ t = tx.tokenSlot)) :
    debitFoldMT f txs m t = f m t := by
  induction txs generalizing f with
  | nil => rfl
  | cons tx rest ih =>
    have htx := h tx (List.mem_cons_self _ _)
    simp only [debitFoldMT]
    rw [ih (setCt2 f tx.sender tx.tokenSlot tx.afterCt)
        (fun v hv => h v (List.mem_cons_of_mem _ hv))]
    exact setCt2_not _ _ _ _ _ _ htx

theorem creditFoldMT_untouched (txs : List BatchTxMT)
    (f : Member → TokenSlot → Ct) (m : Member) (t : TokenSlot)
    (h : ∀ tx ∈ txs, ¬(m = tx.recipient ∧ t = tx.tokenSlot)) :
    creditFoldMT f txs m t = f m t := by
  induction txs generalizing f with
  | nil => rfl
  | cons tx rest ih =>
    have htx := h tx (List.mem_cons_self _ _)
    simp only [creditFoldMT]
    rw [ih (updCt2 f tx.recipient tx.tokenSlot tx.encAmount)
        (fun v hv => h v (List.mem_cons_of_mem _ hv))]
    exact updCt2_not _ _ _ _ _ _ htx

/-- **Mixed-token frame theorem — TM-2's "other 9 unchanged", batch form
    (TM-14).** The batch fold changes a (member, token) balance ONLY if some
    tx in the batch actually debits or credits that exact position; every
    untouched position keeps its bit-for-bit anchor value. Needs NO proof
    hypotheses: it is structural in the fold. -/
theorem batchMT_frame (s : EncBalanceStateMT) (txs : List BatchTxMT)
    (m : Member) (t : TokenSlot)
    (h : ∀ tx ∈ txs, ¬ TouchesMT tx m t) :
    (applyBatchMT s txs).bal m t = s.bal m t := by
  have hs : ∀ tx ∈ txs, ¬(m = tx.sender ∧ t = tx.tokenSlot) :=
    fun tx htx hc => h tx htx (Or.inl hc)
  have hr : ∀ tx ∈ txs, ¬(m = tx.recipient ∧ t = tx.tokenSlot) :=
    fun tx htx hc => h tx htx (Or.inr hc)
  show (creditFoldMT (debitFoldMT s.encBal txs) txs m t).pt = (s.encBal m t).pt
  rw [creditFoldMT_untouched txs (debitFoldMT s.encBal txs) m t hr,
      debitFoldMT_untouched txs s.encBal m t hs]

/-- **Per-token batch frame — P2.** A token no tx of the batch moves keeps
    its exact channel total (structural, no proof hypotheses needed). -/
theorem batchMT_frame_total (s : EncBalanceStateMT) (txs : List BatchTxMT)
    (t : TokenSlot) (h : ∀ tx ∈ txs, tx.tokenSlot ≠ t) :
    (applyBatchMT s txs).total t = s.total t := by
  have huntouched : ∀ m : Member, ∀ tx ∈ txs, ¬ TouchesMT tx m t := by
    intro m tx htx hc
    cases hc with
    | inl hc => exact h tx htx hc.2.symm
    | inr hc => exact h tx htx hc.2.symm
  show (applyBatchMT s txs).bal .m0 t + (applyBatchMT s txs).bal .m1 t
      + (applyBatchMT s txs).bal .m2 t
      = s.bal .m0 t + s.bal .m1 t + s.bal .m2 t
  rw [batchMT_frame s txs .m0 t (huntouched .m0),
      batchMT_frame s txs .m1 t (huntouched .m1),
      batchMT_frame s txs .m2 t (huntouched .m2)]

/-! ### Sequential equivalence (mirror of ChannelSafety21 §4.2b (1)) -/

/-- One tx applied the solo §N-3 way: install the sender's fresh `after`
    ciphertext at (sender, tokenSlot), then credit (recipient, tokenSlot). -/
def seqStepMT (f : Member → TokenSlot → Ct) (tx : BatchTxMT) :
    Member → TokenSlot → Ct :=
  updCt2 (setCt2 f tx.sender tx.tokenSlot tx.afterCt)
    tx.recipient tx.tokenSlot tx.encAmount

def seqFoldMT (f : Member → TokenSlot → Ct) :
    List BatchTxMT → (Member → TokenSlot → Ct)
  | [] => f
  | tx :: rest => seqFoldMT (seqStepMT f tx) rest

/-- A replace at (m, t) and a homomorphic add at (r, t') commute when the two
    points differ in the member OR the token. -/
theorem setCt2_updCt2_comm (f : Member → TokenSlot → Ct)
    (m : Member) (t : TokenSlot) (c : Ct)
    (r : Member) (t' : TokenSlot) (d : Ct)
    (hne : m ≠ r ∨ t ≠ t') :
    setCt2 (updCt2 f r t' d) m t c = updCt2 (setCt2 f m t c) r t' d := by
  funext j u
  by_cases h1 : j = m ∧ u = t
  · obtain ⟨hjm, hut⟩ := h1
    have h2 : ¬(j = r ∧ u = t') := by
      intro hc
      obtain ⟨hjr, hut'⟩ := hc
      cases hne with
      | inl h => exact h (hjm.symm.trans hjr)
      | inr h => exact h (hut.symm.trans hut')
    rw [updCt2_not _ _ _ _ _ _ h2, hjm, hut, setCt2_same, setCt2_same]
  · rw [setCt2_not _ _ _ _ _ _ h1]
    by_cases h2 : j = r ∧ u = t'
    · obtain ⟨hjr, hut'⟩ := h2
      have h1' : ¬(r = m ∧ t' = t) := fun hc =>
        h1 ⟨hjr.trans hc.1, hut'.trans hc.2⟩
      rw [hjr, hut', updCt2_same, updCt2_same, setCt2_not _ _ _ _ _ _ h1']
    · rw [updCt2_not _ _ _ _ _ _ h2, updCt2_not _ _ _ _ _ _ h2,
          setCt2_not _ _ _ _ _ _ h1]

theorem debitFoldMT_updCt2_comm (rest : List BatchTxMT)
    (f : Member → TokenSlot → Ct) (r : Member) (t' : TokenSlot) (d : Ct)
    (hne : ∀ v ∈ rest, v.sender ≠ r ∨ v.tokenSlot ≠ t') :
    updCt2 (debitFoldMT f rest) r t' d = debitFoldMT (updCt2 f r t' d) rest := by
  induction rest generalizing f with
  | nil => rfl
  | cons v tail ih =>
    have hv := hne v (List.mem_cons_self _ _)
    simp only [debitFoldMT]
    rw [ih (setCt2 f v.sender v.tokenSlot v.afterCt)
        (fun w hw => hne w (List.mem_cons_of_mem _ hw))]
    rw [setCt2_updCt2_comm f v.sender v.tokenSlot v.afterCt r t' d hv]

private theorem creditDebitMT_eq_seq (txs : List BatchTxMT) :
    ∀ (f : Member → TokenSlot → Ct), sendersDistinctMT txs →
      (∀ a ∈ txs, ∀ b ∈ txs, a.sender ≠ b.recipient ∨ a.tokenSlot ≠ b.tokenSlot) →
      creditFoldMT (debitFoldMT f txs) txs = seqFoldMT f txs := by
  induction txs with
  | nil => intro f _ _; rfl
  | cons tx rest ih =>
    intro f hdist hdisj
    obtain ⟨_hhead, hrest⟩ := hdist
    have hdisj' : ∀ a ∈ rest, ∀ b ∈ rest,
        a.sender ≠ b.recipient ∨ a.tokenSlot ≠ b.tokenSlot :=
      fun a ha b hb =>
        hdisj a (List.mem_cons_of_mem _ ha) b (List.mem_cons_of_mem _ hb)
    have hcredit_t : ∀ v ∈ rest,
        v.sender ≠ tx.recipient ∨ v.tokenSlot ≠ tx.tokenSlot :=
      fun v hv =>
        hdisj v (List.mem_cons_of_mem _ hv) tx (List.mem_cons_self _ _)
    simp only [debitFoldMT, creditFoldMT, seqFoldMT]
    rw [debitFoldMT_updCt2_comm rest (setCt2 f tx.sender tx.tokenSlot tx.afterCt)
        tx.recipient tx.tokenSlot tx.encAmount hcredit_t]
    exact ih (updCt2 (setCt2 f tx.sender tx.tokenSlot tx.afterCt)
        tx.recipient tx.tokenSlot tx.encAmount) hrest hdisj'

/-- **§N-3 / TM-14 sequential equivalence (mirror of `batch_step_eq_seq`).**
    When no (member, token) debit point is also a credit point in the batch,
    the canonical fold equals the sequential per-tx application: a
    mixed-token batch is literally a compressed run of K solo §N-3 steps
    sharing one agreement round. -/
theorem batchMT_step_eq_seq (s : EncBalanceStateMT) (txs : List BatchTxMT)
    (hdist : sendersDistinctMT txs)
    (hdisj : ∀ a ∈ txs, ∀ b ∈ txs,
        a.sender ≠ b.recipient ∨ a.tokenSlot ≠ b.tokenSlot) :
    (applyBatchMT s txs).encBal = seqFoldMT s.encBal txs :=
  creditDebitMT_eq_seq txs s.encBal hdist hdisj

/-- K = 1 degenerates to the single-tx transition (sender ≠ recipient). -/
theorem batchMT_singleton_eq_single (s : EncBalanceStateMT) (tx : BatchTxMT)
    (hne : tx.sender ≠ tx.recipient) :
    (applyBatchMT s [tx]).encBal = seqStepMT s.encBal tx := by
  have hdist : sendersDistinctMT [tx] := by simp [sendersDistinctMT]
  have hdisj : ∀ a ∈ [tx], ∀ b ∈ [tx],
      a.sender ≠ b.recipient ∨ a.tokenSlot ≠ b.tokenSlot := by
    intro a ha b hb
    simp at ha hb
    subst ha; subst hb
    exact Or.inl hne
  have h := batchMT_step_eq_seq s [tx] hdist hdisj
  simpa [seqFoldMT] using h

/-! ## §6 Inter-channel (C2C) transfer: base token_index end-to-end
(detail2.md §N-4, TM-6)

The per-token generalization of ChannelSafety21's inter-channel bulk model
(`BulkChannelUpdate` / `bulk_interChannel_conservation_dest` / `_bound`).
The C2C descriptor carries the BASE `tokenIndex : Nat` — never a local slot
(§N-4): source and destination channels each resolve it against their OWN
signed registry to independent local slots `ts` / `td`. That in-circuit
resolution (`ResolvesMT`, the TM-6 contract) is what pins the credited
ciphertext position; `sampleC2C_misresolution_breaks_conservation` in §8
shows it is load-bearing. -/

/-- One receive leg of a bulk C2C update: destination channel id, recipient
    member in that channel, plaintext amount, and its recipient-key
    encryption (mirror of ChannelSafety21's `TransferEntry`). The token is
    NOT per-entry: the whole update moves one base token (§N-4). -/
structure TransferEntryMT where
  dest : Nat
  recipient : Member
  amount : Int
  recipientDelta : Ct

/-- §N-4 bulk C2C descriptor, per base token: `tokenIndex` is the BASE token
    index (spec.md §1.1), `senderDelta` the (negative) ciphertext added to
    the sender's resolved source slot, `entries` the receive legs. -/
structure BulkChannelUpdateMT where
  tokenIndex : Nat
  totalAmount : Int
  senderDelta : Ct
  entries : List TransferEntryMT

def entryAmountSumMT : List TransferEntryMT → Int
  | [] => 0
  | e :: rest => e.amount + entryAmountSumMT rest

def entriesForDestMT (dest : Nat) (entries : List TransferEntryMT) :
    List TransferEntryMT :=
  entries.filter (fun e => decide (e.dest = dest))

def destAmountSumMT (dest : Nat) (entries : List TransferEntryMT) : Int :=
  entryAmountSumMT (entriesForDestMT dest entries)

theorem entriesForDestMT_eq_of_forall (dest : Nat)
    (entries : List TransferEntryMT) (h : ∀ e ∈ entries, e.dest = dest) :
    entriesForDestMT dest entries = entries := by
  unfold entriesForDestMT
  induction entries with
  | nil => rfl
  | cons e rest ih =>
    have he : decide (e.dest = dest) = true := by
      rw [decide_eq_true_iff]; exact h e (List.mem_cons_self _ _)
    have ihr := ih fun e' hmem => h e' (List.mem_cons_of_mem _ hmem)
    simp [List.filter, he, ihr]

/-- §N-4 channelUpdateZKP soundness contract per base token (A2 + TM-6),
    source side: the source registry resolves `tokenIndex` at `ts`, the
    amounts are consistent and non-negative, the sender delta debits exactly
    `totalAmount`, and the sender's balance AT THE RESOLVED SLOT covers it.
    Mirrors ChannelSafety21's `BulkUpdateProven` plus the registry clause. -/
def BulkUpdateProvenMT (u : BulkChannelUpdateMT) (s : EncBalanceStateMT)
    (sender : Member) (ts : TokenSlot) : Prop :=
  ResolvesMT s u.tokenIndex ts
  ∧ u.totalAmount = entryAmountSumMT u.entries
  ∧ 0 ≤ u.totalAmount
  ∧ u.senderDelta.pt = -u.totalAmount
  ∧ (∀ e ∈ u.entries, 0 ≤ e.amount ∧ e.recipientDelta.pt = e.amount)
  ∧ u.totalAmount ≤ s.bal sender ts

def RecipientEntryVerifiedMT (e : TransferEntryMT) : Prop :=
  0 ≤ e.amount ∧ e.recipientDelta.pt = e.amount

/-- What the DESTINATION channel verifies (TM-6): its own registry resolves
    the descriptor's base `tokenIndex` at `td`, and each of its legs credits
    exactly its stated non-negative amount. Sender-side solvency is not
    re-checkable by the receiver (as in ChannelSafety2 §4). -/
def RecipientBulkVerifiedMT (dest : Nat) (u : BulkChannelUpdateMT)
    (r : EncBalanceStateMT) (td : TokenSlot) : Prop :=
  ResolvesMT r u.tokenIndex td
  ∧ ∀ e ∈ entriesForDestMT dest u.entries, RecipientEntryVerifiedMT e

/-- §N-4 source side: sender's position-`ts` ciphertext takes the (negative)
    delta; `provenTotal ts` drops by `totalAmount`; all other token slots
    untouched by construction; registry header unchanged. -/
def applyBulkSendMT (s : EncBalanceStateMT) (sender : Member) (ts : TokenSlot)
    (u : BulkChannelUpdateMT) : EncBalanceStateMT where
  encBal := updCt2 s.encBal sender ts u.senderDelta
  provenTotal := fun w => if w = ts then s.provenTotal w - u.totalAmount
                          else s.provenTotal w
  version := s.version + 1
  registry := s.registry
  tokenCount := s.tokenCount

/-- Credit one receive leg at the DESTINATION-resolved slot `td` (no version
    bump; the bulk receive folds these). -/
def applyEntryCreditMT (td : TokenSlot) (st : EncBalanceStateMT)
    (e : TransferEntryMT) : EncBalanceStateMT where
  encBal := updCt2 st.encBal e.recipient td e.recipientDelta
  provenTotal := fun w => if w = td then st.provenTotal w + e.amount
                          else st.provenTotal w
  version := st.version
  registry := st.registry
  tokenCount := st.tokenCount

/-- §N-4 destination side: fold all legs addressed to this channel, crediting
    each at (leg recipient, `td`); one version bump for the whole receive. -/
def applyBulkReceiveMT (r : EncBalanceStateMT) (dest : Nat) (td : TokenSlot)
    (u : BulkChannelUpdateMT) : EncBalanceStateMT :=
  { (entriesForDestMT dest u.entries).foldl (applyEntryCreditMT td) r with
    version := r.version + 1 }

/-- The credit fold never touches the registry header (TM-9: header changes
    only via `TokenRegister`). -/
theorem foldlEntryCreditMT_header (td : TokenSlot) (es : List TransferEntryMT)
    (init : EncBalanceStateMT) :
    (es.foldl (applyEntryCreditMT td) init).registry = init.registry
    ∧ (es.foldl (applyEntryCreditMT td) init).tokenCount = init.tokenCount := by
  induction es generalizing init with
  | nil => exact ⟨rfl, rfl⟩
  | cons e rest ih =>
    simp only [List.foldl]
    exact ih (applyEntryCreditMT td init e)

/-- A bulk receive never touches the registry header. -/
theorem applyBulkReceiveMT_header (r : EncBalanceStateMT) (dest : Nat)
    (td : TokenSlot) (u : BulkChannelUpdateMT) :
    (applyBulkReceiveMT r dest td u).registry = r.registry
    ∧ (applyBulkReceiveMT r dest td u).tokenCount = r.tokenCount :=
  foldlEntryCreditMT_header td (entriesForDestMT dest u.entries) r

theorem foldlEntryCreditMT_provenTotal (td : TokenSlot)
    (init : EncBalanceStateMT) (es : List TransferEntryMT) (w : TokenSlot) :
    (es.foldl (applyEntryCreditMT td) init).provenTotal w
      = init.provenTotal w + (if w = td then entryAmountSumMT es else 0) := by
  induction es generalizing init with
  | nil => simp [entryAmountSumMT]
  | cons e rest ih =>
    simp only [List.foldl, entryAmountSumMT]
    rw [ih (applyEntryCreditMT td init e)]
    show (if w = td then init.provenTotal w + e.amount else init.provenTotal w)
        + (if w = td then entryAmountSumMT rest else 0)
      = init.provenTotal w + (if w = td then e.amount + entryAmountSumMT rest else 0)
    by_cases hw : w = td
    · subst hw
      simp <;> omega
    · simp [hw] <;> omega

theorem foldlEntryCreditMT_total (td : TokenSlot) (init : EncBalanceStateMT)
    (es : List TransferEntryMT)
    (hent : ∀ e ∈ es, e.recipientDelta.pt = e.amount) (w : TokenSlot) :
    (es.foldl (applyEntryCreditMT td) init).total w
      = init.total w + (if w = td then entryAmountSumMT es else 0) := by
  induction es generalizing init with
  | nil => simp [entryAmountSumMT]
  | cons e rest ih =>
    have he := hent e (List.mem_cons_self _ _)
    simp only [List.foldl, entryAmountSumMT]
    rw [ih (applyEntryCreditMT td init e)
        (fun e' h' => hent e' (List.mem_cons_of_mem _ h'))]
    have h1 : (applyEntryCreditMT td init e).total w
        = init.total w + (if w = td then e.recipientDelta.pt else 0) :=
      updCt2_mapTotal init.encBal e.recipient td e.recipientDelta w
    rw [h1]
    by_cases hw : w = td
    · subst hw
      simp [he] <;> omega
    · simp [hw] <;> omega

/-- Pointwise frame of the credit fold: every token slot other than `td`
    keeps every member's exact balance. -/
theorem foldlEntryCreditMT_frame_bal (td : TokenSlot)
    (es : List TransferEntryMT) (init : EncBalanceStateMT)
    (j : Member) (w : TokenSlot) (hw : w ≠ td) :
    (es.foldl (applyEntryCreditMT td) init).bal j w = init.bal j w := by
  induction es generalizing init with
  | nil => rfl
  | cons e rest ih =>
    simp only [List.foldl]
    rw [ih (applyEntryCreditMT td init e)]
    show (updCt2 init.encBal e.recipient td e.recipientDelta j w).pt
        = (init.encBal j w).pt
    rw [updCt2_diff_token _ _ _ _ _ _ hw]

theorem foldlEntryCreditMT_frame_total (td : TokenSlot)
    (es : List TransferEntryMT) (init : EncBalanceStateMT)
    (w : TokenSlot) (hw : w ≠ td) :
    (es.foldl (applyEntryCreditMT td) init).total w = init.total w := by
  show (es.foldl (applyEntryCreditMT td) init).bal .m0 w
      + (es.foldl (applyEntryCreditMT td) init).bal .m1 w
      + (es.foldl (applyEntryCreditMT td) init).bal .m2 w
      = init.bal .m0 w + init.bal .m1 w + init.bal .m2 w
  rw [foldlEntryCreditMT_frame_bal td es init .m0 w hw,
      foldlEntryCreditMT_frame_bal td es init .m1 w hw,
      foldlEntryCreditMT_frame_bal td es init .m2 w hw]

theorem applyEntryCreditMT_preserves (td : TokenSlot) (st : EncBalanceStateMT)
    (e : TransferEntryMT) (hst : ValidEncStateMT st)
    (he : RecipientEntryVerifiedMT e) :
    ValidEncStateMT (applyEntryCreditMT td st e) := by
  obtain ⟨hnn, htot⟩ := hst
  obtain ⟨_hpos, hrd⟩ := he
  constructor
  · intro j w
    show 0 ≤ (updCt2 st.encBal e.recipient td e.recipientDelta j w).pt
    have hnj : 0 ≤ (st.encBal j w).pt := hnn j w
    have hnr : 0 ≤ (st.encBal e.recipient td).pt := hnn e.recipient td
    by_cases hj : j = e.recipient ∧ w = td
    · obtain ⟨h1, h2⟩ := hj
      subst h1; subst h2
      simp [updCt2] <;> omega
    · rw [updCt2_not _ _ _ _ _ _ hj]
      exact hnj
  · intro w
    have h1 := updCt2_mapTotal st.encBal e.recipient td e.recipientDelta w
    have htot' : mapTotal2 st.encBal w = st.provenTotal w := htot w
    show mapTotal2 (updCt2 st.encBal e.recipient td e.recipientDelta) w
        = (if w = td then st.provenTotal w + e.amount else st.provenTotal w)
    by_cases hw : w = td
    · subst hw
      simp at h1 ⊢
      omega
    · simp [hw] at h1 ⊢
      omega

theorem foldlEntryCreditMT_preserves (td : TokenSlot)
    (init : EncBalanceStateMT) (es : List TransferEntryMT)
    (hinit : ValidEncStateMT init)
    (hent : ∀ e ∈ es, RecipientEntryVerifiedMT e) :
    ValidEncStateMT (es.foldl (applyEntryCreditMT td) init) := by
  induction es generalizing init with
  | nil => exact hinit
  | cons e rest ih =>
    exact ih (applyEntryCreditMT td init e)
      (applyEntryCreditMT_preserves td init e hinit
        (hent e (List.mem_cons_self _ _)))
      (fun e' h' => hent e' (List.mem_cons_of_mem _ h'))

/-- **TM-6 / §N-4, source side.** With a verified per-base-token
    channelUpdateZKP, the deducted source state stays valid and its resolved
    slot's certified total decreases by exactly the public `totalAmount`. -/
theorem c2cMT_send_preserves_validity (s : EncBalanceStateMT) (sender : Member)
    (ts : TokenSlot) (u : BulkChannelUpdateMT)
    (hvalid : ValidEncStateMT s) (hu : BulkUpdateProvenMT u s sender ts) :
    ValidEncStateMT (applyBulkSendMT s sender ts u)
    ∧ (applyBulkSendMT s sender ts u).provenTotal ts
        = s.provenTotal ts - u.totalAmount := by
  obtain ⟨hnn, htot⟩ := hvalid
  obtain ⟨_hres, _hsum, _hpos, hsd, _hent, hsolv⟩ := hu
  have hsolv' : u.totalAmount ≤ (s.encBal sender ts).pt := hsolv
  refine ⟨⟨?_, ?_⟩, by simp [applyBulkSendMT]⟩
  · intro j w
    show 0 ≤ (updCt2 s.encBal sender ts u.senderDelta j w).pt
    have hnj : 0 ≤ (s.encBal j w).pt := hnn j w
    by_cases hj : j = sender ∧ w = ts
    · obtain ⟨h1, h2⟩ := hj
      subst h1; subst h2
      simp [updCt2] <;> omega
    · rw [updCt2_not _ _ _ _ _ _ hj]
      exact hnj
  · intro w
    have h1 := updCt2_mapTotal s.encBal sender ts u.senderDelta w
    have htot' : mapTotal2 s.encBal w = s.provenTotal w := htot w
    show mapTotal2 (updCt2 s.encBal sender ts u.senderDelta) w
        = (if w = ts then s.provenTotal w - u.totalAmount else s.provenTotal w)
    by_cases hw : w = ts
    · subst hw
      simp at h1 ⊢
      omega
    · simp [hw] at h1 ⊢
      omega

/-- **TM-6 / §N-4, destination side.** Crediting the destination-registry-
    resolved slot with the verified legs keeps the destination state valid
    and grows that slot's certified total by exactly the legs' amount sum.
    Only receiver-checkable facts are assumed (`RecipientBulkVerifiedMT`). -/
theorem c2cMT_receive_preserves_validity (r : EncBalanceStateMT) (dest : Nat)
    (td : TokenSlot) (u : BulkChannelUpdateMT)
    (hvalid : ValidEncStateMT r)
    (hdest : RecipientBulkVerifiedMT dest u r td) :
    ValidEncStateMT (applyBulkReceiveMT r dest td u)
    ∧ (applyBulkReceiveMT r dest td u).provenTotal td
        = r.provenTotal td + destAmountSumMT dest u.entries := by
  obtain ⟨_hres, hent⟩ := hdest
  constructor
  · exact foldlEntryCreditMT_preserves td r (entriesForDestMT dest u.entries)
      hvalid hent
  · have h := foldlEntryCreditMT_provenTotal td r
      (entriesForDestMT dest u.entries) td
    simp at h
    exact h

/-- **TM-6 / §N-4, both sides in one statement** (the requested
    `c2cMT_preserves_validity`): a verified C2C update leaves BOTH channels'
    multi-token invariants intact. -/
theorem c2cMT_preserves_validity (s r : EncBalanceStateMT) (sender : Member)
    (ts td : TokenSlot) (dest : Nat) (u : BulkChannelUpdateMT)
    (hs : ValidEncStateMT s) (hr : ValidEncStateMT r)
    (hu : BulkUpdateProvenMT u s sender ts)
    (hdest : RecipientBulkVerifiedMT dest u r td) :
    ValidEncStateMT (applyBulkSendMT s sender ts u)
    ∧ ValidEncStateMT (applyBulkReceiveMT r dest td u) :=
  ⟨(c2cMT_send_preserves_validity s sender ts u hs hu).1,
   (c2cMT_receive_preserves_validity r dest td u hr hdest).1⟩

/-- **LOCAL-SLOT arithmetic lemma (mirror of
    `bulk_interChannel_conservation_dest`) — feeds the base-token statement
    `c2cMT_conservation_base` below.** HONESTY NOTE (review finding M1): the
    conclusion is about the two LOCAL slots `ts`/`td` and holds for ANY `td`
    — the `_hres` hypothesis is deliberately inert here. By itself this says
    "some slot's total went up by what the sender's slot lost", NOT "base
    token `u.tokenIndex` was conserved". The TM-6 claim about BASE-token
    value is `c2cMT_conservation_base`, where the resolution and injectivity
    hypotheses do real work; `sampleC2C_misresolution_breaks_conservation`
    shows what goes wrong at the base level when resolution is dropped. -/
theorem c2cMT_conservation (s r : EncBalanceStateMT) (sender : Member)
    (ts td : TokenSlot) (dest : Nat) (u : BulkChannelUpdateMT)
    (_hres : ResolvesMT r u.tokenIndex td)
    (honly : ∀ e ∈ u.entries, e.dest = dest)
    (hu : BulkUpdateProvenMT u s sender ts) :
    (applyBulkSendMT s sender ts u).total ts
      + (applyBulkReceiveMT r dest td u).total td
      = s.total ts + r.total td := by
  obtain ⟨_hres_s, hsum, _hpos, hsd, hentAll, _hsolv⟩ := hu
  have hfilter := entriesForDestMT_eq_of_forall dest u.entries honly
  have hrd : ∀ e ∈ entriesForDestMT dest u.entries,
      e.recipientDelta.pt = e.amount :=
    fun e hmem => (hentAll e (by rw [hfilter] at hmem; exact hmem)).2
  have hsend := updCt2_mapTotal s.encBal sender ts u.senderDelta ts
  have hrecv := foldlEntryCreditMT_total td r (entriesForDestMT dest u.entries)
    hrd td
  have hsum2 : entryAmountSumMT (entriesForDestMT dest u.entries)
      = u.totalAmount := by
    rw [hfilter]; exact hsum.symm
  show mapTotal2 (updCt2 s.encBal sender ts u.senderDelta) ts
      + ((entriesForDestMT dest u.entries).foldl (applyEntryCreditMT td) r).total td
      = mapTotal2 s.encBal ts + r.total td
  simp at hsend hrecv
  omega

/-- **TM-6 conservation under commitment binding (mirror of
    `bulk_interChannel_conservation_bound`).** Sender and receiver each
    verify their side against the SAME committed descriptor (which contains
    the base `tokenIndex`); commitment injectivity is A1's collision
    resistance. If both sides open the same commitment, cross-channel
    per-base-token conservation holds even though the two channels never
    compare registries or plaintexts directly. -/
theorem c2cMT_conservation_bound
    (commit : BulkChannelUpdateMT → Nat)
    (hinj : ∀ u u', commit u = commit u' → u = u')
    (us ur : BulkChannelUpdateMT) (hsame : commit us = commit ur)
    (s r : EncBalanceStateMT) (sender : Member) (ts td : TokenSlot)
    (dest : Nat)
    (hres : ResolvesMT r ur.tokenIndex td)
    (honly : ∀ e ∈ us.entries, e.dest = dest)
    (hu : BulkUpdateProvenMT us s sender ts) :
    (applyBulkSendMT s sender ts us).total ts
      + (applyBulkReceiveMT r dest td ur).total td
      = s.total ts + r.total td := by
  obtain rfl := hinj us ur hsame
  exact c2cMT_conservation s r sender ts td dest us hres honly hu

/-- **TM-6 frame, source side.** Every token slot other than the source-
    resolved `ts` keeps every balance, its total, AND its certified total: a
    C2C send cannot move any other base token's value (the wrong-slot-debit
    analogue of TM-6 excluded structurally). -/
theorem c2cMT_frame_send (s : EncBalanceStateMT) (sender : Member)
    (ts : TokenSlot) (u : BulkChannelUpdateMT) (w : TokenSlot) (hw : w ≠ ts) :
    (∀ j : Member, (applyBulkSendMT s sender ts u).bal j w = s.bal j w)
    ∧ (applyBulkSendMT s sender ts u).total w = s.total w
    ∧ (applyBulkSendMT s sender ts u).provenTotal w = s.provenTotal w := by
  refine ⟨?_, ?_, ?_⟩
  · intro j
    show (updCt2 s.encBal sender ts u.senderDelta j w).pt = (s.encBal j w).pt
    rw [updCt2_diff_token _ _ _ _ _ _ hw]
  · have h := updCt2_mapTotal s.encBal sender ts u.senderDelta w
    show mapTotal2 (updCt2 s.encBal sender ts u.senderDelta) w
        = mapTotal2 s.encBal w
    simp [hw] at h
    exact h
  · show (if w = ts then s.provenTotal w - u.totalAmount else s.provenTotal w)
        = s.provenTotal w
    rw [if_neg hw]

/-- **TM-6 frame, destination side.** Every token slot other than the
    destination-resolved `td` keeps every balance, its total, AND its
    certified total: the credit cannot land in (or leak into) any other base
    token's slot (the TM-6 wrong-slot-credit attack excluded structurally,
    GIVEN the resolution pinned `td`). -/
theorem c2cMT_frame_receive (r : EncBalanceStateMT) (dest : Nat)
    (td : TokenSlot) (u : BulkChannelUpdateMT) (w : TokenSlot) (hw : w ≠ td) :
    (∀ j : Member, (applyBulkReceiveMT r dest td u).bal j w = r.bal j w)
    ∧ (applyBulkReceiveMT r dest td u).total w = r.total w
    ∧ (applyBulkReceiveMT r dest td u).provenTotal w = r.provenTotal w := by
  refine ⟨?_, ?_, ?_⟩
  · intro j
    show ((entriesForDestMT dest u.entries).foldl (applyEntryCreditMT td) r).bal j w
        = r.bal j w
    exact foldlEntryCreditMT_frame_bal td (entriesForDestMT dest u.entries) r j w hw
  · show ((entriesForDestMT dest u.entries).foldl (applyEntryCreditMT td) r).total w
        = r.total w
    exact foldlEntryCreditMT_frame_total td (entriesForDestMT dest u.entries) r w hw
  · have h := foldlEntryCreditMT_provenTotal td r
      (entriesForDestMT dest u.entries) w
    show ((entriesForDestMT dest u.entries).foldl (applyEntryCreditMT td) r).provenTotal w
        = r.provenTotal w
    simp [hw] at h
    exact h

/-- **TM-6 BASE-token conservation (M1, the real §N-4 statement).** Under
    the full in-circuit contract — source obligations (`BulkUpdateProvenMT`,
    which includes source-side resolution), destination-side resolution
    (`hresr`), and BOTH registries injective (TM-1) — a C2C transfer:
    (1) conserves the total BASE-token-`u.tokenIndex` value across the two
        channels (`baseTotal src + baseTotal dst` invariant), and
    (2) for EVERY other base token `Y ≠ u.tokenIndex`, leaves `baseTotal Y`
        unchanged on BOTH channels.
    Unlike the local-slot lemma above, dropping `hresr` here breaks the
    statement — the mis-resolved credit of
    `sampleC2C_misresolution_breaks_conservation` (td' = 1, where
    `ResolvesMT dstMT 0 1` is FALSE because `dstMT.registry 1 = 99 ≠ 0`)
    visibly violates this theorem's hypotheses, which is exactly the TM-6
    wrong-slot-credit attack being excluded. -/
theorem c2cMT_conservation_base (s r : EncBalanceStateMT) (sender : Member)
    (ts td : TokenSlot) (dest : Nat) (u : BulkChannelUpdateMT)
    (hinjs : RegistryInjective s) (hinjr : RegistryInjective r)
    (hresr : ResolvesMT r u.tokenIndex td)
    (honly : ∀ e ∈ u.entries, e.dest = dest)
    (hu : BulkUpdateProvenMT u s sender ts) :
    (baseTotal (applyBulkSendMT s sender ts u) u.tokenIndex
      + baseTotal (applyBulkReceiveMT r dest td u) u.tokenIndex
      = baseTotal s u.tokenIndex + baseTotal r u.tokenIndex)
    ∧ (∀ Y : Nat, Y ≠ u.tokenIndex →
        baseTotal (applyBulkSendMT s sender ts u) Y = baseTotal s Y
        ∧ baseTotal (applyBulkReceiveMT r dest td u) Y = baseTotal r Y) := by
  have hress : ResolvesMT s u.tokenIndex ts := hu.1
  -- Header transports to the post-states (registry/tokenCount unchanged).
  have hress' := resolvesMT_of_header_eq s (applyBulkSendMT s sender ts u)
    u.tokenIndex ts (fun _ => rfl) rfl hress
  have hinjs' := registryInjective_of_header_eq s (applyBulkSendMT s sender ts u)
    (fun _ => rfl) rfl hinjs
  have hhdr := applyBulkReceiveMT_header r dest td u
  have hregR : ∀ t : TokenSlot,
      (applyBulkReceiveMT r dest td u).registry t = r.registry t :=
    fun t => congrFun hhdr.1 t
  have hresr' := resolvesMT_of_header_eq r (applyBulkReceiveMT r dest td u)
    u.tokenIndex td hregR hhdr.2 hresr
  have hinjr' := registryInjective_of_header_eq r (applyBulkReceiveMT r dest td u)
    hregR hhdr.2 hinjr
  constructor
  · -- (1) base-token conservation via the bridge on all four states.
    have hb1 := baseTotal_eq_total_of_resolves (applyBulkSendMT s sender ts u)
      u.tokenIndex ts hress' hinjs'
    have hb2 := baseTotal_eq_total_of_resolves s u.tokenIndex ts hress hinjs
    have hb3 := baseTotal_eq_total_of_resolves (applyBulkReceiveMT r dest td u)
      u.tokenIndex td hresr' hinjr'
    have hb4 := baseTotal_eq_total_of_resolves r u.tokenIndex td hresr hinjr
    have hloc := c2cMT_conservation s r sender ts td dest u hresr honly hu
    omega
  · -- (2) every other base token framed on both sides.
    intro Y hY
    constructor
    · refine baseTotal_congr s (applyBulkSendMT s sender ts u) Y
        (fun _ => rfl) rfl ?_
      intro t' _hlt hregt
      have hne : t' ≠ ts := by
        intro h
        subst h
        exact hY (hregt.symm.trans hress.2)
      exact (c2cMT_frame_send s sender ts u t' hne).2.1
    · refine baseTotal_congr r (applyBulkReceiveMT r dest td u) Y
        hregR hhdr.2 ?_
      intro t' _hlt hregt
      have hne : t' ≠ td := by
        intro h
        subst h
        exact hY (hregt.symm.trans hresr.2)
      exact (c2cMT_frame_receive r dest td u t' hne).2.1

/-! ## §7 Top-level no-cross-token corollary (detail2.md §N-9, property P2) -/

/-- The step kinds of the multi-token channel layer modeled in this file,
    seen from ONE channel's perspective (solo transfer §N-3, mixed-token
    batch §N-3/TM-14, L1 deposit import §N-5, TokenRegister §N-1, and the
    two single-channel halves of a C2C transfer §N-4/TM-6 — this channel as
    source resp. destination; the authoritative cross-channel coupling of
    the two halves is §6's base-token statement `c2cMT_conservation_base`,
    with `c2cMT_conservation` as its supporting local-slot arithmetic). -/
inductive StepMT
  | transfer (tx : TransferMT)
  | batch (txs : List BatchTxMT)
  | deposit (recipient : Member) (amount : Int) (tokenSlot : TokenSlot)
      (recipientDelta : Ct)
  | register (baseIndex : Nat)
  | c2cSend (sender : Member) (ts : TokenSlot) (u : BulkChannelUpdateMT)
  | c2cReceive (dest : Nat) (td : TokenSlot) (u : BulkChannelUpdateMT)

def applyStepMT (s : EncBalanceStateMT) : StepMT → EncBalanceStateMT
  | .transfer tx => applyTransferMT s tx
  | .batch txs => applyBatchMT s txs
  | .deposit recipient amount tokenSlot recipientDelta =>
      applyL1DepositImportMT s recipient amount tokenSlot recipientDelta
  | .register baseIndex => applyTokenRegister s baseIndex
  | .c2cSend sender ts u => applyBulkSendMT s sender ts u
  | .c2cReceive dest td u => applyBulkReceiveMT s dest td u

/-- Which token a step moves value in. TokenRegister moves value in NO token
    (header-only, §N-1). For the C2C halves it is the registry-RESOLVED local
    slot of this channel (§N-4). -/
def stepTouchesToken : StepMT → TokenSlot → Prop
  | .transfer tx, t => tx.tokenSlot = t
  | .batch txs, t => ∃ tx ∈ txs, tx.tokenSlot = t
  | .deposit _ _ tokenSlot _, t => tokenSlot = t
  | .register _, _ => False
  | .c2cSend _ ts _, t => ts = t
  | .c2cReceive _ td _, t => td = t

/-- **No-cross-token corollary (P2, §N-9).** For ANY step of the system and
    ANY token slot the step does not move value in, BOTH the channel total
    AND the certified `provenTotal` of that token are unchanged — value can
    never leak between token slots on any modeled path. For TokenRegister
    this holds for ALL tokens. Structural: needs no ZKP hypotheses. -/
theorem no_cross_token_step (s : EncBalanceStateMT) (st : StepMT)
    (t : TokenSlot) (h : ¬ stepTouchesToken st t) :
    (applyStepMT s st).total t = s.total t
    ∧ (applyStepMT s st).provenTotal t = s.provenTotal t := by
  cases st with
  | transfer tx =>
    have hne : t ≠ tx.tokenSlot := fun he => h he.symm
    exact ⟨transferMT_frame_total s tx t hne, rfl⟩
  | batch txs =>
    have hall : ∀ tx ∈ txs, tx.tokenSlot ≠ t :=
      fun tx htx he => h ⟨tx, htx, he⟩
    exact ⟨batchMT_frame_total s txs t hall, rfl⟩
  | deposit recipient amount tokenSlot recipientDelta =>
    have hne : t ≠ tokenSlot := fun he => h he.symm
    exact l1_depositMT_frame s recipient amount tokenSlot recipientDelta t hne
  | register baseIndex => exact ⟨rfl, rfl⟩
  | c2cSend sender ts u =>
    have hne : t ≠ ts := fun he => h he.symm
    exact ⟨(c2cMT_frame_send s sender ts u t hne).2.1,
           (c2cMT_frame_send s sender ts u t hne).2.2⟩
  | c2cReceive dest td u =>
    have hne : t ≠ td := fun he => h he.symm
    exact ⟨(c2cMT_frame_receive s dest td u t hne).2.1,
           (c2cMT_frame_receive s dest td u t hne).2.2⟩

/-! ### InactiveZero preservation (M5 / TM-8, the §N-2 validate() fail-close)

Every step's soundness contract carries `ActiveToken` for the slot it
mutates, so no step ever writes into an inactive slot; combined with the
frame theorems this makes `InactiveZero` an inductive invariant. This is the
state-level counterpart of §N-2's "positions `t >= token_count` MUST equal
the canonical zero digest": without it, `TokenRegister` would hand out
whatever value already sat in the newly activated slot. -/

/-- The per-step soundness contract (what the corresponding circuit
    verifies), packaged per step kind for the invariant theorems. For
    `register` the InactiveZero argument needs no contract at all. -/
def StepProvenMT (s : EncBalanceStateMT) : StepMT → Prop
  | .transfer tx => TransferProvenMT tx s
  | .batch txs => BatchProvenMT s txs
  | .deposit _ amount tokenSlot recipientDelta =>
      ∃ tokenIndex : Nat,
        L1DepositImportVerifiedMT s amount tokenIndex tokenSlot recipientDelta
  | .register _ => True
  | .c2cSend sender ts u => BulkUpdateProvenMT u s sender ts
  | .c2cReceive dest td u => RecipientBulkVerifiedMT dest u s td

theorem transferMT_preserves_inactiveZero (s : EncBalanceStateMT)
    (tx : TransferMT) (hiz : InactiveZero s) (ht : TransferProvenMT tx s) :
    InactiveZero (applyTransferMT s tx) := by
  intro t hinact
  have hinact' : ¬ ActiveToken s t := hinact
  have hne : t ≠ tx.tokenSlot := by
    intro h
    subst h
    exact hinact' ht.1
  obtain ⟨hbal, hpt⟩ := hiz t hinact'
  refine ⟨fun m => ?_, hpt⟩
  rw [transferMT_frame_bal s tx m t hne]
  exact hbal m

theorem batchMT_preserves_inactiveZero (s : EncBalanceStateMT)
    (txs : List BatchTxMT) (hiz : InactiveZero s) (h : BatchProvenMT s txs) :
    InactiveZero (applyBatchMT s txs) := by
  intro t hinact
  have hinact' : ¬ ActiveToken s t := hinact
  obtain ⟨hbal, hpt⟩ := hiz t hinact'
  have huntouched : ∀ m : Member, ∀ tx ∈ txs, ¬ TouchesMT tx m t := by
    intro m tx htx hc
    have hact : ActiveToken s tx.tokenSlot := (h.1 tx htx).1
    have heq : t = tx.tokenSlot := by
      cases hc with
      | inl hc => exact hc.2
      | inr hc => exact hc.2
    exact hinact' (by rw [heq]; exact hact)
  refine ⟨fun m => ?_, hpt⟩
  rw [batchMT_frame s txs m t (huntouched m)]
  exact hbal m

theorem l1_depositMT_preserves_inactiveZero (s : EncBalanceStateMT)
    (recipient : Member) (amount : Int) (tokenIndex : Nat)
    (tokenSlot : TokenSlot) (recipientDelta : Ct)
    (hiz : InactiveZero s)
    (hd : L1DepositImportVerifiedMT s amount tokenIndex tokenSlot recipientDelta) :
    InactiveZero (applyL1DepositImportMT s recipient amount tokenSlot
      recipientDelta) := by
  intro t hinact
  have hinact' : ¬ ActiveToken s t := hinact
  have hne : t ≠ tokenSlot := by
    intro h
    subst h
    exact hinact' hd.1.1
  obtain ⟨hbal, hpt⟩ := hiz t hinact'
  refine ⟨fun m => ?_, ?_⟩
  · rw [l1_depositMT_frame_bal s recipient amount tokenSlot recipientDelta
        m t (fun hc => hne hc.2)]
    exact hbal m
  · show (if t = tokenSlot then s.provenTotal t + amount else s.provenTotal t) = 0
    rw [if_neg hne]
    exact hpt

theorem tokenRegister_preserves_inactiveZero (s : EncBalanceStateMT)
    (baseIndex : Nat) (hiz : InactiveZero s) :
    InactiveZero (applyTokenRegister s baseIndex) := by
  intro t hinact
  have hinact' : ¬ ActiveToken s t := by
    intro hact
    have h1 : t.val < s.tokenCount := hact
    exact hinact (show t.val < s.tokenCount + 1 by omega)
  exact hiz t hinact'

theorem c2cMT_send_preserves_inactiveZero (s : EncBalanceStateMT)
    (sender : Member) (ts : TokenSlot) (u : BulkChannelUpdateMT)
    (hiz : InactiveZero s) (hu : BulkUpdateProvenMT u s sender ts) :
    InactiveZero (applyBulkSendMT s sender ts u) := by
  intro t hinact
  have hinact' : ¬ ActiveToken s t := hinact
  have hne : t ≠ ts := by
    intro h
    subst h
    exact hinact' hu.1.1
  obtain ⟨hbal, hpt⟩ := hiz t hinact'
  refine ⟨fun m => ?_, ?_⟩
  · rw [(c2cMT_frame_send s sender ts u t hne).1 m]
    exact hbal m
  · rw [(c2cMT_frame_send s sender ts u t hne).2.2]
    exact hpt

theorem c2cMT_receive_preserves_inactiveZero (s : EncBalanceStateMT)
    (dest : Nat) (td : TokenSlot) (u : BulkChannelUpdateMT)
    (hiz : InactiveZero s) (hv : RecipientBulkVerifiedMT dest u s td) :
    InactiveZero (applyBulkReceiveMT s dest td u) := by
  intro t hinact
  have hhdr := applyBulkReceiveMT_header s dest td u
  have hinact' : ¬ ActiveToken s t := by
    intro hact
    exact hinact (show t.val < (applyBulkReceiveMT s dest td u).tokenCount by
      rw [hhdr.2]; exact hact)
  have hne : t ≠ td := by
    intro h
    subst h
    exact hinact' hv.1.1
  obtain ⟨hbal, hpt⟩ := hiz t hinact'
  refine ⟨fun m => ?_, ?_⟩
  · rw [(c2cMT_frame_receive s dest td u t hne).1 m]
    exact hbal m
  · rw [(c2cMT_frame_receive s dest td u t hne).2.2]
    exact hpt

/-- **M5 / TM-8 main invariant theorem.** `InactiveZero` — the state-level
    §N-2 validate() fail-close — is preserved by EVERY step kind under that
    step's own soundness contract. -/
theorem step_preserves_inactiveZero (s : EncBalanceStateMT) (st : StepMT)
    (hiz : InactiveZero s) (hst : StepProvenMT s st) :
    InactiveZero (applyStepMT s st) := by
  cases st with
  | transfer tx => exact transferMT_preserves_inactiveZero s tx hiz hst
  | batch txs => exact batchMT_preserves_inactiveZero s txs hiz hst
  | deposit recipient amount tokenSlot recipientDelta =>
    obtain ⟨tokenIndex, hd⟩ := hst
    exact l1_depositMT_preserves_inactiveZero s recipient amount tokenIndex
      tokenSlot recipientDelta hiz hd
  | register baseIndex => exact tokenRegister_preserves_inactiveZero s baseIndex hiz
  | c2cSend sender ts u => exact c2cMT_send_preserves_inactiveZero s sender ts u hiz hst
  | c2cReceive dest td u =>
    exact c2cMT_receive_preserves_inactiveZero s dest td u hiz hst

/-- **M5 / TM-8 corollary: a freshly activated slot starts empty.** Under
    the `InactiveZero` system invariant, the slot a `TokenRegister`
    activates carries zero in every member position and a zero certified
    total — registering a token cannot "reveal" pre-existing value. (This is
    exactly the property that would FAIL if `InactiveZero` were not
    maintained; see the header disclosure.) -/
theorem tokenRegister_fresh_slot_zero (s : EncBalanceStateMT)
    (baseIndex : Nat) (hiz : InactiveZero s) (t : TokenSlot)
    (htv : t.val = s.tokenCount) :
    (∀ m : Member, (applyTokenRegister s baseIndex).bal m t = 0)
    ∧ (applyTokenRegister s baseIndex).provenTotal t = 0 := by
  have hinact : ¬ ActiveToken s t := by
    intro h
    have h1 : t.val < s.tokenCount := h
    omega
  exact hiz t hinact

/-! ## §8 Sanity: the multi-token hypotheses are satisfiable (non-vacuity) -/

section Sanity

/-- A valid multi-token state: one registered token (slot 0 → base index 0,
    the v1-compatible `registry=[ETH]` shape of owner decision 5), each
    member holding 10 of it; every other slot is the canonical zero. -/
def sampleMT : EncBalanceStateMT where
  encBal := fun _ t => if t.val = 0 then ⟨10⟩ else ⟨0⟩
  provenTotal := fun t => if t.val = 0 then 30 else 0
  version := 0
  registry := fun _ => 0
  tokenCount := 1

theorem sampleMT_valid : ValidEncStateMT sampleMT := by
  constructor
  · intro _m t
    show 0 ≤ (if t.val = 0 then (⟨10⟩ : Ct) else ⟨0⟩).pt
    by_cases h : t.val = 0 <;> simp [h] <;> omega
  · intro t
    show (if t.val = 0 then (⟨10⟩ : Ct) else ⟨0⟩).pt
        + (if t.val = 0 then (⟨10⟩ : Ct) else ⟨0⟩).pt
        + (if t.val = 0 then (⟨10⟩ : Ct) else ⟨0⟩).pt
        = (if t.val = 0 then (30 : Int) else 0)
    by_cases h : t.val = 0 <;> simp [h] <;> omega

theorem sampleMT_bounded : TokenCountBounded sampleMT :=
  ⟨by show 1 ≤ 1; omega, by show 1 ≤ 10; omega⟩

theorem sampleMT_registry_injective : RegistryInjective sampleMT := by
  intro t1 t2 h1 h2 _
  have h1' : t1.val < 1 := h1
  have h2' : t2.val < 1 := h2
  exact Fin.eq_of_val_eq (by omega)

/-- A provable solo-transfer instance exists (token 0, m0 → m1, amount 4). -/
def sampleTxMT : TransferMT where
  sender := .m0
  recipient := .m1
  tokenSlot := 0
  encAmount := ⟨4⟩

theorem sampleTxMT_proven : TransferProvenMT sampleTxMT sampleMT :=
  ⟨by show (0 : Fin 10).val < 1; decide,
   by show (0 : Int) ≤ 4; omega,
   by show (4 : Int) ≤ 10; omega⟩

theorem sampleTxMT_valid :
    ValidEncStateMT (applyTransferMT sampleMT sampleTxMT) :=
  transferMT_preserves_validity sampleMT sampleTxMT sampleMT_valid
    sampleTxMT_proven

/-- A provable batch instance exists (single token-0 tx, m0 → m1, amount 5). -/
def sampleBatchTxMT : BatchTxMT :=
  ⟨.m0, .m1, 0, 5, ⟨5⟩, ⟨5⟩⟩

theorem sampleBatchMT_proven : BatchProvenMT sampleMT [sampleBatchTxMT] := by
  constructor
  · intro tx htx
    simp at htx
    subst htx
    refine ⟨by show (0 : Fin 10).val < 1; decide,
            by show (0 : Int) ≤ 5; omega, rfl,
            by show (5 : Int) = 10 - 5; omega,
            by show (0 : Int) ≤ 5; omega⟩
  · simp [sendersDistinctMT]

theorem sampleBatchMT_valid :
    ValidEncStateMT (applyBatchMT sampleMT [sampleBatchTxMT]) :=
  (batchMT_preserves_validity sampleMT [sampleBatchTxMT] sampleMT_valid
    sampleBatchMT_proven).1

/-- A provable deposit-import instance exists (base token 0 → local slot 0,
    amount 7), including the M2 registry-resolution leg (c). -/
theorem sampleDepositMT_verified :
    L1DepositImportVerifiedMT sampleMT 7 0 0 ⟨7⟩ :=
  ⟨⟨by show (0 : Fin 10).val < 1; decide, rfl⟩,
   by show (0 : Int) ≤ 7; omega, rfl⟩

/-- m6: `l1_depositMT_preserves_validity` instantiated on the witness. -/
theorem sampleDepositMT_valid :
    ValidEncStateMT (applyL1DepositImportMT sampleMT .m2 7 0 ⟨7⟩) :=
  (l1_depositMT_preserves_validity sampleMT .m2 7 0 0 ⟨7⟩ sampleMT_valid
    sampleDepositMT_verified).1

/-- m6/M5: `InactiveZero` is satisfiable (slots ≥ tokenCount are all zero in
    the sample state). -/
theorem sampleMT_inactiveZero : InactiveZero sampleMT := by
  intro t hinact
  have ht : ¬ t.val < 1 := hinact
  have h0 : ¬ t.val = 0 := by omega
  constructor
  · intro _m
    show (if t.val = 0 then (⟨10⟩ : Ct) else ⟨0⟩).pt = 0
    simp [h0]
  · show (if t.val = 0 then (30 : Int) else 0) = 0
    simp [h0]

/-- Registering a fresh base index (7) at slot 1 preserves TM-1 injectivity. -/
theorem sampleRegisterMT_injective :
    RegistryInjective (applyTokenRegister sampleMT 7) := by
  apply tokenRegister_preserves_injectivity sampleMT 7 sampleMT_registry_injective
  intro t _ht
  show sampleMT.registry t ≠ 7
  simp [sampleMT]

/-! ### C2C samples (§N-4, TM-6) -/

/-- A destination channel with TWO registered tokens: local slot 0 → base
    index 0 (same base token as `sampleMT`'s slot 0) and local slot 1 → base
    index 99 (a DIFFERENT base token). Each member holds 10 of token 0. -/
def dstMT : EncBalanceStateMT where
  encBal := fun _ t => if t.val = 0 then ⟨10⟩ else ⟨0⟩
  provenTotal := fun t => if t.val = 0 then 30 else 0
  version := 0
  registry := fun t => if t.val = 0 then 0 else 99
  tokenCount := 2

theorem dstMT_valid : ValidEncStateMT dstMT := by
  constructor
  · intro _m t
    show 0 ≤ (if t.val = 0 then (⟨10⟩ : Ct) else ⟨0⟩).pt
    by_cases h : t.val = 0 <;> simp [h] <;> omega
  · intro t
    show (if t.val = 0 then (⟨10⟩ : Ct) else ⟨0⟩).pt
        + (if t.val = 0 then (⟨10⟩ : Ct) else ⟨0⟩).pt
        + (if t.val = 0 then (⟨10⟩ : Ct) else ⟨0⟩).pt
        = (if t.val = 0 then (30 : Int) else 0)
    by_cases h : t.val = 0 <;> simp [h] <;> omega

/-- One receive leg: destination channel 1, recipient m1, amount 5. -/
def sampleC2CEntry : TransferEntryMT := ⟨1, .m1, 5, ⟨5⟩⟩

/-- A C2C update moving 5 units of BASE token 0 from `sampleMT` to `dstMT`. -/
def sampleBulkMT : BulkChannelUpdateMT := ⟨0, 5, ⟨-5⟩, [sampleC2CEntry]⟩

/-- The source-side obligations are satisfiable (source resolves base token 0
    at its local slot 0). -/
theorem sampleBulkMT_proven : BulkUpdateProvenMT sampleBulkMT sampleMT .m0 0 := by
  refine ⟨⟨by show (0 : Fin 10).val < 1; decide, rfl⟩,
          by show (5 : Int) = 5 + 0; omega,
          by show (0 : Int) ≤ 5; omega,
          rfl, ?_,
          by show (5 : Int) ≤ 10; omega⟩
  intro e he
  simp [sampleBulkMT, sampleC2CEntry] at he
  subst he
  exact ⟨by show (0 : Int) ≤ 5; omega, rfl⟩

/-- The destination-side obligations are satisfiable (destination resolves
    the SAME base token 0 at ITS local slot 0). -/
theorem sampleBulkMT_recipientVerified :
    RecipientBulkVerifiedMT 1 sampleBulkMT dstMT 0 := by
  refine ⟨⟨by show (0 : Fin 10).val < 2; decide, by decide⟩, ?_⟩
  intro e he
  simp [entriesForDestMT, sampleBulkMT, sampleC2CEntry] at he
  subst he
  exact ⟨by show (0 : Int) ≤ 5; omega, rfl⟩

/-- With CORRECT registry resolution on both sides (td = 0, the slot `dstMT`
    resolves for base token 0), cross-channel conservation holds on the
    sample instance. -/
theorem sampleC2C_conservation :
    (applyBulkSendMT sampleMT .m0 0 sampleBulkMT).total 0
      + (applyBulkReceiveMT dstMT 1 0 sampleBulkMT).total 0
      = sampleMT.total 0 + dstMT.total 0 :=
  c2cMT_conservation sampleMT dstMT .m0 0 0 1 sampleBulkMT
    ⟨by show (0 : Fin 10).val < 2; decide, by decide⟩
    (by intro e he
        simp [sampleBulkMT, sampleC2CEntry] at he
        subst he
        rfl)
    sampleBulkMT_proven

/-- TM-1 injectivity of `dstMT`'s registry over its two active slots
    (slot 0 → base 0, slot 1 → base 99). -/
theorem dstMT_registry_injective : RegistryInjective dstMT := by
  intro t1 t2 h1 h2 heq
  have h1' : t1.val < 2 := h1
  have h2' : t2.val < 2 := h2
  by_cases e1 : t1.val = 0 <;> by_cases e2 : t2.val = 0
  · exact Fin.eq_of_val_eq (e1.trans e2.symm)
  · exact absurd heq (by simp [dstMT, e1, e2])
  · exact absurd heq (by simp [dstMT, e1, e2])
  · exact Fin.eq_of_val_eq (by omega)

/-- Non-vacuity of the flagship theorem: `c2cMT_conservation_base`
    instantiated on the witnesses — base token 0's value is conserved across
    the two channels, and every other base token's `baseTotal` is unchanged
    on both sides. -/
theorem sampleC2C_conservation_base :
    (baseTotal (applyBulkSendMT sampleMT .m0 0 sampleBulkMT)
        sampleBulkMT.tokenIndex
      + baseTotal (applyBulkReceiveMT dstMT 1 0 sampleBulkMT)
        sampleBulkMT.tokenIndex
      = baseTotal sampleMT sampleBulkMT.tokenIndex
        + baseTotal dstMT sampleBulkMT.tokenIndex)
    ∧ (∀ Y : Nat, Y ≠ sampleBulkMT.tokenIndex →
        baseTotal (applyBulkSendMT sampleMT .m0 0 sampleBulkMT) Y
          = baseTotal sampleMT Y
        ∧ baseTotal (applyBulkReceiveMT dstMT 1 0 sampleBulkMT) Y
          = baseTotal dstMT Y) :=
  c2cMT_conservation_base sampleMT dstMT .m0 0 0 1 sampleBulkMT
    sampleMT_registry_injective dstMT_registry_injective
    ⟨by show (0 : Fin 10).val < 2; decide, by decide⟩
    (by intro e he
        simp [sampleBulkMT, sampleC2CEntry] at he
        subst he
        rfl)
    sampleBulkMT_proven

/-- m6: `c2cMT_preserves_validity` instantiated on the witnesses (both
    channels stay valid across the sample C2C transfer). -/
theorem sampleC2C_valid :
    ValidEncStateMT (applyBulkSendMT sampleMT .m0 0 sampleBulkMT)
    ∧ ValidEncStateMT (applyBulkReceiveMT dstMT 1 0 sampleBulkMT) :=
  c2cMT_preserves_validity sampleMT dstMT .m0 0 0 1 sampleBulkMT
    sampleMT_valid dstMT_valid sampleBulkMT_proven
    sampleBulkMT_recipientVerified

/-! ### Mixed-token batch sample (m6, TM-14) -/

/-- Two registered tokens (slot 0 → base 0, slot 1 → base 99), member
    balances 10 in token 0 and 6 in token 1. -/
def sampleMT2 : EncBalanceStateMT where
  encBal := fun _ t => if t.val = 0 then ⟨10⟩ else if t.val = 1 then ⟨6⟩ else ⟨0⟩
  provenTotal := fun t => if t.val = 0 then 30 else if t.val = 1 then 18 else 0
  version := 0
  registry := fun t => if t.val = 0 then 0 else if t.val = 1 then 99 else 0
  tokenCount := 2

theorem sampleMT2_valid : ValidEncStateMT sampleMT2 := by
  constructor
  · intro _m t
    show 0 ≤ (if t.val = 0 then (⟨10⟩ : Ct)
        else if t.val = 1 then ⟨6⟩ else ⟨0⟩).pt
    by_cases h0 : t.val = 0 <;> by_cases h1 : t.val = 1 <;>
      simp [h0, h1] <;> omega
  · intro t
    show (if t.val = 0 then (⟨10⟩ : Ct) else if t.val = 1 then ⟨6⟩ else ⟨0⟩).pt
        + (if t.val = 0 then (⟨10⟩ : Ct) else if t.val = 1 then ⟨6⟩ else ⟨0⟩).pt
        + (if t.val = 0 then (⟨10⟩ : Ct) else if t.val = 1 then ⟨6⟩ else ⟨0⟩).pt
        = (if t.val = 0 then (30 : Int) else if t.val = 1 then 18 else 0)
    by_cases h0 : t.val = 0 <;> by_cases h1 : t.val = 1 <;>
      simp [h0, h1] <;> omega

/-- Token-0 leg: m0 → m1, amount 5 (m0's token-0 anchor balance 10 → 5). -/
def mixTxTok0 : BatchTxMT := ⟨.m0, .m1, 0, 5, ⟨5⟩, ⟨5⟩⟩

/-- Token-1 leg: the SAME member m0 → m2, amount 4 in a DIFFERENT token
    (m0's token-1 anchor balance 6 → 2) — same-member-two-tokens is allowed
    by the per-(sender, token) single-debit rule R1. -/
def mixTxTok1 : BatchTxMT := ⟨.m0, .m2, 1, 4, ⟨4⟩, ⟨2⟩⟩

/-- A genuinely mixed-token batch satisfies the full TM-14 obligation. -/
theorem sampleMixedBatch_proven :
    BatchProvenMT sampleMT2 [mixTxTok0, mixTxTok1] := by
  constructor
  · intro tx htx
    simp [mixTxTok0, mixTxTok1] at htx
    rcases htx with h | h
    · subst h
      exact ⟨by show (0 : Fin 10).val < 2; decide,
             by show (0 : Int) ≤ 5; omega, rfl,
             by show (5 : Int) = 10 - 5; omega,
             by show (0 : Int) ≤ 5; omega⟩
    · subst h
      exact ⟨by show (1 : Fin 10).val < 2; decide,
             by show (0 : Int) ≤ 4; omega, rfl,
             by show (2 : Int) = 6 - 4; omega,
             by show (0 : Int) ≤ 2; omega⟩
  · refine ⟨?_, by simp [sendersDistinctMT]⟩
    intro v hv
    simp at hv
    subst hv
    exact Or.inr (by decide)

/-- m6: `batchMT_preserves_validity` instantiated on the mixed-token batch. -/
theorem sampleMixedBatch_valid :
    ValidEncStateMT (applyBatchMT sampleMT2 [mixTxTok0, mixTxTok1]) :=
  (batchMT_preserves_validity sampleMT2 [mixTxTok0, mixTxTok1]
    sampleMT2_valid sampleMixedBatch_proven).1

/-- m6: `batchMT_conserves_total` instantiated — EVERY token's total is
    conserved across the mixed-token batch. -/
theorem sampleMixedBatch_conserves_total (t : TokenSlot) :
    (applyBatchMT sampleMT2 [mixTxTok0, mixTxTok1]).total t
      = sampleMT2.total t :=
  batchMT_conserves_total sampleMT2 [mixTxTok0, mixTxTok1]
    sampleMixedBatch_proven t

/-- **TM-6 negative guard: the registry-resolution hypothesis is
    LOAD-BEARING.** If the destination credits a MIS-RESOLVED slot td' = 1 —
    a slot whose registry entry (base index 99) does NOT match the
    descriptor's base `tokenIndex` (0), i.e. `ResolvesMT dstMT 0 1` is false
    — then cross-channel conservation of base token 0 BREAKS: the source's
    token-0 pool drops by 5 while the destination's token-0 pool is
    unchanged (the 5 units materialize in base token 99 instead). This is
    exactly the TM-6 wrong-slot-credit attack. The scenario VISIBLY violates
    the hypotheses of `c2cMT_conservation_base` — its `hresr : ResolvesMT r
    u.tokenIndex td` is false here (`dstMT.registry 1 = 99 ≠ 0`, exhibited
    as `_hnres` below) — which is what excludes the attack; the in-circuit
    §N-4 resolution check is what discharges that hypothesis in practice. -/
theorem sampleC2C_misresolution_breaks_conservation :
    (applyBulkSendMT sampleMT .m0 0 sampleBulkMT).total 0
      + (applyBulkReceiveMT dstMT 1 1 sampleBulkMT).total 0
      ≠ sampleMT.total 0 + dstMT.total 0 := by
  -- `_hnres` is documentation-only (decorative by design): it exhibits, inside
  -- the proof, that the mis-resolved slot violates `ResolvesMT` — i.e. the
  -- hypotheses of `c2cMT_conservation_base` — without being needed for the
  -- arithmetic contradiction below.
  have _hnres : ¬ ResolvesMT dstMT sampleBulkMT.tokenIndex 1 := by
    intro hres
    have h99 : dstMT.registry 1 = 0 := hres.2
    simp [dstMT] at h99
  have hrecv := (c2cMT_frame_receive dstMT 1 1 sampleBulkMT 0 (by decide)).2.1
  have hsd : sampleBulkMT.senderDelta.pt = -5 := rfl
  have hsend : (applyBulkSendMT sampleMT .m0 0 sampleBulkMT).total 0
      = sampleMT.total 0 + sampleBulkMT.senderDelta.pt := by
    have h := updCt2_mapTotal sampleMT.encBal .m0 0 sampleBulkMT.senderDelta 0
    show mapTotal2 (updCt2 sampleMT.encBal .m0 0 sampleBulkMT.senderDelta) 0
        = mapTotal2 sampleMT.encBal 0 + sampleBulkMT.senderDelta.pt
    simp at h
    exact h
  intro heq
  omega

end Sanity

end ChannelSafetyMT
