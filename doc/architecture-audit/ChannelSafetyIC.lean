/-
# ChannelSafetyIC.lean — inter-channel credit: no-double-credit, §P aggregation, multi-dest
# conservation (audit25-08-2026 Part 3 V4)

The credit path was the corpus's weakest link (audit Part 1(d)):
  * "the mechanism that prevents the DOUBLE CREDIT of the same settled tx … is UNMODELED"
    (`lean-safety-proof2.md:97-99`, abstraction M4) — modeled and proved here (§2).
  * detail2 §P (aggregated inter-channel rounds, per-leaf IMI5 sender signature, the root-signer's
    five-point checklist) had no Lean statement — modeled and proved here (§3).
  * Cross-channel conservation was proven ONLY single-destination (`honly` premise,
    `ChannelSafety21.lean:252`; flagged in audit Part 4) — the MULTI-destination partition
    theorem is proved here (§4).

## Trust base

  (A1) Signatures are facts (`Sig : Key → Digest → Prop`), as in ChannelSafetyQ.
  (CR) `computeRoot` collision resistance enters ONLY in `agg_root_binds_manifest` as an explicit
       hypothesis `hinj` — the same disclosed pattern as `interChannel_conservation_bound`'s
       `commit`+`hinj`. No other theorem consumes it.

## Not modeled (honest)

  * The E-2/E-1 proof contents (implementation-Lean / A2). The credit guard here is the REPLAY
    LEDGER (`applied_tx_identities` / settled-chain membership), which is precisely the mechanism
    M4 left out.
  * Regev ciphertext arithmetic — plaintext `Int`, as the whole v2 lineage (A5 modulus caveat
    applies here exactly as there).
-/

namespace ChannelSafetyIC

/-! ## §0 List helpers (self-contained, as ChannelSafetyQ) -/

def isum : List Int → Int
  | [] => 0
  | x :: xs => x + isum xs

@[simp] theorem isum_nil : isum [] = 0 := rfl
@[simp] theorem isum_cons (x : Int) (xs : List Int) : isum (x :: xs) = x + isum xs := rfl

/-! ## §1 The destination channel and the settled-tx replay ledger -/

/-- A settled inter-channel tx identity (the replay-ledger key: tx hash / IMCK identity). -/
abbrev TxId := Nat

/-- Destination-channel accounting view: the recipient balance and the ledger of tx identities
    ALREADY credited (the `applied_tx_identities` replay ledger — M4's missing mechanism). -/
structure DestState where
  bal : Int
  credited : List TxId
  deriving DecidableEq

/-- The credit step: crediting `amt` for settled tx `id` is guarded on `id ∉ credited` and
    RECORDS `id`. This is the fail-closed replay check `receive_inter_channel` /
    `cosign-l1-deposit-import` run before any balance change. -/
inductive Credit : DestState → TxId → Int → DestState → Prop
  | step {s : DestState} {id : TxId} {amt : Int} :
      id ∉ s.credited →
      Credit s id amt ⟨s.bal + amt, id :: s.credited⟩

/-! ## §2 No double credit — the M4 gap, closed -/

/-- **T1 (a credit requires freshness and records the identity).** -/
theorem credit_requires_fresh
    {s s' : DestState} {id : TxId} {amt : Int} (h : Credit s id amt s') :
    id ∉ s.credited ∧ id ∈ s'.credited ∧ s'.bal = s.bal + amt := by
  cases h with
  | step hfresh => exact ⟨hfresh, List.mem_cons_self _ _, rfl⟩

/-- **T2 (the ledger only grows).** Every credit preserves all previously recorded identities. -/
theorem credited_monotone
    {s s' : DestState} {id : TxId} {amt : Int} (h : Credit s id amt s') :
    ∀ x ∈ s.credited, x ∈ s'.credited := by
  cases h with
  | step _ => exact fun x hx => List.mem_cons_of_mem _ hx

/-- **T3 (NO DOUBLE CREDIT).** The same settled tx can never be credited twice, at any distance:
    once `id` is credited, every later state in any credit chain still records it (T2), so a second
    `Credit _ id _ _` step is impossible. Stated over an arbitrary chain of intervening credits. -/
inductive CreditChain : DestState → DestState → Prop
  | refl (s : DestState) : CreditChain s s
  | step {s t u : DestState} {id : TxId} {amt : Int} :
      Credit s id amt t → CreditChain t u → CreditChain s u

theorem chain_preserves_credited
    {s u : DestState} (h : CreditChain s u) :
    ∀ x ∈ s.credited, x ∈ u.credited := by
  induction h with
  | refl _ => exact fun _ hx => hx
  | step hc _ ih => exact fun x hx => ih x (credited_monotone hc x hx)

/-- The headline: after `id` is credited once, no state reachable by ANY further chain of credits
    admits a second credit of `id`. This is exactly the double-credit-of-the-same-settled-tx
    attack `lean-safety-proof2.md:97-99` declared unmodeled. -/
theorem no_double_credit
    {s0 s1 u : DestState} {id : TxId} {amt amt' : Int}
    (hfirst : Credit s0 id amt s1) (hchain : CreditChain s1 u) :
    ¬ ∃ u', Credit u id amt' u' := by
  rintro ⟨u', hsecond⟩
  have hrec : id ∈ s1.credited := (credit_requires_fresh hfirst).2.1
  have hstill : id ∈ u.credited := chain_preserves_credited hchain id hrec
  exact (credit_requires_fresh hsecond).1 hstill

/-! ## §3 detail2 §P — the aggregated window and the root-signer's checklist -/

/-- Keys / digests, as ChannelSafetyQ. -/
abbrev Key := Nat
abbrev Digest := Nat
abbrev SigModel := Key → Digest → Prop

/-- One leaf of an aggregated window: source channel, its sender's signing key, and the canonical
    leaf content (Transfer→TxV2 digest). -/
structure Leaf where
  channel : Nat
  sender : Key
  content : Nat
  deriving DecidableEq

/-- The leaf's IMI5 digest — what the SENDER signs (§P-2). -/
opaque imi5 : Leaf → Digest

/-- The aggregated tree root over an ordered manifest (§P-1: leaf at index = source channel). -/
opaque computeRoot : List Leaf → Digest

/-- §P-3, the root-signer's checklist as the acceptance predicate: a member co-signs a state whose
    h2_tag commits `root` ONLY when (1) the root IS the full-manifest recompute — completeness:
    nothing omitted, nothing added, nothing misplaced — and (2) EVERY leaf carries its sender's
    IMI5 signature. -/
def AggAccepted (Sig : SigModel) (manifest : List Leaf) (root : Digest) : Prop :=
  root = computeRoot manifest ∧
  ∀ l ∈ manifest, Sig l.sender (imi5 l)

/-- **T4 (no unsigned leaf under a signed root).** Acceptance entails every manifest leaf is
    sender-signed — the user-stated §P invariant "no inter-channel tx without its sender's
    signature enters the tree". -/
theorem agg_leaf_authorized
    {Sig : SigModel} {manifest : List Leaf} {root : Digest}
    (h : AggAccepted Sig manifest root) :
    ∀ l ∈ manifest, Sig l.sender (imi5 l) :=
  h.2

/-- **T5 (the root binds the manifest — completeness).** Under collision resistance of the tree
    fold (`hinj`, the disclosed CR hypothesis), two accepted views of the SAME root are the SAME
    manifest: no foreign/extra leaf can hide in a tree whose root a member verified against its
    full manifest. -/
theorem agg_root_binds_manifest
    {Sig Sig' : SigModel} {m m' : List Leaf} {root : Digest}
    (hinj : ∀ a b : List Leaf, computeRoot a = computeRoot b → a = b)
    (h : AggAccepted Sig m root) (h' : AggAccepted Sig' m' root) :
    m = m' := by
  exact hinj m m' (h.1 ▸ h'.1 ▸ rfl)

/-- **T6 (R1 — an honest window is acceptable).** If every sender in the manifest signed its leaf,
    the manifest's own recompute is accepted: the checklist is satisfiable, not a fail-closed wall. -/
theorem honest_window_accepted
    (Sig : SigModel) (manifest : List Leaf)
    (hsigs : ∀ l ∈ manifest, Sig l.sender (imi5 l)) :
    AggAccepted Sig manifest (computeRoot manifest) :=
  ⟨rfl, hsigs⟩

/-! ## §4 Multi-destination conservation — closing the `honly` gap

    `bulk_interChannel_conservation_dest` (ChannelSafety21) requires every entry to target ONE
    destination. Here: a window's entries fan out to MANY destinations; the sum of all
    destinations' credits equals the total debited. -/

/-- A transfer entry: destination channel and (positive) amount. -/
structure Entry where
  dest : Nat
  amt : Int
  deriving DecidableEq

/-- Credit accrued at destination `d` from a window's entries (fold once over the window). -/
def creditAt (entries : List Entry) (d : Nat) : Int :=
  isum (entries.map (fun e => if e.dest = d then e.amt else 0))

/-- Total debited from the source: the sum of all entry amounts. -/
def totalDebit (entries : List Entry) : Int :=
  isum (entries.map (·.amt))

/-- Duplicate-freedom, self-contained (core Lean has no `List.Nodup`). -/
def nodup : List Nat → Prop
  | [] => True
  | x :: xs => x ∉ xs ∧ nodup xs

/-- All-zero map sums to zero. -/
theorem isum_map_zero (ds : List Nat) : isum (ds.map (fun _ => (0 : Int))) = 0 := by
  induction ds with
  | nil => rfl
  | cons _ xs ih => simp [ih]

/-- Indicator-sum: over a duplicate-free list containing `d`, the indicator of `d` sums to exactly
    its value. -/
theorem isum_indicator (ds : List Nat) (d : Nat) (a : Int)
    (hnodup : nodup ds) (hd : d ∈ ds) :
    isum (ds.map (fun x => if x = d then a else 0)) = a := by
  induction ds with
  | nil => cases hd
  | cons x xs ih =>
    obtain ⟨hx, hxs⟩ := hnodup
    by_cases hxd : x = d
    · subst hxd
      -- d = x, and x ∉ xs ⇒ the tail's indicator sums to 0.
      have htail : isum (xs.map (fun y => if y = x then a else 0)) = 0 := by
        have : xs.map (fun y => if y = x then a else 0) = xs.map (fun _ => (0 : Int)) := by
          apply List.map_congr_left
          intro y hy
          have : y ≠ x := fun h => hx (h ▸ hy)
          simp [this]
        rw [this, isum_map_zero]
      simp [htail]
    · have hd' : d ∈ xs := by
        cases hd with
        | head => exact absurd rfl hxd
        | tail _ h => exact h
      simp [hxd, ih hxs hd']

/-- **T7 (MULTI-destination joint conservation).** For ANY window whose entries' destinations all
    lie in a duplicate-free destination list `ds`, the sum over ALL destinations of their credits
    equals the total debited from the source. No single-`dest` restriction (the `honly` gap): the
    fan-out is exact — value credited across every destination is precisely the value the source
    lost, so crediting one destination's share to another cannot conserve. -/
theorem multi_dest_conservation
    (entries : List Entry) (ds : List Nat)
    (hnodup : nodup ds) (hcover : ∀ e ∈ entries, e.dest ∈ ds) :
    isum (ds.map (creditAt entries)) = totalDebit entries := by
  induction entries with
  | nil =>
    have : ds.map (creditAt []) = ds.map (fun _ => (0 : Int)) := by
      apply List.map_congr_left
      intro d _
      simp [creditAt]
    rw [this, isum_map_zero]
    rfl
  | cons e rest ih =>
    have hrest : ∀ x ∈ rest, x.dest ∈ ds := fun x hx => hcover x (List.mem_cons_of_mem _ hx)
    have hd : e.dest ∈ ds := hcover e (List.mem_cons_self _ _)
    have hsplit : ds.map (creditAt (e :: rest))
        = ds.map (fun d => (if e.dest = d then e.amt else 0) + creditAt rest d) := by
      apply List.map_congr_left
      intro d _
      simp [creditAt]
    have hadd : ∀ (f g : Nat → Int) (l : List Nat),
        isum (l.map (fun d => f d + g d)) = isum (l.map f) + isum (l.map g) := by
      intro f g l
      induction l with
      | nil => rfl
      | cons x xs ihx => simp only [List.map_cons, isum_cons, ihx]; omega
    have hflip : ds.map (fun d => if e.dest = d then e.amt else 0)
        = ds.map (fun d => if d = e.dest then e.amt else 0) := by
      apply List.map_congr_left
      intro d _
      by_cases h : d = e.dest
      · simp [h]
      · have h' : e.dest ≠ d := fun hh => h hh.symm
        simp [h, h']
    calc isum (ds.map (creditAt (e :: rest)))
        = isum (ds.map (fun d => (if e.dest = d then e.amt else 0) + creditAt rest d)) := by
          rw [hsplit]
      _ = isum (ds.map (fun d => if e.dest = d then e.amt else 0))
            + isum (ds.map (creditAt rest)) := hadd _ _ ds
      _ = e.amt + totalDebit rest := by
          rw [hflip, isum_indicator ds e.dest e.amt hnodup hd, ih hrest]
      _ = totalDebit (e :: rest) := by simp [totalDebit]

end ChannelSafetyIC
