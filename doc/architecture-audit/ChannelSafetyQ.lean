/-
# ChannelSafetyQ.lean — Machine-checked safety for detail2 §Q (dynamic co-signer membership)

HISTORICAL ONLY (2026-09-05 alignment): direct MSU was retired on 2026-09-02.
The current Manager has no direct-MSU entry point. The positive theorems below
describe the retired prototype, not a supported production capability; see
`doc/audit/lean-current-safety.md`. Definitions are retained for historical review.

Formalizes `detail2.md §Q`: adding a co-signer and rotating one's own signing key on a live
channel, authorized by the PREVIOUS set's N-of-N over the IMMS digest plus the affected party's
own consent (IMKR for rotation, IMJC for a joiner). This is the channel-layer (stage Q1) model —
the object `verify_member_set_update` (`src/wallet_core.rs`) accepts.

## Why a fresh model rather than reusing ChannelSafety2

`ChannelSafety2` fixes a 3-element `Member` inductive and models a signature as `signs : Member →
State → Tag → Prop` — the signing identity IS the slot. §Q's whole subject is a signing key that
can be REPLACED at a slot, and a slot count that can GROW. So the co-signer set is modeled here as
lists of `Key`s (rotatable) and `Regev` digests (preserved), decoupling the signing key from the
slot it occupies.

## Trust base (declared, per the discipline the honest headers keep)

  (A1) Signature unforgeability + collision resistance. As in ChannelSafety2, a signature is the
       FACT that a key signed a digest (`Sig : Key → Digest → Prop`); the theorems below take the
       N-of-N / consent sig facts the gate saw as HYPOTHESES and derive what acceptance entails.
       Constructing `Sig k d` for a key you do not hold is what A1 forbids — out of model, exactly
       as `signs` is in ChannelSafety2.
  (A2) The Regev digest identifies the decryption key. `rotate_preserves_regev` is what keeps this
       true across a rotation (the balance ciphertexts stay decryptable); Regev-key rotation is
       detail2 §Q-6 OUT OF SCOPE and is NOT modeled.

## What is DELIBERATELY NOT modeled (kept honest, cf. audit25-08-2026 Part 4)

  * The on-chain (stage Q2/Q3) transition and the validity-circuit re-statement of
    `member_set_immutable` — `member_set_immutable_on_normal_step` / `member_set_changes_iff_update`
    here are the SPEC-level invariant that Q2's circuit must be checked against; the
    implementation-Lean theorem is not touched by this file.
  * Digest injectivity is not assumed; no theorem here needs to distinguish two updates' digests.
  * Liveness beyond acceptance-consistency: `honest_member_can_rotate` proves the honest path is
    NOT fail-closed (the acceptance conditions are jointly satisfiable), not that inclusion/L1
    delivery succeeds (out of scope, as everywhere in this corpus).
-/

namespace ChannelSafetyQ

/-! ## §0 Self-contained list helpers (core Lean 4.10 has no `List.sum`; set-lemma names vary) -/

/-- Sum of an `Int` list. -/
def isum : List Int → Int
  | [] => 0
  | x :: xs => x + isum xs

@[simp] theorem isum_nil : isum [] = 0 := rfl
@[simp] theorem isum_cons (x : Int) (xs : List Int) : isum (x :: xs) = x + isum xs := rfl

theorem isum_append (a b : List Int) : isum (a ++ b) = isum a + isum b := by
  induction a with
  | nil => simp
  | cons x xs ih => simp only [List.cons_append, isum_cons, ih]; omega

/-- Reading back a `set` at its own index, proven by controlled induction (avoids relying on a
    particular library lemma name across Lean versions). -/
theorem getElem?_set_self {α : Type} : ∀ (l : List α) (i : Nat) (a : α),
    i < l.length → (l.set i a)[i]? = some a
  | [], i, a, h => absurd h (Nat.not_lt_zero i)
  | _ :: xs, 0, a, _ => by simp
  | _ :: xs, i + 1, a, h => by
      have hx : i < xs.length := Nat.lt_of_succ_lt_succ h
      simpa [List.set] using getElem?_set_self xs i a hx

/-! ## §1 Keys, digests, and the co-signer set -/

/-- A rotatable signing identity (Falcon `pk_g`/`pk_b` pair, abstracted). -/
abbrev Key := Nat
/-- A Regev public-key digest (`poseidon(regev_pk)`); identifies the decryption key. -/
abbrev Regev := Nat
/-- An L1 exit address (B-1b recipient). -/
abbrev Addr := Nat
/-- A hash output. -/
abbrev Digest := Nat

/-- The REGISTERED co-signer set: left-packed signing keys, their Regev digests, and a
    strictly-monotone version. `detail2.md §Q-1`. Keys and Regev digests are kept in SEPARATE
    slot-indexed lists so that a rotation, which touches only `keys`, provably leaves `regevs`
    untouched. -/
structure MemberSet where
  keys : List Key
  regevs : List Regev
  version : Nat
  deriving DecidableEq

/-- Number of co-signer slots. -/
def MemberSet.n (s : MemberSet) : Nat := s.keys.length

/-! ## §2 The update operation and its authorization -/

/-- `detail2.md §Q-1` `MemberSetOp`. -/
inductive MemberSetOp
  /-- New co-signer appended at slot `n` (left-packed prefix preserved). -/
  | addCosigner (k : Key) (r : Regev) (recip : Addr)
  /-- Replace the SIGNING key at `slot`; the Regev digest is preserved (§Q-6). -/
  | rotateKey (slot : Nat) (newK : Key)

/-- Apply an op structurally (the state delta only; authorization is separate). A rotation writes
    ONLY `keys`; `regevs` is copied verbatim. -/
def applyOp (s : MemberSet) : MemberSetOp → MemberSet
  | .addCosigner k r _ =>
      { keys := s.keys ++ [k], regevs := s.regevs ++ [r], version := s.version + 1 }
  | .rotateKey slot newK =>
      { keys := s.keys.set slot newK, regevs := s.regevs, version := s.version + 1 }

/-- IMMS digest — the message the PREVIOUS set's N-of-N signs (§Q-1). Abstract deterministic
    function of the update's identity; no theorem needs its injectivity. -/
opaque immsDigest : MemberSet → MemberSetOp → Digest

/-- IMKR digest — rotation self-consent, signed by the slot's CURRENT key (§Q-1). -/
opaque imkrDigest : MemberSet → Nat → Key → Digest

/-- IMJC digest — joiner consent, signed by the NEW key (§Q-1). -/
opaque imjcDigest : MemberSet → Key → Regev → Addr → Digest

/-- A signature fact: the holder of `Key` signed `Digest` (A1). -/
abbrev SigModel := Key → Digest → Prop

/-- Op-specific consent (§Q-1): a rotation needs the slot's CURRENT key over IMKR; a join needs
    the NEW key over IMJC. This is the "change your own key with your own signature" obligation,
    independent of the N-of-N (which already gives every member a veto). -/
def consentOK (Sig : SigModel) (s : MemberSet) : MemberSetOp → Prop
  | .rotateKey slot newK => Sig (s.keys.getD slot 0) (imkrDigest s slot newK)
  | .addCosigner k r recip => Sig k (imjcDigest s k r recip)

/-- `detail2.md §Q-2` — the gate `verify_member_set_update`. `next` is accepted from `prev` under
    `op` iff: it is the structural application, the version advances by exactly one, the PREVIOUS
    set's full N-of-N signed the IMMS digest, and the op's consent holds. -/
def AuthorizedUpdate (Sig : SigModel) (prev next : MemberSet) (op : MemberSetOp) : Prop :=
  next = applyOp prev op ∧
  next.version = prev.version + 1 ∧
  (∀ k ∈ prev.keys, Sig k (immsDigest prev op)) ∧
  consentOK Sig prev op

/-! ## §3 Soundness — what acceptance entails -/

/-- **T1 (prev-set N-of-N required).** No new member set is accepted without the PREVIOUS set's
    full N-of-N over the IMMS digest — the cross-set root of trust. -/
theorem update_requires_prev_nofn
    {Sig : SigModel} {prev next : MemberSet} {op : MemberSetOp}
    (h : AuthorizedUpdate Sig prev next op) :
    ∀ k ∈ prev.keys, Sig k (immsDigest prev op) :=
  h.2.2.1

/-- **T2 (rotation needs self-consent).** A `rotateKey` is accepted only if the slot's CURRENT key
    signed the IMKR digest — "change your own key with your own signature." Even a full N-of-N
    cannot rotate a slot whose current holder did not consent. -/
theorem rotate_requires_self_consent
    {Sig : SigModel} {prev next : MemberSet} {slot : Nat} {newK : Key}
    (h : AuthorizedUpdate Sig prev next (.rotateKey slot newK)) :
    Sig (prev.keys.getD slot 0) (imkrDigest prev slot newK) :=
  h.2.2.2

/-- **T3a (rotation preserves EVERY Regev key).** detail2 §Q-6: the balance ciphertexts stay
    decryptable because rotation touches only the signing key. -/
theorem rotate_preserves_regev (s : MemberSet) (slot : Nat) (newK : Key) :
    (applyOp s (.rotateKey slot newK)).regevs = s.regevs := rfl

/-- **T3b (rotation is effective).** With a new key, the rotated slot's signing key changes to it,
    so a state co-signed under the OLD key no longer satisfies the new set's N-of-N. -/
theorem rotate_sets_new_key (s : MemberSet) (slot : Nat) (newK : Key) (hslot : slot < s.n) :
    (applyOp s (.rotateKey slot newK)).keys[slot]? = some newK :=
  getElem?_set_self s.keys slot newK hslot

/-- **T4a (add preserves the existing keys, appends the joiner).** The left-packed prefix is
    preserved and the joiner sits at slot `n` (§Q-4b). -/
theorem add_appends_joiner (s : MemberSet) (k : Key) (r : Regev) (recip : Addr) :
    (applyOp s (.addCosigner k r recip)).keys = s.keys ++ [k] := rfl

/-- **T4b (the count grows by exactly one).** -/
theorem add_grows_by_one (s : MemberSet) (k : Key) (r : Regev) (recip : Addr) :
    (applyOp s (.addCosigner k r recip)).n = s.n + 1 := by
  simp [applyOp, MemberSet.n]

/-- **T5 (version strictly advances).** The gate requires `next.version = prev.version + 1`, so a
    replay at or below the current version is rejected (detail2 §Q-5 monotonicity). -/
theorem update_version_advances
    {Sig : SigModel} {prev next : MemberSet} {op : MemberSetOp}
    (h : AuthorizedUpdate Sig prev next op) :
    next.version = prev.version + 1 :=
  h.2.1

/-! ## §4 Conservation — an update moves no value -/

/-- Per-slot channel balances, one entry per co-signer slot. -/
abbrev Bal := List Int

/-- Balance-state side of an op: add opens a fresh ZERO slot (a joined slot adds no value —
    the §Q / delegate-join conservation argument); rotate leaves balances untouched. -/
def applyBal (b : Bal) : MemberSetOp → Bal
  | .addCosigner _ _ _ => b ++ [0]
  | .rotateKey _ _ => b

/-- **T6a (add conserves the total).** Opening a co-signer slot at zero balance keeps the channel
    total exactly. -/
theorem add_conserves_total (b : Bal) (k : Key) (r : Regev) (recip : Addr) :
    isum (applyBal b (.addCosigner k r recip)) = isum b := by
  simp [applyBal, isum_append]

/-- **T6b (rotation conserves the balances, pointwise).** -/
theorem rotate_conserves_balances (b : Bal) (slot : Nat) (newK : Key) :
    applyBal b (.rotateKey slot newK) = b := rfl

/-! ## §5 The re-statement of member-set immutability

    The implementation Lean proves `member_set_immutable`: the update path COPIES the member root,
    so it can NEVER change (`UpdateUser.lean:47-51`). detail2 §Q-3 makes it change under an
    authorized MemberSetUpdate. The correct invariant — which Q2's circuit must be checked against
    — is that the set is immutable EXCEPT under an authorized update. -/

/-- A channel step: an ordinary co-signed state transition, or a member-set update. -/
inductive StepKind
  | normalTx
  | memberUpdate (op : MemberSetOp)

/-- The member-set component of a step. An ordinary transition PRESERVES the set verbatim (the
    `member_pubkeys_root` copy of `UpdateUser.lean`); a member-set update advances it by `applyOp`. -/
def stepSet (s : MemberSet) : StepKind → MemberSet
  | .normalTx => s
  | .memberUpdate op => applyOp s op

/-- **T7 (immutable on ordinary transitions).** The registered co-signer set — keys, Regev
    digests, and version — is unchanged by any non-update step. The preserved direction of
    `member_set_immutable`, now carrying the `¬ isMemberSetUpdate` hypothesis. -/
theorem member_set_immutable_on_normal_step (s : MemberSet) :
    stepSet s .normalTx = s := rfl

/-- **T8 (advances ONLY under a member-set update, and only as the op dictates).** A step changes
    the set only if it is a member-set update, and then the new set is exactly `applyOp`. Together
    with T7 this is `member_set_immutable_unless_authorized`: no hidden member-set change rides an
    ordinary block. -/
theorem member_set_changes_iff_update (s : MemberSet) :
    ∀ sk : StepKind, stepSet s sk ≠ s →
      ∃ op, sk = .memberUpdate op ∧ stepSet s sk = applyOp s op := by
  intro sk hne
  cases sk with
  | normalTx => exact absurd rfl hne
  | memberUpdate op => exact ⟨op, rfl, rfl⟩

/-! ## §6 Liveness — the honest path is not fail-closed (R1)

    The gate-8 lesson (`audit25-08-2026` Part 2): a fail-closed check no honest party can satisfy
    is a fund-lock the soundness axis cannot see. We prove the ACCEPTANCE direction: an honest,
    consenting member CAN produce an update the gate accepts (the acceptance conditions are jointly
    satisfiable, not mutually contradictory). -/

/-- **T9 (an honest member CAN rotate).** Given the cooperative N-of-N over IMMS and the rotating
    slot's own IMKR consent, `AuthorizedUpdate` holds — a correctly-formed rotation by a consenting
    member is ACCEPTED. -/
theorem honest_member_can_rotate
    (prev : MemberSet) (slot : Nat) (newK : Key) (Sig : SigModel)
    (hnofn : ∀ k ∈ prev.keys, Sig k (immsDigest prev (.rotateKey slot newK)))
    (hself : Sig (prev.keys.getD slot 0) (imkrDigest prev slot newK)) :
    AuthorizedUpdate Sig prev (applyOp prev (.rotateKey slot newK)) (.rotateKey slot newK) :=
  ⟨rfl, rfl, hnofn, hself⟩

/-- **T10 (an honest joiner CAN be added).** The dual for AddCosigner: current N-of-N over IMMS
    plus the joiner's own IMJC consent ⇒ accepted. -/
theorem honest_join_accepted
    (prev : MemberSet) (k : Key) (r : Regev) (recip : Addr) (Sig : SigModel)
    (hnofn : ∀ kk ∈ prev.keys, Sig kk (immsDigest prev (.addCosigner k r recip)))
    (hjoin : Sig k (imjcDigest prev k r recip)) :
    AuthorizedUpdate Sig prev (applyOp prev (.addCosigner k r recip)) (.addCosigner k r recip) :=
  ⟨rfl, rfl, hnofn, hjoin⟩

end ChannelSafetyQ
