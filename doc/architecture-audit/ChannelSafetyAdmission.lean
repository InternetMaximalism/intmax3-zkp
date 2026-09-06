import Std

/-!
# Private credit admission and reserved deposit capacity

Manual model of runtime base `05ec7ae` (MLE pin `6cefc6ac`), Lean 4.10.
Source correspondence:
* `src/channel_credit_safety.rs`: `as_u64`, `add_bounds`, `tighter_bound`,
  `with_owned_plaintext`, `bootstrap`, `advance_authenticated`, `can_credit`.
* `src/bin/channel_member.rs`: `owned_credit_plaintexts`,
  `admit_credit_safe_successor_excluding`, `check_reserved_credit_capacity`.
* `src/bin/channel_member/deposit_capacity.rs`: `pending_at`,
  `check_candidates`, `reserve`; the import caller retains the reservation
  through proving/signing and completes it only with its exact deposit WAL.
* `src/circuits/channel/state_update_verifier.rs` ordinary metadata/state
  checks and `src/wallet_core.rs` transition verifiers run BEFORE this gate.

Amounts are nonnegative mathematical integers. `clip` explicitly models the
inclusive u64 limit; it does NOT truncate or reduce modulo a field. Unknown
private evidence is `none`, not zero. `chooseOwned` checks the u64 domain
explicitly because its Rust input is already a u64. Outer `none` is rejection;
`some none` is successful preservation of an UNKNOWN, UNCHANGED position.

Assumptions are stated at use sites, not imported as axioms: authenticated
nonnegative token accounting; the same key/ciphertext means the same value;
and locally verified exact decryption/opening. No theorem assumes the desired
recipient u64 safety as the result of a remote proof. `token_accounting_pool`
derives the changed-set budget from accounting equations with a per-token
unallocated remainder. The bound on its release by the runtime's scalar
unallocated decrease is an explicit refinement obligation. The scalar is
charged conservatively to EACH changed token, never moved between tokens.

The range module does not authenticate roots, signatures, channels, registries,
transitions, encrypted plaintexts, exit shape, or proof soundness. Those checks
are separate runtime premises. State-digest binding and the private cache's
provenance/rollback protection are not cryptographic theorems here. Nat fund
amounts intentionally overapproximate U256: these range-only properties impose
no global fund cap but do NOT prove full-width deposit/fund arithmetic valid.

The reservation model is the per-cell projection of the native aggregate of
all pending candidate-slot reservations. Every alternative candidate reserves
the full amount; this can over-reserve, not under-reserve. Once the exact import
WAL commits, the native reservation becomes completed for ALL candidate slots.
The selected slot converts its reserved amount into balance; unselected slots
release the same amount without changing balance. The model conservatively
linearizes that multi-cell operation as selected import THEN unused-candidate
releases. These intermediate states retain excess reservations, so safety is
preserved; this is not an extracted atomic-WAL or concurrency proof. A supplied
completion observation must denote the exact committed reservation/transaction,
not merely a confirmed L1 deposit or an unfinished signing operation.
Persistent state and atomic WAL commit are modeled at committed boundaries. The environment must
honor the successful fsync-before-spend response, exact transaction/intent
binding, mutual exclusion and retained completion tombstones. This module does
NOT prove filesystem crash semantics, receipt finality, exactly-once external
spending, noise/refresh-budget admission, or withdrawal liveness. It proves
capacity conservation even across arbitrarily many modeled committed steps.

These are executable abstraction theorems, not an automatic Rust refinement
certificate, whole-protocol conservation proof, or claim of new circuit proofs.
No imported historical model is promoted to a current implementation result.
-/

namespace ChannelSafetyAdmission

def u64Max : Nat := 2 ^ 64 - 1
abbrev Bound := Option Nat

def clip (n : Nat) : Bound := if n ≤ u64Max then some n else none

def addBounds : Bound → Bound → Bound
  | some a, some b => clip (a + b)
  | _, _ => none

def tighter : Bound → Bound → Bound
  | some a, some b => some (min a b)
  | some a, none => some a
  | none, some b => some b
  | none, none => none

def BoundSound (value : Nat) : Bound → Prop
  | none => True
  | some upper => value ≤ upper ∧ upper ≤ u64Max

/-- Owned entries come only from exact local decryption/verified openings. -/
def OwnedExact (value : Nat) : Bound → Prop
  | none => True
  | some opening => opening = value ∧ opening ≤ u64Max

def chooseOwned (bound owned : Bound) : Option Bound :=
  match owned with
  | none => some bound
  | some value =>
    if value ≤ u64Max then
      match bound with
      | none => some (some value)
      | some upper => if value ≤ upper then some (some value) else none
    else none

/-- `carried` is the old cell bound or the changed-set pooled bound. -/
def admitCell (changed : Bool) (carried : Bound) (fund : Nat)
    (owned : Bound) : Option Bound :=
  match chooseOwned (tighter carried (clip fund)) owned with
  | none => none
  | some known => if changed && known.isNone then none else some known

theorem clip_sound {value amount : Nat} (h : value ≤ amount) :
    BoundSound value (clip amount) := by
  unfold clip
  split <;> simp_all [BoundSound]

theorem evidence_not_zero : BoundSound 37 none ∧ ¬ BoundSound 37 (some 0) := by
  simp [BoundSound]

theorem sound_mono {a b : Nat} {bound : Bound}
    (hab : a ≤ b) (hb : BoundSound b bound) : BoundSound a bound := by
  cases bound with
  | none => trivial
  | some upper => exact ⟨Nat.le_trans hab hb.1, hb.2⟩

theorem addBounds_sound {a b : Nat} {x y : Bound}
    (hx : BoundSound a x) (hy : BoundSound b y) :
    BoundSound (a + b) (addBounds x y) := by
  cases x with
  | none => trivial
  | some x =>
    cases y with
    | none => trivial
    | some y =>
      apply clip_sound
      exact Nat.add_le_add hx.1 hy.1

theorem tighter_sound {value : Nat} {x y : Bound}
    (hx : BoundSound value x) (hy : BoundSound value y) :
    BoundSound value (tighter x y) := by
  cases x with
  | none => cases y <;> assumption
  | some x =>
    cases y with
    | none => exact hx
    | some y =>
      exact ⟨Nat.le_min.mpr ⟨hx.1, hy.1⟩, Nat.le_trans (Nat.min_le_left x y) hx.2⟩

theorem chooseOwned_sound {value : Nat} {bound owned result : Bound}
    (hb : BoundSound value bound) (ho : OwnedExact value owned)
    (h : chooseOwned bound owned = some result) : BoundSound value result := by
  cases owned with
  | none =>
    simp [chooseOwned] at h
    subst result
    exact hb
  | some opening =>
    rcases ho with ⟨rfl, hmax⟩
    cases bound with
    | none =>
      simp [chooseOwned, hmax] at h
      subst result
      exact ⟨Nat.le_refl _, hmax⟩
    | some upper =>
      simp [chooseOwned, hmax, hb.1] at h
      subst result
      exact ⟨Nat.le_refl _, hmax⟩

theorem owned_exact_admitted {value fund : Nat} {carried : Bound}
    (hv : value ≤ u64Max) (hf : value ≤ fund)
    (hc : BoundSound value carried) (changed : Bool) :
    admitCell changed carried fund (some value) = some (some value) := by
  have ht := tighter_sound hc (clip_sound hf)
  unfold admitCell
  cases hbound : tighter carried (clip fund) with
  | none => simp [chooseOwned, hv]
  | some upper =>
    rw [hbound] at ht
    simp [chooseOwned, hv, ht.1]

theorem admitted_bound_sound {value fund : Nat} {carried owned result : Bound}
    {changed : Bool} (hc : BoundSound value carried) (hf : value ≤ fund)
    (ho : OwnedExact value owned)
    (h : admitCell changed carried fund owned = some result) :
    BoundSound value result := by
  have ht := tighter_sound hc (clip_sound hf)
  unfold admitCell at h
  cases hchoose : chooseOwned (tighter carried (clip fund)) owned with
  | none => simp [hchoose] at h
  | some known =>
    simp only [hchoose] at h
    split at h
    · contradiction
    · cases h
      exact chooseOwned_sound ht ho hchoose

theorem changed_admission_is_u64 {value fund : Nat} {carried owned result : Bound}
    (hc : BoundSound value carried) (hf : value ≤ fund)
    (ho : OwnedExact value owned)
    (h : admitCell true carried fund owned = some result) : value ≤ u64Max := by
  have hs := admitted_bound_sound hc hf ho h
  cases result with
  | some upper => exact Nat.le_trans hs.1 hs.2
  | none =>
    unfold admitCell at h
    cases hchoose : chooseOwned (tighter carried (clip fund)) owned with
    | none => simp [hchoose] at h
    | some known => cases known <;> simp [hchoose] at h

/-- Closure for a complete ordinary transition: affected cells use the gate;
    every unaffected cell keeps its already safe value. `carriedSound` is
    obtained from `pooled_evidence_sound` for the changed set, not from a
    request-carried bound. No range claim is made for bootstrapped unknown
    values unless the authenticated initial state already has that range. -/
theorem all_cells_range_preserved {CellId : Type}
    (before after fund : CellId → Nat) (changed : CellId → Bool)
    (carried owned result : CellId → Bound)
    (initial : ∀ c, before c ≤ u64Max)
    (frame : ∀ c, changed c = false → after c = before c)
    (carriedSound : ∀ c, changed c = true → BoundSound (after c) (carried c))
    (fundSound : ∀ c, after c ≤ fund c)
    (ownedExact : ∀ c, OwnedExact (after c) (owned c))
    (admitted : ∀ c, admitCell (changed c) (carried c) (fund c) (owned c) = some (result c)) :
    ∀ c, after c ≤ u64Max := by
  intro c
  cases hc : changed c with
  | false => rw [frame c hc]; exact initial c
  | true =>
    have ha := admitted c
    rw [hc] at ha
    exact changed_admission_is_u64 (carriedSound c hc) (fundSound c) (ownedExact c) ha

theorem unknown_unchanged_not_blocked {fund : Nat} (h : u64Max < fund) :
    admitCell false none fund none = some none := by
  simp [admitCell, chooseOwned, tighter, clip, Nat.not_le.mpr h]

theorem unknown_changed_requires_evidence {fund : Nat} (h : u64Max < fund) :
    admitCell true none fund none = none := by
  simp [admitCell, chooseOwned, tighter, clip, Nat.not_le.mpr h]

theorem small_fund_fastpath {fund : Nat} (h : fund ≤ u64Max) :
    admitCell true none fund none = some (some fund) := by
  simp [admitCell, chooseOwned, tighter, clip, h]

/-- A known bound allows hidden redistribution even when the fund is wide. -/
theorem known_bound_no_global_cap {upper fund : Nat}
    (_valid : upper ≤ u64Max) (wide : u64Max < fund) :
    admitCell true (some upper) fund none = some (some upper) := by
  simp [admitCell, chooseOwned, tighter, clip, Nat.not_le.mpr wide]

def sumBounds : List Bound → Bound
  | [] => some 0
  | b :: bs => addBounds b (sumBounds bs)

def sumValues : List Nat → Nat
  | [] => 0
  | n :: ns => n + sumValues ns

def EvidenceList : List Nat → List Bound → Prop
  | [], [] => True
  | v :: vs, b :: bs => BoundSound v b ∧ EvidenceList vs bs
  | _, _ => False

theorem sumBounds_sound {values : List Nat} {bounds : List Bound}
    (h : EvidenceList values bounds) : BoundSound (sumValues values) (sumBounds bounds) := by
  induction values generalizing bounds with
  | nil =>
    cases bounds with
    | nil => exact ⟨Nat.le_refl _, Nat.zero_le _⟩
    | cons => contradiction
  | cons v vs ih =>
    cases bounds with
    | nil => contradiction
    | cons b bs => exact addBounds_sound h.1 (ih h.2)

/-- The unallocated-release term is necessary for phase 2 of an incoming import.
    `stable` cancels because unchanged ciphertexts AND registered keys are fixed.
    `release` is the conservative scalar drop charged to this token. -/
theorem token_accounting_pool {before after stable oldFree newFree oldFund newFund release : Nat}
    (oldAccounting : before + stable + oldFree = oldFund)
    (newAccounting : after + stable + newFree = newFund)
    (allocation : oldFree - newFree ≤ release) :
    after ≤ before + (newFund - oldFund) + release := by
  omega

def pooled (bounds : List Bound) (fundGrowth allocationRelease : Nat) : Bound :=
  addBounds (addBounds (clip fundGrowth) (clip allocationRelease)) (sumBounds bounds)

/-- Includes checked accumulation of ALL changed predecessor cells. If any term
    is unknown/too wide, the pool stays unknown; other evidence may still admit. -/
theorem pooled_evidence_sound {values : List Nat} {bounds : List Bound}
    {value growth release : Nat} (he : EvidenceList values bounds)
    (budget : value ≤ sumValues values + growth + release) :
    BoundSound value (pooled bounds growth release) := by
  apply sound_mono (b := growth + release + sumValues values)
  · omega
  · exact addBounds_sound
      (addBounds_sound (clip_sound (Nat.le_refl _)) (clip_sound (Nat.le_refl _)))
      (sumBounds_sound he)

/-- Connects token accounting to the actual changed-cell admission algorithm.
    `nextCell` is any one of the nonnegative changed balances (bounded by their
    sum). Owned evidence may rescue an intentionally loose/overflowed pool. -/
theorem accounted_changed_cell_is_u64
    {oldValues : List Nat} {oldBounds : List Bound}
    {afterSum stable oldFree newFree oldFund newFund release value : Nat}
    {owned result : Bound}
    (evidence : EvidenceList oldValues oldBounds)
    (oldAccounting : sumValues oldValues + stable + oldFree = oldFund)
    (newAccounting : afterSum + stable + newFree = newFund)
    (allocation : oldFree - newFree ≤ release)
    (nextCell : value ≤ afterSum) (ownedExact : OwnedExact value owned)
    (admitted : admitCell true (pooled oldBounds (newFund - oldFund) release)
      newFund owned = some result) : value ≤ u64Max := by
  have pool := token_accounting_pool oldAccounting newAccounting allocation
  have budget : value ≤ sumValues oldValues + (newFund - oldFund) + release := by omega
  have fund : value ≤ newFund := by omega
  exact changed_admission_is_u64 (pooled_evidence_sound evidence budget) fund ownedExact admitted

/-- Bootstrap learns only the token fund or verified own opening, never a
    peer's asserted balance. Unknown positions remain deliberately unknown. -/
def bootstrapCell (fund : Nat) (owned : Bound) : Option Bound :=
  chooseOwned (clip fund) owned

theorem bootstrap_sound {value fund : Nat} {owned result : Bound}
    (hf : value ≤ fund) (ho : OwnedExact value owned)
    (h : bootstrapCell fund owned = some result) : BoundSound value result := by
  exact chooseOwned_sound (clip_sound hf) ho h

/-- Existing public-credit preflight, with an explicit Nat-domain guard for
    the amount which is a u64 in Rust. It does not authorize a deposit itself. -/
def canCredit (before : Bound) (fund amount : Nat) (ownedBefore : Bound) : Bool :=
  if amount ≤ u64Max then
    match chooseOwned (tighter before (clip fund)) ownedBefore with
    | none => false
    | some known =>
      (tighter (addBounds known (some amount))
        (addBounds (clip fund) (some amount))).isSome
  else false

theorem public_credit_preflight_safe {value fund amount : Nat} {before owned : Bound}
    (he : BoundSound value before) (hf : value ≤ fund) (ho : OwnedExact value owned)
    (accepted : canCredit before fund amount owned = true) : value + amount ≤ u64Max := by
  unfold canCredit at accepted
  split at accepted
  · rename_i amountRange
    cases hc : chooseOwned (tighter before (clip fund)) owned with
    | none => simp [hc] at accepted
    | some known =>
      have hk := chooseOwned_sound (tighter_sound he (clip_sound hf)) ho hc
      have ha : BoundSound amount (some amount) := ⟨Nat.le_refl _, amountRange⟩
      have hs := tighter_sound (addBounds_sound hk ha) (addBounds_sound (clip_sound hf) ha)
      cases hb : tighter (addBounds known (some amount))
          (addBounds (clip fund) (some amount)) with
      | none => simp [hc, hb] at accepted
      | some upper =>
        rw [hb] at hs
        exact Nat.le_trans hs.1 hs.2
  · contradiction

/-! ## Per-cell reserved capacity, before irreversible external spending

This projection uses exact semantic balances, not public plaintext leakage.
`public_credit_preflight_safe` is the bridge from private runtime evidence to
the capacity guards. Proofs never require another token's fund to fit u64.
-/

abbrev Slot := Nat
abbrev Token := Nat
abbrev Cell := Slot × Token

structure CapacityState where
  balance : Cell → Nat
  pending : Cell → Nat

def emptyCapacity : CapacityState := ⟨fun _ => 0, fun _ => 0⟩

def putCell (f : Cell → Nat) (cell : Cell) (value : Nat) : Cell → Nat :=
  fun c => if c = cell then value else f c

def reserveState (s : CapacityState) (cell : Cell) (amount : Nat) : CapacityState :=
  { s with pending := putCell s.pending cell (s.pending cell + amount) }

def importState (s : CapacityState) (cell : Cell) (amount : Nat) : CapacityState :=
  { balance := putCell s.balance cell (s.balance cell + amount)
    pending := putCell s.pending cell (s.pending cell - amount) }

def updateState (s : CapacityState) (cell : Cell) (balance : Nat) : CapacityState :=
  { s with balance := putCell s.balance cell balance }

def releaseUnusedState (s : CapacityState) (cell : Cell) (amount : Nat) : CapacityState :=
  { s with pending := putCell s.pending cell (s.pending cell - amount) }

/-- A trusted observation of the completed exact import WAL. IDs stand for
    canonical reservation/transaction identities, not caller-chosen authority.
    The Rust validator checks the exact token, amount and selected candidate;
    completion becomes durable with the selected credit and replay tombstone. -/
structure CompletedReservationObservation where
  reservationId : Nat
  transactionId : Nat
  token : Token
  amount : Nat
  selectedSlot : Slot
  candidateSlots : List Slot
  exactIntentMatched : Bool
  walCommitted : Bool

def CanReleaseUnused (s : CapacityState) (cell : Cell) (amount : Nat)
    (completed : CompletedReservationObservation) : Prop :=
  completed.exactIntentMatched = true ∧ completed.walCommitted = true ∧
    completed.token = cell.2 ∧ completed.amount = amount ∧
    cell.1 ∈ completed.candidateSlots ∧ completed.selectedSlot ∈ completed.candidateSlots ∧
    cell.1 ≠ completed.selectedSlot ∧ amount ≤ s.pending cell

def CapacitySafe (s : CapacityState) : Prop :=
  ∀ c, s.balance c + s.pending c ≤ u64Max

inductive CapacityEvent where
  | reserved (cell : Cell) (amount : Nat)
  | externalSpend (cell : Cell) (amount : Nat)
  | imported (cell : Cell) (amount : Nat)
  | updated (cell : Cell) (balance : Nat)
  | unusedReleased (cell : Cell) (amount : Nat)

/-- The spend step does not release its capacity. The import is a committed
    exact-intent WAL operation: it converts capacity to balance, not to free
    room. Other candidates release capacity ONLY against its exact committed
    completion observation. Exact-ID/tx-hash matching and one-time reservation
    enumeration are environment/refinement premises, not inferred from a Nat ID. -/
inductive CapacityStep : CapacityState → CapacityEvent → CapacityState → Prop where
  | reserve {s cell amount}
      (checked : s.balance cell + s.pending cell + amount ≤ u64Max) :
      CapacityStep s (.reserved cell amount) (reserveState s cell amount)
  | spend {s cell amount} (reserved : amount ≤ s.pending cell) :
      CapacityStep s (.externalSpend cell amount) s
  | importDeposit {s cell amount} (reserved : amount ≤ s.pending cell) :
      CapacityStep s (.imported cell amount) (importState s cell amount)
  | update {s cell balance}
      (keepsReservations : balance + s.pending cell ≤ u64Max) :
      CapacityStep s (.updated cell balance) (updateState s cell balance)
  | releaseUnused {s cell amount} (completed : CompletedReservationObservation)
      (checked : CanReleaseUnused s cell amount completed) :
      CapacityStep s (.unusedReleased cell amount) (releaseUnusedState s cell amount)

inductive CapacityTrace : CapacityState → List CapacityEvent → CapacityState → Prop where
  | nil (s) : CapacityTrace s [] s
  | cons {s m f e es} : CapacityStep s e m → CapacityTrace m es f →
      CapacityTrace s (e :: es) f

/-- The semantic guard in `reserve` follows from the actual executable
    preflight on `all pending + this amount`; no plaintext-range conclusion is
    merely assumed by the lifecycle model. Pending-add counts are separate. -/
theorem reserve_from_public_preflight {s : CapacityState} {cell : Cell}
    {amount fund : Nat} {before owned : Bound}
    (he : BoundSound (s.balance cell) before) (hf : s.balance cell ≤ fund)
    (ho : OwnedExact (s.balance cell) owned)
    (accepted : canCredit before fund (s.pending cell + amount) owned = true) :
    CapacityStep s (.reserved cell amount) (reserveState s cell amount) := by
  apply CapacityStep.reserve
  have h := public_credit_preflight_safe he hf ho accepted
  omega

/-- Before a different signed update is admitted, every pending reservation
    is rechecked at its successor. This bridge is why an unrelated incoming
    credit cannot consume room promised to a pending external deposit. -/
theorem update_from_reserved_preflight {s : CapacityState} {cell : Cell}
    {newBalance fund : Nat} {nextBound owned : Bound}
    (he : BoundSound newBalance nextBound) (hf : newBalance ≤ fund)
    (ho : OwnedExact newBalance owned)
    (accepted : canCredit nextBound fund (s.pending cell) owned = true) :
    CapacityStep s (.updated cell newBalance) (updateState s cell newBalance) := by
  exact CapacityStep.update (public_credit_preflight_safe he hf ho accepted)

theorem import_converts_reserved_capacity {s : CapacityState} {cell : Cell} {amount : Nat}
    (h : amount ≤ s.pending cell) :
    (importState s cell amount).balance cell + (importState s cell amount).pending cell =
      s.balance cell + s.pending cell := by
  simp [importState, putCell]
  omega

theorem unused_release_requires_committed_exact_wal
    {s : CapacityState} {cell : Cell} {amount : Nat}
    {completed : CompletedReservationObservation}
    (h : CanReleaseUnused s cell amount completed) :
    completed.exactIntentMatched = true ∧ completed.walCommitted = true ∧
      cell.1 ≠ completed.selectedSlot := ⟨h.1, h.2.1, h.2.2.2.2.2.2.1⟩

theorem unused_release_blocked_before_completion
    {s : CapacityState} {cell : Cell} {amount : Nat}
    {completed : CompletedReservationObservation} (notCommitted : completed.walCommitted = false) :
    ¬ CanReleaseUnused s cell amount completed := by
  intro h
  have committed := h.2.1
  simp_all

theorem unused_release_preserves_all_balances (s : CapacityState) (cell : Cell) (amount : Nat) :
    (releaseUnusedState s cell amount).balance = s.balance := rfl

theorem unused_release_removes_exact_reserved_amount {s : CapacityState} {cell : Cell} {amount : Nat}
    (h : amount ≤ s.pending cell) :
    (releaseUnusedState s cell amount).pending cell + amount = s.pending cell := by
  simp [releaseUnusedState, putCell]
  omega

theorem capacity_step_preserves {s s' : CapacityState} {e : CapacityEvent}
    (step : CapacityStep s e s') (safe : CapacitySafe s) : CapacitySafe s' := by
  intro c
  have hc := safe c
  cases step with
  | reserve checked =>
    simp only [reserveState, putCell]
    split
    · subst c
      omega
    · exact safe c
  | spend => exact safe c
  | importDeposit reserved =>
    simp only [importState, putCell]
    split
    · subst c
      omega
    · exact safe c
  | update keepsReservations =>
    simp only [updateState, putCell]
    split
    · subst c
      exact keepsReservations
    · exact safe c
  | releaseUnused completed checked =>
    simp only [releaseUnusedState, putCell]
    split
    · subst c
      omega
    · exact safe c

theorem capacity_trace_preserves {s f : CapacityState} {events : List CapacityEvent}
    (trace : CapacityTrace s events f) (safe : CapacitySafe s) : CapacitySafe f := by
  induction trace with
  | nil => exact safe
  | cons step _ ih => exact ih (capacity_step_preserves step safe)

theorem from_empty_every_cell_has_room {f : CapacityState} {events : List CapacityEvent}
    (trace : CapacityTrace emptyCapacity events f) (c : Cell) :
    f.balance c ≤ u64Max ∧ f.pending c ≤ u64Max ∧
      f.balance c + f.pending c ≤ u64Max := by
  have initial : CapacitySafe emptyCapacity := by
    intro _
    exact Nat.zero_le _
  have hf := capacity_trace_preserves trace initial c
  omega

theorem spend_does_not_release {s s' : CapacityState} {cell : Cell} {amount : Nat}
    (step : CapacityStep s (.externalSpend cell amount) s') : s' = s := by
  cases step
  rfl

theorem other_cell_framed {s s' : CapacityState} {e : CapacityEvent} {touched c : Cell}
    (step : CapacityStep s e s')
    (eventCell : (match e with
      | .reserved x _ | .externalSpend x _ | .imported x _ | .updated x _
      | .unusedReleased x _ => x) = touched)
    (different : c ≠ touched) :
    s'.balance c = s.balance c ∧ s'.pending c = s.pending c := by
  cases step <;> simp_all [reserveState, importState, updateState, releaseUnusedState, putCell]

/-- Per-token independence, including reservations at another member slot. -/
theorem other_token_framed {s s' : CapacityState} {e : CapacityEvent}
    {slot otherSlot : Slot} {token otherToken : Token}
    (step : CapacityStep s e s')
    (eventCell : (match e with
      | .reserved x _ | .externalSpend x _ | .imported x _ | .updated x _
      | .unusedReleased x _ => x) = (slot, token))
    (different : otherToken ≠ token) :
    s'.balance (otherSlot, otherToken) = s.balance (otherSlot, otherToken) ∧
      s'.pending (otherSlot, otherToken) = s.pending (otherSlot, otherToken) := by
  apply other_cell_framed step eventCell
  intro h
  have : otherToken = token := congrArg Prod.snd h
  contradiction

/-! ## Normal non-vacuity checks (kernel reduction; no generated proof fixture)
These examples include a fund above u64, unknown unaffected positions, exact
owned rescue, a phase-2 allocation and a reserve/spend/import trace.
-/

theorem example_inclusive_u64_limit : addBounds (some (u64Max - 1)) (some 1) = some u64Max := by decide
theorem example_checked_add_above_limit : addBounds (some u64Max) (some 1) = none := by decide
theorem example_known_bound_with_wide_fund :
    admitCell true (some 10) (u64Max + 100) none = some (some 10) := by decide
theorem example_unknown_unchanged_with_wide_fund :
    admitCell false none (u64Max + 100) none = some none := by decide
theorem example_owned_opening_with_wide_fund :
    admitCell true none (u64Max + 100) (some 31) = some (some 31) := by decide
theorem example_second_phase_allocation : pooled [some 10] 0 7 = some 17 := by decide
theorem example_public_credit_with_wide_fund :
    canCredit (some 10) (u64Max + 100) 7 none = true := by decide
theorem example_public_credit_exceeds_cell_capacity :
    canCredit (some 10) (u64Max + 100) u64Max none = false := by decide

theorem example_reserve_spend_import_trace : CapacityTrace emptyCapacity
    [.reserved (0, 4) 7, .externalSpend (0, 4) 7, .imported (0, 4) 7]
    (importState (reserveState emptyCapacity (0, 4) 7) (0, 4) 7) := by
  apply CapacityTrace.cons (CapacityStep.reserve (by decide))
  apply CapacityTrace.cons (CapacityStep.spend (by decide))
  apply CapacityTrace.cons (CapacityStep.importDeposit (by decide))
  exact CapacityTrace.nil _

def exampleTwoCandidateReservation : CapacityState :=
  reserveState (reserveState emptyCapacity (0, 4) 7) (1, 4) 7

def exampleSelectedImport : CapacityState := importState exampleTwoCandidateReservation (0, 4) 7

def exampleCompletedReservation : CompletedReservationObservation :=
  ⟨11, 22, 4, 7, 0, [0, 1], true, true⟩

/-- The observed WAL has committed the credit to slot 0. The linearized release
    of slot 1 follows it; it does not create another credit or release before
    completion. Actual Rust changes all candidates' completed flag atomically. -/
theorem example_selected_import_then_unused_release : CapacityTrace emptyCapacity
    [.reserved (0, 4) 7, .reserved (1, 4) 7, .externalSpend (0, 4) 7,
      .imported (0, 4) 7, .unusedReleased (1, 4) 7]
    (releaseUnusedState exampleSelectedImport (1, 4) 7) := by
  apply CapacityTrace.cons (CapacityStep.reserve (by decide))
  apply CapacityTrace.cons (CapacityStep.reserve (by decide))
  apply CapacityTrace.cons (CapacityStep.spend (by decide))
  apply CapacityTrace.cons (CapacityStep.importDeposit (by decide))
  apply CapacityTrace.cons (CapacityStep.releaseUnused exampleCompletedReservation (by
    simp [CanReleaseUnused, exampleCompletedReservation, importState, reserveState,
      emptyCapacity, putCell]))
  exact CapacityTrace.nil _

theorem example_unused_candidate_is_uncredited_and_unreserved :
    (releaseUnusedState exampleSelectedImport (1, 4) 7).balance (0, 4) = 7 ∧
    (releaseUnusedState exampleSelectedImport (1, 4) 7).balance (1, 4) = 0 ∧
    (releaseUnusedState exampleSelectedImport (1, 4) 7).pending (0, 4) = 0 ∧
    (releaseUnusedState exampleSelectedImport (1, 4) 7).pending (1, 4) = 0 := by decide

end ChannelSafetyAdmission
