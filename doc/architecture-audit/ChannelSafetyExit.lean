import Std

/-!
# Current whole-state close admission, posting journal, and atomic materialization

Manual executable/relational abstraction of runtime `05ec7ae`, MLE pin
`6cefc6ac`, checked with Lean 4.10 and Std only.

Source map:
* `contracts/src/ChannelSettlementManager.sol`: `submitCloseIntent` checks
  BOTH authorized and pending burn high-water marks, including an exact IMCS
  digest at equal (epoch, version); `_finalizeClose` copies the admitted whole
  state and derives every cap from its one vector. `_pullChannelFunds` requires
  this channel's materialized IMCS and an exact balance delta.
* `contracts/src/CloseFundingMaterializer.sol`: `bindManager`,
  `recordPost`/`rollbackPost`, `freezeFromManager`/`unfreezeFromManager`,
  `materializeSignedHead`/`_materialize`, `_validateBackingPublicInputs`.
* `contracts/src/IntmaxRollup.sol`: `_postBlock` calls the posting journal at
  increasing global block numbers; `_rollbackBatch` invokes rollback in
  descending order. `creditChannelExit` is callable only by the set-once
  materializer and atomically moves token escrow to the exact Manager's ledger.

Each slice exposes its omitted interface assumptions rather than treating
arbitrary verifier observations as proof of ownership. Composite authenticated
state/statement binding is a PARAMETER in the one theorem needing full snapshot
identity: it requires the close proof, ChannelState/IMCH/IMCS links, canonical
representations and collision resistance, not IMCS collision resistance alone.
No custom axiom or cryptographic theorem is introduced. Proof verification,
N-of-N authentication, funding/Balance completeness, deployed code/chain pins,
hashes and the provenance of Manager/rollup observations are NOT proved here.

The journal theorem proves exact pointer AND journal restoration after any
finite strictly increasing sequence of journaled posts, including interleaved
channels, by reverse-order rollback. A fresh journal slot and positive bound
channel are required. Unbound posts have no journal effect; rollback of absent
entries is a stutter. Manager binding at the globally finalized head supplies
the conservative pre-binding floor. Rollback eligibility (never finalized),
global hashes/roots, registration/deposit accumulators and live watcher storage
are separate mechanisms; this module does not pretend to prove their behavior.

The materialization model consumes one immutable Manager-supplied whole vector,
not caller-selected token amounts. Unique registry entries and checked uint256
debit/add guards are explicit. A committed success is the entire outer EVM
transaction; failure restores ALL modeled state. No token callback occurs in
`creditChannelExit`. EVM rollback and the set-once caller boundary are refinement
premises, not a model of the EVM interpreter or arbitrary token internals.
Other manager/channel ledger entries are framed, but GLOBAL token escrow is
deliberately shared and decreases on an exit. This is NOT a proof that a valid
Balance represents rightful backing or that cross-channel theft is impossible.

Freeze/thaw model only satellite guards. It does not replace Manager participant,
cancel proof/replay, close challenge timing, or signed-era checks. The generation
is the monotone request generation, NOT the restored freeze nonce. Posting is
blocked only for the bound source channel, not for arbitrary incoming deposits.

The three slices are not an automatic whole-program refinement. Their interface
obligations are stated explicitly; no arbitrary-trace theorem silently assumes
all omitted calls preserve an invariant. Normal finite examples establish that
successful admission, interleaved rollback and one-shot materialization exist.
-/

namespace ChannelSafetyExit

abbrev Channel := Nat
abbrev Manager := Nat
abbrev Token := Nat
abbrev BlockNumber := Nat
abbrev Digest := Nat

def uint256Limit : Nat := 2 ^ 256

def put {α : Type} (f : Nat → α) (key : Nat) (value : α) : Nat → α :=
  fun k => if k = key then value else f k

theorem put_at {α : Type} (f : Nat → α) (key : Nat) (value : α) :
    put f key value key = value := by simp [put]

theorem put_other {α : Type} (f : Nat → α) (key other : Nat) (value : α)
    (h : other ≠ key) : put f key value other = f other := by simp [put, h]

theorem put_restore {α : Type} (f : Nat → α) (key : Nat) (value : α) :
    put (put f key value) key (f key) = f := by
  funext k
  by_cases h : k = key <;> simp [put, h]

/-! ## Whole-state burn floors and finalization -/

structure Asset where
  token : Token
  amount : Nat
  deriving DecidableEq, Repr

structure WholeState where
  epoch : Nat
  version : Nat
  closeId : Digest
  channelStateId : Digest
  balanceH1 : Digest
  settledChain : Digest
  tokenFundsId : Digest
  signedFundRoot : Digest
  funds : List Asset
  deriving DecidableEq, Repr

def older (candidate floor : WholeState) : Prop :=
  candidate.epoch < floor.epoch ∨
    (candidate.epoch = floor.epoch ∧ candidate.version < floor.version)

def sameCoordinate (a b : WholeState) : Prop :=
  a.epoch = b.epoch ∧ a.version = b.version

def clears (candidate floor : WholeState) : Prop :=
  ¬ older candidate floor ∧ (sameCoordinate candidate floor → candidate.closeId = floor.closeId)

def clearsOptional (candidate : WholeState) : Option WholeState → Prop
  | none => True
  | some floor => clears candidate floor

def WholeAdmission (authorized pending : Option WholeState) (candidate : WholeState) : Prop :=
  clearsOptional candidate authorized ∧ clearsOptional candidate pending

instance (candidate floor : WholeState) : Decidable (clears candidate floor) := by
  unfold clears older sameCoordinate
  infer_instance

instance (candidate : WholeState) (floor : Option WholeState) :
    Decidable (clearsOptional candidate floor) := by
  cases floor <;> unfold clearsOptional <;> infer_instance

instance (authorized pending : Option WholeState) (candidate : WholeState) :
    Decidable (WholeAdmission authorized pending candidate) := by
  unfold WholeAdmission
  infer_instance

theorem both_burn_floors_are_enforced {authorized pending candidate : WholeState}
    (h : WholeAdmission (some authorized) (some pending) candidate) :
    ¬ older candidate authorized ∧ ¬ older candidate pending := ⟨h.1.1, h.2.1⟩

theorem same_coordinate_requires_exact_identity {candidate floor : WholeState}
    (h : clears candidate floor) (same : sameCoordinate candidate floor) :
    candidate.closeId = floor.closeId := h.2 same

/-- Composite authenticated state/statement binding, scoped to the same
    channel/deployment domain: the close proof binds the ChannelState and
    IMCH/IMCS commitments to canonical complete representations, with collision
    resistance at those commitments. IMCS collision resistance alone does not
    establish this implication. This is NOT asserted for arbitrary Nat IDs. -/
def VerifiedDigestBinding (verified : WholeState → Prop) : Prop :=
  ∀ a b, verified a → verified b → a.closeId = b.closeId → a = b

theorem same_coordinate_has_one_whole_vector
    {verified : WholeState → Prop} (binding : VerifiedDigestBinding verified)
    {candidate floor : WholeState} (hc : verified candidate) (hf : verified floor)
    (h : clears candidate floor) (same : sameCoordinate candidate floor) :
    candidate.funds = floor.funds ∧ candidate.settledChain = floor.settledChain ∧
      candidate.channelStateId = floor.channelStateId := by
  have heq := binding candidate floor hc hf (h.2 same)
  subst candidate
  exact ⟨rfl, rfl, rfl⟩

/-- A strictly newer accepted challenge cannot regress either fixed burn floor.
    Burn submissions require Active; finalization of a pending burn is blocked
    while ClosePending, so these floors are stable during one close challenge. -/
theorem strictly_newer_clears_floor {newer current floor : WholeState}
    (hn : older current newer) (hc : clears current floor) : clears newer floor := by
  rcases hc with ⟨notOld, _⟩
  constructor
  · unfold older at *
    omega
  · intro same
    unfold sameCoordinate at same
    unfold older at *
    omega

def capAt (funds : List Asset) (token : Token) : Nat :=
  match funds with
  | [] => 0
  | a :: rest => (if a.token = token then a.amount else 0) + capAt rest token

structure FinalizedState where
  whole : WholeState
  cap : Token → Nat

/-- Models `_finalizeClose`: the pending snapshot is copied once; no floor
    snapshot supplies an individual replacement token component. Duplicate
    registry entries aggregate here like Manager `+=`; materialization later
    independently rejects duplicates. -/
def finalizeWhole (pending : WholeState) : FinalizedState :=
  ⟨pending, capAt pending.funds⟩

theorem finalization_never_splices_components (pending : WholeState) (token : Token) :
    (finalizeWhole pending).whole = pending ∧
      (finalizeWhole pending).cap token = capAt pending.funds token := ⟨rfl, rfl⟩

theorem admitted_finalization_keeps_both_floors {authorized pending : Option WholeState}
    {candidate : WholeState} (h : WholeAdmission authorized pending candidate) :
    WholeAdmission authorized pending (finalizeWhole candidate).whole := h

/-! ## Per-channel predecessor journal and exact descending restoration -/

structure JournalEntry where
  channel : Channel
  previous : BlockNumber
  deriving DecidableEq, Repr

structure Journal where
  head : Channel → BlockNumber
  entry : BlockNumber → Option JournalEntry

def emptyJournal : Journal := ⟨fun _ => 0, fun _ => none⟩

def post (s : Journal) (channel : Channel) (height : BlockNumber) : Journal :=
  { head := put s.head channel height
    entry := put s.entry height (some ⟨channel, s.head channel⟩) }

def rollback (s : Journal) (height : BlockNumber) : Option Journal :=
  match s.entry height with
  | none => some s
  | some e =>
    if s.head e.channel = height then
      some { head := put s.head e.channel e.previous, entry := put s.entry height none }
    else none

theorem post_frames_other_channel (s : Journal) (channel other : Channel) (height : BlockNumber)
    (h : other ≠ channel) : (post s channel height).head other = s.head other := by
  exact put_other s.head channel other height h

theorem unjournaled_rollback_is_stutter {s : Journal} {height : BlockNumber}
    (h : s.entry height = none) : rollback s height = some s := by simp [rollback, h]

theorem rollback_requires_channel_tip {s : Journal} {height : BlockNumber} {e : JournalEntry}
    (entry : s.entry height = some e) (notTip : s.head e.channel ≠ height) :
    rollback s height = none := by simp [rollback, entry, notTip]

theorem post_then_rollback_exact {s : Journal} {channel : Channel} {height : BlockNumber}
    (fresh : s.entry height = none) : rollback (post s channel height) height = some s := by
  simp only [rollback, post, put_at, ↓reduceIte]
  rw [put_restore]
  rw [← fresh, put_restore]

def rollbackMany (s : Journal) : List BlockNumber → Option Journal
  | [] => some s
  | h :: hs => (rollback s h).bind (fun next => rollbackMany next hs)

theorem rollbackMany_append (s : Journal) (xs ys : List BlockNumber) :
    rollbackMany s (xs ++ ys) = (rollbackMany s xs).bind (fun middle => rollbackMany middle ys) := by
  induction xs generalizing s with
  | nil => rfl
  | cons h hs ih =>
    simp only [List.cons_append, rollbackMany]
    cases rollback s h with
    | none => rfl
    | some next => exact ih next

abbrev Posting := Channel × BlockNumber

/-- Only bound-channel writes appear here; unbound heights are permissible
    gaps. `floor` may be the canonical finalized head recorded at binding. -/
inductive PostedTrace : BlockNumber → Journal → List Posting → Journal → Prop where
  | nil (floor : BlockNumber) (s : Journal) : PostedTrace floor s [] s
  | cons {floor : BlockNumber} {s final : Journal} {channel : Channel}
      {height : BlockNumber} {rest : List Posting}
      (increasing : floor < height) (boundChannel : channel ≠ 0)
      (fresh : s.entry height = none)
      (tail : PostedTrace height (post s channel height) rest final) :
      PostedTrace floor s ((channel, height) :: rest) final

/-- Arbitrary-length, interleaved-channel restoration of the COMPLETE modeled
    journal, not just a maximum height or a single channel example. -/
theorem descending_rollback_restores_journal {floor : BlockNumber} {s final : Journal}
    {posts : List Posting} (h : PostedTrace floor s posts final) :
    rollbackMany final (posts.reverse.map Prod.snd) = some s := by
  induction h with
  | nil => rfl
  | @cons floor s final channel height rest increasing boundChannel fresh tail ih =>
    simp only [List.reverse_cons, List.map_append, List.map_cons, List.map_nil]
    rw [rollbackMany_append, ih]
    simpa [rollbackMany] using post_then_rollback_exact (channel := channel) fresh

/-! ## Satellite freeze/thaw guards -/

inductive Status where
  | active | pending | closed
  deriving DecidableEq, Repr

structure Control where
  bound : Channel → Option Manager
  frozen : Channel → Nat
  exited : Channel → Option Digest

structure FreezeObservation where
  managerChannel : Channel
  managerGeneration : Nat
  managerStatus : Status

def CanFreeze (s : Control) (channel : Channel) (caller : Manager) (generation : Nat)
    (obs : FreezeObservation) : Prop :=
  s.bound channel = some caller ∧ s.exited channel = none ∧ s.frozen channel = 0 ∧
    obs.managerChannel = channel ∧ obs.managerGeneration = generation ∧
    generation ≠ 0 ∧ obs.managerStatus = .pending

def freeze (s : Control) (channel : Channel) (generation : Nat) : Control :=
  { s with frozen := put s.frozen channel generation }

def CanThaw (s : Control) (channel : Channel) (caller : Manager) (generation : Nat) : Prop :=
  s.bound channel = some caller ∧ s.frozen channel ≠ 0 ∧
    s.frozen channel = generation ∧ s.exited channel = none

def thaw (s : Control) (channel : Channel) : Control :=
  { s with frozen := put s.frozen channel 0 }

def CanPost (s : Control) (channel : Channel) : Prop :=
  s.bound channel = none ∨ (s.exited channel = none ∧ s.frozen channel = 0)

theorem frozen_bound_channel_cannot_post {s : Control} {channel : Channel} {manager : Manager}
    (bound : s.bound channel = some manager) (frozen : s.frozen channel ≠ 0) :
    ¬ CanPost s channel := by simp [CanPost, bound, frozen]

theorem exited_bound_channel_cannot_post {s : Control} {channel : Channel} {manager : Manager}
    {digest : Digest} (bound : s.bound channel = some manager)
    (exited : s.exited channel = some digest) : ¬ CanPost s channel := by
  simp [CanPost, bound, exited]

theorem freeze_then_exact_thaw {s : Control} {channel : Channel} {caller generation : Nat}
    {obs : FreezeObservation} (h : CanFreeze s channel caller generation obs) :
    CanThaw (freeze s channel generation) channel caller generation ∧
      thaw (freeze s channel generation) channel = s := by
  constructor
  · exact ⟨h.1, by simpa [freeze, put_at] using h.2.2.2.2.2.1,
      by simp [freeze, put_at], h.2.1⟩
  · unfold thaw freeze
    rw [← h.2.2.1, put_restore]

theorem old_generation_cannot_thaw {s : Control} {channel : Channel}
    {caller current old : Nat} (frozen : s.frozen channel = current) (distinct : old ≠ current) :
    ¬ CanThaw s channel caller old := by
  intro h
  exact distinct (h.2.2.1.symm.trans frozen)

/-! ## One-shot whole-vector materialization -/

structure FinalizedObservation where
  manager : Manager
  channel : Channel
  generation : Nat
  status : Status
  whole : WholeState

structure BackingObservation where
  channel : Channel
  settledChain : Digest
  tokenFundsId : Digest
  anchor : BlockNumber
  verifiedExactProof : Bool
  exactProofAttested : Bool
  backingRootFinalized : Bool
  signedFundRootFinalized : Bool

structure MaterialContext where
  bound : Channel → Option Manager
  frozen : Channel → Nat
  lastPosted : Channel → BlockNumber
  latestFinalized : BlockNumber

structure Ledger where
  exited : Channel → Option Digest
  escrow : Token → Nat
  credit : Manager → Token → Nat

def uniqueTokens : List Token → Bool
  | [] => true
  | t :: rest => !rest.contains t && uniqueTokens rest

def CanMaterialize (ctx : MaterialContext) (s : Ledger)
    (manager : FinalizedObservation) (backing : BackingObservation) : Prop :=
  ctx.bound manager.channel = some manager.manager ∧
  ctx.frozen manager.channel ≠ 0 ∧
  manager.generation = ctx.frozen manager.channel ∧
  manager.status = .closed ∧ manager.whole.closeId ≠ 0 ∧
  s.exited manager.channel = none ∧
  backing.verifiedExactProof = true ∧ backing.exactProofAttested = true ∧
  backing.backingRootFinalized = true ∧ backing.signedFundRootFinalized = true ∧
  backing.channel = manager.channel ∧
  backing.settledChain = manager.whole.settledChain ∧
  backing.tokenFundsId = manager.whole.tokenFundsId ∧
  ctx.lastPosted manager.channel ≤ backing.anchor ∧ backing.anchor ≤ ctx.latestFinalized ∧
  0 < manager.whole.funds.length ∧ manager.whole.funds.length ≤ 10 ∧
  uniqueTokens (manager.whole.funds.map Asset.token) = true ∧
  (∀ t, capAt manager.whole.funds t ≤ s.escrow t ∧
    s.credit manager.manager t + capAt manager.whole.funds t < uint256Limit)

/-- This is an authenticated Manager read, NOT a caller's chosen amount map.
    Amount-zero skips in the real loop have exactly this functional effect. -/
def materialize (s : Ledger) (manager : FinalizedObservation) : Ledger :=
  { exited := put s.exited manager.channel (some manager.whole.closeId)
    escrow := fun t => s.escrow t - capAt manager.whole.funds t
    credit := put s.credit manager.manager
      (fun t => s.credit manager.manager t + capAt manager.whole.funds t) }

def commit (s candidate : Ledger) (allCallsSucceeded : Bool) : Ledger :=
  if allCallsSucceeded then candidate else s

inductive MaterialEvent where
  | materialized (channel : Channel) (digest : Digest)
  | reverted
  deriving DecidableEq, Repr

/-- Includes EVM failure stuttering; no event records a partially credited lane.
    Context/observations may vary between steps, so the one-shot trace theorem
    does not assume a favorable fixed external root, generation or manager. -/
inductive MaterialStep : Ledger → MaterialEvent → Ledger → Prop where
  | apply {s : Ledger} {ctx : MaterialContext} {manager : FinalizedObservation}
      {backing : BackingObservation} (admitted : CanMaterialize ctx s manager backing)
      (allCallsSucceeded : Bool) :
      MaterialStep s
        (if allCallsSucceeded then .materialized manager.channel manager.whole.closeId else .reverted)
        (commit s (materialize s manager) allCallsSucceeded)
  | reverted (s : Ledger) : MaterialStep s .reverted s

inductive MaterialTrace : Ledger → List MaterialEvent → Ledger → Prop where
  | nil (s : Ledger) : MaterialTrace s [] s
  | cons {s m final : Ledger} {event : MaterialEvent} {events : List MaterialEvent} :
      MaterialStep s event m → MaterialTrace m events final →
      MaterialTrace s (event :: events) final

theorem failed_outer_call_restores_everything (s : Ledger) (manager : FinalizedObservation) :
    commit s (materialize s manager) false = s := rfl

/-- Even if a later token's checked debit fails after an earlier token was
    tentatively credited, the outer transaction restores the entire prefix. -/
theorem atomic_failure_discards_partial_vector (s prefixState : Ledger) :
    commit s prefixState false = s := rfl

theorem materialization_uses_exact_finalized_vector (s : Ledger)
    (manager : FinalizedObservation) (token : Token) :
    (materialize s manager).credit manager.manager token =
      s.credit manager.manager token + capAt manager.whole.funds token := by
  simp [materialize, put_at]

theorem materialization_frames_other_manager (s : Ledger)
    (manager : FinalizedObservation) (other : Manager) (token : Token)
    (distinct : other ≠ manager.manager) :
    (materialize s manager).credit other token = s.credit other token := by
  simp [materialize, put, distinct]

theorem materialization_frames_other_channel (s : Ledger)
    (manager : FinalizedObservation) (other : Channel) (distinct : other ≠ manager.channel) :
    (materialize s manager).exited other = s.exited other := by
  exact put_other _ _ _ _ distinct

theorem escrow_to_credit_conserved {ctx : MaterialContext} {s : Ledger}
    {manager : FinalizedObservation} {backing : BackingObservation}
    (h : CanMaterialize ctx s manager backing) (token : Token) :
    (materialize s manager).escrow token + (materialize s manager).credit manager.manager token =
      s.escrow token + s.credit manager.manager token := by
  have arithmetic := h.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2 token
  simp only [materialize, put_at]
  omega

theorem materialized_identity_is_exact (s : Ledger) (manager : FinalizedObservation) :
    (materialize s manager).exited manager.channel = some manager.whole.closeId := by
  exact put_at _ _ _

theorem exit_identity_preserved_by_step {s next : Ledger} {event : MaterialEvent}
    (h : MaterialStep s event next) {channel : Channel} {digest : Digest}
    (exited : s.exited channel = some digest) : next.exited channel = some digest := by
  cases h with
  | @apply ctx manager backing admitted succeeded =>
    cases succeeded with
    | false => exact exited
    | true =>
      have fresh : s.exited manager.channel = none := admitted.2.2.2.2.2.1
      have different : channel ≠ manager.channel := by
        intro eq
        subst channel
        rw [fresh] at exited
        contradiction
      simpa [commit, materialize, put, different] using exited
  | reverted => exact exited

theorem exit_identity_preserved_by_trace {s final : Ledger} {events : List MaterialEvent}
    (h : MaterialTrace s events final) {channel : Channel} {digest : Digest}
    (exited : s.exited channel = some digest) : final.exited channel = some digest := by
  induction h with
  | nil => exact exited
  | cons step _ ih => exact ih (exit_identity_preserved_by_step step exited)

theorem materialized_event_is_fresh {s next : Ledger} {event : MaterialEvent}
    {channel : Channel} {digest : Digest}
    (h : MaterialStep s event next) (he : event = .materialized channel digest) :
    s.exited channel = none ∧ next.exited channel = some digest := by
  cases h with
  | @apply ctx manager backing admitted succeeded =>
    cases succeeded with
    | false => cases he
    | true =>
      cases he
      exact ⟨admitted.2.2.2.2.2.1, materialized_identity_is_exact _ _⟩
  | reverted => cases he

theorem successful_materialization_is_fresh {s next : Ledger} {channel : Channel} {digest : Digest}
    (h : MaterialStep s (.materialized channel digest) next) :
    s.exited channel = none ∧ next.exited channel = some digest :=
  materialized_event_is_fresh h rfl

theorem no_second_materialization_after_any_trace
    {s once later final : Ledger} {channel : Channel} {firstId secondId : Digest}
    {events : List MaterialEvent}
    (first : MaterialStep s (.materialized channel firstId) once)
    (between : MaterialTrace once events later) :
    ¬ MaterialStep later (.materialized channel secondId) final := by
  intro second
  have used := exit_identity_preserved_by_trace between (successful_materialization_is_fresh first).2
  have fresh := (successful_materialization_is_fresh second).1
  rw [fresh] at used
  contradiction

/-! ## Normal non-vacuity examples -/

def sampleWhole : WholeState :=
  ⟨2, 7, 101, 201, 301, 401, 501, 601, [⟨0, 7⟩, ⟨3, 11⟩]⟩

theorem example_exact_both_burn_floors :
    WholeAdmission (some sampleWhole) (some sampleWhole) sampleWhole := by decide

theorem example_newer_whole_state_admitted :
    WholeAdmission (some sampleWhole) none { sampleWhole with version := 8, closeId := 102 } := by
  decide

theorem example_finalize_two_token_vector :
    (finalizeWhole sampleWhole).cap 0 = 7 ∧ (finalizeWhole sampleWhole).cap 3 = 11 := by
  decide

def sampleJournal : Journal := post (post (post emptyJournal 1 5) 2 6) 1 7

theorem example_interleaved_post_trace :
    PostedTrace 4 emptyJournal [(1, 5), (2, 6), (1, 7)] sampleJournal := by
  apply PostedTrace.cons (by decide) (by decide) (by decide)
  apply PostedTrace.cons (by decide) (by decide) (by decide)
  apply PostedTrace.cons (by decide) (by decide) (by decide)
  exact PostedTrace.nil _ _

theorem example_interleaved_reverse_rollback :
    rollbackMany sampleJournal [7, 6, 5] = some emptyJournal := by
  have h : PostedTrace 4 emptyJournal [(1, 5), (2, 6), (1, 7)] sampleJournal := by
    apply PostedTrace.cons (by decide) (by decide) (by decide)
    apply PostedTrace.cons (by decide) (by decide) (by decide)
    apply PostedTrace.cons (by decide) (by decide) (by decide)
    exact PostedTrace.nil _ _
  exact descending_rollback_restores_journal h

def sampleManager : FinalizedObservation := ⟨9, 1, 3, .closed, sampleWhole⟩
def sampleBacking : BackingObservation := ⟨1, 401, 501, 7, true, true, true, true⟩
def sampleContext : MaterialContext := ⟨fun _ => some 9, fun _ => 3, fun _ => 7, 10⟩
def sampleLedger : Ledger := ⟨fun _ => none, fun _ => 100, fun _ _ => 0⟩

theorem example_whole_vector_materialization_admitted :
    CanMaterialize sampleContext sampleLedger sampleManager sampleBacking := by
  simp [CanMaterialize, sampleContext, sampleLedger, sampleManager, sampleBacking, sampleWhole,
    uniqueTokens]
  intro t
  simp only [capAt]
  split <;> split <;> decide

theorem example_whole_vector_credit_and_escrow :
    (materialize sampleLedger sampleManager).credit 9 0 = 7 ∧
    (materialize sampleLedger sampleManager).credit 9 3 = 11 ∧
    (materialize sampleLedger sampleManager).escrow 3 = 89 := by decide

theorem example_successful_materialization_trace : MaterialTrace sampleLedger [.materialized 1 101]
    (materialize sampleLedger sampleManager) := by
  have accepted : CanMaterialize sampleContext sampleLedger sampleManager sampleBacking := by
    simp [CanMaterialize, sampleContext, sampleLedger, sampleManager, sampleBacking, sampleWhole,
      uniqueTokens]
    intro t
    simp only [capAt]
    split <;> split <;> decide
  exact MaterialTrace.cons (MaterialStep.apply accepted true) (MaterialTrace.nil _)

end ChannelSafetyExit
