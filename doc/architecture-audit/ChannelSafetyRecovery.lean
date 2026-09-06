import Std

/-!
# Durable intent, signature-release and publication recovery

Manual source correspondence: parent runtime `05ec7ae`, not an extracted semantics.

* `OutboxStep.reserve/sign/persist/broadcast/complete/retry` abstracts
  `api/lib/deposit-spend.js::{requestBinding,spendDeposit,markImported}` and
  `node/delegate/signed-transaction-outbox.js::{_newAttempt,send,markFinalized,
  resumeExact}`. `_writeIntentReservation` precedes offline signing; `_write`
  and `_writeReservation` precede broadcast. Complete records are not removed.
  `OutboxStep.abandon` covers `resumeExact`'s explicit unlink of an initial
  stage=intent reservation only when this exact action has no raw WAL and no
  prior/current transaction hash. It is NOT represented as a refusal stutter.
  `node/common/l1-deposit-outbox.js::{send,confirm,exactDeposit}` supplies the
  exact calldata/value binding and finalized expected-deposit observation.
* `rememberSignature`, `SignatureStep` abstracts
  `hosting/wallet/signature-release-ledger.mjs::{signatureDecision,
  createIndexedDbSignatureLedger,createSignatureReleaseGate}` and the worker's
  postMessage fence. Native `channel_member.rs::{state_signing_ledger_key,
  ledgered_state_signature_with,ledger_sign_all_controlled,save_state}` checks
  the same predecessor decision and retains the exact signature bytes.
* `PublicationStep` abstracts `channel_member/deposit_recovery.rs` and
  `burn_recovery.rs::{commit,validate/validate_journal,finish,recover}`: the
  journal is durable before replacing the head, outputs precede retirement,
  and recovery accepts only its exact before/after head. Both validators also
  compare prior signing/replay ledgers; that source-level comparison is not
  replaced by an assumption that a checksum proves a valid state transition.

Explicit refinement limits / environmental obligations:

1. Each modeled durable write is a successful atomic durable operation. The
   filesystem must honor file fsync + atomic rename + directory fsync, and
   IndexedDB must honor strict readwrite transaction completion. A crash may
   occur BETWEEN modeled writes, not corrupt an acknowledged durable write.
   Disk rollback, loss, manual deletion, browser-profile/origin migration and
   key-only restore are excluded. Failed/unacknowledged writes may stutter.
   `api/lib/cli.js::writeJson` tolerates unsupported directory-sync errors;
   those API success returns alone do not discharge this premise. Filesystem
   refinement requires a supported filesystem on which directory sync succeeds.
2. OS/channel/signer locks and IndexedDB transactions must serialize competing
   writers. A step is their linearized operation; this file does not prove
   the JavaScript/Rust/OS concurrency implementation or cancellation semantics.
3. Nat request keys denote collision-free canonical identities, and Nat byte
   identifiers denote exact byte strings. Intent equality includes all checked
   transaction and allocation fields. Parsing, hashing, raw-transaction decode,
   arithmetic bounds, signing, proof verification and ownership are not proved.
4. `FinalizedObservation` is an explicit oracle INPUT indexed by exact request
   and raw record. Real use must discharge canonical chain/receipt, signer,
   target/calldata/value, expected-event and finality checks. The results below
   prove local replay fences even for an arbitrary oracle, NOT honest RPC,
   EVM exactly-once execution, rightful allocation or global asset conservation.
5. The outbox slice is AUTOMATIC exact retry, with no operator-authorized fee
   bump or fresh-nonce replacement. Those retain semantic intent in source but
   deliberately create another raw attempt and need a separate nonce model.
   Initial reservations without a raw WAL may be explicitly abandoned. Their
   intent (including reserved nonce) is NOT permanent; only raw-backed intent
   and completed tombstones have the monotone retention property below. The
   API's separate high-level deposit-operation record is not deleted by this
   outbox operation. Abandonment assumes the exact signer lock/lease checks in
   `resumeExact`; it never authorizes deletion of another action's reservation.
6. Signature keys encode (signer identity, channel, predecessor). Native keys
   use channel/predecessor/slot under an authenticated fixed slot-to-key binding;
   browser decisions additionally compare memberSlot. Purpose/plan below model
   native checks; browser instantiation fixes these to constants. A native
   in-memory signature is NOT yet a `persist` step: its enclosing state/WAL must
   be durably committed before modeled external release. Direct WASM consumers
   outside the worker, transition/exit-kit admissibility and key compromise are
   outside this release-fence theorem.
7. Publication is one ALREADY VALIDATED signed before/after transition. Its
   output/metadata byte identities are frozen inputs, not fresh chain evidence.
   Signature/replay ledger retention is modeled separately, not a proof that
   every Rust journal field is correctly decoded or that every call site saves.

No invariant is stored as a proof field in a runtime state. Safety predicates
are derived from the explicit initial states and checked transition rules.
This establishes conditional local trace safety and finite recovery examples,
not unconditional availability, latest-head exit liveness, or release approval.
-/

namespace ChannelSafetyRecovery

private def put {α : Type} (f : Nat → α) (key : Nat) (value : α) : Nat → α :=
  fun k => if k = key then value else f k

theorem put_retains {α : Type} {f : Nat → Option α} {key k : Nat}
    {value prior : α} (fresh : f key = none) (known : f k = some prior) :
    put f key (some value) k = some prior := by
  by_cases h : k = key
  · subst k
    simp [fresh] at known
  · simpa [put, h] using known

structure Intent where
  channelId : Nat
  chainId : Nat
  signer : Nat
  target : Nat
  calldataBytes : Nat
  value : Nat
  allocationIdentity : Nat
  nonce : Nat
  deriving DecidableEq, Repr

/-- A raw record AFTER the implementation's decode/binding checks, not an arbitrary byte proof. -/
structure RawRecord where
  intent : Intent
  exactBytes : Nat
  deriving DecidableEq, Repr

structure OutboxState where
  intents : Nat → Option Intent
  raws : Nat → Option RawRecord
  terminal : Nat → Bool
  volatileRaw : Option (Nat × RawRecord)

def emptyOutbox : OutboxState :=
  ⟨fun _ => none, fun _ => none, fun _ => false, none⟩

def crashOutbox (s : OutboxState) : OutboxState := { s with volatileRaw := none }

/-- The raw-absent initial lease may be dropped after interrupted signing. Any
    volatile candidate is discarded; source serialization prevents a concurrent
    signer from publishing it after the lease is released. -/
def abandonOutbox (s : OutboxState) (key : Nat) : OutboxState :=
  { s with intents := put s.intents key none, volatileRaw := none }

abbrev FinalizedObservation := Nat → RawRecord → Prop

inductive OutboxEvent where
  | reserved (key : Nat) (intent : Intent)
  | signed (key : Nat) (raw : RawRecord)
  | persisted (key : Nat) (raw : RawRecord)
  | broadcast (key : Nat) (raw : RawRecord)
  | completed (key : Nat) (raw : RawRecord)
  | retried (key : Nat) (intent : Intent)
  | abandoned (key : Nat)
  | crashed
  | refused
  deriving DecidableEq, Repr

inductive OutboxStep (finalized : FinalizedObservation) :
    OutboxState → OutboxEvent → OutboxState → Prop where
  | reserve {s key intent} (fresh : s.intents key = none) :
      OutboxStep finalized s (.reserved key intent)
        { s with intents := put s.intents key (some intent) }
  | sign {s key raw} (bound : s.intents key = some raw.intent)
      (freshRaw : s.raws key = none) :
      OutboxStep finalized s (.signed key raw) { s with volatileRaw := some (key, raw) }
  | persist {s key raw} (bound : s.intents key = some raw.intent)
      (freshRaw : s.raws key = none) (signed : s.volatileRaw = some (key, raw)) :
      OutboxStep finalized s (.persisted key raw)
        { s with raws := put s.raws key (some raw), volatileRaw := none }
  | broadcast {s key raw} (record : s.raws key = some raw) (active : s.terminal key = false) :
      OutboxStep finalized s (.broadcast key raw) s
  | complete {s key raw} (record : s.raws key = some raw) (active : s.terminal key = false)
      (observed : finalized key raw) :
      OutboxStep finalized s (.completed key raw) { s with terminal := put s.terminal key true }
  | retry {s key intent} (bound : s.intents key = some intent) :
      OutboxStep finalized s (.retried key intent) s
  | abandon {s key} (noRaw : s.raws key = none) (notTerminal : s.terminal key = false) :
      OutboxStep finalized s (.abandoned key) (abandonOutbox s key)
  | crash (s) : OutboxStep finalized s .crashed (crashOutbox s)
  | refuse (s) : OutboxStep finalized s .refused s

inductive OutboxTrace (finalized : FinalizedObservation) :
    OutboxState → List OutboxEvent → OutboxState → Prop where
  | nil (s) : OutboxTrace finalized s [] s
  | cons {s m f e es} : OutboxStep finalized s e m → OutboxTrace finalized m es f →
      OutboxTrace finalized s (e :: es) f

structure OutboxExtends (s t : OutboxState) : Prop where
  /-- A raw-absent reservation can be released; only raw-backed intent persists. -/
  intents : ∀ k i r, s.raws k = some r → s.intents k = some i → t.intents k = some i
  raws : ∀ k r, s.raws k = some r → t.raws k = some r
  terminal : ∀ k, s.terminal k = true → t.terminal k = true

structure OutboxSafe (s : OutboxState) : Prop where
  rawBound : ∀ k r, s.raws k = some r → s.intents k = some r.intent
  terminalRecorded : ∀ k, s.terminal k = true → ∃ r, s.raws k = some r

theorem outbox_step_extends {obs s e t} (step : OutboxStep obs s e t) :
    OutboxExtends s t := by
  cases step with
  | reserve fresh =>
      exact ⟨fun _ _ _ _ known => put_retains fresh known, fun _ _ h => h, fun _ h => h⟩
  | persist _ fresh _ =>
      exact ⟨fun _ _ _ _ h => h, fun _ _ known => put_retains fresh known, fun _ h => h⟩
  | complete =>
      refine ⟨fun _ _ _ _ h => h, fun _ _ h => h, ?_⟩
      intro k h
      simp only [put]
      split <;> simp_all
  | @abandon key noRaw notTerminal =>
      refine ⟨?_, fun _ _ h => h, fun _ h => h⟩
      intro k i r record known
      have other : k ≠ key := by
        intro eq
        subst k
        simp [noRaw] at record
      simpa [abandonOutbox, put, other] using known
  | _ => exact ⟨fun _ _ _ _ h => h, fun _ _ h => h, fun _ h => h⟩

theorem outbox_trace_extends {obs s es t} (trace : OutboxTrace obs s es t) :
    OutboxExtends s t := by
  induction trace with
  | nil => exact ⟨fun _ _ _ _ h => h, fun _ _ h => h, fun _ h => h⟩
  | cons step _ ih =>
      have first := outbox_step_extends step
      exact ⟨fun k i r record h => ih.intents k i r (first.raws k r record)
          (first.intents k i r record h),
        fun k r h => ih.raws k r (first.raws k r h),
        fun k h => ih.terminal k (first.terminal k h)⟩

theorem empty_outbox_safe : OutboxSafe emptyOutbox := by
  constructor <;> simp [emptyOutbox]

theorem outbox_step_safe {obs s e t} (safe : OutboxSafe s)
    (step : OutboxStep obs s e t) : OutboxSafe t := by
  have extension := outbox_step_extends step
  constructor
  · intro k r known
    cases step with
    | reserve fresh => exact put_retains fresh (safe.rawBound k r known)
    | persist bound fresh signed =>
        simp only [put] at known
        split at known
        · cases known
          simp_all
        · exact safe.rawBound k r known
    | @abandon key noRaw notTerminal =>
        have other : k ≠ key := by
          intro eq
          subst k
          simp [abandonOutbox, noRaw] at known
        simpa [abandonOutbox, put, other] using safe.rawBound k r known
    | _ => exact safe.rawBound k r known
  · intro k done
    cases step with
    | complete record active observed =>
        simp only [put] at done
        split at done
        · subst k
          exact ⟨_, record⟩
        · exact safe.terminalRecorded k done
    | _ =>
        obtain ⟨r, known⟩ := safe.terminalRecorded k done
        exact ⟨r, extension.raws k r known⟩

theorem outbox_trace_safe {obs es t} (trace : OutboxTrace obs emptyOutbox es t) :
    OutboxSafe t := by
  have general : ∀ {s es t}, OutboxTrace obs s es t → OutboxSafe s → OutboxSafe t := by
    intro s es t tr
    induction tr with
    | nil => exact fun h => h
    | cons step _ ih => exact fun h => ih (outbox_step_safe h step)
  exact general trace empty_outbox_safe

theorem broadcast_record_survives_trace {obs s es t key raw}
    (trace : OutboxTrace obs s es t) (seen : OutboxEvent.broadcast key raw ∈ es) :
    t.raws key = some raw := by
  induction trace with
  | nil => simp at seen
  | cons step tail ih =>
      rcases List.mem_cons.mp seen with first | later
      · cases first
        cases step with
        | broadcast record _ => exact (outbox_trace_extends tail).raws key raw record
      · exact ih later

theorem automatic_rebroadcast_is_byte_identical {obs s es t key a b}
    (trace : OutboxTrace obs s es t)
    (first : OutboxEvent.broadcast key a ∈ es) (second : OutboxEvent.broadcast key b ∈ es) :
    a = b := by
  exact Option.some.inj ((broadcast_record_survives_trace trace first).symm.trans
    (broadcast_record_survives_trace trace second))

theorem broadcast_has_exact_durable_intent {obs es s t key raw}
    (history : OutboxTrace obs emptyOutbox es s)
    (broadcast : OutboxStep obs s (.broadcast key raw) t) :
    s.raws key = some raw ∧ s.intents key = some raw.intent := by
  cases broadcast with
  | broadcast record _ => exact ⟨record, (outbox_trace_safe history).rawBound key raw record⟩

theorem terminal_tombstone_survives_restart_and_retry {obs s es t key}
    (trace : OutboxTrace obs s es t) (done : s.terminal key = true) :
    t.terminal key = true := (outbox_trace_extends trace).terminal key done

theorem raw_backed_intent_survives_trace {obs s es t key raw}
    (trace : OutboxTrace obs s es t) (safe : OutboxSafe s)
    (record : s.raws key = some raw) : t.intents key = some raw.intent :=
  (outbox_trace_extends trace).intents key raw.intent raw record (safe.rawBound key raw record)

theorem raw_backed_reservation_cannot_be_abandoned {obs s key raw t}
    (record : s.raws key = some raw) : ¬ OutboxStep obs s (.abandoned key) t := by
  intro step
  cases step with
  | abandon noRaw _ => simp_all

theorem terminal_cannot_broadcast {obs s key raw t} (done : s.terminal key = true) :
    ¬ OutboxStep obs s (.broadcast key raw) t := by
  intro step
  cases step with
  | broadcast _ active => simp_all

/-- Retry uses the current durable binding. A raw-backed binding is permanent
    by `raw_backed_intent_survives_trace`; a pre-WAL binding may be abandoned. -/
theorem retry_requires_original_intent {obs s key intent t}
    (step : OutboxStep obs s (.retried key intent) t) :
    s.intents key = some intent ∧ t = s := by
  cases step with
  | retry bound => exact ⟨bound, rfl⟩

theorem crash_retains_all_outbox_durable_records (s : OutboxState) :
    (crashOutbox s).intents = s.intents ∧ (crashOutbox s).raws = s.raws ∧
    (crashOutbox s).terminal = s.terminal ∧ (crashOutbox s).volatileRaw = none := by
  exact ⟨rfl, rfl, rfl, rfl⟩

structure SignatureIntent where
  successor : Nat
  memberSlot : Nat
  purpose : Nat
  terminalPlan : Option Nat
  deriving DecidableEq, Repr

structure SignatureDecision where
  intent : SignatureIntent
  exactBytes : Nat
  deriving DecidableEq, Repr

abbrev SignatureLedger := Nat → Option SignatureDecision

/-- Atomic store transaction result. Exact retries select OLD bytes, never new randomized bytes. -/
def rememberSignature (ledger : SignatureLedger) (key : Nat) (candidate : SignatureDecision) :
    Option (SignatureLedger × SignatureDecision) :=
  match ledger key with
  | none => some (put ledger key (some candidate), candidate)
  | some previous =>
      if candidate.intent = previous.intent then some (ledger, previous) else none

theorem signature_retry_returns_original_bytes {ledger key candidate previous}
    (known : ledger key = some previous) (same : candidate.intent = previous.intent) :
    rememberSignature ledger key candidate = some (ledger, previous) := by
  simp [rememberSignature, known, same]

theorem signature_conflicting_intent_refused {ledger key candidate previous}
    (known : ledger key = some previous) (different : candidate.intent ≠ previous.intent) :
    rememberSignature ledger key candidate = none := by
  simp [rememberSignature, known, different]

theorem signature_remember_records_and_retains {ledger key candidate next selected}
    (result : rememberSignature ledger key candidate = some (next, selected)) :
    next key = some selected ∧
      (∀ k previous, ledger k = some previous → next k = some previous) := by
  cases known : ledger key with
  | none =>
      simp only [rememberSignature, known, Option.some.injEq, Prod.mk.injEq] at result
      rcases result with ⟨rfl, rfl⟩
      exact ⟨by simp [put], fun _ _ h => put_retains known h⟩
  | some previous =>
      by_cases same : candidate.intent = previous.intent
      · simp only [rememberSignature, known, if_pos same, Option.some.injEq, Prod.mk.injEq] at result
        rcases result with ⟨rfl, rfl⟩
        exact ⟨known, fun _ _ h => h⟩
      · simp [rememberSignature, known, same] at result

structure SignatureState where
  ledger : SignatureLedger
  candidate : Option (Nat × SignatureDecision)
  ready : Option (Nat × SignatureDecision)

def emptySignatures : SignatureState := ⟨fun _ => none, none, none⟩

def crashSignatures (s : SignatureState) : SignatureState :=
  { s with candidate := none, ready := none }

inductive SignatureEvent where
  | prepared (key : Nat) (candidate : SignatureDecision)
  | persisted (key : Nat) (selected : SignatureDecision)
  | released (key : Nat) (selected : SignatureDecision)
  | crashed
  | refused
  deriving DecidableEq, Repr

inductive SignatureStep : SignatureState → SignatureEvent → SignatureState → Prop where
  | prepare (s key candidate) :
      SignatureStep s (.prepared key candidate) { s with candidate := some (key, candidate), ready := none }
  | persist {s key candidate next selected} (pending : s.candidate = some (key, candidate))
      (committed : rememberSignature s.ledger key candidate = some (next, selected)) :
      SignatureStep s (.persisted key selected) ⟨next, none, some (key, selected)⟩
  | release {s key selected} (ready : s.ready = some (key, selected)) :
      SignatureStep s (.released key selected) { s with ready := none }
  | crash (s) : SignatureStep s .crashed (crashSignatures s)
  | refuse (s) : SignatureStep s .refused s

inductive SignatureTrace : SignatureState → List SignatureEvent → SignatureState → Prop where
  | nil (s) : SignatureTrace s [] s
  | cons {s m f e es} : SignatureStep s e m → SignatureTrace m es f → SignatureTrace s (e :: es) f

def SignatureSafe (s : SignatureState) : Prop :=
  ∀ k d, s.ready = some (k, d) → s.ledger k = some d

theorem signature_step_safe_and_monotone {s e t} (safe : SignatureSafe s)
    (step : SignatureStep s e t) :
    SignatureSafe t ∧ (∀ k d, s.ledger k = some d → t.ledger k = some d) := by
  cases step with
  | persist pending committed =>
      have checked := signature_remember_records_and_retains committed
      constructor
      · intro k d ready
        cases ready
        exact checked.1
      · exact checked.2
  | refuse => exact ⟨safe, fun _ _ h => h⟩
  | _ => exact ⟨by simp [SignatureSafe, crashSignatures], fun _ _ h => h⟩

/-- Trace result combines readiness provenance, retention, and all already-public decisions. -/
structure SignatureTraceSafe (start : SignatureState) (events : List SignatureEvent)
    (finish : SignatureState) : Prop where
  readyRecorded : SignatureSafe finish
  retained : ∀ k d, start.ledger k = some d → finish.ledger k = some d
  releasedRecorded : ∀ k d, SignatureEvent.released k d ∈ events → finish.ledger k = some d

theorem signature_trace_release_is_durable {s es t} (trace : SignatureTrace s es t)
    (safe : SignatureSafe s) : SignatureTraceSafe s es t := by
  induction trace with
  | nil => exact ⟨safe, fun _ _ h => h, by simp⟩
  | cons step tail ih =>
      have first := signature_step_safe_and_monotone safe step
      have rest := ih first.1
      refine ⟨rest.readyRecorded, fun k d h => rest.retained k d (first.2 k d h), ?_⟩
      intro k d seen
      rcases List.mem_cons.mp seen with head | later
      · cases head
        cases step with
        | release ready => exact rest.retained k d (safe k d ready)
      · exact rest.releasedRecorded k d later

theorem released_signatures_cannot_equivocate {es t key a b}
    (trace : SignatureTrace emptySignatures es t)
    (first : SignatureEvent.released key a ∈ es) (second : SignatureEvent.released key b ∈ es) :
    a = b := by
  have initial : SignatureSafe emptySignatures := by simp [SignatureSafe, emptySignatures]
  have retained := signature_trace_release_is_durable trace initial
  exact Option.some.inj ((retained.releasedRecorded key a first).symm.trans
    (retained.releasedRecorded key b second))

theorem crash_retains_signature_ledger (s : SignatureState) :
    (crashSignatures s).ledger = s.ledger ∧ (crashSignatures s).ready = none ∧
    (crashSignatures s).candidate = none := ⟨rfl, rfl, rfl⟩

structure Publication where
  beforeHead : Nat
  afterHead : Nat
  metadataBytes : Nat
  resultBytes : Nat
  deriving DecidableEq, Repr

/-- One fixed journal's durable files. In-memory buffers are deliberately not represented. -/
structure PublicationState where
  head : Nat
  metadata : Option Nat
  result : Option Nat
  pending : Bool
  deriving DecidableEq, Repr

def initialPublication (p : Publication) : PublicationState := ⟨p.beforeHead, none, none, false⟩

def finishedPublication (p : Publication) : PublicationState :=
  ⟨p.afterHead, some p.metadataBytes, some p.resultBytes, false⟩

inductive PublicationEvent where
  | prepared | headSaved | metadataSaved | resultSaved | retired | crashed
  deriving DecidableEq, Repr

inductive PublicationStep (p : Publication) :
    PublicationState → PublicationEvent → PublicationState → Prop where
  | prepare {s} (before : s.head = p.beforeHead) (absent : s.pending = false) :
      PublicationStep p s .prepared { s with pending := true }
  | head {s} (journal : s.pending = true) (matching : s.head = p.beforeHead ∨ s.head = p.afterHead) :
      PublicationStep p s .headSaved { s with head := p.afterHead }
  | metadata {s} (journal : s.pending = true) (head : s.head = p.afterHead) :
      PublicationStep p s .metadataSaved { s with metadata := some p.metadataBytes }
  | result {s} (journal : s.pending = true) (head : s.head = p.afterHead) :
      PublicationStep p s .resultSaved { s with result := some p.resultBytes }
  | retire {s} (journal : s.pending = true) (head : s.head = p.afterHead)
      (metadata : s.metadata = some p.metadataBytes) (result : s.result = some p.resultBytes) :
      PublicationStep p s .retired { s with pending := false }
  | crash (s) : PublicationStep p s .crashed s

inductive PublicationTrace (p : Publication) :
    PublicationState → List PublicationEvent → PublicationState → Prop where
  | nil (s) : PublicationTrace p s [] s
  | cons {s m f e es} : PublicationStep p s e m → PublicationTrace p m es f →
      PublicationTrace p s (e :: es) f

def PublicationSafe (p : Publication) (s : PublicationState) : Prop :=
  s.head = p.afterHead → s.pending = true ∨
    (s.metadata = some p.metadataBytes ∧ s.result = some p.resultBytes)

theorem initial_publication_safe (p : Publication) (distinct : p.beforeHead ≠ p.afterHead) :
    PublicationSafe p (initialPublication p) := by
  simp [PublicationSafe, initialPublication, distinct]

theorem publication_step_safe {p s e t} (safe : PublicationSafe p s)
    (step : PublicationStep p s e t) : PublicationSafe p t := by
  intro afterHead
  cases step with
  | prepare => exact Or.inl rfl
  | head journal _ => exact Or.inl journal
  | metadata journal _ => exact Or.inl journal
  | result journal _ => exact Or.inl journal
  | retire _ _ metadata result => exact Or.inr ⟨metadata, result⟩
  | crash => exact safe afterHead

theorem publication_trace_retains_recovery_until_outputs_durable {p es t}
    (distinct : p.beforeHead ≠ p.afterHead)
    (trace : PublicationTrace p (initialPublication p) es t) : PublicationSafe p t := by
  have general : ∀ {s es t}, PublicationTrace p s es t → PublicationSafe p s → PublicationSafe p t := by
    intro s es t tr
    induction tr with
    | nil => exact fun h => h
    | cons step _ ih => exact fun h => ih (publication_step_safe h step)
  exact general trace (initial_publication_safe p distinct)

/-- Successful whole recovery, summarizing the guarded writes, never a fresh signature. -/
def recoverPublication (p : Publication) (s : PublicationState) : Option PublicationState :=
  if s.pending then
    if s.head = p.beforeHead ∨ s.head = p.afterHead then some (finishedPublication p) else none
  else some s

theorem recovery_finishes_exact_outputs {p s} (pending : s.pending = true)
    (matching : s.head = p.beforeHead ∨ s.head = p.afterHead) :
    recoverPublication p s = some (finishedPublication p) ∧
      PublicationTrace p s [.headSaved, .metadataSaved, .resultSaved, .retired]
        (finishedPublication p) := by
  constructor
  · simp [recoverPublication, pending, matching]
  · apply PublicationTrace.cons
    · exact PublicationStep.head pending matching
    apply PublicationTrace.cons
    · exact PublicationStep.metadata pending rfl
    apply PublicationTrace.cons
    · exact PublicationStep.result pending rfl
    apply PublicationTrace.cons
    · exact PublicationStep.retire pending rfl rfl rfl
    exact PublicationTrace.nil _

theorem recovery_is_idempotent {p s t} (recovered : recoverPublication p s = some t) :
    recoverPublication p t = some t := by
  unfold recoverPublication at recovered
  split at recovered
  · split at recovered
    · cases recovered
      simp [recoverPublication, finishedPublication]
    · contradiction
  · cases recovered
    simp_all [recoverPublication]

theorem unrelated_head_cannot_be_overwritten_by_recovery {p s} (pending : s.pending = true)
    (notBefore : s.head ≠ p.beforeHead) (notAfter : s.head ≠ p.afterHead) :
    recoverPublication p s = none := by
  simp [recoverPublication, pending, notBefore, notAfter]

/-! ## Positive, finite normal-operation and restart traces

These are kernel-checked concrete transition witnesses, not tests against RPC,
the browser or a native binary. No real keys, transactions or proofs are used.
-/

def exampleIntent : Intent := ⟨7, 31337, 2, 3, 400, 5, 6, 0⟩
def exampleRaw : RawRecord := ⟨exampleIntent, 101⟩
def exampleReserved : OutboxState :=
  { emptyOutbox with intents := put emptyOutbox.intents 7 (some exampleIntent) }
def examplePersisted : OutboxState :=
  { exampleReserved with raws := put exampleReserved.raws 7 (some exampleRaw) }
def exampleCompleted : OutboxState :=
  { examplePersisted with terminal := put examplePersisted.terminal 7 true }

/-- A normal payment can crash after raw persistence, rebroadcast, complete, and answer a retry. -/
theorem example_outbox_crash_retry_and_completion :
    OutboxTrace (fun _ _ => True) emptyOutbox
      [.reserved 7 exampleIntent, .signed 7 exampleRaw, .persisted 7 exampleRaw,
       .broadcast 7 exampleRaw, .crashed, .retried 7 exampleIntent, .broadcast 7 exampleRaw,
       .completed 7 exampleRaw, .retried 7 exampleIntent] exampleCompleted := by
  apply OutboxTrace.cons
  · exact OutboxStep.reserve rfl
  apply OutboxTrace.cons
  · exact OutboxStep.sign rfl rfl
  apply OutboxTrace.cons
  · exact OutboxStep.persist rfl rfl rfl
  apply OutboxTrace.cons
  · exact OutboxStep.broadcast rfl rfl
  apply OutboxTrace.cons
  · exact OutboxStep.crash _
  apply OutboxTrace.cons
  · exact OutboxStep.retry rfl
  apply OutboxTrace.cons
  · exact OutboxStep.broadcast rfl rfl
  apply OutboxTrace.cons
  · exact OutboxStep.complete rfl rfl True.intro
  apply OutboxTrace.cons
  · exact OutboxStep.retry rfl
  exact OutboxTrace.nil _

def exampleAbandoned : OutboxState := abandonOutbox exampleReserved 7
def exampleNewIntent : Intent := { exampleIntent with nonce := 1 }
def exampleNewRaw : RawRecord := ⟨exampleNewIntent, 102⟩
def exampleReReserved : OutboxState :=
  { exampleAbandoned with intents := put exampleAbandoned.intents 7 (some exampleNewIntent) }
def exampleReCompleted : OutboxState :=
  { exampleReReserved with
    raws := put exampleReReserved.raws 7 (some exampleNewRaw)
    terminal := put exampleReReserved.terminal 7 true }

/-- A crash before raw persistence permits explicit initial-lease abandonment.
    Re-reserving a nonce afterward is possible; only the newly persisted raw is
    broadcast. This does not remove the API's separate deposit intent record. -/
theorem example_initial_reservation_abandon_then_completion :
    OutboxTrace (fun _ _ => True) emptyOutbox
      [.reserved 7 exampleIntent, .signed 7 exampleRaw, .crashed, .abandoned 7,
       .reserved 7 exampleNewIntent, .signed 7 exampleNewRaw, .persisted 7 exampleNewRaw,
       .broadcast 7 exampleNewRaw, .completed 7 exampleNewRaw] exampleReCompleted := by
  apply OutboxTrace.cons
  · exact OutboxStep.reserve rfl
  apply OutboxTrace.cons
  · exact OutboxStep.sign rfl rfl
  apply OutboxTrace.cons
  · exact OutboxStep.crash _
  apply OutboxTrace.cons
  · exact OutboxStep.abandon rfl rfl
  apply OutboxTrace.cons
  · exact OutboxStep.reserve rfl
  apply OutboxTrace.cons
  · exact OutboxStep.sign rfl rfl
  apply OutboxTrace.cons
  · exact OutboxStep.persist rfl rfl rfl
  apply OutboxTrace.cons
  · exact OutboxStep.broadcast rfl rfl
  apply OutboxTrace.cons
  · exact OutboxStep.complete rfl rfl True.intro
  exact OutboxTrace.nil _

def exampleSignature : SignatureDecision := ⟨⟨22, 1, 0, none⟩, 300⟩
def exampleResigned : SignatureDecision := ⟨exampleSignature.intent, 301⟩
def exampleSignatureLedger : SignatureLedger := put (fun _ => none) 9 (some exampleSignature)
def exampleSignatureFinished : SignatureState := ⟨exampleSignatureLedger, none, none⟩

/-- Re-signing the same state after restart still releases the original durable bytes (300). -/
theorem example_signature_restart_reuses_original_bytes :
    SignatureTrace emptySignatures
      [.prepared 9 exampleSignature, .persisted 9 exampleSignature, .released 9 exampleSignature,
       .crashed, .prepared 9 exampleResigned, .persisted 9 exampleSignature,
       .released 9 exampleSignature] exampleSignatureFinished := by
  apply SignatureTrace.cons
  · exact SignatureStep.prepare _ 9 exampleSignature
  apply SignatureTrace.cons
  · exact SignatureStep.persist (candidate := exampleSignature)
      (next := exampleSignatureLedger) rfl rfl
  apply SignatureTrace.cons
  · exact SignatureStep.release rfl
  apply SignatureTrace.cons
  · exact SignatureStep.crash _
  apply SignatureTrace.cons
  · exact SignatureStep.prepare _ 9 exampleResigned
  apply SignatureTrace.cons
  · exact SignatureStep.persist (candidate := exampleResigned)
      (next := exampleSignatureLedger) rfl rfl
  apply SignatureTrace.cons
  · exact SignatureStep.release rfl
  exact SignatureTrace.nil _

def examplePublication : Publication := ⟨10, 11, 200, 201⟩

/-- Crash after head replacement still permits metadata/result publication before WAL retirement. -/
theorem example_publication_crash_then_completion :
    PublicationTrace examplePublication (initialPublication examplePublication)
      [.prepared, .headSaved, .crashed, .metadataSaved, .resultSaved, .retired]
      (finishedPublication examplePublication) := by
  apply PublicationTrace.cons
  · exact PublicationStep.prepare rfl rfl
  apply PublicationTrace.cons
  · exact PublicationStep.head rfl (Or.inl rfl)
  apply PublicationTrace.cons
  · exact PublicationStep.crash _
  apply PublicationTrace.cons
  · exact PublicationStep.metadata rfl rfl
  apply PublicationTrace.cons
  · exact PublicationStep.result rfl rfl
  apply PublicationTrace.cons
  · exact PublicationStep.retire rfl rfl rfl rfl
  exact PublicationTrace.nil _

/-- Both interruption points admitted by the native before/after-head gate finish identically. -/
theorem example_before_and_after_head_recover_to_same_outputs :
    recoverPublication examplePublication ⟨10, none, none, true⟩ =
      some (finishedPublication examplePublication) ∧
    recoverPublication examplePublication ⟨11, none, none, true⟩ =
      some (finishedPublication examplePublication) := by
  exact ⟨rfl, rfl⟩

end ChannelSafetyRecovery
