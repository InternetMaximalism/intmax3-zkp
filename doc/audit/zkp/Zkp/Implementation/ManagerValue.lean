import Std

/-!
# Selected Manager value-transition implementation model

Manual, partial translation of `contracts/src/ChannelSettlementManager.sol`.
This is not compiler refinement, a proof of circuit soundness, channel ownership of
pooled Rollup escrow, or latest-head exit availability. The accompanying whole-file
line map explicitly leaves constructor, close proof composition, challenge/finalize,
partial withdrawal, and participant Merkle verification bodies untranslated.

This tranche is a storage/call projection: emitted event encodings and scalar
return values are not represented. Their source spans are dependency boundaries.

Source mapping: `_requestClose` -> `requestCloseCore`; the two exact whole-state
burn admission blocks in `submitCloseIntent` -> `checkBurnFloor`; `_isNewer` ->
`isNewer`; `_checkCanonicalCloseMetadata` -> `checkCanonicalMetadata`;
`submitWithdrawalClaim` -> `submitClaim`; `_pullChannelFunds` -> `pullCore`;
`claimWithdrawalCredit` -> `claimCredit`; its CEI writes -> `payoutEffects`.
Runtime/reentrancy modifiers and native receive are translated separately.

Unsigned ABI/storage words are represented by Nat. Their canonical ABI widths are
an explicit refinement obligation, NOT a theorem. Addition/subtraction checks at
the selected monetary sites are executable below; timestamp uint64 conversion is
explicit modulo, not a silent no-overflow premise. Fixed registry access retains
an array-bounds error. All amounts are raw indivisible token units.

`External` is an ordered-call observation boundary, indexed by the actual token,
amount, recipient, channel/head, and locally visible state. A successful balance
observation must be the canonical result of the source balanceOf staticcall;
malformed/failed calls are errors. Token transfer includes SafeERC20 semantics as
an external obligation, not an assumption that value arrived: recipient balance
delta is checked separately. Freeze receives the already updated manager state;
payout callbacks receive CEI-deleted state. EVM transaction rollback and call
atomicity, non-reentrant entry discipline, gas/resource behavior and external
contract identity are separate obligations. Except.error exposes no committed
successor state, but does not itself prove EVM rollback. Public claim membership
and amount correctness remain properties of the exact external verification call.
-/
namespace Zkp.Implementation.ManagerValue

abbrev Word := Nat
abbrev Token := Nat
abbrev Address := Nat
abbrev Digest := Nat
abbrev Proof := List Nat
def wordLimit : Nat := 2^256
def nonceLimit : Nat := 2^64

inductive Fault where
  | runtime | reentrant | onlyRollup | closed | alreadyFrozen | overflow | bounds
  | closeNotActive | digestMismatch | tokenSlot | tokenRegistry | usedNullifier
  | invalidProof | cap | noCredit | wrongRecipient | insufficientCredit
  | tokenNotRegistered | alreadyReceived | notMaterialized | fundingMismatch
  | transferFailed | payoutMismatch | olderBurn | forkedBurn | metadata
  | external (data : Nat)
  deriving DecidableEq, Repr

abbrev Result := Except Fault

inductive Lifecycle where
  | active | pending | closed
  deriving DecidableEq, Repr

structure Payout where
  recipient : Address
  token : Token
  amount : Word
  deriving DecidableEq, Repr

def emptyPayout : Payout := ⟨0, 0, 0⟩

structure Claim where
  closeDigest : Digest
  memberKey : Digest
  recipient : Address
  amountDigest : Digest
  amount : Word
  tokenSlot : Nat
  token : Token
  nullifier : Digest
  deriving DecidableEq, Repr

structure State where
  lifecycle : Lifecycle
  generation : Nat
  freezeNonce : Nat
  requestedAt : Nat
  status : Nat
  finalDigest : Digest
  finalH1 : Digest
  tokenCount : Nat
  registry : Fin 10 → Token
  cap : Token → Word
  withdrawn : Token → Word
  received : Token → Word
  paid : Token → Word
  credit : Token → Address → Word
  payouts : Digest → Payout
  used : Digest → Bool

structure Config where
  channel : Nat
  manager : Address
  rollup : Address
  materializer : Address
  verifier : Address
  chainId : Nat
  challengePeriod : Nat

inductive Phase where
  | before | after
  deriving DecidableEq, Repr

structure External where
  verifyClaim : Address → Nat → Digest → Claim → Proof → Result Bool
  tokenAddress : Token → Result Address
  materialized : Address → Nat → Result Digest
  freeze : State → Address → Nat → Nat → Result Unit
  balance : Phase → State → Token → Address → Address → Result Word
  pull : State → Token → Word → Result Unit
  payNative : State → Address → Word → Result Bool
  payToken : State → Token → Address → Address → Word → Result Unit

def put {α : Type} (f : Nat → α) (key : Nat) (value : α) : Nat → α :=
  fun k => if k = key then value else f k

def runtimeGuard (cfg : Config) : Result Unit :=
  if cfg.chainId != 31337 && cfg.challengePeriod < 86400 then .error .runtime else .ok ()

def reentrantBefore (s : State) : Result State :=
  if s.status = 2 then .error .reentrant else .ok {s with status := 2}

def reentrantAfter (s : State) : State := {s with status := 1}

def receiveNative (cfg : Config) (sender : Address) : Result Unit :=
  if sender != cfg.rollup then .error .onlyRollup else .ok ()

def withRuntime (cfg : Config) (body : Unit → Result State) : Result State :=
  match runtimeGuard cfg with
  | .error e => .error e
  | .ok _ => body ()

def withValueModifiers (cfg : Config) (s : State) (body : State → Result State) : Result State :=
  withRuntime cfg fun _ =>
    match reentrantBefore s with
    | .error e => .error e
    | .ok locked => match body locked with
      | .error e => .error e
      | .ok done => .ok (reentrantAfter done)

def requestCloseCore (cfg : Config) (ext : External) (now : Nat) (s : State) : Result State :=
  if s.lifecycle = .closed then .error .closed else
  if s.lifecycle != .active then .error .alreadyFrozen else
  if s.generation + 1 >= nonceLimit then .error .overflow else
  if s.freezeNonce + 1 >= nonceLimit then .error .overflow else
  let next := {s with
    generation := s.generation + 1, freezeNonce := s.freezeNonce + 1,
    lifecycle := .pending, requestedAt := now % nonceLimit}
  match ext.freeze next cfg.materializer cfg.channel next.generation with
  | .error e => .error e
  | .ok _ => .ok next

structure OrderKey where
  epoch : Nat
  version : Nat
  deriving DecidableEq, Repr

def isNewer (next previous : OrderKey) : Bool :=
  next.epoch > previous.epoch || (next.epoch == previous.epoch && next.version > previous.version)

/- The floor is an exact source excerpt, not all of submitCloseIntent. -/
def checkBurnFloor (active : Bool) (floor candidate : OrderKey)
    (floorDigest candidateDigest : Digest) : Result Unit :=
  if active then
    if candidate.epoch < floor.epoch ||
        (candidate.epoch == floor.epoch && candidate.version < floor.version) then .error .olderBurn
    else if candidate.epoch = floor.epoch ∧ candidate.version = floor.version ∧
        candidateDigest != floorDigest then .error .forkedBurn else .ok ()
  else .ok ()

def checkCanonicalMetadata (nonce freeze snapshot burn : Nat) : Result Unit :=
  if nonce != freeze || snapshot != 0 || burn != 0 then .error .metadata else .ok ()

def claimEffects (s : State) (claim : Claim) : State :=
  {s with
    withdrawn := put s.withdrawn claim.token (s.withdrawn claim.token + claim.amount),
    used := put s.used claim.nullifier true,
    credit := put s.credit claim.token
      (put (s.credit claim.token) claim.recipient (s.credit claim.token claim.recipient + claim.amount)),
    payouts := put s.payouts claim.nullifier ⟨claim.recipient, claim.token, claim.amount⟩}

def submitClaimCore (cfg : Config) (ext : External) (s : State) (claim : Claim) (proof : Proof) : Result State :=
  if s.lifecycle != .closed then .error .closeNotActive else
  if claim.closeDigest != s.finalDigest then .error .digestMismatch else
  if claim.tokenSlot >= s.tokenCount then .error .tokenSlot else
  if h : claim.tokenSlot < 10 then
    if s.registry ⟨claim.tokenSlot, h⟩ != claim.token then .error .tokenRegistry else
    if s.used claim.nullifier then .error .usedNullifier else
    match ext.verifyClaim cfg.verifier cfg.channel s.finalH1 claim proof with
    | .error e => .error e
    | .ok verified =>
      if !verified then .error .invalidProof else
      if s.withdrawn claim.token + claim.amount >= wordLimit then .error .overflow else
      if s.withdrawn claim.token + claim.amount > s.cap claim.token then .error .cap else
      if s.credit claim.token claim.recipient + claim.amount >= wordLimit then .error .overflow else
      .ok (claimEffects s claim)
  else .error .bounds

def submitClaim (cfg : Config) (ext : External) (s : State) (claim : Claim) (proof : Proof) : Result State :=
  withRuntime cfg fun _ => submitClaimCore cfg ext s claim proof

def resolveToken (ext : External) (token : Token) : Result Address :=
  if token = 0 then .ok 0 else
  match ext.tokenAddress token with
  | .error e => .error e
  | .ok address => if address = 0 then .error .tokenNotRegistered else .ok address

def pullCore (cfg : Config) (ext : External) (s : State) (token : Token) : Result State :=
  if s.lifecycle != .closed then .error .closeNotActive else
  match resolveToken ext token with
  | .error e => .error e
  | .ok asset =>
    if s.received token >= s.cap token then .error .alreadyReceived else
    match ext.materialized cfg.materializer cfg.channel with
    | .error e => .error e
    | .ok digest =>
      if digest != s.finalDigest then .error .notMaterialized else
      let expected := s.cap token - s.received token
      match ext.balance .before s token asset cfg.manager with
      | .error e => .error e
      | .ok before => match ext.pull s token expected with
        | .error e => .error e
        | .ok _ => match ext.balance .after s token asset cfg.manager with
          | .error e => .error e
          | .ok after =>
            if after < before then .error .overflow else
            if after - before != expected then .error .fundingMismatch else
            .ok {s with received := put s.received token (s.cap token)}

def pullNative (cfg : Config) (ext : External) (s : State) : Result State :=
  withValueModifiers cfg s fun locked => pullCore cfg ext locked 0

def pullToken (cfg : Config) (ext : External) (s : State) (token : Token) : Result State :=
  withValueModifiers cfg s fun locked =>
    if token = 0 then .error .tokenNotRegistered else pullCore cfg ext locked token

def payoutEffects (s : State) (nullifier : Digest) : State :=
  let p := s.payouts nullifier
  {s with
    payouts := put s.payouts nullifier emptyPayout,
    credit := put s.credit p.token (put (s.credit p.token) p.recipient
      (s.credit p.token p.recipient - p.amount)),
    paid := put s.paid p.token (s.paid p.token + p.amount)}

def transferPayout (ext : External) (asset : Address) (next : State) (p : Payout) : Result State :=
  if p.token = 0 then
    match ext.payNative next p.recipient p.amount with
    | .error e => .error e
    | .ok ok => if ok then .ok next else .error .transferFailed
  else
    match ext.balance .before next p.token asset p.recipient with
    | .error e => .error e
    | .ok before => match ext.payToken next p.token asset p.recipient p.amount with
      | .error e => .error e
      | .ok _ => match ext.balance .after next p.token asset p.recipient with
        | .error e => .error e
        | .ok after =>
          if after < before then .error .overflow else
          if after - before != p.amount then .error .payoutMismatch else .ok next

def claimCreditCore (ext : External) (s : State) (sender : Address) (nullifier : Digest) : Result State :=
  let p := s.payouts nullifier
  if p.amount = 0 then .error .noCredit else
  if sender != p.recipient then .error .wrongRecipient else
  if p.amount > s.credit p.token p.recipient then .error .insufficientCredit else
  if s.paid p.token + p.amount >= wordLimit then .error .overflow else
  if s.paid p.token + p.amount > s.received p.token then .error .cap else
  match resolveToken ext p.token with
  | .error e => .error e
  | .ok asset => transferPayout ext asset (payoutEffects s nullifier) p

def claimCredit (cfg : Config) (ext : External) (s : State) (sender : Address)
    (nullifier : Digest) : Result State :=
  withValueModifiers cfg s fun locked => claimCreditCore ext locked sender nullifier

theorem put_same {α : Type} (f : Nat → α) (k : Nat) (v : α) : put f k v k = v := by simp [put]
theorem put_other {α : Type} (f : Nat → α) (k j : Nat) (v : α) (h : j ≠ k) :
    put f k v j = f j := by simp [put, h]

theorem runtime_guard_exact (cfg : Config) : runtimeGuard cfg = .ok () ↔
    cfg.chainId = 31337 ∨ cfg.challengePeriod ≥ 86400 := by
  simp [runtimeGuard]; omega

theorem native_receive_exact_sender (cfg : Config) (sender : Address) :
    receiveNative cfg sender = .ok () ↔ sender = cfg.rollup := by simp [receiveNative]

theorem reentrant_entry_refused (s : State) (h : s.status = 2) :
    reentrantBefore s = .error .reentrant := by simp [reentrantBefore, h]

theorem request_success_generation (cfg : Config) (ext : External) (now : Nat) (s next : State)
    (h : requestCloseCore cfg ext now s = .ok next) :
    next.generation = s.generation + 1 ∧ next.freezeNonce = s.freezeNonce + 1 ∧
    next.lifecycle = .pending := by
  dsimp only [requestCloseCore] at h
  iterate 15 all_goals (try (split at h <;> simp_all))
  all_goals cases h; trivial

theorem equal_burn_coordinate_requires_same_digest (floor : OrderKey) (d e : Digest) :
    checkBurnFloor true floor floor d e = .ok () ↔ e = d := by
  simp [checkBurnFloor]

theorem strictly_newer_burn_admitted (floor candidate : OrderKey) (d e : Digest)
    (h : isNewer candidate floor = true) : checkBurnFloor true floor candidate d e = .ok () := by
  simp [isNewer] at h
  simp only [checkBurnFloor, Bool.true_eq, ite_true]
  split <;> simp_all <;> try omega

theorem metadata_exact (nonce freeze snapshot burn : Nat) :
    checkCanonicalMetadata nonce freeze snapshot burn = .ok () ↔
    nonce = freeze ∧ snapshot = 0 ∧ burn = 0 := by simp [checkCanonicalMetadata, and_assoc]

theorem claim_effect_exact_payout (s : State) (c : Claim) :
    (claimEffects s c).payouts c.nullifier = ⟨c.recipient, c.token, c.amount⟩ := by
  simp [claimEffects, put]

theorem claim_effect_same_token (s : State) (c : Claim) :
    (claimEffects s c).withdrawn c.token = s.withdrawn c.token + c.amount ∧
    (claimEffects s c).credit c.token c.recipient = s.credit c.token c.recipient + c.amount ∧
    (claimEffects s c).used c.nullifier = true := by simp [claimEffects, put]

theorem claim_effect_other_token (s : State) (c : Claim) (t : Token) (h : t ≠ c.token) :
    (claimEffects s c).withdrawn t = s.withdrawn t ∧ (claimEffects s c).credit t = s.credit t := by
  simp [claimEffects, put, h]

theorem submit_success_effects (cfg : Config) (ext : External) (s next : State) (c : Claim) (proof : Proof)
    (h : submitClaimCore cfg ext s c proof = .ok next) : next = claimEffects s c := by
  dsimp only [submitClaimCore] at h
  split at h <;> try contradiction
  split at h <;> try contradiction
  split at h <;> try contradiction
  split at h <;> try contradiction
  split at h <;> try contradiction
  split at h <;> try contradiction
  cases ev : ext.verifyClaim cfg.verifier cfg.channel s.finalH1 c proof <;> simp only [ev] at h <;> try contradiction
  split at h <;> try contradiction
  split at h <;> try contradiction
  split at h <;> try contradiction
  split at h <;> try contradiction
  exact (Except.ok.inj h).symm

theorem submit_success_cap (cfg : Config) (ext : External) (s next : State) (c : Claim) (proof : Proof)
    (h : submitClaimCore cfg ext s c proof = .ok next) :
    next.withdrawn c.token ≤ s.cap c.token := by
  have he := submit_success_effects cfg ext s next c proof h
  subst next
  simp only [claimEffects, put, ite_true]
  dsimp only [submitClaimCore] at h
  split at h <;> try contradiction
  split at h <;> try contradiction
  split at h <;> try contradiction
  split at h <;> try contradiction
  split at h <;> try contradiction
  split at h <;> try contradiction
  cases ev : ext.verifyClaim cfg.verifier cfg.channel s.finalH1 c proof <;> simp only [ev] at h <;> try contradiction
  split at h <;> try contradiction
  split at h <;> try contradiction
  split at h <;> try contradiction
  exact Nat.le_of_not_gt (by assumption)

theorem pull_success_exact_cap (cfg : Config) (ext : External) (s next : State) (t : Token)
    (h : pullCore cfg ext s t = .ok next) :
    next.received = put s.received t (s.cap t) ∧ next.paid = s.paid := by
  dsimp only [pullCore] at h
  split at h <;> try contradiction
  cases er : resolveToken ext t with
  | error e => simp only [er] at h
  | ok asset =>
    simp only [er] at h
    split at h <;> try contradiction
    cases em : ext.materialized cfg.materializer cfg.channel <;> simp only [em] at h <;> try contradiction
    split at h <;> try contradiction
    cases eb : ext.balance .before s t asset cfg.manager <;> simp only [eb] at h <;> try contradiction
    cases ep : ext.pull s t (s.cap t - s.received t) <;> simp only [ep] at h <;> try contradiction
    cases ea : ext.balance .after s t asset cfg.manager <;> simp only [ea] at h <;> try contradiction
    split at h <;> try contradiction
    split at h <;> try contradiction
    cases h
    exact ⟨rfl, rfl⟩

theorem pull_success_materialized (cfg : Config) (ext : External) (s next : State) (t : Token)
    (h : pullCore cfg ext s t = .ok next) :
    ext.materialized cfg.materializer cfg.channel = .ok s.finalDigest := by
  dsimp only [pullCore] at h
  split at h <;> try contradiction
  cases er : resolveToken ext t with
  | error e => simp only [er] at h
  | ok asset =>
    simp only [er] at h
    split at h <;> try contradiction
    cases em : ext.materialized cfg.materializer cfg.channel <;> simp only [em] at h <;> try contradiction
    split at h <;> try contradiction
    simp_all

theorem payout_deletes_only_own_record (s : State) (n m : Digest) (h : m ≠ n) :
    (payoutEffects s n).payouts n = emptyPayout ∧
    (payoutEffects s n).payouts m = s.payouts m := by simp [payoutEffects, put, h]

theorem payout_preserves_nullifier_tombstones (s : State) (n : Digest) :
    (payoutEffects s n).used = s.used := rfl

theorem payout_exact_debit (s : State) (n : Digest)
    (h : (s.payouts n).amount ≤ s.credit (s.payouts n).token (s.payouts n).recipient) :
    (payoutEffects s n).credit (s.payouts n).token (s.payouts n).recipient +
      (s.payouts n).amount = s.credit (s.payouts n).token (s.payouts n).recipient := by
  simpa only [payoutEffects, put, ite_true] using Nat.sub_add_cancel h

theorem transfer_success_preserves_cei_state (ext : External) (asset : Address) (next out : State) (p : Payout)
    (h : transferPayout ext asset next p = .ok out) : out = next := by
  dsimp only [transferPayout] at h
  split at h
  · cases en : ext.payNative next p.recipient p.amount <;> simp only [en] at h <;> try contradiction
    split at h <;> try contradiction
    exact (Except.ok.inj h).symm
  · cases eb : ext.balance .before next p.token asset p.recipient <;> simp only [eb] at h <;> try contradiction
    cases ep : ext.payToken next p.token asset p.recipient p.amount <;> simp only [ep] at h <;> try contradiction
    cases ea : ext.balance .after next p.token asset p.recipient <;> simp only [ea] at h <;> try contradiction
    split at h <;> try contradiction
    split at h <;> try contradiction
    exact (Except.ok.inj h).symm

theorem payout_success_exact_effects (ext : External) (s out : State) (sender : Address) (n : Digest)
    (h : claimCreditCore ext s sender n = .ok out) :
    out = payoutEffects s n ∧ sender = (s.payouts n).recipient ∧
    s.paid (s.payouts n).token + (s.payouts n).amount ≤ s.received (s.payouts n).token := by
  dsimp only [claimCreditCore] at h
  split at h <;> try contradiction
  split at h <;> try contradiction
  split at h <;> try contradiction
  split at h <;> try contradiction
  split at h <;> try contradiction
  cases er : resolveToken ext (s.payouts n).token <;> simp only [er] at h <;> try contradiction
  have he := transfer_success_preserves_cei_state ext _ _ out _ h
  simp_all

theorem payout_cannot_repay_deleted_record (ext : External) (s : State) (sender : Address) (n : Digest) :
    claimCreditCore ext (payoutEffects s n) sender n = .error .noCredit := by
  simp [claimCreditCore, payoutEffects, put, emptyPayout]

theorem payout_success_received_ceiling (ext : External) (s out : State) (sender : Address) (n : Digest)
    (h : claimCreditCore ext s sender n = .ok out) :
    out.paid (s.payouts n).token ≤ out.received (s.payouts n).token := by
  obtain ⟨he, _, hc⟩ := payout_success_exact_effects ext s out sender n h
  subst out
  simpa [payoutEffects, put] using hc

/- Named positive examples: successful ordinary native claim, backing pull, freeze.
   These are model evaluations, not transactions against any deployment. -/
def sampleConfig : Config := ⟨1, 42, 50, 60, 70, 31337, 2⟩

def sampleState : State := {
  lifecycle := .closed, generation := 2, freezeNonce := 3, requestedAt := 0,
  status := 1, finalDigest := 7, finalH1 := 8, tokenCount := 1,
  registry := fun _ => 0, cap := fun _ => 100, withdrawn := fun _ => 0,
  received := fun _ => 100, paid := fun _ => 0, credit := fun _ _ => 0,
  payouts := fun _ => emptyPayout, used := fun _ => false }

def sampleExternal : External := {
  verifyClaim := fun _ _ _ _ _ => .ok true,
  tokenAddress := fun _ => .ok 70,
  materialized := fun _ _ => .ok 7,
  freeze := fun _ _ _ _ => .ok (),
  balance := fun phase _ _ _ _ => .ok (if phase = .before then 0 else 100),
  pull := fun _ _ _ => .ok (),
  payNative := fun _ _ _ => .ok true,
  payToken := fun _ _ _ _ _ => .ok () }

def sampleClaim : Claim := ⟨7, 11, 23, 12, 5, 0, 0, 91⟩

theorem normal_claim_then_exact_payment :
    (match submitClaim sampleConfig sampleExternal sampleState sampleClaim [] with
    | .error e => .error e
    | .ok accrued => match claimCredit sampleConfig sampleExternal accrued 23 91 with
      | .error e => .error e
      | .ok paid => .ok (paid.withdrawn 0, paid.paid 0, paid.credit 0 23,
          (paid.payouts 91).amount, paid.used 91, paid.status)) =
      (Except.ok (5, 5, 0, 0, true, 1) : Result (Nat × Nat × Nat × Nat × Bool × Nat)) := by rfl

theorem normal_exact_backing_pull :
    (match pullNative sampleConfig sampleExternal {sampleState with received := fun _ => 0} with
    | .error e => .error e
    | .ok next => .ok (next.received 0, next.paid 0, next.status)) =
      (Except.ok (100, 0, 1) : Result (Nat × Nat × Nat)) := by rfl

theorem normal_generation_freeze :
    (match requestCloseCore sampleConfig sampleExternal 17 {sampleState with lifecycle := .active} with
    | .error e => .error e
    | .ok next => .ok (next.generation, next.freezeNonce, next.requestedAt, next.lifecycle)) =
      (Except.ok (3, 4, 17, Lifecycle.pending) : Result (Nat × Nat × Nat × Lifecycle)) := by rfl

end Zkp.Implementation.ManagerValue
