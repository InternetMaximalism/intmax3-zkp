import Std

/-!
# Manager manual implementation semantics

Every explicit function body in `contracts/src/ChannelSettlementManager.sol` has
an executable counterpart here. This is a manual semantic model, NOT Solidity
compiler refinement, circuit soundness, channel ownership of pooled Rollup escrow,
or unconditional latest-head exit availability. The line map separately records
interface/storage ABI, hash/assembly and external-call boundaries; no generated
getter bytecode, gas feasibility, or deployed-code equivalence is certified.

`State` and the original value helpers remain a monetary storage projection used
by cross-module accounting proofs. `FullState` adds constructor bindings, complete
close/PW records, high-water snapshots, lifetime replay floors and local events.
Full entrypoint wrappers preserve scalar payout/pull returns and Manager event
arguments. Global ordering relative to external-contract logs and exact Solidity
event/error ABI encoding remain dependency obligations. In particular the payout
wrapper projects its own event, not the point at which a callback observes logs.

Main source mapping: constructor -> `constructor`/`installMembers`; participant
hash/tree -> `participantLeaf`/`participantNode`/`memberOnlyRoot`/`isParticipant`;
close proof -> `checkCloseProof`/`runCloseVerify`; request -> `requestFullCore`;
admission -> `submitCloseIntent`/`checkBurnFloor`; window -> `storePending`;
cancel/finalize -> `cancelClose`/`finalizeCloseCore`; PW lifecycle -> corresponding
full functions and `newestBurnSnapshot`/`authorizePWEffects`; value calls ->
`submitWithdrawalClaim`/`pullChannelFunds`/`pullChannelTokenFunds`/
`claimWithdrawalCredit`. Disabled ABI selectors retain unconditional errors.

Unsigned ABI/storage words are represented by Nat. Their canonical ABI widths are
an explicit refinement obligation, NOT a theorem. Addition/subtraction checks at
all modeled monetary sites are executable below; timestamp uint64 conversion is
explicit modulo, not a silent no-overflow premise. Fixed registry access retains
an array-bounds error. All amounts are raw indivisible token units.

`External` and `FullExternal` are call-observation boundaries, indexed by actual token,
amount, recipient, channel/head, and locally visible state. A successful balance
observation must be the canonical result of the source balanceOf staticcall;
malformed/failed calls are errors. Token transfer includes SafeERC20 semantics as
an external obligation, not an assumption that value arrived: recipient balance
delta is checked separately. Freeze receives the already updated manager state;
payout callbacks receive CEI-deleted state. The finalization TFD staticcall is
indexed by the intermediate Manager state: finalized metadata, active registry
prefix and accrual caps are already written, while pending close, lifecycle,
request timestamp, challenge horizon and prior TFD remain unchanged until return.
The inactive registry suffix is preserved. EVM transaction rollback and call
atomicity, non-reentrant entry discipline, gas/resource behavior and external
contract identity are separate obligations. Callback observations preserve the
represented local storage frame: actual cross-entrypoint callback interference is
not silently assumed impossible or modeled as a successful local-state mutation.
The Config.chainId, sender, timestamp and constructor initialBond parameters denote
the actual call environment (initialBond is msg.value); matching that environment
and ABI-canonical widths is required by a refinement, not proved by these types.
Keccak collision/preimage resistance and verifier soundness are not assumptions
used to conclude the local guard theorems. Available-input examples instantiate
successful observations, not actual proof generation or proof validity.
Except.error exposes no committed
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

set_option maxHeartbeats 800000 in
inductive Fault where
  | runtime | reentrant | onlyRollup | closed | alreadyFrozen | overflow | bounds
  | closeNotActive | digestMismatch | tokenSlot | tokenRegistry | usedNullifier
  | invalidProof | cap | noCredit | wrongRecipient | insufficientCredit
  | tokenNotRegistered | alreadyReceived | notMaterialized | fundingMismatch
  | transferFailed | payoutMismatch | olderBurn | forkedBurn | metadata
  | invalidChannel | invalidMemberCount | invalidBp | invalidPeriod | invalidVerifier
  | invalidMaterializer | invalidBinding | duplicateMember | invalidParticipantRoot
  | memberSetMismatch | bpMismatch | invalidFreeze | notMember | participantProof
  | tokenCount | windowClosed | windowOpen | notNewer | notRequested | grace
  | cancelReplay | invalidCancel | rootNotFinalized
  | specialDisabled | lateDisabled | postDisabled | fundingDeprecated
  | pwNotPending | pwAuxZero | pwChain | pwDescriptor | pwDifferentBurn | pwAccounted
  | pwNotNewer | pwSuperseded | pwCloseInProgress | pwCancelReplay
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

/-! ## Complete lifecycle storage and exact dependency interfaces

The extension keeps concrete metadata, fixed vectors, pending residual fields,
exact call arguments and Manager-emitted event values. Existing accounting
projections above remain reusable; these richer transitions do not treat their
guards as proof of rightful ownership. `logs` is an observer projection, not an
extra Solidity storage field. External global-log interleaving is not modeled.
-/

abbrev Vector := Fin 10 → Nat

def zeroVector : Vector := fun _ => 0

structure CloseIntent where
  closeNonce : Nat := 0
  epoch : Nat := 0
  smallBlock : Nat := 0
  freezeNonce : Nat := 0
  stateDigest : Digest := 0
  h1 : Digest := 0
  funds : Vector := zeroVector
  registry : Vector := zeroVector
  tokenCount : Nat := 0
  fundRoot : Digest := 0
  burn : Digest := 0
  withdrawalDigest : Digest := 0
  snapshot : Nat := 0
  version : Nat := 0
  settledChain : Digest := 0
  accumulatorRoot : Digest := 0

def CloseIntent.key (i : CloseIntent) : OrderKey := ⟨i.epoch, i.version⟩

structure PendingClose where
  active : Bool := false
  intent : CloseIntent := {}
  deadline : Nat := 0
  digest : Digest := 0

structure FinalMetadata where
  stateDigest : Digest := 0
  h1 : Digest := 0
  burn : Digest := 0
  withdrawalDigest : Digest := 0
  fundRoot : Digest := 0
  settledChain : Digest := 0
  accumulatorRoot : Digest := 0
  epoch : Nat := 0
  smallBlock : Nat := 0
  version : Nat := 0

structure MemberBinding where
  pkG : Digest
  recipient : Address
  deriving DecidableEq, Repr

structure Binding where
  config : Config
  bpSlot : Nat
  bpKey : Digest
  specialPenalty : Nat
  closeAdapter : Address
  members : List MemberBinding
  memberKeys : Fin 8 → Digest
  registeredRecipient : Digest → Address
  registeredIndex : Digest → Nat
  memberRecipient : Address → Bool
  memberCount : Nat
  delegateCount : Nat
  participantCount : Nat
  participantRoot : Digest

structure PendingWithdrawal where
  active : Bool := false
  authDigest : Digest := 0
  chainKey : Digest := 0
  burnKey : Digest := 0
  closeDigest : Digest := 0
  deadline : Nat := 0
  version : Nat := 0
  epoch : Nat := 0
  freezeNonce : Nat := 0
  token : Nat := 0
  amount : Nat := 0
  registry : Vector := zeroVector
  funds : Vector := zeroVector
  tokenCount : Nat := 0

structure AuthorizedBurn where
  active : Bool := false
  epoch : Nat := 0
  version : Nat := 0
  closeDigest : Digest := 0
  registry : Vector := zeroVector
  tokenCount : Nat := 0
  postFunds : Token → Nat := fun _ => 0

structure AuthorizedWithdrawal where
  recipient : Address
  token : Token
  amount : Nat
  baseNonce : Nat
  nullifier : Digest
  auxData : Digest
  txLeaf : Digest

structure CancelRequest where
  closeDigest : Digest
  revivedVersion : Nat
  revivedDigest : Digest

inductive ManagerEvent where
  | closeRequested (sender time nonce : Nat)
  | closeSubmitted (digest burn nonce epoch freeze amount deadline version chain : Nat)
  | closeCancelled (digest revived version : Nat)
  | closeFinalized (digest burn epoch amount version chain : Nat)
  | withdrawalAccepted (digest nullifier member recipient amount token : Nat)
  | withdrawalClaimed (nullifier recipient token amount : Nat)
  | fundsPulled (token amount total : Nat)
  | pwSubmitted (auth chain deadline version : Nat)
  | pwFinalized (auth chain : Nat)
  | pwCancelled (auth revived version : Nat)
  deriving DecidableEq, Repr

structure FullState where
  value : State
  pending : PendingClose := {}
  final : FinalMetadata := {}
  horizon : Nat := 0
  highestCancelled : Nat := 0
  burn : AuthorizedBurn := {}
  burnAmount : Token → Nat := fun _ => 0
  accountedBurn : Digest → Bool := fun _ => false
  cancelledPWVersion : Digest → Nat := fun _ => 0
  cancelledPWReview : Digest → Nat := fun _ => 0
  pw : PendingWithdrawal := {}
  tokenFundsDigest : Digest := 0
  bpBond : Nat := 0
  latestSpecialDigest : Digest := 0
  usedShared : Digest → Bool := fun _ => false
  usedLate : Digest → Bool := fun _ => false
  logs : List ManagerEvent := []

structure CloseFields where
  channel : Nat
  intent : CloseIntent
  memberSet : Digest
  memberCount : Nat
  delegateCount : Nat

structure FullExternal where
  hash : List Nat → Digest
  codeSize : Address → Nat
  closeAdapter : Address → Result Address
  memberSetHash : Address → (Fin 8 → Digest) → Nat → Result Digest
  registeredSet : Address → Nat → Result Digest
  registeredBpSlot : Address → Nat → Result Nat
  registeredBpKey : Address → Nat → Result Digest
  finalizedRoot : Address → Digest → Result Bool
  verifyClose : Address → Proof → Result (List Nat)
  bindClose : Address → CloseFields → List Nat → Result Bool
  fundsHash : FullState → Address → Vector → Nat → Vector → Result Digest
  requireBacking : Address → Nat → Digest → Digest → Result Unit
  verifyCancel : Address → Nat → Digest → Digest → Nat → Nat → Digest → Proof → Result Bool
  freeze : FullState → Address → Nat → Nat → Result Unit
  thaw : FullState → Address → Nat → Nat → Result Unit
  authorizePW : FullState → Address → Digest → Result Unit

def emitEvent (s : FullState) (e : ManagerEvent) : FullState := {s with logs := s.logs ++ [e]}

def checkedAdd (limit a b : Nat) : Result Nat :=
  if a + b < limit then .ok (a+b) else .error .overflow

def bytesBE : Nat → Nat → List Nat
  | 0, _ => []
  | n+1, v => (v / 256^n % 256) :: bytesBE n v

def closeId (ext : FullExternal) (b : Binding) (i : CloseIntent) : Digest :=
  ext.hash (bytesBE 4 0x494d4353 ++ bytesBE 4 b.config.channel ++
    bytesBE 32 i.stateDigest ++ bytesBE 8 i.freezeNonce)

def sharedNullifier (ext : FullExternal) (close tx receiver : Digest) : Digest :=
  ext.hash (bytesBE 4 0x494d434b ++ bytesBE 32 close ++ bytesBE 32 tx ++ bytesBE 32 receiver)

def participantLeaf (ext : FullExternal) (slot key recipient : Nat) : Digest :=
  ext.hash (bytesBE 4 0x494d5052 ++ bytesBE 2 slot ++ bytesBE 32 key ++ bytesBE 20 recipient)

def participantNode (ext : FullExternal) (left right : Digest) : Digest :=
  ext.hash (bytesBE 4 0x494d504e ++ bytesBE 32 left ++ bytesBE 32 right)

def merkleLevel (ext : FullExternal) : List Digest → List Digest
  | a :: b :: xs => participantNode ext a b :: merkleLevel ext xs
  | _ => []

def merkleLevels (ext : FullExternal) : Nat → List Digest → List Digest
  | 0, xs => xs
  | n+1, xs => merkleLevels ext n (merkleLevel ext xs)

def memberOnlyRoot (ext : FullExternal) (members : List MemberBinding) : Result Digest :=
  if members.length > 1024 then .error .bounds else
  let leaves := (List.range 1024).map fun i =>
    match members[i]? with
    | none => 0
    | some m => participantLeaf ext (i % 65536) m.pkG m.recipient
  .ok ((merkleLevels ext 10 leaves).headD 0)

def participantPath (ext : FullExternal) : Nat → Digest → List Digest → Digest
  | _, node, [] => node
  | index, node, sibling :: rest =>
    let parent := if index % 2 = 0 then participantNode ext node sibling else participantNode ext sibling node
    participantPath ext (index / 2) parent rest

def isParticipant (ext : FullExternal) (b : Binding) (slot key recipient : Nat)
    (siblings : Fin 10 → Digest) : Bool :=
  if slot ≥ b.participantCount || key = 0 || recipient = 0 then false else
  participantPath ext slot (participantLeaf ext slot key recipient)
    ((List.range 10).map fun i => siblings ⟨i % 10, Nat.mod_lt _ (by decide)⟩) == b.participantRoot

def registeredMemberSet (ext : FullExternal) (b : Binding) : Result Digest :=
  ext.memberSetHash b.config.verifier b.memberKeys b.memberCount

def runCloseVerify (ext : FullExternal) (b : Binding) (intent : CloseIntent) (proof : Proof) :
    Result (Bool × List Nat) := do
  let members ← registeredMemberSet ext b
  let fields : CloseFields := ⟨b.config.channel, intent, members, b.memberCount, b.delegateCount⟩
  let inputs ← ext.verifyClose b.closeAdapter proof
  let verified ← ext.bindClose b.config.verifier fields inputs
  return (verified, inputs)

def packLimbs (words : List Nat) : Nat :=
  words.foldl (fun acc limb => (Nat.lor ((acc * 2^32) % wordLimit) limb) % wordLimit) 0

def checkCloseProof (ext : FullExternal) (b : Binding) (intent : CloseIntent) (proof : Proof) : Result Unit := do
  let _ ← checkCanonicalMetadata intent.closeNonce intent.freezeNonce intent.snapshot intent.burn
  let finalized ← ext.finalizedRoot b.config.rollup intent.fundRoot
  if !finalized then throw .rootNotFinalized
  let (verified, inputs) ← runCloseVerify ext b intent proof
  if !verified then throw .invalidProof
  if inputs.length < 103 then throw .bounds
  let digest := packLimbs ((inputs.drop 95).take 8)
  ext.requireBacking b.config.materializer b.config.channel intent.settledChain digest

def newerIntent (i : CloseIntent) (p : PendingClose) : Bool := isNewer i.key p.intent.key

def closeWindow (period now horizon : Nat) : Result Nat := do
  let natural ← checkedAdd wordLimit now period
  let response := min period 3600
  let floor ← checkedAdd wordLimit now response
  let absoluteEnd ← checkedAdd wordLimit horizon response
  return min (max (min natural horizon) floor) absoluteEnd % nonceLimit

def storePending (b : Binding) (now : Nat) (s : FullState) (intent : CloseIntent)
    (digest : Digest) : Result FullState := do
  let deadline ← closeWindow b.config.challengePeriod now s.horizon
  return {s with pending := ⟨true, intent, deadline, digest⟩}

def requestFullCore (ext : FullExternal) (b : Binding) (sender now : Nat) (s : FullState) : Result FullState := do
  if s.value.lifecycle = .closed then throw .closed
  if s.value.lifecycle != .active then throw .alreadyFrozen
  let generation ← checkedAdd nonceLimit s.value.generation 1
  let nonce ← checkedAdd nonceLimit s.value.freezeNonce 1
  let next := {s with value := {s.value with
    generation := generation, freezeNonce := nonce, lifecycle := .pending, requestedAt := now % nonceLimit}}
  let _ ← ext.freeze next b.config.materializer b.config.channel generation
  return emitEvent next (.closeRequested sender (now % nonceLimit) nonce)

def requestClose (ext : FullExternal) (b : Binding) (sender now expectedNonce expectedCancelled : Nat)
    (s : FullState) : Result FullState := do
  let _ ← runtimeGuard b.config
  if s.value.freezeNonce != expectedNonce || s.highestCancelled != expectedCancelled then throw .invalidFreeze
  if !b.memberRecipient sender then throw .notMember
  requestFullCore ext b sender now s

def requestCloseAsParticipant (ext : FullExternal) (b : Binding) (sender now slot key : Nat)
    (siblings : Fin 10 → Digest) (expectedNonce expectedCancelled : Nat) (s : FullState) : Result FullState := do
  let _ ← runtimeGuard b.config
  if s.value.freezeNonce != expectedNonce || s.highestCancelled != expectedCancelled then throw .invalidFreeze
  if !isParticipant ext b slot key sender siblings then throw .participantProof
  requestFullCore ext b sender now s

def submitCloseIntent (ext : FullExternal) (b : Binding) (now : Nat) (s : FullState)
    (intent : CloseIntent) (proof : Proof) : Result FullState := do
  let _ ← runtimeGuard b.config
  if s.value.lifecycle = .closed then throw .closed
  if intent.tokenCount = 0 || intent.tokenCount > 10 then throw .tokenCount
  let _ ← checkCloseProof ext b intent proof
  let digest := closeId ext b intent
  let _ ← checkBurnFloor s.burn.active ⟨s.burn.epoch, s.burn.version⟩ intent.key s.burn.closeDigest digest
  let _ ← checkBurnFloor s.pw.active ⟨s.pw.epoch, s.pw.version⟩ intent.key s.pw.closeDigest digest
  let mut next := s
  if s.pending.active then
    if now > s.pending.deadline then throw .windowClosed
    let absoluteEnd ← checkedAdd wordLimit s.horizon (min b.config.challengePeriod 3600)
    if now > absoluteEnd then throw .windowClosed
    if intent.freezeNonce != s.value.freezeNonce then throw .invalidFreeze
    if !newerIntent intent s.pending then throw .notNewer
  else
    if s.value.lifecycle = .active then throw .notRequested
    let graceEnd ← checkedAdd wordLimit s.value.requestedAt 600
    if now < graceEnd then throw .grace
    if intent.freezeNonce != s.value.freezeNonce then throw .invalidFreeze
    let doublePeriod ← checkedAdd wordLimit b.config.challengePeriod b.config.challengePeriod
    let horizon ← checkedAdd wordLimit now doublePeriod
    next := {s with horizon := horizon % nonceLimit}
  let stored ← storePending b now next intent digest
  return emitEvent stored (.closeSubmitted digest intent.burn intent.closeNonce intent.epoch
    intent.freezeNonce (intent.funds ⟨0, by decide⟩) stored.pending.deadline intent.version intent.settledChain)

def cancelClose (ext : FullExternal) (b : Binding) (s : FullState)
    (r : CancelRequest) (proof : Proof) : Result FullState := do
  let _ ← runtimeGuard b.config
  if !s.pending.active then throw .closeNotActive
  if r.closeDigest != s.pending.digest then throw .digestMismatch
  if r.revivedVersion ≤ s.pending.intent.version then throw .notNewer
  if r.revivedVersion ≤ s.highestCancelled then throw .cancelReplay
  let members ← registeredMemberSet ext b
  let ok ← ext.verifyCancel b.config.verifier b.config.channel r.closeDigest members
    s.pending.intent.version r.revivedVersion r.revivedDigest proof
  if !ok then throw .invalidCancel
  let consumed := {s with highestCancelled := r.revivedVersion}
  let _ ← ext.thaw consumed b.config.materializer b.config.channel s.value.generation
  if s.value.freezeNonce = 0 then throw .overflow
  let next := {consumed with
    pending := {}, horizon := 0,
    value := {s.value with lifecycle := .active, requestedAt := 0, freezeNonce := s.value.freezeNonce - 1}}
  return emitEvent next (.closeCancelled s.pending.digest r.revivedDigest r.revivedVersion)

def aggregateVector (registry amounts : Vector) (cap : Token → Nat) : Nat → Nat → Result (Token → Nat)
  | 0, _ => .ok cap
  | n+1, index => do
    if h : index < 10 then
      let token := registry ⟨index, h⟩
      let total ← checkedAdd wordLimit (cap token) (amounts ⟨index, h⟩)
      aggregateVector registry amounts (put cap token total) n (index+1)
    else throw .bounds

def finalMetadata (i : CloseIntent) : FinalMetadata :=
  ⟨i.stateDigest, i.h1, i.burn, i.withdrawalDigest, i.fundRoot, i.settledChain,
    i.accumulatorRoot, i.epoch, i.smallBlock, i.version⟩

/-- Solidity1656–1686: these writes precede tokenFundsDigest's external staticcall.
Only the active registry prefix changes; no pending/lifecycle cleanup occurs yet. -/
def finalizationPreCall (s : FullState) (caps : Token → Nat) : FullState :=
  let i := s.pending.intent
  {s with
    final := finalMetadata i,
    value := {s.value with
      finalDigest := s.pending.digest, finalH1 := i.h1, tokenCount := i.tokenCount,
      registry := fun t => if t.val < i.tokenCount then i.registry t else s.value.registry t,
      cap := caps}}

/-- Solidity1685–1709: store returned TFD, close lifecycle/clear timestamp and
horizon, emit using the still-present pending record, then delete pendingClose. -/
def finalizationAfterCall (visible : FullState) (digest : Digest) : FullState :=
  let i := visible.pending.intent
  let closed := {visible with tokenFundsDigest := digest, horizon := 0, value := {visible.value with lifecycle := .closed, requestedAt := 0}}
  let logged := emitEvent closed (.closeFinalized visible.pending.digest i.burn i.epoch
    (i.funds ⟨0, by decide⟩) i.version i.settledChain)
  {logged with pending := {}}

def finalizeCloseCore (ext : FullExternal) (b : Binding) (now : Nat) (s : FullState) : Result FullState := do
  if !s.pending.active then throw .closeNotActive
  if now ≤ s.pending.deadline then throw .windowOpen
  let i := s.pending.intent
  let caps ← aggregateVector i.registry i.funds s.value.cap i.tokenCount 0
  let visible := finalizationPreCall s caps
  let digest ← ext.fundsHash visible b.config.verifier i.registry i.tokenCount i.funds
  return finalizationAfterCall visible digest

def finalizeCloseGuarded (ext : FullExternal) (b : Binding) (now expectedDigest expectedGeneration : Nat)
    (s : FullState) : Result FullState := do
  let _ ← runtimeGuard b.config
  if !s.pending.active then throw .closeNotActive
  if s.pending.digest != expectedDigest || s.value.generation != expectedGeneration then throw .digestMismatch
  finalizeCloseCore ext b now s

def emptyValue : State := {
  lifecycle := .active, generation := 0, freezeNonce := 0, requestedAt := 0,
  status := 1, finalDigest := 0, finalH1 := 0, tokenCount := 0,
  registry := zeroVector, cap := fun _ => 0, withdrawn := fun _ => 0,
  received := fun _ => 0, paid := fun _ => 0, credit := fun _ _ => 0,
  payouts := fun _ => emptyPayout, used := fun _ => false }

def putFin {n : Nat} {α : Type} (f : Fin n → α) (i : Fin n) (value : α) : Fin n → α :=
  fun j => if j = i then value else f j

def installMembers (b : Binding) (index : Nat) : List MemberBinding → Result Binding
  | [] => .ok b
  | m :: rest => do
    if m.pkG = 0 || m.recipient = 0 then throw .invalidBinding
    if b.registeredIndex m.pkG != 0 then throw .duplicateMember
    if h : index < 8 then
      let next := {b with
        registeredRecipient := put b.registeredRecipient m.pkG m.recipient,
        registeredIndex := put b.registeredIndex m.pkG (b.members.length + 1),
        members := b.members ++ [m], memberKeys := putFin b.memberKeys ⟨index, h⟩ m.pkG,
        memberRecipient := put b.memberRecipient m.recipient true}
      installMembers next (index+1) rest
    else throw .bounds

def constructor (ext : FullExternal) (cfg : Config) (bpSlot bpKey delegateCount root penalty initialBond : Nat)
    (members : List MemberBinding) : Result (Binding × FullState) := do
  if cfg.channel = 0 then throw .invalidChannel
  if members.length < 2 || members.length > 8 then throw .invalidMemberCount
  if bpSlot ≥ members.length then throw .invalidBp
  if bpKey = 0 then throw .invalidBp
  if cfg.challengePeriod = 0 then throw .invalidPeriod
  let _ ← runtimeGuard cfg
  if ext.codeSize cfg.verifier = 0 then throw .invalidVerifier
  let adapter ← match ext.closeAdapter cfg.verifier with
    | .error _ => .error .invalidVerifier
    | .ok a => .ok a
  if ext.codeSize adapter = 0 then throw .invalidVerifier
  if cfg.materializer = 0 || ext.codeSize cfg.materializer = 0 then throw .invalidMaterializer
  let participants ← checkedAdd wordLimit members.length delegateCount
  if participants > 1024 then throw .invalidMemberCount
  let empty : Binding := ⟨cfg, bpSlot, bpKey, penalty, adapter, [], fun _ => 0,
    fun _ => 0, fun _ => 0, fun _ => false, members.length % 256, delegateCount,
    participants % 65536, 0⟩
  let installed ← installMembers empty 0 members
  if h : bpSlot < 8 then
    if installed.memberKeys ⟨bpSlot, h⟩ != bpKey then throw .invalidBp
  else throw .bounds
  let resolvedRoot ← if root = 0 then do
      if delegateCount != 0 then throw .invalidParticipantRoot
      memberOnlyRoot ext members
    else .ok root
  if resolvedRoot = 0 then throw .invalidParticipantRoot
  let b := {installed with participantRoot := resolvedRoot}
  let ownSet ← registeredMemberSet ext b
  let registered ← ext.registeredSet cfg.rollup cfg.channel
  if ownSet != registered then throw .memberSetMismatch
  let registrySlot ← ext.registeredBpSlot cfg.rollup cfg.channel
  if bpSlot != registrySlot then throw .bpMismatch
  let registryKey ← ext.registeredBpKey cfg.rollup cfg.channel
  if bpKey != registryKey then throw .bpMismatch
  return (b, {value := emptyValue, bpBond := initialBond})

def memberCount (b : Binding) : Nat := b.members.length
def getPendingClose (s : FullState) : PendingClose := s.pending
def isNativeSendAllowed (b : Binding) (s : FullState) (nonce : Nat) : Bool :=
  if b.config.chainId != 31337 && b.config.challengePeriod < 86400 then false else
  s.value.lifecycle == .active && nonce == s.value.freezeNonce

def submitSpecialClose (_request _proof : Proof) : Result Unit := .error .specialDisabled
def submitLateOutgoingDebitCorrection (_request _proof : Proof) : Result Unit := .error .lateDisabled
def submitPostCloseClaim (_request _proof : Proof) : Result Unit := .error .postDisabled
def authorizeCloseFunding (_token _aux : Nat) : Result Digest := .error .fundingDeprecated

def descriptor (ext : FullExternal) (b : Binding) (w : AuthorizedWithdrawal) : Digest :=
  let baseRecipient := Nat.lor (2 * 2^248) (w.recipient % 2^160)
  ext.hash (bytesBE 4 0x494d4432 ++ bytesBE 4 b.config.channel ++ bytesBE 4 w.baseNonce ++
    bytesBE 32 w.txLeaf ++ bytesBE 32 baseRecipient ++ bytesBE 4 w.token ++ bytesBE 32 w.amount)

def withdrawalAuth (ext : FullExternal) (w : AuthorizedWithdrawal) : Digest :=
  ext.hash (bytesBE 4 0x49505732 ++ bytesBE 20 w.recipient ++ bytesBE 4 w.token ++
    bytesBE 32 w.amount ++ bytesBE 32 w.auxData)

def withdrawalBurnKey (ext : FullExternal) (b : Binding) (w : AuthorizedWithdrawal) : Digest :=
  ext.hash (bytesBE 4 0x494d424b ++ bytesBE 4 b.config.channel ++ bytesBE 32 w.auxData)

def registryContains (i : CloseIntent) (token : Nat) : Bool :=
  ((List.range (min i.tokenCount 10)).map fun n =>
    i.registry ⟨n % 10, Nat.mod_lt _ (by decide)⟩).contains token

def submitPartialWithdrawalIntent (ext : FullExternal) (b : Binding) (now : Nat) (s : FullState)
    (i : CloseIntent) (proof : Proof) (previousChain : Digest) (w : AuthorizedWithdrawal) : Result FullState := do
  let _ ← runtimeGuard b.config
  if s.value.lifecycle != .active then throw .closed
  let _ ← checkCloseProof ext b i proof
  let expectedNonce ← checkedAdd nonceLimit s.value.freezeNonce 1
  if i.freezeNonce != expectedNonce then throw .invalidFreeze
  if w.auxData = 0 then throw .pwAuxZero
  let chain := ext.hash (bytesBE 4 0x494d5443 ++ bytesBE 32 previousChain ++ bytesBE 32 w.auxData)
  if chain != i.settledChain then throw .pwChain
  if !registryContains i w.token then throw .tokenRegistry
  if w.auxData != descriptor ext b w then throw .pwDescriptor
  let chainKey := ext.hash (bytesBE 4 b.config.channel ++ bytesBE 32 i.settledChain)
  let burnKey := withdrawalBurnKey ext b w
  if s.accountedBurn burnKey then throw .pwAccounted
  if s.pw.active then
    if burnKey != s.pw.burnKey then throw .pwDifferentBurn
    if !isNewer i.key ⟨s.pw.epoch, s.pw.version⟩ then throw .pwNotNewer
  let auth := withdrawalAuth ext w
  let natural ← checkedAdd nonceLimit (now % nonceLimit) b.config.challengePeriod
  let deadline := if s.pw.active then s.pw.deadline else max natural (s.cancelledPWReview burnKey)
  let pending : PendingWithdrawal := ⟨true, auth, chainKey, burnKey, closeId ext b i,
    deadline, i.version, i.epoch, s.value.freezeNonce, w.token, w.amount, i.registry, i.funds, i.tokenCount⟩
  return emitEvent {s with pw := pending} (.pwSubmitted auth chainKey deadline i.version)

def clearSnapshot (registry : Vector) (funds : Token → Nat) : Nat → Nat → Result (Token → Nat)
  | 0, _ => .ok funds
  | n+1, index => do
    if h : index < 10 then
      clearSnapshot registry (put funds (registry ⟨index, h⟩) 0) n (index+1)
    else throw .bounds

def replaceAuthorizedBurnSnapshot (s : FullState) : Result AuthorizedBurn := do
  let cleared ← clearSnapshot s.burn.registry s.burn.postFunds s.burn.tokenCount 0
  let funds ← aggregateVector s.pw.registry s.pw.funds cleared s.pw.tokenCount 0
  return {s.burn with
    registry := fun t => if t.val < s.pw.tokenCount then s.pw.registry t
      else if t.val < s.burn.tokenCount then 0 else s.burn.registry t,
    tokenCount := s.pw.tokenCount, postFunds := funds}

def newestBurnSnapshot (s : FullState) : Result AuthorizedBurn := do
  if !s.burn.active || isNewer ⟨s.pw.epoch, s.pw.version⟩ ⟨s.burn.epoch, s.burn.version⟩ then
    let replaced ← replaceAuthorizedBurnSnapshot s
    return {replaced with
      active := true, epoch := s.pw.epoch, version := s.pw.version,
      closeDigest := s.pw.closeDigest}
  else return s.burn

def authorizePWEffects (s : FullState) (burn : AuthorizedBurn) (amount : Nat) : FullState :=
  {s with
    burn := burn, burnAmount := put s.burnAmount s.pw.token amount,
    accountedBurn := put s.accountedBurn s.pw.burnKey true, pw := {}}

def finalizePartialWithdrawal (ext : FullExternal) (b : Binding) (now : Nat) (s : FullState) : Result FullState := do
  let _ ← runtimeGuard b.config
  if !s.pw.active then throw .pwNotPending
  if now ≤ s.pw.deadline then throw .windowOpen
  if s.value.lifecycle = .closed then
    if isNewer ⟨s.pw.epoch, s.pw.version⟩ ⟨s.final.epoch, s.final.version⟩ then throw .pwSuperseded
  else if s.value.lifecycle != .active then throw .pwCloseInProgress
  if s.accountedBurn s.pw.burnKey then throw .pwAccounted
  let amount ← checkedAdd wordLimit (s.burnAmount s.pw.token) s.pw.amount
  let burn ← newestBurnSnapshot s
  let next := authorizePWEffects s burn amount
  let _ ← ext.authorizePW next b.config.rollup s.pw.authDigest
  return emitEvent next (.pwFinalized s.pw.authDigest s.pw.chainKey)

def cancelPartialWithdrawal (ext : FullExternal) (b : Binding) (now : Nat) (s : FullState)
    (r : CancelRequest) (proof : Proof) : Result FullState := do
  let _ ← runtimeGuard b.config
  if !s.pw.active then throw .pwNotPending
  if r.closeDigest != s.pw.closeDigest then throw .digestMismatch
  if r.revivedVersion ≤ s.pw.version then throw .pwNotNewer
  if r.revivedVersion ≤ s.cancelledPWVersion s.pw.burnKey then throw .pwCancelReplay
  let members ← registeredMemberSet ext b
  let ok ← ext.verifyCancel b.config.verifier b.config.channel s.pw.closeDigest members
    s.pw.version r.revivedVersion r.revivedDigest proof
  if !ok then throw .invalidCancel
  let doubled ← checkedAdd nonceLimit b.config.challengePeriod b.config.challengePeriod
  let reviewUntil ← checkedAdd nonceLimit (now % nonceLimit) doubled
  let residual : PendingWithdrawal := {registry := s.pw.registry, funds := s.pw.funds, tokenCount := s.pw.tokenCount}
  let next := {s with
    cancelledPWVersion := put s.cancelledPWVersion s.pw.burnKey r.revivedVersion,
    cancelledPWReview := put s.cancelledPWReview s.pw.burnKey (max reviewUntil (s.cancelledPWReview s.pw.burnKey)),
    pw := residual}
  return emitEvent next (.pwCancelled s.pw.authDigest r.revivedDigest r.revivedVersion)

/- Full wrappers preserve return values and the source's own event coordinates.
   External returns remain storage-frame observations; callbacks changing other
   unguarded Manager entrypoints require a separate EVM interleaving refinement. -/
def submitWithdrawalClaim (b : Binding) (ext : External) (s : FullState) (c : Claim)
    (proof : Proof) : Result FullState := do
  let value ← submitClaim b.config ext s.value c proof
  return emitEvent {s with value := value}
    (.withdrawalAccepted c.closeDigest c.nullifier c.memberKey c.recipient c.amount c.token)

def pullChannelFunds (b : Binding) (ext : External) (s : FullState) : Result (FullState × Nat) := do
  let value ← pullNative b.config ext s.value
  let amount := s.value.cap 0 - s.value.received 0
  return (emitEvent {s with value := value} (.fundsPulled 0 amount (s.value.cap 0)), amount)

def pullChannelTokenFunds (b : Binding) (ext : External) (s : FullState)
    (token : Nat) : Result (FullState × Nat) := do
  let value ← pullToken b.config ext s.value token
  let amount := s.value.cap token - s.value.received token
  return (emitEvent {s with value := value} (.fundsPulled token amount (s.value.cap token)), amount)

def claimWithdrawalCredit (b : Binding) (ext : External) (s : FullState)
    (sender nullifier : Nat) : Result (FullState × Nat) := do
  let p := s.value.payouts nullifier
  let value ← claimCredit b.config ext s.value sender nullifier
  return (emitEvent {s with value := value} (.withdrawalClaimed nullifier p.recipient p.token p.amount), p.amount)

def tokenBalanceOf (call : Address → Proof → Result Proof) (token account : Address) : Result Nat := do
  let data ← match call token (bytesBE 4 0x70a08231 ++ bytesBE 32 account) with
    | .error _ => .error (.external 0)
    | .ok bytes => .ok bytes
  if data.length < 32 then throw (.external 0)
  return ((data.take 32).foldl (fun n b => n*256+b) 0) % wordLimit

theorem checked_add_success (limit a b result : Nat) :
    checkedAdd limit a b = .ok result ↔ a+b < limit ∧ result = a+b := by
  by_cases good : a+b < limit
  · simp [checkedAdd, good, eq_comm]
  · simp only [checkedAdd, if_neg good]
    constructor
    · intro h; cases h
    · rintro ⟨bound, _⟩; exact False.elim (good bound)

theorem manager_events_preserve_storage (s : FullState) (event : ManagerEvent) :
    (emitEvent s event).value = s.value ∧ (emitEvent s event).pending = s.pending ∧
    (emitEvent s event).logs = s.logs ++ [event] := by exact ⟨rfl, rfl, rfl⟩

theorem disabled_special_close (r p : Proof) : submitSpecialClose r p = .error .specialDisabled := rfl
theorem disabled_late_debit (r p : Proof) : submitLateOutgoingDebitCorrection r p = .error .lateDisabled := rfl
theorem disabled_post_credit (r p : Proof) : submitPostCloseClaim r p = .error .postDisabled := rfl
theorem retired_cooperative_funding (token aux : Nat) :
    authorizeCloseFunding token aux = .error .fundingDeprecated := rfl

def vectorContribution (registry amounts : Vector) (token : Nat) : Nat → Nat → Nat
  | 0, _ => 0
  | n+1, index =>
    if h : index < 10 then
      (if registry ⟨index, h⟩ = token then amounts ⟨index, h⟩ else 0) +
        vectorContribution registry amounts token n (index+1)
    else 0

theorem aggregate_vector_exact (registry amounts : Vector) (cap out : Token → Nat)
    (count index token : Nat) (h : aggregateVector registry amounts cap count index = .ok out) :
    out token = cap token + vectorContribution registry amounts token count index := by
  induction count generalizing cap index with
  | zero => simpa [aggregateVector, vectorContribution] using congrArg (fun f => f token) (Except.ok.inj h).symm
  | succ n ih =>
    simp only [aggregateVector, Bind.bind, Except.bind] at h
    split at h
    · rename_i bounds
      cases sum : checkedAdd wordLimit (cap (registry ⟨index, bounds⟩)) (amounts ⟨index, bounds⟩) with
      | error e => simp [sum] at h
      | ok total =>
        simp only [sum, Except.bind] at h
        have totalEq := (checked_add_success _ _ _ _).mp sum
        have result := ih _ _ h
        simp only [vectorContribution, dif_pos bounds]
        rw [result]
        by_cases same : registry ⟨index, bounds⟩ = token
        · simp [put, same, totalEq.2, Nat.add_assoc]
        · have other : token ≠ registry ⟨index, bounds⟩ := Ne.symm same
          simp [put, same, other]
    · simp_all

theorem finalized_metadata_is_one_head (i : CloseIntent) :
    (finalMetadata i).stateDigest = i.stateDigest ∧ (finalMetadata i).h1 = i.h1 ∧
    (finalMetadata i).settledChain = i.settledChain ∧ (finalMetadata i).epoch = i.epoch ∧
    (finalMetadata i).version = i.version := by exact ⟨rfl, rfl, rfl, rfl, rfl⟩

theorem finalization_precall_copies_final_fields (s : FullState) (caps : Token → Nat) :
    (finalizationPreCall s caps).final = finalMetadata s.pending.intent ∧
    (finalizationPreCall s caps).value.finalDigest = s.pending.digest ∧
    (finalizationPreCall s caps).value.finalH1 = s.pending.intent.h1 ∧
    (finalizationPreCall s caps).value.tokenCount = s.pending.intent.tokenCount ∧
    (finalizationPreCall s caps).value.cap = caps := by
  exact ⟨rfl, rfl, rfl, rfl, rfl⟩

theorem finalization_precall_retains_pending_phase (s : FullState) (caps : Token → Nat) :
    (finalizationPreCall s caps).pending = s.pending ∧
    (finalizationPreCall s caps).value.lifecycle = s.value.lifecycle ∧
    (finalizationPreCall s caps).value.requestedAt = s.value.requestedAt ∧
    (finalizationPreCall s caps).horizon = s.horizon ∧
    (finalizationPreCall s caps).tokenFundsDigest = s.tokenFundsDigest ∧
    (finalizationPreCall s caps).logs = s.logs := by
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩

theorem finalization_precall_active_registry_prefix (s : FullState) (caps : Token → Nat)
    (slot : Fin 10) (active : slot.val < s.pending.intent.tokenCount) :
    (finalizationPreCall s caps).value.registry slot = s.pending.intent.registry slot := by
  simp [finalizationPreCall, active]

theorem finalization_precall_preserves_registry_suffix (s : FullState) (caps : Token → Nat)
    (slot : Fin 10) (inactive : s.pending.intent.tokenCount ≤ slot.val) :
    (finalizationPreCall s caps).value.registry slot = s.value.registry slot := by
  simp [finalizationPreCall, Nat.not_lt_of_ge inactive]

/-- A receipt of the actual executable finalization exposes the exact state and
arguments supplied to the TFD boundary, not merely an unrelated helper value. -/
theorem successful_finalization_has_visible_hash_call (ext : FullExternal) (b : Binding) (now : Nat)
    (s next : FullState) (accepted : finalizeCloseCore ext b now s = .ok next) :
    ∃ caps digest,
      aggregateVector s.pending.intent.registry s.pending.intent.funds s.value.cap s.pending.intent.tokenCount 0 = .ok caps ∧
      ext.fundsHash (finalizationPreCall s caps) b.config.verifier s.pending.intent.registry
        s.pending.intent.tokenCount s.pending.intent.funds = .ok digest ∧
      next = finalizationAfterCall (finalizationPreCall s caps) digest := by
  simp only [finalizeCloseCore, Bind.bind, Except.bind, Pure.pure, Except.pure] at accepted
  split at accepted <;> try contradiction
  split at accepted <;> try contradiction
  cases aggregate : aggregateVector s.pending.intent.registry s.pending.intent.funds s.value.cap
      s.pending.intent.tokenCount 0 with
  | error e => simp [aggregate] at accepted
  | ok caps =>
    simp only [aggregate, Except.bind] at accepted
    cases funds : ext.fundsHash (finalizationPreCall s caps) b.config.verifier s.pending.intent.registry
        s.pending.intent.tokenCount s.pending.intent.funds with
    | error e => simp [funds] at accepted
    | ok digest =>
      simp only [funds, Except.bind] at accepted
      cases accepted
      exact ⟨caps, digest, rfl, funds, rfl⟩

theorem successful_finalization_exposes_source_precall_state (ext : FullExternal) (b : Binding) (now : Nat)
    (s next : FullState) (accepted : finalizeCloseCore ext b now s = .ok next) :
    ∃ visible digest,
      ext.fundsHash visible b.config.verifier s.pending.intent.registry
        s.pending.intent.tokenCount s.pending.intent.funds = .ok digest ∧
      visible.final = finalMetadata s.pending.intent ∧
      visible.value.finalDigest = s.pending.digest ∧
      visible.value.tokenCount = s.pending.intent.tokenCount ∧
      (∀ token, visible.value.cap token = s.value.cap token + vectorContribution
        s.pending.intent.registry s.pending.intent.funds token s.pending.intent.tokenCount 0) ∧
      visible.pending = s.pending ∧ visible.value.lifecycle = s.value.lifecycle ∧
      visible.value.requestedAt = s.value.requestedAt ∧ visible.horizon = s.horizon ∧
      visible.tokenFundsDigest = s.tokenFundsDigest ∧
      (∀ slot : Fin 10, visible.value.registry slot =
        if slot.val < s.pending.intent.tokenCount then s.pending.intent.registry slot else s.value.registry slot) := by
  obtain ⟨caps, digest, aggregate, funds, _⟩ := successful_finalization_has_visible_hash_call ext b now s next accepted
  refine ⟨finalizationPreCall s caps, digest, funds, rfl, rfl, rfl, ?_, rfl, rfl, rfl, rfl, rfl, ?_⟩
  · intro token
    exact aggregate_vector_exact _ _ _ _ _ _ _ aggregate
  · intro slot
    rfl

theorem successful_finalization_preserves_registry_suffix (ext : FullExternal) (b : Binding) (now : Nat)
    (s next : FullState) (accepted : finalizeCloseCore ext b now s = .ok next)
    (slot : Fin 10) (inactive : s.pending.intent.tokenCount ≤ slot.val) :
    next.value.registry slot = s.value.registry slot := by
  obtain ⟨caps, digest, _, _, exactNext⟩ := successful_finalization_has_visible_hash_call ext b now s next accepted
  rw [exactNext]
  exact finalization_precall_preserves_registry_suffix s caps slot inactive

theorem finalize_closed_copies_exact_head (ext : FullExternal) (b : Binding) (now : Nat)
    (s next : FullState) (accepted : finalizeCloseCore ext b now s = .ok next) :
    next.value.lifecycle = .closed ∧ next.pending.active = false ∧
    next.final = finalMetadata s.pending.intent ∧ next.value.finalDigest = s.pending.digest ∧
    next.value.tokenCount = s.pending.intent.tokenCount ∧ next.value.generation = s.value.generation := by
  simp only [finalizeCloseCore, Bind.bind, Except.bind, Pure.pure, Except.pure] at accepted
  split at accepted <;> try contradiction
  split at accepted <;> try contradiction
  cases caps : aggregateVector s.pending.intent.registry s.pending.intent.funds s.value.cap
      s.pending.intent.tokenCount 0 with
  | error e => simp [caps] at accepted
  | ok cap =>
    simp only [caps, Except.bind] at accepted
    cases funds : ext.fundsHash (finalizationPreCall s cap) b.config.verifier s.pending.intent.registry s.pending.intent.tokenCount
        s.pending.intent.funds with
    | error e => simp [funds] at accepted
    | ok digest =>
      simp only [funds, Except.bind] at accepted
      cases accepted
      exact ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩

theorem finalize_full_token_vector (ext : FullExternal) (b : Binding) (now : Nat)
    (s next : FullState) (accepted : finalizeCloseCore ext b now s = .ok next) (token : Nat) :
    next.value.cap token = s.value.cap token + vectorContribution s.pending.intent.registry
      s.pending.intent.funds token s.pending.intent.tokenCount 0 := by
  simp only [finalizeCloseCore, Bind.bind, Except.bind, Pure.pure, Except.pure] at accepted
  split at accepted <;> try contradiction
  split at accepted <;> try contradiction
  cases caps : aggregateVector s.pending.intent.registry s.pending.intent.funds s.value.cap
      s.pending.intent.tokenCount 0 with
  | error e => simp [caps] at accepted
  | ok cap =>
    simp only [caps, Except.bind] at accepted
    cases funds : ext.fundsHash (finalizationPreCall s cap) b.config.verifier s.pending.intent.registry s.pending.intent.tokenCount
        s.pending.intent.funds with
    | error e => simp [funds] at accepted
    | ok digest =>
      simp only [funds, Except.bind] at accepted
      cases accepted
      exact aggregate_vector_exact _ _ _ _ _ _ _ caps

theorem finalize_requires_strict_deadline (ext : FullExternal) (b : Binding) (now : Nat)
    (s next : FullState) (accepted : finalizeCloseCore ext b now s = .ok next) : s.pending.deadline < now := by
  simp only [finalizeCloseCore, Bind.bind, Except.bind, Pure.pure, Except.pure] at accepted
  split at accepted <;> try contradiction
  split at accepted <;> try contradiction
  exact Nat.lt_of_not_ge (by assumption)

theorem close_window_absolute_bound (period now horizon deadline : Nat)
    (accepted : closeWindow period now horizon = .ok deadline)
    (fits : horizon + min period 3600 < nonceLimit) : deadline ≤ horizon + min period 3600 := by
  simp only [closeWindow, Bind.bind, Except.bind] at accepted
  cases natural : checkedAdd wordLimit now period with
  | error e => simp [natural] at accepted
  | ok a =>
    simp only [natural, Except.bind] at accepted
    cases floor : checkedAdd wordLimit now (min period 3600) with
    | error e => simp [floor] at accepted
    | ok c =>
      simp only [floor, Except.bind] at accepted
      cases ending : checkedAdd wordLimit horizon (min period 3600) with
      | error e => simp [ending] at accepted
      | ok d =>
        simp only [ending, Except.bind] at accepted
        have de := (checked_add_success _ _ _ _).mp ending
        have le := Nat.min_le_right (max (min a horizon) c) d
        have bound : min (max (min a horizon) c) d < nonceLimit := by omega
        cases accepted
        rw [Nat.mod_eq_of_lt bound]
        simpa [de.2] using le

theorem pending_stores_one_complete_intent (b : Binding) (now : Nat) (s next : FullState)
    (intent : CloseIntent) (digest : Digest) (accepted : storePending b now s intent digest = .ok next) :
    next.pending.intent = intent ∧ next.pending.digest = digest ∧
    next.value = s.value ∧ next.burn = s.burn := by
  simp only [storePending, Bind.bind, Except.bind] at accepted
  cases deadline : closeWindow b.config.challengePeriod now s.horizon with
  | error e => simp [deadline] at accepted
  | ok n => simp only [deadline, Except.bind] at accepted; cases accepted; exact ⟨rfl, rfl, rfl, rfl⟩

theorem request_advances_exact_generation (ext : FullExternal) (b : Binding) (sender now : Nat)
    (s next : FullState) (h : requestFullCore ext b sender now s = .ok next) :
    next.value.generation = s.value.generation + 1 ∧ next.value.freezeNonce = s.value.freezeNonce + 1 ∧
    next.value.lifecycle = .pending ∧ next.highestCancelled = s.highestCancelled := by
  simp only [requestFullCore, Bind.bind, Except.bind, Pure.pure, Except.pure] at h
  split at h <;> try contradiction
  split at h <;> try contradiction
  cases generation : checkedAdd nonceLimit s.value.generation 1 with
  | error e => simp [generation] at h
  | ok gen =>
    simp only [generation, Except.bind] at h
    cases nonce : checkedAdd nonceLimit s.value.freezeNonce 1 with
    | error e => simp [nonce] at h
    | ok n =>
      simp only [nonce, Except.bind] at h
      split at h <;> try contradiction
      have ge := (checked_add_success _ _ _ _).mp generation
      have ne := (checked_add_success _ _ _ _).mp nonce
      cases h
      exact ⟨ge.2, ne.2, rfl, rfl⟩

theorem cancel_restores_nonce_not_generation (ext : FullExternal) (b : Binding)
    (s next : FullState) (r : CancelRequest) (proof : Proof)
    (h : cancelClose ext b s r proof = .ok next) :
    next.value.generation = s.value.generation ∧ next.value.freezeNonce + 1 = s.value.freezeNonce ∧
    next.highestCancelled = r.revivedVersion ∧ s.highestCancelled < next.highestCancelled ∧
    next.pending.active = false ∧ next.value.lifecycle = .active := by
  simp only [cancelClose, Bind.bind, Except.bind, Pure.pure, Except.pure] at h
  cases runtime : runtimeGuard b.config <;> simp only [runtime, Except.bind] at h <;> try contradiction
  split at h <;> try contradiction
  split at h <;> try contradiction
  split at h <;> try contradiction
  split at h <;> try contradiction
  cases members : registeredMemberSet ext b <;> simp only [members, Except.bind] at h <;> try contradiction
  split at h <;> try contradiction
  split at h <;> try contradiction
  split at h <;> try contradiction
  split at h <;> try contradiction
  cases h
  constructor
  · rfl
  constructor
  · change s.value.freezeNonce - 1 + 1 = s.value.freezeNonce
    omega
  constructor
  · rfl
  constructor
  · exact Nat.lt_of_not_ge (by assumption)
  exact ⟨rfl, rfl⟩

theorem guarded_finalize_names_digest_and_generation (ext : FullExternal) (b : Binding)
    (now digest generation : Nat) (s next : FullState)
    (h : finalizeCloseGuarded ext b now digest generation s = .ok next) :
    s.pending.digest = digest ∧ s.value.generation = generation := by
  simp only [finalizeCloseGuarded, Bind.bind, Except.bind, Pure.pure, Except.pure] at h
  cases runtime : runtimeGuard b.config <;> simp only [runtime, Except.bind] at h <;> try contradiction
  split at h <;> try contradiction
  split at h <;> try contradiction
  simp_all

theorem registered_participant_requires_live_slot (ext : FullExternal) (b : Binding)
    (slot key recipient : Nat) (siblings : Fin 10 → Digest)
    (h : isParticipant ext b slot key recipient siblings = true) :
    slot < b.participantCount ∧ key ≠ 0 ∧ recipient ≠ 0 := by
  unfold isParticipant at h
  split at h <;> simp_all

theorem request_guard_authenticates_expected_fences (ext : FullExternal) (b : Binding)
    (sender now nonce cancelled : Nat) (s next : FullState)
    (h : requestClose ext b sender now nonce cancelled s = .ok next) :
    s.value.freezeNonce = nonce ∧ s.highestCancelled = cancelled ∧ b.memberRecipient sender = true := by
  simp only [requestClose, Bind.bind, Except.bind, Pure.pure, Except.pure] at h
  cases runtime : runtimeGuard b.config <;> simp only [runtime, Except.bind] at h <;> try contradiction
  split at h <;> try contradiction
  split at h <;> try contradiction
  simp_all

theorem request_cancel_cycle_keeps_generation_progress (ext : FullExternal) (b : Binding)
    (sender now : Nat) (initial frozen restored : FullState) (r : CancelRequest) (proof : Proof)
    (request : requestFullCore ext b sender now initial = .ok frozen)
    (cancel : cancelClose ext b frozen r proof = .ok restored) :
    restored.value.generation = initial.value.generation + 1 ∧
    restored.value.freezeNonce = initial.value.freezeNonce ∧
    initial.highestCancelled < restored.highestCancelled := by
  obtain ⟨gen, nonce, _, floor⟩ := request_advances_exact_generation ext b sender now initial frozen request
  obtain ⟨sameGen, back, _, newer, _, _⟩ := cancel_restores_nonce_not_generation ext b frozen restored r proof cancel
  constructor
  · exact sameGen.trans gen
  constructor
  · omega
  · simpa [floor] using newer

theorem no_second_finalize_without_another_pending (ext : FullExternal) (b : Binding) (now later : Nat)
    (s next : FullState) (h : finalizeCloseCore ext b now s = .ok next) :
    finalizeCloseCore ext b later next = .error .closeNotActive := by
  have inactive := (finalize_closed_copies_exact_head ext b now s next h).2.1
  unfold finalizeCloseCore
  rw [inactive]
  rfl

theorem consumed_cancel_version_cannot_cancel_again (ext : FullExternal) (b : Binding)
    (s next : FullState) (r : CancelRequest) (proof : Proof) (used : r.revivedVersion ≤ s.highestCancelled) :
    cancelClose ext b s r proof ≠ .ok next := by
  intro accepted
  have h := (cancel_restores_nonce_not_generation ext b s next r proof accepted).2.2
  have newer : s.highestCancelled < r.revivedVersion := by simpa [h.1] using h.2.1
  exact Nat.not_lt_of_ge used newer

theorem available_pending_can_finalize (ext : FullExternal) (b : Binding) (now : Nat)
    (s : FullState) (caps : Token → Nat) (digest : Digest)
    (active : s.pending.active = true) (elapsed : s.pending.deadline < now)
    (aggregate : aggregateVector s.pending.intent.registry s.pending.intent.funds s.value.cap
      s.pending.intent.tokenCount 0 = .ok caps)
    (hashAvailable : ext.fundsHash (finalizationPreCall s caps) b.config.verifier s.pending.intent.registry s.pending.intent.tokenCount
      s.pending.intent.funds = .ok digest) :
    ∃ next, finalizeCloseCore ext b now s = .ok next ∧ next.value.lifecycle = .closed := by
  have notOpen : ¬now ≤ s.pending.deadline := Nat.not_le_of_gt elapsed
  refine ⟨finalizationAfterCall (finalizationPreCall s caps) digest, ?_, rfl⟩
  simp [finalizeCloseCore, active, notOpen, aggregate, hashAvailable,
    Bind.bind, Except.bind, Pure.pure, Except.pure]

theorem older_burn_does_not_replace_high_water (s : FullState)
    (active : s.burn.active = true)
    (notNewer : isNewer ⟨s.pw.epoch, s.pw.version⟩ ⟨s.burn.epoch, s.burn.version⟩ = false) :
    newestBurnSnapshot s = .ok s.burn := by
  simp [newestBurnSnapshot, active, notNewer, Pure.pure, Except.pure]

theorem selected_new_burn_copies_whole_identity (s : FullState) (burn : AuthorizedBurn)
    (newer : (!s.burn.active || isNewer ⟨s.pw.epoch, s.pw.version⟩ ⟨s.burn.epoch, s.burn.version⟩) = true)
    (h : newestBurnSnapshot s = .ok burn) :
    burn.epoch = s.pw.epoch ∧ burn.version = s.pw.version ∧
    burn.closeDigest = s.pw.closeDigest ∧ burn.active = true := by
  simp only [newestBurnSnapshot, newer, Bool.true_eq, if_true, Bind.bind, Except.bind,
    Pure.pure, Except.pure] at h
  cases replaced : replaceAuthorizedBurnSnapshot s with
  | error e => simp [replaced] at h
  | ok r => simp only [replaced, Except.bind] at h; cases h; exact ⟨rfl, rfl, rfl, rfl⟩

theorem partial_withdrawal_finalization_consumes_pending (ext : FullExternal) (b : Binding)
    (now : Nat) (s next : FullState) (h : finalizePartialWithdrawal ext b now s = .ok next) :
    next.accountedBurn s.pw.burnKey = true ∧ next.pw.active = false ∧
    next.value = s.value ∧ next.burnAmount s.pw.token = s.burnAmount s.pw.token + s.pw.amount ∧
    s.pw.deadline < now := by
  simp only [finalizePartialWithdrawal, Bind.bind, Except.bind, Pure.pure, Except.pure] at h
  cases runtime : runtimeGuard b.config <;> simp only [runtime, Except.bind] at h <;> try contradiction
  split at h <;> try contradiction
  split at h <;> try contradiction
  have elapsed : s.pw.deadline < now := Nat.lt_of_not_ge (by assumption)
  split at h
  · split at h <;> try contradiction
    split at h <;> try contradiction
    cases amount : checkedAdd wordLimit (s.burnAmount s.pw.token) s.pw.amount with
    | error e => simp [amount] at h
    | ok a =>
      simp only [amount, Except.bind] at h
      cases burn : newestBurnSnapshot s with
      | error e => simp [burn] at h
      | ok v =>
        simp only [burn, Except.bind] at h
        split at h <;> try contradiction
        cases h
        exact ⟨by simp [emitEvent, authorizePWEffects, put], rfl, rfl,
          by simpa [emitEvent, authorizePWEffects, put] using (checked_add_success _ _ _ _).mp amount |>.2,
          elapsed⟩
  · split at h <;> try contradiction
    split at h <;> try contradiction
    cases amount : checkedAdd wordLimit (s.burnAmount s.pw.token) s.pw.amount with
    | error e => simp [amount] at h
    | ok a =>
      simp only [amount, Except.bind] at h
      cases burn : newestBurnSnapshot s with
      | error e => simp [burn] at h
      | ok v =>
        simp only [burn, Except.bind] at h
        split at h <;> try contradiction
        cases h
        exact ⟨by simp [emitEvent, authorizePWEffects, put], rfl, rfl,
          by simpa [emitEvent, authorizePWEffects, put] using (checked_add_success _ _ _ _).mp amount |>.2,
          elapsed⟩

theorem finalized_partial_withdrawal_cannot_finalize_twice (ext : FullExternal) (b : Binding)
    (now later : Nat) (s next : FullState)
    (h : finalizePartialWithdrawal ext b now s = .ok next) (runtime : runtimeGuard b.config = .ok ()) :
    finalizePartialWithdrawal ext b later next = .error .pwNotPending := by
  have inactive := (partial_withdrawal_finalization_consumes_pending ext b now s next h).2.1
  simp [finalizePartialWithdrawal, runtime, inactive, Bind.bind, Except.bind, Pure.pure, Except.pure]

theorem cancelled_partial_withdrawal_retains_vectors (ext : FullExternal) (b : Binding)
    (now : Nat) (s next : FullState) (r : CancelRequest) (proof : Proof)
    (h : cancelPartialWithdrawal ext b now s r proof = .ok next) :
    next.pw.active = false ∧ next.pw.registry = s.pw.registry ∧ next.pw.funds = s.pw.funds ∧
    next.cancelledPWVersion s.pw.burnKey = r.revivedVersion ∧
    s.cancelledPWVersion s.pw.burnKey < r.revivedVersion ∧
    next.value = s.value := by
  simp only [cancelPartialWithdrawal, Bind.bind, Except.bind, Pure.pure, Except.pure] at h
  cases runtime : runtimeGuard b.config <;> simp only [runtime, Except.bind] at h <;> try contradiction
  split at h <;> try contradiction
  split at h <;> try contradiction
  split at h <;> try contradiction
  split at h <;> try contradiction
  have floor : s.cancelledPWVersion s.pw.burnKey < r.revivedVersion := Nat.lt_of_not_ge (by assumption)
  cases members : registeredMemberSet ext b <;> simp only [members, Except.bind] at h <;> try contradiction
  split at h <;> try contradiction
  split at h <;> try contradiction
  cases doubled : checkedAdd nonceLimit b.config.challengePeriod b.config.challengePeriod with
  | error e => simp [doubled] at h
  | ok d =>
    simp only [doubled, Except.bind] at h
    cases review : checkedAdd nonceLimit (now % nonceLimit) d with
    | error e => simp [review] at h
    | ok v =>
      simp only [review, Except.bind] at h
      cases h
      exact ⟨rfl, rfl, rfl, by simp [emitEvent, put], floor, rfl⟩

/- Local normal-flow examples use explicit successful dependency observations.
   They are not generated ZK proofs or evidence of hash/PCS soundness. The TFD
   fixture deliberately observes the intermediate Manager state, so the normal
   close witness also checks the metadata-before-call/cleanup-after-call order. -/
def normalFullExternal : FullExternal := {
  hash := fun _ => 7, codeSize := fun _ => 1, closeAdapter := fun _ => .ok 71,
  memberSetHash := fun _ _ _ => .ok 17, registeredSet := fun _ _ => .ok 17,
  registeredBpSlot := fun _ _ => .ok 0, registeredBpKey := fun _ _ => .ok 11,
  finalizedRoot := fun _ _ => .ok true,
  verifyClose := fun _ _ => .ok (List.replicate 103 0), bindClose := fun _ _ _ => .ok true,
  fundsHash := fun visible _ _ count _ =>
    if visible.pending.active && visible.value.lifecycle == .pending &&
        visible.final.stateDigest == visible.pending.intent.stateDigest &&
        visible.value.finalDigest == visible.pending.digest && visible.value.tokenCount == count &&
        visible.value.cap 0 == 100 && visible.horizon != 0 && visible.tokenFundsDigest == 0
      then .ok 7 else .error .invalidProof,
  requireBacking := fun _ _ _ _ => .ok (),
  verifyCancel := fun _ _ _ _ _ _ _ _ => .ok true,
  freeze := fun _ _ _ _ => .ok (), thaw := fun _ _ _ _ => .ok (),
  authorizePW := fun _ _ _ => .ok () }

def normalFullSetup : Result (Binding × FullState) :=
  constructor normalFullExternal sampleConfig 0 11 0 1 0 0 [⟨11, 23⟩, ⟨12, 24⟩]

def normalHead : CloseIntent := {
  closeNonce := 1, freezeNonce := 1, epoch := 1, stateDigest := 9, h1 := 8,
  funds := fun t => if t.val = 0 then 100 else 0,
  tokenCount := 1, fundRoot := 10, version := 2, settledChain := 20, accumulatorRoot := 30 }

def normalCloseExecution : Result FullState := do
  let (b, s) ← normalFullSetup
  let requested ← requestClose normalFullExternal b 23 0 0 0 s
  let submitted ← submitCloseIntent normalFullExternal b 600 requested normalHead [11]
  finalizeCloseGuarded normalFullExternal b 603 7 1 submitted

theorem normal_existing_head_closes_without_new_signature :
    (match normalCloseExecution with
      | .error e => .error e
      | .ok s => .ok (s.value.lifecycle, s.value.cap 0, s.value.generation, s.final.version,
        s.pending.active, s.logs.length)) =
      (Except.ok (Lifecycle.closed, 100, 1, 2, false, 3) : Result (Lifecycle × Nat × Nat × Nat × Bool × Nat)) := by rfl

def normalCancelCycle : Result FullState := do
  let (b, s) ← normalFullSetup
  let requested ← requestClose normalFullExternal b 23 0 0 0 s
  let submitted ← submitCloseIntent normalFullExternal b 600 requested normalHead [11]
  let cancelled ← cancelClose normalFullExternal b submitted ⟨7, 3, 40⟩ [12]
  requestClose normalFullExternal b 23 601 0 3 cancelled

theorem normal_cancel_reopen_uses_new_generation :
    (match normalCancelCycle with
      | .error e => .error e
      | .ok s => .ok (s.value.lifecycle, s.value.generation, s.value.freezeNonce, s.highestCancelled)) =
      (Except.ok (Lifecycle.pending, 2, 1, 3) : Result (Lifecycle × Nat × Nat × Nat)) := by rfl

def normalBurn : AuthorizedWithdrawal := ⟨23, 0, 5, 0, 91, 7, 44⟩

def normalPWExecution : Result FullState := do
  let (b, s) ← normalFullSetup
  let head := {normalHead with settledChain := 7, funds := fun t => if t.val = 0 then 95 else 0}
  let submitted ← submitPartialWithdrawalIntent normalFullExternal b 0 s head [11] 0 normalBurn
  finalizePartialWithdrawal normalFullExternal b 3 submitted

theorem normal_partial_withdrawal_authorization_preserves_active_channel :
    (match normalPWExecution with
      | .error e => .error e
      | .ok s => .ok (s.value.lifecycle, s.burnAmount 0, s.burn.postFunds 0,
        s.accountedBurn 7, s.pw.active, s.burn.version)) =
      (Except.ok (Lifecycle.active, 5, 95, true, false, 2) :
        Result (Lifecycle × Nat × Nat × Bool × Bool × Nat)) := by rfl

end Zkp.Implementation.ManagerValue
