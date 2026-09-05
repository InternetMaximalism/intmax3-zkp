import Std

/-!
# Current, nullifier-scoped terminal settlement accounting

Source snapshot: parent `c533e710a2d8787624fe429fceee70cdbe000221`.
This independent module does not import the historical close/PW/MT models.

The scope is ONE fixed Manager instance AFTER close finalization. Its channel,
finalized close identity, token registry and per-token caps are fixed parameters.
The storage updates below correspond to `contracts/src/ChannelSettlementManager.sol`:

* `Step.register` / `registerState`: `submitWithdrawalClaim`, lines 2221–2276.
  The lifetime `totalWithdrawn` cap, used-nullifier test/set, exact payout record
  and amount-wise aggregate credit addition are included (including overflow).
* `Step.fund` / `fundState`: `_pullChannelFunds`, lines 2402–2436. The caller
  observes `_closeFundingAuthorizationIssued`,
  `!registry.partialWithdrawalAuthorized(authDigest)` and the EXACT balance
  delta `cap - received`. This is not an arbitrary increase of backing.
* `Step.pay` / `payState`: `claimWithdrawalCredit(bytes32)`, lines 2469–2505.
  It consumes ONE record, subtracts its amount (not all recipient credit),
  increments `totalCreditedOut`, and commits only after a successful transfer.

`WithdrawalProofAccepted` is the observed verifier result for the COMPLETE
call tuple (fixed channel/close/H1, member, recipient, amount, token and
nullifier). It is an explicit input, NOT a cryptographic-soundness axiom.
`FundingObservation` exposes the issued/consumed authorization and actual
balance-delta checks. Their provenance depends on the actual Rollup verified
withdrawal and `CloseFundingMaterializer.materializeNative/materializeERC20`
(lines 53–78), whose authorize-and-consume operation is atomic. That binding,
the Rollup ledger, proof/PCS/signature semantics and the materializer's full
lane validation are NOT proved by this module. These safety bounds hold even
for arbitrary verifier observations, but do NOT establish rightful ownership.

`transferAccepted` means the native call succeeded, or the registered ERC20
transfer succeeded AND the recipient balance delta equalled the amount.
`commitTransfer` models transaction-level EVM rollback, NOT arbitrary token
internals or an EVM-refinement theorem. The actual `nonReentrant` guard covers
funding pulls and payouts, NOT `submitWithdrawalClaim`. A callback can attempt
registration; proving its linearization and nested-call rollback against full
EVM execution remains outside this accounting transition model. This is NOT a
claim that all entrypoints forbid callbacks. Failed calls are stuttering steps.
Nat amounts have the actual checked uint256 addition guards; the Claim amount
domain deliberately overapproximates the Solidity uint64 ABI field. The bounds
hold on that larger domain too. Identities are abstract nonnegative identifiers.

The trace equalities concern TRACKED channel backing, not the entire physical
Manager balance (which can include donations). They prove no duplicate payout
of a recorded nullifier, not uniqueness of cryptographic nullifier derivation.
Zero-amount registration is deliberately allowed, like Solidity; it consumes
the nullifier but can never produce a successful payout.

Excluded from this FIRST accounting slice: the close/cancel/time game;
PW burn/close high-water composition;
changing caps before finalization; whole-protocol L2/L1 conservation; release
readiness and unconditional withdrawal liveness. Old close/PW theorems are
not promoted to current implementation certificates by this module.
-/

namespace ChannelSafetyCurrent

abbrev Token := Nat
abbrev Recipient := Nat
abbrev Nullifier := Nat

def uint256Limit : Nat := 2 ^ 256

structure Config where
  managerId : Nat
  channelId : Nat
  closeId : Nat
  balanceStateH1 : Nat
  tokenCount : Nat
  tokenAt : Nat → Token
  registered : Token → Bool
  cap : Token → Nat

structure Payout where
  token : Token
  recipient : Recipient
  amount : Nat
  deriving DecidableEq, Repr

structure Claim where
  closeId : Nat
  tokenSlot : Nat
  nullifier : Nullifier
  memberPkG : Nat
  userAmountDigest : Nat
  payout : Payout
  deriving DecidableEq, Repr

/-- The complete verifier observation is indexed by the fixed instance and claim. -/
abbrev WithdrawalProofAccepted := Config → Claim → Prop

structure FundingObservation where
  authorizationIssued : Bool
  authorizationOutstanding : Bool
  actualBalanceDelta : Nat

structure State where
  withdrawn : Token → Nat
  received : Token → Nat
  paid : Token → Nat
  credit : Token → Recipient → Nat
  used : Nullifier → Bool
  payout : Nullifier → Option Payout

def empty : State :=
  ⟨fun _ => 0, fun _ => 0, fun _ => 0, fun _ _ => 0,
   fun _ => false, fun _ => none⟩

def put {α : Type} (f : Nat → α) (key : Nat) (value : α) : Nat → α :=
  fun k => if k = key then value else f k

def registerState (s : State) (c : Claim) : State :=
  { s with
    withdrawn := put s.withdrawn c.payout.token (s.withdrawn c.payout.token + c.payout.amount)
    credit := put s.credit c.payout.token
      (put (s.credit c.payout.token) c.payout.recipient
        (s.credit c.payout.token c.payout.recipient + c.payout.amount))
    used := put s.used c.nullifier true
    payout := put s.payout c.nullifier (some c.payout) }

def fundState (cfg : Config) (s : State) (t : Token) : State :=
  { s with received := put s.received t (cfg.cap t) }

def payState (s : State) (n : Nullifier) (p : Payout) : State :=
  { s with
    payout := put s.payout n none
    credit := put s.credit p.token
      (put (s.credit p.token) p.recipient (s.credit p.token p.recipient - p.amount))
    paid := put s.paid p.token (s.paid p.token + p.amount) }

/-- The transaction boundary restores ALL modeled storage if the external send fails. -/
def commitTransfer (before candidate : State) (transferAccepted : Bool) : State :=
  if transferAccepted then candidate else before

inductive Event where
  | registered (claim : Claim)
  | funded (token : Token) (delta : Nat)
  | paid (nullifier : Nullifier) (payout : Payout)
  | reverted
  deriving DecidableEq, Repr

/-- Committed call semantics. Rejected calls cannot mint a success event. -/
inductive Step (cfg : Config) (proofAccepted : WithdrawalProofAccepted) :
    State → Event → State → Prop where
  | register {s : State} {c : Claim}
      (close : c.closeId = cfg.closeId)
      (slot : c.tokenSlot < cfg.tokenCount)
      (token : cfg.tokenAt c.tokenSlot = c.payout.token)
      (fresh : s.used c.nullifier = false)
      (proof : proofAccepted cfg c)
      (withdrawOverflow : s.withdrawn c.payout.token + c.payout.amount < uint256Limit)
      (cap : s.withdrawn c.payout.token + c.payout.amount ≤ cfg.cap c.payout.token)
      (creditOverflow : s.credit c.payout.token c.payout.recipient + c.payout.amount < uint256Limit) :
      Step cfg proofAccepted s (.registered c) (registerState s c)
  | fund {s : State} {t : Token} {obs : FundingObservation}
      (token : t = 0 ∨ cfg.registered t = true)
      (notFull : s.received t < cfg.cap t)
      (issued : obs.authorizationIssued = true)
      (consumed : obs.authorizationOutstanding = false)
      (delta : obs.actualBalanceDelta = cfg.cap t - s.received t) :
      Step cfg proofAccepted s (.funded t obs.actualBalanceDelta) (fundState cfg s t)
  | pay {s : State} {n : Nullifier} {p : Payout} {caller : Recipient}
      (transferAccepted : Bool)
      (record : s.payout n = some p)
      (positive : 0 < p.amount)
      (recipient : caller = p.recipient)
      (credit : p.amount ≤ s.credit p.token p.recipient)
      (overflow : s.paid p.token + p.amount < uint256Limit)
      (backing : s.paid p.token + p.amount ≤ s.received p.token)
      (token : p.token = 0 ∨ cfg.registered p.token = true) :
      Step cfg proofAccepted s
        (if transferAccepted then .paid n p else .reverted)
        (commitTransfer s (payState s n p) transferAccepted)
  | reverted (s : State) : Step cfg proofAccepted s .reverted s

inductive Trace (cfg : Config) (proofAccepted : WithdrawalProofAccepted) :
    State → List Event → State → Prop where
  | nil (s : State) : Trace cfg proofAccepted s [] s
  | cons {s m f : State} {e : Event} {es : List Event} :
      Step cfg proofAccepted s e m → Trace cfg proofAccepted m es f →
      Trace cfg proofAccepted s (e :: es) f

structure Safe (cfg : Config) (s : State) : Prop where
  accrualCap : ∀ t, s.withdrawn t ≤ cfg.cap t
  receivedCap : ∀ t, s.received t ≤ cfg.cap t
  payoutCap : ∀ t, s.paid t ≤ s.received t
  recordedUsed : ∀ n p, s.payout n = some p → s.used n = true

theorem empty_safe (cfg : Config) : Safe cfg empty := by
  constructor <;> simp [empty]

theorem step_preserves_safety {cfg proofAccepted s e s'}
    (h : Step cfg proofAccepted s e s') (hs : Safe cfg s) : Safe cfg s' := by
  cases h with
  | register close slot token fresh proof overflow cap creditOverflow =>
    constructor
    · intro t
      simp only [registerState, put]
      split <;> simp_all [Safe.accrualCap]
    · exact hs.receivedCap
    · exact hs.payoutCap
    · intro n p hp
      simp only [registerState, put] at hp ⊢
      split at hp
      · simp_all
      · split
        · contradiction
        · exact hs.recordedUsed n p hp
  | fund token notFull issued consumed delta =>
    constructor
    · exact hs.accrualCap
    · intro t
      simp only [fundState, put]
      split
      · simp_all
      · exact hs.receivedCap t
    · intro t
      simp only [fundState, put]
      split
      · subst t
        exact Nat.le_trans (hs.payoutCap _) (hs.receivedCap _)
      · exact hs.payoutCap t
    · exact hs.recordedUsed
  | pay accepted record positive recipient credit overflow backing token =>
    cases accepted with
    | false => simpa [commitTransfer] using hs
    | true =>
      simp only [commitTransfer, Bool.true_eq, ↓reduceIte]
      constructor
      · exact hs.accrualCap
      · exact hs.receivedCap
      · intro t
        simp only [payState, put]
        split
        · simp_all
        · exact hs.payoutCap t
      · intro n p hp
        simp only [payState, put] at hp ⊢
        split at hp
        · contradiction
        · exact hs.recordedUsed n p hp
  | reverted => exact hs

theorem trace_preserves_safety {cfg proofAccepted s es f}
    (h : Trace cfg proofAccepted s es f) (hs : Safe cfg s) : Safe cfg f := by
  induction h with
  | nil => exact hs
  | cons hstep _ ih => exact ih (step_preserves_safety hstep hs)

theorem trace_caps {cfg proofAccepted es f}
    (h : Trace cfg proofAccepted empty es f) (t : Token) :
    f.withdrawn t ≤ cfg.cap t ∧ f.paid t ≤ f.received t ∧ f.received t ≤ cfg.cap t := by
  have hf := trace_preserves_safety h (empty_safe cfg)
  exact ⟨hf.accrualCap t, hf.payoutCap t, hf.receivedCap t⟩

def creditAt (t : Token) (r : Recipient) : Event → Nat
  | .registered c => if c.payout.token = t ∧ c.payout.recipient = r then c.payout.amount else 0
  | _ => 0

def paidAt (t : Token) (r : Recipient) : Event → Nat
  | .paid _ p => if p.token = t ∧ p.recipient = r then p.amount else 0
  | _ => 0

def creditedToken (t : Token) : Event → Nat
  | .registered c => if c.payout.token = t then c.payout.amount else 0
  | _ => 0

def paidToken (t : Token) : Event → Nat
  | .paid _ p => if p.token = t then p.amount else 0
  | _ => 0

def fundedToken (t : Token) : Event → Nat
  | .funded u a => if u = t then a else 0
  | _ => 0

def sumEvents (value : Event → Nat) : List Event → Nat
  | [] => 0
  | e :: es => value e + sumEvents value es

theorem step_credit_conservation {cfg proofAccepted s e s'}
    (h : Step cfg proofAccepted s e s') (t : Token) (r : Recipient) :
    s.credit t r + creditAt t r e = s'.credit t r + paidAt t r e := by
  cases h with
  | @register c _ _ _ _ _ _ _ _ =>
    by_cases ht : t = c.payout.token <;> by_cases hr : r = c.payout.recipient <;>
      simp [registerState, put, creditAt, paidAt, ht, hr, Ne.symm, eq_comm]
  | fund => simp [fundState, creditAt, paidAt]
  | @pay n p caller accepted _ _ _ credit _ _ _ =>
    cases accepted with
    | false => simp [commitTransfer, creditAt, paidAt]
    | true =>
      by_cases ht : t = p.token <;> by_cases hr : r = p.recipient <;>
        simp [commitTransfer, payState, put, creditAt, paidAt, ht, hr, Ne.symm, eq_comm]
      omega
  | reverted => simp [creditAt, paidAt]

theorem step_token_conservation {cfg proofAccepted s e s'}
    (h : Step cfg proofAccepted s e s') (t : Token) :
    s.withdrawn t + creditedToken t e = s'.withdrawn t ∧
    s.paid t + paidToken t e = s'.paid t ∧
    s.received t + fundedToken t e = s'.received t := by
  cases h with
  | @register c _ _ _ _ _ _ _ _ =>
    by_cases ht : t = c.payout.token <;>
      simp [registerState, put, creditedToken, paidToken, fundedToken, ht, Ne.symm, eq_comm]
  | @fund u obs _ notFull _ _ delta =>
    by_cases ht : t = u
    · subst t
      simp [fundState, put, creditedToken, paidToken, fundedToken, delta]
      omega
    · simp [fundState, put, creditedToken, paidToken, fundedToken, ht, Ne.symm]
  | @pay n p caller accepted _ _ _ _ _ _ _ =>
    cases accepted with
    | false => simp [commitTransfer, creditedToken, paidToken, fundedToken]
    | true =>
      by_cases ht : t = p.token <;>
        simp [commitTransfer, payState, put, creditedToken, paidToken, fundedToken, ht, Ne.symm, eq_comm]
  | reverted => simp [creditedToken, paidToken, fundedToken]

theorem trace_credit_conservation {cfg proofAccepted s es f}
    (h : Trace cfg proofAccepted s es f) (t : Token) (r : Recipient) :
    s.credit t r + sumEvents (creditAt t r) es =
      f.credit t r + sumEvents (paidAt t r) es := by
  induction h with
  | nil => simp [sumEvents]
  | cons hstep _ ih =>
    have := step_credit_conservation hstep t r
    simp only [sumEvents]
    omega

theorem trace_token_conservation {cfg proofAccepted s es f}
    (h : Trace cfg proofAccepted s es f) (t : Token) :
    s.withdrawn t + sumEvents (creditedToken t) es = f.withdrawn t ∧
    s.paid t + sumEvents (paidToken t) es = f.paid t ∧
    s.received t + sumEvents (fundedToken t) es = f.received t := by
  induction h with
  | nil => simp [sumEvents]
  | cons hstep _ ih =>
    have := step_token_conservation hstep t
    simp only [sumEvents]
    omega

/-- Exact conservation of accounted backing across any mix of successful/reverted calls. -/
theorem trace_backing_conservation {cfg proofAccepted es f}
    (h : Trace cfg proofAccepted empty es f) (t : Token) :
    sumEvents (fundedToken t) es =
      sumEvents (paidToken t) es + (f.received t - f.paid t) := by
  have ht := trace_token_conservation h t
  have hc := trace_caps h t
  simp only [empty] at ht
  omega

/-- Accepted credits are conserved independently for each token AND recipient. -/
theorem trace_recipient_conservation {cfg proofAccepted es f}
    (h : Trace cfg proofAccepted empty es f) (t : Token) (r : Recipient) :
    sumEvents (creditAt t r) es = f.credit t r + sumEvents (paidAt t r) es := by
  simpa [empty] using trace_credit_conservation h t r

theorem trace_total_paid_bounded {cfg proofAccepted es f}
    (h : Trace cfg proofAccepted empty es f) (t : Token) :
    sumEvents (paidToken t) es ≤ sumEvents (fundedToken t) es ∧
    sumEvents (paidToken t) es ≤ cfg.cap t := by
  have ht := trace_token_conservation h t
  have hc := trace_caps h t
  simp only [empty] at ht
  omega

theorem trace_total_credited_bounded {cfg proofAccepted es f}
    (h : Trace cfg proofAccepted empty es f) (t : Token) :
    sumEvents (creditedToken t) es ≤ cfg.cap t := by
  have ht := trace_token_conservation h t
  have hc := trace_caps h t
  simp only [empty] at ht
  omega

def Spent (s : State) (n : Nullifier) : Prop :=
  s.used n = true ∧ s.payout n = none

theorem step_used_monotone {cfg proofAccepted s e s'}
    (h : Step cfg proofAccepted s e s') (n : Nullifier) (hu : s.used n = true) :
    s'.used n = true := by
  cases h with
  | register => simp [registerState, put, hu]
  | fund => exact hu
  | pay accepted _ _ _ _ _ _ _ => cases accepted <;> simpa [commitTransfer, payState] using hu
  | reverted => exact hu

theorem trace_used_monotone {cfg proofAccepted s es f}
    (h : Trace cfg proofAccepted s es f) (n : Nullifier) (hu : s.used n = true) :
    f.used n = true := by
  induction h with
  | nil => exact hu
  | cons hstep _ ih => exact ih (step_used_monotone hstep n hu)

theorem step_spent_preserved {cfg proofAccepted s e s'}
    (h : Step cfg proofAccepted s e s') (n : Nullifier) (hn : Spent s n) :
    Spent s' n := by
  constructor
  · exact step_used_monotone h n hn.1
  · cases h with
    | @register c _ _ _ fresh _ _ _ _ =>
      have hne : n ≠ c.nullifier := by
        intro heq
        subst n
        simp_all [Spent]
      simp [registerState, put, hne, hn.2]
    | fund => exact hn.2
    | pay accepted _ _ _ _ _ _ _ =>
      cases accepted <;> simp [commitTransfer, payState, put, hn.2]
    | reverted => exact hn.2

def payoutCount (n : Nullifier) : Event → Nat
  | .paid m _ => if m = n then 1 else 0
  | _ => 0

theorem step_no_payout_of_spent {cfg proofAccepted s e s'}
    (h : Step cfg proofAccepted s e s') (n : Nullifier) (hn : Spent s n) :
    payoutCount n e = 0 := by
  cases h with
  | register => rfl
  | fund => rfl
  | reverted => rfl
  | @pay m p caller accepted record _ _ _ _ _ _ =>
    cases accepted with
    | false => rfl
    | true =>
      have hne : m ≠ n := by
        intro heq
        subst m
        rw [hn.2] at record
        contradiction
      simp [payoutCount, hne]

theorem trace_no_payout_of_spent {cfg proofAccepted s es f}
    (h : Trace cfg proofAccepted s es f) (n : Nullifier) (hn : Spent s n) :
    sumEvents (payoutCount n) es = 0 := by
  induction h with
  | nil => rfl
  | cons hstep _ ih =>
    simp [sumEvents, step_no_payout_of_spent hstep n hn,
      ih (step_spent_preserved hstep n hn)]

theorem successful_payment_spent {cfg s n p} (hs : Safe cfg s)
    (record : s.payout n = some p) : Spent (payState s n p) n := by
  exact ⟨hs.recordedUsed n p record, by simp [payState, put]⟩

/-- Not just an immediate retry: no later interleaving can pay the same nullifier twice. -/
theorem trace_payout_at_most_once {cfg proofAccepted s es f}
    (h : Trace cfg proofAccepted s es f) (hs : Safe cfg s) (n : Nullifier) :
    sumEvents (payoutCount n) es ≤ 1 := by
  induction h with
  | nil => simp [sumEvents]
  | cons hstep htail ih =>
    have hnext := step_preserves_safety hstep hs
    have hi := ih hnext
    cases hstep with
    | register => simpa [sumEvents, payoutCount] using hi
    | fund => simpa [sumEvents, payoutCount] using hi
    | reverted => simpa [sumEvents, payoutCount] using hi
    | @pay m p caller accepted record positive recipient credit overflow backing token =>
      cases accepted with
      | false => simpa [sumEvents, payoutCount] using hi
      | true =>
        by_cases heq : m = n
        · subst m
          have hspent := successful_payment_spent hs record
          have hz := trace_no_payout_of_spent htail n (by simpa [commitTransfer] using hspent)
          simp [sumEvents, payoutCount, hz]
        · simpa [sumEvents, payoutCount, heq] using hi

theorem registered_nullifier_cannot_be_registered_again {cfg proofAccepted s es f}
    (h : Trace cfg proofAccepted s es f) (n : Nullifier) (hu : s.used n = true) :
    f.used n ≠ false := by
  have := trace_used_monotone h n hu
  simp_all

theorem empty_trace_payout_at_most_once {cfg proofAccepted es f}
    (h : Trace cfg proofAccepted empty es f) (n : Nullifier) :
    sumEvents (payoutCount n) es ≤ 1 :=
  trace_payout_at_most_once h (empty_safe cfg) n

/-- Failed external transfers restore the record, credits, paid totals and every other field. -/
theorem failed_transfer_no_state_change (s : State) (n : Nullifier) (p : Payout) :
    commitTransfer s (payState s n p) false = s := by
  rfl

theorem pay_other_token_frame (s : State) (n : Nullifier) (p : Payout)
    (t : Token) (ht : t ≠ p.token) :
    (payState s n p).credit t = s.credit t ∧
    (payState s n p).paid t = s.paid t ∧
    (payState s n p).withdrawn t = s.withdrawn t ∧
    (payState s n p).received t = s.received t := by
  simp [payState, put, ht]

theorem register_other_token_frame (s : State) (c : Claim)
    (t : Token) (ht : t ≠ c.payout.token) :
    (registerState s c).credit t = s.credit t ∧
    (registerState s c).withdrawn t = s.withdrawn t ∧
    (registerState s c).paid t = s.paid t ∧
    (registerState s c).received t = s.received t := by
  simp [registerState, put, ht]

theorem fund_other_token_frame (cfg : Config) (s : State) (t u : Token) (h : u ≠ t) :
    (fundState cfg s t).received u = s.received u ∧
    (fundState cfg s t).credit u = s.credit u ∧
    (fundState cfg s t).paid u = s.paid u ∧
    (fundState cfg s t).withdrawn u = s.withdrawn u := by
  simp [fundState, put, h]

theorem pay_other_recipient_frame (s : State) (n : Nullifier) (p : Payout)
    (r : Recipient) (hr : r ≠ p.recipient) :
    (payState s n p).credit p.token r = s.credit p.token r := by
  simp [payState, put, hr]

theorem register_other_recipient_frame (s : State) (c : Claim)
    (r : Recipient) (hr : r ≠ c.payout.recipient) :
    (registerState s c).credit c.payout.token r = s.credit c.payout.token r := by
  simp [registerState, put, hr]

theorem pay_other_nullifier_frame (s : State) (n m : Nullifier) (p : Payout) (h : m ≠ n) :
    (payState s n p).payout m = s.payout m ∧ (payState s n p).used m = s.used m := by
  simp [payState, put, h]

theorem register_exact_record (s : State) (c : Claim) :
    (registerState s c).payout c.nullifier = some c.payout ∧
    (registerState s c).used c.nullifier = true := by
  simp [registerState, put]

theorem register_other_nullifier_frame (s : State) (c : Claim) (n : Nullifier)
    (h : n ≠ c.nullifier) :
    (registerState s c).payout n = s.payout n ∧
    (registerState s c).used n = s.used n := by
  simp [registerState, put, h]

theorem pay_exact_record_and_amount (s : State) (n : Nullifier) (p : Payout) :
    (payState s n p).payout n = none ∧
    (payState s n p).credit p.token p.recipient = s.credit p.token p.recipient - p.amount ∧
    (payState s n p).paid p.token = s.paid p.token + p.amount := by
  simp [payState, put]

theorem funded_token_cannot_be_funded_again (cfg : Config) (s : State) (t : Token) :
    ¬ (fundState cfg s t).received t < cfg.cap t := by
  simp [fundState, put]

/-! A positive accounting example, NOT a cryptographic fixture or production proof. -/
def sampleConfig : Config :=
  ⟨1, 2, 3, 4, 1, id, fun _ => true, fun t => if t = 0 then 10 else 0⟩

def sampleClaim : Claim := ⟨3, 0, 9, 17, 18, ⟨0, 7, 3⟩⟩

def sampleFunded : State := fundState sampleConfig empty 0
def sampleRegistered : State := registerState sampleFunded sampleClaim
def samplePaid : State := payState sampleRegistered sampleClaim.nullifier sampleClaim.payout

theorem positive_fund_register_pay :
    Trace sampleConfig (fun _ _ => True) empty
      [.funded 0 10, .registered sampleClaim, .paid 9 sampleClaim.payout] samplePaid := by
  apply Trace.cons (Step.fund (cfg := sampleConfig) (s := empty) (obs := ⟨true, false, 10⟩)
    (Or.inl rfl) (by decide) rfl rfl (by decide))
  apply Trace.cons (Step.register (cfg := sampleConfig) (s := sampleFunded) (c := sampleClaim)
    rfl (by decide) rfl rfl trivial (by decide) (by decide) (by decide))
  apply Trace.cons (Step.pay (cfg := sampleConfig) (s := sampleRegistered)
    (n := sampleClaim.nullifier) (p := sampleClaim.payout) (caller := 7) true
    rfl (by decide) rfl (by decide) (by decide) (by decide) (Or.inl rfl))
  exact Trace.nil _

theorem positive_accounting_result :
    samplePaid.received 0 = 10 ∧ samplePaid.withdrawn 0 = 3 ∧
    samplePaid.paid 0 = 3 ∧ samplePaid.credit 0 7 = 0 ∧
    samplePaid.payout 9 = none ∧ samplePaid.used 9 = true := by
  decide

/-- Two distinct accepted nullifiers for one recipient must NOT be swept together. -/
def sampleSecondClaim : Claim := ⟨3, 0, 10, 19, 20, ⟨0, 7, 4⟩⟩
def sampleTwoRegistered : State := registerState sampleRegistered sampleSecondClaim
def sampleFirstPaid : State := payState sampleTwoRegistered 9 sampleClaim.payout

theorem positive_two_records_failure_then_payment :
    Trace sampleConfig (fun _ _ => True) empty
      [.funded 0 10, .registered sampleClaim, .registered sampleSecondClaim,
       .reverted, .paid 9 sampleClaim.payout] sampleFirstPaid := by
  apply Trace.cons (Step.fund (cfg := sampleConfig) (s := empty) (obs := ⟨true, false, 10⟩)
    (Or.inl rfl) (by decide) rfl rfl (by decide))
  apply Trace.cons (Step.register (cfg := sampleConfig) (s := sampleFunded) (c := sampleClaim)
    rfl (by decide) rfl rfl trivial (by decide) (by decide) (by decide))
  apply Trace.cons (Step.register (cfg := sampleConfig) (s := sampleRegistered) (c := sampleSecondClaim)
    rfl (by decide) rfl (by decide) trivial (by decide) (by decide) (by decide))
  apply Trace.cons (Step.pay (cfg := sampleConfig) (s := sampleTwoRegistered)
    (n := 9) (p := sampleClaim.payout) (caller := 7) false
    (by decide) (by decide) rfl (by decide) (by decide) (by decide) (Or.inl rfl))
  apply Trace.cons (Step.pay (cfg := sampleConfig) (s := sampleTwoRegistered)
    (n := 9) (p := sampleClaim.payout) (caller := 7) true
    (by decide) (by decide) rfl (by decide) (by decide) (by decide) (Or.inl rfl))
  exact Trace.nil _

theorem positive_other_record_survives :
    sampleFirstPaid.credit 0 7 = 4 ∧ sampleFirstPaid.paid 0 = 3 ∧
    sampleFirstPaid.withdrawn 0 = 7 ∧ sampleFirstPaid.payout 9 = none ∧
    sampleFirstPaid.payout 10 = some sampleSecondClaim.payout ∧
    sampleFirstPaid.used 9 = true ∧ sampleFirstPaid.used 10 = true := by
  decide

/-!
## Current close lifecycle: replay fences, not a complete close-game proof

This second slice is independent of the terminal accounting state above; their
composition, including PW high-water snapshots and setting the final caps, is
NOT proved here. It transcribes these Manager sites from the same source pin:

* requestClose/requestCloseAsParticipant/_requestClose: 1166–1208;
* submitCloseIntent/_storePendingClose: 1214–1301, 1351–1387;
* cancelClose: 1406–1498, 1563–1566 (there is NO cancel deadline guard);
* finalizeCloseGuarded/_finalizeClose: 1588–1608, 1665–1675, 1739–1753;
* strict lexicographic _isNewer: 2633–2635.

`LifecycleEnvironment` fixes the channel/member-set identities. Its proof and
membership observations are external results, not assumed signing soundness.
The opaque intent fields stand for the remaining complete proof-bound tuple;
`intentDigest` is the observed computeCloseIntentDigest result, not a supplied
free digest or an injectivity axiom. `closeAccepted` includes the canonical
metadata, finalized Rollup root and bound full-verifier checks at 2540–2622.
`cancelAccepted` represents the complete verifyCancelClose call at 1477–1485.

Only this storage projection is modeled. releaseRuntime is omitted, so the
model overapproximates deployments where that modifier rejects. Non-mutating
guard ordering is collapsed; revert selectors and guard evaluation costs are
not modeled. Participant
proof construction, proof cost, transaction ordering/fairness, semantic latest
state, and signature availability are outside scope. No unconditional exit
or always-successful finalization theorem is claimed: `tailCommits` covers the
omitted checked cap aggregation, PW snapshot adjustment and external
tokenFundsDigest call at 1660–1730. A false tail rolls back the whole call.

Counters and stored times are real-width Fin uint64 values, with checked +1
for generation/nonce and checked -1 on cancel. Explicit Solidity uint64 TIME
casts are modulo 2^64, not checked casts; the code below preserves that fact.
The source's uint256 additions before time casts have explicit overflow guards.
Nat calculations over two uint64 values need no additional overflow guard.
These safety theorems do not require clocks to progress and prove no timing
liveness. In particular, freeze nonce is deliberately NOT monotone.
-/

def uint64Limit : Nat := 2 ^ 64
abbrev LifecycleU64 := Fin uint64Limit
abbrev LifecycleTime := Fin uint256Limit

def lifecycleCast64 (n : Nat) : LifecycleU64 :=
  ⟨n % uint64Limit, Nat.mod_lt _ (by decide)⟩

instance (n : Nat) : OfNat LifecycleU64 n := ⟨lifecycleCast64 n⟩
instance (n : Nat) : OfNat LifecycleTime n :=
  ⟨⟨n % uint256Limit, Nat.mod_lt _ (by decide)⟩⟩

structure StateKey where
  epoch : LifecycleU64
  version : LifecycleU64
  deriving DecidableEq, Repr

structure LifecycleIntent where
  key : StateKey
  freezeNonce : LifecycleU64
  tokenCount : Nat
  opaqueBoundFields : Nat
  deriving DecidableEq, Repr

structure PendingIntent where
  digest : Nat
  key : StateKey
  freezeNonce : LifecycleU64
  deadline : LifecycleU64
  deriving DecidableEq, Repr

structure LifecycleCancelRequest where
  digest : Nat
  revivedVersion : LifecycleU64
  revivedStateDigest : Nat
  deriving DecidableEq, Repr

inductive LifecycleStatus where
  | active | pending | closed
  deriving DecidableEq, Repr

structure LifecycleState where
  status : LifecycleStatus
  freezeNonce : LifecycleU64
  generation : LifecycleU64
  cancelledVersionFloor : LifecycleU64
  requestedAt : LifecycleU64
  horizon : LifecycleU64
  pending : Option PendingIntent
  finalizedDigest : Nat
  finalizedKey : StateKey
  deriving DecidableEq, Repr

structure LifecycleEnvironment where
  channelId : Nat
  registeredMemberSet : Nat
  challengePeriod : LifecycleU64
  intentDigest : LifecycleIntent → Nat
  closeAccepted : Nat → Nat → LifecycleIntent → Bool
  cancelAccepted : Nat → Nat → PendingIntent → LifecycleCancelRequest → Bool

def lifecycleInitial : LifecycleState :=
  ⟨.active, 0, 0, 0, 0, 0, none, 0, ⟨0, 0⟩⟩

def lifecycleNewer (candidate current : StateKey) : Bool :=
  decide (current.epoch.val < candidate.epoch.val ∨
    (candidate.epoch = current.epoch ∧ current.version.val < candidate.version.val))

def lifecycleRequestState (s : LifecycleState) (now : LifecycleTime) : LifecycleState :=
  { s with
    status := .pending
    generation := lifecycleCast64 (s.generation.val + 1)
    freezeNonce := lifecycleCast64 (s.freezeNonce.val + 1)
    requestedAt := lifecycleCast64 now.val }

def lifecycleRequest (s : LifecycleState) (now : LifecycleTime)
    (expectedFreeze expectedFloor : LifecycleU64) (memberAccepted : Bool) : Option LifecycleState :=
  if s.freezeNonce = expectedFreeze ∧ s.cancelledVersionFloor = expectedFloor ∧
      memberAccepted = true ∧ s.status = .active ∧
      s.generation.val + 1 < uint64Limit ∧ s.freezeNonce.val + 1 < uint64Limit then
    some (lifecycleRequestState s now)
  else none

def lifecycleDeadline (e : LifecycleEnvironment) (now : LifecycleTime)
    (horizon : LifecycleU64) : LifecycleU64 :=
  let minResponse := min e.challengePeriod.val 3600
  lifecycleCast64 (min (max (min (now.val + e.challengePeriod.val) horizon.val)
    (now.val + minResponse)) (horizon.val + minResponse))

def lifecycleStore (e : LifecycleEnvironment) (s : LifecycleState) (now : LifecycleTime)
    (i : LifecycleIntent) (horizon : LifecycleU64) : LifecycleState :=
  { s with
    horizon := horizon
    pending := some ⟨e.intentDigest i, i.key, i.freezeNonce, lifecycleDeadline e now horizon⟩ }

def lifecycleSubmit (e : LifecycleEnvironment) (s : LifecycleState) (now : LifecycleTime)
    (i : LifecycleIntent) : Option LifecycleState :=
  if s.status = .closed ∨ i.tokenCount = 0 ∨ 10 < i.tokenCount then none
  else if e.closeAccepted e.channelId e.registeredMemberSet i = false then none
  else if i.freezeNonce ≠ s.freezeNonce then none
  else if uint256Limit ≤ now.val + e.challengePeriod.val then none
  else match s.pending with
    | some p =>
      if now.val ≤ p.deadline.val ∧
          now.val ≤ s.horizon.val + min e.challengePeriod.val 3600 ∧
          lifecycleNewer i.key p.key = true then
        some (lifecycleStore e s now i s.horizon)
      else none
    | none =>
      if s.status ≠ .active ∧ s.requestedAt.val + 600 ≤ now.val ∧
          now.val + 2 * e.challengePeriod.val < uint256Limit then
        some (lifecycleStore e s now i (lifecycleCast64 (now.val + 2 * e.challengePeriod.val)))
      else none

def lifecycleCancelState (s : LifecycleState) (r : LifecycleCancelRequest) : LifecycleState :=
  { s with
    status := .active
    freezeNonce := lifecycleCast64 (s.freezeNonce.val - 1)
    cancelledVersionFloor := r.revivedVersion
    pending := none
    requestedAt := 0
    horizon := 0 }

def lifecycleCancel (e : LifecycleEnvironment) (s : LifecycleState)
    (r : LifecycleCancelRequest) : Option LifecycleState :=
  match s.pending with
  | none => none
  | some p =>
    if r.digest = p.digest ∧ p.key.version.val < r.revivedVersion.val ∧
        s.cancelledVersionFloor.val < r.revivedVersion.val ∧
        e.cancelAccepted e.channelId e.registeredMemberSet p r = true ∧ 0 < s.freezeNonce.val then
      some (lifecycleCancelState s r)
    else none

def lifecycleFinalizeState (s : LifecycleState) (p : PendingIntent) : LifecycleState :=
  { s with
    status := .closed
    pending := none
    requestedAt := 0
    horizon := 0
    finalizedDigest := p.digest
    finalizedKey := p.key }

def lifecycleFinalize (s : LifecycleState) (now : LifecycleTime) (expectedDigest : Nat)
    (expectedGeneration : LifecycleU64) (tailCommits : Bool) : Option LifecycleState :=
  match s.pending with
  | none => none
  | some p =>
    if p.digest = expectedDigest ∧ s.generation = expectedGeneration ∧
        p.deadline.val < now.val ∧ tailCommits = true then
      some (lifecycleFinalizeState s p)
    else none

inductive LifecycleAction where
  | request (now : LifecycleTime) (expectedFreeze expectedFloor : LifecycleU64) (memberAccepted : Bool)
  | submit (now : LifecycleTime) (intent : LifecycleIntent)
  | cancel (request : LifecycleCancelRequest)
  | finalize (now : LifecycleTime) (expectedDigest : Nat) (expectedGeneration : LifecycleU64) (tailCommits : Bool)
  deriving DecidableEq, Repr

def lifecycleCall (e : LifecycleEnvironment) (s : LifecycleState) :
    LifecycleAction → Option LifecycleState
  | .request now freeze floor member => lifecycleRequest s now freeze floor member
  | .submit now intent => lifecycleSubmit e s now intent
  | .cancel request => lifecycleCancel e s request
  | .finalize now digest generation tail => lifecycleFinalize s now digest generation tail

def lifecycleStep (e : LifecycleEnvironment) (s : LifecycleState) (a : LifecycleAction) : LifecycleState :=
  (lifecycleCall e s a).getD s

def lifecycleRun (e : LifecycleEnvironment) : LifecycleState → List LifecycleAction → LifecycleState
  | s, [] => s
  | s, a :: rest => lifecycleRun e (lifecycleStep e s a) rest

theorem lifecycle_request_success {s s' : LifecycleState} {now : LifecycleTime}
    {freeze floor : LifecycleU64} {member : Bool}
    (h : lifecycleRequest s now freeze floor member = some s') :
    s.freezeNonce = freeze ∧ s.cancelledVersionFloor = floor ∧ member = true ∧
    s.status = .active ∧ s.generation.val + 1 < uint64Limit ∧
    s.freezeNonce.val + 1 < uint64Limit ∧ s' = lifecycleRequestState s now := by
  unfold lifecycleRequest at h
  split at h
  · rename_i guards
    exact ⟨guards.1, guards.2.1, guards.2.2.1, guards.2.2.2.1,
      guards.2.2.2.2.1, guards.2.2.2.2.2, (Option.some.inj h).symm⟩
  · contradiction

theorem lifecycle_request_increments_counters {s s' : LifecycleState} {now : LifecycleTime}
    {freeze floor : LifecycleU64} {member : Bool}
    (h : lifecycleRequest s now freeze floor member = some s') :
    s'.generation.val = s.generation.val + 1 ∧
    s'.freezeNonce.val = s.freezeNonce.val + 1 ∧
    s'.cancelledVersionFloor = s.cancelledVersionFloor := by
  rcases lifecycle_request_success h with ⟨_, _, _, _, hg, hn, hs'⟩
  subst s'
  simp [lifecycleRequestState, lifecycleCast64, Nat.mod_eq_of_lt hg, Nat.mod_eq_of_lt hn]

theorem lifecycle_submit_preserves_fences {e : LifecycleEnvironment} {s s' : LifecycleState}
    {now : LifecycleTime} {i : LifecycleIntent}
    (h : lifecycleSubmit e s now i = some s') :
    s'.generation = s.generation ∧ s'.cancelledVersionFloor = s.cancelledVersionFloor ∧
    s'.freezeNonce = s.freezeNonce := by
  unfold lifecycleSubmit at h
  split at h <;> try contradiction
  split at h <;> try contradiction
  split at h <;> try contradiction
  split at h <;> try contradiction
  split at h
  · split at h
    · cases (Option.some.inj h).symm
      exact ⟨rfl, rfl, rfl⟩
    · contradiction
  · split at h
    · cases (Option.some.inj h).symm
      exact ⟨rfl, rfl, rfl⟩
    · contradiction

theorem lifecycle_cancel_success {e : LifecycleEnvironment} {s s' : LifecycleState}
    {r : LifecycleCancelRequest} (h : lifecycleCancel e s r = some s') :
    ∃ p, s.pending = some p ∧ r.digest = p.digest ∧
      p.key.version.val < r.revivedVersion.val ∧
      s.cancelledVersionFloor.val < r.revivedVersion.val ∧
      e.cancelAccepted e.channelId e.registeredMemberSet p r = true ∧
      0 < s.freezeNonce.val ∧ s' = lifecycleCancelState s r := by
  cases hp : s.pending with
  | none => simp [lifecycleCancel, hp] at h
  | some p =>
    simp only [lifecycleCancel, hp] at h
    split at h
    · rename_i guards
      exact ⟨p, rfl, guards.1, guards.2.1, guards.2.2.1, guards.2.2.2.1,
        guards.2.2.2.2, (Option.some.inj h).symm⟩
    · contradiction

theorem lifecycle_cancel_advances_floor_preserves_generation {e : LifecycleEnvironment}
    {s s' : LifecycleState} {r : LifecycleCancelRequest}
    (h : lifecycleCancel e s r = some s') :
    s'.generation = s.generation ∧ s'.cancelledVersionFloor = r.revivedVersion ∧
    s.cancelledVersionFloor.val < s'.cancelledVersionFloor.val := by
  rcases lifecycle_cancel_success h with ⟨p, _, _, _, hf, _, _, hs'⟩
  subst s'
  exact ⟨rfl, rfl, hf⟩

theorem lifecycle_cancel_strictly_decreases_nonce {e : LifecycleEnvironment}
    {s s' : LifecycleState} {r : LifecycleCancelRequest}
    (h : lifecycleCancel e s r = some s') :
    s'.freezeNonce.val + 1 = s.freezeNonce.val ∧ s'.freezeNonce.val < s.freezeNonce.val := by
  rcases lifecycle_cancel_success h with ⟨p, _, _, _, _, _, hn, hs'⟩
  subst s'
  have hsub : s.freezeNonce.val - 1 < uint64Limit := by omega
  simp only [lifecycleCancelState, lifecycleCast64, Nat.mod_eq_of_lt hsub]
  omega

theorem lifecycle_finalize_success {s s' : LifecycleState} {now : LifecycleTime}
    {digest : Nat} {generation : LifecycleU64} {tail : Bool}
    (h : lifecycleFinalize s now digest generation tail = some s') :
    ∃ p, s.pending = some p ∧ p.digest = digest ∧ s.generation = generation ∧
      p.deadline.val < now.val ∧ tail = true ∧ s' = lifecycleFinalizeState s p := by
  cases hp : s.pending with
  | none => simp [lifecycleFinalize, hp] at h
  | some p =>
    simp only [lifecycleFinalize, hp] at h
    split at h
    · rename_i guards
      exact ⟨p, rfl, guards.1, guards.2.1, guards.2.2.1, guards.2.2.2,
        (Option.some.inj h).symm⟩
    · contradiction

theorem lifecycle_finalize_preserves_fences {s s' : LifecycleState} {now : LifecycleTime}
    {digest : Nat} {generation : LifecycleU64} {tail : Bool}
    (h : lifecycleFinalize s now digest generation tail = some s') :
    s'.generation = s.generation ∧ s'.cancelledVersionFloor = s.cancelledVersionFloor ∧
    s'.freezeNonce = s.freezeNonce ∧ s'.pending = none ∧ s'.status = .closed := by
  rcases lifecycle_finalize_success h with ⟨p, _, _, _, _, _, hs'⟩
  subst s'
  exact ⟨rfl, rfl, rfl, rfl, rfl⟩

theorem lifecycle_call_fences_monotone {e : LifecycleEnvironment} {s s' : LifecycleState}
    {a : LifecycleAction} (h : lifecycleCall e s a = some s') :
    s.generation.val ≤ s'.generation.val ∧
    s.cancelledVersionFloor.val ≤ s'.cancelledVersionFloor.val := by
  cases a with
  | request now freeze floor member =>
    have hc := lifecycle_request_increments_counters h
    rw [hc.1, hc.2.2]
    omega
  | submit now intent =>
    have hc := lifecycle_submit_preserves_fences h
    rw [hc.1, hc.2.1]
    exact ⟨Nat.le_refl _, Nat.le_refl _⟩
  | cancel request =>
    have hc := lifecycle_cancel_advances_floor_preserves_generation h
    rw [hc.1]
    exact ⟨Nat.le_refl _, Nat.le_of_lt hc.2.2⟩
  | finalize now digest generation tail =>
    have hc := lifecycle_finalize_preserves_fences h
    rw [hc.1, hc.2.1]
    exact ⟨Nat.le_refl _, Nat.le_refl _⟩

theorem lifecycle_step_fences_monotone (e : LifecycleEnvironment) (s : LifecycleState)
    (a : LifecycleAction) :
    s.generation.val ≤ (lifecycleStep e s a).generation.val ∧
    s.cancelledVersionFloor.val ≤ (lifecycleStep e s a).cancelledVersionFloor.val := by
  cases h : lifecycleCall e s a with
  | none => simp [lifecycleStep, h]
  | some s' => simpa [lifecycleStep, h] using lifecycle_call_fences_monotone h

theorem lifecycle_run_fences_monotone (e : LifecycleEnvironment) (s : LifecycleState)
    (actions : List LifecycleAction) :
    s.generation.val ≤ (lifecycleRun e s actions).generation.val ∧
    s.cancelledVersionFloor.val ≤ (lifecycleRun e s actions).cancelledVersionFloor.val := by
  induction actions generalizing s with
  | nil => simp [lifecycleRun]
  | cons a rest ih =>
    have hh := lifecycle_step_fences_monotone e s a
    have ht := ih (lifecycleStep e s a)
    simp only [lifecycleRun]
    omega

theorem lifecycle_failed_call_preserves_state {e : LifecycleEnvironment} {s : LifecycleState}
    {a : LifecycleAction} (h : lifecycleCall e s a = none) : lifecycleStep e s a = s := by
  simp [lifecycleStep, h]

theorem lifecycle_request_rejects_stale_floor (s : LifecycleState) (now : LifecycleTime)
    (freeze floor : LifecycleU64) (member : Bool) (h : s.cancelledVersionFloor ≠ floor) :
    lifecycleRequest s now freeze floor member = none := by
  simp [lifecycleRequest, h]

theorem lifecycle_finalize_rejects_stale_generation (s : LifecycleState) (now : LifecycleTime)
    (digest : Nat) (generation : LifecycleU64) (tail : Bool) (h : s.generation ≠ generation) :
    lifecycleFinalize s now digest generation tail = none := by
  cases hp : s.pending <;> simp [lifecycleFinalize, hp, h]

theorem lifecycle_finalize_rejects_stale_digest {s : LifecycleState} {p : PendingIntent}
    (hp : s.pending = some p) (now : LifecycleTime) (digest : Nat)
    (generation : LifecycleU64) (tail : Bool) (h : p.digest ≠ digest) :
    lifecycleFinalize s now digest generation tail = none := by
  simp [lifecycleFinalize, hp, h]

theorem lifecycle_finalize_rejects_deadline_equality {s : LifecycleState} {p : PendingIntent}
    (hp : s.pending = some p) (now : LifecycleTime) (digest : Nat)
    (generation : LifecycleU64) (tail : Bool) (h : now.val = p.deadline.val) :
    lifecycleFinalize s now digest generation tail = none := by
  simp [lifecycleFinalize, hp, h]

theorem lifecycle_finalize_failed_tail_rolls_back (s : LifecycleState) (now : LifecycleTime)
    (digest : Nat) (generation : LifecycleU64) :
    lifecycleFinalize s now digest generation false = none := by
  cases hp : s.pending <;> simp [lifecycleFinalize, hp]

theorem lifecycle_cancel_rejects_consumed_version (e : LifecycleEnvironment) (s : LifecycleState)
    (r : LifecycleCancelRequest) (h : r.revivedVersion.val ≤ s.cancelledVersionFloor.val) :
    lifecycleCancel e s r = none := by
  have hnot : ¬ s.cancelledVersionFloor.val < r.revivedVersion.val := by omega
  cases hp : s.pending <;> simp [lifecycleCancel, hp, hnot]

theorem lifecycle_cancel_replay_rejected_after_trace {e : LifecycleEnvironment}
    {s s' : LifecycleState} {r : LifecycleCancelRequest}
    (h : lifecycleCancel e s r = some s') (actions : List LifecycleAction) :
    lifecycleCancel e (lifecycleRun e s' actions) r = none := by
  have hc := lifecycle_cancel_advances_floor_preserves_generation h
  have ht := lifecycle_run_fences_monotone e s' actions
  apply lifecycle_cancel_rejects_consumed_version
  rw [hc.2.1] at ht
  exact ht.2

theorem lifecycle_old_request_rejected_after_cancel_trace {e : LifecycleEnvironment}
    {s s' : LifecycleState} {r : LifecycleCancelRequest}
    (h : lifecycleCancel e s r = some s') (actions : List LifecycleAction)
    (now : LifecycleTime) (expectedFreeze : LifecycleU64) (member : Bool) :
    lifecycleRequest (lifecycleRun e s' actions) now expectedFreeze s.cancelledVersionFloor member = none := by
  have hc := lifecycle_cancel_advances_floor_preserves_generation h
  have ht := lifecycle_run_fences_monotone e s' actions
  apply lifecycle_request_rejects_stale_floor
  intro heq
  have hv := congrArg Fin.val heq
  omega

theorem lifecycle_old_finalize_rejected_after_new_request_trace {e : LifecycleEnvironment}
    {s s' : LifecycleState} {now : LifecycleTime} {freeze floor : LifecycleU64} {member : Bool}
    (h : lifecycleRequest s now freeze floor member = some s') (actions : List LifecycleAction)
    (later : LifecycleTime) (digest : Nat) (tail : Bool) :
    lifecycleFinalize (lifecycleRun e s' actions) later digest s.generation tail = none := by
  have hc := lifecycle_request_increments_counters h
  have ht := lifecycle_run_fences_monotone e s' actions
  apply lifecycle_finalize_rejects_stale_generation
  intro heq
  have hv := congrArg Fin.val heq
  omega

theorem lifecycle_newer_is_strict_lexicographic (candidate current : StateKey) :
    lifecycleNewer candidate current = true ↔
      current.epoch.val < candidate.epoch.val ∨
      (candidate.epoch = current.epoch ∧ current.version.val < candidate.version.val) := by
  simp [lifecycleNewer]

theorem lifecycle_same_key_not_newer (key : StateKey) : lifecycleNewer key key = false := by
  simp [lifecycleNewer]

theorem lifecycle_newer_transitive {a b c : StateKey}
    (hab : lifecycleNewer a b = true) (hbc : lifecycleNewer b c = true) :
    lifecycleNewer a c = true := by
  simp only [lifecycleNewer, decide_eq_true_eq, Fin.ext_iff] at *
  omega

theorem lifecycle_newer_asymmetric {a b : StateKey} (h : lifecycleNewer a b = true) :
    lifecycleNewer b a = false := by
  simp only [lifecycleNewer, decide_eq_true_eq, decide_eq_false_iff_not, Fin.ext_iff] at *
  omega

theorem lifecycle_replacement_requires_newer {e : LifecycleEnvironment} {s s' : LifecycleState}
    {now : LifecycleTime} {i : LifecycleIntent} {p : PendingIntent}
    (hp : s.pending = some p) (h : lifecycleSubmit e s now i = some s') :
    now.val ≤ p.deadline.val ∧ lifecycleNewer i.key p.key = true := by
  unfold lifecycleSubmit at h
  split at h <;> try contradiction
  split at h <;> try contradiction
  split at h <;> try contradiction
  split at h <;> try contradiction
  simp only [hp] at h
  split at h
  · rename_i guards
    exact ⟨guards.1, guards.2.2⟩
  · contradiction

/-- Only this module's lifecycle operation universe: no claim about PW or all EVM calls. -/
theorem lifecycle_closed_calls_reject (e : LifecycleEnvironment) (s : LifecycleState)
    (a : LifecycleAction) (hc : s.status = .closed) (hp : s.pending = none) :
    lifecycleCall e s a = none := by
  cases a with
  | request => simp [lifecycleCall, lifecycleRequest, hc]
  | submit => simp [lifecycleCall, lifecycleSubmit, hc]
  | cancel => simp [lifecycleCall, lifecycleCancel, hp]
  | finalize => simp [lifecycleCall, lifecycleFinalize, hp]

theorem lifecycle_closed_trace_unchanged (e : LifecycleEnvironment) (s : LifecycleState)
    (actions : List LifecycleAction) (hc : s.status = .closed) (hp : s.pending = none) :
    lifecycleRun e s actions = s := by
  induction actions with
  | nil => rfl
  | cons a rest ih =>
    have hcall := lifecycle_closed_calls_reject e s a hc hp
    simpa [lifecycleRun, lifecycleStep, hcall] using ih

/-- Bridges to a fixed terminal snapshot only within this projected lifecycle;
it does NOT prove the omitted cap/PW/accounting composition or EVM refinement. -/
theorem lifecycle_finalized_state_unchanged_after_trace {s s' : LifecycleState}
    {now : LifecycleTime} {digest : Nat} {generation : LifecycleU64} {tail : Bool}
    (h : lifecycleFinalize s now digest generation tail = some s')
    (e : LifecycleEnvironment) (actions : List LifecycleAction) :
    lifecycleRun e s' actions = s' := by
  rcases lifecycle_finalize_preserves_fences h with ⟨_, _, _, hp, hc⟩
  exact lifecycle_closed_trace_unchanged e s' actions hc hp

/-! Non-cryptographic executable examples. The verifier observations below are
ordinary positive placeholders, not fixtures or evidence of signature validity. -/

def lifecycleExampleEnvironment : LifecycleEnvironment :=
  ⟨2, 3, 10, fun i => i.opaqueBoundFields, fun _ _ _ => true, fun _ _ _ _ => true⟩
def lifecycleExampleIntent : LifecycleIntent := ⟨⟨0, 1⟩, 1, 1, 15⟩
def lifecycleExampleCancel : LifecycleCancelRequest := ⟨15, 2, 16⟩
def lifecycleExampleFirstRequest : LifecycleState := lifecycleRequestState lifecycleInitial 0
def lifecycleExampleFirstPending : LifecycleState :=
  lifecycleStore lifecycleExampleEnvironment lifecycleExampleFirstRequest 600 lifecycleExampleIntent 620
def lifecycleExampleCancelled : LifecycleState :=
  lifecycleCancelState lifecycleExampleFirstPending lifecycleExampleCancel
def lifecycleExampleSecondRequest : LifecycleState := lifecycleRequestState lifecycleExampleCancelled 700
def lifecycleExampleSecondPending : LifecycleState :=
  lifecycleStore lifecycleExampleEnvironment lifecycleExampleSecondRequest 1300 lifecycleExampleIntent 1320

/-- The cancel floor does NOT prohibit resubmission of an older close state;
it consumes cancel material and fences raw requests instead. -/
theorem lifecycle_positive_request_cancel_request :
    lifecycleRequest lifecycleInitial 0 0 0 true = some lifecycleExampleFirstRequest ∧
    lifecycleSubmit lifecycleExampleEnvironment lifecycleExampleFirstRequest 600 lifecycleExampleIntent =
      some lifecycleExampleFirstPending ∧
    lifecycleCancel lifecycleExampleEnvironment lifecycleExampleFirstPending lifecycleExampleCancel =
      some lifecycleExampleCancelled ∧
    lifecycleRequest lifecycleExampleCancelled 700 0 2 true = some lifecycleExampleSecondRequest ∧
    lifecycleSubmit lifecycleExampleEnvironment lifecycleExampleSecondRequest 1300 lifecycleExampleIntent =
      some lifecycleExampleSecondPending := by
  decide

theorem lifecycle_positive_nonce_restored_generation_advances :
    lifecycleExampleFirstPending.freezeNonce = lifecycleExampleSecondPending.freezeNonce ∧
    lifecycleExampleCancelled.freezeNonce.val = 0 ∧ lifecycleExampleCancelled.generation.val = 1 ∧
    lifecycleExampleSecondPending.generation.val = 2 ∧
    lifecycleExampleSecondPending.cancelledVersionFloor.val = 2 := by
  decide

theorem lifecycle_positive_strict_replay_and_deadline_gates :
    lifecycleRequest lifecycleExampleCancelled 700 0 0 true = none ∧
    lifecycleFinalize lifecycleExampleSecondPending 1311 15 1 true = none ∧
    lifecycleFinalize lifecycleExampleSecondPending 1310 15 2 true = none ∧
    lifecycleFinalize lifecycleExampleSecondPending 1311 15 2 false = none ∧
    ∃ s', lifecycleFinalize lifecycleExampleSecondPending 1311 15 2 true = some s' ∧
      s'.status = .closed ∧ s'.pending = none := by
  refine ⟨by decide, by decide, by decide, by decide, ?_⟩
  exact ⟨lifecycleFinalizeState lifecycleExampleSecondPending
    ⟨15, lifecycleExampleIntent.key, 1, 1310⟩, by decide, rfl, rfl⟩

end ChannelSafetyCurrent
