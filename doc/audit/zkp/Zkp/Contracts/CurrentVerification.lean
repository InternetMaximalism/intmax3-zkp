import Std

/-!
# Current wire-v3 application verification boundary

Source pin: parent c533e710a2d8787624fe429fceee70cdbe000221,
submodule b569e0d71c6a7a180fe616915b7a76976540b155.

This is an independent, manually transcribed CONTROL-FLOW model, not a proof
of Solidity/Rust compilation, cryptographic soundness, or byte-code refinement.
It deliberately imports none of the historical CField/contract models.

Sources (paths relative to the parent repository):
* contracts/src/IntmaxRollup.sol:1357-1441, 1476-1507, 1896-1938,
  1951-2037, 2043-2099, 2178-2181.
* contracts/lib/polygon-plonky2/mle/contracts/src/PinnedMleVerifierV2.sol:
  53-95, 123-180, 272-298; CompactMleProofV2.sol:36-112.
* src/utils/mle_prover.rs:47-85 and the pinned Rust verifier_v2.rs:57-436.

The decoder, full wire-v3 core, hash functions, KZG attestation lookup and
resource-failure observations are explicit FUNCTION PARAMETERS. No property
of their implementations, no hash injectivity, and no accepted-proof-to-valid-
witness implication is assumed. In particular, `CoreReply.accepted` is the
observed return of the full core, NOT a theorem that the witness is valid.
The basic theorems recover checks from executable definitions, not from an
assumption record containing those same checks.
`Failure.invalidProof` is the already-parsed exact four-byte selector
observation; raw EVM revert bytes and the assembly selector parser are not
mechanically modeled. The fraud body below is its self-called frame only;
direct external calls to that body's guarded entry point are outside this API.

Words, heights and addresses have the real unsigned widths. Bytes are UInt8.
The hash-to-eight-u32 conversion is explicit and does not truncate PI limbs.
ABI decoding, compact field/shape validation and hash preimage serialization
remain at the named decoder/hash boundary. The Nat length of an allocated
byte list abstracts address-space limits; allocation failure is a rejection.

Pins are a fixed environment, never calldata or mutable trace state. Their
purpose mapping records the application's constructor-selected adapter roles;
distinct addresses alone do NOT prove that a deployer selected the right
circuit. Authenticating that registry from CircuitData remains a deployment
obligation. Configuration-load failure cannot replace the pinned config.

Only finalization-related storage is modeled. Other successful operations may
change Context but cannot change finalized roots. Refund/rollback arithmetic
and ETH accounting are outside this slice; `tailCommits` models whole-call
atomic rollback when a later effect fails. The trace theorem applies to this
explicit transition universe, not automatically to every EVM execution.
There is no old degreeBits/test-flag verification bypass in this model.
-/

namespace Zkp.Contracts.CurrentVerification

abbrev Word := Fin (2 ^ 256)
abbrev Height := Fin (2 ^ 64)
abbrev Address := Fin (2 ^ 160)
abbrev Bytes := List UInt8
abbrev PublicInputs := List Word

inductive Purpose where
  | validity | withdrawal | close | withdrawalClaim | postCloseClaim | cancelClose
  deriving DecidableEq, Repr

structure PinnedConfig where
  adapter : Address
  core : Address
  allowedChainId : Word
  encodedConfiguration : Bytes

structure DecodedProof where
  publicInputs : PublicInputs
  /-- Opaque decoded remainder, passed unchanged to the full core. -/
  body : Bytes

inductive Failure where
  /-- Exactly the four-byte InvalidMleProof selector, not a prefix match. -/
  | invalidProof
  /-- Configuration, chain, unknown revert, ABI/memory failure, etc. -/
  | unavailable
  deriving DecidableEq, Repr

inductive CoreReply where
  | accepted
  | returnedFalse
  | reverted (reason : Failure)
  deriving DecidableEq, Repr

structure Engine where
  pins : Purpose → PinnedConfig
  configurationAvailable : Purpose → Bool
  decodeForCore : Bytes → Bytes → Except Failure DecodedProof
  decodeStrict : Bytes → Bytes → Except Failure DecodedProof
  coreVerify : Address → Bytes → DecodedProof → CoreReply
  proofHash : Bytes → Word
  attested : Word → Word → Word → Nat → Bool

/-- Same eight big-endian u32 words as the parent and adapter comparison loops.
The modulo is on the HASH word only; supplied public-input words are not masked. -/
def hashLimbs (hash : Word) : PublicInputs :=
  (List.range 8).map fun i =>
    ⟨(hash.val / 2 ^ (224 - i * 32)) % 2 ^ 32,
      Nat.lt_trans (Nat.mod_lt _ (by decide)) (by decide)⟩

theorem hashLimbs_length (hash : Word) : (hashLimbs hash).length = 8 := by
  simp only [hashLimbs, List.length_map]
  rfl

theorem hashLimbs_each_lt_u32 {hash limb : Word} (h : limb ∈ hashLimbs hash) :
    limb.val < 2 ^ 32 := by
  rcases List.mem_map.mp h with ⟨i, _, hi⟩
  subst limb
  exact Nat.mod_lt _ (by decide)

/-- PinnedMleVerifierV2.verifyCompactPublicInputs: chain, fixed config, one
decode, full core, then (and only then) return that decoded proof's PI vector. -/
def verifyCompactPublicInputs (e : Engine) (chain : Word) (purpose : Purpose)
    (bytes : Bytes) : Option PublicInputs :=
  if chain ≠ (e.pins purpose).allowedChainId then none
  else if e.configurationAvailable purpose = false then none
  else match e.decodeForCore (e.pins purpose).encodedConfiguration bytes with
    | .error _ => none
    | .ok proof =>
      match e.coreVerify (e.pins purpose).core (e.pins purpose).encodedConfiguration proof with
      | .accepted => some proof.publicInputs
      | _ => none

theorem returned_pi_requires_full_core {e : Engine} {chain : Word} {purpose : Purpose}
    {bytes : Bytes} {pis : PublicInputs}
    (h : verifyCompactPublicInputs e chain purpose bytes = some pis) :
    chain = (e.pins purpose).allowedChainId ∧
    e.configurationAvailable purpose = true ∧
    ∃ proof,
      e.decodeForCore (e.pins purpose).encodedConfiguration bytes = .ok proof ∧
      e.coreVerify (e.pins purpose).core (e.pins purpose).encodedConfiguration proof = .accepted ∧
      pis = proof.publicInputs := by
  unfold verifyCompactPublicInputs at h
  split at h
  · contradiction
  · rename_i hc
    split at h
    · contradiction
    · rename_i ha
      cases hd : e.decodeForCore (e.pins purpose).encodedConfiguration bytes with
      | error err => simp [hd] at h
      | ok proof =>
        simp only [hd] at h
        cases hv : e.coreVerify (e.pins purpose).core
            (e.pins purpose).encodedConfiguration proof <;> simp [hv] at h
        exact ⟨by simpa using hc, by cases hb : e.configurationAvailable purpose <;> simp_all,
          proof, rfl, hv, h.symm⟩

structure ValidityPI where
  initialBlockNumber : Height
  initialBlockChain : Word
  initialExtCommitment : Word
  finalBlockNumber : Height
  finalBlockChain : Word
  finalExtCommitment : Word
  prover : Address

structure Submission where
  commitment : Word
  finalized : Bool
  stateRoot : Word
  startBlockNumber : Height
  endBlockNumber : Height
  submittedAtBlock : Height

structure Context where
  submissions : Word → Submission
  blockHashChainAt : Height → Word

structure State where
  context : Context
  latestFinalizedStateRoot : Word
  latestFinalizedBlockNumber : Height
  isFinalizedStateRoot : Word → Bool

structure Request where
  submissionId : Word
  stateRoot : Word
  pi : ValidityPI
  compactProof : Bytes

/-- Uninterpreted deterministic serialization+Keccak of the explicit VPI,
separate from the byte-stream hash used for proof DA. -/
abbrev PIHash := ValidityPI → Word

def fullVerify (e : Engine) (piHash : PIHash) (chain : Word)
    (s : State) (r : Request) : Bool :=
  if r.pi.finalBlockNumber.val < s.latestFinalizedBlockNumber.val then false
  else if r.pi.initialExtCommitment ≠ s.latestFinalizedStateRoot then false
  else if r.pi.initialBlockChain ≠ s.context.blockHashChainAt r.pi.initialBlockNumber then false
  else if r.pi.finalBlockChain ≠ s.context.blockHashChainAt r.pi.finalBlockNumber then false
  else if r.pi.finalExtCommitment ≠ r.stateRoot then false
  else match verifyCompactPublicInputs e chain .validity r.compactProof with
    | none => false
    | some authenticated => decide (authenticated = hashLimbs (piHash r.pi))

def StateBindings (s : State) (r : Request) : Prop :=
  s.latestFinalizedBlockNumber.val ≤ r.pi.finalBlockNumber.val ∧
  r.pi.initialExtCommitment = s.latestFinalizedStateRoot ∧
  r.pi.initialBlockChain = s.context.blockHashChainAt r.pi.initialBlockNumber ∧
  r.pi.finalBlockChain = s.context.blockHashChainAt r.pi.finalBlockNumber ∧
  r.pi.finalExtCommitment = r.stateRoot

theorem fullVerify_requires_bound_authenticated_pi {e : Engine} {piHash : PIHash}
    {chain : Word} {s : State} {r : Request}
    (h : fullVerify e piHash chain s r = true) :
    StateBindings s r ∧
    verifyCompactPublicInputs e chain .validity r.compactProof =
      some (hashLimbs (piHash r.pi)) := by
  unfold fullVerify at h
  split at h
  · contradiction
  · rename_i hheight
    split at h
    · contradiction
    · rename_i hroot
      split at h
      · contradiction
      · rename_i hinitial
        split at h
        · contradiction
        · rename_i hfinal
          split at h
          · contradiction
          · rename_i hext
            cases hv : verifyCompactPublicInputs e chain .validity r.compactProof with
            | none => simp [hv] at h
            | some pis =>
              simp only [hv, decide_eq_true_eq] at h
              refine ⟨⟨Nat.le_of_not_gt hheight, ?_, ?_, ?_, ?_⟩, ?_⟩
              · simpa using hroot
              · simpa using hinitial
              · simpa using hfinal
              · simpa using hext
              · simp [h]

def daAttested (e : Engine) (s : State) (r : Request) : Bool :=
  e.attested r.submissionId (s.context.submissions r.submissionId).commitment
    (e.proofHash r.compactProof) r.compactProof.length

def writeFinalized (s : State) (r : Request) : State :=
  { s with
    context := { s.context with submissions := fun id =>
      if id = r.submissionId then { s.context.submissions id with finalized := true }
      else s.context.submissions id }
    latestFinalizedStateRoot := r.stateRoot
    latestFinalizedBlockNumber := r.pi.finalBlockNumber
    isFinalizedStateRoot := fun root =>
      if root = r.stateRoot then true else s.isFinalizedStateRoot root }

/-- `none` projects either false/rejection or an atomic revert; both preserve
the finalization state. `tailCommits` abstracts the later refund's success. -/
def finalize (e : Engine) (piHash : PIHash) (chain : Word)
    (s : State) (r : Request) (tailCommits : Bool) : Option State :=
  let sub := s.context.submissions r.submissionId
  if sub.commitment = 0 then none
  else if sub.finalized = true then none
  else if r.stateRoot ≠ sub.stateRoot then none
  else if r.pi.finalBlockNumber ≠ sub.endBlockNumber then none
  else if daAttested e s r = false then none
  else if fullVerify e piHash chain s r = false then none
  else if tailCommits = false then none
  else some (writeFinalized s r)

def FinalizationChecks (e : Engine) (piHash : PIHash) (chain : Word)
    (s : State) (r : Request) (tailCommits : Bool) : Prop :=
  (s.context.submissions r.submissionId).commitment ≠ 0 ∧
  (s.context.submissions r.submissionId).finalized = false ∧
  r.stateRoot = (s.context.submissions r.submissionId).stateRoot ∧
  r.pi.finalBlockNumber = (s.context.submissions r.submissionId).endBlockNumber ∧
  daAttested e s r = true ∧ fullVerify e piHash chain s r = true ∧ tailCommits = true

theorem finalize_success_checks {e : Engine} {piHash : PIHash} {chain : Word}
    {s s' : State} {r : Request} {tail : Bool}
    (h : finalize e piHash chain s r tail = some s') :
    FinalizationChecks e piHash chain s r tail ∧ s' = writeFinalized s r := by
  unfold finalize at h
  dsimp only at h
  split at h
  · contradiction
  · rename_i hexists
    split at h
    · contradiction
    · rename_i hnotfin
      split at h
      · contradiction
      · rename_i hroot
        split at h
        · contradiction
        · rename_i hend
          split at h
          · contradiction
          · rename_i hda
            split at h
            · contradiction
            · rename_i hfull
              split at h
              · contradiction
              · rename_i htail
                refine ⟨⟨hexists, ?_, ?_, ?_, ?_, ?_, ?_⟩, ?_⟩
                · cases hb : (s.context.submissions r.submissionId).finalized <;> simp_all
                · simpa using hroot
                · simpa using hend
                · cases hb : daAttested e s r <;> simp_all
                · cases hb : fullVerify e piHash chain s r <;> simp_all
                · cases tail <;> simp_all
                · exact (Option.some.inj h).symm

/-- This is a lookup of the exact (id, commitment, byte hash, byte length)
tuple, not a theorem that KZG/hash binding is sound. -/
theorem finalize_requires_da_and_full_verification {e : Engine} {piHash : PIHash}
    {chain : Word} {s s' : State} {r : Request} {tail : Bool}
    (h : finalize e piHash chain s r tail = some s') :
    e.attested r.submissionId (s.context.submissions r.submissionId).commitment
      (e.proofHash r.compactProof) r.compactProof.length = true ∧
    StateBindings s r ∧
    ∃ proof,
      e.decodeForCore (e.pins .validity).encodedConfiguration r.compactProof = .ok proof ∧
      e.coreVerify (e.pins .validity).core (e.pins .validity).encodedConfiguration proof = .accepted ∧
      proof.publicInputs = hashLimbs (piHash r.pi) := by
  have checks := (finalize_success_checks h).1
  have bound := fullVerify_requires_bound_authenticated_pi checks.2.2.2.2.2.1
  rcases (returned_pi_requires_full_core bound.2).2.2 with ⟨proof, hd, hv, hp⟩
  exact ⟨checks.2.2.2.2.1, bound.1, proof, hd, hv, hp.symm⟩

/-- Exact PI equality after successful finalization implies eight CANONICAL
u32 limbs. A prover-supplied limb is never accepted merely modulo 2^32. -/
theorem finalize_authenticated_pi_are_u32 {e : Engine} {piHash : PIHash}
    {chain : Word} {s s' : State} {r : Request} {tail : Bool}
    (h : finalize e piHash chain s r tail = some s') :
    ∃ proof,
      e.decodeForCore (e.pins .validity).encodedConfiguration r.compactProof = .ok proof ∧
      e.coreVerify (e.pins .validity).core (e.pins .validity).encodedConfiguration proof = .accepted ∧
      proof.publicInputs.length = 8 ∧
      ∀ limb ∈ proof.publicInputs, limb.val < 2 ^ 32 := by
  rcases (finalize_requires_da_and_full_verification h).2.2 with ⟨proof, hd, hv, hp⟩
  refine ⟨proof, hd, hv, ?_, ?_⟩
  · rw [hp]
    exact hashLimbs_length _
  · intro limb hmem
    apply hashLimbs_each_lt_u32
    simpa [hp] using hmem

theorem no_finalize_without_fullVerify {e : Engine} {piHash : PIHash} {chain : Word}
    {s : State} {r : Request} {tail : Bool}
    (h : fullVerify e piHash chain s r = false) :
    finalize e piHash chain s r tail = none := by
  simp [finalize, h]

/-! ## Typed fraud, with timeout kept separate from proof invalidity -/

inductive Verdict where
  | invalid | valid | unevaluable | starved | piMismatch
  deriving DecidableEq, Repr

def compactFraudBody (e : Engine) (bytes : Bytes) (expectedPI : Word) : Except Failure Verdict :=
  if e.configurationAvailable .validity = false then .error .unavailable
  else match e.decodeStrict (e.pins .validity).encodedConfiguration bytes with
    | .error reason => .error reason
    | .ok proof =>
      -- The PI comparison is used ONLY after core success. An invalid proof
      -- or exact decoder invalidity can convict even with a wrong PI preimage.
      match e.coreVerify (e.pins .validity).core (e.pins .validity).encodedConfiguration proof with
      | .accepted => .ok (if proof.publicInputs = hashLimbs expectedPI then .valid else .piMismatch)
      | .returnedFalse => .ok .unevaluable
      | .reverted reason => .error reason

/-- `caughtStarved` is the actual post-catch gas comparison, not a theorem
about EIP-150. It has priority over INVALID on the compact path (b569:159). -/
def compactVerdict (e : Engine) (chain : Word) (bytes : Bytes) (expectedPI : Word)
    (caughtStarved : Bool) : Verdict :=
  if chain ≠ (e.pins .validity).allowedChainId then .unevaluable
  else match compactFraudBody e bytes expectedPI with
    | .ok verdict => verdict
    | .error reason =>
      if caughtStarved then .starved
      else match reason with
        | .invalidProof => .invalid
        | .unavailable => .unevaluable

def verdictCode : Verdict → Nat
  | .invalid => 0 | .valid => 1 | .unevaluable => 2 | .starved => 3 | .piMismatch => 4

inductive FraudDecision where
  | noAction | proofInvalid | revertStarved | revertUnevaluable
  deriving DecidableEq, Repr

/-- The parent uses this exact order, including unknown future uint8 codes.
Nat includes additional codes beyond uint8; all are also non-convicting. -/
def interpretVerdictCode (code : Nat) : FraudDecision :=
  if code = 4 then .noAction
  else if code = 3 then .revertStarved
  else if code > 1 then .revertUnevaluable
  else if code = 0 then .proofInvalid else .noAction

theorem proof_conviction_requires_exact_invalid_code {code : Nat}
    (h : interpretVerdictCode code = .proofInvalid) : code = 0 := by
  unfold interpretVerdictCode at h
  split at h
  · contradiction
  · split at h
    · contradiction
    · split at h
      · contradiction
      · split at h
        · assumption
        · contradiction

theorem unknown_code_never_convicts {code : Nat} (h : 4 < code) :
    interpretVerdictCode code = .revertUnevaluable := by
  simp [interpretVerdictCode, show code ≠ 4 by omega, show code ≠ 3 by omega,
    show 1 < code by omega]

theorem starved_and_piMismatch_never_convict :
    interpretVerdictCode (verdictCode .starved) = .revertStarved ∧
    interpretVerdictCode (verdictCode .piMismatch) = .noAction ∧
    interpretVerdictCode (verdictCode .unevaluable) = .revertUnevaluable := by decide

theorem compact_body_invalid_requires_exact_failure {e : Engine} {bytes : Bytes} {pi : Word}
    (h : compactFraudBody e bytes pi = .error .invalidProof) :
    e.decodeStrict (e.pins .validity).encodedConfiguration bytes = .error .invalidProof ∨
    ∃ proof, e.decodeStrict (e.pins .validity).encodedConfiguration bytes = .ok proof ∧
      e.coreVerify (e.pins .validity).core (e.pins .validity).encodedConfiguration proof =
        .reverted .invalidProof := by
  unfold compactFraudBody at h
  split at h
  · simp at h
  · cases hd : e.decodeStrict (e.pins .validity).encodedConfiguration bytes with
    | error reason =>
      simp only [hd, Except.error.injEq] at h
      exact Or.inl (by simp [h])
    | ok proof =>
      simp only [hd] at h
      cases hv : e.coreVerify (e.pins .validity).core
          (e.pins .validity).encodedConfiguration proof with
      | accepted => simp [hv] at h
      | returnedFalse => simp [hv] at h
      | reverted reason =>
        simp only [hv, Except.error.injEq] at h
        exact Or.inr ⟨proof, rfl, by simpa [h] using hv⟩

theorem compact_body_never_returns_invalid (e : Engine) (bytes : Bytes) (pi : Word) :
    compactFraudBody e bytes pi ≠ .ok .invalid := by
  unfold compactFraudBody
  split
  · simp
  · split
    · simp
    · split
      · split <;> simp
      · simp
      · simp

theorem compact_invalid_requires_exact_failure {e : Engine} {chain : Word}
    {bytes : Bytes} {pi : Word} {starved : Bool}
    (h : compactVerdict e chain bytes pi starved = .invalid) :
    starved = false ∧ compactFraudBody e bytes pi = .error .invalidProof := by
  unfold compactVerdict at h
  split at h
  · contradiction
  · cases hb : compactFraudBody e bytes pi with
    | ok verdict =>
      -- The body cannot return INVALID as an ordinary success.
      have hnot := compact_body_never_returns_invalid e bytes pi
      simp only [hb] at h
      exact False.elim (hnot (by simpa [h] using hb))
    | error reason =>
      cases starved <;> cases reason <;> simp_all

theorem valid_proof_wrong_pi_is_nonconvicting {e : Engine} {chain : Word}
    {bytes : Bytes} {pi : Word} {proof : DecodedProof} {starved : Bool}
    (hc : chain = (e.pins .validity).allowedChainId)
    (ha : e.configurationAvailable .validity = true)
    (hd : e.decodeStrict (e.pins .validity).encodedConfiguration bytes = .ok proof)
    (hv : e.coreVerify (e.pins .validity).core (e.pins .validity).encodedConfiguration proof = .accepted)
    (hp : proof.publicInputs ≠ hashLimbs pi) :
    compactVerdict e chain bytes pi starved = .piMismatch := by
  simp [compactVerdict, compactFraudBody, hc, ha, hd, hv, hp]

/-- The parent transport reserves gas too. A failed call never supplies an
INVALID code. `failure = some b` records catch + its starvation comparison. -/
def parentVerdict (entryEnough : Bool) (failure : Option Bool) (adapter : Verdict) : Nat :=
  if entryEnough = false then 3
  else match failure with
    | some true => 3
    | some false => 2
    | none => verdictCode adapter

theorem parent_invalid_requires_adapter_invalid {entry : Bool} {failure : Option Bool}
    {adapter : Verdict} (h : parentVerdict entry failure adapter = 0) :
    entry = true ∧ failure = none ∧ adapter = .invalid := by
  cases entry <;> cases failure with
  | none => cases adapter <;> simp_all [parentVerdict, verdictCode]
  | some b => cases b <;> simp_all [parentVerdict]

def fraudStateBindings (s : State) (r : Request) : Bool :=
  decide (r.pi.initialExtCommitment = s.latestFinalizedStateRoot) &&
  decide (r.pi.initialBlockChain = s.context.blockHashChainAt r.pi.initialBlockNumber) &&
  decide (r.pi.finalBlockChain = s.context.blockHashChainAt r.pi.finalBlockNumber) &&
  decide (r.pi.finalExtCommitment = r.stateRoot)

def verifyFraud (e : Engine) (piHash : PIHash) (chain : Word) (s : State) (r : Request)
    (entryEnough caughtStarved : Bool) (transportFailure : Option Bool) : FraudDecision :=
  if daAttested e s r = false then .noAction
  else if fraudStateBindings s r = false then .noAction
  else interpretVerdictCode (parentVerdict entryEnough transportFailure
    (compactVerdict e chain r.compactProof (piHash r.pi) caughtStarved))

theorem verifyFraud_conviction_requires_attested_invalid {e : Engine} {piHash : PIHash}
    {chain : Word} {s : State} {r : Request} {entry starved : Bool} {failure : Option Bool}
    (h : verifyFraud e piHash chain s r entry starved failure = .proofInvalid) :
    daAttested e s r = true ∧ fraudStateBindings s r = true ∧ entry = true ∧
    failure = none ∧ compactVerdict e chain r.compactProof (piHash r.pi) starved = .invalid := by
  unfold verifyFraud at h
  split at h
  · contradiction
  · rename_i hda
    split at h
    · contradiction
    · rename_i hstate
      have hv := proof_conviction_requires_exact_invalid_code h
      refine ⟨?_, ?_, parent_invalid_requires_adapter_invalid hv⟩
      · cases hb : daAttested e s r <;> simp_all
      · cases hb : fraudStateBindings s r <;> simp_all

inductive RemovalReason where
  | timeout | invalidProof
  deriving DecidableEq, Repr

inductive FraudOutcome where
  | noAction | reverted | removed (reason : RemovalReason)
  deriving DecidableEq, Repr

/-- Timeout is a separate policy, checked BEFORE the proof path. The two
removals intentionally share no theorem equating timeout with invalidity.
`tailCommits` includes _truncateSubmissions' finalized-entry and effect checks. -/
def fraudProof (e : Engine) (piHash : PIHash) (chain now : Word) (s : State) (r : Request)
    (entryEnough caughtStarved tailCommits : Bool) (transportFailure : Option Bool) : FraudOutcome :=
  let sub := s.context.submissions r.submissionId
  if sub.commitment = 0 then .noAction
  else if sub.finalized = true then .reverted
  else if sub.startBlockNumber.val ≤ s.latestFinalizedBlockNumber.val then .reverted
  else if sub.submittedAtBlock.val + 3600 < now.val then
    if tailCommits then .removed .timeout else .reverted
  else match verifyFraud e piHash chain s r entryEnough caughtStarved transportFailure with
    | .proofInvalid => if tailCommits then .removed .invalidProof else .reverted
    | .noAction => .noAction
    | .revertStarved | .revertUnevaluable => .reverted

theorem proof_removal_requires_typed_conviction {e : Engine} {piHash : PIHash}
    {chain now : Word} {s : State} {r : Request} {entry starved tail : Bool}
    {failure : Option Bool}
    (h : fraudProof e piHash chain now s r entry starved tail failure = .removed .invalidProof) :
    ¬ ((s.context.submissions r.submissionId).submittedAtBlock.val + 3600 < now.val) ∧
    verifyFraud e piHash chain s r entry starved failure = .proofInvalid := by
  unfold fraudProof at h
  dsimp only at h
  split at h <;> try contradiction
  split at h <;> try contradiction
  split at h <;> try contradiction
  split at h
  · cases tail <;> simp_all
  · rename_i ht
    refine ⟨ht, ?_⟩
    cases hv : verifyFraud e piHash chain s r entry starved failure <;>
      simp_all

/-! ## Arbitrary-trace provenance, with ghost receipts generated by execution -/

/-- Ghost instrumentation only. It contains data, not a proof of successful
verification; membership's success property is established below. -/
structure Receipt where
  before : State
  request : Request
  tailCommits : Bool

inductive Action where
  | finalize (request : Request) (tailCommits : Bool)
  /-- Projection of non-finalizing operations. It cannot write any finalized
  root or finalized-height field. This is the explicit scope restriction. -/
  | updateContext (context : Context)

def step (e : Engine) (piHash : PIHash) (chain : Word) (s : State) :
    Action → State × List Receipt
  | .updateContext context => ({ s with context }, [])
  | .finalize request tail =>
    match finalize e piHash chain s request tail with
    | none => (s, [])
    | some next => (next, [⟨s, request, tail⟩])

def run (e : Engine) (piHash : PIHash) (chain : Word) (s : State) :
    List Action → State × List Receipt
  | [] => (s, [])
  | action :: rest =>
    let first := step e piHash chain s action
    let later := run e piHash chain first.1 rest
    (later.1, first.2 ++ later.2)

theorem step_height_nondecreasing (e : Engine) (piHash : PIHash) (chain : Word)
    (s : State) (a : Action) :
    s.latestFinalizedBlockNumber.val ≤
      (step e piHash chain s a).1.latestFinalizedBlockNumber.val := by
  cases a with
  | updateContext context => exact Nat.le_refl _
  | finalize request tail =>
    cases hf : finalize e piHash chain s request tail with
    | none => simp [step, hf]
    | some next =>
      have checks := finalize_success_checks hf
      have hheight := (fullVerify_requires_bound_authenticated_pi checks.1.2.2.2.2.2.1).1.1
      simpa [step, hf, checks.2, writeFinalized] using hheight

theorem run_height_nondecreasing (e : Engine) (piHash : PIHash) (chain : Word)
    (s : State) (actions : List Action) :
    s.latestFinalizedBlockNumber.val ≤
      (run e piHash chain s actions).1.latestFinalizedBlockNumber.val := by
  induction actions generalizing s with
  | nil => exact Nat.le_refl _
  | cons action rest ih =>
    exact Nat.le_trans (step_height_nondecreasing e piHash chain s action)
      (ih (step e piHash chain s action).1)

theorem step_finalized_roots_persist {e : Engine} {piHash : PIHash} {chain : Word}
    {s : State} {a : Action} {root : Word} (h : s.isFinalizedStateRoot root = true) :
    (step e piHash chain s a).1.isFinalizedStateRoot root = true := by
  cases a with
  | updateContext context => exact h
  | finalize request tail =>
    cases hf : finalize e piHash chain s request tail with
    | none => simpa [step, hf] using h
    | some next =>
      have heq := (finalize_success_checks hf).2
      simp [step, hf, heq, writeFinalized, h]

theorem run_finalized_roots_persist {e : Engine} {piHash : PIHash} {chain : Word}
    {s : State} {actions : List Action} {root : Word}
    (h : s.isFinalizedStateRoot root = true) :
    (run e piHash chain s actions).1.isFinalizedStateRoot root = true := by
  induction actions generalizing s with
  | nil => exact h
  | cons action _ ih => exact ih (step_finalized_roots_persist h)

theorem step_receipt_success {e : Engine} {piHash : PIHash} {chain : Word}
    {s : State} {a : Action} {receipt : Receipt}
    (h : receipt ∈ (step e piHash chain s a).2) :
    ∃ next, finalize e piHash chain receipt.before receipt.request receipt.tailCommits = some next := by
  cases a with
  | updateContext context => simp [step] at h
  | finalize request tail =>
    cases hf : finalize e piHash chain s request tail with
    | none => simp [step, hf] at h
    | some next =>
      simp [step, hf] at h
      subst receipt
      exact ⟨next, hf⟩

theorem run_receipt_success {e : Engine} {piHash : PIHash} {chain : Word}
    {s : State} {actions : List Action} {receipt : Receipt}
    (h : receipt ∈ (run e piHash chain s actions).2) :
    ∃ next, finalize e piHash chain receipt.before receipt.request receipt.tailCommits = some next := by
  induction actions generalizing s with
  | nil => simp [run] at h
  | cons action rest ih =>
    simp only [run, List.mem_append] at h
    exact h.elim step_receipt_success (fun hlater => ih hlater)

theorem step_root_provenance {e : Engine} {piHash : PIHash} {chain : Word}
    {s : State} {a : Action} {root : Word}
    (h : (step e piHash chain s a).1.isFinalizedStateRoot root = true) :
    s.isFinalizedStateRoot root = true ∨
    ∃ receipt ∈ (step e piHash chain s a).2, receipt.request.stateRoot = root := by
  cases a with
  | updateContext context => exact Or.inl h
  | finalize request tail =>
    cases hf : finalize e piHash chain s request tail with
    | none => exact Or.inl (by simpa [step, hf] using h)
    | some next =>
      have heq := (finalize_success_checks hf).2
      by_cases hr : root = request.stateRoot
      · exact Or.inr ⟨⟨s, request, tail⟩, by simp [step, hf], hr.symm⟩
      · exact Or.inl (by simpa [step, hf, heq, writeFinalized, hr] using h)

theorem run_root_provenance {e : Engine} {piHash : PIHash} {chain : Word}
    {s : State} {actions : List Action} {root : Word}
    (h : (run e piHash chain s actions).1.isFinalizedStateRoot root = true) :
    s.isFinalizedStateRoot root = true ∨
    ∃ receipt ∈ (run e piHash chain s actions).2, receipt.request.stateRoot = root := by
  induction actions generalizing s with
  | nil => exact Or.inl h
  | cons action rest ih =>
    have htail := ih (s := (step e piHash chain s action).1) h
    rcases htail with hfirst | ⟨receipt, hmem, hroot⟩
    · rcases step_root_provenance hfirst with hold | ⟨receipt, hmem, hroot⟩
      · exact Or.inl hold
      · exact Or.inr ⟨receipt, by simp only [run, List.mem_append]; exact Or.inl hmem, hroot⟩
    · exact Or.inr ⟨receipt, by simp only [run, List.mem_append]; exact Or.inr hmem, hroot⟩

/-- The target root alone must be initially unfinalized. Other roots may be
trusted genesis roots, as in the actual constructor. Receipt validity is
obtained from run, not stored as an assumption in the receipt or trace. -/
theorem newly_finalized_requires_verified_receipt {e : Engine} {piHash : PIHash}
    {chain : Word} {s : State} {actions : List Action} {root : Word}
    (hinitial : s.isFinalizedStateRoot root = false)
    (h : (run e piHash chain s actions).1.isFinalizedStateRoot root = true) :
    ∃ receipt ∈ (run e piHash chain s actions).2,
      receipt.request.stateRoot = root ∧
      FinalizationChecks e piHash chain receipt.before receipt.request receipt.tailCommits := by
  rcases run_root_provenance h with hold | ⟨receipt, hmem, hroot⟩
  · rw [hinitial] at hold
    contradiction
  · rcases run_receipt_success hmem with ⟨next, hnext⟩
    exact ⟨receipt, hmem, hroot, (finalize_success_checks hnext).1⟩

/-- Special empty-registry corollary; the generic theorem above also supports
the real constructor's trusted, nonzero genesis root. -/
theorem finalized_from_genesis_requires_verified_receipt {e : Engine} {piHash : PIHash}
    {chain : Word} {s : State} {actions : List Action} {root : Word}
    (hgen : ∀ r, s.isFinalizedStateRoot r = false)
    (h : (run e piHash chain s actions).1.isFinalizedStateRoot root = true) :
    ∃ receipt ∈ (run e piHash chain s actions).2,
      receipt.request.stateRoot = root ∧
      FinalizationChecks e piHash chain receipt.before receipt.request receipt.tailCommits := by
  exact newly_finalized_requires_verified_receipt (hgen root) h

/-- Direct end-to-end control-flow corollary. The DA claim is the exact lookup
tuple, and core acceptance is an observed reply, not a witness-validity axiom. -/
theorem newly_finalized_requires_pinned_core {e : Engine} {piHash : PIHash}
    {chain : Word} {s : State} {actions : List Action} {root : Word}
    (hinitial : s.isFinalizedStateRoot root = false)
    (h : (run e piHash chain s actions).1.isFinalizedStateRoot root = true) :
    ∃ receipt ∈ (run e piHash chain s actions).2,
      receipt.request.stateRoot = root ∧
      daAttested e receipt.before receipt.request = true ∧
      StateBindings receipt.before receipt.request ∧
      ∃ proof,
        e.decodeForCore (e.pins .validity).encodedConfiguration receipt.request.compactProof = .ok proof ∧
        e.coreVerify (e.pins .validity).core (e.pins .validity).encodedConfiguration proof = .accepted ∧
        proof.publicInputs = hashLimbs (piHash receipt.request.pi) := by
  rcases newly_finalized_requires_verified_receipt hinitial h with
    ⟨receipt, hmem, hroot, _⟩
  rcases run_receipt_success hmem with ⟨next, hnext⟩
  exact ⟨receipt, hmem, hroot, finalize_requires_da_and_full_verification hnext⟩

/-- Optional semantic lifting only. Supplying proof-system soundness is an
explicit hypothesis of THIS theorem; none of the control-flow proofs uses it. -/
theorem accepted_witness_only_conditionally {e : Engine} {chain : Word} {purpose : Purpose}
    {bytes : Bytes} {pis : PublicInputs} {Witness : Type}
    (satisfies : PinnedConfig → PublicInputs → Witness → Prop)
    (sound : ∀ proof,
      e.coreVerify (e.pins purpose).core (e.pins purpose).encodedConfiguration proof = .accepted →
      ∃ witness, satisfies (e.pins purpose) proof.publicInputs witness)
    (h : verifyCompactPublicInputs e chain purpose bytes = some pis) :
    ∃ witness, satisfies (e.pins purpose) pis witness := by
  rcases (returned_pi_requires_full_core h).2.2 with ⟨proof, _, hv, hp⟩
  simpa [hp] using sound proof hv

/-! ## Ordinary positive non-vacuity examples (not cryptographic fixtures) -/

private def exampleSubmission : Submission :=
  ⟨1, false, 2, 1, 1, 0⟩

private def exampleState : State :=
  ⟨⟨fun _ => exampleSubmission, fun _ => 0⟩, 0, 0, fun _ => false⟩

private def exampleRequest : Request :=
  ⟨0, 2, ⟨0, 0, 0, 1, 0, 2, 0⟩, []⟩

private def exampleEngine : Engine :=
  { pins := fun _ => ⟨1, 2, 1, []⟩
    configurationAvailable := fun _ => true
    decodeForCore := fun _ _ => .ok ⟨hashLimbs 0, []⟩
    decodeStrict := fun _ _ => .ok ⟨hashLimbs 0, []⟩
    coreVerify := fun _ _ _ => .accepted
    proofHash := fun _ => 0
    attested := fun _ _ _ _ => true }

theorem ordinary_finalization_is_possible :
    finalize exampleEngine (fun _ => 0) 1 exampleState exampleRequest true =
      some (writeFinalized exampleState exampleRequest) := by
  rfl

theorem empty_trace_has_no_receipt (e : Engine) (piHash : PIHash) (chain : Word) (s : State) :
    run e piHash chain s [] = (s, []) := rfl

/-- A constructor-trusted root need not have a receipt. This is why the new-
root theorems require the TARGET root to be initially absent from membership. -/
theorem trusted_initial_root_needs_no_receipt {e : Engine} {piHash : PIHash}
    {chain : Word} {s : State} {root : Word} (h : s.isFinalizedStateRoot root = true) :
    (run e piHash chain s []).1.isFinalizedStateRoot root = true ∧
    (run e piHash chain s []).2 = [] := ⟨h, rfl⟩

theorem ordinary_valid_proof_is_not_fraud :
    fraudProof exampleEngine (fun _ => 0) 1 1 exampleState exampleRequest true false true none =
      .noAction := by decide

/-- Positive timeout-policy case: the proof is still valid, so this event
must NOT be presented as evidence of cryptographic invalidity. -/
theorem timeout_removal_is_separate_policy :
    compactVerdict exampleEngine 1 [] 0 false = .valid ∧
    fraudProof exampleEngine (fun _ => 0) 1 3601 exampleState exampleRequest true false true none =
      .removed .timeout := by decide

end Zkp.Contracts.CurrentVerification
