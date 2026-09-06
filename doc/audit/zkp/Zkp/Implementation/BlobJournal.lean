import Std

/-!
# Blob DA journal and exact source-controlled metadata

Source: contracts/src/BlobKZGVerifier.sol, runtime 05ec7ae.
This source-oriented translation covers the metadata, sidecar length/ordering,
attestation journal, commitment preimages, point-evaluation/SHA result guards
and SimpleCoder payload byte addressing. The SHA/Keccak, blob polynomial,
modexp and EVM memory/CALL/ABI implementation are explicit dependencies.
The line map marks the untranscribed polynomial/assembly loops UNTRANSLATED;
their existence is not hidden behind an assumption claiming overall DA safety.

The accepted KZG ceremony is not challenged here. It does not by itself prove
that a handwritten SimpleCoder/evaluation implementation follows the ceremony's
polynomial convention. These local results do not prove KZG/DA soundness.

No authenticity/injectivity is assumed for the executable journal properties.
Consequently a zero hash can compare equal to an empty entry, exactly as the
source lookup does. The stronger observation-to-receipt conclusion explicitly
requires a nonzero digest. Do not turn this interface theorem into a claim that
an arbitrary caller-chosen hash implies published or available proof bytes.
-/

namespace Zkp.Implementation.BlobJournal

abbrev Word := Fin (2 ^ 256)
abbrev Address := Fin (2 ^ 160)
abbrev BlockNumber := Fin (2 ^ 64)
abbrev Byte := Fin 256
abbrev Bytes := List Byte

def zeroWord : Word := ⟨0, by decide⟩
def zeroByte : Byte := ⟨0, by decide⟩
def fieldElements : Nat := 4096
def oneCapacity : Nat := (4096 - 1) * 31
def twoCapacity : Nat := (2 * 4096 - 1) * 31
def blsModulus : Nat :=
  0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001

inductive Failure where
  | emptyProof
  | proofTooLarge (length : Nat)
  | blobCountMismatch (expected supplied : Nat)
  | missingBlob (index : Nat)
  | extraBlob (index : Nat)
  | sidecarLength (expected actual : Nat)
  | shaFailed
  | modexpFailed
  | pointFailed (index : Nat)
  | pointResult (index : Nat)
  | invalidContext
  | abiDecodeReverted
  | unavailable
  | commitmentMismatch
  | conflictingAttestation
  | dependencyFailed
  deriving DecidableEq, Repr

/-- _blobCount:439–444; Nat is the mathematical value of the source uint256. -/
def blobCount (length : Nat) : Except Failure Nat :=
  if length = 0 then .error .emptyProof
  else if length ≤ oneCapacity then .ok 1
  else if length ≤ twoCapacity then .ok 2
  else .error (.proofTooLarge length)

structure Metadata where
  hash0 : Word
  hash1 : Word
  count : Nat
  deriving DecidableEq, Repr

/-- BLOBHASH is an environment observation, not a caller-provided commitment. -/
abbrev BlobHash := Nat → Word

/-- Preserve the actual early return at hash1=0. Contiguous BLOBHASH indices
    are an EVM dependency, not an additional source-level check on hash2. -/
def postedBlobMetadata (hash : BlobHash) : Except Failure Metadata :=
  if hash 0 = zeroWord then .error (.missingBlob 0)
  else if hash 1 = zeroWord then .ok ⟨hash 0, zeroWord, 1⟩
  else if hash 2 ≠ zeroWord then .error (.extraBlob 2)
  else .ok ⟨hash 0, hash 1, 2⟩

def blobMetadata (length : Nat) (hash : BlobHash) : Except Failure Metadata := do
  let count ← blobCount length
  if hash 0 = zeroWord then throw (.missingBlob 0)
  if count = 1 then
    if hash 1 ≠ zeroWord then throw (.extraBlob 1)
  else
    if hash 1 = zeroWord then throw (.missingBlob 1)
    if hash 2 ≠ zeroWord then throw (.extraBlob 2)
  return ⟨hash 0, hash 1, count⟩

/-- Explicit ABI preimage roles, including the source's two distinct domains. -/
inductive HashInput where
  | proofBytes (bytes : Bytes)
  | proofAttestationDomain
  | proofDaDomain
  | proofDigest (domain proofHash : Word) (length : Nat)
  | journalKey (rollup : Address) (submissionId commitment : Word)
  | submission (domain : Word) (metadata : Metadata) (stateRoot : Word)
      (submittedAt : BlockNumber) (submissionId : Word)

abbrev Hash := HashInput → Word

def proofDigest (hash : Hash) (proofHash : Word) (length : Nat) : Word :=
  hash (.proofDigest (hash .proofAttestationDomain) proofHash length)

def journalKey (hash : Hash) (rollup : Address) (id commitment : Word) : Word :=
  hash (.journalKey rollup id commitment)

def commitment (hash : Hash) (metadata : Metadata) (root : Word)
    (atBlock : BlockNumber) (id : Word) : Word :=
  hash (.submission (hash .proofDaDomain) metadata root atBlock id)

def postCommitment (hash : Hash) (blobs : BlobHash) (root : Word)
    (atBlock : BlockNumber) (id : Word) : Except Failure Word := do
  let meta ← postedBlobMetadata blobs
  return commitment hash meta root atBlock id

structure Sidecar where
  commitment : Bytes
  proof : Bytes

def sidecarAt (bytes : Bytes) (index : Nat) : Sidecar :=
  ⟨(bytes.drop (index * 96)).take 48, (bytes.drop (index * 96 + 48)).take 48⟩

/-- Opaque _blobEvaluation/_pointEvaluation dependency. Its argument contains
    the exact full proof stream, index and sliced commitment/proof, not metadata. -/
abbrev VerifyBlob := Bytes → Nat → Sidecar → Except Failure Word

def verify (verifyBlob : VerifyBlob) (proof sidecars : Bytes) :
    Except Failure Metadata := do
  let count ← blobCount proof.length
  let expected := count * 96
  if sidecars.length ≠ expected then throw (.sidecarLength expected sidecars.length)
  let hash0 ← verifyBlob proof 0 (sidecarAt sidecars 0)
  let hash1 ← if count = 2 then verifyBlob proof 1 (sidecarAt sidecars 1) else pure zeroWord
  return ⟨hash0, hash1, count⟩

def verifyAndCommit (hash : Hash) (verifyBlob : VerifyBlob) (proof sidecars : Bytes)
    (root : Word) (atBlock : BlockNumber) (id : Word) : Except Failure Word := do
  let meta ← verify verifyBlob proof sidecars
  return commitment hash meta root atBlock id

structure SubmissionContext where
  commitment : Word
  producer : Address
  finalized : Bool
  submittedAt : BlockNumber
  root : Word

structure ContextReply where
  ok : Bool
  byteLength : Nat
  decoded : Option SubmissionContext

/-- The staticcall target, getSubmission selector role and exact ID are fixed
    by this typed request. ABI selector bytes/encoding remain a dependency. -/
inductive ContextRequest where
  | getSubmission (rollup : Address) (submissionId : Word)

abbrev GetContext := ContextRequest → ContextReply

def readContext (reply : ContextReply) : Except Failure SubmissionContext :=
  if !reply.ok || reply.byteLength != 160 then .error .invalidContext
  else match reply.decoded with
  | none => .error .abiDecodeReverted
  | some context =>
    if context.commitment = zeroWord || context.finalized then .error .unavailable
    else .ok context

abbrev Journal := Word → Word
def emptyJournal : Journal := fun _ => zeroWord

def put (journal : Journal) (key value : Word) : Journal :=
  fun k => if k = key then value else journal k

/-- No global assertion that zero is impossible: mirror the exact source test. -/
def record (journal : Journal) (key digest : Word) : Except Failure Journal :=
  if journal key ≠ zeroWord && journal key ≠ digest then .error .conflictingAttestation
  else .ok (put journal key digest)

structure AttestedEvent where
  rollup : Address
  submissionId : Word
  commitment : Word
  digest : Word
  proofHash : Word
  proofLength : Nat

structure AttestationResult where
  journal : Journal
  returnedDigest : Word
  event : AttestedEvent

def attestProofData (hash : Hash) (verifyBlob : VerifyBlob) (journal : Journal)
    (rollup : Address) (id : Word) (getContext : GetContext) (proof sidecars : Bytes) :
    Except Failure AttestationResult := do
  let context ← readContext (getContext (.getSubmission rollup id))
  let opened ← verifyAndCommit hash verifyBlob proof sidecars context.root context.submittedAt id
  if opened ≠ context.commitment then throw .commitmentMismatch
  let bytesHash := hash (.proofBytes proof)
  let digest := proofDigest hash bytesHash proof.length
  let key := journalKey hash rollup id context.commitment
  let next ← record journal key digest
  return ⟨next, digest, ⟨rollup, id, context.commitment, digest, bytesHash, proof.length⟩⟩

def isProofDataAttested (hash : Hash) (journal : Journal) (caller : Address)
    (id comm proofHash : Word) (length : Nat) : Bool :=
  journal (journalKey hash caller id comm) == proofDigest hash proofHash length

/-- Source's call outputs must have the exact observed returndata size. -/
structure PointReply where
  ok : Bool
  byteLength : Nat
  outElements : Nat
  outModulus : Nat

def pointEvaluationResult (index : Nat) (reply : PointReply) : Except Failure Unit :=
  if !reply.ok || reply.byteLength != 64 then .error (.pointFailed index)
  else if reply.outElements != 4096 || reply.outModulus != blsModulus
    then .error (.pointResult index)
  else .ok ()

def shaResult (ok : Bool) (size : Nat) (digest : Word) : Except Failure Word :=
  if ok && size == 32 then .ok digest else .error .shaFailed

/-- Byte-lane projection of _fillSimpleCoderBlob. The length header occupies
    global FE zero; payload lanes are 31 bytes per subsequent FE, zero-padded.
    Assembly word shifts/calldata slice bounds require separate refinement. -/
def payloadByte (proof : Bytes) (globalField : Nat) (lane : Fin 31) : Byte :=
  proof.getD ((globalField - 1) * 31 + lane.val) zeroByte

def decodedPayloadByte (proof : Bytes) (offset : Nat) : Byte :=
  payloadByte proof (offset / 31 + 1) ⟨offset % 31, Nat.mod_lt _ (by decide)⟩

theorem source_payload_index_roundtrip (offset : Nat) :
    (offset / 31 + 1 - 1) * 31 + offset % 31 = offset := by
  simpa [Nat.mul_comm] using Nat.div_add_mod offset 31

theorem payload_addressing_is_lossless (proof : Bytes) (offset : Nat) :
    decodedPayloadByte proof offset = proof.getD offset zeroByte := by
  change proof.getD ((offset / 31 + 1 - 1) * 31 + offset % 31) zeroByte =
    proof.getD offset zeroByte
  rw [source_payload_index_roundtrip]

theorem blobCount_only_one_or_two {length count : Nat} (h : blobCount length = .ok count) :
    count = 1 ∨ count = 2 := by
  unfold blobCount at h
  split at h <;> try contradiction
  split at h
  · exact Or.inl (Except.ok.inj h).symm
  · split at h
    · exact Or.inr (Except.ok.inj h).symm
    · contradiction

theorem blobCount_length_bounded {length count : Nat} (h : blobCount length = .ok count) :
    0 < length ∧ length ≤ twoCapacity := by
  unfold blobCount at h
  split at h <;> try contradiction
  rename_i positive
  split at h
  · rename_i bound
    exact ⟨Nat.pos_of_ne_zero positive, Nat.le_trans bound (by decide)⟩
  · split at h
    · exact ⟨Nat.pos_of_ne_zero positive, by assumption⟩
    · contradiction

theorem blobCount_empty_rejected : blobCount 0 = .error .emptyProof := by rfl
theorem example_one_blob_boundary : blobCount oneCapacity = .ok 1 := by rfl
theorem example_two_blob_boundary : blobCount (oneCapacity + 1) = .ok 2 := by rfl
theorem example_max_blob_boundary : blobCount twoCapacity = .ok 2 := by rfl
theorem example_oversize_rejected :
    blobCount (twoCapacity + 1) = .error (.proofTooLarge (twoCapacity + 1)) := by rfl

theorem record_sets_exact_key {journal next : Journal} {key digest : Word}
    (h : record journal key digest = .ok next) : next key = digest := by
  unfold record at h
  split at h <;> try contradiction
  cases h
  simp [put]

theorem record_frames_other_key {journal next : Journal} {key other digest : Word}
    (h : record journal key digest = .ok next) (different : other ≠ key) :
    next other = journal other := by
  unfold record at h
  split at h <;> try contradiction
  cases h
  simp [put, different]

theorem nonzero_record_cannot_be_replaced {journal next : Journal} {key digest prior : Word}
    (known : journal key = prior) (nonzero : prior ≠ zeroWord)
    (h : record journal key digest = .ok next) : digest = prior := by
  unfold record at h
  by_cases same : prior = digest
  · exact same.symm
  · simp [known, nonzero, same] at h

theorem exact_record_retry_accepted (journal : Journal) (key digest : Word)
    (known : journal key = digest) :
    record journal key digest = .ok (put journal key digest) := by
  simp [record, known]

inductive RecordTrace : Journal → Journal → Prop where
  | nil (s) : RecordTrace s s
  | step {s mid final key digest} : record s key digest = .ok mid →
      RecordTrace mid final → RecordTrace s final

theorem nonzero_record_survives_trace {s final : Journal} {key prior : Word}
    (trace : RecordTrace s final) (known : s key = prior) (nonzero : prior ≠ zeroWord) :
    final key = prior := by
  induction trace with
  | nil => exact known
  | @step s mid _ touched digest step _ ih =>
    apply ih
    by_cases same : key = touched
    · subst touched
      rw [record_sets_exact_key step]
      exact nonzero_record_cannot_be_replaced known nonzero step
    · rw [record_frames_other_key step same]
      exact known

theorem lookup_binds_caller_namespace {hash : Hash} {journal : Journal}
    {caller : Address} {id comm proofHash : Word} {length : Nat}
    (h : isProofDataAttested hash journal caller id comm proofHash length = true) :
    journal (journalKey hash caller id comm) = proofDigest hash proofHash length := by
  simpa [isProofDataAttested] using h

theorem absent_nonzero_digest_not_attested {hash : Hash} {caller : Address}
    {id comm proofHash : Word} {length : Nat}
    (nonzero : proofDigest hash proofHash length ≠ zeroWord) :
    isProofDataAttested hash emptyJournal caller id comm proofHash length = false := by
  simp [isProofDataAttested, emptyJournal, Ne.symm nonzero]

theorem point_acceptance_requires_exact_reply {index : Nat} {r : PointReply}
    (h : pointEvaluationResult index r = .ok ()) :
    r.ok = true ∧ r.byteLength = 64 ∧ r.outElements = 4096 ∧ r.outModulus = blsModulus := by
  unfold pointEvaluationResult at h
  split at h <;> try contradiction
  rename_i callOk
  split at h <;> try contradiction
  rename_i fields
  simp only [Bool.or_eq_true, Bool.not_eq_true', bne_iff_ne, not_or] at callOk fields
  have ok : r.ok = true := by cases eq : r.ok <;> simp_all
  exact ⟨ok, by omega, by omega, by omega⟩

theorem sha_acceptance_requires_exact_reply {ok : Bool} {size : Nat} {digest result : Word}
    (h : shaResult ok size digest = .ok result) : ok = true ∧ size = 32 ∧ result = digest := by
  unfold shaResult at h
  split at h <;> try contradiction
  rename_i conditions
  simp only [Bool.and_eq_true, beq_iff_eq] at conditions
  exact ⟨conditions.1, conditions.2, (Except.ok.inj h).symm⟩

end Zkp.Implementation.BlobJournal
