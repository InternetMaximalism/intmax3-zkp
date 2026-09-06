import Std

/-!
# Blob DA journal and exact source-controlled metadata

Source: contracts/src/BlobKZGVerifier.sol, runtime 05ec7ae.
This source-oriented translation covers the metadata, sidecar length/ordering,
attestation journal, commitment preimages, point-evaluation/SHA result guards
and SimpleCoder payload byte addressing. The SHA/Keccak, blob polynomial,
modexp and EVM memory/CALL/ABI implementation are explicit dependencies.
The evaluation control flow is translated below, including both loops, the
root-hit branch and precompile request parameters. Barycentric interpolation
correctness, field inversion, primitive roots, memory and SHA/KZG soundness are
NOT inferred from translating that control flow.

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

@[simp] theorem result_bind_ok {α β : Type} (x : α) (f : α → Except ε β) :
    ((Except.ok x : Except ε α) >>= f) = f x := rfl
@[simp] theorem result_bind_error {α β : Type} (e : ε) (f : α → Except ε β) :
    ((Except.error e : Except ε α) >>= f) = .error e := rfl
@[simp] theorem result_pure {α : Type} (x : α) : (pure x : Except ε α) = .ok x := rfl

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
  | arithmeticPanic
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

/-! ## Evaluation algorithm and typed precompile observations

Nat is used for mathematical EVM words. ADDMOD/MULMOD are unbounded arithmetic
then modulus, as specified for those opcodes, not wrapped ADD/MUL. Memory loads
are supplied as an indexed blob; actual mstore/calldataload/shifts and allocation
remain an assembly refinement obligation. `scalarBlob` below is the intended
byte-lane content, not a claim that the EVM has already written those lanes.
-/

def rootOfUnity : Nat :=
  0x564c0a11a0f704f4fc3e8acfe0f8245f0ad1347b378fbf96e206da11a5d36306
def rootOfUnityInv : Nat :=
  0x0391b2856c609b4784ae25ffab9dc59865046d17864183203961a252dd8543362
def inverseWidth : Nat :=
  0x73e66878b46ae3705eb6a46a89213de7d3686828bfce5c19400fffff00100001
def challengePrefix : Nat :=
  0x4653424c4f425645524946595f56315f00000000000000000000000000001000
def challengeInputLength : Nat := 0x20050
def reverseNibbles : Nat := 0xf7b3d591e6a2c480
def pointGas : Nat := 50000
def mulmod (a b : Nat) : Nat := (a * b) % blsModulus
def addmod (a b : Nat) : Nat := (a + b) % blsModulus
def reverseNibble (x : Nat) : Nat := (reverseNibbles >>> ((x &&& 15) * 4)) &&& 15
def bitReverse12 (x : Nat) : Nat :=
  ((reverseNibble x) <<< 8) ||| ((reverseNibble (x >>> 4)) <<< 4) ||| reverseNibble (x >>> 8)

abbrev Blob := Nat → Nat

def scalarBlob (proof : Bytes) (blobIndex localIndex : Nat) : Nat :=
  if blobIndex = 0 ∧ localIndex = 0 then (proof.length * 2 ^ 184) % 2 ^ 256
  else (List.range 31).foldl
    (fun acc lane => acc * 256 + (proof.getD ((blobIndex * 4096 + localIndex - 1) * 31 + lane) zeroByte).val) 0

structure WordReply where
  ok : Bool
  size : Nat
  word : Word

inductive PrecompileRequest where
  | challengeSha (prefixWord inputLength : Nat) (blob : Blob) (commitment : Bytes)
  | commitmentSha (commitment : Bytes)
  | modexp (baseLength exponentLength modulusLength base exponent modulus : Nat)

abbrev WordPrecompile := PrecompileRequest → WordReply

def checkedSha (reply : WordReply) : Except Failure Word :=
  shaResult reply.ok reply.size reply.word

def modexp (call : WordPrecompile) (base exponent : Nat) : Except Failure Nat :=
  let reply := call (.modexp 32 32 32 base exponent blsModulus)
  if reply.ok && reply.size == 32 then .ok reply.word.val else .error .modexpFailed

def versionedHash (call : WordPrecompile) (commitment : Bytes) : Except Failure Word := do
  let digest ← checkedSha (call (.commitmentSha commitment))
  let value := (digest.val % 2 ^ 248) + 2 ^ 248
  pure ⟨value, by have h := Nat.mod_lt digest.val (show 0 < 2 ^ 248 by decide); omega⟩

inductive ScanResult where
  | atRoot (value : Nat)
  | denominators (product : Nat) (prefixes : Nat → Nat)

/-- Forward loop: the early root return occurs before reading a prefix or
    invoking modexp. Prefixes contain products BEFORE the current denominator. -/
def scanDenominators (blob : Blob) (z : Nat) :
    Nat → Nat → Nat → Nat → (Nat → Nat) → Except Failure ScanResult
  | 0, _, product, _, prefixes => .ok (.denominators product prefixes)
  | fuel + 1, i, product, omega, prefixes =>
    if z = omega then .ok (.atRoot (blob (bitReverse12 i)))
    else if blsModulus < omega then .error .arithmeticPanic
    else scanDenominators blob z fuel (i + 1)
      (mulmod product (addmod z (blsModulus - omega))) (mulmod omega rootOfUnity)
      (fun index => if index = i then product else prefixes index)

/-- Reverse loop: decrement precedes array access, inverse-product update
    follows the summand, and the first omega is ROOT_OF_UNITY_INV. -/
def sumDenominators (blob : Blob) (z : Nat) (prefixes : Nat → Nat) :
    Nat → Nat → Nat → Nat → Except Failure Nat
  | 0, _, _, sum => .ok sum
  | cursor + 1, inverseProduct, omega, sum =>
    if blsModulus < omega then .error .arithmeticPanic
    else
      let denominator := addmod z (blsModulus - omega)
      let inverseDenominator := mulmod inverseProduct (prefixes cursor)
      let value := blob (bitReverse12 cursor)
      let nextSum := addmod sum (mulmod (mulmod value omega) inverseDenominator)
      sumDenominators blob z prefixes cursor (mulmod inverseProduct denominator)
        (mulmod omega rootOfUnityInv) nextSum

def repeatedSquare : Nat → Nat → Nat
  | 0, z => z
  | n + 1, z => repeatedSquare n (mulmod z z)

def evaluateBlob (call : WordPrecompile) (blob : Blob) (z : Nat) : Except Failure Nat := do
  let scan ← scanDenominators blob z 4096 0 1 1 (fun _ => 0)
  match scan with
  | .atRoot value => pure value
  | .denominators product prefixes => do
    let inverseProduct ← modexp call product (blsModulus - 2)
    let sum ← sumDenominators blob z prefixes 4096 inverseProduct rootOfUnityInv 0
    let scale := mulmod (addmod (repeatedSquare 12 z) (blsModulus - 1)) inverseWidth
    pure (mulmod sum scale)

structure Evaluation where
  versioned : Word
  z : Nat
  y : Nat

def blobEvaluation (call : WordPrecompile) (blob : Blob) (commitment : Bytes) :
    Except Failure Evaluation := do
  let digest ← checkedSha (call (.challengeSha challengePrefix challengeInputLength blob commitment))
  let z := digest.val % blsModulus
  let y ← evaluateBlob call blob z
  let versioned ← versionedHash call commitment
  pure ⟨versioned, z, y⟩

structure PointRequest where
  gas : Nat
  address : Nat
  inputLength : Nat
  outputLength : Nat
  versioned : Word
  z : Nat
  y : Nat
  commitment : Bytes
  proof : Bytes

def verifyBlobBody (call : WordPrecompile) (point : PointRequest → PointReply)
    (proof : Bytes) (index : Nat) (sidecar : Sidecar) : Except Failure Word := do
  let e ← blobEvaluation call (scalarBlob proof index) sidecar.commitment
  let reply := point ⟨pointGas, 10, 192, 64, e.versioned, e.z, e.y, sidecar.commitment, sidecar.proof⟩
  pointEvaluationResult index reply
  pure e.versioned

def verifyConcrete (call : WordPrecompile) (point : PointRequest → PointReply)
    (proof sidecars : Bytes) : Except Failure Metadata :=
  verify (verifyBlobBody call point) proof sidecars

def attestConcrete (call : WordPrecompile) (point : PointRequest → PointReply)
    (hash : Hash) (journal : Journal) (rollup : Address) (id : Word)
    (getContext : GetContext) (proof sidecars : Bytes) : Except Failure AttestationResult :=
  attestProofData hash (verifyBlobBody call point) journal rollup id getContext proof sidecars

theorem concrete_verifier_uses_evaluation_body (call : WordPrecompile)
    (point : PointRequest → PointReply) (proof sidecars : Bytes) :
    verifyConcrete call point proof sidecars = verify (verifyBlobBody call point) proof sidecars := rfl

theorem root_constants_are_canonical :
    0 < blsModulus ∧ rootOfUnity < blsModulus ∧ rootOfUnityInv < blsModulus ∧
      inverseWidth < blsModulus := by decide

theorem mulmod_is_canonical (a b : Nat) : mulmod a b < blsModulus :=
  Nat.mod_lt _ root_constants_are_canonical.1

theorem addmod_is_canonical (a b : Nat) : addmod a b < blsModulus :=
  Nat.mod_lt _ root_constants_are_canonical.1

theorem root_scan_returns_exact_value (blob : Blob) (fuel i product omega : Nat)
    (prefixes : Nat → Nat) :
    scanDenominators blob omega (fuel + 1) i product omega prefixes =
      .ok (.atRoot (blob (bitReverse12 i))) := by simp [scanDenominators]

theorem evaluation_at_one_skips_precompiles (call : WordPrecompile) (blob : Blob) :
    evaluateBlob call blob 1 = .ok (blob 0) := by
  rw [evaluateBlob, root_scan_returns_exact_value]
  rfl

theorem modexp_exact_call_and_reply (call : WordPrecompile) (base exponent result : Nat)
    (h : modexp call base exponent = .ok result) :
    let reply := call (.modexp 32 32 32 base exponent blsModulus)
    reply.ok = true ∧ reply.size = 32 ∧ result = reply.word.val := by
  dsimp only [modexp] at h
  split at h <;> try contradiction
  rename_i accepted
  simp only [Bool.and_eq_true, beq_iff_eq] at accepted
  exact ⟨accepted.1, accepted.2, (Except.ok.inj h).symm⟩

theorem repeated_square_step (n z : Nat) :
    repeatedSquare (n + 1) z = repeatedSquare n (mulmod z z) := rfl

theorem root_has_power_of_two_order :
    repeatedSquare 12 rootOfUnity = 1 ∧ repeatedSquare 11 rootOfUnity ≠ 1 := by decide

theorem inverse_constants_check :
    mulmod rootOfUnity rootOfUnityInv = 1 ∧ mulmod 4096 inverseWidth = 1 := by decide

theorem reverse_nibble_table :
    (List.range 16).map reverseNibble = [0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15] := by decide

set_option maxHeartbeats 4000000 in
theorem bit_reverse_three_nibbles :
    ∀ high middle low : Fin 16,
      bitReverse12 (bitReverse12 (high.val * 256 + middle.val * 16 + low.val)) =
        high.val * 256 + middle.val * 16 + low.val := by decide

theorem bit_reverse_involutive_on_blob_indices (index : Fin 4096) :
    bitReverse12 (bitReverse12 index.val) = index.val := by
  have range := index.isLt
  have highBound : index.val / 256 < 16 := by omega
  have expansion : index.val / 256 * 256 + index.val / 16 % 16 * 16 + index.val % 16 = index.val := by omega
  have reversed := bit_reverse_three_nibbles ⟨index.val / 256, highBound⟩
    ⟨index.val / 16 % 16, Nat.mod_lt _ (by decide)⟩ ⟨index.val % 16, Nat.mod_lt _ (by decide)⟩
  simpa only [expansion] using reversed

theorem challenge_length_exact : challengeInputLength = 32 + 4096 * 32 + 48 := by decide

theorem simple_coder_header (proof : Bytes) :
    scalarBlob proof 0 0 = (proof.length * 2 ^ 184) % 2 ^ 256 := by simp [scalarBlob]

theorem versioned_hash_prefix (call : WordPrecompile) (commitment : Bytes) (out : Word)
    (h : versionedHash call commitment = .ok out) :
    2 ^ 248 ≤ out.val ∧ out.val < 2 * 2 ^ 248 := by
  unfold versionedHash at h
  cases sha : checkedSha (call (.commitmentSha commitment)) with
  | error e => simp [sha, Except.bind] at h
  | ok digest =>
    simp [sha, Except.bind] at h
    subst out
    have bound := Nat.mod_lt digest.val (show 0 < 2 ^ 248 by decide)
    simp only []
    omega

end Zkp.Implementation.BlobJournal
