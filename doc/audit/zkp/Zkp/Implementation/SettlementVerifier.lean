import Std

/-!
# Function-level translation of ChannelSettlementVerifier.sol

Source: parent runtime 05ec7ae, contracts/src/ChannelSettlementVerifier.sol (959 lines).
This is a hand-written executable translation, NOT Solidity compiler/EVM refinement.
All source function bodies have a corresponding definition. Successful ABI decoding
supplies bounded Solidity values; returned PI words remain arbitrary Nat until checked.
External view/static calls, extcodesize, chain identity, ABI decoding and Keccak are
explicit environment boundaries. The model proves their use, not their truth or
cryptographic soundness. Return-data ABI decoder failures can be external-call
failures. Resource limits, gas, allocation/OOG (including pure internal computation)
are omitted resource/refinement boundaries, not a proved interpreter or modeled calls.

Important source distinctions preserved:
* adapters need code and correct chain IDs; the constructor does not itself prove
  expected bytecode/VK/config hashes. Same-slot adapter = core is allowed.
* bindCloseIntentPublicInputs is public and unauthenticated by itself; only the
  verify entry point composes the pinned adapter call. Manager composition is external.
* value-authorizing endpoints return true or revert, never false on malformed PI.
* special/late digest ABI stubs still return a Bool; their Manager callers disable
  authority. They are NOT silently translated as reverts or as ZK verification.
* closeMemberSetCommitment masks inactive padding itself but has no 1..8 count
  rejection. tokenFundsDigest checks 1..10 and hashes ALL ten lanes, including padding.
* legacy comments 446..451 describe deferred decryption; they are not executable
  semantics. Proving plaintext/recipient ownership belongs to the claim circuits.

Unsigned integer casts after successful ABI decoding are lossless except explicit
word extraction. Big-endian bytes/words below use division and modulus, a mathematical
translation of shift/mask, not a theorem about compiled bitwise bytecode. Every actual
PI comparison is exact equality of the unmasked returned word, with u32 range first.
-/

namespace Zkp.Implementation.SettlementVerifier

abbrev U8 := Fin (2 ^ 8)
abbrev U32 := Fin (2 ^ 32)
abbrev U64 := Fin (2 ^ 64)
abbrev U160 := Fin (2 ^ 160)
abbrev U256 := Fin (2 ^ 256)
abbrev Address := U160
abbrev Bytes := List Nat
abbrev Limbs := List Nat

def limbBound : Nat := 2 ^ 32
def closePiLen : Nat := 103
def withdrawalPiLen : Nat := 50
def cancelPiLen : Nat := 29
def postClosePiLen : Nat := 57
def maxSigCluster : Nat := 8
def maxParticipants : Nat := 1024
def maxTokens : Nat := 10
def closeStateDomain : Nat := 0x494d4353
def specialDomain : Nat := 0x494d5343
def cancelDomain : Nat := 0x494d434e
def lateDomain : Nat := 0x494d4c44
def memberDomain : Nat := 0x494d434d
def tokenFundsDomain : Nat := 0x494d5446

inductive Fault where
  | invalidPinned (verifier : Address)
  | wrongChain (verifier : Address) (expected actual : U256)
  | duplicatePinned
  | tokenCount
  | delegateCount
  | closePiLength | closeExpectedLength | closeLimbRange | closeLimbMismatch
  | claimPiLength | claimLimbRange | claimLimbMismatch
  | externalCall (payload : Bytes)
  deriving DecidableEq, Repr

abbrev Result := Except Fault

/-- The four signatures of contracts/src/IPinnedMleVerifierV2.sol. The interface
    itself has no executable implementation or soundness guarantee. ABI decoding,
    byte-level selectors and EVM STATICCALL are separate dependencies. In
    particular uint8 fraudVerdict permits all 256 values at the ABI boundary;
    meanings of those values are imposed by the consuming Rollup, not here. -/
structure PinnedInterface where
  allowedChainId : Except Bytes U256
  core : Except Bytes Address
  verifyCompactPublicInputs : Bytes → Except Bytes Limbs
  fraudVerdictCompact : Bytes → U256 → Except Bytes U8

/-- Exact external call results, including failure; no `accepted implies sound` premise. -/
structure EvmView where
  chainId : U256
  codeSize : Address → Nat
  allowedChainId : Address → Except Bytes U256
  core : Address → Except Bytes Address
  verifyCompactPublicInputs : Address → Bytes → Except Bytes Limbs

structure Adapters where
  close : Address
  withdrawal : Address
  postClose : Address
  cancel : Address
  deriving DecidableEq, Repr

def Adapters.list (a : Adapters) : List Address := [a.close, a.withdrawal, a.postClose, a.cancel]

structure Installed where
  adapters : Adapters
  cores : Adapters
  deriving DecidableEq, Repr

/-- Source 145..173: catch target is adapter for core() failure, core for its chain getter failure. -/
def requirePinnedVerifier (evm : EvmView) (adapter : Address) : Result Address :=
  if evm.codeSize adapter = 0 then .error (.invalidPinned adapter)
  else match evm.allowedChainId adapter with
    | .error _ => .error (.invalidPinned adapter)
    | .ok chain =>
      if chain ≠ evm.chainId then .error (.wrongChain adapter evm.chainId chain)
      else match evm.core adapter with
        | .error _ => .error (.invalidPinned adapter)
        | .ok core =>
          if evm.codeSize core = 0 then .error (.invalidPinned adapter)
          else match evm.allowedChainId core with
            | .error _ => .error (.invalidPinned core)
            | .ok coreChain =>
              if coreChain ≠ evm.chainId then .error (.wrongChain core evm.chainId coreChain)
              else .ok core

/-- Six adapter comparisons are performed before any external call. -/
def distinctAdapters (a : Adapters) : Bool := decide
  (a.close ≠ a.withdrawal ∧ a.close ≠ a.postClose ∧ a.close ≠ a.cancel ∧
   a.withdrawal ≠ a.postClose ∧ a.withdrawal ≠ a.cancel ∧ a.postClose ≠ a.cancel)

def adapterAt (a : Adapters) : Fin 4 → Address
  | ⟨0, _⟩ => a.close
  | ⟨1, _⟩ => a.withdrawal
  | ⟨2, _⟩ => a.postClose
  | _ => a.cancel

/-- Source nested loops, in i-major then j-major order. Same pair is excluded. -/
def isolatedPairs (a cores : Adapters) : Bool :=
  ([0, 1, 2, 3] : List (Fin 4)).all fun i => ([0, 1, 2, 3] : List (Fin 4)).all fun j =>
    decide (i = j ∨ (adapterAt cores i ≠ adapterAt cores j ∧ adapterAt a i ≠ adapterAt cores j))

def finishConstructor (a cores : Adapters) : Result Installed :=
  if isolatedPairs a cores then .ok ⟨a, cores⟩ else .error .duplicatePinned

def constructor (evm : EvmView) (a : Adapters) : Result Installed :=
  if !distinctAdapters a then .error .duplicatePinned
  else match requirePinnedVerifier evm a.close with
    | .error e => .error e
    | .ok close => match requirePinnedVerifier evm a.withdrawal with
      | .error e => .error e
      | .ok withdrawal => match requirePinnedVerifier evm a.postClose with
        | .error e => .error e
        | .ok postClose => match requirePinnedVerifier evm a.cancel with
          | .error e => .error e
          | .ok cancel => finishConstructor a ⟨close, withdrawal, postClose, cancel⟩

/-- Fixed-width big-endian byte stream. Nat identifiers here are actual byte values. -/
def beBytes : Nat → Nat → Bytes
  | 0, _ => []
  | n + 1, value => (value / 256 ^ n % 256) :: beBytes n value

def word (value exponent : Nat) : Nat := value / limbBound ^ exponent % limbBound
def putU64 (v : U64) : Limbs := [v.val / limbBound, v.val % limbBound]
def putUint256 (v : U256) : Limbs :=
  [word v.val 7, word v.val 6, word v.val 5, word v.val 4,
   word v.val 3, word v.val 2, word v.val 1, word v.val 0]
def putBytes32 (v : U256) : Limbs := putUint256 v
def putAddress (v : Address) : Limbs :=
  [word v.val 4, word v.val 3, word v.val 2, word v.val 1, word v.val 0]

/-- Hashing is a boundary function, not assumed injective and not an ownership oracle. -/
abbrev Keccak := Bytes → U256

def tenList {α : Type} (f : Fin 10 → α) : List α :=
  [f 0, f 1, f 2, f 3, f 4, f 5, f 6, f 7, f 8, f 9]

def eightList {α : Type} (f : Fin 8 → α) : List α :=
  [f 0, f 1, f 2, f 3, f 4, f 5, f 6, f 7]

structure CloseFields where
  channelId : U32
  closeNonce : U64
  finalEpoch : U64
  finalSmallBlockNumber : U64
  closeFreezeNonce : U64
  finalChannelStateDigest : U256
  finalBalanceStateH1 : U256
  channelFundAmounts : Fin 10 → U256
  channelFundIntmaxStateRoot : U256
  burnTxHash : U256
  closeWithdrawalDigest : U256
  snapshotMediumBlockNumber : U64
  finalStateVersion : U64
  finalSettledTxChain : U256
  finalSettledTxAccumulatorRoot : U256
  memberSetCommitment : U256
  memberCount : U8
  minDelegateCount : U32
  tokenRegistry : Fin 10 → U32
  tokenCount : U8

def tokenFundsPreimage (registry : Fin 10 → U32) (count : U8) (amounts : Fin 10 → U256) : Bytes :=
  beBytes 4 tokenFundsDomain ++ (tenList fun i => beBytes 4 (registry i).val).join ++
  beBytes 4 count.val ++ (tenList fun i => beBytes 32 (amounts i).val).join

def tokenFundsDigest (hash : Keccak) (registry : Fin 10 → U32) (count : U8)
    (amounts : Fin 10 → U256) : Result U256 :=
  if count.val = 0 ∨ count.val > 10 then .error .tokenCount
  else .ok (hash (tokenFundsPreimage registry count amounts))

def closeIntentPreimage (f : CloseFields) : Bytes :=
  beBytes 4 closeStateDomain ++ beBytes 4 f.channelId.val ++
  beBytes 32 f.finalChannelStateDigest.val ++ beBytes 8 f.closeFreezeNonce.val

def closeIntentDigest (hash : Keccak) (f : CloseFields) : U256 := hash (closeIntentPreimage f)

/-- Source c cursor/order transcribed verbatim; slot zero amount is not the full TFD. -/
def closeLayout (hash : Keccak) (f : CloseFields) (delegateCount : Nat) (tfd : U256) : Limbs :=
  [f.channelId.val] ++ putU64 f.closeNonce ++ putU64 f.finalEpoch ++
  putU64 f.finalSmallBlockNumber ++ putU64 f.closeFreezeNonce ++
  putBytes32 f.finalChannelStateDigest ++ putBytes32 f.finalBalanceStateH1 ++
  putUint256 (f.channelFundAmounts 0) ++ putBytes32 f.channelFundIntmaxStateRoot ++
  putBytes32 f.burnTxHash ++ putBytes32 f.closeWithdrawalDigest ++
  putBytes32 (closeIntentDigest hash f) ++ putU64 f.snapshotMediumBlockNumber ++
  putU64 f.finalStateVersion ++ putBytes32 f.finalSettledTxChain ++
  putBytes32 f.finalSettledTxAccumulatorRoot ++ putBytes32 f.memberSetCommitment ++
  [f.memberCount.val, delegateCount] ++ putBytes32 tfd

def expectedCloseLimbs (hash : Keccak) (f : CloseFields) (delegateCount : Nat) : Result Limbs :=
  match tokenFundsDigest hash f.tokenRegistry f.tokenCount f.channelFundAmounts with
  | .error e => .error e
  | .ok tfd => .ok (closeLayout hash f delegateCount tfd)

/-- Public layout helper takes uint32; it performs no snapshot/count authorization. -/
def expectedCloseLimbsPublic (hash : Keccak) (f : CloseFields) (delegateCount : U32) : Result Limbs :=
  expectedCloseLimbs hash f delegateCount.val

structure CancelFields where
  channelId : U32
  closeIntentDigest : U256
  memberSetCommitment : U256
  closeFinalStateVersion : U64
  revivedStateVersion : U64
  revivedChannelStateDigest : U256

def expectedCancelCloseLimbs (f : CancelFields) : Limbs :=
  [f.channelId.val] ++ putBytes32 f.closeIntentDigest ++ putBytes32 f.memberSetCommitment ++
  putU64 f.closeFinalStateVersion ++ putU64 f.revivedStateVersion ++ putBytes32 f.revivedChannelStateDigest

structure WithdrawalFields where
  channelId : U32
  closeIntentDigest : U256
  finalBalanceStateH1 : U256
  memberPkG : U256
  recipient : Address
  userAmountDigest : U256
  withdrawalNullifier : U256
  amount : U64
  tokenSlot : U8
  tokenIndex : U32

def expectedWithdrawalClaimLimbs (f : WithdrawalFields) : Limbs :=
  putBytes32 f.closeIntentDigest ++ [f.channelId.val] ++ putBytes32 f.finalBalanceStateH1 ++
  putBytes32 f.memberPkG ++ putAddress f.recipient ++ putBytes32 f.userAmountDigest ++
  putBytes32 f.withdrawalNullifier ++ putU64 f.amount ++ [f.tokenSlot.val, f.tokenIndex.val]

structure PostCloseFields where
  channelId : U32
  closeIntentDigest : U256
  incomingTxHash : U256
  receiverPkG : U256
  recipient : Address
  sharedNativeNullifier : U256
  amount : U64
  finalBalanceStateH1 : U256
  finalSettledTxAccumulatorRoot : U256
  tokenIndex : U32

def expectedPostCloseClaimLimbs (f : PostCloseFields) : Limbs :=
  putBytes32 f.closeIntentDigest ++ [f.channelId.val] ++ putBytes32 f.incomingTxHash ++
  putBytes32 f.receiverPkG ++ putAddress f.recipient ++ putBytes32 f.sharedNativeNullifier ++
  putU64 f.amount ++ putBytes32 f.finalBalanceStateH1 ++
  putBytes32 f.finalSettledTxAccumulatorRoot ++ [f.tokenIndex.val]

/-- The cursor-count assertions in the four source builders are discharged by length
    theorems below. These public helpers return the exact same list without verification. -/
def expectedCancelCloseLimbsPublic := expectedCancelCloseLimbs
def expectedWithdrawalClaimLimbsPublic := expectedWithdrawalClaimLimbs
def expectedPostCloseClaimLimbsPublic := expectedPostCloseClaimLimbs

/-- Source loop, with range-before-equality order and immediate revert. Length is
    already checked by callers; mismatched recursion is given their same length fault. -/
def scanLimbs (lengthFault rangeFault mismatchFault : Fault) : Limbs → Limbs → Result Unit
  | [], [] => .ok ()
  | x :: xs, y :: ys =>
    if x < limbBound then
      if x = y then scanLimbs lengthFault rangeFault mismatchFault xs ys
      else .error mismatchFault
    else .error rangeFault
  | _, _ => .error lengthFault

def bindCloseLimbsStrict (pi expected : Limbs) : Result Unit :=
  if pi.length ≠ 103 then .error .closePiLength
  else if expected.length ≠ 103 then .error .closeExpectedLength
  else scanLimbs .closePiLength .closeLimbRange .closeLimbMismatch pi expected

def bindLimbsStrict (pi expected : Limbs) : Result Unit :=
  if pi.length ≠ expected.length then .error .claimPiLength
  else scanLimbs .claimPiLength .claimLimbRange .claimLimbMismatch pi expected

/-- Length guard precedes pi[94]; getD is safe here because successful execution
    reached length=103. No PI word is masked/reduced before any comparison. -/
def bindCloseIntentPublicInputs (hash : Keccak) (f : CloseFields) (pi : Limbs) : Result Bool :=
  if pi.length ≠ 103 then .error .closePiLength
  else
    let delegateCount := pi.getD 94 0
    if delegateCount ≥ limbBound then .error .closeLimbRange
    else if delegateCount ≠ f.minDelegateCount.val then .error .delegateCount
    else if f.memberCount.val + delegateCount > 1024 then .error .delegateCount
    else match expectedCloseLimbs hash f delegateCount with
      | .error e => .error e
      | .ok expected => match bindCloseLimbsStrict pi expected with
        | .error e => .error e
        | .ok _ => .ok true

def verifyCloseIntent (evm : EvmView) (installed : Installed) (hash : Keccak)
    (f : CloseFields) (proof : Bytes) : Result Bool :=
  match evm.verifyCompactPublicInputs installed.adapters.close proof with
  | .error payload => .error (.externalCall payload)
  | .ok pi => bindCloseIntentPublicInputs hash f pi

def verifyClaimEndpoint (evm : EvmView) (adapter : Address) (proof : Bytes)
    (expected : Limbs) : Result Bool :=
  match evm.verifyCompactPublicInputs adapter proof with
  | .error payload => .error (.externalCall payload)
  | .ok pi => match bindLimbsStrict pi expected with
    | .error e => .error e
    | .ok _ => .ok true

def verifyWithdrawalClaim (evm : EvmView) (installed : Installed) (f : WithdrawalFields)
    (proof : Bytes) : Result Bool :=
  verifyClaimEndpoint evm installed.adapters.withdrawal proof (expectedWithdrawalClaimLimbs f)

def verifyCancelClose (evm : EvmView) (installed : Installed) (f : CancelFields)
    (proof : Bytes) : Result Bool :=
  verifyClaimEndpoint evm installed.adapters.cancel proof (expectedCancelCloseLimbs f)

def verifyPostCloseClaim (evm : EvmView) (installed : Installed) (f : PostCloseFields)
    (proof : Bytes) : Result Bool :=
  verifyClaimEndpoint evm installed.adapters.postClose proof (expectedPostCloseClaimLimbs f)

def memberSetPreimage (members : Fin 8 → U256) (count : U8) : Bytes :=
  beBytes 4 memberDomain ++ beBytes 4 count.val ++
  (eightList fun i : Fin 8 => beBytes 32 (if i.val < count.val then (members i).val else 0)).join

def closeMemberSetCommitment (hash : Keccak) (members : Fin 8 → U256) (count : U8) : U256 :=
  hash (memberSetPreimage members count)

structure SpecialFields where
  channelId : U32
  offendingBpMemberSlot : U8
  offendingBpPkG : U256
  fullySignedSmallBlockRoot : U256
  smallBlockNumber : U64
  signedMediumBlockNumber : U64
  latestFinalizedMediumBlockNumber : U64

def specialClosePreimage (f : SpecialFields) : Bytes :=
  beBytes 4 specialDomain ++ beBytes 4 f.channelId.val ++ beBytes 4 f.offendingBpMemberSlot.val ++
  beBytes 32 f.offendingBpPkG.val ++ beBytes 32 f.fullySignedSmallBlockRoot.val ++
  beBytes 8 f.smallBlockNumber.val ++ beBytes 8 f.signedMediumBlockNumber.val ++
  beBytes 8 f.latestFinalizedMediumBlockNumber.val

def specialClosePIHash (hash : Keccak) (f : SpecialFields) : U256 := hash (specialClosePreimage f)

structure LateFields where
  channelId : U32
  closeIntentDigest : U256
  sourceTxHash : U256
  senderPkG : U256
  senderAmountDigest : U256
  debitNullifier : U256
  amount : U64

def lateOutgoingDebitPreimage (f : LateFields) : Bytes :=
  beBytes 4 lateDomain ++ beBytes 32 f.closeIntentDigest.val ++ beBytes 4 f.channelId.val ++
  beBytes 32 f.sourceTxHash.val ++ beBytes 32 f.senderPkG.val ++
  beBytes 32 f.senderAmountDigest.val ++ beBytes 32 f.debitNullifier.val ++ beBytes 8 f.amount.val

def lateOutgoingDebitPIHash (hash : Keccak) (f : LateFields) : U256 := hash (lateOutgoingDebitPreimage f)

/-- ABI decode(bytes32) after the exact 32-byte guard is equivalent to equality
    of the canonical bytes32 serialization. Valid calldata bytes are an ABI premise. -/
def matchesDigest (proof : Bytes) (expected : U256) : Bool :=
  decide (proof.length = 32 ∧ proof = beBytes 32 expected.val)

def verifySpecialClose (hash : Keccak) (f : SpecialFields) (proof : Bytes) : Bool :=
  matchesDigest proof (specialClosePIHash hash f)

def verifyLateOutgoingDebit (hash : Keccak) (f : LateFields) (proof : Bytes) : Bool :=
  matchesDigest proof (lateOutgoingDebitPIHash hash f)

/-! ## Local arithmetic, layout, and exact-binding proofs -/

theorem beBytes_length (n v : Nat) : (beBytes n v).length = n := by
  induction n with
  | zero => rfl
  | succ n ih => simp [beBytes, ih]

theorem beBytes_canonical (n v b : Nat) (h : b ∈ beBytes n v) : b < 256 := by
  induction n with
  | zero => simp [beBytes] at h
  | succ n ih =>
    simp only [beBytes, List.mem_cons] at h
    rcases h with rfl | tail
    · exact Nat.mod_lt _ (by decide)
    · exact ih tail

theorem word_canonical (v n : Nat) : word v n < limbBound := Nat.mod_lt _ (by decide)

theorem putU64_length (v : U64) : (putU64 v).length = 2 := rfl
theorem putUint256_length (v : U256) : (putUint256 v).length = 8 := rfl
theorem putBytes32_length (v : U256) : (putBytes32 v).length = 8 := rfl
theorem putAddress_length (v : Address) : (putAddress v).length = 5 := rfl

theorem putU64_reconstructs (v : U64) : v.val / limbBound * limbBound + v.val % limbBound = v.val := by
  simpa [Nat.mul_comm] using Nat.div_add_mod v.val limbBound

theorem putU64_canonical (v : U64) (x : Nat) (h : x ∈ putU64 v) : x < limbBound := by
  have range := v.isLt
  change v.val < 18446744073709551616 at range
  simp only [putU64, List.mem_cons, List.not_mem_nil, or_false] at h
  rcases h with rfl | rfl
  · change v.val / 4294967296 < 4294967296
    omega
  · exact Nat.mod_lt _ (by decide)

theorem putUint256_canonical (v : U256) (x : Nat) (h : x ∈ putUint256 v) : x < limbBound := by
  simp only [putUint256, List.mem_cons, List.not_mem_nil, or_false] at h
  rcases h with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;> exact word_canonical _ _

theorem putAddress_canonical (v : Address) (x : Nat) (h : x ∈ putAddress v) : x < limbBound := by
  simp only [putAddress, List.mem_cons, List.not_mem_nil, or_false] at h
  rcases h with rfl | rfl | rfl | rfl | rfl <;> exact word_canonical _ _

theorem closeLayout_length (hash : Keccak) (f : CloseFields) (dc : Nat) (tfd : U256) :
    (closeLayout hash f dc tfd).length = 103 := by
  simp [closeLayout, putU64, putBytes32, putUint256]

theorem cancelLayout_length (f : CancelFields) : (expectedCancelCloseLimbs f).length = 29 := by
  simp [expectedCancelCloseLimbs, putBytes32, putUint256, putU64]

theorem withdrawalLayout_length (f : WithdrawalFields) : (expectedWithdrawalClaimLimbs f).length = 50 := by
  simp [expectedWithdrawalClaimLimbs, putBytes32, putUint256, putU64, putAddress]

theorem postCloseLayout_length (f : PostCloseFields) : (expectedPostCloseClaimLimbs f).length = 57 := by
  simp [expectedPostCloseClaimLimbs, putBytes32, putUint256, putU64, putAddress]

theorem scanLimbs_success_iff (len range mismatch : Fault) (pi expected : Limbs) :
    scanLimbs len range mismatch pi expected = .ok () ↔
      pi = expected ∧ ∀ x ∈ pi, x < limbBound := by
  induction pi generalizing expected with
  | nil => cases expected <;> simp [scanLimbs]
  | cons x xs ih =>
    cases expected with
    | nil => simp [scanLimbs]
    | cons y ys =>
      by_cases bound : x < limbBound
      · by_cases same : x = y
        · subst y
          simp [scanLimbs, bound, ih]
        · simp [scanLimbs, bound, same]
      · simp [scanLimbs, bound]

theorem bindLimbsStrict_success_iff (pi expected : Limbs) :
    bindLimbsStrict pi expected = .ok () ↔ pi = expected ∧ ∀ x ∈ pi, x < limbBound := by
  by_cases len : pi.length = expected.length
  · simp [bindLimbsStrict, len, scanLimbs_success_iff]
  · simp [bindLimbsStrict, len]
    intro eq
    exact False.elim (len (congrArg List.length eq))

theorem bindCloseLimbsStrict_success_iff (pi expected : Limbs) :
    bindCloseLimbsStrict pi expected = .ok () ↔
      pi.length = 103 ∧ expected.length = 103 ∧ pi = expected ∧ ∀ x ∈ pi, x < limbBound := by
  by_cases a : pi.length = 103 <;> by_cases b : expected.length = 103 <;>
    simp [bindCloseLimbsStrict, a, b, scanLimbs_success_iff]

theorem tokenFundsDigest_success_iff (hash : Keccak) (registry : Fin 10 → U32)
    (count : U8) (amounts : Fin 10 → U256) (digest : U256) :
    tokenFundsDigest hash registry count amounts = .ok digest ↔
      0 < count.val ∧ count.val ≤ 10 ∧ hash (tokenFundsPreimage registry count amounts) = digest := by
  unfold tokenFundsDigest
  split <;> simp_all <;> omega

theorem matches_success_iff (proof : Bytes) (expected : U256) :
    matchesDigest proof expected = true ↔ proof.length = 32 ∧ proof = beBytes 32 expected.val := by
  simp [matchesDigest]

theorem requirePinnedVerifier_success_iff (evm : EvmView) (adapter core : Address) :
    requirePinnedVerifier evm adapter = .ok core ↔
      evm.codeSize adapter ≠ 0 ∧ evm.allowedChainId adapter = .ok evm.chainId ∧
      evm.core adapter = .ok core ∧ evm.codeSize core ≠ 0 ∧
      evm.allowedChainId core = .ok evm.chainId := by
  by_cases code : evm.codeSize adapter = 0
  · simp [requirePinnedVerifier, code]
  cases chainCall : evm.allowedChainId adapter with
  | error e => simp [requirePinnedVerifier, code, chainCall]
  | ok chain =>
    by_cases chainEq : chain = evm.chainId
    · subst chain
      cases coreCall : evm.core adapter with
      | error e => simp [requirePinnedVerifier, code, chainCall, coreCall]
      | ok found =>
        by_cases foundCode : evm.codeSize found = 0
        · simp [requirePinnedVerifier, code, chainCall, coreCall, foundCode]
          intro eq
          subst core
          simp [foundCode]
        cases coreChainCall : evm.allowedChainId found with
        | error e =>
          simp [requirePinnedVerifier, code, chainCall, coreCall, foundCode, coreChainCall]
          intro eq
          subst core
          simp [coreChainCall]
        | ok foundChain =>
          by_cases lastEq : foundChain = evm.chainId
          · subst foundChain
            simp [requirePinnedVerifier, code, chainCall, coreCall, foundCode, coreChainCall]
            intro eq
            subst core
            exact ⟨foundCode, coreChainCall⟩
          · simp [requirePinnedVerifier, code, chainCall, coreCall, foundCode, coreChainCall, lastEq]
            intro eq
            subst core
            simp [coreChainCall, lastEq]
    · simp [requirePinnedVerifier, code, chainCall, chainEq]

theorem constructor_duplicate_adapter_first (evm : EvmView) (a : Adapters)
    (duplicate : distinctAdapters a = false) : constructor evm a = .error .duplicatePinned := by
  simp [constructor, duplicate]

theorem constructor_success_fields (evm : EvmView) (a : Adapters) (installed : Installed)
    (accepted : constructor evm a = .ok installed) :
    installed.adapters = a ∧ distinctAdapters a = true ∧ isolatedPairs a installed.cores = true ∧
      requirePinnedVerifier evm a.close = .ok installed.cores.close ∧
      requirePinnedVerifier evm a.withdrawal = .ok installed.cores.withdrawal ∧
      requirePinnedVerifier evm a.postClose = .ok installed.cores.postClose ∧
      requirePinnedVerifier evm a.cancel = .ok installed.cores.cancel := by
  cases distinct : distinctAdapters a with
  | false => simp [constructor, distinct] at accepted
  | true =>
    cases c : requirePinnedVerifier evm a.close with
    | error e => simp [constructor, distinct, c] at accepted
    | ok cv =>
      cases w : requirePinnedVerifier evm a.withdrawal with
      | error e => simp [constructor, distinct, c, w] at accepted
      | ok wv =>
        cases p : requirePinnedVerifier evm a.postClose with
        | error e => simp [constructor, distinct, c, w, p] at accepted
        | ok pv =>
          cases k : requirePinnedVerifier evm a.cancel with
          | error e => simp [constructor, distinct, c, w, p, k] at accepted
          | ok kv =>
            simp only [constructor, distinct, Bool.not_true, Bool.false_eq_true,
              ↓reduceIte, c, w, p, k, Except.bind] at accepted
            unfold finishConstructor at accepted
            split at accepted
            · cases accepted
              simp_all
            · contradiction

theorem tokenFundsPreimage_length (registry : Fin 10 → U32) (count : U8) (amounts : Fin 10 → U256) :
    (tokenFundsPreimage registry count amounts).length = 368 := by
  simp [tokenFundsPreimage, tenList, List.join, beBytes_length]

theorem memberSetPreimage_length (members : Fin 8 → U256) (count : U8) :
    (memberSetPreimage members count).length = 264 := by
  simp [memberSetPreimage, eightList, List.join, beBytes_length]

theorem closeIntentPreimage_length (f : CloseFields) : (closeIntentPreimage f).length = 48 := by
  simp [closeIntentPreimage, beBytes_length]

theorem specialClosePreimage_length (f : SpecialFields) : (specialClosePreimage f).length = 100 := by
  simp [specialClosePreimage, beBytes_length]

theorem lateOutgoingDebitPreimage_length (f : LateFields) : (lateOutgoingDebitPreimage f).length = 176 := by
  simp [lateOutgoingDebitPreimage, beBytes_length]

theorem memberSet_inactive_padding_irrelevant (hash : Keccak) (a b : Fin 8 → U256) (count : U8)
    (activeSame : ∀ i, i.val < count.val → a i = b i) :
    closeMemberSetCommitment hash a count = closeMemberSetCommitment hash b count := by
  have slots : (fun i : Fin 8 => beBytes 32 (if i.val < count.val then (a i).val else 0)) =
      (fun i : Fin 8 => beBytes 32 (if i.val < count.val then (b i).val else 0)) := by
    funext i
    by_cases h : i.val < count.val
    · simp [h, activeSame i h]
    · simp [h]
  simp only [closeMemberSetCommitment, memberSetPreimage, slots]

theorem expectedCloseLimbs_success (hash : Keccak) (f : CloseFields) (dc : Nat) (pi : Limbs)
    (ok : expectedCloseLimbs hash f dc = .ok pi) :
    0 < f.tokenCount.val ∧ f.tokenCount.val ≤ 10 ∧
      pi = closeLayout hash f dc (hash (tokenFundsPreimage f.tokenRegistry f.tokenCount f.channelFundAmounts)) ∧
      pi.length = 103 := by
  cases digest : tokenFundsDigest hash f.tokenRegistry f.tokenCount f.channelFundAmounts with
  | error e => simp [expectedCloseLimbs, digest] at ok
  | ok tfd =>
    have checked := (tokenFundsDigest_success_iff _ _ _ _ _).mp digest
    simp [expectedCloseLimbs, digest] at ok
    subst pi
    exact ⟨checked.1, checked.2.1, by rw [checked.2.2], closeLayout_length _ _ _ _⟩

theorem close_binding_success (hash : Keccak) (f : CloseFields) (pi : Limbs)
    (accepted : bindCloseIntentPublicInputs hash f pi = .ok true) :
    pi.length = 103 ∧ pi.getD 94 0 = f.minDelegateCount.val ∧
      f.memberCount.val + pi.getD 94 0 ≤ 1024 ∧
      (∀ x ∈ pi, x < limbBound) ∧
      pi = closeLayout hash f (pi.getD 94 0)
        (hash (tokenFundsPreimage f.tokenRegistry f.tokenCount f.channelFundAmounts)) := by
  unfold bindCloseIntentPublicInputs at accepted
  split at accepted
  · contradiction
  rename_i len
  dsimp only at accepted
  split at accepted
  · contradiction
  split at accepted
  · contradiction
  rename_i snapshot
  split at accepted
  · contradiction
  rename_i capacity
  cases layout : expectedCloseLimbs hash f (pi.getD 94 0) with
  | error e => simp only [layout] at accepted
  | ok expected =>
    simp only [layout, Except.bind] at accepted
    cases bindResult : bindCloseLimbsStrict pi expected with
    | error e => simp [bindResult] at accepted
    | ok unitResult =>
      cases unitResult
      have exactBinding := (bindCloseLimbsStrict_success_iff pi expected).mp bindResult
      have expectedBinding := expectedCloseLimbs_success hash f _ expected layout
      exact ⟨by omega, by omega, by omega, exactBinding.2.2.2,
        exactBinding.2.2.1.trans expectedBinding.2.2.1⟩

theorem claim_endpoint_success (evm : EvmView) (adapter : Address) (proof : Bytes) (expected : Limbs)
    (accepted : verifyClaimEndpoint evm adapter proof expected = .ok true) :
    evm.verifyCompactPublicInputs adapter proof = .ok expected ∧ ∀ x ∈ expected, x < limbBound := by
  cases call : evm.verifyCompactPublicInputs adapter proof with
  | error e => simp [verifyClaimEndpoint, call] at accepted
  | ok pi =>
    cases bound : bindLimbsStrict pi expected with
    | error e => simp [verifyClaimEndpoint, call, bound] at accepted
    | ok unitResult =>
      cases unitResult
      have checked := (bindLimbsStrict_success_iff pi expected).mp bound
      rcases checked with ⟨eq, canonical⟩
      subst pi
      exact ⟨rfl, canonical⟩

theorem claim_endpoint_never_returns_false (evm : EvmView) (adapter : Address) (proof : Bytes) (expected : Limbs) :
    verifyClaimEndpoint evm adapter proof expected ≠ .ok false := by
  cases call : evm.verifyCompactPublicInputs adapter proof with
  | error e => simp [verifyClaimEndpoint, call]
  | ok pi => cases bound : bindLimbsStrict pi expected <;> simp [verifyClaimEndpoint, call, bound]

theorem close_verification_has_external_provenance (evm : EvmView) (installed : Installed)
    (hash : Keccak) (f : CloseFields) (proof : Bytes)
    (accepted : verifyCloseIntent evm installed hash f proof = .ok true) :
    ∃ pi, evm.verifyCompactPublicInputs installed.adapters.close proof = .ok pi ∧
      bindCloseIntentPublicInputs hash f pi = .ok true := by
  cases call : evm.verifyCompactPublicInputs installed.adapters.close proof with
  | error e => simp [verifyCloseIntent, call] at accepted
  | ok pi => exact ⟨pi, rfl, by simpa [verifyCloseIntent, call] using accepted⟩

theorem withdrawal_verification_exact_statement (evm : EvmView) (installed : Installed)
    (f : WithdrawalFields) (proof : Bytes)
    (accepted : verifyWithdrawalClaim evm installed f proof = .ok true) :
    evm.verifyCompactPublicInputs installed.adapters.withdrawal proof = .ok (expectedWithdrawalClaimLimbs f) ∧
      ∀ x ∈ expectedWithdrawalClaimLimbs f, x < limbBound :=
  claim_endpoint_success evm _ proof _ accepted

theorem cancel_verification_exact_statement (evm : EvmView) (installed : Installed)
    (f : CancelFields) (proof : Bytes)
    (accepted : verifyCancelClose evm installed f proof = .ok true) :
    evm.verifyCompactPublicInputs installed.adapters.cancel proof = .ok (expectedCancelCloseLimbs f) ∧
      ∀ x ∈ expectedCancelCloseLimbs f, x < limbBound :=
  claim_endpoint_success evm _ proof _ accepted

theorem postClose_verification_exact_statement (evm : EvmView) (installed : Installed)
    (f : PostCloseFields) (proof : Bytes)
    (accepted : verifyPostCloseClaim evm installed f proof = .ok true) :
    evm.verifyCompactPublicInputs installed.adapters.postClose proof = .ok (expectedPostCloseClaimLimbs f) ∧
      ∀ x ∈ expectedPostCloseClaimLimbs f, x < limbBound :=
  claim_endpoint_success evm _ proof _ accepted

theorem isolatedPairs_no_cross_slot (a cores : Adapters) (h : isolatedPairs a cores = true)
    (i j : Fin 4) (different : i ≠ j) :
    adapterAt cores i ≠ adapterAt cores j ∧ adapterAt a i ≠ adapterAt cores j := by
  have member (k : Fin 4) : k ∈ ([0, 1, 2, 3] : List (Fin 4)) := by
    have bound := k.isLt
    have cases : k.val = 0 ∨ k.val = 1 ∨ k.val = 2 ∨ k.val = 3 := by omega
    rcases cases with h | h | h | h
    all_goals simp only [List.mem_cons, List.not_mem_nil, or_false]
    · exact Or.inl (Fin.ext h)
    · exact Or.inr (Or.inl (Fin.ext h))
    · exact Or.inr (Or.inr (Or.inl (Fin.ext h)))
    · exact Or.inr (Or.inr (Or.inr (Fin.ext h)))
  have first := (List.all_eq_true.mp h) i (member i)
  have second := (List.all_eq_true.mp first) j (member j)
  simpa [different] using second

theorem constructor_no_cross_slot (evm : EvmView) (a : Adapters) (installed : Installed)
    (accepted : constructor evm a = .ok installed) (i j : Fin 4) (different : i ≠ j) :
    adapterAt installed.cores i ≠ adapterAt installed.cores j ∧
      adapterAt a i ≠ adapterAt installed.cores j :=
  isolatedPairs_no_cross_slot a installed.cores (constructor_success_fields evm a installed accepted).2.2.1
    i j different

theorem putU64_injective (a b : U64) (equal : putU64 a = putU64 b) : a = b := by
  simp only [putU64, List.cons.injEq] at equal
  have ar := putU64_reconstructs a
  have br := putU64_reconstructs b
  rw [equal.1, equal.2.1] at ar
  exact Fin.ext (ar.symm.trans br)

theorem putAddress_injective (a b : Address) (equal : putAddress a = putAddress b) : a = b := by
  have ar := a.isLt
  have br := b.isLt
  simp only [putAddress, List.cons.injEq, word, limbBound] at equal
  apply Fin.ext
  omega

theorem putUint256_injective (a b : U256) (equal : putUint256 a = putUint256 b) : a = b := by
  have ar := a.isLt
  have br := b.isLt
  simp only [putUint256, List.cons.injEq, word, limbBound] at equal
  apply Fin.ext
  omega

def slice (xs : Limbs) (start count : Nat) : Limbs := (xs.drop start).take count

theorem withdrawalLayout_field_positions (f : WithdrawalFields) :
    let pi := expectedWithdrawalClaimLimbs f
    slice pi 0 8 = putBytes32 f.closeIntentDigest ∧ slice pi 8 1 = [f.channelId.val] ∧
    slice pi 9 8 = putBytes32 f.finalBalanceStateH1 ∧ slice pi 17 8 = putBytes32 f.memberPkG ∧
    slice pi 25 5 = putAddress f.recipient ∧ slice pi 30 8 = putBytes32 f.userAmountDigest ∧
    slice pi 38 8 = putBytes32 f.withdrawalNullifier ∧ slice pi 46 2 = putU64 f.amount ∧
    slice pi 48 2 = [f.tokenSlot.val, f.tokenIndex.val] := by
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩

theorem cancelLayout_field_positions (f : CancelFields) :
    let pi := expectedCancelCloseLimbs f
    slice pi 0 1 = [f.channelId.val] ∧ slice pi 1 8 = putBytes32 f.closeIntentDigest ∧
    slice pi 9 8 = putBytes32 f.memberSetCommitment ∧
    slice pi 17 2 = putU64 f.closeFinalStateVersion ∧ slice pi 19 2 = putU64 f.revivedStateVersion ∧
    slice pi 21 8 = putBytes32 f.revivedChannelStateDigest := by
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩

theorem postCloseLayout_field_positions (f : PostCloseFields) :
    let pi := expectedPostCloseClaimLimbs f
    slice pi 0 8 = putBytes32 f.closeIntentDigest ∧ slice pi 8 1 = [f.channelId.val] ∧
    slice pi 9 8 = putBytes32 f.incomingTxHash ∧ slice pi 17 8 = putBytes32 f.receiverPkG ∧
    slice pi 25 5 = putAddress f.recipient ∧ slice pi 30 8 = putBytes32 f.sharedNativeNullifier ∧
    slice pi 38 2 = putU64 f.amount ∧ slice pi 40 8 = putBytes32 f.finalBalanceStateH1 ∧
    slice pi 48 8 = putBytes32 f.finalSettledTxAccumulatorRoot ∧ slice pi 56 1 = [f.tokenIndex.val] := by
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩

theorem withdrawalLayout_binds_payout (a b : WithdrawalFields)
    (same : expectedWithdrawalClaimLimbs a = expectedWithdrawalClaimLimbs b) :
    a.recipient = b.recipient ∧ a.amount = b.amount ∧ a.tokenIndex = b.tokenIndex ∧
      a.tokenSlot = b.tokenSlot ∧ a.withdrawalNullifier = b.withdrawalNullifier := by
  have recipient := congrArg (fun pi => slice pi 25 5) same
  have amount := congrArg (fun pi => slice pi 46 2) same
  have tokens := congrArg (fun pi => slice pi 48 2) same
  have nullifier := congrArg (fun pi => slice pi 38 8) same
  change [a.tokenSlot.val, a.tokenIndex.val] = [b.tokenSlot.val, b.tokenIndex.val] at tokens
  simp only [List.cons.injEq] at tokens
  exact ⟨putAddress_injective _ _ recipient, putU64_injective _ _ amount,
    Fin.ext tokens.2.1, Fin.ext tokens.1, putUint256_injective _ _ nullifier⟩

theorem postCloseLayout_binds_payout (a b : PostCloseFields)
    (same : expectedPostCloseClaimLimbs a = expectedPostCloseClaimLimbs b) :
    a.recipient = b.recipient ∧ a.amount = b.amount ∧ a.tokenIndex = b.tokenIndex ∧
      a.sharedNativeNullifier = b.sharedNativeNullifier := by
  have recipient := congrArg (fun pi => slice pi 25 5) same
  have amount := congrArg (fun pi => slice pi 38 2) same
  have token := congrArg (fun pi => slice pi 56 1) same
  have nullifier := congrArg (fun pi => slice pi 30 8) same
  change [a.tokenIndex.val] = [b.tokenIndex.val] at token
  simp only [List.cons.injEq] at token
  exact ⟨putAddress_injective _ _ recipient, putU64_injective _ _ amount,
    Fin.ext token.1, putUint256_injective _ _ nullifier⟩

theorem withdrawal_same_proof_no_payout_rebinding (evm : EvmView) (installed : Installed)
    (a b : WithdrawalFields) (proof : Bytes)
    (first : verifyWithdrawalClaim evm installed a proof = .ok true)
    (second : verifyWithdrawalClaim evm installed b proof = .ok true) :
    a.recipient = b.recipient ∧ a.amount = b.amount ∧ a.tokenIndex = b.tokenIndex ∧
      a.tokenSlot = b.tokenSlot ∧ a.withdrawalNullifier = b.withdrawalNullifier := by
  have ha := (withdrawal_verification_exact_statement evm installed a proof first).1
  have hb := (withdrawal_verification_exact_statement evm installed b proof second).1
  exact withdrawalLayout_binds_payout a b (Except.ok.inj (ha.symm.trans hb))

theorem postClose_same_proof_no_payout_rebinding (evm : EvmView) (installed : Installed)
    (a b : PostCloseFields) (proof : Bytes)
    (first : verifyPostCloseClaim evm installed a proof = .ok true)
    (second : verifyPostCloseClaim evm installed b proof = .ok true) :
    a.recipient = b.recipient ∧ a.amount = b.amount ∧ a.tokenIndex = b.tokenIndex ∧
      a.sharedNativeNullifier = b.sharedNativeNullifier := by
  have ha := (postClose_verification_exact_statement evm installed a proof first).1
  have hb := (postClose_verification_exact_statement evm installed b proof second).1
  exact postCloseLayout_binds_payout a b (Except.ok.inj (ha.symm.trans hb))

theorem close_wrong_length_reverts_first (hash : Keccak) (f : CloseFields) (pi : Limbs)
    (wrong : pi.length ≠ 103) :
    bindCloseIntentPublicInputs hash f pi = .error .closePiLength := by
  simp [bindCloseIntentPublicInputs, wrong]

theorem close_delegate_range_reverts_before_addition (hash : Keccak) (f : CloseFields) (pi : Limbs)
    (length : pi.length = 103) (range : pi.getD 94 0 ≥ limbBound) :
    bindCloseIntentPublicInputs hash f pi = .error .closeLimbRange := by
  simp only [bindCloseIntentPublicInputs, length, ne_eq, not_true_eq_false, ↓reduceIte, range]

theorem close_delegate_addition_cannot_overflow (f : CloseFields) (dc : Nat)
    (canonical : dc < limbBound) : f.memberCount.val + dc < 2 ^ 256 := by
  have memberBound := f.memberCount.isLt
  change f.memberCount.val < 256 at memberBound
  change dc < 4294967296 at canonical
  omega

theorem close_binding_never_returns_false (hash : Keccak) (f : CloseFields) (pi : Limbs) :
    bindCloseIntentPublicInputs hash f pi ≠ .ok false := by
  unfold bindCloseIntentPublicInputs
  split
  · simp
  dsimp only
  split
  · simp
  split
  · simp
  split
  · simp
  cases _layout : expectedCloseLimbs hash f (pi.getD 94 0) with
  | error e => simp
  | ok expected => cases bound : bindCloseLimbsStrict pi expected <;> simp [bound]

theorem close_verification_never_returns_false (evm : EvmView) (installed : Installed)
    (hash : Keccak) (f : CloseFields) (proof : Bytes) :
    verifyCloseIntent evm installed hash f proof ≠ .ok false := by
  cases call : evm.verifyCompactPublicInputs installed.adapters.close proof with
  | error e => simp [verifyCloseIntent, call]
  | ok pi => simpa [verifyCloseIntent, call] using close_binding_never_returns_false hash f pi

theorem claim_external_revert_preserved (evm : EvmView) (adapter : Address) (proof : Bytes)
    (expected : Limbs) (payload : Bytes)
    (failure : evm.verifyCompactPublicInputs adapter proof = .error payload) :
    verifyClaimEndpoint evm adapter proof expected = .error (.externalCall payload) := by
  simp [verifyClaimEndpoint, failure]

theorem close_external_revert_preserved (evm : EvmView) (installed : Installed) (hash : Keccak)
    (f : CloseFields) (proof payload : Bytes)
    (failure : evm.verifyCompactPublicInputs installed.adapters.close proof = .error payload) :
    verifyCloseIntent evm installed hash f proof = .error (.externalCall payload) := by
  simp [verifyCloseIntent, failure]

end Zkp.Implementation.SettlementVerifier
