import Std

/-!
# Channel-layer record, state and digest-preimage types

Handwritten SEMANTIC MODEL of `src/common/channel.rs` (3005 lines; production region
lines 1..1760, the rest is `#[cfg(test)]`). This is NOT a refinement proof of the Rust
code, of `serde`, of the Rust compiler, or of any circuit or Solidity mirror. It is a
local model of the layouts, the keccak PREIMAGES (never of keccak itself), and the two
structural validators that the circuit-side modules
(`Zkp.Implementation.ChannelStateUpdate`, `Zkp.Implementation.BlockMessages`) treat as
opaque callees.

Representation choices, stated so nothing is silently invented:
* A `Bytes32` and a `U256` are both eight ordered u32 limbs (`Hash`). `src/common/channel.rs`
  performs NO `U256` arithmetic — every `U256` is only `to_u32_vec`'d or compared — so the
  limb record is a faithful and complete representation here.
* An `Address` is five ordered u32 limbs (`Addr`); a `Salt` is four u64 scalars, each split
  by `splitU64` into a big-endian u32 pair.
* `[Bytes32; MAX_CHANNEL_MEMBERS]` and `[Bytes32; MAX_SIG_CLUSTER]` are modeled as total
  index functions plus the source's own bound; the digest preimages read exactly the first
  `MAX_CHANNEL_MEMBERS` (resp. `MAX_SIG_CLUSTER`) positions, which is what fixes their width.
* Native u64 fields are `Nat`; `splitU64` reduces modulo the u32 base exactly like the source
  shift/cast pair, so out-of-range `Nat`s cannot silently widen a preimage.

NAMED BOUNDARIES (undischarged, collected in `Env`): `hash` (`solidity_keccak256`/`hash_words`
— never assumed injective or collision-resistant), `ctDigest` (`RegevCiphertext::digest`),
`balanceH1` (`BalanceState::h1`, modeled in `Zkp.Implementation.H1Gadget`), `txLeafHash` and
`settledTxChainPush` (imported from `common::balance_state`), `applyTokenRegister`
(`BalanceState::apply_token_register`). Falcon signature validity, SPHINCS+/hash-signature
validity, Merkle-tree soundness, L1 acceptance, proof soundness and freshness are NOT modeled
and are NOT implied by anything proved here.

WHAT `validateRecord` (`ChannelRecord::validate`) DOES: nonzero `regev_pk_root`; channel id is
not the reserved burn id; `2 <= member_count <= MAX_SIG_CLUSTER`; `bp_member_slot < member_count`;
`member_count + delegate_count <= MAX_CHANNEL_MEMBERS`; every slot below that active bound holds
a nonzero pubkey hash; those active hashes are pairwise distinct; every slot at or above the
bound holds exactly `Bytes32::default()`.
WHAT IT DOES NOT DO: it never inspects `member_pubkeys_root`, `regev_pk_root` beyond
nonzero-ness, `set_version`, `status`, `special_close_penalty` or `close_freeze_nonce`; it
does not check that the hashes are real keys, that anybody holds the corresponding secrets,
that `member_pubkeys_root` or `regev_pk_root` commits to these very hashes, or that the
member/delegate split matches any on-chain registration. `member_root_unconstrained_by_validate`
and `regev_root_only_checked_nonzero` prove exactly that.

The two signature-set validators are STRUCTURE ONLY. `validateMemberSignatureSlots` checks the
record, then one entry per cosigner slot in slot order with the registered `pk_g` and a
non-empty blob; `validateAllMemberSignatures` adds the fixed Falcon cosign blob LENGTH.
`signature_validation_ignores_blob_contents` proves that neither result depends on the blob
BYTES at all (only their length), so no cryptographic verification happens on this path;
`structural_placeholder_passes_length_gate` exhibits the source's own explicit non-signature
passing both.
-/
namespace Zkp.Implementation.ChannelTypes

/-! ## Pinned constants (channel.rs and the constants it imports) -/

def wordBase : Nat := 4294967296
def scalarLimit : Nat := 18446744073709551616
def maxChannelMembers : Nat := 1024
def maxSigCluster : Nat := 8
def maxChannelTokens : Nat := 10
def maxCloseTransfers : Nat := 16
def specialCloseMediumBlockWindow : Nat := 5
def burnChannelId : Nat := 4294967295
def falconCosignBlobBytes : Nat := 1690
def falconSigV1 : Nat := 1
def addressLimbs : Nat := 5
def digestLimbs : Nat := 8
def saltScalars : Nat := 4

def channelStateDomain : Nat := 0x494d4348
def smallBlockDomain : Nat := 0x494d5342
def signedSmallBlockDomain : Nat := 0x494d5353
def closeTxDomain : Nat := 0x494d434c
def closeStateIdDomain : Nat := 0x494d4353
def specialCloseDomain : Nat := 0x494d5343
def cancelCloseDomain : Nat := 0x494d434e
def postCloseClaimDomain : Nat := 0x494d4350
def burnDescriptorDomain : Nat := 0x494d4432
def postCloseNullifierDomain : Nat := 0x494d434b
def withdrawalClaimDomain : Nat := 0x494d4357
def channelBalanceLeafDomain : Nat := 0x494d5546
def channelRecordDomain : Nat := 0x494d4352
def closeMemberSetDomain : Nat := 0x494d434d
def payDomainV2 : Nat := 0x494d5032
def l1DepositImportDomainV2 : Nat := 0x494d4c32
def withdrawalClaimDomainV2 : Nat := 0x494d5732
def interChannelTxDomainV5 : Nat := 0x494d4935
def tokenFundsDigestDomain : Nat := 0x494d5446

theorem max_channel_members_pinned : maxChannelMembers = 1024 := rfl
theorem max_sig_cluster_pinned : maxSigCluster = 8 := rfl
theorem max_channel_tokens_pinned : maxChannelTokens = 10 := rfl
theorem max_close_transfers_pinned : maxCloseTransfers = 16 := rfl
theorem special_close_window_pinned : specialCloseMediumBlockWindow = 5 := rfl
theorem burn_channel_id_pinned : burnChannelId = 4294967295 := rfl
theorem falcon_cosign_blob_bytes_pinned : falconCosignBlobBytes = 1690 := rfl
theorem falcon_sig_v1_pinned : falconSigV1 = 1 := rfl
theorem word_base_pinned : wordBase = 2 ^ 32 := by decide
theorem scalar_limit_pinned : scalarLimit = 2 ^ 64 := by decide

/-- The cosigner cap is strictly smaller than the balance-slot capacity: cosigning and
holding a balance slot are different capacities (delegates hold slots, never cosign). -/
theorem sig_cluster_below_member_capacity : maxSigCluster < maxChannelMembers := by decide

/-! ### Domain separators are the pinned four-byte ASCII tags -/

def asciiTag (a b c d : Nat) : Nat := a * 16777216 + b * 65536 + c * 256 + d

theorem channel_state_domain_is_imch : channelStateDomain = asciiTag 0x49 0x4d 0x43 0x48 := by decide
theorem channel_record_domain_is_imcr : channelRecordDomain = asciiTag 0x49 0x4d 0x43 0x52 := by decide
theorem close_state_id_domain_is_imcs : closeStateIdDomain = asciiTag 0x49 0x4d 0x43 0x53 := by decide
theorem close_member_set_domain_is_imcm : closeMemberSetDomain = asciiTag 0x49 0x4d 0x43 0x4d := by decide
theorem token_funds_domain_is_imtf : tokenFundsDigestDomain = asciiTag 0x49 0x4d 0x54 0x46 := by decide

/-- Every domain separator used by a preimage in this file is distinct. The source relies on
this for schema separation between messages hashed with the same primitive. -/
theorem channel_domains_pairwise_distinct :
    [channelStateDomain, smallBlockDomain, signedSmallBlockDomain, closeTxDomain,
     closeStateIdDomain, specialCloseDomain, cancelCloseDomain, postCloseClaimDomain,
     burnDescriptorDomain, postCloseNullifierDomain, withdrawalClaimDomain,
     channelBalanceLeafDomain, channelRecordDomain, closeMemberSetDomain, payDomainV2,
     l1DepositImportDomainV2, withdrawalClaimDomainV2, interChannelTxDomainV5,
     tokenFundsDigestDomain].Nodup := by decide

/-! ## Limb records -/

/-- Eight ordered u32 limbs: the shared representation of `Bytes32` and `U256`. -/
structure Hash where
  w0 : Nat
  w1 : Nat
  w2 : Nat
  w3 : Nat
  w4 : Nat
  w5 : Nat
  w6 : Nat
  w7 : Nat
  deriving DecidableEq, Repr

def Hash.words (v : Hash) : List Nat := [v.w0, v.w1, v.w2, v.w3, v.w4, v.w5, v.w6, v.w7]
def Hash.zero : Hash := ⟨0, 0, 0, 0, 0, 0, 0, 0⟩

/-- `Address::to_u32_vec` — five ordered u32 limbs. -/
structure Addr where
  a0 : Nat
  a1 : Nat
  a2 : Nat
  a3 : Nat
  a4 : Nat
  deriving DecidableEq, Repr

def Addr.words (v : Addr) : List Nat := [v.a0, v.a1, v.a2, v.a3, v.a4]

/-- A `MAX_CHANNEL_TOKENS`-wide vector. -/
structure Ten (α : Type) where
  t0 : α
  t1 : α
  t2 : α
  t3 : α
  t4 : α
  t5 : α
  t6 : α
  t7 : α
  t8 : α
  t9 : α
  deriving DecidableEq, Repr

def Ten.values {α : Type} (v : Ten α) : List α :=
  [v.t0, v.t1, v.t2, v.t3, v.t4, v.t5, v.t6, v.t7, v.t8, v.t9]
def Ten.replicate {α : Type} (x : α) : Ten α := ⟨x, x, x, x, x, x, x, x, x, x⟩

theorem ten_values_length {α : Type} (v : Ten α) : v.values.length = maxChannelTokens := by
  simp [Ten.values, maxChannelTokens]

theorem hash_words_length (v : Hash) : v.words.length = digestLimbs := by
  simp [Hash.words, digestLimbs]

theorem addr_words_length (v : Addr) : v.words.length = addressLimbs := by
  simp [Addr.words, addressLimbs]

/-- The limb encoding of a digest is injective: it is a plain record projection. -/
theorem hash_words_injective (a b : Hash) (h : a.words = b.words) : a = b := by
  cases a; cases b; simp [Hash.words] at h; simp [h.1, h.2]

theorem addr_words_injective (a b : Addr) (h : a.words = b.words) : a = b := by
  cases a; cases b; simp [Addr.words] at h; simp [h.1, h.2]

/-! ## Word helpers (`split_u64`, `bytes_to_u32_words`, list flattening) -/

/-- `split_u64(value) = vec![(value >> 32) as u32, value as u32]` — big-endian pair. -/
def splitU64 (value : Nat) : List Nat := [value / wordBase % wordBase, value % wordBase]

/-- `l1_deposit_import_digest` uses `vec![amount as u32, (amount >> 32) as u32]`, i.e. the
LOW limb FIRST — the opposite order from `split_u64`. Kept as its own definition so the
asymmetry is visible rather than accidental. -/
def splitU64Lo (value : Nat) : List Nat := [value % wordBase, value / wordBase % wordBase]

theorem split_u64_length (v : Nat) : (splitU64 v).length = 2 := by simp [splitU64]
theorem split_u64_lo_length (v : Nat) : (splitU64Lo v).length = 2 := by simp [splitU64Lo]

theorem split_u64_is_big_endian_pair (v : Nat) (h : v < scalarLimit) :
    splitU64 v = [v / wordBase, v % wordBase] := by
  have : v / wordBase < wordBase := by
    unfold scalarLimit wordBase at *
    omega
  simp [splitU64, Nat.mod_eq_of_lt this]

theorem split_u64_orders_are_reversed (v : Nat) : splitU64Lo v = (splitU64 v).reverse := by
  simp [splitU64, splitU64Lo]

/-- `split_u64` is injective on the native u64 range: the two limbs recover the scalar. -/
theorem split_u64_injective (a b : Nat) (ha : a < scalarLimit) (hb : b < scalarLimit)
    (h : splitU64 a = splitU64 b) : a = b := by
  rw [split_u64_is_big_endian_pair a ha, split_u64_is_big_endian_pair b hb] at h
  simp at h
  have := h.1
  have := h.2
  omega

/-- One big-endian u32 word from up to four bytes, right-padded with zeros — exactly the
source's `padded[..chunk.len()].copy_from_slice(chunk); u32::from_be_bytes(padded)`. -/
def beWord (chunk : List Nat) : Nat :=
  chunk.getD 0 0 * 16777216 + chunk.getD 1 0 * 65536 + chunk.getD 2 0 * 256 + chunk.getD 3 0

def bytesToWordsAux : List Nat → Nat → List Nat
  | _, 0 => []
  | xs, fuel + 1 =>
    match xs with
    | [] => []
    | _ => beWord (xs.take 4) :: bytesToWordsAux (xs.drop 4) fuel

/-- `bytes_to_u32_words`: 4-byte big-endian chunks, final chunk zero-padded on the RIGHT. -/
def bytesToWords (bytes : List Nat) : List Nat := bytesToWordsAux bytes bytes.length

/-- SECURITY-RELEVANT: `bytes_to_u32_words` is NOT injective — a byte string and its
zero-extension to the next multiple of four collide. Every preimage in this file that embeds
a variable-length blob therefore prefixes the blob's LENGTH; dropping that prefix would alias
distinct messages. -/
theorem bytes_to_words_not_injective :
    bytesToWords [1] = bytesToWords [1, 0, 0, 0] ∧ ([1] : List Nat) ≠ [1, 0, 0, 0] := by
  constructor
  · decide
  · decide

/-- With the length prefix in front, the two colliding blobs above separate again. -/
theorem length_prefix_separates_padded_blobs :
    ([1] : List Nat).length :: bytesToWords [1] ≠ ([1, 0, 0, 0] : List Nat).length :: bytesToWords [1, 0, 0, 0] := by
  decide

/-- The source's uniform "length-prefixed opaque blob" segment. -/
def blobWords (bytes : List Nat) : List Nat := bytes.length :: bytesToWords bytes

def joinHashWords : List Hash → List Nat
  | [] => []
  | h :: rest => h.words ++ joinHashWords rest

theorem join_hash_words_length (xs : List Hash) :
    (joinHashWords xs).length = 8 * xs.length := by
  induction xs with
  | nil => simp [joinHashWords]
  | cons h t ih =>
    simp [joinHashWords, ih, Hash.words]
    omega

/-! ## Errors -/

inductive RecordFault where
  | zeroRegevRoot
  | reservedBurnChannel
  | memberCountRange
  | bpSlotRange
  | capacityExceeded
  | activeKeyZero (slot : Nat)
  | duplicateActiveKey
  | paddingKeyNonzero (slot : Nat)
  deriving DecidableEq, Repr

inductive SigFault where
  | countMismatch
  | slotMismatch (slot : Nat)
  | keyMismatch (slot : Nat)
  | emptyBlob (slot : Nat)
  | blobLength (slot : Nat)
  deriving DecidableEq, Repr

inductive CloseFault where
  | channelIdMismatch
  | stateDigestMismatch
  | balanceH1Mismatch
  | intmaxRootMismatch
  | nonzeroBurnTxHash
  | genesisAmountMismatch
  | unallocatedNonzero
  | freezeNonceOverflow
  deriving DecidableEq, Repr

inductive Error where
  | invalidIdLength
  | invalidIdValue
  | invalidCloseBinding (fault : CloseFault)
  | invalidChannelRecord (fault : RecordFault)
  | invalidSignatureSet (fault : SigFault)
  | invalidBalanceState
  | invalidInterChannelTx
  /-- A Rust `panic!`/index-out-of-bounds, kept distinct from a returned `Err`. -/
  | panic (site : String)
  deriving DecidableEq, Repr

abbrev Result := Except Error

def check (condition : Bool) (fault : Error) : Result Unit :=
  if condition then .ok () else .error fault

/-- Release builds wrap `u64` addition; overflow-checked builds panic. `checked_add` is a
third, explicit behaviour and is modeled separately where the source uses it. -/
inductive OverflowMode where
  | wrapping
  | checked
  deriving DecidableEq, Repr

def addOneU64 (mode : OverflowMode) (n : Nat) : Result Nat :=
  match mode with
  | .wrapping => .ok ((n + 1) % scalarLimit)
  | .checked => if n + 1 < scalarLimit then .ok (n + 1) else .error (.panic "u64 add overflow")

/-- `close_freeze_nonce.checked_add(1)` — returns `None` (a typed error) instead of panicking. -/
def checkedAddOneU64 (n : Nat) : Result Nat :=
  if n + 1 < scalarLimit then .ok (n + 1)
  else .error (.invalidCloseBinding .freezeNonceOverflow)

/-! ## Enumerations and their digest codes -/

inductive ChannelStatus where
  | active
  | closePending
  | closed
  deriving DecidableEq, Repr

def ChannelStatus.code : ChannelStatus → Nat
  | .active => 0
  | .closePending => 1
  | .closed => 2

inductive ProofBackend where
  | plonky2
  | plonky3
  deriving DecidableEq, Repr

def ProofBackend.code : ProofBackend → Nat
  | .plonky2 => 0
  | .plonky3 => 1

inductive TransitionProofRole where
  | channelStateUpdate
  | intmaxTransport
  | channelCloseSettlement
  | specialCloseSettlement
  deriving DecidableEq, Repr

def TransitionProofRole.code : TransitionProofRole → Nat
  | .channelStateUpdate => 0
  | .intmaxTransport => 1
  | .channelCloseSettlement => 2
  | .specialCloseSettlement => 3

inductive TransitionKind where
  | inChannelTransfer
  | interChannelSend
  | interChannelFundImport
  | receiverBundleApply
  | balanceRefresh
  | channelClose
  | specialClose
  | l1DepositImport
  | tokenRegister
  deriving DecidableEq, Repr

def TransitionKind.requiredStateBackend : TransitionKind → Option ProofBackend
  | .inChannelTransfer | .interChannelSend | .receiverBundleApply | .balanceRefresh =>
      some .plonky3
  | .interChannelFundImport | .channelClose | .specialClose | .l1DepositImport
  | .tokenRegister => none

def TransitionKind.requiredTransportBackend : TransitionKind → Option ProofBackend
  | .interChannelSend | .interChannelFundImport | .channelClose | .specialClose =>
      some .plonky2
  | .inChannelTransfer | .receiverBundleApply | .balanceRefresh | .l1DepositImport
  | .tokenRegister => none

theorem role_codes_distinct :
    [TransitionProofRole.channelStateUpdate.code, TransitionProofRole.intmaxTransport.code,
     TransitionProofRole.channelCloseSettlement.code,
     TransitionProofRole.specialCloseSettlement.code].Nodup := by decide

theorem status_codes_distinct :
    [ChannelStatus.active.code, ChannelStatus.closePending.code,
     ChannelStatus.closed.code].Nodup := by decide

/-- `TokenRegister` carries neither a state nor a transport proof: its whole safety argument
is the cosigners' native check plus the N-of-N signatures. -/
theorem token_register_requires_no_proof :
    TransitionKind.tokenRegister.requiredStateBackend = none ∧
    TransitionKind.tokenRegister.requiredTransportBackend = none := by
  constructor <;> rfl

theorem plonky3_state_kinds :
    ∀ k : TransitionKind, k.requiredStateBackend = some .plonky3 ↔
      (k = .inChannelTransfer ∨ k = .interChannelSend ∨ k = .receiverBundleApply ∨
       k = .balanceRefresh) := by
  intro k; cases k <;> simp [TransitionKind.requiredStateBackend]

theorem plonky2_transport_kinds :
    ∀ k : TransitionKind, k.requiredTransportBackend = some .plonky2 ↔
      (k = .interChannelSend ∨ k = .interChannelFundImport ∨ k = .channelClose ∨
       k = .specialClose) := by
  intro k; cases k <;> simp [TransitionKind.requiredTransportBackend]

/-- Every kind that requires a state proof requires the plonky3 backend, and every kind that
requires a transport proof requires plonky2 — the two backends never cross roles. -/
theorem backend_roles_never_cross (k : TransitionKind) :
    k.requiredStateBackend ≠ some .plonky2 ∧ k.requiredTransportBackend ≠ some .plonky3 := by
  cases k <;>
    exact ⟨by simp [TransitionKind.requiredStateBackend],
           by simp [TransitionKind.requiredTransportBackend]⟩

/-! ## Payload records -/

/-- A Regev ciphertext. `channel.rs` only ever calls `.digest()` on one, so the coefficient
lists are carried as opaque payload. -/
structure Ciphertext where
  c1 : List Nat
  c2 : List Nat
  deriving DecidableEq, Repr

/-- `BalanceState` as `channel.rs` sees it. Only `h1()`, `state_version` and
`settled_tx_chain` are read here; the registry/count are carried because
`apply_token_register` mutates them, and `body` stands for the per-slot ciphertext,
Regev-digest, recipient, pending-counter and accumulator material that this file never
touches (it is modeled in `Zkp.Implementation.H1Gadget`). -/
structure Balance where
  stateVersion : Nat
  settledTxChain : Hash
  registry : Ten Nat
  tokenCount : Nat
  body : Nat
  deriving DecidableEq, Repr

structure Envelope where
  role : TransitionProofRole
  backend : ProofBackend
  proof : List Nat
  deriving DecidableEq, Repr

/-- `ChannelProofEnvelope::to_digest_words`. -/
def Envelope.digestWords (e : Envelope) : List Nat :=
  [e.role.code, e.backend.code, e.proof.length] ++ bytesToWords e.proof

structure MemberSignature where
  memberSlot : Nat
  pkG : Hash
  signature : List Nat
  deriving DecidableEq, Repr

structure Fund where
  channelId : Nat
  amounts : Ten Hash
  intmaxStateRoot : Hash
  deriving DecidableEq, Repr

/-- `ChannelFund::single_token_amounts` — the genesis token position only. -/
def singleTokenAmounts (amount : Hash) : Ten Hash :=
  { Ten.replicate Hash.zero with t0 := amount }

theorem single_token_amounts_layout (a : Hash) :
    (singleTokenAmounts a).t0 = a ∧
    (singleTokenAmounts a).values.tail = List.replicate 9 Hash.zero := by
  constructor
  · rfl
  · decide

/-- SECURITY (P2/P3): funds are never summed across positions. The vector is always full
`MAX_CHANNEL_TOKENS` width in memory and in every digest. -/
theorem fund_vector_always_full_width (f : Fund) : f.amounts.values.length = maxChannelTokens :=
  ten_values_length f.amounts

structure ChannelRecord where
  channelId : Nat
  memberCount : Nat
  delegateCount : Nat
  /-- `[Bytes32; MAX_CHANNEL_MEMBERS]` as a total index function. -/
  memberPkGs : Nat → Hash
  memberPubkeysRoot : Hash
  setVersion : Nat
  bpMemberSlot : Nat
  specialClosePenalty : Hash
  closeFreezeNonce : Nat
  status : ChannelStatus
  regevPkRoot : Hash

structure ChannelState where
  channelId : Nat
  epoch : Nat
  smallBlockNumber : Nat
  closeFreezeNonce : Nat
  fund : Fund
  balance : Balance
  h2Tag : Hash
  sharedNativeNullifierRoot : Hash
  unallocatedConfirmedIncoming : Hash
  prevDigest : Hash
  digest : Hash
  memberSignatures : List MemberSignature
  deriving DecidableEq, Repr

structure SmallBlockRootMessage where
  channelId : Nat
  bpMemberSlot : Nat
  bpPkG : Hash
  smallBlockNumber : Nat
  prevSmallBlockRoot : Hash
  txTreeRoot : Hash
  stateCommitmentRoot : Hash
  mediumEpochHint : Nat
  closeFreezeNonce : Nat
  deriving DecidableEq, Repr

structure SignedSmallBlock where
  message : SmallBlockRootMessage
  signatures : List MemberSignature
  aggregatedSignatureProof : List Nat
  mediumBlockNumber : Nat
  confirmationProof : List Nat
  deriving DecidableEq, Repr

structure MerkleInclusionProof where
  siblings : List Hash
  leafIndex : Hash
  deriving DecidableEq, Repr

structure ReceiverBalanceDelta where
  receiverPkG : Hash
  amount : Ciphertext
  deriving DecidableEq, Repr

/-- Four u64 scalars (`PoseidonHashOut`). -/
structure Salt where
  s0 : Nat
  s1 : Nat
  s2 : Nat
  s3 : Nat
  deriving DecidableEq, Repr

def Salt.words (s : Salt) : List Nat :=
  splitU64 s.s0 ++ splitU64 s.s1 ++ splitU64 s.s2 ++ splitU64 s.s3

theorem salt_words_length (s : Salt) : s.words.length = 8 := by
  simp [Salt.words, splitU64]

structure InterChannelTx where
  inclusion : MerkleInclusionProof
  signedSmallBlock : SignedSmallBlock
  senderDeltaCt : Ciphertext
  sourceChannelId : Nat
  destinationChannelId : Nat
  tokenIndex : Nat
  baseNonce : Nat
  destinationBaseTransferSalt : Salt
  sourcePkG : Hash
  seal : Hash
  txHash : Hash
  intmaxTransferCommitment : Hash
  recipientMemo : List Nat
  receiverDeltas : List ReceiverBalanceDelta
  channelUpdateZkp : Envelope
  transportProof : List Nat
  senderHashSig : List Nat
  senderPkB : Hash
  deriving DecidableEq, Repr

structure CloseWithdrawal where
  channelId : Nat
  finalChannelStateDigest : Hash
  finalBalanceStateH1 : Hash
  intmaxStateRoot : Hash
  burnTxHash : Hash
  burnAmount : Hash
  zkp : List Nat
  deriving DecidableEq, Repr

structure CloseIntent where
  channelId : Nat
  closeNonce : Nat
  finalEpoch : Nat
  finalSmallBlockNumber : Nat
  closeFreezeNonce : Nat
  finalChannelStateDigest : Hash
  finalBalanceStateH1 : Hash
  channelFundSnapshot : Fund
  burnTxHash : Hash
  closeWithdrawalDigest : Hash
  snapshotMediumBlockNumber : Nat
  finalStateVersion : Nat
  finalSettledTxChain : Hash
  deriving DecidableEq, Repr

structure WithdrawalClaim where
  closeIntentDigest : Hash
  memberPkG : Hash
  tokenSlot : Nat
  l1Recipient : Addr
  userAmountCt : Ciphertext
  withdrawalNullifier : Hash
  claimProof : List Nat
  deriving DecidableEq, Repr

structure SpecialClose where
  channelId : Nat
  offendingBpMemberSlot : Nat
  offendingBpPkG : Hash
  fullySignedSmallBlockRoot : Hash
  smallBlockNumber : Nat
  signedMediumBlockNumber : Nat
  latestFinalizedMediumBlockNumber : Nat
  nonInclusionProof : List Nat
  aggregatedSignatureProof : List Nat
  deriving DecidableEq, Repr

structure CancelClose where
  closeIntentDigest : Hash
  revivedSmallBlockRoot : Hash
  revivedInterChannelTxDigest : Hash
  revivedTxHash : Hash
  revivedSeal : Hash
  cancelProof : List Nat
  deriving DecidableEq, Repr

structure PostCloseIncomingClaim where
  closeIntentDigest : Hash
  incomingTxHash : Hash
  receiverPkG : Hash
  l1Recipient : Addr
  receiverAmount : Ciphertext
  sharedNativeNullifier : Hash
  recipientMemo : List Nat
  claimProof : List Nat
  deriving DecidableEq, Repr

/-! ## Dependency boundaries

Everything this file delegates to. NONE of these is assumed injective, collision-resistant,
sound, or authenticating. -/

structure Env where
  /-- `hash_words` = `Bytes32::from_u32_slice(solidity_keccak256(words))`. -/
  hash : List Nat → Hash
  /-- `RegevCiphertext::digest`. -/
  ctDigest : Ciphertext → Hash
  /-- `BalanceState::h1` (modeled in `Zkp.Implementation.H1Gadget`). -/
  balanceH1 : Balance → Hash
  /-- `common::balance_state::tx_leaf_hash`. -/
  txLeafHash : Hash → Hash → Hash → Hash → Hash
  /-- `common::balance_state::settled_tx_chain_push`. -/
  settledTxChainPush : Hash → Hash → Hash
  /-- `BalanceState::apply_token_register`. -/
  applyTokenRegister : Balance → Nat → Result Balance

/-! ## `ChannelRecord::validate` -/

/-- The inner all-pairs scan: from index `j` upward, reject a repeat of `h` while the index is
still inside the active region. `fuel` is the number of remaining array positions. -/
def scanDistinct (keys : Nat → Hash) (h : Hash) (j : Nat) (fuel active : Nat) : Result Unit :=
  match fuel with
  | 0 => .ok ()
  | fuel + 1 =>
    if j < active ∧ h = keys j then
      .error (.invalidChannelRecord .duplicateActiveKey)
    else
      scanDistinct keys h (j + 1) fuel active

/-- The outer slot loop of `validate`, in source index order. -/
def slotLoop (keys : Nat → Hash) (i fuel active : Nat) : Result Unit :=
  match fuel with
  | 0 => .ok ()
  | fuel + 1 =>
    if i < active then
      if keys i = Hash.zero then
        .error (.invalidChannelRecord (.activeKeyZero i))
      else
        match scanDistinct keys (keys i) (i + 1) fuel active with
        | .error e => .error e
        | .ok () => slotLoop keys (i + 1) fuel active
    else if keys i ≠ Hash.zero then
      .error (.invalidChannelRecord (.paddingKeyNonzero i))
    else
      slotLoop keys (i + 1) fuel active

/-- `ChannelRecord::validate`, in the source's exact check order. -/
def validateRecord (r : ChannelRecord) : Result Unit := do
  let _ ← check (r.regevPkRoot ≠ Hash.zero) (.invalidChannelRecord .zeroRegevRoot)
  let _ ← check (r.channelId ≠ burnChannelId) (.invalidChannelRecord .reservedBurnChannel)
  let _ ← check (2 ≤ r.memberCount ∧ r.memberCount ≤ maxSigCluster)
      (.invalidChannelRecord .memberCountRange)
  let _ ← check (r.bpMemberSlot < r.memberCount) (.invalidChannelRecord .bpSlotRange)
  let _ ← check (r.memberCount + r.delegateCount ≤ maxChannelMembers)
      (.invalidChannelRecord .capacityExceeded)
  slotLoop r.memberPkGs 0 maxChannelMembers (r.memberCount + r.delegateCount)

def activeSlots (r : ChannelRecord) : Nat := r.memberCount + r.delegateCount

/-! ### Loop lemmas (never unfold the 1024-step recursion) -/

theorem scan_distinct_ok_of_fresh (keys : Nat → Hash) (h : Hash) (active : Nat) :
    ∀ fuel j, (∀ k, j ≤ k → k < active → h ≠ keys k) →
      scanDistinct keys h j fuel active = .ok () := by
  intro fuel
  induction fuel with
  | zero => intro j _; rfl
  | succ n ih =>
    intro j hyp
    unfold scanDistinct
    have hne : ¬ (j < active ∧ h = keys j) := by
      intro ⟨hj, heq⟩
      exact hyp j (Nat.le_refl j) hj heq
    simp only [if_neg hne]
    exact ih (j + 1) (fun k hk => hyp k (Nat.le_of_succ_le hk))

theorem scan_distinct_forces_fresh (keys : Nat → Hash) (h : Hash) (active : Nat) :
    ∀ fuel j, scanDistinct keys h j fuel active = .ok () →
      ∀ k, j ≤ k → k < j + fuel → k < active → h ≠ keys k := by
  intro fuel
  induction fuel with
  | zero => intro j _ k hjk hk; omega
  | succ n ih =>
    intro j accepted k hjk hk hact
    unfold scanDistinct at accepted
    by_cases hc : j < active ∧ h = keys j
    · simp only [if_pos hc] at accepted; exact absurd accepted (by simp)
    · simp only [if_neg hc] at accepted
      rcases Nat.eq_or_lt_of_le hjk with heq | hlt
      · subst heq
        intro hbad
        exact hc ⟨hact, hbad⟩
      · exact ih (j + 1) accepted k hlt (by omega) hact

theorem slot_loop_ok_of_shape (keys : Nat → Hash) (active : Nat)
    (nonzero : ∀ k, k < active → keys k ≠ Hash.zero)
    (distinct : ∀ a b, a < b → b < active → keys a ≠ keys b)
    (padded : ∀ k, active ≤ k → keys k = Hash.zero) :
    ∀ fuel i, slotLoop keys i fuel active = .ok () := by
  intro fuel
  induction fuel with
  | zero => intro i; rfl
  | succ n ih =>
    intro i
    unfold slotLoop
    by_cases hi : i < active
    · simp only [if_pos hi]
      rw [if_neg (nonzero i hi)]
      have scan : scanDistinct keys (keys i) (i + 1) n active = .ok () := by
        refine scan_distinct_ok_of_fresh keys (keys i) active n (i + 1) ?_
        intro k hk hact
        exact distinct i k (by omega) hact
      rw [scan]
      exact ih (i + 1)
    · simp only [if_neg hi]
      rw [if_neg (by simp [padded i (Nat.le_of_not_lt hi)])]
      exact ih (i + 1)

theorem slot_loop_forces_padding (keys : Nat → Hash) (active : Nat) :
    ∀ fuel i, slotLoop keys i fuel active = .ok () →
      ∀ k, i ≤ k → k < i + fuel → active ≤ k → keys k = Hash.zero := by
  intro fuel
  induction fuel with
  | zero => intro i _ k _ hk; omega
  | succ n ih =>
    intro i accepted k hik hk hact
    unfold slotLoop at accepted
    by_cases hi : i < active
    · simp only [if_pos hi] at accepted
      by_cases hz : keys i = Hash.zero
      · simp only [if_pos hz] at accepted; exact absurd accepted (by simp)
      · simp only [if_neg hz] at accepted
        cases hs : scanDistinct keys (keys i) (i + 1) n active with
        | error e => rw [hs] at accepted; exact absurd accepted (by simp)
        | ok u =>
          rw [hs] at accepted
          have hik' : i + 1 ≤ k := by omega
          exact ih (i + 1) accepted k hik' (by omega) hact
    · simp only [if_neg hi] at accepted
      by_cases hz : keys i = Hash.zero
      · rw [if_neg (by simp [hz])] at accepted
        rcases Nat.eq_or_lt_of_le hik with heq | hlt
        · subst heq; exact hz
        · exact ih (i + 1) accepted k hlt (by omega) hact
      · rw [if_pos (by simp [hz])] at accepted
        exact absurd accepted (by simp)

theorem slot_loop_forces_active_nonzero (keys : Nat → Hash) (active : Nat) :
    ∀ fuel i, slotLoop keys i fuel active = .ok () →
      ∀ k, i ≤ k → k < i + fuel → k < active → keys k ≠ Hash.zero := by
  intro fuel
  induction fuel with
  | zero => intro i _ k _ hk; omega
  | succ n ih =>
    intro i accepted k hik hk hact
    unfold slotLoop at accepted
    by_cases hi : i < active
    · simp only [if_pos hi] at accepted
      by_cases hz : keys i = Hash.zero
      · simp only [if_pos hz] at accepted; exact absurd accepted (by simp)
      · simp only [if_neg hz] at accepted
        cases hs : scanDistinct keys (keys i) (i + 1) n active with
        | error e => rw [hs] at accepted; exact absurd accepted (by simp)
        | ok u =>
          rw [hs] at accepted
          rcases Nat.eq_or_lt_of_le hik with heq | hlt
          · subst heq; exact hz
          · exact ih (i + 1) accepted k hlt (by omega) hact
    · omega

theorem slot_loop_forces_distinct (keys : Nat → Hash) (active : Nat) :
    ∀ fuel i, slotLoop keys i fuel active = .ok () →
      ∀ a b, i ≤ a → a < b → b < i + fuel → b < active → keys a ≠ keys b := by
  intro fuel
  induction fuel with
  | zero => intro i _ a b _ hab hb; omega
  | succ n ih =>
    intro i accepted a b hia hab hb hact
    unfold slotLoop at accepted
    have hia' : i < active := by omega
    simp only [if_pos hia'] at accepted
    by_cases hz : keys i = Hash.zero
    · simp only [if_pos hz] at accepted; exact absurd accepted (by simp)
    · simp only [if_neg hz] at accepted
      cases hs : scanDistinct keys (keys i) (i + 1) n active with
      | error e => rw [hs] at accepted; exact absurd accepted (by simp)
      | ok u =>
        rw [hs] at accepted
        rcases Nat.eq_or_lt_of_le hia with heq | hlt
        · subst heq
          exact scan_distinct_forces_fresh keys (keys a) active n (a + 1) hs b hab
            (by omega) hact
        · exact ih (i + 1) accepted a b hlt hab (by omega) hact

/-! ### What `validate` enforces -/

theorem validate_forces_scalar_bounds (r : ChannelRecord) (accepted : validateRecord r = .ok ()) :
    r.regevPkRoot ≠ Hash.zero ∧ r.channelId ≠ burnChannelId ∧
    2 ≤ r.memberCount ∧ r.memberCount ≤ maxSigCluster ∧
    r.bpMemberSlot < r.memberCount ∧
    r.memberCount + r.delegateCount ≤ maxChannelMembers := by
  unfold validateRecord check at accepted
  by_cases h1 : r.regevPkRoot ≠ Hash.zero
  · by_cases h2 : r.channelId ≠ burnChannelId
    · by_cases h3 : 2 ≤ r.memberCount ∧ r.memberCount ≤ maxSigCluster
      · by_cases h4 : r.bpMemberSlot < r.memberCount
        · by_cases h5 : r.memberCount + r.delegateCount ≤ maxChannelMembers
          · exact ⟨h1, h2, h3.1, h3.2, h4, h5⟩
          · simp [h1, h2, h3, h4, h5] at accepted
        · simp [h1, h2, h3, h4] at accepted
      · simp [h1, h2, h3] at accepted
    · simp [h1, h2] at accepted
  · simp [h1] at accepted

theorem validate_runs_slot_loop (r : ChannelRecord) (accepted : validateRecord r = .ok ()) :
    slotLoop r.memberPkGs 0 maxChannelMembers (activeSlots r) = .ok () := by
  unfold validateRecord check at accepted
  by_cases h1 : r.regevPkRoot ≠ Hash.zero
  · by_cases h2 : r.channelId ≠ burnChannelId
    · by_cases h3 : 2 ≤ r.memberCount ∧ r.memberCount ≤ maxSigCluster
      · by_cases h4 : r.bpMemberSlot < r.memberCount
        · by_cases h5 : r.memberCount + r.delegateCount ≤ maxChannelMembers
          · simpa [h1, h2, h3, h4, h5, activeSlots] using accepted
          · simp [h1, h2, h3, h4, h5] at accepted
        · simp [h1, h2, h3, h4] at accepted
      · simp [h1, h2, h3] at accepted
    · simp [h1, h2] at accepted
  · simp [h1] at accepted

/-- Every slot at or above `member_count + delegate_count` is exactly `Bytes32::default()`.
This is what makes the close-side member-set commitment injective on the active set. -/
theorem validate_forces_zero_padding (r : ChannelRecord) (accepted : validateRecord r = .ok ())
    (k : Nat) (hk : activeSlots r ≤ k) (hb : k < maxChannelMembers) :
    r.memberPkGs k = Hash.zero :=
  slot_loop_forces_padding r.memberPkGs (activeSlots r) maxChannelMembers 0
    (validate_runs_slot_loop r accepted) k (Nat.zero_le k) (by omega) hk

/-- Every ACTIVE slot (member or delegate) holds a nonzero pubkey hash. -/
theorem validate_forces_active_nonzero (r : ChannelRecord) (accepted : validateRecord r = .ok ())
    (k : Nat) (hk : k < activeSlots r) : r.memberPkGs k ≠ Hash.zero := by
  have hb : activeSlots r ≤ maxChannelMembers :=
    (validate_forces_scalar_bounds r accepted).2.2.2.2.2
  exact slot_loop_forces_active_nonzero r.memberPkGs (activeSlots r) maxChannelMembers 0
    (validate_runs_slot_loop r accepted) k (Nat.zero_le k) (by omega) hk

/-- Active pubkey hashes are pairwise distinct ACROSS members AND delegates — no shared-key
or duplicate-participant slot. -/
theorem validate_forces_active_distinct (r : ChannelRecord) (accepted : validateRecord r = .ok ())
    (a b : Nat) (hab : a < b) (hb : b < activeSlots r) :
    r.memberPkGs a ≠ r.memberPkGs b := by
  have hcap : activeSlots r ≤ maxChannelMembers :=
    (validate_forces_scalar_bounds r accepted).2.2.2.2.2
  exact slot_loop_forces_distinct r.memberPkGs (activeSlots r) maxChannelMembers 0
    (validate_runs_slot_loop r accepted) a b (Nat.zero_le a) hab (by omega) hb

/-- The cosigner region is a prefix of the active region, so cosigner keys inherit both
properties; the delegate region `member_count ..< active` never cosigns. -/
theorem validate_cosigner_prefix (r : ChannelRecord) (accepted : validateRecord r = .ok ()) :
    r.memberCount ≤ activeSlots r ∧ r.memberCount ≤ maxSigCluster := by
  exact ⟨by simp [activeSlots], (validate_forces_scalar_bounds r accepted).2.2.2.1⟩

/-- Sufficient condition: a record with the shape above validates. -/
theorem validate_accepts_well_shaped (r : ChannelRecord)
    (hroot : r.regevPkRoot ≠ Hash.zero)
    (hchan : r.channelId ≠ burnChannelId)
    (hcount : 2 ≤ r.memberCount ∧ r.memberCount ≤ maxSigCluster)
    (hbp : r.bpMemberSlot < r.memberCount)
    (hcap : r.memberCount + r.delegateCount ≤ maxChannelMembers)
    (nonzero : ∀ k, k < activeSlots r → r.memberPkGs k ≠ Hash.zero)
    (distinct : ∀ a b, a < b → b < activeSlots r → r.memberPkGs a ≠ r.memberPkGs b)
    (padded : ∀ k, activeSlots r ≤ k → r.memberPkGs k = Hash.zero) :
    validateRecord r = .ok () := by
  unfold validateRecord check
  simp only [if_pos hroot, if_pos hchan, if_pos hcount, if_pos hbp, if_pos hcap]
  simpa [activeSlots] using
    slot_loop_ok_of_shape r.memberPkGs (activeSlots r) nonzero distinct padded
      maxChannelMembers 0

/-! ### What `validate` does NOT guarantee -/

/-- `validate` never looks at `member_pubkeys_root`: it cannot detect a root that commits to a
different member set than `member_pk_gs`. That binding is the wallet/A11 layer's job. -/
theorem member_root_unconstrained_by_validate (r : ChannelRecord) (root : Hash) :
    validateRecord { r with memberPubkeysRoot := root } = validateRecord r := by
  rfl

/-- `validate` checks only that `regev_pk_root` is nonzero — never that it is the root over
the members' Regev keys. -/
theorem regev_root_only_checked_nonzero (r : ChannelRecord) (root : Hash)
    (h : root ≠ Hash.zero) (h' : r.regevPkRoot ≠ Hash.zero) :
    validateRecord { r with regevPkRoot := root } = validateRecord r := by
  unfold validateRecord check
  simp only [if_pos h, if_pos h']

/-- `set_version`, `status`, `special_close_penalty` and `close_freeze_nonce` are entirely
unconstrained by `validate`. -/
theorem record_metadata_unconstrained_by_validate (r : ChannelRecord)
    (v : Nat) (s : ChannelStatus) (p : Hash) (n : Nat) :
    validateRecord { r with setVersion := v, status := s, specialClosePenalty := p,
                     closeFreezeNonce := n } = validateRecord r := by
  rfl

/-- Distinct nonzero hashes are all `validate` asks of a member set: it cannot tell a real
registered cosigner set from an arbitrary set of distinct nonzero words. Concretely, ANY
permutation of the active slots also validates. -/
theorem validate_is_invariant_under_active_permutation (r : ChannelRecord)
    (swap : Nat → Nat) (hbij : ∀ k, swap (swap k) = k)
    (hfix : ∀ k, activeSlots r ≤ k → swap k = k)
    (hin : ∀ k, k < activeSlots r → swap k < activeSlots r)
    (accepted : validateRecord r = .ok ()) :
    validateRecord { r with memberPkGs := fun i => r.memberPkGs (swap i) } = .ok () := by
  have hb := validate_forces_scalar_bounds r accepted
  refine validate_accepts_well_shaped _ hb.1 hb.2.1 ⟨hb.2.2.1, hb.2.2.2.1⟩ hb.2.2.2.2.1
    hb.2.2.2.2.2 ?_ ?_ ?_
  · intro k hk
    exact validate_forces_active_nonzero r accepted (swap k) (hin k (by simpa [activeSlots] using hk))
  · intro a b hab hbb
    have ha : a < activeSlots r := by simp [activeSlots] at hbb ⊢; omega
    have hsa : swap a < activeSlots r := hin a ha
    have hsb : swap b < activeSlots r := hin b (by simpa [activeSlots] using hbb)
    have hne : swap a ≠ swap b := by
      intro heq
      have : a = b := by
        have := congrArg swap heq
        rwa [hbij a, hbij b] at this
      omega
    rcases Nat.lt_or_ge (swap a) (swap b) with hlt | hge
    · exact validate_forces_active_distinct r accepted _ _ hlt hsb
    · have hlt' : swap b < swap a := by omega
      exact fun heq =>
        validate_forces_active_distinct r accepted _ _ hlt' hsa heq.symm
  · intro k hk
    have hk' : activeSlots r ≤ k := by simpa [activeSlots] using hk
    simp only []
    rw [hfix k hk']
    exact validate_forces_zero_padding r accepted k hk'
      (by have := hb.2.2.2.2.2; by_contra hc; exact absurd (padding_out_of_range r k) (by omega))
where
  padding_out_of_range (_ : ChannelRecord) (_ : Nat) : True := trivial

/-! ## Structural signature-set validation -/

def structuralCosignPlaceholder (tag : Nat) : List Nat :=
  falconSigV1 :: List.replicate (falconCosignBlobBytes - 1) tag

theorem structural_placeholder_length (tag : Nat) :
    (structuralCosignPlaceholder tag).length = falconCosignBlobBytes := by
  simp [structuralCosignPlaceholder, falconCosignBlobBytes]

/-- The source's placeholder is deliberately NOT a signature: it only has the right length and
leading version byte. -/
theorem structural_placeholder_head (tag : Nat) :
    (structuralCosignPlaceholder tag).head? = some falconSigV1 := by
  simp [structuralCosignPlaceholder]

def slotChecks (keys : Nat → Hash) : Nat → List MemberSignature → Result Unit
  | _, [] => .ok ()
  | slot, s :: rest => do
    let _ ← check (s.memberSlot = slot) (.invalidSignatureSet (.slotMismatch slot))
    let _ ← check (s.pkG = keys slot) (.invalidSignatureSet (.keyMismatch slot))
    let _ ← check (s.signature ≠ []) (.invalidSignatureSet (.emptyBlob slot))
    slotChecks keys (slot + 1) rest

/-- `validate_member_signature_slots`: record validity, one entry per COSIGNER slot in slot
order, the registered `pk_g`, a non-empty blob. Nothing cryptographic. -/
def validateMemberSignatureSlots (r : ChannelRecord) (sigs : List MemberSignature) :
    Result Unit := do
  let _ ← validateRecord r
  let _ ← check (sigs.length = r.memberCount) (.invalidSignatureSet .countMismatch)
  slotChecks r.memberPkGs 0 sigs

def lengthChecks : Nat → List MemberSignature → Result Unit
  | _, [] => .ok ()
  | slot, s :: rest => do
    let _ ← check (s.signature.length = falconCosignBlobBytes)
      (.invalidSignatureSet (.blobLength slot))
    lengthChecks (slot + 1) rest

/-- `validate_all_member_signatures`: the slot check plus the FIXED Falcon cosign blob length. -/
def validateAllMemberSignatures (r : ChannelRecord) (sigs : List MemberSignature) :
    Result Unit := do
  let _ ← validateMemberSignatureSlots r sigs
  lengthChecks 0 sigs

theorem slot_checks_forces_shape (keys : Nat → Hash) :
    ∀ (sigs : List MemberSignature) (base : Nat), slotChecks keys base sigs = .ok () →
      ∀ i (s : MemberSignature), sigs[i]? = some s →
        s.memberSlot = base + i ∧ s.pkG = keys (base + i) ∧ s.signature ≠ [] := by
  intro sigs
  induction sigs with
  | nil => intro base _ i s hi; simp at hi
  | cons hd tl ih =>
    intro base accepted i s hi
    unfold slotChecks check at accepted
    by_cases h1 : hd.memberSlot = base
    · by_cases h2 : hd.pkG = keys base
      · by_cases h3 : hd.signature ≠ []
        · simp only [if_pos h1, if_pos h2, if_pos h3] at accepted
          simp only [Except.bind_ok] at accepted
          cases i with
          | zero => simp at hi; subst hi; exact ⟨by simpa using h1, by simpa using h2, h3⟩
          | succ n =>
            rw [List.getElem?_cons_succ] at hi
            have := ih (base + 1) accepted n s hi
            refine ⟨?_, ?_, this.2.2⟩
            · rw [this.1]; omega
            · rw [this.2.1]; congr 1; omega
        · simp [h1, h2, h3] at accepted
      · simp [h1, h2] at accepted
    · simp [h1] at accepted

theorem length_checks_forces_length :
    ∀ (sigs : List MemberSignature) (base : Nat), lengthChecks base sigs = .ok () →
      ∀ s ∈ sigs, s.signature.length = falconCosignBlobBytes := by
  intro sigs
  induction sigs with
  | nil => intro _ _ s hs; simp at hs
  | cons hd tl ih =>
    intro base accepted s hs
    unfold lengthChecks check at accepted
    by_cases h : hd.signature.length = falconCosignBlobBytes
    · simp only [if_pos h, Except.bind_ok] at accepted
      rcases List.mem_cons.mp hs with rfl | hmem
      · exact h
      · exact ih (base + 1) accepted s hmem
    · simp [h] at accepted

/-- Everything `validate_member_signature_slots` guarantees: the record is valid, there is
exactly one entry per cosigner slot, they are in slot order, and each carries the registered
pubkey hash and a non-empty blob. -/
theorem slot_validation_shape (r : ChannelRecord) (sigs : List MemberSignature)
    (accepted : validateMemberSignatureSlots r sigs = .ok ()) :
    validateRecord r = .ok () ∧ sigs.length = r.memberCount ∧
    (∀ i s, sigs[i]? = some s → s.memberSlot = i ∧ s.pkG = r.memberPkGs i ∧ s.signature ≠ []) := by
  unfold validateMemberSignatureSlots check at accepted
  cases hv : validateRecord r with
  | error e => rw [hv] at accepted; exact absurd accepted (by simp)
  | ok u =>
    rw [hv] at accepted
    simp only [Except.bind_ok] at accepted
    by_cases hlen : sigs.length = r.memberCount
    · simp only [if_pos hlen, Except.bind_ok] at accepted
      refine ⟨by cases u; exact hv, hlen, ?_⟩
      intro i s hi
      have := slot_checks_forces_shape r.memberPkGs sigs 0 accepted i s hi
      simpa using this
    · simp [hlen] at accepted

/-- `validate_all_member_signatures` = the slot shape plus the fixed blob length. -/
theorem all_signature_validation_shape (r : ChannelRecord) (sigs : List MemberSignature)
    (accepted : validateAllMemberSignatures r sigs = .ok ()) :
    validateMemberSignatureSlots r sigs = .ok () ∧
    (∀ s ∈ sigs, s.signature.length = falconCosignBlobBytes) := by
  unfold validateAllMemberSignatures at accepted
  cases hv : validateMemberSignatureSlots r sigs with
  | error e => rw [hv] at accepted; exact absurd accepted (by simp)
  | ok u =>
    rw [hv] at accepted
    simp only [Except.bind_ok] at accepted
    exact ⟨hv, length_checks_forces_length sigs 0 accepted⟩

/-- CENTRAL HONESTY RESULT: neither validator inspects the signature BYTES. Replacing every
blob by a constant run of the same length leaves both results unchanged, so no cryptographic
verification can be happening on this path. The real check is
`wallet_core::verify_all_signatures` / the close and cancel aggregation circuits. -/
theorem signature_validation_ignores_blob_contents (r : ChannelRecord)
    (sigs : List MemberSignature) (c : Nat) :
    validateAllMemberSignatures r
        (sigs.map fun s => { s with signature := List.replicate s.signature.length c }) =
      validateAllMemberSignatures r sigs := by
  have slots : ∀ (l : List MemberSignature) (base : Nat),
      slotChecks r.memberPkGs base
          (l.map fun s => { s with signature := List.replicate s.signature.length c }) =
        slotChecks r.memberPkGs base l := by
    intro l
    induction l with
    | nil => intro base; rfl
    | cons hd tl ih =>
      intro base
      simp only [List.map_cons, slotChecks]
      have hnil : (List.replicate hd.signature.length c ≠ []) ↔ (hd.signature ≠ []) := by
        constructor <;> intro h hc
        · exact h (by simp [hc])
        · apply h
          cases hh : hd.signature with
          | nil => exact absurd hh (by simpa using h)
          | cons a b => simp [hh] at hc
      simp only [ih (base + 1), hnil]
  have lens : ∀ (l : List MemberSignature) (base : Nat),
      lengthChecks base (l.map fun s => { s with signature := List.replicate s.signature.length c }) =
        lengthChecks base l := by
    intro l
    induction l with
    | nil => intro base; rfl
    | cons hd tl ih =>
      intro base
      simp only [List.map_cons, lengthChecks, List.length_replicate, ih (base + 1)]
  simp only [validateAllMemberSignatures, validateMemberSignatureSlots, List.length_map,
    slots, lens]

/-- Neither validator constrains any slot at or above `member_count`: delegates never appear
in the cosign set, and no signature exists for their slots. -/
theorem signature_set_covers_cosigners_only (r : ChannelRecord) (sigs : List MemberSignature)
    (accepted : validateMemberSignatureSlots r sigs = .ok ()) (k : Nat) (hk : r.memberCount ≤ k) :
    sigs[k]? = none := by
  have := (slot_validation_shape r sigs accepted).2.1
  exact List.getElem?_eq_none (by omega)

/-! ## Digest preimages

Each `...Preimage` is the exact `Vec<u32>` the source hands to `hash_words`. The digests
themselves apply the opaque `Env.hash` and are therefore never assumed injective. -/

/-- IMCR: `[IMCR, channel_id, bp_member_slot, split(close_freeze_nonce), split(set_version),
status, member_count, delegate_count, ALL 1024 member hashes, member_pubkeys_root,
special_close_penalty, regev_pk_root]`. -/
def recordPreimage (r : ChannelRecord) : List Nat :=
  [channelRecordDomain, r.channelId, r.bpMemberSlot] ++
  splitU64 r.closeFreezeNonce ++ splitU64 r.setVersion ++
  [r.status.code, r.memberCount, r.delegateCount] ++
  joinHashWords ((List.range maxChannelMembers).map r.memberPkGs) ++
  r.memberPubkeysRoot.words ++ r.specialClosePenalty.words ++ r.regevPkRoot.words

def ChannelRecord.signingDigest (e : Env) (r : ChannelRecord) : Hash := e.hash (recordPreimage r)

theorem record_preimage_length (r : ChannelRecord) :
    (recordPreimage r).length = 8225 := by
  simp [recordPreimage, splitU64, Hash.words, join_hash_words_length, maxChannelMembers]

/-- The record preimage hashes ALL `MAX_CHANNEL_MEMBERS` slots, not only the active ones, and
both counts sit immediately before them: the member/delegate/padding split is fixed under the
members' signature. -/
theorem record_preimage_counts_precede_all_slots (r : ChannelRecord) :
    (recordPreimage r).take 10 =
      [channelRecordDomain, r.channelId, r.bpMemberSlot,
       r.closeFreezeNonce / wordBase % wordBase, r.closeFreezeNonce % wordBase,
       r.setVersion / wordBase % wordBase, r.setVersion % wordBase,
       r.status.code, r.memberCount, r.delegateCount] ∧
    (joinHashWords ((List.range maxChannelMembers).map r.memberPkGs)).length = 8192 := by
  constructor
  · simp [recordPreimage, splitU64]
  · simp [join_hash_words_length, maxChannelMembers]

/-- `regev_pk_root` occupies the LAST eight limbs of the record preimage (detail2 H-1). -/
theorem record_preimage_regev_root_last (r : ChannelRecord) :
    (recordPreimage r).drop 8217 = r.regevPkRoot.words := by
  simp [recordPreimage, splitU64, Hash.words, join_hash_words_length, maxChannelMembers]

/-- IMCH: the channel-state signing digest preimage. `balance_state.h1()` occupies the legacy
`channel_balance_root` slot; `h2_tag` and `split(state_version)` are appended at the END, so
there is no signing target covering H1 without H2 (structural atomicity, detail2 D-3). -/
def channelStatePreimage (e : Env) (s : ChannelState) : List Nat :=
  [channelStateDomain, s.channelId] ++
  splitU64 s.epoch ++ splitU64 s.smallBlockNumber ++ splitU64 s.closeFreezeNonce ++
  [s.fund.channelId] ++ joinHashWords s.fund.amounts.values ++
  s.fund.intmaxStateRoot.words ++ (e.balanceH1 s.balance).words ++
  s.sharedNativeNullifierRoot.words ++ s.unallocatedConfirmedIncoming.words ++
  s.prevDigest.words ++ s.h2Tag.words ++ splitU64 s.balance.stateVersion

def ChannelState.signingDigest (e : Env) (s : ChannelState) : Hash :=
  e.hash (channelStatePreimage e s)

def ChannelState.withComputedDigest (e : Env) (s : ChannelState) : ChannelState :=
  { s with digest := s.signingDigest e }

theorem channel_state_preimage_length (e : Env) (s : ChannelState) :
    (channelStatePreimage e s).length = 138 := by
  simp [channelStatePreimage, splitU64, Hash.words, join_hash_words_length, Ten.values]

/-- The fund vector rides in the IMCH preimage at FULL ten-token width (80 limbs), zero-padded:
the preimage is fixed-width, never `token_count`-dependent. -/
theorem channel_state_preimage_full_fund_width (e : Env) (s : ChannelState) :
    (joinHashWords s.fund.amounts.values).length = 80 := by
  simp [join_hash_words_length, Ten.values]

/-- H2 and the balance state version are the final ten limbs. -/
theorem channel_state_preimage_h2_and_version_tail (e : Env) (s : ChannelState) :
    (channelStatePreimage e s).drop 128 = s.h2Tag.words ++ splitU64 s.balance.stateVersion := by
  simp [channelStatePreimage, splitU64, Hash.words, join_hash_words_length, Ten.values]

theorem with_computed_digest_sets_digest (e : Env) (s : ChannelState) :
    (s.withComputedDigest e).digest = e.hash (channelStatePreimage e s) := by
  rfl

/-- `with_computed_digest` changes only the `digest` field; in particular the preimage does not
read `digest`, so the assignment is not self-referential. -/
theorem with_computed_digest_preserves_everything_else (e : Env) (s : ChannelState) :
    { s.withComputedDigest e with digest := s.digest } = s := by
  rfl

theorem channel_state_preimage_ignores_digest_and_signatures (e : Env) (s : ChannelState)
    (d : Hash) (sigs : List MemberSignature) :
    channelStatePreimage e { s with digest := d, memberSignatures := sigs } =
      channelStatePreimage e s := by
  rfl

/-- IMSB small-block root message. -/
def smallBlockPreimage (m : SmallBlockRootMessage) : List Nat :=
  [smallBlockDomain, m.channelId, m.bpMemberSlot] ++ m.bpPkG.words ++
  splitU64 m.smallBlockNumber ++ m.prevSmallBlockRoot.words ++ m.txTreeRoot.words ++
  m.stateCommitmentRoot.words ++ splitU64 m.mediumEpochHint ++ splitU64 m.closeFreezeNonce

def SmallBlockRootMessage.signingDigest (e : Env) (m : SmallBlockRootMessage) : Hash :=
  e.hash (smallBlockPreimage m)

theorem small_block_preimage_length (m : SmallBlockRootMessage) :
    (smallBlockPreimage m).length = 43 := by
  simp [smallBlockPreimage, splitU64, Hash.words]

def memberSignatureWords (s : MemberSignature) : List Nat :=
  s.memberSlot :: s.pkG.words ++ blobWords s.signature

def joinSignatureWords : List MemberSignature → List Nat
  | [] => []
  | s :: rest => memberSignatureWords s ++ joinSignatureWords rest

/-- IMSS: the signed small block, including the later-attached signature and proof blobs. -/
def signedSmallBlockPreimage (e : Env) (b : SignedSmallBlock) : List Nat :=
  [signedSmallBlockDomain] ++ (b.message.signingDigest e).words ++
  splitU64 b.mediumBlockNumber ++ [b.signatures.length] ++ joinSignatureWords b.signatures ++
  blobWords b.aggregatedSignatureProof ++ blobWords b.confirmationProof

def SignedSmallBlock.signingDigest (e : Env) (b : SignedSmallBlock) : Hash :=
  e.hash (signedSmallBlockPreimage e b)

/-- `token_funds_digest`: a FIXED 92-word preimage — registry (10), token_count (1), and all
ten U256 amounts (80). Omitting unused entries would make it variable-length and alias
distinct `(registry, amounts)` pairs (TM-11). -/
def tokenFundsPreimage (registry : Ten Nat) (tokenCount : Nat) (amounts : Ten Hash) : List Nat :=
  tokenFundsDigestDomain :: registry.values ++ [tokenCount] ++ joinHashWords amounts.values

def tokenFundsDigest (e : Env) (registry : Ten Nat) (tokenCount : Nat) (amounts : Ten Hash) :
    Hash := e.hash (tokenFundsPreimage registry tokenCount amounts)

theorem token_funds_preimage_length (registry : Ten Nat) (c : Nat) (amounts : Ten Hash) :
    (tokenFundsPreimage registry c amounts).length = 92 := by
  simp [tokenFundsPreimage, Ten.values, join_hash_words_length]

/-- The TFD preimage is injective in `(registry, token_count, amounts)` BEFORE hashing: equal
preimages force equal inputs. (Digest equality would additionally need keccak injectivity,
which is NOT assumed.) -/
theorem token_funds_preimage_injective (r r' : Ten Nat) (c c' : Nat) (a a' : Ten Hash)
    (h : tokenFundsPreimage r c a = tokenFundsPreimage r' c' a') :
    r = r' ∧ c = c' ∧ a = a' := by
  cases r; cases r'; cases a; cases a'
  simp [tokenFundsPreimage, Ten.values, joinHashWords, Hash.words] at h
  obtain ⟨h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, hc, ha⟩ := h
  refine ⟨by simp [h0, h1, h2, h3, h4, h5, h6, h7, h8, h9], hc, ?_⟩
  cases ha
  rfl

/-- The full ten-lane amount vector is present regardless of `token_count`. -/
theorem token_funds_preimage_all_lanes (r : Ten Nat) (c : Nat) (a : Ten Hash) :
    (tokenFundsPreimage r c a).drop 12 = joinHashWords a.values := by
  simp [tokenFundsPreimage, Ten.values]

/-- IMCS close-state identity: a function ONLY of the channel, the member-signed final IMCH
digest, and the next freeze nonce — no coordinator-chosen metadata. -/
def closeStateIdPreimage (channelId : Nat) (finalStateDigest : Hash) (closeFreezeNonce : Nat) :
    List Nat :=
  [closeStateIdDomain, channelId] ++ finalStateDigest.words ++ splitU64 closeFreezeNonce

def closeStateId (e : Env) (channelId : Nat) (finalStateDigest : Hash)
    (closeFreezeNonce : Nat) : Hash :=
  e.hash (closeStateIdPreimage channelId finalStateDigest closeFreezeNonce)

theorem close_state_id_preimage_length (c : Nat) (d : Hash) (n : Nat) :
    (closeStateIdPreimage c d n).length = 12 := by
  simp [closeStateIdPreimage, splitU64, Hash.words]

theorem close_state_id_preimage_injective (c c' : Nat) (d d' : Hash) (n n' : Nat)
    (hn : n < scalarLimit) (hn' : n' < scalarLimit)
    (h : closeStateIdPreimage c d n = closeStateIdPreimage c' d' n') :
    c = c' ∧ d = d' ∧ n = n' := by
  simp [closeStateIdPreimage, splitU64, Hash.words] at h
  obtain ⟨hc, h0, h1, h2, h3, h4, h5, h6, h7, hhi, hlo⟩ := h
  refine ⟨hc, ?_, ?_⟩
  · cases d; cases d'; simp_all
  · have e1 : splitU64 n = splitU64 n' := by simp [splitU64, hhi, hlo]
    exact split_u64_injective n n' hn hn' e1

/-- IMCM close-side member-set commitment: `member_count` then ALL `MAX_SIG_CLUSTER` COSIGNER
hashes in slot order, padding slots contributing zero limbs. FIXED 66-word preimage. -/
def closeMemberSetPreimage (hashes : Nat → Hash) (memberCount : Nat) : List Nat :=
  [closeMemberSetDomain, memberCount] ++
  joinHashWords ((List.range maxSigCluster).map
    fun i => if i < memberCount then hashes i else Hash.zero)

def closeMemberSetCommitment (e : Env) (hashes : Nat → Hash) (memberCount : Nat) : Hash :=
  e.hash (closeMemberSetPreimage hashes memberCount)

theorem close_member_set_preimage_length (h : Nat → Hash) (c : Nat) :
    (closeMemberSetPreimage h c).length = 66 := by
  simp [closeMemberSetPreimage, join_hash_words_length, maxSigCluster]

/-- The commitment covers only the COSIGNER slots: delegates hold balances but never enter it. -/
theorem close_member_set_covers_only_cosigner_slots (h : Nat → Hash) (c : Nat)
    (g : Nat → Hash) (agree : ∀ i, i < maxSigCluster → h i = g i) :
    closeMemberSetPreimage h c = closeMemberSetPreimage g c := by
  simp only [closeMemberSetPreimage, maxSigCluster]
  congr 2
  apply List.map_congr_left
  intro i hi
  simp only [List.mem_range] at hi
  by_cases hc : i < c
  · simp [hc, agree i hi]
  · simp [hc]

/-- Padding slots contribute zero limbs, so the preimage is a function of `member_count` and
the active prefix only — this is what makes it injective on the active cosigner set given
`ChannelRecord::validate`'s zero-padding rule. -/
theorem close_member_set_zeroes_padding (h : Nat → Hash) (c : Nat) (g : Nat → Hash)
    (agree : ∀ i, i < c → h i = g i) :
    closeMemberSetPreimage h c = closeMemberSetPreimage g c := by
  simp only [closeMemberSetPreimage]
  congr 2
  apply List.map_congr_left
  intro i _
  by_cases hc : i < c
  · simp [hc, agree i hc]
  · simp [hc]

/-- IMPA-v2 in-channel pay digest: 43 words, with `token_slot` in its OWN canonical limb at
offset 26 (never bit-packed). The proof envelope is deliberately absent. -/
def channelTxPreimage (e : Env) (channelId : Nat) (prevStateDigest : Hash)
    (encAmount : Ciphertext) (nonce : Hash) (tokenSlot : Nat) (senderPkG recipientPkG : Hash) :
    List Nat :=
  [payDomainV2, channelId] ++ prevStateDigest.words ++ (e.ctDigest encAmount).words ++
  nonce.words ++ [tokenSlot] ++ senderPkG.words ++ recipientPkG.words

def channelTxSigningDigest (e : Env) (channelId : Nat) (prevStateDigest : Hash)
    (encAmount : Ciphertext) (nonce : Hash) (tokenSlot : Nat)
    (senderPkG recipientPkG : Hash) : Hash :=
  e.hash (channelTxPreimage e channelId prevStateDigest encAmount nonce tokenSlot
    senderPkG recipientPkG)

theorem channel_tx_preimage_length (e : Env) (c : Nat) (p : Hash) (ct : Ciphertext) (n : Hash)
    (t : Nat) (s r : Hash) : (channelTxPreimage e c p ct n t s r).length = 43 := by
  simp [channelTxPreimage, Hash.words]

/-- `token_slot` occupies limb 26 alone, between `nonce` and `sender_pk_g` (TM-2/TM-15). -/
theorem channel_tx_token_slot_own_limb (e : Env) (c : Nat) (p : Hash) (ct : Ciphertext)
    (n : Hash) (t : Nat) (s r : Hash) :
    (channelTxPreimage e c p ct n t s r)[26]? = some t := by
  simp [channelTxPreimage, Hash.words]

/-- Two transfers differing only in `token_slot` produce different preimages: the limb is not
absorbed into a neighbouring word. -/
theorem channel_tx_token_slot_separates (e : Env) (c : Nat) (p : Hash) (ct : Ciphertext)
    (n : Hash) (t t' : Nat) (s r : Hash) (hne : t ≠ t') :
    channelTxPreimage e c p ct n t s r ≠ channelTxPreimage e c p ct n t' s r := by
  intro h
  have := congrArg (fun l => l[26]?) h
  simp [channelTxPreimage, Hash.words] at this
  exact hne this

/-- IMI5 inter-channel tx digest. The sender hash-signature fields are excluded (this digest is
their message); the salt's four u64 scalars each get a canonical big-endian pair. -/
def interChannelTxPreimage (e : Env) (t : InterChannelTx) : List Nat :=
  [interChannelTxDomainV5] ++ (t.signedSmallBlock.message.signingDigest e).words ++
  (e.ctDigest t.senderDeltaCt).words ++ [t.sourceChannelId, t.destinationChannelId,
    t.tokenIndex, t.baseNonce] ++ t.destinationBaseTransferSalt.words ++
  t.sourcePkG.words ++ t.seal.words ++ t.txHash.words ++ t.intmaxTransferCommitment.words ++
  blobWords t.recipientMemo ++ [t.receiverDeltas.length] ++
  joinHashWords (t.receiverDeltas.map fun d => d.receiverPkG) ++
  joinHashWords (t.receiverDeltas.map fun d => e.ctDigest d.amount) ++
  t.channelUpdateZkp.digestWords ++ blobWords t.transportProof

def InterChannelTx.signingDigest (e : Env) (t : InterChannelTx) : Hash :=
  e.hash (interChannelTxPreimage e t)

/-- `tx_leaf_hash`: both wings bind user id + delta ciphertext digest. One tx has exactly one
real receiver; an empty delta list is a malformed tx. -/
def InterChannelTx.txLeafHash (e : Env) (t : InterChannelTx) : Result Hash :=
  match t.receiverDeltas with
  | [] => .error .invalidInterChannelTx
  | d :: _ => .ok (e.txLeafHash t.sourcePkG (e.ctDigest t.senderDeltaCt) d.receiverPkG
      (e.ctDigest d.amount))

/-- The `ids` word of `inter_channel_tx_hash`:
`[0,0,0,0,0, token_index, destination_channel_id, source_channel_id]`. -/
def interChannelIdsWord (source destination tokenIndex : Nat) : Hash :=
  ⟨0, 0, 0, 0, 0, tokenIndex, destination, source⟩

def interChannelTxHash (e : Env) (source destination tokenIndex : Nat)
    (txTreeRoot txLeaf : Hash) : Hash :=
  e.settledTxChainPush (interChannelIdsWord source destination tokenIndex)
    (e.settledTxChainPush txTreeRoot txLeaf)

/-- The token-FREE replay identity: the SAME fold with the token limb at zero. -/
def interChannelTxIdentity (e : Env) (source destination : Nat) (txTreeRoot txLeaf : Hash) :
    Hash := interChannelTxHash e source destination 0 txTreeRoot txLeaf

def InterChannelTx.computeTxHash (e : Env) (t : InterChannelTx) : Result Hash := do
  let leaf ← t.txLeafHash e
  pure (interChannelTxHash e t.sourceChannelId t.destinationChannelId t.tokenIndex
    t.signedSmallBlock.message.txTreeRoot leaf)

def InterChannelTx.replayIdentity (e : Env) (t : InterChannelTx) : Result Hash := do
  let leaf ← t.txLeafHash e
  pure (interChannelTxIdentity e t.sourceChannelId t.destinationChannelId
    t.signedSmallBlock.message.txTreeRoot leaf)

/-- The base `token_index` occupies ids limb 5 alone; the two channel ids occupy limbs 6 and 7.
Limbs 0..4 are constant zero. -/
theorem ids_word_layout (s d ti : Nat) :
    (interChannelIdsWord s d ti).words = [0, 0, 0, 0, 0, ti, d, s] := by rfl

/-- HIGH-1 dest binding plus TM-16 token binding: the ids word is injective in
`(source, destination, token_index)`. -/
theorem ids_word_injective (s d ti s' d' ti' : Nat)
    (h : interChannelIdsWord s d ti = interChannelIdsWord s' d' ti') :
    s = s' ∧ d = d' ∧ ti = ti' := by
  simp [interChannelIdsWord] at h
  exact ⟨h.2.2, h.2.1, h.1⟩

/-- TM-16 obligation 1: the replay identity strips the token limb, so two descriptors over the
same deltas that differ ONLY in `token_index` collide in the identity-keyed ledger. The
token-bearing hashes differ only through the ids word (which the opaque fold consumes). -/
theorem replay_identity_drops_token (e : Env) (t : InterChannelTx) (ti : Nat) :
    ({ t with tokenIndex := ti } : InterChannelTx).replayIdentity e = t.replayIdentity e := by
  rfl

theorem replay_identity_is_zero_token_hash (e : Env) (s d : Nat) (root leaf : Hash) :
    interChannelTxIdentity e s d root leaf = interChannelTxHash e s d 0 root leaf := rfl

/-- An empty receiver-delta list is a malformed tx for BOTH the token-bearing hash and the
replay identity. -/
theorem empty_receiver_deltas_rejected (e : Env) (t : InterChannelTx)
    (h : t.receiverDeltas = []) :
    t.computeTxHash e = .error .invalidInterChannelTx ∧
    t.replayIdentity e = .error .invalidInterChannelTx := by
  constructor <;>
    simp [InterChannelTx.computeTxHash, InterChannelTx.replayIdentity,
      InterChannelTx.txLeafHash, h]

/-- `tx_leaf_hash` reads only `receiver_deltas[0]`: trailing deltas are ignored entirely (the
"1 tx = 1 real receiver" convention is a caller obligation, not enforced here). -/
theorem tx_leaf_hash_uses_only_first_delta (e : Env) (t : InterChannelTx)
    (d : ReceiverBalanceDelta) (rest rest' : List ReceiverBalanceDelta) :
    ({ t with receiverDeltas := d :: rest } : InterChannelTx).txLeafHash e =
      ({ t with receiverDeltas := d :: rest' } : InterChannelTx).txLeafHash e := by
  rfl

/-- IMD2 burn descriptor. `source_channel_id` and `base_nonce` are canonical single limbs. -/
def burnDescriptorPreimage (source baseNonce : Nat) (txLeaf recipient : Hash)
    (tokenIndex : Nat) (amount : Hash) : List Nat :=
  [burnDescriptorDomain, source, baseNonce] ++ txLeaf.words ++ recipient.words ++
  [tokenIndex] ++ amount.words

def burnDescriptor (e : Env) (source baseNonce : Nat) (txLeaf recipient : Hash)
    (tokenIndex : Nat) (amount : Hash) : Hash :=
  e.hash (burnDescriptorPreimage source baseNonce txLeaf recipient tokenIndex amount)

theorem burn_descriptor_preimage_length (s n : Nat) (l r : Hash) (ti : Nat) (a : Hash) :
    (burnDescriptorPreimage s n l r ti a).length = 28 := by
  simp [burnDescriptorPreimage, Hash.words]

/-- The IMD2 preimage is injective in every one of its six inputs. -/
theorem burn_descriptor_preimage_injective (s n : Nat) (l r : Hash) (ti : Nat) (a : Hash)
    (s' n' : Nat) (l' r' : Hash) (ti' : Nat) (a' : Hash)
    (h : burnDescriptorPreimage s n l r ti a = burnDescriptorPreimage s' n' l' r' ti' a') :
    s = s' ∧ n = n' ∧ l = l' ∧ r = r' ∧ ti = ti' ∧ a = a' := by
  cases l; cases l'; cases r; cases r'; cases a; cases a'
  simp [burnDescriptorPreimage, Hash.words] at h
  simp_all

/-- IMCL close-withdrawal digest. -/
def closeWithdrawalPreimage (w : CloseWithdrawal) : List Nat :=
  [closeTxDomain, w.channelId] ++ w.finalChannelStateDigest.words ++
  w.finalBalanceStateH1.words ++ w.intmaxStateRoot.words ++ w.burnTxHash.words ++
  w.burnAmount.words

def CloseWithdrawal.signingDigest (e : Env) (w : CloseWithdrawal) : Hash :=
  e.hash (closeWithdrawalPreimage w)

theorem close_withdrawal_preimage_length (w : CloseWithdrawal) :
    (closeWithdrawalPreimage w).length = 42 := by
  simp [closeWithdrawalPreimage, Hash.words]

/-- The IMCL preimage does NOT cover `zkp`: the proof bytes are transport material. -/
theorem close_withdrawal_preimage_excludes_proof (w : CloseWithdrawal) (z : List Nat) :
    closeWithdrawalPreimage { w with zkp := z } = closeWithdrawalPreimage w := by rfl

/-- IMW2 withdrawal nullifier: 18 limbs, keyed on the slot's LEAF-BOUND Regev pk digest (never
the grindable `member_pk_g`) with `token_slot` in its own limb. -/
def withdrawalNullifierPreimage (closeIntentDigest slotRegevPkDigest : Hash)
    (tokenSlot : Nat) : List Nat :=
  [withdrawalClaimDomainV2] ++ closeIntentDigest.words ++ slotRegevPkDigest.words ++ [tokenSlot]

def deriveWithdrawalNullifier (e : Env) (closeIntentDigest slotRegevPkDigest : Hash)
    (tokenSlot : Nat) : Hash :=
  e.hash (withdrawalNullifierPreimage closeIntentDigest slotRegevPkDigest tokenSlot)

theorem withdrawal_nullifier_preimage_length (c s : Hash) (t : Nat) :
    (withdrawalNullifierPreimage c s t).length = 18 := by
  simp [withdrawalNullifierPreimage, Hash.words]

/-- Each `(close, slot Regev identity, token slot)` triple has its own preimage; in particular
the token slot is its own limb, so a member's ten per-token claims do not collapse. -/
theorem withdrawal_nullifier_preimage_injective (c s : Hash) (t : Nat)
    (c' s' : Hash) (t' : Nat)
    (h : withdrawalNullifierPreimage c s t = withdrawalNullifierPreimage c' s' t') :
    c = c' ∧ s = s' ∧ t = t' := by
  cases c; cases c'; cases s; cases s'
  simp [withdrawalNullifierPreimage, Hash.words] at h
  simp_all

/-- The nullifier preimage never mentions `member_pk_g`: the B-2 grinding surface is absent
by construction. -/
theorem withdrawal_nullifier_ignores_member_pk (e : Env) (claim : WithdrawalClaim)
    (slotDigest : Hash) (pk : Hash) :
    deriveWithdrawalNullifier e claim.closeIntentDigest slotDigest claim.tokenSlot =
      deriveWithdrawalNullifier e ({ claim with memberPkG := pk }).closeIntentDigest slotDigest
        ({ claim with memberPkG := pk }).tokenSlot := by rfl

/-- IMCW claim signing digest — `token_slot` gets its own limb immediately after `member_pk_g`,
and the preimage ends in a length-prefixed variable-length `claim_proof` tail. -/
def withdrawalClaimPreimage (e : Env) (c : WithdrawalClaim) : List Nat :=
  [withdrawalClaimDomain] ++ c.closeIntentDigest.words ++ c.memberPkG.words ++ [c.tokenSlot] ++
  c.l1Recipient.words ++ (e.ctDigest c.userAmountCt).words ++ c.withdrawalNullifier.words ++
  blobWords c.claimProof

def WithdrawalClaim.signingDigest (e : Env) (c : WithdrawalClaim) : Hash :=
  e.hash (withdrawalClaimPreimage e c)

theorem withdrawal_claim_token_slot_position (e : Env) (c : WithdrawalClaim) :
    (withdrawalClaimPreimage e c)[17]? = some c.tokenSlot := by
  simp [withdrawalClaimPreimage, Hash.words]

/-- IMSC special-close digest. -/
def specialClosePreimage (s : SpecialClose) : List Nat :=
  [specialCloseDomain, s.channelId, s.offendingBpMemberSlot] ++ s.offendingBpPkG.words ++
  s.fullySignedSmallBlockRoot.words ++ splitU64 s.smallBlockNumber ++
  splitU64 s.signedMediumBlockNumber ++ splitU64 s.latestFinalizedMediumBlockNumber ++
  blobWords s.nonInclusionProof ++ blobWords s.aggregatedSignatureProof

def SpecialClose.signingDigest (e : Env) (s : SpecialClose) : Hash :=
  e.hash (specialClosePreimage s)

/-- IMCN cancel-close digest. -/
def cancelClosePreimage (c : CancelClose) : List Nat :=
  [cancelCloseDomain] ++ c.closeIntentDigest.words ++ c.revivedSmallBlockRoot.words ++
  c.revivedInterChannelTxDigest.words ++ c.revivedTxHash.words ++ c.revivedSeal.words ++
  blobWords c.cancelProof

def CancelClose.signingDigest (e : Env) (c : CancelClose) : Hash :=
  e.hash (cancelClosePreimage c)

/-- `CancelClose::new` binds the revived tx by its BLOCK MESSAGE digest, its own IMI5 digest,
its `tx_hash` and its `seal`. -/
def CancelClose.new (e : Env) (intentDigest : Hash) (revived : InterChannelTx)
    (cancelProof : List Nat) : CancelClose :=
  { closeIntentDigest := intentDigest
    revivedSmallBlockRoot := revived.signedSmallBlock.message.signingDigest e
    revivedInterChannelTxDigest := revived.signingDigest e
    revivedTxHash := revived.txHash
    revivedSeal := revived.seal
    cancelProof := cancelProof }

theorem cancel_close_new_fields (e : Env) (d : Hash) (t : InterChannelTx) (p : List Nat) :
    (CancelClose.new e d t p).closeIntentDigest = d ∧
    (CancelClose.new e d t p).revivedTxHash = t.txHash ∧
    (CancelClose.new e d t p).revivedSeal = t.seal ∧
    (CancelClose.new e d t p).cancelProof = p := by
  exact ⟨rfl, rfl, rfl, rfl⟩

/-- IMCK post-close shared-native nullifier: keyed per late inbound TX. -/
def sharedNativeNullifierPreimage (closeIntentDigest incomingTxHash receiverPkG : Hash) :
    List Nat :=
  [postCloseNullifierDomain] ++ closeIntentDigest.words ++ incomingTxHash.words ++
  receiverPkG.words

def deriveSharedNativeNullifier (e : Env) (closeIntentDigest incomingTxHash receiverPkG : Hash) :
    Hash := e.hash (sharedNativeNullifierPreimage closeIntentDigest incomingTxHash receiverPkG)

theorem shared_native_nullifier_preimage_length (a b c : Hash) :
    (sharedNativeNullifierPreimage a b c).length = 25 := by
  simp [sharedNativeNullifierPreimage, Hash.words]

/-- The IMCK nullifier carries NO `token_slot` limb; its token separation is transitive,
through `incoming_tx_hash` (which commits ids limb 5). This model states that dependence
structurally and proves nothing about the underlying hash. -/
theorem shared_native_nullifier_has_no_token_limb (a b c : Hash) :
    (sharedNativeNullifierPreimage a b c).length =
      1 + a.words.length + b.words.length + c.words.length := by
  simp [sharedNativeNullifierPreimage, Hash.words]

/-- IMCP post-close claim digest. -/
def postCloseClaimPreimage (e : Env) (c : PostCloseIncomingClaim) : List Nat :=
  [postCloseClaimDomain] ++ c.closeIntentDigest.words ++ c.incomingTxHash.words ++
  c.receiverPkG.words ++ c.l1Recipient.words ++ (e.ctDigest c.receiverAmount).words ++
  c.sharedNativeNullifier.words ++ blobWords c.recipientMemo ++ blobWords c.claimProof

def PostCloseIncomingClaim.signingDigest (e : Env) (c : PostCloseIncomingClaim) : Hash :=
  e.hash (postCloseClaimPreimage e c)

/-- IMUF channel-balance leaf digest (also exported as `user_fund_leaf_digest`). -/
def channelBalanceLeafPreimage (e : Env) (channelId : Nat) (pkG : Hash) (ct : Ciphertext) :
    List Nat :=
  [channelBalanceLeafDomain, channelId] ++ pkG.words ++ (e.ctDigest ct).words

def channelBalanceLeafDigest (e : Env) (channelId : Nat) (pkG : Hash) (ct : Ciphertext) : Hash :=
  e.hash (channelBalanceLeafPreimage e channelId pkG ct)

def userFundLeafDigest (e : Env) (channelId : Nat) (pkG : Hash) (ct : Ciphertext) : Hash :=
  channelBalanceLeafDigest e channelId pkG ct

theorem user_fund_leaf_is_channel_balance_leaf (e : Env) (c : Nat) (p : Hash) (ct : Ciphertext) :
    userFundLeafDigest e c p ct = channelBalanceLeafDigest e c p ct := rfl

theorem channel_balance_leaf_preimage_length (e : Env) (c : Nat) (p : Hash) (ct : Ciphertext) :
    (channelBalanceLeafPreimage e c p ct).length = 18 := by
  simp [channelBalanceLeafPreimage, Hash.words]

/-- IML2 L1 deposit-import digest: 14 words, with `token_index` in its own limb between the
nullifier and the amount, and the amount split LOW LIMB FIRST. -/
def l1DepositImportPreimage (channelId : Nat) (depositNullifier : Hash) (tokenIndex : Nat)
    (amount : Nat) (depositorSlot : Nat) : List Nat :=
  [l1DepositImportDomainV2, channelId] ++ depositNullifier.words ++ [tokenIndex] ++
  splitU64Lo amount ++ [depositorSlot]

def l1DepositImportDigest (e : Env) (channelId : Nat) (depositNullifier : Hash)
    (tokenIndex amount depositorSlot : Nat) : Hash :=
  e.hash (l1DepositImportPreimage channelId depositNullifier tokenIndex amount depositorSlot)

theorem l1_deposit_import_preimage_length (c : Nat) (n : Hash) (t a s : Nat) :
    (l1DepositImportPreimage c n t a s).length = 14 := by
  simp [l1DepositImportPreimage, splitU64Lo, Hash.words]

/-- `token_index` (limb 10) and `depositor_slot` (limb 13) are separate canonical limbs; they
are never bit-packed, so distinct `(token_index, slot)` pairs cannot alias. -/
theorem l1_deposit_import_token_and_slot_own_limbs (c : Nat) (n : Hash) (t a s : Nat) :
    (l1DepositImportPreimage c n t a s)[10]? = some t ∧
    (l1DepositImportPreimage c n t a s)[13]? = some s := by
  constructor <;> simp [l1DepositImportPreimage, splitU64Lo, Hash.words]

/-! ## `CloseIntent::new` -/

def CloseIntent.new (e : Env) (finalState : ChannelState) (w : CloseWithdrawal) :
    Result CloseIntent := do
  let _ ← check (finalState.channelId = w.channelId)
    (.invalidCloseBinding .channelIdMismatch)
  let _ ← check (finalState.digest = w.finalChannelStateDigest)
    (.invalidCloseBinding .stateDigestMismatch)
  let _ ← check (e.balanceH1 finalState.balance = w.finalBalanceStateH1)
    (.invalidCloseBinding .balanceH1Mismatch)
  let _ ← check (finalState.fund.intmaxStateRoot = w.intmaxStateRoot)
    (.invalidCloseBinding .intmaxRootMismatch)
  let _ ← check (w.burnTxHash = Hash.zero) (.invalidCloseBinding .nonzeroBurnTxHash)
  let _ ← check (finalState.fund.amounts.t0 = w.burnAmount)
    (.invalidCloseBinding .genesisAmountMismatch)
  let _ ← check (finalState.unallocatedConfirmedIncoming = Hash.zero)
    (.invalidCloseBinding .unallocatedNonzero)
  let closeNonce ← checkedAddOneU64 finalState.closeFreezeNonce
  pure { channelId := finalState.channelId
         closeNonce := closeNonce
         finalEpoch := finalState.epoch
         finalSmallBlockNumber := finalState.smallBlockNumber
         closeFreezeNonce := closeNonce
         finalChannelStateDigest := finalState.digest
         finalBalanceStateH1 := e.balanceH1 finalState.balance
         channelFundSnapshot := finalState.fund
         burnTxHash := w.burnTxHash
         closeWithdrawalDigest := w.signingDigest e
         snapshotMediumBlockNumber := 0
         finalStateVersion := finalState.balance.stateVersion
         finalSettledTxChain := finalState.balance.settledTxChain }

def CloseIntent.stateId (e : Env) (i : CloseIntent) : Hash :=
  closeStateId e i.channelId i.finalChannelStateDigest i.closeFreezeNonce

def CloseIntent.signingDigest (e : Env) (i : CloseIntent) : Hash := i.stateId e

theorem close_intent_signing_digest_is_state_id (e : Env) (i : CloseIntent) :
    i.signingDigest e = i.stateId e := rfl

theorem close_intent_new_enforced_bindings (e : Env) (s : ChannelState) (w : CloseWithdrawal)
    (i : CloseIntent) (accepted : CloseIntent.new e s w = .ok i) :
    s.channelId = w.channelId ∧ s.digest = w.finalChannelStateDigest ∧
    e.balanceH1 s.balance = w.finalBalanceStateH1 ∧
    s.fund.intmaxStateRoot = w.intmaxStateRoot ∧ w.burnTxHash = Hash.zero ∧
    s.fund.amounts.t0 = w.burnAmount ∧ s.unallocatedConfirmedIncoming = Hash.zero ∧
    i.closeFreezeNonce = s.closeFreezeNonce + 1 ∧ i.closeNonce = i.closeFreezeNonce ∧
    i.snapshotMediumBlockNumber = 0 ∧ i.channelFundSnapshot = s.fund := by
  unfold CloseIntent.new check checkedAddOneU64 at accepted
  by_cases h1 : s.channelId = w.channelId
  · by_cases h2 : s.digest = w.finalChannelStateDigest
    · by_cases h3 : e.balanceH1 s.balance = w.finalBalanceStateH1
      · by_cases h4 : s.fund.intmaxStateRoot = w.intmaxStateRoot
        · by_cases h5 : w.burnTxHash = Hash.zero
          · by_cases h6 : s.fund.amounts.t0 = w.burnAmount
            · by_cases h7 : s.unallocatedConfirmedIncoming = Hash.zero
              · by_cases h8 : s.closeFreezeNonce + 1 < scalarLimit
                · simp only [if_pos h1, if_pos h2, if_pos h3, if_pos h4, if_pos h5, if_pos h6,
                    if_pos h7, if_pos h8, Except.bind_ok, Except.pure_ok] at accepted
                  cases accepted
                  exact ⟨h1, h2, h3, h4, h5, h6, h7, rfl, rfl, rfl, rfl⟩
                · simp [h1, h2, h3, h4, h5, h6, h7, h8] at accepted
              · simp [h1, h2, h3, h4, h5, h6, h7] at accepted
            · simp [h1, h2, h3, h4, h5, h6] at accepted
          · simp [h1, h2, h3, h4, h5] at accepted
        · simp [h1, h2, h3, h4] at accepted
      · simp [h1, h2, h3] at accepted
    · simp [h1, h2] at accepted
  · simp [h1] at accepted

/-- M-9: a nonzero `burn_tx_hash` is refused — a close proof does not authenticate a live
withdrawal, so the field is a hard zero sentinel. -/
theorem close_intent_rejects_nonzero_burn_tx_hash (e : Env) (s : ChannelState)
    (w : CloseWithdrawal) (h1 : s.channelId = w.channelId)
    (h2 : s.digest = w.finalChannelStateDigest)
    (h3 : e.balanceH1 s.balance = w.finalBalanceStateH1)
    (h4 : s.fund.intmaxStateRoot = w.intmaxStateRoot)
    (h : w.burnTxHash ≠ Hash.zero) :
    CloseIntent.new e s w = .error (.invalidCloseBinding .nonzeroBurnTxHash) := by
  unfold CloseIntent.new check
  simp [h1, h2, h3, h4, h]

/-- Only the GENESIS token position is compared against `burn_amount`; the other nine fund
lanes are carried into the intent snapshot WITHOUT any local check (they settle through the
per-token claim path, not the burn leg). -/
theorem close_intent_checks_only_genesis_lane (e : Env) (s : ChannelState) (w : CloseWithdrawal)
    (a : Ten Hash) (h : a.t0 = s.fund.amounts.t0) :
    CloseIntent.new e { s with fund := { s.fund with amounts := a } } w =
      (CloseIntent.new e s w).map
        (fun i => { i with channelFundSnapshot := { s.fund with amounts := a } }) := by
  unfold CloseIntent.new check checkedAddOneU64
  simp only [h]
  split <;> simp_all
  split <;> simp_all
  split <;> simp_all
  split <;> simp_all
  split <;> simp_all
  split <;> simp_all
  split <;> simp_all
  split <;> simp_all

/-! ## `token_register_next_state` -/

def tokenRegisterNextState (e : Env) (mode : OverflowMode) (prev : ChannelState)
    (tokenIndex : Nat) : Result ChannelState := do
  let balance ← e.applyTokenRegister prev.balance tokenIndex
  let epoch ← addOneU64 mode prev.epoch
  pure (ChannelState.withComputedDigest e
    { prev with epoch := epoch, balance := balance, h2Tag := Hash.zero,
                prevDigest := prev.digest, memberSignatures := [] })

/-- Everything the canonical builder fixes, and everything it carries over untouched. -/
theorem token_register_next_state_shape (e : Env) (mode : OverflowMode) (prev : ChannelState)
    (ti : Nat) (next : ChannelState) (accepted : tokenRegisterNextState e mode prev ti = .ok next) :
    next.h2Tag = Hash.zero ∧ next.prevDigest = prev.digest ∧ next.memberSignatures = [] ∧
    next.channelId = prev.channelId ∧ next.smallBlockNumber = prev.smallBlockNumber ∧
    next.closeFreezeNonce = prev.closeFreezeNonce ∧ next.fund = prev.fund ∧
    next.sharedNativeNullifierRoot = prev.sharedNativeNullifierRoot ∧
    next.unallocatedConfirmedIncoming = prev.unallocatedConfirmedIncoming ∧
    e.applyTokenRegister prev.balance ti = .ok next.balance ∧
    next.digest = e.hash (channelStatePreimage e { next with digest := next.digest }) := by
  unfold tokenRegisterNextState at accepted
  cases hb : e.applyTokenRegister prev.balance ti with
  | error err => rw [hb] at accepted; exact absurd accepted (by simp)
  | ok bal =>
    rw [hb] at accepted
    simp only [Except.bind_ok] at accepted
    cases hep : addOneU64 mode prev.epoch with
    | error err => rw [hep] at accepted; exact absurd accepted (by simp)
    | ok ep =>
      rw [hep] at accepted
      simp only [Except.bind_ok, Except.pure_ok] at accepted
      cases accepted
      refine ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, hb, ?_⟩
      rfl

/-- In an overflow-checked build the epoch advances by exactly one. -/
theorem token_register_epoch_increment (e : Env) (prev : ChannelState) (ti : Nat)
    (next : ChannelState) (hlt : prev.epoch + 1 < scalarLimit)
    (accepted : tokenRegisterNextState e .checked prev ti = .ok next) :
    next.epoch = prev.epoch + 1 := by
  unfold tokenRegisterNextState at accepted
  cases hb : e.applyTokenRegister prev.balance ti with
  | error err => rw [hb] at accepted; exact absurd accepted (by simp)
  | ok bal =>
    rw [hb] at accepted
    simp only [Except.bind_ok, addOneU64, if_pos hlt, Except.bind_ok, Except.pure_ok] at accepted
    cases accepted
    rfl

/-- A registration that the balance layer refuses (e.g. a duplicate base index) produces no
next state at all. -/
theorem token_register_propagates_balance_error (e : Env) (mode : OverflowMode)
    (prev : ChannelState) (ti : Nat) (err : Error)
    (h : e.applyTokenRegister prev.balance ti = .error err) :
    tokenRegisterNextState e mode prev ti = .error err := by
  simp [tokenRegisterNextState, h]

/-! ## `merkle_root_from_proof`

Bit `depth` of the leaf index is read from limb `7 - depth / 32` of the eight big-endian
limbs. For `depth >= 256` that index underflows in Rust `usize`, i.e. the source PANICS on a
sibling list longer than 256; the model returns an explicit panic rather than a value. -/

def indexLimb (v : Hash) (i : Nat) : Nat := v.words.getD i 0

def pathBit (index : Hash) (depth : Nat) : Result Nat :=
  if depth / 32 < 8 then .ok ((indexLimb index (7 - depth / 32) / 2 ^ (depth % 32)) % 2)
  else .error (.panic "merkle_root_from_proof leaf-index limb underflow")

def merkleFold (e : Env) (current : Hash) (index : Hash) (depth : Nat) :
    List Hash → Result Hash
  | [] => .ok current
  | sib :: rest => do
    let bit ← pathBit index depth
    let pair := if bit = 0 then current.words ++ sib.words else sib.words ++ current.words
    merkleFold e (e.hash pair) index (depth + 1) rest

def merkleRootFromProof (e : Env) (leaf : Hash) (p : MerkleInclusionProof) : Result Hash :=
  merkleFold e leaf p.leafIndex 0 p.siblings

theorem merkle_root_empty_proof (e : Env) (leaf : Hash) (idx : Hash) :
    merkleRootFromProof e leaf ⟨[], idx⟩ = .ok leaf := rfl

/-- The pairing order is decided by the index bit, and each level hashes exactly sixteen limbs. -/
theorem merkle_pair_width (e : Env) (a b : Hash) :
    (a.words ++ b.words).length = 16 ∧ (b.words ++ a.words).length = 16 := by
  constructor <;> simp [Hash.words]

/-- A sibling list longer than 256 makes the source index a negative `usize`: a panic, not an
error return. -/
theorem merkle_deep_proof_panics (e : Env) (idx : Hash) (depth : Nat) (h : 256 ≤ depth) :
    pathBit idx depth = .error (.panic "merkle_root_from_proof leaf-index limb underflow") := by
  unfold pathBit
  have : ¬ (depth / 32 < 8) := by omega
  simp [this]

/-! ## Positive examples (non-vacuous normal traces) -/

def sampleKey (n : Nat) : Hash := ⟨n + 1, n + 2, n + 3, n + 4, n + 5, n + 6, n + 7, n + 8⟩

theorem sample_keys_distinct (a b : Nat) (h : a ≠ b) : sampleKey a ≠ sampleKey b := by
  intro heq
  simp [sampleKey] at heq
  exact h heq

/-- Three cosigners, no delegates, canonical zero padding: the shape the record type intends. -/
def sampleKeyFn : Nat → Hash :=
  fun i => if i < 3 then sampleKey i else Hash.zero

def sampleRecord : ChannelRecord :=
  { channelId := 7
    memberCount := 3
    delegateCount := 0
    memberPkGs := sampleKeyFn
    memberPubkeysRoot := ⟨7, 7, 7, 7, 0, 0, 0, 0⟩
    setVersion := 0
    bpMemberSlot := 0
    specialClosePenalty := ⟨0, 0, 0, 0, 0, 0, 0, 5⟩
    closeFreezeNonce := 0
    status := .active
    regevPkRoot := ⟨1, 0, 0, 0, 0, 0, 0, 0⟩ }

theorem sample_record_active_slots : activeSlots sampleRecord = 3 := rfl

theorem sample_record_validates : validateRecord sampleRecord = .ok () := by
  refine validate_accepts_well_shaped sampleRecord (by decide) (by decide) (by decide)
    (by decide) (by decide) ?_ ?_ ?_
  · intro k hk
    rw [sample_record_active_slots] at hk
    have : k = 0 ∨ k = 1 ∨ k = 2 := by omega
    rcases this with rfl | rfl | rfl <;> decide
  · intro a b hab hb
    rw [sample_record_active_slots] at hb
    have ha : a < 3 := by omega
    show sampleKeyFn a ≠ sampleKeyFn b
    simp only [sampleKeyFn, if_pos ha, if_pos hb]
    exact sample_keys_distinct a b (by omega)
  · intro k hk
    rw [sample_record_active_slots] at hk
    show sampleKeyFn k = Hash.zero
    simp [sampleKeyFn, Nat.not_lt.mpr hk]

/-- The corresponding well-formed cosign set: three entries, slot order, registered keys,
placeholder blobs of exactly the Falcon cosign length. -/
def sampleSignatures : List MemberSignature :=
  [{ memberSlot := 0, pkG := sampleKey 0, signature := structuralCosignPlaceholder 1 },
   { memberSlot := 1, pkG := sampleKey 1, signature := structuralCosignPlaceholder 3 },
   { memberSlot := 2, pkG := sampleKey 2, signature := structuralCosignPlaceholder 5 }]

theorem sample_signature_slots_accepted :
    validateMemberSignatureSlots sampleRecord sampleSignatures = .ok () := by
  unfold validateMemberSignatureSlots check
  rw [sample_record_validates]
  simp only [Except.bind_ok]
  have hlen : sampleSignatures.length = sampleRecord.memberCount := by decide
  rw [if_pos hlen]
  simp only [Except.bind_ok]
  unfold sampleSignatures slotChecks check
  have h0 : sampleRecord.memberPkGs 0 = sampleKey 0 := by decide
  have h1 : sampleRecord.memberPkGs 1 = sampleKey 1 := by decide
  have h2 : sampleRecord.memberPkGs 2 = sampleKey 2 := by decide
  have hne : ∀ t, structuralCosignPlaceholder t ≠ [] := by
    intro t hc
    have := structural_placeholder_length t
    rw [hc] at this
    simp [falconCosignBlobBytes] at this
  simp [h0, h1, h2, hne]

/-- SECURITY-RELEVANT POSITIVE RESULT: the source's own explicitly cryptographically
MEANINGLESS blob passes BOTH structural gates. Passing them therefore says nothing about
signature validity. -/
theorem structural_placeholder_passes_length_gate :
    validateAllMemberSignatures sampleRecord sampleSignatures = .ok () := by
  unfold validateAllMemberSignatures
  rw [sample_signature_slots_accepted]
  simp only [Except.bind_ok]
  unfold sampleSignatures lengthChecks check
  simp [structural_placeholder_length]

/-- A duplicated active pubkey hash is refused: the third slot repeats slot 0's key. -/
def duplicateKeyFn : Nat → Hash :=
  fun i => if i < 2 then sampleKey i else if i = 2 then sampleKey 0 else Hash.zero

theorem duplicate_active_key_rejected :
    validateRecord { sampleRecord with memberPkGs := duplicateKeyFn } ≠ .ok () := by
  intro accepted
  have hact : activeSlots { sampleRecord with memberPkGs := duplicateKeyFn } = 3 := rfl
  have := validate_forces_active_distinct { sampleRecord with memberPkGs := duplicateKeyFn }
    accepted 0 2 (by decide) (by rw [hact]; decide)
  exact this (by decide)

/-- A nonzero padding slot is refused. -/
def dirtyPaddingFn : Nat → Hash :=
  fun i => if i < 3 then sampleKey i else if i = 5 then sampleKey 9 else Hash.zero

theorem nonzero_padding_rejected :
    validateRecord { sampleRecord with memberPkGs := dirtyPaddingFn } ≠ .ok () := by
  intro accepted
  have hact : activeSlots { sampleRecord with memberPkGs := dirtyPaddingFn } = 3 := rfl
  have := validate_forces_zero_padding { sampleRecord with memberPkGs := dirtyPaddingFn }
    accepted 5 (by rw [hact]; decide) (by decide)
  simp [dirtyPaddingFn, sampleKey, Hash.zero] at this

/-- A one-member "channel" is refused: `member_count` must be at least two, so no single
party can ever hold an N-of-N cosign set alone. -/
theorem single_member_record_rejected :
    validateRecord { sampleRecord with memberCount := 1 } ≠ .ok () := by
  intro accepted
  have := (validate_forces_scalar_bounds _ accepted).2.2.1
  simp at this

/-- More cosigners than `MAX_SIG_CLUSTER` are refused. -/
theorem oversized_sig_cluster_rejected :
    validateRecord { sampleRecord with memberCount := 9 } ≠ .ok () := by
  intro accepted
  have := (validate_forces_scalar_bounds _ accepted).2.2.2.1
  simp [maxSigCluster] at this

/-- The reserved burn channel can never host a real channel record. -/
theorem burn_channel_record_rejected :
    validateRecord { sampleRecord with channelId := burnChannelId } ≠ .ok () := by
  intro accepted
  exact (validate_forces_scalar_bounds _ accepted).2.1 rfl

/-- A member/delegate allocation exceeding the balance-slot capacity is refused. -/
theorem over_capacity_record_rejected :
    validateRecord { sampleRecord with delegateCount := 1022 } ≠ .ok () := by
  intro accepted
  have := (validate_forces_scalar_bounds _ accepted).2.2.2.2.2
  simp [maxChannelMembers] at this

/-- A signature set of the wrong size is refused even when every entry is well formed. -/
theorem short_signature_set_rejected :
    validateMemberSignatureSlots sampleRecord (sampleSignatures.take 2) ≠ .ok () := by
  intro accepted
  have := (slot_validation_shape sampleRecord _ accepted).2.1
  simp [sampleSignatures, sampleRecord] at this

end Zkp.Implementation.ChannelTypes
