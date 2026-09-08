import Std

/-!
# Channel-layer record, state and digest-preimage types

Handwritten SEMANTIC MODEL of `src/common/channel.rs` (3005 lines; production region
lines 1..1760, the remainder is `#[cfg(test)]`). This is NOT a refinement proof of the Rust
code, of `serde`, of the Rust compiler, or of any circuit or Solidity mirror. It is a local
model of the layouts, of the keccak PREIMAGES (never of keccak itself), and of the two
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
* Native u64 fields are `Nat`; `splitU64` reduces modulo the u32 base exactly like the source's
  shift/cast pair, so an out-of-range `Nat` cannot silently widen a preimage.

NAMED BOUNDARIES (undischarged, collected in `Env`): `hash` (`solidity_keccak256` /
`hash_words` — never assumed injective or collision-resistant), `ctDigest`
(`RegevCiphertext::digest`), `balanceH1` (`BalanceState::h1`, modeled in
`Zkp.Implementation.H1Gadget`), `txLeafHash` and `settledTxChainPush` (imported from
`common::balance_state`), `applyTokenRegister` (`BalanceState::apply_token_register`).
Falcon signature validity, hash-signature/SPHINCS+ validity, Merkle soundness, L1 acceptance,
proof soundness and freshness are NOT modeled and are NOT implied by anything proved here.
Every "injective" theorem below is about a PREIMAGE (a `List Nat`), never about a digest.

WHAT `validateRecord` (`ChannelRecord::validate`) DOES: nonzero `regev_pk_root`; the channel id
is not the reserved burn id; `2 <= member_count <= MAX_SIG_CLUSTER`;
`bp_member_slot < member_count`; `member_count + delegate_count <= MAX_CHANNEL_MEMBERS`; every
slot below that active bound holds a nonzero pubkey hash; those active hashes are pairwise
distinct; every slot from the bound up to `MAX_CHANNEL_MEMBERS` holds exactly
`Bytes32::default()`.
WHAT IT DOES NOT DO: it never inspects `member_pubkeys_root`, never inspects `regev_pk_root`
beyond nonzero-ness, and never inspects `set_version`, `status`, `special_close_penalty` or
`close_freeze_nonce`. It does not check that the hashes are real keys, that anyone holds the
corresponding secrets, that `member_pubkeys_root` or `regev_pk_root` commits to these very
hashes, or that the member/delegate split matches any on-chain registration — a wholly
substituted set of distinct nonzero words validates just as well
(`validate_accepts_substituted_member_set`, `member_root_unconstrained_by_validate`,
`regev_root_only_checked_nonzero`, `record_metadata_unconstrained_by_validate`).

The two signature-set validators are STRUCTURE ONLY. `validateMemberSignatureSlots` runs the
record check, then requires one entry per COSIGNER slot in slot order carrying the registered
`pk_g` and a non-empty blob; `validateAllMemberSignatures` adds the fixed Falcon cosign blob
LENGTH. `signature_validation_ignores_blob_contents` proves neither result depends on the blob
BYTES at all (only their length), so no cryptographic verification happens on this path, and
`structural_placeholder_passes_both_gates` exhibits the source's own explicit non-signature
passing both.
-/
namespace Zkp.Implementation.ChannelTypes

/-! ## Pinned constants -/

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

/-- The cosigner cap is strictly smaller than the balance-slot capacity: cosigning and holding
a balance slot are different capacities (delegates hold slots but never cosign). -/
theorem sig_cluster_below_member_capacity : maxSigCluster < maxChannelMembers := by decide

def asciiTag (a b c d : Nat) : Nat := a * 16777216 + b * 65536 + c * 256 + d

theorem channel_state_domain_is_imch :
    channelStateDomain = asciiTag 0x49 0x4d 0x43 0x48 := by decide
theorem channel_record_domain_is_imcr :
    channelRecordDomain = asciiTag 0x49 0x4d 0x43 0x52 := by decide
theorem close_state_id_domain_is_imcs :
    closeStateIdDomain = asciiTag 0x49 0x4d 0x43 0x53 := by decide
theorem close_member_set_domain_is_imcm :
    closeMemberSetDomain = asciiTag 0x49 0x4d 0x43 0x4d := by decide
theorem token_funds_domain_is_imtf :
    tokenFundsDigestDomain = asciiTag 0x49 0x4d 0x54 0x46 := by decide

def pairwiseDistinct : List Nat → Bool
  | [] => true
  | x :: xs => !(xs.contains x) && pairwiseDistinct xs

/-- Every domain separator used by a preimage in this file is distinct. The source relies on
this for schema separation between messages hashed with the same primitive. -/
theorem channel_domains_pairwise_distinct :
    pairwiseDistinct
      [channelStateDomain, smallBlockDomain, signedSmallBlockDomain, closeTxDomain,
       closeStateIdDomain, specialCloseDomain, cancelCloseDomain, postCloseClaimDomain,
       burnDescriptorDomain, postCloseNullifierDomain, withdrawalClaimDomain,
       channelBalanceLeafDomain, channelRecordDomain, closeMemberSetDomain, payDomainV2,
       l1DepositImportDomainV2, withdrawalClaimDomainV2, interChannelTxDomainV5,
       tokenFundsDigestDomain] = true := by decide

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

/-- Read eight consecutive limbs back out of a preimage. -/
def readHash (xs : List Nat) (o : Nat) : Hash :=
  ⟨xs.getD o 0, xs.getD (o + 1) 0, xs.getD (o + 2) 0, xs.getD (o + 3) 0,
   xs.getD (o + 4) 0, xs.getD (o + 5) 0, xs.getD (o + 6) 0, xs.getD (o + 7) 0⟩

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
  cases a; cases b; simp [Hash.words] at h; simp [h]

theorem addr_words_injective (a b : Addr) (h : a.words = b.words) : a = b := by
  cases a; cases b; simp [Addr.words] at h; simp [h]

theorem read_hash_of_words (v : Hash) (xs : List Nat) :
    readHash (v.words ++ xs) 0 = v := by
  cases v; rfl

/-! ## Word helpers (`split_u64`, `bytes_to_u32_words`, list flattening) -/

/-- `split_u64(value) = vec![(value >> 32) as u32, value as u32]` — big-endian pair. -/
def splitU64 (value : Nat) : List Nat := [value / wordBase % wordBase, value % wordBase]

/-- `l1_deposit_import_digest` instead uses `vec![amount as u32, (amount >> 32) as u32]`, i.e.
the LOW limb FIRST — the opposite order from `split_u64`. Kept as its own definition so the
asymmetry is visible rather than accidental. -/
def splitU64Lo (value : Nat) : List Nat := [value % wordBase, value / wordBase % wordBase]

theorem split_u64_length (v : Nat) : (splitU64 v).length = 2 := by simp [splitU64]
theorem split_u64_lo_length (v : Nat) : (splitU64Lo v).length = 2 := by simp [splitU64Lo]

theorem split_u64_is_big_endian_pair (v : Nat) (h : v < scalarLimit) :
    splitU64 v = [v / wordBase, v % wordBase] := by
  have hb : v / wordBase < wordBase := by
    have : v < wordBase * wordBase := by simpa [wordBase, scalarLimit] using h
    exact Nat.div_lt_of_lt_mul (by simpa [Nat.mul_comm] using this)
  simp [splitU64, Nat.mod_eq_of_lt hb]

theorem split_u64_orders_are_reversed (v : Nat) : splitU64Lo v = (splitU64 v).reverse := by
  simp [splitU64, splitU64Lo]

/-- `split_u64` is injective on the native u64 range: the two limbs recover the scalar. -/
theorem split_u64_injective (a b : Nat) (ha : a < scalarLimit) (hb : b < scalarLimit)
    (h : splitU64 a = splitU64 b) : a = b := by
  rw [split_u64_is_big_endian_pair a ha, split_u64_is_big_endian_pair b hb] at h
  simp only [List.cons.injEq, and_true] at h
  have hd : a / wordBase = b / wordBase := h.1
  have hm : a % wordBase = b % wordBase := h.2
  calc a = wordBase * (a / wordBase) + a % wordBase := (Nat.div_add_mod a wordBase).symm
    _ = wordBase * (b / wordBase) + b % wordBase := by rw [hd, hm]
    _ = b := Nat.div_add_mod b wordBase

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
zero-extension to the next multiple of four collide. Every preimage in this file that embeds a
variable-length blob therefore prefixes the blob's LENGTH; dropping that prefix would alias
distinct messages. -/
theorem bytes_to_words_not_injective :
    bytesToWords [1] = bytesToWords [1, 0, 0, 0] ∧ ([1] : List Nat) ≠ [1, 0, 0, 0] := by
  constructor
  · decide
  · decide

/-- With the length prefix in front, the two colliding blobs above separate again. -/
theorem length_prefix_separates_padded_blobs :
    ([1] : List Nat).length :: bytesToWords [1] ≠
      ([1, 0, 0, 0] : List Nat).length :: bytesToWords [1, 0, 0, 0] := by
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
    simp only [joinHashWords, List.length_append, ih, Hash.words, List.length_cons,
      List.length_nil]
    omega

/-- `0, 1, ..., n-1` — a local index list (this toolchain's `Std` carries no `List.range`
lemmas, and the 1024-element list must never be unfolded in a proof). -/
def indexList : Nat → List Nat
  | 0 => []
  | n + 1 => indexList n ++ [n]

theorem index_list_length (n : Nat) : (indexList n).length = n := by
  induction n with
  | zero => rfl
  | succ m ih => simp [indexList, ih]

theorem map_index_congr {α : Type} (n : Nat) (f g : Nat → α) (h : ∀ i, i < n → f i = g i) :
    (indexList n).map f = (indexList n).map g := by
  induction n with
  | zero => rfl
  | succ m ih =>
    simp only [indexList, List.map_append, List.map_cons, List.map_nil,
      ih (fun i hi => h i (by omega)), h m (by omega)]

theorem drop_append_exact {α : Type} (xs ys : List α) (n : Nat) (h : xs.length = n) :
    (xs ++ ys).drop n = ys := by
  subst h
  induction xs with
  | nil => rfl
  | cons _ t ih => simp only [List.cons_append, List.length_cons, List.drop_succ_cons]; exact ih

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
  /-- A Rust `panic!` / index-out-of-bounds, kept distinct from a returned `Err`. -/
  | panic (site : String)
  deriving DecidableEq, Repr

abbrev Result := Except Error

/-- Release builds wrap `u64` addition; overflow-checked builds panic. `checked_add` is a
third, explicit behaviour, modeled separately where the source uses it. -/
inductive OverflowMode where
  | wrapping
  | checked
  deriving DecidableEq, Repr

def addOneU64 (mode : OverflowMode) (n : Nat) : Result Nat :=
  match mode with
  | .wrapping => .ok ((n + 1) % scalarLimit)
  | .checked => if n + 1 < scalarLimit then .ok (n + 1) else .error (.panic "u64 add overflow")

/-- `close_freeze_nonce.checked_add(1)` — a typed error, never a panic. -/
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
    pairwiseDistinct
      [TransitionProofRole.channelStateUpdate.code, TransitionProofRole.intmaxTransport.code,
       TransitionProofRole.channelCloseSettlement.code,
       TransitionProofRole.specialCloseSettlement.code] = true := by decide

theorem status_codes_distinct :
    pairwiseDistinct
      [ChannelStatus.active.code, ChannelStatus.closePending.code,
       ChannelStatus.closed.code] = true := by decide

/-- `TokenRegister` carries neither a state nor a transport proof: its whole safety argument is
the cosigners' native check plus the N-of-N signatures. -/
theorem token_register_requires_no_proof :
    TransitionKind.tokenRegister.requiredStateBackend = none ∧
    TransitionKind.tokenRegister.requiredTransportBackend = none := ⟨rfl, rfl⟩

theorem plonky3_state_kinds (k : TransitionKind) :
    k.requiredStateBackend = some .plonky3 ↔
      (k = .inChannelTransfer ∨ k = .interChannelSend ∨ k = .receiverBundleApply ∨
       k = .balanceRefresh) := by
  cases k <;> simp [TransitionKind.requiredStateBackend]

theorem plonky2_transport_kinds (k : TransitionKind) :
    k.requiredTransportBackend = some .plonky2 ↔
      (k = .interChannelSend ∨ k = .interChannelFundImport ∨ k = .channelClose ∨
       k = .specialClose) := by
  cases k <;> simp [TransitionKind.requiredTransportBackend]

/-- The two backends never cross roles: a state proof is always plonky3, a transport proof
always plonky2. -/
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

/-- `BalanceState` as `channel.rs` sees it. Only `h1()`, `state_version` and `settled_tx_chain`
are read here; the registry and count are carried because `apply_token_register` mutates them,
and `body` stands for the per-slot ciphertext, Regev-digest, recipient, pending-counter and
accumulator material this file never touches (modeled in `Zkp.Implementation.H1Gadget`). -/
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

/-- `ChannelProofEnvelope::to_digest_words`: role and backend tags precede the length-prefixed
proof bytes, so a proof signed for one (role, backend) slot cannot be replayed into another. -/
def Envelope.digestWords (e : Envelope) : List Nat :=
  [e.role.code, e.backend.code, e.proof.length] ++ bytesToWords e.proof

theorem envelope_digest_words_tag_prefix (e : Envelope) :
    (e.digestWords).take 3 = [e.role.code, e.backend.code, e.proof.length] := by
  simp [Envelope.digestWords]

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
    (singleTokenAmounts a).values.drop 1 = List.replicate 9 Hash.zero := ⟨rfl, rfl⟩

/-- SECURITY (P2/P3): funds are never summed across positions. The vector is always full
`MAX_CHANNEL_TOKENS` width in memory and in every digest. -/
theorem fund_vector_always_full_width (f : Fund) :
    f.amounts.values.length = maxChannelTokens := ten_values_length f.amounts

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
  transferSeal : Hash
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
still inside the active region. `fuel` counts the remaining array positions. -/
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
        | .ok _ => slotLoop keys (i + 1) fuel active
    else if keys i ≠ Hash.zero then
      .error (.invalidChannelRecord (.paddingKeyNonzero i))
    else
      slotLoop keys (i + 1) fuel active

/-- `ChannelRecord::validate`, in the source's exact early-return order. -/
def validateRecord (r : ChannelRecord) : Result Unit :=
  if r.regevPkRoot = Hash.zero then
    .error (.invalidChannelRecord .zeroRegevRoot)
  else if r.channelId = burnChannelId then
    .error (.invalidChannelRecord .reservedBurnChannel)
  else if r.memberCount < 2 ∨ maxSigCluster < r.memberCount then
    .error (.invalidChannelRecord .memberCountRange)
  else if r.memberCount ≤ r.bpMemberSlot then
    .error (.invalidChannelRecord .bpSlotRange)
  else if maxChannelMembers < r.memberCount + r.delegateCount then
    .error (.invalidChannelRecord .capacityExceeded)
  else
    slotLoop r.memberPkGs 0 maxChannelMembers (r.memberCount + r.delegateCount)

def activeSlots (r : ChannelRecord) : Nat := r.memberCount + r.delegateCount

/-! ### Loop lemmas (the 1024-step recursion is never unfolded) -/

theorem scan_distinct_ok_of_fresh (keys : Nat → Hash) (h : Hash) (active : Nat) :
    ∀ fuel j, (∀ k, j ≤ k → k < j + fuel → k < active → h ≠ keys k) →
      scanDistinct keys h j fuel active = .ok () := by
  intro fuel
  induction fuel with
  | zero => intro j _; rfl
  | succ n ih =>
    intro j hyp
    unfold scanDistinct
    have hne : ¬ (j < active ∧ h = keys j) := by
      intro hc
      exact hyp j (Nat.le_refl j) (by omega) hc.1 hc.2
    rw [if_neg hne]
    exact ih (j + 1) (fun k hk hk2 => hyp k (Nat.le_of_succ_le hk) (by omega))

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
    · rw [if_pos hc] at accepted; simp at accepted
    rw [if_neg hc] at accepted
    rcases Nat.eq_or_lt_of_le hjk with heq | hlt
    · subst heq
      intro hbad
      exact hc ⟨hact, hbad⟩
    · exact ih (j + 1) accepted k hlt (by omega) hact

theorem slot_loop_ok_of_shape (keys : Nat → Hash) (active : Nat) :
    ∀ fuel i,
      (∀ k, i ≤ k → k < i + fuel → k < active → keys k ≠ Hash.zero) →
      (∀ a b, i ≤ a → a < b → b < i + fuel → b < active → keys a ≠ keys b) →
      (∀ k, i ≤ k → k < i + fuel → active ≤ k → keys k = Hash.zero) →
      slotLoop keys i fuel active = .ok () := by
  intro fuel
  induction fuel with
  | zero => intro i _ _ _; rfl
  | succ n ih =>
    intro i nonzero distinct padded
    unfold slotLoop
    by_cases hi : i < active
    · rw [if_pos hi, if_neg (nonzero i (Nat.le_refl i) (by omega) hi)]
      have scan : scanDistinct keys (keys i) (i + 1) n active = .ok () := by
        refine scan_distinct_ok_of_fresh keys (keys i) active n (i + 1) ?_
        intro k hk hk2 hact
        exact distinct i k (Nat.le_refl i) (by omega) (by omega) hact
      rw [scan]
      exact ih (i + 1)
        (fun k hk hk2 => nonzero k (by omega) (by omega))
        (fun a b ha hab hb => distinct a b (by omega) hab (by omega))
        (fun k hk hk2 => padded k (by omega) (by omega))
    · rw [if_neg hi, if_neg (by simp [padded i (Nat.le_refl i) (by omega) (by omega)])]
      exact ih (i + 1)
        (fun k hk hk2 => nonzero k (by omega) (by omega))
        (fun a b ha hab hb => distinct a b (by omega) hab (by omega))
        (fun k hk hk2 => padded k (by omega) (by omega))

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
    · rw [if_pos hi] at accepted
      by_cases hz : keys i = Hash.zero
      · rw [if_pos hz] at accepted; simp at accepted
      rw [if_neg hz] at accepted
      cases hs : scanDistinct keys (keys i) (i + 1) n active with
      | error e => rw [hs] at accepted; simp at accepted
      | ok u =>
        rw [hs] at accepted
        exact ih (i + 1) accepted k (by omega) (by omega) hact
    · rw [if_neg hi] at accepted
      by_cases hz : keys i = Hash.zero
      · rw [if_neg (by simp [hz])] at accepted
        rcases Nat.eq_or_lt_of_le hik with heq | hlt
        · subst heq; exact hz
        · exact ih (i + 1) accepted k hlt (by omega) hact
      · rw [if_pos (by simp [hz])] at accepted; simp at accepted

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
    · rw [if_pos hi] at accepted
      by_cases hz : keys i = Hash.zero
      · rw [if_pos hz] at accepted; simp at accepted
      rw [if_neg hz] at accepted
      cases hs : scanDistinct keys (keys i) (i + 1) n active with
      | error e => rw [hs] at accepted; simp at accepted
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
    rw [if_pos hia'] at accepted
    by_cases hz : keys i = Hash.zero
    · rw [if_pos hz] at accepted; simp at accepted
    rw [if_neg hz] at accepted
    cases hs : scanDistinct keys (keys i) (i + 1) n active with
    | error e => rw [hs] at accepted; simp at accepted
    | ok u =>
      rw [hs] at accepted
      cases u
      rcases Nat.eq_or_lt_of_le hia with heq | hlt
      · subst heq
        exact scan_distinct_forces_fresh keys (keys i) active n (i + 1) hs b hab
          (by omega) hact
      · exact ih (i + 1) accepted a b hlt hab (by omega) hact

/-! ### What `validate` enforces -/

theorem validate_forces_scalar_bounds (r : ChannelRecord)
    (accepted : validateRecord r = .ok ()) :
    r.regevPkRoot ≠ Hash.zero ∧ r.channelId ≠ burnChannelId ∧
    2 ≤ r.memberCount ∧ r.memberCount ≤ maxSigCluster ∧
    r.bpMemberSlot < r.memberCount ∧
    r.memberCount + r.delegateCount ≤ maxChannelMembers := by
  unfold validateRecord at accepted
  by_cases h1 : r.regevPkRoot = Hash.zero
  · rw [if_pos h1] at accepted; simp at accepted
  rw [if_neg h1] at accepted
  by_cases h2 : r.channelId = burnChannelId
  · rw [if_pos h2] at accepted; simp at accepted
  rw [if_neg h2] at accepted
  by_cases h3 : r.memberCount < 2 ∨ maxSigCluster < r.memberCount
  · rw [if_pos h3] at accepted; simp at accepted
  rw [if_neg h3] at accepted
  by_cases h4 : r.memberCount ≤ r.bpMemberSlot
  · rw [if_pos h4] at accepted; simp at accepted
  rw [if_neg h4] at accepted
  by_cases h5 : maxChannelMembers < r.memberCount + r.delegateCount
  · rw [if_pos h5] at accepted; simp at accepted
  exact ⟨h1, h2, by omega, by omega, by omega, by omega⟩

theorem validate_runs_slot_loop (r : ChannelRecord) (accepted : validateRecord r = .ok ()) :
    slotLoop r.memberPkGs 0 maxChannelMembers (activeSlots r) = .ok () := by
  unfold validateRecord at accepted
  by_cases h1 : r.regevPkRoot = Hash.zero
  · rw [if_pos h1] at accepted; simp at accepted
  rw [if_neg h1] at accepted
  by_cases h2 : r.channelId = burnChannelId
  · rw [if_pos h2] at accepted; simp at accepted
  rw [if_neg h2] at accepted
  by_cases h3 : r.memberCount < 2 ∨ maxSigCluster < r.memberCount
  · rw [if_pos h3] at accepted; simp at accepted
  rw [if_neg h3] at accepted
  by_cases h4 : r.memberCount ≤ r.bpMemberSlot
  · rw [if_pos h4] at accepted; simp at accepted
  rw [if_neg h4] at accepted
  by_cases h5 : maxChannelMembers < r.memberCount + r.delegateCount
  · rw [if_pos h5] at accepted; simp at accepted
  rw [if_neg h5] at accepted
  exact accepted

/-- Every slot from `member_count + delegate_count` up to `MAX_CHANNEL_MEMBERS` is exactly
`Bytes32::default()`. This is what makes the close-side member-set commitment injective on the
active set. -/
theorem validate_forces_zero_padding (r : ChannelRecord) (accepted : validateRecord r = .ok ())
    (k : Nat) (hk : activeSlots r ≤ k) (hb : k < maxChannelMembers) :
    r.memberPkGs k = Hash.zero :=
  slot_loop_forces_padding r.memberPkGs (activeSlots r) maxChannelMembers 0
    (validate_runs_slot_loop r accepted) k (Nat.zero_le k) (by omega) hk

/-- Every ACTIVE slot (member or delegate) holds a nonzero pubkey hash. -/
theorem validate_forces_active_nonzero (r : ChannelRecord)
    (accepted : validateRecord r = .ok ()) (k : Nat) (hk : k < activeSlots r) :
    r.memberPkGs k ≠ Hash.zero := by
  have hb : activeSlots r ≤ maxChannelMembers :=
    (validate_forces_scalar_bounds r accepted).2.2.2.2.2
  exact slot_loop_forces_active_nonzero r.memberPkGs (activeSlots r) maxChannelMembers 0
    (validate_runs_slot_loop r accepted) k (Nat.zero_le k) (by omega) hk

/-- Active pubkey hashes are pairwise distinct ACROSS members AND delegates — no shared-key or
duplicate-participant slot. -/
theorem validate_forces_active_distinct (r : ChannelRecord)
    (accepted : validateRecord r = .ok ()) (a b : Nat) (hab : a < b) (hb : b < activeSlots r) :
    r.memberPkGs a ≠ r.memberPkGs b := by
  have hcap : activeSlots r ≤ maxChannelMembers :=
    (validate_forces_scalar_bounds r accepted).2.2.2.2.2
  exact slot_loop_forces_distinct r.memberPkGs (activeSlots r) maxChannelMembers 0
    (validate_runs_slot_loop r accepted) a b (Nat.zero_le a) hab (by omega) hb

/-- The cosigner region is a prefix of the active region, and is capped by `MAX_SIG_CLUSTER`;
the delegate region `member_count ..< active` never cosigns. -/
theorem validate_cosigner_prefix (r : ChannelRecord) (accepted : validateRecord r = .ok ()) :
    r.memberCount ≤ activeSlots r ∧ r.memberCount ≤ maxSigCluster :=
  ⟨by simp only [activeSlots]; omega, (validate_forces_scalar_bounds r accepted).2.2.2.1⟩

/-- Sufficient condition: a record with exactly this shape validates. The slot hypotheses are
windowed to `< MAX_CHANNEL_MEMBERS` because that is the only range the source inspects. -/
theorem validate_accepts_well_shaped (r : ChannelRecord)
    (hroot : r.regevPkRoot ≠ Hash.zero)
    (hchan : r.channelId ≠ burnChannelId)
    (hlow : 2 ≤ r.memberCount) (hhigh : r.memberCount ≤ maxSigCluster)
    (hbp : r.bpMemberSlot < r.memberCount)
    (hcap : r.memberCount + r.delegateCount ≤ maxChannelMembers)
    (nonzero : ∀ k, k < activeSlots r → r.memberPkGs k ≠ Hash.zero)
    (distinct : ∀ a b, a < b → b < activeSlots r → r.memberPkGs a ≠ r.memberPkGs b)
    (padded : ∀ k, activeSlots r ≤ k → k < maxChannelMembers → r.memberPkGs k = Hash.zero) :
    validateRecord r = .ok () := by
  unfold validateRecord
  rw [if_neg hroot, if_neg hchan, if_neg (by omega : ¬ (r.memberCount < 2 ∨
    maxSigCluster < r.memberCount)), if_neg (by omega : ¬ (r.memberCount ≤ r.bpMemberSlot)),
    if_neg (by omega : ¬ (maxChannelMembers < r.memberCount + r.delegateCount))]
  refine slot_loop_ok_of_shape r.memberPkGs (activeSlots r) maxChannelMembers 0
    (fun k _ _ hact => nonzero k hact)
    (fun a b _ hab _ hact => distinct a b hab hact)
    (fun k _ hk hact => padded k hact (by omega))

/-! ### What `validate` does NOT guarantee -/

/-- `validate` never looks at `member_pubkeys_root`: it cannot detect a root committing to a
different member set than `member_pk_gs`. That binding is the wallet/A11 layer's job. -/
theorem member_root_unconstrained_by_validate (r : ChannelRecord) (root : Hash) :
    validateRecord { r with memberPubkeysRoot := root } = validateRecord r := rfl

/-- `validate` checks only that `regev_pk_root` is nonzero — never that it is the root over the
members' Regev keys. -/
theorem regev_root_only_checked_nonzero (r : ChannelRecord) (root : Hash)
    (h : root ≠ Hash.zero) (h' : r.regevPkRoot ≠ Hash.zero) :
    validateRecord { r with regevPkRoot := root } = validateRecord r := by
  unfold validateRecord
  rw [if_neg h, if_neg h']

/-- `set_version`, `status`, `special_close_penalty` and `close_freeze_nonce` are entirely
unconstrained by `validate`. -/
theorem record_metadata_unconstrained_by_validate (r : ChannelRecord)
    (v : Nat) (s : ChannelStatus) (p : Hash) (n : Nat) :
    validateRecord { r with setVersion := v, status := s, specialClosePenalty := p, closeFreezeNonce := n } = validateRecord r := rfl

/-- The member set of a valid record can be swapped wholesale for ANY other set of distinct
nonzero words, leaving both roots untouched, and `validate` still accepts. Structural validity
is therefore no evidence at all that the recorded keys are the registered ones. -/
theorem validate_accepts_substituted_member_set (r : ChannelRecord) (g : Nat → Hash)
    (accepted : validateRecord r = .ok ())
    (nonzero : ∀ k, k < activeSlots r → g k ≠ Hash.zero)
    (distinct : ∀ a b, a < b → b < activeSlots r → g a ≠ g b)
    (padded : ∀ k, activeSlots r ≤ k → k < maxChannelMembers → g k = Hash.zero) :
    validateRecord { r with memberPkGs := g } = .ok () := by
  have hb := validate_forces_scalar_bounds r accepted
  exact validate_accepts_well_shaped { r with memberPkGs := g } hb.1 hb.2.1 hb.2.2.1
    hb.2.2.2.1 hb.2.2.2.2.1 hb.2.2.2.2.2 nonzero distinct padded

/-! ## Structural signature-set validation -/

/-- `structural_cosign_placeholder`: the v1 version byte followed by filler, of exactly the
Falcon cosign blob length. Explicitly NOT a signature. -/
def structuralCosignPlaceholder (tag : Nat) : List Nat :=
  falconSigV1 :: List.replicate (falconCosignBlobBytes - 1) tag

theorem structural_placeholder_length (tag : Nat) :
    (structuralCosignPlaceholder tag).length = falconCosignBlobBytes := by
  simp [structuralCosignPlaceholder, falconCosignBlobBytes]

theorem structural_placeholder_head (tag : Nat) :
    (structuralCosignPlaceholder tag).head? = some falconSigV1 := by
  simp [structuralCosignPlaceholder]

theorem structural_placeholder_nonempty (tag : Nat) :
    structuralCosignPlaceholder tag ≠ [] := by
  simp [structuralCosignPlaceholder]

def slotChecks (keys : Nat → Hash) : Nat → List MemberSignature → Result Unit
  | _, [] => .ok ()
  | slot, s :: rest =>
    if s.memberSlot ≠ slot then .error (.invalidSignatureSet (.slotMismatch slot))
    else if s.pkG ≠ keys slot then .error (.invalidSignatureSet (.keyMismatch slot))
    else if s.signature = [] then .error (.invalidSignatureSet (.emptyBlob slot))
    else slotChecks keys (slot + 1) rest

/-- `validate_member_signature_slots`: record validity, one entry per COSIGNER slot in slot
order, the registered `pk_g`, a non-empty blob. Nothing cryptographic. -/
def validateMemberSignatureSlots (r : ChannelRecord) (sigs : List MemberSignature) :
    Result Unit :=
  match validateRecord r with
  | .error e => .error e
  | .ok _ =>
    if sigs.length ≠ r.memberCount then .error (.invalidSignatureSet .countMismatch)
    else slotChecks r.memberPkGs 0 sigs

def lengthChecks : Nat → List MemberSignature → Result Unit
  | _, [] => .ok ()
  | slot, s :: rest =>
    if s.signature.length ≠ falconCosignBlobBytes then
      .error (.invalidSignatureSet (.blobLength slot))
    else lengthChecks (slot + 1) rest

/-- `validate_all_member_signatures`: the slot check plus the FIXED Falcon cosign blob length. -/
def validateAllMemberSignatures (r : ChannelRecord) (sigs : List MemberSignature) :
    Result Unit :=
  match validateMemberSignatureSlots r sigs with
  | .error e => .error e
  | .ok _ => lengthChecks 0 sigs

theorem slot_checks_forces_shape (keys : Nat → Hash) :
    ∀ (sigs : List MemberSignature) (base : Nat), slotChecks keys base sigs = .ok () →
      ∀ i (s : MemberSignature), sigs[i]? = some s →
        s.memberSlot = base + i ∧ s.pkG = keys (base + i) ∧ s.signature ≠ [] := by
  intro sigs
  induction sigs with
  | nil => intro base _ i s hi; simp at hi
  | cons hd tl ih =>
    intro base accepted i s hi
    simp only [slotChecks] at accepted
    by_cases h1 : hd.memberSlot ≠ base
    · rw [if_pos h1] at accepted; simp at accepted
    rw [if_neg h1] at accepted
    by_cases h2 : hd.pkG ≠ keys base
    · rw [if_pos h2] at accepted; simp at accepted
    rw [if_neg h2] at accepted
    by_cases h3 : hd.signature = []
    · rw [if_pos h3] at accepted; simp at accepted
    rw [if_neg h3] at accepted
    cases i with
    | zero =>
      simp only [List.getElem?_cons_zero, Option.some.injEq] at hi
      subst hi
      simp only [Nat.add_zero]
      exact ⟨by simpa using h1, by simpa using h2, h3⟩
    | succ n =>
      rw [List.getElem?_cons_succ] at hi
      have hres := ih (base + 1) accepted n s hi
      refine ⟨?_, ?_, hres.2.2⟩
      · rw [hres.1]; omega
      · rw [hres.2.1]; congr 1; omega

theorem length_checks_forces_length :
    ∀ (sigs : List MemberSignature) (base : Nat), lengthChecks base sigs = .ok () →
      ∀ s ∈ sigs, s.signature.length = falconCosignBlobBytes := by
  intro sigs
  induction sigs with
  | nil => intro _ _ s hs; simp at hs
  | cons hd tl ih =>
    intro base accepted s hs
    simp only [lengthChecks] at accepted
    by_cases h : hd.signature.length ≠ falconCosignBlobBytes
    · rw [if_pos h] at accepted; simp at accepted
    rw [if_neg h] at accepted
    rcases List.mem_cons.mp hs with rfl | hmem
    · simpa using h
    · exact ih (base + 1) accepted s hmem

/-- Everything `validate_member_signature_slots` guarantees: the record is valid, there is
exactly one entry per cosigner slot, they are in slot order, and each carries the registered
pubkey hash and a non-empty blob. -/
theorem slot_validation_shape (r : ChannelRecord) (sigs : List MemberSignature)
    (accepted : validateMemberSignatureSlots r sigs = .ok ()) :
    validateRecord r = .ok () ∧ sigs.length = r.memberCount ∧
    (∀ i s, sigs[i]? = some s →
      s.memberSlot = i ∧ s.pkG = r.memberPkGs i ∧ s.signature ≠ []) := by
  unfold validateMemberSignatureSlots at accepted
  cases hv : validateRecord r with
  | error e => rw [hv] at accepted; simp at accepted
  | ok u =>
    rw [hv] at accepted
    cases u
    by_cases hlen : sigs.length ≠ r.memberCount
    · rw [if_pos hlen] at accepted; simp at accepted
    rw [if_neg hlen] at accepted
    refine ⟨rfl, by simpa using hlen, ?_⟩
    intro i s hi
    simpa using slot_checks_forces_shape r.memberPkGs sigs 0 accepted i s hi

/-- `validate_all_member_signatures` = the slot shape plus the fixed blob length. -/
theorem all_signature_validation_shape (r : ChannelRecord) (sigs : List MemberSignature)
    (accepted : validateAllMemberSignatures r sigs = .ok ()) :
    validateMemberSignatureSlots r sigs = .ok () ∧
    (∀ s ∈ sigs, s.signature.length = falconCosignBlobBytes) := by
  unfold validateAllMemberSignatures at accepted
  cases hv : validateMemberSignatureSlots r sigs with
  | error e => rw [hv] at accepted; simp at accepted
  | ok u =>
    rw [hv] at accepted
    cases u
    exact ⟨rfl, length_checks_forces_length sigs 0 accepted⟩

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
      have hnil : (List.replicate hd.signature.length c = []) = (hd.signature = []) := by
        cases hd.signature <;> simp
      simp only [List.map_cons, slotChecks, hnil, ih (base + 1)]
  have lens : ∀ (l : List MemberSignature) (base : Nat),
      lengthChecks base
          (l.map fun s => { s with signature := List.replicate s.signature.length c }) =
        lengthChecks base l := by
    intro l
    induction l with
    | nil => intro base; rfl
    | cons hd tl ih =>
      intro base
      simp only [List.map_cons, lengthChecks, List.length_replicate, ih (base + 1)]
  simp only [validateAllMemberSignatures, validateMemberSignatureSlots, List.length_map,
    slots, lens]

/-- Neither validator constrains any slot at or above `member_count`: delegates never appear in
the cosign set, and no signature exists for their slots. -/
theorem signature_set_covers_cosigners_only (r : ChannelRecord) (sigs : List MemberSignature)
    (accepted : validateMemberSignatureSlots r sigs = .ok ()) (k : Nat)
    (hk : r.memberCount ≤ k) : sigs[k]? = none := by
  have hlen := (slot_validation_shape r sigs accepted).2.1
  exact List.getElem?_eq_none (by omega)

/-! ## Digest preimages

Each `...Preimage` is the exact `Vec<u32>` the source hands to `hash_words`. The digests apply
the opaque `Env.hash` and are therefore never assumed injective. -/

/-- IMCR: `[IMCR, channel_id, bp_member_slot, split(close_freeze_nonce), split(set_version),
status, member_count, delegate_count, ALL 1024 member hashes, member_pubkeys_root,
special_close_penalty, regev_pk_root]`. -/
def recordPreimage (r : ChannelRecord) : List Nat :=
  [channelRecordDomain, r.channelId, r.bpMemberSlot] ++
  splitU64 r.closeFreezeNonce ++ splitU64 r.setVersion ++
  [r.status.code, r.memberCount, r.delegateCount] ++
  joinHashWords ((indexList maxChannelMembers).map r.memberPkGs) ++
  r.memberPubkeysRoot.words ++ r.specialClosePenalty.words ++ r.regevPkRoot.words

def ChannelRecord.signingDigest (e : Env) (r : ChannelRecord) : Hash := e.hash (recordPreimage r)

theorem record_preimage_length (r : ChannelRecord) : (recordPreimage r).length = 8226 := by
  simp [recordPreimage, splitU64, Hash.words, join_hash_words_length, maxChannelMembers, index_list_length]

/-- The record preimage hashes ALL `MAX_CHANNEL_MEMBERS` slots, not only the active ones, and
both counts sit immediately before them: the member/delegate/padding split is fixed under the
members' signature. -/
theorem record_preimage_counts_precede_all_slots (r : ChannelRecord) :
    (recordPreimage r).take 10 =
      [channelRecordDomain, r.channelId, r.bpMemberSlot,
       r.closeFreezeNonce / wordBase % wordBase, r.closeFreezeNonce % wordBase,
       r.setVersion / wordBase % wordBase, r.setVersion % wordBase,
       r.status.code, r.memberCount, r.delegateCount] ∧
    (joinHashWords ((indexList maxChannelMembers).map r.memberPkGs)).length = 8192 := by
  constructor
  · simp [recordPreimage, splitU64]
  · simp [join_hash_words_length, maxChannelMembers, index_list_length]

/-- `regev_pk_root` occupies the LAST eight limbs of the record preimage (detail2 H-1). -/
theorem record_preimage_regev_root_last (r : ChannelRecord) :
    (recordPreimage r).drop 8218 = r.regevPkRoot.words := by
  unfold recordPreimage
  refine drop_append_exact _ _ 8218 ?_
  simp [splitU64, Hash.words, join_hash_words_length, maxChannelMembers, index_list_length]

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
    (channelStatePreimage e s).length = 139 := by
  simp [channelStatePreimage, splitU64, Hash.words, join_hash_words_length, Ten.values]

/-- The fund vector rides in the IMCH preimage at FULL ten-token width (80 limbs), zero-padded:
the preimage is fixed-width, never `token_count`-dependent. -/
theorem channel_state_preimage_full_fund_width (s : ChannelState) :
    (joinHashWords s.fund.amounts.values).length = 80 := by
  simp [join_hash_words_length, Ten.values]

/-- H2 and the balance state version are the final ten limbs. -/
theorem channel_state_preimage_h2_and_version_tail (e : Env) (s : ChannelState) :
    (channelStatePreimage e s).drop 129 = s.h2Tag.words ++ splitU64 s.balance.stateVersion := by
  unfold channelStatePreimage
  rw [List.append_assoc _ s.h2Tag.words (splitU64 s.balance.stateVersion)]
  refine drop_append_exact _ _ 129 ?_
  simp [splitU64, Hash.words, join_hash_words_length, Ten.values]

theorem with_computed_digest_sets_digest (e : Env) (s : ChannelState) :
    (s.withComputedDigest e).digest = e.hash (channelStatePreimage e s) := rfl

/-- `with_computed_digest` changes only the `digest` field, and the preimage does not read
`digest`, so the assignment is not self-referential. -/
theorem with_computed_digest_preserves_everything_else (e : Env) (s : ChannelState) :
    { s.withComputedDigest e with digest := s.digest } = s := rfl

/-- The IMCH preimage covers neither the stored `digest` nor `member_signatures`: signatures
are over the digest, and the digest is not part of its own preimage. -/
theorem channel_state_preimage_ignores_digest_and_signatures (e : Env) (s : ChannelState)
    (d : Hash) (sigs : List MemberSignature) :
    channelStatePreimage e { s with digest := d, memberSignatures := sigs } =
      channelStatePreimage e s := rfl

/-- IMSB small-block root message. -/
def smallBlockPreimage (m : SmallBlockRootMessage) : List Nat :=
  [smallBlockDomain, m.channelId, m.bpMemberSlot] ++ m.bpPkG.words ++
  splitU64 m.smallBlockNumber ++ m.prevSmallBlockRoot.words ++ m.txTreeRoot.words ++
  m.stateCommitmentRoot.words ++ splitU64 m.mediumEpochHint ++ splitU64 m.closeFreezeNonce

def SmallBlockRootMessage.signingDigest (e : Env) (m : SmallBlockRootMessage) : Hash :=
  e.hash (smallBlockPreimage m)

theorem small_block_preimage_length (m : SmallBlockRootMessage) :
    (smallBlockPreimage m).length = 41 := by
  simp [smallBlockPreimage, splitU64, Hash.words]

def memberSignatureWords (s : MemberSignature) : List Nat :=
  s.memberSlot :: s.pkG.words ++ blobWords s.signature

def joinSignatureWords : List MemberSignature → List Nat
  | [] => []
  | s :: rest => memberSignatureWords s ++ joinSignatureWords rest

/-- IMSS: the signed small block, INCLUDING the later-attached signature and proof blobs. This
is why `InterChannelTx::signing_digest` binds the block MESSAGE digest instead. -/
def signedSmallBlockPreimage (e : Env) (b : SignedSmallBlock) : List Nat :=
  [signedSmallBlockDomain] ++ (b.message.signingDigest e).words ++
  splitU64 b.mediumBlockNumber ++ [b.signatures.length] ++ joinSignatureWords b.signatures ++
  blobWords b.aggregatedSignatureProof ++ blobWords b.confirmationProof

def SignedSmallBlock.signingDigest (e : Env) (b : SignedSmallBlock) : Hash :=
  e.hash (signedSmallBlockPreimage e b)

/-- `token_funds_digest`: a FIXED 92-word preimage — registry (10), token_count (1) and all ten
U256 amounts (80). Omitting unused entries would make it variable-length and alias distinct
`(registry, amounts)` pairs (TM-11). -/
def tokenFundsPreimage (registry : Ten Nat) (tokenCount : Nat) (amounts : Ten Hash) : List Nat :=
  tokenFundsDigestDomain :: registry.values ++ [tokenCount] ++ joinHashWords amounts.values

def tokenFundsDigest (e : Env) (registry : Ten Nat) (tokenCount : Nat) (amounts : Ten Hash) :
    Hash := e.hash (tokenFundsPreimage registry tokenCount amounts)

theorem token_funds_preimage_length (registry : Ten Nat) (c : Nat) (amounts : Ten Hash) :
    (tokenFundsPreimage registry c amounts).length = 92 := by
  simp [tokenFundsPreimage, Ten.values, join_hash_words_length]

def tokenFundsDecode (xs : List Nat) : Ten Nat × Nat × Ten Hash :=
  (⟨xs.getD 1 0, xs.getD 2 0, xs.getD 3 0, xs.getD 4 0, xs.getD 5 0, xs.getD 6 0, xs.getD 7 0,
    xs.getD 8 0, xs.getD 9 0, xs.getD 10 0⟩,
   xs.getD 11 0,
   ⟨readHash xs 12, readHash xs 20, readHash xs 28, readHash xs 36, readHash xs 44,
    readHash xs 52, readHash xs 60, readHash xs 68, readHash xs 76, readHash xs 84⟩)

theorem token_funds_preimage_roundtrip (r : Ten Nat) (c : Nat) (a : Ten Hash) :
    tokenFundsDecode (tokenFundsPreimage r c a) = (r, c, a) := by
  cases r; cases a; rfl

/-- The TFD preimage is injective in `(registry, token_count, amounts)`. Digest injectivity
would additionally need keccak collision resistance, which is NOT assumed here. -/
theorem token_funds_preimage_injective (r r' : Ten Nat) (c c' : Nat) (a a' : Ten Hash)
    (h : tokenFundsPreimage r c a = tokenFundsPreimage r' c' a') :
    r = r' ∧ c = c' ∧ a = a' := by
  have h1 := token_funds_preimage_roundtrip r c a
  have h2 := token_funds_preimage_roundtrip r' c' a'
  rw [h, h2] at h1
  exact ⟨(Prod.mk.injEq .. ▸ h1).1.symm, by
    have := congrArg Prod.snd h1
    exact (Prod.mk.injEq .. ▸ this).1.symm, by
    have := congrArg Prod.snd h1
    exact (Prod.mk.injEq .. ▸ this).2.symm⟩

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

def closeStateIdDecode (xs : List Nat) : Nat × Hash × List Nat :=
  (xs.getD 1 0, readHash xs 2, [xs.getD 10 0, xs.getD 11 0])

theorem close_state_id_roundtrip (c : Nat) (d : Hash) (n : Nat) :
    closeStateIdDecode (closeStateIdPreimage c d n) = (c, d, splitU64 n) := by
  cases d; rfl

theorem close_state_id_preimage_injective (c c' : Nat) (d d' : Hash) (n n' : Nat)
    (hn : n < scalarLimit) (hn' : n' < scalarLimit)
    (h : closeStateIdPreimage c d n = closeStateIdPreimage c' d' n') :
    c = c' ∧ d = d' ∧ n = n' := by
  have h1 := close_state_id_roundtrip c d n
  have h2 := close_state_id_roundtrip c' d' n'
  rw [h, h2] at h1
  have hc : c = c' := (Prod.mk.injEq .. ▸ h1).1.symm
  have hrest := congrArg Prod.snd h1
  have hd : d = d' := (Prod.mk.injEq .. ▸ hrest).1.symm
  have hs : splitU64 n = splitU64 n' := (Prod.mk.injEq .. ▸ hrest).2.symm
  exact ⟨hc, hd, split_u64_injective n n' hn hn' hs⟩

/-- IMCM close-side member-set commitment: `member_count` then ALL `MAX_SIG_CLUSTER` COSIGNER
hashes in slot order, padding slots contributing zero limbs. FIXED 66-word preimage. -/
def closeMemberSetPreimage (hashes : Nat → Hash) (memberCount : Nat) : List Nat :=
  [closeMemberSetDomain, memberCount] ++
  joinHashWords ((indexList maxSigCluster).map
    fun i => if i < memberCount then hashes i else Hash.zero)

def closeMemberSetCommitment (e : Env) (hashes : Nat → Hash) (memberCount : Nat) : Hash :=
  e.hash (closeMemberSetPreimage hashes memberCount)

theorem close_member_set_preimage_length (h : Nat → Hash) (c : Nat) :
    (closeMemberSetPreimage h c).length = 66 := by
  simp [closeMemberSetPreimage, join_hash_words_length, maxSigCluster, index_list_length]

/-- The commitment covers only the COSIGNER slots: delegates hold balances but never enter it. -/
theorem close_member_set_covers_only_cosigner_slots (h g : Nat → Hash) (c : Nat)
    (agree : ∀ i, i < maxSigCluster → h i = g i) :
    closeMemberSetPreimage h c = closeMemberSetPreimage g c := by
  simp only [closeMemberSetPreimage]
  congr 2
  refine map_index_congr maxSigCluster _ _ ?_
  intro i hi
  by_cases hc : i < c
  · simp [hc, agree i hi]
  · simp [hc]

/-- Padding slots contribute zero limbs, so the preimage is a function of `member_count` and the
active prefix only — which is what makes it injective on the active cosigner set given
`ChannelRecord::validate`'s zero-padding rule. -/
theorem close_member_set_zeroes_padding (h g : Nat → Hash) (c : Nat)
    (agree : ∀ i, i < c → h i = g i) :
    closeMemberSetPreimage h c = closeMemberSetPreimage g c := by
  simp only [closeMemberSetPreimage]
  congr 2
  refine map_index_congr maxSigCluster _ _ ?_
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
    (channelTxPreimage e c p ct n t s r).getD 26 0 = t := by
  simp [channelTxPreimage, Hash.words]

/-- Two transfers differing only in `token_slot` produce different preimages: the limb is not
absorbed into a neighbouring word. -/
theorem channel_tx_token_slot_separates (e : Env) (c : Nat) (p : Hash) (ct : Ciphertext)
    (n : Hash) (t t' : Nat) (s r : Hash) (hne : t ≠ t') :
    channelTxPreimage e c p ct n t s r ≠ channelTxPreimage e c p ct n t' s r := by
  intro h
  apply hne
  have := congrArg (fun l => l.getD 26 0) h
  simpa [channelTxPreimage, Hash.words] using this

/-- IMI5 inter-channel tx digest. The sender hash-signature fields are excluded (this digest is
their message); each of the salt's four u64 scalars gets a canonical big-endian pair. -/
def interChannelTxPreimage (e : Env) (t : InterChannelTx) : List Nat :=
  [interChannelTxDomainV5] ++ (t.signedSmallBlock.message.signingDigest e).words ++
  (e.ctDigest t.senderDeltaCt).words ++
  [t.sourceChannelId, t.destinationChannelId, t.tokenIndex, t.baseNonce] ++
  t.destinationBaseTransferSalt.words ++
  t.sourcePkG.words ++ t.transferSeal.words ++ t.txHash.words ++
  t.intmaxTransferCommitment.words ++
  blobWords t.recipientMemo ++ [t.receiverDeltas.length] ++
  joinHashWords (t.receiverDeltas.map fun d => d.receiverPkG) ++
  joinHashWords (t.receiverDeltas.map fun d => e.ctDigest d.amount) ++
  t.channelUpdateZkp.digestWords ++ blobWords t.transportProof

def InterChannelTx.signingDigest (e : Env) (t : InterChannelTx) : Hash :=
  e.hash (interChannelTxPreimage e t)

/-- The IMI5 preimage excludes the sender's own hash-signature fields (it IS their message). -/
theorem inter_channel_preimage_excludes_sender_sig (e : Env) (t : InterChannelTx)
    (sig : List Nat) (pkb : Hash) :
    interChannelTxPreimage e { t with senderHashSig := sig, senderPkB := pkb } =
      interChannelTxPreimage e t := rfl

/-- `tx_leaf_hash`: both wings bind user id + delta ciphertext digest. An empty delta list is a
malformed tx. -/
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

def InterChannelTx.computeTxHash (e : Env) (t : InterChannelTx) : Result Hash :=
  match t.txLeafHash e with
  | .error err => .error err
  | .ok leaf => .ok (interChannelTxHash e t.sourceChannelId t.destinationChannelId t.tokenIndex
      t.signedSmallBlock.message.txTreeRoot leaf)

def InterChannelTx.replayIdentity (e : Env) (t : InterChannelTx) : Result Hash :=
  match t.txLeafHash e with
  | .error err => .error err
  | .ok leaf => .ok (interChannelTxIdentity e t.sourceChannelId t.destinationChannelId
      t.signedSmallBlock.message.txTreeRoot leaf)

/-- The base `token_index` occupies ids limb 5 alone; the two channel ids occupy limbs 6 and 7.
Limbs 0..4 are constant zero. -/
theorem ids_word_layout (s d ti : Nat) :
    (interChannelIdsWord s d ti).words = [0, 0, 0, 0, 0, ti, d, s] := rfl

/-- HIGH-1 dest binding plus TM-16 token binding: the ids word is injective in
`(source, destination, token_index)`. -/
theorem ids_word_injective (s d ti s' d' ti' : Nat)
    (h : interChannelIdsWord s d ti = interChannelIdsWord s' d' ti') :
    s = s' ∧ d = d' ∧ ti = ti' := by
  simp only [interChannelIdsWord, Hash.mk.injEq] at h
  exact ⟨h.2.2.2.2.2.2.2, h.2.2.2.2.2.2.1, h.2.2.2.2.2.1⟩

/-- TM-16 obligation 1: the replay identity strips the token limb, so two descriptors over the
same deltas that differ ONLY in `token_index` collide in the identity-keyed ledger — which is
exactly what stops one debit being credited twice under two tokens. -/
theorem replay_identity_drops_token (e : Env) (t : InterChannelTx) (ti : Nat) :
    ({ t with tokenIndex := ti } : InterChannelTx).replayIdentity e = t.replayIdentity e := rfl

theorem replay_identity_is_zero_token_hash (e : Env) (s d : Nat) (root leaf : Hash) :
    interChannelTxIdentity e s d root leaf = interChannelTxHash e s d 0 root leaf := rfl

/-- The token-bearing hash, by contrast, DOES move with the token limb. -/
theorem tx_hash_tracks_token (e : Env) (t : InterChannelTx) (ti : Nat) (leaf : Hash)
    (hleaf : t.txLeafHash e = .ok leaf) :
    ({ t with tokenIndex := ti } : InterChannelTx).computeTxHash e =
      .ok (interChannelTxHash e t.sourceChannelId t.destinationChannelId ti
        t.signedSmallBlock.message.txTreeRoot leaf) := by
  simp [InterChannelTx.computeTxHash, InterChannelTx.txLeafHash] at hleaf ⊢
  simp [hleaf]

/-- An empty receiver-delta list is a malformed tx for BOTH the token-bearing hash and the
replay identity. -/
theorem empty_receiver_deltas_rejected (e : Env) (t : InterChannelTx)
    (h : t.receiverDeltas = []) :
    t.computeTxHash e = .error .invalidInterChannelTx ∧
    t.replayIdentity e = .error .invalidInterChannelTx := by
  constructor <;>
    simp [InterChannelTx.computeTxHash, InterChannelTx.replayIdentity,
      InterChannelTx.txLeafHash, h]

/-- `tx_leaf_hash` reads only `receiver_deltas[0]`: trailing deltas are ignored entirely, so
"1 tx = 1 real receiver" is a caller obligation, not something this function enforces. -/
theorem tx_leaf_hash_uses_only_first_delta (e : Env) (t : InterChannelTx)
    (d : ReceiverBalanceDelta) (rest rest' : List ReceiverBalanceDelta) :
    ({ t with receiverDeltas := d :: rest } : InterChannelTx).txLeafHash e =
      ({ t with receiverDeltas := d :: rest' } : InterChannelTx).txLeafHash e := rfl

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

def burnDescriptorDecode (xs : List Nat) : Nat × Nat × Hash × Hash × Nat × Hash :=
  (xs.getD 1 0, xs.getD 2 0, readHash xs 3, readHash xs 11, xs.getD 19 0, readHash xs 20)

theorem burn_descriptor_roundtrip (s n : Nat) (l r : Hash) (ti : Nat) (a : Hash) :
    burnDescriptorDecode (burnDescriptorPreimage s n l r ti a) = (s, n, l, r, ti, a) := by
  cases l; cases r; cases a; rfl

/-- The IMD2 preimage is injective in every one of its six inputs: two otherwise identical
burns from different channels or base-account slots cannot share an authorization identity. -/
theorem burn_descriptor_preimage_injective (s n : Nat) (l r : Hash) (ti : Nat) (a : Hash)
    (s' n' : Nat) (l' r' : Hash) (ti' : Nat) (a' : Hash)
    (h : burnDescriptorPreimage s n l r ti a = burnDescriptorPreimage s' n' l' r' ti' a') :
    (s, n, l, r, ti, a) = (s', n', l', r', ti', a') := by
  have h1 := burn_descriptor_roundtrip s n l r ti a
  have h2 := burn_descriptor_roundtrip s' n' l' r' ti' a'
  rw [h, h2] at h1
  exact h1.symm

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
    closeWithdrawalPreimage { w with zkp := z } = closeWithdrawalPreimage w := rfl

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

def withdrawalNullifierDecode (xs : List Nat) : Hash × Hash × Nat :=
  (readHash xs 1, readHash xs 9, xs.getD 17 0)

theorem withdrawal_nullifier_roundtrip (c s : Hash) (t : Nat) :
    withdrawalNullifierDecode (withdrawalNullifierPreimage c s t) = (c, s, t) := by
  cases c; cases s; rfl

/-- Each `(close, slot Regev identity, token slot)` triple has its own preimage; in particular
the token slot is its own limb, so a member's ten per-token claims do not collapse to one. -/
theorem withdrawal_nullifier_preimage_injective (c s : Hash) (t : Nat)
    (c' s' : Hash) (t' : Nat)
    (h : withdrawalNullifierPreimage c s t = withdrawalNullifierPreimage c' s' t') :
    (c, s, t) = (c', s', t') := by
  have h1 := withdrawal_nullifier_roundtrip c s t
  have h2 := withdrawal_nullifier_roundtrip c' s' t'
  rw [h, h2] at h1
  exact h1.symm

/-- The nullifier preimage never mentions `member_pk_g`: the B-2 grinding surface is absent by
construction. -/
theorem withdrawal_nullifier_ignores_member_pk (e : Env) (claim : WithdrawalClaim)
    (slotDigest : Hash) (pk : Hash) :
    deriveWithdrawalNullifier e claim.closeIntentDigest slotDigest claim.tokenSlot =
      deriveWithdrawalNullifier e ({ claim with memberPkG := pk }).closeIntentDigest slotDigest
        ({ claim with memberPkG := pk }).tokenSlot := rfl

/-- IMCW claim signing digest — `token_slot` gets its own limb immediately after `member_pk_g`,
and the preimage ends in a length-prefixed variable-length `claim_proof` tail. -/
def withdrawalClaimPreimage (e : Env) (c : WithdrawalClaim) : List Nat :=
  [withdrawalClaimDomain] ++ c.closeIntentDigest.words ++ c.memberPkG.words ++ [c.tokenSlot] ++
  c.l1Recipient.words ++ (e.ctDigest c.userAmountCt).words ++ c.withdrawalNullifier.words ++
  blobWords c.claimProof

def WithdrawalClaim.signingDigest (e : Env) (c : WithdrawalClaim) : Hash :=
  e.hash (withdrawalClaimPreimage e c)

theorem withdrawal_claim_token_slot_position (e : Env) (c : WithdrawalClaim) :
    (withdrawalClaimPreimage e c).getD 17 0 = c.tokenSlot := by
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
its `tx_hash` and its seal. -/
def CancelClose.new (e : Env) (intentDigest : Hash) (revived : InterChannelTx)
    (cancelProof : List Nat) : CancelClose :=
  { closeIntentDigest := intentDigest
    revivedSmallBlockRoot := revived.signedSmallBlock.message.signingDigest e
    revivedInterChannelTxDigest := revived.signingDigest e
    revivedTxHash := revived.txHash
    revivedSeal := revived.transferSeal
    cancelProof := cancelProof }

theorem cancel_close_new_fields (e : Env) (d : Hash) (t : InterChannelTx) (p : List Nat) :
    (CancelClose.new e d t p).closeIntentDigest = d ∧
    (CancelClose.new e d t p).revivedTxHash = t.txHash ∧
    (CancelClose.new e d t p).revivedSeal = t.transferSeal ∧
    (CancelClose.new e d t p).cancelProof = p := ⟨rfl, rfl, rfl, rfl⟩

/-- IMCK post-close shared-native nullifier: keyed per late inbound TX. -/
def sharedNativeNullifierPreimage (closeIntentDigest incomingTxHash receiverPkG : Hash) :
    List Nat :=
  [postCloseNullifierDomain] ++ closeIntentDigest.words ++ incomingTxHash.words ++
  receiverPkG.words

def deriveSharedNativeNullifier (e : Env)
    (closeIntentDigest incomingTxHash receiverPkG : Hash) : Hash :=
  e.hash (sharedNativeNullifierPreimage closeIntentDigest incomingTxHash receiverPkG)

theorem shared_native_nullifier_preimage_length (a b c : Hash) :
    (sharedNativeNullifierPreimage a b c).length = 25 := by
  simp [sharedNativeNullifierPreimage, Hash.words]

/-- The IMCK nullifier carries NO `token_slot` limb: its token separation is only transitive,
through `incoming_tx_hash` (which commits ids limb 5). Stated structurally; nothing is proved
about the underlying hash. -/
theorem shared_native_nullifier_has_no_token_limb (a b c : Hash) :
    sharedNativeNullifierPreimage a b c =
      postCloseNullifierDomain :: (a.words ++ b.words ++ c.words) := by
  simp [sharedNativeNullifierPreimage]

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

theorem user_fund_leaf_is_channel_balance_leaf (e : Env) (c : Nat) (p : Hash)
    (ct : Ciphertext) : userFundLeafDigest e c p ct = channelBalanceLeafDigest e c p ct := rfl

theorem channel_balance_leaf_preimage_length (e : Env) (c : Nat) (p : Hash) (ct : Ciphertext) :
    (channelBalanceLeafPreimage e c p ct).length = 18 := by
  simp [channelBalanceLeafPreimage, Hash.words]

/-- IML2 L1 deposit-import digest: 14 words, `token_index` in its own limb between the nullifier
and the amount, and the amount split LOW LIMB FIRST. -/
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
    (l1DepositImportPreimage c n t a s).getD 10 0 = t ∧
    (l1DepositImportPreimage c n t a s).getD 13 0 = s := by
  constructor <;> simp [l1DepositImportPreimage, splitU64Lo, Hash.words]

/-! ## `CloseIntent::new` -/

/-- The seven binding checks, in the source's exact order. -/
def closeBindingChecks (e : Env) (s : ChannelState) (w : CloseWithdrawal) : Result Unit :=
  if s.channelId ≠ w.channelId then
    .error (.invalidCloseBinding .channelIdMismatch)
  else if s.digest ≠ w.finalChannelStateDigest then
    .error (.invalidCloseBinding .stateDigestMismatch)
  else if e.balanceH1 s.balance ≠ w.finalBalanceStateH1 then
    .error (.invalidCloseBinding .balanceH1Mismatch)
  else if s.fund.intmaxStateRoot ≠ w.intmaxStateRoot then
    .error (.invalidCloseBinding .intmaxRootMismatch)
  else if w.burnTxHash ≠ Hash.zero then
    .error (.invalidCloseBinding .nonzeroBurnTxHash)
  else if s.fund.amounts.t0 ≠ w.burnAmount then
    .error (.invalidCloseBinding .genesisAmountMismatch)
  else if s.unallocatedConfirmedIncoming ≠ Hash.zero then
    .error (.invalidCloseBinding .unallocatedNonzero)
  else .ok ()

def CloseIntent.new (e : Env) (finalState : ChannelState) (w : CloseWithdrawal) :
    Result CloseIntent :=
  match closeBindingChecks e finalState w with
  | .error err => .error err
  | .ok _ =>
    match checkedAddOneU64 finalState.closeFreezeNonce with
    | .error err => .error err
    | .ok closeNonce =>
      .ok { channelId := finalState.channelId
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

theorem close_binding_checks_conditions (e : Env) (s : ChannelState) (w : CloseWithdrawal)
    (accepted : closeBindingChecks e s w = .ok ()) :
    s.channelId = w.channelId ∧ s.digest = w.finalChannelStateDigest ∧
    e.balanceH1 s.balance = w.finalBalanceStateH1 ∧
    s.fund.intmaxStateRoot = w.intmaxStateRoot ∧ w.burnTxHash = Hash.zero ∧
    s.fund.amounts.t0 = w.burnAmount ∧ s.unallocatedConfirmedIncoming = Hash.zero := by
  unfold closeBindingChecks at accepted
  by_cases h1 : s.channelId ≠ w.channelId
  · rw [if_pos h1] at accepted; simp at accepted
  rw [if_neg h1] at accepted
  by_cases h2 : s.digest ≠ w.finalChannelStateDigest
  · rw [if_pos h2] at accepted; simp at accepted
  rw [if_neg h2] at accepted
  by_cases h3 : e.balanceH1 s.balance ≠ w.finalBalanceStateH1
  · rw [if_pos h3] at accepted; simp at accepted
  rw [if_neg h3] at accepted
  by_cases h4 : s.fund.intmaxStateRoot ≠ w.intmaxStateRoot
  · rw [if_pos h4] at accepted; simp at accepted
  rw [if_neg h4] at accepted
  by_cases h5 : w.burnTxHash ≠ Hash.zero
  · rw [if_pos h5] at accepted; simp at accepted
  rw [if_neg h5] at accepted
  by_cases h6 : s.fund.amounts.t0 ≠ w.burnAmount
  · rw [if_pos h6] at accepted; simp at accepted
  rw [if_neg h6] at accepted
  by_cases h7 : s.unallocatedConfirmedIncoming ≠ Hash.zero
  · rw [if_pos h7] at accepted; simp at accepted
  exact ⟨by simpa using h1, by simpa using h2, by simpa using h3, by simpa using h4,
    by simpa using h5, by simpa using h6, by simpa using h7⟩

theorem close_intent_new_enforced_bindings (e : Env) (s : ChannelState) (w : CloseWithdrawal)
    (i : CloseIntent) (accepted : CloseIntent.new e s w = .ok i) :
    closeBindingChecks e s w = .ok () ∧
    i.closeFreezeNonce = s.closeFreezeNonce + 1 ∧ i.closeNonce = i.closeFreezeNonce ∧
    i.snapshotMediumBlockNumber = 0 ∧ i.channelFundSnapshot = s.fund ∧
    i.burnTxHash = Hash.zero ∧ i.finalStateVersion = s.balance.stateVersion ∧
    i.finalSettledTxChain = s.balance.settledTxChain := by
  unfold CloseIntent.new at accepted
  cases hc : closeBindingChecks e s w with
  | error err => rw [hc] at accepted; simp at accepted
  | ok u =>
    rw [hc] at accepted
    cases u
    cases hn : checkedAddOneU64 s.closeFreezeNonce with
    | error err => rw [hn] at accepted; simp at accepted
    | ok n =>
      rw [hn] at accepted
      have hnval : n = s.closeFreezeNonce + 1 := by
        unfold checkedAddOneU64 at hn
        by_cases hlt : s.closeFreezeNonce + 1 < scalarLimit
        · rw [if_pos hlt] at hn; simpa using hn.symm
        · rw [if_neg hlt] at hn; simp at hn
      have hzero : w.burnTxHash = Hash.zero := (close_binding_checks_conditions e s w hc).2.2.2.2.1
      simp only [Except.ok.injEq] at accepted
      subst accepted
      exact ⟨rfl, hnval, rfl, rfl, rfl, hzero, rfl, rfl⟩

/-- M-9: a nonzero `burn_tx_hash` is refused — a close proof does not authenticate a live
withdrawal, so the field is a hard zero sentinel. -/
theorem close_intent_rejects_nonzero_burn_tx_hash (e : Env) (s : ChannelState)
    (w : CloseWithdrawal) (h1 : s.channelId = w.channelId)
    (h2 : s.digest = w.finalChannelStateDigest)
    (h3 : e.balanceH1 s.balance = w.finalBalanceStateH1)
    (h4 : s.fund.intmaxStateRoot = w.intmaxStateRoot)
    (h : w.burnTxHash ≠ Hash.zero) :
    CloseIntent.new e s w = .error (.invalidCloseBinding .nonzeroBurnTxHash) := by
  unfold CloseIntent.new closeBindingChecks
  rw [if_neg (by simpa using h1), if_neg (by simpa using h2), if_neg (by simpa using h3),
    if_neg (by simpa using h4), if_pos h]

/-- A close from a state with unallocated confirmed incoming funds is refused. -/
theorem close_intent_rejects_unallocated_incoming (e : Env) (s : ChannelState)
    (w : CloseWithdrawal) (h1 : s.channelId = w.channelId)
    (h2 : s.digest = w.finalChannelStateDigest)
    (h3 : e.balanceH1 s.balance = w.finalBalanceStateH1)
    (h4 : s.fund.intmaxStateRoot = w.intmaxStateRoot) (h5 : w.burnTxHash = Hash.zero)
    (h6 : s.fund.amounts.t0 = w.burnAmount)
    (h : s.unallocatedConfirmedIncoming ≠ Hash.zero) :
    CloseIntent.new e s w = .error (.invalidCloseBinding .unallocatedNonzero) := by
  unfold CloseIntent.new closeBindingChecks
  rw [if_neg (by simpa using h1), if_neg (by simpa using h2), if_neg (by simpa using h3),
    if_neg (by simpa using h4), if_neg (by simpa using h5), if_neg (by simpa using h6),
    if_pos h]

/-- SECURITY-RELEVANT SCOPE LIMIT: only the GENESIS lane is compared against `burn_amount`.
The other nine fund lanes are copied into the intent snapshot with NO local check — they
settle through the per-token claim path, not the L2 burn leg. -/
theorem close_binding_checks_ignore_non_genesis_lanes (e : Env) (s : ChannelState)
    (w : CloseWithdrawal) (a : Ten Hash) (h : a.t0 = s.fund.amounts.t0) :
    closeBindingChecks e { s with fund := { s.fund with amounts := a } } w =
      closeBindingChecks e s w := by
  unfold closeBindingChecks
  simp only [h]

/-! ## `token_register_next_state` -/

def tokenRegisterNextState (e : Env) (mode : OverflowMode) (prev : ChannelState)
    (tokenIndex : Nat) : Result ChannelState :=
  match e.applyTokenRegister prev.balance tokenIndex with
  | .error err => .error err
  | .ok balance =>
    match addOneU64 mode prev.epoch with
    | .error err => .error err
    | .ok epoch =>
      .ok (ChannelState.withComputedDigest e
        { prev with epoch := epoch, balance := balance, h2Tag := Hash.zero,
                    prevDigest := prev.digest, memberSignatures := [] })

/-- Everything the canonical builder fixes, and everything it carries over untouched. -/
theorem token_register_next_state_shape (e : Env) (mode : OverflowMode) (prev : ChannelState)
    (ti : Nat) (next : ChannelState)
    (accepted : tokenRegisterNextState e mode prev ti = .ok next) :
    next.h2Tag = Hash.zero ∧ next.prevDigest = prev.digest ∧ next.memberSignatures = [] ∧
    next.channelId = prev.channelId ∧ next.smallBlockNumber = prev.smallBlockNumber ∧
    next.closeFreezeNonce = prev.closeFreezeNonce ∧ next.fund = prev.fund ∧
    next.sharedNativeNullifierRoot = prev.sharedNativeNullifierRoot ∧
    next.unallocatedConfirmedIncoming = prev.unallocatedConfirmedIncoming ∧
    e.applyTokenRegister prev.balance ti = .ok next.balance := by
  unfold tokenRegisterNextState at accepted
  cases hb : e.applyTokenRegister prev.balance ti with
  | error err => rw [hb] at accepted; simp at accepted
  | ok bal =>
    rw [hb] at accepted
    cases hep : addOneU64 mode prev.epoch with
    | error err => rw [hep] at accepted; simp at accepted
    | ok ep =>
      rw [hep] at accepted
      simp only [Except.ok.injEq] at accepted
      subst accepted
      exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩

/-- The produced state's `digest` is the hash of its own IMCH preimage. -/
theorem token_register_digest_is_recomputed (e : Env) (mode : OverflowMode)
    (prev : ChannelState) (ti : Nat) (next : ChannelState)
    (accepted : tokenRegisterNextState e mode prev ti = .ok next) :
    next.digest = e.hash (channelStatePreimage e next) := by
  unfold tokenRegisterNextState at accepted
  cases hb : e.applyTokenRegister prev.balance ti with
  | error err => rw [hb] at accepted; simp at accepted
  | ok bal =>
    rw [hb] at accepted
    cases hep : addOneU64 mode prev.epoch with
    | error err => rw [hep] at accepted; simp at accepted
    | ok ep =>
      rw [hep] at accepted
      simp only [Except.ok.injEq] at accepted
      subst accepted
      rfl

/-- In an overflow-checked build the epoch advances by exactly one. -/
theorem token_register_epoch_increment (e : Env) (prev : ChannelState) (ti : Nat)
    (next : ChannelState) (hlt : prev.epoch + 1 < scalarLimit)
    (accepted : tokenRegisterNextState e .checked prev ti = .ok next) :
    next.epoch = prev.epoch + 1 := by
  unfold tokenRegisterNextState at accepted
  cases hb : e.applyTokenRegister prev.balance ti with
  | error err => rw [hb] at accepted; simp at accepted
  | ok bal =>
    rw [hb] at accepted
    simp only [addOneU64, if_pos hlt] at accepted
    simp only [Except.ok.injEq] at accepted
    subst accepted
    rfl

/-- A registration the balance layer refuses (e.g. a duplicate base index) produces no next
state at all. -/
theorem token_register_propagates_balance_error (e : Env) (mode : OverflowMode)
    (prev : ChannelState) (ti : Nat) (err : Error)
    (h : e.applyTokenRegister prev.balance ti = .error err) :
    tokenRegisterNextState e mode prev ti = .error err := by
  simp [tokenRegisterNextState, h]

/-! ## `merkle_root_from_proof`

Bit `depth` of the leaf index is read from limb `7 - depth / 32` of the eight big-endian limbs.
For `depth >= 256` that index underflows in Rust `usize`: the source PANICS on a sibling list
longer than 256. The model returns an explicit panic rather than a value. -/

def indexLimb (v : Hash) (i : Nat) : Nat := v.words.getD i 0

def pathBit (index : Hash) (depth : Nat) : Result Nat :=
  if depth / 32 < 8 then .ok ((indexLimb index (7 - depth / 32) / 2 ^ (depth % 32)) % 2)
  else .error (.panic "merkle_root_from_proof leaf-index limb underflow")

def merkleFold (e : Env) (current : Hash) (index : Hash) (depth : Nat) :
    List Hash → Result Hash
  | [] => .ok current
  | sib :: rest =>
    match pathBit index depth with
    | .error err => .error err
    | .ok bit =>
      merkleFold e (e.hash (if bit = 0 then current.words ++ sib.words
                            else sib.words ++ current.words)) index (depth + 1) rest

def merkleRootFromProof (e : Env) (leaf : Hash) (p : MerkleInclusionProof) : Result Hash :=
  merkleFold e leaf p.leafIndex 0 p.siblings

theorem merkle_root_empty_proof (e : Env) (leaf : Hash) (idx : Hash) :
    merkleRootFromProof e leaf ⟨[], idx⟩ = .ok leaf := rfl

/-- Each level hashes exactly sixteen limbs, in an order chosen by the index bit. -/
theorem merkle_pair_width (a b : Hash) :
    (a.words ++ b.words).length = 16 ∧ (b.words ++ a.words).length = 16 := by
  constructor <;> simp [Hash.words]

/-- A sibling list longer than 256 makes the source index a negative `usize`: a panic, not an
error return. -/
theorem merkle_deep_proof_panics (idx : Hash) (depth : Nat) (h : 256 ≤ depth) :
    pathBit idx depth = .error (.panic "merkle_root_from_proof leaf-index limb underflow") := by
  unfold pathBit
  have hnot : ¬ (depth / 32 < 8) := by
    have : 8 ≤ depth / 32 := Nat.le_div_iff_mul_le (by decide) |>.mpr (by omega)
    omega
  rw [if_neg hnot]

/-! ## Positive examples (non-vacuous normal traces) -/

def sampleKey (n : Nat) : Hash := ⟨n + 1, n + 2, n + 3, n + 4, n + 5, n + 6, n + 7, n + 8⟩

theorem sample_keys_distinct (a b : Nat) (h : a ≠ b) : sampleKey a ≠ sampleKey b := by
  intro heq
  apply h
  have hw := congrArg Hash.w0 heq
  simpa [sampleKey] using hw

def sampleKeyFn : Nat → Hash := fun i => if i < 3 then sampleKey i else Hash.zero

/-- Three cosigners, no delegates, canonical zero padding: the shape the record type intends. -/
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
    (by decide) (by decide) (by decide) ?_ ?_ ?_
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
  · intro k hk _
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
  unfold validateMemberSignatureSlots
  rw [sample_record_validates]
  rw [if_neg (by decide : ¬ (sampleSignatures.length ≠ sampleRecord.memberCount))]
  show slotChecks sampleKeyFn 0 sampleSignatures = .ok ()
  simp only [sampleSignatures, slotChecks]
  rw [if_neg (by decide), if_neg (by decide), if_neg (structural_placeholder_nonempty 1),
    if_neg (by decide), if_neg (by decide), if_neg (structural_placeholder_nonempty 3),
    if_neg (by decide), if_neg (by decide), if_neg (structural_placeholder_nonempty 5)]

/-- SECURITY-RELEVANT POSITIVE RESULT: the source's own explicitly cryptographically
MEANINGLESS blob passes BOTH structural gates. Passing them therefore says nothing at all about
signature validity. -/
theorem structural_placeholder_passes_both_gates :
    validateAllMemberSignatures sampleRecord sampleSignatures = .ok () := by
  unfold validateAllMemberSignatures
  rw [sample_signature_slots_accepted]
  simp only [sampleSignatures, lengthChecks]
  rw [if_neg (by simp [structural_placeholder_length]),
    if_neg (by simp [structural_placeholder_length]),
    if_neg (by simp [structural_placeholder_length])]

/-- A duplicated active pubkey hash is refused: the third slot repeats slot 0's key. -/
def duplicateKeyFn : Nat → Hash :=
  fun i => if i < 2 then sampleKey i else if i = 2 then sampleKey 0 else Hash.zero

theorem duplicate_active_key_rejected :
    validateRecord { sampleRecord with memberPkGs := duplicateKeyFn } ≠ .ok () := by
  intro accepted
  have hact : activeSlots { sampleRecord with memberPkGs := duplicateKeyFn } = 3 := rfl
  exact validate_forces_active_distinct { sampleRecord with memberPkGs := duplicateKeyFn }
    accepted 0 2 (by decide) (by rw [hact]; decide) (by decide)

/-- A nonzero padding slot is refused. -/
def dirtyPaddingFn : Nat → Hash :=
  fun i => if i < 3 then sampleKey i else if i = 5 then sampleKey 9 else Hash.zero

theorem nonzero_padding_rejected :
    validateRecord { sampleRecord with memberPkGs := dirtyPaddingFn } ≠ .ok () := by
  intro accepted
  have hact : activeSlots { sampleRecord with memberPkGs := dirtyPaddingFn } = 3 := rfl
  have hz := validate_forces_zero_padding { sampleRecord with memberPkGs := dirtyPaddingFn }
    accepted 5 (by rw [hact]; decide) (by decide)
  exact absurd hz (by decide)

/-- A one-member "channel" is refused: `member_count` must be at least two, so no single party
can ever hold an N-of-N cosign set alone. -/
theorem single_member_record_rejected :
    validateRecord { sampleRecord with memberCount := 1 } ≠ .ok () := by
  intro accepted
  exact absurd (validate_forces_scalar_bounds _ accepted).2.2.1 (by decide)

/-- More cosigners than `MAX_SIG_CLUSTER` are refused. -/
theorem oversized_sig_cluster_rejected :
    validateRecord { sampleRecord with memberCount := 9 } ≠ .ok () := by
  intro accepted
  exact absurd (validate_forces_scalar_bounds _ accepted).2.2.2.1 (by decide)

/-- The reserved burn channel can never host a real channel record. -/
theorem burn_channel_record_rejected :
    validateRecord { sampleRecord with channelId := burnChannelId } ≠ .ok () := by
  intro accepted
  exact (validate_forces_scalar_bounds _ accepted).2.1 rfl

/-- A member/delegate allocation exceeding the balance-slot capacity is refused. -/
theorem over_capacity_record_rejected :
    validateRecord { sampleRecord with delegateCount := 1022 } ≠ .ok () := by
  intro accepted
  exact absurd (validate_forces_scalar_bounds _ accepted).2.2.2.2.2 (by decide)

/-- A signature set of the wrong size is refused even when every entry is well formed. -/
theorem short_signature_set_rejected :
    validateMemberSignatureSlots sampleRecord (sampleSignatures.take 2) ≠ .ok () := by
  intro accepted
  exact absurd (slot_validation_shape sampleRecord _ accepted).2.1 (by decide)

/-- A cosign set carrying a NON-REGISTERED pubkey hash at a slot is refused — this, and only
this, is the identity binding the structural gate provides. -/
theorem unregistered_key_in_slot_rejected :
    validateMemberSignatureSlots sampleRecord
      [{ memberSlot := 0, pkG := sampleKey 0, signature := structuralCosignPlaceholder 1 },
       { memberSlot := 1, pkG := sampleKey 1, signature := structuralCosignPlaceholder 3 },
       { memberSlot := 2, pkG := sampleKey 99, signature := structuralCosignPlaceholder 5 }]
      ≠ .ok () := by
  intro accepted
  have h := (slot_validation_shape sampleRecord _ accepted).2.2 2
    { memberSlot := 2, pkG := sampleKey 99, signature := structuralCosignPlaceholder 5 }
    (by simp)
  exact absurd h.2.1 (by decide)

/-- And a set presented OUT OF SLOT ORDER is refused. -/
theorem out_of_order_signature_set_rejected :
    validateMemberSignatureSlots sampleRecord
      [{ memberSlot := 1, pkG := sampleKey 0, signature := structuralCosignPlaceholder 1 },
       { memberSlot := 1, pkG := sampleKey 1, signature := structuralCosignPlaceholder 3 },
       { memberSlot := 2, pkG := sampleKey 2, signature := structuralCosignPlaceholder 5 }]
      ≠ .ok () := by
  intro accepted
  have h := (slot_validation_shape sampleRecord _ accepted).2.2 0
    { memberSlot := 1, pkG := sampleKey 0, signature := structuralCosignPlaceholder 1 }
    (by simp)
  exact absurd h.1 (by decide)

end Zkp.Implementation.ChannelTypes
