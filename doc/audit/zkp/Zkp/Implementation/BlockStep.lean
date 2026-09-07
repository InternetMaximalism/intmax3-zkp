import Std

/-!
# BlockStep: one block of the validity (block-hash-chain) recursion

Handwritten semantic model of `src/circuits/validity/block_hash_chain/block_step.rs`
(1169 lines: `BlockStepError`, `BlockStepWitness::to_public_inputs`,
`BlockStepTarget::new`/`set_witness`, `BlockStepCircuit::new`/`prove`/`verify`, and a
release-only integration test), together with the public-input layouts the file
slices (`BlockChainPublicInputs`, `ExtendedPublicState`, `PublicState`,
`UpdateUserPublicInputs`, `DepositChainPublicInputs`, `ChannelRegChainPublicInputs`).

This is NOT a refinement proof of the Rust, of plonky2, or of the compiled circuit.
Field elements are integer representatives, lists of `Nat` stand for u32/u64 limb
vectors, and every cryptographic object is an opaque callback or an explicit premise.

## What one block step proves (as the model states it)

A step consumes the previous chain proof's `(initial_ext_public_state, ext_public_state)`
pair (or, for the first step, a completely free `initial_public_state` witness) and one
`update_channel_tree` proof for the block, and emits a new `BlockChainPublicInputs` in
which:

* `block_number` is the previous block number plus one (native: `U63::add(1)`, rejecting
  at `2^63 - 1`; in-circuit: one `add_const` plus `range_check(_, 63)`);
* `block_hash_chain` is replaced by the update proof's `new_block_hash_chain`, whose
  declared `prev_block_hash_chain` is wired to the previous state's -- this is the fold
  of the block's admitted sub-block message into the on-chain hash chain. The message
  itself, its Poseidon/keccak folding and the N-of-N or block-producer signature over it
  are NOT checked here: they live entirely inside the update proof;
* `bp_sig_chain` is threaded the same way (`prev_bp_sig_chain` wired to the previous
  value, `new_bp_sig_chain` becomes the new one). Whether the accumulator advanced, and
  whether an aggregate signature backs it, is delegated to the update proof and to the
  separate aggregate-list proof checked by the validity circuit;
* deposits are folded conditionally: `has_deposit_proof` is constrained to be exactly
  `prev.deposit_hash_chain != update.deposit_hash_chain`, and when set, the deposit chain
  proof must start at the previous `(hash chain, tree root, count)` triple, end at the
  update proof's declared `deposit_hash_chain`, and carry this block's number;
* channel registrations are folded by the mirror-image conditional: on a registration
  block the account tree root comes from the registration chain's rebuilt channel tree
  instead of the update proof (R6 forces the update proof to leave the account root
  unchanged), and the resulting `channel_reg_hash_chain` is bound (G6) to the value the
  update proof folded into the block hash;
* the public-state tree is advanced by ONE opaque Merkle-path re-use: the same sibling
  path is first checked to open to `prev.prev_public_state_root` at the EMPTY leaf and
  index `prev.block_number`, then re-evaluated with the previous public state inserted at
  that index; the result becomes the new `prev_public_state_root`.

## Authorization: what is checked here vs delegated

NOTHING in this file checks a signature, a sig-cluster membership, an N-of-N threshold or
a block producer key. All of that is inside the `update_channel_tree` proof (and the
aggregate-list proof consumed elsewhere). This file only checks recursive-proof
acceptance (an opaque callback) and equality of declared public inputs. The model names
these as boundaries rather than proving anything about them.

## Named boundaries (all undischarged premises)

* `StepEnv.accepts` -- plonky2/recursive proof verification (previous chain, update,
  deposit chain, channel-registration chain). Nothing about proof soundness is claimed.
* `StepEnv.merkleRoot` -- the public-state incremental Merkle gadget (`get_root`,
  `verify`). Collision freedom is never assumed; where a conclusion needs it, it appears
  as an explicit equality premise on the concrete compared pair.
* `commit` -- the Poseidon commitment used by the one-hot selection of update public
  inputs. Injectivity is a premise on the compared pair, never a theorem.
* `StepEnv.vdEncode` / `StepEnv.vdDecode` -- the verifier-key limb codec
  (`vd_to_vec`/`vd_from_pis_slice`); soundness is the `VdCodecSound` premise.
* Gate lowering -- `conditionally_verify_proof`, `add_proof_target_and_conditionally_verify(_cyclic)`,
  `conditionally_connect_vd`, `select_vec`, `conditional_assert_eq`, `range_check` are
  modeled by their intended local semantics, not by plonky2 gate constraints.
* Field arithmetic -- the in-circuit block-number increment is modeled modulo the
  Goldilocks order; the previous block number is NOT range checked in this file.
* Anchoring of `initial_ext_public_state` and of the cyclic verifier key on a first step
  is outside this file (the block-hash-chain wrapper and the contract snapshot).
-/
namespace Zkp.Implementation.BlockStep

/-! ## Pinned constants -/

/-- `BYTES32_LEN` (u256.rs `U256_LEN`). -/
def bytes32Len : Nat := 8
/-- `POSEIDON_HASH_OUT_LEN`. -/
def poseidonHashOutLen : Nat := 4
/-- `U64_LEN`. -/
def u64Len : Nat := 2
/-- `PUBLIC_STATE_U64_LEN = 1 + U64_LEN + 3 * POSEIDON_HASH_OUT_LEN`. -/
def publicStateU64Len : Nat := 1 + u64Len + 3 * poseidonHashOutLen
/-- `EXTENDED_PUBLIC_STATE_U64_LEN = PUBLIC_STATE_U64_LEN + 4 * BYTES32_LEN + 1`. -/
def extendedPublicStateU64Len : Nat := publicStateU64Len + 4 * bytes32Len + 1
/-- `BLOCK_CHAIN_PUBLIC_INPUTS_LEN = 2 * EXTENDED_PUBLIC_STATE_U64_LEN`. -/
def blockChainPublicInputsLen : Nat := 2 * extendedPublicStateU64Len
/-- `UPDATE_ACCOUNT_PUBLIC_INPUTS_LEN = 1 + U64_LEN + 6 * BYTES32_LEN + 2 * POSEIDON_HASH_OUT_LEN`. -/
def updateUserPublicInputsLen : Nat := 1 + u64Len + 6 * bytes32Len + 2 * poseidonHashOutLen
/-- `DEPOSIT_CHAIN_PUBLIC_INPUTS_LEN = 2 * BYTES32_LEN + 2 * POSEIDON_HASH_OUT_LEN + 3`. -/
def depositChainPublicInputsLen : Nat := 2 * bytes32Len + 2 * poseidonHashOutLen + 3
/-- `CHANNEL_REG_CHAIN_PUBLIC_INPUTS_LEN`, the same layout as the deposit chain. -/
def channelRegChainPublicInputsLen : Nat := 2 * bytes32Len + 2 * poseidonHashOutLen + 3
/-- `BLOCK_NUMBER_BITS = 63`, also `PUBLIC_STATE_TREE_HEIGHT`. -/
def blockNumberBits : Nat := 63
/-- `PUBLIC_STATE_TREE_HEIGHT = BLOCK_NUMBER_BITS`. -/
def publicStateTreeHeight : Nat := blockNumberBits
/-- `U63_MAX_VALUE = (1 << 63) - 1`; `U63::new` rejects anything above it. -/
def u63Max : Nat := 2 ^ blockNumberBits - 1
/-- Goldilocks order `2^64 - 2^32 + 1`, the modulus of the in-circuit `add_const`. -/
def fieldOrder : Nat := 2 ^ 64 - 2 ^ 32 + 1

theorem bytes32_len_pinned : bytes32Len = 8 := by decide
theorem poseidon_hash_out_len_pinned : poseidonHashOutLen = 4 := by decide
theorem public_state_len_pinned : publicStateU64Len = 15 := by decide
theorem extended_public_state_len_pinned : extendedPublicStateU64Len = 48 := by decide
theorem block_chain_public_inputs_len_pinned : blockChainPublicInputsLen = 96 := by decide
theorem update_user_public_inputs_len_pinned : updateUserPublicInputsLen = 59 := by decide
theorem deposit_chain_public_inputs_len_pinned : depositChainPublicInputsLen = 27 := by decide
theorem channel_reg_chain_public_inputs_len_pinned : channelRegChainPublicInputsLen = 27 := by decide
theorem public_state_tree_height_pinned : publicStateTreeHeight = 63 := by decide
theorem u63_max_pinned : u63Max = 9223372036854775807 := by decide
theorem field_order_pinned : fieldOrder = 18446744069414584321 := by decide

theorem u63_max_lt_field_order : u63Max < fieldOrder := by decide

/-! ## Limb words

`Bytes32` is eight u32 limbs stored one per u64 slot, `Hash` (a `PoseidonHashOut`) is four
u64 slots, `U64Val` (a timestamp) is two. They are distinct Lean types so the model cannot
silently compare a channel tree root with a keccak registration chain. -/

structure Bytes32 where
  limbs : List Nat
  deriving DecidableEq, Repr, Inhabited

structure Hash where
  limbs : List Nat
  deriving DecidableEq, Repr, Inhabited

structure U64Val where
  limbs : List Nat
  deriving DecidableEq, Repr, Inhabited

def Bytes32.WellFormed (b : Bytes32) : Prop := b.limbs.length = bytes32Len
def Hash.WellFormed (h : Hash) : Prop := h.limbs.length = poseidonHashOutLen
def U64Val.WellFormed (t : U64Val) : Prop := t.limbs.length = u64Len

/-- `PoseidonHashOut::default()` / `Bytes32::default()`: all-zero limbs. -/
def zeroHash : Hash := ⟨List.replicate poseidonHashOutLen 0⟩
def zeroBytes32 : Bytes32 := ⟨List.replicate bytes32Len 0⟩
def zeroU64 : U64Val := ⟨List.replicate u64Len 0⟩

theorem zero_hash_well_formed : zeroHash.WellFormed := by
  simp [zeroHash, Hash.WellFormed]

theorem zero_bytes32_well_formed : zeroBytes32.WellFormed := by
  simp [zeroBytes32, Bytes32.WellFormed]

theorem zero_u64_well_formed : zeroU64.WellFormed := by
  simp [zeroU64, U64Val.WellFormed]

/-! ## Public-input decoding

The Rust decoders take an exact-length slice and walk a cursor. The model mirrors that
with a cursor-passing `Except` decoder plus one length gate at the top. -/

inductive DecodeError where
  | invalidLength (expected actual : Nat)
  | fieldTooShort (field : String)
  | badVerifierData
  deriving DecidableEq, Repr

/-- Explicit decoder sequencing (kept out of `do` notation so the round-trip proofs
    reduce by `simp only` without unfolding join points). -/
def bindD {α β : Type} (r : Except DecodeError α) (f : α → Except DecodeError β) :
    Except DecodeError β :=
  match r with
  | .error e => .error e
  | .ok a => f a

theorem bind_d_ok {α β : Type} (a : α) (f : α → Except DecodeError β) :
    bindD (.ok a) f = f a := rfl

theorem bind_d_error {α β : Type} (e : DecodeError) (f : α → Except DecodeError β) :
    bindD (.error e) f = .error e := rfl

/-- One cursor step: `values[cursor .. cursor + n]`. -/
def takeLimbs (n : Nat) (field : String) (xs : List Nat) :
    Except DecodeError (List Nat × List Nat) :=
  if xs.length < n then .error (.fieldTooShort field) else .ok (xs.take n, xs.drop n)

/-- One scalar slot (`block_number`, `deposit_count`). -/
def takeScalar (field : String) (xs : List Nat) : Except DecodeError (Nat × List Nat) :=
  match xs with
  | [] => .error (.fieldTooShort field)
  | y :: ys => .ok (y, ys)

theorem take_limbs_append {n : Nat} {field : String} {l rest : List Nat}
    (hl : l.length = n) : takeLimbs n field (l ++ rest) = .ok (l, rest) := by
  have hlen : (l ++ rest).length = n + rest.length := by
    simp [List.length_append, hl]
  have ht : (l ++ rest).take n = l := by
    rw [← hl]; simp
  have hd : (l ++ rest).drop n = rest := by
    rw [← hl]; simp
  simp only [takeLimbs, hlen, ht, hd]
  rw [if_neg (by omega)]

theorem take_scalar_cons {field : String} {y : Nat} {ys : List Nat} :
    takeScalar field (y :: ys) = .ok (y, ys) := rfl

/-! ## Public state and extended public state -/

structure PublicState where
  blockNumber : Nat
  timestamp : U64Val
  accountTreeRoot : Hash
  depositTreeRoot : Hash
  prevPublicStateRoot : Hash
  deriving DecidableEq, Repr, Inhabited

structure ExtendedPublicState where
  inner : PublicState
  blockHashChain : Bytes32
  depositHashChain : Bytes32
  depositCount : Nat
  channelRegHashChain : Bytes32
  bpSigChain : Bytes32
  deriving DecidableEq, Repr, Inhabited

/-- `<PublicState as Leafable>::empty_leaf()`: every field `Default::default()`, i.e. the
    ZERO hashes, not the initialised tree roots that `PublicState::default()` uses. -/
def emptyPublicStateLeaf : PublicState :=
  { blockNumber := 0
    timestamp := zeroU64
    accountTreeRoot := zeroHash
    depositTreeRoot := zeroHash
    prevPublicStateRoot := zeroHash }

def PublicState.encode (s : PublicState) : List Nat :=
  s.blockNumber :: (s.timestamp.limbs ++ s.accountTreeRoot.limbs ++
    s.depositTreeRoot.limbs ++ s.prevPublicStateRoot.limbs)

def ExtendedPublicState.encode (e : ExtendedPublicState) : List Nat :=
  e.inner.encode ++ e.blockHashChain.limbs ++ e.depositHashChain.limbs ++
    [e.depositCount] ++ e.channelRegHashChain.limbs ++ e.bpSigChain.limbs

def PublicState.WellFormed (s : PublicState) : Prop :=
  s.timestamp.WellFormed ∧ s.accountTreeRoot.WellFormed ∧ s.depositTreeRoot.WellFormed ∧
    s.prevPublicStateRoot.WellFormed

def ExtendedPublicState.WellFormed (e : ExtendedPublicState) : Prop :=
  e.inner.WellFormed ∧ e.blockHashChain.WellFormed ∧ e.depositHashChain.WellFormed ∧
    e.channelRegHashChain.WellFormed ∧ e.bpSigChain.WellFormed

def decodePublicStateAt (xs : List Nat) : Except DecodeError (PublicState × List Nat) :=
  bindD (takeScalar "block_number" xs) fun (bn, xs) =>
  bindD (takeLimbs u64Len "timestamp" xs) fun (ts, xs) =>
  bindD (takeLimbs poseidonHashOutLen "account_tree_root" xs) fun (acc, xs) =>
  bindD (takeLimbs poseidonHashOutLen "deposit_tree_root" xs) fun (dep, xs) =>
  bindD (takeLimbs poseidonHashOutLen "prev_public_state_root" xs) fun (prev, xs) =>
  .ok ({ blockNumber := bn, timestamp := ⟨ts⟩, accountTreeRoot := ⟨acc⟩,
         depositTreeRoot := ⟨dep⟩, prevPublicStateRoot := ⟨prev⟩ }, xs)

def decodeExtendedPublicStateAt (xs : List Nat) :
    Except DecodeError (ExtendedPublicState × List Nat) :=
  bindD (decodePublicStateAt xs) fun (inner, xs) =>
  bindD (takeLimbs bytes32Len "block_hash_chain" xs) fun (bhc, xs) =>
  bindD (takeLimbs bytes32Len "deposit_hash_chain" xs) fun (dhc, xs) =>
  bindD (takeScalar "deposit_count" xs) fun (cnt, xs) =>
  bindD (takeLimbs bytes32Len "channel_reg_hash_chain" xs) fun (crhc, xs) =>
  bindD (takeLimbs bytes32Len "bp_sig_chain" xs) fun (bsc, xs) =>
  .ok ({ inner := inner, blockHashChain := ⟨bhc⟩, depositHashChain := ⟨dhc⟩,
         depositCount := cnt, channelRegHashChain := ⟨crhc⟩, bpSigChain := ⟨bsc⟩ }, xs)

theorem public_state_encode_length {s : PublicState} (wf : s.WellFormed) :
    s.encode.length = publicStateU64Len := by
  obtain ⟨ht, ha, hd, hp⟩ := wf
  simp only [PublicState.encode, List.length_cons, List.length_append]
  simp only [U64Val.WellFormed] at ht
  simp only [Hash.WellFormed] at ha hd hp
  rw [ht, ha, hd, hp]
  decide

theorem decode_public_state_encode {s : PublicState} (rest : List Nat) (wf : s.WellFormed) :
    decodePublicStateAt (s.encode ++ rest) = .ok (s, rest) := by
  obtain ⟨ht, ha, hd, hp⟩ := wf
  simp only [U64Val.WellFormed] at ht
  simp only [Hash.WellFormed] at ha hd hp
  simp only [PublicState.encode, List.cons_append, List.append_assoc]
  simp only [decodePublicStateAt, take_scalar_cons, bind_d_ok, take_limbs_append ht,
    take_limbs_append ha, take_limbs_append hd, take_limbs_append hp]

theorem extended_public_state_encode_length {e : ExtendedPublicState}
    (wf : e.WellFormed) : e.encode.length = extendedPublicStateU64Len := by
  obtain ⟨hi, hb, hd, hc, hs⟩ := wf
  simp only [Bytes32.WellFormed] at hb hd hc hs
  simp only [ExtendedPublicState.encode, List.length_append, List.length_cons,
    List.length_nil]
  rw [public_state_encode_length hi, hb, hd, hc, hs]
  simp only [extendedPublicStateU64Len, bytes32Len]

theorem decode_extended_public_state_encode {e : ExtendedPublicState} (rest : List Nat)
    (wf : e.WellFormed) : decodeExtendedPublicStateAt (e.encode ++ rest) = .ok (e, rest) := by
  obtain ⟨hi, hb, hd, hc, hs⟩ := wf
  simp only [Bytes32.WellFormed] at hb hd hc hs
  simp only [ExtendedPublicState.encode, List.append_assoc, List.singleton_append]
  simp only [decodeExtendedPublicStateAt, bind_d_ok, decode_public_state_encode _ hi,
    take_limbs_append hb, take_limbs_append hd]
  simp only [List.cons_append, List.append_assoc, take_scalar_cons, bind_d_ok,
    take_limbs_append hc, take_limbs_append hs]

/-! ## The three consumed public-input layouts

`UpdateUserPublicInputs` (update_channel_tree.rs) carries no verifier data; the two hash
chain layouts end with the cyclic verifier key. -/

structure UpdateUserPublicInputs where
  blockNumber : Nat
  blockTimestamp : U64Val
  prevBlockHashChain : Bytes32
  prevAccountTreeRoot : Hash
  newBlockHashChain : Bytes32
  newAccountTreeRoot : Hash
  depositHashChain : Bytes32
  channelRegHashChain : Bytes32
  prevBpSigChain : Bytes32
  newBpSigChain : Bytes32
  deriving DecidableEq, Repr, Inhabited

structure VerifierKey where
  id : Nat
  deriving DecidableEq, Repr, Inhabited

structure DepositChainPublicInputs where
  initialDepositHashChain : Bytes32
  initialDepositTreeRoot : Hash
  initialDepositCount : Nat
  depositHashChain : Bytes32
  depositTreeRoot : Hash
  depositCount : Nat
  blockNumber : Nat
  vd : VerifierKey
  deriving DecidableEq, Repr, Inhabited

structure ChannelRegChainPublicInputs where
  initialChannelRegHashChain : Bytes32
  initialChannelTreeRoot : Hash
  initialChannelRegCount : Nat
  channelRegHashChain : Bytes32
  channelTreeRoot : Hash
  channelRegCount : Nat
  blockNumber : Nat
  vd : VerifierKey
  deriving DecidableEq, Repr, Inhabited

structure BlockChainPublicInputs where
  initialExt : ExtendedPublicState
  ext : ExtendedPublicState
  vd : VerifierKey
  deriving DecidableEq, Repr, Inhabited

def UpdateUserPublicInputs.encode (u : UpdateUserPublicInputs) : List Nat :=
  u.blockNumber :: (u.blockTimestamp.limbs ++ u.prevBlockHashChain.limbs ++
    u.prevAccountTreeRoot.limbs ++ u.newBlockHashChain.limbs ++ u.newAccountTreeRoot.limbs ++
    u.depositHashChain.limbs ++ u.channelRegHashChain.limbs ++ u.prevBpSigChain.limbs ++
    u.newBpSigChain.limbs)

def UpdateUserPublicInputs.WellFormed (u : UpdateUserPublicInputs) : Prop :=
  u.blockTimestamp.WellFormed ∧ u.prevBlockHashChain.WellFormed ∧
    u.prevAccountTreeRoot.WellFormed ∧ u.newBlockHashChain.WellFormed ∧
    u.newAccountTreeRoot.WellFormed ∧ u.depositHashChain.WellFormed ∧
    u.channelRegHashChain.WellFormed ∧ u.prevBpSigChain.WellFormed ∧ u.newBpSigChain.WellFormed

/-- `UpdateUserPublicInputs::from_u64_slice`: exact-length gate, then the cursor walk. -/
def decodeUpdateUserPis (xs : List Nat) : Except DecodeError UpdateUserPublicInputs :=
  if xs.length ≠ updateUserPublicInputsLen then
    .error (.invalidLength updateUserPublicInputsLen xs.length)
  else
    bindD (takeScalar "block_number" xs) fun (bn, xs) =>
    bindD (takeLimbs u64Len "block_timestamp" xs) fun (ts, xs) =>
    bindD (takeLimbs bytes32Len "prev_block_hash_chain" xs) fun (pbhc, xs) =>
    bindD (takeLimbs poseidonHashOutLen "prev_account_tree_root" xs) fun (patr, xs) =>
    bindD (takeLimbs bytes32Len "new_block_hash_chain" xs) fun (nbhc, xs) =>
    bindD (takeLimbs poseidonHashOutLen "new_account_tree_root" xs) fun (natr, xs) =>
    bindD (takeLimbs bytes32Len "deposit_hash_chain" xs) fun (dhc, xs) =>
    bindD (takeLimbs bytes32Len "channel_reg_hash_chain" xs) fun (crhc, xs) =>
    bindD (takeLimbs bytes32Len "prev_bp_sig_chain" xs) fun (pbsc, xs) =>
    bindD (takeLimbs bytes32Len "new_bp_sig_chain" xs) fun (nbsc, _) =>
    .ok { blockNumber := bn, blockTimestamp := ⟨ts⟩, prevBlockHashChain := ⟨pbhc⟩,
          prevAccountTreeRoot := ⟨patr⟩, newBlockHashChain := ⟨nbhc⟩,
          newAccountTreeRoot := ⟨natr⟩, depositHashChain := ⟨dhc⟩,
          channelRegHashChain := ⟨crhc⟩, prevBpSigChain := ⟨pbsc⟩, newBpSigChain := ⟨nbsc⟩ }

theorem update_user_encode_length {u : UpdateUserPublicInputs} (wf : u.WellFormed) :
    u.encode.length = updateUserPublicInputsLen := by
  obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9⟩ := wf
  simp only [U64Val.WellFormed] at h1
  simp only [Bytes32.WellFormed] at h2 h4 h6 h7 h8 h9
  simp only [Hash.WellFormed] at h3 h5
  simp only [UpdateUserPublicInputs.encode, List.length_cons, List.length_append,
    h1, h2, h3, h4, h5, h6, h7, h8, h9]
  simp only [updateUserPublicInputsLen, bytes32Len, poseidonHashOutLen, u64Len]

theorem decode_update_user_encode {u : UpdateUserPublicInputs} (wf : u.WellFormed) :
    decodeUpdateUserPis u.encode = .ok u := by
  have hlen := update_user_encode_length wf
  obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9⟩ := wf
  simp only [U64Val.WellFormed] at h1
  simp only [Bytes32.WellFormed] at h2 h4 h6 h7 h8 h9
  simp only [Hash.WellFormed] at h3 h5
  simp only [decodeUpdateUserPis, hlen, ne_eq, not_true_eq_false, if_false]
  simp only [UpdateUserPublicInputs.encode, List.cons_append, List.append_assoc,
    take_scalar_cons, bind_d_ok, take_limbs_append h1, take_limbs_append h2,
    take_limbs_append h3, take_limbs_append h4, take_limbs_append h5, take_limbs_append h6,
    take_limbs_append h7, take_limbs_append h8]
  rw [show u.newBpSigChain.limbs = u.newBpSigChain.limbs ++ ([] : List Nat) by simp]
  simp only [take_limbs_append h9, bind_d_ok]

/-! ## Opaque environment

Everything cryptographic in the file is a callback here. `accepts` stands for
`VerifierCircuitData::verify` (previous chain proof, update proof, deposit chain proof,
channel-registration chain proof); `merkleRoot` stands for
`IncrementalMerkleProof::get_root`; `vdEncode`/`vdDecode` stand for the cyclic verifier
key limb codec. No property of any of them is proved. -/

structure VerifierCircuitData where
  /-- identity of the `CommonCircuitData` this key belongs to (compared by `prove`). -/
  common : Nat
  vdLen : Nat
  verifierOnly : VerifierKey
  deriving DecidableEq, Repr, Inhabited

structure Proof where
  publicInputs : List Nat
  deriving DecidableEq, Repr, Inhabited

structure MerkleProof where
  siblings : List Hash
  deriving DecidableEq, Repr, Inhabited

structure StepEnv where
  accepts : VerifierCircuitData → Proof → Bool
  merkleRoot : MerkleProof → PublicState → Nat → Hash
  vdEncode : VerifierKey → List Nat
  vdDecode : List Nat → Except DecodeError VerifierKey

/-- The undischarged assumption that the verifier-key limb codec is a codec at all. -/
structure VdCodecSound (env : StepEnv) (vdLen : Nat) : Prop where
  encode_length : ∀ k, (env.vdEncode k).length = vdLen
  decode_encode : ∀ k, env.vdDecode (env.vdEncode k) = .ok k

def decodeBlockChainPis (env : StepEnv) (vdLen : Nat) (xs : List Nat) :
    Except DecodeError BlockChainPublicInputs :=
  if xs.length ≠ blockChainPublicInputsLen + vdLen then
    .error (.invalidLength (blockChainPublicInputsLen + vdLen) xs.length)
  else
    bindD (decodeExtendedPublicStateAt xs) fun (initExt, xs) =>
    bindD (decodeExtendedPublicStateAt xs) fun (ext, xs) =>
    bindD (env.vdDecode (xs.take vdLen)) fun vd =>
    .ok { initialExt := initExt, ext := ext, vd := vd }

def decodeDepositChainPis (env : StepEnv) (vdLen : Nat) (xs : List Nat) :
    Except DecodeError DepositChainPublicInputs :=
  if xs.length ≠ depositChainPublicInputsLen + vdLen then
    .error (.invalidLength (depositChainPublicInputsLen + vdLen) xs.length)
  else
    bindD (takeLimbs bytes32Len "initial_deposit_hash_chain" xs) fun (idhc, xs) =>
    bindD (takeLimbs poseidonHashOutLen "initial_deposit_tree_root" xs) fun (idtr, xs) =>
    bindD (takeScalar "initial_deposit_count" xs) fun (idc, xs) =>
    bindD (takeLimbs bytes32Len "deposit_hash_chain" xs) fun (dhc, xs) =>
    bindD (takeLimbs poseidonHashOutLen "deposit_tree_root" xs) fun (dtr, xs) =>
    bindD (takeScalar "deposit_count" xs) fun (dc, xs) =>
    bindD (takeScalar "block_number" xs) fun (bn, xs) =>
    bindD (env.vdDecode (xs.take vdLen)) fun vd =>
    .ok { initialDepositHashChain := ⟨idhc⟩, initialDepositTreeRoot := ⟨idtr⟩,
          initialDepositCount := idc, depositHashChain := ⟨dhc⟩, depositTreeRoot := ⟨dtr⟩,
          depositCount := dc, blockNumber := bn, vd := vd }

def decodeChannelRegChainPis (env : StepEnv) (vdLen : Nat) (xs : List Nat) :
    Except DecodeError ChannelRegChainPublicInputs :=
  if xs.length ≠ channelRegChainPublicInputsLen + vdLen then
    .error (.invalidLength (channelRegChainPublicInputsLen + vdLen) xs.length)
  else
    bindD (takeLimbs bytes32Len "initial_channel_reg_hash_chain" xs) fun (ichc, xs) =>
    bindD (takeLimbs poseidonHashOutLen "initial_channel_tree_root" xs) fun (ictr, xs) =>
    bindD (takeScalar "initial_channel_reg_count" xs) fun (icc, xs) =>
    bindD (takeLimbs bytes32Len "channel_reg_hash_chain" xs) fun (chc, xs) =>
    bindD (takeLimbs poseidonHashOutLen "channel_tree_root" xs) fun (ctr, xs) =>
    bindD (takeScalar "channel_reg_count" xs) fun (cc, xs) =>
    bindD (takeScalar "block_number" xs) fun (bn, xs) =>
    bindD (env.vdDecode (xs.take vdLen)) fun vd =>
    .ok { initialChannelRegHashChain := ⟨ichc⟩, initialChannelTreeRoot := ⟨ictr⟩,
          initialChannelRegCount := icc, channelRegHashChain := ⟨chc⟩, channelTreeRoot := ⟨ctr⟩,
          channelRegCount := cc, blockNumber := bn, vd := vd }

theorem decode_block_chain_pis_length_gate {env : StepEnv} {vdLen : Nat} {xs : List Nat}
    (bad : xs.length ≠ blockChainPublicInputsLen + vdLen) :
    decodeBlockChainPis env vdLen xs =
      .error (.invalidLength (blockChainPublicInputsLen + vdLen) xs.length) := by
  simp [decodeBlockChainPis, bad]

theorem decode_deposit_chain_pis_length_gate {env : StepEnv} {vdLen : Nat} {xs : List Nat}
    (bad : xs.length ≠ depositChainPublicInputsLen + vdLen) :
    decodeDepositChainPis env vdLen xs =
      .error (.invalidLength (depositChainPublicInputsLen + vdLen) xs.length) := by
  simp [decodeDepositChainPis, bad]

theorem decode_channel_reg_chain_pis_length_gate {env : StepEnv} {vdLen : Nat} {xs : List Nat}
    (bad : xs.length ≠ channelRegChainPublicInputsLen + vdLen) :
    decodeChannelRegChainPis env vdLen xs =
      .error (.invalidLength (channelRegChainPublicInputsLen + vdLen) xs.length) := by
  simp [decodeChannelRegChainPis, bad]

theorem decode_update_user_pis_length_gate {xs : List Nat}
    (bad : xs.length ≠ updateUserPublicInputsLen) :
    decodeUpdateUserPis xs = .error (.invalidLength updateUserPublicInputsLen xs.length) := by
  simp [decodeUpdateUserPis, bad]

/-! ## Errors and the native witness -/

inductive BlockStepError where
  | invalidInput (message : String)
  | invalidProof (message : String)
  | missingUpdateUserVerifierData (numUsers : Nat)
  | depositChainPublicInputs (error : DecodeError)
  | channelRegChainPublicInputs (error : DecodeError)
  | blockChainPublicInputs (error : DecodeError)
  | updateUserPublicInputs (message : String)
  | publicStateMerkleProof (message : String)
  | failedToProve (message : String)
  deriving DecidableEq, Repr

abbrev Result (α : Type) := Except BlockStepError α

def check (condition : Prop) [Decidable condition] (error : BlockStepError) : Result Unit :=
  if condition then .ok () else .error error

theorem check_ok_iff (condition : Prop) [Decidable condition] (error : BlockStepError) :
    check condition error = .ok () ↔ condition := by
  unfold check
  split
  · rename_i h; simp [h]
  · rename_i h; simp [h]

theorem bind_ok_iff {α β : Type} (r : Result α) (f : α → Result β) (value : β) :
    (r >>= f) = .ok value ↔ ∃ x, r = .ok x ∧ f x = .ok value := by
  cases r <;> simp [Bind.bind, Except.bind]

theorem unit_bind_ok_iff {α : Type} (r : Result Unit) (s : Result α) (value : α) :
    (r >>= fun _ => s) = .ok value ↔ r = .ok () ∧ s = .ok value := by
  cases r with
  | error e => simp [Bind.bind, Except.bind]
  | ok u => cases u; simp [Bind.bind, Except.bind]

theorem exists_unit (p : Unit → Prop) : (∃ x, p x) ↔ p () := by
  constructor
  · rintro ⟨⟨⟩, h⟩; exact h
  · intro h; exact ⟨(), h⟩

theorem pure_ok_iff {α : Type} (a b : α) : (pure a : Result α) = .ok b ↔ a = b := by
  constructor
  · intro h; exact Except.ok.inj h
  · intro h; subst h; rfl

structure BlockStepWitness where
  /-- padding number of users in this block; selects one update-account circuit. -/
  numUsers : Nat
  initialPublicState : Option ExtendedPublicState
  prevBlockChainProof : Option Proof
  depositHashChainProof : Option Proof
  channelRegHashChainProof : Option Proof
  updateUserProof : Proof
  publicStateMerkleProof : MerkleProof
  deriving DecidableEq, Repr, Inhabited

/-- `update_account_vds.iter().map(...).collect::<HashMap<_,_>>()` keeps the LAST entry for a
    repeated `num_users`, unlike a first-match association lookup. -/
def lookupLast (key : Nat) : List (Nat × VerifierCircuitData) → Option VerifierCircuitData
  | [] => none
  | (k, v) :: rest =>
      match lookupLast key rest with
      | some v' => some v'
      | none => if k = key then some v else none

theorem lookup_last_prefers_tail (key k : Nat) (v : VerifierCircuitData)
    (rest : List (Nat × VerifierCircuitData)) (v' : VerifierCircuitData)
    (found : lookupLast key rest = some v') :
    lookupLast key ((k, v) :: rest) = some v' := by
  simp [lookupLast, found]

/-! ## Native acceptance: `BlockStepWitness::to_public_inputs`

Executable mirror of the Rust control flow, including the order of the checks and which
error each one raises. Nothing here is claimed about the proofs it verifies. -/

/-! The `?`/`map_err` conversions from a decoding error to a `BlockStepError`, named so the
acceptance proofs peel them with a lemma instead of a `split`. -/

def liftBlockChain (r : Except DecodeError BlockChainPublicInputs) :
    Result BlockChainPublicInputs :=
  match r with
  | .error e => .error (.blockChainPublicInputs e)
  | .ok v => .ok v

def liftDeposit (r : Except DecodeError DepositChainPublicInputs) :
    Result DepositChainPublicInputs :=
  match r with
  | .error e => .error (.depositChainPublicInputs e)
  | .ok v => .ok v

def liftChannelReg (r : Except DecodeError ChannelRegChainPublicInputs) :
    Result ChannelRegChainPublicInputs :=
  match r with
  | .error e => .error (.channelRegChainPublicInputs e)
  | .ok v => .ok v

def liftUpdate (r : Except DecodeError UpdateUserPublicInputs) :
    Result UpdateUserPublicInputs :=
  match r with
  | .error _ => .error (.updateUserPublicInputs "invalid update-account public inputs")
  | .ok v => .ok v

def liftVd (numUsers : Nat) (o : Option VerifierCircuitData) : Result VerifierCircuitData :=
  match o with
  | none => .error (.missingUpdateUserVerifierData numUsers)
  | some vd => .ok vd

theorem lift_block_chain_ok_iff (r : Except DecodeError BlockChainPublicInputs)
    (v : BlockChainPublicInputs) : liftBlockChain r = .ok v ↔ r = .ok v := by
  cases r <;> simp [liftBlockChain]

theorem lift_deposit_ok_iff (r : Except DecodeError DepositChainPublicInputs)
    (v : DepositChainPublicInputs) : liftDeposit r = .ok v ↔ r = .ok v := by
  cases r <;> simp [liftDeposit]

theorem lift_channel_reg_ok_iff (r : Except DecodeError ChannelRegChainPublicInputs)
    (v : ChannelRegChainPublicInputs) : liftChannelReg r = .ok v ↔ r = .ok v := by
  cases r <;> simp [liftChannelReg]

theorem lift_update_ok_iff (r : Except DecodeError UpdateUserPublicInputs)
    (v : UpdateUserPublicInputs) : liftUpdate r = .ok v ↔ r = .ok v := by
  cases r <;> simp [liftUpdate]

theorem lift_vd_ok_iff (numUsers : Nat) (o : Option VerifierCircuitData)
    (v : VerifierCircuitData) : liftVd numUsers o = .ok v ↔ o = some v := by
  cases o <;> simp [liftVd]

/-- The previous chain state: either the previous proof's public inputs, or (first block)
    the caller-supplied `initial_public_state`, used as BOTH the initial and the current
    extended state. -/
def resolvePrev (env : StepEnv) (blockChainVd : VerifierCircuitData)
    (w : BlockStepWitness) : Result BlockChainPublicInputs :=
  match w.prevBlockChainProof with
  | some prevProof =>
      if !env.accepts blockChainVd prevProof then
        .error (.invalidProof "previous block chain proof invalid")
      else
        liftBlockChain (decodeBlockChainPis env blockChainVd.vdLen prevProof.publicInputs)
  | none =>
      match w.initialPublicState with
      | none =>
          .error (.invalidInput
            "initial_public_state must be provided when previous block proof is absent")
      | some initialState =>
          .ok { initialExt := initialState, ext := initialState,
                vd := blockChainVd.verifierOnly }

structure DepositOutcome where
  depositHashChain : Bytes32
  depositTreeRoot : Hash
  depositCount : Nat
  deriving DecidableEq, Repr, Inhabited

structure ChannelRegOutcome where
  accountTreeRoot : Hash
  channelRegHashChain : Bytes32
  deriving DecidableEq, Repr, Inhabited

/-- Deposit fold. The chain only advances when the update proof's declared
    `deposit_hash_chain` differs from the previous one, and then only via a deposit chain
    proof that starts exactly at the previous triple and ends at the declared value. -/
def resolveDeposit (env : StepEnv) (depositChainVd : VerifierCircuitData)
    (prevExt : ExtendedPublicState) (blockNumber : Nat) (upd : UpdateUserPublicInputs)
    (depositProof : Option Proof) : Result DepositOutcome :=
  if prevExt.depositHashChain = upd.depositHashChain then
    .ok { depositHashChain := prevExt.depositHashChain,
          depositTreeRoot := prevExt.inner.depositTreeRoot,
          depositCount := prevExt.depositCount }
  else
    match depositProof with
    | none =>
        .error (.invalidInput
          "deposit_hash_chain_proof must be provided when deposit hash chain is updated")
    | some proof => do
        let _ ← check (env.accepts depositChainVd proof = true)
          (.invalidProof "deposit hash chain proof invalid")
        let di ← liftDeposit (decodeDepositChainPis env depositChainVd.vdLen proof.publicInputs)
        let _ ← check (di.initialDepositHashChain = prevExt.depositHashChain)
          (.invalidInput "deposit proof initial deposit hash chain mismatch")
        let _ ← check (di.initialDepositTreeRoot = prevExt.inner.depositTreeRoot)
          (.invalidInput "deposit proof initial deposit tree root mismatch")
        let _ ← check (di.initialDepositCount = prevExt.depositCount)
          (.invalidInput "deposit proof initial deposit count mismatch")
        let _ ← check (di.depositHashChain = upd.depositHashChain)
          (.invalidInput
            "deposit proof resulting deposit hash chain must match update account input")
        let _ ← check (di.blockNumber = blockNumber)
          (.invalidInput "deposit proof block number mismatch")
        .ok { depositHashChain := di.depositHashChain, depositTreeRoot := di.depositTreeRoot,
              depositCount := di.depositCount }

/-- Channel-registration fold, including the R6 intra-block exclusion and the
    "proof present iff the chain moves" guard that follows the `if let` block. -/
def resolveChannelReg (env : StepEnv) (channelRegChainVd : VerifierCircuitData)
    (prevExt : ExtendedPublicState) (blockNumber : Nat) (upd : UpdateUserPublicInputs)
    (regProof : Option Proof) : Result ChannelRegOutcome :=
  match regProof with
  | none =>
      .ok { accountTreeRoot := upd.newAccountTreeRoot,
            channelRegHashChain := prevExt.channelRegHashChain }
  | some proof => do
      let _ ← check (env.accepts channelRegChainVd proof = true)
        (.invalidProof "channel reg hash chain proof invalid")
      let ci ← liftChannelReg
        (decodeChannelRegChainPis env channelRegChainVd.vdLen proof.publicInputs)
      let _ ← check (ci.initialChannelRegHashChain = prevExt.channelRegHashChain)
        (.invalidInput "channel reg proof initial channel reg hash chain mismatch")
      let _ ← check (ci.initialChannelTreeRoot = prevExt.inner.accountTreeRoot)
        (.invalidInput "channel reg proof initial channel tree root mismatch")
      let _ ← check (ci.blockNumber = blockNumber)
        (.invalidInput "channel reg proof block number mismatch")
      let _ ← check (upd.newAccountTreeRoot = upd.prevAccountTreeRoot)
        (.invalidInput "registration block must not update the account tree (R6 exclusion)")
      let _ ← check (ci.channelRegHashChain ≠ prevExt.channelRegHashChain)
        (.invalidInput
          "channel_reg_hash_chain_proof must be provided iff the channel reg hash chain changes")
      .ok { accountTreeRoot := ci.channelTreeRoot,
            channelRegHashChain := ci.channelRegHashChain }

/-- The emitted step public inputs: the initial extended state and the cyclic verifier key
    are carried over unchanged from the previous chain proof; everything else is rebuilt. -/
def nativeOutput (prevInputs : BlockChainPublicInputs) (blockNumber : Nat)
    (upd : UpdateUserPublicInputs) (dep : DepositOutcome) (reg : ChannelRegOutcome)
    (prevPublicStateRoot : Hash) : BlockChainPublicInputs :=
  { initialExt := prevInputs.initialExt
    ext := { inner := { blockNumber := blockNumber
                        timestamp := upd.blockTimestamp
                        accountTreeRoot := reg.accountTreeRoot
                        depositTreeRoot := dep.depositTreeRoot
                        prevPublicStateRoot := prevPublicStateRoot }
             blockHashChain := upd.newBlockHashChain
             depositHashChain := dep.depositHashChain
             depositCount := dep.depositCount
             channelRegHashChain := reg.channelRegHashChain
             bpSigChain := upd.newBpSigChain }
    vd := prevInputs.vd }

def toPublicInputs (env : StepEnv) (blockChainVd : VerifierCircuitData)
    (updateAccountVds : List (Nat × VerifierCircuitData))
    (depositChainVd channelRegChainVd : VerifierCircuitData)
    (w : BlockStepWitness) : Result BlockChainPublicInputs := do
  let prevInputs ← resolvePrev env blockChainVd w
  let prevExt := prevInputs.ext
  let prevState := prevExt.inner
  let updateVd ← liftVd w.numUsers (lookupLast w.numUsers updateAccountVds)
  let _ ← check (env.accepts updateVd w.updateUserProof = true)
    (.invalidProof "update account proof invalid")
  let upd ← liftUpdate (decodeUpdateUserPis w.updateUserProof.publicInputs)
  let _ ← check (prevState.blockNumber + 1 ≤ u63Max)
    (.invalidInput "previous block number is at max value")
  let blockNumber := prevState.blockNumber + 1
  let _ ← check (upd.blockNumber = blockNumber)
    (.invalidInput "update account proof block number must be previous block number + 1")
  let _ ← check (upd.prevAccountTreeRoot = prevState.accountTreeRoot)
    (.invalidInput "update account proof initial user tree root mismatch")
  let _ ← check (upd.prevBlockHashChain = prevExt.blockHashChain)
    (.invalidInput "update account proof initial block hash chain mismatch")
  let _ ← check (upd.prevBpSigChain = prevExt.bpSigChain)
    (.invalidInput "update account proof initial bp_sig_chain mismatch")
  let dep ← resolveDeposit env depositChainVd prevExt blockNumber upd w.depositHashChainProof
  let reg ← resolveChannelReg env channelRegChainVd prevExt blockNumber upd
    w.channelRegHashChainProof
  let _ ← check (upd.channelRegHashChain = reg.channelRegHashChain)
    (.invalidInput
      "block channel_reg_hash_chain (in block hash) must equal the resulting ext-state channel_reg_hash_chain")
  let _ ← check
    (env.merkleRoot w.publicStateMerkleProof emptyPublicStateLeaf prevState.blockNumber
      = prevState.prevPublicStateRoot)
    (.publicStateMerkleProof "failed to verify empty public state membership")
  .ok (nativeOutput prevInputs blockNumber upd dep reg
        (env.merkleRoot w.publicStateMerkleProof prevState prevState.blockNumber))

/-! ## What native acceptance establishes

`NativeFacts` is exactly the conjunction of the checks `to_public_inputs` performs, plus
the shape of what it returns. Everything below is derived from it, so no theorem about the
native path can quietly claim more than the Rust checks. -/

structure NativeFacts (env : StepEnv) (blockChainVd : VerifierCircuitData)
    (updateAccountVds : List (Nat × VerifierCircuitData))
    (depositChainVd channelRegChainVd : VerifierCircuitData)
    (w : BlockStepWitness) (out : BlockChainPublicInputs)
    (prevInputs : BlockChainPublicInputs) (upd : UpdateUserPublicInputs)
    (dep : DepositOutcome) (reg : ChannelRegOutcome)
    (updateVd : VerifierCircuitData) : Prop where
  prev_resolved : resolvePrev env blockChainVd w = .ok prevInputs
  update_vd_found : lookupLast w.numUsers updateAccountVds = some updateVd
  update_proof_accepted : env.accepts updateVd w.updateUserProof = true
  update_pis_decoded : decodeUpdateUserPis w.updateUserProof.publicInputs = .ok upd
  block_number_in_range : prevInputs.ext.inner.blockNumber + 1 ≤ u63Max
  update_block_number : upd.blockNumber = prevInputs.ext.inner.blockNumber + 1
  update_prev_account_root : upd.prevAccountTreeRoot = prevInputs.ext.inner.accountTreeRoot
  update_prev_block_hash_chain : upd.prevBlockHashChain = prevInputs.ext.blockHashChain
  update_prev_bp_sig_chain : upd.prevBpSigChain = prevInputs.ext.bpSigChain
  deposit_resolved : resolveDeposit env depositChainVd prevInputs.ext
    (prevInputs.ext.inner.blockNumber + 1) upd w.depositHashChainProof = .ok dep
  channel_reg_resolved : resolveChannelReg env channelRegChainVd prevInputs.ext
    (prevInputs.ext.inner.blockNumber + 1) upd w.channelRegHashChainProof = .ok reg
  reg_chain_anchored_in_block_hash : upd.channelRegHashChain = reg.channelRegHashChain
  empty_leaf_membership :
    env.merkleRoot w.publicStateMerkleProof emptyPublicStateLeaf prevInputs.ext.inner.blockNumber
      = prevInputs.ext.inner.prevPublicStateRoot
  output_shape : out = nativeOutput prevInputs (prevInputs.ext.inner.blockNumber + 1) upd dep reg
    (env.merkleRoot w.publicStateMerkleProof prevInputs.ext.inner prevInputs.ext.inner.blockNumber)

theorem to_public_inputs_native_facts {env : StepEnv} {blockChainVd : VerifierCircuitData}
    {updateAccountVds : List (Nat × VerifierCircuitData)}
    {depositChainVd channelRegChainVd : VerifierCircuitData} {w : BlockStepWitness}
    {out : BlockChainPublicInputs}
    (accepted : toPublicInputs env blockChainVd updateAccountVds depositChainVd
      channelRegChainVd w = .ok out) :
    ∃ (prevInputs : BlockChainPublicInputs) (upd : UpdateUserPublicInputs)
      (dep : DepositOutcome) (reg : ChannelRegOutcome) (updateVd : VerifierCircuitData),
      NativeFacts env blockChainVd updateAccountVds depositChainVd channelRegChainVd w out
        prevInputs upd dep reg updateVd := by
  simp only [toPublicInputs, bind_ok_iff, unit_bind_ok_iff, exists_unit, check_ok_iff,
    pure_ok_iff, lift_vd_ok_iff, lift_update_ok_iff, Except.ok.injEq] at accepted
  obtain ⟨prevInputs, hprev, accepted⟩ := accepted
  obtain ⟨updateVd, hvd, accepted⟩ := accepted
  obtain ⟨hacc, accepted⟩ := accepted
  obtain ⟨upd, hupd, accepted⟩ := accepted
  obtain ⟨hrange, accepted⟩ := accepted
  obtain ⟨hbn, accepted⟩ := accepted
  obtain ⟨hatr, accepted⟩ := accepted
  obtain ⟨hbhc, accepted⟩ := accepted
  obtain ⟨hbsc, accepted⟩ := accepted
  obtain ⟨dep, hdep, accepted⟩ := accepted
  obtain ⟨reg, hreg, accepted⟩ := accepted
  obtain ⟨hg6, accepted⟩ := accepted
  obtain ⟨hmerkle, accepted⟩ := accepted
  exact ⟨prevInputs, upd, dep, reg, updateVd,
        { prev_resolved := hprev, update_vd_found := hvd, update_proof_accepted := hacc
          update_pis_decoded := hupd, block_number_in_range := hrange
          update_block_number := hbn, update_prev_account_root := hatr
          update_prev_block_hash_chain := hbhc, update_prev_bp_sig_chain := hbsc
          deposit_resolved := hdep, channel_reg_resolved := hreg
          reg_chain_anchored_in_block_hash := hg6, empty_leaf_membership := hmerkle
          output_shape := accepted.symm }⟩

/-! ### Consequences of native acceptance -/

theorem to_public_inputs_increments_block_number {env : StepEnv}
    {blockChainVd : VerifierCircuitData} {vds : List (Nat × VerifierCircuitData)}
    {depositChainVd channelRegChainVd : VerifierCircuitData} {w : BlockStepWitness}
    {out : BlockChainPublicInputs}
    (accepted : toPublicInputs env blockChainVd vds depositChainVd channelRegChainVd w = .ok out) :
    ∃ prev : BlockChainPublicInputs,
      resolvePrev env blockChainVd w = .ok prev ∧
      out.ext.inner.blockNumber = prev.ext.inner.blockNumber + 1 ∧
      out.ext.inner.blockNumber ≤ u63Max := by
  obtain ⟨prev, upd, dep, reg, updateVd, facts⟩ := to_public_inputs_native_facts accepted
  refine ⟨prev, facts.prev_resolved, ?_, ?_⟩
  · rw [facts.output_shape]; rfl
  · rw [facts.output_shape]; exact facts.block_number_in_range

theorem to_public_inputs_folds_block_hash_chain {env : StepEnv}
    {blockChainVd : VerifierCircuitData} {vds : List (Nat × VerifierCircuitData)}
    {depositChainVd channelRegChainVd : VerifierCircuitData} {w : BlockStepWitness}
    {out : BlockChainPublicInputs}
    (accepted : toPublicInputs env blockChainVd vds depositChainVd channelRegChainVd w = .ok out) :
    ∃ (prev : BlockChainPublicInputs) (upd : UpdateUserPublicInputs),
      resolvePrev env blockChainVd w = .ok prev ∧
      decodeUpdateUserPis w.updateUserProof.publicInputs = .ok upd ∧
      upd.prevBlockHashChain = prev.ext.blockHashChain ∧
      out.ext.blockHashChain = upd.newBlockHashChain ∧
      upd.prevBpSigChain = prev.ext.bpSigChain ∧
      out.ext.bpSigChain = upd.newBpSigChain := by
  obtain ⟨prev, upd, dep, reg, updateVd, facts⟩ := to_public_inputs_native_facts accepted
  refine ⟨prev, upd, facts.prev_resolved, facts.update_pis_decoded,
    facts.update_prev_block_hash_chain, ?_, facts.update_prev_bp_sig_chain, ?_⟩ <;>
    rw [facts.output_shape] <;> rfl

theorem to_public_inputs_preserves_initial_state_and_key {env : StepEnv}
    {blockChainVd : VerifierCircuitData} {vds : List (Nat × VerifierCircuitData)}
    {depositChainVd channelRegChainVd : VerifierCircuitData} {w : BlockStepWitness}
    {out : BlockChainPublicInputs}
    (accepted : toPublicInputs env blockChainVd vds depositChainVd channelRegChainVd w = .ok out) :
    ∃ prev : BlockChainPublicInputs,
      resolvePrev env blockChainVd w = .ok prev ∧
      out.initialExt = prev.initialExt ∧ out.vd = prev.vd := by
  obtain ⟨prev, upd, dep, reg, updateVd, facts⟩ := to_public_inputs_native_facts accepted
  exact ⟨prev, facts.prev_resolved, by rw [facts.output_shape]; rfl, by
    rw [facts.output_shape]; rfl⟩

theorem resolve_deposit_no_change_freezes {env : StepEnv} {vd : VerifierCircuitData}
    {prevExt : ExtendedPublicState} {bn : Nat} {upd : UpdateUserPublicInputs}
    {proof : Option Proof} {dep : DepositOutcome}
    (same : prevExt.depositHashChain = upd.depositHashChain)
    (resolved : resolveDeposit env vd prevExt bn upd proof = .ok dep) :
    dep.depositHashChain = prevExt.depositHashChain ∧
    dep.depositTreeRoot = prevExt.inner.depositTreeRoot ∧
    dep.depositCount = prevExt.depositCount := by
  simp only [resolveDeposit, same, if_pos] at resolved
  cases resolved
  exact ⟨same.symm, rfl, rfl⟩

theorem resolve_deposit_change_needs_linked_proof {env : StepEnv} {vd : VerifierCircuitData}
    {prevExt : ExtendedPublicState} {bn : Nat} {upd : UpdateUserPublicInputs}
    {proof : Option Proof} {dep : DepositOutcome}
    (changed : prevExt.depositHashChain ≠ upd.depositHashChain)
    (resolved : resolveDeposit env vd prevExt bn upd proof = .ok dep) :
    ∃ (p : Proof) (di : DepositChainPublicInputs),
      proof = some p ∧
      env.accepts vd p = true ∧
      decodeDepositChainPis env vd.vdLen p.publicInputs = .ok di ∧
      di.initialDepositHashChain = prevExt.depositHashChain ∧
      di.initialDepositTreeRoot = prevExt.inner.depositTreeRoot ∧
      di.initialDepositCount = prevExt.depositCount ∧
      di.depositHashChain = upd.depositHashChain ∧
      di.blockNumber = bn ∧
      dep = { depositHashChain := di.depositHashChain, depositTreeRoot := di.depositTreeRoot,
              depositCount := di.depositCount } := by
  simp only [resolveDeposit, changed, if_neg, not_false_eq_true] at resolved
  cases proof with
  | none => exact absurd resolved (by simp)
  | some p =>
    simp only [bind_ok_iff, unit_bind_ok_iff, exists_unit, check_ok_iff, pure_ok_iff,
      lift_deposit_ok_iff, Except.ok.injEq] at resolved
    obtain ⟨hacc, resolved⟩ := resolved
    obtain ⟨di, hdec, resolved⟩ := resolved
    obtain ⟨h1, resolved⟩ := resolved
    obtain ⟨h2, resolved⟩ := resolved
    obtain ⟨h3, resolved⟩ := resolved
    obtain ⟨h4, resolved⟩ := resolved
    obtain ⟨h5, resolved⟩ := resolved
    exact ⟨p, di, rfl, hacc, hdec, h1, h2, h3, h4, h5, resolved.symm⟩

theorem resolve_channel_reg_absent_freezes {env : StepEnv} {vd : VerifierCircuitData}
    {prevExt : ExtendedPublicState} {bn : Nat} {upd : UpdateUserPublicInputs}
    {reg : ChannelRegOutcome}
    (resolved : resolveChannelReg env vd prevExt bn upd none = .ok reg) :
    reg.accountTreeRoot = upd.newAccountTreeRoot ∧
    reg.channelRegHashChain = prevExt.channelRegHashChain := by
  simp only [resolveChannelReg] at resolved
  cases resolved
  exact ⟨rfl, rfl⟩

theorem resolve_channel_reg_present_excludes_user_update {env : StepEnv}
    {vd : VerifierCircuitData} {prevExt : ExtendedPublicState} {bn : Nat}
    {upd : UpdateUserPublicInputs} {p : Proof} {reg : ChannelRegOutcome}
    (resolved : resolveChannelReg env vd prevExt bn upd (some p) = .ok reg) :
    ∃ ci : ChannelRegChainPublicInputs,
      env.accepts vd p = true ∧
      decodeChannelRegChainPis env vd.vdLen p.publicInputs = .ok ci ∧
      ci.initialChannelRegHashChain = prevExt.channelRegHashChain ∧
      ci.initialChannelTreeRoot = prevExt.inner.accountTreeRoot ∧
      ci.blockNumber = bn ∧
      upd.newAccountTreeRoot = upd.prevAccountTreeRoot ∧
      ci.channelRegHashChain ≠ prevExt.channelRegHashChain ∧
      reg = { accountTreeRoot := ci.channelTreeRoot,
              channelRegHashChain := ci.channelRegHashChain } := by
  simp only [resolveChannelReg, bind_ok_iff, unit_bind_ok_iff, exists_unit, check_ok_iff,
    pure_ok_iff, lift_channel_reg_ok_iff, Except.ok.injEq] at resolved
  obtain ⟨hacc, resolved⟩ := resolved
  obtain ⟨ci, hdec, resolved⟩ := resolved
  obtain ⟨h1, resolved⟩ := resolved
  obtain ⟨h2, resolved⟩ := resolved
  obtain ⟨h3, resolved⟩ := resolved
  obtain ⟨h4, resolved⟩ := resolved
  obtain ⟨h5, resolved⟩ := resolved
  exact ⟨ci, hacc, hdec, h1, h2, h3, h4, h5, resolved.symm⟩

/-! ### Deposit / registration conditionality, and the unanchored first block -/

theorem resolve_deposit_ignores_redundant_proof (env : StepEnv) (vd : VerifierCircuitData)
    (prevExt : ExtendedPublicState) (bn : Nat) (upd : UpdateUserPublicInputs)
    (proof : Option Proof) (same : prevExt.depositHashChain = upd.depositHashChain) :
    resolveDeposit env vd prevExt bn upd proof =
      .ok { depositHashChain := prevExt.depositHashChain,
            depositTreeRoot := prevExt.inner.depositTreeRoot,
            depositCount := prevExt.depositCount } := by
  simp [resolveDeposit, same]

theorem resolve_channel_reg_present_moves_chain {env : StepEnv} {vd : VerifierCircuitData}
    {prevExt : ExtendedPublicState} {bn : Nat} {upd : UpdateUserPublicInputs} {p : Proof}
    {reg : ChannelRegOutcome}
    (resolved : resolveChannelReg env vd prevExt bn upd (some p) = .ok reg) :
    reg.channelRegHashChain ≠ prevExt.channelRegHashChain := by
  obtain ⟨ci, _, _, _, _, _, _, hne, hshape⟩ :=
    resolve_channel_reg_present_excludes_user_update resolved
  rw [hshape]; exact hne

theorem channel_reg_proof_present_iff_chain_moves {env : StepEnv} {vd : VerifierCircuitData}
    {prevExt : ExtendedPublicState} {bn : Nat} {upd : UpdateUserPublicInputs}
    {regProof : Option Proof} {reg : ChannelRegOutcome}
    (resolved : resolveChannelReg env vd prevExt bn upd regProof = .ok reg) :
    reg.channelRegHashChain ≠ prevExt.channelRegHashChain ↔ regProof ≠ none := by
  cases regProof with
  | none =>
    obtain ⟨_, hsame⟩ := resolve_channel_reg_absent_freezes resolved
    simp [hsame]
  | some p =>
    have hne : (some p : Option Proof) ≠ none := by simp
    exact ⟨fun _ => hne, fun _ => resolve_channel_reg_present_moves_chain resolved⟩

/-- A first step (no previous chain proof) accepts an ARBITRARY `initial_public_state` and
    publishes it as both the initial and the previous state. Nothing in this file pins it;
    the anchoring lives in the chain wrapper and in the contract snapshot. -/
theorem resolve_prev_first_block_accepts_any_initial_state (env : StepEnv)
    (blockChainVd : VerifierCircuitData) (w : BlockStepWitness) (s : ExtendedPublicState)
    (noPrev : w.prevBlockChainProof = none) (init : w.initialPublicState = some s) :
    resolvePrev env blockChainVd w =
      .ok { initialExt := s, ext := s, vd := blockChainVd.verifierOnly } := by
  simp [resolvePrev, noPrev, init]

theorem resolve_prev_first_block_needs_initial_state (env : StepEnv)
    (blockChainVd : VerifierCircuitData) (w : BlockStepWitness)
    (noPrev : w.prevBlockChainProof = none) (noInit : w.initialPublicState = none) :
    resolvePrev env blockChainVd w = .error (.invalidInput
      "initial_public_state must be provided when previous block proof is absent") := by
  simp [resolvePrev, noPrev, noInit]

theorem resolve_prev_rejects_unaccepted_proof (env : StepEnv)
    (blockChainVd : VerifierCircuitData) (w : BlockStepWitness) (p : Proof)
    (hasPrev : w.prevBlockChainProof = some p) (rejected : env.accepts blockChainVd p = false) :
    resolvePrev env blockChainVd w =
      .error (.invalidProof "previous block chain proof invalid") := by
  simp [resolvePrev, hasPrev, rejected]

/-- The emitted timestamp is whatever the update proof declared: `to_public_inputs` performs
    NO comparison against the previous timestamp (no monotonicity, no bound). -/
theorem to_public_inputs_timestamp_is_update_declared {env : StepEnv}
    {blockChainVd : VerifierCircuitData} {vds : List (Nat × VerifierCircuitData)}
    {depositChainVd channelRegChainVd : VerifierCircuitData} {w : BlockStepWitness}
    {out : BlockChainPublicInputs}
    (accepted : toPublicInputs env blockChainVd vds depositChainVd channelRegChainVd w = .ok out) :
    ∃ upd : UpdateUserPublicInputs,
      decodeUpdateUserPis w.updateUserProof.publicInputs = .ok upd ∧
      out.ext.inner.timestamp = upd.blockTimestamp := by
  obtain ⟨prev, upd, dep, reg, updateVd, facts⟩ := to_public_inputs_native_facts accepted
  exact ⟨upd, facts.update_pis_decoded, by rw [facts.output_shape]; rfl⟩

/-! ## `BlockStepTarget::set_witness` and `BlockStepCircuit::prove` (native side) -/

def dummyLookup (key : Nat) : List (Nat × Proof) → Option Proof
  | [] => none
  | (k, v) :: rest =>
      match dummyLookup key rest with
      | some v' => some v'
      | none => if k = key then some v else none

/-- The one-hot flags `set_witness` writes: `value.num_users == num_users` for EVERY slot,
    so a repeated `num_users` sets more than one flag. -/
def slotFlags (numUsers : Nat) : List (Nat × VerifierCircuitData) → List Bool
  | [] => []
  | (n, _) :: rest => decide (numUsers = n) :: slotFlags numUsers rest

/-- The witness-writing loop: for the selected slot the real update proof is parsed (a
    parse failure is an error), for every other slot a dummy proof must exist. -/
def slotWitness (dummies : List (Nat × Proof)) (w : BlockStepWitness) :
    List (Nat × VerifierCircuitData) → Result Bool
  | [] => .ok false
  | (n, _) :: rest =>
      if w.numUsers = n then
        match decodeUpdateUserPis w.updateUserProof.publicInputs with
        | .error _ =>
            .error (.updateUserPublicInputs "invalid update-account public inputs")
        | .ok _ => (slotWitness dummies w rest) >>= fun _ => .ok true
      else
        match dummyLookup n dummies with
        | none => .error (.invalidInput "dummy update-account proof missing for num_users")
        | some _ => slotWitness dummies w rest

def setWitness (updateAccountVds : List (Nat × VerifierCircuitData))
    (dummies : List (Nat × Proof)) (w : BlockStepWitness) : Result Unit := do
  let _ ← check (w.prevBlockChainProof ≠ none ∨ w.initialPublicState ≠ none)
    (.invalidInput "initial_public_state must be provided when previous block proof is absent")
  let matched ← slotWitness dummies w updateAccountVds
  let _ ← check (matched = true) (.missingUpdateUserVerifierData w.numUsers)
  .ok ()

theorem set_witness_first_block_needs_initial_state
    (updateAccountVds : List (Nat × VerifierCircuitData)) (dummies : List (Nat × Proof))
    (w : BlockStepWitness) (noPrev : w.prevBlockChainProof = none)
    (noInit : w.initialPublicState = none) :
    setWitness updateAccountVds dummies w = .error (.invalidInput
      "initial_public_state must be provided when previous block proof is absent") := by
  simp [setWitness, check, noPrev, noInit, Bind.bind, Except.bind]

theorem slot_witness_true_implies_supported {dummies : List (Nat × Proof)}
    {w : BlockStepWitness} :
    ∀ vds : List (Nat × VerifierCircuitData), slotWitness dummies w vds = .ok true →
      ∃ v : VerifierCircuitData, (w.numUsers, v) ∈ vds := by
  intro vds
  induction vds with
  | nil => intro h; exact absurd h (by simp [slotWitness])
  | cons head rest ih =>
    obtain ⟨n, v⟩ := head
    intro h
    by_cases hn : w.numUsers = n
    · exact ⟨v, by simp [hn]⟩
    · simp only [slotWitness, hn, if_neg, not_false_eq_true] at h
      split at h
      · exact absurd h (by simp)
      · obtain ⟨v', hv'⟩ := ih h
        exact ⟨v', List.mem_cons_of_mem _ hv'⟩

theorem set_witness_requires_supported_user_count
    {updateAccountVds : List (Nat × VerifierCircuitData)} {dummies : List (Nat × Proof)}
    {w : BlockStepWitness} (accepted : setWitness updateAccountVds dummies w = .ok ()) :
    ∃ v : VerifierCircuitData, (w.numUsers, v) ∈ updateAccountVds := by
  simp only [setWitness, bind_ok_iff, unit_bind_ok_iff, exists_unit, check_ok_iff,
    pure_ok_iff] at accepted
  obtain ⟨_, accepted⟩ := accepted
  obtain ⟨matched, hmatched, accepted⟩ := accepted
  obtain ⟨hTrue, _⟩ := accepted
  subst hTrue
  exact slot_witness_true_implies_supported updateAccountVds hmatched

/-- A repeated `num_users` is silently accepted by `prove`'s preflight, resolved by the LAST
    entry natively (`HashMap::collect`) but sets TWO one-hot flags in the witness, which the
    `assert_one(hot_sum)` gate rejects. The two statements below pin both halves. -/
theorem duplicate_user_counts_native_uses_last (numUsers : Nat)
    (v1 v2 : VerifierCircuitData) :
    lookupLast numUsers [(numUsers, v1), (numUsers, v2)] = some v2 := by
  simp [lookupLast]

theorem duplicate_user_counts_set_two_one_hot_flags (numUsers : Nat)
    (v1 v2 : VerifierCircuitData) :
    ((slotFlags numUsers [(numUsers, v1), (numUsers, v2)]).filter id).length = 2 := by
  simp [slotFlags]

structure BlockStepCircuitShape where
  blockChainCommon : Nat
  depositChainCommon : Nat
  channelRegChainCommon : Nat
  supportedUserCounts : List Nat
  deriving DecidableEq, Repr, Inhabited

/-- `BlockStepCircuit::prove`'s preflight, in source order. -/
def provePreflight (shape : BlockStepCircuitShape)
    (blockChainVd depositChainVd channelRegChainVd : VerifierCircuitData)
    (updateAccountVds : List (Nat × VerifierCircuitData)) : Result Unit := do
  let _ ← check (blockChainVd.common = shape.blockChainCommon)
    (.invalidInput "block chain verifier common data mismatch")
  let _ ← check (depositChainVd.common = shape.depositChainCommon)
    (.invalidInput "deposit chain verifier common data mismatch")
  let _ ← check (channelRegChainVd.common = shape.channelRegChainCommon)
    (.invalidInput "channel reg chain verifier common data mismatch")
  let _ ← check (updateAccountVds.length = shape.supportedUserCounts.length)
    (.invalidInput "update account verifier count mismatch")
  let _ ← check (updateAccountVds.map Prod.fst = shape.supportedUserCounts)
    (.invalidInput "update account verifier mismatch")
  .ok ()

theorem prove_preflight_pins_common_data_and_user_counts {shape : BlockStepCircuitShape}
    {blockChainVd depositChainVd channelRegChainVd : VerifierCircuitData}
    {updateAccountVds : List (Nat × VerifierCircuitData)}
    (accepted : provePreflight shape blockChainVd depositChainVd channelRegChainVd
      updateAccountVds = .ok ()) :
    blockChainVd.common = shape.blockChainCommon ∧
    depositChainVd.common = shape.depositChainCommon ∧
    channelRegChainVd.common = shape.channelRegChainCommon ∧
    updateAccountVds.map Prod.fst = shape.supportedUserCounts := by
  simp only [provePreflight, bind_ok_iff, unit_bind_ok_iff, exists_unit, check_ok_iff,
    pure_ok_iff] at accepted
  obtain ⟨h1, accepted⟩ := accepted
  obtain ⟨h2, accepted⟩ := accepted
  obtain ⟨h3, accepted⟩ := accepted
  obtain ⟨_, accepted⟩ := accepted
  obtain ⟨h5, _⟩ := accepted
  exact ⟨h1, h2, h3, h5⟩

/-- The preflight does NOT reject a repeated `num_users`: only the element-wise list of
    counts is compared, so `[n, n]` passes whenever the circuit was built from `[n, n]`. -/
theorem prove_preflight_admits_duplicate_user_counts (n : Nat)
    (blockChainVd depositChainVd channelRegChainVd v1 v2 : VerifierCircuitData) :
    provePreflight { blockChainCommon := blockChainVd.common
                     depositChainCommon := depositChainVd.common
                     channelRegChainCommon := channelRegChainVd.common
                     supportedUserCounts := [n, n] }
      blockChainVd depositChainVd channelRegChainVd [(n, v1), (n, v2)] = .ok () := by
  simp [provePreflight, check, Bind.bind, Except.bind]

/-! ## Arbitrary satisfying witnesses: `BlockStepTarget::new`

The gates below are the LOCAL semantics of the constraints the constructor emits, over a
free assignment of the wires. They are deliberately separate from the native path: a
`BlockStepGates` witness need not come from `to_public_inputs`.

`from_pis`/`from_slice` are pure re-slicings of a proof's public-input targets (their only
length check is a build-time assert, and they perform NO range checks), so the wires simply
carry the parsed structures. Proof acceptance, the Merkle gadget and the Poseidon
commitment remain opaque. -/

theorem decide_ne_eq_false_iff {α : Type} [DecidableEq α] (a b : α) :
    (decide (a ≠ b) = false) ↔ a = b := by
  by_cases h : a = b <;> simp [h]

theorem decide_ne_eq_true_iff {α : Type} [DecidableEq α] (a b : α) :
    (decide (a ≠ b) = true) ↔ a ≠ b := by
  by_cases h : a = b <;> simp [h]

def selectExt (c : Bool) (t f : ExtendedPublicState) : ExtendedPublicState := if c then t else f
def selectHash (c : Bool) (t f : Hash) : Hash := if c then t else f
def selectBytes32 (c : Bool) (t f : Bytes32) : Bytes32 := if c then t else f
def selectNat (c : Bool) (t f : Nat) : Nat := if c then t else f

/-- `builder.add_const(prev_block_number, ONE)` is field addition, not integer addition. -/
def fieldAdd1 (x : Nat) : Nat := (x + 1) % fieldOrder

structure BlockStepWires where
  hasPrevBlockProof : Bool
  hasDepositProof : Bool
  hasChannelRegProof : Bool
  oneHot : List Bool
  slotUpdateInputs : List UpdateUserPublicInputs
  slotProofs : List Proof
  initialPublicState : ExtendedPublicState
  prevBlockChainProof : Proof
  prevProofPis : BlockChainPublicInputs
  depositProof : Proof
  depositInputs : DepositChainPublicInputs
  channelRegProof : Proof
  channelRegInputs : ChannelRegChainPublicInputs
  selectedUpdate : UpdateUserPublicInputs
  merkleProof : MerkleProof
  prevPublicStateRootOut : Hash
  blockChainVd : VerifierKey
  nextBlockNumber : Nat
  newPis : BlockChainPublicInputs

def selectedInitialState (w : BlockStepWires) : ExtendedPublicState :=
  selectExt w.hasPrevBlockProof w.prevProofPis.initialExt w.initialPublicState

def selectedPrevState (w : BlockStepWires) : ExtendedPublicState :=
  selectExt w.hasPrevBlockProof w.prevProofPis.ext w.initialPublicState

def selectedDepositHashChain (w : BlockStepWires) : Bytes32 :=
  selectBytes32 w.hasDepositProof w.depositInputs.depositHashChain
    (selectedPrevState w).depositHashChain

def selectedDepositTreeRoot (w : BlockStepWires) : Hash :=
  selectHash w.hasDepositProof w.depositInputs.depositTreeRoot
    (selectedPrevState w).inner.depositTreeRoot

def selectedDepositCount (w : BlockStepWires) : Nat :=
  selectNat w.hasDepositProof w.depositInputs.depositCount (selectedPrevState w).depositCount

def selectedAccountTreeRoot (w : BlockStepWires) : Hash :=
  selectHash w.hasChannelRegProof w.channelRegInputs.channelTreeRoot
    w.selectedUpdate.newAccountTreeRoot

def selectedChannelRegHashChain (w : BlockStepWires) : Bytes32 :=
  selectBytes32 w.hasChannelRegProof w.channelRegInputs.channelRegHashChain
    (selectedPrevState w).channelRegHashChain

/-- The registered public inputs of the step circuit. -/
def registeredPis (w : BlockStepWires) : BlockChainPublicInputs :=
  { initialExt := selectedInitialState w
    ext := { inner := { blockNumber := w.nextBlockNumber
                        timestamp := w.selectedUpdate.blockTimestamp
                        accountTreeRoot := selectedAccountTreeRoot w
                        depositTreeRoot := selectedDepositTreeRoot w
                        prevPublicStateRoot := w.prevPublicStateRootOut }
             blockHashChain := w.selectedUpdate.newBlockHashChain
             depositHashChain := selectedDepositHashChain w
             depositCount := selectedDepositCount w
             channelRegHashChain := selectedChannelRegHashChain w
             bpSigChain := w.selectedUpdate.newBpSigChain }
    vd := w.blockChainVd }

structure BlockStepGates (env : StepEnv) (commit : UpdateUserPublicInputs → Hash)
    (blockChainVd depositChainVd channelRegChainVd : VerifierCircuitData)
    (updateVds : List VerifierCircuitData) (w : BlockStepWires) : Prop where
  slots_nonempty : 0 < w.oneHot.length
  slot_inputs_aligned : w.slotUpdateInputs.length = w.oneHot.length
  slot_proofs_aligned : w.slotProofs.length = w.oneHot.length
  slot_vds_aligned : updateVds.length = w.oneHot.length
  /-- `builder.assert_one(hot_sum)`. -/
  one_hot_sum : (w.oneHot.filter id).length = 1
  /-- `conditionally_verify_proof` on the previous chain proof. -/
  prev_proof_verified : w.hasPrevBlockProof = true → env.accepts blockChainVd w.prevBlockChainProof = true
  /-- `conditionally_connect_vd`: only when the previous proof is present. -/
  prev_vd_connected : w.hasPrevBlockProof = true → w.prevProofPis.vd = w.blockChainVd
  /-- `add_proof_target_and_conditionally_verify` on the selected update slot. -/
  slot_proof_verified : ∀ (i : Nat) (vd : VerifierCircuitData) (p : Proof),
    w.oneHot[i]? = some true → updateVds[i]? = some vd →
    w.slotProofs[i]? = some p → env.accepts vd p = true
  /-- `select_vec` of the per-slot Poseidon commitments, connected to the selected wires. -/
  selected_commitment : ∀ (i : Nat) (u : UpdateUserPublicInputs),
    w.oneHot[i]? = some true → w.slotUpdateInputs[i]? = some u →
    commit w.selectedUpdate = commit u
  prev_block_number_in_field : (selectedPrevState w).inner.blockNumber < fieldOrder
  next_block_number_add : w.nextBlockNumber = fieldAdd1 (selectedPrevState w).inner.blockNumber
  /-- `builder.range_check(next_block_number_value, 63)` -- on the NEXT value only. -/
  next_block_number_range : w.nextBlockNumber < 2 ^ blockNumberBits
  update_block_number : w.selectedUpdate.blockNumber = w.nextBlockNumber
  update_prev_account_root :
    w.selectedUpdate.prevAccountTreeRoot = (selectedPrevState w).inner.accountTreeRoot
  update_prev_block_hash_chain :
    w.selectedUpdate.prevBlockHashChain = (selectedPrevState w).blockHashChain
  update_prev_bp_sig_chain : w.selectedUpdate.prevBpSigChain = (selectedPrevState w).bpSigChain
  /-- `builder.connect(has_deposit_proof, deposit_hash_changed)`. -/
  deposit_flag_iff : w.hasDepositProof =
    decide ((selectedPrevState w).depositHashChain ≠ w.selectedUpdate.depositHashChain)
  deposit_proof_verified : w.hasDepositProof = true → env.accepts depositChainVd w.depositProof = true
  deposit_initial_chain : w.hasDepositProof = true →
    w.depositInputs.initialDepositHashChain = (selectedPrevState w).depositHashChain
  deposit_initial_tree_root : w.hasDepositProof = true →
    w.depositInputs.initialDepositTreeRoot = (selectedPrevState w).inner.depositTreeRoot
  deposit_initial_count : w.hasDepositProof = true →
    w.depositInputs.initialDepositCount = (selectedPrevState w).depositCount
  deposit_result_chain : w.hasDepositProof = true →
    w.depositInputs.depositHashChain = w.selectedUpdate.depositHashChain
  deposit_block_number : w.hasDepositProof = true →
    w.depositInputs.blockNumber = w.nextBlockNumber
  /-- R6: `conditional_assert_true(has_channel_reg_proof, account_root_eq)`. -/
  reg_excludes_user_update : w.hasChannelRegProof = true →
    w.selectedUpdate.prevAccountTreeRoot = w.selectedUpdate.newAccountTreeRoot
  reg_proof_verified : w.hasChannelRegProof = true →
    env.accepts channelRegChainVd w.channelRegProof = true
  reg_initial_chain : w.hasChannelRegProof = true →
    w.channelRegInputs.initialChannelRegHashChain = (selectedPrevState w).channelRegHashChain
  reg_initial_tree_root : w.hasChannelRegProof = true →
    w.channelRegInputs.initialChannelTreeRoot = (selectedPrevState w).inner.accountTreeRoot
  reg_block_number : w.hasChannelRegProof = true →
    w.channelRegInputs.blockNumber = w.nextBlockNumber
  /-- `builder.connect(has_channel_reg_proof, channel_reg_changed)`. -/
  reg_flag_iff : w.hasChannelRegProof =
    decide ((selectedPrevState w).channelRegHashChain ≠ selectedChannelRegHashChain w)
  /-- G6: the block-hash-committed registration chain equals the resulting one. -/
  reg_chain_in_block_hash : w.selectedUpdate.channelRegHashChain = selectedChannelRegHashChain w
  merkle_empty_leaf :
    env.merkleRoot w.merkleProof emptyPublicStateLeaf (selectedPrevState w).inner.blockNumber
      = (selectedPrevState w).inner.prevPublicStateRoot
  merkle_new_root : w.prevPublicStateRootOut =
    env.merkleRoot w.merkleProof (selectedPrevState w).inner (selectedPrevState w).inner.blockNumber
  registered : w.newPis = registeredPis w

/-! ### What the gates force -/

theorem gates_block_number_increments {env : StepEnv} {commit : UpdateUserPublicInputs → Hash}
    {bcVd dVd rVd : VerifierCircuitData} {uVds : List VerifierCircuitData}
    {w : BlockStepWires} (gates : BlockStepGates env commit bcVd dVd rVd uVds w)
    (prevInRange : (selectedPrevState w).inner.blockNumber < 2 ^ blockNumberBits) :
    w.newPis.ext.inner.blockNumber = (selectedPrevState w).inner.blockNumber + 1 ∧
    w.selectedUpdate.blockNumber = (selectedPrevState w).inner.blockNumber + 1 := by
  have hmod : fieldAdd1 (selectedPrevState w).inner.blockNumber
      = (selectedPrevState w).inner.blockNumber + 1 := by
    unfold fieldAdd1
    apply Nat.mod_eq_of_lt
    have h1 : (2 : Nat) ^ blockNumberBits < fieldOrder := by decide
    omega
  have hnext : w.nextBlockNumber = (selectedPrevState w).inner.blockNumber + 1 := by
    rw [gates.next_block_number_add, hmod]
  refine ⟨?_, ?_⟩
  · rw [gates.registered]; exact hnext
  · rw [gates.update_block_number]; exact hnext

/-- The 63-bit range check is applied to the NEXT block number only, so it does not by
    itself exclude a field wrap-around of the previous one: the model records this rather
    than assuming the previous state is well formed. -/
theorem next_block_number_range_check_allows_field_wrap :
    fieldAdd1 (fieldOrder - 1) = 0 ∧ (0 : Nat) < 2 ^ blockNumberBits := by
  constructor
  · unfold fieldAdd1
    have h : fieldOrder - 1 + 1 = fieldOrder := by unfold fieldOrder; omega
    rw [h, Nat.mod_self]
  · decide

theorem gates_fold_block_hash_chain {env : StepEnv} {commit : UpdateUserPublicInputs → Hash}
    {bcVd dVd rVd : VerifierCircuitData} {uVds : List VerifierCircuitData}
    {w : BlockStepWires} (gates : BlockStepGates env commit bcVd dVd rVd uVds w) :
    w.selectedUpdate.prevBlockHashChain = (selectedPrevState w).blockHashChain ∧
    w.newPis.ext.blockHashChain = w.selectedUpdate.newBlockHashChain := by
  exact ⟨gates.update_prev_block_hash_chain, by rw [gates.registered]; rfl⟩

theorem gates_thread_bp_sig_chain {env : StepEnv} {commit : UpdateUserPublicInputs → Hash}
    {bcVd dVd rVd : VerifierCircuitData} {uVds : List VerifierCircuitData}
    {w : BlockStepWires} (gates : BlockStepGates env commit bcVd dVd rVd uVds w) :
    w.selectedUpdate.prevBpSigChain = (selectedPrevState w).bpSigChain ∧
    w.newPis.ext.bpSigChain = w.selectedUpdate.newBpSigChain := by
  exact ⟨gates.update_prev_bp_sig_chain, by rw [gates.registered]; rfl⟩

theorem gates_no_deposit_proof_freezes_deposit_state {env : StepEnv}
    {commit : UpdateUserPublicInputs → Hash} {bcVd dVd rVd : VerifierCircuitData}
    {uVds : List VerifierCircuitData} {w : BlockStepWires}
    (gates : BlockStepGates env commit bcVd dVd rVd uVds w)
    (noDeposit : w.hasDepositProof = false) :
    (selectedPrevState w).depositHashChain = w.selectedUpdate.depositHashChain ∧
    w.newPis.ext.depositHashChain = (selectedPrevState w).depositHashChain ∧
    w.newPis.ext.inner.depositTreeRoot = (selectedPrevState w).inner.depositTreeRoot ∧
    w.newPis.ext.depositCount = (selectedPrevState w).depositCount := by
  have hflag := gates.deposit_flag_iff
  rw [noDeposit] at hflag
  have hsame : (selectedPrevState w).depositHashChain = w.selectedUpdate.depositHashChain :=
    (decide_ne_eq_false_iff _ _).mp hflag.symm
  refine ⟨hsame, ?_, ?_, ?_⟩ <;>
    rw [gates.registered] <;>
    simp [registeredPis, selectedDepositHashChain, selectedDepositTreeRoot,
      selectedDepositCount, selectBytes32, selectHash, selectNat, noDeposit]

theorem gates_deposit_proof_links_chain {env : StepEnv}
    {commit : UpdateUserPublicInputs → Hash} {bcVd dVd rVd : VerifierCircuitData}
    {uVds : List VerifierCircuitData} {w : BlockStepWires}
    (gates : BlockStepGates env commit bcVd dVd rVd uVds w)
    (hasDeposit : w.hasDepositProof = true) :
    env.accepts dVd w.depositProof = true ∧
    w.depositInputs.initialDepositHashChain = (selectedPrevState w).depositHashChain ∧
    w.depositInputs.initialDepositTreeRoot = (selectedPrevState w).inner.depositTreeRoot ∧
    w.depositInputs.initialDepositCount = (selectedPrevState w).depositCount ∧
    w.depositInputs.depositHashChain = w.selectedUpdate.depositHashChain ∧
    w.depositInputs.blockNumber = w.nextBlockNumber ∧
    w.newPis.ext.depositHashChain = w.depositInputs.depositHashChain ∧
    w.newPis.ext.inner.depositTreeRoot = w.depositInputs.depositTreeRoot ∧
    w.newPis.ext.depositCount = w.depositInputs.depositCount := by
  refine ⟨gates.deposit_proof_verified hasDeposit, gates.deposit_initial_chain hasDeposit,
    gates.deposit_initial_tree_root hasDeposit, gates.deposit_initial_count hasDeposit,
    gates.deposit_result_chain hasDeposit, gates.deposit_block_number hasDeposit, ?_, ?_, ?_⟩ <;>
    rw [gates.registered] <;>
    simp [registeredPis, selectedDepositHashChain, selectedDepositTreeRoot,
      selectedDepositCount, selectBytes32, selectHash, selectNat, hasDeposit]

theorem gates_registration_excludes_user_update {env : StepEnv}
    {commit : UpdateUserPublicInputs → Hash} {bcVd dVd rVd : VerifierCircuitData}
    {uVds : List VerifierCircuitData} {w : BlockStepWires}
    (gates : BlockStepGates env commit bcVd dVd rVd uVds w)
    (hasReg : w.hasChannelRegProof = true) :
    env.accepts rVd w.channelRegProof = true ∧
    w.selectedUpdate.prevAccountTreeRoot = w.selectedUpdate.newAccountTreeRoot ∧
    w.channelRegInputs.initialChannelTreeRoot = (selectedPrevState w).inner.accountTreeRoot ∧
    w.channelRegInputs.initialChannelRegHashChain = (selectedPrevState w).channelRegHashChain ∧
    w.channelRegInputs.blockNumber = w.nextBlockNumber ∧
    w.newPis.ext.inner.accountTreeRoot = w.channelRegInputs.channelTreeRoot ∧
    w.newPis.ext.channelRegHashChain = w.channelRegInputs.channelRegHashChain := by
  refine ⟨gates.reg_proof_verified hasReg, gates.reg_excludes_user_update hasReg,
    gates.reg_initial_tree_root hasReg, gates.reg_initial_chain hasReg,
    gates.reg_block_number hasReg, ?_, ?_⟩ <;>
    rw [gates.registered] <;>
    simp [registeredPis, selectedAccountTreeRoot, selectedChannelRegHashChain, selectHash,
      selectBytes32, hasReg]

theorem gates_no_registration_uses_update_root {env : StepEnv}
    {commit : UpdateUserPublicInputs → Hash} {bcVd dVd rVd : VerifierCircuitData}
    {uVds : List VerifierCircuitData} {w : BlockStepWires}
    (gates : BlockStepGates env commit bcVd dVd rVd uVds w)
    (noReg : w.hasChannelRegProof = false) :
    w.newPis.ext.inner.accountTreeRoot = w.selectedUpdate.newAccountTreeRoot ∧
    w.newPis.ext.channelRegHashChain = (selectedPrevState w).channelRegHashChain := by
  constructor <;> rw [gates.registered] <;>
    simp [registeredPis, selectedAccountTreeRoot, selectedChannelRegHashChain, selectHash,
      selectBytes32, noReg]

/-- G6 as the gates state it: the registration chain the block hash commits to (through the
    update proof) is exactly the one the step publishes. -/
theorem gates_registration_anchored_in_block_hash {env : StepEnv}
    {commit : UpdateUserPublicInputs → Hash} {bcVd dVd rVd : VerifierCircuitData}
    {uVds : List VerifierCircuitData} {w : BlockStepWires}
    (gates : BlockStepGates env commit bcVd dVd rVd uVds w) :
    w.newPis.ext.channelRegHashChain = w.selectedUpdate.channelRegHashChain := by
  rw [gates.registered, gates.reg_chain_in_block_hash]
  rfl

theorem gates_registration_flag_iff_chain_moves {env : StepEnv}
    {commit : UpdateUserPublicInputs → Hash} {bcVd dVd rVd : VerifierCircuitData}
    {uVds : List VerifierCircuitData} {w : BlockStepWires}
    (gates : BlockStepGates env commit bcVd dVd rVd uVds w) :
    (w.hasChannelRegProof = true) ↔
      w.newPis.ext.channelRegHashChain ≠ (selectedPrevState w).channelRegHashChain := by
  have hreg := gates.reg_flag_iff
  have hpis : w.newPis.ext.channelRegHashChain = selectedChannelRegHashChain w := by
    rw [gates.registered]; rfl
  rw [hpis]
  constructor
  · intro h
    rw [h] at hreg
    exact fun hEq => ((decide_ne_eq_true_iff _ _).mp hreg.symm) hEq.symm
  · intro h
    rw [hreg]
    exact (decide_ne_eq_true_iff _ _).mpr (fun hEq => h hEq.symm)

theorem selected_prev_state_key_irrelevant (w : BlockStepWires)
    (noPrev : w.hasPrevBlockProof = false) (k : VerifierKey)
    (pis : BlockChainPublicInputs) :
    selectedPrevState { w with blockChainVd := k, newPis := pis } = selectedPrevState w := by
  simp [selectedPrevState, selectExt, noPrev]

/-- On a first step the emitted initial state is the free `initial_public_state` witness and
    the emitted verifier key is a free witness too: replacing both by anything at all keeps
    every gate satisfied. -/
theorem gates_first_step_verifier_key_is_free {env : StepEnv}
    {commit : UpdateUserPublicInputs → Hash} {bcVd dVd rVd : VerifierCircuitData}
    {uVds : List VerifierCircuitData} {w : BlockStepWires}
    (gates : BlockStepGates env commit bcVd dVd rVd uVds w)
    (noPrev : w.hasPrevBlockProof = false) (k : VerifierKey) :
    BlockStepGates env commit bcVd dVd rVd uVds
      { w with blockChainVd := k, newPis := registeredPis { w with blockChainVd := k } } := by
  have hsel := selected_prev_state_key_irrelevant w noPrev k
    (registeredPis { w with blockChainVd := k })
  exact
    { slots_nonempty := gates.slots_nonempty
      slot_inputs_aligned := gates.slot_inputs_aligned
      slot_proofs_aligned := gates.slot_proofs_aligned
      slot_vds_aligned := gates.slot_vds_aligned
      one_hot_sum := gates.one_hot_sum
      prev_proof_verified := by intro h; simp [noPrev] at h
      prev_vd_connected := by intro h; simp [noPrev] at h
      slot_proof_verified := gates.slot_proof_verified
      selected_commitment := gates.selected_commitment
      prev_block_number_in_field := by rw [hsel]; exact gates.prev_block_number_in_field
      next_block_number_add := by rw [hsel]; exact gates.next_block_number_add
      next_block_number_range := gates.next_block_number_range
      update_block_number := gates.update_block_number
      update_prev_account_root := by rw [hsel]; exact gates.update_prev_account_root
      update_prev_block_hash_chain := by rw [hsel]; exact gates.update_prev_block_hash_chain
      update_prev_bp_sig_chain := by rw [hsel]; exact gates.update_prev_bp_sig_chain
      deposit_flag_iff := by rw [hsel]; exact gates.deposit_flag_iff
      deposit_proof_verified := gates.deposit_proof_verified
      deposit_initial_chain := by rw [hsel]; exact gates.deposit_initial_chain
      deposit_initial_tree_root := by rw [hsel]; exact gates.deposit_initial_tree_root
      deposit_initial_count := by rw [hsel]; exact gates.deposit_initial_count
      deposit_result_chain := gates.deposit_result_chain
      deposit_block_number := gates.deposit_block_number
      reg_excludes_user_update := gates.reg_excludes_user_update
      reg_proof_verified := gates.reg_proof_verified
      reg_initial_chain := by rw [hsel]; exact gates.reg_initial_chain
      reg_initial_tree_root := by rw [hsel]; exact gates.reg_initial_tree_root
      reg_block_number := gates.reg_block_number
      reg_flag_iff := by
        simp only [selectedChannelRegHashChain, hsel]
        exact gates.reg_flag_iff
      reg_chain_in_block_hash := by
        simp only [selectedChannelRegHashChain, hsel]
        exact gates.reg_chain_in_block_hash
      merkle_empty_leaf := by rw [hsel]; exact gates.merkle_empty_leaf
      merkle_new_root := by rw [hsel]; exact gates.merkle_new_root
      registered := rfl }

/-- The one-hot selection identifies the selected update inputs only up to a Poseidon
    commitment collision; the collision-freeness is a premise, never a theorem. -/
theorem gates_selected_update_is_slot_update {env : StepEnv}
    {commit : UpdateUserPublicInputs → Hash} {bcVd dVd rVd : VerifierCircuitData}
    {uVds : List VerifierCircuitData} {w : BlockStepWires} {i : Nat}
    {u : UpdateUserPublicInputs} (gates : BlockStepGates env commit bcVd dVd rVd uVds w)
    (flag : w.oneHot[i]? = some true) (slot : w.slotUpdateInputs[i]? = some u)
    (noCollision : commit w.selectedUpdate = commit u → w.selectedUpdate = u) :
    w.selectedUpdate = u :=
  noCollision (gates.selected_commitment i u flag slot)

/-- The timestamp is passed through from the selected update proof; no gate compares it
    with the previous block's. -/
theorem gates_timestamp_passthrough {env : StepEnv} {commit : UpdateUserPublicInputs → Hash}
    {bcVd dVd rVd : VerifierCircuitData} {uVds : List VerifierCircuitData}
    {w : BlockStepWires} (gates : BlockStepGates env commit bcVd dVd rVd uVds w) :
    w.newPis.ext.inner.timestamp = w.selectedUpdate.blockTimestamp := by
  rw [gates.registered]; rfl

/-! ## Worked examples

A concrete accepting native trace and a concrete satisfying gate assignment, so that none
of the statements above is vacuous. -/

def oneBytes32 : Bytes32 := ⟨List.replicate bytes32Len 1⟩

def exampleUpdate : UpdateUserPublicInputs :=
  { blockNumber := 1
    blockTimestamp := zeroU64
    prevBlockHashChain := zeroBytes32
    prevAccountTreeRoot := zeroHash
    newBlockHashChain := oneBytes32
    newAccountTreeRoot := zeroHash
    depositHashChain := zeroBytes32
    channelRegHashChain := zeroBytes32
    prevBpSigChain := zeroBytes32
    newBpSigChain := zeroBytes32 }

/-- The same block with a different declared timestamp: also accepted, because nothing
    constrains the timestamp. -/
def exampleUpdateOtherTimestamp : UpdateUserPublicInputs :=
  { exampleUpdate with blockTimestamp := ⟨[5, 7]⟩ }

def exampleInitialState : ExtendedPublicState :=
  { inner := { blockNumber := 0
               timestamp := zeroU64
               accountTreeRoot := zeroHash
               depositTreeRoot := zeroHash
               prevPublicStateRoot := zeroHash }
    blockHashChain := zeroBytes32
    depositHashChain := zeroBytes32
    depositCount := 0
    channelRegHashChain := zeroBytes32
    bpSigChain := zeroBytes32 }

def exampleVd : VerifierCircuitData := { common := 0, vdLen := 68, verifierOnly := ⟨7⟩ }

def exampleEnv : StepEnv :=
  { accepts := fun _ _ => true
    merkleRoot := fun _ _ _ => zeroHash
    vdEncode := fun k => List.replicate 68 k.id
    vdDecode := fun xs => .ok ⟨xs.headD 0⟩ }

def exampleWitness (u : UpdateUserPublicInputs) : BlockStepWitness :=
  { numUsers := 2
    initialPublicState := some exampleInitialState
    prevBlockChainProof := none
    depositHashChainProof := none
    channelRegHashChainProof := none
    updateUserProof := ⟨u.encode⟩
    publicStateMerkleProof := ⟨[]⟩ }

def exampleOutput (u : UpdateUserPublicInputs) : BlockChainPublicInputs :=
  { initialExt := exampleInitialState
    ext := { inner := { blockNumber := 1
                        timestamp := u.blockTimestamp
                        accountTreeRoot := zeroHash
                        depositTreeRoot := zeroHash
                        prevPublicStateRoot := zeroHash }
             blockHashChain := oneBytes32
             depositHashChain := zeroBytes32
             depositCount := 0
             channelRegHashChain := zeroBytes32
             bpSigChain := zeroBytes32 }
    vd := exampleVd.verifierOnly }

theorem example_update_well_formed : exampleUpdate.WellFormed := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;>
    simp [exampleUpdate, U64Val.WellFormed, Bytes32.WellFormed, Hash.WellFormed,
      zeroU64, zeroBytes32, zeroHash, oneBytes32, bytes32Len, poseidonHashOutLen, u64Len]

theorem example_update_other_timestamp_well_formed :
    exampleUpdateOtherTimestamp.WellFormed := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;>
    simp [exampleUpdateOtherTimestamp, exampleUpdate, U64Val.WellFormed, Bytes32.WellFormed,
      Hash.WellFormed, zeroU64, zeroBytes32, zeroHash, oneBytes32, bytes32Len,
      poseidonHashOutLen, u64Len]

theorem example_native_accepts_first_block :
    toPublicInputs exampleEnv exampleVd [(2, exampleVd)] exampleVd exampleVd
      (exampleWitness exampleUpdate) = .ok (exampleOutput exampleUpdate) := by
  simp only [toPublicInputs, exampleWitness, resolvePrev, liftVd, lookupLast, liftUpdate,
    decode_update_user_encode example_update_well_formed, check, bind_d_ok]
  rfl

theorem example_native_accepts_any_timestamp :
    toPublicInputs exampleEnv exampleVd [(2, exampleVd)] exampleVd exampleVd
      (exampleWitness exampleUpdateOtherTimestamp) = .ok (exampleOutput exampleUpdateOtherTimestamp) := by
  simp only [toPublicInputs, exampleWitness, resolvePrev, liftVd, lookupLast, liftUpdate,
    decode_update_user_encode example_update_other_timestamp_well_formed, check, bind_d_ok]
  rfl

/-- The two accepted traces differ only in the declared block timestamp, and the step
    publishes both: `to_public_inputs` never compares timestamps. -/
theorem example_timestamps_are_unconstrained :
    (exampleOutput exampleUpdate).ext.inner.timestamp ≠
      (exampleOutput exampleUpdateOtherTimestamp).ext.inner.timestamp := by
  simp only [exampleOutput, exampleUpdate, exampleUpdateOtherTimestamp, zeroU64, u64Len]
  decide

def exampleCommit : UpdateUserPublicInputs → Hash := fun _ => zeroHash

def exampleWiresBase : BlockStepWires :=
  { hasPrevBlockProof := false
    hasDepositProof := false
    hasChannelRegProof := false
    oneHot := [true]
    slotUpdateInputs := [exampleUpdate]
    slotProofs := [⟨exampleUpdate.encode⟩]
    initialPublicState := exampleInitialState
    prevBlockChainProof := ⟨[]⟩
    prevProofPis := default
    depositProof := ⟨[]⟩
    depositInputs := default
    channelRegProof := ⟨[]⟩
    channelRegInputs := default
    selectedUpdate := exampleUpdate
    merkleProof := ⟨[]⟩
    prevPublicStateRootOut := zeroHash
    blockChainVd := ⟨7⟩
    nextBlockNumber := 1
    newPis := default }

def exampleWires : BlockStepWires :=
  { exampleWiresBase with newPis := registeredPis exampleWiresBase }

theorem example_gates_satisfied :
    BlockStepGates exampleEnv exampleCommit exampleVd exampleVd exampleVd [exampleVd]
      exampleWires := by
  constructor
  all_goals first
    | rfl
    | decide
    | (intro h; exact absurd h (by decide))
    | (intro _ _ _ _ _ _; rfl)
    | (intro _ _ _ _; rfl)

/-! ## Circuit construction and verification (`BlockStepCircuit::new` / `verify`)

`new` asserts a non-empty verifier list (a panic, not an error), builds the target, and
registers `new_pis.to_vec(config)` -- and nothing else -- as the circuit's public inputs.
`verify` is a bare delegation to plonky2. -/

/-- `assert!(!update_account_vds.is_empty(), ...)` in `BlockStepTarget::new`. -/
def newTargetPrecondition (updateAccountVds : List (Nat × VerifierCircuitData)) : Prop :=
  updateAccountVds ≠ []

/-- The registered public-input vector: both extended states then the cyclic verifier key. -/
def stepRegisteredPis (env : StepEnv) (_vdLen : Nat) (pis : BlockChainPublicInputs) : List Nat :=
  pis.initialExt.encode ++ pis.ext.encode ++ env.vdEncode pis.vd

def stepRegisteredLen (vdLen : Nat) : Nat := blockChainPublicInputsLen + vdLen

theorem step_registered_len_pinned_at_cap_height_four : stepRegisteredLen 68 = 164 := by decide

theorem step_registered_pis_length {env : StepEnv} {vdLen : Nat}
    {pis : BlockChainPublicInputs} (codec : VdCodecSound env vdLen)
    (wfInit : pis.initialExt.WellFormed) (wfExt : pis.ext.WellFormed) :
    (stepRegisteredPis env vdLen pis).length = stepRegisteredLen vdLen := by
  simp only [stepRegisteredPis, List.length_append,
    extended_public_state_encode_length wfInit, extended_public_state_encode_length wfExt,
    codec.encode_length, stepRegisteredLen, blockChainPublicInputsLen]
  omega

/-- Round trip: a step proof's registered vector decodes back to the same public inputs, so
    the layout the parent step re-slices is the one this step registered. -/
theorem step_registered_pis_round_trip {env : StepEnv} {vdLen : Nat}
    {pis : BlockChainPublicInputs} (codec : VdCodecSound env vdLen)
    (wfInit : pis.initialExt.WellFormed) (wfExt : pis.ext.WellFormed) :
    decodeBlockChainPis env vdLen (stepRegisteredPis env vdLen pis) = .ok pis := by
  have hlen : (pis.initialExt.encode ++ (pis.ext.encode ++ env.vdEncode pis.vd)).length
      = blockChainPublicInputsLen + vdLen := by
    have h := step_registered_pis_length codec wfInit wfExt
    simpa [stepRegisteredPis, stepRegisteredLen, List.append_assoc] using h
  have htake : (env.vdEncode pis.vd).take vdLen = env.vdEncode pis.vd := by
    rw [← codec.encode_length pis.vd]
    simp
  simp only [decodeBlockChainPis, stepRegisteredPis, List.append_assoc]
  rw [if_neg (by simp [hlen])]
  rw [decode_extended_public_state_encode _ wfInit]
  simp only [bind_d_ok]
  rw [decode_extended_public_state_encode _ wfExt]
  simp only [bind_d_ok]
  rw [htake, codec.decode_encode pis.vd]
  simp only [bind_d_ok]

/-- `BlockStepCircuit::verify` performs no local check of its own: it is exactly the
    opaque plonky2 verifier applied to this circuit's key. -/
def verifyStepProof (env : StepEnv) (stepVd : VerifierCircuitData) (proof : Proof) :
    Result Unit :=
  check (env.accepts stepVd proof = true) (.invalidProof "step proof rejected")

theorem verify_step_proof_ok_iff (env : StepEnv) (stepVd : VerifierCircuitData)
    (proof : Proof) :
    verifyStepProof env stepVd proof = .ok () ↔ env.accepts stepVd proof = true := by
  simp [verifyStepProof, check_ok_iff]

end Zkp.Implementation.BlockStep
