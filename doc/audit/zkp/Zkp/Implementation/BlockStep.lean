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

end Zkp.Implementation.BlockStep
