import Std
import Zkp.Implementation.BalancePublicInputs
import Zkp.Implementation.RollupValue

/-!
# Validity statement: extended public state, block-chain fold, validity public inputs

Handwritten source-oriented semantic model of

* `src/circuits/validity/block_hash_chain/validity_circuit.rs` (453 lines),
* `src/circuits/validity/block_hash_chain/block_hash_chain_circuit.rs` (124 lines),
* `src/circuits/validity/block_hash_chain/block_chain_pis.rs` (204 lines),
* `src/circuits/validity/block_hash_chain/ext_public_state.rs` (324 lines).

This is NOT a refinement proof of the Rust sources, of the plonky2 circuit compiler, of the
recursive verifier gadgets, or of the Solidity consumer. It is a Lean model of the *word layout*,
the *order of checks* and the *shape of the constraints* those four files express, plus
kernel-checked theorems about that model.

## What is modeled

`ExtendedPublicState` is the 48-`u64`-word rollup state the block fold carries: the inner
`PublicState` (block number, timestamp, channel/account tree root, deposit tree root, previous
public-state root — reused verbatim from `Zkp.Implementation.BalancePublicInputs`, which already
models that 15-word encoding), then the block hash chain, the deposit hash chain, the deposit
count, the on-chain channel-registration hash chain and the block-producer signature-list
accumulator `bp_sig_chain`. `BlockChainPIs` is the `2 * 48 + vd_vec_len(config)` public-input
vector of the cyclic block-hash-chain wrapper. `ValidityPIs` is the 41-`u32`-word keccak preimage
the validity circuit hashes down to the eight words it registers as its own public inputs.

The bridge to the consumer is explicit: `ValidityPIs.toRollup` maps the circuit's limb-wise
public inputs onto `Zkp.Implementation.RollupValue.ValidityPIs`, and
`circuit_pi_layout_matches_solidity_preimage` DERIVES that the circuit's 164-byte keccak preimage
is literally `RollupValue.hashPreimage (.validityPis ...)`, the preimage `IntmaxRollup.finalize`
compares against. `finalize_consumes_initial_final_chain_and_commitment` then reads off, from
`RollupValue.fullVerify`, which of those words the contract actually binds.

## What is NOT modeled and is left as a named premise

* `blockChainVerifies` / `aggListVerifies` — recursive plonky2 proof verification is an opaque
  predicate. No proof soundness is claimed anywhere.
* `poseidon` / `keccak` — hash callbacks. No collision resistance and no injectivity is claimed;
  every statement that needs "equal digests ⇒ equal states" takes the equality of the concrete
  compared pair as a hypothesis, or uses `RollupValue.HashEncodingAgrees` as an explicit premise.
* The verifier data of a cyclic proof is modeled as an opaque word list of length
  `vdVecLen capCount`; its Merkle-cap/circuit-digest structure and `check_cyclic_proof_verifier_data`
  are boundaries.
* The N-of-N signature semantics behind `bp_sig_chain` (that a folded entry means "all registered
  members signed") lives in `update_channel_tree` / `falcon_sig`, not here. This model only shows
  that a non-zero final chain forces the conditional list verification and the commitment equality.
* The `2^16` validity degree and `2^14` aggregate-list wrapper degree are pinned by a `#[cfg(test)]`
  assertion in the source; they are recorded here as constants but nothing derives them.
* Native-witness generation, field arithmetic, gate lowering and Goldilocks canonicality.
-/

namespace Zkp.Implementation.ValidityChain

/-! ## Pinned constants -/

/-- One `u32` limb. -/
def wordBase : Nat := 4294967296

/-- `U63_MAX_VALUE + 1`: the block-number / deposit-count range. -/
def blockLimit : Nat := 9223372036854775808

/-- `BYTES32_LEN`. -/
def bytes32Len : Nat := 8

/-- `ADDRESS_LEN`. -/
def addressLen : Nat := 5

/-- `PUBLIC_STATE_U64_LEN = 1 + U64_LEN + 3 * POSEIDON_HASH_OUT_LEN`. -/
def publicStateU64Len : Nat := 15

/-- `EXTENDED_PUBLIC_STATE_U64_LEN = PUBLIC_STATE_U64_LEN + 4 * BYTES32_LEN + 1`. -/
def extPublicStateU64Len : Nat := 48

/-- `BLOCK_CHAIN_PUBLIC_INPUTS_LEN = 2 * EXTENDED_PUBLIC_STATE_U64_LEN`. -/
def blockChainPublicInputsLen : Nat := 96

/-- `vd_vec_len(config) = 4 + 4 * config.fri_config.num_cap_elements()`. -/
def vdVecLen (capCount : Nat) : Nat := 4 + 4 * capCount

/-- Number of `u32` limbs in `ValidityPublicInputs::to_u32_vec`. -/
def validityPiWordCount : Nat := 41

/-- Byte width of the keccak preimage those limbs serialize to. -/
def validityPreimageWidth : Nat := 164

/-- `ValidityCircuit` degree pinned by `tests::test_validity_circuit` (Phase 0 gate). -/
def validityDegreeBits : Nat := 16

/-- `AggListCircuit` cyclic wrapper degree pinned by the same test. -/
def aggListWrapperDegreeBits : Nat := 14

theorem word_base_pinned : wordBase = 2 ^ 32 := by decide

theorem block_limit_pinned : blockLimit = 2 ^ 63 := by decide

theorem ext_public_state_len_pinned :
    extPublicStateU64Len = publicStateU64Len + 4 * bytes32Len + 1 := by decide

theorem block_chain_public_inputs_len_pinned :
    blockChainPublicInputsLen = 2 * extPublicStateU64Len := by decide

theorem public_state_len_matches_balance_model :
    publicStateU64Len = BalancePublicInputs.publicStateLength := by decide

theorem vd_vec_len_matches_balance_model (capCount : Nat) :
    vdVecLen capCount = BalancePublicInputs.verifierLength capCount := by
  simp [vdVecLen, BalancePublicInputs.verifierLength]

theorem validity_degree_bits_pinned : validityDegreeBits = 16 := by decide

theorem agg_list_wrapper_degree_bits_pinned : aggListWrapperDegreeBits = 14 := by decide

/-! ## Reused word-level encodings

`Bytes32` is eight `u32` limbs, most significant first; `Root` is a four-`u64` Poseidon output;
`PublicState` is the 15-word inner state. All three already have a source-oriented model in
`Zkp.Implementation.BalancePublicInputs`, which models the same Rust encodings. -/

abbrev Root := BalancePublicInputs.Root
abbrev Bytes32 := BalancePublicInputs.Bytes8
abbrev PublicState := BalancePublicInputs.PublicState

/-- `Address` / `AddressTarget`: five `u32` limbs, most significant first. -/
structure Addr where
  a : Nat
  b : Nat
  c : Nat
  d : Nat
  e : Nat
  deriving DecidableEq, Repr

def Addr.words (x : Addr) : List Nat := [x.a, x.b, x.c, x.d, x.e]

def Addr.zero : Addr := ⟨0, 0, 0, 0, 0⟩

/-- Big-endian recomposition of `u32` limbs into the single integer the Solidity side names. -/
def beValue (ws : List Nat) : Nat := ws.foldl (fun acc w => acc * wordBase + w) 0

/-- Every limb of a word list is a canonical `u32`. -/
def LimbsCanonical (ws : List Nat) : Prop := ∀ x ∈ ws, x < wordBase

/-! ## `ext_public_state.rs`: the extended public state -/

structure ExtendedPublicState where
  inner : PublicState
  blockHashChain : Bytes32
  depositHashChain : Bytes32
  depositCount : Nat
  channelRegHashChain : Bytes32
  bpSigChain : Bytes32
  deriving DecidableEq, Repr

/-- `ExtendedPublicState::to_u64_vec` / `ExtendedPublicStateTarget::to_vec`: the same order in
both the native and the in-circuit path. -/
def ExtendedPublicState.words (s : ExtendedPublicState) : List Nat :=
  s.inner.words ++ s.blockHashChain.words ++ s.depositHashChain.words ++ [s.depositCount] ++
    s.channelRegHashChain.words ++ s.bpSigChain.words

/-- The cursor arithmetic shared by `from_u64_slice` and `ExtendedPublicStateTarget::from_slice`. -/
def ExtendedPublicState.read (xs : List Nat) : ExtendedPublicState :=
  { inner := BalancePublicInputs.PublicState.read xs
    blockHashChain := BalancePublicInputs.Bytes8.read xs 15
    depositHashChain := BalancePublicInputs.Bytes8.read xs 23
    depositCount := xs.getD 31 0
    channelRegHashChain := BalancePublicInputs.Bytes8.read xs 32
    bpSigChain := BalancePublicInputs.Bytes8.read xs 40 }

inductive Fault where
  | invalidLength (expected actual : Nat)
  | publicState (field : String)
  | bytes32 (field : String)
  | depositCount
  | parse (field : String)
  | boundsPanic
  | commonDataMismatch
  | buildFailed
  | cyclicVerifierData
  | proofVerification
  | proveFailed
  deriving DecidableEq, Repr

abbrev Result (α : Type) := Except Fault α

def canonicalLimbs (ws : List Nat) : Bool := ws.all (fun x => decide (x < wordBase))

/-- `ExtendedPublicState::from_u64_slice`, in the source's check order: exact length, then the
inner `PublicState` (u63 block number, then the two `u32` timestamp limbs, then three
length-only Poseidon roots), then the two hash chains, then the u63 deposit count, then the
registration chain and the signature-list accumulator. -/
def ExtendedPublicState.fromU64Slice (xs : List Nat) : Result ExtendedPublicState :=
  if xs.length ≠ extPublicStateU64Len then
    .error (.invalidLength extPublicStateU64Len xs.length)
  else
    let s := ExtendedPublicState.read xs
    if s.inner.blockNumber ≥ blockLimit then .error (.publicState "block_number")
    else if s.inner.timestampHi ≥ wordBase ∨ s.inner.timestampLo ≥ wordBase then
      .error (.publicState "timestamp")
    else if ¬ canonicalLimbs s.blockHashChain.words then .error (.bytes32 "block_hash_chain")
    else if ¬ canonicalLimbs s.depositHashChain.words then .error (.bytes32 "deposit_hash_chain")
    else if s.depositCount ≥ blockLimit then .error .depositCount
    else if ¬ canonicalLimbs s.channelRegHashChain.words then
      .error (.bytes32 "channel_reg_hash_chain")
    else if ¬ canonicalLimbs s.bpSigChain.words then .error (.bytes32 "bp_sig_chain")
    else .ok s

/-- `ExtendedPublicStateTarget::from_slice`: an exact-length ASSERTION (a panic, not an error)
and a pure split. No range check happens on this path; limb canonicality comes from the
`is_checked` allocation inside the circuit that produced those targets. -/
def ExtendedPublicState.fromSliceTarget (xs : List Nat) : Result ExtendedPublicState :=
  if xs.length ≠ extPublicStateU64Len then .error .boundsPanic
  else .ok (ExtendedPublicState.read xs)

/-- `ExtendedPublicState::commitment` / `ExtendedPublicStateTarget::commitment`: an opaque
Poseidon callback over exactly the 48 encoded words. -/
def ExtendedPublicState.commitment (poseidon : List Nat → Bytes32) (s : ExtendedPublicState) :
    Bytes32 := poseidon s.words

/-- `ExtendedPublicStateTarget::connect`: field-wise equality assertions. -/
def ExtendedPublicState.Connect (a b : ExtendedPublicState) : Prop :=
  a.inner = b.inner ∧ a.blockHashChain = b.blockHashChain ∧
    a.depositHashChain = b.depositHashChain ∧ a.depositCount = b.depositCount ∧
    a.channelRegHashChain = b.channelRegHashChain ∧ a.bpSigChain = b.bpSigChain

/-- `ExtendedPublicStateTarget::select`. -/
def ExtendedPublicState.select (cond : Bool) (whenTrue whenFalse : ExtendedPublicState) :
    ExtendedPublicState :=
  if cond then whenTrue else whenFalse

/-! ## `block_chain_pis.rs`: the cyclic wrapper's public inputs -/

/-- The re-exported verifier data is kept as an opaque word list of length `vdVecLen capCount`;
its Merkle-cap / circuit-digest structure is a plonky2 boundary. -/
structure BlockChainPIs where
  initial : ExtendedPublicState
  final : ExtendedPublicState
  vdWords : List Nat
  deriving DecidableEq, Repr

def blockChainPisLen (capCount : Nat) : Nat := blockChainPublicInputsLen + vdVecLen capCount

/-- `BlockChainPublicInputs::to_u64_vec` / `BlockChainPublicInputsTarget::to_vec`. -/
def BlockChainPIs.words (p : BlockChainPIs) : List Nat :=
  p.initial.words ++ p.final.words ++ p.vdWords

/-- `BlockChainPublicInputs::from_u64_slice`: exact length, then the two range-checked extended
states, then the verifier data. -/
def BlockChainPIs.fromU64Slice (capCount : Nat) (xs : List Nat) : Result BlockChainPIs :=
  if xs.length ≠ blockChainPisLen capCount then
    .error (.invalidLength (blockChainPisLen capCount) xs.length)
  else
    match ExtendedPublicState.fromU64Slice (xs.take extPublicStateU64Len) with
    | .error _ => .error (.parse "initial_public_state")
    | .ok initial =>
      match ExtendedPublicState.fromU64Slice
              ((xs.drop extPublicStateU64Len).take extPublicStateU64Len) with
      | .error _ => .error (.parse "public_state")
      | .ok final =>
        .ok { initial := initial
              final := final
              vdWords := (xs.drop blockChainPublicInputsLen).take (vdVecLen capCount) }

/-- `BlockChainPublicInputsTarget::from_pis`: a `>=` length ASSERTION and a pure prefix split.
Trailing public inputs beyond the prefix are ignored, and nothing is range-checked here. -/
def BlockChainPIs.fromPisTarget (capCount : Nat) (xs : List Nat) : Result BlockChainPIs :=
  if xs.length < blockChainPisLen capCount then .error .boundsPanic
  else
    .ok { initial := ExtendedPublicState.read xs
          final := ExtendedPublicState.read (xs.drop extPublicStateU64Len)
          vdWords := (xs.drop blockChainPublicInputsLen).take (vdVecLen capCount) }

/-! ## `validity_circuit.rs`: the validity public inputs -/

/-- `U63::to_u32_vec = [high, low]`. -/
def blockNumberWords (n : Nat) : List Nat := [n / wordBase, n % wordBase]

structure ValidityPIs where
  initialBlockNumber : Nat
  initialBlockChain : Bytes32
  initialExtCommitment : Bytes32
  finalBlockNumber : Nat
  finalBlockChain : Bytes32
  finalExtCommitment : Bytes32
  prover : Addr
  deriving DecidableEq, Repr

/-- `ValidityPublicInputs::to_u32_vec` and `ValidityPublicInputsTarget::to_vec` (same order). -/
def ValidityPIs.u32Words (p : ValidityPIs) : List Nat :=
  blockNumberWords p.initialBlockNumber ++ p.initialBlockChain.words ++
    p.initialExtCommitment.words ++ blockNumberWords p.finalBlockNumber ++
    p.finalBlockChain.words ++ p.finalExtCommitment.words ++ p.prover.words

/-- `solidity_keccak256` serializes every `u32` as four big-endian bytes; this is the keccak
preimage the native `hash()` and the in-circuit `builder.keccak256` both absorb. -/
def ValidityPIs.preimage (p : ValidityPIs) : RollupValue.Bytes :=
  p.u32Words.bind (RollupValue.wordBytes 4)

/-- `ValidityPublicInputs::hash` / `ValidityPublicInputsTarget::hash` with an opaque keccak. -/
def ValidityPIs.hash (keccak : RollupValue.Bytes → Bytes32) (p : ValidityPIs) : Bytes32 :=
  keccak p.preimage

/-- `ValidityPublicInputs::from_states`. -/
def ValidityPIs.fromStates (poseidon : List Nat → Bytes32) (initial final : ExtendedPublicState)
    (prover : Addr) : ValidityPIs :=
  { initialBlockNumber := initial.inner.blockNumber
    initialBlockChain := initial.blockHashChain
    initialExtCommitment := ExtendedPublicState.commitment poseidon initial
    finalBlockNumber := final.inner.blockNumber
    finalBlockChain := final.blockHashChain
    finalExtCommitment := ExtendedPublicState.commitment poseidon final
    prover := prover }

/-- The same seven fields, recomposed into the integers `IntmaxRollup` names. -/
def ValidityPIs.toRollup (p : ValidityPIs) : RollupValue.ValidityPIs :=
  { initialBlock := p.initialBlockNumber
    initialChain := beValue p.initialBlockChain.words
    initialRoot := beValue p.initialExtCommitment.words
    finalBlock := p.finalBlockNumber
    finalChain := beValue p.finalBlockChain.words
    finalRoot := beValue p.finalExtCommitment.words
    prover := beValue p.prover.words }

/-- Range facts the native `U63` / `U32LimbTrait` constructors establish for a well-formed
witness. They are hypotheses, never assumptions about an arbitrary prover's wires. -/
structure LimbBounds (p : ValidityPIs) : Prop where
  initialBlock : p.initialBlockNumber < blockLimit
  finalBlock : p.finalBlockNumber < blockLimit
  initialChain : LimbsCanonical p.initialBlockChain.words
  initialCommitment : LimbsCanonical p.initialExtCommitment.words
  finalChain : LimbsCanonical p.finalBlockChain.words
  finalCommitment : LimbsCanonical p.finalExtCommitment.words
  prover : LimbsCanonical p.prover.words

/-! ## Byte-layout lemmas

`RollupValue.wordBytes` is defined over `List.range`; Lean 4.10's `Std` has no `range`
lemmas, so the two facts we need are proved from the definition of `List.range.loop`. -/

theorem range_loop_eq (n : Nat) (ns : List Nat) :
    List.range.loop n ns = List.range n ++ ns := by
  induction n generalizing ns with
  | zero => simp [List.range, List.range.loop]
  | succ k ih =>
      show List.range.loop k (k :: ns) = List.range (k + 1) ++ ns
      rw [ih, show List.range (k + 1) = List.range.loop k [k] from rfl, ih]
      simp

theorem range_concat (n : Nat) : List.range (n + 1) = List.range n ++ [n] := by
  show List.range.loop n [n] = _
  rw [range_loop_eq]

theorem mem_range_lt {i w : Nat} (h : i ∈ List.range w) : i < w := by
  induction w with
  | zero => simp [List.range, List.range.loop] at h
  | succ k ih =>
      rw [range_concat] at h
      rcases List.mem_append.mp h with hk | hk
      · exact Nat.lt_succ_of_lt (ih hk)
      · simp at hk; omega

theorem range_add_four (w : Nat) :
    List.range (w + 4) = List.range w ++ [w, w + 1, w + 2, w + 3] := by
  rw [show w + 4 = (w + 3) + 1 from rfl, range_concat, show w + 3 = (w + 2) + 1 from rfl,
    range_concat, show w + 2 = (w + 1) + 1 from rfl, range_concat, range_concat]
  simp

/-- Appending one more `u32` limb to a big-endian byte string widens it by exactly four bytes. -/
theorem word_bytes_snoc (w v l : Nat) (hl : l < wordBase) :
    RollupValue.wordBytes (w + 4) (v * wordBase + l)
      = RollupValue.wordBytes w v ++ RollupValue.wordBytes 4 l := by
  simp only [wordBase] at hl ⊢
  have hpow : ∀ k : Nat, (256 : Nat) ^ (k + 4) = 4294967296 * 256 ^ k := by
    intro k
    rw [Nat.pow_add, show (256 : Nat) ^ 4 = 4294967296 from rfl]
    exact Nat.mul_comm _ _
  have hhead :
      List.map (fun i => UInt8.ofNat ((v * 4294967296 + l) / 256 ^ (w + 4 - 1 - i) % 256))
          (List.range w)
        = List.map (fun i => UInt8.ofNat (v / 256 ^ (w - 1 - i) % 256)) (List.range w) := by
    apply List.map_congr_left
    intro i hi
    have hiw : i < w := mem_range_lt hi
    have hk : w + 4 - 1 - i = (w - 1 - i) + 4 := by omega
    have hd : (v * 4294967296 + l) / 4294967296 = v := by omega
    rw [hk, hpow, ← Nat.div_div_eq_div_mul, hd]
  have e0 : w + 4 - 1 - w = 3 := by omega
  have e1 : w + 4 - 1 - (w + 1) = 2 := by omega
  have e2 : w + 4 - 1 - (w + 2) = 1 := by omega
  have e3 : w + 4 - 1 - (w + 3) = 0 := by omega
  simp only [RollupValue.wordBytes, range_add_four, List.map_append, hhead, List.map_cons,
    List.map_nil, List.range_zero, List.nil_append, e0, e1, e2, e3]
  refine congrArg _ ?_
  have k0 : (v * 4294967296 + l) / 256 ^ 3 % 256 = l / 256 ^ 3 % 256 := by
    rw [show (256 : Nat) ^ 3 = 16777216 from rfl]; omega
  have k1 : (v * 4294967296 + l) / 256 ^ 2 % 256 = l / 256 ^ 2 % 256 := by
    rw [show (256 : Nat) ^ 2 = 65536 from rfl]; omega
  have k2 : (v * 4294967296 + l) / 256 ^ 1 % 256 = l / 256 ^ 1 % 256 := by
    rw [show (256 : Nat) ^ 1 = 256 from rfl]; omega
  have k3 : (v * 4294967296 + l) / 256 ^ 0 % 256 = l / 256 ^ 0 % 256 := by
    rw [show (256 : Nat) ^ 0 = 1 from rfl]; omega
  rw [k0, k1, k2, k3]

theorem word_bytes_append_bind (ws : List Nat) (h : LimbsCanonical ws) :
    ∀ w acc : Nat, RollupValue.wordBytes w acc ++ ws.bind (RollupValue.wordBytes 4)
      = RollupValue.wordBytes (w + 4 * ws.length) (ws.foldl (fun a x => a * wordBase + x) acc) := by
  induction ws with
  | nil => intro w acc; simp
  | cons x xs ih =>
      intro w acc
      have hx : x < wordBase := h x (List.mem_cons_self x xs)
      have hxs : LimbsCanonical xs := fun y hy => h y (List.mem_cons_of_mem x hy)
      have step := ih hxs (w + 4) (acc * wordBase + x)
      have hlen : w + 4 * (x :: xs).length = w + 4 + 4 * xs.length := by
        simp [List.length_cons]; omega
      rw [List.bind_cons, ← List.append_assoc, ← word_bytes_snoc w acc x hx, step, hlen]
      simp [List.foldl_cons]

/-- A canonical `u32` limb list serializes to exactly the big-endian byte string of its value. -/
theorem bind_word_bytes (ws : List Nat) (h : LimbsCanonical ws) :
    ws.bind (RollupValue.wordBytes 4) = RollupValue.wordBytes (4 * ws.length) (beValue ws) := by
  have := word_bytes_append_bind ws h 0 0
  simpa [RollupValue.wordBytes, beValue] using this

theorem length_range (n : Nat) : (List.range n).length = n := by
  induction n with
  | zero => rfl
  | succ k ih => rw [range_concat, List.length_append, ih]; rfl

theorem word_bytes_length (w v : Nat) : (RollupValue.wordBytes w v).length = w := by
  simp [RollupValue.wordBytes, length_range]

theorem bind_word_bytes_length (ws : List Nat) :
    (ws.bind (RollupValue.wordBytes 4)).length = 4 * ws.length := by
  induction ws with
  | nil => simp
  | cons x xs ih =>
      rw [List.bind_cons, List.length_append, word_bytes_length, ih, List.length_cons]
      omega

/-! ## Widths and the layout bridge -/

theorem ext_public_state_word_count (s : ExtendedPublicState) :
    s.words.length = extPublicStateU64Len := by
  simp [ExtendedPublicState.words, BalancePublicInputs.PublicState.words,
    BalancePublicInputs.Root.words, BalancePublicInputs.Bytes8.words, extPublicStateU64Len]

theorem block_chain_words_count (p : BlockChainPIs) :
    p.words.length = blockChainPublicInputsLen + p.vdWords.length := by
  simp [BlockChainPIs.words, ext_public_state_word_count, extPublicStateU64Len,
    blockChainPublicInputsLen]
  omega

theorem validity_pi_word_count (p : ValidityPIs) :
    p.u32Words.length = validityPiWordCount := by
  simp [ValidityPIs.u32Words, blockNumberWords, BalancePublicInputs.Bytes8.words, Addr.words,
    validityPiWordCount]

theorem validity_preimage_width (p : ValidityPIs) :
    p.preimage.length = validityPreimageWidth := by
  rw [ValidityPIs.preimage, bind_word_bytes_length, validity_pi_word_count]
  decide

/-- The circuit's own keccak preimage is byte-for-byte the preimage the Solidity model hashes
for `finalize`: same field order, same widths (8/32/32/8/32/32/20), same big-endian packing. -/
theorem circuit_pi_layout_matches_solidity_preimage (p : ValidityPIs) (b : LimbBounds p) :
    p.preimage = RollupValue.hashPreimage (.validityPis p.toRollup) := by
  have hblock : ∀ n : Nat, n < blockLimit →
      (blockNumberWords n).bind (RollupValue.wordBytes 4) = RollupValue.wordBytes 8 n := by
    intro n hn
    have hc : LimbsCanonical (blockNumberWords n) := by
      intro x hx
      simp [blockNumberWords] at hx
      rcases hx with h | h <;> subst h <;> simp [wordBase, blockLimit] at hn ⊢ <;> omega
    rw [bind_word_bytes _ hc]
    have hlen : 4 * (blockNumberWords n).length = 8 := by simp [blockNumberWords]
    rw [hlen]
    congr 1
    simp [beValue, blockNumberWords, wordBase]
    omega
  have hb32 : ∀ x : Bytes32, LimbsCanonical x.words →
      x.words.bind (RollupValue.wordBytes 4) = RollupValue.wordBytes 32 (beValue x.words) := by
    intro x hx
    rw [bind_word_bytes _ hx, show 4 * x.words.length = 32 from rfl]
  have haddr : ∀ x : Addr, LimbsCanonical x.words →
      x.words.bind (RollupValue.wordBytes 4) = RollupValue.wordBytes 20 (beValue x.words) := by
    intro x hx
    rw [bind_word_bytes _ hx, show 4 * x.words.length = 20 from rfl]
  simp only [ValidityPIs.preimage, ValidityPIs.u32Words, List.append_bind,
    hblock _ b.initialBlock, hblock _ b.finalBlock, hb32 _ b.initialChain,
    hb32 _ b.initialCommitment, hb32 _ b.finalChain, hb32 _ b.finalCommitment,
    haddr _ b.prover, RollupValue.hashPreimage, ValidityPIs.toRollup]

theorem solidity_preimage_width (p : ValidityPIs) :
    (RollupValue.hashPreimage (.validityPis p.toRollup)).length = validityPreimageWidth :=
  RollupValue.validity_preimage_has_exact_width _

/-! ## What `IntmaxRollup.finalize` binds -/

/-- Read off `RollupValue.fullVerify`: an accepted validity proof pins the initial extended
commitment to the contract's finalized root, the final commitment to the submitted root, both
block-hash-chain values to the contract's recorded chain at the respective heights, and forbids
finalized-height regression. Nothing here claims the proof is sound. -/
theorem finalize_consumes_initial_final_chain_and_commitment
    (e : RollupValue.Environment) (s : RollupValue.State) (root : RollupValue.Hash)
    (p : ValidityPIs) (proof : RollupValue.Bytes)
    (h : RollupValue.fullVerify e s root p.toRollup proof = .ok true) :
    s.chain.finalizedBlock ≤ p.finalBlockNumber ∧
      p.toRollup.initialRoot = s.chain.finalizedRoot ∧
      p.toRollup.initialChain = s.chain.blockHashAt p.initialBlockNumber ∧
      p.toRollup.finalChain = s.chain.blockHashAt p.finalBlockNumber ∧
      p.toRollup.finalRoot = root := by
  simp only [RollupValue.fullVerify, RollupValue.require] at h
  split at h
  · rename_i h1
    split at h
    · rename_i h2
      split at h
      · rename_i h3
        split at h
        · rename_i h4
          split at h
          · rename_i h5
            simp at h1 h2 h3 h4 h5
            exact ⟨h1, h2, h3, h4, h5⟩
          · simp at h
        · simp at h
      · simp at h
    · simp at h
  · simp at h

/-- The eight registered public-input words are exactly what the contract's `mlePublicInputsMatch`
compares against, PROVIDED the environment's hash is keccak over `hashPreimage`
(`RollupValue.HashEncodingAgrees`) and the circuit's keccak agrees with it on this preimage.
This is the one remaining gap between the circuit's public inputs and `finalize`; it is a named
premise, not a derived fact. -/
theorem registered_words_match_contract_comparison
    (e : RollupValue.Environment) (keccak : RollupValue.Bytes → Bytes32) (p : ValidityPIs)
    (b : LimbBounds p)
    (agree : RollupValue.HashEncodingAgrees e (fun bytes => beValue (keccak bytes).words))
    (canon : LimbsCanonical (ValidityPIs.hash keccak p).words) :
    RollupValue.limbsMatchBytes32 (ValidityPIs.hash keccak p).words 0
      (RollupValue.computeValidityPIHash e p.toRollup) = true := by
  have hpre := circuit_pi_layout_matches_solidity_preimage p b
  have hval : RollupValue.computeValidityPIHash e p.toRollup
      = beValue (ValidityPIs.hash keccak p).words := by
    rw [RollupValue.computeValidityPIHash, agree, ValidityPIs.hash, hpre]
  rw [hval]
  generalize ValidityPIs.hash keccak p = q at canon ⊢
  obtain ⟨a0, a1, a2, a3, a4, a5, a6, a7⟩ := q
  simp only [BalancePublicInputs.Bytes8.words, LimbsCanonical] at canon ⊢
  have h0 : a0 < wordBase := canon a0 (by simp)
  have h1 : a1 < wordBase := canon a1 (by simp)
  have h2 : a2 < wordBase := canon a2 (by simp)
  have h3 : a3 < wordBase := canon a3 (by simp)
  have h4 : a4 < wordBase := canon a4 (by simp)
  have h5 : a5 < wordBase := canon a5 (by simp)
  have h6 : a6 < wordBase := canon a6 (by simp)
  have h7 : a7 < wordBase := canon a7 (by simp)
  simp only [wordBase] at h0 h1 h2 h3 h4 h5 h6 h7
  simp [RollupValue.limbsMatchBytes32, beValue, wordBase, RollupValue.u32Limit]
  omega

/-! ## Parser round trips -/

theorem ext_read_after_words (s : ExtendedPublicState) (rest : List Nat) :
    ExtendedPublicState.read (s.words ++ rest) = s := by
  obtain ⟨inner, bc, dc, n, rc, sc⟩ := s
  obtain ⟨bn, thi, tlo, ar, dr, pr⟩ := inner
  obtain ⟨ar0, ar1, ar2, ar3⟩ := ar
  obtain ⟨dr0, dr1, dr2, dr3⟩ := dr
  obtain ⟨pr0, pr1, pr2, pr3⟩ := pr
  obtain ⟨b0, b1, b2, b3, b4, b5, b6, b7⟩ := bc
  obtain ⟨d0, d1, d2, d3, d4, d5, d6, d7⟩ := dc
  obtain ⟨r0, r1, r2, r3, r4, r5, r6, r7⟩ := rc
  obtain ⟨s0, s1, s2, s3, s4, s5, s6, s7⟩ := sc
  simp only [ExtendedPublicState.read, ExtendedPublicState.words,
    BalancePublicInputs.PublicState.read, BalancePublicInputs.PublicState.words,
    BalancePublicInputs.Root.read, BalancePublicInputs.Root.words,
    BalancePublicInputs.Bytes8.read, BalancePublicInputs.Bytes8.words,
    List.cons_append, List.nil_append, List.getD_cons_zero, List.getD_cons_succ]

theorem take_prefix (l r : List Nat) (n : Nat) (h : l.length = n) : (l ++ r).take n = l := by
  subst h; exact List.take_left l r

theorem drop_prefix (l r : List Nat) (n : Nat) (h : l.length = n) : (l ++ r).drop n = r := by
  subst h; exact List.drop_left l r

theorem canonical_limbs_iff (ws : List Nat) : canonicalLimbs ws = true ↔ LimbsCanonical ws := by
  simp [canonicalLimbs, LimbsCanonical]

/-- `ExtendedPublicState::from_u64_slice` accepts exactly what `to_u64_vec` produced, provided the
native range invariants hold. -/
theorem ext_from_u64_slice_roundtrip (s : ExtendedPublicState)
    (hb : s.inner.blockNumber < blockLimit)
    (hhi : s.inner.timestampHi < wordBase) (hlo : s.inner.timestampLo < wordBase)
    (h1 : LimbsCanonical s.blockHashChain.words)
    (h2 : LimbsCanonical s.depositHashChain.words)
    (hn : s.depositCount < blockLimit)
    (h3 : LimbsCanonical s.channelRegHashChain.words)
    (h4 : LimbsCanonical s.bpSigChain.words) :
    ExtendedPublicState.fromU64Slice s.words = .ok s := by
  have hread : ExtendedPublicState.read s.words = s := by
    simpa using ext_read_after_words s []
  simp only [ExtendedPublicState.fromU64Slice, ext_public_state_word_count, hread,
    ne_eq, not_true_eq_false, if_false]
  rw [if_neg (by omega), if_neg (by omega),
    if_neg (by simp [(canonical_limbs_iff _).mpr h1]),
    if_neg (by simp [(canonical_limbs_iff _).mpr h2]),
    if_neg (by omega),
    if_neg (by simp [(canonical_limbs_iff _).mpr h3]),
    if_neg (by simp [(canonical_limbs_iff _).mpr h4])]

theorem ext_from_u64_slice_rejects_wrong_length (xs : List Nat)
    (h : xs.length ≠ extPublicStateU64Len) :
    ExtendedPublicState.fromU64Slice xs = .error (.invalidLength extPublicStateU64Len xs.length) := by
  simp [ExtendedPublicState.fromU64Slice, h]

theorem ext_from_u64_slice_rejects_an_oversized_deposit_count (xs : List Nat)
    (hlen : xs.length = extPublicStateU64Len)
    (hb : (ExtendedPublicState.read xs).inner.blockNumber < blockLimit)
    (hhi : (ExtendedPublicState.read xs).inner.timestampHi < wordBase)
    (hlo : (ExtendedPublicState.read xs).inner.timestampLo < wordBase)
    (h1 : LimbsCanonical (ExtendedPublicState.read xs).blockHashChain.words)
    (h2 : LimbsCanonical (ExtendedPublicState.read xs).depositHashChain.words)
    (hn : (ExtendedPublicState.read xs).depositCount ≥ blockLimit) :
    ExtendedPublicState.fromU64Slice xs = .error .depositCount := by
  simp only [ExtendedPublicState.fromU64Slice, hlen, ne_eq, not_true_eq_false, if_false]
  rw [if_neg (by omega), if_neg (by omega),
    if_neg (by simp [(canonical_limbs_iff _).mpr h1]),
    if_neg (by simp [(canonical_limbs_iff _).mpr h2]), if_pos (by omega)]

/-- The in-circuit split performs NO range validation: it accepts limbs no native constructor
would have produced. Canonicality of those wires comes from the `is_checked` allocation in the
circuit that registered them, not from this parser. -/
theorem ext_from_slice_target_performs_no_range_check (s : ExtendedPublicState) :
    ExtendedPublicState.fromSliceTarget s.words = .ok s := by
  have hread : ExtendedPublicState.read s.words = s := by
    simpa using ext_read_after_words s []
  simp [ExtendedPublicState.fromSliceTarget, ext_public_state_word_count, hread]

theorem block_chain_from_pis_target_roundtrip (capCount : Nat) (c : BlockChainPIs)
    (hvd : c.vdWords.length = vdVecLen capCount) (suffix : List Nat) :
    BlockChainPIs.fromPisTarget capCount (c.words ++ suffix) = .ok c := by
  have hlen : (c.words ++ suffix).length = blockChainPisLen capCount + suffix.length := by
    rw [List.length_append, block_chain_words_count, hvd, blockChainPisLen]
  have hinit : ExtendedPublicState.read (c.words ++ suffix) = c.initial := by
    rw [BlockChainPIs.words]
    simp only [List.append_assoc]
    exact ext_read_after_words _ _
  have hdrop : (c.words ++ suffix).drop extPublicStateU64Len
      = c.final.words ++ (c.vdWords ++ suffix) := by
    rw [BlockChainPIs.words]
    simp only [List.append_assoc]
    exact drop_prefix _ _ _ (ext_public_state_word_count _)
  have hfinal : ExtendedPublicState.read ((c.words ++ suffix).drop extPublicStateU64Len)
      = c.final := by
    rw [hdrop]; exact ext_read_after_words _ _
  have hdrop2 : (c.words ++ suffix).drop blockChainPublicInputsLen = c.vdWords ++ suffix := by
    rw [show blockChainPublicInputsLen = extPublicStateU64Len + extPublicStateU64Len from rfl,
      ← List.drop_drop, hdrop]
    exact drop_prefix _ _ _ (ext_public_state_word_count _)
  simp only [BlockChainPIs.fromPisTarget]
  rw [if_neg (by omega), hinit, hfinal, hdrop2, take_prefix _ _ _ hvd]

/-- `from_pis` reads a fixed prefix: any trailing public inputs of the inner proof are dropped
without constraint. -/
theorem block_chain_from_pis_target_ignores_trailing_inputs (capCount : Nat) (c : BlockChainPIs)
    (hvd : c.vdWords.length = vdVecLen capCount) (suffix : List Nat) :
    BlockChainPIs.fromPisTarget capCount (c.words ++ suffix)
      = BlockChainPIs.fromPisTarget capCount c.words := by
  rw [block_chain_from_pis_target_roundtrip capCount c hvd suffix,
    show c.words = c.words ++ ([] : List Nat) from (List.append_nil _).symm,
    block_chain_from_pis_target_roundtrip capCount c hvd []]

theorem block_chain_from_pis_target_rejects_short_input (capCount : Nat) (xs : List Nat)
    (h : xs.length < blockChainPisLen capCount) :
    BlockChainPIs.fromPisTarget capCount xs = .error .boundsPanic := by
  simp [BlockChainPIs.fromPisTarget, h]

theorem block_chain_from_u64_slice_rejects_wrong_length (capCount : Nat) (xs : List Nat)
    (h : xs.length ≠ blockChainPisLen capCount) :
    BlockChainPIs.fromU64Slice capCount xs
      = .error (.invalidLength (blockChainPisLen capCount) xs.length) := by
  simp [BlockChainPIs.fromU64Slice, h]

/-! ## Structure of the extended public state -/

/-- The 48-word Poseidon preimage determines every extended-state field: no field is left out of
the commitment. This is an encoding fact; it is NOT hash injectivity. -/
theorem ext_encoding_injective {a b : ExtendedPublicState} (h : a.words = b.words) : a = b := by
  have hra : ExtendedPublicState.read a.words = a := by simpa using ext_read_after_words a []
  have hrb : ExtendedPublicState.read b.words = b := by simpa using ext_read_after_words b []
  rw [← hra, ← hrb, h]

/-- `ExtendedPublicStateTarget::connect` is field-wise equality, so it pins the whole state. -/
theorem connected_ext_states_are_equal {a b : ExtendedPublicState}
    (h : ExtendedPublicState.Connect a b) : a = b := by
  obtain ⟨h1, h2, h3, h4, h5, h6⟩ := h
  obtain ⟨ia, ba, da, na, ra, sa⟩ := a
  obtain ⟨ib, bb, db, nb, rb, sb⟩ := b
  simp_all

theorem ext_select_picks_the_branch (t f : ExtendedPublicState) :
    ExtendedPublicState.select true t f = t ∧ ExtendedPublicState.select false t f = f := by
  exact ⟨rfl, rfl⟩

theorem ext_commitment_absorbs_every_word (poseidon : List Nat → Bytes32)
    {a b : ExtendedPublicState} (h : a.words = b.words) :
    ExtendedPublicState.commitment poseidon a = ExtendedPublicState.commitment poseidon b := by
  simp [ExtendedPublicState.commitment, h]

/-- Only three of the extended state's fields reach the validity public inputs directly: the
block number, the block hash chain, and the Poseidon commitment. The deposit hash chain, the
deposit count, the channel-registration hash chain, the signature-list accumulator and every
inner tree root are visible to `IntmaxRollup` ONLY through that commitment. -/
theorem validity_pis_expose_only_block_number_chain_and_commitment
    (poseidon : List Nat → Bytes32) (a b f : ExtendedPublicState) (prover : Addr)
    (hn : a.inner.blockNumber = b.inner.blockNumber)
    (hc : a.blockHashChain = b.blockHashChain)
    (hk : ExtendedPublicState.commitment poseidon a = ExtendedPublicState.commitment poseidon b) :
    ValidityPIs.fromStates poseidon a f prover = ValidityPIs.fromStates poseidon b f prover := by
  simp [ValidityPIs.fromStates, hn, hc, hk]

theorem from_states_takes_the_span_endpoints (poseidon : List Nat → Bytes32)
    (initial final : ExtendedPublicState) (prover : Addr) :
    (ValidityPIs.fromStates poseidon initial final prover).initialBlockNumber
        = initial.inner.blockNumber ∧
      (ValidityPIs.fromStates poseidon initial final prover).finalBlockNumber
        = final.inner.blockNumber ∧
      (ValidityPIs.fromStates poseidon initial final prover).initialExtCommitment
        = poseidon initial.words ∧
      (ValidityPIs.fromStates poseidon initial final prover).finalExtCommitment
        = poseidon final.words :=
  ⟨rfl, rfl, rfl, rfl⟩

/-! ## `block_hash_chain_circuit.rs`: the cyclic wrapper -/

def BlockHashChainCircuit.newBuild (commonMatches buildSucceeded : Bool) : Result Unit :=
  if ¬ commonMatches then .error .commonDataMismatch
  else if ¬ buildSucceeded then .error .buildFailed
  else .ok ()

/-- `BlockHashChainCircuit::verify`: `check_cyclic_proof_verifier_data` runs BEFORE the plonky2
proof check. -/
def BlockHashChainCircuit.verify (cyclicVdOk proofOk : Bool) : Result Unit :=
  if ¬ cyclicVdOk then .error .cyclicVerifierData
  else if ¬ proofOk then .error .proofVerification
  else .ok ()

/-- `generate_cd` overwrites `common.num_public_inputs` with this count. -/
def BlockHashChainCircuit.publicInputCount (capCount : Nat) : Nat := blockChainPisLen capCount

/-- The wrapper's only constraints: verify the block-step proof against the baked-in constant
verifier data, then re-register the parsed `2 * 48 + vd` prefix of that proof's public inputs. -/
def BlockHashChainGates (capCount : Nat) (blockStepVerifies : List Nat → Prop)
    (stepPis registered : List Nat) : Prop :=
  blockStepVerifies stepPis ∧
    ∃ c : BlockChainPIs,
      BlockChainPIs.fromPisTarget capCount stepPis = .ok c ∧ registered = c.words

theorem block_hash_chain_build_checks_common_data_first (buildSucceeded : Bool) :
    BlockHashChainCircuit.newBuild false buildSucceeded = .error .commonDataMismatch := rfl

theorem block_hash_chain_build_rejects_a_failed_build :
    BlockHashChainCircuit.newBuild true false = .error .buildFailed := rfl

theorem block_hash_chain_verify_checks_cyclic_vd_first (proofOk : Bool) :
    BlockHashChainCircuit.verify false proofOk = .error .cyclicVerifierData := rfl

theorem block_hash_chain_verify_needs_both_checks :
    BlockHashChainCircuit.verify true false = .error .proofVerification ∧
      BlockHashChainCircuit.verify true true = .ok () := ⟨rfl, rfl⟩

theorem block_hash_chain_public_input_count_pinned (capCount : Nat) :
    BlockHashChainCircuit.publicInputCount capCount
      = blockChainPublicInputsLen + vdVecLen capCount := rfl

/-- The wrapper is a pure pass-through: whatever extended states and verifier data the block-step
proof exports in its prefix are re-registered verbatim, for ARBITRARY such values. In particular
the wrapper itself does not constrain the re-exported verifier data to be its own; that binding
comes from `check_cyclic_proof_verifier_data` natively and from
`add_proof_target_and_verify_cyclic` inside `ValidityCircuit`. -/
theorem block_hash_chain_re_exports_the_block_step_prefix (capCount : Nat)
    (blockStepVerifies : List Nat → Prop) (c : BlockChainPIs)
    (hvd : c.vdWords.length = vdVecLen capCount) (suffix : List Nat)
    (verified : blockStepVerifies (c.words ++ suffix)) :
    BlockHashChainGates capCount blockStepVerifies (c.words ++ suffix) c.words :=
  ⟨verified, c, block_chain_from_pis_target_roundtrip capCount c hvd suffix, rfl⟩

/-! ## `validity_circuit.rs`: the validity circuit's constraint system -/

/-- Build-time constants and opaque callbacks of `ValidityCircuit::new`. The two `*Verifies`
predicates stand for recursive plonky2 verification; nothing derives them and nothing derives
anything from their truth. -/
structure CircuitEnv where
  capCount : Nat
  /-- `block_hash_chain_vd.verifier_only`, baked in as a circuit constant (A7). -/
  blockChainVdWords : List Nat
  blockChainVerifies : List Nat → Prop
  aggListVerifies : List Nat → Prop
  poseidon : List Nat → Bytes32
  keccak : RollupValue.Bytes → Bytes32

/-- An arbitrary satisfying assignment of the circuit's wires, not a natively generated witness. -/
structure ValidityWitness where
  blockChainPis : List Nat
  aggListPis : List Nat
  prover : Addr
  registered : List Nat

/-- `agg_list_proof.public_inputs[0..BYTES32_LEN]`, the list circuit's commitment `C`. -/
def listCommitment (xs : List Nat) : Bytes32 := BalancePublicInputs.Bytes8.read xs 0

/-- `should_verify_list = not(final.bp_sig_chain.is_zero())`: computed from the folded chain,
never from a prover-supplied flag. -/
def shouldVerifyList (c : BlockChainPIs) : Bool :=
  ! (c.final.bpSigChain == BalancePublicInputs.Bytes8.zero)

def validityPisOf (env : CircuitEnv) (c : BlockChainPIs) (prover : Addr) : ValidityPIs :=
  ValidityPIs.fromStates env.poseidon c.initial c.final prover

def registeredWords (env : CircuitEnv) (c : BlockChainPIs) (prover : Addr) : List Nat :=
  (ValidityPIs.hash env.keccak (validityPisOf env c prover)).words

/-- The gate set of `ValidityCircuit::new`, in source order:
1. recursively verify the block-hash-chain proof and connect the constant verifier data to the
   one the proof re-exports in its own public inputs (`add_proof_target_and_verify_cyclic`);
2. compute `should_verify_list` from the folded `final.bp_sig_chain`;
3. conditionally verify the aggregate-list proof and, under the same condition, assert its
   commitment equals that chain;
4. register the keccak of the seven-field validity public inputs built from the SAME parsed
   initial/final extended states plus the freely chosen `prover` address.

Note what is absent: no comparison of the initial and final block numbers, no constraint on
`initial.bp_sig_chain`, and no constraint on the block-chain proof's public inputs beyond the
prefix `from_pis` reads. -/
def Gates (env : CircuitEnv) (w : ValidityWitness) : Prop :=
  ∃ c : BlockChainPIs,
    BlockChainPIs.fromPisTarget env.capCount w.blockChainPis = .ok c ∧
      env.blockChainVerifies w.blockChainPis ∧
      c.vdWords = env.blockChainVdWords ∧
      (shouldVerifyList c = true →
        env.aggListVerifies w.aggListPis ∧ listCommitment w.aggListPis = c.final.bpSigChain) ∧
      w.registered = registeredWords env c w.prover

/-- Every satisfying assignment registers the keccak of the public inputs derived from the
block-chain proof's OWN initial and final extended states: the prover cannot decouple the
announced span endpoints from the folded ones. The prover address is unconstrained by design. -/
theorem gates_register_the_hash_of_the_folded_states (env : CircuitEnv) (w : ValidityWitness)
    (c : BlockChainPIs) (g : Gates env w)
    (parsed : BlockChainPIs.fromPisTarget env.capCount w.blockChainPis = .ok c) :
    w.registered
      = (ValidityPIs.hash env.keccak
          (ValidityPIs.fromStates env.poseidon c.initial c.final w.prover)).words := by
  obtain ⟨c', parsed', _, _, _, hreg⟩ := g
  rw [parsed] at parsed'
  cases parsed'
  exact hreg

/-- The cyclic binding: the verifier data the inner proof re-exports must equal the build-time
constant, so the fold cannot be continued under a different circuit's key. -/
theorem gates_bind_the_inner_verifier_data (env : CircuitEnv) (w : ValidityWitness)
    (c : BlockChainPIs) (g : Gates env w)
    (parsed : BlockChainPIs.fromPisTarget env.capCount w.blockChainPis = .ok c) :
    c.vdWords = env.blockChainVdWords := by
  obtain ⟨c', parsed', _, hvd, _, _⟩ := g
  rw [parsed] at parsed'
  cases parsed'
  exact hvd

/-- A non-zero folded signature chain forces both the recursive aggregate-list verification and
the commitment equality. -/
theorem gates_force_the_signature_list_proof_when_the_chain_is_nonzero
    (env : CircuitEnv) (w : ValidityWitness) (c : BlockChainPIs) (g : Gates env w)
    (parsed : BlockChainPIs.fromPisTarget env.capCount w.blockChainPis = .ok c)
    (nonzero : c.final.bpSigChain ≠ BalancePublicInputs.Bytes8.zero) :
    env.aggListVerifies w.aggListPis ∧ listCommitment w.aggListPis = c.final.bpSigChain := by
  obtain ⟨c', parsed', _, _, hlist, _⟩ := g
  rw [parsed] at parsed'
  cases parsed'
  exact hlist (by simp [shouldVerifyList, nonzero])

/-- Contrapositive, the A8 truncation guard: if no aggregate-list proof verifies for this witness,
the folded lifetime signature chain must be empty. -/
theorem gates_imply_an_empty_chain_when_no_list_proof_verifies
    (env : CircuitEnv) (w : ValidityWitness) (c : BlockChainPIs) (g : Gates env w)
    (parsed : BlockChainPIs.fromPisTarget env.capCount w.blockChainPis = .ok c)
    (noProof : ¬ env.aggListVerifies w.aggListPis) :
    c.final.bpSigChain = BalancePublicInputs.Bytes8.zero := by
  by_contra nonzero
  exact noProof
    (gates_force_the_signature_list_proof_when_the_chain_is_nonzero env w c g parsed nonzero).1

/-- The same conclusion from the commitment side: the dummy proof's all-zero commitment cannot
stand in for a non-empty signature chain. -/
theorem dummy_list_commitment_forces_an_empty_chain
    (env : CircuitEnv) (w : ValidityWitness) (c : BlockChainPIs) (g : Gates env w)
    (parsed : BlockChainPIs.fromPisTarget env.capCount w.blockChainPis = .ok c)
    (dummy : listCommitment w.aggListPis = BalancePublicInputs.Bytes8.zero) :
    c.final.bpSigChain = BalancePublicInputs.Bytes8.zero := by
  by_contra nonzero
  have := (gates_force_the_signature_list_proof_when_the_chain_is_nonzero env w c g parsed nonzero).2
  exact nonzero (by rw [← this, dummy])

/-- An environment in which both recursive verifications succeed; used only to exhibit satisfying
assignments. It asserts nothing about real proofs. -/
def openEnv (capCount : Nat) (vd : List Nat) (poseidon : List Nat → Bytes32)
    (keccak : RollupValue.Bytes → Bytes32) : CircuitEnv :=
  { capCount := capCount
    blockChainVdWords := vd
    blockChainVerifies := fun _ => True
    aggListVerifies := fun _ => True
    poseidon := poseidon
    keccak := keccak }

/-- Positive example: a normal accepted trace. -/
theorem gates_have_a_satisfying_assignment (capCount : Nat) (vd : List Nat)
    (hvd : vd.length = vdVecLen capCount) (poseidon : List Nat → Bytes32)
    (keccak : RollupValue.Bytes → Bytes32) (initial final : ExtendedPublicState) (prover : Addr) :
    Gates (openEnv capCount vd poseidon keccak)
      { blockChainPis := (BlockChainPIs.mk initial final vd).words
        aggListPis := (BalancePublicInputs.Bytes8.zero).words
        prover := prover
        registered := registeredWords (openEnv capCount vd poseidon keccak)
          (BlockChainPIs.mk initial final vd) prover } := by
  refine ⟨BlockChainPIs.mk initial final vd, ?_, trivial, rfl, ?_, rfl⟩
  · simpa using block_chain_from_pis_target_roundtrip capCount (BlockChainPIs.mk initial final vd)
      hvd []
  · intro h
    exact ⟨trivial, by
      simp only [shouldVerifyList, bne_iff_ne, ne_eq, Bool.not_eq_true'] at h
      simp only [listCommitment, BalancePublicInputs.Bytes8.words,
        BalancePublicInputs.Bytes8.read, BalancePublicInputs.Bytes8.zero]
      simp_all⟩

/-- The circuit deliberately does NOT require `initial.bp_sig_chain = 0`: a validity span may start
from any finalized extended state whose lifetime signature chain is already non-empty. Exhibited
by a satisfying assignment. -/
theorem gates_accept_a_span_starting_from_a_nonzero_signature_chain (capCount : Nat)
    (vd : List Nat) (hvd : vd.length = vdVecLen capCount) (poseidon : List Nat → Bytes32)
    (keccak : RollupValue.Bytes → Bytes32) (initial final : ExtendedPublicState) (prover : Addr)
    (started : initial.bpSigChain ≠ BalancePublicInputs.Bytes8.zero)
    (ended : final.bpSigChain = BalancePublicInputs.Bytes8.zero) :
    ∃ w : ValidityWitness, Gates (openEnv capCount vd poseidon keccak) w ∧
      (∃ c, BlockChainPIs.fromPisTarget capCount w.blockChainPis = .ok c ∧
        c.initial.bpSigChain ≠ BalancePublicInputs.Bytes8.zero) := by
  refine ⟨_, gates_have_a_satisfying_assignment capCount vd hvd poseidon keccak initial final
    prover, BlockChainPIs.mk initial final vd, ?_, started⟩
  simpa using block_chain_from_pis_target_roundtrip capCount (BlockChainPIs.mk initial final vd)
    hvd []

/-- The validity circuit imposes no ordering between the announced initial and final block
numbers: a satisfying assignment exists with `final < initial`. Monotonicity is enforced by the
folded block-step statement and, on chain, by `fullVerify`'s `blockHashAt` comparisons — not
here. -/
theorem gates_do_not_order_the_initial_and_final_block_numbers (capCount : Nat)
    (vd : List Nat) (hvd : vd.length = vdVecLen capCount) (poseidon : List Nat → Bytes32)
    (keccak : RollupValue.Bytes → Bytes32) (initial final : ExtendedPublicState) (prover : Addr)
    (regress : final.inner.blockNumber < initial.inner.blockNumber)
    (ended : final.bpSigChain = BalancePublicInputs.Bytes8.zero) :
    ∃ w : ValidityWitness, Gates (openEnv capCount vd poseidon keccak) w ∧
      (∃ c, BlockChainPIs.fromPisTarget capCount w.blockChainPis = .ok c ∧
        c.final.inner.blockNumber < c.initial.inner.blockNumber) := by
  refine ⟨_, gates_have_a_satisfying_assignment capCount vd hvd poseidon keccak initial final
    prover, BlockChainPIs.mk initial final vd, ?_, regress⟩
  simpa using block_chain_from_pis_target_roundtrip capCount (BlockChainPIs.mk initial final vd)
    hvd []
