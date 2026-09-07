import Zkp.Implementation.BalancePublicInputs
import Zkp.Implementation.PrivateState
import Zkp.Implementation.UpdatePublicState
import Zkp.Implementation.U256Arithmetic
import Zkp.Implementation.RollupValue

/-!
# SingleWithdrawalCircuit: one withdrawal carved out of a verified balance proof

Handwritten SEMANTIC MODEL of src/circuits/withdraw/single_withdrawal_circuit.rs
(1037 lines): the 45-limb public-input codec (`SingleWithdawalPublicInputs`
native `from_u64_slice`/`to_u64_vec` and the target `from_vec`/`to_vec`), the
native admission helper `SingleWithdawalWitness::to_public_inputs`, the circuit
constructor `SingleWithdawalTarget::new` (as a gate predicate over arbitrary
wire assignments), `set_witness`, `SingleWithdawalCircuit::new` and `prove`.
This is NOT a refinement proof of the Rust, plonky2 or Solidity code. Wires and
field elements are integer representatives. Poseidon, the four Merkle gadgets,
plonky2 proof verification, the balance verifier key, the `UpdatePublicState`
Merkle root and the `AccountState` openings are opaque callbacks of an
`Environment`; every fact below is derived from the explicit control flow and
the callback *results*, never from hash injectivity or proof soundness.

Imported models of genuinely called code:
* `BalancePublicInputs` — `BalanceFullPublicInputs::from_u64_slice` (native)
  and `from_pis` (target) and the `PublicState` word layout;
* `PrivateState` — `PrivateState::commitment` preimage (`words`);
* `UpdatePublicState` — `UpdatePublicState::verify` (native) and the target
  gates;
* `U256Arithmetic` — limb checks and the big-endian u256 value of `amount`;
* `RollupValue` — only the 5-field `Withdrawal` leaf that
  `foldWithdrawalLeaf`/`verifyWithdrawalSet` consume on L1, to state the
  projection from this circuit's 30-limb withdrawal encoding.

What the source does (and the model states):
* Native admission (`toPublicInputs`) verifies the balance proof against the
  FIXED `balance_vd` captured at `SingleWithdawalCircuit::new` (cyclic
  verifier-data check on the trailing limbs, then plonky2 `verify`), parses the
  balance public inputs, checks the private-state commitment, verifies and
  binds the public-state update (`old` = balance public state, output = `new`),
  opens the sender's tx in its own sent-tx tree at index `tx.nonce` under the
  private state's `sent_tx_tree_root`, opens the transfer under
  `tx.transfer_tree_root`, binds the account state to the balance channel and
  to the `new` account root, and opens the tx (legacy `Tx` or typed `TxV2`
  restricted to `UserTransfer` with zero `channel_action_root`) at index
  `channel_id` under `send_leaf.tx_tree_root`. The recipient must be the
  canonical ADDRESS_TAG encoding; the nullifier is Poseidon over
  `Transfer ++ [channel_id, transfer_index, nonce]` split into 8 limbs.
* The circuit (`CircuitGates`) enforces the same equalities with `connect`,
  range-checks `tx.nonce` to 32 bits, forces the prover-supplied
  `send_leaf.tx_tree_root` bytes to the canonical field representation
  (`to_hash_out`, the TODO-2 fix) and selects legacy/v2 inclusion by the
  boolean `use_tx_v2` with conditional asserts.
* `prove` runs native admission BEFORE filling the witness; every failure of
  the plonky2 prover is `FailedToProve`.

What the model does NOT claim (recorded, not assumed): proof soundness of the
embedded balance verifier; that the `sent_tx_tree_root` inside the private
state really contains only spent transfers (that is the balance/spend
circuits' job); that `send_leaf.tx_tree_root` was posted on chain (validity
proof / `account_tree_root` of the OUTPUT public state, checked downstream in
withdrawal_step.rs and on L1); freshness or uniqueness of the nullifier beyond
representation binding of its preimage (consumption is `IntmaxRollup`'s
`used[nullifier]`); the `SentTxMerkleProof` error variant of the source is
never produced (the sent-tx opening failure is reported as `TxMerkleProof`).
Serialization (`to_bytes`/`from_bytes`) and the unit tests are not modeled.
-/
namespace Zkp.Implementation.SingleWithdrawalCircuit

abbrev Root := BalancePublicInputs.Root
abbrev Bytes8 := BalancePublicInputs.Bytes8
abbrev PublicState := BalancePublicInputs.PublicState
abbrev BalancePis := BalancePublicInputs.PublicInputs
abbrev VerifierData := BalancePublicInputs.VerifierData
abbrev Update := UpdatePublicState.Update

/-! ## Pinned constants (withdrawal.rs, address.rs, u256.rs, bytes32.rs,
public_state.rs, constants.rs, recipient.rs, tx.rs) -/

def wordBase : Nat := 2 ^ 32
def goldilocks : Nat := 0xffffffff00000001
def addressLen : Nat := 5
def u256Len : Nat := 8
def bytes32Len : Nat := 8
def withdrawalLen : Nat := addressLen + 1 + u256Len + 2 * bytes32Len
def publicStateU64Len : Nat := BalancePublicInputs.publicStateLength
def singleWithdrawalPublicInputsLen : Nat := publicStateU64Len + withdrawalLen
def sentTxTreeHeight : Nat := 32
def txTreeHeight : Nat := 32
def channelIdBits : Nat := 32
def transferTreeHeight : Nat := 6
def userTransferClass : Nat := 0
def addressTag : Nat := 2
def addressTagWord : Nat := addressTag * 2 ^ 24
def blockLimit : Nat := BalancePublicInputs.blockLimit

theorem withdrawal_len_pinned : withdrawalLen = 30 := by decide
theorem public_inputs_len_pinned : singleWithdrawalPublicInputsLen = 45 := by decide
theorem public_state_len_pinned : publicStateU64Len = 15 := by decide
theorem tx_tree_height_is_channel_id_bits : txTreeHeight = channelIdBits := rfl
theorem sent_tx_tree_height_pinned : sentTxTreeHeight = 32 := rfl
theorem address_tag_word_pinned : addressTagWord = 0x02000000 := by decide
theorem block_limit_pinned : blockLimit = 2 ^ 63 := rfl

/-! ## Withdrawal and public-input encodings -/

structure Address where
  a0 : Nat
  a1 : Nat
  a2 : Nat
  a3 : Nat
  a4 : Nat
  deriving DecidableEq, Repr

def Address.words (a : Address) : List Nat := [a.a0, a.a1, a.a2, a.a3, a.a4]
def Address.read (xs : List Nat) (o : Nat) : Address :=
  ⟨xs.getD o 0, xs.getD (o+1) 0, xs.getD (o+2) 0, xs.getD (o+3) 0, xs.getD (o+4) 0⟩

/-- `Withdrawal` (withdrawal.rs): recipient address (5 limbs), token index,
    u256 amount (8 big-endian limbs), nullifier and aux data (8 limbs each). -/
structure Withdrawal where
  recipient : Address
  tokenIndex : Nat
  amount : Bytes8
  nullifier : Bytes8
  auxData : Bytes8
  deriving DecidableEq, Repr

def Withdrawal.words (w : Withdrawal) : List Nat :=
  w.recipient.words ++ [w.tokenIndex] ++ w.amount.words ++ w.nullifier.words ++ w.auxData.words
def Withdrawal.read (xs : List Nat) : Withdrawal :=
  ⟨Address.read xs 0, xs.getD 5 0, BalancePublicInputs.Bytes8.read xs 6,
    BalancePublicInputs.Bytes8.read xs 14, BalancePublicInputs.Bytes8.read xs 22⟩
def Withdrawal.Checked (w : Withdrawal) : Prop := U256Arithmetic.Checked wordBase w.words
theorem word_base_agrees : wordBase = U256Arithmetic.wordBase := rfl
def Withdrawal.amountValue (w : Withdrawal) : Nat := U256Arithmetic.valueBE w.amount.words

/-- `SingleWithdawalPublicInputs`: public state (15 limbs) then withdrawal (30). -/
structure PublicInputs where
  publicState : PublicState
  withdrawal : Withdrawal
  deriving DecidableEq, Repr

def PublicInputs.words (p : PublicInputs) : List Nat := p.publicState.words ++ p.withdrawal.words
def readPublicInputs (xs : List Nat) : PublicInputs :=
  ⟨BalancePublicInputs.PublicState.read (xs.take publicStateU64Len),
    Withdrawal.read ((xs.drop publicStateU64Len).take withdrawalLen)⟩

inductive PisFault where
  | invalidLength (expected actual : Nat)
  | publicState (field : String)
  | withdrawal (reason : String)
  | u32Panic
  | targetLengthAssert
  deriving DecidableEq, Repr

theorem except_bind_ok_iff {ε α β : Type} (r : Except ε α) (f : α → Except ε β) (value : β) :
    (r >>= f) = .ok value ↔ ∃ x, r = .ok x ∧ f x = .ok value := by
  cases r <;> simp [Bind.bind, Except.bind]

/-- `PublicState::from_u64_slice`: exact length, `BlockNumber::new` (< 2^63),
    `U64::from_u64_slice` (two u32 limbs); Poseidon roots are copied without a
    field bound. -/
def publicStateFromNative (xs : List Nat) : Except PisFault PublicState :=
  if xs.length ≠ publicStateU64Len then .error (.publicState "length") else
  if (BalancePublicInputs.PublicState.read xs).blockNumber ≥ blockLimit then
    .error (.publicState "block_number") else
  if (BalancePublicInputs.PublicState.read xs).timestampHi ≥ wordBase ∨
      (BalancePublicInputs.PublicState.read xs).timestampLo ≥ wordBase then
    .error (.publicState "timestamp") else
  .ok (BalancePublicInputs.PublicState.read xs)

/-- `Withdrawal::from_u64_slice`: `assert!(x <= u32::MAX)` on every limb
    (a panic, before any length check), then `from_u32_slice` exact length. -/
def withdrawalFromNative (xs : List Nat) : Except PisFault Withdrawal :=
  if xs.any (fun x => decide (x ≥ wordBase)) then .error .u32Panic else
  if xs.length ≠ withdrawalLen then .error (.withdrawal "length") else
  .ok (Withdrawal.read xs)

/-- `SingleWithdawalPublicInputs::from_u64_slice` (lines 79-101). -/
def fromNative (xs : List Nat) : Except PisFault PublicInputs :=
  if xs.length ≠ singleWithdrawalPublicInputsLen then
    .error (.invalidLength singleWithdrawalPublicInputsLen xs.length)
  else do
    let ps ← publicStateFromNative (xs.take publicStateU64Len)
    let w ← withdrawalFromNative ((xs.drop publicStateU64Len).take withdrawalLen)
    pure ⟨ps, w⟩

/-- `SingleWithdawalPublicInputsTarget::from_vec` (lines 115-134): `assert_eq!`
    on the exact length, then positional slices. -/
def fromVec (xs : List Nat) : Except PisFault PublicInputs :=
  if xs.length = singleWithdrawalPublicInputsLen then .ok (readPublicInputs xs)
  else .error .targetLengthAssert

def NativeDomain (p : PublicInputs) : Prop :=
  p.publicState.blockNumber < blockLimit ∧ p.publicState.timestampHi < wordBase ∧
  p.publicState.timestampLo < wordBase ∧ p.withdrawal.Checked

theorem withdrawal_words_length (w : Withdrawal) : w.words.length = withdrawalLen := by
  simp [Withdrawal.words, Address.words, BalancePublicInputs.Bytes8.words, withdrawalLen,
    addressLen, u256Len, bytes32Len]

theorem public_inputs_words_length (p : PublicInputs) :
    p.words.length = singleWithdrawalPublicInputsLen := by
  simp [PublicInputs.words, withdrawal_words_length, BalancePublicInputs.public_state_word_count,
    singleWithdrawalPublicInputsLen, publicStateU64Len]

theorem withdrawal_read_words (w : Withdrawal) : Withdrawal.read w.words = w := by
  obtain ⟨⟨a0,a1,a2,a3,a4⟩, t, ⟨m0,m1,m2,m3,m4,m5,m6,m7⟩, ⟨n0,n1,n2,n3,n4,n5,n6,n7⟩,
    ⟨x0,x1,x2,x3,x4,x5,x6,x7⟩⟩ := w
  rfl

theorem public_state_read_words (ps : PublicState) :
    BalancePublicInputs.PublicState.read ps.words = ps := by
  obtain ⟨b, hi, lo, ⟨a0,a1,a2,a3⟩, ⟨d0,d1,d2,d3⟩, ⟨p0,p1,p2,p3⟩⟩ := ps
  rfl

theorem take_public_state_words (ps : PublicState) (suffix : List Nat) :
    (ps.words ++ suffix).take publicStateU64Len = ps.words := by
  obtain ⟨b, hi, lo, ⟨a0,a1,a2,a3⟩, ⟨d0,d1,d2,d3⟩, ⟨p0,p1,p2,p3⟩⟩ := ps
  rfl

theorem drop_public_state_words (ps : PublicState) (suffix : List Nat) :
    (ps.words ++ suffix).drop publicStateU64Len = suffix := by
  obtain ⟨b, hi, lo, ⟨a0,a1,a2,a3⟩, ⟨d0,d1,d2,d3⟩, ⟨p0,p1,p2,p3⟩⟩ := ps
  rfl

theorem take_withdrawal_words (w : Withdrawal) : w.words.take withdrawalLen = w.words := by
  obtain ⟨⟨a0,a1,a2,a3,a4⟩, t, ⟨m0,m1,m2,m3,m4,m5,m6,m7⟩, ⟨n0,n1,n2,n3,n4,n5,n6,n7⟩,
    ⟨x0,x1,x2,x3,x4,x5,x6,x7⟩⟩ := w
  rfl

theorem public_inputs_read_words (p : PublicInputs) : readPublicInputs p.words = p := by
  obtain ⟨ps, w⟩ := p
  simp only [readPublicInputs, PublicInputs.words, take_public_state_words, drop_public_state_words,
    take_withdrawal_words, public_state_read_words, withdrawal_read_words]

theorem public_inputs_encoding_injective {p q : PublicInputs} (same : p.words = q.words) : p = q := by
  have := congrArg readPublicInputs same
  simpa only [public_inputs_read_words] using this

theorem withdrawal_encoding_injective {w v : Withdrawal} (same : w.words = v.words) : w = v := by
  have := congrArg Withdrawal.read same
  simpa only [withdrawal_read_words] using this

/-- Limb offsets consumed downstream: recipient 15..19, token 20, amount
    21..28, nullifier 29..36, aux 37..44 (withdrawal_step.rs slices the first
    45 limbs and keccak-chains `withdrawal.to_u32_vec()`). -/
theorem withdrawal_limbs_follow_public_state (p : PublicInputs) :
    p.words.drop publicStateU64Len = p.withdrawal.words := by
  obtain ⟨⟨b, hi, lo, ⟨a0,a1,a2,a3⟩, ⟨d0,d1,d2,d3⟩, ⟨p0,p1,p2,p3⟩⟩, w⟩ := p
  rfl

theorem nullifier_limbs_at_offset_29 (p : PublicInputs) :
    (p.words.drop 29).take 8 = p.withdrawal.nullifier.words := by
  obtain ⟨⟨b, hi, lo, ⟨a0,a1,a2,a3⟩, ⟨d0,d1,d2,d3⟩, ⟨p0,p1,p2,p3⟩⟩,
    ⟨⟨r0,r1,r2,r3,r4⟩, t, ⟨m0,m1,m2,m3,m4,m5,m6,m7⟩, ⟨n0,n1,n2,n3,n4,n5,n6,n7⟩,
    ⟨x0,x1,x2,x3,x4,x5,x6,x7⟩⟩⟩ := p
  rfl

theorem recipient_limbs_at_offset_15 (p : PublicInputs) :
    (p.words.drop 15).take 5 = p.withdrawal.recipient.words := by
  obtain ⟨⟨b, hi, lo, ⟨a0,a1,a2,a3⟩, ⟨d0,d1,d2,d3⟩, ⟨p0,p1,p2,p3⟩⟩,
    ⟨⟨r0,r1,r2,r3,r4⟩, t, ⟨m0,m1,m2,m3,m4,m5,m6,m7⟩, ⟨n0,n1,n2,n3,n4,n5,n6,n7⟩,
    ⟨x0,x1,x2,x3,x4,x5,x6,x7⟩⟩⟩ := p
  rfl

theorem token_index_at_offset_20 (p : PublicInputs) :
    p.words[20]? = some p.withdrawal.tokenIndex := by
  obtain ⟨⟨b, hi, lo, ⟨a0,a1,a2,a3⟩, ⟨d0,d1,d2,d3⟩, ⟨p0,p1,p2,p3⟩⟩,
    ⟨⟨r0,r1,r2,r3,r4⟩, t, ⟨m0,m1,m2,m3,m4,m5,m6,m7⟩, ⟨n0,n1,n2,n3,n4,n5,n6,n7⟩,
    ⟨x0,x1,x2,x3,x4,x5,x6,x7⟩⟩⟩ := p
  rfl

theorem amount_limbs_at_offset_21 (p : PublicInputs) :
    (p.words.drop 21).take 8 = p.withdrawal.amount.words := by
  obtain ⟨⟨b, hi, lo, ⟨a0,a1,a2,a3⟩, ⟨d0,d1,d2,d3⟩, ⟨p0,p1,p2,p3⟩⟩,
    ⟨⟨r0,r1,r2,r3,r4⟩, t, ⟨m0,m1,m2,m3,m4,m5,m6,m7⟩, ⟨n0,n1,n2,n3,n4,n5,n6,n7⟩,
    ⟨x0,x1,x2,x3,x4,x5,x6,x7⟩⟩⟩ := p
  rfl

theorem aux_data_limbs_at_offset_37 (p : PublicInputs) :
    (p.words.drop 37).take 8 = p.withdrawal.auxData.words := by
  obtain ⟨⟨b, hi, lo, ⟨a0,a1,a2,a3⟩, ⟨d0,d1,d2,d3⟩, ⟨p0,p1,p2,p3⟩⟩,
    ⟨⟨r0,r1,r2,r3,r4⟩, t, ⟨m0,m1,m2,m3,m4,m5,m6,m7⟩, ⟨n0,n1,n2,n3,n4,n5,n6,n7⟩,
    ⟨x0,x1,x2,x3,x4,x5,x6,x7⟩⟩⟩ := p
  rfl

theorem native_length_guard (xs : List Nat) (wrong : xs.length ≠ singleWithdrawalPublicInputsLen) :
    fromNative xs = .error (.invalidLength singleWithdrawalPublicInputsLen xs.length) := by
  simp [fromNative, wrong]

theorem target_length_assert (xs : List Nat) (wrong : xs.length ≠ singleWithdrawalPublicInputsLen) :
    fromVec xs = .error .targetLengthAssert := by
  simp [fromVec, wrong]

theorem target_roundtrip (p : PublicInputs) : fromVec p.words = .ok p := by
  simp [fromVec, public_inputs_words_length, public_inputs_read_words]

theorem withdrawal_native_roundtrip (w : Withdrawal) (checked : w.Checked) :
    withdrawalFromNative w.words = .ok w := by
  have none : w.words.any (fun x => decide (x ≥ wordBase)) = false := by
    cases h : w.words.any (fun x => decide (x ≥ wordBase)) with
    | false => rfl
    | true =>
      obtain ⟨x, hx, hb⟩ := List.any_eq_true.mp h
      simp only [decide_eq_true_eq] at hb
      exact absurd (checked x hx) (Nat.not_lt.mpr hb)
  simp [withdrawalFromNative, none, withdrawal_words_length, withdrawal_read_words]

theorem public_state_native_roundtrip (ps : PublicState) (block : ps.blockNumber < blockLimit)
    (hi : ps.timestampHi < wordBase) (lo : ps.timestampLo < wordBase) :
    publicStateFromNative ps.words = .ok ps := by
  have b' : ¬ blockLimit ≤ ps.blockNumber := Nat.not_le.mpr block
  have h' : ¬ wordBase ≤ ps.timestampHi := Nat.not_le.mpr hi
  have l' : ¬ wordBase ≤ ps.timestampLo := Nat.not_le.mpr lo
  simp [publicStateFromNative, BalancePublicInputs.public_state_word_count, publicStateU64Len,
    public_state_read_words, b', h', l']

theorem native_roundtrip (p : PublicInputs) (domain : NativeDomain p) : fromNative p.words = .ok p := by
  obtain ⟨ps, w⟩ := p
  obtain ⟨block, hi, lo, checked⟩ := domain
  simp only [fromNative, public_inputs_words_length ⟨ps, w⟩, ne_eq, not_true_eq_false, if_false,
    PublicInputs.words, take_public_state_words, drop_public_state_words, take_withdrawal_words,
    public_state_native_roundtrip ps block hi lo, withdrawal_native_roundtrip w checked]
  rfl

theorem public_state_from_native_ok (xs : List Nat) (ps : PublicState)
    (ok : publicStateFromNative xs = .ok ps) :
    ps = BalancePublicInputs.PublicState.read xs ∧ xs.length = publicStateU64Len ∧
    ps.blockNumber < blockLimit ∧ ps.timestampHi < wordBase ∧ ps.timestampLo < wordBase := by
  unfold publicStateFromNative at ok
  split at ok
  · exact absurd ok (by simp)
  split at ok
  · exact absurd ok (by simp)
  split at ok
  · exact absurd ok (by simp)
  rename_i len block ts
  simp only [Except.ok.injEq] at ok
  subst ok
  exact ⟨rfl, by omega, by omega, by omega, by omega⟩

theorem withdrawal_from_native_ok (xs : List Nat) (w : Withdrawal)
    (ok : withdrawalFromNative xs = .ok w) :
    w = Withdrawal.read xs ∧ xs.length = withdrawalLen ∧ ∀ x ∈ xs, x < wordBase := by
  unfold withdrawalFromNative at ok
  split at ok
  · exact absurd ok (by simp)
  split at ok
  · exact absurd ok (by simp)
  rename_i none len
  simp only [Except.ok.injEq] at ok
  subst ok
  refine ⟨rfl, by omega, ?_⟩
  intro x hx
  refine Nat.not_le.mp ?_
  intro ge
  exact none (List.any_eq_true.mpr ⟨x, hx, decide_eq_true ge⟩)

/-- Native parsing agrees with the target reader wherever it succeeds: the
    native path only adds the exact-length and range guards. -/
theorem native_parse_is_target_read (xs : List Nat) (p : PublicInputs)
    (ok : fromNative xs = .ok p) :
    p = readPublicInputs xs ∧ xs.length = singleWithdrawalPublicInputsLen := by
  unfold fromNative at ok
  split at ok
  · exact absurd ok (by simp)
  · rename_i len
    simp only [except_bind_ok_iff, pure, Except.pure, Except.ok.injEq] at ok
    obtain ⟨ps, hps, w, hw, rfl⟩ := ok
    obtain ⟨rfl, _⟩ := public_state_from_native_ok _ _ hps
    obtain ⟨rfl, _⟩ := withdrawal_from_native_ok _ _ hw
    exact ⟨rfl, by omega⟩

/-! ## Bridge to the L1 withdrawal leaf (RollupValue.foldWithdrawalLeaf) -/

def addressValue (a : Address) : Nat := U256Arithmetic.valueBE a.words
def bytes32Value (b : Bytes8) : Nat := U256Arithmetic.valueBE b.words

/-- The 5-field leaf hashed by `Withdrawal::hash_with_prev_hash` (keccak over
    `prev ++ to_u32_vec()`) and modeled on L1 as `RollupValue.Withdrawal`. -/
def rollupLeaf (w : Withdrawal) : RollupValue.Withdrawal :=
  ⟨addressValue w.recipient, w.tokenIndex, w.amountValue, bytes32Value w.nullifier,
    bytes32Value w.auxData⟩

theorem value_le_injective_on_checked {base : Nat} :
    ∀ {xs ys : List Nat}, U256Arithmetic.Checked base xs → U256Arithmetic.Checked base ys →
      xs.length = ys.length → U256Arithmetic.valueLE base xs = U256Arithmetic.valueLE base ys → xs = ys
  | [], [], _, _, _, _ => rfl
  | [], _ :: _, _, _, len, _ => by simp at len
  | _ :: _, [], _, _, len, _ => by simp at len
  | x :: xs, y :: ys, cx, cy, len, eq => by
    have hx : x < base := cx x (by simp)
    have hy : y < base := cy y (by simp)
    have pos : 0 < base := by omega
    simp only [U256Arithmetic.valueLE] at eq
    have modx : (x + base * U256Arithmetic.valueLE base xs) % base = x := by
      rw [Nat.add_mul_mod_self_left]; exact Nat.mod_eq_of_lt hx
    have mody : (y + base * U256Arithmetic.valueLE base ys) % base = y := by
      rw [Nat.add_mul_mod_self_left]; exact Nat.mod_eq_of_lt hy
    have headEq : x = y := by rw [← modx, ← mody, eq]
    subst headEq
    have tailEq : U256Arithmetic.valueLE base xs = U256Arithmetic.valueLE base ys := by
      have := Nat.eq_of_mul_eq_mul_left pos (Nat.add_left_cancel eq)
      exact this
    have cx' : U256Arithmetic.Checked base xs := fun d hd => cx d (by simp [hd])
    have cy' : U256Arithmetic.Checked base ys := fun d hd => cy d (by simp [hd])
    have len' : xs.length = ys.length := by simpa using len
    rw [value_le_injective_on_checked cx' cy' len' tailEq]

theorem value_be_injective_on_checked {xs ys : List Nat}
    (cx : U256Arithmetic.Checked U256Arithmetic.wordBase xs)
    (cy : U256Arithmetic.Checked U256Arithmetic.wordBase ys)
    (len : xs.length = ys.length) (eq : U256Arithmetic.valueBE xs = U256Arithmetic.valueBE ys) :
    xs = ys := by
  have cx' : U256Arithmetic.Checked U256Arithmetic.wordBase xs.reverse :=
    fun d hd => cx d (List.mem_reverse.mp hd)
  have cy' : U256Arithmetic.Checked U256Arithmetic.wordBase ys.reverse :=
    fun d hd => cy d (List.mem_reverse.mp hd)
  have len' : xs.reverse.length = ys.reverse.length := by simpa using len
  have reversed := value_le_injective_on_checked cx' cy' len' eq
  have := congrArg List.reverse reversed
  simpa using this

/-- Representation binding of the L1 leaf projection: two 32-bit-checked
    circuit withdrawals with the same five L1 leaf fields are the same limbs. -/
theorem rollup_leaf_injective_on_checked {w v : Withdrawal} (cw : w.Checked) (cv : v.Checked)
    (same : rollupLeaf w = rollupLeaf v) : w = v := by
  simp only [rollupLeaf, RollupValue.Withdrawal.mk.injEq] at same
  obtain ⟨hr, ht, ha, hn, hx⟩ := same
  have sub : ∀ part : List Nat, ∀ {u : Withdrawal}, u.Checked →
      (∀ x ∈ part, x ∈ u.words) → U256Arithmetic.Checked U256Arithmetic.wordBase part :=
    fun part _ cu mem d hd => word_base_agrees ▸ cu d (mem d hd)
  have rec := value_be_injective_on_checked
    (sub _ cw (by intro y hy; simp [Withdrawal.words, hy]))
    (sub _ cv (by intro y hy; simp [Withdrawal.words, hy])) (by simp [Address.words]) hr
  have amt := value_be_injective_on_checked
    (sub _ cw (by intro y hy; simp [Withdrawal.words, hy]))
    (sub _ cv (by intro y hy; simp [Withdrawal.words, hy]))
    (by simp [BalancePublicInputs.Bytes8.words]) ha
  have nul := value_be_injective_on_checked
    (sub _ cw (by intro y hy; simp [Withdrawal.words, hy]))
    (sub _ cv (by intro y hy; simp [Withdrawal.words, hy]))
    (by simp [BalancePublicInputs.Bytes8.words]) hn
  have aux := value_be_injective_on_checked
    (sub _ cw (by intro y hy; simp [Withdrawal.words, hy]))
    (sub _ cv (by intro y hy; simp [Withdrawal.words, hy]))
    (by simp [BalancePublicInputs.Bytes8.words]) hx
  apply withdrawal_encoding_injective
  simp only [Withdrawal.words, rec, ht, amt, nul, aux]

/-! ## Recipient tag, nullifier preimage, Bytes32/HashOut conversions -/

/-- `calculate_recipient_from_address`: zero padding, byte 0 = ADDRESS_TAG,
    bytes 12..31 = address. -/
def recipientOfAddress (a : Address) : Bytes8 :=
  ⟨addressTagWord, 0, 0, a.a0, a.a1, a.a2, a.a3, a.a4⟩

structure Tx where
  transferTreeRoot : Root
  nonce : Nat
  deriving DecidableEq, Repr

def Tx.words (t : Tx) : List Nat := t.transferTreeRoot.words ++ [t.nonce]

structure TxV2 where
  txClass : Nat
  transferTreeRoot : Root
  nonce : Nat
  channelActionRoot : Root
  deriving DecidableEq, Repr

/-- `TxV2::default()` used by `set_witness` when no typed tx is supplied. -/
def TxV2.default : TxV2 :=
  ⟨userTransferClass, BalancePublicInputs.Root.zero, 0, BalancePublicInputs.Root.zero⟩

structure Transfer where
  recipient : Bytes8
  tokenIndex : Nat
  amount : Bytes8
  auxData : Bytes8
  deriving DecidableEq, Repr

/-- `Transfer::to_u64_vec`: 8 + 1 + 8 + 8 = 25 words. -/
def Transfer.words (t : Transfer) : List Nat :=
  t.recipient.words ++ [t.tokenIndex] ++ t.amount.words ++ t.auxData.words

/-- `SettledTransfer::to_u64_vec`: transfer, then `from` channel id,
    `transfer_index`, `nonce` (F-WD-2: the sender nonce, not a block number). -/
def settledTransferWords (t : Transfer) (channel transferIndex nonce : Nat) : List Nat :=
  t.words ++ [channel, transferIndex, nonce]

theorem transfer_words_length (t : Transfer) : t.words.length = 25 := by
  simp [Transfer.words, BalancePublicInputs.Bytes8.words]

theorem settled_transfer_words_length (t : Transfer) (c i n : Nat) :
    (settledTransferWords t c i n).length = 28 := by
  simp [settledTransferWords, transfer_words_length]

theorem settled_words_bind_transfer_channel_index_nonce {t u : Transfer} {c d i j n m : Nat}
    (same : settledTransferWords t c i n = settledTransferWords u d j m) :
    t = u ∧ c = d ∧ i = j ∧ n = m := by
  obtain ⟨⟨r0,r1,r2,r3,r4,r5,r6,r7⟩, tk, ⟨a0,a1,a2,a3,a4,a5,a6,a7⟩, ⟨x0,x1,x2,x3,x4,x5,x6,x7⟩⟩ := t
  obtain ⟨⟨s0,s1,s2,s3,s4,s5,s6,s7⟩, uk, ⟨b0,b1,b2,b3,b4,b5,b6,b7⟩, ⟨y0,y1,y2,y3,y4,y5,y6,y7⟩⟩ := u
  simp only [settledTransferWords, Transfer.words, BalancePublicInputs.Bytes8.words,
    List.cons_append, List.nil_append, List.cons.injEq, Transfer.mk.injEq,
    BalancePublicInputs.Bytes8.mk.injEq, and_true, and_assoc] at same ⊢
  exact same

/-- `From<PoseidonHashOut> for Bytes32`: each 64-bit element becomes
    `[high, low]` 32-bit limbs. -/
def bytes32OfHashOut (r : Root) : Bytes8 :=
  ⟨r.a / wordBase, r.a % wordBase, r.b / wordBase, r.b % wordBase,
    r.c / wordBase, r.c % wordBase, r.d / wordBase, r.d % wordBase⟩

/-- `Bytes32::reduce_to_hash_out` (native, plain u64 arithmetic) and the
    circuit `reduce_to_hash_out` before any canonicity check. -/
def reduceToHashOut (b : Bytes8) : Root :=
  ⟨b.a * wordBase + b.b, b.c * wordBase + b.d, b.e * wordBase + b.f, b.g * wordBase + b.h⟩

/-- What `Bytes32Target::to_hash_out` enforces (TODO-2 fix at line 477):
    every limb is a 32-bit value and every recombined element is a canonical
    Goldilocks representative. -/
def CanonicalBytes32 (b : Bytes8) : Prop :=
  (∀ x ∈ b.words, x < wordBase) ∧ ∀ x ∈ (reduceToHashOut b).words, x < goldilocks

theorem reduce_of_split (r : Root) : reduceToHashOut (bytes32OfHashOut r) = r := by
  have key : ∀ n : Nat, n / wordBase * wordBase + n % wordBase = n := by
    intro n
    rw [Nat.mul_comm (n / wordBase) wordBase]
    exact Nat.div_add_mod n wordBase
  obtain ⟨a, b, c, d⟩ := r
  simp only [reduceToHashOut, bytes32OfHashOut, BalancePublicInputs.Root.mk.injEq]
  exact ⟨key a, key b, key c, key d⟩

theorem canonical_reduction_injective {b c : Bytes8} (hb : CanonicalBytes32 b) (hc : CanonicalBytes32 c)
    (same : reduceToHashOut b = reduceToHashOut c) : b = c := by
  obtain ⟨b0,b1,b2,b3,b4,b5,b6,b7⟩ := b
  obtain ⟨c0,c1,c2,c3,c4,c5,c6,c7⟩ := c
  have l := hb.1
  have m := hc.1
  simp only [BalancePublicInputs.Bytes8.words, List.mem_cons, List.mem_singleton, forall_eq_or_imp,
    forall_eq, List.not_mem_nil, false_imp_iff, and_true, wordBase] at l m
  simp only [reduceToHashOut, wordBase, BalancePublicInputs.Root.mk.injEq] at same
  simp only [BalancePublicInputs.Bytes8.mk.injEq]
  omega

theorem split_of_canonical_reduction {b : Bytes8} (hb : CanonicalBytes32 b) :
    bytes32OfHashOut (reduceToHashOut b) = b := by
  obtain ⟨b0,b1,b2,b3,b4,b5,b6,b7⟩ := b
  have l := hb.1
  simp only [BalancePublicInputs.Bytes8.words, List.mem_cons, List.mem_singleton, forall_eq_or_imp,
    forall_eq, List.not_mem_nil, false_imp_iff, and_true, wordBase] at l
  simp only [bytes32OfHashOut, reduceToHashOut, wordBase, BalancePublicInputs.Bytes8.mk.injEq]
  omega

/-! ## Witness components (fields actually read by this file) -/

structure SendLeaf where
  prev : Nat
  cur : Nat
  txTreeRoot : Bytes8
  deriving DecidableEq, Repr

structure AccountState (Path Leaf : Type) where
  channelId : Nat
  accountTreeRoot : Root
  sendLeaf : SendLeaf
  sendLeafIndex : Nat
  sendMerkleProof : Path
  channelLeaf : Leaf
  userMerkleProof : Path

structure TransferWitness (Path : Type) where
  transferTreeRoot : Root
  transfer : Transfer
  transferIndex : Nat
  transferMerkleProof : Path

/-- Opaque dependencies. `balanceKey` is `balance_vd.verifier_only` captured at
    `SingleWithdawalCircuit::new`; `balanceVerify` is plonky2 verification
    under that same key; every Merkle `verify` is the gadget/native result on
    the concrete (leaf, index, root) it was called with. -/
structure Environment (Proof Path Leaf : Type) where
  capCount : Nat
  balanceKey : VerifierData
  balanceVerify : Proof → List Nat → Bool
  hashInputs : List Nat → Root
  updateRoot : UpdatePublicState.RootCall
  sentTxVerify : Path → Tx → Nat → PrivateState.Hash4 → Bool
  txVerify : Path → Tx → Nat → Root → Bool
  txV2Verify : Path → TxV2 → Nat → Root → Bool
  transferVerify : Path → Transfer → Nat → Root → Bool
  accountVerify : AccountState Path Leaf → Bool

structure Witness (Proof Path Leaf : Type) where
  balanceProof : Proof
  balancePis : List Nat
  privateState : PrivateState.State
  updatePublicState : Update
  accountState : AccountState Path Leaf
  txMerkleProof : Path
  txV2MerkleProof : Option Path
  txV2 : Option TxV2
  tx : Tx
  sentTxMerkleProof : Path
  transferWitness : TransferWitness Path

/-- `check_cyclic_proof_verifier_data`: the trailing verifier-data limbs of the
    submitted proof must equal the fixed balance key. -/
def verifierTail (count : Nat) (pis : List Nat) : List Nat :=
  pis.drop (pis.length - BalancePublicInputs.verifierLength count)
def checkCyclicVerifierData (count : Nat) (own : VerifierData) (pis : List Nat) : Bool :=
  verifierTail count pis == own.words

def privateCommitment {Proof Path Leaf : Type} (e : Environment Proof Path Leaf)
    (s : PrivateState.State) : Root :=
  e.hashInputs (PrivateState.words s)

def hash4OfRoot (r : Root) : PrivateState.Hash4 := ⟨r.a, r.b, r.c, r.d⟩

theorem private_commitment_is_private_state_commitment {Proof Path Leaf : Type}
    (e : Environment Proof Path Leaf) (s : PrivateState.State) :
    hash4OfRoot (privateCommitment e s) =
      PrivateState.commitment (fun xs => hash4OfRoot (e.hashInputs xs)) s := rfl

def nullifierOf {Proof Path Leaf : Type} (e : Environment Proof Path Leaf) (t : Transfer)
    (channel transferIndex nonce : Nat) : Bytes8 :=
  bytes32OfHashOut (e.hashInputs (settledTransferWords t channel transferIndex nonce))

/-! ## Native admission: `SingleWithdawalWitness::to_public_inputs` -/

inductive Error where
  | balanceProofVerification (reason : String)
  | balancePublicInputs
  | privateStateCommitmentMismatch (expected actual : Root)
  | txMerkleProof
  | txV2MerkleProof
  | transferWitness
  | invalidRecipient (reason : String)
  | inconsistentWitness (reason : String)
  | accountState
  | updatePublicState
  | balancePublicStateMismatch
  deriving DecidableEq, Repr

abbrev Result (α : Type) := Except Error α

def require (condition : Bool) (error : Error) : Result Unit :=
  if condition then .ok () else .error error

def lift {ε α : Type} (r : Except ε α) (error : Error) : Result α :=
  match r with
  | .ok a => .ok a
  | .error _ => .error error

/-- `extract_address_from_recipient`: tag byte, then the canonical-form
    round trip (bytes 1..11 must be zero). -/
def extractAddress (r : Bytes8) : Result Address :=
  if r.a / 2 ^ 24 ≠ addressTag then .error (.invalidRecipient "Invalid recipient tag") else
  if r ≠ recipientOfAddress ⟨r.d, r.e, r.f, r.g, r.h⟩ then
    .error (.invalidRecipient "non-canonical ADDRESS_TAG recipient: bytes 1..11 must be zero")
  else .ok ⟨r.d, r.e, r.f, r.g, r.h⟩

/-- Lines 325-366: typed tx path (both supplied) or legacy path (neither);
    a half-supplied pair is rejected. -/
def verifyTxInclusion {Proof Path Leaf : Type} (e : Environment Proof Path Leaf)
    (w : Witness Proof Path Leaf) (channelId : Nat) (txTreeRoot : Root) : Result Unit :=
  match w.txV2, w.txV2MerkleProof with
  | some txV2, some proof => do
    require (e.txV2Verify proof txV2 channelId txTreeRoot) .txV2MerkleProof
    require (txV2.txClass == userTransferClass)
      (.inconsistentWitness "withdrawal tx_v2 must be TxClass::UserTransfer")
    require (txV2.channelActionRoot == BalancePublicInputs.Root.zero)
      (.inconsistentWitness "withdrawal tx_v2 must have zero channel_action_root")
    require (txV2.transferTreeRoot == w.tx.transferTreeRoot)
      (.inconsistentWitness "tx_v2 transfer tree root mismatch")
    require (txV2.nonce == w.tx.nonce) (.inconsistentWitness "tx_v2 nonce mismatch")
  | none, none =>
    require (e.txVerify w.txMerkleProof w.tx channelId txTreeRoot) .txMerkleProof
  | some _, none =>
    .error (.inconsistentWitness "tx_v2 and tx_v2_merkle_proof must be provided together")
  | none, some _ =>
    .error (.inconsistentWitness "tx_v2 and tx_v2_merkle_proof must be provided together")

def toPublicInputs {Proof Path Leaf : Type} (e : Environment Proof Path Leaf)
    (w : Witness Proof Path Leaf) : Result PublicInputs := do
  require (checkCyclicVerifierData e.capCount e.balanceKey w.balancePis)
    (.balanceProofVerification "cyclic verifier data check failed")
  require (e.balanceVerify w.balanceProof w.balancePis)
    (.balanceProofVerification "verification failed")
  let full ← lift (BalancePublicInputs.fullFromNative pure e.capCount w.balancePis) .balancePublicInputs
  let pis := full.pis
  let channelId := pis.channelId
  let commitment := privateCommitment e w.privateState
  require (pis.privateCommitment == commitment)
    (.privateStateCommitmentMismatch pis.privateCommitment commitment)
  lift (UpdatePublicState.nativeVerify e.updateRoot w.updatePublicState) .updatePublicState
  require (w.updatePublicState.oldState == pis.publicState) .balancePublicStateMismatch
  let publicState := w.updatePublicState.newState
  require (e.sentTxVerify w.sentTxMerkleProof w.tx w.tx.nonce w.privateState.sentTxRoot) .txMerkleProof
  require (w.transferWitness.transferTreeRoot == w.tx.transferTreeRoot)
    (.inconsistentWitness "transfer tree root mismatch")
  require (e.transferVerify w.transferWitness.transferMerkleProof w.transferWitness.transfer
    w.transferWitness.transferIndex w.transferWitness.transferTreeRoot) .transferWitness
  require (w.accountState.channelId == channelId)
    (.inconsistentWitness "account state user != balance proof user")
  require (w.accountState.accountTreeRoot == publicState.accountRoot)
    (.inconsistentWitness "user tree root mismatch")
  require (e.accountVerify w.accountState) .accountState
  let txTreeRoot := reduceToHashOut w.accountState.sendLeaf.txTreeRoot
  verifyTxInclusion e w channelId txTreeRoot
  let transfer := w.transferWitness.transfer
  let recipient ← extractAddress transfer.recipient
  let nullifier := nullifierOf e transfer channelId w.transferWitness.transferIndex w.tx.nonce
  pure ⟨publicState, ⟨recipient, transfer.tokenIndex, transfer.amount, nullifier, transfer.auxData⟩⟩

/-! ### Except helpers (copied pattern from ChannelStateUpdate) -/

theorem require_ok_iff (condition : Bool) (error : Error) :
    require condition error = .ok () ↔ condition = true := by
  cases condition <;> simp [require]
theorem lift_ok_iff {ε α : Type} (r : Except ε α) (error : Error) (value : α) :
    lift r error = .ok value ↔ r = .ok value := by
  cases r <;> simp [lift]
theorem bind_ok_iff {α β : Type} (r : Result α) (f : α → Result β) (value : β) :
    (r >>= f) = .ok value ↔ ∃ x, r = .ok x ∧ f x = .ok value := by
  cases r <;> simp [Bind.bind, Except.bind]
theorem unit_bind_ok_iff {α : Type} (r : Result Unit) (s : Result α) (value : α) :
    (r >>= fun _ => s) = .ok value ↔ r = .ok () ∧ s = .ok value := by
  cases r with
  | error error => simp [Bind.bind, Except.bind]
  | ok value => cases value; simp [Bind.bind, Except.bind]
theorem exists_unit (p : Unit → Prop) : (∃ x, p x) ↔ p () := by
  constructor
  · rintro ⟨⟨⟩, h⟩; exact h
  · intro h; exact ⟨(), h⟩
theorem pure_ok_iff {α : Type} (x value : α) : (pure x : Result α) = .ok value ↔ x = value := by
  simp [pure, Except.pure]

theorem extract_address_ok_iff (r : Bytes8) (a : Address) :
    extractAddress r = .ok a ↔ r = recipientOfAddress a := by
  constructor
  · intro h
    unfold extractAddress at h
    split at h
    · exact absurd h (by simp)
    split at h
    · exact absurd h (by simp)
    rename_i canonical
    simp only [Except.ok.injEq] at h
    subst h
    exact Decidable.of_not_not canonical
  · rintro rfl
    obtain ⟨a0,a1,a2,a3,a4⟩ := a
    simp [extractAddress, recipientOfAddress, addressTagWord, addressTag]

theorem tx_inclusion_ok_iff {Proof Path Leaf : Type} (e : Environment Proof Path Leaf)
    (w : Witness Proof Path Leaf) (channelId : Nat) (txTreeRoot : Root) :
    verifyTxInclusion e w channelId txTreeRoot = .ok () ↔
      ((∃ txV2 proof, w.txV2 = some txV2 ∧ w.txV2MerkleProof = some proof ∧
        e.txV2Verify proof txV2 channelId txTreeRoot = true ∧ txV2.txClass = userTransferClass ∧
        txV2.channelActionRoot = BalancePublicInputs.Root.zero ∧
        txV2.transferTreeRoot = w.tx.transferTreeRoot ∧ txV2.nonce = w.tx.nonce) ∨
      (w.txV2 = none ∧ w.txV2MerkleProof = none ∧
        e.txVerify w.txMerkleProof w.tx channelId txTreeRoot = true)) := by
  rcases hv : w.txV2 with _ | txV2
  · rcases hp : w.txV2MerkleProof with _ | proof
    · simp [verifyTxInclusion, hv, hp, require_ok_iff]
    · simp [verifyTxInclusion, hv, hp]
  · rcases hp : w.txV2MerkleProof with _ | proof
    · simp [verifyTxInclusion, hv, hp]
    · simp only [verifyTxInclusion, hv, hp, unit_bind_ok_iff, require_ok_iff, beq_iff_eq,
        Option.some.injEq, reduceCtorEq, false_and, and_false, or_false]
      constructor
      · rintro ⟨a, b, c, d, f⟩
        exact ⟨txV2, proof, rfl, rfl, a, b, c, d, f⟩
      · rintro ⟨x, y, hx, hy, a, b, c, d, f⟩
        cases hx; cases hy
        exact ⟨a, b, c, d, f⟩

/-- Everything native admission checked, in source order. `full` is the parsed
    balance public inputs; the output is assembled from `update_public_state.new`
    and the opened transfer. -/
theorem native_admission_facts {Proof Path Leaf : Type} {e : Environment Proof Path Leaf}
    {w : Witness Proof Path Leaf} {p : PublicInputs} (accepted : toPublicInputs e w = .ok p) :
    checkCyclicVerifierData e.capCount e.balanceKey w.balancePis = true ∧
    e.balanceVerify w.balanceProof w.balancePis = true ∧
    ∃ full : BalancePublicInputs.FullInputs,
      BalancePublicInputs.fullFromNative pure e.capCount w.balancePis = .ok full ∧
      full.pis.privateCommitment = privateCommitment e w.privateState ∧
      UpdatePublicState.nativeVerify e.updateRoot w.updatePublicState = .ok () ∧
      w.updatePublicState.oldState = full.pis.publicState ∧
      e.sentTxVerify w.sentTxMerkleProof w.tx w.tx.nonce w.privateState.sentTxRoot = true ∧
      w.transferWitness.transferTreeRoot = w.tx.transferTreeRoot ∧
      e.transferVerify w.transferWitness.transferMerkleProof w.transferWitness.transfer
        w.transferWitness.transferIndex w.transferWitness.transferTreeRoot = true ∧
      w.accountState.channelId = full.pis.channelId ∧
      w.accountState.accountTreeRoot = w.updatePublicState.newState.accountRoot ∧
      e.accountVerify w.accountState = true ∧
      verifyTxInclusion e w full.pis.channelId (reduceToHashOut w.accountState.sendLeaf.txTreeRoot) = .ok () ∧
      ∃ recipient : Address, extractAddress w.transferWitness.transfer.recipient = .ok recipient ∧
        p = ⟨w.updatePublicState.newState,
          ⟨recipient, w.transferWitness.transfer.tokenIndex, w.transferWitness.transfer.amount,
            nullifierOf e w.transferWitness.transfer full.pis.channelId
              w.transferWitness.transferIndex w.tx.nonce,
            w.transferWitness.transfer.auxData⟩⟩ := by
  simp only [toPublicInputs, unit_bind_ok_iff, bind_ok_iff, exists_unit, require_ok_iff,
    lift_ok_iff, pure_ok_iff, beq_iff_eq] at accepted
  obtain ⟨cyc, ver, full, hfull, commit, upd, old, sent, troot, tver, chan, aroot, acc, incl,
    recipient, hr, hp⟩ := accepted
  exact ⟨cyc, ver, full, hfull, commit, upd, old, sent, troot, tver, chan, aroot, acc, incl,
    recipient, hr, hp.symm⟩

/-! ### Fund-safety corollaries of native admission -/

theorem native_output_state_is_updated_state {Proof Path Leaf : Type} {e : Environment Proof Path Leaf}
    {w : Witness Proof Path Leaf} {p : PublicInputs} (accepted : toPublicInputs e w = .ok p) :
    p.publicState = w.updatePublicState.newState := by
  obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, hp⟩ := native_admission_facts accepted
  rw [hp]

theorem native_balance_proof_is_checked_against_fixed_key {Proof Path Leaf : Type}
    {e : Environment Proof Path Leaf} {w : Witness Proof Path Leaf} {p : PublicInputs}
    (accepted : toPublicInputs e w = .ok p) :
    verifierTail e.capCount w.balancePis = e.balanceKey.words ∧
    e.balanceVerify w.balanceProof w.balancePis = true := by
  obtain ⟨cyc, ver, _⟩ := native_admission_facts accepted
  exact ⟨by simpa [checkCyclicVerifierData] using cyc, ver⟩

/-- The withdrawal's (recipient, token, amount, aux) are copied from the
    transfer that is opened under `tx.transfer_tree_root`, where `tx` is opened
    at index `tx.nonce` in the sent-tx tree of the private state whose
    commitment the verified balance proof exposes. -/
theorem native_withdrawal_comes_from_sent_transfer {Proof Path Leaf : Type}
    {e : Environment Proof Path Leaf} {w : Witness Proof Path Leaf} {p : PublicInputs}
    (accepted : toPublicInputs e w = .ok p) :
    ∃ full : BalancePublicInputs.FullInputs,
      BalancePublicInputs.fullFromNative pure e.capCount w.balancePis = .ok full ∧
      full.pis.privateCommitment = e.hashInputs (PrivateState.words w.privateState) ∧
      e.sentTxVerify w.sentTxMerkleProof w.tx w.tx.nonce w.privateState.sentTxRoot = true ∧
      e.transferVerify w.transferWitness.transferMerkleProof w.transferWitness.transfer
        w.transferWitness.transferIndex w.tx.transferTreeRoot = true ∧
      w.transferWitness.transfer.recipient = recipientOfAddress p.withdrawal.recipient ∧
      p.withdrawal.tokenIndex = w.transferWitness.transfer.tokenIndex ∧
      p.withdrawal.amount = w.transferWitness.transfer.amount ∧
      p.withdrawal.auxData = w.transferWitness.transfer.auxData := by
  obtain ⟨_, _, full, hfull, commit, _, _, sent, troot, tver, _, _, _, _, r, hr, hp⟩ :=
    native_admission_facts accepted
  subst hp
  refine ⟨full, hfull, commit, sent, ?_, (extract_address_ok_iff _ _).mp hr, rfl, rfl, rfl⟩
  rw [← troot]; exact tver

/-- Block anchoring: the account state carries the balance channel, its
    account root is the OUTPUT public state's, and the sender's tx is opened at
    index `channel_id` under the reduced `send_leaf.tx_tree_root`. -/
theorem native_tx_is_anchored_to_account_state {Proof Path Leaf : Type}
    {e : Environment Proof Path Leaf} {w : Witness Proof Path Leaf} {p : PublicInputs}
    (accepted : toPublicInputs e w = .ok p) :
    ∃ full : BalancePublicInputs.FullInputs,
      BalancePublicInputs.fullFromNative pure e.capCount w.balancePis = .ok full ∧
      w.accountState.channelId = full.pis.channelId ∧
      w.accountState.accountTreeRoot = p.publicState.accountRoot ∧
      e.accountVerify w.accountState = true ∧
      ((∃ txV2 proof, w.txV2 = some txV2 ∧ w.txV2MerkleProof = some proof ∧
        e.txV2Verify proof txV2 full.pis.channelId (reduceToHashOut w.accountState.sendLeaf.txTreeRoot) = true ∧
        txV2.txClass = userTransferClass ∧ txV2.channelActionRoot = BalancePublicInputs.Root.zero ∧
        txV2.transferTreeRoot = w.tx.transferTreeRoot ∧ txV2.nonce = w.tx.nonce) ∨
      (w.txV2 = none ∧ w.txV2MerkleProof = none ∧
        e.txVerify w.txMerkleProof w.tx full.pis.channelId (reduceToHashOut w.accountState.sendLeaf.txTreeRoot) = true)) := by
  obtain ⟨_, _, full, hfull, _, _, _, _, _, _, chan, aroot, acc, incl, r, hr, hp⟩ :=
    native_admission_facts accepted
  subst hp
  exact ⟨full, hfull, chan, aroot, acc, (tx_inclusion_ok_iff e w _ _).mp incl⟩

theorem native_update_binds_balance_state {Proof Path Leaf : Type}
    {e : Environment Proof Path Leaf} {w : Witness Proof Path Leaf} {p : PublicInputs}
    (accepted : toPublicInputs e w = .ok p) :
    ∃ full : BalancePublicInputs.FullInputs,
      BalancePublicInputs.fullFromNative pure e.capCount w.balancePis = .ok full ∧
      w.updatePublicState.oldState = full.pis.publicState ∧
      UpdatePublicState.ValidUpdate e.updateRoot w.updatePublicState ∧
      p.publicState = w.updatePublicState.newState := by
  obtain ⟨_, _, full, hfull, _, upd, old, _, _, _, _, _, _, _, r, hr, hp⟩ :=
    native_admission_facts accepted
  subst hp
  exact ⟨full, hfull, old, (UpdatePublicState.native_verify_iff_local_history _ _).mp upd, rfl⟩

theorem native_nullifier_binds_sender_nonce_and_index {Proof Path Leaf : Type}
    {e : Environment Proof Path Leaf} {w : Witness Proof Path Leaf} {p : PublicInputs}
    (accepted : toPublicInputs e w = .ok p) :
    ∃ full : BalancePublicInputs.FullInputs,
      BalancePublicInputs.fullFromNative pure e.capCount w.balancePis = .ok full ∧
      p.withdrawal.nullifier = bytes32OfHashOut (e.hashInputs (settledTransferWords
        w.transferWitness.transfer full.pis.channelId w.transferWitness.transferIndex w.tx.nonce)) := by
  obtain ⟨_, _, full, hfull, _, _, _, _, _, _, _, _, _, _, r, hr, hp⟩ :=
    native_admission_facts accepted
  subst hp
  exact ⟨full, hfull, rfl⟩

theorem native_half_supplied_tx_v2_is_rejected {Proof Path Leaf : Type}
    {e : Environment Proof Path Leaf} {w : Witness Proof Path Leaf} {p : PublicInputs}
    (accepted : toPublicInputs e w = .ok p) :
    w.txV2.isSome = w.txV2MerkleProof.isSome := by
  obtain ⟨_, _, full, _, _, _, _, _, _, _, _, _, _, incl, _⟩ := native_admission_facts accepted
  rcases (tx_inclusion_ok_iff e w _ _).mp incl with ⟨_, _, hv, hp, _⟩ | ⟨hv, hp, _⟩ <;>
    simp [hv, hp]

theorem native_rejects_non_canonical_recipient {Proof Path Leaf : Type}
    {e : Environment Proof Path Leaf} {w : Witness Proof Path Leaf}
    (bad : ∀ a : Address, w.transferWitness.transfer.recipient ≠ recipientOfAddress a) :
    ∀ p, toPublicInputs e w ≠ .ok p := by
  intro p accepted
  obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, _, r, hr, _⟩ := native_admission_facts accepted
  exact bad r ((extract_address_ok_iff _ _).mp hr)

/-! ## Arbitrary satisfying wire assignment: `SingleWithdawalTarget::new` -/

/-- All wires of the target, after `set_witness` (or adversarially chosen). -/
structure Wires (Proof Path Leaf : Type) where
  balanceProof : Proof
  balancePis : List Nat
  privateState : PrivateState.State
  updatePublicState : Update
  updateWitness : UpdatePublicState.Witness
  accountState : AccountState Path Leaf
  tx : Tx
  txMerkleProof : Path
  useTxV2 : Bool
  txV2MerkleProof : Path
  txV2 : TxV2
  sentTxMerkleProof : Path
  transferWitness : TransferWitness Path

/-- `BalanceFullPublicInputsTarget::from_pis` reads the balance fields from the
    leading limbs of the balance proof's public inputs. -/
def balancePisOf {Proof Path Leaf : Type} (x : Wires Proof Path Leaf) : BalancePis :=
  BalancePublicInputs.readFields x.balancePis

def txTreeRootOf {Proof Path Leaf : Type} (x : Wires Proof Path Leaf) : Root :=
  reduceToHashOut x.accountState.sendLeaf.txTreeRoot

/-- Gate equations of `SingleWithdawalTarget::new` (lines 425-537) plus the
    checked allocations of `TransferWitnessTarget::new(builder, true)`. Each
    Merkle/proof gadget is the environment's opaque result on the exact wires
    it is applied to. -/
structure CircuitGates {Proof Path Leaf : Type} (e : Environment Proof Path Leaf)
    (x : Wires Proof Path Leaf) (p : PublicInputs) : Prop where
  pisLength : BalancePublicInputs.balanceLength + BalancePublicInputs.verifierLength e.capCount ≤
    x.balancePis.length
  keyConnected : checkCyclicVerifierData e.capCount e.balanceKey x.balancePis = true
  proofGadget : e.balanceVerify x.balanceProof x.balancePis = true
  nonceRange : x.tx.nonce < 2 ^ sentTxTreeHeight
  privateCommitment : privateCommitment e x.privateState = (balancePisOf x).privateCommitment
  oldState : x.updatePublicState.oldState = (balancePisOf x).publicState
  updateGates : UpdatePublicState.CircuitGates e.updateRoot x.updatePublicState x.updateWitness
  accountChannel : x.accountState.channelId = (balancePisOf x).channelId
  accountRoot : x.accountState.accountTreeRoot = x.updatePublicState.newState.accountRoot
  accountGadget : e.accountVerify x.accountState = true
  sentTxGadget : e.sentTxVerify x.sentTxMerkleProof x.tx x.tx.nonce x.privateState.sentTxRoot = true
  transferRoot : x.transferWitness.transferTreeRoot = x.tx.transferTreeRoot
  transferChecked : ∀ v ∈ x.transferWitness.transfer.words, v < wordBase
  transferIndexRange : x.transferWitness.transferIndex < 2 ^ transferTreeHeight
  transferGadget : e.transferVerify x.transferWitness.transferMerkleProof x.transferWitness.transfer
    x.transferWitness.transferIndex x.transferWitness.transferTreeRoot = true
  txTreeRootCanonical : CanonicalBytes32 x.accountState.sendLeaf.txTreeRoot
  legacyTxGadget : x.useTxV2 = false →
    e.txVerify x.txMerkleProof x.tx (balancePisOf x).channelId (txTreeRootOf x) = true
  v2TxGadget : x.useTxV2 = true →
    e.txV2Verify x.txV2MerkleProof x.txV2 (balancePisOf x).channelId (txTreeRootOf x) = true
  v2Class : x.useTxV2 = true → x.txV2.txClass = userTransferClass
  v2ActionRoot : x.useTxV2 = true → x.txV2.channelActionRoot = BalancePublicInputs.Root.zero
  v2TransferRoot : x.useTxV2 = true → x.txV2.transferTreeRoot = x.tx.transferTreeRoot
  v2Nonce : x.useTxV2 = true → x.txV2.nonce = x.tx.nonce
  recipientCanonical : x.transferWitness.transfer.recipient = recipientOfAddress p.withdrawal.recipient
  publicStateOut : p.publicState = x.updatePublicState.newState
  tokenOut : p.withdrawal.tokenIndex = x.transferWitness.transfer.tokenIndex
  amountOut : p.withdrawal.amount = x.transferWitness.transfer.amount
  auxOut : p.withdrawal.auxData = x.transferWitness.transfer.auxData
  nullifierOut : p.withdrawal.nullifier = nullifierOf e x.transferWitness.transfer
    (balancePisOf x).channelId x.transferWitness.transferIndex x.tx.nonce

/-- Only primitive gate lowering is unresolved; named in the boundaries. -/
def FieldLowering {Proof Path Leaf Raw : Type} (e : Environment Proof Path Leaf)
    (accepts : Raw → Wires Proof Path Leaf → PublicInputs → Prop) : Prop :=
  ∀ raw x p, accepts raw x p → CircuitGates e x p

theorem gates_output_state_is_updated_state {Proof Path Leaf : Type} {e : Environment Proof Path Leaf}
    {x : Wires Proof Path Leaf} {p : PublicInputs} (g : CircuitGates e x p) :
    p.publicState = x.updatePublicState.newState := g.publicStateOut

theorem gates_balance_proof_is_checked_against_fixed_key {Proof Path Leaf : Type}
    {e : Environment Proof Path Leaf} {x : Wires Proof Path Leaf} {p : PublicInputs}
    (g : CircuitGates e x p) :
    verifierTail e.capCount x.balancePis = e.balanceKey.words ∧
    e.balanceVerify x.balanceProof x.balancePis = true := by
  exact ⟨by simpa [checkCyclicVerifierData] using g.keyConnected, g.proofGadget⟩

theorem gates_withdrawal_comes_from_sent_transfer {Proof Path Leaf : Type}
    {e : Environment Proof Path Leaf} {x : Wires Proof Path Leaf} {p : PublicInputs}
    (g : CircuitGates e x p) :
    (balancePisOf x).privateCommitment = e.hashInputs (PrivateState.words x.privateState) ∧
    e.sentTxVerify x.sentTxMerkleProof x.tx x.tx.nonce x.privateState.sentTxRoot = true ∧
    x.tx.nonce < 2 ^ 32 ∧
    e.transferVerify x.transferWitness.transferMerkleProof x.transferWitness.transfer
      x.transferWitness.transferIndex x.tx.transferTreeRoot = true ∧
    x.transferWitness.transfer.recipient = recipientOfAddress p.withdrawal.recipient ∧
    p.withdrawal.tokenIndex = x.transferWitness.transfer.tokenIndex ∧
    p.withdrawal.amount = x.transferWitness.transfer.amount ∧
    p.withdrawal.auxData = x.transferWitness.transfer.auxData := by
  refine ⟨g.privateCommitment.symm, g.sentTxGadget, g.nonceRange, ?_, g.recipientCanonical,
    g.tokenOut, g.amountOut, g.auxOut⟩
  rw [← g.transferRoot]; exact g.transferGadget

/-- The circuit selects exactly one inclusion path, and the typed path is
    restricted to `UserTransfer` with zero channel-action root and the same
    (transfer root, nonce) as the legacy `tx` wires. -/
theorem gates_tx_is_anchored_to_account_state {Proof Path Leaf : Type}
    {e : Environment Proof Path Leaf} {x : Wires Proof Path Leaf} {p : PublicInputs}
    (g : CircuitGates e x p) :
    x.accountState.channelId = (balancePisOf x).channelId ∧
    x.accountState.accountTreeRoot = p.publicState.accountRoot ∧
    e.accountVerify x.accountState = true ∧
    CanonicalBytes32 x.accountState.sendLeaf.txTreeRoot ∧
    ((x.useTxV2 = false ∧
        e.txVerify x.txMerkleProof x.tx (balancePisOf x).channelId (txTreeRootOf x) = true) ∨
      (x.useTxV2 = true ∧
        e.txV2Verify x.txV2MerkleProof x.txV2 (balancePisOf x).channelId (txTreeRootOf x) = true ∧
        x.txV2.txClass = userTransferClass ∧
        x.txV2.channelActionRoot = BalancePublicInputs.Root.zero ∧
        x.txV2.transferTreeRoot = x.tx.transferTreeRoot ∧ x.txV2.nonce = x.tx.nonce)) := by
  refine ⟨g.accountChannel, by rw [g.publicStateOut]; exact g.accountRoot, g.accountGadget,
    g.txTreeRootCanonical, ?_⟩
  cases h : x.useTxV2
  · exact Or.inl ⟨rfl, g.legacyTxGadget h⟩
  · exact Or.inr ⟨rfl, g.v2TxGadget h, g.v2Class h, g.v2ActionRoot h, g.v2TransferRoot h, g.v2Nonce h⟩

/-- The canonical tx-tree-root bytes are recoverable from the reduced root:
    a prover cannot alias two byte-distinct roots onto one Merkle root wire. -/
theorem gates_tx_tree_root_bytes_are_recoverable {Proof Path Leaf : Type}
    {e : Environment Proof Path Leaf} {x : Wires Proof Path Leaf} {p : PublicInputs}
    (g : CircuitGates e x p) :
    bytes32OfHashOut (txTreeRootOf x) = x.accountState.sendLeaf.txTreeRoot :=
  split_of_canonical_reduction g.txTreeRootCanonical

theorem gates_update_binds_balance_state {Proof Path Leaf : Type}
    {e : Environment Proof Path Leaf} {x : Wires Proof Path Leaf} {p : PublicInputs}
    (g : CircuitGates e x p) :
    x.updatePublicState.oldState = (balancePisOf x).publicState ∧
    UpdatePublicState.nativeVerify e.updateRoot x.updatePublicState = .ok () ∧
    p.publicState = x.updatePublicState.newState :=
  ⟨g.oldState, UpdatePublicState.target_implies_native_local_verification g.updateGates,
    g.publicStateOut⟩

theorem gates_nullifier_binds_sender_nonce_and_index {Proof Path Leaf : Type}
    {e : Environment Proof Path Leaf} {x : Wires Proof Path Leaf} {p : PublicInputs}
    (g : CircuitGates e x p) :
    p.withdrawal.nullifier = bytes32OfHashOut (e.hashInputs (settledTransferWords
      x.transferWitness.transfer (balancePisOf x).channelId x.transferWitness.transferIndex x.tx.nonce)) :=
  g.nullifierOut

theorem gates_withdrawal_is_checked {Proof Path Leaf : Type}
    {e : Environment Proof Path Leaf} {x : Wires Proof Path Leaf} {p : PublicInputs}
    (g : CircuitGates e x p) (stateChecked : ∀ v ∈ p.publicState.words, v < wordBase)
    (nullifierChecked : ∀ v ∈ p.withdrawal.nullifier.words, v < wordBase) :
    ∀ v ∈ p.words, v < wordBase := by
  have t := g.transferChecked
  rw [g.recipientCanonical] at t
  have tok := g.tokenOut
  have amt := g.amountOut
  have aux := g.auxOut
  obtain ⟨ps, ⟨⟨r0,r1,r2,r3,r4⟩, tk, ⟨a0,a1,a2,a3,a4,a5,a6,a7⟩, ⟨n0,n1,n2,n3,n4,n5,n6,n7⟩,
    ⟨x0,x1,x2,x3,x4,x5,x6,x7⟩⟩⟩ := p
  simp only [Transfer.words, recipientOfAddress, BalancePublicInputs.Bytes8.words, Address.words,
    List.mem_append, List.mem_cons, List.mem_singleton, List.not_mem_nil, or_false] at t
  simp only at tok amt aux
  subst tok amt aux
  simp only [BalancePublicInputs.Bytes8.words, List.mem_cons, List.mem_singleton, List.not_mem_nil,
    or_false] at nullifierChecked
  intro v hv
  simp only [PublicInputs.words, Withdrawal.words, Address.words, BalancePublicInputs.Bytes8.words,
    List.mem_append, List.mem_cons, List.mem_singleton, List.not_mem_nil, or_false] at hv
  rcases hv with hv | hv
  · exact stateChecked v hv
  · rcases hv with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
      rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
    all_goals first
      | exact t _ (by simp)
      | exact nullifierChecked _ (by simp)

/-! ## Nullifier binding (representation, not hash injectivity) -/

def HashBindingAt {α β : Type} (hash : α → β) (a b : α) : Prop := hash a = hash b → a = b

theorem same_nullifier_inputs_have_same_nullifier {Proof Path Leaf : Type}
    (e : Environment Proof Path Leaf) {t u : Transfer} {c d i j n m : Nat}
    (ht : t = u) (hc : c = d) (hi : i = j) (hn : n = m) :
    nullifierOf e t c i n = nullifierOf e u d j m := by
  subst ht hc hi hn; rfl

/-- Two admitted withdrawals with equal nullifiers, under a concrete binding
    premise on the two compared Poseidon preimages and canonical (< 2^64)
    hash elements, spend the same (transfer, channel, index, nonce). -/
theorem equal_nullifiers_bind_same_spend {Proof Path Leaf : Type}
    {e : Environment Proof Path Leaf} {t u : Transfer} {c d i j n m : Nat}
    (same : nullifierOf e t c i n = nullifierOf e u d j m)
    (binding : HashBindingAt e.hashInputs (settledTransferWords t c i n) (settledTransferWords u d j m)) :
    t = u ∧ c = d ∧ i = j ∧ n = m := by
  apply settled_words_bind_transfer_channel_index_nonce
  apply binding
  unfold nullifierOf at same
  have := congrArg reduceToHashOut same
  simpa only [reduce_of_split] using this

/-! ## `set_witness`, `SingleWithdawalCircuit::new`, `prove` -/

/-- `set_witness` (lines 555-586): `use_tx_v2 = tx_v2.is_some()`, dummy typed
    proof / default `TxV2` when absent. -/
def Witness.toWires {Proof Path Leaf : Type} (dummyTxV2Proof : Path)
    (updateWitness : UpdatePublicState.Witness) (w : Witness Proof Path Leaf) : Wires Proof Path Leaf :=
  { balanceProof := w.balanceProof, balancePis := w.balancePis, privateState := w.privateState,
    updatePublicState := w.updatePublicState, updateWitness := updateWitness,
    accountState := w.accountState, tx := w.tx, txMerkleProof := w.txMerkleProof,
    useTxV2 := w.txV2.isSome, txV2MerkleProof := w.txV2MerkleProof.getD dummyTxV2Proof,
    txV2 := w.txV2.getD TxV2.default, sentTxMerkleProof := w.sentTxMerkleProof,
    transferWitness := w.transferWitness }

/-- `SingleWithdawalCircuit::new` registers `public_inputs.to_vec()`: the 15
    public-state wires then the 30 withdrawal wires, nothing else. -/
def registeredPublicInputs (t : PublicInputs) : List Nat := t.words

theorem registered_public_input_count (t : PublicInputs) :
    (registeredPublicInputs t).length = 45 := by
  rw [registeredPublicInputs, public_inputs_words_length]; rfl

inductive CircuitError where
  | witness (error : Error)
  | failedToProve (message : String)
  deriving DecidableEq, Repr

/-- `prove` (lines 632-643): native admission first, then witness filling,
    then the opaque plonky2 prover on the filled wires and public inputs. -/
def prove {Proof Path Leaf Out : Type} (e : Environment Proof Path Leaf)
    (prover : Wires Proof Path Leaf → PublicInputs → Except String Out)
    (dummyTxV2Proof : Path) (updateWitness : UpdatePublicState.Witness)
    (w : Witness Proof Path Leaf) : Except CircuitError Out :=
  match toPublicInputs e w with
  | .error error => .error (.witness error)
  | .ok p =>
    match prover (w.toWires dummyTxV2Proof updateWitness) p with
    | .error message => .error (.failedToProve message)
    | .ok out => .ok out

theorem prove_requires_native_admission {Proof Path Leaf Out : Type} {e : Environment Proof Path Leaf}
    {prover : Wires Proof Path Leaf → PublicInputs → Except String Out} {dummy : Path}
    {uw : UpdatePublicState.Witness} {w : Witness Proof Path Leaf} {out : Out}
    (proved : prove e prover dummy uw w = .ok out) :
    ∃ p, toPublicInputs e w = .ok p ∧ prover (w.toWires dummy uw) p = .ok out := by
  unfold prove at proved
  split at proved
  · exact absurd proved (by simp)
  · rename_i p hp
    split at proved
    · exact absurd proved (by simp)
    · rename_i o ho
      simp only [Except.ok.injEq] at proved
      subst proved
      exact ⟨p, hp, ho⟩

theorem prove_rejected_witness_never_reaches_prover {Proof Path Leaf Out : Type}
    (e : Environment Proof Path Leaf) (prover : Wires Proof Path Leaf → PublicInputs → Except String Out)
    (dummy : Path) (uw : UpdatePublicState.Witness) (w : Witness Proof Path Leaf) (error : Error)
    (rejected : toPublicInputs e w = .error error) :
    prove e prover dummy uw w = .error (.witness error) := by
  simp [prove, rejected]

theorem native_fill_selects_typed_path_iff_supplied {Proof Path Leaf : Type} (dummy : Path)
    (uw : UpdatePublicState.Witness) (w : Witness Proof Path Leaf) :
    (w.toWires dummy uw).useTxV2 = w.txV2.isSome := rfl

/-! ## Positive example: one legacy-path withdrawal admitted natively -/

def exampleRoot : Root := ⟨11, 12, 13, 14⟩
def exampleAccountRoot : Root := ⟨21, 22, 23, 24⟩
def examplePublicState : PublicState :=
  ⟨7, 0, 1000, exampleAccountRoot, ⟨31, 32, 33, 34⟩, ⟨41, 42, 43, 44⟩⟩
def examplePrivateState : PrivateState.State :=
  ⟨⟨1, 2, 3, 4⟩, ⟨5, 6, 7, 8⟩, ⟨9, 10, 11, 12⟩, PrivateState.zeroHash, 3, ⟨13, 14, 15, 16⟩⟩
/-- A stand-in hash: (length, first word, 0, 0). Only its results matter. -/
def exampleHash (xs : List Nat) : Root := ⟨xs.length, xs.headD 0, 0, 0⟩
def exampleKey : VerifierData := ⟨⟨101, 102, 103, 104⟩, []⟩
def exampleBalancePis : BalancePis :=
  ⟨1, examplePublicState, 0, exampleHash (PrivateState.words examplePrivateState),
    BalancePublicInputs.Bytes8.zero⟩
def exampleAddress : Address := ⟨51, 52, 53, 54, 55⟩
def exampleTransfer : Transfer :=
  ⟨recipientOfAddress exampleAddress, 0, ⟨0, 0, 0, 0, 0, 0, 0, 3⟩, BalancePublicInputs.Bytes8.zero⟩
def exampleTx : Tx := ⟨exampleRoot, 3⟩
def exampleAccountState : AccountState Unit Unit :=
  ⟨1, exampleAccountRoot, ⟨5, 7, ⟨0, 61, 0, 62, 0, 63, 0, 64⟩⟩, 0, (), (), ()⟩

def exampleEnv : Environment Unit Unit Unit :=
  { capCount := 0, balanceKey := exampleKey, balanceVerify := fun _ _ => true,
    hashInputs := exampleHash, updateRoot := fun _ _ _ => BalancePublicInputs.Root.zero,
    sentTxVerify := fun _ _ _ _ => true, txVerify := fun _ _ _ _ => true,
    txV2Verify := fun _ _ _ _ => true, transferVerify := fun _ _ _ _ => true,
    accountVerify := fun _ => true }

def exampleWitness : Witness Unit Unit Unit :=
  { balanceProof := (), balancePis := exampleBalancePis.words ++ exampleKey.words,
    privateState := examplePrivateState,
    updatePublicState := ⟨examplePublicState, examplePublicState, UpdatePublicState.dummyProof⟩,
    accountState := exampleAccountState, txMerkleProof := (), txV2MerkleProof := none, txV2 := none,
    tx := exampleTx, sentTxMerkleProof := (),
    transferWitness := ⟨exampleRoot, exampleTransfer, 0, ()⟩ }

def exampleExpected : PublicInputs :=
  ⟨examplePublicState,
    ⟨exampleAddress, 0, ⟨0, 0, 0, 0, 0, 0, 0, 3⟩,
      bytes32OfHashOut (exampleHash (settledTransferWords exampleTransfer 1 0 3)),
      BalancePublicInputs.Bytes8.zero⟩⟩

theorem normal_witness_is_admitted : toPublicInputs exampleEnv exampleWitness = .ok exampleExpected := by
  decide

theorem normal_nullifier_limbs :
    exampleExpected.withdrawal.nullifier = ⟨0, 28, 0, addressTagWord, 0, 0, 0, 0⟩ := by
  decide

theorem normal_public_inputs_native_roundtrip :
    fromNative exampleExpected.words = .ok exampleExpected := by
  decide

theorem normal_rollup_leaf :
    rollupLeaf exampleExpected.withdrawal =
      ⟨addressValue exampleAddress, 0, 3, bytes32Value ⟨0, 28, 0, addressTagWord, 0, 0, 0, 0⟩, 0⟩ := by
  decide

theorem normal_half_supplied_pair_is_rejected :
    ∀ p, toPublicInputs exampleEnv { exampleWitness with txV2 := some TxV2.default } ≠ .ok p := by
  intro p accepted
  have := native_half_supplied_tx_v2_is_rejected accepted
  simp [exampleWitness] at this

end Zkp.Implementation.SingleWithdrawalCircuit
