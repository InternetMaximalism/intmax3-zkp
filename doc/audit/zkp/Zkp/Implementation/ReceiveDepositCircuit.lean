import Zkp.Implementation.UpdatePrivateState
import Zkp.Implementation.UpdatePublicState

/-!
# ReceiveDepositCircuit: crediting an L1 deposit into a balance statement

Handwritten semantic model of src/circuits/balance/receive_deposit_circuit.rs
(733 lines; production 1–515, tests 517–733 read but not translated), together
with the callee control flow of `DepositWitness::verify` (deposit_witness.rs
76–100), `Deposit::to_u64_vec` / `nullifier` (deposit.rs 68–98),
`calculate_recipient_from_user_id` (recipient.rs 29–37) and
`U63Target::enforce_ge` / `conditional_ge` / `conditional_gt` (u63.rs 225–274).
This is NOT a refinement proof of the Rust / plonky2 code: every theorem below
is about the Lean model, and the source-to-model correspondence is a line-map
claim only.

Two separate objects are modeled:

* `nativeToPublicInputs` — `ReceiveDepositWitness::to_public_inputs`, the
  native admission helper that `prove` runs before filling the witness. It
  parses the previous balance statement with the real 29-word native decoder,
  then runs the source's guards in source order with source error precedence.
  It never verifies a proof, never re-derives the private-state update, and
  trusts the supplied `new_private_state`
  (`native_trusts_supplied_new_private_state`, `native_ignores_gadget_semantics`).
* `CircuitGates` — the constraints `ReceiveDepositTarget::new` lays down on an
  ARBITRARY satisfying witness. The private-state gadget is the imported
  `UpdatePrivateState.CircuitGates` (so the credited leaf is exactly
  `prev + amount` through the per-limb AddGates relation on the deposit's
  token), the public-state update is the imported
  `UpdatePublicState.CircuitGates`, the deposit nullifier is the Poseidon
  callback applied to the full 32-word `Deposit::to_u64_vec` preimage
  (deposit index and block number included), the recipient is the Poseidon
  callback over `[USER_ID_DOMAIN, channel, salt]` with the tag byte forced to
  `USER_ID_TAG`, and the settled-tx chain is unconditionally
  `keccak([0x494d5443, chain, nullifier])`. The balance-proof verifier, the
  deposit-tree Merkle opening (against the NEW public state's deposit root at
  `deposit_index`), and the account-state openings are OPAQUE acceptance
  premises in `Environment`.

Block-number comparisons are NOT read as integer orderings. `U63Target::
enforce_ge(self, lower)` is `range_check(self - lower, 63)` in Goldilocks;
`EnforceGe` below is that field relation. `enforce_ge_accepts_zero_below_top`
shows it accepts `self = 0` against `lower = 2^63 - 1` (the wrapped difference
is `2^63 - 2^32 + 2 < 2^63`), and `enforce_ge_iff_le_of_lower_bounded` shows
it IS the ordering `lower ≤ self` whenever `self < 2^63` and
`lower ≤ 2^63 - 2^32 + 1`. Integer block-window theorems therefore carry those
bounds as explicit premises.

Nothing here asserts proof soundness, hash injectivity (Poseidon / keccak are
opaque callbacks; only preimage-layout injectivity is proved), Merkle
soundness, nullifier freshness, L1 finality of the deposit, or
"acceptance ⇒ safe".

Named boundaries (also listed in the line map): `proofAccepted` (recursive
plonky2 verification of the previous balance proof under its own embedded
verifier data), `depositMerkleAccepted` / `depositMerkleVerify` (deposit-tree
inclusion gadget and native check), `accountStateAccepted` /
`accountStateVerify` (send-leaf and channel-leaf openings), `poseidonBytes32`
(Poseidon + u64→u32 limb split, used for both nullifier and recipient),
`keccak` (settled-tx-chain fold), `getRoot` / `assetRoot` / `nullifierCall`
(imported gadget interfaces), `convertFields` (native field conversion of
verifier data), the Goldilocks lowering of `sub` / `range_check` / `is_zero`
/ `select` to `EnforceGe` / `ConditionalGe` / `ConditionalGt`, the
range-check premises (`newBlockRange`, `accountRanges`, `depositRanges`) that
checked allocations are assumed to contribute, and the native witness-write /
proving effects.
-/

namespace Zkp.Implementation.ReceiveDepositCircuit

abbrev Root := BalancePublicInputs.Root
abbrev Bytes8 := BalancePublicInputs.Bytes8
abbrev PublicState := BalancePublicInputs.PublicState
abbrev FullInputs := BalancePublicInputs.FullInputs
abbrev VerifierData := BalancePublicInputs.VerifierData
abbrev Hash4 := PrivateState.Hash4
abbrev Amount := UpdatePrivateState.Amount
/-- `Bytes32` as the 8-limb word used by `UpdatePrivateState` (nullifier). -/
abbrev Bytes32 := UpdatePrivateState.Bytes32
/-- `Salt` is the four-element Poseidon wrapper (src/common/salt.rs). -/
abbrev Salt := PrivateState.Hash4

/-! ## Pinned constants -/

def balanceLength : Nat := 29
/-- `Deposit::to_u64_vec` word count: index, block, 5 depositor limbs, 8
recipient limbs, token index, 8 amount limbs, 8 aux limbs. -/
def depositLength : Nat := 32
/-- `DEPOSIT_TREE_HEIGHT` (src/constants.rs). -/
def depositTreeHeight : Nat := 63
def witnessWriteCount : Nat := 7
/-- `SETTLED_TX_CHAIN_DOMAIN` ("IMTC") from src/common/balance_state.rs. -/
def settledTxChainDomain : Nat := 0x494d5443
/-- `USER_ID_DOMAIN` ("UID\0") and `USER_ID_TAG` from recipient.rs. -/
def userIdDomain : Nat := 0x55494400
def userIdTag : Nat := 1
/-- `U63_BITS` and the range-check limit `2^63`. -/
def u63Bits : Nat := 63
def u63Limit : Nat := 2 ^ 63
/-- Goldilocks modulus `2^64 - 2^32 + 1`. -/
def goldilocks : Nat := 2 ^ 64 - 2 ^ 32 + 1
/-- Largest `lower` operand for which `enforce_ge` is the integer ordering:
`goldilocks - u63Limit = 2^63 - 2^32 + 1`. -/
def orderingBound : Nat := 2 ^ 63 - 2 ^ 32 + 1

theorem balance_length_pinned : balanceLength = 29 := rfl
theorem balance_length_matches_codec : balanceLength = BalancePublicInputs.balanceLength := rfl
theorem deposit_length_pinned : depositLength = 32 := rfl
theorem deposit_tree_height_pinned : depositTreeHeight = 63 := rfl
theorem witness_write_count_pinned : witnessWriteCount = 7 := rfl
theorem settled_tx_chain_domain_pinned : settledTxChainDomain = 0x494d5443 := rfl
theorem user_id_domain_pinned : userIdDomain = 0x55494400 := rfl
theorem user_id_tag_pinned : userIdTag = 1 := rfl
theorem u63_bits_pinned : u63Bits = 63 := rfl
theorem u63_limit_pinned : u63Limit = 9223372036854775808 := by decide
theorem goldilocks_pinned : goldilocks = 18446744069414584321 := by decide
theorem ordering_bound_pinned : orderingBound = 9223372032559808513 := by decide
theorem ordering_bound_is_field_minus_limit : orderingBound = goldilocks - u63Limit := by decide
theorem block_limit_matches_u63 : BalancePublicInputs.blockLimit = u63Limit := rfl
theorem deposit_index_limit_matches_u63 : 2 ^ depositTreeHeight = u63Limit := rfl

/-- Both `PoseidonHashOut` representations used by the imports. -/
def rootOfHash (h : Hash4) : Root := ⟨h.a, h.b, h.c, h.d⟩

theorem root_of_hash_injective {a b : Hash4} (h : rootOfHash a = rootOfHash b) : a = b := by
  cases a; cases b
  simp only [rootOfHash, BalancePublicInputs.Root.mk.injEq] at h
  obtain ⟨rfl, rfl, rfl, rfl⟩ := h
  rfl

/-- The same 8-limb word viewed as the settled-chain / recipient `Bytes32`. -/
def toBytes8 (a : Amount) : Bytes8 := ⟨a.w0, a.w1, a.w2, a.w3, a.w4, a.w5, a.w6, a.w7⟩

theorem to_bytes8_injective {a b : Amount} (h : toBytes8 a = toBytes8 b) : a = b := by
  cases a; cases b
  simp only [toBytes8, BalancePublicInputs.Bytes8.mk.injEq] at h
  obtain ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩ := h
  rfl

/-! ## Goldilocks lowering of `U63Target::enforce_ge` (u63.rs 225–274)

`enforce_ge(self, lower)` = `range_check(sub(self, lower), 63)`; plonky2's
`range_check(x, 63)` is `split_le(x, 63)`, i.e. the canonical field value of
`x` is below `2^63`. `conditional_ge` range-checks `select(cond, diff, 0)`;
`conditional_gt` is `conditional_ge` against `lower + 1`. Operands are Nat
values below the modulus. -/

def fieldSub (a b : Nat) : Nat := (a + goldilocks - b) % goldilocks
def fieldAddOne (a : Nat) : Nat := (a + 1) % goldilocks
def selectOrZero (cond : Bool) (x : Nat) : Nat := if cond then x else 0

def EnforceGe (self lower : Nat) : Prop := fieldSub self lower < u63Limit
def ConditionalGe (cond : Bool) (self lower : Nat) : Prop :=
  selectOrZero cond (fieldSub self lower) < u63Limit
def ConditionalGt (cond : Bool) (self lower : Nat) : Prop :=
  ConditionalGe cond self (fieldAddOne lower)

theorem enforce_ge_of_le {self lower : Nat} (h : lower ≤ self) (hs : self < u63Limit) :
    EnforceGe self lower := by
  simp only [EnforceGe, fieldSub, goldilocks_pinned, u63_limit_pinned] at *
  omega

theorem enforce_gt_of_lt {self lower : Nat} (h : lower < self) (hs : self < u63Limit) :
    EnforceGe self (fieldAddOne lower) := by
  simp only [EnforceGe, fieldSub, fieldAddOne, goldilocks_pinned, u63_limit_pinned] at *
  omega

/-- `enforce_ge` IS the integer ordering when `self < 2^63` and the lower
operand is at most `2^63 - 2^32 + 1`. -/
theorem enforce_ge_iff_le_of_lower_bounded {self lower : Nat} (hs : self < u63Limit)
    (hl : lower ≤ orderingBound) : EnforceGe self lower ↔ lower ≤ self := by
  simp only [EnforceGe, fieldSub, goldilocks_pinned, u63_limit_pinned, ordering_bound_pinned] at *
  constructor <;> intro h <;> omega

theorem enforce_gt_iff_lt_of_lower_bounded {self lower : Nat} (hs : self < u63Limit)
    (hl : lower + 1 ≤ orderingBound) : EnforceGe self (fieldAddOne lower) ↔ lower < self := by
  simp only [EnforceGe, fieldSub, fieldAddOne, goldilocks_pinned, u63_limit_pinned,
    ordering_bound_pinned] at *
  constructor <;> intro h <;> omega

/-- The wrapped difference `0 - (2^63 - 1)` in Goldilocks is `2^63 - 2^32 + 2`,
which passes the 63-bit range check. -/
theorem wrapped_difference_at_top : fieldSub 0 (u63Limit - 1) = u63Limit - 2 ^ 32 + 2 := by decide

/-- `enforce_ge` is NOT an ordering check at the top of the 63-bit domain: it
accepts `self = 0` against `lower = 2^63 - 1`. -/
theorem enforce_ge_accepts_zero_below_top : EnforceGe 0 (u63Limit - 1) := by
  unfold EnforceGe
  decide

theorem enforce_ge_is_not_ordering_at_top :
    ∃ self lower, self < u63Limit ∧ lower < u63Limit ∧ self < lower ∧ EnforceGe self lower :=
  ⟨0, u63Limit - 1, by decide, by decide, by decide, enforce_ge_accepts_zero_below_top⟩

theorem conditional_ge_false_is_vacuous (self lower : Nat) : ConditionalGe false self lower := by
  simp only [ConditionalGe, selectOrZero, Bool.false_eq_true, if_false]
  decide

theorem conditional_ge_true_iff (self lower : Nat) :
    ConditionalGe true self lower ↔ EnforceGe self lower := by
  simp only [ConditionalGe, selectOrZero, if_true, EnforceGe]

theorem conditional_ge_of_imp {cond : Bool} {self lower : Nat}
    (h : cond = true → EnforceGe self lower) : ConditionalGe cond self lower := by
  cases cond
  · exact conditional_ge_false_is_vacuous self lower
  · exact (conditional_ge_true_iff self lower).mpr (h rfl)

theorem conditional_gt_of_imp {cond : Bool} {self lower : Nat}
    (h : cond = true → EnforceGe self (fieldAddOne lower)) : ConditionalGt cond self lower :=
  conditional_ge_of_imp h

/-! ## Data carried by the witness (fields this file reads) -/

/-- `Address` (20 bytes) as its five u32 limbs. -/
structure Address where
  l0 : Nat
  l1 : Nat
  l2 : Nat
  l3 : Nat
  l4 : Nat
  deriving DecidableEq, Repr

def Address.words (a : Address) : List Nat := [a.l0, a.l1, a.l2, a.l3, a.l4]
def Address.zero : Address := ⟨0, 0, 0, 0, 0⟩

/-- `Deposit` (src/common/deposit.rs): index and block number are u63, the
rest are u32-limb words; `amount` is a U256. -/
structure Deposit where
  depositIndex : Nat
  blockNumber : Nat
  depositor : Address
  recipient : Bytes8
  tokenIndex : Nat
  amount : Amount
  auxData : Bytes8
  deriving DecidableEq, Repr

/-- `Deposit::to_u64_vec` (deposit.rs 68–78): the nullifier preimage. The
deposit index and block number are the first two words. -/
def Deposit.words (d : Deposit) : List Nat :=
  [d.depositIndex, d.blockNumber] ++ d.depositor.words ++ d.recipient.words ++
    [d.tokenIndex] ++ UpdatePrivateState.amountWords d.amount ++ d.auxData.words

theorem deposit_has_32_words (d : Deposit) : d.words.length = depositLength := by
  simp [Deposit.words, Address.words, BalancePublicInputs.Bytes8.words,
    UpdatePrivateState.amountWords, depositLength]

theorem deposit_words_start_with_index (d : Deposit) : d.words[0]? = some d.depositIndex := by
  simp [Deposit.words]

theorem deposit_words_have_block_second (d : Deposit) : d.words[1]? = some d.blockNumber := by
  simp [Deposit.words]

/-- The nullifier preimage separates deposits by index, block, depositor,
recipient, token, amount and aux data: equal preimages have equal deposits.
This is a fact about the preimage layout, not about the Poseidon output. -/
theorem deposit_words_injective {d e : Deposit} (h : d.words = e.words) : d = e := by
  obtain ⟨di, db, ⟨d0, d1, d2, d3, d4⟩, ⟨r0, r1, r2, r3, r4, r5, r6, r7⟩, dt,
    ⟨a0, a1, a2, a3, a4, a5, a6, a7⟩, ⟨x0, x1, x2, x3, x4, x5, x6, x7⟩⟩ := d
  obtain ⟨ei, eb, ⟨f0, f1, f2, f3, f4⟩, ⟨s0, s1, s2, s3, s4, s5, s6, s7⟩, et,
    ⟨b0, b1, b2, b3, b4, b5, b6, b7⟩, ⟨y0, y1, y2, y3, y4, y5, y6, y7⟩⟩ := e
  simp only [Deposit.words, Address.words, BalancePublicInputs.Bytes8.words,
    UpdatePrivateState.amountWords, List.cons_append, List.nil_append, List.cons.injEq] at h
  obtain ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl,
    rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, _⟩ := h
  rfl

/-- `Deposit::nullifier` = `Bytes32::from(PoseidonHashOut::hash_inputs_u64(to_u64_vec))`. -/
def nullifierOf (poseidon : List Nat → Bytes32) (d : Deposit) : Bytes32 := poseidon d.words

/-- `calculate_recipient_from_user_id` preimage: `[USER_ID_DOMAIN, channel] ++ salt`. -/
def recipientPreimage (channel : Nat) (salt : Salt) : List Nat :=
  [userIdDomain, channel] ++ PrivateState.hashWords salt

theorem recipient_preimage_has_6_words (channel : Nat) (salt : Salt) :
    (recipientPreimage channel salt).length = 6 := by
  simp [recipientPreimage, PrivateState.hashWords]

theorem recipient_preimage_injective {c c' : Nat} {s s' : Salt}
    (h : recipientPreimage c s = recipientPreimage c' s') : c = c' ∧ s = s' := by
  cases s; cases s'
  simp only [recipientPreimage, PrivateState.hashWords, List.cons_append, List.nil_append,
    List.cons.injEq] at h
  obtain ⟨_, rfl, rfl, rfl, rfl, rfl, _⟩ := h
  exact ⟨rfl, rfl⟩

/-- Replace big-endian byte 0 (the top byte of limb 0) with `USER_ID_TAG`
(recipient.rs 33–36). -/
def tagUserId (b : Bytes8) : Bytes8 := { b with a := userIdTag * 2 ^ 24 + b.a % 2 ^ 24 }

def recipientOf (poseidon : List Nat → Bytes32) (channel : Nat) (salt : Salt) : Bytes8 :=
  tagUserId (toBytes8 (poseidon (recipientPreimage channel salt)))

theorem recipient_top_byte_is_user_id_tag (poseidon : List Nat → Bytes32) (channel : Nat)
    (salt : Salt) : (recipientOf poseidon channel salt).a / 2 ^ 24 = userIdTag := by
  simp only [recipientOf, tagUserId, userIdTag]
  omega

theorem recipient_keeps_low_limbs (poseidon : List Nat → Bytes32) (channel : Nat) (salt : Salt) :
    (recipientOf poseidon channel salt).b = (poseidon (recipientPreimage channel salt)).w1 ∧
    (recipientOf poseidon channel salt).h = (poseidon (recipientPreimage channel salt)).w7 :=
  ⟨rfl, rfl⟩

/-- `DepositWitness` (deposit_witness.rs 39–46): receiver channel, the deposit
tree root, the recipient salt, the deposit leaf and its opaque Merkle proof. -/
structure DepositWitness (P : Type) where
  channelId : Nat
  depositTreeRoot : Root
  depositSalt : Salt
  deposit : Deposit
  merkleProof : P

/-- `AccountState`: only the fields this file reads. `send_leaf.prev/cur` and
`channel_leaf.prev` are u63 block numbers; the two Merkle proofs and the leaf
index are opaque. -/
structure AccountState (P : Type) where
  channelId : Nat
  accountTreeRoot : Root
  sendLeafPrev : Nat
  sendLeafCur : Nat
  channelLeafPrev : Nat
  proofs : P

/-- `has_outgoing = not(is_zero(channel_leaf.prev))` (source line 314–315). -/
def hasOutgoing (a : AccountState P) : Bool := !decide (a.channelLeafPrev = 0)

theorem has_outgoing_iff (a : AccountState P) : hasOutgoing a = true ↔ a.channelLeafPrev ≠ 0 := by
  simp [hasOutgoing]

/-! ## Opaque dependencies -/

/-- Every callee whose semantics this file does not define. `Prop`-valued
fields are acceptance premises of sub-gadgets that the CIRCUIT lays down and
the NATIVE helper never evaluates; `Except`-valued fields are the native
callees' results. -/
structure Environment (N P : Type) where
  /-- `balance_cd.config` cap count used by both balance-statement codecs. -/
  capCount : Nat
  /-- `ToField::to_field_vec` on the verifier-data suffix (may fail). -/
  convertFields : List Nat → BalancePublicInputs.Result (List Nat)
  /-- Poseidon `hash_inputs` for the private-state commitment. -/
  hash : List Nat → Hash4
  /-- `PoseidonHashOut::hash_inputs_u64(..).into()`: Poseidon followed by the
  u64→(high, low) u32 limb split, used by both `Deposit::nullifier` and
  `calculate_recipient_from_user_id`. -/
  poseidonBytes32 : List Nat → Bytes32
  /-- keccak256 over u32 words, used by `settled_tx_chain_push`. -/
  keccak : List Nat → Bytes8
  /-- Native `DepositMerkleProof::verify(deposit, index, root)`. -/
  depositMerkleVerify : P → Deposit → Nat → Root → Except String Unit
  /-- Native `AccountState::verify` (both openings). -/
  accountStateVerify : AccountState P → Except String Unit
  /-- `builder.verify_proof` of the previous balance proof with the given
  statement under the given verifier data. -/
  proofAccepted : VerifierData → FullInputs → Prop
  /-- `DepositMerkleProofTarget::verify(deposit, deposit.deposit_index, root)`. -/
  depositMerkleAccepted : P → Deposit → Nat → Root → Prop
  /-- `AccountStateTarget::new(_, true)`: send/channel leaf openings. -/
  accountStateAccepted : AccountState P → Prop
  /-- Imported `UpdatePublicState` Merkle-root call. -/
  getRoot : UpdatePublicState.RootCall
  /-- Imported `UpdatePrivateState` asset-root call. -/
  assetRoot : List Hash4 → Amount → Nat → Hash4
  /-- Imported `UpdatePrivateState` nullifier-insertion gadget relation. -/
  nullifierCall : N → Hash4 → Amount → Hash4 → Prop

/-- `settled_tx_chain_push` preimage: domain word, 8 chain limbs, 8 leaf limbs. -/
def chainPreimage (chain leaf : Bytes8) : List Nat :=
  [settledTxChainDomain] ++ chain.words ++ leaf.words

theorem chain_preimage_has_17_words (chain leaf : Bytes8) :
    (chainPreimage chain leaf).length = 17 := by
  simp [chainPreimage, BalancePublicInputs.Bytes8.words]

theorem chain_preimage_starts_with_domain (chain leaf : Bytes8) :
    (chainPreimage chain leaf)[0]? = some 0x494d5443 := by
  simp [chainPreimage, settledTxChainDomain]

def chainPush (keccak : List Nat → Bytes8) (chain leaf : Bytes8) : Bytes8 :=
  keccak (chainPreimage chain leaf)

/-! ## `DepositWitness::verify` (deposit_witness.rs 76–100) -/

inductive DepositWitnessError where
  | invalidDepositIndex
  | invalidDepositMerkleProof (detail : String)
  | invalidRecipient
  deriving DecidableEq, Repr

def depositWitnessVerify (e : Environment N P) (dw : DepositWitness P) :
    Except DepositWitnessError Unit :=
  if dw.deposit.depositIndex ≥ 2 ^ depositTreeHeight then .error .invalidDepositIndex
  else
    match e.depositMerkleVerify dw.merkleProof dw.deposit dw.deposit.depositIndex
        dw.depositTreeRoot with
    | .error detail => .error (.invalidDepositMerkleProof detail)
    | .ok _ =>
      if dw.deposit.recipient ≠ recipientOf e.poseidonBytes32 dw.channelId dw.depositSalt then
        .error .invalidRecipient
      else .ok ()

theorem deposit_witness_verify_ok_iff (e : Environment N P) (dw : DepositWitness P) :
    depositWitnessVerify e dw = .ok () ↔
      dw.deposit.depositIndex < u63Limit ∧
      e.depositMerkleVerify dw.merkleProof dw.deposit dw.deposit.depositIndex dw.depositTreeRoot =
        .ok () ∧
      dw.deposit.recipient = recipientOf e.poseidonBytes32 dw.channelId dw.depositSalt := by
  unfold depositWitnessVerify
  rw [deposit_index_limit_matches_u63]
  by_cases hi : dw.deposit.depositIndex ≥ u63Limit
  · rw [if_pos hi]
    have : ¬ dw.deposit.depositIndex < u63Limit := by omega
    simp [this]
  · rw [if_neg hi]
    have hi' : dw.deposit.depositIndex < u63Limit := by omega
    cases hm : e.depositMerkleVerify dw.merkleProof dw.deposit dw.deposit.depositIndex
        dw.depositTreeRoot with
    | error detail => simp [hm]
    | ok u =>
      cases u
      by_cases hr : dw.deposit.recipient = recipientOf e.poseidonBytes32 dw.channelId dw.depositSalt
      · simp [hi', hm, hr]
      · simp [hm, hr]

theorem deposit_witness_index_error_first (e : Environment N P) (dw : DepositWitness P)
    (h : u63Limit ≤ dw.deposit.depositIndex) :
    depositWitnessVerify e dw = .error .invalidDepositIndex := by
  simp [depositWitnessVerify, deposit_index_limit_matches_u63, h]

theorem deposit_witness_merkle_error_second (e : Environment N P) (dw : DepositWitness P)
    (hi : dw.deposit.depositIndex < u63Limit) (detail : String)
    (hm : e.depositMerkleVerify dw.merkleProof dw.deposit dw.deposit.depositIndex
      dw.depositTreeRoot = .error detail) :
    depositWitnessVerify e dw = .error (.invalidDepositMerkleProof detail) := by
  have hi' : ¬ dw.deposit.depositIndex ≥ 2 ^ depositTreeHeight := by
    rw [deposit_index_limit_matches_u63]; omega
  simp [depositWitnessVerify, hi', hm]

theorem deposit_witness_recipient_error_third (e : Environment N P) (dw : DepositWitness P)
    (hi : dw.deposit.depositIndex < u63Limit)
    (hm : e.depositMerkleVerify dw.merkleProof dw.deposit dw.deposit.depositIndex
      dw.depositTreeRoot = .ok ())
    (hr : dw.deposit.recipient ≠ recipientOf e.poseidonBytes32 dw.channelId dw.depositSalt) :
    depositWitnessVerify e dw = .error .invalidRecipient := by
  have hi' : ¬ dw.deposit.depositIndex ≥ 2 ^ depositTreeHeight := by
    rw [deposit_index_limit_matches_u63]; omega
  simp [depositWitnessVerify, hi', hm, hr]

/-! ## Native admission: `ReceiveDepositWitness::to_public_inputs` -/

/-- `ReceiveDepositError`, in source order. `invalidBalanceProof` and
`invalidBalanceVd` are declared by the source but never produced by
`to_public_inputs`. -/
inductive Error where
  | connection (detail : String)
  | balancePublicInputs (fault : BalancePublicInputs.Fault)
  | invalidBalanceProof (detail : String)
  | invalidBalanceVd (detail : String)
  | invalidRecipient
  | blockNumber (detail : String)
  | invalidDepositWitness (detail : String)
  | failedToProve (detail : String)
  deriving DecidableEq, Repr

abbrev Result (α : Type) := Except Error α

/-- `ReceiveDepositWitness` (source lines 66–91). The previous balance proof is
represented by its public-input words only; the proof body is never read by
the native helper. -/
structure Witness (N P : Type) where
  prevProofWords : List Nat
  updatePublicState : UpdatePublicState.Update
  newBlockR : Nat
  accountState : AccountState P
  depositWitness : DepositWitness P
  /-- The already-built native `UpdatePrivateState` (inputs + `new_private_state`). -/
  updatePrivateState : UpdatePrivateState.Output N

def check (p : Prop) [Decidable p] (e : Error) : Result Unit :=
  if p then .ok () else .error e

def parseFull (e : Environment N P) (words : List Nat) : Result FullInputs :=
  match BalancePublicInputs.fullFromNative e.convertFields e.capCount words with
  | .error fault => .error (.balancePublicInputs fault)
  | .ok full => .ok full

/-- Source lines 111–115: `update_public_state.verify()` mapped to `ConnectionError`. -/
def publicUpdateOrError (e : Environment N P) (u : UpdatePublicState.Update) : Result Unit :=
  match UpdatePublicState.nativeVerify e.getRoot u with
  | .error _ => .error (.connection "update_public_state verification failed")
  | .ok _ => .ok ()

/-- Source lines 125–131: `account_state.verify()` mapped to `ConnectionError`. -/
def accountStateOrError (e : Environment N P) (a : AccountState P) : Result Unit :=
  match e.accountStateVerify a with
  | .error _ => .error (.connection "account_state verification failed")
  | .ok _ => .ok ()

def describeDepositWitnessError : DepositWitnessError → String
  | .invalidDepositIndex => "Invalid deposit index"
  | .invalidDepositMerkleProof detail => "Invalid deposit merkle proof: " ++ detail
  | .invalidRecipient => "Invalid recipient in deposit"

/-- Source lines 153–160: `InvalidRecipient` keeps its own variant; every other
`DepositWitnessError` becomes `InvalidDepositWitness`. -/
def depositWitnessOrError (e : Environment N P) (dw : DepositWitness P) : Result Unit :=
  match depositWitnessVerify e dw with
  | .error .invalidRecipient => .error .invalidRecipient
  | .error err => .error (.invalidDepositWitness (describeDepositWitnessError err))
  | .ok _ => .ok ()

/-- Source lines 178–192: extra window checks only when the receiver has a
previous outgoing tx (`channel_leaf.prev != 0`). -/
def outgoingWindowCheck (prevBlockR : Nat) (a : AccountState P) (newBlockR : Nat) : Result Unit :=
  if a.channelLeafPrev = 0 then .ok ()
  else if prevBlockR < a.sendLeafPrev then .error (.blockNumber "send_leaf.prev")
  else if a.sendLeafCur ≤ newBlockR then .error (.blockNumber "send_leaf.cur")
  else .ok ()

/-- Source lines 236–248: the new 29-word statement plus the shared verifier
data. The consumed deposit's nullifier is ALWAYS folded into the chain. -/
def nativeOutput (e : Environment N P) (w : Witness N P) (prevFull : FullInputs) : FullInputs :=
  ⟨⟨prevFull.pis.channelId, w.updatePublicState.newState, w.newBlockR,
    rootOfHash (PrivateState.commitment e.hash w.updatePrivateState.next),
    chainPush e.keccak prevFull.pis.settledChain
      (toBytes8 (nullifierOf e.poseidonBytes32 w.depositWitness.deposit))⟩,
   prevFull.vd⟩

def nativeToPublicInputs (e : Environment N P) (w : Witness N P) : Result FullInputs := do
  let prevFull ← parseFull e w.prevProofWords
  publicUpdateOrError e w.updatePublicState
  check (w.updatePublicState.oldState = prevFull.pis.publicState)
    (.connection "update_public_state.old")
  accountStateOrError e w.accountState
  check (w.accountState.channelId = prevFull.pis.channelId) (.connection "account_state.channel_id")
  check (w.accountState.accountTreeRoot = w.updatePublicState.newState.accountRoot)
    (.connection "account_state.account_tree_root")
  check (w.depositWitness.channelId = prevFull.pis.channelId)
    (.connection "deposit_witness.channel_id")
  depositWitnessOrError e w.depositWitness
  check (w.depositWitness.depositTreeRoot = w.updatePublicState.newState.depositRoot)
    (.connection "deposit_witness.deposit_tree_root")
  check (¬ (w.newBlockR < prevFull.pis.blockR ∨
      w.updatePublicState.newState.blockNumber < w.newBlockR)) (.blockNumber "new_block_r")
  outgoingWindowCheck prevFull.pis.blockR w.accountState w.newBlockR
  check (¬ w.newBlockR < w.depositWitness.deposit.blockNumber) (.blockNumber "deposit.block_number")
  check (w.updatePrivateState.inputs.tokenIndex = w.depositWitness.deposit.tokenIndex)
    (.connection "update_private_state.token_index")
  check (w.updatePrivateState.inputs.amount = w.depositWitness.deposit.amount)
    (.connection "update_private_state.amount")
  check (w.updatePrivateState.inputs.nullifier = nullifierOf e.poseidonBytes32 w.depositWitness.deposit)
    (.connection "update_private_state.nullifier")
  check (rootOfHash (PrivateState.commitment e.hash w.updatePrivateState.inputs.previous) =
      prevFull.pis.privateCommitment)
    (.connection "update_private_state.prev_private_state.commitment")
  return nativeOutput e w prevFull

/-! ### Except helpers (same shape as ChannelStateUpdate) -/

theorem check_ok_iff (p : Prop) [Decidable p] (e : Error) : check p e = .ok () ↔ p := by
  by_cases h : p <;> simp [check, h]

theorem bind_ok_iff {ε α β : Type} (r : Except ε α) (f : α → Except ε β) (value : β) :
    (r >>= f) = .ok value ↔ ∃ x, r = .ok x ∧ f x = .ok value := by
  cases r <;> simp [Bind.bind, Except.bind]

theorem exists_unit (p : Unit → Prop) : (∃ x, p x) ↔ p () := by
  constructor
  · rintro ⟨⟨⟩, h⟩; exact h
  · intro h; exact ⟨(), h⟩

theorem pure_ok_iff {ε α : Type} (a b : α) : (pure a : Except ε α) = .ok b ↔ a = b := by
  constructor
  · intro h; exact Except.ok.inj h
  · intro h; subst h; rfl

theorem parse_ok_iff (e : Environment N P) (words : List Nat) (full : FullInputs) :
    parseFull e words = .ok full ↔
      BalancePublicInputs.fullFromNative e.convertFields e.capCount words = .ok full := by
  cases h : BalancePublicInputs.fullFromNative e.convertFields e.capCount words <;> simp [parseFull, h]

theorem parse_error_maps_fault (e : Environment N P) (words : List Nat)
    (fault : BalancePublicInputs.Fault)
    (h : BalancePublicInputs.fullFromNative e.convertFields e.capCount words = .error fault) :
    parseFull e words = .error (.balancePublicInputs fault) := by
  simp [parseFull, h]

theorem public_update_ok_iff (e : Environment N P) (u : UpdatePublicState.Update) :
    publicUpdateOrError e u = .ok () ↔ UpdatePublicState.nativeVerify e.getRoot u = .ok () := by
  cases h : UpdatePublicState.nativeVerify e.getRoot u with
  | error err => simp [publicUpdateOrError, h]
  | ok v => cases v; simp [publicUpdateOrError, h]

theorem account_state_ok_iff (e : Environment N P) (a : AccountState P) :
    accountStateOrError e a = .ok () ↔ e.accountStateVerify a = .ok () := by
  cases h : e.accountStateVerify a with
  | error err => simp [accountStateOrError, h]
  | ok v => cases v; simp [accountStateOrError, h]

theorem deposit_witness_or_error_ok_iff (e : Environment N P) (dw : DepositWitness P) :
    depositWitnessOrError e dw = .ok () ↔ depositWitnessVerify e dw = .ok () := by
  cases h : depositWitnessVerify e dw with
  | error err => cases err <;> simp [depositWitnessOrError, h]
  | ok v => cases v; simp [depositWitnessOrError, h]

theorem deposit_witness_recipient_error_is_invalid_recipient (e : Environment N P)
    (dw : DepositWitness P) (h : depositWitnessVerify e dw = .error .invalidRecipient) :
    depositWitnessOrError e dw = .error .invalidRecipient := by
  simp [depositWitnessOrError, h]

theorem deposit_witness_other_error_is_invalid_deposit_witness (e : Environment N P)
    (dw : DepositWitness P) (err : DepositWitnessError) (h : depositWitnessVerify e dw = .error err)
    (notRecipient : err ≠ .invalidRecipient) :
    depositWitnessOrError e dw = .error (.invalidDepositWitness (describeDepositWitnessError err)) := by
  cases err with
  | invalidRecipient => exact absurd rfl notRecipient
  | invalidDepositIndex => simp [depositWitnessOrError, h]
  | invalidDepositMerkleProof detail => simp [depositWitnessOrError, h]

theorem outgoing_ok_iff (prevBlockR : Nat) (a : AccountState P) (newBlockR : Nat) :
    outgoingWindowCheck prevBlockR a newBlockR = .ok () ↔
      (a.channelLeafPrev ≠ 0 → a.sendLeafPrev ≤ prevBlockR ∧ newBlockR < a.sendLeafCur) := by
  unfold outgoingWindowCheck
  by_cases h0 : a.channelLeafPrev = 0
  · simp [h0]
  · by_cases h1 : prevBlockR < a.sendLeafPrev
    · simp [h0, h1]
      intro _
      omega
    · by_cases h2 : a.sendLeafCur ≤ newBlockR
      · simp [h0, h1, h2]
      · simp [h0, h1, h2]
        omega

/-! ### Bounds the native 29-word parser guarantees -/

theorem check_native_fields_ok (p q : BalancePublicInputs.PublicInputs)
    (h : BalancePublicInputs.checkNativeFields p = .ok q) :
    q = p ∧ p.publicState.blockNumber < u63Limit ∧ p.blockR < u63Limit := by
  unfold BalancePublicInputs.checkNativeFields at h
  split at h
  · simp at h
  · split at h
    · simp at h
    · split at h
      · simp at h
      · split at h
        · simp at h
        · split at h
          · simp at h
          · refine ⟨(Except.ok.inj h).symm, ?_, ?_⟩ <;>
              simp only [block_limit_matches_u63, u63_limit_pinned] at * <;> omega

theorem native_parse_bounds (convert : List Nat → BalancePublicInputs.Result (List Nat))
    (count : Nat) (xs : List Nat) (full : FullInputs)
    (h : BalancePublicInputs.fullFromNative convert count xs = .ok full) :
    full.pis.publicState.blockNumber < u63Limit ∧ full.pis.blockR < u63Limit := by
  unfold BalancePublicInputs.fullFromNative at h
  split at h
  · simp only [bind_ok_iff, pure_ok_iff] at h
    obtain ⟨pis, hpis, _, _, vd, _, hfull⟩ := h
    unfold BalancePublicInputs.fromNative at hpis
    split at hpis
    · obtain ⟨hq, hb, hr⟩ := check_native_fields_ok _ _ hpis
      subst hfull
      subst hq
      exact ⟨hb, hr⟩
    · simp at hpis
  · simp at h

/-! ### The native guard bundle -/

/-- Everything `to_public_inputs` checks, in source order. No proof is
verified and `updatePrivateState.next` is not inspected. -/
structure NativeChecks (e : Environment N P) (w : Witness N P) (prevFull : FullInputs) : Prop where
  prevParse : BalancePublicInputs.fullFromNative e.convertFields e.capCount w.prevProofWords = .ok prevFull
  publicUpdate : UpdatePublicState.nativeVerify e.getRoot w.updatePublicState = .ok ()
  publicOld : w.updatePublicState.oldState = prevFull.pis.publicState
  accountVerified : e.accountStateVerify w.accountState = .ok ()
  accountChannel : w.accountState.channelId = prevFull.pis.channelId
  accountRoot : w.accountState.accountTreeRoot = w.updatePublicState.newState.accountRoot
  depositChannel : w.depositWitness.channelId = prevFull.pis.channelId
  depositVerified : depositWitnessVerify e w.depositWitness = .ok ()
  depositRoot : w.depositWitness.depositTreeRoot = w.updatePublicState.newState.depositRoot
  blockWindow : ¬ (w.newBlockR < prevFull.pis.blockR ∨
    w.updatePublicState.newState.blockNumber < w.newBlockR)
  outgoingWindow : w.accountState.channelLeafPrev ≠ 0 →
    w.accountState.sendLeafPrev ≤ prevFull.pis.blockR ∧ w.newBlockR < w.accountState.sendLeafCur
  depositBlock : ¬ w.newBlockR < w.depositWitness.deposit.blockNumber
  tokenIndex : w.updatePrivateState.inputs.tokenIndex = w.depositWitness.deposit.tokenIndex
  amount : w.updatePrivateState.inputs.amount = w.depositWitness.deposit.amount
  nullifier : w.updatePrivateState.inputs.nullifier =
    nullifierOf e.poseidonBytes32 w.depositWitness.deposit
  previousCommitment : rootOfHash (PrivateState.commitment e.hash w.updatePrivateState.inputs.previous) =
    prevFull.pis.privateCommitment

theorem native_ok_iff (e : Environment N P) (w : Witness N P) (out : FullInputs) :
    nativeToPublicInputs e w = .ok out ↔
      ∃ prevFull, NativeChecks e w prevFull ∧ out = nativeOutput e w prevFull := by
  constructor
  · intro accepted
    simp only [nativeToPublicInputs, bind_ok_iff, exists_unit, pure_ok_iff, check_ok_iff,
      parse_ok_iff, public_update_ok_iff, account_state_ok_iff, deposit_witness_or_error_ok_iff,
      outgoing_ok_iff] at accepted
    obtain ⟨prevFull, hPrev, hPub, hOld, hAcc, hAccCh, hAccRoot, hDepCh, hDep, hDepRoot, hWindow,
      hOut, hDepBlock, hTok, hAmt, hNul, hPrevC, hEq⟩ := accepted
    exact ⟨prevFull, ⟨hPrev, hPub, hOld, hAcc, hAccCh, hAccRoot, hDepCh, hDep, hDepRoot, hWindow,
      hOut, hDepBlock, hTok, hAmt, hNul, hPrevC⟩, hEq.symm⟩
  · rintro ⟨prevFull, c, rfl⟩
    simp only [nativeToPublicInputs, bind_ok_iff, exists_unit, pure_ok_iff, check_ok_iff,
      parse_ok_iff, public_update_ok_iff, account_state_ok_iff, deposit_witness_or_error_ok_iff,
      outgoing_ok_iff]
    exact ⟨prevFull, c.prevParse, c.publicUpdate, c.publicOld, c.accountVerified, c.accountChannel,
      c.accountRoot, c.depositChannel, c.depositVerified, c.depositRoot, c.blockWindow,
      c.outgoingWindow, c.depositBlock, c.tokenIndex, c.amount, c.nullifier, c.previousCommitment,
      rfl⟩

theorem native_success_extracts (e : Environment N P) (w : Witness N P) (out : FullInputs)
    (h : nativeToPublicInputs e w = .ok out) :
    ∃ prevFull, NativeChecks e w prevFull ∧ out = nativeOutput e w prevFull :=
  (native_ok_iff e w out).mp h

/-! ### Error precedence (leading guards) -/

theorem native_prev_parse_failure_first (e : Environment N P) (w : Witness N P)
    (fault : BalancePublicInputs.Fault)
    (h : BalancePublicInputs.fullFromNative e.convertFields e.capCount w.prevProofWords = .error fault) :
    nativeToPublicInputs e w = .error (.balancePublicInputs fault) := by
  simp [nativeToPublicInputs, parse_error_maps_fault e _ fault h, Bind.bind, Except.bind]

theorem native_public_update_failure_second (e : Environment N P) (w : Witness N P)
    (prevFull : FullInputs) (err : UpdatePublicState.Error)
    (hp : BalancePublicInputs.fullFromNative e.convertFields e.capCount w.prevProofWords = .ok prevFull)
    (h : UpdatePublicState.nativeVerify e.getRoot w.updatePublicState = .error err) :
    nativeToPublicInputs e w = .error (.connection "update_public_state verification failed") := by
  have hp' : parseFull e w.prevProofWords = .ok prevFull := (parse_ok_iff e _ _).mpr hp
  simp [nativeToPublicInputs, hp', publicUpdateOrError, h, Bind.bind, Except.bind]

theorem native_old_state_mismatch_third (e : Environment N P) (w : Witness N P)
    (prevFull : FullInputs)
    (hp : BalancePublicInputs.fullFromNative e.convertFields e.capCount w.prevProofWords = .ok prevFull)
    (hv : UpdatePublicState.nativeVerify e.getRoot w.updatePublicState = .ok ())
    (different : w.updatePublicState.oldState ≠ prevFull.pis.publicState) :
    nativeToPublicInputs e w = .error (.connection "update_public_state.old") := by
  have hp' : parseFull e w.prevProofWords = .ok prevFull := (parse_ok_iff e _ _).mpr hp
  have hv' : publicUpdateOrError e w.updatePublicState = .ok () :=
    (public_update_ok_iff e _).mpr hv
  simp [nativeToPublicInputs, hp', hv', check, different, Bind.bind, Except.bind]

/-! ### Facts derived from native success -/

theorem native_success_block_window (e : Environment N P) (w : Witness N P) (out : FullInputs)
    (h : nativeToPublicInputs e w = .ok out) :
    ∃ prevFull, BalancePublicInputs.fullFromNative e.convertFields e.capCount w.prevProofWords = .ok prevFull ∧
      prevFull.pis.blockR ≤ w.newBlockR ∧ w.newBlockR ≤ out.pis.publicState.blockNumber ∧
      w.depositWitness.deposit.blockNumber ≤ w.newBlockR ∧ out.pis.blockR = w.newBlockR := by
  obtain ⟨prevFull, c, rfl⟩ := native_success_extracts e w out h
  refine ⟨prevFull, c.prevParse, ?_, ?_, ?_, rfl⟩
  · have := c.blockWindow; omega
  · have := c.blockWindow; simp only [nativeOutput]; omega
  · have := c.depositBlock; omega

theorem native_success_credits_deposit_token_and_amount (e : Environment N P) (w : Witness N P)
    (out : FullInputs) (h : nativeToPublicInputs e w = .ok out) :
    w.updatePrivateState.inputs.tokenIndex = w.depositWitness.deposit.tokenIndex ∧
    w.updatePrivateState.inputs.amount = w.depositWitness.deposit.amount := by
  obtain ⟨_, c, _⟩ := native_success_extracts e w out h
  exact ⟨c.tokenIndex, c.amount⟩

theorem native_success_nullifier_is_full_deposit_hash (e : Environment N P) (w : Witness N P)
    (out : FullInputs) (h : nativeToPublicInputs e w = .ok out) :
    w.updatePrivateState.inputs.nullifier = e.poseidonBytes32 w.depositWitness.deposit.words ∧
    w.depositWitness.deposit.words[0]? = some w.depositWitness.deposit.depositIndex := by
  obtain ⟨_, c, _⟩ := native_success_extracts e w out h
  exact ⟨c.nullifier, deposit_words_start_with_index _⟩

theorem native_success_deposit_opens_under_new_deposit_root (e : Environment N P)
    (w : Witness N P) (out : FullInputs) (h : nativeToPublicInputs e w = .ok out) :
    w.depositWitness.deposit.depositIndex < u63Limit ∧
    e.depositMerkleVerify w.depositWitness.merkleProof w.depositWitness.deposit
      w.depositWitness.deposit.depositIndex out.pis.publicState.depositRoot = .ok () := by
  obtain ⟨_, c, rfl⟩ := native_success_extracts e w out h
  obtain ⟨hi, hm, _⟩ := (deposit_witness_verify_ok_iff e _).mp c.depositVerified
  refine ⟨hi, ?_⟩
  simp only [nativeOutput]
  rw [← c.depositRoot]
  exact hm

theorem native_success_recipient_is_receiver_channel_with_salt (e : Environment N P)
    (w : Witness N P) (out : FullInputs) (h : nativeToPublicInputs e w = .ok out) :
    w.depositWitness.deposit.recipient =
      recipientOf e.poseidonBytes32 out.pis.channelId w.depositWitness.depositSalt := by
  obtain ⟨_, c, rfl⟩ := native_success_extracts e w out h
  obtain ⟨_, _, hr⟩ := (deposit_witness_verify_ok_iff e _).mp c.depositVerified
  simp only [nativeOutput]
  rw [← c.depositChannel]
  exact hr

theorem native_success_chain_always_folds_nullifier (e : Environment N P) (w : Witness N P)
    (out : FullInputs) (h : nativeToPublicInputs e w = .ok out) :
    ∃ prevFull, BalancePublicInputs.fullFromNative e.convertFields e.capCount w.prevProofWords = .ok prevFull ∧
      out.pis.settledChain = e.keccak (chainPreimage prevFull.pis.settledChain
        (toBytes8 (e.poseidonBytes32 w.depositWitness.deposit.words))) := by
  obtain ⟨prevFull, c, rfl⟩ := native_success_extracts e w out h
  exact ⟨prevFull, c.prevParse, rfl⟩

theorem native_success_output_shape (e : Environment N P) (w : Witness N P) (out : FullInputs)
    (h : nativeToPublicInputs e w = .ok out) :
    out.pis.publicState = w.updatePublicState.newState ∧
    out.pis.privateCommitment = rootOfHash (PrivateState.commitment e.hash w.updatePrivateState.next) ∧
    out.pis.words.length = balanceLength := by
  obtain ⟨_, _, rfl⟩ := native_success_extracts e w out h
  exact ⟨rfl, rfl, BalancePublicInputs.balance_word_count _⟩

theorem native_success_public_update_is_locally_verified (e : Environment N P) (w : Witness N P)
    (out : FullInputs) (h : nativeToPublicInputs e w = .ok out) :
    UpdatePublicState.ValidUpdate e.getRoot w.updatePublicState ∧
    ∃ prevFull, BalancePublicInputs.fullFromNative e.convertFields e.capCount w.prevProofWords = .ok prevFull ∧
      w.updatePublicState.oldState = prevFull.pis.publicState := by
  obtain ⟨prevFull, c, _⟩ := native_success_extracts e w out h
  exact ⟨(UpdatePublicState.native_verify_iff_local_history _ _).mp c.publicUpdate,
    prevFull, c.prevParse, c.publicOld⟩

/-- Replace only the claimed `new_private_state`. -/
def Witness.withNext (w : Witness N P) (s : PrivateState.State) : Witness N P :=
  { w with updatePrivateState := { w.updatePrivateState with next := s } }

/-- The native helper does not recompute the private-state update: whatever
`new_private_state` the caller supplies is committed unchanged into the output
statement, with every other check unaffected. This is what the CIRCUIT's
`UpdatePrivateState.CircuitGates` adds and the native path does not. -/
theorem native_trusts_supplied_new_private_state (e : Environment N P) (w : Witness N P)
    (out : FullInputs) (h : nativeToPublicInputs e w = .ok out) (s : PrivateState.State) :
    ∃ out', nativeToPublicInputs e (w.withNext s) = .ok out' ∧
      out'.pis.privateCommitment = rootOfHash (PrivateState.commitment e.hash s) ∧
      out'.pis.channelId = out.pis.channelId ∧ out'.pis.publicState = out.pis.publicState ∧
      out'.pis.blockR = out.pis.blockR ∧ out'.pis.settledChain = out.pis.settledChain ∧
      out'.vd = out.vd := by
  obtain ⟨prevFull, c, rfl⟩ := native_success_extracts e w out h
  refine ⟨nativeOutput e (w.withNext s) prevFull, ?_, rfl, rfl, rfl, rfl, rfl, rfl⟩
  exact (native_ok_iff e _ _).mpr ⟨prevFull, ⟨c.prevParse, c.publicUpdate, c.publicOld,
    c.accountVerified, c.accountChannel, c.accountRoot, c.depositChannel, c.depositVerified,
    c.depositRoot, c.blockWindow, c.outgoingWindow, c.depositBlock, c.tokenIndex, c.amount,
    c.nullifier, c.previousCommitment⟩, rfl⟩

/-- Swap every gadget-acceptance premise and gadget interface for arbitrary ones. -/
def Environment.withGadgets (e : Environment N P)
    (proofAccepted : VerifierData → FullInputs → Prop)
    (depositMerkleAccepted : P → Deposit → Nat → Root → Prop)
    (accountStateAccepted : AccountState P → Prop)
    (assetRoot : List Hash4 → Amount → Nat → Hash4)
    (nullifierCall : N → Hash4 → Amount → Hash4 → Prop) : Environment N P :=
  { e with
    proofAccepted := proofAccepted
    depositMerkleAccepted := depositMerkleAccepted
    accountStateAccepted := accountStateAccepted
    assetRoot := assetRoot
    nullifierCall := nullifierCall }

/-- Native admission never evaluates proof verification, the target Merkle
gadgets, the asset-root or nullifier gadgets: its result is invariant under
any replacement of those interfaces. -/
theorem native_ignores_gadget_semantics (e : Environment N P) (w : Witness N P)
    (proofAccepted : VerifierData → FullInputs → Prop)
    (depositMerkleAccepted : P → Deposit → Nat → Root → Prop)
    (accountStateAccepted : AccountState P → Prop)
    (assetRoot : List Hash4 → Amount → Nat → Hash4)
    (nullifierCall : N → Hash4 → Amount → Hash4 → Prop) :
    nativeToPublicInputs (e.withGadgets proofAccepted depositMerkleAccepted accountStateAccepted
      assetRoot nullifierCall) w = nativeToPublicInputs e w := by
  cases e
  rfl

/-! ## `prove` (source lines 441–453) -/

/-- `ReceiveDepositCircuit::prove`: native admission first, then the opaque
prover over the same statement. -/
def prove (e : Environment N P) (prover : Witness N P → FullInputs → Except String Pf)
    (w : Witness N P) : Result Pf := do
  let pis ← nativeToPublicInputs e w
  match prover w pis with
  | .error detail => throw (.failedToProve detail)
  | .ok proof => pure proof

theorem prove_requires_native_admission (e : Environment N P)
    (prover : Witness N P → FullInputs → Except String Pf) (w : Witness N P) (proof : Pf)
    (h : prove e prover w = .ok proof) :
    ∃ pis, nativeToPublicInputs e w = .ok pis ∧ prover w pis = .ok proof := by
  simp only [prove, bind_ok_iff] at h
  obtain ⟨pis, hpis, hrest⟩ := h
  refine ⟨pis, hpis, ?_⟩
  cases hp : prover w pis with
  | error d => simp [hp] at hrest
  | ok p => simpa [hp, Pure.pure, Except.pure] using hrest

theorem prove_failure_precedence (e : Environment N P)
    (prover : Witness N P → FullInputs → Except String Pf) (w : Witness N P) (err : Error)
    (h : nativeToPublicInputs e w = .error err) : prove e prover w = .error err := by
  simp [prove, h, Bind.bind, Except.bind]

/-! ## Witness writes (source lines 374–396, plus `prove` line 449) -/

inductive Write where
  | prevBalanceProof | updatePublicState | newBlockR | accountState | depositWitness
  | updatePrivateState | newFullPis
  deriving DecidableEq, Repr

def witnessWrites : List Write :=
  [.prevBalanceProof, .updatePublicState, .newBlockR, .accountState, .depositWitness,
   .updatePrivateState, .newFullPis]

theorem witness_write_count : witnessWrites.length = witnessWriteCount := rfl

theorem witness_writes_derived_statement_last : witnessWrites[6]? = some .newFullPis := rfl

/-- `prove` writes the derived statement twice: through `target.set_witness`
and again through `public_inputs.set_witness` (the same target wires). -/
def proveWrites : List Write := witnessWrites ++ [.newFullPis]

theorem prove_writes_statement_twice : proveWrites.length = witnessWriteCount + 1 := rfl

/-! ## Constructor program (source lines 275–289, 418–431) -/

inductive BuildOp where
  | virtualBalanceProof
  | parseFullPis
  | verifyBalanceProof
  | updatePublicState
  | blockNumber (checked : Bool)
  | accountState (checked : Bool)
  | depositWitness (checked : Bool)
  | updatePrivateState (checked : Bool)
  | registerPublicInputs
  | addConstGate
  | build
  deriving DecidableEq, Repr

def buildPlan : List BuildOp :=
  [.virtualBalanceProof, .parseFullPis, .verifyBalanceProof, .updatePublicState,
   .blockNumber true, .accountState true, .depositWitness true, .updatePrivateState true,
   .registerPublicInputs, .addConstGate, .build]

theorem balance_proof_verified_before_gadgets :
    buildPlan[2]? = some .verifyBalanceProof ∧ buildPlan[3]? = some .updatePublicState := ⟨rfl, rfl⟩

theorem every_sub_gadget_is_checked_allocation :
    buildPlan[4]? = some (.blockNumber true) ∧ buildPlan[5]? = some (.accountState true) ∧
    buildPlan[6]? = some (.depositWitness true) ∧ buildPlan[7]? = some (.updatePrivateState true) :=
  ⟨rfl, rfl, rfl, rfl⟩

theorem const_gate_added_after_public_inputs :
    buildPlan[8]? = some .registerPublicInputs ∧ buildPlan[9]? = some .addConstGate ∧
    buildPlan[10]? = some .build := ⟨rfl, rfl, rfl⟩

/-! ## Arbitrary satisfying witness: `ReceiveDepositTarget::new` -/

/-- Range obligations the checked `DepositTarget::new(_, true)` allocation
contributes (u63 index/block, u32 limbs, 32-bit token index). -/
def DepositChecked (d : Deposit) : Prop :=
  d.depositIndex < u63Limit ∧ d.blockNumber < u63Limit ∧
  (∀ n ∈ d.depositor.words, n < 2 ^ 32) ∧ (∀ n ∈ d.recipient.words, n < 2 ^ 32) ∧
  d.tokenIndex < 2 ^ 32 ∧ UpdatePrivateState.Checked d.amount ∧ (∀ n ∈ d.auxData.words, n < 2 ^ 32)

/-- Wires of one satisfying assignment. The balance statement is what
`BalanceFullPublicInputsTarget::from_pis` reads from the proof wires. -/
structure CircuitWitness (N P : Type) where
  prevProofWords : List Nat
  prevFull : FullInputs
  updatePublicState : UpdatePublicState.Update
  publicUpsWitness : UpdatePublicState.Witness
  newBlockR : Nat
  accountState : AccountState P
  depositWitness : DepositWitness P
  updatePrivateState : UpdatePrivateState.Inputs N
  upsWitness : UpdatePrivateState.CircuitWitness
  output : FullInputs

def receiverId (w : CircuitWitness N P) : Nat := w.prevFull.pis.channelId
def publicStateOf (w : CircuitWitness N P) : PublicState := w.updatePublicState.newState
def depositOf (w : CircuitWitness N P) : Deposit := w.depositWitness.deposit

def circuitOutput (e : Environment N P) (w : CircuitWitness N P) : FullInputs :=
  ⟨⟨receiverId w, publicStateOf w, w.newBlockR,
    rootOfHash (PrivateState.commitment e.hash w.upsWitness.next),
    chainPush e.keccak w.prevFull.pis.settledChain
      (toBytes8 (nullifierOf e.poseidonBytes32 (depositOf w)))⟩,
   w.prevFull.vd⟩

/-- The local constraint system of `ReceiveDepositTarget::new` (source lines
275–361), one field per source connection / gadget call. Block comparisons
are the Goldilocks relations `EnforceGe` / `ConditionalGe` / `ConditionalGt`
(not integer orderings). Sub-gadget calls are the imported `CircuitGates`
where a current module exists and opaque acceptance premises otherwise. -/
structure CircuitGates (e : Environment N P) (w : CircuitWitness N P) : Prop where
  prevParse : BalancePublicInputs.fullFromTarget e.capCount w.prevProofWords = .ok w.prevFull
  prevProofVerified : e.proofAccepted w.prevFull.vd w.prevFull
  publicUpdate : UpdatePublicState.CircuitGates e.getRoot w.updatePublicState w.publicUpsWitness
  newBlockRange : w.newBlockR < u63Limit
  accountStateGadget : e.accountStateAccepted w.accountState
  accountRanges : w.accountState.channelId < 2 ^ 32 ∧ w.accountState.sendLeafPrev < u63Limit ∧
    w.accountState.sendLeafCur < u63Limit ∧ w.accountState.channelLeafPrev < u63Limit
  depositChannelRange : w.depositWitness.channelId < 2 ^ 32
  depositRanges : DepositChecked (depositOf w)
  depositMerkle : e.depositMerkleAccepted w.depositWitness.merkleProof (depositOf w)
    (depositOf w).depositIndex w.depositWitness.depositTreeRoot
  depositRecipient : (depositOf w).recipient =
    recipientOf e.poseidonBytes32 w.depositWitness.channelId w.depositWitness.depositSalt
  privateUpdate : UpdatePrivateState.CircuitGates e.hash e.assetRoot e.nullifierCall true
    w.updatePrivateState w.upsWitness
  publicOld : w.updatePublicState.oldState = w.prevFull.pis.publicState
  accountChannel : w.accountState.channelId = receiverId w
  accountRoot : w.accountState.accountTreeRoot = (publicStateOf w).accountRoot
  depositChannel : w.depositWitness.channelId = receiverId w
  depositRoot : w.depositWitness.depositTreeRoot = (publicStateOf w).depositRoot
  blockLower : EnforceGe w.newBlockR w.prevFull.pis.blockR
  blockUpper : EnforceGe (publicStateOf w).blockNumber w.newBlockR
  outgoingLower : ConditionalGe (hasOutgoing w.accountState) w.prevFull.pis.blockR
    w.accountState.sendLeafPrev
  outgoingUpper : ConditionalGt (hasOutgoing w.accountState) w.accountState.sendLeafCur w.newBlockR
  depositBlock : EnforceGe w.newBlockR (depositOf w).blockNumber
  tokenIndex : w.updatePrivateState.tokenIndex = (depositOf w).tokenIndex
  amount : w.updatePrivateState.amount = (depositOf w).amount
  nullifier : w.updatePrivateState.nullifier = nullifierOf e.poseidonBytes32 (depositOf w)
  previousCommitment : rootOfHash (PrivateState.commitment e.hash w.updatePrivateState.previous) =
    w.prevFull.pis.privateCommitment
  outputStatement : w.output = circuitOutput e w

variable {e : Environment N P} {w : CircuitWitness N P}

/-! ### Credit semantics (through the imported private-state gadget) -/

theorem circuit_credits_exact_deposit_amount (h : CircuitGates e w) :
    UpdatePrivateState.value w.upsWitness.newLeaf =
      UpdatePrivateState.value w.updatePrivateState.previousBalance +
        UpdatePrivateState.value (depositOf w).amount := by
  rw [← h.amount]
  exact UpdatePrivateState.circuit_credits_exact_amount h.privateUpdate

theorem circuit_credit_does_not_decrease_balance (h : CircuitGates e w) :
    UpdatePrivateState.value w.updatePrivateState.previousBalance ≤
      UpdatePrivateState.value w.upsWitness.newLeaf :=
  UpdatePrivateState.circuit_credit_does_not_decrease_balance h.privateUpdate

theorem circuit_credit_lands_at_deposit_token (h : CircuitGates e w) :
    e.assetRoot w.updatePrivateState.assetSiblings w.updatePrivateState.previousBalance
      (depositOf w).tokenIndex = w.updatePrivateState.previous.assetRoot ∧
    w.upsWitness.next.assetRoot = e.assetRoot w.updatePrivateState.assetSiblings
      w.upsWitness.newLeaf (depositOf w).tokenIndex := by
  rw [← h.tokenIndex]
  exact UpdatePrivateState.circuit_replaces_same_token_same_path h.privateUpdate

theorem circuit_keeps_sent_root_nonce_salt (h : CircuitGates e w) :
    w.upsWitness.next.sentTxRoot = w.updatePrivateState.previous.sentTxRoot ∧
    w.upsWitness.next.nonce = w.updatePrivateState.previous.nonce ∧
    w.upsWitness.next.salt = w.updatePrivateState.previous.salt :=
  UpdatePrivateState.circuit_keeps_sent_root_nonce_salt h.privateUpdate

theorem circuit_range_checks_credit_inputs (h : CircuitGates e w) :
    w.updatePrivateState.tokenIndex < 2 ^ 32 ∧ UpdatePrivateState.Checked w.updatePrivateState.amount ∧
    UpdatePrivateState.Checked w.updatePrivateState.nullifier ∧
    UpdatePrivateState.Checked w.updatePrivateState.previousBalance :=
  UpdatePrivateState.enabled_checks_bound_input_words h.privateUpdate

/-! ### Nullifier and chain -/

theorem circuit_nullifier_is_full_deposit_hash (h : CircuitGates e w) :
    w.updatePrivateState.nullifier = e.poseidonBytes32 (depositOf w).words ∧
    (depositOf w).words[0]? = some (depositOf w).depositIndex ∧
    (depositOf w).words[1]? = some (depositOf w).blockNumber :=
  ⟨h.nullifier, deposit_words_start_with_index _, deposit_words_have_block_second _⟩

theorem circuit_invokes_nullifier_gadget_with_deposit_nullifier (h : CircuitGates e w) :
    e.nullifierCall w.updatePrivateState.nullifierProof w.updatePrivateState.previous.nullifierRoot
      (e.poseidonBytes32 (depositOf w).words) w.upsWitness.next.nullifierRoot := by
  have := UpdatePrivateState.circuit_invokes_nullifier_gadget_with_incoming_nullifier h.privateUpdate
  rw [h.nullifier] at this
  exact this

theorem circuit_chain_always_folds_nullifier (h : CircuitGates e w) :
    w.output.pis.settledChain = e.keccak (chainPreimage w.prevFull.pis.settledChain
      (toBytes8 (e.poseidonBytes32 (depositOf w).words))) := by
  rw [h.outputStatement]
  rfl

/-- Two deposits with different indices (or any other differing field) yield
different nullifier PREIMAGES; whether the Poseidon outputs differ is the
opaque hash boundary. -/
theorem distinct_deposits_have_distinct_nullifier_preimages {d e : Deposit} (h : d ≠ e) :
    d.words ≠ e.words := fun same => h (deposit_words_injective same)

/-! ### Deposit-tree inclusion and recipient -/

theorem circuit_deposit_opens_under_output_deposit_root_at_index (h : CircuitGates e w) :
    (depositOf w).depositIndex < u63Limit ∧
    e.depositMerkleAccepted w.depositWitness.merkleProof (depositOf w) (depositOf w).depositIndex
      w.output.pis.publicState.depositRoot := by
  refine ⟨h.depositRanges.1, ?_⟩
  rw [h.outputStatement]
  show e.depositMerkleAccepted _ _ _ (publicStateOf w).depositRoot
  rw [← h.depositRoot]
  exact h.depositMerkle

theorem circuit_recipient_binds_receiver_channel_and_salt (h : CircuitGates e w) :
    (depositOf w).recipient =
      recipientOf e.poseidonBytes32 w.output.pis.channelId w.depositWitness.depositSalt := by
  rw [h.outputStatement]
  show _ = recipientOf _ (receiverId w) _
  rw [← h.depositChannel]
  exact h.depositRecipient

theorem circuit_recipient_top_byte_is_tagged (h : CircuitGates e w) :
    (depositOf w).recipient.a / 2 ^ 24 = userIdTag := by
  rw [h.depositRecipient]
  exact recipient_top_byte_is_user_id_tag _ _ _

/-! ### Statement wiring -/

theorem circuit_output_commits_the_gadget_output (h : CircuitGates e w) :
    w.output.pis.privateCommitment = rootOfHash (PrivateState.commitment e.hash
      (UpdatePrivateState.updatedState e.hash w.updatePrivateState.previous
        (e.assetRoot w.updatePrivateState.assetSiblings w.upsWitness.newLeaf w.updatePrivateState.tokenIndex)
        w.upsWitness.newNullifierRoot)) := by
  rw [h.outputStatement, ← h.privateUpdate.outputWiring]
  rfl

theorem circuit_previous_state_opens_prev_statement (h : CircuitGates e w) :
    rootOfHash (PrivateState.commitment e.hash w.updatePrivateState.previous) =
      w.prevFull.pis.privateCommitment := h.previousCommitment

theorem circuit_output_keeps_receiver_channel_and_key (h : CircuitGates e w) :
    w.output.pis.channelId = w.prevFull.pis.channelId ∧ w.output.vd = w.prevFull.vd := by
  rw [h.outputStatement]
  exact ⟨rfl, rfl⟩

theorem circuit_output_public_state_is_updated_state (h : CircuitGates e w) :
    w.output.pis.publicState = w.updatePublicState.newState ∧
    w.updatePublicState.oldState = w.prevFull.pis.publicState ∧
    UpdatePublicState.nativeVerify e.getRoot w.updatePublicState = .ok () := by
  rw [h.outputStatement]
  exact ⟨rfl, h.publicOld, UpdatePublicState.target_implies_native_local_verification h.publicUpdate⟩

theorem circuit_account_state_is_receivers_at_new_account_root (h : CircuitGates e w) :
    w.accountState.channelId = w.prevFull.pis.channelId ∧
    w.accountState.accountTreeRoot = w.output.pis.publicState.accountRoot := by
  rw [h.outputStatement]
  exact ⟨h.accountChannel, h.accountRoot⟩

theorem circuit_output_statement_has_29_words (_h : CircuitGates e w) :
    w.output.pis.words.length = balanceLength :=
  BalancePublicInputs.balance_word_count _

theorem circuit_output_block_r_is_new_block_r (h : CircuitGates e w) :
    w.output.pis.blockR = w.newBlockR := by
  rw [h.outputStatement]
  rfl

/-! ### Block window: integer readings need the Goldilocks bounds -/

theorem circuit_block_window_when_operands_bounded (h : CircuitGates e w)
    (hprev : w.prevFull.pis.blockR ≤ orderingBound) (hnew : w.newBlockR ≤ orderingBound)
    (hps : (publicStateOf w).blockNumber < u63Limit) :
    w.prevFull.pis.blockR ≤ w.output.pis.blockR ∧
    w.output.pis.blockR ≤ w.output.pis.publicState.blockNumber := by
  rw [circuit_output_block_r_is_new_block_r h, h.outputStatement]
  exact ⟨(enforce_ge_iff_le_of_lower_bounded h.newBlockRange hprev).mp h.blockLower,
    (enforce_ge_iff_le_of_lower_bounded hps hnew).mp h.blockUpper⟩

theorem circuit_deposit_block_when_bounded (h : CircuitGates e w)
    (hdep : (depositOf w).blockNumber ≤ orderingBound) :
    (depositOf w).blockNumber ≤ w.newBlockR :=
  (enforce_ge_iff_le_of_lower_bounded h.newBlockRange hdep).mp h.depositBlock

theorem circuit_outgoing_window_when_prior_send (h : CircuitGates e w)
    (priorSend : w.accountState.channelLeafPrev ≠ 0)
    (hprevRange : w.prevFull.pis.blockR < u63Limit)
    (hsend : w.accountState.sendLeafPrev ≤ orderingBound)
    (hnew : w.newBlockR + 1 ≤ orderingBound) :
    w.accountState.sendLeafPrev ≤ w.prevFull.pis.blockR ∧ w.newBlockR < w.accountState.sendLeafCur := by
  have flag : hasOutgoing w.accountState = true := (has_outgoing_iff _).mpr priorSend
  have lower := h.outgoingLower
  have upper := h.outgoingUpper
  rw [flag] at lower upper
  exact ⟨(enforce_ge_iff_le_of_lower_bounded hprevRange hsend).mp
      ((conditional_ge_true_iff _ _).mp lower),
    (enforce_gt_iff_lt_of_lower_bounded h.accountRanges.2.2.1 hnew).mp
      ((conditional_ge_true_iff _ _).mp upper)⟩

/-- Without the bounds the lower block gate is satisfiable by a wrap: the
`blockLower` obligation holds for `newBlockR = 0` against `blockR = 2^63 - 1`,
although `2^63 - 1 ≤ 0` is false. -/
theorem circuit_block_lower_gate_admits_wrap :
    EnforceGe 0 (u63Limit - 1) ∧ ¬ (u63Limit - 1 ≤ 0) :=
  ⟨enforce_ge_accepts_zero_below_top, by decide⟩

/-! ### Registered public inputs (source line 422) -/

/-- `builder.register_public_inputs(&public_inputs.to_vec(&balance_cd.config))`. -/
def registeredPublicInputs (capCount : Nat) (out : FullInputs) : BalancePublicInputs.Result (List Nat) :=
  out.toConfiguredWords capCount

theorem registered_statement_is_full_encoding (out : FullInputs) :
    registeredPublicInputs out.vd.cap.length out = .ok out.words :=
  BalancePublicInputs.configured_encoding_matches_full_shape out

theorem registered_statement_width (out : FullInputs) :
    out.words.length = balanceLength + BalancePublicInputs.verifierLength out.vd.cap.length :=
  BalancePublicInputs.full_encoding_length out

/-! ### Vacuity guard: the native path yields a satisfying witness -/

/-- Every native success, together with the sub-gadget acceptance premises the
circuit adds (proof verification, deposit and account Merkle gadgets, the
imported private/public-state gadgets, the range obligations of the checked
allocations, the target parser reading the same statement, and the new public
state's block number being a 63-bit value) is a satisfying `CircuitGates`
witness with the same output. It exhibits satisfiability only; none of the
premises is discharged. -/
theorem target_witness_of_native_success (e : Environment N P) (w : Witness N P)
    (out : FullInputs) (h : nativeToPublicInputs e w = .ok out)
    (prevFull : FullInputs) (checks : NativeChecks e w prevFull)
    (prevTarget : BalancePublicInputs.fullFromTarget e.capCount w.prevProofWords = .ok prevFull)
    (prevVerified : e.proofAccepted prevFull.vd prevFull)
    (publicPath : w.updatePublicState.proof.length = UpdatePublicState.height)
    (newStateBlockRange : w.updatePublicState.newState.blockNumber < u63Limit)
    (newBlockRange : w.newBlockR < u63Limit)
    (accountAccepted : e.accountStateAccepted w.accountState)
    (accountRanges : w.accountState.channelId < 2 ^ 32 ∧ w.accountState.sendLeafPrev < u63Limit ∧
      w.accountState.sendLeafCur < u63Limit ∧ w.accountState.channelLeafPrev < u63Limit)
    (depositChannelRange : w.depositWitness.channelId < 2 ^ 32)
    (depositRanges : DepositChecked w.depositWitness.deposit)
    (depositAccepted : e.depositMerkleAccepted w.depositWitness.merkleProof w.depositWitness.deposit
      w.depositWitness.deposit.depositIndex w.depositWitness.depositTreeRoot)
    (upsW : UpdatePrivateState.CircuitWitness)
    (upsGadget : UpdatePrivateState.CircuitGates e.hash e.assetRoot e.nullifierCall true
      w.updatePrivateState.inputs upsW)
    (upsNext : upsW.next = w.updatePrivateState.next) :
    ∃ cw : CircuitWitness N P, CircuitGates e cw ∧ cw.output = out ∧ cw.upsWitness = upsW := by
  obtain ⟨prevFull', checks', rfl⟩ := native_success_extracts e w out h
  have hp : prevFull = prevFull' := by
    have := checks.prevParse.symm.trans checks'.prevParse
    exact Except.ok.inj this
  subst hp
  obtain ⟨_, hprevRange⟩ := native_parse_bounds _ _ _ _ checks.prevParse
  obtain ⟨_, _, hrecipient⟩ := (deposit_witness_verify_ok_iff e _).mp checks.depositVerified
  refine ⟨⟨w.prevProofWords, prevFull, w.updatePublicState,
    ⟨UpdatePublicState.statesEqual w.updatePublicState.newState w.updatePublicState.oldState,
      !UpdatePublicState.statesEqual w.updatePublicState.newState w.updatePublicState.oldState,
      UpdatePublicState.expectedOldRoot e.getRoot w.updatePublicState⟩,
    w.newBlockR, w.accountState, w.depositWitness, w.updatePrivateState.inputs, upsW,
    nativeOutput e w prevFull⟩, ?_, rfl, rfl⟩
  refine ⟨prevTarget, prevVerified,
    UpdatePublicState.target_witness_of_native_local_verification _ _ publicPath checks.publicUpdate,
    newBlockRange, accountAccepted, accountRanges, depositChannelRange, depositRanges,
    depositAccepted, hrecipient, upsGadget, checks.publicOld, checks.accountChannel,
    checks.accountRoot, checks.depositChannel, checks.depositRoot, ?_, ?_, ?_, ?_, ?_,
    checks.tokenIndex, checks.amount, checks.nullifier, checks.previousCommitment, ?_⟩
  · have := checks.blockWindow
    exact enforce_ge_of_le (by dsimp only; omega) newBlockRange
  · have := checks.blockWindow
    exact enforce_ge_of_le (by dsimp only [publicStateOf]; omega) newStateBlockRange
  · apply conditional_ge_of_imp
    intro flag
    have prior := (has_outgoing_iff _).mp flag
    exact enforce_ge_of_le (checks.outgoingWindow prior).1 hprevRange
  · apply conditional_gt_of_imp
    intro flag
    have prior := (has_outgoing_iff _).mp flag
    exact enforce_gt_of_lt (checks.outgoingWindow prior).2 accountRanges.2.2.1
  · have := checks.depositBlock
    exact enforce_ge_of_le (by dsimp only [depositOf]; omega) newBlockRange
  · simp only [circuitOutput, nativeOutput, receiverId, publicStateOf, depositOf, upsNext]

/-! ## Concrete normal trace (mirrors the source unit test values) -/

theorem from_small_checked (n : Nat) (h : n < 2 ^ 32) :
    UpdatePrivateState.Checked (UpdatePrivateState.fromSmall n) := by
  intro d hd
  simp only [UpdatePrivateState.amountWords, UpdatePrivateState.fromSmall, List.mem_cons,
    List.mem_nil_iff, or_false] at hd
  rcases hd with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
  all_goals first | exact h | decide

def normalRoot : Root := ⟨1, 1, 1, 1⟩
def normalHash : Hash4 := ⟨1, 1, 1, 1⟩
def normalNullifier : Bytes32 := UpdatePrivateState.fromSmall 5
/-- `tagUserId (toBytes8 normalNullifier)`: limb 0 carries the tag byte. -/
def normalRecipient : Bytes8 := ⟨16777216, 0, 0, 0, 0, 0, 0, 5⟩

/-- Receiver last synced at block 4, new block_r 6, public state at block 8. -/
def normalPublicState : PublicState := ⟨8, 0, 0, BalancePublicInputs.Root.zero,
  normalRoot, BalancePublicInputs.Root.zero⟩

def normalVd : VerifierData := ⟨BalancePublicInputs.Root.zero, []⟩

def normalPrevFull : FullInputs :=
  ⟨⟨7, normalPublicState, 4, normalRoot, ⟨7, 7, 7, 7, 7, 7, 7, 7⟩⟩, normalVd⟩

def normalDeposit : Deposit :=
  ⟨0, 6, Address.zero, normalRecipient, 0, UpdatePrivateState.fromSmall 2,
    BalancePublicInputs.Bytes8.zero⟩

def normalPrevState : PrivateState.State :=
  ⟨PrivateState.zeroHash, PrivateState.zeroHash, PrivateState.zeroHash, PrivateState.zeroHash, 0,
    PrivateState.zeroHash⟩
def normalNextState : PrivateState.State :=
  UpdatePrivateState.updatedState (fun _ => normalHash) normalPrevState PrivateState.zeroHash
    PrivateState.zeroHash

def normalUpsInputs : UpdatePrivateState.Inputs Unit :=
  ⟨0, UpdatePrivateState.fromSmall 2, normalNullifier, normalPrevState, (),
    UpdatePrivateState.fromSmall 7, List.replicate 32 PrivateState.zeroHash⟩

def normalEnvironment : Environment Unit Unit :=
  { capCount := 0
    convertFields := fun xs => .ok xs
    hash := fun _ => normalHash
    poseidonBytes32 := fun _ => normalNullifier
    keccak := fun _ => ⟨4, 4, 4, 4, 4, 4, 4, 4⟩
    depositMerkleVerify := fun _ _ _ _ => .ok ()
    accountStateVerify := fun _ => .ok ()
    proofAccepted := fun _ _ => True
    depositMerkleAccepted := fun _ _ _ _ => True
    accountStateAccepted := fun _ => True
    getRoot := fun _ _ _ => BalancePublicInputs.Root.zero
    assetRoot := fun _ _ _ => PrivateState.zeroHash
    nullifierCall := fun _ _ _ _ => True }

def normalWitness : Witness Unit Unit :=
  { prevProofWords := normalPrevFull.words
    updatePublicState := ⟨normalPublicState, normalPublicState, UpdatePublicState.dummyProof⟩
    newBlockR := 6
    accountState := ⟨7, BalancePublicInputs.Root.zero, 0, 0, 0, ()⟩
    depositWitness := ⟨7, normalRoot, PrivateState.zeroHash, normalDeposit, ()⟩
    updatePrivateState := ⟨normalUpsInputs, normalNextState⟩ }

theorem normal_prev_statement_parses :
    BalancePublicInputs.fullFromNative (fun xs => .ok xs) 0 normalPrevFull.words = .ok normalPrevFull := by
  apply BalancePublicInputs.native_full_roundtrip
  · simp [BalancePublicInputs.AllocationChecks, normalPrevFull, normalPublicState,
      BalancePublicInputs.Bytes8.words, BalancePublicInputs.wordBase, BalancePublicInputs.blockLimit]
  · decide
  · rfl

theorem normal_recipient_is_tagged_hash :
    recipientOf normalEnvironment.poseidonBytes32 7 PrivateState.zeroHash = normalRecipient := by
  decide

theorem normal_deposit_witness_verifies :
    depositWitnessVerify normalEnvironment normalWitness.depositWitness = .ok () := by
  apply (deposit_witness_verify_ok_iff _ _).mpr
  exact ⟨by decide, rfl, normal_recipient_is_tagged_hash.symm⟩

theorem normal_native_checks : NativeChecks normalEnvironment normalWitness normalPrevFull :=
  ⟨normal_prev_statement_parses, UpdatePublicState.native_equal_verify_needs_no_root _ _ _, rfl,
    rfl, rfl, rfl, rfl, normal_deposit_witness_verifies, rfl, by decide, fun p => absurd rfl p,
    by decide, rfl, rfl, rfl, rfl⟩

theorem normal_native_admission :
    nativeToPublicInputs normalEnvironment normalWitness =
      .ok (nativeOutput normalEnvironment normalWitness normalPrevFull) :=
  (native_ok_iff _ _ _).mpr ⟨normalPrevFull, normal_native_checks, rfl⟩

theorem normal_output_credits_receiver_at_block_6 :
    (nativeOutput normalEnvironment normalWitness normalPrevFull).pis.channelId = 7 ∧
    (nativeOutput normalEnvironment normalWitness normalPrevFull).pis.blockR = 6 ∧
    (nativeOutput normalEnvironment normalWitness normalPrevFull).pis.settledChain =
      ⟨4, 4, 4, 4, 4, 4, 4, 4⟩ := ⟨rfl, rfl, rfl⟩

theorem normal_deposit_checked : DepositChecked normalDeposit :=
  ⟨by decide, by decide, by decide, by decide, by decide, from_small_checked 2 (by decide), by decide⟩

/-- The same trace as an arbitrary-witness assignment: the credited leaf is the
per-limb sum 7 + 2 = 9 of the imported AddGates relation. -/
theorem normal_circuit_witness :
    ∃ cw : CircuitWitness Unit Unit, CircuitGates normalEnvironment cw ∧
      cw.output = nativeOutput normalEnvironment normalWitness normalPrevFull ∧
      UpdatePrivateState.value cw.upsWitness.newLeaf = 9 := by
  obtain ⟨cw, gates, hout, hups⟩ := target_witness_of_native_success normalEnvironment normalWitness _
    normal_native_admission normalPrevFull normal_native_checks
    (BalancePublicInputs.full_target_roundtrip normalPrevFull) trivial
    UpdatePublicState.dummy_has_63_siblings (by decide) (by decide) trivial
    ⟨by decide, by decide, by decide, by decide⟩ (by decide) normal_deposit_checked trivial
    ⟨UpdatePrivateState.fromSmall 9, PrivateState.zeroHash, normalNextState⟩
    ⟨fun _ => ⟨by decide, from_small_checked 2 (by decide), from_small_checked 5 (by decide),
      from_small_checked 7 (by decide)⟩, rfl, trivial, rfl,
      UpdatePrivateState.normal_credit_7_plus_2, rfl⟩ rfl
  refine ⟨cw, gates, hout, ?_⟩
  rw [hups]
  exact UpdatePrivateState.normal_credit_value_9

end Zkp.Implementation.ReceiveDepositCircuit
