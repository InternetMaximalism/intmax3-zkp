import Zkp.Implementation.UpdatePrivateState
import Zkp.Implementation.UpdatePublicState

/-!
# ReceiveTransferCircuit: crediting an incoming transfer

Handwritten semantic model of src/circuits/balance/receive_transfer_circuit.rs
(1110 lines; production 1–718, tests 720–1110 read but not translated). This
is NOT a refinement proof of the Rust / plonky2 code: every theorem below is
about the Lean model, and the source-to-model correspondence is a line-map
claim only.

Two separate objects are modeled:

* `nativeToPublicInputs` — `ReceiveTransferWitness::to_public_inputs`, the
  native admission helper that `prove` runs before filling the witness. It
  parses both balance statements with the real 29-word native decoder, then
  runs the source's guards in source order with source error precedence. It
  never verifies a proof, never re-runs a Merkle opening, never re-derives the
  private-state update, and trusts the supplied `new_private_state`
  (`native_trusts_supplied_new_private_state`, `native_ignores_gadget_semantics`).
* `CircuitGates` — the constraints `ReceiveTransferTarget::new` lays down on
  an ARBITRARY satisfying witness. The private-state gadget is the imported
  `UpdatePrivateState.CircuitGates` (so the credited leaf is exactly
  `prev + amount` through the per-limb AddGates relation), the two
  public-state updates are the imported `UpdatePublicState.CircuitGates`, and
  the balance-proof verifier, account-state / tx-settlement / transfer-witness
  sub-gadgets, Poseidon recipient hash, Poseidon nullifier, keccak chain push
  and asset/nullifier Merkle roots are OPAQUE callbacks or acceptance premises
  in `Environment`. Nothing here asserts proof soundness, hash injectivity,
  Merkle soundness, nullifier freshness, finality, or "acceptance ⇒ safe".

Named boundaries (also listed in the line map): `proofAccepted` (recursive
plonky2 verification of both balance proofs under the shared verifier data),
`accountStateAccepted` / `txSettlementAccepted` / `transferWitnessAccepted`
(sub-gadget Merkle and spend-proof checks, including `spend_pis.tx == tx`),
`recipientOf` (Poseidon + tag byte), `nullifierOf` (Poseidon over the 28-word
settled-transfer preimage), `keccak` (settled-tx-chain fold), `getRoot` /
`assetRoot` / `nullifierCall` (imported gadget interfaces), `convertFields`
(native field conversion of verifier data), field lowering of `enforce_ge` /
`conditional_ge` / `is_zero` / `select` to the integer relations used here,
and the native witness-write / proving effects.
-/

namespace Zkp.Implementation.ReceiveTransferCircuit

abbrev Root := BalancePublicInputs.Root
abbrev Bytes8 := BalancePublicInputs.Bytes8
abbrev PublicState := BalancePublicInputs.PublicState
abbrev FullInputs := BalancePublicInputs.FullInputs
abbrev VerifierData := BalancePublicInputs.VerifierData
abbrev Hash4 := PrivateState.Hash4
abbrev Amount := UpdatePrivateState.Amount
/-- `Salt` is the four-element Poseidon wrapper (src/common/salt.rs). -/
abbrev Salt := PrivateState.Hash4

/-! ## Pinned constants -/

def balanceLength : Nat := 29
def transferLength : Nat := 25
def settledTransferLength : Nat := 28
def witnessWriteCount : Nat := 11
/-- `SETTLED_TX_CHAIN_DOMAIN` from src/common/balance_state.rs, the first word
of the keccak preimage used by `settled_tx_chain_push`. -/
def settledTxChainDomain : Nat := 0x494d5443

theorem balance_length_pinned : balanceLength = 29 := rfl
theorem balance_length_matches_codec : balanceLength = BalancePublicInputs.balanceLength := rfl
theorem transfer_length_pinned : transferLength = 25 := rfl
theorem settled_transfer_length_pinned : settledTransferLength = 28 := rfl
theorem witness_write_count_pinned : witnessWriteCount = 11 := rfl
theorem settled_tx_chain_domain_pinned : settledTxChainDomain = 0x494d5443 := rfl

/-- Both `PoseidonHashOut` (four u64 words) representations used by the
imports; the private-state commitment crosses from `PrivateState.Hash4` into
the balance statement's `Root`. -/
def rootOfHash (h : Hash4) : Root := ⟨h.a, h.b, h.c, h.d⟩

theorem root_of_hash_injective {a b : Hash4} (h : rootOfHash a = rootOfHash b) : a = b := by
  cases a; cases b
  simp only [rootOfHash, BalancePublicInputs.Root.mk.injEq] at h
  obtain ⟨rfl, rfl, rfl, rfl⟩ := h
  rfl

/-! ## Data carried by the witness (fields this file reads) -/

/-- `Transfer` (src/common/transfer.rs): recipient, token index, U256 amount,
merkle-bound aux data. -/
structure Transfer where
  recipient : Bytes8
  tokenIndex : Nat
  amount : Amount
  auxData : Bytes8
  deriving DecidableEq, Repr

/-- `Transfer::to_u64_vec`: recipient limbs, token index, amount limbs, aux limbs. -/
def Transfer.words (t : Transfer) : List Nat :=
  t.recipient.words ++ [t.tokenIndex] ++ UpdatePrivateState.amountWords t.amount ++ t.auxData.words

theorem transfer_has_25_words (t : Transfer) : t.words.length = transferLength := by
  simp [Transfer.words, BalancePublicInputs.Bytes8.words, UpdatePrivateState.amountWords, transferLength]

/-- `SettledTransfer::new(transfer, from, transfer_index, nonce)` — the
nullifier preimage (source lines 283–289 / 478–484). -/
structure SettledTransfer where
  inner : Transfer
  sender : Nat
  transferIndex : Nat
  nonce : Nat
  deriving DecidableEq, Repr

/-- `SettledTransfer::to_u64_vec`: transfer words, then from, index, nonce. -/
def SettledTransfer.words (s : SettledTransfer) : List Nat :=
  s.inner.words ++ [s.sender] ++ [s.transferIndex] ++ [s.nonce]

theorem settled_transfer_has_28_words (s : SettledTransfer) :
    s.words.length = settledTransferLength := by
  simp [SettledTransfer.words, Transfer.words, BalancePublicInputs.Bytes8.words,
    UpdatePrivateState.amountWords, settledTransferLength]

/-- The nullifier preimage separates transfers by sender channel, transfer
index and sender nonce: equal preimages have equal components. This is a fact
about the preimage layout, not about the Poseidon output. -/
theorem settled_transfer_words_injective {s t : SettledTransfer} (h : s.words = t.words) :
    s = t := by
  obtain ⟨⟨sr, si, sa, sx⟩, sf, sn, sc⟩ := s
  obtain ⟨⟨tr, ti, ta, tx⟩, tf, tn, tc⟩ := t
  cases sr; cases tr; cases sa; cases ta; cases sx; cases tx
  simp only [SettledTransfer.words, Transfer.words, BalancePublicInputs.Bytes8.words,
    UpdatePrivateState.amountWords, List.cons_append, List.nil_append, List.cons.injEq] at h
  obtain ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl,
    rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, _⟩ := h
  rfl

/-- `TransferWitness`: the transfer leaf, its index and (opaque) Merkle proof
against `transfer_tree_root`. Verification of the proof is the imported
gadget, not this file. -/
structure TransferWitness (P : Type) where
  transferTreeRoot : Root
  transfer : Transfer
  transferIndex : Nat
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

/-- The two `Tx` fields this file reads. -/
structure Tx where
  transferTreeRoot : Root
  nonce : Nat
  deriving DecidableEq, Repr

/-- `SpendPublicInputs` (spend_circuit.rs) as parsed from the settlement's
spend proof. -/
structure SpendPublicInputs where
  prevPrivateCommitment : Root
  newPrivateCommitment : Root
  tx : Tx
  isValid : Bool
  deriving DecidableEq, Repr

/-- `TxSettlement`: sender channel, settled tx, public state, the sender's
account state at settlement, and opaque tx Merkle proof / spend proof. -/
structure TxSettlement (S P : Type) where
  channelId : Nat
  tx : Tx
  publicState : PublicState
  accountState : AccountState P
  txMerkleProof : P
  spendProof : S

/-- `TxSettlement::tx_block_number` = `account_state.send_leaf.cur`. -/
def txBlockNumber (t : TxSettlement S P) : Nat := t.accountState.sendLeafCur

/-! ## Opaque dependencies -/

/-- Every callee whose semantics this file does not define. `Prop`-valued
fields are acceptance premises of sub-gadgets that the CIRCUIT lays down and
the NATIVE helper never evaluates. -/
structure Environment (N S P : Type) where
  /-- `balance_cd.config` cap count used by both balance-statement codecs. -/
  capCount : Nat
  /-- `ToField::to_field_vec` on the verifier-data suffix (may fail). -/
  convertFields : List Nat → BalancePublicInputs.Result (List Nat)
  /-- Poseidon `hash_inputs` for the private-state commitment. -/
  hash : List Nat → Hash4
  /-- `calculate_recipient_from_user_id(channel, salt)`: Poseidon + tag byte. -/
  recipientOf : Nat → Salt → Bytes8
  /-- `SettledTransfer::nullifier`: Poseidon over the 28-word preimage. -/
  nullifierOf : List Nat → UpdatePrivateState.Bytes32
  /-- keccak256 over u32 words, used by `settled_tx_chain_push`. -/
  keccak : List Nat → Bytes8
  /-- Native `TxSettlement::spend_pis` (parse of the spend proof's inputs). -/
  spendPis : S → Except String SpendPublicInputs
  /-- Target `SpendPublicInputsTarget::from_pis` (wire projection, total). -/
  spendPisTarget : S → SpendPublicInputs
  /-- `builder.verify_proof` of a balance proof with the given statement under
  the given verifier data. -/
  proofAccepted : VerifierData → FullInputs → Prop
  /-- Imported `UpdatePublicState` Merkle-root call. -/
  getRoot : UpdatePublicState.RootCall
  /-- Imported `UpdatePrivateState` asset-root call. -/
  assetRoot : List Hash4 → Amount → Nat → Hash4
  /-- Imported `UpdatePrivateState` nullifier-insertion gadget relation. -/
  nullifierCall : N → Hash4 → Amount → Hash4 → Prop
  /-- `AccountStateTarget::new(_, true)`: send/channel leaf openings. -/
  accountStateAccepted : AccountState P → Prop
  /-- `TxSettlementTarget::new`: tx opening, spend-proof verification and
  `tx.connect(spend_pis.tx)`. -/
  txSettlementAccepted : TxSettlement S P → Prop
  /-- `TransferWitnessTarget::new(_, true)`: transfer-leaf opening. -/
  transferWitnessAccepted : TransferWitness P → Prop

/-- `settled_tx_chain_push` preimage: domain word, 8 chain limbs, 8 leaf limbs. -/
def chainPreimage (chain leaf : Bytes8) : List Nat :=
  [settledTxChainDomain] ++ chain.words ++ leaf.words

theorem chain_preimage_has_17_words (chain leaf : Bytes8) : (chainPreimage chain leaf).length = 17 := by
  simp [chainPreimage, BalancePublicInputs.Bytes8.words]

def chainPush (keccak : List Nat → Bytes8) (chain leaf : Bytes8) : Bytes8 :=
  keccak (chainPreimage chain leaf)

/-- Source lines 322–326 / 514–526: fold only when `aux_data != 0`. -/
def foldChain (keccak : List Nat → Bytes8) (chain aux : Bytes8) : Bytes8 :=
  if aux = BalancePublicInputs.Bytes8.zero then chain else chainPush keccak chain aux

theorem fold_chain_unchanged_when_aux_zero (keccak : List Nat → Bytes8) (chain : Bytes8) :
    foldChain keccak chain BalancePublicInputs.Bytes8.zero = chain := by
  simp [foldChain]

theorem fold_chain_pushes_when_aux_nonzero (keccak : List Nat → Bytes8) (chain aux : Bytes8)
    (nonzero : aux ≠ BalancePublicInputs.Bytes8.zero) :
    foldChain keccak chain aux = keccak (chainPreimage chain aux) := by
  simp [foldChain, chainPush, nonzero]

/-! ## Native admission: `ReceiveTransferWitness::to_public_inputs` -/

/-- `ReceiveTransferError`, in source order. -/
inductive Error where
  | connection (detail : String)
  | balancePublicInputs (fault : BalancePublicInputs.Fault)
  | invalidBalanceProof (detail : String)
  | invalidBalanceVd
  | invalidRecipient
  | blockNumber (detail : String)
  | spendPis (detail : String)
  | failedToProve (detail : String)
  deriving DecidableEq, Repr

abbrev Result (α : Type) := Except Error α

/-- `ReceiveTransferWitness` (source lines 76–114). The two balance proofs are
represented by their public-input words only; the proof bodies are never read
by the native helper. -/
structure Witness (N S P : Type) where
  prevProofWords : List Nat
  senderProofWords : List Nat
  senderUpdatePublicState : UpdatePublicState.Update
  receiverUpdatePublicState : UpdatePublicState.Update
  newBlockR : Nat
  accountState : AccountState P
  txSettlement : TxSettlement S P
  transferWitness : TransferWitness P
  transferSalt : Salt
  /-- The already-built native `UpdatePrivateState` (inputs + `new_private_state`). -/
  updatePrivateState : UpdatePrivateState.Output N

def check (p : Prop) [Decidable p] (e : Error) : Result Unit :=
  if p then .ok () else .error e

def parseFull (e : Environment N S P) (words : List Nat) : Result FullInputs :=
  match BalancePublicInputs.fullFromNative e.convertFields e.capCount words with
  | .error fault => .error (.balancePublicInputs fault)
  | .ok full => .ok full

def spendOrError (e : Environment N S P) (proof : S) : Result SpendPublicInputs :=
  match e.spendPis proof with
  | .error detail => .error (.spendPis detail)
  | .ok pis => .ok pis

/-- Source lines 229–245: extra window checks only when the receiver has a
previous outgoing tx (`channel_leaf.prev != 0`). -/
def outgoingWindowCheck (prevBlockR : Nat) (a : AccountState P) (newBlockR : Nat) : Result Unit :=
  if a.channelLeafPrev = 0 then .ok ()
  else if prevBlockR < a.sendLeafPrev then .error (.blockNumber "send_leaf.prev")
  else if a.sendLeafCur ≤ newBlockR then .error (.blockNumber "send_leaf.cur")
  else .ok ()

/-- Native nullifier preimage: `from` is the SENDER balance statement's channel. -/
def nativeSettledTransfer (w : Witness N S P) (senderFull : FullInputs) : SettledTransfer :=
  ⟨w.transferWitness.transfer, senderFull.pis.channelId, w.transferWitness.transferIndex,
    w.txSettlement.tx.nonce⟩

/-- Source lines 317–337: the new 29-word statement plus the shared verifier data. -/
def nativeOutput (e : Environment N S P) (w : Witness N S P) (prevFull : FullInputs) : FullInputs :=
  ⟨⟨prevFull.pis.channelId, w.receiverUpdatePublicState.newState, w.newBlockR,
    rootOfHash (PrivateState.commitment e.hash w.updatePrivateState.next),
    foldChain e.keccak prevFull.pis.settledChain w.transferWitness.transfer.auxData⟩,
   prevFull.vd⟩

def nativeToPublicInputs (e : Environment N S P) (w : Witness N S P) : Result FullInputs := do
  let prevFull ← parseFull e w.prevProofWords
  let senderFull ← parseFull e w.senderProofWords
  check (prevFull.vd = senderFull.vd) .invalidBalanceVd
  check (w.receiverUpdatePublicState.oldState = prevFull.pis.publicState)
    (.connection "receiver_update_public_state.old")
  check (w.senderUpdatePublicState.oldState = senderFull.pis.publicState)
    (.connection "sender_update_public_state.old")
  check (w.receiverUpdatePublicState.newState = w.senderUpdatePublicState.newState)
    (.connection "update_public_state.new")
  check (w.accountState.channelId = prevFull.pis.channelId) (.connection "account_state.channel_id")
  check (w.accountState.accountTreeRoot = w.receiverUpdatePublicState.newState.accountRoot)
    (.connection "account_state.account_tree_root")
  check (w.txSettlement.channelId = senderFull.pis.channelId) (.connection "tx_settlement.channel_id")
  check (w.txSettlement.publicState = w.receiverUpdatePublicState.newState)
    (.connection "tx_settlement.public_state")
  check (w.transferWitness.transferTreeRoot = w.txSettlement.tx.transferTreeRoot)
    (.connection "transfer_witness.transfer_tree_root")
  check (w.transferWitness.transfer.recipient = e.recipientOf prevFull.pis.channelId w.transferSalt)
    .invalidRecipient
  check (¬ (w.newBlockR < prevFull.pis.blockR ∨
      w.receiverUpdatePublicState.newState.blockNumber < w.newBlockR)) (.blockNumber "new_block_r")
  outgoingWindowCheck prevFull.pis.blockR w.accountState w.newBlockR
  check (¬ w.newBlockR < txBlockNumber w.txSettlement) (.blockNumber "tx_block_number")
  let spend ← spendOrError e w.txSettlement.spendProof
  check (senderFull.pis.privateCommitment = spend.prevPrivateCommitment)
    (.connection "spend_pis.prev_private_commitment")
  check (spend.isValid = true) (.connection "spend_pis.is_valid")
  check (w.updatePrivateState.inputs.tokenIndex = w.transferWitness.transfer.tokenIndex)
    (.connection "update_private_state.token_index")
  check (w.updatePrivateState.inputs.amount = w.transferWitness.transfer.amount)
    (.connection "update_private_state.amount")
  check (w.updatePrivateState.inputs.nullifier = e.nullifierOf (nativeSettledTransfer w senderFull).words)
    (.connection "update_private_state.nullifier")
  check (rootOfHash (PrivateState.commitment e.hash w.updatePrivateState.inputs.previous) =
      prevFull.pis.privateCommitment) (.connection "update_private_state.prev_private_state.commitment")
  return nativeOutput e w prevFull

/-! ### Except helpers (same shape as ChannelStateUpdate) -/

theorem check_ok_iff (p : Prop) [Decidable p] (e : Error) : check p e = .ok () ↔ p := by
  by_cases h : p <;> simp [check, h]

theorem bind_ok_iff {α β : Type} (r : Result α) (f : α → Result β) (value : β) :
    (r >>= f) = .ok value ↔ ∃ x, r = .ok x ∧ f x = .ok value := by
  cases r <;> simp [Bind.bind, Except.bind]

theorem exists_unit (p : Unit → Prop) : (∃ x, p x) ↔ p () := by
  constructor
  · rintro ⟨⟨⟩, h⟩; exact h
  · intro h; exact ⟨(), h⟩

theorem pure_ok_iff {α : Type} (a b : α) : (pure a : Result α) = .ok b ↔ a = b := by
  constructor
  · intro h; exact Except.ok.inj h
  · intro h; subst h; rfl

theorem parse_ok_iff (e : Environment N S P) (words : List Nat) (full : FullInputs) :
    parseFull e words = .ok full ↔
      BalancePublicInputs.fullFromNative e.convertFields e.capCount words = .ok full := by
  cases h : BalancePublicInputs.fullFromNative e.convertFields e.capCount words <;> simp [parseFull, h]

theorem parse_error_maps_fault (e : Environment N S P) (words : List Nat)
    (fault : BalancePublicInputs.Fault)
    (h : BalancePublicInputs.fullFromNative e.convertFields e.capCount words = .error fault) :
    parseFull e words = .error (.balancePublicInputs fault) := by
  simp [parseFull, h]

theorem spend_ok_iff (e : Environment N S P) (proof : S) (pis : SpendPublicInputs) :
    spendOrError e proof = .ok pis ↔ e.spendPis proof = .ok pis := by
  cases h : e.spendPis proof <;> simp [spendOrError, h]

theorem outgoing_ok_iff (prevBlockR : Nat) (a : AccountState P) (newBlockR : Nat) :
    outgoingWindowCheck prevBlockR a newBlockR = .ok () ↔
      (a.channelLeafPrev ≠ 0 → a.sendLeafPrev ≤ prevBlockR ∧ newBlockR < a.sendLeafCur) := by
  unfold outgoingWindowCheck
  by_cases h0 : a.channelLeafPrev = 0
  · simp [h0]
  · by_cases h1 : prevBlockR < a.sendLeafPrev
    · simp [h0, h1] <;> omega
    · by_cases h2 : a.sendLeafCur ≤ newBlockR
      · simp [h0, h1, h2] <;> omega
      · simp [h0, h1, h2] <;> omega

/-! ### The native guard bundle -/

/-- Everything `to_public_inputs` checks, in source order. No proof is
verified, no Merkle path is opened, and `updatePrivateState.next` is not
inspected. -/
structure NativeChecks (e : Environment N S P) (w : Witness N S P)
    (prevFull senderFull : FullInputs) (spend : SpendPublicInputs) : Prop where
  prevParse : BalancePublicInputs.fullFromNative e.convertFields e.capCount w.prevProofWords = .ok prevFull
  senderParse : BalancePublicInputs.fullFromNative e.convertFields e.capCount w.senderProofWords = .ok senderFull
  sharedVerifierData : prevFull.vd = senderFull.vd
  receiverOld : w.receiverUpdatePublicState.oldState = prevFull.pis.publicState
  senderOld : w.senderUpdatePublicState.oldState = senderFull.pis.publicState
  newStatesAgree : w.receiverUpdatePublicState.newState = w.senderUpdatePublicState.newState
  accountChannel : w.accountState.channelId = prevFull.pis.channelId
  accountRoot : w.accountState.accountTreeRoot = w.receiverUpdatePublicState.newState.accountRoot
  settlementChannel : w.txSettlement.channelId = senderFull.pis.channelId
  settlementPublicState : w.txSettlement.publicState = w.receiverUpdatePublicState.newState
  transferRoot : w.transferWitness.transferTreeRoot = w.txSettlement.tx.transferTreeRoot
  recipient : w.transferWitness.transfer.recipient = e.recipientOf prevFull.pis.channelId w.transferSalt
  blockWindow : ¬ (w.newBlockR < prevFull.pis.blockR ∨
    w.receiverUpdatePublicState.newState.blockNumber < w.newBlockR)
  outgoingWindow : w.accountState.channelLeafPrev ≠ 0 →
    w.accountState.sendLeafPrev ≤ prevFull.pis.blockR ∧ w.newBlockR < w.accountState.sendLeafCur
  settlementBlock : ¬ w.newBlockR < txBlockNumber w.txSettlement
  spendParse : e.spendPis w.txSettlement.spendProof = .ok spend
  spendCommitment : senderFull.pis.privateCommitment = spend.prevPrivateCommitment
  spendValid : spend.isValid = true
  tokenIndex : w.updatePrivateState.inputs.tokenIndex = w.transferWitness.transfer.tokenIndex
  amount : w.updatePrivateState.inputs.amount = w.transferWitness.transfer.amount
  nullifier : w.updatePrivateState.inputs.nullifier =
    e.nullifierOf (nativeSettledTransfer w senderFull).words
  previousCommitment : rootOfHash (PrivateState.commitment e.hash w.updatePrivateState.inputs.previous) =
    prevFull.pis.privateCommitment

theorem native_ok_iff (e : Environment N S P) (w : Witness N S P) (out : FullInputs) :
    nativeToPublicInputs e w = .ok out ↔
      ∃ prevFull senderFull spend, NativeChecks e w prevFull senderFull spend ∧
        out = nativeOutput e w prevFull := by
  constructor
  · intro accepted
    simp only [nativeToPublicInputs, bind_ok_iff, exists_unit, pure_ok_iff, check_ok_iff,
      parse_ok_iff, spend_ok_iff, outgoing_ok_iff] at accepted
    obtain ⟨prevFull, hPrev, senderFull, hSender, hVd, hRecvOld, hSendOld, hNew, hAccCh, hAccRoot,
      hTxCh, hTxPs, hTrRoot, hRecip, hWindow, hOut, hTxBlock, spend, hSpend, hSpendC, hSpendV,
      hTok, hAmt, hNul, hPrevC, hEq⟩ := accepted
    exact ⟨prevFull, senderFull, spend, ⟨hPrev, hSender, hVd, hRecvOld, hSendOld, hNew, hAccCh,
      hAccRoot, hTxCh, hTxPs, hTrRoot, hRecip, hWindow, hOut, hTxBlock, hSpend, hSpendC, hSpendV,
      hTok, hAmt, hNul, hPrevC⟩, hEq.symm⟩
  · rintro ⟨prevFull, senderFull, spend, c, rfl⟩
    simp only [nativeToPublicInputs, bind_ok_iff, exists_unit, pure_ok_iff, check_ok_iff,
      parse_ok_iff, spend_ok_iff, outgoing_ok_iff]
    exact ⟨prevFull, c.prevParse, senderFull, c.senderParse, c.sharedVerifierData, c.receiverOld,
      c.senderOld, c.newStatesAgree, c.accountChannel, c.accountRoot, c.settlementChannel,
      c.settlementPublicState, c.transferRoot, c.recipient, c.blockWindow, c.outgoingWindow,
      c.settlementBlock, spend, c.spendParse, c.spendCommitment, c.spendValid, c.tokenIndex,
      c.amount, c.nullifier, c.previousCommitment, rfl⟩

theorem native_success_extracts (e : Environment N S P) (w : Witness N S P) (out : FullInputs)
    (h : nativeToPublicInputs e w = .ok out) :
    ∃ prevFull senderFull spend, NativeChecks e w prevFull senderFull spend ∧
      out = nativeOutput e w prevFull :=
  (native_ok_iff e w out).mp h

/-! ### Error precedence (first three guards) -/

theorem native_prev_parse_failure_first (e : Environment N S P) (w : Witness N S P)
    (fault : BalancePublicInputs.Fault)
    (h : BalancePublicInputs.fullFromNative e.convertFields e.capCount w.prevProofWords = .error fault) :
    nativeToPublicInputs e w = .error (.balancePublicInputs fault) := by
  simp [nativeToPublicInputs, parse_error_maps_fault e _ fault h, Bind.bind, Except.bind]

theorem native_sender_parse_failure_second (e : Environment N S P) (w : Witness N S P)
    (prevFull : FullInputs) (fault : BalancePublicInputs.Fault)
    (hp : BalancePublicInputs.fullFromNative e.convertFields e.capCount w.prevProofWords = .ok prevFull)
    (h : BalancePublicInputs.fullFromNative e.convertFields e.capCount w.senderProofWords = .error fault) :
    nativeToPublicInputs e w = .error (.balancePublicInputs fault) := by
  have hp' : parseFull e w.prevProofWords = .ok prevFull := (parse_ok_iff e _ _).mpr hp
  simp [nativeToPublicInputs, hp', parse_error_maps_fault e _ fault h, Bind.bind, Except.bind]

theorem native_verifier_data_mismatch_third (e : Environment N S P) (w : Witness N S P)
    (prevFull senderFull : FullInputs)
    (hp : BalancePublicInputs.fullFromNative e.convertFields e.capCount w.prevProofWords = .ok prevFull)
    (hs : BalancePublicInputs.fullFromNative e.convertFields e.capCount w.senderProofWords = .ok senderFull)
    (different : prevFull.vd ≠ senderFull.vd) :
    nativeToPublicInputs e w = .error .invalidBalanceVd := by
  have hp' : parseFull e w.prevProofWords = .ok prevFull := (parse_ok_iff e _ _).mpr hp
  have hs' : parseFull e w.senderProofWords = .ok senderFull := (parse_ok_iff e _ _).mpr hs
  simp [nativeToPublicInputs, hp', hs', check, different, Bind.bind, Except.bind]

/-! ### Facts derived from native success -/

theorem native_success_block_window (e : Environment N S P) (w : Witness N S P) (out : FullInputs)
    (h : nativeToPublicInputs e w = .ok out) :
    ∃ prevFull, BalancePublicInputs.fullFromNative e.convertFields e.capCount w.prevProofWords = .ok prevFull ∧
      prevFull.pis.blockR ≤ w.newBlockR ∧ w.newBlockR ≤ out.pis.publicState.blockNumber ∧
      txBlockNumber w.txSettlement ≤ w.newBlockR ∧ out.pis.blockR = w.newBlockR := by
  obtain ⟨prevFull, senderFull, spend, c, rfl⟩ := native_success_extracts e w out h
  refine ⟨prevFull, c.prevParse, ?_, ?_, ?_, rfl⟩
  · have := c.blockWindow; omega
  · have := c.blockWindow; simp only [nativeOutput]; omega
  · have := c.settlementBlock; omega

theorem native_success_credits_transfer_token_and_amount (e : Environment N S P) (w : Witness N S P)
    (out : FullInputs) (h : nativeToPublicInputs e w = .ok out) :
    w.updatePrivateState.inputs.tokenIndex = w.transferWitness.transfer.tokenIndex ∧
    w.updatePrivateState.inputs.amount = w.transferWitness.transfer.amount := by
  obtain ⟨_, _, _, c, _⟩ := native_success_extracts e w out h
  exact ⟨c.tokenIndex, c.amount⟩

theorem native_success_binds_nullifier_to_sender_index_nonce (e : Environment N S P)
    (w : Witness N S P) (out : FullInputs) (h : nativeToPublicInputs e w = .ok out) :
    ∃ senderFull, BalancePublicInputs.fullFromNative e.convertFields e.capCount w.senderProofWords = .ok senderFull ∧
      w.txSettlement.channelId = senderFull.pis.channelId ∧
      w.updatePrivateState.inputs.nullifier = e.nullifierOf
        (SettledTransfer.words ⟨w.transferWitness.transfer, senderFull.pis.channelId,
          w.transferWitness.transferIndex, w.txSettlement.tx.nonce⟩) := by
  obtain ⟨_, senderFull, _, c, _⟩ := native_success_extracts e w out h
  exact ⟨senderFull, c.senderParse, c.settlementChannel, c.nullifier⟩

theorem native_success_recipient_is_receiver_channel_with_salt (e : Environment N S P)
    (w : Witness N S P) (out : FullInputs) (h : nativeToPublicInputs e w = .ok out) :
    w.transferWitness.transfer.recipient = e.recipientOf out.pis.channelId w.transferSalt := by
  obtain ⟨_, _, _, c, rfl⟩ := native_success_extracts e w out h
  exact c.recipient

theorem native_success_output_shape (e : Environment N S P) (w : Witness N S P) (out : FullInputs)
    (h : nativeToPublicInputs e w = .ok out) :
    out.pis.publicState = w.receiverUpdatePublicState.newState ∧
    out.pis.publicState = w.txSettlement.publicState ∧
    out.pis.privateCommitment = rootOfHash (PrivateState.commitment e.hash w.updatePrivateState.next) ∧
    out.pis.words.length = balanceLength := by
  obtain ⟨_, _, _, c, rfl⟩ := native_success_extracts e w out h
  exact ⟨rfl, c.settlementPublicState.symm, rfl, BalancePublicInputs.balance_word_count _⟩

/-- Replace only the claimed `new_private_state`. -/
def Witness.withNext (w : Witness N S P) (s : PrivateState.State) : Witness N S P :=
  { w with updatePrivateState := { w.updatePrivateState with next := s } }

/-- No native guard reads `updatePrivateState.next`: every check survives a
replacement of the claimed `new_private_state`. -/
theorem native_checks_ignore_next (e : Environment N S P) (w : Witness N S P) (s : PrivateState.State)
    (prevFull senderFull : FullInputs) (spend : SpendPublicInputs)
    (c : NativeChecks e w prevFull senderFull spend) :
    NativeChecks e (w.withNext s) prevFull senderFull spend :=
  ⟨c.prevParse, c.senderParse, c.sharedVerifierData, c.receiverOld, c.senderOld, c.newStatesAgree,
    c.accountChannel, c.accountRoot, c.settlementChannel, c.settlementPublicState, c.transferRoot,
    c.recipient, c.blockWindow, c.outgoingWindow, c.settlementBlock, c.spendParse, c.spendCommitment,
    c.spendValid, c.tokenIndex, c.amount, c.nullifier, c.previousCommitment⟩

/-- The native helper does not recompute the private-state update: whatever
`new_private_state` the caller supplies is committed unchanged into the output
statement, with every other check unaffected. This is what the CIRCUIT's
`UpdatePrivateState.CircuitGates` adds and the native path does not. -/
theorem native_trusts_supplied_new_private_state (e : Environment N S P) (w : Witness N S P)
    (out : FullInputs) (h : nativeToPublicInputs e w = .ok out) (s : PrivateState.State) :
    ∃ out', nativeToPublicInputs e (w.withNext s) = .ok out' ∧
      out'.pis.privateCommitment = rootOfHash (PrivateState.commitment e.hash s) ∧
      out'.pis.channelId = out.pis.channelId ∧ out'.pis.publicState = out.pis.publicState ∧
      out'.pis.blockR = out.pis.blockR ∧ out'.pis.settledChain = out.pis.settledChain ∧
      out'.vd = out.vd := by
  obtain ⟨prevFull, senderFull, spend, c, rfl⟩ := native_success_extracts e w out h
  refine ⟨nativeOutput e (w.withNext s) prevFull, ?_, rfl, rfl, rfl, rfl, rfl, rfl⟩
  exact (native_ok_iff e _ _).mpr
    ⟨prevFull, senderFull, spend, native_checks_ignore_next e w s prevFull senderFull spend c, rfl⟩

/-- Swap every gadget-acceptance premise and gadget interface for arbitrary ones. -/
def Environment.withGadgets (e : Environment N S P)
    (proofAccepted : VerifierData → FullInputs → Prop) (getRoot : UpdatePublicState.RootCall)
    (assetRoot : List Hash4 → Amount → Nat → Hash4)
    (nullifierCall : N → Hash4 → Amount → Hash4 → Prop)
    (accountStateAccepted : AccountState P → Prop) (txSettlementAccepted : TxSettlement S P → Prop)
    (transferWitnessAccepted : TransferWitness P → Prop) (spendPisTarget : S → SpendPublicInputs) :
    Environment N S P :=
  { e with
    proofAccepted := proofAccepted
    getRoot := getRoot
    assetRoot := assetRoot
    nullifierCall := nullifierCall
    accountStateAccepted := accountStateAccepted
    txSettlementAccepted := txSettlementAccepted
    transferWitnessAccepted := transferWitnessAccepted
    spendPisTarget := spendPisTarget }

/-- Native admission never evaluates proof verification, Merkle openings, the
nullifier gadget or the target spend-PI projection: its result is invariant
under any replacement of those interfaces. -/
theorem native_ignores_gadget_semantics (e : Environment N S P) (w : Witness N S P)
    (proofAccepted : VerifierData → FullInputs → Prop) (getRoot : UpdatePublicState.RootCall)
    (assetRoot : List Hash4 → Amount → Nat → Hash4)
    (nullifierCall : N → Hash4 → Amount → Hash4 → Prop)
    (accountStateAccepted : AccountState P → Prop) (txSettlementAccepted : TxSettlement S P → Prop)
    (transferWitnessAccepted : TransferWitness P → Prop) (spendPisTarget : S → SpendPublicInputs) :
    nativeToPublicInputs (e.withGadgets proofAccepted getRoot assetRoot nullifierCall
      accountStateAccepted txSettlementAccepted transferWitnessAccepted spendPisTarget) w =
    nativeToPublicInputs e w := by
  cases e
  rfl

/-! ## `prove` (source lines 697–709) -/

/-- `ReceiveTransferCircuit::prove`: native admission first, then the opaque
prover over the same statement. -/
def prove (e : Environment N S P) (prover : Witness N S P → FullInputs → Except String Pf)
    (w : Witness N S P) : Result Pf :=
  match nativeToPublicInputs e w with
  | .error err => .error err
  | .ok pis =>
    match prover w pis with
    | .error detail => .error (.failedToProve detail)
    | .ok proof => .ok proof

theorem prove_requires_native_admission (e : Environment N S P)
    (prover : Witness N S P → FullInputs → Except String Pf) (w : Witness N S P) (proof : Pf)
    (h : prove e prover w = .ok proof) :
    ∃ pis, nativeToPublicInputs e w = .ok pis ∧ prover w pis = .ok proof := by
  unfold prove at h
  cases hn : nativeToPublicInputs e w with
  | error err => simp [hn] at h
  | ok pis =>
    cases hp : prover w pis with
    | error d => simp [hn, hp] at h
    | ok p =>
      simp [hn, hp] at h
      exact ⟨pis, rfl, by rw [hp, h]⟩

theorem prove_failure_precedence (e : Environment N S P)
    (prover : Witness N S P → FullInputs → Except String Pf) (w : Witness N S P) (err : Error)
    (h : nativeToPublicInputs e w = .error err) : prove e prover w = .error err := by
  simp [prove, h]

/-! ## Witness writes (source lines 555–583) -/

inductive Write where
  | prevBalanceProof | senderBalanceProof | senderUpdatePublicState | receiverUpdatePublicState
  | newBlockR | accountState | txSettlement | transferWitness | transferSalt | updatePrivateState
  | newFullPis
  deriving DecidableEq, Repr

def witnessWrites : List Write :=
  [.prevBalanceProof, .senderBalanceProof, .senderUpdatePublicState, .receiverUpdatePublicState,
   .newBlockR, .accountState, .txSettlement, .transferWitness, .transferSalt, .updatePrivateState,
   .newFullPis]

theorem witness_write_count : witnessWrites.length = witnessWriteCount := rfl

theorem witness_writes_derived_statement_last : witnessWrites[10]? = some .newFullPis := rfl

/-! ## Constructor program (source lines 368–400) -/

inductive BuildOp where
  | virtualBalanceProof (sender : Bool)
  | parseFullPis (sender : Bool)
  | connectVerifierData
  | verifyBalanceProof (sender : Bool)
  | updatePublicState (sender : Bool)
  | blockNumber (checked : Bool)
  | accountState (checked : Bool)
  | txSettlement (checked : Bool)
  | transferWitness (checked : Bool)
  | salt
  | updatePrivateState (checked : Bool)
  deriving DecidableEq, Repr

def buildPlan : List BuildOp :=
  [.virtualBalanceProof false, .parseFullPis false, .virtualBalanceProof true, .parseFullPis true,
   .connectVerifierData, .verifyBalanceProof false, .verifyBalanceProof true,
   .updatePublicState true, .updatePublicState false, .blockNumber true, .accountState true,
   .txSettlement true, .transferWitness true, .salt, .updatePrivateState true]

theorem both_balance_proofs_verified_after_key_connection :
    buildPlan[4]? = some .connectVerifierData ∧ buildPlan[5]? = some (.verifyBalanceProof false) ∧
    buildPlan[6]? = some (.verifyBalanceProof true) := ⟨rfl, rfl, rfl⟩

theorem every_sub_gadget_is_checked_allocation :
    buildPlan[9]? = some (.blockNumber true) ∧ buildPlan[10]? = some (.accountState true) ∧
    buildPlan[11]? = some (.txSettlement true) ∧ buildPlan[12]? = some (.transferWitness true) ∧
    buildPlan[14]? = some (.updatePrivateState true) := ⟨rfl, rfl, rfl, rfl, rfl⟩

/-! ## Arbitrary satisfying witness: `ReceiveTransferTarget::new` -/

/-- Wires of one satisfying assignment. The balance statements are what
`BalanceFullPublicInputsTarget::from_pis` reads from the proof wires. -/
structure CircuitWitness (N S P : Type) where
  prevProofWords : List Nat
  senderProofWords : List Nat
  prevFull : FullInputs
  senderFull : FullInputs
  senderUpdatePublicState : UpdatePublicState.Update
  senderUpsWitness : UpdatePublicState.Witness
  receiverUpdatePublicState : UpdatePublicState.Update
  receiverUpsWitness : UpdatePublicState.Witness
  newBlockR : Nat
  accountState : AccountState P
  txSettlement : TxSettlement S P
  transferWitness : TransferWitness P
  transferSalt : Salt
  updatePrivateState : UpdatePrivateState.Inputs N
  upsWitness : UpdatePrivateState.CircuitWitness
  output : FullInputs

def receiverId (w : CircuitWitness N S P) : Nat := w.prevFull.pis.channelId
def senderId (w : CircuitWitness N S P) : Nat := w.senderFull.pis.channelId
def publicStateOf (w : CircuitWitness N S P) : PublicState := w.receiverUpdatePublicState.newState

/-- In-circuit `SettledTransferTarget { inner, from: tx_settlement.channel_id,
transfer_index, nonce: tx.nonce }`. -/
def settledTransferOf (w : CircuitWitness N S P) : SettledTransfer :=
  ⟨w.transferWitness.transfer, w.txSettlement.channelId, w.transferWitness.transferIndex,
    w.txSettlement.tx.nonce⟩

def circuitOutput (e : Environment N S P) (w : CircuitWitness N S P) : FullInputs :=
  ⟨⟨receiverId w, publicStateOf w, w.newBlockR,
    rootOfHash (PrivateState.commitment e.hash w.upsWitness.next),
    foldChain e.keccak w.prevFull.pis.settledChain w.transferWitness.transfer.auxData⟩,
   w.prevFull.vd⟩

/-- The local constraint system of `ReceiveTransferTarget::new` (source lines
368–538), one field per source connection / gadget call. `enforce_ge`,
`conditional_ge/gt`, `is_zero` and `select` are read as their integer
relations (field lowering is a boundary). Sub-gadget calls are the imported
`CircuitGates` where a current module exists and opaque acceptance premises
otherwise. -/
structure CircuitGates (e : Environment N S P) (w : CircuitWitness N S P) : Prop where
  prevParse : BalancePublicInputs.fullFromTarget e.capCount w.prevProofWords = .ok w.prevFull
  senderParse : BalancePublicInputs.fullFromTarget e.capCount w.senderProofWords = .ok w.senderFull
  sharedVerifierData : w.prevFull.vd = w.senderFull.vd
  prevProofVerified : e.proofAccepted w.prevFull.vd w.prevFull
  senderProofVerified : e.proofAccepted w.prevFull.vd w.senderFull
  senderPublicUpdate : UpdatePublicState.CircuitGates e.getRoot w.senderUpdatePublicState w.senderUpsWitness
  receiverPublicUpdate : UpdatePublicState.CircuitGates e.getRoot w.receiverUpdatePublicState w.receiverUpsWitness
  accountStateGadget : e.accountStateAccepted w.accountState
  txSettlementGadget : e.txSettlementAccepted w.txSettlement
  transferWitnessGadget : e.transferWitnessAccepted w.transferWitness
  privateUpdate : UpdatePrivateState.CircuitGates e.hash e.assetRoot e.nullifierCall true
    w.updatePrivateState w.upsWitness
  receiverOld : w.receiverUpdatePublicState.oldState = w.prevFull.pis.publicState
  senderOld : w.senderUpdatePublicState.oldState = w.senderFull.pis.publicState
  newStatesAgree : w.receiverUpdatePublicState.newState = w.senderUpdatePublicState.newState
  accountChannel : w.accountState.channelId = receiverId w
  accountRoot : w.accountState.accountTreeRoot = (publicStateOf w).accountRoot
  settlementChannel : w.txSettlement.channelId = senderId w
  settlementPublicState : w.txSettlement.publicState = publicStateOf w
  transferRoot : w.transferWitness.transferTreeRoot = w.txSettlement.tx.transferTreeRoot
  recipient : w.transferWitness.transfer.recipient = e.recipientOf (receiverId w) w.transferSalt
  blockLower : w.prevFull.pis.blockR ≤ w.newBlockR
  blockUpper : w.newBlockR ≤ (publicStateOf w).blockNumber
  outgoingLower : w.accountState.channelLeafPrev ≠ 0 →
    w.accountState.sendLeafPrev ≤ w.prevFull.pis.blockR
  outgoingUpper : w.accountState.channelLeafPrev ≠ 0 → w.newBlockR < w.accountState.sendLeafCur
  settlementBlock : txBlockNumber w.txSettlement ≤ w.newBlockR
  spendCommitment : (e.spendPisTarget w.txSettlement.spendProof).prevPrivateCommitment =
    w.senderFull.pis.privateCommitment
  spendValid : (e.spendPisTarget w.txSettlement.spendProof).isValid = true
  tokenIndex : w.transferWitness.transfer.tokenIndex = w.updatePrivateState.tokenIndex
  amount : w.transferWitness.transfer.amount = w.updatePrivateState.amount
  nullifier : w.updatePrivateState.nullifier = e.nullifierOf (settledTransferOf w).words
  previousCommitment : rootOfHash (PrivateState.commitment e.hash w.updatePrivateState.previous) =
    w.prevFull.pis.privateCommitment
  outputStatement : w.output = circuitOutput e w

variable {e : Environment N S P} {w : CircuitWitness N S P}

/-! ### Credit semantics (through the imported private-state gadget) -/

theorem circuit_credits_exact_transfer_amount (h : CircuitGates e w) :
    UpdatePrivateState.value w.upsWitness.newLeaf =
      UpdatePrivateState.value w.updatePrivateState.previousBalance +
        UpdatePrivateState.value w.transferWitness.transfer.amount := by
  rw [h.amount]
  exact UpdatePrivateState.circuit_credits_exact_amount h.privateUpdate

theorem circuit_credit_does_not_decrease_balance (h : CircuitGates e w) :
    UpdatePrivateState.value w.updatePrivateState.previousBalance ≤
      UpdatePrivateState.value w.upsWitness.newLeaf :=
  UpdatePrivateState.circuit_credit_does_not_decrease_balance h.privateUpdate

theorem circuit_credit_lands_at_transfer_token (h : CircuitGates e w) :
    e.assetRoot w.updatePrivateState.assetSiblings w.updatePrivateState.previousBalance
      w.transferWitness.transfer.tokenIndex = w.updatePrivateState.previous.assetRoot ∧
    w.upsWitness.next.assetRoot = e.assetRoot w.updatePrivateState.assetSiblings
      w.upsWitness.newLeaf w.transferWitness.transfer.tokenIndex := by
  rw [h.tokenIndex]
  exact UpdatePrivateState.circuit_replaces_same_token_same_path h.privateUpdate

theorem circuit_keeps_sent_root_nonce_salt (h : CircuitGates e w) :
    w.upsWitness.next.sentTxRoot = w.updatePrivateState.previous.sentTxRoot ∧
    w.upsWitness.next.nonce = w.updatePrivateState.previous.nonce ∧
    w.upsWitness.next.salt = w.updatePrivateState.previous.salt :=
  UpdatePrivateState.circuit_keeps_sent_root_nonce_salt h.privateUpdate

theorem circuit_invokes_nullifier_gadget_with_transfer_nullifier (h : CircuitGates e w) :
    e.nullifierCall w.updatePrivateState.nullifierProof w.updatePrivateState.previous.nullifierRoot
      (e.nullifierOf (settledTransferOf w).words) w.upsWitness.next.nullifierRoot := by
  rw [← h.nullifier]
  exact UpdatePrivateState.circuit_invokes_nullifier_gadget_with_incoming_nullifier h.privateUpdate

theorem circuit_range_checks_credit_inputs (h : CircuitGates e w) :
    w.updatePrivateState.tokenIndex < 2 ^ 32 ∧ UpdatePrivateState.Checked w.updatePrivateState.amount ∧
    UpdatePrivateState.Checked w.updatePrivateState.nullifier ∧
    UpdatePrivateState.Checked w.updatePrivateState.previousBalance :=
  UpdatePrivateState.enabled_checks_bound_input_words h.privateUpdate

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
    w.output.pis.channelId = w.prevFull.pis.channelId ∧ w.output.vd = w.prevFull.vd ∧
    w.output.vd = w.senderFull.vd := by
  rw [h.outputStatement]
  exact ⟨rfl, rfl, h.sharedVerifierData⟩

theorem circuit_output_public_state_is_the_settlement_state (h : CircuitGates e w) :
    w.output.pis.publicState = w.txSettlement.publicState ∧
    w.output.pis.publicState = w.senderUpdatePublicState.newState ∧
    w.output.pis.publicState = w.receiverUpdatePublicState.newState := by
  rw [h.outputStatement]
  exact ⟨h.settlementPublicState.symm, h.newStatesAgree, rfl⟩

theorem circuit_public_updates_start_from_both_statements (h : CircuitGates e w) :
    w.receiverUpdatePublicState.oldState = w.prevFull.pis.publicState ∧
    w.senderUpdatePublicState.oldState = w.senderFull.pis.publicState ∧
    UpdatePublicState.nativeVerify e.getRoot w.receiverUpdatePublicState = .ok () ∧
    UpdatePublicState.nativeVerify e.getRoot w.senderUpdatePublicState = .ok () :=
  ⟨h.receiverOld, h.senderOld,
    UpdatePublicState.target_implies_native_local_verification h.receiverPublicUpdate,
    UpdatePublicState.target_implies_native_local_verification h.senderPublicUpdate⟩

theorem circuit_block_window (h : CircuitGates e w) :
    w.prevFull.pis.blockR ≤ w.output.pis.blockR ∧
    w.output.pis.blockR ≤ w.output.pis.publicState.blockNumber ∧
    txBlockNumber w.txSettlement ≤ w.output.pis.blockR := by
  rw [h.outputStatement]
  exact ⟨h.blockLower, h.blockUpper, h.settlementBlock⟩

theorem circuit_outgoing_window_when_prior_send (h : CircuitGates e w)
    (priorSend : w.accountState.channelLeafPrev ≠ 0) :
    w.accountState.sendLeafPrev ≤ w.prevFull.pis.blockR ∧ w.newBlockR < w.accountState.sendLeafCur :=
  ⟨h.outgoingLower priorSend, h.outgoingUpper priorSend⟩

theorem circuit_account_state_is_receivers_at_settlement_root (h : CircuitGates e w) :
    w.accountState.channelId = w.prevFull.pis.channelId ∧
    w.accountState.accountTreeRoot = w.output.pis.publicState.accountRoot := by
  rw [h.outputStatement]
  exact ⟨h.accountChannel, h.accountRoot⟩

theorem circuit_transfer_leaf_belongs_to_senders_settled_tx (h : CircuitGates e w) :
    w.txSettlement.channelId = w.senderFull.pis.channelId ∧
    w.transferWitness.transferTreeRoot = w.txSettlement.tx.transferTreeRoot :=
  ⟨h.settlementChannel, h.transferRoot⟩

theorem circuit_recipient_binds_receiver_channel_and_salt (h : CircuitGates e w) :
    w.transferWitness.transfer.recipient = e.recipientOf w.output.pis.channelId w.transferSalt := by
  rw [h.outputStatement]
  exact h.recipient

theorem circuit_sender_spend_authorizes_credit (h : CircuitGates e w) :
    (e.spendPisTarget w.txSettlement.spendProof).prevPrivateCommitment =
      w.senderFull.pis.privateCommitment ∧
    (e.spendPisTarget w.txSettlement.spendProof).isValid = true :=
  ⟨h.spendCommitment, h.spendValid⟩

theorem circuit_nullifier_binds_sender_channel_index_nonce (h : CircuitGates e w) :
    w.updatePrivateState.nullifier = e.nullifierOf (SettledTransfer.words
      ⟨w.transferWitness.transfer, w.senderFull.pis.channelId, w.transferWitness.transferIndex,
        w.txSettlement.tx.nonce⟩) := by
  have := h.nullifier
  simp only [settledTransferOf, h.settlementChannel, senderId] at this
  exact this

theorem circuit_chain_unchanged_when_aux_zero (h : CircuitGates e w)
    (legacy : w.transferWitness.transfer.auxData = BalancePublicInputs.Bytes8.zero) :
    w.output.pis.settledChain = w.prevFull.pis.settledChain := by
  rw [h.outputStatement]
  simp only [circuitOutput, legacy, fold_chain_unchanged_when_aux_zero]

theorem circuit_chain_folds_aux_when_nonzero (h : CircuitGates e w)
    (interChannel : w.transferWitness.transfer.auxData ≠ BalancePublicInputs.Bytes8.zero) :
    w.output.pis.settledChain = e.keccak
      (chainPreimage w.prevFull.pis.settledChain w.transferWitness.transfer.auxData) := by
  rw [h.outputStatement]
  simp only [circuitOutput, fold_chain_pushes_when_aux_nonzero _ _ _ interChannel]

theorem circuit_output_statement_has_29_words (h : CircuitGates e w) :
    w.output.pis.words.length = balanceLength := by
  rw [h.outputStatement]
  exact BalancePublicInputs.balance_word_count _

/-! ### Registered public inputs (source line 612) -/

/-- `builder.register_public_inputs(&new_full_pis.to_vec(&balance_cd.config))`. -/
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
circuit adds (proof verification, three Merkle sub-gadgets, the imported
private/public-state gadgets, and the target parser reading the same
statements), is a satisfying `CircuitGates` witness with the same output. It
exhibits satisfiability only; none of the premises is discharged. -/
theorem target_witness_of_native_success (e : Environment N S P) (w : Witness N S P)
    (out : FullInputs) (h : nativeToPublicInputs e w = .ok out)
    (prevFull senderFull : FullInputs) (spend : SpendPublicInputs)
    (checks : NativeChecks e w prevFull senderFull spend)
    (prevTarget : BalancePublicInputs.fullFromTarget e.capCount w.prevProofWords = .ok prevFull)
    (senderTarget : BalancePublicInputs.fullFromTarget e.capCount w.senderProofWords = .ok senderFull)
    (prevVerified : e.proofAccepted prevFull.vd prevFull)
    (senderVerified : e.proofAccepted prevFull.vd senderFull)
    (senderPath : w.senderUpdatePublicState.proof.length = UpdatePublicState.height)
    (receiverPath : w.receiverUpdatePublicState.proof.length = UpdatePublicState.height)
    (senderHistory : UpdatePublicState.nativeVerify e.getRoot w.senderUpdatePublicState = .ok ())
    (receiverHistory : UpdatePublicState.nativeVerify e.getRoot w.receiverUpdatePublicState = .ok ())
    (accountAccepted : e.accountStateAccepted w.accountState)
    (settlementAccepted : e.txSettlementAccepted w.txSettlement)
    (transferAccepted : e.transferWitnessAccepted w.transferWitness)
    (upsW : UpdatePrivateState.CircuitWitness)
    (upsGadget : UpdatePrivateState.CircuitGates e.hash e.assetRoot e.nullifierCall true
      w.updatePrivateState.inputs upsW)
    (upsNext : upsW.next = w.updatePrivateState.next)
    (spendTarget : e.spendPisTarget w.txSettlement.spendProof = spend) :
    ∃ cw : CircuitWitness N S P, CircuitGates e cw ∧ cw.output = out ∧ cw.upsWitness = upsW := by
  obtain ⟨prevFull', senderFull', spend', checks', rfl⟩ := native_success_extracts e w out h
  have hp : prevFull' = prevFull := Except.ok.inj (checks'.prevParse.symm.trans checks.prevParse)
  subst prevFull'
  refine ⟨⟨w.prevProofWords, w.senderProofWords, prevFull, senderFull, w.senderUpdatePublicState,
    ⟨UpdatePublicState.statesEqual w.senderUpdatePublicState.newState w.senderUpdatePublicState.oldState,
      !UpdatePublicState.statesEqual w.senderUpdatePublicState.newState w.senderUpdatePublicState.oldState,
      UpdatePublicState.expectedOldRoot e.getRoot w.senderUpdatePublicState⟩,
    w.receiverUpdatePublicState,
    ⟨UpdatePublicState.statesEqual w.receiverUpdatePublicState.newState w.receiverUpdatePublicState.oldState,
      !UpdatePublicState.statesEqual w.receiverUpdatePublicState.newState w.receiverUpdatePublicState.oldState,
      UpdatePublicState.expectedOldRoot e.getRoot w.receiverUpdatePublicState⟩,
    w.newBlockR, w.accountState, w.txSettlement, w.transferWitness, w.transferSalt,
    w.updatePrivateState.inputs, upsW, nativeOutput e w prevFull⟩, ?_, rfl, rfl⟩
  refine ⟨prevTarget, senderTarget, checks.sharedVerifierData, prevVerified, senderVerified,
    UpdatePublicState.target_witness_of_native_local_verification e.getRoot w.senderUpdatePublicState
      senderPath senderHistory,
    UpdatePublicState.target_witness_of_native_local_verification e.getRoot w.receiverUpdatePublicState
      receiverPath receiverHistory,
    accountAccepted, settlementAccepted, transferAccepted, upsGadget,
    checks.receiverOld, checks.senderOld, checks.newStatesAgree, checks.accountChannel,
    checks.accountRoot, checks.settlementChannel, checks.settlementPublicState, checks.transferRoot,
    checks.recipient, ?_, ?_, fun p => (checks.outgoingWindow p).1, fun p => (checks.outgoingWindow p).2,
    ?_, ?_, ?_, checks.tokenIndex.symm, checks.amount.symm, ?_, checks.previousCommitment, ?_⟩
  · show prevFull.pis.blockR ≤ w.newBlockR
    have := checks.blockWindow; omega
  · show w.newBlockR ≤ w.receiverUpdatePublicState.newState.blockNumber
    have := checks.blockWindow; omega
  · show txBlockNumber w.txSettlement ≤ w.newBlockR
    have := checks.settlementBlock; omega
  · show (e.spendPisTarget w.txSettlement.spendProof).prevPrivateCommitment =
      senderFull.pis.privateCommitment
    rw [spendTarget]; exact checks.spendCommitment.symm
  · show (e.spendPisTarget w.txSettlement.spendProof).isValid = true
    rw [spendTarget]; exact checks.spendValid
  · show w.updatePrivateState.inputs.nullifier = e.nullifierOf (SettledTransfer.words
      ⟨w.transferWitness.transfer, w.txSettlement.channelId, w.transferWitness.transferIndex,
        w.txSettlement.tx.nonce⟩)
    rw [checks.settlementChannel]; exact checks.nullifier
  · show nativeOutput e w prevFull = ⟨⟨prevFull.pis.channelId, w.receiverUpdatePublicState.newState,
      w.newBlockR, rootOfHash (PrivateState.commitment e.hash upsW.next),
      foldChain e.keccak prevFull.pis.settledChain w.transferWitness.transfer.auxData⟩, prevFull.vd⟩
    rw [upsNext]; rfl

/-! ## Concrete normal trace -/

def normalRoot : Root := ⟨1, 1, 1, 1⟩
def normalHash : Hash4 := ⟨1, 1, 1, 1⟩
def normalRecipient : Bytes8 := ⟨1, 2, 3, 4, 5, 6, 7, 8⟩
def normalAux : Bytes8 := ⟨0, 0, 0, 0, 0, 0, 0, 9⟩
def normalNullifier : UpdatePrivateState.Bytes32 := UpdatePrivateState.fromSmall 5

/-- Sender settled at block 4; receiver last synced at block 3; both see block 6. -/
def normalPublicState : PublicState := ⟨6, 0, 100, BalancePublicInputs.Root.zero,
  BalancePublicInputs.Root.zero, BalancePublicInputs.Root.zero⟩

def normalVd : VerifierData := ⟨BalancePublicInputs.Root.zero, []⟩

def normalPrevFull : FullInputs :=
  ⟨⟨7, normalPublicState, 3, normalRoot, BalancePublicInputs.Bytes8.zero⟩, normalVd⟩
def normalSenderFull : FullInputs :=
  ⟨⟨9, normalPublicState, 6, ⟨2, 2, 2, 2⟩, BalancePublicInputs.Bytes8.zero⟩, normalVd⟩

def normalTransfer : Transfer := ⟨normalRecipient, 0, UpdatePrivateState.fromSmall 2, normalAux⟩
def normalTx : Tx := ⟨normalRoot, 1⟩
def normalSpend : SpendPublicInputs := ⟨⟨2, 2, 2, 2⟩, ⟨3, 3, 3, 3⟩, normalTx, true⟩

def normalPrevState : PrivateState.State :=
  ⟨PrivateState.zeroHash, PrivateState.zeroHash, PrivateState.zeroHash, PrivateState.zeroHash, 0,
    PrivateState.zeroHash⟩
def normalNextState : PrivateState.State :=
  UpdatePrivateState.updatedState (fun _ => normalHash) normalPrevState PrivateState.zeroHash
    PrivateState.zeroHash

def normalUpsInputs : UpdatePrivateState.Inputs Unit :=
  ⟨0, UpdatePrivateState.fromSmall 2, normalNullifier, normalPrevState, (), UpdatePrivateState.fromSmall 7,
    List.replicate 32 PrivateState.zeroHash⟩

def normalEnvironment : Environment Unit Unit Unit :=
  { capCount := 0
    convertFields := fun xs => .ok xs
    hash := fun _ => normalHash
    recipientOf := fun _ _ => normalRecipient
    nullifierOf := fun _ => normalNullifier
    keccak := fun _ => ⟨4, 4, 4, 4, 4, 4, 4, 4⟩
    spendPis := fun _ => .ok normalSpend
    spendPisTarget := fun _ => normalSpend
    proofAccepted := fun _ _ => True
    getRoot := fun _ _ _ => BalancePublicInputs.Root.zero
    assetRoot := fun _ _ _ => PrivateState.zeroHash
    nullifierCall := fun _ _ _ _ => True
    accountStateAccepted := fun _ => True
    txSettlementAccepted := fun _ => True
    transferWitnessAccepted := fun _ => True }

def normalWitness : Witness Unit Unit Unit :=
  { prevProofWords := normalPrevFull.words
    senderProofWords := normalSenderFull.words
    senderUpdatePublicState := ⟨normalPublicState, normalPublicState, UpdatePublicState.dummyProof⟩
    receiverUpdatePublicState := ⟨normalPublicState, normalPublicState, UpdatePublicState.dummyProof⟩
    newBlockR := 5
    accountState := ⟨7, BalancePublicInputs.Root.zero, 0, 0, 0, ()⟩
    txSettlement := ⟨9, normalTx, normalPublicState, ⟨9, BalancePublicInputs.Root.zero, 2, 4, 2, ()⟩, (), ()⟩
    transferWitness := ⟨normalRoot, normalTransfer, 0, ()⟩
    transferSalt := PrivateState.zeroHash
    updatePrivateState := ⟨normalUpsInputs, normalNextState⟩ }

theorem normal_prev_statement_parses :
    BalancePublicInputs.fullFromNative (fun xs => .ok xs) 0 normalPrevFull.words = .ok normalPrevFull := by
  apply BalancePublicInputs.native_full_roundtrip
  · simp [BalancePublicInputs.AllocationChecks, normalPrevFull, normalPublicState,
      BalancePublicInputs.Bytes8.words, BalancePublicInputs.Bytes8.zero, BalancePublicInputs.wordBase,
      BalancePublicInputs.blockLimit]
  · decide
  · rfl

theorem normal_sender_statement_parses :
    BalancePublicInputs.fullFromNative (fun xs => .ok xs) 0 normalSenderFull.words = .ok normalSenderFull := by
  apply BalancePublicInputs.native_full_roundtrip
  · simp [BalancePublicInputs.AllocationChecks, normalSenderFull, normalPublicState,
      BalancePublicInputs.Bytes8.words, BalancePublicInputs.Bytes8.zero, BalancePublicInputs.wordBase,
      BalancePublicInputs.blockLimit]
  · decide
  · rfl

theorem normal_native_checks :
    NativeChecks normalEnvironment normalWitness normalPrevFull normalSenderFull normalSpend :=
  ⟨normal_prev_statement_parses, normal_sender_statement_parses, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl,
    rfl, rfl, by decide, fun p => absurd rfl p, by decide, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩

theorem normal_native_admission :
    nativeToPublicInputs normalEnvironment normalWitness =
      .ok (nativeOutput normalEnvironment normalWitness normalPrevFull) :=
  (native_ok_iff _ _ _).mpr ⟨normalPrevFull, normalSenderFull, normalSpend, normal_native_checks, rfl⟩

theorem normal_output_credits_receiver_at_block_5 :
    (nativeOutput normalEnvironment normalWitness normalPrevFull).pis.channelId = 7 ∧
    (nativeOutput normalEnvironment normalWitness normalPrevFull).pis.blockR = 5 ∧
    (nativeOutput normalEnvironment normalWitness normalPrevFull).pis.settledChain =
      ⟨4, 4, 4, 4, 4, 4, 4, 4⟩ := by
  refine ⟨rfl, rfl, ?_⟩
  simp [nativeOutput, normalWitness, normalTransfer, normalAux, foldChain, chainPush,
    normalEnvironment, BalancePublicInputs.Bytes8.zero]

/-- Small amounts (one nonzero low limb below `2^32`) pass the u32 limb range check. -/
theorem small_amount_checked (n : Nat) (bound : n < U256Arithmetic.wordBase) :
    UpdatePrivateState.Checked (UpdatePrivateState.fromSmall n) := by
  intro d hd
  simp only [UpdatePrivateState.fromSmall, UpdatePrivateState.amountWords, List.mem_cons,
    List.mem_nil_iff, or_false] at hd
  rcases hd with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
  all_goals first | exact bound | decide

/-- The same trace as an arbitrary-witness assignment: the credited leaf is the
per-limb sum 7 + 2 = 9 of the imported AddGates relation. -/
theorem normal_circuit_witness :
    ∃ cw : CircuitWitness Unit Unit Unit, CircuitGates normalEnvironment cw ∧
      cw.output = nativeOutput normalEnvironment normalWitness normalPrevFull ∧
      UpdatePrivateState.value cw.upsWitness.newLeaf = 9 := by
  obtain ⟨cw, gates, hout, hnext⟩ := target_witness_of_native_success normalEnvironment normalWitness _
    normal_native_admission normalPrevFull normalSenderFull normalSpend normal_native_checks
    (BalancePublicInputs.full_target_roundtrip normalPrevFull)
    (BalancePublicInputs.full_target_roundtrip normalSenderFull) trivial trivial
    UpdatePublicState.dummy_has_63_siblings UpdatePublicState.dummy_has_63_siblings
    (UpdatePublicState.native_equal_verify_needs_no_root _ _ _)
    (UpdatePublicState.native_equal_verify_needs_no_root _ _ _) trivial trivial trivial
    ⟨UpdatePrivateState.fromSmall 9, PrivateState.zeroHash, normalNextState⟩
    ⟨fun _ => ⟨by decide, small_amount_checked 2 (by decide), small_amount_checked 5 (by decide),
        small_amount_checked 7 (by decide)⟩, by decide, trivial, rfl,
      UpdatePrivateState.normal_credit_7_plus_2, rfl⟩ rfl rfl
  exact ⟨cw, gates, hout, by rw [hnext]; exact UpdatePrivateState.normal_credit_value_9⟩

end Zkp.Implementation.ReceiveTransferCircuit
