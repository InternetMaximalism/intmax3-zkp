import Zkp.Implementation.ClosePublicInputs

/-!
# Native state-update verifier control flow

Manual translation of state_update_verifier.rs default-production functions.
This is NOT Rust compiler refinement, a circuit acceptance predicate, or a proof
that arbitrary trait implementations authenticate anything. Complete local input
records, ordered checks, typed proof statements and returned public data are kept.
Hashing, BalanceState/ChannelRecord validation and deterministic imported builders
are individually indexed dependency calls, NOT whole-system safety assumptions.

The source signature helpers check slot/key/blob STRUCTURE, not Falcon validity;
sender hash-signature verification and A11 membership are wallet responsibilities.
L1 deposit backing, actual nullifier-tree insertion, source/destination agreement,
the accumulator frontier and durable signer/replay ledgers are not supplied here.
An unequal root is not assumed to be a valid fresh insertion. All-cluster behavior
in its own channel is not promoted into authorization over a different channel.

Nat scalar fields represent native-width values under NativeWidths, not invented
range checks. Ordinary u64 addition is explicitly profile dependent: release wraps,
overflow-checked builds panic. Native U256 addition always panics on final carry.
Array indexing and imported hash/helper panics are distinct from returned errors.
The source's malformed Vec shapes remain representable; no prior validate call is
silently inserted before linkage hashes. Error category/order is modeled; exact
format!/Display, allocation failure, serde and host panic strategy remain boundaries.
Neither the source nor this model binds `channel_fund.channel_id` or `intmax_state_root`
(`Fund.channelId` / `Fund.root`) individually in send, fund import or L1 deposit; only the
whole-struct fund equality of the no-fund-change kinds constrains those two fields.
-/
namespace Zkp.Implementation.ChannelStateUpdate

abbrev Hash := ClosePublicInputs.Words8
abbrev Ten := ClosePublicInputs.Ten
abbrev Amount := Fin (2^256)
def wordBase : Nat := 2^32
def scalarLimit : Nat := 2^64
def slotCount : Nat := 1024
def tokenWidth : Nat := 10
def regevN : Nat := 2048
def regevQ : Nat := 2013265921
def addBudget : Nat := 64
def burnChannel : Nat := 4294967295
def zero : Hash := ClosePublicInputs.Words8.zero

structure Slots (α : Type) where
  values : List α
  width : values.length = slotCount
  deriving DecidableEq

structure Ciphertext where
  c1 : List Nat
  c2 : List Nat
  deriving DecidableEq, Repr
structure PublicKey where
  a : List Nat
  b : List Nat
  deriving DecidableEq, Repr
structure SecretKey where
  coefficients : List Int
  deriving DecidableEq, Repr
structure Signature where
  slot : Nat
  pk : Hash
  bytes : List Nat
  deriving DecidableEq, Repr

structure Balance where
  channelId : Nat
  memberCount : Nat
  delegateCount : Nat
  ciphertexts : List (Ten Ciphertext)
  regevDigests : Slots Hash
  recipients : Slots Nat
  chain : Hash
  accumulator : Hash
  version : Nat
  pending : List (Ten Nat)
  registry : Ten Nat
  tokenCount : Nat
  deriving DecidableEq
structure Fund where
  channelId : Nat
  amounts : Ten Amount
  root : Hash
  deriving DecidableEq
structure State where
  channelId : Nat
  epoch : Nat
  smallBlock : Nat
  closeNonce : Nat
  fund : Fund
  balance : Balance
  h2 : Hash
  nullifierRoot : Hash
  unallocated : Amount
  prevDigest : Hash
  digest : Hash
  signatures : List Signature
  deriving DecidableEq
structure Record where
  channelId : Nat
  memberCount : Nat
  delegateCount : Nat
  keys : Slots Hash
  memberRoot : Hash
  setVersion : Nat
  bpSlot : Nat
  penalty : Amount
  closeNonce : Nat
  status : Nat
  regevRoot : Hash
  deriving DecidableEq

inductive Backend where | plonky2 | plonky3 deriving DecidableEq, Repr
inductive Role where | stateUpdate | transport | closeSettlement | specialSettlement
  deriving DecidableEq, Repr
inductive Kind where
  | inChannel | send | fundImport | bundleApply | refresh | close | specialClose | l1Deposit | tokenRegister
  deriving DecidableEq, Repr
def Kind.code : Kind → Nat
  | .inChannel => 0 | .send => 1 | .fundImport => 2 | .bundleApply => 3 | .refresh => 4
  | .close => 5 | .specialClose => 6 | .l1Deposit => 7 | .tokenRegister => 8
inductive Purpose where | channelTx | channelUpdate | withdrawal | refresh
  deriving DecidableEq, Repr
structure Envelope where
  role : Role
  backend : Backend
  proof : List Nat
  deriving DecidableEq, Repr
inductive RegevStatement where
  | channelTx (sender recipient : PublicKey) (before encryptedAmount after : Ciphertext)
  | channelUpdate (sender recipient : PublicKey) (before after senderDelta receiverDelta : Ciphertext)
      (amount tokenIndex : Nat)
  | withdrawal (key : PublicKey) (ciphertext : Ciphertext) (amount : Nat)
  | refresh (key : PublicKey) (before after : Ciphertext)
  deriving DecidableEq, Repr
structure ChannelTx where
  recipient : Hash
  tokenSlot : Nat
  encryptedAmount : Ciphertext
  nonce : Hash
  regevProof : Envelope
  sender : Hash
  senderHashSignature : List Nat
  senderPkB : Hash
  deriving DecidableEq, Repr
structure SmallBlockMessage where
  channelId : Nat
  bpSlot : Nat
  bpKey : Hash
  smallBlock : Nat
  previousRoot : Hash
  txRoot : Hash
  stateRoot : Hash
  mediumEpoch : Nat
  closeNonce : Nat
  deriving DecidableEq, Repr
structure SignedSmallBlock where
  message : SmallBlockMessage
  signatures : List Signature
  aggregateProof : List Nat
  mediumBlock : Nat
  confirmationProof : List Nat
  deriving DecidableEq, Repr
structure Delta where
  recipient : Hash
  ciphertext : Ciphertext
  deriving DecidableEq, Repr
structure Inclusion where
  siblings : List Hash
  index : Amount
  deriving DecidableEq
structure InterTx where
  inclusion : Inclusion
  signedBlock : SignedSmallBlock
  senderDelta : Ciphertext
  sourceChannel : Nat
  destinationChannel : Nat
  tokenIndex : Nat
  baseNonce : Nat
  destinationSalt : List Nat
  sender : Hash
  transactionSeal : Hash
  txHash : Hash
  transferCommitment : Hash
  memo : List Nat
  receivers : List Delta
  regevProof : Envelope
  transportBytes : List Nat
  senderHashSignature : List Nat
  senderPkB : Hash
  deriving DecidableEq

structure PublicInputs where
  kind : Kind
  channelId : Nat
  prevDigest : Hash
  nextDigest : Hash
  amount : Nat
  prevVersion : Nat
  nextVersion : Nat
  h2 : Hash
  prevChain : Hash
  nextChain : Hash
  receiverCount : Nat
  senderHash : Hash
  receiverHash : Hash
  fundBefore : Ten Amount
  fundAfter : Ten Amount
  unallocatedBefore : Amount
  unallocatedAfter : Amount
  nullifierBefore : Hash
  nullifierAfter : Hash
  transitionDigest : Hash
  deriving DecidableEq

inductive Category where
  | proofRole | proofBackend | linkage | pkRoot | version | h2 | chain | ciphertext
  | pending | amount | root | transition | bundle | smallBlock | signatures | decryption
  | proofVerification | publicInput
  deriving DecidableEq, Repr
inductive Fault where
  | rejected (category : Category) (location : String)
  | panic (location : String)
  deriving DecidableEq, Repr
abbrev Result := Except Fault
def mapRejected {α : Type} (category : Category) : Result α → Result α
  | .ok value => .ok value
  | .error (.panic label) => .error (.panic label)
  | .error (.rejected _ label) => .error (.rejected category label)
def check (condition : Bool) (category : Category) (location : String) : Result Unit :=
  if condition then .ok () else .error (.rejected category location)
def atIndex {α : Type} (xs : List α) (index : Nat) : Result α :=
  match xs[index]? with | none => .error (.panic "index") | some x => .ok x
def forEach {α : Type} (xs : List α) (action : α → Result Unit) : Result Unit :=
  match xs with
  | [] => .ok ()
  | x::rest => do let _ ← action x; forEach rest action
def firstIndex {α : Type} (predicate : α → Bool) : List α → Option Nat
  | [] => none
  | x::xs => if predicate x then some 0 else (firstIndex predicate xs).map Nat.succ

inductive OverflowMode where | wrapping | checked deriving DecidableEq, Repr
def addScalarOne (mode : OverflowMode) (n : Nat) : Result Nat :=
  match mode with
  | .wrapping => .ok ((n+1) % scalarLimit)
  | .checked => if n+1 < scalarLimit then .ok (n+1) else .error (.panic "u64 addition overflow")
def addAmount (a b : Amount) : Result Amount :=
  if h : a.val+b.val < 2^256 then .ok ⟨a.val+b.val,h⟩ else .error (.panic "U256 addition carry")
def u64ToU256 (n : Nat) : Result Amount :=
  -- Exact source cast through two u32 limbs; native n is u64.
  .ok ⟨n % scalarLimit,by have := Nat.mod_lt n (by decide : 0 < scalarLimit); unfold scalarLimit at *; omega⟩
def splitU64 (n : Nat) : List Nat := [n / wordBase % wordBase,n % wordBase]
def amountWords (a : Amount) : List Nat :=
  (List.range 8).reverse.map fun i => a.val / wordBase^i % wordBase
def fundWords (a : Ten Amount) : List Nat := (a.values.map amountWords).join
def publicWords (p : PublicInputs) : List Nat :=
  [p.kind.code,p.channelId] ++ p.prevDigest.words ++ p.nextDigest.words ++ splitU64 p.amount ++
  splitU64 p.prevVersion ++ splitU64 p.nextVersion ++ p.h2.words ++ p.prevChain.words ++
  p.nextChain.words ++ splitU64 p.receiverCount ++ p.senderHash.words ++ p.receiverHash.words ++
  fundWords p.fundBefore ++ fundWords p.fundAfter ++ amountWords p.unallocatedBefore ++
  amountWords p.unallocatedAfter ++ p.nullifierBefore.words ++ p.nullifierAfter.words ++ p.transitionDigest.words

/-- Exact individual callees, including panic observations. No acceptance=>safe oracle. -/
structure Environment (Tree : Type) where
  mode : OverflowMode
  hashWords : List Nat → Result Hash
  stateDigest : State → Result Hash
  balanceH1 : Balance → Result Hash
  validateBalance : Balance → Result Unit
  -- `record.validate()` is not a separate callee here: the source runs it inside
  -- `validate_member_signature_slots` (channel.rs), i.e. within `validateSignatureSlots`.
  validateSignatureSlots : Record → List Signature → Result Unit
  validateStateSignatureStructure : Record → List Signature → Result Unit
  validatePublicKey : PublicKey → Result Unit
  keyRoot : Slots PublicKey → Result Hash
  ciphertextAdd : Ciphertext → Ciphertext → Result Ciphertext
  decrypt : SecretKey → Ciphertext → Result Nat
  ciphertextDigest : Ciphertext → Result Hash
  /-- `ChannelTx::signing_digest(channel_id, prev_state_digest, enc_amount, nonce, token_slot,
  sender_pk_g, recipient_pk_g)`: exactly the source's seven inputs, in source order. The
  sender hash-signature bytes and `sender_pk_b` are deliberately NOT part of the preimage. -/
  channelTxDigest : Nat → Hash → Ciphertext → Hash → Nat → Hash → Hash → Result Hash
  txLeaf : InterTx → Result Hash
  txHash : InterTx → Result Hash
  interSigningDigest : InterTx → Result Hash
  chainPush : Hash → Hash → Result Hash
  burnDescriptor : Nat → Nat → Hash → Hash → Nat → Amount → Result Hash
  depositDigest : Nat → Hash → Nat → Nat → Nat → Result Hash
  tokenRegisterBalance : Balance → Balance → Nat → Result Unit
  tokenRegisterState : State → Nat → Result State
  accumulatorPush : Tree → Hash → Result Tree
  accumulatorRoot : Tree → Result Hash

abbrev RegevVerifier := Envelope → Purpose → RegevStatement → Result Unit
abbrev TransportVerifier := Envelope → PublicInputs → Result Unit
def realRegevVerify (real : Purpose → List Nat → RegevStatement → Result Unit)
    (proof : Envelope) (purpose : Purpose) (statement : RegevStatement) : Result Unit := do
  check (proof.role == .stateUpdate) .proofRole "Regev.role"
  check (proof.backend == .plonky3) .proofBackend "Regev.backend"
  mapRejected .proofVerification (real purpose proof.proof statement)
def verifyProof (verifier : TransportVerifier) (proof : Envelope) (role : Role)
    (backend : Backend) (p : PublicInputs) : Result Unit := do
  check (proof.role == role) .proofRole "transport.role"
  check (proof.backend == backend) .proofBackend "transport.backend"
  verifier proof p
def digest {Tree : Type} (e : Environment Tree) (p : PublicInputs) : Result Hash := e.hashWords (publicWords p)
def hashMember {Tree : Type} (e : Environment Tree) (key : Hash) : Result Hash := e.hashWords key.words

def verifyStateLinkage {Tree : Type} (e : Environment Tree) (prev next : State) : Result Unit := do
  check (prev.channelId == next.channelId) .linkage "channel id"
  let epoch ← addScalarOne e.mode prev.epoch
  check (next.epoch == epoch) .linkage "epoch"
  check (next.prevDigest == prev.digest) .linkage "prev digest link"
  let before ← e.stateDigest prev
  check (prev.digest == before) .linkage "prev signing digest"
  let after ← e.stateDigest next
  check (next.digest == after) .linkage "next signing digest"
def verifyOrdinaryStateMetadata (record : Record) (prev next : State) : Result Unit := do
  forEach [prev,next] fun state =>
    check (state.balance.memberCount == record.memberCount && state.balance.delegateCount == record.delegateCount)
      .linkage "participant split"
  check (next.closeNonce == prev.closeNonce) .linkage "close era"
def requireSmallBlockUnchanged (prev next : State) : Result Unit :=
  check (next.smallBlock == prev.smallBlock) .linkage "small block"
def verifyBalanceShared {Tree : Type} (e : Environment Tree) (record : Record) (prev next : State) : Result Unit := do
  verifyOrdinaryStateMetadata record prev next
  mapRejected .ciphertext (e.validateBalance prev.balance)
  mapRejected .ciphertext (e.validateBalance next.balance)
  check (prev.balance.channelId == prev.channelId && next.balance.channelId == next.channelId &&
    prev.channelId == record.channelId) .linkage "balance channel id"
  let version ← addScalarOne e.mode prev.balance.version
  check (next.balance.version == version) .version "state version"
  check (prev.balance.recipients == next.balance.recipients) .linkage "recipients"
  check (prev.balance.regevDigests == next.balance.regevDigests) .linkage "Regev digests"
def verifyBalanceCommon {Tree : Type} (e : Environment Tree) (record : Record) (prev next : State) : Result Unit := do
  verifyBalanceShared e record prev next
  check (prev.balance.registry == next.balance.registry && prev.balance.tokenCount == next.balance.tokenCount)
    .linkage "token registry/count"
def verifyRegevPkRoot {Tree : Type} (e : Environment Tree) (record : Record) (keys : Slots PublicKey) : Result Unit := do
  forEach keys.values fun key => mapRejected .pkRoot (e.validatePublicKey key)
  let root ← e.keyRoot keys
  check (root == record.regevRoot) .pkRoot "registered key root"
def requireH2Zero (next : State) : Result Unit := check (next.h2 == zero) .h2 "h2 zero"
def requireChainUnchanged (prev next : State) : Result Unit :=
  check (next.balance.chain == prev.balance.chain) .chain "chain unchanged"
def requireChainPush {Tree : Type} (e : Environment Tree) (prev next : State) (leaf : Hash) : Result Unit := do
  let expected ← e.chainPush prev.balance.chain leaf
  check (next.balance.chain == expected) .chain "chain push"
def requireAccumulatorPush {Tree : Type} (e : Environment Tree) (tree : Tree) (txHash next : Hash) : Result Unit := do
  let advanced ← e.accumulatorPush tree txHash
  let expected ← e.accumulatorRoot advanced
  check (expected == next) .chain "accumulator push"
def requireAccumulatorUnchanged (prev next : Hash) : Result Unit :=
  check (prev == next) .chain "accumulator unchanged"
def ensureSlotUnchanged (prev next : State) (index : Nat) : Result Unit := do
  let before ← atIndex prev.balance.ciphertexts index
  let after ← atIndex next.balance.ciphertexts index
  check (before == after) .ciphertext "whole slot"
def ensureRowUnchangedExcept (prev next : State) (index tokenSlot : Nat) : Result Unit :=
  forEach (List.range tokenWidth) fun t => do
    if t != tokenSlot then
      let before ← atIndex prev.balance.ciphertexts index
      let after ← atIndex next.balance.ciphertexts index
      let b ← atIndex before.values t
      let a ← atIndex after.values t
      check (b == a) .ciphertext "other token position"
def requirePendingUnchanged (prev next : State) (index : Nat) : Result Unit := do
  let before ← atIndex prev.balance.pending index
  let after ← atIndex next.balance.pending index
  check (before == after) .pending "whole counter row"
def requirePendingUnchangedExcept (prev next : State) (index tokenSlot : Nat) : Result Unit :=
  forEach (List.range tokenWidth) fun t => do
    if t != tokenSlot then
      let before ← atIndex prev.balance.pending index
      let after ← atIndex next.balance.pending index
      let b ← atIndex before.values t
      let a ← atIndex after.values t
      check (b == a) .pending "other counter position"
def requirePendingIncrement (prev next : State) (index tokenSlot : Nat) : Result Unit := do
  let before ← atIndex prev.balance.pending index
  let after ← atIndex next.balance.pending index
  let b ← atIndex before.values tokenSlot
  let a ← atIndex after.values tokenSlot
  check (b < addBudget) .pending "refresh budget"
  check (a == b+1) .pending "counter increment"
  requirePendingUnchangedExcept prev next index tokenSlot
def requireTokenBearingHash {Tree : Type} (e : Environment Tree) (tx : InterTx) : Result Unit := do
  let computed ← mapRejected .chain (e.txHash tx)
  check (computed == tx.txHash) .chain "token-bearing tx hash"
def resolveTokenSlot (balance : Balance) (tokenIndex : Nat) : Result Nat :=
  match firstIndex (fun i => i == tokenIndex) (balance.registry.values.take (min balance.tokenCount tokenWidth)) with
  | none => .error (.rejected .amount "unregistered base token")
  | some index => .ok index
def ensureFundsUnchangedExcept (prev next : State) (tokenSlot : Nat) : Result Unit :=
  forEach (List.range tokenWidth) fun t => do
    if t != tokenSlot then
      let before ← atIndex prev.fund.amounts.values t
      let after ← atIndex next.fund.amounts.values t
      check (before == after) .amount "other fund position"
def memberSlotIndex (record : Record) (pk : Hash) : Result Nat :=
  match firstIndex (fun key => key == pk) record.keys.values with
  | none => .error (.rejected .linkage "member key not found")
  | some index => .ok index
def memberIndexKey (record : Record) (index : Nat) : Result Hash :=
  match record.keys.values[index]? with
  | none => .error (.rejected .linkage "member index out of range")
  | some key => .ok key
def verifyNextStateSignatures {Tree : Type} (e : Environment Tree) (record : Record) (next : State) : Result Unit :=
  mapRejected .signatures (e.validateStateSignatureStructure record next.signatures)
def validateSignedSmallBlock {Tree : Type} (e : Environment Tree) (record : Record)
    (sourceChannel nonce : Nat) (tx : InterTx) : Result Unit := do
  check (tx.sourceChannel == sourceChannel) .smallBlock "source channel"
  let signed := tx.signedBlock
  check (signed.message.channelId == sourceChannel) .smallBlock "message channel"
  -- Preserve short-circuit evaluation: no BP index lookup on a mismatched slot.
  if signed.message.bpSlot != record.bpSlot then
    throw (.rejected .smallBlock "BP mismatch")
  let key ← memberIndexKey record record.bpSlot
  check (signed.message.bpKey == key) .smallBlock "BP mismatch"
  check (signed.message.closeNonce == nonce) .smallBlock "close nonce"
  check (signed.message.mediumEpoch == 0 && signed.mediumBlock == 0) .smallBlock "retired medium numbers"
  check signed.aggregateProof.isEmpty .smallBlock "retired aggregate proof"
  check signed.confirmationProof.isEmpty .smallBlock "retired confirmation proof"
  check (tx.transactionSeal == zero && tx.memo.isEmpty && tx.transportBytes.isEmpty &&
    tx.inclusion.siblings.isEmpty && tx.inclusion.index.val == 0) .smallBlock "retired inter fields"
  check (tx.transferCommitment != zero) .smallBlock "base transfer commitment"
  mapRejected .smallBlock (e.validateSignatureSlots record signed.signatures)
def ensureSameChannelFund (prev next : State) : Result Unit :=
  check (prev.fund == next.fund) .root "channel fund"
def ensureSameRoot (name : String) (before after : Hash) : Result Unit := check (before == after) .root name
def ensureDifferentRoot (name : String) (before after : Hash) : Result Unit := check (before != after) .root name
def ensureSameU256 (name : String) (before after : Amount) : Result Unit := check (before == after) .root name

/-- Aliases below package repeated source expressions, without reordering checks. -/
def ciphertextAt (state : State) (member token : Nat) : Result Ciphertext := do
  let row ← atIndex state.balance.ciphertexts member
  atIndex row.values token
def pendingAt (state : State) (member token : Nat) : Result Nat := do
  let row ← atIndex state.balance.pending member
  atIndex row.values token
def fundAt (state : State) (token : Nat) : Result Amount := atIndex state.fund.amounts.values token
def pendingReset (next : State) (member token : Nat) : Result Unit := do
  let count ← pendingAt next member token
  check (count == 0) .pending "fresh selected position"
def debitFundAt (prev next : State) (token amount : Nat) : Result Unit := do
  let after ← fundAt next token
  let amount256 ← u64ToU256 amount
  let sum ← addAmount after amount256
  let before ← fundAt prev token
  check (sum == before) .amount "fund decrease at resolved token"
def creditFundAt (prev next : State) (token amount : Nat) : Result Unit := do
  let after ← fundAt next token
  let before ← fundAt prev token
  let amount256 ← u64ToU256 amount
  let sum ← addAmount before amount256
  check (after == sum) .amount "fund increase at resolved token"
def creditUnallocated (prev next : State) (amount : Nat) : Result Unit := do
  let amount256 ← u64ToU256 amount
  let sum ← addAmount prev.unallocated amount256
  check (next.unallocated == sum) .amount "unallocated increase"
def debitUnallocated (prev next : State) (amount : Nat) : Result Unit := do
  let amount256 ← u64ToU256 amount
  let sum ← addAmount next.unallocated amount256
  check (prev.unallocated == sum) .amount "unallocated decrease"
def recipientAdd {Tree : Type} (e : Environment Tree) (prev next : State)
    (recipient token : Nat) (delta : Ciphertext) : Result Unit := do
  let before ← ciphertextAt prev recipient token
  let expected ← mapRejected .ciphertext (e.ciphertextAdd before delta)
  let after ← ciphertextAt next recipient token
  check (after == expected) .ciphertext "recipient homomorphic add"
def recipientDecrypt {Tree : Type} (e : Environment Tree) (next : State) (recipient token : Nat)
    (delta : Ciphertext) (secret : Option SecretKey) (expected : Option Nat) : Result Unit := do
  match secret with
  | none => pure ()
  | some sk =>
    let expected ← match expected with
      | none => throw (.rejected .decryption "recipient_sk requires expected_amount")
      | some expected => pure expected
    let decrypted ← mapRejected .decryption (e.decrypt sk delta)
    check (decrypted == expected) .decryption "expected delta plaintext"
    let after ← ciphertextAt next recipient token
    let _ ← mapRejected .decryption (e.decrypt sk after)
    pure ()
def baseInputs (kind : Kind) (prev next : State) (amount receiverCount : Nat)
    (senderHash receiverHash transitionDigest : Hash) : PublicInputs :=
  { kind, channelId := prev.channelId, prevDigest := prev.digest, nextDigest := next.digest,
    amount, prevVersion := prev.balance.version, nextVersion := next.balance.version,
    h2 := next.h2, prevChain := prev.balance.chain, nextChain := next.balance.chain,
    receiverCount, senderHash, receiverHash, fundBefore := prev.fund.amounts,
    fundAfter := next.fund.amounts, unallocatedBefore := prev.unallocated,
    unallocatedAfter := next.unallocated, nullifierBefore := prev.nullifierRoot,
    nullifierAfter := next.nullifierRoot, transitionDigest }

structure InChannelWitness where
  record : Record
  keys : Slots PublicKey
  prev : State
  next : State
  tx : ChannelTx
  senderIndex : Nat
  recipientIndex : Nat
  recipientSk : Option SecretKey
  expectedAmount : Option Nat
structure SendWitness where
  record : Record
  keys : Slots PublicKey
  destinationRecipientPk : PublicKey
  prev : State
  next : State
  tx : InterTx
  amount : Nat
  transport : Envelope
structure FundImportWitness where
  sourceRecord : Record
  receiverRecord : Record
  prev : State
  next : State
  tx : InterTx
  amount : Nat
  transport : Envelope
structure DepositWitness where
  record : Record
  prev : State
  next : State
  amount : Nat
  nullifier : Hash
  tokenIndex : Nat
  depositorSlot : Nat
structure BundleWitness where
  receiverRecord : Record
  keys : Slots PublicKey
  sourceSenderPk : PublicKey
  senderBefore : Ciphertext
  senderAfter : Ciphertext
  prev : State
  next : State
  tx : InterTx
  amount : Nat
  recipientIndex : Nat
  recipientSk : Option SecretKey
  expectedAmount : Option Nat
structure RefreshWitness where
  record : Record
  keys : Slots PublicKey
  prev : State
  next : State
  memberIndex : Nat
  tokenSlot : Nat
  proof : Envelope
structure TokenRegisterWitness where
  record : Record
  prev : State
  next : State
  tokenIndex : Nat

def verifyInChannel {Tree : Type} (e : Environment Tree) (verifier : RegevVerifier)
    (w : InChannelWitness) : Result PublicInputs := do
  verifyRegevPkRoot e w.record w.keys
  verifyStateLinkage e w.prev w.next
  verifyBalanceCommon e w.record w.prev w.next
  requireSmallBlockUnchanged w.prev w.next
  requireH2Zero w.next
  requireChainUnchanged w.prev w.next
  requireAccumulatorUnchanged w.prev.balance.accumulator w.next.balance.accumulator
  ensureSameChannelFund w.prev w.next
  ensureSameU256 "unallocated" w.prev.unallocated w.next.unallocated
  ensureSameRoot "nullifier" w.prev.nullifierRoot w.next.nullifierRoot
  verifyNextStateSignatures e w.record w.next
  let sender ← memberIndexKey w.record w.senderIndex
  let recipient ← memberIndexKey w.record w.recipientIndex
  check (w.senderIndex != w.recipientIndex) .linkage "distinct parties"
  check (w.tx.sender == sender) .transition "sender key"
  check (w.tx.recipient == recipient) .transition "recipient key"
  check (!w.tx.senderHashSignature.isEmpty) .signatures "sender hash-signature present"
  let transition ← e.channelTxDigest w.prev.channelId w.prev.digest w.tx.encryptedAmount w.tx.nonce
    w.tx.tokenSlot w.tx.sender w.tx.recipient
  let token := w.tx.tokenSlot
  check (token < tokenWidth) .ciphertext "token layout bound"
  check (token < w.prev.balance.tokenCount) .ciphertext "active token bound"
  recipientAdd e w.prev w.next w.recipientIndex token w.tx.encryptedAmount
  ensureRowUnchangedExcept w.prev w.next w.recipientIndex token
  ensureRowUnchangedExcept w.prev w.next w.senderIndex token
  forEach (List.range slotCount) fun index => do
    if index != w.senderIndex && index != w.recipientIndex then
      ensureSlotUnchanged w.prev w.next index
  requirePendingIncrement w.prev w.next w.recipientIndex token
  pendingReset w.next w.senderIndex token
  requirePendingUnchangedExcept w.prev w.next w.senderIndex token
  forEach (List.range slotCount) fun index => do
    if index != w.senderIndex && index != w.recipientIndex then
      requirePendingUnchanged w.prev w.next index
  let senderPk ← atIndex w.keys.values w.senderIndex
  let recipientPk ← atIndex w.keys.values w.recipientIndex
  let before ← ciphertextAt w.prev w.senderIndex token
  let after ← ciphertextAt w.next w.senderIndex token
  verifier w.tx.regevProof .channelTx
    (.channelTx senderPk recipientPk before w.tx.encryptedAmount after)
  recipientDecrypt e w.next w.recipientIndex token w.tx.encryptedAmount w.recipientSk w.expectedAmount
  let senderHash ← hashMember e w.tx.sender
  let receiverHash ← hashMember e w.tx.recipient
  return baseInputs .inChannel w.prev w.next 0 1 senderHash receiverHash transition

def verifySend {Tree : Type} (e : Environment Tree) (transport : TransportVerifier)
    (regev : RegevVerifier) (w : SendWitness) : Result PublicInputs := do
  verifyRegevPkRoot e w.record w.keys
  verifyStateLinkage e w.prev w.next
  verifyBalanceCommon e w.record w.prev w.next
  verifyNextStateSignatures e w.record w.next
  validateSignedSmallBlock e w.record w.prev.channelId w.prev.closeNonce w.tx
  check (w.prev.channelId == w.tx.sourceChannel) .linkage "source channel id"
  check (w.tx.signedBlock.message.txRoot != zero) .h2 "nonzero send h2"
  check (w.next.h2 == w.tx.signedBlock.message.txRoot) .h2 "send h2 target"
  let h1 ← e.balanceH1 w.next.balance
  check (w.tx.signedBlock.message.stateRoot == h1) .smallBlock "post-debit H1"
  check (w.tx.receivers.length == 1) .bundle "exact one receiver"
  let receiver ← atIndex w.tx.receivers 0
  let leaf ← mapRejected .chain (e.txLeaf w.tx)
  let chainLeaf ← if w.tx.destinationChannel == burnChannel then do
      let amount256 ← u64ToU256 w.amount
      e.burnDescriptor w.tx.sourceChannel w.tx.baseNonce leaf receiver.recipient w.tx.tokenIndex amount256
    else pure leaf
  requireChainPush e w.prev w.next chainLeaf
  -- Source does NOT invoke requireAccumulatorPush here: wallet frontier boundary.
  let token ← resolveTokenSlot w.prev.balance w.tx.tokenIndex
  requireTokenBearingHash e w.tx
  debitFundAt w.prev w.next token w.amount
  ensureFundsUnchangedExcept w.prev w.next token
  ensureSameU256 "unallocated" w.prev.unallocated w.next.unallocated
  ensureDifferentRoot "nullifier" w.prev.nullifierRoot w.next.nullifierRoot
  let sender ← memberSlotIndex w.record w.tx.sender
  forEach (List.range slotCount) fun index => do
    if index != sender then
      ensureSlotUnchanged w.prev w.next index
      requirePendingUnchanged w.prev w.next index
  ensureRowUnchangedExcept w.prev w.next sender token
  pendingReset w.next sender token
  requirePendingUnchangedExcept w.prev w.next sender token
  let key ← atIndex w.keys.values sender
  let before ← ciphertextAt w.prev sender token
  let after ← ciphertextAt w.next sender token
  regev w.tx.regevProof .channelUpdate (.channelUpdate key w.destinationRecipientPk before after
    w.tx.senderDelta receiver.ciphertext w.amount w.tx.tokenIndex)
  check (w.tx.transportBytes == w.transport.proof) .transition "transport bytes"
  let senderHash ← hashMember e w.tx.sender
  let receiverHash ← hashMember e receiver.recipient
  let transition ← e.interSigningDigest w.tx
  let p := baseInputs .send w.prev w.next w.amount 1 senderHash receiverHash transition
  verifyProof transport w.transport .transport .plonky2 p
  return p

def verifyFundImport {Tree : Type} (e : Environment Tree) (transport : TransportVerifier)
    (w : FundImportWitness) : Result PublicInputs := do
  verifyStateLinkage e w.prev w.next
  verifyBalanceCommon e w.receiverRecord w.prev w.next
  verifyNextStateSignatures e w.receiverRecord w.next
  -- Source nonce argument is the message's own nonce, not a receiver-local nonce.
  validateSignedSmallBlock e w.sourceRecord w.tx.sourceChannel w.tx.signedBlock.message.closeNonce w.tx
  check (w.prev.channelId == w.tx.destinationChannel) .linkage "destination channel id"
  requireH2Zero w.next
  let leaf ← mapRejected .chain (e.txLeaf w.tx)
  requireChainPush e w.prev w.next leaf
  let token ← resolveTokenSlot w.prev.balance w.tx.tokenIndex
  requireTokenBearingHash e w.tx
  creditFundAt w.prev w.next token w.amount
  ensureFundsUnchangedExcept w.prev w.next token
  creditUnallocated w.prev w.next w.amount
  forEach (List.range slotCount) fun index => do
    ensureSlotUnchanged w.prev w.next index
    requirePendingUnchanged w.prev w.next index
  ensureDifferentRoot "nullifier" w.prev.nullifierRoot w.next.nullifierRoot
  check (w.tx.transportBytes == w.transport.proof) .transition "transport bytes"
  let receiver ← match w.tx.receivers.head? with
    | none => throw (.rejected .bundle "fund import requires receiver")
    | some receiver => pure receiver
  let senderHash ← hashMember e w.tx.sender
  let receiverHash ← hashMember e receiver.recipient
  let transition ← e.interSigningDigest w.tx
  let p := baseInputs .fundImport w.prev w.next w.amount (w.tx.receivers.length % scalarLimit)
    senderHash receiverHash transition
  verifyProof transport w.transport .transport .plonky2 p
  return p

def verifyDeposit {Tree : Type} (e : Environment Tree) (w : DepositWitness) : Result PublicInputs := do
  verifyStateLinkage e w.prev w.next
  verifyBalanceCommon e w.record w.prev w.next
  verifyNextStateSignatures e w.record w.next
  requireH2Zero w.next
  requireChainPush e w.prev w.next w.nullifier
  let token ← resolveTokenSlot w.prev.balance w.tokenIndex
  creditFundAt w.prev w.next token w.amount
  ensureFundsUnchangedExcept w.prev w.next token
  creditUnallocated w.prev w.next w.amount
  forEach (List.range slotCount) fun index => do
    ensureSlotUnchanged w.prev w.next index
    requirePendingUnchanged w.prev w.next index
  ensureDifferentRoot "nullifier" w.prev.nullifierRoot w.next.nullifierRoot
  -- Direct native array indexing, NOT the checked memberIndexKey helper.
  let depositor ← atIndex w.record.keys.values w.depositorSlot
  let transition ← e.depositDigest w.prev.channelId w.nullifier w.tokenIndex w.amount (w.depositorSlot % 65536)
  let senderHash ← hashMember e depositor
  let receiverHash ← hashMember e depositor
  return baseInputs .l1Deposit w.prev w.next w.amount 0 senderHash receiverHash transition

def verifyBundle {Tree : Type} (e : Environment Tree) (regev : RegevVerifier)
    (w : BundleWitness) : Result PublicInputs := do
  verifyRegevPkRoot e w.receiverRecord w.keys
  verifyStateLinkage e w.prev w.next
  verifyBalanceCommon e w.receiverRecord w.prev w.next
  verifyNextStateSignatures e w.receiverRecord w.next
  check (w.prev.channelId == w.tx.destinationChannel) .linkage "destination channel id"
  requireH2Zero w.next
  ensureSameChannelFund w.prev w.next
  debitUnallocated w.prev w.next w.amount
  ensureSameRoot "nullifier" w.prev.nullifierRoot w.next.nullifierRoot
  check (w.tx.receivers.length == 1) .bundle "exact one receiver"
  let receiver ← atIndex w.tx.receivers 0
  let recipient ← memberIndexKey w.receiverRecord w.recipientIndex
  check (receiver.recipient == recipient) .bundle "recipient key"
  requireChainUnchanged w.prev w.next
  requireAccumulatorUnchanged w.prev.balance.accumulator w.next.balance.accumulator
  let token ← resolveTokenSlot w.prev.balance w.tx.tokenIndex
  requireTokenBearingHash e w.tx
  recipientAdd e w.prev w.next w.recipientIndex token receiver.ciphertext
  ensureRowUnchangedExcept w.prev w.next w.recipientIndex token
  forEach (List.range slotCount) fun index => do
    if index != w.recipientIndex then
      ensureSlotUnchanged w.prev w.next index
      requirePendingUnchanged w.prev w.next index
  requirePendingIncrement w.prev w.next w.recipientIndex token
  let recipientPk ← atIndex w.keys.values w.recipientIndex
  regev w.tx.regevProof .channelUpdate (.channelUpdate w.sourceSenderPk recipientPk
    w.senderBefore w.senderAfter w.tx.senderDelta receiver.ciphertext w.amount w.tx.tokenIndex)
  recipientDecrypt e w.next w.recipientIndex token receiver.ciphertext w.recipientSk w.expectedAmount
  let senderHash ← hashMember e w.tx.sender
  let receiverHash ← hashMember e receiver.recipient
  let transition ← e.interSigningDigest w.tx
  return baseInputs .bundleApply w.prev w.next w.amount 1 senderHash receiverHash transition

def refreshDomain : Nat := 0x494d5246
def refreshPreimage (member token : Nat) (oldDigest newDigest : Hash) : List Nat :=
  [refreshDomain,member % wordBase,token % wordBase] ++ oldDigest.words ++ newDigest.words
def verifyRefresh {Tree : Type} (e : Environment Tree) (regev : RegevVerifier)
    (w : RefreshWitness) : Result PublicInputs := do
  verifyRegevPkRoot e w.record w.keys
  verifyStateLinkage e w.prev w.next
  verifyBalanceCommon e w.record w.prev w.next
  requireSmallBlockUnchanged w.prev w.next
  verifyNextStateSignatures e w.record w.next
  requireH2Zero w.next
  requireChainUnchanged w.prev w.next
  requireAccumulatorUnchanged w.prev.balance.accumulator w.next.balance.accumulator
  ensureSameChannelFund w.prev w.next
  ensureSameU256 "unallocated" w.prev.unallocated w.next.unallocated
  ensureSameRoot "nullifier" w.prev.nullifierRoot w.next.nullifierRoot
  let member ← memberIndexKey w.record w.memberIndex
  forEach (List.range slotCount) fun index => do
    if index != w.memberIndex then
      ensureSlotUnchanged w.prev w.next index
      requirePendingUnchanged w.prev w.next index
  let token := w.tokenSlot
  check (token < tokenWidth) .ciphertext "token layout bound"
  check (token < w.prev.balance.tokenCount) .ciphertext "active token bound"
  pendingReset w.next w.memberIndex token
  requirePendingUnchangedExcept w.prev w.next w.memberIndex token
  ensureRowUnchangedExcept w.prev w.next w.memberIndex token
  let old ← ciphertextAt w.prev w.memberIndex token
  let new ← ciphertextAt w.next w.memberIndex token
  let key ← atIndex w.keys.values w.memberIndex
  regev w.proof .refresh (.refresh key old new)
  let oldDigest ← e.ciphertextDigest old
  let newDigest ← e.ciphertextDigest new
  let transition ← e.hashWords (refreshPreimage w.memberIndex token oldDigest newDigest)
  let senderHash ← hashMember e member
  let receiverHash ← hashMember e member
  return baseInputs .refresh w.prev w.next 0 0 senderHash receiverHash transition

def verifyTokenRegister {Tree : Type} (e : Environment Tree) (w : TokenRegisterWitness) : Result PublicInputs := do
  verifyStateLinkage e w.prev w.next
  verifyBalanceShared e w.record w.prev w.next
  mapRejected .linkage (e.tokenRegisterBalance w.prev.balance w.next.balance w.tokenIndex)
  requireH2Zero w.next
  requireChainUnchanged w.prev w.next
  requireAccumulatorUnchanged w.prev.balance.accumulator w.next.balance.accumulator
  ensureSameChannelFund w.prev w.next
  ensureSameU256 "unallocated" w.prev.unallocated w.next.unallocated
  ensureSameRoot "nullifier" w.prev.nullifierRoot w.next.nullifierRoot
  requireSmallBlockUnchanged w.prev w.next
  check (w.next.closeNonce == w.prev.closeNonce) .linkage "close era"
  let expected ← mapRejected .linkage (e.tokenRegisterState w.prev w.tokenIndex)
  check ({expected with signatures := w.next.signatures} == w.next) .linkage "canonical whole state"
  verifyNextStateSignatures e w.record w.next
  return baseInputs .tokenRegister w.prev w.next 0 0 zero zero w.next.digest

/-! Representation domains (not runtime admission predicates). Vec lengths remain
arbitrary. In particular these do NOT assume canonical modulo-q ciphertexts,
active membership, registry uniqueness, backing, valid signatures or valid proofs.
Machine usize is taken as 64-bit for the audited host; a 32-bit target needs its own
domain. Addresses are native 160-bit values; U256 is already Fin (2^256). -/
def WordsWidth (xs : List Nat) (bits : Nat) : Prop := ∀ x ∈ xs, x < 2^bits
def HashWidth (hash : Hash) : Prop := WordsWidth hash.words 32
def CiphertextWidth (ct : Ciphertext) : Prop := WordsWidth ct.c1 32 ∧ WordsWidth ct.c2 32
def KeyWidth (pk : PublicKey) : Prop := WordsWidth pk.a 32 ∧ WordsWidth pk.b 32
def SignatureWidth (signature : Signature) : Prop :=
  signature.slot < 256 ∧ HashWidth signature.pk ∧ WordsWidth signature.bytes 8
def BalanceWidth (balance : Balance) : Prop :=
  balance.channelId < wordBase ∧ balance.memberCount < 256 ∧ balance.delegateCount < 65536 ∧
  (∀ row ∈ balance.ciphertexts, ∀ ct ∈ row.values, CiphertextWidth ct) ∧
  (∀ digest ∈ balance.regevDigests.values, HashWidth digest) ∧ WordsWidth balance.recipients.values 160 ∧
  HashWidth balance.chain ∧ HashWidth balance.accumulator ∧ balance.version < scalarLimit ∧
  (∀ row ∈ balance.pending, WordsWidth row.values 32) ∧ WordsWidth balance.registry.values 32 ∧
  balance.tokenCount < 256
def StateWidth (state : State) : Prop :=
  state.channelId < wordBase ∧ state.epoch < scalarLimit ∧ state.smallBlock < scalarLimit ∧
  state.closeNonce < scalarLimit ∧ state.fund.channelId < wordBase ∧ HashWidth state.fund.root ∧
  BalanceWidth state.balance ∧ HashWidth state.h2 ∧ HashWidth state.nullifierRoot ∧
  HashWidth state.prevDigest ∧ HashWidth state.digest ∧ (∀ sig ∈ state.signatures, SignatureWidth sig)
def NativeWidths (p : PublicInputs) : Prop :=
  p.channelId < wordBase ∧ p.amount < scalarLimit ∧ p.prevVersion < scalarLimit ∧
  p.nextVersion < scalarLimit ∧ p.receiverCount < scalarLimit ∧
  (∀ hash ∈ [p.prevDigest,p.nextDigest,p.h2,p.prevChain,p.nextChain,p.senderHash,p.receiverHash,
    p.nullifierBefore,p.nullifierAfter,p.transitionDigest], HashWidth hash)

/-! Kernel-checked local properties. Success hypotheses concern the executable
guards above, never an idealized predicate named "safe". -/
theorem check_ok_iff (condition : Bool) (category : Category) (label : String) :
    check condition category label = .ok () ↔ condition = true := by
  cases condition <;> simp [check]
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
  · intro h; exact ⟨(),h⟩
theorem map_rejected_ok_iff {α : Type} (category : Category) (r : Result α) (value : α) :
    mapRejected category r = .ok value ↔ r = .ok value := by
  cases r with
  | ok value => rfl
  | error error => cases error <;> simp [mapRejected]
theorem for_each_success {α : Type} (xs : List α) (action : α → Result Unit) :
    forEach xs action = .ok () ↔ ∀ x ∈ xs, action x = .ok () := by
  induction xs with
  | nil => simp [forEach]
  | cons x xs ih => simp [forEach, unit_bind_ok_iff, ih]
theorem scalar_checked_success (n result : Nat) :
    addScalarOne .checked n = .ok result ↔ n+1 < scalarLimit ∧ result = n+1 := by
  simp only [addScalarOne]
  split <;> simp_all [eq_comm] <;> omega
theorem scalar_wrapping_no_overflow (n : Nat) (bound : n+1 < scalarLimit) :
    addScalarOne .wrapping n = .ok (n+1) := by
  simp [addScalarOne, Nat.mod_eq_of_lt bound]
theorem native_amount_add_success (a b result : Amount) :
    addAmount a b = .ok result ↔ result.val = a.val+b.val := by
  unfold addAmount
  split
  · simp only [Except.ok.injEq, Fin.ext_iff]; omega
  · simp only [Except.noConfusion, false_iff]
    have bound := result.isLt
    omega
theorem native_amount_add_no_wrap (a b result : Amount)
    (accepted : addAmount a b = .ok result) :
    a.val ≤ result.val ∧ b.val ≤ result.val ∧ a.val+b.val < 2^256 := by
  have exactSum := (native_amount_add_success a b result).mp accepted
  have _bound := result.isLt
  omega
theorem u64_embedding_exact (n : Nat) (bound : n < scalarLimit) :
    ∃ value, u64ToU256 n = .ok value ∧ value.val = n := by
  refine ⟨⟨n % scalarLimit, ?_⟩, rfl, Nat.mod_eq_of_lt bound⟩
  have modBound := Nat.mod_lt n (by decide : 0 < scalarLimit)
  unfold scalarLimit at *
  omega
theorem amount_words_length (a : Amount) : (amountWords a).length = 8 := by
  simp only [amountWords, List.length_map, List.length_reverse]
  decide
theorem fund_words_length (fund : Ten Amount) : (fundWords fund).length = 80 := by
  cases fund
  simp [fundWords, ClosePublicInputs.Ten.values, amount_words_length]
theorem public_words_length (p : PublicInputs) : (publicWords p).length = 266 := by
  simp [publicWords, splitU64, ClosePublicInputs.Words8.words, fund_words_length, amount_words_length]
theorem refresh_preimage_length (member token : Nat) (old new : Hash) :
    (refreshPreimage member token old new).length = 19 := by
  simp [refreshPreimage, ClosePublicInputs.Words8.words]
theorem base_inputs_full_fund_vectors (kind : Kind) (prev next : State) (amount count : Nat)
    (sender receiver transition : Hash) :
    (baseInputs kind prev next amount count sender receiver transition).fundBefore = prev.fund.amounts ∧
    (baseInputs kind prev next amount count sender receiver transition).fundAfter = next.fund.amounts ∧
    (baseInputs kind prev next amount count sender receiver transition).unallocatedBefore = prev.unallocated ∧
    (baseInputs kind prev next amount count sender receiver transition).unallocatedAfter = next.unallocated := by
  exact ⟨rfl,rfl,rfl,rfl⟩
theorem ordinary_metadata_success (record : Record) (prev next : State) :
    verifyOrdinaryStateMetadata record prev next = .ok () ↔
    prev.balance.memberCount = record.memberCount ∧ prev.balance.delegateCount = record.delegateCount ∧
    next.balance.memberCount = record.memberCount ∧ next.balance.delegateCount = record.delegateCount ∧
    next.closeNonce = prev.closeNonce := by
  simp [verifyOrdinaryStateMetadata, unit_bind_ok_iff, for_each_success, check_ok_iff, and_assoc]
theorem balance_shared_success {Tree : Type} (e : Environment Tree) (record : Record) (prev next : State)
    (accepted : verifyBalanceShared e record prev next = .ok ()) :
    next.closeNonce = prev.closeNonce ∧ prev.balance.recipients = next.balance.recipients ∧
    prev.balance.regevDigests = next.balance.regevDigests ∧
    prev.balance.channelId = prev.channelId ∧ next.balance.channelId = next.channelId ∧
    prev.channelId = record.channelId ∧
    ∃ version, addScalarOne e.mode prev.balance.version = .ok version ∧ next.balance.version = version := by
  simp only [verifyBalanceShared, bind_ok_iff, exists_unit] at accepted
  rcases accepted with ⟨metadata, _, _, channels, version, inc, versionEq, recipients, digests⟩
  have era := (ordinary_metadata_success record prev next).mp metadata
  simp only [check_ok_iff, beq_iff_eq, Bool.and_eq_true] at channels versionEq recipients digests
  exact ⟨era.2.2.2.2, recipients, digests, channels.1.1, channels.1.2, channels.2,
    version, inc, versionEq⟩
theorem balance_common_registry_success {Tree : Type} (e : Environment Tree)
    (record : Record) (prev next : State) (accepted : verifyBalanceCommon e record prev next = .ok ()) :
    verifyBalanceShared e record prev next = .ok () ∧
    prev.balance.registry = next.balance.registry ∧ prev.balance.tokenCount = next.balance.tokenCount := by
  simpa [verifyBalanceCommon, unit_bind_ok_iff, check_ok_iff, and_assoc] using accepted
theorem unchanged_whole_fund (prev next : State) :
    ensureSameChannelFund prev next = .ok () ↔ prev.fund = next.fund := by
  simp [ensureSameChannelFund, check_ok_iff]
theorem h2_zero_success (next : State) : requireH2Zero next = .ok () ↔ next.h2 = zero := by
  simp [requireH2Zero, check_ok_iff]
theorem chain_unchanged_success (prev next : State) :
    requireChainUnchanged prev next = .ok () ↔ next.balance.chain = prev.balance.chain := by
  simp [requireChainUnchanged, check_ok_iff]
theorem accumulator_unchanged_success (prev next : Hash) :
    requireAccumulatorUnchanged prev next = .ok () ↔ prev = next := by
  simp [requireAccumulatorUnchanged, check_ok_iff]
theorem unequal_root_is_only_inequality (label : String) (before after : Hash) :
    ensureDifferentRoot label before after = .ok () ↔ before ≠ after := by
  simp [ensureDifferentRoot, check_ok_iff]
theorem transport_exact_call (verifier : TransportVerifier) (proof : Envelope)
    (role : Role) (backend : Backend) (p : PublicInputs) :
    verifyProof verifier proof role backend p = .ok () ↔
    proof.role = role ∧ proof.backend = backend ∧ verifier proof p = .ok () := by
  simp [verifyProof, unit_bind_ok_iff, check_ok_iff]
theorem real_regev_exact_call (real : Purpose → List Nat → RegevStatement → Result Unit)
    (proof : Envelope) (purpose : Purpose) (statement : RegevStatement) :
    realRegevVerify real proof purpose statement = .ok () ↔
    proof.role = .stateUpdate ∧ proof.backend = .plonky3 ∧ real purpose proof.proof statement = .ok () := by
  simp [realRegevVerify, unit_bind_ok_iff, check_ok_iff, map_rejected_ok_iff]
theorem signature_check_is_structural {Tree : Type} (e : Environment Tree) (record : Record) (next : State) :
    verifyNextStateSignatures e record next = .ok () ↔
    e.validateStateSignatureStructure record next.signatures = .ok () := by
  simp [verifyNextStateSignatures, map_rejected_ok_iff]

theorem at_index_success {α : Type} (xs : List α) (index : Nat) (value : α) :
    atIndex xs index = .ok value ↔ xs[index]? = some value := by
  unfold atIndex
  cases h : xs[index]? <;> simp [h]
theorem first_index_found {α : Type} (predicate : α → Bool) (xs : List α) (index : Nat)
    (found : firstIndex predicate xs = some index) :
    ∃ value, xs[index]? = some value ∧ predicate value = true := by
  induction xs generalizing index with
  | nil => simp [firstIndex] at found
  | cons x xs ih =>
    simp only [firstIndex] at found
    split at found
    · cases found
      exact ⟨x, by simp, by assumption⟩
    · cases tail : firstIndex predicate xs with
      | none => simp [tail] at found
      | some i =>
        simp only [tail, Option.map_some', Option.some.injEq] at found
        cases found
        obtain ⟨value, lookup, matched⟩ := ih i tail
        exact ⟨value, by simpa using lookup, matched⟩
theorem registry_resolution_exact (balance : Balance) (baseToken index : Nat)
    (accepted : resolveTokenSlot balance baseToken = .ok index) :
    (balance.registry.values.take (min balance.tokenCount tokenWidth))[index]? = some baseToken := by
  unfold resolveTokenSlot at accepted
  cases found : firstIndex (fun i => i == baseToken)
      (balance.registry.values.take (min balance.tokenCount tokenWidth)) with
  | none => simp [found] at accepted
  | some i =>
    simp only [found, Except.ok.injEq] at accepted
    subst i
    obtain ⟨value, lookup, matched⟩ := first_index_found _ _ _ found
    have same : value = baseToken := by simpa using matched
    simpa [same] using lookup
theorem other_fund_positions_frozen (prev next : State) (selected token : Nat)
    (range : token ∈ List.range tokenWidth) (other : token ≠ selected)
    (accepted : ensureFundsUnchangedExcept prev next selected = .ok ()) :
    ∃ before after, fundAt prev token = .ok before ∧ fundAt next token = .ok after ∧ before = after := by
  have one := (for_each_success _ _).mp accepted token range
  simp only [ne_eq, bne_iff_ne, other, not_false_eq_true, if_true, ite_true, bind_ok_iff,
    exists_unit, check_ok_iff, beq_iff_eq] at one
  obtain ⟨before, beforeAt, after, afterAt, same⟩ := one
  exact ⟨before, after, beforeAt, afterAt, same⟩
theorem debit_fund_exact (prev next : State) (token amount : Nat)
    (accepted : debitFundAt prev next token amount = .ok ()) :
    ∃ before after, fundAt prev token = .ok before ∧ fundAt next token = .ok after ∧
      before.val = after.val + amount % scalarLimit := by
  simp only [debitFundAt, bind_ok_iff, exists_unit] at accepted
  rcases accepted with ⟨after, afterAt, embedded, embeddedEq, sum, sumEq, before, beforeAt, checked⟩
  have embeddedVal : embedded.val = amount % scalarLimit := by
    simp only [u64ToU256, Except.ok.injEq, Fin.ext_iff] at embeddedEq
    exact embeddedEq.symm
  have equal : sum = before := by simpa [check_ok_iff] using checked
  have exactSum := (native_amount_add_success after embedded sum).mp sumEq
  refine ⟨before,after,beforeAt,afterAt,?_⟩
  simpa [equal,embeddedVal] using exactSum
theorem credit_fund_exact (prev next : State) (token amount : Nat)
    (accepted : creditFundAt prev next token amount = .ok ()) :
    ∃ before after, fundAt prev token = .ok before ∧ fundAt next token = .ok after ∧
      after.val = before.val + amount % scalarLimit := by
  simp only [creditFundAt, bind_ok_iff, exists_unit] at accepted
  rcases accepted with ⟨after, afterAt, before, beforeAt, embedded, embeddedEq, sum, sumEq, checked⟩
  have embeddedVal : embedded.val = amount % scalarLimit := by
    simp only [u64ToU256, Except.ok.injEq, Fin.ext_iff] at embeddedEq
    exact embeddedEq.symm
  have equal : after = sum := by simpa [check_ok_iff] using checked
  have exactSum := (native_amount_add_success before embedded sum).mp sumEq
  refine ⟨before,after,beforeAt,afterAt,?_⟩
  simpa [equal,embeddedVal] using exactSum
theorem credit_unallocated_exact (prev next : State) (amount : Nat)
    (accepted : creditUnallocated prev next amount = .ok ()) :
    next.unallocated.val = prev.unallocated.val + amount % scalarLimit := by
  simp only [creditUnallocated, bind_ok_iff, exists_unit] at accepted
  rcases accepted with ⟨embedded, embeddedEq, sum, sumEq, checked⟩
  have embeddedVal : embedded.val = amount % scalarLimit := by
    simp only [u64ToU256, Except.ok.injEq, Fin.ext_iff] at embeddedEq
    exact embeddedEq.symm
  have equal : next.unallocated = sum := by simpa [check_ok_iff] using checked
  simpa [← equal,embeddedVal] using (native_amount_add_success prev.unallocated embedded sum).mp sumEq
theorem debit_unallocated_exact (prev next : State) (amount : Nat)
    (accepted : debitUnallocated prev next amount = .ok ()) :
    prev.unallocated.val = next.unallocated.val + amount % scalarLimit := by
  simp only [debitUnallocated, bind_ok_iff, exists_unit] at accepted
  rcases accepted with ⟨embedded, embeddedEq, sum, sumEq, checked⟩
  have embeddedVal : embedded.val = amount % scalarLimit := by
    simp only [u64ToU256, Except.ok.injEq, Fin.ext_iff] at embeddedEq
    exact embeddedEq.symm
  have equal : prev.unallocated = sum := by simpa [check_ok_iff] using checked
  simpa [← equal,embeddedVal] using (native_amount_add_success next.unallocated embedded sum).mp sumEq
theorem pending_increment_budget (prev next : State) (index token : Nat)
    (accepted : requirePendingIncrement prev next index token = .ok ()) :
    ∃ before after, pendingAt prev index token = .ok before ∧ pendingAt next index token = .ok after ∧
      before < addBudget ∧ after = before+1 ∧ after ≤ addBudget ∧
      requirePendingUnchangedExcept prev next index token = .ok () := by
  simp only [requirePendingIncrement, bind_ok_iff, exists_unit] at accepted
  rcases accepted with ⟨beforeRow, beforeAt, afterRow, afterAt, before, beforeToken,
    after, afterToken, budget, inc, rest⟩
  have budget' : before < addBudget := by simpa [check_ok_iff] using budget
  have inc' : after = before+1 := by simpa [check_ok_iff] using inc
  refine ⟨before,after,?_,?_,budget',inc',by omega,rest⟩
  · simp [pendingAt, beforeAt, beforeToken, Bind.bind, Except.bind]
  · simp [pendingAt, afterAt, afterToken, Bind.bind, Except.bind]

/-- All data directly projected from prev/next remain exact; this says nothing
about whether an injected hash/proof implementation is cryptographically sound. -/
def OutputContext (kind : Kind) (prev next : State) (amount count : Nat) (p : PublicInputs) : Prop :=
  p.kind = kind ∧ p.channelId = prev.channelId ∧ p.prevDigest = prev.digest ∧ p.nextDigest = next.digest ∧
  p.amount = amount ∧ p.prevVersion = prev.balance.version ∧ p.nextVersion = next.balance.version ∧
  p.h2 = next.h2 ∧ p.prevChain = prev.balance.chain ∧ p.nextChain = next.balance.chain ∧
  p.receiverCount = count ∧ p.fundBefore = prev.fund.amounts ∧ p.fundAfter = next.fund.amounts ∧
  p.unallocatedBefore = prev.unallocated ∧ p.unallocatedAfter = next.unallocated ∧
  p.nullifierBefore = prev.nullifierRoot ∧ p.nullifierAfter = next.nullifierRoot
def Every {α : Type} (result : Result α) (property : α → Prop) : Prop :=
  ∀ value, result = .ok value → property value
theorem every_bind {α β : Type} (r : Result α) (f : α → Result β) (property : β → Prop)
    (continuations : ∀ x, Every (f x) property) : Every (r >>= f) property := by
  intro result accepted
  obtain ⟨x,_,next⟩ := (bind_ok_iff r f result).mp accepted
  exact continuations x result next
theorem base_context (kind : Kind) (prev next : State) (amount count : Nat) (s r d : Hash) :
    Every (.ok (baseInputs kind prev next amount count s r d)) (OutputContext kind prev next amount count) := by
  intro p accepted
  cases accepted
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩
theorem throw_ok_iff_false {α : Type} (fault : Fault) (value : α) :
    ((throw fault : Result α) = .ok value) ↔ False := by
  constructor
  · intro h; cases h
  · intro h; exact h.elim
theorem pure_ok_iff {α : Type} (a b : α) : (pure a : Result α) = .ok b ↔ a = b := by
  constructor
  · intro h; exact Except.ok.inj h
  · intro h; subst h; rfl
theorem in_channel_output {Tree : Type} (e : Environment Tree) (regev : RegevVerifier) (w : InChannelWitness) :
    Every (verifyInChannel e regev w) (OutputContext .inChannel w.prev w.next 0 1) := by
  -- Rewrite the accepted run into its statement conjunction instead of `apply`-peeling
  -- binds: a failing final `apply` made the unifier unfold `List.range slotCount`.
  intro p accepted
  simp only [verifyInChannel, bind_ok_iff, exists_unit, pure_ok_iff] at accepted
  repeat' (first
    | obtain ⟨_, accepted⟩ := (accepted : _ ∧ _)
    | obtain ⟨_, accepted⟩ := (accepted : ∃ _, _))
  subst accepted
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩
theorem send_output {Tree : Type} (e : Environment Tree) (transport : TransportVerifier)
    (regev : RegevVerifier) (w : SendWitness) :
    Every (verifySend e transport regev w) (OutputContext .send w.prev w.next w.amount 1) := by
  -- Rewrite the accepted run into its statement conjunction instead of `apply`-peeling
  -- binds: a failing final `apply` made the unifier unfold `List.range slotCount`.
  intro p accepted
  simp only [verifySend, bind_ok_iff, exists_unit, pure_ok_iff] at accepted
  repeat' (first
    | obtain ⟨_, accepted⟩ := (accepted : _ ∧ _)
    | obtain ⟨_, accepted⟩ := (accepted : ∃ _, _))
  -- The remaining hypothesis is the inlined branch join point; a `throw` branch
  -- reduces to `False` and closes its goal inside the simp call.
  split at accepted
  all_goals
    (simp only [bind_ok_iff, exists_unit, pure_ok_iff, throw_ok_iff_false, false_and,
      exists_false, and_false] at accepted) <;>
    (repeat' (first
      | obtain ⟨_, accepted⟩ := (accepted : _ ∧ _)
      | obtain ⟨_, accepted⟩ := (accepted : ∃ _, _));
     subst accepted;
     exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩)
theorem fund_import_output {Tree : Type} (e : Environment Tree) (transport : TransportVerifier)
    (w : FundImportWitness) :
    Every (verifyFundImport e transport w)
      (OutputContext .fundImport w.prev w.next w.amount (w.tx.receivers.length % scalarLimit)) := by
  -- Rewrite the accepted run into its statement conjunction instead of `apply`-peeling
  -- binds: a failing final `apply` made the unifier unfold `List.range slotCount`.
  intro p accepted
  simp only [verifyFundImport, bind_ok_iff, exists_unit, pure_ok_iff] at accepted
  repeat' (first
    | obtain ⟨_, accepted⟩ := (accepted : _ ∧ _)
    | obtain ⟨_, accepted⟩ := (accepted : ∃ _, _))
  -- The remaining hypothesis is the inlined branch join point; a `throw` branch
  -- reduces to `False` and closes its goal inside the simp call.
  split at accepted
  all_goals
    (simp only [bind_ok_iff, exists_unit, pure_ok_iff, throw_ok_iff_false, false_and,
      exists_false, and_false] at accepted) <;>
    (repeat' (first
      | obtain ⟨_, accepted⟩ := (accepted : _ ∧ _)
      | obtain ⟨_, accepted⟩ := (accepted : ∃ _, _));
     subst accepted;
     exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩)
theorem deposit_output {Tree : Type} (e : Environment Tree) (w : DepositWitness) :
    Every (verifyDeposit e w) (OutputContext .l1Deposit w.prev w.next w.amount 0) := by
  -- Rewrite the accepted run into its statement conjunction instead of `apply`-peeling
  -- binds: a failing final `apply` made the unifier unfold `List.range slotCount`.
  intro p accepted
  simp only [verifyDeposit, bind_ok_iff, exists_unit, pure_ok_iff] at accepted
  repeat' (first
    | obtain ⟨_, accepted⟩ := (accepted : _ ∧ _)
    | obtain ⟨_, accepted⟩ := (accepted : ∃ _, _))
  subst accepted
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩
theorem bundle_output {Tree : Type} (e : Environment Tree) (regev : RegevVerifier) (w : BundleWitness) :
    Every (verifyBundle e regev w) (OutputContext .bundleApply w.prev w.next w.amount 1) := by
  -- Rewrite the accepted run into its statement conjunction instead of `apply`-peeling
  -- binds: a failing final `apply` made the unifier unfold `List.range slotCount`.
  intro p accepted
  simp only [verifyBundle, bind_ok_iff, exists_unit, pure_ok_iff] at accepted
  repeat' (first
    | obtain ⟨_, accepted⟩ := (accepted : _ ∧ _)
    | obtain ⟨_, accepted⟩ := (accepted : ∃ _, _))
  subst accepted
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩
theorem refresh_output {Tree : Type} (e : Environment Tree) (regev : RegevVerifier) (w : RefreshWitness) :
    Every (verifyRefresh e regev w) (OutputContext .refresh w.prev w.next 0 0) := by
  -- Rewrite the accepted run into its statement conjunction instead of `apply`-peeling
  -- binds: a failing final `apply` made the unifier unfold `List.range slotCount`.
  intro p accepted
  simp only [verifyRefresh, bind_ok_iff, exists_unit, pure_ok_iff] at accepted
  repeat' (first
    | obtain ⟨_, accepted⟩ := (accepted : _ ∧ _)
    | obtain ⟨_, accepted⟩ := (accepted : ∃ _, _))
  subst accepted
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩
theorem token_register_output {Tree : Type} (e : Environment Tree) (w : TokenRegisterWitness) :
    Every (verifyTokenRegister e w) (OutputContext .tokenRegister w.prev w.next 0 0) := by
  -- Rewrite the accepted run into its statement conjunction instead of `apply`-peeling
  -- binds: a failing final `apply` made the unifier unfold `List.range slotCount`.
  intro p accepted
  simp only [verifyTokenRegister, bind_ok_iff, exists_unit, pure_ok_iff] at accepted
  repeat' (first
    | obtain ⟨_, accepted⟩ := (accepted : _ ∧ _)
    | obtain ⟨_, accepted⟩ := (accepted : ∃ _, _))
  subst accepted
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩

theorem in_channel_checked_guards {Tree : Type} (e : Environment Tree) (regev : RegevVerifier)
    (w : InChannelWitness) (p : PublicInputs) (accepted : verifyInChannel e regev w = .ok p) :
    verifyBalanceCommon e w.record w.prev w.next = .ok () ∧
    requireSmallBlockUnchanged w.prev w.next = .ok () ∧ requireH2Zero w.next = .ok () ∧
    requireChainUnchanged w.prev w.next = .ok () ∧
    requireAccumulatorUnchanged w.prev.balance.accumulator w.next.balance.accumulator = .ok () ∧
    w.prev.fund = w.next.fund ∧ w.prev.unallocated = w.next.unallocated ∧
    w.prev.nullifierRoot = w.next.nullifierRoot := by
  simp only [verifyInChannel, bind_ok_iff, exists_unit] at accepted
  rcases accepted with ⟨_,_,common,small,h2,chain,accumulator,fund,unallocated,nullifier,_⟩
  refine ⟨common,small,h2,chain,accumulator,(unchanged_whole_fund _ _).mp fund,?_,?_⟩
  · simpa [ensureSameU256,check_ok_iff] using unallocated
  · simpa [ensureSameRoot,check_ok_iff] using nullifier
theorem send_checked_guards {Tree : Type} (e : Environment Tree) (transport : TransportVerifier)
    (regev : RegevVerifier) (w : SendWitness) (p : PublicInputs)
    (accepted : verifySend e transport regev w = .ok p) :
    verifyBalanceCommon e w.record w.prev w.next = .ok () ∧
    validateSignedSmallBlock e w.record w.prev.channelId w.prev.closeNonce w.tx = .ok () ∧
    w.prev.channelId = w.tx.sourceChannel ∧ w.next.h2 = w.tx.signedBlock.message.txRoot ∧
    w.tx.signedBlock.message.txRoot ≠ zero ∧
    ∃ token, resolveTokenSlot w.prev.balance w.tx.tokenIndex = .ok token ∧
      requireTokenBearingHash e w.tx = .ok () ∧ debitFundAt w.prev w.next token w.amount = .ok () ∧
      ensureFundsUnchangedExcept w.prev w.next token = .ok () ∧
      w.prev.unallocated = w.next.unallocated ∧ w.prev.nullifierRoot ≠ w.next.nullifierRoot := by
  simp only [verifySend, bind_ok_iff, exists_unit] at accepted
  rcases accepted with ⟨_,_,common,_,small,source,nonzero,h2,_,_,_,_,_,_,_,_,branch⟩
  refine ⟨common,small,?_,?_,?_,?_⟩
  · simpa [check_ok_iff] using source
  · simpa [check_ok_iff] using h2
  · simpa [check_ok_iff] using nonzero
  -- Burn and non-burn chain leaves share the tail after the inlined join point.
  split at branch <;> simp only [bind_ok_iff, exists_unit] at branch
  · rcases branch with ⟨_,_,_,_,_,token,resolved,hash,debit,others,unallocated,nullifier,_⟩
    exact ⟨token,resolved,hash,debit,others, by simpa [ensureSameU256,check_ok_iff] using unallocated,
      by simpa [ensureDifferentRoot,check_ok_iff] using nullifier⟩
  · rcases branch with ⟨_,_,_,token,resolved,hash,debit,others,unallocated,nullifier,_⟩
    exact ⟨token,resolved,hash,debit,others, by simpa [ensureSameU256,check_ok_iff] using unallocated,
      by simpa [ensureDifferentRoot,check_ok_iff] using nullifier⟩
theorem fund_import_checked_guards {Tree : Type} (e : Environment Tree) (transport : TransportVerifier)
    (w : FundImportWitness) (p : PublicInputs) (accepted : verifyFundImport e transport w = .ok p) :
    verifyBalanceCommon e w.receiverRecord w.prev w.next = .ok () ∧
    w.prev.channelId = w.tx.destinationChannel ∧
    ∃ token, resolveTokenSlot w.prev.balance w.tx.tokenIndex = .ok token ∧
      requireTokenBearingHash e w.tx = .ok () ∧ creditFundAt w.prev w.next token w.amount = .ok () ∧
      ensureFundsUnchangedExcept w.prev w.next token = .ok () ∧
      creditUnallocated w.prev w.next w.amount = .ok () ∧
      forEach (List.range slotCount) (fun index => do
        ensureSlotUnchanged w.prev w.next index; requirePendingUnchanged w.prev w.next index) = .ok () := by
  simp only [verifyFundImport, bind_ok_iff, exists_unit] at accepted
  rcases accepted with ⟨_,common,_,_,destination,_,_,_,_,token,resolved,hash,credit,others,unallocated,rows,_⟩
  exact ⟨common,by simpa [check_ok_iff] using destination,token,resolved,hash,credit,others,unallocated,rows⟩
theorem deposit_checked_guards {Tree : Type} (e : Environment Tree) (w : DepositWitness) (p : PublicInputs)
    (accepted : verifyDeposit e w = .ok p) :
    verifyBalanceCommon e w.record w.prev w.next = .ok () ∧
    ∃ token, resolveTokenSlot w.prev.balance w.tokenIndex = .ok token ∧
      creditFundAt w.prev w.next token w.amount = .ok () ∧
      ensureFundsUnchangedExcept w.prev w.next token = .ok () ∧
      creditUnallocated w.prev w.next w.amount = .ok () ∧
      forEach (List.range slotCount) (fun index => do
        ensureSlotUnchanged w.prev w.next index; requirePendingUnchanged w.prev w.next index) = .ok () := by
  simp only [verifyDeposit, bind_ok_iff, exists_unit] at accepted
  rcases accepted with ⟨_,common,_,_,_,token,resolved,credit,others,unallocated,rows,_⟩
  exact ⟨common,token,resolved,credit,others,unallocated,rows⟩
theorem bundle_checked_guards {Tree : Type} (e : Environment Tree) (regev : RegevVerifier)
    (w : BundleWitness) (p : PublicInputs) (accepted : verifyBundle e regev w = .ok p) :
    verifyBalanceCommon e w.receiverRecord w.prev w.next = .ok () ∧
    w.prev.channelId = w.tx.destinationChannel ∧ w.prev.fund = w.next.fund ∧
    debitUnallocated w.prev w.next w.amount = .ok () ∧ w.prev.nullifierRoot = w.next.nullifierRoot := by
  simp only [verifyBundle, bind_ok_iff, exists_unit] at accepted
  rcases accepted with ⟨_,_,common,_,destination,_,fund,debit,nullifier,_⟩
  exact ⟨common,by simpa [check_ok_iff] using destination,(unchanged_whole_fund _ _).mp fund,
    debit,by simpa [ensureSameRoot,check_ok_iff] using nullifier⟩
theorem refresh_checked_guards {Tree : Type} (e : Environment Tree) (regev : RegevVerifier)
    (w : RefreshWitness) (p : PublicInputs) (accepted : verifyRefresh e regev w = .ok p) :
    verifyBalanceCommon e w.record w.prev w.next = .ok () ∧
    requireSmallBlockUnchanged w.prev w.next = .ok () ∧ requireH2Zero w.next = .ok () ∧
    requireChainUnchanged w.prev w.next = .ok () ∧
    requireAccumulatorUnchanged w.prev.balance.accumulator w.next.balance.accumulator = .ok () ∧
    w.prev.fund = w.next.fund ∧ w.prev.unallocated = w.next.unallocated ∧
    w.prev.nullifierRoot = w.next.nullifierRoot := by
  simp only [verifyRefresh, bind_ok_iff, exists_unit] at accepted
  rcases accepted with ⟨_,_,common,small,_,h2,chain,accumulator,fund,unallocated,nullifier,_⟩
  refine ⟨common,small,h2,chain,accumulator,(unchanged_whole_fund _ _).mp fund,?_,?_⟩
  · simpa [ensureSameU256,check_ok_iff] using unallocated
  · simpa [ensureSameRoot,check_ok_iff] using nullifier
theorem token_register_checked_guards {Tree : Type} (e : Environment Tree) (w : TokenRegisterWitness)
    (p : PublicInputs) (accepted : verifyTokenRegister e w = .ok p) :
    verifyBalanceShared e w.record w.prev w.next = .ok () ∧
    e.tokenRegisterBalance w.prev.balance w.next.balance w.tokenIndex = .ok () ∧
    w.prev.fund = w.next.fund ∧ w.prev.unallocated = w.next.unallocated ∧
    w.prev.nullifierRoot = w.next.nullifierRoot ∧ w.next.smallBlock = w.prev.smallBlock ∧
    ∃ expected, e.tokenRegisterState w.prev w.tokenIndex = .ok expected ∧
      {expected with signatures := w.next.signatures} = w.next := by
  simp only [verifyTokenRegister, bind_ok_iff, exists_unit] at accepted
  rcases accepted with ⟨_,shared,balance,_,_,_,fund,unallocated,nullifier,small,_,expected,built,whole,_⟩
  refine ⟨shared,(map_rejected_ok_iff _ _ _).mp balance,(unchanged_whole_fund _ _).mp fund,
    ?_,?_,?_,expected,(map_rejected_ok_iff _ _ _).mp built,?_⟩
  · simpa [ensureSameU256,check_ok_iff] using unallocated
  · simpa [ensureSameRoot,check_ok_iff] using nullifier
  · simpa [requireSmallBlockUnchanged,check_ok_iff] using small
  · simpa [check_ok_iff] using whole

/-! Forced-empty transport proof bytes. `validateSignedSmallBlock` rejects any non-empty
`transportBytes` (source: `!inter_channel_tx.transport_proof.is_empty()` in
`validate_signed_small_block`, ~line 1983), and send/import then require
`transportBytes == transport.proof` (~740, ~863) before `verify_proof(.., &self.transport_proof, ..)`
(~768, ~901). So on every accepted send/import the transport envelope carries EMPTY proof bytes
and the injected transport verifier is invoked on that empty envelope with the returned public
inputs. This is a source observation made visible, not a vulnerability proof: what the transport
verifier accepts on empty bytes is a property of the injected verifier, outside this model. -/
theorem is_empty_eq_nil {α : Type} (xs : List α) (empty : xs.isEmpty = true) : xs = [] := by
  cases xs with
  | nil => rfl
  | cons x xs => simp at empty
theorem throw_ne_ok {α : Type} (fault : Fault) (value : α) : (throw fault : Result α) ≠ .ok value := by
  intro h; cases h
theorem signed_small_block_transport_empty {Tree : Type} (e : Environment Tree) (record : Record)
    (sourceChannel nonce : Nat) (tx : InterTx)
    (accepted : validateSignedSmallBlock e record sourceChannel nonce tx = .ok ()) :
    tx.transportBytes = [] := by
  simp only [validateSignedSmallBlock, bind_ok_iff, exists_unit] at accepted
  rcases accepted with ⟨_, _, branch⟩
  split at branch
  · simp only [bind_ok_iff, exists_unit, throw_ok_iff_false] at branch
    exact branch.1.elim
  · simp only [bind_ok_iff, exists_unit] at branch
    rcases branch with ⟨_, _, _, _, _, _, _, _, retired, _⟩
    simp only [check_ok_iff, Bool.and_eq_true] at retired
    exact is_empty_eq_nil _ retired.1.1.2
/-- Accepted send: the inter-channel tx transport bytes and the transport envelope's proof bytes
are both `[]`, the envelope has the checked role/backend, and the transport verifier itself was
invoked on that empty envelope with exactly the returned public inputs and answered `.ok ()`. -/
theorem send_transport_bytes_empty {Tree : Type} (e : Environment Tree) (transport : TransportVerifier)
    (regev : RegevVerifier) (w : SendWitness) (p : PublicInputs)
    (accepted : verifySend e transport regev w = .ok p) :
    w.tx.transportBytes = [] ∧ w.transport.proof = [] ∧ w.transport.role = .transport ∧
    w.transport.backend = .plonky2 ∧ transport w.transport p = .ok () := by
  simp only [verifySend, bind_ok_iff, exists_unit] at accepted
  rcases accepted with ⟨_,_,_,_,small,_,_,_,_,_,_,_,_,_,_,_,branch⟩
  have empty := signed_small_block_transport_empty e w.record w.prev.channelId w.prev.closeNonce w.tx small
  split at branch <;> simp only [bind_ok_iff, exists_unit] at branch
  · rcases branch with ⟨_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,bytes,_,_,_,_,_,_,verified,returned⟩
    have same : w.tx.transportBytes = w.transport.proof := by simpa [check_ok_iff] using bytes
    have returnedEq := (pure_ok_iff _ _).mp returned
    subst returnedEq
    obtain ⟨role, backend, called⟩ := (transport_exact_call _ _ _ _ _).mp verified
    exact ⟨empty, same ▸ empty, role, backend, called⟩
  · rcases branch with ⟨_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,bytes,_,_,_,_,_,_,verified,returned⟩
    have same : w.tx.transportBytes = w.transport.proof := by simpa [check_ok_iff] using bytes
    have returnedEq := (pure_ok_iff _ _).mp returned
    subst returnedEq
    obtain ⟨role, backend, called⟩ := (transport_exact_call _ _ _ _ _).mp verified
    exact ⟨empty, same ▸ empty, role, backend, called⟩
/-- Accepted fund import: same forced-empty transport envelope as `send_transport_bytes_empty`. -/
theorem fund_import_transport_bytes_empty {Tree : Type} (e : Environment Tree)
    (transport : TransportVerifier) (w : FundImportWitness) (p : PublicInputs)
    (accepted : verifyFundImport e transport w = .ok p) :
    w.tx.transportBytes = [] ∧ w.transport.proof = [] ∧ w.transport.role = .transport ∧
    w.transport.backend = .plonky2 ∧ transport w.transport p = .ok () := by
  simp only [verifyFundImport, bind_ok_iff, exists_unit] at accepted
  rcases accepted with ⟨_,_,_,small,_,_,_,_,_,_,_,_,_,_,_,_,_,bytes,branch⟩
  have empty := signed_small_block_transport_empty e w.sourceRecord w.tx.sourceChannel
    w.tx.signedBlock.message.closeNonce w.tx small
  have same : w.tx.transportBytes = w.transport.proof := by simpa [check_ok_iff] using bytes
  split at branch
  · simp only [bind_ok_iff, exists_unit, throw_ok_iff_false, false_and, exists_false] at branch
  · simp only [bind_ok_iff, exists_unit] at branch
    rcases branch with ⟨_,_,_,_,_,_,_,_,verified,returned⟩
    have returnedEq := (pure_ok_iff _ _).mp returned
    subst returnedEq
    obtain ⟨role, backend, called⟩ := (transport_exact_call _ _ _ _ _).mp verified
    exact ⟨empty, same ▸ empty, role, backend, called⟩

end Zkp.Implementation.ChannelStateUpdate
