/-
# ChannelSafety.lean — Machine-checked safety proofs for `abstract.md`

This file formalizes the minimal payment-channel specification in
`architecture-audit/abstract.md` and proves its four safety properties
(abstract.md §0 / §4):

  1. authorization        — §4.1  (`authorization`, `atomicity_no_loss_shift`)
  2. no-double-spend      — §4.2  (`exec_conservation`, `no_double_settlement`,
                                    `close_boundary_no_double_spend`)
  3. solvency             — §4.3  (`exec_nonneg`, `channelTx_preserves_validity`,
                                    `interSend_preserves_validity`)
  4. exit safety          — §4.4  (`challenge_latest_wins`, `close_no_overdraw`,
                                    `end_to_end_close_safety`)

The model is *abstract*: cryptographic primitives are replaced by their
*soundness contracts*, stated as explicit hypotheses. The trust base is:

  (A1) SPHINCS+ unforgeability — "member i signed X" is modeled as a
       predicate `signsState i X`; an adversary cannot produce a signature
       a member did not make. (abstract.md §1 `SpxSigWitness`)
  (A2) balanceProof / validityProof ZK soundness — a proof cannot certify a
       balance the channel does not have. Modeled by the solvency
       side-conditions (`hsolv`) on ledger transitions and on `exitBurn`
       (abstract.md §2.1 premise, §3.5.4 step 2).
  (A3) Honest-member discipline — honest members follow §3.1/§3.2.3/§3.4/§3.5.1
       (sign only valid states, one state per version, freeze after
       requestClose). Modeled by `SignsOnlyValid`, `OneStatePerVersion`
       and the `hno_newer` hypothesis of `challenge_latest_wins`.
  (A4) L1 contract correctness — the L1 close contract enforces the checks of
       §3.5.2–§3.5.4 (all-signed, version-monotone replacement, Σ payout ≤ cap).
       Modeled by `L1CloseRule` and the `finalize` fold.

Model abstractions (disclosed limitations — see lean-safety-proof.md for the
full adversarial-review findings):

  (M1) One settlement per L2 block. `no_double_settlement` derives nullifier
       uniqueness from block numbers alone; the real system batches many
       transfers per block (`TxV2Tree`), where intra-block uniqueness comes
       from the `transfer_index`/`from` fields of
       `SettledTransfer::nullifier()`, which are not modeled.
  (M2) The channel-state layer (`BalanceState.provenTotal`) is not linked to
       the ledger (`Ledger.spendable`). The binding "a balanceProof cannot
       certify more than the channel actually holds" enters only at exit
       points, as the `hsolv` side condition of `exitBurn` (A2);
       `close_no_overdraw` therefore *assumes* the L2 burn succeeded rather
       than deriving it.
  (M3) `OneStatePerVersion` is an honest-signer discipline assumed to hold
       across crashes/restores and concurrent same-version proposals; the
       protocol text (§3.1) does not by itself enforce it.
  (M4) The receive side (`flowReceive3`) and the separate on-chain storage of
       `lateBalanceProof` (§3.5.5) are not modeled individually;
       `exec_exit_bound` bounds all exits (close burn + late claims) in
       aggregate instead.

Liveness (timeouts firing, L1 inclusion, message delivery) is OUT of scope;
only safety is proved.

Conventions: amounts (`U256`) are `Int` with explicit `0 ≤ _` invariants (no
wrap-around in the spec model); versions, block numbers and channel ids are
`Nat`. Plain `Int`/`Nat` is used instead of type aliases because the `omega`
decision procedure requires syntactic `Int`/`Nat`.

Checked with: Lean 4.10.0, core library only (no mathlib).
  $ lean ChannelSafety.lean
-/

namespace ChannelSafety

/-! ## §1 Basic types (abstract.md §1–§2) -/

/-- abstract.md §2.1: the three fixed members of a channel (`memberKeys`,
    `[Address; 3]`, fixed at creation, §3.0). -/
inductive Member
  | m0 | m1 | m2
deriving DecidableEq

/-- abstract.md §2.1: `BalanceState { balances, balanceProof, stateVersion }`.
    `bal` is `balances : [U256; 3]`; `provenTotal` is the channel total
    certified by the `balanceProof` public inputs (`BalancePublicInputs`) —
    the proof object itself is abstracted to the value it certifies (trust
    base A2); `version` is `stateVersion`. -/
structure BalanceState where
  bal : Member → Int
  provenTotal : Int
  version : Nat

/-- Total of the three internal balances. -/
def BalanceState.total (s : BalanceState) : Int :=
  s.bal .m0 + s.bal .m1 + s.bal .m2

/-- Single-point additive update of a member-indexed balance map. -/
def updBal (f : Member → Int) (m : Member) (a : Int) : Member → Int :=
  fun j => if j = m then f j + a else f j

theorem updBal_self (f : Member → Int) (m : Member) (a : Int) :
    updBal f m a m = f m + a := by
  simp [updBal]

theorem updBal_other (f : Member → Int) (m : Member) (a : Int)
    (j : Member) (h : j ≠ m) : updBal f m a j = f j := by
  simp [updBal, h]

theorem total_updBal (f : Member → Int) (m : Member) (a : Int) :
    updBal f m a .m0 + updBal f m a .m1 + updBal f m a .m2
      = (f .m0 + f .m1 + f .m2) + a := by
  cases m <;> simp [updBal] <;> omega

/-- abstract.md §3.1 step 1 / §4.3: what honest members check before signing a
    `BalanceState`: every internal balance is non-negative and the internal
    balances are consistent with what the attached `balanceProof` certifies. -/
def ValidBalanceState (s : BalanceState) : Prop :=
  (∀ m : Member, 0 ≤ s.bal m) ∧ s.total = s.provenTotal

/-! ## §2 Signature and honesty model (abstract.md §1, §3.1, §4.1)

`signsState i s` means: member `i` produced a `SpxSigWitness` over
`balanceStateHash = hash(BalanceState)` (abstract.md §3.1 step 3).
By SPHINCS+ unforgeability (A1) and collision resistance of `hash`, the
predicate is the *only* way a signature on `s` can exist. -/

structure SigModel where
  signsState : Member → BalanceState → Prop
  honest : Member → Prop

/-- abstract.md §3.1 out: a `BalanceState` is confirmed iff all three members
    signed its hash (confirmed once all `[SpxSigWitness; 3]` are gathered). -/
def Confirmed (M : SigModel) (s : BalanceState) : Prop :=
  ∀ i : Member, M.signsState i s

/-- Honest-member discipline, part 1 (abstract.md §3.1 steps 1–2): honest
    members verify a candidate state and refuse to sign invalid ones. -/
def SignsOnlyValid (M : SigModel) (Valid : BalanceState → Prop) : Prop :=
  ∀ i s, M.honest i → M.signsState i s → Valid s

/-- Honest-member discipline, part 2 (abstract.md §3.1: each member verifies
    that `stateVersion` is the current one +1): an honest member never signs two *different* states carrying
    the same version. -/
def OneStatePerVersion (M : SigModel) : Prop :=
  ∀ i s s', M.honest i → M.signsState i s → M.signsState i s' →
    s.version = s'.version → s = s'

/-- **Property 1 — authorization (abstract.md §4.1).**
    If at least one member is honest, every confirmed `BalanceState` satisfies
    the validity predicate honest members enforce. An adversary controlling
    the other two members cannot confirm an invalid state, because
    confirmation requires *all three* signatures (§3.1) and the honest
    signature on an invalid state does not exist (A1 + A3). -/
theorem authorization
    (M : SigModel) (Valid : BalanceState → Prop)
    (hdisc : SignsOnlyValid M Valid)
    (i : Member) (hi : M.honest i)
    (s : BalanceState) (hconf : Confirmed M s) :
    Valid s :=
  hdisc i s hi (hconf i)

/-- With one honest member, two confirmed states with the same version are
    equal (used by the challenge game, §3.5.3). -/
theorem confirmed_unique_per_version
    (M : SigModel) (huniq : OneStatePerVersion M)
    (i : Member) (hi : M.honest i)
    (s s' : BalanceState)
    (hs : Confirmed M s) (hs' : Confirmed M s')
    (hv : s.version = s'.version) : s = s' :=
  huniq i s s' hi (hs i) (hs' i) hv

/-! ## §3 Intra-channel transfer (abstract.md §2.2, §3.2) -/

/-- abstract.md §2.2: `ChannelTx { recipient, amount, salt }`. The `salt` is
    irrelevant to the accounting and omitted; `sender` is the signing actor of
    §3.2.1. -/
structure ChannelTx where
  sender : Member
  recipient : Member
  amount : Int

/-- abstract.md §3.2.1 step 1: `balances'[sender] -= amount`,
    `balances'[recipient] += amount`, `balanceProof` unchanged,
    `stateVersion + 1`. -/
def applyChannelTx (s : BalanceState) (t : ChannelTx) : BalanceState where
  bal := updBal (updBal s.bal t.sender (-t.amount)) t.recipient t.amount
  provenTotal := s.provenTotal
  version := s.version + 1

/-- Intra-channel transfers conserve the channel total (no internal mint):
    the state honest co-signers check in §3.2.3 keeps `total = provenTotal`
    with the `balanceProof` unchanged. -/
theorem channelTx_preserves_validity (s : BalanceState) (t : ChannelTx)
    (hvalid : ValidBalanceState s)
    (hpos : 0 ≤ t.amount)
    (hsolv : t.amount ≤ s.bal t.sender) :
    ValidBalanceState (applyChannelTx s t) := by
  obtain ⟨hnn, htot⟩ := hvalid
  constructor
  · intro j
    show 0 ≤ updBal (updBal s.bal t.sender (-t.amount)) t.recipient t.amount j
    by_cases hr : j = t.recipient
    · rw [hr, updBal_self]
      by_cases hrs : t.recipient = t.sender
      · rw [hrs, updBal_self]
        have := hnn t.sender
        omega
      · rw [updBal_other _ _ _ _ hrs]
        have := hnn t.recipient
        omega
    · rw [updBal_other _ _ _ _ hr]
      by_cases hs : j = t.sender
      · rw [hs, updBal_self]
        omega
      · rw [updBal_other _ _ _ _ hs]
        exact hnn j
  · have h1 := total_updBal (updBal s.bal t.sender (-t.amount)) t.recipient t.amount
    have h2 := total_updBal s.bal t.sender (-t.amount)
    have htot' : s.bal .m0 + s.bal .m1 + s.bal .m2 = s.provenTotal := htot
    show updBal (updBal s.bal t.sender (-t.amount)) t.recipient t.amount .m0
       + updBal (updBal s.bal t.sender (-t.amount)) t.recipient t.amount .m1
       + updBal (updBal s.bal t.sender (-t.amount)) t.recipient t.amount .m2
       = s.provenTotal
    omega

/-! ## §4 Inter-channel transfer and signature atomicity (abstract.md §3.4) -/

/-- The sending-channel view of an inter-channel `Transfer` (abstract.md §2.3):
    `amount` leaves the channel, so the new `balanceProof'` certifies
    `provenTotal - amount` (flowSend1 step 8: post-send L2 balance `B - amount`). -/
structure OutgoingTransfer where
  sender : Member
  amount : Int

/-- abstract.md §3.4 flowSend1 steps 5–6: the deducted state `BalanceState'`
    (sender balance -= amount, total proof value -= amount, version + 1). -/
def deduct (s : BalanceState) (t : OutgoingTransfer) : BalanceState where
  bal := updBal s.bal t.sender (-t.amount)
  provenTotal := s.provenTotal - t.amount
  version := s.version + 1

/-- Outgoing deduction keeps the state valid when the sender is solvent —
    exactly the `rangeProof` check of §3.3.1 (balance ≥ transfer amount) — and the
    certified total decreases monotonically (§4.3 monotone update: the sender side decreases).
    This is the completeness counterpart: honest members *can* sign the
    deducted state. -/
theorem interSend_preserves_validity (s : BalanceState) (t : OutgoingTransfer)
    (hvalid : ValidBalanceState s)
    (hpos : 0 ≤ t.amount)
    (hsolv : t.amount ≤ s.bal t.sender) :
    ValidBalanceState (deduct s t)
    ∧ (deduct s t).provenTotal ≤ s.provenTotal := by
  obtain ⟨hnn, htot⟩ := hvalid
  refine ⟨⟨?_, ?_⟩, ?_⟩
  · intro j
    show 0 ≤ updBal s.bal t.sender (-t.amount) j
    by_cases hs : j = t.sender
    · rw [hs, updBal_self]
      omega
    · rw [updBal_other _ _ _ _ hs]
      exact hnn j
  · have h2 := total_updBal s.bal t.sender (-t.amount)
    have htot' : s.bal .m0 + s.bal .m1 + s.bal .m2 = s.provenTotal := htot
    show updBal s.bal t.sender (-t.amount) .m0
       + updBal s.bal t.sender (-t.amount) .m1
       + updBal s.bal t.sender (-t.amount) .m2
       = s.provenTotal - t.amount
    omega
  · show s.provenTotal - t.amount ≤ s.provenTotal
    omega

/-- abstract.md §3.4 invariant (signature atomicity): the signature model extended
    with `tx_tree_root` signatures (`senderRootSig`, §3.3.2). The `atomic`
    field IS the invariant: a member's root signature over a tree containing
    transfer `t` from state `s` is only *valid* together with that member's
    signature on the deducted state `deduct s t` (a signature on only one side is invalid). -/
structure AtomicSigModel extends SigModel where
  signsRoot : Member → OutgoingTransfer → BalanceState → Prop
  atomic : ∀ i t s, signsRoot i t s → signsState i (deduct s t)

/-- abstract.md §3.3.2 / §3.4 flowSend1 step 6: the transfer is authorized
    (a valid `senderRootSig` exists, channel acting as 1 user) iff all three
    members produced the atomic root signature. -/
def TransferAuthorized (M : AtomicSigModel) (t : OutgoingTransfer)
    (s : BalanceState) : Prop :=
  ∀ i : Member, M.signsRoot i t s

/-- **Property 1, atomicity half (abstract.md §3.4 invariant / §4.1).**
    If an inter-channel transfer is authorized, the deducted `BalanceState'`
    is automatically confirmed, so the attack "authorize the send, then
    refuse to sign the internal deduction, shifting the loss to co-members"
    (intra-channel theft) cannot occur.

    NOTE: this theorem *records the consequence of the assumed atomic
    co-signing rule* (the `atomic` field of `AtomicSigModel`); it does not
    derive atomicity from a signature-verification model. Whether the
    implementation really binds the root signature and the deduction
    signature into one indivisible action must be enforced at the
    protocol/circuit level — this file makes the requirement explicit. -/
theorem atomicity_no_loss_shift
    (M : AtomicSigModel) (t : OutgoingTransfer) (s : BalanceState)
    (hauth : TransferAuthorized M t s) :
    Confirmed M.toSigModel (deduct s t) :=
  fun i => M.atomic i t s (hauth i)

/-- In the confirmed deducted state, co-members' balances are untouched —
    the entire deduction is borne by the sender (no loss shifting). -/
theorem atomicity_comember_unaffected
    (s : BalanceState) (t : OutgoingTransfer)
    (j : Member) (hj : j ≠ t.sender) :
    (deduct s t).bal j = s.bal j :=
  updBal_other s.bal t.sender (-t.amount) j hj

/-! ## §5 Base-intmax ledger (abstract.md §2.3, §3.3, §4.2)

The base layer is modeled as a transition system over per-channel *spendable*
balances. One `Apply` step = one posted block containing one settlement
(`produceBlock` / `postBlock` / `generateValidityProof`, §3.3.3–§3.3.5).
The side conditions of each constructor are exactly the checks the validity
circuit enforces (A2):

  * `hsolv`  — solvency: `rangeProof` (§3.3.1) + balanceProof soundness
               (§2.1 premise: an excessive balance cannot be forged);
  * `hfresh` — `ChannelLeaf.prev`: the channel's last-included block number
               must not exceed the current block (§2.3 `PublicState`,
               §3.3.5 step 2). -/

structure Ledger where
  /-- spendable L2 balance per channel id (abstract.md §2.4: spendable supply). -/
  spendable : Nat → Int
  /-- abstract.md §2.3: `ChannelLeaf.prev` — last block that included a tx of
      this channel (inside `account_tree_root`). -/
  lastIncluded : Nat → Nat
  /-- abstract.md §2.3: `PublicState.block_number`. -/
  blockNo : Nat

/-- Single-point additive update of a channel-indexed map. -/
def addAt (f : Nat → Int) (i : Nat) (a : Int) : Nat → Int :=
  fun j => if j = i then f j + a else f j

theorem addAt_self (f : Nat → Int) (i : Nat) (a : Int) :
    addAt f i a i = f i + a := by
  simp [addAt]

theorem addAt_other (f : Nat → Int) (i : Nat) (a : Int)
    (j : Nat) (h : j ≠ i) : addAt f i a j = f j := by
  simp [addAt, h]

/-- Sum of `f` over channel ids `< n`. -/
def sumBelow (f : Nat → Int) : Nat → Int
  | 0 => 0
  | n + 1 => sumBelow f n + f n

theorem sumBelow_congr {f g : Nat → Int} :
    ∀ {n : Nat}, (∀ j, j < n → f j = g j) → sumBelow f n = sumBelow g n
  | 0, _ => rfl
  | n + 1, h => by
    have ih := sumBelow_congr (n := n) fun j hj => h j (Nat.lt_succ_of_lt hj)
    simp [sumBelow, ih, h n (Nat.lt_succ_self n)]

theorem sumBelow_addAt (f : Nat → Int) (i : Nat) (a : Int) :
    ∀ {n : Nat}, i < n → sumBelow (addAt f i a) n = sumBelow f n + a := by
  intro n
  induction n with
  | zero => intro h; exact absurd h (Nat.not_lt_zero i)
  | succ n ih =>
    intro h
    by_cases hi : i = n
    · have hcong : sumBelow (addAt f i a) n = sumBelow f n :=
        sumBelow_congr fun j hj => by
          have hji : j ≠ i := by omega
          simp [addAt, hji]
      have hn : addAt f i a n = f n + a := by
        rw [← hi, addAt_self]
      show sumBelow (addAt f i a) n + addAt f i a n = sumBelow f n + f n + a
      rw [hcong, hn]
      omega
    · have h' : i < n := by omega
      have hn : addAt f i a n = f n := addAt_other f i a n fun hh => hi hh.symm
      show sumBelow (addAt f i a) n + addAt f i a n = sumBelow f n + f n + a
      rw [ih h', hn]
      omega

/-- The three settlement kinds of the base layer (abstract.md §3.3.2b):
    `transfer` requires the channel's atomic authorization (§3.3.2);
    `deposit` (L1-driven mint) and `exitBurn` (`closeBurnTx` §3.5.4 /
    `claimLateTx` §3.5.5 payout) are accepted *without* an L2 signature,
    enforced purely by the validity / withdrawal circuits. -/
inductive Op where
  | transfer (src dst : Nat) (amount : Int)
  | deposit (dst : Nat) (amount : Int)
  | exitBurn (src : Nat) (amount : Int)

def Op.mint : Op → Int
  | .deposit _ a => a
  | _ => 0

def Op.burn : Op → Int
  | .exitBurn _ a => a
  | _ => 0

/-- All channels an op touches lie below `C`. -/
def Op.inRange (C : Nat) : Op → Prop
  | .transfer s d _ => s < C ∧ d < C
  | .deposit d _ => d < C
  | .exitBurn s _ => s < C

/-- One block-settlement step. Side conditions = circuit checks (see header). -/
inductive Apply : Ledger → Op → Ledger → Prop
  | transfer {L : Ledger} {src dst : Nat} {amount : Int}
      (hne : src ≠ dst)
      (hpos : 0 ≤ amount)
      -- §3.3.1 rangeProof + §2.1 balanceProof soundness (A2)
      (hsolv : amount ≤ L.spendable src)
      -- §2.3 / §3.3.5: ChannelLeaf.prev freshness — no replay of an earlier inclusion
      (hfresh : L.lastIncluded src ≤ L.blockNo) :
      Apply L (.transfer src dst amount)
        { spendable := addAt (addAt L.spendable src (-amount)) dst amount
          lastIncluded := fun c => if c = src then L.blockNo + 1 else L.lastIncluded c
          blockNo := L.blockNo + 1 }
  | deposit {L : Ledger} {dst : Nat} {amount : Int}
      (hpos : 0 ≤ amount) :
      Apply L (.deposit dst amount)
        { spendable := addAt L.spendable dst amount
          lastIncluded := L.lastIncluded
          blockNo := L.blockNo + 1 }
  | exitBurn {L : Ledger} {src : Nat} {amount : Int}
      (hpos : 0 ≤ amount)
      -- §3.5.4 step 2: burning `withdrawCap` on L2 requires the funds to
      -- actually exist in the channel (same solvency check as `Transfer`)
      (hsolv : amount ≤ L.spendable src) :
      Apply L (.exitBurn src amount)
        { spendable := addAt L.spendable src (-amount)
          lastIncluded := L.lastIncluded
          blockNo := L.blockNo + 1 }

theorem apply_blockNo {L L' : Ledger} {op : Op} (h : Apply L op L') :
    L'.blockNo = L.blockNo + 1 := by
  cases h <;> rfl

/-- **Property 2, conservation (abstract.md §4.2, single step).**
    A settlement step changes the total spendable supply by exactly
    `mint − burn`: transfers move value, deposits mint it, burns destroy it.
    In particular no transfer can create value (preventing illicit mint). -/
theorem apply_conservation {L L' : Ledger} {op : Op} (h : Apply L op L')
    {C : Nat} (hC : op.inRange C) :
    sumBelow L'.spendable C = sumBelow L.spendable C + op.mint - op.burn := by
  cases h with
  | @transfer src dst amount hne hpos hsolv hfresh =>
    obtain ⟨hs, hd⟩ := hC
    show sumBelow (addAt (addAt L.spendable src (-amount)) dst amount) C
      = sumBelow L.spendable C + Op.mint (.transfer src dst amount)
        - Op.burn (.transfer src dst amount)
    rw [sumBelow_addAt _ _ _ hd, sumBelow_addAt _ _ _ hs]
    simp only [Op.mint, Op.burn]
    omega
  | @deposit dst amount hpos =>
    show sumBelow (addAt L.spendable dst amount) C
      = sumBelow L.spendable C + Op.mint (.deposit dst amount)
        - Op.burn (.deposit dst amount)
    rw [sumBelow_addAt _ _ _ hC]
    simp only [Op.mint, Op.burn]
    omega
  | @exitBurn src amount hpos hsolv =>
    show sumBelow (addAt L.spendable src (-amount)) C
      = sumBelow L.spendable C + Op.mint (.exitBurn src amount)
        - Op.burn (.exitBurn src amount)
    rw [sumBelow_addAt _ _ _ hC]
    simp only [Op.mint, Op.burn]
    omega

/-- Every channel's spendable balance is non-negative. -/
def NonNeg (L : Ledger) : Prop := ∀ c, 0 ≤ L.spendable c

/-- **Property 3, ledger half (abstract.md §4.3, single step).**
    The solvency checks keep every channel's spendable balance non-negative:
    nobody can spend funds they do not have. -/
theorem apply_nonneg {L L' : Ledger} {op : Op} (h : Apply L op L')
    (hL : NonNeg L) : NonNeg L' := by
  cases h with
  | @transfer src dst amount hne hpos hsolv hfresh =>
    intro c
    show 0 ≤ addAt (addAt L.spendable src (-amount)) dst amount c
    have hdst : dst ≠ src := fun hh => hne hh.symm
    by_cases hcd : c = dst
    · rw [hcd, addAt_self, addAt_other _ _ _ _ hdst]
      have := hL dst
      omega
    · rw [addAt_other _ _ _ _ hcd]
      by_cases hcs : c = src
      · rw [hcs, addAt_self]
        omega
      · rw [addAt_other _ _ _ _ hcs]
        exact hL c
  | @deposit dst amount hpos =>
    intro c
    show 0 ≤ addAt L.spendable dst amount c
    by_cases hcd : c = dst
    · rw [hcd, addAt_self]
      have := hL dst
      omega
    · rw [addAt_other _ _ _ _ hcd]
      exact hL c
  | @exitBurn src amount hpos hsolv =>
    intro c
    show 0 ≤ addAt L.spendable src (-amount) c
    by_cases hcs : c = src
    · rw [hcs, addAt_self]
      omega
    · rw [addAt_other _ _ _ _ hcs]
      exact hL c

/-! ### Execution traces and nullifier uniqueness

abstract.md §2.3: `SettledTransfer::nullifier()` hashes (among other fields)
the `block_number` of inclusion. We model a settled op as the pair
`(op, block number at which it settled)`; nullifier uniqueness then reduces
to: *no two settlements in a trace carry the same block number*. -/

inductive Exec : Ledger → List (Op × Nat) → Ledger → Prop
  | nil (L : Ledger) : Exec L [] L
  | cons {L L' L'' : Ledger} {op : Op} {stamp : Nat} {rest : List (Op × Nat)}
      (happ : Apply L op L')
      (hstamp : stamp = L'.blockNo)
      (hrest : Exec L' rest L'') :
      Exec L ((op, stamp) :: rest) L''

theorem exec_stamp_gt {L L'' : Ledger} {sops : List (Op × Nat)}
    (h : Exec L sops L'') : ∀ p ∈ sops, L.blockNo < p.2 := by
  induction h with
  | nil => intro p hp; cases hp
  | @cons L L' _ op stamp rest happ hstamp _ ih =>
    intro p hp
    have hb := apply_blockNo happ
    cases hp with
    | head =>
      show L.blockNo < stamp
      omega
    | tail _ hmem =>
      have := ih p hmem
      omega

/-- **Property 2, replay half (abstract.md §4.2).**
    In any valid execution, at most one settlement carries a given block
    number, so within this model two distinct settlements always have
    distinct nullifiers (`SettledTransfer::nullifier()` binds `block_number`,
    abstract.md §2.3) — the same transfer can never be settled twice
    (no double spend by replay).

    NOTE (M1): this holds because the abstract ledger settles exactly one op
    per block. The real system batches many transfers per block (`TxV2Tree`);
    there, intra-block nullifier uniqueness must come from the
    `transfer_index` / `from` fields, which are outside this model.

    NOTE (F-WD-2, 2026-07-04): the real system re-keyed the nullifier preimage
    from `block_number` to the sender tx `nonce`, making double-settle
    prevention SETTLEMENT-INDEPENDENT — two settlements of the same deduction
    now produce the IDENTICAL nullifier (caught by the on-chain used-set),
    rather than distinct per-block nullifiers. So the real property no longer
    relies on the unrealistic "at most one settlement per block" assumption
    that M1 flagged; this model's block-number argument is now strictly weaker
    than the deployed scheme. -/
theorem no_double_settlement {L L'' : Ledger} {sops : List (Op × Nat)}
    (h : Exec L sops L'') :
    ∀ p ∈ sops, ∀ q ∈ sops, p.2 = q.2 → p = q := by
  induction h with
  | nil => intro p hp; cases hp
  | @cons _ L' L'' op stamp rest _ hstamp hrest ih =>
    intro p hp q hq heq
    cases hp with
    | head =>
      cases hq with
      | head => rfl
      | tail _ hq' =>
        have hgt := exec_stamp_gt hrest q hq'
        have heq' : stamp = q.2 := heq
        exact absurd heq' (by omega)
    | tail _ hp' =>
      cases hq with
      | head =>
        have hgt := exec_stamp_gt hrest p hp'
        have heq' : p.2 = stamp := heq
        exact absurd heq' (by omega)
      | tail _ hq' => exact ih p hp' q hq' heq

def mintSum : List (Op × Nat) → Int
  | [] => 0
  | p :: rest => p.1.mint + mintSum rest

def burnSum : List (Op × Nat) → Int
  | [] => 0
  | p :: rest => p.1.burn + burnSum rest

/-- **Property 2, conservation over a whole trace (abstract.md §4.2).**
    Across any execution, the spendable supply changes by exactly
    `Σ deposits − Σ burns`. No sequence of transfers — adversarial or not —
    can mint value out of thin air. -/
theorem exec_conservation {L L'' : Ledger} {sops : List (Op × Nat)} {C : Nat}
    (h : Exec L sops L'') :
    (∀ p ∈ sops, Op.inRange C p.1) →
    sumBelow L''.spendable C
      = sumBelow L.spendable C + mintSum sops - burnSum sops := by
  induction h with
  | nil =>
    intro _
    simp only [mintSum, burnSum]
    omega
  | cons happ _ _ ih =>
    intro hC
    have h1 := apply_conservation happ (hC _ (List.mem_cons_self _ _))
    have h2 := ih fun p hp => hC p (List.mem_cons_of_mem _ hp)
    simp only [mintSum, burnSum]
    omega

/-- Non-negativity is an invariant of whole executions (Property 3). -/
theorem exec_nonneg {L L'' : Ledger} {sops : List (Op × Nat)}
    (h : Exec L sops L'') (hL : NonNeg L) : NonNeg L'' := by
  induction h with
  | nil => exact hL
  | cons happ _ _ ih => exact ih (apply_nonneg happ hL)

theorem sumBelow_nonneg {f : Nat → Int} (hf : ∀ c, 0 ≤ f c) :
    ∀ n, 0 ≤ sumBelow f n
  | 0 => Int.le_refl 0
  | n + 1 => by
    have h1 := sumBelow_nonneg hf n
    have h2 := hf n
    show 0 ≤ sumBelow f n + f n
    omega

/-- **Properties 2 + 4 — aggregate exit solvency (audit C1 / §3.5.4–§3.5.5
    combined).** Across any execution — including a close burn followed by any
    number of late-claim burns (M4) — the total value burned, which by the cap
    rule (`close_no_overdraw`) upper-bounds everything that can ever be paid
    out on L1, never exceeds the initial supply plus all genuine deposits.
    In particular a late claim cannot be backed by the same funds that already
    backed the close payout: every L1 exit consumes distinct L2 supply. -/
theorem exec_exit_bound {L L'' : Ledger} {sops : List (Op × Nat)} {C : Nat}
    (h : Exec L sops L'') (hL : NonNeg L)
    (hC : ∀ p ∈ sops, Op.inRange C p.1) :
    burnSum sops ≤ sumBelow L.spendable C + mintSum sops := by
  have hcons := exec_conservation h hC
  have hfin := sumBelow_nonneg (exec_nonneg h hL) C
  omega

/-! ## §6 Close game: withdrawCap and the close boundary (abstract.md §2.4, §3.5.4) -/

/-- The L1 side of `closeAndWithdraw` (abstract.md §3.5.4).
    `claims` is `finalBalanceState.balances` — possibly adversarial;
    `cap` is `withdrawCap = closeBurnTx.amount` = the channel total certified
    by `finalBalanceProof` (§2.4); `paid` is what L1 actually pays out. -/
structure CloseGame where
  channel : Nat
  cap : Int
  claims : Member → Int
  paid : Member → Int

def CloseGame.totalPaid (g : CloseGame) : Int :=
  g.paid .m0 + g.paid .m1 + g.paid .m2

/-- abstract.md §3.5.4 steps 3–4 — the checks the L1 contract enforces (A4):
    payouts are non-negative, follow the final state's claims, and never
    exceed `withdrawCap` in total. -/
structure L1CloseRule (g : CloseGame) : Prop where
  paid_nonneg : ∀ m, 0 ≤ g.paid m
  paid_le_claim : ∀ m, g.paid m ≤ g.claims m
  total_capped : g.totalPaid ≤ g.cap

/-- **Property 4 / audit C2, C5 (abstract.md §4.2 withdrawal cap).**
    *Given that the L2 burn of `withdrawCap` succeeded* (§3.5.4 step 2 —
    this is where balanceProof soundness A2 enters, as the `hsolv` side
    condition of `exitBurn`; see M2), the total L1 payout is bounded by the
    channel's *actual* spendable L2 balance at burn time:
    `Σ paid ≤ withdrawCap ≤ spendable`. Whatever an inflated or stale
    `finalBalanceState.balances` claims, it cannot extract more than the
    channel really holds. -/
theorem close_no_overdraw {L L' : Ledger} (g : CloseGame)
    (hburn : Apply L (.exitBurn g.channel g.cap) L')
    (hrule : L1CloseRule g) :
    g.totalPaid ≤ L.spendable g.channel := by
  cases hburn with
  | exitBurn hpos hsolv =>
    have := hrule.total_capped
    omega

/-- **Property 2 / audit C1 — close-boundary double spend (abstract.md §4.2
    close burn tx).** After `closeAndWithdraw`, the value paid out on L1 plus
    the value still spendable on L2 does not exceed the value the channel had
    before the close: the L1 withdrawal is fully backed by the L2 burn, so the
    "withdraw on L1 *and* keep spending on L2" attack is impossible. -/
theorem close_boundary_no_double_spend {L L' : Ledger} (g : CloseGame)
    (hburn : Apply L (.exitBurn g.channel g.cap) L')
    (hrule : L1CloseRule g) :
    L'.spendable g.channel + g.totalPaid ≤ L.spendable g.channel := by
  cases hburn with
  | exitBurn hpos hsolv =>
    have h1 := hrule.total_capped
    show addAt L.spendable g.channel (-g.cap) g.channel + g.totalPaid
      ≤ L.spendable g.channel
    rw [addAt_self]
    omega

/-! ## §7 Challenge game (abstract.md §3.5.2–§3.5.3, §4.4) -/

/-- abstract.md §3.5.3 step 3: keep the submission with the higher
    `stateVersion`. -/
def better (a b : BalanceState) : BalanceState :=
  if a.version < b.version then b else a

theorem better_eq (a b : BalanceState) : better a b = a ∨ better a b = b := by
  unfold better
  by_cases h : a.version < b.version <;> simp [h]

theorem version_le_better_left (a b : BalanceState) :
    a.version ≤ (better a b).version := by
  unfold better
  by_cases h : a.version < b.version <;> simp [h] <;> omega

theorem version_le_better_right (a b : BalanceState) :
    b.version ≤ (better a b).version := by
  unfold better
  by_cases h : a.version < b.version <;> simp [h] <;> omega

/-- The state the challenge period converges to: the `startProcess` submission
    (`init`, §3.5.2) refined by every `challenge` submission (§3.5.3). -/
def finalize (init : BalanceState) (subs : List BalanceState) : BalanceState :=
  subs.foldl better init

theorem finalize_mem :
    ∀ (subs : List BalanceState) (init : BalanceState),
      finalize init subs = init ∨ finalize init subs ∈ subs
  | [], _ => Or.inl rfl
  | s :: rest, init => by
    have h := finalize_mem rest (better init s)
    cases h with
    | inl h =>
      cases better_eq init s with
      | inl hb => exact Or.inl (h.trans hb)
      | inr hb =>
        refine Or.inr ?_
        have hfin : finalize init (s :: rest) = s := h.trans hb
        rw [hfin]
        exact List.mem_cons_self _ _
    | inr h => exact Or.inr (List.mem_cons_of_mem _ h)

theorem finalize_version_ge_init :
    ∀ (subs : List BalanceState) (init : BalanceState),
      init.version ≤ (finalize init subs).version
  | [], _ => Nat.le_refl _
  | s :: rest, init =>
    Nat.le_trans (version_le_better_left init s)
      (finalize_version_ge_init rest (better init s))

theorem finalize_version_ge :
    ∀ (subs : List BalanceState) (init : BalanceState),
      ∀ s ∈ subs, s.version ≤ (finalize init subs).version
  | [], _, _, hs => by cases hs
  | t :: rest, init, s, hs => by
    cases hs with
    | head =>
      exact Nat.le_trans (version_le_better_right init t)
        (finalize_version_ge_init rest (better init t))
    | tail _ h => exact finalize_version_ge rest (better init t) s h

/-- **Property 4 — stale close prevention (abstract.md §3.5.3, §4.4).**
    Suppose one member is honest, L1 verified the all-member signatures on
    `init` and on every challenge submission (§3.5.2 step 2 / §3.5.3 step 2),
    the honest member submitted the latest confirmed state, and — by the
    signing freeze after `requestClose` (§3.5.1) plus honest discipline (A3) —
    no confirmed state newer than it exists. Then the challenge game settles
    on exactly that latest state: closing with a stale (or fabricated)
    `BalanceState` is impossible.

    NOTE: `hconf_subs` models the L1 contract's all-signed check (§3.5.2
    step 2 / §3.5.3 step 2, A4) as a pre-filter on the submission list, and
    `hsubmitted` — the honest member's submission actually being included
    within the challenge period — is a *liveness* precondition outside the
    proved scope (no-L1-censorship assumption). -/
theorem challenge_latest_wins
    (M : SigModel) (i : Member) (hi : M.honest i)
    (huniq : OneStatePerVersion M)
    (init latest : BalanceState) (subs : List BalanceState)
    (hsubmitted : latest ∈ subs)
    (hconf_init : Confirmed M init)
    (hconf_subs : ∀ s ∈ subs, Confirmed M s)
    (hno_newer : ∀ s, Confirmed M s → s.version ≤ latest.version) :
    finalize init subs = latest := by
  have hconf_fin : Confirmed M (finalize init subs) := by
    cases finalize_mem subs init with
    | inl h => rw [h]; exact hconf_init
    | inr h => exact hconf_subs _ h
  have h1 : latest.version ≤ (finalize init subs).version :=
    finalize_version_ge subs init latest hsubmitted
  have h2 : (finalize init subs).version ≤ latest.version :=
    hno_newer _ hconf_fin
  exact confirmed_unique_per_version M huniq i hi _ _ hconf_fin
    (hconf_subs latest hsubmitted) (Nat.le_antisymm h2 h1)

/-! ## §8 End-to-end close safety -/

/-- **Composition of Properties 1–4 at the close boundary.**
    Assume: one honest member (A1, A3), the final state is all-signed, the L2
    burn of `withdrawCap` succeeded (§3.5.4 step 2, A2), and L1 enforces the
    close rule (A4). Then, no matter what the other two members and the BP do:

    1. each member is paid at most their share in the all-signed final state;
    2. the total payout never exceeds the channel's real L2 funds at close;
    3. the final state itself is valid (non-negative balances consistent with
       the certified total);
    4. the cap equals the agreed total exactly, so it is not only safe but
       also sufficient to pay every member their full agreed share. -/
theorem end_to_end_close_safety
    (M : SigModel) (hdisc : SignsOnlyValid M ValidBalanceState)
    (i : Member) (hi : M.honest i)
    (final : BalanceState) (hconf : Confirmed M final)
    (g : CloseGame)
    (hcap : g.cap = final.provenTotal)
    (hclaims : g.claims = final.bal)
    (hrule : L1CloseRule g)
    {L L' : Ledger} (hburn : Apply L (.exitBurn g.channel g.cap) L') :
    (∀ m, g.paid m ≤ final.bal m)
    ∧ g.totalPaid ≤ L.spendable g.channel
    ∧ ValidBalanceState final
    ∧ final.total = g.cap := by
  have hvalid : ValidBalanceState final :=
    authorization M ValidBalanceState hdisc i hi final hconf
  refine ⟨fun m => ?_, close_no_overdraw g hburn hrule, hvalid,
    hvalid.2.trans hcap.symm⟩
  have h := hrule.paid_le_claim m
  rw [hclaims] at h
  exact h

/-! ## §9 Sanity: the assumptions are satisfiable (non-vacuity)

If the hypotheses of the theorems above were contradictory, every theorem
would hold vacuously. The instances below exhibit models satisfying them. -/

section Sanity

/-- A signature model in which every member is honest and signs exactly the
    valid states — `SignsOnlyValid` is satisfiable. -/
def allHonestModel : SigModel where
  signsState := fun _ s => ValidBalanceState s
  honest := fun _ => True

theorem allHonestModel_discipline :
    SignsOnlyValid allHonestModel ValidBalanceState :=
  fun _ _ _ h => h

/-- Non-vacuity in the *adversarial* configuration the theorems target:
    exactly one honest member (`m0`) among two members who sign anything.
    The discipline hypothesis of `authorization` is satisfiable here too. -/
def oneHonestModel : SigModel where
  signsState := fun i s => i = .m0 → ValidBalanceState s
  honest := fun i => i = .m0

theorem oneHonestModel_discipline :
    SignsOnlyValid oneHonestModel ValidBalanceState :=
  fun _ _ hi hsig => hsig hi

/-- The adversarial members really are unconstrained: `m1` signs *every*
    state, including invalid ones, without breaking the honest discipline. -/
theorem oneHonestModel_adversary_unconstrained (s : BalanceState) :
    oneHonestModel.signsState .m1 s :=
  fun h => Member.noConfusion h

/-- A valid, confirmable balance state exists. -/
def sampleState : BalanceState where
  bal := fun _ => 10
  provenTotal := 30
  version := 0

theorem sampleState_valid : ValidBalanceState sampleState :=
  ⟨fun _ => by show (0 : Int) ≤ 10; omega,
   by show (10 : Int) + 10 + 10 = 30; omega⟩

theorem sampleState_confirmed : Confirmed allHonestModel sampleState :=
  fun _ => sampleState_valid

/-- The ledger transition hypotheses are satisfiable: an empty ledger accepts
    a deposit, and the resulting ledger accepts a transfer of part of it. -/
def emptyLedger : Ledger where
  spendable := fun _ => 0
  lastIncluded := fun _ => 0
  blockNo := 0

theorem deposit_possible :
    ∃ L', Apply emptyLedger (.deposit 0 5) L' :=
  ⟨_, .deposit (by omega)⟩

theorem transfer_possible :
    ∃ L₁ L₂, Apply emptyLedger (.deposit 0 5) L₁
      ∧ Apply L₁ (.transfer 0 1 3) L₂ := by
  refine ⟨_, _, .deposit (by omega), .transfer (by omega) (by omega) ?_ ?_⟩
  · show (3 : Int) ≤ 0 + 5
    omega
  · show (0 : Nat) ≤ 0 + 1
    omega

end Sanity

end ChannelSafety
