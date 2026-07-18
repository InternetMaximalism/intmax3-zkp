/-
# ChannelSafety21.lean — Machine-checked safety proofs for `abstract2-1.md`

Formalizes the small-block + cross-channel bulk revision of abstract2.md
(`architecture-audit/abstract2-1.md`), importing
`ChannelSafety2.lean` for the Lattice v2 core.

Model notes (abstract2-1):
  M1' — one sending channel inter-channel settlement = one small block =
        one ledger step; other channels' SubBlocks are separate steps.
  M6' — bulk `TransferAuthorized21` binds state to per-channel `tx_root`;
        entry↔ledger amount correspondence remains `hcircuit` (A2).
  M8  — partial receive: each destination verifies its legs via commitment
        injectivity (`bulk_interChannel_conservation_bound`).

Trust base: A1–A6 inherited from ChannelSafety2 (lean-safety-proof21.md).

Checked with: Lean 4.10.0, core only. Three-step build:
  $ lean ChannelSafety.lean -o ChannelSafety.olean
  $ LEAN_PATH=$PWD lean ChannelSafety2.lean -o ChannelSafety2.olean
  $ LEAN_PATH=$PWD lean ChannelSafety21.lean
-/

import ChannelSafety2

namespace ChannelSafety21

open ChannelSafety
open ChannelSafety2

/-! ## §1 Encrypted balance state with settled chain -/

structure EncBalanceState21 where
  encBal : Member → Ct
  provenTotal : Int
  version : Nat
  settledChain : Nat

def EncBalanceState21.bal (s : EncBalanceState21) (m : Member) : Int :=
  (s.encBal m).pt

def EncBalanceState21.total (s : EncBalanceState21) : Int :=
  s.bal .m0 + s.bal .m1 + s.bal .m2

def EncBalanceState21.toV2 (s : EncBalanceState21) : EncBalanceState :=
  { encBal := s.encBal, provenTotal := s.provenTotal, version := s.version }

def ValidEncState21 (s : EncBalanceState21) : Prop :=
  ValidEncState s.toV2

/-! ## §2 Bulk inter-channel update -/

structure TransferEntry where
  dest : Nat
  recipient : Member
  amount : Int
  recipientDelta : Ct

structure BulkChannelUpdate where
  totalAmount : Int
  senderDelta : Ct
  entries : List TransferEntry

def entryAmountSum : List TransferEntry → Int
  | [] => 0
  | e :: rest => e.amount + entryAmountSum rest

def entriesForDest (dest : Nat) (entries : List TransferEntry) : List TransferEntry :=
  entries.filter (fun e => decide (e.dest = dest))

def destAmountSum (dest : Nat) (entries : List TransferEntry) : Int :=
  entryAmountSum (entriesForDest dest entries)

def BulkUpdateProven (u : BulkChannelUpdate) (s : EncBalanceState21)
    (sender : Member) : Prop :=
  u.totalAmount = entryAmountSum u.entries
  ∧ 0 ≤ u.totalAmount
  ∧ u.senderDelta.pt = -u.totalAmount
  ∧ (∀ e ∈ u.entries, 0 ≤ e.amount ∧ e.recipientDelta.pt = e.amount)
  ∧ u.totalAmount ≤ s.bal sender

def RecipientEntryVerified (e : TransferEntry) : Prop :=
  0 ≤ e.amount ∧ e.recipientDelta.pt = e.amount

def RecipientBulkVerified (dest : Nat) (u : BulkChannelUpdate) : Prop :=
  ∀ e ∈ entriesForDest dest u.entries, RecipientEntryVerified e

def applyBulkSend (s : EncBalanceState21) (sender : Member)
    (u : BulkChannelUpdate) : EncBalanceState21 where
  encBal := updCt s.encBal sender u.senderDelta
  provenTotal := s.provenTotal - u.totalAmount
  version := s.version + 1
  settledChain := s.settledChain

/-- Credit one leg without bumping `version` (bulk receive folds these). -/
def applyEntryCredit (st : EncBalanceState21) (e : TransferEntry) :
    EncBalanceState21 where
  encBal := updCt st.encBal e.recipient e.recipientDelta
  provenTotal := st.provenTotal + e.amount
  version := st.version
  settledChain := st.settledChain

def applyBulkReceive (r : EncBalanceState21) (dest : Nat)
    (u : BulkChannelUpdate) : EncBalanceState21 :=
  let credited := (entriesForDest dest u.entries).foldl applyEntryCredit r
  { credited with version := r.version + 1 }

theorem applyBulkSend_total (s : EncBalanceState21) (sender : Member)
    (u : BulkChannelUpdate) :
    (applyBulkSend s sender u).total = s.total + u.senderDelta.pt :=
  updCt_total s.encBal sender u.senderDelta

theorem applyEntryCredit_total (st : EncBalanceState21) (e : TransferEntry)
    (hrd : e.recipientDelta.pt = e.amount) :
    (applyEntryCredit st e).total = st.total + e.amount := by
  have h1 := updCt_total st.encBal e.recipient e.recipientDelta
  simp [applyEntryCredit, EncBalanceState21.total, EncBalanceState21.bal, hrd]
  omega

theorem entryAmountSum_cons (e : TransferEntry) (rest : List TransferEntry) :
    entryAmountSum (e :: rest) = e.amount + entryAmountSum rest := rfl

theorem foldlEntryCredit_provenTotal (init : EncBalanceState21)
    (es : List TransferEntry) :
    (es.foldl applyEntryCredit init).provenTotal
      = init.provenTotal + entryAmountSum es := by
  induction es generalizing init with
  | nil => simp [entryAmountSum]
  | cons e rest ih =>
    simp only [List.foldl, entryAmountSum]
    change (List.foldl applyEntryCredit (applyEntryCredit init e) rest).provenTotal
        = init.provenTotal + (e.amount + entryAmountSum rest)
    rw [ih (applyEntryCredit init e)]
    simp [applyEntryCredit]
    omega

theorem foldlEntryCredit_total (init : EncBalanceState21) (es : List TransferEntry)
    (hent : ∀ e ∈ es, e.recipientDelta.pt = e.amount) :
    (es.foldl applyEntryCredit init).total
      = init.total + entryAmountSum es := by
  induction es generalizing init with
  | nil => simp [entryAmountSum]
  | cons e rest ih =>
    have he := hent e (List.mem_cons_self _ _)
    simp only [List.foldl, entryAmountSum]
    change (List.foldl applyEntryCredit (applyEntryCredit init e) rest).total
        = init.total + (e.amount + entryAmountSum rest)
    rw [ih (applyEntryCredit init e) (fun e' hmem => hent e' (List.mem_cons_of_mem _ hmem)),
        applyEntryCredit_total init e he]
    omega

theorem applyBulkReceive_provenTotal (r : EncBalanceState21) (dest : Nat)
    (u : BulkChannelUpdate) :
    (applyBulkReceive r dest u).provenTotal
      = r.provenTotal + destAmountSum dest u.entries := by
  unfold applyBulkReceive destAmountSum
  exact foldlEntryCredit_provenTotal r (entriesForDest dest u.entries)

theorem applyBulkReceive_total (r : EncBalanceState21) (dest : Nat)
    (u : BulkChannelUpdate)
    (hent : ∀ e ∈ entriesForDest dest u.entries, e.recipientDelta.pt = e.amount) :
    (applyBulkReceive r dest u).total
      = r.total + destAmountSum dest u.entries := by
  unfold applyBulkReceive destAmountSum
  simpa using
    foldlEntryCredit_total r (entriesForDest dest u.entries)
      (fun e hmem => hent e hmem)

/-! ## §3 Bulk solvency -/

theorem bulk_send_preserves_validity (s : EncBalanceState21) (sender : Member)
    (u : BulkChannelUpdate)
    (hvalid : ValidEncState21 s) (hu : BulkUpdateProven u s sender) :
    ValidEncState21 (applyBulkSend s sender u)
    ∧ (applyBulkSend s sender u).provenTotal ≤ s.provenTotal := by
  obtain ⟨hnn, htot⟩ := hvalid
  obtain ⟨_, _, hsd, _, hsolv⟩ := hu
  have hsolv' : u.totalAmount ≤ (s.encBal sender).pt := hsolv
  refine ⟨⟨?_, ?_⟩, ?_⟩
  · intro j
    show 0 ≤ (updCt s.encBal sender u.senderDelta j).pt
    have hnj : 0 ≤ (s.encBal j).pt := hnn j
    by_cases hj : j = sender
    · simp [updCt, hj]; omega
    · simp [updCt, hj]; exact hnj
  · dsimp [ValidEncState, applyBulkSend, EncBalanceState21.toV2]
    have h1 := updCt_total s.encBal sender u.senderDelta
    have htot' : (s.encBal .m0).pt + (s.encBal .m1).pt + (s.encBal .m2).pt
               = s.provenTotal := htot
    simp only [EncBalanceState.total, EncBalanceState.bal, EncBalanceState21.bal]
    omega
  · dsimp [applyBulkSend]; omega

theorem applyEntryCredit_preserves (st : EncBalanceState21) (e : TransferEntry)
    (hst : ValidEncState21 st) (he : RecipientEntryVerified e) :
    ValidEncState21 (applyEntryCredit st e) := by
  obtain ⟨hnn, htot⟩ := hst
  obtain ⟨_hpos, hrd⟩ := he
  constructor
  · intro j
    show 0 ≤ (updCt st.encBal e.recipient e.recipientDelta j).pt
    have hnj : 0 ≤ (st.encBal j).pt := hnn j
    have hnr : 0 ≤ (st.encBal e.recipient).pt := hnn e.recipient
    by_cases hj : j = e.recipient
    · simp [updCt, hj]; omega
    · simp [updCt, hj]; exact hnj
  · dsimp [ValidEncState, applyEntryCredit, EncBalanceState21.toV2]
    have h1 := updCt_total st.encBal e.recipient e.recipientDelta
    have htot' : (st.encBal .m0).pt + (st.encBal .m1).pt + (st.encBal .m2).pt
               = st.provenTotal := htot
    simp only [EncBalanceState.total, EncBalanceState.bal, EncBalanceState21.bal, hrd]
    omega

theorem foldlEntryCredit_preserves (init : EncBalanceState21) (es : List TransferEntry)
    (hinit : ValidEncState21 init)
    (hent : ∀ e ∈ es, RecipientEntryVerified e) :
    ValidEncState21 (es.foldl applyEntryCredit init) := by
  induction es generalizing init with
  | nil => simpa using hinit
  | cons e rest ih =>
    have he := hent e (List.mem_cons_self _ _)
    have hent' := fun e' hmem => hent e' (List.mem_cons_of_mem _ hmem)
    exact ih (applyEntryCredit init e) (applyEntryCredit_preserves init e hinit he) hent'

theorem bulk_receive_preserves_validity (r : EncBalanceState21) (dest : Nat)
    (u : BulkChannelUpdate)
    (hvalid : ValidEncState21 r) (hdest : RecipientBulkVerified dest u) :
    ValidEncState21 (applyBulkReceive r dest u)
    ∧ (applyBulkReceive r dest u).provenTotal
        = r.provenTotal + destAmountSum dest u.entries := by
  have hent : ∀ e ∈ entriesForDest dest u.entries, RecipientEntryVerified e :=
    hdest
  refine ⟨?_, applyBulkReceive_provenTotal r dest u⟩
  unfold applyBulkReceive
  simpa using
    foldlEntryCredit_preserves r (entriesForDest dest u.entries) hvalid hent

/-! ## §4 Cross-channel conservation -/

theorem entriesForDest_eq_of_forall (dest : Nat) (entries : List TransferEntry)
    (h : ∀ e ∈ entries, e.dest = dest) :
    entriesForDest dest entries = entries := by
  unfold entriesForDest
  induction entries with
  | nil => rfl
  | cons e rest ih =>
    have he : decide (e.dest = dest) = true := by
      rw [decide_eq_true_iff]; exact h e (List.mem_cons_self _ _)
    have ihr := ih fun e' hmem => h e' (List.mem_cons_of_mem _ hmem)
    simp [List.filter, he, ihr]

theorem bulk_interChannel_conservation_dest
    (s r : EncBalanceState21) (sender : Member) (dest : Nat)
    (u : BulkChannelUpdate)
    (honly : ∀ e ∈ u.entries, e.dest = dest)
    (hu : BulkUpdateProven u s sender) :
    (applyBulkSend s sender u).total + (applyBulkReceive r dest u).total
      = s.total + r.total := by
  have h1 := applyBulkSend_total s sender u
  obtain ⟨htotEq, _, _hsd, hentAll, _⟩ := hu
  have hfilter := entriesForDest_eq_of_forall dest u.entries honly
  have hrd : ∀ e ∈ entriesForDest dest u.entries, e.recipientDelta.pt = e.amount :=
    fun e hmem => (hentAll e (by rw [hfilter] at hmem; exact hmem)).2
  have h2 := applyBulkReceive_total r dest u hrd
  have hsum : destAmountSum dest u.entries = u.totalAmount := by
    unfold destAmountSum; rw [hfilter, htotEq]
  omega

theorem bulk_interChannel_conservation_bound
    (commit : BulkChannelUpdate → Nat)
    (hinj : ∀ u u', commit u = commit u' → u = u')
    (us ur : BulkChannelUpdate) (hsame : commit us = commit ur)
    (s r : EncBalanceState21) (sender : Member) (dest : Nat)
    (honly : ∀ e ∈ us.entries, e.dest = dest)
    (hu : BulkUpdateProven us s sender) :
    (applyBulkSend s sender us).total + (applyBulkReceive r dest ur).total
      = s.total + r.total := by
  obtain rfl := hinj us ur hsame
  exact bulk_interChannel_conservation_dest s r sender dest us honly hu

/-! ## §5 Small-block authorization -/

def TransferAuthorized21 (M : SigModel2) (s' : EncBalanceState) (root : Nat) : Prop :=
  TransferAuthorized2 M s' root

theorem authorized_bulk_send_state_valid
    (M : SigModel2) (hdisc : SignsOnlyValid2 M ValidEncState)
    (i : Member) (hi : M.honest i)
    (s' : EncBalanceState21) (root : Nat)
    (hauth : TransferAuthorized21 M s'.toV2 root) :
    ValidEncState21 s' :=
  hdisc i s'.toV2 (.txRoot root) hi (hauth i)

/-! ## §6 settledTxChain step -/

def applyBulkSendChain (s : EncBalanceState21) (sender : Member)
    (u : BulkChannelUpdate) (commit : BulkChannelUpdate → Nat)
    (hash2 : Nat → Nat → Nat) : EncBalanceState21 :=
  let s' := applyBulkSend s sender u
  { s' with settledChain := hash2 s.settledChain (commit u) }

theorem bulk_send_chain_step
    (hash2 : Nat → Nat → Nat) (s : EncBalanceState21) (sender : Member)
    (u : BulkChannelUpdate) (commit : BulkChannelUpdate → Nat) :
    (applyBulkSendChain s sender u commit hash2).settledChain
      = hash2 s.settledChain (commit u) := rfl

/-! ## §7 Close safety via v2 projection -/

theorem end_to_end_close_safety21
    (M : SigModel2) (hdisc : SignsOnlyValid2 M ValidEncState)
    (i : Member) (hi : M.honest i)
    (final : EncBalanceState21) (hconf : ConfirmedAny M final.toV2)
    (g : CloseGame)
    (hcap : g.cap = final.provenTotal)
    (hclaims : g.claims = final.bal)
    (hrule : L1CloseRule g)
    {L L' : Ledger} (hburn : Apply L (.exitBurn g.channel g.cap) L') :
    (∀ m, g.paid m ≤ final.bal m)
    ∧ g.totalPaid ≤ L.spendable g.channel
    ∧ ValidEncState21 final
    ∧ final.total = g.cap :=
  end_to_end_close_safety2 M hdisc i hi final.toV2 hconf g hcap hclaims hrule hburn

/-! ## §7a L1 deposit import (mid-channel top-up, abstract2-1 §3.3.2c) -/

/-- L1 deposit import credits a single recipient with a non-negative amount and
    increases `provenTotal` by the same. Mirrors `applyEntryCredit` but is a
    standalone state transition (not folded inside a bulk receive). -/
def applyL1DepositImport (s : EncBalanceState21) (recipient : Member)
    (amount : Int) (recipientDelta : Ct) : EncBalanceState21 where
  encBal := updCt s.encBal recipient recipientDelta
  provenTotal := s.provenTotal + amount
  version := s.version + 1
  settledChain := s.settledChain

/-- The deposit amount is non-negative and the ciphertext encrypts exactly that amount. -/
def L1DepositImportVerified (amount : Int) (recipientDelta : Ct) : Prop :=
  0 ≤ amount ∧ recipientDelta.pt = amount

theorem applyL1DepositImport_total (s : EncBalanceState21) (recipient : Member)
    (amount : Int) (recipientDelta : Ct) :
    (applyL1DepositImport s recipient amount recipientDelta).total
      = s.total + recipientDelta.pt :=
  updCt_total s.encBal recipient recipientDelta

theorem l1_deposit_preserves_validity
    (s : EncBalanceState21) (hvalid : ValidEncState21 s)
    (recipient : Member) (amount : Int) (recipientDelta : Ct)
    (hdeposit : L1DepositImportVerified amount recipientDelta) :
    ValidEncState21 (applyL1DepositImport s recipient amount recipientDelta)
    ∧ (applyL1DepositImport s recipient amount recipientDelta).provenTotal
        = s.provenTotal + amount
    ∧ (applyL1DepositImport s recipient amount recipientDelta).total
        = s.total + amount := by
  obtain ⟨hnn, htot⟩ := hvalid
  obtain ⟨hamtnn, hrd⟩ := hdeposit
  refine ⟨⟨?_, ?_⟩, ?_, ?_⟩
  · -- All balances non-negative
    intro j
    show 0 ≤ (updCt s.encBal recipient recipientDelta j).pt
    have hnj : 0 ≤ (s.encBal j).pt := hnn j
    have hnr : 0 ≤ (s.encBal recipient).pt := hnn recipient
    by_cases hj : j = recipient
    · simp [updCt, hj]; omega
    · simp [updCt, hj]; exact hnj
  · -- total = provenTotal
    dsimp [ValidEncState, applyL1DepositImport, EncBalanceState21.toV2]
    have h1 := updCt_total s.encBal recipient recipientDelta
    have htot' : (s.encBal .m0).pt + (s.encBal .m1).pt + (s.encBal .m2).pt
               = s.provenTotal := htot
    simp only [EncBalanceState.total, EncBalanceState.bal, hrd]
    omega
  · -- provenTotal increases by amount (definitional)
    rfl
  · -- total increases by amount (via updCt_total)
    have h := applyL1DepositImport_total s recipient amount recipientDelta
    rw [hrd] at h; exact h

/-! ### Settled-tx-chain step for L1 deposit import -/

def applyL1DepositImportChain (s : EncBalanceState21) (recipient : Member)
    (amount : Int) (recipientDelta : Ct) (depositNullifier : Nat)
    (hash2 : Nat → Nat → Nat) : EncBalanceState21 :=
  let s' := applyL1DepositImport s recipient amount recipientDelta
  { s' with settledChain := hash2 s.settledChain depositNullifier }

theorem l1_deposit_chain_step
    (hash2 : Nat → Nat → Nat) (s : EncBalanceState21) (recipient : Member)
    (amount : Int) (recipientDelta : Ct) (depositNullifier : Nat) :
    (applyL1DepositImportChain s recipient amount recipientDelta depositNullifier hash2).settledChain
      = hash2 s.settledChain depositNullifier := rfl

/-! ## §8 Batched intra-channel transfer (abstract2-1 §2.2b / §3.2b / §4.2b)

One state transition applies K txs: all debits against the ANCHOR state, then
all credits (canonical fold, R3). Soundness rests on the single-debit rule R1
(`sendersDistinct`): each tx's channelTxZKP is stated against the anchor
ciphertext of its own sender slot, and the K debited slots are disjoint.

  `batch_preserves_validity` — ValidEncState21 is maintained and the channel
      total (= provenTotal) is conserved for ANY proven batch (sender-as-
      recipient allowed).
  `batch_step_eq_seq` — when additionally no debiting slot is credited in the
      same batch, the fold is extensionally equal to the sequential per-tx
      application (the abstract2 §3.2 chain); with sender-as-recipient the
      batch equals the debit-before-credit order, and validity/conservation
      are covered directly by `batch_preserves_validity`. -/

structure BatchTx where
  sender : Member
  recipient : Member
  amount : Int
  encAmount : Ct
  afterCt : Ct

/-- channelTxZKP statement of one batch tx against the ANCHOR state `s`
    (abstract2-1 §2.2 binding refinement): `encAmount` encrypts a non-negative
    `amount`; `afterCt` encrypts `s.bal sender − amount`, non-negative. -/
def BatchTxProven (s : EncBalanceState21) (t : BatchTx) : Prop :=
  0 ≤ t.amount
  ∧ t.encAmount.pt = t.amount
  ∧ t.afterCt.pt = s.bal t.sender - t.amount
  ∧ 0 ≤ t.afterCt.pt

/-- R1 (single-debit rule): sender slots pairwise distinct. -/
def sendersDistinct : List BatchTx → Prop
  | [] => True
  | t :: rest => (∀ u ∈ rest, u.sender ≠ t.sender) ∧ sendersDistinct rest

/-- What every co-signer checks before signing a batch (§3.2b.3). -/
def BatchProven (s : EncBalanceState21) (txs : List BatchTx) : Prop :=
  (∀ t ∈ txs, BatchTxProven s t) ∧ sendersDistinct txs

/-- Replace one slot's ciphertext (a debit installs the fresh `after` ct). -/
def setCt (f : Member → Ct) (m : Member) (c : Ct) : Member → Ct :=
  fun j => if j = m then c else f j

def debitFold (f : Member → Ct) : List BatchTx → (Member → Ct)
  | [] => f
  | t :: rest => debitFold (setCt f t.sender t.afterCt) rest

def creditFold (f : Member → Ct) : List BatchTx → (Member → Ct)
  | [] => f
  | t :: rest => creditFold (updCt f t.recipient t.encAmount) rest

/-- §3.2b.2 canonical fold: debits first (against the anchor), then credits.
    ONE version bump for the whole batch; `settledChain` invariant (`H2 = 0`);
    `provenTotal` unchanged (intra-channel). -/
def applyBatch (s : EncBalanceState21) (txs : List BatchTx) : EncBalanceState21 where
  encBal := creditFold (debitFold s.encBal txs) txs
  provenTotal := s.provenTotal
  version := s.version + 1
  settledChain := s.settledChain

def mapTotal (f : Member → Ct) : Int :=
  (f .m0).pt + (f .m1).pt + (f .m2).pt

def amtSum : List BatchTx → Int
  | [] => 0
  | t :: rest => t.amount + amtSum rest

theorem setCt_total (f : Member → Ct) (m : Member) (c : Ct) :
    mapTotal (setCt f m c) = mapTotal f - (f m).pt + c.pt := by
  cases m <;> simp [mapTotal, setCt] <;> omega

theorem updCt_mapTotal (f : Member → Ct) (m : Member) (d : Ct) :
    mapTotal (updCt f m d) = mapTotal f + d.pt := by
  have h := updCt_total f m d
  simpa [mapTotal] using h

/-- Credits add exactly the encrypted amounts. -/
theorem creditFold_total (txs : List BatchTx) (f : Member → Ct)
    (hprf : ∀ t ∈ txs, t.encAmount.pt = t.amount) :
    mapTotal (creditFold f txs) = mapTotal f + amtSum txs := by
  induction txs generalizing f with
  | nil => simp [creditFold, amtSum]
  | cons t rest ih =>
    have ht := hprf t (List.mem_cons_self _ _)
    have ihr := ih (updCt f t.recipient t.encAmount)
      (fun u hu => hprf u (List.mem_cons_of_mem _ hu))
    simp only [creditFold, amtSum]
    rw [ihr, updCt_mapTotal, ht]
    omega

/-- Debits remove exactly the amounts, provided each debit still sees the
    ANCHOR ciphertext of its sender slot (guaranteed by R1: earlier debits in
    the fold touch other slots only). -/
theorem debitFold_total (s : EncBalanceState21) (txs : List BatchTx)
    (f : Member → Ct)
    (hagree : ∀ t ∈ txs, f t.sender = s.encBal t.sender)
    (hdist : sendersDistinct txs)
    (hprf : ∀ t ∈ txs, BatchTxProven s t) :
    mapTotal (debitFold f txs) = mapTotal f - amtSum txs := by
  induction txs generalizing f with
  | nil => simp [debitFold, amtSum]
  | cons t rest ih =>
    obtain ⟨hhead, hrest⟩ := hdist
    obtain ⟨_, _, hafter, _⟩ := hprf t (List.mem_cons_self _ _)
    have hat : f t.sender = s.encBal t.sender := hagree t (List.mem_cons_self _ _)
    have hat' : (f t.sender).pt = (s.encBal t.sender).pt := by rw [hat]
    have hagree' : ∀ u ∈ rest,
        (setCt f t.sender t.afterCt) u.sender = s.encBal u.sender := by
      intro u hu
      have hne : u.sender ≠ t.sender := hhead u hu
      simp only [setCt, if_neg hne]
      exact hagree u (List.mem_cons_of_mem _ hu)
    have ihr := ih (setCt f t.sender t.afterCt) hagree' hrest
      (fun u hu => hprf u (List.mem_cons_of_mem _ hu))
    have hbal : (s.encBal t.sender).pt = s.bal t.sender := rfl
    simp only [debitFold, amtSum]
    rw [ihr, setCt_total]
    omega

/-- Pointwise: credits never decrease a slot. -/
theorem creditFold_ge (txs : List BatchTx) (f : Member → Ct)
    (hnn : ∀ t ∈ txs, 0 ≤ t.encAmount.pt) (j : Member) :
    (f j).pt ≤ (creditFold f txs j).pt := by
  induction txs generalizing f with
  | nil => simp [creditFold]
  | cons t rest ih =>
    have ht := hnn t (List.mem_cons_self _ _)
    have h2 := ih (updCt f t.recipient t.encAmount)
      (fun u hu => hnn u (List.mem_cons_of_mem _ hu))
    have step : (f j).pt ≤ (updCt f t.recipient t.encAmount j).pt := by
      by_cases hj : j = t.recipient
      · simp [updCt, hj]; omega
      · simp [updCt, hj]
    simp only [creditFold]
    omega

/-- Pointwise: after all debits every slot is still non-negative. -/
theorem debitFold_nonneg (s : EncBalanceState21) (txs : List BatchTx)
    (f : Member → Ct)
    (hf : ∀ j, 0 ≤ (f j).pt)
    (hprf : ∀ t ∈ txs, BatchTxProven s t) (j : Member) :
    0 ≤ (debitFold f txs j).pt := by
  induction txs generalizing f with
  | nil => exact hf j
  | cons t rest ih =>
    obtain ⟨_, _, _, hpos⟩ := hprf t (List.mem_cons_self _ _)
    have hf' : ∀ k, 0 ≤ ((setCt f t.sender t.afterCt) k).pt := by
      intro k
      by_cases hk : k = t.sender
      · simp [setCt, hk]; exact hpos
      · simp [setCt, hk]; exact hf k
    exact ih (setCt f t.sender t.afterCt) hf'
      (fun u hu => hprf u (List.mem_cons_of_mem _ hu))

/-- §4.2b (3): a proven batch conserves the channel total. -/
theorem batch_conserves_total (s : EncBalanceState21) (txs : List BatchTx)
    (h : BatchProven s txs) :
    (applyBatch s txs).total = s.total := by
  obtain ⟨hprf, hdist⟩ := h
  have henc : ∀ t ∈ txs, t.encAmount.pt = t.amount := fun t ht => (hprf t ht).2.1
  have hd := debitFold_total s txs s.encBal (fun _ _ => rfl) hdist hprf
  have hc := creditFold_total txs (debitFold s.encBal txs) henc
  show mapTotal (creditFold (debitFold s.encBal txs) txs) = mapTotal s.encBal
  omega

/-- §4.2b main theorem: a proven batch (R1; sender-as-recipient allowed)
    preserves the inductive channel invariant, conserves `provenTotal`, and
    leaves `settledTxChain` untouched. -/
theorem batch_preserves_validity (s : EncBalanceState21) (txs : List BatchTx)
    (hvalid : ValidEncState21 s) (h : BatchProven s txs) :
    ValidEncState21 (applyBatch s txs)
    ∧ (applyBatch s txs).provenTotal = s.provenTotal
    ∧ (applyBatch s txs).settledChain = s.settledChain := by
  obtain ⟨hnn, htot⟩ := hvalid
  obtain ⟨hprf, hdist⟩ := h
  refine ⟨⟨?_, ?_⟩, rfl, rfl⟩
  · -- every component non-negative: mid ≥ 0, credits only add
    intro j
    have hmid := debitFold_nonneg s txs s.encBal (fun k => hnn k) hprf j
    have hge := creditFold_ge txs (debitFold s.encBal txs)
      (fun t ht => by
        obtain ⟨hpos, henc, _, _⟩ := hprf t ht
        omega) j
    show 0 ≤ (creditFold (debitFold s.encBal txs) txs j).pt
    omega
  · -- total = provenTotal
    have hcons := batch_conserves_total s txs ⟨hprf, hdist⟩
    have h1 : EncBalanceState.total (EncBalanceState21.toV2 (applyBatch s txs))
        = (applyBatch s txs).total := rfl
    show EncBalanceState.total (EncBalanceState21.toV2 (applyBatch s txs))
        = (EncBalanceState21.toV2 (applyBatch s txs)).provenTotal
    rw [h1, hcons]
    exact htot

/-! ### Sequential equivalence (§4.2b (1)) -/

/-- One tx applied the abstract2 §3.2 way: install the sender's fresh `after`
    ct, then credit the recipient homomorphically. -/
def seqStep (f : Member → Ct) (t : BatchTx) : Member → Ct :=
  updCt (setCt f t.sender t.afterCt) t.recipient t.encAmount

def seqFold (f : Member → Ct) : List BatchTx → (Member → Ct)
  | [] => f
  | t :: rest => seqFold (seqStep f t) rest

theorem setCt_updCt_comm (f : Member → Ct) (m r : Member) (c d : Ct)
    (hne : m ≠ r) :
    setCt (updCt f r d) m c = updCt (setCt f m c) r d := by
  funext j
  by_cases hjm : j = m
  · subst hjm; simp [setCt, updCt, hne]
  · by_cases hjr : j = r
    · subst hjr; simp [setCt, updCt, hjm]
    · simp [setCt, updCt, hjm, hjr]

theorem debitFold_updCt_comm (rest : List BatchTx) (f : Member → Ct)
    (r : Member) (d : Ct)
    (hne : ∀ u ∈ rest, u.sender ≠ r) :
    updCt (debitFold f rest) r d = debitFold (updCt f r d) rest := by
  induction rest generalizing f with
  | nil => rfl
  | cons u tail ih =>
    have hu : u.sender ≠ r := hne u (List.mem_cons_self _ _)
    simp only [debitFold]
    rw [ih (setCt f u.sender u.afterCt)
        (fun v hv => hne v (List.mem_cons_of_mem _ hv))]
    rw [setCt_updCt_comm f u.sender r u.afterCt d hu]

private theorem creditDebit_eq_seq (txs : List BatchTx) :
    ∀ (f : Member → Ct), sendersDistinct txs →
      (∀ t ∈ txs, ∀ u ∈ txs, t.sender ≠ u.recipient) →
      creditFold (debitFold f txs) txs = seqFold f txs := by
  induction txs with
  | nil => intro f _ _; rfl
  | cons t rest ih =>
    intro f hdist hdisj
    obtain ⟨_hhead, hrest⟩ := hdist
    have hdisj' : ∀ a ∈ rest, ∀ b ∈ rest, a.sender ≠ b.recipient :=
      fun a ha b hb =>
        hdisj a (List.mem_cons_of_mem _ ha) b (List.mem_cons_of_mem _ hb)
    have hcredit_t : ∀ u ∈ rest, u.sender ≠ t.recipient :=
      fun u hu =>
        hdisj u (List.mem_cons_of_mem _ hu) t (List.mem_cons_self _ _)
    simp only [debitFold, creditFold, seqFold]
    rw [debitFold_updCt_comm rest (setCt f t.sender t.afterCt)
        t.recipient t.encAmount hcredit_t]
    exact ih (updCt (setCt f t.sender t.afterCt) t.recipient t.encAmount)
      hrest hdisj'

/-- §4.2b (1): when no debiting slot is also credited in the batch, the
    canonical fold equals the sequential per-tx application — the batch is
    literally a compressed run of K abstract2 §3.2 steps sharing one
    agreement round. -/
theorem batch_step_eq_seq (s : EncBalanceState21) (txs : List BatchTx)
    (hdist : sendersDistinct txs)
    (hdisj : ∀ t ∈ txs, ∀ u ∈ txs, t.sender ≠ u.recipient) :
    (applyBatch s txs).encBal = seqFold s.encBal txs :=
  creditDebit_eq_seq txs s.encBal hdist hdisj

/-- K = 1 degenerates to the single-tx transition (sender ≠ recipient). -/
theorem batch_singleton_eq_single (s : EncBalanceState21) (t : BatchTx)
    (hne : t.sender ≠ t.recipient) :
    (applyBatch s [t]).encBal = seqStep s.encBal t := by
  have hdist : sendersDistinct [t] := by simp [sendersDistinct]
  have hdisj : ∀ a ∈ [t], ∀ b ∈ [t], a.sender ≠ b.recipient := by
    intro a ha b hb
    simp at ha hb
    subst ha; subst hb; exact hne
  have h := batch_step_eq_seq s [t] hdist hdisj
  simpa [seqFold] using h

/-! ## §9 Sanity -/

section Sanity

def sampleEnc21 : EncBalanceState21 where
  encBal := fun _ => ⟨10⟩
  provenTotal := 30
  version := 0
  settledChain := 0

theorem sampleEnc21_valid : ValidEncState21 sampleEnc21 :=
  sampleEnc_valid

def entryAonly : TransferEntry where
  dest := 1
  recipient := .m1
  amount := 5
  recipientDelta := ⟨5⟩

def sampleBulkDest1 : BulkChannelUpdate where
  totalAmount := 5
  senderDelta := ⟨-5⟩
  entries := [entryAonly]

theorem sampleBulkDest1_entrySum :
    entryAmountSum sampleBulkDest1.entries = 5 := by
  simp [sampleBulkDest1, entryAmountSum, entryAonly]

theorem sampleBulkDest1_proven : BulkUpdateProven sampleBulkDest1 sampleEnc21 .m0 := by
  refine ⟨sampleBulkDest1_entrySum, ?_, rfl, ?_, ?_⟩
  · show (0 : Int) ≤ 5; omega
  · intro e he
    simp [sampleBulkDest1, entryAonly] at he
    subst he
    exact ⟨by show (0 : Int) ≤ 5; omega, rfl⟩
  · show (5 : Int) ≤ 10; omega

theorem sample_bulk_conservation_dest1 :
    (applyBulkSend sampleEnc21 .m0 sampleBulkDest1).total
      + (applyBulkReceive sampleEnc21 1 sampleBulkDest1).total
      = sampleEnc21.total + sampleEnc21.total :=
  bulk_interChannel_conservation_dest sampleEnc21 sampleEnc21 .m0 1 sampleBulkDest1
    (by intro e he; simp [sampleBulkDest1, entryAonly] at he; subst he; rfl)
    sampleBulkDest1_proven

/-- Batch sanity: m0→m1 (5) and m1→m2 (3) in ONE transition. m1 both debits
    and receives (allowed by R2); senders {m0, m1} distinct (R1). -/
def batchTx1 : BatchTx := ⟨.m0, .m1, 5, ⟨5⟩, ⟨5⟩⟩
def batchTx2 : BatchTx := ⟨.m1, .m2, 3, ⟨3⟩, ⟨7⟩⟩

theorem sampleBatch_proven :
    BatchProven sampleEnc21 [batchTx1, batchTx2] := by
  constructor
  · intro t ht
    simp [batchTx1, batchTx2] at ht
    rcases ht with h | h
    · subst h
      exact ⟨by show (0:Int) ≤ 5; omega, rfl,
             by show (5:Int) = 10 - 5; omega,
             by show (0:Int) ≤ 5; omega⟩
    · subst h
      exact ⟨by show (0:Int) ≤ 3; omega, rfl,
             by show (7:Int) = 10 - 3; omega,
             by show (0:Int) ≤ 7; omega⟩
  · simp [sendersDistinct, batchTx1, batchTx2]

theorem sampleBatch_valid :
    ValidEncState21 (applyBatch sampleEnc21 [batchTx1, batchTx2]) :=
  (batch_preserves_validity sampleEnc21 [batchTx1, batchTx2]
    sampleEnc21_valid sampleBatch_proven).1

theorem sampleBatch_total_conserved :
    (applyBatch sampleEnc21 [batchTx1, batchTx2]).total = sampleEnc21.total :=
  batch_conserves_total sampleEnc21 [batchTx1, batchTx2] sampleBatch_proven

def oneHonestModel21 : SigModel2 :=
  oneHonestModel2

theorem oneHonestModel21_discipline :
    SignsOnlyValid2 oneHonestModel21 ValidEncState :=
  oneHonestModel2_discipline

end Sanity

end ChannelSafety21
