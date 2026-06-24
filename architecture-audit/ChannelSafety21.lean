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

/-! ## §8 Sanity -/

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

def oneHonestModel21 : SigModel2 :=
  oneHonestModel2

theorem oneHonestModel21_discipline :
    SignsOnlyValid2 oneHonestModel21 ValidEncState :=
  oneHonestModel2_discipline

end Sanity

end ChannelSafety21
