/-
# ChannelSafety2.lean — Machine-checked safety proofs for `abstract2.md` (Lattice v2)

This file formalizes the Lattice (Regev/LWE) revision of the minimal
payment-channel specification, `architecture-audit/abstract2.md`, REUSING the
v1 proof `ChannelSafety.lean` via `import` for everything the v2 spec leaves
unchanged:

  REUSED from v1 (unchanged base layer, abstract2.md §2.3/§3.3/§3.5):
    * the L2 ledger transition system (`Ledger`, `Op`, `Apply`, `Exec`) and its
      theorems: `apply/exec_conservation`, `apply/exec_nonneg`,
      `no_double_settlement`, `exec_exit_bound`
    * the close game (`CloseGame`, `L1CloseRule`, `close_no_overdraw`,
      `close_boundary_no_double_spend`)
    * `Member`, `updBal` lemmas

  NEW in v2 (this file):
    * `Ct` — Regev ciphertext abstracted to its plaintext semantics (A5);
      `EncBalanceState` with per-member encrypted balances (abstract2.md §2.1)
    * `Tag` — the H2 component: `.internal` (= 0) or `.txRoot r`
      (= tx_tree_root); signatures are over the PAIR (state, tag) =
      hash(H1, H2) (abstract2.md §2.1/§3.3.2)
    * **structural atomicity**: v1's `AtomicSigModel.atomic` ASSUMPTION becomes
      a THEOREM (`bridgeToV1`) — a root-only signature is not expressible
    * `ChannelUpdate` / `UpdateProven` — the channelUpdateZKP soundness
      contract (abstract2.md §2.3), and the RECEIVE side (`applyReceive`),
      closing part of v1 review finding M4
    * `interChannel_conservation` — sender + recipient channel totals are
      conserved across an inter-channel transfer (delta 両翼束縛, §4.3)
    * challenge game and end-to-end close safety re-proved over encrypted
      states (`challenge_latest_wins2`, `end_to_end_close_safety2`)

Trust base (hypotheses, not theorems):
  (A1) SPHINCS+ unforgeability — `signs i s g` is the only way a signature on
       hash(H1(s), H2(g)) can exist; hash is collision-resistant, so the
       signature binds the exact (state, tag) pair.
  (A2) ZK soundness — balanceProof / validityProof / channelUpdateZKP /
       withdrawClaimZKP cannot certify false statements. Enters as
       `UpdateProven`, the `hsolv` side conditions of the imported ledger, and
       the `hclaims`/`hcap` hypotheses of `end_to_end_close_safety2`.
  (A3) Honest-member discipline — `SignsOnlyValid2`, `OneStatePerVersion2`,
       signing freeze after requestClose (the `hno_newer` hypothesis).
  (A4) L1 contract correctness — `L1CloseRule`, all-signed pre-filtering of
       challenge submissions (`hconf_subs`).
  (A5) Lattice homomorphic correctness — `Ct` is modeled by the plaintext it
       decrypts to (`Ct.pt : Int`, unbounded); ciphertext addition adds
       plaintexts. This SILENTLY assumes no decryption-noise overflow and no
       plaintext-modulus wraparound: real Regev plaintexts live in a finite
       `Z_p` and accumulated noise can break correctness. `channelUpdateZKP`
       must enforce that every intermediate plaintext stays inside the
       modulus range; a wraparound (balance wrapping past 0 or p) is a real
       attack this model cannot express.
  (A6) Confidentiality (property 5, abstract2.md §4.5) — IND-CPA security of
       Regev encryption is a cryptographic indistinguishability statement
       OUTSIDE this model. What IS structural here: the imported BASE-LAYER
       `Ledger` carries only per-channel totals (no member-indexed data exists
       in its type). The channel-state theorems below DO quantify over all
       members' plaintexts (`ValidEncState`) — see M5.

Model abstractions (M1–M3 inherited from v1; M4 revised; M5–M7 new in the
round-2 adversarial review — see lean-safety-proof2.md for the full findings):

  (M1) one settlement per block (imported ledger unchanged);
  (M2) `provenTotal` not linked to the ledger at the state layer;
  (M3) `OneStatePerVersion2` is an assumed discipline. v2 makes it HARDER to
       satisfy: if a send fails at the BP level and is retried at the same
       `stateVersion` with a different root, or rolled back, an honest member
       is forced to sign two different states at one version. The spec needs
       explicit version-allocation/abort semantics for failed sends.
  (M4) receive-side ACCOUNTING is modeled (`applyReceive`,
       `interChannel_conservation`), but receive-side BINDING (that the
       receiver credits the very delta the sender debited) is assumed — made
       explicit as commitment injectivity in
       `interChannel_conservation_bound` — and receive-side REPLAY protection
       (double-crediting the same settled tx) is unmodeled; in the spec it
       rests on `balanceProof` recomputation (A2).
  (M5) RESOLVED AT SPEC LEVEL (abstract2.md rev: `channelTxZKP`): every
       state update — intra-channel included — now carries a range proof, so
       `ValidEncState` is maintainable INDUCTIVELY from per-update ZKPs plus
       each member's own-component check; no member ever needs a co-member's
       plaintext. The proof's soundness enters the model as `ChannelTxProven`
       (A2); `claims_exactly_fill_cap` records the attack this closes
       (negative-component overdraft crowding the honest member's withdrawal
       out of the cap). `authorization2`'s conclusion should still be read
       as "honest checks PLUS ZK soundness (A2) jointly".
  (M6) `TransferAuthorized2` binds the deducted state to a bare root id
       (`Nat`). That the tree at that root contains exactly the transfer
       matching the deduction (TxLeafHash contents, §3.3.2 steps 1–2) is not
       modeled; `settled_transfer_guarantees` takes the circuit-side check as
       the free hypothesis `hcircuit` (A2 + A4), and nothing in the model
       links the ledger op's `amount`/`src` to `s'`/`root`.
  (M7) SPEC-LEVEL OPEN ISSUE: a deducted state signed under `.txRoot r`
       (flowSend1 step 6) is fully confirmed BEFORE L1 inclusion. If the tx
       is never included, the channel holds a signed post-deduction state at
       version v+1 whose deduction never settled; the close game as specified
       picks the highest version, enforcing a deduction that did not happen.
       The spec should require an L1-inclusion witness for `.txRoot`-tagged
       states in close, or let honest members advance the internal version
       only after confirming inclusion.

Round-2 finding 3 (H1 contained the not-yet-generated balanceProof) is
RESOLVED AT SPEC LEVEL by `settledTxChain` (abstract2.md §2.1 rev): H1
commits to the settlement-history hash chain — computable at signing time —
instead of the proof object, and L1 matches the chain exposed in the
submitted proof's public inputs against the signed state's chain. §9 below
proves this binding sound under A1 (`chain_binding_resolves_attachment`).

Liveness is out of scope; only safety is proved.

Checked with: Lean 4.10.0, core library only. Two-step build:
  $ lean ChannelSafety.lean -o ChannelSafety.olean
  $ LEAN_PATH=$PWD lean ChannelSafety2.lean
-/

import ChannelSafety

namespace ChannelSafety2

open ChannelSafety

/-! ## §1 Lattice ciphertexts and encrypted balance states (abstract2.md §1, §2.1) -/

/-- abstract2.md §1 `LatticeCt`: a Regev ciphertext, abstracted to the
    plaintext it decrypts to under its owner's key (A5). Ciphertext
    indistinguishability (A6) is not representable at this abstraction level —
    by design, the safety theorems below never depend on it. -/
structure Ct where
  pt : Int

/-- Homomorphic addition (A5): adding ciphertexts adds plaintexts. -/
def Ct.add (a b : Ct) : Ct := ⟨a.pt + b.pt⟩

/-- abstract2.md §2.1: `BalanceState { encBalances, balanceProof, stateVersion }`.
    `encBal m` is member `m`'s balance encrypted under `m`'s `RegevPk`;
    `provenTotal` is the channel total certified by `balanceProof` (A2). -/
structure EncBalanceState where
  encBal : Member → Ct
  provenTotal : Int
  version : Nat

/-- Plaintext semantics of a member's encrypted balance (A5). -/
def EncBalanceState.bal (s : EncBalanceState) (m : Member) : Int :=
  (s.encBal m).pt

def EncBalanceState.total (s : EncBalanceState) : Int :=
  s.bal .m0 + s.bal .m1 + s.bal .m2

/-- Single-point homomorphic update of an encrypted balance map. -/
def updCt (f : Member → Ct) (m : Member) (d : Ct) : Member → Ct :=
  fun j => if j = m then ⟨(f j).pt + d.pt⟩ else f j

theorem updCt_total (f : Member → Ct) (m : Member) (d : Ct) :
    (updCt f m d .m0).pt + (updCt f m d .m1).pt + (updCt f m d .m2).pt
      = ((f .m0).pt + (f .m1).pt + (f .m2).pt) + d.pt := by
  cases m <;> simp [updCt] <;> omega

/-- abstract2.md §3.1 step 1 / §4.3: what honest members check before signing.
    Stated over the plaintext semantics (A5): each encrypted balance decrypts
    to a non-negative value and the plaintexts sum to the certified total. -/
def ValidEncState (s : EncBalanceState) : Prop :=
  (∀ m : Member, 0 ≤ s.bal m) ∧ s.total = s.provenTotal

/-! ## §2 Tagged signatures: hash(H1, H2) (abstract2.md §2.1, §3.3.2)

In v2 the signature target is the PAIR (state, tag): `H1` commits the
`BalanceState`, `H2` is `0` for intra-channel updates and `tx_tree_root` for
inter-channel sends. By A1 (unforgeability + collision resistance of
`hash(H1, H2)`) a signature binds exactly one such pair, so we model
signatures as a predicate over the pair directly. -/

/-- abstract2.md §2.1 `H2`: the two transfer kinds of §0, made exclusive and
    exhaustive BY CONSTRUCTION. -/
inductive Tag
  | internal            -- H2 = 0 : intra-channel update (§3.2, flowReceive3)
  | txRoot (root : Nat) -- H2 = tx_tree_root : inter-channel send (§3.4)

structure SigModel2 where
  signs : Member → EncBalanceState → Tag → Prop
  honest : Member → Prop

/-- abstract2.md §3.1: a (state, tag) pair is confirmed iff all three members
    signed `hash(H1, H2)`. -/
def Confirmed2 (M : SigModel2) (s : EncBalanceState) (g : Tag) : Prop :=
  ∀ i : Member, M.signs i s g

/-- A state is confirmed under *some* tag (what the close game checks: L1
    verifies the all-member signatures on the submitted state, §3.5.2). -/
def ConfirmedAny (M : SigModel2) (s : EncBalanceState) : Prop :=
  ∃ g : Tag, ∀ i : Member, M.signs i s g

/-- Honest discipline, part 1 (abstract2.md §3.1 steps 1–2, A3). -/
def SignsOnlyValid2 (M : SigModel2) (Valid : EncBalanceState → Prop) : Prop :=
  ∀ i s g, M.honest i → M.signs i s g → Valid s

/-- Honest discipline, part 2 (A3/M3): an honest member never signs two
    different states carrying the same version — regardless of tags. -/
def OneStatePerVersion2 (M : SigModel2) : Prop :=
  ∀ i s g s' g', M.honest i → M.signs i s g → M.signs i s' g' →
    s.version = s'.version → s = s'

/-- **Property 1 — authorization (abstract2.md §4.1).**
    With at least one honest member, every confirmed (state, tag) pair has a
    valid state: the other two members cannot confirm an invalid state. -/
theorem authorization2
    (M : SigModel2) (Valid : EncBalanceState → Prop)
    (hdisc : SignsOnlyValid2 M Valid)
    (i : Member) (hi : M.honest i)
    (s : EncBalanceState) (g : Tag) (hconf : Confirmed2 M s g) :
    Valid s :=
  hdisc i s g hi (hconf i)

/-- With one honest member, two anywhere-confirmed states with the same
    version are equal (used by the challenge game). -/
theorem confirmed_unique_per_version2
    (M : SigModel2) (huniq : OneStatePerVersion2 M)
    (i : Member) (hi : M.honest i)
    (s s' : EncBalanceState)
    (hs : ConfirmedAny M s) (hs' : ConfirmedAny M s')
    (hv : s.version = s'.version) : s = s' := by
  obtain ⟨g, hg⟩ := hs
  obtain ⟨g', hg'⟩ := hs'
  exact huniq i s g s' g' hi (hg i) (hg' i) hv

/-! ## §3 Intra-channel transfer (abstract2.md §2.2, §3.2 — `H2 = 0`) -/

/-- abstract2.md §2.2: `ChannelTx { recipient, encAmount, nonce }`.
    `encAmount` is the amount encrypted under the recipient's `RegevPk`;
    `.pt` is its plaintext semantics (A5). The `nonce` is irrelevant to the
    accounting and omitted. -/
structure ChannelTx2 where
  sender : Member
  recipient : Member
  encAmount : Ct

/-- abstract2.md §2.2 `channelTxZKP` soundness contract (A2) — the M5 fix:
    the sender proves, without revealing any plaintext, that `encAmount`
    encrypts a non-negative amount under the recipient's `RegevPk` and that
    the sender's post-deduction encrypted balance stays non-negative
    (残高 ≥ 送金額). Co-signers VERIFY this proof before signing (§3.2.3) —
    which is exactly what makes the hypotheses of
    `channelTx2_preserves_validity` checkable by members who cannot see the
    sender's plaintext. Without it, two colluding members could create a
    negative balance component intra-channel and, at close, crowd the honest
    member's withdrawal out of the cap (round-2 review finding 5). -/
def ChannelTxProven (t : ChannelTx2) (s : EncBalanceState) : Prop :=
  0 ≤ t.encAmount.pt ∧ t.encAmount.pt ≤ s.bal t.sender

/-- abstract2.md §3.2.1: sender's ct decreases, recipient's ct increases
    homomorphically; `balanceProof` unchanged; `stateVersion + 1`. -/
def applyChannelTx2 (s : EncBalanceState) (t : ChannelTx2) : EncBalanceState where
  encBal := updCt (updCt s.encBal t.sender ⟨-t.encAmount.pt⟩) t.recipient t.encAmount
  provenTotal := s.provenTotal
  version := s.version + 1

/-- **Property 3, intra-channel half (abstract2.md §4.3).**
    With a verified `channelTxZKP` (`ChannelTxProven`, A2), intra-channel
    transfers preserve validity over the plaintext semantics: every component
    stays non-negative and `total = provenTotal` with the `balanceProof`
    unchanged. Starting from a valid state, validity is therefore maintained
    INDUCTIVELY by per-update ZKPs plus each member's own-component check —
    no member ever needs a co-member's plaintext (M5 resolution). -/
theorem channelTx2_preserves_validity (s : EncBalanceState) (t : ChannelTx2)
    (hvalid : ValidEncState s)
    (ht : ChannelTxProven t s) :
    ValidEncState (applyChannelTx2 s t) := by
  obtain ⟨hnn, htot⟩ := hvalid
  obtain ⟨hpos, hsolv⟩ := ht
  have hsolv' : t.encAmount.pt ≤ (s.encBal t.sender).pt := hsolv
  constructor
  · intro j
    show 0 ≤ (updCt (updCt s.encBal t.sender ⟨-t.encAmount.pt⟩)
                t.recipient t.encAmount j).pt
    have hns : 0 ≤ (s.encBal t.sender).pt := hnn t.sender
    have hnr : 0 ≤ (s.encBal t.recipient).pt := hnn t.recipient
    have hnj : 0 ≤ (s.encBal j).pt := hnn j
    by_cases hr : j = t.recipient
    · by_cases hrs : t.recipient = t.sender
      · simp [updCt, hr, hrs]
        omega
      · simp [updCt, hr, hrs]
        omega
    · by_cases hs : j = t.sender
      · have hsr : t.sender ≠ t.recipient := fun hh => hr (hs.trans hh)
        simp [updCt, hr, hs, hsr]
        omega
      · simp [updCt, hr, hs]
        omega
  · have h1 := updCt_total (updCt s.encBal t.sender ⟨-t.encAmount.pt⟩)
      t.recipient t.encAmount
    have h2 : (updCt s.encBal t.sender ⟨-t.encAmount.pt⟩ .m0).pt
            + (updCt s.encBal t.sender ⟨-t.encAmount.pt⟩ .m1).pt
            + (updCt s.encBal t.sender ⟨-t.encAmount.pt⟩ .m2).pt
            = ((s.encBal .m0).pt + (s.encBal .m1).pt + (s.encBal .m2).pt)
              + -t.encAmount.pt :=
      updCt_total s.encBal t.sender ⟨-t.encAmount.pt⟩
    have htot' : (s.encBal .m0).pt + (s.encBal .m1).pt + (s.encBal .m2).pt
               = s.provenTotal := htot
    show (updCt (updCt s.encBal t.sender ⟨-t.encAmount.pt⟩)
            t.recipient t.encAmount .m0).pt
       + (updCt (updCt s.encBal t.sender ⟨-t.encAmount.pt⟩)
            t.recipient t.encAmount .m1).pt
       + (updCt (updCt s.encBal t.sender ⟨-t.encAmount.pt⟩)
            t.recipient t.encAmount .m2).pt
       = s.provenTotal
    omega

/-! ## §4 Inter-channel transfer: channelUpdateZKP, send AND receive
(abstract2.md §2.3, §3.4) -/

/-- abstract2.md §2.3 `TxAux` deltas: `senderDelta` is the (negative) ct added
    to the sending channel's sender balance, `recipientDelta` the (positive)
    ct added to the receiving channel's recipient balance. `amount` is the
    base-layer plaintext amount (public, §4.5 秘匿境界). -/
structure ChannelUpdate where
  amount : Int
  senderDelta : Ct
  recipientDelta : Ct

/-- abstract2.md §2.3 `channelUpdateZKP` soundness contract (A2): what a
    verified proof guarantees about the deltas —
    1. equal magnitude, opposite signs, matching the public `amount`;
    2. the sender stays solvent (残高 ≥ 送金額, the §3.3.1 range constraint).
    Ciphertext well-formedness w.r.t. the `RegevPk`s is absorbed into A5. -/
def UpdateProven (u : ChannelUpdate) (s : EncBalanceState) (sender : Member) : Prop :=
  0 ≤ u.amount
  ∧ u.senderDelta.pt = -u.amount
  ∧ u.recipientDelta.pt = u.amount
  ∧ u.amount ≤ s.bal sender

/-- abstract2.md §3.4 flowSend1 step 5: the deducted state `BalanceState'` of
    the SENDING channel (sender ct += senderDelta, certified total − amount,
    version + 1). -/
def applySend (s : EncBalanceState) (sender : Member) (u : ChannelUpdate) :
    EncBalanceState where
  encBal := updCt s.encBal sender u.senderDelta
  provenTotal := s.provenTotal - u.amount
  version := s.version + 1

/-- abstract2.md §3.4 flowReceive3 step 3: the credited state of the RECEIVING
    channel (recipient ct += recipientDelta, certified total + amount,
    version + 1). NEW in v2 — v1 left the receive side unmodeled (M4). -/
def applyReceive (r : EncBalanceState) (recipient : Member) (u : ChannelUpdate) :
    EncBalanceState where
  encBal := updCt r.encBal recipient u.recipientDelta
  provenTotal := r.provenTotal + u.amount
  version := r.version + 1

theorem applySend_total (s : EncBalanceState) (sender : Member)
    (u : ChannelUpdate) :
    (applySend s sender u).total = s.total + u.senderDelta.pt :=
  updCt_total s.encBal sender u.senderDelta

theorem applyReceive_total (r : EncBalanceState) (recipient : Member)
    (u : ChannelUpdate) :
    (applyReceive r recipient u).total = r.total + u.recipientDelta.pt :=
  updCt_total r.encBal recipient u.recipientDelta

/-- **Property 3, send half (abstract2.md §4.3).** With a verified
    `channelUpdateZKP`, the deducted state stays valid and the certified total
    decreases monotonically (送信側は減少). Honest members *can* sign it. -/
theorem send_preserves_validity (s : EncBalanceState) (sender : Member)
    (u : ChannelUpdate)
    (hvalid : ValidEncState s) (hu : UpdateProven u s sender) :
    ValidEncState (applySend s sender u)
    ∧ (applySend s sender u).provenTotal ≤ s.provenTotal := by
  obtain ⟨hnn, htot⟩ := hvalid
  obtain ⟨hpos, hsd, hrd, hsolv⟩ := hu
  have hsolv' : u.amount ≤ (s.encBal sender).pt := hsolv
  refine ⟨⟨?_, ?_⟩, ?_⟩
  · intro j
    show 0 ≤ (updCt s.encBal sender u.senderDelta j).pt
    have hnj : 0 ≤ (s.encBal j).pt := hnn j
    by_cases hj : j = sender
    · simp [updCt, hj]
      omega
    · simp [updCt, hj]
      omega
  · have h1 := updCt_total s.encBal sender u.senderDelta
    have htot' : (s.encBal .m0).pt + (s.encBal .m1).pt + (s.encBal .m2).pt
               = s.provenTotal := htot
    show (updCt s.encBal sender u.senderDelta .m0).pt
       + (updCt s.encBal sender u.senderDelta .m1).pt
       + (updCt s.encBal sender u.senderDelta .m2).pt
       = s.provenTotal - u.amount
    omega
  · show s.provenTotal - u.amount ≤ s.provenTotal
    omega

/-- What the RECEIVING channel can actually verify from the transmitted data
    (flowReceive3 step 1: the `channelUpdateZKP` it re-checks, A2): the public
    amount is non-negative and the recipient delta credits exactly that
    amount. Sender solvency is asserted transitively by the verified proof
    but is NOT re-checkable by the receiver (it cannot see the sender
    channel's state) — hence it is deliberately not a hypothesis of
    `receive_preserves_validity`. -/
def RecipientVerified (u : ChannelUpdate) : Prop :=
  0 ≤ u.amount ∧ u.recipientDelta.pt = u.amount

/-- A verified `channelUpdateZKP` implies the receiver-side facts. -/
theorem updateProven_recipientVerified {u : ChannelUpdate}
    {s : EncBalanceState} {sender : Member}
    (hu : UpdateProven u s sender) : RecipientVerified u :=
  ⟨hu.1, hu.2.2.1⟩

/-- **Property 3, receive half (abstract2.md §4.3, flowReceive3) — NEW in v2.**
    Crediting the proven `recipientDelta` keeps the receiving channel's state
    valid and increases its certified total by exactly the public `amount`
    (受金側は増加). The hypothesis is only what the receiver can check
    (`RecipientVerified`), not the sender-side solvency it cannot see. -/
theorem receive_preserves_validity (r : EncBalanceState)
    (recipient : Member) (u : ChannelUpdate)
    (hvalid : ValidEncState r) (hu : RecipientVerified u) :
    ValidEncState (applyReceive r recipient u)
    ∧ (applyReceive r recipient u).provenTotal = r.provenTotal + u.amount := by
  obtain ⟨hnn, htot⟩ := hvalid
  obtain ⟨hpos, hrd⟩ := hu
  refine ⟨⟨?_, ?_⟩, rfl⟩
  · intro j
    show 0 ≤ (updCt r.encBal recipient u.recipientDelta j).pt
    have hnr : 0 ≤ (r.encBal recipient).pt := hnn recipient
    have hnj : 0 ≤ (r.encBal j).pt := hnn j
    by_cases hj : j = recipient
    · simp [updCt, hj]
      omega
    · simp [updCt, hj]
      omega
  · have h1 := updCt_total r.encBal recipient u.recipientDelta
    have htot' : (r.encBal .m0).pt + (r.encBal .m1).pt + (r.encBal .m2).pt
               = r.provenTotal := htot
    show (updCt r.encBal recipient u.recipientDelta .m0).pt
       + (updCt r.encBal recipient u.recipientDelta .m1).pt
       + (updCt r.encBal recipient u.recipientDelta .m2).pt
       = r.provenTotal + u.amount
    omega

/-- **Property 2/3 — cross-channel conservation (abstract2.md §4.3 delta
    両翼束縛) — NEW in v2.** `channelUpdateZKP` proves `senderDelta` and
    `recipientDelta` equal and opposite, so an inter-channel transfer
    conserves the sum of the two channels' totals. (v1 could not even state
    this — the receive side was unmodeled, review finding 13/M4.)

    NOTE: this statement applies ONE shared update `u` to both channels, so
    the cross-channel binding is assumed by variable sharing. The binding is
    made an explicit (A1) assumption in `interChannel_conservation_bound`
    below; receive-side replay protection remains unmodeled (M4). -/
theorem interChannel_conservation
    (s r : EncBalanceState) (sender recipient : Member) (u : ChannelUpdate)
    (hu : UpdateProven u s sender) :
    (applySend s sender u).total + (applyReceive r recipient u).total
      = s.total + r.total := by
  obtain ⟨_hpos, hsd, hrd, _hsolv⟩ := hu
  have h1 := applySend_total s sender u
  have h2 := applyReceive_total r recipient u
  omega

/-- The cross-channel binding made explicit (round-2 review finding 8): in
    the spec, sender and receiver each verify their delta against the SAME
    committed `TxLeafHash` (a leaf included under `tx_tree_root`, checked by
    `TxV2MerkleProof`). We model the leaf commitment as an abstract function
    `commit`; its injectivity is exactly A1's collision resistance. If the
    update the sender debited and the update the receiver credits open the
    same commitment, conservation holds even though the two channels never
    compare plaintexts. -/
theorem interChannel_conservation_bound
    (commit : ChannelUpdate → Nat)
    (hinj : ∀ u u', commit u = commit u' → u = u')
    (us ur : ChannelUpdate) (hsame : commit us = commit ur)
    (s r : EncBalanceState) (sender recipient : Member)
    (hu : UpdateProven us s sender) :
    (applySend s sender us).total + (applyReceive r recipient ur).total
      = s.total + r.total := by
  obtain rfl := hinj us ur hsame
  exact interChannel_conservation s r sender recipient us hu

/-- Co-members' encrypted balances (hence plaintexts) are untouched by an
    outgoing deduction — the deduction is borne entirely by the sender. -/
theorem send_comember_unaffected (s : EncBalanceState) (sender : Member)
    (u : ChannelUpdate) (j : Member) (hj : j ≠ sender) :
    (applySend s sender u).bal j = s.bal j := by
  show (updCt s.encBal sender u.senderDelta j).pt = (s.encBal j).pt
  simp [updCt, hj]

/-! ## §5 Structural atomicity (abstract2.md §3.3.2, §3.4 / §4.1)

In v1, "the tx_tree_root signature is only valid together with the
deducted-state signature" was an ASSUMPTION (`AtomicSigModel.atomic`) — the
v1 adversarial review flagged it as such (finding 5). In v2 the signature
target IS `hash(H1', H2 = tx_tree_root)`: a root signature without a state
does not exist as an object. Authorization of an inter-channel send is
DEFINITIONALLY the confirmation of the deducted state under the `.txRoot` tag. -/

/-- abstract2.md §3.4 flowSend1 step 6: the transfer at `root` with deducted
    state `s'` is authorized iff all members signed `hash(H1(s'), root)`. -/
def TransferAuthorized2 (M : SigModel2) (s' : EncBalanceState) (root : Nat) : Prop :=
  Confirmed2 M s' (.txRoot root)

/-- With honest discipline, any authorized send carries a VALID deducted
    state: the loss-shift attack of v1 §3.4 (authorize the send, refuse the
    deduction) is not merely forbidden but inexpressible — there is no
    send-authorization object that does not contain the deducted state. -/
theorem authorized_send_state_valid
    (M : SigModel2) (hdisc : SignsOnlyValid2 M ValidEncState)
    (i : Member) (hi : M.honest i)
    (s' : EncBalanceState) (root : Nat)
    (hauth : TransferAuthorized2 M s' root) :
    ValidEncState s' :=
  hdisc i s' (.txRoot root) hi (hauth i)

/-- Trivial re-encryption used only by the v1 bridge below (it does not claim
    confidentiality — only signature structure). -/
def encOf (ps : ChannelSafety.BalanceState) : EncBalanceState where
  encBal := fun m => ⟨ps.bal m⟩
  provenTotal := ps.provenTotal
  version := ps.version

/-- **v1's atomicity ASSUMPTION becomes provable under v2's signing scheme —
    within the predicate model.** Any v2 signature model induces a v1
    `AtomicSigModel` whose `atomic` field is *proved* (the one-line witness
    below), not assumed: a v2 "root signature" is by definition a signature
    on the deducted state tagged with that root.

    Honest scope of this claim (round-2 review findings 2, 15): it is a
    statement about the MODEL's predicates, conditioned on A1 — that the
    implementation's `channelStateSig` bytes verify only against
    `hash(H1', H2)` and that the hash binds the pair. It does NOT bind the
    tree contents at `root` to the deduction in `H1'` (that is §3.3.2
    steps 1–2 + the validity circuit, see M6), and `root` here is a fixed
    parameter, not derived from the transfer. -/
def bridgeToV1 (M : SigModel2) (root : Nat) : ChannelSafety.AtomicSigModel where
  signsState := fun i ps => ∃ g : Tag, M.signs i (encOf ps) g
  honest := M.honest
  signsRoot := fun i t ps =>
    M.signs i (encOf (ChannelSafety.deduct ps t)) (.txRoot root)
  atomic := fun _i _t _s h => ⟨.txRoot root, h⟩

/-- §3.3.5 composition. `hcircuit` is the ASSUMPTION (A2 + A4) that the
    validity circuit settles a transfer only when the sending channel's
    tagged state signature exists — it is NOT derived here, and the model
    does not link the ledger op's `amount`/`src` to `s'`/`root` (M6; the
    imported `Apply.transfer` carries no signature side condition). Under
    that assumption, a settled transfer simultaneously satisfies the
    state-layer guarantee (valid deducted state, all-signed) and the
    ledger-layer guarantees (non-negative amount, solvency). Formalizing the
    circuit constraint itself (parameterizing `Apply` by the signature model
    and the tx tree) is the main candidate for a v3 model. -/
theorem settled_transfer_guarantees
    (M : SigModel2) (hdisc : SignsOnlyValid2 M ValidEncState)
    (i : Member) (hi : M.honest i)
    {L L' : Ledger} {src dst : Nat} {amount : Int} {root : Nat}
    (s' : EncBalanceState)
    (happly : Apply L (.transfer src dst amount) L')
    (hcircuit : TransferAuthorized2 M s' root) :
    ValidEncState s' ∧ 0 ≤ amount ∧ amount ≤ L.spendable src := by
  cases happly with
  | transfer hne hpos hsolv hfresh =>
    exact ⟨hdisc i s' (.txRoot root) hi (hcircuit i), hpos, hsolv⟩

/-! ## §6 Base layer — REUSED from v1

abstract2.md leaves the base layer structurally unchanged (blocks, commonState
/ `PublicState`, `ChannelLeaf.prev`, deposits, close burn). The imported
theorems apply verbatim:

  * `ChannelSafety.exec_conservation`  — supply changes by Σmint − Σburn
  * `ChannelSafety.exec_nonneg`        — solvency invariant
  * `ChannelSafety.no_double_settlement` — nullifier uniqueness (M1 caveat)
  * `ChannelSafety.exec_exit_bound`    — aggregate close + late-claim bound
  * `ChannelSafety.close_no_overdraw`, `close_boundary_no_double_spend`

Note (A6, property 5): the `Ledger` type contains only per-channel totals —
member-indexed balances do not exist at the base layer, so nothing the BP or
L1 processes ever depends on an individual plaintext balance. -/

/-! ## §7 Challenge game over encrypted states (abstract2.md §3.5.2–§3.5.3) -/

def better2 (a b : EncBalanceState) : EncBalanceState :=
  if a.version < b.version then b else a

theorem better2_eq (a b : EncBalanceState) :
    better2 a b = a ∨ better2 a b = b := by
  unfold better2
  by_cases h : a.version < b.version <;> simp [h]

theorem version_le_better2_left (a b : EncBalanceState) :
    a.version ≤ (better2 a b).version := by
  unfold better2
  by_cases h : a.version < b.version <;> simp [h] <;> omega

theorem version_le_better2_right (a b : EncBalanceState) :
    b.version ≤ (better2 a b).version := by
  unfold better2
  by_cases h : a.version < b.version <;> simp [h] <;> omega

def finalize2 (init : EncBalanceState) (subs : List EncBalanceState) :
    EncBalanceState :=
  subs.foldl better2 init

theorem finalize2_mem :
    ∀ (subs : List EncBalanceState) (init : EncBalanceState),
      finalize2 init subs = init ∨ finalize2 init subs ∈ subs
  | [], _ => Or.inl rfl
  | s :: rest, init => by
    have h := finalize2_mem rest (better2 init s)
    cases h with
    | inl h =>
      cases better2_eq init s with
      | inl hb => exact Or.inl (h.trans hb)
      | inr hb =>
        refine Or.inr ?_
        have hfin : finalize2 init (s :: rest) = s := h.trans hb
        rw [hfin]
        exact List.mem_cons_self _ _
    | inr h => exact Or.inr (List.mem_cons_of_mem _ h)

theorem finalize2_version_ge_init :
    ∀ (subs : List EncBalanceState) (init : EncBalanceState),
      init.version ≤ (finalize2 init subs).version
  | [], _ => Nat.le_refl _
  | s :: rest, init =>
    Nat.le_trans (version_le_better2_left init s)
      (finalize2_version_ge_init rest (better2 init s))

theorem finalize2_version_ge :
    ∀ (subs : List EncBalanceState) (init : EncBalanceState),
      ∀ s ∈ subs, s.version ≤ (finalize2 init subs).version
  | [], _, _, hs => by cases hs
  | t :: rest, init, s, hs => by
    cases hs with
    | head =>
      exact Nat.le_trans (version_le_better2_right init t)
        (finalize2_version_ge_init rest (better2 init t))
    | tail _ h => exact finalize2_version_ge rest (better2 init t) s h

/-- **Property 4 — stale close prevention (abstract2.md §3.5.3, §4.4).**
    Same statement as v1, over encrypted states: with one honest member, L1's
    all-signed pre-filtering (A4), the honest member's latest state submitted
    (`hsubmitted` — a liveness precondition), and the post-requestClose
    signing freeze (A3), the challenge game settles on exactly the latest
    confirmed state. Note: the L1 contract checks signatures over
    `hash(H1, H2)` without learning any plaintext balance (A6). -/
theorem challenge_latest_wins2
    (M : SigModel2) (i : Member) (hi : M.honest i)
    (huniq : OneStatePerVersion2 M)
    (init latest : EncBalanceState) (subs : List EncBalanceState)
    (hsubmitted : latest ∈ subs)
    (hconf_init : ConfirmedAny M init)
    (hconf_subs : ∀ s ∈ subs, ConfirmedAny M s)
    (hno_newer : ∀ s, ConfirmedAny M s → s.version ≤ latest.version) :
    finalize2 init subs = latest := by
  have hconf_fin : ConfirmedAny M (finalize2 init subs) := by
    cases finalize2_mem subs init with
    | inl h => rw [h]; exact hconf_init
    | inr h => exact hconf_subs _ h
  have h1 : latest.version ≤ (finalize2 init subs).version :=
    finalize2_version_ge subs init latest hsubmitted
  have h2 : (finalize2 init subs).version ≤ latest.version :=
    hno_newer _ hconf_fin
  exact confirmed_unique_per_version2 M huniq i hi _ _ hconf_fin
    (hconf_subs latest hsubmitted) (Nat.le_antisymm h2 h1)

/-! ## §8 End-to-end close safety (abstract2.md §3.5.4) -/

/-- **Composition of properties 1–4 at the close boundary, v2.**
    As in v1, plus the v2 reading of the payout rule: `g.claims = final.bal`
    states that L1 pays member `m` only what `m` proves via
    `withdrawClaimZKP` — the plaintext of their own encrypted balance in the
    all-signed final state (A2; no other member's cooperation or plaintext is
    needed, §4.4). Conclusions: per-member payout ≤ agreed share; total payout
    ≤ the channel's real L2 funds at burn time; the final state is valid; and
    the cap equals the agreed total exactly. -/
theorem end_to_end_close_safety2
    (M : SigModel2) (hdisc : SignsOnlyValid2 M ValidEncState)
    (i : Member) (hi : M.honest i)
    (final : EncBalanceState) (hconf : ConfirmedAny M final)
    (g : CloseGame)
    (hcap : g.cap = final.provenTotal)
    (hclaims : g.claims = final.bal)
    (hrule : L1CloseRule g)
    {L L' : Ledger} (hburn : Apply L (.exitBurn g.channel g.cap) L') :
    (∀ m, g.paid m ≤ final.bal m)
    ∧ g.totalPaid ≤ L.spendable g.channel
    ∧ ValidEncState final
    ∧ final.total = g.cap := by
  obtain ⟨tg, htg⟩ := hconf
  have hvalid : ValidEncState final := hdisc i final tg hi (htg i)
  refine ⟨fun m => ?_, close_no_overdraw g hburn hrule, hvalid,
    hvalid.2.trans hcap.symm⟩
  have h := hrule.paid_le_claim m
  rw [hclaims] at h
  exact h

/-- **M5 attack closure (round-2 review finding 5).** In a VALID final state
    the three (provably non-negative) shares sum EXACTLY to the cap, so the
    L1 rule `Σ paid ≤ withdrawCap` admits every member withdrawing their full
    share simultaneously: the collusive "negative-component overdraft whose
    non-negative claims exceed the cap and crowd out the honest member's
    withdrawal" is impossible once EVERY state update carries its range proof
    (`ChannelTxProven` intra-channel / `UpdateProven` inter-channel, A2),
    because validity is then maintained inductively
    (`channelTx2_preserves_validity`, `send/receive_preserves_validity`). -/
theorem claims_exactly_fill_cap
    (final : EncBalanceState) (hvalid : ValidEncState final)
    (g : CloseGame)
    (hcap : g.cap = final.provenTotal)
    (hclaims : g.claims = final.bal) :
    g.claims .m0 + g.claims .m1 + g.claims .m2 = g.cap := by
  rw [hclaims, hcap]
  exact hvalid.2

/-! ## §9 state ↔ balanceProof binding via `settledTxChain`
(abstract2.md §2.1 rev — resolution of round-2 review finding 3)

The signed `H1` cannot contain the post-send `balanceProof` (it does not
exist yet at signing time). Instead the state commits to `settledTxChain` —
a hash chain over the identifiers of the base-layer settlements the state
accounts for (`TxLeafHash` for transfers, deposit hashes for deposits). The
`TxLeafHash` IS known at signing time, unlike the nullifier (whose preimage
includes the not-yet-known `block_number` — which is why the nullifier
cannot serve this role directly; it keeps its base-layer anti-replay duty).
The balance circuit exposes the chain of settlements it incorporated as a
public input (A2), and L1 accepts a submitted proof only if the two chains
match (§3.5.2 step 2). -/

/-- Hash chain over settlement identifiers: genesis 0, then
    `chain' = hash2 chain id`. -/
def chainOf (hash2 : Nat → Nat → Nat) : List Nat → Nat
  | [] => 0
  | x :: rest => hash2 (chainOf hash2 rest) x

/-- Collision resistance of the chain (A1): if `hash2` is injective on pairs
    and never outputs the genesis value, equal chains imply equal settlement
    histories. -/
theorem chainOf_injective (hash2 : Nat → Nat → Nat)
    (hinj : ∀ a b a' b', hash2 a b = hash2 a' b' → a = a' ∧ b = b')
    (hnz : ∀ a b, hash2 a b ≠ 0) :
    ∀ l l', chainOf hash2 l = chainOf hash2 l' → l = l'
  | [], [], _ => rfl
  | [], _x :: _r, h => absurd h.symm (hnz _ _)
  | _x :: _r, [], h => absurd h (hnz _ _)
  | x :: r, x' :: r', h => by
    obtain ⟨hc, hx⟩ := hinj _ _ _ _ h
    rw [hx, chainOf_injective hash2 hinj hnz r r' hc]

/-- **State↔proof binding is sound (round-2 review finding 3 resolved).**
    `totalOf` models the channel total a balance proof certifies as a
    deterministic function of the settlement history it incorporated (A2).
    If the submitted proof's exposed chain equals the signed state's
    `settledTxChain`, both were computed from the SAME history (A1), so the
    proof certifies exactly the total the state accounts for: attaching a
    proof based on a different settlement history to a confirmed state is
    impossible. -/
theorem chain_binding_resolves_attachment
    (hash2 : Nat → Nat → Nat)
    (hinj : ∀ a b a' b', hash2 a b = hash2 a' b' → a = a' ∧ b = b')
    (hnz : ∀ a b, hash2 a b ≠ 0)
    (totalOf : List Nat → Int)
    (histState histProof : List Nat)
    (hmatch : chainOf hash2 histState = chainOf hash2 histProof) :
    totalOf histState = totalOf histProof := by
  rw [chainOf_injective hash2 hinj hnz histState histProof hmatch]

/-! ## §10 Sanity: the v2 assumptions are satisfiable (non-vacuity) -/

section Sanity

/-- A valid encrypted state exists. -/
def sampleEnc : EncBalanceState where
  encBal := fun _ => ⟨10⟩
  provenTotal := 30
  version := 0

theorem sampleEnc_valid : ValidEncState sampleEnc :=
  ⟨fun _ => by show (0 : Int) ≤ 10; omega,
   by show (10 : Int) + 10 + 10 = 30; omega⟩

/-- A provable `channelUpdateZKP` instance exists (the hypotheses of
    `send/receive_preserves_validity` and `interChannel_conservation` are
    jointly satisfiable). -/
def sampleUpdate : ChannelUpdate where
  amount := 4
  senderDelta := ⟨-4⟩
  recipientDelta := ⟨4⟩

theorem sampleUpdate_proven : UpdateProven sampleUpdate sampleEnc .m0 :=
  ⟨by show (0 : Int) ≤ 4; omega, rfl, rfl, by show (4 : Int) ≤ 10; omega⟩

/-- A provable `channelTxZKP` instance exists (the hypothesis of
    `channelTx2_preserves_validity` is satisfiable). -/
def sampleChannelTx : ChannelTx2 where
  sender := .m0
  recipient := .m1
  encAmount := ⟨3⟩

theorem sampleChannelTx_proven : ChannelTxProven sampleChannelTx sampleEnc :=
  ⟨by show (0 : Int) ≤ 3; omega, by show (3 : Int) ≤ 10; omega⟩

/-- Cross-channel conservation holds on the sample instance. -/
theorem sample_conservation :
    (applySend sampleEnc .m0 sampleUpdate).total
      + (applyReceive sampleEnc .m1 sampleUpdate).total
      = sampleEnc.total + sampleEnc.total :=
  interChannel_conservation sampleEnc sampleEnc .m0 .m1 sampleUpdate
    sampleUpdate_proven

/-- Non-vacuity in the adversarial configuration: exactly one honest member
    (`m0`) among two members who sign anything, over tagged signatures. -/
def oneHonestModel2 : SigModel2 where
  signs := fun i s _g => i = .m0 → ValidEncState s
  honest := fun i => i = .m0

theorem oneHonestModel2_discipline :
    SignsOnlyValid2 oneHonestModel2 ValidEncState :=
  fun _ _ _ hi hsig => hsig hi

/-- The adversarial members really are unconstrained: `m1` signs every
    (state, tag) pair — including invalid states and arbitrary roots — without
    breaking the honest discipline. -/
theorem oneHonestModel2_adversary_unconstrained
    (s : EncBalanceState) (g : Tag) :
    oneHonestModel2.signs .m1 s g :=
  fun h => Member.noConfusion h

end Sanity

end ChannelSafety2
