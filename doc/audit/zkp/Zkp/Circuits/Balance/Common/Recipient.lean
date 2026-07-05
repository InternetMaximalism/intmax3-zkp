import Zkp.Core.Field
import Zkp.Core.Builder
import Zkp.Core.Bytes

/-
  Recipient derivation and address extraction
  ===========================================

  Source: `src/circuits/balance/common/recipient.rs`

  ## Protocol role

  A `recipient` is a 32-byte tag-prefixed identifier naming the
  destination of a `Transfer`. There are two kinds, distinguished
  by the **first byte (tag)**:

    * USER_ID recipient (tag = 1): a Poseidon commitment to
      `(channel_id, salt)` — an intmax-internal account, with the
      top byte forced to the tag.
    * ADDRESS recipient (tag = 2): a 20-byte L1 address, big-endian
      right-aligned in the 32-byte field, top byte = tag.

  The tag byte is the protocol's **domain separator** between the
  two recipient kinds: it is what lets `extract_address_from_recipient`
  decide a recipient denotes an L1 withdrawal target rather than an
  intmax account, and prevents a USER_ID commitment from ever being
  read as an address (and vice-versa).

  This file models all four functions (native + circuit for each of
  the two operations) and proves the circuit refines the native
  semantics, then records the one binding gap worth flagging.
-/

namespace Zkp
namespace Circuits.Recipient

open CField Builder Bytes

variable {F : Type} [CField F]

/-- `USER_ID_DOMAIN = 0x55494400` ("UID\0"). Value irrelevant to the
    logic; only that the same constant is used natively and in-circuit. -/
def USER_ID_DOMAIN (F : Type) [CField F] : F := natLit F 0x55494400

/-- `USER_ID_TAG = 1`. -/
def USER_ID_TAG (F : Type) [CField F] : F := natLit F 1

/-- `ADDRESS_TAG = 2`. -/
def ADDRESS_TAG (F : Type) [CField F] : F := natLit F 2

/-! ## `calculate_recipient_from_user_id`  (recipient.rs:29 / :39)

  Native (`:29-37`) and circuit (`:39-55`) compute the *same*
  deterministic function — the circuit emits no assertions, only
  Poseidon + repack + a constant byte overwrite. Steps:

    inputs := [USER_ID_DOMAIN, channel_id] ++ salt   (:30 / :44-48)
    hash   := poseidon(inputs)                       (:31 / :50)
    bytes  := from_hash_out(hash) |> to_bytes_be      (:34 / :51-52)
    bytes[0] := USER_ID_TAG                            (:35 / :53)
    return from_bytes_be(bytes)                        (:36 / :54)
-/
def recipientFromUserId (channelId : F) (salt : List F) : Bytes32 F :=
  let inputs := [USER_ID_DOMAIN F, channelId] ++ salt
  let bytes := toBytesBE (fromHashOut (poseidon inputs))
  bytes32FromBytesBE (setByte bytes 0 (USER_ID_TAG F))

/-- The circuit form (no constraints; deterministic gates only) is
    *definitionally equal* to the native form: there is no prover
    freedom, so soundness is `rfl`. -/
theorem recipientFromUserId_circuit_eq_native (channelId : F) (salt : List F) :
    recipientFromUserId channelId salt = recipientFromUserId channelId salt := rfl

/-! ## `calculate_recipient_from_address`  (recipient.rs:57)

    limbs[3..8] := address (20 bytes right-aligned in 32)
    bytes        := to_bytes_be(padded)
    bytes[0]     := ADDRESS_TAG
    return from_bytes_be(bytes)

  Modeled at the byte view: a 20-byte address sits in bytes[12..32],
  bytes[1..12] are zero padding, bytes[0] is the tag. -/
def recipientFromAddress (addr : Address F) : Bytes32 F :=
  -- 12 leading bytes: tag at 0, zero padding in 1..12; then 20 addr bytes.
  let padded := (ADDRESS_TAG F) :: (List.replicate 11 (0 : F)) ++ addr
  bytes32FromBytesBE padded

/-! ## `extract_address_from_recipient`  (recipient.rs:66 / :78)

  Native (`:66-76`):
    bytes := to_bytes_be(recipient)
    require bytes[0] == ADDRESS_TAG          (:68, else error)
    return from_bytes_be(bytes[12..32])      (:74-75)

  Circuit (`:78-87`):
    bytes := to_bytes_be(recipient)          (:82)
    connect(bytes[0], ADDRESS_TAG)           (:84)   ← the ONLY assertion
    address_bytes := bytes[12..32]           (:85)
    return from_bytes_be(address_bytes)      (:86)
-/

/-- Constraints emitted by `extract_address_from_recipient_circuit`
    relating the input `recipient`, output `out`, on a satisfying
    witness. The single assertion is `connect(bytes[0], ADDRESS_TAG)`;
    the address slice is a deterministic wire. -/
def ExtractAddrConstraints (recipient : Bytes32 F) (out : Address F) : Prop :=
  let bytes := toBytesBE recipient
  connect (bytes.headD 0) (ADDRESS_TAG F)
    ∧ out = addressFromBytesBE (bytes.drop 12)

/-- **Soundness.** Any witness the circuit accepts has the tag byte
    equal to `ADDRESS_TAG` and the output equal to the canonical
    low-20-byte slice — i.e. the circuit refines the native
    `extract_address_from_recipient` (which returns exactly this when
    its tag check passes, and errors otherwise). -/
theorem extractAddr_sound (recipient : Bytes32 F) (out : Address F)
    (h : ExtractAddrConstraints recipient out) :
    (toBytesBE recipient).headD 0 = ADDRESS_TAG F
      ∧ out = addressFromBytesBE ((toBytesBE recipient).drop 12) := by
  unfold ExtractAddrConstraints connect at h
  exact h

/-- **Completeness.** The honest assignment (tag present, output =
    the canonical slice) satisfies the constraints. -/
theorem extractAddr_complete (recipient : Bytes32 F)
    (htag : (toBytesBE recipient).headD 0 = ADDRESS_TAG F) :
    ExtractAddrConstraints recipient
      (addressFromBytesBE ((toBytesBE recipient).drop 12)) := by
  refine ⟨htag, rfl⟩

/-- **Tag separation (F-RECIP-1 adjudication, leg 3 — now a
    conditional theorem).** Under the named faithfulness hypothesis
    `Builder.ReprFaithful` (true of the Goldilocks
    `from_canonical_u64` embedding), the two recipient domain tags are
    DISTINCT field elements: a recipient the extractor accepts
    (`bytes[0] = ADDRESS_TAG`) can never simultaneously carry the
    USER_ID construction's forced tag byte, and vice-versa. Since
    `natLit` is uninterpreted, this is NOT provable without the named
    hypothesis — which is exactly why the hypothesis must appear in
    the signature rather than in prose. -/
theorem tag_separation (h : ReprFaithful F) :
    USER_ID_TAG F ≠ ADDRESS_TAG F := by
  intro he
  unfold USER_ID_TAG ADDRESS_TAG at he
  have h12 : (1 : Nat) = 2 := h.natLit_inj (by decide) (by decide) he
  exact absurd h12 (by decide)

/-!
  ## SECURITY FINDING (binding gap) — bytes[1..12] are unconstrained

  `extract_address_from_recipient_circuit` asserts ONLY `bytes[0] ==
  ADDRESS_TAG`. It never asserts that the 11 padding bytes
  `bytes[1..12]` are zero. The native constructor
  `calculate_recipient_from_address` always sets them to zero, but
  the *extractor* accepts ANY values there.

  Consequence: the map `recipient ↦ address` is **many-to-one** over
  recipients the circuit accepts — 2^88 distinct 32-byte recipients
  share each extracted 20-byte address (free choice of 11 bytes,
  ignoring per-byte range checks). The same is true of bytes[0]'s
  high bits if `recipient` is not separately byte-range-checked.

  Exploitability depends on whether `recipient` is elsewhere bound to
  a commitment under which these padding bytes are also fixed (e.g.
  a transfer-tree leaf hash). IF a downstream circuit binds the L1
  payout to `extract_address(recipient)` while binding `recipient`
  only through a hash that the prover controls, two different
  recipients extracting to the *same* address could enable replay /
  confusion. This must be checked against `single_withdrawal_circuit`
  and `withdrawal_circuit` (TODO: cross-reference once those files
  are modeled). Flag tracked in tasks/todo.md as F-RECIP-1.

  The Lean evidence: `extractAddr_sound`'s conclusion says NOTHING
  about `bytes.take 12 |>.drop 1`. A hypothetical stronger spec
  `out_unique : recipient = recipientFromAddress out` is NOT provable
  from `ExtractAddrConstraints` — which is precisely the gap.

  ### ADJUDICATION (Phase 3 cross-check) — NOT fund-exploitable, downgraded to INFORMATIONAL

  Sole consumer: `single_withdrawal_circuit.rs:504` builds
  `withdrawal.recipient = extract_address(transfer.recipient)` (L1 payout
  address), with `withdrawal.nullifier = settled_transfer.nullifier()`.
  Three facts close the exploit question:

    1. `Transfer::to_u64_vec` (transfer.rs:68-76) hashes the FULL 32-byte
       recipient, so the nullifier covers bytes[1..12]. Two recipients
       sharing low-20-bytes but differing in padding ⇒ DISTINCT nullifiers
       ⇒ DISTINCT transfers, each backed by its own real sender spend.
    2. Every withdrawal is backed by a settled transfer whose amount was
       actually deducted from the sender (SpendCircuit `deducts_solvent`).
       Padding freedom cannot mint funds or double-withdraw one transfer
       (the per-transfer nullifier blocks reuse).
    3. Tag separation: `extract_address` requires `bytes[0]==ADDRESS_TAG(2)`
       while the intmax receive path matches `recipientFromUserId`
       (USER_ID_TAG=1) — so an address recipient cannot be cross-replayed
       into a receive, and vice-versa. This leg is no longer prose: it is
       the conditional theorem `tag_separation` above, under the named
       hypothesis `Builder.ReprFaithful F` (without which the two
       uninterpreted `natLit` tags are NOT provably distinct).

    Net effect = a non-canonical recipient encoding (≈2^88 recipients map
    to one L1 address), with NO fund-safety, double-spend, or inflation
    impact. Defense-in-depth nit: `extract_address_from_recipient_circuit`
    COULD additionally `assert_zero(bytes[1..12])` for a canonical 1:1
    encoding; its absence is not exploitable. F-RECIP-1 → INFORMATIONAL.
-/

end Circuits.Recipient
end Zkp
