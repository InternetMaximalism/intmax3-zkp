import Zkp.Core.Field
import Zkp.Core.Builder

/-
  Zkp.Core.Bytes
  ==============

  Models the byte/limb-structured Ethereum-compatible types the
  circuits manipulate: `Bytes32`, `Address`, `U256`, and the
  Poseidon hash output `HashOut`.

  In the Rust code (`src/ethereum_types/`) these are stored as
  arrays of `u32` limbs for Plonky2 compatibility, with helper
  conversions `to_bytes_be` / `from_bytes_be` / `from_hash_out`.
  For reasoning about the *logic* of the circuits that consume
  them, the relevant view is the big-endian **byte list**: that is
  the granularity at which tag bytes are read/overwritten and
  slices are taken. We therefore model each type at the byte-list
  level and treat the limb⇄byte repacking as the identity on this
  view (it is a bijection in the real code).

  SECURITY: byte-validity (`repr b < 256` for each byte) is a
  *constraint the circuit must emit* (range checks), not a free
  fact. We expose it as `IsByte` so that a soundness proof which
  relies on a byte being `< 256` cannot succeed unless the circuit
  actually range-checked it. A missing range check then shows up
  as an unprovable obligation — exactly the kind of gap we hunt.
-/

namespace Zkp
namespace Bytes

open CField Builder

variable {F : Type} [CField F]

/-- A wire is a valid byte iff its canonical representative is < 256.
    Enforced in-circuit by an 8-bit range check. -/
def IsByte (b : F) : Prop := repr b < 256

/-- Poseidon hash output: 4 Goldilocks field elements.
    (`utils/poseidon_hash_out::PoseidonHashOut`.) -/
abbrev HashOut (F : Type) := List F  -- length 4 by convention

/-- Poseidon over a list of field elements. Out of audit scope as a
    primitive, so modeled as an *uninterpreted function*: this gives
    determinism (same preimage ⇒ same digest) for free, which is all
    soundness needs from the gate. Where the *protocol* relies on
    collision resistance we state that as an explicit hypothesis
    (`PoseidonCR`) so the trust assumption is visible, never hidden. -/
opaque poseidon : List F → HashOut F

/-- Collision-resistance assumption, stated explicitly so any proof
    depending on "distinct preimages ⇒ distinct digests" must name it.
    NOTE: this covers the LIST-input leaf/commitment hash only. The
    Merkle fold uses a different opaque, the 2-to-1 compression
    `Merkle.compress`; its CR is the separate named hypothesis
    `Merkle.CompressCR`, consumed by the binding theorems in
    Core/Merkle.lean (`fold_inj`, `merkleVerify_binding`,
    `pathUpdate_preserves_other`). Both share the same idealization
    caveat documented on `Merkle.CompressCR`: injectivity is the
    symbolic "no collision occurred" model, unsatisfiable literally
    for a compressing hash. -/
def PoseidonCR (F : Type) [CField F] : Prop :=
  ∀ xs ys : List F, poseidon xs = poseidon ys → xs = ys

/-! ### NAMED OBSERVATION — cross-domain hash separation

The audit models many struct-leaf digests as DISTINCT opaque symbols
(`transferLeaf`, `txLeafHash`, `sendLeafHash`, `channelLeafHash`,
`memberLeafHash`, `psLeaf`, `privateCommitment`/`commitment`, ...),
but in Rust most of them are UNTAGGED `hash_n_to_hash_no_pad` /
Poseidon calls over the struct's `to_vec()` — there is generally no
per-struct domain-separation tag (the channel leaf's "CHLF" tag,
channel_tree.rs:92, is the exception). Consequences, stated so nobody
over-reads the per-symbol CR hypotheses:

  * Per-symbol collision resistance (a `PoseidonCR`-style hypothesis
    on ONE opaque) says nothing about CROSS-STRUCT collisions: a
    struct whose `to_vec()` coincides with a DIFFERENT struct's
    `to_vec()` hashes identically in Rust, yet the Lean model — with
    two unrelated opaque symbols — cannot even express that
    collision. Treating the symbols as independent is therefore PART
    OF THE IDEALIZATION: it silently assumes the preimage encodings
    never collide across struct types (often true via distinct input
    lengths, but NOT checked pair-by-pair in Lean).
  * Any future theorem that needs "this digest can only open to a
    leaf of THIS struct type" must either verify a genuine tag /
    length separation in the Rust and cite it, or take an explicit
    cross-domain separation hypothesis — never derive it from the
    per-symbol CR alone.

This is the leaf-hash analogue of the `Merkle.CompressCR`
idealization caveat and shares its "no colliding instance exhibited"
symbolic reading. -/

/-- 32-byte big-endian value. Modeled as its byte list (length 32). -/
abbrev Bytes32 (F : Type) := List F

/-- 20-byte Ethereum address (length 20). -/
abbrev Address (F : Type) := List F

/-- `Bytes32Target::from_hash_out`: repack a 4-limb Poseidon digest
    into 32 big-endian bytes. Bijective in the real code; modeled
    opaquely since its internal limb arithmetic is not the subject
    of these logic proofs. -/
opaque fromHashOut : HashOut F → Bytes32 F

/-- `to_bytes_be` on a `Bytes32` is the identity on the byte-list
    view (the limb→byte repack). -/
def toBytesBE (b : Bytes32 F) : List F := b

/-- `from_bytes_be` reconstructs the value from its byte list. -/
def bytes32FromBytesBE (bs : List F) : Bytes32 F := bs

/-- Build an `Address` from a 20-byte big-endian slice. -/
def addressFromBytesBE (bs : List F) : Address F := bs

/-- Overwrite the byte at index `i` with value `v` (used by the tag
    operations `bytes[0] = TAG`). -/
def setByte (bs : List F) (i : Nat) (v : F) : List F := bs.set i v

end Bytes
end Zkp
