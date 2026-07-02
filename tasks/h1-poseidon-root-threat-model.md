# Threat model: BalanceState.h1 → Poseidon Merkle-root commitment

Date: 2026-07-02. Branch `feat/channel-api-impl` (HEAD 76a4dd0).
Change: replace the flat IMBS keccak over all `MAX_CHANNEL_MEMBERS = 1024` slots with
`H1 = Poseidon(header)` where the header carries a Poseidon Merkle ROOT of the 1024
balance slots. "The tree lives in storage/DB; state carries only the root."

## 1. What H1 is and why it is the deepest binding

`H1 = BalanceState::h1()` is the digest of the hidden balance state. It is:

- hashed into `ChannelState::signing_digest()` (IMCH), which every cosigner signs via the
  aggregated sign-zkp — H1 is therefore the ONLY thing that makes the per-slot balances,
  the settle history and the state version "member-attested";
- hashed into IMCL (`CloseWithdrawal::signing_digest`) and IMCI (`CloseIntent::signing_digest`);
- the `state_commitment_root` of every signed small block
  (`state_update_verifier.rs:520`, wallet_core invariant 5);
- pinned on L1 (`ChannelSettlementManager.finalizedBalanceStateH1`) and used as the anchor
  for withdrawal claims and post-close claims.

Every value the old flat keccak bound MUST remain bound (checklist §5):
`channel_id`, `member_count`, `delegate_count`, per-slot `regev_pk_digests[i]`,
per-slot `enc_balances[i].digest()`, per-slot `pending_adds[i]`, `settled_tx_chain`,
`settled_tx_accumulator_root`, `state_version`.

## 2. New form

Per-slot leaf (member slot order, index i ∈ [0, 1024)):

```
leaf_i = Poseidon([BALANCE_SLOT_LEAF_DOMAIN,
                   regev_pk_digests[i]      (8 u32 limbs),
                   enc_balances[i].digest() (8 u32 limbs),
                   pending_adds[i]          (1 u32 limb)])        -- 18 field elements, FIXED width
```

Slot tree: binary Poseidon Merkle tree of height `BALANCE_SLOT_TREE_HEIGHT = 10`
(`1 << 10 == MAX_CHANNEL_MEMBERS`, const-asserted), node = `PoseidonHashOut::two_to_one`,
ALL 1024 leaves populated (padding slots hash their canonical padding values — the tree is a
function of the FULL slot array, exactly like the old flat keccak). Implemented over the
existing audited `IncrementalMerkleTree<PoseidonHashOut>` /
`IncrementalMerkleProofTarget<PoseidonHashOutTarget>` machinery (leaf value = `leaf_i`,
`Leafable::hash` = identity — the leaf hash IS `leaf_i`).

New H1 (fixed-width header, 26 field elements):

```
H1 = Bytes32::from( Poseidon([BALANCE_STATE_DOMAIN (IMBS),
                              channel_id            (1 u32),
                              member_count          (1 u32),
                              delegate_count        (1 u32),
                              slot_tree_root        (4 Goldilocks elements),
                              settled_tx_chain      (8 u32 limbs),
                              settled_tx_accumulator_root (8 u32 limbs),
                              split_u64(state_version)    (2 u32 limbs, [hi, lo])]) )
```

encoded to a `Bytes32` PI via the canonical `PoseidonHashOut → Bytes32` map
(`Bytes32Target::from_hash_out` with `safe_split_lo_and_hi` in-circuit; `Bytes32::from` natively)
— the SAME injective encoding already used for `settled_tx_accumulator_root` and
`regev_pk_digests`. The close PI layout (95 limbs) is UNCHANGED; only the definition of the
`final_balance_state_h1` bytes changes.

## 3. Injectivity analysis

**T1 — header injectivity.** The header is FIXED width (26 elements) with fixed field
positions; every u32 limb is a canonical value `< 2^32 < p` and the 4 root elements are
canonical Goldilocks values. Two distinct tuples `(channel_id, member_count, delegate_count,
root, chain, acc_root, version)` therefore produce distinct input vectors, and a collision
requires a Poseidon collision. No variable-length ambiguity exists (plonky2's
`hash_no_pad` has no length padding, but ALL callers of this header use exactly 26 elements).

**T2 — leaf injectivity.** Fixed 18-element width, leading domain constant, all payload
limbs canonical u32. Distinct `(pk_digest, enc_digest, pending_adds)` tuples → distinct
inputs. In-circuit, the limbs fed to the leaf hash are u32-range-checked
(PI limbs / `Bytes32Target::new(builder, true)` / `u32_limb`) — kept as defense-in-depth even
though a non-canonical witness limb would simply change the Poseidon output (field elements
are the hash inputs; there is no keccak-style byte-decomposition assumption to violate).

**T3 — leaf vs. node vs. header cross-domain.** Internal nodes hash exactly 8 elements
(two 4-element children); leaves hash 18; the header hashes 26. A leaf/header value cannot be
reinterpreted as a node preimage without a Poseidon break. Additionally the proof height is
FIXED at 10 (the in-circuit `IncrementalMerkleProofTarget` allocates exactly 10 siblings and
`split_le(index, 10)` forces `index < 1024`), so an "extension attack" (opening an internal
node as a leaf at a shallower depth) is structurally impossible: every opening walks exactly
10 levels. `BALANCE_SLOT_LEAF_DOMAIN` is a NEW domain constant added to the repo-wide
non-collision test list.

**T4 — Poseidon `hash_no_pad` length-extension concern.** `hash_n_to_hash_no_pad` absorbs
in rate-8 chunks without padding, so it is only collision-resistant *per fixed input length*.
All three uses here (18, 26, 8) are fixed-length by construction on both the native and
circuit side, matching the existing repo-wide usage pattern (all `hash_inputs_u32` /
`two_to_one` call sites are fixed-width). No variable-length data enters any Poseidon call.

**T5 — Bytes32 encoding of H1.** `Bytes32::from(PoseidonHashOut)` splits each 64-bit element
into (hi, lo) 32-bit limbs — injective. In-circuit `from_hash_out` uses
`safe_split_lo_and_hi`, which forbids the non-canonical `(hi = 2^32-1, lo = x+1)`
decomposition, so exactly ONE Bytes32 encodes a given root/H1. (The claim circuits'
`to_hash_out` round-trip check on `final_settled_tx_accumulator_root` already relies on the
same property.)

## 4. Slot aliasing / index attacks

**A1 — slot i aliasing slot j.** The Merkle position IS the slot index: an inclusion proof
for `leaf` at `index` binds `(leaf, index)` to the root (audited `MerkleProofTarget::get_root`,
`two_to_one_swapped` driven by the `split_le` bits of the index target). A claimant cannot
present slot j's leaf at index i without a Poseidon collision.

**A2 — out-of-range index.** `split_le(index, 10)` inside the proof-target enforces
`index < 1024`. The active-region check `index < member_count + delegate_count` (the same
`less_than_u32` comparator as before) rejects padding slots. `member_count`/`delegate_count`
are bound inside the SAME signed H1 header, so the active/padding boundary is fixed by the
cosigner signatures exactly as before.

  - Pre-existing completeness bug fixed in passing: the claim circuits range-checked
    `active = member_count + delegate_count` to 8 bits with a stale "MAX = 16" comment;
    with MAX = 1024 that would have rejected legal states with `active > 255`. Now checked to
    11 bits (and `active <= 1024` asserted). Soundness was never affected (narrower check).

**A3 — duplicate-leaf ambiguity.** Two slots MAY legitimately hold identical
(pk, ct, adds) tuples (identical leaves). As in the old flat hash, H1 commits the full
ordered vector; a claim opens ONE (leaf, index) pair. Nullifiers are keyed by
`close_intent_digest × member_pk_g` (withdrawal) / `× incoming_tx_hash × receiver_pk_g`
(post-close), NOT by slot index — unchanged semantics, no new double-claim vector.

**A4 — root well-formedness.** The close/cancel circuits witness `slot_tree_root` directly
and do NOT rebuild the tree. This is sound because the root is INSIDE the signed H1 header:
the aggregated cosigner signatures over IMCH (which hashes H1) attest the root, exactly as
they attested the 1024 slot digests before. The circuit's job is only to prove that the PI
scalars (`member_count`, `delegate_count`, `state_version`, `settled_tx_chain`,
`settled_tx_accumulator_root`, `channel_id`) are THE values inside the signed H1 — which the
O(1) header recompute still does with the SAME PI wires feeding H1, IMCH and IMCI (no
divergence possible between the three). Nothing else in close/cancel ever consumed the
individual slot vectors (verified by audit of both circuits: the 1024-wide targets fed ONLY
the H1 keccak), so deleting them removes no binding.

**A5 — garbage root.** A prover COULD sign/produce a state whose header contains 4 arbitrary
field elements that are not the root of any known tree — but that requires the cosigners to
sign it (H1 is signed), i.e. it is the same trust statement as before: cosigners must
validate the state they sign (`BalanceState::validate()` + native `h1()` recompute). A
garbage root makes every later claim unprovable (no inclusion proof exists), harming only the
signers themselves — equivalent to signing garbage ciphertexts under the old scheme.

## 5. Cross-channel / cross-version reuse

- `channel_id` stays in the header ⇒ H1 cannot be replayed across channels.
- `state_version` stays in the header ⇒ H1 cannot be replayed across versions; the
  cancel-close staleness comparison (`revived_state_version > close_final_state_version`)
  keeps using the SAME wire that feeds the header.
- `settled_tx_chain` / `settled_tx_accumulator_root` stay in the header ⇒ the balance-proof
  chain binding (close constraint (e)) and the post-close inclusion-root binding are unchanged.
- The IMBS domain constant leads the header ⇒ the header hash cannot collide with any other
  fixed-width Poseidon use in the repo (domain list test extended with the new leaf domain).
- Hash-function migration: old H1 values (keccak outputs) and new H1 values (canonical
  Poseidon→Bytes32 encodings) are format-distinguishable in practice (the new form has all
  8 limbs `< 2^32` with the (hi,lo) canonical structure; a keccak output is uniform), but no
  system component ever accepts BOTH forms — all circuits, native signers and the L1 pin move
  atomically to the new definition, and all baked fixtures/VKs are invalidated (see §7).

## 6. Consumer-by-consumer audit (who recomputes or opens H1)

| Consumer | Old behavior | New behavior | Binding preserved? |
|---|---|---|---|
| `close_circuit` | in-circuit IMBS keccak over 3×1024 witnessed slot vectors; result → `final_balance_state_h1` PI, → IMCH, → IMCL/IMCI | O(1) Poseidon header over witnessed root + the SAME PI wires; slot vectors deleted | yes — slots bound via root (signed); scalars bound via same wires |
| `cancel_close_circuit` | same, for the REVIVED state | same replacement | yes — revived version/count wires unchanged |
| `withdrawal_claim_circuit` | full slot vectors + 1024-bit one-hot select of `enc_digest` and `regev_pk_digest` + IMBS keccak | height-10 inclusion proof of `leaf_{member_index}` against the witnessed root + O(1) header recompute; leaf fields = (pk-digest gadget output, `user_amount_digest` PI, witnessed `pending_adds_i`) | yes — the leaf hash binds pk-digest AND ct-digest AND adds to the SAME slot index; index bound by Merkle path; active-region check kept |
| `post_close_claim_circuit` | full slot vectors + one-hot select of `regev_pk_digest` + IMBS keccak; acc-root PI fed into H1 | inclusion proof of the receiver's leaf + O(1) header recompute (acc-root PI still feeds the header — same wire binding as before) | yes |
| native `BalanceState::h1()` | flat keccak | rebuilds slot tree (O(1024) native Poseidon) + header; same signature, callers unchanged | yes |
| `wallet_core`, `state_update_verifier`, `channel_member` bin, e2e_flow, `*_pis.rs` | call `.h1()` natively | unchanged call sites | yes |
| Solidity (`ChannelSettlementManager.sol`, `IntmaxRollup.sol`) | **pins/compares `finalBalanceStateH1` as an opaque bytes32 only** — greps for the IMBS domain / any slot-level H1 recompute in `contracts/src` return NOTHING | no contract change needed | yes — value-only pin; fixtures/VKs regenerate |
| `poseidon_sig::domain_constants_no_collision` test | lists IMBS | new `BALANCE_SLOT_LEAF_DOMAIN` added to the list | n/a |

## 7. Residuals & operational notes

- **Fixture/VK invalidation:** every baked artifact that embeds an H1 (close/cancel VKs, MLE
  fixtures, `contracts/test/data/*.json`, Sepolia demo state) is invalidated and must be
  regenerated in the follow-up (same gotcha as the reg-preimage change). No contract CODE
  changes.
- **Signing-cost note:** native `h1()` now costs ~2k Poseidon permutations (bottom-up fold)
  instead of a ~70 KB keccak — still trivially cheap for wallets; production nodes should
  cache the slot tree incrementally (out of scope here).
- **Not changed:** H2, IMCH/IMCL/IMCI keccak layouts, member_set_commitment, the aggregated
  sign-zkp, A5 distinctness, the 95-limb close PI layout, nullifier derivations.
- **Checklist (all former bindings):** channel_id ✓(header), member_count ✓(header),
  delegate_count ✓(header), regev_pk_digests[i] ✓(leaf i), enc_balance digest[i] ✓(leaf i),
  pending_adds[i] ✓(leaf i), settled_tx_chain ✓(header), settled_tx_accumulator_root
  ✓(header), state_version ✓(header). Slot ORDER ✓ (Merkle position). Active/padding split ✓
  (member_count+delegate_count in header + active-region checks in claims + native
  `validate()` padding canonicality, all unchanged).
