# Phase 1 — linearize A5 pk_g distinctness (O(N²) → O(N log N)), MAX-agnostic groundwork

Goal: replace the O(MAX²) pairwise pk_g distinctness check in the close circuit (and keep the
Solidity side consistent) with a sub-quadratic check, WITHOUT changing slot semantics, so that a
later MAX bump (Phase 2) does not blow up circuit size / gas. Done at the current MAX=16 first,
adversarially reviewed and tested, then carried into Phase 2.

## Background (established this session)
- close_circuit.rs:657-664 enforces A5 ("no two ACTIVE member slots share pk_g") via an all-pairs
  loop → O(MAX²). MAX=16→120 pairs (cheap), 256→32,640, 1024→523,776 (infeasible). The cost bites
  the CIRCUIT at high MAX; the Solidity 120-pair loop (IntmaxRollup.sol:927-934) is cheap.
- Adversarial review CONFIRMED the loop is the SOLE in-circuit enforcer of A5 (the C' fold uses a
  constant state_digest, so one key can sign two slots). It must be REPLACED, not deleted.

## Design decision: indexed-Merkle insertion (NOT sort-slots, NOT grand-product)
- **Option A (sort slot order by pk_g) — REJECTED.** Breaks the system: cosigners fixed at slots
  0,1,2 (CLI_SLOTS, BP_SLOT=0); bpMemberSlot addresses a member by slot INDEX
  (ChannelSettlementManager.sol:627 `memberPkGs[bpMemberSlot]`); members/delegates occupy contiguous
  regions 0..mc / mc..mc+dc; joins are append-only with STABLE slots; all commitments/H1 are in slot
  order. Sorting would move cosigners, break bpMemberSlot, and shift existing slots on each join.
- **Option B (witnessed sorted permutation + grand-product) — fallback only.** Preserves slot order
  but needs a Fiat-Shamir-bound challenge + injective enc() — novel crypto (CLAUDE.md: avoid
  from-scratch primitives).
- **CHOSEN: indexed-Merkle insertion.** Process ACTIVE keys IN SLOT ORDER, inserting each (gated by
  active_bits) into an initially-empty IndexedMerkleTree; the existing insertion gadget
  (src/utils/trees/indexed_merkle_tree/insertion.rs:286-294) proves `prev_low.key < key <
  next.key` per insert = non-membership = distinctness. A duplicate makes an insert fail. Reuses
  AUDITED nullifier code; slot order untouched; no permutation, no new Fiat-Shamir. O(N·height).

## Soundness obligations the new check MUST enforce (falsifiable)
- [ ] Two active slots i,j (both < member_count) with equal pk_g ⇒ circuit UNSATISFIABLE (the second
      insertion's low-leaf bound fails). Test with a malicious witness.
- [ ] Padding slots (i >= member_count) are NOT inserted (gated by active_bits); duplicate padding
      zeros never trip the check and never mask a real collision.
- [ ] The keys fed to the distinctness check are the SAME member_pk_g_targets used in
      member_set_commitment and the C' fold (connect, don't re-witness).
- [ ] active_bits / member_count binding unchanged (close_circuit.rs:439-459) and still gates the set.
- [ ] pk_g compared as canonical 256-bit (watch the Bytes32 top-limb 29-bit masking,
      bytes32.rs:31-33).
- [ ] Equivalent to the deleted loop: A5 holds for member_count active members.

## Solidity side (Phase 1 scope)
- At MAX=16 the on-chain O(N²) registration check is cheap; linearizing it is a Phase-2 concern (the
  real gas risk is the iterative abi.encodePacked builders, not the distinctness loop).
- Phase 1 = CIRCUIT change only. member_set_commitment stays byte-identical (do NOT touch the
  Solidity formula). The close VK changes (circuit changed) → re-pin + regenerate close/cancel-close
  fixtures.

## Files
- [ ] src/circuits/channel/close_circuit.rs — replace :657-664 with indexed-insertion distinctness
- [ ] src/circuits/channel/cancel_close_circuit.rs:445-446 — same O(N²) loop, same replacement
- [ ] src/utils/trees/indexed_merkle_tree/ — reuse insertion gadget (CONFIRM a circuit-target path
      exists; if only native, the target path is a bigger task — escalate)
- [ ] Tests: malicious-duplicate (must fail), honest close (must pass), padding-zeros; existing close
      tests still pass; regenerate close/cancel-close fixtures + re-pin VKs.

## Process (CLAUDE.md)
1. [ ] Read the insertion gadget — confirm a CIRCUIT (target) insertion exists, not just native.
2. [ ] Implement in close_circuit (then cancel_close_circuit).
3. [ ] INDEPENDENT adversarial subagent review (separate from implementer).
4. [ ] Tests + regenerate fixtures + re-pin VKs.
5. [ ] Only then Phase 2 (MAX bump).

## Status: design fixed (indexed-Merkle insertion). NEXT: confirm a circuit-target insertion path.
