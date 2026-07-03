# Reg-chain at MAX_CHANNEL_MEMBERS=1024 — diagnosis + restructure design (Phase 2c precursor)

## Symptom
`a3_channel_withdrawal_builds_and_verifies` fails with "Common data mismatch in channel reg hash
chain circuit" (channel_reg_hash_chain_circuit.rs:71). Two stacked causes:
1. `ChannelRegHashChainCircuit::generate_cd()` pins a noop-padded 2^12 template; at MAX=1024 the
   reg-STEP circuit ballooned, so the wrapper that verifies it exceeds the pinned common data.
2. Root cause: `channel_reg_step.rs` witnesses ALL 1024 `MemberRegEntry`s (pk_g, pk_b,
   regev_pk_digest, recipient — 116B/slot) and folds a ~118KB keccak preimage in-circuit
   (`hash_with_prev_hash`, flat pad-to-MAX) — the same flat-keccak disease H1 had (fixed in
   a43e16f by tree-rooting). Also cross-layer: Solidity `_channelRegHashChain`
   (IntmaxRollup.sol:1020) still loops 16 slots → Rust(1024) vs contract(16) digests can never
   match; at 1024 the contract loop would be an O(N²)-memory abi.encodePacked gas bomb and the
   calldata alone (1024×116B) ≈ 1.9M gas.

## Design direction (mirror the H1 fix; owner: "tree in storage, root in state")
The reg-step ALREADY builds the height-10 Poseidon MemberTree for `ChannelLeaf.member_pubkeys_root`
(R2 cross-binding). Restructure the reg-record commitment to a FIXED-width header:
  reg keccak preimage = [prev_hash, channel_id, bp_member_slot, member_count, delegate_count,
                         member_tree_root (as Bytes32), recipients_commitment?]
→ the in-circuit keccak becomes O(1); the 1024 identities stay bound through the Poseidon root the
step already computes from witnessed leaves.

## Open design decisions (need a threat model before code)
1. **What does L1 registration mean for 1024 delegates?** Today `registerChannel` takes full pk
   arrays as calldata and the CONTRACT enforces distinctness/nonzero + recomputes the chain. With a
   root-only record the contract can no longer see individual keys:
   - distinctness/nonzero enforcement moves IN-CIRCUIT (cosigners: A5 chain exists at 16; the
     delegate region at 1024 would need an indexed-Merkle chain at 1024×h≈11k Poseidon in the
     validity path — measure) or moves to a different invariant (do DELEGATE pk collisions matter?
     delegates don't co-sign; a duplicate delegate pk_g affects only claim routing — analyze).
   - recipient binding for claims: currently `registeredRecipientOf[pk_g]` per entry on-chain. With
     root-only, the claim circuit proves (pk_g, recipient) inclusion against the registered root —
     zero extra on-chain cost (claims already verify a ZK proof). Manager storage model changes.
2. **Genesis vs dynamic joins**: the demo adds delegates POST-genesis (relay co-sign flow) with no
   L1 tx per join. Does genesis registration even need 1024 slots, or 16 cosigners + a delegate
   accumulator that grows via later (validity-proven) joins? The latter matches reality and keeps
   registerChannel calldata small.
3. Wrapper CD padding (generate_cd 2^12) must be re-derived after the step shrinks.
4. pw_submit / lifecycle fixtures + validity VK regenerate; Solidity `_channelRegHashChain`,
   `registerChannel`, Manager `_registerDelegates` / `registeredRecipientOf` all change in lockstep.

## Also pending (same workstream)
- wallet_core test binaries stack-overflow at 1024 ([RegevCiphertext; 1024] ≈ 1MB arrays on 2MB
  test-thread stacks) — Box the big arrays in test builders or document RUST_MIN_STACK; decide
  whether runtime paths (wasm 1MB stacks!) are also at risk — wasm has 16MB stack configured in
  .cargo/config.toml, native threads default 2MB.
- delegate_count is u8 (max 255) in BalanceState/ChannelRecord — contradicts the ~1000-delegate
  goal; widen to u16 (H1 header now takes it as a single limb, so the widening is cheap) together
  with the Solidity uint8→uint16 surgery (Manager/Verifier packing + close PI limbs 93/94).

## Status: design doc only — no code yet. Blocked on: H1 adversarial review (running), then a
## dedicated threat model for the registration restructure (CLAUDE.md: threat model before code).
