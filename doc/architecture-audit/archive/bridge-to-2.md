# bridge-to-2.md — Mapping Current Implementation to abstract2.md

**Status:** Readiness assessment for Lattice-encrypted channel implementation  
**Date:** 2026-06-11  
**Target:** abstract2.md (v2, Lattice edition)

---

## Executive Summary

The codebase has **strong foundational infrastructure** (lattice commitments, hash chains, proof verification) but **lacks the specific compositional layer** defined in abstract2.md. The gap is not architectural — the abstractions fit — but rather **structural (types/wiring) and proof-compositional (explicit ZKP proofs for balance updates)**.

**Effort estimate:** 6–8 weeks for full implementation, broken into 4 phases (see below).

---

## Current Implementation State vs. abstract2.md

### What's Already Done (≥70% complete)

| Component | Location | Status | abstract2 mapping |
|-----------|----------|--------|-------------------|
| **Lattice commitments (encrypted balances)** | `src/common/channel.rs:293–305` | ✅ Full | `LatticeCt`, `Ct.pt` semantics |
| **Lattice binding verification** | `src/circuits/channel/state_update_verifier.rs:88–102` | ✅ Full | `channelUpdateZKP` / `channelTxZKP` soundness (A2) |
| **Hash chain infrastructure** | `src/utils/hash_chain/mod.rs` + `src/circuits/validity/deposit_hash_chain/` | ✅ Full | `settledTxChain` = hash chain over `TxLeafHash` |
| **Balance proof circuit** | `src/circuits/balance/balance_circuit.rs` + `balance_pis.rs` | ✅ 70% | Balance PIS exists; needs `settledTxChain` exposure in public inputs |
| **Close workflow & withdrawal** | `src/common/channel.rs:600–765` + `src/circuits/channel/close_circuit.rs` | ✅ 80% | `CloseWithdrawal`, `WithdrawalClaim` exist; missing `finalBalanceProof` explicit binding |
| **State digest/signing** | `src/common/channel.rs:445–470` | ✅ 60% | Signs state; lacks two-part `hash(H1, H2)` structure |

### What's Partially Stubbed (30–60% complete)

| Gap | Current state | abstract2 requirement | Implementation effort |
|-----|-------|---|---|
| **BalanceState as first-class type** | Embedded in `ChannelState` | Separate `BalanceState { encBalances, settledTxChain, stateVersion }` | 1 day: extract struct, add fields |
| **Settlement tracking in state** | Hash chain exists, not integrated | `settledTxChain` field in `BalanceState` | 2 days: wire chain updates into state transitions |
| **H1/H2 two-part signing** | Single `signing_digest()` hash | `hash(H1, H2)` with H2 tag (0 = intra / `tx_tree_root` = inter) | 3–4 days: refactor signature targets, separate intra/inter code paths |
| **BalanceProof ↔ state binding** | No explicit binding | Public inputs expose `settledTxChain`; L1 matches against state | 2 days: add chain to PIS, L1 verification |
| **Per-member public keys** | Implicit in lattice ops | `RegevPk` per member, explicit in `memberKeys[channel_id]` | 1 day: add to channel structure |

### What's Absent (0% complete)

| Component | Where in abstract2 | Implementation blocker? |
|-----------|---|---|
| **`channelTxZKP` (intra-channel range proof)** | §2.2, §3.2.1, §3.2.3 | **High** — needed to prevent negative-balance attacks (M5) |
| **`channelUpdateZKP` explicit structure** | §2.3, §3.4 | **Medium** — lattice binding verifier exists but not structured as distinct proof type |
| **Explicit `TxLeafHash` structure** | §2.3 (txLeafHash = hash of senderAddr, senderDelta, recipientAddr, recipientDelta) | **Low** — hash composition is simple |
| **`finalBalanceProof` structure** | §2.4, §3.5.4 | **Low** — WithdrawalClaim exists; just needs naming + L1 matching logic |
| **`withdrawClaimZKP`** | §3.5.4 step 4 | **Low** — withdrawal circuits exist; need per-member ZKP validation in L1 |
| **`lateBalanceProof` separate tracking** | §2.4, §3.5.5 | **Low** — same as balance proofs; separation is in post-close handling |

---

## Implementation Phases

### Phase 1: Structural (1–2 weeks)
**Goal:** Extract `BalanceState` type, add `stateVersion` and `settledTxChain`, expose `RegevPk`.

**Files to modify:**
- `src/common/channel.rs` — extract `BalanceState { encBalances: [LatticeCt; 3], settledTxChain: Nat, stateVersion: Nat }` from `ChannelState`
  - Add `memberKeys[channel_id] = [(Address, RegevPk); 3]` mapping
  - `ChannelState` now contains `latestBalanceState: BalanceState` instead of embedded `channel_balance_root`
- `src/common/channel.rs` — add `ChannelTx { recipient: Address, encAmount: LatticeCt, nonce: Nat }`

**Not blocking:** Proof logic unchanged; just data reshuffling.

**Verification:** `cargo build` on new struct definitions.

---

### Phase 2: Settlement Tracking (1 week)
**Goal:** Wire `settledTxChain` into state transitions. Track settled tx history.

**Files to modify:**
- `src/common/channel.rs` — when applying `ChannelTx` or `Transfer`, update `settledTxChain`:
  - Intra-channel: `settledTxChain' = settledTxChain` (unchanged per spec)
  - Inter-channel: `settledTxChain' = hash(settledTxChain, TxLeafHash)` for both sending and receiving channels
- `src/circuits/balance/balance_pis.rs` — add `settledTxChain: Nat` to `BalancePublicInputs`
- `src/circuits/balance/balance_circuit.rs` — update balance update logic to derive `settledTxChain'` from `TxLeafHash`

**Verification:** Balance proof generation still works; new chain output is determistic from tx history.

**Risk:** All state versions must now track chain updates. Off-by-one errors are easy here — thorough test coverage needed.

---

### Phase 3: Proof Structures (`channelTxZKP` + `channelUpdateZKP`) (2–3 weeks)
**Goal:** Define explicit proof types for intra- and inter-channel balance updates. **This is the highest-risk phase** (needed for M5 attack prevention).

**Files to add/modify:**
- `src/circuits/balance/common/` — new module `channel_update_proof.rs`:
  - `channelUpdateZKP`: proves (senderDelta, recipientDelta) equal/opposite and sum-preserving
  - Exports in constraint form the public inputs (amount, senderDelta.pt, recipientDelta.pt)
- `src/circuits/balance/common/` — new module `channel_tx_proof.rs`:
  - `channelTxZKP`: proves sender's updated encrypted balance ≥ 0 after deduction
  - Soundness relies on correct decryption (A5) and range constraint (A2)
- `src/common/channel.rs` — add proof type fields:
  - `ChannelTx.proof: channelTxZKP` (mandatory)
  - `Transfer` (inter-channel) carries both proof types implicitly in `TxAux`

**Critical checklist:**
- [ ] `channelTxZKP` soundness: can the circuit be fooled into accepting a negative post-deduction balance?
- [ ] `channelUpdateZKP` soundness: can delta values be swapped or negated post-proof?
- [ ] Non-negativity range: what's the field modulus for Regev plaintexts? Guard against wraparound.
- [ ] All three range proofs (`channelTxZKP`, `channelUpdateZKP`, existing `balanceProof`) compose correctly in aggregate solvency checking.

**Verification:** Each proof independently correct; test with:
- Happy-path channel transfers and inter-channel sends
- Adversarial inputs (negative amounts, swapped deltas, balance wrap-around attempts)

**Risk: CRITICAL** — M5 attack (negative-component overdraft crowding out honest members' withdrawals) is only closed here. Incomplete implementation = broken security guarantee.

---

### Phase 4: H1/H2 Signing & L1 Verification (1–2 weeks)
**Goal:** Separate intra-channel and inter-channel signing via two-part `hash(H1, H2)` structure. Update L1 close/challenge logic.

**Files to modify:**
- `src/common/channel.rs` — refactor `signing_digest()`:
  - `H1 = hash(encBalances, settledTxChain, stateVersion)` (unchanged data, just reparameterized)
  - `H2 = 0` for intra-channel / `H2 = tx_tree_root` for inter-channel
  - Signed message = `hash(H1, H2)`
- `src/circuits/channel/state_update_verifier.rs` — update state transition constraint:
  - Verify signed message = `hash(H1, H2)` (not just H1)
  - Enforce `H2` matches the operation type (intra ⇒ 0, inter ⇒ root)
- `contracts/src/IntmaxRollup.sol` / `ChannelSettlementManager.sol` — L1 close/challenge:
  - When accepting `BalanceState` submission: verify signature over `hash(H1, H2)`
  - When checking `finalBalanceProof`: match `proof.publicInputs.settledTxChain == state.settledTxChain`
  - Reject proof with mismatched chain

**Verification:** 
- Test both `H2 = 0` (intra-channel proof) and `H2 = tx_tree_root` paths
- L1: verify rejects proof with wrong `settledTxChain`

**Risk:** Moderate. Two-part hash is a refactoring; existing signing logic mostly preserved. Main risk is inconsistency (sign H1 in one place, verify against H1+H2 elsewhere).

---

## Risk & Mitigation Map

### High-risk areas

1. **Phase 3: `channelTxZKP` soundness (M5 prevention)**
   - **Risk:** Incomplete range constraint allows negative post-deduction balance → close-boundary attack
   - **Mitigation:** Extensive adversarial test suite; have security team review proof constraints before merging

2. **Phase 2: Settlement chain correctness**
   - **Risk:** Off-by-one in chain updates → state/proof mismatch → L1 rejects valid close
   - **Mitigation:** Property-based tests: `forall histories, settledTxChain(history) == hash-chain-fold(history)`

3. **Phase 4: H2 tag consistency**
   - **Risk:** Sign H1 but verify H1+H2 (or vice versa) → signature verification bypass
   - **Mitigation:** Explicit test: create a state with both H2=0 and H2=root forms, sign both, verify cross-signature fails

### Medium-risk areas

- **Lattice wraparound in proofs** (Phase 3): Regev plaintext space is finite; overflow attack on balance range checking. Mitigation: explicit modulus guards in circuit, test against max values.
- **BalanceProof chain binding edge case** (Phase 4): What if channel 0 has chain C and channel 1 submits proof from channel 0 with chain C? Mitigation: channel_id is part of the challenge, not just the chain.

### Low-risk areas

- Phase 1 structural changes: straightforward refactoring, can be tested independently
- Phase 4 H2 tag: separated concerns, can verify independently in UT and integration tests

---

## Implementation Sequence Recommendation

**Tight coupling (Phase 1 → Phase 2):** BalanceState type must exist before chain tracking makes sense.

**Decoupled from 1–2 (Phase 3):** Proof structures can be written in parallel but should NOT be merged before 1–2 (stubs in BalanceState referring to channel updates).

**Depends on all (Phase 4):** H1/H2 signing can start in parallel; L1 verification must wait for Phase 2 (settledTxChain in PIS) to be final.

**Critical path:** 1 → 2 → (3 + 4 in parallel) = **4–5 weeks minimum for a careful, well-tested rollout.**

---

## Reference: File Locations & Ownership

**Structural (Phase 1):**
- `src/common/channel.rs` ← BalanceState extract, RegevPk, ChannelTx
- `src/common/transfer.rs` ← Transfer witness updates (TxLeafHash)

**Settlement tracking (Phase 2):**
- `src/circuits/balance/balance_pis.rs` ← settledTxChain PIS field
- `src/circuits/balance/balance_circuit.rs` ← chain derivation logic
- `src/utils/hash_chain/mod.rs` ← existing, no changes needed (reuse for `TxLeafHash` folding)

**Proofs (Phase 3):**
- `src/circuits/balance/common/channel_update_proof.rs` ← NEW
- `src/circuits/balance/common/channel_tx_proof.rs` ← NEW
- `src/circuits/channel/state_update_verifier.rs` ← integrate proofs

**Signing & L1 (Phase 4):**
- `src/common/channel.rs` ← refactor signing_digest (H1/H2)
- `src/circuits/channel/state_update_verifier.rs` ← verify H1/H2 signature
- `contracts/src/IntmaxRollup.sol` ← close/challenge L1 logic
- `contracts/src/ChannelSettlementManager.sol` ← if exists, finality/burn logic

---

## Testing Strategy

Each phase should have:
- **Unit tests** (phase-specific circuits/types)
- **Integration tests** (full flow with all phases)
- **Adversarial tests** (attack scenarios, e.g., negative-amount channels for Phase 3)
- **L1 verification** (Phase 4: test L1 rejects invalid proofs)

Key test suites:
- `tests/channel_balance_state.rs` ← Phase 1 & 2 structure + chain correctness
- `tests/channel_tx_zk_proof.rs` ← Phase 3 range proof soundness
- `tests/channel_update_zk_proof.rs` ← Phase 3 inter-channel transfer proof
- `contracts/test/ChannelSettlementManager.t.sol` ← Phase 4 L1 verification

---

## Known Unknowns & Follow-ups

1. **Lattice modulus & wraparound:** What is the Regev plaintext space? Where are overflow checks?
   → Needed for Phase 3; consult with cryptography team.

2. **Bloom of proof complexity:** Will bundling `channelTxZKP` + `channelUpdateZKP` + `balanceProof` into one close proof cause circuit bloat?
   → Research in Phase 3; may need to split into separate circuits if witness/constraint ratio explodes.

3. **Backward compatibility:** Should v2 co-exist with v1 channels, or hard-cut?
   → Affects Phase 4 L1 contract design; decide before implementation.

4. **WebGPU GPU acceleration:** Can WASM Merkle hashing (used in `settledTxChain` derivation) benefit from `gpu_merkle` feature?
   → Noted in abstract2.md as pending; affects Phase 2 WASM build.

---

## Conclusion

**Short answer:** The implementation can follow a 4-phase approach mapping directly to abstract2.md § numbers. No architectural rewrite needed; existing lattice and hash-chain infrastructure fits. The main work is **proof compositional refinement** (Phase 3, M5 prevention) and **structural wiring** (Phases 1–2, settling chain integration).

**Confidence:** High (80+%) for Phases 1, 2, 4. **Medium (60%)** for Phase 3 proof soundness — this is the security-critical path and should undergo independent cryptographic review before merge.

Estimated delivery: **End of July 2026** for a full, audited rollout.
