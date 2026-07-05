# Phase 2 — raise MAX_CHANNEL_MEMBERS (full-stack, coordinated Rust + Solidity + circuits + deploy)

Prereq: Phase 1 (A5 O(N²)→O(N·h) in-circuit) is committed (ca1f8c6). This phase raises capacity.

## GATE 0 — target MAX value (decides the whole scope)
- The count fields `memberCount`/`delegateCount` are 8-bit in Solidity
  (`memberAndDelegateCount = (memberCount<<8)|delegateCount`, Manager:1277; `uint8` at
  Verifier:1029, Manager:106, `activeMemberCount/activeDelegateCount` immutable uint8 Manager:460,468).
  → **MAX >= 256 OVERFLOWS uint8** and requires widening to uint16 across Manager/Verifier + the
  close-PI limb encoding (PI 93/94). MAX <= 255 fits uint8 (NO type surgery).
- The iterative `abi.encodePacked` keccak builders (IntmaxRollup:998-1001, 1029-1048) are O(N²)
  memory → block-gas risk at N>=256, severe at 1024. Recommend rewriting with assembly/mstore
  preallocation before ANY N>=256; mandatory for 1024.
- Recommendation: **MAX=255** (3 cosigners + 252 delegates ≈ the requested "~256") to AVOID the
  uint8→uint16 surgery and keep the gas/EIP-170 risk lowest. 256 needs the surgery; 1024 needs
  surgery + the abi.encodePacked rewrite + heavy settlement circuits.

## Task breakdown (after GATE 0)
1. **Rust MAX bump** — `src/constants.rs` MAX + MEMBER_TREE_HEIGHT (= log2(MAX)); apply the
   MAX>32 support (serde-big-array + `std::array::from_fn` at the `[MemberRegEntry; MAX]` Default
   sites) — captured in `.claude/max256.patch` (adapt to the chosen value). Fix the remaining
   MAX-driven test Default site (`channel_reg_chain_processor.rs:115`).
2. **Solidity constants** — IntmaxRollup:444, Verifier:45, Manager:135 (MAX_MEMBER_COUNT) to the
   same value. If >=256: widen the uint8 count fields → uint16 (Manager/Verifier + the close-PI
   limb encoding) and re-derive the PI limb layout.
3. **Commitment consistency (致命)** — `member_set_commitment` (Rust close_member_set_commitment /
   circuit) and `_channelRegHashChain` must byte-match Solidity over the SAME MAX slot count. Update
   the Solidity loops (IntmaxRollup:998, 1029; Verifier:1035) and re-run the cross-check tests.
4. **Solidity gas** — rewrite the iterative `abi.encodePacked` builders (IntmaxRollup:998-1001,
   1029-1048) to preallocate one buffer + mstore (removes the O(N²) memory blowup). Assess whether
   the registration distinctness loop (IntmaxRollup:927-934) needs linearizing at the chosen MAX
   (independent of the circuit's Phase-1 check; borderline-OK at 256, must-fix at 1024).
5. **Circuits / VKs** — all settlement circuits (close, cancel-close [both now O(N·h) after Phase 1],
   withdrawal-claim, post-close-claim) + validity channel_reg_step grow with MAX → regenerate and
   re-pin their VKs. On-chain close PI stays 95 limbs (member set = single keccak) so the VK SCHEMA
   is unchanged, but the VK DIGEST changes → re-pin via the deployer setters.
6. **Fixtures** — regenerate every settlement/validity MLE fixture (close/cancel/withdrawal/
   post-close/lifecycle + validity mle_fixture) — the proof bytes, digests, PI limbs, and the
   keccak commitments all change.
7. **Tests** — Rust (`cargo test --release`, incl the Phase-1 A5 tests + the Rust↔Solidity
   commitment cross-check) + Foundry (`forge test`, incl the bytes32[16]→[N] callers).
8. **EIP-170** — `forge build --sizes`; IntmaxRollup has ~130 B headroom at MAX=16 — verify the
   type-widening/encoding changes don't cross 24,576 B.
9. **Deploy** — redeploy IntmaxRollup + ChannelSettlementVerifier + every per-channel
   ChannelSettlementManager on Sepolia; rebuild the arm64 binary + wasm at the new MAX; ship to the
   testnet + reset state. (This also fixes the currently-broken withdraw path from the MAX=256
   binary vs MAX=16 contracts mismatch.)

## Process (CLAUDE.md)
- Security-critical parts (commitment consistency, any distinctness change, uint16 PI re-encoding)
  get an INDEPENDENT adversarial review before merge.
- Work at each step with tests green; do not deploy until Rust + Foundry + cross-check all pass and
  EIP-170 is verified.

## Status: GATE 0 pending — awaiting target MAX (recommend 255).

---

## Phase 2 REVISED — O(active) settlement re-architecture (owner: flat pad-to-MAX is wasteful; make cost scale with member_count, keep the tree in storage=root)

### Diagnosis (measured: MAX=1024 close = degree19 / ~14.5GB, even for a 2-member close)
Flat 0..MAX drivers in close/cancel (all four settlement circuits share E):
- **E — H1 keccak** over ~17*MAX u32 words (regev_pk_digests+enc_balances+pending_adds, ALL slots). #1 driver, present in close/cancel/withdrawal-claim/post-close.
- **H — A5 distinctness** MAX*height indexed-Merkle inserts (Phase 1's chain, at MAX).
- **G — C' signature fold** MAX Poseidon (redundant: ListCircuit already folds sigs recursively/O(active)).
- **I — member_set_commitment keccak** over 2+MAX*8 words.

### Key de-risking fact
Contract stores `channelMemberSetCommitment[channelId]` ONCE at registration (IntmaxRollup.sol:961) and only READS it on the settlement hot path → no on-chain MAX loop to match; only the final digest VALUE must stay consistent → contract change is registration-only + localized.

### Target design (Option B+)
1. NEW recursive **member-fold** circuit (template: poseidon_sig/list.rs ListCircuit + CyclicChainCircuit): 1 step = 1 active member, accumulating {sig-fold C, member-set commitment M = Poseidon chain over pk_g (replaces the MAX keccak I), distinctness root (one insert/step, replaces H), count n}. Enforces a constant IMCH message across steps. → constructs D/F/G/H/I become O(active). close/cancel then just verify ONE fold proof + bind (M==member_set_commitment PI, n==member_count, message==state_digest).
2. **H1 (E, #1 driver)**: make H1 an O(active) Poseidon chain over the ACTIVE prefix, computed inside the balance proof; settlement circuits READ H1 from the balance-proof PIs instead of recomputing the MAX keccak. Deepest binding → dedicated threat model (H1 anchors settled_tx_chain/state_version/member_count/delegate_count/accum_root).
3. Contract: member-set commitment (registration) → active-prefix Poseidon chain; H1/IMBS definition → active-prefix chain. All settlement VKs + fixtures regenerate.

### Security to preserve (each needs adversarial review)
N-of-N coverage (fold must bind n==member_count so a prover can't fold fewer — the property ListCircuit explicitly does NOT provide), A5 empty-tree start, member_count triple-binding collapse, member-set→registered injectivity (bind n into/alongside M so [a] != [a,pad]), IMCH message binding, H1 anchoring.

### Sequencing
- **2a-i**: standalone recursive member-fold circuit (step + cyclic wrapper) built + proven + tested in ISOLATION (fold N members; duplicate pk_g unprovable; count/message binding). ← START HERE.
- **2a-ii**: integrate into close/cancel (delete G/H/I, verify fold proof, bind outputs) + change member_set_commitment definition (Rust close_member_set_commitment + Solidity registration + cross-check test) + regen fixtures/VK. Measure degree drop.
- **2b**: H1 → balance-proof active chain (E). Measure degree drop to target (2-member close ≈ degree17 / few GB).
- **2c/2d**: full MAX=1024 Solidity (uint16 etc.) + all VK/fixture regen + redeploy.
