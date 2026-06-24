# intmax3-zkp Security Audit Report

**Report ID:** audit622  
**Date:** 2026-06-22  
**Repository:** intmax3-zkp  
**Focus:** Fund solvency and system liveness; forged-proof resistance where applicable

---

## Executive Summary

This report consolidates a multi-pass review of the intmax3-zkp implementation across three layers:

1. **Smart contracts** (`ChannelSettlementManager.sol`, `ChannelSettlementVerifier.sol`, `IntmaxRollup.sol`)
2. **Channel / protocol implementation** (Rust wallet, CLI, native transition verifier)
3. **ZKP circuits** (Plonky2 recursive circuits under `src/circuits/`)

**Cross-channel fund theft:** No CRITICAL path was identified in contract or protocol logic that would let an attacker drain rollup escrow or pull more ETH from `ChannelSettlementManager` than `receivedChannelFunds` allows. Rollup `totalEscrowed`, manager payout caps, and nullifier CEI are well-designed and backed by adversarial tests.

**Intra-channel and integration risks:** Several HIGH and MEDIUM issues remain—most notably wallet persistence gaps for the settled-tx accumulator, incomplete snapshot verification, genesis fund truncation, documented withdrawal-claim amount binding residuals at the contract comment layer, and architectural gaps in the ZKP stack (channel transitions not proved in Plonky2, no global solvency proof at close).

**ZKP forged proofs:** Legacy balance / validity / withdraw Plonky2 circuits appear sound for their stated statements. Channel v2 close and claim circuits include Decryption Stage 2 (amount bound to ciphertext via `decryption_gadget`). The largest ZKP-level gaps are architectural: daily channel fund transitions are native/off-circuit, and `channel_fund_amount` is not tied to the sum of decrypted slot balances.

---

## Scope

### In Scope

| Area | Paths / Components |
|------|-------------------|
| Smart contracts | `contracts/src/ChannelSettlementManager.sol`, `ChannelSettlementVerifier.sol`, `IntmaxRollup.sol`, related Foundry tests |
| Protocol / wallet | `src/wallet_core.rs`, `src/wasm_wallet.rs`, `src/bin/channel_member.rs`, `src/common/channel.rs` |
| Native transition verifier | `src/circuits/channel/state_update_verifier.rs` (protocol semantics, not Plonky2) |
| ZKP circuits | `src/circuits/{channel,balance,withdraw,validity}/`, `decryption_gadget.rs`, `src/utils/wrapper.rs` |

### Out of Scope

- Low-level cryptographic primitive implementations (Regev STARK BabyBear core, Poseidon, SPHINCS+ internals) beyond circuit gadgets that embed them
- MLE/WHIR PCS cryptographic soundness (wrapper is a thin passthrough)
- BP censorship, MEV, off-chain P2P availability
- Production VK deployment verification (noted as operational dependency)

---

## Methodology

- Manual code review of primary paths (close, inter-channel send/receive, withdrawal, validity finalization, claims)
- Cross-reference with in-repo threat models (`tasks/phase-b-claims-threat-model.md`, `tasks/decryption-subphase-design.md`, `tasks/wallet-threat-model.md`, `architecture-audit/detail2.md`)
- Verification of SECURITY / RESIDUAL comments in circuit and contract code
- Review of adversarial Foundry tests (`ChannelSettlementAdversarial.t.sol`, `ChannelSettlementInvariant.t.sol`, circuit negative tests)

---

## Part A — Smart Contracts

### A.1 What Is Sound

| Mechanism | Location | Property |
|-----------|----------|----------|
| Rollup escrow ceiling | `IntmaxRollup.sol` — `totalEscrowed` | Deposits increment; `withdrawNative` decrements with underflow revert |
| Proof-bound payouts | `IntmaxRollup.sol` — `withdrawNative` | `ws[]` re-folded to `pis_hash`; amount/recipient not caller-declared |
| Rollup nullifiers | `IntmaxRollup.sol` | `withdrawalNullifierUsed` check-then-set per leaf |
| Manager cross-channel cap | `ChannelSettlementManager.sol:1002-1004` | `totalCreditedOut + amount ≤ receivedChannelFunds` |
| Accrual cap | `ChannelSettlementManager.sol:900-903` | `totalWithdrawn ≤ finalizedChannelFundAmount` (shared pool) |
| Pull-before-pay | `ChannelSettlementManager.sol` | Claims accrue credits; ETH only after `pullChannelFunds` |
| `receivedChannelFunds` source | `ChannelSettlementManager.sol:514-516` | Only rollup `registry.withdraw()` delta; stray `receive()` rejected |
| Member-set binding | Constructor + close proof | `MemberSetMismatch` / in-circuit `member_set_commitment` |
| Cancel member binding | `cancelClose` | Manager injects `registeredMemberSetCommitment()`, not caller field |
| Post-close nullifier | `ChannelSettlementManager.sol` | `_deriveSharedNativeNullifier` recomputed on-chain |
| VK fail-closed | `ChannelSettlementVerifier.sol` | Revert until VK set; `degreeBits == 0` rejected |
| Disabled forgeable paths | `submitSpecialClose`, `submitLateOutgoingDebitCorrection` | Hard revert |

### A.2 Findings

#### A-H1 — Intra-channel over-claim via withdrawal-claim `amount` (documented residual)

| Field | Value |
|-------|-------|
| **Severity** | HIGH (intra-channel fairness; not cross-channel theft) |
| **Files** | `ChannelSettlementVerifier.sol:419-423`, `783-784`; `ChannelSettlementManager.sol:867-915` |

**Issue:** Contract comments state Option D: `amount` is a PI limb but not bound to decrypted ciphertext at the Solidity binding layer. A colluding member could accrue up to `finalizedChannelFundAmount`, disadvantaging co-members.

**Mitigation in place:** Cross-channel theft blocked by `receivedChannelFunds`; per-channel cap on `totalWithdrawn`.

**Note:** Rust `withdrawal_claim_circuit.rs` implements Decryption Stage 2 in-circuit. End-to-end security depends on the deployed VK matching the current circuit. See Part B.

---

#### A-H2 — Wrong settlement manager deployment (operational)

| Field | Value |
|-------|-------|
| **Severity** | HIGH if mis-deployed |
| **Files** | `ChannelSettlementManager.sol:421-424`, `518-557` |

**Issue:** `registry` and `channelId` are deployer-supplied. Users must verify `registry()` and `channelId()` before funding. Phishing deploy could route rollup payouts to an attacker-controlled manager.

**Mitigation:** Constructor asserts member/BP alignment when registry matches.

---

#### A-M1 — Challenge deadline resets on every replacement (liveness griefing)

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Files** | `ChannelSettlementManager.sol:744-762` |

**Issue:** Each successful challenge sets `challengeDeadline = block.timestamp + challengePeriod`. Ping-pong with marginally newer co-signed states can delay `finalizeClose` indefinitely while `ClosePending` freezes native sends.

---

#### A-M2 — Single-member `requestClose` freezes channel

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Files** | `ChannelSettlementManager.sol:670-678` |

**Issue:** Any registered member recipient can move channel to `ClosePending` (minimum 600s grace). Intentional two-step design; disgruntled member can repeat after `cancelClose`.

---

#### A-M3 — Accrual vs payout mismatch (first-claimer wins)

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Files** | `ChannelSettlementManager.sol:1000-1007` |

**Issue:** When `Σ withdrawalCredits > receivedChannelFunds`, early claimers get paid; later claimers hit `WithdrawalCapExceeded` with no partial payout. ETH may remain stranded in manager.

**Tests:** `ChannelSettlementAdversarial.t.sol` — `test_C18_intent_overdeclares_received_cap_wins`.

---

#### A-M4 — Incomplete VK initialization in deploy scripts

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM (liveness bricking) |
| **Files** | `DeployClose.s.sol`, `DeployCloseCli.s.sol` |

**Issue:** Some deploy scripts omit `initializePostCloseClaimVk` / `initializeCancelCloseVk`. Paths revert fail-closed until deployer completes init.

---

#### A-M5 — Delegate payout bindings not registry-verified

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM (trust model) |
| **Files** | `ChannelSettlementManager.sol:616-626` |

**Issue:** Delegate `pkG → recipient` mappings are deployer-asserted. Documented trust on deployer.

---

#### A-L1 — Over-pull surplus ETH locked in manager

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Files** | `ChannelSettlementManager.sol:467-478` |

**Issue:** If rollup pays more than `finalizedChannelFundAmount`, surplus ETH has no extraction path.

---

#### A-L2 — Stale contract comments

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Files** | `ChannelSettlementVerifier.sol` header, limb count comments |

**Issue:** Header still says "stub verifier" in places; `CLOSE_PI_LEN = 95` vs legacy "87 limb" references.

---

---

## Part B — Protocol / Wallet Implementation

### B.1 What Is Sound

| Mechanism | Location |
|-----------|----------|
| Real co-sign crypto | `verify_all_signatures` — SingleSig proofs over IMCH digest |
| In-channel send | `verify_send_transition` — E-1, A11 hash-sig, trusted-record binding |
| Inter-channel credit gate | `verify_inter_channel_credit_transition` — N-of-N A state, E-2, TxV2 inclusion |
| Atomic CLI inter-channel | `cosign-inter-transfer` — both legs validated before persist |
| Replay ledgers (CLI) | `spent_tx_hashes` / `applied_tx_hashes` in `CliState` |
| Genesis fail-closed backing | `sign_state_if_backed` / `verify_channel_backing` |
| Close preconditions | `CloseIntent::new` requires `unallocated_confirmed_incoming == 0` |
| Native transition rules | `state_update_verifier.rs` — fund decrease on send, chain push, H2≠0, D3 `pending_adds` |

### B.2 Findings

#### B-H1 — Settled-tx accumulator never persisted after inter-channel ops

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Files** | `wallet_core.rs:1300-1304`, `1533-1541`; `wasm_wallet.rs:451-492`; `channel_member.rs:2162-2169` |

**Issue:** `build_inter_channel_send` returns `settled_tx_accumulator`, but `wallet_finalize`, `cosign-inter-transfer`, and `cmd_finalize` update only `snapshot.state`. `ChannelSnapshot.settled_tx_accumulator` stays at genesis empty tree.

**Impact:** Second inter-channel send uses wrong frontier; signed H1 `settled_tx_accumulator_root` may desync from persisted tree; post-close inclusion proofs fail or prove wrong history.

---

#### B-H2 — `verify_snapshot` does not bind accumulator tree to signed root

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Files** | `wallet_core.rs:760-828` |

**Issue:** Missing check:

```text
Bytes32::from(snapshot.settled_tx_accumulator.get_root())
    == snapshot.state.balance_state.settled_tx_accumulator_root
```

Also missing: `record.member_count` / `delegate_count` vs `balance_state`; `record.channel_id` vs `state.channel_id` on import.

---

#### B-H3 — Genesis `channel_fund` u32 truncation

| Field | Value |
|-------|-------|
| **Severity** | HIGH when `fund_amount > 2³²-1`; LOW otherwise |
| **Files** | `wallet_core.rs:646`; `channel_member.rs` deposit paths |

**Issue:**

```rust
amount: U256::from(fund_amount.min(u32::MAX as u64) as u32),
```

Inter-channel conservation uses full `u64_to_u256`; genesis/close cap path truncates silently.

---

#### B-M1 — M7: Signed-but-unsettled inter-channel close race

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM–HIGH |
| **Files** | `architecture-audit/detail2.md` (M7); `wallet_core.rs:1587-1590`; `channel_member.rs:562-607` |

**Issue:** Members can sign post-debit state (`h2_tag = tx_tree_root`) before L1 absorbs the small block. Wallet layer does not require L1 inclusion witness before co-signing close on `h2_tag ≠ 0` states.

---

#### B-M2 — Replay protection not in `wallet_core` / WASM

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Files** | `wallet_core.rs:1273-1276` |

**Issue:** `verify_inter_channel_credit_transition` does not maintain consumed-tx ledger. Custom integrators bypassing CLI atomic flow get no replay protection.

---

#### B-M3 — Non-atomic A/B filesystem commit

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Files** | `channel_member.rs:2162-2169` |

**Issue:** Crash after A `save_state` but before B `save_state_at` can strand value until manual recovery.

---

#### B-M4 — Stale balance attestation blocks close after inter-channel

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM (liveness) |
| **Files** | `channel_member.rs:587-607` |

**Issue:** `cmd_close` uses genesis `balance_proof`. After inter-channel activity, `settled_tx_chain` advances; close circuit requires matching chain → proof generation fails until fresh attestation wiring exists.

---

#### B-M5 — Optimistic co-sign without full verification

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM (misuse) |
| **Files** | `channel_member.rs:1848-1858` |

**Issue:** `cmd_cosign` advances head without `verify_all_signatures` before persist. Safe for demo; risky for multi-party deployments.

---

#### B-L1 — WASM `can_send` weak witness binding

| Field | Value |
|-------|-------|
| **Severity** | LOW–MEDIUM |
| **Files** | `wasm_wallet.rs:218-228` |

**Issue:** `can_send` does not prove witness matches current ciphertext digest after import/refresh edge cases.

---

---

## Part C — ZKP Circuits

### C.1 Architecture

```text
Plonky2 recursive circuits          Native / external (NOT Plonky2)
────────────────────────────        ────────────────────────────────
Validity (block/deposit/reg chains)  state_update_verifier.rs
Balance IVC                          E-1 / E-2 Regev STARKs
Withdrawal chain                     N-of-N member signatures
Close / Claim / CancelClose
```

Channel fund transitions, homomorphic slot updates, and accumulator push correctness are **not proved in any Plonky2 circuit**. Security relies on co-signer honesty + native verifier + external Regev proofs.

### C.2 What Is Sound

| Circuit family | Key properties |
|----------------|----------------|
| **Validity** | `keccak256(ValidityPublicInputs)`; conditional deposit/reg sub-proofs; `bp_sig_chain` gates ListCircuit on computed accumulator (not prover flag) |
| **Balance IVC** | Spend borrow=0; receive nullifier insert + `assert_one(is_valid)`; switch-board one-hot |
| **Withdrawal** | WDR-CRIT-001 canonical `public_state`; amount from Merkle-bound transfer; `ADDRESS_TAG` recipient |
| **Close** | H1/IMCH/IMCI recompute; `unallocated=0`; N-of-N ListCircuit; pk_g distinctness; member_set_commitment |
| **Withdrawal claim** | Decryption Stage 2: pk bound to H1 `regev_pk_digests`; `decryption_core` binds amount |
| **Post-close claim** | tx_hash recomputation + accumulator Merkle inclusion + decryption |
| **Cancel close** | `revived_state_version > close.final_state_version`; era fence; member_set binding |

Adversarial circuit tests include `withdrawal_claim_circuit_rejects_over_claim`, `withdrawal_claim_circuit_rejects_fake_pk_for_victim_ct`, `post_close_claim_circuit_rejects_over_claim`.

### C.3 Findings

#### C-ARCH1 — Channel state transitions not in Plonky2

| Field | Value |
|-------|-------|
| **Severity** | HIGH (architectural) |
| **Files** | `state_update_verifier.rs`; `close_circuit.rs:582-592` |

**Issue:** Close circuit binds balance proof only to `channel_id` + `settled_tx_chain`. Fund arithmetic, ciphertext transitions, and E-2 are off-circuit.

---

#### C-H1 — Accumulator insertion not circuit-proven

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Files** | `state_update_verifier.rs:1107-1145` |

**Issue:** `require_accumulator_push` is native co-signer only. Close includes root in signed H1; post-close proves inclusion against that root—but push correctness is signature-attested, not ZK-proven.

---

#### C-H2 — No global solvency: `channel_fund` ≠ Σ decrypted balances

| Field | Value |
|-------|-------|
| **Severity** | HIGH (collusion) |
| **Files** | `close_circuit.rs` |

**Issue:** `channel_fund_amount` in IMCH/IMCI but not tied to sum of slot ciphertexts or decrypted amounts. Per-slot claims are sound individually; aggregate L1 payout can exceed true deposits if members collude on inflated `channel_fund_amount`.

---

#### C-H3 — `decryption_gadget.rs` hand-rolled lattice relation

| Field | Value |
|-------|-------|
| **Severity** | HIGH (trust boundary) |
| **Files** | `decryption_gadget.rs`; `tasks/decryption-subphase-design.md` |

**Issue:** Highest-risk in-circuit component. MUST-FIX #1–#7 implemented; adversarial tests exist. Full soundness depends on negacyclic indexing proof (crypto primitive internals out of scope).

---

#### C-M1 — F3-A: `aux_data` semantics off-circuit

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Files** | `send_tx_circuit.rs:285-289`; `receive_transfer_circuit.rs:496-504` |

**Issue:** Circuit folds Merkle-bound `aux_data` into `settled_tx_chain` but does not prove `aux_data == tx_leaf_hash(inter_channel_tx)`.

---

#### C-M2 — `WithdrawalCircuit` partial `ExtendedPublicState` binding

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Files** | `withdrawal_circuit.rs:190-194` |

**Issue:** Only `ext_public_state.inner` connected to chain `public_state`. Hash-chain limbs are witness-supplied; L1 `finalizedStateRoots` compensates.

---

#### C-M3 — Balance sub-circuit IVC wiring asymmetry

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Files** | `send_tx_circuit.rs:226`; `single_withdrawal_circuit.rs` (cyclic) |

**Issue:** Sub-circuits use `verify_proof` with VD from same proof PIs; withdrawal uses `add_proof_target_and_verify_cyclic`. Practical forgery unlikely with fixed `balance_cd`; style inconsistency.

---

#### C-M4 — Validity: one signature fold per block

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Files** | `update_channel_tree.rs:962-966` |

**Issue:** Second channel update in same block would leave second signature unfolded. Safe under current 1-channel-per-small-block protocol.

---

#### C-L1 — Stale module comments in `withdrawal_claim_circuit.rs`

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Files** | `withdrawal_claim_circuit.rs:3-5`, `392-395` |

**Issue:** Header says decryption deferred; lines 21-28 and 339-378 implement Decryption Stage 2.

---

#### C-L2 — Withdrawal nullifier `block_number` not tied to `public_state.block_number`

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Files** | `single_withdrawal_circuit.rs` |

**Issue:** `send_leaf.cur` sets nullifier block number without explicit bind to withdrawal `public_state`. Griefing/accounting confusion, not amount inflation.

---

---

## Cross-Layer Attack Matrix

| Attack | Contracts | Protocol | ZKP circuits |
|--------|-----------|----------|--------------|
| Cross-channel fund theft | **Blocked** (`receivedChannelFunds`, `totalEscrowed`) | N/A | N/A |
| Rollup double-spend | **Blocked** (nullifiers) | N/A | N/A |
| Intra-channel unfair withdrawal split | **Partial** (fund cap only; H1 comment) | Co-signer trust | Per-slot decryption sound |
| Forged validity finalization | **Blocked** (PI + L1) | N/A | **Sound** |
| Withdraw without prior send | **Blocked** | N/A | **Sound** (Merkle) |
| Post-close double-claim | **Blocked** (nullifier) | N/A | **Sound** (inclusion + decrypt) |
| Inter-channel replay (CLI) | N/A | **Blocked** (ledgers) | N/A |
| Inter-channel replay (WASM/custom) | N/A | **Gap** (B-M2) | N/A |
| 2nd inter-channel / post-close | N/A | **Broken** (B-H1) | Inclusion assumes correct root |
| Close on unsettled debit (M7) | Challenge game | **Gap** (B-M1) | Close does not require L1 inclusion |
| Global channel solvency at close | Cap on declared fund | Co-signer trust | **Not proved** (C-H2) |
| Channel transition forgery (ZK-only verifier) | N/A | Native verifier | **Not in ZK** (C-ARCH1) |

---

## Recommendations

### P0 (Critical path)

1. **Persist `settled_tx_accumulator`** in `wallet_finalize`, `cosign-inter-transfer`, and `cmd_finalize` after every inter-channel operation.
2. **Extend `verify_snapshot`** with accumulator root reconciliation and record/state consistency checks.
3. **Fix genesis fund truncation** — use `u64_to_u256(fund_amount)` consistently.
4. **Document or close M7** — require L1 inclusion witness before close on states with `h2_tag ≠ 0`.

### P1 (High value)

5. **Channel transition ZK** — Plonky2 transport proof recursively bound in close, or explicit threat-model acceptance.
6. **Global solvency at close** — prove `channel_fund_amount` relates to sum of slot balances (or enforce on L1).
7. **In-circuit accumulator push** or bind close to transport proof with frontier witness.
8. **F3-A in-circuit** — `aux_data == tx_leaf_hash(...)` in balance send path.
9. **Align deployed VKs** with Decryption Stage 2 circuits; update stale Solidity/module comments.

### P2 (Defense in depth)

10. **WithdrawalCircuit** — connect full `ExtendedPublicState` to validity-finalized data.
11. **Balance sub-circuits** — unify on `add_proof_target_and_verify_cyclic`.
12. **Challenge deadline cap** — bound maximum close duration against ping-pong griefing.
13. **Deploy scripts** — initialize all VKs (close, withdrawal-claim, post-close-claim, cancel-close).
14. **Atomic A/B persist** — temp file + rename for inter-channel commit.
15. **Manager tests** — withdrawal nullifier replay, challenge deadline extension.

---

## Severity Summary

| ID | Severity | Layer | Title |
|----|----------|-------|-------|
| B-H1 | HIGH | Protocol | Accumulator not persisted after inter-channel |
| B-H2 | HIGH | Protocol | `verify_snapshot` missing accumulator bind |
| B-H3 | HIGH* | Protocol | Genesis fund u32 truncation |
| A-H1 | HIGH | Contracts | Intra-channel withdrawal amount residual |
| C-ARCH1 | HIGH | ZKP | Channel transitions not in Plonky2 |
| C-H1 | HIGH | ZKP | Accumulator push not circuit-proven |
| C-H2 | HIGH | ZKP | No global solvency at close |
| C-H3 | HIGH | ZKP | `decryption_gadget` trust boundary |
| A-H2 | HIGH† | Ops | Wrong manager deployment |
| B-M1 | MED–HIGH | Protocol | M7 close before L1 settlement |
| A-M1–M5 | MEDIUM | Contracts | Griefing, accrual mismatch, VK deploy, delegates |
| B-M2–M5 | MEDIUM | Protocol | Replay, atomicity, stale attestation, cosign |
| C-M1–M4 | MEDIUM | ZKP | F3-A, ext state, IVC style, validity invariant |
| A-L*, B-L*, C-L* | LOW | Various | Surplus lock, stale docs, nullifier block, WASM |

\*HIGH only when `fund_amount > 2³²-1`.  
†Operational if users verify deployment.

**No CRITICAL cross-channel theft path identified** in reviewed contract and protocol logic.

---

## Limitations

- Cryptographic soundness of Regev STARK (E-1/E-2), MLE/WHIR, and full `decryption_gadget` lattice argument not formally verified in this audit.
- Production VK ↔ circuit alignment assumed operational; not verified against live deployment.
- Lean proofs (`architecture-audit/ChannelSafety*.lean`) provide abstract model assurance under assumptions A1–A6; implementation gaps (M7, bulk transfer) documented separately in spec.

---

## References

- `architecture-audit/detail2.md` — protocol specification; M7 open item
- `architecture-audit/abstract2-1.md` — small-block / bulk transfer model
- `tasks/decryption-subphase-design.md` — decryption gadget design and MUST-FIX list
- `tasks/phase-b-claims-threat-model.md` — claim binding phases
- `tasks/wallet-threat-model.md` — wallet verification obligations
- `contracts/test/ChannelSettlementAdversarial.t.sol` — adversarial contract tests
- `src/circuits/channel/e2e_flow.rs` — channel circuit negative suite

---

*End of report audit622*
