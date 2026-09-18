# A-3 main implementation spec: channel close / withdraw-to-L1 / settle lifecycle

Status: **APPROVED (2026-06-20)**. Each implementation phase must pass a dedicated attacker subagent review before work starts (CLAUDE.md §Adversarial).

**Approved decisions (§7):**
1. **Include the on-chain anchor check** (`finalizeClose` requires `finalizedStateRoots(root)`). This changes the Manager bytecode → entails regenerating the close fixtures.
2. **Implement everything now** (all of P1–P6, including post-close-claim and **turning specialClose/lateOutgoingDebit into reverts** = closing off the forgeable stubs).
3. **Liveness grief is only documented** (a sound remedy waits on cross-layer proofs and is handled separately).

## 0. Goal and premises

Make it possible to drive the complete channel lifecycle — **deposit → operation → close → challenge → withdraw → claim** — against a real L1 from the CLI (`channel_member`). Today, `close`/`withdraw`/`settle` are fail-closed stubs (already made safe in A-3).

**Established facts (investigated and attacker-reviewed):**
- The on-chain settlement machinery (`ChannelSettlementManager.sol` / `ChannelSettlementVerifier.sol`) and the close-family circuits (close / withdrawal-claim / post-close-claim / cancel-close) are **already REAL and nearly complete**. `CloseLifecycleE2E` keeps all of these paths green on fixtures.
- What is missing is the **connection layer**: (1) sourcing the real L1 anchor, (2) the wallet_core close builders, (3) the CLI commands, (4) on-chain submission, (5) relay/E2E.
- No new cryptographic primitives are needed. The members' N-of-N co-signatures, the balance proof, and the withdrawal proof all already exist.

## 1. Current state (what is already REAL)

| Layer | State |
|---|---|
| `ChannelSettlementManager`: requestClose / submitCloseIntent / cancelClose / finalizeClose / submitWithdrawalClaim / submitPostCloseClaim / pullChannelFunds / claimWithdrawalCredit | **REAL** |
| state machine: Active → ClosePending → Closed, GRACE=600s / CHALLENGE=86400s | **REAL** |
| payout: `pullChannelFunds` (rollup→manager) → `claimWithdrawalCredit` (to the member), with the global solvency cap `totalCreditedOut ≤ receivedChannelFunds` | **REAL** |
| `ChannelSettlementVerifier`: verifyCloseIntent (95 limbs) / verifyWithdrawalClaim (48) / verifyPostCloseClaim (56) / verifyCancelClose (27), VK set-once | **REAL MLE/WHIR** |
| the close-family circuits + the `test_fixture` witness builders | **REAL** |
| fund custody: `IntmaxRollup.withdrawNative` binds to the finalized state root and satisfies the manager's `pendingWithdrawals` | **REAL** |
| `verifySpecialClose` (C2) / `verifyLateOutgoingDebit` (C3) | **DISABLED stub** (detail2 §H-3; out of scope for this spec. See §3.5 below) |

## 2. Gaps (what this implementation builds)

1. **The real L1-close anchor** (`channel_fund_intmax_state_root`) — currently a zero placeholder.
2. **The wallet_core close builders** — `build_close_full_witness` / close proof generation / `build_withdrawal_claim` / the channel withdrawal proof (recipient=manager).
3. **CLI commands** — `close` / `settle` (=finalize) / `withdraw` / `claim` (plus `cancel-close` for the challenge).
4. **On-chain submission** — calling the Manager / IntmaxRollup via `cast send`.
5. **Relay endpoints + a real E2E** (anvil, CLI-driven rather than fixture-driven).

## 3. Design

### 3.1 The L1-close anchor (`channel_fund_intmax_state_root`) — attacker review conclusions

**Conclusion (Option B, verified by an attacker subagent):** this value is a **member-signed value internal to the channel**; it is only keccak-folded into IMCH/IMCL/IMCI. The circuits never cross-check it against an external rollup root. Fund safety is **fully** guaranteed by the **separate withdrawal proof** path (which verifies `ext_public_state_commitment` against `IntmaxRollup.finalizedStateRoots[]` + a nullifier).
- Zero anchor: **SAFE** (over/double-withdraw is impossible; the payout is gated by the withdrawal proof).
- Forged anchor: **SAFE** (IMCH changes, so the members' list proof does not pass = a third party cannot forge it. Even if a member signs it themselves, the payout is gated separately).
- double-backing: **SAFE** (deposit nullifier + settled_tx_chain separation + the manager's solvency cap).

**Adopted approach:**
- **(required) source the real value**: at `setup-backing` time, fetch `IntmaxRollup.latestFinalizedStateRoot()` over RPC and store it in `ChannelBacking.intmax_state_root` (removing the placeholder). Flow it into `ChannelFund.intmax_state_root` during genesis assembly. → This corrects the semantics and satisfies a precondition for future post-close functionality.
- **(recommended, low cost) on-chain consistency check**: in `finalizeClose()`, if `finalizedChannelFundIntmaxStateRoot != 0`, require `IntmaxRollup.finalizedStateRoots(root)` (`CloseFundAnchorNotFinalized`). A defensive measure against future misuse. **Note that this does not change the IntmaxRollup bytecode, but it does change the Manager bytecode → the close fixtures must be regenerated** (the same metadata-hash property as in A-2). Whether to adopt it is to be decided in §7.

### 3.2 The wallet_core close builders (new pub fns)

All of this is wiring of existing machinery. No new cryptography.

| Function | Input (already held by the wallet) | Output | Helpers (existing) |
|---|---|---|---|
| `build_close_intent(state, close_nonce, burn_tx_hash, snapshot_medium_block_number)` | a signed `ChannelState` | `ChannelCloseWitness` (intent+close_tx) | `CloseIntent::new` |
| `build_close_full_witness(close_witness, member_auth, balance_proof, member_sigs)` | record.member_pk_gs, `channel_attestation.bin` (= the balance proof), the members' IMCH co-signatures | `ChannelCloseFullWitness` | fold the N signatures with `ListCircuit::prove_append` |
| `prove_close(full_witness) → MleProof JSON + CloseProofFields` | the above | close MLE proof + descriptor | the same wrap+MLE as `generate_close_fixture.rs` |
| `build_channel_withdrawal(state, manager_addr, finalized_root)` | a signed state, the manager address, the finalized root | a withdrawal proof (recipient=manager) | the existing withdraw circuit (the withdrawNative path) |
| `build_withdrawal_claim(final_balance_state, member_index, regev_sk, recipient)` | the finalized balance, the member's regev_sk | `WithdrawalClaim` + E-3 proof + MLE | the existing withdrawal_claim circuit |
| (optional/later) `build_post_close_claim(...)` / `build_cancel_close(revived_state, close_intent)` | — | post-close / cancel MLE | existing circuits |

**The key practical issue**: the close proof requires that **the N-of-N members co-sign the IMCH digest** (there is no threshold). This is the same machinery as `cosign`, and in a configuration where the relay owns all members (the current delegate demo) they can be collected in a single command. **If even one member refuses, the close cannot be built** (liveness is a matter for the cancel/special-close side → §3.5).

### 3.3 CLI command spec

| Subcommand | Role | Main processing | On-chain |
|---|---|---|---|
| `close <manager_addr>` | generate the close intent | read the final state, collect the N-of-N IMCH co-signatures, generate the close MLE with `prove_close` → `close_intent.json` + `close_intent_mle.json`. Pin the freeze nonce / cancel floor in a durable checkpoint and call `requestClose` | `cast send Manager.requestClose(uint64,uint64)` → `submitCloseIntent(intent, mleProof)` |
| `cancel-close <manager_addr> <revived_state.json>` | challenge: withdraw the close with a newer signed state | `build_cancel_close` → MLE | `cast send Manager.cancelClose(req, mleProof)` |
| `settle <manager_addr>` | finalize after the challenge period | pin and re-validate the pending digest / request generation via the durable checkpoint | `cast send Manager.finalizeCloseGuarded(bytes32,uint64)` |
| `withdraw <rollup_addr> <manager_addr>` | move funds from the rollup to the manager | `build_channel_withdrawal` (recipient=manager, finalized root) → withdrawal proof | `cast send IntmaxRollup.withdrawNative(...)` → `Manager.pullChannelFunds()` |
| `claim <manager_addr> <member_slot>` | a member claims and withdraws their share | `build_withdrawal_claim` (the member's regev_sk) → MLE | `cast send Manager.submitWithdrawalClaim(claim, mleProof)` → `claimWithdrawalCredit(bytes32 withdrawalNullifier)` |

- State files: `close_intent.json` / `close_intent_mle.json` / `withdrawal_claim_*.json` are written to the channel directory (same schema as the existing fixtures).
- Secret-key handling follows CLAUDE.md (expand `.claude/priv` in the shell; never put it in front of the assistant).

### 3.4 Relay endpoints (optional, for E2E)

`/api/close` (collect the N-of-N co-signatures and generate the close MLE), `/api/settle`, `/api/withdraw`, `/api/claim`. On the premise that the relay owns every channel, each one launches the CLI with a cwd switch (the same shape as the existing `/api/inter/send`).

### 3.5 Out of scope (explicitly)

- **specialClose (C2) / lateOutgoingDebit (C3)**: detail2 §H-3 says "forgeable stub → DISABLE". This implementation **does not implement them**. The right (safe-side) move is instead to **turn the entry points into reverts** in a separate PR, closing off the forgeable stubs. This spec says: do not call them, do not touch them.
- **post-close-claim**: the circuit is REAL but it is not needed for the happy-path close. Later in the phase sequence, or in a separate PR.

## 4. Threat model (CLAUDE.md checklist)

| Threat | Mitigation | State |
|---|---|---|
| a third party forges a close | the close circuit verifies the N-of-N members' IMCH signatures with ListCircuit. A non-member key is rejected by the member_set_commitment mismatch (Findings E/D) | existing REAL |
| closing with a stale state (freezing an old balance) | the challenge period (86400s) + `cancelClose` (REAL): presenting a more recent N-of-N-signed state withdraws it. `revived_version > close_version` is enforced by the circuit (Finding B) | existing REAL |
| over-withdraw / double-withdraw | the used-nullifier map + `totalWithdrawn ≤ fund` + `totalCreditedOut ≤ receivedChannelFunds` (capped by the amount actually received) | existing REAL |
| zero/forged anchor | the §3.1 attacker conclusion = funds are safe (a separate withdrawal proof is the gate). Using the real value is about semantics + future defense | made real in this implementation |
| substituting the payout destination | `registeredRecipientOf[pkG]` is fixed at registration time, binding member pk→recipient 1:1 | existing REAL |
| close liveness grief (one member refuses and close becomes impossible) | **residual risk**: because N-of-N is mandatory, a malicious member can obstruct the close. special-close (the intended remedy) is DISABLED. → documented as a known limitation; to be designed separately | design issue (documented) |
| manipulating the challenge-period time on anvil (tests) | controlled with `vm.warp` / anvil `evm_increaseTime` | a testing facility |
| baking the manager address into fixtures (the CREATE2 metadata-hash fragility) | in production, use the real address of a normally deployed manager (CREATE2 is test-only). Any change to the Manager bytecode (such as the §3.1 recommended check) requires regenerating the close fixtures | caveat |

**Before starting**: immediately before implementing each phase, run a dedicated attacker subagent and confirm the above plus any new findings (mandatory per CLAUDE.md).

## 5. Phase breakdown (falsifiable deliverables)

- **P1 — the real anchor**: `setup-backing` fetches `latestFinalizedStateRoot()` → stores it in `ChannelBacking.intmax_state_root` and propagates it into genesis. Placeholder removed. (Optional) add the on-chain check in `finalizeClose` → adoption decided in §7. **Verification**: the backing JSON contains the real root and the existing tests are green.
- **P2 — the wallet_core close builders**: `build_close_intent` / `build_close_full_witness` / `prove_close`. **Verification**: a new Rust unit test generates and self-verifies a close MLE, and negatives (tampered signature / non-member) are rejected.
- **P3 — CLI `close` + `cancel-close`**: intent generation + co-signature aggregation + on-chain submission. **Verification**: requestClose→submitCloseIntent passes on anvil.
- **P4 — `settle` + `withdraw` + `claim`**: finalize → withdrawNative → pull → submitWithdrawalClaim → claimWithdrawalCredit. **Verification**: a member receives real ETH on anvil.
- **P5 — relay + full E2E**: `/api/close|settle|withdraw|claim`, and a CLI-driven anvil E2E (deposit→operation→close→challenge→withdraw→claim). **Verification**: a new `tests/close_lifecycle_cli_e2e.rs` (real proofs, strong negatives, pinned error strings).
- **P6 — cleanup**: mark `doc/tasks/a3-close-lifecycle-followup.md` as closed and replace the fail-closed stubs with implementations. Turning specialClose/lateDebit into reverts is proposed as a separate PR.

At the end of each phase, record the results in the `doc/tasks/audit-fixes-todo.md` family.

## 6. Test plan

- **Unit (Rust, release)**: correctness of the close/withdrawal-claim/cancel witness builders + negatives (tampered IMCH, non-member signature, stale version, tampered amount). Follow the pinned-error-string pattern of `tests/inter_channel_live.rs`.
- **On-chain (forge)**: extend `CloseLifecycleE2E` into a CLI-driven version, or add new `ChannelSettlementManager` negatives (verdicts, period boundaries).
- **E2E (anvil, Rust-driven)**: `tests/close_lifecycle_cli_e2e.rs` — deposit→close→challenge (including withdrawal via cancel)→settle→withdraw→claim, asserting the increase in the member's L1 balance. It is heavy (real proofs), so obtain explicit user permission.
- **Regression**: the `generate_*` fixtures and `CloseLifecycleE2E` stay green. If the Manager bytecode changes, regenerate the close fixtures (the §3.1 caveat).

## 7. Points requiring a user decision

1. **Whether to include the on-chain anchor check (recommended in §3.1)**: including it strengthens the semantics and adds future defense, but changes the Manager bytecode → the close fixtures must be regenerated. Excluding it means only using the real value (fund safety is unchanged either way). **Recommendation: include it** (defensive, low cost, and it means doing the same regeneration as A-2 once).
2. **Scope**: up to the happy path (P1–P5), or also including post-close-claim / turning specialClose into a revert. **Recommendation: first complete the happy path + cancel-close (P1–P5), and do post-close and the stub reverts in a separate PR**.
3. **How to handle liveness grief (one member refuses and close becomes impossible)**: either document it as a "known limitation" in this implementation, or design a remedy as well (a sound version of special-close = a cross-layer non-inclusion proof). **Recommendation: document it for now and handle the remedy separately** (detail2 §H-3 states it is waiting on cross-layer commitments).
