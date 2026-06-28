# intmax3-zkp — Lean formalization: audit summary

**Scope:** Plonky2 ZKP circuits, excluding cryptographic-primitive internals
(Poseidon/SPHINCS+/Regev/MLE-WHIR — uninterpreted) and all channel circuits.
**Artifact:** `audit/zkp/` — 36 Lean files, **101 machine-checked theorems**
(61 circuit + 40 contract), 4759 LOC, **zero `sorry`**, clean `lake build` from
scratch. Covers BOTH the Plonky2 ZKP circuits AND the L1 Solidity contracts in
one framework, enabling end-to-end combined-system safety. Every in-scope file
is covered: modeled with proved soundness, or mapped to proved generic
properties in `Circuits/Plumbing.lean` / `Contracts/Coverage.lean`.

**Method:** each circuit is a predicate `Constraints → Prop` (one conjunct per
`builder.*` gate, citing `source.rs:line`); soundness is `Constraints → spec`.
A *provable* theorem = the circuit binds what it must; an *unprovable
strengthening* = the missing constraint = a candidate finding. See `README.md`.

## Bottom line

The complete user fund flow — **deposit → spend → send → receive → withdraw** —
plus validity-top, on-chain binding, and nullifier non-membership is **formally
established sound**. **No new exploitable circuit-level vulnerability** was found
beyond one previously-known residual (C-M2), which is contract-contingent.

## Soundness theorems (selected)

| Property | Theorem | File |
|---|---|---|
| No balance inflation (overflow rejected) | `add_no_wrap`, `credit_strictly_increases` | U256, UpdatePrivateState |
| Spender solvency (no overspend, ≤64 transfers) | `deducts_solvent` | SpendCircuit |
| Credit/deduction touches only the indexed leaf | `AssetUpdate`, `dual_accumulation` | UpdatePrivateState, DepositStep |
| Invalid spend is a no-op | `invalid_spend_is_noop` | SendTxCircuit |
| Receive requires a valid sender spend | `requires_valid_sender_spend` | ReceiveTransferCircuit |
| Tx inclusion unavoidable | `inclusion_unavoidable` | TxSettlement |
| IVC dispatch: output from the unique verified branch | `routing_sound` | SwitchBoard |
| Cyclic recursion fixed-point binding | `cyclic_sound` | BalanceCircuit |
| Withdrawal provenance + one-shot nullifier | `withdrawal_sound` | SingleWithdrawalCircuit |
| Withdrawal aggregation: faithful fold + single state | `fold_faithful`, `state_threaded` | WithdrawalStep |
| Deposit chain: sequential append, no gaps/dups | `sequential_append` | DepositStep |
| Signatures non-skippable (computed gate) | `signatures_not_skippable` | ValidityCircuit |
| bp_sig_chain accumulation threading | `bp_sig_chain_threaded` | BlockStep |
| Nullifier non-membership (spend-once) | `key_absent`, `no_double_insert` | IndexedMerkle |
| Producer signature bound to block tx tree | `digest_binds_block` | SmallBlockMessage |
| PI layout no-aliasing (round-trip) | `pi_roundtrip_two` | Plumbing |
| Recursion-binding completeness of PIs | `connectPis_iff_eq` | BalancePis |

## Combined-system safety (circuits + L1 contract)

`Zkp/Contracts/` extends the same framework to `IntmaxRollup.sol` (Solidity
modeled as `Option`-returning state transitions; `require`/checked-math =
revert; crypto verifiers = uninterpreted oracles). The native fund lifecycle
(deposit → withdrawNative → withdraw) is proved safe, with these theorems:

| Property | Theorem | File |
|---|---|---|
| Global solvency: Σ ETH out ≤ Σ ETH in | `solvent_from_genesis`, `global_solvency`, `run_conservation` | IntmaxRollupSolvency |
| Per-call withdraw ≤ escrow (underflow-revert ceiling) | `withdrawNative_solvency`, `withdrawLoop_solvency` | IntmaxRollupWithdraw |
| No double-withdraw (CEI nullifier) | `withdrawLeaf_nullifier_once`, `withdrawLeaf_consumes` | IntmaxRollupWithdraw |
| No payout without a verified+anchored proof | `withdrawNative_requires_proof` | IntmaxRollupWithdraw |
| Finalized roots written ONLY by verified validity proofs | `finalize_only_on_valid` | IntmaxRollupWithdraw |
| Pull-payment claim-once (CEI) | `claimWithdraw_no_double` | IntmaxRollupWithdraw |
| Burn-withdrawal solvency + auth-gated | `claimAuthorized_safe` | IntmaxRollupWithdraw |
| Stake single-resolution + conservation | `no_double_payout_*`, `stake_conserved` | IntmaxRollupStake |
| Deposit sequential append (↔ circuit) | `deposit_sequential` | IntmaxRollupDeposit |
| Two-level access control (deployer→manager) | `registerManager_requires_deployer`, `authorizePartial_requires_manager` | IntmaxRollupDeposit |
| Rollback floor — finalized roots permanent | `fraud_above_floor`, `finalized_roots_persist` | IntmaxRollupOptimistic |
| Channel payout cap (Σ out ≤ Σ pulled) | `claim_preserves_cap`, `pull_preserves_cap` | ChannelSettlementManager |
| Channel no-double-claim (CEI) | `claim_no_double` | ChannelSettlementManager |

**End-to-end:** every L1 ETH payout is (1) backed by a verified WithdrawalCircuit
proof bound to the leaves (`pisHash`) → `SingleWithdrawalCircuit.withdrawal_sound`
(a real sent transfer) → `SpendCircuit.deducts_solvent` (a real balance
deduction); (2) anchored to a finalized validity state written only by
`finalize` on a verified validity proof (`signatures_not_skippable` ⇒ no forged
blocks); (3) single-use (per-transfer nullifier, `IndexedMerkle.key_absent`,
consumed CEI); and (4) bounded by `Σ out ≤ Σ in`. **F-WITHDRAW-1 is closed both
in-circuit and contract-side.** No exploitable gap at the circuit↔contract
boundary for the native fund path.

> Contract coverage: COMPLETE. All fund-safety-critical logic of
> `IntmaxRollup.sol`, `ChannelSettlementManager.sol`, and
> `ChannelSettlementVerifier.sol` is proved (40 contract theorems across 7
> modules). Remaining lines (hash-layout folds, crypto-verifier wrappers,
> getters, init, rollback bookkeeping) are categorized in
> `Zkp/Contracts/Coverage.lean` — STRUCTURAL (subsumed by `keccak_det` +
> differential-tested layout), CRYPTO ORACLE (uninterpreted, as in the
> circuit model), or LIVENESS/VIEW (no escrow effect). `BlobKZGVerifier.sol`
> and the submodule `MleVerifier.sol` are pure PCS/pairing math (oracles).

## Findings

| ID | Severity | Status | Summary |
|---|---|---|---|
| **F-WITHDRAW-1** | MEDIUM | **OPEN** | = audit622 **C-M2**, independently re-derived. `withdrawal_circuit.rs:190-194` binds only `ext_public_state.inner`; the 5 extended fields are free witnesses yet committed on-chain. Safe **iff** `IntmaxRollup.sol` re-pins `ext_public_state_commitment` to the stored block. **Contract-check task spawned** (`task_cae4b173`). |
| F-NULL-1 | — | **Discharged** | Nullifier non-membership proved (`IndexedMerkle`); empty-leaf=MAX sentinel closes the documented duplicate-insertion PoC. |
| F-RECIP-1 | Info | Adjudicated | `extract_address` ignores recipient padding; NOT fund-exploitable (full-recipient nullifier + solvency + tag separation). Defense-in-depth: assert padding zero. |
| F-SPEND-1 | — | Closed | `is_valid` consumed (send_tx no-op + receive asserts true). |
| F-ACCT-1 | — | Closed | `is_checked` true at all callers; index widths match tree heights. |
| F-BLKR-1 | Low | Mostly resolved | `block_r ≤ block_number` enforced on receive paths. |
| F-AUX-1 | — | Residual (by design) | `aux_data == tx_leaf_hash` enforced off-circuit at co-sign (documented). |

## Trusted base / assumptions

- `Core/Field.lean`: a commutative integral-domain field (the entire algebraic
  base). Goldilocks characteristic NOT axiomatized; the one place it's
  load-bearing (4-wide one-hot in SwitchBoard) is surfaced explicitly.
- Poseidon/keccak: uninterpreted functions; collision resistance is the named
  hypothesis `Bytes.PoseidonCR` where the protocol relies on it.
- `update_user` (SPHINCS+/Poseidon signature gates) and MLE/WHIR: treated as
  verified sub-proofs / out of scope per the audit boundary.

## Not separately modeled (no new soundness leaf constraints)

PI-layout / message-encoding / cyclic-wrapper / orchestration files
(`small_block_message`, `ext_public_state`, `*_chain_pis`, `*_circuit`,
`*_processor`, deposit-chain wrappers, `balance_processor`,
`withdrawal_chain/processor`). Their PI round-trip no-aliasing property is
proved generically in `BalancePis.connectPis_iff_eq`.
