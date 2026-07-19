# Lean safety proof of abstract2-1.md — explanation, threat model, limitations

[`ChannelSafety21.lean`](./ChannelSafety21.lean) is the Lean 4 formalization of
`abstract2-1.md` (v2.1 = small-block posting + cross-channel bulk transfer). It
**imports** [`ChannelSafety2.lean`](./ChannelSafety2.lean) (abstract2 / Lattice v2)
for the unchanged core: `Ct`, `Tag`, intra-channel `channelTxZKP`, single-leg
inter-channel lemmas, and the close/challenge theorems on `EncBalanceState`.

[`ChannelSafety2.lean`](./ChannelSafety2.lean) is **frozen** for abstract2.md and is
not modified by this revision.

## Verification method (3-step build)

```bash
cd architecture-audit
lean ChannelSafety.lean -o ChannelSafety.olean
LEAN_PATH=$PWD lean ChannelSafety2.lean -o ChannelSafety2.olean
LEAN_PATH=$PWD lean ChannelSafety21.lean   # exit 0 = all theorems verified
```

Lean 4.10.0 / core only. No `sorry` / `axiom`.

## Reuse from v2 and new parts

| Category | Content |
|---|---|
| **Reuse (import ChannelSafety2)** | `Ct`, `Tag`, `SigModel2`, `ValidEncState`, intra-channel theorems, single-leg `ChannelUpdate`, `challenge_latest_wins2`, `end_to_end_close_safety2`, `chain_binding_resolves_attachment`, base-layer ledger (via ChannelSafety) |
| **New (v2.1)** | `EncBalanceState21` (+ `settledChain`), `BulkChannelUpdate` / `TransferEntry`, `BulkUpdateProven`, `applyBulkSend` / `applyBulkReceive`, bulk solvency + conservation, `bulk_send_chain_step`, `TransferAuthorized21`, `end_to_end_close_safety21` (projection) |
| **New (v2.1b batch)** | `BatchTx` / `BatchTxProven` / `BatchProven` (`sendersDistinct` = R1), `applyBatch` (debits-then-credits canonical fold, one version bump), `batch_conserves_total`, `batch_preserves_validity`, `batch_step_eq_seq` / `batch_singleton_eq_single` (sequential equivalence) |

## What v2.1 newly proves

1. **Bulk solvency** — `bulk_send_preserves_validity` / `bulk_receive_preserves_validity`
   under `BulkUpdateProven` (A2) and per-leg `RecipientBulkVerified`.
2. **Cross-channel conservation (single-dest legs)** —
   `bulk_interChannel_conservation_dest`: when all entries target one
   `dest`, sender debit + receiver credit conserve the combined total.
3. **M8 partial-receive binding** — `bulk_interChannel_conservation_bound`:
   commitment injectivity (A1) identifies the bulk update the sender debited
   with the one the receiver credits.
4. **settledTxChain in state** — `bulk_send_chain_step` models
   `settledChain' = hash2 settledChain (commit u)` on send.
5. **Small-block authorization** — `TransferAuthorized21` (= v2
   `TransferAuthorized2` on projected state); per-channel `tx_root` semantics
   documented in the file header (M1').
6. **Batched intra-channel transfer (v2.1b, abstract2-1 §2.2b/§3.2b/§4.2b)** —
   `applyBatch` applies K txs in ONE state transition: every debit is checked
   against the ANCHOR state (`BatchTxProven`: `after = before − amount`, both
   non-negative, `encAmount = amount`), all debited slots distinct
   (`sendersDistinct` = single-debit rule R1), then all credits fold as
   homomorphic adds. Proven:
   - `batch_preserves_validity`: `ValidEncState21` is maintained,
     `provenTotal` conserved, `settledChain` untouched — for ANY proven batch,
     **including sender-as-recipient** (R2).
   - `batch_conserves_total`: Σ balances invariant (illicit-mint impossibility
     for the whole batch).
   - `batch_step_eq_seq`: when no debiting slot is also credited, the batch
     fold is **extensionally equal** to the sequential per-tx application
     (`seqFold` of abstract2 §3.2 steps) — the batch is a compressed run of K
     ordinary transfers under one agreement round. `batch_singleton_eq_single`
     recovers K = 1 exactly.
   The cross-batch double-spend argument (a debit's `before`-ct binding acts
   as a natural nullifier) lives at the spec level (abstract2-1 §2.2, §4.2b(4));
   in the model it corresponds to `BatchTxProven` failing against any state
   whose sender ciphertext differs from the anchor.

## Theorem ↔ specification correspondence

| abstract2-1.md | Property | Lean theorem |
|---|---|---|
| §2.1 `settledTxChain` in `H1` | chain step on send | `bulk_send_chain_step` |
| §3.2 / §4.3 | intra-channel solvency | *(reuse)* `channelTx2_preserves_validity` |
| §2.3 bulk `channelUpdateZKP` | solvency send | `bulk_send_preserves_validity` |
| §3.4 flowReceive3 (filtered legs) | solvency receive | `bulk_receive_preserves_validity` |
| §4.3 delta binding | conservation | `bulk_interChannel_conservation_dest`, `bulk_interChannel_conservation_bound` |
| §3.3.2 / §4.1 | authorization | `TransferAuthorized21`, `authorized_bulk_send_state_valid` |
| §3.5.4 | close composition | `end_to_end_close_safety21` (via `end_to_end_close_safety2`) |
| §3.1 / §4.1 | authorization (intra / single-leg) | *(reuse)* `authorization2`, … |
| §3.5.2–3 | stale close | *(reuse)* `challenge_latest_wins2` |
| §2.1 chain binding | proof attachment | *(reuse)* `chain_binding_resolves_attachment` |
| §2.2b / §3.2b R1 | batch single-debit rule | `sendersDistinct` hypothesis of `batch_preserves_validity` |
| §4.2b (1) sequential equivalence | batch = K compressed §3.2 steps | `batch_step_eq_seq`, `batch_singleton_eq_single` |
| §4.2b (3) conservation | batch total invariant | `batch_conserves_total` |
| §4.2b main | batch validity | `batch_preserves_validity` |
| — | non-vacuity | §9 Sanity (`sampleBulkDest1_proven`, `sample_bulk_conservation_dest1`, `sampleBatch_proven`, `sampleBatch_valid`, `sampleBatch_total_conserved`) |

Base-layer no-double-spend / conservation: v1 theorems via import (unchanged).

## Trust base (A1–A6)

Inherited from [lean-safety-proof2.md](./lean-safety-proof2.md):

- **A1** signature unforgeability + `hash(H1,H2)` collision resistance
- **A2** ZK soundness (`BulkUpdateProven`, `balanceProof`, `validityProof`, …)
- **A3** honest-member discipline (`SignsOnlyValid2`, `OneStatePerVersion2`, close freeze)
- **A4** L1 contract correctness (`L1CloseRule`)
- **A5** lattice homomorphism (no noise overflow / modulus wrap in model)
- **A6** IND-CPA confidentiality out of model; structural ledger fact unchanged

**Bulk-specific (M8):** each destination channel trusts only its legs via
Merkle inclusion inside `TxLeafHash`; the model's `commit` injectivity stands
in for that binding.

## Model limitations (M1'–M8)

| ID | Limitation |
|---|---|
| **M1'** | One sending-channel inter-channel settlement = one small block = one abstract `Apply` step. Other channels' `SubBlock`s in the same medium round are separate channel ids / steps. |
| **M2–M5** | Inherited from ChannelSafety2 (ledger↔state link, version discipline, receive replay, tree contents). |
| **M6'** | `TransferAuthorized21` binds deducted state to bare `tx_root`; bulk entry ↔ ledger `amount` still `hcircuit` (A2). |
| **M7** | Signed-but-unsettled `.txRoot` state at close — spec open (abstract2-1 §6). |
| **M8** | Multi-destination bulk: conservation theorem proved for **one `dest` at a time** (`honly : ∀ e ∈ entries, e.dest = dest`). Cross-channel multi-dest conservation is by iterating per-dest channels + global `BulkUpdateProven` (not a single closed-form lemma). |
| **M9** | Batch (v2.1b): `batch_step_eq_seq` requires no debiting slot to be credited in the same batch; the sender-as-recipient case is covered by `batch_preserves_validity` directly (the fold order debit-before-credit is then normative, not derived). The D3 `pending_adds` budget and witness invalidation (refresh) are implementation-layer concerns, not modeled — the model's `BatchTxProven`-against-anchor stands in for "the E-1 proof matches the current stored ciphertext". |

## Relationship to abstract2 / ChannelSafety2

```
abstract.md     → ChannelSafety.lean
abstract2.md    → ChannelSafety2.lean   (aggregated TxV2Tree model)
abstract2-1.md  → ChannelSafety21.lean (small-block + bulk; imports 2)
```

When the implementation catches up to cross-channel bulk (see abstract2-1 §5),
extend `BulkChannelUpdate` proofs and validity-circuit parameterization (M6'
v3 candidate) accordingly.

## Conclusion

abstract2-1's structural changes (per-channel small block, bulk send/receive) are
backed by new machine-checked bulk solvency and conservation theorems. Close
safety reuses v2 via `EncBalanceState21.toV2`. Open spec items (M7, multi-dest
replay at receive) remain explicit in the model header and §6 of abstract2-1.md.
