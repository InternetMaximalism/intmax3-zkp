# Category E — deposit / block / finalize ordering & duplication hazards

The rollup folds a PENDING deposit (and a pending registration) into the FIRST posted block; the
validity proof's block-hash chain must match the on-chain `blockHashChainAt[]` exactly (the §F-1
"keystone"). Operator/attacker ordering or duplication mistakes should fail CLOSED (finalize reverts),
never misbind funds. These pin that property.

Layer: Rust+anvil (drive `cast send` postBlock blob txs + `deposit` + forge `finalizeStep` in custom
orders). Reuse the `tests/close_lifecycle_cli_e2e.rs` harness; for several of these you post blocks
manually rather than via `cmd_withdraw` so you can perturb the order.

---

### E25 — deposit folds into the wrong block
- **Severity**: liveness (fail-closed) — must NOT misbind.
- **Setup**: proof models deposit in block 2; on-chain, call `deposit()` AFTER block 2 is posted (so it
  lands in block 3's pending chain).
- **Assert**: `blockHashChainAt[2]` on-chain ≠ proof → `finalize` reverts (false); no payout possible.
  Pin fail-closed. (Mirror of the bug fixed this session — but as a perturbation test.)

### E26 — finalize the WRONG submission id (`SUB_ID`)
- **Severity**: liveness.
- **Setup**: post 3 rounds (submissions base..base+2); call `finalize` with the wrong submission id.
- **Assert**: reverts / returns false (PI binding to the wrong round's chain); the correct id finalizes.

### E27 — reuse / double-finalize a finalized root
- **Severity**: fund-safety / idempotency.
- **Setup**: finalize submission X; try to `finalize` it (or another) for the same already-finalized root.
- **Assert**: second finalize is rejected / no-ops (`sub.finalized` guard); `finalizedStateRoots` stays
  consistent; no double escrow accounting.

### E28 — blocks posted out of order / registration after deposit
- **Severity**: liveness.
- **Setup**: post the withdrawal block before the deposit block, or the deposit before the registration
  is folded.
- **Assert**: the resulting chain ≠ proof → `finalize` reverts. (Also: a registration block that tries to
  also carry a deposit is rejected by the witness generator's R6 guard — verify the on-chain analogue
  fails closed.)

### E29 — two channels both deposit before either posts a block
- **Severity**: liveness (pending-chain contention).
- **Setup**: A.deposit, B.deposit (both pending), then A posts its block first.
- **Assert**: A's first block absorbs BOTH pending deposits → A's chain ≠ A's proof (which modeled only
  A's deposit) → A's finalize reverts. Pin that interleaved pending deposits across channels brick the
  first poster unless the operator serializes deposit→post per channel. (This is the multi-channel
  generalization of the single-channel fold-order constraint.)

### E30 — depositor mismatch (msg.sender ≠ proved depositor)
- **Severity**: liveness (fail-closed).
- **Setup**: send `deposit()` from an EOA different from the one the proof folded as depositor.
- **Assert**: deposit hash (folds msg.sender) ≠ proof → block 2 chain mismatch → finalize reverts.
  Confirms the depositor binding is enforced end-to-end.

### E31 — wrong deposit amount / recipient / aux vs the proof
- **Severity**: liveness (fail-closed).
- **Setup**: on-chain `deposit()` with an amount/recipient/aux differing from the proof's deposit fields.
- **Assert**: deposit-hash mismatch → finalize reverts. (Parameterize each field independently.)
