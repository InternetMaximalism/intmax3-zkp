# INTMAX3 release disposition — 2026-09-18

> **The NO-GO determination is LIFTED.** Every finding that carried a NO-GO in
> `audit30-08-2026-final-security-closure.md` is closed. This is a status record, not a new audit:
> it supersedes the release conclusions of the 2026-08-30 and 2026-09-02 reports and leaves their
> technical bodies standing as dated records.
>
> **Lifting NO-GO is not a GO.** The remaining work listed below is ordinary pre-release
> verification, tracked as release evidence rather than as blockers.
>
> **No finding at Critical severity is open.** The open findings are re-assessed in
> "Open findings" below; the highest is HIGH, and it has a client-side one-line fix.

## Why the NO-GO rows are closed

| Row (`audit30-08-2026-final-security-closure.md`) | Disposition | Basis |
|---|---|---|
| MLE/WHIR PCS soundness | **CLOSED** | The constituent-evaluation repair is complete. **Owner-asserted**; the repair lives in `InternetMaximalism/intmax-plonky2` and was not re-verified from this repository. |
| Rollup → Manager backing | **CLOSED** | `CloseFundingMaterializer` is the channel-bound credit path. `IntmaxRollup.creditChannelExit` (`:781-788`) accepts only `_channelExitMaterializer`, and the materializer credits every active token atomically only after validating the backing proof against the channel id, settled chain, token-funds digest and a finalized root. Global or donated escrow cannot substitute for channel-scoped evidence. Verified in code, and modelled in Lean as `BackingBridge` / `CloseFunding.materializeSignedHead` (premises (c0)-(c4) of `Zkp.Implementation.TrustBoundary`). |
| Delegate close-proof availability | **CLOSED** | Closing is **keyless**. The N-of-N Falcon signatures ride on the accepted signed head, collected when that state was agreed; `public_close_prover` "neither loads nor requires a member signing key" (`audit02-09-2026-release-blockers-2-5.md` §1). Anyone holding the head and its public backing can drive a close to completion, so cosigners cannot block an exit by withholding signatures. The fresh N-of-N requirement applies only to the optional *cooperative terminal-funding* lane (ibid. §2), which is not a precondition for closing. |

An earlier reading of this record mistook the cooperative terminal-funding lane's signature
requirement for a precondition of closing, and quoted the frozen 2026-08-30 matrix as a current
state. Both are corrected here.

## WHIR / plonky2 verifier — audit confirmation

The MLE/WHIR proof system is audited in its own repository, `InternetMaximalism/intmax-plonky2`,
under `mle/audit` (Lean 4, its own guard `check-wire3.py`). Status reported 2026-09-18:

| | |
|---|---|
| Audit head | `4ae524dc` — `audit(wire3): record the 43a454fb fresh-source receipt` (2026-09-18) |
| Merged to | the submodule's own `main`, fast-forwarded `becfe98e` → `4ae524dc`, pushed |
| Guard | PASS — **157 models / 516 files / 6,542 theorems** |
| Fresh-source rebuild | run twice from clean output; the first run caught a mid-run file-change conflict, re-run after edits settled |
| Documentation | `README.md`, `SCOPE.md`, `REPORT.md` (2,244 lines, all 55 continuation-update sections) and the three `HISTORICAL-*` files translated to English with every proved/not-proved distinction, hedge, citation, hash and identifier preserved; zero CJK characters verified independently in all six. The guard scripts contained no Japanese. |
| Adversarial work carried | the 2026-09-18 re-audit of the deployed verifier, with PoC suites (`PocWhirFiatShamir`, `PocGateExt3Production`, `PocOuterCanonicality`, `PocOuterFraudVerdict`, `PocWhirDotEqBounds`) |

### The audited tree is not the tree this repository pins

This is the one qualification on the confirmation above, and it needs reconciling before the wire3
audit can be cited as covering what this repository deploys.

- This repository pins `contracts/lib/polygon-plonky2` at **`6cefc6ac`** — on this branch, on
  `origin/main`, and in `doc/audit/lean-current-source-manifest.json`.
- The audit line's head is **`4ae524dc`**.
- **The two have diverged.** Their merge base is `b569e0d7` (2026-09-04). The pinned commit adds two
  merges the audit line does not have (`ca5c8fc6` "Merge wire-v3 PCS repair into main integration
  branch and isolate legacy APIs", then `6cefc6ac` "Merge main PCS isolation while retaining
  target-105 verifier optimizations"). The audit line adds 66 commits the pin does not have.
- The PCS repair itself (`5b1c28ae`), `96b5836c` and `b569e0d7` are ancestors of **both**, so both
  lines carry the repair.
- The divergence is not confined to audit artifacts: `git diff 6cefc6ac 4ae524dc` touches verifier
  source — `mle/src/commitment/whir_pcs.rs` (44 lines), `mle/src/prover.rs` (14),
  `mle/src/lib.rs` (38 deletions), `mle/src/verifier.rs` (2), `mle/src/fixture.rs`,
  `mle/src/generated/mle_whir_v2.rs`, plus the legacy-containment test harnesses.

Consequence: the Lean premise (a0) `mleVerifierSoundness` in `Zkp.Implementation.TrustBoundary` is
scoped **by commit** to `6cefc6ac`, while the wire3 audit's evidence is about `4ae524dc`. The wire3
result therefore does not transfer to the pinned artifact as-is.

**Action:** reconcile the two lines — either merge the isolation work into the audit line and re-run
its guard and fresh-source receipt, or merge the audit line into the pinned line and advance this
repository's submodule pointer and manifest pin — then restate (a0)'s scope at the resulting commit.
Until then, cite the wire3 audit as covering `4ae524dc`, not the deployed pin.

## Release evidence still to be produced (not blockers)

1. Independent cryptographic review of the **repaired** PCS design — transcript order, commitment
   format, Rust verifier and Solidity verifier — followed by redeployment of the audited verifier
   and verification of the deployed runtime bytecode. The `mle/audit` wire3 corpus above is that
   review for the audit line: 157 models / 516 files / 6,542 theorems at `4ae524dc`, plus the
   2026-09-18 adversarial re-audit of the deployed verifier. What is outstanding is the
   reconciliation of `4ae524dc` with the pinned `6cefc6ac`, and the deployed-bytecode verification.
2. Public-chain browser-to-payout E2E with production key custody, including restart and reorg
   recovery. Local fixtures and development secrets are not release evidence.
3. Repeat the clean-clone matrix: regenerate and hash every VK and fixture, verify deployed runtime
   bytecode, and re-measure EIP-170 margins. `IntmaxRollup` had only a 62-byte margin at
   2026-08-30, so any code movement since then requires a fresh size gate.
4. Member-set updates stay disabled until one proof or receipt atomically advances both the Manager
   member set and the validity-tree member set.

## Open findings (re-assessed 2026-09-18; none at Critical)

| Finding | Severity | Assessment |
|---|---|---|
| F-PUBST-1 | **CLOSED** | Discharged by inspection. `PublicState` and `PublicStateTarget` each have exactly the same five fields, and `PublicStateTarget::is_equal` (`src/common/public_state.rs:307-328`) ANDs all five. The component comparisons are complete too: `u32limb_trait::is_equal` (`:178-189`) zips every limb, `PoseidonHashOutTarget::is_equal` (`:210-222`) folds all four elements. The `conditional_verify` skip at `update_public_state.rs:97` therefore fires only on a genuine no-op, and the transition-forgery path the finding worried about does not exist. |
| Genesis Regev-digest binding (H-2 residual, delegate anchoring) | **HIGH** (raised from MEDIUM) | Every identity-bearing root **is** bound to real keys: `member_pubkeys_root` recomputes `regev_pk_digest` as `m.regev_pk.poseidon_digest()` from the full public key (`wallet_core.rs:854-866`), `MemberInfo` carries no digest field, `verify_snapshot` re-derives and checks both `regev_pk_root` and `member_pubkeys_root` (`:1297-1312`), and `wallet_import_channel` locates the wallet's slot by matching its own full Regev public key (`wasm_wallet.rs:443-448`). The single exception is `balance_state.regev_pk_digests[slot]` — the copy the withdrawal-claim circuit actually checks — which is cross-checked against the record nowhere; `BalanceState::validate()` constrains only padding slots (`balance_state.rs:667-670`), and the H-2 freeze preserves whatever was seeded at genesis. A **cosigner** is protected, because `wallet_sign_state` refuses to sign a genesis whose own-slot digest is not `poseidon_digest(own key)`. A **delegate is not**: that function requires `slot < member_count`, and delegates do not sign genesis. Import and balance decryption both succeed regardless (decryption reads the ciphertext and the secret key, never the digest), so a wrong digest stays invisible until claim time, when the loss is permanent and there is no sweep path. Not Critical: the outcome is a freeze of one slot, not theft — the attacker gains nothing, the delegate slot starts at the canonical zero ciphertext, and it requires the genesis assembler to be malicious or buggy. Raised to HIGH because the loss is permanent, silent until unrecoverable, and the only automatic check is structurally unavailable to the party at risk. |
| Registration consent | **LOW-MEDIUM** (lowered from MEDIUM) | `registerChannel` still verifies no member signature and `member_regev_pk_digests` are still freely witnessed in-circuit, so nothing on-chain enforces the binding. In practice a forged registration is detected client-side: the roots a wallet re-derives come from the real keys, so an importing wallet either fails to find its own key in `members` or fails the root comparison. The residual is one of ordering — the check must happen before the member commits funds — not of detectability. |
| F-AUX-1 (= audit622 C-M1) | **MEDIUM** | The in-circuit guarantee is real: `aux_data` is Merkle-bound to the exact consumed transfer leaf, which is bound through `tx.transfer_tree_root` to the sender's settled tx, so a prover cannot swap it. What is not proved in-circuit is the semantic claim `aux_data == tx_leaf_hash(...)`; the source says so and names the compensating layers (`receive_transfer_circuit.rs:505-513`): the co-sign-time check, the §E-2 `channelUpdateZKP`, and the receiving channel's independent recomputation. Exploitation needs the receiving channel's N-of-N cosigners all to skip that recomputation, so it is not unilaterally exploitable. It stays MEDIUM rather than lower because two of its three compensating layers — the plonky3 STARK and off-chain client code — are the least independently verified parts of the system. |

### Recommended next fix

Extend `verify_snapshot_own_slot` (`wallet_core.rs:1322-1354`), which already holds the wallet's
keys and its slot, with the one comparison it currently omits:

```rust
if snapshot.state.balance_state.regev_pk_digests[slot as usize]
    != Bytes32::from(keys.regev_pk.poseidon_digest())
{
    return bail("my slot's balance-state Regev digest does not match my key");
}
```

This covers cosigners and delegates alike at import time, needs no contract or circuit change, and
does not hit the obstacle that blocked the original H-2 pinning (the twenty-one corpus sites that
build active slots with all-zero digests were a problem for an in-circuit or `validate()`
constraint, not for a wallet-side check — the corpus should still be re-run).
