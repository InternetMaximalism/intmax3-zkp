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
| Audit head | `4ae524dc` — `audit(wire3): record the 43a454fb fresh-source receipt` (2026-09-18); carried into `3a20a05f`, which this repository now pins |
| Merged to | the submodule's own `main`, fast-forwarded `becfe98e` → `4ae524dc`, pushed |
| Guard | PASS — **157 models / 516 files / 6,542 theorems** |
| Fresh-source rebuild | run twice from clean output; the first run caught a mid-run file-change conflict, re-run after edits settled |
| Documentation | `README.md`, `SCOPE.md`, `REPORT.md` (2,244 lines, all 55 continuation-update sections) and the three `HISTORICAL-*` files translated to English with every proved/not-proved distinction, hedge, citation, hash and identifier preserved; zero CJK characters verified independently in all six. The guard scripts contained no Japanese. |
| Adversarial work carried | the 2026-09-18 re-audit of the deployed verifier, with PoC suites (`PocWhirFiatShamir`, `PocGateExt3Production`, `PocOuterCanonicality`, `PocOuterFraudVerdict`, `PocWhirDotEqBounds`) |

### The audited tree is now the tree this repository pins — RESOLVED

This was open earlier the same day and is now closed.

The two lines had diverged from merge base `b569e0d7`: the pin `6cefc6ac` carried the isolation
merges (`ca5c8fc6`, then `6cefc6ac` itself), and the audit line `4ae524dc` carried 66 audit
commits. Moving the pointer straight to `4ae524dc` would have broken this repository — the parent's
`deprecated-msu = ["plonky2_mle/legacy-conformance"]` (`Cargo.toml:223`) names a feature that exists
in `6cefc6ac`'s `mle/Cargo.toml` and not in `4ae524dc`'s — and would have un-gated the historical
protocol-1 prover and verifier that `audit30-08-2026` recorded as isolated.

The submodule side therefore took the isolation line into its own `main`, producing **`3a20a05f`**
(`merge(non-audit): take the mle-node-safety isolation line (ca5c8fc6, 6cefc6ac)`), pushed. This
repository now pins that commit — gitlink, `doc/audit/lean-current-source-manifest.json`, and the
(a0) scope statement in `Zkp.Implementation.TrustBoundary` all updated together.

Checks made before moving the pin:

- `4ae524dc` and the PCS repair `5b1c28ae` are both ancestors of `3a20a05f`.
- `legacy-conformance` is present in `3a20a05f`'s `mle/Cargo.toml`, so the parent's `deprecated-msu`
  feature resolves and the protocol-1 entrypoints stay gated.
- On source paths (`mle/src`, `mle/contracts/src`, `mle/Cargo.toml`, `plonky2`, `field`, `util`,
  `starky`), `git diff 6cefc6ac 3a20a05f` is **one file**: `mle/src/verifier.rs`, +15/−2, and the
  change is entirely comments recording the D3 history and why the retained fold is now only a
  shape guard. No semantic change, and that file is behind `legacy-conformance` in any case.
- Everything else `3a20a05f` adds over `6cefc6ac` is additive: the audit corpus, the PoC suites
  (`PocWhirFiatShamir`, `PocGateExt3Production`, `PocOuterCanonicality`, `PocOuterFraudVerdict`,
  `PocWhirDotEqBounds`, and the Rust `poc_*` tests), the re-audit task note and its test vectors.

Submodule-side verification of `3a20a05f`, as reported: Lean guard PASS (157 models / 520 files /
6,542 theorems), `cargo test` 141 passed on default features and 196 passed with
`legacy-conformance`, `forge test` 385 passed. The fresh-source receipt was not re-run because no
Lean file changed in that merge; the `43a454fb` receipt recorded in that repository's REPORT §56
still covers the identical Lean tree.

This also repairs a latent breakage: `6cefc6ac` had never been pushed to the submodule's remote, so
a fresh clone followed by `git submodule update` could not fetch the commit the parent pinned.
`3a20a05f` is on that remote's `main`.

**(a0) is re-scoped, not discharged.** The premise now names `3a20a05f`. The submodule carrying its
own Lean audit does not discharge it: that corpus is not built, hashed or replayed by this
project's guard, and nothing here checks its scope or residues. (a0) remains an accepted premise.

## Release evidence still to be produced (not blockers)

1. Independent cryptographic review of the **repaired** PCS design — transcript order, commitment
   format, Rust verifier and Solidity verifier — followed by redeployment of the audited verifier
   and verification of the deployed runtime bytecode. The `mle/audit` wire3 corpus above is that
   review for the audit line: 157 models / 516 files / 6,542 theorems at `4ae524dc`, plus the
   2026-09-18 adversarial re-audit of the deployed verifier. What is outstanding is the
   deployed-bytecode verification; the tree reconciliation is done (see above, now pinned at
   `3a20a05f`).
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
