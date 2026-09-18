# INTMAX3 release disposition — 2026-09-18

> **The NO-GO determination is LIFTED.** Every finding that carried a NO-GO in
> `audit30-08-2026-final-security-closure.md` is closed. This is a status record, not a new audit:
> it supersedes the release conclusions of the 2026-08-30 and 2026-09-02 reports and leaves their
> technical bodies standing as dated records.
>
> **Lifting NO-GO is not a GO.** The remaining work listed below is ordinary pre-release
> verification, tracked as release evidence rather than as blockers.

## Why the NO-GO rows are closed

| Row (`audit30-08-2026-final-security-closure.md`) | Disposition | Basis |
|---|---|---|
| MLE/WHIR PCS soundness | **CLOSED** | The constituent-evaluation repair is complete. **Owner-asserted**; the repair lives in `InternetMaximalism/intmax-plonky2` and was not re-verified from this repository. |
| Rollup → Manager backing | **CLOSED** | `CloseFundingMaterializer` is the channel-bound credit path. `IntmaxRollup.creditChannelExit` (`:781-788`) accepts only `_channelExitMaterializer`, and the materializer credits every active token atomically only after validating the backing proof against the channel id, settled chain, token-funds digest and a finalized root. Global or donated escrow cannot substitute for channel-scoped evidence. Verified in code, and modelled in Lean as `BackingBridge` / `CloseFunding.materializeSignedHead` (premises (c0)-(c4) of `Zkp.Implementation.TrustBoundary`). |
| Delegate close-proof availability | **CLOSED** | Closing is **keyless**. The N-of-N Falcon signatures ride on the accepted signed head, collected when that state was agreed; `public_close_prover` "neither loads nor requires a member signing key" (`audit02-09-2026-release-blockers-2-5.md` §1). Anyone holding the head and its public backing can drive a close to completion, so cosigners cannot block an exit by withholding signatures. The fresh N-of-N requirement applies only to the optional *cooperative terminal-funding* lane (ibid. §2), which is not a precondition for closing. |

An earlier reading of this record mistook the cooperative terminal-funding lane's signature
requirement for a precondition of closing, and quoted the frozen 2026-08-30 matrix as a current
state. Both are corrected here.

## Release evidence still to be produced (not blockers)

1. Independent cryptographic review of the **repaired** PCS design — transcript order, commitment
   format, Rust verifier and Solidity verifier — followed by redeployment of the audited verifier
   and verification of the deployed runtime bytecode.
2. Public-chain browser-to-payout E2E with production key custody, including restart and reorg
   recovery. Local fixtures and development secrets are not release evidence.
3. Repeat the clean-clone matrix: regenerate and hash every VK and fixture, verify deployed runtime
   bytecode, and re-measure EIP-170 margins. `IntmaxRollup` had only a 62-byte margin at
   2026-08-30, so any code movement since then requires a fresh size gate.
4. Member-set updates stay disabled until one proof or receipt atomically advances both the Manager
   member set and the validity-tree member set.

## Open findings (medium; outside the NO-GO set)

| Finding | Where | State |
|---|---|---|
| F-PUBST-1 | `update_public_state.rs:97` | The `conditional_verify` skip is sound only if `PublicStateTarget::is_equal` compares **every** public-state field. If one is omitted, a prover sets `e=1` with that field mutated and skips the Merkle check — transition forgery. Load-bearing assumption, not yet confirmed. |
| F-AUX-1 (= audit622 C-M1) | `send_tx_circuit.rs:285-289`, `receive_transfer_circuit.rs:496-504` | Inter-channel `aux_data` is folded into `settled_tx_chain` but is not proved equal to the tx-leaf hash. Residual, documented off-circuit. |
| Registration consent | `IntmaxRollup.sol:1248-1286`, `channel_reg_step.rs:331-332` | `registerChannel` verifies no member signature, and `member_regev_pk_digests` are freely witnessed in-circuit, so nothing binds a registered Regev identity to the key its holder actually controls. No client reads the registered bytes back and compares them against its own key; the browser path (`wallet_sign_state`) checks only the JSON it is handed. Registration is one-shot and immutable, so a client-side read-back check closes this without contract or circuit changes. |
| H-2 genesis residual | `state_update_verifier.rs:1561` (the freeze), registration | The freeze now preserves `regev_pk_digests` across transitions — and therefore also preserves a wrong value seeded at genesis. |
| Delegate key anchoring | `channel_reg_step.rs`, `wallet_core.rs:841` | Delegates are excluded from L1 registration by construction (`delegateCount != 0` reverts; `assert_zero(delegate_count)` in-circuit) and are authenticated only by the cosigner-signed H1 slot tree, so a delegate has no immutable on-chain anchor to verify against. |
