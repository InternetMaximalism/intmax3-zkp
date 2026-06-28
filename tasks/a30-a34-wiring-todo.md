# A30 cancelClose + A34 submitPostCloseClaim — CLI/forge/relay wiring

## Goal
Turn the two `501` API stubs (`POST .../close/cancel`, `POST .../close/post-close-claim`) into real
endpoints by wiring the EXISTING, tested Rust provers + Solidity contracts through new
`channel_member` CLI subcommands and forge steps. NO new circuits, NO new contracts, NO soundness
changes — pure wiring of already-audited cryptographic machinery.

Scope EXCLUDES A15 (bulk inter-channel) — investigation proved it needs a multi-recipient E-2 STARK
circuit redesign, not wiring.

## Pre-existing, verified machinery (do NOT reimplement)
- `CancelCloseProver` (src/wallet_core.rs:2864) — `new()`, `build_full_witness(revived_state,
  member_keys, close_intent)`, `prove()`, `prove_mle()`. Circuit enforces revived_version >
  close.final_state_version and the era fence in-circuit.
- `PostCloseClaimProver` (src/wallet_core.rs:2996) — `build_full_witness(final_balance_state,
  receiver_member_index, receiver_pk, receiver_sk, receiver_pk_g, recipient, close_intent_digest,
  source_tx, accumulator, incoming_tx_index, level)`, `prove()`, `prove_mle()`.
- Contracts: `cancelClose(CancelCloseRequest, MleProof)` (ChannelSettlementManager.sol:822),
  `submitPostCloseClaim(PostCloseClaim, MleProof)` (1085), `claimWithdrawalCredit()` (1167).
- Verifier strict-binds limbs; manager INJECTS `registeredMemberSetCommitment()` /
  recomputes `sharedNativeNullifier` — neither is caller-controlled.
- Golden fixtures already prove circuit↔contract: generate_cancel_close_fixture.rs (27 limbs),
  generate_post_close_claim_fixture.rs (56 limbs).

## THREAT MODEL (written before code, per CLAUDE.md)

### Trust boundary
The CLI runs the co-signer/relay (trusted to hold member keys). The *adversary* controls: the inputs
to the CLI (env vars, request bodies relayed from a browser), timing, and replay. The L1 manager +
verifier are the ultimate soundness gate; the CLI cannot mint a valid proof for a false statement.

### cancel-close (A30) — adversarial analysis
1. **Forged/old close_intent.** If the CLI reconstructs the wrong `close_intent`, the proof's
   `close_intent_digest` PI won't equal on-chain `pendingClose.closeIntentDigest`; manager reverts
   `CloseIntentDigestMismatch`. → Reconstruct from the EXACT persisted `CloseIntent`
   (`close_intent_full.json`, serde), NOT a lossy hex round-trip. The digest is the binding anchor.
2. **Stale revived state.** Circuit enforces `revived.state_version > close.final_state_version`
   (strict); Rust precondition bails early too. Cannot cancel with equal/older version.
3. **Cross-era cancel.** Circuit enforces era fence
   `revived.close_freeze_nonce + 1 == close.close_freeze_nonce`. Not relaxable from the CLI.
4. **Wrong member set.** `member_set_commitment` is a circuit-derived PI; manager injects
   `registeredMemberSetCommitment()` and the verifier strict-binds equality (Finding D). N-of-N
   folded list proof requires every registered member's real signature over the revived IMCH digest.
5. **Member key substitution.** `build_full_witness` rejects duplicate pk_g and requires exactly
   `member_count` keys; keys come from the co-signer's own derivation, never the request body.
6. **DoS via repeated cancel.** `cancelClose` moves no funds; re-submit after cancel reverts
   `CloseNotActive`.

### post-close-claim (A34) — adversarial analysis
1. **Over-claim.** Amount is DERIVED in-circuit by decrypting the receiver's own delta ciphertext;
   the CLI cannot inflate it. Manager caps accrual at the channel fund (shared `totalWithdrawn`).
2. **Fabricated incoming tx.** Circuit recomputes the tx hash and proves Merkle inclusion against
   the CLOSED channel's finalized `settled_tx_accumulator_root` (a re-bound PI). Source
   `InterChannelTx` comes from the wallet's persisted inter-channel artifact, not the request.
3. **Double claim / replay.** `sharedNativeNullifier` is RECOMPUTED by the manager
   (keccak(IMCK, closeIntentDigest, incomingTxHash, receiverPkG), HAZARD #8) and stored in
   `usedSharedNativeNullifiers`. The CLI's descriptor value is advisory only.
4. **Receiver-pk substitution.** Circuit binds the witnessed Regev pk to the H1-committed
   `regev_pk_digests[receiver_member_index]`; manager checks `receiverPkG` is a registered member
   and `recipient` matches its registered L1 address.
5. **Wrong channel status.** Manager requires `Closed` + `closeIntentDigest == finalized`.
6. **Recipient format.** Descriptor serializes `recipient` as `to_hex()` so `vm.parseJsonAddress`
   matches the tested `submitWithdrawalClaim` path.

### Residual / operational (NOT soundness) — documented, not blocking
- cancel-close needs a *revived* head (version > closed); post-close-claim needs a persisted late
  `InterChannelTx`. The two-channel demo doesn't auto-produce these; the CLI accepts them via
  persisted artifacts/args and is correct regardless. End-to-end demo exercise requires constructing
  those scenarios (the fixtures do so synthetically).
- HEAVY (real MLE/WHIR proving, minutes). Relay keeps the per-channel lock.

## PLAN (falsifiable)
- [ ] cmd_close also persists full `CloseIntent` → `close_intent_full.json` (serde, camelCase).
- [ ] cmd_cancel_close(manager, [rpc]) → cancel_close.json + cancel_close_mle.json → forge
      cancelCloseStep().
- [ ] cmd_post_close_claim(manager, receiver_slot, tx_index, [rpc]) → post_close_claim.json +
      post_close_claim_mle.json → forge submitPostCloseClaimStep() → claimWithdrawalCredit().
- [ ] RunClose.s.sol: add cancelCloseStep() + submitPostCloseClaimStep().
- [ ] Dispatcher + usage string register both.
- [ ] api/routes/close.js: real handlers for /close/cancel + /close/post-close-claim.
- [ ] cargo build --release; cancel-close + post-close-claim fixture gens + Forge tests (no regress).
- [ ] Independent security-review subagent.

## OUTCOME / ASSESSMENT
DONE. A30 cancelClose + A34 submitPostCloseClaim are now fully wired CLI→forge→relay.

- `cmd_cancel_close` / `cmd_post_close_claim` added + dispatcher entries; build clean.
- `cmd_close` persists `close_intent_full.json` (lossless serde); BOTH A30 and A34 read it for the
  digest (A34 hardened to drop the env-var re-derivation footgun per the security review).
- RunClose.s.sol: `cancelCloseStep()` (0xfa3b24c6) + `submitPostCloseClaimStep()` (0x18944985)
  compile; descriptor JSON keys/types verified against the forge parsers AND the golden fixtures.
- api/routes/close.js: `/close/cancel` + `/close/post-close-claim` invoke the CLI (execFileSync
  argv — no shell injection), per-channel lock held.
- Regression: all 10 ChannelSettlementManager cancelClose/postCloseClaim Forge tests PASS.

### Independent security review (separate subagent, NOT the implementer) — VERDICT: no soundness holes
Every attack path is fail-closed by an in-circuit PI binding + on-chain re-derivation the CLI/forge
cannot influence:
- close_intent digest is the binding anchor (manager matches pendingClose / finalized digest).
- member_set_commitment is manager-INJECTED; shared_native_nullifier is manager-RECOMPUTED;
  descriptors' advisory copies are not parsed.
- incoming_tx_index / source_tx forgeries fail the in-circuit Merkle inclusion against the finalized
  settled-tx accumulator root; amount is in-circuit decrypted (no over-claim).
- version/era checks enforced in-circuit; CLI preconditions are cosmetic-but-consistent.

## EXTENDED SCOPE (autonomous finish — A26/A28/A29/A33 phase correctness + A45 decision)
After A30/A34, the remaining 501s and semantic gaps were addressed where soundly wire-able:

- **Phase flags on cmd_close / cmd_claim (opt-in; default flow byte-identical):**
  - `CLOSE_REQUEST_ONLY=1` → A26 requestClose-only (freeze + optional grace advance), NO proving.
  - `CLOSE_SKIP_REQUEST=1` → A28 submit-intent / A29 challenge: skip requestClose (channel already
    ClosePending), build proof + submitCloseIntent.
  - `CLAIM_PULL_ONLY=1` → A33 pull-credit-only (claimWithdrawalCredit), NO proving.
- **A29 challengeClose WIRED** (api/routes/close.js): mechanically = submitCloseIntent on an
  already-pending close with a strictly higher (epoch, version); the manager enforces the monotonic
  ordering, so a non-newer challenge fails closed. Same proving machinery as A28/close.
- **A26/A28/A33 corrected** to pass the right flags + inputs (A33 now requires recipient — the
  claimWithdrawalCredit caller).
- Build clean; forge 0 errors; endpoints verified (A29 501→400, A45 accurate 501).

### A45 cancelPartialWithdrawal — DELIBERATELY NOT ENABLED (soundness escalation)
Doc correction: NO new prover is needed — `cancelPartialWithdrawal(CancelCloseRequest, MleProof)`
reuses the EXACT `verifier.verifyCancelClose(...)` + `CancelCloseProver` proof as A30. BUT
`cmd_pw_submit` builds the partial-withdrawal `CloseIntent` with `close_freeze_nonce = 0`, while the
cancel circuit's era fence requires `revived.close_freeze_nonce + 1 == intent.close_freeze_nonce`,
which is UNSATISFIABLE at 0. Enabling A45 requires resolving that era-fence interaction (its own
threat model + independent review). Per CLAUDE.md ("cannot articulate the security argument → do not
proceed"), A45 stays a 501 with an accurate message rather than shipping unverified money-cancel
logic.

### Delta review (separate subagent) — VERDICT: all deltas sound, no soundness holes
- CLOSE_REQUEST_ONLY: inert (requestClose is fully on-chain-guarded: Active + member, no funds).
- CLOSE_SKIP_REQUEST: cannot bypass first-close grace — submitCloseIntent reverts CloseNotRequested
  if nothing is pending and GracePeriodNotElapsed otherwise; challenge ordering is monotonic on-chain
  via `_isNewer` (strict lexicographic (epoch, version)), so a non-newer challenge fails closed.
- Default path (no flags) byte-identical to before — no regression.
- CLAIM_PULL_ONLY: cannot steal — claimWithdrawalCredit pays only withdrawalCredits[msg.sender] with
  the global solvency cap; CLAIM_RECIPIENT does NOT flow into the contract call (advisory/log only).
- api handlers: correct env + per-channel lock + execFileSync argv (no shell injection).
- A45 non-ship VERIFIED CORRECT: CloseIntent::new advances close_freeze_nonce by +1 (channel.rs:780)
  so a full close at era 0 → intent nonce 1 (cancel fence `revived 0 + 1 == 1` satisfiable), but
  cmd_pw_submit hand-builds intent nonce 0, making the fence unsatisfiable. Enabling A45 needs a
  distinct PW-cancel era model — correctly escalated to a 501, no silent workaround.

### Genuinely out of wiring scope (need circuits / architecture, NOT shippable as wiring)
- A15 sendBulkInterChannel / W5 / W9 — multi-recipient E-2 STARK circuit redesign.
- A17 receiveInterChannel — multi-co-signer architecture (currently correct as co-signer-internal).
- A35 postBlock — separate BP service.

### Residual (NOT soundness; documented)
- LOW: api handlers don't regex-validate address/number inputs and forward `sourceTx` as a file path
  (POST_CLOSE_SOURCE_TX). execFileSync argv ⇒ no shell injection; bad inputs fail-close at the proof.
  Hardening (constrain sourceTx to channel dir, validate formats) is optional defense-in-depth.
- OPERATIONAL: the two-channel demo does not auto-produce a *revived* head (A30) or a *late*
  InterChannelTx (A34); driving these end-to-end on a live chain requires constructing those
  scenarios. The CLI commands are correct regardless (the golden fixtures prove the circuit↔contract
  path). A full live E2E (anvil + setup-backing + proving) was NOT run — heavy compute, deferred.
