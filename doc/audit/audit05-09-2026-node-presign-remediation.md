# Remediation of the node pre-signing and pre-deposit checks, and operational handover

Date: 2026-09-05. Base: `a2886fff08c2619ba47604e4d2fa5634b9e17471`.
Working branch: `codex/node-presign-safety-20260905`.
Working location: `/private/tmp/intmax3-node-preflight-audit-20260905.m7xtV6/checkout`.
As of the first version of this document, nothing was committed and nothing was pushed. Ahead of the MLE update integration of 2026-09-06, this node remediation is collected into an independent preservation commit. The original working directory and branch were not modified.

## 1. Conclusion and scope

We implemented defenses against the six main findings of the previous audit (N-01 through N-06). Among the conditional findings, we also addressed the browser signing history, duplicated exit keys, the non-degeneracy condition for claims, Node numeric conversion, burn/destination recovery, and the pre-freeze posting-readiness check.

Rather than "signing and proceeding on a state that cannot be verified", the policy is to check legitimate transactions at an early stage and, on a transient failure, to resume from the same persisted operation. **This is not a declaration that all release conditions are complete.** Automatic wiring of the backing attestation on the normal PW path, the watcher's deposit classification, and production-equivalent E2E are outstanding work described below.

The trust assumptions of the design are unchanged.

- Misallocation of a channel's own assets through collusion of the entire sig-cluster within that channel is accepted. The funds of other channels are protected.
- We accept a design in which at least one honest signer performs the off-chain checks.
- The goal is that exit from the last N-of-N signed H is possible without any additional channel signature.
- The KZG ceremony is trusted. The MLE/WHIR submodule and the Solidity code were not changed in this work. MSU / the old CloseFunding have not been re-enabled.
- The node's local services, configuration, and private state are inside the trust boundary. Balance claims and recipient claims arriving as external input are not treated as equivalent to private, verified records.

## 2. The six main findings

| Finding | Change | Care for the happy path and for resumption |
| --- | --- | --- |
| N-01 state signed too early when a proposal is generated | The `wallet_core` builders for send, refresh, inter-send/credit, deposit, and token-register return the state unsigned. The explicit checked signing boundary of native/browser is used instead | The sender's own A11 transaction authentication is retained. The structural checks of the two-phase import and the happy-path tests also handle unsigned proposals |
| N-02 close metadata on normal transitions | Cross-check the participant count from the trusted record and the close-freeze nonce of the previous H. The small-block number of a normal send/refresh is also preserved | A new era after a legitimate close-cancel is not rejected by pinning it to the genesis value. The import-specific counter increment is preserved |
| N-03 u64 range of the cumulative received balance | In `channel_credit_safety`, the post-change cell is checked before signing, from the verified conservation law, the token fund, one's own decryption, and private conservative upper bounds | No u64 fund cap is imposed on the channel as a whole. An unknown balance is not treated as zero. Unrelated unknown cells alone do not block every operation |
| N-04 fictitious initial recovery destination | Production `setup-backing`/genesis now requires the recovery destination of every controlled cosigner to be stated explicitly. Malformed values, zero, and known synthetic defaults are rejected | Existing signed recipients are not changed. Operations on existing channels are not uniformly required to carry the new genesis configuration. Only explicitly insecure tests keep the default values |
| N-05 wrong deposit slot after re-joining | Resolve the exact original slot from the contribution's pkG, pkB, Regev key, and signed recipient | A re-joining member is not assumed to be in the "last slot". Reuse of a request ID for a different intent is rejected |
| N-06 the deposit is found to be un-creditable only after funds have been spent | Check the same amount/token/slot/increment count/receive headroom as native does, before spending. Reserve the headroom and broadcast the raw L1 transaction only after persisting it | A timeout does not create a new transfer. Resumption uses the same request ID, the same raw bytes, and the same tx hash. A completed reservation is kept as a tombstone that is never credited again |

### Reading the limits of N-03 precisely

What is persisted is a private upper bound; no public snapshot and no proof public input was added. Balances that can be decrypted with one's own key are checked exactly. Even with a large fund, an operation can proceed as long as a sufficient upper bound for the target cell is known.

On the other hand, when the upper bound of another party's balance is unknown under a very large token fund, even a legitimate credit may be conservatively rejected. Removing this entirely would require a different design that safely obtains the necessary range information. We do not treat the existing refresh proof by itself as a proof of the u64 bound. An insufficient increment count can be resolved by an ordinary refresh, but **a lack of range information about hidden balances is not always resolved by refresh alone**.

When a new deposit reservation is added, the earlier admission cache for the unsigned future head is discarded. A deposit's own reservation is excluded from double counting only while that deposit is being checked, and is not released midway through signing. It is completed in the same WAL as the state after the full N-of-N is complete.

## 3. Deposit persistence and resumption order

1. Check the admission conditions from the private signed head and the recipient identity.
2. The trusted local live service issues and persists a one-time deposit recipient for its own channel.
3. Pin the intent, the candidate slot, and that recipient into the operation journal and the native capacity reservation.
4. Sign the L1 transaction, fsync the raw bytes, and only then broadcast.
5. Pin the exact tx hash into the reservation. Re-pointing it to a different hash is forbidden.
6. Verify the canonical chain receipt, the recipient, the depositor, the amount, the token, and the producer/live processing.
7. Check both the fund-import and the bundle successors, and prepare the required exit kit and N-of-N.
8. Persist the completed state and result into `.pending-deposit-import.json` before applying the head/result.
9. Store the completion receipt in `.deposit-import-receipts/`; a retry of the same import returns the existing result.

The rotating one-time recipient must not be selectable from an arbitrary HTTP parameter. `inspect`/`import` resolve a new expected recipient only from a tx hash that matches a private reservation. The legacy entry points that have no reservation keep the `channel_backing.json` recipient check. This does not mean that checking the recipient's tag alone proves channel ownership.

An identical request that omits the request ID also resumes as the same deposit. **A new deposit of the same amount must use a new request ID.** An error saying that a pending operation exists must not be reread as "not yet sent". Do not delete the journal/reservation/raw bytes and retry.

## 4. Additional persistence and exit paths that were fixed

- **Burn:** `.pending-burn-publication.json` binds the signed head together with `last_burn.json`/`burn_cosigned.json`. Both burn APIs run native recovery before looking at the result files, and do not re-sign an already persisted burn.
- **Inter-channel:** hold the native process lock for both A and B. A concurrent operation in the opposite direction detects the conflict non-blockingly and retries without deadlocking. Journals of unrelated channel pairs are not subject to recovery.
- **B's pending operations:** if B's deposit/burn/inter WAL has not been recovered, stop before A signs. The standard API pre-recovers both A and B.
- **B's kit:** the archive, the Balance verifier data, and the backing are all verified in B's own directory. Files of a different channel that happen to sit in A's cwd are not used.
- **Inter WAL v2:** the checksum of the persisted JSON is verified before the typed state is restored. HashSet re-serialization order no longer causes a healthy journal to be treated as corrupt. v1 is read only when the original compact bytes match the old checksum.
- **Destination-only recovery:** `incoming_inter_transfer_recovery.json` is added to what the 2PC persists. B can resume from the persisted source input, producer receipt, and live source artifact through receive and kit installation. It does not depend on the source's convenience files, even if a later operation by A overwrites them.
- **Legacy inter processing:** sidecar completion is implemented only for already-complete inputs, and reuse of the old argv only for the same request/input. No history deletion and no reset of signing decisions.
- **API exit-kit:** an ambiguous failure after the child process has started is not unconditionally abandoned. The exact proposal, kit, and request ID are retained, and the completion state is recovered from the accepted head.
- **Participant close / credit pull:** the read-only `staticCall` explicitly passes the caller's own `from`.
- **Readiness before a new freeze:** against the complete public-close bundle and the pinned deployment, the exact H, both state roots, the anchor, L1 finality, the runtime/config, the Active status, and the next nonce are checked read-only. The same bundle is also used by the downstream publisher. Recovery of an existing raw transaction does not require a fresh readiness check.
- **Publisher wiring:** the Node side strictly interprets every progress phase, including native attest/materialize, and the schema 3 result.

Readiness is a check that discourages freezing on one's own initiative while dependent data is still unposted or unfinalized. It does not make the check and the actual L1 transaction atomic at the contract level, and it is not a guarantee that all races with other L1 operations are eliminated.

## 5. Browser, keys, numerics

- Browser member mode waits for a strict IndexedDB transaction to complete before returning a signature outside the worker. A different successor for the same predecessor is rejected; the same successor returns the persisted signature. No unnecessary persistence is added to the ordinary delegate send path.
- `wallet_sign_state` cross-checks the expected recipient at contribution time and its own Regev digest before signing.
- For new participants/genesis, duplicated Regev exit keys, padding digests, and degenerate keys are rejected. A modified balance ciphertext is also checked against the non-degeneracy condition of existing withdrawal claims. A canonical empty slot with zero assets is allowed.
- The Node-side amount, slot, token, channel, and nonce are checked before the WASM call, so that a JS/WASM numeric truncation is never mistaken for a fund-movement intent.

The browser ledger is persistent storage scoped to one origin/profile. It does not make deletion, rollback to an old backup, or use of the same signer key under a different profile safe. A custom host that uses the raw WASM directly needs an equivalent durable signing boundary.

## 6. Distribution and migration

1. Do not mix old and new native binaries over the same state directory; update native, API, and Node together. The private schema is 6 and the inter WAL writer is 2. Do not downgrade to an old binary as-is.
2. An old schema can be read as long as the required existing security ledger is present. A missing new bound is not filled in as "zero balance" or as "already checked".
3. Rebuild `channel_member`/`public_close_publisher` and the WASM package. Do not update only the source and ship a stale generated WASM.
4. Ship `wallet-worker.js` and the new `signature-release-ledger.mjs` in the same release. The detailed distribution commands are in `doc/docs/deploy-runbook.md`.
5. For a new channel, configure the recovery destination of every cosigner following `doc/tasks/node-presign-recipient-setup.md`. Key custody for EOAs and the actual recovery path for smart wallets must also be confirmed on the operations side.
6. Install the dependencies from both the `api/` and `node/` lockfiles, and share the signer lock root across every publisher/deposit sender that uses the same L1 signer.
7. Preserve the state, the replay ledger, the exit-kit archive, the deposit/burn/inter journals, the L1 outbox, and the browser signing ledger as one consistent generation. Do not delete them or lift their TTL in order to restore availability.

This work does not rewrite an improper recipient in an existing H, a balance that is already out of range, or a duplicated exit key. We do not declare that existing inconsistencies can always be remedied without additional signatures.

## 7. Verification and performance

The final full Node suite is **497 passing out of 506, 0 failing, 9 pre-existing skips**. The skips are 1 conditional on an unbuilt daemon and 8 conditional on ungenerated state-delta fixtures.

| Targeted Rust tests | Passing |
| --- | ---: |
| private credit bounds | 11 |
| native capacity reservation | 11 |
| deposit recovery | 6 |
| burn publication recovery | 2 |
| inter WAL codec / happy-path file persistence | 5 |
| cosigner recipient configuration | 5 |
| unit checks of normal metadata | 4 |
| native signing ledger / B's kit context | 11 |
| happy-path send/deposit/refresh/inter/register/close-era (release) | 9 |
| happy-path participant record / key admission (release) | 1 |
| public-close publisher, all 42 (including 3 readiness tests) | 42 |
| public-close publisher CLI arguments | 3 |

The table above is a selection of targeted tests; it is not a full run of the Rust repository's entire suite. The final native library / `channel_member` / `public_close_publisher` test builds and the WASM target check succeeded offline with a pinned lockfile. Pre-existing warnings remain. No real service and no chain was contacted; the publisher was exercised against the existing fake backend. `git diff --check` also passed.

- The 9 Rust release tests for happy-path send/deposit/refresh/inter/token-register and close-era metadata passed.
- Ran the targeted tests for the new private bounds, capacity reservation, deposit recovery, inter WAL codec, recipient configuration, and signing ledger.
- The actual `cast mktx` output was checked with a public dummy key, a zero amount, all tx fields explicit, and no network access. No real funds and no real chain were submitted to.
- `cargo check` for the WASM target succeeded. Running the generated package in a browser, and a real-browser IndexedDB E2E, have not been carried out.
- No proof circuit, public input, or proof format was added for normal operation. The cryptographic implementation in the submodule was not changed. The pre-freeze proof is reused downstream rather than generated twice.
- On the other hand, decryption, host-side checks, fsyncs, and the volume stored in private journals/sidecars all increase. Comparative before/after measurements of proving time, end-to-end latency, and memory/disk use have not been made, so we do not claim by measurement that performance is unchanged.

## 8. Outstanding work — items not to be treated as done

### A. Exact backing attestation on the normal PW path

PW submit over the normal API/CLI proceeds when the exact signed-head backing has already been attested on L1, but the wiring that establishes this automatically is not implemented. The contract's downstream check is retained, so if it is missing the submission is rejected.

A candidate for the next implementation is to unify the existing close proof that PW generates with the public-close bundle, and to reuse the same artifact for both the backing attestation and the PW submit. Simply adding a separate full close proof generation would mean generating it twice. The devnet fixture attestation script must not be used as a substitute for production. No additional channel signature is required, but a gas signer for the permissionless L1 transaction and a durable outbox are.

### B. Watcher stalling on an unrelated deposit

When native rejects an unrelated deposit, the current watcher can retry at the same block and thereby obstruct subsequent monitoring. In this work we did not make a change that ignores the rejection error and advances the cursor.

A safe fix requires an authoritative `required / proven-unrelated / unresolved` decision that covers the live service's history as well as its current entries. Because a salt disappears from the current getter once consumed, a mismatch against the current recipient alone cannot prove that a deposit is "unrelated". RPC errors, reorgs, and unknown recipients are likewise not grounds for skipping. Separating the historical lookup from the progress of monitoring is the next priority task.

### C. Production-equivalent end-to-end verification

End-to-end verification covering real-browser durable signing, a real daemon, L1 posting/finality, and the path from deposit to a signer-independent exit/claim at the latest H remains outstanding. The new readiness check must also be measured in a production-equivalent setting. Before real funds are introduced, the happy path, resumption after interruption, multiple tokens, and concurrent operation must be confirmed in an isolated environment.
