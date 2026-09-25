# Local wallet partial-withdrawal repair

The previous relay could burn and update a live balance without publishing any producer blocks
on L1. Its settlement deployer also used a Keccak Regev key digest where the producer's validity
registration uses Poseidon. This made the one-shot L1 registration incompatible with the saved
producer chain. Existing incompatible deployments cannot be repaired by retrying or re-burning.
Keep their files/keys and deploy a separate coherent test environment.

The new local flow:

0. Export the verification configuration from the same resident circuit constructor and arities
   used by the daemon, deploy those exact pins, and compare all three deployed core digests before
   funding. The sample fixture configuration targets different arities and is not interchangeable.
   The exported config cache is keyed by the CLI binary digest and arities.
1. Init deploys the settlement on the channel's existing rollup. L1 registration uses the exact
   Poseidon key identity used by the producer and signed balance state.
2. Before producer registration, match the L1 ChannelRegistered event's cumulative hash and
   index against the exact snapshot and previous producer registration head. Refuse mismatch.
3. Before PW submit, lazily start the resident validity prover. Prove the saved history, post each
   block with its historical pending-chain checkpoint and real blob proof DA, then attest/finalize
   the real compact validity proof. Raw signed posts are persisted before broadcast for recovery.
   Reuse the exact MLE bytes pinned in the immutable publication manifest: regenerating a
   randomized MLE for the same producer candidate would conflict with its already-signed blobs.
4. Acknowledge finalization only via the daemon's canonical L1 transaction read-back. Generate and
   attest signed-head backing, then use the real post-burn balance proof for close/PW submission.
5. Finalize the proof-backed payout. A browser recipient remains claim_pending until its exact
   MetaMask withdraw/withdrawToken transaction is verified. Saved transaction hashes resume after
   reload; the UI does not authorize another burn while receipt is pending.
   Submit retries detect the same pending/authorized/paid burn on L1. Payout retries reuse the
   exact proof bytes matching the authorization and producer anchor, preserving the native
   payout journal's candidate identity. Forge dry-run records use an invocation-specific output
   directory and support both function-named and legacy run-latest journals.

Wallet orchestration and the Solidity helper refuse non-31337 chains. Public-chain release
readiness is unchanged. No dummy proofs, force-set roots, contract-storage patches or verifier
bypasses are used.

The local publication and payout commands explicitly set `INTMAX_WALLET_ANVIL_MINE=1` to mine
64 real empty blocks after the latest head changes, before reading Anvil's finalized checkpoint.
Repeated reads at the same head remain stable. The native helper refuses this
flag on any other chain and still validates the actual RPC-finalized canonical receipt. This
avoids waiting forever on a local node with automining but no periodic empty blocks.
Anvil 1.5.1 was observed to return BlockOutOfRangeError on the first historical eth_call after
evm_mine followed by anvil_mine; the same read immediately succeeds on retry. Only that read-only,
explicitly block-pinned error is retried (up to three attempts), never a send or a different tag.

The relay supports INTMAX_WORK_DIR, INTMAX_CHANNELS, RPC and RELAY_PORT so tests can run on a
separate Anvil and separate ports. WALLET_E2E_DIR, RPC and WALLET_E2E_URL select the explicitly
isolated instance for `node hosting/wallet/wallet-l1-e2e.js`. The harness stores a disposable
seed and completed operation artifacts in WALLET_E2E_DIR and resumes without double deposits or
burns. Do not point it at a user's wallet work directory.

Validation: registration Rust regression passed; 583 Node unit/HTTP regressions passed
(the long resident `api-live-balance.test.js` suite is excluded from that count). Real isolated
wallet join, 0.01 ETH deposit/import and 0.005 ETH burn succeeded. Real validity publication,
backing attestation, manager finalization, proof payout and recipient pull succeeded on isolated
Anvil RPC8558. The recipient's before/after balance, adjusted for gas, increased by exactly
5000000000000000 wei. Payout transaction:
0x2021a2703dd181c85385323e50b88d11aed65d3ac56c6ff0e0c501265bd69e66;
pull transaction: 0x4ed563fe5c73898301a1ab1877aa782dc1149228a549fe62b51a6f695a8ec008.
The remaining 0.005 ETH was then burned to a different Anvil account. Repeating submit returned
the exact existing authorization without advancing the operator transaction nonce. The native
driver credited the external recipient, the recipient's exact pull increased its balance by
5000000000000000 wei excluding gas, and `/api/pw-claim-confirm` completed the ticket.
External proof payout: 0x547b845b7977ce896c7c498e0ca293d12967675da0f67555654ddefc9c300bb3;
external pull: 0x64a61b52e883d48818ac455ec2e61dae9479a1efc1f435af22f7d441420e8ed0.
The external-recipient harness used an unlocked disposable Anvil account, not the user's MetaMask.
The user approved the environment switch on 2026-09-24. Actual MetaMask signing remains to be
tested by the user; the replacement relay is now active on HTTPS8000 / HTTP8001.


Replacement environment activated (2026-09-24):
- Original Anvil RPC8545 is still running; no reset, impersonation, or balance override was used.
- Original `wallet-live-work` remains intact. A second complete copy and Anvil state dump are in
  `/private/tmp/intmax-wallet-preserved-20260924T191524Z`.
- New work directory: `wallet-live-work-v2-20260924`; rollup
  `0xCD8a1C3ba11CF5ECfa6267617243239504a98d90`; channels 17 (user) and 18 (validation).
- User channel 17 has real 0.09 ETH operator genesis backing and awaits the user's first Join.
  This backing is not the user's opening balance. User deposits are selected after Join.
- TEST index 1 uses the existing permissionless mint contract
  `0x67d269191c92Caf3cD7723F116c85e6E9bf55933`. It is registered on the new rollup.
  An additional 10 TEST was minted directly to the user's L1 wallet. Receipt:
  `0x445bcc6dcc5dace16305ab17a355bcd5c8355c25bc6c86d00d8387ceee534f46`.
- `INTMAX_INITIAL_TOKEN_INDICES=1` makes Join adopt the real backing and register TEST through
  the existing verified exit-kit and co-signing pipeline, then return its exact final snapshot.
  Metadata must match on-chain registration. No browser-provided token identity is accepted.
- Channel 18's disposable account completed Join, TEST registration, and a real 10 TEST deposit
  import. WASM decrypted token slot 1/index 1 as 10000000 base units. Artifacts are under
  `wallet-live-work-v2-20260924/validation`, including its private disposable seed; the entire
  work directory is gitignored.
- UI discovers `/api/channels`, selects 17 when the saved channel 7 is no longer served, and
  leaves the old saved seed/channel untouched until explicit Join. An HTTP8001 browser preview
  showed Ready / channel 17 / Join / collapsed messages. HTTPS8000 endpoints passed read-back;
  the automation browser does not trust the local self-signed certificate.
- 29 focused regressions passed after the switch changes, including 3 new channel-selection
  checks. Browser JS syntax and `git diff --check` passed.

Restart the replacement relay only after stopping its PID from `relay-runtime.json`:
`python3 wallet-live-work-v2-20260924/start-relay.py 8000`.
The launcher pins RPC8545, channels17/18 and initial token index1. Old channel7's saved burn
remains unresolved in the preserved old environment; its balance/ticket was not migrated.


### 2026-09-24 — second-channel Join / InvalidChannelExitManager repaired

The rollup permits one set-once CloseFundingMaterializer shared by all channel managers.
DeployWalletSettlement incorrectly created a new materializer for every manager; channel18
registered first, so channel17's Join reverted during simulation. The devnet coordinator now
selects a previously registered sibling manager on the same rollup. The deployment script
verifies that manager's rollup/registration, the materializer's rollup, and the backing adapter's
chain plus all three pinned core configuration digests before reusing it. The rollup's set-once
check remains intact. First-channel deployments still create the materializer.

The user confirmed account `0x47607f687491348caf382d6abb1d18b09246db9a` (the original channel17
member); a later contribution from `0x9d4f46…466374` was a different account and was not installed.
The original PREPARED channel17 registration was resumed using its existing public member record,
with the pre-recovery directory retained at `wallet-live-work-v2-20260924/before-shared-materializer-fix`.
Join now completed at state version1 with verified ETH and TEST slots. On-chain read-back confirmed
both channel17 and18 managers bound to the same materializer. The browser's private key was not
read or replaced. Use the original joining browser and the confirmed MetaMask account to reconnect.

The confirmed account had zero native ETH; real Anvil transactions supplied 0.1 test ETH and
10 TEST for deposit/gas testing. Receipts are stored under the new work directory as
`gas-funding-ch17-recipient.json` and `test-token-provision-ch17-recipient.json`.
Join errors now return the final diagnosis (bounded to1200 characters), keeping full Forge traces
in relay.log. The replacement relay has been restarted with these fixes on8000/8001.

Validation: four Solidity deployment tests passed, including a real second manager deployment
sharing the first materializer and rejection of an unregistered reference. Twenty focused Node
tests passed, including sibling-rollup selection. Actual channel17 Join and chain bindings were
verified. User browser deposit/withdrawal on channel17 remains to be exercised.


### Join key mismatch follow-up

The next actual Join request again used recipient `0x9d4f46b2b701aa2875a18e8803338eaf3d466374`
and a different pkG from channel17's registered delegate. Channel17 remains Active for the user-
confirmed `0x47607f687491348caf382d6abb1d18b09246db9a`. Contract registration is healthy.
The relay now checks public identity before writing contribution.json: a frozen channel never
accepts a replacement key, even for the same MetaMask address; matching keys require their bound
recipient. Conflicts return409 with short recovery guidance, not native internal-state traces.
The browser rereads eth_accounts when using an already connected provider to avoid relying only
on accountsChanged events. Eighteen Node tests passed. The actual mismatching HTTP retry returned
409 without changing contribution.json, cli_state.json, or channel_snapshot.json (SHA256 checked).
The user has been asked whether the original browser/exact origin remains available or Clear/site-
data deletion occurred. Do not claim private-key recovery: no browser seed has been inspected,
replaced, or reconstructed. MetaMask address control alone cannot restore that channel key.


### Fresh-channel option after repeated identity conflict

Because the current browser kept submitting the different key/account and recovery-origin details
were unavailable, added a separate empty channel19 on the SAME retained Anvil/rollup. Channels17/18
are unchanged. `/api/channels` now reports `availableForJoin:[19]`; ETH/TEST metadata was verified
for19, and its backing/deposit-info is ready. No member is pre-bound to19: the user's explicit Join
will bind the currently connected account and browser key. This is a new account, not recovery or
migration of17. No existing seed or on-chain binding was replaced.
The browser offers “Join new channel 19” after a key/frozen-membership conflict. Clicking it selects
the unused advertised channel and uses the ordinary Join flow. No silent redirection, relay seed
access, or MetaMask impersonation is used. Errors preserve their structured code for this UI flow.
The launcher now serves17/18/19. Twenty-three focused tests passed, including explicit-click-only
recovery and refusal to offer occupied/unserved channels; browser syntax/diff checks passed.


### User-requested UI rollback

Removed the newly introduced “Join new channel” button and identity-conflict navigation branch.
The Join panel again has only its channel input and Join button. Existing navbar Clear, multi-token
deposit UI, and collapsed messages remain as requested earlier. This is a static UI change; no
channel state, browser key, contract, or balance was reset. Channel19 remains available as data,
with no special UI for it.


### 2026-09-24 — send disconnect and destination exit-kit repaired

After the user joined19 and deposited0.01 ETH (L1tx
0xcafcd94bd39d60d207818d31fae31d64d91ae04f02853744cd759c16954b781a), the19→17-0 transfer
failed before signing: destination17's persisted exit-kit archive was the token-registration
PRE-SIGN envelope, lacking the final N-of-N signatures. The relay then used native exit status1
as an HTTP status and crashed, causing all later browser calls to report Failed to fetch.

Both token-registration routes now install the actual signed-head exit-kit AFTER publication.
The shared relay error handler bounds HTTP errors to400..599, and an uncommitted native signing
refusal is normalized to409 in the shared inter-channel coordinator. Existing17's kit was repaired
through the same idempotent init path. No signature checks were bypassed. The stale7-0 default
recipient is now blank; no new UI branch was introduced. Pre-repair17/19 data is preserved in
`wallet-live-work-v2-20260924/before-send-repair`.

Restarted relay and replayed ONLY the user's exact saved19→17 request:
inter:61fb73f8b28e26e9498332f588ed65c293cb52372c16f9983e1fb29ae370463a.
The transfer completed; source19 is signed version4, destination17 signed version3. Both live
snapshot digests match the returned signed response, inter_operation.json is completed, and
/api/inter/pending?channel=19 reports false. Saved response: recovered-send19-to17.json.
The original0.001 ETH send to17-0 is done and must NOT be resent. Subsequent19-0 attempts occurred
while the relay was dead and were not replayed. Twelve focused crash/recovery/error-response tests
passed, including a native status1 signing refusal; diff check passed.
