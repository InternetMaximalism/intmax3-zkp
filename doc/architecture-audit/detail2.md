# detail2 — Current implementation reference and historical design rationale

> **Implementation alignment: 2026-09-06.** This reference describes runtime parent `05ec7ae`
> (including node/admission repairs `b5bafb7`) with MLE submodule `6cefc6ac`, wire v3,
> target 105 / inverse-rate 6. It is not a deployment approval or an unconditional asset-safety
> proof. The earlier Lean baseline `3e2d45c` is extended by `ChannelSafetyAdmission`,
> `ChannelSafetyRecovery` and `ChannelSafetyExit`. Their conditional results and validation
> are recorded in [the current Lean scope](../audit/lean-current-safety.md), not release approval.

## Current implementation contract (2026-09-06)

This section and the dated current section of
[the implementation notes](./detail2-implementation-notes.md) supersede the evolutionary
§A–R text below. [abstract2.md](./abstract2.md) and [abstract2-1.md](./abstract2-1.md) describe the
design requirements; this section records how the inspected implementation satisfies them,
where it is deliberately different, and where work remains. A requirement or historical
completion statement must not be mistaken for implemented behavior. Exact source definitions
and generated protocol constants govern serialization; the old Rust sketches are not schemas.
The [Lean scope](../audit/lean-current-safety.md) and its source manifest must be read with their
own revision: a prior manifest does not certify this runtime or its MLE cohort.

### Current types, widths, and commitments

| Item | Current representation / constraint | Source |
|---|---|---|
| Sig-cluster | `member_count: u8`, `2..=MAX_SIG_CLUSTER`, cap **8**; only these members co-sign | [`constants.rs`](../../src/constants.rs), [`ChannelRecord`](../../src/common/channel.rs) |
| Balance participants | `delegate_count: u16`; members followed by delegates, total at most **1024**; participant slots use `u16` | [`BalanceState`](../../src/common/balance_state.rs), [`ChannelRecord`](../../src/common/channel.rs) |
| Registered / live membership | Registered sig-cluster tree height **3**; wallet live-member tree height **10**; these are different roots, not interchangeable | [`constants.rs`](../../src/constants.rs) |
| Balance storage | `Vec<TokenCiphertexts>` and `Vec<TokenPendingAdds>` with exactly 1024 rows; each row is 10-wide; recipient and Regev-digest arrays remain 1024-wide | [`BalanceState`](../../src/common/balance_state.rs) |
| Token registry | `[u32; 10]`, `token_count: u8` in `1..=10`; unique active base-token indices, canonical zero suffix, append-only local mapping | [`BalanceState`](../../src/common/balance_state.rs) |
| Money | Each encrypted cell / transfer plaintext is **u64**; aggregate `ChannelFund.amounts` is **`[U256; 10]`**. There is no global u64 channel-fund cap | [`channel.rs`](../../src/common/channel.rs), [`channel_credit_safety.rs`](../../src/channel_credit_safety.rs) |
| Other integers | `ChannelId` is u32; base transaction nonce is u32; state version, epoch and close-era counters are u64; `BlockNumber` is u63 | [`channel.rs`](../../src/common/channel.rs), [`u63.rs`](../../src/common/u63.rs), [`channel_id.rs`](../../src/common/channel_id.rs) |
| Regev | `n = 2048`, `q = 2,013,265,921`, `eta = 2`, plaintext modulus 256; a fresh u64 amount occupies 64 binary coefficients | [`params.rs`](../../src/regev/params.rs) |
| Homomorphic credits | Per-cell `pending_adds: u32`, maximum **64** before a verified refresh/fresh re-encryption. This digit/noise budget is separate from the u64 amount bound | [`params.rs`](../../src/regev/params.rs), [`channel_credit_safety.rs`](../../src/channel_credit_safety.rs) |
| H1 | Height-10 balance-slot tree; **104-element** `IMS2` leaf and **37-element** `IMB2` header. The leaf commits all 10 ciphertext digests/counters plus Regev digest and **5-limb** recipient | [`balance_state.rs`](../../src/common/balance_state.rs) |
| Fund commitment | `token_funds_digest` is the fixed **92-u32-word** IMTF preimage over the full registry, token count, and ten U256 amounts | [`channel.rs`](../../src/common/channel.rs) |
| Close-family public inputs | Close **103**, withdrawal claim **50**, cancel-close **29**, backing **26**; historical post-close claim **57**, but its extra-credit entry point is disabled | [`close_pis.rs`](../../src/circuits/channel/close_pis.rs), [`withdrawal_claim_pis.rs`](../../src/circuits/channel/withdrawal_claim_pis.rs), [`cancel_close_pis.rs`](../../src/circuits/channel/cancel_close_pis.rs), [`close_asset_backing_circuit.rs`](../../src/circuits/channel/close_asset_backing_circuit.rs), [`post_close_claim_pis.rs`](../../src/circuits/channel/post_close_claim_pis.rs) |

`pk_g` is the Falcon-512/Poseidon-H2P identity `Poseidon(IMFK || encode(h))`; `pk_b` is the
separate BabyBear sender-authorization key. The close/cancel/PW producer context uses
[`FalconBatchAggCircuit`](../../src/falcon_sig/batch.rs) through the current
[`wallet_core` proving contexts](../../src/wallet_core.rs), not the historical preimage-signature
scheme or its 16-leaf aggregation tree. `IMCM` is the fixed eight-slot, **66-u32-word** cosigner
commitment; delegates are excluded. The current distinctness tree has height **4**. Delegates
remain protected by the honest-sig-cluster transition checks, not by a close proof that independently
proves every historical delegate debit. Fully colluding members of a channel remain inside the
accepted within-channel trust model; this is not permission to spend another channel's backing.

### Admission before money movement or state-signature release

Production `setup-backing` and genesis require `CLI_RECIPIENT_SLOT_<slot>` for **every controlled
cosigner**, including initially zero-funded slots. The resolver rejects missing, malformed, zero,
and known synthetic test recipients before initial L1 spending. Only explicit insecure test-key
mode may use synthetic defaults. Configuration is not proof of key possession: the operator must
check that the participant can call the claim path from that EOA/smart wallet. Existing signed
recipients are never rewritten by changing environment variables. The claim recipient is opened
from the signed H1 balance leaf, including for delegates; the old deployer-asserted delegate
recipient-map description is not the current payout authority. See
[`resolve_cosigner_leaf_recipient`](../../src/bin/channel_member.rs) and
[the recipient setup procedure](../tasks/node-presign-recipient-setup.md).

Proposal builders for send, refresh, inter-channel debit/credit, deposit and token registration
return **unsigned channel-state proposals**. A11 sender authorization remains a separate transaction
authorization. Native explicit signing verifies the transition against its trusted predecessor and
record, including counts, preserved close-freeze era and operation-specific counters, before
releasing a state signature. Fresh/joined exit keys must be nondegenerate, nonpadding and distinct;
changed ciphertext cells must satisfy the existing withdrawal-claim shape. See
[`wallet_core.rs`](../../src/wallet_core.rs),
[`state_update_verifier.rs`](../../src/circuits/channel/state_update_verifier.rs), and
[`ledgered_state_signature_with`](../../src/bin/channel_member.rs).

After transition authentication, private [`ChannelCreditBounds`](../../src/channel_credit_safety.rs)
uses established nonnegative conservation, the token fund, known conservative bounds, and exact
own-key decryption to establish each changed cell's u64 bound. `None` means **unknown**, never zero.
These bounds are signer-private state, not peer assertions or new proof public inputs. Unknown
unchanged cells need not stop an unrelated operation. An affected cell can be conservatively
refused even when the intended credit is valid; a hidden-message refresh alone does not establish
the missing amount range. Neither ciphertext well-formedness nor a 64-add counter substitutes for
this cumulative range check.

The native signing ledger records `(channel, predecessor, controlled member slot)` together with
successor, purpose, optional plan, and exact signature bytes. An exact retry returns the recorded
signature; a sibling/purpose change is refused. Local state, key identity, ledgers and exit-kit
archive are trusted, rollback-protected storage assumptions, not adversarially editable evidence.
The browser's explicit `wallet_sign_state` / `wallet_cosign` exports have the corresponding worker
release fence: [`signature-release-ledger.mjs`](../../hosting/wallet/signature-release-ledger.mjs)
waits for strict IndexedDB `readwrite` **`oncomplete`** before returning the own member signature,
using `(pk_g, channelId, prevDigest)` as its key. Same-successor recovery returns exact saved bytes;
another successor is refused. Ordinary unsigned delegate proposals do not require this ledger.
Clearing browser storage, rolling it back, or using one key in another browser profile is not made
safe by this mechanism; a custom raw-WASM host needs an equivalent release boundary.

Host numeric input checks must precede WASM coercion: use exact decimal text / bigint for amounts
above JS's safe-integer range, and reject fractional, out-of-range or unsafe numeric slot/token/
channel/nonce values. Preserve the serialized u64 state text when substituting a saved browser
signature; parsing and reserializing the whole state through JS numbers is not lossless. Sources:
[`node/common/wallet.js`](../../node/common/wallet.js),
[`wasm_wallet.rs`](../../src/wasm_wallet.rs), and the browser release ledger.

### Refresh-free sends and cluster co-signing (2026-09-21)

Two changes to the contract above the E-1/E-2 statements and the signing locus:

- **Refresh is no longer a precondition of sending.** Every in-channel send, inter-channel
  debit and burn opens the sender's `before` ciphertext by **decryption under the sender's own
  Regev secret key** inside the STARK (`DecryptedDualKeyAir`, purposes `ChannelTxDecrypted`
  "IMDS" and `ChannelUpdateDecrypted` "IMDU", §E-1b/§E-2b). A position credited homomorphically
  (deposit import, received transfer) is spent directly; the fresh `after` re-encryption resets
  its digits, noise and `pending_adds` exactly as a refresh would. Relying parties accept the
  decrypted purpose or its witnessed twin for the same statement shape
  (`state_update_verifier::verify_transfer_proof_either`); the `pending_adds != 0 ⇒ refresh
  required` gates are retired. `RefreshAir` remains a maintenance operation (e.g. a pure receiver
  approaching the 64-add budget of §B-3), never a send prerequisite. Author cryptographic review
  of the new AIR is still required before production; the adversarial test battery
  (`src/regev/transfer_stark.rs`) is a guardrail, not a soundness proof.
- **The sig-cluster signs host-by-host.** `cosign` (one process signing every slot) is the
  single-host deployment only. The cluster deployment splits it into `cosign-partial` (gate + this
  host's slots, ledgered, head not advanced) and `cosign-merge` (each pooled signature verified
  individually, N-of-N head adopted) and exchanges signatures N-to-N over
  `/api/cluster/*` with a 1-minute close warning, a 5-minute halt and a 24-hour auto-close at the
  last fully signed state (§S). Only the in-channel send goes through the cluster round today;
  refresh, inter-channel, deposit import, token registration and member-set updates still sign on
  the receiving host.

### Deposit admission and durable recovery

Before an API-funded L1 deposit, resolve a rejoining contribution to its **exact original slot**
using pkG, pkB, Regev key and signed recipient; do not assume the newest/last slot. Validate amount
`1..=u64::MAX`, base token, candidate slot, add-count budget and cumulative recipient capacity.
Reserve capacity for the exact intent and all admitted candidate slots before signing the L1
transaction; concurrent local signatures must preserve that reserved room. A new reservation
invalidates cached admission of unsigned future heads. Only the deposit's own admission excludes
its reservation from double counting; it is not released while signatures are incomplete.

The trusted local live service supplies and persists the channel's one-time **deposit recipient**.
This bytes32 base-layer recipient is distinct from the participant's 20-byte **exit recipient**.
The operation journal and native reservation bind it; later native inspect/import may use it only
through that reservation's exact transaction hash. An arbitrary request recipient or a matching
tag is not channel ownership evidence. The unreserved legacy entrance retains its configured
backing-recipient check.

The ordering is: private-head admission → durable operation/reservation → sign and fsync exact
raw L1 bytes → broadcast/retry the same transaction → bind exact hash → verify canonical receipt
and exact deposited fields → durable producer/live receive → prepare import exit kit → verify and
N-of-N-sign both import successors → journal and roll forward the head/result/receipt together.
The completed reservation remains a tombstone, not reusable credit. The per-deposit completion
receipt permits result recovery without a second import. A timeout never authorizes a new payment;
an identical new payment needs a new request ID. Sources:
[`deposit-preflight.js`](../../api/lib/deposit-preflight.js),
[`deposit-spend.js`](../../api/lib/deposit-spend.js),
[`deposit-pipeline.js`](../../api/lib/deposit-pipeline.js),
[`deposit_capacity.rs`](../../src/bin/channel_member/deposit_capacity.rs),
[`deposit_recovery.rs`](../../src/bin/channel_member/deposit_recovery.rs), and
[`l1-deposit-outbox.js`](../../node/common/l1-deposit-outbox.js).

### Signer-independent exact-vector close

Let `H` be one authenticated N-of-N signed head and `funds(H)` its complete registry/fund vector.
Its exit kit carries a recursively verified Balance proof and the **whole-vector**
`CloseAssetBacking` proof/statement. The producer uses a private-state opening to construct that
proof; the opening is not public kit material. The backing circuit rebuilds the entire canonical
asset tree from the empty root and that one ten-token
vector: a scalar Balance commitment or an individually valid token opening is insufficient.
The composition key is exactly `(channel_id, settled_tx_chain, token_funds_digest)`.
**Full-B is the whole-state rule:** when `B` is the authenticated authorized-burn high-water state,
an older close candidate `V` cannot be installed. Use B itself (the exact identity at that ordering
key) or one strictly newer whole state, with a matching complete backing statement. No per-token
V/B mixing, min/max selection, or splicing amounts from different state generations is permitted.

The backing proof's finalized extended-state root can be later than, and different from, H's
signed channel-fund root. They are separately authenticated/finalized dependencies, not roots to
equate or freely substitute. The backing anchor is a canonical **u63** block number and must cover
the channel's current relevant post history before exit. Sources:
[`CloseAssetBackingCircuit`](../../src/circuits/channel/close_asset_backing_circuit.rs),
[`validate_signed_head_backing_composition`](../../src/public_close_prover.rs),
[`verify_close_asset_vector`](../../src/live_balance_service.rs), and
[`CloseFundingMaterializer`](../../contracts/src/CloseFundingMaterializer.sol).

From H plus the durable kit, the public prover/publisher requires **no new Falcon channel
signature or terminal child**. A participant first requests the guarded freeze; backing attestation,
close submission, guarded finalization and materialization are permissionless transactions with an
L1 gas signer. `attestSignedHeadBacking` verifies and records the exact compact backing proof before
close/PW admission; `materializeSignedHead` checks the finalized whole-vector statement, frozen
generation and current anchor, and atomically consumes the channel-exit latch before crediting the
vector. The old cooperative `CloseFunding` path remains refused. Keyless proving is not gasless
publication, and signature independence does not imply unconditional proof/data availability or
eventual inclusion.

Before a **new** participant close freeze, Node's `checkReadiness` prepares/reuses the same immutable
bundle as `advance`, then invokes the native read-only readiness check. It checks independent exact
H and deployment pins, both roots, anchor/finality, runtime/config linkage and the active era;
there is no L1 account, transaction journal or signing in this native check. An existing raw request
is recovered without imposing fresh readiness. The check and later transaction are not atomic:
contract rechecks remain necessary. The publisher journals attest/submit/finalize/materialize,
adopts an exact finalized permissionless winner when appropriate, and retains superseded local raw
transactions until their nonce outcome is reconciled. Sources:
[`public_close_publisher.rs`](../../src/public_close_publisher.rs),
[`public-close-publisher.js`](../../node/delegate/public-close-publisher.js), and
[`participant-close.js`](../../node/delegate/participant-close.js).

Manager finalization chooses one complete admissible head after the authorized-burn high-water
checks; it does not merge per-token caps from different heads. Replacement is strictly newer in
`(epoch, stateVersion)`; guarded finalization binds digest and lifetime request generation and
requires `now > deadline`. Cancellation can restore the freeze nonce, but not the lifetime request
generation or cancellation-version floor. After closure, `submitWithdrawalClaim` registers a
proof/nullifier-scoped per-token claim; exact backing pull and claim registration may occur in
either order. `claimWithdrawalCredit(bytes32)` pays only that recipient/token/amount record.
Lifetime accepted claims, live credit, recognized backing and actual payments are different counters.
`submitPostCloseClaim`, special close, and late outgoing debit correction are disabled, not extra
spendable credit paths. Sources:
[`ChannelSettlementManager.sol`](../../contracts/src/ChannelSettlementManager.sol) and
[`CloseFundingMaterializer.sol`](../../contracts/src/CloseFundingMaterializer.sol).

### Crash consistency and stored protocol versions

[`channel_member`](../../src/bin/channel_member.rs) writes private state schema **6**; the live
service snapshot is **4**, signed-head kit **1**, public backing/bundle **3**, deployment manifest
**4**, public publisher journal **6**, and completion result **3**. These are separate schemas,
not synonyms for MLE wire v3. Readiness has its own schema **1**. Required historical security
ledgers must remain present; missing range evidence is not invented during migration.

Deposit completion uses `.pending-deposit-import.json` plus `.deposit-import-receipts/`.
Burn publication uses [`.pending-burn-publication.json`](../../src/bin/channel_member/burn_recovery.rs)
to bind the signed head to `last_burn.json` / `burn_cosigned.json`; APIs run native recovery before
reading those results, so recovery does not sign another burn. Inter-channel operations hold both
channel process locks and refuse unresolved destination deposit/burn/inter WALs before source
signing. Their two-channel `.inter-transfer-journal` commits heads, results, and destination
`incoming_inter_transfer_recovery.json` before retirement. Destination recovery uses its saved
source input, producer receipt and live artifact, not the source's later-overwritten convenience
files. Destination kit verification resolves B's own archive/VD/backing directory, never A's cwd.

The [inter WAL codec](../../src/bin/channel_member/inter_transfer_recovery_codec.rs) writes version
**2**, checking the stored JSON value before typed decoding so HashSet iteration does not change
the checksum. Version 1 is read-only compatible only with its original compact journal bytes and
matching checksum. A checksum is corruption detection, not authority to replace signed state.
The L1 outboxes fsync exact decoded raw bytes before broadcast; uncertain outcomes preserve the
same intent/hash/nonce rather than signing anew. Preserve state, security ledgers, kits, journals,
recovery sidecars and browser ledger consistently; do not delete them or expire signing decisions
to restore availability. The
[node remediation handoff](../audit/audit05-09-2026-node-presign-remediation.md) records the repair
scope and migration precautions, not completion of the acceptance matrix.

### Deployment, proving policy, and remaining obligations

The runtime is **deployment-chain pinned, not 31337-only**:
[`IntmaxRollup.releaseRuntime`](../../contracts/src/IntmaxRollup.sol) requires
`block.chainid == deploymentChainId`, established with constructor-pinned verifier chain IDs.
The current [`PinnedMleVerifierV2`](../../contracts/lib/polygon-plonky2/mle/contracts/src/PinnedMleVerifierV2.sol)
uses immutable code-resident configuration and `allowedChainId`. Public publishers also bind the
SHA-pinned deployment's Manager, materializer, adapter/core code, configuration, protocol and session.
Chain 31337 is a local-development exception for explicitly permitted finality/short-window behavior,
not proof that a public deployment is release-ready. Some convenience API routes remain devnet-only;
the native pinned public publisher is the relevant public-chain interface.

The MLE cohort is **wire v3 / `MLEWHIR3`, target 105, inverse-rate 6 (`2^-6`), PoW 22, fold 4**.
Historical `V2` filenames/types do not mean wire v2. Old target-133/rate-4 proofs/configuration,
pre-repair fixtures and old deployments are not current acceptance evidence: regenerate and pin
the complete circuit/VK/config/proof/compact/deployment cohort together. The submodule describes
about 101.535 bits of aggregate generic work, not a literal unconditional failure probability or a
whole-system 128-bit claim; parent default Poseidon remains a separate approximately-95-bit bound.
External cryptographic and Fiat–Shamir/composition review remains required. See the
[current MLE guide](../../contracts/lib/polygon-plonky2/mle/README.md).

[Server-only Plonky2/MLE proving](../docs/proving-boundaries.md) is the deployment policy.
Client-side Regev/BabyBear Plonky3 proofs and native Falcon signing are distinct from that producer
work. **Implementation-policy mismatch still open:**
[`wasm_wallet::wallet_withdrawal_claim`](../../src/wasm_wallet.rs) constructs `WithdrawalClaimProver`
and calls `prove` / `prove_mle`, exposed as `withdrawalClaim` by
[`wallet-worker.js`](../../hosting/wallet/wallet-worker.js). Thus the shipped source cannot yet be
described as fully enforcing “no browser Plonky2 proving.” Move that work behind the intended
server/delegate boundary with its required private-witness design; do not fix the document by
claiming the export is absent. Browser member Falcon signing is supported under the durable
release fence above; the old “never signs in browser” rule is also not a description of this source.

Direct MSU remains retired: [`deprecated-msu`](../../Cargo.toml) isolates historical construction,
the production CLI/service refuse it, and the Manager exposes no direct mutation selector.
[Channel-change MSU](../tasks/channel-change-msu.md) is a TODO, not implemented migration authority.
The following likewise remain open:

- ordinary PW's automatic exact backing attestation/reuse integration; contract refusal when the
  attestation is absent is not an automatic successful PW workflow;
- authoritative watcher deposit classification across current **and historical** live recipients:
  distinguish required, proven unrelated, and unresolved. Handler errors, RPC ambiguity, reorgs or
  a mismatch with only the current rotating recipient do not authorize cursor advancement;
- full browser durability, real daemon, L1 posting/finality, multi-token and interrupted-recovery
  acceptance through latest-H exit and claim; plus measurement of the added host/persistence costs;
- actual source-to-model refinement and composition of admission/recovery/exit with the rest
  of the protocol. The [current Lean results](../audit/lean-current-safety.md), including
  finalization/fraud, replay fences and per-token payouts, do not prove all circuits,
  cryptographic primitives, durable-storage implementations, or unconditional liveness.

Trust in the configured local service/private store, the established setup/VK ceremony and KZG
setup, authenticated proof observations, honest-member admission and external transfer/finality
observations must remain explicit. This sync does not discharge them or rescue an already-signed
bad recipient, out-of-range balance, duplicate exit key, or unavailable historical kit.

## Historical implementation evolution — non-normative archive

Sections A–R below preserve the original migration rationale and dated checkpoints. Within this
archive, “current,” “authoritative,” “approved,” “implemented,” “GO,” and test counts refer only to
the stage being narrated. They do not override the current contract above, certify the present
code, reopen retired capabilities, or close today's release obligations. Old type sketches,
constants, proof layouts, selectors and machine-specific paths must not be copied into a current
integration. The companion notes retain the same historical status.

## A. Intentional differences from abstract2.md (historical migration)

### A-1. SIS commitment → Regev encryption (form change)

The current implementation's lattice layer (`src/lattice/proof_adapter.rs`) is a **SIS commitment**
(Q = 8,380,417, M = 128, N = 256, `LatticeCommitment` + `LatticeOpening`).
This spec replaces it with **Regev (Ring-LWE) encryption**.

- Source of port: `/Users/plasma/repos/SIS-lattice-paymentchannel` (despite the repository name,
  the contents are a Regev/Ring-LWE implementation. `crates/regev-adapter`, `crates/channel-types`,
  `crates/channel-state`, `regev_plonky3`).
- **The biggest formal change**: With SIS, the recipient cannot verify the amount unless they receive the opening (amount + randomness),
  and the source implementation also sent `ReceiverWitnessShare` (the full share of the encryption randomness `r`, `e1u/e1v/e2u/e2v`).
  By **encrypting to the recipient's `RegevPk`** with Regev, the recipient
  can verify the amount **simply by decrypting with their own secret key**. The **randomness share structure is abolished**
  (no type equivalent to `ReceiverWitnessShare` is carried over). The encryption randomness becomes a
  **STARK private witness** held only by the sender.
- Since a third party (a co-member who is neither the recipient nor the sender) cannot decrypt, verification
  relies on `channelTxZKP` / `channelUpdateZKP` (§E) — this is exactly as designed in abstract2.md §3.1.

### A-2. Small-block model: 1 channel = 1 small block = 1 tx

abstract2.md §2.3 is a model where "the BP **collects txs from multiple senders (channels)** to build a `TxV2Tree`, and binds to its
root (`tx_tree_root`)." The current implementation differs, and **this spec does not match abstract2.md on this point**
(user decision):

- **One small block is owned exclusively by one channel and effectively carries 1 tx** (1 block = 1 user / 1 tx).
- The BP concatenates a **sequence** of per-channel `SubBlock`s for each posting round and posts it to L1
  (`IntmaxRollup.postBlockAndSubmit`, `SubBlock[]`). Rather than "collecting multiple channels' txs into a single tree,"
  it "chains per-channel small blocks with a hash chain."
- Consequence 1: abstract2's `tx_tree_root` corresponds in this spec to **the `tx_tree_root` of
  one's own channel's small block** (`SmallBlockRootMessage.tx_tree_root`). The contents are effectively 1 leaf, and
  `TxV2MerkleProof` (inclusion proof) is a **trivial proof against a 1-leaf tree** (`MerkleInclusionProof` is
  formally retained).
- Consequence 2: `H2` (the transfer-type tag) holds **the `tx_tree_root` of one's own channel's small block** rather than
  abstract2's "the tx_tree_root of the entire block." The argument for atomicity (a single signature over authorization and subtraction)
  is unchanged (§D-3).
- Consequence 3: The ITS (intmax-tx-sender) role is, in the current implementation, served by **the member designated by `bp_member_slot`**
  (`ChannelRecord.bp_member_slot ∈ {0,1,2}`, whose slot's `member_sphincs_pubkey_hashes[bp_member_slot]`
  is the BP-duty key). Identification of the role is done by **member slot**, not by key hash (array index).

This difference does not weaken the safety properties (the 5 properties of abstract2.md §4): the inclusion proof degenerates because there is no aggregation tree, but
the structure of the signing target `hash(H1, H2)`, the chain binding, and the cap enforcement are all preserved.

### A-3. Signatures: SPHINCS+ → Poseidon-preimage ZK signature (two-key)

> **SUPERSEDED for the `pk_g` half — see §O (falcon-sig, 2026-08).** The Goldilocks
> Poseidon-preimage ZK signature described below (`SingleSigCircuit`, `pk_g = Poseidon(IMPG‖sk)`)
> and BOTH of its aggregators are DELETED and replaced by **Falcon-512 with Poseidon
> hash-to-point**; `pk_g` is redefined in place as `Poseidon(IMFK‖encode(h))`. The BabyBear `pk_b`
> half below is UNCHANGED. The rest of this subsection is retained as the historical record of the
> scheme §O replaced.

The member signatures this spec describes as SPHINCS+ (§B-4, §C, §D, §F) were **replaced by a
Poseidon-preimage ZK signature** (a ZK proof of knowledge of `sk` with `pk = Poseidon(sk)`, message
bound as a public input), and SPHINCS+ was removed entirely. Two keys per member, each native to its
proof system: a **Goldilocks** key `pk_g` (Plonky2 — channel-state agreement / close / small-block,
via `SingleSigCircuit`) and a **BabyBear** key `pk_b` (Plonky3 — the in-channel channel-tx sender
authorization, via `Poseidon2HashSigAir`). The member identity `pk_g` occupies the same `Bytes32`
slot the SPHINCS+ pubkey hash did; `pk_b` is added to `MemberLeaf`. The full delta (validity
`bp_sig_chain` accumulator, close list-proof consumer, two-key A11 binding, wallet Goldilocks
co-signing, SPHINCS+ removal) is **D8 in detail2-implementation-notes.md**; threat model in
`doc/tasks/poseidon-signature-threat-model.md`.

**Aggregation shape (updated by D13):** the `SingleSigCircuit` proofs feed two aggregators, one per
consumer path. The **validity** `bp_sig_chain` path keeps the linear recursive hash-chain
**`ListCircuit`** (`src/poseidon_sig/list.rs`, D8). The **close / cancel-close** path no longer
consumes the `ListCircuit`: cosigner single-sig proofs are aggregated PAIRWISE per level by the
**binary-tree aggregated sign-zkp** (`src/poseidon_sig/aggregate.rs`, `AggLevelCircuit` ×
`AGG_LEVELS = 4`, pk-slot widths 2 → 4 → 8 → 16) whose public inputs expose
`[message(8), signer_count(1), pk list (2^k × 8)]`; the close/cancel circuits recursively verify ONE
level-4 proof and wire the cosigner key vector directly from its PI signer list (§F-3, D13 in
detail2-implementation-notes.md).

---

## B. Cryptographic primitives and parameters

### B-1. Regev (Ring-LWE) parameters

Follows the `channel_params` of the port source `SIS-lattice-paymentchannel/crates/regev-adapter`:

| Parameter | Value | Description |
|---|---|---|
| `q` (residue field) | BabyBear `2^31 − 2^27 + 1 = 2,013,265,921` | Matches the native field of the Plonky3 STARK |
| `n` (ring degree) | **2048** (power of 2, 128-bit RLWE target) | Number of coefficients of one polynomial |
| `eta` (noise) | 2 | CBD (centered binomial) parameter |
| `plain_bits` | 8 | Plaintext bits per coefficient |
| Amount type | `u64` | Encoded into 8 bits × 8 coefficients (remaining coefficients are 0) *(superseded by D1: 1 bit/coefficient × 64 coefficients, t=256)* |

### B-2. Types and sizes

```rust
/// Each member's Regev public key (public within the channel, fixed at channel creation)
pub struct RegevPk {
    pub a: Vec<u32>,   // n coefficients (mod q)
    pub b: Vec<u32>,   // n coefficients; b = a·s + e
}
/// Regev ciphertext (abstract2.md's `LatticeCt`)
pub struct RegevCiphertext {
    pub c1: Vec<u32>,  // n coefficients (mod q)
    pub c2: Vec<u32>,  // n coefficients (mod q)
}
```

| Item | Raw binary size (n = 2048) |
|---|---|
| `RegevPk` | 2 × 2048 × 4 = **16,384 bytes** |
| `RegevCiphertext` | 2 × 2048 × 4 = **16,384 bytes** |
| `encBalances` (per active slot/token) | **16,384 bytes** (slot capacity `MAX_CHANNEL_MEMBERS` = 1024; padding uses the canonical compact representation) |
| Decryption key `RegevSk { s: Vec<i8> }` | 2,048 bytes (held only by the owner. Does not appear in any struct) |

`RegevCiphertext::digest() = hash_words([REGEV_CT_DOMAIN, c1.len() as u32, c1…, c2…]) → Bytes32`
(keccak256. What enters state or the PI is always this digest).

### B-3. Homomorphic addition and noise budget (A5)

> Historical parameter rationale. The n=128 / approximately-120× noise-margin figures below are
> retired. Current n=2048 retains the 64-add policy with the bound documented in `regev/params.rs`
> (approximately 7.5× worst-case noise margin); cumulative u64 admission is a separate host check.

- `ct_a + ct_b` (component-wise mod q addition) corresponds to plaintext addition. Applying a delta to the recipient-side balance
  (abstract2.md §3.2 step 3 "add `encAmount` to the recipient's ct") uses this.
- **The sender's own balance update is fresh re-encryption, not homomorphic**: the sender **re-encrypts** the updated balance
  **anew**, and `channelTxZKP` / `channelUpdateZKP`
  proves "the plaintext of the old ct = the plaintext of the new ct + the delta plaintext" (isomorphic to the source transfer STARK).
  This way, the sender-side ct's noise does not accumulate.
- The recipient-side ct accumulates noise via homomorphic addition. It is mandatory that **for every `MAX_HOMO_ADDS_BEFORE_REFRESH` additions,
  the recipient themselves performs a fresh re-encryption (refresh) in the version where they next author state**.
  The validity of refresh is proved by a separate `RefreshAir` (a combined Decrypt+Encrypt AIR proving plaintext
  equality in-circuit), **not** by `channelTxZKP` with delta = 0 (see D2, `src/regev/transfer_stark.rs`).
  > **2026-09-21:** a refresh is no longer required *before sending*. The decrypted send/update
  > (§E-1b/§E-2b) opens the accumulated ciphertext in-circuit and the fresh `after` resets the
  > position, so every send counts as the re-encryption this rule asks for. The 64-add budget is
  > still enforced on the receiving side (D3); `RefreshAir` stays available for a slot that only
  > receives.
- Noise condition (decryption correctness): the ∞-norm of the accumulated noise must be less than `q / 2^(plain_bits+1)`.
  `MAX_HOMO_ADDS_BEFORE_REFRESH` is derived from the per-ct noise upper bound of CBD (eta=2).
  > **SECURITY (approved)**: `MAX_HOMO_ADDS_BEFORE_REFRESH = 64` is an **approved** security parameter
  > (see D1 in detail2-implementation-notes.md and `doc/docs/regev-noise-analysis.md`: worst-case digit headroom ≈ 4×,
  > noise headroom ≈ 120×, zero decryption-failure within the budget for eta=2 / n=128 / q=BabyBear).
  > Do not change it silently (CLAUDE.md general rule).

### B-4. ZK proof systems

| Proof | Backend | Port source / existing |
|---|---|---|
| `channelTxZKP` / `channelUpdateZKP` / refresh proof | **Plonky3 STARK** (BabyBear) | The transfer STARK of `SIS-lattice-paymentchannel` (proves `before = after + delta` as an n-bit integer + well-formedness of 3 cts). **A range proof is built in via the ripple-carry constraint where no digit borrow occurs**, making underflow (negative balance) constructively impossible |
| `withdrawClaimZKP` | Plonky3 STARK | A degenerate form of the above ("the plaintext of my own ct = the public withdrawal amount") |
| `balanceProof` / `validityProof` | Plonky2 (existing) | `src/circuits/balance/`, `src/circuits/validity/` (changes are in §F) |
| close / claim PI binding | Plonky2 (existing) | `src/circuits/channel/close_circuit.rs` and others |
| Signature | ~~SPHINCS+ (Poseidon)~~ → ~~Poseidon-preimage ZK sig~~ → **Falcon-512 / Poseidon H2P (`pk_g`) + BabyBear `pk_b`** | **SUPERSEDED — see §O.** `pk_g` is now a native **Falcon-512** signature (Poseidon hash-to-point, IMFH; identity `Poseidon(IMFK‖encode(h))`), verified natively off-circuit for the wallet co-sign and IN-circuit by `falcon_sig::agg::FalconAggCircuit` (close/cancel) and by the validity list step. `pk_b` (Plonky3 `Poseidon2HashSigAir`) is unchanged. Historical record follows: D8 (+ D13) in detail2-implementation-notes.md — Goldilocks `pk_g` (Plonky2 `SingleSigCircuit`; validity path aggregated by the recursive `ListCircuit`, close/cancel path by the binary-tree `AggLevelCircuit` sign-zkp, D13) for state/close/IMSB; BabyBear `pk_b` (Plonky3 `Poseidon2HashSigAir`) for the channel-tx sender. SPHINCS+ fully removed. |

`ChannelProofEnvelope { role, backend, proof }` (`state_update_verifier.rs:20-24`) is retained, and
`ProofBackend::Plonky3` is used to carry the lattice STARKs (as in the existing design).

---

## C. Data structures (updated version)

Legend: **[New]** = new type / **[Chg]** = change to existing type / **[Keep]** = unchanged / **[Del]** = abolished.

### C-1. [Del] SIS-related

- `LatticeCommitment` (`src/common/channel.rs:293-305`) → replaced by `RegevCiphertext`.
- `LatticeOpening` (`channel.rs:309-313`) → **abolished**. A structure passing amount/randomness to the counterparty is
  unnecessary with Regev (§A-1). Verification has only 2 paths: (a) the recipient's decryption, (b) STARK proof.
- `LatticeBindingVerifier` trait / `LatticeProofPurpose` (`state_update_verifier.rs:88-102`) →
  renamed and retyped to the `RegevProofVerifier` trait (§E-4).

### C-2. [New] BalanceState (the core of abstract2.md §2.1)

> Historical single-token sketch, not a current Rust/JSON schema. Current `delegate_count` is u16,
> token matrices are heap-backed 1024×10, and the leaf-bound recipient is mandatory; see the
> current types table above. The old `MAX_COSIGNERS = 16` text below records D12, not today's cap.

```rust
/// abstract2.md: BalanceState { encBalances, settledTxChain, stateVersion }
pub struct BalanceState {
    pub channel_id: ChannelId,
    pub member_count: u8,                                  // co-signing COSIGNERS = slot 0..member_count (2..=MAX_SIG_CLUSTER = 8 (2026-08-24, was MAX_COSIGNERS = 16), D6/D12)
    pub delegate_count: u8,                                // DELEGATES = slot member_count..member_count+delegate_count (§L, D9)
    pub enc_balances: [RegevCiphertext; MAX_CHANNEL_MEMBERS],   // 1024 balance slots; active = cosigners+delegates, padding default/zero
    pub regev_pk_digests: [Bytes32; MAX_CHANNEL_MEMBERS],  // per-slot Regev pk Poseidon digests (decryption Stage 1); padding = default
    pub settled_tx_chain: Bytes32,                          // genesis = 0x00…00
    pub settled_tx_accumulator_root: Bytes32,               // Stage 3: settled-tx Merkle accumulator root (post-close source-tx anchoring)
    pub state_version: u64,                                 // +1 on both intra- and inter-channel updates
    pub pending_adds: [u32; MAX_CHANNEL_MEMBERS],           // per-slot homomorphic-add counters (D3); padding = 0
}
impl BalanceState {
    /// H1 = hash(BalanceState). Does not include the proof object (all components known at signing time).
    /// D14 ("tree in storage, root in state"): H1 is a FIXED-width 26-element Poseidon header over the
    /// ROOT of the balance-slot Poseidon Merkle tree — the flat keccak over all slots is retired:
    ///
    ///   leaf_i = Poseidon([BALANCE_SLOT_LEAF_DOMAIN "IMSL", regev_pk_digests[i] (8 u32 limbs),
    ///                      enc_balances[i].digest() (8 u32 limbs), pending_adds[i] (1 u32 limb)])
    ///            // 18 elements, fixed width; leaf INDEX i = Merkle position (slot order bound structurally)
    ///   slot_tree_root = height-BALANCE_SLOT_TREE_HEIGHT (= 10 = log2(1024), const-asserted)
    ///                    IncrementalMerkleTree<PoseidonHashOut> root over ALL 1024 leaves
    ///   H1 = Bytes32::from(Poseidon([BALANCE_STATE_DOMAIN "IMBS", channel_id, member_count, delegate_count,
    ///                                slot_tree_root (4 Goldilocks elements), settled_tx_chain (8),
    ///                                settled_tx_accumulator_root (8), split_u64(state_version) (hi, lo)]))
    ///
    /// delegate_count sits IMMEDIATELY AFTER member_count (§L, D9). Semantics unchanged — the same
    /// values are bound and H1 keeps the same signing role; only the commitment STRUCTURE became a
    /// tree root, O(1) in-circuit regardless of slot capacity (src/common/balance_state.rs;
    /// threat model tasks/h1-poseidon-root-threat-model.md; D14).
    pub fn h1(&self) -> Bytes32 { … }
}
/// Agreement / signing target (abstract2.md: balanceStateHash = hash(H1, H2))
pub fn balance_state_hash(h1: Bytes32, h2: Bytes32) -> Bytes32 {
    // [BALANCE_STATE_HASH_DOMAIN, h1, h2] → keccak256
}
```

- **Balance-slot capacity vs cosigners (`MAX_CHANNEL_MEMBERS = 1024`, `MAX_SIG_CLUSTER = 8` (was `MAX_COSIGNERS = 16`); pad-to-MAX,
  §G, D6 → D12).** The two roles D6's single `MAX_CHANNEL_MEMBERS = 16` conflated are now separate
  constants: `MAX_CHANNEL_MEMBERS = 1024` is the BALANCE-SLOT capacity (cosigners + delegates +
  padding) sizing `enc_balances` / `regev_pk_digests` / `pending_adds` / `ChannelRecord.member_pk_gs`
  (`[_; 1024]`, serde-big-array), while `MAX_COSIGNERS = 16` caps the N-of-N close SIGNERS:
  `member_count: u8` (`2 <= member_count <= MAX_COSIGNERS`) counts cosigners only, and
  `member_count + delegate_count <= MAX_CHANNEL_MEMBERS`. The circuit does not branch — balance/H1
  work covers all 1024 slots (via the D14 slot-tree root), and all close/cancel SIGNATURE work
  (member_set_commitment, aggregated sign-zkp pk slots, A5 distinctness, active-bits gating) is sized
  `MAX_COSIGNERS`. A participant is referenced by **slot** as the array index into `enc_balances` /
  `pending_adds` (D3). **A member's identity is the `pk_g` pubkey (`Bytes32`)** (DA → D8), and the
  slot is merely an array position. `ChannelRecord::validate()` requires that active slots be
  **distinct non-zero hashes**, that padding slots be default, and that
  `bp_member_slot < member_count`. The channel→member binding tree is the `MemberTree`
  (`src/common/trees/key_tree.rs`, height `MEMBER_TREE_HEIGHT = 10` = 1024 leaves =
  `MAX_CHANNEL_MEMBERS`), whose root is `ChannelLeaf.member_pubkeys_root` (§G, DB).
  *(abstract2.md §2.1's `[(Address,RegevPk);3]` is fixed at 3 people, so N members is a spec deviation.
  The authoritative deltas are D6 and D12 in detail2-implementation-notes.md.)*
- Range of `H2`: `0x00…00` (intra-channel) / one's own small block's `tx_tree_root` (inter-channel, §A-2).
  **Reservation of `H2 = 0`**: on the inter-channel path, `tx_tree_root == 0` is rejected at verification (guaranteeing that the
  empty-tree root does not become 0 via the keccak-based tree. The implementation answer to v2 audit finding 4).

### C-3. [Chg] ChannelState

Change `ChannelState` of `src/common/channel.rs:431-470` as follows:

| Field | Treatment |
|---|---|
| `channel_id, epoch, small_block_number, close_freeze_nonce` | [Keep] |
| `channel_fund: ChannelFund` | [Keep] (the source of `withdrawCap`) |
| `channel_balance_root: Bytes32` | [Chg] **replaced by `balance_state: BalanceState`** (holds the body rather than the root. Uses `h1()` at L1 submission) |
| `shared_native_nullifier_root, unallocated_confirmed_incoming, prev_digest, digest` | [Keep] |
| `member_signatures: Vec<MemberSignature>` | [Chg] the signing target changes (below) + `MemberSignature` retyped: `{ member_slot: u8, sphincs_pubkey_hash: Bytes32, signature }` (old `key_id`/`user_id`/`key_condition_proof` abolished, DA/DC). N-of-N (3/3): `signatures[i].member_slot == i` and `signatures[i].sphincs_pubkey_hash == record.member_sphincs_pubkey_hashes[i]` |
| **(new) `h2_tag: Bytes32`** | The tag used to finalize this version. Intra-channel update = 0 |

Change the preimage of `ChannelState::signing_digest()` (domain `0x494d4348` "IMCH"):
put **`balance_state.h1()`** in the position of `channel_balance_root`, and append **`h2_tag`** and
**`split_u64(balance_state.state_version)`** at the end. Thereby
**`signing_digest()` itself embeds `hash(H1, H2)`**, and `member_signatures`
realizes abstract2.md §3.1's "all-3 signatures over `hash(H1, H2)`."

- `state_version` is a **monotonic counter independent of epoch and small_block_number** (since intra-channel transfers
  do not create small blocks, versions cannot be counted by `small_block_number`).
- Invariant: `state_version` strictly increases, 1 version 1 state (challenge order is §H-4).

### C-4. [Chg] ChannelBalance

```rust
pub struct ChannelBalance {
    pub channel_id: ChannelId,
    pub sphincs_pubkey_hash: Bytes32,          // old: user_id: UserId (DA: member identification = public-key hash)
    pub balance_ciphertext: RegevCiphertext,   // old: balance_commitment: LatticeCommitment
}
```

### C-5. [Chg] Pay → ChannelTx (intra-channel transfer, abstract2.md §2.2)

Retype existing `Pay` (`channel.rs:501-529`):

```rust
pub struct ChannelTx {
    pub recipient_sphincs_pubkey_hash: Bytes32,  // old: recipient_user_id: UserId (DA)
    pub enc_amount: RegevCiphertext,        // encrypted with the recipient's RegevPk (the sent amount)
    pub nonce: Bytes32,                     // one-time random value
    pub channel_tx_zkp: ChannelProofEnvelope,  // mandatory (co-sign rejected if absent)
    pub sender_sphincs_pubkey_hash: Bytes32,     // old: sender_user_id: UserId (DA)
    pub sender_signature: SignatureBytes,
}
```

- `signing_digest` (domain `PAY_DOMAIN = 0x494d5041` retained): change the preimage to
  `[domain, channel_id, prev_state_digest, enc_amount.digest(), nonce, sender_sphincs_pubkey_hash(8), recipient_sphincs_pubkey_hash(8)]`
  (the member portion is 2→8 limbs each).
- Old `Pay.amount: LatticeCommitment` (which assumed an attached plaintext opening) is abolished. Only the recipient learns the amount by decryption.

### C-6. [Chg] InterChannelTx (inter-channel transfer, corresponds to abstract2.md §2.3 `TxAux`)

Retype existing `InterChannelTx` (`channel.rs:541-597`). Map abstract2's `TxAux` /
`TxLeafHash` / `channelUpdateZKP` to the current implementation's fields:

| abstract2.md | This spec's field | Treatment |
|---|---|---|
| `senderAddr / recipientAddr` | `source_sphincs_pubkey_hash: Bytes32` / `receiver_deltas[i].receiver_sphincs_pubkey_hash: Bytes32` | [Chg] (old `UserId` → public-key hash, DA) |
| `senderChannelId / recipientChannelId` | `source_channel_id / destination_channel_id` | [Keep] |
| `senderDelta : LatticeCt` | **(new) `sender_delta_ct: RegevCiphertext`** (addressed to the sender's `RegevPk`, negative-value plaintext) | replaces old `sender_amount: LatticeCommitment` |
| `recipientDelta : LatticeCt` | retype the `amount` of `receiver_deltas: Vec<ReceiverBalanceDelta>` to `RegevCiphertext` (addressed to the recipient's `RegevPk`, positive-value plaintext) | [Chg] |
| `channelUpdateZKP` | **(new) `channel_update_zkp: ChannelProofEnvelope`** (consolidates old `sender_balance_update_proof` / `receiver_update_proof`) | [Chg] |
| `TxV2MerkleProof` | `tx_inclusion_proof: MerkleInclusionProof` (1-leaf tree, §A-2) | [Keep] |
| (binding to tx_tree_root) | `signed_small_block: SignedSmallBlock` | [Keep] |
| `tx_hash` etc. | `seal, tx_hash, intmax_transfer_commitment, recipient_memo, transport_proof` | [Keep] |

> **`transport_proof` is DEPRECATED (no separate verifier).** Per the abstract2.md §3.4 design note,
> the inter-channel transfer carries no bundled transport proof: the receiving channel verifies
> settlement DIRECTLY against L1 (`flowReceive3` step 1 — `TxV2MerkleProof` inclusion of the
> `tx_tree_root` in a validity-proven block + the sender's `balanceProof`), and the small-block
> `channelStateSig` (`hash(H1', tx_tree_root)`) is verified by the REAL validity proof
> (`update_channel_tree` / `bp_sig_chain`, §F-2). The `transport_proof` field is retained only as a
> vestigial carrier and is NOT verified by a dedicated `ChannelProofVerifier` (verified end-to-end in
> `tests/small_block_sig_validity.rs`).
>
> Inclusion liveness is handled by member incentive, NOT a proof. Because a channel's members only
> sign `hash(H1', tx_tree_root)` when they intend the small block to be included on L1:
> 1. **a member does not sign the next intmax-native tx until the current one is included** (one state
>    per version — never advance on an unconfirmed state); and
> 2. **if no one (the BP) includes the small block, a member includes it themselves** (force-include /
>    self-post the small block to L1).
>
> This is the standard rollup force-inclusion argument; it costs only liveness (eventual inclusion),
> never safety — the receiver only ever applies a *confirmed* incoming (verified on L1; absent ⇒ the
> sender is ignored), so delay/censorship reflects no incorrect balance.

**[New] TxLeafHash** (abstract2.md §2.3. The update unit of `settledTxChain`):

```rust
pub fn tx_leaf_hash(tx: &InterChannelTx) -> Bytes32 {
    // hash( hash(TX_LEAF_DOMAIN, source_sphincs_pubkey_hash(8), sender_delta_ct.digest()),
    //       hash(TX_LEAF_DOMAIN, receiver_sphincs_pubkey_hash(8), receiver_delta_ct.digest()) )
    // → binds the sender-side and receiver-side public-key hashes (DA) and the lattice balance changes on both wings (member portion 2→8 limbs)
}
```

`settledTxChain` update rule (abstract2.md §2.1):
- Inter-channel transfer (both send and receive): `chain' = hash_words([SETTLED_TX_CHAIN_DOMAIN, chain, tx_leaf_hash])`
- Deposit ingestion: `chain' = hash_words([SETTLED_TX_CHAIN_DOMAIN, chain, deposit_hash])`
- Intra-channel transfer: unchanged.
- `TxLeafHash` is known at signing time (flowSend1 step 6 = small block signing time) and is the canonical
  settle/tx identity the chain uses. The base-layer nullifier (`SettledTransfer::nullifier()`, now binding
  `nonce` — settlement-independent, F-WD-2) remains dedicated to double-settle / anti-replay prevention in the
  base layer: two settlements of one deduction now collide to the same nullifier (as in the note of abstract2.md §2.1).

### C-7. [Chg] SmallBlockRootMessage (the carrier of H1/H2)

`channel.rs:324-352`. The field set is retained and the **meaning is redefined**:

| Field | Redefinition |
|---|---|
| `tx_tree_root` | **= `H2`**. In an inter-channel transfer small block, the root of that 1-tx tree (≠ 0). |
| `state_commitment_root` | **= `H1'`** (the `h1()` of the post-subtraction `BalanceState`). Replaced from the old "root of the lattice commitment group." |
| Other fields | [Chg] `bp_key_id` → **`bp_member_slot: u8` + `bp_sphincs_pubkey_hash: Bytes32`** (DA, in lockstep with `sphincs_sig.rs`). The rest (`channel_id, small_block_number, prev_small_block_root, medium_epoch_hint, close_freeze_nonce`) is [Keep] |

The preimage of `signing_digest()` (domain `0x494d5342` "IMSB") updates only the member portion
(`bp_key_id` → `bp_member_slot`(1)+`bp_sphincs_pubkey_hash`(8)), but the structure **containing both** `tx_tree_root` (= H2) and
`state_commitment_root` (= H1′) is unchanged, so this single signature realizes abstract2.md §3.3.2's
`hash(H1', H2 = tx_tree_root)` signature (= `channelStateSig`, structural atomicity).
**There is no signing target that signs only one side** (inseparable, the structuring of the abstract2.md §3.4 invariant).

`SignedSmallBlock` (`channel.rs:365-403`) is [Keep].

### C-8. [Chg] Close-related (abstract2.md §2.4)

| Type | Treatment |
|---|---|
| `CloseWithdrawal` (`channel.rs:601-626`) | [Chg] `final_channel_balance_root` → **`final_balance_state_h1: Bytes32`**. `burn_amount = withdrawCap` (abstract2's `closeBurnTx.amount`). |
| `CloseIntent` (`channel.rs:615-`) | [Chg] the same replacement + add **(new) `final_state_version: u64`** and **(new) `final_settled_tx_chain: Bytes32`** (for L1 reconciliation). Append both to the `signing_digest` (IMCI) preimage. |
| `WithdrawalClaim` (`channel.rs:727-`) | [Chg] `user_amount: LatticeCommitment` → `user_amount_ct: RegevCiphertext`. Member identification `user_id: UserId` → **`member_sphincs_pubkey_hash: Bytes32`** (DA). `claim_proof` = `withdrawClaimZKP` (§E-3). Nullifier derivation is **`[IMCW, close_intent_digest(8), member_sphincs_pubkey_hash(8)]`** (collision-safe since close_intent_digest embeds channel_id, member portion 2→8 limbs). |
| `PostCloseIncomingClaim` (`channel.rs:856-`) | [Chg] make `receiver_amount` a `RegevCiphertext`. Member identification `receiver_user_id: UserId` → **`receiver_sphincs_pubkey_hash: Bytes32`** (DA). Implementation of abstract2.md §3.5.5 `claimLateTx`. `lateBalanceProof` is verified inside `claim_proof`, and is managed as a **separate variable** from `finalBalanceProof` (also separated in contract storage via the `usedSharedNativeNullifiers` family). |
| `SpecialClose` / `CancelClose` | [Chg] hash only the member identifiers to pubkey hashes (`SpecialClose`'s censorship BP designation = `offending_bp_member_slot: u8` + `offending_bp_sphincs_pubkey_hash: Bytes32`, DA). Otherwise [Keep] (additional defenses outside the scope of abstract2.md. Retained since they are additions that do not weaken the safety properties. §I-3) |

**[New] close PI's `member_set_commitment` (F5 SECURITY, DB; D6/D12)**: the full channel-close circuit
**exposes `member_set_commitment = keccak([CLOSE_MEMBER_SET_DOMAIN, member_count(1), pk_g_0(8) …
pk_g_15(8)])`** — a fixed **`MAX_COSIGNERS` = 16-slot** keccak (2 + 16×8 = 130 u32 words, padding
slots zeroed, D6; `close_member_set_commitment`, domain `CLOSE_MEMBER_SET_DOMAIN = 0x494d434d`
"IMCM") over the **COSIGNERS only** — the array is sized by the cosigner cap, NOT the 1024
balance-slot capacity; delegates never enter it (D12) (code: `src/common/channel.rs`,
`close_member_set_commitment`). In the current 95-limb close-PI layout it **occupies limbs 85–92**,
with `member_count` at limb 93 and `delegate_count` at limb 94 (`close_pis.rs`, §F-3). L1
(`ChannelSettlementManager`) recomputes the same keccak from the registered cosigner `pk_g`s +
`member_count` and reconciles, **binding that the keys whose N-of-N signatures were verified inside the circuit
are the registered member set of that channel** (excluding signature substitution by non-member keys).
The Solidity mirror's internal 16-slot form is byte-identical to the Rust `MAX_COSIGNERS` form
(shared vector `close_member_set_commitment_matches_solidity_shared_vector`), so this commitment
survives the D12 split unchanged.

### C-9. [Keep/Del] base-layer types

`Transfer` (`transfer.rs:34-42`, TRANSFER_LEN = 25), `SettledTransfer` (including the nullifier),
`Block`, `PublicState`, `ValidityPublicInputs`, `ChannelId` — all unchanged.

- **[Del]** `KeyId` / `UserId` / `KeyRecord` (and `KEY_RECORD_DOMAIN`) were **deleted** (DA/DC, §D5).
  These were remnants of the old 2-layer identity (multisig/threshold), and were inconsistent with abstract2.md §1 ("1 person 1 key 1 account,
  address == pubkey"). Member identifiers are unified across all layers to the **SPHINCS+ public-key hash `Bytes32`**.
- **[Chg]** `ChannelRecord` / `MemberSignature` are hashed to pubkey hashes as in §C-3 / §H-1 (not unchanged).
- **`Block.key_ids`**: the field name is retained, but the meaning is reinterpreted as **"active member slots (0/1/2)"**
  (it remains in the block hash preimage). It represents the set of slots of members who signed in that block, not the multisig
  key identity.

### C-10. [New] Mid-Channel L1 Deposit Import

An L1 deposit can be folded into an already-open channel, increasing `channelFund.amount` and
crediting the depositing member's encrypted balance — the channel stays `Active` throughout
(the symmetric ENTRY half of partial withdrawal §GAP2).

**Transition kind:** `ChannelTransitionKind::L1DepositImport` (no Plonky3 STARK, no Plonky2 transport
proof — trust anchor is the `receive_deposit` balance proof verified via `verify_channel_backing`).

**Two-step state transition** (mirrors `InterChannelFundImport` + `ReceiverBundleApply`):

| Step | `channel_fund.amount` | `unallocated` | `enc_balances` | `settledTxChain` | `shared_native_nullifier_root` |
|------|----------------------|---------------|----------------|-----------------|-------------------------------|
| 1 (fund import) | `+= amount` | `+= amount` | unchanged | push `deposit.nullifier()` | advances |
| 2 (bundle apply) | unchanged | `-= amount` | `recipient_slot += delta` | push `deposit.nullifier()` | unchanged |

**Trust anchor:** The `receive_deposit` balance proof (recursive IVC, `ReceiveDepositCircuit`)
proves Merkle inclusion of the deposit in the finalized `deposit_tree_root` (T1 mitigation) and
inserts `Deposit::nullifier()` into the nullifier tree (T2 double-fold mitigation, C15 verified).
`verify_channel_backing` binds the balance proof's `settled_tx_chain` to the channel state's chain.

**Transition digest:** `l1_deposit_import_digest = keccak([IMLD, channel_id, deposit_nullifier,
amount_lo, amount_hi, depositor_slot])` (domain `0x494d4c44` "IMLD", `channel.rs`).

**Verification (`L1DepositImportUpdateWitness::verify()`):** identical to
`InterChannelFundImportUpdateWitness::verify()` EXCEPT no transport proof verification — the
balance proof is the external trust anchor (not an inter-channel transport envelope).

**Co-signer gate:** `verify_l1_deposit_import_transition()` — every N-of-N co-signer MUST call
this before signing the proposed state. Fail-closed.

**`settledTxChain` update rule** (extending §C-6 line 300): Mid-channel deposit import uses the
same rule as deposit ingestion: `chain' = hash_words([SETTLED_TX_CHAIN_DOMAIN, chain,
deposit_nullifier])`.

---

## D. Unification of signing targets (abstract2.md §3.1 / §3.3.2)

> Historical signing-target table. Its signature-free `deposit / closeBurnTx` row does not
> authorize an unsigned channel-state import or the retired cooperative terminal child. Current
> imports have verified N-of-N successors; full close consumes existing H plus its backing kit.

| Update kind | Signing target | H2 | Implementation signing digest |
|---|---|---|---|
| Intra-channel transfer (`ChannelTx`) | `hash(H1', 0)` | `0x00…00` | `ChannelState::signing_digest()` (h2_tag = 0, §C-3) |
| Inter-channel transfer (sender side) | `hash(H1', tx_tree_root)` | the small block's `tx_tree_root` | `SmallBlockRootMessage::signing_digest()` (§C-7) |
| Inter-channel receipt (receiver side) | `hash(H1', 0)` | `0x00…00` | `ChannelState::signing_digest()` (the receiver side does not create a small block) |
| deposit / closeBurnTx | **No signature required** (abstract2.md §3.3.2b) | — | Accepted within the validity / close circuit |
| Mid-channel L1 deposit import | `hash(H1', 0)` | `0x00…00` | `ChannelState::signing_digest()` — N-of-N co-sign the post-import state (§C-10) |

- **D-3 (atomicity)**: In an inter-channel transfer, a signature that "authorizes the transfer but refuses the subtraction" **does not exist by definition**, because
  `H1'` (post-subtraction state) and `H2` (tx_tree_root) coexist in a single preimage in the signing target.
  The validity / confirmation circuit verifies this signature as a **substitute** for a signature over tx_tree_root
  (constraining that the `H2` component = the `tx_tree_root` of the posted small block. §F-2).
- **D-4 (cosigner aggregation shape, D13)** — **SUPERSEDED by §O-3 (falcon-sig):** the STATEMENT and
  PI layout below survive verbatim, but the leaves are now **Falcon signatures verified in-circuit**
  by `falcon_sig::agg::FalconAggCircuit` (leaf 2^16 + 4 levels at 2^14) instead of recursively
  verified `SingleSigCircuit` proofs, and the validity `ListCircuit` step likewise verifies a Falcon
  signature directly. Everything else — left-packing enforced in-circuit, `signer_count` counting
  verified leaves, close/cancel binding `message`/`signer_count` and wiring the pk vector into IMCM
  + the A5 chain with zero witnessed freedom — is unchanged. Historical text:
  each cosigner produces ONE `SingleSigCircuit` sign-zkp
  over the common message (the recomputed IMCH digest for close/cancel); the proofs are aggregated
  PAIRWISE per level by `poseidon_sig::aggregate::AggLevelCircuit` (one circuit per level,
  `AGG_LEVELS = 4`, pk-slot widths 2 → 4 → 8 → 16 = `MAX_AGG_SIGNERS`), each level's PI layout being
  `[message(8), signer_count(1), pk_0..pk_{2^k−1} (8 each)]` — combining two aggregated proofs
  concatenates their signer lists. Left-packing is enforced **in-circuit** (a present right child
  forces the left child FULL, so zero-pk padding is provably a suffix) and `signer_count` counts
  exactly the verified leaf signatures. The close / cancel-close circuits recursively verify ONE
  level-`AGG_LEVELS` proof at constant VK, bind `message == recomputed IMCH digest` and
  `signer_count == member_count`, and WIRE the cosigner key vector from the proof's PI signer list
  (zero witnessed freedom) into the `member_set_commitment` keccak and the A5 distinctness chain
  (§F-3). The validity `bp_sig_chain` path keeps the linear `ListCircuit` (D8) — only close/cancel
  moved to the tree aggregator.

---

## E. lattice ZKPs (new circuits, Plonky3)

### E-1. channelTxZKP (intra-channel, abstract2.md §2.2 / audit finding 5)

**Proof statement** (public: `prev_sender_ct.digest()`, `next_sender_ct.digest()`, `enc_amount.digest()`,
the `RegevPk` digests of sender / recipient. private: plaintext balance, amount, encryption randomness):
1. `enc_amount` is a correct ciphertext to the recipient `RegevPk`, with plaintext `amount ≥ 0`.
2. The plaintext of `prev_sender_ct` = the plaintext of `next_sender_ct` + `amount`, and each plaintext is an n-bit non-negative integer
   (**underflow is impossible via the ripple-carry constraint → updated sender balance ≥ 0 is built in**).
3. `next_sender_ct` is well-formed as a fresh encryption to the sender `RegevPk`.

### E-1b. channelTxZKP, decrypted `before` (refresh-free send, 2026-09-21)

Same public statement as E-1 (`before` / `after` under the sender `RegevPk`, `enc_amount` under
the recipient `RegevPk`, `before = after + amount` over the integers), but item (2)'s opening of
`prev_sender_ct` is **by decryption**: the E-3 decryption core (key binding `b = a·s + e_pk`,
decryption `v = c2 − c1·s`, digit extraction, digit→bit normalization) runs on `before` under the
sender's secret key `s` (private witness), and its normalized bit column *is* `m_before` of the
ripple-carry conservation chain. `after` and `enc_amount` stay fresh well-formed encryptions
(E-1's ring identities). No encryption witness of `before` is needed, so a ciphertext that is a
homomorphic sum (deposit import, received transfers) is spendable directly. Purpose
`ChannelTxDecrypted`, domain "IMDS"; AIR `DecryptedDualKeyAir::send`. The noise budget is the
one E-3 / refresh already rely on (§B-3, D1); no new cryptographic assumption.

### E-2. channelUpdateZKP (inter-channel, abstract2.md §2.3)

**Proof statement** (public: `sender_delta_ct.digest()`, `receiver_delta_ct.digest()`,
`prev/next_sender_ct.digest()`, both `RegevPk` digests, `amount` (plaintext in the base layer)):
1. The absolute values of the plaintexts of `sender_delta_ct` and `receiver_delta_ct` are both `amount` (equal magnitude, opposite sign).
2. Update of the sender balance (the same ripple-carry as E-1, `balance ≥ amount`).
3. Both deltas are correct ciphertexts to their respective `RegevPk`.

`rangeProof` (abstract2.md §3.3.1) = the **verification** of this ZKP (performed by ITS = the member designated by `bp_member_slot` before handing it to the BP).

### E-2b. channelUpdateZKP, decrypted `before` (refresh-free inter-channel debit / burn, 2026-09-21)

E-2 with `prev_sender_ct` opened by the decryption core exactly as in §E-1b; `after`,
`sender_delta` and `receiver_delta` remain fresh encryptions and both deltas' message evaluations
are published and pinned to the public `amount` (F2-C) as in E-2. Purpose
`ChannelUpdateDecrypted`, domain "IMDU"; AIR `DecryptedDualKeyAir::update`. Needed because the
inter-channel debit and the burn are E-2 statements, not E-1.

### E-3. withdrawClaimZKP (post-close withdrawal, abstract2.md §2.4)

**Proof statement** (public: one's own component `user_amount_ct.digest()` within `final_balance_state_h1`,
the withdrawal amount `amount` (plaintext, public), one's own `RegevPk` digest):
"the plaintext of `user_amount_ct` = `amount`." The decryption key is a private witness. No cooperation of other members is needed
(exit-liveness, abstract2.md §4.4).

### E-4. Verification trait (refactor of `state_update_verifier.rs`)

```rust
pub enum RegevProofPurpose {
    ChannelTx,               // E-1
    ChannelUpdate,           // E-2
    WithdrawClaim,           // E-3
    BalanceRefresh,          // §B-3 refresh (combined Decrypt+Encrypt AIR)
    ChannelTxDecrypted,      // E-1b: E-1 statement, `before` opened by decryption ("IMDS")
    ChannelUpdateDecrypted,  // E-2b: E-2 statement, `before` opened by decryption ("IMDU")
}
pub trait RegevProofVerifier {
    fn verify(&self, envelope: &ChannelProofEnvelope, purpose: RegevProofPurpose,
              public_inputs: &[u32]) -> Result<(), ChannelStateUpdateError>;
}
```

The old `LatticeBindingVerifier` / `LatticeProofPurpose::{TransferAmount, BalanceOpening}` and the
`LatticeOpening` field family (which assumed opening hand-off) inside
`ReceiverDeltaApplicationWitness` / `InChannelTransferUpdateWitness` are abolished.
The external helper process (`tools/lattice-proof-helper`) is also abolished, and the Plonky3 STARK is verified in-process.

> **Note (D2):** `RegevProofPurpose` is defined in `src/regev` and only re-exported by
> `state_update_verifier.rs:14`. The shipped AIRs that back these purposes are
> `DualKeyTransferAir` (E-1) / `ChannelUpdateAir` (E-2) / `DecryptionAir` (E-3) / `RefreshAir` (§B-3 refresh)
> / `DecryptedDualKeyAir` (E-1b send shape, E-2b update shape)
> in `src/regev/transfer_stark.rs` — refresh is a separate `RefreshAir`, not E-1 with delta = 0.
> A decrypted purpose shares its `RegevStatement` shape with its witnessed twin but is a distinct
> transcript domain and a structurally different AIR, so a proof verifies under at most one;
> relying parties call `verify_transfer_proof_either` (decrypted first, witnessed fallback).

---

## F. Changes to the balance / validity circuits

### F-1. BalancePublicInputs (`src/circuits/balance/balance_pis.rs:47-63`)

```rust
pub struct BalancePublicInputs {
    pub channel_id: ChannelId,                 // [Keep]
    pub public_state: PublicState,             // [Keep]
    pub block_r: BlockNumber,                  // [Keep]
    pub private_commitment: PoseidonHashOut,   // [Keep]
    pub settled_tx_chain: Bytes32,             // [New] the chain of the settle history ingested by the circuit
}
// BALANCE_PUBLIC_INPUTS_LEN += 8 (for Bytes32)
```

Each time the balance circuit ingests one settle (transfer / deposit), it computes
`chain' = hash(chain, TxLeafHash or deposit_hash)` **inside the circuit** and exposes the final value as a public
input (a new requirement of abstract2.md §2.1). Since `H1` does not include the proof object, the
state↔proof correspondence can be mechanically verified by the
**equality reconciliation** "`balanceProof.PI.settled_tx_chain == BalanceState.settled_tx_chain`" (resolving the circularity of "proof not generated at signing time" = audit finding 3).

> **Note (mid-channel deposit):** `verify_channel_backing` (wallet_core.rs) enforces this
> reconciliation at TWO points: (a) genesis backing (the initial deposit's balance proof) and
> (b) mid-channel L1 deposit import (§C-10). In both cases the `settled_tx_chain` equality check
> binds the balance proof to the channel state, preventing unescrowded deposit claims.

### F-2. validity / confirmation circuit (abstract2.md §3.3.5)

- To the verification of the small-block signature (equivalent to `channelStateSig` = `SignedSmallBlock.signatures`),
  add the constraints **"the `tx_tree_root` component of the signature preimage = the `tx_tree_root` of that small block" and
  "on the inter-channel path, `tx_tree_root ≠ 0`"**. Signature verification is done **in-circuit in the per-slot loop of `update_channel_tree`
  (UpdateUserTree)** (the old `signature_aggregation/` pipeline is dead code not connected to the
  live validity path, and is deleted, DC / §D5). The same loop also proves that the signing pubkey is
  included in a slot under the channel's Poseidon `member_pubkeys_root` (the soundness binding of §F-3).
- The `ChannelLeaf.prev` update of `PublicState.account_tree_root` (the ingested block number, double-spend prevention) is [Keep].

### F-3. ChannelClosePublicInputs (`close_pis.rs`)

> Historical D14 layout/aggregation checkpoint. The current lengths are close 103, claim 50,
> cancel 29 and backing 26; current close proving uses the eight-signer Falcon batch context.
> The 95/48/27 and sixteen-slot tables below are preserved to explain the migration, not as ABI.

Added fields: `final_state_version: u64` (2 limbs), `final_settled_tx_chain: Bytes32` (8 limbs),
**`member_set_commitment: Bytes32` (8 limbs, §C-8) + `member_count` (1 limb, D6)**.
`final_channel_balance_root` is renamed to `final_balance_state_h1`.
**`CHANNEL_CLOSE_PUBLIC_INPUTS_LEN` = 77 → 86 (D6) → 87 (D9) → 95 (D14 checkpoint)**: the Stage-3
`final_settled_tx_accumulator_root` (8 limbs, §C-2) sits at limbs 77..85, shifting
`member_set_commitment` to 85..93; `member_count` is limb 93 and `delegate_count` limb 94
(code: `close_pis.rs:37 = 95`). The original 77-limb prefix is unchanged.

Other close PIs. (The D5 values — withdrawal claim 42→48, post-close 34→40, cancel 41 — were further
changed by the subsequent close-game hardening / Stage-3 work; the table shows that historical
checkpoint, before the current lengths listed above.)

| Circuit | PI length (D14 checkpoint) | Note |
|---|---|---|
| close (`close_pis.rs`) | **95** | 77-limb legacy prefix + `final_settled_tx_accumulator_root` (8) + `member_set_commitment` (8) + `member_count` (1) + `delegate_count` (1) |
| withdrawal claim (`withdrawal_claim_pis.rs`) | **48** | member identifier is the 8-limb `pk_g` (DA → D8); claimant slot opened via a height-10 Merkle inclusion against the H1 slot-tree root (D14) |
| post-close claim (`post_close_claim_pis.rs`) | **56** | 40 (D5) + Stage-3 accumulator-anchored source-tx binding; claimed slot opened via the same height-10 inclusion (D14) |
| cancel close (`cancel_close_pis.rs`) | **27** | CORRECTED C1 statement: `channelId(1) \| closeIntentDigest(8) \| memberSetCommitment(8) \| revivedStateVersion(2) \| revivedChannelStateDigest(8)` (replaces the forgeable legacy 41-limb revived-tx layout) |

**Close/cancel-circuit machinery (historical D11–D14):** the close and cancel-close circuits each
recursively verify **one level-`AGG_LEVELS` (16-slot) aggregated sign-zkp proof** (§D D-4, D13) at a
constant baked VK (`const`-asserted `MAX_COSIGNERS == MAX_AGG_SIGNERS`); the cosigner `pk_g` vector
is **wired from the verified proof's PI signer list** (the former per-slot signature verification /
in-circuit C' `ListCircuit` fold is deleted), with `message == recomputed IMCH digest` and
`signer_count == member_count` enforced in-circuit. `member_count` is range-checked
`2..=MAX_COSIGNERS` via the 16-bit unary active-bits decomposition. **A5 pk_g distinctness** is an
indexed-Merkle **insertion chain** (D11): each active cosigner `pk_g` is inserted in slot order into
a fresh `IndexedMerkleTree` of height `MEMBER_DISTINCTNESS_TREE_HEIGHT = 5` via the audited
`conditional_get_new_root` gadget — a duplicate key has no valid low-leaf, so it is unprovable
(replaces the O(N²) all-pairs loop). `member_set_commitment` stays the **fixed `MAX_COSIGNERS` =
16-slot keccak over the COSIGNERS** (§C-8). The in-circuit H1 recompute is the O(1) D14 header: the
slot-tree root is witnessed (bound by the cosigner signatures over H1), and the 1024-slot target
vectors + flat keccak are deleted.

**Soundness binding**: validity (`update_channel_tree`) proves, via a slot inclusion proof, that the **signing pubkey ∈ the channel's Poseidon
`member_pubkeys_root`** (bound to the `ChannelLeaf` under `account_tree_root`) (DB). close exposes `member_set_commitment`, and L1 keccak-reconciles it against the registered member set
(§C-8). Thereby "signing key = registered member" is bound both inside the circuit (Poseidon) and at the L1 boundary (keccak).

---

## G. List of numeric constants

> Historical constants inventory. Use the current types/widths table at the start of this file;
> in particular n=128, sixteen signers, registered tree height 10, and four aggregation levels
> below are old values. Domain entries also include retired protocol generations explicitly.

### G-1. Newly established

| Constant | Value | Rationale |
|---|---|---|
| `MAX_CHANNEL_MEMBERS` | **1024** | BALANCE-SLOT capacity (cosigners + delegates + padding; pad-to-MAX, D6 → D12). Sizes `BalanceState.enc_balances` / `regev_pk_digests` / `pending_adds` and `ChannelRecord.member_pk_gs` (`[_; 1024]`). A spec deviation from abstract2.md §2.1's fixed 3 people (replaces old `CHANNEL_MEMBERS = 3`; was 16 before D12) |
| `MAX_COSIGNERS` | **16** (NEW, D12) | Cap on the N-of-N close SIGNERS. `member_count: u8` is range-checked `2..=MAX_COSIGNERS` (native + in-circuit via the 16-bit unary active-bits sum); all close/cancel SIGNATURE-side arrays/circuits (member_set_commitment, aggregated sign-zkp pk slots, A5 chain, activeness gating) are sized by this, keeping the close/cancel degree tractable while balance/H1 arrays stay 1024 |
| `MEMBER_TREE_HEIGHT` | **10** (= log2(1024) leaves = `MAX_CHANNEL_MEMBERS`) | The Poseidon Merkle height of the validity-side `MemberTree` (DB / D6 / D12; invariant `1 << height == MAX_CHANNEL_MEMBERS`). **Replaces and deletes** old `KEY_TREE_HEIGHT` / `KEY_SET_TREE_HEIGHT` / `MEMBER_KEY_TREE_HEIGHT` / `KEY_ID_BITS` |
| `BALANCE_SLOT_TREE_HEIGHT` | **10** (const-asserted `1 << height == MAX_CHANNEL_MEMBERS`) | Height of the H1 balance-slot Poseidon Merkle tree (D14, §C-2). Distinct from `MEMBER_TREE_HEIGHT` (the validity-side pubkey tree) — same value only because both are indexed by the slot space `0..MAX_CHANNEL_MEMBERS` |
| `MEMBER_DISTINCTNESS_TREE_HEIGHT` | **5** (= ceil(log2(`MAX_COSIGNERS` + 1)), derived const) | Height of the in-circuit indexed-Merkle tree of the A5 pk_g distinctness insertion chain in close/cancel (D11): one sentinel leaf + up to 16 cosigner keys ⇒ 2^5 = 32 leaf slots |
| `AGG_LEVELS` / `MAX_AGG_SIGNERS` | **4** / **16** (= `1 << AGG_LEVELS`) | Binary-tree aggregated sign-zkp (`src/poseidon_sig/aggregate.rs`, D13): one `AggLevelCircuit` per level, top-level pk list = 16 slots; `const`-asserted `MAX_AGG_SIGNERS == MAX_COSIGNERS` at the close-circuit consumer |
| `SIGN_TIMEOUT_SECS` | **180** | abstract2.md §2.5 (3 min). Replaces old `SMALL_BLOCK_SIGNATURE_TIMEOUT_SECS = 60` |
| `GRACE_BEFORE_PROCESS_SECS` | **600** | abstract2.md §2.5 (10 min). §H-2 |
| `CHALLENGE_PERIOD_SECS` | **86,400** | abstract2.md §2.5 (1 day). Set to the immutable `challengePeriod` of `ChannelSettlementManager` |
| `MAX_HOMO_ADDS_BEFORE_REFRESH` | **64 (approved — see D1 and doc/docs/regev-noise-analysis.md)** | §B-3 |
| `REGEV_N` / `REGEV_ETA` / `REGEV_PLAIN_BITS` | 128 / 2 / 8 | §B-1 |

### G-2. Newly established domain constants (non-collision with existing IMxx confirmed)

| Constant | Value | ASCII |
|---|---|---|
| `BALANCE_STATE_DOMAIN` | `0x494d4253` | "IMBS" |
| `BALANCE_STATE_HASH_DOMAIN` | `0x494d4248` | "IMBH" |
| `TX_LEAF_DOMAIN` | `0x494d544c` | "IMTL" |
| `SETTLED_TX_CHAIN_DOMAIN` | `0x494d5443` | "IMTC" |
| `REGEV_CT_DOMAIN` | `0x494d5243` | "IMRC" |
| `CHANNEL_TX_ZKP_DOMAIN` | `0x494d435a` | "IMCZ" |
| `CHANNEL_UPDATE_ZKP_DOMAIN` (v1, retired) | `0x494d555a` | "IMUZ" (retired in multitoken Phase 2b — superseded by "IMU2" when the E-2 public values gained `token_index`; value stays pinned in the non-collision test) |
| `CLOSE_MEMBER_SET_DOMAIN` | `0x494d434d` | "IMCM" (keccak, §C-8 close PI `member_set_commitment`. L1 reconciliation) |
| `MEMBER_LEAF_DOMAIN` | `0x4d424c46` | "MBLF" (**Poseidon**. Leaf domain separation of `MemberTree`, `key_tree.rs`, DB) |
| `REGEV_PK_POSEIDON_DOMAIN` | `0x494d5250` | "IMRP" (**Poseidon**. The member-tree leaf's `regev_pk_digest = Poseidon([IMRP, n, a…, b…])`, `regev/keys.rs`) |
| `BALANCE_SLOT_LEAF_DOMAIN` | `0x494d534c` | "IMSL" (**Poseidon**. Per-slot leaf of the H1 balance-slot Merkle tree, `src/common/balance_state.rs`, D14. Distinct from every existing IMxx domain — covered by the repo-wide domain non-collision test in `poseidon_sig`) |
| `LIST_LEAF_DOMAIN` | `0x494d4c4c` | "IMLL" (**Poseidon**. Sign-zkp list leaf `Poseidon([IMLL] ‖ m ‖ pk)`, `src/poseidon_sig/list.rs`, D8 — the validity `bp_sig_chain` aggregation path; close/cancel moved to the tree aggregator, which introduces NO new domain of its own — the aggregation statement is carried by recursive proof PIs, not a hash chain, D13) |
| `BALANCE_STATE_DOMAIN_V2` | `0x494d4232` | "IMB2" (**Poseidon**. §N-1 multi-token v2 H1 header — 37 elems, commits `token_count` + `token_registry(10)`; supersedes "IMBS" for the native `h1()`; `src/constants.rs`. TM-9/TM-15) |
| `BALANCE_SLOT_LEAF_DOMAIN_V2` | `0x494d5332` | "IMS2" (**Poseidon**. §N-2 multi-token v2 balance-slot leaf — 104 elems: `[IMS2, pk_digest(8), ct_digest[0..10](80), pending_adds[0..10](10), recipient(5)]`; the §N-2 "103" figure counted the recipient as 4 limbs, but the canonical `Address` encoding is 5 — flagged Phase 1 deviation. Supersedes "IMSL" for the native leaf; TM-8/TM-15) |
| `PAY_DOMAIN_V2` | `0x494d5032` | "IMP2" (keccak. §N-3 IMPA-v2 `ChannelTx` signing digest — 43 words, `token_slot` its own limb after `nonce`. Replaces "IMPA" (v1 constant deleted; value stays pinned in the non-collision test). TM-2/TM-15) |
| `L1_DEPOSIT_IMPORT_DOMAIN_V2` | `0x494d4c32` | "IML2" (keccak. §N-5 IMLD-v2 deposit-import digest — 14 words, `token_index` its own limb. Replaces "IMLD" (v1 constant deleted; value pinned in the non-collision test). TM-7/TM-15) |
| `WITHDRAWAL_CLAIM_DOMAIN_V2` | `0x494d5732` | "IMW2" (keccak. §N-6 per-(slot, token) claim nullifier — 18 limbs `[IMW2, close_intent(8), slot_regev_pk_digest(8), token_slot]`. "IMCW" remains for the claim `signing_digest`. TM-5/TM-15) |
| `CHANNEL_UPDATE_ZKP_DOMAIN_V2` | `0x494d5532` | "IMU2" (WIRED in Phase 2b: the §N-4 E-2 public values gain the base `token_index` as their own extra PV (`e2_extra_pvs`, `transfer_stark.rs`); replaces "IMUZ". TM-6/TM-15) |
| `INTER_CHANNEL_TX_DOMAIN_V2` | `0x494d4932` | "IMI2" (keccak. §N-4 `InterChannelTx` signing digest — base `token_index` its own limb after `destination_channel_id`. Replaces "IMIT" (Phase 2b; value pinned in the non-collision test). NEW domain rather than in-place widening: the preimage has three variable-length length-prefixed tails, so the equal-total-length v1↔v2 realignment case would otherwise rest on the v3 reset alone; exactly one hashing site, no in-circuit/Solidity mirror. TM-6/TM-15) |
| `TOKEN_FUNDS_DIGEST_DOMAIN` | `0x494d5446` | "IMTF" (keccak. §N-6 `token_funds_digest = keccak([IMTF, registry(10×u32), token_count, amounts(10×U256)])` — fixed 92-word preimage, always full width. TM-11) |
| `DOMAIN_FALCON_H2P` | `0x494d4648` | "IMFH" (**Poseidon**. §O-1 capacity domain separator of the Falcon-512 hash-to-point sponge: `absorb(salt(40 B) ‖ message digest(32 B))`, then 64 squeezes × 8 rate elements = 512 coefficients, one FULL field element reduced mod q per coefficient. `src/falcon_sig/vendor/hash_to_point.rs`; native and in-circuit pinned equal by shared vectors. TM-C1/O-1/O-2) |
| `DOMAIN_FALCON_PK` | `0x494d464b` | "IMFK" (**Poseidon**. §O-2 member identity `pk_g = Poseidon(IMFK ‖ encode(h))` over the canonical encoding of the Falcon public polynomial `h`. REDEFINES `pk_g` IN PLACE — same `Bytes32` width, same `MemberLeaf` slot, same L1 registration keccak layout, same Solidity `bytes32 pkG`: values change, layouts do not. `src/falcon_sig/mod.rs`. TM-C7/A-F4) |
| `DOMAIN_FALCON_KEYGEN` | `0x494d4647` | "IMFG" (**keccak**. §O-4 keygen-RNG seed separation: the NTRU keygen ChaCha20 seed is `keccak256("IMFG" ‖ member_seed)`, never the raw member seed — so this use of the seed cannot collide with any other consumer of the same 32 bytes. `src/falcon_sig/mod.rs::FalconKeys::from_seed`. TM-C10/O-11) |

> **RETIRED by falcon-sig (Phase 4)**: `DOMAIN_PK_G` "IMPG" `0x494d5047` and `DOMAIN_SIG_G` "IMSG"
> `0x494d5347` — the domains of the deleted Poseidon-preimage ZK signature (`pk = H(IMPG‖sk)`,
> `sig = H(IMSG‖sk‖m)`). Nothing derives from them any more. They are **kept as RESERVED constants**
> in `src/poseidon_sig/mod.rs` precisely so the repo-wide non-collision tests
> (`constants.rs::all_domain_constants_pairwise_distinct`,
> `falcon_sig::tests::falcon_domains_do_not_collide`) keep proving that no LIVE domain — IMFH/IMFK/
> IMFG included — collides with a value this system once hashed under. Deleting them would delete
> those proofs. **`IMCM` (`CLOSE_MEMBER_SET_DOMAIN`) is NOT retired**: the close member-set
> commitment keeps its domain and its keccak layout; only the `pk_g` VALUES inside it change
> (falcon-sig Phase 2 notes §5, TM-C7). `IMLL` (`LIST_LEAF_DOMAIN`) is likewise retained — the
> validity `bp_sig_chain` list format survives the migration unchanged; only the list step's leaf
> verification changed (§O-3).

> Note: `MEMBER_LEAF_DOMAIN` / `REGEV_PK_POSEIDON_DOMAIN` are domains of **in-circuit Poseidon** (member-tree binding, DB).
> `CLOSE_MEMBER_SET_DOMAIN` is a domain of **L1 keccak** (close PI reconciliation). It is the design of DB that the same member set is represented by
> two systems: in-circuit (Poseidon) / L1 boundary (keccak). `regev_pk_root` (keccak "IMRR" `0x494d5252`) is for the L1 anchor of §H-1.
>
> **D14 update:** `BALANCE_STATE_DOMAIN` "IMBS" is now a **Poseidon** domain — the H1 header is
> `Poseidon([IMBS, …])` (keccak is retired from H1; §C-2). `BALANCE_STATE_HASH_DOMAIN` "IMBH" and the
> other chain/L1 domains remain keccak.
>
> **TM-16 note (Phase 5a, no new domain):** the inter-channel `tx_hash` fold's IMTC ids word
> gained the base `token_index` at limb 5 (`[0,0,0,0,0, token_index, dest_id, src_id]`, §N-6).
> The IMTC push domain is RETAINED: the preimage SHAPE is unchanged (two Bytes32 words per fold);
> a previously constant-zero limb of a data word gained meaning, occupying its own canonical u32
> limb (TM-15 — no bit-packing). v1 leaves read as token 0 = ETH (backward-consistent; moot under
> the v3 reset). The token-free v1 fold lives on as `InterChannelTx::replay_identity` — the
> replay/consumed-ledger key (TM-16 obligation 1).

### G-3. Existing (unchanged, reference)

Domains: IMCH / IMPA / IMSB / IMSS / IMIT / IMCL / IMCI / IMSC / IMCN / IMCP / IMCW / IMUF /
IMCR / IMLD. Trees: `CHANNEL_TREE_HEIGHT = 32`,
`TRANSFER_TREE_HEIGHT = 6`, `TX_TREE_HEIGHT = 32`, `BLOCK_NUMBER_BITS = 63`.
`MAX_CLOSE_TRANSFERS = 16`, `SPECIAL_CLOSE_MEDIUM_BLOCK_WINDOW = 5`.
**Deleted**: `KEY_ID_BITS` / `KEY_TREE_HEIGHT` / `KEY_SET_TREE_HEIGHT` / `MEMBER_KEY_TREE_HEIGHT`,
and `IMKR` (`KEY_RECORD_DOMAIN`) and the threshold / num_keys constants (DA/DC, §D5).

---

## H. Flow correspondence (abstract2.md §3 → implementation)

### H-1. Normal operation

| abstract2.md | Implementation (updated version) |
|---|---|
| §3.0 `publishRegevPk` | At channel creation, `registerChannel` fixes a per-channel variable of **2..16 cosigners** (+ optional delegates up to the 1024-slot capacity, §L) `(pk_g, pk_b, regev_pk, l1_recipient)` + `member_count` (per-key_id threshold / key-set registration is abolished, DA/DC). `ChannelSettlementManager` stores the registered cosigner set + `activeMemberCount` (its internal mirror is the 16-slot cosigner form, byte-identical to the Rust `MAX_COSIGNERS` commitment; **the contract-side alignment to the 1024 balance-slot capacity — registration reg-chain preimage, H1 slot mirrors — is PENDING, D12**). `memberKeys[channel_id]` is a spec deviation generalizing abstract2 §1's `Map<ChannelId,[(Address,RegevPk);3]>` to N members (D6/D12). L1 anchor: take `ChannelRecord`'s `member_pk_gs` (all `MAX_CHANNEL_MEMBERS` = 1024 slots) + `member_count` + `member_pubkeys_root` + `regev_pk_root` (keccak "IMRR") into the IMCR `signing_digest`. The in-circuit binding is the Poseidon `MemberTree` assembled from the same members (DB) |
| §3.1 `agreeBalanceState` | Collect active-member (`0..member_count`) signatures over `ChannelState::signing_digest()` (= embeds hash(H1,H2)). Verification items are as in abstract2 §3.1 (version+1 / chain consistency / own-component decryption verification / `channelTxZKP` / `channelUpdateZKP` + inclusion proof) |
| §3.2 `channelTransfer` | Build `ChannelTx` (§C-5) → generate `channelTxZKP` (§E-1) → propagate → co-sign. `ChannelTransition::InChannelTransfer` |
| §3.3.1 `rangeProof` | The member designated by `bp_member_slot` verifies `channelUpdateZKP` with `RegevProofVerifier` |
| §3.3.2 `signChannelState` | `SmallBlockRootMessage` signature (§C-7). Inclusion confirmation is `tx_inclusion_proof` against a 1-leaf tree (§A-2) |
| §3.3.3–3.3.4 `produceBlock` / `postBlock` | The BP constructs the posting round's `SubBlock[]` and calls `IntmaxRollup.postBlockAndSubmit` (`IntmaxRollup.sol:433-445`). 1 SubBlock = 1 channel |
| §3.3.5 `generateValidityProof` | Existing validity stack + the §F-2 constraints |
| §3.3.6 `generateBalanceProof` | Existing balance stack + the §F-1 chain expose |
| §3.4 flowSend1/2, flowReceive3 | Implemented with `InterChannelTx` (§C-6). The `chain'` of step 5 is computed from `TxLeafHash` before signing. The receiver side is `ChannelTransition::ReceiverBundleApply` |

### H-2. close game (abstract2.md §3.5 → `ChannelSettlementManager.sol`)

| abstract2.md | Implementation (updated version) | Change |
|---|---|---|
| §3.5.1 `requestClose` | **[New] `requestClose(uint64,uint64)`**: binds the signed transaction to the durable freeze/cancel era, immediately makes `channelStatus` `ClosePending`, increments the monotone request generation, and records `closeRequestedAt = block.timestamp` (the signal to stop signing. `isNativeSendAllowed` becomes false) | Since the current contract does not separate request/startProcess, **a function is added** |
| §3.5.2 `startProcess` | Add **`require(block.timestamp ≥ closeRequestedAt + GRACE_BEFORE_PROCESS_SECS)`** to `submitCloseIntent(CloseIntent, proof)` (`ChannelSettlementManager.sol:submitCloseIntent` :558; GRACE check :587). Add to L1 verification: **(new) "the PI `settled_tx_chain` of `finalBalanceProof` == `CloseIntent.final_settled_tx_chain`" "all member signatures are over a `hash(H1,H2)`-family digest"** | Adding chain reconciliation is the core of v2 |
| §3.5.3 `challenge` | Existing "replacement by a newer close intent within the challenge period" (the ClosePending branch inside `submitCloseIntent`). Change the replacement order from `(final_epoch, closeNonce)` to **`(final_epoch, final_state_version)`**. Perform chain reconciliation for each submission | To `final_state_version` comparison |
| §3.5.4 `closeAndWithdraw` | After `finalizeCloseGuarded(bytes32,uint64)`, `submitWithdrawalClaim` records individual claims; `materializeSignedHead` verifies the exact already-attested whole-vector backing proof and backing pull funds the Manager. Claim registration and backing pull may occur in either order; `claimWithdrawalCredit(bytes32 withdrawalNullifier)` requires both. Lifetime accepted claims are capped by `totalWithdrawn + amount ≤ finalizedChannelFundAmount`; actual payments are separately capped by recognized backing. **The former fresh terminal-child requirement is retired:** the current path consumes existing N-of-N H plus its durable kit without another channel signature. | Current disposition; conditional on exact kit, finalized dependencies and the deployment/transfer assumptions above |
| §3.5.5 `claimLateTx` | **Disabled:** `submitPostCloseClaim` reverts unconditionally because the old statement can double-credit a delta already absorbed by the closing balance. Re-enable only with an explicit unapplied-incoming commitment. | [Do not expose] |

### H-3. Implementation-specific additional defenses (outside the scope of abstract2.md)

Three challenge primitives sit outside abstract2's 5 properties (they strengthen exit-liveness, not
fund-custody safety). Status after the A1 settlement-verifier hardening (2026-06; the value-bearing
`verifyCloseIntent` / `verifyWithdrawalClaim` / `verifyPostCloseClaim` are now REAL MLE/WHIR proofs, not
`_matches` stubs):

**`cancelClose` (C1) — REAL.** A pending close is cancelled by a ZK proof that the channel's REGISTERED members
N-of-N signed a channel state at `state_version > pending_close.final_state_version`, in the same close-freeze
era (`revived.close_freeze_nonce + 1 == close.close_freeze_nonce`). The cancel circuit exposes
`member_set_commitment`, matched on-chain against `ChannelSettlementManager.registeredMemberSetCommitment()`, so
ONLY the registered members can cancel — a third party signing a revival block with their own keys is rejected
(member-set mismatch). NOTE: "a later signed BP small block exists" alone is NOT a sound staleness condition (the
BP unilaterally produces small blocks and can race a later block after an honest close starts); the sound
condition is "a strictly-newer N-of-N member-signed state exists", which is what the circuit proves.

**`submitSpecialClose` (C2) — DISABLED (IMPLEMENTED 2026-06, P6-A): the entry point now reverts
`SpecialCloseDisabled()` unconditionally (`ChannelSettlementManager.sol`); the stub verifier is left in place but
unreachable. Adversarial-reviewed (no defects; freeze-grief removed, no member funds move). Forgeable stub;
revert the entry point.** Intended fault: the BP fully
signed a small block but failed to finalize it within `SPECIAL_CLOSE_MEDIUM_BLOCK_WINDOW = 5` medium blocks
(censorship); on success it slashes `min(specialClosePenalty, bpBondCredits)` to the caller and freezes the
channel. A SOUND proof of this fault requires **non-inclusion of the BP-signed block in the finalized
medium-block chain** — proving a negative (it was never finalized) — and that finalized-chain commitment lives
in the validity / `IntmaxRollup` layer, not in the settlement contract (a cross-layer commitment, deferred). The
current `verifySpecialClose` is a tautological `_matches` stub (the "proof" is just `keccak(public inputs)`,
computable by anyone), so anyone can fabricate the accusation and slash an honest BP. **Disposition: disable
(revert) `submitSpecialClose`** until the cross-layer non-inclusion commitment exists. **Safety while disabled:**
the BP-censorship slash is simply unavailable; no member funds move; the BP bond (`bpBondCredits`) is a separate
pot, and if it is unfunded (= 0) the forged-slash steals nothing — disabling only removes the freeze-grief.

**`submitLateOutgoingDebitCorrection` (C3) — DISABLED (IMPLEMENTED 2026-06, P6-A): the entry point now reverts
`LateOutgoingDebitDisabled()` unconditionally; the stub verifier is left in place but unreachable.
Adversarial-reviewed (no defects; double-pay still prevented by the nullifier used-sets + cancelClose).
Forgeable stub; redundant. The threat it targets is already prevented; the conditions are:**
1. **No double-withdrawal — guaranteed by on-chain nullifier used-sets** (the "non-inclusion list of
   withdrawals" is a Solidity `mapping(bytes32 => bool)`, O(1), at EVERY payout path):
   `IntmaxRollup.withdrawalNullifierUsed` (base `withdrawNative`),
   `ChannelSettlementManager.usedWithdrawalNullifiers` (per-member claim), and `usedSharedNativeNullifiers`
   (post-close claim). Each nullifier is **derived deterministically in-circuit and bound** to the withdrawal
   identity (e.g. `keccak(IMCW, close_intent_digest, member_pk_g)`; post-close `keccak(IMCK, close_intent_digest,
   incoming_tx_hash, receiver_pk_g)`, recomputed by the manager), so re-running the ZKP cannot dodge it. The same
   tx pays out EXACTLY ONCE (check-then-set CEI). **A ZK proof for one withdrawal cannot be paid twice.**
2. **A co-signed outgoing debit cannot be silently omitted at the same version**: `H1` commits `settled_tx_chain`
   AND the (already-debited) `enc_balances` under the SAME N-of-N member signatures, so members never sign an H1
   whose settle chain contains the tx but whose balance is un-debited.
3. **Omitting a co-signed debit ⇒ closing on an older `state_version` ⇒ a stale close**, which is rejected by
   `cancelClose` (C1).
4. **A merely sender-signed (not co-signed/settled) tx is NOT a committed debit.** The 10-minute close grace
   (`GRACE_BEFORE_PROCESS_SECS = 600`) lets members settle any pending tx into a block before the close
   processes; afterwards honest members stop signing. There is **no mid-channel withdrawal** in the protocol
   (the only L1 exit is channel close: `finalizeClose → submitWithdrawalClaim → claimWithdrawalCredit`), so there
   is no "in-flight withdrawal" that a close could omit.
5. **Explicitly out of scope (accepted):** a time-difference grief where a non-settled tx is used to block a
   close. The only required property — "the same withdrawal cannot be paid more than once" — is met by (1).
   Therefore C3 is **redundant** with the nullifier used-sets + `cancelClose`. **Disposition: disable (revert)
   `submitLateOutgoingDebitCorrection`.**

These disables are **safety-neutral**: cross-channel isolation (the `Σ paid ≤ receivedChannelFunds` cap) and the
no-double-withdraw guarantee (nullifier used-sets) do NOT depend on C2/C3. Disabling only removes the
forgeable-while-stubbed BP-censorship slash (C2) and the redundant late-debit cancel (C3).

FOLLOW-UP (non-security): with C2/C3 disabled, several symbols touched only by their removed bodies remain
dead — `latestSpecialCloseDigest`, `usedLateOutgoingDebitNullifiers`, and the `SpecialCloseSubmitted` /
`LateOutgoingDebitAccepted` events. The adversarial review confirmed these are harmless (no invariant reads
them). The unused external `computeSpecialCloseDigest` helper was removed before release because its ABI decoder
materially contributed to an EIP-170 overflow in the clean recorded-submodule build. The remaining storage/event
symbols do not add callable runtime behavior and are deferred to the final fixture-regeneration boundary.

### H-4. Invariant of the challenge order

L1's replacement rule is "larger `final_epoch`, and on a tie, larger `final_state_version`."
Discipline of an honest member (A3): sign only 1 state per version (`OneStatePerVersion`).
Thereby "the all-signed state of the highest version is uniquely determined" (consistent with the premise of ChannelSafety2.lean's
`challenge_latest_wins2`).

---

## I. File layout (change map)

### I-1. New

| Path | Contents |
|---|---|
| `src/regev/mod.rs` | Module declaration |
| `src/regev/params.rs` | §B-1 parameters (port of `channel_params`) |
| `src/regev/keys.rs` | `RegevPk` / `RegevSk` / keygen (port source `regev-adapter/src/lib.rs:110-123`) |
| `src/regev/encrypt.rs` | encrypt / decrypt / homomorphic addition / amount encoding (port of `encode_value_message`) |
| `src/regev/transfer_stark.rs` | The Plonky3 AIR of E-1/E-2/E-3/refresh (extends the port source transfer STARK to 4 purposes) |
| `src/common/balance_state.rs` | `BalanceState` / `balance_state_hash` / `tx_leaf_hash` / chain update (§C-2, C-6) |

### I-2. Changed

| Path | Change |
|---|---|
| `src/common/channel.rs` | The full set of type changes of §C-1 through C-8. Delete `LatticeCommitment` / `LatticeOpening` |
| `src/lattice/proof_adapter.rs` | **Deleted** (SIS-related). `tools/lattice-proof-helper` also deleted |
| `src/circuits/channel/state_update_verifier.rs` | Make it `RegevProofVerifier` (§E-4). Remove `LatticeOpening` from witness structures |
| `src/circuits/balance/balance_pis.rs` / `balance_circuit.rs` | Expose `settled_tx_chain` (§F-1) |
| `src/circuits/validity/…` (confirmation family) | The H2 constraints of §F-2 |
| `src/circuits/channel/close_pis.rs` / `close_circuit.rs` | §F-3 |
| `src/circuits/channel/withdrawal_claim_pis.rs` | Change the meaning of `user_amount_digest` to `RegevCiphertext::digest()` |
| `contracts/src/ChannelSettlementManager.sol` | Add guarded `requestClose(uint64,uint64)` / enforce GRACE / chain reconciliation / `final_state_version` comparison (§H-2) |
| `contracts/src/ChannelSettlementVerifier.sol` | Add `final_state_version` / `final_settled_tx_chain` to the close PI hash |
| `src/constants.rs` | Add the §G constants; `MAX_CHANNEL_MEMBERS = 1024` (balance-slot capacity) split from `MAX_COSIGNERS = 16` (variable `member_count`, D6 → D12) |
| `src/circuits/channel/e2e_flow.rs` | Make E2E Regev-based (remove opening hand-off, make ZKP mandatory) |

### I-3. Unchanged

`src/common/transfer.rs` (`Transfer` / `SettledTransfer` / nullifier), `src/common/block.rs`,
`src/common/public_state.rs`, `src/utils/hash_chain/`, the SPHINCS+ family
(`sphincs_sig.rs`), the MLE/WHIR wrapper.

> **Update — `IntmaxRollup.sol` is no longer "Unchanged".** Its escrow / withdraw / registration
> surface changed: payable `deposit()` escrow tracked by `totalEscrowed` (`IntmaxRollup.sol:428,723-737`),
> `withdrawNative()` (`:1155`), `withdraw()` (`:1060`), `reclaimStake()` (`:1117`), and
> `registerChannel()` (`:789`, the D7 on-chain registration surface). `finalize` / `fraudProof` / `verify`
> are now MLE/WHIR-only with Groth16 removed (D6 — see the D6 Change B note above). Only the
> postBlock / deposit ingestion flow is structurally as before.

> **Update (D6 Change B):** `IntmaxRollup`'s `finalize` / `fraudProof` / `verify` / `fullVerify` become
> **MLE/WHIR-only**, removing Groth16 (no longer taking `Groth16Params`). The validity-PI binding that
> the former Groth16 PI-hash check alone carried is replaced by `_mlePublicInputsMatch(mleProof.publicInputs,
> keccak256(ValidityPublicInputs))` (soundness-critical). Delete `Groth16Verifier.sol` /
> `GnarkGroth16Verifier.sol` / `E2E_RealGroth16.t.sol` / `src/utils/groth16_wrapper.rs`.
> Details and verification tests are in detail2-implementation-notes.md D6.

---

## J. abstract2.md necessary-condition checklist

| abstract2.md requirement | Satisfaction in this spec | Status |
|---|---|---|
| §1 `RegevPk` / `LatticeCt` | §B-2 (`RegevPk` / `RegevCiphertext`) | New |
| §2.1 `BalanceState { encBalances, settledTxChain, stateVersion }` | §C-2 | New |
| §2.1 do not include the proof in `H1` | §C-2 `h1()` (digest only) | New |
| §2.1 expose chain in `BalancePublicInputs` | §F-1 | Changed |
| §2.2 `ChannelTx` + `channelTxZKP` mandatory | §C-5 + §E-1 | New |
| §2.3 `TxAux` / `TxLeafHash` / `channelUpdateZKP` | §C-6 + §E-2 | Changed |
| §2.3 `channelStateSig` (hash(H1', H2) signature) | §C-7 / §D | Changed (redefined) |
| §2.4 chain reconciliation of `finalBalanceProof` | §H-2 startProcess/challenge | Changed |
| §2.4 `withdrawClaimZKP` / `lateBalanceProof` | §E-3 / §H-2 | Changed |
| §2.5 the 3 timeout constants | §G-1 | Changed (60s→180s etc.) |
| §3.2 / §3.4 flow | §H-1 | Changed |
| §3.3.2b no-signature special case (deposit / closeBurnTx) | §D table | Consistent with existing |
| §3.5 close game (request → 10min → start → 1day → close) | §H-2 (add `requestClose`) | Changed |
| §4.2 Σ(withdrawals) ≤ withdrawCap | Existing `totalWithdrawn` enforcement | Existing |
| §4.5 confidentiality boundary (amount is base-layer plaintext, total balance is PI-visible) | §E-2 public `amount` / balanceProof PI | Consistent |
| (difference) `TxV2Tree` aggregation | **Not satisfied** (§A-2, user decision) | Intentional difference |

## K. Open items (abstract3 / to be resolved at implementation time)

1. **M7 (signed-but-unsettled race)**: the window in which the all-signed state of flowSend1 step 6 exists before
   L1 ingestion. Unresolved even in abstract2.md (lean-safety-proof2.md). Candidate implementation countermeasure:
   when adopting a `.txRoot`-tagged state (a `ChannelState` with `h2_tag ≠ 0`) for close,
   L1 requires the inclusion proof of that small block — it is expected that the existing mechanisms of `CancelClose` / confirmation proof
   (`SignedSmallBlock.confirmation_proof`) can be reused. Spec finalization is in abstract3.
2. **Semantics of retry / version reassignment** (audit finding 12): clarification of the version-consumption rule when a transfer does not succeed.
3. **Rigorous analysis of the noise budget** (the parameter requiring approval in §B-3).
4. **Authenticity of `RegevPk`**: the key-substitution attack surface of `publishRegevPk`. It is anchored to L1 by taking
   `regev_pk_root` into `ChannelRecord` (§H-1), but the procedure for registration-time verification (e.g., confirming decryption of a test ct
   encrypted with one's own key) is to be designed at implementation time.
5. **Following up the Lean model**: reflect `final_state_version` comparison, the 1 block = 1 tx degeneration, and the refresh operation
   into the v3 revision of ChannelSafety2.lean (parameterizing the signature of `Apply`).
6. **Registration mechanism (genesis ingestion of the member tree)** (DA/DB, §D5) — **RESOLVED by D7.**
   The in-circuit binding (`update_channel_tree` proving slot inclusion under `member_pubkeys_root`) is
   implemented and unit-tested, and the registration path is now in place: channels enter via a **registration
   block** (`src/circuits/validity/channel_reg_hash_chain/` + `src/common/channel_registration.rs` +
   `IntmaxRollup.registerChannel`), whose ZK proof deterministically rebuilds the channel tree from the on-chain
   registration hash chain (mirroring the deposit mechanism). `tests/e2e.rs:94` calls `add_channel_registration`
   and the full-stack e2e (register block → deposit → transfer → close) **PASSES**. The
   `switch_board.rs:230` empty-genesis is **intentional** — channels enter through a registration block, not
   genesis. (Residual unification items between the validity-path and close-path registration surfaces are
   tracked in D7's "Residual".)

---

## L. Delegate account (added feature, 2026-06; D9)

> Historical enrollment/account evolution. Current counts are u8 members (2..8) and u16 delegates
> (total at most 1024). The registered eight-leaf sig-cluster root differs from the live 1024-leaf
> wallet root. Current delegate payout authority is the signed balance-slot recipient/Regev leaf,
> not the old constructor-supplied delegate map in L-5. Settlement activation freezes its live
> participant snapshot; the Manager's exact delegate-count binding is not a mutable join registry.

A **delegate account** is a channel participant that has a lattice (Regev) balance and SENDs / RECEIVEs /
WITHDRAWs with the **identical proofs** a co-signing member uses, but does **NOT** participate in the
N-of-N multisig that co-signs channel-state updates. It relies on the co-signing members for state
maintenance. Not in abstract2.md; authoritative delta = **D9** in detail2-implementation-notes.md.
Threat model + adversarial review: `doc/tasks/delegate-account-threat-model.md` (DA1–DA6).

### L-1. Slot regions (one fixed-`MAX_CHANNEL_MEMBERS` array, contiguous regions)
`delegate_count: u8` is added alongside `member_count: u8` on `BalanceState`, `ChannelRecord`, and the
registration record. With `active = member_count + delegate_count` (slot capacity
`MAX_CHANNEL_MEMBERS` = **1024** since D12; it was 16 when this section was written):
- slots `0 .. member_count`            → **co-signing members** (balance + send/receive + N-of-N co-sign; `member_count <= MAX_COSIGNERS = 16`, D12).
- slots `member_count .. active`       → **delegates** (balance + send/receive/withdraw; **NO** co-sign).
- slots `active .. MAX_CHANNEL_MEMBERS` → padding (canonical empty ciphertext, `pending_adds = 0`).

Invariants (enforced natively + in-circuit + Solidity): `2 <= member_count <= MAX_COSIGNERS`,
`active <= MAX_CHANNEL_MEMBERS` (overflow-safe `checked_add`), active slots non-padding and
pairwise-distinct `pk_g`, padding slots canonical,
`bp_member_slot < member_count` (the block proposer must be a co-signing member, never a delegate).

### L-2. Trust model (DLG-1 / DLG-2 / DLG-3)
- **DLG-1 (theft protection — TRANSITION LAYER, honest-member only):** a debit of a delegate's slot is
  bound to the delegate's OWN send authorization (E-1 `channelTxZKP` + the BabyBear A11 hash-sig over the
  IMPA digest). **Honest signing members refuse to co-sign a state update that debits any slot via a send
  lacking that sender's signature.** So under honest members, a delegate's funds move only by its own
  authorization. Enforced by member honesty at sign time, NOT cryptographically at close.
- **DLG-2 (final balance is TRUSTED to the members):** the delegate does not co-sign state, so **fully
  colluding members CAN forge the delegate's final balance** (under-report it). Accepted by design — the
  delegate has no cryptographic recourse; the N-of-N members' co-signature over the final state is
  authoritative. The delegate also trusts members for others' balance soundness + sum conservation.
- **DLG-3 (censorship / liveness): OUT OF SCOPE.** The delegate relies on members for inclusion of its
  sends and close cooperation. Also covers the on-chain deployer-asserted delegate binding (L-5) — a
  misbind only DENIES the delegate's honest claim (it cannot steal; E-3 needs the delegate's Regev key),
  i.e. griefing, not theft.

The only non-negotiable on-chain guarantees the delegate inherits (same as members): **solvency**
(Σ all withdrawals ≤ channel fund) and **no double-withdraw** (nullifier).

### L-3. Data layer — where `delegate_count` is committed
`delegate_count` is committed as ONE u32 limb **IMMEDIATELY AFTER `member_count`**, byte-identically,
in every "twin" preimage so the member/delegate/padding split is fixed under the members' signatures:
- `BalanceState::h1()` (IMBS) + the close-circuit in-circuit H1 recompute (`close_circuit.rs`).
- `ChannelRecord::signing_digest()` (IMCR) — NATIVE-ONLY digest (no circuit/Solidity twin).
- Registration reg-chain keccak preimage: native `ChannelRegRecord::hash_with_prev_hash` + in-circuit twin
  `channel_reg_step` (`channel_reg_hash_with_prev_hash_circuit`) + Solidity `IntmaxRollup.registerChannel`.
  `CHANNEL_REG_PREIMAGE_U32_LEN`: **475 → 476**. (Re-pinned differentials `PINNED_MC2/8/16`.)
- Close PI vector: `delegate_count` appended at the END (limb 86, after `member_count` at 85);
  `CHANNEL_CLOSE_PUBLIC_INPUTS_LEN`: **86 → 87** *(now 95: the Stage-3 accumulator insertion shifted
  `member_count`/`delegate_count` to limbs 93/94 — §F-3)*; Solidity `closePIHash` appends it (packed
  `(memberCount<<8)|delegateCount` into one uint16 in `CloseProofFields`).
- **IMCM** close member-set commitment (`close_member_set_commitment`) STAYS **member-only**
  (`0..member_count`) — delegates do not co-sign, so they are excluded.
- `member_pubkeys_root` / the reg `MemberTree` COVER active (members + delegates) — a delegate has a real
  `MemberLeaf{pk_g, pk_b, regev_pk_digest}` identity so it can send + withdraw.

> **Gotcha (D9):** adding the `delegate_count` limb changes every hash that includes the registration
> EVEN when `delegate_count = 0`. The reg preimage is folded on-chain into `_pendingChannelRegHashChain`,
> which is bound into the validity proof's block-hash-chain, so ALL baked validity/c2c/withdrawal/close MLE
> fixtures were regenerated. "delegate_count = 0 ⇒ byte-identical" holds for newly-generated artifacts
> (Rust ↔ circuit ↔ Solidity agree) but NOT for baked proofs. A conditional-omit-when-0 encoding was
> rejected (it would make the R3 word-aligned fixed-length single-keccak preimage variable-length).

### L-4. Send / receive / withdraw / refresh (active-region; co-sign stays member-only)
- **Send (delegate as sender):** identical to a member send — E-1 debits the delegate's slot, the BabyBear
  A11 hash-sig authorizes (DLG-1). The off-chain checks (`wallet_core`: `check_slot`, `member_pubkeys_root`,
  the member-list bijection, `verify_send_transition`/A11) admit the full active region
  (`member_count + delegate_count`). The in-circuit `state_update_verifier` E-1 path is slot-agnostic.
  `build_send` self-signs the next state ONLY for a member sender (`slot < member_count`); a DELEGATE is
  send-only and adds NO state signature.
- **Receive:** homomorphic credit to the delegate's slot, no signature (slot-agnostic).
- **Balance refresh (detail2 §B-3):** after RECEIVING, a slot's `pending_adds` raises. *(Historical:
  it then became receive-only until a refresh. Since 2026-09-21 the decrypted send spends such a
  position directly — §E-1b/§E-2b — and the refresh below is optional maintenance.)* A refresh
  re-encrypts to clean digits, same value, `RefreshAir` proof. Wallet API:
  `wallet_core::build_refresh` / `verify_refresh_transition` (+ `regev::prove_balance_refresh_witnessed`,
  which also returns the fresh `AmountWitness` so the wallet can spend again) → wasm `wallet_refresh()` →
  CLI `cosign-refresh`. Works identically for a member or a delegate slot; the members co-sign, the
  delegate does not.
- **Withdraw (delegate at close):** the final member-signed `BalanceState` includes the delegate slots. A
  delegate withdraws via the SAME `WithdrawalClaim` + E-3 `withdrawClaimZKP` a member uses — the claimant
  slot gate is `member_index < member_count + delegate_count` (`withdrawal_claim_pis.rs`); H1 (signed) binds
  the active/padding boundary, the ciphertext binding + E-3 decryption are slot-agnostic; the per-(close,
  pk_g) nullifier + solvency cap bound double/over-withdraw (DA4). The delegate is NOT among the IMCH close
  co-signers (only `member_count` members sign the close state — DLG-2).
- **Co-sign (UNCHANGED, member-only):** `verify_all_signatures` / `validate_all_member_signatures`, the
  close circuit `active_bits` + IMCM member-set rebuild, and the validity bp set ALL stay `0..member_count`.
  The split is signed (both counts in H1/IMCR), so neither side is relabelable without all members' consent.

### L-5. On-chain (Solidity)
- `IntmaxRollup.registerChannel(channelId, bpSlot, delegateCount, memberPkGs, pkBs, regevPkDigests, recipients)`
  — the arrays carry the ACTIVE participants (members first, then delegates); `memberCount = arrayLength −
  delegateCount`; `delegateCount` is committed in the reg preimage after `memberCount`. (Four registerChannel
  require-strings were converted to custom errors to keep IntmaxRollup runtime under the EIP-170 24,576-byte
  limit after the delegate logic.)
- `ChannelSettlementManager` constructor takes a `delegateBindings` array (length = `delegateCount_`).
  `_registerDelegates` records each delegate's `(pk_g → recipient)` in `registeredMemberIndexPlusOne`
  (non-zero presence marker), `registeredRecipientOf`, and `isMemberRecipient`, so `submitWithdrawalClaim` /
  `submitPostCloseClaim` accept delegates. Delegates are NOT added to `registeredMemberPkGs` / `memberPkGs`,
  so the IMCM member-set commitment (`closeMemberSetCommitment`, uses `activeMemberCount`) and the N-of-N set
  stay member-only. Delegate pk_g must be distinct from every member AND every other delegate. The global
  solvency cap `totalWithdrawn ≤ finalizedChannelFundAmount` already covers members + delegates. TRUST:
  delegate bindings are deployer-asserted (not re-checked vs the member-only registry IMCM) — DLG-3.
- `closePIHash` takes the `CloseProofFields` struct (byte-identical 87-limb preimage) to keep callers within
  the via-IR stack budget once the trailing limb count grew from 1 to 2.

### L-6. Status
Implemented + independently security-reviewed (separate adversarial agent: GO, no CRITICAL/HIGH; DA1–DA6 all
blocked or accepted-as-designed). Branch `real-delegate-paymentchannel`. GREEN end-to-end: Rust native +
circuits, Solidity forge full suite, and a real 2-session browser test (Playwright) of the wallet-live
delegate demo (open as distinct delegate slots → send → receive → refresh → send again). A wallet-live demo
runs 3 CLI co-signing members + browsers as send-only delegates (`channel_member` / `wallet-relay.js` /
`wallet-live.html`).

---

## M. v2.1b batched co-sign: slim wire format + streaming verification (2026-07-23)

Implements abstract2-1 §2.2b/§3.2b at scale. The first batch implementation (2026-07-19) transported
K full `SendPayload`s; a 1000-sender storm showed that format is the scalability wall, NOT the batch
design: at 1016 active slots one `SendPayload` is ~16.8 MB (≈ 4.8 MB padded `proposed_next_state` +
~8 MB `members` list + E-1/A11 proofs), so K×16.8 MB hits, in order, the express JSON.parse
serialization stall, the V8 max-string (~512 MB ⇒ K ≤ 30), and the relay heap (core-dump at
K ≈ 1000). This section replaces the batch transport with the spec's own slim shape and bounds every
memory use independently of K.

### M-1. Wire types (slim)

```rust
/// One sender's contribution to a batch — abstract2-1 §2.2b `SignedChannelTx` (+ the E-1 `after`
/// ciphertext, which the fold installs). Serialized camelCase; `anchor_digest` FIRST so a
/// transport can extract it from the head of the byte stream without a full parse.
pub struct SlimSendPayload {
    pub anchor_digest: Bytes32,       // digest(S) the tx extends (== ChannelTx signing anchor)
    pub sender_index: u16,            // balance slot (member OR delegate)
    pub recipient_index: u16,
    pub channel_tx: ChannelTx,        // enc_amount, nonce, E-1 zkp, sender pk_g/pk_b + A11 hash-sig
    pub after_ct: RegevCiphertext,    // sender's fresh post-debit ct (the E-1 `after`)
}
```

- **Batch file (relay → CLI): NDJSON** — line 1 a `{"anchorDigest": …, "k": …}` header, then one
  `SlimSendPayload` per line. No single JSON document ever aggregates the batch (kills the V8
  512 MB stringify cap and lets the CLI parse line-at-a-time).
- Dropped vs the fat `SendPayload`: `proposed_next_state`, `members`, `record`. **Every dropped
  field is data the verifier must already hold** (its own head state and its own
  verified-at-import member set / record). One slim tx ≈ the two ciphertexts + the E-1 + A11
  proofs (~4 MB at Production level today; proof size is the remaining wire weight).

### M-2. Verification obligations (unchanged model, stronger posture)

Per abstract2-1 §3.2b.3, the co-signer recomputes everything from its OWN authenticated context:

1. `anchor_digest == digest(own head S)` — batch-level; additionally each tx's A11 sender
   hash-sig already binds the anchor (M-3), so a mismatched tx also fails its signature.
2. R1: sender slots pairwise distinct (reject batch).
3. Per tx (bounded-parallel): rebuild the solo next-state from S
   (`enc[sender] = after_ct`, `enc[recipient] += enc_amount`, `pending_adds` update, version+1)
   and run the EXISTING hardened `InChannelTransferUpdateWitness::verify` + A11 sender-sig check
   against it — **`members`/`record` come from the verifier's own snapshot, never from the wire.**
   The fat path's P4-1/A11 re-authentication of a peer-supplied member list becomes moot on the
   slim path (there is no peer-supplied member list at all); the trusted-record binding is the
   verifier's own.
4. Canonical fold R3 (debits install `after_ct`, then homomorphic credits), D3 `pending_adds`
   budget post-fold, uninvolved slots untouched by construction.
5. N-of-N signing round over `hash(H1', 0)` as before. K = 1 slim fold is field-identical to the
   solo `proposed_next_state` (same digest), preserving the browser witness-commit fast path.

### M-3. Anchor binding is exact (intentional divergence from abstract2-1 §2.2 "retry-friendly")

The IMPA `ChannelTx::signing_digest` preimage contains `prev_state_digest` (§C-5), so a sender's
tx authorizes application at EXACTLY one anchor. abstract2-1 §2.2 would allow re-applying at any
later state whose sender ct is unchanged (the before-binding nullifier alone); the implementation
is STRICTER: a tx that misses its batch must be re-signed (the wallet redoes the cheap A11 sig; the
E-1 proof itself is anchor-independent — its statement binds `(before-ct, encAmount, after)` — but
the implementation regenerates the payload wholesale today). Strictly-tighter authorization ⇒ no
soundness impact; noted for spec fidelity.

### M-4. Memory plan (every bound K-independent)

| Stage | Mechanism | Bound |
|---|---|---|
| relay ingest (`/api/cosign2`) | stream request body straight to a per-request spool file (no express.json); stale-filter reads `anchorDigest` from the first bytes | O(1) heap per request |
| relay queue | holds `{file, anchorDigest}` tuples only | O(K) tuples, ~100 B each |
| batch handoff | concat spool files into NDJSON (streamed append) | O(1) heap |
| CLI `cosign-batch` | read NDJSON line-at-a-time; verify with bounded rayon parallelism (chunks); after a tx verifies, RETAIN only `(sender, recipient, enc_amount, after_ct)` (~8 KB) and DROP the proofs | O(chunk) proofs + O(K×8 KB) retained |
| fold + sign | over retained ciphertexts | as today |

Legacy paths kept: `/api/cosign` (fat solo, browser) is unchanged — including the K = 1
sender-state-sig carry-over; when the relay coalesces K > 1 requests it CONVERTS each fat payload
to slim at enqueue (extract `after_ct = proposedNextState.encBalances[senderIndex]`, drop the
rest) and routes through the slim batch path. Browser member-senders inside a K > 1 batch remain
a known limitation (their Goldilocks state sig cannot be minted by the relay) — same as the
2026-07-19 implementation; live-demo browser users are delegates, which never state-sign.

### M-5. Relay hardening (from the 2026-07-22/23 storm findings)

- `MAX_BATCH_K` cap (default 1024) — a batch never exceeds it; overflow waits (stale-filtered
  against the post-batch head as today).
- HTTP listen backlog raised (default 511 dropped ~5% of 10,000 simultaneous connects); pair with
  kernel `somaxconn`.
- Spool directory bounded by disk, not heap; spool files unlinked after batch consumption.

### M-6. Security summary

The five properties are those of abstract2-1 §4.2b verbatim — the slim wire carries exactly the
information content of the Lean batch model (`ChannelSafety21.lean` §8 `BatchTx {sender,
recipient, amount, encAmount, afterCt}`), which is what `batch_preserves_validity` /
`batch_conserves_total` / `batch_step_eq_seq` are proven over. Nothing security-relevant moved:
`before` never comes from the wire; the signature target `hash(H1', 0)` is derived by each
verifier from its own verified inputs; R1/R3/D3 and the before-binding cross-batch nullifier are
unchanged. What changed is WHERE redundant copies of already-held data are (no longer on the
wire) and how memory scales (streaming, K-independent bounds).

### M-7. Relay batch window: 1 s / 200 tx per co-signed transition (2026-08-23)

§M-1..6 specified the slim transport and the CLI's `cosign-batch`; the relay still routed every
`/api/cosign` through the SOLO path (K = 1 per N-of-N round). M-7 closes that gap: the relay
coalesces requests into windows and the channel co-signs ONE state transition per window.

- **Window**: on the first enqueued payload the relay opens a `BATCH_WINDOW_MS = 1000` window for
  that channel. Every `/api/cosign` arriving inside it joins the same window, capped at
  `BATCH_WINDOW_MAX = 200` txs; the 201st tx (or any tx arriving after close) opens the NEXT
  window. The window closes on whichever comes first — the timer or the cap — then drains under
  the per-channel lock.
- **Anchor pre-filter (stale = per-tx error, not batch poison)**: at drain, payloads whose
  `proposedNextState.prevDigest` differs from the channel's CURRENT head digest are rejected
  individually (HTTP 409, `staleAnchor`); the client re-signs per §M-3. Only same-anchor payloads
  form the batch, so the CLI's batch-level anchor check can only fail on a head moved by a
  non-window writer (inter-channel credit, refresh) — those still serialize behind the same lock.
- **Drain**: K = 1 → the EXACT legacy solo path (`cosign payload.json`), preserving the browser
  member fast path and the K = 1 state-sig carry-over. K > 1 → each fat payload is projected to
  `SlimSendPayload` per §M-4 (`afterCt = proposedNextState.encBalances[senderIndex][channelTx.tokenSlot]`,
  `anchorDigest = proposedNextState.prevDigest`), spooled one file per tx, and handed to
  `cosign-batch` as a §M-1 manifest. All K waiters receive the SAME fully-signed batch state.
- **Fail-whole fallback**: `cosign-batch` is deliberately fail-whole (one invalid proof rejects
  the batch — §M-2 obligations are per-tx but the fold is all-or-nothing). To stop one bad tx
  DoSing its window, on batch rejection the relay REPLAYS the window sequentially through the
  solo path: honest txs land (each its own co-signed transition), the invalid tx alone errors.
  The fallback is bounded — it runs only on rejection, and a window is ≤ 200 txs.
- **Throughput shape**: worst case (window always full) the channel commits 200 tx per N-of-N
  round at ≥ 1 round/s — the §M streaming bounds hold (200 < MAX_BATCH_K = 1024). The browser
  member-sender limitation of §M-4 is unchanged: inside a K > 1 batch only delegates can send
  (live-demo browsers are delegates; a member-sender window degrades to K = 1 solo rounds via
  the fallback if it ever produces a batch rejection).

---

## N. Multi-token channels: historical migration to up to 10 currencies (2026-07-27)

> Multi-token representation and per-token settlement are now implemented as described in the
> current contract above. Phase status and regeneration notes in this section belong to the July
> migration; they do not describe current release acceptance or an unimplemented scalar-to-vector change.

Extends the channel layer from one balance scalar per slot to up to `MAX_CHANNEL_TOKENS = 10`
independent per-token balances, funded by and settled against the base layer's existing
`token_index: u32` machinery (spec.md §1.1–1.2), including REAL ERC-20 escrow on L1.
Owner decisions fixed 2026-07-27: (1) L1 scope includes ERC-20 escrow; (2) balance representation
is the fixed in-leaf token vector; (3) token set = init + append-only cosigned adds; (4)
in-channel cross-token swap is OUT OF SCOPE for v1 — every tx conserves within exactly one token;
(5) no live migration — v3 testnet resets (a v1 state is definitionally `registry=[ETH]`, all
balances at token slot 0). Threat model: `doc/tasks/multitoken-threat-model.md` (TM-1..TM-15);
every obligation below cites its TM id. Implementation plan: `doc/tasks/multitoken-todo.md`.

### N-1. Token registry (channel-local, inside the signed H1 header)

```rust
pub const MAX_CHANNEL_TOKENS: usize = 10;

// In BalanceState (§C-2):
pub token_registry: [u32; MAX_CHANNEL_TOKENS], // local token slot t -> BASE token_index; zero-padded
pub token_count: u8,                           // 1 <= token_count <= 10 (TM-8)
```

- BOTH fields ride in the H1 header preimage (26 → 37 elems: `+ token_count (1) + registry (10
  canonical u32 limbs, always full width, zero-padded)`), new header domain constant. Mirrors the
  `member_count`/`delegate_count` discipline exactly — an unsigned active/unused token boundary is
  reinterpretable under existing signatures (TM-9).
- Registry is injective on base `token_index` over `[0..token_count)` — enforced IN-CIRCUIT in the
  `TokenRegister` transition and re-checked in the close circuit (TM-1). No removal, no reorder:
  local index stability is what gives every historical ciphertext a stable meaning.
- `ChannelTransitionKind::TokenRegister` (new): appends `token_index` at position `token_count`,
  increments `token_count`, `state_version`+1, N-of-N cosigned like any transition. Leaves are
  UNTOUCHED (all 10 ciphertext positions exist from genesis as canonical zeros; the registry lives
  only in the header), so registering a token is a header-only state change.
- A channel MAY register a token_index with no L1 ERC-20 registration; it is inert (imports
  require L1 deposits, so `fund[t]` stays 0 and claims decrypt to 0). See threat model residual #4.

### N-2. Balance-slot leaf v2 (fixed 10-wide ciphertext vector)

```
leaf_i = Poseidon([ SLOT_LEAF_DOMAIN_V2,
  regev_pk_digests[i]      (8),
  ct_digest[i][0..10]      (80),   // 10 independent RegevCiphertexts, one per token slot
  pending_adds[i][0..10]   (10),   // per-(slot, token) homomorphic-add counters (D3, TM-13)
  recipient[i]             (5) ])  // 104 elems total (was 23; Address is canonically 5 u32 limbs)
```

- Each token position is an independent Regev ciphertext: D1 encoding (u64, 1 bit × 64 coeffs),
  the 64-add refresh budget, and RefreshAir all apply per (slot, token) unchanged. The
  cryptographic layer does not change.
- Unused positions (`t >= token_count`, and any token a member does not hold) use the canonical
  zero ciphertext (`RegevCiphertext::padding()`, all-zero coeffs — decrypts to 0 under ANY key, so
  unused-position claims provably yield 0; TM-8). Its digest is a precomputed constant; storage
  MAY be sparse (materialize nonzero balances only), the hash layout is always full width.
- `validate()` fail-closes per (slot, token): positions `t >= token_count` MUST equal the
  canonical zero digest with `pending_adds == 0`; all 10 counters range-checked against
  `MAX_HOMO_ADDS_BEFORE_REFRESH` (TM-8, TM-13).
- The widening applies to ALL leaves (padding slots included) simultaneously under the new leaf
  domain — same fixed-width injective discipline as the D14 18→23 change (TM-9, TM-15).

### N-3. Intra-channel transfer: IMPA-v2 + the token binding triple (TM-2)

- `ChannelTx` gains `token_slot: u8`, occupying its OWN canonical limb in a NEW-domain IMPA-v2
  preimage (no bit-packing into existing words, TM-15):
  `[IMPA_V2, channel_id, prev_state_digest, enc_amount.digest, nonce, token_slot,
  sender_pk(8), recipient_pk(8)]`.
- E-1 (`DualKeyTransferAir`) is UNCHANGED internally. The transition verifier
  (`InChannelTransferUpdateWitness::verify` generalization) enforces the binding triple as
  connected constraints — this wrapper is the soundness-critical seam:
  1. `token_slot < token_count` (and < 10) — TM-8;
  2. signed `token_slot` == leaf one-hot select == the ONLY position of 10 whose ct digest
     changes, on the sender leaf (prev → `after_ct`) AND the recipient leaf (`+= enc_amount`);
     the other 9 positions proven identical prev→next on both leaves;
  3. `pending_adds` increments only at `(recipient, token_slot)`;
  4. E-1 is handed exactly the (prev, after) ciphertexts selected by `token_slot`.
- One tx = one token. Cross-token conservation is structural: no transition mutates two token
  positions (swap is a future feature with its own two-leg signed transition; out of scope v1).
- Slim wire (§M-1): `SlimSendPayload` gains `token_slot` (echo of the signed field; the verifier
  trusts only the digest-bound copy). v2.1b batch obligations (§M-2 step 3) generalize per token:
  the per-tx solo-rebuild + verify covers the FULL binding triple over all 10 positions for every
  tx — never only the tokens with nonzero delta (TM-14). Mixed-token batches are allowed; the
  canonical fold (§M-2 step 4) is per-(slot, token).

### N-4. Inter-channel transfer (C2C): base token_index end-to-end (TM-6)

- The transfer descriptor carries the BASE `token_index: u32` (never a local slot — source and
  destination registries map it to different local slots).
- E-2 (`ChannelUpdateAir`) unchanged internally; its PI gains `token_index`. BOTH sides'
  transition verifiers constrain, against their OWN H1-committed registries:
  `registry[local_slot] == token_index ∧ local_slot < token_count`, and apply the delta at that
  local position only (binding triple as in N-3). Unregistered on either side ⇒ reject in-circuit.

### N-5. Mid-channel L1 deposit import (§C-10 v2): three-way binding (TM-7)

- `l1_deposit_import_digest` v2 (new IMLD-v2 domain): gains `token_index` as its own limb:
  `keccak([IMLD_V2, channel_id, deposit_nullifier, token_index, amount_lo, amount_hi,
  depositor_slot])`.
- The import transition constrains, in-circuit: the base deposit's `token_index` (already present
  in the base `Deposit`, spec.md §1.2 — no longer dropped) resolves via the registry to local
  slot t; `channel_fund[t] += amount`; the credited ciphertext is the depositor leaf's position-t
  ciphertext; binding triple for the other 9 positions as in N-3.

### N-6. Close, claims, settlement: per-token funds (TM-1/3/5/8/11)

- `ChannelFund` → `amounts: [U256; MAX_CHANNEL_TOKENS]` aligned to the registry; `withdrawCap` is
  per token.
- Close PI: `+ token_funds_digest (8 limbs)` where
  `token_funds_digest = keccak([TFD_DOMAIN, registry (10×u32, zero-padded), token_count,
  amounts (10×U256, zero-padded)])` — ALWAYS full width (variable-length preimages alias, TM-11).
  `CHANNEL_CLOSE_PUBLIC_INPUTS_LEN` 95 → 103; Rust↔Solidity byte-for-byte differential test
  re-pins the `closePIHash` preimage.
- Withdrawal claims are per (member slot, token slot). E-3 (`DecryptionAir`) unchanged; the claim
  circuit opens the leaf, one-hot selects `ct_digest[token_slot]` bound to the PI `token_slot`,
  and exposes the resolved BASE `token_index` (`registry[token_slot]`, with
  `token_slot < token_count`) so L1 pays the right asset.
- Nullifier v2: `[IMCW_V2, close_intent_digest (8), slot_regev_pk_digest (8), token_slot]` —
  keyed on the LEAF-BOUND Regev pk digest exactly as today (B-2 grinding fix preserved, see
  channel.rs:857-870), plus the token slot. Exactly one nullifier per (slot, token). NEVER keyed
  on `member_pk_g` (TM-5).
- `ChannelSettlementManager`: EVERY accounting variable becomes per-base-token —
  `finalizedChannelFundAmount[t]`, `totalWithdrawn[t]`, `receivedChannelFunds[t]`,
  `totalCreditedOut[t]`, `withdrawalCredits[t][addr]` — with per-token CapInv
  `totalCreditedOut[t] + amount <= receivedChannelFunds[t]` and payout dispatch by t
  (t == 0 → ETH; else ERC-20 at the L1-registered address). Token-t claims are paid ONLY from
  token-t funds (TM-3). Current `claimWithdrawalCredit(bytes32)` pays one proof/nullifier-scoped
  record and subtracts only its amount from aggregate credit. `totalWithdrawn` is the lifetime
  accepted-claim amount; `totalCreditedOut` is the actual paid amount. Funding pulls exactly the
  remaining finalized cap after the terminal authorization is issued and consumed, and rejects
  a mismatched native/ERC-20 balance delta. Unrelated recipient-wide Rollup credit alone is not
  evidence that this channel's terminal proof was materialized.
- **Historical post-close claim token binding (TM-16, Phase 5a; current entry point disabled):**
  the following describes the retained historical circuit/PI format, not an active extra-credit
  path. `submitPostCloseClaim` unconditionally reverts; ordinary slot-balance claims already include
  absorbed incoming value. The inter-channel `tx_hash` fold — the
  settled-tx-accumulator leaf and the only artifact of an absorbed incoming tx that the closed
  channel's signed final state anchors — gains the descriptor's BASE `token_index` as its own
  canonical limb in the IMTC ids word: `ids = [0,0,0,0,0, token_index, dest_id, src_id]`
  (`common::channel::inter_channel_tx_hash`; before TM-16 no anchored preimage carried the
  token, which forced the L1 genesis-registry[0] pin). Post-close claim PI 56 → 57: `token_index`
  appended at limb 56, wired in-circuit as the SAME wire as ids limb 5 of the `incoming_tx_hash`
  recompute (never an independent witness); the Manager credits
  `withdrawalCredits[tokenIndex]` / accrues `totalWithdrawn[tokenIndex]` against
  `finalizedChannelFundAmount[tokenIndex]` from the strict-bound limb, with a registry-membership
  re-check (defense in depth over the zero cap). Soundness obligations (threat model TM-16):
  every absorb-time gate recomputes the token-bearing `tx_hash` from the descriptor's OWN
  `token_index` before chaining/accumulating it, and the replay/consumed ledgers key on the
  token-FREE identity (`InterChannelTx::replay_identity` — the v1 fold) so a second token-variant
  of the same debit is refused as a replay.

### N-7. L1: real ERC-20 escrow in IntmaxRollup (TM-1/4/10)

- Append-only, set-once `tokenIndex → IERC20` registry (immutable per index once set; a
  remappable index converts token-A escrow into token-B withdrawals, TM-10b). Index 0 remains
  native ETH.
- `deposit(tokenIndex != 0)`: `nonReentrant`; measure `balanceOf(this)` delta around
  `safeTransferFrom`; REVERT unless delta == stated amount (the deposit hash chain must never
  record unreceived value). Fee-on-transfer / rebasing / hook-reentrant tokens are UNSUPPORTED
  and fail closed (TM-4). The "accounting-only nonzero tokenIndex" regime is retired.
- Per-token escrow ceiling: `escrowed[tokenIndex] -= amount` with underflow-revert on every
  withdrawal — the per-token analogue of today's global `totalEscrowed` solvency backstop.
- `withdrawERC20` mirrors `withdrawNative` (same authDigest binding, which already includes
  `tokenIndex`), gated on `tokenIndex != 0` with a registered address; `withdrawNative` keeps its
  `tokenIndex == 0` guard.

### N-8. Privacy deviation (ACCEPTED, TM-12)

`token_slot` travels in cleartext (IMPA-v2, slim wire), and per-(member, token) close claims
reveal each claimant's recipient, token and claimed amount on chain: `WithdrawalClaim.amount`
is public calldata. The confidentiality of balances during channel operation does not extend to
amounts explicitly claimed on L1. Asset identity is also public. This is an interface boundary,
not a cryptographic confidentiality theorem.

### N-9. Formal model + security summary

- Lean: the historical multi-token design extension is in `ChannelSafetyMT.lean`; the frozen
  `ChannelSafety2/21.lean` modules are not silently replaced by a current multi-token contract model.
  `ChannelSafetyCurrent.lean` covers the current fixed-channel, finalized-cap, per-base-token
  claim/pull/payout slice, including lifetime claim allocation and nullifier-scoped payments.
  A separate slice in that module covers current close replay fences and strict deadlines;
  its composition with finalized accounting remains an explicit open obligation.
  `Zkp.Contracts.CurrentVerification` covers the current compact verification/finalization/fraud
  boundary. [The dated scope](../audit/lean-current-safety.md) lists assumptions and exclusions.
- Domain constants: every changed preimage gets a NEW constant (slot leaf, H1 header, IMPA, IMLD,
  IMCW, E-2 PI, TFD), registered in §G-2 with the non-collision check at implementation time;
  new fields always occupy their own canonical limb (TM-15).
- The three load-bearing properties (threat model): P1 the token binding triple (N-3), P2
  per-token conservation on every path (N-3/4/5/6), P3 L1 per-token isolation with no residual
  single-asset variable (N-6/7). A fresh attacker-subagent pass over the actual diffs is REQUIRED
  before each implementation phase merges.

---

## O. Falcon-512 (Poseidon hash-to-point) unified signing key (2026-08; branch `feat/falcon-poseidon-sig`)

**SUPERSEDES the Goldilocks half of §A-3 / §B-4 / §D-4.** The Poseidon-preimage ZK signature
(`SingleSigCircuit`, `pk_g = Poseidon(IMPG‖sk)`) and both of its aggregators
(`poseidon_sig::aggregate::AggLevelCircuit` for close/cancel, the `SingleSig`-leaf `ListCircuit`
for validity) are **DELETED**. Everywhere `sk_g` signed, a **Falcon-512 signature with
Poseidon hash-to-point** signs instead. The BabyBear sender key `pk_b` (§B-4, Plonky3
`Poseidon2HashSigAir`) and the Regev encryption keys are **UNCHANGED** — this is a one-key
replacement, not a re-architecture. Threat model: `doc/tasks/falcon-sig-threat-model.md`
(TM-C1..C13, obligations O-1..O-12); plan and phase notes: `doc/tasks/falcon-sig-todo.md`,
`doc/tasks/falcon-sig-phase{0,1,2,2_5,2_6,3,4,5}-notes.md`.

### O-1. The scheme

Falcon-512 (`n = 512`, `q = 12289`), vendored from `0xMiden/crypto`'s `falcon512_poseidon2`
(MIT/Apache-2.0) at `src/falcon_sig/vendor/` with **only** `hash_to_point.rs` replaced: the
sponge is the in-tree plonky2 Poseidon (Goldilocks, width 12) under the new capacity domain
**IMFH**, absorbing `salt(40 B) ‖ message_digest(32 B)` and squeezing 64 × 8 = 512 coefficients,
**one full field element per coefficient** reduced mod `q` (the Falcon spec's sanctioned
no-rejection variant; bias ≈ 2^-41 total — A-F3/O-1). ffSampling, samplerz, the FFT and NTRU
keygen are untouched vendor code.

- Verification equation: `s1 = c − s2·h mod q mod (X^512 + 1)`; accept iff
  `‖(s1, s2)‖² ≤ β² = 34 034 726`.
- Salt: **40-byte CSPRNG salt per signature, randomized — not deterministic signing** (TM-C2;
  CARDIS-2023 fault attack on deterministic Falcon). Sampled once outside the retry loop.
- Wire format (`FalconSignature`): `FALCON_SIG_V1(1) ‖ salt(40) ‖ compressed s2 (625, Falcon
  Golomb-Rice)` = **666 B**. The version byte is checked FIRST, before length and before any
  structural parse, so a legacy ~76 KB `SingleSigCircuit` blob is rejected at the gate with a
  distinct `UnsupportedVersion` error (O-9/TM-C8). The encoding is a bijection — signature BYTES
  feed `SignedSmallBlock::signing_digest()` downstream.
- Measured (native, M-series): keygen ~455 ms, sign ~5.4 ms, verify ~63 µs. Keygen runs at
  **join/restore only**, never per signature.

### O-2. Member identity: `pk_g` redefined IN PLACE

`pk_g = Poseidon(IMFK ‖ encode(h))`, where `encode(h)` is the canonical packing of the 512
public-polynomial coefficients (each `< q`). This **replaces** `Poseidon(IMPG ‖ sk_g)` at the same
32-byte width and the same slot everywhere: `MemberLeaf` stays 3 fields, the L1 registration
keccak preimage is unchanged, the `IMCM` member-set commitment keeps its domain and layout, the
`IMLL` list-leaf format still binds a 32-byte `pk`, and Solidity's `bytes32 pkG` is untouched.
**Layouts do not change; VALUES do** — which is why the whole fixture/VK set regenerates (§O-6)
and why the migration needs no schema change on any JS/relay/CLI/Solidity consumer.

One key per member signs **both** contexts, exactly as `sk_g` did: the channel-state co-sign
(**IMCH** digest) and the bp's small-block root (**IMSB** digest). Isolation rests entirely on the
two digests being distinct keccak outputs over distinct-domain, distinct-layout preimages, and on
neither consumer ever accepting a caller-supplied message (§O-3). Pinned in BOTH directions at the
two REAL circuit entry points by `falcon_sig::list::tests::imch_and_imsb_signatures_reject_in_both_directions`
(TM-C6/O-6).

`MemberKeys` holds the key as `Arc<FalconKeys>` derived from the member seed via
`FalconKeys::from_seed` (ChaCha20 seeded with `keccak256(IMFG ‖ seed)`, §G-2). The registration
path and the signing path share the **same key object**, so "the registered identity is the signing
identity" holds by construction rather than by two derivations agreeing (this is what closed the
Phase-3 identity-split finding).

### O-3. Consumers

| Consumer | Before | After |
|---|---|---|
| Wallet / wasm / CLI channel-state co-sign, native N-of-N verify | `SingleSigCircuit` proof (~76 KB), verified by a plonky2 verifier | **native Falcon verify**, ~63 µs, **no circuit built and no proof produced** on the co-sign path |
| Close / cancel-close circuits | recursive verify of ONE `AggLevelCircuit` proof | recursive verify of ONE **`falcon_sig::agg::FalconAggCircuit`** proof at constant VK — a pure VK swap; close degree unchanged at 2^17 |
| Validity path: bp's IMSB signature (`ListCircuit` → `bp_sig_chain`) | `SingleSig` proof as leaf, recursively verified per list step | the list step **verifies the Falcon signature directly in-circuit** with the Phase-1 gadget; `list_leaf` / `chain_step_target` / `bp_sig_chain` formats all UNCHANGED |

**In-circuit gadget** (`src/falcon_sig/circuit.rs`, Phase 1): H2P in-circuit (64 Poseidon
permutations, native gates), an NTT mod-12289 gadget with range-checked reductions, `s2`
canonicity, the norm bound at β², and the `h` → `pk_f` opening. Measured **~51.7 k gates per
signature** (N=1 → 2^16, prove 2.2 s). **No plonky2 lookups anywhere** — Phase 2.5 established
that plonky2's LogUp lookup argument does not enforce table membership at this pin and was
REJECTED as unsound (`falcon-sig-phase2_5-notes.md`); every range check is binary/arithmetic.

**Aggregation shape (`FalconAggCircuit`, Phase 2.6)** — replaces D-4's `AggLevelCircuit` tree with
the same statement over Falcon leaves: a **binary tree**, leaf at 2^16 + `AGG_LEVELS = 4` levels at
2^14, PI layout per level `[message(8), signer_count(1), pk_0..pk_{2^k−1}(8 each)]`. Left-packing
is enforced in-circuit; the leaf gadget is UNCONDITIONAL, so `signer_count ≥ 1` is structural and
`signer_count = 0` is unrepresentable. The close/cancel circuits bind `message == recomputed IMCH
digest` and `signer_count == member_count` and wire the cosigner key vector from the PI signer list
into the `IMCM` member-set commitment keccak and the A5 distinctness chain — **zero witnessed
freedom**, unchanged from D-4. The flat design was abandoned on memory: peak RSS 22.3 GB → 4.99 GB,
prove 70 s → 36.9 s.

### O-4. Co-signature wire: `h` travels (TM-C12, ACCEPTED)

`MemberSignature.signature` carries `FALCON_SIG_V1(1) ‖ salt(40) ‖ s2(625) ‖ h(1024 = 512 × u16
LE)` = **1690 B** (vs ~76 KB before, a ~45× reduction). `h` must travel because `pk_g` is a hash and
the verification equation needs `h` itself; widening `MemberInfo`/`MemberLeaf` instead was rejected
as it would break the layout stability this migration rests on **and** still need the same digest
check.

**`h` is untrusted input, never a source of identity.** It is consumed only through
`verify_with_pk_g`, which recomputes `Poseidon(IMFK ‖ encode(h)) == pk_g` — against the
AUTHENTICATED `record.member_pk_gs[slot]`, never against anything in the carrier — **before** the
signature check. Substituting an attacker's `(h', sig')` therefore requires a Poseidon second
preimage under IMFK (A-F4). This is the same check the in-circuit gadget performs. Publishing `h`
is not an unforgeability or linkability weakening (Falcon's `h` is public by design; `pk_g` was
already in the clear) — it removes a defence-in-depth layer, and that is the accepted consequence
recorded as TM-C12.

Structural gate (TM-C8): `validate_all_member_signatures` requires the **exact**
`FALCON_COSIGN_BLOB_BYTES = 1690`.

### O-5. Cross-platform keygen determinism (TM-C13 / O-12)

A wallet restored in the browser must derive the same `pk_g` as the CLI, or its L1 registration
names an identity it cannot reproduce and the channel becomes permanently unclosable. NTRU keygen
runs f64 arithmetic, and **this repository has already observed one wasm-vs-native numeric
divergence** (the Regev STARK verifier, recorded in `.cargo/config.toml`), so this is measured, not
argued: `hosting/check-falcon-wasm-keygen.sh` builds the cdylib, runs it under Node and compares
`pk_g(seed = [42; 32])` against the constant the native suite pins. **O-12: re-run before any
browser deploy and after any bump of the wasm toolchain, `num-complex`, `num-bigint`, or the
vendored Falcon math.**

### O-6. Migration consequences

- **VK cascade**: the list VK changed → the validity chain VKs changed; close/cancel VKs changed.
  Degrees did NOT move (list STEP 2^12 → 2^16, but the cyclic wrapper stayed 2^14 and
  `ValidityCircuit` stayed 2^16), so nothing structural changes downstream of the MLE wrapper — but
  every VK VALUE does.
- **Every `pk_g` VALUE changed**, so the registration keccak chain, the member-set commitment, the
  close/cancel proofs, and every baked `contracts/test/data/*` artifact regenerate together
  (§G-2 retirement note; `doc/tasks/regen-and-redeploy-runbook.md`).
- **Every live-deployed channel is invalidated**: existing registrations name identities no wallet
  can reproduce. The **v3 reset** was already the approved policy (threat model §5 non-goals); there
  is deliberately **no dual-scheme transition period**.
- The cosigner path's security **no longer depends on FRI soundness** — a proof-system config bug
  can no longer mint cosignatures. (It still can on the validity path, which remains a plonky2
  circuit.)

## P. Aggregated inter-channel rounds: multi-leaf tx tree + per-leaf sender signature (2026-08-23; design fixed, implementation in progress)

Today the inter-channel path is 1-block = 1-channel = 1-tx (§A-2): `inter_channel_tx_v2`
(wallet_core) builds a ONE-leaf `TxV2Tree`, the sender channel co-signs `h2_tag = root`, and the
producer posts one block per transfer. §P batches: the producer collects inter-channel txs for a
short window and posts ONE aggregated tx tree; every participating channel's members sign that
root — after verifying the ENTIRE tree, leaf by leaf.

### P-1. Window and tree shape

- `INTER_WINDOW_MS` (default 3000): the producer service opens a window on the first submitted
  inter-channel tx and closes it on the timer. All txs submitted inside the window share ONE
  `TxV2Tree`.
- **Leaf index = source channel id, one tx per source channel per window** (a second tx from the
  same channel waits for the next window). This preserves the existing index discipline
  (`TX_TREE_HEIGHT == CHANNEL_ID_BITS`, `TxSettlement` verifies inclusion at `channel_id`), so
  **no circuit changes**: `TxSettlement` and `update_channel_tree` already verify sparse
  inclusion proofs that are shape-identical for 1-leaf and K-leaf trees.
- The producer posts one `SubBlock` per participating channel, all carrying the SAME aggregated
  `txTreeRoot` (the contract's `postBlockAndSubmit(SubBlock[])` already accepts this).

### P-2. Per-leaf sender signature (IMI4 v5)

`InterChannelTx` gains `sender_pk_b: Bytes32` + `sender_hash_sig: HashSig` — the same A11
Poseidon2-BabyBear hash-sig the in-channel `ChannelTx` already carries — signed by the SENDER over
the `InterChannelTx` signing digest. The digest domain bumps to `IMI5` ("inter-channel tx v5");
the preimage covers source/dest channel ids, sender/recipient slots, token index, enc amount
digest, base nonce and the debit anchor digest (everything the v4 IMI4 digest covered). Rationale:
today an inter-channel leaf has NO per-tx sender signature — sender authorization is implied by
the E-2 STARK plus the source channel's own N-of-N, which members of OTHER channels in an
aggregated tree cannot check without that channel's record. The per-leaf hash-sig makes "no
unsigned tx in the tree" verifiable by every member of every participating channel with only the
manifest in hand. v3-reset policy applies (no dual-format transition; old descriptors are
rejected).

### P-3. Root-signing obligations (the member's checklist)

A member co-signs a state with `h2_tag = H2_agg` ONLY after verifying, from the window's
**aggregate manifest** = the full ordered leaf set `[{source_channel_id, inter_channel_tx,
tx_v2}]`:

1. **Own leaf**: this channel's tx in the manifest is byte-identical to the debit payload the
   member just verified (existing send-transition checks unchanged).
2. **Every leaf's sender signature**: `verify_hash_sig(sender_pk_b, IMI5 digest, sender_hash_sig)`
   per leaf — a leaf without a valid sender signature fails the whole round (nobody signs).
3. **Canonical rebuild**: each leaf's `TxV2` equals the canonical
   `Transfer → TransferTree → TxV2` rebuild from its `inter_channel_tx` (same deterministic
   construction as today's `canonical_inter_channel_binding`, applied per leaf).
4. **Root equality + completeness**: inserting ALL manifest leaves (and nothing else) at their
   channel-id indices into an empty `TxV2Tree` reproduces EXACTLY `H2_agg`. Because the root is a
   binding commitment, recomputation from the full manifest simultaneously proves no leaf was
   omitted, none added, and none placed at a foreign index. (A membership-proof-only check would
   miss additions; the full recompute is O(K log N) and K ≤ window size.)
5. **Uniqueness**: manifest indices pairwise distinct (one tx per channel per window).

### P-4. Binding and settlement changes

- `verify_canonical_inter_channel_binding` ("signed H2 == the 1-leaf root") is replaced by
  inclusion form: the canonical leaf verifies at index `source_channel_id` under the signed
  `H2_agg` via `tx_v2_merkle_proof`. Credit-gate invariant 7 already has this shape; the send
  side and the daemon (`settle_inter_channel`, `receive_inter_channel`) move to it.
- `inter_channel_tx_v2` splits: `inter_channel_tx_v2_leaf(...) -> TxV2` (canonical leaf, single
  source of truth) + window-side aggregation into the shared tree. `tx_v2_merkle_proof` in the
  descriptor is generated AFTER window close, against the aggregated tree.
- Producer bookkeeping (`accepted_inter_channel_txs`, base nonces, per-channel monotonicity) is
  applied atomically per window; sub-block timestamps within a window are strictly increasing.

### P-5. What does NOT change

The Solidity contract; `Block::hash_with_prev_hash`; the IMCH/IMSB preimages (members still sign
their channel state, whose `h2_tag` limb carries the root); the Falcon N-of-N aggregate machinery;
the E-2 STARK; `TxSettlement` / `update_channel_tree` circuits. K = 1 windows degenerate to
today's flow (the aggregated tree of one leaf IS the current tree).

### P-6. Implementation status + open items (2026-08-23)

**Landed** (stage 1+2): IMI5 per-leaf sender signature (signed at build, refused when stripped or
non-member-forged); `inter_channel_tx_v2_leaf` / `build_aggregated_tx_v2_tree` (K = 1 bit-identical
to the legacy tree; per-leaf inclusion at channel-id indices verified); `AggregateManifest` on the
debit payload + `verify_aggregate_manifest` wired into the co-sign gate behind
`InterChannelMemberLookup` (CLI: sibling-dir store; default: fail-closed).

**Stage 3 — remaining, in dependency order:**
1. Two-phase builder: `prepare` (E-2 + canonical leaf, root-independent) / `finalize` (root +
   manifest + descriptor proof against the aggregated tree). The current builder computes
   h2_tag inline from its own 1-leaf tree.
2. Producer collection window (`INTER_WINDOW_MS`) in `block_producer_service` + the node/API
   rendezvous: submit-leaf → window close → root+manifest broadcast → per-channel co-sign →
   one `SubBlock` per channel in a single `postBlockAndSubmit`.
3. Credit-side + daemon per-leaf verification (needs the same lookup pattern).
4. **OPEN — partial-window abort semantics**: if one channel fails its co-sign round after the
   window closes, the remaining channels' states already reference H2_agg. Either (a) the round
   aborts and every participant re-runs against a re-rooted window (leaf re-signing is cheap:
   only the A11 sig + state sigs re-run; the E-2 proof is root-independent), or (b) the producer
   posts the full tree anyway and the failed channel's leaf simply never settles (its debit was
   never co-signed, so no state references the root — the leaf is inert in the tree but
   UNSPENDABLE, since settlement requires the source channel's signed state). (b) is simpler and
   sound — an inert leaf has no signed state and no E-2-committed debit — but wastes the slot for
   that window. Decide at stage-3 implementation time.

## Q. Historical direct member-set mutation design (2026-08-23; retired 2026-09-02)

> STATUS: **SUPERSEDED / NOT A PRODUCTION CAPABILITY.** This section records the direct
> `MemberSetUpdate` prototype that was once implemented and tested. It must not be read as the
> current protocol or as release evidence. The constructive circuit is isolated behind the
> `deprecated-msu` feature, active fixture generation/deployment is removed, the production CLI,
> producer and service retain rejection tombstones only, and the Manager has no direct-MSU ABI
> selector. Historical raw calldata reaches no fallback and reverts before decoding. Current
> membership changes are intentionally unsupported.
> The replacement design is the TODO in `doc/tasks/channel-change-msu.md`: unanimous ordinary
> close, registration of a distinct channel id, then exact once-only asset/commitment migration.
>
> The remainder of §Q is preserved solely as a historical audit/design record. Statements such as
> “landed”, “complete”, or “henceforth” below describe that retired snapshot, not the current tree.

Today the co-signer set is write-once, pinned independently at three layers (the audit below cites
the exact 28 rejection points): (a) off-chain gates compare every payload against a locally-held
"trusted record" with no notion of an authorized transition; (b) the validity circuit freezes
`ChannelLeaf.member_pubkeys_root` at registration and copies it verbatim across every transition;
(c) L1 pins `channelMemberSetCommitment` → the Manager's immutable `memberPkGs`/`activeMemberCount`
→ the close proof's strict limbs 85..93. Delegates already grow the set dynamically — but only
because they live OUTSIDE all three pins (wallet-tree only, close via slot-leaf inclusion).

The retired §Q prototype made the CO-SIGNER set updatable through one canonical object verified at
all three layers; production no longer exposes that transition.

### Q-1. The update object and its digests

```rust
enum MemberSetOp {
    /// New co-signer at slot == prev member_count (left-packed prefix preserved).
    AddCosigner { leaf: MemberLeaf, recipient: Address, consent_sig: Vec<u8> /* joiner, IMJC */ },
    /// Replace the SIGNING identity at `slot`. regev_pk_digest is PRESERVED — balances stay
    /// decryptable; rotating the Regev key would require slot re-encryption (out of scope, §Q-6).
    RotateKey { slot: u8, new_pk_g: Bytes32, new_pk_b: Bytes32, self_sig: Vec<u8> /* IMKR */ },
}
struct MemberSetUpdate {
    channel_id: ChannelId,
    set_version: u64,            // strictly monotone, genesis = 0
    prev_member_root: Bytes32,   // REGISTERED 16-slot cosigner tree root, before
    new_member_root: Bytes32,    // after
    op: MemberSetOp,
    member_signatures: Vec<MemberSignature>, // N-of-N of the PREVIOUS set over the IMMS digest
}
```

- **IMMS** ("member set") — the update digest the previous set's N-of-N signs:
  `hash([IMMS, channel_id, set_version, prev_member_root, new_member_root, op_digest])`. This is
  the single canonical commitment all three layers verify.
- **IMKR** — rotation self-consent, signed by the slot's CURRENT Falcon key:
  `hash([IMKR, channel_id, set_version, slot, old_pk_g, new_pk_g, new_pk_b, prev_member_root])`.
  NOTE the channel is N-of-N, so the rotating member's current-key signature is ALREADY required
  inside `member_signatures` — every member, including the affected one, holds a veto. IMKR makes
  the individual consent explicit rather than derived (and survives any future sub-N threshold).
- **IMJC** — joiner consent for AddCosigner, signed by the NEW key over
  `hash([IMJC, channel_id, set_version, new_pk_g, new_pk_b, regev_pk_digest, recipient,
  prev_member_root])`: proves possession of the new key and intent to join (no rogue-key
  enrollment); B-1b recipient uniqueness applies as at delegate join.

### Q-2. Stage Q1 — channel layer (lands first)

- `ChannelRecord` gains `set_version` (IMCR preimage extends; native-only digest, no twin to sync).
- `verify_member_set_update(trusted_record, update, level) -> ChannelRecord`: set_version ==
  trusted+1; prev_member_root == the trusted record's registered cosigner root; op-specific
  structural delta (Add: slots identical except member_count's goes empty→leaf, member_count+1 <=
  MAX_COSIGNERS; Rotate: exactly slot j's pk_g/pk_b differ, regev digest preserved); consent sig
  valid; N-of-N of the PREVIOUS set over IMMS. Returns the advanced record (both roots — the
  registered 16-slot root and the wallet-tree `member_pubkeys_root` — recomputed).
- `advance_trusted_record(trusted, &[MemberSetUpdate])`: fold a chain of updates; this is how a
  PEER (or channel B holding A's record) accepts a record whose digest no longer equals its stored
  one — the inter-channel debit payload gains an optional update-chain suffix, and the sibling /
  cross-channel gates try the chain before rejecting on digest inequality.
- CLI: `propose-member-update` (build + self-sign), `cosign-member-update` (each member verifies
  the gate, adds its Falcon sig over IMMS), `apply-member-update` (full set present → new record,
  state_version+1 re-sign as at delegate join; Add also initializes the new slot's balance row:
  zero ciphertexts, regev digest, recipient — the same A-1/B-1b hardening as `join_delegate`).

### Q-3. Stage Q2 — validity circuit (VK rotation + fixture regen)

`ChannelActionKind::MemberSetUpdate = 2`. A member-set-update BLOCK carries a ChannelAction leaf
whose `payload_hash` commits the IMMS digest; the signed state's h2_tag → tx_tree_root → IMCH
binding means the N-of-N that update_channel_tree already verifies (against the PREVIOUS root's
keys — items 10-12 of the audit) is a signature over exactly this update. The transition rule
(today "member_pubkeys_root preserved verbatim", items 13-14) becomes: preserved UNLESS the
block's action kind is MemberSetUpdate, in which case the circuit witnesses BOTH leaf arrays,
folds both roots (the fold gadget already exists — channel_reg_step shares it), asserts the old
fold == prev leaf root, the new fold == the new leaf root, and the leaf-array delta matches the
op (one changed slot for Rotate with regev digest equality; one empty→nonempty at member_count
for Add). Joiner/rotation consent sigs stay native-only obligations of the co-sign gate (Q-2) —
in-circuit the N-of-N over the update suffices (an unconsented Add cannot harm the added key's
owner, who never signs anything; a Rotate without IMKR cannot pass the gate off-chain and cannot
gather N-of-N on-chain because the affected member refuses).

### Q-4. Stage Q3 — L1 (Manager storage + update entry; redeploy)

- Manager: `memberPkGs`/`activeMemberCount` move from immutable/constructor-only to storage
  seeded by the constructor (genesis = registration, audit items 19-23 unchanged at deploy time);
  new `applyMemberSetUpdate(newPkGs, newCount, newRecipient?, version, mleProof)` verifying an
  MLE-wrapped **member-set-update circuit** proof (the same Falcon-agg recursion the close
  circuit uses) whose PIs bind [channel_id, old commitment, new commitment, old/new count,
  version]; version strictly monotone on-chain. Close / cancel / partial-withdrawal then bind
  limbs 85..93 against the CURRENT storage values — no other close-path change (limb layout
  unchanged). `isMemberRecipient` / `registeredRecipientOf` gain entries on Add.
- `IntmaxRollup.channelMemberSetCommitment` stays the GENESIS anchor (historical registration);
  the Manager's storage is the live head. The constructor pin (item 23) still checks genesis.

### Q-4b. AddCosigner reslots delegates (slot-shift rule)

Delegates occupy the left-packed suffix starting at slot `member_count`, so adding a co-signer
inserts at that boundary and SHIFTS every delegate slot up by one. The update's apply step must
move the per-slot state rows together — `enc_balances`, `pending_adds`, `regev_pk_digests`,
`recipients` — and the H1 slot tree is rebuilt over the shifted rows before the re-sign, so the
signed state and the record agree on every slot. Delegate-facing artifacts keyed by slot
(withdrawal-claim `member_index`) use the post-shift slot from then on; pre-shift claims against a
pre-shift signed H1 remain valid against THAT state. The gate enforces the shift structurally
(rows moved, not altered).

### Q-5. Ordering / consistency

set_version totally orders updates; every layer checks strict +1 monotonicity, so the channel
layer, the validity chain and L1 cannot diverge silently — a missing update at any layer blocks
the next one there fail-closed. An update is BLOCKING for the channel: like a close-freeze, no
sends are co-signed between `propose` and `apply` (the gate refuses mixed anchors anyway, since
the record digest changes).

### Q-6. Out of scope (documented)

Regev-key rotation (requires re-encrypting the slot under the new key — a separate value-moving
operation); member REMOVAL (changes quorum semantics and stranded-balance rules; needs its own
design); sub-N thresholds.

## R. Terminology + sig-cluster cap (2026-08-24)

- **The co-signing member set is henceforth the SIG-CLUSTER** (its members: sig-cluster members;
  delegates remain outside it). New identifiers use the term (`MAX_SIG_CLUSTER`); legacy CLI verbs
  (`cosign`, `cosign-batch`, …) and wire field names (`member_signatures`) are unchanged for
  interface stability.
- **`MAX_SIG_CLUSTER = 8`** (was `MAX_COSIGNERS = 16`). Derived shapes halve:
  `MEMBER_TREE_HEIGHT = 3`, Falcon aggregation `AGG_LEVELS = 3` (8-slot batch circuit — the
  aggregate proof covers 8 signature slots instead of 16), registration pad-to-MAX preimages are
  8-wide on BOTH the Rust and Solidity mirrors (IntmaxRollup `MAX_CHANNEL_MEMBERS = 8`, Manager
  `MAX_MEMBER_COUNT = 8`, Verifier `MAX_CHANNEL_MEMBERS = 8`), and the IMCM close member-set
  commitment is `keccak([IMCM, member_count, h_0..h_7])` (66 u32 words; shared cross-language
  vector re-pinned, both sides independently agree).
- **This is a circuit-shape change**: every VK rotates (validity, close family, withdrawal,
  Falcon aggregate), so the full fixture set must be regenerated (regen runbook Step 1) and the
  contracts redeployed before any fixture-backed Forge test or deployment is meaningful again.
  Channel capacity beyond 8 signers is delegates' job (`MAX_CHANNEL_MEMBERS = 1024` unchanged).

## R. Proving-locus history: what was intended to prove where (2026-08-24)

> Superseded by the current deployment-policy/implementation distinction above and
> [proving-boundaries.md](../docs/proving-boundaries.md). The browser has explicit durable Falcon
> member signing, and its withdrawal-claim export still invokes a Plonky2/MLE prover contrary to
> server-only policy. Neither historical assertion below is a current source-conformance claim.

Two invariants recorded at that stage (not current normative text):

### R-1. The sig-cluster never proves (or signs) in the browser

All sig-cluster work — Falcon signing, signature verification, and every plonky2 proof — runs in
Rust on the OS (`channel_member` CLI / the daemon). The WASM wallet builds NO plonky2 circuit and
generates NO plonky2 proof; the only proving on WASM is the DELEGATE's own plonky3
(`p3-batch-stark`, BabyBear) STARKs:

| proof | backend | where |
|---|---|---|
| E-1 channel-tx (`prove_channel_tx`) | plonky3 | WASM (delegate) |
| E-2 channelUpdateZKP (`prove_channel_update`) | plonky3 | WASM (delegate, inter-channel send) |
| A11 sender hash-sig (`prove_hash_sig`) | plonky3 | WASM (delegate) |
| Falcon sign / N-of-N verify | native Rust | OS only |
| Falcon batch aggregate (plonky2, §R-2) | plonky2 | OS only |
| balance / validity / close / MLE wrap | plonky2 | OS only |

Consequence: sig-cluster sizing (8 slots, §O) has ZERO effect on browser-side latency — the
browser cost is the delegate's own transfer proving, invariant in the cluster.

### R-2. The cluster's N/N plonky2 proof is a settlement artifact

The sig-cluster's N-of-N is collected as NATIVE Falcon signatures on each co-signed state — cheap,
per-transfer, no ZKP. The plonky2 aggregate proof (`FalconBatchAggCircuit` over all N signatures,
one proof) is built ONLY when settlement needs it: `close`, `cancel-close`, and the
partial-withdrawal submit each obtain it via `cache_falcon_aggregate`, which proves on a cache
miss. Order is always: aggregate the Falcon signatures first, THEN feed them into plonky2 — the
close/PW circuits recursively verify that one aggregate proof (its pk-list public inputs are the
member keys the close commitment is computed from).

Per-finalization pre-warming of the artifact is OPT-IN (`INTMAX_FALCON_AGG_PRECOMPUTE=1`,
detached + digest-keyed + idempotent); the default is lazy — outside the settlement paths no
plonky2 proving happens at all. (Flipped 2026-08-24: the previous default precomputed at every
N-of-N finalization.)

---

## S. Cluster co-signing protocol (2026-09-21)

Implementation: `api/lib/cluster.js` (protocol, transport- and clock-agnostic),
`hosting/wallet/wallet-relay.js` (HTTP wiring, `/api/cluster/*`), `channel_member cosign-partial`
/ `cosign-merge`, `wallet_core::verify_member_signature`. Tests:
`node/test/cluster-cosign.test.js`. Specification: [`doc/tasks/cluster-cosign-protocol.md`](../tasks/cluster-cosign-protocol.md).

### S-1. Topology

Up to `MAX_SIG_CLUSTER = 8` hosts (§R). Each cosigner slot is held by exactly one host
(`INTMAX_CLUSTER_SIGN_SLOTS`); a host may hold several. Hosts know each other's URLs
(`INTMAX_CLUSTER_SELF_URL`, `INTMAX_CLUSTER_PEERS`). Without this configuration the relay keeps
the single-host `cosign` path (one process signing every slot), which is what §D and §O describe.

### S-2. Round

1. **Propose.** The relay receiving a wallet's `SendPayload` runs `cosign-partial`: the full
   co-sign gate (`verify_send_transition`: E-1 or E-1b, A11 sender signature, structural fold,
   recipient decryption) and its own slot signatures over `ChannelState::signing_digest()`,
   recorded in the anti-equivocation `state_signing_ledger`, **head not advanced**; then
   broadcasts the payload to every peer.
2. **Sign and fan out (N-to-N).** Every peer acknowledges immediately, runs the same gate and
   `cosign-partial` for its own slots, and sends its signatures to **every** host. Signatures are
   pooled per `nextDigest`; one that arrives before its proposal waits for the payload.
3. **Assemble.** Any host holding all `member_count` slots runs `cosign-merge`: it re-runs the
   gate, verifies **each** pooled signature individually (`verify_member_signature`: cosigner
   slot, registered `pk_g` at that slot, Falcon over the recomputed IMCH digest) and adopts the
   N-of-N head. The coordinator answers the wallet with it; every host adopts independently.
4. **Close warning (1 min, repeated every minute).** A host whose round is incomplete broadcasts
   the missing slots (`/api/cluster/missing`). Every host holding any of them — its own signature
   or one received from a third host — supplies them to the warner.
5. **Halt (5 min).** Still incomplete: the channel is **HALTED** (`cluster_halt.json`, broadcast
   via `/api/cluster/halt`). Mutating relay routes answer `503` except close/settle/withdraw. A
   complete set arriving later still finishes the round and lifts the halt.
6. **Auto-close (24 h, node-program rule).** A watchdog closes a channel halted for 24 hours at
   its **last fully signed state** — the adopted head, never the stalled proposal — with `close`
   against the ACTIVE settlement binding; a failed close is retried every tick; a lifted halt is
   never closed.

Timers: `INTMAX_CLUSTER_WARN_MS` / `HALT_MS` / `CLOSE_MS` / `WATCHDOG_MS` (60 s / 5 min / 24 h /
60 s). Observability: `GET /api/cluster/status?channel=N`.

### S-3. Security posture

- Pooled signatures are never trusted: `cosign-merge` verifies each against the registered member
  set before any head is adopted, and `cosign-partial` re-runs the transition gate before this
  host signs. A forged or mis-slotted signature is rejected at merge; a proposal that fails the
  gate is never signed.
- `cosign-partial` writes the same signing ledger as `cosign`: a host that signed successor X at
  head P can never sign a sibling successor at P, so a stalled round cannot be replaced by an
  equivocating one — the halt/close path is the only way forward.
- Each host adopts the N-of-N head only from signatures it verified itself; no host trusts
  another host's claim of completion.
- Cluster mode forces the relay batch window (§M-7) to one proposal per round; `cosign-batch`
  has no partial/merge form yet. The other co-sign purposes (refresh, inter-channel debit and
  credit, deposit import, token registration, member-set update) still sign every slot on the
  receiving host — extending them is the same gate → partial → merge split.
