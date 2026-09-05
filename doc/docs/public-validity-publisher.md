# Public validity publisher

> **RELEASE STATUS (2026-09-03): NO-GO.** The commit-before-challenge MLE/WHIR V2 path is
> integrated here, but its mandatory independent cryptographic review and public-chain acceptance
> run are not complete. `IntmaxRollup.releaseRuntime` therefore remains restricted to chain
> `31337`. This publisher cannot authorize a public deposit/post/finalize/value transition, and a
> successful local run is not release evidence. Preserve every separate NO-GO disposition in
> `doc/audit/audit30-08-2026-final-security-closure.md`.
>
> V2 is a clean protocol cutover. Journal version 2, deployment-manifest schema 2, and envelope
> schema 2 intentionally reject legacy tuple-proof journals/manifests/envelopes. Resolve or retire
> old pending submissions and bonds under their original deployment; never relabel or deserialize
> them as compact V2 state.

`public_validity_publisher` is the operator-owned bridge between the keyless HTTP/API process and
the public L1. It consumes the exact `postingArtifact` + `finalizeArtifact` envelope emitted by the
resident validity prover. It does not prove again. The only proof representation sent to the
Rollup, KZG proof-DA satellite, finalizer, or fraud classifier is the same canonical
`.compactProof.bytes` stream.

## Invocation

Import the funded signer into Foundry's encrypted keystore, then select the account by name. Never
pass a private key to this command.

```sh
cargo run --release --bin public_validity_publisher --locked -- \
  --artifact /absolute/private/path/close-validity.json \
  --deployment-manifest /absolute/release/path/public-validity-deployment.json \
  --deployment-manifest-sha256 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --journal /absolute/private/path/public-validity.journal.json \
  --lock-root /absolute/private/path/l1-signer-locks \
  --rpc-url https://operator-owned-rpc.example \
  --account intmax-release-operator
```

`--deployment-manifest-sha256` is mandatory and must come from the independent release/deployment
record, not be computed by this invocation from the file it is about to trust. The publisher hashes
the manifest's exact raw bytes and compares this pin before JSON parsing, WAL creation, or signing.
Changing whitespace, key order, or a trailing newline therefore requires a newly reviewed pin even
when the parsed JSON would be equivalent.

The command prints one JSON object only after all three transactions are canonical and finalized.
The API acknowledgement must use `finalizationTransactionHash` with the matching `candidateId` and
`candidateRequestId`. Intermediate transaction hashes and raw transactions remain in the private
journal rather than crossing back into the keyless API.

## Durable protocol

1. The envelope is checked against its recursively canonical `artifactHash`. Its candidate receipt,
   one prepared terminal sub-block, historical pending-chain checkpoint, validity public inputs,
   final root, predicted on-chain block hash chain, and the exact eight MLE public-input limbs must
   all agree. The VPI hash uses the contract's exact 164-byte `abi.encodePacked` layout.
2. `validityMleJson` must be the exact canonical full fixture schema
   `plonky2-mle-v3-solidity`, schema/protocol version 3 and WHIR PoW 22. The publisher cross-checks the proof,
   verification key, immutable adapter view, Solidity ABI redundancy, encoded configuration,
   compact shape, resource statistics and generated upper bound. It strictly decodes and
   canonically re-encodes `.compactProof.bytes`, requires `MLEWHIR3`, and then discards every
   alternate representation. V1 and partially versioned artifacts are rejected even on 31337.
3. Foundry signs an EIP-4844 type-3 `postBlockAndSubmitGuarded` transaction. Before broadcast, the
   command independently decodes it and checks chain, signer, rollup, one-ether stake, calldata,
   exact Alloy `SimpleCoder` blob bytes, commitments, KZG proofs, and versioned hashes. The guarded
   call also carries the candidate's exact predecessor block number/hash chain. The raw transaction
   and complete compact sidecars are fsynced to a 0600 journal before publication.
4. The exact raw transaction is resent on restart. Completion requires a stable successful receipt,
   its exact `Submitted` event, the canonical receipt block, and coverage by the RPC's `finalized`
   head. `latest` is never authority outside an explicit chain-31337 development run.
5. `attestProofData` and `finalize` are likewise signed raw transactions and fsynced before their
   first broadcast. Attestation requires the exact event plus receipt-block read-back from the
   release-pinned KZG satellite; its address and runtime-code hash are rechecked at that finalized
   receipt block. Posting sidecars, attestation, finalization and fraud classification are all
   bound to the same exact compact byte stream and its length/hash; no lossy or proof-tuple DA
   reconstruction is permitted.
6. Because `finalize` is permissionless, the publisher scans from the finalized posting receipt to
   the durable head before signing and on every recovery. It may adopt a relayer or batch-wrapper
   transaction only when that transaction has one unique exact `Finalized(submissionId,stateRoot)`
   event from the pinned Rollup and its transaction body, receipt, block, and log positions agree.
   The wrapper's outer sender, target, calldata, and value are not semantic authority.
7. Finalization read-back checks the pinned Rollup runtime code, the complete
   `getSubmission(id)` tuple (nonzero commitment, exact posting signer, finalized flag, exact
   posting receipt block, and exact state root), `isFinalized(id)`, and the exact
   `latestFinalizedStateRoot` / `latestFinalizedBlockNumber` at the canonical receipt block. Only
   after all historical reads does it fetch and revalidate a fresh durable checkpoint and re-read
   the receipt block, rejecting same-height replacement or stitched RPC observations.

The deployment manifest is mandatory and has this closed schema:

```json
{
  "schemaVersion": 2,
  "chainId": 11155111,
  "rollup": "0x...",
  "rollupRuntimeCodeHash": "0x...",
  "validityMleVerifier": "0x<adapter>",
  "validityMleVerifierRuntimeCodeHash": "0x...",
  "validityMleVerifierCore": "0x<core>",
  "validityMleVerifierCoreRuntimeCodeHash": "0x...",
  "validityMleVerificationConfigDigest": "0x...",
  "validityMleCircuitConfigDigest": "0x...",
  "validityMleWhirParametersDigest": "0x...",
  "validityMleWhirProtocolId": "0x<64-bytes>",
  "validityMleWhirSessionId": "0x...",
  "kzgVerifier": "0x...",
  "kzgVerifierRuntimeCodeHash": "0x...",
  "mleFixtureSchema": "plonky2-mle-v3-solidity",
  "mleProtocolVersion": 3,
  "mleProofAbiSignature": "<generated MLE_PROOF_ABI_SIGNATURE_V2>",
  "mleProofLayoutHash": "0x...",
  "mleCompactLayoutHash": "0x...",
  "mleCompactProofEncoding": "MLEWHIR3",
  "postBlockAndSubmitGuardedSelector": "0x...",
  "attestProofDataSelector": "0x...",
  "finalizeSelector": "0x...",
  "fraudProofSelector": "0x..."
}
```

Before risking the posting stake, the publisher first authenticates the manifest's exact raw bytes
against the independently supplied SHA-256 pin. It then hashes deployed runtime code at a durable L1
checkpoint, follows `rollup.validityMleVerifier()`, that adapter's `core()`, and
`rollup.kzgVerifier()`. It checks distinct nonzero adapter/core addresses, both runtime-code hashes,
both `allowedChainId()` values, and the core's verification-config, circuit-config,
WHIR-parameters, protocol and session identities against both the manifest and the full proof
artifact. It also recomputes all four selectors from the compiled ABI. Every address and
runtime-code hash pin must be nonzero. After the historical reads, the exact checkpoint block and
the durable head are re-read; a replacement, regression, chain/source change, or loss of coverage
fails closed. This prevents a V2 envelope from reaching an older, cross-circuit, or substituted
adapter/core or an unintended proof-DA satellite.

The compiled selector signatures are `postBlockAndSubmitGuarded(...,bytes32,uint64,bytes32)`,
`attestProofData(uint256,bytes,bytes)`, `finalize(...,bytes)`, and `fraudProof(...,bytes)`. A
deployment record containing a retired tuple-proof selector is invalid; do not hand-edit it to
match an old contract.

The journal path is a single-candidate capability. Reusing it for another chain, rollup, candidate,
artifact, proof schema, or signer fails closed. `--lock-root` is mandatory, is canonicalized, and is
made private (0700); every process that can use the same Foundry signer must be configured with this
one operator-owned root. All INTMAX L1 publishers share the exact lock filename
`.intmax-l1-signer-{chainId}-{lowercaseAddress}.lock`; it is derived only below that root, never
below a publisher-specific journal directory. The live `flock` is paired with one durable
`.intmax-l1-signer-{chainId}-{lowercaseAddress}.reservation.json`. Before every offline signing
call, the publisher fsyncs an exact owner identity consisting of the canonical journal path,
phase, candidate binding, target, value, and calldata hash. The record survives a process crash and
blocks every sibling journal until the exact transaction is canonical-finalized and that
confirmation has itself been fsynced to the journal. A clean signing failure before raw bytes can
escape releases it; a failure or crash after raw persistence does not. The canonical root is also
pinned in the journal. If another process or wallet consumes a journaled nonce, the command retains
both evidence and reservation and refuses to sign a replacement.

If a permissionless finalizer wins after a local raw transaction was already journaled, the
publisher first fsyncs the adopted semantic evidence. It then republishes only the byte-identical
local raw transaction and retains the signer reservation until that nonce is itself
canonical-finalized. A successful EVM receipt must contain the exact `FinalizeRejected` result for
this submission; an EVM revert is also a terminal nonce-consuming loser. That loser confirmation is
fsynced before the reservation is released. The publisher never manufactures a cancellation or a
sibling same-nonce transaction, and a stored loser receipt that later disappears fails closed.

### Remaining atomic-head requirement

The publisher checks `blockNumber`, `blockHashChain`, `latestFinalizedBlockNumber`, and
`latestFinalizedStateRoot` against the candidate predecessor immediately before signing and again
immediately before publication. More importantly, production uses only
`postBlockAndSubmitGuarded(..., uint64 expectedBlockNumber, bytes32 expectedBlockHashChain)`: the
contract checks the predecessor atomically before stake/state mutation. The unguarded compatibility
entrypoint is never accepted by this command or its deployment manifest.

On a public chain the RPC must support the canonical `finalized` block tag and historical calls at
the receipt block. These are release requirements, not optional optimizations. Pinning the KZG
satellite's address and runtime bytecode authenticates the selected deployment; it does not re-audit
the ceremony. The KZG trusted setup is the project's accepted trust assumption.
