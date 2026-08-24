# Validity proof commitment / blob DA v2 — threat model and deployment gate

Status: **P0 DEPLOYMENT BLOCKER** (confirmed on `main` `4568bcf`, 2026-08-19).

## Confirmed current behavior

1. `postBlockAndSubmit` stores only
   `keccak256(blobhash(0) || proofHash || proofLength || stateRoot || ethBlock)`.
2. `finalize` never opens that commitment. It accepts any valid `(stateRoot, validityPIs,
   mleProof)` for the current on-chain history, even when those values are not the ones committed
   by the selected `submissionId`.
3. The CLI and smoke runbook attach 131,072 zero bytes and submit an FNV-derived hash of the JSON
   fixture. `_verifyFraud`, in contrast, requires `proofHash == keccak256(proofBytes)` and
   `proofBytes == abi.encode(mleProof)`. The posted demo tuple can therefore never satisfy the
   normal fraud-proof preconditions.
4. A real checked-in validity proof (`lifecycle_validity_mle.json`) encodes to **131,264 bytes** as
   `abi.encode(MleProof)`: 192 bytes more than one 131,072-byte blob.
5. `BlobKZGVerifierExt._toFieldElements` clears the top three bits of every 32-byte chunk. That map
   is not injective, so a blob containing those field elements is not a lossless encoding from
   which a watcher can reconstruct arbitrary ABI proof bytes.
6. The current `KZGProof` carries `lagrangeBasisG1` at 128 bytes per opened element. A full 4,096-
   element blob therefore requires **524,288 bytes of basis calldata** before the proof and other
   arguments. The existing verifier shape is not an operational full-blob verification path; a
   two-blob change cannot simply duplicate it.

The size measurement was made by parsing the checked-in fixture with `FixtureLib.parseProof` and
asserting `abi.encode(proof).length` in Forge. The observed value was 131,264.

## Required invariants before any public testnet

- **C1 — submission binding:** finalization must open the selected submission's commitment and
  bind its exact state root, proof hash, proof length, and blob versioned hash(es).
- **C2 — exact proof binding:** the proof verified by `fullVerify` must be byte-identical under one
  canonical serialization to the proof committed at submission.
- **C3 — lossless DA:** a watcher starting only from transaction/blob data must reconstruct that
  canonical proof without guessing discarded bits or obtaining side-channel files from the BP.
- **C4 — complete capacity:** the format must reject oversize proofs before posting and must cover
  every byte; no uncommitted suffix, truncation, or ignored second blob.
- **C5 — fraud parity:** the normal finalize and fraud paths must use the same serialization and
  blob split. A fixture-only FNV/JSON commitment is forbidden.
- **C6 — atomic rollback:** a failed proof/DA check must not finalize state, refund stake, consume a
  submission, or partially roll back later submissions.
- **C7 — operational verification bound:** KZG/blob binding calldata and gas must fit the target
  chain's transaction and block limits at the maximum accepted proof size. Test-only precompile
  shortcuts and caller-supplied 512 KiB basis arrays do not satisfy this invariant.

## Recommended protocol

Use a versioned, lossless **two-blob** envelope for the current ABI proof:

- pack 31 payload bytes into each BLS scalar field element (one fixed zero prefix byte), giving
  126,976 lossless payload bytes per blob;
- split the canonical proof at exactly that boundary and commit `blobhash(0)` and `blobhash(1)`
  plus the total byte length and `keccak256(canonicalProofBytes)`;
- store or open both hashes in `Submission`, and require `finalize` to recompute/open the selected
  submission commitment before MLE verification;
- make the KZG satellite verify both slices with the same 31-byte packing; reject absent/extra
  blobs and non-canonical padding. Replace the linear caller-supplied `lagrangeBasisG1` surface
  with a compact, deployment-pinned setup/verification scheme and measure its worst-case gas;
- replace every FNV/zero-blob fixture path with the exact canonical bytes;
- add adversarial tests for wrong submission id, swapped blob order, missing blob 2, one-bit proof
  changes, discarded-high-bit collisions, truncation, appended bytes, and finalize-with-a-valid-
  but-different-proof.

One blob cannot carry the current proof losslessly: even before the 31-byte field encoding, the
ABI payload is already larger than 128 KiB. A compact custom proof codec is a possible alternative,
but it creates a second Solidity/Rust serialization protocol and a much larger audit surface. The
two-blob format is therefore the recommended testnet path.

## Operational gate

Until C1–C7 are implemented and tested, non-local posting is forbidden. The Rust `withdraw` command
enforces this by accepting the zero-blob lifecycle only on chain id 31337, and the Sepolia runbook
is marked blocked. This guard is not the fix; it prevents the known demo path from being mistaken
for a testnet-ready producer.
