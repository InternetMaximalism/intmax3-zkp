# MLE/WHIR PCS soundness repair handoff

> **Start here in the dedicated repair thread. Read this file completely before editing.**
>
> Current status: **Critical / NO-GO for production**. The chain pin is containment only.
> The task is not complete until the concrete correlated forgeries are rejected by the
> cryptographic verifier on its allowed chain, rather than by a chain guard.

## 1. Repository topology and starting state

The MLE/WHIR implementation is in the nested Git submodule:

```text
parent:    intmax3-zkp
submodule: contracts/lib/polygon-plonky2
package:   contracts/lib/polygon-plonky2/mle
remote:    https://github.com/InternetMaximalism/intmax-plonky2.git
```

Start from:

| Repository | Branch/ref | Relevant baseline |
|---|---|---|
| Parent | `codex/final-security-closure-20260830` | `8b386cb998057104f99df2a927917b1a4736c740` plus the commit containing this handoff |
| Submodule | `codex/whir-leaf-consistency-20260830` | `54c0b86a353e13c4ac738b020fc0d2bcb184a200` |

The submodule must be committed and pushed first. Then commit its new gitlink in the parent.
Do not accidentally implement the repair only in the parent dependency graph or only in a detached
submodule checkout.

The final system audit is `doc/audit/audit30-08-2026-final-security-closure.md`. It remains the
authority for non-PCS release blockers. The older fixture runbook
`doc/tasks/regen-and-redeploy-runbook.md` is useful for generator ordering, but its historical
release statements are superseded by the final audit.

## 2. Exact vulnerability

The current proof commits one already-batched polynomial per oracle group:

```text
P(X) = sum_i rho^i f_i(X)
```

The batching scalar `rho` is known before the root committing `P`. Terminal checks later consume
prover-supplied constituent evaluations `y_i = f_i(z)`. The verifier checks their random-linear
combination against the opened batched value, but it does not prove that each `y_i` is an opening
of a previously committed constituent polynomial.

An attacker can therefore choose a non-zero delta vector after learning `rho` such that:

```text
sum_i rho^i delta_i = 0
```

and compensate another claimed constituent used by a terminal equation. Roots, WHIR
transcript/hints, sumcheck messages, public inputs and the opened batched value stay unchanged.
Schwartz-Zippel does not apply to constituent polynomials that were never fixed before the
challenge.

This affects all four current groups:

- preprocessed constants and sigma columns;
- witness wire columns;
- auxiliary `C_tilde` and `h_tilde` columns;
- inverse helpers `A_j` and `B_j`.

It affects values consumed at the combined-sumcheck point, `r_inv`, `r_h`, and `r_gate_v2`.

### Frozen concrete exploit: parent validity fixture

The final audit records an accepted three-field mutation:

| Field | Before | After |
|---|---:|---:|
| `witnessIndividualEvalsAtRInv[0]` | 8093513556413711660 | 8093513556413711661 |
| `witnessIndividualEvalsAtRInv[80]` | 2800508231593448274 | 15862999140234155880 |
| `inverseHelpersEvalsAtRInv[1]` | 17516173920822186472 | 6112368312529039975 |

The witness batch remains `12944411284857403794`, and the `Phi_inv` terminal value remains
`580551468794229723`. Index 80 is outside the 80-routed-wire terminal loop, so it supplies a batch
cancellation coordinate while the inverse-helper change cancels the terminal delta.

### Frozen concrete exploit: submodule `small_mul`

The corresponding regression values are in
`mle/contracts/test/BoundaryCheckTest.t.sol`:

| Field | Before | After |
|---|---:|---:|
| `witnessIndividualEvalsAtRInv[0]` | 3051498664030569048 | 3051498664030569049 |
| `witnessIndividualEvalsAtRInv[80]` | 6063719204085150528 | 2587698932769584699 |
| `inverseHelpersEvalsAtRInv[1]` | 7495656216612080666 | 14584819668673277578 |

The existing test proves only that the chain pin blocks this mutation after a chain-id change.
The repair must add a same-chain test in which the engine is enabled and the proof is rejected for
a proof-dependent cryptographic reason.

## 3. Primary implementation files

### Rust prover, verifier and proof format in the submodule

- `mle/src/prover.rs`: transcript order, batching challenges, constituent construction,
  commitments, sumchecks and WHIR openings.
- `mle/src/verifier.rs`: transcript reconstruction, WHIR verification, batch checks and terminal
  equations.
- `mle/src/proof.rs`: proof/VK schema and the four oracle groups.
- `mle/src/commitment/whir_pcs.rs`: phased/split multi-vector WHIR wrapper.
- `mle/src/transcript.rs`: outer Fiat-Shamir transcript, currently versioned
  `plonky2-mle-v0`.
- `mle/src/fixture.rs`: canonical Rust-to-JSON export, WHIR parameters, protocol/session IDs.
- `mle/tests/generate_fixtures.rs`, `mle/tests/integration_tests.rs`, and
  `mle/tests/transcript_*`: fixture and parity tests.

### Solidity verifier in the submodule

- `mle/contracts/src/MleVerifier.sol`: proof schema, outer transcript, WHIR evaluation vector,
  batch identities and terminal equations.
- `mle/contracts/src/spongefish/SpongefishWhirVerify.sol` and adjacent `spongefish/` files:
  on-chain WHIR verification and field/point encoding.
- `mle/contracts/src/TranscriptLib.sol`: Solidity outer transcript, currently
  `plonky2-mle-v0`.
- `mle/contracts/test/BoundaryCheckTest.t.sol`: frozen attack and boundary cases.
- `mle/contracts/test/MleE2ETest.t.sol`, `TranscriptCompat.t.sol`,
  `TranscriptE2ETrace.t.sol`, and `WhirVerifyTest.t.sol`: Rust/Solidity parity.

### Parent integration surfaces

- `contracts/script/FixtureLib.sol`: JSON proof/VK parsing used by deploy scripts.
- `contracts/src/IntmaxRollup.sol`: validity/withdrawal verification and fraud classifier.
- `contracts/src/ChannelSettlementVerifier.sol`: close, cancel and claim VK consumers.
- `contracts/test/MleE2E.t.sol`, `MleFinalizeE2E.t.sol`, `ClaimMleVerify.t.sol`,
  `MemberSetUpdateE2E.t.sol`, and `CloseLifecycleE2E.t.sol`.
- `tests/mle_onchain_e2e.rs`: real Rust proof generation followed by on-chain verification.
- `src/bin/generate_*fixture.rs`: validity, withdrawal, close/cancel/claim, C2C and WASM fixtures.

## 4. Non-negotiable soundness invariant

For every constituent evaluation `f_i(z)` used by any terminal equation, the verifier must validate
it as an opening of an ordered constituent/vector commitment `C`. The commitment must bind group
identity, vector labels/order/count and widths, and must be absorbed before sampling the
vector-combination challenge and before deriving the terminal point `z`.

A successful forgery after the repair must imply breaking the commitment/PCS binding property, or
occur only within a quantified documented soundness probability. Merely checking
`sum rho^i f_i(z) == P(z)` is not sufficient.

Exact lengths must be VK/schema-bound. Do not retain an ignored tail, `>=` length check, duplicate
label, optional missing vector, or padding rule that gives the prover a cancellation coordinate.

## 5. Required protocol ordering

The final design may use direct vector openings, a genuine multi-vector PCS, or a proven equivalent.
It must satisfy all of the following:

1. Commit the preprocessed and witness **constituent vectors**, including their ordered schema.
   Absorb those commitments before deriving their aggregation/query challenges.
2. `A_j/B_j` legitimately depend on `beta/gamma`. Derive `beta/gamma` only after the base
   commitments; construct the helpers; commit their constituents; then derive `rho_inv`, the
   inverse/logUp challenges and their query points.
3. `C_tilde/h_tilde` legitimately depend on earlier challenges. Construct them, commit both
   constituents, then derive `rho_aux`, `mu`, sumcheck challenges and query points.
4. Open the same committed constituents used by terminal checks at every required point:
   combined `r`, `r_inv`, `r_h`, and `r_gate_v2`.
5. Transcript-bind the proof/VK version, group ID, root order, vector count, widths, field and
   extension encoding, protocol ID and session ID.
6. Publish a byte-exact transcript table: domain label, absorbed bytes and lengths in order, and
   each squeezed challenge. Rust prover, Rust verifier and Solidity must share it.
7. Remove challenge fields from the proof when possible. Otherwise rederive and equality-check
   every one.
8. Bump the outer `plonky2-mle-v0` protocol version and all affected WHIR/session/schema versions.
   Old proof bytes must not decode or verify as the new version.

### Soundness budget

A single Goldilocks scalar provides at most roughly 64 bits before accounting for vector count,
degree, multiple openings, union bounds and Fiat-Shamir grinding. Production acceptance requires a
written bound of at least 128 bits for the complete construction. Use Ext3 challenges, repeated
independent challenges, direct constituent openings, or another reviewed construction as needed.

The dense-MLE convention is LSB-first. Specify and test the exact conversion to WHIR point order
and the full Goldilocks-to-Ext3 embedding. A `c0`-only comparison is not an acceptable substitute
for a sound embedding/opening argument.

## 6. Changes that are not a repair

Do not close the Critical finding with any of these alone:

- comparing the Goldilocks batch to only the WHIR Ext3 `c0` limb;
- reversing or permuting evaluation-point coordinates;
- hashing the claimed individual evaluations after their values are chosen;
- adding more algebraic equalities over the same uncommitted claims;
- checking only one concrete mutation;
- increasing array/range validation without binding the arrays to committed constituents;
- relying on `allowedChainId`, `31337`, a deploy flag, or `MleProofEngineUnavailable`;
- trusting the honest Rust prover while leaving the malicious-prover language unchanged.

Keep the immutable `MleVerifier.allowedChainId` containment throughout the repair. Removing or
relaxing deployment/value-flow guards is a separate release decision after independent review.

## 7. Rust/Solidity parity and fraud semantics

- One canonical proof schema/layout constant must drive Rust proof serialization, fixture export,
  Rust verification, Solidity struct/parsing, WHIR `numCommitments/numVectors`, and VK generation.
  No consumer-side hand patching.
- Add a golden transcript trace containing the state/digest after every absorb and every root,
  challenge and query point. Rust prover, Rust verifier and Solidity must match all checkpoints.
- Differential tests must accept the same honest Rust proof and reject each mutation with matching
  semantics, including canonical `< P` checks, lengths, Ext3 limb order, point order and root order.
- `InvalidMleProof` remains reserved for authenticated proof-dependent invalidity. Configuration,
  unsupported features, unknown reverts and OOG remain `UNEVALUABLE`/`STARVED`; they must never
  convict or slash an honest submission.
- `skipVerification`, zero-VK test bypasses and always-true mocks remain local-development-only.

## 8. Mandatory adversarial tests

All exploit tests must run on the verifier's allowed chain with verification enabled.

1. Freeze both concrete triple mutations above. Keep roots, WHIR transcript/hints, sumchecks,
   public inputs and batch values unchanged. Rust and Solidity must reject them cryptographically.
2. Add a generalized adversarial prover/property test that constructs non-zero kernel deltas for
   every oracle group and terminal point, including witness/inverse and auxiliary compensation.
3. Reject root/vector reorder, swap, duplicate, omission, truncation, extension, cross-group reuse,
   old/new commitment mixing and query-point permutation.
4. Reject LSB/MSB reversal and non-zero/mutated Ext3 `c1/c2` attacks.
5. Reject old-proof/new-verifier, new-proof/old-VK, wrong circuit, wrong schema/version, malformed
   encoding, non-canonical fields and shape changes.
6. Include a deliberate bad-order regression implementation or model where `rho` is sampled before
   the constituent commitment and show that the kernel exploit reappears there.
7. Prove honest fixtures for every statement family and verify them in both Rust and Solidity.

## 9. Fixture and deployment migration

This is a proof/VK/ABI version change, not a verifier-only patch.

- Regenerate validity, withdrawal, close, cancel-close, withdrawal-claim, post-close-claim, C2C,
  submodule and WASM fixtures from one pinned toolchain and dependency lock.
- Recompute circuit/VK roots, gates/schema digest, protocol/session IDs, proof bytes/length/hash,
  blob commitments and any downstream DA artifacts.
- A Solidity source or proof-layout change can change metadata and initcode. Recompute CREATE2
  addresses. Close withdrawal fixtures bake the exact Manager address as their recipient, so use
  `CloseLifecycleE2ETest.test_printCloseManagerAddress`, regenerate the `close_` fixture family with
  that address, and then run the lifecycle E2E.
- Set-once VK contracts and immutable verifier deployments require fresh deployment unless a
  separately audited versioned migration is designed.
- Define an explicit cutover for old pending submissions and bonds. Never evaluate v0 bytes under
  v1 semantics or strand old state silently.

Use the generator ordering in `doc/tasks/regen-and-redeploy-runbook.md`, while retaining the
NO-GO/release constraints in the final audit.

## 10. Verification commands and release gates

At minimum, run from the appropriate repository roots:

```bash
# Submodule Rust
cd contracts/lib/polygon-plonky2
cargo test -p plonky2_mle --all-targets --locked

# Submodule Solidity
cd mle/contracts
forge test --offline

# Parent proof-generation/on-chain differential E2E
cd ../../../../..
cargo test --release --test mle_onchain_e2e --locked -- --nocapture

# Parent Solidity, including invariant/fuzz suites
cd contracts
forge test --offline
forge build --sizes --offline

# Repository integrity
cd ..
cargo check --all-targets --locked
git diff --check
git submodule status
```

Current pre-repair baselines are 109/109 submodule Forge tests and 503/503 parent Forge tests.
The `forge build --sizes` command reports non-zero because test-only `BlockHashHarness` is 82 bytes
over EIP-170; production contracts are currently under the limit. `IntmaxRollup` has only 62 bytes
of runtime margin, so report production sizes explicitly rather than treating the aggregate exit
code as sufficient evidence.

The Critical may be closed only when:

- the two frozen forgeries and generalized kernel attacks reach a proof-dependent rejection on the
  enabled allowed chain;
- a written soundness reduction/budget covers the complete transcript and all openings;
- Rust/Solidity differential, full Forge, Rust, fixture, gas/proof-size and EIP-170 gates pass;
- an independent cryptographic reviewer approves the transcript order, commitment format,
  malicious-prover model and Rust/Solidity parity;
- official release/deployment containment remains in place until that review is recorded.

Closing this PCS Critical does **not** close the separate NO-GO items: public close-proof
availability, a live withdrawal producer, channel-scoped Manager backing, browser/public claim E2E,
or atomic MSU. Preserve those dispositions in the final audit.

## 11. Suggested prompt for the repair thread

```text
Read doc/audit/mle-whir-pcs-repair-handoff.md completely before editing. Work in the
contracts/lib/polygon-plonky2 submodule first and treat the constituent-evaluation/RLC-kernel
soundness break as the primary objective. Implement a real commit-before-challenge/vector-opening
repair in Rust and Solidity, preserve the chain containment and fraud-classifier semantics, add
same-chain exploit tests, regenerate all affected fixtures, run the full acceptance matrix, commit
the submodule first and then update the parent gitlink. Do not claim the Critical is fixed based on
chain guards, c0 equality, coordinate reversal, honest-prover tests, or one frozen mutation.
```
