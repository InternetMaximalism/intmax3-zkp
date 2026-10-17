# Consolidated Cryptographic Soundness Review

**Project:** intmax3-zkp  
**Review date:** 16 October 2026  
**Reviewed main commit:** `0a2f5a284c0ae6cf6d23e53b810240151e696724`

## Executive assessment

The five component reviews identified **10 distinct prioritized findings: 2 P1, 6 P2, and 2 P3**. The most important issues are a missing verification-key binding in the production cyclic signature-history consumer and recipient decryption performed before sender authentication and public proof verification. These findings prevent a conclusion that the reviewed system is sound and secure as a whole.

The reviews did not identify an additional arithmetic constraint omission in the examined Regev encryption, range, and transfer AIRs; Falcon verification arithmetic; residual Poseidon signature helpers; or BN128 Poseidon permutation. This narrower result does not resolve the integration findings. An unresolved correlation between hiding salts and proof masks also requires investigation or a design change.

Some dependency fixes already existed in the working tree when the reviews began. They were tested but were **not included in the reviewed main commit**. Other findings concern generic configurations that production does not use. The inventory below preserves these differences rather than treating every finding as an active production exploit.

This report consolidates the five reviews listed in the evidence index. Finding status, source locations, and test results refer to their recorded audit state. Consolidation did not introduce product changes, rerun the audit suites, or establish remediation after that state.

## Scope and source baseline

| Component | Scope and production relevance |
| --- | --- |
| Vendored Plonky3 and external `regev_plonky3` | FRI, Merkle commitments, hiding commitments, uni-STARK, Poseidon2 AIR, DFT/NTT, Regev configuration, and encryption/range/transfer constraints |
| `src/falcon_sig` | Falcon-512 implementation and codecs, native verification, circuit gadgets, batch checks, aggregate/list recursion, and direct validity/close consumers |
| `src/regev/{encrypt,keys,params,mod}.rs` | Native key generation, encryption, decryption, ciphertext addition, encoding, parameters, randomness, and callers that enforce input and addition limits |
| `src/poseidon_sig` | Two remaining files, 177 lines: legacy list formatting and shared native/circuit hash-chain helpers; the old signature scheme has been removed |
| `src/wrapper_config` | Five files, 2,706 lines: native BN128 Poseidon permutation, constants, field representation, hash configuration, decoding, and wrapper integration |

Each component review verified that local and remote `main` matched the commit above using a read-only remote lookup. The first-party target modules and the cited validity consumer matched HEAD. Relevant pinned dependencies were:

| Dependency | Recorded version or commit | Working-tree qualification |
| --- | --- | --- |
| Plonky3 legacy tree | 0.4.2 under `vendor/plonky3/` | Present in the dependency graph; direct application use was not identified |
| Plonky3 active dependencies | 0.5.3 | Used by Regev and BabyBear hash-signature proofs; three Merkle source files had pre-existing local repairs |
| `regev_plonky3` | `5495edab5aa8ec7eae02a35e3098ddee384a1f58` | Local Cargo patch adds a singleton-NTT early return and test; the reviewed native `regev.rs` is byte-identical to the pinned source |
| DFT | 0.5.3 | HEAD resolves the registry crate; the working tree uses a local source patch |
| Plonky2 submodule | `3a20a05fb99d2653c4d37debb4f1ead2f422dfb2` | Baseline for recursive-verifier and hash-interface checks |
| Falcon upstream reference | Miden `475092a8476bf4c806424579e5d9225b12941c1a` | Eleven public source files were compared with the local implementation |
| BN128 Poseidon reference | iden3 `e5cf066b8be3da9a3df9544c65818df189fdbebe` | Permutation schedule and all 512 constants were checked |

Tests generally used the repository's pinned `rustc 1.87.0-nightly (b48576b4d 2025-03-22)` and the existing working-tree dependency graph. Separate dependency probes also used the toolchains recorded in their commands. Results must not be represented as a clean build of unmodified HEAD.

The [sig-cluster and delegate rules](/Users/andropov/repos/intmax3-zkp/doc/docs/sig-cluster-vs-delegates.md) apply throughout: N-of-N signature requirements concern the 2–8 co-signers. Delegates do not sign channel states and may join after deployment under the existing rules. Input-validation and signature fixes must preserve this distinction.

## Finding inventory

P1 denotes a high-priority security boundary defect; P2 denotes a defect requiring correction with the stated applicability; P3 denotes secret-handling hardening. These are inherited review priorities, not CVSS scores. VK means verification key; MMCS is the matrix commitment layer used by the proof system; AIR is its algebraic constraint description.

| ID | Priority | Finding | Applicability and status at review | Original reference |
| --- | --- | --- | --- | --- |
| C01 | P1 | Cyclic signature-history VK is not bound by the validity consumer | Production circuit; open in HEAD and working tree | Falcon F1; repeated by Poseidon |
| C02 | P1 | Recipient decryption precedes authentication and proof verification | CLI/browser wrappers and relay/API callers, subject to access and request conditions; open | Native Regev F1 |
| C03 | P2 | FRI uses proof-derived arity and height before adequate validation | Active Regev verification path; open | Plonky3/Regev F1 |
| C04 | P2 | Unvalidated Regev keys and ciphertexts reach asserting digest functions | Snapshot, registration, and JSON transaction paths; open | Native Regev F2 |
| C05 | P2 | A cap can omit smaller matrices from a mixed-height commitment | Generic nonzero-cap MMCS; production Regev uses cap height zero and avoids this condition | Plonky3/Regev F2 |
| C06 | P2 | MMCS does not fully bind path length and cap size to dimensions | HEAD binary case reproduced; local binary repair exists; N > 2 remains open | Plonky3/Regev F3 |
| C07 | P2 | Hiding MMCS does not enforce the fixed salt length | HEAD case reproduced; local 0.5.3 repair exists; legacy 0.4.2 also lacks the check | Plonky3/Regev F4 |
| C08 | P2 | BN128 hash decoding panics on invalid representations | Exported library API; no current production caller identified; open | Wrapper config F1 |
| C09 | P3 | Temporary Falcon secret-polynomial copies are not erased | Normal key generation/signing temporaries; open | Falcon F2 |
| C10 | P3 | Regev secrets and encryption witnesses expose Debug output and lack erasure | Secret-handling API; no actual external disclosure identified; open | Native Regev F3 |

The cyclic-VK issue is counted once. The Poseidon helper review added no independent finding. RNG correlation and other dependency/API concerns below retain their original ungraded status.

## High-priority security boundaries

### C01 Missing cyclic verification-key binding

**Location:** [validity_circuit.rs:249](/Users/andropov/repos/intmax3-zkp/src/circuits/validity/block_hash_chain/validity_circuit.rs:249).

`ValidityCircuit` verifies a nonzero signature-chain commitment using an `AggListCircuit` proof and the ordinary `add_proof_target_and_conditionally_verify` helper. That helper fixes the outer proof's VK but does not constrain the recursive VK carried in the cyclic proof's public inputs to equal the expected VK.

`AggListCircuit` exposes a [CyclicChainCircuit wrapper](/Users/andropov/repos/intmax3-zkp/src/falcon_sig/agg_list.rs:423). The wrapper uses a public-input VK to verify its predecessor and connects the current and predecessor *supplied* VKs. This does not establish equality with the actual wrapper VK. The pinned Plonky2 [cyclic-recursion contract](/Users/andropov/repos/intmax3-zkp/contracts/lib/polygon-plonky2/plonky2/src/recursion/cyclic_recursion.rs:94) explicitly requires an external binding check.

The validity circuit only extracts the first eight chain-commitment limbs and connects them to `final.bp_sig_chain`. Subsequent verification does not add the missing check, and the internal VK is not retained in the validity public outputs. Matching `CommonCircuitData` does not imply matching VKs or statements.

**Impact and evidence:** This is a source-confirmed missing constraint in the production circuit factory. A genuine terminal aggregate step and its Falcon verification remain necessary, but the preceding signature-history prefix is not inductively authenticated back to genesis. Honest witness generation and service-side native checks cannot replace constraints against a malicious prover. A complete forged validity proof, L1 acceptance, and asset movement were not demonstrated.

**Correction:** Use the existing [conditional cyclic helper](/Users/andropov/repos/intmax3-zkp/src/utils/recursively_verifiable.rs:70), or add equivalent conditional equality constraints for the internal circuit digest and every constants/sigmas cap element. Preserve the current computed nonzero-chain condition. The resulting validity VK changes, so dependent VKs, fixtures, and deployment configuration must be regenerated consistently.

Regression coverage should check all VK elements on the active branch, valid initial and subsequent spans, and the zero-chain dummy branch. Ordinary roundtrips alone always supply the expected VK and do not detect this omission.

### C02 Decryption of unverified ciphertexts exposes a secret-dependent predicate

**Locations:** [CLI co-sign gate](/Users/andropov/repos/intmax3-zkp/src/bin/channel_member.rs:10939), [batch verification](/Users/andropov/repos/intmax3-zkp/src/bin/channel_member.rs:11214), and [browser co-signing](/Users/andropov/repos/intmax3-zkp/src/wasm_wallet.rs:970).

After checking that a proposed transition extends the current head, these wrappers decrypt `enc_amount` when the recipient is a locally managed slot. They perform sender authentication and E-1/decrypted E-1 proof verification afterward. An invalid signature or proof therefore does not prevent the earlier secret-key operation. Head agreement and recipient-slot selection are public conditions.

The native [decoder](/Users/andropov/repos/intmax3-zkp/src/regev/encrypt.rs:213) validates ciphertext shape, computes `c2-c1*s`, and returns `DecryptOverflow` if upper digits are nonzero or the reconstructed amount exceeds u64. The wrapper exposes a different failure from later transition/proof rejection. Thus it exposes a predicate on a decryption result even when it returns neither plaintext nor a signature.

**Reachability and evidence:** Source tracing found that the wallet relay's [`/api/cosign`](/Users/andropov/repos/intmax3-zkp/hosting/wallet/wallet-relay.js:1130) returns CLI errors, including captured output. Its row/shape checks, JSON hash, replay handling, and head conditions are not cryptographic authentication. The relay listens on `0.0.0.0` without bearer middleware; actual reverse-proxy and network exposure were not inspected. The separate [production API](/Users/andropov/repos/intmax3-zkp/api/server.js:15) has bearer authentication and rate limiting, but an authorized caller reaches the same CLI. Browser code returns errors to its caller; arbitrary remote access to that browser function was not established.

The confidentiality boundary is defective, but query complexity, recoverable information, key recovery, and asset theft were not demonstrated. The finding rests on control flow and distinguishable error handling, not an executed key-recovery attack.

**Correction:** Authenticate the sender, reconstruct the statement from authenticated data, and verify the encryption/transfer proof before using the recipient's secret key. The core [slim verifier](/Users/andropov/repos/intmax3-zkp/src/wallet_core.rs:2015) already follows this order; wrapper pre-decryption defeats it. Split public verification from recipient confirmation, or first call the existing verifier without a recipient key or expected amount. Preserve amount policy. Normalizing error text alone does not remove the unnecessary secret-key operation.

## Verifier and decoding defects

### C03 FRI arity and height validation occurs too late

**Location:** [0.5.3 FRI verifier](/Users/andropov/repos/intmax3-zkp/vendor/p3-fri-0.5.3/src/verifier.rs:95). Open in both reviewed HEAD and working tree.

The verifier derives `log_global_max_height` from query-opening arities and uses it for index sampling before validating individual arity bounds, total reduction against the input domain, and integer/field limits. The active `SerializingChallenger32<BabyBear, ...>` asserts that the requested bit count fits both `usize` and its field sampling range. Excessive proof-derived heights can therefore panic before `InvalidProofShape` is returned. Later operations also contain unchecked height subtraction and arity shifts.

The application's [verify_one](/Users/andropov/repos/intmax3-zkp/src/regev/transfer_stark.rs:889) checks outer degree bits and public evaluation counts, but not these FRI arities. The active batch-STARK/PCS path reaches this verifier. Earlier shape checks and proof of work must succeed: the configuration uses 8 commit-grinding bits and 16 query-grinding bits, and arities are transcript-bound before query PoW. This is not a claim that changing one byte of an existing proof suffices. Publicly recomputable PoW does not authenticate the input.

**Impact and correction:** Native release uses `panic="abort"`, so a reached panic terminates the process. A network reproduction and false-statement acceptance were not demonstrated. Derive the allowed LDE height from verifier-owned input domains, use checked arithmetic, and reject invalid arities, schedules, and sampler bounds before PoW or index sampling. Legacy 0.4.2 has a related early-use boundary, but its application use was not established.

### C04 Regev digest callers fail to validate external inputs first

**Locations:** [snapshot key-root calculation](/Users/andropov/repos/intmax3-zkp/src/wallet_core.rs:1337), [registration key digest](/Users/andropov/repos/intmax3-zkp/src/block_producer.rs:151), and [transaction signing digest](/Users/andropov/repos/intmax3-zkp/src/wallet_core.rs:1871).

`RegevPk::digest`, `poseidon_digest`, and `RegevCiphertext::digest` enforce their preconditions with ordinary assertions in every build profile. Derived serde decoding does not perform validation. Several callers hash the resulting objects before validating them:

- Snapshot verification checks record structure and duplicates, then computes a key root without validating every participant's key. Signature verification follows. Browser import and native producer registration reach this path.
- Registration validation and fat-send member-key-root reconstruction also compute key digests too early.
- Fat and JSON-slim transaction verification compute a signing digest over `enc_amount` before checking ciphertext coefficient count and canonicality. The slim binary decoder validates ciphertexts, but the JSON path does not provide the same protection.

Pre-decryption in C02 incidentally validates a ciphertext only when the recipient is locally managed; it does not protect other cases. JS payload-shape checks do not enforce coefficient count or `<q`.

**Impact and evidence:** Source tracing identifies panic paths rather than acceptance of malformed keys or ciphertexts. Native release aborts; a CLI subprocess failure may be confined to that request, whereas a resident caller may terminate. WASM traps, with host recovery behavior unmeasured. No new malformed service request was executed for this finding.

**Correction:** Validate each public key and ciphertext before hashing at snapshot, registration, and transaction boundaries, returning ordinary errors. Checked digest/root APIs or validated types can enforce this contract. Reusing all of a new-participant admission function may unintentionally change participant policy; use the required format checks while preserving delegate admission rules.

### C05 Mixed-height commitments can omit matrices above the cap

**Locations:** [cap construction](/Users/andropov/repos/intmax3-zkp/vendor/p3-merkle-tree-0.5.3/src/merkle_tree.rs:199) and [MMCS verification success](/Users/andropov/repos/intmax3-zkp/vendor/p3-merkle-tree-0.5.3/src/mmcs.rs:427). Open in both reviewed states.

For a binary MMCS with matrix heights `[8,1]` and cap height 1, construction produces digest layers of lengths `[8,4,2,1]`. The height-1 matrix is injected only at the root layer. The published cap is the length-2 layer, so it does not depend on that matrix. Verification stops at the cap after `8→4→2` and does not check that every required matrix has been consumed.

This is a source-confirmed generic commitment-binding omission independent of hash collision resistance. No forged opening was executed in this review. Both ordinary and hiding [Regev configurations](/Users/andropov/repos/intmax3-zkp/vendor/regev-plonky3-5495eda/src/config.rs:163) use `cap_height=0`, which reaches the root and incorporates the small matrix; legacy 0.4.2 is also root-only.

**Correction:** Reject cap choices that stop before all matrices are injected, or authenticate injections above the cap in the proof format. Verification must confirm that every required matrix was authenticated. Positive mixed-height opening tests alone do not establish that property.

### C06 MMCS path length and cap size are insufficiently bound

**Locations:** [binary guards](/Users/andropov/repos/intmax3-zkp/vendor/p3-merkle-tree-0.5.3/src/mmcs.rs:344) and [proof-length-driven traversal](/Users/andropov/repos/intmax3-zkp/vendor/p3-merkle-tree-0.5.3/src/mmcs.rs:381).

HEAD does not fully derive the expected path length and cap size from the declared dimensions. A comparison using the existing boundary test showed that an opening for height 2 was accepted when the declared height was changed to 8. The pre-existing working-tree binary repair rejects the changed height by checking the expected total path length and cap count.

For N > 2, per-step sibling-count checks do not fully bind the entire traversal to the configured dimensions and cap. That generic case remains open; application use of N > 2 was not identified. Full false FRI/STARK acceptance was not demonstrated.

**Correction:** Include the binary repair in the released source and dependency resolution. For N > 2, derive and validate the complete arity schedule, total sibling count, and cap size from verifier-owned dimensions and configuration. Constructor termination fixes alone do not repair this verifier boundary.

### C07 Hiding MMCS accepts a noncanonical salt length

**Location:** [hiding MMCS verification](/Users/andropov/repos/intmax3-zkp/vendor/p3-merkle-tree-0.5.3/src/hiding_mmcs.rs:151).

HEAD checks the outer salt count but not that each salt contains exactly `SALT_ELEMS` elements. An existing boundary test appended a zero to a four-element salt; the leaf hash remained unchanged and HEAD accepted the opening. The local 0.5.3 repair validates salt length and rejects it.

The reproduced difference for C06 and C07 was:

```text
HEAD:         valid=true; changed_height=true; changed_width=true; longer_salt=true
Working tree: valid=true; changed_height=false; changed_width=true; longer_salt=false
```

[Comparison log](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/plonky3-regev-review-20261016/head-mmcs.log). The HEAD regression test intentionally fails the repaired expectations. Acceptance of a changed width is not independently treated as a production bypass: FRI intentionally supplies width zero to MMCS and checks row lengths later against OOD evaluations.

**Correction and scope:** Release the exact-salt-length repair. Legacy 0.4.2 also lacks the check, without identified current use. A second salt encoding alone was not shown to enable asset forgery.

### C08 BN128 hash decoding panics on malformed input

**Locations:** [serde decoding](/Users/andropov/repos/intmax3-zkp/src/wrapper_config/plonky2_config.rs:135) and [binary decoding](/Users/andropov/repos/intmax3-zkp/src/wrapper_config/plonky2_config.rs:74).

`PoseidonBN128HashOut::Deserialize` returns a `Result` but unwraps type decoding, decimal parsing, conversion to 32 bytes, and canonical scalar decoding. Invalid types, invalid decimal strings, oversized integers, and values at or above the modulus panic. `from_bytes` similarly panics on invalid length or a noncanonical scalar. Plonky2's fallible `read_hash` calls that infallible trait method after reading 32 bytes, so it does not convert the canonicality failure into an I/O error.

A small program including the unchanged source accepted decimal strings for zero and `r-1`. A JSON integer, a nondecimal string, decimal `r`, and an all-`0xff` binary scalar each panicked. Its subprocesses were deliberately compiled with `panic=abort`, producing SIGABRT; this probe choice does not establish an embedding application's panic strategy. [Decoder evidence](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/wrapper-config-review-20261016/decoder-probe/probe-results.log).

**Applicability and correction:** The public library module remains exported, but no production caller of this BN128 configuration was found. This is a dormant API availability defect, not a demonstrated production DoS or alternate accepted scalar encoding. Propagate serde errors and return custom errors for parse/range failures. Add a fallible binary decoder and validate external input before the existing infallible trait boundary.

## Secret handling

### C09 Falcon temporary polynomial copies are not zeroized

**Locations:** [Polynomial zeroization traits](/Users/andropov/repos/intmax3-zkp/src/falcon_sig/vendor/math/polynomial.rs:652) and [secret-basis cloning](/Users/andropov/repos/intmax3-zkp/src/falcon_sig/vendor/keys/secret_key.rs:375).

`Polynomial<F>` implements `Zeroize` and the `ZeroizeOnDrop` marker but has no destructor that invokes erasure. Normal key generation and signing clone the four secret NTRU-basis polynomials when building complex FFT values; those copies and secret-derived temporaries receive ordinary deallocation. Public-key computation also clones secret polynomials. The pinned upstream source shares this behavior.

This increases residual exposure if heap disclosure or memory acquisition occurs. Stored `SecretKey` and LDL-tree objects do have explicit erasure, so the finding does not mean that all key storage is unprotected. No remote extraction was demonstrated.

Use an actual zeroizing owner or scoped guard for secret temporaries, or explicitly erase them after use. A blanket generic `Drop` on every polynomial requires care because existing code moves coefficient storage and uses varied field types.

### C10 Regev secret and witness types permit disclosure and residual copies

**Locations:** [RegevSk](/Users/andropov/repos/intmax3-zkp/src/regev/keys.rs:119) and [AmountWitness](/Users/andropov/repos/intmax3-zkp/src/regev/encrypt.rs:146).

The secret key exposes a public vector, derives `Clone` and `Debug`, and has no zeroizing destructor. The temporary upstream key used during decryption is another unprotected copy. Amount/encryption witnesses can print amounts, randomness, and noise and are released as ordinary heap buffers.

The review found no production logging of these complete objects, peer serialization of the secret witness, or demonstrated remote disclosure. Redact Debug output and manage actual secret ownership, clones, and temporary lifetimes with erasure. Erasing only the root key does not erase its copies.

## Additional unresolved design and API concerns

### Hiding salts and masks share cloned RNG state

The external Regev [zk_config_with](/Users/andropov/repos/intmax3-zkp/vendor/regev-plonky3-5495eda/src/config.rs:163) gives clones of the same ChaCha20 RNG state to input MMCS, FRI MMCS, and PCS masking. Cloning a secure RNG does not create independent streams. Salt and mask BabyBear samples are correlated, and disclosed salts can coincide with randomness used for masks. Constructing a fresh configuration for every proof does not remove correlation *within* a proof.

This remains an **unresolved zero-knowledge design concern**, not a demonstrated recovery of balances or keys. Its consequence depends on trace shape and remaining mask freedom. Derive independent, domain-separated seeds for the three purposes, or provide a security argument for the exact joint distribution.

### Dependency contracts require stronger enforcement

| Concern | Recorded behavior and applicability | Required follow-up |
| --- | --- | --- |
| Ignored `eta` parameter | Validation accepts values such as 32, while key generation, encryption, and AIR use CBD(2). Current channels fix eta to 2. | Reject unsupported values so downstream security assumptions match the implementation. |
| Late public lookup-count checks | Upstream encryption/transfer verification checks counts 4/8 after inner verification, which already assumes the shape. The application's main `verify_one` checks them earlier. | Move dependency checks before indexing and assertions. No complete malformed proof was executed for this case. |
| Polynomial-length assumptions | Some upstream ciphertext operations use `zip` without fully checking every length. Current application validation and conversion/addition entry points supply the invariant. | Enforce matching lengths in the standalone dependency API as well. |
| RNG trait bound | Native key generation and encryption require `Rng`, not `CryptoRng`. Reviewed private production callers use CSPRNGs or secret seeds. | Make the caller obligation explicit or enforce it in the type bound; no weak private-production RNG use was found. |
| Conditional signature gadget | The caller must constrain its flag to Boolean and bind it to an authenticated active condition. | Preserve those conditions; `select` alone does not establish Booleanity. |
| Insecure Falcon basis import | The named insecure importer checks the 4,096-byte length, not the NTRU relation or sampling-tree validity. Identified non-test use is an explicitly insecure deterministic test-key cache. | Keep it outside untrusted production key import. |

## Properties checked without an additional confirmed defect

### Regev proof constraints and dependency arithmetic

The AIR review checked ternary randomness, CBD half constraints in `{0,1,2}`, Boolean message and carry constraints, initial/final zero carries, the final Horner anchor, shared challenges after the main commitment, ring-quotient identities, re-evaluation of public polynomials, and agreement between trace height and ring dimension.

The range AIR connects complements, flags, prefix counts, weights, and suffix sums, with `value_bits<=29` preventing the examined field wrap. It constrains the low `value_bits`; it does not claim to prove that all higher message coefficients are zero. Poseidon2 AIR checks covered full/partial rounds, S-box intermediates, and post-state constraints.

The local field chunk-processing replacement preserved complete chunks and tails. The local DFT repair replaces an aggregate transmute between distinct `DenseMatrix` generic instantiations with element slices and explicit reconstruction; no concrete compiler layout mismatch was observed. Tested LDE outputs matched `NaiveDft`. The existing singleton-NTT repair handles length 1; the channel uses n=2048 and product-transform length 4096.

### Falcon verification and aggregation

Native verification checks public-key coefficients below 12289, derives H2P from the actual salt and message, computes `s1=c-s2*h` using exact finite-field NTT, and accumulates centered norms in u64. The transport codec checks the version and 666-byte length, coefficient range `[-2047,2047]`, negative zero, unary length, unused bits, and exact re-encoding of the 625-byte compressed portion.

Native verification and circuit logic bind the public-key digest through `Poseidon(IMFK || encode(h))`. Four 14-bit coefficients fit below `2^56`, below the Goldilocks modulus. H2P agrees on eight 40-bit salt elements, eight u32 message limbs, the IMFH capacity domain, absorption order, and 64 squeezes.

Canonical Goldilocks splitting excludes `x+p` aliases by requiring `lo=0` when `hi=2^32-1`. Modular reduction constrains `t=k*q+r`, quotient width, and `r<q`; the examined bounds prevent wrap from selecting a different integer. NTT butterflies, products, inverse transforms, and final reductions are range-checked. Even adversarial centering-bit choices keep the full norm below `1024*q^2<2^38`, while the 26-bit difference constraint enforces `norm<=34,034,726`.

The gadget verifies mathematical mod-q signature residues, which is broader than the native compressed transport's coefficient range. That documented API difference was not shown to permit forgery.

The batch product check commits canonical `h`, `s2`, and all 1,023 product coefficients before deriving an extension-field challenge. Each slot checks its own polynomial identity, preventing cancellation between slots. When the identity holds, coefficient bounds `512*(q-1)^2<2^37` establish the integer interpretation without field wrap. Active flags, count, padding, constant child VKs, and message/key-list connections were inspected.

An aggregate alone does not prohibit duplicate signers. Reviewed close/cancel-close consumers additionally bind message, count, member commitment, and active-key distinctness. C01 is the separate cyclic-history boundary.

### Native Regev encryption and addition budget

The active parameters are `n=2048`, `q=2,013,265,921`, `eta=2`, `t=256`, and `Delta=7,864,320`, with `q=256*Delta+1`. Correctly generated keys use uniform `a`, ternary `s`, and CBD(2) error, with `b=a*s+e`. Encryption computes `c1=a*r+e1` and `c2=b*r+e2+Delta*m` in the negacyclic ring.

Primitive encryption/decryption/addition validate two 2,048-coefficient polynomials and canonical coefficients before conversion. C04 concerns callers that bypass those checks when hashing. Amount encoding puts the low 64 bits into separate 0/1 coefficients and zeros the rest. Decryption uses `floor((256*v+floor(q/2))/q) mod 256`; u128 accumulation is bounded below `2^72` before checked u64 conversion. Ciphertext addition uses u64 arithmetic and explicit mod-q reduction, with sums at most `2q-2`.

For correct matching keys and fresh encryption, each coefficient satisfies:

```text
E = e*r - e1*s + e2
|E_fresh| <= 2n + 2n + 2 = 8,194
```

One fresh balance plus 64 credits has **65** fresh noise terms, giving a conservative bound of **532,610**, with per-digit value at most 65. For every digit from 0 through 255, the actual decoder is correct throughout `|E|<=3,932,159`. The bound therefore retains approximately 7.38 times noise headroom. A canonical-zero starting balance needs only 64 terms. Integer endpoint checks cover all 256 digits and, by monotonicity, all errors between the endpoints. [Rounding evidence](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/regev-encryption-review-20261016/rounding.log).

The stateless addition function does not count operations. Balance validation, state-update constraints, and batch folding enforce the reviewed 64-credit limit. No bypass was found in the examined direct callers. This noise/digit guarantee is separate from the requirement that the total amount fit u64.

Canonical-zero ciphertext is a valid additive identity whose zero witness claims amount zero. It is distinct from randomized encryption of zero. Exit-shape admission is not a substitute for proof of encryption or amount range. Public-key format validation does not prove entropy, uniform generation, or secret-key possession; separate admission checks reject all-zero `a` and duplicate keys. Decryption checks secret-key length but not ternary coefficients, so the noise guarantee assumes properly generated matching keys.

PK/ciphertext digests bind domains, lengths, coefficient order, and ordered key roots. Keccak uses big-endian u32 encoding; Poseidon's coefficient lift is injective because `q<2^32<p_Goldilocks`. Private production RNG callers were checked separately from public deposit/genesis reconstruction and explicit development/test seeds. Stored refresh amount/seed witnesses are private state; reviewed persistence uses mode 0600 and atomic replacement, with no identified peer-snapshot export.

### Residual Poseidon signature helpers

The old `GoldilocksSecretKey`/`SingleSigCircuit` scheme and fallback are absent from executable code. The remaining list functions compute:

```text
leaf_i = Poseidon(IMLL || message_i[8 u32] || public_key_i[8 u32])
C_0    = [0, 0, 0, 0]
C_i    = Poseidon(C_(i-1)[4 field elements] || leaf_i[4 field elements])
output = canonical Bytes32(C_N)
```

Native and circuit functions agree on their fixed 17-element leaf and eight-element chain layouts. The current leaf caller receives range-checked message/key limbs from the Falcon gadget. Commitment conversions reconstruct canonical Goldilocks splits, excluding mod-p aliases. Order and repeated entries are represented in the chain; these utilities do not independently establish signature validity, signer membership, uniqueness, or completeness.

Production validity uses `FalconAggCircuit → AggListCircuit → ValidityCircuit`, with IMPL for all eight key slots, IMAL for the aggregate leaf, and IMCH for the actual channel/block message. Producer and consumer reconstruct the same message, signer count, and key-list digest. They share the chain-step helper, rather than using the old IMLL pair as the production leaf. The cumulative builder preserves the history across spans. These consistent hash connections do not repair C01.

### BN128 Poseidon and the actual wrapper configuration

The BN128 field is the BN254 scalar field, not the curve base field. Width 4, rate 3, eight full rounds, 56 partial rounds, `x^5`, dense-matrix orientation, and sparse-update order match the pinned iden3 source. All **512 constants** match: 88 C entries, 392 S entries, and 16 entries each in M and P. All 69 nonempty square minors of M are nonzero, P and all 56 sparse matrices are invertible, and `gcd(5,r-1)=1`. [Comparison evidence](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/wrapper-config-review-20261016/constant-comparison.log).

Input packing uses at most three canonical Goldilocks u64 values per Fr element, fitting in 192 bits without reduction. `hash_or_noop` correctly limits direct packing to three elements. Output conversion uses five limbs of 56/56/56/56/32 bits, preserving all 32 bytes injectively. Merkle compression uses the complete ordered pair `[0,0,left,right]`; padding is sized for nine Goldilocks elements per absorption.

Unpadded hashing has cross-length zero-extension ambiguity, consistent with its pinned fixed-length contract. Plonky2 FRI checks leaf widths, reduction arities, and path depths before openings; cross-length aliases alone were not established as alternate accepted fixed-shape openings. This Plonky2 shape check is separate from the Plonky3 FRI issue C03.

BN128 commitments use a Goldilocks Poseidon Fiat–Shamir permutation and absorb all five digest limbs. `InnerHasher` handles public-input hashing and other inner uses. The mixed field design was not found to truncate the transcript or create a prover/verifier mismatch.

The module contains no BN128 non-native circuit gadget or `AlgebraicHasher` implementation. Actual application wrappers use `WrapperCircuit<F,C,C,D>` with `C=PoseidonGoldilocksConfig`, then MLE/WHIR proving and verification. The contract calls the pinned MLE verifier and binds its returned public inputs to the expected validity hash. It does not decode BN128 decimal hashes. No current gnark execution path was found. This caller tracing establishes C08's limited applicability; it is not a complete MLE or contract audit.

## Security assumptions and advisory context

The examined vendored Plonky3 generations contain checks corresponding to published [FRI size](https://github.com/Plonky3/Plonky3/security/advisories/GHSA-m23j-cj9m-ppg9), [final-degree and roll-in](https://github.com/Plonky3/Plonky3/security/advisories/GHSA-f69f-5fx9-w9r9), and [opened-value transcript-binding](https://github.com/Plonky3/Plonky3/security/advisories/GHSA-vrmm-4mm5-38vm) advisories. Their presence does not close C03–C07.

The [MultiField32Challenger advisory](https://github.com/Plonky3/Plonky3/security/advisories/GHSA-vj64-rjf3-w3v7) was addressed upstream in 0.4.3/0.5.3. The older version is present in the graph, but current Regev uses a different 0.5.3 challenger; version presence alone does not establish exposure. The [PaddingFreeSponge advisory](https://github.com/Plonky3/Plonky3/security/advisories/GHSA-3g92-f9ch-qjcm) makes fixed layouts and salt lengths material. Enforcing `Dimensions.width` blindly inside MMCS would reject valid FRI calls that intentionally pass zero; width checks need a coordinated caller contract.

| Security statement | Interpretation retained from the component review |
| --- | --- |
| Regev proof configuration | 42 queries, rate 1/4, and 16 query-grinding bits advertise approximately 100 bits of conjectured proof security; n=2048 is a separate encryption parameter. |
| Falcon batch product check | A roughly 128-bit extension-field challenge space and degree at most 1022 give the code's conservative error estimate below `2^-117`, under Poseidon/Fiat–Shamir assumptions. |
| Falcon H2P | The approved implementation uses Poseidon rather than SHAKE. Standard Falcon tests do not certify that substitution's random-oracle assumption. |
| Native Regev lattice estimates | The documented 197/178-bit primal-uSVP/core-SVP figures were not recomputed across a pinned estimator, all attacks, distributions, sample counts, and cost models. |
| BN128 reference agreement | Exact constants and permutation behavior support implementation consistency, not a new cryptanalytic proof of Poseidon round security. |

None of these statements is a system-wide 128-bit security certification. The reviews do not prove resistance to timing, fault, heap disclosure, sampler-distribution attacks, or every SIMD/compiler target. They do not constitute a complete protocol conservation proof or a full WASM/browser recovery assessment.

## Recorded validation

The following are **per-review counts**, not disjoint suites. In particular, the native Regev tests overlap the broader Regev filter, and Falcon list/domain tests overlap the Poseidon review. No aggregate test total is claimed.

| Review | Recorded validation | Evidence |
| --- | --- | --- |
| Plonky3 and external Regev | 64 repository Regev tests passed. Production-configuration n=2048 encryption/range/transfer proofs succeeded; changed public statements and transfer roles were rejected. | [Production fixture and log](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/plonky3-regev-review-20261016/production-regev.log) |
| MMCS and arithmetic dependencies | Two repaired-boundary tests; two termination/N-ary tests; three rejection-sampling tests; 168 DFT/LDE comparisons in sequential and parallel modes; two FRI tests and one uni-STARK test. HEAD MMCS failed repaired expectations as intended, reproducing C06/C07. | [Dependency review and commands](/Users/andropov/repos/intmax3-zkp/doc/audit/docs/plonky3-regev-review-2026-10-16.md), [HEAD comparison](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/plonky3-regev-review-20261016/head-mmcs.log) |
| Falcon | 61 distinct existing tests: 13 native/codec/identity, 4 hardening, 3 vendor math, 22 gadget, 12 batch, 3 tree, 1 list roundtrip, 1 cyclic aggregate-list roundtrip, 2 statement/parser tests. Benchmarks excluded. | [Test manifest](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/falcon-review-20261016/test-results.json) |
| Native Regev | 14 distinct existing tests: 7 encryption, 3 keys/root, 1 parameters, 1 domains, 1 zero witness, 1 balance/addition budget. Integer rounding inequalities separately checked all 256 digits at both error endpoints. | [Test manifest](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/regev-encryption-review-20261016/test-results.json) |
| Residual Poseidon helpers | 20 existing tests: 2 chains, 13 conversions, 1 Falcon list, 2 domains, 2 legacy-proof rejection. Two additional small circuit proofs checked native/target agreement and canonical boundary conversions. | [Test manifest](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/poseidon-sig-review-20261016/test-results.json), [Boundary proofs](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/poseidon-sig-review-20261016/boundary-probe.log) |
| BN128 wrapper config | Six existing tests passed; one contains four permutation vectors. Two valid decoder cases succeeded and four invalid cases panicked. All 512 constants and matrix invariants passed independent checks. | [Test manifest](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/wrapper-config-review-20261016/test-results.json) |

The MMCS sweeps covered 5,058 binary, 48 extension, and 155 four-ary boundary cases, plus mixed-height sweeps. Additional ordinary-opening sweeps covered 48,829 N=4, 37,024 N=8, and 36,169 N=16 cases. These are subcases, not additional independent test-function totals.

Legacy 0.4.2 development dependencies and some 0.5.3 Circle/Mersenne development dependencies were unavailable offline, so their full suites were not run. Full upstream Falcon signing KATs and a removed gnark verifier comparison were not run. Some negative tests fail during witness generation, which does not alone establish that the constraints reject every malicious witness. Source-level constraints and integer bounds support the arithmetic conclusions; successful honest proofs do not disprove C01 or C02.

## Remediation sequence and acceptance criteria

1. **Repair C01 and C02.** Bind every cyclic VK element in the active validity branch, regenerate affected verification artifacts, and enforce public authentication/proof verification before all recipient secret-key operations. Preserve genuine roundtrips, zero-chain behavior, and recipient amount policy.
2. **Close active input and verifier boundaries.** Address C03 with early checked FRI schedule validation and C04 with validation before all asserting digests. Invalid input should return an error without sampling outside bounds, panicking, or invoking unnecessary secret-key operations.
3. **Release and verify existing dependency repairs.** Include binary MMCS path/cap checks, salt-length checks, DFT reconstruction, singleton NTT handling, Cargo patches, and lockfile changes in the released source state. Local working-tree success is insufficient evidence that HEAD or a deployed artifact contains them.
4. **Complete generic commitment protections.** Repair C05 and the N > 2 portion of C06. Check that every matrix affects the commitment, and that dimensions and cap configuration uniquely determine the accepted traversal.
5. **Resolve RNG independence and parameter contracts.** Separate salt/mask randomness and reject unsupported eta values; move lookup-count and polynomial-length checks to the dependency boundaries that require them.
6. **Harden dormant decoding and secret lifetimes.** Address C08 before deploying the BN128 config, and implement actual erasure and redacted diagnostics for C09/C10.

These actions are recommendations from the reviews. This consolidation does not mark them completed.

## Documentation corrections

| Area | Correction supported by the reviewed code |
| --- | --- |
| Falcon inactive padding | An inactive gadget slot may use any canonical public-key polynomial with its corresponding digest; a zero-polynomial witness is one construction. Current consumers exclude inactive keys from the public statement. |
| Falcon norm bound | The comment's `<2^36` assumes the minimum centered choice. Allowing adversarial centering bits requires `<2^38`, still below the Goldilocks modulus; the bounds-ledger test already uses the correct bound. |
| Regev addition budget | Count 65 fresh noise terms for a fresh base plus 64 credits, yielding 532,610 rather than 524,416. This does not justify changing the existing 64-credit limit. |
| Poseidon list descriptions | Replace obsolete IMLL/IMSB production-consumer descriptions and the deleted consumer-module reference with the actual IMAL/IMCH aggregate statement; only the chain step is shared. |
| BN128 and Groth16 descriptions | The current fixture generator uses one ordinary Poseidon wrapper and MLE/WHIR, despite comments describing two BN128 wraps. `--skip-groth16` is a historical no-op. |

These inaccuracies were not independently established as additional bypasses and are excluded from the 10-finding count.

## Evidence and original reports

The original reports remain intact. They retain detailed source references, reproduction commands, qualifications, and logs. Source manifests identify the exact reviewed files and distinguish relevant HEAD content from existing local changes.

| Source report | Recorded source inventory | Additional evidence |
| --- | --- | --- |
| [Plonky3 and external Regev](/Users/andropov/repos/intmax3-zkp/doc/audit/docs/plonky3-regev-review-2026-10-16.md) | [Source manifest](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/plonky3-regev-review-20261016/source-manifest.json) | [Fixture manifest](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/plonky3-regev-review-20261016/Cargo.toml) |
| [Falcon implementation and circuits](/Users/andropov/repos/intmax3-zkp/doc/audit/docs/falcon-soundness-review-2026-10-16.md) | [Source manifest](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/falcon-review-20261016/source-manifest.json) | [Upstream comparison](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/falcon-review-20261016/provenance-comparison.json) |
| [Native Regev encryption](/Users/andropov/repos/intmax3-zkp/doc/audit/docs/regev-encryption-review-2026-10-16.md) | [Source manifest](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/regev-encryption-review-20261016/source-manifest.json) | [Rounding checker](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/regev-encryption-review-20261016/check_rounding.py) |
| [Residual Poseidon signature helpers](/Users/andropov/repos/intmax3-zkp/doc/audit/docs/poseidon-sig-review-2026-10-16.md) | [Source manifest](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/poseidon-sig-review-20261016/source-manifest.json) | [Boundary fixture](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/poseidon-sig-review-20261016/fixture/src/main.rs) |
| [BN128 Poseidon wrapper config](/Users/andropov/repos/intmax3-zkp/doc/audit/docs/wrapper-config-review-2026-10-16.md) | [Source manifest](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/wrapper-config-review-20261016/source-manifest.json) | [Reference provenance](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/wrapper-config-review-20261016/reference-provenance.json), [Decoder probe](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/wrapper-config-review-20261016/decoder-probe/probe.rs) |
