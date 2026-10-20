# Utilities Soundness Review

**Review date:** 17 October 2026  
**Repository / branch:** intmax3-zkp / main  
**Reviewed HEAD:** `0a2f5a284c0ae6cf6d23e53b810240151e696724`

## Assessment

This review identifies **four new prioritized findings: three P2 and one P3**. The most directly exposed issue is a panic while deserializing an incremental Merkle tree: a malformed `ChannelSnapshot` reaches it before signature verification. The other findings concern inconsistent Merkle index validation, noncanonical field representations, and panic behavior in hash-chain APIs.

The native Merkle verifier demonstrably accepts an index outside its tree, but the corresponding fixed-height circuit constrains the index. No additional production proof-forgery path was established. The previously reported cyclic verification-key binding issue remains open at its validity-circuit consumer; it is not counted again here.

All **30 Rust files under `src/utils/`**, totaling **7,549 lines including comments and tests**, were inspected, together with relevant callers and selected dependency implementations. Both local and remote `main` matched the commit above. All target files matched HEAD and remained unchanged. Tests used the existing working tree, which contains local Cargo/dependency changes and unrelated fixes. No product code was modified.

## Findings

| ID | Priority | Finding | Demonstrated impact / reachability |
| --- | --- | --- | --- |
| UTILS-01 | P2 | Tree deserialization reconstructs invalid state without checking invariants | Bounded malformed JSON aborts the process, including through the real ChannelSnapshot type; production import/command paths decode this type before verifying it |
| UTILS-02 | P2 | Merkle index validation differs between native verification, storage, and circuits | One proof verifies at indices 0 and 4 in a height-two tree; an out-of-range sparse leaf is stored without changing the root |
| UTILS-03 | P2 | PoseidonHashOut's numeric constructor bypasses canonical field decoding | Distinct Rust objects map to the same field values/hash, and an accepted object cannot deserialize its own JSON encoding |
| UTILS-04 | P3 | Hash-chain Result APIs panic on malformed inputs | Chain-end numeric decoding aborts on oversized limbs; generic chain processor also slices/unwraps unvalidated previous proof fields; no active production caller of these affected generic APIs found |

These priorities distinguish input availability and API integrity from cryptographic proof acceptance. Findings that share the missing Merkle-index invariant are grouped under UTILS-02 rather than counted twice.

### UTILS-01 — Tree deserialization can abort before snapshot authentication

**Locations:** [IncrementalMerkleTree deserialization](/Users/andropov/repos/intmax3-zkp/src/utils/trees/incremental_merkle_tree.rs:225), [unpack](/Users/andropov/repos/intmax3-zkp/src/utils/trees/incremental_merkle_tree.rs:207), [push assertion](/Users/andropov/repos/intmax3-zkp/src/utils/trees/incremental_merkle_tree.rs:70), [IndexedMerkleTree derive](/Users/andropov/repos/intmax3-zkp/src/utils/trees/indexed_merkle_tree/mod.rs:22).

The incremental tree decoder reads an arbitrary height and leaf vector, calls `unpack`, and rebuilds the tree by calling `push`. It does not check the height/capacity relationship before reconstruction. The valid JSON `{"height":0,"leaves":[1,2]}` reaches the second push and panics because the capacity is one. The enclosing `serde_json::from_str` therefore does not return a serde error. The same issue applies to a tree embedded in a larger message.

The boundary fixture reproduced this with both `IncrementalMerkleTree<u32>` and the application's actual `ChannelSnapshot` type, using two ordinary zero Bytes32 leaves in `settledTxAccumulator`. Both subprocesses terminated with SIGABRT under the release profile. The snapshot test supplies only that field; the panic happens while decoding it, before the decoder can return a missing-field error for the rest of the message. It needs no valid signatures or expensive malformed proof.

This decoder is reachable at [wallet_import_channel](/Users/andropov/repos/intmax3-zkp/src/wasm_wallet.rs:443), before `verify_snapshot`, and through the [block-producer Register command](/Users/andropov/repos/intmax3-zkp/src/block_producer_service.rs:512), before `register` validates the decoded snapshot. `map_err` handles returned errors, not this panic. Whether an external party can submit to a particular service depends on that service's access controls; no live service request was sent. The demonstrated native release outcome is process termination. A WASM invocation can trap rather than returning its intended error result.

There is also a non-panicking invariant bypass in the indexed wrapper: derived deserialization accepts `{"height":2,"leaves":[]}`, while `IndexedMerkleTree::new(2)` always inserts the sentinel leaf at position zero. The fixture confirmed the decoded empty tree has a different root and no sentinel. This does not by itself bypass authentication of a previously committed root, but it means constructor-established indexed-tree invariants do not survive decoding.

**Correction:** validate supported height and leaf capacity with checked arithmetic before reconstruction and return serde errors for invalid data. Validate the indexed tree's required sentinel and list invariants, or reconstruct from a canonical higher-level representation. Validate application-specific heights before using decoded snapshots. Preserve the distinction between the sentinel and unused positions; making them equal would reopen the duplicate-insertion problem the current code explicitly prevents.

### UTILS-02 — Native Merkle verification and storage accept out-of-range indices

**Locations:** [MerkleProof::get_root](/Users/andropov/repos/intmax3-zkp/src/utils/trees/merkle_tree.rs:136), [BitPath::new](/Users/andropov/repos/intmax3-zkp/src/utils/trees/bit_path.rs:17), [tree update](/Users/andropov/repos/intmax3-zkp/src/utils/trees/merkle_tree.rs:72), [SparseMerkleTree::update](/Users/andropov/repos/intmax3-zkp/src/utils/trees/sparse_merkle_tree.rs:68), [circuit index decomposition](/Users/andropov/repos/intmax3-zkp/src/utils/trees/merkle_tree.rs:225).

`BitPath::new` stores the supplied length and value without ensuring that the value fits. Native proof verification pops exactly one bit per sibling and discards any remaining high bits. A height-two proof for leaf 7 at index 0 therefore also verifies at index 4 against the same root. This was reproduced using a proof generated by the ordinary incremental tree implementation.

Storage behaves differently but is also invalid. Updating index 4 in a height-two sparse tree stores the leaf and intermediate nodes under paths whose final length-zero key is `(length=0, value=1)`. The actual root is read at `(0,0)`, so `get_leaf(4)` returns the newly stored value and `len()` increases, while `get_root()` remains unchanged. A serialized sparse tree containing this out-of-range entry is accepted on restoration and preserves the same inconsistency. The fixture checks both direct update and deserialization.

By contrast, `MerkleProofTarget::get_root` uses `builder.split_le(index, height)`, constraining the field index to the fixed number of bits for the production heights in use. This excludes the illustrated index 4 at height two. Some native callers independently check the range: [DepositWitness::verify](/Users/andropov/repos/intmax3-zkp/src/circuits/balance/common/deposit_witness.rs:77) checks the deposit-tree bound before calling the generic verifier. Other common identities use bounded integer types. These checks limit production reachability; the demonstrated defect is in the reusable native APIs, not a bypass of that circuit decomposition.

**Correction:** reject indices outside the supported tree domain in proof verification, proving, lookup, update, and unpacking. Perform validation before mutation. Check the intended proof height at fixed-height protocol boundaries rather than treating any sibling-vector length as the expected tree shape. Do not repair this by masking the index: that would preserve the ambiguity.

### UTILS-03 — Numeric PoseidonHashOut construction admits noncanonical limbs

**Locations:** [from_u64_slice](/Users/andropov/repos/intmax3-zkp/src/utils/poseidon_hash_out.rs:61), [hash_inputs_u64](/Users/andropov/repos/intmax3-zkp/src/utils/poseidon_hash_out.rs:75), [u64-to-field conversion](/Users/andropov/repos/intmax3-zkp/src/utils/conversion.rs:43), [checked Bytes32 conversion](/Users/andropov/repos/intmax3-zkp/src/utils/poseidon_hash_out.rs:280), [serde decoding](/Users/andropov/repos/intmax3-zkp/src/utils/poseidon_hash_out.rs:386).

`PoseidonHashOut::from_u64_slice` checks only that there are four words. Unlike its Bytes32/serde decoder, it accepts a word equal to the Goldilocks modulus `p = 2^64 - 2^32 + 1`. The resulting object is unequal to the all-zero object under Rust equality and preserves the noncanonical bytes when serialized.

Later field conversion calls `from_canonical_u64` without a runtime range check. In the pinned Goldilocks implementation that method only has a [debug assertion](/Users/andropov/repos/intmax3-zkp/contracts/lib/polygon-plonky2/field/src/goldilocks_field.rs:154). Release field operations consequently interpret the word `p` as zero. The fixture confirmed all of the following:

- `[p, 0, 0, 0]` is accepted by `from_u64_slice` and differs from `[0, 0, 0, 0]` as a Rust object.
- Hashing those two arrays through `hash_inputs_u64` produces the same result.
- A target constructed from the noncanonical object exposes four zero canonical public inputs in an ordinary verified circuit proof.
- Serializing the accepted object succeeds, but deserializing its own JSON fails the stricter canonicality check.

This is a representation alias, not a break of Poseidon. Verified field public inputs converted using `ToU64` are canonical, and the checked Bytes32 target conversion retains its round-trip constraints. No new production authentication bypass through those checked paths was established.

**Correction:** enforce `element < GOLDILOCKS_ORDER` in the checked numeric constructor and make field-conversion contracts explicit. Values intended as arbitrary 64-bit integers require an injective limb encoding; intentional field reduction should be a separate, explicitly named operation. Audit public struct construction and witness setters as well as the parser. Preserve existing commitment encodings unless a deliberate migration is planned.

### UTILS-04 — Hash-chain decoding/proving APIs can panic instead of returning errors

**Locations:** [ChainEndProofPublicInputs numeric decoder](/Users/andropov/repos/intmax3-zkp/src/utils/hash_chain/chain_end_circuit.rs:63), [HashChainProcessor::prove_chain](/Users/andropov/repos/intmax3-zkp/src/utils/hash_chain/hash_chain_processor.rs:59).

After checking the overall length, the chain-end parser asserts that each word fits in 32 bits. A correctly sized 13-word input with one word equal to `2^32` aborts instead of returning `HashChainError`. The isolated fixture reproduced SIGABRT at this assertion.

The generic chain processor similarly reads the first eight public inputs of an optional previous proof before validating its shape, then unwraps Bytes32 decoding. Short public-input vectors can panic on slicing; oversized limbs can panic at the unwrap. This second path is source-confirmed and was not exercised by constructing a chain circuit.

Repository searches did not identify current production call sites for `ChainEndProofPublicInputs` parsing or this generic `HashChainProcessor`; the similarly named block hash-chain processor is a different implementation. The shared `CyclicChainCircuit` is used, but that fact does not establish reachability of these parser failures.

**Correction:** validate lengths and limb ranges using fallible conversions, propagate errors, and validate the previous proof at the appropriate trust boundary. Do not rely on `Result` in the signature to contain panics from indexing or assertions.

## Other boundary concerns

These observations are retained without counting them as additional demonstrated production security failures.

- [IndexedMerkleLeaf::empty_leaf](/Users/andropov/repos/intmax3-zkp/src/utils/trees/indexed_merkle_tree/leaf.rs:68) deliberately sets `next_index = u64::MAX`, which exceeds the field modulus. Its hash and target constant paths feed this to `from_canonical_u64`, violating that function's precondition and triggering the upstream assertion in debug builds. The release tests exercise the reduced field representation. Handle intentional reduction explicitly and preserve the existing empty-leaf commitment and sentinel separation. No full debug build was run in this review.
- [IncrementalMerkleTree::update](/Users/andropov/repos/intmax3-zkp/src/utils/trees/incremental_merkle_tree.rs:65) mutates Merkle nodes before indexing the leaf vector. An index inside the tree capacity but beyond the allocated vector can panic after changing the root. Similarly, [indexed insertion](/Users/andropov/repos/intmax3-zkp/src/utils/trees/indexed_merkle_tree/insertion.rs:68) updates the predecessor before the final capacity-checked push. A panic caught in an unwind build can therefore leave partial state; panic-abort terminates instead. Validate allocation/capacity before mutation. This was established from operation order, without an unwind-build reproduction.
- `BuilderLogic::select_vec` assumes its flags are one-hot; it does not enforce this itself. Both current production callers explicitly constrain Boolean flags and their sum to one: [balance switch board](/Users/andropov/repos/intmax3-zkp/src/circuits/balance/switch_board.rs:188) and [block step](/Users/andropov/repos/intmax3-zkp/src/circuits/validity/block_hash_chain/block_step.rs:461). No missing selector constraint was found at these uses.

## Recursion, MLE, and previous findings

The ordinary proof helpers verify against a fixed supplied VK. The cyclic variants additionally connect the embedded VK digest and cap to that expected VK. `ChainEndCircuit` uses the cyclic helper correctly. A generic `WrapperCircuit` is not a substitute for the additional binding required by a cyclic proof's external consumer.

The existing **C01** finding in the [consolidated cryptographic report](/Users/andropov/repos/intmax3-zkp/doc/audit/docs/consolidated-cryptographic-review-2026-10-16.md) remains relevant: the validity circuit consumes AggList's cyclic proof through the ordinary conditional helper. This review did not count that known integration defect as a new bug in the generic helper.

The previously reported **COMMON-04** PublicState empty-leaf mismatch is also visible at the generic padded-tree builder. The padding algorithm uses the `LeafableTarget` implementation as designed; the mismatch belongs to the PublicState implementation and is not counted again here. See the [common review](/Users/andropov/repos/intmax3-zkp/doc/audit/docs/common-soundness-review-2026-10-17.md).

In `mle_prover.rs`, production export and `validated_compact_mle_v2_bytes` derive the expected configuration from the circuit and compare the fixture against it. The dependency's `validate_against_common` decodes the authoritative compact proof, checks its agreement with the structured/ABI views, and performs native verification. The low-level `verify_mle_proof_v2` instead receives its VK from its caller and passes that VK plus common data to the verifier; callers must supply a trusted VK. The inspected production callers derive it from their circuit. The artifact-consistency helper `validate_mle_v2_full_against_config_json` is not itself a cryptographic proof verifier.

No additional missing arithmetic or recursive binding constraint was established in these correctly used utility paths. This is a targeted review of the wrappers and selected consumers, not a re-audit of the complete ML/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/utils-review-20261017/WHIR implementation or deployed contracts.

## Coverage

| Files under src/utils | Review focus / result |
| --- | --- |
| `conversion.rs`, `poseidon_hash_out.rs` | Canonical limbs, byte/field conversion, split uniqueness, native/target hashes, serialization: UTILS-03 and the intentional-reduction observation |
| `trees/bit_path.rs`, `trees/merkle_tree.rs`, `trees/sparse_merkle_tree.rs` | Index domain, node addressing, proof folding, fixed-height circuit decomposition, sparse restoration: UTILS-02 |
| `trees/incremental_merkle_tree.rs` | Capacity, updates, serde reconstruction, proof forwarding: UTILS-01 and mutation-before-panic observation |
| `trees/indexed_merkle_tree/{mod,insertion,leaf}.rs` | Sentinel/empty distinction, lower/upper key bounds, predecessor/insertion paths, conditional constraints: decoded sentinel bypass and boundary observations; existing duplicate-insertion regression passed |
| `trees/get_root.rs`, `leafable.rs`, `leafable_hasher.rs` | Native/target leaf and internal hashing, padding, Keccak/Poseidon branch order; existing COMMON-04 distinguished from utility code |
| `recursively_verifiable.rs`, `cyclic.rs`, `dummy.rs`, `wrapper.rs` | Fixed VKs, cyclic suffix/cap binding, conditional dummy verification and public-input propagation; known C01 consumer remains separate |
| `hash_chain/{mod,hash_inner_circuit,cyclic_chain_circuit,chain_end_circuit,hash_chain_processor}.rs` | Previous-hash linkage, zero genesis, cyclic termination, parser/prover error boundaries: UTILS-04 |
| `logic.rs` | Conditional Boolean operations, selector preconditions and current callers; no additional constraint omission established |
| `mle_prover.rs` | VK/config binding, proof/export views, wire-v3 validation, gate support, config publication/cutover; test limitations below |
| `serialize.rs`, `serializer.rs`, `error.rs`, `hash_chain/error.rs`, `trees/error.rs`, both utility/tree `mod.rs` | Serializer gate mappings, error propagation and exported API wiring; no additional independent finding established |

## Validation and evidence

- `cargo test --offline --release --locked --lib utils:: -- --test-threads=1`: **70 passed, 0 failed**, including current wire-v3 MLE export checks, config publication/cutover tests, native/circuit tree tests, and duplicate indexed-insertion rejection.
- The isolated `utils-boundary-audit` fixture completed successfully and reproduced native index aliasing, uncommitted sparse entries, indexed-tree sentinel omission, and noncanonical Poseidon representations. The small representation circuit proof verified. Passing this diagnostic confirms the defects; it is not a security pass.
- Three separate bounded decoder probes — incremental tree, real ChannelSnapshot type, and chain-end public inputs — each terminated with **SIGABRT / return code -6**, as expected from the identified assertions.
- `cargo test --offline --release --locked --test mle_gate_support -- --test-threads=1`: **6 passed, 12 failed**. The failed tests expect legacy top-level `gates`/`whirParams`. All 58 JSON files inspected in `contracts/test/data` lack those legacy top-level fields, and `withdrawal_claim_mle.json` uses `plonky2-mle-v3-solidity`. Three tests fail their minimum-fixture count and nine fail while reading the missing top-level array. This is a stale integration-test/schema mismatch, not twelve demonstrated verifier defects. Those fixture-dependent checks remain unverified by that suite and should be migrated to the current schema.
- The Ext3 evaluator source's dispatched gate IDs were separately checked against the current utility constant: both contain **0 through 13**. This checks supported IDs, not every gate equation or deployed bytecode.

Evidence is in [utils-review-20261017](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/utils-review-20261017/): exact source hashes, baseline metadata, isolated fixture and lockfile, test logs, subprocess results, and MLE schema/gate context. No service was attacked, no production invalid proof was submitted, and no source repair or deployment change was made. Existing unrelated working-tree changes were preserved.
