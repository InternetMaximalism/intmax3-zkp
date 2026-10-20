# Consolidated Follow-Up Review Report

**Compilation date:** 19 October 2026  
**Source report date:** 17 October 2026  
**Repository:** intmax3-zkp  
**Revision recorded by all three source reports:** `0a2f5a284c0ae6cf6d23e53b810240151e696724` (`main`)

## Purpose and scope

This document consolidates the completed reports beginning with the request to review `src/common/`. It is an editorial summary of those reports. No additional source-code investigation, testing, exploit development, remediation, or verification of present-day status was performed to prepare this compilation. Priorities, evidence, reachability limits, and repair status are carried forward from the original reports.

The completed source reports are:

| Source | Reported coverage | Original report |
| --- | --- | --- |
| `src/common/` | 27 Rust files; 9,903 lines including comments and tests | [Common Types and Gadgets: Soundness Review](/Users/andropov/repos/intmax3-zkp/doc/audit/docs/common-soundness-review-2026-10-17.md) |
| `src/utils/` | 30 Rust files; 7,549 lines including comments and tests | [Utilities Soundness Review](/Users/andropov/repos/intmax3-zkp/doc/audit/docs/utils-soundness-review-2026-10-17.md) |
| `src/ethereum_types/` | Eight Rust files; 2,036 lines including comments and tests | [Ethereum Types Soundness Review](/Users/andropov/repos/intmax3-zkp/doc/audit/docs/ethereum-types-soundness-review-2026-10-17.md) |

The combined reported coverage is **65 Rust files and 19,488 lines**. The original reports also describe targeted inspection of callers and dependencies; those additional files are not included in this total.

Later requests concerning `src/wallet_core.rs`, `src/regev/hash_sig.rs`, `src/constants.rs`, and `src/lib.rs` had not produced a completed written report before this compilation. Their status is recorded below. Preliminary concerns raised in progress messages are excluded from the findings register.

The earlier [Consolidated Cryptographic Review of 16 October](/Users/andropov/repos/intmax3-zkp/doc/audit/docs/consolidated-cryptographic-review-2026-10-16.md) predates the requested starting point. It is referenced only where the later reports identify an existing issue or a duplicate; its findings are not added to the totals here.

## Summary of reported findings

The three completed reports contain **13 finding records: one P1, seven P2, and five P3**. Of these, **COMMON-01 was an already documented issue with a pre-existing local repair**. The other **12 findings were reported as additional open issues**: seven P2 and five P3. These are historical statuses from the source reports, not a new assessment of whether subsequent changes have resolved them.

The reports distinguish circuit-relation defects, native representation inconsistencies, decoding failures, and utility API errors. They do not present the 13 records as 13 demonstrated production proof forgeries. None of these completed reports established an additional end-to-end production proof-forgery path.

| ID | Priority | Reported finding | Status and principal limitation in the source report |
| --- | --- | --- | --- |
| COMMON-01 | P1 | U63 modular subtraction accepts incorrect integer ordering | Known defect at the recorded HEAD; local repair already existed and its regression passed; deployment integration was not established |
| COMMON-02 | P2 | U63 deserialization bypasses the 63-bit invariant | Invalid values and inconsistent encodings reproduced; relevant checked parsers/circuits provide independent bounds |
| COMMON-03 | P2 | Transaction numeric decoders discard high bits | Decoder aliases reproduced; production Tx nonce has an independent circuit range check |
| COMMON-04 | P2 | PublicState native and target empty leaves differ | Generic padded-tree root mismatch reproduced; inspected production insertion uses the correct native empty leaf explicitly |
| COMMON-05 | P3 | ChannelClose numeric encoding cannot round-trip | Valid close-action decode fails; no production use of the affected numeric decoder identified |
| COMMON-06 | P3 | Withdrawal numeric decoder panics on oversized limbs | Isolated abort reproduced; examined production paths verify proofs before decoding |
| COMMON-07 | P3 | FullPublicState changes state before returning an error | Partial mutation reproduced; uses identified only in tests |
| UTILS-01 | P2 | Tree deserialization can abort before authentication | Abort reproduced through the actual ChannelSnapshot type; import/command paths decode before verification |
| UTILS-02 | P2 | Native Merkle APIs accept out-of-range indices | Proof-index alias and sparse storage/root inconsistency reproduced; corresponding fixed-height circuit constrains the index |
| UTILS-03 | P2 | Numeric PoseidonHashOut construction accepts noncanonical limbs | Distinct native representations collapse to the same field values; no authentication bypass through the checked conversion path established |
| UTILS-04 | P3 | Hash-chain APIs panic instead of returning declared errors | Chain-end parser abort reproduced; generic processor failure paths source-confirmed; no active production caller identified |
| ETH-01 | P2 | U256-to-Fq conversion incorrectly marks values as reduced | Field-predicate inconsistency reproduced in a verified standalone circuit proof; no application caller identified |
| ETH-02 | P3 | Witness extraction silently truncates oversized limbs | Reproduced for all five implementing types; no caller identified and checked circuit bounds remain effective |

## Consolidated finding details

### COMMON-01 — Incorrect U63 ordering at the recorded HEAD

The original comparator implemented integer ordering by subtracting in the Goldilocks field and checking that the result fit in 63 bits. The common report records that `a = 0` and `b = 2^63 - 1` satisfy the resulting constraint despite the requested ordering being false. Strict and enabled conditional comparisons share the problem.

The report identifies production gadget consumers, while limiting its claim to the defective relation rather than a constructed production asset-loss history. Earlier evidence already documented successful component proofs for the incorrect comparisons. A bitwise comparator repair was present in the working tree before the review, and the existing regression passed. The reported action was to retain and integrate that repair and account for circuit/verifier-key changes. Integration into deployed verifiers was not established.

### COMMON-02 — U63 decoding bypasses constructor validation

Derived deserialization accepts `2^63`, although the checked constructor rejects it. The accepted object's scalar accessor preserves that value, while its masked high-word encoding produces the same words as zero. The report treats this as a native type-invariant and encoding defect.

The checked PublicState numeric parser and relevant circuit paths impose independent bounds. The reported correction was checked deserialization through the constructor while preserving the established wire format.

### COMMON-03 — Transaction numeric decoding narrows silently

The numeric decoders for Tx, TxV2, and ChannelAction use narrowing casts for nonce, class, or kind words. A word equal to `2^32` becomes zero, allowing distinct arrays to decode to the same transaction or enum variant.

The report reproduced the aliases and noted that the production Spend circuit independently constrains its nonce. Only test callers were found for the affected TxV2 and ChannelAction numeric decoders. Its correction was fallible integer conversion before enum or nonce construction.

### COMMON-04 — PublicState empty leaves disagree

The native empty leaf uses zero roots, whereas the target implementation embeds a default state with initialized tree roots. The report reproduced different roots when padding three PublicState leaves to a height-two tree, and verified the circuit proof computing the target result.

The inspected block-step insertion explicitly uses the native empty leaf and avoids the mismatch. No production use of the affected generic padded-tree combination was found. The reported correction was to make the target empty leaf use the same native empty value.

### COMMON-05 — Valid close actions fail numeric round-trip

A ChannelClose action intentionally uses the zero dummy destination. Its numeric decoder always invokes the nonzero channel-ID constructor, so a valid encoded close action fails to decode.

No production use of that numeric decoder was identified. The report recommends validating destination rules according to action kind, retaining the zero sentinel where required and preserving validation of actual channel identities. It does not propose a membership-policy change.

### COMMON-06 — Withdrawal decoding can terminate the process

The Result-returning numeric parser asserts that words fit in 32 bits. An oversized word panics rather than returning its declared error, including before an incorrect overall length is rejected. A separate release subprocess terminated with SIGABRT.

The report did not establish a remotely reachable production denial of service through this API. Examined production consumers verified proofs before decoding. Its correction was to check length and convert limbs fallibly while retaining caller-side proof verification.

### COMMON-07 — Failed block application leaves partial state

FullPublicState updates history, counters, and its hash chain before validating a channel ID in the nonzero-key path. The report reproduced a call that returned an error while leaving the public state changed and a block appended.

Current uses found during that review were confined to tests. The reported correction was validation before mutation, or committing a candidate update only after all fallible work succeeds.

### UTILS-01 — Tree decoding can abort before snapshot verification

Incremental tree deserialization reconstructs leaves through capacity-checked pushes without first validating the supplied height and leaf count. The report reproduced a panic using a height-zero tree with two leaves, including as the `settledTxAccumulator` field of the actual ChannelSnapshot type. Both isolated release processes aborted.

The source report identified wallet import and block-producer command paths that decode the snapshot before authentication. It did not send a request to a live service, and external exposure depends on access controls. It also reproduced indexed-tree decoding that omits the constructor's sentinel leaf. The reported correction was fallible validation of height, capacity, required sentinel, and application-specific tree invariants before reconstruction.

### UTILS-02 — Native Merkle index domains are inconsistent

Native verification consumes only as many index bits as there are siblings. A height-two proof therefore verified at both index zero and index four. Sparse storage accepted index four and stored a retrievable leaf without changing the actual root; serialization preserved that inconsistency.

The fixed-height target implementation constrains the index width, and some native production callers independently validate the bound. The report therefore limits the finding to the reusable native API and storage invariant. Its correction was to reject out-of-range indices consistently, before mutation, rather than mask their high bits.

### UTILS-03 — Noncanonical Poseidon representations are accepted

The numeric constructor accepts a word equal to the Goldilocks modulus. That native object differs from zero, while later release field conversion interprets it as zero. The report reproduced equal hashes, zero canonical public inputs in a verified small circuit, and an object whose successful JSON serialization could not be decoded by its stricter deserializer.

The report describes a representation alias and does not claim a break of the hash function. Checked Bytes32 conversion and canonical verified public inputs retain their protections. The reported correction was to enforce canonical field bounds at checked numeric construction and distinguish intentional reduction from injective integer encoding.

### UTILS-04 — Hash-chain error APIs contain panic paths

The chain-end numeric parser aborts on a correctly sized input containing an oversized limb. The report reproduced this in a subprocess. The generic chain processor also slices and unwraps previous-proof fields before validating their shape; those paths were identified from source and were not separately exercised with a chain circuit.

No active production callers of these affected generic APIs were found. The similarly named production block hash-chain processor is a different implementation. The reported correction was fallible shape/range validation and error propagation at the relevant trust boundary.

### ETH-01 — U256 conversion violates the Fq representation contract

The conversion invokes a dependency constructor that marks its input as already reduced modulo the BN254 base-field modulus. A range-checked U256 need not be below that modulus.

The report verified a standalone circuit proof for inputs `q` and `q + 1`. Immediately after conversion, they failed equality to their expected field values zero and one; after adding field zero and reducing, equality succeeded. All integer limbs were valid u32 values. No application caller of the conversion was found, and no production transaction or withdrawal bypass was established. The reported correction was an explicit conversion that either enforces the canonical range or performs modular reduction before marking the result reduced.

### ETH-02 — Witness extraction discards high bits

The shared `get_witness` implementation narrows canonical field values to u32 before the native constructor can reject oversized limbs. The report reproduced `2^32 + 7` becoming `Ok(7)` for Address, Bytes16, Bytes32, U64, and U256. The corresponding native u64-slice constructor rejected the same input.

No caller was found. A verified witness for targets already constrained to 32 bits cannot contain the illustrated oversized limb. The report rates this as a dormant exported-helper correctness issue and recommends fallible conversion or reuse of the checked u64-slice constructor.

## Deduplication and additional observations

The original identifiers are retained for traceability. The reports already grouped related instances and distinguished findings from observations:

- The proof-index alias and sparse-tree root inconsistency remain one record, UTILS-02, because they share the missing index-domain invariant.
- The PublicState padding mismatch remains COMMON-04. Its appearance at the generic utility builder is not counted again.
- ETH-02 affects five implementing types but remains one shared-trait finding.
- The previously reported Regev digest-before-validation problem and cyclic verification-key binding problem remain references to the earlier cryptographic report. They are not additional entries in this compilation.

The common report separately notes unchecked maximum-counter increments without establishing a reachable authenticated maximum-counter history. The utils report notes an intentional noncanonical empty-leaf value that violates a field-conversion precondition, and mutation-before-panic ordering in tree operations without an unwind-build reproduction. Those observations retain their original qualification and are not added to the prioritized finding count.

The reports also record caller contracts that matter to their conclusions: unchecked target allocation requires later constraints; selector helpers require Boolean/one-hot inputs; proof helpers require the appropriate ordinary or cyclic binding; and low-level MLE verification requires a trusted verification key. They did not establish additional defects where the examined callers met those contracts.

## Previously reported validation results

All results below were recorded during the earlier reviews. Nothing was rerun for this compilation.

| Report / check | Recorded result |
| --- | --- |
| Common release unit suite | 75 passed, zero failed |
| Existing U63 ordering regression | One test passed, covering 144 comparison cases |
| Common boundary fixture | Five diagnostic groups completed, reproducing COMMON-02/03/04/05/07; the PublicState circuit proof verified with the differing padded root |
| Withdrawal decoder subprocess | SIGABRT, confirming COMMON-06 |
| Utils release unit suite | 70 passed, zero failed |
| Utils boundary fixture | Reproduced index aliasing, sparse root inconsistency, missing indexed sentinel, and noncanonical Poseidon representations; the representation circuit proof verified |
| Utils decoder subprocesses | Three SIGABRT outcomes: incremental tree, actual ChannelSnapshot type, and chain-end parser |
| MLE gate-support integration suite | Six passed, 12 failed; the report attributes failures to tests expecting legacy top-level fixture fields rather than the current wire-v3 schema |
| Ethereum-types release unit suite | 47 passed, zero failed |
| Ethereum-types encoding probes | Three values for each of five types; native/target round-trips completed and malformed native inputs were rejected |
| Ethereum-types arithmetic/order probes | 100 U64 boundary pairs and 144 U256 boundary pairs; recorded valid arithmetic results agreed |
| Ethereum-types invalid-witness probes | Eight rejected; seven during witness generation and one at proof verification |
| Ethereum-types defect probes | ETH-01 verified in a standalone proof; ETH-02 reproduced for all five native types |

The MLE suite's 12 failures were not reported as 12 verifier vulnerabilities. Its fixture-dependent checks remained unverified by that suite. Passing ordinary tests and successfully reproducing a defect are also different outcomes; neither is a general certification of the protocol.

## Status of subsequent requests

The subsequent wallet/hash-signature/constants/library requests had no completed report to consolidate. An interim message recorded 20 passing hash-signature tests. That progress result does not establish a completed audit of `src/regev/hash_sig.rs`. No completed wallet test-suite result or finalized finding set was reported.

Accordingly, this compilation makes no final soundness determination for `src/wallet_core.rs`, `src/regev/hash_sig.rs`, `src/constants.rs`, or `src/lib.rs`. Preliminary concerns mentioned while those reviews were in progress are not treated as confirmed findings. Further investigative work was stopped at the user's request; this document only summarizes the existing reports and reported progress.

## Historical baseline and evidence references

All three completed reports recorded the same main-branch revision. They used a working tree with pre-existing Cargo/dependency changes and unrelated modifications. The common scope additionally contained a pre-existing U63 repair. The original reviews reported that they preserved those changes and did not modify product code. This compilation likewise changes only documentation and makes no claim about subsequent remediation or deployed verifier versions.

The original reports remain the source of detailed locations, reproduction procedures, evidence descriptions, and limitations:

- [Common report](/Users/andropov/repos/intmax3-zkp/doc/audit/docs/common-soundness-review-2026-10-17.md) and [its evidence directory](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/common-review-20261017/).
- [Utils report](/Users/andropov/repos/intmax3-zkp/doc/audit/docs/utils-soundness-review-2026-10-17.md) and [its evidence directory](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/utils-review-20261017/).
- [Ethereum-types report](/Users/andropov/repos/intmax3-zkp/doc/audit/docs/ethereum-types-soundness-review-2026-10-17.md) and [its evidence directory](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/ethereum-types-review-20261017/).
