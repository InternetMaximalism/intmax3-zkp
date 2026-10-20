# Common Types and Gadgets: Soundness Review

**Review date:** 17 October 2026  
**Repository / branch:** intmax3-zkp / main  
**HEAD:** `0a2f5a284c0ae6cf6d23e53b810240151e696724`

## Assessment

The review found **one previously documented P1 circuit-comparison defect at HEAD, already repaired in the local working tree**, and **six additional API/correctness findings**: three P2 and three P3. The latter concern integer decoding, native/circuit consistency, valid-message decoding, panic behavior, and state mutation on error. They are not six demonstrated proof-forgery vulnerabilities.

No additional end-to-end acceptance of an invalid production proof was demonstrated. This does not establish that the complete protocol is sound: the findings in the earlier cryptographic reviews remain separate and unresolved unless their reports say otherwise.

All 27 Rust files under `src/common/` were examined (9,903 lines including comments and tests), with selected callers and tree utilities inspected to determine whether checks occur elsewhere. Remote `main` was checked read-only and matched HEAD. The only pre-existing modification inside this scope was `u63.rs`; Cargo manifests, the lockfile, and dependencies also have pre-existing local changes. Runtime results therefore describe the working tree, not an untouched checkout of HEAD. No product code was changed during this review.

## Findings

| ID | Priority | Finding | Status / reachability |
| --- | --- | --- | --- |
| COMMON-01 | P1 | Modular subtraction is not a sound 63-bit ordering test | Known HEAD defect; pre-existing local fix; production gadgets call these methods |
| COMMON-02 | P2 | Derived `U63` deserialization bypasses the 63-bit invariant | Open public API defect; inconsistent encodings reproduced |
| COMMON-03 | P2 | Transaction array decoders silently discard high bits | Open decoder defect; production Tx nonce has an independent circuit range check |
| COMMON-04 | P2 | PublicState native and circuit empty leaves differ | Open generic tree API defect; current production insertion uses the correct native empty leaf explicitly |
| COMMON-05 | P3 | ChannelClose actions cannot round-trip through the numeric decoder | Open; no current production caller of this decoder identified |
| COMMON-06 | P3 | Withdrawal numeric decoder panics instead of returning an error | Open; examined production paths verify proofs before decoding |
| COMMON-07 | P3 | FullPublicState commits partial changes before rejecting an invalid channel ID | Open utility defect; current uses found only in tests |

Priorities reflect repair urgency and demonstrated reachability. P3 does not mean that silently changing the API contract is acceptable.

### COMMON-01 — U63 comparison at HEAD accepts the wrong integer ordering

**Locations:** [HEAD source snapshot](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/common-review-20261017/u63-at-head.rs.txt:225); [current comparator](/Users/andropov/repos/intmax3-zkp/src/common/u63.rs:224); [receive-deposit consumer](/Users/andropov/repos/intmax3-zkp/src/circuits/balance/receive_deposit_circuit.rs:312).

At HEAD, `enforce_ge` computes `a - b` in Goldilocks and range-checks the result to 63 bits. This does not imply integer `a >= b`. With `p = 2^64 - 2^32 + 1`, `a = 0`, and `b = 2^63 - 1`, the field difference is `2^63 - 2^32 + 2`, which passes the 63-bit check even though the requested ordering is false. Both operands are legitimate 63-bit integers. Strict comparison and enabled conditional comparison inherit the defect.

These methods constrain block ordering in send, receive-deposit, and receive-transfer circuits. Their relation is unsound independently of honest witness generation. A complete production exploit additionally needs authenticated states and the other constraints to admit the required values; this review does not claim that such a history or asset-loss proof was constructed.

This issue was already documented in [the earlier ordering evidence](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/u63-ordering-repair/review.json). Its metadata records successful component proof verification for all four incorrect comparisons. That evidence was inspected, not rerun against a reverted checkout here. The current working tree already replaces subtraction with a bitwise comparison of canonical 63-bit decompositions and masks disabled conditional operands before decomposition. This review preserved that change and reran the existing regression.

**Action:** retain and integrate the local repair, then handle the resulting circuit/verifier-key changes consistently. A regression pass against the working tree does not prove that deployed verifiers use the repaired relation.

### COMMON-02 — U63 deserialization can construct values the constructor rejects

**Locations:** [derived Deserialize](/Users/andropov/repos/intmax3-zkp/src/common/u63.rs:32), [constructor](/Users/andropov/repos/intmax3-zkp/src/common/u63.rs:38), [high-word masking](/Users/andropov/repos/intmax3-zkp/src/common/u63.rs:63).

`U63` derives `Deserialize` directly over its inner `u64`. Deserialization does not call `U63::new`, so JSON `9223372036854775808` produces a `U63` even though `U63::new(1 << 63)` rejects it. The decoded object's `as_u64()` preserves `2^63`, while `to_u32_vec()` produces `[0, 0]` because `high()` masks off bit 63. Zero and the invalid value therefore share one encoding but differ in another.

This breaks a common type invariant relied on by block numbers, deposit indices, and send/channel leaves. It creates native/serialization disagreement before any circuit is built. The public-input parser for `PublicState` does call the checked constructor, and relevant checked circuit paths constrain the width; no bypass of those checks was established. In particular, this finding is separate from the comparator defect above.

**Evidence:** the boundary fixture asserts constructor rejection, successful serde decoding, and the zero-word encoding alias.

**Correction:** implement checked deserialization through `U63::new`, preserving the established wire representation. Cover both JSON and the binary serde formats used by the application, including `2^63 - 1`, `2^63`, and `u64::MAX`.

### COMMON-03 — Tx, TxV2, and ChannelAction numeric decoders accept noncanonical integers

**Locations:** [Tx nonce](/Users/andropov/repos/intmax3-zkp/src/common/tx.rs:63), [ChannelAction kind](/Users/andropov/repos/intmax3-zkp/src/common/tx.rs:280), [TxV2 class and nonce](/Users/andropov/repos/intmax3-zkp/src/common/tx.rs:445).

`Tx::from_u64_slice` narrows its nonce with `as u32`. `TxV2::from_u64_slice` does the same for its class and nonce; `ChannelAction::from_u64_slice` narrows its kind before enum validation. A word equal to `2^32` becomes zero. Thus an out-of-range class or kind is accepted as a legitimate enum variant, and distinct numeric arrays decode to the same transaction.

The boundary fixture reproduces these aliases with otherwise ordinary zero/default data and valid channel IDs. This is a decoder canonicality defect, not evidence of a hash collision or a production signature forgery. The current Spend circuit [range-checks the nonce to 32 bits](/Users/andropov/repos/intmax3-zkp/src/circuits/balance/spend_circuit.rs:265), so its verified output cannot contain the illustrated nonce. Searches found only test callers of the TxV2 and ChannelAction numeric decoders.

**Correction:** use fallible `u32::try_from` before enum conversion and nonce construction; reject rather than normalize out-of-range words. Keep exact length checks. Parsing already verified, range-constrained public inputs may be safe at a caller, but it should not silently weaken an exported general decoder.

### COMMON-04 — PublicState uses different empty leaves in native and circuit Merkle trees

**Locations:** [native empty leaf](/Users/andropov/repos/intmax3-zkp/src/common/public_state.rs:168), [target empty leaf](/Users/andropov/repos/intmax3-zkp/src/common/public_state.rs:375), [generic circuit padding](/Users/andropov/repos/intmax3-zkp/src/utils/trees/get_root.rs:52).

The native `Leafable::empty_leaf` sets all three roots to zero. The target implementation instead embeds `PublicState::default()`, whose roots are initialized Channel, Deposit, and PublicState Merkle roots. These are different leaves and have different hashes.

The generic padded tree builder uses the target empty leaf when padding the supplied leaves to their next power of two. Three identical PublicState leaves in a height-two tree therefore yield different native and circuit roots. The boundary fixture computes both roots and verifies the ordinary circuit proof; the mismatch is in what the two implementations compute. No forged proof is needed to exhibit it.

The current [block-step insertion](/Users/andropov/repos/intmax3-zkp/src/circuits/validity/block_hash_chain/block_step.rs:676) explicitly creates a target from `PublicState::empty_leaf()`, avoiding this mismatch. No current production instantiation of the generic padded builder with PublicStateTarget was found. The demonstrated impact is incorrect roots and failure to interoperate when this exported implementation is used, rather than a currently demonstrated production acceptance bypass.

**Correction:** implement the target empty leaf using `PublicState::empty_leaf()`. Add native/target consistency coverage for zero, one, three, and four leaves, including larger configured tree heights.

### COMMON-05 — A valid ChannelClose action fails numeric round-trip

**Locations:** [close action construction](/Users/andropov/repos/intmax3-zkp/src/common/channel_message.rs:115), [destination decoding](/Users/andropov/repos/intmax3-zkp/src/common/tx.rs:287).

`to_channel_close_action` intentionally writes `ChannelId::dummy()` (zero) as the destination. `ChannelAction::from_u64_slice` always calls the nonzero `ChannelId::from_u64` constructor on that destination. Consequently, encoding an ordinary close action and immediately decoding it returns an error. Existing round-trip tests use nonzero source and destination IDs and miss this case.

The fixture reproduces the failure with the exact field shape emitted by the close-action constructor. No current production use of this numeric decoder was identified; JSON serde and direct circuit construction are different paths.

**Correction:** validate destination semantics by action kind, accepting the zero sentinel where the protocol requires it. Do not globally weaken real-channel ID validation. This codec correction should not change co-signer membership or post-deployment delegate joining policy.

### COMMON-06 — Withdrawal's Result-returning decoder panics on oversized limbs

**Location:** [Withdrawal::from_u64_slice](/Users/andropov/repos/intmax3-zkp/src/common/withdrawal.rs:86).

Each input word is asserted to fit in 32 bits before the length-checked `from_u32_slice` parser runs. An oversized word therefore panics instead of returning `CommonError`; even an otherwise wrong-length array can trigger the assertion first. In a process built with panic-abort this can terminate the process.

The independent fixture invocation passes a single oversized word to this API and records its exit status. This establishes an exported parser failure, not remote denial of service in the deployed service. The inspected [withdrawal-step path](/Users/andropov/repos/intmax3-zkp/src/circuits/withdraw/withdrawal_step.rs:246) verifies the single-withdrawal proof before extracting these fields, and the examined wallet flow also verifies its generated proof before decoding it.

**Correction:** check length and convert every limb fallibly, returning the declared error type. Keep callers' proof verification and circuit limb constraints.

### COMMON-07 — FullPublicState changes state even when add_block returns Err

**Location:** [mutations before channel-ID validation](/Users/andropov/repos/intmax3-zkp/src/common/public_state.rs:488).

`add_block_with_channel` pushes the previous public state, increments the block number, appends the new block, and updates the hash chain before validating the channel ID in its nonzero-key loop. For channel zero with a nonzero key ID, that validation returns an error after the earlier mutations have happened. The channel/send trees have not been updated consistently with the accepted-looking block history.

The fixture starts with `FullPublicState::new(&[1])`, calls the method with channel zero and key ID one, and confirms both `Err` and a changed public state / appended block. A caller that retries or continues after the error now operates on partially advanced state. Repository searches found current instantiations only in the helper's own tests, so this is classified as a utility defect.

**Correction:** validate every fallible input and next counter value before mutation, or build a candidate update and commit it atomically after success. Preserve intentionally permitted dummy/padding semantics explicitly.

## Additional observations and existing findings

- `BalanceState::apply_token_register` increments `state_version` without `checked_add`; `token_register_next_state` similarly increments `epoch`. Related native transition verification also uses ordinary `+ 1`. At the integer maximum these can wrap in release builds or panic with overflow checks. A reachable authenticated maximum-counter history was not established, so this is a boundary-hardening observation, not an additional practical forgery claim. Compute checked next values before mutation.
- Some channel signing/hash helpers invoke Regev ciphertext digests directly. Malformed ciphertexts reaching digest computation before validation are already covered by **C04** of the earlier consolidated review; this is not counted again as a new common-module finding.
- Constructors named `new(..., is_checked)` and several target containers intentionally permit unchecked intermediate values. A missing local range check is not sufficient on its own to establish soundness failure. The examined Spend/transfer and withdrawal consumers impose relevant nonce, index, limb, and proof constraints elsewhere.
- `ChannelId` supports a zero dummy sentinel in some structures. Replacing every zero with an error would break valid protocol representations; validation must distinguish active channel identity from padding and close destinations.
- Structural signature-list validation in common types is not itself cryptographic signature verification. The callers and proof consumers must authenticate those signatures. No new missing signature constraint was established in this module review; the earlier cyclic verification-key finding remains independently relevant.

## Coverage

| Files under src/common | Main checks and result |
| --- | --- |
| `u63.rs` | Bounds, serde, field encoding, all four order comparisons, conditional behavior: COMMON-01 and 02 |
| `tx.rs`, `withdrawal.rs` | Numeric codecs, enum bounds, nonce and limb widths, native/target layout: COMMON-03, 05, 06 |
| `public_state.rs` | Native/target hashes, empty leaves, state application and failure handling: COMMON-04 and 07 |
| `balance_state.rs` | Header/slot commitments, fixed-width token matrices, registry uniqueness/padding, ciphertext canonicality, active participant ranges, recipients, addition budgets; counter observation above |
| `channel.rs` | Signing preimages, state linkage, transfer identities, proof/blob encoding, close/state builders and structural signature checks; existing Regev digest-validation concern and counter observation above |
| `block.rs`, `channel_id.rs`, `channel_message.rs`, `channel_registration.rs` | Block/registration layouts, channel sentinel semantics, signed payload bindings, co-signer/delegate distinctions; no additional finding beyond the close-action codec issue |
| `deposit.rs`, `private_state.rs`, `salt.rs`, `transfer.rs` | Hash layouts, native/target consistency, numeric widths and caller constraints; no additional finding established |
| `trees/channel_tree.rs`, `trees/key_tree.rs`, `trees/nullifier_tree.rs`, `trees/tx_v2_tree.rs` | Leaf encodings, domain separation, membership/index use, native/target root derivation; no additional independent finding established |
| `trees/{asset,deposit,public_state,sent_tx,transfer,tx}_tree.rs`, both `mod.rs`, `error.rs` | Alias/type wiring, exported modules and error definitions; no additional independent finding established |

“No additional finding” means none was established in this review, not a formal proof of correctness. The caller tracing was targeted, and this was not a renewed audit of all circuits, contracts, clients, dependencies, or deployment state.

## Validation and evidence

- `cargo test --offline --release --locked --lib common:: -- --test-threads=1`: **75 passed, 0 failed** (18.40 seconds test runtime).
- `cargo test --offline --release --locked --test u63_ordering -- --test-threads=1`: **1 passed, 0 failed**; the existing test covers **144 comparison cases** across all four operations, including active out-of-range values and disabled branches. A direct execution of the same linked test also passed; it is not counted as additional coverage.
- The isolated `common-boundary-audit` fixture: **completed successfully**, confirming the five diagnostic groups for COMMON-02/03/04/05/07. Its PublicState circuit proof verified while its padded root differed from the native result. These assertions reproduce defects rather than certify correctness.
- The isolated Withdrawal invocation: **SIGABRT (subprocess return code -6)** at the oversized-limb assertion, confirming COMMON-06. It was run separately so the expected abort did not interrupt other checks.
- All report source links resolve; hashes of all 27 common source files were checked again after validation and remained unchanged.

The suites were run on the current locally modified dependency graph using the pinned nightly Rust toolchain. Full wallet/service flows, end-to-end exploit construction, deployment-key verification, fuzzing, and formal implementation proofs were not performed in this review.

The fixture, logs, source hashes, HEAD U63 snapshot, pre-existing U63 diff, and baseline metadata are saved in [the evidence directory](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/common-review-20261017/). The fixture has its own manifest and lockfile and uses the locally patched dependency graph. Build warnings already present in the repository were emitted. The two initial fixture setup attempts failed on workspace/lock resolution; adding an isolated workspace declaration and seeding its lockfile from the root resolved those setup issues without editing the root manifest.

The prior [consolidated cryptographic report](/Users/andropov/repos/intmax3-zkp/doc/audit/docs/consolidated-cryptographic-review-2026-10-16.md) remains unchanged. This document adds the common-module review and does not imply that prior findings have been repaired.
