# Ethereum Types Soundness Review

**Review date:** 17 October 2026  
**Repository / branch:** intmax3-zkp / main  
**Reviewed HEAD:** `0a2f5a284c0ae6cf6d23e53b810240151e696724`

## Assessment

This review identifies **two new findings: one P2 and one P3**, in `u256.rs` and `u32limb_trait.rs`. The P2 finding violates the BN254 field-target invariant and was reproduced in a circuit whose proof successfully verified. The P3 finding silently truncates oversized witness limbs during native extraction.

Neither affected conversion has a current call site in the searched application and test sources. Consequently, the demonstrated field-gadget inconsistency does **not establish an exploitable production proof-acceptance path**. No additional defect was established in the checked U64/U256 arithmetic, ordering, byte/bit encodings, or address decoding examined here.

All **eight Rust files under `src/ethereum_types/`**, totaling **2,036 lines including comments and tests**, were inspected. Local HEAD and remote `main` matched the commit above. Every file in this directory matched HEAD. Tests used the existing working tree, including pre-existing Cargo/dependency changes; those changes and all product sources were preserved. The audit added only this report and its evidence files.

## Findings

| ID | Priority | File | Finding | Demonstrated reachability |
| --- | --- | --- | --- | --- |
| ETH-01 | P2 | `u256.rs` | U256-to-Fq conversion falsely marks arbitrary U256 values as reduced modulo the BN254 base-field modulus | Verified standalone circuit proof; no current application caller found |
| ETH-02 | P3 | `u32limb_trait.rs` | `get_witness` silently narrows oversized field elements to u32 | Reproduced for all five implementing native types; no current caller found |

### ETH-01 — U256-to-Fq conversion violates canonical field representation

**Location:** [From<U256Target> for FqTarget](/Users/andropov/repos/intmax3-zkp/src/ethereum_types/u256.rs:153).

The conversion reverses the eight limbs and calls `FqTarget::from_slice`. In the pinned `plonky2_bn254` dependency, that constructor assumes the limbs are already range checked and reduced, and sets `mod_taken = true`. The local conversion neither enforces `value < q` nor requests modular reduction. A correctly range-checked U256 can still be greater than or equal to the BN254 base-field modulus:

```text
q = 21888242871839275222246405745257275088696311157297823662689037894645226208583
```

`FqTarget::take_mod` returns the object unchanged when this flag is true. Its equality and zero predicates consequently operate on a noncanonical representation, while an operation such as addition marks its output as requiring reduction. The resulting predicates depend on whether a mathematically neutral addition has occurred.

The fixture creates **checked, virtual U256 targets** for `q` and `q + 1`, converts them through the existing `From` implementation, and verifies a proof enforcing all these results:

| Input U256 | Expected field value | `is_valid()` | Equality to expected value immediately after conversion | Equality after adding field zero and reducing |
| --- | --- | --- | --- | --- |
| `q` | `0` | false | false | true |
| `q + 1` | `1` | false | false | true |

The input limbs and these predicate outputs are public inputs of the verified proof. This is a concrete violation of the field-conversion contract, even when every input limb is in range. Checking only 32-bit limb bounds therefore does not repair it.

**Impact and limits:** a consumer that relies on the conversion to produce a valid field element can obtain inconsistent equality/nonzero checks or reject legitimate field identities. An application exploit would require a caller relying on those predicates without its own canonicality check. Searches of `src/` and `tests/` found the conversion definition but no consumer; no production transaction, signature, or withdrawal bypass is claimed.

**Correction:** replace the implicit conversion with an explicit builder-taking operation whose semantics are either (a) constrain the integer to `0 <= x < q`, or (b) reduce it modulo `q`. Preserve or establish u32 limb bounds and only mark the output as reduced after that condition is enforced. An unreduced intermediate must retain `mod_taken = false`. Add regressions at `0`, `q - 1`, `q`, `q + 1`, and `2^256 - 1`, including equality and zero tests before and after neutral arithmetic.

**Supporting dependency code:** [from_slice](/Users/andropov/.cargo/git/checkouts/plonky2_bn254-6d6b3459202b0930/18044f3/src/fields/fq.rs:67), [take_mod](/Users/andropov/.cargo/git/checkouts/plonky2_bn254-6d6b3459202b0930/18044f3/src/fields/fq.rs:150), [add](/Users/andropov/.cargo/git/checkouts/plonky2_bn254-6d6b3459202b0930/18044f3/src/fields/fq.rs:158), [is_equal](/Users/andropov/.cargo/git/checkouts/plonky2_bn254-6d6b3459202b0930/18044f3/src/fields/fq.rs:188).

### ETH-02 — Witness extraction accepts truncated out-of-range limbs

**Location:** [U32LimbTargetTrait::get_witness](/Users/andropov/repos/intmax3-zkp/src/ethereum_types/u32limb_trait.rs:315), particularly the narrowing cast at line 322.

The method returns `Result<V>`, but converts each canonical field value with `as u32` before invoking `V::from_u32_slice`. All high bits have already been discarded by the time that constructor runs. Unlike [from_u64_slice](/Users/andropov/repos/intmax3-zkp/src/ethereum_types/u32limb_trait.rs:29), this path cannot return `OutOfU32Range` for an oversized limb.

For each of `Address`, `Bytes16`, `Bytes32`, `U64`, and `U256`, the fixture assigns an unchecked target the final limb `2^32 + 7` with all other limbs zero. `get_witness` returns `Ok` with final limb `7`. Calling the corresponding native `from_u64_slice` on the same words correctly returns an error.

**Impact and limits:** native witness extraction can misreport an unchecked or not-yet-validated witness as a different valid value. This does not remove constraints from a circuit: a verified witness for targets whose limbs were constrained to 32 bits cannot contain this oversized limb. No `get_witness` caller was found in `src/` or `tests/`; the finding is a dormant exported-helper correctness issue, rated P3 accordingly.

**Correction:** collect canonical u64 values and pass them to `V::from_u64_slice`, or use fallible u32 conversion and propagate `OutOfU32Range`. Retain the same checks for all implementing types. A successful extraction should preserve the witnessed value exactly.

## Coverage and constraint review

| File | Reviewed behavior | Assessment |
| --- | --- | --- |
| `address.rs` | Native hex/serde, fixed-width limb storage, target construction | No independent finding; shares ETH-02 through the trait |
| `bytes16.rs` | Hex/serde, BigUint conversions, byte/bit representation | No independent finding; oversized BigUint is rejected; shares ETH-02 |
| `bytes32.rs` | Hex/serde, U256 round trips, `remove_3bits` native/target agreement | No independent finding; shares ETH-02 |
| `u64.rs` | Full 64-bit storage, serde, arithmetic, ordering, BigUint target limb order | No independent finding; shares ETH-02 |
| `u256.rs` | Decimal/hex parsing, BigUint conversions, arithmetic, ordering, Fq conversion | ETH-01; also shares ETH-02 |
| `u32limb_trait.rs` | Numeric/byte/bit decoding, checked allocation, conditional operations, witness I/O | ETH-02 |
| `error.rs` | Error definitions and conversions | No independent finding |
| `mod.rs` | Exports and result alias | No independent finding |

The following properties were checked to distinguish defects from the APIs' intended contracts:

- **U64/U256 ordering uses bounded limbs.** Both `is_le` implementations reverse big-endian limbs before calling `list_le_circuit`, which processes little-endian limbs. The pinned comparison gate reconstructs each 32-bit input from sixteen two-bit chunks and constrains those chunks. The comparison itself therefore supplies input bounds, even when allocation omitted them. Strict comparison additionally excludes equality. This implementation does not use a single full-width modular subtraction like the previously reported U63 comparison issue.
- **Checked arithmetic rejects overflow and underflow.** Inputs must be range checked before add/sub; these operations do not independently validate every input limb. The invoked addition gate constrains the result and carry, subtraction constrains the result and Boolean borrow, and the wrappers connect the final carry/borrow to zero. With u32 operands, the local equations remain far below the Goldilocks modulus and cannot gain an alternative solution by field wraparound. Native operators also reject overflow/underflow by panicking. Their panic behavior is intentional checked-operator behavior; this review did not establish a new remotely reachable panic path through those operators.
- **Relevant production arithmetic allocates checked inputs.** [SpendTarget](/Users/andropov/repos/intmax3-zkp/src/circuits/balance/spend_circuit.rs:269) checks transfers and balances. Both [receive-deposit](/Users/andropov/repos/intmax3-zkp/src/circuits/balance/receive_deposit_circuit.rs:290) and [receive-transfer](/Users/andropov/repos/intmax3-zkp/src/circuits/balance/receive_transfer_circuit.rs:401) instantiate the shared private-state update with `is_checked = true`. Representative channel-close/version operands also use checked targets. The membership/delegate design note was read before inspecting these consumers; no membership-policy changes are proposed.
- **Numeric native decoding rejects oversized limbs.** `from_u64_slice` checks before narrowing. Private `[u32; N]` native storage and the explicit serde implementations preserve width. This differs from previously reported narrowing bugs in higher-level public-input parsers, which are not counted again here.
- **Byte/bit encoding is big endian and bounded.** Target byte decoding checks each byte to eight bits; target encoding decomposes each limb to 32 bits. Bit reconstruction assumes genuine Boolean targets, as do `select` and `mul_bool`. Passing an unconstrained `BoolTarget::new_unsafe` would violate that caller contract. Likewise, `new(..., false)` and `from_slice` intentionally leave range-check obligations to their consumers.
- **Short hex encodings are accepted intentionally.** Native byte/hex decoders left-pad short inputs, including empty hex as zero, and serialize fixed-width values. Existing tests explicitly require this behavior. Target byte/bit constructors require fixed-length input. U256's string parser additionally accepts hexadecimal, while its serde format is a decimal string; no authentication bypass was established from these format choices.
- **`remove_3bits` deliberately masks the high three bits.** Native and circuit behavior agreed at four high-limb boundaries. The withdrawal consumer applies it to a Keccak result. This explicit digest transformation is separate from accidental witness truncation in ETH-02.

## Validation and evidence

| Check | Result |
| --- | --- |
| Existing `ethereum_types::` release unit tests | **47 passed, 0 failed** |
| Native/circuit encoding probes | Three values each for five types; all proofs verified; malformed widths/limbs rejected by native decoders |
| ETH-01 reproduction | Proof verified for both `q` and `q + 1`, with inconsistent equality before/after adding zero |
| ETH-02 reproduction | Silent truncation reproduced for all five implementing types |
| U64 differential arithmetic/order | **100 boundary pairs**, both `<=` and `<`; 51 valid sums and 55 valid differences |
| U256 differential arithmetic/order | **144 boundary pairs**, both `<=` and `<`; 122 valid sums and 78 valid differences, compared against BigUint |
| Digest-mask agreement | Four boundary cases; native and target results match |
| Invalid-witness probes | **Eight rejected:** U64/U256 overflow and underflow, oversized limb, oversized byte, comparison with oversized limb, and incorrect comparison result |

The differential circuits use virtual checked input targets, so the arithmetic is not reduced to constant folding. U64 cases include `2^63`, the Goldilocks modulus, and `u64::MAX`; U256 cases exercise carries across multiple limbs and the high bit. For the negative probes, seven failed during witness generation with inconsistent assignments. The unchecked oversized comparison input produced a proof that **failed verification**. No negative probe was counted as a successful rejection based solely on a process crash. These tests complement the constraint inspection; they are not an exhaustive proof of soundness.

Reproduction commands from the repository root:

```sh
/Users/andropov/.cargo/bin/cargo test --offline --release --locked --lib ethereum_types:: -- --test-threads=1
CARGO_TARGET_DIR=/Users/andropov/repos/intmax3-zkp/target /Users/andropov/.cargo/bin/cargo run --offline --release --locked --manifest-path doc/audit/zkp/evidence/ethereum-types-review-20261017/fixture/Cargo.toml
python3 doc/audit/zkp/evidence/ethereum-types-review-20261017/run-rejection-probes.py
```

The fixture has its own manifest/lockfile and uses the existing repository path patches and cached dependencies. It requires the pinned nightly toolchain and the local paths recorded in its manifest. The audited dependency revisions are `plonky2_bn254` **`18044f3413fc799723f270a48b257094a105c5b1`**, `plonky2_u32` **`d0b3bfd904021b99bbec7f94c10ffe32b94aafac`**, and the local polygon-plonky2 submodule **`3a20a05fb99d2653c4d37debb4f1ead2f422dfb2`**.

Evidence is saved in [the audit evidence directory](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/ethereum-types-review-20261017): [baseline and eight source hashes](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/ethereum-types-review-20261017/baseline.json), [verification context and dependency-file hashes](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/ethereum-types-review-20261017/verification-context.json), [unit-test log](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/ethereum-types-review-20261017/unit-tests.log), [boundary fixture](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/ethereum-types-review-20261017/fixture/src/main.rs), [boundary results](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/ethereum-types-review-20261017/boundary-probes.log), [negative-probe results](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/ethereum-types-review-20261017/rejection-results.json), and [conversion call-site search](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/ethereum-types-review-20261017/conversion-callsite-search.txt).

This is a scoped implementation review, not a formal verification of the proof system or a fresh full audit of the external BN254/u32 crates. It supplements the earlier [common](/Users/andropov/repos/intmax3-zkp/doc/audit/docs/common-soundness-review-2026-10-17.md), [utils](/Users/andropov/repos/intmax3-zkp/doc/audit/docs/utils-soundness-review-2026-10-17.md), and [consolidated cryptographic](/Users/andropov/repos/intmax3-zkp/doc/audit/docs/consolidated-cryptographic-review-2026-10-16.md) reviews without changing their findings or remediation status. Production sources were not modified.
