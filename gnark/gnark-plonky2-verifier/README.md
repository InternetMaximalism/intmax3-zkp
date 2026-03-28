# Gnark Plonky2 Verifier (with Fraud Proof Support)

> **Fork of [succinctlabs/gnark-plonky2-verifier](https://github.com/succinctlabs/gnark-plonky2-verifier)** with fraud proof capability.

This is an implementation of a [Plonky2](https://github.com/mir-protocol/plonky2) verifier in Gnark (supports Groth16 and PLONK).

## Changes from Upstream

The upstream verifier uses `api.AssertIsEqual` internally, which makes the circuit **unsatisfiable** when an invalid Plonky2 proof is provided. This means a Groth16 proof can only be generated for **valid** Plonky2 proofs.

This fork adds a `VerifyAndReturnResult` method that replaces all internal assertions with soft checks (`api.IsEqual` + `api.And`), returning a boolean result (`1` = valid, `0` = invalid) instead of asserting. This keeps the circuit satisfiable regardless of the Plonky2 proof's validity, enabling two use cases:

- **Validity proof** (`result == 1`): Proves that a Plonky2 proof is correct (same as upstream).
- **Fraud proof** (`result == 0`): Proves that a Plonky2 proof is **incorrect** — the circuit is still satisfiable, so a Groth16 proof can be generated.

### Modified / Added Files

| File | Description |
|---|---|
| `verifier/verifier.go` | Added `VerifyAndReturnResult()` — top-level non-asserting verification |
| `verifier/util.go` | Added `AssertHashEqual` / `IsHashEqual` helpers for hash comparison |
| `plonk/plonk.go` | Added `VerifyAndReturnResult()` — PLONK constraint check returning boolean |
| `fri/fri.go` | Added `VerifyFriProofAndReturnResult()` and non-asserting variants of FRI verification (Merkle cap checks, query round checks, final polynomial check) |
| `goldilocks/base.go` | Added `IsEqual` for Goldilocks field elements |
| `goldilocks/quadratic_extension.go` | Added `IsEqualExtension` for quadratic extension field elements |

### How It Works

The wrapper circuit can use `VerifyAndReturnResult` to constrain the expected outcome:

```go
func (c *FraudAwareVerifierCircuit) Define(api frontend.API) error {
    api.AssertIsBoolean(c.ExpectedResult)

    verifierChip := verifier.NewVerifierChip(api, c.CommonCircuitData)
    result := verifierChip.VerifyAndReturnResult(
        c.Proof, c.PublicInputs, c.VerifierOnlyCircuitData,
    )

    // Core constraint: actual verification result == expected result
    api.AssertIsEqual(result, c.ExpectedResult)
    return nil
}
```

- `ExpectedResult = 1` + valid proof → Groth16 proof generated (validity proof)
- `ExpectedResult = 0` + invalid proof → Groth16 proof generated (fraud proof)
- Mismatched expectation → circuit unsatisfiable, no Groth16 proof generated

### Backward Compatibility

The original `Verify()` method is preserved and unchanged. Existing code that does not need fraud proof support can continue using it without modification.

## Requirements

- [Go (1.19+)](https://go.dev/doc/install)

## Benchmark

To run the benchmark,
```
go run benchmark.go
```

## Profiling

First run the benchmark with profiling turned on
```
go run benchmark.go -profile
```

Then use the following command to generate a visualization of the pprof
```
go tool pprof --png gnark.pprof > verifier.png
```