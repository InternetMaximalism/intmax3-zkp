# Fraud Proof Architecture — WHIR-only Design

## Overview

INTMAX3 uses a **dual verification** architecture for finalize and a **WHIR-only** architecture for fraud proofs:

- **`finalize()`**: WHIR + Groth16 (both must pass)
- **`fraudProof()`**: WHIR-only (no Groth16)

## Why Groth16 Is Not Used for Fraud Proofs

### The Goldilocks Hard Constraint Problem

The gnark-plonky2-verifier's `FraudAwareVerifierCircuit` uses `VerifyAndReturnResult()`, which softens the final PLONK/FRI comparison checks (using `api.IsEqual` instead of `api.AssertIsEqual`). However, the underlying **Goldilocks field arithmetic** (`MulAdd`, `Reduce`, `RangeCheck`, etc. in `goldilocks/base.go`) retains hard constraints (`api.AssertIsEqual`).

This means:
- **Valid proof + ExpectedResult=1** → circuit satisfiable → Groth16 proof generated ✓
- **Valid proof + ExpectedResult=0** → `AssertIsEqual(1, 0)` fires → unsatisfiable ✓ (security property)
- **Corrupted proof + ExpectedResult=0** → Goldilocks arithmetic hard constraints fire → unsatisfiable ✗

The third case means it's impossible to generate a Groth16 proof for corrupted Plonky2 data, regardless of `ExpectedResult`.

### Why This Is Actually a Security Feature

The fact that `ExpectedResult=0` cannot be generated for a valid proof is a **strong security property**: it is cryptographically impossible for anyone to create a Groth16 proof claiming a valid Plonky2 proof is invalid.

### WHIR-Only Fraud Detection

Fraud is detected on-chain via the WHIR verification pipeline alone:

```
fraudProof() → _verifyWhirOnly():

  Binding checks (must ALL pass):
    1. Commitment check (blobHash + proofHash + proofLength + stateRoot)
    2. KZG blob binding (calldata bytes match blob content)
    3. PI binding (validityPIs match on-chain state)

  WHIR checks (must FAIL for fraud to be confirmed):
    4. Plonky2 PI hash == WHIR statement.evaluations[0]
    5. WHIR proof verification

  Fraud confirmed iff: all bindings pass AND WHIR verification fails
```

If the Plonky2 proof in the blob is invalid:
- The PI hash won't match WHIR statement.evaluations[0] (step 4 fails), OR
- The WHIR verification itself will fail (step 5 fails)

Either way, fraud is detected without Groth16.

## Finalize Pipeline

```
finalize() → _fullVerify():

  Binding checks (must ALL pass):
    1. Commitment check
    2. KZG blob binding
    3. PI binding to on-chain state

  Proof validity checks (must ALL pass):
    4. Plonky2 PI hash == WHIR statement.evaluations[0]
    5. WHIR proof verification
    6. Groth16 verification (ExpectedResult must be 1)

  Returns true only if ALL steps pass.
```

## Verified Security Properties

### Tested (see `test_groth16_fraud_proof_broken_plonky2`)

1. **Valid proof + ExpectedResult=0 → gnark refuses**: The circuit constraint `AssertIsEqual(1, 0)` fires. This proves it is cryptographically impossible to generate a fraudulent Groth16 proof against a valid Plonky2 proof.

2. **Fraud detection via WHIR**: On-chain fraud is detected through PI hash mismatch (step 4) or WHIR verification failure (step 5), without needing Groth16.

### Security Invariants

- A valid block cannot be falsely flagged as fraud (binding checks prevent arbitrary input)
- An invalid block can always be detected via WHIR verification failure
- Groth16 provides additional security for `finalize()` but is not needed for `fraudProof()`

## Contract Interface

```solidity
// Finalize: requires both WHIR and Groth16
function finalize(
    uint256 submissionId,
    bytes32 blobVersionedHash,
    bytes32 stateRoot,
    bytes calldata plonky2ProofBytes,
    ValidityPublicInputs calldata validityPIs,
    WhirConfig calldata config,
    Statement calldata statement,
    WhirProof calldata whirProof,
    bytes calldata transcript,
    KZGProof calldata kzg,
    Groth16Params memory groth16        // ← Groth16 required
) external returns (bool);

// Fraud proof: WHIR-only, no Groth16
function fraudProof(
    uint256 submissionId,
    bytes32 blobVersionedHash,
    bytes32 stateRoot,
    bytes calldata plonky2ProofBytes,
    ValidityPublicInputs calldata validityPIs,
    WhirConfig calldata config,
    Statement calldata statement,
    WhirProof calldata whirProof,
    bytes calldata transcript,
    KZGProof calldata kzg               // ← No Groth16Params
) external returns (bool fraudConfirmed);
```
