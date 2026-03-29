# WHIR as Complete FRI Replacement + On-chain Constraint Check

## Architecture

```
Plonky2 Prover
  → polynomial coefficients (constants, sigmas, wires, Z, quotient)
  → openings at ζ (evaluations of all polys at challenge point)
  → WHIR commitments to each polynomial batch (replaces FRI Merkle tree)
  → WHIR evaluation proofs (replaces FRI folding)

On-chain Verification (Solidity):
  1. WHIR proof verification → proves openings are from committed low-degree polynomials
  2. Constraint satisfaction check → using openings, verify vanishing(ζ) == Z_H(ζ) * quotient(ζ)
  3. Groth16 verification → independent correctness proof (BN254-based)

finalize():  WHIR + constraint check + Groth16 all pass → accept
fraudProof(): blob data fails any of WHIR/constraint/Groth16 → fraud confirmed
```

## Blob Contents (NEW)

OLD: plonky2_proof_bytes (raw Plonky2 proof)
NEW: whir_proof_data || groth16_proof_data

whir_proof_data includes:
- 4 WHIR proofs (constants_sigmas, wires, zs_partial_products, quotient)
- Opening values at ζ and g·ζ
- Public inputs
- Fiat-Shamir challenges (or enough data to recompute them)

## Implementation Steps

### Step 1: Fix whir_plonky2_prover.rs — proper polynomial commitments

Current problems:
- `wires_whir` commits to opening values, not wire polynomial coefficients
- `zs_partial_products_whir` commits to FRI final poly, not Z/partial products
- `quotient_polys_whir` commits to Merkle caps (JSON), not quotient coefficients

Fix: Access actual polynomial coefficients for each batch.
- constants_sigmas: already correct (from prover_data)
- wires: need to re-derive from witness (or fork Plonky2)
- zs_partial_products: need to re-derive
- quotient: need to re-derive

Approach: Fork polygon-plonky2 to expose intermediate PolynomialBatch objects
from the prover, OR re-derive them by re-running the proving steps.

### Step 2: Implement GoldilocksField.sol — field arithmetic

Goldilocks: p = 2^64 - 2^32 + 1 = 18446744069414584321

```solidity
library GoldilocksField {
    uint64 constant P = 18446744069414584321;

    function add(uint64 a, uint64 b) → uint64
    function sub(uint64 a, uint64 b) → uint64
    function mul(uint64 a, uint64 b) → uint64   // needs 128-bit intermediate
    function inv(uint64 a) → uint64              // Fermat's little theorem
    function exp(uint64 base, uint64 e) → uint64
}
```

Extension field (D=2): F_p[x] / (x^2 - 7), W = 7

```solidity
library GoldilocksExt2 {
    struct Ext2 { uint64 c0; uint64 c1; }  // c0 + c1*α, α^2 = 7

    function add(Ext2, Ext2) → Ext2
    function sub(Ext2, Ext2) → Ext2
    function mul(Ext2, Ext2) → Ext2  // (a0+a1α)(b0+b1α) = (a0b0+7·a1b1) + (a0b1+a1b0)α
    function inv(Ext2) → Ext2
}
```

### Step 3: Implement Plonky2ConstraintChecker.sol

Takes opening values as input, verifies constraint satisfaction.

```solidity
function verifyConstraints(
    OpeningValues calldata openings,  // all poly evaluations at ζ
    Ext2 zeta,                        // challenge point
    uint64 degree_bits,               // log2(trace length)
    uint64[] calldata public_inputs,
    bytes32 circuit_digest,
    // Fiat-Shamir challenges
    uint64[] calldata plonk_betas,
    uint64[] calldata plonk_gammas,
    uint64[] calldata plonk_alphas
) external pure returns (bool)
```

Checks:
1. Gate constraints evaluation at ζ
2. Permutation argument: L_0(ζ)·(Z(ζ)-1) + partial product checks
3. vanishing[i] == (ζ^n - 1) · reduce_with_powers(quotient_chunks, ζ^n)

### Step 4: Update IntmaxRollup.sol

```solidity
function finalize(...) {
    // 1. Binding checks (commitment, KZG, PI binding)
    // 2. WHIR proof verification (4 polynomial batch proofs)
    // 3. Constraint satisfaction check (Goldilocks arithmetic)
    // 4. Groth16 verification
    // All must pass
}

function fraudProof(...) {
    // 1. Binding checks (must pass)
    // 2. Try WHIR + constraint + Groth16
    // If any fails → fraud confirmed
}
```

### Step 5: Groth16 setup persistence

- `gnark/main.go`: --setup-dir flag to save/load PK and VK
- `groth16_wrapper.rs`: cache setup artifacts on disk

### Step 6: Tests

- GoldilocksField.t.sol: field arithmetic unit tests
- Plonky2ConstraintChecker.t.sol: constraint check with known-good openings
- IntmaxRollup E2E: full pipeline with real proofs
- Fraud proof E2E: corrupted data → detection

## Gate Types to Implement

Need to check which gates the validity circuit actually uses.
Common gates: ArithmeticGate, PoseidonGate, ConstantGate, PublicInputGate.
Each gate has specific constraint equations that must be replicated in Solidity.

## Gas Estimation

- Goldilocks mul: ~100 gas (mulmod with 64-bit modulus)
- Extension mul: ~400 gas (4 base muls + 2 adds)
- Per-gate constraint: ~1000-5000 gas depending on gate type
- Permutation check: ~2000 gas per routed wire chunk
- Total constraint check: ~100k-500k gas (depends on circuit complexity)
- WHIR verification: ~300-500k gas
- Groth16: ~250k gas
- Total finalize: ~650k-1250k gas
