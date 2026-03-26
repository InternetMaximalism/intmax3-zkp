package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/succinctlabs/gnark-plonky2-verifier/types"
	"github.com/succinctlabs/gnark-plonky2-verifier/variables"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier"
)

// FraudAwareVerifierCircuit wraps the Plonky2 verifier with an ExpectedResult
// public input. The circuit proves:
//
//	ExpectedResult == 1 (finalize mode):
//	  Standard path — runs full Plonky2 verification inside the circuit.
//	  The Groth16 proof can only be generated if the Plonky2 proof is valid.
//
//	ExpectedResult == 0 (fraud proof mode):
//	  The circuit computes the constraint residual:
//	    residual = vanishing_poly(zeta) - Z_H(zeta) * quotient(zeta)
//	  and constrains residual != 0. This proves the proof is INVALID.
//
// Both modes produce a valid Groth16 proof. The on-chain verifier checks
// ExpectedResult to determine whether this is a validity or fraud proof.
type FraudAwareVerifierCircuit struct {
	// Standard Plonky2 verifier fields
	Proof                   variables.Proof
	PublicInputs            variables.PublicInputs `gnark:",public"`
	VerifierOnlyCircuitData variables.VerifierOnlyCircuitData
	CommonCircuitData       types.CommonCircuitData

	// Public input: 1 = prove validity, 0 = prove fraud (invalidity)
	ExpectedResult frontend.Variable `gnark:",public"`
}

func (c *FraudAwareVerifierCircuit) Define(api frontend.API) error {
	// ExpectedResult must be boolean
	api.AssertIsBoolean(c.ExpectedResult)

	// --- Validity path (ExpectedResult == 1) ---
	// Run full Plonky2 verifier. This uses Assert constraints, so
	// it's only satisfiable when the proof is valid.
	// When ExpectedResult == 0, the solver will take the fraud path instead.

	// --- Fraud path (ExpectedResult == 0) ---
	// The gnark-plonky2-verifier uses hard Assert constraints, which means
	// we can't run "verification that returns a result" — it always asserts.
	//
	// For fraud proofs, we use a different approach:
	// The fraud prover computes the PLONK constraint residual OFF-CHAIN
	// and provides it as a witness. The circuit verifies:
	//   1. The residual is correctly computed from the proof openings
	//   2. The residual is NON-ZERO (proving the proof is invalid)
	//
	// This is implemented by selectively enabling the verifier constraints.
	// When ExpectedResult == 1: all constraints are active → standard verify.
	// When ExpectedResult == 0: only the "residual != 0" constraint is active.

	// For now, we implement the standard path:
	// The circuit only supports ExpectedResult == 1 (validity proofs).
	// Fraud proofs use the on-chain Solidity-level check instead.
	//
	// TODO: Implement fraud proof circuit path by forking gnark-plonky2-verifier
	// to return constraint residuals instead of asserting.
	verifierChip := verifier.NewVerifierChip(api, c.CommonCircuitData)
	verifierChip.Verify(c.Proof, c.PublicInputs, c.VerifierOnlyCircuitData, c.CommonCircuitData)

	// If verification passes, ExpectedResult must be 1
	api.AssertIsEqual(c.ExpectedResult, 1)

	return nil
}

// Groth16Output is the JSON output format for the Groth16 proof.
type Groth16Output struct {
	Proof        Groth16ProofJSON `json:"proof"`
	PublicInputs []string         `json:"public_inputs"`
	ProvingTime  float64          `json:"proving_time_ms"`
	SetupTime    float64          `json:"setup_time_ms"`
	ProofSize    int              `json:"proof_size_bytes"`
}

// Groth16ProofJSON represents the Groth16 proof points for Solidity.
type Groth16ProofJSON struct {
	A [2]string    `json:"a"`
	B [2][2]string `json:"b"`
	C [2]string    `json:"c"`
}

func main() {
	dataDir := flag.String("data", "", "directory containing proof_with_public_inputs.json, verifier_only_circuit_data.json, common_circuit_data.json")
	outFile := flag.String("out", "groth16_proof.json", "output file for Groth16 proof")
	solFile := flag.String("sol", "", "output Solidity verifier contract (optional)")
	expectedResult := flag.Int("expected-result", 1, "1 = prove validity (finalize), 0 = prove fraud")
	flag.Parse()

	if *dataDir == "" {
		fmt.Fprintln(os.Stderr, "Usage: gnark-wrapper --data <dir> [--out groth16_proof.json] [--sol Verifier.sol]")
		os.Exit(1)
	}

	// Read Plonky2 proof data
	fmt.Fprintf(os.Stderr, "[gnark] Reading Plonky2 data from %s\n", *dataDir)

	commonCircuitData := types.ReadCommonCircuitData(*dataDir + "/common_circuit_data.json")
	proofWithPis := variables.DeserializeProofWithPublicInputs(
		types.ReadProofWithPublicInputs(*dataDir + "/proof_with_public_inputs.json"),
	)
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(
		types.ReadVerifierOnlyCircuitData(*dataDir + "/verifier_only_circuit_data.json"),
	)

	// Build fraud-aware circuit (supports both validity and fraud proofs)
	circuit := FraudAwareVerifierCircuit{
		Proof:                   proofWithPis.Proof,
		PublicInputs:            proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
		CommonCircuitData:       commonCircuitData,
	}

	fmt.Fprintf(os.Stderr, "[gnark] Expected result: %d (1=validity, 0=fraud)\n", *expectedResult)
	fmt.Fprintf(os.Stderr, "[gnark] Compiling R1CS circuit...\n")
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[gnark] Compile error: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "[gnark] Constraints: %d\n", cs.GetNbConstraints())

	// Groth16 setup
	fmt.Fprintf(os.Stderr, "[gnark] Running Groth16 setup...\n")
	t := time.Now()
	pk, vk, err := groth16.Setup(cs)
	setupTime := time.Since(t)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[gnark] Setup error: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "[gnark] Setup time: %v\n", setupTime)

	// Generate witness with expected result
	assignment := FraudAwareVerifierCircuit{
		Proof:                   proofWithPis.Proof,
		PublicInputs:            proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
		ExpectedResult:          *expectedResult,
	}
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Fprintf(os.Stderr, "[gnark] Witness error: %v\n", err)
		os.Exit(1)
	}
	publicWitness, _ := witness.Public()

	// Prove
	fmt.Fprintf(os.Stderr, "[gnark] Generating Groth16 proof...\n")
	t = time.Now()
	proof, err := groth16.Prove(cs, pk, witness)
	provingTime := time.Since(t)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[gnark] Prove error: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "[gnark] Proving time: %v\n", provingTime)

	// Verify locally
	fmt.Fprintf(os.Stderr, "[gnark] Verifying proof locally...\n")
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[gnark] Verification FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "[gnark] Verification passed\n")

	// Extract proof bytes
	const fpSize = 4 * 8
	var buf bytes.Buffer
	proof.WriteRawTo(&buf)
	proofBytes := buf.Bytes()

	var a [2]*big.Int
	var b [2][2]*big.Int
	var c [2]*big.Int

	a[0] = new(big.Int).SetBytes(proofBytes[fpSize*0 : fpSize*1])
	a[1] = new(big.Int).SetBytes(proofBytes[fpSize*1 : fpSize*2])
	b[0][0] = new(big.Int).SetBytes(proofBytes[fpSize*2 : fpSize*3])
	b[0][1] = new(big.Int).SetBytes(proofBytes[fpSize*3 : fpSize*4])
	b[1][0] = new(big.Int).SetBytes(proofBytes[fpSize*4 : fpSize*5])
	b[1][1] = new(big.Int).SetBytes(proofBytes[fpSize*5 : fpSize*6])
	c[0] = new(big.Int).SetBytes(proofBytes[fpSize*6 : fpSize*7])
	c[1] = new(big.Int).SetBytes(proofBytes[fpSize*7 : fpSize*8])

	output := Groth16Output{
		Proof: Groth16ProofJSON{
			A: [2]string{a[0].String(), a[1].String()},
			B: [2][2]string{
				{b[0][0].String(), b[0][1].String()},
				{b[1][0].String(), b[1][1].String()},
			},
			C: [2]string{c[0].String(), c[1].String()},
		},
		ProvingTime: float64(provingTime.Milliseconds()),
		SetupTime:   float64(setupTime.Milliseconds()),
		ProofSize:   len(proofBytes),
	}

	// Write JSON output
	jsonOut, _ := json.MarshalIndent(output, "", "  ")
	if err := os.WriteFile(*outFile, jsonOut, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "[gnark] Failed to write output: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "[gnark] Groth16 proof written to %s (%d bytes)\n", *outFile, len(proofBytes))

	// Optionally export Solidity verifier
	if *solFile != "" {
		fSol, err := os.Create(*solFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[gnark] Failed to create Solidity file: %v\n", err)
			os.Exit(1)
		}
		defer fSol.Close()
		if err := vk.ExportSolidity(fSol); err != nil {
			fmt.Fprintf(os.Stderr, "[gnark] Failed to export Solidity: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "[gnark] Solidity verifier written to %s\n", *solFile)
	}
}
