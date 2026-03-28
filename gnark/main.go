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

// Groth16Output is the JSON output format for the Groth16 proof.
type Groth16Output struct {
	Proof        Groth16ProofJSON `json:"proof"`
	PublicInputs []string         `json:"public_inputs"`
	ProvingTime  float64          `json:"proving_time_ms"`
	SetupTime    float64          `json:"setup_time_ms"`
	ProofSize    int              `json:"proof_size_bytes"`
	VerifyingKey Groth16VerifyingKeyJSON `json:"verifying_key"`
}

// Groth16ProofJSON represents the Groth16 proof points for Solidity.
type Groth16ProofJSON struct {
	A [2]string    `json:"a"`
	B [2][2]string `json:"b"`
	C [2]string    `json:"c"`
}

type Groth16VerifyingKeyJSON struct {
	Alpha [2]string    `json:"alpha"`
	Beta  [2][2]string `json:"beta"`
	Gamma [2][2]string `json:"gamma"`
	Delta [2][2]string `json:"delta"`
	IC    [][2]string  `json:"ic"`
}

func main() {
	dataDir := flag.String("data", "", "directory containing proof_with_public_inputs.json, verifier_only_circuit_data.json, common_circuit_data.json")
	outFile := flag.String("out", "groth16_proof.json", "output file for Groth16 proof")
	solFile := flag.String("sol", "", "output Solidity verifier contract (optional)")
	expectedResult := flag.Int("expected-result", 1, "1 = prove validity (finalize), 0 = prove fraud")
	flag.Parse()

	if *dataDir == "" {
		fmt.Fprintln(os.Stderr, "Usage: gnark-wrapper --data <dir> [--out groth16_proof.json] [--sol Verifier.sol] [--expected-result 0|1]")
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

	// Use FraudAwareVerifierCircuit for soft verification.
	// This enables Groth16 proof generation for both
	// valid (ExpectedResult=1) and invalid (ExpectedResult=0) Plonky2 proofs.
	circuit := verifier.FraudAwareVerifierCircuit{
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

	// Generate witness with expected result.
	// Re-deserialize proof data for the assignment because frontend.Compile()
	// mutates PublicInputs in-place (replacing concrete values with symbolic
	// expressions), and slices share underlying arrays.
	assignmentProofWithPis := variables.DeserializeProofWithPublicInputs(
		types.ReadProofWithPublicInputs(*dataDir + "/proof_with_public_inputs.json"),
	)
	assignment := verifier.FraudAwareVerifierCircuit{
		ExpectedResult: *expectedResult,
		PublicInputs:   assignmentProofWithPis.PublicInputs,
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

	// Extract public inputs from the witness
	pubWitnessSchema, _ := frontend.NewSchema(&assignment)
	pubWitnessJSON, _ := publicWitness.ToJSON(pubWitnessSchema)
	var pubWitnessMap map[string]interface{}
	json.Unmarshal(pubWitnessJSON, &pubWitnessMap)

	var pubInputStrs []string
	// Add ExpectedResult first
	if er, ok := pubWitnessMap["ExpectedResult"]; ok {
		pubInputStrs = append(pubInputStrs, fmt.Sprintf("%v", er))
	}
	// Add Plonky2 public inputs
	if pis, ok := pubWitnessMap["PublicInputs"]; ok {
		if pisList, ok := pis.([]interface{}); ok {
			for _, pi := range pisList {
				if piMap, ok := pi.(map[string]interface{}); ok {
					if limb, ok := piMap["Limb"]; ok {
						pubInputStrs = append(pubInputStrs, fmt.Sprintf("%v", limb))
					}
				}
			}
		}
	}

	output := Groth16Output{
		Proof: Groth16ProofJSON{
			A: [2]string{a[0].String(), a[1].String()},
			B: [2][2]string{
				{b[0][0].String(), b[0][1].String()},
				{b[1][0].String(), b[1][1].String()},
			},
			C: [2]string{c[0].String(), c[1].String()},
		},
		PublicInputs: pubInputStrs,
		ProvingTime:  float64(provingTime.Milliseconds()),
		SetupTime:    float64(setupTime.Milliseconds()),
		ProofSize:    len(proofBytes),
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
