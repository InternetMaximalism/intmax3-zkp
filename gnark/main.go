package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
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
	RawProofHex  string           `json:"raw_proof_hex"`
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
	setupDir := flag.String("setup-dir", "", "directory to save/load trusted setup (pk.bin, vk.bin). If empty, setup is regenerated each time (dev mode)")
	expectedResult := flag.Int("expected-result", 1, "1 = prove validity (finalize), 0 = prove fraud")
	flag.Parse()

	if *dataDir == "" {
		fmt.Fprintln(os.Stderr, "Usage: gnark-wrapper --data <dir> [--out groth16_proof.json] [--sol Verifier.sol]")
		os.Exit(1)
	}

	// Read Plonky2 proof data
	fmt.Fprintf(os.Stderr, "[gnark] Reading Plonky2 data from %s\n", *dataDir)
	fmt.Fprintf(os.Stderr, "[gnark] Expected result: %d (1=validity, 0=fraud)\n", *expectedResult)
	_ = *expectedResult // Used for circuit mode selection (future: FraudAwareVerifierCircuit)

	commonCircuitData := types.ReadCommonCircuitData(*dataDir + "/common_circuit_data.json")
	proofWithPis := variables.DeserializeProofWithPublicInputs(
		types.ReadProofWithPublicInputs(*dataDir + "/proof_with_public_inputs.json"),
	)
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(
		types.ReadVerifierOnlyCircuitData(*dataDir + "/verifier_only_circuit_data.json"),
	)

	// Use ExampleVerifierCircuit: Plonky2 proof is private, only PublicInputs are public.
	// The Plonky2 validity circuit registers keccak256(ValidityPublicInputs).to_u32_vec()
	// (8 big-endian u32 limbs) as its public inputs. gnark maps each Goldilocks element
	// to one BN254 scalar, so groth16.pubInputs will have exactly 8 elements.
	circuit := verifier.ExampleVerifierCircuit{
		Proof:                   proofWithPis.Proof,
		PublicInputs:            proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
		CommonCircuitData:       commonCircuitData,
	}

	fmt.Fprintf(os.Stderr, "[gnark] Compiling R1CS circuit...\n")
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[gnark] Compile error: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "[gnark] Constraints: %d\n", cs.GetNbConstraints())

	// Groth16 setup — load from disk if available, otherwise generate and save
	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey
	var setupTime time.Duration

	if *setupDir != "" {
		pkPath := *setupDir + "/pk.bin"
		vkPath := *setupDir + "/vk.bin"

		if pkData, err := os.ReadFile(pkPath); err == nil {
			if vkData, err := os.ReadFile(vkPath); err == nil {
				fmt.Fprintf(os.Stderr, "[gnark] Loading trusted setup from %s...\n", *setupDir)
				t := time.Now()
				pk = groth16.NewProvingKey(ecc.BN254)
				if _, err := pk.ReadFrom(bytes.NewReader(pkData)); err != nil {
					fmt.Fprintf(os.Stderr, "[gnark] Failed to read PK: %v\n", err)
					os.Exit(1)
				}
				vk = groth16.NewVerifyingKey(ecc.BN254)
				if _, err := vk.ReadFrom(bytes.NewReader(vkData)); err != nil {
					fmt.Fprintf(os.Stderr, "[gnark] Failed to read VK: %v\n", err)
					os.Exit(1)
				}
				setupTime = time.Since(t)
				fmt.Fprintf(os.Stderr, "[gnark] Loaded trusted setup in %v\n", setupTime)
			}
		}
	}

	if pk == nil {
		fmt.Fprintf(os.Stderr, "[gnark] Running Groth16 setup (generating new keys)...\n")
		t := time.Now()
		var err error
		pk, vk, err = groth16.Setup(cs)
		setupTime = time.Since(t)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[gnark] Setup error: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "[gnark] Setup time: %v\n", setupTime)

		// Save keys to disk if setup-dir is specified
		if *setupDir != "" {
			fmt.Fprintf(os.Stderr, "[gnark] Saving trusted setup to %s...\n", *setupDir)
			os.MkdirAll(*setupDir, 0755)

			var pkBuf, vkBuf bytes.Buffer
			pk.WriteTo(&pkBuf)
			vk.WriteTo(&vkBuf)

			if err := os.WriteFile(*setupDir+"/pk.bin", pkBuf.Bytes(), 0644); err != nil {
				fmt.Fprintf(os.Stderr, "[gnark] Warning: failed to save PK: %v\n", err)
			}
			if err := os.WriteFile(*setupDir+"/vk.bin", vkBuf.Bytes(), 0644); err != nil {
				fmt.Fprintf(os.Stderr, "[gnark] Warning: failed to save VK: %v\n", err)
			}
			fmt.Fprintf(os.Stderr, "[gnark] Trusted setup saved\n")
		}
	}

	// Generate witness with expected result.
	// Re-deserialize proof data for the assignment because frontend.Compile()
	// mutates PublicInputs in-place (replacing concrete values with symbolic
	// expressions), and slices share underlying arrays.
	assignmentProofWithPis := variables.DeserializeProofWithPublicInputs(
		types.ReadProofWithPublicInputs(*dataDir + "/proof_with_public_inputs.json"),
	)
	assignment := verifier.ExampleVerifierCircuit{
		PublicInputs: assignmentProofWithPis.PublicInputs,
	}
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Fprintf(os.Stderr, "[gnark] Witness error: %v\n", err)
		os.Exit(1)
	}
	publicWitness, _ := witness.Public()

	// Prove with SHA-256 as HashToField (required for gnark v0.10+ Solidity verifier)
	fmt.Fprintf(os.Stderr, "[gnark] Generating Groth16 proof...\n")
	tProve := time.Now()
	proof, err := groth16.Prove(cs, pk, witness, backend.WithProverHashToFieldFunction(sha256.New()))
	provingTime := time.Since(tProve)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[gnark] Prove error: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "[gnark] Proving time: %v\n", provingTime)

	// Verify locally with SHA-256 hash function (must match prover)
	fmt.Fprintf(os.Stderr, "[gnark] Verifying proof locally...\n")
	err = groth16.Verify(proof, vk, publicWitness, backend.WithVerifierHashToFieldFunction(sha256.New()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[gnark] Verification FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "[gnark] Verification passed\n")

	// After verification, the publicWitness was not modified. But we can replicate
	// the exact computation from groth16/bn254/verify.go by accessing the BN254-specific
	// proof structure which contains Commitments.
	bn254Proof := proof.(*groth16_bn254.Proof)
	fmt.Fprintf(os.Stderr, "[gnark] Proof has %d commitments\n", len(bn254Proof.Commitments))
	if len(bn254Proof.Commitments) > 0 {
		commitMarshaled := bn254Proof.Commitments[0].Marshal()
		fmt.Fprintf(os.Stderr, "[gnark] Commitment[0] marshaled length: %d bytes\n", len(commitMarshaled))
		fmt.Fprintf(os.Stderr, "[gnark] Commitment[0] hex: 0x%x\n", commitMarshaled)
	}

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

	// Extract user public inputs from the witness.
	pubVec := publicWitness.Vector().(fr.Vector)
	var pubInputStrs []string
	for _, elem := range pubVec {
		var val big.Int
		elem.BigInt(&val)
		pubInputStrs = append(pubInputStrs, val.String())
	}

	// Compute the 9th public input (commitment hash) using gnark's verifier logic.
	// After groth16.Verify() succeeds, we replicate its commitment hash computation.
	{
		// Access BN254-specific VK to get commitment info
		bn254VK := vk.(*groth16_bn254.VerifyingKey)
		fmt.Fprintf(os.Stderr, "[gnark] VK.G1.K length: %d\n", len(bn254VK.G1.K))
		fmt.Fprintf(os.Stderr, "[gnark] VK.PublicAndCommitmentCommitted: %v\n", bn254VK.PublicAndCommitmentCommitted)

		// Parse commitment point from raw proof
		// Layout: A(64) + B(128) + C(64) = 256 bytes, then nbCommitments(4), then commitment(64)
		commitOffset := fpSize*8 + 4 // skip nbCommitments (4 bytes)
		commitBytes := proofBytes[commitOffset : commitOffset+64] // 64 bytes

		// Build prehash: commitment_point || committed_public_inputs
		var prehash []byte
		prehash = append(prehash, commitBytes...)
		if len(bn254VK.PublicAndCommitmentCommitted) > 0 {
			for _, idx := range bn254VK.PublicAndCommitmentCommitted[0] {
				prehash = append(prehash, pubVec[idx-1].Marshal()...)
			}
		}

		commitmentDst := []byte("bsb22-commitment")
		res, err := fr.Hash(prehash, commitmentDst, 1)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[gnark] Commitment hash error: %v\n", err)
			os.Exit(1)
		}
		var commitHashBigInt big.Int
		res[0].BigInt(&commitHashBigInt)
		pubInputStrs = append(pubInputStrs, commitHashBigInt.String())
		fmt.Fprintf(os.Stderr, "[gnark] Commitment hash (9th input): %s\n", commitHashBigInt.String())
	}

	// Also output the raw proof bytes as hex for on-chain use with gnark generated verifier
	rawProofHex := fmt.Sprintf("0x%x", proofBytes)
	fmt.Fprintf(os.Stderr, "[gnark] Public inputs: %d (user + commitment), raw proof: %d bytes\n", len(pubInputStrs), len(proofBytes))

	// Extract VK for on-chain deployment
	var vkBuf bytes.Buffer
	vk.WriteRawTo(&vkBuf)
	vkBytes := vkBuf.Bytes()

	// VK raw layout: alpha(2*fpSize) + beta(2*2*fpSize) + gamma(2*2*fpSize) + delta(2*2*fpSize) + ic(n*2*fpSize)
	vkAlpha := [2]string{
		new(big.Int).SetBytes(vkBytes[fpSize*0 : fpSize*1]).String(),
		new(big.Int).SetBytes(vkBytes[fpSize*1 : fpSize*2]).String(),
	}
	vkBeta := [2][2]string{
		{
			new(big.Int).SetBytes(vkBytes[fpSize*2 : fpSize*3]).String(),
			new(big.Int).SetBytes(vkBytes[fpSize*3 : fpSize*4]).String(),
		},
		{
			new(big.Int).SetBytes(vkBytes[fpSize*4 : fpSize*5]).String(),
			new(big.Int).SetBytes(vkBytes[fpSize*5 : fpSize*6]).String(),
		},
	}
	vkGamma := [2][2]string{
		{
			new(big.Int).SetBytes(vkBytes[fpSize*6 : fpSize*7]).String(),
			new(big.Int).SetBytes(vkBytes[fpSize*7 : fpSize*8]).String(),
		},
		{
			new(big.Int).SetBytes(vkBytes[fpSize*8 : fpSize*9]).String(),
			new(big.Int).SetBytes(vkBytes[fpSize*9 : fpSize*10]).String(),
		},
	}
	vkDelta := [2][2]string{
		{
			new(big.Int).SetBytes(vkBytes[fpSize*10 : fpSize*11]).String(),
			new(big.Int).SetBytes(vkBytes[fpSize*11 : fpSize*12]).String(),
		},
		{
			new(big.Int).SetBytes(vkBytes[fpSize*12 : fpSize*13]).String(),
			new(big.Int).SetBytes(vkBytes[fpSize*13 : fpSize*14]).String(),
		},
	}
	// IC points: remaining bytes after the fixed VK header
	icStart := fpSize * 14
	numIC := (len(vkBytes) - icStart) / (fpSize * 2)
	var vkIC [][2]string
	for i := 0; i < numIC; i++ {
		offset := icStart + i*fpSize*2
		vkIC = append(vkIC, [2]string{
			new(big.Int).SetBytes(vkBytes[offset : offset+fpSize]).String(),
			new(big.Int).SetBytes(vkBytes[offset+fpSize : offset+fpSize*2]).String(),
		})
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
		VerifyingKey: Groth16VerifyingKeyJSON{
			Alpha: vkAlpha,
			Beta:  vkBeta,
			Gamma: vkGamma,
			Delta: vkDelta,
			IC:    vkIC,
		},
		PublicInputs: pubInputStrs,
		RawProofHex:  rawProofHex,
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
