package verifier

import (
	"github.com/consensys/gnark/frontend"
	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
	"github.com/succinctlabs/gnark-plonky2-verifier/types"
	"github.com/succinctlabs/gnark-plonky2-verifier/variables"
)

type ExampleVerifierCircuit struct {
	PublicInputs            []gl.Variable                     `gnark:",public"`
	Proof                   variables.Proof                   `gnark:"-"`
	VerifierOnlyCircuitData variables.VerifierOnlyCircuitData `gnark:"-"`

	// This is configuration for the circuit, it is a constant not a variable
	CommonCircuitData types.CommonCircuitData
}

func (c *ExampleVerifierCircuit) Define(api frontend.API) error {
	verifierChip := NewVerifierChip(api, c.CommonCircuitData)
	verifierChip.Verify(c.Proof, c.PublicInputs, c.VerifierOnlyCircuitData)

	return nil
}

// FraudAwareVerifierCircuit is a circuit that can generate Groth16 proofs for both
// valid and invalid Plonky2 proofs.
//
//   - ExpectedResult == 1: proves that the Plonky2 proof is valid (finalize use case)
//   - ExpectedResult == 0: proves that the Plonky2 proof is invalid (fraud proof use case)
type FraudAwareVerifierCircuit struct {
	// ExpectedResult is 1 for a valid proof, 0 for a fraud proof.
	ExpectedResult frontend.Variable `gnark:",public"`

	PublicInputs            []gl.Variable                     `gnark:",public"`
	Proof                   variables.Proof                   `gnark:"-"`
	VerifierOnlyCircuitData variables.VerifierOnlyCircuitData `gnark:"-"`

	// This is configuration for the circuit, it is a constant not a variable
	CommonCircuitData types.CommonCircuitData
}

func (c *FraudAwareVerifierCircuit) Define(api frontend.API) error {
	api.AssertIsBoolean(c.ExpectedResult)

	verifierChip := NewVerifierChip(api, c.CommonCircuitData)
	result := verifierChip.VerifyAndReturnResult(c.Proof, c.PublicInputs, c.VerifierOnlyCircuitData)

	// Core constraint: actual verification result must match expected result
	api.AssertIsEqual(result, c.ExpectedResult)

	return nil
}
