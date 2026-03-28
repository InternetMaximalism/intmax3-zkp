package types

import (
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
)

type HashOutRaw struct {
	Elements []uint64 `json:"elements"`
}

func (h *HashOutRaw) UnmarshalJSON(data []byte) error {
	// Handle decimal string encoding (new format)
	if len(data) > 0 && data[0] == '"' {
		var dec string
		if err := json.Unmarshal(data, &dec); err != nil {
			return err
		}
		limbs, err := decimalStringToLimbs(dec)
		if err != nil {
			return err
		}
		h.Elements = limbs
		return nil
	}
	// Fallback to legacy object format
	type alias HashOutRaw
	var aux alias
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	h.Elements = aux.Elements
	return nil
}

func decimalStringToLimbs(dec string) ([]uint64, error) {
	value, ok := new(big.Int).SetString(dec, 10)
	if !ok {
		return nil, fmt.Errorf("invalid decimal hash: %s", dec)
	}
	base := new(big.Int).Lsh(big.NewInt(1), 64)
	limbs := make([]uint64, 4)
	for i := 0; i < len(limbs); i++ {
		mod := new(big.Int).Mod(value, base)
		limbs[i] = mod.Uint64()
		value.Div(value, base)
	}
	return limbs, nil
}

type ProofWithPublicInputsRaw struct {
	Proof struct {
		WiresCap                  []HashOutRaw `json:"wires_cap"`
		PlonkZsPartialProductsCap []HashOutRaw `json:"plonk_zs_partial_products_cap"`
		QuotientPolysCap          []HashOutRaw `json:"quotient_polys_cap"`
		Openings                  struct {
			Constants       [][]uint64 `json:"constants"`
			PlonkSigmas     [][]uint64 `json:"plonk_sigmas"`
			Wires           [][]uint64 `json:"wires"`
			PlonkZs         [][]uint64 `json:"plonk_zs"`
			PlonkZsNext     [][]uint64 `json:"plonk_zs_next"`
			PartialProducts [][]uint64 `json:"partial_products"`
			QuotientPolys   [][]uint64 `json:"quotient_polys"`
		} `json:"openings"`
		OpeningProof OpeningProofRaw `json:"opening_proof"`
	} `json:"proof"`
	PublicInputs []uint64 `json:"public_inputs"`
}

type OpeningProofRaw struct {
	CommitPhaseMerkleCaps [][]HashOutRaw `json:"commit_phase_merkle_caps"`
	QueryRoundProofs      []struct {
		InitialTreesProof struct {
			EvalsProofs []EvalProofRaw `json:"evals_proofs"`
		} `json:"initial_trees_proof"`
		Steps []struct {
			Evals       [][]uint64 `json:"evals"`
			MerkleProof struct {
				Siblings []HashOutRaw `json:"siblings"`
			} `json:"merkle_proof"`
		} `json:"steps"`
	} `json:"query_round_proofs"`
	FinalPoly struct {
		Coeffs [][]uint64 `json:"coeffs"`
	} `json:"final_poly"`
	PowWitness uint64 `json:"pow_witness"`
}

type EvalProofRaw struct {
	LeafElements []uint64
	MerkleProof  MerkleProofRaw
}

func (e *EvalProofRaw) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &[]interface{}{&e.LeafElements, &e.MerkleProof})
}

type MerkleProofRaw struct {
	Hash []HashOutRaw
}

func (m *MerkleProofRaw) UnmarshalJSON(data []byte) error {
	type SiblingObject struct {
		Siblings []HashOutRaw `json:"siblings"`
	}

	var siblings SiblingObject
	if err := json.Unmarshal(data, &siblings); err != nil {
		return err
	}

	m.Hash = make([]HashOutRaw, len(siblings.Siblings))
	copy(m.Hash[:], siblings.Siblings)

	return nil
}

type ProofChallengesRaw struct {
	PlonkBetas    []uint64 `json:"plonk_betas"`
	PlonkGammas   []uint64 `json:"plonk_gammas"`
	PlonkAlphas   []uint64 `json:"plonk_alphas"`
	PlonkZeta     []uint64 `json:"plonk_zeta"`
	FriChallenges struct {
		FriAlpha        []uint64   `json:"fri_alpha"`
		FriBetas        [][]uint64 `json:"fri_betas"`
		FriPowResponse  uint64     `json:"fri_pow_response"`
		FriQueryIndices []uint64   `json:"fri_query_indices"`
	} `json:"fri_challenges"`
}

type VerifierOnlyCircuitDataRaw struct {
	ConstantsSigmasCap []HashOutRaw `json:"constants_sigmas_cap"`
	CircuitDigest      HashOutRaw   `json:"circuit_digest"`
}

func ReadProofWithPublicInputs(path string) ProofWithPublicInputsRaw {
	jsonFile, err := os.Open(path)
	if err != nil {
		panic(err)
	}

	defer jsonFile.Close()
	rawBytes, _ := io.ReadAll(jsonFile)

	var raw ProofWithPublicInputsRaw
	err = json.Unmarshal(rawBytes, &raw)
	if err != nil {
		panic(err)
	}

	return raw
}

func ReadVerifierOnlyCircuitData(path string) VerifierOnlyCircuitDataRaw {
	jsonFile, err := os.Open(path)
	if err != nil {
		panic(err)
	}

	defer jsonFile.Close()
	rawBytes, _ := io.ReadAll(jsonFile)

	var raw VerifierOnlyCircuitDataRaw
	err = json.Unmarshal(rawBytes, &raw)
	if err != nil {
		panic(err)
	}

	return raw
}
