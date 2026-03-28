package variables

import (
	"math/big"

	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
	"github.com/succinctlabs/gnark-plonky2-verifier/types"
)

// hashOutRawToBigInt packs 4 uint64 limbs into a single big.Int.
// Uses base = 2^64, little-endian (limb[0] is least significant).
func hashOutRawToBigInt(hash types.HashOutRaw) *big.Int {
	result := new(big.Int)
	base := new(big.Int).Lsh(big.NewInt(1), 64) // 2^64

	for i := len(hash.Elements) - 1; i >= 0; i-- {
		result.Mul(result, base)
		limb := new(big.Int).SetUint64(hash.Elements[i])
		result.Add(result, limb)
	}
	return result
}

func hashOutRawToHashOut(hash types.HashOutRaw) poseidon.BN254HashOut {
	return poseidon.BN254HashOut(hashOutRawToBigInt(hash))
}

func DeserializeMerkleCap(merkleCapRaw []types.HashOutRaw) FriMerkleCap {
	n := len(merkleCapRaw)
	merkleCap := make([]poseidon.BN254HashOut, n)
	for i := 0; i < n; i++ {
		merkleCap[i] = hashOutRawToHashOut(merkleCapRaw[i])
	}
	return merkleCap
}

func DeserializeMerkleProof(merkleProofRaw struct{ Siblings []interface{} }) FriMerkleProof {
	n := len(merkleProofRaw.Siblings)
	var mp FriMerkleProof
	mp.Siblings = make([]poseidon.BN254HashOut, n)
	for i := 0; i < n; i++ {
		element := merkleProofRaw.Siblings[i].(struct{ Elements []uint64 })
		mp.Siblings[i] = hashOutRawToHashOut(types.HashOutRaw{Elements: element.Elements})
	}
	return mp
}

func DeserializeOpeningSet(openingSetRaw struct {
	Constants       [][]uint64
	PlonkSigmas     [][]uint64
	Wires           [][]uint64
	PlonkZs         [][]uint64
	PlonkZsNext     [][]uint64
	PartialProducts [][]uint64
	QuotientPolys   [][]uint64
}) OpeningSet {
	return OpeningSet{
		Constants:       gl.Uint64ArrayToQuadraticExtensionArray(openingSetRaw.Constants),
		PlonkSigmas:     gl.Uint64ArrayToQuadraticExtensionArray(openingSetRaw.PlonkSigmas),
		Wires:           gl.Uint64ArrayToQuadraticExtensionArray(openingSetRaw.Wires),
		PlonkZs:         gl.Uint64ArrayToQuadraticExtensionArray(openingSetRaw.PlonkZs),
		PlonkZsNext:     gl.Uint64ArrayToQuadraticExtensionArray(openingSetRaw.PlonkZsNext),
		PartialProducts: gl.Uint64ArrayToQuadraticExtensionArray(openingSetRaw.PartialProducts),
		QuotientPolys:   gl.Uint64ArrayToQuadraticExtensionArray(openingSetRaw.QuotientPolys),
	}
}

func HashArrayToHashBN254Array(rawHashes []types.HashOutRaw) []poseidon.BN254HashOut {
	hashes := make([]poseidon.BN254HashOut, len(rawHashes))
	for i := 0; i < len(rawHashes); i++ {
		hashes[i] = hashOutRawToHashOut(rawHashes[i])
	}
	return hashes
}

func DeserializeFriProof(openingProofRaw types.OpeningProofRaw) FriProof {
	var openingProof FriProof
	openingProof.PowWitness = gl.NewVariable(openingProofRaw.PowWitness)
	openingProof.FinalPoly.Coeffs = gl.Uint64ArrayToQuadraticExtensionArray(openingProofRaw.FinalPoly.Coeffs)

	openingProof.CommitPhaseMerkleCaps = make([]FriMerkleCap, len(openingProofRaw.CommitPhaseMerkleCaps))
	for i := 0; i < len(openingProofRaw.CommitPhaseMerkleCaps); i++ {
		openingProof.CommitPhaseMerkleCaps[i] = HashArrayToHashBN254Array(openingProofRaw.CommitPhaseMerkleCaps[i])
	}

	numQueryRoundProofs := len(openingProofRaw.QueryRoundProofs)
	openingProof.QueryRoundProofs = make([]FriQueryRound, numQueryRoundProofs)

	for i := 0; i < numQueryRoundProofs; i++ {
		numEvalProofs := len(openingProofRaw.QueryRoundProofs[i].InitialTreesProof.EvalsProofs)
		openingProof.QueryRoundProofs[i].InitialTreesProof.EvalsProofs = make([]FriEvalProof, numEvalProofs)
		for j := 0; j < numEvalProofs; j++ {
			openingProof.QueryRoundProofs[i].InitialTreesProof.EvalsProofs[j].Elements = gl.Uint64ArrayToVariableArray(openingProofRaw.QueryRoundProofs[i].InitialTreesProof.EvalsProofs[j].LeafElements)
			openingProof.QueryRoundProofs[i].InitialTreesProof.EvalsProofs[j].MerkleProof.Siblings = HashArrayToHashBN254Array(openingProofRaw.QueryRoundProofs[i].InitialTreesProof.EvalsProofs[j].MerkleProof.Hash)
		}

		numSteps := len(openingProofRaw.QueryRoundProofs[i].Steps)
		openingProof.QueryRoundProofs[i].Steps = make([]FriQueryStep, numSteps)
		for j := 0; j < numSteps; j++ {
			openingProof.QueryRoundProofs[i].Steps[j].Evals = gl.Uint64ArrayToQuadraticExtensionArray(openingProofRaw.QueryRoundProofs[i].Steps[j].Evals)
			openingProof.QueryRoundProofs[i].Steps[j].MerkleProof.Siblings = HashArrayToHashBN254Array(openingProofRaw.QueryRoundProofs[i].Steps[j].MerkleProof.Siblings)
		}
	}

	return openingProof
}

func DeserializeProofWithPublicInputs(raw types.ProofWithPublicInputsRaw) ProofWithPublicInputs {
	var proofWithPis ProofWithPublicInputs
	proofWithPis.Proof.WiresCap = DeserializeMerkleCap(raw.Proof.WiresCap)
	proofWithPis.Proof.PlonkZsPartialProductsCap = DeserializeMerkleCap(raw.Proof.PlonkZsPartialProductsCap)
	proofWithPis.Proof.QuotientPolysCap = DeserializeMerkleCap(raw.Proof.QuotientPolysCap)
	proofWithPis.Proof.Openings = DeserializeOpeningSet(struct {
		Constants       [][]uint64
		PlonkSigmas     [][]uint64
		Wires           [][]uint64
		PlonkZs         [][]uint64
		PlonkZsNext     [][]uint64
		PartialProducts [][]uint64
		QuotientPolys   [][]uint64
	}(raw.Proof.Openings))
	proofWithPis.Proof.OpeningProof = DeserializeFriProof(raw.Proof.OpeningProof)
	proofWithPis.PublicInputs = gl.Uint64ArrayToVariableArray(raw.PublicInputs)

	return proofWithPis
}

func DeserializeVerifierOnlyCircuitData(raw types.VerifierOnlyCircuitDataRaw) VerifierOnlyCircuitData {
	var verifierOnlyCircuitData VerifierOnlyCircuitData
	verifierOnlyCircuitData.ConstantSigmasCap = DeserializeMerkleCap(raw.ConstantsSigmasCap)
	verifierOnlyCircuitData.CircuitDigest = hashOutRawToHashOut(raw.CircuitDigest)
	return verifierOnlyCircuitData
}
