// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {Verifier as GnarkVerifier} from "../src/GnarkGroth16Verifier.sol";
import {Verifier as WhirVerifier} from "sol-whir/Whir.sol";
import {WhirProof, Statement, WhirConfig} from "sol-whir/WhirStructs.sol";
import {BN254} from "solidity-bn254/BN254.sol";
import {JSONWhirProof, JSONUtils} from "sol-whir/utils/WhirJson.sol";

/// @title E2E test with REAL Groth16 (gnark) + REAL WHIR proof
/// @notice Verifies that:
///   1. A real gnark Groth16 proof (from Plonky2 validity circuit) passes on-chain verification
///   2. A real WHIR proof (BN254) passes sol-whir verification
///   3. Both are bound to the same piHash (keccak256 of ValidityPublicInputs)
contract E2E_RealGroth16Test is Test {

    function test_realGroth16_verifies() public {
        GnarkVerifier gnarkVerifier = new GnarkVerifier();

        // Load the E2E fixture
        string memory groth16Json = vm.readFile(
            string.concat(vm.projectRoot(), "/test/data/e2e_groth16.json")
        );

        // Parse raw proof hex (first 256 bytes = A+B+C in gnark format)
        bytes memory rawProof = abi.decode(vm.parseJson(groth16Json, ".raw_proof_hex"), (bytes));
        require(rawProof.length >= 256, "Raw proof too short");

        uint256[8] memory proof;
        assembly {
            let src := add(rawProof, 32) // skip length prefix
            for { let i := 0 } lt(i, 8) { i := add(i, 1) } {
                mstore(add(proof, mul(i, 32)), mload(add(src, mul(i, 32))))
            }
        }

        // Parse 9 public inputs (8 user + 1 commitment hash)
        uint256[9] memory input;
        {
            uint256[] memory pis = abi.decode(vm.parseJson(groth16Json, ".public_inputs"), (uint256[]));
            require(pis.length == 9, "Expected 9 public inputs");
            for (uint256 i = 0; i < 9; i++) {
                input[i] = pis[i];
            }
        }

        // Verify — reverts with ProofInvalid() if verification fails
        gnarkVerifier.verifyProof(proof, input);

        // If we reach here, the real Groth16 proof verified on-chain
        assertTrue(true, "Real gnark Groth16 proof verified on-chain");
    }

    function test_realWhir_verifies() public {
        // Load WHIR fixture bound to the same piHash
        string memory whirJson = vm.readFile(
            string.concat(vm.projectRoot(), "/test/data/whir/intmax3_e2e_whir_fixture.json")
        );
        bytes memory parsed = vm.parseJson(whirJson);
        JSONWhirProof memory jsonProof = abi.decode(parsed, (JSONWhirProof));

        WhirConfig memory config = JSONUtils.jsonWhirConfigToWhirConfig(jsonProof.config);
        Statement memory statement = JSONUtils.jsonStatementToStatement(jsonProof.statement);
        WhirProof memory whirProof = JSONUtils.jsonWhirProofToWhirProof(jsonProof);
        bytes memory transcript = jsonProof.arthur.transcript;

        bool ok = WhirVerifier.verify(config, statement, whirProof, transcript);
        assertTrue(ok, "Real WHIR proof verified on-chain");
    }

    function test_e2e_piHash_binding() public {
        // Load piHash from the E2E fixture
        string memory groth16Json = vm.readFile(
            string.concat(vm.projectRoot(), "/test/data/e2e_groth16.json")
        );

        // piHash = keccak256(ValidityPublicInputs)
        string memory piHashHex = abi.decode(vm.parseJson(groth16Json, ".pi_hash"), (string));

        // piHashReduced = piHash % BN254.R_MOD
        string memory piHashReducedHex = abi.decode(vm.parseJson(groth16Json, ".pi_hash_reduced"), (string));
        uint256 piHashReduced = vm.parseUint(piHashReducedHex);

        // Load WHIR fixture
        string memory whirJson = vm.readFile(
            string.concat(vm.projectRoot(), "/test/data/whir/intmax3_e2e_whir_fixture.json")
        );
        bytes memory parsed = vm.parseJson(whirJson);
        JSONWhirProof memory jsonProof = abi.decode(parsed, (JSONWhirProof));
        Statement memory statement = JSONUtils.jsonStatementToStatement(jsonProof.statement);

        // Verify binding: WHIR evaluations[0] == piHashReduced
        uint256 whirEval = BN254.ScalarField.unwrap(statement.evaluations[0]);
        assertEq(whirEval, piHashReduced, "WHIR evaluations[0] must equal piHashReduced");

        // Verify binding: Groth16 pubInputs encode the same piHash as 8 u32 limbs
        uint256[] memory pis = abi.decode(vm.parseJson(groth16Json, ".public_inputs"), (uint256[]));
        bytes32 piHash = bytes32(vm.parseUint(piHashHex));
        // First 8 public inputs are the u32 limbs of piHash
        bytes32 reconstructed;
        for (uint256 i = 0; i < 8; i++) {
            reconstructed = bytes32(uint256(reconstructed) | (pis[i] << (224 - i * 32)));
        }
        assertEq(reconstructed, piHash, "Groth16 pubInputs must encode piHash");
    }
}
