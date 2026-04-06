// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {Verifier as GnarkVerifier} from "../src/GnarkGroth16Verifier.sol";

/// @title E2E test with REAL Groth16 (gnark)
/// @notice Verifies that a real gnark Groth16 proof (from Plonky2 validity circuit)
///         passes on-chain verification.
///
/// NOTE: WHIR verification (Goldilocks Ext3) is tested in WhirOnchainE2E.t.sol.
///       Complete finalize() E2E test (test_finalize_realE2E) is in IntmaxRollup.t.sol.
contract E2E_RealGroth16Test is Test {

    function test_realGroth16_verifies() public {
        GnarkVerifier gnarkVerifier = new GnarkVerifier();

        string memory groth16Json = vm.readFile(
            string.concat(vm.projectRoot(), "/test/data/e2e_groth16.json")
        );

        bytes memory rawProof = abi.decode(vm.parseJson(groth16Json, ".raw_proof_hex"), (bytes));
        require(rawProof.length >= 388, "Raw proof too short");

        uint256[8] memory proof;
        assembly {
            let src := add(rawProof, 32)
            for { let i := 0 } lt(i, 8) { i := add(i, 1) } {
                mstore(add(proof, mul(i, 32)), mload(add(src, mul(i, 32))))
            }
        }

        uint256[2] memory commitments;
        assembly {
            let src := add(add(rawProof, 32), 260)
            mstore(commitments, mload(src))
            mstore(add(commitments, 32), mload(add(src, 32)))
        }

        uint256[2] memory commitmentPok;
        assembly {
            let src := add(add(rawProof, 32), 324)
            mstore(commitmentPok, mload(src))
            mstore(add(commitmentPok, 32), mload(add(src, 32)))
        }

        uint256[8] memory input;
        for (uint256 i = 0; i < 8; i++) {
            string memory key = string.concat(".public_inputs_hex[", vm.toString(i), "]");
            input[i] = abi.decode(vm.parseJson(groth16Json, key), (uint256));
        }

        gnarkVerifier.verifyProof(proof, commitments, commitmentPok, input);
        assertTrue(true, "Real gnark Groth16 proof verified on-chain");
    }

    function test_e2e_piHash_binding_groth16() public {
        string memory e2eJson = vm.readFile(
            string.concat(vm.projectRoot(), "/test/data/e2e_fixture.json")
        );
        bytes32 piHash = abi.decode(vm.parseJson(e2eJson, ".pi_hash"), (bytes32));

        string memory groth16Json = vm.readFile(
            string.concat(vm.projectRoot(), "/test/data/e2e_groth16.json")
        );
        bytes32 reconstructed;
        for (uint256 i = 0; i < 8; i++) {
            string memory key = string.concat(".public_inputs_hex[", vm.toString(i), "]");
            uint256 limb = abi.decode(vm.parseJson(groth16Json, key), (uint256));
            reconstructed = bytes32(uint256(reconstructed) | (limb << (224 - i * 32)));
        }
        assertEq(reconstructed, piHash, "Groth16 pubInputs must encode piHash");
    }
}
