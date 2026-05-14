// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {Verifier as GnarkVerifier} from "../src/GnarkGroth16Verifier.sol";

/// @title E2E test with REAL Groth16 (gnark)
/// @notice Verifies that a real gnark Groth16 proof (from Plonky2 validity circuit)
///         passes on-chain verification.
contract E2E_RealGroth16Test is Test {

    /// @dev Set `SKIP_GROTH16=1` (or `true`) in the environment to skip this test.
    ///      Mirrors the previous `--skip-groth16` flag from the WHIR-era
    ///      `generate_e2e_fixture` binary. Useful for local iteration when the
    ///      gnark binary / Groth16 fixtures are not available, or simply to
    ///      cut wall-clock when iterating on non-Groth16 code paths.
    function test_realGroth16_verifies() public {
        if (vm.envOr("SKIP_GROTH16", false)) {
            vm.skip(true, "SKIP_GROTH16 env var set");
            return;
        }

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
}
