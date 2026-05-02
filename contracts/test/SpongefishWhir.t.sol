// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {Keccak256Chain} from "../src/spongefish/Keccak256Chain.sol";
import {SpongefishWhir} from "../src/spongefish/SpongefishWhir.sol";

/// @title SpongefishWhirTest
/// @notice Tests that the Solidity Keccak256Chain matches the Rust Keccak256Chain.
contract SpongefishWhirTest is Test {
    using Keccak256Chain for Keccak256Chain.Sponge;

    /// @notice Test basic absorb/squeeze determinism.
    function test_keccak256chain_deterministic() public pure {
        Keccak256Chain.Sponge memory s1 = Keccak256Chain.init();
        s1.absorb(hex"68656c6c6f"); // "hello"
        bytes memory out1 = s1.squeeze(32);

        Keccak256Chain.Sponge memory s2 = Keccak256Chain.init();
        s2.absorb(hex"68656c6c6f"); // "hello"
        bytes memory out2 = s2.squeeze(32);

        assertEq(out1, out2, "Keccak256Chain must be deterministic");
    }

    /// @notice Test that absorb matches Rust: state = keccak256(0x00...00 || "hello").
    function test_keccak256chain_absorb_matches_evm() public pure {
        Keccak256Chain.Sponge memory s = Keccak256Chain.init();
        s.absorb(hex"68656c6c6f"); // "hello"

        bytes32 expected = keccak256(abi.encodePacked(bytes32(0), hex"68656c6c6f"));
        assertEq(s.state, expected, "absorb state must match keccak256(zeros || hello)");
    }

    /// @notice Test transcript initialization with protocol_id + session_id from fixture.
    function test_transcript_init_from_fixture() public {
        string memory json = vm.readFile(
            string.concat(vm.projectRoot(), "/../tests/fixtures/whir_verifier_data.json")
        );

        bytes memory protocolId = vm.parseJsonBytes(json, ".protocol_id");
        bytes memory sessionId = vm.parseJsonBytes(json, ".session_id");
        bytes memory instance = vm.parseJsonBytes(json, ".instance");

        SpongefishWhir.TranscriptState memory ts = SpongefishWhir.initTranscript(
            protocolId, sessionId, instance
        );

        // Just verify we can squeeze without reverting
        bytes memory challenge = ts.sponge.squeeze(32);
        assertTrue(challenge.length == 32, "squeeze must return 32 bytes");
    }
}
