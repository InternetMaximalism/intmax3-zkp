// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {FixtureLib} from "./FixtureLib.sol";

/// @title PrepareProofDa
/// @notice Produces the canonical validity-proof byte stream consumed by Foundry's EIP-4844
///         `SidecarBuilder<SimpleCoder>` when `cast send --blob --path ...` is used.
///
/// @dev The file is deliberately the fixture's exact canonical `compactProof.bytes` stream.
///      Foundry 1.5.1's
///      `SimpleCoder` adds one field-element header
///      (`0x00 || uint64_be(length) || 23 zero bytes`), packs 31 payload bytes into each subsequent
///      BLS scalar field element (`0x00 || payload chunk`), zero pads the final word, and
///      automatically splits the result across blobs. Supplying an already field-packed file would
///      therefore double-encode it and make recovery impossible.
contract PrepareProofDa is Script {
    uint256 public constant FIELD_ELEMENTS_PER_BLOB = 4096;
    uint256 public constant PAYLOAD_BYTES_PER_FIELD_ELEMENT = 31;
    uint256 public constant MAX_BLOBS = 2;

    string internal constant INPUT = "test/data/sepolia_lifecycle_validity_mle.json";
    string internal constant OUTPUT = "../proof-da-output/validity-proof.bin";
    string internal constant METADATA = "../proof-da-output/validity-proof.json";

    error EmptyProofPayload();
    error ProofPayloadTooLarge(uint256 proofLength, uint256 requiredBlobs);

    /// @notice Number of blobs Foundry's SimpleCoder will produce for one ingested byte slice.
    /// @dev One field element is consumed by the length header. This makes the first-blob payload
    ///      capacity 4095*31 = 126,945 bytes; every later blob contributes 4096*31 bytes.
    function blobCountForLength(uint256 proofLength) public pure returns (uint8) {
        if (proofLength == 0) revert EmptyProofPayload();
        uint256 payloadElements = (proofLength + PAYLOAD_BYTES_PER_FIELD_ELEMENT - 1)
            / PAYLOAD_BYTES_PER_FIELD_ELEMENT;
        uint256 totalElements = 1 + payloadElements;
        uint256 count = (totalElements + FIELD_ELEMENTS_PER_BLOB - 1) / FIELD_ELEMENTS_PER_BLOB;
        if (count > MAX_BLOBS) revert ProofPayloadTooLarge(proofLength, count);
        return uint8(count);
    }

    function canonicalProofBytes(bytes memory compactProof) public pure returns (bytes memory) {
        return compactProof;
    }

    function run() external {
        string memory json = vm.readFile(string.concat(vm.projectRoot(), "/", INPUT));
        bytes memory payload = canonicalProofBytes(FixtureLib.parseCompactProofV2(json));
        uint8 blobCount = blobCountForLength(payload.length);
        bytes32 proofHash = keccak256(payload);

        vm.writeFileBinary(string.concat(vm.projectRoot(), "/", OUTPUT), payload);
        vm.writeFile(
            string.concat(vm.projectRoot(), "/", METADATA),
            string.concat(
                "{\n",
                '  "codec": "alloy-simple-coder-v1",\n',
                '  "proof_hash": "',
                vm.toString(proofHash),
                '",\n',
                '  "proof_length": ',
                vm.toString(payload.length),
                ",\n",
                '  "blob_count": ',
                vm.toString(uint256(blobCount)),
                "\n}\n"
            )
        );

        console2.log("proof DA bytes:", payload.length);
        console2.log("proof DA blobs:", blobCount);
        console2.logBytes32(proofHash);
    }
}
