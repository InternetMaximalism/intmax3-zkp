// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BlobKZGVerifierExt} from "../../src/BlobKZGVerifier.sol";

/// @dev Legacy test-only carrier retained while old fraud regressions are expressed through the
///      new compact Proof-DA API. Production code never imports or decodes this type.
struct KZGProof {
    bytes kzgCommitment48;
    bytes kzgCommitmentG1;
    bytes openingProof;
    bytes vanishingG2;
    bytes lagrangeBasisG1;
}

/// @notice Lightweight Proof-DA satellite for tests whose subject is not KZG or blob encoding.
/// @dev It deliberately bypasses blob/proof binding so pre-existing tests can isolate unrelated
///      rollup invariants while calling the new API. It still binds the state root and submission
///      block so those lifecycle checks remain live. Dedicated BlobKzgPairing/ProofDaRollup tests
///      exercise canonical proof bytes, exact blob counts/hashes, and the 0x0a precompile.
contract TestProofDaVerifier {
    bytes32 private constant PROOF_DA_DOMAIN = keccak256("INTMAX3_PROOF_DA_V3");
    bytes32 private constant PROOF_ATTESTATION_DOMAIN = keccak256("INTMAX3_PROOF_ATTESTATION_V1");
    mapping(bytes32 => bytes32) private _attested;
    error UnexpectedSidecar();

    function postCommitment(
        bytes32 stateRoot,
        uint64 submittedAtBlock,
        uint256 submissionId
    ) external pure returns (bytes32) {
        return _commitment(stateRoot, submittedAtBlock, submissionId);
    }

    function verifyAndCommit(
        bytes calldata,
        bytes calldata sidecars,
        bytes32 stateRoot,
        uint64 submittedAtBlock,
        uint256 submissionId
    ) external pure returns (bytes32) {
        if (sidecars.length != 0) revert UnexpectedSidecar();
        return _commitment(stateRoot, submittedAtBlock, submissionId);
    }

    function attestProofData(address rollup, uint256 submissionId, bytes calldata proofBytes, bytes calldata sidecars)
        external
        returns (bytes32 digest)
    {
        if (sidecars.length != 0) revert UnexpectedSidecar();
        (bool ok, bytes memory context) = rollup.staticcall(
            abi.encodeWithSelector(bytes4(keccak256("getSubmission(uint256)")), submissionId)
        );
        require(ok && context.length == 160, "context");
        (bytes32 commitment,,,,) = abi.decode(context, (bytes32, address, bool, uint64, bytes32));
        digest = _digest(keccak256(proofBytes), proofBytes.length);
        _attested[keccak256(abi.encode(rollup, submissionId, commitment))] = digest;
    }

    function isProofDataAttested(
        uint256,
        bytes32,
        bytes32,
        uint256
    ) external pure returns (bool) {
        // Tests using this mock intentionally isolate non-DA behavior. Production journal binding
        // is covered with BlobKZGVerifierExt in ProofDaRollup/BlobKzgPairing.
        return true;
    }

    function asProductionType() external view returns (BlobKZGVerifierExt) {
        return BlobKZGVerifierExt(address(this));
    }

    function _commitment(
        bytes32 stateRoot,
        uint64 submittedAtBlock,
        uint256 submissionId
    ) private pure returns (bytes32) {
        return keccak256(
            abi.encode(
                PROOF_DA_DOMAIN,
                bytes32(0),
                bytes32(0),
                uint8(1),
                stateRoot,
                submittedAtBlock,
                submissionId
            )
        );
    }

    function _digest(bytes32 proofHash, uint256 proofLength) private pure returns (bytes32) {
        return keccak256(abi.encode(PROOF_ATTESTATION_DOMAIN, proofHash, proofLength));
    }
}
