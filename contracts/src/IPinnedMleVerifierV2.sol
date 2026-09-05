// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Minimal application-facing ABI for a constructor-pinned MLE/WHIR v2 verifier.
/// @dev Parent contracts deliberately depend only on the compact proof boundary. The concrete
///      adapter owns the circuit-specific verification configuration and its linked v2 core.
interface IPinnedMleVerifierV2 {
    function allowedChainId() external view returns (uint256);

    function core() external view returns (address);

    function verifyCompactPublicInputs(bytes calldata compactProof)
        external
        view
        returns (uint256[] memory publicInputs);

    function fraudVerdictCompact(bytes calldata compactProof, bytes32 expectedPiHash)
        external
        view
        returns (uint8 verdict);
}
