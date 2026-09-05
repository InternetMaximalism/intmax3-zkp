// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IPinnedMleVerifierV2} from "../../src/IPinnedMleVerifierV2.sol";

/// @notice Constructor-pinned V2 verifier stand-in for parent unit tests.
/// @dev The compact-proof surrogate is exactly `abi.encode(uint256[] publicInputs)`.
///      Cryptographic verification and fraud classification are independently
///      controllable so tests cannot accidentally turn configuration, unknown,
///      or resource failures into proof-dependent fraud.
contract MockPinnedMleVerifierV2 is IPinnedMleVerifierV2 {
    error MockMleWrongChain(uint256 actualChainId, uint256 allowedChainId);
    error MockMleVerificationRejected();

    uint8 internal constant MLE_INVALID = 0;
    uint8 internal constant MLE_VALID = 1;
    uint8 internal constant MLE_UNEVALUABLE = 2;
    uint8 internal constant MLE_STARVED = 3;
    uint8 internal constant MLE_PI_MISMATCH = 4;

    uint256 public immutable override allowedChainId;

    bool public verificationVerdict = true;
    uint8 public fraudVerdict = MLE_VALID;

    constructor(uint256 allowedChainId_) {
        allowedChainId = allowedChainId_;
    }

    /// @dev Returning this deployed adapter supplies the production constructor's
    ///      non-empty core-code invariant without introducing another test contract.
    function core() external view virtual override returns (address) {
        return address(this);
    }

    function setVerificationVerdict(bool verdict) external {
        verificationVerdict = verdict;
    }

    /// @dev Compatibility spelling used by existing unit tests.
    function setVerdict(bool verdict) external {
        verificationVerdict = verdict;
    }

    function setFraudVerdict(uint8 verdict) external {
        require(verdict <= MLE_PI_MISMATCH, "mock verdict out of range");
        fraudVerdict = verdict;
    }

    function verifyCompactPublicInputs(bytes calldata compactProof)
        external
        view
        override
        returns (uint256[] memory publicInputs)
    {
        if (block.chainid != allowedChainId) {
            revert MockMleWrongChain(block.chainid, allowedChainId);
        }
        if (!verificationVerdict) revert MockMleVerificationRejected();
        publicInputs = abi.decode(compactProof, (uint256[]));
        if (keccak256(abi.encode(publicInputs)) != keccak256(compactProof)) {
            revert MockMleVerificationRejected();
        }
    }

    function fraudVerdictCompact(bytes calldata, bytes32) external view override returns (uint8 verdict) {
        verdict = block.chainid == allowedChainId ? fraudVerdict : MLE_UNEVALUABLE;
    }
}

    /// @notice Adversarial wiring stub: a distinct adapter address which reports a caller-selected
    ///         core. Parent-constructor tests use it to prove cross-statement core reuse and core-chain
    ///         mismatches fail before any protocol state exists.
    contract MockPinnedMleVerifierV2WithCore is MockPinnedMleVerifierV2 {
        address private immutable _configuredCore;

        constructor(uint256 allowedChainId_, address configuredCore_) MockPinnedMleVerifierV2(allowedChainId_) {
            _configuredCore = configuredCore_;
        }

        function core() external view override returns (address) {
            return _configuredCore;
        }
    }

    library MockPinnedMleVerifierV2Proof {
        function encode(uint256[] memory publicInputs) internal pure returns (bytes memory) {
            return abi.encode(publicInputs);
        }
    }
