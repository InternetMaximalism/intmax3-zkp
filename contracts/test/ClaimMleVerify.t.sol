// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {OuterLogupExt3Verifier} from "@mle/OuterLogupExt3Verifier.sol";
import {MleVerifierV2} from "@mle/MleVerifierV2.sol";
import {PinnedMleVerifierV2} from "@mle/PinnedMleVerifierV2.sol";
import {Plonky2GateEvaluatorExt3} from "@mle/Plonky2GateEvaluatorExt3.sol";
import {PoseidonPublicInputsHash} from "@mle/PoseidonPublicInputsHash.sol";
import {SpongefishWhirVerify} from "@mle/spongefish/SpongefishWhirVerify.sol";
import {FixtureLib} from "../script/FixtureLib.sol";

/// @title Real constructor-pinned V2 verifier acceptance for settlement statements.
/// @dev Each statement fixture is consumed only when it carries the strict V2 schema. Historical
///      V1 ABI fixtures self-skip here rather than being reinterpreted as compact bytes; the
///      non-skipping V2FixtureCompletenessTest and CI anti-skip guard make that a release failure.
contract ClaimMleVerifyTest is Test {
    uint256 private constant MAX_PRODUCTION_VERIFY_GAS = 20_000_000;

    /// Fixtures searched, in order, for a duplicated final-round query row. WHIR's Fiat-Shamir
    /// queries are fixture-specific, so the duplicate is located from the current WHIR shape
    /// instead of pinning byte offsets that move on every regeneration.
    function _duplicateRowCandidates() internal pure returns (string[7] memory) {
        return [
            "withdrawal_claim_mle.json",
            "close_intent_mle.json",
            "post_close_claim_mle.json",
            "cancel_close_mle.json",
            "withdrawal_mle.json",
            "close_withdrawal_mle.json",
            "c2c_withdrawal_mle.json"
        ];
    }

    function _load(string memory name) internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/", name));
    }

    function _loadV2OrSkip(string memory name) internal returns (string memory json) {
        json = _load(name);
        if (!vm.keyExistsJson(json, ".schemaVersion")) {
            vm.skip(true);
            return "";
        }
    }

    function _maxResourceV2() internal view returns (string memory) {
        return vm.readFile(
            string.concat(vm.projectRoot(), "/lib/polygon-plonky2/mle/contracts/test/fixtures/v2_max_resource.json")
        );
    }

    function _assertRealVerifierAccepts(string memory fixtureName) internal {
        string memory json = _loadV2OrSkip(fixtureName);
        (, PinnedMleVerifierV2 adapter) = FixtureLib.deployPinnedMleV2(json);
        bytes memory compactProof = FixtureLib.parseCompactProofV2(json);
        assertTrue(adapter.verifyCompact(compactProof), string.concat("real V2 verifier rejected ", fixtureName));
    }

    function _assertRejected(PinnedMleVerifierV2 adapter, bytes memory compactProof, string memory why) internal view {
        (bool success, bytes memory result) =
            address(adapter).staticcall(abi.encodeCall(PinnedMleVerifierV2.verifyCompact, (compactProof)));
        if (success) assertFalse(abi.decode(result, (bool)), why);
    }

    function test_realMleVerifier_acceptsTrackedV2ResourceProof() public {
        string memory json = _maxResourceV2();
        (, PinnedMleVerifierV2 adapter) = FixtureLib.deployPinnedMleV2(json);
        bytes memory compactProof = FixtureLib.parseCompactProofV2(json);
        assertTrue(adapter.verifyCompact(compactProof));
    }

    function test_realMleVerifier_acceptsWithdrawalClaimProof() public {
        _assertRealVerifierAccepts("withdrawal_claim_mle.json");
    }

    function test_realMleVerifier_acceptsPostCloseClaimProof() public {
        _assertRealVerifierAccepts("post_close_claim_mle.json");
    }

    function test_realMleVerifier_acceptsCancelCloseProof() public {
        _assertRealVerifierAccepts("cancel_close_mle.json");
    }

    function test_realMleVerifier_acceptsCloseProof() public {
        _assertRealVerifierAccepts("close_intent_mle.json");
    }

    /// @dev Measure the exact production adapter entry point with intrinsic calldata gas. The
    /// synthetic resource fixture is not a substitute: it has five gate kinds and one PI, whereas
    /// every live parent circuit has thirteen gate kinds and statement-dependent PI counts.
    function _assertPublicInputsPathFitsProductionGasEnvelope(string memory fixtureName, uint256 expectedPublicInputs)
        internal
    {
        string memory json = _loadV2OrSkip(fixtureName);
        (, PinnedMleVerifierV2 adapter) = FixtureLib.deployPinnedMleV2(json);
        bytes memory compactProof = FixtureLib.parseCompactProofV2(json);
        bytes memory callData = abi.encodeCall(PinnedMleVerifierV2.verifyCompactPublicInputs, (compactProof));

        // Deployment above warms the downstream accounts and every constructor-written adapter
        // slot inside this test transaction. Reset all of them, including the core's runtime-linked
        // libraries. A direct transaction's `to` account is warm by protocol, so cooling the
        // adapter too is conservative; the core, libraries and adapter storage are genuinely cold.
        address core = address(adapter.core());
        vm.cool(core);
        vm.cool(address(OuterLogupExt3Verifier));
        vm.cool(address(Plonky2GateEvaluatorExt3));
        vm.cool(address(PoseidonPublicInputsHash));
        vm.cool(address(SpongefishWhirVerify));
        // Keep this last: reading adapter.core() itself performs a STATICCALL that warms adapter.
        vm.cool(address(adapter));

        // Execute under the actual post-intrinsic 20M budget rather than measuring with unlimited
        // wrapper gas and checking only afterwards. Nested EIP-150 forwarding is therefore part of
        // the acceptance condition.
        uint256 executionBudget = MAX_PRODUCTION_VERIFY_GAS - _calldataIntrinsicGas(callData);
        uint256 gasBefore = gasleft();
        (bool success, bytes memory result) = address(adapter).staticcall{gas: executionBudget}(callData);
        uint256 executionGas = gasBefore - gasleft();
        uint256 transactionGasUpperBound = executionGas + _calldataIntrinsicGas(callData);
        assertTrue(success, string.concat(fixtureName, " PI-return call failed inside production gas cap"));
        uint256[] memory publicInputs = abi.decode(result, (uint256[]));

        emit log_named_string("production V2 gas fixture", fixtureName);
        emit log_named_uint("compact bytes", compactProof.length);
        emit log_named_uint("authenticated public inputs", publicInputs.length);
        emit log_named_uint("PI-return execution gas", executionGas);
        emit log_named_uint("PI-return transaction gas upper bound", transactionGasUpperBound);
        assertEq(publicInputs.length, expectedPublicInputs, "public-input shape drift");
        assertLt(
            transactionGasUpperBound,
            MAX_PRODUCTION_VERIFY_GAS,
            string.concat(fixtureName, " PI-return transaction exceeds production block envelope")
        );
    }

    function test_realValidityPublicInputsPathFitsProductionGasEnvelope() public {
        _assertPublicInputsPathFitsProductionGasEnvelope("mle_fixture.json", 8);
    }

    function test_realWithdrawalPublicInputsPathFitsProductionGasEnvelope() public {
        _assertPublicInputsPathFitsProductionGasEnvelope("withdrawal_mle.json", 17);
    }

    function test_realClosePublicInputsPathFitsProductionGasEnvelope() public {
        _assertPublicInputsPathFitsProductionGasEnvelope("pw_close_intent_mle.json", 103);
    }

    function test_realWithdrawalClaimPublicInputsPathFitsProductionGasEnvelope() public {
        _assertPublicInputsPathFitsProductionGasEnvelope("withdrawal_claim_mle.json", 50);
    }

    function test_realPostCloseClaimPublicInputsPathFitsProductionGasEnvelope() public {
        _assertPublicInputsPathFitsProductionGasEnvelope("post_close_claim_mle.json", 57);
    }

    function test_realCancelClosePublicInputsPathFitsProductionGasEnvelope() public {
        _assertPublicInputsPathFitsProductionGasEnvelope("cancel_close_mle.json", 29);
    }

    function _calldataIntrinsicGas(bytes memory callData) private pure returns (uint256 gasCost) {
        gasCost = 21_000;
        for (uint256 i = 0; i < callData.length; ++i) {
            gasCost += callData[i] == bytes1(0) ? 4 : 16;
        }
    }

    function test_realMleVerifier_rejectsMismatchedFinalDuplicateRow() public {
        string[7] memory candidates = _duplicateRowCandidates();
        for (uint256 c = 0; c < candidates.length; c++) {
            // Each ~1 MB V2 artifact is probed in its OWN call frame: Solidity never releases
            // memory, so scanning all seven fixtures inline exhausts the quadratic memory budget.
            if (this.probeDuplicateFinalRow(candidates[c])) {
                emit log_named_string("duplicate final query fixture", candidates[c]);
                return;
            }
        }
        // WHIR draws 16 final-round queries from a 2^11 domain, so a checked-in proof carries a
        // duplicated query only with ~6% probability per fixture. Regeneration is not
        // reproducible (ZK blinding), so the duplicate-row path can only be exercised against a
        // real proof when one of the fixtures happens to contain one; report that explicitly
        // instead of failing the suite on fixture luck.
        vm.skip(true, "no checked-in proof carries a duplicated final-round query; regenerate one that does");
    }

    /// @dev External only so the candidate loop above can drop this frame's memory. Returns false
    ///      when the fixture is not V2 or carries no duplicated final-round row; otherwise proves
    ///      the verifier rejects the one-byte mutation of the repeated row (assertions revert on
    ///      failure, which fails the calling test).
    function probeDuplicateFinalRow(string calldata fixtureName) external returns (bool found) {
        require(msg.sender == address(this), "probe is an internal frame");
        string memory json = _load(fixtureName);
        // Historical V1 ABI fixtures carry no compact bytes and are never reinterpreted.
        if (!vm.keyExistsJson(json, ".schemaVersion")) return false;
        bytes memory hints = vm.parseJsonBytes(json, ".proof.whirHints");
        uint256 duplicateOffset;
        (found, duplicateOffset) = _findFinalDuplicateRow(hints, _verificationConfig(json).whir);
        if (!found) return false;

        (, PinnedMleVerifierV2 adapter) = FixtureLib.deployPinnedMleV2(json);
        bytes memory compactProof = FixtureLib.parseCompactProofV2(json);
        assertTrue(adapter.verifyCompact(compactProof), "unmodified fixture verifies");
        // The verifier sorts/hash-deduplicates rows before evaluating the opening. A one-byte
        // mutation in the repeated row must therefore hit the explicit duplicate-hash equality
        // check, rather than letting Merkle dedup silently authenticate only the first copy.
        uint256 target = _compactWhirHintsOffset(compactProof, json, hints) + duplicateOffset;
        compactProof[target] = bytes1(uint8(compactProof[target]) ^ 1);
        _assertRejected(adapter, compactProof, "mismatched duplicate final-round row accepted");
    }

    /// @dev The exact constructor-pinned configuration the adapter was deployed from. Its WHIR
    ///      shape (final-round query count / interleaving depth / Merkle depth) locates the rows.
    function _verificationConfig(string memory json) internal pure returns (MleVerifierV2.VerificationConfig memory) {
        return abi.decode(
            vm.parseJsonBytes(json, ".solidityAbiVerificationConfig.bytes"), (MleVerifierV2.VerificationConfig)
        );
    }

    /// @dev Byte offset of the opaque `whirHints` stream inside the canonical `MLEWHIR3` compact
    ///      encoding: magic(8) | protocolVersion(8) | constituentWidth(4) | circuitDigest(4x8) |
    ///      publicInputs(n x 8) | three roots(3x32) | u32 len + whirTranscript | u32 len + hints.
    ///      The field lengths come from the fixture's structured proof, and the located window is
    ///      cross-checked byte-for-byte against the fixture's own `whirHints`, so a codec change
    ///      cannot silently move the mutation into a different proof field.
    function _compactWhirHintsOffset(bytes memory compactProof, string memory json, bytes memory hints)
        internal
        pure
        returns (uint256 offset)
    {
        uint256 publicInputCount = vm.parseJsonStringArray(json, ".proof.publicInputs").length;
        uint256 transcriptLength = vm.parseJsonBytes(json, ".proof.whirTranscript").length;
        offset = 8 + 8 + 4 + 4 * 8 + publicInputCount * 8 + 3 * 32 + 4 + transcriptLength + 4;
        require(offset + hints.length <= compactProof.length, "compact hints out of range");
        bytes memory window = new bytes(hints.length);
        for (uint256 i = 0; i < window.length; i++) {
            window[i] = compactProof[offset + i];
        }
        require(keccak256(window) == keccak256(hints), "compact hints offset drift");
    }

    /// Locate the second copy of a duplicated final-round query row. The final intermediate
    /// commitment is opened as an Arkworks Vec of `inDomainSamples` rows of `interleavingDepth`
    /// extension-field elements (24 bytes each); rows are serialized in transcript order, so a
    /// repeated query index yields byte-identical rows.
    function _findFinalDuplicateRow(bytes memory hints, SpongefishWhirVerify.WhirParams memory whir)
        internal pure returns (bool found, uint256 duplicateOffset)
    {
        if (whir.numRounds == 0 || whir.rounds.length != whir.numRounds) return (false, 0);
        SpongefishWhirVerify.RoundParams memory finalRound = whir.rounds[whir.numRounds - 1];
        uint256 rawQueryCount = finalRound.inDomainSamples;
        uint256 rowBytes = finalRound.interleavingDepth * 24;
        uint256 expectedElements = rawQueryCount * finalRound.interleavingDepth;
        if (expectedElements > type(uint64).max) return (false, 0);
        (bool prefixFound, uint256 prefixOffset) = _findUniqueFinalVecPrefix(
            hints, uint64(expectedElements), rawQueryCount, rowBytes, finalRound.merkleDepth
        );
        if (!prefixFound) return (false, 0);
        uint256 rowsStart = prefixOffset + 8;
        bytes32[] memory rowHashes = new bytes32[](rawQueryCount);
        for (uint256 i = 0; i < rawQueryCount; i++) {
            bytes memory row = new bytes(rowBytes);
            for (uint256 b = 0; b < rowBytes; b++) row[b] = hints[rowsStart + i * rowBytes + b];
            rowHashes[i] = keccak256(row);
            for (uint256 j = 0; j < i; j++) {
                if (rowHashes[j] == rowHashes[i]) return (true, rowsStart + i * rowBytes);
            }
        }
        return (false, 0);
    }

    /// @dev Locate the final canonical Arkworks u64-LE prefix. Besides exact 64-bit matching, the
    ///      candidate must leave exactly the final raw rows followed only by whole Merkle hashes,
    ///      bounded by one sibling per query per tree layer. This ties the dynamic location to the
    ///      final-opening shape instead of accepting an equal 8-byte sequence in arbitrary row data.
    ///      Returns `found == false` (never reverts) when the stream carries no unique such prefix,
    ///      so a fixture whose hint grammar differs simply drops out of the candidate search.
    function _findUniqueFinalVecPrefix(
        bytes memory data,
        uint64 needle,
        uint256 rawQueryCount,
        uint256 rowBytes,
        uint256 merkleDepth
    ) internal pure returns (bool found, uint256 offset) {
        if (data.length < 8) return (false, 0);
        uint256 rowsBytes = rawQueryCount * rowBytes;
        uint256 maxMerkleBytes = rawQueryCount * merkleDepth * 32;
        for (uint256 i = 0; i <= data.length - 8; i++) {
            if (_readU64LeAt(data, i) != needle) continue;
            uint256 rowsEnd = i + 8 + rowsBytes;
            if (rowsEnd > data.length) continue;
            uint256 merkleBytes = data.length - rowsEnd;
            if (merkleBytes % 32 != 0 || merkleBytes > maxMerkleBytes) continue;
            if (found) return (false, 0); // ambiguous
            found = true;
            offset = i;
        }
    }

    function _readU64LeAt(bytes memory data, uint256 offset) internal pure returns (uint64 value) {
        assembly {
            let word := shr(192, mload(add(add(data, 0x20), offset)))
            word := or(and(shr(8, word), 0x00FF00FF00FF00FF), and(shl(8, word), 0xFF00FF00FF00FF00))
            word := or(and(shr(16, word), 0x0000FFFF0000FFFF), and(shl(16, word), 0xFFFF0000FFFF0000))
            value := and(or(shr(32, word), shl(32, word)), 0xFFFFFFFFFFFFFFFF)
        }
    }

    /// @notice Arkworks' Vec prefix is part of the canonical proof encoding, not padding. The final
    ///         intermediate opening's u64-LE prefix is located from the pinned WHIR shape instead
    ///         of a hard-coded byte offset, so regeneration cannot silently retarget the flip.
    function test_realMleVerifier_rejectsWrongWhirVectorLengthPrefix() public {
        string memory json = _loadV2OrSkip("close_intent_mle.json");
        (, PinnedMleVerifierV2 adapter) = FixtureLib.deployPinnedMleV2(json);
        bytes memory compactProof = FixtureLib.parseCompactProofV2(json);
        bytes memory hints = vm.parseJsonBytes(json, ".proof.whirHints");
        SpongefishWhirVerify.WhirParams memory whir = _verificationConfig(json).whir;
        require(whir.numRounds > 0, "close fixture needs an intermediate WHIR round");
        require(whir.rounds.length == whir.numRounds, "close WHIR round count mismatch");
        SpongefishWhirVerify.RoundParams memory finalRound = whir.rounds[whir.numRounds - 1];
        uint256 expectedElements = finalRound.inDomainSamples * finalRound.interleavingDepth;
        require(expectedElements <= type(uint64).max, "final Vec length exceeds u64");
        (bool found, uint256 prefixOffset) = _findUniqueFinalVecPrefix(
            hints,
            uint64(expectedElements),
            finalRound.inDomainSamples,
            finalRound.interleavingDepth * 24,
            finalRound.merkleDepth
        );
        require(found, "final Vec prefix not found in compact WHIR hints");
        uint256 target = _compactWhirHintsOffset(compactProof, json, hints) + prefixOffset;
        compactProof[target] = bytes1(uint8(compactProof[target]) ^ 1);
        _assertRejected(adapter, compactProof, "tampered WHIR Vec length prefix accepted");
    }

    function test_realMleVerifier_rejectsTrailingWhirHints() public {
        string memory json = _loadV2OrSkip("close_intent_mle.json");
        (, PinnedMleVerifierV2 adapter) = FixtureLib.deployPinnedMleV2(json);
        bytes memory compactProof = bytes.concat(FixtureLib.parseCompactProofV2(json), hex"00");
        _assertRejected(adapter, compactProof, "trailing compact byte accepted");
    }

    function test_realMleVerifier_rejectsTamperedWithdrawalClaimProof() public {
        string memory json = _loadV2OrSkip("withdrawal_claim_mle.json");
        (, PinnedMleVerifierV2 adapter) = FixtureLib.deployPinnedMleV2(json);
        bytes memory compactProof = FixtureLib.parseCompactProofV2(json);
        compactProof[compactProof.length / 2] = bytes1(uint8(compactProof[compactProof.length / 2]) ^ 1);
        _assertRejected(adapter, compactProof, "tampered withdrawal proof accepted");
    }
}
