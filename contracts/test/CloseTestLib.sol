// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MleVerifier} from "@mle/MleVerifier.sol";
import {SumcheckVerifier} from "@mle/SumcheckVerifier.sol";
import {SpongefishWhirVerify} from "@mle/spongefish/SpongefishWhirVerify.sol";
import {GoldilocksExt3} from "@mle/spongefish/GoldilocksExt3.sol";
import {Plonky2GateEvaluator} from "@mle/Plonky2GateEvaluator.sol";
import {ChannelSettlementVerifier} from "../src/ChannelSettlementVerifier.sol";

/// @title MockMleVerifier
/// @notice A drop-in stand-in for `@mle/MleVerifier` whose `verify()` returns a CONTROLLABLE bool.
/// @dev INTENTIONALLY SIMPLE (CLAUDE.md "helper contracts that implement real interfaces with
///      simple fixed behavior"): the manager-lifecycle tests exercise the manager's grace /
///      challenge / finalize / cancel logic and the verifier's REAL 95-limb
///      `_bindCloseLimbsStrict` binding — NOT the WHIR cryptography itself (that is covered
///      end-to-end by `CloseLifecycleE2E.t.sol` against the real `MleVerifier` + the real close
///      fixture). This mock lets a lifecycle test drive the close path with a hand-built proof
///      whose `publicInputs` we set to the expected 95 limbs, while still letting us flip the
///      crypto-verdict to `false` to assert the manager rejects a crypto-invalid proof.
///
///      The verifier holds `closeMleVerifier` typed as `MleVerifier`, so a test passes
///      `MleVerifier(address(mock))` to `initializeCloseVk`; the runtime dispatch hits this
///      contract's `verify` by selector. The signature MUST match the real one byte-for-byte.
contract MockMleVerifier {
    bool public verdict = true;

    function setVerdict(bool v) external {
        verdict = v;
    }

    function verify(
        MleVerifier.MleProof calldata,
        MleVerifier.VerifyParams memory,
        SpongefishWhirVerify.WhirParams memory,
        bytes32
    ) external view returns (bool) {
        return verdict;
    }
}

/// @title CloseTestLib
/// @notice Builders for the test-side close `MleVerifier.MleProof` used to drive the (mock-verified)
///         manager-lifecycle tests. The ONLY proof field the real verifier reads for binding is
///         `publicInputs`; everything else is left default and ignored by `MockMleVerifier`.
library CloseTestLib {
    /// Build a close `MleProof` carrying the (95) raw close limbs `limbs` as its `publicInputs`.
    /// All other fields are default — the mock verifier ignores them and the verifier only binds
    /// `publicInputs`.
    function proofWithLimbs(uint256[] memory limbs)
        internal
        pure
        returns (MleVerifier.MleProof memory proof)
    {
        proof.publicInputs = limbs;
    }

    /// A trivial whir-params + empty arrays VK bundle adequate for `initializeCloseVk` in the
    /// mock-verified lifecycle tests (the mock ignores them). `degreeBits` MUST be > 0 to satisfy
    /// the close VK's no-disable-seam guard.
    function dummyVkArgs()
        internal
        pure
        returns (
            ChannelSettlementVerifier.CloseVk memory vk,
            SpongefishWhirVerify.WhirParams memory whir,
            bytes memory protocolId,
            bytes memory sessionId,
            uint256[] memory kIs,
            uint256[] memory subgroupGenPowers
        )
    {
        vk = ChannelSettlementVerifier.CloseVk({
            degreeBits: 1,
            preprocessedRoot: bytes32(uint256(1)),
            numConstants: 1,
            numRoutedWires: 1,
            gatesDigest: bytes32(uint256(2))
        });
        // whir / arrays stay default-empty; the mock verifier never reads them.
        protocolId = hex"";
        sessionId = hex"";
        kIs = new uint256[](0);
        subgroupGenPowers = new uint256[](0);
    }

    /// Phase B-D: trivial `StatementVk` bundle for `initializeWithdrawalClaimVk` /
    /// `initializePostCloseClaimVk` in the mock-verified tests. `degreeBits` MUST be > 0.
    function dummyStatementVkArgs()
        internal
        pure
        returns (
            ChannelSettlementVerifier.StatementVk memory vk,
            SpongefishWhirVerify.WhirParams memory whir,
            bytes memory protocolId,
            bytes memory sessionId,
            uint256[] memory kIs,
            uint256[] memory subgroupGenPowers
        )
    {
        vk = ChannelSettlementVerifier.StatementVk({
            degreeBits: 1,
            preprocessedRoot: bytes32(uint256(1)),
            numConstants: 1,
            numRoutedWires: 1,
            gatesDigest: bytes32(uint256(2))
        });
        protocolId = hex"";
        sessionId = hex"";
        kIs = new uint256[](0);
        subgroupGenPowers = new uint256[](0);
    }
}
