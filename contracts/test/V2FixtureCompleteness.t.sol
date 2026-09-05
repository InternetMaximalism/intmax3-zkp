// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {FixtureLib} from "../script/FixtureLib.sol";

/// @title Non-skipping release gate for every tracked, live full-proof MLE artifact.
/// @notice Individual E2Es may skip while expensive proofs are being regenerated. This suite may
///         not: a release test run fails until every production/E2E fixture is a strict canonical
///         V2 compact artifact with the generated schema, protocol, ABI layout, magic, cap, length
///         and hash. One test per artifact makes stale/missing files visible by name.
/// @dev Proof-free `*_config.json` artifacts have their own strict deployment parser and are not
///      full proofs. The retired member-set-update fixture is intentionally isolated under
///      `test/data/deprecated` and excluded from the live release manifest.
contract V2FixtureCompletenessTest is Test {
    function _assertFullV2(string memory relativePath) private view returns (bytes memory compactProof) {
        string memory json = vm.readFile(string.concat(vm.projectRoot(), relativePath));
        compactProof = FixtureLib.parseCompactProofV2(json);
        assertGt(compactProof.length, 0, relativePath);
    }

    /// @dev Submission, Proof-DA, attestation and fraud all consume the exact compact proof. A
    ///      companion descriptor must commit only to canonical `compactProof.bytes` via its
    ///      Keccak-256 and exact byte length.
    function _assertDaCompanion(string memory proofRelativePath, string memory companionRelativePath) private view {
        bytes memory compactProof = _assertFullV2(proofRelativePath);
        string memory companion = vm.readFile(string.concat(vm.projectRoot(), companionRelativePath));
        assertEq(
            vm.parseJsonBytes32(companion, ".proof_hash"),
            keccak256(compactProof),
            string.concat(companionRelativePath, ": proof_hash != keccak256(compactProof)")
        );
        assertEq(
            vm.parseJsonUint(companion, ".proof_length"),
            compactProof.length,
            string.concat(companionRelativePath, ": proof_length != compactProof.length")
        );
    }

    function test_releaseFixture_genericValidity() public view {
        _assertDaCompanion("/test/data/mle_fixture.json", "/test/data/block_fixture.json");
    }

    function test_releaseFixture_genericLifecycleValidity() public view {
        _assertDaCompanion("/test/data/lifecycle_validity_mle.json", "/test/data/lifecycle.json");
    }

    function test_releaseFixture_genericWithdrawal() public view {
        _assertFullV2("/test/data/withdrawal_mle.json");
    }

    function test_releaseFixture_closeLifecycleValidity() public view {
        _assertDaCompanion("/test/data/close_lifecycle_validity_mle.json", "/test/data/close_lifecycle.json");
    }

    function test_releaseFixture_closeWithdrawal() public view {
        _assertFullV2("/test/data/close_withdrawal_mle.json");
    }

    function test_releaseFixture_closeIntent() public view {
        _assertFullV2("/test/data/close_intent_mle.json");
    }

    function test_releaseFixture_withdrawalClaim() public view {
        _assertFullV2("/test/data/withdrawal_claim_mle.json");
    }

    function test_releaseFixture_postCloseClaim() public view {
        _assertFullV2("/test/data/post_close_claim_mle.json");
    }

    function test_releaseFixture_cancelClose() public view {
        _assertFullV2("/test/data/cancel_close_mle.json");
    }

    function test_releaseFixture_c2cLifecycleValidity() public view {
        _assertDaCompanion("/test/data/c2c_lifecycle_validity_mle.json", "/test/data/c2c_lifecycle.json");
    }

    function test_releaseFixture_c2cWithdrawal() public view {
        _assertFullV2("/test/data/c2c_withdrawal_mle.json");
    }

    function test_releaseFixture_burnLifecycleValidity() public view {
        _assertDaCompanion("/test/data/burn_lifecycle_validity_mle.json", "/test/data/burn_lifecycle.json");
    }

    function test_releaseFixture_burnWithdrawal() public view {
        _assertFullV2("/test/data/burn_withdrawal_mle.json");
    }

    function test_releaseFixture_partialWithdrawalCloseIntent() public view {
        _assertFullV2("/test/data/pw_close_intent_mle.json");
    }

    function test_releaseFixture_sepoliaLifecycleValidity() public view {
        _assertDaCompanion("/test/data/sepolia_lifecycle_validity_mle.json", "/test/data/sepolia_lifecycle.json");
    }

    function test_releaseFixture_sepoliaWithdrawal() public view {
        _assertFullV2("/test/data/sepolia_withdrawal_mle.json");
    }

    function test_releaseFixture_maxResourceEnvelope() public view {
        _assertFullV2("/lib/polygon-plonky2/mle/contracts/test/fixtures/v2_max_resource.json");
    }
}
