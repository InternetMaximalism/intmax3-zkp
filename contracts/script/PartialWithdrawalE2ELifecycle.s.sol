// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {ChannelSettlementManager} from "../src/ChannelSettlementManager.sol";
import {CloseFundingMaterializer} from "../src/CloseFundingMaterializer.sol";
import {FixtureLib} from "./FixtureLib.sol";

/// @title PartialWithdrawalE2ELifecycle
/// @notice Local-devnet steps of `tests/partial_withdrawal_e2e.rs` that need a Solidity ABI
///         encoder for large calldata (a 130 KB compact validity proof, its KZG sidecars and the
///         whole-vector backing proof cannot be passed as `cast` argv on every platform).
/// @dev The blob-carrying `postBlockAndSubmit` transactions are sent by the Rust test with
///      `cast mktx --blob` (EIP-4844 blobs cannot be attached by a forge script). Every artifact is
///      read from `PW_E2E_DIR`, a directory the test writes under the gitignored
///      `proof-da-output/` tree (readable through `fs_permissions`), never from `test/data`.
contract PartialWithdrawalE2ELifecycle is Script {
    function _rollup() internal view returns (IntmaxRollup) {
        return IntmaxRollup(payable(vm.envAddress("ROLLUP")));
    }

    function _artifact(string memory name) internal view returns (string memory) {
        return vm.readFile(string.concat(vm.envString("PW_E2E_DIR"), "/", name));
    }

    function _validityCompactProof() internal view returns (bytes memory) {
        return FixtureLib.parseCompactProofV2(_artifact("pw_lifecycle_validity_mle.json"));
    }

    /// @notice `attestProofData` for the last posted submission with the exact blob sidecars the
    ///         Rust test validated against the signed blob transaction.
    function attestProofData() external {
        require(block.chainid == 31337, "local-devnet only: partial-withdrawal E2E");
        uint256 subId = vm.envUint("SUB_ID");
        bytes memory blobSidecars = vm.envBytes("BLOB_SIDECARS");
        bytes memory compactProof = _validityCompactProof();

        vm.startBroadcast();
        bytes32 digest = _rollup().attestProofData(subId, compactProof, blobSidecars);
        vm.stopBroadcast();
        console2.log("PW_E2E_PROOF_DATA_ATTESTED:");
        console2.logBytes32(digest);
    }

    /// @notice Finalize the whole posted chain with the real multi-block validity MLE proof.
    function finalize() external {
        require(block.chainid == 31337, "local-devnet only: partial-withdrawal E2E");
        string memory lc = _artifact("pw_lifecycle.json");
        IntmaxRollup.ValidityPublicInputs memory vpis;
        vpis.initialBlockNumber = uint64(vm.parseJsonUint(lc, ".vpis.initial_block_number"));
        vpis.initialBlockChain = vm.parseJsonBytes32(lc, ".vpis.initial_block_chain");
        vpis.initialExtCommitment = vm.parseJsonBytes32(lc, ".vpis.initial_ext_commitment");
        vpis.finalBlockNumber = uint64(vm.parseJsonUint(lc, ".vpis.final_block_number"));
        vpis.finalBlockChain = vm.parseJsonBytes32(lc, ".vpis.final_block_chain");
        vpis.finalExtCommitment = vm.parseJsonBytes32(lc, ".vpis.final_ext_commitment");
        vpis.prover = vm.parseJsonAddress(lc, ".vpis.prover");
        bytes32 finalRoot = vm.parseJsonBytes32(lc, ".final_state_root");
        uint256 subId = vm.envUint("SUB_ID");
        bytes memory compactProof = _validityCompactProof();

        vm.startBroadcast();
        bool ok = _rollup().finalize(subId, finalRoot, vpis, compactProof);
        vm.stopBroadcast();
        require(ok, "finalize returned false (validity MLE verification or PI binding failed)");
        require(_rollup().latestFinalizedStateRoot() == finalRoot, "finalized root mismatch");
        console2.log("PW_E2E_FINALIZED_BLOCK:", _rollup().latestFinalizedBlockNumber());
    }

    /// @notice Attest the whole-vector CloseAssetBacking proof of the post-burn head, which
    ///         `submitPartialWithdrawalIntent` requires through `requireSignedHeadBacking`.
    function attestBacking() external {
        require(block.chainid == 31337, "local-devnet only: partial-withdrawal E2E");
        ChannelSettlementManager manager = ChannelSettlementManager(payable(vm.envAddress("MANAGER")));
        CloseFundingMaterializer materializer = CloseFundingMaterializer(address(manager.closeFundingMaterializer()));
        bytes memory backingProof = FixtureLib.parseCompactProofV2(_artifact("pw_backing_mle.json"));

        vm.startBroadcast();
        materializer.attestSignedHeadBacking(manager, backingProof);
        vm.stopBroadcast();
        console2.log("PW_E2E_BACKING_ATTESTED materializer:", address(materializer));
    }
}
