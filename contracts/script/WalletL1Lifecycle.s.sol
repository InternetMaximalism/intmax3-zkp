// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {Script} from "forge-std/Script.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {ChannelSettlementManager} from "../src/ChannelSettlementManager.sol";
import {CloseFundingMaterializer} from "../src/CloseFundingMaterializer.sol";
import {FixtureLib} from "./FixtureLib.sol";

/// Local wallet orchestration only. Every proof is checked by the deployed pinned verifier.
contract WalletL1Lifecycle is Script {
    function finalizeValidity() external {
        require(block.chainid == 31337, "local wallet only");
        IntmaxRollup rollup = IntmaxRollup(payable(vm.envAddress("ROLLUP")));
        string memory j = vm.readFile(vm.envString("WALLET_VPIS_PATH"));
        bytes memory proof = FixtureLib.parseCompactProofV2(vm.readFile(vm.envString("WALLET_VALIDITY_PATH")));
        IntmaxRollup.ValidityPublicInputs memory p;
        p.initialBlockNumber = uint64(vm.parseJsonUint(j, ".initial_block_number"));
        p.initialBlockChain = vm.parseJsonBytes32(j, ".initial_block_chain");
        p.initialExtCommitment = vm.parseJsonBytes32(j, ".initial_ext_commitment");
        p.finalBlockNumber = uint64(vm.parseJsonUint(j, ".final_block_number"));
        p.finalBlockChain = vm.parseJsonBytes32(j, ".final_block_chain");
        p.finalExtCommitment = vm.parseJsonBytes32(j, ".final_ext_commitment");
        p.prover = vm.parseJsonAddress(j, ".prover");
        uint256 subId = vm.envUint("SUB_ID");
        vm.startBroadcast();
        if (!rollup.isFinalizedStateRoot(p.finalExtCommitment)) {
            rollup.attestProofData(subId, proof, vm.envBytes("BLOB_SIDECARS"));
            require(rollup.finalize(subId, p.finalExtCommitment, p, proof), "validity finalization failed");
        }
        vm.stopBroadcast();
        require(rollup.latestFinalizedBlockNumber() >= p.finalBlockNumber, "finalized height mismatch");
    }
    function attestBacking() external {
        require(block.chainid == 31337, "local wallet only");
        ChannelSettlementManager manager = ChannelSettlementManager(payable(vm.envAddress("MANAGER")));
        CloseFundingMaterializer materializer = CloseFundingMaterializer(address(manager.closeFundingMaterializer()));
        bytes memory proof = FixtureLib.parseCompactProofV2(vm.readFile(vm.envString("WALLET_BACKING_PATH")));
        vm.startBroadcast();
        materializer.attestSignedHeadBacking(manager, proof);
        vm.stopBroadcast();
    }
}
