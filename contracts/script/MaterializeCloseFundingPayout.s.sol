// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {ChannelSettlementManager} from "../src/ChannelSettlementManager.sol";
import {CloseFundingMaterializer} from "../src/CloseFundingMaterializer.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {FixtureLib} from "./FixtureLib.sol";

/// @title Keyless close-funding payout calldata materializer
/// @notice Parses one already-produced terminal payout lane and writes only its ABI calldata.
/// @dev This helper deliberately has no `startBroadcast`, private-key, account, or RPC path. The
///      Rust close-funding publisher validates the JSON independently, hashes this output, pins its
///      selector to a release manifest, signs the exact bytes with `cast mktx`, and fsyncs that raw
///      transaction before it is ever published.
contract MaterializeCloseFundingPayout is Script {
    function run() external {
        string memory payout = vm.readFile(vm.envString("CF_PAYOUT_PATH"));
        string memory mle = vm.readFile(vm.envString("CF_MLE_PATH"));
        uint256 count = vm.envUint("CF_WITHDRAWAL_COUNT");
        require(count > 0 && count <= 10, "close-funding lane size out of range");

        IntmaxRollup.Withdrawal[] memory withdrawals = new IntmaxRollup.Withdrawal[](count);
        for (uint256 i = 0; i < count; i++) {
            string memory prefix = string.concat(".withdrawals[", vm.toString(i), "]");
            uint256 tokenIndex = vm.parseJsonUint(payout, string.concat(prefix, ".token_index"));
            require(tokenIndex <= type(uint32).max, "close-funding token index overflow");
            withdrawals[i] = IntmaxRollup.Withdrawal({
                recipient: vm.parseJsonAddress(payout, string.concat(prefix, ".recipient")),
                tokenIndex: uint32(tokenIndex),
                amount: vm.parseUint(vm.parseJsonString(payout, string.concat(prefix, ".amount"))),
                nullifier: vm.parseJsonBytes32(payout, string.concat(prefix, ".nullifier")),
                auxData: vm.parseJsonBytes32(payout, string.concat(prefix, ".aux_data"))
            });
        }

        address prover = vm.parseJsonAddress(payout, ".withdrawal_prover");
        ChannelSettlementManager manager = ChannelSettlementManager(payable(vm.envAddress("CF_MANAGER")));
        MleVerifier.MleProof memory proof = FixtureLib.parseProof(mle);
        string memory lane = vm.envString("CF_LANE");
        bytes memory callData;
        if (keccak256(bytes(lane)) == keccak256("native")) {
            for (uint256 i = 0; i < count; i++) {
                require(withdrawals[i].tokenIndex == 0, "native lane contains ERC-20");
            }
            callData = abi.encodeCall(
                CloseFundingMaterializer.materializeNative, (manager, withdrawals, prover, proof)
            );
        } else {
            require(keccak256(bytes(lane)) == keccak256("erc20"), "unknown close-funding lane");
            for (uint256 i = 0; i < count; i++) {
                require(withdrawals[i].tokenIndex != 0, "ERC-20 lane contains native token");
            }
            callData = abi.encodeCall(
                CloseFundingMaterializer.materializeERC20, (manager, withdrawals, prover, proof)
            );
        }
        vm.writeFile(vm.envString("CF_CALLDATA_OUT"), vm.toString(callData));
    }
}
