// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CloseE2EBase} from "./CloseE2EBase.sol";
import {ChannelSettlementManager} from "../src/ChannelSettlementManager.sol";

/// @title Print the close-lifecycle ChannelSettlementManager CREATE2 address (test context).
/// @notice Run this FIRST to learn the address to bake into the close withdrawal proof:
///           forge test --match-test test_printCloseManagerAddress -vv
///         then:
///           WD_RECIPIENT=<addr> WD_OUT_PREFIX=close_ cargo run --release --bin generate_withdrawal_fixture
///
/// @dev MUST be a TEST (not a forge script): MleVerifier links external libraries
///      (Plonky2GateEvaluator / SpongefishWhirVerify) whose addresses are baked into
///      `type(MleVerifier).creationCode`, and Foundry resolves those addresses DIFFERENTLY in
///      script vs test execution contexts. So only a TEST yields the same MleVerifier (hence rollup,
///      hence manager) CREATE2 address that `CloseLifecycleE2E.t.sol` actually deploys to.
///      Reads the plain P2 fixtures (VK / genesis / registration are identical to the close set, so
///      the manager address is the same), so it works before the close fixtures exist.
contract CloseManagerAddrTest is CloseE2EBase {
    function test_printCloseManagerAddress() external {
        string memory vkJson = vm.readFile(string.concat(vm.projectRoot(), "/test/data/lifecycle_validity_mle.json"));
        string memory lcJson = vm.readFile(string.concat(vm.projectRoot(), "/test/data/lifecycle.json"));
        (, , , ChannelSettlementManager manager) = _deployAll(vkJson, lcJson);
        emit log_named_address("CLOSE_MANAGER_ADDRESS", address(manager));
    }
}
