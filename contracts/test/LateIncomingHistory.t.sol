// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LateIncomingLifecycleTest} from "./LateIncomingLifecycle.t.sol";
import {CloseFundingMaterializer} from "../src/CloseFundingMaterializer.sol";

/// Production Manager/materializer history control; the inherited Rollup ledger
/// and proof verifier are mocks. This is not a cryptographic soundness test.
contract LateIncomingHistoryTest is LateIncomingLifecycleTest {
    function testFuzz_mixedHistoryWithRejectedReplaysPreservesOrdinaryBudget(bytes32 seed, uint8 count) external {
        count = uint8(bound(count, 2, 8));
        uint256 nativeAmount;
        uint256 tokenAmount;
        uint32 channel = uint32(CHANNEL_ID);
        for (uint256 i; i < count; ++i) {
            uint32 asset = i % 2 == 0 ? 0 : TOKEN;
            uint64 amount = uint64(uint256(keccak256(abi.encode(seed, i))));
            if (amount == 0) amount = 1;
            address recipient = i % 2 == 0 ? alice : bob;
            _receive(asset, amount, recipient, i + 1);
            if (asset == 0) nativeAmount += amount;
            else tokenAmount += amount;

            // Rebase onto the current cursor so the replay reaches the spent
            // nullifier check rather than merely failing an old-cursor check.
            bytes32 cursor = materializer.lateBalanceStateCommitment(channel);
            bytes32 nf = keccak256(abi.encode("incoming", i + 1));
            bytes memory replay = _proof(cursor, keccak256(abi.encode("replay", i)), nf,
                recipient, asset, amount);
            vm.expectRevert(CloseFundingMaterializer.InvalidLateIncoming.selector);
            materializer.claimLateIncoming(manager, replay);
            assertEq(materializer.lateBalanceStateCommitment(channel), cursor);
            assertTrue(materializer.lateReceiveNullifierUsed(channel, nf));
            assertEq(manager.lateIncomingFundAmount(0), nativeAmount);
            assertEq(manager.lateIncomingFundAmount(TOKEN), tokenAmount);
            assertEq(manager.totalWithdrawn(0), nativeAmount);
            assertEq(manager.totalWithdrawn(TOKEN), tokenAmount);
            assertEq(rollup.escrow(0), 1e30 - 75 - nativeAmount);
            assertEq(rollup.escrow(TOKEN), 1e30 - 40 - tokenAmount);
            assertEq(manager.finalizedChannelFundAmount(0) + manager.lateIncomingFundAmount(0)
                - manager.totalWithdrawn(0), 75);
            assertEq(manager.finalizedChannelFundAmount(TOKEN) + manager.lateIncomingFundAmount(TOKEN)
                - manager.totalWithdrawn(TOKEN), 40);
        }
    }
}
