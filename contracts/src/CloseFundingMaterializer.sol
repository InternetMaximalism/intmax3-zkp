// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ChannelSettlementManager} from "./ChannelSettlementManager.sol";
import {IntmaxRollup} from "./IntmaxRollup.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";

/// @title Atomic terminal close-funding materializer
/// @notice Installs every authorization for one terminal asset lane and consumes them with the
///         proof-bound Rollup withdrawal in the SAME transaction.
/// @dev IPW2 deliberately does not bind a proof's nullifier: the Manager can authenticate the
///      terminal economics, but not that proof-private identity. Issuing authorizations in an
///      earlier transaction therefore let a different valid proof consume one token's flag and
///      wedge the publisher's original multi-token proof forever. This contract removes that
///      intermediate state. It accepts only the COMPLETE nonzero native or ERC-20 lane committed
///      by the finalized close, authorizes the exact leaves through the Manager, and immediately
///      calls the real withdrawal verifier. Any mismatch or invalid proof reverts every latch.
///
///      The operation remains permissionless. A competing valid proof may win, but only if it
///      materializes the same complete terminal economics into the same Manager. That is a safe
///      semantic success which publishers can adopt from `CloseFundingMaterialized`.
contract CloseFundingMaterializer {
    uint256 private constant MAX_CHANNEL_TOKENS = 10;

    error InvalidRollup();
    error ManagerRollupMismatch();
    error ManagerMaterializerMismatch();
    error EmptyFundingLane();
    error FundingLaneLengthMismatch(uint256 expected, uint256 supplied);
    error FundingRecipientMismatch(uint256 withdrawalIndex);
    error FundingAssetClassMismatch(uint256 withdrawalIndex);
    error FundingTokenNotExpected(uint32 tokenIndex);
    error DuplicateFundingToken(uint32 tokenIndex);
    error FundingAmountMismatch(uint32 tokenIndex, uint256 expected, uint256 supplied);
    error FundingAuxDataMismatch(uint256 withdrawalIndex);

    IntmaxRollup public immutable rollup;

    /// `lane` is 0 for native and 1 for ERC-20. `fundingAuxData` is the Manager-recomputed IMCF
    /// identity. `withdrawalSetDigest` is diagnostic only; semantic adoption keys on the first
    /// three indexed fields and then revalidates Manager/Rollup state at this receipt block.
    event CloseFundingMaterialized(
        address indexed manager,
        uint8 indexed lane,
        bytes32 indexed fundingAuxData,
        bytes32 withdrawalSetDigest
    );

    constructor(IntmaxRollup rollup_) {
        if (address(rollup_).code.length == 0) revert InvalidRollup();
        rollup = rollup_;
    }

    function materializeNative(
        ChannelSettlementManager manager,
        IntmaxRollup.Withdrawal[] calldata withdrawals,
        address withdrawalProver,
        MleVerifier.MleProof calldata mleProof
    ) external {
        bytes32 auxData = _validateCompleteLane(manager, withdrawals, true);
        for (uint256 i = 0; i < withdrawals.length; ++i) {
            manager.authorizeCloseFunding(withdrawals[i].tokenIndex, withdrawals[i].auxData);
        }
        rollup.withdrawNative(withdrawals, withdrawalProver, mleProof);
        emit CloseFundingMaterialized(address(manager), 0, auxData, keccak256(abi.encode(withdrawals)));
    }

    function materializeERC20(
        ChannelSettlementManager manager,
        IntmaxRollup.Withdrawal[] calldata withdrawals,
        address withdrawalProver,
        MleVerifier.MleProof calldata mleProof
    ) external {
        bytes32 auxData = _validateCompleteLane(manager, withdrawals, false);
        for (uint256 i = 0; i < withdrawals.length; ++i) {
            manager.authorizeCloseFunding(withdrawals[i].tokenIndex, withdrawals[i].auxData);
        }
        rollup.withdrawERC20(withdrawals, withdrawalProver, mleProof);
        emit CloseFundingMaterialized(address(manager), 1, auxData, keccak256(abi.encode(withdrawals)));
    }

    function _validateCompleteLane(
        ChannelSettlementManager manager,
        IntmaxRollup.Withdrawal[] calldata withdrawals,
        bool nativeLane
    ) private view returns (bytes32 auxData) {
        if (address(manager.registry()) != address(rollup)) revert ManagerRollupMismatch();
        if (manager.closeFundingMaterializer() != address(this)) revert ManagerMaterializerMismatch();

        uint256 tokenCount = manager.finalizedTokenCount();
        uint256 expectedCount;
        for (uint256 slot = 0; slot < tokenCount; ++slot) {
            uint32 tokenIndex = manager.finalizedTokenRegistry(slot);
            uint256 amount = manager.finalizedChannelFundAmount(tokenIndex);
            if (amount != 0 && ((tokenIndex == 0) == nativeLane)) ++expectedCount;
        }
        if (expectedCount == 0) revert EmptyFundingLane();
        if (withdrawals.length != expectedCount) {
            revert FundingLaneLengthMismatch(expectedCount, withdrawals.length);
        }

        bool[MAX_CHANNEL_TOKENS] memory matchedSlots;
        for (uint256 i = 0; i < withdrawals.length; ++i) {
            IntmaxRollup.Withdrawal calldata withdrawal = withdrawals[i];
            if (withdrawal.recipient != address(manager)) revert FundingRecipientMismatch(i);
            if ((withdrawal.tokenIndex == 0) != nativeLane) revert FundingAssetClassMismatch(i);

            bool found;
            for (uint256 slot = 0; slot < tokenCount; ++slot) {
                uint32 expectedToken = manager.finalizedTokenRegistry(slot);
                uint256 expectedAmount = manager.finalizedChannelFundAmount(expectedToken);
                if (expectedAmount == 0 || ((expectedToken == 0) != nativeLane)) continue;
                if (expectedToken != withdrawal.tokenIndex) continue;
                if (matchedSlots[slot]) revert DuplicateFundingToken(expectedToken);
                if (withdrawal.amount != expectedAmount) {
                    revert FundingAmountMismatch(expectedToken, expectedAmount, withdrawal.amount);
                }
                matchedSlots[slot] = true;
                found = true;
                break;
            }
            if (!found) revert FundingTokenNotExpected(withdrawal.tokenIndex);
            if (i == 0) {
                auxData = withdrawal.auxData;
            } else if (withdrawal.auxData != auxData) {
                revert FundingAuxDataMismatch(i);
            }
        }
    }
}
