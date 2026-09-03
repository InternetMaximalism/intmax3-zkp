// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title CloseTestLib
/// @notice Compact-proof surrogate builders for mock-verified settlement unit tests.
/// @dev Production consumes canonical MLE/WHIR V2 compact bytes. Unit tests that
///      exercise only application binding encode the authenticated public-input
///      vector as `abi.encode(uint256[])`; `MockPinnedMleVerifierV2` is the sole
///      decoder for this deliberately small test grammar.
library CloseTestLib {
    function proofWithLimbs(uint256[] memory limbs) internal pure returns (bytes memory) {
        return abi.encode(limbs);
    }
}
