// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IForcedTxLogic
/// @notice Interface for external contracts that supply forced Intmax transactions.
///         Each user may register one logic contract at ID registration time.
///         When `insertIntmaxTx()` is called, the contract returns the hash of an
///         Intmax transaction to be forcibly included, or `bytes32(0)` to signal
///         that no transaction should be inserted.
interface IForcedTxLogic {
    /// @notice Called by IntmaxRollup.queueForcedTx() to request a forced tx.
    /// @return txHash  The Intmax transaction hash to insert, or bytes32(0) for none.
    function insertIntmaxTx() external returns (bytes32 txHash);

    /// @notice Called by IntmaxRollup.registerForcedTxLogic() to confirm the
    ///         contract accepts being registered for a specific userId.
    ///         Must return the same userId to confirm acceptance.
    /// @param userId  The Intmax user ID being registered.
    /// @return confirmedUserId  Must equal userId to accept.
    function acceptRegistration(uint64 userId) external returns (uint64 confirmedUserId);
}
