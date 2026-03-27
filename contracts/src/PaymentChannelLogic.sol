// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IForcedTxLogic} from "./IForcedTxLogic.sol";

/// @title PaymentChannelLogic
/// @notice AccountLogic contract for N-party payment channels on the Intmax
///         Forced TX Queue.  All state-changing functions are restricted to
///         channel members only.
///
///         State machine:
///           Open → Closing → Finalized → Closed
///
///         See docs/PaymentChannel.md for the full protocol specification.
contract PaymentChannelLogic is IForcedTxLogic {
    // -----------------------------------------------------------------------
    // Errors
    // -----------------------------------------------------------------------
    error NotMember();
    error NotRollup();
    error InvalidState(State expected, State actual);
    error SequenceNotHigher();
    error InitiatorCannotEndorse();
    error AlreadyEndorsed();
    error CannotFinalizeYet();
    error NoMembers();
    error ChallengePeriodTooShort();

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------
    event ChannelCloseInitiated(
        address indexed initiator,
        uint64 sequence,
        bytes32 txTreeRoot,
        uint256 challengeDeadline
    );

    event ChannelChallenged(
        address indexed challenger,
        uint64 sequence,
        bytes32 txTreeRoot,
        uint256 newDeadline
    );

    event MemberEndorsed(address indexed member);

    event ChannelFinalized(uint64 sequence, bytes32 txTreeRoot);

    event ChannelClosed(bytes32 txTreeRoot);

    // -----------------------------------------------------------------------
    // Types
    // -----------------------------------------------------------------------
    enum State {
        Open,
        Closing,
        Finalized,
        Closed
    }

    // -----------------------------------------------------------------------
    // Immutables
    // -----------------------------------------------------------------------
    address public immutable rollup;
    uint256 public immutable challengePeriod;

    // -----------------------------------------------------------------------
    // State
    // -----------------------------------------------------------------------
    State public state;

    address[] public members;
    mapping(address => bool) public isMember;

    /// @notice The member who initiated closeChannel.
    address public closeInitiator;

    /// @notice The latest submitted sequence number.
    uint64 public latestSequence;

    /// @notice The tx tree root corresponding to latestSequence.
    bytes32 public latestTxTreeRoot;

    /// @notice Timestamp after which the timeout path becomes available.
    uint256 public challengeDeadline;

    /// @notice Tracks which members have endorsed the current latest state.
    mapping(address => bool) public hasEndorsed;

    /// @notice Number of non-initiator members who have endorsed.
    uint256 public endorseCount;

    // -----------------------------------------------------------------------
    // Modifiers
    // -----------------------------------------------------------------------
    modifier onlyMember() {
        if (!isMember[msg.sender]) revert NotMember();
        _;
    }

    modifier inState(State expected) {
        if (state != expected) revert InvalidState(expected, state);
        _;
    }

    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------

    /// @param _rollup          Address of the IntmaxRollup contract.
    /// @param _members         Ethereum addresses of all channel members.
    /// @param _challengePeriod Challenge period in seconds (e.g. 259200 for 3 days).
    constructor(
        address _rollup,
        address[] memory _members,
        uint256 _challengePeriod
    ) {
        if (_members.length == 0) revert NoMembers();
        if (_challengePeriod < 1 hours) revert ChallengePeriodTooShort();

        rollup = _rollup;
        challengePeriod = _challengePeriod;

        for (uint256 i = 0; i < _members.length; i++) {
            members.push(_members[i]);
            isMember[_members[i]] = true;
        }
    }

    // -----------------------------------------------------------------------
    // closeChannel — initiate channel close
    // -----------------------------------------------------------------------

    /// @notice Initiate a channel close by submitting the latest agreed state.
    /// @param sequence    The sequence number of the channel state.
    /// @param txTreeRoot  The pre-computed Intmax tx tree root for this state.
    function closeChannel(uint64 sequence, bytes32 txTreeRoot)
        external
        onlyMember
        inState(State.Open)
    {
        state = State.Closing;
        closeInitiator = msg.sender;
        latestSequence = sequence;
        latestTxTreeRoot = txTreeRoot;
        challengeDeadline = block.timestamp + challengePeriod;

        emit ChannelCloseInitiated(msg.sender, sequence, txTreeRoot, challengeDeadline);
    }

    // -----------------------------------------------------------------------
    // challenge — submit a newer state during the challenge period
    // -----------------------------------------------------------------------

    /// @notice Submit a state with a higher sequence number.
    ///         Resets all endorsements and extends the challenge deadline.
    /// @param sequence    Must be strictly greater than latestSequence.
    /// @param txTreeRoot  The tx tree root for the new state.
    function challenge(uint64 sequence, bytes32 txTreeRoot)
        external
        onlyMember
        inState(State.Closing)
    {
        if (sequence <= latestSequence) revert SequenceNotHigher();

        latestSequence = sequence;
        latestTxTreeRoot = txTreeRoot;

        // Extend deadline so members have time to review the new state
        uint256 newDeadline = block.timestamp + challengePeriod;
        if (newDeadline > challengeDeadline) {
            challengeDeadline = newDeadline;
        }

        // Reset all endorsements
        _resetEndorsements();

        emit ChannelChallenged(msg.sender, sequence, txTreeRoot, challengeDeadline);
    }

    // -----------------------------------------------------------------------
    // endorse — approve the current latest state
    // -----------------------------------------------------------------------

    /// @notice Endorse the current latest state.  Only non-initiator members
    ///         may endorse.  The initiator is assumed to endorse by having
    ///         initiated or not challenged.
    function endorse()
        external
        onlyMember
        inState(State.Closing)
    {
        if (msg.sender == closeInitiator) revert InitiatorCannotEndorse();
        if (hasEndorsed[msg.sender]) revert AlreadyEndorsed();

        hasEndorsed[msg.sender] = true;
        endorseCount++;

        emit MemberEndorsed(msg.sender);
    }

    // -----------------------------------------------------------------------
    // finalize — transition to Finalized when conditions are met
    // -----------------------------------------------------------------------

    /// @notice Finalize the channel close.  Requires that all non-initiator
    ///         members have endorsed, and either:
    ///         (a) immediate path — endorsements alone are sufficient, OR
    ///         (b) timeout path  — the challenge deadline has passed.
    ///
    ///         After finalization, anyone may call queueForcedTx() on the
    ///         rollup to trigger insertIntmaxTx().
    function finalize()
        external
        onlyMember
        inState(State.Closing)
    {
        bool _allEndorsed = endorseCount == members.length - 1;

        // Immediate path: all non-initiator members endorsed
        // Timeout path:   deadline passed AND all endorsed
        if (!_allEndorsed) revert CannotFinalizeYet();

        state = State.Finalized;

        emit ChannelFinalized(latestSequence, latestTxTreeRoot);
    }

    // -----------------------------------------------------------------------
    // insertIntmaxTx — IForcedTxLogic implementation
    // -----------------------------------------------------------------------

    /// @notice Called by IntmaxRollup.queueForcedTx().
    ///         Returns the tx tree root only when the channel is Finalized.
    ///         Transitions to Closed after returning.
    /// @return txHash The Intmax tx tree root, or bytes32(0) if not ready.
    function acceptRegistration(uint64 userId) external view returns (uint64) {
        if (msg.sender != rollup) revert NotRollup();
        return userId;
    }

    function insertIntmaxTx() external returns (bytes32 txHash) {
        // Only the rollup contract may call this
        if (msg.sender != rollup) revert NotRollup();

        if (state != State.Finalized) {
            return bytes32(0);
        }

        state = State.Closed;
        emit ChannelClosed(latestTxTreeRoot);
        return latestTxTreeRoot;
    }

    // -----------------------------------------------------------------------
    // View helpers
    // -----------------------------------------------------------------------

    /// @notice Returns the number of channel members.
    function memberCount() external view returns (uint256) {
        return members.length;
    }

    /// @notice Returns true if all non-initiator members have endorsed.
    function allEndorsed() external view returns (bool) {
        return endorseCount == members.length - 1;
    }

    /// @notice Returns true if the challenge deadline has passed.
    function deadlinePassed() external view returns (bool) {
        return block.timestamp >= challengeDeadline;
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    /// @dev Reset all endorsement state.  Called when a challenge updates the
    ///      latest state.
    function _resetEndorsements() internal {
        for (uint256 i = 0; i < members.length; i++) {
            if (hasEndorsed[members[i]]) {
                hasEndorsed[members[i]] = false;
            }
        }
        endorseCount = 0;
    }
}
