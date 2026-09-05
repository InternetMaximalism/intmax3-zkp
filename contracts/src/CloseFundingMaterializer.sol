// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ChannelSettlementManager} from "./ChannelSettlementManager.sol";
import {IntmaxRollup} from "./IntmaxRollup.sol";
import {IPinnedMleVerifierV2} from "./IPinnedMleVerifierV2.sol";

/// @title RETIRED terminal-child close-funding implementation
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
/// @dev Kept as an abstract audit record only. Production deployments instantiate the
///      signer-independent `CloseFundingMaterializer` below.
abstract contract LegacyTerminalChildFundingMaterializer {
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
        address indexed manager, uint8 indexed lane, bytes32 indexed fundingAuxData, bytes32 withdrawalSetDigest
    );

    constructor(IntmaxRollup rollup_) {
        if (address(rollup_).code.length == 0) revert InvalidRollup();
        rollup = rollup_;
    }

    function materializeNative(
        ChannelSettlementManager manager,
        IntmaxRollup.Withdrawal[] calldata withdrawals,
        address withdrawalProver,
        bytes calldata compactProof
    ) external {
        bytes32 auxData = _validateCompleteLane(manager, withdrawals, true);
        for (uint256 i = 0; i < withdrawals.length; ++i) {
            manager.authorizeCloseFunding(withdrawals[i].tokenIndex, withdrawals[i].auxData);
        }
        rollup.withdrawNative(withdrawals, withdrawalProver, compactProof);
        emit CloseFundingMaterialized(address(manager), 0, auxData, keccak256(abi.encode(withdrawals)));
    }

    function materializeERC20(
        ChannelSettlementManager manager,
        IntmaxRollup.Withdrawal[] calldata withdrawals,
        address withdrawalProver,
        bytes calldata compactProof
    ) external {
        bytes32 auxData = _validateCompleteLane(manager, withdrawals, false);
        for (uint256 i = 0; i < withdrawals.length; ++i) {
            manager.authorizeCloseFunding(withdrawals[i].tokenIndex, withdrawals[i].auxData);
        }
        rollup.withdrawERC20(withdrawals, withdrawalProver, compactProof);
        emit CloseFundingMaterialized(address(manager), 1, auxData, keccak256(abi.encode(withdrawals)));
    }

    function _validateCompleteLane(
        ChannelSettlementManager manager,
        IntmaxRollup.Withdrawal[] calldata withdrawals,
        bool nativeLane
    ) private view returns (bytes32 auxData) {
        if (address(manager.registry()) != address(rollup)) {
            revert ManagerRollupMismatch();
        }
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

/// @title Signer-independent whole-state close materializer
/// @notice A last N-of-N signed state H can complete its L1 exit after the close and backing
///         proofs finalize, without constructing or signing a terminal child transaction T(H).
///         Token indices and amounts are read from the exact bound Manager; callers supply none.
/// @dev This contract also carries the channel-scoped posting/freeze journal. IntmaxRollup is at
///      the EIP-170 ceiling, so keeping validation here preserves deployability while every escrow
///      debit and pending-ledger credit still executes in—and is authenticated by—the Rollup.
contract CloseFundingMaterializer {
    uint256 private constant MAX_CHANNEL_TOKENS = 10;
    bytes4 private constant BACKING_STATEMENT_DOMAIN = 0x494d4241; // "IMBA"
    bytes4 private constant BACKING_PROOF_DOMAIN = 0x494d4250; // "IMBP"

    error InvalidRollup();
    error OnlyRollup();
    error InvalidManager();
    error ManagerRollupMismatch();
    error ManagerMaterializerMismatch();
    error ManagerAlreadyBound(uint32 channelId);
    error BindWithUnfinalizedHead();
    error NotBoundManager();
    error ChannelExitAlreadyFrozen();
    error ChannelExitNotFrozen();
    error ChannelExitGenerationMismatch();
    error ChannelAlreadyExited();
    error ChannelExitHasUnfinalizedBlocks();
    error ChannelExitManagerNotClosed();
    error ChannelExitStatementMismatch();
    error ChannelExitTokenCountOutOfRange();
    error ChannelExitDuplicateToken(uint32 tokenIndex);
    error CooperativeCloseFundingDeprecated();
    // ABI names retained so old publishers/tests can identify the retired route; the tombstone
    // functions below now always return CooperativeCloseFundingDeprecated before evaluating them.
    error FundingLaneLengthMismatch(uint256 expected, uint256 supplied);
    error InvalidBackingVerifier(address verifier);
    error BackingVerifierChainMismatch(address verifier, uint256 expected, uint256 actual);
    error BackingProofInvalid();
    error BackingProofNotAttested();
    error BackingPublicInputsMismatch();

    struct BackingStatement {
        bytes32 settledTxChain;
        bytes32 tokenFundsDigest;
        bytes32 backingRoot;
        uint64 anchorBlockNumber;
    }

    IntmaxRollup public immutable rollup;
    /// @notice The constructor-pinned compact-v2 adapter of the CloseAssetBacking circuit. It
    ///         recursively checks the Balance proof and exposes only the 26 fields consumed at the
    ///         L1 exit boundary. Like every other statement verifier of this deployment it owns its
    ///         complete immutable VK/configuration; there is no post-deploy initialization.
    IPinnedMleVerifierV2 public immutable backingMleVerifier;

    mapping(uint32 => address) public managerOfChannel;
    mapping(uint32 => uint64) public frozenGeneration;
    mapping(uint32 => uint64) public lastPostedBlock;
    mapping(uint32 => bytes32) public materializedChannelExit;
    /// 0 means absent; otherwise value - 1 is the greatest verified anchor for this exact
    /// manager/channel + settled-chain + token-funds composition.
    mapping(bytes32 => uint64) public signedHeadBackingAnchorPlusOne;
    /// Exact canonical `(chain, deployment, rollup, manager, proof)` receipt. Materialization
    /// supplies the proof argument but reuses this earlier verification instead of paying the MLE
    /// verifier twice.
    mapping(bytes32 => bool) public attestedBackingProof;
    mapping(uint64 => uint32) private _postedChannel;
    mapping(uint64 => uint64) private _previousChannelBlock;

    event ChannelExitManagerBound(uint32 indexed channelId, address indexed manager);
    event ChannelExitFrozen(uint32 indexed channelId, uint64 indexed generation, uint64 lastPostedBlock);
    event ChannelExitUnfrozen(uint32 indexed channelId, uint64 indexed generation);
    event SignedHeadBackingAttested(
        uint32 indexed channelId,
        address indexed manager,
        bytes32 indexed statementKey,
        bytes32 backingRoot,
        uint64 anchorBlockNumber,
        bytes32 proofId
    );
    event SignedHeadExitMaterialized(
        uint32 indexed channelId, address indexed manager, bytes32 indexed closeIntentDigest, uint8 tokenCount
    );

    constructor(IntmaxRollup rollup_, IPinnedMleVerifierV2 backingMleVerifier_) {
        if (address(rollup_).code.length == 0) revert InvalidRollup();
        rollup = rollup_;
        _requirePinnedVerifier(backingMleVerifier_);
        backingMleVerifier = backingMleVerifier_;
    }

    /// @dev Mirrors the Rollup/Manager constructor invariant: the adapter and its linked core must
    ///      be deployed, pinned to this chain, and consistent with each other before any receipt
    ///      can be recorded against them.
    function _requirePinnedVerifier(IPinnedMleVerifierV2 verifier) private view {
        address verifierAddress = address(verifier);
        if (verifierAddress.code.length == 0) revert InvalidBackingVerifier(verifierAddress);
        uint256 verifierChainId;
        try verifier.allowedChainId() returns (uint256 chainId) {
            verifierChainId = chainId;
        } catch {
            revert InvalidBackingVerifier(verifierAddress);
        }
        if (verifierChainId != block.chainid) {
            revert BackingVerifierChainMismatch(verifierAddress, block.chainid, verifierChainId);
        }
        address verifierCore;
        try verifier.core() returns (address core_) {
            verifierCore = core_;
        } catch {
            revert InvalidBackingVerifier(verifierAddress);
        }
        if (verifierCore.code.length == 0) revert InvalidBackingVerifier(verifierAddress);
        uint256 coreChainId;
        try IPinnedMleVerifierV2(verifierCore).allowedChainId() returns (uint256 chainId) {
            coreChainId = chainId;
        } catch {
            revert InvalidBackingVerifier(verifierCore);
        }
        if (coreChainId != block.chainid) {
            revert BackingVerifierChainMismatch(verifierCore, block.chainid, coreChainId);
        }
    }


    modifier onlyRollup() {
        if (msg.sender != address(rollup)) revert OnlyRollup();
        _;
    }

    /// @notice Called by the Rollup while registering a real settlement Manager. Legacy partial-
    ///         withdrawal mocks that do not expose `channelId()` never reach this method.
    function bindManager(address manager) external onlyRollup {
        if (manager.code.length == 0) revert InvalidManager();
        ChannelSettlementManager m = ChannelSettlementManager(payable(manager));
        uint32 channelId = uint32(m.channelId());
        if (channelId == 0 || rollup.channelMemberSetCommitment(channelId) == bytes32(0)) {
            revert InvalidManager();
        }
        if (address(m.registry()) != address(rollup)) revert ManagerRollupMismatch();
        if (m.closeFundingMaterializer() != address(this)) revert ManagerMaterializerMismatch();
        address incumbent = managerOfChannel[channelId];
        if (incumbent != address(0) && incumbent != manager) revert ManagerAlreadyBound(channelId);
        // A manager can be introduced only at a canonical global head. This prevents a pre-binding
        // pending block for its channel from being absent from the per-channel journal.
        if (rollup.blockNumber() != rollup.latestFinalizedBlockNumber()) revert BindWithUnfinalizedHead();
        if (incumbent == address(0)) {
            managerOfChannel[channelId] = manager;
            // Pre-binding channel history is not journaled here. Conservatively require every
            // future backing proof to anchor at or after the canonical finalized head at binding;
            // this turns unknown historical channel posts into a safe global floor.
            lastPostedBlock[channelId] = rollup.blockNumber();
            emit ChannelExitManagerBound(channelId, manager);
        }
    }

    /// @dev Manager changes its own status/generation first; a mismatch reverts all local writes.
    function freezeFromManager(uint32 channelId, uint64 generation) external {
        address manager = msg.sender;
        if (managerOfChannel[channelId] != manager) revert NotBoundManager();
        if (materializedChannelExit[channelId] != bytes32(0)) revert ChannelAlreadyExited();
        if (frozenGeneration[channelId] != 0) revert ChannelExitAlreadyFrozen();
        ChannelSettlementManager m = ChannelSettlementManager(payable(manager));
        if (
            uint32(m.channelId()) != channelId || m.closeRequestGeneration() != generation || generation == 0
                || m.channelStatus() != ChannelSettlementManager.ChannelLifecycleStatus.ClosePending
        ) revert ChannelExitGenerationMismatch();
        frozenGeneration[channelId] = generation;
        emit ChannelExitFrozen(channelId, generation, lastPostedBlock[channelId]);
    }

    function unfreezeFromManager(uint32 channelId, uint64 generation) external {
        address manager = msg.sender;
        if (managerOfChannel[channelId] != manager) revert NotBoundManager();
        uint64 frozen = frozenGeneration[channelId];
        if (frozen == 0) revert ChannelExitNotFrozen();
        if (frozen != generation) revert ChannelExitGenerationMismatch();
        if (materializedChannelExit[channelId] != bytes32(0)) revert ChannelAlreadyExited();
        frozenGeneration[channelId] = 0;
        emit ChannelExitUnfrozen(channelId, generation);
    }

    /// @dev Unbound channels need no journal. Binding is allowed only at a globally finalized
    ///      head, so no earlier pending block for a newly bound channel can be missed.
    function recordPost(uint32 channelId, uint64 blockNumber) external onlyRollup {
        if (managerOfChannel[channelId] == address(0)) return;
        if (materializedChannelExit[channelId] != bytes32(0)) revert ChannelAlreadyExited();
        if (frozenGeneration[channelId] != 0) revert ChannelExitAlreadyFrozen();
        _postedChannel[blockNumber] = channelId;
        _previousChannelBlock[blockNumber] = lastPostedBlock[channelId];
        lastPostedBlock[channelId] = blockNumber;
    }

    /// @dev The Rollup invokes this in descending order, restoring the exact prior per-channel
    ///      pointer even when a reverted range interleaves several channels.
    function rollbackPost(uint64 blockNumber) external onlyRollup {
        uint32 channelId = _postedChannel[blockNumber];
        if (channelId == 0) return;
        if (lastPostedBlock[channelId] != blockNumber) revert ChannelExitStatementMismatch();
        lastPostedBlock[channelId] = _previousChannelBlock[blockNumber];
        delete _postedChannel[blockNumber];
        delete _previousChannelBlock[blockNumber];
    }

    /// @notice Verify and durably register an exact signed-head backing statement before it is
    ///         allowed to become the Manager's close or partial-withdrawal high-water mark.
    /// @dev Permissionless and idempotent. Splitting this expensive verification from close
    ///      submission keeps the Manager ABI and challenge transaction bounded while preventing a
    ///      valid but unavailable backing proof from permanently displacing an exit-capable head.
    function attestSignedHeadBacking(ChannelSettlementManager manager, bytes calldata backingProof) external {
        uint256[] memory pi = _verifyBackingProof(backingProof);
        BackingStatement memory statement = _validateBackingPublicInputs(manager, pi);

        uint32 channelId = uint32(manager.channelId());
        bytes32 statementKey =
            _backingStatementKey(address(manager), channelId, statement.settledTxChain, statement.tokenFundsDigest);
        bytes32 proofId = _backingProofId(address(manager), backingProof);
        uint64 anchorPlusOne = statement.anchorBlockNumber + 1;
        if (anchorPlusOne > signedHeadBackingAnchorPlusOne[statementKey]) {
            signedHeadBackingAnchorPlusOne[statementKey] = anchorPlusOne;
        }
        if (!attestedBackingProof[proofId]) {
            attestedBackingProof[proofId] = true;
            emit SignedHeadBackingAttested(
                channelId, address(manager), statementKey, statement.backingRoot, statement.anchorBlockNumber, proofId
            );
        }
    }

    /// @notice True only when this exact bound Manager has a verified whole-vector backing
    ///         receipt whose anchor is not older than the channel's current reorg-aware post head.
    function hasSignedHeadBacking(
        address manager,
        uint32 channelId,
        bytes32 settledTxChain,
        bytes32 tokenFundsDigest,
        bool requireCurrent
    ) external view returns (bool) {
        return _hasSignedHeadBacking(manager, channelId, settledTxChain, tokenFundsDigest, requireCurrent);
    }

    /// @notice Manager-only admission check. Keeping the branch and error in this satellite saves
    ///         scarce ChannelSettlementManager runtime bytes while preserving the submit ABI.
    function requireSignedHeadBacking(uint32 channelId, bytes32 settledTxChain, bytes32 tokenFundsDigest)
        external
        view
    {
        bool requireCurrent = ChannelSettlementManager(payable(msg.sender)).channelStatus()
            != ChannelSettlementManager.ChannelLifecycleStatus.Active;
        if (!_hasSignedHeadBacking(msg.sender, channelId, settledTxChain, tokenFundsDigest, requireCurrent)) {
            revert BackingProofNotAttested();
        }
    }

    function _hasSignedHeadBacking(
        address manager,
        uint32 channelId,
        bytes32 settledTxChain,
        bytes32 tokenFundsDigest,
        bool requireCurrent
    ) private view returns (bool) {
        if (managerOfChannel[channelId] != manager) return false;
        uint64 anchorPlusOne =
            signedHeadBackingAnchorPlusOne[_backingStatementKey(manager, channelId, settledTxChain, tokenFundsDigest)];
        return anchorPlusOne != 0 && (!requireCurrent || anchorPlusOne - 1 >= lastPostedBlock[channelId]);
    }

    /// @notice Permissionless signer-independent exit using finalized H plus its already-attested
    ///         CloseAssetBacking proof. No new channel signature or terminal child is accepted.
    function materializeSignedHead(ChannelSettlementManager manager, bytes calldata backingProof) external {
        // The public inputs are re-derived by the pinned adapter from the exact compact bytes
        // rather than trusted from calldata; the statement/manager binding is checked first so a
        // proof for another channel or an unbound manager fails by its own reason, then the
        // attestation receipt keyed on these same bytes must exist.
        BackingStatement memory statement =
            _validateBackingPublicInputs(manager, _verifyBackingProof(backingProof));
        bytes32 proofId = _backingProofId(address(manager), backingProof);
        if (!attestedBackingProof[proofId]) revert BackingProofNotAttested();
        if (
            statement.settledTxChain != manager.finalizedSettledTxChain()
                || statement.tokenFundsDigest != manager.finalizedTokenFundsDigest()
        ) revert BackingPublicInputsMismatch();
        _materialize(manager, statement.anchorBlockNumber);
    }

    /// @dev The pinned adapter verifies the compact proof against its immutable configuration and
    ///      returns the authenticated public inputs; any verifier failure is one explicit error.
    function _verifyBackingProof(bytes calldata backingProof) private view returns (uint256[] memory pi) {
        try backingMleVerifier.verifyCompactPublicInputs(backingProof) returns (uint256[] memory publicInputs) {
            pi = publicInputs;
        } catch {
            revert BackingProofInvalid();
        }
    }

    /// @dev Re-entered only by the Rollup's authenticated endpoint. The digest is consumed before
    ///      token credits; any later underflow/mismatch reverts it and every Rollup mutation.
    function _materialize(ChannelSettlementManager m, uint64 anchorBlockNumber) private {
        address manager = address(m);
        uint32 channelId = uint32(m.channelId());
        if (managerOfChannel[channelId] != manager) revert NotBoundManager();
        uint64 generation = frozenGeneration[channelId];
        if (generation == 0) revert ChannelExitNotFrozen();
        if (materializedChannelExit[channelId] != bytes32(0)) revert ChannelAlreadyExited();
        if (m.channelStatus() != ChannelSettlementManager.ChannelLifecycleStatus.Closed) {
            revert ChannelExitManagerNotClosed();
        }
        if (m.closeRequestGeneration() != generation) revert ChannelExitGenerationMismatch();
        bytes32 digest = m.finalizedCloseIntentDigest();
        bytes32 stateRoot = m.finalizedChannelFundIntmaxStateRoot();
        if (digest == bytes32(0) || !rollup.isFinalizedStateRoot(stateRoot)) {
            revert ChannelExitStatementMismatch();
        }
        if (anchorBlockNumber > rollup.latestFinalizedBlockNumber() || lastPostedBlock[channelId] > anchorBlockNumber) {
            revert ChannelExitHasUnfinalizedBlocks();
        }

        uint8 tokenCount = m.finalizedTokenCount();
        if (tokenCount == 0 || tokenCount > MAX_CHANNEL_TOKENS) revert ChannelExitTokenCountOutOfRange();
        uint32[10] memory registry;
        uint256[10] memory amounts;
        for (uint256 i = 0; i < tokenCount; ++i) {
            uint32 tokenIndex = m.finalizedTokenRegistry(i);
            for (uint256 j = 0; j < i; ++j) {
                if (registry[j] == tokenIndex) revert ChannelExitDuplicateToken(tokenIndex);
            }
            registry[i] = tokenIndex;
            amounts[i] = m.finalizedChannelFundAmount(tokenIndex);
        }

        materializedChannelExit[channelId] = digest;
        for (uint256 i = 0; i < tokenCount; ++i) {
            uint256 amount = amounts[i];
            if (amount != 0) rollup.creditChannelExit(manager, registry[i], amount);
        }
        emit SignedHeadExitMaterialized(channelId, manager, digest, tokenCount);
    }

    /// @dev Exact PI layout (26 limbs): channelId[1] | settledTxChain[8] | TFD[8] |
    ///      finalizedExtendedStateCommitment[8] | anchorBlockNumber[1]. The first 25 are canonical
    ///      u32 limbs; the anchor is canonical u63. The backing ext root need not equal H's signed
    ///      channel-fund root: it is the later finalized root that actually contains this Balance
    ///      proof. Channel/settled-chain/TFD are the bridge back to H.
    function _validateBackingPublicInputs(ChannelSettlementManager manager, uint256[] memory pi)
        private
        view
        returns (BackingStatement memory statement)
    {
        if (pi.length != 26) revert BackingPublicInputsMismatch();
        for (uint256 i = 0; i < 25; ++i) {
            if (pi[i] > type(uint32).max) revert BackingPublicInputsMismatch();
        }
        if (pi[25] >= (uint256(1) << 63)) revert BackingPublicInputsMismatch();
        uint32 channelId = uint32(manager.channelId());
        if (managerOfChannel[channelId] != address(manager)) revert NotBoundManager();
        if (pi[0] != channelId) revert BackingPublicInputsMismatch();
        statement = BackingStatement({
            settledTxChain: _limbsToBytes32(pi, 1),
            tokenFundsDigest: _limbsToBytes32(pi, 9),
            backingRoot: _limbsToBytes32(pi, 17),
            anchorBlockNumber: uint64(pi[25])
        });
        if (!rollup.isFinalizedStateRoot(statement.backingRoot)) revert BackingPublicInputsMismatch();
        // Historical exact backing remains usable for a previously signed partial-withdrawal burn
        // even after later channel posts. Terminal close/materialization independently requires a
        // current anchor, so accepting the receipt here cannot close from a stale economic state.
        if (statement.anchorBlockNumber > rollup.latestFinalizedBlockNumber()) {
            revert ChannelExitHasUnfinalizedBlocks();
        }
    }

    function _backingStatementKey(address manager, uint32 channelId, bytes32 settledTxChain, bytes32 tokenFundsDigest)
        private
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                BACKING_STATEMENT_DOMAIN,
                block.chainid,
                address(this),
                address(rollup),
                manager,
                channelId,
                settledTxChain,
                tokenFundsDigest
            )
        );
    }

    function _backingProofId(address manager, bytes calldata proof) private view returns (bytes32) {
        return keccak256(
            abi.encode(BACKING_PROOF_DOMAIN, block.chainid, address(this), address(rollup), manager, keccak256(proof))
        );
    }

    function _limbsMatch(uint256[] memory limbs, uint256 offset, bytes32 value) private pure returns (bool) {
        uint256 v = uint256(value);
        for (uint256 i = 0; i < 8; ++i) {
            if (limbs[offset + i] != uint32(v >> (224 - 32 * i))) return false;
        }
        return true;
    }

    function _limbsToBytes32(uint256[] memory limbs, uint256 offset) private pure returns (bytes32 result) {
        uint256 v;
        for (uint256 i = 0; i < 8; ++i) {
            v = (v << 32) | limbs[offset + i];
        }
        result = bytes32(v);
    }

    /// @notice Retired terminal-child route. Stale publishers fail with an explicit error.
    function materializeNative(
        ChannelSettlementManager,
        IntmaxRollup.Withdrawal[] calldata,
        address,
        bytes calldata
    ) external pure {
        revert CooperativeCloseFundingDeprecated();
    }

    /// @notice Retired terminal-child route. Stale publishers fail with an explicit error.
    function materializeERC20(
        ChannelSettlementManager,
        IntmaxRollup.Withdrawal[] calldata,
        address,
        bytes calldata
    ) external pure {
        revert CooperativeCloseFundingDeprecated();
    }
}
