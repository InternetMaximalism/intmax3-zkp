// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IChannelSettlementVerifier, CloseProofFields} from "./ChannelSettlementManager.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {SpongefishWhirVerify} from "@mle/spongefish/SpongefishWhirVerify.sol";
import {GoldilocksExt3} from "@mle/spongefish/GoldilocksExt3.sol";

/// @dev Stub proof verifier: each `verify*` recomputes the expected public-input hash and
/// matches it against the supplied "proof" bytes. The `*PIHash` preimages are byte-exact
/// mirrors of the Rust public-input limb vectors (`to_u64_vec()`, big-endian u32 words) in
/// `src/circuits/channel/*_pis.rs`, with the protocol domain word prepended.
///
/// SECURITY — TRUST BOUNDARY (P3/P4, accepted-stub scope):
///   These verify* checks are INTRA-CHANNEL consensus stubs (2-party signed close intent + a
///   challenge/replace window), NOT a real ZK verification of the close state transition. They are
///   accepted-stubs by design: the protocol-critical invariant is CROSS-CHANNEL isolation, and that
///   is enforced elsewhere by REAL cryptography, not here:
///     • The channel's aggregate native settlement is paid by `IntmaxRollup.withdrawNative`, which
///       verifies a real MLE/WHIR withdrawal proof bound to a finalized state root (recipient = the
///       channel's `ChannelSettlementManager`).
///     • `ChannelSettlementManager` then caps ALL member payouts at `receivedChannelFunds` — the
///       real ETH it actually pulled from the rollup — so Σ paid ≤ Σ received. A channel can never
///       pay out (and thus never steal) more ETH than its own verified withdrawal delivered,
///       regardless of what these stubs accept. Intra-channel mis-allocation among a channel's own
///       members is the accepted residual risk of these stubs.
///   Replacing these with real close-circuit ZK proofs is tracked as future work; doing so would
///   harden intra-channel correctness but is NOT required for cross-channel safety.
///
/// F7 (one SPHINCS+ key per member): member identity is the SPHINCS+ pubkey hash (bytes32, 8
/// limbs); the legacy `bytes8 userId` (2 limbs) is removed from the withdrawal / post-close
/// claims, and the close PI appends a `memberSetCommitment` (keccak over the 3 members' pubkey
/// hashes) so L1 binds the verified signing keys to the channel's registered member set.
contract ChannelSettlementVerifier is IChannelSettlementVerifier {
    uint32 internal constant CLOSE_INTENT_DOMAIN = 0x494d4349;
    uint32 internal constant SPECIAL_CLOSE_DOMAIN = 0x494d5343;
    uint32 internal constant CANCEL_CLOSE_DOMAIN = 0x494d434e;
    uint32 internal constant LATE_OUTGOING_DEBIT_DOMAIN = 0x494d4c44;
    /// "IMCM" — close-circuit member-set commitment domain (mirrors Rust
    /// `CLOSE_MEMBER_SET_DOMAIN` / `close_member_set_commitment`, src/common/channel.rs).
    uint32 internal constant CLOSE_MEMBER_SET_DOMAIN = 0x494d434d;
    /// D6 pad-to-MAX: the close circuit is sized for this many member slots (mirrors Rust
    /// `MAX_CHANNEL_MEMBERS`, src/constants.rs). Active members occupy slots `0..memberCount`;
    /// padding slots are zero.
    uint256 internal constant MAX_CHANNEL_MEMBERS = 16;

    /// Number of RAW Goldilocks public-input limbs the close circuit registers (mirrors Rust
    /// `CHANNEL_CLOSE_PUBLIC_INPUTS_LEN`, src/circuits/channel/close_pis.rs). The close
    /// `WrapperCircuit` re-registers them VERBATIM, so a close `MleProof.publicInputs` is this
    /// raw 87-limb vector — NOT an 8-limb keccak like validity/withdrawal.
    uint256 internal constant CLOSE_PI_LEN = 87;
    /// Phase B-D: RAW Goldilocks PI limb counts for the two new binding circuits (mirror Rust
    /// `WITHDRAWAL_CLAIM_PUBLIC_INPUTS_LEN` / `POST_CLOSE_CLAIM_PUBLIC_INPUTS_LEN`). Their
    /// `WrapperCircuit` re-registers the limbs VERBATIM, so the `MleProof.publicInputs` are these
    /// raw vectors (NOT a keccak).
    uint256 internal constant WITHDRAWAL_CLAIM_PI_LEN = 48;
    uint256 internal constant POST_CLOSE_CLAIM_PI_LEN = 40;
    /// 2**32 — every close PI limb is a u32 word, so a canonical limb is strictly below this.
    uint256 internal constant LIMB_BOUND = 0x1_0000_0000;

    // -----------------------------------------------------------------------
    // Phase A — REAL on-chain close verification VK (close-verifier-a1-plan.md)
    //
    // SECURITY: the close VK is its OWN complete, independent MLE/WHIR verification key (its own
    // degreeBits / preprocessedRoot / gatesDigest / numConstants / numRoutedWires / kIs /
    // subgroupGenPowers / WHIR params / protocolId / sessionId). It is NOT shared with the
    // validity/withdrawal VK storage in IntmaxRollup, and it carries the REAL close-circuit digests,
    // so a validity/withdrawal MLE proof replayed as a close proof is rejected by MleVerifier's
    // circuitDigest absorb + preprocessedRoot VK-binding + gatesDigest check.
    //
    // It is set EXACTLY ONCE by the deployer via `initializeCloseVk` (set-once latch +
    // `degreeBits > 0` guard), mirroring `IntmaxRollup.initializeWithdrawalVk`. `verifyCloseIntent`
    // REVERTS until it is set — there is deliberately NO `degreeBits == 0 => return true` disable
    // seam on this value-bearing path.
    // -----------------------------------------------------------------------

    /// @notice Scalar VK params (mirror of `IntmaxRollup.MleVk`). Dynamic arrays live in dedicated
    ///         storage variables below.
    struct CloseVk {
        uint256 degreeBits;
        bytes32 preprocessedRoot;
        uint256 numConstants;
        uint256 numRoutedWires;
        bytes32 gatesDigest;
    }

    error CloseVkNotSet();
    error CloseVkDegreeBitsZero();

    event CloseVkInitialized(uint256 degreeBits, bytes32 preprocessedRoot);

    /// @notice The only address allowed to set the close VK (once). Set to the constructor caller.
    address public immutable deployer;

    /// @notice The shared MLE verifier contract used to verify the close proof. Set once, together
    ///         with the close VK, by the deployer (pinned atomically so the verifier the close VK
    ///         was sized for cannot be swapped afterwards).
    MleVerifier public closeMleVerifier;

    /// @notice Close-circuit MLE verification key. `degreeBits == 0` ⇒ unset (reverts on verify).
    CloseVk public closeVk;

    /// @notice True once `initializeCloseVk` has run. Set-once latch.
    bool public closeVkInitialized;

    SpongefishWhirVerify.WhirParams internal _closeWhirParams;
    bytes public closeWhirProtocolId;
    bytes public closeWhirSplitSessionId;
    uint256[] internal _closeKIs;
    uint256[] internal _closeSubgroupGenPowers;

    constructor() {
        deployer = msg.sender;
    }

    /// @notice Set the close-circuit MLE verification key + the MLE verifier contract. Deployer-only,
    ///         set EXACTLY ONCE.
    /// @dev SECURITY: governs which Plonky2 circuit `verifyCloseIntent` accepts. Fixed by the
    ///      deployer immediately after deploy and never changed (`closeVkInitialized` latch).
    ///      `degreeBits` MUST be > 0 — the close path never runs with verification disabled. Mirrors
    ///      `IntmaxRollup.initializeWithdrawalVk` (deployer + `!initialized` latch + degreeBits>0).
    function initializeCloseVk(
        MleVerifier verifier_,
        CloseVk memory _vk,
        SpongefishWhirVerify.WhirParams memory whirParams_,
        bytes memory _protocolId,
        bytes memory _sessionId,
        uint256[] memory _kIs,
        uint256[] memory _subgroupGenPowers
    ) external {
        require(msg.sender == deployer, "only deployer");
        require(!closeVkInitialized, "close vk already set");
        if (_vk.degreeBits == 0) revert CloseVkDegreeBitsZero();
        closeVkInitialized = true;
        closeMleVerifier = verifier_;
        closeVk = _vk;
        _copyWhirParams(_closeWhirParams, whirParams_);
        closeWhirProtocolId = _protocolId;
        closeWhirSplitSessionId = _sessionId;
        for (uint256 i = 0; i < _kIs.length; i++) {
            _closeKIs.push(_kIs[i]);
        }
        for (uint256 i = 0; i < _subgroupGenPowers.length; i++) {
            _closeSubgroupGenPowers.push(_subgroupGenPowers[i]);
        }
        emit CloseVkInitialized(_vk.degreeBits, _vk.preprocessedRoot);
    }

    /// @notice REAL on-chain verification of the channel-close-intent proof (Phase A).
    /// @dev SECURITY: replaces the former tautological `closePIHash`+`_matches` stub. Two checks,
    ///      both mandatory:
    ///        1. `_bindCloseLimbsStrict` binds ALL 87 raw Goldilocks public-input limbs of the close
    ///           proof, limb-by-limb with STRICT equality (no masking), to the expected vector
    ///           rebuilt from `fields` (`_expectedCloseLimbs`). This binds channelId(0),
    ///           finalStateVersion(67..68), finalSettledTxChain(69..76), memberSetCommitment(77..84),
    ///           memberCount(85) and delegateCount(86) — NONE are left free.
    ///        2. `MleVerifier.verify` re-checks the proof against the close VK (circuitDigest absorb,
    ///           preprocessedRoot VK-binding, gatesDigest), blocking cross-circuit replay.
    ///      Reverts (`CloseVkNotSet`) until the VK is set: no verification-disabled window.
    function verifyCloseIntent(
        CloseProofFields calldata fields,
        MleVerifier.MleProof calldata mleProof
    ) external view returns (bool) {
        if (!closeVkInitialized) revert CloseVkNotSet();
        _bindCloseLimbsStrict(mleProof.publicInputs, _expectedCloseLimbs(fields));
        return _verifyCloseMle(mleProof);
    }

    /// @dev Bind the proof's public-input limbs to the expected close vector. `pi` MUST be exactly
    ///      87 limbs; each limb MUST equal the expected limb (strict equality, no masking) AND be a
    ///      canonical u32 (`< 2**32`). Reverts on any violation — there is no partial / masked match.
    function _bindCloseLimbsStrict(
        uint256[] calldata pi,
        uint256[] memory expected
    ) internal pure {
        require(pi.length == CLOSE_PI_LEN, "close pi len");
        require(expected.length == CLOSE_PI_LEN, "close expected len");
        for (uint256 i = 0; i < CLOSE_PI_LEN; i++) {
            uint256 limb = pi[i];
            // SECURITY: reject any non-canonical limb (>= 2**32). Every close PI limb is a u32 word;
            // a limb at or above 2**32 cannot be a legitimate close public input, and accepting it
            // would also be a footgun if a downstream consumer reduced it mod the field.
            require(limb < LIMB_BOUND, "close limb range");
            require(limb == expected[i], "close limb mismatch");
        }
    }

    /// @dev Deep-copy a WhirParams (scalar fields + dynamic arrays) from memory into storage. The
    ///      destination arrays are assumed empty (the close VK slot is written exactly once). Mirrors
    ///      `IntmaxRollup._copyWhirParams`.
    function _copyWhirParams(
        SpongefishWhirVerify.WhirParams storage dst,
        SpongefishWhirVerify.WhirParams memory src
    ) private {
        dst.numVariables = src.numVariables;
        dst.foldingFactor = src.foldingFactor;
        dst.numVectors = src.numVectors;
        dst.numCommitments = src.numCommitments;
        dst.outDomainSamples = src.outDomainSamples;
        dst.inDomainSamples = src.inDomainSamples;
        dst.initialSumcheckRounds = src.initialSumcheckRounds;
        dst.numRounds = src.numRounds;
        dst.finalSumcheckRounds = src.finalSumcheckRounds;
        dst.finalSize = src.finalSize;
        dst.initialCodewordLength = src.initialCodewordLength;
        dst.initialMerkleDepth = src.initialMerkleDepth;
        dst.initialDomainGenerator = src.initialDomainGenerator;
        dst.initialInterleavingDepth = src.initialInterleavingDepth;
        dst.initialNumVariables = src.initialNumVariables;
        dst.initialCosetSize = src.initialCosetSize;
        dst.initialNumCosets = src.initialNumCosets;
        for (uint256 i = 0; i < src.rounds.length; i++) {
            dst.rounds.push(src.rounds[i]);
        }
        for (uint256 i = 0; i < src.evaluationPoint.length; i++) {
            dst.evaluationPoint.push(src.evaluationPoint[i]);
        }
        for (uint256 i = 0; i < src.evaluationPoint2.length; i++) {
            dst.evaluationPoint2.push(src.evaluationPoint2[i]);
        }
    }

    /// @dev Load the close WhirParams from storage into memory, then call `MleVerifier.verify` with
    ///      the close VK. Extracted into its own (external-callable would be nicer for try/catch, but
    ///      the manager already wraps the result) view function to keep `verifyCloseIntent`'s stack
    ///      small. The MLE verifier reverts on a failed check; a successful return is `true`.
    function _verifyCloseMle(MleVerifier.MleProof calldata mleProof) internal view returns (bool) {
        SpongefishWhirVerify.WhirParams memory whirParams = _loadWhirParams(_closeWhirParams);
        MleVerifier.VerifyParams memory vp = MleVerifier.VerifyParams({
            degreeBits: closeVk.degreeBits,
            preprocessedCommitmentRoot: closeVk.preprocessedRoot,
            numConstants: closeVk.numConstants,
            numRoutedWires: closeVk.numRoutedWires,
            protocolId: closeWhirProtocolId,
            sessionId: closeWhirSplitSessionId,
            kIs: _closeKIs,
            subgroupGenPowers: _closeSubgroupGenPowers
        });
        return closeMleVerifier.verify(mleProof, vp, whirParams, closeVk.gatesDigest);
    }

    /// @dev Load a WhirParams from the given storage slot into memory (mirror of
    ///      `IntmaxRollup._loadWhirParamsFrom`). Shared across the close / withdrawal-claim /
    ///      post-close-claim VKs (each has its OWN storage slot — see Phase B-D below).
    function _loadWhirParams(SpongefishWhirVerify.WhirParams storage s)
        private view returns (SpongefishWhirVerify.WhirParams memory p)
    {
        p.numVariables = s.numVariables;
        p.foldingFactor = s.foldingFactor;
        p.numVectors = s.numVectors;
        p.numCommitments = s.numCommitments;
        p.outDomainSamples = s.outDomainSamples;
        p.inDomainSamples = s.inDomainSamples;
        p.initialSumcheckRounds = s.initialSumcheckRounds;
        p.numRounds = s.numRounds;
        p.finalSumcheckRounds = s.finalSumcheckRounds;
        p.finalSize = s.finalSize;
        p.initialCodewordLength = s.initialCodewordLength;
        p.initialMerkleDepth = s.initialMerkleDepth;
        p.initialDomainGenerator = s.initialDomainGenerator;
        p.initialInterleavingDepth = s.initialInterleavingDepth;
        p.initialNumVariables = s.initialNumVariables;
        p.initialCosetSize = s.initialCosetSize;
        p.initialNumCosets = s.initialNumCosets;
        uint256 rLen = s.rounds.length;
        p.rounds = new SpongefishWhirVerify.RoundParams[](rLen);
        for (uint256 i = 0; i < rLen; i++) {
            p.rounds[i] = s.rounds[i];
        }
        uint256 epLen = s.evaluationPoint.length;
        p.evaluationPoint = new GoldilocksExt3.Ext3[](epLen);
        for (uint256 i = 0; i < epLen; i++) {
            p.evaluationPoint[i] = s.evaluationPoint[i];
        }
        uint256 ep2Len = s.evaluationPoint2.length;
        p.evaluationPoint2 = new GoldilocksExt3.Ext3[](ep2Len);
        for (uint256 i = 0; i < ep2Len; i++) {
            p.evaluationPoint2[i] = s.evaluationPoint2[i];
        }
    }

    /// @notice TEST-INTROSPECTION HELPER: public view passthrough exposing the EXPECTED 87-limb
    ///         close public-input vector for `fields`. Lets the manager-lifecycle tests build a
    ///         close `MleVerifier.MleProof` whose `publicInputs` equal exactly what
    ///         `verifyCloseIntent`'s `_bindCloseLimbsStrict` will require. It is a pure view of the
    ///         same `_expectedCloseLimbs` the binding uses (no security impact — it reveals nothing a
    ///         caller cannot already recompute from `fields`, analogous to the existing public
    ///         `closePIHash`).
    function expectedCloseLimbs(CloseProofFields calldata fields)
        external
        pure
        returns (uint256[] memory)
    {
        return _expectedCloseLimbs(fields);
    }

    /// @dev Build the EXPECTED 87-limb close public-input vector from `fields`, in the EXACT order
    ///      of the Rust `ChannelClosePublicInputs::to_u64_vec()` (pinned by the Rust↔Solidity golden
    ///      vector: Rust `close_public_inputs_match_solidity_shared_vector`, Solidity
    ///      `test_expectedCloseLimbs_goldenVector`). Each multi-limb field is split into big-endian
    ///      u32 words; each u64 scalar is split into (hi, lo). The `closeIntentDigest` (limbs 57..64)
    ///      is RECOMPUTED here via `_closeIntentDigest` (it is not a `CloseProofFields` member), and
    ///      `memberSetCommitment` (limbs 77..84) is the channel-registered value the manager passes.
    ///
    ///      Layout (limb index → field):
    ///        [0]      channelId
    ///        [1..2]   closeNonce (hi, lo)
    ///        [3..4]   finalEpoch
    ///        [5..6]   finalSmallBlockNumber
    ///        [7..8]   closeFreezeNonce
    ///        [9..16]  finalChannelStateDigest (8 BE u32)
    ///        [17..24] finalBalanceStateH1
    ///        [25..32] channelFundAmount (uint256, 8 BE u32)
    ///        [33..40] channelFundIntmaxStateRoot
    ///        [41..48] burnTxHash
    ///        [49..56] closeWithdrawalDigest
    ///        [57..64] closeIntentDigest (RECOMPUTED)
    ///        [65..66] snapshotMediumBlockNumber
    ///        [67..68] finalStateVersion
    ///        [69..76] finalSettledTxChain
    ///        [77..84] memberSetCommitment
    ///        [85]     memberCount
    ///        [86]     delegateCount
    function _expectedCloseLimbs(CloseProofFields calldata fields)
        internal
        pure
        returns (uint256[] memory limbs)
    {
        limbs = new uint256[](CLOSE_PI_LEN);
        uint256 c = 0;
        // channelId is a bytes4 holding the BE u32 value, so the limb is the integer value.
        limbs[c++] = uint256(uint32(fields.channelId));
        c = _putU64(limbs, c, fields.closeNonce);
        c = _putU64(limbs, c, fields.finalEpoch);
        c = _putU64(limbs, c, fields.finalSmallBlockNumber);
        c = _putU64(limbs, c, fields.closeFreezeNonce);
        c = _putBytes32(limbs, c, fields.finalChannelStateDigest);
        c = _putBytes32(limbs, c, fields.finalBalanceStateH1);
        c = _putUint256(limbs, c, fields.channelFundAmount);
        c = _putBytes32(limbs, c, fields.channelFundIntmaxStateRoot);
        c = _putBytes32(limbs, c, fields.burnTxHash);
        c = _putBytes32(limbs, c, fields.closeWithdrawalDigest);
        c = _putBytes32(limbs, c, _closeIntentDigest(fields));
        c = _putU64(limbs, c, fields.snapshotMediumBlockNumber);
        c = _putU64(limbs, c, fields.finalStateVersion);
        c = _putBytes32(limbs, c, fields.finalSettledTxChain);
        c = _putBytes32(limbs, c, fields.memberSetCommitment);
        limbs[c++] = uint256(fields.memberAndDelegateCount >> 8) & 0xff; // memberCount
        limbs[c++] = uint256(fields.memberAndDelegateCount) & 0xff;      // delegateCount
        require(c == CLOSE_PI_LEN, "close limb count");
    }

    /// @dev split a uint64 into (hi, lo) u32 limbs (Rust `split_u64`).
    function _putU64(uint256[] memory limbs, uint256 c, uint64 v) private pure returns (uint256) {
        limbs[c++] = uint256(v >> 32);
        limbs[c++] = uint256(uint32(v));
        return c;
    }

    /// @dev split a bytes32 into 8 big-endian u32 limbs (`Bytes32::to_u64_vec`).
    function _putBytes32(uint256[] memory limbs, uint256 c, bytes32 v) private pure returns (uint256) {
        return _putUint256(limbs, c, uint256(v));
    }

    /// @dev split a uint256 into 8 big-endian u32 limbs (`U256::to_u64_vec`, most-significant word
    ///      first). word i = (v >> (32 * (7 - i))) & 0xffffffff.
    function _putUint256(uint256[] memory limbs, uint256 c, uint256 v) private pure returns (uint256) {
        for (uint256 i = 0; i < 8; i++) {
            limbs[c++] = (v >> (32 * (7 - i))) & 0xffffffff;
        }
        return c;
    }

    /// @dev Recompute the close-intent digest (IMCI) exactly as the Rust `CloseIntent::signing_digest`
    ///      / the in-circuit IMCI keccak / the manager's `computeCloseIntentDigest` do: a single
    ///      keccak over the IMCI domain word + the close-intent fields (incl. the second `channelId`
    ///      from `channel_fund_snapshot` and the finalStateVersion / finalSettledTxChain tail). This
    ///      is the SAME preimage the former `closePIHash` inner keccak used.
    function _closeIntentDigest(CloseProofFields calldata fields) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                bytes4(CLOSE_INTENT_DOMAIN),
                fields.channelId,
                fields.closeNonce,
                fields.finalEpoch,
                fields.finalSmallBlockNumber,
                fields.closeFreezeNonce,
                fields.finalChannelStateDigest,
                fields.finalBalanceStateH1,
                fields.channelId,
                fields.channelFundAmount,
                fields.channelFundIntmaxStateRoot,
                fields.burnTxHash,
                fields.closeWithdrawalDigest,
                fields.snapshotMediumBlockNumber,
                fields.finalStateVersion,
                fields.finalSettledTxChain
            )
        );
    }

    // =======================================================================
    // Phase B-D (tasks/phase-b-claims-threat-model.md) — REAL on-chain verification of the
    // withdrawal-claim and post-close-claim BINDING circuits, on the SAME @mle rail as close.
    //
    // SCOPE = Option D: these prove EVERYTHING EXCEPT the Regev decryption of the claimed
    // ciphertext. SECURITY (RESIDUAL, documented loudly): the `amount` limb is NOT bound to the
    // ciphertext plaintext — over-claim is bounded only by the manager's
    // `totalWithdrawn <= finalizedChannelFundAmount` cap + the authoritative `receivedChannelFunds`
    // ETH ceiling. The decryption binding is a deferred sub-phase.
    //
    // Each statement gets its OWN complete, independent VK (own degreeBits / preprocessedRoot /
    // gatesDigest / numConstants / numRoutedWires / kIs / subgroupGenPowers / WHIR params /
    // protocolId / sessionId), set EXACTLY ONCE by the deployer (set-once latch + degreeBits>0
    // guard). The verify path REVERTS until its VK is set — no verification-disabled seam. Mirrors
    // the Phase A close VK machinery exactly.
    // =======================================================================

    /// @notice Generic scalar VK params (same shape as `CloseVk`), reused for the two Phase B-D
    ///         statements. Dynamic arrays live in dedicated storage variables below.
    struct StatementVk {
        uint256 degreeBits;
        bytes32 preprocessedRoot;
        uint256 numConstants;
        uint256 numRoutedWires;
        bytes32 gatesDigest;
    }

    error WithdrawalClaimVkNotSet();
    error PostCloseClaimVkNotSet();
    error StatementVkDegreeBitsZero();

    event WithdrawalClaimVkInitialized(uint256 degreeBits, bytes32 preprocessedRoot);
    event PostCloseClaimVkInitialized(uint256 degreeBits, bytes32 preprocessedRoot);

    // ── withdrawal-claim VK storage ──
    MleVerifier public withdrawalClaimMleVerifier;
    StatementVk public withdrawalClaimVk;
    bool public withdrawalClaimVkInitialized;
    SpongefishWhirVerify.WhirParams internal _withdrawalClaimWhirParams;
    bytes public withdrawalClaimWhirProtocolId;
    bytes public withdrawalClaimWhirSplitSessionId;
    uint256[] internal _withdrawalClaimKIs;
    uint256[] internal _withdrawalClaimSubgroupGenPowers;

    // ── post-close-claim VK storage ──
    MleVerifier public postCloseClaimMleVerifier;
    StatementVk public postCloseClaimVk;
    bool public postCloseClaimVkInitialized;
    SpongefishWhirVerify.WhirParams internal _postCloseClaimWhirParams;
    bytes public postCloseClaimWhirProtocolId;
    bytes public postCloseClaimWhirSplitSessionId;
    uint256[] internal _postCloseClaimKIs;
    uint256[] internal _postCloseClaimSubgroupGenPowers;

    /// @notice Set the withdrawal-claim MLE VK + verifier. Deployer-only, set EXACTLY ONCE,
    ///         degreeBits>0. Mirrors `initializeCloseVk`.
    function initializeWithdrawalClaimVk(
        MleVerifier verifier_,
        StatementVk memory _vk,
        SpongefishWhirVerify.WhirParams memory whirParams_,
        bytes memory _protocolId,
        bytes memory _sessionId,
        uint256[] memory _kIs,
        uint256[] memory _subgroupGenPowers
    ) external {
        require(msg.sender == deployer, "only deployer");
        require(!withdrawalClaimVkInitialized, "withdrawal claim vk already set");
        if (_vk.degreeBits == 0) revert StatementVkDegreeBitsZero();
        withdrawalClaimVkInitialized = true;
        withdrawalClaimMleVerifier = verifier_;
        withdrawalClaimVk = _vk;
        _copyWhirParams(_withdrawalClaimWhirParams, whirParams_);
        withdrawalClaimWhirProtocolId = _protocolId;
        withdrawalClaimWhirSplitSessionId = _sessionId;
        for (uint256 i = 0; i < _kIs.length; i++) {
            _withdrawalClaimKIs.push(_kIs[i]);
        }
        for (uint256 i = 0; i < _subgroupGenPowers.length; i++) {
            _withdrawalClaimSubgroupGenPowers.push(_subgroupGenPowers[i]);
        }
        emit WithdrawalClaimVkInitialized(_vk.degreeBits, _vk.preprocessedRoot);
    }

    /// @notice Set the post-close-claim MLE VK + verifier. Deployer-only, set EXACTLY ONCE,
    ///         degreeBits>0. Mirrors `initializeCloseVk`.
    function initializePostCloseClaimVk(
        MleVerifier verifier_,
        StatementVk memory _vk,
        SpongefishWhirVerify.WhirParams memory whirParams_,
        bytes memory _protocolId,
        bytes memory _sessionId,
        uint256[] memory _kIs,
        uint256[] memory _subgroupGenPowers
    ) external {
        require(msg.sender == deployer, "only deployer");
        require(!postCloseClaimVkInitialized, "post close claim vk already set");
        if (_vk.degreeBits == 0) revert StatementVkDegreeBitsZero();
        postCloseClaimVkInitialized = true;
        postCloseClaimMleVerifier = verifier_;
        postCloseClaimVk = _vk;
        _copyWhirParams(_postCloseClaimWhirParams, whirParams_);
        postCloseClaimWhirProtocolId = _protocolId;
        postCloseClaimWhirSplitSessionId = _sessionId;
        for (uint256 i = 0; i < _kIs.length; i++) {
            _postCloseClaimKIs.push(_kIs[i]);
        }
        for (uint256 i = 0; i < _subgroupGenPowers.length; i++) {
            _postCloseClaimSubgroupGenPowers.push(_subgroupGenPowers[i]);
        }
        emit PostCloseClaimVkInitialized(_vk.degreeBits, _vk.preprocessedRoot);
    }

    /// @dev Build the EXPECTED 48-limb withdrawal-claim PI vector, in the EXACT order of the Rust
    ///      `WithdrawalClaimPublicInputs::to_u64_vec()` (pinned by the Rust↔Solidity golden vector
    ///      `withdrawal_claim_public_inputs_match_solidity_shared_vector`). Layout:
    ///        [0..8]   closeIntentDigest        (8 BE u32)
    ///        [8]      channelId                (u32 value)
    ///        [9..17]  finalBalanceStateH1
    ///        [17..25] memberPkG
    ///        [25..30] recipient                (5 BE u32, 160-bit address)
    ///        [30..38] userAmountDigest
    ///        [38..46] withdrawalNullifier
    ///        [46..48] amount                   (hi, lo)
    function _expectedWithdrawalClaimLimbs(
        bytes4 channelId,
        bytes32 closeIntentDigest,
        bytes32 finalBalanceStateH1,
        bytes32 memberPkG,
        address recipient,
        bytes32 userAmountDigest,
        bytes32 withdrawalNullifier,
        uint64 amount
    ) internal pure returns (uint256[] memory limbs) {
        limbs = new uint256[](WITHDRAWAL_CLAIM_PI_LEN);
        uint256 c = 0;
        c = _putBytes32(limbs, c, closeIntentDigest);
        limbs[c++] = uint256(uint32(channelId));
        c = _putBytes32(limbs, c, finalBalanceStateH1);
        c = _putBytes32(limbs, c, memberPkG);
        c = _putAddress(limbs, c, recipient);
        c = _putBytes32(limbs, c, userAmountDigest);
        c = _putBytes32(limbs, c, withdrawalNullifier);
        c = _putU64(limbs, c, amount);
        require(c == WITHDRAWAL_CLAIM_PI_LEN, "wclaim limb count");
    }

    /// @dev Build the EXPECTED 40-limb post-close-claim PI vector, in the EXACT order of the Rust
    ///      `PostCloseClaimPublicInputs::to_u64_vec()` (pinned by
    ///      `post_close_claim_public_inputs_match_solidity_shared_vector`). Layout:
    ///        [0..8]   closeIntentDigest
    ///        [8]      receiverChannelId        (u32 value)
    ///        [9..17]  incomingTxHash
    ///        [17..25] receiverPkG
    ///        [25..30] recipient                (5 BE u32)
    ///        [30..38] sharedNativeNullifier
    ///        [38..40] amount                   (hi, lo)
    function _expectedPostCloseClaimLimbs(
        bytes4 channelId,
        bytes32 closeIntentDigest,
        bytes32 incomingTxHash,
        bytes32 receiverPkG,
        address recipient,
        bytes32 sharedNativeNullifier,
        uint64 amount
    ) internal pure returns (uint256[] memory limbs) {
        limbs = new uint256[](POST_CLOSE_CLAIM_PI_LEN);
        uint256 c = 0;
        c = _putBytes32(limbs, c, closeIntentDigest);
        limbs[c++] = uint256(uint32(channelId));
        c = _putBytes32(limbs, c, incomingTxHash);
        c = _putBytes32(limbs, c, receiverPkG);
        c = _putAddress(limbs, c, recipient);
        c = _putBytes32(limbs, c, sharedNativeNullifier);
        c = _putU64(limbs, c, amount);
        require(c == POST_CLOSE_CLAIM_PI_LEN, "pcclaim limb count");
    }

    /// @dev split a 160-bit address into 5 big-endian u32 limbs (`Address::to_u64_vec`,
    ///      most-significant word first). ADDRESS_LEN = 5.
    function _putAddress(uint256[] memory limbs, uint256 c, address a) private pure returns (uint256) {
        uint256 v = uint256(uint160(a));
        for (uint256 i = 0; i < 5; i++) {
            limbs[c++] = (v >> (32 * (4 - i))) & 0xffffffff;
        }
        return c;
    }

    /// @dev Strict limb bind for an arbitrary-length raw-limb PI vector (length, exact eq, <2**32,
    ///      no mask). Shared by the two Phase B-D verify paths (the close path keeps its own
    ///      `_bindCloseLimbsStrict` to preserve the Phase A audited error strings).
    function _bindLimbsStrict(uint256[] calldata pi, uint256[] memory expected) internal pure {
        require(pi.length == expected.length, "claim pi len");
        for (uint256 i = 0; i < expected.length; i++) {
            uint256 limb = pi[i];
            require(limb < LIMB_BOUND, "claim limb range");
            require(limb == expected[i], "claim limb mismatch");
        }
    }

    function _verifyWithdrawalClaimMle(MleVerifier.MleProof calldata mleProof)
        internal view returns (bool)
    {
        SpongefishWhirVerify.WhirParams memory whirParams =
            _loadWhirParams(_withdrawalClaimWhirParams);
        MleVerifier.VerifyParams memory vp = MleVerifier.VerifyParams({
            degreeBits: withdrawalClaimVk.degreeBits,
            preprocessedCommitmentRoot: withdrawalClaimVk.preprocessedRoot,
            numConstants: withdrawalClaimVk.numConstants,
            numRoutedWires: withdrawalClaimVk.numRoutedWires,
            protocolId: withdrawalClaimWhirProtocolId,
            sessionId: withdrawalClaimWhirSplitSessionId,
            kIs: _withdrawalClaimKIs,
            subgroupGenPowers: _withdrawalClaimSubgroupGenPowers
        });
        return withdrawalClaimMleVerifier.verify(
            mleProof, vp, whirParams, withdrawalClaimVk.gatesDigest
        );
    }

    function _verifyPostCloseClaimMle(MleVerifier.MleProof calldata mleProof)
        internal view returns (bool)
    {
        SpongefishWhirVerify.WhirParams memory whirParams =
            _loadWhirParams(_postCloseClaimWhirParams);
        MleVerifier.VerifyParams memory vp = MleVerifier.VerifyParams({
            degreeBits: postCloseClaimVk.degreeBits,
            preprocessedCommitmentRoot: postCloseClaimVk.preprocessedRoot,
            numConstants: postCloseClaimVk.numConstants,
            numRoutedWires: postCloseClaimVk.numRoutedWires,
            protocolId: postCloseClaimWhirProtocolId,
            sessionId: postCloseClaimWhirSplitSessionId,
            kIs: _postCloseClaimKIs,
            subgroupGenPowers: _postCloseClaimSubgroupGenPowers
        });
        return postCloseClaimMleVerifier.verify(
            mleProof, vp, whirParams, postCloseClaimVk.gatesDigest
        );
    }

    function verifySpecialClose(
        bytes4 channelId,
        uint8 offendingBpMemberSlot,
        bytes32 offendingBpSphincsPubkeyHash,
        bytes32 fullySignedSmallBlockRoot,
        uint64 smallBlockNumber,
        uint64 signedMediumBlockNumber,
        uint64 latestFinalizedMediumBlockNumber,
        bytes calldata proof
    ) external pure returns (bool) {
        return _matches(
            proof,
            specialClosePIHash(
                channelId,
                offendingBpMemberSlot,
                offendingBpSphincsPubkeyHash,
                fullySignedSmallBlockRoot,
                smallBlockNumber,
                signedMediumBlockNumber,
                latestFinalizedMediumBlockNumber
            )
        );
    }

    /// @notice REAL on-chain verification of the withdrawal-claim binding proof (Phase B-D).
    /// @dev SECURITY: replaces the former tautological `withdrawalClaimPIHash`+`_matches` stub. Two
    ///      mandatory checks: (1) `_bindLimbsStrict` binds ALL 48 raw Goldilocks limbs limb-by-limb
    ///      (strict eq, <2**32, no mask) to the expected vector; (2) `MleVerifier.verify` re-checks
    ///      the proof against the withdrawal-claim VK (circuitDigest/preprocessedRoot/gatesDigest →
    ///      cross-circuit replay blocked). Reverts until the VK is set.
    ///      RESIDUAL: `amount` is bound as a PI limb but NOT to the ciphertext plaintext (decryption
    ///      deferred); over-claim is bounded only by the manager's fund caps.
    function verifyWithdrawalClaim(
        bytes4 channelId,
        bytes32 closeIntentDigest,
        bytes32 finalBalanceStateH1,
        bytes32 memberSphincsPubkeyHash,
        address recipient,
        bytes32 userAmountDigest,
        uint64 amount,
        bytes32 withdrawalNullifier,
        MleVerifier.MleProof calldata mleProof
    ) external view returns (bool) {
        if (!withdrawalClaimVkInitialized) revert WithdrawalClaimVkNotSet();
        _bindLimbsStrict(
            mleProof.publicInputs,
            _expectedWithdrawalClaimLimbs(
                channelId,
                closeIntentDigest,
                finalBalanceStateH1,
                memberSphincsPubkeyHash,
                recipient,
                userAmountDigest,
                withdrawalNullifier,
                amount
            )
        );
        return _verifyWithdrawalClaimMle(mleProof);
    }

    function verifyCancelClose(
        bytes4 channelId,
        bytes32 closeIntentDigest,
        bytes32 revivedSmallBlockRoot,
        bytes32 revivedInterChannelTxDigest,
        bytes32 revivedTxHash,
        bytes32 revivedSeal,
        bytes calldata proof
    ) external pure returns (bool) {
        return _matches(
            proof,
            cancelPIHash(
                channelId,
                closeIntentDigest,
                revivedSmallBlockRoot,
                revivedInterChannelTxDigest,
                revivedTxHash,
                revivedSeal
            )
        );
    }

    /// @notice REAL on-chain verification of the post-close-claim binding proof (Phase B-D).
    /// @dev SECURITY: replaces the former tautological `postCloseClaimPIHash`+`_matches` stub. Two
    ///      mandatory checks: (1) `_bindLimbsStrict` binds ALL 40 raw Goldilocks limbs; (2)
    ///      `MleVerifier.verify` against the post-close-claim VK. Reverts until the VK is set.
    ///      HAZARD #8: `sharedNativeNullifier` is DERIVED in-circuit from
    ///      keccak(IMCK, closeIntentDigest, incomingTxHash, receiverPkG); the manager passes the
    ///      RECOMPUTED value here (not an opaque claim field), so the binding rejects a
    ///      freshly-picked nullifier. RESIDUAL: `amount` is not bound to the plaintext (decryption
    ///      deferred).
    function verifyPostCloseClaim(
        bytes4 channelId,
        bytes32 closeIntentDigest,
        bytes32 incomingTxHash,
        bytes32 receiverSphincsPubkeyHash,
        address recipient,
        bytes32 sharedNativeNullifier,
        uint64 amount,
        MleVerifier.MleProof calldata mleProof
    ) external view returns (bool) {
        if (!postCloseClaimVkInitialized) revert PostCloseClaimVkNotSet();
        _bindLimbsStrict(
            mleProof.publicInputs,
            _expectedPostCloseClaimLimbs(
                channelId,
                closeIntentDigest,
                incomingTxHash,
                receiverSphincsPubkeyHash,
                recipient,
                sharedNativeNullifier,
                amount
            )
        );
        return _verifyPostCloseClaimMle(mleProof);
    }

    function verifyLateOutgoingDebit(
        bytes4 channelId,
        bytes32 closeIntentDigest,
        bytes32 sourceTxHash,
        bytes32 senderSphincsPubkeyHash,
        bytes32 senderAmountDigest,
        bytes32 debitNullifier,
        uint64 amount,
        bytes calldata proof
    ) external pure returns (bool) {
        return _matches(
            proof,
            lateOutgoingDebitPIHash(
                channelId,
                closeIntentDigest,
                sourceTxHash,
                senderSphincsPubkeyHash,
                senderAmountDigest,
                debitNullifier,
                amount
            )
        );
    }

    /// @dev OUTER keccak mirror of the 87-limb `ChannelClosePublicInputs.to_u64_vec()`
    /// (src/circuits/channel/close_pis.rs, post-F4/D6 + delegate account): the legacy 67 limbs —
    /// channelId(1), closeNonce(2), finalEpoch(2), finalSmallBlockNumber(2), closeFreezeNonce(2),
    /// finalChannelStateDigest(8), finalBalanceStateH1(8), channelFundAmount(8),
    /// channelFundIntmaxStateRoot(8), burnTxHash(8), closeWithdrawalDigest(8),
    /// closeIntentDigest(8), snapshotMediumBlockNumber(2) — followed by
    /// split_u64(finalStateVersion)(2), finalSettledTxChain(8), memberSetCommitment(8), the
    /// appended memberCount(1) and then delegateCount(1) at the very END. Each limb is one
    /// big-endian u32 word, so `abi.encodePacked` of the typed fields (memberCount/delegateCount as
    /// uint32) reproduces the byte stream exactly. Total = 87 limbs.
    ///
    /// The INNER keccak (`closeIntentDigest`) mirrors the Rust IMCI preimage
    /// (`CloseIntent::signing_digest()`, src/common/channel.rs) including the
    /// `channel_fund_snapshot.channel_id` slot (second `channelId`) and the appended
    /// finalStateVersion / finalSettledTxChain tail (detail2 §C-8). It is NOT member-bearing, so
    /// it is byte-for-byte unchanged by F4/D6 (the shared close-intent vector is preserved).
    /// Delegate account / via-IR: takes the `CloseProofFields` struct (memory) rather than 16 loose
    /// scalars. Passing one struct pointer (members read by `mload`) instead of marshaling 16
    /// stack arguments is what keeps every caller — and this function's own two keccak encodes —
    /// within the via-IR 16-slot stack budget once the trailing limb count grew from 1
    /// (`memberCount`) to 2 (`memberCount`, `delegateCount`). `fields.memberAndDelegateCount` is the
    /// packed `(memberCount << 8) | delegateCount` (see verifyCloseIntent).
    function closePIHash(CloseProofFields memory fields) public pure returns (bytes32) {
        bytes32 closeIntentDigest = keccak256(
            abi.encodePacked(
                bytes4(CLOSE_INTENT_DOMAIN),
                fields.channelId,
                fields.closeNonce,
                fields.finalEpoch,
                fields.finalSmallBlockNumber,
                fields.closeFreezeNonce,
                fields.finalChannelStateDigest,
                fields.finalBalanceStateH1,
                fields.channelId,
                fields.channelFundAmount,
                fields.channelFundIntmaxStateRoot,
                fields.burnTxHash,
                fields.closeWithdrawalDigest,
                fields.snapshotMediumBlockNumber,
                fields.finalStateVersion,
                fields.finalSettledTxChain
            )
        );
        // Outer 87-limb preimage. The heavy field marshaling is a SINGLE 16-item `abi.encodePacked`
        // into `pre`, then the two count limbs are appended in a TINY second encode where only
        // `pre` + the packed count are live. The trailing limbs are memberCount(1) then
        // delegateCount(1), each a u32 limb unpacked from `memberAndDelegateCount` — byte-identical
        // to the Rust `ChannelClosePublicInputs.to_u64_vec()` tail. The result equals a single
        // abi.encodePacked of all 87 limbs in order.
        bytes memory pre = abi.encodePacked(
            fields.channelId,
            fields.closeNonce,
            fields.finalEpoch,
            fields.finalSmallBlockNumber,
            fields.closeFreezeNonce,
            fields.finalChannelStateDigest,
            fields.finalBalanceStateH1,
            fields.channelFundAmount,
            fields.channelFundIntmaxStateRoot,
            fields.burnTxHash,
            fields.closeWithdrawalDigest,
            closeIntentDigest,
            fields.snapshotMediumBlockNumber,
            fields.finalStateVersion,
            fields.finalSettledTxChain,
            fields.memberSetCommitment
        );
        return keccak256(
            abi.encodePacked(
                pre,
                uint32(fields.memberAndDelegateCount >> 8),   // memberCount
                uint32(fields.memberAndDelegateCount & 0xff)  // delegateCount
            )
        );
    }

    /// @dev F4/D6 member-set commitment (pad-to-MAX): FIXED-length keccak over
    /// `[IMCM, memberCount, h_0..h_{MAX-1}]` — the domain word, the `memberCount` u32 limb, and
    /// ALL `MAX_CHANNEL_MEMBERS` (16) SPHINCS+ pubkey hashes in slot order, where padding slots
    /// (`>= memberCount`) contribute zero. Byte-for-byte mirror of Rust
    /// `close_member_set_commitment` (src/common/channel.rs): one big-endian u32 word per limb
    /// (130 u32 words total = 4 domain + 4 memberCount + 16*32 hash bytes), so
    /// `abi.encodePacked(bytes4(domain), uint32(memberCount), h_0..h_15)` reproduces the preimage.
    ///
    /// SECURITY: this is the in-circuit FIXED form — the close circuit zeroes padding slots and
    /// `memberCount` fixes the active/padding boundary, so the commitment is injective on the
    /// active member set (no non-member-key substitution). The caller MUST pass the channel's
    /// registered hashes already zero-padded to MAX_CHANNEL_MEMBERS.
    function closeMemberSetCommitment(
        bytes32[MAX_CHANNEL_MEMBERS] memory memberSphincsPubkeyHashes,
        uint8 memberCount
    ) public pure returns (bytes32) {
        bytes memory packed = abi.encodePacked(
            bytes4(CLOSE_MEMBER_SET_DOMAIN),
            uint32(memberCount)
        );
        for (uint256 i = 0; i < MAX_CHANNEL_MEMBERS; i++) {
            // SECURITY: zero padding slots (>= memberCount) INTERNALLY, exactly mirroring the Rust
            // `close_member_set_commitment` (which substitutes Bytes32::default() for slots
            // >= member_count) and the in-circuit gadget (which selects zero on slot_is_active).
            // This makes the commitment depend ONLY on memberCount and the active hashes, so it is
            // injective on the active set regardless of any (malformed) padding the caller supplies.
            bytes32 slot = i < memberCount ? memberSphincsPubkeyHashes[i] : bytes32(0);
            packed = abi.encodePacked(packed, slot);
        }
        return keccak256(packed);
    }

    /// @dev Mirrors the Rust `SpecialClose::signing_digest()` (IMSC, src/common/channel.rs): the
    /// block-proposer identity is now `offendingBpMemberSlot`(1 u32 limb) + the proposer's
    /// `offendingBpSphincsPubkeyHash`(8 limbs), replacing the legacy `offendingBpKeyId`(1 limb).
    function specialClosePIHash(
        bytes4 channelId,
        uint8 offendingBpMemberSlot,
        bytes32 offendingBpSphincsPubkeyHash,
        bytes32 fullySignedSmallBlockRoot,
        uint64 smallBlockNumber,
        uint64 signedMediumBlockNumber,
        uint64 latestFinalizedMediumBlockNumber
    ) public pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                bytes4(SPECIAL_CLOSE_DOMAIN),
                channelId,
                uint32(offendingBpMemberSlot),
                offendingBpSphincsPubkeyHash,
                fullySignedSmallBlockRoot,
                smallBlockNumber,
                signedMediumBlockNumber,
                latestFinalizedMediumBlockNumber
            )
        );
    }

    /// @notice TEST-INTROSPECTION HELPER: public view of the EXPECTED 48-limb withdrawal-claim PI
    ///         vector (lets tests build an `MleProof` whose `publicInputs` match the strict bind).
    ///         No security impact (reveals nothing a caller cannot recompute).
    function expectedWithdrawalClaimLimbs(
        bytes4 channelId,
        bytes32 closeIntentDigest,
        bytes32 finalBalanceStateH1,
        bytes32 memberSphincsPubkeyHash,
        address recipient,
        bytes32 userAmountDigest,
        uint64 amount,
        bytes32 withdrawalNullifier
    ) external pure returns (uint256[] memory) {
        return _expectedWithdrawalClaimLimbs(
            channelId,
            closeIntentDigest,
            finalBalanceStateH1,
            memberSphincsPubkeyHash,
            recipient,
            userAmountDigest,
            withdrawalNullifier,
            amount
        );
    }

    /// @notice TEST-INTROSPECTION HELPER: public view of the EXPECTED 40-limb post-close-claim PI
    ///         vector.
    function expectedPostCloseClaimLimbs(
        bytes4 channelId,
        bytes32 closeIntentDigest,
        bytes32 incomingTxHash,
        bytes32 receiverSphincsPubkeyHash,
        address recipient,
        bytes32 sharedNativeNullifier,
        uint64 amount
    ) external pure returns (uint256[] memory) {
        return _expectedPostCloseClaimLimbs(
            channelId,
            closeIntentDigest,
            incomingTxHash,
            receiverSphincsPubkeyHash,
            recipient,
            sharedNativeNullifier,
            amount
        );
    }

    /// @dev Mirrors the 41-limb `CancelClosePublicInputs.to_u64_vec()`
    /// (src/circuits/channel/cancel_close_pis.rs): channelId(1), closeIntentDigest(8),
    /// revivedSmallBlockRoot(8), revivedInterChannelTxDigest(8), revivedTxHash(8),
    /// revivedSeal(8) — with the IMCN domain word prepended. F7: unchanged (no member id in PI).
    function cancelPIHash(
        bytes4 channelId,
        bytes32 closeIntentDigest,
        bytes32 revivedSmallBlockRoot,
        bytes32 revivedInterChannelTxDigest,
        bytes32 revivedTxHash,
        bytes32 revivedSeal
    ) public pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                bytes4(CANCEL_CLOSE_DOMAIN),
                channelId,
                closeIntentDigest,
                revivedSmallBlockRoot,
                revivedInterChannelTxDigest,
                revivedTxHash,
                revivedSeal
            )
        );
    }

    /// @dev Late-outgoing-debit correction PI (Solidity-side challenge primitive). F7: the
    /// sender identity is the member's SPHINCS+ pubkey hash (8 limbs), replacing the legacy
    /// senderUserId(2 limbs), so it keys off the same identity the Manager binds to the member
    /// set.
    function lateOutgoingDebitPIHash(
        bytes4 channelId,
        bytes32 closeIntentDigest,
        bytes32 sourceTxHash,
        bytes32 senderSphincsPubkeyHash,
        bytes32 senderAmountDigest,
        bytes32 debitNullifier,
        uint64 amount
    ) public pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                bytes4(LATE_OUTGOING_DEBIT_DOMAIN),
                closeIntentDigest,
                channelId,
                sourceTxHash,
                senderSphincsPubkeyHash,
                senderAmountDigest,
                debitNullifier,
                amount
            )
        );
    }

    function _matches(bytes calldata proof, bytes32 expected) internal pure returns (bool) {
        return proof.length == 32 && abi.decode(proof, (bytes32)) == expected;
    }
}
