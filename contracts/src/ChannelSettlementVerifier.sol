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
    uint256 internal constant MAX_CHANNEL_MEMBERS = 8;
    /// B-2 (doc/tasks/b2-delegate-close-threat-model.md §4d): the BALANCE-SLOT capacity — the total
    /// number of active PARTICIPANTS (cosigning members + delegates) a channel's balance state can
    /// hold. MUST equal Rust `MAX_CHANNEL_MEMBERS` (src/constants.rs:96 = 1024), which is the bound
    /// the withdrawal-claim / post-close-claim circuits enforce IN-CIRCUIT on
    /// `active = member_count + delegate_count` (withdrawal_claim_circuit.rs:353-371,
    /// post_close_claim_circuit.rs:428-443). DISTINCT from `MAX_CHANNEL_MEMBERS` above, which is the
    /// SIG-CLUSTER cap (Rust `MAX_SIG_CLUSTER` = 8) — the close circuit's signature loop is sized by
    /// that one.
    uint256 internal constant MAX_CHANNEL_PARTICIPANTS = 1024;
    /// B-2: close-PI limb index of `delegateCount` (see the `_expectedCloseLimbs` layout table).
    /// Named because `verifyCloseIntent` reads this limb OUT of the strict loop, before it runs.
    uint256 internal constant CLOSE_PI_DELEGATE_COUNT_INDEX = 94;

    /// Number of RAW Goldilocks public-input limbs the close circuit registers (mirrors Rust
    /// `CHANNEL_CLOSE_PUBLIC_INPUTS_LEN`, src/circuits/channel/close_pis.rs). The close
    /// `WrapperCircuit` re-registers them VERBATIM, so a close `MleProof.publicInputs` is this
    /// raw 103-limb vector — NOT an 8-limb keccak like validity/withdrawal. Stage 3 inserted
    /// `finalSettledTxAccumulatorRoot` (8 limbs) after `finalSettledTxChain`, shifting the tail +8;
    /// multi-token (§N-6, TM-11) appended `tokenFundsDigest` (8 limbs) at the very end (95..103).
    uint256 internal constant CLOSE_PI_LEN = 103;
    /// "IMTF" — token-funds digest domain (multitoken §N-6, TM-11). MUST equal Rust
    /// `TOKEN_FUNDS_DIGEST_DOMAIN` (src/constants.rs) so the on-chain recompute is byte-identical
    /// to `src/common/channel.rs::token_funds_digest`.
    uint32 internal constant TOKEN_FUNDS_DIGEST_DOMAIN = 0x494d5446;
    /// Fixed per-channel token capacity (mirrors Rust `MAX_CHANNEL_TOKENS`, src/constants.rs).
    uint256 internal constant MAX_CHANNEL_TOKENS = 10;
    /// Phase B-D: RAW Goldilocks PI limb counts for the two new binding circuits (mirror Rust
    /// `WITHDRAWAL_CLAIM_PUBLIC_INPUTS_LEN` / `POST_CLOSE_CLAIM_PUBLIC_INPUTS_LEN`). Their
    /// `WrapperCircuit` re-registers the limbs VERBATIM, so the `MleProof.publicInputs` are these
    /// raw vectors (NOT a keccak). Stage 3 appended `finalBalanceStateH1` (8 limbs) and
    /// `finalSettledTxAccumulatorRoot` (8 limbs) to the post-close claim, 40 -> 56.
    /// Multi-token (§N-6): 48 → 50 — `token_slot` (limb 48) and the resolved BASE `token_index`
    /// (limb 49, circuit-enforced == the H1-committed `registry[token_slot]`) appended at the END.
    /// TM-16 (§N-6, Phase 5a): post-close claim 56 → 57 — the BASE `token_index` (limb 56,
    /// circuit-enforced == ids limb 5 of the anchored `incoming_tx_hash` recompute) appended at
    /// the END; it replaces the Manager's genesis-token pin.
    uint256 internal constant WITHDRAWAL_CLAIM_PI_LEN = 50;
    uint256 internal constant POST_CLOSE_CLAIM_PI_LEN = 57;
    /// Phase C1: RAW Goldilocks PI limb count for the CORRECTED cancel-close circuit (mirror Rust
    /// `CANCEL_CLOSE_PUBLIC_INPUTS_LEN`, src/circuits/channel/cancel_close_pis.rs). Its
    /// `WrapperCircuit` re-registers the limbs VERBATIM, so the `MleProof.publicInputs` is this raw
    /// 27-limb vector. Layout: channelId(1) | closeIntentDigest(8) | memberSetCommitment(8) |
    /// revivedStateVersion(2 hi,lo) | revivedChannelStateDigest(8).
    uint256 internal constant CANCEL_CLOSE_PI_LEN = 27;
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
    error MemberSetUpdateVkNotSet();
    error MemberSetUpdateVkDegreeBitsZero();
    /// Multi-token (§N-6, review MINOR 2): `tokenFundsDigest` rejects a token count outside the
    /// in-circuit-enforced 1..=MAX_CHANNEL_TOKENS range, making the Verifier self-contained
    /// defense-in-depth (not reliant on the Manager's structural check + the transitive TFD bind).
    error TokenCountOutOfRange();
    /// B-2 (doc/tasks/b2-delegate-close-threat-model.md §4d): the close proof's `delegateCount` limb
    /// (94) is outside the accepted one-sided range — either BELOW the channel's registered floor
    /// (`fields.minDelegateCount`, i.e. the close claims FEWER delegates than were registered here)
    /// or ABOVE the structural capacity (`memberCount + delegateCount > 1024`, a state the claim
    /// circuits could not serve anyway). DELIBERATELY distinct from the generic
    /// `"close limb mismatch"` revert so this one predicate is diagnosable on its own.
    ///
    /// SECURITY (scope of the floor — review finding 6): this is a CARDINALITY bound, NOT an
    /// identity bound. L1 never binds any delegate to a slot INDEX (`delegateBindings` carries
    /// `(pkG, recipient)` pairs, and nothing ties entry `i` to balance slot `activeMemberCount + i`
    /// in the proof), so the floor cannot deliver "no delegate registered here may be EXCLUDED": a
    /// close carrying a large enough count while a DIFFERENT delegate occupies the region passes it.
    /// What it does deliver is that the active region cannot be SHRUNK below the registered
    /// cardinality — enough to stop a blanket freeze-out of the registered delegate population, not
    /// enough to protect any named delegate. The old strict equality had exactly the same property;
    /// this is a wording correction, not a regression. Per-delegate protection comes from the
    /// leaf-bound recipient / pk_digest / amount bindings inside the claim circuits.
    error CloseDelegateCountOutOfRange();

    event CloseVkInitialized(uint256 degreeBits, bytes32 preprocessedRoot);

    /// @notice The only address allowed to set the close VK (once). Set to the constructor caller.
    address public immutable deployer;

    /// @notice The shared MLE verifier contract used to verify the close proof. Set once, together
    ///         with the close VK, by the deployer (pinned atomically so the verifier the close VK
    ///         was sized for cannot be swapped afterwards).
    MleVerifier public closeMleVerifier;

    /// @notice Close-circuit MLE verification key. `degreeBits == 0` ⇒ unset (reverts on verify).
    CloseVk public closeVk;

    /// detail2 §Q-4: the member-set-update VK. ONLY the per-circuit anchor is stored — the
    /// WHIR/MLE rail (whirParams, kIs, subgroupGenPowers, protocol/session ids, the MleVerifier)
    /// is the WRAPPER's, which is circuit-independent (every inner circuit wraps to the same
    /// degree-13 shape; verified against the close fixture: whirParams/kIs/protocol byte-equal,
    /// only `preprocessedCommitmentRoot` differs). The close rail storage is therefore REUSED;
    /// soundness is pinned by THIS VK's preprocessedRoot/gatesDigest, and a rail mismatch can
    /// only ever fail verification, never accept a foreign proof.
    CloseVk public memberSetUpdateVk;
    bool public memberSetUpdateVkInitialized;

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

    event MemberSetUpdateVkInitialized(uint256 degreeBits, bytes32 preprocessedRoot);

    /// detail2 §Q-4: one-time member-set-update VK initialization. Deployer-only, set exactly
    /// once, degreeBits > 0 — NO disable seam: applyMemberSetUpdate always runs real MLE
    /// verification. Requires the close rail (whir params etc., reused — see the storage doc) to
    /// be initialized first.
    function initializeMemberSetUpdateVk(CloseVk memory _vk) external {
        require(msg.sender == deployer, "only deployer");
        require(!memberSetUpdateVkInitialized, "msu vk already set");
        require(closeVkInitialized, "close rail not initialized");
        if (_vk.degreeBits == 0) revert MemberSetUpdateVkDegreeBitsZero();
        memberSetUpdateVkInitialized = true;
        memberSetUpdateVk = _vk;
        emit MemberSetUpdateVkInitialized(_vk.degreeBits, _vk.preprocessedRoot);
    }

    /// detail2 §Q-4: the member-set-update proof's public-input length —
    /// `[channelId(1) | setVersion(2) | oldCommitment(8) | newCommitment(8) | oldCount(1)
    ///  | newCount(1) | recipient(5)]` (Rust `MEMBER_SET_UPDATE_PUBLIC_INPUTS_LEN`).
    uint256 internal constant MSU_PI_LEN = 26;

    /// @notice REAL on-chain verification of a member-set-update proof (detail2 §Q-4). Binds ALL
    ///         26 raw limbs strictly (canonical-u32 + equality, the close-limb discipline) to the
    ///         caller-supplied expectation, then verifies the MLE proof under the msu VK. The
    ///         proof's in-circuit statement is: the OLD set's full N-of-N (batch Falcon aggregate,
    ///         recursively verified) signed the IMMS digest committing EXACTLY the
    ///         (oldCommitment → newCommitment) transition at this version, with the §Q-3
    ///         structural delta enforced in-circuit.
    function verifyMemberSetUpdate(
        uint32 channelId_,
        uint64 newVersion,
        bytes32 oldCommitment,
        bytes32 newCommitment,
        uint8 oldCount,
        uint8 newCount,
        address recipient,
        MleVerifier.MleProof calldata mleProof
    ) external view returns (bool) {
        if (!memberSetUpdateVkInitialized) revert MemberSetUpdateVkNotSet();
        uint256[] calldata pi = mleProof.publicInputs;
        require(pi.length == MSU_PI_LEN, "msu pi len");
        uint256[] memory expected = new uint256[](MSU_PI_LEN);
        uint256 c = 0;
        expected[c++] = uint256(channelId_);
        c = _putU64(expected, c, newVersion);
        c = _putBytes32(expected, c, oldCommitment);
        c = _putBytes32(expected, c, newCommitment);
        expected[c++] = uint256(oldCount);
        expected[c++] = uint256(newCount);
        // Rust `Address::to_u32_vec`: 5 big-endian u32 words of the 20-byte address.
        for (uint256 i = 0; i < 5; i++) {
            expected[c++] = (uint256(uint160(recipient)) >> (32 * (4 - i))) & 0xffffffff;
        }
        require(c == MSU_PI_LEN, "msu limb count");
        for (uint256 i = 0; i < MSU_PI_LEN; i++) {
            uint256 limb = pi[i];
            require(limb < LIMB_BOUND, "msu limb range");
            require(limb == expected[i], "msu limb mismatch");
        }
        return _verifyMsuMle(mleProof);
    }

    function _verifyMsuMle(MleVerifier.MleProof calldata mleProof) internal view returns (bool) {
        // The close rail (wrapper-shape parameters) with the msu VK's own soundness anchors.
        SpongefishWhirVerify.WhirParams memory whirParams = _loadWhirParams(_closeWhirParams);
        MleVerifier.VerifyParams memory vp = MleVerifier.VerifyParams({
            degreeBits: memberSetUpdateVk.degreeBits,
            preprocessedCommitmentRoot: memberSetUpdateVk.preprocessedRoot,
            numConstants: memberSetUpdateVk.numConstants,
            numRoutedWires: memberSetUpdateVk.numRoutedWires,
            protocolId: closeWhirProtocolId,
            sessionId: closeWhirSplitSessionId,
            kIs: _closeKIs,
            subgroupGenPowers: _closeSubgroupGenPowers
        });
        return closeMleVerifier.verify(mleProof, vp, whirParams, memberSetUpdateVk.gatesDigest);
    }

    /// @notice REAL on-chain verification of the channel-close-intent proof (Phase A).
    /// @dev SECURITY: replaces the former tautological `closePIHash`+`_matches` stub. Two checks,
    ///      both mandatory:
    ///        1. `_bindCloseLimbsStrict` binds ALL 103 raw Goldilocks public-input limbs of the
    ///           close proof, limb-by-limb with STRICT equality (no masking), to the expected vector
    ///           rebuilt from `fields` (`_expectedCloseLimbs`). This binds channelId(0),
    ///           finalStateVersion(67..68), finalSettledTxChain(69..76),
    ///           finalSettledTxAccumulatorRoot(77..84), memberSetCommitment(85..92),
    ///           memberCount(93), delegateCount(94) and tokenFundsDigest(95..102) — NONE are left
    ///           free. The tokenFundsDigest limbs are a RECOMPUTE over the supplied
    ///           (tokenRegistry, tokenCount, channelFundAmounts) — see `_expectedCloseLimbs` — so
    ///           the per-token settlement vectors the Manager stores are proof-bound (TM-11).
    ///        2. `MleVerifier.verify` re-checks the proof against the close VK (circuitDigest absorb,
    ///           preprocessedRoot VK-binding, gatesDigest), blocking cross-circuit replay.
    ///      Reverts (`CloseVkNotSet`) until the VK is set: no verification-disabled window.
    ///
    ///      B-2 (doc/tasks/b2-delegate-close-threat-model.md, option (d)): limb 94 (`delegateCount`)
    ///      is the ONE limb whose expected value is not an L1-rooted constant. It is a decommitment
    ///      of a field of the cosigner-signed H1 (limbs 17..24): the close circuit `connect`s the
    ///      recomputed H1 to that PI (close_circuit.rs:609-620), so a prover cannot move limb 94
    ///      without a Poseidon collision or the N-of-N Falcon signatures. The Manager's
    ///      `activeDelegateCount`, by contrast, is a deployer-asserted constructor argument
    ///      cross-checked against nothing (Option B made L1 registration cosigners-only, so L1 has
    ///      NO independent record of the delegate population — ChannelSettlementManager.sol:771).
    ///      Binding a cosigner-authenticated value with strict equality to a weaker deployer
    ///      assertion bought no soundness and produced only false negatives (every channel whose
    ///      delegate count moved after manager deployment could neither close nor partially
    ///      withdraw). It is therefore replaced by an explicit ONE-SIDED RANGE predicate, evaluated
    ///      BEFORE the strict loop, and the validated value is then written into the expected vector
    ///      so the loop still accounts for all 103 limbs (NONE are left free — that structural
    ///      invariant is load-bearing for auditability).
    function verifyCloseIntent(
        CloseProofFields calldata fields,
        MleVerifier.MleProof calldata mleProof
    ) external view returns (bool) {
        if (!closeVkInitialized) revert CloseVkNotSet();
        uint256[] calldata pi = mleProof.publicInputs;
        // SECURITY (B-2 A-4): the length check is HOISTED out of `_bindCloseLimbsStrict` because the
        // delegate-count predicate below indexes `pi[94]` BEFORE the strict loop runs. Reading limb
        // 94 of a shorter array would be an out-of-bounds calldata read. Same revert string as the
        // in-loop check it replaces, so the failure mode is unchanged for short vectors.
        require(pi.length == CLOSE_PI_LEN, "close pi len");
        uint256 delegateCount = pi[CLOSE_PI_DELEGATE_COUNT_INDEX];
        // SECURITY (B-2 A-5): canonicality (`< 2**32`) is checked BEFORE any arithmetic on the limb.
        // Without it the `memberCount + delegateCount` sum below could be a 0.8 overflow panic rather
        // than the explicit named error, and a non-canonical limb is never a legitimate close PI.
        // `_bindCloseLimbsStrict` re-checks this limb (and all others) — the duplication is
        // deliberate: the loop stays a self-contained, inspectable "every limb is canonical" pass.
        require(delegateCount < LIMB_BOUND, "close limb range");
        // SECURITY (B-2 §4d, floor): `delegate_count` only ever INCREASES — `join_delegate`
        // (src/bin/channel_member.rs) increments and there is no leave path — so L1 can still
        // insist that the active region `[0, member_count + delegate_count)` is at least as WIDE as
        // the delegate population registered at manager-deployment time. A deflated count shrinks
        // that region and makes the claims of whoever occupies its tail unprovable (threat model
        // §3.3).
        // SCOPE (review finding 6): this is a CARDINALITY bound, not an identity one — L1 binds no
        // delegate to a slot INDEX, so it cannot single out a NAMED delegate as excluded. See the
        // `CloseDelegateCountOutOfRange` doc comment.
        if (delegateCount < fields.minDelegateCount) revert CloseDelegateCountOutOfRange();
        // SECURITY (B-2 §4d, ceiling): mirror of the IN-CIRCUIT bound the claim circuits enforce on
        // `active = member_count + delegate_count` (`active <= MAX_CHANNEL_MEMBERS = 1024`,
        // withdrawal_claim_circuit.rs:353-371). `fields.memberCount` is itself strict-equality-bound
        // to limb 93 by the loop below, so this is a bound on the PROOF's own participant count, not
        // on a caller-chosen number. No arithmetic overflow is possible: memberCount is uint8 and
        // delegateCount was just bounded by 2**32.
        if (uint256(fields.memberCount) + delegateCount > MAX_CHANNEL_PARTICIPANTS) {
            revert CloseDelegateCountOutOfRange();
        }
        // SECURITY (B-2 A-6): the VALIDATED delegate count is passed in explicitly, and limb 93
        // (`memberCount`) keeps its STRICT equality against the channel's registered
        // `activeMemberCount`. Limb 93 must NEVER get the same pass-through treatment: a state with a
        // smaller `member_count` would close under fewer than N signatures (the close circuit gates
        // its signature loop on `i < member_count`, close_circuit.rs:498-528).
        _bindCloseLimbsStrict(pi, _expectedCloseLimbs(fields, delegateCount));
        return _verifyCloseMle(mleProof);
    }

    /// @dev Bind the proof's public-input limbs to the expected close vector. `pi` MUST be exactly
    ///      `CLOSE_PI_LEN` (103) limbs; each limb MUST equal the expected limb (strict equality, no
    ///      masking) AND be a canonical u32 (`< 2**32`). Reverts on any violation — there is no
    ///      partial / masked match.
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

    /// @notice TEST-INTROSPECTION HELPER: public view passthrough exposing the EXPECTED 103-limb
    ///         close public-input vector for `fields`. Lets the manager-lifecycle tests build a
    ///         close `MleVerifier.MleProof` whose `publicInputs` equal exactly what
    ///         `verifyCloseIntent`'s `_bindCloseLimbsStrict` will require. It is a pure view of the
    ///         same `_expectedCloseLimbs` the binding uses (no security impact — it reveals nothing
    ///         a caller cannot already recompute from `fields`).
    /// @param delegateCount B-2: the limb-94 value to lay out. `verifyCloseIntent` takes this from
    ///        the PROOF (after the range predicate); this helper takes it from the caller so a test
    ///        can build a vector for ANY delegate count, including ones the predicate rejects. It
    ///        deliberately does NOT apply the range predicate — it is a pure layout view, not a
    ///        verification entry point.
    function expectedCloseLimbs(CloseProofFields calldata fields, uint32 delegateCount)
        external
        pure
        returns (uint256[] memory)
    {
        return _expectedCloseLimbs(fields, uint256(delegateCount));
    }

    /// @notice Byte-exact Solidity mirror of the Rust `token_funds_digest`
    ///         (src/common/channel.rs; multitoken §N-6, TM-11): a single keccak over the FIXED
    ///         92-word preimage `[IMTF, registry (10 x u32), token_count (1 x u32),
    ///         amounts (10 x U256 = 80 words)]` — ALWAYS full width regardless of `tokenCount`
    ///         (omitting unused entries would make the preimage variable-length and alias distinct
    ///         `(registry, amounts)` pairs). `abi.encodePacked` emits each uint32 as 4 BE bytes and
    ///         each uint256 as 32 BE bytes, reproducing the Rust u32-word stream exactly (pinned by
    ///         the Rust↔Solidity shared vector `test_tokenFundsDigest_matchesRustSharedVector`).
    function tokenFundsDigest(
        uint32[10] memory tokenRegistry,
        uint8 tokenCount,
        uint256[10] memory amounts
    ) public pure returns (bytes32) {
        // SECURITY (review MINOR 2, TM-8): the close circuit constrains token_count to 1..=10
        // in-circuit, so no legitimate TFD preimage exists outside that range — reject here so
        // this recompute (and every `_expectedCloseLimbs` caller) is self-contained defense-in-
        // depth rather than relying on the Manager's structural check.
        if (tokenCount == 0 || tokenCount > MAX_CHANNEL_TOKENS) revert TokenCountOutOfRange();
        // NOTE: abi.encodePacked(uint32[10] memory) would pad each element to 32 bytes, which does
        // NOT match the Rust 4-byte-per-u32 packing — the registry words are packed manually.
        bytes memory pre = abi.encodePacked(bytes4(TOKEN_FUNDS_DIGEST_DOMAIN));
        for (uint256 t = 0; t < MAX_CHANNEL_TOKENS; t++) {
            pre = abi.encodePacked(pre, tokenRegistry[t]);
        }
        pre = abi.encodePacked(pre, uint32(tokenCount));
        for (uint256 t = 0; t < MAX_CHANNEL_TOKENS; t++) {
            pre = abi.encodePacked(pre, amounts[t]);
        }
        return keccak256(pre);
    }

    /// @dev Build the EXPECTED 103-limb close public-input vector from `fields`, in the EXACT order
    ///      of the Rust `ChannelClosePublicInputs::to_u64_vec()` (layout pinned by the Rust
    ///      `close_public_inputs_roundtrip` limb-index assertions and the Solidity
    ///      `test_expectedCloseLimbs_goldenVector`). Each multi-limb field is split into big-endian
    ///      u32 words; each u64 scalar is split into (hi, lo). The `closeIntentDigest` (limbs
    ///      57..64) is RECOMPUTED here via `_closeIntentDigest`, and the `tokenFundsDigest` (limbs
    ///      95..102) is RECOMPUTED via `tokenFundsDigest` from the supplied
    ///      (tokenRegistry, tokenCount, channelFundAmounts) — neither is a caller-suppliable digest,
    ///      so the strict bind forces the proof's in-circuit digests to equal recomputes over the
    ///      vectors the Manager will settle with (TM-11). `memberSetCommitment` (limbs 85..92) is
    ///      the channel-registered value the manager passes.
    ///
    ///      Layout (limb index → field):
    ///        [0]      channelId
    ///        [1..2]   closeNonce (hi, lo)
    ///        [3..4]   finalEpoch
    ///        [5..6]   finalSmallBlockNumber
    ///        [7..8]   closeFreezeNonce
    ///        [9..16]  finalChannelStateDigest (8 BE u32)
    ///        [17..24] finalBalanceStateH1
    ///        [25..32] channelFundAmount = channelFundAmounts[0] (uint256, 8 BE u32; the close
    ///                 burn is denominated in the genesis token — Phase 2a wired amounts[0] to
    ///                 this PI)
    ///        [33..40] channelFundIntmaxStateRoot
    ///        [41..48] burnTxHash
    ///        [49..56] closeWithdrawalDigest
    ///        [57..64] closeIntentDigest (RECOMPUTED; preimage carries ALL 10 amounts)
    ///        [65..66] snapshotMediumBlockNumber
    ///        [67..68] finalStateVersion
    ///        [69..76] finalSettledTxChain
    ///        [77..84] finalSettledTxAccumulatorRoot  (Stage 3, inserted here)
    ///        [85..92] memberSetCommitment            (shifted +8)
    ///        [93]     memberCount                    (shifted +8)
    ///        [94]     delegateCount                  (shifted +8; B-2: the caller-VALIDATED value,
    ///                 see `delegateCount` below)
    ///        [95..102] tokenFundsDigest              (multi-token §N-6, RECOMPUTED, appended)
    ///
    /// @param delegateCount B-2 (threat model §4d step 3): the ALREADY-RANGE-CHECKED limb-94 value.
    ///        SECURITY: this is the one expected limb that is NOT an L1-rooted constant — it comes
    ///        from the proof itself. It is passed as an explicit argument, never read from `pi`
    ///        inside this function, precisely so that the only place it can enter the expected
    ///        vector is a call site that has already run the floor/ceiling predicate
    ///        (`verifyCloseIntent`). Its authority is the N-of-N cosigner signature over the H1 that
    ///        the close circuit forces limb 94 to decommit (threat model §5); L1 adds only
    ///        monotonicity + capacity on top.
    function _expectedCloseLimbs(CloseProofFields calldata fields, uint256 delegateCount)
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
        c = _putUint256(limbs, c, fields.channelFundAmounts[0]);
        c = _putBytes32(limbs, c, fields.channelFundIntmaxStateRoot);
        c = _putBytes32(limbs, c, fields.burnTxHash);
        c = _putBytes32(limbs, c, fields.closeWithdrawalDigest);
        c = _putBytes32(limbs, c, _closeIntentDigest(fields));
        c = _putU64(limbs, c, fields.snapshotMediumBlockNumber);
        c = _putU64(limbs, c, fields.finalStateVersion);
        c = _putBytes32(limbs, c, fields.finalSettledTxChain);
        // Stage 3: the accumulator root is inserted IMMEDIATELY AFTER the chain (byte-identical to
        // the Rust close-PI order / the H1 preimage), shifting memberSetCommitment / counts +8.
        c = _putBytes32(limbs, c, fields.finalSettledTxAccumulatorRoot);
        c = _putBytes32(limbs, c, fields.memberSetCommitment);
        // SECURITY (B-2 A-6): limb 93 stays a STRICT equality against the channel's registered
        // `activeMemberCount` — it is the L1-rooted half of the member/delegate boundary (also
        // hashed into `memberSetCommitment`, limbs 85..92, which the constructor cross-checks
        // against the rollup registry). Never give it the limb-94 pass-through treatment.
        limbs[c++] = uint256(fields.memberCount);
        // B-2: the validated, proof-derived delegate count (floor+ceiling checked by the caller).
        limbs[c++] = delegateCount;
        // Multi-token (§N-6, TM-11): RECOMPUTED over the supplied settlement vectors, appended at
        // the very end. The strict bind then forces the proof's member-signed in-circuit TFD to
        // equal this recompute, proof-binding the (registry, count, amounts) the Manager stores.
        c = _putBytes32(
            limbs,
            c,
            tokenFundsDigest(fields.tokenRegistry, fields.tokenCount, fields.channelFundAmounts)
        );
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
    ///      from `channel_fund_snapshot` and the finalStateVersion / finalSettledTxChain tail).
    ///
    ///      Multi-token (§N-6, TM-11): the former single 8-word `channel_fund_amount` segment is
    ///      widened IN PLACE to the ALWAYS-full-width 80-word `channelFundAmounts[0..10]` vector
    ///      (each uint256 = 8 BE u32 words), byte-identical to the Rust preimage (shared vector:
    ///      `close_intent_digest_matches_solidity_shared_vector`). Built in two concatenated chunks
    ///      for the via-IR stack budget; the byte stream equals one flat encodePacked.
    function _closeIntentDigest(CloseProofFields calldata fields) internal pure returns (bytes32) {
        bytes memory head = abi.encodePacked(
            bytes4(CLOSE_INTENT_DOMAIN),
            fields.channelId,
            fields.closeNonce,
            fields.finalEpoch,
            fields.finalSmallBlockNumber,
            fields.closeFreezeNonce,
            fields.finalChannelStateDigest,
            fields.finalBalanceStateH1,
            fields.channelId
        );
        // amounts[0..10]: abi.encodePacked emits each uint256 as its 32 big-endian bytes, exactly
        // the Rust `U256::to_u32_vec` 8-word stream per amount (80 words total, zero-padded slots
        // included — fixed-width injective, TM-11).
        for (uint256 t = 0; t < MAX_CHANNEL_TOKENS; t++) {
            head = abi.encodePacked(head, fields.channelFundAmounts[t]);
        }
        return keccak256(
            abi.encodePacked(
                head,
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
    error CancelCloseVkNotSet();
    error StatementVkDegreeBitsZero();

    event WithdrawalClaimVkInitialized(uint256 degreeBits, bytes32 preprocessedRoot);
    event PostCloseClaimVkInitialized(uint256 degreeBits, bytes32 preprocessedRoot);
    event CancelCloseVkInitialized(uint256 degreeBits, bytes32 preprocessedRoot);

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

    // ── cancel-close VK storage (Phase C1) ──
    MleVerifier public cancelCloseMleVerifier;
    StatementVk public cancelCloseVk;
    bool public cancelCloseVkInitialized;
    SpongefishWhirVerify.WhirParams internal _cancelCloseWhirParams;
    bytes public cancelCloseWhirProtocolId;
    bytes public cancelCloseWhirSplitSessionId;
    uint256[] internal _cancelCloseKIs;
    uint256[] internal _cancelCloseSubgroupGenPowers;

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

    /// @notice Set the cancel-close MLE VK + verifier (Phase C1). Deployer-only, set EXACTLY ONCE,
    ///         degreeBits>0. Mirrors `initializeCloseVk` / `initializeWithdrawalClaimVk`.
    function initializeCancelCloseVk(
        MleVerifier verifier_,
        StatementVk memory _vk,
        SpongefishWhirVerify.WhirParams memory whirParams_,
        bytes memory _protocolId,
        bytes memory _sessionId,
        uint256[] memory _kIs,
        uint256[] memory _subgroupGenPowers
    ) external {
        require(msg.sender == deployer, "only deployer");
        require(!cancelCloseVkInitialized, "cancel close vk already set");
        if (_vk.degreeBits == 0) revert StatementVkDegreeBitsZero();
        cancelCloseVkInitialized = true;
        cancelCloseMleVerifier = verifier_;
        cancelCloseVk = _vk;
        _copyWhirParams(_cancelCloseWhirParams, whirParams_);
        cancelCloseWhirProtocolId = _protocolId;
        cancelCloseWhirSplitSessionId = _sessionId;
        for (uint256 i = 0; i < _kIs.length; i++) {
            _cancelCloseKIs.push(_kIs[i]);
        }
        for (uint256 i = 0; i < _subgroupGenPowers.length; i++) {
            _cancelCloseSubgroupGenPowers.push(_subgroupGenPowers[i]);
        }
        emit CancelCloseVkInitialized(_vk.degreeBits, _vk.preprocessedRoot);
    }

    /// @dev Build the EXPECTED 27-limb cancel-close PI vector, in the EXACT order of the Rust
    ///      `CancelClosePublicInputs::to_u64_vec()` (pinned by the Rust↔Solidity golden vector
    ///      `cancel_close_public_inputs_match_solidity_shared_vector`). Layout:
    ///        [0]      channelId                  (u32 value)
    ///        [1..9]   closeIntentDigest          (8 BE u32)
    ///        [9..17]  memberSetCommitment        (8 BE u32) — REGISTERED set (manager-injected)
    ///        [17..19] revivedStateVersion        (hi, lo)
    ///        [19..27] revivedChannelStateDigest  (8 BE u32)
    ///
    ///      SECURITY (Finding D fix): `memberSetCommitment` is NOT a caller-supplied request field —
    ///      `ChannelSettlementManager.cancelClose` passes `registeredMemberSetCommitment()` here, the
    ///      SAME mechanism the close path uses (`_runCloseVerify`). The strict bind then forces the
    ///      proof's in-circuit member-set commitment to equal the channel's registered member set, so
    ///      a third party cannot forge a cancel with their own keys.
    function _expectedCancelCloseLimbs(
        bytes4 channelId,
        bytes32 closeIntentDigest,
        bytes32 memberSetCommitment,
        uint64 revivedStateVersion,
        bytes32 revivedChannelStateDigest
    ) internal pure returns (uint256[] memory limbs) {
        limbs = new uint256[](CANCEL_CLOSE_PI_LEN);
        uint256 c = 0;
        limbs[c++] = uint256(uint32(channelId));
        c = _putBytes32(limbs, c, closeIntentDigest);
        c = _putBytes32(limbs, c, memberSetCommitment);
        c = _putU64(limbs, c, revivedStateVersion);
        c = _putBytes32(limbs, c, revivedChannelStateDigest);
        require(c == CANCEL_CLOSE_PI_LEN, "cancel limb count");
    }

    function _verifyCancelCloseMle(MleVerifier.MleProof calldata mleProof)
        internal view returns (bool)
    {
        SpongefishWhirVerify.WhirParams memory whirParams =
            _loadWhirParams(_cancelCloseWhirParams);
        MleVerifier.VerifyParams memory vp = MleVerifier.VerifyParams({
            degreeBits: cancelCloseVk.degreeBits,
            preprocessedCommitmentRoot: cancelCloseVk.preprocessedRoot,
            numConstants: cancelCloseVk.numConstants,
            numRoutedWires: cancelCloseVk.numRoutedWires,
            protocolId: cancelCloseWhirProtocolId,
            sessionId: cancelCloseWhirSplitSessionId,
            kIs: _cancelCloseKIs,
            subgroupGenPowers: _cancelCloseSubgroupGenPowers
        });
        return cancelCloseMleVerifier.verify(
            mleProof, vp, whirParams, cancelCloseVk.gatesDigest
        );
    }

    /// @dev Build the EXPECTED 50-limb withdrawal-claim PI vector, in the EXACT order of the Rust
    ///      `WithdrawalClaimPublicInputs::to_u64_vec()`
    ///      (src/circuits/channel/withdrawal_claim_pis.rs). Layout:
    ///        [0..8]   closeIntentDigest        (8 BE u32)
    ///        [8]      channelId                (u32 value)
    ///        [9..17]  finalBalanceStateH1
    ///        [17..25] memberPkG
    ///        [25..30] recipient                (5 BE u32, 160-bit address)
    ///        [30..38] userAmountDigest
    ///        [38..46] withdrawalNullifier
    ///        [46..48] amount                   (hi, lo)
    ///        [48]     tokenSlot                (multi-token §N-6: the claimed LOCAL slot; drives
    ///                 the in-circuit one-hot ct select, the `< token_count` bound and the IMW2
    ///                 nullifier limb — TM-5/TM-8)
    ///        [49]     tokenIndex               (multi-token §N-6, review m8: the resolved BASE
    ///                 token, circuit-enforced == the H1-committed `registry[tokenSlot]` — NEVER a
    ///                 prover/caller choice; the asset L1 pays this claim in)
    function _expectedWithdrawalClaimLimbs(
        bytes4 channelId,
        bytes32 closeIntentDigest,
        bytes32 finalBalanceStateH1,
        bytes32 memberPkG,
        address recipient,
        bytes32 userAmountDigest,
        bytes32 withdrawalNullifier,
        uint64 amount,
        uint8 tokenSlot,
        uint32 tokenIndex
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
        limbs[c++] = uint256(tokenSlot);
        limbs[c++] = uint256(tokenIndex);
        require(c == WITHDRAWAL_CLAIM_PI_LEN, "wclaim limb count");
    }

    /// @dev Build the EXPECTED 57-limb post-close-claim PI vector, in the EXACT order of the Rust
    ///      `PostCloseClaimPublicInputs::to_u64_vec()` (pinned by
    ///      `post_close_claim_public_inputs_match_solidity_shared_vector`). Layout:
    ///        [0..8]   closeIntentDigest
    ///        [8]      receiverChannelId             (u32 value)
    ///        [9..17]  incomingTxHash
    ///        [17..25] receiverPkG
    ///        [25..30] recipient                     (5 BE u32)
    ///        [30..38] sharedNativeNullifier
    ///        [38..40] amount                        (hi, lo)
    ///        [40..48] finalBalanceStateH1           (Stage 3, appended)
    ///        [48..56] finalSettledTxAccumulatorRoot (Stage 3, appended)
    ///        [56]     tokenIndex                    (TM-16 §N-6: the BASE token the anchored
    ///                 incoming tx moved — in-circuit it IS ids limb 5 of the `incomingTxHash`
    ///                 recompute, so the accumulator leaf commits it; never a prover/caller
    ///                 choice. The Manager credits `withdrawalCredits[tokenIndex]` with this.)
    function _expectedPostCloseClaimLimbs(
        bytes4 channelId,
        bytes32 closeIntentDigest,
        bytes32 incomingTxHash,
        bytes32 receiverPkG,
        address recipient,
        bytes32 sharedNativeNullifier,
        uint64 amount,
        bytes32 finalBalanceStateH1,
        bytes32 finalSettledTxAccumulatorRoot,
        uint32 tokenIndex
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
        // Stage 3: appended after the legacy 40 limbs (receiver-pk bind anchor + source-tx anchor).
        c = _putBytes32(limbs, c, finalBalanceStateH1);
        c = _putBytes32(limbs, c, finalSettledTxAccumulatorRoot);
        // TM-16: the base token limb, strict-bound like every other limb.
        limbs[c++] = uint256(tokenIndex);
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
    ///      mandatory checks: (1) `_bindLimbsStrict` binds ALL 50 raw Goldilocks limbs limb-by-limb
    ///      (strict eq, <2**32, no mask) to the expected vector; (2) `MleVerifier.verify` re-checks
    ///      the proof against the withdrawal-claim VK (circuitDigest/preprocessedRoot/gatesDigest →
    ///      cross-circuit replay blocked). Reverts until the VK is set.
    ///      `amount` is bound as a PI limb AND, in-circuit, to the slot ciphertext plaintext: the
    ///      withdrawal claim circuit's `decryption_core(expose_amount = true)` recomputes
    ///      `v = c2 - c1*s` under the leaf-bound Regev key and `connect`s the decoded 64-bit amount to
    ///      the `amount` PI (withdrawal_claim_circuit.rs), so a member can only claim exactly what
    ///      their signed slot ciphertext decrypts to — over-claim is prevented at the proof level, not
    ///      merely bounded by the manager's fund caps.
    ///      Multi-token (§N-6): `tokenSlot` (limb 48) and `tokenIndex` (limb 49) are strict-bound
    ///      too. In-circuit, `tokenSlot` selects the claimed ciphertext position (one-hot, `<
    ///      token_count`) and `tokenIndex == registry[tokenSlot]` of the H1-committed registry — so
    ///      the ASSET this claim pays in is proof-enforced, never a caller choice (TM-2/TM-8, m8).
    function verifyWithdrawalClaim(
        bytes4 channelId,
        bytes32 closeIntentDigest,
        bytes32 finalBalanceStateH1,
        bytes32 memberSphincsPubkeyHash,
        address recipient,
        bytes32 userAmountDigest,
        uint64 amount,
        uint8 tokenSlot,
        uint32 tokenIndex,
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
                amount,
                tokenSlot,
                tokenIndex
            )
        );
        return _verifyWithdrawalClaimMle(mleProof);
    }

    /// @notice REAL on-chain verification of the CORRECTED cancelClose proof (Phase C1).
    /// @dev SECURITY: replaces the former forgeable `cancelPIHash`+`_matches` stub (the legacy
    ///      41-limb revived-tx design had no member binding — Finding D — and an unsound staleness
    ///      predicate — Finding B). Two mandatory checks:
    ///        1. `_bindLimbsStrict` binds ALL 27 raw Goldilocks limbs limb-by-limb (strict eq,
    ///           <2**32, no mask) to the expected vector. This binds channelId(0),
    ///           closeIntentDigest(1..8), memberSetCommitment(9..16), revivedStateVersion(17..18)
    ///           and revivedChannelStateDigest(19..26) — NONE are left free. The in-circuit
    ///           constraints already proved `revivedStateVersion > close.finalStateVersion` (the
    ///           Finding-B staleness fix) and the era fence against the close intent whose digest is
    ///           `closeIntentDigest`.
    ///        2. `MleVerifier.verify` re-checks the proof against the cancel-close VK (circuitDigest
    ///           absorb, preprocessedRoot VK-binding, gatesDigest), blocking cross-circuit replay.
    ///      FINDING D FIX: `memberSetCommitment` is the channel's REGISTERED member-set commitment,
    ///      passed by `ChannelSettlementManager.cancelClose` from `registeredMemberSetCommitment()`
    ///      (NOT a caller request field). The strict bind forces the proof's in-circuit member-set
    ///      commitment to equal it, so the verified signing keys are the channel's registered
    ///      members — a third party cannot forge a cancel with their own keys.
    ///      Reverts (`CancelCloseVkNotSet`) until the VK is set: no verification-disabled window.
    function verifyCancelClose(
        bytes4 channelId,
        bytes32 closeIntentDigest,
        bytes32 memberSetCommitment,
        uint64 revivedStateVersion,
        bytes32 revivedChannelStateDigest,
        MleVerifier.MleProof calldata mleProof
    ) external view returns (bool) {
        if (!cancelCloseVkInitialized) revert CancelCloseVkNotSet();
        _bindLimbsStrict(
            mleProof.publicInputs,
            _expectedCancelCloseLimbs(
                channelId,
                closeIntentDigest,
                memberSetCommitment,
                revivedStateVersion,
                revivedChannelStateDigest
            )
        );
        return _verifyCancelCloseMle(mleProof);
    }

    /// @notice TEST-INTROSPECTION HELPER: public view of the EXPECTED 27-limb cancel-close PI vector
    ///         (lets tests build an `MleProof` whose `publicInputs` match the strict bind). No
    ///         security impact (reveals nothing a caller cannot recompute).
    function expectedCancelCloseLimbs(
        bytes4 channelId,
        bytes32 closeIntentDigest,
        bytes32 memberSetCommitment,
        uint64 revivedStateVersion,
        bytes32 revivedChannelStateDigest
    ) external pure returns (uint256[] memory) {
        return _expectedCancelCloseLimbs(
            channelId,
            closeIntentDigest,
            memberSetCommitment,
            revivedStateVersion,
            revivedChannelStateDigest
        );
    }

    /// @notice REAL on-chain verification of the post-close-claim binding proof (Phase B-D +
    ///         Stage 3).
    /// @dev SECURITY: (1) `_bindLimbsStrict` binds ALL 56 raw Goldilocks limbs; (2)
    ///      `MleVerifier.verify` against the post-close-claim VK. Reverts until the VK is set.
    ///      HAZARD #8: `sharedNativeNullifier` is DERIVED in-circuit from
    ///      keccak(IMCK, closeIntentDigest, incomingTxHash, receiverPkG); the manager passes the
    ///      RECOMPUTED value here (not an opaque claim field), so the binding rejects a
    ///      freshly-picked nullifier. STAGE 3: `finalBalanceStateH1` (the receiver-pk one-hot bind
    ///      anchor) and `finalSettledTxAccumulatorRoot` (the source-tx Merkle inclusion anchor) are
    ///      the FINALIZED values the manager passes from `finalizeClose`; the in-circuit recompute +
    ///      inclusion proof are bound to them. Over-claim is CLOSED (amount == decrypted plaintext)
    ///      and the claim is anchored to a REAL signed settle (no vacuous inclusion).
    ///      TM-16 (§N-6): `tokenIndex` (limb 56) is strict-bound too — in-circuit it is the SAME
    ///      wire as ids limb 5 of the anchored `incomingTxHash` recompute, so the token the
    ///      Manager credits is exactly the one the absorbed accumulator leaf commits.
    function verifyPostCloseClaim(
        bytes4 channelId,
        bytes32 closeIntentDigest,
        bytes32 incomingTxHash,
        bytes32 receiverSphincsPubkeyHash,
        address recipient,
        bytes32 sharedNativeNullifier,
        uint64 amount,
        bytes32 finalBalanceStateH1,
        bytes32 finalSettledTxAccumulatorRoot,
        uint32 tokenIndex,
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
                amount,
                finalBalanceStateH1,
                finalSettledTxAccumulatorRoot,
                tokenIndex
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

    // NOTE (multitoken Phase 3): the legacy `closePIHash` outer-keccak mirror was REMOVED. It had
    // no remaining caller (the live close path strict-binds the 103 raw limbs via
    // `_bindCloseLimbsStrict`, never a keccak of them), and keeping a second, parallel preimage
    // mirror in sync with every PI-layout change is exactly the stale-mirror hazard class TM-11
    // warns about. The IMCI inner keccak lives on as `_closeIntentDigest`.

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

    /// @notice TEST-INTROSPECTION HELPER: public view of the EXPECTED 50-limb withdrawal-claim PI
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
        uint8 tokenSlot,
        uint32 tokenIndex,
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
            amount,
            tokenSlot,
            tokenIndex
        );
    }

    /// @notice TEST-INTROSPECTION HELPER: public view of the EXPECTED 57-limb post-close-claim PI
    ///         vector (Stage 3: + finalBalanceStateH1 + finalSettledTxAccumulatorRoot; TM-16:
    ///         + tokenIndex at limb 56).
    function expectedPostCloseClaimLimbs(
        bytes4 channelId,
        bytes32 closeIntentDigest,
        bytes32 incomingTxHash,
        bytes32 receiverSphincsPubkeyHash,
        address recipient,
        bytes32 sharedNativeNullifier,
        uint64 amount,
        bytes32 finalBalanceStateH1,
        bytes32 finalSettledTxAccumulatorRoot,
        uint32 tokenIndex
    ) external pure returns (uint256[] memory) {
        return _expectedPostCloseClaimLimbs(
            channelId,
            closeIntentDigest,
            incomingTxHash,
            receiverSphincsPubkeyHash,
            recipient,
            sharedNativeNullifier,
            amount,
            finalBalanceStateH1,
            finalSettledTxAccumulatorRoot,
            tokenIndex
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
