// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IChannelSettlementVerifier, CloseProofFields} from "./ChannelSettlementManager.sol";
import {IPinnedMleVerifierV2} from "./IPinnedMleVerifierV2.sol";

/// @dev The four value-authorizing circuit statements (close, withdrawal claim, cancel close and
/// post-close claim) use distinct immutable compact-v2 adapters and strictly rebind every returned
/// public-input limb. The legacy `verifySpecialClose` and `verifyLateOutgoingDebit` digest stubs
/// remain only for ABI compatibility; their manager entry points remain disabled.
///
/// F7 (one SPHINCS+ key per member): member identity is the SPHINCS+ pubkey hash (bytes32, 8
/// limbs); the legacy `bytes8 userId` (2 limbs) is removed from the withdrawal / post-close
/// claims, and the close PI appends a `memberSetCommitment` (keccak over the 3 members' pubkey
/// hashes) so L1 binds the verified signing keys to the channel's registered member set.
contract ChannelSettlementVerifier is IChannelSettlementVerifier {
    /// "IMCS" — canonical metadata-free close-state identity.
    uint32 internal constant CLOSE_STATE_ID_DOMAIN = 0x494d4353;
    uint32 internal constant SPECIAL_CLOSE_DOMAIN = 0x494d5343;
    uint32 internal constant CANCEL_CLOSE_DOMAIN = 0x494d434e;
    uint32 internal constant LATE_OUTGOING_DEBIT_DOMAIN = 0x494d4c44;
    /// "IMCM" — close-circuit member-set commitment domain (mirrors Rust
    /// `CLOSE_MEMBER_SET_DOMAIN` / `close_member_set_commitment`, src/common/channel.rs).
    uint32 internal constant CLOSE_MEMBER_SET_DOMAIN = 0x494d434d;
    /// D6 pad-to-MAX: the close circuit is sized for this many cosigner slots (mirrors Rust
    /// `MAX_SIG_CLUSTER`, src/constants.rs). Active members occupy slots `0..memberCount`;
    /// padding slots are zero. The legacy internal name denotes this sig-cluster width, not the
    /// separate 1024-slot balance capacity.
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
    /// `WrapperCircuit` re-registers them VERBATIM, so the adapter-authenticated public input is this
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
    /// `WrapperCircuit` re-registers the limbs VERBATIM, so the authenticated public inputs are these
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
    /// `WrapperCircuit` re-registers the limbs VERBATIM, so the authenticated public input is this raw
    /// 29-limb vector. Layout: channelId(1) | closeIntentDigest/closeStateId(8) |
    /// memberSetCommitment(8) | closeFinalStateVersion(2 hi,lo) |
    /// revivedStateVersion(2 hi,lo) | revivedChannelStateDigest(8).
    uint256 internal constant CANCEL_CLOSE_PI_LEN = 29;
    /// 2**32 — every close PI limb is a u32 word, so a canonical limb is strictly below this.
    uint256 internal constant LIMB_BOUND = 0x1_0000_0000;

    error InvalidPinnedMleVerifier(address verifier);
    error PinnedMleVerifierChainMismatch(address verifier, uint256 expected, uint256 actual);
    error DuplicatePinnedMleVerifier();
    /// Multi-token (§N-6, review MINOR 2): `tokenFundsDigest` rejects a token count outside the
    /// in-circuit-enforced 1..=MAX_CHANNEL_TOKENS range, making the Verifier self-contained
    /// defense-in-depth (not reliant on the Manager's structural check + the transitive TFD bind).
    error TokenCountOutOfRange();
    /// B-2: the close proof's `delegateCount` limb (94) differs from the immutable live-snapshot
    /// count (`fields.minDelegateCount`; legacy field name) or exceeds the structural capacity when
    /// added to `memberCount`. Settlement activation freezes joins and the complete participant
    /// root/count, so both shrinking and widening this boundary describe a different unsupported
    /// snapshot. DELIBERATELY distinct from the generic `"close limb mismatch"` revert so this
    /// snapshot predicate is diagnosable on its own.
    ///
    /// SECURITY SCOPE: limb 94 binds cardinality, not delegate identities. Identity/slot/recipient
    /// protection is supplied separately by the Manager's immutable participant root and the
    /// leaf-bound claim circuits. Exact count equality must not be described as identity binding.
    error CloseDelegateCountOutOfRange();

    /// @notice One immutable compact-v2 adapter per independent statement circuit.
    IPinnedMleVerifierV2 public immutable override closeMleVerifier;
    IPinnedMleVerifierV2 public immutable withdrawalClaimMleVerifier;
    IPinnedMleVerifierV2 public immutable postCloseClaimMleVerifier;
    IPinnedMleVerifierV2 public immutable cancelCloseMleVerifier;

    constructor(
        IPinnedMleVerifierV2 closeMleVerifier_,
        IPinnedMleVerifierV2 withdrawalClaimMleVerifier_,
        IPinnedMleVerifierV2 postCloseClaimMleVerifier_,
        IPinnedMleVerifierV2 cancelCloseMleVerifier_
    ) {
        address closeAddress = address(closeMleVerifier_);
        address withdrawalClaimAddress = address(withdrawalClaimMleVerifier_);
        address postCloseClaimAddress = address(postCloseClaimMleVerifier_);
        address cancelCloseAddress = address(cancelCloseMleVerifier_);
        if (
            closeAddress == withdrawalClaimAddress || closeAddress == postCloseClaimAddress
                || closeAddress == cancelCloseAddress || withdrawalClaimAddress == postCloseClaimAddress
                || withdrawalClaimAddress == cancelCloseAddress || postCloseClaimAddress == cancelCloseAddress
        ) revert DuplicatePinnedMleVerifier();

        address[4] memory adapters = [closeAddress, withdrawalClaimAddress, postCloseClaimAddress, cancelCloseAddress];
        address[4] memory cores = [
            _requirePinnedVerifier(closeMleVerifier_),
            _requirePinnedVerifier(withdrawalClaimMleVerifier_),
            _requirePinnedVerifier(postCloseClaimMleVerifier_),
            _requirePinnedVerifier(cancelCloseMleVerifier_)
        ];
        // Enforce one adapter/core identity per statement domain in the contract itself, not only
        // in the off-chain release manifest. Same-pair adapter==core is retained for explicit test
        // stubs, but no address may cross from one statement slot into another slot's pair.
        for (uint256 i = 0; i < 4; ++i) {
            for (uint256 j = 0; j < 4; ++j) {
                if (i != j && (cores[i] == cores[j] || adapters[i] == cores[j])) {
                    revert DuplicatePinnedMleVerifier();
                }
            }
        }
        closeMleVerifier = closeMleVerifier_;
        withdrawalClaimMleVerifier = withdrawalClaimMleVerifier_;
        postCloseClaimMleVerifier = postCloseClaimMleVerifier_;
        cancelCloseMleVerifier = cancelCloseMleVerifier_;
    }

    function _requirePinnedVerifier(IPinnedMleVerifierV2 verifier) private view returns (address verifierCore) {
        address verifierAddress = address(verifier);
        if (verifierAddress.code.length == 0) revert InvalidPinnedMleVerifier(verifierAddress);

        uint256 verifierChainId;
        try verifier.allowedChainId() returns (uint256 chainId) {
            verifierChainId = chainId;
        } catch {
            revert InvalidPinnedMleVerifier(verifierAddress);
        }
        if (verifierChainId != block.chainid) {
            revert PinnedMleVerifierChainMismatch(verifierAddress, block.chainid, verifierChainId);
        }
        try verifier.core() returns (address coreAddress) {
            verifierCore = coreAddress;
        } catch {
            revert InvalidPinnedMleVerifier(verifierAddress);
        }
        if (verifierCore.code.length == 0) revert InvalidPinnedMleVerifier(verifierAddress);

        uint256 coreChainId;
        try IPinnedMleVerifierV2(verifierCore).allowedChainId() returns (uint256 chainId) {
            coreChainId = chainId;
        } catch {
            revert InvalidPinnedMleVerifier(verifierCore);
        }
        if (coreChainId != block.chainid) {
            revert PinnedMleVerifierChainMismatch(verifierCore, block.chainid, coreChainId);
        }
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
    ///        2. The dedicated pinned v2 adapter verifies the compact proof against the close
    ///           circuit's immutable VK/configuration, blocking cross-circuit replay.
    ///      The adapter is fixed in the constructor: there is no verification-disabled window.
    ///
    ///      B-2: limb 94 (`delegateCount`) is a decommitment of the cosigner-signed H1 (limbs
    ///      17..24): the close circuit `connect`s the recomputed H1 to that PI
    ///      (close_circuit.rs:609-620), so a prover cannot move it without a Poseidon collision or
    ///      the N-of-N Falcon signatures. Settlement activation also freezes the authenticated live
    ///      participant root/count and disables later joins. The Manager supplies that immutable
    ///      snapshot count in `fields.minDelegateCount` (legacy ABI name), and this verifier requires
    ///      EXACT equality before writing the value into the expected vector. Thus all 103 limbs
    ///      remain accounted for and neither a narrower nor wider post-activation boundary passes.
    function verifyCloseIntent(CloseProofFields calldata fields, bytes calldata compactProof)
        external
        view
        returns (bool)
    {
        uint256[] memory pi = closeMleVerifier.verifyCompactPublicInputs(compactProof);
        return _bindCloseIntentPublicInputs(fields, pi);
    }

    /// @notice Strictly bind an already-authenticated close PI vector to application fields.
    /// @dev SECURITY / AUTHORITY BOUNDARY: this function is deliberately stateless and confers no
    ///      authorization. It can be called by anyone and merely answers whether one 103-limb
    ///      vector matches `fields`. `ChannelSettlementManager` is the value-bearing caller: it
    ///      constructor-pins this contract's `closeMleVerifier`, calls that adapter itself, and only
    ///      then supplies the authenticated result here. Keeping proof verification mandatory in
    ///      the Manager removes one ~195 KiB ABI relay without weakening any limb binding.
    function bindCloseIntentPublicInputs(CloseProofFields calldata fields, uint256[] calldata publicInputs)
        external
        pure
        returns (bool)
    {
        return _bindCloseIntentPublicInputs(fields, publicInputs);
    }

    function _bindCloseIntentPublicInputs(CloseProofFields calldata fields, uint256[] memory pi)
        internal
        pure
        returns (bool)
    {
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
        // SECURITY (B-2, immutable snapshot): settlement activation freezes the authenticated live
        // participant root/count and durably disables later joins. The close must therefore open
        // the SAME delegate boundary. A smaller value excludes frozen tail slots; a larger value
        // names slots absent from the immutable identity snapshot. `minDelegateCount` is retained
        // only as a legacy ABI field name; this predicate is exact equality, not a lower bound.
        if (delegateCount != fields.minDelegateCount) revert CloseDelegateCountOutOfRange();
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
        return true;
    }

    /// @dev Bind the proof's public-input limbs to the expected close vector. `pi` MUST be exactly
    ///      `CLOSE_PI_LEN` (103) limbs; each limb MUST equal the expected limb (strict equality, no
    ///      masking) AND be a canonical u32 (`< 2**32`). Reverts on any violation — there is no
    ///      partial / masked match.
    function _bindCloseLimbsStrict(uint256[] memory pi, uint256[] memory expected) internal pure {
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

    /// @notice TEST-INTROSPECTION HELPER: public view passthrough exposing the EXPECTED 103-limb
    ///         close public-input vector for `fields`. Lets the manager-lifecycle tests build a
    ///         authenticated close public-input vector whose limbs equal exactly what
    ///         `verifyCloseIntent`'s `_bindCloseLimbsStrict` will require. It is a pure view of the
    ///         same `_expectedCloseLimbs` the binding uses (no security impact — it reveals nothing
    ///         a caller cannot already recompute from `fields`).
    /// @param delegateCount B-2: the limb-94 value to lay out. Verification takes this from the
    ///        proof after exact snapshot equality and capacity checks; this pure layout helper takes
    ///        it from the caller so tests can also construct vectors the predicate rejects.
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
    function tokenFundsDigest(uint32[10] memory tokenRegistry, uint8 tokenCount, uint256[10] memory amounts)
        public
        pure
        returns (bytes32)
    {
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
    /// @param delegateCount B-2: the already-validated limb-94 value. The binding path first
    ///        requires it to equal the Manager's immutable snapshot count and satisfy capacity,
    ///        then passes it explicitly here. Its proof-side authority is the N-of-N cosigner
    ///        signature over the H1 that the close circuit forces limb 94 to decommit.
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
        // B-2: proof-derived count after exact immutable-snapshot equality + capacity checks.
        limbs[c++] = delegateCount;
        // Multi-token (§N-6, TM-11): RECOMPUTED over the supplied settlement vectors, appended at
        // the very end. The strict bind then forces the proof's member-signed in-circuit TFD to
        // equal this recompute, proof-binding the (registry, count, amounts) the Manager stores.
        c = _putBytes32(limbs, c, tokenFundsDigest(fields.tokenRegistry, fields.tokenCount, fields.channelFundAmounts));
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

    /// @dev Recompute canonical `closeStateId` exactly as Rust and both close circuits do:
    ///      `keccak(IMCS, channelId, finalChannelStateDigest, closeFreezeNonce)`. The externally
    ///      visible `closeIntentDigest` name is retained, but coordinator-chosen metadata is
    ///      intentionally absent so it cannot mint a fresh replay/cancel/nullifier namespace.
    function _closeIntentDigest(CloseProofFields calldata fields) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                bytes4(CLOSE_STATE_ID_DOMAIN), fields.channelId, fields.finalChannelStateDigest, fields.closeFreezeNonce
            )
        );
    }

    // =======================================================================
    // Phase B-D (tasks/phase-b-claims-threat-model.md) — REAL on-chain verification of the
    // withdrawal-claim and post-close-claim BINDING circuits, each through its own pinned v2
    // adapter fixed atomically in this contract's constructor.
    //
    // SCOPE = Option D: these prove EVERYTHING EXCEPT the Regev decryption of the claimed
    // ciphertext. SECURITY (RESIDUAL, documented loudly): the `amount` limb is NOT bound to the
    // ciphertext plaintext — over-claim is bounded only by the manager's
    // `totalWithdrawn <= finalizedChannelFundAmount` cap + the authoritative `receivedChannelFunds`
    // ETH ceiling. The decryption binding is a deferred sub-phase.
    //
    // Each statement gets its OWN complete, independent VK/configuration inside an immutable
    // pinned adapter. There is no post-deployment initializer and no verification-disabled seam.
    // =======================================================================

    /// @dev Build the EXPECTED 29-limb cancel-close PI vector, in the EXACT order of the Rust
    ///      `CancelClosePublicInputs::to_u64_vec()` (pinned by the Rust↔Solidity golden vector
    ///      `cancel_close_public_inputs_match_solidity_shared_vector`). Layout:
    ///        [0]      channelId                  (u32 value)
    ///        [1..9]   closeIntentDigest          (8 BE u32)
    ///        [9..17]  memberSetCommitment        (8 BE u32) — REGISTERED set (manager-injected)
    ///        [17..19] closeFinalStateVersion     (hi, lo; Manager pending-close value)
    ///        [19..21] revivedStateVersion        (hi, lo)
    ///        [21..29] revivedChannelStateDigest  (8 BE u32)
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
        uint64 closeFinalStateVersion,
        uint64 revivedStateVersion,
        bytes32 revivedChannelStateDigest
    ) internal pure returns (uint256[] memory limbs) {
        limbs = new uint256[](CANCEL_CLOSE_PI_LEN);
        uint256 c = 0;
        limbs[c++] = uint256(uint32(channelId));
        c = _putBytes32(limbs, c, closeIntentDigest);
        c = _putBytes32(limbs, c, memberSetCommitment);
        c = _putU64(limbs, c, closeFinalStateVersion);
        c = _putU64(limbs, c, revivedStateVersion);
        c = _putBytes32(limbs, c, revivedChannelStateDigest);
        require(c == CANCEL_CLOSE_PI_LEN, "cancel limb count");
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
    function _bindLimbsStrict(uint256[] memory pi, uint256[] memory expected) internal pure {
        require(pi.length == expected.length, "claim pi len");
        for (uint256 i = 0; i < expected.length; i++) {
            uint256 limb = pi[i];
            require(limb < LIMB_BOUND, "claim limb range");
            require(limb == expected[i], "claim limb mismatch");
        }
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
    /// @dev SECURITY: the pinned adapter first verifies the canonical compact v2 proof against the
    ///      withdrawal-claim circuit's immutable VK/configuration and returns its authenticated
    ///      public inputs. `_bindLimbsStrict` then binds all 50 limbs exactly and canonically.
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
        bytes calldata compactProof
    ) external view returns (bool) {
        uint256[] memory publicInputs = withdrawalClaimMleVerifier.verifyCompactPublicInputs(compactProof);
        _bindLimbsStrict(
            publicInputs,
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
        return true;
    }

    /// @notice REAL on-chain verification of the CORRECTED cancelClose proof (Phase C1).
    /// @dev SECURITY: replaces the former forgeable `cancelPIHash`+`_matches` stub (the legacy
    ///      41-limb revived-tx design had no member binding — Finding D — and an unsound staleness
    ///      predicate — Finding B). Two mandatory checks:
    ///        1. `_bindLimbsStrict` binds ALL 29 raw Goldilocks limbs limb-by-limb (strict eq,
    ///           <2**32, no mask) to the expected vector. This binds channelId(0),
    ///           closeIntentDigest(1..8), memberSetCommitment(9..16),
    ///           closeFinalStateVersion(17..18), revivedStateVersion(19..20), and
    ///           revivedChannelStateDigest(21..28) — NONE are left free. The in-circuit
    ///           constraints prove `revivedStateVersion > closeFinalStateVersion` and the era
    ///           fence against the canonical close state whose legacy ABI key is
    ///           `closeIntentDigest`.
    ///        2. The dedicated pinned v2 adapter re-checks the proof against the cancel-close
    ///           circuit's immutable VK/configuration, blocking cross-circuit replay.
    ///      FINDING D FIX: `memberSetCommitment` is the channel's REGISTERED member-set commitment,
    ///      passed by `ChannelSettlementManager.cancelClose` from `registeredMemberSetCommitment()`
    ///      (NOT a caller request field). The strict bind forces the proof's in-circuit member-set
    ///      commitment to equal it, so the verified signing keys are the channel's registered
    ///      members — a third party cannot forge a cancel with their own keys.
    ///      The adapter is fixed in the constructor: there is no verification-disabled window.
    function verifyCancelClose(
        bytes4 channelId,
        bytes32 closeIntentDigest,
        bytes32 memberSetCommitment,
        uint64 closeFinalStateVersion,
        uint64 revivedStateVersion,
        bytes32 revivedChannelStateDigest,
        bytes calldata compactProof
    ) external view returns (bool) {
        uint256[] memory publicInputs = cancelCloseMleVerifier.verifyCompactPublicInputs(compactProof);
        _bindLimbsStrict(
            publicInputs,
            _expectedCancelCloseLimbs(
                channelId,
                closeIntentDigest,
                memberSetCommitment,
                closeFinalStateVersion,
                revivedStateVersion,
                revivedChannelStateDigest
            )
        );
        return true;
    }

    /// @notice TEST-INTROSPECTION HELPER: public view of the EXPECTED 29-limb cancel-close PI vector
    ///         (lets tests compare fixture public inputs with the strict bind). No
    ///         security impact (reveals nothing a caller cannot recompute).
    function expectedCancelCloseLimbs(
        bytes4 channelId,
        bytes32 closeIntentDigest,
        bytes32 memberSetCommitment,
        uint64 closeFinalStateVersion,
        uint64 revivedStateVersion,
        bytes32 revivedChannelStateDigest
    ) external pure returns (uint256[] memory) {
        return _expectedCancelCloseLimbs(
            channelId,
            closeIntentDigest,
            memberSetCommitment,
            closeFinalStateVersion,
            revivedStateVersion,
            revivedChannelStateDigest
        );
    }

    /// @notice REAL on-chain verification of the post-close-claim binding proof (Phase B-D +
    ///         Stage 3).
    /// @dev SECURITY: the dedicated pinned v2 adapter verifies the canonical compact proof against
    ///      the post-close-claim circuit's immutable VK/configuration, then `_bindLimbsStrict`
    ///      binds all 57 authenticated public-input limbs.
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
        bytes calldata compactProof
    ) external view returns (bool) {
        uint256[] memory publicInputs = postCloseClaimMleVerifier.verifyCompactPublicInputs(compactProof);
        _bindLimbsStrict(
            publicInputs,
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
        return true;
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
    // warns about. The canonical IMCS state-identity keccak lives on as `_closeIntentDigest`.

    /// @dev F4/D6 member-set commitment (pad-to-MAX): FIXED-length keccak over
    /// `[IMCM, memberCount, h_0..h_{MAX-1}]` — the domain word, the `memberCount` u32 limb, and
    /// ALL `MAX_CHANNEL_MEMBERS` (8) SPHINCS+ pubkey hashes in slot order, where padding slots
    /// (`>= memberCount`) contribute zero. Byte-for-byte mirror of Rust
    /// `close_member_set_commitment` (src/common/channel.rs): one big-endian u32 word per limb
    /// (264 bytes total = 4-byte domain + 4-byte memberCount + 8*32-byte hashes), so
    /// `abi.encodePacked(bytes4(domain), uint32(memberCount), h_0..h_7)` reproduces the preimage.
    ///
    /// SECURITY: this is the in-circuit FIXED form — the close circuit zeroes padding slots and
    /// `memberCount` fixes the active/padding boundary, so the commitment is injective on the
    /// active member set (no non-member-key substitution). The caller MUST pass the channel's
    /// registered hashes already zero-padded to MAX_CHANNEL_MEMBERS.
    function closeMemberSetCommitment(bytes32[MAX_CHANNEL_MEMBERS] memory memberSphincsPubkeyHashes, uint8 memberCount)
        public
        pure
        returns (bytes32)
    {
        bytes memory packed = abi.encodePacked(bytes4(CLOSE_MEMBER_SET_DOMAIN), uint32(memberCount));
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
    ///         vector (lets tests compare fixture public inputs with the strict bind).
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
