// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {BlobKZGVerifierExt} from "../src/BlobKZGVerifier.sol";
import {
    ChannelSettlementManager,
    IChannelSettlementVerifier,
    IChannelRegistry
} from "../src/ChannelSettlementManager.sol";
import {ChannelSettlementVerifier} from "../src/ChannelSettlementVerifier.sol";
import {CloseFundingMaterializer} from "../src/CloseFundingMaterializer.sol";
import {IPinnedMleVerifierV2} from "../src/IPinnedMleVerifierV2.sol";
import {PinnedMleVerifierV2} from "@mle/PinnedMleVerifierV2.sol";
import {FixtureLib} from "./FixtureLib.sol";
import {DeployConfig} from "./DeployConfig.sol";
import {RegRecordLib} from "./RegRecordLib.sol";

/// @title A-3 P5-B: deploy the close-lifecycle stack registered with the CLI channel's REAL members.
/// @notice Unlike `DeployClose` (which registers the fixture members from `close_lifecycle.json`),
///         this registers the channel with the members emitted by `channel_member export-reg-record`
///         (`cli_reg_record.json`) and binds the manager to the same members — so the close proof's
///         member-set commitment AND the registration block `withdraw` posts both match this single
///         on-chain registration. The MLE/WHIR VKs are channel/member-INDEPENDENT (they are the
///         circuits' verifier data), so they are taken from the existing `close_*` fixtures and the
///         CLI's freshly-proved (channel-7) close/withdraw proofs verify under them.
/// @dev All four settlement-circuit adapters are constructed and pinned before the settlement
///      verifier; a fresh rollup likewise receives its two adapters atomically. Env: none required;
///      reads contracts/test/data/{close_*_mle_config.json,close_asset_backing_mle_config.json,
///      cli_reg_record.json}; a fresh-rollup bootstrap additionally reads close_lifecycle.json for
///      its genesis root, and an `EXISTING_ROLLUP` attach reads the manifest-authenticated
///      close_asset_backing_{manifest,mle,public_inputs}.json bundle. Prints deployed addresses.
contract DeployCloseCli is Script {
    // SECURITY (challenge-period floor): the challenge window is the ONLY interval in which an
    // honest member can replace or cancel a stale close intent, and guarded finalization is
    // permissionless the moment it lapses. This script previously hardcoded 1 second — enough for
    // the anvil E2Es (`evm_increaseTime` then settle), and a permanent fund-mis-allocation hole on
    // any real chain. `DeployConfig.challengePeriodSecs()` keeps the 1-second value on chain id
    // 31337 and uses `ChannelSettlementManager.CHALLENGE_PERIOD_SECS` (1 day) everywhere else; the
    // manager's constructor rejects anything below the floor off-devnet regardless of what this
    // script passes. A REAL-NETWORK close therefore now takes a day to finalize, by design.
    uint256 internal constant SPECIAL_CLOSE_PENALTY = 0;
    uint256 internal constant INITIAL_BP_BOND = 0;

    /// @dev `virtual` ONLY so `test/DeployGuards.t.sol` can substitute the ONE input this script
    ///      takes that is not checked in — `cli_reg_record.json`, which `channel_member
    ///      export-reg-record` stages at run time. `foundry.toml`'s `fs_permissions` is read-only
    ///      (deliberately: the repo root holds gitignored secrets), so a test cannot write that file
    ///      and would otherwise have to skip — and a guard that cannot run is not a guard. The
    ///      override swaps file BYTES only; `run()` under test is this exact `run()`.
    function _read(string memory f) internal view virtual returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/", f));
    }

    /// @dev The ONLY two env inputs that select the attach branch (`EXISTING_ROLLUP`,
    ///      `EXPECTED_BROADCASTER`). `virtual` for the same reason as `_read`: `vm.setEnv` is
    ///      PROCESS-global and forge runs the test functions of one contract in parallel, so a
    ///      guard test that set these through the environment would flip every concurrently
    ///      running fresh-branch guard onto the attach branch for the duration of the run. The
    ///      harness substitutes VALUES only; `run()` under test is this exact `run()`.
    function _envOrAddress(string memory name, address defaultValue) internal view virtual returns (address) {
        return vm.envOr(name, defaultValue);
    }

    /// @dev Read and authenticate the exact CloseAssetBacking MLE artifact staged by the Rust
    ///      deployment driver from a `public_close_prover` bundle. This is deliberately a separate
    ///      file from `close_intent_mle.json`: the two adapters describe different circuits and
    ///      pinning the close adapter here would make every honest signer-independent
    ///      materialization fail closed.
    function _readBackingMle(address expectedRollup, uint32 expectedChannelId)
        internal
        view
        returns (string memory backingJson)
    {
        string memory manifest = _read("close_asset_backing_manifest.json");
        backingJson = _read("close_asset_backing_mle.json");
        string memory backingPublicInputs = _read("close_asset_backing_public_inputs.json");
        require(vm.parseJsonUint(manifest, ".schemaVersion") == 2, "unsupported public-close bundle schema");
        require(vm.parseJsonUint(manifest, ".chainId") == block.chainid, "backing bundle chain mismatch");
        require(vm.parseJsonAddress(manifest, ".rollup") == expectedRollup, "backing bundle rollup mismatch");
        require(vm.parseJsonUint(manifest, ".channelId") == expectedChannelId, "backing bundle channel mismatch");
        require(vm.parseJsonBool(manifest, ".selfVerified"), "backing bundle is not self-verified");
        require(!vm.parseJsonBool(manifest, ".keyMaterialConsumed"), "backing bundle consumed key material");
        require(
            keccak256(bytes(vm.parseJsonString(manifest, ".backingMleFile"))) == keccak256(bytes("backing_mle.json")),
            "backing bundle names an unexpected MLE file"
        );
        require(
            vm.parseJsonUint(manifest, ".backingMleBytes") == bytes(backingJson).length, "backing MLE length mismatch"
        );
        require(
            vm.parseJsonBytes32(manifest, ".backingMleSha256") == sha256(bytes(backingJson)),
            "backing MLE SHA-256 mismatch"
        );
        require(
            vm.parseJsonUint(manifest, ".backingPublicInputCount") == 26,
            "backing circuit must expose exactly 26 public inputs"
        );
        require(
            keccak256(bytes(vm.parseJsonString(manifest, ".backingPublicInputsFile")))
                == keccak256(bytes("backing_public_inputs.json")),
            "backing bundle names an unexpected public-input file"
        );
        require(
            vm.parseJsonBytes32(manifest, ".backingPublicInputsSha256") == sha256(bytes(backingPublicInputs)),
            "backing public-input SHA-256 mismatch"
        );
    }

    /// @dev The constructor-pinned configuration of the CloseAssetBacking circuit
    ///      (`close_asset_backing_mle_config.json`, co-generated with the backing proof). The
    ///      materializer's adapter is constructed from this proof-free artifact. When the staged,
    ///      manifest-authenticated backing proof is present (attach branch) the configuration is
    ///      additionally bound to it: both carry the same `pinnedVerifier.verificationConfigDigest`,
    ///      so a config of any other circuit (or a stale regeneration) fails before broadcast.
    function _readBackingMleConfig(string memory authenticatedBackingJson)
        internal
        view
        returns (string memory backingConfigJson)
    {
        backingConfigJson = _read("close_asset_backing_mle_config.json");
        require(
            keccak256(bytes(vm.parseJsonString(backingConfigJson, ".schema")))
                == keccak256("plonky2-mle-v3-solidity-config"),
            "backing config is not a v2 config-only artifact"
        );
        if (bytes(authenticatedBackingJson).length != 0) {
            require(
                vm.parseJsonBytes32(backingConfigJson, ".pinnedVerifier.verificationConfigDigest")
                    == vm.parseJsonBytes32(authenticatedBackingJson, ".pinnedVerifier.verificationConfigDigest"),
                "backing config does not match the authenticated backing proof"
            );
        }
    }

    /// @return rollup  the deployed IntmaxRollup
    /// @return sv      the deployed ChannelSettlementVerifier (the four live settlement VKs keyed:
    ///                 close, withdrawalClaim, postCloseClaim and cancelClose; the retired direct
    ///                 member-set-update verifier surface no longer exists)
    /// @return manager the deployed ChannelSettlementManager, registered on `rollup`
    /// @dev The return values exist so `test/DeployGuards.t.sol` can assert on what this script
    ///      actually deployed. `forge script --sig run` is unaffected (return types are not part of
    ///      the selector, and the console2 lines the Rust drivers parse are unchanged).
    function run()
        external
        returns (IntmaxRollup rollup, ChannelSettlementVerifier sv, ChannelSettlementManager manager)
    {
        string memory vkJson = _read("close_lifecycle_validity_mle_config.json");
        string memory wJson = _read("close_withdrawal_mle_config.json");
        string memory cJson = _read("close_intent_mle_config.json");
        string memory wcJson = _read("withdrawal_claim_mle_config.json");
        string memory pcJson = _read("post_close_claim_mle_config.json");
        string memory ccJson = _read("cancel_close_mle_config.json");
        // Staged into test/data/ by the driver. Parsed through the SHARED reader, which is the one
        // place that decides which delegate count reaches `registerChannel` (a constant zero) and
        // which reaches the manager (the record's live `active_delegate_count`).
        RegRecordLib.Record memory r = RegRecordLib.parse(_read("cli_reg_record.json"));
        address existingRollup = _envOrAddress("EXISTING_ROLLUP", address(0));
        address expectedBroadcaster = _envOrAddress("EXPECTED_BROADCASTER", address(0));
        // A public deployment must attach to the already-live rollup, because the authenticated
        // backing bundle is scoped to that exact escrow contract. The fresh branch remains a
        // local-dev bootstrap only; it cannot silently deploy a public materializer whose backing
        // adapter was not bound to an authenticated bundle.
        require(existingRollup != address(0) || block.chainid == 31337, "public settlement requires existing rollup");
        string memory backingJson;
        if (existingRollup != address(0)) {
            require(r.participantRootDeclared, "production reg record must declare authenticated participant_root");
            require(expectedBroadcaster != address(0), "EXPECTED_BROADCASTER required for existing-rollup attach");
            bool broadcasterIsParticipant = false;
            for (uint256 i = 0; i < r.recipients.length; i++) {
                if (r.recipients[i] == expectedBroadcaster) {
                    broadcasterIsParticipant = true;
                    break;
                }
            }
            require(broadcasterIsParticipant, "settlement broadcaster is not an active signed-state recipient");
            // Read and hash all runtime-staged input before `startBroadcast`, so a missing, mixed,
            // or context-substituted bundle cannot leave a partially deployed production stack.
            backingJson = _readBackingMle(existingRollup, r.channelId);
        }
        // The CloseAssetBacking adapter configuration is circuit-level (channel-independent) like
        // the six settlement/rollup configs above, so BOTH branches pin it; the attach branch also
        // binds it to the authenticated bundle. Read before `startBroadcast` for the same reason.
        string memory backingConfigJson = _readBackingMleConfig(backingJson);
        // SECURITY / OPERABILITY: attaching the settlement stack to an already-funded rollup
        // must not depend on a witness-derived lifecycle proof fixture.  Only a fresh rollup needs
        // the fixture's genesis root; the existing-rollup branch authenticates its deployed state
        // and V2 adapters below.  This keeps verifier deployment config-first and breaks the
        // verifier-address -> proof-fixture -> deployment circularity for the production path.
        bytes32 genesis;
        if (existingRollup == address(0)) {
            string memory lcJson = _read("close_lifecycle.json");
            genesis = vm.parseJsonBytes32(lcJson, ".genesis_state_root");
        }
        // SECURITY (#6): a fresh rollup needs a fraud treasury.  An attach does not create or
        // mutate this immutable and therefore must not demand an unrelated value.
        address fraudTreasury = vm.envOr("FRAUD_TREASURY", address(0));
        if (existingRollup == address(0) && fraudTreasury == address(0)) {
            require(block.chainid == 31337, "FRAUD_TREASURY must be set for non-local deploys");
            fraudTreasury = msg.sender;
        }

        vm.startBroadcast();

        // 1. Attach to the rollup that already escrows this channel's funds when
        // `EXISTING_ROLLUP` is supplied.  The fresh branch is retained for isolated/dev bootstrap,
        // but the production Rust driver always supplies the backing rollup.
        if (existingRollup == address(0)) {
            (, PinnedMleVerifierV2 validityVerifier) = FixtureLib.deployPinnedMleV2(vkJson);
            (, PinnedMleVerifierV2 withdrawalVerifier) = FixtureLib.deployPinnedMleV2(wJson);
            rollup = new IntmaxRollup(
                fraudTreasury,
                IPinnedMleVerifierV2(address(validityVerifier)),
                IPinnedMleVerifierV2(address(withdrawalVerifier)),
                genesis
            );
            // Pin the KZG blob-binding satellite (EIP-170 relief; fraudProof binding is fail-closed until set).
            rollup.setKzgVerifier(new BlobKZGVerifierExt());
            // Authorize the block producer used by the CLI withdraw flow (the selected Foundry signer).
            rollup.setBlockProducer(vm.envOr("BLOCK_PRODUCER", msg.sender), true);
        } else {
            require(existingRollup.code.length != 0, "EXISTING_ROLLUP has no code");
            rollup = IntmaxRollup(payable(existingRollup));
            require(rollup.deployer() == expectedBroadcaster, "broadcaster is not existing rollup deployer");
            require(rollup.deploymentChainId() == block.chainid, "existing rollup deployment chain mismatch");
            IPinnedMleVerifierV2 validityVerifier = rollup.validityMleVerifier();
            IPinnedMleVerifierV2 withdrawalVerifier = rollup.withdrawalMleVerifier();
            require(
                address(validityVerifier) != address(withdrawalVerifier), "existing rollup reuses one circuit adapter"
            );
            require(
                address(validityVerifier).code.length != 0 && address(withdrawalVerifier).code.length != 0,
                "existing rollup V2 adapter unavailable"
            );
            require(
                validityVerifier.allowedChainId() == block.chainid
                    && withdrawalVerifier.allowedChainId() == block.chainid,
                "existing rollup V2 adapter chain mismatch"
            );
            require(
                validityVerifier.core().code.length != 0 && withdrawalVerifier.core().code.length != 0,
                "existing rollup V2 core unavailable"
            );
            require(address(rollup.kzgVerifier()) != address(0), "existing rollup KZG verifier is not set");
        }
        // 2. The REAL CloseAssetBacking adapter, constructor-pinned into the materializer. It comes
        // from the separately named backing configuration, never from the close-intent fixture.
        // There is no post-deploy VK latch any more: an omitted or substituted configuration cannot
        // yield a materializer at all, so the deployment can never be announced with a wrong or
        // missing backing verifier.
        (, PinnedMleVerifierV2 backingVerifier) = FixtureLib.deployPinnedMleV2(backingConfigJson);
        CloseFundingMaterializer materializer =
            new CloseFundingMaterializer(rollup, IPinnedMleVerifierV2(address(backingVerifier)));

        // 3. Deploy all four circuit-specific adapters before the parent verifier.  Distinct
        //    constructor slots make cross-statement replay and partial initialization impossible.
        (, PinnedMleVerifierV2 closeVerifier) = FixtureLib.deployPinnedMleV2(cJson);
        (, PinnedMleVerifierV2 withdrawalClaimVerifier) = FixtureLib.deployPinnedMleV2(wcJson);
        (, PinnedMleVerifierV2 postCloseClaimVerifier) = FixtureLib.deployPinnedMleV2(pcJson);
        (, PinnedMleVerifierV2 cancelCloseVerifier) = FixtureLib.deployPinnedMleV2(ccJson);
        sv = new ChannelSettlementVerifier(
            IPinnedMleVerifierV2(address(closeVerifier)),
            IPinnedMleVerifierV2(address(withdrawalClaimVerifier)),
            IPinnedMleVerifierV2(address(postCloseClaimVerifier)),
            IPinnedMleVerifierV2(address(cancelCloseVerifier))
        );

        // 4. registerChannel with the CLI COSIGNER set — the L1 registration record is
        //    cosigners-only (Option B) and its `delegateCount` limb is a CONSTANT zero.
        //
        //    SECURITY: `channel_member`'s `build_reg_record` already emits a cosigner-only record
        //    (`reg_delegate_count = 0`, arrays of exactly `member_count`), so this changes nothing a
        //    real deployment does today. It is wired through `RegRecordLib` so that the value fed
        //    to `registerChannel` is no longer READ FROM THE RECORD AT ALL: the shape of the defect
        //    fixed in `DeployWalletSettlement.s.sol` — one JSON field feeding both the registration
        //    and the manager, so a producer that learns the live delegate count silently emits a
        //    registration the validity `channel_reg_step` circuit refuses to fold — cannot recur
        //    here either. `RegRecordLib.parse` additionally REQUIRES `reg_delegate_count == 0`, so
        //    a producer change fails loudly at deploy time instead of being quietly ignored.
        rollup.registerChannel(
            r.channelId,
            r.bpSlot,
            RegRecordLib.REGISTRATION_DELEGATE_COUNT,
            RegRecordLib.regPkGs(r),
            RegRecordLib.regPkBs(r),
            RegRecordLib.regRegevDigests(r),
            RegRecordLib.regRecipients(r)
        );

        // 5. Manager bound to the SAME active snapshot.  Recipients are copied EXACTLY from the
        // cosigner-signed BalanceState leaves; there is no broadcaster override.  Only cosigners
        // become mappings/SSTOREs.  The full member+delegate identity is one immutable Merkle root,
        // so 1024 participants remain deployable within ordinary block gas limits.
        ChannelSettlementManager.MemberBinding[] memory mBind =
            new ChannelSettlementManager.MemberBinding[](r.memberCount);
        for (uint256 i = 0; i < r.memberCount; i++) {
            mBind[i] = ChannelSettlementManager.MemberBinding({pkG: r.pkGs[i], recipient: r.recipients[i]});
        }
        // B-2 (doc/tasks/b2-delegate-close-threat-model.md): `activeDelegateCount` is a FLOOR for
        // the close/partial-withdrawal bind, not an exact expected count. It is the record's
        // `active_delegate_count` — DELIBERATELY a different field from the zero registered in
        // step 4, because the two answer different questions ("what did L1 register?" vs "how many
        // delegates must a close at least account for?"). Reading the registration's zero here
        // would silently retire the fence.
        //
        // Under Option B this is 0 for the CLI record today (`build_reg_record` has no live channel
        // state to read a delegate count from), so the floor is currently vacuous while the live
        // channel may hold delegates — the pre-existing, reviewed behaviour of this path, unchanged
        // here. Raising it would additionally require delegate pk_g/recipient bindings this record
        // does not carry (the constructor enforces `dBind.length == activeDelegateCount`).
        // SCOPE (review finding 6): CARDINALITY only. L1 binds no delegate to a balance-slot index,
        // so this cannot guarantee that any NAMED delegate registered here is present in the closed
        // state — only that the active region was not shrunk below this count.
        manager = new ChannelSettlementManager(
            bytes4(r.channelId),
            r.bpSlot,
            r.pkGs[r.bpSlot],
            r.activeDelegateCount,
            r.participantRoot,
            DeployConfig.challengePeriodSecs(),
            SPECIAL_CLOSE_PENALTY,
            INITIAL_BP_BOND,
            IChannelSettlementVerifier(address(sv)),
            IChannelRegistry(address(rollup)),
            address(materializer),
            mBind
        );

        // 6. Register the manager just deployed as an authorized partial-withdrawal authorizer.
        //
        // SECURITY / LIVENESS (same defect class as the withdrawal VK and audit622 A-M4 — a
        // fail-closed check that is soundness-safe while making an HONEST path impossible):
        // `ChannelSettlementManager.finalizePartialWithdrawal()` ends by calling
        // `IntmaxRollup.authorizePartialWithdrawal`, which opens with
        // `if (!isRegisteredSettlementManager[msg.sender]) revert NotRegisteredSettlementManager();`.
        // Until 2026-08-13 the ONLY callers of `registerSettlementManager` were the two
        // `chainid == 31337`-gated mock scripts, so on every REAL deployment made with this script
        // `pw-finalize` (`src/bin/channel_member.rs`, driven by `api/routes/partial-withdrawal.js`)
        // reverted — AFTER the user had already submitted the intent and waited out the full
        // challenge period. No fail-closed check is weakened here: the revert stays; we grant the
        // right it was correctly demanding.
        //
        // WHY THIS IS SAFE — registering the manager THIS script itself constructs, and no other
        // address, is exactly the intended use of the deployer-only, additive `registerSettlementManager`:
        //   * The right granted is narrow. `authorizePartialWithdrawal` only sets a boolean in
        //     `partialWithdrawalAuthorized[authDigest]`. It moves no funds and names no amount or
        //     recipient — `claimAuthorizedWithdrawal`, the proof-free payout door that once consumed
        //     that flag directly, was REMOVED (see the tombstone above `postBlock` in
        //     `IntmaxRollup.sol`, doc/tasks/pw-auth-threat-model.md). The flag is now only ever a
        //     SECOND factor inside `withdrawNative`/`withdrawERC20`, where the economics come from
        //     the verified withdrawal proof, so it can veto a payout but never supply one.
        //   * The manager cannot mint an authorization on demand: `finalizePartialWithdrawal` is
        //     reachable only after `submitPartialWithdrawalIntent` verified an N-of-N close proof
        //     against `sv`'s close VK and the challenge window elapsed with no `cancelPartialWithdrawal`.
        //   * The address is not attacker-influenced: `manager` is the return of the `new` on the
        //     line above, in the same broadcast, bound by its constructor to THIS `rollup` as its
        //     registry and to this channel's on-chain member-set commitment (Finding E).
        //
        // ORDERING: this must come AFTER the `new ChannelSettlementManager` above (the address must
        // exist) and BEFORE `stopBroadcast`. It is deliberately in the TRAILING group of broadcast
        // operations — everything after the manager's CREATE is a plain call that adds no CREATE,
        // so it cannot move the manager's own address; the close/withdrawal fixtures bake that
        // address as the payout recipient inside the proof.
        rollup.registerSettlementManager(address(manager));

        // 7. Direct member-set updates are retired. The active verifier exposes no MSU key or
        // verification entry point, and the Manager keeps only an explicit compatibility
        // tombstone. The replacement is a unanimous close followed by a separately registered
        // channel and proof-bound asset/commitment migration.

        vm.stopBroadcast();

        // Read the registration back rather than trusting the call above ran, mirroring
        // `Deploy.s.sol`'s withdrawal-VK read-back: a deploy that reaches the console2 lines below
        // has a working partial-withdrawal finalize, and one that does not aborts loudly instead of
        // printing an address an operator would go on to fund.
        require(
            rollup.isRegisteredSettlementManager(address(manager)),
            "settlement manager not registered: partial withdrawal cannot finalize"
        );
        // The materializer's backing adapter is immutable and constructor-validated; read it back
        // anyway so a deploy that reaches the console2 lines below provably carries a chain-pinned
        // CloseAssetBacking verifier distinct from the close-intent adapter.
        IPinnedMleVerifierV2 pinnedBacking = materializer.backingMleVerifier();
        require(address(pinnedBacking) != address(0), "close-asset backing adapter was not pinned");
        require(address(pinnedBacking).code.length != 0, "close-asset backing adapter has no code");
        require(pinnedBacking.allowedChainId() == block.chainid, "close-asset backing adapter chain mismatch");
        require(
            address(pinnedBacking) != address(sv.closeMleVerifier()),
            "close-asset backing adapter must not be the close-intent adapter"
        );

        console2.log("=== close-lifecycle CLI deploy ===");
        console2.log("IntmaxRollup:", address(rollup));
        console2.log("SettlementVerifier:", address(sv));
        console2.log("CloseFundingMaterializer:", address(materializer));
        console2.log("CLOSE_MANAGER_ADDRESS:", address(manager));
    }
}
