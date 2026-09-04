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
import {MleVerifier} from "@mle/MleVerifier.sol";
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
/// @dev Run with the broadcasting EOA = deployer (so `initializeWithdrawalVk` / `initializeCloseVk`
///      pass their deployer-only guards). Env: none required; reads contracts/test/data/{close_*,
///      cli_reg_record.json}. Prints the deployed addresses for the driver.
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
    ///      file from `close_intent_mle.json`: the two VKs describe different circuits and using the
    ///      close VK here would make every honest signer-independent materialization fail closed.
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
        string memory vkJson = _read("close_lifecycle_validity_mle.json");
        string memory lcJson = _read("close_lifecycle.json");
        string memory wJson = _read("close_withdrawal_mle.json");
        string memory cJson = _read("close_intent_mle.json");
        // Staged into test/data/ by the driver. Parsed through the SHARED reader, which is the one
        // place that decides which delegate count reaches `registerChannel` (a constant zero) and
        // which reaches the manager (the record's live `active_delegate_count`).
        RegRecordLib.Record memory r = RegRecordLib.parse(_read("cli_reg_record.json"));
        address existingRollup = _envOrAddress("EXISTING_ROLLUP", address(0));
        address expectedBroadcaster = _envOrAddress("EXPECTED_BROADCASTER", address(0));
        // A public deployment must attach to the already-live rollup, because the authenticated
        // backing bundle is scoped to that exact escrow contract. The fresh branch remains a
        // local-dev bootstrap only; it cannot silently deploy a public materializer with no VK.
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
        bytes32 genesis = vm.parseJsonBytes32(lcJson, ".genesis_state_root");
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
        MleVerifier verifier = new MleVerifier(FixtureLib.mleVerifierChainId());
        if (existingRollup == address(0)) {
            IntmaxRollup.MleVk memory vvk = FixtureLib.buildMleVk(vkJson, verifier);
            FixtureLib.DeployData memory vdd = FixtureLib.parseDeployData(vkJson);
            rollup = new IntmaxRollup(
                fraudTreasury,
                vvk,
                vdd.whirParams,
                vdd.protocolId,
                vdd.sessionId,
                vdd.kIs,
                vdd.subgroupGenPowers,
                verifier,
                genesis,
                false
            );
            // Pin the KZG blob-binding satellite (EIP-170 relief; fraudProof binding is fail-closed until set).
            rollup.setKzgVerifier(new BlobKZGVerifierExt());
            // Authorize the block producer used by the CLI withdraw flow (the selected Foundry signer).
            rollup.setBlockProducer(vm.envOr("BLOCK_PRODUCER", msg.sender), true);

            // Withdrawal VK (deployer == EOA == broadcaster).
            FixtureLib.DeployData memory wdd = FixtureLib.parseDeployData(wJson);
            IntmaxRollup.MleVk memory wvk = FixtureLib.buildMleVk(wJson, verifier);
            rollup.initializeWithdrawalVk(
                wvk, wdd.whirParams, wdd.protocolId, wdd.sessionId, wdd.kIs, wdd.subgroupGenPowers
            );
        } else {
            require(existingRollup.code.length != 0, "EXISTING_ROLLUP has no code");
            rollup = IntmaxRollup(payable(existingRollup));
            require(rollup.deployer() == expectedBroadcaster, "broadcaster is not existing rollup deployer");
            require(!rollup.allowMleDisabled(), "existing rollup has test-only validity bypass enabled");
            require(rollup.withdrawalVkInitialized(), "existing rollup withdrawal VK is not initialized");
            require(address(rollup.kzgVerifier()) != address(0), "existing rollup KZG verifier is not set");
        }
        CloseFundingMaterializer materializer = new CloseFundingMaterializer(rollup);

        // 2. The REAL CloseAssetBacking VK. It comes from the separately named backing artifact,
        // never from the close-intent fixture. The set-once materializer latch makes an omitted or
        // substituted key fail closed before this deployment can be announced as usable.
        if (existingRollup != address(0)) {
            FixtureLib.DeployData memory bdd = FixtureLib.parseDeployData(backingJson);
            MleVerifier.MleProof memory bproof = FixtureLib.parseProof(backingJson);
            bytes32 backingGatesDigest = verifier.computeGatesDigest(
                bproof.gates,
                bproof.witnessIndividualEvalsAtRGateV2.length,
                bproof.numSelectors,
                bproof.numGateConstraints,
                bproof.quotientDegreeFactor
            );
            CloseFundingMaterializer.MleVk memory bvk = CloseFundingMaterializer.MleVk({
                degreeBits: bdd.degreeBits,
                preprocessedRoot: bdd.preCommitRoot,
                numConstants: bdd.numConstants,
                numRoutedWires: bdd.numRoutedWires,
                gatesDigest: backingGatesDigest
            });
            materializer.initializeBackingVk(
                verifier, bvk, bdd.whirParams, bdd.protocolId, bdd.sessionId, bdd.kIs, bdd.subgroupGenPowers
            );
        }

        // 3. Settlement verifier + the REAL close VK (the close circuit's MLE/WHIR verifier data).
        sv = new ChannelSettlementVerifier();
        {
            FixtureLib.DeployData memory cdd = FixtureLib.parseDeployData(cJson);
            MleVerifier.MleProof memory cproof = FixtureLib.parseProof(cJson);
            bytes32 gatesDigest = verifier.computeGatesDigest(
                cproof.gates,
                cproof.witnessIndividualEvalsAtRGateV2.length,
                cproof.numSelectors,
                cproof.numGateConstraints,
                cproof.quotientDegreeFactor
            );
            ChannelSettlementVerifier.CloseVk memory cvk = ChannelSettlementVerifier.CloseVk({
                degreeBits: cdd.degreeBits,
                preprocessedRoot: cdd.preCommitRoot,
                numConstants: cdd.numConstants,
                numRoutedWires: cdd.numRoutedWires,
                gatesDigest: gatesDigest
            });
            sv.initializeCloseVk(
                verifier, cvk, cdd.whirParams, cdd.protocolId, cdd.sessionId, cdd.kIs, cdd.subgroupGenPowers
            );
        }

        // 3b. Withdrawal-claim VK (the claim circuit's MLE/WHIR verifier data — channel-independent,
        //     taken from the checked-in claim fixture; the CLI's fresh per-member claim proof verifies
        //     under it). Required for `claim` → `submitWithdrawalClaim` → `verifyWithdrawalClaim`.
        {
            string memory wcJson = _read("withdrawal_claim_mle.json");
            FixtureLib.DeployData memory wcdd = FixtureLib.parseDeployData(wcJson);
            MleVerifier.MleProof memory wcproof = FixtureLib.parseProof(wcJson);
            bytes32 wcGatesDigest = verifier.computeGatesDigest(
                wcproof.gates,
                wcproof.witnessIndividualEvalsAtRGateV2.length,
                wcproof.numSelectors,
                wcproof.numGateConstraints,
                wcproof.quotientDegreeFactor
            );
            ChannelSettlementVerifier.StatementVk memory wcvk = ChannelSettlementVerifier.StatementVk({
                degreeBits: wcdd.degreeBits,
                preprocessedRoot: wcdd.preCommitRoot,
                numConstants: wcdd.numConstants,
                numRoutedWires: wcdd.numRoutedWires,
                gatesDigest: wcGatesDigest
            });
            sv.initializeWithdrawalClaimVk(
                verifier, wcvk, wcdd.whirParams, wcdd.protocolId, wcdd.sessionId, wcdd.kIs, wcdd.subgroupGenPowers
            );
        }

        // 3b. Post-close-claim VK. SECURITY/LIVENESS (audit622 A-M4, reported 2026-06-22, open until
        //     now; same class as the gate-8 defect — a fail-closed check that protects soundness
        //     while making an HONEST path impossible): without this,
        //     `ChannelSettlementVerifier.sol:1111` reverts `PostCloseClaimVkNotSet()` on every call,
        //     so the live `post-close-claim` CLI command (`channel_member.rs:2152-2184`) can never
        //     succeed on a real deployment. No fail-closed check is weakened here — the revert stays;
        //     we supply the VK it was correctly demanding.
        {
            string memory pcJson = _read("post_close_claim_mle.json");
            FixtureLib.DeployData memory pcdd = FixtureLib.parseDeployData(pcJson);
            MleVerifier.MleProof memory pcproof = FixtureLib.parseProof(pcJson);
            bytes32 pcGatesDigest = verifier.computeGatesDigest(
                pcproof.gates,
                pcproof.witnessIndividualEvalsAtRGateV2.length,
                pcproof.numSelectors,
                pcproof.numGateConstraints,
                pcproof.quotientDegreeFactor
            );
            ChannelSettlementVerifier.StatementVk memory pcvk = ChannelSettlementVerifier.StatementVk({
                degreeBits: pcdd.degreeBits,
                preprocessedRoot: pcdd.preCommitRoot,
                numConstants: pcdd.numConstants,
                numRoutedWires: pcdd.numRoutedWires,
                gatesDigest: pcGatesDigest
            });
            sv.initializePostCloseClaimVk(
                verifier, pcvk, pcdd.whirParams, pcdd.protocolId, pcdd.sessionId, pcdd.kIs, pcdd.subgroupGenPowers
            );
        }

        // 3c. Cancel-close VK. SECURITY/LIVENESS (audit622 A-M4): without this,
        //     `ChannelSettlementVerifier.sol:1050` reverts `CancelCloseVkNotSet()`, disabling
        //     `cancel-close` (`channel_member.rs:1988-2025`) — the ONLY on-chain remedy against a
        //     stale/unwanted close. Previously initialized only by the two anvil-gated
        //     (`chainid == 31337`) scripts, so every REAL deployment shipped without it.
        {
            string memory ccJson = _read("cancel_close_mle.json");
            FixtureLib.DeployData memory ccdd = FixtureLib.parseDeployData(ccJson);
            MleVerifier.MleProof memory ccproof = FixtureLib.parseProof(ccJson);
            bytes32 ccGatesDigest = verifier.computeGatesDigest(
                ccproof.gates,
                ccproof.witnessIndividualEvalsAtRGateV2.length,
                ccproof.numSelectors,
                ccproof.numGateConstraints,
                ccproof.quotientDegreeFactor
            );
            ChannelSettlementVerifier.StatementVk memory ccvk = ChannelSettlementVerifier.StatementVk({
                degreeBits: ccdd.degreeBits,
                preprocessedRoot: ccdd.preCommitRoot,
                numConstants: ccdd.numConstants,
                numRoutedWires: ccdd.numRoutedWires,
                gatesDigest: ccGatesDigest
            });
            sv.initializeCancelCloseVk(
                verifier, ccvk, ccdd.whirParams, ccdd.protocolId, ccdd.sessionId, ccdd.kIs, ccdd.subgroupGenPowers
            );
        }

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
        if (existingRollup != address(0)) {
            require(materializer.backingVkInitialized(), "close-asset backing VK was not initialized");
            require(
                address(materializer.backingMleVerifier()) == address(verifier),
                "close-asset backing VK is bound to the wrong MLE verifier"
            );
        }

        console2.log("=== close-lifecycle CLI deploy ===");
        console2.log("IntmaxRollup:", address(rollup));
        console2.log("SettlementVerifier:", address(sv));
        console2.log("CloseFundingMaterializer:", address(materializer));
        console2.log("CLOSE_MANAGER_ADDRESS:", address(manager));
    }
}
