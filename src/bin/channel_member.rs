//! CLI companion for the browser wallet: runs the CO-SIGNING members so a full in-channel send can
//! complete end-to-end. Regev channel model, E-1 STARK at Production level.
//!
//! DELEGATE DEMO LAYOUT: slots 0,1,2 = three CLI-controlled CO-SIGNING MEMBERS; slot 3 = the
//! browser, a send-only DELEGATE (it has a balance + sends with its own BabyBear A11 hash-sig, but
//! does NOT co-sign channel state — the N-of-N is the three members). So `init` produces a
//! FULLY-SIGNED genesis (the 3 members sign; the delegate does not), and the browser imports it
//! directly.
//!
//! State (`cli_state.json` in the cwd) stores only reproducible seeds + the public snapshot; the
//! controlled members' keys and their genesis balance witnesses are regenerated deterministically
//! each run (so nothing unserializable is persisted). Each CLI member sends at most once from its
//! fresh genesis balance, so no post-send witness ever needs reconstructing.
//!
//! Commands:
//!   init <browser_delegate_contribution.json> <out_signed_snapshot.json>
//!   add-genesis-sig <browser_member_sig.json> <out_snapshot.json>   (legacy member-mode; unused by
//! the delegate demo)   send <from_slot> <to_slot> <amount> <out_payload.json>
//!   cosign <payload_or_state.json> <out_state.json>
//!   finalize <fully_signed_state.json>
//!   balance

use std::{
    collections::{BTreeMap, HashSet},
    fs::{self, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
    process::{Command, Stdio, exit},
};

#[cfg(unix)]
use std::os::{
    fd::AsRawFd as _,
    unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
};

#[cfg(feature = "deprecated-msu")]
#[allow(deprecated)]
use intmax3_zkp::wallet_core::{
    apply_member_set_update_to_state, cosign_member_set_update, propose_add_cosigner,
    propose_rotate_key, verify_member_set_update,
};
use intmax3_zkp::{
    block_producer::ProductionDepositRequest,
    circuits::{
        balance::{
            balance_pis::{BALANCE_PUBLIC_INPUTS_LEN, BalancePublicInputs},
            balance_processor::BalanceProcessor,
            common::recipient::calculate_recipient_from_user_id,
            spend_circuit::SpendCircuit,
        },
        channel::{
            cancel_close_pis::{CANCEL_CLOSE_PUBLIC_INPUTS_LEN, CancelClosePublicInputs},
            close_pis::{CHANNEL_CLOSE_PUBLIC_INPUTS_LEN, ChannelClosePublicInputs},
            post_close_claim_pis::{
                POST_CLOSE_CLAIM_PUBLIC_INPUTS_LEN, PostCloseClaimPublicInputs,
            },
            state_update_verifier::verify_regev_pk_root,
            withdrawal_claim_pis::{
                WITHDRAWAL_CLAIM_PUBLIC_INPUTS_LEN, WithdrawalClaimPublicInputs,
            },
        },
        witness::{
            balance_witness_generator::{BalanceWitnessGenerator, ReceiveDepositData},
            block_witness_generator::{
                BlockWitnessGenerator, BlockWitnessGeneratorHandle, ChannelMemberKeys,
                TEST_ACTIVE_MEMBERS, test_recipient_for,
            },
        },
    },
    close_funding::{CloseFundingProposal, verify_close_funding_proposal},
    common::{
        balance_state::{BalanceState, settled_tx_chain_push, tx_leaf_hash},
        channel::{
            ChannelRecord, ChannelState, CloseIntent, CloseWithdrawal, InterChannelTx,
            MemberSignature, burn_descriptor, close_member_set_commitment, token_funds_digest,
        },
        channel_id::ChannelId,
        deposit::Deposit,
        private_state::FullPrivateState,
        salt::Salt,
        u63::U63,
        withdrawal::Withdrawal,
    },
    constants::{MAX_CHANNEL_MEMBERS, MAX_SIG_CLUSTER, TOKEN_UNIT},
    ethereum_types::{
        address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait as _, u256::U256,
    },
    proof_da::{
        DecodedBlobTransaction, ValidatedBlobSidecars, submitted_id_from_receipt,
        validate_decoded_blob_transaction,
    },
    public_close_prover::{
        MAX_BALANCE_VERIFIER_DATA_BYTES, MAX_PUBLIC_BACKING_ENVELOPE_BYTES,
        PublicCloseExpectations, parse_public_close_backing_envelope, verify_public_backing,
    },
    regev::{RegevCiphertext, RegevPk, RegevSecurityLevel, encrypt_amount},
    utils::{
        conversion::ToU64 as _,
        serialize::{deserialize_verifier_data, serialize_verifier_data},
    },
    wallet_core::{
        BatchTxApply, BuiltInterChannelCredit, BuiltSend, CancelCloseProver,
        ChannelBalanceAttestation, ChannelSnapshot, ChannelWithdrawalParams, CloseProver,
        Erc20LaneParams, FalconAggregateProofArtifact, FalconProverContext,
        InterChannelDebitPayload, InterChannelTransferDescriptor, MemberInfo, MemberKeys,
        PostCloseClaimProver, RefreshPayload, SendPayload, SlimSendPayload, WithdrawalClaimProver,
        add_signature, assemble_genesis_state_backed, build_batch_next_state,
        build_channel_withdrawal, build_inter_channel_credit, build_l1_deposit_import,
        build_record, build_refresh, build_send_token, build_token_register, burn_withdrawal_leaf,
        decrypt_balance_token, default_settled_tx_accumulator, inter_channel_base_transfer,
        inter_channel_tx_v2, partial_withdrawal_auth_digest, regev_pks_array,
        resolve_local_token_slot, sign_state, sign_state_if_backed, verify_all_signatures,
        verify_base_nonce_available, verify_inter_channel_credit_transition,
        verify_inter_channel_descriptor_matches_debit,
        verify_inter_channel_send_transition_with_lookup, verify_l1_deposit_import_transition,
        verify_refresh_transition, verify_send_transition, verify_slim_send_tx, verify_snapshot,
        verify_state_sig, verify_token_register_state_transition,
    },
};
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    plonk::{
        circuit_data::VerifierCircuitData, config::PoseidonGoldilocksConfig,
        proof::ProofWithPublicInputs,
    },
};
use rand010::{SeedableRng, rngs::StdRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

// Base-layer proof config (matches `BalanceProcessor` / `wallet_core`).
type BF = GoldilocksField;
type BC = PoseidonGoldilocksConfig;
const BD: usize = 2;

const LEVEL: RegevSecurityLevel = RegevSecurityLevel::Production;
const STATE_FILE: &str = "cli_state.json";
const STATE_PROCESS_LOCK_FILE: &str = ".cli_state.process.lock";
const DETACHED_PRECOMPUTE_LOCK_BYPASS_ENV: &str = "INTMAX_DETACHED_PRECOMPUTE_LOCK_BYPASS";
const FALCON_AGG_CACHE_DIR: &str = "falcon_aggregate_cache";
// Which channel this CLI process operates. The relay runs ONE process per channel (channels 7 and
// 8), each in its own working directory, selecting the channel via the `INTMAX_CHANNEL` env var.
// Defaults to 7 for standalone use. Channel id is part of the deposit recipient + the channel
// record, so two channels are fully distinct on-chain identities (each backed by its own real
// deposit).
fn channel_id_env() -> u32 {
    std::env::var("INTMAX_CHANNEL")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(7)
}
const BP_SLOT: u8 = 0;
// A-3 P1 / detail2 §K-4: the channel's L1-close anchor (`ChannelFund.intmax_state_root`) is the
// rollup state root the close circuit binds into the members' IMCH/IMCI signatures. `setup-backing`
// now sources the REAL value by querying `IntmaxRollup.latestFinalizedStateRoot()` (no longer a
// placeholder). SECURITY: this value is NOT load-bearing for fund custody — the actual exit is
// gated by the withdrawal proof's `finalizedStateRoots[ext_commitment]` check in IntmaxRollup
// (IntmaxRollup.sol:1262), which independently proves the funds against a finalized rollup state.
// The anchor is therefore a channel-internal, member-signed value (adversarial review: a zero or
// forged anchor is fund-safe). If the rollup has no finalized block yet, the sourced root is the
// genesis/zero root — fund-safe, but the eventual on-chain close would treat it as a placeholder
// (liveness caveat, see tasks/a3-close-lifecycle-spec.md threat model Threat 7).
// detail2 §F-1 deposit backing: produced ONCE by `setup-backing`, consumed by the co-sign gate.
const BACKING_FILE: &str = "channel_backing.json"; // settled_tx_chain / intmax_state_root / fund
const ATTESTATION_FILE: &str = "channel_attestation.bin"; // the channel's base-layer balance proof
const BALANCE_VD_FILE: &str = "balance_vd.bin"; // cached balance verifier data (the gate needs only this)
/// Production `deploy-settlement` consumes a complete, self-verified `public_close_prover` bundle
/// from this directory. Only its CloseAssetBacking artifact is staged into Foundry's read-only
/// input directory; the close-intent VK is never reused for the backing circuit.
const PUBLIC_CLOSE_BUNDLE_ENV: &str = "INTMAX_PUBLIC_CLOSE_BUNDLE";
const STAGED_CLOSE_BACKING_MANIFEST: &str = "close_asset_backing_manifest.json";
const STAGED_CLOSE_BACKING_MLE: &str = "close_asset_backing_mle.json";
const STAGED_CLOSE_BACKING_PUBLIC_INPUTS: &str = "close_asset_backing_public_inputs.json";
// A-3 P3 close artifacts: the descriptor + wrapped-close MLE proof the on-chain
// `ChannelSettlementManager.submitCloseIntent` consumes (same schema as generate_close_fixture).
const CLOSE_INTENT_FILE: &str = "close_intent.json";
const CLOSE_INTENT_MLE_FILE: &str = "close_intent_mle.json";
const PW_CLOSE_INTENT_MLE_FILE: &str = "pw_close_intent_mle.json";
// A-3 H-3 C1 (A30 cancelClose): the EXACT pending `CloseIntent` (serde, camelCase) persisted by
// `close` so `cancel-close` can reconstruct the same close_intent_digest the manager froze on-chain
// — a lossless round-trip (NOT the hex-string descriptor), so the cancel proof's
// close_intent_digest PI matches `pendingClose.closeIntentDigest` or the manager fail-closes
// (CloseIntentDigestMismatch).
const CLOSE_INTENT_FULL_FILE: &str = "close_intent_full.json";
const CANCEL_CLOSE_FILE: &str = "cancel_close.json";
const CANCEL_CLOSE_MLE_FILE: &str = "cancel_close_mle.json";
// A-3 H-2 §3.5.5 (A34 submitPostCloseClaim): a member claims a late inter-channel delta that landed
// AFTER the channel was finalized.
const POST_CLOSE_CLAIM_FILE: &str = "post_close_claim.json";
const POST_CLOSE_CLAIM_MLE_FILE: &str = "post_close_claim_mle.json";
// Delegate demo: slots 0..cli_cosigner_count() = CLI-controlled CO-SIGNING MEMBERS (with genesis
// balances); the next slot = the browser, a send-only DELEGATE (delegate_count = 1).
//
// The cosigner count is env-configurable (`INTMAX_CLI_COSIGNERS`, default 3, max MAX_SIG_CLUSTER)
// so a stress box can exercise a full 8-of-8 co-sign round (MAX_SIG_CLUSTER). Slots 0..2 keep their
// historical genesis balances and any EXTRA cosigner slot holds 0, so Σ(genesis balances) — and
// therefore the deposit-backing `fund` reconciliation — is IDENTICAL for every cosigner count.
fn cli_cosigner_count() -> u16 {
    let n: u16 = std::env::var("INTMAX_CLI_COSIGNERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3);
    if n < 1 || n as usize > MAX_SIG_CLUSTER {
        die(format!(
            "INTMAX_CLI_COSIGNERS must be 1..={MAX_SIG_CLUSTER}"
        ));
    }
    n
}
fn cli_slots() -> Vec<u16> {
    (0..cli_cosigner_count()).collect()
}
// Genesis allocations in BASE UNITS (= wei). With TOKEN_DECIMALS=18, 1 token = 1 ETH.
// 0.04 + 0.03 + 0.02 = 0.09 ETH total — fits comfortably in u64 (max ~18.4 ETH).
fn genesis_amount(slot: u16) -> u64 {
    match slot {
        0 => TOKEN_UNIT / 25,      // 0.04 ETH
        1 => TOKEN_UNIT / 100 * 3, // 0.03 ETH
        2 => TOKEN_UNIT / 50,      // 0.02 ETH
        _ => 0,                    // extra stress cosigners co-sign but hold no balance
    }
}
fn first_delegate_slot() -> u16 {
    cli_cosigner_count()
}
// The first browser delegate's genesis allocation (BASE UNITS) out of the deposited fund (so
// Σ balances == fund): 50 tokens.
const DELEGATE_GENESIS: u64 = 0;

/// A reproducible balance witness for ONE (CLI member, LOCAL token position) pair, recorded by
/// `refresh` (multitoken §N × detail2 §B-3).
///
/// The legacy `ControlledMember::{balance_amount, balance_seed, has_witness}` triple only ever
/// described the GENESIS token (local position 0): the CLI members are funded at genesis in token
/// 0 and nowhere else. A non-genesis position is credited HOMOMORPHICALLY (an L1 deposit import,
/// or an incoming in-channel transfer), which leaves a ciphertext this process holds no encryption
/// witness for AND `pending_adds > 0` — `build_send_token` refuses both, fail-closed. `refresh`
/// is the value-preserving way out; this record is what makes the resulting witness reconstructible
/// on the NEXT process invocation without persisting unserializable key material.
///
/// SECURITY: `seed_hex` is 32 bytes drawn from the OS CSPRNG at refresh time, never derived from
/// channel state. Regev encryption randomness must never be reused across two different plaintexts
/// under one key, so each refresh draws its own seed; `has_witness` is cleared the moment the
/// position is spent, so a stale witness can never be handed to the E-1 prover.
#[derive(Clone, Serialize, Deserialize)]
struct TokenWitness {
    /// LOCAL token position (index into the channel's signed `token_registry`).
    token_slot: u8,
    /// Plaintext value the recorded ciphertext encrypts (read back from the refresh proof's own
    /// decryption of the authenticated state — not from CLI bookkeeping).
    amount: u64,
    /// Hex of the 32-byte `StdRng` seed that reproduces the position's ciphertext + witness.
    seed_hex: String,
    /// False once the position has been spent (the recorded seed no longer matches state).
    has_witness: bool,
}

#[derive(Clone, Serialize, Deserialize)]
struct ControlledMember {
    slot: u16,
    keygen_seed: u64,
    balance_amount: u64,
    balance_seed: u64,
    has_witness: bool,
    /// Per-LOCAL-token-position witnesses recorded by `refresh`. Absent in pre-multitoken state
    /// files (serde default = empty), which keeps every existing token-0 flow byte-identical.
    #[serde(default)]
    token_witnesses: Vec<TokenWitness>,
}

/// Schema version stamped into every `cli_state.json` this build writes.
///
/// SECURITY (deposit-import-threat-model.md §10.8 finding 2): the three replay ledgers below used
/// to be `#[serde(default)]`, so a state file that LACKED or differently-NAMED a ledger key
/// deserialized to an EMPTY ledger and every `contains()` refusal built on it silently passed.
/// That is not hypothetical — it already happened once when `applied_tx_hashes` was renamed to
/// `applied_tx_identities` and the old entries were dropped without a diagnostic. A security
/// ledger that resets itself in silence is worse than no ledger, because the operator believes it
/// is running. Bump this whenever the on-disk shape of a ledger changes.
const STATE_SCHEMA_VERSION: u32 = 4;

/// The replay-ledger keys `cli_state.json` MUST carry. SECURITY: `load_state` checks for these BY
/// NAME and fails LOUDLY on absence — the enumeration is deliberately in one auditable place. Add
/// a key here the moment a new ledger is added; RENAMING a key here without a
/// `STATE_SCHEMA_VERSION` bump is the exact mistake this list exists to make impossible to repeat.
const REQUIRED_LEDGER_KEYS: [&str; 5] = [
    "applied_tx_identities",
    "spent_tx_identities",
    "imported_deposits",
    "state_signing_ledger",
    "signer_exit_kit_receipt",
];
const SETTLEMENT_BINDING_KEY: &str = "settlement_binding";
const STATE_SIGNING_LEDGER_KEY: &str = "state_signing_ledger";
const SIGNER_EXIT_KIT_RECEIPT_KEY: &str = "signer_exit_kit_receipt";
const SIGNER_EXIT_KIT_RECEIPT_SCHEMA_VERSION: u32 = 1;
const SIGNER_EXIT_KIT_ARCHIVE_DIR: &str = ".signer-exit-kits";

/// Why a member key signed a particular child. This is durable security metadata, not a display
/// label: replay is accepted only when the successor, purpose and optional plan digest all agree.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StateSigningPurpose {
    Genesis,
    DelegateJoin,
    InChannelSend,
    InChannelBatch,
    BalanceRefresh,
    InterChannelDebit,
    InterChannelFundImport,
    InterChannelBundleApply,
    BurnDebit,
    TokenRegister,
    L1DepositFundImport,
    L1DepositBundleApply,
    CloseFunding,
}

impl StateSigningPurpose {
    fn is_terminal(self) -> bool {
        self == Self::CloseFunding
    }

    /// These transitions change the L1-backed asset/composition statement. The current protocol
    /// can materialize their signer-independent exit kit only *after* it receives an N-of-N state,
    /// which is too late: once the final signature exists a coordinator can withhold both the
    /// state and the newly required proof. Keep every such path fail-closed at the common signing
    /// primitive until a pre-sign prepare+fsync receipt is part of this API.
    fn requires_prepared_exit_kit(self) -> bool {
        matches!(
            self,
            Self::InterChannelDebit
                | Self::InterChannelFundImport
                | Self::InterChannelBundleApply
                | Self::BurnDebit
                | Self::TokenRegister
                | Self::L1DepositFundImport
                | Self::L1DepositBundleApply
                | Self::CloseFunding
        )
    }

    /// H2=0 value-preserving successors may reuse the predecessor's backing proof, but only when
    /// the complete proof statement key is unchanged. Genesis has no predecessor and delegate
    /// enrollment is handled by its separate zero-opening construction.
    fn reuses_predecessor_exit_kit(self) -> bool {
        matches!(
            self,
            Self::InChannelSend | Self::InChannelBatch | Self::BalanceRefresh
        )
    }
}

/// Crash-safe evidence that this signer personally obtained and cryptographically verified a
/// complete public exit artifact before releasing another signature. The large envelope lives in
/// a content-addressed archive; this small receipt stays in `cli_state.json` and is carried across
/// every H2=0 successor whose exact backing statement remains unchanged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SignerExitKitReceipt {
    schema_version: u32,
    archive_sha256: [u8; 32],
    balance_verifier_data_sha256: [u8; 32],
    chain_id: u64,
    rollup: Address,
    source_signed_head_digest: Bytes32,
    channel_id: ChannelId,
    settled_tx_chain: Bytes32,
    token_funds_digest: Bytes32,
}

fn exit_kit_statement_key(state: &ChannelState) -> (ChannelId, Bytes32, Bytes32) {
    (
        state.channel_id,
        state.balance_state.settled_tx_chain,
        token_funds_digest(
            &state.balance_state.token_registry,
            state.balance_state.token_count,
            &state.channel_fund.amounts,
        ),
    )
}

fn exit_kit_receipt_archive_path(receipt: &SignerExitKitReceipt) -> PathBuf {
    Path::new(SIGNER_EXIT_KIT_ARCHIVE_DIR)
        .join(format!("{}.json", hex::encode(receipt.archive_sha256)))
}

fn validate_exit_kit_receipt_for_head(
    receipt: &SignerExitKitReceipt,
    head: &ChannelState,
) -> Result<(), String> {
    if receipt.schema_version != SIGNER_EXIT_KIT_RECEIPT_SCHEMA_VERSION {
        return Err(format!(
            "signer exit-kit receipt schema {} is not supported version {}",
            receipt.schema_version, SIGNER_EXIT_KIT_RECEIPT_SCHEMA_VERSION
        ));
    }
    if receipt.archive_sha256 == [0; 32]
        || receipt.balance_verifier_data_sha256 == [0; 32]
        || receipt.chain_id == 0
        || receipt.rollup == Address::default()
        || receipt.source_signed_head_digest == Bytes32::default()
    {
        return Err("signer exit-kit receipt contains a zero security binding".into());
    }
    let expected = exit_kit_statement_key(head);
    let actual = (
        receipt.channel_id,
        receipt.settled_tx_chain,
        receipt.token_funds_digest,
    );
    if actual != expected {
        return Err(format!(
            "signer exit-kit receipt does not compose with the durable head \
             (receipt={actual:?}, head={expected:?})"
        ));
    }
    Ok(())
}

/// Enforce the signature-release half of the signer-independent-exit invariant before looking up
/// an old signature and, critically, before invoking the signer. There is deliberately no
/// "operator override": an exact historical replay is still an external release and must pass the
/// current safety gate too.
fn enforce_exit_kit_before_signature_release(
    cli: &mut CliState,
    successor: &ChannelState,
    purpose: StateSigningPurpose,
) -> Result<(), String> {
    if purpose.requires_prepared_exit_kit() {
        return Err(format!(
            "SIGNER-INDEPENDENT EXIT REQUIRED: refusing {purpose:?} before signature release; \
             this asset/composition-moving transition has no exact durable pre-sign exit kit. \
             Stage and fsync the exact (channel_id, settled_tx_chain, token_funds_digest) kit \
             before enabling this signing purpose"
        ));
    }

    if purpose.reuses_predecessor_exit_kit() {
        let predecessor = &cli.snapshot.state;
        if successor.prev_digest != predecessor.digest {
            return Err(
                "EXIT-KIT REUSE REFUSAL: successor does not extend the locally durable signed head"
                    .into(),
            );
        }
        if successor.h2_tag != Bytes32::default() {
            return Err(
                "EXIT-KIT REUSE REFUSAL: only an H2=0 successor may reuse the predecessor kit"
                    .into(),
            );
        }
        let predecessor_key = exit_kit_statement_key(predecessor);
        let successor_key = exit_kit_statement_key(successor);
        if successor_key != predecessor_key {
            return Err(format!(
                "EXIT-KIT REUSE REFUSAL: H2=0 is insufficient; exact \
                 (channel_id, settled_tx_chain, token_funds_digest) equality is required \
                (predecessor={predecessor_key:?}, successor={successor_key:?})"
            ));
        }

        let receipt = cli.signer_exit_kit_receipt.as_ref().ok_or_else(|| {
            "SIGNER-INDEPENDENT EXIT REQUIRED: the durable predecessor has no cryptographically \
             verified signer exit-kit receipt; legacy/key-equality-only reuse is forbidden"
                .to_string()
        })?;
        validate_exit_kit_receipt_for_head(receipt, predecessor)?;
        if !cli.signer_exit_kit_receipt_verified {
            verify_persisted_signer_exit_kit(cli)?;
            cli.signer_exit_kit_receipt_verified = true;
        }
    }

    Ok(())
}

/// One crash-safe anti-equivocation decision. The map key repeats the first three fields in a
/// canonical printable form so malformed/renamed state cannot alias two signing decisions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateSigningLedgerEntry {
    channel_id: ChannelId,
    predecessor_digest: Bytes32,
    member_slot: u16,
    successor_digest: Bytes32,
    purpose: StateSigningPurpose,
    plan_digest: Option<Bytes32>,
    signature: MemberSignature,
}

/// Durable, sticky proof that this channel's participant identity has been frozen into an L1
/// settlement manager.  It lives in the crash-safe private state rather than `settlement.json`:
/// deleting a convenience address file or starting the CLI from another directory cannot turn a
/// post-deployment channel back into one that admits new delegate keys.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SettlementBinding {
    status: SettlementBindingStatus,
    channel_id: u32,
    snapshot_state_digest: Bytes32,
    participant_root: Bytes32,
    participant_count: u16,
    rollup: String,
    verifier: Option<String>,
    manager: Option<String>,
    /// Immutable atomic terminal-funding gateway bound by the Manager constructor.
    #[serde(default)]
    materializer: Option<String>,
    /// Production-only crash-recovery identity.  This is persisted in the PREPARED write before
    /// `forge --broadcast` starts.  A missing value on a PREPARED real-chain binding is not
    /// interpreted as permission to start over: it is a legacy/incomplete deployment that needs
    /// operator recovery.
    #[serde(default)]
    deployment: Option<SettlementDeploymentIntent>,
    /// The canonical durable head at which every production deployment readback was pinned.
    /// Devnet bindings leave this empty; a real-chain binding may become ACTIVE only with one.
    #[serde(default)]
    activation_checkpoint: Option<intmax3_zkp::l1_finality::L1FinalizedCheckpoint>,
    /// Production-only deployed runtime identity, measured at the canonical activation block and
    /// rechecked at every later durable head before a fund-moving command may proceed. Legacy
    /// production bindings without this field fail closed; devnet mock bindings leave it empty.
    #[serde(default)]
    runtime_code_hashes: Option<SettlementRuntimeCodeHashes>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SettlementRuntimeCodeHashes {
    rollup: Bytes32,
    verifier: Bytes32,
    manager: Bytes32,
    #[serde(default)]
    materializer: Bytes32,
}

/// Everything needed to prove that a Foundry `run-latest.json` belongs to this exact settlement
/// attempt.  In particular, `start_nonce` makes an old run for the same channel distinguishable
/// from this one, while `plan_digest` commits the live registration, script and VK fixtures.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SettlementDeploymentIntent {
    chain_id: u64,
    broadcaster: String,
    start_nonce: u64,
    start_block: u64,
    broadcast_artifact_path: String,
    plan_digest: Bytes32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SettlementBindingStatus {
    Prepared,
    Active,
}

/// Always serialize the CURRENT schema version, whatever the in-memory value says, so no write can
/// ever stamp a file with an older schema than it actually has.
fn serialize_current_schema_version<S: serde::Serializer>(
    _v: &u32,
    s: S,
) -> Result<S::Ok, S::Error> {
    s.serialize_u32(STATE_SCHEMA_VERSION)
}

// SECURITY (`deny_unknown_fields`): an unrecognised key is a hard error rather than a silent drop.
// Combined with the ABSENCE of `#[serde(default)]` on the ledgers below, this makes the on-disk
// key set an EXACT match of the struct in both directions: a renamed ledger fails as BOTH a
// missing field and an unknown one, so a rename can never again quietly reset a ledger to empty.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CliState {
    /// On-disk schema version. This is the ONE retained `#[serde(default)]` in this struct, and it
    /// is justified: every state file in existence pre-dates the field, so requiring it would
    /// refuse to load live channels (e.g. `wallet-live-work/ch7`). Defaulting to `0` is SAFE here
    /// — unlike a defaulted ledger — because it makes no security claim by itself: `load_state`
    /// still verifies every ledger key is PRESENT, and it ANNOUNCES the pre-versioning file on
    /// stderr rather than accepting it silently. A version NEWER than this build is refused.
    #[serde(default, serialize_with = "serialize_current_schema_version")]
    state_schema_version: u32,
    controlled: Vec<ControlledMember>,
    snapshot: ChannelSnapshot,
    /// No serde default: absence is a schema/migration event, never an implicit "not frozen".
    /// `load_state` names the missing key and `migrate-state` may add null only while no local
    /// settlement record exists.  Once Some, no command clears it.
    settlement_binding: Option<SettlementBinding>,
    /// No serde default: a legacy file must explicitly migrate to `null`, after which every
    /// H2=0 signature path still fails closed until `install-exit-kit` verifies and archives an
    /// exact public artifact. Merely matching the three composition fields is not a receipt.
    signer_exit_kit_receipt: Option<SignerExitKitReceipt>,
    /// Process-local verification cache. This is deliberately never serialized: every new CLI
    /// invocation re-hashes the archive and cryptographically verifies its Balance/backing proofs
    /// once before the first signature is released.
    #[serde(skip)]
    signer_exit_kit_receipt_verified: bool,
    /// REPLAY LEDGER (inter-channel invariant 6): the set of inter-channel REPLAY IDENTITIES
    /// (`InterChannelTx::replay_identity()` — the token-FREE fold over
    /// `(source, dest, tx_tree_root, tx_leaf)`) already CREDITED into THIS channel (the
    /// DESTINATION / B side). A credit is applied at most once; a descriptor whose identity is
    /// already present is REFUSED (fail-closed). Persisted in `cli_state.json` so the ledger
    /// survives across CLI invocations (each channel runs as its own process).
    ///
    /// SECURITY (TM-16 obligation 1, MATERIAL): the ledger keys on the token-FREE identity,
    /// NEVER on the token-bearing `tx_hash`. Since TM-16 the `tx_hash` commits the descriptor's
    /// base `token_index` (ids limb 5), so a malicious sender could prove E-2 twice (token X and
    /// token Y) over the SAME deltas and present two IMI2-signed descriptors with DIFFERENT
    /// tx_hashes — a tx_hash-keyed set would credit the same debit twice across two tokens. The
    /// identity strips the token limb, so the second variant is refused as a replay.
    ///
    /// SECURITY (NO `#[serde(default)]` — §10.8 finding 2): this field used to carry one, and the
    /// TM-16 rename from `applied_tx_hashes` therefore DROPPED every pre-rename entry in silence.
    /// A state file that does not name this key is now a LOUD `load_state` failure with a
    /// migration instruction; see `REQUIRED_LEDGER_KEYS` and `migrate-state`.
    ///
    /// Stored as a `HashSet` (Phase 5a review MINOR): membership checks are O(1) instead of a
    /// linear scan over an unbounded Vec; the ledger only ever grows for the channel's lifetime
    /// (pruned implicitly by the channel close — a closed channel's state dir is retired). JSON
    /// serialization stays an array (element order is not meaningful and not relied upon).
    applied_tx_identities: HashSet<Bytes32>,
    /// SPENT LEDGER (A side): the set of inter-channel REPLAY IDENTITIES already DEBITED out of
    /// THIS channel as the SOURCE. A debit is applied at most once; if the identity is already
    /// present the combined `cosign-inter-transfer` REFUSES (fail-closed). This is the A-side
    /// counterpart to `applied_tx_identities` — together they make a transfer atomic AND
    /// single-use on both ends. Same TM-16 token-free keying as `applied_tx_identities` (the
    /// A-side leg of the cross-token double-debit defense). Same `HashSet` rationale as
    /// `applied_tx_identities`, and the same NO-`#[serde(default)]` rule for the same reason.
    spent_tx_identities: HashSet<Bytes32>,
    /// CONSUMED-DEPOSIT LEDGER (L1 import replay protection — deposit-import-threat-model.md §4):
    /// the set of L1 deposits already CREDITED into this channel, keyed on the canonical deposit
    /// identity `"{chain_id}:{rollup_lowercase}:{deposit_index}"`.
    ///
    /// SECURITY (why this must exist): the channel layer has NO nullifier SET.
    /// `ChannelState.shared_native_nullifier_root` is a keccak hash CHAIN, and
    /// `build_l1_deposit_import` only FOLDS the deposit nullifier into it. The native gate
    /// (`L1DepositImportUpdateWitness::verify`) requires just `require_chain_push` +
    /// `ensure_different_root` — and because the fold is prev-bound, replaying the SAME nullifier
    /// always produces a DIFFERENT root, so `ensure_different_root` passes on a replay by
    /// construction. The co-signer gate `verify_l1_deposit_import_transition` is rebuild-equality
    /// only and does no freshness checking. Nothing else refuses a second import of one deposit.
    ///
    /// Keyed on `deposit_index` (the contract's own monotone `depositCount`) and NOT on the tx
    /// hash, because ONE transaction can emit several `Deposited` logs — a tx-hash key would
    /// under-count. `chain_id` + `rollup` scope the index to the contract that issued it.
    ///
    /// RESIDUAL RISK (documented, not fixed here — same standing as the inter-channel ledgers
    /// above): this is LOCAL CLI state, not a cryptographic enforcement. Deleting
    /// `cli_state.json`, or running a second CLI with a fresh state dir, defeats it. The
    /// protocol-level fix (a real indexed nullifier set checked in-circuit) is a design change
    /// beyond this vulnerability. What this ledger DOES guarantee is that a replay is no longer
    /// reachable by an unauthenticated remote caller through any relay/api endpoint.
    ///
    /// SECURITY (NO `#[serde(default)]`): this ledger is also the only backstop that would catch a
    /// re-import of the channel's own backing deposit if the backing-deposit guard were disarmed
    /// (§10.4 Finding B). Both defences used to fail silently and independently; neither does now.
    imported_deposits: HashSet<String>,
    /// CRASH-SAFE ANTI-EQUIVOCATION LEDGER. A locally controlled member may authorize at most one
    /// successor for a `(channel_id, predecessor_digest, member_slot)` key. The exact serialized
    /// Falcon signature is retained so a retry of the same successor returns byte-identical bytes;
    /// a sibling successor is refused before a fresh signature is produced. Terminal close-funding
    /// entries are permanent global reservations: after the first one, no non-identical state may
    /// ever be signed, and there is deliberately no timestamp, TTL, release or delete command.
    ///
    /// No serde default: losing this field would silently erase every prior signing decision.
    state_signing_ledger: BTreeMap<String, StateSigningLedgerEntry>,
}

fn state_signing_ledger_key(
    channel_id: ChannelId,
    predecessor_digest: Bytes32,
    member_slot: u16,
) -> String {
    format!(
        "{}:{}:{}",
        channel_id.as_u64(),
        predecessor_digest.to_hex().to_ascii_lowercase(),
        member_slot
    )
}

/// Return the one permanent terminal reservation represented by the ledger, if any. Multiple
/// member entries for the same terminal child are expected; any disagreement is corruption.
fn terminal_signing_reservation(
    ledger: &BTreeMap<String, StateSigningLedgerEntry>,
) -> Result<Option<(ChannelId, Bytes32, Bytes32, Bytes32)>, String> {
    let mut terminal = None;
    for entry in ledger.values().filter(|entry| entry.purpose.is_terminal()) {
        let plan_digest = entry
            .plan_digest
            .ok_or_else(|| "terminal signing entry has no plan_digest".to_string())?;
        let candidate = (
            entry.channel_id,
            entry.predecessor_digest,
            entry.successor_digest,
            plan_digest,
        );
        match terminal {
            None => terminal = Some(candidate),
            Some(existing) if existing == candidate => {}
            Some(_) => {
                return Err(
                    "signing ledger contains two different terminal close reservations".into(),
                );
            }
        }
    }
    Ok(terminal)
}

/// Cheap structural validation on every state read/write. Historical Falcon signatures are not
/// re-verified here (that would make ordinary CLI startup linear in channel lifetime); the exact
/// stored signature is cryptographically checked when it is replayed, and every newly inserted
/// signature is checked before persistence.
fn validate_signing_security_state(state: &CliState) -> Result<(), String> {
    let record = &state.snapshot.record;
    if let Some(receipt) = &state.signer_exit_kit_receipt {
        validate_exit_kit_receipt_for_head(receipt, &state.snapshot.state)?;
    } else if state.signer_exit_kit_receipt_verified {
        return Err("exit-kit verification cache is set without a durable receipt".into());
    }
    for (key, entry) in &state.state_signing_ledger {
        let expected_key = state_signing_ledger_key(
            entry.channel_id,
            entry.predecessor_digest,
            entry.member_slot,
        );
        if key != &expected_key {
            return Err(format!(
                "signing ledger key {key:?} does not match its canonical fields {expected_key:?}"
            ));
        }
        if entry.channel_id != record.channel_id {
            return Err("signing ledger entry belongs to a different channel".into());
        }
        if entry.member_slot >= u16::from(record.member_count) {
            return Err(format!(
                "signing ledger member slot {} is outside member_count {}",
                entry.member_slot, record.member_count
            ));
        }
        if entry.successor_digest == Bytes32::default() {
            return Err("signing ledger contains a zero successor digest".into());
        }
        if entry.signature.member_slot as u16 != entry.member_slot
            || entry.signature.pk_g != record.member_pk_gs[entry.member_slot as usize]
        {
            return Err(format!(
                "signing ledger signature identity disagrees with member slot {}",
                entry.member_slot
            ));
        }
        if entry.purpose.is_terminal() != entry.plan_digest.is_some() {
            return Err(
                "only terminal close-funding signing entries may carry a plan_digest".into(),
            );
        }
    }

    if let Some((channel_id, predecessor, successor, _)) =
        terminal_signing_reservation(&state.state_signing_ledger)?
    {
        if channel_id != record.channel_id {
            return Err("terminal signing reservation belongs to a different channel".into());
        }
        let head = state.snapshot.state.digest;
        if head != predecessor && head != successor {
            return Err(format!(
                "terminal signing reservation permits only predecessor {predecessor} or terminal \
                 successor {successor}, but cli_state head is {head}"
            ));
        }
    }
    Ok(())
}

/// The sole state-signature mint/replay primitive in this binary (deprecated MSU is intentionally
/// isolated from it). It checks the durable decision before invoking `signer`, returns stored bytes
/// on an exact replay, and rejects a sibling or a post-terminal request before a new signature is
/// produced.
fn ledgered_state_signature_with<F>(
    cli: &mut CliState,
    record: &ChannelRecord,
    controlled: &ControlledMember,
    successor: &ChannelState,
    purpose: StateSigningPurpose,
    plan_digest: Option<Bytes32>,
    candidate_signature: Option<MemberSignature>,
    signer: F,
) -> Result<MemberSignature, String>
where
    F: FnOnce(&MemberKeys) -> Result<MemberSignature, String>,
{
    if successor.channel_id != record.channel_id
        || successor.channel_id != successor.balance_state.channel_id
        || successor.channel_id != successor.channel_fund.channel_id
    {
        return Err("state-signing request has inconsistent channel ids".into());
    }
    if successor.digest != successor.signing_digest() {
        return Err("state-signing request digest does not match its signed preimage".into());
    }
    if controlled.slot >= u16::from(record.member_count) {
        return Err(format!(
            "controlled slot {} is outside member_count {}",
            controlled.slot, record.member_count
        ));
    }
    if purpose.is_terminal() != plan_digest.is_some() {
        return Err(
            "close-funding requires exactly one plan_digest; other purposes forbid it".into(),
        );
    }

    // SECURITY: this is intentionally before both terminal/anti-equivocation replay lookup and
    // `signer`. Returning stored signature bytes is still an external release; grandfathering an
    // unsafe historical decision here would recreate the signer-withholding failure.
    enforce_exit_kit_before_signature_release(cli, successor, purpose)?;

    let requested_terminal = plan_digest.map(|plan| {
        (
            successor.channel_id,
            successor.prev_digest,
            successor.digest,
            plan,
        )
    });
    if let Some(reserved) = terminal_signing_reservation(&cli.state_signing_ledger)? {
        if requested_terminal != Some(reserved) {
            return Err(format!(
                "TERMINAL SIGNING RESERVATION: channel {} is permanently reserved for successor \
                 {} (plan {}); refusing any different/non-terminal state",
                reserved.0.as_u64(),
                reserved.2,
                reserved.3
            ));
        }
    }

    let key =
        state_signing_ledger_key(successor.channel_id, successor.prev_digest, controlled.slot);
    if let Some(existing) = cli.state_signing_ledger.get(&key) {
        if existing.successor_digest != successor.digest
            || existing.purpose != purpose
            || existing.plan_digest != plan_digest
        {
            return Err(format!(
                "ANTI-EQUIVOCATION REFUSAL: member slot {} already signed successor {} for \
                 predecessor {}; requested sibling {}",
                controlled.slot, existing.successor_digest, successor.prev_digest, successor.digest
            ));
        }
        verify_state_sig(
            existing.signature.pk_g,
            &existing.successor_digest,
            &existing.signature.signature,
        )
        .map_err(|e| format!("stored signing-ledger signature is invalid: {e}"))?;
        return Ok(existing.signature.clone());
    }

    let keys = keys_for(controlled.keygen_seed);
    let expected_pk_g = record.member_pk_gs[controlled.slot as usize];
    if keys.pk_g() != expected_pk_g {
        return Err(format!(
            "controlled key for slot {} differs from the channel record",
            controlled.slot
        ));
    }
    let signature = match candidate_signature {
        Some(signature) => signature,
        None => signer(&keys)?,
    };
    if signature.member_slot as u16 != controlled.slot || signature.pk_g != expected_pk_g {
        return Err(format!(
            "candidate signature identity disagrees with controlled slot {}",
            controlled.slot
        ));
    }
    verify_state_sig(expected_pk_g, &successor.digest, &signature.signature)
        .map_err(|e| format!("candidate state signature is invalid: {e}"))?;

    cli.state_signing_ledger.insert(
        key,
        StateSigningLedgerEntry {
            channel_id: successor.channel_id,
            predecessor_digest: successor.prev_digest,
            member_slot: controlled.slot,
            successor_digest: successor.digest,
            purpose,
            plan_digest,
            signature: signature.clone(),
        },
    );
    Ok(signature)
}

fn ledgered_state_signature(
    cli: &mut CliState,
    record: &ChannelRecord,
    controlled: &ControlledMember,
    successor: &ChannelState,
    purpose: StateSigningPurpose,
    plan_digest: Option<Bytes32>,
) -> Result<MemberSignature, String> {
    let candidates: Vec<MemberSignature> = successor
        .member_signatures
        .iter()
        .filter(|signature| signature.member_slot as u16 == controlled.slot)
        .cloned()
        .collect();
    if candidates.len() > 1 {
        return Err(format!(
            "state carries duplicate signatures for member slot {}",
            controlled.slot
        ));
    }
    let candidate = candidates.into_iter().next();
    ledgered_state_signature_with(
        cli,
        record,
        controlled,
        successor,
        purpose,
        plan_digest,
        candidate,
        |keys| {
            sign_state(keys, controlled.slot as u8, successor)
                .map_err(|e| format!("sign state: {e}"))
        },
    )
}

fn ledger_sign_all_controlled(
    cli: &mut CliState,
    successor: &mut ChannelState,
    purpose: StateSigningPurpose,
    plan_digest: Option<Bytes32>,
) {
    let record = cli.snapshot.record.clone();
    let controlled = cli.controlled.clone();
    for member in &controlled {
        let signature =
            ledgered_state_signature(cli, &record, member, successor, purpose, plan_digest)
                .unwrap_or_else(|error| die(error));
        // Always replace a request-carried signature with the durable signature. This is what
        // makes an exact retry byte-identical even though Falcon signing itself is randomized.
        add_signature(successor, signature);
    }
}

const INTER_TRANSFER_COMMIT_MAGIC: &str = "INTMAX_INTER_TRANSFER_2PC";
const INTER_TRANSFER_COMMIT_VERSION: u32 = 1;
const INTER_TRANSFER_COMMIT_DIR: &str = ".inter-transfer-journal";
const MAX_INTER_TRANSFER_JOURNALS: usize = 100_000;
const MAX_INTER_TRANSFER_JOURNAL_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InterTransferOut {
    a_head: ChannelState,
    b_fund_import_state: ChannelState,
    b_bundle_apply_state: ChannelState,
    b_snapshot: ChannelSnapshot,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum InterTransferCommitPhase {
    Prepared,
    Committed,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InterTransferCommitJournal {
    magic: String,
    version: u32,
    phase: InterTransferCommitPhase,
    tx_hash: Bytes32,
    replay_identity: Bytes32,
    source_channel_id: u64,
    destination_channel_id: u64,
    source_before_digest: Bytes32,
    destination_before_digest: Bytes32,
    source_after: CliState,
    destination_after: CliState,
    result: InterTransferOut,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InterTransferCommitEnvelope {
    checksum: Bytes32,
    journal: InterTransferCommitJournal,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrowserContribution {
    regev_pk: RegevPk,
    /// The browser member's Goldilocks signing public key `pk_g` (canonical Bytes32 hex, P4-2).
    pk_g: String,
    /// P3: the browser member's BabyBear hash-sig public key `pk_b` (canonical Bytes32 hex, A11).
    pk_b: String,
    /// SECURITY (A-1): ACCEPTED FOR WIRE COMPATIBILITY AND THEN IGNORED. This used to be installed
    /// verbatim as the delegate's opening balance at genesis (`create_channel`) and at join
    /// (`join_delegate`) — a self-declared, Regev-encrypted, unbacked amount that no cosigner can
    /// inspect and that `cmd_setup_backing`'s `fund` never accounted for. Both paths now open the
    /// delegate's slot at the canonical zero ciphertext instead, so this field has NO effect on
    /// state. It stays REQUIRED (no serde default) so existing browsers/relays that send it are
    /// unaffected. Do not start reading it again without a backing proof alongside it.
    #[allow(dead_code)]
    genesis_ct: RegevCiphertext,
    /// B-1b: the joining delegate's L1 exit address (hex, 0x-prefixed 20 bytes; the browser
    /// passes the user's MetaMask address). REQUIRED and NONZERO — serde has no default, so an
    /// absent field fails deserialization, and `parse_contribution_recipient` rejects the zero
    /// address (fail-closed: under Option B this leaf-bound address is the delegate's ONLY
    /// payout binding; a zero recipient could never exit).
    recipient: String,
}

/// Parse + fail-closed-validate a contribution's B-1b recipient: must parse as a 20-byte L1
/// address and must be NONZERO. The cosigners REFUSE to assemble/sign a state otherwise.
fn parse_contribution_recipient(recipient_hex: &str) -> Address {
    let recipient = Address::from_hex(recipient_hex)
        .unwrap_or_else(|e| die(format!("parse browser recipient: {e:?}")));
    if recipient == Address::default() {
        die(
            "REFUSING contribution: recipient is the zero address (B-1b fail-closed — the \
             delegate's leaf-bound L1 exit address is its only payout binding and address(0) \
             could never exit)",
        );
    }
    recipient
}

fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!("error: {msg}");
    exit(1);
}

/// Env override naming the Foundry `contracts/` checkout explicitly.
const CONTRACTS_DIR_ENV: &str = "CONTRACTS_DIR";

/// Locate the Foundry `contracts/` checkout WITHOUT consulting the current working directory.
///
/// LIVENESS (doc/audit/exit-path-facade-sweep.md F4 — the defect this closes): `close`, `claim`,
/// `cancel-close`, `post-close-claim` and `withdraw` used to reach the checkout through the
/// RELATIVE paths `Path::new("contracts/test/data")` and `Command::current_dir("contracts")`. All
/// three product drivers run this binary with `cwd = wallet-live-work/chN` (`api/lib/cli.js`,
/// `hosting/wallet/wallet-relay.js`, `hosting/wallet/wallet-relay-ec2.js`), and that directory has
/// no `contracts/` — so every exit command aborted, and in `close`/`withdraw` it aborted AFTER the
/// multi-minute proof, discarding a finished proof over a path lookup. The Rust E2Es never caught
/// it because they invoke the CLI with `cwd = repo_root()`, the one directory where the relative
/// path happens to resolve.
///
/// The resolution below is NOT new: it is exactly what `deploy-settlement` and `pw-submit` already
/// did two functions away — an explicit `CONTRACTS_DIR`, else an ancestor search from THE
/// EXECUTABLE. Nothing here reads the cwd, so an exit command behaves identically from any
/// directory.
///
/// Returns `(dir, provenance)` for the diagnostic line; every failure path `die`s.
fn resolve_contracts_dir() -> (std::path::PathBuf, String) {
    match std::env::var(CONTRACTS_DIR_ENV) {
        Ok(raw) if !raw.trim().is_empty() => (
            std::path::PathBuf::from(raw.trim()),
            format!("{CONTRACTS_DIR_ENV} env"),
        ),
        _ => {
            let exe = std::env::current_exe()
                .unwrap_or_else(|e| die(format!("cannot locate this executable: {e}")));
            let repo = exe
                .ancestors()
                .find(|p| p.join("contracts").is_dir())
                .unwrap_or_else(|| {
                    die(format!(
                        "cannot find a contracts/ dir in any ancestor of this executable ({}) — \
                         set {CONTRACTS_DIR_ENV}=<path to the foundry contracts checkout>. \
                         (The cwd is deliberately NOT consulted: every product driver runs this \
                         binary from a per-channel work dir that has no contracts/.)",
                        exe.display()
                    ))
                })
                .to_path_buf();
            (repo.join("contracts"), "executable ancestor search".into())
        }
    }
}

/// Resolve AND validate the contracts checkout an exit command is about to use, then announce it.
///
/// FAIL EARLY, FAIL LOUD (the second half of F4): a wrong or missing checkout used to surface as
/// `stage close_intent.json: No such file or directory` at the `fs::copy` — i.e. after `close` and
/// `withdraw` had already paid for their proof. Wasting a multi-minute proof on a path error is
/// itself the defect, so every exit command calls this BEFORE it loads state or proves anything,
/// and every caller names the forge script it will actually run so a checkout that is present but
/// wrong (an unrelated `contracts/` dir, a checkout without the staging dir) is rejected here
/// rather than mid-pipeline.
///
/// SECURITY: this is a liveness precondition only — it gates NO proof property. It never falls
/// back and never continues on a partial match: an unusable checkout is a `die`, never a warning.
fn require_contracts_dir(cmd: &str, scripts: &[&str]) -> std::path::PathBuf {
    let (dir, provenance) = resolve_contracts_dir();
    let mut missing: Vec<String> = Vec::new();
    if !dir.is_dir() {
        missing.push("the directory itself does not exist".to_string());
    } else {
        if !dir.join("test").join("data").is_dir() {
            missing.push(
                "test/data/ (the staging dir the forge steps read their inputs from)".to_string(),
            );
        }
        for script in scripts {
            if !dir.join(script).is_file() {
                missing.push(format!("{script} (the forge step `{cmd}` runs)"));
            }
        }
    }
    if !missing.is_empty() {
        die(format!(
            "`{cmd}`: {} is not a usable contracts checkout — missing: {}.\n\
             Resolved via {provenance}. Set {CONTRACTS_DIR_ENV}=<path to this repo's contracts/> \
             and re-run.\n\
             REFUSING NOW, BEFORE PROVING: `{cmd}` reaches the checkout only at the very end of \
             its pipeline, so continuing would burn the whole proof and then fail on a path \
             lookup (doc/audit/exit-path-facade-sweep.md F4).",
            dir.display(),
            missing.join(", ")
        ));
    }

    // Observable, not silent: the resolved path is printed BEFORE the heavy work so an operator
    // can see which checkout a live run is about to stage into.
    eprintln!(
        "[{cmd}] contracts dir: {} (via {provenance}; the cwd is not consulted)",
        dir.display()
    );
    dir
}

/// Env var naming the FILE that holds this host's co-signer master secret (production).
///
/// SECURITY: the env carries only a PATH — a path is not a secret, so it is safe for the variable
/// to be visible in `ps -E` / `/proc/PID/environ` and to be inherited by the ~27 `cast`
/// subprocesses. The secret itself is reachable only through the filesystem, where unix
/// permissions protect it AND can be verified (see `load_cosigner_master`). An env var holding the
/// secret DIRECTLY was rejected for exactly the inheritance/visibility reason
/// (doc/tasks/cosigner-key-provenance.md §4.1).
const COSIGNER_KEYFILE_ENV: &str = "INTMAX_COSIGNER_KEYFILE";

/// Env var that OPTS IN to the fully-derivable, publicly-known test keys.
///
/// SECURITY: deliberately long and screaming. There is NO default, NO precedence rule and NO
/// truthiness parsing — the only accepted value is the exact string "1", and setting it TOGETHER
/// with `COSIGNER_KEYFILE_ENV` is a hard error rather than a downgrade. A correctly provisioned
/// production host therefore cannot be silently reverted to test keys: adding this flag there is
/// an OUTAGE, not a weakening (doc/tasks/cosigner-key-provenance.md §5.5).
const INSECURE_KEYS_ENV: &str = "INTMAX_INSECURE_DETERMINISTIC_KEYS";

/// Domain tag folded in when normalising the operator's key file to a 32-byte master.
const KDF_MASTER_DOMAIN: &[u8] = b"INTMAX3/CLI-COSIGNER-MASTER/v1";
/// Domain tag folded in when deriving a per-label key seed from the master.
///
/// SECURITY: distinct from `KDF_MASTER_DOMAIN` so a master value can never collide with a
/// per-slot seed. Keccak is a sponge, so there is no length-extension concern in either step.
const KDF_SLOT_DOMAIN: &[u8] = b"INTMAX3/CLI-COSIGNER-KEYS/v1";

/// Where this process's co-signer key material comes from. Resolved EXACTLY ONCE per process
/// (`OnceLock` below) so two calls in one invocation can never disagree about provenance.
enum KeyProvenance {
    /// Production: every key is derived by KDF from an operator-provisioned external secret.
    ///
    /// SECURITY: `Zeroizing` wipes the master on drop, and this variant deliberately has no
    /// `Debug`/`Display` — the master must never be formattable into a log line, a `die` message
    /// or a panic payload.
    Master(zeroize::Zeroizing<[u8; 32]>),
    /// TEST ONLY: the legacy `seed_from_u64` derivation, whose outputs are computable by anyone
    /// who can read this public repository.
    InsecureDeterministic,
}

/// SECURITY (the whole point of this module): key material must come from an EXTERNAL SECRET,
/// never from a compile-time constant. `CLI_COSIGNER_SEED_BASE` used to be that constant, which
/// meant every co-signer private key of every CLI/API-driven channel was derivable from the public
/// source tree — full N-of-N custody of channel funds for any reader of the repo. Full analysis,
/// including what a code fix can NOT undo for already-created channels, is in
/// doc/tasks/cosigner-key-provenance.md.
///
/// FAIL CLOSED: this function has no fallback branch. Every unconfigured, ambiguously configured
/// or malformed state calls `die`. Forgetting to provision a host makes the CLI stop working
/// loudly; it can never make it work insecurely and silently.
fn key_provenance() -> &'static KeyProvenance {
    static PROVENANCE: std::sync::OnceLock<KeyProvenance> = std::sync::OnceLock::new();
    PROVENANCE.get_or_init(|| {
        let keyfile = std::env::var(COSIGNER_KEYFILE_ENV).ok().filter(|s| !s.is_empty());
        let insecure = std::env::var(INSECURE_KEYS_ENV).ok().filter(|s| !s.is_empty());
        match (keyfile, insecure) {
            // SECURITY: ambiguous provenance is REFUSED, never resolved by precedence. This is
            // what makes the insecure flag an outage rather than a downgrade on a provisioned
            // production host.
            (Some(_), Some(_)) => die(format!(
                "{COSIGNER_KEYFILE_ENV} and {INSECURE_KEYS_ENV} are BOTH set — refusing to guess \
                 which key material to use. Unset one. (If this is production, unset \
                 {INSECURE_KEYS_ENV}.)"
            )),
            (Some(path), None) => KeyProvenance::Master(load_cosigner_master(&path)),
            (None, Some(flag)) => {
                // SECURITY: exact-match only. No truthiness parsing — "0", "false", "no" and any
                // typo DIE rather than being interpreted, in either direction.
                if flag != "1" {
                    die(format!(
                        "{INSECURE_KEYS_ENV} must be exactly \"1\" to opt in to insecure test keys \
                         (got {flag:?}); it is not parsed for truthiness"
                    ));
                }
                eprintln!(
                    "\n\
                     !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n\
                     !! INSECURE DETERMINISTIC KEYS ARE ACTIVE ({INSECURE_KEYS_ENV}=1).\n\
                     !! Every co-signer private key this process uses is derived from a constant\n\
                     !! in a PUBLIC repository and is computable by anyone. Any channel created,\n\
                     !! signed or closed by this process offers NO custody of funds whatsoever.\n\
                     !! TESTS ONLY. If you are seeing this on a deployed host, STOP: set\n\
                     !! {COSIGNER_KEYFILE_ENV} instead and treat existing channels as compromised.\n\
                     !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
                );
                KeyProvenance::InsecureDeterministic
            }
            (None, None) => die(format!(
                "no co-signer key material configured: set {COSIGNER_KEYFILE_ENV}=/path/to/secret \
                 (a file with 0600 permissions containing >=32 bytes of hex, e.g. `umask 077; \
                 openssl rand -hex 32 > .claude/cosigner.key`). REFUSING to fall back to derived \
                 keys — the old constant-seeded keys were publicly computable. Tests may set \
                 {INSECURE_KEYS_ENV}=1 instead. See doc/tasks/cosigner-key-provenance.md"
            )),
        }
    })
}

/// Read + fail-closed-validate the operator's co-signer master secret.
///
/// SECURITY: every rejection below is a `die`, and NONE of the `die` messages contain file
/// CONTENTS — they name the env var and the path only (a path is not a secret). The decoded bytes
/// live in `Zeroizing` buffers and are never formatted, printed or returned in an error.
fn load_cosigner_master(path: &str) -> zeroize::Zeroizing<[u8; 32]> {
    let meta = std::fs::metadata(path).unwrap_or_else(|e| {
        die(format!(
            "{COSIGNER_KEYFILE_ENV}={path}: cannot stat co-signer key file: {e}"
        ))
    });
    if !meta.is_file() {
        die(format!("{COSIGNER_KEYFILE_ENV}={path}: not a regular file"));
    }
    // SECURITY: a world- or group-readable key file is the same class of bug this whole change
    // exists to remove, so it is REFUSED rather than warned about.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            die(format!(
                "{COSIGNER_KEYFILE_ENV}={path}: permissions are {mode:04o}; the co-signer key file \
                 must not be group- or world-readable. Run: chmod 600 {path}"
            ));
        }
    }
    let raw = zeroize::Zeroizing::new(std::fs::read_to_string(path).unwrap_or_else(|e| {
        die(format!(
            "{COSIGNER_KEYFILE_ENV}={path}: cannot read co-signer key file: {e}"
        ))
    }));
    let trimmed = raw.trim();
    let trimmed = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    // NOTE: the decode error is deliberately NOT propagated — `hex::FromHexError` renders the
    // offending character, which is key material.
    let bytes = zeroize::Zeroizing::new(hex::decode(trimmed).unwrap_or_else(|_| {
        die(format!(
            "{COSIGNER_KEYFILE_ENV}={path}: contents are not valid hex (expected >=32 bytes of \
             hex, optionally 0x-prefixed)"
        ))
    }));
    if bytes.len() < 32 {
        die(format!(
            "{COSIGNER_KEYFILE_ENV}={path}: only {} bytes of key material; at least 32 are \
             required (an empty or truncated key file is refused)",
            bytes.len()
        ));
    }
    // SECURITY: catches a placeholder file created by `truncate`, a device that reads as zeros, or
    // a hand-written file of `0000...` — all of which would otherwise "work" with a fixed key.
    if bytes.iter().all(|b| *b == 0) {
        die(format!(
            "{COSIGNER_KEYFILE_ENV}={path}: key material is all zeros; refusing to derive keys \
             from a placeholder"
        ));
    }
    let mut buf = Vec::with_capacity(KDF_MASTER_DOMAIN.len() + bytes.len());
    buf.extend_from_slice(KDF_MASTER_DOMAIN);
    buf.extend_from_slice(&bytes);
    let master = zeroize::Zeroizing::new(keccak_hash::keccak(&buf).0);
    zeroize::Zeroize::zeroize(&mut buf);
    master
}

/// Derive the 32-byte keygen seed for the public slot label `label` from the master secret.
///
/// SECURITY: Keccak-256 from `keccak-hash` (already this repo's hash in `falcon_sig`) — no
/// primitive is implemented from scratch. `KDF_SLOT_DOMAIN` separates this from the master
/// normalisation, and the fixed-width little-endian label makes distinct slots' preimages
/// unambiguous.
fn derive_key_seed(master: &[u8; 32], label: u64) -> zeroize::Zeroizing<[u8; 32]> {
    let mut buf = Vec::with_capacity(KDF_SLOT_DOMAIN.len() + 40);
    buf.extend_from_slice(KDF_SLOT_DOMAIN);
    buf.extend_from_slice(master);
    buf.extend_from_slice(&label.to_le_bytes());
    let seed = zeroize::Zeroizing::new(keccak_hash::keccak(&buf).0);
    zeroize::Zeroize::zeroize(&mut buf);
    seed
}

/// THE SINGLE BIRTH POINT of every `MemberKeys` in this binary.
///
/// `seed` is NO LONGER key material: under `KeyProvenance::Master` it is a PUBLIC SLOT LABEL fed
/// into the KDF, which is why the persisted `ControlledMember.keygen_seed` field keeps its `u64`
/// on-disk shape (no `cli_state.json` migration) while the actual secret moves out of the source
/// tree.
///
/// SECURITY (why this MUST stay the only constructor): the Phase-3 finding-7 incident was caused
/// by a SECOND derivation existing beside this one, so `export-reg-record` registered one member
/// set on L1 while `withdraw` proved against another. `cmd_gen_contribution` and the delegate-send
/// reconstruction used to call `MemberKeys::generate` inline for exactly that reason; they now go
/// through here. INVARIANT: every `MemberKeys::generate` hit in this file must be INSIDE this
/// function (currently two — one per provenance arm). A hit anywhere else is a second derivation
/// and must be rejected in review.
fn keys_for(seed: u64) -> MemberKeys {
    match key_provenance() {
        KeyProvenance::Master(master) => {
            MemberKeys::generate(&mut StdRng::from_seed(*derive_key_seed(master, seed)))
        }
        // SECURITY: reachable ONLY via an explicit `INTMAX_INSECURE_DETERMINISTIC_KEYS=1`, which
        // printed the banner in `key_provenance`. Publicly computable by construction.
        KeyProvenance::InsecureDeterministic => {
            MemberKeys::generate(&mut StdRng::seed_from_u64(seed))
        }
    }
}

/// The CLI's canonical keygen seed base for cosigner slots.
///
/// SECURITY (Phase-3 review finding 7, CLOSED in Phase 4): the CLI's Falcon identities used to
/// come from a SECOND derivation (`falcon_seed_for`) that lived beside `keys_for` and silently
/// disagreed with what `build_channel_withdrawal` derived, so `export-reg-record` registered one
/// member set on L1 while `withdraw` proved against another (fail-closed, but the channel became
/// unclosable). There is now ONE derivation: `keys_for(CLI_COSIGNER_SEED_BASE + slot)` produces a
/// `MemberKeys` whose OWN Falcon key is the identity every path uses — `close`, `cancel-close`,
/// `export-reg-record` and `withdraw` all read it off the same object, and
/// `build_channel_withdrawal` takes the `MemberKeys` rather than a seed slice.
///
/// SECURITY (CRITICAL, fixed): this constant used to BE the key material — `keys_for` seeded the
/// keygen RNG with it directly, so every co-signer's Falcon/BabyBear/Regev SECRET key of every
/// CLI- and API-driven channel was computable by anyone who could read this public repository.
/// That is full N-of-N custody of channel funds. It is now only a PUBLIC SLOT LABEL fed into a
/// KDF over an operator-provisioned external secret (see `key_provenance` / `keys_for`).
///
/// A code fix does NOT un-compromise channels created before it: their `pk_g` values are already
/// bound in `ChannelRecord.member_pk_gs` on L1 and in every signed snapshot. Those member sets
/// must be drained and retired operationally — see doc/tasks/cosigner-key-provenance.md §2.
pub(crate) const CLI_COSIGNER_SEED_BASE: u64 = 0xC1_0000;

// NOTE (detached close signing). Two helpers used to live here and are deleted:
//   * `cli_falcon_keys(active)` — refcounted handles on the CLI cosigners' Falcon SECRET keys,
//     derived by `close` and `cancel-close` so those commands could re-mint the N-of-N signature
//     set. They now consume the detached cosignatures the head state already carries, so NO
//     close-lifecycle path in this binary derives a signing key.
//   * `cli_cosigner_keys(active)` — its only caller.
// The surviving key derivations are `cli_members()` (channel genesis, which is legitimately the
// N members), the co-SIGNING commands (each holds the slots it controls, via
// `keys_for(c.keygen_seed)`), and `cli_active_keys()` (PUBLIC values for `export-reg-record` /
// `withdraw`). See doc/tasks/close-detached-signing-design.md.

/// The channel's ACTIVE participant key material in slot order for the close-lifecycle paths: the 3
/// CLI co-signing members (slots 0..3) FOLLOWED BY the delegate (slot 3). The delegate uses
/// `keys_for(DELEGATE_SEED)` — the SAME identity `gen-contribution <bal> <DELEGATE_SEED>` produces
/// — so the on-chain registration (member set + delegate) matches the channel state `init` builds.
/// `member_count = TEST_ACTIVE_MEMBERS = 3`, `delegate_count = 1` in the CHANNEL STATE. Used by
/// `export-reg-record` and `withdraw`, which under Option B register the COSIGNER slice only (L1
/// registration never carries delegates; the delegate is authenticated by the cosigner-signed H1
/// slot tree).
fn cli_active_keys() -> Vec<MemberKeys> {
    let mut v: Vec<MemberKeys> = cli_slots()
        .into_iter()
        .map(|slot| keys_for(CLI_COSIGNER_SEED_BASE + slot as u64))
        .collect();
    v.push(keys_for(delegate_seed()));
    v
}

/// The keygen LABEL of the DEMO delegate — the identity `gen-contribution <bal> <DELEGATE_SEED>`
/// produces. INTENTIONALLY SIMPLE: one reader, so `cli_active_keys` and the claim-identity
/// resolution below can never disagree about which label the demo delegate uses.
///
/// NOTE: a REAL browser delegate does NOT have a label here at all — it generates its own key with
/// `wallet_keygen` and the secret never leaves the browser. See `claim_keys_for_slot`.
fn delegate_seed() -> u64 {
    std::env::var("DELEGATE_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1)
}

fn member_info_for(slot: u16, keys: &MemberKeys) -> MemberInfo {
    MemberInfo {
        slot,
        pk_g: keys.pk_g(),
        pk_b: keys.pk_b(),
        regev_pk: keys.regev_pk.clone(),
    }
}

/// Env name of the per-slot GENESIS leaf-recipient override consumed by `create_channel`.
fn cosigner_recipient_env(slot: u16) -> String {
    format!("CLI_RECIPIENT_SLOT_{slot}")
}

/// The B-1b L1 exit address written into a CLI COSIGNER's genesis balance-slot leaf.
///
/// Default: `test_recipient_for(channel_id, slot)` — the canonical deterministic per-(channel,
/// slot) address, which is also what the on-chain registration record carries. It is SYNTHETIC:
/// nobody holds its key, so a claim credited to it can never be pulled (`claimWithdrawalCredit`
/// pays `msg.sender`). That is fine for every flow that never exercises the payout, and it is the
/// default here so no real address is baked into library/CLI code.
///
/// Opt-in override: `CLI_RECIPIENT_SLOT_<slot>=0x<20-byte address>` makes THAT slot's leaf a
/// caller-chosen exit address, so an end-to-end test (or a live deployment) can route a slot's
/// payout to a key it actually holds. Only the slot(s) named are affected; every other slot keeps
/// the default.
///
/// SECURITY: this override moves the recipient in the ONE place B-1b makes authoritative — the
/// cosigner-signed genesis balance-slot leaf, folded into H1 — so it WEAKENS NOTHING:
///   * every cosigner signs the genesis that carries it (an override that the other members did not
///     intend simply does not get signed / does not reproduce their expected state);
///   * `WithdrawalClaimWitness` still requires `member.l1_withdrawal_recipient ==
///     final_balance_state.recipients[member_index]`, and the circuit still opens the leaf, so a
///     claim can never name an address other than the signed leaf's;
///   * the payout still requires the recipient's own key (`claimWithdrawalCredit` credits
///     `withdrawalCredits[token][claim.recipient]` and pays `msg.sender`).
/// It is fail-closed: a set-but-unparsable or zero address aborts rather than silently falling
/// back to the default (a silent fallback would strand the payout at an unclaimable address —
/// exactly the failure this override exists to remove).
/// INTENTIONALLY SIMPLE: no channel scoping in the env name — the CLI already scopes everything it
/// does to `INTMAX_CHANNEL`, and genesis is written exactly once per channel.
fn cosigner_leaf_recipient(channel_id: u32, slot: u16) -> Address {
    let key = cosigner_recipient_env(slot);
    match std::env::var(&key) {
        Ok(raw) => {
            let addr = Address::from_hex(raw.trim())
                .unwrap_or_else(|e| die(format!("{key}: not a 20-byte L1 address ({e:?})")));
            if addr == Address::default() {
                die(format!(
                    "{key} is the zero address — REFUSING (B-1b: an active slot's exit address \
                     must be nonzero, and a zero recipient could never claim)"
                ));
            }
            eprintln!(
                "[init] slot {slot} genesis leaf recipient OVERRIDDEN to {} (via {key})",
                addr.to_hex()
            );
            addr
        }
        Err(_) => test_recipient_for(channel_id, slot as usize),
    }
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &str) -> T {
    let s = fs::read_to_string(path).unwrap_or_else(|e| die(format!("read {path}: {e}")));
    serde_json::from_str(&s).unwrap_or_else(|e| die(format!("parse {path}: {e}")))
}

/// Refuse symlink substitution and repair legacy overly-broad permissions before reading a file
/// that contains cosigner seeds or the base private witness.
fn secure_private_path(path: &Path) {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(error) => die(format!("inspect private file {}: {error}", path.display())),
    };
    if metadata.file_type().is_symlink() {
        die(format!(
            "REFUSING private file symlink {} (would expose or replace signing/base state)",
            path.display()
        ));
    }
    if !metadata.is_file() {
        die(format!(
            "private path {} is not a regular file",
            path.display()
        ));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap_or_else(|error| {
            die(format!(
                "private file {} is readable by other users and chmod 0600 failed: {error}",
                path.display()
            ))
        });
        eprintln!(
            "[state] SECURITY: repaired {} permissions to 0600",
            path.display()
        );
    }
}

/// One process at a time may observe and replace `cli_state.json` in a channel directory.
///
/// Atomic rename prevents a torn file, but it does not prevent the classic lost-update race:
/// process A can read an unfrozen state, process B can fsync a PREPARED settlement binding, and A
/// can then atomically replace the file with its older `settlement_binding: None`.  Every normal
/// CLI command takes this advisory lock before recovery or state reads, so the PREPARED join
/// freeze and all later mutations are serialized across processes as well as crash-safe.
#[cfg(unix)]
struct CliStateProcessLock(fs::File);

#[cfg(unix)]
impl CliStateProcessLock {
    fn acquire() -> Self {
        let path = Path::new(STATE_PROCESS_LOCK_FILE);
        secure_private_path(path);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .open(path)
            .unwrap_or_else(|error| {
                die(format!(
                    "open state process lock {STATE_PROCESS_LOCK_FILE}: {error}"
                ))
            });
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap_or_else(|error| {
            die(format!(
                "chmod 0600 state process lock {STATE_PROCESS_LOCK_FILE}: {error}"
            ))
        });
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            die(format!(
                "another channel_member process holds {STATE_PROCESS_LOCK_FILE}; refusing a concurrent state read/write"
            ));
        }
        Self(file)
    }
}

#[cfg(unix)]
impl Drop for CliStateProcessLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

#[cfg(not(unix))]
struct CliStateProcessLock;

#[cfg(not(unix))]
impl CliStateProcessLock {
    fn acquire() -> Self {
        die("channel_member requires an OS advisory file lock; this build target is unsupported")
    }
}

fn read_private_json<T: for<'de> Deserialize<'de>>(path: &str) -> T {
    secure_private_path(Path::new(path));
    read_json(path)
}

/// Crash-safe private-state writer: write a new 0600 inode, fsync it, atomically rename it, then
/// fsync the parent directory. A failed/partial write never truncates the last committed state.
fn write_private_json_at<T: Serialize>(path: &Path, value: &T) {
    let bytes = serde_json::to_vec(value).unwrap_or_else(|e| die(e));
    write_private_bytes_at(path, &bytes);
}

/// Crash-safe byte writer used for proof artifacts as well as JSON journals. The operation
/// journal must never point at a proof file that was only partially copied when the process died.
fn write_private_bytes_at(path: &Path, bytes: &[u8]) {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)
        .unwrap_or_else(|error| die(format!("create {}: {error}", parent.display())));
    secure_private_path(path);
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_else(|| die(format!("private path {} has no filename", path.display())));
    let temp = parent.join(format!(".{name}.tmp.{}", std::process::id()));
    if temp.exists() {
        secure_private_path(&temp);
        fs::remove_file(&temp)
            .unwrap_or_else(|error| die(format!("remove stale {}: {error}", temp.display())));
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(&temp)
        .unwrap_or_else(|error| die(format!("create private temp {}: {error}", temp.display())));
    file.write_all(&bytes)
        .unwrap_or_else(|error| die(format!("write private temp {}: {error}", temp.display())));
    file.sync_all()
        .unwrap_or_else(|error| die(format!("fsync private temp {}: {error}", temp.display())));
    drop(file);
    fs::rename(&temp, path).unwrap_or_else(|error| {
        die(format!(
            "atomic replace {} -> {}: {error}",
            temp.display(),
            path.display()
        ))
    });
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .unwrap_or_else(|error| die(format!("chmod 0600 {}: {error}", path.display())));
    FileSync::sync_directory(parent);
}

struct FileSync;

impl FileSync {
    fn sync_directory(path: &Path) {
        let directory = fs::File::open(path).unwrap_or_else(|error| {
            die(format!(
                "open directory {} for fsync: {error}",
                path.display()
            ))
        });
        directory
            .sync_all()
            .unwrap_or_else(|error| die(format!("fsync directory {}: {error}", path.display())));
    }
}

fn write_private_json<T: Serialize>(path: &str, value: &T) {
    write_private_json_at(Path::new(path), value);
}

// COMPACT (not pretty) on purpose: these files are wire/state artifacts, not human documents.
// Pretty-printing inflated a SlimSendPayload 1.41 MB → 4.5 MB (3.2×) and the 1016-member
// snapshot/cli_state ~3× — paid on EVERY upload, JSON parse, and CLI state load.
fn write_json<T: Serialize>(path: &str, value: &T) {
    // Public/wire artifacts need the same crash boundary as private state. A truncate/write gap
    // can otherwise leave `channel_snapshot.json` empty (or one head behind) after the
    // authoritative `cli_state.json` rename has committed. The 0600 mode is intentional: these
    // files are handed to the local relay/browser, not a world-readable filesystem consumer.
    write_private_json_at(Path::new(path), value);
}

/// Re-publish the authoritative private snapshot after a crash between the `cli_state.json` and
/// `channel_snapshot.json` renames. This command never signs or advances state; API recovery runs
/// it under the channel process/route locks before exposing `/snapshot` or `/backing`.
fn cmd_publish_snapshot(args: &[String]) {
    let out_path = args
        .get(1)
        .map(String::as_str)
        .unwrap_or("channel_snapshot.json");
    let state = load_state();
    verify_snapshot(&state.snapshot, None)
        .unwrap_or_else(|error| die(format!("refusing to publish invalid snapshot: {error}")));
    write_json(out_path, &state.snapshot);
    println!(
        "published snapshot {} at state {}",
        state.snapshot.state.digest, state.snapshot.state.balance_state.state_version
    );
}

fn inter_transfer_commit_dir() -> PathBuf {
    PathBuf::from("..").join(INTER_TRANSFER_COMMIT_DIR)
}

fn inter_transfer_channel_dir(channel_id: u64) -> PathBuf {
    PathBuf::from("..").join(format!("ch{channel_id}"))
}

fn inter_transfer_commit_path(tx_hash: Bytes32) -> PathBuf {
    let hex = tx_hash.to_hex();
    inter_transfer_commit_dir().join(format!("{}.json", hex.trim_start_matches("0x")))
}

fn inter_transfer_commit_checksum(journal: &InterTransferCommitJournal) -> Bytes32 {
    let bytes = serde_json::to_vec(journal)
        .unwrap_or_else(|e| die(format!("serialize inter-transfer commit journal: {e}")));
    Bytes32::from_bytes_be(&keccak_hash::keccak(bytes).0)
        .unwrap_or_else(|e| die(format!("inter-transfer journal checksum: {e:?}")))
}

fn write_inter_transfer_commit(path: &Path, journal: &InterTransferCommitJournal) {
    let directory = path.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(directory).unwrap_or_else(|e| {
        die(format!(
            "create inter-transfer journal directory {}: {e}",
            directory.display()
        ))
    });
    let metadata = fs::symlink_metadata(directory).unwrap_or_else(|e| {
        die(format!(
            "inspect inter-transfer journal directory {}: {e}",
            directory.display()
        ))
    });
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        die(format!(
            "inter-transfer journal path {} is not a real directory",
            directory.display()
        ));
    }
    #[cfg(unix)]
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap_or_else(|e| {
        die(format!(
            "chmod 0700 inter-transfer journal directory {}: {e}",
            directory.display()
        ))
    });
    let envelope = InterTransferCommitEnvelope {
        checksum: inter_transfer_commit_checksum(journal),
        journal: journal.clone(),
    };
    write_private_json_at(path, &envelope);
}

fn read_inter_transfer_commit(path: &Path) -> InterTransferCommitJournal {
    secure_private_path(path);
    let metadata = fs::metadata(path).unwrap_or_else(|e| {
        die(format!(
            "stat inter-transfer journal {}: {e}",
            path.display()
        ))
    });
    if metadata.len() > MAX_INTER_TRANSFER_JOURNAL_BYTES {
        die(format!(
            "inter-transfer journal {} is too large ({} bytes)",
            path.display(),
            metadata.len()
        ));
    }
    let bytes = fs::read(path).unwrap_or_else(|e| {
        die(format!(
            "read inter-transfer journal {}: {e}",
            path.display()
        ))
    });
    let envelope: InterTransferCommitEnvelope =
        serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            die(format!(
                "parse inter-transfer journal {}: {e}",
                path.display()
            ))
        });
    let expected = inter_transfer_commit_checksum(&envelope.journal);
    if envelope.checksum != expected {
        die(format!(
            "inter-transfer journal {} checksum mismatch — refusing partial/corrupt state",
            path.display()
        ));
    }
    validate_inter_transfer_commit(&envelope.journal);
    envelope.journal
}

fn validate_inter_transfer_commit(journal: &InterTransferCommitJournal) {
    if journal.magic != INTER_TRANSFER_COMMIT_MAGIC
        || journal.version != INTER_TRANSFER_COMMIT_VERSION
    {
        die("unsupported inter-transfer commit journal magic/version");
    }
    if journal.source_channel_id == journal.destination_channel_id
        || journal.result.a_head.channel_id.as_u64() != journal.source_channel_id
        || journal.result.b_fund_import_state.channel_id.as_u64() != journal.destination_channel_id
        || journal.result.b_bundle_apply_state.channel_id.as_u64() != journal.destination_channel_id
    {
        die("inter-transfer commit journal has inconsistent channel ids");
    }
    if journal.result.a_head.prev_digest != journal.source_before_digest
        || journal.result.b_fund_import_state.prev_digest != journal.destination_before_digest
        || journal.result.b_bundle_apply_state.prev_digest
            != journal.result.b_fund_import_state.digest
        || journal.source_after.snapshot.state.digest != journal.result.a_head.digest
        || journal.destination_after.snapshot.state.digest
            != journal.result.b_bundle_apply_state.digest
        || journal.result.b_snapshot.state.digest != journal.result.b_bundle_apply_state.digest
    {
        die("inter-transfer commit journal breaks the prepared digest chain");
    }
    if !journal
        .source_after
        .spent_tx_identities
        .contains(&journal.replay_identity)
        || !journal
            .destination_after
            .applied_tx_identities
            .contains(&journal.replay_identity)
    {
        die("inter-transfer commit journal omits a required replay-ledger entry");
    }
    verify_all_signatures(
        &journal.source_after.snapshot.record,
        &journal.source_after.snapshot.members,
        &journal.result.a_head,
    )
    .unwrap_or_else(|e| die(format!("inter-transfer journal source signature gate: {e}")));
    verify_all_signatures(
        &journal.destination_after.snapshot.record,
        &journal.destination_after.snapshot.members,
        &journal.result.b_fund_import_state,
    )
    .unwrap_or_else(|e| {
        die(format!(
            "inter-transfer journal fund-import signature gate: {e}"
        ))
    });
    verify_all_signatures(
        &journal.destination_after.snapshot.record,
        &journal.destination_after.snapshot.members,
        &journal.result.b_bundle_apply_state,
    )
    .unwrap_or_else(|e| die(format!("inter-transfer journal bundle signature gate: {e}")));
}

fn read_cli_state_at(dir: &Path) -> CliState {
    let path = dir.join(STATE_FILE);
    secure_private_path(&path);
    let bytes = fs::read(&path)
        .unwrap_or_else(|e| die(format!("read channel state {}: {e}", path.display())));
    let state: CliState = serde_json::from_slice(&bytes)
        .unwrap_or_else(|e| die(format!("parse channel state {}: {e}", path.display())));
    if state.state_schema_version != STATE_SCHEMA_VERSION {
        die(format!(
            "channel state {} has schema version {}, but two-channel recovery requires exact v{} \
             security-ledger semantics; migrate it in its own channel directory first",
            path.display(),
            state.state_schema_version,
            STATE_SCHEMA_VERSION
        ));
    }
    validate_signing_security_state(&state).unwrap_or_else(|error| {
        die(format!(
            "channel state {} has an invalid signing ledger: {error}",
            path.display()
        ))
    });
    state
}

fn persist_cli_state_at(dir: &Path, state: &CliState) {
    validate_signing_security_state(state).unwrap_or_else(|error| {
        die(format!(
            "refusing to persist invalid signing ledger: {error}"
        ))
    });
    write_private_json_at(&dir.join(STATE_FILE), state);
    write_private_json_at(&dir.join("channel_snapshot.json"), &state.snapshot);
}

fn remove_inter_transfer_commit(path: &Path) {
    fs::remove_file(path)
        .unwrap_or_else(|e| die(format!("remove completed journal {}: {e}", path.display())));
    FileSync::sync_directory(path.parent().unwrap_or(Path::new(".")));
}

fn roll_forward_inter_transfer_commit(path: &Path, journal: &mut InterTransferCommitJournal) {
    let source_dir = inter_transfer_channel_dir(journal.source_channel_id);
    let destination_dir = inter_transfer_channel_dir(journal.destination_channel_id);
    let source_current = read_cli_state_at(&source_dir);
    let destination_current = read_cli_state_at(&destination_dir);
    let source_digest = source_current.snapshot.state.digest;
    let destination_digest = destination_current.snapshot.state.digest;
    if source_digest != journal.source_before_digest
        && source_digest != journal.source_after.snapshot.state.digest
    {
        die(format!(
            "cannot recover inter-transfer {}: source head is neither before nor prepared after",
            journal.tx_hash
        ));
    }
    if destination_digest != journal.destination_before_digest
        && destination_digest != journal.destination_after.snapshot.state.digest
    {
        die(format!(
            "cannot recover inter-transfer {}: destination head is neither before nor prepared after",
            journal.tx_hash
        ));
    }

    // Idempotent roll-forward. Every individual replacement is atomic; the PREPARED journal stays
    // durable until both channel files, both snapshots and both public recovery artifacts do.
    persist_cli_state_at(&source_dir, &journal.source_after);
    // Release-only crash testing still needs to exercise the real fsync/rename boundary. Keep the
    // failpoint unreachable under production key provenance so an operator-controlled environment
    // variable can never deliberately strand a live transfer half-applied.
    if std::env::var("INTMAX_TEST_FAIL_INTER_TRANSFER_AFTER_SOURCE").as_deref() == Ok("1") {
        let insecure = std::env::var(INSECURE_KEYS_ENV).as_deref() == Ok("1");
        let production_keyfile = std::env::var_os(COSIGNER_KEYFILE_ENV).is_some();
        if !insecure || production_keyfile {
            die(
                "REFUSING inter-transfer crash failpoint outside the explicit insecure-test key \
                 provenance",
            );
        }
        die("TEST FAILPOINT: source committed; PREPARED journal retained for roll-forward");
    }
    persist_cli_state_at(&destination_dir, &journal.destination_after);
    write_private_json_at(&source_dir.join("inter_transfer.json"), &journal.result);
    write_private_json_at(
        &destination_dir.join("incoming_inter_transfer.json"),
        &journal.result,
    );

    journal.phase = InterTransferCommitPhase::Committed;
    write_inter_transfer_commit(path, journal);
    remove_inter_transfer_commit(path);
}

fn recover_pending_inter_transfers() {
    let directory = inter_transfer_commit_dir();
    let metadata = match fs::symlink_metadata(&directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(error) => die(format!(
            "inspect inter-transfer journal directory {}: {error}",
            directory.display()
        )),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        die(format!(
            "inter-transfer journal path {} is not a real directory",
            directory.display()
        ));
    }
    let mut paths: Vec<PathBuf> = fs::read_dir(&directory)
        .unwrap_or_else(|e| die(format!("read inter-transfer journal directory: {e}")))
        .map(|entry| {
            entry
                .unwrap_or_else(|e| die(format!("read inter-transfer journal entry: {e}")))
                .path()
        })
        .collect();
    paths.sort();
    if paths.len() > MAX_INTER_TRANSFER_JOURNALS {
        die(format!(
            "too many inter-transfer recovery journals ({} > {})",
            paths.len(),
            MAX_INTER_TRANSFER_JOURNALS
        ));
    }
    for path in paths {
        let mut journal = read_inter_transfer_commit(&path);
        match journal.phase {
            InterTransferCommitPhase::Prepared => {
                roll_forward_inter_transfer_commit(&path, &mut journal)
            }
            InterTransferCommitPhase::Committed => remove_inter_transfer_commit(&path),
        }
    }
}

/// Read `cli_state.json` as a JSON object, or die. Shared by `load_state` and `migrate-state` so
/// both see exactly the same bytes and the same key set.
fn read_state_object() -> serde_json::Map<String, serde_json::Value> {
    secure_private_path(Path::new(STATE_FILE));
    let text =
        fs::read_to_string(STATE_FILE).unwrap_or_else(|e| die(format!("read {STATE_FILE}: {e}")));
    let raw: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|e| die(format!("parse {STATE_FILE}: {e}")));
    match raw {
        serde_json::Value::Object(m) => m,
        _ => die(format!(
            "{STATE_FILE} is not a JSON object — refusing to guess its shape"
        )),
    }
}

/// Load the CLI state, FAILING LOUDLY if any replay ledger is absent from the file.
///
/// SECURITY (deposit-import-threat-model.md §10.8 finding 2 — the reason this is not a one-line
/// `read_json`): the ledgers behind `cosign-inter-transfer`'s double-debit refusal, the credit
/// refusal, and the L1 deposit-import replay refusal are ONLY as good as their contents. While
/// they were `#[serde(default)]`, a file written by a build that lacked or differently-named a key
/// deserialized to an EMPTY set, and every refusal built on it passed VACUOUSLY — with no
/// diagnostic anywhere. The failure mode was invisible by construction, and it had already
/// occurred once (the `applied_tx_hashes` → `applied_tx_identities` rename).
///
/// So absence is now a hard, explanatory error, and the only way past it is the DELIBERATE
/// `migrate-state` command, which makes the operator acknowledge in the command line itself that
/// they are creating an empty ledger.
fn load_state() -> CliState {
    let obj = read_state_object();

    // 1. VERSION GATE. A file from a NEWER build may encode a ledger in a shape this build cannot
    //    read; silently loading it would be the same vacuity in the other direction.
    let version: u32 = match obj.get("state_schema_version") {
        None => 0,
        Some(v) => v
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .unwrap_or_else(|| die(format!("{STATE_FILE}: state_schema_version is not a u32"))),
    };
    if version > STATE_SCHEMA_VERSION {
        die(format!(
            "{STATE_FILE} was written by a NEWER build (state_schema_version {version} > \
             {STATE_SCHEMA_VERSION} understood here). Refusing to load it: a ledger this build \
             cannot read is a ledger this build would silently treat as empty. Fail-closed."
        ));
    }

    // 2. LEDGER PRESENCE, by name. This is the check the `#[serde(default)]`s used to swallow.
    let missing: Vec<&str> = REQUIRED_LEDGER_KEYS
        .iter()
        .copied()
        .filter(|k| !obj.contains_key(*k))
        .collect();
    if !missing.is_empty() {
        let signing_missing = missing.contains(&STATE_SIGNING_LEDGER_KEY);
        die(format!(
            "REFUSING to load {STATE_FILE}: the SECURITY/REPLAY LEDGER key(s) {missing:?} are \
             ABSENT.\n\
             Replay ledgers prevent repeated transfers/deposits; `{STATE_SIGNING_LEDGER_KEY}` \
             prevents one member key from signing sibling channel states. Treating an absent key \
             as empty would silently disable the corresponding refusal.\n\
             Run `channel_member migrate-state` only if this file genuinely pre-dates the missing \
             ledger(s). Missing replay ledgers require \
             --i-understand-this-resets-replay-ledgers; missing anti-equivocation state requires \
             --i-understand-this-resets-anti-equivocation-ledger{} .\n\
             Otherwise restore the state file that has them. Fail-closed.",
            if signing_missing {
                ""
            } else {
                " (not needed for this file)"
            }
        ));
    }

    if !obj.contains_key(SETTLEMENT_BINDING_KEY) {
        die(format!(
            "REFUSING to load {STATE_FILE}: `{SETTLEMENT_BINDING_KEY}` is ABSENT. Treating an \
             unknown settlement state as unfrozen would let a new delegate join after the L1 \
             participant root was fixed. Run `channel_member migrate-state` in the original \
             channel directory; migration refuses if settlement.json already records a deploy."
        ));
    }

    // 3. STRICT deserialization. `deny_unknown_fields` turns a ledger that is present under an OLD
    //    name into a hard error too, instead of an ignored key plus an empty set.
    let mut state: CliState = serde_json::from_value(serde_json::Value::Object(obj))
        .unwrap_or_else(|e| die(format!("parse {STATE_FILE}: {e}")));

    if version < STATE_SCHEMA_VERSION {
        // OBSERVABLE, not silent: the file is accepted on the strength of the presence check
        // above, and says so.
        eprintln!(
            "[state] SECURITY NOTE: {STATE_FILE} pre-dates schema versioning \
             (state_schema_version {version} < {STATE_SCHEMA_VERSION}). Accepted because all \
             {} security ledgers are PRESENT; it will be stamped v{STATE_SCHEMA_VERSION} on the \
             next save.",
            REQUIRED_LEDGER_KEYS.len()
        );
    }
    state.state_schema_version = STATE_SCHEMA_VERSION;
    validate_signing_security_state(&state)
        .unwrap_or_else(|error| die(format!("{STATE_FILE}: invalid signing ledger: {error}")));
    state
}

fn save_state(state: &CliState) {
    // The version stamp is forced by `serialize_current_schema_version`, so no writer can forget
    // it and no file can be written back claiming an older schema than it has.
    validate_signing_security_state(state)
        .unwrap_or_else(|error| die(format!("refusing to save invalid signing ledger: {error}")));
    write_private_json(STATE_FILE, state);
    // A state becomes reusable settlement authority exactly when it carries the complete N-of-N
    // signature set. Pay the Falcon aggregation cost ONCE at that boundary, never later in the
    // close/PW/cancel race. The digest-keyed cache makes repeat saves idempotent. A deployment may
    // disable this only when its long-lived prover service has taken responsibility for invoking
    // `precompute-falcon-aggregate` asynchronously; silently disabling it is not the default.
    // detail2 §R invariant (2): the sig-cluster's N/N plonky2 aggregate proof is a SETTLEMENT
    // artifact — close / cancel-close / partial-withdrawal build it (via `cache_falcon_aggregate`,
    // which proves on a cache miss), and nothing else needs it. The per-finalization precompute
    // below is therefore OPT-IN (a deployment that wants the artifact pre-warmed sets
    // INTMAX_FALCON_AGG_PRECOMPUTE=1; it runs detached, digest-keyed, idempotent). The default is
    // LAZY: no plonky2 proving happens outside the settlement paths.
    let is_finalized =
        state.snapshot.state.member_signatures.len() == state.snapshot.record.member_count as usize;
    let prewarm_opted_in = std::env::var("INTMAX_FALCON_AGG_PRECOMPUTE").as_deref() == Ok("1");
    if is_finalized && prewarm_opted_in {
        spawn_detached_falcon_precompute(state.snapshot.state.digest);
    }
}

/// Resolve settlement authority from the crash-safe channel state, never from a convenience JSON
/// file or a caller-supplied address alone.  Every close/claim/withdraw command calls this before
/// proving or broadcasting, so a stale `settlement.json`, copied CLI argument, or local path mixup
/// cannot redirect a valid proof or channel funds to a different manager/verifier/rollup.
fn require_active_settlement_binding(
    rpc: &str,
    supplied_manager: &str,
    supplied_verifier: Option<&str>,
    supplied_rollup: Option<&str>,
) -> SettlementBinding {
    let state = load_state();
    let binding = state
        .settlement_binding
        .clone()
        .unwrap_or_else(|| die("no durable settlement binding; run deploy-settlement first"));
    if binding.status != SettlementBindingStatus::Active {
        die("settlement binding is PREPARED, not ACTIVE; refusing every close/fund-moving route");
    }
    let manager = binding
        .manager
        .as_deref()
        .unwrap_or_else(|| die("ACTIVE settlement binding has no manager"));
    let verifier = binding
        .verifier
        .as_deref()
        .unwrap_or_else(|| die("ACTIVE settlement binding has no verifier"));
    let materializer = binding
        .materializer
        .as_deref()
        .unwrap_or_else(|| die("ACTIVE settlement binding has no close-funding materializer"));
    let parsed_materializer = Address::from_hex(materializer).unwrap_or_else(|error| {
        die(format!(
            "invalid durable close-funding materializer: {error:?}"
        ))
    });
    if parsed_materializer == Address::default() {
        die("ACTIVE settlement binding has the zero close-funding materializer");
    }
    if strip0x(manager) != strip0x(supplied_manager) {
        die(format!(
            "supplied manager {supplied_manager} differs from durable ACTIVE manager {manager}"
        ));
    }
    if supplied_verifier.is_some_and(|value| strip0x(value) != strip0x(verifier)) {
        die(format!(
            "supplied settlement verifier {:?} differs from durable ACTIVE verifier {verifier}",
            supplied_verifier
        ));
    }
    if supplied_rollup.is_some_and(|value| strip0x(value) != strip0x(&binding.rollup)) {
        die(format!(
            "supplied rollup {:?} differs from durable ACTIVE rollup {}",
            supplied_rollup, binding.rollup
        ));
    }

    // Member-set updates are fail-closed in this release. Therefore the deployed participant
    // root/count must still equal the live signed snapshot on every use; any accidental local
    // mutation after deployment is detected before it can construct an L1 proof/call.
    let reg = build_live_settlement_reg_record(&state);
    let (participant_root, participant_count) = staged_settlement_identity(&reg);
    if binding.channel_id != channel_id_env()
        || binding.participant_root != participant_root
        || binding.participant_count != participant_count
    {
        die("live signed participant identity differs from the durable ACTIVE settlement binding");
    }

    let chain_id = rpc_chain_id(rpc);
    if chain_id != DEVNET_CHAIN_ID {
        let deployment = binding.deployment.as_ref().unwrap_or_else(|| {
            die(
                "production ACTIVE settlement has no pinned deployment intent; legacy state is \
                 not trusted for fund-moving operations",
            )
        });
        let checkpoint = binding.activation_checkpoint.as_ref().unwrap_or_else(|| {
            die(
                "production ACTIVE settlement has no finalized activation checkpoint; legacy \
                 state is not trusted for fund-moving operations",
            )
        });
        if deployment.chain_id != chain_id || checkpoint.chain_id != chain_id {
            die("ACTIVE settlement deployment/checkpoint belongs to a different RPC chain");
        }
        let current = revalidate_l1_checkpoint(rpc, checkpoint);
        let expected_hashes = binding.runtime_code_hashes.as_ref().unwrap_or_else(|| {
            die(
                "production ACTIVE settlement has no pinned runtime code hashes; legacy state is \
                 not trusted for fund-moving operations",
            )
        });
        require_settlement_runtime_code_hashes_at(
            rpc,
            &binding.rollup,
            verifier,
            manager,
            materializer,
            expected_hashes,
            current.block_number,
        );
        let bound_materializer = cast_call_at(
            rpc,
            manager,
            "closeFundingMaterializer()(address)",
            &[],
            current.block_number,
        );
        if strip0x(&bound_materializer) != strip0x(materializer) {
            die(format!(
                "settlement manager is bound to close-funding materializer {bound_materializer}, \
                 not durable ACTIVE materializer {materializer}"
            ));
        }
        let materializer_rollup = cast_call_at(
            rpc,
            materializer,
            "rollup()(address)",
            &[],
            current.block_number,
        );
        if strip0x(&materializer_rollup) != strip0x(&binding.rollup) {
            die(format!(
                "close-funding materializer is bound to rollup {materializer_rollup}, not durable \
                 ACTIVE rollup {}",
                binding.rollup
            ));
        }
        require_stable_durable_l1_checkpoint(rpc, &current);
    } else if binding.deployment.is_some()
        || binding.activation_checkpoint.is_some()
        || binding.runtime_code_hashes.is_some()
    {
        die("devnet ACTIVE settlement unexpectedly carries production deployment authority");
    }
    binding
}

/// Keyless/read-only projection of the durable ACTIVE settlement authority for the API daemon.
/// This deliberately reuses the exact gate every fund-moving CLI command calls: the convenience
/// `settlement.json` file is not sufficient authority, and on production chains the persisted L1
/// activation checkpoint is revalidated before anything is printed.
fn cmd_verify_settlement_binding(args: &[String]) {
    let manager = args.get(1).unwrap_or_else(|| {
        die("verify-settlement-binding needs <manager> <rpc_url> <rollup> <verifier>")
    });
    let rpc = args.get(2).unwrap_or_else(|| {
        die("verify-settlement-binding needs <manager> <rpc_url> <rollup> <verifier>")
    });
    let rollup = args.get(3).unwrap_or_else(|| {
        die("verify-settlement-binding needs <manager> <rpc_url> <rollup> <verifier>")
    });
    let verifier = args.get(4).unwrap_or_else(|| {
        die("verify-settlement-binding needs <manager> <rpc_url> <rollup> <verifier>")
    });
    let binding = require_active_settlement_binding(rpc, manager, Some(verifier), Some(rollup));
    println!(
        "{}",
        serde_json::json!({
            "schemaVersion": 1,
            "status": "active",
            "chainId": rpc_chain_id(rpc),
            "channelId": binding.channel_id,
            "snapshotStateDigest": binding.snapshot_state_digest,
            "participantRoot": binding.participant_root,
            "participantCount": binding.participant_count,
            "rollup": binding.rollup,
            "manager": binding.manager,
            "verifier": binding.verifier,
            "closeFundingMaterializer": binding.materializer,
            "activationCheckpoint": binding.activation_checkpoint,
            "runtimeCodeHashes": binding.runtime_code_hashes,
        })
    );
}

/// Kick off `precompute-falcon-aggregate` as a DETACHED child of this binary and return at once.
///
/// PERF: the Falcon aggregate proof itself is ~0.1 s, but `FalconProverContext::new()` builds the
/// Plonky2 batch circuit (~2 s wall) and every CLI invocation is a fresh process, so running the
/// precompute inline put ~2 s on the critical path of EVERY co-sign that finalized a state — pure
/// latency for the user, with no bearing on the co-sign's correctness (the signature is already
/// complete; the aggregate is only consumed by close/PW/cancel, which fall back to computing it
/// on demand). The digest-keyed cache is idempotent and written atomically (tmp + rename), so a
/// detached child racing a later settlement is safe: whichever finishes first wins and the other
/// finds a valid artifact. If the child fails, the settlement path regenerates the artifact
/// (`cache_falcon_aggregate` falls through to `prove_finalized_state`), so nothing is lost —
/// only the precompute's latency benefit. Inherits cwd + env (INTMAX_CHANNEL, key provenance).
fn spawn_detached_falcon_precompute(digest: Bytes32) {
    spawn_detached_falcon_precompute_in(digest, std::path::Path::new("."));
}

/// `work_dir` is the channel directory holding `cli_state.json` and the cache; the child runs
/// there. Returns whether a child was actually spawned (false = cached / unavailable).
fn spawn_detached_falcon_precompute_in(digest: Bytes32, work_dir: &std::path::Path) -> bool {
    // Already cached (idempotent re-save of the same head): nothing to do, don't even fork.
    if work_dir.join(falcon_aggregate_path(digest)).is_file() {
        return false;
    }
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "[falcon-aggregate] cannot locate own binary ({e}); precompute deferred to settlement"
            );
            return false;
        }
    };
    match std::process::Command::new(exe)
        .arg("precompute-falcon-aggregate")
        // The parent already holds the channel-wide process lock until this command exits.  The
        // detached precompute only reads one atomic snapshot and writes a digest-keyed cache file;
        // it never mutates cli_state.json, so it may safely bypass that lock (and the mutation
        // recovery pass) instead of racing the parent and immediately failing.
        .env(DETACHED_PRECOMPUTE_LOCK_BYPASS_ENV, "1")
        .current_dir(work_dir)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(_child) => {
            // Dropping the handle detaches: the child is reparented on exit and finishes on its
            // own.
            eprintln!("[falcon-aggregate] precompute for state {digest} running detached");
            true
        }
        Err(e) => {
            eprintln!("[falcon-aggregate] spawn failed ({e}); precompute deferred to settlement");
            false
        }
    }
}

fn falcon_aggregate_path(state_digest: Bytes32) -> std::path::PathBuf {
    std::path::Path::new(FALCON_AGG_CACHE_DIR).join(format!(
        "{}.bin",
        state_digest.to_hex().trim_start_matches("0x")
    ))
}

/// Load-or-create the state-scoped Falcon artifact and verify it against the current circuit before
/// returning it. Corrupt or stale bytes are never trusted; they are replaced from the authentic
/// N-of-N signatures still carried by the finalized state.
fn cache_falcon_aggregate(
    ctx: &FalconProverContext,
    record: &ChannelRecord,
    state: &ChannelState,
) -> Result<FalconAggregateProofArtifact, String> {
    let path = falcon_aggregate_path(state.digest);
    if path.is_file() {
        match fs::read(&path)
            .map_err(|e| e.to_string())
            .and_then(|b| FalconAggregateProofArtifact::from_bytes(&b).map_err(|e| e.to_string()))
            .and_then(|a| {
                ctx.verify_finalized_state_artifact(record, state, &a)
                    .map_err(|e| e.to_string())?;
                Ok(a)
            }) {
            Ok(artifact) => return Ok(artifact),
            Err(e) => eprintln!(
                "[falcon-aggregate] cached artifact {} rejected ({e}); regenerating from the finalized signatures",
                path.display()
            ),
        }
    }

    let artifact = ctx
        .prove_finalized_state(record, state)
        .map_err(|e| e.to_string())?;
    let bytes = artifact.to_bytes().map_err(|e| e.to_string())?;
    fs::create_dir_all(FALCON_AGG_CACHE_DIR).map_err(|e| e.to_string())?;
    let tmp = path.with_extension(format!("bin.tmp.{}", std::process::id()));
    fs::write(&tmp, bytes).map_err(|e| e.to_string())?;
    fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
    eprintln!(
        "[falcon-aggregate] cached state {} → {}",
        state.digest,
        path.display()
    );
    Ok(artifact)
}

fn cmd_precompute_falcon_aggregate() {
    let state = load_state();
    let ctx = FalconProverContext::new();
    let artifact = cache_falcon_aggregate(&ctx, &state.snapshot.record, &state.snapshot.state)
        .unwrap_or_else(|e| die(format!("precompute-falcon-aggregate: {e}")));
    println!(
        "precompute-falcon-aggregate OK: state {} members {} proof {} bytes",
        artifact.state_digest,
        artifact.member_count,
        artifact.proof.len()
    );
}

/// ONE-TIME, EXPLICIT migration for a `cli_state.json` written before a replay ledger existed.
///
/// SECURITY: this is the deliberate path that replaces the old silent `#[serde(default)]`. It
/// creates the absent ledger(s) EMPTY — exactly what the default used to do — but it (a) requires
/// the operator to type an acknowledgement that names the consequence, (b) reports precisely which
/// ledgers were created and what becomes replayable, and (c) REFUSES if the file carries any
/// unrecognised key, because an unrecognised key is the signature of a ledger that was RENAMED and
/// whose entries would be thrown away — the incident that motivated all of this.
/// detail2 §Q stage Q1 — the member-set update command (audit25-08-2026 Part 3 V1's gate,
/// `ChannelSafetyQ.lean`'s verified shape). Two ops:
///
///   member-update rotate <slot> <new_keygen_seed>
///   member-update add <joiner_keygen_seed> <recipient_hex>
///
/// Single atomic command in the deployment's key model (this CLI holds every cluster slot's key
/// via `keys_for`, exactly as `cosign`/`join_delegate` do): it proposes (IMKR/IMJC consent),
/// collects the PREVIOUS set's full N-of-N over IMMS, runs `verify_member_set_update` — the same
/// fail-closed gate a remote co-signer would run — applies the §Q-4b state advance, has the NEW
/// set re-sign the state, and persists. The gate is NEVER bypassed: a forged consent, a wrong
/// version, or a structural delta beyond the op dies here exactly as in the Lean model
/// (rotate_requires_self_consent / update_requires_prev_nofn).
///
/// SECURITY (key provenance): the new key comes from `keys_for(new_seed)` — the file's single
/// derivation (finding-7 invariant). The rotated slot's `ControlledMember.keygen_seed` is updated
/// so every later `cosign`/`close` signs with the NEW key; the old seed's key simply stops being
/// referenced (the record no longer contains its pk_g — `rotate_sets_new_key`).
fn cmd_member_update(_args: &[String]) {
    die(
        "member-update is retired; close the old channel by unanimous consent and migrate all assets and commitments into a newly registered channel",
    );
}

/// Deprecated audit-only implementation; excluded from every default/release build.
#[cfg(feature = "deprecated-msu")]
#[allow(dead_code, deprecated)]
fn cmd_member_update_future(args: &[String]) {
    let sub = args
        .get(1)
        .map(String::as_str)
        .unwrap_or_else(|| die("member-update <rotate|add> ..."));
    let mut state = load_state();
    let record = state.snapshot.record.clone();
    let members = state.snapshot.members.clone();

    let (update, new_controlled_seed_change): (
        intmax3_zkp::wallet_core::deprecated_member_set_update::MemberSetUpdate,
        Option<(u16, u64)>,
    ) = match sub {
        "rotate" => {
            let slot: u16 = args
                .get(2)
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| die("member-update rotate <slot> <new_keygen_seed>"));
            let new_seed: u64 = args
                .get(3)
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| die("member-update rotate <slot> <new_keygen_seed>"));
            let ctl = state
                .controlled
                .iter()
                .find(|c| c.slot == slot)
                .unwrap_or_else(|| die(format!("slot {slot} is not a controlled member slot")));
            let current_keys = keys_for(ctl.keygen_seed);
            let new_keys = keys_for(new_seed);
            if new_keys.pk_g() == current_keys.pk_g() {
                die(
                    "member-update rotate: the new seed derives the CURRENT key — refusing a no-op rotation",
                );
            }
            let update =
                propose_rotate_key(&current_keys, &new_keys, &record, &members, slot as u8)
                    .unwrap_or_else(|e| die(format!("propose rotate: {e}")));
            (update, Some((slot, new_seed)))
        }
        "add" => {
            let joiner_seed: u64 = args
                .get(2)
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| die("member-update add <joiner_keygen_seed> <recipient_hex>"));
            let recipient = args
                .get(3)
                .map(|s| Address::from_hex(s).unwrap_or_else(|e| die(format!("recipient: {e:?}"))))
                .unwrap_or_else(|| die("member-update add <joiner_keygen_seed> <recipient_hex>"));
            // B-1b: recipient must be distinct across active slots (same guard as join_delegate).
            {
                let bs = &state.snapshot.state.balance_state;
                let active = bs.member_count as usize + bs.delegate_count as usize;
                if (0..active).any(|i| bs.recipients[i] == recipient) {
                    die("member-update add: recipient already bound to an active slot (B-1b)");
                }
            }
            let joiner_keys = keys_for(joiner_seed);
            let update = propose_add_cosigner(&joiner_keys, recipient, &record, &members)
                .unwrap_or_else(|e| die(format!("propose add: {e}")));
            (update, Some((record.member_count as u16, joiner_seed)))
        }
        other => die(format!("member-update: unknown op {other:?} (rotate|add)")),
    };

    // The PREVIOUS set's full N-of-N over the IMMS digest — every cluster slot votes.
    let mut update = update;
    update.member_signatures = state
        .controlled
        .iter()
        .filter(|c| (c.slot as usize) < record.member_count as usize)
        .map(|c| cosign_member_set_update(&keys_for(c.keygen_seed), c.slot as u8, &update))
        .collect();

    // THE gate — identical to what a remote co-signer runs; never bypassed.
    let (new_record, new_members) = verify_member_set_update(&record, &members, &update)
        .unwrap_or_else(|e| die(format!("member-set update REFUSED: {e}")));

    // §Q-4b state advance (rotate: rows untouched; add: zero row inserted, delegates shift).
    let mut next_state = apply_member_set_update_to_state(&state.snapshot.state, &record, &update)
        .unwrap_or_else(|e| die(format!("apply member-set update: {e}")));

    // Bookkeeping: rotated slot's controlled seed moves to the new key; an added member becomes a
    // controlled slot; delegates' controlled slots shift up by one on add.
    match &new_controlled_seed_change {
        Some((slot, seed)) if sub == "rotate" => {
            for c in state.controlled.iter_mut() {
                if c.slot == *slot {
                    c.keygen_seed = *seed;
                }
            }
        }
        Some((slot, seed)) => {
            for c in state.controlled.iter_mut() {
                if c.slot >= *slot {
                    c.slot += 1; // §Q-4b: delegates shift up
                }
            }
            state.controlled.push(ControlledMember {
                slot: *slot,
                keygen_seed: *seed,
                balance_amount: 0,
                balance_seed: 0,
                has_witness: false,
                token_witnesses: Vec::new(),
            });
            state.controlled.sort_by_key(|c| c.slot);
        }
        None => unreachable!(),
    }

    // The NEW set re-signs the advanced state (the rotated/added key signs as itself now).
    next_state = next_state.with_computed_digest();
    for c in &state.controlled {
        if (c.slot as usize) < new_record.member_count as usize {
            let sig = sign_state(&keys_for(c.keygen_seed), c.slot as u8, &next_state)
                .unwrap_or_else(|e| die(format!("re-sign: {e:?}")));
            add_signature(&mut next_state, sig);
        }
    }

    state.snapshot.record = new_record.clone();
    state.snapshot.members = new_members;
    state.snapshot.state = next_state;
    save_state(&state);
    write_json("channel_snapshot.json", &state.snapshot);
    println!(
        "member-update {sub} OK: set_version {} member_count {} (registered root advanced)",
        new_record.set_version, new_record.member_count
    );
}

fn cmd_migrate_state(args: &[String]) {
    const REPLAY_ACK: &str = "--i-understand-this-resets-replay-ledgers";
    const SIGNING_ACK: &str = "--i-understand-this-resets-anti-equivocation-ledger";
    let replay_acked = args.iter().any(|a| a == REPLAY_ACK);
    let signing_acked = args.iter().any(|a| a == SIGNING_ACK);

    let mut obj = read_state_object();
    let known: [&str; 4] = [
        "state_schema_version",
        "controlled",
        "snapshot",
        SETTLEMENT_BINDING_KEY,
    ];
    let unknown: Vec<&String> = obj
        .keys()
        .filter(|k| !known.contains(&k.as_str()) && !REQUIRED_LEDGER_KEYS.contains(&k.as_str()))
        .collect();
    if !unknown.is_empty() {
        die(format!(
            "REFUSING to migrate {STATE_FILE}: unrecognised key(s) {unknown:?}. An unknown key is \
             how a RENAMED security ledger looks from here, and migrating would silently discard \
             its entries. Reconcile the file by hand. Fail-closed."
        ));
    }

    let missing: Vec<&str> = REQUIRED_LEDGER_KEYS
        .iter()
        .copied()
        .filter(|k| !obj.contains_key(*k))
        .collect();
    let missing_signing = missing.contains(&STATE_SIGNING_LEDGER_KEY);
    let missing_exit_kit_receipt = missing.contains(&SIGNER_EXIT_KIT_RECEIPT_KEY);
    let missing_replay: Vec<&str> = missing
        .iter()
        .copied()
        .filter(|key| {
            *key != STATE_SIGNING_LEDGER_KEY && *key != SIGNER_EXIT_KIT_RECEIPT_KEY
        })
        .collect();
    let stale_version = obj
        .get("state_schema_version")
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
        < u64::from(STATE_SCHEMA_VERSION);
    let missing_settlement_binding = !obj.contains_key(SETTLEMENT_BINDING_KEY);
    if missing.is_empty() && !stale_version && !missing_settlement_binding {
        println!(
            "migrate-state: nothing to do — {STATE_FILE} already carries every security ledger at \
             schema v{STATE_SCHEMA_VERSION}."
        );
        return;
    }
    if !missing_replay.is_empty() && !replay_acked {
        die(format!(
            "migrate-state would CREATE the replay ledger(s) {missing_replay:?} EMPTY in \
             {STATE_FILE}.\n\
             CONSEQUENCE: every inter-channel transfer and every L1 deposit this channel has \
             already credited/debited becomes replayable ONE more time, because the record that \
             they happened will no longer exist. There is no way to reconstruct the lost entries \
             from this file.\n\
             If that is acceptable, re-run with {REPLAY_ACK}. Fail-closed."
        ));
    }
    if missing_signing && !signing_acked {
        die(format!(
            "migrate-state would CREATE `{STATE_SIGNING_LEDGER_KEY}` EMPTY in {STATE_FILE}.\n\
             CONSEQUENCE: this process cannot know whether its member keys signed a sibling of \
             the current head before this ledger existed. Resetting that history can permit one \
             conflicting successor signature. There is no safe automatic reconstruction.\n\
             If the operator has independently reconciled every prior signed state and accepts \
             this risk, re-run with {SIGNING_ACK}. Fail-closed."
        ));
    }

    for k in &missing_replay {
        obj.insert((*k).to_string(), serde_json::Value::Array(Vec::new()));
    }
    if missing_signing {
        obj.insert(
            STATE_SIGNING_LEDGER_KEY.to_string(),
            serde_json::Value::Object(serde_json::Map::new()),
        );
    }
    if missing_exit_kit_receipt {
        obj.insert(
            SIGNER_EXIT_KIT_RECEIPT_KEY.to_string(),
            serde_json::Value::Null,
        );
        eprintln!(
            "[state] SECURITY: migrated legacy state with no signer exit-kit receipt to explicit \
             null. H2=0 signing remains disabled until `install-exit-kit` cryptographically \
             verifies and fsyncs an exact public artifact."
        );
    }
    if missing_settlement_binding {
        if Path::new("settlement.json").exists() {
            die(format!(
                "REFUSING to migrate {STATE_FILE}: `{SETTLEMENT_BINDING_KEY}` is absent while \
                 settlement.json exists. The channel may already have an immutable L1 participant \
                 root; writing null would reopen delegate joins. Reconstruct the binding from the \
                 deployed manager instead."
            ));
        }
        obj.insert(SETTLEMENT_BINDING_KEY.to_string(), serde_json::Value::Null);
    }
    obj.insert(
        "state_schema_version".to_string(),
        serde_json::Value::from(STATE_SCHEMA_VERSION),
    );
    write_private_json_at(Path::new(STATE_FILE), &serde_json::Value::Object(obj));

    // Prove the migrated file actually loads under the strict path before declaring success.
    let _ = load_state();
    if missing.is_empty() {
        println!("migrate-state OK: {STATE_FILE} stamped schema v{STATE_SCHEMA_VERSION}.");
    } else {
        println!(
            "migrate-state OK: created EMPTY security ledger(s) {missing:?} and stamped schema \
             v{STATE_SCHEMA_VERSION}. SECURITY: replay history and/or state-signing history named \
             above begins at this explicit migration boundary."
        );
    }
}

/// Whether the channel's OWN backing deposit is on-chain yet, and therefore whether the import
/// path's backing-deposit guard (`cmd_cosign_l1_deposit_import`) is APPLICABLE at all.
///
/// SECURITY (deposit-import-threat-model.md §10.6): this tri-state exists because an EMPTY tx-hash
/// string cannot distinguish "no backing deposit exists yet" from "one exists and we lost its
/// hash". The old scalar `deposit_tx` conflated them, and the guard `if !deposit_tx.is_empty()`
/// therefore SKIPPED SILENTLY in exactly the case where it was needed. The point of the enum is
/// that "the guard does not apply here" becomes a STATED, justified conclusion the code prints,
/// never something inferred from an empty string.
///
/// The serde default is the UNSAFE case (`Unknown`) so that a backing file written before this
/// field existed FAILS CLOSED rather than silently disarming the guard. See
/// `ChannelBacking::resolved_backing_deposit_status` for the one narrow, evidence-backed exception.
#[derive(Serialize, Deserialize, Default, PartialEq, Eq, Clone, Copy, Debug)]
#[serde(rename_all = "snake_case")]
enum BackingDepositStatus {
    /// Pre-dates this field, or the CLI genuinely does not know. FAIL CLOSED: refuse to import.
    #[default]
    Unknown,
    /// `setup-backing` DEFERRED the on-chain deposit to `withdraw` (`SETUP_BACKING_NO_ONCHAIN_
    /// DEPOSIT`). No backing deposit exists on-chain yet, so no import can be one — the guard is
    /// NOT APPLICABLE, and says so out loud.
    Deferred,
    /// The backing deposit is on-chain and `backing_deposit_txs` names it (plus, for legacy files,
    /// the retained `deposit_tx` scalar).
    Landed,
}

/// Backed-genesis parameters produced once by `setup-backing` (detail2 §F-1).
#[derive(Serialize, Deserialize)]
struct ChannelBacking {
    /// hex of the deposit settle-history the channel's balance proof folded in (§F-1
    /// reconciliation).
    settled_tx_chain: String,
    /// hex anchor of the channel fund to intmax state (close-time L1 check; NOT the §F-1 co-sign
    /// gate).
    intmax_state_root: String,
    /// the deposited native value backing the channel (== Σ genesis balances).
    fund: u64,
    /// On-chain provenance of the REAL deposit that backs this channel (detail2 §F-1 origin).
    #[serde(default)]
    rollup: String,
    /// LEGACY (retained for the backing files already shipped to production, which carry only this
    /// scalar): the `setup-backing` deposit transaction. Still consulted by the import guard, but
    /// `backing_deposit_txs` is the field new code writes and reads. Do NOT add new writers.
    #[serde(default)]
    deposit_tx: String,
    /// Every transaction in which THIS CLI deposited to `deposit_recipient`. A SET, not a scalar:
    /// `setup-backing` makes at most one, and `withdraw` makes one or two more (native +
    /// ERC-20 lane) — see deposit-import-threat-model.md §10.4 Finding B, where `withdraw`'s
    /// deposit was invisible to the import guard in EVERY mode because only the `setup-backing`
    /// hash was ever recorded.
    ///
    /// SECURITY: `cmd_withdraw` BACKFILLS this (and persists it) immediately after each
    /// `deposit()` it sends, BEFORE proceeding — so a crash between the deposit landing and the
    /// rest of the pipeline still leaves the guard armed. Hashes are stored as written by `cast`;
    /// comparison is always through `strip0x` + lowercase.
    #[serde(default)]
    backing_deposit_txs: Vec<String>,
    /// Whether a backing deposit exists on-chain at all. Serde default = `Unknown` = FAIL CLOSED.
    #[serde(default)]
    backing_deposit_status: BackingDepositStatus,
    /// A-3 P5-B: the deposit salt used to derive the on-chain deposit recipient
    /// (`calculate_recipient_from_user_id(channel_id, deposit_salt)`). Persisted so `withdraw` can
    /// reconstruct the SAME deposit block (matching the already-made on-chain `deposit()`),
    /// letting one channel registration + deposit serve both the close and withdraw paths.
    #[serde(default)]
    deposit_salt: Option<Salt>,
    /// The on-chain deposit recipient (hex of `calculate_recipient_from_user_id(channel_id,
    /// deposit_salt)`). Persisted so the relay can call `deposit()` without Rust recomputation.
    #[serde(default)]
    deposit_recipient: String,
    /// P2-4: authoritative private witness for the persisted base balance IVC head. The sent-tx
    /// tree, not a CLI counter, answers whether a proposed burn nonce is actually empty. Legacy
    /// backing files deserialize to `None` and burns fail closed with a migration instruction.
    #[serde(default)]
    base_private_state: Option<FullPrivateState>,
}

/// Canonical form for comparing hex identifiers that different producers spell differently
/// (`cast` emits `0x…`, argv and JSON may or may not). SECURITY: every comparison of a tx hash or
/// address in this file goes through this — two spellings of one value must never key differently.
fn strip0x(s: &str) -> String {
    s.trim_start_matches("0x")
        .trim_start_matches("0X")
        .to_ascii_lowercase()
}

impl ChannelBacking {
    /// Every tx hash this CLI knows to be a deposit it made to `deposit_recipient`, canonicalized.
    /// The union of the legacy `deposit_tx` scalar and the `backing_deposit_txs` set — the legacy
    /// field is included so the four production backing files (which carry only the scalar) keep
    /// their guard armed.
    fn known_backing_deposit_txs(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::with_capacity(self.backing_deposit_txs.len() + 1);
        for h in std::iter::once(&self.deposit_tx).chain(self.backing_deposit_txs.iter()) {
            let h = strip0x(h);
            if !h.is_empty() && !out.contains(&h) {
                out.push(h);
            }
        }
        out
    }

    /// Resolve the recorded status, applying the ONE legacy inference that is backed by evidence.
    ///
    /// SECURITY: a backing file written before `backing_deposit_status` existed deserializes to
    /// `Unknown`. For such a file a NON-EMPTY `deposit_tx` is positive evidence that the
    /// `setup-backing` deposit really was made and that we still hold its hash, so `Landed` is a
    /// justified conclusion rather than an assumption — this is what keeps the four shipped
    /// production backing records (deploy-staging/ch7|ch8, wallet-live-work/ch7|ch8) working. An
    /// EMPTY `deposit_tx` on such a file carries no evidence either way and stays `Unknown`, which
    /// fails closed.
    ///
    /// RESIDUAL (documented, not fixable retroactively): a LEGACY file whose channel already ran
    /// `withdraw` under the pre-fix code has an unrecorded second deposit (§10.4 Finding B). Its
    /// hash cannot be recovered from the file, so the guard cannot name it. Any FUTURE `withdraw`
    /// backfills, and re-running `setup-backing` re-arms from scratch.
    fn resolved_backing_deposit_status(&self) -> BackingDepositStatus {
        match self.backing_deposit_status {
            BackingDepositStatus::Unknown if !strip0x(&self.deposit_tx).is_empty() => {
                BackingDepositStatus::Landed
            }
            recorded => recorded,
        }
    }
}

/// Append `tx_hash` to the channel backing's `backing_deposit_txs` and mark the backing deposit as
/// `Landed`, then PERSIST immediately.
///
/// SECURITY (deposit-import-threat-model.md §10.4 Finding B): `withdraw` always makes a real
/// deposit to `deposit_recipient`, and before this backfill its hash was discarded — so the import
/// path's backing-deposit guard could not recognise it and the channel could be made to credit
/// itself twice against one L1 escrow (wedging its own exit). Persisting happens BEFORE the
/// caller proceeds so that a crash later in the withdraw pipeline cannot leave a landed deposit
/// unrecorded.
fn record_backing_deposit_tx(tx_hash: &str) {
    if strip0x(tx_hash).is_empty() {
        die("record_backing_deposit_tx: empty tx hash — refusing to record an unusable entry");
    }
    let mut backing: ChannelBacking = read_private_json(BACKING_FILE);
    if !backing
        .known_backing_deposit_txs()
        .contains(&strip0x(tx_hash))
    {
        backing.backing_deposit_txs.push(tx_hash.to_string());
    }
    backing.backing_deposit_status = BackingDepositStatus::Landed;
    write_private_json(BACKING_FILE, &backing);
    eprintln!(
        "[withdraw] SECURITY: recorded backing-recipient deposit {tx_hash} in {BACKING_FILE} \
         (backing_deposit_txs, status=landed) — the import guard now refuses it."
    );
}

fn backing_exists() -> bool {
    std::path::Path::new(BACKING_FILE).exists()
        && std::path::Path::new(ATTESTATION_FILE).exists()
        && std::path::Path::new(BALANCE_VD_FILE).exists()
}

/// Load the cached deposit backing: the small `balance_vd` (the gate needs only this — not the
/// prover), the channel's balance-proof attestation, and the backed-genesis params.
fn load_backing() -> (
    VerifierCircuitData<BF, BC, BD>,
    ChannelBalanceAttestation,
    ChannelBacking,
) {
    if !backing_exists() {
        die(
            "no deposit backing found: run `channel_member setup-backing` first (detail2 §F-1). \
             Refusing to operate an unbacked channel.",
        );
    }
    let vd_bytes =
        fs::read(BALANCE_VD_FILE).unwrap_or_else(|e| die(format!("read {BALANCE_VD_FILE}: {e}")));
    let balance_vd = deserialize_verifier_data::<BF, BC, BD>(&vd_bytes)
        .unwrap_or_else(|e| die(format!("deserialize balance_vd: {e}")));
    let proof =
        fs::read(ATTESTATION_FILE).unwrap_or_else(|e| die(format!("read {ATTESTATION_FILE}: {e}")));
    let backing: ChannelBacking = read_private_json(BACKING_FILE);
    (
        balance_vd,
        ChannelBalanceAttestation {
            balance_proof: proof,
        },
        backing,
    )
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn validate_signer_exit_kit_archive_directory() -> Result<(), String> {
    let path = Path::new(SIGNER_EXIT_KIT_ARCHIVE_DIR);
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(format!(
                    "signer exit-kit archive {} is not a real directory",
                    path.display()
                ));
            }
            #[cfg(unix)]
            if metadata.permissions().mode() & 0o077 != 0 {
                fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| {
                    format!(
                        "restrict signer exit-kit archive {} to 0700: {error}",
                        path.display()
                    )
                })?;
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path).map_err(|error| {
                format!(
                    "create signer exit-kit archive {}: {error}",
                    path.display()
                )
            })?;
            #[cfg(unix)]
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| {
                format!(
                    "restrict signer exit-kit archive {} to 0700: {error}",
                    path.display()
                )
            })?;
            FileSync::sync_directory(Path::new("."));
        }
        Err(error) => {
            return Err(format!(
                "inspect signer exit-kit archive {}: {error}",
                path.display()
            ));
        }
    }
    Ok(())
}

/// Derive independent verification context from the signer's existing durable state. A public
/// envelope never gets to choose its own chain, rollup or Balance verifier key. Before a
/// production settlement is ACTIVE there is intentionally no production context; only local
/// chain 31337 may install a receipt from the rollup already pinned by `setup-backing`.
fn signer_exit_kit_context(cli: &CliState) -> Result<(u64, Address, [u8; 32]), String> {
    let vd_bytes = read_bounded_regular_file(
        Path::new(BALANCE_VD_FILE),
        MAX_BALANCE_VERIFIER_DATA_BYTES as u64,
        "local Balance verifier data",
    )?;
    let vd_sha256 = sha256_bytes(&vd_bytes);

    if let Some(binding) = &cli.settlement_binding {
        if binding.status != SettlementBindingStatus::Active {
            return Err(
                "cannot install/verify an exit-kit receipt while settlement is only PREPARED"
                    .into(),
            );
        }
        let rollup = Address::from_hex(binding.rollup.trim())
            .map_err(|error| format!("parse durable settlement rollup: {error}"))?;
        if rollup == Address::default() {
            return Err("durable settlement binding contains a zero rollup".into());
        }
        let chain_id = match (&binding.deployment, &binding.activation_checkpoint) {
            (Some(deployment), Some(checkpoint)) => {
                if checkpoint.chain_id != deployment.chain_id {
                    return Err(
                        "settlement deployment and activation checkpoint disagree on chain id"
                            .into(),
                    );
                }
                deployment.chain_id
            }
            (None, None) => DEVNET_CHAIN_ID,
            _ => {
                return Err(
                    "settlement binding has incomplete production chain/finality context".into(),
                );
            }
        };
        return Ok((chain_id, rollup, vd_sha256));
    }

    let backing_bytes = read_bounded_regular_file(
        Path::new(BACKING_FILE),
        1024 * 1024,
        "local channel backing",
    )?;
    let backing: ChannelBacking = serde_json::from_slice(&backing_bytes)
        .map_err(|error| format!("parse local channel backing: {error}"))?;
    let rollup = Address::from_hex(backing.rollup.trim())
        .map_err(|error| format!("parse local backing rollup: {error}"))?;
    if rollup == Address::default() {
        return Err("local channel backing contains a zero rollup".into());
    }
    Ok((DEVNET_CHAIN_ID, rollup, vd_sha256))
}

fn verified_signer_exit_kit_receipt(
    cli: &CliState,
    envelope_bytes: &[u8],
    require_current_source_head: bool,
) -> Result<SignerExitKitReceipt, String> {
    let envelope = parse_public_close_backing_envelope(envelope_bytes)
        .map_err(|error| format!("parse public signer exit-kit envelope: {error}"))?;
    let (chain_id, rollup, vd_sha256) = signer_exit_kit_context(cli)?;
    let expected = PublicCloseExpectations {
        channel_id: cli.snapshot.record.channel_id,
        chain_id,
        rollup,
        balance_verifier_data_sha256: Some(vd_sha256),
    };
    let verification = verify_public_backing(&envelope, &expected)
        .map_err(|error| format!("cryptographically verify signer exit kit: {error}"))?;
    if !verification.self_verified {
        return Err("public backing verifier returned a non-verified receipt".into());
    }

    let source_head = &envelope.backing.signed_head;
    if require_current_source_head
        && (source_head.digest != cli.snapshot.state.digest
            || envelope.backing.channel_record != cli.snapshot.record)
    {
        return Err(
            "exit-kit source is not the signer's exact current head and channel record".into(),
        );
    }
    let kit = envelope
        .backing
        .signed_head_exit_kit
        .as_ref()
        .ok_or_else(|| "verified public backing unexpectedly omitted its exit kit".to_string())?;
    let receipt = SignerExitKitReceipt {
        schema_version: SIGNER_EXIT_KIT_RECEIPT_SCHEMA_VERSION,
        archive_sha256: sha256_bytes(envelope_bytes),
        balance_verifier_data_sha256: vd_sha256,
        chain_id,
        rollup,
        source_signed_head_digest: source_head.digest,
        channel_id: kit.backing_public_inputs.channel_id,
        settled_tx_chain: kit.backing_public_inputs.settled_tx_chain,
        token_funds_digest: kit.backing_public_inputs.token_funds_digest,
    };
    validate_exit_kit_receipt_for_head(&receipt, source_head)?;
    if require_current_source_head {
        validate_exit_kit_receipt_for_head(&receipt, &cli.snapshot.state)?;
    }
    Ok(receipt)
}

/// Re-open, re-hash and cryptographically verify the exact archived envelope once per process.
/// The boolean cache is non-serialized, so a restart can never trust yesterday's filesystem.
fn verify_persisted_signer_exit_kit(cli: &CliState) -> Result<(), String> {
    let receipt = cli.signer_exit_kit_receipt.as_ref().ok_or_else(|| {
        "SIGNER-INDEPENDENT EXIT REQUIRED: no signer exit-kit receipt is installed".to_string()
    })?;
    validate_exit_kit_receipt_for_head(receipt, &cli.snapshot.state)?;
    validate_signer_exit_kit_archive_directory()?;
    let path = exit_kit_receipt_archive_path(receipt);
    let bytes = read_bounded_regular_file(
        &path,
        MAX_PUBLIC_BACKING_ENVELOPE_BYTES as u64,
        "content-addressed signer exit-kit envelope",
    )?;
    if sha256_bytes(&bytes) != receipt.archive_sha256 {
        return Err(format!(
            "signer exit-kit archive {} does not match its SHA-256 receipt",
            path.display()
        ));
    }
    let recomputed = verified_signer_exit_kit_receipt(cli, &bytes, false)?;
    if &recomputed != receipt {
        return Err(
            "cryptographically reverified signer exit-kit archive differs from its durable receipt"
                .into(),
        );
    }
    Ok(())
}

fn cmd_install_exit_kit(args: &[String]) {
    let envelope_path = args
        .get(1)
        .unwrap_or_else(|| die("install-exit-kit <public_backing_envelope.json>"));
    let envelope_bytes = read_bounded_regular_file(
        Path::new(envelope_path),
        MAX_PUBLIC_BACKING_ENVELOPE_BYTES as u64,
        "public signer exit-kit envelope",
    )
    .unwrap_or_else(|error| die(error));
    let mut cli = load_state();
    let receipt = verified_signer_exit_kit_receipt(&cli, &envelope_bytes, true)
        .unwrap_or_else(|error| die(format!("REFUSING signer exit-kit install: {error}")));

    validate_signer_exit_kit_archive_directory().unwrap_or_else(|error| die(error));
    let archive_path = exit_kit_receipt_archive_path(&receipt);
    match fs::symlink_metadata(&archive_path) {
        Ok(_) => {
            let existing = read_bounded_regular_file(
                &archive_path,
                MAX_PUBLIC_BACKING_ENVELOPE_BYTES as u64,
                "existing content-addressed signer exit-kit envelope",
            )
            .unwrap_or_else(|error| die(error));
            if existing != envelope_bytes {
                die("content-addressed signer exit-kit path contains different bytes");
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            write_private_bytes_at(&archive_path, &envelope_bytes);
        }
        Err(error) => die(format!(
            "inspect signer exit-kit archive {}: {error}",
            archive_path.display()
        )),
    }

    // Archive fsync happens first; only then may the small state receipt point to it. A crash can
    // leave an unreferenced content-addressed file, never a receipt naming missing bytes.
    cli.signer_exit_kit_receipt = Some(receipt.clone());
    cli.signer_exit_kit_receipt_verified = true;
    save_state(&cli);
    println!(
        "install-exit-kit OK: verified+fsynced head {} statement ({}, {}, {}) at {}",
        receipt.source_signed_head_digest,
        receipt.channel_id.as_u64(),
        receipt.settled_tx_chain,
        receipt.token_funds_digest,
        archive_path.display()
    );
}

// anvil dev account[0] private key — a PUBLIC throwaway (safe on the CLI; NEVER a real key).
const ANVIL_DEV_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/// Foundry signer used for L1 writes.
///
/// A raw key is supported only on chain 31337, where the default is Anvil's public throwaway key.
/// Every other chain must use an encrypted Foundry keystore selected by `INTMAX_L1_ACCOUNT`.
/// Consequently a real private key is never present in this process' child argv. Foundry may read
/// the keystore password from its standard `ETH_PASSWORD` environment or prompt on a TTY; callers
/// may also configure Foundry's own password-file mechanism outside this process.
#[derive(Clone, Debug, Eq, PartialEq)]
enum L1Signer {
    LocalDevPrivateKey(String),
    FoundryAccount(String),
}

impl L1Signer {
    fn for_chain_id(chain_id: u64) -> Self {
        let legacy_key = std::env::var("INTMAX_DEPOSIT_KEY")
            .unwrap_or_default()
            .trim()
            .to_string();
        let account = std::env::var("INTMAX_L1_ACCOUNT")
            .unwrap_or_default()
            .trim()
            .to_string();

        if chain_id == DEVNET_CHAIN_ID {
            if !account.is_empty() {
                return Self::validated_account(account);
            }
            return Self::LocalDevPrivateKey(if legacy_key.is_empty() {
                ANVIL_DEV_KEY.to_string()
            } else {
                legacy_key
            });
        }

        if !legacy_key.is_empty() {
            die(format!(
                "INTMAX_DEPOSIT_KEY is set on non-dev chain id {chain_id}, but raw private keys are \
                 forbidden for real-network L1 writes because `--private-key <secret>` is visible \
                 in process argv. Import the key into Foundry's encrypted keystore (`cast wallet \
                 import <name> --interactive`), unset INTMAX_DEPOSIT_KEY, and set \
                 INTMAX_L1_ACCOUNT=<name>. Foundry reads the password through its standard \
                 ETH_PASSWORD/password-file mechanism."
            ));
        }
        if account.is_empty() {
            die(format!(
                "INTMAX_L1_ACCOUNT is not set for non-dev chain id {chain_id}. Refusing to place a \
                 real private key in child-process argv. Import the funded signer with `cast wallet \
                 import <name> --interactive`, then set INTMAX_L1_ACCOUNT=<name> (and configure \
                 Foundry's ETH_PASSWORD/password-file mechanism)."
            ));
        }
        Self::validated_account(account)
    }

    fn validated_account(account: String) -> Self {
        let valid = account.len() <= 128
            && account
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphanumeric())
            && account
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
        if !valid {
            die(
                "INTMAX_L1_ACCOUNT must be a Foundry keystore filename (1..128 ASCII \
                 alphanumeric/._- characters, beginning with an alphanumeric character)",
            );
        }
        Self::FoundryAccount(account)
    }

    fn for_rpc(rpc: &str) -> Self {
        Self::for_chain_id(rpc_chain_id(rpc))
    }
}

/// A [`L1Signer`] whose chain-id probe is deferred to first use.
///
/// SECURITY: this changes WHEN the chain id is read, never WHETHER. `for_rpc` still reads it from
/// THE CHAIN via `rpc_chain_id`, still dies on an unreadable id, and still runs before any signer
/// material reaches a child process — the guarantees documented on `rpc_chain_id` /
/// `settlement_deploy_plan` are untouched. What it removes is a network round-trip standing in
/// front of the CHEAP OFFLINE gates (contracts-checkout resolution, the co-signer identity gate)
/// that every exit command runs first. Constructing eagerly made an unreachable RPC mask those
/// refusals: `tests/exit_path_cwd.rs` asserts precisely that they land before the CLI touches the
/// network, and four of its five cases could no longer reach them. It also defeated the F4 intent
/// stated in `cmd_cancel_close` / `cmd_post_close_claim` — validate the checkout BEFORE the heavy
/// proof — by probing even earlier than the validation it was meant to precede.
struct LazyL1Signer<'a> {
    rpc: &'a str,
    cell: std::cell::OnceCell<L1Signer>,
}

impl<'a> LazyL1Signer<'a> {
    fn new(rpc: &'a str) -> Self {
        Self {
            rpc,
            cell: std::cell::OnceCell::new(),
        }
    }

    /// Read the chain id (once) and resolve the signer. Call at the LAST moment before signer
    /// material is needed, so every offline refusal has already had its chance to fire.
    fn get(&self) -> &L1Signer {
        self.cell.get_or_init(|| L1Signer::for_rpc(self.rpc))
    }
}

impl L1Signer {
    /// Add only Foundry wallet-selection flags. Password material is deliberately never added.
    fn append_args(&self, argv: &mut Vec<String>) {
        match self {
            Self::LocalDevPrivateKey(key) => {
                argv.push("--private-key".to_string());
                argv.push(key.clone());
            }
            Self::FoundryAccount(account) => {
                argv.push("--account".to_string());
                argv.push(account.clone());
            }
        }
    }

    fn append_to_command(&self, command: &mut Command) {
        match self {
            Self::LocalDevPrivateKey(key) => {
                command.arg("--private-key").arg(key);
            }
            Self::FoundryAccount(account) => {
                command.arg("--account").arg(account);
            }
        }
    }

    fn address(&self) -> String {
        let mut argv = vec!["wallet".to_string(), "address".to_string()];
        self.append_args(&mut argv);
        cast_owned(&argv).trim().to_string()
    }
}

#[cfg(test)]
mod falcon_precompute_detach_tests {
    use super::*;

    fn digest(byte: u8) -> Bytes32 {
        Bytes32::from_hex(&format!("0x{}", format!("{byte:02x}").repeat(32))).unwrap()
    }

    /// The finalize-time Falcon precompute must NOT sit on the co-sign critical path: building the
    /// batch circuit is ~2 s, and `save_state` runs at the tail of every co-sign that completes an
    /// N-of-N set. The spawn must return in well under the circuit-build time.
    #[test]
    fn detached_precompute_returns_without_waiting_for_the_circuit_build() {
        let dir = std::env::temp_dir().join(format!("falcon-detach-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let started = std::time::Instant::now();
        let spawned = spawn_detached_falcon_precompute_in(digest(0x11), &dir);
        let elapsed = started.elapsed();
        let _ = std::fs::remove_dir_all(&dir);

        assert!(spawned, "no cache present, so a child must be spawned");
        // Circuit build alone is ~2 s; a synchronous precompute could never return this fast.
        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "precompute blocked the caller for {elapsed:?}"
        );
    }

    /// An already-cached digest (idempotent re-save of the same head) must not fork at all —
    /// forking a 2 s child per save would be the old latency in disguise.
    #[test]
    fn cached_digest_does_not_spawn() {
        let dir = std::env::temp_dir().join(format!("falcon-cached-{}", std::process::id()));
        std::fs::create_dir_all(dir.join(FALCON_AGG_CACHE_DIR)).unwrap();
        std::fs::write(dir.join(falcon_aggregate_path(digest(0x22))), b"stub").unwrap();

        let spawned = spawn_detached_falcon_precompute_in(digest(0x22), &dir);
        let _ = std::fs::remove_dir_all(&dir);

        assert!(!spawned, "cached digest must short-circuit without forking");
    }
}

#[cfg(test)]
mod l1_signer_tests {
    use super::*;

    #[test]
    fn foundry_account_child_argv_contains_no_private_or_password_material() {
        let signer = L1Signer::FoundryAccount("sepolia-operator".to_string());
        let mut command = Command::new("forge");
        command.args(["script", "script/Deploy.s.sol"]);
        signer.append_to_command(&mut command);
        let argv: Vec<String> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();

        assert_eq!(
            argv,
            [
                "script",
                "script/Deploy.s.sol",
                "--account",
                "sepolia-operator"
            ]
        );
        assert!(!argv.iter().any(|arg| arg.contains("private-key")));
        assert!(!argv.iter().any(|arg| arg.contains("password")));
    }
}

/// Run `cast <args>` and return stdout (dies on failure; foundry `cast` must be on PATH).
fn cast(args: &[&str]) -> String {
    let out = Command::new("cast")
        .args(args)
        .output()
        .unwrap_or_else(|e| die(format!("cast failed to start ({e}); is foundry installed?")));
    if !out.status.success() {
        die(format!(
            "cast {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// Owned-argument variant used for signed calls, where the wallet selector is chosen at runtime.
fn cast_owned(args: &[String]) -> String {
    let out = Command::new("cast")
        .args(args)
        .output()
        .unwrap_or_else(|e| die(format!("cast failed to start ({e}); is foundry installed?")));
    if !out.status.success() {
        // Do not format wallet argv into the error: even a local developer may have selected a
        // non-default Anvil fixture key, and diagnostics must not turn that into a log disclosure.
        die(format!(
            "signed cast command failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// Run a signed `cast` command. The RPC is resolved before signer selection so a raw key can only
/// reach argv after the endpoint has proved it is chain 31337.
fn cast_signed(rpc: &str, signer: &L1Signer, args: &[&str]) -> String {
    let mut argv: Vec<String> = args.iter().map(|arg| (*arg).to_string()).collect();
    signer.append_args(&mut argv);
    argv.extend(["--rpc-url".to_string(), rpc.to_string()]);
    cast_owned(&argv)
}

/// The `transactionHash` of a `cast send --json` receipt. FAIL-CLOSED: a receipt we cannot read a
/// hash out of is a hard error, never an empty string — an empty hash is exactly what disarmed the
/// backing-deposit guard (deposit-import-threat-model.md §10.2).
fn parse_cast_tx_hash(send_out: &str, what: &str) -> String {
    send_out
        .split("\"transactionHash\":\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .filter(|h| !strip0x(h).is_empty())
        .unwrap_or_else(|| die(format!("{what}: tx hash not found in cast --json output")))
        .to_string()
}

/// The 32-byte ABI word at index `i` of a hex data blob (no `0x` prefix).
fn abi_word(data: &str, i: usize) -> &str {
    &data[i * 64..(i + 1) * 64]
}

/// ONE-TIME setup: fund the channel with a REAL L1 deposit and cache its base-layer balance proof
/// as the channel's deposit backing (detail2 §F-1). Builds the `BalanceProcessor` (~25s), proves
/// the deposit, and writes the attestation + verifier data + backed-genesis params. Run BEFORE
/// `init`. `setup-backing [fund]` (default = Σ CLI member genesis balances).
fn cmd_setup_backing(args: &[String]) {
    use rand::{SeedableRng as _, rngs::StdRng as DepRng};
    let rpc = args.get(1).cloned().unwrap_or_else(|| {
        die("setup-backing needs <rpc_url> <rollup_addr> [fund] (real on-chain deposit)")
    });
    let rollup = args
        .get(2)
        .cloned()
        .unwrap_or_else(|| die("setup-backing needs <rpc_url> <rollup_addr> [fund]"));
    let fund: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or_else(|| {
        cli_slots().iter().map(|&s| genesis_amount(s)).sum::<u64>() + DELEGATE_GENESIS
    });
    let l1_signer = LazyL1Signer::new(&rpc);

    eprintln!("setup-backing: building the balance prover (one-time, ~25s)…");
    let spend = SpendCircuit::<BF, BC, BD>::new();
    let bp = BalanceProcessor::<BF, BC, BD>::new(&spend.data.verifier_data());
    let bwgen = BlockWitnessGeneratorHandle::new(BlockWitnessGenerator::new(&[1, 4, 512]));

    let mut rng = DepRng::seed_from_u64(0x00DE_C0DE ^ channel_id_env() as u64);
    let channel_id =
        ChannelId::new(channel_id_env() as u64).unwrap_or_else(|e| die(format!("{e:?}")));
    let salt = Salt::rand(&mut rng);
    let mut bwg = BalanceWitnessGenerator::new(channel_id, salt, bwgen.clone(), &bp)
        .unwrap_or_else(|e| die(format!("balance witness generator: {e:?}")));

    let deposit_salt = Salt::rand(&mut rng);
    let recipient = calculate_recipient_from_user_id(channel_id, deposit_salt);
    let amount = fund;

    // P5-B 案B: optionally DEFER the on-chain deposit to `withdraw` so the withdraw block chain
    // folds the deposit in the exact order its proof models (the standalone fold order). The
    // default makes the REAL on-chain deposit now (detail2 §F-1 backing origin + keystone
    // reconciliation — the browser demo path). When `SETUP_BACKING_NO_ONCHAIN_DEPOSIT` is set
    // (the close-lifecycle E2E), we only build the off-chain balance proof + persist the
    // params; the deposit is made by `withdraw`. SECURITY: fund custody is gated by the
    // withdrawal proof's finalized-root check at exit (IntmaxRollup.sol:1262) — this only
    // changes WHEN the deposit lands on-chain, not whether the eventual L1 exit is backed.
    let no_onchain_deposit = std::env::var("SETUP_BACKING_NO_ONCHAIN_DEPOSIT").is_ok();
    let (depositor, txhash) = if no_onchain_deposit {
        let dep_hex = l1_signer.get().address();
        let dep = Address::from_hex(&dep_hex)
            .unwrap_or_else(|e| die(format!("parse depositor address: {e:?}")));
        eprintln!(
            "setup-backing: NO on-chain deposit (P5-B: deferred to `withdraw`); depositor = {dep_hex}."
        );
        (dep, String::new())
    } else {
        // REAL on-chain ETH deposit (detail2 §F-1 backing ORIGIN — no fabrication): the local chain
        // really escrows the value, and we read the deposit back from the receipt.
        eprintln!(
            "setup-backing: real ETH deposit on {rpc} → IntmaxRollup {rollup} (amount {amount})…"
        );
        let recipient_hex = recipient.to_hex();
        let send_out = cast_signed(
            &rpc,
            l1_signer.get(),
            &[
                "send",
                &rollup,
                "deposit(bytes32,uint32,uint256,bytes32)",
                &recipient_hex,
                "0",
                &amount.to_string(),
                "0x0000000000000000000000000000000000000000000000000000000000000000",
                "--value",
                &amount.to_string(),
                "--json",
            ],
        );
        let txhash = parse_cast_tx_hash(&send_out, "setup-backing deposit");

        // Read the deposit back from the LIVE receipt: depositor + the on-chain depositHashChain.
        let receipt = cast(&["receipt", &txhash, "--rpc-url", &rpc, "--json"]);
        let data = receipt
            .split("\"data\":\"0x")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .unwrap_or_else(|| die("Deposited log data not found in receipt"));
        let depositor = Address::from_hex(&format!("0x{}", &abi_word(data, 0)[24..]))
            .unwrap_or_else(|e| die(format!("parse depositor: {e:?}")));
        let onchain_chain = Bytes32::from_hex(&format!("0x{}", abi_word(data, 5)))
            .unwrap_or_else(|e| die(format!("parse on-chain depositHashChain: {e:?}")));

        // KEYSTONE (fail-closed): the Rust deposit MUST reproduce the on-chain depositHashChain,
        // else the witness would not mirror the real deposit. Refuse to back the channel on
        // any mismatch.
        let rust_deposit = Deposit {
            deposit_index: Default::default(),
            block_number: Default::default(),
            depositor,
            recipient,
            token_index: 0,
            amount: U256::from(amount),
            aux_data: Bytes32::default(),
        };
        if rust_deposit.hash_with_prev_hash(Bytes32::default()) != onchain_chain {
            die(
                "on-chain depositHashChain != Rust deposit hash — refusing to back the channel with an unreconciled deposit",
            );
        }
        eprintln!(
            "setup-backing: on-chain deposit reconciled (depositHashChain {}).",
            onchain_chain.to_hex()
        );
        (depositor, txhash)
    };

    // Feed the REAL on-chain deposit fields into the witness generator → real-deposit-backed proof.
    bwgen
        .borrow_mut()
        .add_deposit(
            depositor,
            recipient,
            0,
            U256::from(amount),
            Bytes32::default(),
        )
        .unwrap_or_else(|e| die(format!("queue deposit: {e:?}")));
    bwgen
        .borrow_mut()
        .add_block(0, &[], 0, Bytes32::default())
        .unwrap_or_else(|e| die(format!("apply deposit block: {e:?}")));

    let dw = bwg
        .receive_deposit_witness(&ReceiveDepositData {
            receiver: recipient,
            deposit_salt,
        })
        .unwrap_or_else(|e| die(format!("receive deposit witness: {e:?}")));
    eprintln!("setup-backing: proving the deposit…");
    let proof = bp
        .prove_receive_deposit(&dw)
        .unwrap_or_else(|e| die(format!("prove deposit: {e:?}")));
    bwg.commit_receive_deposit(&proof, &dw)
        .unwrap_or_else(|e| die(format!("commit deposit: {e:?}")));
    let pis = bwg
        .get_public_inputs()
        .unwrap_or_else(|e| die(format!("balance pis: {e:?}")));

    fs::write(ATTESTATION_FILE, proof.to_bytes())
        .unwrap_or_else(|e| die(format!("write {ATTESTATION_FILE}: {e}")));
    let vd_bytes = serialize_verifier_data(&bp.balance_vd())
        .unwrap_or_else(|e| die(format!("serialize balance_vd: {e}")));
    fs::write(BALANCE_VD_FILE, vd_bytes)
        .unwrap_or_else(|e| die(format!("write {BALANCE_VD_FILE}: {e}")));
    // A-3 P1: source the REAL L1-close anchor = the rollup's current finalized state root. See the
    // ChannelFund.intmax_state_root note above for why this is fund-safe regardless of value.
    let finalized_root_hex = cast(&[
        "call",
        &rollup,
        "latestFinalizedStateRoot()",
        "--rpc-url",
        &rpc,
    ])
    .trim()
    .to_string();
    let intmax_state_root = Bytes32::from_hex(&finalized_root_hex)
        .unwrap_or_else(|e| die(format!("parse latestFinalizedStateRoot(): {e:?}")));
    if intmax_state_root == Bytes32::default() {
        eprintln!(
            "setup-backing WARNING: IntmaxRollup has no finalized state root yet (genesis/zero). The \
             channel's L1-close anchor will be zero. This is FUND-SAFE (the withdrawal proof's \
             finalized-root check gates the actual exit), but the close anchor is a placeholder until \
             a validity block is finalized (liveness caveat; see a3-close-lifecycle-spec.md Threat 7)."
        );
    }
    // SECURITY (§10.6 L2): record the backing deposit's existence EXPLICITLY. `Deferred` is a
    // positive statement ("no backing deposit is on-chain yet"), not the absence of a hash — the
    // import guard prints that conclusion instead of silently skipping itself.
    let (backing_deposit_status, backing_deposit_txs) = if no_onchain_deposit {
        (BackingDepositStatus::Deferred, Vec::new())
    } else {
        (BackingDepositStatus::Landed, vec![txhash.clone()])
    };
    write_private_json(
        BACKING_FILE,
        &ChannelBacking {
            settled_tx_chain: pis.settled_tx_chain.to_hex(),
            // A-3 P1: REAL L1-close anchor (rollup latestFinalizedStateRoot at backing time).
            intmax_state_root: intmax_state_root.to_hex(),
            fund,
            rollup: rollup.clone(),
            deposit_tx: txhash.clone(),
            backing_deposit_txs,
            backing_deposit_status,
            deposit_salt: Some(deposit_salt),
            deposit_recipient: recipient.to_hex(),
            base_private_state: Some(bwg.full_private_state.clone()),
        },
    );
    // SECURITY (§10.2, second aggravating detail): this line used to say "REAL on-chain deposit"
    // UNCONDITIONALLY, so in deferred mode stdout read `… tx )` with an empty hash while the only
    // warning went to stderr. An operator — or a stdout-scraping script — was told a deposit had
    // been made when none had. Report what actually happened, on the stream that is read.
    let settled = pis.settled_tx_chain.to_hex();
    let channel = channel_id_env();
    if no_onchain_deposit {
        println!(
            "setup-backing OK: NO on-chain deposit made — DEFERRED to `withdraw` \
             (SETUP_BACKING_NO_ONCHAIN_DEPOSIT is set). Channel {channel} is backed by an \
             off-chain balance proof only until `withdraw` runs (IntmaxRollup {rollup}); \
             settled_tx_chain={settled}. Now run `init`."
        );
    } else {
        println!(
            "setup-backing OK: REAL on-chain deposit {fund} to channel {channel} (IntmaxRollup \
             {rollup}, tx {txhash}); settled_tx_chain={settled}. Now run `init`."
        );
    }
}

/// A-3 P3: the close-intent descriptor written to `close_intent.json` — the SAME schema
/// `generate_close_fixture` produces and `ChannelSettlementManager.submitCloseIntent` consumes
/// (every field is a PROVED close public input, no fabrication).
#[derive(Serialize)]
struct CloseIntentDescriptor {
    channel_id: u32,
    close_nonce: u64,
    final_epoch: u64,
    final_small_block_number: u64,
    close_freeze_nonce: u64,
    final_channel_state_digest: String,
    final_balance_state_h1: String,
    channel_fund_amount: String,
    channel_fund_intmax_state_root: String,
    burn_tx_hash: String,
    close_withdrawal_digest: String,
    snapshot_medium_block_number: u64,
    final_state_version: u64,
    final_settled_tx_chain: String,
    final_settled_tx_accumulator_root: String,
    close_intent_digest: String,
    member_set_commitment: String,
    member_count: u8,
    delegate_count: u16,
    member_pk_gs: Vec<String>,
    /// Multi-token (§N-6, Phase 5b): the FULL per-token fund vector of the proved final state
    /// (10 x 0x-hex U256, registry-aligned; `[0]` == the legacy `channel_fund_amount` burn leg).
    /// The on-chain verifier RECOMPUTES `token_funds_digest` over exactly these three fields and
    /// binds it to the member-signed PI (limbs 95..103) — RunClose parses them verbatim.
    channel_fund_amounts: Vec<String>,
    /// Multi-token: the final state's base-token registry (10 x u32, active prefix).
    token_registry: Vec<u32>,
    /// Multi-token: number of ACTIVE registry slots (1..=10).
    token_count: u8,
}

/// Read the two monotone/equality guards that make a member close request one-shot, from one
/// hash-authenticated durable block. The final checkpoint revalidation is deliberately performed
/// immediately before the signer is asked to create a transaction; if state changes afterwards,
/// the Manager's atomic equality checks make the old calldata revert.
fn send_guarded_member_close_request(rpc: &str, manager: &str, signer: &L1Signer) {
    let chain_id = rpc_chain_id(rpc);
    let checkpoint = read_durable_l1_checkpoint(rpc, chain_id);
    let status = parse_u64_quantity(
        &cast_call_at(
            rpc,
            manager,
            "channelStatus()",
            &[],
            checkpoint.block_number,
        ),
        "durable manager channelStatus",
    );
    if status != 0 {
        die(format!(
            "manager is not Active at durable block {} (channelStatus={status}); refusing to sign requestClose",
            checkpoint.block_number
        ));
    }
    let freeze_nonce = parse_u64_quantity(
        &cast_call_at(
            rpc,
            manager,
            "currentCloseFreezeNonce()",
            &[],
            checkpoint.block_number,
        ),
        "durable currentCloseFreezeNonce",
    );
    let cancellation_floor = parse_u64_quantity(
        &cast_call_at(
            rpc,
            manager,
            "highestCancelledRevivedStateVersion()",
            &[],
            checkpoint.block_number,
        ),
        "durable highestCancelledRevivedStateVersion",
    );
    require_stable_durable_l1_checkpoint(rpc, &checkpoint);

    let freeze_nonce = freeze_nonce.to_string();
    let cancellation_floor = cancellation_floor.to_string();
    cast_signed(
        rpc,
        signer,
        &[
            "send",
            manager,
            "requestClose(uint64,uint64)",
            &freeze_nonce,
            &cancellation_floor,
        ],
    );
}

/// Read the exact pending close identity from one durable block. `getPendingClose()` is requested
/// without return types so `cast` yields raw ABI words; the first seven fixed words end at the
/// proof-bound close-intent digest and are independent of the later fixed-array expansion.
fn durable_pending_close_guard(rpc: &str, manager: &str) -> (String, u64) {
    let chain_id = rpc_chain_id(rpc);
    let checkpoint = read_durable_l1_checkpoint(rpc, chain_id);
    let status = parse_u64_quantity(
        &cast_call_at(
            rpc,
            manager,
            "channelStatus()",
            &[],
            checkpoint.block_number,
        ),
        "durable manager channelStatus",
    );
    if status != 1 {
        die(format!(
            "manager has no pending close at durable block {} (channelStatus={status}); refusing to sign finalize",
            checkpoint.block_number
        ));
    }
    let encoded = cast_call_at(
        rpc,
        manager,
        "getPendingClose()",
        &[],
        checkpoint.block_number,
    );
    let words = encoded
        .trim()
        .strip_prefix("0x")
        .or_else(|| encoded.trim().strip_prefix("0X"))
        .unwrap_or_else(|| die("getPendingClose returned non-hex ABI data"));
    if words.len() < 7 * 64 || !words.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        die("getPendingClose returned truncated or malformed ABI data");
    }
    let active = u64::from_str_radix(abi_word(words, 0), 16)
        .unwrap_or_else(|error| die(format!("parse getPendingClose.active: {error}")));
    if active != 1 {
        die("manager status is ClosePending but getPendingClose.active is false");
    }
    let digest = format!("0x{}", abi_word(words, 6));
    let parsed_digest = Bytes32::from_hex(&digest)
        .unwrap_or_else(|error| die(format!("parse pending close-intent digest: {error:?}")));
    if parsed_digest == Bytes32::default() {
        die("pending close-intent digest is zero; refusing guarded finalize");
    }
    let generation = parse_u64_quantity(
        &cast_call_at(
            rpc,
            manager,
            "closeRequestGeneration()",
            &[],
            checkpoint.block_number,
        ),
        "durable closeRequestGeneration",
    );
    if generation == 0 {
        die("pending close has zero request generation; refusing guarded finalize");
    }
    require_stable_durable_l1_checkpoint(rpc, &checkpoint);
    (digest, generation)
}

/// A-3 P3: build the channel's REAL close-intent proof from the wallet's final signed state + the N
/// co-signing members' keys + the base-layer balance proof, write the on-chain artifacts, and
/// submit the close to L1: `requestClose` (cast) then `submitCloseIntent` (the wrapped-close MLE
/// proof is large struct calldata, so it goes through the `RunClose` forge step). Usage:
///   channel_member close <manager_addr> [rpc_url]
/// env: CLOSE_SV (settlement verifier). Close nonce/snapshot/burn metadata is canonical and has no
/// caller input: nonce = signed close_freeze_nonce + 1, snapshot = 0, burn hash = 0.
fn cmd_close(args: &[String]) {
    let manager = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| die("close needs <manager_addr> [rpc_url]"));
    let rpc = args
        .get(2)
        .cloned()
        .unwrap_or_else(|| "http://localhost:8545".to_string());
    let supplied_sv = std::env::var("CLOSE_SV")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let settlement_binding =
        require_active_settlement_binding(&rpc, &manager, supplied_sv.as_deref(), None);
    let sv = supplied_sv.unwrap_or_else(|| {
        settlement_binding
            .verifier
            .clone()
            .unwrap_or_else(|| die("ACTIVE settlement binding has no verifier"))
    });
    let l1_signer = LazyL1Signer::new(&rpc);

    // Phase control (opt-in; default = the combined requestClose + submitCloseIntent flow):
    //   CLOSE_REQUEST_ONLY=1 → A26 requestClose-only (freeze + grace), NO proving, return early.
    //   CLOSE_SKIP_REQUEST=1 → A28 submit-intent / A29 challenge: skip requestClose (the channel is
    //     already ClosePending), build the proof and submit the (possibly higher-version) intent.
    // SECURITY: pure on-chain call-sequence control; the proof + the manager/verifier gate every
    // soundness property. Skipping requestClose cannot weaken the close — submitCloseIntent still
    // verifies the wrapped MLE proof and the manager enforces challenge ordering (epoch, version).
    let skip_request = std::env::var("CLOSE_SKIP_REQUEST").is_ok();
    if std::env::var("CLOSE_REQUEST_ONLY").is_ok() {
        eprintln!(
            "[close] guarded requestClose on manager {manager} (A26 request-only phase, no proving)…"
        );
        send_guarded_member_close_request(&rpc, &manager, l1_signer.get());
        if let Ok(secs) = std::env::var("CLOSE_ADVANCE_TIME") {
            eprintln!(
                "[close] advancing chain time by {secs}s (evm_increaseTime) to pass the grace window…"
            );
            cast(&["rpc", "evm_increaseTime", &secs, "--rpc-url", &rpc]);
            cast(&["rpc", "evm_mine", "--rpc-url", &rpc]);
        }
        println!(
            "[close] requestClose submitted; channel ClosePending. Run submit-intent (CLOSE_SKIP_REQUEST=1) after the grace window."
        );
        return;
    }

    // F4: resolve the contracts checkout NOW — the staging + forge step at the end of this command
    // is the ONLY thing here that touches it, and reaching it after the close proof is what made a
    // path error cost a full proof. (Not hoisted above the CLOSE_REQUEST_ONLY branch on purpose:
    // that branch is a pure `cast send` and legitimately needs no checkout.)
    let contracts_dir = require_contracts_dir("close", &["script/RunClose.s.sol"]);

    // Load the final signed state and the base-layer balance proof.
    //
    // SECURITY (detached close signing, design Option A): this command derives NO co-signer key.
    // The N-of-N Falcon cosignatures the close proof needs are already in the head state — every
    // route to becoming the head runs `verify_all_signatures` (`finalize`) or constructs the full
    // set (`create-channel` / `cosign`), and those signatures are over `state.signing_digest()`,
    // which IS the digest the close circuit binds. Re-deriving keys here to re-mint equivalent
    // signatures is what forced one process to hold every member's secret key; it is gone.
    let st = load_state();
    let state = st.snapshot.state.clone();
    let record = st.snapshot.record.clone();
    let member_count = state.balance_state.member_count as usize;
    let (balance_vd, att, backing) = load_backing();
    if strip0x(&backing.rollup) != strip0x(&settlement_binding.rollup) {
        die(format!(
            "channel backing rollup {} differs from durable ACTIVE rollup {}",
            backing.rollup, settlement_binding.rollup
        ));
    }
    let balance_proof = ProofWithPublicInputs::<BF, BC, BD>::from_bytes(
        att.balance_proof.clone(),
        &balance_vd.common,
    )
    .unwrap_or_else(|e| die(format!("deserialize balance proof: {e}")));

    eprintln!(
        "[close] building close witness (member_count={member_count}) + proving close circuit + MLE (HEAVY)…"
    );
    let prover = CloseProver::new(&balance_vd);
    let falcon_artifact = cache_falcon_aggregate(prover.falcon_context(), &record, &state)
        .unwrap_or_else(|e| die(format!("Falcon aggregate cache: {e}")));
    let witness = prover
        .build_full_witness_from_aggregate(&record, &state, &falcon_artifact, balance_proof)
        .unwrap_or_else(|e| die(format!("build close witness: {}", e.0)));
    let close_proof = prover
        .prove(&witness)
        .unwrap_or_else(|e| die(format!("close proof: {}", e.0)));
    let mle_json = prover
        .prove_mle(&close_proof)
        .unwrap_or_else(|e| die(format!("close MLE: {}", e.0)));

    // Descriptor from the PROVED close public inputs (the 103 raw close limbs the manager
    // re-binds).
    let pi_limbs = close_proof.public_inputs[..CHANNEL_CLOSE_PUBLIC_INPUTS_LEN].to_u64_vec();
    let pis = ChannelClosePublicInputs::from_u64_slice(&pi_limbs)
        .unwrap_or_else(|e| die(format!("decode close PIs: {e:?}")));
    let member_pk_gs: Vec<String> = witness
        .member_auth
        .iter()
        .map(|a| a.pk_g.to_string())
        .collect();
    let descriptor = CloseIntentDescriptor {
        channel_id: pis.channel_id.channel_id(),
        close_nonce: pis.close_nonce,
        final_epoch: pis.final_epoch,
        final_small_block_number: pis.final_small_block_number,
        close_freeze_nonce: pis.close_freeze_nonce,
        final_channel_state_digest: pis.final_channel_state_digest.to_string(),
        final_balance_state_h1: pis.final_balance_state_h1.to_string(),
        channel_fund_amount: pis.channel_fund_amount.to_string(),
        channel_fund_intmax_state_root: pis.channel_fund_intmax_state_root.to_string(),
        burn_tx_hash: pis.burn_tx_hash.to_string(),
        close_withdrawal_digest: pis.close_withdrawal_digest.to_string(),
        snapshot_medium_block_number: pis.snapshot_medium_block_number,
        final_state_version: pis.final_state_version,
        final_settled_tx_chain: pis.final_settled_tx_chain.to_string(),
        final_settled_tx_accumulator_root: pis.final_settled_tx_accumulator_root.to_string(),
        close_intent_digest: pis.close_intent_digest.to_string(),
        member_set_commitment: pis.member_set_commitment.to_string(),
        member_count: pis.member_count,
        delegate_count: pis.delegate_count,
        member_pk_gs,
        // Multi-token (§N-6): the SAME signed state the close witness proved — the verifier's
        // tokenFundsDigest recompute over these must equal the proof's PI limbs 95..103.
        channel_fund_amounts: state
            .channel_fund
            .amounts
            .iter()
            .map(|a| a.to_string())
            .collect(),
        token_registry: state.balance_state.token_registry.to_vec(),
        token_count: state.balance_state.token_count,
    };

    fs::write(CLOSE_INTENT_MLE_FILE, &mle_json)
        .unwrap_or_else(|e| die(format!("write {CLOSE_INTENT_MLE_FILE}: {e}")));
    write_json(CLOSE_INTENT_FILE, &descriptor);

    // A30 prerequisite: persist the EXACT pending `CloseIntent` (lossless serde) so a later
    // `cancel-close` reconstructs the same close_intent_digest the manager just froze on-chain.
    // Reconstructed identically to `cmd_claim` from the state that was closed; all legacy
    // metadata fields are derived canonically by `CloseIntent::new`.
    let close_tx = CloseWithdrawal {
        channel_id: state.channel_id,
        final_channel_state_digest: state.digest,
        final_balance_state_h1: state.balance_state.h1(),
        intmax_state_root: state.channel_fund.intmax_state_root,
        burn_tx_hash: Bytes32::default(),
        burn_amount: state.channel_fund.amounts[0],
        zkp: Vec::new(),
    };
    let close_intent = CloseIntent::new(&state, &close_tx)
        .unwrap_or_else(|e| die(format!("reconstruct close intent for persistence: {e:?}")));
    write_json(CLOSE_INTENT_FULL_FILE, &close_intent);
    println!(
        "[close] wrote {CLOSE_INTENT_FILE} + {CLOSE_INTENT_MLE_FILE} + {CLOSE_INTENT_FULL_FILE} (close_intent_digest {})",
        pis.close_intent_digest.to_hex()
    );

    // ── On-chain: requestClose (freeze) then submitCloseIntent (large calldata → forge step). ──
    // When CLOSE_SKIP_REQUEST is set (A28 submit-after-request / A29 challenge), the channel is
    // ALREADY ClosePending — skip requestClose (it would revert) and go straight to the intent.
    if skip_request {
        eprintln!(
            "[close] CLOSE_SKIP_REQUEST set: skipping requestClose (submit-intent / challenge on an already-pending close)…"
        );
    } else {
        eprintln!("[close] guarded requestClose on manager {manager}…");
        send_guarded_member_close_request(&rpc, &manager, l1_signer.get());
    }

    // GRACE: the manager rejects the FIRST close intent until `GRACE_BEFORE_PROCESS_SECS` (600s)
    // after requestClose (so members can settle any pending tx first). In production this is real
    // wall-clock waiting; on a dev chain set `CLOSE_ADVANCE_TIME=<secs>` to fast-forward via
    // anvil's evm_increaseTime so `submitCloseIntent` is not rejected with
    // `GracePeriodNotElapsed`. (A challenge replaces an existing intent, so no new grace applies.)
    if !skip_request && std::env::var("CLOSE_ADVANCE_TIME").is_ok() {
        let secs = std::env::var("CLOSE_ADVANCE_TIME").unwrap();
        eprintln!(
            "[close] advancing chain time by {secs}s (evm_increaseTime) to pass the close grace window…"
        );
        cast(&["rpc", "evm_increaseTime", &secs, "--rpc-url", &rpc]);
        cast(&["rpc", "evm_mine", "--rpc-url", &rpc]);
    }

    // The RunClose forge step reads the close artifacts from `contracts/test/data/sepolia_close_*`
    // and submits the large-struct calldata. Stage the just-generated artifacts there and run it.
    let data_dir = contracts_dir.join("test/data");
    fs::copy(
        CLOSE_INTENT_FILE,
        data_dir.join("sepolia_close_intent.json"),
    )
    .unwrap_or_else(|e| die(format!("stage close_intent.json: {e}")));
    fs::copy(
        CLOSE_INTENT_MLE_FILE,
        data_dir.join("sepolia_close_intent_mle.json"),
    )
    .unwrap_or_else(|e| die(format!("stage close_intent_mle.json: {e}")));
    eprintln!("[close] submitCloseIntent via forge RunClose step…");
    let mut forge = std::process::Command::new("forge");
    forge.current_dir(&contracts_dir).args([
        "script",
        "script/RunClose.s.sol",
        "--sig",
        "closeIntentStep()",
        "--rpc-url",
        &rpc,
        "--broadcast",
    ]);
    l1_signer.get().append_to_command(&mut forge);
    let status = forge
        .env("ROLLUP", &backing.rollup)
        .env("MANAGER", &manager)
        .env("SV", &sv)
        .status()
        .unwrap_or_else(|e| die(format!("forge submitCloseIntent failed to start: {e}")));
    if !status.success() {
        die(
            "forge submitCloseIntent step failed (set CLOSE_SV to the settlement verifier address; ensure the close VK is initialized)",
        );
    }
    println!(
        "[close] close intent submitted on-chain. Wait the challenge period, then run `settle`."
    );
}

/// A-3 P4: finalize the close after the challenge period has elapsed. The close was already proven
/// at submit time; the two small guard arguments bind the signed transaction to its exact digest
/// and manager-lifetime request generation so cancellation cannot redirect an old raw transaction.
/// Usage: channel_member settle <manager_addr> [rpc_url]
fn cmd_settle(args: &[String]) {
    let manager = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| die("settle needs <manager_addr> [rpc_url]"));
    let rpc = args
        .get(2)
        .cloned()
        .unwrap_or_else(|| "http://localhost:8545".to_string());
    require_active_settlement_binding(&rpc, &manager, None, None);
    let l1_signer = LazyL1Signer::new(&rpc);
    let (close_intent_digest, close_request_generation) =
        durable_pending_close_guard(&rpc, &manager);
    eprintln!(
        "[settle] finalizeCloseGuarded on manager {manager} for generation {close_request_generation} (the challenge period must have elapsed)…"
    );
    let generation = close_request_generation.to_string();
    cast_signed(
        &rpc,
        l1_signer.get(),
        &[
            "send",
            &manager,
            "finalizeCloseGuarded(bytes32,uint64)",
            &close_intent_digest,
            &generation,
        ],
    );
    println!(
        "[settle] channel finalized (Closed). Now run `withdraw` (rollup → manager) then `claim`."
    );
}

/// A-3 P4: the withdrawal-claim descriptor (the on-chain `ChannelSettlementManager.WithdrawalClaim`
/// fields, every value a PROVED withdrawal-claim public input).
#[derive(Serialize, Deserialize)]
struct WithdrawalClaimDescriptor {
    close_intent_digest: String,
    member_pk_g: String,
    recipient: String,
    user_amount_digest: String,
    amount: u64,
    withdrawal_nullifier: String,
    /// Multi-token (§N-6): the claimed LOCAL token slot (claim PI limb 48).
    token_slot: u8,
    /// Multi-token (§N-6, m8): the PROVED base `token_index = registry[token_slot]` the Manager
    /// pays this claim in (claim PI limb 49).
    token_index: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct WithdrawalPayoutView {
    recipient: Address,
    token_index: u32,
    amount: U256,
}

fn read_withdrawal_payout(
    rpc: &str,
    manager: &str,
    withdrawal_nullifier: Bytes32,
) -> WithdrawalPayoutView {
    let raw = cast_call(
        rpc,
        manager,
        "withdrawalPayouts(bytes32)(address,uint32,uint256)",
        &[&withdrawal_nullifier.to_hex()],
    );
    let normalized = raw.replace(['(', ')', '[', ']', ','], " ");
    let fields: Vec<&str> = normalized.split_whitespace().collect();
    if fields.len() != 3 {
        die(format!(
            "withdrawalPayouts({withdrawal_nullifier}) returned an unexpected tuple {raw:?}"
        ));
    }
    let recipient = Address::from_hex(fields[0])
        .unwrap_or_else(|e| die(format!("parse withdrawal payout recipient: {e:?}")));
    let parse_u32 = |raw: &str| -> u32 {
        let value = if let Some(hex) = raw.strip_prefix("0x") {
            u64::from_str_radix(hex, 16)
        } else {
            raw.parse::<u64>()
        }
        .unwrap_or_else(|e| die(format!("parse withdrawal payout token index: {e}")));
        u32::try_from(value).unwrap_or_else(|_| die("withdrawal payout token index exceeds uint32"))
    };
    let amount = fields[2]
        .parse::<U256>()
        .unwrap_or_else(|e| die(format!("parse withdrawal payout amount: {e:?}")));
    WithdrawalPayoutView {
        recipient,
        token_index: parse_u32(fields[1]),
        amount,
    }
}

fn validate_withdrawal_claimed_receipt(
    receipt_raw: &str,
    manager: &str,
    withdrawal_nullifier: Bytes32,
    recipient: Address,
    token_index: u32,
    amount: u64,
) -> Result<(), String> {
    fn checked_abi_u64(word: &str, what: &str) -> Result<u64, String> {
        let body = word.strip_prefix("0x").unwrap_or(word);
        if body.len() != 64 || !body.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!(
                "{what} is not one canonical 32-byte ABI word: {word:?}"
            ));
        }
        if body[..48].chars().any(|c| c != '0') {
            return Err(format!("{what} exceeds u64"));
        }
        u64::from_str_radix(&body[48..], 16).map_err(|e| format!("parse {what}: {e}"))
    }

    let receipt: serde_json::Value = serde_json::from_str(receipt_raw.trim())
        .map_err(|e| format!("parse claim receipt: {e}"))?;
    let status = receipt["status"]
        .as_str()
        .map(|raw| raw == "0x1" || raw == "1")
        .or_else(|| receipt["status"].as_u64().map(|status| status == 1))
        .unwrap_or(false);
    if !status {
        return Err("claimWithdrawalCredit receipt is not successful".into());
    }
    if !receipt["to"]
        .as_str()
        .is_some_and(|to| same_hex_value(to, manager))
    {
        return Err("claimWithdrawalCredit receipt target differs from the bound manager".into());
    }

    let topic0 = format!(
        "0x{}",
        hex::encode(keccak_hash::keccak(b"WithdrawalClaimed(bytes32,address,uint32,uint256)").0)
    );
    let logs = receipt["logs"]
        .as_array()
        .ok_or_else(|| "claimWithdrawalCredit receipt has no logs array".to_string())?;
    let mut matched = 0usize;
    for log in logs {
        if !log["address"]
            .as_str()
            .is_some_and(|address| same_hex_value(address, manager))
        {
            continue;
        }
        let Some(topics) = log["topics"].as_array() else {
            continue;
        };
        if !topics
            .first()
            .and_then(serde_json::Value::as_str)
            .is_some_and(|topic| same_hex_value(topic, &topic0))
        {
            continue;
        }
        if log["removed"].as_bool() == Some(true) || topics.len() != 4 {
            return Err("WithdrawalClaimed event is removed or has the wrong topic count".into());
        }
        let topic = |index: usize| -> Result<&str, String> {
            topics[index]
                .as_str()
                .ok_or_else(|| format!("WithdrawalClaimed topic {index} is not a string"))
        };
        let recipient_topic = topic(2)?.trim_start_matches("0x");
        let recipient_hex = recipient.to_hex();
        let recipient_body = recipient_hex.trim_start_matches("0x");
        let data = log["data"]
            .as_str()
            .ok_or_else(|| "WithdrawalClaimed data is not a string".to_string())?
            .trim_start_matches("0x");
        if !same_hex_value(topic(1)?, &withdrawal_nullifier.to_hex())
            || recipient_topic.len() != 64
            || !recipient_topic[..24].bytes().all(|byte| byte == b'0')
            || !recipient_topic[24..].eq_ignore_ascii_case(recipient_body)
            || checked_abi_u64(topic(3)?, "WithdrawalClaimed.tokenIndex")? != u64::from(token_index)
            || data.len() != 64
            || checked_abi_u64(data, "WithdrawalClaimed.amount")? != amount
        {
            return Err(
                "WithdrawalClaimed event differs from the bound nullifier/recipient/token/amount"
                    .into(),
            );
        }
        matched += 1;
    }
    if matched != 1 {
        return Err(format!(
            "expected exactly one bound WithdrawalClaimed event, observed {matched}"
        ));
    }
    Ok(())
}

/// Pay exactly one proof-scoped payout. Both the pre-call getter and the emitted event bind the
/// same nullifier, recipient, token and amount; aggregate withdrawal credit is never used as a
/// selector. The post-call getter must be deleted, proving this exact payout cannot be replayed.
fn claim_withdrawal_credit_bound(
    rpc: &str,
    signer: &L1Signer,
    manager: &str,
    withdrawal_nullifier: Bytes32,
    recipient: Address,
    token_index: u32,
    amount: u64,
) {
    let signer_address = signer.address();
    if !same_hex_value(&signer_address, &recipient.to_hex()) {
        die(format!(
            "claimWithdrawalCredit signer {signer_address} is not the proof-bound recipient {}",
            recipient.to_hex()
        ));
    }
    let expected = WithdrawalPayoutView {
        recipient,
        token_index,
        amount: U256::from(amount),
    };
    let before = read_withdrawal_payout(rpc, manager, withdrawal_nullifier);
    if before != expected {
        die(format!(
            "withdrawalPayouts({withdrawal_nullifier}) = {before:?}, expected the exact \
             proof-scoped payout {expected:?}"
        ));
    }

    let receipt = cast_signed(
        rpc,
        signer,
        &[
            "send",
            manager,
            "claimWithdrawalCredit(bytes32)",
            &withdrawal_nullifier.to_hex(),
            "--json",
        ],
    );
    validate_withdrawal_claimed_receipt(
        &receipt,
        manager,
        withdrawal_nullifier,
        recipient,
        token_index,
        amount,
    )
    .unwrap_or_else(|error| die(format!("claimWithdrawalCredit receipt mismatch: {error}")));

    let after = read_withdrawal_payout(rpc, manager, withdrawal_nullifier);
    if after.recipient != Address::default()
        || after.token_index != 0
        || after.amount != U256::default()
    {
        die(format!(
            "withdrawalPayouts({withdrawal_nullifier}) was not consumed after its exact claim"
        ));
    }
}

/// Env override naming the keygen LABEL to derive the claimant's key from, when it is not the
/// label this binary would infer. Fail-closed either way: the derived identity is still checked
/// against the signed slot leaf below, so a wrong label is a refusal, never a wrong claim.
const CLAIM_KEYGEN_LABEL_ENV: &str = "CLAIM_KEYGEN_LABEL";

/// Resolve the `MemberKeys` that OWN balance slot `slot`, and REFUSE unless the derived identity is
/// the one the channel's signed state actually committed to that slot.
///
/// F8 (doc/audit/exit-path-facade-sweep.md). `claim` and `post-close-claim` used to hard-code
/// `keys_for(CLI_COSIGNER_SEED_BASE + slot)` — the OPERATOR's co-signer derivation — for whatever
/// slot the caller named. For a CLI co-signer slot that is the right key. For a BROWSER DELEGATE it
/// is a different key entirely: a delegate generates its own Regev keypair in the browser
/// (`wasm_wallet::wallet_keygen`) and the secret never leaves it, so the operator's derivation can
/// never reproduce it. The old code then spent the entire heavy claim proof before the in-circuit
/// slot-leaf bind rejected it, with an error that named neither the cause nor the fact that the
/// delegate has no working path at all.
///
/// SECURITY: this is the NATIVE MIRROR of a binding the circuit already enforces — the claim
/// circuit opens slot leaf `slot` by inclusion and one-hot-binds the witnessed Regev `(a, b)` to
/// the H1-committed `regev_pk_digests[slot]` (`withdrawal_claim_pis.rs`,
/// `post_close_claim_pis.rs:160-172`). It REPLACES NOTHING and WEAKENS NOTHING; it moves the same
/// predicate to before the proof so an impossible claim fails in milliseconds with an explanation
/// instead of in minutes without one. `post_close_claim_pis` already carries this check natively;
/// `withdrawal_claim_pis` binds it in-circuit only, which is why the CLI-side check matters most
/// for `claim`.
fn claim_keys_for_slot(
    cmd: &str,
    controlled: &[ControlledMember],
    final_balance_state: &BalanceState,
    slot: u16,
) -> MemberKeys {
    let active =
        final_balance_state.member_count as usize + final_balance_state.delegate_count as usize;
    if slot as usize >= active {
        die(format!(
            "`{cmd}`: slot {slot} is a PADDING slot of the signed final state (active slots are \
             0..{active} = member_count {} + delegate_count {}). Padding slots hold the canonical \
             zero ciphertext and are not claimable.",
            final_balance_state.member_count, final_balance_state.delegate_count
        ));
    }

    // Which keygen label owns this slot, in order of authority:
    //   1. an explicit operator override (still gated by the leaf check below);
    //   2. the slot's OWN recorded label in `cli_state.controlled` — the same single source of
    //      truth every co-signing command uses (`keys_for(c.keygen_seed)`), rather than a second
    //      copy of the `CLI_COSIGNER_SEED_BASE + slot` formula (the Phase-3 finding-7 shape);
    //   3. the DEMO delegate's label, for a slot past the co-signer range;
    //   4. the historical co-signer formula, so a state file predating `controlled` still resolves.
    // NONE of these is a fallback in the dangerous sense: whichever label is chosen, the identity
    // it derives is checked against the signed leaf and a mismatch is fatal.
    let (label, label_src) = match std::env::var(CLAIM_KEYGEN_LABEL_ENV) {
        Ok(raw) if !raw.trim().is_empty() => (
            raw.trim().parse::<u64>().unwrap_or_else(|_| {
                die(format!(
                    "{CLAIM_KEYGEN_LABEL_ENV}={raw:?} is not a u64 keygen label"
                ))
            }),
            format!("{CLAIM_KEYGEN_LABEL_ENV} override"),
        ),
        _ => match controlled.iter().find(|c| c.slot == slot) {
            Some(c) => (c.keygen_seed, "cli_state.controlled".to_string()),
            None if slot >= cli_cosigner_count() => {
                (delegate_seed(), "DELEGATE_SEED (demo delegate)".to_string())
            }
            None => (
                CLI_COSIGNER_SEED_BASE + slot as u64,
                "CLI co-signer slot formula".to_string(),
            ),
        },
    };

    let keys = keys_for(label);
    let derived = Bytes32::from(keys.regev_pk.poseidon_digest());
    let committed = final_balance_state.regev_pk_digests[slot as usize];
    if derived != committed {
        die(format!(
            "`{cmd}`: THIS CLI CANNOT CLAIM FOR BALANCE SLOT {slot}.\n\
             \n\
             The channel's signed state commits slot {slot}'s Regev public key as\n  \
               {}\n\
             but the key this host derives for it (label {label}, chosen from {label_src}) is\n  \
               {}\n\
             so this process does NOT hold the secret key that slot {slot}'s balance ciphertext is \
             encrypted under. Every claim proof it could build would be rejected — by the E-3 \
             decryption proof, or by the circuit's slot-leaf Regev-pk bind.\n\
             \n\
             WHO CAN USE `{cmd}`: a slot whose key material comes from THIS host's co-signer \
             master ({COSIGNER_KEYFILE_ENV}) — i.e. the CLI co-signer slots this process controls \
             (0..{}), plus a DEMO delegate created by `gen-contribution` with a DELEGATE_SEED this \
             host can reproduce.\n\
             WHO CANNOT USE THIS CLI: a REAL BROWSER/NODE DELEGATE. It generates its own Regev \
             keypair with `wallet_keygen[_seeded]` and that secret NEVER leaves the WASM session. \
             Such a delegate must use `wallet_withdrawal_claim`, which proves and self-verifies \
             inside WASM and exports only public claim/MLE calldata; this native CLI intentionally \
             cannot reproduce that secret-owned claim.\n\
             \n\
             REFUSING before proving rather than spending minutes building a claim for an identity \
             that is not the slot owner's. If you believe this host does own the slot under a \
             different keygen label, set {CLAIM_KEYGEN_LABEL_ENV}=<u64> — it is checked against the \
             same signed leaf and cannot be used to claim someone else's balance.",
            committed.to_hex(),
            derived.to_hex(),
            cli_cosigner_count(),
        ));
    }
    eprintln!(
        "[{cmd}] slot {slot} identity confirmed against the signed slot leaf (label from \
         {label_src})"
    );
    keys
}

/// A-3 P4: a member claims their slot balance from the CLOSED channel. Builds the withdrawal-claim
/// MLE proof via the verified `WithdrawalClaimProver` (the amount is DERIVED by decrypting the
/// member's own slot ciphertext, so it cannot over-claim), submits it (`submitWithdrawalClaim` via
/// the forge step), then consumes that proof's exact nullifier-scoped payout
/// (`claimWithdrawalCredit(bytes32)`). Usage:
///   channel_member claim <manager_addr> <member_slot> [rpc_url] [token_slot]
/// `token_slot` (OPTIONAL, default 0 = genesis token): claims are per (member slot, token slot);
/// the circuit resolves + proves the base token_index the Manager pays (§N-6). Native and ERC-20
/// payouts use the same nullifier-scoped entry point; unsafe aggregate overloads are never called.
/// env: CLAIM_RECIPIENT (the member's registered L1 address; also the claimWithdrawalCredit
/// caller). Close metadata is reconstructed canonically from the finalized signed state.
fn cmd_claim(args: &[String]) {
    let manager = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| die("claim needs <manager_addr> <member_slot> [rpc_url] [token_slot]"));
    let member_slot: u16 = args
        .get(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| die("claim needs <member_slot>"));
    let rpc = args
        .get(3)
        .cloned()
        .unwrap_or_else(|| "http://localhost:8545".to_string());
    let token_slot: u8 = args
        .get(4)
        .map(|s| s.parse().unwrap_or_else(|_| die("bad [token_slot]")))
        .unwrap_or(0);
    require_active_settlement_binding(&rpc, &manager, None, None);
    let recipient = std::env::var("CLAIM_RECIPIENT")
        .ok()
        .and_then(|s| Address::from_hex(&s).ok())
        .unwrap_or_else(|| {
            die("set CLAIM_RECIPIENT=0x<20-byte member L1 recipient> (must equal the registered recipient)")
        });
    let l1_signer = LazyL1Signer::new(&rpc);

    // A33 pull-only phase (opt-in): replay the exact proof-scoped nullifier recorded with the
    // submitted claim. Aggregate recipient/token credit entry points are permanently disabled.
    if std::env::var("CLAIM_PULL_ONLY").is_ok() {
        let recipient_hex = recipient.to_hex();
        let descriptor: WithdrawalClaimDescriptor = read_json("withdrawal_claim.json");
        let nullifier = Bytes32::from_hex(&descriptor.withdrawal_nullifier)
            .unwrap_or_else(|e| die(format!("withdrawal_claim.json nullifier: {e:?}")));
        let descriptor_recipient = Address::from_hex(&descriptor.recipient)
            .unwrap_or_else(|e| die(format!("withdrawal_claim.json recipient: {e:?}")));
        if descriptor_recipient != recipient {
            die("pull-only withdrawal claim recipient differs from CLAIM_RECIPIENT");
        }
        eprintln!(
            "[claim] claimWithdrawalCredit({nullifier}) pull-only (recipient {recipient_hex})…"
        );
        claim_withdrawal_credit_bound(
            &rpc,
            l1_signer.get(),
            &manager,
            nullifier,
            recipient,
            descriptor.token_index,
            descriptor.amount,
        );
        println!(
            "[claim] pull-only OK: recipient {recipient_hex} consumed withdrawal payout {nullifier}."
        );
        return;
    }

    // F4: resolve + validate the contracts checkout BEFORE the heavy claim proof (see
    // `require_contracts_dir`). The CLAIM_PULL_ONLY branch above is a pure `cast send` and
    // deliberately stays above this line.
    let contracts_dir = require_contracts_dir("claim", &["script/RunClose.s.sol"]);

    let st = load_state();
    let state = st.snapshot.state.clone();
    let final_balance_state = state.balance_state.clone();
    // Reconstruct the finalized close (MUST match what `close` submitted: same params + state).
    let close_tx = CloseWithdrawal {
        channel_id: state.channel_id,
        final_channel_state_digest: state.digest,
        final_balance_state_h1: state.balance_state.h1(),
        intmax_state_root: state.channel_fund.intmax_state_root,
        burn_tx_hash: Bytes32::default(),
        burn_amount: state.channel_fund.amounts[0],
        zkp: Vec::new(),
    };
    let close_intent = CloseIntent::new(&state, &close_tx)
        .unwrap_or_else(|e| die(format!("reconstruct close intent: {e:?}")));

    // F8: the claimant's identity is the one the SIGNED slot leaf commits, or this command refuses.
    let keys = claim_keys_for_slot("claim", &st.controlled, &final_balance_state, member_slot);
    let member_pk_g = keys.pk_g();
    // The recipient is bound to the cosigner-signed per-slot exit address (B-1b). The witness
    // builder enforces this too (`WithdrawalClaimWitness` → RecipientMismatch); checking it here
    // just moves a certain failure ahead of the proof instead of after it.
    let leaf_recipient = final_balance_state.recipients[member_slot as usize];
    if recipient != leaf_recipient {
        die(format!(
            "claim: CLAIM_RECIPIENT {} is not slot {member_slot}'s signed exit address {}. The \
             claim circuit opens that leaf field and binds it to the payout recipient, so a claim \
             naming any other address cannot verify. Fail-closed BEFORE proving.",
            recipient.to_hex(),
            leaf_recipient.to_hex()
        ));
    }

    eprintln!(
        "[claim] building withdrawal claim for slot {member_slot} token {token_slot} + proving (HEAVY)…"
    );
    let prover = WithdrawalClaimProver::new();
    let witness = prover
        .build_full_witness(
            &final_balance_state,
            member_slot as usize,
            token_slot,
            member_pk_g,
            &keys.regev_pk,
            &keys.regev_sk,
            recipient,
            &close_intent,
            &close_tx,
            RegevSecurityLevel::Production,
        )
        .unwrap_or_else(|e| die(format!("build withdrawal claim: {}", e.0)));
    let proof = prover
        .prove(&witness)
        .unwrap_or_else(|e| die(format!("withdrawal claim proof: {}", e.0)));
    let mle_json = prover
        .prove_mle(&proof)
        .unwrap_or_else(|e| die(format!("withdrawal claim MLE: {}", e.0)));

    let pi_limbs = proof.public_inputs[..WITHDRAWAL_CLAIM_PUBLIC_INPUTS_LEN].to_u64_vec();
    let pis = WithdrawalClaimPublicInputs::from_u64_slice(&pi_limbs)
        .unwrap_or_else(|e| die(format!("decode withdrawal-claim PIs: {e:?}")));
    let descriptor = WithdrawalClaimDescriptor {
        close_intent_digest: pis.close_intent_digest.to_string(),
        member_pk_g: pis.member_pk_g.to_string(),
        recipient: pis.recipient.to_hex(),
        user_amount_digest: pis.user_amount_digest.to_string(),
        amount: pis.amount,
        withdrawal_nullifier: pis.withdrawal_nullifier.to_string(),
        token_slot: pis.token_slot,
        token_index: pis.token_index,
    };

    let wc_file = "withdrawal_claim.json";
    let wc_mle_file = "withdrawal_claim_mle.json";
    fs::write(wc_mle_file, &mle_json).unwrap_or_else(|e| die(format!("write {wc_mle_file}: {e}")));
    write_json(wc_file, &descriptor);
    println!(
        "[claim] wrote {wc_file} + {wc_mle_file} (amount {})",
        pis.amount
    );

    // Stage for the forge submit step, submit, then pull the credit (caller MUST be the recipient).
    let data_dir = contracts_dir.join("test/data");
    fs::copy(wc_file, data_dir.join("sepolia_withdrawal_claim.json"))
        .unwrap_or_else(|e| die(format!("stage withdrawal_claim.json: {e}")));
    fs::copy(
        wc_mle_file,
        data_dir.join("sepolia_withdrawal_claim_mle.json"),
    )
    .unwrap_or_else(|e| die(format!("stage withdrawal_claim_mle.json: {e}")));
    eprintln!("[claim] submitWithdrawalClaim via forge…");
    let mut forge = std::process::Command::new("forge");
    forge.current_dir(&contracts_dir).args([
        "script",
        "script/RunClose.s.sol",
        "--sig",
        "submitWithdrawalClaimStep()",
        "--rpc-url",
        &rpc,
        "--broadcast",
    ]);
    l1_signer.get().append_to_command(&mut forge);
    let status = forge
        .env("MANAGER", &manager)
        .status()
        .unwrap_or_else(|e| die(format!("forge submitWithdrawalClaim failed to start: {e}")));
    if !status.success() {
        die(
            "forge submitWithdrawalClaim step failed (ensure the withdrawal-claim VK is initialized and funds were pulled into the manager)",
        );
    }
    let recipient_hex = recipient.to_hex();
    eprintln!(
        "[claim] claimWithdrawalCredit({}) for exact proof payout (recipient {recipient_hex})…",
        pis.withdrawal_nullifier
    );
    claim_withdrawal_credit_bound(
        &rpc,
        l1_signer.get(),
        &manager,
        pis.withdrawal_nullifier,
        recipient,
        pis.token_index,
        pis.amount,
    );
    println!(
        "[claim] OK: recipient {recipient_hex} consumed proof payout {} (token {}, amount {}).",
        pis.withdrawal_nullifier, pis.token_index, pis.amount
    );
}

/// A30 cancelClose descriptor — the on-chain `ChannelSettlementManager.CancelCloseRequest` fields
/// plus the member pk_g set (so the manager/forge step can confirm the registered member-set
/// commitment matches the proven one). Every value is a PROVED cancel-close public input.
#[derive(Serialize)]
struct CancelCloseDescriptor {
    channel_id: u32,
    close_intent_digest: String,
    member_set_commitment: String,
    revived_state_version: u64,
    revived_channel_state_digest: String,
    member_pk_gs: Vec<String>,
}

/// A-3 H-3 C1 (A30): cancel a PENDING on-chain close by proving the N members kept operating at a
/// strictly HIGHER `state_version` than the close froze. Builds the REAL cancel-close MLE/WHIR
/// proof via `CancelCloseProver` (revived head + the persisted pending `CloseIntent`), writes the
/// artifacts, and submits `cancelClose(request, proof)` via the forge `RunClose` step. Usage:
///   channel_member cancel-close <manager_addr> [rpc_url]
/// env: CANCEL_SV (settlement verifier address, forwarded to the forge step).
///
/// PRECONDITION: a prior `close` persisted `close_intent_full.json` AND the channel head has since
/// advanced to a strictly higher `state_version` (the revived state the members co-signed). The
/// circuit + manager enforce both: revived_version > close.final_state_version, the era fence
/// (revived.close_freeze_nonce + 1 == close.close_freeze_nonce), and `close_intent_digest` ==
/// `pendingClose.closeIntentDigest`. Any mismatch fails closed (no fund movement in cancelClose).
fn cmd_cancel_close(args: &[String]) {
    let manager = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| die("cancel-close needs <manager_addr> [rpc_url]"));
    let rpc = args
        .get(2)
        .cloned()
        .unwrap_or_else(|| "http://localhost:8545".to_string());
    require_active_settlement_binding(&rpc, &manager, None, None);
    let l1_signer = LazyL1Signer::new(&rpc);
    // F4: resolve + validate the contracts checkout BEFORE the heavy cancel proof (see
    // `require_contracts_dir`). A cancel that dies on a path lookup after proving is worse than a
    // cancel that never started: the challenge window is what a cancel is racing.
    let contracts_dir = require_contracts_dir("cancel-close", &["script/RunClose.s.sol"]);

    // The REVIVED (later) signed state is the current committed head. It already carries the N-of-N
    // cosignatures over its own IMCH digest, which is exactly what the cancel circuit binds.
    //
    // SECURITY (detached close signing, design Option A / X-3): this command derives NO co-signer
    // key either. Cancelling a hostile close used to require all N secret keys, which meant only
    // the coordinator could cancel — the very party a cancel defends against. Any holder of a
    // later co-signed head can now build this proof.
    let st = load_state();
    let revived_state = st.snapshot.state.clone();
    let record = st.snapshot.record.clone();
    let member_count = revived_state.balance_state.member_count as usize;

    // The PENDING close being cancelled — the EXACT `CloseIntent` `close` froze on-chain, read back
    // losslessly (NOT a hex-string descriptor round-trip), so the proof's `close_intent_digest`
    // matches `pendingClose.closeIntentDigest` or the manager rejects (CloseIntentDigestMismatch).
    let close_intent: CloseIntent = read_json(CLOSE_INTENT_FULL_FILE);
    if revived_state.balance_state.state_version <= close_intent.final_state_version {
        die(format!(
            "cancel-close: head state_version {} must be STRICTLY > the pending close final_state_version {} \
             (the channel head must have advanced past the close before cancelling)",
            revived_state.balance_state.state_version, close_intent.final_state_version
        ));
    }

    eprintln!(
        "[cancel-close] building cancel witness (member_count={member_count}, revived v{} > close v{}) + proving + MLE (HEAVY)…",
        revived_state.balance_state.state_version, close_intent.final_state_version
    );
    let prover = CancelCloseProver::new();
    let falcon_artifact = cache_falcon_aggregate(prover.falcon_context(), &record, &revived_state)
        .unwrap_or_else(|e| die(format!("Falcon aggregate cache: {e}")));
    let witness = prover
        .build_full_witness_from_aggregate(&record, &revived_state, &falcon_artifact, &close_intent)
        .unwrap_or_else(|e| die(format!("build cancel-close witness: {}", e.0)));
    let cancel_proof = prover
        .prove(&witness)
        .unwrap_or_else(|e| die(format!("cancel-close proof: {}", e.0)));
    let mle_json = prover
        .prove_mle(&cancel_proof)
        .unwrap_or_else(|e| die(format!("cancel-close MLE: {}", e.0)));

    let pi_limbs = cancel_proof.public_inputs[..CANCEL_CLOSE_PUBLIC_INPUTS_LEN].to_u64_vec();
    let pis = CancelClosePublicInputs::from_u64_slice(&pi_limbs)
        .unwrap_or_else(|e| die(format!("decode cancel-close PIs: {e:?}")));
    let member_pk_gs: Vec<String> = witness
        .member_auth
        .iter()
        .map(|a| a.pk_g.to_string())
        .collect();
    let descriptor = CancelCloseDescriptor {
        channel_id: pis.channel_id.channel_id(),
        close_intent_digest: pis.close_intent_digest.to_string(),
        member_set_commitment: pis.member_set_commitment.to_string(),
        revived_state_version: pis.revived_state_version,
        revived_channel_state_digest: pis.revived_channel_state_digest.to_string(),
        member_pk_gs,
    };

    fs::write(CANCEL_CLOSE_MLE_FILE, &mle_json)
        .unwrap_or_else(|e| die(format!("write {CANCEL_CLOSE_MLE_FILE}: {e}")));
    write_json(CANCEL_CLOSE_FILE, &descriptor);
    println!(
        "[cancel-close] wrote {CANCEL_CLOSE_FILE} + {CANCEL_CLOSE_MLE_FILE} (close_intent_digest {})",
        pis.close_intent_digest.to_hex()
    );

    // ── On-chain: cancelClose (large struct calldata → forge step). ──
    let data_dir = contracts_dir.join("test/data");
    fs::copy(
        CANCEL_CLOSE_FILE,
        data_dir.join("sepolia_cancel_close.json"),
    )
    .unwrap_or_else(|e| die(format!("stage cancel_close.json: {e}")));
    fs::copy(
        CANCEL_CLOSE_MLE_FILE,
        data_dir.join("sepolia_cancel_close_mle.json"),
    )
    .unwrap_or_else(|e| die(format!("stage cancel_close_mle.json: {e}")));
    let sv = std::env::var("CANCEL_SV").unwrap_or_default();
    eprintln!("[cancel-close] cancelClose via forge RunClose step…");
    let mut forge = Command::new("forge");
    forge.current_dir(&contracts_dir).args([
        "script",
        "script/RunClose.s.sol",
        "--sig",
        "cancelCloseStep()",
        "--rpc-url",
        &rpc,
        "--broadcast",
    ]);
    l1_signer.get().append_to_command(&mut forge);
    let status = forge
        .env("MANAGER", &manager)
        .env("SV", &sv)
        .status()
        .unwrap_or_else(|e| die(format!("forge cancelClose failed to start: {e}")));
    if !status.success() {
        die(
            "forge cancelClose step failed (set CANCEL_SV to the settlement verifier; ensure the cancel-close VK is initialized and a close is pending)",
        );
    }
    println!("[cancel-close] cancelClose submitted on-chain; channel status restored to Active.");
}

/// A34 submitPostCloseClaim descriptor — the on-chain `ChannelSettlementManager.PostCloseClaim`
/// fields. `shared_native_nullifier` is advisory only (the manager RECOMPUTES it, HAZARD #8);
/// `recipient` is emitted as `to_hex()` so the forge `vm.parseJsonAddress` matches the tested
/// withdrawal-claim path. Every value is a PROVED post-close-claim public input.
#[derive(Serialize)]
struct PostCloseClaimDescriptor {
    receiver_channel_id: u32,
    close_intent_digest: String,
    incoming_tx_hash: String,
    receiver_pk_g: String,
    recipient: String,
    shared_native_nullifier: String,
    amount: u64,
    /// TM-16 (multi-token §N-6): the PROVED base token_index (PI limb 56) — the asset the
    /// Manager credits. Descriptor-derived by the prover, never a caller choice.
    token_index: u32,
}

/// A-3 H-2 §3.5.5 (A34): claim a late inter-channel delta that landed on THIS (now CLOSED) channel
/// after finalization. Builds the REAL post-close-claim MLE/WHIR proof via `PostCloseClaimProver`
/// (the receiver decrypts its own delta ciphertext from the persisted source `InterChannelTx`, and
/// the circuit proves the tx's inclusion in the finalized settled-tx accumulator), submits
/// `submitPostCloseClaim(claim, proof)` via the forge step, then pulls the credit
/// (`claimWithdrawalCredit`). Usage:
///   channel_member post-close-claim <manager_addr> <receiver_slot> <incoming_tx_index> [rpc_url]
/// env: CLAIM_RECIPIENT (the member's registered L1 address; also the claimWithdrawalCredit
/// caller),      POST_CLOSE_SOURCE_TX (path to the persisted source InterChannelTransferDescriptor
/// JSON;      default `inter_descriptor.json`).
/// The finalized close digest is read from `close_intent_full.json` (persisted by `close`), so no
/// close-metadata re-derivation is needed (and no env-var footgun).
fn cmd_post_close_claim(args: &[String]) {
    let manager = args.get(1).cloned().unwrap_or_else(|| {
        die("post-close-claim needs <manager_addr> <receiver_slot> <incoming_tx_index> [rpc_url]")
    });
    let receiver_slot: u16 = args
        .get(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| die("post-close-claim needs <receiver_slot>"));
    let incoming_tx_index: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or_else(|| {
        die("post-close-claim needs <incoming_tx_index> (leaf index in the settled-tx accumulator)")
    });
    let rpc = args
        .get(4)
        .cloned()
        .unwrap_or_else(|| "http://localhost:8545".to_string());
    require_active_settlement_binding(&rpc, &manager, None, None);
    let recipient = std::env::var("CLAIM_RECIPIENT")
        .ok()
        .and_then(|s| Address::from_hex(&s).ok())
        .unwrap_or_else(|| {
            die("set CLAIM_RECIPIENT=0x<20-byte member L1 recipient> (must equal the registered recipient)")
        });
    let l1_signer = LazyL1Signer::new(&rpc);
    // F4: resolve + validate the contracts checkout BEFORE the heavy post-close-claim proof (see
    // `require_contracts_dir`).
    let contracts_dir = require_contracts_dir("post-close-claim", &["script/RunClose.s.sol"]);

    // The CLOSED channel's finalized state + its settled-tx accumulator (the inclusion anchor).
    let st = load_state();
    let final_balance_state = st.snapshot.state.balance_state.clone();
    let accumulator = st.snapshot.settled_tx_accumulator.clone();

    // The finalized close's digest — read from the EXACT pending `CloseIntent` persisted by `close`
    // (`close_intent_full.json`), the SAME lossless source `cancel-close` uses, so the proof's
    // `close_intent_digest` PI equals on-chain `finalizedCloseIntentDigest`. (No metadata
    // re-derivation footgun: the close constructor now has one canonical representation.)
    let close_intent: CloseIntent = read_json(CLOSE_INTENT_FULL_FILE);
    let close_intent_digest = close_intent.signing_digest();

    // The late inter-channel transfer that delivered the receiver's delta. The wallet persists the
    // source `InterChannelTransferDescriptor` (its `inter_channel_tx` carries the receiver deltas).
    let source_path = std::env::var("POST_CLOSE_SOURCE_TX")
        .unwrap_or_else(|_| "inter_descriptor.json".to_string());
    let source_desc: InterChannelTransferDescriptor = read_json(&source_path);
    let source_tx: InterChannelTx = source_desc.inter_channel_tx.clone();

    // F8: same identity gate as `claim` — the receiver's key must be the one the signed slot leaf
    // commits, or this command refuses instead of proving for the wrong identity.
    let keys = claim_keys_for_slot(
        "post-close-claim",
        &st.controlled,
        &final_balance_state,
        receiver_slot,
    );
    let receiver_pk_g = keys.pk_g();
    // B-1b: the payout address is the signed per-slot exit address. `PostCloseClaimWitness` already
    // rejects a mismatch (RecipientMismatch); this only moves that certain failure ahead of the
    // proof.
    let leaf_recipient = final_balance_state.recipients[receiver_slot as usize];
    if recipient != leaf_recipient {
        die(format!(
            "post-close-claim: CLAIM_RECIPIENT {} is not slot {receiver_slot}'s signed exit \
             address {}. Fail-closed BEFORE proving.",
            recipient.to_hex(),
            leaf_recipient.to_hex()
        ));
    }

    eprintln!(
        "[post-close-claim] building claim for slot {receiver_slot} (tx index {incoming_tx_index}) + proving + MLE (HEAVY)…"
    );
    let prover = PostCloseClaimProver::new();
    let witness = prover
        .build_full_witness(
            &final_balance_state,
            receiver_slot as usize,
            &keys.regev_pk,
            &keys.regev_sk,
            receiver_pk_g,
            recipient,
            close_intent_digest,
            &source_tx,
            &accumulator,
            incoming_tx_index,
            RegevSecurityLevel::Production,
        )
        .unwrap_or_else(|e| die(format!("build post-close claim: {}", e.0)));
    let proof = prover
        .prove(&witness)
        .unwrap_or_else(|e| die(format!("post-close claim proof: {}", e.0)));
    let mle_json = prover
        .prove_mle(&proof)
        .unwrap_or_else(|e| die(format!("post-close claim MLE: {}", e.0)));

    let pi_limbs = proof.public_inputs[..POST_CLOSE_CLAIM_PUBLIC_INPUTS_LEN].to_u64_vec();
    let pis = PostCloseClaimPublicInputs::from_u64_slice(&pi_limbs)
        .unwrap_or_else(|e| die(format!("decode post-close-claim PIs: {e:?}")));
    let descriptor = PostCloseClaimDescriptor {
        receiver_channel_id: pis.receiver_channel_id.channel_id(),
        close_intent_digest: pis.close_intent_digest.to_string(),
        incoming_tx_hash: pis.incoming_tx_hash.to_string(),
        receiver_pk_g: pis.receiver_pk_g.to_string(),
        // Emit as 0x-hex so the forge `vm.parseJsonAddress` matches the tested claim path.
        recipient: pis.recipient.to_hex(),
        shared_native_nullifier: pis.shared_native_nullifier.to_string(),
        amount: pis.amount,
        token_index: pis.token_index,
    };

    fs::write(POST_CLOSE_CLAIM_MLE_FILE, &mle_json)
        .unwrap_or_else(|e| die(format!("write {POST_CLOSE_CLAIM_MLE_FILE}: {e}")));
    write_json(POST_CLOSE_CLAIM_FILE, &descriptor);
    println!(
        "[post-close-claim] wrote {POST_CLOSE_CLAIM_FILE} + {POST_CLOSE_CLAIM_MLE_FILE} (amount {})",
        pis.amount
    );

    // ── On-chain: submitPostCloseClaim (large struct calldata → forge step), then pull credit. ──
    let data_dir = contracts_dir.join("test/data");
    fs::copy(
        POST_CLOSE_CLAIM_FILE,
        data_dir.join("sepolia_post_close_claim.json"),
    )
    .unwrap_or_else(|e| die(format!("stage post_close_claim.json: {e}")));
    fs::copy(
        POST_CLOSE_CLAIM_MLE_FILE,
        data_dir.join("sepolia_post_close_claim_mle.json"),
    )
    .unwrap_or_else(|e| die(format!("stage post_close_claim_mle.json: {e}")));
    eprintln!("[post-close-claim] submitPostCloseClaim via forge RunClose step…");
    let mut forge = Command::new("forge");
    forge.current_dir(&contracts_dir).args([
        "script",
        "script/RunClose.s.sol",
        "--sig",
        "submitPostCloseClaimStep()",
        "--rpc-url",
        &rpc,
        "--broadcast",
    ]);
    l1_signer.get().append_to_command(&mut forge);
    let status = forge
        .env("MANAGER", &manager)
        .status()
        .unwrap_or_else(|e| die(format!("forge submitPostCloseClaim failed to start: {e}")));
    if !status.success() {
        die(
            "forge submitPostCloseClaim step failed (ensure the post-close-claim VK is initialized and the channel is finalized)",
        );
    }
    let recipient_hex = recipient.to_hex();
    eprintln!(
        "[post-close-claim] claimWithdrawalCredit({}) exact payout (recipient {recipient_hex})…",
        pis.shared_native_nullifier
    );
    claim_withdrawal_credit_bound(
        &rpc,
        l1_signer.get(),
        &manager,
        pis.shared_native_nullifier,
        recipient,
        pis.token_index,
        pis.amount,
    );
    println!(
        "[post-close-claim] OK: recipient {recipient_hex} received native ETH (amount {}).",
        pis.amount
    );
}

// ───────────────────────────────────────────────────────────────────────────────────────────────
// A-3 P4: `withdraw` — move the channel's native funds from the rollup to the manager.
//
// Full pipeline (this drives, against a LIVE rollup, the exact sequence proved+verified in
// `contracts/test/WithdrawNativeE2E.t.sol::_runLifecycleThroughFinalize`):
//   build_channel_withdrawal (HEAVY proving, recipient = manager)
//     -> registerChannel (one-time; skipped if already registered)
//     -> deposit{value} (sent by the depositor = the funding key, so msg.sender matches the proof)
//     -> postBlockAndSubmit ×3 (EIP-4844 blob txs: registration / deposit / withdrawal blocks)
//     -> finalize (real validity MLE/WHIR proof; gates `finalizedStateRoots`)
//     -> withdrawNative (real withdrawal MLE/WHIR proof; credits pendingWithdrawals[manager])
//     -> pullChannelFunds (manager pulls its escrowed credit out of the rollup)
//
// SECURITY: soundness is entirely in-circuit + on-chain. `build_channel_withdrawal` self-verifies
// every proof and re-folds the withdrawal keccak chain before returning; on-chain, `finalize`
// re-derives the block-hash chain and verifies the validity proof, and `withdrawNative` re-folds
// the withdrawal set + gates on `finalizedStateRoots[ext_commitment]`. The CLI cannot choose any
// payout value — `withdrawal_payout.json` is the proof's committed public inputs. The depositor is
// pinned to the funding key's address so the on-chain `deposit()` `msg.sender` reproduces block 2's
// hash; a mismatch makes `finalize` revert (fail-closed). EIP-4844 blobs cannot be attached by a
// forge script, so `postBlockAndSubmit` is sent via `cast send --blob` (per
// docs/sepolia-smoke-runbook.md).
//
// Requires the rollup to be deployed with the (deterministic) validity VK + genesis and the
// withdrawal VK initialized; the VK is deterministic (only the proof is randomized by ZK blinding),
// so a pre-initialized VK accepts the freshly-generated proof.
//
// env: ROLLUP (rollup addr; falls back to channel_backing.json), INTMAX_CHANNEL (channel id),
//      INTMAX_L1_ACCOUNT (Foundry keystore account off-devnet; local Anvil may use its dev key),
//      WD_DEPOSIT_AMOUNT / WD_AMOUNT (native units; default 10 / 3).
const PROOF_DA_DIR: &str = "proof-da-output";
const PROOF_DA_FILE: &str = "validity-proof.bin";
const PROOF_DA_METADATA_FILE: &str = "validity-proof.json";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ProofDaMetadata {
    codec: String,
    proof_hash: String,
    proof_length: u64,
    blob_count: u8,
}

const PROOF_DA_POST_JOURNAL_VERSION: u32 = 1;
const FULL_WITHDRAWAL_JOURNAL_VERSION: u32 = 1;
const POST_BLOCK_STAKE_WEI: u64 = 1_000_000_000_000_000_000;

/// Stable, semantic identity of one full-withdrawal lifecycle.  Unlike the validity proof hash,
/// these fields do not change when the randomized MLE/WHIR prover is invoked again.  There is one
/// journal slot per (chain, rollup, channel, depositor); changing any economic field while that
/// slot exists is refused rather than silently starting a second lifecycle.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FullWithdrawalOperationKey {
    chain_id: u64,
    rollup: String,
    manager: String,
    depositor: String,
    channel_id: u32,
    integrated: bool,
    deposit_amount: u64,
    withdrawal_amount: u64,
    erc20_token_index: Option<u32>,
    erc20_amount: Option<u64>,
    erc20_token: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FullWithdrawalArtifactDigest {
    file_name: String,
    byte_length: u64,
    keccak256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FullWithdrawalArtifactManifest {
    files: Vec<FullWithdrawalArtifactDigest>,
    proof_da: ProofDaMetadata,
    final_state_root: String,
    native_withdrawal_nullifier: String,
    erc20_withdrawal_nullifier: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FullWithdrawalCallConfirmation {
    transaction_hash: String,
    block_hash: String,
    block_number: u64,
    finalized_checkpoint: intmax3_zkp::l1_finality::L1FinalizedCheckpoint,
}

/// A write-ahead L1 call.  Exact target/calldata/value and sender nonce are fsynced before the
/// first broadcast.  A restart first scans canonical finalized blocks for that exact tuple; it can
/// therefore bridge the otherwise unknowable crash between `eth_sendRawTransaction` succeeding
/// and the RPC response reaching this process without ever creating a duplicate deposit/payout.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FullWithdrawalCallIntent {
    caller: String,
    target: String,
    calldata: String,
    value: u64,
    caller_nonce: u64,
    start_block: u64,
    transaction_hashes: Vec<String>,
    confirmation: Option<FullWithdrawalCallConfirmation>,
    #[serde(default)]
    external_completion: Option<FullWithdrawalCallConfirmation>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FullWithdrawalOperationJournal {
    version: u32,
    key: FullWithdrawalOperationKey,
    artifacts: Option<FullWithdrawalArtifactManifest>,
    calls: BTreeMap<String, FullWithdrawalCallIntent>,
    complete: bool,
}

struct PersistedFullWithdrawalArtifacts {
    lifecycle_json: Vec<u8>,
    validity_mle_json: Vec<u8>,
    withdrawal_mle_json: Vec<u8>,
    payout_json: Vec<u8>,
    erc20_withdrawal_mle_json: Option<Vec<u8>>,
    erc20_payout_json: Option<Vec<u8>>,
    proof_da_path: PathBuf,
    proof_da_payload: Vec<u8>,
    proof_da: ProofDaMetadata,
}

struct DryRunL1Call {
    target: String,
    calldata: String,
    value: u64,
}

fn full_withdrawal_operation_dir(key: &FullWithdrawalOperationKey) -> PathBuf {
    // Deliberately exclude manager/amounts from the slot id.  Those values are compared against
    // `journal.key`, so changing them while a lifecycle is incomplete fails closed instead of
    // allocating a second slot and repeating the deposit.
    let scope = format!(
        "INTMAX3/FULL-WITHDRAWAL/v1|{}|{}|{}|{}",
        key.chain_id,
        key.rollup.to_ascii_lowercase(),
        key.channel_id,
        key.depositor.to_ascii_lowercase()
    );
    let digest = hex::encode(keccak_hash::keccak(scope.as_bytes()).0);
    Path::new(PROOF_DA_DIR).join(format!("withdrawal-operation-{digest}"))
}

fn load_or_create_full_withdrawal_operation(
    key: FullWithdrawalOperationKey,
) -> (PathBuf, PathBuf, FullWithdrawalOperationJournal) {
    let operation_dir = full_withdrawal_operation_dir(&key);
    let journal_path = operation_dir.join("operation.json");
    if journal_path.exists() {
        secure_private_path(&journal_path);
        let bytes = fs::read(&journal_path)
            .unwrap_or_else(|error| die(format!("read {}: {error}", journal_path.display())));
        let journal: FullWithdrawalOperationJournal = serde_json::from_slice(&bytes)
            .unwrap_or_else(|error| die(format!("parse {}: {error}", journal_path.display())));
        if journal.version != FULL_WITHDRAWAL_JOURNAL_VERSION || journal.key != key {
            die(format!(
                "withdrawal operation slot {} already contains a different chain/rollup/channel/manager/amount/token lifecycle; refusing a second deposit",
                journal_path.display()
            ));
        }
        return (operation_dir, journal_path, journal);
    }
    let journal = FullWithdrawalOperationJournal {
        version: FULL_WITHDRAWAL_JOURNAL_VERSION,
        key,
        artifacts: None,
        calls: BTreeMap::new(),
        complete: false,
    };
    write_private_json_at(&journal_path, &journal);
    (operation_dir, journal_path, journal)
}

fn full_withdrawal_artifact_digest(file_name: &str, bytes: &[u8]) -> FullWithdrawalArtifactDigest {
    FullWithdrawalArtifactDigest {
        file_name: file_name.to_string(),
        byte_length: bytes.len() as u64,
        keccak256: format!("0x{}", hex::encode(keccak_hash::keccak(bytes).0)),
    }
}

fn persist_full_withdrawal_artifact(
    operation_dir: &Path,
    file_name: &str,
    bytes: &[u8],
) -> FullWithdrawalArtifactDigest {
    if file_name.contains('/') || file_name.contains('\\') || file_name.starts_with('.') {
        die(format!("unsafe withdrawal artifact filename {file_name:?}"));
    }
    write_private_bytes_at(&operation_dir.join(file_name), bytes);
    full_withdrawal_artifact_digest(file_name, bytes)
}

fn read_verified_full_withdrawal_artifact(
    operation_dir: &Path,
    manifest: &FullWithdrawalArtifactManifest,
    file_name: &str,
) -> Vec<u8> {
    let expected = manifest
        .files
        .iter()
        .find(|file| file.file_name == file_name)
        .unwrap_or_else(|| die(format!("withdrawal manifest is missing {file_name}")));
    let path = operation_dir.join(file_name);
    secure_private_path(&path);
    let bytes =
        fs::read(&path).unwrap_or_else(|error| die(format!("read {}: {error}", path.display())));
    let actual = full_withdrawal_artifact_digest(file_name, &bytes);
    if actual != *expected {
        die(format!(
            "persisted withdrawal artifact {} changed after its manifest was fsynced",
            path.display()
        ));
    }
    bytes
}

fn payout_nullifier(json: &[u8], what: &str) -> String {
    let value: serde_json::Value =
        serde_json::from_slice(json).unwrap_or_else(|error| die(format!("parse {what}: {error}")));
    value["withdrawals"][0]["nullifier"]
        .as_str()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| die(format!("{what} has no withdrawals[0].nullifier")))
        .to_string()
}

fn load_persisted_full_withdrawal_artifacts(
    operation_dir: &Path,
    manifest: &FullWithdrawalArtifactManifest,
) -> PersistedFullWithdrawalArtifacts {
    let lifecycle_json =
        read_verified_full_withdrawal_artifact(operation_dir, manifest, "lifecycle.json");
    let validity_mle_json = read_verified_full_withdrawal_artifact(
        operation_dir,
        manifest,
        "lifecycle_validity_mle.json",
    );
    let withdrawal_mle_json =
        read_verified_full_withdrawal_artifact(operation_dir, manifest, "withdrawal_mle.json");
    let payout_json =
        read_verified_full_withdrawal_artifact(operation_dir, manifest, "withdrawal_payout.json");
    let erc20_withdrawal_mle_json = manifest
        .files
        .iter()
        .any(|file| file.file_name == "erc20_withdrawal_mle.json")
        .then(|| {
            read_verified_full_withdrawal_artifact(
                operation_dir,
                manifest,
                "erc20_withdrawal_mle.json",
            )
        });
    let erc20_payout_json = manifest
        .files
        .iter()
        .any(|file| file.file_name == "erc20_withdrawal_payout.json")
        .then(|| {
            read_verified_full_withdrawal_artifact(
                operation_dir,
                manifest,
                "erc20_withdrawal_payout.json",
            )
        });
    if payout_nullifier(&payout_json, "withdrawal_payout.json")
        != manifest.native_withdrawal_nullifier
    {
        die("native withdrawal nullifier differs from the operation manifest");
    }
    match (&erc20_payout_json, &manifest.erc20_withdrawal_nullifier) {
        (Some(json), Some(expected))
            if payout_nullifier(json, "erc20_withdrawal_payout.json") == *expected => {}
        (None, None) => {}
        _ => die("ERC-20 withdrawal artifacts/nullifier differ from the operation manifest"),
    }
    let proof_da_payload =
        read_verified_full_withdrawal_artifact(operation_dir, manifest, PROOF_DA_FILE);
    let proof_da_metadata_bytes =
        read_verified_full_withdrawal_artifact(operation_dir, manifest, PROOF_DA_METADATA_FILE);
    let proof_da: ProofDaMetadata = serde_json::from_slice(&proof_da_metadata_bytes)
        .unwrap_or_else(|error| die(format!("parse persisted proof DA metadata: {error}")));
    if proof_da != manifest.proof_da
        || proof_da.proof_length != proof_da_payload.len() as u64
        || !same_hex_value(
            &proof_da.proof_hash,
            &format!(
                "0x{}",
                hex::encode(keccak_hash::keccak(&proof_da_payload).0)
            ),
        )
    {
        die("persisted proof DA payload/metadata differs from the operation manifest");
    }
    PersistedFullWithdrawalArtifacts {
        lifecycle_json,
        validity_mle_json,
        withdrawal_mle_json,
        payout_json,
        erc20_withdrawal_mle_json,
        erc20_payout_json,
        proof_da_path: operation_dir.join(PROOF_DA_FILE),
        proof_da_payload,
        proof_da,
    }
}

/// One blob post, persisted after signing and before publishing.  The raw network transaction
/// includes its blobs, commitments and KZG proofs, so a crash can never leave an unknowable
/// transaction between local intent and L1.  `receipt` is filled only after finalized canonical
/// read-back and exact `Submitted` event validation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProofDaPostRoundJournal {
    round_index: usize,
    pending_chains_pin: String,
    calldata: String,
    raw_signed_transaction: String,
    transaction_hash: String,
    blob_versioned_hashes: Vec<String>,
    compact_sidecars: String,
    submission_id: Option<String>,
    receipt_block_hash: Option<String>,
    receipt_block_number: Option<u64>,
    finalized_checkpoint: Option<intmax3_zkp::l1_finality::L1FinalizedCheckpoint>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProofDaPostJournal {
    version: u32,
    chain_id: u64,
    rollup: String,
    submitter: String,
    proof_hash: String,
    proof_length: u32,
    state_root: String,
    rounds: Vec<ProofDaPostRoundJournal>,
}

fn same_hex_value(left: &str, right: &str) -> bool {
    left.trim_start_matches("0x")
        .eq_ignore_ascii_case(right.trim_start_matches("0x"))
}

fn validate_durable_checkpoint_advancement(
    stored: &intmax3_zkp::l1_finality::L1FinalizedCheckpoint,
    current: &intmax3_zkp::l1_finality::L1FinalizedCheckpoint,
) -> Result<(), String> {
    stored.validate()?;
    current.validate()?;
    if current.chain_id != stored.chain_id || current.source != stored.source {
        return Err("durable checkpoint changed chain or finality source".into());
    }
    if current.block_number < stored.block_number {
        return Err("durable checkpoint regressed".into());
    }
    if current.block_number == stored.block_number
        && (current.block_hash != stored.block_hash || current.parent_hash != stored.parent_hash)
    {
        return Err("durable checkpoint was replaced at the same height".into());
    }
    Ok(())
}

fn load_or_create_proof_da_post_journal(
    path: &Path,
    chain_id: u64,
    rollup: &str,
    submitter: &str,
    proof_hash: &str,
    proof_length: u32,
    state_root: &str,
) -> ProofDaPostJournal {
    if path.exists() {
        secure_private_path(path);
        let bytes =
            fs::read(path).unwrap_or_else(|error| die(format!("read {}: {error}", path.display())));
        let journal: ProofDaPostJournal = serde_json::from_slice(&bytes)
            .unwrap_or_else(|error| die(format!("parse {}: {error}", path.display())));
        if journal.version != PROOF_DA_POST_JOURNAL_VERSION
            || journal.chain_id != chain_id
            || !same_hex_value(&journal.rollup, rollup)
            || !same_hex_value(&journal.submitter, submitter)
            || !same_hex_value(&journal.proof_hash, proof_hash)
            || journal.proof_length != proof_length
            || !same_hex_value(&journal.state_root, state_root)
            || journal.rounds.len() > 3
            || journal
                .rounds
                .iter()
                .enumerate()
                .any(|(index, round)| round.round_index != index)
        {
            die(format!(
                "proof-DA journal {} does not describe this exact chain/rollup/proof lifecycle",
                path.display()
            ));
        }
        return journal;
    }
    let journal = ProofDaPostJournal {
        version: PROOF_DA_POST_JOURNAL_VERSION,
        chain_id,
        rollup: rollup.to_string(),
        submitter: submitter.to_string(),
        proof_hash: proof_hash.to_string(),
        proof_length,
        state_root: state_root.to_string(),
        rounds: Vec::new(),
    };
    write_private_json_at(path, &journal);
    journal
}

fn stage_persisted_full_withdrawal_artifacts(
    artifacts: &PersistedFullWithdrawalArtifacts,
    contracts_dir: &Path,
) {
    let write = |path: &Path, bytes: &[u8]| {
        fs::write(path, bytes)
            .unwrap_or_else(|error| die(format!("stage {}: {error}", path.display())));
    };
    write(Path::new("lifecycle.json"), &artifacts.lifecycle_json);
    write(
        Path::new("lifecycle_validity_mle.json"),
        &artifacts.validity_mle_json,
    );
    write(
        Path::new("withdrawal_mle.json"),
        &artifacts.withdrawal_mle_json,
    );
    write(Path::new("withdrawal_payout.json"), &artifacts.payout_json);
    let data_dir = contracts_dir.join("test/data");
    write(
        &data_dir.join("sepolia_lifecycle.json"),
        &artifacts.lifecycle_json,
    );
    write(
        &data_dir.join("sepolia_lifecycle_validity_mle.json"),
        &artifacts.validity_mle_json,
    );
    write(
        &data_dir.join("sepolia_withdrawal_mle.json"),
        &artifacts.withdrawal_mle_json,
    );
    write(
        &data_dir.join("sepolia_withdrawal_payout.json"),
        &artifacts.payout_json,
    );
    match (
        &artifacts.erc20_withdrawal_mle_json,
        &artifacts.erc20_payout_json,
    ) {
        (Some(mle), Some(payout)) => {
            write(Path::new("erc20_withdrawal_mle.json"), mle);
            write(Path::new("erc20_withdrawal_payout.json"), payout);
            write(&data_dir.join("sepolia_erc20_withdrawal_mle.json"), mle);
            write(
                &data_dir.join("sepolia_erc20_withdrawal_payout.json"),
                payout,
            );
        }
        (None, None) => {}
        _ => die("persisted ERC-20 withdrawal artifact pair is incomplete"),
    }
}

fn run_close_materialized_call(
    contracts_dir: &Path,
    step: &str,
    journal_path: &Path,
    expected_target: &str,
    environment: &[(&str, &str)],
) -> DryRunL1Call {
    let materialize_step = match step {
        "attestProofDataStep()" => "materializeAttestProofDataCalldataStep()",
        "finalizeStep()" => "materializeFinalizeCalldataStep()",
        "withdrawNativeStep()" => "materializeWithdrawNativeCalldataStep()",
        "withdrawErc20Step()" => "materializeWithdrawErc20CalldataStep()",
        _ => die(format!(
            "no deterministic calldata materializer is defined for {step}"
        )),
    };
    let output_path = journal_path
        .parent()
        .unwrap_or_else(|| die("withdrawal journal has no operation directory"))
        .join(format!("{}.calldata", step.trim_end_matches("()")));
    // Poison any stale helper output before running Forge.  Only a successful script that replaces
    // this sentinel with valid hex can cross the durable-intent boundary below.
    write_private_bytes_at(&output_path, b"INVALID");
    let mut forge = Command::new("forge");
    forge.current_dir(contracts_dir).args([
        "script",
        "script/RunClose.s.sol:RunClose",
        "--sig",
        materialize_step,
    ]);
    for (name, value) in environment {
        forge.env(name, value);
    }
    forge.env("CALLDATA_OUT", &output_path);
    let output = forge.output().unwrap_or_else(|error| {
        die(format!(
            "forge {step} calldata materializer failed to start: {error}"
        ))
    });
    if !output.status.success() {
        die(format!(
            "forge {step} calldata materialization FAILED before any broadcast:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let calldata = fs::read_to_string(&output_path)
        .unwrap_or_else(|error| die(format!("read {}: {error}", output_path.display())))
        .trim()
        .to_string();
    let body = calldata
        .strip_prefix("0x")
        .or_else(|| calldata.strip_prefix("0X"))
        .unwrap_or_else(|| {
            die(format!(
                "forge {step} materialized calldata has no 0x prefix"
            ))
        });
    if body.len() < 8 || body.len() % 2 != 0 || !body.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        die(format!("forge {step} materialized malformed calldata"));
    }
    DryRunL1Call {
        target: expected_target.to_string(),
        calldata,
        value: 0,
    }
}

fn execute_run_close_full_withdrawal_step(
    contracts_dir: &Path,
    rpc: &str,
    chain_id: u64,
    signer: &L1Signer,
    journal_path: &Path,
    journal: &mut FullWithdrawalOperationJournal,
    journal_step: &str,
    forge_step: &str,
    expected_target: &str,
    environment: &[(&str, &str)],
) -> FullWithdrawalCallConfirmation {
    let intent = prepare_run_close_full_withdrawal_step(
        contracts_dir,
        rpc,
        chain_id,
        signer,
        journal_path,
        journal,
        journal_step,
        forge_step,
        expected_target,
        environment,
        None,
    );
    execute_full_withdrawal_call(
        rpc,
        chain_id,
        signer,
        journal_path,
        journal,
        journal_step,
        &intent.target,
        &intent.calldata,
        intent.value,
    )
}

#[allow(clippy::too_many_arguments)]
fn prepare_run_close_full_withdrawal_step(
    contracts_dir: &Path,
    rpc: &str,
    chain_id: u64,
    signer: &L1Signer,
    journal_path: &Path,
    journal: &mut FullWithdrawalOperationJournal,
    journal_step: &str,
    forge_step: &str,
    expected_target: &str,
    environment: &[(&str, &str)],
    observation_start_block: Option<u64>,
) -> FullWithdrawalCallIntent {
    if let Some(intent) = journal.calls.get(journal_step).cloned() {
        if !same_hex_value(&intent.target, expected_target) {
            die(format!(
                "persisted {journal_step} target differs from the expected contract"
            ));
        }
        return intent;
    }
    let dry = run_close_materialized_call(
        contracts_dir,
        forge_step,
        journal_path,
        expected_target,
        environment,
    );
    if !same_hex_value(&dry.target, expected_target) {
        die(format!(
            "forge {forge_step} dry-run targets {}, expected {expected_target}",
            dry.target
        ));
    }
    ensure_full_withdrawal_call_intent(
        rpc,
        chain_id,
        signer,
        journal_path,
        journal,
        journal_step,
        &dry.target,
        &dry.calldata,
        dry.value,
        observation_start_block,
    )
}

/// Materialize the exact `abi.encode(MleProof)` byte stream before any on-chain lifecycle
/// mutation. `cast send --blob --path` feeds this raw stream to Foundry's SimpleCoder, which adds
/// its length header, losslessly packs 31 payload bytes per field element and splits it across
/// blobs. The Solidity script is the single ABI encoder; Rust independently re-checks its length,
/// keccak and expected blob count so a stale/malformed output cannot be posted.
fn prepare_validity_proof_da(contracts_dir: &Path) -> (PathBuf, ProofDaMetadata) {
    let repo_root = contracts_dir
        .parent()
        .unwrap_or_else(|| die("contracts checkout has no parent directory"));
    let output_dir = repo_root.join(PROOF_DA_DIR);
    fs::create_dir_all(&output_dir)
        .unwrap_or_else(|e| die(format!("create {}: {e}", output_dir.display())));

    let status = Command::new("forge")
        .current_dir(contracts_dir)
        .args([
            "script",
            "script/PrepareProofDa.s.sol:PrepareProofDa",
            "--sig",
            "run()",
        ])
        .status()
        .unwrap_or_else(|e| die(format!("forge proof-DA encoder failed to start: {e}")));
    if !status.success() {
        die("forge proof-DA encoder failed; no on-chain withdrawal step was attempted");
    }

    let payload_path = output_dir.join(PROOF_DA_FILE);
    let metadata_path = output_dir.join(PROOF_DA_METADATA_FILE);
    let payload = fs::read(&payload_path)
        .unwrap_or_else(|e| die(format!("read {}: {e}", payload_path.display())));
    let metadata: ProofDaMetadata = serde_json::from_slice(
        &fs::read(&metadata_path)
            .unwrap_or_else(|e| die(format!("read {}: {e}", metadata_path.display()))),
    )
    .unwrap_or_else(|e| die(format!("parse {}: {e}", metadata_path.display())));

    if metadata.codec != "alloy-simple-coder-v1" {
        die(format!("unsupported proof-DA codec {}", metadata.codec));
    }
    if payload.len() as u64 != metadata.proof_length {
        die(format!(
            "proof-DA length mismatch: file {} != metadata {}",
            payload.len(),
            metadata.proof_length
        ));
    }
    let actual_hash = format!("0x{}", hex::encode(keccak_hash::keccak(&payload).0));
    if !metadata.proof_hash.eq_ignore_ascii_case(&actual_hash) {
        die(format!(
            "proof-DA hash mismatch: file {actual_hash} != metadata {}",
            metadata.proof_hash
        ));
    }
    // SimpleCoder consumes one field element for the u64 length header, then ceil(len/31)
    // elements for payload. Each blob has exactly 4096 elements.
    let payload_elements = (payload.len() + 30) / 31;
    let expected_blobs = (1 + payload_elements).div_ceil(4096);
    if expected_blobs == 0 || expected_blobs > 2 || metadata.blob_count as usize != expected_blobs {
        die(format!(
            "proof-DA blob count mismatch/overflow: expected {expected_blobs}, metadata {}",
            metadata.blob_count
        ));
    }

    (payload_path, metadata)
}

/// Render a serde_json array of hex/decimal strings as a cast array literal `[a,b,c]`.
fn json_str_array(v: &serde_json::Value) -> String {
    let items: Vec<String> = v
        .as_array()
        .unwrap_or_else(|| die("expected JSON array"))
        .iter()
        .map(|e| {
            e.as_str()
                .unwrap_or_else(|| die("expected JSON string element"))
                .to_string()
        })
        .collect();
    format!("[{}]", items.join(","))
}

/// Render a serde_json array of numbers as a cast array literal `[1,2]`.
fn json_num_array(v: &serde_json::Value) -> String {
    let items: Vec<String> = v
        .as_array()
        .unwrap_or_else(|| die("expected JSON array"))
        .iter()
        .map(|e| {
            e.as_u64()
                .unwrap_or_else(|| die("expected JSON number element"))
                .to_string()
        })
        .collect();
    format!("[{}]", items.join(","))
}

fn lifecycle_registration_commitment(registration: &serde_json::Value) -> String {
    let active = registration["member_pk_gs"]
        .as_array()
        .unwrap_or_else(|| die("registration.member_pk_gs must be an array"));
    if active.is_empty() || active.len() > MAX_SIG_CLUSTER {
        die("registration.member_pk_gs has an invalid cosigner count");
    }
    let mut hashes = [Bytes32::default(); MAX_SIG_CLUSTER];
    for (index, value) in active.iter().enumerate() {
        hashes[index] = value
            .as_str()
            .unwrap_or_else(|| die("registration.member_pk_gs entry is not a string"))
            .parse::<Bytes32>()
            .unwrap_or_else(|error| die(format!("parse registration pk_g: {error}")));
    }
    close_member_set_commitment(&hashes, active.len() as u8).to_string()
}

fn decode_signed_blob_transaction(raw_transaction: &str) -> DecodedBlobTransaction {
    let raw = raw_transaction.trim();
    if raw.len() < 4
        || raw.len() > 2 * 1024 * 1024
        || !raw.starts_with("0x03")
        || !raw[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        die("cast mktx returned a malformed or oversized signed blob transaction");
    }
    let mut child = Command::new("cast")
        .args(["decode-transaction", "--json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| die(format!("cast decode-transaction failed to start: {error}")));
    child
        .stdin
        .take()
        .expect("piped cast decoder stdin")
        .write_all(raw.as_bytes())
        .unwrap_or_else(|error| die(format!("write signed transaction to cast decoder: {error}")));
    let output = child
        .wait_with_output()
        .unwrap_or_else(|error| die(format!("wait for cast transaction decoder: {error}")));
    if !output.status.success() || output.stdout.len() > 2 * 1024 * 1024 {
        die(format!(
            "cast decode-transaction rejected the signed blob transaction: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| die(format!("parse decoded signed blob transaction: {error}")))
}

fn sign_blob_post(
    rollup: &str,
    signer: &L1Signer,
    rpc: &str,
    sub_block: &str,
    proof_da_path: &str,
    proof_hash: &str,
    proof_length: u32,
    state_root: &str,
    pending_pin: &str,
) -> (String, String) {
    const POST_SIG: &str =
        "postBlockAndSubmit((uint32,uint64,bytes32,uint32[])[],bytes32,uint32,bytes32,bytes32)";
    let proof_length = proof_length.to_string();
    let intended_calldata = cast(&[
        "calldata",
        POST_SIG,
        sub_block,
        proof_hash,
        &proof_length,
        state_root,
        pending_pin,
    ])
    .trim()
    .to_string();

    let mut command = Command::new("cast");
    command.args([
        "mktx",
        rollup,
        POST_SIG,
        sub_block,
        proof_hash,
        &proof_length,
        state_root,
        pending_pin,
        "--value",
        "1ether",
        "--blob",
        "--path",
        proof_da_path,
        "--rpc-url",
        rpc,
        "--json",
    ]);
    signer.append_to_command(&mut command);
    let output = command
        .output()
        .unwrap_or_else(|error| die(format!("cast mktx blob post failed to start: {error}")));
    if !output.status.success() {
        die(format!(
            "cast mktx blob post failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let raw = String::from_utf8(output.stdout)
        .unwrap_or_else(|error| die(format!("signed blob transaction is not UTF-8 hex: {error}")))
        .trim()
        .to_string();
    (raw, intended_calldata)
}

fn rpc_knows_transaction(rpc: &str, tx_hash: &str) -> bool {
    let output = Command::new("cast")
        .args(["rpc", "eth_getTransactionByHash", tx_hash, "--rpc-url", rpc])
        .output()
        .unwrap_or_else(|error| die(format!("query blob transaction failed to start: {error}")));
    output.status.success()
        && serde_json::from_slice::<serde_json::Value>(&output.stdout)
            .is_ok_and(|value| !value.is_null())
}

fn full_withdrawal_intent_tx_hash_in_block(
    block: &serde_json::Value,
    intent: &FullWithdrawalCallIntent,
) -> Result<Option<String>, String> {
    let transactions = block["transactions"]
        .as_array()
        .ok_or_else(|| "full block has no transactions array".to_string())?;
    for transaction in transactions {
        let Some(from) = transaction["from"].as_str() else {
            continue;
        };
        if !from.eq_ignore_ascii_case(&intent.caller) {
            continue;
        }
        let nonce = json_u64_quantity(&transaction["nonce"], "transaction nonce")?;
        if nonce != intent.caller_nonce {
            continue;
        }
        let target = transaction["to"].as_str().unwrap_or_default();
        let calldata = transaction["input"]
            .as_str()
            .or_else(|| transaction["data"].as_str())
            .ok_or_else(|| "transaction at intended nonce has no calldata".to_string())?;
        let value = json_u64_quantity(&transaction["value"], "transaction value")?;
        if !target.eq_ignore_ascii_case(&intent.target)
            || !same_hex_value(calldata, &intent.calldata)
            || value != intent.value
        {
            return Err(format!(
                "sender nonce {} was replaced: target={target}, value={value}",
                intent.caller_nonce
            ));
        }
        return transaction["hash"]
            .as_str()
            .filter(|hash| !hash.is_empty())
            .map(|hash| Some(hash.to_string()))
            .ok_or_else(|| "exact transaction has no hash".to_string());
    }
    Ok(None)
}

fn scan_finalized_full_withdrawal_intent(
    rpc: &str,
    intent: &FullWithdrawalCallIntent,
) -> Option<String> {
    let durable = read_durable_l1_checkpoint(rpc, rpc_chain_id(rpc));
    if durable.block_number < intent.start_block {
        return None;
    }
    for block_number in intent.start_block..=durable.block_number {
        let block_arg = block_number.to_string();
        let raw = cast(&["block", &block_arg, "--full", "--json", "--rpc-url", rpc]);
        let block: serde_json::Value = serde_json::from_str(raw.trim())
            .unwrap_or_else(|error| die(format!("parse full block {block_number}: {error}")));
        match full_withdrawal_intent_tx_hash_in_block(&block, intent) {
            Ok(Some(hash)) => return Some(hash),
            Ok(None) => {}
            Err(error) => die(format!(
                "full-withdrawal transaction at persisted sender nonce is not the exact intended call: {error}"
            )),
        }
    }
    None
}

fn wait_for_finalized_full_withdrawal_call(
    rpc: &str,
    chain_id: u64,
    transaction_hash: &str,
    intent: &FullWithdrawalCallIntent,
) -> FullWithdrawalCallConfirmation {
    let timeout_secs = std::env::var("INTMAX_L1_FINALITY_TIMEOUT_SECS")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .unwrap_or(3_600)
        .clamp(1, 86_400);
    let started = std::time::Instant::now();
    loop {
        if let Some(receipt) = try_blob_receipt(rpc, transaction_hash) {
            let receipt_hash = receipt["transactionHash"]
                .as_str()
                .unwrap_or_else(|| die("full-withdrawal receipt has no transactionHash"));
            let from = receipt["from"]
                .as_str()
                .unwrap_or_else(|| die("full-withdrawal receipt has no from"));
            let to = receipt["to"]
                .as_str()
                .unwrap_or_else(|| die("full-withdrawal receipt has no to"));
            if !same_hex_value(receipt_hash, transaction_hash)
                || !same_hex_value(from, &intent.caller)
                || !same_hex_value(to, &intent.target)
            {
                die("full-withdrawal receipt identity differs from the durable intent");
            }
            let status = receipt["status"]
                .as_str()
                .map(|status| status == "0x1" || status == "1")
                .or_else(|| receipt["status"].as_u64().map(|status| status == 1))
                .unwrap_or(false);
            if !status {
                die(format!(
                    "full-withdrawal transaction {transaction_hash} reverted; the operation journal is retained and no alternative call will be attempted"
                ));
            }

            let transaction_raw = cast(&["tx", transaction_hash, "--json", "--rpc-url", rpc]);
            let transaction: serde_json::Value = serde_json::from_str(transaction_raw.trim())
                .unwrap_or_else(|error| die(format!("parse full-withdrawal transaction: {error}")));
            let synthetic_block = serde_json::json!({ "transactions": [transaction] });
            match full_withdrawal_intent_tx_hash_in_block(&synthetic_block, intent) {
                Ok(Some(hash)) if same_hex_value(&hash, transaction_hash) => {}
                Ok(_) => die("full-withdrawal transaction does not match its durable intent"),
                Err(error) => die(format!("validate full-withdrawal transaction: {error}")),
            }

            let block_hash_text = receipt["blockHash"]
                .as_str()
                .unwrap_or_else(|| die("full-withdrawal receipt has no blockHash"));
            let block_hash = block_hash_text
                .parse::<Bytes32>()
                .unwrap_or_else(|error| die(format!("parse receipt block hash: {error}")));
            let block_number = receipt_quantity(&receipt, "blockNumber");
            let durable_before = read_durable_l1_checkpoint(rpc, chain_id);
            if block_number <= durable_before.block_number {
                let block_tag = format!("0x{block_number:x}");
                let canonical = rpc_block_json(rpc, &block_tag)
                    .and_then(|raw| {
                        parse_l1_checkpoint_block(&raw, chain_id, durable_before.source)
                    })
                    .unwrap_or_else(|error| {
                        die(format!(
                            "read canonical full-withdrawal receipt block: {error}"
                        ))
                    });
                validate_receipt_block_evidence(
                    block_number,
                    block_hash,
                    &canonical,
                    &durable_before,
                )
                .unwrap_or_else(|error| {
                    die(format!(
                        "full-withdrawal transaction {transaction_hash} is not canonical/final: {error}"
                    ))
                });
                let second = try_blob_receipt(rpc, transaction_hash).unwrap_or_else(|| {
                    die("full-withdrawal receipt disappeared during final read-back")
                });
                for field in [
                    "transactionHash",
                    "blockHash",
                    "blockNumber",
                    "status",
                    "from",
                    "to",
                    "logs",
                ] {
                    if receipt[field] != second[field] {
                        die(format!(
                            "full-withdrawal receipt field {field} changed during final read-back"
                        ));
                    }
                }
                revalidate_l1_checkpoint(rpc, &durable_before);
                let durable_after = read_durable_l1_checkpoint(rpc, chain_id);
                if durable_after.source != durable_before.source
                    || durable_after.block_number < durable_before.block_number
                    || (durable_after.block_number == durable_before.block_number
                        && (durable_after.block_hash != durable_before.block_hash
                            || durable_after.parent_hash != durable_before.parent_hash))
                {
                    die(
                        "durable L1 head regressed or changed during full-withdrawal receipt read-back",
                    );
                }
                durable_after
                    .covers_receipt(block_number, block_hash)
                    .unwrap_or_else(|error| die(format!("receipt lost finality: {error}")));
                return FullWithdrawalCallConfirmation {
                    transaction_hash: transaction_hash.to_string(),
                    block_hash: block_hash_text.to_string(),
                    block_number,
                    finalized_checkpoint: durable_after,
                };
            }
        }
        if started.elapsed().as_secs() >= timeout_secs {
            die(format!(
                "full-withdrawal transaction {transaction_hash} is not covered by a canonical durable head after {timeout_secs}s; its exact intent/nonce is safely persisted"
            ));
        }
        std::thread::sleep(std::time::Duration::from_secs(6));
    }
}

fn revalidate_full_withdrawal_confirmation(
    rpc: &str,
    chain_id: u64,
    intent: &FullWithdrawalCallIntent,
    stored: &FullWithdrawalCallConfirmation,
) {
    if !intent
        .transaction_hashes
        .iter()
        .any(|hash| same_hex_value(hash, &stored.transaction_hash))
    {
        die("full-withdrawal confirmation names a transaction outside its intent journal");
    }
    revalidate_l1_checkpoint(rpc, &stored.finalized_checkpoint);
    let reread =
        wait_for_finalized_full_withdrawal_call(rpc, chain_id, &stored.transaction_hash, intent);
    validate_durable_checkpoint_advancement(
        &stored.finalized_checkpoint,
        &reread.finalized_checkpoint,
    )
    .unwrap_or_else(|error| die(format!("full-withdrawal checkpoint progression: {error}")));
    // A later finalized head is expected.  Receipt identity must remain exact; requiring the head
    // struct itself to remain byte-identical would make every healthy restart fail as L1 advances.
    if !same_hex_value(&reread.transaction_hash, &stored.transaction_hash)
        || !same_hex_value(&reread.block_hash, &stored.block_hash)
        || reread.block_number != stored.block_number
    {
        die("stored full-withdrawal receipt changed or was orphaned");
    }
}

fn publish_full_withdrawal_call(
    rpc: &str,
    signer: &L1Signer,
    intent: &FullWithdrawalCallIntent,
) -> String {
    let nonce = intent.caller_nonce.to_string();
    let value = intent.value.to_string();
    let mut command = Command::new("cast");
    command.args([
        "send",
        &intent.target,
        &intent.calldata,
        "--value",
        &value,
        "--nonce",
        &nonce,
        "--async",
        "--rpc-url",
        rpc,
    ]);
    signer.append_to_command(&mut command);
    let output = command
        .output()
        .unwrap_or_else(|error| die(format!("broadcast full-withdrawal call: {error}")));
    if !output.status.success() {
        die(format!(
            "full-withdrawal broadcast returned an error after its intent was safely journaled: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if hex_body(&hash, 64, "full-withdrawal transaction hash").len() != 64 {
        unreachable!("hex_body either validates or terminates")
    }
    hash
}

#[allow(clippy::too_many_arguments)]
fn ensure_full_withdrawal_call_intent(
    rpc: &str,
    chain_id: u64,
    signer: &L1Signer,
    journal_path: &Path,
    journal: &mut FullWithdrawalOperationJournal,
    step: &str,
    target: &str,
    calldata: &str,
    value: u64,
    observation_start_block: Option<u64>,
) -> FullWithdrawalCallIntent {
    let caller = signer.address();
    if let Some(intent) = journal.calls.get(step) {
        if !same_hex_value(&intent.caller, &caller)
            || !same_hex_value(&intent.target, target)
            || !same_hex_value(&intent.calldata, calldata)
            || intent.value != value
        {
            die(format!(
                "full-withdrawal step {step} differs from its durable target/calldata/value intent"
            ));
        }
        return intent.clone();
    }

    let checkpoint = read_durable_l1_checkpoint(rpc, chain_id);
    require_stable_durable_l1_checkpoint(rpc, &checkpoint);
    let start_block = observation_start_block.unwrap_or(checkpoint.block_number);
    if start_block > checkpoint.block_number {
        die(format!(
            "full-withdrawal step {step} observation start {start_block} is ahead of durable L1 block {}",
            checkpoint.block_number
        ));
    }
    let intent = FullWithdrawalCallIntent {
        caller,
        target: target.to_string(),
        calldata: calldata.to_string(),
        value,
        caller_nonce: read_account_nonce(rpc, &signer.address(), "latest"),
        start_block,
        transaction_hashes: Vec::new(),
        confirmation: None,
        external_completion: None,
    };
    journal.calls.insert(step.to_string(), intent.clone());
    // Irreversible ordering: exact call + value + nonce reach durable storage before either an
    // observation of a permissionless equivalent or our first broadcast.
    write_private_json_at(journal_path, journal);
    intent
}

fn execute_full_withdrawal_call(
    rpc: &str,
    chain_id: u64,
    signer: &L1Signer,
    journal_path: &Path,
    journal: &mut FullWithdrawalOperationJournal,
    step: &str,
    target: &str,
    calldata: &str,
    value: u64,
) -> FullWithdrawalCallConfirmation {
    let caller = signer.address();
    let mut intent = ensure_full_withdrawal_call_intent(
        rpc,
        chain_id,
        signer,
        journal_path,
        journal,
        step,
        target,
        calldata,
        value,
        None,
    );
    if let Some(confirmation) = &intent.confirmation {
        revalidate_full_withdrawal_confirmation(rpc, chain_id, &intent, confirmation);
        return confirmation.clone();
    }

    let known = intent
        .transaction_hashes
        .iter()
        .rev()
        .find(|hash| rpc_knows_transaction(rpc, hash))
        .cloned();
    let transaction_hash = known
        .or_else(|| scan_finalized_full_withdrawal_intent(rpc, &intent))
        .unwrap_or_else(|| {
            require_nonce_free_for_exact_rebroadcast(rpc, &caller, intent.caller_nonce);
            let hash = publish_full_withdrawal_call(rpc, signer, &intent);
            intent.transaction_hashes.push(hash.clone());
            journal.calls.insert(step.to_string(), intent.clone());
            write_private_json_at(journal_path, journal);
            hash
        });
    if !intent
        .transaction_hashes
        .iter()
        .any(|hash| same_hex_value(hash, &transaction_hash))
    {
        intent.transaction_hashes.push(transaction_hash.clone());
        journal.calls.insert(step.to_string(), intent.clone());
        write_private_json_at(journal_path, journal);
    }
    let confirmation =
        wait_for_finalized_full_withdrawal_call(rpc, chain_id, &transaction_hash, &intent);
    intent.confirmation = Some(confirmation.clone());
    journal.calls.insert(step.to_string(), intent);
    write_private_json_at(journal_path, journal);
    confirmation
}

const NATIVE_WITHDRAWN_TOPIC0: &str =
    "0x0dcdc8824ca42304db65c0f3d90130322c57c0f555020903b0093ae53a63cb83";
const ERC20_WITHDRAWN_TOPIC0: &str =
    "0x8f44e01a37a9f44336a841309918a3d5ba2899c0707d8cbea326b68dfd84796e";
const CHANNEL_FUNDS_PULLED_TOPIC0: &str =
    "0x9553ce64219459d216d4165bfe5b52b4c4495e00b24a1fc57afcb4a0d38e5d50";
const WITHDRAWAL_CREDITED_TOPIC0: &str =
    "0x459f560336b72d57e46610439b7c1a8426cf7b7a2a0428d5fb5c7b0b7528b60d";
const FINALIZED_TOPIC0: &str = "0xa05a0e9561eff1f01a29e7a680d5957bb7312e5766a8da1f494b6d6ac18031f4";
const PROOF_DATA_ATTESTED_TOPIC0: &str =
    "0x7ede6b2f9f8a23acaf8c0e62b696ec12ae1bc8df6da2a0816238ee2909768993";

#[derive(Clone, Debug)]
enum FullWithdrawalEventExpectation {
    ProofDataAttested {
        rollup: String,
        submission_id: u64,
        submission_commitment: String,
        proof_hash: String,
        proof_length: u32,
    },
    Finalized {
        submission_id: u64,
        state_root: String,
    },
    WithdrawalCredited {
        recipient: String,
        amount: u64,
    },
    NativeWithdrawn {
        recipient: String,
        amount: u64,
        nullifier: String,
        intmax_block_number: u64,
    },
    Erc20Withdrawn {
        recipient: String,
        token_index: u32,
        amount: u64,
        nullifier: String,
        intmax_block_number: u64,
    },
    ChannelFundsPulled {
        token_index: u32,
        minimum_amount: u64,
    },
}

impl FullWithdrawalEventExpectation {
    fn topic0(&self) -> &'static str {
        match self {
            Self::ProofDataAttested { .. } => PROOF_DATA_ATTESTED_TOPIC0,
            Self::Finalized { .. } => FINALIZED_TOPIC0,
            Self::WithdrawalCredited { .. } => WITHDRAWAL_CREDITED_TOPIC0,
            Self::NativeWithdrawn { .. } => NATIVE_WITHDRAWN_TOPIC0,
            Self::Erc20Withdrawn { .. } => ERC20_WITHDRAWN_TOPIC0,
            Self::ChannelFundsPulled { .. } => CHANNEL_FUNDS_PULLED_TOPIC0,
        }
    }

    fn matches(&self, log: &serde_json::Value) -> Result<bool, String> {
        if log["removed"].as_bool().unwrap_or(false) {
            return Ok(false);
        }
        let topics = log["topics"]
            .as_array()
            .ok_or_else(|| "event log has no topics".to_string())?;
        let topic = |index: usize| -> Result<&str, String> {
            topics
                .get(index)
                .and_then(|value| value.as_str())
                .ok_or_else(|| format!("event log has no topic {index}"))
        };
        if !same_hex_value(topic(0)?, self.topic0()) {
            return Ok(false);
        }
        let data = log["data"]
            .as_str()
            .ok_or_else(|| "event log has no data".to_string())?
            .trim_start_matches("0x");
        let address_topic_matches = |actual: &str, expected: &str| -> Result<bool, String> {
            let actual = hex_body(actual, 64, "indexed address topic");
            let expected = hex_body(expected, 40, "expected address");
            Ok(actual[..24].bytes().all(|byte| byte == b'0')
                && actual[24..].eq_ignore_ascii_case(expected))
        };
        match self {
            Self::ProofDataAttested {
                rollup,
                submission_id,
                submission_commitment,
                proof_hash,
                proof_length,
            } => Ok(address_topic_matches(topic(1)?, rollup)?
                && abi_word_u64(topic(2)?, "ProofDataAttested.submissionId") == *submission_id
                && same_hex_value(topic(3)?, submission_commitment)
                && same_hex_value(abi_word(data, 1), proof_hash)
                && abi_word_u64(abi_word(data, 2), "ProofDataAttested.proofLength")
                    == u64::from(*proof_length)),
            Self::Finalized {
                submission_id,
                state_root,
            } => Ok(
                abi_word_u64(topic(1)?, "Finalized.submissionId") == *submission_id
                    && same_hex_value(abi_word(data, 0), state_root),
            ),
            Self::WithdrawalCredited { recipient, amount } => {
                Ok(address_topic_matches(topic(1)?, recipient)?
                    && abi_word_u64(abi_word(data, 0), "WithdrawalCredited.amount") == *amount)
            }
            Self::NativeWithdrawn {
                recipient,
                amount,
                nullifier,
                intmax_block_number,
            } => Ok(address_topic_matches(topic(1)?, recipient)?
                && same_hex_value(topic(2)?, nullifier)
                && abi_word_u64(abi_word(data, 0), "NativeWithdrawn.amount") == *amount
                && abi_word_u64(abi_word(data, 1), "NativeWithdrawn.blockNumber")
                    == *intmax_block_number),
            Self::Erc20Withdrawn {
                recipient,
                token_index,
                amount,
                nullifier,
                intmax_block_number,
            } => Ok(address_topic_matches(topic(1)?, recipient)?
                && abi_word_u64(topic(2)?, "Erc20Withdrawn.tokenIndex") == u64::from(*token_index)
                && same_hex_value(topic(3)?, nullifier)
                && abi_word_u64(abi_word(data, 0), "Erc20Withdrawn.amount") == *amount
                && abi_word_u64(abi_word(data, 1), "Erc20Withdrawn.blockNumber")
                    == *intmax_block_number),
            Self::ChannelFundsPulled {
                token_index,
                minimum_amount,
            } => Ok(abi_word_u64(topic(1)?, "ChannelFundsPulled.tokenIndex")
                == u64::from(*token_index)
                && abi_word_u64(abi_word(data, 0), "ChannelFundsPulled.amount") >= *minimum_amount),
        }
    }
}

#[derive(Clone, Debug)]
struct FullWithdrawalDescriptor {
    recipient: String,
    token_index: u32,
    amount: u64,
    nullifier: String,
    intmax_block_number: u64,
}

fn full_withdrawal_descriptor(payout_json: &[u8], what: &str) -> FullWithdrawalDescriptor {
    let value: serde_json::Value = serde_json::from_slice(payout_json)
        .unwrap_or_else(|error| die(format!("parse {what}: {error}")));
    let withdrawal = &value["withdrawals"][0];
    FullWithdrawalDescriptor {
        recipient: withdrawal["recipient"]
            .as_str()
            .unwrap_or_else(|| die(format!("{what} has no recipient")))
            .to_string(),
        token_index: u32::try_from(
            withdrawal["token_index"]
                .as_u64()
                .unwrap_or_else(|| die(format!("{what} has no token_index"))),
        )
        .unwrap_or_else(|_| die(format!("{what} token_index exceeds u32"))),
        amount: withdrawal["amount"]
            .as_str()
            .unwrap_or_else(|| die(format!("{what} has no amount")))
            .parse()
            .unwrap_or_else(|error| die(format!("parse {what} amount: {error}"))),
        nullifier: withdrawal["nullifier"]
            .as_str()
            .unwrap_or_else(|| die(format!("{what} has no nullifier")))
            .to_string(),
        intmax_block_number: value["block_number"]
            .as_u64()
            .unwrap_or_else(|| die(format!("{what} has no block_number"))),
    }
}

fn proof_data_attestation_state(
    rpc: &str,
    rollup: &str,
    submission_id: u64,
    proof_hash: &str,
    proof_length: u32,
    block_number: Option<u64>,
) -> (String, String, bool) {
    let submission = submission_id.to_string();
    let kzg = block_number.map_or_else(
        || cast_call(rpc, rollup, "kzgVerifier()(address)", &[]),
        |block| cast_call_at(rpc, rollup, "kzgVerifier()(address)", &[], block),
    );
    let commitment = block_number.map_or_else(
        || {
            cast_call(
                rpc,
                rollup,
                "getCommitment(uint256)(bytes32)",
                &[&submission],
            )
        },
        |block| {
            cast_call_at(
                rpc,
                rollup,
                "getCommitment(uint256)(bytes32)",
                &[&submission],
                block,
            )
        },
    );
    if strip0x(&kzg).trim_matches('0').is_empty()
        || strip0x(&commitment).trim_matches('0').is_empty()
    {
        die("proof-DA attestation lookup found a zero verifier or submission commitment");
    }
    // `BlobKZGVerifier.isProofDataAttested` namespaces its lookup by msg.sender.  eth_call permits
    // an explicit `from`; using the rollup address reproduces the actual call context without
    // adding another byte to the EIP-170-constrained rollup runtime.
    let length = proof_length.to_string();
    let mut command = Command::new("cast");
    command.args([
        "call",
        &kzg,
        "isProofDataAttested(uint256,bytes32,bytes32,uint256)(bool)",
        &submission,
        &commitment,
        proof_hash,
        &length,
        "--from",
        rollup,
        "--rpc-url",
        rpc,
    ]);
    let block = block_number.map(|number| number.to_string());
    if let Some(block) = &block {
        command.args(["--block", block]);
    }
    let output = command
        .output()
        .unwrap_or_else(|error| die(format!("query proof-DA attestation: {error}")));
    if !output.status.success() {
        die(format!(
            "query proof-DA attestation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let attested = match String::from_utf8_lossy(&output.stdout).trim() {
        "true" => true,
        "false" => false,
        other => die(format!("proof-DA attestation returned {other:?}")),
    };
    (kzg, commitment, attested)
}

fn finalized_external_event_confirmation(
    rpc: &str,
    chain_id: u64,
    log: &serde_json::Value,
    intent: &FullWithdrawalCallIntent,
) -> FullWithdrawalCallConfirmation {
    let transaction_hash = log["transactionHash"]
        .as_str()
        .unwrap_or_else(|| die("external completion log has no transactionHash"));
    let block_hash_text = log["blockHash"]
        .as_str()
        .unwrap_or_else(|| die("external completion log has no blockHash"));
    let block_hash = block_hash_text
        .parse::<Bytes32>()
        .unwrap_or_else(|error| die(format!("parse external completion block hash: {error}")));
    let block_number = json_u64_quantity(&log["blockNumber"], "external event blockNumber")
        .unwrap_or_else(|error| die(error));
    let receipt = try_blob_receipt(rpc, transaction_hash)
        .unwrap_or_else(|| die("external completion event transaction has no mined receipt"));
    let status = receipt["status"]
        .as_str()
        .map(|status| status == "0x1" || status == "1")
        .or_else(|| receipt["status"].as_u64().map(|status| status == 1))
        .unwrap_or(false);
    if !status
        || !same_hex_value(
            receipt["transactionHash"].as_str().unwrap_or_default(),
            transaction_hash,
        )
        || !same_hex_value(
            receipt["blockHash"].as_str().unwrap_or_default(),
            block_hash_text,
        )
        || receipt_quantity(&receipt, "blockNumber") != block_number
    {
        die("external completion receipt identity/status differs from its event log");
    }
    // A matching event alone is not sufficient: the same contract may emit the same payout tuple
    // for another operation.  The transaction that carried it must be the exact target/calldata/
    // value we durably intended.  The sender is deliberately *not* pinned because these protocol
    // effects are permissionless and this branch exists to adopt a copied/front-run call.
    let transaction_raw = cast(&["tx", transaction_hash, "--json", "--rpc-url", rpc]);
    let transaction: serde_json::Value = serde_json::from_str(transaction_raw.trim())
        .unwrap_or_else(|error| die(format!("parse external-completion transaction: {error}")));
    let transaction_target = transaction["to"].as_str().unwrap_or_default();
    let transaction_calldata = transaction["input"]
        .as_str()
        .or_else(|| transaction["data"].as_str())
        .unwrap_or_else(|| die("external-completion transaction has no calldata"));
    let transaction_value = json_u64_quantity(
        &transaction["value"],
        "external-completion transaction value",
    )
    .unwrap_or_else(|error| die(error));
    if !same_hex_value(
        transaction["hash"].as_str().unwrap_or_default(),
        transaction_hash,
    ) || !same_hex_value(transaction_target, &intent.target)
        || !same_hex_value(transaction_calldata, &intent.calldata)
        || transaction_value != intent.value
        || !same_hex_value(
            transaction["blockHash"].as_str().unwrap_or_default(),
            block_hash_text,
        )
        || json_u64_quantity(
            &transaction["blockNumber"],
            "external-completion transaction blockNumber",
        )
        .unwrap_or_else(|error| die(error))
            != block_number
    {
        die(
            "external completion transaction differs from the durable target/calldata/value intent",
        );
    }
    let log_index = log["logIndex"].clone();
    let receipt_log = receipt["logs"]
        .as_array()
        .and_then(|logs| {
            logs.iter()
                .find(|candidate| candidate["logIndex"] == log_index)
        })
        .unwrap_or_else(|| die("external completion event is absent from its transaction receipt"));
    for field in [
        "address",
        "topics",
        "data",
        "transactionHash",
        "blockHash",
        "blockNumber",
    ] {
        if receipt_log[field] != log[field] {
            die(format!(
                "external completion event field {field} differs from its receipt"
            ));
        }
    }
    let durable_before = read_durable_l1_checkpoint(rpc, chain_id);
    let tag = format!("0x{block_number:x}");
    let canonical = rpc_block_json(rpc, &tag)
        .and_then(|raw| parse_l1_checkpoint_block(&raw, chain_id, durable_before.source))
        .unwrap_or_else(|error| die(format!("read external completion block: {error}")));
    validate_receipt_block_evidence(block_number, block_hash, &canonical, &durable_before)
        .unwrap_or_else(|error| {
            die(format!(
                "external completion is not canonical/final: {error}"
            ))
        });
    let second = try_blob_receipt(rpc, transaction_hash)
        .unwrap_or_else(|| die("external completion receipt disappeared during read-back"));
    for field in [
        "transactionHash",
        "blockHash",
        "blockNumber",
        "status",
        "from",
        "to",
        "logs",
    ] {
        if receipt[field] != second[field] {
            die(format!(
                "external completion receipt field {field} changed during read-back"
            ));
        }
    }
    revalidate_l1_checkpoint(rpc, &durable_before);
    let durable_after = read_durable_l1_checkpoint(rpc, chain_id);
    validate_durable_checkpoint_advancement(&durable_before, &durable_after)
        .unwrap_or_else(|error| die(format!("external completion checkpoint: {error}")));
    durable_after
        .covers_receipt(block_number, block_hash)
        .unwrap_or_else(|error| die(format!("external completion lost finality: {error}")));
    FullWithdrawalCallConfirmation {
        transaction_hash: transaction_hash.to_string(),
        block_hash: block_hash_text.to_string(),
        block_number,
        finalized_checkpoint: durable_after,
    }
}

fn reconcile_external_full_withdrawal_effect(
    rpc: &str,
    chain_id: u64,
    journal_path: &Path,
    journal: &mut FullWithdrawalOperationJournal,
    step: &str,
    contract: &str,
    expectation: &FullWithdrawalEventExpectation,
) -> Option<FullWithdrawalCallConfirmation> {
    let intent = journal.calls.get(step)?.clone();
    if intent.confirmation.is_some() {
        return None;
    }
    let durable = read_durable_l1_checkpoint(rpc, chain_id);
    let filter = serde_json::json!({
        "fromBlock": format!("0x{:x}", intent.start_block),
        "toBlock": format!("0x{:x}", durable.block_number),
        "address": contract,
        "topics": [expectation.topic0()],
    })
    .to_string();
    let raw = cast(&["rpc", "eth_getLogs", &filter, "--rpc-url", rpc]);
    let logs: Vec<serde_json::Value> = serde_json::from_str(raw.trim())
        .unwrap_or_else(|error| die(format!("parse external-completion logs: {error}")));
    let mut matches = Vec::new();
    for log in logs {
        if expectation
            .matches(&log)
            .unwrap_or_else(|error| die(format!("parse external-completion event: {error}")))
        {
            matches.push(log);
        }
    }
    let stored = intent.external_completion.as_ref();
    let chosen = if let Some(stored) = stored {
        matches
            .into_iter()
            .find(|log| {
                same_hex_value(
                    log["transactionHash"].as_str().unwrap_or_default(),
                    &stored.transaction_hash,
                ) && same_hex_value(
                    log["blockHash"].as_str().unwrap_or_default(),
                    &stored.block_hash,
                ) && json_u64_quantity(&log["blockNumber"], "event block")
                    .ok()
                    .is_some_and(|number| number == stored.block_number)
            })
            .unwrap_or_else(|| die("stored external completion event disappeared or was replaced"))
    } else {
        matches.into_iter().max_by_key(|log| {
            (
                json_u64_quantity(&log["blockNumber"], "event block").unwrap_or(0),
                json_u64_quantity(&log["logIndex"], "event log index").unwrap_or(0),
            )
        })?
    };
    let confirmation = finalized_external_event_confirmation(rpc, chain_id, &chosen, &intent);
    if let Some(stored) = stored {
        validate_durable_checkpoint_advancement(
            &stored.finalized_checkpoint,
            &confirmation.finalized_checkpoint,
        )
        .unwrap_or_else(|error| die(format!("external completion checkpoint: {error}")));
        if !same_hex_value(&stored.transaction_hash, &confirmation.transaction_hash)
            || !same_hex_value(&stored.block_hash, &confirmation.block_hash)
            || stored.block_number != confirmation.block_number
        {
            die("stored external completion receipt changed");
        }
    } else {
        let mut updated = intent;
        updated.external_completion = Some(confirmation.clone());
        journal.calls.insert(step.to_string(), updated);
        write_private_json_at(journal_path, journal);
        eprintln!(
            "[withdraw] {step}: adopted permissionless completion {} after exact finalized event/postcondition validation",
            confirmation.transaction_hash
        );
    }
    Some(confirmation)
}

/// Release gate for the fixture-backed full-withdrawal pipeline.
///
/// `build_channel_withdrawal` currently constructs a fresh three-block history beginning at
/// genesis.  It does not import the rollup's finalized state or the live pending deposit/channel
/// accumulators.  `pendingChainsPin()` only prevents those accumulators from changing between the
/// pin read and block inclusion; it cannot make an already-built proof commit to their values.
/// Running this flow on a shared production rollup can therefore deposit funds and post blocks
/// that the generated validity proof can never finalize.  Keep the deterministic Anvil E2E path,
/// but fail closed everywhere else until withdrawal blocks are built by the live producer.
fn full_withdrawal_release_gate(chain_id: u64) -> Result<(), &'static str> {
    if chain_id == DEVNET_CHAIN_ID {
        Ok(())
    } else {
        Err(
            "production full withdrawal is disabled: the current withdrawal builder starts from \
             a fresh genesis history and does not import the live finalized state or pending \
             deposit/channel accumulators; pendingChainsPin only detects movement after its read \
             and cannot bind the prebuilt proof to those accumulators",
        )
    }
}

#[cfg(test)]
mod full_withdrawal_journal_tests {
    use super::*;
    use intmax3_zkp::{
        ethereum_types::bytes32::Bytes32,
        l1_finality::{L1FinalitySource, L1FinalizedCheckpoint},
    };

    fn word(value: u32) -> Bytes32 {
        Bytes32::from_u32_slice(&[value; 8]).expect("bytes32")
    }

    #[test]
    fn full_withdrawal_release_gate_is_devnet_only() {
        assert_eq!(full_withdrawal_release_gate(DEVNET_CHAIN_ID), Ok(()));
        for chain_id in [1, 10, 11_155_111, u64::MAX] {
            let error = full_withdrawal_release_gate(chain_id)
                .expect_err("every non-devnet chain must fail closed");
            assert!(error.contains("fresh genesis history"));
            assert!(error.contains("pendingChainsPin"));
        }
    }

    fn key() -> FullWithdrawalOperationKey {
        FullWithdrawalOperationKey {
            chain_id: 1,
            rollup: "0x1111111111111111111111111111111111111111".into(),
            manager: "0x2222222222222222222222222222222222222222".into(),
            depositor: "0x3333333333333333333333333333333333333333".into(),
            channel_id: 7,
            integrated: true,
            deposit_amount: 10,
            withdrawal_amount: 3,
            erc20_token_index: None,
            erc20_amount: None,
            erc20_token: None,
        }
    }

    fn intent() -> FullWithdrawalCallIntent {
        FullWithdrawalCallIntent {
            caller: "0x3333333333333333333333333333333333333333".into(),
            target: "0x1111111111111111111111111111111111111111".into(),
            calldata: "0x12345678".into(),
            value: 10,
            caller_nonce: 9,
            start_block: 100,
            transaction_hashes: Vec::new(),
            confirmation: None,
            external_completion: None,
        }
    }

    #[test]
    fn semantic_slot_cannot_be_escaped_by_changing_amount_or_manager() {
        let original = key();
        let mut changed = original.clone();
        changed.manager = "0x4444444444444444444444444444444444444444".into();
        changed.deposit_amount = 999;
        assert_eq!(
            full_withdrawal_operation_dir(&original),
            full_withdrawal_operation_dir(&changed),
            "one chain/rollup/channel/depositor must have one operation slot"
        );
        changed.channel_id += 1;
        assert_ne!(
            full_withdrawal_operation_dir(&original),
            full_withdrawal_operation_dir(&changed)
        );
    }

    #[test]
    fn crash_after_publish_is_recovered_by_exact_sender_nonce_tuple() {
        let intent = intent();
        let exact = serde_json::json!({
            "transactions": [{
                "from": intent.caller.clone(),
                "to": intent.target.clone(),
                "nonce": "0x9",
                "input": intent.calldata.clone(),
                "value": "0xa",
                "hash": format!("0x{}", "ab".repeat(32)),
            }]
        });
        assert_eq!(
            full_withdrawal_intent_tx_hash_in_block(&exact, &intent)
                .expect("exact transaction")
                .expect("hash"),
            format!("0x{}", "ab".repeat(32))
        );

        for (field, replacement) in [
            (
                "to",
                serde_json::json!("0x9999999999999999999999999999999999999999"),
            ),
            ("input", serde_json::json!("0xdeadbeef")),
            ("value", serde_json::json!("0xb")),
        ] {
            let mut replaced = exact.clone();
            replaced["transactions"][0][field] = replacement;
            assert!(
                full_withdrawal_intent_tx_hash_in_block(&replaced, &intent).is_err(),
                "same-nonce replacement of {field} must fail closed"
            );
        }
    }

    #[test]
    fn advanced_finalized_head_is_accepted_but_reorg_or_regression_is_not() {
        let stored = L1FinalizedCheckpoint {
            chain_id: 1,
            block_number: 100,
            block_hash: word(100),
            parent_hash: word(99),
            source: L1FinalitySource::RpcFinalized,
        };
        let advanced = L1FinalizedCheckpoint {
            block_number: 101,
            block_hash: word(101),
            parent_hash: word(100),
            ..stored
        };
        assert!(validate_durable_checkpoint_advancement(&stored, &advanced).is_ok());
        assert!(validate_durable_checkpoint_advancement(&advanced, &stored).is_err());
        let replaced = L1FinalizedCheckpoint {
            block_hash: word(777),
            ..stored
        };
        assert!(validate_durable_checkpoint_advancement(&stored, &replaced).is_err());
    }

    #[test]
    fn artifact_manifest_detects_any_byte_change() {
        let expected = full_withdrawal_artifact_digest("proof.bin", b"canonical-proof");
        let changed = full_withdrawal_artifact_digest("proof.bin", b"canonical-proog");
        assert_ne!(expected, changed);
    }

    #[test]
    fn intent_roundtrip_preserves_write_ahead_fields_before_any_hash_exists() {
        let mut journal = FullWithdrawalOperationJournal {
            version: FULL_WITHDRAWAL_JOURNAL_VERSION,
            key: key(),
            artifacts: None,
            calls: BTreeMap::new(),
            complete: false,
        };
        journal.calls.insert("deposit-native".into(), intent());
        let bytes = serde_json::to_vec(&journal).expect("serialize");
        let decoded: FullWithdrawalOperationJournal =
            serde_json::from_slice(&bytes).expect("deserialize");
        let recovered = &decoded.calls["deposit-native"];
        assert_eq!(recovered.caller_nonce, 9);
        assert_eq!(recovered.value, 10);
        assert!(recovered.transaction_hashes.is_empty());
        assert!(recovered.confirmation.is_none());
    }
}

fn publish_blob_transaction(rpc: &str, raw_transaction: &str, expected_hash: &str) {
    if rpc_knows_transaction(rpc, expected_hash) {
        eprintln!(
            "[withdraw] signed blob transaction {expected_hash} is already known; reconciling"
        );
        return;
    }
    let output = Command::new("cast")
        .args(["publish", raw_transaction, "--async", "--rpc-url", rpc])
        .output()
        .unwrap_or_else(|error| {
            die(format!(
                "cast publish blob transaction failed to start: {error}"
            ))
        });
    if !output.status.success() {
        // The RPC may have accepted the transaction but disconnected before answering.  Adopt it
        // only when an independent hash lookup sees the exact signed hash.
        if rpc_knows_transaction(rpc, expected_hash) {
            return;
        }
        die(format!(
            "cast publish blob transaction failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let published = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !same_hex_value(&published, expected_hash) {
        die(format!(
            "RPC published blob transaction {published}, but signed transaction hash is {expected_hash}"
        ));
    }
}

fn try_blob_receipt(rpc: &str, tx_hash: &str) -> Option<serde_json::Value> {
    let output = Command::new("cast")
        .args(["receipt", tx_hash, "--json", "--async", "--rpc-url", rpc])
        .output()
        .unwrap_or_else(|error| die(format!("cast receipt failed to start: {error}")));
    if !output.status.success() || output.stdout.is_empty() {
        return None;
    }
    serde_json::from_slice::<serde_json::Value>(&output.stdout)
        .ok()
        .filter(|value| !value.is_null())
}

fn receipt_quantity(receipt: &serde_json::Value, field: &str) -> u64 {
    let value = &receipt[field];
    if let Some(raw) = value.as_str() {
        parse_u64_quantity(raw, field)
    } else {
        value
            .as_u64()
            .unwrap_or_else(|| die(format!("blob-post receipt has no numeric {field}")))
    }
}

fn wait_for_finalized_blob_submission(
    rpc: &str,
    chain_id: u64,
    tx_hash: &str,
    rollup: &str,
    submitter: &str,
    proof_hash: &str,
    proof_length: u32,
    state_root: &str,
) -> (
    String,
    String,
    u64,
    intmax3_zkp::l1_finality::L1FinalizedCheckpoint,
) {
    let timeout_secs = std::env::var("INTMAX_L1_FINALITY_TIMEOUT_SECS")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .unwrap_or(3_600)
        .clamp(1, 86_400);
    let started = std::time::Instant::now();
    loop {
        if let Some(receipt) = try_blob_receipt(rpc, tx_hash) {
            let receipt_hash = receipt["transactionHash"]
                .as_str()
                .unwrap_or_else(|| die("blob-post receipt has no transactionHash"));
            if !same_hex_value(receipt_hash, tx_hash) {
                die("blob-post receipt hash differs from the signed transaction hash");
            }
            let from = receipt["from"]
                .as_str()
                .unwrap_or_else(|| die("blob-post receipt has no from"));
            let to = receipt["to"]
                .as_str()
                .unwrap_or_else(|| die("blob-post receipt has no to"));
            if !same_hex_value(from, submitter) || !same_hex_value(to, rollup) {
                die("blob-post receipt sender/target differs from the signed transaction");
            }
            let block_hash_text = receipt["blockHash"]
                .as_str()
                .unwrap_or_else(|| die("blob-post receipt has no blockHash"));
            let block_hash = block_hash_text
                .parse::<Bytes32>()
                .unwrap_or_else(|error| die(format!("parse blob-post block hash: {error}")));
            let block_number = receipt_quantity(&receipt, "blockNumber");
            let durable_before = read_durable_l1_checkpoint(rpc, chain_id);
            if block_number <= durable_before.block_number {
                let receipt_block_tag = format!("0x{block_number:x}");
                let canonical_receipt_block = rpc_block_json(rpc, &receipt_block_tag)
                    .and_then(|raw| {
                        parse_l1_checkpoint_block(&raw, chain_id, durable_before.source)
                    })
                    .unwrap_or_else(|error| {
                        die(format!("read canonical blob receipt block: {error}"))
                    });
                validate_receipt_block_evidence(
                    block_number,
                    block_hash,
                    &canonical_receipt_block,
                    &durable_before,
                )
                .unwrap_or_else(|error| {
                    die(format!(
                        "blob transaction {tx_hash} is not canonical/final: {error}"
                    ))
                });

                let second = try_blob_receipt(rpc, tx_hash)
                    .unwrap_or_else(|| die("blob-post receipt disappeared during final read-back"));
                for field in [
                    "transactionHash",
                    "blockHash",
                    "blockNumber",
                    "status",
                    "from",
                    "to",
                    "logs",
                ] {
                    if receipt[field] != second[field] {
                        die(format!(
                            "blob-post receipt field {field} changed during final read-back"
                        ));
                    }
                }
                revalidate_l1_checkpoint(rpc, &durable_before);
                let durable_after = read_durable_l1_checkpoint(rpc, chain_id);
                if durable_after.source != durable_before.source
                    || durable_after.block_number < durable_before.block_number
                    || (durable_after.block_number == durable_before.block_number
                        && (durable_after.block_hash != durable_before.block_hash
                            || durable_after.parent_hash != durable_before.parent_hash))
                {
                    die("durable L1 head regressed or changed during blob receipt read-back");
                }
                durable_after
                    .covers_receipt(block_number, block_hash)
                    .unwrap_or_else(|error| die(format!("blob receipt lost finality: {error}")));
                let submission_id = submitted_id_from_receipt(
                    &receipt,
                    rollup,
                    submitter,
                    proof_hash,
                    proof_length,
                    state_root,
                )
                .unwrap_or_else(|error| die(format!("validate Submitted event: {error}")));
                return (
                    submission_id,
                    block_hash_text.to_string(),
                    block_number,
                    durable_after,
                );
            }
        }
        if started.elapsed().as_secs() >= timeout_secs {
            die(format!(
                "blob transaction {tx_hash} is not covered by a canonical durable head after \
                 {timeout_secs}s; its signed raw transaction is safely persisted, so retry the \
                 exact lifecycle after L1 finality advances"
            ));
        }
        std::thread::sleep(std::time::Duration::from_secs(6));
    }
}

/// Post one block (index `i` into `lifecycle.blocks`) as its own blob submission round.  Returns
/// the finalized event-derived submission id and the compact sidecars for this exact transaction.
fn post_block_round(
    rollup: &str,
    lc: &serde_json::Value,
    i: usize,
    signer: &L1Signer,
    rpc: &str,
    proof_da_path: &str,
    proof_payload: &[u8],
    proof_hash: &str,
    proof_length: u32,
    journal_path: &Path,
    journal: &mut ProofDaPostJournal,
) -> (String, String) {
    let block = &lc["blocks"][i];
    let channel_id = block["channel_id"]
        .as_u64()
        .unwrap_or_else(|| die("block channel_id"));
    let timestamp = block["timestamp"]
        .as_u64()
        .unwrap_or_else(|| die("block timestamp"));
    let tx_tree_root = block["tx_tree_root"]
        .as_str()
        .unwrap_or_else(|| die("block tx_tree_root"));
    let key_ids = json_num_array(&block["key_ids"]);
    let sub_block = format!("[({channel_id},{timestamp},{tx_tree_root},{key_ids})]");
    let state_root = lc["final_state_root"]
        .as_str()
        .unwrap_or_else(|| die("final_state_root"));
    // M-5 (audit28-08-2026): pin the pending deposit/registration chains the witness was built
    // against. Both are LIVE CUMULATIVE and are folded into the last sub-block at POSTING time, so
    // any `deposit()` or `registerChannel()` landing in between would make the posted block commit
    // a chain the proof does not cover — `finalize` would then fail SILENTLY and block every
    // withdrawal until the ~12 h timeout. With the pin the race is a clean revert and we retry.
    let existing = journal.rounds.get(i).cloned();
    let (mut round, validated): (ProofDaPostRoundJournal, ValidatedBlobSidecars) =
        if let Some(round) = existing {
            let expected_calldata = cast(&[
            "calldata",
            "postBlockAndSubmit((uint32,uint64,bytes32,uint32[])[],bytes32,uint32,bytes32,bytes32)",
            &sub_block,
            proof_hash,
            &proof_length.to_string(),
            state_root,
            &round.pending_chains_pin,
        ])
        .trim()
        .to_string();
            if round.round_index != i || !same_hex_value(&round.calldata, &expected_calldata) {
                die(format!(
                    "persisted proof-DA round {i} has different calldata"
                ));
            }
            let decoded = decode_signed_blob_transaction(&round.raw_signed_transaction);
            let checked = validate_decoded_blob_transaction(
                &decoded,
                proof_payload,
                journal.chain_id,
                &journal.submitter,
                rollup,
                POST_BLOCK_STAKE_WEI,
                &round.calldata,
            )
            .unwrap_or_else(|error| {
                die(format!("revalidate persisted proof-DA round {i}: {error}"))
            });
            if !same_hex_value(&checked.transaction_hash, &round.transaction_hash)
                || checked.blob_versioned_hashes != round.blob_versioned_hashes
                || !same_hex_value(&checked.compact_sidecars, &round.compact_sidecars)
            {
                die(format!(
                    "persisted proof-DA round {i} sidecar metadata was modified"
                ));
            }
            (round, checked)
        } else {
            if journal.rounds.len() != i {
                die("proof-DA round journal is not a contiguous 0,1,2 sequence");
            }
            let pending_pin = cast_call(rpc, rollup, "pendingChainsPin()(bytes32)", &[])
                .trim()
                .to_string();
            let (raw_signed_transaction, calldata) = sign_blob_post(
                rollup,
                signer,
                rpc,
                &sub_block,
                proof_da_path,
                proof_hash,
                proof_length,
                state_root,
                &pending_pin,
            );
            let decoded = decode_signed_blob_transaction(&raw_signed_transaction);
            let checked = validate_decoded_blob_transaction(
                &decoded,
                proof_payload,
                journal.chain_id,
                &journal.submitter,
                rollup,
                POST_BLOCK_STAKE_WEI,
                &calldata,
            )
            .unwrap_or_else(|error| die(format!("validate signed proof-DA round {i}: {error}")));
            let round = ProofDaPostRoundJournal {
                round_index: i,
                pending_chains_pin: pending_pin,
                calldata,
                raw_signed_transaction,
                transaction_hash: checked.transaction_hash.clone(),
                blob_versioned_hashes: checked.blob_versioned_hashes.clone(),
                compact_sidecars: checked.compact_sidecars.clone(),
                submission_id: None,
                receipt_block_hash: None,
                receipt_block_number: None,
                finalized_checkpoint: None,
            };
            // Irreversible ordering: signed raw tx + sidecars hit durable storage first.  Only the
            // next line after this branch may publish it.
            journal.rounds.push(round.clone());
            write_private_json_at(journal_path, journal);
            (round, checked)
        };

    eprintln!(
        "[withdraw] postBlockAndSubmit round {i}: signed {} blob(s), tx {} (journaled before publish)…",
        validated.blob_versioned_hashes.len(),
        validated.transaction_hash
    );
    publish_blob_transaction(rpc, &round.raw_signed_transaction, &round.transaction_hash);
    let (submission_id, block_hash, block_number, finalized_checkpoint) =
        wait_for_finalized_blob_submission(
            rpc,
            journal.chain_id,
            &round.transaction_hash,
            rollup,
            &journal.submitter,
            proof_hash,
            proof_length,
            state_root,
        );
    if let Some(stored) = &round.submission_id {
        if !same_hex_value(stored, &submission_id)
            || round.receipt_block_hash.as_deref() != Some(block_hash.as_str())
            || round.receipt_block_number != Some(block_number)
        {
            die(format!(
                "proof-DA round {i} finalized receipt changed after persistence"
            ));
        }
        let stored_checkpoint = round.finalized_checkpoint.as_ref().unwrap_or_else(|| {
            die(format!(
                "proof-DA round {i} has a stored receipt without its finalized checkpoint"
            ))
        });
        // The durable head is expected to advance between runs.  Revalidate the old checkpoint
        // and exact receipt block, then accept the newer monotonically-covering checkpoint returned
        // above; byte-equality here used to make every otherwise healthy restart fail.
        revalidate_l1_checkpoint(rpc, stored_checkpoint);
        validate_durable_checkpoint_advancement(stored_checkpoint, &finalized_checkpoint)
            .unwrap_or_else(|error| {
                die(format!(
                    "proof-DA round {i} checkpoint progression: {error}"
                ))
            });
    } else {
        round.submission_id = Some(submission_id.clone());
        round.receipt_block_hash = Some(block_hash);
        round.receipt_block_number = Some(block_number);
        round.finalized_checkpoint = Some(finalized_checkpoint);
        journal.rounds[i] = round.clone();
        write_private_json_at(journal_path, journal);
    }
    (submission_id, round.compact_sidecars)
}

fn cmd_withdraw(args: &[String]) {
    let manager = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| die("withdraw needs <manager_addr> [rpc_url]"));
    let rpc = args
        .get(2)
        .cloned()
        .unwrap_or_else(|| "http://localhost:8545".to_string());
    // F4: resolve + validate the contracts checkout FIRST. `withdraw` is the longest pipeline in
    // this binary (channel-withdrawal proof set, then 3 blob posts, then finalize) and it did not
    // touch the checkout until the `finalize` step near the end — so a path error used to cost the
    // entire proof AND leave real on-chain state half-advanced. See `require_contracts_dir`.
    let contracts_dir = require_contracts_dir(
        "withdraw",
        &["script/RunClose.s.sol", "script/PrepareProofDa.s.sol"],
    );
    // Rollup address: explicit ROLLUP env, else the backing record from `setup-backing`.
    let rollup = std::env::var("ROLLUP")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| backing_exists().then(|| load_backing().2.rollup))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| die("set ROLLUP=0x<rollup addr> (or run setup-backing first)"));
    require_active_settlement_binding(&rpc, &manager, None, Some(&rollup));
    // Resolve every local prerequisite before touching the network. Besides making diagnostics
    // deterministic, this keeps an unavailable RPC from hiding an unusable checkout or missing
    // rollup configuration before the expensive withdrawal proof path starts.
    let chain_id = rpc_chain_id(&rpc);
    full_withdrawal_release_gate(chain_id).unwrap_or_else(|error| die(error));
    let l1_signer = L1Signer::for_chain_id(chain_id);
    let channel_id = channel_id_env();

    // The depositor MUST be the EOA that sends `deposit()` (its address is folded into block 2's
    // hash). Pin it to the funding key's address so the on-chain msg.sender reproduces the proof.
    let depositor_hex = l1_signer.address();
    let depositor = Address::from_hex(&depositor_hex)
        .unwrap_or_else(|e| die(format!("parse depositor address: {e:?}")));
    let manager_addr = Address::from_hex(manager.trim())
        .unwrap_or_else(|e| die(format!("parse manager address {manager}: {e:?}")));

    // P5-B: INTEGRATED (a backed channel from `setup-backing`) vs STANDALONE (self-contained P4
    // path). Integrated binds the withdrawal to the channel's REAL co-signing members + REAL
    // deposit so ONE on-chain registration + deposit serves both the close and withdraw paths.
    // Standalone keeps the P4 behavior (self-generated registration + its own deposit,
    // env-tunable amounts).
    //
    // CORRECTED (deposit-import-threat-model.md §10.4): this comment used to claim "the deposit
    // was already made on-chain by `setup-backing`, so we do NOT deposit again here". That is
    // FALSE and was load-bearing for a security argument — `withdraw` ALWAYS makes its own
    // `deposit()` below (step 3), in integrated mode too. Its hash is now backfilled into
    // `backing_deposit_txs` so the import guard can recognise it.
    let integrated = backing_exists();
    let (deposit_amount, withdrawal_amount, deposit_salt, cli_members): (
        u64,
        u64,
        Option<Salt>,
        Option<Vec<MemberKeys>>,
    ) = if integrated {
        let backing = load_backing().2;
        let fund = backing.fund;
        let salt = backing.deposit_salt.unwrap_or_else(|| {
            die(
                "channel_backing.json has no deposit_salt — re-run `setup-backing` (P5-B needs it to \
                 reconstruct the deposit block that matches the on-chain deposit). Fail-closed.",
            )
        });
        // ACTIVE set = 3 members + delegate. Option B: `build_channel_withdrawal` registers the
        // COSIGNER slice only (delegate_count = 0), matching `export-reg-record`'s cosigner-only
        // deploy registration, so finalize matches.
        //
        // B-2 (RESOLVED, doc/tasks/b2-delegate-close-threat-model.md): an on-chain CLOSE of a
        // delegate-bearing channel still exposes its live `delegate_count` in the close PI, and the
        // Manager's registered count is now a FLOOR rather than an exact expected value, so the
        // mismatch is no longer a refusal. `export-reg-record` may (and does) keep emitting
        // `delegate_count = 0` — under Option B that is CORRECT by design, not a tolerated gap:
        // L1 registration is cosigners-only and the delegate half of the boundary is rooted in the
        // N-of-N cosigner signature over the H1 that limb 94 decommits.
        let members = cli_active_keys();
        eprintln!(
            "[withdraw] integrated: real members + delegate + real deposit (fund {fund}); withdraw \
             makes the deposit in standalone fold order."
        );
        (fund, fund, Some(salt), Some(members))
    } else {
        let da: u64 = std::env::var("WD_DEPOSIT_AMOUNT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10);
        let wa: u64 = std::env::var("WD_AMOUNT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(3);
        (da, wa, None, None)
    };
    if withdrawal_amount > deposit_amount {
        die(format!(
            "withdrawal amount {withdrawal_amount} exceeds deposit amount {deposit_amount}"
        ));
    }

    // Multitoken Phase 5b: optional ERC-20 settlement lane. WD_ERC20_TOKEN (registered base
    // token index) + WD_ERC20_AMOUNT (deposited == withdrawn amount) + WD_ERC20_TOKEN_ADDR (the
    // ERC-20 contract, for the on-chain approve + deposit calls). The lane adds a second deposit
    // to the deposit block and produces a second withdrawal chain paid to the manager via
    // `withdrawERC20` → `pullChannelTokenFunds`.
    let erc20_env: Option<(u32, u64, String)> = match (
        std::env::var("WD_ERC20_TOKEN").ok(),
        std::env::var("WD_ERC20_AMOUNT").ok(),
        std::env::var("WD_ERC20_TOKEN_ADDR").ok(),
    ) {
        (Some(t), Some(a), Some(addr)) => {
            let token_address = addr
                .parse::<Address>()
                .unwrap_or_else(|error| die(format!("bad WD_ERC20_TOKEN_ADDR: {error}")))
                .to_string();
            Some((
                t.parse().unwrap_or_else(|_| die("bad WD_ERC20_TOKEN")),
                a.parse().unwrap_or_else(|_| die("bad WD_ERC20_AMOUNT")),
                token_address,
            ))
        }
        (None, None, None) => None,
        _ => die("set ALL of WD_ERC20_TOKEN / WD_ERC20_AMOUNT / WD_ERC20_TOKEN_ADDR, or none"),
    };

    let operation_key = FullWithdrawalOperationKey {
        chain_id,
        rollup: rollup.to_ascii_lowercase(),
        manager: manager_addr.to_string().to_ascii_lowercase(),
        depositor: depositor_hex.to_ascii_lowercase(),
        channel_id,
        integrated,
        deposit_amount,
        withdrawal_amount,
        erc20_token_index: erc20_env.as_ref().map(|(token, _, _)| *token),
        erc20_amount: erc20_env.as_ref().map(|(_, amount, _)| *amount),
        erc20_token: erc20_env
            .as_ref()
            .map(|(_, _, address)| address.to_ascii_lowercase()),
    };
    let (operation_dir, operation_journal_path, mut operation_journal) =
        load_or_create_full_withdrawal_operation(operation_key);

    if operation_journal.artifacts.is_none() {
        // Only a PREPARED operation without any L1 mutation may invoke the randomized prover.
        // Once these exact bytes are manifested, every restart loads them from the stable semantic
        // operation slot and proof regeneration is impossible.
        eprintln!(
            "[withdraw] building channel-withdrawal proof set (channel {channel_id}, deposit \
             {deposit_amount}, withdraw {withdrawal_amount} → manager {manager}) — HEAVY…"
        );
        let params = ChannelWithdrawalParams {
            channel_id,
            deposit_amount,
            withdrawal_amount,
            depositor: Some(depositor),
            withdrawal_recipient: Some(manager_addr),
            deposit_salt,
            erc20_lane: erc20_env.as_ref().map(|(t, a, _)| Erc20LaneParams {
                token_index: *t,
                deposit_amount: *a,
                withdrawal_amount: *a,
                deposit_salt: None,
            }),
            burn_aux_data: None,
        };
        let built = build_channel_withdrawal(&params, cli_members.as_deref())
            .unwrap_or_else(|error| die(format!("build withdrawal: {error}")));

        // PrepareProofDa reads this exact staged MLE file.  No L1 action has happened yet, so a
        // crash anywhere in this preflight may safely rebuild; the manifest below is the boundary
        // after which rebuilding is forbidden.
        let data_dir = contracts_dir.join("test/data");
        fs::write(
            data_dir.join("sepolia_lifecycle_validity_mle.json"),
            &built.validity_mle_json,
        )
        .unwrap_or_else(|error| die(format!("stage validity MLE for proof DA: {error}")));
        let (prepared_proof_path, proof_da) = prepare_validity_proof_da(&contracts_dir);
        let proof_da_payload = fs::read(&prepared_proof_path)
            .unwrap_or_else(|error| die(format!("read canonical proof DA payload: {error}")));
        let proof_da_metadata_bytes =
            fs::read(Path::new(PROOF_DA_DIR).join(PROOF_DA_METADATA_FILE))
                .unwrap_or_else(|error| die(format!("read canonical proof DA metadata: {error}")));

        let lifecycle_value: serde_json::Value = serde_json::from_str(&built.lifecycle_json)
            .unwrap_or_else(|error| die(format!("parse generated lifecycle JSON: {error}")));
        let final_state_root = lifecycle_value["final_state_root"]
            .as_str()
            .unwrap_or_else(|| die("generated lifecycle has no final_state_root"))
            .to_string();
        let native_nullifier =
            payout_nullifier(built.payout_json.as_bytes(), "generated withdrawal payout");
        let erc20_nullifier = built
            .erc20_payout_json
            .as_ref()
            .map(|json| payout_nullifier(json.as_bytes(), "generated ERC-20 withdrawal payout"));
        let mut files = vec![
            persist_full_withdrawal_artifact(
                &operation_dir,
                "lifecycle.json",
                built.lifecycle_json.as_bytes(),
            ),
            persist_full_withdrawal_artifact(
                &operation_dir,
                "lifecycle_validity_mle.json",
                built.validity_mle_json.as_bytes(),
            ),
            persist_full_withdrawal_artifact(
                &operation_dir,
                "withdrawal_mle.json",
                built.withdrawal_mle_json.as_bytes(),
            ),
            persist_full_withdrawal_artifact(
                &operation_dir,
                "withdrawal_payout.json",
                built.payout_json.as_bytes(),
            ),
        ];
        match (&built.erc20_withdrawal_mle_json, &built.erc20_payout_json) {
            (Some(mle), Some(payout)) => {
                files.push(persist_full_withdrawal_artifact(
                    &operation_dir,
                    "erc20_withdrawal_mle.json",
                    mle.as_bytes(),
                ));
                files.push(persist_full_withdrawal_artifact(
                    &operation_dir,
                    "erc20_withdrawal_payout.json",
                    payout.as_bytes(),
                ));
            }
            (None, None) => {}
            _ => die("generated ERC-20 withdrawal artifact pair is incomplete"),
        }
        files.push(persist_full_withdrawal_artifact(
            &operation_dir,
            PROOF_DA_FILE,
            &proof_da_payload,
        ));
        files.push(persist_full_withdrawal_artifact(
            &operation_dir,
            PROOF_DA_METADATA_FILE,
            &proof_da_metadata_bytes,
        ));
        operation_journal.artifacts = Some(FullWithdrawalArtifactManifest {
            files,
            proof_da,
            final_state_root,
            native_withdrawal_nullifier: native_nullifier,
            erc20_withdrawal_nullifier: erc20_nullifier,
        });
        write_private_json_at(&operation_journal_path, &operation_journal);
    } else {
        eprintln!(
            "[withdraw] resuming the exact manifested proof artifacts from {} (no proof regeneration)",
            operation_dir.display()
        );
    }

    let persisted_artifacts = load_persisted_full_withdrawal_artifacts(
        &operation_dir,
        operation_journal
            .artifacts
            .as_ref()
            .unwrap_or_else(|| die("withdrawal artifact manifest disappeared")),
    );
    stage_persisted_full_withdrawal_artifacts(&persisted_artifacts, &contracts_dir);
    let proof_da_path = persisted_artifacts
        .proof_da_path
        .to_str()
        .unwrap_or_else(|| die("proof-DA output path is not valid UTF-8"))
        .to_string();
    let proof_da = persisted_artifacts.proof_da.clone();
    let proof_payload = persisted_artifacts.proof_da_payload.clone();
    let proof_length = u32::try_from(proof_da.proof_length)
        .unwrap_or_else(|_| die("canonical proof DA payload exceeds the uint32 protocol limit"));
    eprintln!(
        "[withdraw] canonical proof DA: {} bytes / {} blob(s) / {}",
        proof_da.proof_length, proof_da.blob_count, proof_da.proof_hash
    );

    let lc: serde_json::Value = serde_json::from_slice(&persisted_artifacts.lifecycle_json)
        .unwrap_or_else(|e| die(format!("parse lifecycle json: {e}")));
    let reg = &lc["registration"];
    let final_state_root = lc["final_state_root"]
        .as_str()
        .unwrap_or_else(|| die("final_state_root"));
    let proof_da_journal_path = operation_dir.join("proof-da-posts.json");
    let mut proof_da_journal = load_or_create_proof_da_post_journal(
        &proof_da_journal_path,
        chain_id,
        &rollup,
        &depositor_hex,
        &proof_da.proof_hash,
        proof_length,
        final_state_root,
    );

    // 1. registerChannel (one-time per channel; skip if already registered so re-runs are
    //    idempotent and the close-lifecycle path — where the channel is already registered —
    //    composes).
    let existing = cast(&[
        "call",
        &rollup,
        "channelMemberSetCommitment(uint32)(bytes32)",
        &channel_id.to_string(),
        "--rpc-url",
        &rpc,
    ]);
    let already_registered = existing
        .trim()
        .trim_start_matches("0x")
        .chars()
        .any(|c| c != '0');
    let expected_registration_commitment = lifecycle_registration_commitment(reg);
    let bp_slot = reg["bp_member_slot"]
        .as_u64()
        .unwrap_or_else(|| die("bp_member_slot"))
        .to_string();
    let expected_bp_pk_g = reg["member_pk_gs"]
        .as_array()
        .and_then(|values| values.get(bp_slot.parse::<usize>().unwrap_or(usize::MAX)))
        .and_then(|value| value.as_str())
        .unwrap_or_else(|| die("registration bp_member_slot does not select a member pk_g"));
    if already_registered {
        let observed_bp_slot = cast_call(
            &rpc,
            &rollup,
            "channelBpMemberSlot(uint32)(uint8)",
            &[&channel_id.to_string()],
        );
        let observed_bp_pk_g = cast_call(
            &rpc,
            &rollup,
            "channelBpPkG(uint32)(bytes32)",
            &[&channel_id.to_string()],
        );
        if !same_hex_value(existing.trim(), &expected_registration_commitment)
            || observed_bp_slot.trim() != bp_slot
            || !same_hex_value(&observed_bp_pk_g, expected_bp_pk_g)
        {
            die(format!(
                "channel {channel_id} is already registered with a different member set/BP identity; refusing to post or deposit against it"
            ));
        }
        eprintln!("[withdraw] channel {channel_id} exact registration already exists — reconciled");
    } else {
        eprintln!("[withdraw] registerChannel({channel_id})…");
        let pk_gs = json_str_array(&reg["member_pk_gs"]);
        let pk_bs = json_str_array(&reg["member_pk_bs"]);
        let regev = json_str_array(&reg["regev_pk_digests"]);
        let recipients = json_str_array(&reg["recipients"]);
        let registration_calldata = cast(&[
            "calldata",
            "registerChannel(uint32,uint8,uint8,bytes32[],bytes32[],bytes32[],address[])",
            &channel_id.to_string(),
            &bp_slot,
            "0",
            &pk_gs,
            &pk_bs,
            &regev,
            &recipients,
        ]);
        execute_full_withdrawal_call(
            &rpc,
            chain_id,
            &l1_signer,
            &operation_journal_path,
            &mut operation_journal,
            "register-channel",
            &rollup,
            registration_calldata.trim(),
            0,
        );
        let observed = cast_call(
            &rpc,
            &rollup,
            "channelMemberSetCommitment(uint32)(bytes32)",
            &[&channel_id.to_string()],
        );
        if !same_hex_value(&observed, &expected_registration_commitment) {
            die(
                "registerChannel receipt finalized but exact member-set commitment read-back failed",
            );
        }
    }

    // 2. Registration block.
    let (registration_submission, _) = post_block_round(
        &rollup,
        &lc,
        0,
        &l1_signer,
        &rpc,
        &proof_da_path,
        &proof_payload,
        &proof_da.proof_hash,
        proof_length,
        &proof_da_journal_path,
        &mut proof_da_journal,
    );

    // 3. Deposit (P5-B 案B: `withdraw` ALWAYS makes the deposit here, between the registration
    //    block and the deposit block — the standalone fold order the withdrawal proof models. In
    //    integrated mode `setup-backing` deliberately deferred the on-chain deposit to this point,
    //    so there is no earlier pending deposit to pollute the registration block. Sent BY the
    //    depositor key (== the proved depositor), escrowing real native into the rollup.)
    {
        let dep = &lc["deposit"];
        let dep_recipient = dep["recipient"]
            .as_str()
            .unwrap_or_else(|| die("deposit.recipient"));
        let dep_token = u32::try_from(
            dep["token_index"]
                .as_u64()
                .unwrap_or_else(|| die("deposit.token_index")),
        )
        .unwrap_or_else(|_| die("deposit.token_index exceeds u32"));
        let dep_amount_text = dep["amount"]
            .as_str()
            .unwrap_or_else(|| die("deposit.amount"));
        let dep_amount = dep_amount_text
            .parse::<u64>()
            .unwrap_or_else(|error| die(format!("parse deposit.amount: {error}")));
        let dep_aux = dep["aux_data"]
            .as_str()
            .unwrap_or_else(|| die("deposit.aux_data"));
        eprintln!(
            "[withdraw] deposit{{value: {dep_amount}}}(recipient,…) as depositor {depositor_hex}…"
        );
        let deposit_calldata = cast(&[
            "calldata",
            "deposit(bytes32,uint32,uint256,bytes32)",
            dep_recipient,
            &dep_token.to_string(),
            dep_amount_text,
            dep_aux,
        ]);
        let deposit_confirmation = execute_full_withdrawal_call(
            &rpc,
            chain_id,
            &l1_signer,
            &operation_journal_path,
            &mut operation_journal,
            "deposit-native",
            &rollup,
            deposit_calldata.trim(),
            dep_amount,
        );
        let deposit_recipient = dep_recipient
            .parse::<Bytes32>()
            .unwrap_or_else(|error| die(format!("parse deposit recipient: {error}")));
        let observed = fetch_onchain_deposit(
            &rpc,
            &deposit_confirmation.transaction_hash,
            &rollup,
            deposit_recipient,
            Some(1),
        );
        let expected_aux = dep_aux
            .parse::<Bytes32>()
            .unwrap_or_else(|error| die(format!("parse deposit aux data: {error}")));
        if observed.chain_id != chain_id
            || observed.depositor != depositor
            || observed.token_index != dep_token
            || observed.amount != dep_amount
            || observed.aux_data != expected_aux
        {
            die("canonical native Deposited event differs from the manifested lifecycle");
        }
        // SECURITY (§10.4 Finding B): capture and PERSIST this hash before doing anything else.
        // It is a real `Deposited` log from this rollup to the channel's own `deposit_recipient`,
        // so it passes every check on the import path; only the backing-deposit guard can refuse
        // it, and the guard can only refuse what it has been told about. In STANDALONE mode there
        // is no backing file to record into (and no import path either, since
        // `cosign-l1-deposit-import` requires the backing).
        if integrated {
            record_backing_deposit_tx(&deposit_confirmation.transaction_hash);
        }

        // Multitoken Phase 5b: the ERC-20 lane's deposit — SECOND in the block, matching the
        // proof's fold order. `deposit()`'s ERC-20 branch pulls via transferFrom (balanceOf-delta
        // checked on-chain, TM-4), so approve first; no --value.
        if let Some((_, _, token_addr)) = &erc20_env {
            let dep2 = &lc["deposit_erc20"];
            let dep2_recipient = dep2["recipient"]
                .as_str()
                .unwrap_or_else(|| die("deposit_erc20.recipient"));
            let dep2_token = u32::try_from(
                dep2["token_index"]
                    .as_u64()
                    .unwrap_or_else(|| die("deposit_erc20.token_index")),
            )
            .unwrap_or_else(|_| die("deposit_erc20.token_index exceeds u32"));
            let dep2_amount_text = dep2["amount"]
                .as_str()
                .unwrap_or_else(|| die("deposit_erc20.amount"));
            let dep2_amount = dep2_amount_text
                .parse::<u64>()
                .unwrap_or_else(|error| die(format!("parse deposit_erc20.amount: {error}")));
            let dep2_aux = dep2["aux_data"]
                .as_str()
                .unwrap_or_else(|| die("deposit_erc20.aux_data"));
            eprintln!(
                "[withdraw] approve + ERC-20 deposit (token {dep2_token}, amount {dep2_amount}) as \
                 depositor {depositor_hex}…"
            );
            let approval_calldata = cast(&[
                "calldata",
                "approve(address,uint256)",
                &rollup,
                dep2_amount_text,
            ]);
            execute_full_withdrawal_call(
                &rpc,
                chain_id,
                &l1_signer,
                &operation_journal_path,
                &mut operation_journal,
                "approve-erc20-deposit",
                token_addr,
                approval_calldata.trim(),
                0,
            );
            let erc20_deposit_calldata = cast(&[
                "calldata",
                "deposit(bytes32,uint32,uint256,bytes32)",
                dep2_recipient,
                &dep2_token.to_string(),
                dep2_amount_text,
                dep2_aux,
            ]);
            let erc20_deposit_confirmation = execute_full_withdrawal_call(
                &rpc,
                chain_id,
                &l1_signer,
                &operation_journal_path,
                &mut operation_journal,
                "deposit-erc20",
                &rollup,
                erc20_deposit_calldata.trim(),
                0,
            );
            let observed = fetch_onchain_deposit(
                &rpc,
                &erc20_deposit_confirmation.transaction_hash,
                &rollup,
                dep2_recipient.parse::<Bytes32>().unwrap_or_else(|error| {
                    die(format!("parse ERC-20 deposit recipient: {error}"))
                }),
                Some(1),
            );
            if observed.chain_id != chain_id
                || observed.depositor != depositor
                || observed.token_index != dep2_token
                || observed.amount != dep2_amount
                || observed.aux_data
                    != dep2_aux.parse::<Bytes32>().unwrap_or_else(|error| {
                        die(format!("parse ERC-20 deposit aux data: {error}"))
                    })
            {
                die("canonical ERC-20 Deposited event differs from the manifested lifecycle");
            }
            // SECURITY: the ERC-20 lane's deposit is recorded for the SAME reason as the native
            // one — its value is already spoken for by the withdrawal proof, so importing it into
            // the channel balance would credit value twice against one escrow.
            if integrated {
                record_backing_deposit_tx(&erc20_deposit_confirmation.transaction_hash);
            }
        }
    }

    // 4. Deposit block, then 5. Withdrawal block.
    let (deposit_submission, _) = post_block_round(
        &rollup,
        &lc,
        1,
        &l1_signer,
        &rpc,
        &proof_da_path,
        &proof_payload,
        &proof_da.proof_hash,
        proof_length,
        &proof_da_journal_path,
        &mut proof_da_journal,
    );
    let (final_sub, final_blob_sidecars) = post_block_round(
        &rollup,
        &lc,
        2,
        &l1_signer,
        &rpc,
        &proof_da_path,
        &proof_payload,
        &proof_da.proof_hash,
        proof_length,
        &proof_da_journal_path,
        &mut proof_da_journal,
    );

    // 6. Split proof-DA attestation and MLE finalization.  Each call has its own durable intent and
    // canonical finalized receipt; combining the ~22M KZG opening with the ~11M MLE verification
    // in one transaction exceeds the supported Ethereum block gas budget.
    let final_submission_id = parse_u64_quantity(&final_sub, "final submission id");
    let final_post_block = proof_da_journal
        .rounds
        .get(2)
        .and_then(|round| round.receipt_block_number)
        .unwrap_or_else(|| die("final proof-DA post has no canonical receipt block"));
    eprintln!("[withdraw] attest proof DA for submission {final_sub}…");
    let attest_intent = prepare_run_close_full_withdrawal_step(
        &contracts_dir,
        &rpc,
        chain_id,
        &l1_signer,
        &operation_journal_path,
        &mut operation_journal,
        "attest-proof-data",
        "attestProofDataStep()",
        &rollup,
        &[
            ("ROLLUP", &rollup),
            ("SUB_ID", &final_sub),
            ("BLOB_SIDECARS", &final_blob_sidecars),
        ],
        Some(final_post_block),
    );
    let (kzg, submission_commitment, proof_already_attested) = proof_data_attestation_state(
        &rpc,
        &rollup,
        final_submission_id,
        &proof_da.proof_hash,
        proof_length,
        None,
    );
    let attestation_confirmation = if attest_intent.confirmation.is_some() {
        execute_full_withdrawal_call(
            &rpc,
            chain_id,
            &l1_signer,
            &operation_journal_path,
            &mut operation_journal,
            "attest-proof-data",
            &attest_intent.target,
            &attest_intent.calldata,
            attest_intent.value,
        )
    } else if attest_intent.external_completion.is_some() || proof_already_attested {
        reconcile_external_full_withdrawal_effect(
            &rpc,
            chain_id,
            &operation_journal_path,
            &mut operation_journal,
            "attest-proof-data",
            &kzg,
            &FullWithdrawalEventExpectation::ProofDataAttested {
                rollup: rollup.clone(),
                submission_id: final_submission_id,
                submission_commitment,
                proof_hash: proof_da.proof_hash.clone(),
                proof_length,
            },
        )
        .unwrap_or_else(|| {
            die(
                "the exact proof-DA attestation is visible but its event is not yet covered by the durable L1 head; retry after finality",
            )
        })
    } else {
        execute_full_withdrawal_call(
            &rpc,
            chain_id,
            &l1_signer,
            &operation_journal_path,
            &mut operation_journal,
            "attest-proof-data",
            &attest_intent.target,
            &attest_intent.calldata,
            attest_intent.value,
        )
    };
    let (_, _, attested_at_receipt) = proof_data_attestation_state(
        &rpc,
        &rollup,
        final_submission_id,
        &proof_da.proof_hash,
        proof_length,
        Some(attestation_confirmation.block_number),
    );
    if !attested_at_receipt {
        die(
            "canonical proof-DA attestation receipt did not authenticate the manifested proof bytes",
        );
    }

    eprintln!("[withdraw] finalize submission {final_sub} (real validity MLE)…");
    let finalize_intent = prepare_run_close_full_withdrawal_step(
        &contracts_dir,
        &rpc,
        chain_id,
        &l1_signer,
        &operation_journal_path,
        &mut operation_journal,
        "finalize-validity",
        "finalizeStep()",
        &rollup,
        &[("ROLLUP", &rollup), ("SUB_ID", &final_sub)],
        Some(attestation_confirmation.block_number),
    );
    let already_finalized = cast_call(&rpc, &rollup, "isFinalized(uint256)(bool)", &[&final_sub])
        .trim()
        .eq_ignore_ascii_case("true");
    let finalize_confirmation = if finalize_intent.confirmation.is_some() {
        execute_full_withdrawal_call(
            &rpc,
            chain_id,
            &l1_signer,
            &operation_journal_path,
            &mut operation_journal,
            "finalize-validity",
            &finalize_intent.target,
            &finalize_intent.calldata,
            finalize_intent.value,
        )
    } else if finalize_intent.external_completion.is_some() || already_finalized {
        reconcile_external_full_withdrawal_effect(
            &rpc,
            chain_id,
            &operation_journal_path,
            &mut operation_journal,
            "finalize-validity",
            &rollup,
            &FullWithdrawalEventExpectation::Finalized {
                submission_id: final_submission_id,
                state_root: final_state_root.to_string(),
            },
        )
        .unwrap_or_else(|| {
            die(
                "submission is finalized but its exact Finalized event is not yet covered by the durable L1 head; retry after finality",
            )
        })
    } else {
        execute_full_withdrawal_call(
            &rpc,
            chain_id,
            &l1_signer,
            &operation_journal_path,
            &mut operation_journal,
            "finalize-validity",
            &finalize_intent.target,
            &finalize_intent.calldata,
            finalize_intent.value,
        )
    };
    if !read_bool_view_at(
        &rpc,
        &rollup,
        "isFinalized(uint256)",
        &final_sub,
        finalize_confirmation.block_number,
    ) || !read_bool_view_at(
        &rpc,
        &rollup,
        "isFinalizedStateRoot(bytes32)",
        final_state_root,
        finalize_confirmation.block_number,
    ) {
        die("finalized submission/root canonical receipt-block read-back failed");
    }

    // One aggregate proof finalizes all three rounds but `finalize` refunds only the selected
    // submission. Reclaim the first two now that their block ranges are finalized, then pull all
    // three credits. A zero submitter means the exact bond was already refunded/reclaimed; this
    // makes crash recovery idempotent without trusting a local completion flag.
    for submission in [&registration_submission, &deposit_submission] {
        let step = format!("reclaim-stake-{submission}");
        let calldata = cast(&["calldata", "reclaimStake(uint256)", submission]);
        let intent = ensure_full_withdrawal_call_intent(
            &rpc,
            chain_id,
            &l1_signer,
            &operation_journal_path,
            &mut operation_journal,
            &step,
            &rollup,
            calldata.trim(),
            0,
            Some(finalize_confirmation.block_number),
        );
        let stake = cast_call(
            &rpc,
            &rollup,
            "stakeInfo(uint256)(address,bool)",
            &[submission],
        );
        let submitter = stake
            .split_whitespace()
            .next()
            .unwrap_or_else(|| die("stakeInfo returned no submitter"));
        let stake_cleared = same_hex_value(submitter, "0x0000000000000000000000000000000000000000");
        let reclaim_confirmation = if intent.confirmation.is_some() {
            execute_full_withdrawal_call(
                &rpc,
                chain_id,
                &l1_signer,
                &operation_journal_path,
                &mut operation_journal,
                &step,
                &intent.target,
                &intent.calldata,
                intent.value,
            )
        } else if intent.external_completion.is_some() || stake_cleared {
            reconcile_external_full_withdrawal_effect(
                &rpc,
                chain_id,
                &operation_journal_path,
                &mut operation_journal,
                &step,
                &rollup,
                &FullWithdrawalEventExpectation::WithdrawalCredited {
                    recipient: depositor_hex.clone(),
                    amount: POST_BLOCK_STAKE_WEI,
                },
            )
            .unwrap_or_else(|| {
                die(format!(
                    "stake {submission} is cleared but the exact permissionless reclaim event is not yet durable"
                ))
            })
        } else {
            execute_full_withdrawal_call(
                &rpc,
                chain_id,
                &l1_signer,
                &operation_journal_path,
                &mut operation_journal,
                &step,
                &rollup,
                calldata.trim(),
                0,
            )
        };
        let after = cast_call_at(
            &rpc,
            &rollup,
            "stakeInfo(uint256)(address,bool)",
            &[submission],
            reclaim_confirmation.block_number,
        );
        let after_submitter = after
            .split_whitespace()
            .next()
            .unwrap_or_else(|| die("stakeInfo read-back returned no submitter"));
        if !same_hex_value(
            after_submitter,
            "0x0000000000000000000000000000000000000000",
        ) {
            die(format!(
                "stake {submission} was not cleared after canonical reclaim"
            ));
        }
    }
    let pending_stake_refund = cast_call(
        &rpc,
        &rollup,
        "pendingWithdrawals(address)(uint256)",
        &[&depositor_hex],
    );
    let pending_stake_refund = pending_stake_refund
        .split_whitespace()
        .next()
        .unwrap_or_else(|| die("pendingWithdrawals returned no amount"));
    if let Some(intent) = operation_journal.calls.get("pull-stake-refunds").cloned() {
        execute_full_withdrawal_call(
            &rpc,
            chain_id,
            &l1_signer,
            &operation_journal_path,
            &mut operation_journal,
            "pull-stake-refunds",
            &intent.target,
            &intent.calldata,
            intent.value,
        );
    } else if parse_u64_quantity(pending_stake_refund, "pending stake refund") != 0 {
        let calldata = cast(&["calldata", "withdraw(uint256)", pending_stake_refund]);
        execute_full_withdrawal_call(
            &rpc,
            chain_id,
            &l1_signer,
            &operation_journal_path,
            &mut operation_journal,
            "pull-stake-refunds",
            &rollup,
            calldata.trim(),
            0,
        );
    }

    // 7. withdrawNative.  Dry-run only materializes the exact large calldata; the durable
    // write-ahead intent owns the actual broadcast and restart reconciliation.
    eprintln!("[withdraw] withdrawNative (real withdrawal MLE) → manager {manager}…");
    let native_descriptor =
        full_withdrawal_descriptor(&persisted_artifacts.payout_json, "withdrawal_payout.json");
    let native_nullifier = native_descriptor.nullifier.clone();
    let native_intent = prepare_run_close_full_withdrawal_step(
        &contracts_dir,
        &rpc,
        chain_id,
        &l1_signer,
        &operation_journal_path,
        &mut operation_journal,
        "withdraw-native",
        "withdrawNativeStep()",
        &rollup,
        &[("ROLLUP", &rollup), ("MANAGER", &manager)],
        Some(finalize_confirmation.block_number),
    );
    let native_used = cast_call(
        &rpc,
        &rollup,
        "withdrawalNullifierUsed(bytes32)(bool)",
        &[&native_nullifier],
    )
    .trim()
    .eq_ignore_ascii_case("true");
    let native_withdrawal_confirmation = if native_intent.confirmation.is_some() {
        execute_full_withdrawal_call(
            &rpc,
            chain_id,
            &l1_signer,
            &operation_journal_path,
            &mut operation_journal,
            "withdraw-native",
            &native_intent.target,
            &native_intent.calldata,
            native_intent.value,
        )
    } else if native_intent.external_completion.is_some() || native_used {
        reconcile_external_full_withdrawal_effect(
            &rpc,
            chain_id,
            &operation_journal_path,
            &mut operation_journal,
            "withdraw-native",
            &rollup,
            &FullWithdrawalEventExpectation::NativeWithdrawn {
                recipient: native_descriptor.recipient.clone(),
                amount: native_descriptor.amount,
                nullifier: native_descriptor.nullifier.clone(),
                intmax_block_number: native_descriptor.intmax_block_number,
            },
        )
        .unwrap_or_else(|| {
            die(
                "native withdrawal nullifier is used but its exact event is not yet covered by the durable L1 head",
            )
        })
    } else {
        execute_full_withdrawal_call(
            &rpc,
            chain_id,
            &l1_signer,
            &operation_journal_path,
            &mut operation_journal,
            "withdraw-native",
            &native_intent.target,
            &native_intent.calldata,
            native_intent.value,
        )
    };
    if !read_bool_view_at(
        &rpc,
        &rollup,
        "withdrawalNullifierUsed(bytes32)",
        &native_nullifier,
        native_withdrawal_confirmation
            .finalized_checkpoint
            .block_number,
    ) {
        die("canonical withdrawNative receipt did not consume the manifested nullifier");
    }

    // 7b. Multitoken Phase 5b: the ERC-20 lane — withdrawERC20 (its own chain + the SAME
    //     withdrawal VK) credits pendingTokenWithdrawals[t][manager].
    let erc20_withdrawal_confirmation = if let Some((token_index, ..)) = &erc20_env {
        eprintln!(
            "[withdraw] withdrawERC20 (real withdrawal MLE, token {token_index}) → manager {manager}…"
        );
        let erc20_descriptor = full_withdrawal_descriptor(
            persisted_artifacts
                .erc20_payout_json
                .as_deref()
                .unwrap_or_else(|| die("ERC-20 lane has no persisted payout artifact")),
            "erc20_withdrawal_payout.json",
        );
        let erc20_nullifier = erc20_descriptor.nullifier.clone();
        let erc20_intent = prepare_run_close_full_withdrawal_step(
            &contracts_dir,
            &rpc,
            chain_id,
            &l1_signer,
            &operation_journal_path,
            &mut operation_journal,
            "withdraw-erc20",
            "withdrawErc20Step()",
            &rollup,
            &[("ROLLUP", &rollup), ("MANAGER", &manager)],
            Some(finalize_confirmation.block_number),
        );
        let erc20_used = cast_call(
            &rpc,
            &rollup,
            "withdrawalNullifierUsed(bytes32)(bool)",
            &[&erc20_nullifier],
        )
        .trim()
        .eq_ignore_ascii_case("true");
        let confirmation = if erc20_intent.confirmation.is_some() {
            execute_full_withdrawal_call(
                &rpc,
                chain_id,
                &l1_signer,
                &operation_journal_path,
                &mut operation_journal,
                "withdraw-erc20",
                &erc20_intent.target,
                &erc20_intent.calldata,
                erc20_intent.value,
            )
        } else if erc20_intent.external_completion.is_some() || erc20_used {
            reconcile_external_full_withdrawal_effect(
                &rpc,
                chain_id,
                &operation_journal_path,
                &mut operation_journal,
                "withdraw-erc20",
                &rollup,
                &FullWithdrawalEventExpectation::Erc20Withdrawn {
                    recipient: erc20_descriptor.recipient.clone(),
                    token_index: erc20_descriptor.token_index,
                    amount: erc20_descriptor.amount,
                    nullifier: erc20_descriptor.nullifier.clone(),
                    intmax_block_number: erc20_descriptor.intmax_block_number,
                },
            )
            .unwrap_or_else(|| {
                die(
                    "ERC-20 withdrawal nullifier is used but its exact event is not yet covered by the durable L1 head",
                )
            })
        } else {
            execute_full_withdrawal_call(
                &rpc,
                chain_id,
                &l1_signer,
                &operation_journal_path,
                &mut operation_journal,
                "withdraw-erc20",
                &erc20_intent.target,
                &erc20_intent.calldata,
                erc20_intent.value,
            )
        };
        if !read_bool_view_at(
            &rpc,
            &rollup,
            "withdrawalNullifierUsed(bytes32)",
            &erc20_nullifier,
            confirmation.finalized_checkpoint.block_number,
        ) {
            die("canonical withdrawERC20 receipt did not consume the manifested nullifier");
        }
        Some(confirmation)
    } else {
        None
    };

    // 8. pullChannelFunds (manager pulls its escrowed credit out of the rollup).
    eprintln!("[withdraw] pullChannelFunds() on manager {manager}…");
    let pull_native_calldata = cast(&["calldata", "pullChannelFunds()"]);
    let pull_native_intent = ensure_full_withdrawal_call_intent(
        &rpc,
        chain_id,
        &l1_signer,
        &operation_journal_path,
        &mut operation_journal,
        "manager-pull-native",
        &manager,
        pull_native_calldata.trim(),
        0,
        Some(native_withdrawal_confirmation.block_number),
    );
    let pending_native = cast_call(
        &rpc,
        &rollup,
        "pendingWithdrawals(address)(uint256)",
        &[&manager],
    );
    let pending_native = parse_u64_quantity(
        pending_native.split_whitespace().next().unwrap_or_default(),
        "manager native pending credit",
    );
    let pull_native_confirmation = if pull_native_intent.confirmation.is_some() {
        execute_full_withdrawal_call(
            &rpc,
            chain_id,
            &l1_signer,
            &operation_journal_path,
            &mut operation_journal,
            "manager-pull-native",
            &pull_native_intent.target,
            &pull_native_intent.calldata,
            pull_native_intent.value,
        )
    } else if pull_native_intent.external_completion.is_some() || pending_native == 0 {
        reconcile_external_full_withdrawal_effect(
            &rpc,
            chain_id,
            &operation_journal_path,
            &mut operation_journal,
            "manager-pull-native",
            &manager,
            &FullWithdrawalEventExpectation::ChannelFundsPulled {
                token_index: 0,
                minimum_amount: native_descriptor.amount,
            },
        )
        .unwrap_or_else(|| {
            die(
                "manager native credit is zero but the exact permissionless pull event is not yet durable",
            )
        })
    } else {
        execute_full_withdrawal_call(
            &rpc,
            chain_id,
            &l1_signer,
            &operation_journal_path,
            &mut operation_journal,
            "manager-pull-native",
            &pull_native_intent.target,
            &pull_native_intent.calldata,
            pull_native_intent.value,
        )
    };
    if read_u64_view_at(
        &rpc,
        &rollup,
        "pendingWithdrawals(address)",
        &manager,
        pull_native_confirmation.finalized_checkpoint.block_number,
    ) != 0
    {
        die("manager native pending credit remained after canonical pullChannelFunds receipt");
    }
    // 8b. pullChannelTokenFunds(t) — the ERC-20 mirror (measured balanceOf delta).
    if let Some((token_index, ..)) = &erc20_env {
        eprintln!("[withdraw] pullChannelTokenFunds({token_index}) on manager {manager}…");
        let token_index_text = token_index.to_string();
        let calldata = cast(&[
            "calldata",
            "pullChannelTokenFunds(uint32)",
            &token_index_text,
        ]);
        let intent = ensure_full_withdrawal_call_intent(
            &rpc,
            chain_id,
            &l1_signer,
            &operation_journal_path,
            &mut operation_journal,
            "manager-pull-erc20",
            &manager,
            calldata.trim(),
            0,
            Some(
                erc20_withdrawal_confirmation
                    .as_ref()
                    .unwrap_or_else(|| die("ERC-20 pull has no causal withdrawal confirmation"))
                    .block_number,
            ),
        );
        let pending_token = cast_call(
            &rpc,
            &rollup,
            "pendingTokenWithdrawals(uint32,address)(uint256)",
            &[&token_index_text, &manager],
        );
        let pending_token = parse_u64_quantity(
            pending_token.split_whitespace().next().unwrap_or_default(),
            "manager ERC-20 pending credit",
        );
        let confirmation = if intent.confirmation.is_some() {
            execute_full_withdrawal_call(
                &rpc,
                chain_id,
                &l1_signer,
                &operation_journal_path,
                &mut operation_journal,
                "manager-pull-erc20",
                &intent.target,
                &intent.calldata,
                intent.value,
            )
        } else if intent.external_completion.is_some() || pending_token == 0 {
            reconcile_external_full_withdrawal_effect(
                &rpc,
                chain_id,
                &operation_journal_path,
                &mut operation_journal,
                "manager-pull-erc20",
                &manager,
                &FullWithdrawalEventExpectation::ChannelFundsPulled {
                    token_index: *token_index,
                    minimum_amount: erc20_env
                        .as_ref()
                        .map(|(_, amount, _)| *amount)
                        .unwrap_or(0),
                },
            )
            .unwrap_or_else(|| {
                die(
                    "manager ERC-20 credit is zero but the exact permissionless pull event is not yet durable",
                )
            })
        } else {
            execute_full_withdrawal_call(
                &rpc,
                chain_id,
                &l1_signer,
                &operation_journal_path,
                &mut operation_journal,
                "manager-pull-erc20",
                &intent.target,
                &intent.calldata,
                intent.value,
            )
        };
        if read_u64_view2_at(
            &rpc,
            &rollup,
            "pendingTokenWithdrawals(uint32,address)",
            &token_index_text,
            &manager,
            confirmation.finalized_checkpoint.block_number,
        ) != 0
        {
            die("manager ERC-20 pending credit remained after canonical token pull receipt");
        }
    }
    operation_journal.complete = true;
    write_private_json_at(&operation_journal_path, &operation_journal);
    println!(
        "[withdraw] OK: {withdrawal_amount} native withdrawn from the rollup into manager {manager} \
         (now `claim` per member to distribute)."
    );
}

/// A-3 P5-B: emit the channel's member registration record (the 3 CLI co-signing members), derived
/// deterministically — NO proving. Writes `cli_reg_record.json` and prints it. A deploy script
/// reads it to `registerChannel` the channel with these members AND bind the manager to them, so
/// the member-set commitment the close proof binds and the registration block `withdraw` posts both
/// match this single on-chain registration. The recipients use the canonical per-(channel, slot)
/// formula (`ChannelMemberKeys::to_reg_record`) so they equal the recipients
/// `build_channel_withdrawal` emits.
fn cmd_export_reg_record() {
    let s = serde_json::to_string_pretty(&build_reg_record()).unwrap_or_else(|e| die(e));
    fs::write("cli_reg_record.json", &s)
        .unwrap_or_else(|e| die(format!("write cli_reg_record.json: {e}")));
    println!("{s}");
}

/// THE registration record `cli_reg_record.json` carries, as a value.
///
/// SECURITY (why this is a function and not a second copy of the code): the Phase-3 finding-7
/// incident was caused by a SECOND derivation of the member set existing beside the first, so
/// `export-reg-record` registered one member set on L1 while `withdraw` proved against another —
/// fail-closed, but the channel became permanently unclosable. `deploy-settlement`'s real-chain
/// path has to stage the SAME record for `DeployCloseCli.s.sol`, so it calls this rather than
/// rebuilding it: there is exactly one derivation, and the two commands cannot drift.
fn build_reg_record() -> serde_json::Value {
    let channel_id = channel_id_env();
    // SECURITY (Option B, tasks/reg-chain-1024-threat-model.md): L1 registration is
    // COSIGNERS-ONLY — the record carries the 3 CLI co-signing members with `delegate_count = 0`.
    // Delegates (the browser slots >= TEST_ACTIVE_MEMBERS) are authenticated by the
    // cosigner-signed H1 balance-slot tree, never by prior L1 registration; their claim-recipient
    // binding is the B-1c leaf `recipient` field (NOT `registeredRecipientOf`).
    let members: Vec<MemberKeys> = cli_active_keys()
        .into_iter()
        .take(TEST_ACTIVE_MEMBERS)
        .collect();
    let delegate_count = 0usize;
    let active = members.len();
    // falcon-sig Phase 4: the registered member identity is the member's OWN Falcon `pk_g`, read
    // off the same `MemberKeys` the close/cancel-close paths sign with — so the member-set
    // commitment the close proof binds equals the one this record registers, by construction.
    let record = ChannelMemberKeys::from_member_keys(&members).to_reg_record_split(
        channel_id,
        TEST_ACTIVE_MEMBERS as u32,
        delegate_count as u32,
    );
    let mut member_pk_gs = Vec::new();
    let mut member_pk_bs = Vec::new();
    let mut regev_pk_digests = Vec::new();
    let mut recipients = Vec::new();
    for i in 0..active {
        let m = &record.members[i];
        member_pk_gs.push(m.pk_g.to_string());
        member_pk_bs.push(m.pk_b.to_string());
        regev_pk_digests.push(m.regev_pk_digest.to_string());
        recipients.push(m.recipient.to_hex());
    }
    // Both counts are zero-delegate here, for two DIFFERENT reasons (they are not one value):
    //   * the registration side is cosigner-only by protocol (Option B), enforced in-circuit;
    //   * this record has no live channel state to read a delegate count from, so the manager
    //     `DeployCloseCli.s.sol` builds binds no delegates — its B-2 floor is vacuous, the
    //     pre-existing reviewed behaviour of the real-chain path. Raising it would need delegate
    //     pk_g/recipient bindings this record does not carry.
    settlement_reg_json(
        channel_id,
        TEST_ACTIVE_MEMBERS,
        delegate_count,
        &member_pk_gs,
        &member_pk_bs,
        &regev_pk_digests,
        &recipients,
    )
}

/// Build the production settlement input from the one authenticated, fully signed live snapshot.
/// No deterministic-key fallback and no derived recipient formula is permitted here: the exact
/// slot recipient committed inside `BalanceState::h1()` is what the manager root freezes.
fn build_live_settlement_reg_record(state: &CliState) -> serde_json::Value {
    verify_snapshot(&state.snapshot, None)
        .unwrap_or_else(|e| die(format!("settlement live-snapshot verification failed: {e}")));
    verify_all_signatures(
        &state.snapshot.record,
        &state.snapshot.members,
        &state.snapshot.state,
    )
    .unwrap_or_else(|e| {
        die(format!(
            "settlement N-of-N signature verification failed: {e}"
        ))
    });

    let channel_id = channel_id_env();
    let record = &state.snapshot.record;
    let balance = &state.snapshot.state.balance_state;
    if record.channel_id.as_u64() != u64::from(channel_id)
        || balance.channel_id.as_u64() != u64::from(channel_id)
    {
        die("settlement snapshot channel id does not match INTMAX_CHANNEL");
    }
    if record.member_count != balance.member_count
        || record.delegate_count != balance.delegate_count
    {
        die("settlement snapshot record/balance participant counts disagree");
    }
    let member_count = record.member_count as usize;
    let delegate_count = record.delegate_count as usize;
    let active = member_count + delegate_count;
    if active > MAX_CHANNEL_MEMBERS {
        die(format!(
            "settlement snapshot has {active} participants, maximum is 1024"
        ));
    }

    let mut by_slot: Vec<Option<&MemberInfo>> = vec![None; active];
    for member in &state.snapshot.members {
        let slot = member.slot as usize;
        if slot >= active || by_slot[slot].replace(member).is_some() {
            die(format!(
                "settlement snapshot has invalid/duplicate participant slot {slot}"
            ));
        }
    }

    let mut pk_gs = Vec::with_capacity(active);
    let mut pk_bs = Vec::with_capacity(active);
    let mut regev_digests = Vec::with_capacity(active);
    let mut recipients = Vec::with_capacity(active);
    for slot in 0..active {
        let member = by_slot[slot]
            .unwrap_or_else(|| die(format!("settlement snapshot is missing active slot {slot}")));
        if member.pk_g != record.member_pk_gs[slot] {
            die(format!("settlement snapshot pk_g mismatch at slot {slot}"));
        }
        let recipient = balance.recipients[slot];
        if recipient == Address::default() {
            die(format!(
                "settlement snapshot has zero signed recipient at slot {slot}"
            ));
        }
        pk_gs.push(member.pk_g.to_hex());
        pk_bs.push(member.pk_b.to_hex());
        regev_digests.push(member.regev_pk.digest().to_hex());
        recipients.push(recipient.to_hex());
    }
    settlement_reg_json(
        channel_id,
        member_count,
        delegate_count,
        &pk_gs,
        &pk_bs,
        &regev_digests,
        &recipients,
    )
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("");
    // Release MSU gate must run before *every* mutation-capable prelude too. In particular, the
    // normal process startup rolls a PREPARED inter-channel 2PC journal forward before dispatch;
    // leaving the rejection only in the match arm meant invoking the disabled command could still
    // replace two channel states and retire a recovery journal before printing "disabled". Those
    // writes were not an MSU, but they violated the stronger operational invariant promised by
    // this entry point: a disabled MSU request has no side effects at all.
    if cmd == "member-update" {
        cmd_member_update(&args);
    }
    let detached_precompute_bypass = cmd == "precompute-falcon-aggregate"
        && std::env::var(DETACHED_PRECOMPUTE_LOCK_BYPASS_ENV).as_deref() == Ok("1");
    // SECURITY: this lock is deliberately process-wide and acquired before recovery.  Per-file
    // atomic writes prevent torn JSON, but only serialization prevents an older init/cosign image
    // from overwriting a settlement PREPARED by another process.  The sole bypass is the
    // digest-keyed detached proof-cache worker described at its spawn site above.
    let _state_process_lock = (!detached_precompute_bypass).then(CliStateProcessLock::acquire);
    // A prepared two-channel transfer is a global mutation barrier for every channel CLI command,
    // not merely for the next inter-transfer. If the previous process died after replacing A but
    // before replacing B, allowing (for example) a burn or token registration to extend either
    // half-head would make deterministic roll-forward impossible and leave value one-sided.
    // Recovery is idempotent and a no-op when the sibling journal directory does not exist.
    if !detached_precompute_bypass {
        recover_pending_inter_transfers();
    }
    match cmd {
        "setup-backing" => cmd_setup_backing(&args),
        "init" => cmd_init(&args),
        "gen-contribution" => cmd_gen_contribution(&args), // dev/test: simulate a browser delegate
        "gen-send" => cmd_gen_send(&args),                 /* dev/test: simulate a browser */
        // delegate SENDING
        "add-genesis-sig" => cmd_add_genesis_sig(&args),
        "send" => cmd_send(&args),
        "install-exit-kit" => cmd_install_exit_kit(&args),
        "cosign" => cmd_cosign(&args),
        "cosign-batch" => cmd_cosign_batch(&args),
        "cosign-refresh" => cmd_cosign_refresh(&args),
        "sign-close-funding" => cmd_sign_close_funding(&args),
        "cosign-inter-transfer" => cmd_cosign_inter_transfer(&args),
        "recover-inter-transfers" => {
            recover_pending_inter_transfers();
            println!("inter-transfer recovery complete");
        }
        "publish-snapshot" => cmd_publish_snapshot(&args),
        "cosign-burn-send" => cmd_cosign_burn_send(&args),
        "finalize" => cmd_finalize(&args),
        "precompute-falcon-aggregate" => cmd_precompute_falcon_aggregate(),
        "balance" => cmd_balance(),
        "register-token" => cmd_register_token(&args),
        "refresh" => cmd_refresh(&args),
        // A-3 P3: `close` builds the real close proof from wallet state and submits it on-chain.
        "close" => cmd_close(&args),
        // A-3 P4: `settle` finalizes the close after the challenge period (no proof calldata).
        "settle" => cmd_settle(&args),
        // A-3 P4: `claim` proves + submits a member's withdrawal claim and pulls the credit.
        "claim" => cmd_claim(&args),
        // A-3 P4: `withdraw` builds the channel-withdrawal proof set and drives the full on-chain
        // pipeline (register → deposit → postBlock×3 → finalize → withdrawNative →
        // pullChannelFunds).
        "withdraw" => cmd_withdraw(&args),
        // A-3 P5-B: print/write the channel's member registration record (no proving) so a deploy
        // script can `registerChannel` + bind the manager to the SAME members the close/withdraw
        // proofs use (lets one on-chain registration serve the whole close lifecycle).
        "export-reg-record" => cmd_export_reg_record(),
        "deploy-settlement" => cmd_deploy_settlement(&args),
        "verify-settlement-binding" => cmd_verify_settlement_binding(&args),
        "inspect-l1-deposit" => cmd_inspect_l1_deposit(&args),
        "cosign-l1-deposit-import" => cmd_cosign_l1_deposit_import(&args),
        "pw-submit" => cmd_pw_submit(&args),
        "pw-finalize" => cmd_pw_finalize(&args),
        "cancel-close" => cmd_cancel_close(&args),
        "post-close-claim" => cmd_post_close_claim(&args),
        // SECURITY: the DELIBERATE, acknowledged path for a `cli_state.json` that pre-dates a
        // replay ledger. It replaces the old `#[serde(default)]`, which did the same reset in
        // silence on every load.
        "member-update" => cmd_member_update(&args),
        "migrate-state" => cmd_migrate_state(&args),
        _ => {
            eprintln!(
                "usage: channel_member <setup-backing|init|gen-contribution|gen-send|send|install-exit-kit|cosign|cosign-batch|cosign-burn-send|sign-close-funding|recover-inter-transfers|publish-snapshot|register-token|refresh|deploy-settlement|verify-settlement-binding|inspect-l1-deposit|cosign-l1-deposit-import|pw-submit|pw-finalize|close|settle|withdraw|claim|cancel-close|post-close-claim|precompute-falcon-aggregate|migrate-state|...> ...\n  install-exit-kit <public_backing_envelope.json>: cryptographically verify and fsync a content-addressed signer-independent kit receipt for the exact current head\n  sign-close-funding <proposal.json> <out_state.json>: verify ACTIVE chain/rollup/manager/verifier binding, then permanently reserve and N-of-N sign the exact terminal child without advancing the head\n  verify-settlement-binding <manager> <rpc> <rollup> <verifier>: keyless read-back of the durable ACTIVE binding after participant and finalized-L1 revalidation\n  precompute-falcon-aggregate: prove + persist the current finalized state's reusable Falcon aggregate artifact\n  recover-inter-transfers: idempotently roll forward any fsynced two-channel PREPARED journal before accepting another mutation\n  publish-snapshot [out.json]: atomically re-publish the authoritative private snapshot without signing or advancing state\n  migrate-state [--i-understand-this-resets-replay-ledgers] [--i-understand-this-resets-anti-equivocation-ledger]: one-time, EXPLICIT repair of a cli_state.json written before a required security ledger existed\n  multi-token (§N): send/gen-send take [token_slot]; claim takes [token_slot]; inspect-l1-deposit emits the canonical producer request; cosign-l1-deposit-import <slot|auto> <tx_hash> <rpc_url> reads amount/depositor/token_index FROM THE CHAIN; register-token <base_token_index> appends a cosigned registry entry; refresh <slot> [token_slot] re-encrypts a CLI member's own position so it can send again after a homomorphic credit"
            );
            exit(2);
        }
    }
}

/// `init` = CREATE-OR-JOIN. The first call CREATES the channel (3 members + this delegate at slot
/// 3, genesis v0). Each later call JOINS the existing channel as a NEW delegate at the next free
/// slot — a state-PRESERVING membership add: the CURRENT balances and any sends already made are
/// kept, the new delegate's slot is added, `state_version` is bumped, and the 3 members re-sign. So
/// joining AFTER sends does NOT wipe them, and multiple browsers are DISTINCT delegates (slots
/// 3,4,5,…) in the SAME channel.
fn cmd_init(args: &[String]) {
    let contrib_path = args
        .get(1)
        .unwrap_or_else(|| die("init needs <browser_contribution.json>"));
    let out_path = args
        .get(2)
        .map(String::as_str)
        .unwrap_or("channel_snapshot.json");
    let contrib: BrowserContribution = read_json(contrib_path);
    let new_delegate = MemberInfo {
        slot: 0, // assigned by create/join
        pk_g: Bytes32::from_hex(&contrib.pk_g)
            .unwrap_or_else(|e| die(format!("parse browser pk_g: {e:?}"))),
        pk_b: Bytes32::from_hex(&contrib.pk_b)
            .unwrap_or_else(|e| die(format!("parse browser pk_b: {e:?}"))),
        regev_pk: contrib.regev_pk.clone(),
    };
    // SECURITY (A-1): `contrib.genesis_ct` is READ OFF THE WIRE AND DISCARDED — deliberately. It
    // is a self-declared opening balance with no backing, and neither the create nor the join path
    // installs it any more (see `create_channel` / `join_delegate`). The field is still REQUIRED by
    // the wire format so existing browsers/relays keep working unchanged; it simply has no effect.
    // B-1b fail-closed: the delegate's L1 exit address must be present and nonzero BEFORE any
    // channel state is assembled or signed.
    let new_recipient = parse_contribution_recipient(&contrib.recipient);
    let previous = Path::new(STATE_FILE).exists().then(load_state);

    // IDEMPOTENT RE-JOIN (pk_g dedup): if a member with this EXACT pk_g already exists, the join is
    // a no-op — return that member's existing slot and the CURRENT snapshot UNCHANGED.
    // Re-running `init` with the same browser contribution (e.g. a retried request, or a
    // browser that lost its local copy) must NOT allocate a new slot, bump state_version, or
    // grow delegate_count: doing so caused slot collisions on re-join. Only a genuinely NEW
    // pk_g advances to the next free slot.
    if let Some(prev) = previous.as_ref() {
        if let Some(existing) = prev
            .snapshot
            .members
            .iter()
            .find(|m| m.pk_g == new_delegate.pk_g)
        {
            let slot = existing.slot;
            let dc = prev.snapshot.record.delegate_count;
            let v = prev.snapshot.state.balance_state.state_version;
            // Re-publish the UNCHANGED snapshot so the caller's out_path is current; cli_state is
            // left exactly as-is (no state bump, no ledger change).
            write_json(out_path, &prev.snapshot);
            let mc = prev.snapshot.record.member_count;
            println!(
                "delegate at slot {slot} (idempotent re-join: pk_g already present; member_count={mc}, delegate_count={dc}, state_version={v}). Browser: wallet_import_channel(<{out_path}>)."
            );
            return;
        }
        if let Some(binding) = &prev.settlement_binding {
            die(format!(
                "delegate join is frozen: settlement {:?} ({:?}) already committed participant \
                 root {} for {} active slots at state {}. Re-running init with an EXISTING pk_g \
                 remains idempotent, but a new pk_g can never be added after settlement.",
                binding.manager,
                binding.status,
                binding.participant_root,
                binding.participant_count,
                binding.snapshot_state_digest,
            ));
        }
    }

    // SECURITY: every replay ledger must SURVIVE a delegate join — dropping one here would let a
    // join re-open an already-consumed transfer or L1 deposit for a second credit.
    let (prior_applied, prior_spent, prior_imported, prior_signing_ledger) = previous
        .as_ref()
        .map(|prev| {
            (
                prev.applied_tx_identities.clone(),
                prev.spent_tx_identities.clone(),
                prev.imported_deposits.clone(),
                prev.state_signing_ledger.clone(),
            )
        })
        .unwrap_or_else(|| {
            (
                HashSet::new(),
                HashSet::new(),
                HashSet::new(),
                BTreeMap::new(),
            )
        });
    let (record, unsigned_state, members, controlled, slot) = if let Some(prev) = previous.as_ref()
    {
        // SECURITY (A-1, doc/tasks/b2-delegate-close-threat-model.md §9): `new_ct` is DELIBERATELY
        // NOT passed to `join_delegate`. A joiner's self-declared opening ciphertext is unbacked
        // value; see the argument at `join_delegate`. The join opens the slot at the canonical
        // zero.
        join_delegate(prev, new_delegate, new_recipient)
    } else {
        // SECURITY (A-1, genesis half): likewise NOT passed to `create_channel`. This is the path
        // the product actually takes (the first browser CREATES channel N, later browsers JOIN),
        // so closing only the join lane would have left the shipped flow wide open.
        create_channel(new_delegate, new_recipient)
    };

    let settled_tx_accumulator = previous
        .as_ref()
        .map(|prev| prev.snapshot.settled_tx_accumulator.clone())
        .unwrap_or_else(default_settled_tx_accumulator);
    let snapshot = ChannelSnapshot {
        record,
        state: unsigned_state,
        members,
        // Genesis starts empty; a later delegate join must retain the exact authenticated
        // accumulator instead of silently resetting already-settled history.
        settled_tx_accumulator,
    };
    let mut cli = CliState {
        state_schema_version: STATE_SCHEMA_VERSION,
        controlled,
        snapshot,
        applied_tx_identities: prior_applied,
        spent_tx_identities: prior_spent,
        imported_deposits: prior_imported,
        state_signing_ledger: prior_signing_ledger,
        settlement_binding: None,
        // A delegate join changes the authenticated channel record. Even though its balance row
        // opens at zero, do not carry an archive verified against the older record: the new head
        // must be exported, verified and installed before any subsequent signature is released.
        signer_exit_kit_receipt: None,
        signer_exit_kit_receipt_verified: false,
    };

    // No signature leaves the process before the decision and exact bytes are fsynced in `cli`.
    // Genesis retains the stronger deposit-backing gate; delegate joins use the ordinary
    // validated, value-preserving successor gate described at `join_delegate`.
    let record = cli.snapshot.record.clone();
    let controlled = cli.controlled.clone();
    let mut signed_state = cli.snapshot.state.clone();
    if previous.is_none() {
        let (balance_vd, attestation, _) = load_backing();
        for member in &controlled {
            let signature = ledgered_state_signature_with(
                &mut cli,
                &record,
                member,
                &signed_state,
                StateSigningPurpose::Genesis,
                None,
                None,
                |keys| {
                    sign_state_if_backed(
                        keys,
                        member.slot as u8,
                        &record,
                        &signed_state,
                        &attestation,
                        &balance_vd,
                    )
                    .map_err(|e| format!("REFUSING TO SIGN genesis — {e}"))
                },
            )
            .unwrap_or_else(|error| die(error));
            add_signature(&mut signed_state, signature);
        }
    } else {
        for member in &controlled {
            let signature = ledgered_state_signature(
                &mut cli,
                &record,
                member,
                &signed_state,
                StateSigningPurpose::DelegateJoin,
                None,
            )
            .unwrap_or_else(|error| die(error));
            add_signature(&mut signed_state, signature);
        }
    }
    verify_all_signatures(&record, &cli.snapshot.members, &signed_state)
        .unwrap_or_else(|e| die(format!("state not fully/validly member-signed: {e}")));
    cli.snapshot.state = signed_state;
    let dc = cli.snapshot.record.delegate_count;
    let mc = cli.snapshot.record.member_count;
    let v = cli.snapshot.state.balance_state.state_version;
    save_state(&cli);
    write_json(out_path, &cli.snapshot);
    println!(
        "delegate at slot {slot} (member_count={mc}, delegate_count={dc}, state_version={v}). Browser: wallet_import_channel(<{out_path}>)."
    );
}

/// The three CLI co-signing members (deterministic keys + genesis balances).
fn cli_members() -> (
    Vec<MemberInfo>,
    Vec<(u16, RegevCiphertext)>,
    Vec<ControlledMember>,
) {
    let mut members = Vec::new();
    let mut enc = Vec::new();
    let mut controlled = Vec::new();
    for slot in cli_slots() {
        let keygen_seed = 0xC1_0000 + slot as u64;
        let keys = keys_for(keygen_seed);
        members.push(member_info_for(slot, &keys));
        let amount = genesis_amount(slot);
        let balance_seed = 0xBA_0000 + slot as u64;
        let (ct, _w) = encrypt_amount(
            &mut StdRng::seed_from_u64(balance_seed),
            &keys.regev_pk,
            amount,
        )
        .unwrap_or_else(|e| die(e));
        enc.push((slot, ct));
        controlled.push(ControlledMember {
            slot,
            keygen_seed,
            balance_amount: amount,
            balance_seed,
            has_witness: true,
            token_witnesses: Vec::new(),
        });
    }
    (members, enc, controlled)
}

/// CREATE the channel: `cli_cosigner_count()` members + this delegate at the first delegate slot,
/// genesis (v0), returned unsigned so `cmd_init` can route every signature through its durable
/// anti-equivocation ledger before publication.
/// `new_recipient` (B-1b) is the delegate's NONZERO L1 exit address, leaf-bound in the genesis H1.
///
/// SECURITY (A-1 conservation control, GENESIS half — doc/tasks/b2-implementation-notes.md §7):
/// this function takes NO caller-supplied delegate ciphertext. It used to install
/// `contrib.genesis_ct` verbatim at the delegate slot, which is the SAME unbacked-value-injection
/// lane that was closed at `join_delegate`, and it is the lane the PRODUCT actually reaches: the
/// relay forwards the browser's contribution body verbatim (`hosting/wallet/wallet-relay.js`) and
/// the standard single-delegate channel is created, not joined, so `join_delegate` is never
/// entered on that path. `cmd_setup_backing` computes the L1-deposited `fund` as
/// `Σ genesis_amount(cosigner slots) + DELEGATE_GENESIS` with `DELEGATE_GENESIS == 0` — it
/// EXCLUDES the delegate's contribution — and nothing anywhere binds `Σ slot balances <= channel
/// fund` (R3). A creator-supplied nonzero delegate ciphertext therefore made `Σ balances > fund`
/// at genesis, and after close that surplus is claimed out of the real pot ahead of the honest
/// participants (bounded by `finalizedChannelFundAmount`, so it is MISALLOCATION — theft from
/// co-participants, first-come-first-served — not minting).
///
/// The control is the same as at join and for the same reason: the amount is Regev-encrypted, so
/// no cosigner can decide "does this encrypt zero?", and the contribution payload carries neither
/// a declared amount nor the encryption randomness. So the untrusted input is REMOVED rather than
/// validated — the delegate's genesis slot opens at the canonical zero ciphertext, which decrypts
/// to 0 under any key. `Σ genesis balances == fund` then holds by construction instead of by
/// assumption (the comment below said it; now it is true).
///
/// COMPLETENESS: this MATCHES PRODUCTION — `hosting/wallet/wallet-live.html` already passes
/// `balance: toBase('0')`, so the live browser flow contributes exactly what is now installed. The
/// delegate's real funding lanes are unchanged and are the conservation-preserving ones (L1
/// deposit import, which moves `channel_fund` and the slot leaf together, and in-channel transfers
/// proven by the E-1/E-2 STARK). If some future flow genuinely needs a NONZERO opening balance for
/// the delegate, it must arrive with backing — do not restore a caller-supplied ciphertext here.
fn create_channel(
    mut nd: MemberInfo,
    new_recipient: Address,
) -> (
    ChannelRecord,
    ChannelState,
    Vec<MemberInfo>,
    Vec<ControlledMember>,
    u16,
) {
    let delegate_slot = first_delegate_slot();
    nd.slot = delegate_slot;
    let (mut members, mut enc, controlled) = cli_members();
    members.push(nd);
    // SECURITY (A-1, genesis half): the delegate's genesis ciphertext is the CANONICAL ZERO, not a
    // caller-supplied one. See the conservation argument on this function. `zero_ciphertext()`
    // decrypts to 0 under every Regev key, so the delegate contributes exactly `DELEGATE_GENESIS`
    // (== 0) — the amount `cmd_setup_backing` actually put into `fund`. Do NOT reintroduce a
    // caller-supplied ciphertext here without an accompanying backing proof — that is the R3 hole.
    enc.push((
        delegate_slot,
        intmax3_zkp::common::balance_state::zero_ciphertext().clone(),
    ));
    members.sort_by_key(|m| m.slot);
    let record = build_record(channel_id_env(), &members, BP_SLOT, 1).unwrap_or_else(|e| die(e));
    enc.sort_by_key(|(s, _)| *s);
    let encs: Vec<RegevCiphertext> = enc.into_iter().map(|(_, c)| c).collect();

    // detail2 §F-1: the genesis is funded by the REAL L1 deposit backing (no self-minted fund).
    // `fund` == the deposited native value; `settled_tx_chain` ties the state to that deposit so
    // the co-sign gate reconciles.
    // SECURITY (A-1): `Σ(genesis balances) == fund` now holds BY CONSTRUCTION, not by assumption —
    // the cosigner slots carry exactly `genesis_amount(slot)` (the same values `cmd_setup_backing`
    // summed) and the delegate slot carries the canonical zero (== `DELEGATE_GENESIS`). Before
    // A-1 this line was an unchecked claim that a caller-supplied delegate ciphertext could
    // falsify.
    let (_, _, backing) = load_backing();
    let settled = Bytes32::from_hex(&backing.settled_tx_chain)
        .unwrap_or_else(|e| die(format!("backing settled_tx_chain: {e:?}")));
    let intmax_root = Bytes32::from_hex(&backing.intmax_state_root)
        .unwrap_or_else(|e| die(format!("backing intmax_state_root: {e:?}")));
    // Decryption Stage 1: the per-active-slot Regev pk Poseidon digests, in the SAME slot order as
    // `members`/`encs` (members then delegates), folded into the signed genesis H1.
    let regev_pk_digests: Vec<Bytes32> = members
        .iter()
        .map(|m| Bytes32::from(m.regev_pk.poseidon_digest()))
        .collect();
    // B-1b: per-active-slot L1 exit addresses, in slot order. The CLI COSIGNERS default to the
    // deterministic per-(channel, slot) `test_recipient_for` (the same formula their on-chain
    // registration record carries), overridable per slot (see `cosigner_leaf_recipient`), and the
    // browser DELEGATE's slot carries its contribution recipient (already fail-closed nonzero).
    // All folded into the cosigner-signed genesis H1 via the slot leaves.
    let channel_id = channel_id_env();
    let recipients: Vec<Address> = members
        .iter()
        .map(|m| {
            if m.slot == delegate_slot {
                new_recipient
            } else {
                cosigner_leaf_recipient(channel_id, m.slot)
            }
        })
        .collect();
    let state = assemble_genesis_state_backed(
        &record,
        &encs,
        &regev_pk_digests,
        &recipients,
        backing.fund,
        settled,
        intmax_root,
    )
    .unwrap_or_else(|e| die(e));

    (record, state, members, controlled, delegate_slot)
}

/// JOIN the existing channel as a NEW delegate, PRESERVING the current state (balances + sends).
/// The new delegate's slot is added at a ZERO opening balance, `delegate_count` and
/// `state_version` are bumped, and the members re-sign the new state. Existing delegates'
/// ciphertexts are untouched, so their browser send-witnesses stay valid.
/// `new_recipient` (B-1b) is the joining delegate's NONZERO L1 exit address — written into the
/// new slot's `recipients` entry so it enters the cosigner-signed H1 (the delegate's ONLY payout
/// binding under Option B; the caller has already rejected zero/absent recipients fail-closed).
///
/// SECURITY (A-1 conservation control, doc/tasks/b2-delegate-close-threat-model.md §9 /
/// doc/tasks/b2-implementation-notes.md):
/// This function takes NO joiner-supplied ciphertext. It used to write `contrib.genesis_ct`
/// verbatim into the new slot and have the cosigners re-sign with plain `sign_state`. That is an
/// UNBACKED VALUE INJECTION: the contribution is Regev-encrypted, so the cosigners cannot see the
/// amount they are attesting to, and no layer anywhere binds `Σ slot balances <= channel fund`
/// (R3). A joining stranger could therefore self-declare an arbitrary opening balance and, after
/// close, claim against the real pot ahead of honest participants (bounded by
/// `finalizedChannelFundAmount` / `receivedChannelFunds`, so it is MISALLOCATION of the real pot,
/// not minting — but misallocation is the whole loss for the victims).
///
/// It cannot be fixed by CHECKING the ciphertext: Regev is semantically secure, so "does this
/// ciphertext encrypt zero?" is undecidable for the cosigners without the joiner's secret key or
/// its encryption witness, and the contribution payload carries neither (a declared-amount + seed
/// rebuild-equality scheme would work, but it means a schema change across the browser/relay/API
/// and publishing the opening balance). The control used instead REMOVES the untrusted input
/// rather than validating it: the new slot opens at the CANONICAL ZERO ciphertext, which decrypts
/// to 0 under every Regev key (`balance_state::zero_ciphertext`). A join then provably changes no
/// slot's balance, so `Σ balances` is invariant across it and the genesis-anchored backing that
/// `cmd_setup_backing` computed (`Σ cosigner genesis amounts + DELEGATE_GENESIS`, where
/// `DELEGATE_GENESIS == 0`) still holds afterwards. This is strictly stronger than any check the
/// cosigners could perform, and it is exactly what the fund accounting already assumed.
///
/// COMPLETENESS (this must not wrongly reject or strand a legitimate joiner): opening at zero costs
/// the delegate nothing it could legitimately have had. The two lanes by which a delegate actually
/// receives value both work from a zero slot and are themselves conservation-preserving:
///   * L1 deposit import (`cosign-l1-deposit-import`) reads amount/depositor/token from the CHAIN
///     and moves `channel_fund` and the slot leaf TOGETHER (`wallet_core.rs`), and
///     `add_ciphertexts(zero, x) == x`;
///   * an in-channel transfer from an existing slot, whose E-1/E-2 STARK proves `before == after +
///     amount`.
/// The delegate needs no encryption witness for the zero ciphertext: sending requires a refresh
/// (which needs only the delegate's SECRET KEY, `wallet_refresh`), and a withdrawal/post-close
/// claim decrypts in-circuit under the secret key. The production browser flow already contributes
/// 0 (`hosting/wallet/wallet-live.html`), and the CLI's own `DELEGATE_GENESIS` is already 0, so no
/// legitimate join loses anything it has today.
///
/// The GENESIS half of the same lane is closed too — `create_channel` no longer installs a
/// caller-supplied delegate ciphertext either. That is the path the shipped product actually
/// takes, so fixing only this one would have left the product untouched; see the argument there.
///
/// NOT FIXED HERE (tracked, pre-existing): R3 itself — there is still no in-circuit
/// `Σ slot balances <= channel fund`. Removing the two injection lanes means the CLI/browser flow
/// never creates a state that violates conservation, but it is not a proof that no state can.
fn join_delegate(
    prev: &CliState,
    mut nd: MemberInfo,
    new_recipient: Address,
) -> (
    ChannelRecord,
    ChannelState,
    Vec<MemberInfo>,
    Vec<ControlledMember>,
    u16,
) {
    // SECURITY (B-1b uniqueness, adversarial review finding 1): a joining member declares its own
    // L1 exit address. If it were allowed to declare an address ALREADY bound to another active
    // slot, the L1-deposit import's depositor->slot resolution would become ambiguous: the joiner
    // could capture the victim's genuine deposits (or, at minimum, make them permanently
    // unimportable — an irreversible exit-wedge). Exit addresses must therefore be DISTINCT across
    // active slots. Refused fail-closed at the join, where the collision is introduced.
    {
        let bs = &prev.snapshot.state.balance_state;
        let active = bs.member_count as usize + bs.delegate_count as usize;
        if let Some(clash) = (0..active).find(|&i| bs.recipients[i] == new_recipient) {
            die(format!(
                "REFUSING contribution: recipient {} is ALREADY the bound (B-1b) L1 exit address \
                 of ACTIVE slot {clash}. Exit addresses must be distinct — a duplicate would make \
                 L1 deposit crediting ambiguous and could capture that member's deposits.",
                new_recipient.to_hex()
            ));
        }
    }
    let delegate_slot = first_delegate_slot();
    let existing = prev
        .snapshot
        .members
        .iter()
        .filter(|m| m.slot >= delegate_slot)
        .count();
    // Check capacity BEFORE computing the slot (u16 arithmetic; the old `as u8` add wrapped at
    // slot 256 — the 2026-07-18 storm bug).
    if delegate_slot as usize + existing + 1 > MAX_CHANNEL_MEMBERS {
        die("channel is full (member_count + delegate_count would exceed MAX_CHANNEL_MEMBERS)");
    }
    let new_slot = delegate_slot + existing as u16;
    nd.slot = new_slot;
    // SECURITY (A-1 finding 1 — THE EXIT LANE): capture the joiner's Regev pk digest BEFORE `nd` is
    // moved into `members`. Until now `join_delegate` never wrote `balance_state.regev_pk_digests`
    // for the new slot, so it stayed at the padding zero while the slot was fully ACTIVE.
    // `BalanceState::validate()` cannot catch that — it only constrains PADDING slots to the zero
    // digest and treats active-slot digests as arbitrary — and `verify_snapshot` checks
    // `record.regev_pk_root`, never `balance_state.regev_pk_digests`. The consequence was
    // permanent: the withdrawal-claim circuit derives `pk_digest = poseidon(a, b)` from the
    // witnessed key and hashes it INTO the slot leaf it must Merkle-verify against the
    // cosigner-signed slot tree root, so a leaf built over a zero digest can only be reproduced by
    // a Regev key whose Poseidon digest is zero. Any value that ever reached a joined delegate's
    // slot — an honest L1 deposit import, an honest in-channel transfer — was UNCLAIMABLE at close.
    // The A-1 conservation argument (a joined slot is fundable only through those two lanes)
    // depends on this exit lane working, so it is fixed here rather than merely documented.
    let new_pk_digest = Bytes32::from(nd.regev_pk.poseidon_digest());
    // SECURITY: fail closed rather than sign an unclaimable slot. A zero digest is exactly the
    // padding value, so it would reproduce the very bug above; it is also what a degenerate or
    // malformed key would have to produce. Poseidon preimage resistance makes this unreachable for
    // a real key — this is the assertion that keeps it that way.
    if new_pk_digest == Bytes32::default() {
        die(
            "REFUSING join: the contributed Regev public key hashes to the ZERO Poseidon digest, \
             which is the reserved PADDING value — the slot's balance would be permanently \
             unclaimable at close (the claim circuit binds poseidon(a,b) into the signed slot leaf)",
        );
    }
    let mut members = prev.snapshot.members.clone();
    members.push(nd);
    members.sort_by_key(|m| m.slot);
    let new_delegate_count = (existing + 1) as u16;
    let mut record = build_record(channel_id_env(), &members, BP_SLOT, new_delegate_count)
        .unwrap_or_else(|e| die(e));
    // §Q: a delegate join does not change the registered co-signer set — carry the version.
    record.set_version = prev.snapshot.record.set_version;

    // Membership add: keep the CURRENT balance state (preserving every slot's ciphertext + any
    // sends), add the new delegate's slot, bump delegate_count + state_version, clear sigs,
    // members re-sign.
    let mut state = prev.snapshot.state.clone();
    state.prev_digest = state.digest;
    state.balance_state.delegate_count = new_delegate_count;
    // SECURITY (A-1): a JOINING delegate opens at the canonical ZERO ciphertext in EVERY token
    // position — including position 0, which used to receive the joiner-supplied `genesis_ct`. See
    // the conservation argument on this function. `zero_token_row()` is the all-zero Regev
    // ciphertext, which decrypts to 0 under any key, so the join adds no balance to the channel and
    // `Σ balances` is provably unchanged by it. Do NOT reintroduce a caller-supplied ciphertext
    // here without an accompanying backing proof — that is the R3 hole.
    state.balance_state.enc_balances[new_slot as usize] =
        intmax3_zkp::common::balance_state::zero_token_row();
    state.balance_state.pending_adds[new_slot as usize] =
        [0u32; intmax3_zkp::constants::MAX_CHANNEL_TOKENS];
    // SECURITY (A-1 finding 1): bind the JOINER'S OWN Regev pk digest into its slot leaf, so the
    // slot is claimable at close. The value is not free: it is `poseidon(a, b)` over the very key
    // `nd.regev_pk` that `build_record` above already folded into the record's `regev_pk_root`, so
    // the balance state and the record commit to ONE key per slot and the joiner cannot name a
    // different key here than the one it is registered under.
    //
    // SECURITY (why this write is not itself an unbacked-value lane): the digest decides only WHO
    // can decrypt and claim this slot, never HOW MUCH it holds — the amount comes from the slot's
    // ciphertext, which the line above pins to the canonical zero. Naming a victim's public key
    // would hand the joiner a slot it cannot decrypt (claiming needs the secret `s` with
    // `b = a·s + e`), so it can only harm itself, and the balance it would be "stealing" is
    // provably 0. The recipient-uniqueness guard at the top of this function is what prevents a
    // duplicate-identity join from capturing another slot's L1 deposits.
    state.balance_state.regev_pk_digests[new_slot as usize] = new_pk_digest;
    // B-1b: bind the new delegate's L1 exit address into its slot leaf (cosigner-signed H1).
    state.balance_state.recipients[new_slot as usize] = new_recipient;
    state.balance_state.state_version += 1;
    state.member_signatures = Vec::new();
    let state = state.with_computed_digest();
    // `cmd_init` performs the N-of-N through the durable anti-equivocation ledger. Returning an
    // unsigned child is intentional: no join signature is ever minted before the sibling check.
    (record, state, members, prev.controlled.clone(), new_slot)
}

/// DEV/TEST ONLY: simulate the browser's `wallet_genesis_contribution` — generate a delegate's keys
/// + encrypt its opening balance, and emit a `BrowserContribution` JSON. Lets the relay flow be
/// driven headlessly. `gen-contribution <balance> <seed> <out.json>`.
fn cmd_gen_contribution(args: &[String]) {
    let balance: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(50);
    let seed: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1);
    let out = args
        .get(3)
        .map(String::as_str)
        .unwrap_or("contribution.json");
    // SECURITY: routed through `keys_for`, NOT a second inline `MemberKeys::generate`. If this kept
    // the old `seed_from_u64` derivation while `cli_active_keys` used the KDF, the delegate
    // identity would silently diverge between `gen-contribution` and `init` — the Phase-3 finding-7
    // failure that leaves a channel unclosable. `seed` is a public slot LABEL here, not key
    // material (doc/tasks/cosigner-key-provenance.md §4.3).
    let keys = keys_for(seed);
    let (ct, _w) = encrypt_amount(
        &mut StdRng::seed_from_u64(seed ^ 0xA11CE),
        &keys.regev_pk,
        balance,
    )
    .unwrap_or_else(|e| die(e));
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Contribution {
        regev_pk: RegevPk,
        pk_g: String,
        pk_b: String,
        genesis_ct: RegevCiphertext,
        /// B-1b: the simulated delegate's L1 exit address (nonzero, seed-derived).
        recipient: String,
    }
    // B-1b: deterministic NONZERO per-seed exit address (a real browser passes the user's
    // MetaMask address here).
    let recipient = Address::from_u32_slice(&[0xDE1E_0000u32.wrapping_add(seed as u32); 5])
        .unwrap_or_else(|e| die(format!("derive contribution recipient: {e:?}")));
    write_json(
        out,
        &Contribution {
            regev_pk: keys.regev_pk.clone(),
            pk_g: keys.pk_g().to_hex(),
            pk_b: keys.pk_b().to_hex(),
            genesis_ct: ct,
            recipient: recipient.to_hex(),
        },
    );
    println!("wrote {out} (delegate balance {balance}, seed {seed})");
}

/// dev/test: simulate a browser delegate SENDING — the send-side counterpart of
/// `gen-contribution`. Rebuilds the delegate identity AND its genesis balance witness
/// deterministically from `(balance, seed)` (the exact randomness `gen-contribution` used), finds
/// the delegate's slot in the given snapshot by `pk_g`, and builds a complete `SendPayload`
/// (E-1 proof included) WITHOUT touching `cli_state.json` — stateless, so payload generation can
/// run in parallel and against any snapshot copy.
///
/// SOUNDNESS OF THE SIMULATION: valid only while the delegate's slot ciphertext at the selected
/// token position is one this stateless simulator can OPEN — either the canonical zero opening
/// every delegate slot now starts at (A-1; balance must then be 0), or the deterministic
/// `encrypt_amount(seed, pk, balance)` ct for legacy seeded snapshots. Both are checked
/// fail-closed against the snapshot below, so a stale witness can never produce a payload that
/// would waste a co-sign round.
///
/// NOTE (A-1): a delegate no longer opens with a self-declared balance, so the `<balance>`
/// argument is 0 for every delegate created by the current CLI/browser flow. A FUNDED delegate
/// (post L1-deposit-import or post-transfer) cannot be driven from here at all — its ciphertext is
/// not reproducible from `(balance, seed)` — and the guard says so rather than guessing.
///
/// usage: gen-send <balance> <seed> <to_slot> <amount> [snapshot.json] [out.json] [token_slot]
/// `token_slot` (OPTIONAL, default 0) selects the LOCAL token position (multitoken §N-3). Every
/// unfunded position is the canonical zero ct, so a nonzero `token_slot` behaves exactly like
/// token 0 until that position is funded — after which this simulator can no longer build for it.
fn cmd_gen_send(args: &[String]) {
    let balance: u64 = args
        .get(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| die("gen-send <balance> <seed> <to_slot> <amount> <snapshot> <out>"));
    let seed: u64 = args
        .get(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| die("bad <seed>"));
    let to: u16 = args
        .get(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| die("bad <to_slot>"));
    let amount: u64 = args
        .get(4)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| die("bad <amount>"));
    let snapshot_path = args
        .get(5)
        .map(String::as_str)
        .unwrap_or("channel_snapshot.json");
    let out = args
        .get(6)
        .map(String::as_str)
        .unwrap_or("send_payload.json");
    let token_slot: u8 = args
        .get(7)
        .map(|s| s.parse().unwrap_or_else(|_| die("bad [token_slot]")))
        .unwrap_or(0);

    // Reconstruct the delegate exactly as gen-contribution created it.
    // SECURITY: must go through the SAME single birth point `keys_for` that `gen-contribution`
    // uses, or this reconstruction silently yields a different identity under `KeyProvenance::
    // Master` and the `pk_g` lookup below fails closed (or worse, matches the wrong slot).
    let keys = keys_for(seed);

    let snapshot: ChannelSnapshot = read_json(snapshot_path);
    let from = snapshot
        .members
        .iter()
        .find(|m| m.pk_g == keys.pk_g())
        .map(|m| m.slot)
        .unwrap_or_else(|| {
            die(format!(
                "seed {seed}: pk_g not found in snapshot members — join first"
            ))
        });
    // Fail-closed: the witness must actually OPEN the delegate's current ciphertext at the
    // selected token position. Two admissible openings, in this order:
    //
    // SECURITY (A-1 finding 3): since A-1 a delegate's slot opens at the CANONICAL ZERO ciphertext
    // (`RegevCiphertext::padding()`) — at genesis via `create_channel` and at join via
    // `join_delegate` — not at a `gen-contribution`-shaped `encrypt_amount(seed, pk, balance)`. So
    // the canonical zero is the FIRST case, and it admits exactly ONE balance: 0. The opening is
    // the public all-zero witness (`zero_amount_witness()`, which opens `padding()` under any key
    // and cannot open any nonzero amount). Asserting `balance == 0` here rather than silently
    // coercing it keeps the caller's stated balance and the proven balance the same value — a
    // silent coercion would let a caller believe it had drafted a spend out of a funded slot.
    let cur_ct = &snapshot.state.balance_state.enc_balances[from as usize][token_slot as usize];
    let witness = if cur_ct == intmax3_zkp::common::balance_state::zero_ciphertext() {
        if balance != 0 {
            die(format!(
                "slot {from} token {token_slot}: the slot holds the CANONICAL ZERO ciphertext \
                 (a delegate's A-1 opening balance), so its only valid opening is 0 — but \
                 <balance> = {balance} was requested. A delegate is funded through the L1 deposit \
                 import or an in-channel transfer, never by declaring an opening balance; after \
                 funding, the slot is no longer the canonical zero and this simulator needs a \
                 refresh-derived witness it does not have."
            ));
        }
        intmax3_zkp::regev::encrypt::zero_amount_witness()
    } else {
        // The legacy lane: the slot still holds the exact deterministic ciphertext this simulator
        // can rebuild from `(balance, seed)`. Kept for any snapshot whose slot was seeded that way.
        let (genesis_ct, w) = encrypt_amount(
            &mut StdRng::seed_from_u64(seed ^ 0xA11CE),
            &keys.regev_pk,
            balance,
        )
        .unwrap_or_else(|e| die(e));
        if *cur_ct != genesis_ct {
            die(format!(
                "slot {from} token {token_slot}: ciphertext is neither the canonical zero opening \
                 nor the deterministic ct for balance {balance} / seed {seed} (sent or received \
                 since join) — the deterministic witness is stale; gen-send cannot build this \
                 payload"
            ));
        }
        w
    };

    let nonce = intmax3_zkp::ethereum_types::bytes32::Bytes32::default();
    // SECURITY: the send's encryption randomness comes from the OS CSPRNG, NOT from `seed`.
    //
    // WHY THE GENESIS GUARD ABOVE IS NOT SUFFICIENT. It only pins the ciphertext this payload
    // spends FROM, which stops randomness reuse ACROSS co-signed states (the second call fails the
    // guard once the first payload is applied). It does NOT stop two gen-send calls made against
    // the SAME, still-untouched genesis state: neither has been co-signed, so both pass the guard,
    // and with a `seed`-derived RNG both would replay the same `r` for `enc_amount` and for the
    // sender's `after_ct`. Two Regev encryptions under one key with one `r` reveal the difference
    // of their plaintexts (`c2 - c2' = Δ·(m - m')`), so anyone who sees both drafted payloads
    // learns the difference of the two amounts — and, since `balance` is a CLI argument known to
    // the caller, the second amount outright. Fresh per-invocation randomness closes that.
    // (`seed` still selects the delegate IDENTITY and its genesis witness, which is what this
    // stateless browser simulator actually needs to be deterministic about.)
    let mut rng = StdRng::from_seed(fresh_seed32());
    let BuiltSend {
        payload,
        new_balance,
        ..
    } = build_send_token(
        &keys, &snapshot, from, to, token_slot, amount, balance, &witness, nonce, LEVEL, &mut rng,
    )
    .unwrap_or_else(|e| die(e));
    // Emit the SLIM wire shape (detail2 §M-1) — the batch path's native format; ~50-100x smaller
    // than the fat SendPayload at high membership (no state / member list / record).
    write_json(out, &payload.to_slim());
    println!(
        "built SLIM send {from}→{to} amount {amount} token {token_slot} (new balance {new_balance}) → {out} (proof generated, stateless)"
    );
}

fn cmd_add_genesis_sig(args: &[String]) {
    let sig_path = args
        .get(1)
        .unwrap_or_else(|| die("needs <browser_sig.json>"));
    let out_path = args
        .get(2)
        .map(String::as_str)
        .unwrap_or("channel_snapshot.json");
    let sig: MemberSignature = read_json(sig_path);
    let mut state = load_state();
    add_signature(&mut state.snapshot.state, sig);
    verify_all_signatures(
        &state.snapshot.record,
        &state.snapshot.members,
        &state.snapshot.state,
    )
    .unwrap_or_else(|e| die(format!("genesis not fully/validly signed: {e}")));
    save_state(&state);
    write_json(out_path, &state.snapshot);
    println!("genesis fully signed → {out_path}. Browser: wallet_import_channel(<{out_path}>).");
}

/// 32 bytes from the OS CSPRNG (`rand010::rng()` is a cryptographically secure, OS-seeded thread
/// RNG). Used to seed the `StdRng` that produces Regev encryption randomness, so that no two
/// invocations can reuse it: reusing one `r` across two DIFFERENT plaintexts under one Regev key
/// leaks their difference (`c2 - c2' = Δ·(m - m')`), which for balances is the balance itself.
fn fresh_seed32() -> [u8; 32] {
    let mut rng = rand010::rng();
    let mut seed = [0u8; 32];
    for chunk in seed.chunks_mut(4) {
        chunk.copy_from_slice(&rand010::Rng::next_u32(&mut rng).to_le_bytes());
    }
    seed
}

fn parse_seed32(hex_str: &str) -> [u8; 32] {
    let bytes =
        hex::decode(hex_str).unwrap_or_else(|e| die(format!("cli_state: bad witness seed: {e}")));
    <[u8; 32]>::try_from(bytes.as_slice())
        .unwrap_or_else(|_| die("cli_state: witness seed must be 32 bytes"))
}

/// Where the reconstructible balance witness for `(member, token_slot)` lives, if any.
enum WitnessSource {
    /// `refresh`-recorded: a 32-byte `StdRng` seed (any local token position).
    Refreshed { amount: u64, seed: [u8; 32] },
    /// Genesis (local token position 0 only): the legacy u64 `balance_seed` written by
    /// `cli_members`. Unchanged so every pre-multitoken flow behaves byte-identically.
    Genesis { amount: u64, seed: u64 },
}

/// Resolve the sender's balance witness for one LOCAL token position, fail-closed.
///
/// SECURITY: a `refresh` record always WINS over the genesis triple for the same position — the
/// refresh replaced the ciphertext, so the genesis seed is stale there and handing it to the E-1
/// prover would build an unsatisfiable statement. `has_witness` gates both: a spent position has
/// no reconstructible witness and must be refreshed before it can send again.
fn witness_source(cm: &ControlledMember, token_slot: u8) -> Option<WitnessSource> {
    if let Some(w) = cm
        .token_witnesses
        .iter()
        .find(|w| w.token_slot == token_slot && w.has_witness)
    {
        return Some(WitnessSource::Refreshed {
            amount: w.amount,
            seed: parse_seed32(&w.seed_hex),
        });
    }
    if token_slot == 0 && cm.has_witness {
        return Some(WitnessSource::Genesis {
            amount: cm.balance_amount,
            seed: cm.balance_seed,
        });
    }
    None
}

/// Invalidate the witness for `(member, token_slot)` after the position was spent, and record the
/// new plaintext balance. Fail-closed bookkeeping: the position cannot send again until a
/// `refresh` re-establishes a reconstructible witness.
fn invalidate_witness(cm: &mut ControlledMember, token_slot: u8, new_balance: u64) {
    if let Some(w) = cm
        .token_witnesses
        .iter_mut()
        .find(|w| w.token_slot == token_slot)
    {
        w.has_witness = false;
        w.amount = new_balance;
    }
    if token_slot == 0 {
        cm.has_witness = false;
        cm.balance_amount = new_balance;
    }
}

/// usage: send <from> <to> <amount> [out.json] [token_slot]
/// `token_slot` (OPTIONAL, default 0 = the genesis token) is the LOCAL token position to move
/// (multitoken §N-3); it is signed into the IMPA-v2 digest and enforced by every verifier.
/// NOTE: the CLI's balance-witness store tracks the member's LAST self-encrypted ciphertext per
/// position — for a non-genesis token that only exists after `refresh <slot> <token_slot>`, and a
/// stale witness fails the E-1 proof fail-closed.
fn cmd_send(args: &[String]) {
    let from: u16 = args
        .get(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| die("send <from> <to> <amount> [out.json] [token_slot]"));
    let to: u16 = args
        .get(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| die("bad <to>"));
    let amount: u64 = args
        .get(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| die("bad <amount>"));
    let out_path = args.get(4).map(String::as_str).unwrap_or("payload.json");
    let token_slot: u8 = args
        .get(5)
        .map(|s| s.parse().unwrap_or_else(|_| die("bad [token_slot]")))
        .unwrap_or(0);
    let mut state = load_state();

    let cm = state
        .controlled
        .iter()
        .find(|c| c.slot == from)
        .unwrap_or_else(|| die(format!("slot {from} is not a CLI-controlled member")));
    let keys = keys_for(cm.keygen_seed);
    // Reconstruct the sender's current balance witness for THIS token position deterministically.
    let (before_amount, mut wit_rng) = match witness_source(cm, token_slot) {
        Some(WitnessSource::Refreshed { amount, seed }) => (amount, StdRng::from_seed(seed)),
        Some(WitnessSource::Genesis { amount, seed }) => (amount, StdRng::seed_from_u64(seed)),
        None => die(format!(
            "slot {from} has no spendable balance witness at token slot {token_slot} — the \
             position was never funded with a locally-witnessed ciphertext, or it was spent. Run \
             `channel_member refresh {from} {token_slot}` first (a homomorphically credited \
             position ALWAYS needs one)."
        )),
    };
    let (_ct, witness) =
        encrypt_amount(&mut wit_rng, &keys.regev_pk, before_amount).unwrap_or_else(|e| die(e));

    // SECURITY: the send's own encryption randomness comes from the OS CSPRNG, NOT from a
    // per-sender constant. A fixed seed was safe only while every CLI member sent at most once;
    // a repeat sender (e.g. the testnet ITX faucet member) would otherwise encrypt two different
    // plaintexts under the SAME `r`, which reveals their difference. Nondeterministic by design —
    // nothing downstream depends on byte-identical send payloads.
    let mut rng = StdRng::from_seed(fresh_seed32());
    let nonce = intmax3_zkp::ethereum_types::bytes32::Bytes32::default();
    let BuiltSend {
        payload,
        new_balance,
        ..
    } = build_send_token(
        &keys,
        &state.snapshot,
        from,
        to,
        token_slot,
        amount,
        before_amount,
        &witness,
        nonce,
        LEVEL,
        &mut rng,
    )
    .unwrap_or_else(|e| die(e));

    // Mark the SENT position as having no reproducible witness for its new ciphertext (the send's
    // `after_ct` randomness is not recorded). Sending again from this position requires a
    // `refresh` first. Balance commits on finalize.
    if let Some(c) = state.controlled.iter_mut().find(|c| c.slot == from) {
        invalidate_witness(c, token_slot, new_balance);
    }
    save_state(&state);
    write_json(out_path, &payload);
    println!(
        "built send {from}→{to} amount {amount} (token slot {token_slot}) → {out_path} (proof generated). Now collect co-signatures."
    );
}

fn cmd_cosign(args: &[String]) {
    let in_path = args
        .get(1)
        .unwrap_or_else(|| die("cosign <payload_or_state.json> <out>"));
    let out_path = args
        .get(2)
        .map(String::as_str)
        .unwrap_or("cosigned_state.json");
    let mut state = load_state();

    // SECURITY: require a SendPayload (which carries the ChannelTx + E-1 proof) so EVERY cosigner
    // re-verifies the transition before signing — never sign a bare state we did not validate.
    let payload: SendPayload = read_json(in_path);
    let mut next_state = payload.proposed_next_state.clone();

    if next_state.prev_digest != state.snapshot.state.digest {
        die("payload does not extend the current head");
    }

    // Verify the transition + E-1 proof once (with recipient decryption if a CLI slot receives).
    let recipient_is_cli = state
        .controlled
        .iter()
        .find(|c| c.slot == payload.recipient_index);
    let (sk, expected) = if let Some(c) = recipient_is_cli {
        let keys = keys_for(c.keygen_seed);
        let amt =
            intmax3_zkp::regev::decrypt_amount(&keys.regev_sk, &payload.channel_tx.enc_amount)
                .unwrap_or_else(|e| die(e));
        (Some(keys.regev_sk), Some(amt))
    } else {
        (None, None)
    };
    verify_send_transition(
        &state.snapshot.state,
        &state.snapshot.record,
        &payload,
        LEVEL,
        sk.as_ref(),
        expected,
    )
    .unwrap_or_else(|e| die(format!("transition invalid: {e}")));

    // CHECK-AND-SIGN (detail2 §3.1): each member signs the next state ONLY IF its settled_tx_chain
    // matches the held intmax balance backing (invariant across in-channel sends, so the genesis
    // attestation backs every in-channel state). Fail-closed — refuse otherwise.
    // SECURITY (§F-1): the deposit backing is anchored at GENESIS (create_channel co-signs only if
    // backed). Ongoing transitions are validated just above (verify_send_transition: real E-1 +
    // conservation), and a send legitimately ADVANCES settled_tx_chain once inter-channel transfers
    // exist — so re-checking it against the FIXED genesis backing here is wrong (it would reject
    // every state after the first inter-channel send). The backing holds inductively from the
    // backed genesis through validated, conservation-preserving transitions; reconciliation
    // against the deposit is the close/settlement step. (Same rationale as
    // cosign-inter-transfer.)
    ledger_sign_all_controlled(
        &mut state,
        &mut next_state,
        StateSigningPurpose::InChannelSend,
        None,
    );

    let signed: Vec<u8> = next_state
        .member_signatures
        .iter()
        .map(|s| s.member_slot)
        .collect();
    // DEMO: advance this CLI member's stored head to the just-cosigned state so SEQUENTIAL sends
    // work. Without this, cli_state stays at the genesis head and the 2nd send fails "payload does
    // not extend the current head". The browser finalizes exactly what we cosigned in this single
    // relay flow, so advancing optimistically is safe here; a real multi-party deployment would
    // advance only on confirmed finalization.
    state.snapshot.state = next_state;
    save_state(&state);
    // HEAD SYNC: publish the advanced head so `/api/snapshot` (the browsers' re-import source) is
    // current — otherwise a later re-import returns the stale init snapshot and the next send fails
    // "payload does not extend the current head".
    write_json("channel_snapshot.json", &state.snapshot);
    write_json(out_path, &state.snapshot.state);
    println!(
        "co-signed → {out_path}. Signatures now present for slots {signed:?} (need 0..{}).",
        state.snapshot.record.member_count
    );
}

/// Batched co-sign (abstract2-1 §3.2b): `cosign-batch <batch_payloads.json> <out>` where the input
/// is a JSON ARRAY of `SendPayload`s all anchored at the CURRENT head. Every payload is verified
/// with the full solo pipeline (`verify_send_transition`: E-1 proof, A11 sender sig, structural
/// fold) — IN PARALLEL, since the K verifications are independent — then the canonical batch state
/// is built (`build_batch_next_state`: R1 single-debit, debits-then-credits fold, D3 budget) and
/// co-signed once. ONE state_version bump for K transfers.
/// Input formats (detail2 §M-1/§M-4):
///   - MANIFEST (streaming, K-independent memory): `{"files": ["spool/a.json", …]}` — each file one
///     `SlimSendPayload`. Parsed + verified in bounded-size chunks; after a chunk verifies, only
///     the ~8 KB `BatchTxApply` residues are retained and the proofs are dropped.
///   - LEGACY array of fat `SendPayload`s — converted to slim in memory (small-K back-compat).
fn cmd_cosign_batch(args: &[String]) {
    let in_path = args
        .get(1)
        .unwrap_or_else(|| die("cosign-batch <manifest.json|batch_payloads.json> <out>"));
    let out_path = args
        .get(2)
        .map(String::as_str)
        .unwrap_or("batch_cosigned.json");
    let mut state = load_state();
    let head = state.snapshot.state.clone();

    #[derive(Deserialize)]
    struct BatchManifest {
        files: Vec<String>,
    }

    use rayon::prelude::*;
    // Per-BATCH one-time work (do NOT pay per tx): the 1024-entry Regev pk array (one clone per
    // member) and its authenticity check against the record's regev_pk_root (F9-A). Our snapshot's
    // member set was verified when it was written, but the root re-check is cheap once per batch.
    let regev_pks = regev_pks_array(&state.snapshot.members);
    verify_regev_pk_root(&state.snapshot.record, &regev_pks)
        .unwrap_or_else(|e| die(format!("regev_pk_root mismatch: {e:?}")));
    // Verify one slim tx against the head, with the CLI-recipient decryption check (same
    // belt-and-braces accounting check cmd_cosign runs) — members/record are OUR OWN snapshot's.
    let verify_one = |tag: &str, slim: &SlimSendPayload| -> Result<(), String> {
        let (sk, expected) = match state
            .controlled
            .iter()
            .find(|c| c.slot == slim.recipient_index)
        {
            Some(c) => {
                let keys = keys_for(c.keygen_seed);
                match intmax3_zkp::regev::decrypt_amount(
                    &keys.regev_sk,
                    &slim.channel_tx.enc_amount,
                ) {
                    Ok(amt) => (Some(keys.regev_sk), Some(amt)),
                    Err(e) => return Err(format!("{tag}: decrypt enc_amount: {e}")),
                }
            }
            None => (None, None),
        };
        verify_slim_send_tx(
            &head,
            &state.snapshot.record,
            &state.snapshot.members,
            &regev_pks,
            slim,
            LEVEL,
            sk.as_ref(),
            expected,
        )
        .map_err(|e| format!("{tag}: transition invalid: {e}"))
    };

    // Barrier-free pipeline: one flat par_iter over the manifest. Rayon runs at most
    // `num_threads` tasks at once and each task holds ONE parsed payload at a time, so peak
    // memory stays O(threads × payload) with no idle cores at chunk boundaries (the old
    // chunks-of-8 join let the fast core drain and wait on the slow one every chunk).
    let raw = fs::read_to_string(in_path).unwrap_or_else(|e| die(format!("read {in_path}: {e}")));
    let applies: Vec<BatchTxApply>;
    let k: usize;
    if let Ok(manifest) = serde_json::from_str::<BatchManifest>(&raw) {
        if manifest.files.is_empty() {
            die("cosign-batch: empty batch");
        }
        k = manifest.files.len();
        let result: Result<Vec<BatchTxApply>, String> = manifest
            .files
            .par_iter()
            .map(|f| {
                let bytes = fs::read(f).map_err(|e| format!("{f}: read: {e}"))?;
                let slim = SlimSendPayload::from_wire_or_json(&bytes)
                    .map_err(|e| format!("{f}: parse: {e}"))?;
                verify_one(f, &slim)?;
                Ok(BatchTxApply::from(&slim))
                // the parsed SlimSendPayload (and its proofs) drops here; only the residue survives
            })
            .collect();
        applies = result.unwrap_or_else(|e| die(format!("cosign-batch rejected: {e}")));
    } else {
        // LEGACY: a JSON array of fat SendPayloads.
        let payloads: Vec<SendPayload> = read_json(in_path);
        if payloads.is_empty() {
            die("cosign-batch: empty batch");
        }
        k = payloads.len();
        let errors: Vec<String> = payloads
            .par_iter()
            .enumerate()
            .filter_map(|(i, p)| verify_one(&format!("payload[{i}]"), &p.to_slim()).err())
            .collect();
        if !errors.is_empty() {
            die(format!("cosign-batch rejected: {}", errors.join("; ")));
        }
        applies = payloads
            .iter()
            .map(|p| BatchTxApply::from(&p.to_slim()))
            .collect();
    }

    let mut next_state = build_batch_next_state(&head, &applies)
        .unwrap_or_else(|e| die(format!("batch build: {e}")));

    // N-of-N co-sign for all CLI-controlled slots (same §F-1 rationale as cmd_cosign: backing is
    // anchored at genesis; per-state re-checks would wrongly reject post-inter-channel states).
    ledger_sign_all_controlled(
        &mut state,
        &mut next_state,
        StateSigningPurpose::InChannelBatch,
        None,
    );
    let next_version = next_state.balance_state.state_version;

    // Advance + republish head (same head-sync rationale as cmd_cosign).
    state.snapshot.state = next_state;
    save_state(&state);
    write_json("channel_snapshot.json", &state.snapshot);
    write_json(out_path, &state.snapshot.state);
    println!(
        "batch co-signed {k} txs in ONE state transition → {out_path} (state_version {next_version})"
    );
}

/// Co-sign a balance-REFRESH payload (a delegate/member re-encrypting its own slot to clean digits
/// so it can send again after receiving). Each member re-verifies the value-preserving refresh
/// transition before signing; the head advances + is published exactly like cmd_cosign.
fn cmd_cosign_refresh(args: &[String]) {
    let in_path = args
        .get(1)
        .unwrap_or_else(|| die("cosign-refresh <payload.json> <out>"));
    let out_path = args
        .get(2)
        .map(String::as_str)
        .unwrap_or("cosigned_state.json");
    let mut state = load_state();
    let payload: RefreshPayload = read_json(in_path);
    let mut next_state = payload.proposed_next_state.clone();
    if next_state.prev_digest != state.snapshot.state.digest {
        die("payload does not extend the current head");
    }
    verify_refresh_transition(
        &state.snapshot.state,
        &state.snapshot.record,
        &payload,
        LEVEL,
    )
    .unwrap_or_else(|e| die(format!("refresh transition invalid: {e}")));
    // SECURITY (§F-1): backing is anchored at GENESIS; the refresh transition is validated just
    // above (verify_refresh_transition: value-preserving). A refresh preserves
    // settled_tx_chain, but that chain may already have ADVANCED from a prior inter-channel
    // send, so it no longer equals the fixed genesis backing — re-checking it here would
    // wrongly reject. Plain N-of-N; same rationale as cmd_cosign / cosign-inter-transfer.
    ledger_sign_all_controlled(
        &mut state,
        &mut next_state,
        StateSigningPurpose::BalanceRefresh,
        None,
    );
    state.snapshot.state = next_state;
    save_state(&state);
    write_json("channel_snapshot.json", &state.snapshot);
    write_json(out_path, &state.snapshot.state);
    println!(
        "balance-refresh co-signed for slot {} (head advanced).",
        payload.member_index
    );
}

/// Pre-authorize the one terminal close-funding child without advancing the local channel head.
/// The signature decision is durable before the signed state is published, and the first accepted
/// terminal tuple permanently freezes this keyring to that exact successor/plan.
fn cmd_sign_close_funding(args: &[String]) {
    let proposal_path = args
        .get(1)
        .unwrap_or_else(|| die("sign-close-funding <proposal.json> <out_state.json>"));
    let out_path = args
        .get(2)
        .map(String::as_str)
        .unwrap_or("close_funding_signed_state.json");
    let proposal: CloseFundingProposal = read_json(proposal_path);
    let mut cli = load_state();
    let predecessor = cli.snapshot.state.clone();

    verify_snapshot(&cli.snapshot, None)
        .unwrap_or_else(|e| die(format!("current channel snapshot is invalid: {e}")));
    verify_all_signatures(&cli.snapshot.record, &cli.snapshot.members, &predecessor)
        .unwrap_or_else(|e| {
            die(format!(
                "sign-close-funding requires the current predecessor to be fully N-of-N signed: {e}"
            ))
        });

    // Resolve authority from the sticky ACTIVE binding and the configured RPC, never from the
    // proposal alone. Production bindings additionally revalidate their finalized L1 checkpoint.
    let rpc = std::env::var("RPC").unwrap_or_else(|_| "http://127.0.0.1:8545".to_string());
    let durable = cli
        .settlement_binding
        .clone()
        .unwrap_or_else(|| die("sign-close-funding requires a durable settlement binding"));
    if durable.status != SettlementBindingStatus::Active {
        die("sign-close-funding requires an ACTIVE settlement binding");
    }
    let durable_manager = durable
        .manager
        .clone()
        .unwrap_or_else(|| die("ACTIVE settlement binding has no manager"));
    let durable_verifier = durable
        .verifier
        .clone()
        .unwrap_or_else(|| die("ACTIVE settlement binding has no verifier"));
    let verifier_address = Address::from_hex(&durable_verifier)
        .unwrap_or_else(|e| die(format!("ACTIVE verifier is not an address: {e:?}")));
    if verifier_address == Address::default() {
        die("ACTIVE settlement binding has the zero verifier");
    }
    let manager = proposal.plan.manager.to_hex();
    let rollup = proposal.plan.rollup.to_hex();
    require_active_settlement_binding(&rpc, &manager, Some(&durable_verifier), Some(&rollup));
    if !same_hex_value(&durable_manager, &manager) || !same_hex_value(&durable.rollup, &rollup) {
        die("close-funding plan manager/rollup differs from the durable ACTIVE settlement binding");
    }
    let chain_id = rpc_chain_id(&rpc);
    if proposal.plan.chain_id != chain_id {
        die(format!(
            "close-funding plan chain {} differs from configured RPC chain {chain_id}",
            proposal.plan.chain_id
        ));
    }

    let record = cli.snapshot.record.clone();
    let controlled = cli.controlled.clone();
    let mut signed = proposal.proposed_state.clone();
    for member in &controlled {
        // Deliberately rerun canonical rebuild-equality immediately before EACH member decision.
        // Future refactors cannot validate one object and then sign a mutated sibling in-loop.
        verify_close_funding_proposal(&predecessor, &signed, &proposal.plan).unwrap_or_else(|e| {
            die(format!(
                "REFUSING close-funding signature for slot {}: {e}",
                member.slot
            ))
        });
        let signature = ledgered_state_signature(
            &mut cli,
            &record,
            member,
            &signed,
            StateSigningPurpose::CloseFunding,
            Some(proposal.plan.plan_digest),
        )
        .unwrap_or_else(|error| die(error));
        add_signature(&mut signed, signature);
    }
    verify_all_signatures(&record, &cli.snapshot.members, &signed).unwrap_or_else(|e| {
        die(format!(
            "close-funding child is not fully N-of-N signed: {e}"
        ))
    });

    // `cli.snapshot.state` intentionally remains the fully signed predecessor. Only the permanent
    // ledger reservation and exact signatures are committed in this atomic/fsynced write.
    save_state(&cli);
    write_json(out_path, &signed);
    println!(
        "sign-close-funding OK: terminal successor {} / plan {} reserved permanently; signed \
         state written to {out_path} without advancing the local head.",
        signed.digest, proposal.plan.plan_digest
    );
}

// ===================== INTER-CHANNEL TRANSFER (single atomic command) =====================
//
// CRITICAL-1 FIX. A cross-channel transfer is ONE atomic, synchronous command run by the relay,
// which OWNS BOTH channels (sibling cwds wallet-live-work/ch7, ch8). It is the single source of
// truth for both, so it never has to trust a request-body signed state.
//
//   `cosign-inter-transfer <debit_payload.json> <descriptor.json> <out.json>`
//   (cwd = SOURCE channel A, INTMAX_CHANNEL = A; destination B resolved as ../ch<dest_id>/)
//
// The credit leg is bound to A's COMMITTED on-disk head and a freshly-co-signed debit produced IN
// THIS PROCESS — never an `aSignedState` blob from the request body. This closes the value-creation
// hole: channel A's co-signing members derive their keys from PUBLIC seeds, so anyone could forge a
// fully-valid N-of-N `aSignedState` for an arbitrary post-debit state and POST it to a standalone
// credit endpoint. There is NO such endpoint anymore. The ONLY `a_signed_state` the credit gate
// ever sees is the one this command just built by extending A's REAL committed head and debiting
// A's fund.
//
// ATOMICITY: nothing is persisted unless BOTH legs validate. The debit leg co-signs A's proposed
// head IN MEMORY; the credit leg validates + builds B's credited head IN MEMORY; only after both
// succeed do we persist A's head, B's head (under the resolved ../ch<B>/ paths), and append the
// tx_hash to A's SPENT ledger and B's APPLIED ledger. If either leg fails, the process `die()`s
// having written nothing — A's head on disk is unchanged.
//
// SECURITY — why this path uses `sign_state` (plain N-of-N), not `sign_state_if_backed`:
// `sign_state_if_backed` reconciles `state.balance_state.settled_tx_chain` against the channel's
// genesis deposit-backing attestation. That holds for IN-channel sends/refreshes (which PRESERVE
// settled_tx_chain), but an inter-channel debit/credit PUSHES a new tx leaf into settled_tx_chain
// (detail2 §C-6), so the genesis attestation can never reconcile against the advanced chain —
// re-proving the channel's balance attestation for the new settle history is a separate §F-1 step
// (out of scope for the wallet wiring layer). The cryptographic soundness of these transitions is
// carried by the inter-channel gates (`verify_inter_channel_{send,credit}_transition`, re-verifying
// the REAL E-2 STARK + every cross-channel invariant) PLUS the N-of-N member signatures collected
// here. We DO NOT weaken `verify_channel_backing` to make a stale attestation pass.

/// Load the sibling DESTINATION-channel `CliState` (channel B) from
/// `../ch<dest_id>/cli_state.json`, relative to A's cwd. FAIL-CLOSED: refuse if it is missing.
/// Returns (B state, B's dir path) so the caller can persist B's head back under the same resolved
/// paths.
fn load_sibling_dest_state(dest_channel_id: u64) -> (CliState, std::path::PathBuf) {
    let dir = std::path::PathBuf::from(format!("../ch{dest_channel_id}"));
    let path = dir.join(STATE_FILE);
    if !path.exists() {
        die(format!(
            "destination channel B state not found at {}: the relay lays channels out as \
             wallet-live-work/ch<id>; the source process resolves B as ../ch<dest_id>/. Refusing to \
             credit without B's authentic on-disk state.",
            path.display()
        ));
    }
    secure_private_path(&path);
    let s =
        fs::read_to_string(&path).unwrap_or_else(|e| die(format!("read {}: {e}", path.display())));
    let st: CliState =
        serde_json::from_str(&s).unwrap_or_else(|e| die(format!("parse B state: {e}")));
    (st, dir)
}

/// detail2 §P-3: trusted member sets for FOREIGN channels' manifest leaves, resolved from the
/// relay's sibling channel layout (`../ch<id>/`, the same on-disk trust root
/// `load_sibling_dest_state` uses for the credit leg). A channel with no sibling state resolves to
/// `None`, which fails the aggregated round closed for that leaf — a member never signs a root
/// carrying a leaf whose sender it cannot authenticate. The (record, members) pairing returned
/// here is re-anchored inside `verify_aggregate_manifest` via the member_pubkeys_root recompute.
struct SiblingDirMemberLookup;
impl intmax3_zkp::wallet_core::InterChannelMemberLookup for SiblingDirMemberLookup {
    fn members_for(
        &self,
        channel: intmax3_zkp::common::channel_id::ChannelId,
    ) -> Option<(
        intmax3_zkp::common::channel::ChannelRecord,
        Vec<intmax3_zkp::wallet_core::MemberInfo>,
    )> {
        let path = std::path::PathBuf::from(format!("../ch{}", channel.as_u64())).join(STATE_FILE);
        if !path.exists() {
            return None;
        }
        secure_private_path(&path);
        let st: CliState = serde_json::from_str(&fs::read_to_string(&path).ok()?).ok()?;
        Some((st.snapshot.record, st.snapshot.members))
    }
}

/// D4a — the operator's node passes the daemon's authoritative live base nonce (served by
/// `/base-head`, which now proxies `liveBaseHead`) so the outgoing-send co-sign guards check
/// against the ADVANCED cursor instead of the frozen `channel_backing.json`.
///
/// That file's `base_private_state` is written once at `setup-backing` and never advanced, so on a
/// SECOND consecutive send it disagrees with the daemon: the old guard passed (stale == stale), the
/// channel debit was persisted, and only then did the daemon reject the settle — stranding the
/// value (retry blocked by the consumed replay identity). When this override is present it is
/// authoritative and the frozen witness is not consulted; sent-tx slot occupancy is still enforced
/// in-circuit (`spend_circuit`) and at the daemon's own settle. When absent (legacy / direct CLI
/// with no daemon), the guard falls back to the frozen witness, which fails closed on staleness.
const LIVE_BASE_NONCE_ENV: &str = "INTMAX_LIVE_BASE_NONCE";

fn live_base_nonce_override() -> Option<u32> {
    match std::env::var(LIVE_BASE_NONCE_ENV) {
        Ok(s) if s.trim().is_empty() => None,
        Ok(s) => Some(
            s.trim()
                .parse::<u32>()
                .unwrap_or_else(|e| die(format!("{LIVE_BASE_NONCE_ENV}={s:?} is not a u32: {e}"))),
        ),
        Err(_) => None,
    }
}

/// Gate an outgoing base send's nonce before any member signs and before the channel debit is
/// persisted. Prefers the daemon's live cursor (D4a); otherwise falls back to the frozen backing
/// witness. `die`s (fail-closed) on any mismatch or on a legacy backing with no override.
fn guard_outgoing_base_nonce(backing: &ChannelBacking, descriptor_base_nonce: u32, ctx: &str) {
    if let Some(live) = live_base_nonce_override() {
        if descriptor_base_nonce != live {
            die(format!(
                "{ctx}: base nonce {descriptor_base_nonce} != daemon live base nonce {live}; \
                 REFUSING before co-signing/debiting — the settle would be rejected and the debit \
                 stranded"
            ));
        }
        return;
    }
    let base_private = backing.base_private_state.as_ref().unwrap_or_else(|| {
        die(format!(
            "{ctx}: channel_backing.json has no base_private_state and no {LIVE_BASE_NONCE_ENV} \
             override was supplied; cannot gate the base nonce — migrate the live base IVC head"
        ))
    });
    verify_base_nonce_available(base_private, descriptor_base_nonce)
        .unwrap_or_else(|e| die(format!("{ctx}: {}", e.0)));
}

/// `cosign-inter-transfer <debit_payload.json> <descriptor.json> <out.json>` — the single atomic
/// cross-channel transfer command. Run with cwd = SOURCE channel A, INTMAX_CHANNEL = A.
///
/// Writes `{ "aHead": <A's co-signed new state>, "bSnapshot": <B's credited snapshot> }` to
/// out.json.
fn cmd_cosign_inter_transfer(args: &[String]) {
    recover_pending_inter_transfers();
    let payload_path = args.get(1).unwrap_or_else(|| {
        die("cosign-inter-transfer <debit_payload.json> <descriptor.json> <out.json>")
    });
    let desc_path = args.get(2).unwrap_or_else(|| {
        die("cosign-inter-transfer <debit_payload.json> <descriptor.json> <out.json>")
    });
    let out_path = args
        .get(3)
        .map(String::as_str)
        .unwrap_or("inter_transfer.json");

    let payload: InterChannelDebitPayload = read_json(payload_path);
    let descriptor: InterChannelTransferDescriptor = read_json(desc_path);

    // ---- Load A's COMMITTED head (this process's own cli_state). ----
    let mut a_state = load_state();

    verify_inter_channel_descriptor_matches_debit(&payload, &descriptor)
        .unwrap_or_else(|e| die(format!("inter-channel descriptor/debit mismatch: {e}")));

    // Every outgoing inter-channel debit consumes a base sent-tx slot. Receiving/importing can
    // advance the channel small-block counter without changing this cursor, so the IMI3-bound
    // explicit nonce is checked against the persisted base witness before any member signs.
    let backing: ChannelBacking = read_private_json(BACKING_FILE);
    guard_outgoing_base_nonce(
        &backing,
        descriptor.inter_channel_tx.base_nonce,
        "REFUSING inter-channel debit before co-signing",
    );

    // The descriptor must describe a transfer OUT of THIS channel (A) — defense in depth before the
    // gates run; A is the source.
    if descriptor.source_channel_id.as_u64() != channel_id_env() as u64 {
        die(format!(
            "descriptor.source_channel_id ({}) != this (source) channel {} — refusing",
            descriptor.source_channel_id.as_u64(),
            channel_id_env()
        ));
    }
    // The destination MUST be a DIFFERENT channel than the source: dest == source would resolve the
    // sibling B-state to A's own cli_state, and the B-write would clobber the A spent-ledger entry
    // (a self-transfer is meaningless here anyway). Reject before any state is loaded/written.
    if descriptor.destination_channel_id.as_u64() == channel_id_env() as u64 {
        die(format!(
            "descriptor.destination_channel_id ({}) == source channel — inter-channel transfer needs a DIFFERENT destination; refusing",
            descriptor.destination_channel_id.as_u64()
        ));
    }

    // SPENT LEDGER (A side, TM-16 obligation 1): refuse a debit whose token-FREE replay identity
    // was already debited out of A (single-use on the source, across ALL token relabelings of the
    // same deltas — see `CliState::spent_tx_identities`).
    let replay_identity = descriptor
        .inter_channel_tx
        .replay_identity()
        .unwrap_or_else(|e| die(format!("descriptor replay_identity: {e}")));
    if a_state.spent_tx_identities.contains(&replay_identity) {
        die(format!(
            "REFUSING: inter-channel tx identity {} already debited from channel A (replay) — fail-closed",
            replay_identity.to_hex()
        ));
    }

    // ================= LEG A (in memory): co-sign the post-debit head, extending A's REAL head.
    // ==== The proposed next state MUST extend A's COMMITTED head digest — not a request-body
    // blob.
    if payload.proposed_next_state.prev_digest != a_state.snapshot.state.digest {
        die("debit payload does not extend channel A's committed head");
    }
    // FAIL-CLOSED: re-verify the REAL E-2 + the send transition against A's TRUSTED head + record.
    verify_inter_channel_send_transition_with_lookup(
        &a_state.snapshot.state,
        &a_state.snapshot.record,
        &payload,
        LEVEL,
        &SiblingDirMemberLookup,
    )
    .unwrap_or_else(|e| die(format!("inter-channel send transition invalid: {e}")));

    let mut a_head = payload.proposed_next_state.clone();
    ledger_sign_all_controlled(
        &mut a_state,
        &mut a_head,
        StateSigningPurpose::InterChannelDebit,
        None,
    );
    // Authoritative N-of-N gate under A's OWN record. `a_head` is now the ONLY a_signed_state the
    // credit leg will ever see — built here, never from a request body.
    verify_all_signatures(&a_state.snapshot.record, &a_state.snapshot.members, &a_head)
        .unwrap_or_else(|e| die(format!("inter-debit a_head not N-of-N co-signed: {e}")));

    // CONSERVATION (A side, full u64 precision, per token — TM-6): A's fund decreased by
    // EXACTLY descriptor.amount at the LOCAL slot A's registry resolves for the descriptor's
    // BASE token_index, and at NO other position (belt-and-braces over the witness's
    // ensure_funds_unchanged_except).
    let amt256 = intmax3_zkp::wallet_core::u64_to_u256(descriptor.amount);
    let a_token_slot = resolve_local_token_slot(
        &a_state.snapshot.state.balance_state,
        descriptor.inter_channel_tx.token_index,
    )
    .unwrap_or_else(|e| die(format!("A-side token resolution: {e}")));
    for t in 0..a_head.channel_fund.amounts.len() {
        let (before, after) = (
            a_state.snapshot.state.channel_fund.amounts[t],
            a_head.channel_fund.amounts[t],
        );
        let ok = if t == a_token_slot {
            after + amt256 == before
        } else {
            after == before
        };
        if !ok {
            die(format!(
                "conservation check FAILED: A channel_fund position {t} did not move by exactly \
                 the expected delta (token slot {a_token_slot}, amount {})",
                descriptor.amount
            ));
        }
    }

    // ================= LEG B (in memory): validate + build B's credited head.
    // ======================
    let (mut b_state, _b_dir) = load_sibling_dest_state(descriptor.destination_channel_id.as_u64());

    // REPLAY LEDGER (B side, invariant 6 + TM-16 obligation 1): refuse a credit whose token-FREE
    // replay identity was already credited into B. Keying on the identity (never the
    // token-bearing tx_hash) is what refuses a SECOND, fully-consistent token-Y variant of an
    // already-credited debit — the cross-token double-credit is structurally a replay here.
    if b_state.applied_tx_identities.contains(&replay_identity) {
        die(format!(
            "REFUSING: inter-channel tx identity {} already credited into channel B (replay) — fail-closed (invariant 6)",
            replay_identity.to_hex()
        ));
    }

    // The TRUSTED A record is A's OWN committed record (this process). The credit gate's
    // `a_signed_state` is the IN-MEMORY `a_head` we just co-signed — NOT a request-body blob. So a
    // forged N-of-N state (built from the public member seeds) can never be credited: it would have
    // to equal `a_head`, which can only be produced by extending A's real head and debiting A's
    // fund.
    let trusted_a_record = a_state.snapshot.record.clone();
    verify_inter_channel_credit_transition(
        &b_state.snapshot.state,
        &b_state.snapshot.record,
        &descriptor,
        &a_head,
        &trusted_a_record,
        LEVEL,
    )
    .unwrap_or_else(|e| die(format!("inter-channel credit gate REFUSED: {e}")));

    // Pick a CLI member to APPLY the credit. If the recipient slot is a CLI member, use its keys so
    // build_inter_channel_credit also runs the recipient-decryption == amount check; otherwise (a
    // delegate recipient) any CLI member may build the homomorphic add.
    let recipient_slot = descriptor.recipient_slot;
    let builder = b_state
        .controlled
        .iter()
        .find(|c| c.slot == recipient_slot)
        .or_else(|| b_state.controlled.first())
        .unwrap_or_else(|| die("channel B has no CLI member to apply the credit"));
    let builder_keys = keys_for(builder.keygen_seed);

    // TM-6 (B side): the credit lands at the LOCAL slot B's OWN registry resolves for the
    // descriptor's BASE token_index (source and destination registries may map it differently).
    let b_token_slot = resolve_local_token_slot(
        &b_state.snapshot.state.balance_state,
        descriptor.inter_channel_tx.token_index,
    )
    .unwrap_or_else(|e| die(format!("B-side token resolution: {e}")));
    let b_fund_before = b_state.snapshot.state.channel_fund.amounts;
    // NOT a randomness-reuse site today: `build_inter_channel_credit` opens with `let _ = rng;`
    // (which MOVES the `&mut`, so the borrow checker forbids any later use) and encrypts nothing —
    // the credit is a deterministic homomorphic add of the descriptor's `receiver_deltas`, which
    // the SOURCE channel already encrypted. The old fixed seed was therefore dead, but it was a
    // trap: the day that builder starts drawing randomness, a per-recipient-slot constant becomes
    // exactly the reuse bug fixed in `cmd_send`. Seed from the OS CSPRNG so the call site is right
    // regardless of what the callee does.
    let mut rng = StdRng::from_seed(fresh_seed32());
    let BuiltInterChannelCredit {
        fund_import_state,
        bundle_apply_state,
        ..
    } = build_inter_channel_credit(
        &builder_keys,
        &b_state.snapshot,
        &descriptor,
        LEVEL,
        &mut rng,
    )
    .unwrap_or_else(|e| die(format!("build_inter_channel_credit failed: {e}")));

    // CONSERVATION (B side, full u64 precision, per token): B's fund increased by EXACTLY
    // descriptor.amount at the resolved slot and at NO other position.
    for t in 0..bundle_apply_state.channel_fund.amounts.len() {
        let (before, after) = (b_fund_before[t], bundle_apply_state.channel_fund.amounts[t]);
        let ok = if t == b_token_slot {
            after == before + amt256
        } else {
            after == before
        };
        if !ok {
            die(format!(
                "conservation check FAILED: B channel_fund position {t} did not move by exactly \
                 the expected delta (token slot {b_token_slot}, amount {})",
                descriptor.amount
            ));
        }
    }

    // N-of-N co-sign BOTH destination states. The intermediate fund-import head is not merely a
    // local construction detail: the durable producer and live balance IVC replay the exact
    // contiguous sequence after a crash. Persisting only the final bundle state would leave its
    // `prev_digest` pointing at an unauthenticated, unrecoverable gap.
    let mut b_fund_import = fund_import_state;
    ledger_sign_all_controlled(
        &mut b_state,
        &mut b_fund_import,
        StateSigningPurpose::InterChannelFundImport,
        None,
    );
    verify_all_signatures(
        &b_state.snapshot.record,
        &b_state.snapshot.members,
        &b_fund_import,
    )
    .unwrap_or_else(|e| {
        die(format!(
            "inter-credit B fund-import not N-of-N co-signed: {e}"
        ))
    });

    // The bundle state was built against the same digest (signatures do not enter the state
    // digest). Collect the remaining real member signatures independently.
    let mut b_head = bundle_apply_state;
    ledger_sign_all_controlled(
        &mut b_state,
        &mut b_head,
        StateSigningPurpose::InterChannelBundleApply,
        None,
    );
    verify_all_signatures(&b_state.snapshot.record, &b_state.snapshot.members, &b_head)
        .unwrap_or_else(|e| die(format!("inter-credit B state not N-of-N co-signed: {e}")));

    // ================= COMMIT (both legs validated): durable two-phase roll-forward.
    // The PREPARED journal contains both complete post-states and is fsynced before either channel
    // moves. A crash after one replacement is recovered by `recover-inter-transfers`; no later API
    // mutation can run first because its producer-head preflight invokes that command.
    a_state.snapshot.state = a_head.clone();
    a_state.spent_tx_identities.insert(replay_identity);
    b_state.snapshot.state = b_head.clone();
    b_state.applied_tx_identities.insert(replay_identity);
    let result = InterTransferOut {
        a_head: a_head.clone(),
        b_fund_import_state: b_fund_import.clone(),
        b_bundle_apply_state: b_head.clone(),
        b_snapshot: b_state.snapshot.clone(),
    };
    let mut commit = InterTransferCommitJournal {
        magic: INTER_TRANSFER_COMMIT_MAGIC.to_string(),
        version: INTER_TRANSFER_COMMIT_VERSION,
        phase: InterTransferCommitPhase::Prepared,
        tx_hash: descriptor.tx_hash,
        replay_identity,
        source_channel_id: descriptor.source_channel_id.as_u64(),
        destination_channel_id: descriptor.destination_channel_id.as_u64(),
        source_before_digest: a_head.prev_digest,
        destination_before_digest: b_fund_import.prev_digest,
        source_after: a_state.clone(),
        destination_after: b_state.clone(),
        result,
    };
    validate_inter_transfer_commit(&commit);
    let commit_path = inter_transfer_commit_path(descriptor.tx_hash);
    if commit_path.exists() {
        die(format!(
            "inter-transfer commit journal {} already exists; run recover-inter-transfers",
            commit_path.display()
        ));
    }
    write_inter_transfer_commit(&commit_path, &commit);
    roll_forward_inter_transfer_commit(&commit_path, &mut commit);
    // Recovery always publishes the canonical API artifact name. Preserve a caller's additional
    // explicit output path as a convenience only after the two-channel commit is durable.
    if out_path != "inter_transfer.json" {
        write_json(out_path, &commit.result);
    }

    let a_signed: Vec<u8> = a_head
        .member_signatures
        .iter()
        .map(|s| s.member_slot)
        .collect();
    let b_signed: Vec<u8> = b_head
        .member_signatures
        .iter()
        .map(|s| s.member_slot)
        .collect();
    println!(
        "inter-channel TRANSFER applied atomically: channel {} → channel {} slot {}, amount {}. \
         A debited (sigs {a_signed:?}, tx recorded in A spent ledger); B credited (sigs {b_signed:?}, \
         tx recorded in B applied ledger). tx_hash {} → {out_path}.",
        descriptor.source_channel_id.as_u64(),
        descriptor.destination_channel_id.as_u64(),
        recipient_slot,
        descriptor.amount,
        descriptor.tx_hash.to_hex()
    );
}

/// Burn-send co-sign: the DEBIT leg of an inter-channel transfer to `BURN_CHANNEL_ID` (partial
/// withdrawal). Identical to the first half of `cmd_cosign_inter_transfer` but with NO credit leg
/// (the burn channel is unregisterable → the phantom credit is unclaimable). Persists
/// `last_burn.json` so `pw-submit` can reconstruct the `Withdrawal` struct.
fn cmd_cosign_burn_send(args: &[String]) {
    let payload_path = args.get(1).unwrap_or_else(|| {
        die("cosign-burn-send <debit_payload.json> <descriptor.json> <out.json>")
    });
    let desc_path = args.get(2).unwrap_or_else(|| {
        die("cosign-burn-send <debit_payload.json> <descriptor.json> <out.json>")
    });
    let out_path = args
        .get(3)
        .map(String::as_str)
        .unwrap_or("burn_cosigned.json");

    let payload: InterChannelDebitPayload = read_json(payload_path);
    let descriptor: InterChannelTransferDescriptor = read_json(desc_path);

    let mut a_state = load_state();

    // P0-7: bind descriptor economics to the E-2-proved payload BEFORE any member signature or
    // channel debit. In particular, `descriptor.amount = X+1` with an honest proof for X dies here.
    verify_inter_channel_descriptor_matches_debit(&payload, &descriptor)
        .unwrap_or_else(|e| die(format!("burn descriptor/debit mismatch: {e}")));

    // P2-4: a partial-withdrawal leaf is provable only if its Tx nonce names an EMPTY position in
    // the base account's sent-tx tree and is exactly the base private state's next nonce. Checking
    // only the channel small-block counter hid divergence until after an irreversible channel
    // debit. This reads the witness paired with `channel_attestation.bin`; it is not a best-effort
    // local replay ledger.
    let backing: ChannelBacking = read_private_json(BACKING_FILE);
    let burn_nonce = descriptor.inter_channel_tx.base_nonce;
    guard_outgoing_base_nonce(
        &backing,
        burn_nonce,
        "burn nonce guard: REFUSING before co-signing/debiting because the withdrawal would be \
         unprovable",
    );

    if descriptor.source_channel_id.as_u64() != channel_id_env() as u64 {
        die(format!(
            "descriptor.source_channel_id ({}) != this channel {} — refusing",
            descriptor.source_channel_id.as_u64(),
            channel_id_env()
        ));
    }

    // TM-16 obligation 1: the burn spent ledger keys on the token-FREE replay identity too (a
    // burn is the debit leg of an inter-channel send; same cross-token relabel surface).
    let burn_replay_identity = descriptor
        .inter_channel_tx
        .replay_identity()
        .unwrap_or_else(|e| die(format!("burn descriptor replay_identity: {e}")));
    if a_state.spent_tx_identities.contains(&burn_replay_identity) {
        die(format!(
            "REFUSING: burn tx identity {} already debited (replay) — fail-closed",
            burn_replay_identity.to_hex()
        ));
    }

    if payload.proposed_next_state.prev_digest != a_state.snapshot.state.digest {
        die("burn debit payload does not extend channel's committed head");
    }

    verify_inter_channel_send_transition_with_lookup(
        &a_state.snapshot.state,
        &a_state.snapshot.record,
        &payload,
        LEVEL,
        &SiblingDirMemberLookup,
    )
    .unwrap_or_else(|e| die(format!("burn send transition invalid: {e}")));

    let mut a_head = payload.proposed_next_state.clone();
    ledger_sign_all_controlled(
        &mut a_state,
        &mut a_head,
        StateSigningPurpose::BurnDebit,
        None,
    );
    verify_all_signatures(&a_state.snapshot.record, &a_state.snapshot.members, &a_head)
        .unwrap_or_else(|e| die(format!("burn debit not N-of-N co-signed: {e}")));

    // CONSERVATION (per token — TM-6): the burn debits EXACTLY the LOCAL slot resolved for the
    // descriptor's BASE token_index, and no other position.
    let amt256 = intmax3_zkp::wallet_core::u64_to_u256(descriptor.amount);
    let burn_token_slot = resolve_local_token_slot(
        &a_state.snapshot.state.balance_state,
        descriptor.inter_channel_tx.token_index,
    )
    .unwrap_or_else(|e| die(format!("burn token resolution: {e}")));
    for t in 0..a_head.channel_fund.amounts.len() {
        let (before, after) = (
            a_state.snapshot.state.channel_fund.amounts[t],
            a_head.channel_fund.amounts[t],
        );
        let ok = if t == burn_token_slot {
            after + amt256 == before
        } else {
            after == before
        };
        if !ok {
            die(format!(
                "conservation check FAILED: channel_fund position {t} did not move by exactly \
                 the expected burn delta (token slot {burn_token_slot}, amount {})",
                descriptor.amount
            ));
        }
    }

    let pre_burn_settled_tx_chain = a_state.snapshot.state.balance_state.settled_tx_chain;
    a_state.snapshot.state = a_head.clone();
    a_state.spent_tx_identities.insert(burn_replay_identity);
    save_state(&a_state);
    write_json("channel_snapshot.json", &a_state.snapshot);

    // Persist burn metadata for `pw-submit` to reconstruct the Withdrawal. `token_index` is the
    // BASE token the burn debited (multitoken §N — rides into the Withdrawal + IPW2 authDigest).
    //
    // SECURITY: the L1 withdrawal leaf — and above all its NULLIFIER — is recorded HERE, derived
    // by the one shared `burn_withdrawal_leaf`. It is settlement-independent (F-WD-2), so it is
    // fully determined the moment the burn is co-signed. `pw-submit` recomputes it and refuses to
    // proceed on any disagreement, so a coordinator cannot substitute a leaf between the two
    // steps, and the value that goes into the on-chain authorization is the same value a provable
    // `single_withdrawal` leaf will carry.
    let burn_tx_leaf = tx_leaf_hash(
        descriptor.source_pk_g,
        payload.inter_channel_tx.sender_delta_ct.digest(),
        descriptor.receiver_pk_g,
        descriptor.receiver_delta.digest(),
    );
    let burn_aux_data = burn_descriptor(
        descriptor.source_channel_id,
        descriptor.inter_channel_tx.base_nonce,
        burn_tx_leaf,
        descriptor.receiver_pk_g,
        descriptor.inter_channel_tx.token_index,
        intmax3_zkp::wallet_core::u64_to_u256(descriptor.amount),
    );
    let burn_leaf = burn_withdrawal_leaf(
        descriptor.source_channel_id,
        descriptor.receiver_pk_g,
        descriptor.inter_channel_tx.token_index,
        descriptor.amount,
        burn_aux_data,
        descriptor.tx_v2.nonce,
    )
    .unwrap_or_else(|e| die(format!("burn withdrawal leaf: {e:?}")));
    write_json(
        "last_burn.json",
        &serde_json::json!({
            "tx_hash": descriptor.tx_hash.to_hex(),
            "amount": descriptor.amount,
            "token_index": descriptor.inter_channel_tx.token_index,
            "source_pk_g": descriptor.source_pk_g.to_hex(),
            "receiver_pk_g": descriptor.receiver_pk_g.to_hex(),
            "sender_delta_ct_digest": payload.inter_channel_tx.sender_delta_ct.digest().to_hex(),
            "receiver_delta_ct_digest": descriptor.receiver_delta.digest().to_hex(),
            "pre_burn_settled_tx_chain": pre_burn_settled_tx_chain.to_hex(),
            "channel_id": descriptor.source_channel_id.as_u64(),
            "tx_nonce": descriptor.tx_v2.nonce,
            "base_nonce": descriptor.inter_channel_tx.base_nonce,
            "tx_leaf": burn_tx_leaf.to_hex(),
            "aux_data": burn_aux_data.to_hex(),
            "withdrawal_recipient": format!("0x{}", hex::encode(burn_leaf.recipient.to_bytes_be())),
            "withdrawal_nullifier": burn_leaf.nullifier.to_hex(),
        }),
    );

    write_json(out_path, &a_head);
    let signed: Vec<u8> = a_head
        .member_signatures
        .iter()
        .map(|s| s.member_slot)
        .collect();
    println!(
        "burn-send co-signed: channel {} debited {} at token slot {burn_token_slot} (base index \
         {}, sigs {signed:?}). Fund: {} → {}. Burn metadata written to last_burn.json.",
        channel_id_env(),
        descriptor.amount,
        descriptor.inter_channel_tx.token_index,
        a_state.snapshot.state.channel_fund.amounts[burn_token_slot] + amt256,
        a_state.snapshot.state.channel_fund.amounts[burn_token_slot],
    );
}

fn cmd_finalize(args: &[String]) {
    let in_path = args
        .get(1)
        .unwrap_or_else(|| die("finalize <fully_signed_state.json>"));
    let next_state: ChannelState = read_json(in_path);
    let mut state = load_state();
    if next_state.prev_digest != state.snapshot.state.digest {
        die("finalized state does not extend the current head");
    }
    verify_all_signatures(&state.snapshot.record, &state.snapshot.members, &next_state)
        .unwrap_or_else(|e| die(format!("not fully/validly signed: {e}")));
    state.snapshot.state = next_state;
    verify_snapshot(&state.snapshot, None).unwrap_or_else(|e| die(e));
    // Refresh controlled balances from the new state (recipients gain; senders already updated).
    // The CLI's stored per-member scalar tracks the GENESIS token position (0); non-genesis
    // balances are displayed per token by `cmd_balance` but not witness-tracked here.
    for c in state.controlled.iter_mut() {
        let keys = keys_for(c.keygen_seed);
        if let Ok(bal) = decrypt_balance_token(&keys, &state.snapshot, c.slot, 0) {
            if bal != c.balance_amount {
                // A receive (homomorphic add): balance changed, witness no longer reproducible.
                c.balance_amount = bal;
                c.has_witness = false;
            }
        }
    }
    save_state(&state);
    println!(
        "finalized. New state_version = {}.",
        state.snapshot.state.balance_state.state_version
    );
    cmd_balance();
}

fn cmd_balance() {
    let state = load_state();
    let bs = &state.snapshot.state.balance_state;
    let token_count = bs.token_count as usize;
    for c in &state.controlled {
        let keys = keys_for(c.keygen_seed);
        // Per-token view (multitoken §N-2): every ACTIVE registry position; unused positions
        // are the canonical zero ct and decrypt to 0 under any key.
        for t in 0..token_count {
            match decrypt_balance_token(&keys, &state.snapshot, c.slot, t as u8) {
                Ok(bal) => println!(
                    "  slot {} token {} (base index {}) balance = {}{}",
                    c.slot,
                    t,
                    bs.token_registry[t],
                    bal,
                    if t == 0 {
                        format!(" (can_send={})", c.has_witness)
                    } else {
                        String::new()
                    }
                ),
                Err(e) => {
                    println!("  slot {} token {t} balance = <decrypt error: {e}>", c.slot)
                }
            }
        }
    }
}

/// usage: register-token <base_token_index> [out.json]
/// detail2 §N-1: append-only cosigned `TokenRegister` — appends the BASE-layer `token_index` at
/// local position `token_count` (header-only state change; balances/funds untouched). All
/// CLI-controlled members run the fail-closed gate (`verify_token_register_state_transition`:
/// append-exactness + full freeze + rebuild-equality, TM-1/TM-9) before signing; the head
/// advances only once the REAL N-of-N signature set verifies.
fn cmd_register_token(args: &[String]) {
    let token_index: u32 = args
        .get(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| die("register-token <base_token_index> [out.json]"));
    let out_path = args
        .get(2)
        .map(String::as_str)
        .unwrap_or("token_register_cosigned.json");
    let mut state = load_state();

    let builder = state
        .controlled
        .first()
        .unwrap_or_else(|| die("no CLI-controlled member to propose the registration"));
    let builder_keys = keys_for(builder.keygen_seed);
    let mut proposed =
        build_token_register(&builder_keys, &state.snapshot, builder.slot, token_index)
            .unwrap_or_else(|e| die(format!("build token register: {e}")));

    // Every other CLI-controlled member re-runs the gate itself, then signs (check-and-sign).
    let controlled = state.controlled.clone();
    let record = state.snapshot.record.clone();
    for c in &controlled {
        verify_token_register_state_transition(
            &state.snapshot.state,
            &record,
            &proposed,
            token_index,
        )
        .unwrap_or_else(|e| die(format!("REFUSING TO SIGN token register — {e}")));
        let sig = ledgered_state_signature(
            &mut state,
            &record,
            c,
            &proposed,
            StateSigningPurpose::TokenRegister,
            None,
        )
        .unwrap_or_else(|error| die(error));
        add_signature(&mut proposed, sig);
    }
    // Authoritative N-of-N gate before the head advances.
    verify_all_signatures(&state.snapshot.record, &state.snapshot.members, &proposed)
        .unwrap_or_else(|e| die(format!("token register not fully/validly signed: {e}")));

    state.snapshot.state = proposed;
    save_state(&state);
    write_json("channel_snapshot.json", &state.snapshot);
    write_json(out_path, &state.snapshot.state);
    let bs = &state.snapshot.state.balance_state;
    println!(
        "register-token OK: base token_index {token_index} registered at local slot {} \
         (token_count {}, state_version {}) → {out_path}.",
        bs.token_count - 1,
        bs.token_count,
        bs.state_version
    );
}

/// usage: refresh <slot> [token_slot] [out.json]
///
/// Balance-REFRESH a CLI-controlled member's OWN `(slot, token_slot)` position (detail2 §B-3 ×
/// multitoken §N, TM-13): re-encrypt the position's current value to a FRESH ciphertext whose
/// encryption witness this process can reconstruct later, and reset that position's
/// `pending_adds`. This is the CLI twin of the browser's `wallet_refresh`.
///
/// WHY IT IS NEEDED. A position credited HOMOMORPHICALLY — an L1 deposit import (`+= delta`,
/// `pending_adds += 1`) or an incoming in-channel transfer — leaves a ciphertext for which this
/// process holds NO encryption witness, and `build_send_token` refuses to spend it twice over:
/// once on the `pending_adds != 0` gate and once because a stale witness cannot satisfy E-1.
/// A refresh is the only value-preserving way out. That is exactly the situation of the testnet
/// ITX faucet member, whose supply arrives via `cosign-l1-deposit-import`.
///
/// NOTHING IS MINTED. `RefreshAir` proves `old_ct` and `new_ct` encrypt the SAME hidden value, and
/// `verify_refresh_transition` re-runs that proof plus the structural witness (only this position
/// changes, its counter resets, every other position frozen) before any signature is added. The
/// head advances only once the REAL N-of-N signature set verifies.
///
/// SECURITY — witness reproducibility. `build_refresh` hands its RNG to
/// `prove_balance_refresh_witnessed`, whose first and ONLY RNG consumption is the `encrypt_amount`
/// that produces the new ciphertext. Seeding a `StdRng` with 32 OS-random bytes and RECORDING that
/// seed therefore reconstructs the exact `AmountWitness` on a later invocation without persisting
/// unserializable key material — the same deterministic-seed model the genesis witnesses use. That
/// invariant is not assumed: it is RE-CHECKED below against the co-signed state, fail-closed, so an
/// upstream change in RNG consumption stops the command instead of silently recording a witness
/// that would fail E-1 later.
fn cmd_refresh(args: &[String]) {
    let slot: u16 = args
        .get(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| die("refresh <slot> [token_slot] [out.json]"));
    let token_slot: u8 = args
        .get(2)
        .map(|s| s.parse().unwrap_or_else(|_| die("bad [token_slot]")))
        .unwrap_or(0);
    let out_path = args
        .get(3)
        .map(String::as_str)
        .unwrap_or("refresh_cosigned.json");
    let mut state = load_state();

    let cm = state
        .controlled
        .iter()
        .find(|c| c.slot == slot)
        .unwrap_or_else(|| {
            die(format!(
                "slot {slot} is not a CLI-controlled member — only the owner of a position may \
                 refresh it (the refresh proof needs its Regev secret key)"
            ))
        });
    let keys = keys_for(cm.keygen_seed);

    let seed = fresh_seed32();
    let (payload, witness) = build_refresh(
        &keys,
        &state.snapshot,
        slot,
        token_slot,
        LEVEL,
        &mut StdRng::from_seed(seed),
    )
    .unwrap_or_else(|e| die(format!("build refresh: {e}")));

    // Fail-closed self-check: the recorded seed MUST reproduce exactly the ciphertext the refresh
    // installs, or the stored witness is worthless and every later send from this position would
    // fail E-1 with a confusing error. Cheap (one encryption) relative to the proof just built.
    let (replayed_ct, _) =
        encrypt_amount(&mut StdRng::from_seed(seed), &keys.regev_pk, witness.amount)
            .unwrap_or_else(|e| die(e));
    if replayed_ct
        != payload.proposed_next_state.balance_state.enc_balances[slot as usize]
            [token_slot as usize]
    {
        die(
            "refresh: the recorded seed does not reproduce the refreshed ciphertext — the RNG \
             consumption of prove_balance_refresh_witnessed changed. REFUSING to record an \
             unusable witness.",
        );
    }

    let mut next_state = payload.proposed_next_state.clone();
    if next_state.prev_digest != state.snapshot.state.digest {
        die("refresh does not extend the current head");
    }
    // CHECK-AND-SIGN: every CLI-controlled member re-runs the adversarial gate itself (real
    // RefreshAir verification + structural freeze) before adding its signature — the builder being
    // this same process buys the transition nothing.
    let controlled = state.controlled.clone();
    let record = state.snapshot.record.clone();
    for c in &controlled {
        verify_refresh_transition(&state.snapshot.state, &record, &payload, LEVEL)
            .unwrap_or_else(|e| die(format!("REFUSING TO SIGN refresh — {e}")));
        let sig = ledgered_state_signature(
            &mut state,
            &record,
            c,
            &next_state,
            StateSigningPurpose::BalanceRefresh,
            None,
        )
        .unwrap_or_else(|error| die(error));
        add_signature(&mut next_state, sig);
    }
    // Authoritative N-of-N gate before the head advances.
    verify_all_signatures(&state.snapshot.record, &state.snapshot.members, &next_state)
        .unwrap_or_else(|e| die(format!("refresh not fully/validly signed: {e}")));

    // Record the reconstructible witness for this position ONLY after the head is committed.
    if let Some(c) = state.controlled.iter_mut().find(|c| c.slot == slot) {
        let entry = TokenWitness {
            token_slot,
            amount: witness.amount,
            seed_hex: hex::encode(seed),
            has_witness: true,
        };
        match c
            .token_witnesses
            .iter_mut()
            .find(|w| w.token_slot == token_slot)
        {
            Some(w) => *w = entry,
            None => c.token_witnesses.push(entry),
        }
        // A refresh of position 0 REPLACES the genesis ciphertext, so the legacy `balance_seed`
        // triple is stale from here on. Retire it explicitly rather than relying on the lookup
        // order in `witness_source` — if this record is ever spent and invalidated, the fallback
        // must not silently resurrect a seed that no longer matches state.
        if token_slot == 0 {
            c.has_witness = false;
            c.balance_amount = witness.amount;
        }
    }
    state.snapshot.state = next_state.clone();
    save_state(&state);
    write_json("channel_snapshot.json", &state.snapshot);
    write_json(out_path, &next_state);
    println!(
        "refresh OK: slot {slot} token slot {token_slot} re-encrypted (value {}, state_version {}) → {out_path}. \
         The position is spendable again.",
        witness.amount, state.snapshot.state.balance_state.state_version
    );
}

// ─── Wallet testnet UX: settlement deploy + L1 deposit import + partial withdrawal ────────

/// The ONE chain id that may receive a settlement stack wired to an ALWAYS-TRUE mock MLE verifier.
///
/// SECURITY: 31337 is anvil's default and is not a public network. `DeployWalletSettlement.s.sol`
/// itself carries the same `require(block.chainid == 31337)`, so the mock stack is gated twice,
/// independently — this constant is the Rust half.
const DEVNET_CHAIN_ID: u64 = 31337;

/// Which forge script `deploy-settlement` will run, chosen from the chain id the RPC reports.
///
/// SECURITY (why this is a type and not a `&str` picked inline): a mock MLE verifier returns true
/// for ANY proof, so a settlement stack built on one has a vacuous `_checkCloseProof` — anyone can
/// close any channel to any state and drain it. Making the mock script name reachable ONLY through
/// `SettlementDeployPlan::MockDevnet::script()`, and making that variant constructible ONLY by
/// `settlement_deploy_plan(31337)`, turns "never deploy the mock off-devnet" from a rule someone
/// has to remember into something the type system enforces: there is no code path that names
/// `DeployWalletSettlement.s.sol` without first having proved `chain_id == DEVNET_CHAIN_ID`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SettlementDeployPlan {
    /// anvil only — `DeployWalletSettlement.s.sol`: mock (always-true) MLE verifier, 1-second
    /// challenge period, placeholder VKs.
    MockDevnet,
    /// Every other chain — `DeployCloseCli.s.sol`: real MLE/WHIR verifier data for all four
    /// settlement statements, real challenge period, `registerSettlementManager`.
    RealChain,
}

impl SettlementDeployPlan {
    /// The forge script path, relative to the contracts checkout.
    ///
    /// SECURITY: this match and `contract()` are the ONLY places in the binary where the mock
    /// deployer is named. Grep for `DeployWalletSettlement` — two hits, both in a `MockDevnet` arm.
    fn script(self) -> &'static str {
        match self {
            Self::MockDevnet => "script/DeployWalletSettlement.s.sol",
            Self::RealChain => "script/DeployCloseCli.s.sol",
        }
    }

    /// The `--tc` contract name inside that script.
    fn contract(self) -> &'static str {
        match self {
            Self::MockDevnet => "DeployWalletSettlement",
            Self::RealChain => "DeployCloseCli",
        }
    }

    /// Human label for the announcement line the drivers and tests read.
    fn label(self) -> &'static str {
        match self {
            Self::MockDevnet => "devnet-mock",
            Self::RealChain => "real-chain",
        }
    }
}

/// THE selection rule. Total, pure, and tested exhaustively-by-property in `deploy_plan_tests`.
///
/// SECURITY: fail-closed by construction — every chain id that is not exactly `DEVNET_CHAIN_ID`
/// maps to `RealChain`. There is no "unknown chain" arm, no default, and no way to reach
/// `MockDevnet` from an unreadable or unexpected chain id; an id we cannot read never gets here at
/// all (`rpc_chain_id` dies first).
fn settlement_deploy_plan(chain_id: u64) -> SettlementDeployPlan {
    if chain_id == DEVNET_CHAIN_ID {
        SettlementDeployPlan::MockDevnet
    } else {
        SettlementDeployPlan::RealChain
    }
}

/// Read the chain id from the RPC the caller named.
///
/// SECURITY: the target chain is read from THE CHAIN, never from a flag or an env var — a
/// caller-supplied "this is devnet" claim is exactly the input an attacker would forge to get the
/// mock verifier installed on a real network. Unparseable output is a hard error: guessing (or
/// defaulting to devnet) would reintroduce the same hole through the error path.
fn rpc_chain_id(rpc: &str) -> u64 {
    let raw = cast(&["chain-id", "--rpc-url", rpc]);
    raw.trim().parse::<u64>().unwrap_or_else(|e| {
        die(format!(
            "cannot read the chain id from {rpc} ({e}; got {:?}) — REFUSING to guess. \
             `deploy-settlement` picks the deploy script from the chain id, and the wrong pick on \
             a real chain installs an always-true mock verifier.",
            raw.trim()
        ))
    })
}

/// Deploy (or refuse to deploy) the settlement stack for this channel on the chain `rpc` points at.
///
/// The script is chosen from the RPC's OWN chain id (`settlement_deploy_plan`), not from an
/// argument: anvil keeps the mock-verifier stack it has always used, every other chain gets the
/// real-VK `DeployCloseCli.s.sol` path with a full precondition check. Usage:
///   channel_member deploy-settlement <rpc_url>
fn cmd_deploy_settlement(args: &[String]) {
    let rpc = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| die("deploy-settlement needs <rpc_url>"));

    let chain_id = rpc_chain_id(&rpc);
    let plan = settlement_deploy_plan(chain_id);
    // Observable BEFORE anything is written or broadcast: an operator (and the regression tests)
    // can see which stack this run is about to install.
    eprintln!(
        "[deploy-settlement] chain id {chain_id} → plan: {} ({})",
        plan.label(),
        plan.script()
    );
    match plan {
        SettlementDeployPlan::MockDevnet => deploy_settlement_devnet(&rpc, chain_id),
        SettlementDeployPlan::RealChain => deploy_settlement_real(&rpc, chain_id),
    }
}

/// THE registration record the settlement deploy scripts read (`pw_reg.json`,
/// `cli_reg_record.json`), as a value. ONE producer, so the two commands that stage a record cannot
/// drift.
///
/// SECURITY (Option B — why there are TWO delegate-count fields, and why neither is named
/// `delegate_count`): a registration record feeds two structurally different consumers, and a
/// single field feeding both is precisely the defect this shape exists to prevent.
///
///   * `reg_delegate_count` — the L1 REGISTRATION RECORD's count. ALWAYS 0. L1 registration is
///     cosigners-only: `ChannelRegStepCircuit` CONSTRAINS the `delegate_count` limb to zero
///     (`assert_zero` in `ChannelRegStepTarget::new`), so a registration transaction carrying a
///     nonzero one is UNPROVABLE — the reg-chain step can never fold it and the channel is stuck in
///     the validity chain. Independently, the proving side has always built this preimage
///     cosigner-only (`wallet_core::build_channel_withdrawal`), so a delegate-bearing registration
///     never matched the proof either. `deploy-settlement`'s devnet path used to pass the LIVE
///     snapshot count here (`wallet-live-work/chN/channel_snapshot.json` carries delegates), which
///     is the conflation this function removes.
///   * `active_delegate_count` — the LIVE count frozen by the `ChannelSettlementManager`. Close PI
///     limb 94 must equal this count, and the full participant identity below is committed by one
///     immutable Merkle root. Delegates prove their `(slot, pk_g, recipient)` leaf when requesting
///     a unilateral close; they are intentionally not expanded into deployment-time SSTOREs.
///
/// The four arrays carry the ACTIVE participants, MEMBERS FIRST (`0..member_count`) then delegates
/// (`member_count..member_count + active_delegate_count`). `RegRecordLib.sol` — the single reader
/// on the Solidity side — hands `registerChannel` the leading cosigner slice with a CONSTANT zero
/// delegate count, and hands the manager the whole set with `active_delegate_count`.
fn settlement_participant_root(pk_gs: &[String], recipients: &[String]) -> Bytes32 {
    const LEAF_DOMAIN: [u8; 4] = *b"IMPR";
    const NODE_DOMAIN: [u8; 4] = *b"IMPN";
    assert_eq!(pk_gs.len(), recipients.len());
    assert!(pk_gs.len() <= MAX_CHANNEL_MEMBERS);

    let mut nodes = vec![[0u8; 32]; MAX_CHANNEL_MEMBERS];
    for (slot, (pk_g_hex, recipient_hex)) in pk_gs.iter().zip(recipients).enumerate() {
        let pk_g = Bytes32::from_hex(pk_g_hex)
            .unwrap_or_else(|e| die(format!("participant slot {slot} pk_g: {e:?}")));
        let recipient = Address::from_hex(recipient_hex)
            .unwrap_or_else(|e| die(format!("participant slot {slot} recipient: {e:?}")));
        if pk_g == Bytes32::default() || recipient == Address::default() {
            die(format!(
                "participant slot {slot} has a zero pk_g or recipient"
            ));
        }
        let mut preimage = Vec::with_capacity(4 + 2 + 32 + 20);
        preimage.extend_from_slice(&LEAF_DOMAIN);
        preimage.extend_from_slice(&(slot as u16).to_be_bytes());
        preimage.extend_from_slice(&pk_g.to_bytes_be());
        preimage.extend_from_slice(&recipient.to_bytes_be());
        nodes[slot] = keccak_hash::keccak(preimage).0;
    }
    let mut width = MAX_CHANNEL_MEMBERS;
    while width > 1 {
        for i in (0..width).step_by(2) {
            let mut preimage = Vec::with_capacity(68);
            preimage.extend_from_slice(&NODE_DOMAIN);
            preimage.extend_from_slice(&nodes[i]);
            preimage.extend_from_slice(&nodes[i + 1]);
            nodes[i >> 1] = keccak_hash::keccak(preimage).0;
        }
        width >>= 1;
    }
    Bytes32::from_bytes_be(&nodes[0]).expect("32-byte participant root")
}

fn settlement_reg_json(
    channel_id: u32,
    member_count: usize,
    active_delegate_count: usize,
    pk_gs: &[String],
    pk_bs: &[String],
    regev_pk_digests: &[String],
    recipients: &[String],
) -> serde_json::Value {
    let active = member_count + active_delegate_count;
    assert!(
        pk_gs.len() == active
            && pk_bs.len() == active
            && regev_pk_digests.len() == active
            && recipients.len() == active,
        "settlement_reg_json: the arrays must hold member_count + active_delegate_count = {active} \
         entries (members first), got {}/{}/{}/{}",
        pk_gs.len(),
        pk_bs.len(),
        regev_pk_digests.len(),
        recipients.len()
    );
    assert!(
        active <= MAX_CHANNEL_MEMBERS,
        "active participants exceed 1024"
    );
    let participant_root = settlement_participant_root(pk_gs, recipients);
    serde_json::json!({
        "channel_id": channel_id,
        "bp_member_slot": BP_SLOT,
        "member_count": member_count,
        // SECURITY: a LITERAL zero, never a variable. See the doc comment above.
        "reg_delegate_count": 0,
        "active_delegate_count": active_delegate_count,
        "participant_root": participant_root.to_hex(),
        "member_pk_gs": pk_gs,
        "member_pk_bs": pk_bs,
        "regev_pk_digests": regev_pk_digests,
        "recipients": recipients,
    })
}

/// WHAT THESE TESTS ARE FOR (security, not mechanics). The registration record is read by three
/// deploy scripts, and until now ONE `delegate_count` field fed both the L1 registration and the
/// settlement manager. Each direction of that conflation is a distinct defect, so there is one test
/// per direction — a single test asserting "the two agree" would pass for either broken value.
#[cfg(test)]
mod settlement_reg_record_tests {
    use super::*;

    /// A record for a channel with `m` cosigners and `d` LIVE delegates.
    fn sample(m: usize, d: usize) -> serde_json::Value {
        let n = m + d;
        let hex = |tag: &str, i: usize| format!("0x{tag}{i:063x}");
        let pk_gs: Vec<String> = (0..n).map(|i| hex("a", i)).collect();
        let pk_bs: Vec<String> = (0..n).map(|i| hex("b", i)).collect();
        let regev: Vec<String> = (0..n).map(|i| hex("c", i)).collect();
        let recipients: Vec<String> = (0..n)
            .map(|i| format!("0x{:040x}", 0x4444_0000 + i))
            .collect();
        settlement_reg_json(7, m, d, &pk_gs, &pk_bs, &regev, &recipients)
    }

    /// DIRECTION 1 — the registration side must stay ZERO even when the live channel has delegates.
    ///
    /// SECURITY: `ChannelRegStepCircuit` constrains the registration record's `delegate_count` limb
    /// to zero, so a nonzero value here produces an L1 registration NO reg-chain step can fold: the
    /// channel becomes unprovable in the validity chain (and never matched the cosigner-only
    /// preimage `build_channel_withdrawal` proves against in the first place). The live counts
    /// below are the wallet demo's own (`wallet-live-work/ch7` runs with 2 delegates), which is
    /// exactly the input that used to leak through.
    #[test]
    fn registration_delegate_count_is_always_zero() {
        for (m, d) in [(3usize, 0usize), (3, 1), (3, 2), (2, 14), (16, 0)] {
            let reg = sample(m, d);
            assert_eq!(
                reg["reg_delegate_count"], 0,
                "the L1 registration record must be cosigner-only (member_count={m}, live \
                 delegates={d}); a nonzero registration is unprovable by channel_reg_step"
            );
            assert_eq!(
                reg["member_count"], m,
                "member_count must be the cosigner count, unaffected by delegates"
            );
            // The legacy AMBIGUOUS field must be gone: a reader that still asks for it must fail
            // loudly (`vm.parseJsonUint` reverts) instead of silently reading one count for both.
            assert!(
                reg.get("delegate_count").is_none(),
                "the ambiguous `delegate_count` key must not come back — it is the conflation"
            );
        }
    }

    /// DIRECTION 2 — the manager side must NOT be zeroed to match the registration.
    ///
    /// SECURITY: `active_delegate_count` is an exact frozen close-PI count and contributes to the
    /// immutable participant-root active prefix. Lowering it to zero would authenticate a
    /// different participant set — the exact "fix by weakening a check" this test rejects.
    #[test]
    fn manager_delegate_count_keeps_the_live_value() {
        for (m, d) in [(3usize, 1usize), (3, 2), (2, 14)] {
            let reg = sample(m, d);
            assert_eq!(
                reg["active_delegate_count"], d,
                "the manager's delegate count must stay the exact LIVE frozen count, not the \
                 registration's zero"
            );
            // ...and the delegate key material must still be in the record so RegRecordLib can
            // recompute the authenticated participant root. Solidity stores only the root/count,
            // avoiding O(1024) constructor SSTOREs.
            assert_eq!(
                reg["member_pk_gs"].as_array().map(|a| a.len()),
                Some(m + d),
                "the arrays must carry the full ACTIVE set (members first, then delegates)"
            );
            assert_eq!(reg["recipients"].as_array().map(|a| a.len()), Some(m + d));
        }
    }

    /// The two counts are INDEPENDENT fields, not one value written twice: a record with delegates
    /// must show them disagreeing. If a future edit re-derives one from the other, this fails.
    #[test]
    fn the_two_counts_are_not_the_same_field() {
        let reg = sample(3, 2);
        assert_ne!(
            reg["reg_delegate_count"], reg["active_delegate_count"],
            "a delegate-bearing channel must register 0 while the manager keeps 2"
        );
    }
}

fn staged_settlement_identity(reg: &serde_json::Value) -> (Bytes32, u16) {
    let root = reg["participant_root"]
        .as_str()
        .and_then(|s| Bytes32::from_hex(s).ok())
        .unwrap_or_else(|| die("staged settlement record has no valid participant_root"));
    let count = reg["member_count"]
        .as_u64()
        .and_then(|m| reg["active_delegate_count"].as_u64().map(|d| m + d))
        .and_then(|n| u16::try_from(n).ok())
        .unwrap_or_else(|| die("staged settlement record has an invalid participant count"));
    (root, count)
}

/// Phase 1: persist the irreversible delegate-join freeze BEFORE any deployment broadcast.  A
/// failed or interrupted deployment conservatively leaves the channel frozen.  A retry may resume
/// only this exact snapshot/root/count/rollup identity; it can never deploy a newer join set.
fn prepare_settlement_binding(state: &mut CliState, reg: &serde_json::Value, rollup: &str) {
    let (participant_root, participant_count) = staged_settlement_identity(reg);
    let expected_digest = state.snapshot.state.digest;
    if let Some(existing) = &state.settlement_binding {
        let same = existing.channel_id == channel_id_env()
            && existing.snapshot_state_digest == expected_digest
            && existing.participant_root == participant_root
            && existing.participant_count == participant_count
            && strip0x(&existing.rollup) == strip0x(rollup);
        if !same {
            die(format!(
                "settlement PREPARED identity mismatch: cli_state freezes root {} / state {} / \
                 count {} / rollup {}, while this run proposes root {} / state {} / count {} / \
                 rollup {}. Refusing a different participant set after the crash boundary.",
                existing.participant_root,
                existing.snapshot_state_digest,
                existing.participant_count,
                existing.rollup,
                participant_root,
                expected_digest,
                participant_count,
                rollup,
            ));
        }
        if existing.status == SettlementBindingStatus::Active {
            die("settlement binding is already ACTIVE in cli_state.json");
        }
        eprintln!(
            "[deploy-settlement] resuming the identical fsynced PREPARED participant identity"
        );
        return;
    }
    state.settlement_binding = Some(SettlementBinding {
        status: SettlementBindingStatus::Prepared,
        channel_id: channel_id_env(),
        snapshot_state_digest: expected_digest,
        participant_root,
        participant_count,
        rollup: rollup.to_string(),
        verifier: None,
        manager: None,
        materializer: None,
        deployment: None,
        activation_checkpoint: None,
        runtime_code_hashes: None,
    });
    save_state(state);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RealSettlementDeployMode {
    Fresh,
    Resume,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SettlementBroadcastAddresses {
    mle_verifier: String,
    verifier: String,
    manager: String,
    materializer: String,
    registration_tx_hash: Bytes32,
    registration_calldata_hash: Bytes32,
    registration_nonce: u64,
}

const SETTLEMENT_BROADCAST_ARTIFACT_MAX_BYTES: u64 = 8 * 1024 * 1024;
const PUBLIC_CLOSE_MANIFEST_MAX_BYTES: u64 = 256 * 1024;
const CLOSE_BACKING_MLE_MAX_BYTES: u64 = 32 * 1024 * 1024;
const CLOSE_BACKING_PUBLIC_INPUTS_MAX_BYTES: u64 = 64 * 1024;
const CLOSE_BACKING_PUBLIC_INPUTS: usize = 26;
const CLOSE_BACKING_MLE_PROTOCOL_VERSION: u64 = 1;
const CLOSE_BACKING_MLE_CONSTITUENT_FIELDS: [&str; 6] = [
    "preprocessedIndividualEvals",
    "witnessIndividualEvals",
    "inverseHelpersEvalsAtRInv",
    "inverseHelpersEvalsAtRH",
    "preprocessedIndividualEvalsAtRGateV2",
    "witnessIndividualEvalsAtRGateV2",
];
const CLOSE_BACKING_STAGED_FILES: [&str; 3] = [
    STAGED_CLOSE_BACKING_MANIFEST,
    STAGED_CLOSE_BACKING_MLE,
    STAGED_CLOSE_BACKING_PUBLIC_INPUTS,
];
const SETTLEMENT_PLAN_DOMAIN: &[u8] = b"INTMAX_SETTLEMENT_DEPLOY_PLAN_V1";

#[derive(Debug)]
struct ValidatedCloseBackingBundle {
    manifest: Vec<u8>,
    mle: Vec<u8>,
    public_inputs: Vec<u8>,
}

fn read_bounded_regular_file(path: &Path, maximum: u64, what: &str) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("stat {what} {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "{what} {} is not a regular non-symlink file",
            path.display()
        ));
    }
    if metadata.len() > maximum {
        return Err(format!(
            "{what} {} is {} bytes, above the {maximum}-byte limit",
            path.display(),
            metadata.len()
        ));
    }
    let bytes =
        fs::read(path).map_err(|error| format!("read {what} {}: {error}", path.display()))?;
    if bytes.len() as u64 > maximum {
        return Err(format!(
            "{what} {} changed while reading and now exceeds the {maximum}-byte limit",
            path.display()
        ));
    }
    Ok(bytes)
}

fn json_required_u64(value: &serde_json::Value, field: &str) -> Result<u64, String> {
    value
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("JSON field `{field}` is missing or not a canonical u64"))
}

fn json_required_string<'a>(value: &'a serde_json::Value, field: &str) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("public-close manifest `{field}` is missing or not a string"))
}

fn canonical_hex(value: &str, bytes: usize, what: &str) -> Result<String, String> {
    let body = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    if body.len() != bytes * 2 || !body.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{what} must be exactly {bytes} bytes of hex"));
    }
    Ok(format!("0x{}", body.to_ascii_lowercase()))
}

fn close_backing_sha256(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(Sha256::digest(bytes)))
}

fn close_backing_public_input(value: &serde_json::Value, index: usize) -> Result<u64, String> {
    match value {
        serde_json::Value::String(value) => value.parse::<u64>().map_err(|_| {
            format!("CloseAssetBacking public input {index} is not a canonical decimal u64")
        }),
        serde_json::Value::Number(value) => value.as_u64().ok_or_else(|| {
            format!("CloseAssetBacking public input {index} is not a canonical u64")
        }),
        _ => Err(format!(
            "CloseAssetBacking public input {index} is neither a decimal string nor an integer"
        )),
    }
}

fn parse_close_backing_public_inputs(
    value: &serde_json::Value,
    what: &str,
) -> Result<Vec<u64>, String> {
    let values = value
        .as_array()
        .ok_or_else(|| format!("{what} must be a JSON array"))?;
    if values.len() != CLOSE_BACKING_PUBLIC_INPUTS {
        return Err(format!(
            "{what} has {} limbs; the CloseAssetBacking circuit requires exactly {CLOSE_BACKING_PUBLIC_INPUTS}",
            values.len()
        ));
    }
    let parsed = values
        .iter()
        .enumerate()
        .map(|(index, value)| close_backing_public_input(value, index))
        .collect::<Result<Vec<_>, _>>()?;
    if parsed[..25].iter().any(|value| *value > u32::MAX as u64) {
        return Err(format!("{what} contains a non-canonical u32 limb"));
    }
    if parsed[25] >= (1u64 << 63) {
        return Err(format!("{what} anchor block is not a canonical u63"));
    }
    Ok(parsed)
}

fn close_backing_limb_bytes32(inputs: &[u64], offset: usize) -> String {
    let mut bytes = [0u8; 32];
    for index in 0..8 {
        bytes[index * 4..index * 4 + 4]
            .copy_from_slice(&(inputs[offset + index] as u32).to_be_bytes());
    }
    format!("0x{}", hex::encode(bytes))
}

/// Enforce the same release envelope as the public publisher. These fields are deliberately not
/// part of Solidity's proof tuple, so the deployment driver must refuse a legacy or width-mismatched
/// artifact before its VK becomes the materializer's immutable set-once key.
fn validate_close_backing_mle_release_envelope(
    mle: &serde_json::Value,
) -> Result<(), String> {
    if json_required_u64(mle, "protocolVersion")? != CLOSE_BACKING_MLE_PROTOCOL_VERSION {
        return Err(format!(
            "backing MLE protocolVersion is not release version {CLOSE_BACKING_MLE_PROTOCOL_VERSION}"
        ));
    }
    let mut constituent_width = 2usize;
    for field in CLOSE_BACKING_MLE_CONSTITUENT_FIELDS {
        let length = mle
            .get(field)
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| format!("backing MLE `{field}` is missing or not an array"))?
            .len();
        constituent_width = constituent_width.max(length);
    }
    if json_required_u64(mle, "constituentWidth")?
        != u64::try_from(constituent_width)
            .map_err(|_| "backing MLE constituent width does not fit u64".to_string())?
    {
        return Err(format!(
            "backing MLE constituentWidth does not equal canonical width {constituent_width}"
        ));
    }
    Ok(())
}

fn validate_close_backing_bundle_bytes(
    manifest_bytes: &[u8],
    mle_bytes: &[u8],
    public_input_bytes: &[u8],
    chain_id: u64,
    rollup: &str,
    channel_id: u32,
    balance_vd_sha256: &str,
) -> Result<(), String> {
    let manifest: serde_json::Value = serde_json::from_slice(manifest_bytes)
        .map_err(|error| format!("parse public-close manifest: {error}"))?;
    if !manifest.is_object() {
        return Err("public-close manifest must be a JSON object".to_string());
    }
    if json_required_u64(&manifest, "schemaVersion")? != 2 {
        return Err("public-close manifest schemaVersion must be 2".to_string());
    }
    if json_required_u64(&manifest, "chainId")? != chain_id {
        return Err("public-close manifest belongs to a different chain".to_string());
    }
    if canonical_hex(
        json_required_string(&manifest, "rollup")?,
        20,
        "manifest rollup",
    )? != canonical_hex(rollup, 20, "backing rollup")?
    {
        return Err("public-close manifest belongs to a different rollup".to_string());
    }
    if json_required_u64(&manifest, "channelId")? != u64::from(channel_id) {
        return Err("public-close manifest belongs to a different channel".to_string());
    }
    if manifest
        .get("selfVerified")
        .and_then(serde_json::Value::as_bool)
        != Some(true)
        || manifest
            .get("keyMaterialConsumed")
            .and_then(serde_json::Value::as_bool)
            != Some(false)
    {
        return Err(
            "public-close manifest must be self-verified and key-material independent".to_string(),
        );
    }
    if canonical_hex(
        json_required_string(&manifest, "balanceVerifierDataSha256")?,
        32,
        "manifest balance verifier-data SHA-256",
    )? != canonical_hex(balance_vd_sha256, 32, "local balance verifier-data SHA-256")?
    {
        return Err(
            "public-close bundle was built against different Balance verifier data".to_string(),
        );
    }
    if json_required_string(&manifest, "backingMleFile")? != "backing_mle.json"
        || json_required_string(&manifest, "backingPublicInputsFile")?
            != "backing_public_inputs.json"
    {
        return Err("public-close manifest names unexpected backing files".to_string());
    }
    if json_required_u64(&manifest, "backingMleBytes")? != mle_bytes.len() as u64
        || canonical_hex(
            json_required_string(&manifest, "backingMleSha256")?,
            32,
            "manifest backing MLE SHA-256",
        )? != close_backing_sha256(mle_bytes)
    {
        return Err("backing_mle.json does not match its manifest length/SHA-256".to_string());
    }
    if canonical_hex(
        json_required_string(&manifest, "backingPublicInputsSha256")?,
        32,
        "manifest backing public-input SHA-256",
    )? != close_backing_sha256(public_input_bytes)
    {
        return Err("backing_public_inputs.json does not match its manifest SHA-256".to_string());
    }
    if json_required_u64(&manifest, "backingPublicInputCount")?
        != CLOSE_BACKING_PUBLIC_INPUTS as u64
    {
        return Err("manifest does not declare the exact 26-limb backing statement".to_string());
    }

    let mle: serde_json::Value = serde_json::from_slice(mle_bytes)
        .map_err(|error| format!("parse backing_mle.json: {error}"))?;
    validate_close_backing_mle_release_envelope(&mle)?;
    if json_required_u64(&mle, "degreeBits")? == 0 {
        return Err("backing MLE has a disabled degreeBits=0 VK".to_string());
    }
    let mle_inputs = parse_close_backing_public_inputs(
        mle.get("publicInputs")
            .ok_or_else(|| "backing MLE has no publicInputs".to_string())?,
        "backing MLE publicInputs",
    )?;
    let public_input_json: serde_json::Value = serde_json::from_slice(public_input_bytes)
        .map_err(|error| format!("parse backing_public_inputs.json: {error}"))?;
    let separate_inputs =
        parse_close_backing_public_inputs(&public_input_json, "backing_public_inputs.json")?;
    if mle_inputs != separate_inputs {
        return Err(
            "backing MLE and separate public-input file describe different statements".to_string(),
        );
    }
    if mle_inputs[0] != u64::from(channel_id) {
        return Err("backing MLE public inputs belong to a different channel".to_string());
    }
    let declared_root = canonical_hex(
        json_required_string(&manifest, "backingFinalizedExtendedStateCommitment")?,
        32,
        "manifest backing finalized root",
    )?;
    if close_backing_limb_bytes32(&mle_inputs, 17) != declared_root {
        return Err("backing MLE finalized root differs from its manifest".to_string());
    }
    if json_required_u64(&manifest, "backingAnchorBlockNumber")? != mle_inputs[25] {
        return Err("backing MLE anchor block differs from its manifest".to_string());
    }
    Ok(())
}

fn load_close_backing_bundle(
    bundle_dir: &Path,
    chain_id: u64,
    rollup: &str,
    channel_id: u32,
    balance_vd_sha256: &str,
) -> Result<ValidatedCloseBackingBundle, String> {
    let metadata = fs::symlink_metadata(bundle_dir)
        .map_err(|error| format!("stat public-close bundle {}: {error}", bundle_dir.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "public-close bundle {} is not a real non-symlink directory",
            bundle_dir.display()
        ));
    }
    let manifest = read_bounded_regular_file(
        &bundle_dir.join("public_close_manifest.json"),
        PUBLIC_CLOSE_MANIFEST_MAX_BYTES,
        "public-close manifest",
    )?;
    let mle = read_bounded_regular_file(
        &bundle_dir.join("backing_mle.json"),
        CLOSE_BACKING_MLE_MAX_BYTES,
        "CloseAssetBacking MLE artifact",
    )?;
    let public_inputs = read_bounded_regular_file(
        &bundle_dir.join("backing_public_inputs.json"),
        CLOSE_BACKING_PUBLIC_INPUTS_MAX_BYTES,
        "CloseAssetBacking public inputs",
    )?;
    validate_close_backing_bundle_bytes(
        &manifest,
        &mle,
        &public_inputs,
        chain_id,
        rollup,
        channel_id,
        balance_vd_sha256,
    )?;
    Ok(ValidatedCloseBackingBundle {
        manifest,
        mle,
        public_inputs,
    })
}

/// Stage one exact, self-verified CloseAssetBacking artifact before the PREPARED deployment
/// boundary. A retry never imports a new bundle: it revalidates the already plan-digested files.
fn stage_close_backing_bundle(
    contracts_dir: &Path,
    resume_prepared: bool,
    chain_id: u64,
    rollup: &str,
    channel_id: u32,
) {
    secure_private_path(Path::new(BALANCE_VD_FILE));
    let balance_vd = fs::read(BALANCE_VD_FILE)
        .unwrap_or_else(|error| die(format!("read {BALANCE_VD_FILE}: {error}")));
    let balance_vd_sha256 = close_backing_sha256(&balance_vd);
    let data_dir = contracts_dir.join("test/data");
    let staged_manifest = data_dir.join(STAGED_CLOSE_BACKING_MANIFEST);
    let staged_mle = data_dir.join(STAGED_CLOSE_BACKING_MLE);
    let staged_public_inputs = data_dir.join(STAGED_CLOSE_BACKING_PUBLIC_INPUTS);

    if !resume_prepared {
        let bundle = std::env::var(PUBLIC_CLOSE_BUNDLE_ENV).unwrap_or_else(|_| {
            die(format!(
                "production deploy-settlement requires {PUBLIC_CLOSE_BUNDLE_ENV}=<directory> \
                 naming a self-verified `public_close_prover --output-dir` bundle. The backing VK \
                 cannot be inferred from or replaced by close_intent_mle.json."
            ))
        });
        let bundle = load_close_backing_bundle(
            Path::new(&bundle),
            chain_id,
            rollup,
            channel_id,
            &balance_vd_sha256,
        )
        .unwrap_or_else(|error| die(format!("invalid {PUBLIC_CLOSE_BUNDLE_ENV}: {error}")));
        // Manifest is the commit marker: a crash before it lands leaves no apparently complete
        // staged set, and no PREPARED state has been written yet.
        write_private_bytes_at(&staged_mle, &bundle.mle);
        write_private_bytes_at(&staged_public_inputs, &bundle.public_inputs);
        write_private_bytes_at(&staged_manifest, &bundle.manifest);
    }

    let staged = ValidatedCloseBackingBundle {
        manifest: read_bounded_regular_file(
            &staged_manifest,
            PUBLIC_CLOSE_MANIFEST_MAX_BYTES,
            "staged public-close manifest",
        )
        .unwrap_or_else(|error| die(error)),
        mle: read_bounded_regular_file(
            &staged_mle,
            CLOSE_BACKING_MLE_MAX_BYTES,
            "staged CloseAssetBacking MLE artifact",
        )
        .unwrap_or_else(|error| die(error)),
        public_inputs: read_bounded_regular_file(
            &staged_public_inputs,
            CLOSE_BACKING_PUBLIC_INPUTS_MAX_BYTES,
            "staged CloseAssetBacking public inputs",
        )
        .unwrap_or_else(|error| die(error)),
    };
    validate_close_backing_bundle_bytes(
        &staged.manifest,
        &staged.mle,
        &staged.public_inputs,
        chain_id,
        rollup,
        channel_id,
        &balance_vd_sha256,
    )
    .unwrap_or_else(|error| {
        die(format!(
            "staged CloseAssetBacking deployment input is invalid: {error}; refusing to deploy or resume"
        ))
    });
}

fn append_deployment_digest_field(preimage: &mut Vec<u8>, field: &[u8]) {
    preimage.extend_from_slice(&(field.len() as u64).to_be_bytes());
    preimage.extend_from_slice(field);
}

/// Commit the PREPARED record to every local input which determines the broadcast.  This is not a
/// substitute for inspecting `run-latest.json` (done separately); it prevents a retry after an
/// upgrade or fixture replacement from silently treating a different build as the same attempt.
fn settlement_deployment_plan_digest(
    contracts_dir: &Path,
    chain_id: u64,
    broadcaster: &str,
    start_nonce: u64,
    rollup: &str,
    state_digest: Bytes32,
    reg: &serde_json::Value,
) -> Result<Bytes32, String> {
    const PLAN_FILES: [&str; 13] = [
        "foundry.toml",
        "script/DeployCloseCli.s.sol",
        "script/DeployConfig.sol",
        "script/FixtureLib.sol",
        "script/RegRecordLib.sol",
        "src/BlobKZGVerifier.sol",
        "src/ChannelSettlementManager.sol",
        "src/ChannelSettlementVerifier.sol",
        "src/CloseFundingMaterializer.sol",
        "src/IntmaxRollup.sol",
        "lib/polygon-plonky2/mle/contracts/src/MleVerifier.sol",
        "lib/polygon-plonky2/mle/contracts/src/Plonky2GateEvaluator.sol",
        "lib/polygon-plonky2/mle/contracts/src/spongefish/SpongefishWhirVerify.sol",
    ];

    let mut preimage = Vec::new();
    preimage.extend_from_slice(SETTLEMENT_PLAN_DOMAIN);
    append_deployment_digest_field(&mut preimage, &chain_id.to_be_bytes());
    append_deployment_digest_field(&mut preimage, strip0x(broadcaster).as_bytes());
    append_deployment_digest_field(&mut preimage, &start_nonce.to_be_bytes());
    append_deployment_digest_field(&mut preimage, strip0x(rollup).as_bytes());
    append_deployment_digest_field(&mut preimage, &state_digest.to_bytes_be());
    let reg_bytes =
        serde_json::to_vec(reg).map_err(|e| format!("serialize settlement record: {e}"))?;
    append_deployment_digest_field(&mut preimage, &reg_bytes);

    for relative in PLAN_FILES {
        let bytes = fs::read(contracts_dir.join(relative))
            .map_err(|e| format!("read settlement plan input {relative}: {e}"))?;
        append_deployment_digest_field(&mut preimage, relative.as_bytes());
        append_deployment_digest_field(&mut preimage, &bytes);
    }
    for relative in CLOSE_CLI_FIXTURES {
        let relative = format!("test/data/{relative}");
        let bytes = fs::read(contracts_dir.join(&relative))
            .map_err(|e| format!("read settlement fixture {relative}: {e}"))?;
        append_deployment_digest_field(&mut preimage, relative.as_bytes());
        append_deployment_digest_field(&mut preimage, &bytes);
    }
    for relative in CLOSE_BACKING_STAGED_FILES {
        let relative = format!("test/data/{relative}");
        let bytes = fs::read(contracts_dir.join(&relative))
            .map_err(|e| format!("read staged CloseAssetBacking input {relative}: {e}"))?;
        append_deployment_digest_field(&mut preimage, relative.as_bytes());
        append_deployment_digest_field(&mut preimage, &bytes);
    }

    Bytes32::from_bytes_be(&keccak_hash::keccak(preimage).0)
        .map_err(|e| format!("construct settlement plan digest: {e:?}"))
}

fn settlement_broadcast_artifact_relative_path(chain_id: u64) -> String {
    format!("broadcast/DeployCloseCli.s.sol/{chain_id}/run-latest.json")
}

fn expected_settlement_deployment_intent(
    contracts_dir: &Path,
    chain_id: u64,
    broadcaster: &str,
    start_nonce: u64,
    start_block: u64,
    rollup: &str,
    state_digest: Bytes32,
    reg: &serde_json::Value,
) -> Result<SettlementDeploymentIntent, String> {
    Ok(SettlementDeploymentIntent {
        chain_id,
        broadcaster: broadcaster.to_string(),
        start_nonce,
        start_block,
        broadcast_artifact_path: settlement_broadcast_artifact_relative_path(chain_id),
        plan_digest: settlement_deployment_plan_digest(
            contracts_dir,
            chain_id,
            broadcaster,
            start_nonce,
            rollup,
            state_digest,
            reg,
        )?,
    })
}

fn settlement_deploy_mode_for_intent(
    prepared_binding_exists: bool,
    existing: Option<&SettlementDeploymentIntent>,
    expected: &SettlementDeploymentIntent,
) -> Result<RealSettlementDeployMode, String> {
    match (prepared_binding_exists, existing) {
        (false, None) => Ok(RealSettlementDeployMode::Fresh),
        (true, None) => Err(
            "PREPARED settlement has no broadcast recovery identity; fresh rerun forbidden"
                .to_string(),
        ),
        (false, Some(_)) => {
            Err("deployment intent exists without a PREPARED settlement binding".to_string())
        }
        (true, Some(existing)) if existing == expected => Ok(RealSettlementDeployMode::Resume),
        (true, Some(existing)) => Err(format!(
            "persisted settlement broadcast identity {:?} does not match this run {:?}",
            existing, expected
        )),
    }
}

/// Production phase 1.  The nonce/chain/signer/artifact identity is included in the SAME fsynced
/// write that freezes joins, so there is no state in which transactions may have started but a
/// retry is still allowed to invent a new Foundry run.
fn prepare_real_settlement_binding(
    rpc: &str,
    contracts_dir: &Path,
    state: &mut CliState,
    reg: &serde_json::Value,
    rollup: &str,
    chain_id: u64,
    broadcaster: &str,
) -> RealSettlementDeployMode {
    let (participant_root, participant_count) = staged_settlement_identity(reg);
    let state_digest = state.snapshot.state.digest;

    if let Some(existing) = &state.settlement_binding {
        let same_binding = existing.channel_id == channel_id_env()
            && existing.snapshot_state_digest == state_digest
            && existing.participant_root == participant_root
            && existing.participant_count == participant_count
            && strip0x(&existing.rollup) == strip0x(rollup);
        if !same_binding {
            die(
                "settlement PREPARED identity differs from the live snapshot/rollup; refusing to \
                 resume or create a replacement deployment",
            );
        }
        if existing.status == SettlementBindingStatus::Active {
            die("settlement binding is already ACTIVE in cli_state.json");
        }
        let persisted = existing.deployment.as_ref().unwrap_or_else(|| {
            die(
                "real-chain settlement is PREPARED but has no broadcast recovery identity. \
                 Refusing a fresh forge run: transactions may already have been sent. Operator \
                 migration must reconcile the chain and the original broadcast artifact.",
            )
        });
        let expected = expected_settlement_deployment_intent(
            contracts_dir,
            chain_id,
            broadcaster,
            persisted.start_nonce,
            persisted.start_block,
            rollup,
            state_digest,
            reg,
        )
        .unwrap_or_else(|e| die(e));
        settlement_deploy_mode_for_intent(true, Some(persisted), &expected)
            .unwrap_or_else(|e| die(format!("cannot resume settlement deployment: {e}")))
    } else {
        let latest_nonce = read_account_nonce(rpc, broadcaster, "latest");
        let pending_nonce = read_account_nonce(rpc, broadcaster, "pending");
        if latest_nonce != pending_nonce {
            die(format!(
                "settlement broadcaster {broadcaster} has outstanding transactions \
                 (latest nonce {latest_nonce}, pending nonce {pending_nonce}); refusing to pin an \
                 ambiguous Foundry start nonce"
            ));
        }
        let deployment_start = read_durable_l1_checkpoint(rpc, chain_id);
        require_stable_durable_l1_checkpoint(rpc, &deployment_start);
        let deployment = expected_settlement_deployment_intent(
            contracts_dir,
            chain_id,
            broadcaster,
            latest_nonce,
            deployment_start.block_number,
            rollup,
            state_digest,
            reg,
        )
        .unwrap_or_else(|e| die(e));
        debug_assert_eq!(
            settlement_deploy_mode_for_intent(false, None, &deployment),
            Ok(RealSettlementDeployMode::Fresh)
        );
        state.settlement_binding = Some(SettlementBinding {
            status: SettlementBindingStatus::Prepared,
            channel_id: channel_id_env(),
            snapshot_state_digest: state_digest,
            participant_root,
            participant_count,
            rollup: rollup.to_string(),
            verifier: None,
            manager: None,
            materializer: None,
            deployment: Some(deployment),
            activation_checkpoint: None,
            runtime_code_hashes: None,
        });
        save_state(state);
        RealSettlementDeployMode::Fresh
    }
}

fn settlement_artifact_quantity(value: &serde_json::Value, what: &str) -> Result<u64, String> {
    if let Some(value) = value.as_u64() {
        return Ok(value);
    }
    let raw = value
        .as_str()
        .ok_or_else(|| format!("{what} is neither a JSON integer nor a quantity string"))?;
    if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|e| format!("parse {what} {raw:?}: {e}"))
    } else {
        raw.parse::<u64>()
            .map_err(|e| format!("parse {what} {raw:?}: {e}"))
    }
}

fn settlement_artifact_string<'a>(
    value: &'a serde_json::Value,
    key: &str,
    what: &str,
) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("{what} has no string field {key:?}"))
}

fn settlement_artifact_args<'a>(
    tx: &'a serde_json::Value,
    what: &str,
) -> Result<Vec<&'a str>, String> {
    tx.get("arguments")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| format!("{what} has no arguments array"))?
        .iter()
        .enumerate()
        .map(|(i, value)| {
            value
                .as_str()
                .ok_or_else(|| format!("{what} argument {i} is not a string"))
        })
        .collect()
}

fn normalize_abi_text(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .flat_map(char::to_lowercase)
        .collect()
}

fn abi_array(values: &[String]) -> String {
    format!("[{}]", values.join(","))
}

fn cast_encode_settlement_calldata(function: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new("cast")
        .arg("calldata")
        .arg(function)
        .args(args)
        .output()
        .map_err(|e| format!("start `cast calldata` for {function}: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "`cast calldata` rejected Foundry metadata for {function}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn cast_encode_settlement_constructor(args: &[&str]) -> Result<String, String> {
    const SIGNATURE: &str = "constructor(bytes4,uint8,bytes32,uint16,bytes32,uint64,uint256,uint256,address,address,address,(bytes32,address)[])";
    let output = Command::new("cast")
        .arg("abi-encode")
        .arg(SIGNATURE)
        .args(args)
        .output()
        .map_err(|e| format!("start `cast abi-encode` for settlement manager: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "`cast abi-encode` rejected manager constructor metadata: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn cast_encode_materializer_constructor(rollup: &str) -> Result<String, String> {
    const SIGNATURE: &str = "constructor(address)";
    let output = Command::new("cast")
        .arg("abi-encode")
        .arg(SIGNATURE)
        .arg(rollup)
        .output()
        .map_err(|e| format!("start `cast abi-encode` for close-funding materializer: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "`cast abi-encode` rejected close-funding materializer constructor metadata: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn validate_settlement_call_input(tx: &serde_json::Value, what: &str) -> Result<(), String> {
    let function = settlement_artifact_string(tx, "function", what)?;
    let args = settlement_artifact_args(tx, what)?;
    let expected = cast_encode_settlement_calldata(function, &args)?;
    let actual = tx
        .get("transaction")
        .and_then(|value| value.get("input"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("{what} has no transaction.input"))?;
    if strip0x(actual) != strip0x(&expected) {
        return Err(format!(
            "{what} calldata does not encode its inspected function/arguments"
        ));
    }
    Ok(())
}

fn settlement_reg_string_vec(
    reg: &serde_json::Value,
    key: &str,
    expected_len: usize,
) -> Result<Vec<String>, String> {
    let values = reg
        .get(key)
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| format!("staged record has no {key} array"))?;
    if values.len() != expected_len {
        return Err(format!(
            "staged record {key} length {} != active participant count {expected_len}",
            values.len()
        ));
    }
    values
        .iter()
        .enumerate()
        .map(|(i, value)| {
            value
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| format!("staged record {key}[{i}] is not a string"))
        })
        .collect()
}

fn settlement_artifact_contract_address(
    tx: &serde_json::Value,
    what: &str,
) -> Result<String, String> {
    let raw = settlement_artifact_string(tx, "contractAddress", what)?;
    let address = Address::from_hex(raw).map_err(|e| format!("{what} contract address: {e:?}"))?;
    if address == Address::default() {
        return Err(format!("{what} has the zero contract address"));
    }
    Ok(address.to_hex())
}

fn validate_settlement_tx_shape(
    tx: &serde_json::Value,
    expected_type: &str,
    expected_contract: &str,
    expected_function_prefix: Option<&str>,
    what: &str,
) -> Result<(), String> {
    if settlement_artifact_string(tx, "transactionType", what)? != expected_type {
        return Err(format!("{what} is not a {expected_type} transaction"));
    }
    if settlement_artifact_string(tx, "contractName", what)? != expected_contract {
        return Err(format!("{what} is not for {expected_contract}"));
    }
    if let Some(prefix) = expected_function_prefix {
        let function = settlement_artifact_string(tx, "function", what)?;
        if !function.starts_with(prefix) || !function.ends_with(')') {
            return Err(format!("{what} has unexpected function {function:?}"));
        }
    }
    Ok(())
}

fn validate_settlement_call_target(
    tx: &serde_json::Value,
    expected: &str,
    what: &str,
) -> Result<(), String> {
    let transaction = tx
        .get("transaction")
        .ok_or_else(|| format!("{what} has no transaction object"))?;
    let to = settlement_artifact_string(transaction, "to", what)?;
    let annotated = settlement_artifact_string(tx, "contractAddress", what)?;
    if strip0x(to) != strip0x(expected) || strip0x(annotated) != strip0x(expected) {
        return Err(format!(
            "{what} targets to={to}, contractAddress={annotated}; expected {expected}"
        ));
    }
    Ok(())
}

/// Validate the complete semantic transaction plan and also re-encode every CALL from Foundry's
/// inspected metadata.  This closes the dangerous gap where a forged/stale JSON annotation says
/// "register this channel" while `transaction.input` actually registers another one.
fn validate_settlement_broadcast_value(
    artifact: &serde_json::Value,
    intent: &SettlementDeploymentIntent,
    reg: &serde_json::Value,
    rollup: &str,
) -> Result<SettlementBroadcastAddresses, String> {
    let artifact_chain = artifact
        .get("chain")
        .ok_or_else(|| "broadcast artifact has no chain".to_string())?;
    if settlement_artifact_quantity(artifact_chain, "broadcast chain")? != intent.chain_id {
        return Err(format!(
            "broadcast artifact chain does not match pinned chain {}",
            intent.chain_id
        ));
    }
    let transactions = artifact
        .get("transactions")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "broadcast artifact has no transactions array".to_string())?;

    for (i, tx) in transactions.iter().enumerate() {
        let what = format!("broadcast transaction {i}");
        let transaction = tx
            .get("transaction")
            .ok_or_else(|| format!("{what} has no transaction object"))?;
        let from = settlement_artifact_string(transaction, "from", &what)?;
        if strip0x(from) != strip0x(&intent.broadcaster) {
            return Err(format!(
                "{what} sender {from} != pinned broadcaster {}",
                intent.broadcaster
            ));
        }
        let nonce = transaction
            .get("nonce")
            .ok_or_else(|| format!("{what} has no nonce"))?;
        let nonce = settlement_artifact_quantity(nonce, &format!("{what} nonce"))?;
        let expected_nonce = intent
            .start_nonce
            .checked_add(i as u64)
            .ok_or_else(|| "broadcast nonce overflow".to_string())?;
        if nonce != expected_nonce {
            return Err(format!(
                "{what} nonce {nonce} != pinned contiguous nonce {expected_nonce}"
            ));
        }
        let tx_chain = transaction
            .get("chainId")
            .ok_or_else(|| format!("{what} has no chainId"))?;
        if settlement_artifact_quantity(tx_chain, &format!("{what} chainId"))? != intent.chain_id {
            return Err(format!("{what} chainId differs from the pinned chain"));
        }
        if transaction
            .get("value")
            .map(|value| settlement_artifact_quantity(value, &format!("{what} value")))
            .transpose()?
            .unwrap_or(0)
            != 0
        {
            return Err(format!("{what} unexpectedly transfers native value"));
        }
    }

    // Solidity libraries may already exist at their deterministic CREATE2 addresses, so Foundry
    // may emit zero, one or both.  No other prelude transaction is permitted.
    let mut core_start = 0usize;
    let mut libraries = HashSet::new();
    while core_start < transactions.len()
        && transactions[core_start]["transactionType"].as_str() == Some("CREATE2")
    {
        let tx = &transactions[core_start];
        let what = format!("broadcast transaction {core_start}");
        let name = settlement_artifact_string(tx, "contractName", &what)?;
        if !matches!(name, "Plonky2GateEvaluator" | "SpongefishWhirVerify")
            || !libraries.insert(name)
        {
            return Err(format!(
                "{what} is an unexpected/duplicate CREATE2 library {name}"
            ));
        }
        let transaction = tx
            .get("transaction")
            .ok_or_else(|| format!("{what} has no transaction object"))?;
        let to = settlement_artifact_string(transaction, "to", &what)?;
        if strip0x(to) != "4e59b44847b379578588920ca78fbf26c0b4956c" {
            return Err(format!(
                "{what} does not use the canonical CREATE2 deployer"
            ));
        }
        settlement_artifact_contract_address(tx, &what)?;
        core_start += 1;
    }
    const CORE_TRANSACTION_COUNT: usize = 11;
    if transactions.len() != core_start + CORE_TRANSACTION_COUNT {
        return Err(format!(
            "broadcast artifact has {} core transactions after {core_start} library creates; \
             expected exactly {CORE_TRANSACTION_COUNT}",
            transactions.len().saturating_sub(core_start)
        ));
    }
    let core = &transactions[core_start..];

    validate_settlement_tx_shape(
        &core[0],
        "CREATE",
        "MleVerifier",
        None,
        "MleVerifier deploy",
    )?;
    let mle = settlement_artifact_contract_address(&core[0], "MleVerifier deploy")?;
    validate_settlement_tx_shape(
        &core[1],
        "CREATE",
        "CloseFundingMaterializer",
        None,
        "close-funding materializer deploy",
    )?;
    let materializer =
        settlement_artifact_contract_address(&core[1], "close-funding materializer deploy")?;
    let materializer_args =
        settlement_artifact_args(&core[1], "close-funding materializer deploy")?;
    if materializer_args.len() != 1 || strip0x(materializer_args[0]) != strip0x(rollup) {
        return Err(
            "CloseFundingMaterializer constructor is not bound to the existing rollup".to_string(),
        );
    }
    let encoded_materializer_constructor = cast_encode_materializer_constructor(rollup)?;
    let materializer_input = core[1]
        .get("transaction")
        .and_then(|value| value.get("input"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "close-funding materializer deploy has no transaction.input".to_string())?;
    if !strip0x(materializer_input).ends_with(&strip0x(&encoded_materializer_constructor)) {
        return Err(
            "close-funding materializer creation input does not end in its inspected rollup constructor ABI"
                .to_string(),
        );
    }
    let backing_initializer = &core[2];
    validate_settlement_tx_shape(
        backing_initializer,
        "CALL",
        "CloseFundingMaterializer",
        Some("initializeBackingVk("),
        "CloseAssetBacking VK initializer",
    )?;
    validate_settlement_call_target(
        backing_initializer,
        &materializer,
        "CloseAssetBacking VK initializer",
    )?;
    let backing_args =
        settlement_artifact_args(backing_initializer, "CloseAssetBacking VK initializer")?;
    if backing_args
        .first()
        .is_none_or(|arg| strip0x(arg) != strip0x(&mle))
    {
        return Err(
            "CloseAssetBacking VK is not bound to the MleVerifier created by this run".to_string(),
        );
    }
    validate_settlement_call_input(backing_initializer, "CloseAssetBacking VK initializer")?;
    validate_settlement_tx_shape(
        &core[3],
        "CREATE",
        "ChannelSettlementVerifier",
        None,
        "settlement verifier deploy",
    )?;
    let verifier = settlement_artifact_contract_address(&core[3], "settlement verifier deploy")?;

    for (offset, function) in [
        "initializeCloseVk(",
        "initializeWithdrawalClaimVk(",
        "initializePostCloseClaimVk(",
        "initializeCancelCloseVk(",
    ]
    .iter()
    .enumerate()
    {
        let tx = &core[4 + offset];
        let what = format!("settlement verifier initializer {function}");
        validate_settlement_tx_shape(
            tx,
            "CALL",
            "ChannelSettlementVerifier",
            Some(function),
            &what,
        )?;
        validate_settlement_call_target(tx, &verifier, &what)?;
        let args = settlement_artifact_args(tx, &what)?;
        if args.first().is_none_or(|arg| strip0x(arg) != strip0x(&mle)) {
            return Err(format!(
                "{what} is not bound to the MleVerifier created by this run"
            ));
        }
        validate_settlement_call_input(tx, &what)?;
    }

    let member_count = reg["member_count"]
        .as_u64()
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| "staged record member_count is invalid".to_string())?;
    let delegate_count = reg["active_delegate_count"]
        .as_u64()
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| "staged record active_delegate_count is invalid".to_string())?;
    let active_count = member_count
        .checked_add(delegate_count)
        .ok_or_else(|| "staged participant count overflow".to_string())?;
    let pk_gs = settlement_reg_string_vec(reg, "member_pk_gs", active_count)?;
    let pk_bs = settlement_reg_string_vec(reg, "member_pk_bs", active_count)?;
    let regev = settlement_reg_string_vec(reg, "regev_pk_digests", active_count)?;
    let recipients = settlement_reg_string_vec(reg, "recipients", active_count)?;
    if member_count == 0 || BP_SLOT as usize >= member_count {
        return Err("staged record has no valid block-proposer member".to_string());
    }

    let register = &core[8];
    validate_settlement_tx_shape(
        register,
        "CALL",
        "IntmaxRollup",
        Some("registerChannel("),
        "registerChannel",
    )?;
    validate_settlement_call_target(register, rollup, "registerChannel")?;
    let register_args = settlement_artifact_args(register, "registerChannel")?;
    if register_args.len() != 7
        || settlement_artifact_quantity(
            &serde_json::Value::String(register_args[0].to_string()),
            "registerChannel channel id",
        )? != reg["channel_id"]
            .as_u64()
            .ok_or_else(|| "staged channel_id is invalid".to_string())?
        || settlement_artifact_quantity(
            &serde_json::Value::String(register_args[1].to_string()),
            "registerChannel bp slot",
        )? != BP_SLOT as u64
        || settlement_artifact_quantity(
            &serde_json::Value::String(register_args[2].to_string()),
            "registerChannel delegate count",
        )? != 0
        || normalize_abi_text(register_args[3])
            != normalize_abi_text(&abi_array(&pk_gs[..member_count]))
        || normalize_abi_text(register_args[4])
            != normalize_abi_text(&abi_array(&pk_bs[..member_count]))
        || normalize_abi_text(register_args[5])
            != normalize_abi_text(&abi_array(&regev[..member_count]))
        || normalize_abi_text(register_args[6])
            != normalize_abi_text(&abi_array(&recipients[..member_count]))
    {
        return Err(
            "registerChannel does not carry the staged cosigner-only channel registration"
                .to_string(),
        );
    }
    validate_settlement_call_input(register, "registerChannel")?;

    let manager_deploy = &core[9];
    validate_settlement_tx_shape(
        manager_deploy,
        "CREATE",
        "ChannelSettlementManager",
        None,
        "settlement manager deploy",
    )?;
    let manager =
        settlement_artifact_contract_address(manager_deploy, "settlement manager deploy")?;
    let manager_args = settlement_artifact_args(manager_deploy, "settlement manager deploy")?;
    let expected_channel = format!(
        "0x{:08x}",
        reg["channel_id"]
            .as_u64()
            .ok_or_else(|| "staged channel_id is invalid".to_string())?
    );
    let expected_bindings = format!(
        "[{}]",
        pk_gs[..member_count]
            .iter()
            .zip(&recipients[..member_count])
            .map(|(pk_g, recipient)| format!("({pk_g},{recipient})"))
            .collect::<Vec<_>>()
            .join(",")
    );
    let expected_root = reg["participant_root"]
        .as_str()
        .ok_or_else(|| "staged participant_root is invalid".to_string())?;
    if manager_args.len() != 12
        || normalize_abi_text(manager_args[0]) != normalize_abi_text(&expected_channel)
        || settlement_artifact_quantity(
            &serde_json::Value::String(manager_args[1].to_string()),
            "manager bp slot",
        )? != BP_SLOT as u64
        || normalize_abi_text(manager_args[2]) != normalize_abi_text(&pk_gs[BP_SLOT as usize])
        || settlement_artifact_quantity(
            &serde_json::Value::String(manager_args[3].to_string()),
            "manager delegate count",
        )? != delegate_count as u64
        || normalize_abi_text(manager_args[4]) != normalize_abi_text(expected_root)
        || settlement_artifact_quantity(
            &serde_json::Value::String(manager_args[5].to_string()),
            "manager challenge period",
        )? != 86_400
        || settlement_artifact_quantity(
            &serde_json::Value::String(manager_args[6].to_string()),
            "manager special-close penalty",
        )? != 0
        || settlement_artifact_quantity(
            &serde_json::Value::String(manager_args[7].to_string()),
            "manager initial BP bond",
        )? != 0
        || strip0x(manager_args[8]) != strip0x(&verifier)
        || strip0x(manager_args[9]) != strip0x(rollup)
        || strip0x(manager_args[10]) != strip0x(&materializer)
        || normalize_abi_text(manager_args[11]) != normalize_abi_text(&expected_bindings)
    {
        return Err(
            "ChannelSettlementManager constructor does not match the pinned snapshot/root/count/rollup"
                .to_string(),
        );
    }
    let encoded_constructor = cast_encode_settlement_constructor(&manager_args)?;
    let manager_input = manager_deploy
        .get("transaction")
        .and_then(|value| value.get("input"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "manager deploy has no transaction.input".to_string())?;
    if !strip0x(manager_input).ends_with(&strip0x(&encoded_constructor)) {
        return Err(
            "manager creation input does not end in the inspected constructor ABI".to_string(),
        );
    }

    let register_manager = &core[10];
    validate_settlement_tx_shape(
        register_manager,
        "CALL",
        "IntmaxRollup",
        Some("registerSettlementManager("),
        "registerSettlementManager",
    )?;
    validate_settlement_call_target(register_manager, rollup, "registerSettlementManager")?;
    let register_manager_args =
        settlement_artifact_args(register_manager, "registerSettlementManager")?;
    if register_manager_args.len() != 1 || strip0x(register_manager_args[0]) != strip0x(&manager) {
        return Err(
            "registerSettlementManager does not register the manager created by this run"
                .to_string(),
        );
    }
    validate_settlement_call_input(register_manager, "registerSettlementManager")?;

    let registration_tx_hash =
        settlement_artifact_string(register_manager, "hash", "registerSettlementManager")?
            .parse::<Bytes32>()
            .map_err(|error| format!("registerSettlementManager transaction hash: {error}"))?;
    if registration_tx_hash == Bytes32::default() {
        return Err("registerSettlementManager transaction hash is zero".to_string());
    }
    let registration_transaction = register_manager
        .get("transaction")
        .ok_or_else(|| "registerSettlementManager has no transaction object".to_string())?;
    let registration_input = settlement_artifact_string(
        registration_transaction,
        "input",
        "registerSettlementManager",
    )?;
    let registration_input_bytes = hex::decode(strip0x(registration_input))
        .map_err(|error| format!("decode registerSettlementManager calldata: {error}"))?;
    let registration_calldata_hash =
        Bytes32::from_bytes_be(&keccak_hash::keccak(registration_input_bytes).0)
            .map_err(|error| format!("construct registration calldata hash: {error:?}"))?;
    let registration_nonce = settlement_artifact_quantity(
        registration_transaction
            .get("nonce")
            .ok_or_else(|| "registerSettlementManager has no nonce".to_string())?,
        "registerSettlementManager nonce",
    )?;

    Ok(SettlementBroadcastAddresses {
        mle_verifier: mle,
        verifier,
        manager,
        materializer,
        registration_tx_hash,
        registration_calldata_hash,
        registration_nonce,
    })
}

fn validate_settlement_broadcast_artifact(
    contracts_dir: &Path,
    intent: &SettlementDeploymentIntent,
    reg: &serde_json::Value,
    rollup: &str,
) -> Result<SettlementBroadcastAddresses, String> {
    let expected_relative = settlement_broadcast_artifact_relative_path(intent.chain_id);
    if intent.broadcast_artifact_path != expected_relative {
        return Err(format!(
            "persisted broadcast path {:?} != deterministic path {:?}",
            intent.broadcast_artifact_path, expected_relative
        ));
    }
    let path = contracts_dir.join(&intent.broadcast_artifact_path);
    let metadata = fs::symlink_metadata(&path)
        .map_err(|e| format!("read broadcast artifact metadata {}: {e}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "broadcast artifact {} is not a regular non-symlink file",
            path.display()
        ));
    }
    if metadata.len() > SETTLEMENT_BROADCAST_ARTIFACT_MAX_BYTES {
        return Err(format!(
            "broadcast artifact {} is {} bytes, above the {} byte safety limit",
            path.display(),
            metadata.len(),
            SETTLEMENT_BROADCAST_ARTIFACT_MAX_BYTES
        ));
    }
    let bytes =
        fs::read(&path).map_err(|e| format!("read broadcast artifact {}: {e}", path.display()))?;
    let artifact: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| format!("parse broadcast artifact {}: {e}", path.display()))?;
    validate_settlement_broadcast_value(&artifact, intent, reg, rollup)
}

/// Adopt the exact final transaction from the pinned Foundry artifact only after its receipt is
/// successful, canonical and covered by the durable L1 head.  A `latest` code/readback is not
/// evidence: it can disappear in a reorg and it can be assembled from a different branch than the
/// transaction which actually registered the manager.
fn settlement_registration_receipt(
    rpc: &str,
    intent: &SettlementDeploymentIntent,
    rollup: &str,
    addresses: &SettlementBroadcastAddresses,
) -> Option<intmax3_zkp::partial_withdrawal_payout::L1TransactionReceipt> {
    use intmax3_zkp::partial_withdrawal_payout::L1CallKind;

    let receipt = try_read_l1_receipt(
        rpc,
        &addresses.registration_tx_hash.to_string(),
        L1CallKind::RegisterSettlementManager,
    )?;
    let expected_from = Address::from_hex(&intent.broadcaster)
        .unwrap_or_else(|error| die(format!("parse settlement broadcaster: {error:?}")));
    let expected_to = Address::from_hex(rollup)
        .unwrap_or_else(|error| die(format!("parse settlement rollup: {error:?}")));
    if !receipt.success
        || receipt.chain_id != intent.chain_id
        || receipt.from != expected_from
        || receipt.to != expected_to
        || receipt.call_kind != L1CallKind::RegisterSettlementManager
        || receipt.calldata_hash != addresses.registration_calldata_hash
        || receipt.transaction_nonce != addresses.registration_nonce
        || receipt.block_number < intent.start_block
    {
        die(format!(
            "pinned registerSettlementManager receipt does not match the PREPARED deployment: {:?}",
            receipt
        ));
    }
    require_stable_durable_l1_checkpoint(rpc, &receipt.finalized_checkpoint);
    Some(receipt)
}

#[cfg(test)]
mod settlement_broadcast_recovery_tests {
    use super::*;

    const CHAIN_ID: u64 = 1;
    const START_NONCE: u64 = 41;
    const BROADCASTER: &str = "0x0000000000000000000000000000000000000055";
    const ROLLUP: &str = "0x0000000000000000000000000000000000000044";
    const MLE: &str = "0x0000000000000000000000000000000000000011";
    const VERIFIER: &str = "0x0000000000000000000000000000000000000022";
    const MANAGER: &str = "0x0000000000000000000000000000000000000033";
    const MATERIALIZER: &str = "0x0000000000000000000000000000000000000088";

    fn intent() -> SettlementDeploymentIntent {
        SettlementDeploymentIntent {
            chain_id: CHAIN_ID,
            broadcaster: BROADCASTER.to_string(),
            start_nonce: START_NONCE,
            start_block: 100,
            broadcast_artifact_path: settlement_broadcast_artifact_relative_path(CHAIN_ID),
            plan_digest: Bytes32::default(),
        }
    }

    fn reg() -> serde_json::Value {
        let pk_gs = (1..=3).map(|i| format!("0x{i:064x}")).collect::<Vec<_>>();
        let pk_bs = (11..=13).map(|i| format!("0x{i:064x}")).collect::<Vec<_>>();
        let regev = (21..=23).map(|i| format!("0x{i:064x}")).collect::<Vec<_>>();
        let recipients = vec![
            BROADCASTER.to_string(),
            "0x0000000000000000000000000000000000000066".to_string(),
            "0x0000000000000000000000000000000000000077".to_string(),
        ];
        settlement_reg_json(7, 2, 1, &pk_gs, &pk_bs, &regev, &recipients)
    }

    fn create_tx(
        nonce: u64,
        contract_name: &str,
        contract_address: &str,
        args: Option<Vec<String>>,
        input: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "hash": format!("0x{:064x}", nonce + 1),
            "transactionType": "CREATE",
            "contractName": contract_name,
            "contractAddress": contract_address,
            "function": null,
            "arguments": args,
            "transaction": {
                "from": BROADCASTER,
                "nonce": format!("0x{nonce:x}"),
                "chainId": format!("0x{CHAIN_ID:x}"),
                "input": input,
            }
        })
    }

    fn call_tx(
        nonce: u64,
        contract_name: &str,
        target: &str,
        function: &str,
        args: Vec<String>,
    ) -> serde_json::Value {
        let refs = args.iter().map(String::as_str).collect::<Vec<_>>();
        let input = cast_encode_settlement_calldata(function, &refs).unwrap();
        serde_json::json!({
            "hash": format!("0x{:064x}", nonce + 1),
            "transactionType": "CALL",
            "contractName": contract_name,
            "contractAddress": target,
            "function": function,
            "arguments": args,
            "transaction": {
                "from": BROADCASTER,
                "to": target,
                "nonce": format!("0x{nonce:x}"),
                "chainId": format!("0x{CHAIN_ID:x}"),
                "input": input,
            }
        })
    }

    fn artifact() -> (serde_json::Value, serde_json::Value) {
        let reg = reg();
        let pk_gs = settlement_reg_string_vec(&reg, "member_pk_gs", 3).unwrap();
        let pk_bs = settlement_reg_string_vec(&reg, "member_pk_bs", 3).unwrap();
        let regev = settlement_reg_string_vec(&reg, "regev_pk_digests", 3).unwrap();
        let recipients = settlement_reg_string_vec(&reg, "recipients", 3).unwrap();
        let root = reg["participant_root"].as_str().unwrap().to_string();
        let member_bindings = format!(
            "[({},{}),({},{})]",
            pk_gs[0], recipients[0], pk_gs[1], recipients[1]
        );
        let manager_args = vec![
            "0x00000007".to_string(),
            "0".to_string(),
            pk_gs[0].clone(),
            "1".to_string(),
            root,
            "86400".to_string(),
            "0".to_string(),
            "0".to_string(),
            VERIFIER.to_string(),
            ROLLUP.to_string(),
            MATERIALIZER.to_string(),
            member_bindings,
        ];
        let manager_refs = manager_args.iter().map(String::as_str).collect::<Vec<_>>();
        let constructor = cast_encode_settlement_constructor(&manager_refs).unwrap();
        let manager_input = format!("0x60006000{}", strip0x(&constructor));
        let materializer_constructor = cast_encode_materializer_constructor(ROLLUP).unwrap();
        let materializer_input = format!("0x6002{}", strip0x(&materializer_constructor));

        let mut transactions = vec![
            create_tx(START_NONCE, "MleVerifier", MLE, None, "0x6000"),
            create_tx(
                START_NONCE + 1,
                "CloseFundingMaterializer",
                MATERIALIZER,
                Some(vec![ROLLUP.to_string()]),
                &materializer_input,
            ),
            call_tx(
                START_NONCE + 2,
                "CloseFundingMaterializer",
                MATERIALIZER,
                "initializeBackingVk(address)",
                vec![MLE.to_string()],
            ),
            create_tx(
                START_NONCE + 3,
                "ChannelSettlementVerifier",
                VERIFIER,
                None,
                "0x6001",
            ),
        ];
        for (offset, function) in [
            "initializeCloseVk(address)",
            "initializeWithdrawalClaimVk(address)",
            "initializePostCloseClaimVk(address)",
            "initializeCancelCloseVk(address)",
        ]
        .iter()
        .enumerate()
        {
            transactions.push(call_tx(
                START_NONCE + 4 + offset as u64,
                "ChannelSettlementVerifier",
                VERIFIER,
                function,
                vec![MLE.to_string()],
            ));
        }
        transactions.push(call_tx(
            START_NONCE + 8,
            "IntmaxRollup",
            ROLLUP,
            "registerChannel(uint32,uint8,uint8,bytes32[],bytes32[],bytes32[],address[])",
            vec![
                "7".to_string(),
                "0".to_string(),
                "0".to_string(),
                abi_array(&pk_gs[..2]),
                abi_array(&pk_bs[..2]),
                abi_array(&regev[..2]),
                abi_array(&recipients[..2]),
            ],
        ));
        transactions.push(create_tx(
            START_NONCE + 9,
            "ChannelSettlementManager",
            MANAGER,
            Some(manager_args),
            &manager_input,
        ));
        transactions.push(call_tx(
            START_NONCE + 10,
            "IntmaxRollup",
            ROLLUP,
            "registerSettlementManager(address)",
            vec![MANAGER.to_string()],
        ));
        (
            serde_json::json!({"chain": CHAIN_ID, "transactions": transactions}),
            reg,
        )
    }

    fn backing_bundle_bytes() -> (Vec<u8>, Vec<u8>, Vec<u8>, String) {
        let mut inputs = vec![0u64; CLOSE_BACKING_PUBLIC_INPUTS];
        inputs[0] = 7;
        for (index, value) in inputs.iter_mut().enumerate().take(25).skip(1) {
            *value = index as u64;
        }
        inputs[25] = 42;
        let serialized_inputs = inputs
            .iter()
            .map(|value| serde_json::Value::String(value.to_string()))
            .collect::<Vec<_>>();
        let mle = serde_json::to_vec(&serde_json::json!({
            "protocolVersion": CLOSE_BACKING_MLE_PROTOCOL_VERSION,
            "constituentWidth": 3,
            "degreeBits": 8,
            "publicInputs": serialized_inputs,
            "preprocessedIndividualEvals": [1, 2],
            "witnessIndividualEvals": [1, 2, 3],
            "inverseHelpersEvalsAtRInv": [],
            "inverseHelpersEvalsAtRH": [],
            "preprocessedIndividualEvalsAtRGateV2": [1],
            "witnessIndividualEvalsAtRGateV2": [1, 2],
        }))
        .unwrap();
        let public_inputs = serde_json::to_vec(&inputs).unwrap();
        let balance_vd_sha256 = close_backing_sha256(b"pinned balance verifier data");
        let manifest = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "chainId": CHAIN_ID,
            "rollup": ROLLUP,
            "channelId": 7,
            "balanceVerifierDataSha256": balance_vd_sha256,
            "backingMleFile": "backing_mle.json",
            "backingMleBytes": mle.len(),
            "backingMleSha256": close_backing_sha256(&mle),
            "backingPublicInputsFile": "backing_public_inputs.json",
            "backingPublicInputCount": CLOSE_BACKING_PUBLIC_INPUTS,
            "backingPublicInputsSha256": close_backing_sha256(&public_inputs),
            "backingFinalizedExtendedStateCommitment": close_backing_limb_bytes32(&inputs, 17),
            "backingAnchorBlockNumber": 42,
            "keyMaterialConsumed": false,
            "selfVerified": true,
        }))
        .unwrap();
        (manifest, mle, public_inputs, balance_vd_sha256)
    }

    #[test]
    fn backing_bundle_is_exactly_bound_and_close_vk_substitution_is_rejected() {
        let (manifest, mle, public_inputs, balance_vd_sha256) = backing_bundle_bytes();
        validate_close_backing_bundle_bytes(
            &manifest,
            &mle,
            &public_inputs,
            CHAIN_ID,
            ROLLUP,
            7,
            &balance_vd_sha256,
        )
        .expect("exact CloseAssetBacking bundle");

        let mut close_mle: serde_json::Value = serde_json::from_slice(&mle).unwrap();
        close_mle["publicInputs"] = serde_json::json!(vec!["0"; 103]);
        let close_mle = serde_json::to_vec(&close_mle).unwrap();
        let mut substituted_manifest: serde_json::Value =
            serde_json::from_slice(&manifest).unwrap();
        substituted_manifest["backingMleBytes"] = serde_json::json!(close_mle.len());
        substituted_manifest["backingMleSha256"] =
            serde_json::json!(close_backing_sha256(&close_mle));
        assert!(
            validate_close_backing_bundle_bytes(
                &serde_json::to_vec(&substituted_manifest).unwrap(),
                &close_mle,
                &public_inputs,
                CHAIN_ID,
                ROLLUP,
                7,
                &balance_vd_sha256,
            )
            .unwrap_err()
            .contains("exactly 26"),
            "a close-proof-shaped MLE must never initialize the backing VK"
        );
    }

    #[test]
    fn backing_bundle_rejects_legacy_and_width_mismatched_mle_envelopes() {
        let (manifest, mle, public_inputs, balance_vd_sha256) = backing_bundle_bytes();
        for (field, replacement, needle) in [
            (
                "protocolVersion",
                serde_json::json!(0),
                "protocolVersion",
            ),
            (
                "constituentWidth",
                serde_json::json!(99),
                "constituentWidth",
            ),
        ] {
            let mut changed_mle: serde_json::Value = serde_json::from_slice(&mle).unwrap();
            changed_mle[field] = replacement;
            let changed_mle = serde_json::to_vec(&changed_mle).unwrap();
            let mut changed_manifest: serde_json::Value =
                serde_json::from_slice(&manifest).unwrap();
            changed_manifest["backingMleBytes"] = serde_json::json!(changed_mle.len());
            changed_manifest["backingMleSha256"] =
                serde_json::json!(close_backing_sha256(&changed_mle));
            let error = validate_close_backing_bundle_bytes(
                &serde_json::to_vec(&changed_manifest).unwrap(),
                &changed_mle,
                &public_inputs,
                CHAIN_ID,
                ROLLUP,
                7,
                &balance_vd_sha256,
            )
            .unwrap_err();
            assert!(error.contains(needle), "unexpected refusal: {error}");
        }
    }

    #[test]
    fn backing_bundle_rejects_hash_context_and_split_public_input_substitution() {
        let (manifest, mle, public_inputs, balance_vd_sha256) = backing_bundle_bytes();
        let check =
            |manifest: &[u8], mle: &[u8], public_inputs: &[u8], chain, rollup, channel, vd| {
                validate_close_backing_bundle_bytes(
                    manifest,
                    mle,
                    public_inputs,
                    chain,
                    rollup,
                    channel,
                    vd,
                )
            };
        assert!(
            check(
                &manifest,
                &mle,
                &public_inputs,
                2,
                ROLLUP,
                7,
                &balance_vd_sha256
            )
            .is_err()
        );
        assert!(
            check(
                &manifest,
                &mle,
                &public_inputs,
                CHAIN_ID,
                "0x0000000000000000000000000000000000000099",
                7,
                &balance_vd_sha256,
            )
            .is_err()
        );
        assert!(
            check(
                &manifest,
                &mle,
                &public_inputs,
                CHAIN_ID,
                ROLLUP,
                8,
                &balance_vd_sha256
            )
            .is_err()
        );
        let other_vd_sha256 = close_backing_sha256(b"other vd");
        assert!(
            check(
                &manifest,
                &mle,
                &public_inputs,
                CHAIN_ID,
                ROLLUP,
                7,
                &other_vd_sha256,
            )
            .is_err()
        );

        let mut tampered_mle = mle.clone();
        tampered_mle.push(b' ');
        assert!(
            check(
                &manifest,
                &tampered_mle,
                &public_inputs,
                CHAIN_ID,
                ROLLUP,
                7,
                &balance_vd_sha256
            )
            .is_err()
        );
        let mut split_inputs: serde_json::Value = serde_json::from_slice(&public_inputs).unwrap();
        split_inputs[1] = serde_json::json!(99);
        let split_inputs = serde_json::to_vec(&split_inputs).unwrap();
        let mut split_manifest: serde_json::Value = serde_json::from_slice(&manifest).unwrap();
        split_manifest["backingPublicInputsSha256"] =
            serde_json::json!(close_backing_sha256(&split_inputs));
        assert!(
            check(
                &serde_json::to_vec(&split_manifest).unwrap(),
                &mle,
                &split_inputs,
                CHAIN_ID,
                ROLLUP,
                7,
                &balance_vd_sha256,
            )
            .unwrap_err()
            .contains("different statements")
        );
    }

    #[test]
    fn prepared_retry_never_selects_a_fresh_run() {
        let expected = intent();
        assert_eq!(
            settlement_deploy_mode_for_intent(false, None, &expected),
            Ok(RealSettlementDeployMode::Fresh)
        );
        assert!(settlement_deploy_mode_for_intent(true, None, &expected).is_err());
        assert_eq!(
            settlement_deploy_mode_for_intent(true, Some(&expected), &expected),
            Ok(RealSettlementDeployMode::Resume)
        );

        let mut stale = expected.clone();
        stale.start_nonce -= 1;
        assert!(settlement_deploy_mode_for_intent(true, Some(&stale), &expected).is_err());
        let mut wrong_chain = expected.clone();
        wrong_chain.chain_id = 10;
        assert!(settlement_deploy_mode_for_intent(true, Some(&wrong_chain), &expected).is_err());
    }

    #[test]
    fn artifact_is_bound_to_chain_sender_nonce_rollup_and_snapshot_constructor() {
        let (artifact, reg) = artifact();
        let addresses =
            validate_settlement_broadcast_value(&artifact, &intent(), &reg, ROLLUP).unwrap();
        assert_eq!(strip0x(&addresses.verifier), strip0x(VERIFIER));
        assert_eq!(strip0x(&addresses.mle_verifier), strip0x(MLE));
        assert_eq!(strip0x(&addresses.manager), strip0x(MANAGER));
        assert_eq!(strip0x(&addresses.materializer), strip0x(MATERIALIZER));
        assert_eq!(addresses.registration_nonce, START_NONCE + 10);
        assert_ne!(addresses.registration_tx_hash, Bytes32::default());
        assert_ne!(addresses.registration_calldata_hash, Bytes32::default());

        let mut backing_vk_targets_other_contract = artifact.clone();
        backing_vk_targets_other_contract["transactions"][2]["transaction"]["to"] =
            serde_json::json!(VERIFIER);
        assert!(
            validate_settlement_broadcast_value(
                &backing_vk_targets_other_contract,
                &intent(),
                &reg,
                ROLLUP,
            )
            .is_err()
        );
        let mut backing_vk_uses_other_mle = artifact.clone();
        backing_vk_uses_other_mle["transactions"][2]["arguments"][0] =
            serde_json::json!("0x0000000000000000000000000000000000000099");
        assert!(
            validate_settlement_broadcast_value(
                &backing_vk_uses_other_mle,
                &intent(),
                &reg,
                ROLLUP,
            )
            .is_err()
        );

        let mut wrong_nonce = artifact.clone();
        wrong_nonce["transactions"][5]["transaction"]["nonce"] =
            serde_json::json!(format!("0x{:x}", START_NONCE + 99));
        assert!(
            validate_settlement_broadcast_value(&wrong_nonce, &intent(), &reg, ROLLUP).is_err()
        );

        let mut wrong_rollup = artifact.clone();
        wrong_rollup["transactions"][8]["transaction"]["to"] =
            serde_json::json!("0x0000000000000000000000000000000000000099");
        assert!(
            validate_settlement_broadcast_value(&wrong_rollup, &intent(), &reg, ROLLUP).is_err()
        );

        let mut wrong_root = artifact.clone();
        wrong_root["transactions"][9]["arguments"][4] =
            serde_json::json!(format!("0x{:064x}", 999));
        assert!(validate_settlement_broadcast_value(&wrong_root, &intent(), &reg, ROLLUP).is_err());

        let mut forged_materializer_init_code = artifact.clone();
        forged_materializer_init_code["transactions"][1]["transaction"]["input"] =
            serde_json::json!("0x6002");
        assert!(
            validate_settlement_broadcast_value(
                &forged_materializer_init_code,
                &intent(),
                &reg,
                ROLLUP,
            )
            .is_err()
        );

        let mut manager_bound_to_other_materializer = artifact.clone();
        manager_bound_to_other_materializer["transactions"][9]["arguments"][10] =
            serde_json::json!("0x0000000000000000000000000000000000000099");
        assert!(
            validate_settlement_broadcast_value(
                &manager_bound_to_other_materializer,
                &intent(),
                &reg,
                ROLLUP,
            )
            .is_err()
        );

        let mut annotated_call_with_other_input = artifact.clone();
        annotated_call_with_other_input["transactions"][10]["transaction"]["input"] = serde_json::json!(
            "0xa01b29350000000000000000000000000000000000000000000000000000000000000099"
        );
        assert!(
            validate_settlement_broadcast_value(
                &annotated_call_with_other_input,
                &intent(),
                &reg,
                ROLLUP,
            )
            .is_err()
        );

        let mut zero_final_hash = artifact.clone();
        zero_final_hash["transactions"][10]["hash"] = serde_json::json!(format!("0x{:064x}", 0));
        assert!(
            validate_settlement_broadcast_value(&zero_final_hash, &intent(), &reg, ROLLUP).is_err()
        );

        let mut value_bearing_registration = artifact.clone();
        value_bearing_registration["transactions"][10]["transaction"]["value"] =
            serde_json::json!("0x1");
        assert!(
            validate_settlement_broadcast_value(
                &value_bearing_registration,
                &intent(),
                &reg,
                ROLLUP,
            )
            .is_err()
        );
    }
}

/// Phase 2: after every canonical on-chain readback passes, fill the deployed addresses and mark
/// ACTIVE.  This is fsynced before `settlement.json` is published.
fn activate_settlement_binding(
    state: &mut CliState,
    reg: &serde_json::Value,
    rollup: &str,
    verifier: &str,
    manager: &str,
    materializer: &str,
    activation_checkpoint: Option<intmax3_zkp::l1_finality::L1FinalizedCheckpoint>,
    runtime_code_hashes: Option<SettlementRuntimeCodeHashes>,
) {
    let (participant_root, participant_count) = staged_settlement_identity(reg);
    let binding = state
        .settlement_binding
        .as_mut()
        .unwrap_or_else(|| die("settlement activation without a fsynced PREPARED binding"));
    if binding.status != SettlementBindingStatus::Prepared
        || binding.snapshot_state_digest != state.snapshot.state.digest
        || binding.participant_root != participant_root
        || binding.participant_count != participant_count
        || strip0x(&binding.rollup) != strip0x(rollup)
    {
        die("settlement activation does not match the fsynced PREPARED identity");
    }
    if binding.deployment.is_some()
        && (activation_checkpoint.is_none() || runtime_code_hashes.is_none())
    {
        die(
            "production settlement activation requires a canonical finalized checkpoint and \
             runtime code hashes",
        );
    }
    if binding.deployment.is_none()
        && (activation_checkpoint.is_some() || runtime_code_hashes.is_some())
    {
        die(
            "devnet settlement activation must not claim production finality or runtime-code authority",
        );
    }
    if let Some(checkpoint) = activation_checkpoint {
        checkpoint.validate().unwrap_or_else(|error| {
            die(format!("invalid settlement activation checkpoint: {error}"))
        });
        let deployment = binding
            .deployment
            .as_ref()
            .unwrap_or_else(|| die("activation checkpoint without deployment intent"));
        if checkpoint.chain_id != deployment.chain_id
            || checkpoint.block_number < deployment.start_block
        {
            die("settlement activation checkpoint does not cover the PREPARED deployment window");
        }
        binding.activation_checkpoint = Some(checkpoint);
    }
    binding.runtime_code_hashes = runtime_code_hashes;
    binding.status = SettlementBindingStatus::Active;
    binding.verifier = Some(verifier.to_string());
    binding.manager = Some(manager.to_string());
    binding.materializer = Some(materializer.to_string());
    save_state(state);
}

/// The anvil path, UNCHANGED: MockMleVerifier + ChannelSettlementVerifier +
/// ChannelSettlementManager attached to the EXISTING rollup in `channel_backing.json`, with the
/// LIVE channel member set from the snapshot (including any runtime-joined delegates).
///
/// SECURITY: `chain_id` is taken as an argument and re-checked below rather than assumed, so the
/// mock stack cannot be installed off-devnet even if a future refactor mis-wires the dispatcher.
fn deploy_settlement_devnet(rpc: &str, chain_id: u64) {
    let mut state = load_state();
    let (_, _, backing) = load_backing();
    let rollup = &backing.rollup;
    if rollup.is_empty() {
        die("no rollup address in channel_backing.json — run setup-backing first");
    }

    let reg = build_live_settlement_reg_record(&state);
    prepare_settlement_binding(&mut state, &reg, rollup);
    // The pattern the five exit commands now share (F4): resolve from the executable, validate,
    // announce. Kept identical here so there is ONE implementation rather than three copies.
    let plan = SettlementDeployPlan::MockDevnet;
    let contracts_dir = require_contracts_dir("deploy-settlement", &[plan.script()]);
    let contracts_dir = contracts_dir.to_string_lossy().to_string();
    let data_path = format!("{contracts_dir}/test/data/pw_reg.json");
    fs::write(
        &data_path,
        serde_json::to_string_pretty(&reg).unwrap_or_else(|e| die(e)),
    )
    .unwrap_or_else(|e| die(format!("write {data_path}: {e}")));
    eprintln!("deploy-settlement: wrote {data_path}");

    // SECURITY (defence in depth — the LAST gate before the mock stack is broadcast): the plan was
    // already chosen from the chain id in `cmd_deploy_settlement`, and the script itself reverts
    // unless `block.chainid == 31337`. This third check exists because the cost of the three being
    // wrong together is total: `WalletMockMleVerifier.verify` returns true for ANY proof, so the
    // close-intent verification on a stack deployed here is vacuous and every channel registered
    // with it can be closed to an arbitrary state by anyone. A dispatcher mis-wired by a future
    // refactor dies HERE rather than sending the transaction.
    if chain_id != DEVNET_CHAIN_ID {
        die(format!(
            "refusing to deploy the MOCK settlement stack on chain id {chain_id}: \
             {} installs an always-true MLE verifier and is devnet-only. \
             This is the in-process backstop; reaching it means the plan selection was bypassed.",
            SettlementDeployPlan::MockDevnet.script()
        ));
    }
    let l1_signer = L1Signer::for_chain_id(chain_id);
    let mut forge = Command::new("forge");
    forge.current_dir(&contracts_dir).args([
        "script",
        plan.script(),
        "--tc",
        plan.contract(),
        "--rpc-url",
        rpc,
        "--broadcast",
        "--code-size-limit",
        "50000",
    ]);
    l1_signer.append_to_command(&mut forge);
    let forge_out = forge
        .env("ROLLUP", rollup)
        .output()
        .unwrap_or_else(|e| die(format!("forge script failed to start: {e}")));
    let out = String::from_utf8_lossy(&forge_out.stdout);
    let err = String::from_utf8_lossy(&forge_out.stderr);
    if !forge_out.status.success() {
        die(format!(
            "forge deploy-settlement FAILED:\nstdout: {out}\nstderr: {err}"
        ));
    }

    let manager = out
        .lines()
        .chain(err.lines())
        .find_map(|l| {
            l.contains("MANAGER:")
                .then(|| l.split("MANAGER:").nth(1).unwrap_or("").trim().to_string())
        })
        .unwrap_or_else(|| {
            die(format!(
                "could not parse MANAGER from forge output:\n{out}\n{err}"
            ))
        });
    let verifier = out
        .lines()
        .chain(err.lines())
        .find_map(|l| {
            l.contains("VERIFIER:")
                .then(|| l.split("VERIFIER:").nth(1).unwrap_or("").trim().to_string())
        })
        .unwrap_or_else(|| {
            die(format!(
                "could not parse VERIFIER from forge output:\n{out}\n{err}"
            ))
        });
    let materializer = out
        .lines()
        .chain(err.lines())
        .find_map(|line| {
            line.contains("CLOSE_FUNDING_MATERIALIZER:").then(|| {
                line.split("CLOSE_FUNDING_MATERIALIZER:")
                    .nth(1)
                    .unwrap_or("")
                    .trim()
                    .to_string()
            })
        })
        .unwrap_or_else(|| {
            die(format!(
                "could not parse CLOSE_FUNDING_MATERIALIZER from forge output:\n{out}\n{err}"
            ))
        });

    activate_settlement_binding(
        &mut state,
        &reg,
        rollup,
        &verifier,
        &manager,
        &materializer,
        None,
        None,
    );
    write_json(
        "settlement.json",
        &serde_json::json!({
            "manager": manager,
            "verifier": verifier,
            "rollup": rollup,
            "close_funding_materializer": materializer,
        }),
    );
    println!(
        "deploy-settlement OK: manager={manager}, verifier={verifier}, \
         materializer={materializer}, rollup={rollup}"
    );
}

/// The checked-in fixtures `DeployCloseCli.s.sol` reads out of `contracts/test/data/`, besides the
/// `cli_reg_record.json` this command stages itself. They carry the MLE/WHIR VERIFIER DATA of the
/// validity, withdrawal, close, withdrawal-claim, post-close-claim and cancel-close circuits —
/// channel- and member-independent, which is why a checked-in copy is the right source.
/// The Balance-VD-dependent CloseAssetBacking VK is intentionally absent: it is staged from the
/// independently checked `INTMAX_PUBLIC_CLOSE_BUNDLE` and plan-digested separately.
///
/// Checked up front so a missing one is an actionable error here, not a `vm.readFile` revert
/// buried in forge output after the operator has already paid for a broadcast.
const CLOSE_CLI_FIXTURES: [&str; 7] = [
    "close_lifecycle_validity_mle.json",
    "close_lifecycle.json",
    "close_withdrawal_mle.json",
    "close_intent_mle.json",
    "withdrawal_claim_mle.json",
    "post_close_claim_mle.json",
    "cancel_close_mle.json",
];

/// `cast call <to> <sig> [args…]`, trimmed. Every read-back below goes through this.
fn cast_call(rpc: &str, to: &str, sig: &str, args: &[&str]) -> String {
    let mut argv: Vec<&str> = vec!["call", to, sig];
    argv.extend_from_slice(args);
    argv.extend_from_slice(&["--rpc-url", rpc]);
    cast(&argv).trim().to_string()
}

fn cast_call_at(rpc: &str, to: &str, sig: &str, args: &[&str], block_number: u64) -> String {
    let block = format!("0x{block_number:x}");
    let mut argv: Vec<&str> = vec!["call", to, sig];
    argv.extend_from_slice(args);
    argv.extend_from_slice(&["--block", &block, "--rpc-url", rpc]);
    cast(&argv).trim().to_string()
}

fn cast_code_at(rpc: &str, address: &str, block_number: u64) -> String {
    let block = format!("0x{block_number:x}");
    cast(&["code", address, "--block", &block, "--rpc-url", rpc])
        .trim()
        .to_string()
}

fn settlement_runtime_code_hash_at(rpc: &str, address: &str, block_number: u64) -> Bytes32 {
    let encoded = cast_code_at(rpc, address, block_number);
    let body = encoded
        .strip_prefix("0x")
        .or_else(|| encoded.strip_prefix("0X"))
        .unwrap_or_else(|| die(format!("runtime code for {address} is not 0x-prefixed hex")));
    if body.is_empty() || body.len() % 2 != 0 {
        die(format!(
            "runtime code for {address} is empty or malformed at block {block_number}"
        ));
    }
    let bytes = hex::decode(body)
        .unwrap_or_else(|error| die(format!("decode runtime code for {address}: {error}")));
    if bytes.is_empty() {
        die(format!(
            "runtime code for {address} is empty at block {block_number}"
        ));
    }
    Bytes32::from_bytes_be(&keccak_hash::keccak(bytes).0)
        .unwrap_or_else(|error| die(format!("construct runtime code hash: {error:?}")))
}

fn require_settlement_runtime_code_hashes_at(
    rpc: &str,
    rollup: &str,
    verifier: &str,
    manager: &str,
    materializer: &str,
    expected: &SettlementRuntimeCodeHashes,
    block_number: u64,
) {
    for (label, address, expected_hash) in [
        ("rollup", rollup, expected.rollup),
        ("settlement verifier", verifier, expected.verifier),
        ("settlement manager", manager, expected.manager),
        (
            "close-funding materializer",
            materializer,
            expected.materializer,
        ),
    ] {
        let observed = settlement_runtime_code_hash_at(rpc, address, block_number);
        if observed != expected_hash {
            die(format!(
                "{label} runtime code hash changed at durable block {block_number}: expected \
                 {expected_hash}, observed {observed}; refusing fund-moving operation"
            ));
        }
    }
}

/// Read back ONE boolean latch, refusing anything that is not exactly `true`.
///
/// SECURITY / LIVENESS: fail-closed on purpose. `cast` decodes `(bool)` to `true`/`false`; any
/// other output (an RPC error page, a changed encoder, a wrong address) is treated as NOT set,
/// because the failure mode we are guarding against — announcing a stack whose latch is missing —
/// is precisely a user losing an exit path they were told they had.
fn require_true(rpc: &str, to: &str, sig: &str, what: &str) {
    let got = cast_call(rpc, to, sig, &[]);
    if got != "true" {
        die(format!(
            "post-deploy check FAILED: {to} `{sig}` returned {got:?}, expected \"true\".\n\
             {what}\n\
             The stack just deployed is NOT usable end to end; refusing to record it in \
             settlement.json (an address recorded here is one an operator would go on to fund)."
        ));
    }
}

fn require_true_at(
    rpc: &str,
    to: &str,
    sig: &str,
    what: &str,
    checkpoint: &intmax3_zkp::l1_finality::L1FinalizedCheckpoint,
) {
    let got = cast_call_at(rpc, to, sig, &[], checkpoint.block_number);
    if got != "true" {
        die(format!(
            "post-deploy check FAILED at finalized block {} ({}): {to} `{sig}` returned \
             {got:?}, expected \"true\".\n{what}\nThe stack is NOT usable end to end; \
             cli_state remains PREPARED.",
            checkpoint.block_number, checkpoint.block_hash
        ));
    }
}

/// Deploy a REAL settlement stack (real MLE/WHIR verifier data for all four settlement statements)
/// via `DeployCloseCli.s.sol`, after checking every precondition a real deployment needs.
///
/// This is stage two of production deployment: the already-live rollup continues to own validity,
/// KZG, withdrawal verification and the channel's escrow; this command attaches the four real
/// settlement VKs, the cosigner-only registration and one manager whose immutable participant
/// root is derived from the current N-of-N-signed snapshot.
fn deploy_settlement_real(rpc: &str, chain_id: u64) {
    let plan = SettlementDeployPlan::RealChain;
    let channel_id = channel_id_env();

    // ── Preconditions. ALL of them run before anything is written or broadcast, so a real-chain
    //    deploy fails on a message an operator can act on rather than on raw forge output. ──

    if std::path::Path::new("settlement.json").exists() {
        die(
            "settlement.json already exists in this working directory — refusing to deploy a \
             SECOND settlement stack. The durable cli_state.json settlement binding is the \
             authoritative freeze; deleting this address file does not permit a redeploy or join.",
        );
    }

    let contracts_dir = require_contracts_dir("deploy-settlement", &[plan.script()]);
    let missing: Vec<&str> = CLOSE_CLI_FIXTURES
        .iter()
        .copied()
        .filter(|f| !contracts_dir.join("test").join("data").join(f).is_file())
        .collect();
    if !missing.is_empty() {
        die(format!(
            "`deploy-settlement` (real chain): {} is missing the verifier-data fixtures \
             {} reads: {}.\n\
             These carry the circuits' MLE/WHIR verifier data; without them the settlement VKs \
             cannot be keyed and the channel could be closed by nobody.",
            contracts_dir.join("test/data").display(),
            plan.script(),
            missing.join(", ")
        ));
    }

    let l1_signer = L1Signer::for_chain_id(chain_id);

    // SECURITY: the member set this deploy REGISTERS on L1 is derived from the co-signer key
    // provenance. Under `INTMAX_INSECURE_DETERMINISTIC_KEYS` every one of those members' SECRET
    // keys is computable by anyone who can read this public repository — i.e. anyone could produce
    // the N-of-N signatures a close needs and take the channel's funds. That is fund-fatal on a
    // real chain and merely convenient on anvil, so it is refused HERE rather than at genesis.
    if matches!(key_provenance(), KeyProvenance::InsecureDeterministic) {
        die(format!(
            "{INSECURE_KEYS_ENV} is set and chain id {chain_id} is not the local devnet — refusing \
             to register a channel whose co-signer SECRET keys are publicly derivable.\n\
             Provision {COSIGNER_KEYFILE_ENV} (a 0600 file outside the repo) and re-run; see \
             doc/docs/deploy-runbook.md."
        ));
    }

    let mut state = load_state();
    if let Some(binding) = &state.settlement_binding {
        if binding.status == SettlementBindingStatus::Active {
            die(format!(
                "settlement is already durably ACTIVE at manager {:?} on rollup {}; deleting \
                 settlement.json cannot reopen deployment or delegate joins",
                binding.manager, binding.rollup
            ));
        }
    }
    let (_, _, backing) = load_backing();
    let backing_rollup = Address::from_hex(backing.rollup.trim()).unwrap_or_else(|_| {
        die(format!(
            "{BACKING_FILE} rollup is not a 20-byte address: {:?}",
            backing.rollup
        ))
    });
    if backing_rollup == Address::default() {
        die(format!("{BACKING_FILE} has a zero rollup address"));
    }
    let backing_rollup_hex = backing_rollup.to_hex();
    let broadcaster = l1_signer.address();

    // ── Stage every runtime input the script takes that is not checked in. ──
    //
    // LIVENESS: `DeployCloseCli.s.sol` reads `test/data/cli_reg_record.json`. Only the Rust E2Es
    // ever staged it (they copy it after `export-reg-record` runs in the repo root); no product
    // driver did, so the real script was unreachable from the CLI at all. The registration record
    // keeps one derivation from the verified live snapshot; the distinct backing bundle is checked
    // and staged below before the PREPARED deployment identity is fsynced.
    let reg = build_live_settlement_reg_record(&state);
    let broadcaster_is_active = reg["recipients"].as_array().is_some_and(|recipients| {
        recipients.iter().any(|r| {
            r.as_str()
                .is_some_and(|s| strip0x(s) == strip0x(&broadcaster))
        })
    });
    if !broadcaster_is_active {
        die(format!(
            "settlement broadcaster {broadcaster} is not an active recipient in the N-of-N-signed \
             live BalanceState. Align INTMAX_L1_ACCOUNT with a signed-state recipient before deploy."
        ));
    }
    let rollup_deployer = cast_call(rpc, &backing_rollup_hex, "deployer()(address)", &[]);
    if !rollup_deployer.eq_ignore_ascii_case(&broadcaster) {
        die(format!(
            "settlement broadcaster {broadcaster} is not the deployer of backing rollup \
             {backing_rollup_hex} (on-chain deployer {rollup_deployer}); registerChannel and \
             registerSettlementManager would revert"
        ));
    }
    let validity_bypass = cast_call(rpc, &backing_rollup_hex, "allowMleDisabled()(bool)", &[]);
    if validity_bypass != "false" {
        die(format!(
            "backing rollup {backing_rollup_hex} is not production-validity enabled \
             (allowMleDisabled returned {validity_bypass:?})"
        ));
    }
    require_true(
        rpc,
        &backing_rollup_hex,
        "withdrawalVkInitialized()(bool)",
        "The existing rollup must have its real withdrawal VK before a settlement manager is attached.",
    );
    let kzg = cast_call(rpc, &backing_rollup_hex, "kzgVerifier()(address)", &[]);
    if strip0x(&kzg).trim_matches('0').is_empty() {
        die(format!(
            "backing rollup {backing_rollup_hex} has no KZG verifier"
        ));
    }
    let resume_prepared = state
        .settlement_binding
        .as_ref()
        .is_some_and(|binding| binding.status == SettlementBindingStatus::Prepared);
    stage_close_backing_bundle(
        &contracts_dir,
        resume_prepared,
        chain_id,
        &backing_rollup_hex,
        channel_id,
    );
    let data_dir = contracts_dir.join("test").join("data");
    let reg_path = data_dir.join("cli_reg_record.json");
    fs::write(
        &reg_path,
        serde_json::to_string_pretty(&reg).unwrap_or_else(|e| die(e)),
    )
    .unwrap_or_else(|e| die(format!("write {}: {e}", reg_path.display())));
    eprintln!(
        "[deploy-settlement] staged {} (channel {channel_id}, {} cosigners + {} delegates, existing rollup {})",
        reg_path.display(),
        reg["member_count"],
        reg["active_delegate_count"],
        backing_rollup_hex
    );

    // The PREPARED write below is the point of no return for participant joins.  It includes the
    // exact chain/signer/start nonce and local-input digest, and is fsynced before Forge can send
    // transaction zero.  An existing PREPARED binding always selects --resume; it never starts a
    // fresh script run with shifted nonces and orphan CREATE addresses.
    let deploy_mode = prepare_real_settlement_binding(
        rpc,
        &contracts_dir,
        &mut state,
        &reg,
        &backing_rollup_hex,
        chain_id,
        &broadcaster,
    );
    let deployment_intent = state
        .settlement_binding
        .as_ref()
        .and_then(|binding| binding.deployment.clone())
        .unwrap_or_else(|| die("PREPARED production settlement lost its deployment identity"));

    let before_resume = if deploy_mode == RealSettlementDeployMode::Resume {
        Some(
            validate_settlement_broadcast_artifact(
                &contracts_dir,
                &deployment_intent,
                &reg,
                &backing_rollup_hex,
            )
            .unwrap_or_else(|e| {
                die(format!(
                    "refusing `forge --resume`: the pinned broadcast artifact failed validation: \
                     {e}. No fresh deployment will be attempted."
                ))
            }),
        )
    } else {
        None
    };
    let already_complete = before_resume.as_ref().is_some_and(|addresses| {
        settlement_registration_receipt(rpc, &deployment_intent, &backing_rollup_hex, addresses)
            .is_some()
    });

    if already_complete {
        eprintln!(
            "[deploy-settlement] the pinned final registerSettlementManager transaction is already \
             canonical and finalized; skipping --resume and proceeding to checkpoint-pinned readback"
        );
    } else {
        let mut forge = Command::new("forge");
        forge.current_dir(&contracts_dir).args([
            "script",
            plan.script(),
            "--tc",
            plan.contract(),
            "--rpc-url",
            rpc,
            "--broadcast",
            // Sequential broadcast: the deploy's transactions are dependent (VK latches and
            // registrations target contracts created earlier in the same run), and a public
            // network can reorder or drop a parallel batch.
            "--slow",
            "--code-size-limit",
            "50000",
        ]);
        if deploy_mode == RealSettlementDeployMode::Resume {
            forge.arg("--resume");
            eprintln!(
                "[deploy-settlement] resuming the validated pinned Foundry run at start nonce {}",
                deployment_intent.start_nonce
            );
        }
        l1_signer.append_to_command(&mut forge);
        let forge_out = forge
            .env("EXISTING_ROLLUP", &backing_rollup_hex)
            .env("EXPECTED_BROADCASTER", &broadcaster)
            .output()
            .unwrap_or_else(|e| die(format!("forge script failed to start: {e}")));
        if !forge_out.status.success() {
            die(format!(
                "forge deploy-settlement ({}) FAILED while cli_state remains PREPARED. A retry \
                 will validate and resume only the pinned artifact; it will never start a new \
                 nonce sequence.\nstdout: {}\nstderr: {}",
                plan.script(),
                String::from_utf8_lossy(&forge_out.stdout),
                String::from_utf8_lossy(&forge_out.stderr)
            ));
        }
    }

    // Never trust console text for addresses, especially on --resume (which may print none). The
    // exact transaction artifact names the CREATE results and is checked against every CALL target
    // and ABI payload before any address reaches the durable ACTIVE record.
    let addresses = validate_settlement_broadcast_artifact(
        &contracts_dir,
        &deployment_intent,
        &reg,
        &backing_rollup_hex,
    )
    .unwrap_or_else(|e| die(format!("post-broadcast artifact validation failed: {e}")));
    let rollup = backing_rollup_hex;
    let registration_receipt = settlement_registration_receipt(
        rpc,
        &deployment_intent,
        &rollup,
        &addresses,
    )
    .unwrap_or_else(|| {
        die(
            "the pinned registerSettlementManager transaction has no canonical finalized receipt; \
             cli_state remains PREPARED and a retry will reconcile the same artifact",
        )
    });
    let activation_checkpoint = registration_receipt.finalized_checkpoint;
    let mle_verifier = addresses.mle_verifier;
    let verifier = addresses.verifier;
    let manager = addresses.manager;
    let materializer = addresses.materializer;

    // ── Read the whole exit checklist back FROM THE CHAIN. ──
    //
    // SECURITY / LIVENESS: not a duplicate of the script's own `require`s. This is the CLI
    // asserting, against the deployed bytecode, that every latch an honest exit depends on is set
    // BEFORE it records an address an operator will fund. Each item below was, at some point in
    // this repository's history, exactly the thing that was missing on a real deployment while the
    // deploy "succeeded": the withdrawal VK (money in, no money out), `registerSettlementManager`
    // (pw-finalize reverts after the user waited out the challenge period), and the
    // cancel-close / post-close-claim VKs (audit622 A-M4).
    for address in [&mle_verifier, &verifier, &manager, &materializer] {
        if strip0x(&cast_code_at(
            rpc,
            address,
            activation_checkpoint.block_number,
        ))
        .is_empty()
        {
            die(format!(
                "post-deploy check FAILED: {address} has no code at finalized activation block {}",
                activation_checkpoint.block_number
            ));
        }
    }
    let runtime_code_hashes = SettlementRuntimeCodeHashes {
        rollup: settlement_runtime_code_hash_at(rpc, &rollup, activation_checkpoint.block_number),
        verifier: settlement_runtime_code_hash_at(
            rpc,
            &verifier,
            activation_checkpoint.block_number,
        ),
        manager: settlement_runtime_code_hash_at(rpc, &manager, activation_checkpoint.block_number),
        materializer: settlement_runtime_code_hash_at(
            rpc,
            &materializer,
            activation_checkpoint.block_number,
        ),
    };
    require_true_at(
        rpc,
        &rollup,
        "withdrawalVkInitialized()(bool)",
        "Without the rollup's withdrawal VK, `withdrawNative`/`withdrawERC20` revert \
         WithdrawalVkNotSet() forever and the rollup can accept deposits it can never pay out.",
        &activation_checkpoint,
    );
    require_true_at(
        rpc,
        &materializer,
        "backingVkInitialized()(bool)",
        "Without the distinct CloseAssetBacking VK, an N-of-N signed head can close but its exact whole-token vector can never be materialized into Rollup withdrawals.",
        &activation_checkpoint,
    );
    let backing_mle_verifier = cast_call_at(
        rpc,
        &materializer,
        "backingMleVerifier()(address)",
        &[],
        activation_checkpoint.block_number,
    );
    if !backing_mle_verifier.eq_ignore_ascii_case(&mle_verifier) {
        die(format!(
            "post-deploy check FAILED: materializer {materializer} is bound to MLE verifier \
             {backing_mle_verifier}, not the verifier {mle_verifier} created and pinned by this run"
        ));
    }
    let registered = cast_call_at(
        rpc,
        &rollup,
        "isRegisteredSettlementManager(address)(bool)",
        &[&manager],
        activation_checkpoint.block_number,
    );
    if registered != "true" {
        die(format!(
            "post-deploy check FAILED: rollup {rollup} does not list manager {manager} as a \
             registered settlement manager (got {registered:?}).\n\
             `finalizePartialWithdrawal` would revert NotRegisteredSettlementManager() AFTER the \
             user submitted an intent and waited out the full challenge period."
        ));
    }
    let commitment = cast_call_at(
        rpc,
        &rollup,
        "channelMemberSetCommitment(uint32)(bytes32)",
        &[&channel_id.to_string()],
        activation_checkpoint.block_number,
    );
    if commitment
        .trim_start_matches("0x")
        .trim_matches('0')
        .is_empty()
    {
        die(format!(
            "post-deploy check FAILED: channel {channel_id} has no member-set commitment on rollup \
             {rollup} (got {commitment:?}) — registerChannel did not take effect for THIS channel \
             id, so no close proof for it could ever verify."
        ));
    }
    for (sig, what) in [
        (
            "closeVkInitialized()(bool)",
            "Without the close VK, `submitCloseIntent` reverts CloseVkNotSet(): the channel can never be closed.",
        ),
        (
            "cancelCloseVkInitialized()(bool)",
            "Without the cancel-close VK, `cancelClose` reverts CancelCloseVkNotSet(): a stale or hostile close intent can never be un-frozen (audit622 A-M4).",
        ),
        (
            "withdrawalClaimVkInitialized()(bool)",
            "Without the withdrawal-claim VK, `submitWithdrawalClaim` reverts WithdrawalClaimVkNotSet(): members can close the channel and then never collect.",
        ),
        (
            "postCloseClaimVkInitialized()(bool)",
            "Without the post-close-claim VK, `post-close-claim` reverts PostCloseClaimVkNotSet(): a member who missed the close can never claim.",
        ),
    ] {
        require_true_at(rpc, &verifier, sig, what, &activation_checkpoint);
    }
    let bound_verifier = cast_call_at(
        rpc,
        &manager,
        "verifier()(address)",
        &[],
        activation_checkpoint.block_number,
    );
    if !bound_verifier.eq_ignore_ascii_case(&verifier) {
        die(format!(
            "post-deploy check FAILED: manager {manager} is bound to verifier {bound_verifier}, \
             not to the {verifier} this run just keyed. The VKs checked above would gate a \
             DIFFERENT contract than the one the manager consults."
        ));
    }
    let bound_materializer = cast_call_at(
        rpc,
        &manager,
        "closeFundingMaterializer()(address)",
        &[],
        activation_checkpoint.block_number,
    );
    if !bound_materializer.eq_ignore_ascii_case(&materializer) {
        die(format!(
            "post-deploy check FAILED: manager {manager} is bound to close-funding materializer \
             {bound_materializer}, not the pinned deployment {materializer}"
        ));
    }
    let materializer_rollup = cast_call_at(
        rpc,
        &materializer,
        "rollup()(address)",
        &[],
        activation_checkpoint.block_number,
    );
    if !materializer_rollup.eq_ignore_ascii_case(&rollup) {
        die(format!(
            "post-deploy check FAILED: close-funding materializer {materializer} is bound to \
             rollup {materializer_rollup}, not the channel backing rollup {rollup}"
        ));
    }
    let bound_channel = cast_call_at(
        rpc,
        &manager,
        "channelId()(bytes4)",
        &[],
        activation_checkpoint.block_number,
    );
    let expect_channel = format!("0x{channel_id:08x}");
    if !bound_channel.eq_ignore_ascii_case(&expect_channel) {
        die(format!(
            "post-deploy check FAILED: manager {manager} is bound to channel {bound_channel}, but \
             this working directory operates channel {channel_id} ({expect_channel}). \
             INTMAX_CHANNEL and the deployed manager disagree."
        ));
    }
    let expected_root = reg["participant_root"]
        .as_str()
        .unwrap_or_else(|| die("staged record missing participant_root"));
    let bound_root = cast_call_at(
        rpc,
        &manager,
        "participantRoot()(bytes32)",
        &[],
        activation_checkpoint.block_number,
    );
    if !bound_root.eq_ignore_ascii_case(expected_root) {
        die(format!(
            "post-deploy check FAILED: manager participant root {bound_root} != signed snapshot \
             root {expected_root}"
        ));
    }
    let expected_members = reg["member_count"]
        .as_u64()
        .unwrap_or_else(|| die("staged record missing member_count"));
    let expected_delegates = reg["active_delegate_count"]
        .as_u64()
        .unwrap_or_else(|| die("staged record missing active_delegate_count"));
    let bound_participants = cast_call_at(
        rpc,
        &manager,
        "activeParticipantCount()(uint16)",
        &[],
        activation_checkpoint.block_number,
    );
    let bound_members = cast_call_at(
        rpc,
        &manager,
        "activeMemberCount()(uint8)",
        &[],
        activation_checkpoint.block_number,
    );
    let bound_delegates = cast_call_at(
        rpc,
        &manager,
        "activeDelegateCount()(uint16)",
        &[],
        activation_checkpoint.block_number,
    );
    if bound_participants != (expected_members + expected_delegates).to_string()
        || bound_members != expected_members.to_string()
        || bound_delegates != expected_delegates.to_string()
    {
        die(format!(
            "post-deploy check FAILED: manager counts participant={bound_participants}, \
             member={bound_members}, delegate={bound_delegates}; signed snapshot requires \
             participant={}, member={expected_members}, delegate={expected_delegates}",
            expected_members + expected_delegates
        ));
    }
    let active_count = usize::try_from(expected_members + expected_delegates)
        .unwrap_or_else(|_| die("signed participant count does not fit usize"));
    let member_count = usize::try_from(expected_members)
        .unwrap_or_else(|_| die("signed member count does not fit usize"));
    let pk_gs =
        settlement_reg_string_vec(&reg, "member_pk_gs", active_count).unwrap_or_else(|e| die(e));
    let recipients =
        settlement_reg_string_vec(&reg, "recipients", active_count).unwrap_or_else(|e| die(e));
    for slot in 0..member_count {
        let bound_recipient = cast_call_at(
            rpc,
            &manager,
            "registeredRecipientOf(bytes32)(address)",
            &[&pk_gs[slot]],
            activation_checkpoint.block_number,
        );
        let bound_index = cast_call_at(
            rpc,
            &manager,
            "registeredMemberIndexPlusOne(bytes32)(uint256)",
            &[&pk_gs[slot]],
            activation_checkpoint.block_number,
        );
        let recipient_is_member = cast_call_at(
            rpc,
            &manager,
            "isMemberRecipient(address)(bool)",
            &[&recipients[slot]],
            activation_checkpoint.block_number,
        );
        if strip0x(&bound_recipient) != strip0x(&recipients[slot])
            || bound_index != (slot + 1).to_string()
            || recipient_is_member != "true"
        {
            die(format!(
                "post-deploy check FAILED: signed cosigner slot {slot} pk_g {} / recipient {} \
                 was not preserved exactly (recipient={bound_recipient}, index={bound_index}, \
                 memberRecipient={recipient_is_member})",
                pk_gs[slot], recipients[slot]
            ));
        }
    }

    // Reported, not asserted: the floor is enforced by the manager's own constructor off-devnet
    // (`CHALLENGE_PERIOD_SECS_FLOOR`), so re-checking it here would duplicate a gate rather than
    // add one — but an operator must be told, because it is the delay before `settle` can succeed.
    let challenge_period = cast_call_at(
        rpc,
        &manager,
        "challengePeriod()(uint64)",
        &[],
        activation_checkpoint.block_number,
    );

    // One final reread proves every historical call above came from one still-current durable
    // authority. If `finalized` advanced or the stored height changed while the checklist ran,
    // keep PREPARED and repeat all reads from the new checkpoint rather than mixing heads.
    require_stable_durable_l1_checkpoint(rpc, &activation_checkpoint);

    // Complete the PREPARED freeze. `save_state` is atomic + fsync-backed; only after ACTIVE lands
    // may the convenience address file announce success. The join gate was already closed before
    // broadcast, so a crash at either boundary remains fail-closed.
    activate_settlement_binding(
        &mut state,
        &reg,
        &rollup,
        &verifier,
        &manager,
        &materializer,
        Some(activation_checkpoint),
        Some(runtime_code_hashes),
    );
    write_json(
        "settlement.json",
        &serde_json::json!({
            "manager": manager,
            "verifier": verifier,
            "mle_verifier": mle_verifier,
            "rollup": rollup,
            "close_funding_materializer": materializer,
            "activation_checkpoint": activation_checkpoint,
            "runtime_code_hashes": runtime_code_hashes,
        }),
    );
    println!(
        "deploy-settlement OK (real chain {chain_id}): manager={manager}, verifier={verifier}, \
         materializer={materializer}, rollup={rollup}\n\
         Verified on-chain: withdrawal VK set, the distinct CloseAssetBacking VK and all four settlement VKs set, channel {channel_id} \
         registered, manager registered as a settlement authorizer, participant root/count match \
         the signed live snapshot, and delegate joins are durably frozen in cli_state.json. All \
         activation reads were pinned to finalized block {} ({}).\n\
         The manager is attached to the EXISTING backing rollup {rollup}; no escrow moved and no \
         replacement rollup was created.\n\
         NOTE: this manager's challenge period is {challenge_period} seconds (read back from the \
         chain) — off-devnet a close takes that long to finalize, by design.",
        activation_checkpoint.block_number, activation_checkpoint.block_hash,
    );
}

/// `keccak256("Deposited(uint64,address,bytes32,uint32,uint256,bytes32,bytes32)")` — topic0 of
/// `IntmaxRollup.Deposited` (IntmaxRollup.sol:129). Re-derive with:
///   `cast sig-event "Deposited(uint64,address,bytes32,uint32,uint256,bytes32,bytes32)"`
/// SECURITY: if this constant were ever wrong, NO log would match and every import would refuse
/// (fail-closed) — the faucet E2E's real ERC-20 deposit is the live proof that it is right.
const DEPOSITED_TOPIC0: &str = "0x35cffad0c6ce159deaf160c503b69a374a9751e480083db7e6849e00f1a2c4fe";

/// Reorg-safety default for a real (non-dev) chain, and the floor an explicit argument is clamped
/// up to. Chain id 31337 (anvil) uses floor 0 — see `min_confirmations_for`.
const DEFAULT_MIN_CONFIRMATIONS: u64 = 12;

/// ONE `Deposited` log, read back from L1. Every economically meaningful field of the imported
/// `Deposit` comes from HERE — none of it is caller-supplied any more (threat model §1, A9).
struct OnChainDeposit {
    deposit_index: u64,
    depositor: Address,
    token_index: u32,
    amount: u64,
    aux_data: Bytes32,
    /// `newDepositHashChain` emitted by this exact log. The keyless producer recomputes and
    /// reconciles it before sealing the deposit block.
    deposit_hash_chain: Bytes32,
    /// The chain the deposit was read from — carried so the replay-ledger key is scoped to the
    /// SAME chain the verification ran against (one `cast chain-id`, not two).
    chain_id: u64,
}

/// Strip an optional `0x` and require exactly `n` lowercase-able hex chars.
fn hex_body<'a>(s: &'a str, n: usize, what: &str) -> &'a str {
    let b = s.strip_prefix("0x").unwrap_or(s);
    if b.len() != n || !b.chars().all(|c| c.is_ascii_hexdigit()) {
        die(format!("{what}: expected {n} hex chars, got {s:?}"));
    }
    b
}

/// Parse a 32-byte ABI word as a `u64`, refusing (rather than truncating) anything wider.
/// SECURITY: a silent truncation here would credit a WRONG amount / index — worse than refusing.
fn abi_word_u64(word: &str, what: &str) -> u64 {
    let w = hex_body(word, 64, what);
    if w[..48].chars().any(|c| c != '0') {
        die(format!(
            "{what} exceeds u64 (0x{w}) — refusing rather than truncating"
        ));
    }
    u64::from_str_radix(&w[48..], 16).unwrap_or_else(|e| die(format!("{what}: {e}")))
}

/// The reorg depth this chain requires. Anvil (31337) mines instantly and has no reorg model, so
/// depth is meaningless there and the floor is 0; every OTHER chain floors at 1 and defaults to
/// [`DEFAULT_MIN_CONFIRMATIONS`]. An explicit argument is honored but CLAMPED UP to the floor:
/// an operator may knowingly tune 12 -> 3, and can NEVER tune a public chain down to 0.
/// SECURITY: this relaxes only REORG DEPTH on a dev chain, never authenticity — the tx must still
/// exist, be mined, and have `status == 1` everywhere. This is NOT an on-chain-check bypass.
fn min_confirmations_for(chain_id: u64, explicit: Option<u64>) -> u64 {
    let floor = if chain_id == 31337 { 0 } else { 1 };
    match explicit {
        Some(v) => v.max(floor),
        None => {
            if chain_id == 31337 {
                0
            } else {
                DEFAULT_MIN_CONFIRMATIONS
            }
        }
    }
}

/// Read the `Deposited` log of `tx_hash` from the chain and validate it against THIS channel.
///
/// SECURITY (the whole point of this function): the deposit's economics are sourced from the
/// chain, never from argv. Refuses fail-closed on: a nonexistent/unmined tx, a reverted tx, an
/// under-confirmed tx, a log from a contract other than the channel's own rollup, a log whose
/// `recipient` is not the channel's `deposit_recipient` (a deposit made for ANOTHER channel), and
/// on ZERO or SEVERAL matching logs (ambiguity).
fn fetch_onchain_deposit(
    rpc: &str,
    tx_hash: &str,
    rollup: &str,
    deposit_recipient: Bytes32,
    explicit_min_conf: Option<u64>,
) -> OnChainDeposit {
    // Shape-validate BEFORE handing it to `cast`: a leading '-' could otherwise be read as a flag.
    let tx = format!("0x{}", hex_body(tx_hash, 64, "tx_hash"));
    let rollup_body = hex_body(rollup, 40, "rollup address from channel_backing.json");

    // `--async` is MANDATORY: without it `cast receipt` BLOCKS FOREVER waiting for an unknown tx,
    // which would turn a refusal into a hang (threat model A1).
    let receipt_raw = cast(&["receipt", &tx, "--rpc-url", rpc, "--json", "--async"]);
    let receipt: serde_json::Value = serde_json::from_str(&receipt_raw)
        .unwrap_or_else(|e| die(format!("parse `cast receipt` JSON: {e}\n{receipt_raw}")));

    let status = receipt["status"].as_str().unwrap_or("");
    if status != "0x1" {
        die(format!(
            "deposit tx {tx} did not succeed (status {status}) — refusing to import a reverted deposit"
        ));
    }
    // SECURITY: parse STRICTLY. An earlier version used `unwrap_or(0)` here, which would silently
    // treat an unparseable blockNumber as block 0 and make `confirmations = head + 1` — i.e. the
    // depth check would pass unconditionally. This is the one place where a permissive default
    // would disable a check, so it dies instead.
    let tx_block = match receipt["blockNumber"].as_str() {
        Some(s) => u64::from_str_radix(s.trim_start_matches("0x"), 16)
            .unwrap_or_else(|e| die(format!("unparseable blockNumber {s:?} on tx {tx}: {e}"))),
        None => die(format!("deposit tx {tx} is not mined yet (no blockNumber)")),
    };

    let chain_id: u64 = cast(&["chain-id", "--rpc-url", rpc])
        .trim()
        .parse()
        .unwrap_or_else(|e| die(format!("parse chain-id: {e}")));
    let head: u64 = cast(&["block-number", "--rpc-url", rpc])
        .trim()
        .parse()
        .unwrap_or_else(|e| die(format!("parse block-number: {e}")));
    let min_conf = min_confirmations_for(chain_id, explicit_min_conf);
    let confirmations = head.saturating_sub(tx_block) + 1;
    if confirmations < min_conf {
        die(format!(
            "deposit tx {tx} has {confirmations} confirmation(s), need {min_conf} on chain \
             {chain_id} (reorg safety) — refusing"
        ));
    }

    let logs = receipt["logs"]
        .as_array()
        .unwrap_or_else(|| die(format!("deposit tx {tx} receipt has no logs array")));

    // Filter to OUR rollup's `Deposited` logs for THIS channel's deposit recipient.
    let mut matching: Vec<&serde_json::Value> = Vec::new();
    let mut saw_deposited_for_other_recipient = 0usize;
    for log in logs {
        let addr = log["address"].as_str().unwrap_or("");
        let topics = log["topics"].as_array().cloned().unwrap_or_default();
        let topic0 = topics.first().and_then(|t| t.as_str()).unwrap_or("");
        // Contract binding (A3): only the channel's OWN rollup may source a deposit — not just any
        // contract that emits a similarly-shaped event.
        if !addr.eq_ignore_ascii_case(&format!("0x{rollup_body}")) {
            continue;
        }
        if !topic0.eq_ignore_ascii_case(DEPOSITED_TOPIC0) {
            continue;
        }
        let data = log["data"].as_str().unwrap_or("");
        let body = data.strip_prefix("0x").unwrap_or(data);
        if body.len() < 64 * 6 {
            die(format!("malformed Deposited log data in tx {tx}"));
        }
        let recipient = Bytes32::from_hex(&format!("0x{}", abi_word(body, 1)))
            .unwrap_or_else(|e| die(format!("parse Deposited.recipient: {e:?}")));
        // Channel binding (A4): a deposit made for ANOTHER channel must not be importable here.
        if recipient != deposit_recipient {
            saw_deposited_for_other_recipient += 1;
            continue;
        }
        matching.push(log);
    }

    if matching.is_empty() {
        die(format!(
            "tx {tx} contains no `Deposited` log from rollup 0x{rollup_body} for this channel's \
             deposit_recipient {} ({saw_deposited_for_other_recipient} Deposited log(s) were for a \
             DIFFERENT recipient) — refusing",
            deposit_recipient.to_hex()
        ));
    }
    // FAIL CLOSED on ambiguity (A5): no disambiguation parameter is offered, so there is no lever
    // to misuse. Deposit each amount in its own transaction.
    if matching.len() > 1 {
        die(format!(
            "tx {tx} contains {} `Deposited` logs for this channel — ambiguous, refusing to guess \
             which one to import",
            matching.len()
        ));
    }

    let log = matching[0];
    let topics = log["topics"].as_array().cloned().unwrap_or_default();
    let index_topic = topics
        .get(1)
        .and_then(|t| t.as_str())
        .unwrap_or_else(|| die("Deposited log has no indexed depositIndex topic"));
    let deposit_index = abi_word_u64(index_topic, "Deposited.depositIndex");

    let data = log["data"].as_str().unwrap_or("");
    let body = data.strip_prefix("0x").unwrap_or(data);
    let depositor = Address::from_hex(&format!("0x{}", &abi_word(body, 0)[24..]))
        .unwrap_or_else(|e| die(format!("parse Deposited.depositor: {e:?}")));
    // `uint32` on-chain, but narrow it CHECKED rather than with `as` — no silent truncation
    // anywhere in this function.
    let token_index = u32::try_from(abi_word_u64(abi_word(body, 2), "Deposited.tokenIndex"))
        .unwrap_or_else(|_| die("Deposited.tokenIndex exceeds u32"));
    // The import encrypts a u64 amount; refuse anything wider rather than truncating (A11).
    let amount = abi_word_u64(abi_word(body, 3), "Deposited.amount");
    let aux_data = Bytes32::from_hex(&format!("0x{}", abi_word(body, 4)))
        .unwrap_or_else(|e| die(format!("parse Deposited.auxData: {e:?}")));
    let deposit_hash_chain = Bytes32::from_hex(&format!("0x{}", abi_word(body, 5)))
        .unwrap_or_else(|e| die(format!("parse Deposited.newDepositHashChain: {e:?}")));

    eprintln!(
        "cosign-l1-deposit-import: verified on-chain deposit #{deposit_index} in tx {tx} \
         (chain {chain_id}, {confirmations} conf, rollup 0x{rollup_body}): depositor {}, \
         token_index {token_index}, amount {amount}.",
        depositor.to_hex()
    );

    OnChainDeposit {
        deposit_index,
        depositor,
        token_index,
        amount,
        aux_data,
        deposit_hash_chain,
        chain_id,
    }
}

/// Read one canonical on-chain `Deposited` log and emit the exact request accepted by the
/// keyless production block producer. This keeps receipt parsing in one hardened Rust path; the
/// API never reinterprets ABI words in JavaScript.
fn cmd_inspect_l1_deposit(args: &[String]) {
    const USAGE: &str = "inspect-l1-deposit <tx_hash> <rpc_url> [out.json] [min_confirmations]";
    let tx_hash = args.get(1).unwrap_or_else(|| die(USAGE));
    let rpc = args.get(2).unwrap_or_else(|| die(USAGE));
    let out_path = args
        .get(3)
        .map(String::as_str)
        .unwrap_or("producer_deposit.json");
    let explicit_min_conf = args
        .get(4)
        .map(|value| value.parse::<u64>().unwrap_or_else(|_| die(USAGE)));
    if args.len() > 5 {
        die(USAGE);
    }
    let (_, _, backing) = load_backing();
    let deposit_recipient = Bytes32::from_hex(&backing.deposit_recipient)
        .unwrap_or_else(|e| die(format!("parse deposit_recipient from backing: {e:?}")));
    if backing.rollup.is_empty() {
        die("channel_backing.json has no rollup address — cannot verify the deposit on-chain");
    }
    let onchain = fetch_onchain_deposit(
        rpc,
        tx_hash,
        &backing.rollup,
        deposit_recipient,
        explicit_min_conf,
    );
    let request = ProductionDepositRequest {
        deposit_index: onchain.deposit_index,
        depositor: onchain.depositor,
        recipient: deposit_recipient,
        token_index: onchain.token_index,
        amount: U256::from(onchain.amount),
        aux_data: onchain.aux_data,
        expected_deposit_hash_chain: onchain.deposit_hash_chain,
    };
    write_json(out_path, &request);
    println!(
        "{}",
        serde_json::to_string(&request).unwrap_or_else(|e| die(e))
    );
}

/// Co-sign an L1 deposit import (mid-channel deposit): fold a REAL, on-chain-verified deposit into
/// the channel's balance without closing. Usage:
///   channel_member cosign-l1-deposit-import <recipient_slot|auto> <tx_hash> <rpc_url> \
///       [out.json] [min_confirmations] [--allow-unbound-depositor] \
///       [--intmax-block-number=N]
///
/// SECURITY (the fix): `amount`, `depositor` and `token_index` are NO LONGER caller-supplied —
/// they are read from the transaction's `Deposited` log. The ability to lie about them was
/// REMOVED rather than cross-checked. `token_index` still resolves against the channel's active
/// registry, and an UNREGISTERED index is refused fail-closed (TM-7).
///
/// `recipient_slot` may be `auto`, which resolves to the unique active slot whose B-1b bound
/// recipient equals the on-chain depositor.
fn cmd_cosign_l1_deposit_import(args: &[String]) {
    const USAGE: &str = "cosign-l1-deposit-import <recipient_slot|auto> <tx_hash> <rpc_url> \
                         [out.json] [min_confirmations] [--allow-unbound-depositor] \
                         [--intmax-block-number=N]";

    // Flags are position-independent; positional args are the non-flag remainder.
    // SECURITY: an UNKNOWN `--flag` is refused rather than ignored. Silently dropping it would let
    // a mistyped or misremembered option (e.g. `--min-confirmations=0`) look accepted while having
    // no effect — the operator would believe they set a policy they did not.
    if let Some(bad) = args.iter().skip(1).find(|a| {
        a.starts_with("--")
            && a.as_str() != "--allow-unbound-depositor"
            && !a.starts_with("--intmax-block-number=")
    }) {
        die(format!("unknown flag {bad:?}\nusage: {USAGE}"));
    }
    let allow_unbound = args.iter().any(|a| a == "--allow-unbound-depositor");
    let intmax_block_number = args
        .iter()
        .filter_map(|arg| arg.strip_prefix("--intmax-block-number="))
        .map(|value| {
            value
                .parse::<u64>()
                .unwrap_or_else(|_| die("--intmax-block-number must be a u63 decimal"))
        })
        .collect::<Vec<_>>();
    if intmax_block_number.len() > 1 {
        die("--intmax-block-number may be specified only once");
    }
    let intmax_block_number = intmax_block_number.first().copied().unwrap_or_default();
    if intmax_block_number == 0 {
        eprintln!(
            "cosign-l1-deposit-import WARNING: no producer-assigned INTMAX block number was \
             supplied; this legacy/unassigned deposit cannot match a live receive_deposit proof"
        );
    }
    let pos: Vec<&String> = args
        .iter()
        .skip(1)
        .filter(|a| !a.starts_with("--"))
        .collect();

    let slot_arg = pos.first().unwrap_or_else(|| die(USAGE));
    let tx_hash = pos.get(1).unwrap_or_else(|| die(USAGE));
    let rpc = pos.get(2).unwrap_or_else(|| die(USAGE));
    let out_path = pos
        .get(3)
        .map(|s| s.as_str())
        .unwrap_or("l1_import_cosigned.json");
    let explicit_min_conf: Option<u64> = pos
        .get(4)
        .map(|s| s.parse().unwrap_or_else(|_| die("bad [min_confirmations]")));

    let (_, _, backing) = load_backing();
    let deposit_recipient = Bytes32::from_hex(&backing.deposit_recipient)
        .unwrap_or_else(|e| die(format!("parse deposit_recipient from backing: {e:?}")));
    if backing.rollup.is_empty() {
        die("channel_backing.json has no rollup address — cannot verify the deposit on-chain");
    }

    // ── BACKING-DEPOSIT GUARD (adversarial review finding 5; deposit-import-threat-model.md §10)
    // The channel's OWN backing deposits are real `Deposited` logs from this rollup to this
    // `deposit_recipient`, so they pass every check in `fetch_onchain_deposit`. But their value is
    // ALREADY counted — the `setup-backing` deposit by the genesis fund, `withdraw`'s deposits by
    // the withdrawal proof — so importing one credits the channel twice against a single L1
    // escrow and (per §10.5) irreversibly wedges the channel's exit. Refuse them by name.
    //
    // SECURITY (§10.6, the shape of this guard): the check is in TWO parts, and both must run.
    //  1. SET MEMBERSHIP over every hash we know — unconditional. It used to be `if
    //     !deposit_tx.is_empty() && …`, i.e. a guard that DISARMED ITSELF whenever the one recorded
    //     hash was missing, which was every deferred-mode channel and (via §10.4) every channel's
    //     `withdraw` deposit in EVERY mode.
    //  2. APPLICABILITY — a stated conclusion about whether a backing deposit exists at all. An
    //     empty set is only acceptable when the CLI can positively say "none is on-chain yet".
    let known_backing_txs = backing.known_backing_deposit_txs();
    if known_backing_txs.contains(&strip0x(tx_hash)) {
        die(
            "REFUSING: this is the channel's BACKING deposit (channel_backing.json \
             backing_deposit_txs/deposit_tx). Its value is already counted against the channel's \
             L1 escrow — importing it would credit the channel twice against one escrow.",
        );
    }
    match backing.resolved_backing_deposit_status() {
        // The set is authoritative and non-empty: the guard above really compared something.
        BackingDepositStatus::Landed if !known_backing_txs.is_empty() => {}
        // "Landed" with nothing to compare against is a self-contradictory record: a backing
        // deposit exists on-chain but we cannot name it, so we cannot tell this import apart from
        // it. FAIL CLOSED rather than let the guard evaluate to a vacuous truth.
        BackingDepositStatus::Landed => die(
            "REFUSING: channel_backing.json says the backing deposit has LANDED but records no \
             transaction hash for it — the backing-deposit guard cannot tell this import apart \
             from the channel's own deposit. Re-run `setup-backing`, or add the hash to \
             `backing_deposit_txs`. Fail-closed.",
        ),
        // NOT APPLICABLE, and we say so. `setup-backing` deferred the deposit to `withdraw`, so
        // no backing deposit is on-chain yet and no import can be one. This is a genuine, safe
        // flow (mid-channel imports before `withdraw` runs — `tests/itx_faucet_cli_e2e.rs`), and
        // blanket-failing-closed on an empty set would refuse it. The note exists so that "the
        // guard did not run" is never indistinguishable from "the guard ran and passed".
        BackingDepositStatus::Deferred => eprintln!(
            "cosign-l1-deposit-import SECURITY NOTE: the backing-deposit guard is NOT APPLICABLE \
             here — channel_backing.json records backing_deposit_status=deferred, i.e. \
             `setup-backing` deferred the on-chain deposit to `withdraw` and no backing deposit \
             exists on-chain yet, so this import cannot be one. The guard re-arms automatically \
             once `withdraw` makes (and records) the deposit."
        ),
        // Pre-dates the field and carries no evidence either way. FAIL CLOSED: this is the state
        // in which the old code silently skipped the guard.
        BackingDepositStatus::Unknown => die(
            "REFUSING: channel_backing.json does not record whether the channel's own backing \
             deposit is on-chain (backing_deposit_status is absent/unknown and no deposit_tx is \
             recorded). The backing-deposit guard cannot be evaluated, and a silent skip is what \
             this refusal exists to prevent (deposit-import-threat-model.md §10). Re-run \
             `setup-backing` to re-arm the guard. Fail-closed.",
        ),
    }

    let onchain = fetch_onchain_deposit(
        rpc,
        tx_hash,
        &backing.rollup,
        deposit_recipient,
        explicit_min_conf,
    );

    let mut state = load_state();

    // ── REPLAY LEDGER (threat model §4) ────────────────────────────────────────────────────
    // The channel layer has NO nullifier SET — `shared_native_nullifier_root` is a keccak CHAIN,
    // and re-folding an identical nullifier always yields a different root, so the native gate's
    // `ensure_different_root` passes on a replay BY CONSTRUCTION. This ledger is therefore the
    // only thing standing between a repeated import and a double credit. Keyed on the canonical
    // L1 deposit identity (chain-scoped contract + the contract's own monotone `depositCount`),
    // NOT on the tx hash: one transaction can carry several `Deposited` logs.
    // SECURITY (adversarial review finding 6): CANONICALIZE the rollup before keying. `hex_body`
    // accepts both `0xabc…` and `abc…`, and `setup-backing` writes `rollup` verbatim from argv —
    // so keying on the raw field would give the SAME deposit two different ledger keys under two
    // spellings, and a replay would slip through. Strip `0x` and lowercase.
    let deposit_identity = format!(
        "{}:{}:{}",
        onchain.chain_id,
        strip0x(&backing.rollup),
        onchain.deposit_index
    );
    if state.imported_deposits.contains(&deposit_identity) {
        die(format!(
            "REPLAY REFUSED: L1 deposit {deposit_identity} has already been imported into this \
             channel. A deposit is credited at most once."
        ));
    }

    // ── CREDIT BINDING (threat model §5) ───────────────────────────────────────────────────
    let balance_state = &state.snapshot.state.balance_state;
    let active = balance_state.member_count as usize + balance_state.delegate_count as usize;
    // UNCONDITIONAL: if the depositor is a channel participant's bound exit address, the deposit
    // belongs to THAT slot. No flag may redirect it — this is the leg that blocks "Mallory imports
    // Alice's genuine deposit into Mallory's slot".
    //
    // SECURITY (ambiguity, adversarial review finding 1): `join_delegate` does not enforce that
    // B-1b recipients are DISTINCT, so a joining member can declare someone else's L1 address as
    // its own bound recipient. A first-match lookup would then resolve the victim's deposit to the
    // ATTACKER's slot (and `auto` is exactly what the chain-driven co-signer path uses). So we
    // collect ALL matches and refuse on more than one — a duplicated exit address is itself the
    // attack signature, and there is no safe way to pick. `cmd_init` also rejects the duplicate at
    // join time; this is the defense-in-depth half for states created before that check existed.
    let depositor_slots: Vec<usize> = (0..active)
        .filter(|&i| balance_state.recipients[i] == onchain.depositor)
        .collect();
    if depositor_slots.len() > 1 {
        die(format!(
            "AMBIGUOUS BINDING REFUSED: the on-chain depositor {} is the bound (B-1b) recipient of \
             {} ACTIVE slots {:?}. A duplicated exit address makes the credited slot ambiguous \
             (and is how a joining member would try to capture someone else's deposit) — refusing.",
            onchain.depositor.to_hex(),
            depositor_slots.len(),
            depositor_slots
        ));
    }
    let depositor_slot = depositor_slots.first().copied();

    let recipient_slot: usize = if slot_arg.as_str() == "auto" {
        depositor_slot.unwrap_or_else(|| {
            die(format!(
                "`auto` could not resolve a slot: no ACTIVE slot's bound recipient equals the \
                 on-chain depositor {} — pass an explicit slot",
                onchain.depositor.to_hex()
            ))
        })
    } else {
        slot_arg.parse().unwrap_or_else(|_| die(USAGE))
    };
    if recipient_slot >= active {
        die(format!(
            "recipient_slot {recipient_slot} is not an ACTIVE slot (active = {active})"
        ));
    }
    match depositor_slot {
        Some(j) if j != recipient_slot => die(format!(
            "CREDIT MISDIRECTION REFUSED: the on-chain depositor {} is the bound (B-1b) recipient \
             of ACTIVE slot {j}, but this import would credit slot {recipient_slot}. This refusal \
             is unconditional — --allow-unbound-depositor does NOT override it.",
            onchain.depositor.to_hex()
        )),
        Some(_) => {}
        None => {
            // The depositor is bound to NO slot (a third party / the operator funding a slot whose
            // recipient is a synthetic address, e.g. the $ITX faucet). Allowed only when the caller
            // says so explicitly.
            //
            // WHO PASSES IT (keep in sync with doc/tasks/deposit-import-threat-model.md): the
            // server-key api routes do — `api/routes/deposit.js` (both import paths) and
            // `api/routes/channel-init.js` — because there the DEPOSITOR IS THE SERVER, not the
            // member, so its address is bound to no slot by construction. The browser relays do
            // NOT pass it: a MetaMask deposit comes from the member's own bound address.
            //
            // This flag can only widen the `None` arm above. It is NOT consulted on the
            // misdirection arm (`Some(j) if j != recipient_slot`), which dies unconditionally, so
            // it can never redirect a deposit that belongs to someone.
            if !allow_unbound {
                die(format!(
                    "REFUSING: the on-chain depositor {} is not the bound (B-1b) recipient of \
                     ACTIVE slot {recipient_slot} (which is {}), and is not bound to any slot. \
                     Pass --allow-unbound-depositor to credit a third-party/operator deposit.",
                    onchain.depositor.to_hex(),
                    balance_state.recipients[recipient_slot].to_hex()
                ));
            }
            eprintln!(
                "cosign-l1-deposit-import: WARNING — crediting slot {recipient_slot} from \
                 depositor {} which is bound to NO active slot (--allow-unbound-depositor).",
                onchain.depositor.to_hex()
            );
        }
    }

    let amount = onchain.amount;
    let token_index = onchain.token_index;
    let deposit = Deposit {
        // REAL on-chain deposit index (the contract's monotone `depositCount`): this is what makes
        // `Deposit::nullifier()` unique per real deposit. See the threat model §4 Finding A.
        deposit_index: U63::new(onchain.deposit_index)
            .unwrap_or_else(|e| die(format!("deposit_index out of range: {e:?}"))),
        // The keyless producer's deposit-only INTMAX block, never the L1 receipt block. The API
        // obtains this from the producer's durable receipt before asking members to cosign.
        block_number: intmax3_zkp::common::u63::BlockNumber::new(intmax_block_number)
            .unwrap_or_else(|e| die(format!("--intmax-block-number out of range: {e:?}"))),
        depositor: onchain.depositor,
        recipient: deposit_recipient,
        token_index,
        amount: U256::from(amount),
        aux_data: onchain.aux_data,
    };

    let snapshot = &state.snapshot;
    let bp_keys = keys_for(state.controlled[0].keygen_seed);

    let recipient_regev_pk = &snapshot.members[recipient_slot].regev_pk;
    // SECURITY: this seed is deliberately FIXED per channel, and that is safe here — unlike
    // `cmd_send`, this randomness protects nothing. It encrypts `amount`, which is a PUBLIC L1
    // deposit value (it is an argument of the `deposit()` transaction, in the deposit hash chain,
    // and in the channel's `channel_fund` in the clear). Reuse across imports can therefore leak
    // only the difference of two already-public numbers. Determinism is load-bearing instead: the
    // TM-7 co-signer gate REBUILDS this exact `recipient_delta` from its own RNG and requires
    // digest equality with the proposal (rebuild-equality), which is what refuses a divergent
    // bundle. Do not "fix" this to fresh randomness without also reworking that gate.
    let mut rng = StdRng::seed_from_u64(0xDE_0517 ^ channel_id_env() as u64);
    let (recipient_delta, _) = encrypt_amount(&mut rng, recipient_regev_pk, amount)
        .unwrap_or_else(|e| die(format!("encrypt deposit amount: {e:?}")));

    let built = build_l1_deposit_import(
        &bp_keys,
        snapshot,
        &deposit,
        recipient_slot,
        &recipient_delta,
        LEVEL,
    )
    .unwrap_or_else(|e| die(format!("build_l1_deposit_import: {e}")));

    let mut fund_state = built.fund_import_state.clone();
    let mut bundle_state = built.bundle_apply_state.clone();

    // TM-7 (two-step gate): verifies the fund-import witness AND rebuilds the canonical bundle
    // step (rebuild-equality) from this co-signer's OWN deterministic `recipient_delta`, so a
    // divergent bundle proposal (wrong credit position / doctored amount) is refused even
    // though this CLI also happens to be the builder.
    verify_l1_deposit_import_transition(
        &state.snapshot.state,
        &state.snapshot.record,
        &deposit,
        &fund_state,
        &bundle_state,
        recipient_slot,
        &recipient_delta,
    )
    .unwrap_or_else(|e| die(format!("L1 deposit import transition invalid: {e}")));

    ledger_sign_all_controlled(
        &mut state,
        &mut fund_state,
        StateSigningPurpose::L1DepositFundImport,
        None,
    );
    ledger_sign_all_controlled(
        &mut state,
        &mut bundle_state,
        StateSigningPurpose::L1DepositBundleApply,
        None,
    );
    verify_all_signatures(&state.snapshot.record, &state.snapshot.members, &fund_state)
        .unwrap_or_else(|e| die(format!("L1 fund-import state not N-of-N signed: {e}")));
    verify_all_signatures(
        &state.snapshot.record,
        &state.snapshot.members,
        &bundle_state,
    )
    .unwrap_or_else(|e| die(format!("L1 bundle-apply state not N-of-N signed: {e}")));

    state.snapshot.state = bundle_state.clone();
    // Consume the deposit in the SAME save as the new snapshot: the credit and the ledger entry
    // land together, so a crash cannot leave a credited-but-unconsumed deposit.
    state.imported_deposits.insert(deposit_identity.clone());
    save_state(&state);
    write_json("channel_snapshot.json", &state.snapshot);

    let result = serde_json::json!({
        "fundImportState": fund_state,
        "bundleApplyState": bundle_state,
        "txHash": tx_hash,
        "depositIndex": onchain.deposit_index,
        "intmaxBlockNumber": intmax_block_number,
    });
    write_json(out_path, &result);
    println!(
        "cosign-l1-deposit-import OK: slot {} received {} deposit import (base token_index {}, \
         L1 deposit {}). New state_version = {}.",
        recipient_slot,
        amount,
        token_index,
        deposit_identity,
        bundle_state.balance_state.state_version
    );
}

/// PRE-FLIGHT GUARD for `pw-submit` — the last point at which a partial withdrawal can still be
/// abandoned for free.
///
/// WHY IT EXISTS. The channel-side debit already happened at `cosign-burn-send`, so a burn whose
/// authorization no provable leaf can satisfy has spent channel value it can never redeem on L1.
/// (The manager's chain key `keccak(channelId, finalSettledTxChain)` is NO LONGER single-use — the
/// former `usedPartialWithdrawalChains` guard was removed as a fossil of the deleted proof-free
/// payout, so a bad submit is now re-submittable rather than permanently chain-locking the burn.
/// This guard therefore no longer prevents an on-chain permanent strand; it prevents wasting a
/// submit and a challenge window on an unmatchable authorization, and catches an unprovable burn
/// before any transaction.) The step is gated on the authorization being matchable, not merely
/// well-formed.
///
/// WHAT IT PROVES. The tuple `(recipient_pk_g, token_index, amount, aux_data, transfer_index=0,
/// tx_nonce, channel_id)` that produced `withdrawal.nullifier` is rebuilt into the burn's 1-tx
/// `TxV2` tree and its root compared against `head.h2_tag` — the value the N-of-N co-signers
/// signed (`h2_tag` is inside the IMCH preimage, `src/common/channel.rs:598`) and which
/// `state_update_verifier.rs:612-616` pins to the small block's `tx_tree_root`. A
/// `single_withdrawal` proof verifies its transfer against exactly that root: merkle membership in
/// `tx.transfer_tree_root` with `transfer_index` asserted zero
/// (`src/circuits/balance/send_tx_circuit.rs:277-279`), the TxV2 at index `channel_id`, and
/// `tx_v2.nonce == tx.nonce` (`single_withdrawal_circuit.rs:501`). So a match here means the very
/// fields the nullifier was computed from are the fields any provable leaf must carry.
///
/// WHY IT CANNOT PRODUCE A FALSE PASS. It is not a self-comparison: `h2_tag` is an independently
/// produced, N-of-N-signed commitment that this process did not compute, and the reconstruction
/// goes through the SAME `inter_channel_base_transfer` / `inter_channel_tx_v2` used to build the
/// original (so a passing comparison is a real preimage match, not a coincidence of two
/// re-derivations of the same wrong formula). Passing with a wrong tuple requires a Poseidon
/// collision. It fails closed in every other direction: any missing field, any mismatch, any
/// state that has moved past the burn (H2 and the chain both change on every send) aborts before
/// `forge` is invoked.
///
/// WHAT IT DOES **NOT** PROVE — stated so nobody reads more into a pass than is there: that a base
/// -layer withdrawal proof can actually be produced today. Provability additionally needs the burn
/// tx settled in a finalized block and the base account's sent-tx slot at index `nonce` empty
/// (`src/circuits/balance/spend_circuit.rs:387-395`); neither is checkable from channel state
/// alone, and `cmd_partial_withdraw` does not exist yet (`doc/tasks/todo.md:90`). This guard
/// removes the *derivation* mismatch as a stranding cause; it does not make the payout leg exist.
#[allow(clippy::too_many_arguments)]
fn preflight_burn_authorization_is_matchable(
    burn: &serde_json::Value,
    head: &ChannelState,
    channel_id: ChannelId,
    withdrawal: &Withdrawal,
    tx_leaf: Bytes32,
    pre_burn_chain: Bytes32,
    receiver_pk_g: Bytes32,
    burn_amount: u64,
    tx_nonce: u32,
) {
    let refuse = |why: String| -> ! {
        die(format!(
            "pw-submit PRE-FLIGHT REFUSED — {why}\n\
             Nothing was submitted, so the channel's single-use partial-withdrawal chain key is \
             still available and this burn can still be withdrawn once the mismatch is resolved. \
             Submitting anyway would consume that key against an authorization no withdrawal \
             proof could ever match, stranding the burned funds permanently."
        ))
    };

    // (0) A partial withdrawal is precisely a leaf with `auxData != 0` — that is the condition
    // under which `withdrawNative`/`withdrawERC20` demand the authorization as a second factor
    // (`contracts/src/IntmaxRollup.sol:1512`, `:1560`). A zero aux_data leaf needs no
    // authorization at all, so authorizing one is meaningless and burns the chain key for nothing.
    if withdrawal.aux_data == Bytes32::default() {
        refuse(
            "the burn descriptor in aux_data is zero, so this is not a partial withdrawal".into(),
        );
    }

    // (1) The head must still BE the post-burn state. Both of these move on every subsequent
    // channel transition, and the manager recomputes the chain fold itself
    // (`ChannelSettlementManager.sol:1143-1146`), so a stale head is an unmatchable intent.
    let expected_chain = settled_tx_chain_push(pre_burn_chain, withdrawal.aux_data);
    if expected_chain != head.balance_state.settled_tx_chain {
        refuse(format!(
            "push(pre_burn_chain, burn_descriptor) = {} but the channel head's settled_tx_chain is {} — \
             the channel has moved past this burn (or last_burn.json belongs to another burn)",
            expected_chain.to_hex(),
            head.balance_state.settled_tx_chain.to_hex()
        ));
    }

    // (2) THE LOAD-BEARING CHECK: the nullifier's own preimage must reproduce the co-signed H2.
    let base_transfer = inter_channel_base_transfer(
        receiver_pk_g,
        withdrawal.token_index,
        burn_amount,
        withdrawal.aux_data,
    );
    let (_, tx_v2_tree) = inter_channel_tx_v2(channel_id, &base_transfer, tx_nonce);
    let rebuilt_h2: Bytes32 = tx_v2_tree.get_root().into();
    if rebuilt_h2 != head.h2_tag {
        refuse(format!(
            "the transfer the nullifier commits to does not reproduce the co-signed h2_tag: \
             rebuilt H2 = {}, signed h2_tag = {}. The authorization would name a leaf the \
             co-signed burn tx does not contain",
            rebuilt_h2.to_hex(),
            head.h2_tag.to_hex()
        ));
    }

    // (3) Cross-check against what `cosign-burn-send` recorded at burn time, when present. Both
    // sides run the SAME `burn_withdrawal_leaf`, so a disagreement is not drift — it means the
    // artefact was edited between the two steps (a coordinator is untrusted for integrity, T7).
    // Absent fields mean a pre-2026-08-13 `last_burn.json`; checks (1) and (2) still bind.
    let recorded = |k: &str| burn[k].as_str().map(|s| s.to_string());
    if let Some(s) = recorded("tx_leaf") {
        let v = Bytes32::from_hex(&s).unwrap_or_else(|e| die(format!("parse tx_leaf: {e:?}")));
        if v != tx_leaf {
            refuse(format!(
                "last_burn.json tx_leaf {} != the one recomputed from its own ciphertext digests {}",
                v.to_hex(),
                tx_leaf.to_hex()
            ));
        }
    }
    if let Some(v) = burn["channel_id"].as_u64() {
        if v != channel_id.as_u64() {
            refuse(format!(
                "last_burn.json channel_id {v} != this CLI's channel {}",
                channel_id.as_u64()
            ));
        }
    }
    if let Some(v) = burn["tx_nonce"].as_u64() {
        if v != tx_nonce as u64 {
            refuse(format!(
                "last_burn.json tx_nonce {v} != the IMI3-bound base nonce {tx_nonce}"
            ));
        }
    }
    if let Some(v) = burn["base_nonce"].as_u64() {
        if v != tx_nonce as u64 {
            refuse(format!(
                "last_burn.json base_nonce {v} != the withdrawal TxV2 nonce {tx_nonce}"
            ));
        }
    }
    if let Some(s) = recorded("withdrawal_nullifier") {
        let v = Bytes32::from_hex(&s).unwrap_or_else(|e| die(format!("parse nullifier: {e:?}")));
        if v != withdrawal.nullifier {
            refuse(format!(
                "last_burn.json nullifier {} != the one derived here {}",
                v.to_hex(),
                withdrawal.nullifier.to_hex()
            ));
        }
    }
    if let Some(s) = recorded("withdrawal_recipient") {
        let v = Address::from_hex(&s).unwrap_or_else(|e| die(format!("parse recipient: {e:?}")));
        if v != withdrawal.recipient {
            refuse(format!(
                "last_burn.json recipient {} != the one derived here {}",
                v.to_hex(),
                withdrawal.recipient.to_hex()
            ));
        }
    }

    eprintln!(
        "pw-submit pre-flight OK: nullifier {} is the one a provable leaf carries — its preimage \
         reproduces the co-signed h2_tag {} and the chain fold matches the head.",
        withdrawal.nullifier.to_hex(),
        head.h2_tag.to_hex()
    );
}

/// Submit a partial withdrawal intent on-chain. Reads the burn metadata from `last_burn.json`
/// (written by `cosign-burn-send`) and the settlement addresses from `settlement.json`.
/// Usage:
///   channel_member pw-submit <rpc_url>
fn cmd_pw_submit(args: &[String]) {
    let rpc = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| die("pw-submit needs <rpc_url>"));

    let settlement: serde_json::Value = read_json("settlement.json");
    let manager = settlement["manager"]
        .as_str()
        .unwrap_or_else(|| die("settlement.json missing manager"));
    let verifier = settlement["verifier"]
        .as_str()
        .unwrap_or_else(|| die("settlement.json missing verifier"));
    require_active_settlement_binding(&rpc, manager, Some(verifier), None);
    let l1_signer = LazyL1Signer::new(&rpc);

    let burn: serde_json::Value = read_json("last_burn.json");
    let burn_amount: u64 = burn["amount"]
        .as_u64()
        .unwrap_or_else(|| die("last_burn.json missing amount"));
    let source_pk_g = Bytes32::from_hex(
        burn["source_pk_g"]
            .as_str()
            .unwrap_or_else(|| die("last_burn.json missing source_pk_g")),
    )
    .unwrap_or_else(|e| die(format!("parse source_pk_g: {e:?}")));
    let receiver_pk_g = Bytes32::from_hex(
        burn["receiver_pk_g"]
            .as_str()
            .unwrap_or_else(|| die("last_burn.json missing receiver_pk_g")),
    )
    .unwrap_or_else(|e| die(format!("parse receiver_pk_g: {e:?}")));

    let pre_burn_chain = Bytes32::from_hex(
        burn["pre_burn_settled_tx_chain"]
            .as_str()
            .unwrap_or_else(|| die("last_burn.json missing pre_burn_settled_tx_chain")),
    )
    .unwrap_or_else(|e| die(format!("parse pre_burn_settled_tx_chain: {e:?}")));

    let state = load_state();
    let head = &state.snapshot.state;

    let sender_delta_digest = Bytes32::from_hex(
        burn["sender_delta_ct_digest"]
            .as_str()
            .unwrap_or_else(|| die("last_burn.json missing sender_delta_ct_digest")),
    )
    .unwrap_or_else(|e| die(format!("parse sender_delta_ct_digest: {e:?}")));
    let receiver_delta_digest = Bytes32::from_hex(
        burn["receiver_delta_ct_digest"]
            .as_str()
            .unwrap_or_else(|| die("last_burn.json missing receiver_delta_ct_digest")),
    )
    .unwrap_or_else(|e| die(format!("parse receiver_delta_ct_digest: {e:?}")));

    let tx_leaf = tx_leaf_hash(
        source_pk_g,
        sender_delta_digest,
        receiver_pk_g,
        receiver_delta_digest,
    );

    // Multitoken §N: the burned BASE token_index recorded by cosign-burn-send (default 0 for
    // legacy last_burn.json files). Bound into the IPW2 authDigest, so the L1 leg pays the burned
    // asset (withdrawNative for 0, withdrawERC20 otherwise).
    let burn_token_index: u32 = burn["token_index"].as_u64().unwrap_or(0) as u32;
    let channel_id = state.snapshot.record.channel_id;
    // The base nonce is an explicit IMI5 field persisted at burn time. It MUST NOT be reconstructed
    // from the channel small-block number: incoming/import transitions advance that counter
    // without consuming a base sent-tx slot. `tx_nonce` is accepted only as the field name used by
    // the immediately preceding schema; neither path invents a nonce from channel state.
    let recorded_nonce = burn["base_nonce"]
        .as_u64()
        .or_else(|| burn["tx_nonce"].as_u64())
        .unwrap_or_else(|| die("last_burn.json missing required base_nonce/tx_nonce"));
    let tx_nonce = u32::try_from(recorded_nonce).unwrap_or_else(|_| {
        die(format!(
            "last_burn.json base nonce {recorded_nonce} exceeds u32"
        ))
    });
    let burn_aux_data = burn_descriptor(
        channel_id,
        tx_nonce,
        tx_leaf,
        receiver_pk_g,
        burn_token_index,
        intmax3_zkp::wallet_core::u64_to_u256(burn_amount),
    );
    if let Some(recorded) = burn["aux_data"].as_str() {
        let recorded = Bytes32::from_hex(recorded)
            .unwrap_or_else(|e| die(format!("parse last_burn.json aux_data: {e:?}")));
        if recorded != burn_aux_data {
            die(format!(
                "last_burn.json burn descriptor {} != canonical IMD2 descriptor {} — refusing",
                recorded.to_hex(),
                burn_aux_data.to_hex()
            ));
        }
    }

    // ── The withdrawal leaf: DERIVED, never invented ────────────────────────────────────────
    //
    // SECURITY (2026-08-13, the fund-stranding fix). This used to compute
    //     nullifier = keccak(tx_leaf ‖ pre_burn_settled_tx_chain)
    // — a formula that exists nowhere else in the system. A provable withdrawal leaf carries
    // `SettledTransfer::nullifier()` (Poseidon over the base transfer + channel id +
    // transfer_index + tx nonce; `src/circuits/withdraw/single_withdrawal_circuit.rs:376-390`
    // natively, `:513-525` in-circuit). Different hash family, different preimage: the two could
    // NEVER coincide, so `submitPartialWithdrawalIntent` recorded an authorization that no proof
    // could ever match, for a burn whose channel-side debit had already happened. Fail-closed on
    // theft. (At the time this also irreversibly consumed the manager's single-use chain key,
    // stranding the value permanently; that `usedPartialWithdrawalChains` guard has since been
    // removed as a fossil, so the residual failure mode is an unredeemable channel debit, not an
    // on-chain chain-lock.)
    //
    // The leaf now comes from `burn_withdrawal_leaf`, the one shared derivation, which calls the
    // same `SettledTransfer::nullifier()` the circuit calls. Every input is settlement-independent
    // (F-WD-2), so no circuit, PI or VK change is required to know the nullifier at burn time.
    let withdrawal = burn_withdrawal_leaf(
        channel_id,
        receiver_pk_g,
        burn_token_index,
        burn_amount,
        burn_aux_data,
        tx_nonce,
    )
    .unwrap_or_else(|e| die(format!("derive burn withdrawal leaf: {e:?}")));
    let withdrawal_addr = withdrawal.recipient;
    let nullifier = withdrawal.nullifier;

    preflight_burn_authorization_is_matchable(
        &burn,
        head,
        channel_id,
        &withdrawal,
        tx_leaf,
        pre_burn_chain,
        receiver_pk_g,
        burn_amount,
        tx_nonce,
    );

    // `PW_RECIPIENT` is no longer an INPUT — the paid address is fixed at burn time
    // (`build_burn_send_token` bakes `ADDRESS_TAG(withdrawal_l1_address)` into the base transfer's
    // recipient, `src/wallet_core.rs:2371`) and is recovered from it above. It survives only as an
    // ASSERTION: if the caller (relay/coordinator) states an address, it must be the one the burn
    // actually pays, or we refuse BEFORE the chain key is spent. Previously a mismatched
    // `PW_RECIPIENT` silently produced an unmatchable authorization and stranded the burn.
    if let Ok(want_hex) = std::env::var("PW_RECIPIENT") {
        let want = Address::from_hex(&want_hex)
            .unwrap_or_else(|e| die(format!("parse PW_RECIPIENT: {e:?}")));
        if want != withdrawal_addr {
            die(format!(
                "PW_RECIPIENT {} != the L1 address this burn pays ({}) — REFUSING to submit. \
                 Submitting anyway would consume the channel's single-use partial-withdrawal \
                 chain key on an authorization no withdrawal proof could ever satisfy, stranding \
                 the burned funds permanently.",
                want.to_hex(),
                withdrawal_addr.to_hex()
            ));
        }
    }

    let auth_digest = partial_withdrawal_auth_digest(&withdrawal);
    eprintln!("pw-submit: authDigest = {}", auth_digest.to_hex());

    // P1: build and wrap a REAL close proof for the co-signed post-burn head. The old code copied
    // fields from `head`, inserted 0/1 literals, then let SubmitPartialWithdrawal synthesize only
    // the public-input array. That was not a proof and could run only against a mock verifier.
    //
    // Fail before the expensive Falcon/close/MLE proving if the persisted balance IVC head is
    // stale. This is expected for legacy backing files: a close proof pins this exact settle chain,
    // so silently substituting the genesis attestation would be both expensive and impossible.
    let (balance_vd, att, _backing) = load_backing();
    let balance_proof =
        ProofWithPublicInputs::<BF, BC, BD>::from_bytes(att.balance_proof, &balance_vd.common)
            .unwrap_or_else(|e| die(format!("deserialize live balance proof: {e}")));
    let balance_pis = BalancePublicInputs::from_u64(
        &balance_proof.public_inputs[..BALANCE_PUBLIC_INPUTS_LEN].to_u64_vec(),
    )
    .unwrap_or_else(|e| die(format!("decode live balance proof PIs: {e}")));
    if balance_pis.channel_id != channel_id
        || balance_pis.settled_tx_chain != head.balance_state.settled_tx_chain
    {
        die(format!(
            "pw-submit REFUSED before proving: persisted live balance proof is not the post-burn \
             head (proof channel {}, chain {}; signed head channel {}, chain {}). A REAL partial-\
             withdrawal close proof cannot be made from the stale genesis attestation. Settle the \
             burn into the base balance IVC head and persist channel_attestation.bin first.",
            balance_pis.channel_id.as_u64(),
            balance_pis.settled_tx_chain.to_hex(),
            channel_id.as_u64(),
            head.balance_state.settled_tx_chain.to_hex(),
        ));
    }

    eprintln!(
        "pw-submit: building REAL close proof + MLE for post-burn state_version {} (HEAVY)…",
        head.balance_state.state_version
    );
    let close_prover = CloseProver::new(&balance_vd);
    let falcon_artifact =
        cache_falcon_aggregate(close_prover.falcon_context(), &state.snapshot.record, head)
            .unwrap_or_else(|e| die(format!("Falcon aggregate cache: {e}")));
    let close_witness = close_prover
        .build_full_witness_from_aggregate(
            &state.snapshot.record,
            head,
            &falcon_artifact,
            balance_proof,
        )
        .unwrap_or_else(|e| die(format!("build real PW close witness: {}", e.0)));
    let close_proof = close_prover
        .prove(&close_witness)
        .unwrap_or_else(|e| die(format!("real PW close proof: {}", e.0)));
    let close_mle_json = close_prover
        .prove_mle(&close_proof)
        .unwrap_or_else(|e| die(format!("real PW close MLE: {}", e.0)));
    let close_pi_limbs = close_proof.public_inputs[..CHANNEL_CLOSE_PUBLIC_INPUTS_LEN].to_u64_vec();
    let close_pis = ChannelClosePublicInputs::from_u64_slice(&close_pi_limbs)
        .unwrap_or_else(|e| die(format!("decode real PW close PIs: {e:?}")));

    // Every scalar below is decoded from the proof's public inputs. The per-token vectors are the
    // exact signed-state witness whose tokenFundsDigest the proof exposes and the verifier
    // recomputes. No submit-only literal is allowed to manufacture an intent field.
    let submit = serde_json::json!({
        "manager": manager,
        "verifier": verifier,
        "close_nonce": close_pis.close_nonce,
        "final_epoch": close_pis.final_epoch,
        "final_small_block_number": close_pis.final_small_block_number,
        "close_freeze_nonce": close_pis.close_freeze_nonce,
        "final_channel_state_digest": close_pis.final_channel_state_digest.to_hex(),
        "final_balance_state_h1": close_pis.final_balance_state_h1.to_hex(),
        "channel_fund_amounts": head.channel_fund.amounts.iter().map(|v| v.to_string()).collect::<Vec<_>>(),
        "token_registry": head.balance_state.token_registry.to_vec(),
        "token_count": head.balance_state.token_count,
        "channel_fund_intmax_state_root": close_pis.channel_fund_intmax_state_root.to_hex(),
        "burn_tx_hash": close_pis.burn_tx_hash.to_hex(),
        "close_withdrawal_digest": close_pis.close_withdrawal_digest.to_hex(),
        "snapshot_medium_block_number": close_pis.snapshot_medium_block_number,
        "final_state_version": close_pis.final_state_version,
        "final_settled_tx_chain": close_pis.final_settled_tx_chain.to_hex(),
        "final_settled_tx_acc_root": close_pis.final_settled_tx_accumulator_root.to_hex(),
        "prev_settled_tx_chain": pre_burn_chain.to_hex(),
        "withdrawal_recipient": format!("0x{}", hex::encode(withdrawal_addr.to_bytes_be())),
        "withdrawal_token_index": burn_token_index,
        "withdrawal_amount": burn_amount,
        "withdrawal_nullifier": nullifier.to_hex(),
        "withdrawal_aux_data": burn_aux_data.to_hex(),
        "withdrawal_base_nonce": tx_nonce,
        "burn_tx_leaf": tx_leaf.to_hex(),
    });
    // Same shared resolution as the exit commands (F4).
    let contracts_dir =
        require_contracts_dir("pw-submit", &["script/SubmitPartialWithdrawal.s.sol"]);
    let contracts_dir = contracts_dir.to_string_lossy().to_string();
    let data_path = format!("{contracts_dir}/test/data/pw_submit.json");
    fs::write(
        &data_path,
        serde_json::to_string_pretty(&submit).unwrap_or_else(|e| die(e)),
    )
    .unwrap_or_else(|e| die(format!("write {data_path}: {e}")));
    let mle_path = format!("{contracts_dir}/test/data/{PW_CLOSE_INTENT_MLE_FILE}");
    fs::write(&mle_path, close_mle_json).unwrap_or_else(|e| die(format!("write {mle_path}: {e}")));

    let mut forge = Command::new("forge");
    forge.current_dir(&contracts_dir).args([
        "script",
        "script/SubmitPartialWithdrawal.s.sol",
        "--rpc-url",
        &rpc,
        "--broadcast",
        "--code-size-limit",
        "50000",
    ]);
    l1_signer.get().append_to_command(&mut forge);
    let forge_out = forge
        .output()
        .unwrap_or_else(|e| die(format!("forge pw-submit failed: {e}")));
    let out = String::from_utf8_lossy(&forge_out.stdout);
    let err = String::from_utf8_lossy(&forge_out.stderr);
    if !forge_out.status.success() {
        die(format!(
            "forge pw-submit FAILED:\nstdout: {out}\nstderr: {err}"
        ));
    }

    let onchain_auth = out
        .lines()
        .chain(err.lines())
        .skip_while(|l| !l.contains("AUTH_DIGEST:"))
        .nth(1)
        .map(|l| l.trim().to_string())
        .unwrap_or_else(|| {
            die(format!(
                "could not parse AUTH_DIGEST from forge output:\n{out}\n{err}"
            ))
        });

    write_json(
        "pw_auth.json",
        &serde_json::json!({
            "auth_digest": onchain_auth,
            "manager": manager,
            "verifier": verifier,
            "withdrawal_recipient": format!("0x{}", hex::encode(withdrawal_addr.to_bytes_be())),
            "withdrawal_token_index": burn_token_index,
            "withdrawal_amount": burn_amount,
            "withdrawal_nullifier": nullifier.to_hex(),
            "withdrawal_aux_data": burn_aux_data.to_hex(),
            "burn_tx_leaf": tx_leaf.to_hex(),
        }),
    );
    println!(
        "pw-submit OK: authDigest = {onchain_auth}, Rust = {}",
        auth_digest.to_hex()
    );
}

/// Finalize a partial withdrawal: advance anvil time, finalize on-chain, and check authorization.
/// Usage:
///   channel_member pw-finalize <rpc_url>
fn cmd_pw_finalize(args: &[String]) {
    let rpc = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| die("pw-finalize needs <rpc_url>"));

    let auth: serde_json::Value = read_json("pw_auth.json");
    let manager = auth["manager"]
        .as_str()
        .unwrap_or_else(|| die("pw_auth.json missing manager"));
    let auth_digest = auth["auth_digest"]
        .as_str()
        .unwrap_or_else(|| die("pw_auth.json missing auth_digest"));

    let l1_signer = LazyL1Signer::new(&rpc);

    let settlement: serde_json::Value = read_json("settlement.json");
    let rollup = settlement["rollup"]
        .as_str()
        .unwrap_or_else(|| die("settlement.json missing rollup"));
    require_active_settlement_binding(&rpc, manager, None, Some(rollup));

    // The payout leg (partial-withdrawal-payout-design Phase 3). History: the old
    // `claimAuthorizedWithdrawal` door was REMOVED 2026-07-28 (it paid the GLOBAL escrow against
    // an authorization binding neither amount nor recipient — doc/tasks/pw-auth-threat-model.md).
    // Payout now goes through `withdrawNative`/`withdrawERC20`: the leaf comes from a VERIFIED
    // base-layer withdrawal proof built by the resident live service against the durable base
    // history (`LiveBalanceService::burn_payout_artifacts`), and this authorization is only a
    // second factor on that leaf. The API route obtains the artifacts from the daemon and stages
    // them in the channel workdir before invoking this command.
    // IPW2 is one-shot: a successful proof payout deletes the authorization in the same
    // transaction that consumes the proof nullifier. The payout driver therefore owns the whole
    // pending -> authorized -> consumed state machine; checking only the authorization here would
    // mistake a completed payout for an unfinalized manager intent and retry a non-pending manager.
    run_partial_withdrawal_payout(&rpc, &l1_signer, rollup, manager, auth_digest);
}

/// Crash-safe L1 payout driver for a proved partial withdrawal, per the protocol documented on
/// `RunPartialWithdrawalPayout.s.sol`: dry-run the script for the EXACT calldata, persist a
/// `BroadcastIntent` (caller, nonce, calldata hash, pre-payout credit) in the durable payout
/// store, only then send at that pinned nonce, then confirm with the receipt + the three
/// on-chain observations the store demands (authorization consumed/false, finalized anchor, used
/// nullifier) and the exact credit delta. Every step is idempotent: a crashed run re-enters at the
/// recorded phase and reconciles a mined transaction by stored hash or pinned sender/nonce.
fn run_partial_withdrawal_payout(
    rpc: &str,
    l1_signer: &LazyL1Signer,
    rollup: &str,
    manager: &str,
    auth_digest: &str,
) {
    use intmax3_zkp::partial_withdrawal_payout::{
        BroadcastIntent, L1CallKind, PartialWithdrawalPayoutStore, PartialWithdrawalProofArtifacts,
        PartialWithdrawalResumeAction, PayoutConfirmation, PreparePartialWithdrawalPayout,
        PullConfirmation, partial_withdrawal_resume_action,
    };

    let contracts_dir =
        require_contracts_dir("pw-finalize", &["script/RunPartialWithdrawalPayout.s.sol"]);
    let contracts_dir = contracts_dir.to_string_lossy().to_string();

    // Staged by the API route from the daemon's `liveBurnPayoutArtifacts` response.
    let artifacts: PartialWithdrawalProofArtifacts = read_json("pw_artifacts.json");
    let producer_meta: serde_json::Value = read_json("pw_producer.json");
    let cosigned_head: serde_json::Value = read_json("burn_cosigned.json");

    let chain_id = rpc_chain_id(rpc);
    let rollup_addr = rollup
        .parse::<Address>()
        .unwrap_or_else(|e| die(format!("parse rollup address: {e}")));
    let manager_addr = manager
        .parse::<Address>()
        .unwrap_or_else(|e| die(format!("parse manager address: {e}")));
    let auth_digest_b32 = auth_digest
        .parse::<Bytes32>()
        .unwrap_or_else(|e| die(format!("parse auth digest: {e}")));
    let signed_head_digest = cosigned_head["digest"]
        .as_str()
        .unwrap_or_else(|| die("burn_cosigned.json missing digest"))
        .parse::<Bytes32>()
        .unwrap_or_else(|e| die(format!("parse signed head digest: {e}")));
    let producer_receipt: intmax3_zkp::block_producer_service::BlockProducerReceipt =
        serde_json::from_value(producer_meta["blockReceipt"].clone())
            .unwrap_or_else(|e| die(format!("pw_producer.json blockReceipt: {e}")));
    let burn_base_nonce = producer_meta["liveReceipt"]["baseNonce"]
        .as_u64()
        .unwrap_or_else(|| {
            die(
                "pw_producer.json liveReceipt.baseNonce missing (was the burn settled in the \
                 live authority?)",
            )
        })
        .checked_sub(1)
        .unwrap_or_else(|| die("live baseNonce 0 cannot follow a burn"))
        as u32;
    let channel_id_u64 = cosigned_head["channelId"]
        .as_u64()
        .unwrap_or_else(|| die("burn_cosigned.json missing channelId"));
    let channel_id = intmax3_zkp::common::channel_id::ChannelId::new(channel_id_u64)
        .unwrap_or_else(|e| die(format!("channel id: {e:?}")));

    let mut store = PartialWithdrawalPayoutStore::open("pw_payout_store.bin")
        .unwrap_or_else(|e| die(format!("open payout store: {e}")));
    let mut candidate = store
        .prepare(PreparePartialWithdrawalPayout {
            chain_id,
            rollup: rollup_addr,
            manager: manager_addr,
            channel_id,
            signed_head_digest,
            burn_base_nonce,
            producer_receipt,
            auth_digest: auth_digest_b32,
            artifacts: artifacts.clone(),
        })
        .unwrap_or_else(|e| die(format!("payout store prepare: {e}")));
    let candidate_id = candidate.candidate_id;
    eprintln!(
        "pw-finalize: payout candidate {candidate_id} prepared (lane {:?})",
        candidate.lane
    );

    // A serialized confirmation is not self-authenticating: its receipt or the finalized head
    // that covered it may have been replaced while this process was down.  Revalidate before any
    // stored `ContinueAfterPayout`/`Done` state is allowed to influence the next fund action.
    revalidate_candidate_l1_confirmations(rpc, &candidate);
    let mut authority = read_durable_l1_checkpoint(rpc, chain_id);

    let nullifier_hex = candidate.artifacts.withdrawal.nullifier.to_string();
    let mut chain_state = read_partial_withdrawal_onchain_state(
        rpc,
        rollup,
        manager,
        auth_digest,
        &nullifier_hex,
        authority.block_number,
    );
    require_stable_durable_l1_checkpoint(rpc, &authority);
    let mut resume_action = partial_withdrawal_resume_action(&candidate, chain_state)
        .unwrap_or_else(|e| die(format!("unsafe partial-withdrawal resume state: {e}")));
    if resume_action == PartialWithdrawalResumeAction::FinalizePending {
        finalize_pending_partial_withdrawal(
            rpc,
            l1_signer,
            rollup,
            manager,
            auth_digest,
            &nullifier_hex,
            &mut store,
            candidate_id,
        );
        candidate = store
            .active()
            .unwrap_or_else(|e| die(format!("payout store active: {e}")))
            .unwrap_or_else(|| die("payout store lost the active candidate"));
        revalidate_candidate_l1_confirmations(rpc, &candidate);
        authority = read_durable_l1_checkpoint(rpc, chain_id);
        chain_state = read_partial_withdrawal_onchain_state(
            rpc,
            rollup,
            manager,
            auth_digest,
            &nullifier_hex,
            authority.block_number,
        );
        require_stable_durable_l1_checkpoint(rpc, &authority);
        resume_action = partial_withdrawal_resume_action(&candidate, chain_state)
            .unwrap_or_else(|e| die(format!("unsafe finalized partial-withdrawal state: {e}")));
        if resume_action != PartialWithdrawalResumeAction::BroadcastPayout {
            die(format!(
                "manager finalization was journaled, but the only safe next action is {resume_action:?} instead of a fresh proof payout"
            ));
        }
        eprintln!("pw-finalize: one-shot authorization recorded by a canonical finalized receipt.");
    }

    let recipient = candidate.artifacts.withdrawal.recipient;
    let recipient_hex = recipient.to_string();
    let is_native = candidate.artifacts.withdrawal.token_index == 0;
    let step = if is_native {
        "withdrawNativeStep()"
    } else {
        "withdrawErc20Step()"
    };

    // Stage the exact script inputs (foundry's fs allow-list covers ./ under contracts).
    let payout_path = format!("{contracts_dir}/test/data/pw_withdrawal_payout.json");
    let mle_path = format!("{contracts_dir}/test/data/pw_withdrawal_mle.json");
    fs::write(&payout_path, &candidate.artifacts.payout_json)
        .unwrap_or_else(|e| die(format!("write {payout_path}: {e}")));
    fs::write(&mle_path, &candidate.artifacts.withdrawal_mle_json)
        .unwrap_or_else(|e| die(format!("write {mle_path}: {e}")));

    if resume_action != PartialWithdrawalResumeAction::ContinueAfterPayout {
        let payout_kind = if is_native {
            L1CallKind::WithdrawNative
        } else {
            L1CallKind::WithdrawErc20
        };
        let current = store
            .active()
            .unwrap_or_else(|e| die(format!("payout store active: {e}")))
            .unwrap_or_else(|| die("payout store lost the active candidate"));
        // Reconcile BEFORE attempting a new forge simulation. Once the exact payout succeeds the
        // one-shot authorization is false, so simulating the same withdrawal necessarily reverts;
        // that normal crash-after-mining state must still reach receipt recovery.
        let reconciled = current.payout_broadcast.as_ref().and_then(|intent| {
            reconcile_confirmed_l1_call(rpc, rollup, intent, &current.payout_tx_hashes, payout_kind)
                .map(|receipt| (receipt, intent.clone()))
        });
        let (receipt, tx_hash, intent) = if let Some((receipt, intent)) = reconciled {
            let hash = receipt.tx_hash.to_string();
            (receipt, hash, intent)
        } else {
            if chain_state.nullifier_used {
                die(
                    "withdrawal nullifier is already used, but no exact canonical payout receipt \
                     was found from the durable broadcast intent",
                );
            }
            let (calldata, calldata_hash) = build_partial_withdrawal_payout_calldata(
                &contracts_dir,
                chain_id,
                rpc,
                rollup,
                &payout_path,
                &mle_path,
                step,
            );
            let caller_hex = l1_signer.get().address();
            let caller = caller_hex
                .parse::<Address>()
                .unwrap_or_else(|e| die(format!("parse caller address: {e}")));
            let intent = if let Some(intent) = current.payout_broadcast.clone() {
                if intent.caller != caller || intent.calldata_hash != calldata_hash {
                    die(
                        "persisted payout intent does not match the current signer or exact proof calldata",
                    );
                }
                intent
            } else {
                let credit_before = read_pending_credit_at(
                    rpc,
                    rollup,
                    &current.artifacts.withdrawal,
                    authority.block_number,
                );
                require_stable_durable_l1_checkpoint(rpc, &authority);
                let intent = BroadcastIntent {
                    caller,
                    start_block: authority.block_number,
                    caller_nonce: read_account_nonce(rpc, &caller_hex, "latest"),
                    calldata_hash,
                    credit_before,
                };
                store
                    .mark_payout_broadcast(candidate_id, intent.clone())
                    .unwrap_or_else(|e| die(format!("persist payout intent: {e}")));
                intent
            };

            // Re-scan after the potentially expensive simulation to close the race with a pending
            // transaction mining while calldata was rebuilt.
            let current = store
                .active()
                .unwrap_or_else(|e| die(format!("payout store active: {e}")))
                .unwrap_or_else(|| die("payout store lost the active candidate"));
            if let Some(receipt) = reconcile_confirmed_l1_call(
                rpc,
                rollup,
                &intent,
                &current.payout_tx_hashes,
                payout_kind,
            ) {
                let hash = receipt.tx_hash.to_string();
                (receipt, hash, intent)
            } else {
                require_nonce_free_for_exact_rebroadcast(rpc, &caller_hex, intent.caller_nonce);
                let nonce_arg = intent.caller_nonce.to_string();
                let send_out = cast_signed(
                    rpc,
                    l1_signer.get(),
                    &["send", rollup, &calldata, "--nonce", &nonce_arg, "--json"],
                );
                let tx_hash = extract_tx_hash(&send_out);
                let tx_hash_b32 = tx_hash
                    .parse::<Bytes32>()
                    .unwrap_or_else(|e| die(format!("parse payout tx hash: {e}")));
                store
                    .record_payout_tx_hash(candidate_id, tx_hash_b32)
                    .unwrap_or_else(|e| die(format!("persist payout tx hash: {e}")));
                (read_l1_receipt(rpc, &tx_hash, payout_kind), tx_hash, intent)
            }
        };

        // Confirm the exact successful receipt and all atomic postconditions. Authorization
        // MUST now be false; used-nullifier + exact credit delta distinguish consumption from a
        // missing/failed authorization.
        let payout_meta: serde_json::Value = serde_json::from_str(&candidate.artifacts.payout_json)
            .unwrap_or_else(|e| die(format!("parse candidate payout json: {e}")));
        let ext_commitment = payout_meta["ext_commitment"]
            .as_str()
            .unwrap_or_else(|| die("candidate payout json missing ext_commitment"))
            .to_string();
        let authorization_observed = read_bool_view_at(
            rpc,
            rollup,
            "partialWithdrawalAuthorized(bytes32)",
            auth_digest,
            receipt.finalized_checkpoint.block_number,
        );
        let finalized_anchor_observed = read_bool_view_at(
            rpc,
            rollup,
            "isFinalizedStateRoot(bytes32)",
            &ext_commitment,
            receipt.finalized_checkpoint.block_number,
        );
        let nullifier_used_observed = read_bool_view_at(
            rpc,
            rollup,
            "withdrawalNullifierUsed(bytes32)",
            &nullifier_hex,
            receipt.finalized_checkpoint.block_number,
        );
        let credit_after = read_pending_credit_at(
            rpc,
            rollup,
            &candidate.artifacts.withdrawal,
            receipt.finalized_checkpoint.block_number,
        );
        require_stable_durable_l1_checkpoint(rpc, &receipt.finalized_checkpoint);
        let confirmation = PayoutConfirmation {
            authorization_observed,
            finalized_anchor_observed,
            nullifier_used_observed,
            credit_before: intent.credit_before,
            credit_after,
            receipt,
        };
        store
            .confirm_payout(candidate_id, confirmation)
            .unwrap_or_else(|e| die(format!("confirm payout: {e}")));
        eprintln!("pw-finalize: proof payout confirmed (tx {tx_hash}).");
    } else {
        eprintln!("pw-finalize: proof payout already confirmed; continuing to the pull leg");
    }

    // 5. The exact-amount pull leg — only when THIS signer is the proved recipient (the store
    //    enforces `intent.caller == recipient`); otherwise the recipient pulls its proof amount.
    let caller_hex = l1_signer.get().address();
    if caller_hex.to_lowercase() != recipient_hex.to_lowercase() {
        store
            .mark_recipient_pull_delegated(candidate_id)
            .unwrap_or_else(|e| die(format!("persist external recipient handoff: {e}")));
        eprintln!(
            "pw-finalize: payout credited {recipient_hex}; that account pulls it with \
             the matching native/ERC-20 pull (this signer is {caller_hex}). Local workflow COMPLETE."
        );
        return;
    }
    let candidate = store
        .active()
        .unwrap_or_else(|e| die(format!("payout store active: {e}")))
        .unwrap_or_else(|| die("payout store lost the active candidate"));
    if candidate.pull_confirmation.is_some() {
        eprintln!("pw-finalize: pull already confirmed. Done.");
        return;
    }
    let _payout_conf = candidate
        .payout_confirmation
        .clone()
        .unwrap_or_else(|| die("pull before payout confirmation"));
    let pull_amount = candidate.artifacts.withdrawal.amount.to_string();
    let pull_calldata_owned = if is_native {
        cast(&["calldata", "withdraw(uint256)", &pull_amount])
    } else {
        let token_index = candidate.artifacts.withdrawal.token_index.to_string();
        cast(&[
            "calldata",
            "withdrawToken(uint32,uint256)",
            &token_index,
            &pull_amount,
        ])
    };
    let pull_calldata = pull_calldata_owned.trim();
    let calldata_hash = cast(&["keccak", pull_calldata])
        .trim()
        .parse::<Bytes32>()
        .unwrap_or_else(|e| die(format!("keccak pull calldata: {e}")));
    let intent = if let Some(intent) = candidate.pull_broadcast.clone() {
        if intent.caller != recipient
            || intent.calldata_hash != calldata_hash
            || intent.credit_before < candidate.artifacts.withdrawal.amount
        {
            die("persisted pull intent differs from the proved recipient/calldata or lacks credit");
        }
        intent
    } else {
        authority = read_durable_l1_checkpoint(rpc, chain_id);
        let current_credit = read_pending_credit_at(
            rpc,
            rollup,
            &candidate.artifacts.withdrawal,
            authority.block_number,
        );
        require_stable_durable_l1_checkpoint(rpc, &authority);
        if current_credit < candidate.artifacts.withdrawal.amount {
            die(format!(
                "recipient has insufficient credit before exact pull: needs {}, observed {}",
                candidate.artifacts.withdrawal.amount, current_credit
            ));
        }
        let intent = BroadcastIntent {
            caller: recipient,
            start_block: authority.block_number,
            caller_nonce: read_account_nonce(rpc, &caller_hex, "latest"),
            calldata_hash,
            credit_before: current_credit,
        };
        store
            .mark_pull_broadcast(candidate.candidate_id, intent.clone())
            .unwrap_or_else(|e| die(format!("persist pull intent: {e}")));
        intent
    };
    let pull_kind = if is_native {
        L1CallKind::PullNative
    } else {
        L1CallKind::PullErc20
    };
    let current = store
        .active()
        .unwrap_or_else(|e| die(format!("payout store active: {e}")))
        .unwrap_or_else(|| die("payout store lost the active candidate"));
    let (receipt, tx_hash) = if let Some(receipt) =
        reconcile_confirmed_l1_call(rpc, rollup, &intent, &current.pull_tx_hashes, pull_kind)
    {
        let hash = receipt.tx_hash.to_string();
        (receipt, hash)
    } else {
        authority = read_durable_l1_checkpoint(rpc, chain_id);
        let credit = read_pending_credit_at(
            rpc,
            rollup,
            &candidate.artifacts.withdrawal,
            authority.block_number,
        );
        require_stable_durable_l1_checkpoint(rpc, &authority);
        if credit < candidate.artifacts.withdrawal.amount {
            die(format!(
                "pull credit fell below the exact signed amount without a canonical receipt: needs {}, observed {}",
                candidate.artifacts.withdrawal.amount, credit
            ));
        }
        require_nonce_free_for_exact_rebroadcast(rpc, &caller_hex, intent.caller_nonce);
        let nonce_arg = intent.caller_nonce.to_string();
        let send_out = cast_signed(
            rpc,
            l1_signer.get(),
            &[
                "send",
                rollup,
                pull_calldata,
                "--nonce",
                &nonce_arg,
                "--json",
            ],
        );
        let tx_hash = extract_tx_hash(&send_out);
        let tx_hash_b32 = tx_hash
            .parse::<Bytes32>()
            .unwrap_or_else(|e| die(format!("parse pull tx hash: {e}")));
        store
            .record_pull_tx_hash(candidate.candidate_id, tx_hash_b32)
            .unwrap_or_else(|e| die(format!("persist pull tx hash: {e}")));
        (read_l1_receipt(rpc, &tx_hash, pull_kind), tx_hash)
    };
    let credit_after = read_pending_credit_at(
        rpc,
        rollup,
        &candidate.artifacts.withdrawal,
        receipt.finalized_checkpoint.block_number,
    );
    require_stable_durable_l1_checkpoint(rpc, &receipt.finalized_checkpoint);
    store
        .confirm_pull(
            candidate.candidate_id,
            PullConfirmation {
                credit_before: intent.credit_before,
                credit_after,
                receipt,
            },
        )
        .unwrap_or_else(|e| die(format!("confirm pull: {e}")));
    eprintln!("pw-finalize: recipient pull confirmed (tx {tx_hash}). Partial withdrawal COMPLETE.");
}

fn build_partial_withdrawal_payout_calldata(
    contracts_dir: &str,
    chain_id: u64,
    rpc: &str,
    rollup: &str,
    payout_path: &str,
    mle_path: &str,
    step: &str,
) -> (String, Bytes32) {
    let mut forge = Command::new("forge");
    forge
        .current_dir(contracts_dir)
        .env("ROLLUP", rollup)
        .env("PW_PAYOUT_PATH", payout_path)
        .env("PW_MLE_PATH", mle_path)
        .args([
            "script",
            "script/RunPartialWithdrawalPayout.s.sol",
            "--sig",
            step,
            "--rpc-url",
            rpc,
            "--code-size-limit",
            "50000",
        ]);
    let out = forge
        .output()
        .unwrap_or_else(|e| die(format!("forge payout dry-run failed to start: {e}")));
    if !out.status.success() {
        die(format!(
            "forge payout dry-run FAILED:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let dry = fs::read_to_string(format!(
        "{contracts_dir}/broadcast/RunPartialWithdrawalPayout.s.sol/{chain_id}/dry-run/run-latest.json"
    ))
    .unwrap_or_else(|e| die(format!("read payout dry-run journal: {e}")));
    let dry: serde_json::Value = serde_json::from_str(&dry)
        .unwrap_or_else(|e| die(format!("parse payout dry-run journal: {e}")));
    let tx = &dry["transactions"][0]["transaction"];
    let calldata = tx["input"]
        .as_str()
        .or_else(|| tx["data"].as_str())
        .unwrap_or_else(|| die("payout dry-run journal has no calldata"))
        .to_string();
    let dry_to = tx["to"].as_str().unwrap_or_default();
    if !dry_to.eq_ignore_ascii_case(rollup) {
        die(format!(
            "payout dry-run targets {dry_to}, expected the rollup {rollup}"
        ));
    }
    let calldata_hash = cast(&["keccak", &calldata])
        .trim()
        .parse::<Bytes32>()
        .unwrap_or_else(|e| die(format!("keccak payout calldata: {e}")));
    (calldata, calldata_hash)
}

fn read_pending_credit_at(
    rpc: &str,
    rollup: &str,
    withdrawal: &Withdrawal,
    block_number: u64,
) -> U256 {
    let recipient = withdrawal.recipient.to_string();
    let block = format!("0x{block_number:x}");
    let raw = if withdrawal.token_index == 0 {
        cast(&[
            "call",
            rollup,
            "pendingWithdrawals(address)",
            &recipient,
            "--block",
            &block,
            "--rpc-url",
            rpc,
        ])
    } else {
        let token_index = withdrawal.token_index.to_string();
        cast(&[
            "call",
            rollup,
            "pendingTokenWithdrawals(uint32,address)",
            &token_index,
            &recipient,
            "--block",
            &block,
            "--rpc-url",
            rpc,
        ])
    };
    Bytes32::from_hex(raw.trim())
        .map(U256::from)
        .unwrap_or_else(|e| die(format!("parse pending withdrawal credit: {e:?}")))
}

fn read_partial_withdrawal_onchain_state(
    rpc: &str,
    rollup: &str,
    manager: &str,
    auth_digest: &str,
    nullifier: &str,
    block_number: u64,
) -> intmax3_zkp::partial_withdrawal_payout::PartialWithdrawalOnchainState {
    use intmax3_zkp::partial_withdrawal_payout::PartialWithdrawalOnchainState;
    let block = format!("0x{block_number:x}");

    // Omit return types so `cast call` returns the raw ABI word consumed by the parsers below.
    // With `(bool)` / `(uint256)`, cast pretty-prints decoded values (for example `true` or a
    // decimal), which must not be compared with or parsed as a 32-byte ABI word.
    let manager_pending =
        read_bool_view0_at(rpc, manager, "partialWithdrawalPending()", block_number);
    let pending_auth_digest = cast(&[
        "call",
        manager,
        "pendingPartialWithdrawalAuthDigest()",
        "--block",
        &block,
        "--rpc-url",
        rpc,
    ])
    .trim()
    .parse::<Bytes32>()
    .unwrap_or_else(|e| die(format!("parse pending partial-withdrawal auth digest: {e}")));
    PartialWithdrawalOnchainState {
        manager_pending,
        pending_auth_digest,
        authorization: read_bool_view_at(
            rpc,
            rollup,
            "partialWithdrawalAuthorized(bytes32)",
            auth_digest,
            block_number,
        ),
        nullifier_used: read_bool_view_at(
            rpc,
            rollup,
            "withdrawalNullifierUsed(bytes32)",
            nullifier,
            block_number,
        ),
    }
}

fn finalize_pending_partial_withdrawal(
    rpc: &str,
    l1_signer: &LazyL1Signer,
    rollup: &str,
    manager: &str,
    auth_digest: &str,
    nullifier: &str,
    store: &mut intmax3_zkp::partial_withdrawal_payout::PartialWithdrawalPayoutStore,
    candidate_id: Bytes32,
) {
    use intmax3_zkp::partial_withdrawal_payout::{
        BroadcastIntent, FinalizeConfirmation, L1CallKind,
    };

    let current = store
        .active()
        .unwrap_or_else(|error| die(format!("payout store active: {error}")))
        .unwrap_or_else(|| die("payout store lost the active candidate"));
    if current.candidate_id != candidate_id {
        die("payout store switched candidates before manager finalization");
    }
    let manager_address = manager
        .parse::<Address>()
        .unwrap_or_else(|error| die(format!("parse manager address: {error}")));
    let rollup_address = rollup
        .parse::<Address>()
        .unwrap_or_else(|error| die(format!("parse rollup address: {error}")));
    let auth_digest_bytes = auth_digest
        .parse::<Bytes32>()
        .unwrap_or_else(|error| die(format!("parse partial-withdrawal auth digest: {error}")));
    if current.manager != manager_address
        || current.rollup != rollup_address
        || current.auth_digest != auth_digest_bytes
        || current.artifacts.withdrawal.nullifier.to_string() != nullifier
    {
        die("manager-finalization arguments differ from the durable payout candidate");
    }
    if current.finalize_confirmation.is_some() {
        return;
    }

    let calldata_owned = cast(&["calldata", "finalizePartialWithdrawal()"]);
    let calldata = calldata_owned.trim();
    let calldata_hash = cast(&["keccak", calldata])
        .trim()
        .parse::<Bytes32>()
        .unwrap_or_else(|error| die(format!("keccak manager-finalization calldata: {error}")));
    let caller_hex = l1_signer.get().address();
    let caller = caller_hex
        .parse::<Address>()
        .unwrap_or_else(|error| die(format!("parse manager-finalization caller: {error}")));

    let intent = if let Some(intent) = current.finalize_broadcast.clone() {
        if intent.caller != caller
            || intent.calldata_hash != calldata_hash
            || intent.credit_before != U256::default()
        {
            die(
                "persisted manager-finalization intent differs from the current signer or exact calldata",
            );
        }
        intent
    } else {
        let authority = read_durable_l1_checkpoint(rpc, current.chain_id);
        let state = read_partial_withdrawal_onchain_state(
            rpc,
            rollup,
            manager,
            auth_digest,
            nullifier,
            authority.block_number,
        );
        require_stable_durable_l1_checkpoint(rpc, &authority);
        require_exact_pending_partial_withdrawal(state, current.auth_digest);
        wait_until_partial_withdrawal_finalizable(rpc, manager);

        // Bind the durable intent only after the challenge window is ready.  Re-read every fund
        // authority fact at one stable finalized checkpoint so an intervening replacement/payout
        // cannot be justified by the older observation.
        let authority = read_durable_l1_checkpoint(rpc, current.chain_id);
        let state = read_partial_withdrawal_onchain_state(
            rpc,
            rollup,
            manager,
            auth_digest,
            nullifier,
            authority.block_number,
        );
        require_stable_durable_l1_checkpoint(rpc, &authority);
        require_exact_pending_partial_withdrawal(state, current.auth_digest);
        let intent = BroadcastIntent {
            caller,
            start_block: authority.block_number,
            caller_nonce: read_account_nonce(rpc, &caller_hex, "latest"),
            calldata_hash,
            credit_before: U256::default(),
        };
        store
            .mark_finalize_broadcast(candidate_id, intent.clone())
            .unwrap_or_else(|error| die(format!("persist manager-finalization intent: {error}")));
        intent
    };

    let current = store
        .active()
        .unwrap_or_else(|error| die(format!("payout store active: {error}")))
        .unwrap_or_else(|| die("payout store lost the active candidate"));
    let reconciled = reconcile_confirmed_l1_call(
        rpc,
        manager,
        &intent,
        &current.finalize_tx_hashes,
        L1CallKind::FinalizePartialWithdrawal,
    );
    let (receipt, tx_hash) = if let Some(receipt) = reconciled {
        let tx_hash = receipt.tx_hash.to_string();
        (receipt, tx_hash)
    } else {
        let authority = read_durable_l1_checkpoint(rpc, current.chain_id);
        let state = read_partial_withdrawal_onchain_state(
            rpc,
            rollup,
            manager,
            auth_digest,
            nullifier,
            authority.block_number,
        );
        require_stable_durable_l1_checkpoint(rpc, &authority);
        require_exact_pending_partial_withdrawal(state, current.auth_digest);
        wait_until_partial_withdrawal_finalizable(rpc, manager);

        let authority = read_durable_l1_checkpoint(rpc, current.chain_id);
        let state = read_partial_withdrawal_onchain_state(
            rpc,
            rollup,
            manager,
            auth_digest,
            nullifier,
            authority.block_number,
        );
        require_stable_durable_l1_checkpoint(rpc, &authority);
        require_exact_pending_partial_withdrawal(state, current.auth_digest);
        require_nonce_free_for_exact_rebroadcast(rpc, &caller_hex, intent.caller_nonce);
        let nonce_arg = intent.caller_nonce.to_string();
        let send_out = cast_signed(
            rpc,
            l1_signer.get(),
            &["send", manager, calldata, "--nonce", &nonce_arg, "--json"],
        );
        let tx_hash = extract_tx_hash(&send_out);
        let tx_hash_bytes = tx_hash
            .parse::<Bytes32>()
            .unwrap_or_else(|error| die(format!("parse manager-finalization tx hash: {error}")));
        store
            .record_finalize_tx_hash(candidate_id, tx_hash_bytes)
            .unwrap_or_else(|error| die(format!("persist manager-finalization tx hash: {error}")));
        (
            read_l1_receipt(rpc, &tx_hash, L1CallKind::FinalizePartialWithdrawal),
            tx_hash,
        )
    };

    let state = read_partial_withdrawal_onchain_state(
        rpc,
        rollup,
        manager,
        auth_digest,
        nullifier,
        receipt.finalized_checkpoint.block_number,
    );
    require_stable_durable_l1_checkpoint(rpc, &receipt.finalized_checkpoint);
    store
        .confirm_finalize(
            candidate_id,
            FinalizeConfirmation {
                receipt,
                manager_pending_observed: state.manager_pending,
                authorization_observed: state.authorization,
                nullifier_used_observed: state.nullifier_used,
            },
        )
        .unwrap_or_else(|error| die(format!("confirm manager finalization: {error}")));
    eprintln!("pw-finalize: manager finalization confirmed (tx {tx_hash}).");
}

fn require_exact_pending_partial_withdrawal(
    state: intmax3_zkp::partial_withdrawal_payout::PartialWithdrawalOnchainState,
    expected_auth_digest: Bytes32,
) {
    if !state.manager_pending
        || state.pending_auth_digest != expected_auth_digest
        || state.authorization
        || state.nullifier_used
    {
        die(
            "manager no longer has this exact pending, unauthorized, unused partial withdrawal at the durable L1 head",
        );
    }
}

fn wait_until_partial_withdrawal_finalizable(rpc: &str, manager: &str) {
    // finalizePartialWithdrawal requires block.timestamp > deadline. Anvil needs explicit time
    // travel; a real chain advances naturally and is polled for at most five minutes here.
    let deadline_hex = cast(&[
        "call",
        manager,
        "pendingPartialWithdrawalDeadline()",
        "--rpc-url",
        rpc,
    ]);
    let deadline = parse_u64_quantity(deadline_hex.trim(), "pendingPartialWithdrawalDeadline");
    if rpc_chain_id(rpc) == 31337 {
        let ts = cast(&["block", "latest", "-f", "timestamp", "--rpc-url", rpc]);
        let ts = parse_u64_quantity(ts.trim(), "latest block timestamp");
        if ts <= deadline {
            let advance = deadline
                .checked_sub(ts)
                .and_then(|delta| delta.checked_add(1))
                .unwrap_or_else(|| die("partial-withdrawal deadline cannot be advanced safely"))
                .to_string();
            cast(&["rpc", "evm_increaseTime", &advance, "--rpc-url", rpc]);
        }
        cast(&["rpc", "evm_mine", "--rpc-url", rpc]);
    } else {
        let mut waited = 0u64;
        loop {
            let ts = cast(&["block", "latest", "-f", "timestamp", "--rpc-url", rpc]);
            let ts = parse_u64_quantity(ts.trim(), "latest block timestamp");
            if ts > deadline {
                break;
            }
            if waited >= 300 {
                die(format!(
                    "challenge window still open after {waited}s (block ts {ts} <= deadline {deadline})"
                ));
            }
            eprintln!(
                "pw-finalize: challenge window open (block ts {ts} <= deadline {deadline}); waiting…"
            );
            std::thread::sleep(std::time::Duration::from_secs(6));
            waited += 6;
        }
    }
}

fn read_bool_view_at(rpc: &str, rollup: &str, sig: &str, arg: &str, block_number: u64) -> bool {
    const TRUE_WORD: &str = "0x0000000000000000000000000000000000000000000000000000000000000001";
    let block = format!("0x{block_number:x}");
    cast(&[
        "call",
        rollup,
        sig,
        arg,
        "--block",
        &block,
        "--rpc-url",
        rpc,
    ])
    .trim()
        == TRUE_WORD
}

fn read_u64_view_at(rpc: &str, contract: &str, sig: &str, arg: &str, block_number: u64) -> u64 {
    let block = format!("0x{block_number:x}");
    let raw = cast(&[
        "call",
        contract,
        sig,
        arg,
        "--block",
        &block,
        "--rpc-url",
        rpc,
    ]);
    abi_word_u64(raw.trim().trim_start_matches("0x"), sig)
}

fn read_u64_view2_at(
    rpc: &str,
    contract: &str,
    sig: &str,
    arg0: &str,
    arg1: &str,
    block_number: u64,
) -> u64 {
    let block = format!("0x{block_number:x}");
    let raw = cast(&[
        "call",
        contract,
        sig,
        arg0,
        arg1,
        "--block",
        &block,
        "--rpc-url",
        rpc,
    ]);
    abi_word_u64(raw.trim().trim_start_matches("0x"), sig)
}

fn read_bool_view0_at(rpc: &str, contract: &str, sig: &str, block_number: u64) -> bool {
    const TRUE_WORD: &str = "0x0000000000000000000000000000000000000000000000000000000000000001";
    let block = format!("0x{block_number:x}");
    cast(&["call", contract, sig, "--block", &block, "--rpc-url", rpc]).trim() == TRUE_WORD
}

fn parse_u64_quantity(raw: &str, what: &str) -> u64 {
    let raw = raw.trim();
    if let Some(hex) = raw.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).unwrap_or_else(|e| die(format!("parse {what}: {e}")))
    } else {
        raw.parse::<u64>()
            .unwrap_or_else(|e| die(format!("parse {what}: {e}")))
    }
}

const UNFINALIZED_DEVNET_ESCAPE_ENV: &str = "INTMAX_ALLOW_UNFINALIZED_DEVNET";

fn unfinalized_devnet_escape_enabled() -> bool {
    std::env::var(UNFINALIZED_DEVNET_ESCAPE_ENV).as_deref() == Ok("1")
}

fn rpc_block_json(rpc: &str, tag: &str) -> Result<String, String> {
    let out = Command::new("cast")
        .args([
            "rpc",
            "eth_getBlockByNumber",
            tag,
            "false",
            "--rpc-url",
            rpc,
        ])
        .output()
        .map_err(|error| format!("start finalized-head RPC read: {error}"))?;
    if !out.status.success() {
        return Err(format!(
            "RPC returned status {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    if out.stdout.len() > 16 * 1024 * 1024 {
        return Err("RPC block response exceeds 16 MiB".into());
    }
    String::from_utf8(out.stdout)
        .map_err(|error| format!("RPC block response is not UTF-8: {error}"))
}

fn parse_l1_checkpoint_block(
    raw: &str,
    chain_id: u64,
    source: intmax3_zkp::l1_finality::L1FinalitySource,
) -> Result<intmax3_zkp::l1_finality::L1FinalizedCheckpoint, String> {
    use intmax3_zkp::l1_finality::L1FinalizedCheckpoint;

    let value: serde_json::Value =
        serde_json::from_str(raw.trim()).map_err(|error| format!("parse block JSON: {error}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "block response is null or not an object".to_string())?;
    let field = |name: &str| {
        object
            .get(name)
            .ok_or_else(|| format!("block response has no {name}"))
    };
    let block_number = json_u64_quantity(field("number")?, "block number")?;
    let block_hash = field("hash")?
        .as_str()
        .ok_or_else(|| "block hash is not a string".to_string())?
        .parse::<Bytes32>()
        .map_err(|error| format!("parse block hash: {error}"))?;
    let parent_hash = field("parentHash")?
        .as_str()
        .ok_or_else(|| "block parentHash is not a string".to_string())?
        .parse::<Bytes32>()
        .map_err(|error| format!("parse block parentHash: {error}"))?;
    let checkpoint = L1FinalizedCheckpoint {
        chain_id,
        block_number,
        block_hash,
        parent_hash,
        source,
    };
    checkpoint.validate()?;
    Ok(checkpoint)
}

/// Return the only L1 head permitted to authorize durable fund state. Public networks require the
/// RPC's `finalized` tag. An RPC without that capability is rejected; `latest` is available only
/// when the endpoint itself reports chain 31337 and the operator explicitly sets the escape env.
fn read_durable_l1_checkpoint(
    rpc: &str,
    expected_chain_id: u64,
) -> intmax3_zkp::l1_finality::L1FinalizedCheckpoint {
    use intmax3_zkp::l1_finality::{ANVIL_CHAIN_ID, L1FinalitySource};

    let observed_chain_id = rpc_chain_id(rpc);
    if observed_chain_id != expected_chain_id {
        die(format!(
            "L1 RPC chain id changed from {expected_chain_id} to {observed_chain_id}; refusing durable state"
        ));
    }
    let finalized = rpc_block_json(rpc, "finalized").and_then(|raw| {
        parse_l1_checkpoint_block(&raw, observed_chain_id, L1FinalitySource::RpcFinalized)
    });
    match finalized {
        Ok(checkpoint) => checkpoint,
        Err(finalized_error)
            if observed_chain_id == ANVIL_CHAIN_ID && unfinalized_devnet_escape_enabled() =>
        {
            eprintln!(
                "WARNING: {UNFINALIZED_DEVNET_ESCAPE_ENV}=1 on chain {ANVIL_CHAIN_ID}; using latest as a non-finalized development checkpoint ({finalized_error})"
            );
            rpc_block_json(rpc, "latest")
                .and_then(|raw| {
                    parse_l1_checkpoint_block(
                        &raw,
                        observed_chain_id,
                        L1FinalitySource::DevnetLatest,
                    )
                })
                .unwrap_or_else(|error| die(format!("read development L1 checkpoint: {error}")))
        }
        Err(error) => die(format!(
            "RPC cannot supply a valid `finalized` block ({error}); refusing to adopt L1 fund state. Only chain {ANVIL_CHAIN_ID} may explicitly set {UNFINALIZED_DEVNET_ESCAPE_ENV}=1 for local testing."
        )),
    }
}

fn revalidate_l1_checkpoint(
    rpc: &str,
    checkpoint: &intmax3_zkp::l1_finality::L1FinalizedCheckpoint,
) -> intmax3_zkp::l1_finality::L1FinalizedCheckpoint {
    checkpoint
        .validate()
        .unwrap_or_else(|error| die(format!("stored L1 checkpoint is invalid: {error}")));
    let tag = format!("0x{:x}", checkpoint.block_number);
    let canonical = rpc_block_json(rpc, &tag)
        .and_then(|raw| parse_l1_checkpoint_block(&raw, checkpoint.chain_id, checkpoint.source))
        .unwrap_or_else(|error| die(format!("re-read stored L1 checkpoint: {error}")));
    if canonical.block_hash != checkpoint.block_hash
        || canonical.parent_hash != checkpoint.parent_hash
        || canonical.block_number != checkpoint.block_number
    {
        die(format!(
            "stored L1 checkpoint {} was replaced (reorg detected); refusing all payout progress",
            checkpoint.block_number
        ));
    }
    let current = read_durable_l1_checkpoint(rpc, checkpoint.chain_id);
    if current.source != checkpoint.source
        || current.block_number < checkpoint.block_number
        || (current.block_number == checkpoint.block_number
            && (current.block_hash != checkpoint.block_hash
                || current.parent_hash != checkpoint.parent_hash))
    {
        die(
            "durable L1 head regressed or changed at the stored height; refusing all payout progress",
        );
    }
    current
}

/// A state read that authorizes a new action must be made at the current durable head, not merely
/// at some still-canonical historical checkpoint. If finality advances during the read, retry from
/// a fresh head so intervening credit/authorization changes cannot be missed.
fn require_stable_durable_l1_checkpoint(
    rpc: &str,
    checkpoint: &intmax3_zkp::l1_finality::L1FinalizedCheckpoint,
) {
    let current = revalidate_l1_checkpoint(rpc, checkpoint);
    if current != *checkpoint {
        die(
            "durable L1 head advanced during the pinned state read; retry from the new finalized head",
        );
    }
}

fn same_l1_receipt_identity(
    left: &intmax3_zkp::partial_withdrawal_payout::L1TransactionReceipt,
    right: &intmax3_zkp::partial_withdrawal_payout::L1TransactionReceipt,
) -> bool {
    left.tx_hash == right.tx_hash
        && left.block_hash == right.block_hash
        && left.block_number == right.block_number
        && left.chain_id == right.chain_id
        && left.from == right.from
        && left.to == right.to
        && left.success == right.success
        && left.call_kind == right.call_kind
        && left.calldata_hash == right.calldata_hash
        && left.transaction_nonce == right.transaction_nonce
        && left.manager_finalized_auth_digest == right.manager_finalized_auth_digest
}

fn revalidate_stored_l1_receipt(
    rpc: &str,
    stored: &intmax3_zkp::partial_withdrawal_payout::L1TransactionReceipt,
) {
    revalidate_l1_checkpoint(rpc, &stored.finalized_checkpoint);
    stored
        .finalized_checkpoint
        .covers_receipt(stored.block_number, stored.block_hash)
        .unwrap_or_else(|error| die(format!("stored receipt is outside its checkpoint: {error}")));
    let reread = read_l1_receipt(rpc, &stored.tx_hash.to_string(), stored.call_kind);
    if !same_l1_receipt_identity(stored, &reread) {
        die(format!(
            "stored receipt {} changed or was orphaned; refusing all payout progress",
            stored.tx_hash
        ));
    }
}

fn revalidate_candidate_l1_confirmations(
    rpc: &str,
    candidate: &intmax3_zkp::partial_withdrawal_payout::PartialWithdrawalCandidate,
) {
    if let Some(confirmation) = &candidate.finalize_confirmation {
        revalidate_stored_l1_receipt(rpc, &confirmation.receipt);
    }
    if let Some(confirmation) = &candidate.payout_confirmation {
        revalidate_stored_l1_receipt(rpc, &confirmation.receipt);
    }
    if let Some(confirmation) = &candidate.pull_confirmation {
        revalidate_stored_l1_receipt(rpc, &confirmation.receipt);
    }
}

fn read_account_nonce(rpc: &str, account: &str, block: &str) -> u64 {
    let raw = cast(&["nonce", account, "--block", block, "--rpc-url", rpc]);
    parse_u64_quantity(raw.trim(), &format!("{block} account nonce"))
}

/// Refuse to guess when a transaction at the pinned nonce may still be pending. If both latest and
/// pending nonces equal the intent nonce, the nonce is free and rebroadcasting the exact calldata
/// is safe. A mined-but-unresolved nonce is also a hard failure: the canonical-block scan should
/// have found it, so proceeding would hide an RPC/pruning/reorg inconsistency.
fn require_nonce_free_for_exact_rebroadcast(rpc: &str, caller: &str, intended_nonce: u64) {
    let latest = read_account_nonce(rpc, caller, "latest");
    let pending = read_account_nonce(rpc, caller, "pending");
    if latest > intended_nonce {
        die(format!(
            "sender nonce {intended_nonce} is already mined but no exact canonical receipt was found"
        ));
    }
    if pending > intended_nonce {
        die(format!(
            "sender nonce {intended_nonce} is still pending; retry after it is mined or dropped"
        ));
    }
    if latest < intended_nonce || pending < intended_nonce {
        die(format!(
            "sender nonce regressed below persisted intent {intended_nonce} (latest={latest}, pending={pending})"
        ));
    }
}

/// Return a successful-or-failed mined receipt candidate for the exact persisted intent. The
/// payout store performs the final success/target/calldata checks. Known hashes are tried first;
/// then canonical blocks are scanned by `(caller, nonce)` to bridge a crash immediately after
/// broadcast but before the returned transaction hash was fsynced.
fn reconcile_confirmed_l1_call(
    rpc: &str,
    expected_to: &str,
    intent: &intmax3_zkp::partial_withdrawal_payout::BroadcastIntent,
    known_hashes: &[Bytes32],
    call_kind: intmax3_zkp::partial_withdrawal_payout::L1CallKind,
) -> Option<intmax3_zkp::partial_withdrawal_payout::L1TransactionReceipt> {
    for hash in known_hashes.iter().rev() {
        if let Some(receipt) = try_read_l1_receipt(rpc, &hash.to_string(), call_kind) {
            return Some(receipt);
        }
    }

    let durable_head = read_durable_l1_checkpoint(rpc, rpc_chain_id(rpc));
    if durable_head.block_number < intent.start_block {
        return None;
    }
    for block_number in intent.start_block..=durable_head.block_number {
        let block_arg = block_number.to_string();
        let raw = cast(&["block", &block_arg, "--full", "--json", "--rpc-url", rpc]);
        let block: serde_json::Value = serde_json::from_str(raw.trim())
            .unwrap_or_else(|e| die(format!("parse full block {block_number}: {e}")));
        match exact_intent_tx_hash_in_block(&block, intent, expected_to) {
            Ok(Some(hash)) => {
                return Some(read_l1_receipt(rpc, &hash, call_kind));
            }
            Ok(None) => {}
            Err(error) => die(format!(
                "transaction at persisted sender nonce is not the exact intended call: {error}"
            )),
        }
    }
    None
}

fn exact_intent_tx_hash_in_block(
    block: &serde_json::Value,
    intent: &intmax3_zkp::partial_withdrawal_payout::BroadcastIntent,
    expected_to: &str,
) -> Result<Option<String>, String> {
    let transactions = block["transactions"]
        .as_array()
        .ok_or_else(|| "full block has no transactions array".to_string())?;
    let caller = intent.caller.to_string().to_lowercase();
    for tx in transactions {
        let Some(from) = tx["from"].as_str() else {
            continue;
        };
        if from.to_lowercase() != caller {
            continue;
        }
        let nonce = json_u64_quantity(&tx["nonce"], "transaction nonce")?;
        if nonce != intent.caller_nonce {
            continue;
        }
        let to = tx["to"].as_str().unwrap_or_default();
        let input = tx["input"]
            .as_str()
            .or_else(|| tx["data"].as_str())
            .ok_or_else(|| "transaction at intended nonce has no input".to_string())?;
        let calldata = hex::decode(input.trim_start_matches("0x"))
            .map_err(|e| format!("decode transaction input: {e}"))?;
        let calldata_hash = Bytes32::from_bytes_be(&keccak_hash::keccak(&calldata).0)
            .map_err(|e| format!("convert calldata hash: {e:?}"))?;
        if !to.eq_ignore_ascii_case(expected_to) || calldata_hash != intent.calldata_hash {
            return Err(format!(
                "nonce {} was replaced (to={to}, calldataHash={calldata_hash})",
                intent.caller_nonce
            ));
        }
        let hash = tx["hash"]
            .as_str()
            .filter(|hash| !hash.is_empty())
            .ok_or_else(|| "exact transaction has no hash".to_string())?;
        return Ok(Some(hash.to_string()));
    }
    Ok(None)
}

fn json_u64_quantity(value: &serde_json::Value, what: &str) -> Result<u64, String> {
    if let Some(value) = value.as_u64() {
        return Ok(value);
    }
    let raw = value
        .as_str()
        .ok_or_else(|| format!("{what} is neither a JSON integer nor quantity string"))?;
    if let Some(hex) = raw.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).map_err(|e| format!("parse {what}: {e}"))
    } else {
        raw.parse().map_err(|e| format!("parse {what}: {e}"))
    }
}

fn extract_tx_hash(send_json: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(send_json.trim())
        .unwrap_or_else(|e| die(format!("parse cast send output: {e}\n{send_json}")));
    v["transactionHash"]
        .as_str()
        .unwrap_or_else(|| die("cast send output has no transactionHash"))
        .to_string()
}

fn read_l1_receipt(
    rpc: &str,
    tx_hash: &str,
    call_kind: intmax3_zkp::partial_withdrawal_payout::L1CallKind,
) -> intmax3_zkp::partial_withdrawal_payout::L1TransactionReceipt {
    // `cast receipt` waits by default. A previously persisted hash can disappear after a reorg,
    // so waiting here would hang recovery forever instead of failing closed on missing evidence.
    let receipt_raw = cast(&["receipt", tx_hash, "--json", "--async", "--rpc-url", rpc]);
    parse_l1_receipt(rpc, tx_hash, call_kind, &receipt_raw)
}

fn try_read_l1_receipt(
    rpc: &str,
    tx_hash: &str,
    call_kind: intmax3_zkp::partial_withdrawal_payout::L1CallKind,
) -> Option<intmax3_zkp::partial_withdrawal_payout::L1TransactionReceipt> {
    let out = Command::new("cast")
        .args(["receipt", tx_hash, "--json", "--async", "--rpc-url", rpc])
        .output()
        .unwrap_or_else(|e| die(format!("cast receipt failed to start: {e}")));
    if !out.status.success() || out.stdout.is_empty() {
        return None;
    }
    let raw = String::from_utf8_lossy(&out.stdout);
    Some(parse_l1_receipt(rpc, tx_hash, call_kind, &raw))
}

fn parse_l1_receipt(
    rpc: &str,
    tx_hash: &str,
    call_kind: intmax3_zkp::partial_withdrawal_payout::L1CallKind,
    receipt_raw: &str,
) -> intmax3_zkp::partial_withdrawal_payout::L1TransactionReceipt {
    use intmax3_zkp::partial_withdrawal_payout::L1TransactionReceipt;
    let r: serde_json::Value = serde_json::from_str(receipt_raw.trim())
        .unwrap_or_else(|e| die(format!("parse cast receipt: {e}")));
    let receipt_tx_hash = r["transactionHash"]
        .as_str()
        .unwrap_or_else(|| die("receipt missing transactionHash"));
    if !receipt_tx_hash.eq_ignore_ascii_case(tx_hash) {
        die(format!(
            "receipt transaction hash {receipt_tx_hash} differs from requested {tx_hash}"
        ));
    }
    let observed_chain_id = rpc_chain_id(rpc);
    let durable_before = read_durable_l1_checkpoint(rpc, observed_chain_id);
    let tx_raw = cast(&["tx", tx_hash, "--json", "--rpc-url", rpc]);
    let t: serde_json::Value =
        serde_json::from_str(tx_raw.trim()).unwrap_or_else(|e| die(format!("parse cast tx: {e}")));
    let hex_u64 = |v: &serde_json::Value, what: &str| -> u64 {
        let s = v
            .as_str()
            .unwrap_or_else(|| die(format!("receipt missing {what}")));
        u64::from_str_radix(s.trim_start_matches("0x"), 16)
            .or_else(|_| s.parse::<u64>())
            .unwrap_or_else(|e| die(format!("parse {what}: {e}")))
    };
    let input = t["input"]
        .as_str()
        .unwrap_or_else(|| die("tx missing input"))
        .to_string();
    let calldata_hash = cast(&["keccak", &input])
        .trim()
        .parse::<Bytes32>()
        .unwrap_or_else(|e| die(format!("keccak tx input: {e}")));
    let chain_id = if t["chainId"].is_null() {
        observed_chain_id
    } else {
        json_u64_quantity(&t["chainId"], "chainId").unwrap_or_else(|e| die(e))
    };
    if chain_id != observed_chain_id {
        die(format!(
            "transaction chain id {chain_id} differs from RPC chain id {observed_chain_id}"
        ));
    }
    let from = r["from"]
        .as_str()
        .unwrap_or_default()
        .parse::<Address>()
        .unwrap_or_else(|e| die(format!("from: {e}")));
    let to = r["to"]
        .as_str()
        .unwrap_or_default()
        .parse::<Address>()
        .unwrap_or_else(|e| die(format!("to: {e}")));
    let tx_object_hash = t["hash"]
        .as_str()
        .unwrap_or_else(|| die("tx object missing hash"));
    let tx_from = t["from"]
        .as_str()
        .unwrap_or_default()
        .parse::<Address>()
        .unwrap_or_else(|error| die(format!("tx object from: {error}")));
    let tx_to = t["to"]
        .as_str()
        .unwrap_or_default()
        .parse::<Address>()
        .unwrap_or_else(|error| die(format!("tx object to: {error}")));
    validate_tx_receipt_identity(
        tx_hash,
        receipt_tx_hash,
        tx_object_hash,
        from,
        to,
        tx_from,
        tx_to,
    )
    .unwrap_or_else(|error| die(error));
    let manager_finalized_auth_digest = if call_kind
        == intmax3_zkp::partial_withdrawal_payout::L1CallKind::FinalizePartialWithdrawal
    {
        Some(
            manager_finalized_auth_digest_from_receipt(&r, to)
                .unwrap_or_else(|error| die(format!("manager-finalization receipt: {error}"))),
        )
    } else {
        None
    };
    let block_hash = r["blockHash"]
        .as_str()
        .unwrap_or_default()
        .parse::<Bytes32>()
        .unwrap_or_else(|e| die(format!("block hash: {e}")));
    let block_number = hex_u64(&r["blockNumber"], "blockNumber");
    let receipt_block_tag = format!("0x{block_number:x}");
    let canonical_receipt_block = rpc_block_json(rpc, &receipt_block_tag)
        .and_then(|raw| parse_l1_checkpoint_block(&raw, observed_chain_id, durable_before.source))
        .unwrap_or_else(|error| die(format!("read canonical receipt block: {error}")));
    if let Err(error) = validate_receipt_block_evidence(
        block_number,
        block_hash,
        &canonical_receipt_block,
        &durable_before,
    ) {
        if block_number > durable_before.block_number {
            die(format!(
                "transaction {tx_hash} is canonical but not finalized yet: {error}; its durable intent/hash journal is retained, retry after the finalized head advances"
            ));
        }
        die(format!(
            "transaction {tx_hash} is not canonical/final: {error}"
        ));
    }

    // The receipt and durable head are read twice around all auxiliary transaction reads. This
    // closes the same-height replacement window where a provider changes its answer mid-check.
    let second_raw = cast(&["receipt", tx_hash, "--json", "--async", "--rpc-url", rpc]);
    let second: serde_json::Value = serde_json::from_str(second_raw.trim())
        .unwrap_or_else(|error| die(format!("parse second cast receipt: {error}")));
    validate_receipt_readback_identity(&r, &second).unwrap_or_else(|field| {
        die(format!(
            "transaction {tx_hash} receipt field {field} changed during read-back (reorg detected)"
        ))
    });
    revalidate_l1_checkpoint(rpc, &durable_before);
    let durable_after = read_durable_l1_checkpoint(rpc, observed_chain_id);
    if durable_after.source != durable_before.source
        || durable_after.block_number < durable_before.block_number
        || (durable_after.block_number == durable_before.block_number
            && (durable_after.block_hash != durable_before.block_hash
                || durable_after.parent_hash != durable_before.parent_hash))
    {
        die("durable L1 head regressed or changed during receipt read-back");
    }
    durable_after
        .covers_receipt(block_number, block_hash)
        .unwrap_or_else(|error| die(format!("receipt lost durable coverage: {error}")));

    L1TransactionReceipt {
        tx_hash: tx_hash
            .parse()
            .unwrap_or_else(|e| die(format!("tx hash: {e}"))),
        block_hash,
        block_number,
        chain_id,
        from,
        to,
        success: r["status"]
            .as_str()
            .map(|s| s == "0x1" || s == "1")
            .unwrap_or_else(|| r["status"].as_u64() == Some(1)),
        call_kind,
        calldata_hash,
        transaction_nonce: hex_u64(&t["nonce"], "nonce"),
        finalized_checkpoint: durable_after,
        manager_finalized_auth_digest,
    }
}

fn validate_tx_receipt_identity(
    requested_hash: &str,
    receipt_hash: &str,
    tx_object_hash: &str,
    receipt_from: Address,
    receipt_to: Address,
    tx_from: Address,
    tx_to: Address,
) -> Result<(), String> {
    if !tx_object_hash.eq_ignore_ascii_case(requested_hash)
        || !tx_object_hash.eq_ignore_ascii_case(receipt_hash)
        || tx_from != receipt_from
        || tx_to != receipt_to
    {
        return Err(
            "cast tx object hash/from/to differs from the requested receipt; refusing mixed RPC evidence"
                .into(),
        );
    }
    Ok(())
}

fn validate_receipt_readback_identity(
    first: &serde_json::Value,
    second: &serde_json::Value,
) -> Result<(), &'static str> {
    for field in [
        "transactionHash",
        "blockHash",
        "blockNumber",
        "status",
        "from",
        "to",
        // Includes every topic, emitting address, data, log index and the nested `removed` flag.
        // The manager authDigest is extracted from these logs, so omitting them would allow the
        // exact evidence used for the binding to change between the two receipt reads.
        "logs",
    ] {
        if first[field] != second[field] {
            return Err(field);
        }
    }
    Ok(())
}

const PARTIAL_WITHDRAWAL_FINALIZED_TOPIC: &str =
    "0xd1a13162df7b47389414f1cb86675a13490c1aea4abe185d1fc644ad30f69685";

/// Extract the candidate identity from the manager's canonical receipt.  The finalized manager
/// function is intentionally zero-argument, so sender/nonce/calldata identify the call but not the
/// pending request it consumed.  The indexed `authDigest` event is the only transaction-local
/// evidence that closes that ambiguity.
fn manager_finalized_auth_digest_from_receipt(
    receipt: &serde_json::Value,
    expected_manager: Address,
) -> Result<Bytes32, String> {
    let logs = receipt["logs"]
        .as_array()
        .ok_or_else(|| "receipt has no logs array".to_string())?;
    let expected_manager = expected_manager.to_string();
    let mut observed = None;
    for log in logs {
        let Some(address) = log["address"].as_str() else {
            continue;
        };
        if !address.eq_ignore_ascii_case(&expected_manager) {
            continue;
        }
        let Some(topics) = log["topics"].as_array() else {
            continue;
        };
        let Some(topic0) = topics.first().and_then(serde_json::Value::as_str) else {
            continue;
        };
        if !topic0.eq_ignore_ascii_case(PARTIAL_WITHDRAWAL_FINALIZED_TOPIC) {
            continue;
        }
        if log["removed"].as_bool() == Some(true) {
            return Err("manager-finalization event is marked removed".into());
        }
        if topics.len() != 3 {
            return Err("manager-finalization event has the wrong indexed-topic count".into());
        }
        let auth_digest = topics[1]
            .as_str()
            .ok_or_else(|| "manager-finalization auth digest topic is not a string".to_string())?
            .parse::<Bytes32>()
            .map_err(|error| format!("parse manager-finalization auth digest: {error}"))?;
        topics[2]
            .as_str()
            .ok_or_else(|| "manager-finalization chain key topic is not a string".to_string())?
            .parse::<Bytes32>()
            .map_err(|error| format!("parse manager-finalization chain key: {error}"))?;
        if observed.replace(auth_digest).is_some() {
            return Err("receipt contains more than one manager-finalization event".into());
        }
    }
    observed.ok_or_else(|| "receipt lacks the manager's PartialWithdrawalFinalized event".into())
}

/// A finalized head only authenticates its own hash directly. For any lower receipt height we
/// still require an exact `eth_getBlockByNumber(height)` answer and compare that canonical hash.
/// Keeping this as a pure predicate makes the lower-height reorg boundary regression-testable.
fn validate_receipt_block_evidence(
    receipt_block_number: u64,
    receipt_block_hash: Bytes32,
    canonical_receipt_block: &intmax3_zkp::l1_finality::L1FinalizedCheckpoint,
    durable_head: &intmax3_zkp::l1_finality::L1FinalizedCheckpoint,
) -> Result<(), String> {
    durable_head.covers_receipt(receipt_block_number, receipt_block_hash)?;
    if canonical_receipt_block.chain_id != durable_head.chain_id {
        return Err("canonical receipt block belongs to a different chain".into());
    }
    if canonical_receipt_block.block_number != receipt_block_number
        || canonical_receipt_block.block_hash != receipt_block_hash
    {
        return Err("receipt block hash was replaced (reorg detected)".into());
    }
    Ok(())
}

#[cfg(test)]
mod partial_withdrawal_reconcile_tests {
    use super::*;
    use intmax3_zkp::{
        l1_finality::{L1FinalitySource, L1FinalizedCheckpoint},
        partial_withdrawal_payout::BroadcastIntent,
    };

    fn word(tag: u32) -> Bytes32 {
        Bytes32::from_u32_slice(&[tag; 8]).expect("bytes32")
    }

    fn checkpoint(block_number: u64, block_hash: Bytes32) -> L1FinalizedCheckpoint {
        L1FinalizedCheckpoint {
            chain_id: 1,
            block_number,
            block_hash,
            parent_hash: word(block_number.saturating_sub(1) as u32),
            source: L1FinalitySource::RpcFinalized,
        }
    }

    fn intent(calldata: &[u8]) -> BroadcastIntent {
        BroadcastIntent {
            caller: "0x0000000000000000000000000000000000000071"
                .parse()
                .unwrap(),
            start_block: 10,
            caller_nonce: 3,
            calldata_hash: Bytes32::from_bytes_be(&keccak_hash::keccak(calldata).0).unwrap(),
            credit_before: U256::default(),
        }
    }

    #[test]
    fn canonical_block_scan_recovers_the_exact_crash_window_transaction() {
        let block = serde_json::json!({
            "transactions": [{
                "hash": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "from": "0x0000000000000000000000000000000000000071",
                "to": "0x0000000000000000000000000000000000000042",
                "nonce": "0x3",
                "input": "0x1234"
            }]
        });
        let found = exact_intent_tx_hash_in_block(
            &block,
            &intent(&[0x12, 0x34]),
            "0x0000000000000000000000000000000000000042",
        )
        .unwrap();
        assert_eq!(
            found.as_deref(),
            Some("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
    }

    #[test]
    fn canonical_block_scan_rejects_same_nonce_replacement() {
        let block = serde_json::json!({
            "transactions": [{
                "hash": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "from": "0x0000000000000000000000000000000000000071",
                "to": "0x0000000000000000000000000000000000000042",
                "nonce": 3,
                "input": "0x9999"
            }]
        });
        let error = exact_intent_tx_hash_in_block(
            &block,
            &intent(&[0x12, 0x34]),
            "0x0000000000000000000000000000000000000042",
        )
        .unwrap_err();
        assert!(error.contains("replaced"));
    }

    #[test]
    fn lower_height_receipt_requires_its_own_canonical_block_hash() {
        let receipt_hash = word(100);
        let durable_head = checkpoint(103, word(103));

        // Coverage by a higher finalized head proves only the height bound. It must not make an
        // arbitrary lower-height hash authoritative without the exact canonical block query.
        assert!(durable_head.covers_receipt(100, receipt_hash).is_ok());
        let replaced = checkpoint(100, word(999));
        assert!(
            validate_receipt_block_evidence(100, receipt_hash, &replaced, &durable_head,).is_err()
        );

        let canonical = checkpoint(100, receipt_hash);
        validate_receipt_block_evidence(100, receipt_hash, &canonical, &durable_head)
            .expect("exact lower-height canonical block evidence");
    }

    #[test]
    fn zero_argument_manager_finalize_requires_one_exact_auth_digest_event() {
        let manager = "0x0000000000000000000000000000000000000043"
            .parse::<Address>()
            .unwrap();
        let auth = word(0xa11);
        let chain_key = word(0xc11);
        let log = serde_json::json!({
            "address": manager.to_string(),
            "topics": [
                PARTIAL_WITHDRAWAL_FINALIZED_TOPIC,
                auth.to_string(),
                chain_key.to_string()
            ],
            "removed": false
        });
        let receipt = serde_json::json!({ "logs": [log.clone()] });
        assert_eq!(
            manager_finalized_auth_digest_from_receipt(&receipt, manager).unwrap(),
            auth
        );

        let wrong_manager = "0x0000000000000000000000000000000000000044"
            .parse::<Address>()
            .unwrap();
        assert!(manager_finalized_auth_digest_from_receipt(&receipt, wrong_manager).is_err());

        let duplicate = serde_json::json!({ "logs": [log.clone(), log] });
        assert!(manager_finalized_auth_digest_from_receipt(&duplicate, manager).is_err());

        let removed = serde_json::json!({
            "logs": [{
                "address": manager.to_string(),
                "topics": [
                    PARTIAL_WITHDRAWAL_FINALIZED_TOPIC,
                    auth.to_string(),
                    chain_key.to_string()
                ],
                "removed": true
            }]
        });
        assert!(manager_finalized_auth_digest_from_receipt(&removed, manager).is_err());
    }

    #[test]
    fn receipt_reread_binds_logs_and_removed_flag_exactly() {
        let first = serde_json::json!({
            "transactionHash": word(1).to_string(),
            "blockHash": word(2).to_string(),
            "blockNumber": "0x2",
            "status": "0x1",
            "from": "0x0000000000000000000000000000000000000071",
            "to": "0x0000000000000000000000000000000000000043",
            "logs": [{
                "address": "0x0000000000000000000000000000000000000043",
                "topics": [PARTIAL_WITHDRAWAL_FINALIZED_TOPIC, word(3).to_string(), word(4).to_string()],
                "data": "0x",
                "removed": false
            }]
        });
        validate_receipt_readback_identity(&first, &first).unwrap();

        let mut changed_digest = first.clone();
        changed_digest["logs"][0]["topics"][1] = serde_json::json!(word(99).to_string());
        assert_eq!(
            validate_receipt_readback_identity(&first, &changed_digest),
            Err("logs")
        );

        let mut removed = first.clone();
        removed["logs"][0]["removed"] = serde_json::json!(true);
        assert_eq!(
            validate_receipt_readback_identity(&first, &removed),
            Err("logs")
        );
    }

    #[test]
    fn tx_object_cannot_be_mixed_with_a_different_receipt() {
        let tx_hash = word(1).to_string();
        let from = "0x0000000000000000000000000000000000000071"
            .parse::<Address>()
            .unwrap();
        let to = "0x0000000000000000000000000000000000000043"
            .parse::<Address>()
            .unwrap();
        validate_tx_receipt_identity(&tx_hash, &tx_hash, &tx_hash, from, to, from, to).unwrap();
        assert!(
            validate_tx_receipt_identity(
                &tx_hash,
                &tx_hash,
                &word(2).to_string(),
                from,
                to,
                from,
                to,
            )
            .is_err()
        );
        assert!(
            validate_tx_receipt_identity(&tx_hash, &tx_hash, &tx_hash, from, to, to, from,)
                .is_err()
        );
    }
}

#[cfg(test)]
mod signing_ledger_tests {
    use super::*;

    fn fixture() -> CliState {
        // This binary intentionally has no implicit test-key fallback. The focused unit tests opt
        // in before `keys_for` is first resolved, exactly like the process E2Es do.
        unsafe { std::env::set_var(INSECURE_KEYS_ENV, "1") };

        let controlled: Vec<ControlledMember> = (0..2u16)
            .map(|slot| ControlledMember {
                slot,
                keygen_seed: CLI_COSIGNER_SEED_BASE + u64::from(slot),
                balance_amount: 0,
                balance_seed: 0,
                has_witness: false,
                token_witnesses: Vec::new(),
            })
            .collect();
        let keys: Vec<MemberKeys> = controlled
            .iter()
            .map(|member| keys_for(member.keygen_seed))
            .collect();
        let members: Vec<MemberInfo> = keys
            .iter()
            .enumerate()
            .map(|(slot, keys)| member_info_for(slot as u16, keys))
            .collect();
        let record = build_record(7, &members, 0, 0).expect("two-member record");
        let zero = intmax3_zkp::common::balance_state::zero_ciphertext().clone();
        let ciphertexts = vec![zero; members.len()];
        let regev_pk_digests: Vec<Bytes32> = keys
            .iter()
            .map(|keys| Bytes32::from(keys.regev_pk.poseidon_digest()))
            .collect();
        let recipients: Vec<Address> = (0..members.len())
            .map(|slot| test_recipient_for(7, slot))
            .collect();
        let genesis = assemble_genesis_state_backed(
            &record,
            &ciphertexts,
            &regev_pk_digests,
            &recipients,
            0,
            Bytes32::default(),
            Bytes32::default(),
        )
        .expect("zero-funded genesis");
        let (channel_id, settled_tx_chain, token_funds_digest) =
            exit_kit_statement_key(&genesis);
        let receipt = SignerExitKitReceipt {
            schema_version: SIGNER_EXIT_KIT_RECEIPT_SCHEMA_VERSION,
            archive_sha256: [0x11; 32],
            balance_verifier_data_sha256: [0x22; 32],
            chain_id: DEVNET_CHAIN_ID,
            rollup: Address::from_hex("0x0000000000000000000000000000000000000043").unwrap(),
            source_signed_head_digest: genesis.digest,
            channel_id,
            settled_tx_chain,
            token_funds_digest,
        };

        CliState {
            state_schema_version: STATE_SCHEMA_VERSION,
            controlled,
            snapshot: ChannelSnapshot {
                record,
                state: genesis,
                members,
                settled_tx_accumulator: default_settled_tx_accumulator(),
            },
            settlement_binding: None,
            applied_tx_identities: HashSet::new(),
            spent_tx_identities: HashSet::new(),
            imported_deposits: HashSet::new(),
            state_signing_ledger: BTreeMap::new(),
            signer_exit_kit_receipt: Some(receipt),
            // Unit tests exercise the release policy itself. Production deserialization always
            // resets this skipped field to false and must re-open + cryptographically verify the
            // content-addressed archive before signing.
            signer_exit_kit_receipt_verified: true,
        }
    }

    fn child_of(predecessor: &ChannelState, epoch_delta: u64) -> ChannelState {
        let mut child = predecessor.clone();
        child.epoch = predecessor.epoch + epoch_delta;
        child.prev_digest = predecessor.digest;
        child.member_signatures.clear();
        child.with_computed_digest()
    }

    #[test]
    fn exact_replay_is_byte_identical_and_sibling_is_refused_before_signing() {
        let mut cli = fixture();
        let record = cli.snapshot.record.clone();
        let controlled = cli.controlled[0].clone();
        let successor = child_of(&cli.snapshot.state, 1);

        let first = ledgered_state_signature_with(
            &mut cli,
            &record,
            &controlled,
            &successor,
            StateSigningPurpose::InChannelSend,
            None,
            None,
            |keys| sign_state(keys, controlled.slot as u8, &successor).map_err(|e| e.to_string()),
        )
        .expect("first decision");
        assert_eq!(cli.state_signing_ledger.len(), 1);

        let replay = ledgered_state_signature_with(
            &mut cli,
            &record,
            &controlled,
            &successor,
            StateSigningPurpose::InChannelSend,
            None,
            None,
            |_| panic!("an exact replay must not invoke a signer"),
        )
        .expect("exact replay");
        assert_eq!(
            serde_json::to_vec(&replay).unwrap(),
            serde_json::to_vec(&first).unwrap(),
            "the persisted randomized Falcon signature must replay byte-for-byte"
        );

        let sibling = child_of(&cli.snapshot.state, 2);
        let refusal = ledgered_state_signature_with(
            &mut cli,
            &record,
            &controlled,
            &sibling,
            StateSigningPurpose::InChannelSend,
            None,
            None,
            |_| panic!("a sibling refusal must happen before signing"),
        )
        .unwrap_err();
        assert!(refusal.contains("ANTI-EQUIVOCATION REFUSAL"), "{refusal}");
        assert_eq!(cli.state_signing_ledger.len(), 1);
    }

    #[test]
    fn asset_or_composition_moving_purposes_fail_before_signing() {
        let template = fixture();
        let record = template.snapshot.record.clone();
        let controlled = template.controlled[0].clone();
        let successor = child_of(&template.snapshot.state, 1);
        let blocked = [
            StateSigningPurpose::InterChannelDebit,
            StateSigningPurpose::InterChannelFundImport,
            StateSigningPurpose::InterChannelBundleApply,
            StateSigningPurpose::BurnDebit,
            StateSigningPurpose::TokenRegister,
            StateSigningPurpose::L1DepositFundImport,
            StateSigningPurpose::L1DepositBundleApply,
            StateSigningPurpose::CloseFunding,
        ];

        for purpose in blocked {
            let mut cli = template.clone();
            let plan_digest = purpose.is_terminal().then(|| {
                Bytes32::from_hex(
                    "0x1111111111111111111111111111111111111111111111111111111111111111",
                )
                .unwrap()
            });

            let refusal = ledgered_state_signature_with(
                &mut cli,
                &record,
                &controlled,
                &successor,
                purpose,
                plan_digest,
                None,
                |_| panic!("{purpose:?} must be refused before invoking the signer"),
            )
            .unwrap_err();
            assert!(
                refusal.contains("SIGNER-INDEPENDENT EXIT REQUIRED"),
                "unexpected refusal for {purpose:?}: {refusal}"
            );
            assert!(
                cli.state_signing_ledger.is_empty(),
                "{purpose:?} must not leave a signing decision behind"
            );
        }
    }

    #[test]
    fn unsafe_historical_signature_is_not_released_from_the_ledger() {
        let mut cli = fixture();
        let record = cli.snapshot.record.clone();
        let controlled = cli.controlled[0].clone();
        let successor = child_of(&cli.snapshot.state, 1);
        let keys = keys_for(controlled.keygen_seed);
        let signature = sign_state(&keys, controlled.slot as u8, &successor).unwrap();
        let key =
            state_signing_ledger_key(successor.channel_id, successor.prev_digest, controlled.slot);
        cli.state_signing_ledger.insert(
            key,
            StateSigningLedgerEntry {
                channel_id: successor.channel_id,
                predecessor_digest: successor.prev_digest,
                member_slot: controlled.slot,
                successor_digest: successor.digest,
                purpose: StateSigningPurpose::BurnDebit,
                plan_digest: None,
                signature,
            },
        );

        let refusal = ledgered_state_signature_with(
            &mut cli,
            &record,
            &controlled,
            &successor,
            StateSigningPurpose::BurnDebit,
            None,
            None,
            |_| panic!("ledger replay must not invoke the signer"),
        )
        .unwrap_err();
        assert!(
            refusal.contains("SIGNER-INDEPENDENT EXIT REQUIRED"),
            "stored bytes must not bypass the release gate: {refusal}"
        );
    }

    #[test]
    fn legacy_head_without_a_non_vacuous_receipt_cannot_reuse_h2_zero() {
        let mut cli = fixture();
        cli.signer_exit_kit_receipt = None;
        cli.signer_exit_kit_receipt_verified = false;
        let record = cli.snapshot.record.clone();
        let controlled = cli.controlled[0].clone();
        let successor = child_of(&cli.snapshot.state, 1);

        let refusal = ledgered_state_signature_with(
            &mut cli,
            &record,
            &controlled,
            &successor,
            StateSigningPurpose::InChannelSend,
            None,
            None,
            |_| panic!("missing-receipt refusal must happen before signing"),
        )
        .unwrap_err();
        assert!(
            refusal.contains("no cryptographically verified signer exit-kit receipt"),
            "key equality must not become a vacuous receipt: {refusal}"
        );
        assert!(cli.state_signing_ledger.is_empty());
    }

    fn assert_exit_kit_reuse_refused(mut cli: CliState, successor: ChannelState, needle: &str) {
        let record = cli.snapshot.record.clone();
        let controlled = cli.controlled[0].clone();
        let refusal = ledgered_state_signature_with(
            &mut cli,
            &record,
            &controlled,
            &successor,
            StateSigningPurpose::InChannelSend,
            None,
            None,
            |_| panic!("exit-kit reuse refusal must happen before signing"),
        )
        .unwrap_err();
        assert!(refusal.contains(needle), "unexpected refusal: {refusal}");
        assert!(cli.state_signing_ledger.is_empty());
    }

    #[test]
    fn h2_zero_reuse_requires_exact_predecessor_and_statement_key() {
        let cli = fixture();

        let mut wrong_predecessor = child_of(&cli.snapshot.state, 1);
        wrong_predecessor.prev_digest =
            Bytes32::from_hex("0x1111111111111111111111111111111111111111111111111111111111111111")
                .unwrap();
        wrong_predecessor = wrong_predecessor.with_computed_digest();
        assert_exit_kit_reuse_refused(
            cli.clone(),
            wrong_predecessor,
            "does not extend the locally durable signed head",
        );

        let mut nonzero_h2 = child_of(&cli.snapshot.state, 1);
        nonzero_h2.h2_tag =
            Bytes32::from_hex("0x2222222222222222222222222222222222222222222222222222222222222222")
                .unwrap();
        nonzero_h2 = nonzero_h2.with_computed_digest();
        assert_exit_kit_reuse_refused(cli.clone(), nonzero_h2, "only an H2=0 successor");

        let mut changed_chain = child_of(&cli.snapshot.state, 1);
        changed_chain.balance_state.settled_tx_chain =
            Bytes32::from_hex("0x3333333333333333333333333333333333333333333333333333333333333333")
                .unwrap();
        changed_chain = changed_chain.with_computed_digest();
        assert_exit_kit_reuse_refused(cli.clone(), changed_chain, "exact (channel_id");

        let mut changed_funds = child_of(&cli.snapshot.state, 1);
        changed_funds.channel_fund.amounts[0] = U256::from(1u64);
        changed_funds = changed_funds.with_computed_digest();
        assert_exit_kit_reuse_refused(cli, changed_funds, "exact (channel_id");
    }

    #[test]
    fn withdrawal_claimed_receipt_is_bound_to_one_exact_payout() {
        let manager = "0x0000000000000000000000000000000000000043";
        let recipient = Address::from_hex("0x0000000000000000000000000000000000000071").unwrap();
        let nullifier =
            Bytes32::from_hex("0x3333333333333333333333333333333333333333333333333333333333333333")
                .unwrap();
        let topic0 = format!(
            "0x{}",
            hex::encode(
                keccak_hash::keccak(b"WithdrawalClaimed(bytes32,address,uint32,uint256)").0
            )
        );
        let recipient_topic = format!(
            "0x000000000000000000000000{}",
            recipient.to_hex().trim_start_matches("0x")
        );
        let mut receipt = serde_json::json!({
            "status": "0x1",
            "to": manager,
            "logs": [{
                "address": manager,
                "topics": [topic0, nullifier.to_hex(), recipient_topic, format!("0x{:064x}", 9u32)],
                "data": format!("0x{:064x}", 17u64),
                "removed": false
            }]
        });
        validate_withdrawal_claimed_receipt(
            &receipt.to_string(),
            manager,
            nullifier,
            recipient,
            9,
            17,
        )
        .expect("exact event");

        receipt["logs"][0]["topics"][3] = serde_json::json!(format!("0x{:064x}", 8u32));
        assert!(
            validate_withdrawal_claimed_receipt(
                &receipt.to_string(),
                manager,
                nullifier,
                recipient,
                9,
                17,
            )
            .is_err(),
            "a different token must fail closed"
        );
        receipt["logs"][0]["topics"][3] = serde_json::json!(format!("0x{:064x}", 9u32));
        receipt["logs"][0]["data"] = serde_json::json!(format!("0x{:064x}", 18u64));
        assert!(
            validate_withdrawal_claimed_receipt(
                &receipt.to_string(),
                manager,
                nullifier,
                recipient,
                9,
                17,
            )
            .is_err(),
            "a different amount must fail closed"
        );
    }
}

#[cfg(test)]
mod falcon_identity_tests {
    use super::*;

    /// SECURITY (Phase-3 review finding 7 — the defect this test exists to prevent recurring).
    ///
    /// Three CLI paths bind the channel's Falcon cosigner identities and MUST agree:
    ///   * `close` / `cancel-close` — the member-set commitment the proof binds,
    ///   * `export-reg-record`      — the `pk_g`s handed to L1 `registerChannel`,
    ///   * `withdraw`               — the in-band channel registration inside
    ///     `build_channel_withdrawal`.
    ///
    /// They diverged once, and silently: `withdraw` reached a builder that RE-DERIVED its own
    /// keys from a different seed formula, so `export-reg-record` registered one member set on
    /// L1 while the withdrawal proved against another. Fail-closed (nothing forged is accepted)
    /// but a real liveness break — the channel becomes unclosable — and it was invisible because
    /// the only test covering the invariant compared two values that came from the same variable.
    ///
    /// PHASE 4 re-aim. The structural fix is now stronger than the Phase-3 one: there is no
    /// Falcon seed formula in this binary at all. `MemberKeys` carries the key, and every path
    /// reads it off the member object. So this test walks the ACTUAL producers rather than the
    /// seeds behind them:
    ///   * `cli_active_keys()`    — what `export-reg-record` registers and `withdraw` hands the
    ///     withdrawal builder (both take the leading `TEST_ACTIVE_MEMBERS` slice);
    ///   * `cli_members()`        — what `create-channel` puts in the `ChannelRecord`, AND the
    ///     `ControlledMember.keygen_seed` every co-signing command feeds to `keys_for` to MINT
    ///     `state.member_signatures`;
    /// and asserts the identities coincide slot by slot. If anyone reintroduces a second
    /// derivation on either side, these stop matching.
    ///
    /// DETACHED-SIGNING re-aim: the second producer used to be `cli_falcon_keys()`, "the signing
    /// keys `close`/`cancel-close` prove with". `close`/`cancel-close` no longer hold any key —
    /// they consume the cosignatures already in the head state, verified against
    /// `record.member_pk_gs[slot]` — so the invariant is re-pointed at its true source. It is now
    /// checked one link EARLIER and one link WIDER: the registered `pk_g`, the persisted cosigning
    /// seed, and the withdraw/export identity must all be one identity. If the cosigning identity
    /// diverged from the registered one, the close prover's §3.5 gate would reject every signature
    /// on a `pk_g` mismatch and the channel would be unclosable.
    #[test]
    fn cli_falcon_identities_agree_across_close_register_and_withdraw() {
        // SECURITY: `keys_for` now FAILS CLOSED — without a provenance it calls `die` (exit 1),
        // which would abort the whole test binary. This test only compares identities to each
        // other, so it opts in to the deterministic test keys explicitly, exactly as the E2E
        // harnesses do. `key_provenance` memoises in a `OnceLock`, and this is the binary's only
        // test, so the variable is set before any reader exists (no cross-thread env race).
        // SAFETY: single-threaded prologue of the only test in this binary.
        unsafe { std::env::set_var(INSECURE_KEYS_ENV, "1") };

        let active = TEST_ACTIVE_MEMBERS;

        // What `export-reg-record` registers / what `withdraw` hands `build_channel_withdrawal`.
        let registered: Vec<MemberKeys> = cli_active_keys().into_iter().take(active).collect();
        assert_eq!(registered.len(), active);

        // What `create-channel` puts in the ChannelRecord, and what every co-signing command
        // re-derives from the persisted `keygen_seed` to MINT `state.member_signatures` — the set
        // `close` / `cancel-close` now consume detached and verify against
        // `record.member_pk_gs[slot]`.
        let (record_members, _enc, controlled) = cli_members();
        assert_eq!(record_members.len(), active);
        assert_eq!(controlled.len(), active);

        for slot in 0..active {
            // registered-in-record identity == withdraw/export identity
            assert_eq!(
                record_members[slot].pk_g,
                registered[slot].pk_g(),
                "slot {slot}: the identity `withdraw`/`export-reg-record` registers differs from \
                 the one `create-channel` puts in the ChannelRecord — this is exactly the \
                 divergence that made channels unclosable"
            );
            // co-SIGNING identity (re-derived from the persisted seed on every cosign) ==
            // registered identity. Under detached close signing this is the link the close
            // prover's gate enforces at proving time: a mismatch here means every cosignature is
            // rejected on `pk_g` and the channel cannot be closed at all.
            assert_eq!(
                keys_for(controlled[slot].keygen_seed).pk_g(),
                record_members[slot].pk_g,
                "slot {slot}: the identity that CO-SIGNS channel state differs from the registered \
                 one; `close` verifies every detached cosignature against \
                 record.member_pk_gs[slot], so this divergence makes the channel unclosable"
            );
        }

        // The identities must also be distinct per slot (a shared key would let one member
        // satisfy several slots, defeating the close circuit's A5 distinctness check).
        for a in 0..active {
            for b in (a + 1)..active {
                assert_ne!(
                    registered[a].pk_g(),
                    registered[b].pk_g(),
                    "cosigner slots {a} and {b} must not share a Falcon identity"
                );
            }
        }
    }
}

/// THE chain-id selection rule for `deploy-settlement`, pinned.
///
/// WHAT THESE TESTS ARE FOR (security, not mechanics): `DeployWalletSettlement.s.sol` installs a
/// `WalletMockMleVerifier` whose `verify` returns true for ANY proof. A settlement stack built on
/// it has a vacuous close-proof check, so anyone can close any channel registered with it to any
/// state and take the funds. Until now `cmd_deploy_settlement` named that script unconditionally
/// while `api/routes/*.js` invoked the command with whatever `RPC` the deployment was configured
/// with — i.e. the product's own API would have installed it on a real network. The tests below
/// exist to fail if that door is ever reopened, including through an "unknown chain" default.
#[cfg(test)]
mod deploy_plan_tests {
    use super::*;

    /// The mock script may be selected for EXACTLY one chain id, and it must be anvil's.
    #[test]
    fn only_the_devnet_chain_id_selects_the_mock_deployer() {
        assert_eq!(
            settlement_deploy_plan(DEVNET_CHAIN_ID),
            SettlementDeployPlan::MockDevnet,
            "anvil must keep the devnet stack the local E2Es depend on"
        );
        assert_eq!(DEVNET_CHAIN_ID, 31337, "anvil's chain id");
    }

    /// Boundary + real-network + nonsense chain ids: every one of them must get the REAL-VK
    /// script. `0` and `u64::MAX` are in here deliberately — an id we cannot interpret must fail
    /// towards the safe stack, never towards the mock one.
    #[test]
    fn every_other_chain_id_selects_the_real_deployer() {
        let ids = [
            0u64,     // unset / unreadable-looking
            1,        // mainnet
            10,       // optimism
            56,       // bnb
            100,      // gnosis
            137,      // polygon
            8453,     // base
            42161,    // arbitrum
            11155111, // sepolia
            17000,    // holesky
            31336,    // one below anvil
            31338,    // one above anvil
            313370,   // anvil's id with a digit appended
            3133,     // anvil's id truncated
            u64::MAX,
        ];
        for id in ids {
            assert_eq!(
                settlement_deploy_plan(id),
                SettlementDeployPlan::RealChain,
                "chain id {id} must NOT get the mock-verifier stack"
            );
        }
    }

    /// Property sweep: no chain id other than 31337 may ever produce the mock script or the mock
    /// contract name, however the selection is implemented.
    #[test]
    fn no_non_devnet_chain_id_can_reach_the_mock_script() {
        // Deterministic LCG (Numerical Recipes constants) — a fixed, reproducible sweep rather
        // than a random one, so a failure is always reproducible from the test alone.
        let mut x: u64 = 0x1234_5678_9abc_def0;
        let mut sampled = 0usize;
        for i in 0..100_000u64 {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            // Mix in small ids too, so the neighbourhood of 31337 is covered densely.
            let id = if i % 2 == 0 { x } else { i };
            if id == DEVNET_CHAIN_ID {
                continue;
            }
            sampled += 1;
            let plan = settlement_deploy_plan(id);
            assert_eq!(plan, SettlementDeployPlan::RealChain, "chain id {id}");
            assert_eq!(
                plan.script(),
                "script/DeployCloseCli.s.sol",
                "chain id {id}"
            );
            assert!(
                !plan.script().contains("WalletSettlement")
                    && !plan.contract().contains("WalletSettlement"),
                "chain id {id} reached the mock deployer"
            );
        }
        assert!(sampled > 99_000, "the sweep must actually sample");
    }

    /// The two plans must stay distinguishable: if they ever named the same script, every guard
    /// above would pass while the mock stack shipped everywhere.
    #[test]
    fn the_two_plans_name_different_deployers() {
        let mock = SettlementDeployPlan::MockDevnet;
        let real = SettlementDeployPlan::RealChain;
        assert_ne!(mock.script(), real.script());
        assert_ne!(mock.contract(), real.contract());
        assert_ne!(mock.label(), real.label());
        assert!(mock.script().contains("DeployWalletSettlement"));
        assert!(real.script().contains("DeployCloseCli"));
    }

    /// The fixture list must name files that actually exist in this checkout — otherwise the
    /// up-front check would refuse every real deploy for a file the script never reads (or, worse,
    /// pass while the script's real input is missing).
    #[test]
    fn the_declared_fixtures_exist_and_are_the_ones_the_script_reads() {
        let data = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("contracts/test/data");
        for f in CLOSE_CLI_FIXTURES {
            assert!(data.join(f).is_file(), "missing fixture {f} in {data:?}");
        }
        let script = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("contracts/script/DeployCloseCli.s.sol"),
        )
        .expect("read DeployCloseCli.s.sol");
        for f in CLOSE_CLI_FIXTURES {
            assert!(
                script.contains(f),
                "{f} is checked up front but {} never reads it",
                "DeployCloseCli.s.sol"
            );
        }
        // The record this command stages itself is the script's remaining input.
        assert!(
            script.contains("cli_reg_record.json"),
            "the staged registration record must still be what the script reads"
        );
        for f in CLOSE_BACKING_STAGED_FILES {
            assert!(
                script.contains(f),
                "runtime-staged CloseAssetBacking input {f} is plan-digested but the production script never reads it"
            );
        }
        assert!(
            script.contains("initializeBackingVk"),
            "the production script must initialize the distinct CloseAssetBacking VK"
        );
    }
}
