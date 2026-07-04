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
    fs,
    process::{Command, exit},
};

use intmax3_zkp::{
    circuits::{
        balance::{
            balance_processor::BalanceProcessor,
            common::recipient::calculate_recipient_from_user_id, spend_circuit::SpendCircuit,
        },
        channel::{
            cancel_close_pis::{CANCEL_CLOSE_PUBLIC_INPUTS_LEN, CancelClosePublicInputs},
            close_pis::{CHANNEL_CLOSE_PUBLIC_INPUTS_LEN, ChannelClosePublicInputs},
            post_close_claim_pis::{
                POST_CLOSE_CLAIM_PUBLIC_INPUTS_LEN, PostCloseClaimPublicInputs,
            },
            withdrawal_claim_pis::{
                WITHDRAWAL_CLAIM_PUBLIC_INPUTS_LEN, WithdrawalClaimPublicInputs,
            },
        },
        test_utils::{
            balance_witness_generator::{BalanceWitnessGenerator, ReceiveDepositData},
            block_witness_generator::{
                BlockWitnessGenerator, BlockWitnessGeneratorHandle, ChannelMemberKeys,
                TEST_ACTIVE_MEMBERS, test_recipient_for,
            },
        },
    },
    common::{
        balance_state::tx_leaf_hash,
        channel::{
            ChannelRecord, ChannelState, CloseIntent, CloseWithdrawal, InterChannelTx,
            MemberSignature,
        },
        channel_id::ChannelId,
        deposit::Deposit,
        salt::Salt,
        withdrawal::Withdrawal,
    },
    constants::{MAX_CHANNEL_MEMBERS, TOKEN_UNIT},
    ethereum_types::{
        address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait as _, u256::U256,
    },
    regev::{RegevCiphertext, RegevPk, RegevSecurityLevel, encrypt_amount},
    utils::{
        conversion::ToU64 as _,
        serialize::{deserialize_verifier_data, serialize_verifier_data},
    },
    wallet_core::{
        BuiltInterChannelCredit, BuiltSend, CancelCloseProver, ChannelBalanceAttestation,
        ChannelSnapshot, ChannelWithdrawalParams, CloseProver, InterChannelDebitPayload,
        InterChannelTransferDescriptor, MemberInfo, MemberKeys, PostCloseClaimProver,
        RefreshPayload, SendPayload, WithdrawalClaimProver, add_signature,
        assemble_genesis_state_backed, build_channel_withdrawal, build_inter_channel_credit,
        build_l1_deposit_import, build_record, build_send, decrypt_balance,
        default_settled_tx_accumulator, partial_withdrawal_auth_digest, sign_state,
        sign_state_if_backed, verify_all_signatures, verify_inter_channel_credit_transition,
        verify_inter_channel_send_transition, verify_l1_deposit_import_transition,
        verify_refresh_transition, verify_send_transition, verify_snapshot,
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

// Base-layer proof config (matches `BalanceProcessor` / `poseidon_sig::circuit`).
type BF = GoldilocksField;
type BC = PoseidonGoldilocksConfig;
const BD: usize = 2;

const LEVEL: RegevSecurityLevel = RegevSecurityLevel::Production;
const STATE_FILE: &str = "cli_state.json";
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
// A-3 P3 close artifacts: the descriptor + wrapped-close MLE proof the on-chain
// `ChannelSettlementManager.submitCloseIntent` consumes (same schema as generate_close_fixture).
const CLOSE_INTENT_FILE: &str = "close_intent.json";
const CLOSE_INTENT_MLE_FILE: &str = "close_intent_mle.json";
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
// Delegate demo: slots 0,1,2 = three CLI-controlled CO-SIGNING MEMBERS (with genesis balances);
// slot 3 = the browser, a send-only DELEGATE (delegate_count = 1).
const CLI_SLOTS: &[u8] = &[0, 1, 2];
// Genesis allocations in BASE UNITS (= wei). With TOKEN_DECIMALS=18, 1 token = 1 ETH.
// 0.04 + 0.03 + 0.02 = 0.09 ETH total — fits comfortably in u64 (max ~18.4 ETH).
const CLI_GENESIS: &[(u8, u64)] = &[
    (0, TOKEN_UNIT / 25),      // 0.04 ETH
    (1, TOKEN_UNIT / 100 * 3), // 0.03 ETH
    (2, TOKEN_UNIT / 50),      // 0.02 ETH
];
const BROWSER_DELEGATE_SLOT: u8 = 3;
const DELEGATE_COUNT: u8 = 1;
// The first browser delegate's genesis allocation (BASE UNITS) out of the deposited fund (so
// Σ balances == fund): 50 tokens.
const DELEGATE_GENESIS: u64 = 0;

#[derive(Serialize, Deserialize)]
struct ControlledMember {
    slot: u8,
    keygen_seed: u64,
    balance_amount: u64,
    balance_seed: u64,
    has_witness: bool,
}

#[derive(Serialize, Deserialize)]
struct CliState {
    controlled: Vec<ControlledMember>,
    snapshot: ChannelSnapshot,
    /// REPLAY LEDGER (inter-channel invariant 6): the set of inter-channel `tx_hash`es already
    /// CREDITED into THIS channel (the DESTINATION / B side). A credit is applied at most once; a
    /// descriptor whose `tx_hash` is already present is REFUSED (fail-closed). Persisted in
    /// `cli_state.json` so the ledger survives across CLI invocations (each channel runs as its
    /// own process). Defaults to empty for states written before this field existed
    /// (back-compat with already-deployed cli_state.json files).
    #[serde(default)]
    applied_tx_hashes: Vec<Bytes32>,
    /// SPENT LEDGER (A side): the set of inter-channel `tx_hash`es already DEBITED out of THIS
    /// channel as the SOURCE. A debit is applied at most once; if a tx_hash is already present
    /// the combined `cosign-inter-transfer` REFUSES (fail-closed). This is the A-side
    /// counterpart to `applied_tx_hashes` — together they make a transfer atomic AND
    /// single-use on both ends.
    #[serde(default)]
    spent_tx_hashes: Vec<Bytes32>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrowserContribution {
    regev_pk: RegevPk,
    /// The browser member's Goldilocks signing public key `pk_g` (canonical Bytes32 hex, P4-2).
    pk_g: String,
    /// P3: the browser member's BabyBear hash-sig public key `pk_b` (canonical Bytes32 hex, A11).
    pk_b: String,
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

fn keys_for(seed: u64) -> MemberKeys {
    MemberKeys::generate(&mut StdRng::seed_from_u64(seed))
}

/// The channel's ACTIVE participant key material in slot order for the close-lifecycle paths: the 3
/// CLI co-signing members (slots 0..3) FOLLOWED BY the delegate (slot 3). The delegate uses
/// `keys_for(DELEGATE_SEED)` — the SAME identity `gen-contribution <bal> <DELEGATE_SEED>` produces
/// — so the on-chain registration (member set + delegate) matches the channel state `init` builds.
/// `member_count = TEST_ACTIVE_MEMBERS = 3`, `delegate_count = 1` in the CHANNEL STATE. Used by
/// `export-reg-record` and `withdraw`, which under Option B register the COSIGNER slice only (L1
/// registration never carries delegates; the delegate is authenticated by the cosigner-signed H1
/// slot tree).
fn cli_active_keys() -> Vec<MemberKeys> {
    let mut v: Vec<MemberKeys> = CLI_SLOTS
        .iter()
        .map(|&slot| keys_for(0xC1_0000 + slot as u64))
        .collect();
    let delegate_seed: u64 = std::env::var("DELEGATE_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    v.push(keys_for(delegate_seed));
    v
}

fn member_info_for(slot: u8, keys: &MemberKeys) -> MemberInfo {
    MemberInfo {
        slot,
        pk_g: keys.pk_g(),
        pk_b: keys.pk_b(),
        regev_pk: keys.regev_pk.clone(),
    }
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &str) -> T {
    let s = fs::read_to_string(path).unwrap_or_else(|e| die(format!("read {path}: {e}")));
    serde_json::from_str(&s).unwrap_or_else(|e| die(format!("parse {path}: {e}")))
}

fn write_json<T: Serialize>(path: &str, value: &T) {
    let s = serde_json::to_string_pretty(value).unwrap_or_else(|e| die(e));
    fs::write(path, s).unwrap_or_else(|e| die(format!("write {path}: {e}")));
}

fn load_state() -> CliState {
    read_json(STATE_FILE)
}
fn save_state(state: &CliState) {
    write_json(STATE_FILE, state);
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
    #[serde(default)]
    deposit_tx: String,
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
    let backing: ChannelBacking = read_json(BACKING_FILE);
    (
        balance_vd,
        ChannelBalanceAttestation {
            balance_proof: proof,
        },
        backing,
    )
}

// anvil dev account[0] private key — a PUBLIC throwaway (safe on the CLI; NEVER a real key).
const ANVIL_DEV_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/// The key that sends the on-chain deposit during `setup-backing`. Defaults to the public anvil dev
/// key (local). For a real testnet (Sepolia) the funded deployer key is passed via the
/// `INTMAX_DEPOSIT_KEY` env var so its value is handed to `cast` by the shell, never hardcoded.
/// SECURITY: this is read once and passed straight to `cast --private-key`; it is never logged.
fn deposit_key_env() -> String {
    std::env::var("INTMAX_DEPOSIT_KEY").unwrap_or_else(|_| ANVIL_DEV_KEY.to_string())
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
    let fund: u64 = args
        .get(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| CLI_GENESIS.iter().map(|(_, a)| *a).sum::<u64>() + DELEGATE_GENESIS);

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

    let deposit_key = deposit_key_env();
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
        let dep_hex = cast(&["wallet", "address", "--private-key", &deposit_key])
            .trim()
            .to_string();
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
        let send_out = cast(&[
            "send",
            &rollup,
            "deposit(bytes32,uint32,uint256,bytes32)",
            &recipient_hex,
            "0",
            &amount.to_string(),
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "--value",
            &amount.to_string(),
            "--private-key",
            &deposit_key,
            "--rpc-url",
            &rpc,
            "--json",
        ]);
        let txhash = send_out
            .split("\"transactionHash\":\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .unwrap_or_else(|| die("deposit tx hash not found in cast output"))
            .to_string();

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
    write_json(
        BACKING_FILE,
        &ChannelBacking {
            settled_tx_chain: pis.settled_tx_chain.to_hex(),
            // A-3 P1: REAL L1-close anchor (rollup latestFinalizedStateRoot at backing time).
            intmax_state_root: intmax_state_root.to_hex(),
            fund,
            rollup: rollup.clone(),
            deposit_tx: txhash.clone(),
            deposit_salt: Some(deposit_salt),
            deposit_recipient: recipient.to_hex(),
        },
    );
    println!(
        "setup-backing OK: REAL on-chain deposit {fund} to channel {} (IntmaxRollup {rollup}, tx {txhash}); settled_tx_chain={}. Now run `init`.",
        channel_id_env(),
        pis.settled_tx_chain.to_hex()
    );
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
    delegate_count: u8,
    member_pk_gs: Vec<String>,
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

/// A-3 P3: build the channel's REAL close-intent proof from the wallet's final signed state + the N
/// co-signing members' keys + the base-layer balance proof, write the on-chain artifacts, and
/// submit the close to L1: `requestClose` (cast) then `submitCloseIntent` (the wrapped-close MLE
/// proof is large struct calldata, so it goes through the `RunClose` forge step). Usage:
///   channel_member close <manager_addr> [rpc_url]
/// env: CLOSE_NONCE, CLOSE_SNAPSHOT_MBN, CLOSE_BURN_TX (members agree), CLOSE_SV (settlement
/// verifier).
fn cmd_close(args: &[String]) {
    let manager = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| die("close needs <manager_addr> [rpc_url]"));
    let rpc = args
        .get(2)
        .cloned()
        .unwrap_or_else(|| "http://localhost:8545".to_string());

    // Phase control (opt-in; default = the combined requestClose + submitCloseIntent flow):
    //   CLOSE_REQUEST_ONLY=1 → A26 requestClose-only (freeze + grace), NO proving, return early.
    //   CLOSE_SKIP_REQUEST=1 → A28 submit-intent / A29 challenge: skip requestClose (the channel is
    //     already ClosePending), build the proof and submit the (possibly higher-version) intent.
    // SECURITY: pure on-chain call-sequence control; the proof + the manager/verifier gate every
    // soundness property. Skipping requestClose cannot weaken the close — submitCloseIntent still
    // verifies the wrapped MLE proof and the manager enforces challenge ordering (epoch, version).
    let skip_request = std::env::var("CLOSE_SKIP_REQUEST").is_ok();
    if std::env::var("CLOSE_REQUEST_ONLY").is_ok() {
        let key = deposit_key_env();
        eprintln!(
            "[close] requestClose() on manager {manager} (A26 request-only phase, no proving)…"
        );
        cast(&[
            "send",
            &manager,
            "requestClose()",
            "--private-key",
            &key,
            "--rpc-url",
            &rpc,
        ]);
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

    let close_nonce = env_u64("CLOSE_NONCE", 1);
    let snapshot_mbn = env_u64("CLOSE_SNAPSHOT_MBN", 1);
    let burn_tx_hash = std::env::var("CLOSE_BURN_TX")
        .ok()
        .and_then(|s| Bytes32::from_hex(&s).ok())
        .unwrap_or_else(|| Bytes32::from_u32_slice(&[9, 8, 7, 6, 0, 0, 0, 0]).unwrap());

    // Load the final signed state, the N ACTIVE co-signing members' keys (CLI controls slots
    // 0..member_count), and the base-layer balance proof.
    let st = load_state();
    let state = st.snapshot.state.clone();
    let member_count = state.balance_state.member_count as usize;
    let member_keys: Vec<MemberKeys> = (0..member_count)
        .map(|slot| keys_for(0xC1_0000 + slot as u64))
        .collect();
    let (balance_vd, att, backing) = load_backing();
    let balance_proof = ProofWithPublicInputs::<BF, BC, BD>::from_bytes(
        att.balance_proof.clone(),
        &balance_vd.common,
    )
    .unwrap_or_else(|e| die(format!("deserialize balance proof: {e}")));

    eprintln!(
        "[close] building close witness (member_count={member_count}) + proving close circuit + MLE (HEAVY)…"
    );
    let prover = CloseProver::new(&balance_vd);
    let witness = prover
        .build_full_witness(
            &state,
            &member_keys,
            balance_proof,
            close_nonce,
            burn_tx_hash,
            snapshot_mbn,
        )
        .unwrap_or_else(|e| die(format!("build close witness: {}", e.0)));
    let close_proof = prover
        .prove(&witness)
        .unwrap_or_else(|e| die(format!("close proof: {}", e.0)));
    let mle_json = prover
        .prove_mle(&close_proof)
        .unwrap_or_else(|e| die(format!("close MLE: {}", e.0)));

    // Descriptor from the PROVED close public inputs (the 95 raw close limbs the manager re-binds).
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
    };

    fs::write(CLOSE_INTENT_MLE_FILE, &mle_json)
        .unwrap_or_else(|e| die(format!("write {CLOSE_INTENT_MLE_FILE}: {e}")));
    write_json(CLOSE_INTENT_FILE, &descriptor);

    // A30 prerequisite: persist the EXACT pending `CloseIntent` (lossless serde) so a later
    // `cancel-close` reconstructs the same close_intent_digest the manager just froze on-chain.
    // Reconstructed identically to `cmd_claim` (same close params + the state that was closed); the
    // `CloseIntent::new` binding checks fail closed if the params disagree with the state.
    let close_tx = CloseWithdrawal {
        channel_id: state.channel_id,
        final_channel_state_digest: state.digest,
        final_balance_state_h1: state.balance_state.h1(),
        intmax_state_root: state.channel_fund.intmax_state_root,
        burn_tx_hash,
        burn_amount: state.channel_fund.amount,
        zkp: Vec::new(),
    };
    let close_intent = CloseIntent::new(close_nonce, &state, &close_tx, snapshot_mbn)
        .unwrap_or_else(|e| die(format!("reconstruct close intent for persistence: {e:?}")));
    write_json(CLOSE_INTENT_FULL_FILE, &close_intent);
    println!(
        "[close] wrote {CLOSE_INTENT_FILE} + {CLOSE_INTENT_MLE_FILE} + {CLOSE_INTENT_FULL_FILE} (close_intent_digest {})",
        pis.close_intent_digest.to_hex()
    );

    // ── On-chain: requestClose (freeze) then submitCloseIntent (large calldata → forge step). ──
    // When CLOSE_SKIP_REQUEST is set (A28 submit-after-request / A29 challenge), the channel is
    // ALREADY ClosePending — skip requestClose (it would revert) and go straight to the intent.
    let key = deposit_key_env();
    if skip_request {
        eprintln!(
            "[close] CLOSE_SKIP_REQUEST set: skipping requestClose (submit-intent / challenge on an already-pending close)…"
        );
    } else {
        eprintln!("[close] requestClose() on manager {manager}…");
        cast(&[
            "send",
            &manager,
            "requestClose()",
            "--private-key",
            &key,
            "--rpc-url",
            &rpc,
        ]);
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
    let data_dir = std::path::Path::new("contracts/test/data");
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
    let sv = std::env::var("CLOSE_SV").unwrap_or_default();
    eprintln!("[close] submitCloseIntent via forge RunClose step…");
    let status = std::process::Command::new("forge")
        .current_dir("contracts")
        .args([
            "script",
            "script/RunClose.s.sol",
            "--sig",
            "closeIntentStep()",
            "--rpc-url",
            &rpc,
            "--private-key",
            &key,
            "--broadcast",
        ])
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

/// A-3 P4: finalize the close after the challenge period has elapsed. `finalizeClose()` carries no
/// proof calldata (the close was already proven at submit time), so it is a plain `cast` call.
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
    let key = deposit_key_env();
    eprintln!(
        "[settle] finalizeClose() on manager {manager} (the challenge period must have elapsed)…"
    );
    cast(&[
        "send",
        &manager,
        "finalizeClose()",
        "--private-key",
        &key,
        "--rpc-url",
        &rpc,
    ]);
    println!(
        "[settle] channel finalized (Closed). Now run `withdraw` (rollup → manager) then `claim`."
    );
}

/// A-3 P4: the withdrawal-claim descriptor (the on-chain `ChannelSettlementManager.WithdrawalClaim`
/// fields, every value a PROVED withdrawal-claim public input).
#[derive(Serialize)]
struct WithdrawalClaimDescriptor {
    close_intent_digest: String,
    member_pk_g: String,
    recipient: String,
    user_amount_digest: String,
    amount: u64,
    withdrawal_nullifier: String,
}

/// A-3 P4: a member claims their slot balance from the CLOSED channel. Builds the withdrawal-claim
/// MLE proof via the verified `WithdrawalClaimProver` (the amount is DERIVED by decrypting the
/// member's own slot ciphertext, so it cannot over-claim), submits it (`submitWithdrawalClaim` via
/// the forge step), then pulls the credit (`claimWithdrawalCredit`). Usage:
///   channel_member claim <manager_addr> <member_slot> [rpc_url]
/// env: CLAIM_RECIPIENT (the member's registered L1 address; also the claimWithdrawalCredit
/// caller),      CLOSE_NONCE / CLOSE_BURN_TX / CLOSE_SNAPSHOT_MBN (MUST equal the values used at
/// `close`).
fn cmd_claim(args: &[String]) {
    let manager = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| die("claim needs <manager_addr> <member_slot> [rpc_url]"));
    let member_slot: u8 = args
        .get(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| die("claim needs <member_slot>"));
    let rpc = args
        .get(3)
        .cloned()
        .unwrap_or_else(|| "http://localhost:8545".to_string());
    let recipient = std::env::var("CLAIM_RECIPIENT")
        .ok()
        .and_then(|s| Address::from_hex(&s).ok())
        .unwrap_or_else(|| {
            die("set CLAIM_RECIPIENT=0x<20-byte member L1 recipient> (must equal the registered recipient)")
        });

    // A33 pull-only phase (opt-in): the claim proof was already submitted (totalWithdrawn
    // credited); just pull the ETH credit to the recipient. No proving. SECURITY:
    // claimWithdrawalCredit pays only the caller's previously-credited amount (caller MUST be
    // the recipient), so this is inert.
    if std::env::var("CLAIM_PULL_ONLY").is_ok() {
        let key = deposit_key_env();
        let recipient_hex = recipient.to_hex();
        eprintln!(
            "[claim] claimWithdrawalCredit() pull-only (caller must be the recipient {recipient_hex})…"
        );
        cast(&[
            "send",
            &manager,
            "claimWithdrawalCredit()",
            "--private-key",
            &key,
            "--rpc-url",
            &rpc,
        ]);
        println!("[claim] pull-only OK: recipient {recipient_hex} pulled its withdrawal credit.");
        return;
    }

    let close_nonce = env_u64("CLOSE_NONCE", 1);
    let snapshot_mbn = env_u64("CLOSE_SNAPSHOT_MBN", 1);
    let burn_tx_hash = std::env::var("CLOSE_BURN_TX")
        .ok()
        .and_then(|s| Bytes32::from_hex(&s).ok())
        .unwrap_or_else(|| Bytes32::from_u32_slice(&[9, 8, 7, 6, 0, 0, 0, 0]).unwrap());

    let st = load_state();
    let state = st.snapshot.state.clone();
    let final_balance_state = state.balance_state.clone();
    // Reconstruct the finalized close (MUST match what `close` submitted: same params + state).
    let close_tx = CloseWithdrawal {
        channel_id: state.channel_id,
        final_channel_state_digest: state.digest,
        final_balance_state_h1: state.balance_state.h1(),
        intmax_state_root: state.channel_fund.intmax_state_root,
        burn_tx_hash,
        burn_amount: state.channel_fund.amount,
        zkp: Vec::new(),
    };
    let close_intent = CloseIntent::new(close_nonce, &state, &close_tx, snapshot_mbn)
        .unwrap_or_else(|e| die(format!("reconstruct close intent: {e:?}")));

    let keys = keys_for(0xC1_0000 + member_slot as u64);
    let member_pk_g = keys.signing_key.public_key();

    eprintln!("[claim] building withdrawal claim for slot {member_slot} + proving (HEAVY)…");
    let prover = WithdrawalClaimProver::new();
    let witness = prover
        .build_full_witness(
            &final_balance_state,
            member_slot as usize,
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
    let data_dir = std::path::Path::new("contracts/test/data");
    fs::copy(wc_file, data_dir.join("sepolia_withdrawal_claim.json"))
        .unwrap_or_else(|e| die(format!("stage withdrawal_claim.json: {e}")));
    fs::copy(
        wc_mle_file,
        data_dir.join("sepolia_withdrawal_claim_mle.json"),
    )
    .unwrap_or_else(|e| die(format!("stage withdrawal_claim_mle.json: {e}")));
    let key = deposit_key_env();
    eprintln!("[claim] submitWithdrawalClaim via forge…");
    let status = std::process::Command::new("forge")
        .current_dir("contracts")
        .args([
            "script",
            "script/RunClose.s.sol",
            "--sig",
            "submitWithdrawalClaimStep()",
            "--rpc-url",
            &rpc,
            "--private-key",
            &key,
            "--broadcast",
        ])
        .env("MANAGER", &manager)
        .status()
        .unwrap_or_else(|e| die(format!("forge submitWithdrawalClaim failed to start: {e}")));
    if !status.success() {
        die(
            "forge submitWithdrawalClaim step failed (ensure the withdrawal-claim VK is initialized and funds were pulled into the manager)",
        );
    }
    let recipient_hex = recipient.to_hex();
    eprintln!("[claim] claimWithdrawalCredit() (caller must be the recipient {recipient_hex})…");
    cast(&[
        "send",
        &manager,
        "claimWithdrawalCredit()",
        "--private-key",
        &key,
        "--rpc-url",
        &rpc,
    ]);
    println!(
        "[claim] OK: recipient {recipient_hex} received native ETH (amount {}).",
        pis.amount
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

    // The REVIVED (later) signed state is the current committed head; the N co-signing members'
    // keys are derived deterministically (slots 0..member_count), exactly as `close` does.
    let st = load_state();
    let revived_state = st.snapshot.state.clone();
    let member_count = revived_state.balance_state.member_count as usize;
    let member_keys: Vec<MemberKeys> = (0..member_count)
        .map(|slot| keys_for(0xC1_0000 + slot as u64))
        .collect();

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
    let witness = prover
        .build_full_witness(&revived_state, &member_keys, &close_intent)
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
    let key = deposit_key_env();
    let data_dir = std::path::Path::new("contracts/test/data");
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
    let status = Command::new("forge")
        .current_dir("contracts")
        .args([
            "script",
            "script/RunClose.s.sol",
            "--sig",
            "cancelCloseStep()",
            "--rpc-url",
            &rpc,
            "--private-key",
            &key,
            "--broadcast",
        ])
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
/// CLOSE_NONCE/CLOSE_BURN_TX re-derivation is needed (and no env-var footgun).
fn cmd_post_close_claim(args: &[String]) {
    let manager = args.get(1).cloned().unwrap_or_else(|| {
        die("post-close-claim needs <manager_addr> <receiver_slot> <incoming_tx_index> [rpc_url]")
    });
    let receiver_slot: u8 = args
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
    let recipient = std::env::var("CLAIM_RECIPIENT")
        .ok()
        .and_then(|s| Address::from_hex(&s).ok())
        .unwrap_or_else(|| {
            die("set CLAIM_RECIPIENT=0x<20-byte member L1 recipient> (must equal the registered recipient)")
        });

    // The CLOSED channel's finalized state + its settled-tx accumulator (the inclusion anchor).
    let st = load_state();
    let final_balance_state = st.snapshot.state.balance_state.clone();
    let accumulator = st.snapshot.settled_tx_accumulator.clone();

    // The finalized close's digest — read from the EXACT pending `CloseIntent` persisted by `close`
    // (`close_intent_full.json`), the SAME lossless source `cancel-close` uses, so the proof's
    // `close_intent_digest` PI equals on-chain `finalizedCloseIntentDigest`. (No env-var
    // re-derivation footgun: a digest from differing CLOSE_NONCE/CLOSE_BURN_TX would silently
    // fail-close on-chain.)
    let close_intent: CloseIntent = read_json(CLOSE_INTENT_FULL_FILE);
    let close_intent_digest = close_intent.signing_digest();

    // The late inter-channel transfer that delivered the receiver's delta. The wallet persists the
    // source `InterChannelTransferDescriptor` (its `inter_channel_tx` carries the receiver deltas).
    let source_path = std::env::var("POST_CLOSE_SOURCE_TX")
        .unwrap_or_else(|_| "inter_descriptor.json".to_string());
    let source_desc: InterChannelTransferDescriptor = read_json(&source_path);
    let source_tx: InterChannelTx = source_desc.inter_channel_tx.clone();

    let keys = keys_for(0xC1_0000 + receiver_slot as u64);
    let receiver_pk_g = keys.signing_key.public_key();

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
    };

    fs::write(POST_CLOSE_CLAIM_MLE_FILE, &mle_json)
        .unwrap_or_else(|e| die(format!("write {POST_CLOSE_CLAIM_MLE_FILE}: {e}")));
    write_json(POST_CLOSE_CLAIM_FILE, &descriptor);
    println!(
        "[post-close-claim] wrote {POST_CLOSE_CLAIM_FILE} + {POST_CLOSE_CLAIM_MLE_FILE} (amount {})",
        pis.amount
    );

    // ── On-chain: submitPostCloseClaim (large struct calldata → forge step), then pull credit. ──
    let data_dir = std::path::Path::new("contracts/test/data");
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
    let key = deposit_key_env();
    eprintln!("[post-close-claim] submitPostCloseClaim via forge RunClose step…");
    let status = Command::new("forge")
        .current_dir("contracts")
        .args([
            "script",
            "script/RunClose.s.sol",
            "--sig",
            "submitPostCloseClaimStep()",
            "--rpc-url",
            &rpc,
            "--private-key",
            &key,
            "--broadcast",
        ])
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
        "[post-close-claim] claimWithdrawalCredit() (caller must be the recipient {recipient_hex})…"
    );
    cast(&[
        "send",
        &manager,
        "claimWithdrawalCredit()",
        "--private-key",
        &key,
        "--rpc-url",
        &rpc,
    ]);
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
//      INTMAX_DEPOSIT_KEY (funding/poster key; defaults to the anvil dev key),
//      WD_DEPOSIT_AMOUNT / WD_AMOUNT (native units; default 10 / 3),
//      SUB_ID (overrides the finalize submission id; default = the 3rd of our posts).
const BLOB_FILE: &str = "blob.bin";

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

/// Post one block (index `i` into `lifecycle.blocks`) as its own blob submission round.
fn post_block_round(rollup: &str, lc: &serde_json::Value, i: usize, key: &str, rpc: &str) {
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
    let proof_hash = lc["proof_hash"]
        .as_str()
        .unwrap_or_else(|| die("proof_hash"));
    let proof_length = lc["proof_length"]
        .as_u64()
        .unwrap_or_else(|| die("proof_length"))
        .to_string();
    let state_root = lc["final_state_root"]
        .as_str()
        .unwrap_or_else(|| die("final_state_root"));
    eprintln!("[withdraw] postBlockAndSubmit round {i} (blob tx, 1 ETH stake)…");
    cast(&[
        "send",
        rollup,
        "postBlockAndSubmit((uint32,uint64,bytes32,uint32[])[],bytes32,uint32,bytes32)",
        &sub_block,
        proof_hash,
        &proof_length,
        state_root,
        "--value",
        "1ether",
        "--blob",
        "--path",
        BLOB_FILE,
        "--private-key",
        key,
        "--rpc-url",
        rpc,
    ]);
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
    // Rollup address: explicit ROLLUP env, else the backing record from `setup-backing`.
    let rollup = std::env::var("ROLLUP")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| backing_exists().then(|| load_backing().2.rollup))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| die("set ROLLUP=0x<rollup addr> (or run setup-backing first)"));
    let key = deposit_key_env();
    let channel_id = channel_id_env();

    // The depositor MUST be the EOA that sends `deposit()` (its address is folded into block 2's
    // hash). Pin it to the funding key's address so the on-chain msg.sender reproduces the proof.
    let depositor_hex = cast(&["wallet", "address", "--private-key", &key])
        .trim()
        .to_string();
    let depositor = Address::from_hex(&depositor_hex)
        .unwrap_or_else(|e| die(format!("parse depositor address: {e:?}")));
    let manager_addr = Address::from_hex(manager.trim())
        .unwrap_or_else(|e| die(format!("parse manager address {manager}: {e:?}")));

    // P5-B: INTEGRATED (a backed channel from `setup-backing`) vs STANDALONE (self-contained P4
    // path). Integrated binds the withdrawal to the channel's REAL co-signing members + REAL
    // deposit so ONE on-chain registration + deposit serves both the close and withdraw paths;
    // the deposit was already made on-chain by `setup-backing`, so we do NOT deposit again
    // here. Standalone keeps the P4 behavior (self-generated registration + its own deposit,
    // env-tunable amounts).
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
        // deploy registration, so finalize matches. NOTE (B-2 dependency): an on-chain CLOSE of a
        // delegate-bearing channel still exposes its live delegate_count in the close PI — the
        // Manager-side count reconciliation moves to the B-2 contract change.
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

    // ── Build the artifacts (HEAVY proving). recipient = manager so the payout credits it. ──
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
    };
    let artifacts = build_channel_withdrawal(&params, cli_members.as_deref())
        .unwrap_or_else(|e| die(format!("build withdrawal: {e}")));

    // Write the artifacts locally and stage them for the forge finalize / withdrawNative steps
    // (RunClose reads `contracts/test/data/sepolia_*`). Each step's inputs are staged before it
    // runs.
    fs::write("lifecycle.json", &artifacts.lifecycle_json)
        .unwrap_or_else(|e| die(format!("write lifecycle.json: {e}")));
    fs::write("lifecycle_validity_mle.json", &artifacts.validity_mle_json)
        .unwrap_or_else(|e| die(format!("write lifecycle_validity_mle.json: {e}")));
    fs::write("withdrawal_mle.json", &artifacts.withdrawal_mle_json)
        .unwrap_or_else(|e| die(format!("write withdrawal_mle.json: {e}")));
    fs::write("withdrawal_payout.json", &artifacts.payout_json)
        .unwrap_or_else(|e| die(format!("write withdrawal_payout.json: {e}")));
    let data_dir = std::path::Path::new("contracts/test/data");
    let stage = |src: &str, dst: &str| {
        fs::copy(src, data_dir.join(dst)).unwrap_or_else(|e| die(format!("stage {src}: {e}")));
    };
    stage("lifecycle.json", "sepolia_lifecycle.json");
    stage(
        "lifecycle_validity_mle.json",
        "sepolia_lifecycle_validity_mle.json",
    );
    stage("withdrawal_mle.json", "sepolia_withdrawal_mle.json");
    stage("withdrawal_payout.json", "sepolia_withdrawal_payout.json");

    let lc: serde_json::Value = serde_json::from_str(&artifacts.lifecycle_json)
        .unwrap_or_else(|e| die(format!("parse lifecycle json: {e}")));
    let reg = &lc["registration"];

    // A 128 KiB blob (content irrelevant — the rollup only checks blobhash(0) is non-zero).
    fs::write(BLOB_FILE, vec![0u8; 131072])
        .unwrap_or_else(|e| die(format!("write {BLOB_FILE}: {e}")));

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
    if already_registered {
        eprintln!("[withdraw] channel {channel_id} already registered — skipping registerChannel");
    } else {
        eprintln!("[withdraw] registerChannel({channel_id})…");
        let bp_slot = reg["bp_member_slot"]
            .as_u64()
            .unwrap_or_else(|| die("bp_member_slot"))
            .to_string();
        let pk_gs = json_str_array(&reg["member_pk_gs"]);
        let pk_bs = json_str_array(&reg["member_pk_bs"]);
        let regev = json_str_array(&reg["regev_pk_digests"]);
        let recipients = json_str_array(&reg["recipients"]);
        cast(&[
            "send",
            &rollup,
            "registerChannel(uint32,uint8,uint8,bytes32[],bytes32[],bytes32[],address[])",
            &channel_id.to_string(),
            &bp_slot,
            "0",
            &pk_gs,
            &pk_bs,
            &regev,
            &recipients,
            "--private-key",
            &key,
            "--rpc-url",
            &rpc,
        ]);
    }

    // Capture the base submission id so we finalize the LAST of our three posts.
    let base_sub: u64 = {
        let out = cast(&[
            "call",
            &rollup,
            "nextSubmissionId()(uint256)",
            "--rpc-url",
            &rpc,
        ]);
        out.trim()
            .split_whitespace()
            .next()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| die(format!("parse nextSubmissionId: {out:?}")))
    };

    // 2. Registration block.
    post_block_round(&rollup, &lc, 0, &key, &rpc);

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
        let dep_token = dep["token_index"]
            .as_u64()
            .unwrap_or_else(|| die("deposit.token_index"))
            .to_string();
        let dep_amount = dep["amount"]
            .as_str()
            .unwrap_or_else(|| die("deposit.amount"));
        let dep_aux = dep["aux_data"]
            .as_str()
            .unwrap_or_else(|| die("deposit.aux_data"));
        eprintln!(
            "[withdraw] deposit{{value: {dep_amount}}}(recipient,…) as depositor {depositor_hex}…"
        );
        cast(&[
            "send",
            &rollup,
            "deposit(bytes32,uint32,uint256,bytes32)",
            dep_recipient,
            &dep_token,
            dep_amount,
            dep_aux,
            "--value",
            dep_amount,
            "--private-key",
            &key,
            "--rpc-url",
            &rpc,
        ]);
    }

    // 4. Deposit block, then 5. Withdrawal block.
    post_block_round(&rollup, &lc, 1, &key, &rpc);
    post_block_round(&rollup, &lc, 2, &key, &rpc);
    let final_sub = std::env::var("SUB_ID").unwrap_or_else(|_| (base_sub + 2).to_string());

    // 6. finalize (forge RunClose step; reads the staged sepolia_lifecycle* files).
    eprintln!("[withdraw] finalize submission {final_sub} (real validity MLE)…");
    let status = Command::new("forge")
        .current_dir("contracts")
        .args([
            "script",
            "script/RunClose.s.sol",
            "--sig",
            "finalizeStep()",
            "--rpc-url",
            &rpc,
            "--private-key",
            &key,
            "--broadcast",
        ])
        .env("ROLLUP", &rollup)
        .env("SUB_ID", &final_sub)
        .status()
        .unwrap_or_else(|e| die(format!("forge finalizeStep failed to start: {e}")));
    if !status.success() {
        die(
            "forge finalizeStep failed (ensure the validity VK + genesis match this rollup, and the 3 blocks posted in order)",
        );
    }

    // 7. withdrawNative (forge RunClose step; credits pendingWithdrawals[manager]).
    eprintln!("[withdraw] withdrawNative (real withdrawal MLE) → manager {manager}…");
    let status = Command::new("forge")
        .current_dir("contracts")
        .args([
            "script",
            "script/RunClose.s.sol",
            "--sig",
            "withdrawNativeStep()",
            "--rpc-url",
            &rpc,
            "--private-key",
            &key,
            "--broadcast",
        ])
        .env("ROLLUP", &rollup)
        .env("MANAGER", &manager)
        .status()
        .unwrap_or_else(|e| die(format!("forge withdrawNativeStep failed to start: {e}")));
    if !status.success() {
        die(
            "forge withdrawNativeStep failed (ensure the withdrawal VK is initialized on this rollup)",
        );
    }

    // 8. pullChannelFunds (manager pulls its escrowed credit out of the rollup).
    eprintln!("[withdraw] pullChannelFunds() on manager {manager}…");
    cast(&[
        "send",
        &manager,
        "pullChannelFunds()",
        "--private-key",
        &key,
        "--rpc-url",
        &rpc,
    ]);
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
    let out = serde_json::json!({
        "channel_id": channel_id,
        "bp_member_slot": BP_SLOT,
        "member_count": TEST_ACTIVE_MEMBERS,
        "delegate_count": delegate_count,
        "member_pk_gs": member_pk_gs,
        "member_pk_bs": member_pk_bs,
        "regev_pk_digests": regev_pk_digests,
        "recipients": recipients,
    });
    let s = serde_json::to_string_pretty(&out).unwrap_or_else(|e| die(e));
    fs::write("cli_reg_record.json", &s)
        .unwrap_or_else(|e| die(format!("write cli_reg_record.json: {e}")));
    println!("{s}");
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("");
    match cmd {
        "setup-backing" => cmd_setup_backing(&args),
        "init" => cmd_init(&args),
        "gen-contribution" => cmd_gen_contribution(&args), // dev/test: simulate a browser delegate
        "add-genesis-sig" => cmd_add_genesis_sig(&args),
        "send" => cmd_send(&args),
        "cosign" => cmd_cosign(&args),
        "cosign-refresh" => cmd_cosign_refresh(&args),
        "cosign-inter-transfer" => cmd_cosign_inter_transfer(&args),
        "cosign-burn-send" => cmd_cosign_burn_send(&args),
        "finalize" => cmd_finalize(&args),
        "balance" => cmd_balance(),
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
        "cosign-l1-deposit-import" => cmd_cosign_l1_deposit_import(&args),
        "pw-submit" => cmd_pw_submit(&args),
        "pw-finalize" => cmd_pw_finalize(&args),
        "cancel-close" => cmd_cancel_close(&args),
        "post-close-claim" => cmd_post_close_claim(&args),
        _ => {
            eprintln!(
                "usage: channel_member <setup-backing|init|send|cosign|cosign-burn-send|deploy-settlement|cosign-l1-deposit-import|pw-submit|pw-finalize|close|settle|withdraw|claim|cancel-close|post-close-claim|...> ..."
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
    let new_ct = contrib.genesis_ct.clone();
    // B-1b fail-closed: the delegate's L1 exit address must be present and nonzero BEFORE any
    // channel state is assembled or signed.
    let new_recipient = parse_contribution_recipient(&contrib.recipient);

    // IDEMPOTENT RE-JOIN (pk_g dedup): if a member with this EXACT pk_g already exists, the join is
    // a no-op — return that member's existing slot and the CURRENT snapshot UNCHANGED.
    // Re-running `init` with the same browser contribution (e.g. a retried request, or a
    // browser that lost its local copy) must NOT allocate a new slot, bump state_version, or
    // grow delegate_count: doing so caused slot collisions on re-join. Only a genuinely NEW
    // pk_g advances to the next free slot.
    if std::path::Path::new(STATE_FILE).exists() {
        let prev = load_state();
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
            println!(
                "delegate at slot {slot} (idempotent re-join: pk_g already present; member_count=3, delegate_count={dc}, state_version={v}). Browser: wallet_import_channel(<{out_path}>)."
            );
            return;
        }
    }

    let (prior_applied, prior_spent) = if std::path::Path::new(STATE_FILE).exists() {
        let prev = load_state();
        (prev.applied_tx_hashes, prev.spent_tx_hashes)
    } else {
        (Vec::new(), Vec::new())
    };
    let (record, state, members, controlled, slot) = if std::path::Path::new(STATE_FILE).exists() {
        join_delegate(new_delegate, new_ct, new_recipient)
    } else {
        create_channel(new_delegate, new_ct, new_recipient)
    };

    verify_all_signatures(&record, &members, &state)
        .unwrap_or_else(|e| die(format!("state not fully/validly member-signed: {e}")));
    let snapshot = ChannelSnapshot {
        record,
        state,
        members,
        // Stage 3: genesis threads the EMPTY settled-tx accumulator (its root ==
        // `empty_settled_tx_accumulator_root()`, which the genesis balance state carries).
        settled_tx_accumulator: default_settled_tx_accumulator(),
    };
    let dc = snapshot.record.delegate_count;
    let v = snapshot.state.balance_state.state_version;
    save_state(&CliState {
        controlled,
        snapshot: snapshot.clone(),
        applied_tx_hashes: prior_applied,
        spent_tx_hashes: prior_spent,
    });
    write_json(out_path, &snapshot);
    println!(
        "delegate at slot {slot} (member_count=3, delegate_count={dc}, state_version={v}). Browser: wallet_import_channel(<{out_path}>)."
    );
}

/// The three CLI co-signing members (deterministic keys + genesis balances).
fn cli_members() -> (
    Vec<MemberInfo>,
    Vec<(u8, RegevCiphertext)>,
    Vec<ControlledMember>,
) {
    let mut members = Vec::new();
    let mut enc = Vec::new();
    let mut controlled = Vec::new();
    for &slot in CLI_SLOTS {
        let keygen_seed = 0xC1_0000 + slot as u64;
        let keys = keys_for(keygen_seed);
        members.push(member_info_for(slot, &keys));
        let amount = CLI_GENESIS
            .iter()
            .find(|(s, _)| *s == slot)
            .map(|(_, a)| *a)
            .unwrap();
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
        });
    }
    (members, enc, controlled)
}

/// CREATE the channel: 3 members + this delegate at slot 3, genesis (v0), 3 members sign.
/// `new_recipient` (B-1b) is the delegate's NONZERO L1 exit address, leaf-bound in the genesis H1.
fn create_channel(
    mut nd: MemberInfo,
    new_ct: RegevCiphertext,
    new_recipient: Address,
) -> (
    ChannelRecord,
    ChannelState,
    Vec<MemberInfo>,
    Vec<ControlledMember>,
    u8,
) {
    let _ = DELEGATE_COUNT; // (delegate_count is now dynamic; first channel has 1)
    nd.slot = BROWSER_DELEGATE_SLOT;
    let (mut members, mut enc, controlled) = cli_members();
    members.push(nd);
    enc.push((BROWSER_DELEGATE_SLOT, new_ct));
    members.sort_by_key(|m| m.slot);
    let record = build_record(channel_id_env(), &members, BP_SLOT, 1).unwrap_or_else(|e| die(e));
    enc.sort_by_key(|(s, _)| *s);
    let encs: Vec<RegevCiphertext> = enc.into_iter().map(|(_, c)| c).collect();

    // detail2 §F-1: the genesis is funded by the REAL L1 deposit backing (no self-minted fund).
    // `fund` == the deposited native value; `settled_tx_chain` ties the state to that deposit so
    // the co-sign gate reconciles. Σ(genesis balances) == fund (CLI members + delegate
    // allocation).
    let (balance_vd, att, backing) = load_backing();
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
    // B-1b: per-active-slot L1 exit addresses, in slot order. The CLI COSIGNERS reuse the SAME
    // deterministic per-(channel, slot) recipients their on-chain registration record carries
    // (`test_recipient_for` — one formula for registeredRecipientOf AND the leaf binding), and
    // the browser DELEGATE's slot carries its contribution recipient (already fail-closed
    // nonzero). All folded into the cosigner-signed genesis H1 via the slot leaves.
    let channel_id = channel_id_env();
    let recipients: Vec<Address> = members
        .iter()
        .map(|m| {
            if m.slot == BROWSER_DELEGATE_SLOT {
                new_recipient
            } else {
                test_recipient_for(channel_id, m.slot as usize)
            }
        })
        .collect();
    let mut state = assemble_genesis_state_backed(
        &record,
        &encs,
        &regev_pk_digests,
        &recipients,
        backing.fund,
        settled,
        intmax_root,
    )
    .unwrap_or_else(|e| die(e));

    // CHECK-AND-SIGN (detail2 §3.1, atomic): each member signs the genesis ONLY IF its
    // settled_tx_chain matches the held deposit backing — fail-closed otherwise (never signs).
    for c in &controlled {
        let sig = sign_state_if_backed(
            &keys_for(c.keygen_seed),
            c.slot,
            &record,
            &state,
            &att,
            &balance_vd,
        )
        .unwrap_or_else(|e| die(format!("REFUSING TO SIGN genesis — {e}")));
        add_signature(&mut state, sig);
    }
    (record, state, members, controlled, BROWSER_DELEGATE_SLOT)
}

/// JOIN the existing channel as a NEW delegate, PRESERVING the current state (balances + sends).
/// The new delegate's slot is added with its genesis ciphertext, `delegate_count` and
/// `state_version` are bumped, and the 3 members re-sign the new state. Existing delegates'
/// ciphertexts are untouched, so their browser send-witnesses stay valid.
/// `new_recipient` (B-1b) is the joining delegate's NONZERO L1 exit address — written into the
/// new slot's `recipients` entry so it enters the cosigner-signed H1 (the delegate's ONLY payout
/// binding under Option B; the caller has already rejected zero/absent recipients fail-closed).
fn join_delegate(
    mut nd: MemberInfo,
    new_ct: RegevCiphertext,
    new_recipient: Address,
) -> (
    ChannelRecord,
    ChannelState,
    Vec<MemberInfo>,
    Vec<ControlledMember>,
    u8,
) {
    let prev = load_state();
    let existing = prev
        .snapshot
        .members
        .iter()
        .filter(|m| m.slot >= BROWSER_DELEGATE_SLOT)
        .count();
    let new_slot = BROWSER_DELEGATE_SLOT + existing as u8;
    if CLI_SLOTS.len() + existing + 1 > MAX_CHANNEL_MEMBERS {
        die("channel is full (member_count + delegate_count would exceed MAX_CHANNEL_MEMBERS)");
    }
    nd.slot = new_slot;
    let mut members = prev.snapshot.members.clone();
    members.push(nd);
    members.sort_by_key(|m| m.slot);
    let new_delegate_count = (existing + 1) as u8;
    let record = build_record(channel_id_env(), &members, BP_SLOT, new_delegate_count)
        .unwrap_or_else(|e| die(e));

    // Membership add: keep the CURRENT balance state (preserving every slot's ciphertext + any
    // sends), add the new delegate's slot, bump delegate_count + state_version, clear sigs,
    // members re-sign.
    let mut state = prev.snapshot.state.clone();
    state.prev_digest = state.digest;
    state.balance_state.delegate_count = new_delegate_count;
    state.balance_state.enc_balances[new_slot as usize] = new_ct;
    state.balance_state.pending_adds[new_slot as usize] = 0;
    // B-1b: bind the new delegate's L1 exit address into its slot leaf (cosigner-signed H1).
    state.balance_state.recipients[new_slot as usize] = new_recipient;
    state.balance_state.state_version += 1;
    state.member_signatures = Vec::new();
    let mut state = state.with_computed_digest();
    // SECURITY (§F-1): backing is anchored at GENESIS; a delegate join preserves the CURRENT state
    // (which may already have an ADVANCED settled_tx_chain from prior inter-channel sends), so it
    // can no longer equal the fixed genesis backing — re-checking it would wrongly reject joins
    // after any inter-channel send. Plain N-of-N re-sign of the membership add; same rationale
    // as cmd_cosign.
    for c in &prev.controlled {
        let sig = sign_state(&keys_for(c.keygen_seed), c.slot, &state)
            .unwrap_or_else(|e| die(format!("sign: {e:?}")));
        add_signature(&mut state, sig);
    }
    (record, state, members, prev.controlled, new_slot)
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
    let keys = MemberKeys::generate(&mut StdRng::seed_from_u64(seed));
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

fn cmd_send(args: &[String]) {
    let from: u8 = args
        .get(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| die("send <from> <to> <amount> <out>"));
    let to: u8 = args
        .get(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| die("bad <to>"));
    let amount: u64 = args
        .get(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| die("bad <amount>"));
    let out_path = args.get(4).map(String::as_str).unwrap_or("payload.json");
    let mut state = load_state();

    let cm = state
        .controlled
        .iter()
        .find(|c| c.slot == from && c.has_witness)
        .unwrap_or_else(|| {
            die(format!(
                "slot {from} is not a CLI member with a spendable balance"
            ))
        });
    let keys = keys_for(cm.keygen_seed);
    // Reconstruct the sender's current balance witness deterministically.
    let (_ct, witness) = encrypt_amount(
        &mut StdRng::seed_from_u64(cm.balance_seed),
        &keys.regev_pk,
        cm.balance_amount,
    )
    .unwrap_or_else(|e| die(e));
    let before_amount = cm.balance_amount;

    let mut rng = StdRng::seed_from_u64(0x5E_0000 + from as u64);
    let nonce = intmax3_zkp::ethereum_types::bytes32::Bytes32::default();
    let BuiltSend {
        payload,
        new_balance,
        ..
    } = build_send(
        &keys,
        &state.snapshot,
        from,
        to,
        amount,
        before_amount,
        &witness,
        nonce,
        LEVEL,
        &mut rng,
    )
    .unwrap_or_else(|e| die(e));

    // Mark this member as having spent (no reproducible witness for its new ciphertext; it will
    // not send again in this demo). Balance commits on finalize.
    if let Some(c) = state.controlled.iter_mut().find(|c| c.slot == from) {
        c.has_witness = false;
        c.balance_amount = new_balance;
    }
    save_state(&state);
    write_json(out_path, &payload);
    println!(
        "built send {from}→{to} amount {amount} → {out_path} (proof generated). Now collect co-signatures."
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
    for c in &state.controlled {
        if next_state
            .member_signatures
            .iter()
            .any(|s| s.member_slot == c.slot)
        {
            continue;
        }
        let sig = sign_state(&keys_for(c.keygen_seed), c.slot, &next_state)
            .unwrap_or_else(|e| die(format!("sign: {e:?}")));
        add_signature(&mut next_state, sig);
    }
    write_json(out_path, &next_state);

    let signed: Vec<u8> = next_state
        .member_signatures
        .iter()
        .map(|s| s.member_slot)
        .collect();
    println!(
        "co-signed → {out_path}. Signatures now present for slots {signed:?} (need 0..{}).",
        state.snapshot.record.member_count
    );

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
    for c in &state.controlled {
        if next_state
            .member_signatures
            .iter()
            .any(|s| s.member_slot == c.slot)
        {
            continue;
        }
        let sig = sign_state(&keys_for(c.keygen_seed), c.slot, &next_state)
            .unwrap_or_else(|e| die(format!("sign: {e:?}")));
        add_signature(&mut next_state, sig);
    }
    write_json(out_path, &next_state);
    state.snapshot.state = next_state;
    save_state(&state);
    write_json("channel_snapshot.json", &state.snapshot);
    println!(
        "balance-refresh co-signed for slot {} (head advanced).",
        payload.member_index
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
    let s =
        fs::read_to_string(&path).unwrap_or_else(|e| die(format!("read {}: {e}", path.display())));
    let st: CliState =
        serde_json::from_str(&s).unwrap_or_else(|e| die(format!("parse B state: {e}")));
    (st, dir)
}

/// Serialize a `CliState` + republish a `ChannelSnapshot` under EXPLICIT paths (used to persist
/// channel B from channel A's cwd). Mirrors `save_state` + the `channel_snapshot.json` head-sync,
/// but targets the sibling B directory rather than the cwd.
fn save_state_at(dir: &std::path::Path, state: &CliState) {
    let cli = serde_json::to_string_pretty(state).unwrap_or_else(|e| die(e));
    fs::write(dir.join(STATE_FILE), cli)
        .unwrap_or_else(|e| die(format!("write {}: {e}", dir.join(STATE_FILE).display())));
    let snap = serde_json::to_string_pretty(&state.snapshot).unwrap_or_else(|e| die(e));
    let snap_path = dir.join("channel_snapshot.json");
    fs::write(&snap_path, snap)
        .unwrap_or_else(|e| die(format!("write {}: {e}", snap_path.display())));
}

/// `cosign-inter-transfer <debit_payload.json> <descriptor.json> <out.json>` — the single atomic
/// cross-channel transfer command. Run with cwd = SOURCE channel A, INTMAX_CHANNEL = A.
///
/// Writes `{ "aHead": <A's co-signed new state>, "bSnapshot": <B's credited snapshot> }` to
/// out.json.
fn cmd_cosign_inter_transfer(args: &[String]) {
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

    // SPENT LEDGER (A side): refuse a tx_hash already DEBITED out of A (single-use on the source).
    if a_state
        .spent_tx_hashes
        .iter()
        .any(|h| *h == descriptor.tx_hash)
    {
        die(format!(
            "REFUSING: inter-channel tx_hash {} already debited from channel A (replay) — fail-closed",
            descriptor.tx_hash.to_hex()
        ));
    }

    // ================= LEG A (in memory): co-sign the post-debit head, extending A's REAL head.
    // ==== The proposed next state MUST extend A's COMMITTED head digest — not a request-body
    // blob.
    if payload.proposed_next_state.prev_digest != a_state.snapshot.state.digest {
        die("debit payload does not extend channel A's committed head");
    }
    // FAIL-CLOSED: re-verify the REAL E-2 + the send transition against A's TRUSTED head + record.
    verify_inter_channel_send_transition(
        &a_state.snapshot.state,
        &a_state.snapshot.record,
        &payload,
        LEVEL,
    )
    .unwrap_or_else(|e| die(format!("inter-channel send transition invalid: {e}")));

    let mut a_head = payload.proposed_next_state.clone();
    for c in &a_state.controlled {
        if a_head
            .member_signatures
            .iter()
            .any(|s| s.member_slot == c.slot)
        {
            continue;
        }
        let sig = sign_state(&keys_for(c.keygen_seed), c.slot, &a_head)
            .unwrap_or_else(|e| die(format!("REFUSING TO SIGN inter-debit — {e}")));
        add_signature(&mut a_head, sig);
    }
    // Authoritative N-of-N gate under A's OWN record. `a_head` is now the ONLY a_signed_state the
    // credit leg will ever see — built here, never from a request body.
    verify_all_signatures(&a_state.snapshot.record, &a_state.snapshot.members, &a_head)
        .unwrap_or_else(|e| die(format!("inter-debit a_head not N-of-N co-signed: {e}")));

    // CONSERVATION (A side, full u64 precision): A.fund decreased by EXACTLY descriptor.amount.
    let amt256 = intmax3_zkp::wallet_core::u64_to_u256(descriptor.amount);
    if a_head.channel_fund.amount + amt256 != a_state.snapshot.state.channel_fund.amount {
        die(
            "conservation check FAILED: A channel_fund did not decrease by exactly descriptor.amount",
        );
    }

    // ================= LEG B (in memory): validate + build B's credited head.
    // ======================
    let (mut b_state, b_dir) = load_sibling_dest_state(descriptor.destination_channel_id.as_u64());

    // REPLAY LEDGER (B side, invariant 6): refuse a tx_hash already credited into B.
    if b_state
        .applied_tx_hashes
        .iter()
        .any(|h| *h == descriptor.tx_hash)
    {
        die(format!(
            "REFUSING: inter-channel tx_hash {} already credited into channel B (replay) — fail-closed (invariant 6)",
            descriptor.tx_hash.to_hex()
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

    let b_fund_before = b_state.snapshot.state.channel_fund.amount;
    let mut rng = StdRng::seed_from_u64(0xC2_0000 + recipient_slot as u64);
    let BuiltInterChannelCredit {
        bundle_apply_state, ..
    } = build_inter_channel_credit(
        &builder_keys,
        &b_state.snapshot,
        &descriptor,
        LEVEL,
        &mut rng,
    )
    .unwrap_or_else(|e| die(format!("build_inter_channel_credit failed: {e}")));

    // CONSERVATION (B side, full u64 precision): B channel_fund increased by EXACTLY
    // descriptor.amount.
    if bundle_apply_state.channel_fund.amount != b_fund_before + amt256 {
        die(
            "conservation check FAILED: B channel_fund did not increase by exactly descriptor.amount",
        );
    }

    // N-of-N co-sign the credited (bundle-apply) B state. build_inter_channel_credit self-signs the
    // builder's slot; collect the remaining CLI members.
    let mut b_head = bundle_apply_state;
    for c in &b_state.controlled {
        if b_head
            .member_signatures
            .iter()
            .any(|s| s.member_slot == c.slot)
        {
            continue;
        }
        let sig = sign_state(&keys_for(c.keygen_seed), c.slot, &b_head)
            .unwrap_or_else(|e| die(format!("REFUSING TO SIGN inter-credit — {e}")));
        add_signature(&mut b_head, sig);
    }
    verify_all_signatures(&b_state.snapshot.record, &b_state.snapshot.members, &b_head)
        .unwrap_or_else(|e| die(format!("inter-credit B state not N-of-N co-signed: {e}")));

    // ================= COMMIT (both legs validated): persist A AND B atomically.
    // ==================== Advance + record on BOTH ledgers. Either-or-neither: any failure
    // above already `die()`d before we got here, so nothing was written.
    a_state.snapshot.state = a_head.clone();
    a_state.spent_tx_hashes.push(descriptor.tx_hash);
    save_state(&a_state);
    write_json("channel_snapshot.json", &a_state.snapshot);

    b_state.snapshot.state = b_head.clone();
    b_state.applied_tx_hashes.push(descriptor.tx_hash);
    save_state_at(&b_dir, &b_state);

    // out.json = { aHead, bSnapshot }.
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct InterTransferOut {
        a_head: ChannelState,
        b_snapshot: ChannelSnapshot,
    }
    write_json(
        out_path,
        &InterTransferOut {
            a_head: a_head.clone(),
            b_snapshot: b_state.snapshot.clone(),
        },
    );

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

    if descriptor.source_channel_id.as_u64() != channel_id_env() as u64 {
        die(format!(
            "descriptor.source_channel_id ({}) != this channel {} — refusing",
            descriptor.source_channel_id.as_u64(),
            channel_id_env()
        ));
    }

    if a_state
        .spent_tx_hashes
        .iter()
        .any(|h| *h == descriptor.tx_hash)
    {
        die(format!(
            "REFUSING: burn tx_hash {} already debited (replay) — fail-closed",
            descriptor.tx_hash.to_hex()
        ));
    }

    if payload.proposed_next_state.prev_digest != a_state.snapshot.state.digest {
        die("burn debit payload does not extend channel's committed head");
    }

    verify_inter_channel_send_transition(
        &a_state.snapshot.state,
        &a_state.snapshot.record,
        &payload,
        LEVEL,
    )
    .unwrap_or_else(|e| die(format!("burn send transition invalid: {e}")));

    let mut a_head = payload.proposed_next_state.clone();
    for c in &a_state.controlled {
        if a_head
            .member_signatures
            .iter()
            .any(|s| s.member_slot == c.slot)
        {
            continue;
        }
        let sig = sign_state(&keys_for(c.keygen_seed), c.slot, &a_head)
            .unwrap_or_else(|e| die(format!("REFUSING TO SIGN burn debit — {e}")));
        add_signature(&mut a_head, sig);
    }
    verify_all_signatures(&a_state.snapshot.record, &a_state.snapshot.members, &a_head)
        .unwrap_or_else(|e| die(format!("burn debit not N-of-N co-signed: {e}")));

    let amt256 = intmax3_zkp::wallet_core::u64_to_u256(descriptor.amount);
    if a_head.channel_fund.amount + amt256 != a_state.snapshot.state.channel_fund.amount {
        die(
            "conservation check FAILED: channel_fund did not decrease by exactly descriptor.amount",
        );
    }

    let pre_burn_settled_tx_chain = a_state.snapshot.state.balance_state.settled_tx_chain;
    a_state.snapshot.state = a_head.clone();
    a_state.spent_tx_hashes.push(descriptor.tx_hash);
    save_state(&a_state);
    write_json("channel_snapshot.json", &a_state.snapshot);

    // Persist burn metadata for `pw-submit` to reconstruct the Withdrawal.
    write_json(
        "last_burn.json",
        &serde_json::json!({
            "tx_hash": descriptor.tx_hash.to_hex(),
            "amount": descriptor.amount,
            "source_pk_g": descriptor.source_pk_g.to_hex(),
            "receiver_pk_g": descriptor.receiver_pk_g.to_hex(),
            "sender_delta_ct_digest": payload.inter_channel_tx.sender_delta_ct.digest().to_hex(),
            "receiver_delta_ct_digest": descriptor.receiver_delta.digest().to_hex(),
            "pre_burn_settled_tx_chain": pre_burn_settled_tx_chain.to_hex(),
        }),
    );

    write_json(out_path, &a_head);
    let signed: Vec<u8> = a_head
        .member_signatures
        .iter()
        .map(|s| s.member_slot)
        .collect();
    println!(
        "burn-send co-signed: channel {} debited {} (sigs {signed:?}). Fund: {} → {}. \
         Burn metadata written to last_burn.json.",
        channel_id_env(),
        descriptor.amount,
        a_state.snapshot.state.channel_fund.amount + amt256,
        a_state.snapshot.state.channel_fund.amount,
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
    for c in state.controlled.iter_mut() {
        let keys = keys_for(c.keygen_seed);
        if let Ok(bal) = decrypt_balance(&keys, &state.snapshot, c.slot) {
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
    for c in &state.controlled {
        let keys = keys_for(c.keygen_seed);
        match decrypt_balance(&keys, &state.snapshot, c.slot) {
            Ok(bal) => println!(
                "  slot {} balance = {} (can_send={})",
                c.slot, bal, c.has_witness
            ),
            Err(e) => println!("  slot {} balance = <decrypt error: {e}>", c.slot),
        }
    }
}

// ─── Wallet testnet UX: settlement deploy + L1 deposit import + partial withdrawal ────────

/// Deploy the settlement infrastructure on anvil: MockMleVerifier + ChannelSettlementVerifier +
/// ChannelSettlementManager, with the LIVE channel member set from the snapshot (including any
/// runtime-joined delegates). Usage:
///   channel_member deploy-settlement <rpc_url>
fn cmd_deploy_settlement(args: &[String]) {
    let rpc = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| die("deploy-settlement needs <rpc_url>"));

    let state = load_state();
    let (_, _, backing) = load_backing();
    let rollup = &backing.rollup;
    if rollup.is_empty() {
        die("no rollup address in channel_backing.json — run setup-backing first");
    }

    let channel_id = channel_id_env();
    let members = &state.snapshot.members;
    let record = &state.snapshot.record;
    let member_count = record.member_count as usize;
    let delegate_count = record.delegate_count as usize;
    let active = member_count + delegate_count;

    let mut pk_gs = Vec::new();
    let mut pk_bs = Vec::new();
    let mut regev_digests = Vec::new();
    let mut recipients = Vec::new();
    for m in members.iter().take(active) {
        pk_gs.push(m.pk_g.to_hex());
        pk_bs.push(m.pk_b.to_hex());
        regev_digests.push(m.regev_pk.digest().to_hex());
        let recipient_addr = Address::from_u32_slice(
            &[0xAAAA_0000u32
                .wrapping_add(channel_id.wrapping_mul(16))
                .wrapping_add(m.slot as u32); 5],
        )
        .expect("address from u32 slice");
        recipients.push(format!("0x{}", hex::encode(recipient_addr.to_bytes_be())));
    }

    let reg = serde_json::json!({
        "channel_id": channel_id,
        "bp_member_slot": BP_SLOT,
        "member_count": member_count,
        "delegate_count": delegate_count,
        "member_pk_gs": pk_gs,
        "member_pk_bs": pk_bs,
        "regev_pk_digests": regev_digests,
        "recipients": recipients,
    });
    let contracts_dir = std::env::var("CONTRACTS_DIR").unwrap_or_else(|_| {
        let exe = std::env::current_exe().unwrap_or_default();
        let repo = exe
            .ancestors()
            .find(|p| p.join("contracts").is_dir())
            .unwrap_or_else(|| die("cannot find contracts/ dir"))
            .to_path_buf();
        repo.join("contracts").to_string_lossy().to_string()
    });
    let data_path = format!("{contracts_dir}/test/data/pw_reg.json");
    fs::write(
        &data_path,
        serde_json::to_string_pretty(&reg).unwrap_or_else(|e| die(e)),
    )
    .unwrap_or_else(|e| die(format!("write {data_path}: {e}")));
    eprintln!("deploy-settlement: wrote {data_path}");

    let deploy_key = deposit_key_env();
    let forge_out = Command::new("forge")
        .current_dir(&contracts_dir)
        .args([
            "script",
            "script/DeployWalletSettlement.s.sol",
            "--tc",
            "DeployWalletSettlement",
            "--rpc-url",
            &rpc,
            "--private-key",
            &deploy_key,
            "--broadcast",
            "--code-size-limit",
            "50000",
        ])
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

    write_json(
        "settlement.json",
        &serde_json::json!({
            "manager": manager,
            "verifier": verifier,
            "rollup": rollup,
        }),
    );
    println!("deploy-settlement OK: manager={manager}, verifier={verifier}, rollup={rollup}");
}

/// Co-sign an L1 deposit import (mid-channel deposit): fold the deposit into the channel's balance
/// without closing. Usage:
///   channel_member cosign-l1-deposit-import <recipient_slot> <amount> <depositor_hex> <out.json>
fn cmd_cosign_l1_deposit_import(args: &[String]) {
    let recipient_slot: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or_else(|| {
        die("cosign-l1-deposit-import <recipient_slot> <amount> <depositor_hex> [out.json]")
    });
    let amount: u64 = args
        .get(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| die("cosign-l1-deposit-import needs <amount>"));
    let depositor_hex = args
        .get(3)
        .unwrap_or_else(|| die("cosign-l1-deposit-import needs <depositor_hex>"));
    let out_path = args
        .get(4)
        .map(String::as_str)
        .unwrap_or("l1_import_cosigned.json");

    let depositor = Address::from_hex(depositor_hex)
        .unwrap_or_else(|e| die(format!("parse depositor address: {e:?}")));
    let (_, _, backing) = load_backing();
    let deposit_recipient = Bytes32::from_hex(&backing.deposit_recipient)
        .unwrap_or_else(|e| die(format!("parse deposit_recipient from backing: {e:?}")));

    let deposit = Deposit {
        deposit_index: Default::default(),
        block_number: Default::default(),
        depositor,
        recipient: deposit_recipient,
        token_index: 0,
        amount: U256::from(amount),
        aux_data: Bytes32::default(),
    };

    let mut state = load_state();
    let snapshot = &state.snapshot;
    let bp_keys = keys_for(state.controlled[0].keygen_seed);

    let recipient_regev_pk = &snapshot.members[recipient_slot].regev_pk;
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

    for c in &state.controlled {
        let k = keys_for(c.keygen_seed);
        if !fund_state
            .member_signatures
            .iter()
            .any(|s| s.member_slot == c.slot)
        {
            let sig = sign_state(&k, c.slot, &fund_state)
                .unwrap_or_else(|e| die(format!("sign fund_import: {e}")));
            add_signature(&mut fund_state, sig);
        }
        if !bundle_state
            .member_signatures
            .iter()
            .any(|s| s.member_slot == c.slot)
        {
            let sig = sign_state(&k, c.slot, &bundle_state)
                .unwrap_or_else(|e| die(format!("sign bundle_apply: {e}")));
            add_signature(&mut bundle_state, sig);
        }
    }

    verify_l1_deposit_import_transition(
        &state.snapshot.state,
        &state.snapshot.record,
        &deposit,
        &fund_state,
        recipient_slot,
    )
    .unwrap_or_else(|e| die(format!("L1 deposit import transition invalid: {e}")));

    state.snapshot.state = bundle_state.clone();
    save_state(&state);
    write_json("channel_snapshot.json", &state.snapshot);

    let result = serde_json::json!({
        "fundImportState": fund_state,
        "bundleApplyState": bundle_state,
    });
    write_json(out_path, &result);
    println!(
        "cosign-l1-deposit-import OK: slot {} received {} deposit import. New state_version = {}.",
        recipient_slot, amount, bundle_state.balance_state.state_version
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

    let burn: serde_json::Value = read_json("last_burn.json");
    let burn_amount: u64 = burn["amount"]
        .as_u64()
        .unwrap_or_else(|| die("last_burn.json missing amount"));
    let _burn_tx_hash = burn["tx_hash"]
        .as_str()
        .unwrap_or_else(|| die("last_burn.json missing tx_hash"));
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

    let withdrawal_addr_hex = std::env::var("PW_RECIPIENT")
        .unwrap_or_else(|_| die("PW_RECIPIENT env var required (L1 withdrawal address)"));
    let withdrawal_addr = Address::from_hex(&withdrawal_addr_hex)
        .unwrap_or_else(|e| die(format!("parse withdrawal address: {e:?}")));

    let nullifier = {
        let mut data = Vec::with_capacity(32 + 32);
        data.extend_from_slice(&tx_leaf.to_bytes_be());
        data.extend_from_slice(&pre_burn_chain.to_bytes_be());
        let hash = keccak_hash::keccak(&data);
        Bytes32::from_bytes_be(hash.as_bytes()).expect("nullifier from keccak")
    };
    let withdrawal = Withdrawal {
        recipient: withdrawal_addr,
        token_index: 0,
        amount: U256::from(burn_amount),
        nullifier,
        aux_data: tx_leaf,
    };
    let auth_digest = partial_withdrawal_auth_digest(&withdrawal);
    eprintln!("pw-submit: authDigest = {}", auth_digest.to_hex());

    let post_fund = {
        let limbs = head.channel_fund.amount.to_u32_vec();
        limbs[7] as u64 | ((limbs[6] as u64) << 32)
    };
    let submit = serde_json::json!({
        "manager": manager,
        "verifier": verifier,
        "close_nonce": 1u64,
        "final_epoch": head.epoch,
        "final_small_block_number": head.small_block_number,
        "close_freeze_nonce": 0u64,
        "final_channel_state_digest": head.digest.to_hex(),
        "final_balance_state_h1": head.balance_state.h1().to_hex(),
        "channel_fund_amount": post_fund,
        "channel_fund_intmax_state_root": head.channel_fund.intmax_state_root.to_hex(),
        "burn_tx_hash": Bytes32::default().to_hex(),
        "close_withdrawal_digest": Bytes32::default().to_hex(),
        "snapshot_medium_block_number": 0u64,
        "final_state_version": head.balance_state.state_version,
        "final_settled_tx_chain": head.balance_state.settled_tx_chain.to_hex(),
        "final_settled_tx_acc_root": head.balance_state.settled_tx_accumulator_root.to_hex(),
        "prev_settled_tx_chain": pre_burn_chain.to_hex(),
        "withdrawal_recipient": format!("0x{}", hex::encode(withdrawal_addr.to_bytes_be())),
        "withdrawal_token_index": 0u32,
        "withdrawal_amount": burn_amount,
        "withdrawal_nullifier": nullifier.to_hex(),
        "withdrawal_aux_data": tx_leaf.to_hex(),
    });
    let contracts_dir = std::env::var("CONTRACTS_DIR").unwrap_or_else(|_| {
        let exe = std::env::current_exe().unwrap_or_default();
        let repo = exe
            .ancestors()
            .find(|p| p.join("contracts").is_dir())
            .unwrap_or_else(|| die("cannot find contracts/ dir"))
            .to_path_buf();
        repo.join("contracts").to_string_lossy().to_string()
    });
    let data_path = format!("{contracts_dir}/test/data/pw_submit.json");
    fs::write(
        &data_path,
        serde_json::to_string_pretty(&submit).unwrap_or_else(|e| die(e)),
    )
    .unwrap_or_else(|e| die(format!("write {data_path}: {e}")));

    let deploy_key = deposit_key_env();
    let forge_out = Command::new("forge")
        .current_dir(&contracts_dir)
        .args([
            "script",
            "script/SubmitPartialWithdrawal.s.sol",
            "--rpc-url",
            &rpc,
            "--private-key",
            &deploy_key,
            "--broadcast",
            "--code-size-limit",
            "50000",
        ])
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
            "withdrawal_token_index": 0u32,
            "withdrawal_amount": burn_amount,
            "withdrawal_nullifier": nullifier.to_hex(),
            "withdrawal_aux_data": tx_leaf.to_hex(),
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

    let deploy_key = deposit_key_env();

    cast(&["rpc", "evm_increaseTime", "2", "--rpc-url", &rpc]);
    cast(&["rpc", "evm_mine", "--rpc-url", &rpc]);

    cast(&[
        "send",
        manager,
        "finalizePartialWithdrawal()",
        "--private-key",
        &deploy_key,
        "--rpc-url",
        &rpc,
    ]);

    let settlement: serde_json::Value = read_json("settlement.json");
    let rollup = settlement["rollup"]
        .as_str()
        .unwrap_or_else(|| die("settlement.json missing rollup"));

    let check = cast(&[
        "call",
        rollup,
        "partialWithdrawalAuthorized(bytes32)",
        auth_digest,
        "--rpc-url",
        &rpc,
    ]);
    let authorized = check.trim().ends_with("1");
    if !authorized {
        die("on-chain partialWithdrawalAuthorized returned false");
    }
    eprintln!("pw-finalize: authorized on-chain. Claiming ETH…");

    let recipient = auth["withdrawal_recipient"]
        .as_str()
        .unwrap_or_else(|| die("pw_auth.json missing withdrawal_recipient"));
    let token_index = auth["withdrawal_token_index"].as_u64().unwrap_or(0);
    let amount = auth["withdrawal_amount"]
        .as_u64()
        .unwrap_or_else(|| die("pw_auth.json missing withdrawal_amount"));
    let nullifier = auth["withdrawal_nullifier"]
        .as_str()
        .unwrap_or_else(|| die("pw_auth.json missing withdrawal_nullifier"));
    let aux_data = auth["withdrawal_aux_data"]
        .as_str()
        .unwrap_or_else(|| die("pw_auth.json missing withdrawal_aux_data"));

    let sig = format!(
        "claimAuthorizedWithdrawal(({},{},{},{},{}))",
        "address", "uint32", "uint256", "bytes32", "bytes32"
    );
    let arg = format!(
        "({},{},{},{},{})",
        recipient, token_index, amount, nullifier, aux_data
    );

    let before = cast(&["balance", recipient, "--rpc-url", &rpc]);
    cast(&[
        "send",
        rollup,
        &sig,
        &arg,
        "--private-key",
        &deploy_key,
        "--rpc-url",
        &rpc,
    ]);
    let after = cast(&["balance", recipient, "--rpc-url", &rpc]);
    println!(
        "pw-finalize OK: {} claimed {} wei. Balance: {} → {}",
        recipient,
        amount,
        before.trim(),
        after.trim()
    );
}
