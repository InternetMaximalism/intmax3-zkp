//! Long-lived JSON-lines adapter for the durable keyless block producer.

use std::io::{self, BufReader, BufWriter};

use clap::Parser;
use intmax3_zkp::{
    block_producer::ProductionDepositRequest,
    block_producer_service::{
        BlockProducerCommand, BlockProducerReceipt, BlockProducerService,
        BlockProducerServiceError,
    },
    common::channel::ChannelState,
    common::channel_id::ChannelId,
    ethereum_types::{address::Address, bytes32::Bytes32},
    live_balance_service::{LiveBalanceService, LiveBalanceServiceError, LiveInterChannelSendArtifact},
    regev::RegevSecurityLevel,
    validity_prover_service::{
        L1FinalizationRpcConfig, ValidityProverService, ValidityProverServiceError,
    },
    wallet_core::{ChannelSnapshot, InterChannelDebitPayload, InterChannelTransferDescriptor},
};
use serde::{Deserialize, Serialize};

const MAX_COMMAND_BYTES: usize = 128 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(name = "block-producer-service")]
#[command(about = "Durable keyless INTMAX block-producer JSONL service")]
struct Args {
    /// Versioned hash-chained producer journal.
    #[arg(long)]
    journal: std::path::PathBuf,

    /// Sorted validity-circuit arities, comma separated.
    #[arg(long, value_delimiter = ',', default_value = "2")]
    supported_user_counts: Vec<u32>,

    /// Durable validity checkpoint. When set, the four validity circuits are constructed once at
    /// startup and retained in this same process (the producer journal lock is never duplicated).
    #[arg(long)]
    validity_snapshot: Option<std::path::PathBuf>,

    /// Address committed into validity proof public inputs.
    #[arg(long, requires = "validity_snapshot")]
    validity_prover: Option<String>,

    /// Operator-owned L1 RPC used only for finalization receipt read-back.
    #[arg(long, requires = "validity_snapshot")]
    l1_rpc_url: Option<String>,

    /// Expected `eth_chainId`; a responsive endpoint on another network is rejected.
    #[arg(long, requires = "validity_snapshot")]
    l1_chain_id: Option<u64>,

    /// Freshly deployed IntmaxRollup whose receipt/events/getters gate validity acknowledgement.
    #[arg(long, requires = "validity_snapshot")]
    l1_rollup: Option<String>,

    /// Required canonical L1 depth before a candidate may become finalized locally.
    #[arg(long, default_value_t = 3, requires = "validity_snapshot")]
    l1_confirmations: u64,

    /// Directory of per-channel durable live-balance snapshots. When set, the `live*` commands are
    /// available and this process is the SOLE base-state authority for those channels (the
    /// checkpoint handoff's wiring requirement): every base proof advance goes through the
    /// journaled `LiveBalanceService` here, never through ad-hoc CLI state.
    #[arg(long)]
    live_root: Option<std::path::PathBuf>,

    /// Prove Regev transitions at the fast TEST parameters instead of Production. E2E-harness
    /// escape hatch; NEVER a per-request choice — a wire request cannot downgrade proving.
    #[arg(long, default_value_t = false)]
    regev_test_proofs: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SuccessResponse {
    ok: bool,
    result: serde_json::Value,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(
    tag = "command",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum ValidityCommand {
    ValidityStatus,
    ProveValidity {
        request_id: String,
    },
    ValidityArtifact,
    AcknowledgeValidity {
        request_id: String,
        candidate_id: Bytes32,
        transaction_hash: Bytes32,
    },
}

/// Live-balance base-state commands. Each channel's durable snapshot lives under `--live-root`;
/// the resident `LiveBalanceService` for a channel is opened once and retained, exactly like the
/// producer journal. `RegevSecurityLevel` is DELIBERATELY absent from every request shape: proving
/// strength is fixed at startup (`--regev-test-proofs`), so a wire request can never downgrade it.
#[derive(Clone, Debug, Deserialize)]
#[serde(
    tag = "command",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum LiveCommand {
    LiveStatus {
        channel_id: ChannelId,
    },
    LiveInit {
        channel_id: ChannelId,
    },
    LivePrepareDepositRecipient {
        channel_id: ChannelId,
    },
    LiveReceiveConfiguredDeposit {
        channel_id: ChannelId,
        producer_receipt: BlockProducerReceipt,
        deposit: ProductionDepositRequest,
    },
    LiveBindSnapshot {
        channel_id: ChannelId,
        signed_snapshot: ChannelSnapshot,
    },
    LiveSettleInterChannel {
        channel_id: ChannelId,
        producer_receipt: BlockProducerReceipt,
        signed_state: ChannelState,
        debit_payload: InterChannelDebitPayload,
        descriptor: InterChannelTransferDescriptor,
    },
    LiveSendArtifact {
        channel_id: ChannelId,
        producer_request_id: String,
    },
    LiveBackingArtifact {
        channel_id: ChannelId,
    },
    LiveBaseHead {
        channel_id: ChannelId,
    },
    LiveReceiveInterChannel {
        channel_id: ChannelId,
        producer_receipt: BlockProducerReceipt,
        debit_payload: InterChannelDebitPayload,
        descriptor: InterChannelTransferDescriptor,
        source_artifact: Box<LiveInterChannelSendArtifact>,
        fund_import_state: ChannelState,
        destination_snapshot: ChannelSnapshot,
    },
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
enum ServiceCommand {
    Validity(ValidityCommand),
    Live(LiveCommand),
    Producer(BlockProducerCommand),
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorResponse<'a> {
    ok: bool,
    error: ErrorBody<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorBody<'a> {
    code: &'a str,
    message: String,
}

enum BoundedLine {
    Eof,
    Line(Vec<u8>),
    TooLarge,
}

fn main() {
    let args = Args::parse();
    let mut service = match BlockProducerService::open(&args.journal, &args.supported_user_counts) {
        Ok(service) => service,
        Err(error) => {
            eprintln!("block-producer startup failed [{}]: {error}", error.code());
            std::process::exit(1);
        }
    };
    let (mut validity, l1) = match configure_validity(&args, &service) {
        Ok(configured) => configured,
        Err(error) => {
            eprintln!("validity-prover startup failed [{}]: {error}", error.code());
            std::process::exit(1);
        }
    };
    let mut live = args.live_root.as_ref().map(|root| LiveState {
        root: root.clone(),
        level: if args.regev_test_proofs {
            RegevSecurityLevel::Test
        } else {
            RegevSecurityLevel::Production
        },
        services: std::collections::HashMap::new(),
    });

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = BufReader::new(stdin.lock());
    let mut writer = BufWriter::new(stdout.lock());
    loop {
        match read_bounded_line(&mut reader) {
            Ok(BoundedLine::Eof) => break,
            Ok(BoundedLine::TooLarge) => {
                write_error(
                    &mut writer,
                    "request_too_large",
                    format!("JSON command exceeds {MAX_COMMAND_BYTES} bytes"),
                );
            }
            Ok(BoundedLine::Line(line)) => {
                if line.iter().all(u8::is_ascii_whitespace) {
                    continue;
                }
                let command = match serde_json::from_slice::<ServiceCommand>(&line) {
                    Ok(command) => command,
                    Err(error) => {
                        write_error(&mut writer, "invalid_json", error.to_string());
                        continue;
                    }
                };
                match execute_command(
                    command,
                    &mut service,
                    validity.as_mut(),
                    l1.as_ref(),
                    live.as_mut(),
                ) {
                    Ok(result) => {
                        let response = SuccessResponse { ok: true, result };
                        write_json_line(&mut writer, &response);
                    }
                    Err((code, message)) => write_error(&mut writer, code, message),
                }
            }
            Err(error) => {
                eprintln!("block-producer stdin failed: {error}");
                std::process::exit(1);
            }
        }
    }
}

fn configure_validity(
    args: &Args,
    producer: &BlockProducerService,
) -> Result<
    (
        Option<ValidityProverService>,
        Option<L1FinalizationRpcConfig>,
    ),
    ValidityProverServiceError,
> {
    let Some(snapshot) = args.validity_snapshot.as_ref() else {
        return Ok((None, None));
    };
    let prover = args
        .validity_prover
        .as_deref()
        .ok_or_else(|| {
            ValidityProverServiceError::InvalidConfiguration(
                "--validity-prover is required with --validity-snapshot".into(),
            )
        })?
        .parse::<Address>()
        .map_err(|e| {
            ValidityProverServiceError::InvalidConfiguration(format!(
                "parse --validity-prover: {e}"
            ))
        })?;
    let rollup = args
        .l1_rollup
        .as_deref()
        .ok_or_else(|| {
            ValidityProverServiceError::InvalidConfiguration(
                "--l1-rollup is required with --validity-snapshot".into(),
            )
        })?
        .parse::<Address>()
        .map_err(|e| {
            ValidityProverServiceError::InvalidConfiguration(format!("parse --l1-rollup: {e}"))
        })?;
    let l1 = L1FinalizationRpcConfig {
        rpc_url: args.l1_rpc_url.clone().ok_or_else(|| {
            ValidityProverServiceError::InvalidConfiguration(
                "--l1-rpc-url is required with --validity-snapshot".into(),
            )
        })?,
        expected_chain_id: args.l1_chain_id.ok_or_else(|| {
            ValidityProverServiceError::InvalidConfiguration(
                "--l1-chain-id is required with --validity-snapshot".into(),
            )
        })?,
        rollup,
        minimum_confirmations: args.l1_confirmations,
    };
    l1.validate()?;
    let service = if snapshot.exists() {
        ValidityProverService::open(snapshot, &args.supported_user_counts, prover, producer)?
    } else {
        ValidityProverService::initialize(snapshot, &args.supported_user_counts, prover, producer)?
    };
    Ok((Some(service), Some(l1)))
}

struct LiveState {
    root: std::path::PathBuf,
    level: RegevSecurityLevel,
    services: std::collections::HashMap<u64, LiveBalanceService>,
}

impl LiveState {
    fn snapshot_path(&self, channel_id: ChannelId) -> std::path::PathBuf {
        self.root
            .join(format!("channel-{}", channel_id.as_u64()))
            .join("balance.snapshot")
    }

    /// Resolve the resident service for `channel_id`, opening the durable snapshot on first use.
    /// `open` reconciles against the producer journal, so a crash-recovered daemon converges to
    /// the same head the producer admitted.
    fn service(
        &mut self,
        channel_id: ChannelId,
        producer: &BlockProducerService,
    ) -> Result<&mut LiveBalanceService, LiveBalanceServiceError> {
        use std::collections::hash_map::Entry;
        match self.services.entry(channel_id.as_u64()) {
            Entry::Occupied(entry) => Ok(entry.into_mut()),
            Entry::Vacant(entry) => {
                let path = self
                    .root
                    .join(format!("channel-{}", channel_id.as_u64()))
                    .join("balance.snapshot");
                let service = LiveBalanceService::open(&path, producer)?;
                Ok(entry.insert(service))
            }
        }
    }
}

fn execute_live_command(
    command: LiveCommand,
    live: &mut LiveState,
    producer: &mut BlockProducerService,
) -> Result<serde_json::Value, LiveBalanceServiceError> {
    let to_value = |v: Result<serde_json::Value, serde_json::Error>| {
        v.map_err(|e| {
            LiveBalanceServiceError::Snapshot(format!("serialize live response: {e}"))
        })
    };
    match command {
        LiveCommand::LiveStatus { channel_id } => {
            let status = live.service(channel_id, producer)?.status()?;
            to_value(serde_json::to_value(status))
        }
        LiveCommand::LiveInit { channel_id } => {
            let path = live.snapshot_path(channel_id);
            if path.exists() {
                // Idempotent restart: an existing snapshot is opened, its configured recipient
                // returned. Never re-randomize salts for a channel that already has state.
                let service = live.service(channel_id, producer)?;
                let recipient = service.configured_deposit_recipient()?.ok_or_else(|| {
                    LiveBalanceServiceError::InvalidRequest(
                        "live balance exists but has no configured deposit recipient; use                          livePrepareDepositRecipient"
                            .into(),
                    )
                })?;
                return to_value(Ok(serde_json::json!({
                    "channelId": channel_id,
                    "depositRecipient": recipient,
                })));
            }
            let (service, init) = LiveBalanceService::initialize_production(&path, channel_id)?;
            live.services.insert(channel_id.as_u64(), service);
            to_value(serde_json::to_value(init))
        }
        LiveCommand::LivePrepareDepositRecipient { channel_id } => {
            let recipient = live
                .service(channel_id, producer)?
                .prepare_deposit_recipient()?;
            to_value(serde_json::to_value(recipient))
        }
        LiveCommand::LiveReceiveConfiguredDeposit {
            channel_id,
            producer_receipt,
            deposit,
        } => {
            let receipt = live
                .service(channel_id, producer)?
                .receive_configured_deposit_unbound(producer, &producer_receipt, &deposit)?;
            to_value(serde_json::to_value(receipt))
        }
        LiveCommand::LiveBindSnapshot {
            channel_id,
            signed_snapshot,
        } => {
            let service = live.service(channel_id, producer)?;
            service.bind_signed_snapshot(&signed_snapshot)?;
            let status = service.status()?;
            to_value(serde_json::to_value(status))
        }
        LiveCommand::LiveSettleInterChannel {
            channel_id,
            producer_receipt,
            signed_state,
            debit_payload,
            descriptor,
        } => {
            let receipt = live.service(channel_id, producer)?.settle_inter_channel(
                producer,
                &producer_receipt,
                &signed_state,
                &debit_payload,
                &descriptor,
            )?;
            to_value(serde_json::to_value(receipt))
        }
        LiveCommand::LiveSendArtifact {
            channel_id,
            producer_request_id,
        } => {
            let artifact = live
                .service(channel_id, producer)?
                .inter_channel_send_artifact(&producer_request_id)?;
            to_value(serde_json::to_value(artifact))
        }
        LiveCommand::LiveBackingArtifact { channel_id } => {
            let artifact = live
                .service(channel_id, producer)?
                .channel_backing_artifact()?;
            to_value(serde_json::to_value(artifact))
        }
        LiveCommand::LiveBaseHead { channel_id } => {
            let head = live.service(channel_id, producer)?.base_head_artifact()?;
            to_value(serde_json::to_value(head))
        }
        LiveCommand::LiveReceiveInterChannel {
            channel_id,
            producer_receipt,
            debit_payload,
            descriptor,
            source_artifact,
            fund_import_state,
            destination_snapshot,
        } => {
            let level = live.level;
            let receipt = live.service(channel_id, producer)?.receive_inter_channel(
                producer,
                &producer_receipt,
                &debit_payload,
                &descriptor,
                &source_artifact,
                &fund_import_state,
                &destination_snapshot,
                level,
            )?;
            to_value(serde_json::to_value(receipt))
        }
    }
}

fn execute_command(
    command: ServiceCommand,
    producer: &mut BlockProducerService,
    validity: Option<&mut ValidityProverService>,
    l1: Option<&L1FinalizationRpcConfig>,
    live: Option<&mut LiveState>,
) -> Result<serde_json::Value, (&'static str, String)> {
    match command {
        ServiceCommand::Live(command) => {
            let live = live.ok_or_else(|| {
                (
                    "live_not_configured",
                    "start the daemon with --live-root to enable live-balance commands".to_string(),
                )
            })?;
            execute_live_command(command, live, producer)
                .map_err(|error| (error.code(), error.to_string()))
        }
        ServiceCommand::Producer(command) => producer
            .execute(command)
            .and_then(|result| {
                serde_json::to_value(result).map_err(|error| {
                    BlockProducerServiceError::Journal(format!(
                        "serialize producer response: {error}"
                    ))
                })
            })
            .map_err(|error| (error.code(), error.to_string())),
        ServiceCommand::Validity(command) => execute_validity_command(
            command,
            producer,
            validity.ok_or_else(|| {
                (
                    "validity_not_configured",
                    "start the daemon with --validity-snapshot and L1 read-back options".into(),
                )
            })?,
            l1,
        )
        .map_err(|error| (error.code(), error.to_string())),
    }
}

fn execute_validity_command(
    command: ValidityCommand,
    producer: &BlockProducerService,
    validity: &mut ValidityProverService,
    l1: Option<&L1FinalizationRpcConfig>,
) -> Result<serde_json::Value, ValidityProverServiceError> {
    let value = match command {
        ValidityCommand::ValidityStatus => serde_json::to_value(validity.status()?),
        ValidityCommand::ProveValidity { request_id } => {
            serde_json::to_value(validity.prove_candidate(request_id, producer)?)
        }
        ValidityCommand::ValidityArtifact => {
            let artifact = validity.candidate_artifact()?;
            return Ok(match artifact {
                None => serde_json::Value::Null,
                Some(artifact) => serde_json::json!({
                    "receipt": artifact.receipt,
                    "prover": artifact.prover,
                    "initialExtendedState": artifact.initial_extended_state,
                    "finalExtendedState": artifact.final_extended_state,
                    // Hex avoids the very large JSON number-array encoding while this control
                    // protocol remains JSONL. The proof itself is canonical plonky2 binary.
                    "validityProof": format!("0x{}", hex::encode(artifact.validity_proof)),
                }),
            });
        }
        ValidityCommand::AcknowledgeValidity {
            request_id,
            candidate_id,
            transaction_hash,
        } => {
            let l1 = l1.ok_or_else(|| {
                ValidityProverServiceError::InvalidConfiguration(
                    "L1 finalization read-back is not configured".into(),
                )
            })?;
            serde_json::to_value(validity.acknowledge_candidate_from_l1(
                request_id,
                candidate_id,
                transaction_hash,
                l1,
                producer,
            )?)
        }
    }
    .map_err(|error| {
        ValidityProverServiceError::Snapshot(format!("serialize validity response: {error}"))
    })?;
    Ok(value)
}

fn write_error(writer: &mut impl io::Write, code: &str, message: String) {
    write_json_line(
        writer,
        &ErrorResponse {
            ok: false,
            error: ErrorBody { code, message },
        },
    );
}

fn write_json_line(writer: &mut impl io::Write, value: &impl Serialize) {
    if let Err(error) = serde_json::to_writer(&mut *writer, value)
        .and_then(|_| writer.write_all(b"\n").map_err(serde_json::Error::io))
        .and_then(|_| writer.flush().map_err(serde_json::Error::io))
    {
        eprintln!("block-producer stdout failed: {error}");
        std::process::exit(1);
    }
}

/// Read one line without allowing an attacker to make `read_line` grow an unbounded allocation.
/// Once the limit is crossed, the rest of that line is drained before the next command is parsed.
fn read_bounded_line(reader: &mut impl io::BufRead) -> io::Result<BoundedLine> {
    let mut line = Vec::new();
    let mut too_large = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return if line.is_empty() && !too_large {
                Ok(BoundedLine::Eof)
            } else if too_large {
                Ok(BoundedLine::TooLarge)
            } else {
                Ok(BoundedLine::Line(line))
            };
        }
        let take = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        if !too_large {
            if line.len().saturating_add(take) > MAX_COMMAND_BYTES {
                too_large = true;
                line.clear();
            } else {
                line.extend_from_slice(&available[..take]);
            }
        }
        let ended = available[take - 1] == b'\n';
        reader.consume(take);
        if ended {
            return if too_large {
                Ok(BoundedLine::TooLarge)
            } else {
                Ok(BoundedLine::Line(line))
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_ack_command_cannot_supply_a_caller_asserted_l1_ack() {
        let candidate = "0x1111111111111111111111111111111111111111111111111111111111111111";
        let transaction = "0x2222222222222222222222222222222222222222222222222222222222222222";
        let valid = format!(
            r#"{{"command":"acknowledgeValidity","requestId":"ack-1","candidateId":"{candidate}","transactionHash":"{transaction}"}}"#
        );
        assert!(serde_json::from_str::<ServiceCommand>(&valid).is_ok());

        let forged = format!(
            r#"{{"command":"acknowledgeValidity","requestId":"ack-1","candidateId":"{candidate}","transactionHash":"{transaction}","acknowledgement":{{"chainId":1,"blockNumber":1,"finalExtendedStateCommitment":"{candidate}"}}}}"#
        );
        assert!(
            serde_json::from_str::<ServiceCommand>(&forged).is_err(),
            "the JSONL boundary must never deserialize caller-asserted L1 evidence"
        );
    }
}
