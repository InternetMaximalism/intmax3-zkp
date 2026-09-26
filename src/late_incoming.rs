//! Native post-close receive workflow. Keep these private checkpoints beside the wallet backup.
//! Build with `authenticated-tail-receive`; all deployed Balance/backing/late verifier keys
//! must come from the same build. A prepared receipt never advances the confirmed checkpoint.
use crate::{
    circuits::{
        balance::{balance_pis::BalanceFullPublicInputs, balance_processor::BalanceProcessor},
        channel::late_incoming_circuit::{LateIncomingCircuit, LateIncomingPublicInputs},
        validity::block_hash_chain::ext_public_state::ExtendedPublicState,
        witness::{
            balance_witness_generator::{BalanceWitnessGenerator, ReceiveTransferData},
            block_witness_generator::BlockWitnessGeneratorHandle,
        },
    },
    common::{channel_id::ChannelId, private_state::FullPrivateState},
    ethereum_types::bytes32::Bytes32,
    public_close_prover::wrap_and_export_circuit_mle,
    utils::{conversion::ToU64, mle_prover::export_mle_v2_config_json, wrapper::WrapperCircuit},
};
use anyhow::{Result, ensure};
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    plonk::{config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs},
};
use serde::{Deserialize, Serialize};
type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LateIncomingCheckpoint {
    channel_id: ChannelId,
    close_intent_digest: Bytes32,
    final_balance_state_h1: Bytes32,
    commitment: Bytes32,
    balance_proof: Vec<u8>,
    private_state: FullPrivateState,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreparedLateIncoming {
    pub statement: LateIncomingPublicInputs,
    /// Exact calldata proof for materializer.claimLateIncoming(manager, compactProof).
    pub compact_proof: Vec<u8>,
    pub mle_json: String,
    pub mle_config_json: String,
    next_checkpoint: LateIncomingCheckpoint,
}

impl LateIncomingCheckpoint {
    /// `expected` is materializer.lateBalanceStateCommitment(channelId) at a confirmed L1 block.
    /// On first use it is the commitment exposed by the materialized CloseAssetBacking proof.
    pub fn new(
        circuit: &LateIncomingCircuit<F, C, D>,
        proof: &ProofWithPublicInputs<F, C, D>,
        private_state: FullPrivateState,
        close_intent_digest: Bytes32,
        final_balance_state_h1: Bytes32,
        expected: Bytes32,
    ) -> Result<Self> {
        ensure!(
            cfg!(feature = "authenticated-tail-receive"),
            "rebuild all verifier keys with authenticated-tail-receive"
        );
        let commitment = circuit.balance_commitment(proof)?;
        ensure!(
            commitment == expected,
            "checkpoint differs from confirmed L1 state"
        );
        let pis = crate::circuits::balance::balance_pis::BalancePublicInputs::from_u64(
            &proof.public_inputs.to_u64_vec()
                [..crate::circuits::balance::balance_pis::BALANCE_PUBLIC_INPUTS_LEN],
        )?;
        ensure!(
            private_state.to_private_state().commitment() == pis.private_commitment,
            "private state mismatch"
        );
        Ok(Self {
            channel_id: pis.channel_id,
            close_intent_digest,
            final_balance_state_h1,
            commitment,
            balance_proof: proof.to_bytes(),
            private_state,
        })
    }

    pub fn commitment(&self) -> Bytes32 {
        self.commitment
    }

    /// Reuse the ordinary receive witness and Balance prover. `extended` must be the canonical
    /// producer journal preimage of the new public state (LiveBlockProducer's matching lookup).
    /// The caller persists the returned artifact BEFORE submission and retains `self` until
    /// finality. No receiver channel co-signature or new outgoing block is requested.
    pub fn prepare(
        &self,
        balance: &BalanceProcessor<F, C, D>,
        circuit: &LateIncomingCircuit<F, C, D>,
        blocks: BlockWitnessGeneratorHandle,
        incoming: &ReceiveTransferData<F, C, D>,
        recipient_binding: &ProofWithPublicInputs<F, C, D>,
        extended: &ExtendedPublicState,
    ) -> Result<PreparedLateIncoming> {
        ensure!(incoming.to == self.channel_id, "wrong destination channel");
        let proof = ProofWithPublicInputs::from_bytes(
            self.balance_proof.clone(),
            &balance.balance_vd().common,
        )?;
        ensure!(
            circuit.balance_commitment(&proof)? == self.commitment,
            "corrupt checkpoint"
        );
        let full = BalanceFullPublicInputs::<F, C, D>::from_u64_slice(
            &proof.public_inputs.to_u64_vec(),
            &balance.balance_vd().common.config,
        )?;
        ensure!(
            full.pis.private_commitment == self.private_state.to_private_state().commitment(),
            "corrupt private checkpoint"
        );
        ensure!(
            full.pis.channel_id == self.channel_id,
            "corrupt checkpoint channel"
        );
        let mut generator = BalanceWitnessGenerator {
            channel_id: self.channel_id,
            salt: self.private_state.salt,
            balance_proof: proof,
            full_private_state: self.private_state.clone(),
            block_witness_generator: blocks,
        };
        let witness = generator.receive_transfer_witness(incoming)?;
        let late_proof = circuit.prove(&witness, recipient_binding, extended)?;
        circuit.data.verify(late_proof.clone())?;
        let statement =
            LateIncomingPublicInputs::from_u64_slice(&late_proof.public_inputs.to_u64_vec())?;
        ensure!(
            statement.close_intent_digest == self.close_intent_digest
                && statement.final_balance_state_h1 == self.final_balance_state_h1
                && statement.previous_balance_commitment == self.commitment,
            "receipt uses another close/checkpoint"
        );
        let next_proof = balance.prove_receive_transfer(&witness)?;
        ensure!(
            circuit.balance_commitment(&next_proof)? == statement.next_balance_commitment,
            "continuation proof mismatch"
        );
        generator.commit_receive_transfer(&next_proof, &witness)?;
        let next_checkpoint = Self::new(
            circuit,
            &next_proof,
            generator.full_private_state,
            self.close_intent_digest,
            self.final_balance_state_h1,
            statement.next_balance_commitment,
        )?;
        let exported = wrap_and_export_circuit_mle(&circuit.data, &late_proof)?;
        Ok(PreparedLateIncoming {
            statement,
            compact_proof: exported.compact_proof,
            mle_json: exported.mle_json,
            mle_config_json: exported.mle_config_json,
            next_checkpoint,
        })
    }
}
impl PreparedLateIncoming {
    /// Promote only after the submission is finalized and the materializer's confirmed checkpoint
    /// equals this receipt's next commitment. A stale competing branch must be rebuilt instead.
    pub fn confirmed_checkpoint(
        &self,
        confirmed_l1_commitment: Bytes32,
    ) -> Result<LateIncomingCheckpoint> {
        ensure!(
            confirmed_l1_commitment == self.statement.next_balance_commitment
                && self.next_checkpoint.commitment == confirmed_l1_commitment,
            "receipt is not the confirmed L1 continuation"
        );
        ensure!(
            self.next_checkpoint.channel_id.as_u64() == u64::from(self.statement.channel_id)
                && self.next_checkpoint.close_intent_digest == self.statement.close_intent_digest
                && self.next_checkpoint.final_balance_state_h1
                    == self.statement.final_balance_state_h1,
            "receipt and checkpoint identify different channel/close state"
        );
        Ok(self.next_checkpoint.clone())
    }
}

/// Available before the first receipt: deploy this config's pinned adapter before the materializer.
pub fn export_late_incoming_mle_config(circuit: &LateIncomingCircuit<F, C, D>) -> Result<String> {
    let wrapper = WrapperCircuit::<F, C, C, D>::new(&circuit.data.verifier_data());
    Ok(export_mle_v2_config_json(&wrapper.data)?)
}

/// Crash-safe immutable private artifact. Publish via hard-link so an existing checkpoint is never
/// replaced, even by a concurrent process. Keep pending and confirmed generations at distinct
/// paths.
pub fn write_private_artifact_new(path: &std::path::Path, artifact: &impl Serialize) -> Result<()> {
    use std::{fs::OpenOptions, io::Write};
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let temporary = parent.join(format!(".late-{}-{nonce}.tmp", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    let result = (|| -> Result<()> {
        file.write_all(&serde_json::to_vec(artifact)?)?;
        file.sync_all()?;
        std::fs::hard_link(&temporary, path)?;
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    let _ = std::fs::remove_file(temporary);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::salt::Salt,
        ethereum_types::{address::Address, u32limb_trait::U32LimbTrait},
    };

    fn word(value: u32) -> Bytes32 {
        Bytes32::from_u32_slice(&[value; 8]).unwrap()
    }
    // Lifecycle/serialization fixture only. No cryptographic validity is claimed for these bytes.
    fn prepared() -> PreparedLateIncoming {
        PreparedLateIncoming {
            statement: LateIncomingPublicInputs {
                channel_id: 7,
                close_intent_digest: word(1),
                final_balance_state_h1: word(2),
                previous_balance_commitment: word(3),
                next_balance_commitment: word(4),
                finalized_extended_state_commitment: word(5),
                anchor_block_number: 19,
                receive_nullifier: word(6),
                recipient: Address::from_u32_slice(&[7; 5]).unwrap(),
                token_index: 55,
                amount: u64::MAX,
            },
            compact_proof: vec![1, 2, 3],
            mle_json: "wire fixture".into(),
            mle_config_json: "config fixture".into(),
            next_checkpoint: LateIncomingCheckpoint {
                channel_id: ChannelId::new(7).unwrap(),
                close_intent_digest: word(1),
                final_balance_state_h1: word(2),
                commitment: word(4),
                balance_proof: vec![4, 5, 6],
                private_state: FullPrivateState::new(Salt::default()),
            },
        }
    }
    fn temporary_dir(name: &str) -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("late-{name}-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        dir
    }

    #[cfg_attr(
        debug_assertions,
        ignore = "FullPrivateState indexed-tree sentinel requires --release"
    )]
    #[test]
    fn pending_receipt_survives_restart_without_promoting_unconfirmed_or_competing_cursor() {
        let dir = temporary_dir("restart");
        let path = dir.join("pending.json");
        let original = prepared();
        write_private_artifact_new(&path, &original).unwrap();
        let restored: PreparedLateIncoming =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert!(
            restored.confirmed_checkpoint(word(3)).is_err(),
            "old cursor is not confirmation"
        );
        assert!(
            restored.confirmed_checkpoint(word(99)).is_err(),
            "competing cursor is not confirmation"
        );
        assert_eq!(restored.statement.amount, u64::MAX);
        let confirmed = restored.confirmed_checkpoint(word(4)).unwrap();
        assert_eq!(
            confirmed.balance_proof,
            original.next_checkpoint.balance_proof
        );
        assert_eq!(
            serde_json::to_value(&confirmed.private_state).unwrap(),
            serde_json::to_value(&original.next_checkpoint.private_state).unwrap()
        );
        write_private_artifact_new(&dir.join("confirmed.json"), &confirmed).unwrap();
        assert_eq!(
            serde_json::from_slice::<PreparedLateIncoming>(&std::fs::read(path).unwrap())
                .unwrap()
                .compact_proof,
            vec![1, 2, 3]
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg_attr(
        debug_assertions,
        ignore = "FullPrivateState indexed-tree sentinel requires --release"
    )]
    #[test]
    fn confirmation_rejects_transplanted_checkpoint_context_even_when_commitment_matches() {
        for field in [
            "channelId",
            "closeIntentDigest",
            "finalBalanceStateH1",
            "commitment",
        ] {
            let mut json = serde_json::to_value(prepared()).unwrap();
            json["nextCheckpoint"][field] = if field == "channelId" {
                serde_json::json!(8)
            } else {
                serde_json::to_value(word(99)).unwrap()
            };
            let swapped: PreparedLateIncoming = serde_json::from_value(json).unwrap();
            assert!(
                swapped.confirmed_checkpoint(word(4)).is_err(),
                "accepted mixed artifact field {field}"
            );
        }
    }

    #[test]
    fn concurrent_writers_publish_exactly_one_complete_artifact() {
        use std::sync::{Arc, Barrier};
        let dir = temporary_dir("concurrent");
        let path = dir.join("pending.json");
        let gate = Arc::new(Barrier::new(8));
        let winners: Vec<usize> = std::thread::scope(|scope| {
            let jobs: Vec<_> = (0..8)
                .map(|id| {
                    let gate = gate.clone();
                    let path = &path;
                    scope.spawn(move || {
                        gate.wait();
                        (
                            id,
                            write_private_artifact_new(path, &vec![id; 1024]).is_ok(),
                        )
                    })
                })
                .collect();
            jobs.into_iter()
                .filter_map(|job| {
                    let (id, ok) = job.join().unwrap();
                    ok.then_some(id)
                })
                .collect()
        });
        assert_eq!(winners.len(), 1);
        let saved: Vec<usize> = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(saved, vec![winners[0]; 1024]);
        assert_eq!(
            std::fs::read_dir(&dir).unwrap().count(),
            1,
            "temporary files cleaned up"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg_attr(
        debug_assertions,
        ignore = "FullPrivateState indexed-tree sentinel requires --release"
    )]
    #[test]
    fn serialization_failure_leaves_no_published_or_temporary_artifact_and_is_retryable() {
        struct Failure;
        impl Serialize for Failure {
            fn serialize<S: serde::Serializer>(
                &self,
                _: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("injected serialization failure"))
            }
        }
        let dir = temporary_dir("failed-save");
        let path = dir.join("pending.json");
        assert!(write_private_artifact_new(&path, &Failure).is_err());
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        write_private_artifact_new(&path, &prepared()).unwrap();
        assert!(
            serde_json::from_slice::<PreparedLateIncoming>(&std::fs::read(path).unwrap()).is_ok()
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[cfg_attr(
        debug_assertions,
        ignore = "FullPrivateState indexed-tree sentinel requires --release"
    )]
    #[test]
    fn existing_symlink_cannot_redirect_or_replace_private_artifact() {
        let dir = temporary_dir("symlink");
        let target = dir.join("target");
        let path = dir.join("pending.json");
        std::fs::write(&target, b"existing secret").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(write_private_artifact_new(&path, &prepared()).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"existing secret");
        std::fs::remove_file(&target).unwrap();
        assert!(
            write_private_artifact_new(&path, &prepared()).is_err(),
            "dangling symlink must also fail"
        );
        assert!(!target.exists());
        assert!(
            std::fs::symlink_metadata(path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn private_artifact_is_complete_immutable_and_private() {
        let dir = std::env::temp_dir().join(format!("late-artifact-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pending.json");
        let _ = std::fs::remove_file(&path);
        write_private_artifact_new(&path, &vec![1u64, 2, 3]).unwrap();
        assert!(write_private_artifact_new(&path, &vec![4u64]).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "[1,2,3]");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}
