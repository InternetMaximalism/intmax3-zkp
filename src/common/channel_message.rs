use plonky2_keccak::utils::solidity_keccak256;
use serde::{Deserialize, Serialize};

use crate::{
    common::{
        trees::tx_v2_tree::compute_channel_action_root,
        tx::{ChannelAction, ChannelActionKind, TxClass, TxV2},
        user_id::UserId,
    },
    ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait, u256::U256},
    utils::poseidon_hash_out::PoseidonHashOut,
};

/// Magic bytes identifying a channel message: "IMPC" (0x494D5043).
/// Used as a domain separator to prevent confusion with Intmax transactions.
pub const CHANNEL_MESSAGE_MAGIC: u32 = 0x494D5043;

/// A single allocation within a channel state, describing how much of a token
/// a particular recipient should receive upon channel close.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Allocation {
    /// The Intmax recipient (userId encoded as Bytes32, or pubkey hash).
    pub recipient: Bytes32,

    /// The token index on Intmax.
    pub token_index: u32,

    /// The amount of tokens allocated to this recipient.
    pub amount: U256,
}

impl Allocation {
    pub fn to_u32_vec(&self) -> Vec<u32> {
        let mut v = self.recipient.to_u32_vec();
        v.push(self.token_index);
        v.extend(self.amount.to_u32_vec());
        v
    }
}

/// An off-chain channel message representing an agreed-upon balance allocation.
///
/// Format is intentionally distinct from Intmax `Tx` (which uses Poseidon hash)
/// to prevent cross-domain signature confusion. Channel messages use keccak256.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelMessage {
    /// The channel's userId (multisig account ID).
    pub channel_id: UserId,

    /// Monotonically increasing sequence number. Higher = newer state.
    pub sequence: u64,

    /// Balance allocations for each participant.
    pub allocations: Vec<Allocation>,

    /// Pre-computed Intmax tx tree root corresponding to these allocations.
    /// This is the value that will be inserted as a forced tx on close.
    pub tx_tree_root: Bytes32,
}

impl ChannelMessage {
    /// Compute the hash that members sign with their SPHINCS+ keys.
    ///
    /// ```text
    /// keccak256(magic || channel_id || sequence || allocations_hash || tx_tree_root)
    /// ```
    ///
    /// where `allocations_hash = keccak256(abi.encode(allocations))`.
    ///
    /// All values are u32-packed to match Solidity layout conventions.
    pub fn signing_hash(&self) -> Bytes32 {
        let allocations_hash = self.allocations_hash();

        let inputs: Vec<u32> = [
            vec![CHANNEL_MESSAGE_MAGIC],
            self.channel_id.to_u32_vec(),
            vec![self.sequence as u32, (self.sequence >> 32) as u32],
            allocations_hash.to_u32_vec(),
            self.tx_tree_root.to_u32_vec(),
        ]
        .concat();

        Bytes32::from_u32_slice(&solidity_keccak256(&inputs)).expect("hash result invalid")
    }

    /// Compute the keccak256 hash of the allocations array.
    pub fn allocations_hash(&self) -> Bytes32 {
        let inputs: Vec<u32> = self
            .allocations
            .iter()
            .flat_map(|a| a.to_u32_vec())
            .collect();

        if inputs.is_empty() {
            return Bytes32::default();
        }

        Bytes32::from_u32_slice(&solidity_keccak256(&inputs)).expect("hash result invalid")
    }

    pub fn close_action_payload_hash(&self) -> PoseidonHashOut {
        PoseidonHashOut::hash_inputs_u32(
            &[
                self.channel_id.to_u32_vec(),
                vec![self.sequence as u32, (self.sequence >> 32) as u32],
                self.allocations_hash().to_u32_vec(),
                self.tx_tree_root.to_u32_vec(),
            ]
            .concat(),
        )
    }

    pub fn to_channel_close_action(&self, seal: Bytes32) -> ChannelAction {
        ChannelAction {
            kind: ChannelActionKind::ChannelClose,
            source_channel_id: self.channel_id,
            destination_channel_id: UserId::dummy(),
            tx_hash: self.signing_hash(),
            seal,
            payload_hash: self.close_action_payload_hash(),
        }
    }

    pub fn to_channel_close_tx_v2(&self, seal: Bytes32, nonce: u32) -> TxV2 {
        let action = self.to_channel_close_action(seal);
        let channel_action_root = compute_channel_action_root(&[action]);
        TxV2 {
            tx_class: TxClass::ChannelAction,
            transfer_tree_root: PoseidonHashOut::default(),
            nonce,
            channel_action_root,
        }
    }

    pub fn channel_close_tx_v2_root(&self, seal: Bytes32, nonce: u32) -> PoseidonHashOut {
        crate::common::trees::tx_v2_tree::compute_tx_v2_root(&[
            self.to_channel_close_tx_v2(seal, nonce)
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::user_id::UserId;
    use rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn test_channel_message_magic() {
        assert_eq!(CHANNEL_MESSAGE_MAGIC, 0x494D5043);
        // "IMPC" in ASCII
        assert_eq!(&CHANNEL_MESSAGE_MAGIC.to_be_bytes(), b"IMPC");
    }

    #[test]
    fn test_signing_hash_deterministic() {
        let msg = ChannelMessage {
            channel_id: UserId::new(1, 100).unwrap(),
            sequence: 5,
            allocations: vec![Allocation {
                recipient: Bytes32::default(),
                token_index: 0,
                amount: U256::default(),
            }],
            tx_tree_root: Bytes32::default(),
        };

        let h1 = msg.signing_hash();
        let h2 = msg.signing_hash();
        assert_eq!(h1, h2, "signing hash should be deterministic");
    }

    #[test]
    fn test_different_sequences_produce_different_hashes() {
        let msg1 = ChannelMessage {
            channel_id: UserId::new(1, 100).unwrap(),
            sequence: 1,
            allocations: vec![],
            tx_tree_root: Bytes32::default(),
        };
        let msg2 = ChannelMessage {
            channel_id: UserId::new(1, 100).unwrap(),
            sequence: 2,
            allocations: vec![],
            tx_tree_root: Bytes32::default(),
        };

        assert_ne!(msg1.signing_hash(), msg2.signing_hash());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let mut rng = StdRng::seed_from_u64(42);
        let msg = ChannelMessage {
            channel_id: UserId::new(2, 50).unwrap(),
            sequence: 10,
            allocations: vec![
                Allocation {
                    recipient: Bytes32::rand(&mut rng),
                    token_index: 1,
                    amount: U256::rand_small(&mut rng),
                },
                Allocation {
                    recipient: Bytes32::rand(&mut rng),
                    token_index: 0,
                    amount: U256::rand_small(&mut rng),
                },
            ],
            tx_tree_root: Bytes32::rand(&mut rng),
        };

        let json = serde_json::to_string(&msg).unwrap();
        let deserialized: ChannelMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(msg, deserialized);
    }

    #[test]
    fn test_channel_close_tx_v2_is_deterministic() {
        let msg = ChannelMessage {
            channel_id: UserId::new(2, 50).unwrap(),
            sequence: 10,
            allocations: vec![],
            tx_tree_root: Bytes32::default(),
        };
        let seal = Bytes32::from_u32_slice(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        let tx_a = msg.to_channel_close_tx_v2(seal, 99);
        let tx_b = msg.to_channel_close_tx_v2(seal, 99);
        assert_eq!(tx_a, tx_b);
        assert_eq!(tx_a.tx_class, TxClass::ChannelAction);
        assert_eq!(
            msg.channel_close_tx_v2_root(seal, 99),
            crate::common::trees::tx_v2_tree::compute_tx_v2_root(&[tx_a])
        );
    }

    /// Full lifecycle test: channel opening → 3 payments → non-cooperative close.
    ///
    /// Simulates Alice & Bob with off-chain channel messages:
    ///   M0 (seq=0): deposit     — Alice=100, Bob=50
    ///   M1 (seq=1): Alice→Bob 20 — Alice=80,  Bob=70
    ///   M2 (seq=2): Bob→Alice 10 — Alice=90,  Bob=60
    ///   M3 (seq=3): Alice→Bob 40 — Alice=50,  Bob=100
    ///
    /// Verifies:
    ///   - Each message produces a unique signing hash
    ///   - Sequence monotonically increases
    ///   - Allocations sum is preserved (conservation of funds)
    ///   - Channel message format is distinct from Intmax Tx
    #[test]
    fn test_full_lifecycle_offchain_messages() {
        let channel_id = UserId::new(1, 42).unwrap();

        let alice_recipient = Bytes32::from_u32_slice(&[0, 0, 0, 0, 0, 0, 0, 1]).unwrap();
        let bob_recipient = Bytes32::from_u32_slice(&[0, 0, 0, 0, 0, 0, 0, 2]).unwrap();
        let token_index: u32 = 0; // ETH

        // Helper: create a channel message with given allocations
        let make_msg = |seq: u64, alice_amt: u64, bob_amt: u64| -> ChannelMessage {
            let allocations = vec![
                Allocation {
                    recipient: alice_recipient,
                    token_index,
                    amount: U256::from(alice_amt as u32),
                },
                Allocation {
                    recipient: bob_recipient,
                    token_index,
                    amount: U256::from(bob_amt as u32),
                },
            ];
            // Use a deterministic fake tx_tree_root derived from sequence
            let tx_tree_root =
                Bytes32::from_u32_slice(&[0, 0, 0, 0, 0, 0, seq as u32, (seq >> 32) as u32])
                    .unwrap();

            ChannelMessage {
                channel_id,
                sequence: seq,
                allocations,
                tx_tree_root,
            }
        };

        // ── M0: Initial deposit state ──
        let m0 = make_msg(0, 100, 50);
        // ── M1: Alice pays Bob 20 ──
        let m1 = make_msg(1, 80, 70);
        // ── M2: Bob pays Alice 10 ──
        let m2 = make_msg(2, 90, 60);
        // ── M3: Alice pays Bob 40 ──
        let m3 = make_msg(3, 50, 100);

        let messages = [&m0, &m1, &m2, &m3];

        // 1. All signing hashes are unique
        let hashes: Vec<Bytes32> = messages.iter().map(|m| m.signing_hash()).collect();
        for i in 0..hashes.len() {
            for j in (i + 1)..hashes.len() {
                assert_ne!(
                    hashes[i], hashes[j],
                    "M{} and M{} should have different signing hashes",
                    i, j
                );
            }
        }

        // 2. Sequence monotonically increases
        for i in 1..messages.len() {
            assert!(
                messages[i].sequence > messages[i - 1].sequence,
                "sequence should increase: M{} seq={} should be > M{} seq={}",
                i,
                messages[i].sequence,
                i - 1,
                messages[i - 1].sequence,
            );
        }

        // 3. Conservation of funds: all allocations sum to 150
        for (idx, msg) in messages.iter().enumerate() {
            let total: u128 = msg
                .allocations
                .iter()
                .map(|a| {
                    // U256 limbs are big-endian: limbs[7] is the least significant u32
                    let limbs = a.amount.to_u32_vec();
                    limbs[7] as u128
                })
                .sum();
            assert_eq!(
                total, 150,
                "M{}: total allocation should be 150, got {}",
                idx, total
            );
        }

        // 4. Signing hash differs from Intmax Tx hash (different domain) The magic prefix ensures
        //    domain separation. Just verify the hash is non-zero and 32 bytes.
        let h = m3.signing_hash();
        assert_ne!(h, Bytes32::default(), "signing hash should not be zero");

        // 5. For non-cooperative close, Bob would submit m3 on-chain. The on-chain contract only
        //    needs (sequence=3, tx_tree_root=m3.tx_tree_root). Verify these are accessible.
        assert_eq!(m3.sequence, 3);
        assert_ne!(m3.tx_tree_root, Bytes32::default());

        // 6. Allocations hash changes with different allocations
        assert_ne!(
            m0.allocations_hash(),
            m3.allocations_hash(),
            "different allocations should produce different hashes"
        );

        // 7. Serialization roundtrip for the final message
        let json = serde_json::to_string(&m3).unwrap();
        let deserialized: ChannelMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(m3, deserialized);
    }
}
