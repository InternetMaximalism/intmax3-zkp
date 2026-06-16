//! On-chain channel registration record + its word-aligned keccak hash-chain preimage.
//!
//! A channel registers on L1 via `IntmaxRollup.registerChannel`, which folds the registration
//! into the keccak `_pendingChannelRegHashChain`. The validity (`channel_reg_step`) circuit
//! consumes that same keccak chain and deterministically rebuilds the channel's Poseidon
//! `member_pubkeys_root`, binding the in-circuit member set to the on-chain registration. This
//! module is the shared definition of the registration record and its keccak preimage.
//!
//! SECURITY (R3, D6 pad-to-MAX): the preimage is a FIXED 16-slot, WORD-ALIGNED u32-limb stream.
//! Active members occupy slots `0..member_count`; padding slots `member_count..16` contribute
//! their zero/default values. Every field is a whole number of u32 limbs, so the in-circuit
//! keccak is a SINGLE keccak with no byte-straddling, and the Rust / circuit / Solidity preimages
//! are byte-identical (asserted by the differential test below + the Foundry counterpart).

use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{target::Target, witness::WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};
use plonky2_keccak::{builder::BuilderKeccak256 as _, utils::solidity_keccak256};
use serde::{Deserialize, Serialize};

use crate::{
    common::channel_id::{ChannelId, ChannelIdTarget},
    constants::MAX_CHANNEL_MEMBERS,
    ethereum_types::{
        address::{Address, AddressTarget},
        bytes32::{Bytes32, Bytes32Target},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
    },
};

/// One channel member's registration entry.
///
/// * `pk_g` — keccak/L1 digest form of the member's Goldilocks signing public key (32 bytes).
/// * `pk_b` — keccak/L1 digest form of the member's BabyBear hash-signature public key (32 bytes,
///   P3). Carried so the in-circuit 3-field `MemberLeaf{pk_g, pk_b, regev_pk}` it rebuilds binds
///   `pk_b` into `member_pubkeys_root` (R2 cross-binding); the off-chain channel-tx verifier reads
///   `pk_b` from the registered member set for the A11 two-key membership check.
/// * `regev_pk_digest` — keccak/L1 digest form of the member's Regev pubkey digest (32 bytes).
/// * `recipient` — the L1 address that receives this member's settlement (20 bytes / 5 u32 limbs).
///
/// SECURITY: both digests are carried as `Bytes32` (the L1/keccak digest form) here. The
/// in-circuit `channel_reg_step` recomputes the Poseidon member-tree leaf from the SAME witnessed
/// `PoseidonHashOut` values, split via `Bytes32Target::from_hash_out` into these 32-byte forms for
/// the keccak preimage (R2 cross-binding); reusing the same targets is the binding.
///
/// SECURITY (canonicality): because the circuit witnesses the identity as a `PoseidonHashOut`
/// (4 Goldilocks limbs, each < p) and derives the 32-byte keccak form via `from_hash_out`, the L1
/// `bytes32` registered MUST be the canonical reduction `Bytes32::from(PoseidonHashOut)` of the
/// member's identity — i.e. `pk_g = Bytes32::from(GoldilocksSecretKey::public_key_hash_out())` and
/// `regev_pk_digest = Bytes32::from(RegevPk::poseidon_digest())`. This is exactly the member
/// identity the consumption side (`block_hash_chain::update_channel_tree`) proves slot inclusion
/// against, so both sides bind the identical canonical value. A non-canonical `bytes32` simply
/// cannot be registered (its `channel_reg_step` proof has no satisfying witness) — it is rejected,
/// not silently aliased.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberRegEntry {
    pub pk_g: Bytes32,
    pub pk_b: Bytes32,
    pub regev_pk_digest: Bytes32,
    pub recipient: Address,
}

#[derive(Clone, Debug)]
pub struct MemberRegEntryTarget {
    pub pk_g: Bytes32Target,
    pub pk_b: Bytes32Target,
    pub regev_pk_digest: Bytes32Target,
    pub recipient: AddressTarget,
}

/// A single on-chain channel registration: a channel id, the bp member slot, the active member
/// count, and a FIXED 16-slot member array (active first, padding zeroed).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelRegRecord {
    pub channel_id: ChannelId,
    pub bp_member_slot: u32,
    pub member_count: u32,
    /// Number of DELEGATE participants registered after the members (delegate account). Delegates
    /// occupy slots `member_count..member_count+delegate_count`; padding is
    /// `member_count+delegate_count..MAX`. Invariant: `member_count + delegate_count <=
    /// MAX_CHANNEL_MEMBERS`. Committed into the reg-chain keccak preimage IMMEDIATELY AFTER
    /// `member_count` so the member/delegate/padding split is bound to the L1 registration chain.
    pub delegate_count: u32,
    pub members: [MemberRegEntry; MAX_CHANNEL_MEMBERS],
}

#[derive(Debug, thiserror::Error)]
pub enum ChannelRegRecordError {
    #[error("member_count {0} out of range (must be 2..={MAX_CHANNEL_MEMBERS})")]
    MemberCountOutOfRange(u32),
    #[error("member_count {0} + delegate_count {1} exceeds MAX_CHANNEL_MEMBERS ({MAX_CHANNEL_MEMBERS})")]
    DelegateCountOutOfRange(u32, u32),
    #[error("active member {0} has a zero pk_g")]
    ZeroActivePkG(usize),
    #[error("active members {0} and {1} have equal pk_g (must be distinct)")]
    DuplicatePkG(usize, usize),
    #[error("padding slot {0} is not default/zero")]
    NonZeroPaddingSlot(usize),
    #[error("bp_member_slot {0} must be < member_count {1}")]
    BpMemberSlotOutOfRange(u32, u32),
}

impl ChannelRegRecord {
    /// SECURITY: validate the structural invariants the contract also enforces. Distinctness /
    /// nonzero of active SPHINCS+ hashes is delegated to the contract in the circuit (the keccak
    /// chain binds the exact bytes); this native helper keeps the same checks so test fixtures and
    /// the witness builder cannot silently construct an invalid record.
    pub fn validate(&self) -> Result<(), ChannelRegRecordError> {
        if self.member_count < 2 || self.member_count as usize > MAX_CHANNEL_MEMBERS {
            return Err(ChannelRegRecordError::MemberCountOutOfRange(
                self.member_count,
            ));
        }
        let mc = self.member_count as usize;
        // Delegate account regions: members `0..mc`, delegates `mc..mc+dc`, padding `mc+dc..MAX`.
        // Active = members + delegates; both must be nonzero + pairwise distinct (no shared-key
        // forgery across the WHOLE active set). `member_count + delegate_count` must not exceed MAX.
        let active = mc
            .checked_add(self.delegate_count as usize)
            .filter(|&a| a <= MAX_CHANNEL_MEMBERS)
            .ok_or(ChannelRegRecordError::DelegateCountOutOfRange(
                self.member_count,
                self.delegate_count,
            ))?;
        for i in 0..active {
            if self.members[i].pk_g == Bytes32::default() {
                return Err(ChannelRegRecordError::ZeroActivePkG(i));
            }
            for j in (i + 1)..active {
                if self.members[i].pk_g == self.members[j].pk_g {
                    return Err(ChannelRegRecordError::DuplicatePkG(i, j));
                }
            }
        }
        for i in active..MAX_CHANNEL_MEMBERS {
            if self.members[i] != MemberRegEntry::default() {
                return Err(ChannelRegRecordError::NonZeroPaddingSlot(i));
            }
        }
        if self.bp_member_slot >= self.member_count {
            return Err(ChannelRegRecordError::BpMemberSlotOutOfRange(
                self.bp_member_slot,
                self.member_count,
            ));
        }
        Ok(())
    }

    /// R3 WORD-ALIGNED fixed-16 keccak preimage (native).
    ///
    /// Preimage u32-limb stream (each whole-word):
    /// `[ prev(8), channel_id(1), bp_member_slot(1), member_count(1), delegate_count(1),
    ///    for i in 0..16: ( pk_g(8), pk_b(8), regev_pk_digest(8), recipient(5) ) ]`
    /// Total = 8 + 1 + 1 + 1 + 1 + 16*(8+8+8+5) = 12 + 464 = 476 u32. `delegate_count` (delegate
    /// account) is a single u32 limb IMMEDIATELY AFTER `member_count`. Padding slots hash their zero
    /// values. `solidity_keccak256` treats each u32 as one big-endian 4-byte word, so this stream
    /// is byte-identical to the Solidity `abi.encodePacked` preimage in
    /// `IntmaxRollup.registerChannel` (verified by the differential test).
    ///
    /// SECURITY (P3): `pk_b` enters this preimage between `pk_g` and `regev_pk_digest` so the
    /// in-circuit 3-field `MemberLeaf` (whose `pk_b` is split from the SAME witnessed Poseidon value)
    /// is bound to the L1 keccak chain — `pk_b` is NOT a free witness at the validity layer.
    pub fn hash_with_prev_hash(&self, prev_hash: Bytes32) -> Bytes32 {
        let mut inputs: Vec<u32> = Vec::with_capacity(CHANNEL_REG_PREIMAGE_U32_LEN);
        inputs.extend(prev_hash.to_u32_vec()); // 8
        inputs.extend(self.channel_id.to_u32_vec()); // 1
        inputs.push(self.bp_member_slot); // 1
        inputs.push(self.member_count); // 1
        inputs.push(self.delegate_count); // 1 (delegate account, immediately after member_count)
        for m in self.members.iter() {
            inputs.extend(m.pk_g.to_u32_vec()); // 8
            inputs.extend(m.pk_b.to_u32_vec()); // 8
            inputs.extend(m.regev_pk_digest.to_u32_vec()); // 8
            inputs.extend(m.recipient.to_u32_vec()); // 5
        }
        debug_assert_eq!(inputs.len(), CHANNEL_REG_PREIMAGE_U32_LEN);
        Bytes32::from_u32_slice(&solidity_keccak256(&inputs)).expect("hashing result invalid")
    }
}

/// Word count of the R3 registration preimage (excluding the keccak output): see
/// [`ChannelRegRecord::hash_with_prev_hash`].
pub const CHANNEL_REG_PREIMAGE_U32_LEN: usize =
    8 + 1 + 1 + 1 + 1 + MAX_CHANNEL_MEMBERS * (8 + 8 + 8 + 5);

impl MemberRegEntryTarget {
    /// The u32-limb stream for one member slot: pk_g(8) || pk_b(8) || regev_pk_digest(8) ||
    /// recipient(5). Mirrors [`MemberRegEntry`]'s contribution to the keccak preimage.
    pub fn to_u32_stream(&self) -> Vec<Target> {
        [
            self.pk_g.to_vec(),
            self.pk_b.to_vec(),
            self.regev_pk_digest.to_vec(),
            self.recipient.to_vec(),
        ]
        .concat()
    }
}

/// In-circuit twin of [`ChannelRegRecord::hash_with_prev_hash`]. Builds the SAME word-aligned u32
/// stream from targets and runs ONE `builder.keccak256`.
///
/// SECURITY (R2 cross-binding): the caller supplies the SAME `pk_g` / `regev_pk_digest`
/// 32-byte targets (split from the witnessed Poseidon member values via
/// `Bytes32Target::from_hash_out`) that feed the Poseidon member-tree leaves. Reusing those exact
/// targets here is what binds the keccak chain to the Poseidon `member_pubkeys_root`.
pub fn channel_reg_hash_with_prev_hash_circuit<F, C, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    prev_hash: &Bytes32Target,
    channel_id: &ChannelIdTarget,
    bp_member_slot: Target,
    member_count: Target,
    delegate_count: Target,
    members: &[MemberRegEntryTarget; MAX_CHANNEL_MEMBERS],
) -> Bytes32Target
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    let mut inputs: Vec<Target> = Vec::with_capacity(CHANNEL_REG_PREIMAGE_U32_LEN);
    inputs.extend(prev_hash.to_vec()); // 8
    inputs.extend(channel_id.to_vec()); // 1
    inputs.push(bp_member_slot); // 1
    inputs.push(member_count); // 1
    inputs.push(delegate_count); // 1 (delegate account, immediately after member_count)
    for m in members.iter() {
        inputs.extend(m.to_u32_stream()); // 8 + 8 + 5
    }
    debug_assert_eq!(inputs.len(), CHANNEL_REG_PREIMAGE_U32_LEN);
    Bytes32Target::from_slice(&builder.keccak256::<C>(&inputs))
}

impl MemberRegEntryTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        Self {
            pk_g: Bytes32Target::new(builder, is_checked),
            pk_b: Bytes32Target::new(builder, is_checked),
            regev_pk_digest: Bytes32Target::new(builder, is_checked),
            recipient: AddressTarget::new(builder, is_checked),
        }
    }

    pub fn set_witness<F: plonky2::field::types::Field, W: WitnessWrite<F>>(
        &self,
        witness: &mut W,
        value: &MemberRegEntry,
    ) {
        self.pk_g
            .set_witness(witness, value.pk_g);
        self.pk_b
            .set_witness(witness, value.pk_b);
        self.regev_pk_digest
            .set_witness(witness, value.regev_pk_digest);
        self.recipient.set_witness(witness, value.recipient);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ethereum_types::u32limb_trait::U32LimbTrait as _;

    /// Build a deterministic test record with `member_count` active members. The pinned-constant
    /// differential test (Rust ↔ Solidity) uses these exact values.
    fn make_record(member_count: u32) -> ChannelRegRecord {
        let mut members: [MemberRegEntry; MAX_CHANNEL_MEMBERS] = Default::default();
        for i in 0..(member_count as usize) {
            // pk_g = 0x11..11 * (i+1) pattern, regev = 0x22.., recipient = 0x33..
            let s = (i as u32) + 1;
            members[i] = MemberRegEntry {
                pk_g: Bytes32::from_u32_slice(&[0x1111_0000 + s; 8]).unwrap(),
                pk_b: Bytes32::from_u32_slice(&[0x4444_0000 + s; 8]).unwrap(),
                regev_pk_digest: Bytes32::from_u32_slice(&[0x2222_0000 + s; 8]).unwrap(),
                recipient: Address::from_u32_slice(&[0x3333_0000 + s; 5]).unwrap(),
            };
        }
        ChannelRegRecord {
            channel_id: ChannelId::new(7).unwrap(),
            bp_member_slot: 1,
            member_count,
            delegate_count: 0,
            members,
        }
    }

    #[test]
    fn test_channel_reg_validate() {
        for mc in [2u32, 8, 16] {
            let rec = make_record(mc);
            rec.validate().expect("valid record");
        }
        // member_count = 1 is out of range.
        let mut bad = make_record(2);
        bad.member_count = 1;
        assert!(bad.validate().is_err());
        // padding slot nonzero.
        let mut bad2 = make_record(2);
        bad2.members[5].pk_g = Bytes32::from_u32_slice(&[1u32; 8]).unwrap();
        assert!(bad2.validate().is_err());
        // bp_member_slot >= member_count.
        let mut bad3 = make_record(2);
        bad3.bp_member_slot = 2;
        assert!(bad3.validate().is_err());
        // duplicate active sphincs hash.
        let mut bad4 = make_record(2);
        bad4.members[1].pk_g = bad4.members[0].pk_g;
        assert!(bad4.validate().is_err());
    }

    /// The keccak-chain seed (prev_hash) shared by the Rust and Solidity differential tests. The
    /// Solidity side calls `registerChannel` from a fresh rollup whose
    /// `_pendingChannelRegHashChain` is `bytes32(0)`, so the seed is the zero hash; the
    /// chain-folding of `prev` into the preimage is identical on both sides regardless of
    /// value.
    const DIFF_PREV_HASH_LIMBS: [u32; 8] = [0, 0, 0, 0, 0, 0, 0, 0];

    // Pinned hashes (hex Bytes32 Display form), generated by `hash_with_prev_hash` over
    // `make_record(mc)` with `prev = DIFF_PREV_HASH_LIMBS`. The Foundry test
    // `IntmaxRollup.t.sol::test_channelRegPreimageDifferential` asserts the IDENTICAL constants
    // over the IDENTICAL values, proving the Rust / circuit / Solidity preimages are byte-equal.
    //
    // SECURITY: if these change, the Rust <-> Solidity encodings have diverged — DO NOT update
    // blindly; investigate the layout.
    // Re-pinned after the delegate-account `delegate_count` limb (= 0 in these vectors) was added
    // to the reg-chain preimage IMMEDIATELY AFTER `member_count` (LEN 475 -> 476).
    const PINNED_MC2: &str = "0x6b32a3c7994eff98d812534363219a621be57b4675141395944c0aaca5edcb5a";
    const PINNED_MC8: &str = "0x7625aed1893502adbf63e376e94f1786eb797fa21c77c0a5101e501993c19fea";
    const PINNED_MC16: &str = "0x6d34a215c0db7a3a400af3e960a231eb1cb0db520076dae2bfa76b6a154b9809";

    /// THE DE-RISK GATE (Rust side). Prints the three hashes (copy into the constants above + the
    /// Foundry test) and asserts they match the pinned constants.
    #[test]
    fn test_channel_reg_preimage_pinned_differential() {
        let prev = Bytes32::from_u32_slice(&DIFF_PREV_HASH_LIMBS).unwrap();
        let h2 = format!("{}", make_record(2).hash_with_prev_hash(prev));
        let h8 = format!("{}", make_record(8).hash_with_prev_hash(prev));
        let h16 = format!("{}", make_record(16).hash_with_prev_hash(prev));
        println!("CHANNEL_REG MC2  = {h2}");
        println!("CHANNEL_REG MC8  = {h8}");
        println!("CHANNEL_REG MC16 = {h16}");
        assert_eq!(h2, PINNED_MC2, "MC2 preimage hash drifted");
        assert_eq!(h8, PINNED_MC8, "MC8 preimage hash drifted");
        assert_eq!(h16, PINNED_MC16, "MC16 preimage hash drifted");
    }
}
