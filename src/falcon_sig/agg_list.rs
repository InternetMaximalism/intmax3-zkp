//! N-of-N signature **list proof** for the validity path (small-block N-of-N, Phase 2 —
//! `doc/tasks/small-block-nofn-design.md` §5.2 (P-b) / §5.3).
//!
//! Where [`crate::falcon_sig::list`] folds ONE directly-verified Falcon signature per chain step,
//! this module folds ONE [`FalconAggCircuit`] TOP proof per chain step — i.e. per signing block it
//! commits to "these `signer_count` keys ALL signed this one digest", instead of "one key signed
//! this digest". The chain shape, the cyclic wrapper and the step's public-input layout
//! (`[prev_chain(8), new_chain(8)]`) are unchanged, so the consumer keeps its
//! `C == final.sig_chain` equality assertion.
//!
//! # The fold (§5.3)
//!
//! ```text
//!   pk_list_digest_i = Poseidon([AGG_PK_LIST_DOMAIN] ‖ pk_g_0(8) ‖ ... ‖ pk_g_15(8))
//!   leaf_i           = Poseidon([AGG_LIST_LEAF_DOMAIN] ‖ m_i(8) ‖ signer_count_i ‖
//!                               pk_list_digest_i(4))
//!   C_0              = 0                       (the empty chain)
//!   C_i              = Poseidon(C_{i-1} ‖ leaf_i)   (two-to-one, the SHARED chain step)
//! ```
//!
//! The pk list is read from the aggregation proof's public inputs VERBATIM, all
//! `MAX_COSIGNERS` slots including the zero padding suffix — the padding slots are *constrained*
//! zero inside `FalconAggCircuit` (`agg.rs` `is_right_present * limb`), so both sides agree on
//! padding without extra work.
//!
//! ## Why a NEW leaf domain rather than the IMLL `(m, pk)` leaf
//!
//! `PoseidonHashOut::hash_inputs*` is a NO-PAD sponge, so neither the input length nor the tuple
//! shape is encoded in the digest; separation between preimage schemas rests entirely on the
//! leading domain constant. The tuple folded here is `(message, signer_count, pk_list_digest)`,
//! NOT the IMLL `(message, public_key)` pair, so it gets its own constant — reusing "IMLL" for a
//! second, differently-shaped tuple would void the domain-separation argument that
//! `constants.rs::all_domain_constants_pairwise_distinct` exists to protect. Same reasoning for
//! the pk-list digest's own constant.
//!
//! SECURITY (what a step proof does and does NOT say):
//!   - It says: a TOP-level `FalconAggCircuit` proof exists (verified against a BUILD-TIME CONSTANT
//!     verifier key) whose statement is exactly the `(message, signer_count, pk_list)` folded into
//!     the chain. Every one of those `signer_count` pk slots is backed by a real Falcon signature
//!     over that one message (`agg.rs` padding-soundness argument).
//!   - It does NOT say the signers are DISTINCT, nor that they are the channel's registered
//!     members, nor that `signer_count` equals the channel's `member_count`. `FalconAggCircuit`
//!     deliberately allows the same leaf proof in two slots (`agg.rs:81-83`). Those are CONSUMER
//!     obligations, discharged in `update_channel_tree` by recomputing the member-tree root over
//!     the same 16 pk slots (design §5.4 items 1-5, Phase 3). Nothing here may be read as evidence
//!     that they are already enforced.

use anyhow::Result;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite as _},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

use super::agg::{
    FALCON_AGG_COUNT_OFFSET, FALCON_AGG_MSG_OFFSET, FALCON_AGG_PK_LIST_OFFSET,
    FALCON_AGG_PUBLIC_INPUTS_LEN,
};
use crate::{
    constants::MAX_COSIGNERS,
    ethereum_types::{
        bytes32::{BYTES32_LEN, Bytes32, Bytes32Target},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
    },
    poseidon_sig::list::{chain_step_target, list_chain_step},
    utils::{
        hash_chain::cyclic_chain_circuit::CyclicChainCircuit,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
        recursively_verifiable::add_proof_target_and_verify,
    },
};

// FORMAT — domain constants
// ================================================================================================

/// "IMAL" — domain separator of the widened aggregate list leaf
/// `Poseidon([IMAL] ‖ message(8) ‖ signer_count ‖ pk_list_digest(4))`.
/// Registered in `constants.rs::all_domain_constants_pairwise_distinct`.
pub const AGG_LIST_LEAF_DOMAIN: u32 = 0x494d_414c;

/// "IMPL" — domain separator of the 16-slot signer pk-list digest
/// `Poseidon([IMPL] ‖ pk_g_0(8) ‖ ... ‖ pk_g_15(8))`.
/// Registered in `constants.rs::all_domain_constants_pairwise_distinct`.
pub const AGG_PK_LIST_DOMAIN: u32 = 0x494d_504c;

/// Number of field elements the pk-list digest hashes (excluding the domain constant).
pub const AGG_PK_LIST_LIMBS: usize = MAX_COSIGNERS * BYTES32_LEN;

// FORMAT — native reference (must match the in-circuit gadgets bit-for-bit)
// ================================================================================================

/// `pk_list_digest = Poseidon([AGG_PK_LIST_DOMAIN] ‖ 16 slots × pk_g(8 limbs))`.
///
/// `signer_pks` are the ACTIVE signers in slot order; the remaining slots are zero — byte-identical
/// to the zero padding `FalconAggCircuit` constrains its inactive slots to, and to the empty
/// `MemberLeaf` slots the consumer will recompute from (Phase 3).
pub fn agg_pk_list_digest(signer_pks: &[Bytes32]) -> PoseidonHashOut {
    assert!(
        signer_pks.len() <= MAX_COSIGNERS,
        "more signers ({}) than slots ({MAX_COSIGNERS})",
        signer_pks.len()
    );
    let mut inputs = Vec::with_capacity(1 + AGG_PK_LIST_LIMBS);
    inputs.push(AGG_PK_LIST_DOMAIN as u64);
    for pk in signer_pks {
        inputs.extend(pk.to_u32_vec().into_iter().map(u64::from));
    }
    inputs.resize(1 + AGG_PK_LIST_LIMBS, 0);
    PoseidonHashOut::hash_inputs_u64(&inputs)
}

/// `leaf = Poseidon([AGG_LIST_LEAF_DOMAIN] ‖ message(8) ‖ signer_count ‖ pk_list_digest(4))`.
pub fn agg_list_leaf(
    message: Bytes32,
    signer_count: u64,
    pk_list_digest: PoseidonHashOut,
) -> PoseidonHashOut {
    let mut inputs = Vec::with_capacity(1 + BYTES32_LEN + 1 + 4);
    inputs.push(AGG_LIST_LEAF_DOMAIN as u64);
    inputs.extend(message.to_u32_vec().into_iter().map(u64::from));
    inputs.push(signer_count);
    inputs.extend_from_slice(&pk_list_digest.elements);
    PoseidonHashOut::hash_inputs_u64(&inputs)
}

/// One folded block statement: "these `signer_pks` (in slot order) ALL signed `message`".
///
/// Mirrors the TOP-level `FalconAggCircuit` public-input contract; `signer_count` is
/// `signer_pks.len()`, which is what a left-packed aggregation proof always exposes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggListEntry {
    pub message: Bytes32,
    pub signer_pks: Vec<Bytes32>,
}

impl AggListEntry {
    pub fn leaf(&self) -> PoseidonHashOut {
        agg_list_leaf(
            self.message,
            self.signer_pks.len() as u64,
            agg_pk_list_digest(&self.signer_pks),
        )
    }

    /// Parse a TOP-level aggregation proof's public inputs into the statement the chain folds.
    ///
    /// PROVER-SIDE CONVENIENCE ONLY: this is how a caller computes the native `prev_chain` it feeds
    /// [`AggListStepCircuit::prove`], and how tests state the expected commitment. It carries NO
    /// security weight — the binding is the in-circuit fold over the RECURSIVELY VERIFIED proof's
    /// public inputs. The structural checks below (arity, `1 <= signer_count <= MAX_COSIGNERS`,
    /// 32-bit limbs, zero-suffix padding) exist so a malformed input fails here with a clear error
    /// instead of silently producing a chain value no circuit can reproduce.
    pub fn from_agg_public_inputs<F: RichField>(pis: &[F]) -> Result<Self> {
        anyhow::ensure!(
            pis.len() == FALCON_AGG_PUBLIC_INPUTS_LEN,
            "aggregation public-input arity is {}, expected {FALCON_AGG_PUBLIC_INPUTS_LEN}",
            pis.len()
        );
        let limb = |f: &F| -> Result<u32> {
            let v = f.to_canonical_u64();
            anyhow::ensure!(v < (1u64 << 32), "public input {v} is not a 32-bit limb");
            Ok(v as u32)
        };
        let message = Bytes32::from_u32_slice(
            &pis[FALCON_AGG_MSG_OFFSET..FALCON_AGG_MSG_OFFSET + BYTES32_LEN]
                .iter()
                .map(limb)
                .collect::<Result<Vec<_>>>()?,
        )?;
        let count = pis[FALCON_AGG_COUNT_OFFSET].to_canonical_u64() as usize;
        anyhow::ensure!(
            (1..=MAX_COSIGNERS).contains(&count),
            "signer_count {count} out of range 1..={MAX_COSIGNERS}"
        );
        let mut signer_pks = Vec::with_capacity(count);
        for slot in 0..MAX_COSIGNERS {
            let start = FALCON_AGG_PK_LIST_OFFSET + slot * BYTES32_LEN;
            let pk = Bytes32::from_u32_slice(
                &pis[start..start + BYTES32_LEN]
                    .iter()
                    .map(limb)
                    .collect::<Result<Vec<_>>>()?,
            )?;
            if slot < count {
                signer_pks.push(pk);
            } else {
                anyhow::ensure!(
                    pk == Bytes32::default(),
                    "padding slot {slot} is not zero (aggregation is not left-packed)"
                );
            }
        }
        Ok(Self {
            message,
            signer_pks,
        })
    }
}

/// The chain commitment over an ordered list of folded block statements, from `C_0 = 0`.
/// The chain STEP is the shared [`list_chain_step`] — only the leaf format widens.
pub fn agg_list_commitment(entries: &[AggListEntry]) -> Bytes32 {
    let mut chain = PoseidonHashOut::default();
    for entry in entries {
        chain = list_chain_step(chain, entry.leaf());
    }
    chain.into()
}

// FORMAT — in-circuit gadgets (shared with the Phase-3 consumer fold in `update_channel_tree`)
// ================================================================================================

/// In-circuit [`agg_pk_list_digest`]. `pk_limbs` MUST be all `MAX_COSIGNERS` slots in slot order
/// (`MAX_COSIGNERS * BYTES32_LEN` limbs), padding included.
pub(crate) fn agg_pk_list_digest_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    pk_limbs: &[Target],
) -> PoseidonHashOutTarget {
    assert_eq!(
        pk_limbs.len(),
        AGG_PK_LIST_LIMBS,
        "pk list must cover all {MAX_COSIGNERS} slots"
    );
    let dom = builder.constant(F::from_canonical_u32(AGG_PK_LIST_DOMAIN));
    let mut inputs = Vec::with_capacity(1 + AGG_PK_LIST_LIMBS);
    inputs.push(dom);
    inputs.extend_from_slice(pk_limbs);
    PoseidonHashOutTarget::hash_inputs(builder, &inputs)
}

/// In-circuit [`agg_list_leaf`].
pub(crate) fn agg_list_leaf_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    message: &Bytes32Target,
    signer_count: Target,
    pk_list_digest: PoseidonHashOutTarget,
) -> PoseidonHashOutTarget {
    let dom = builder.constant(F::from_canonical_u32(AGG_LIST_LEAF_DOMAIN));
    let mut inputs = Vec::with_capacity(1 + BYTES32_LEN + 1 + 4);
    inputs.push(dom);
    inputs.extend(message.to_vec());
    inputs.push(signer_count);
    inputs.extend(pk_list_digest.to_vec());
    PoseidonHashOutTarget::hash_inputs(builder, &inputs)
}

// STEP CIRCUIT
// ================================================================================================

/// One list step: recursively verify ONE [`FalconAggCircuit`] TOP proof at a CONSTANT verifier key
/// and fold its `(message, signer_count, pk_list_digest)` statement into the running chain.
///
/// Public inputs: `[prev_chain(8), new_chain(8)]` — the exact `(prev_hash, hash)` shape
/// [`CyclicChainCircuit`] chains, identical to [`crate::falcon_sig::list::ListStepCircuit`], so the
/// swap is invisible to the cyclic wrapper and to the validity circuit's conditional-verify
/// structure.
///
/// SECURITY (A7, verifier-data binding): `add_proof_target_and_verify` bakes `agg_top_vd` in as a
/// build-time CONSTANT, so only genuine top-level aggregation proofs extend the chain; a proof of
/// any other circuit fails even with an identical public-input shape.
///
/// SECURITY (no free witness on the folded statement): every folded value — the message limbs, the
/// signer count, all 16 pk slots — is read from the VERIFIED proof's public inputs. The only
/// witnesses of this circuit are the proof itself and `prev_chain` (which the cyclic wrapper
/// constrains to the previous step's output, and to zero at the first step).
pub struct AggListStepCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    agg_proof: ProofWithPublicInputsTarget<D>,
    prev_chain: Bytes32Target,
    /// Builder gate count before padding (reported alongside `data.common.degree_bits()`).
    pub num_gates_before_padding: usize,
}

impl<F, C, const D: usize> AggListStepCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    /// `agg_top_vd` MUST be `FalconAggCircuit::verifier_data()` — the TOP (level
    /// `AGG_LEVELS`) verifier data, whose statement is the 137-element contract.
    ///
    /// SECURITY (arity gate): the 137-element layout is asserted BEFORE any target is added, in a
    /// RELEASE-mode `assert_eq!`. Every offset below is positional, so a verifier key for a
    /// DIFFERENT aggregation level (level 2 exposes 41 elements, the leaf 17) would otherwise
    /// silently produce a step that folds a shorter pk list — a circuit that builds, proves and
    /// commits to the wrong statement. This assert cannot catch a caller substituting an unrelated
    /// circuit that happens to expose 137 public inputs; that is the caller's obligation, and the
    /// constant-VK binding makes it observable in the circuit digest.
    pub fn new(agg_top_vd: &VerifierCircuitData<F, C, D>) -> Self {
        assert_eq!(
            agg_top_vd.common.num_public_inputs, FALCON_AGG_PUBLIC_INPUTS_LEN,
            "aggregation verifier data must expose the TOP-level {FALCON_AGG_PUBLIC_INPUTS_LEN}-element layout"
        );

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

        let agg_proof = add_proof_target_and_verify(agg_top_vd, &mut builder);

        // message = PI[0..8]: the ONE digest every aggregated signature was verified against
        // (`agg.rs` "Message binding": a leaf's exposed message IS the gadget's `message_digest`
        // wire, and every level forces its present children to agree limb-by-limb).
        let message = Bytes32Target::from_slice(
            &agg_proof.public_inputs[FALCON_AGG_MSG_OFFSET..FALCON_AGG_MSG_OFFSET + BYTES32_LEN],
        );
        // signer_count = PI[8].
        let signer_count = agg_proof.public_inputs[FALCON_AGG_COUNT_OFFSET];
        // SECURITY (defence in depth): `1 <= signer_count <= MAX_COSIGNERS` is STRUCTURAL in
        // `FalconAggCircuit` (unconditional left child; leaf count is the constant 1; 16 slots), so
        // this range check is redundant TODAY. It is kept because it costs one gate and because
        // this circuit reads the count as an opaque field element: were the aggregator ever to
        // expose an out-of-range count, the fold would otherwise carry it into the chain unnoticed.
        // `count - 1 ∈ [0, 2^4)` is exactly `1 <= count <= 16`.
        let count_minus_one = builder.add_const(signer_count, F::NEG_ONE);
        builder.range_check(count_minus_one, 4);
        // pk_list_digest over ALL 16 slots, padding included (padding is constrained zero inside
        // the aggregation circuit, so both sides agree without an extra gate here).
        let pk_limbs = &agg_proof.public_inputs
            [FALCON_AGG_PK_LIST_OFFSET..FALCON_AGG_PK_LIST_OFFSET + AGG_PK_LIST_LIMBS];
        let pk_list_digest = agg_pk_list_digest_target(&mut builder, pk_limbs);

        let leaf = agg_list_leaf_target(&mut builder, &message, signer_count, pk_list_digest);

        // new_chain = Poseidon(prev_chain ‖ leaf) — the SHARED chain step, unchanged.
        // `to_hash_out` forces `prev_chain` to a canonical hash-out-derived Bytes32.
        let prev_chain = Bytes32Target::new(&mut builder, true);
        let prev_hashout = prev_chain.to_hash_out(&mut builder);
        let new_hashout = chain_step_target(&mut builder, prev_hashout, leaf);
        let new_chain = Bytes32Target::from_hash_out(&mut builder, new_hashout);

        builder.register_public_inputs(&prev_chain.to_vec());
        builder.register_public_inputs(&new_chain.to_vec());

        let num_gates_before_padding = builder.num_gates();
        let data = builder.build::<C>();
        // RELEASE-mode self-check: the cyclic wrapper slices these 16 PIs positionally
        // (`[0..8]` = prev, `[8..16]` = new); a layout drift must fail loudly at build time.
        assert_eq!(
            data.common.num_public_inputs,
            2 * BYTES32_LEN,
            "agg list step public-input arity must stay [prev_chain(8), new_chain(8)]"
        );

        Self {
            data,
            agg_proof,
            prev_chain,
            num_gates_before_padding,
        }
    }

    pub fn verifier_data(&self) -> VerifierCircuitData<F, C, D> {
        self.data.verifier_data()
    }

    /// Fold one aggregation proof into the chain. `prev_chain` is the native running commitment
    /// over all previously-folded statements ([`agg_list_commitment`]); `Bytes32::zero()` for the
    /// first step.
    pub fn prove(
        &self,
        agg_proof: &ProofWithPublicInputs<F, C, D>,
        prev_chain: Bytes32,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::<F>::new();
        pw.set_proof_with_pis_target(&self.agg_proof, agg_proof)?;
        self.prev_chain
            .set_witness::<F, Bytes32>(&mut pw, prev_chain);
        self.data.prove(pw)
    }
}

// THE RECURSIVE LIST = the per-step folder wrapped in the cyclic chain accumulator
// ================================================================================================

/// The recursive N-of-N signature list proof — the `ListCircuit`-equivalent whose verifier data
/// `ValidityCircuit` consumes (Phase 4). Its public output `[0..8]` is the running chain
/// commitment `C`; compare against [`agg_list_commitment`].
///
/// SECURITY (A7/A8): the cyclic wrapper enforces `prev_chain_i == C_{i-1}` and `C_0 == 0`, and
/// self-references its own verifier data, so only proofs from this circuit can extend the list and
/// the list cannot be seeded mid-chain to hide earlier entries.
///
/// FINDING on the `CommonCircuitData` template (design §5.2 watch item, re-derived deliberately in
/// this phase rather than assumed): the fixed `common_data_for_hash_chain_circuit()` template needs
/// NO change. `CyclicChainCircuit::new` byte-asserts its own `common` against it in a release-mode
/// `assert_eq!`, so simply constructing this type is the check, and it passes — measured: the step
/// is 2^13 / 16 public inputs (down from `ListStepCircuit`'s 2^16, same 16 public inputs) and the
/// wrapper lands on the template's 2^14 / 76 public inputs exactly as before. The widening of the
/// fold lives in the step's LEAF FORMULA, not in its interface, so the wrapper sees an unchanged
/// 16-PI step whose recursive-verification cost went DOWN. Pinned by
/// `wrapper_common_data_is_identical_to_the_falcon_list_wrapper`, which byte-compares this
/// wrapper's `common` against the existing `ListCircuit` wrapper's — the property Phase 4 needs,
/// since `ValidityCircuit` reconstructs a dummy proof from `list_vd.common`.
pub struct AggListCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub step: AggListStepCircuit<F, C, D>,
    pub cyclic: CyclicChainCircuit<F, C, D>,
}

impl<F, C, const D: usize> AggListCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new(agg_top_vd: &VerifierCircuitData<F, C, D>) -> Self {
        let step = AggListStepCircuit::new(agg_top_vd);
        let cyclic = CyclicChainCircuit::new(&step.verifier_data());
        Self { step, cyclic }
    }

    pub fn verifier_data(&self) -> VerifierCircuitData<F, C, D> {
        self.cyclic.data.verifier_data()
    }

    /// Append one aggregation proof to the list. `prev_chain` is the native running commitment over
    /// all previously-appended statements (`Bytes32::zero()` for the first); `prev_cyclic` is the
    /// previous list proof (`None` for the first).
    pub fn prove_append(
        &self,
        agg_proof: &ProofWithPublicInputs<F, C, D>,
        prev_chain: Bytes32,
        prev_cyclic: &Option<ProofWithPublicInputs<F, C, D>>,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        let step_proof = self.step.prove(agg_proof, prev_chain)?;
        self.cyclic
            .prove(&step_proof, prev_cyclic)
            .map_err(|e| anyhow::anyhow!("cyclic agg list proof failed: {e:?}"))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use once_cell::sync::Lazy;
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Field as _},
        plonk::config::PoseidonGoldilocksConfig,
    };

    use super::*;
    use crate::falcon_sig::{
        FALCON_N, FalconKeys, FalconSignature,
        agg::{FalconAggCircuit, FalconAggWitness, FalconLeafCircuit},
        falcon_pk_digest,
    };

    const D: usize = 2;
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;

    /// ONE shared aggregation tree AND one shared agg-list circuit for the whole module: every
    /// case proves / fails against the same constraint systems, so sharing weakens nothing, and
    /// the alternative (rebuilding five aggregation circuits per test) is minutes and gigabytes.
    static AGG: Lazy<FalconAggCircuit<F, C, D>> = Lazy::new(FalconAggCircuit::new);
    static AGG_LIST: Lazy<AggListCircuit<F, C, D>> =
        Lazy::new(|| AggListCircuit::new(&AGG.verifier_data()));

    fn digest(tag: u8) -> Bytes32 {
        Bytes32::from_u32_slice(&[0x494d_4348, tag as u32, 2, 3, 4, 5, 6, 7]).unwrap()
    }

    fn signers(n: usize, msg: Bytes32, seed0: u8) -> (Vec<[u16; FALCON_N]>, Vec<FalconSignature>) {
        let mut hs = Vec::new();
        let mut sigs = Vec::new();
        for i in 0..n {
            let keys = FalconKeys::from_seed([seed0 + i as u8; 32]);
            hs.push(keys.pk_coefficients());
            sigs.push(keys.sign(msg));
        }
        (hs, sigs)
    }

    /// A REAL top-level aggregation proof over `n` distinct keys signing `msg`.
    fn real_agg_proof(n: usize, msg: Bytes32, seed0: u8) -> ProofWithPublicInputs<F, C, D> {
        let (hs, sigs) = signers(n, msg, seed0);
        let refs: Vec<(&[u16; FALCON_N], &FalconSignature)> = hs.iter().zip(sigs.iter()).collect();
        let w = FalconAggWitness::for_signatures(msg, &refs);
        let proof = AGG.prove(&w).expect("aggregation proves");
        AGG.data()
            .verify(proof.clone())
            .expect("aggregation verifies");
        proof
    }

    /// Proving a 16-of-16 aggregation is the heaviest thing in this module; each cached proof is
    /// built at most once and reused by every case that needs it.
    static AGG_2: Lazy<ProofWithPublicInputs<F, C, D>> =
        Lazy::new(|| real_agg_proof(2, digest(0x02), 10));
    static AGG_16: Lazy<ProofWithPublicInputs<F, C, D>> =
        Lazy::new(|| real_agg_proof(MAX_COSIGNERS, digest(0x10), 30));

    /// Measurement hygiene / memory: circuit builds and 16-signature aggregations are the heaviest
    /// operations in the repo. Cases that build or prove hold this lock so the suite never runs two
    /// of them concurrently, whatever `--test-threads` is set to.
    static HEAVY: Mutex<()> = Mutex::new(());

    /// The `should_panic` case panics while holding [`HEAVY`], which poisons it; poisoning carries
    /// no meaning here (the guarded data is `()`), so recover rather than cascade-failing the rest.
    fn heavy() -> std::sync::MutexGuard<'static, ()> {
        HEAVY.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn chain_output(proof: &ProofWithPublicInputs<F, C, D>) -> Bytes32 {
        Bytes32::from_u32_slice(
            &proof.public_inputs[0..BYTES32_LEN]
                .iter()
                .map(|f| f.0 as u32)
                .collect::<Vec<_>>(),
        )
        .unwrap()
    }

    fn pks_of(seed0: u8, n: usize) -> Vec<Bytes32> {
        (0..n)
            .map(|i| {
                falcon_pk_digest(&FalconKeys::from_seed([seed0 + i as u8; 32]).pk_coefficients())
            })
            .collect()
    }

    /// Acceptance 1 (design §9 Phase 2): a step over a REAL 2-of-2 aggregation proof verifies, and
    /// commits to exactly the native statement — the equality the consumer's
    /// `C == final.sig_chain` assertion rests on. Also the measurement point for the step's degree
    /// (Phase 0 measured 2^13 / 4,421 gates).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn step_folds_a_real_2_of_2_aggregation() {
        let _heavy = heavy();
        let agg_proof = &*AGG_2;
        let step = &AGG_LIST.step;
        println!(
            "MEASURE agg_list_step gates={} degree=2^{} pis={} | agg_top degree=2^{} | cyclic degree=2^{}",
            step.num_gates_before_padding,
            step.data.common.degree_bits(),
            step.data.common.num_public_inputs,
            AGG.data().common.degree_bits(),
            AGG_LIST.cyclic.data.common.degree_bits(),
        );

        let t = std::time::Instant::now();
        let proof = step.prove(agg_proof, Bytes32::zero()).expect("step proves");
        println!("MEASURE agg_list_step prove={:?}", t.elapsed());
        step.data.verify(proof.clone()).expect("step verifies");

        // The exposed statement is exactly the native fold over (message, 2 signers).
        let entry = AggListEntry::from_agg_public_inputs(&agg_proof.public_inputs).unwrap();
        assert_eq!(entry.message, digest(0x02));
        assert_eq!(entry.signer_pks, pks_of(10, 2));
        assert_eq!(
            chain_output(&proof),
            Bytes32::zero(),
            "PI[0..8] is prev_chain"
        );
        assert_eq!(
            Bytes32::from_u32_slice(
                &proof.public_inputs[BYTES32_LEN..2 * BYTES32_LEN]
                    .iter()
                    .map(|f| f.0 as u32)
                    .collect::<Vec<_>>()
            )
            .unwrap(),
            agg_list_commitment(&[entry]),
            "in-circuit fold must equal the native commitment"
        );
    }

    /// Acceptance 2: a step over a REAL 16-of-16 aggregation proof verifies (a FULL tree, no absent
    /// subtree anywhere) and again matches the native fold — so the padding-slot agreement between
    /// the aggregation circuit and this fold is exercised at both extremes.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn step_folds_a_real_16_of_16_aggregation() {
        let _heavy = heavy();
        let agg_proof = &*AGG_16;
        let step = &AGG_LIST.step;
        let t = std::time::Instant::now();
        let proof = step.prove(agg_proof, Bytes32::zero()).expect("step proves");
        println!("MEASURE agg_list_step prove(n=16)={:?}", t.elapsed());
        step.data.verify(proof.clone()).expect("step verifies");

        let entry = AggListEntry::from_agg_public_inputs(&agg_proof.public_inputs).unwrap();
        assert_eq!(entry.signer_pks, pks_of(30, MAX_COSIGNERS));
        assert_eq!(
            Bytes32::from_u32_slice(
                &proof.public_inputs[BYTES32_LEN..2 * BYTES32_LEN]
                    .iter()
                    .map(|f| f.0 as u32)
                    .collect::<Vec<_>>()
            )
            .unwrap(),
            agg_list_commitment(&[entry])
        );
    }

    /// Acceptance 3: a verifier key for the WRONG aggregation level fails the BUILD-TIME assert.
    /// The leaf circuit is a genuine member of the aggregation family whose statement is the same
    /// shape at a different width (17 elements, level 0) — exactly the mistake that would otherwise
    /// build a step folding a truncated pk list. Uses the LEAF (not level 2) because the assert
    /// must fire before any expensive work, and this keeps the case cheap.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    #[should_panic(expected = "TOP-level 137-element layout")]
    fn wrong_arity_aggregation_vd_fails_the_build_assert() {
        let _heavy = heavy();
        let leaf = FalconLeafCircuit::<F, C, D>::new();
        let _ = AggListStepCircuit::<F, C, D>::new(&leaf.verifier_data());
    }

    /// Acceptance 4, direction 1 (forgery): an aggregation proof whose MESSAGE public inputs were
    /// swapped for another digest is not provable at this step — the recursive verification of the
    /// proof binds its public inputs, so a message cannot be restated after the fact.
    ///
    /// Direction 2 (honest but wrong message): a genuine aggregation over a DIFFERENT message
    /// folds to a DIFFERENT chain value, so a consumer that recomputed its own digest (the validity
    /// path's `C == final.sig_chain`) rejects it. Both directions together are what makes the fold
    /// a real message binding rather than bookkeeping.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn step_rejects_an_aggregation_over_a_different_message() {
        let _heavy = heavy();
        let step = &AGG_LIST.step;

        // Direction 1 — restate the message on a REAL proof.
        let mut tampered = (*AGG_2).clone();
        let other = digest(0x99);
        for (i, l) in other.to_u32_vec().iter().enumerate() {
            tampered.public_inputs[FALCON_AGG_MSG_OFFSET + i] = F::from_canonical_u32(*l);
        }
        assert!(
            AGG.data().verify(tampered.clone()).is_err(),
            "sanity: the tampered aggregation proof must not verify natively"
        );
        assert!(
            step.prove(&tampered, Bytes32::zero()).is_err(),
            "a step must not fold an aggregation proof whose message was restated"
        );

        // Direction 2 — a genuine aggregation over another message folds elsewhere.
        let honest = step
            .prove(&AGG_2, Bytes32::zero())
            .expect("honest step proves");
        let for_msg_2 = AggListEntry::from_agg_public_inputs(&AGG_2.public_inputs).unwrap();
        let same_signers_other_msg = AggListEntry {
            message: other,
            signer_pks: for_msg_2.signer_pks.clone(),
        };
        assert_ne!(
            agg_list_commitment(&[same_signers_other_msg]),
            agg_list_commitment(&[for_msg_2.clone()]),
            "the fold must separate messages"
        );
        assert_eq!(
            Bytes32::from_u32_slice(
                &honest.public_inputs[BYTES32_LEN..2 * BYTES32_LEN]
                    .iter()
                    .map(|f| f.0 as u32)
                    .collect::<Vec<_>>()
            )
            .unwrap(),
            agg_list_commitment(&[for_msg_2]),
            "the honest step commits to ITS OWN message"
        );
    }

    /// Acceptance 5: the cyclic wrapper builds over this step (the design §5.2 watch item — the
    /// `CommonCircuitData` template is a release-mode byte assert inside `CyclicChainCircuit::new`,
    /// so merely constructing `AGG_LIST` is the check) and the list round-trips exactly as
    /// `ListCircuit` does: append two REAL statements (2-of-2 then 16-of-16), each step's
    /// commitment equals the native chain, and the final proof verifies at the wrapper's VK.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn cyclic_wrapper_builds_and_round_trips() {
        let _heavy = heavy();
        let list = &*AGG_LIST;
        let entries: Vec<AggListEntry> = [&*AGG_2, &*AGG_16]
            .iter()
            .map(|p| AggListEntry::from_agg_public_inputs(&p.public_inputs).unwrap())
            .collect();

        let mut prev_cyclic: Option<ProofWithPublicInputs<F, C, D>> = None;
        for (i, agg_proof) in [&*AGG_2, &*AGG_16].iter().enumerate() {
            let prev_chain = agg_list_commitment(&entries[0..i]);
            let cyclic = list
                .prove_append(agg_proof, prev_chain, &prev_cyclic)
                .expect("append");
            assert_eq!(
                chain_output(&cyclic),
                agg_list_commitment(&entries[0..=i]),
                "step {i} commitment mismatch"
            );
            prev_cyclic = Some(cyclic);
        }
        let final_proof = prev_cyclic.unwrap();
        list.verifier_data()
            .verify(final_proof.clone())
            .expect("final list proof must verify");
        assert_eq!(chain_output(&final_proof), agg_list_commitment(&entries));
    }

    /// Design §5.2 watch item, stated as a falsifiable claim rather than a hope: this wrapper's
    /// `CommonCircuitData` is BYTE-IDENTICAL to the wrapper the single-signature `ListCircuit`
    /// produces today. Two consequences worth having pinned:
    ///   - the `common_data_for_hash_chain_circuit()` template needed no re-derivation despite the
    ///     widened fold (the widening is inside the leaf formula; the step interface is unchanged);
    ///   - Phase 4's `list_vd` -> `agg_list_vd` swap is a VERIFIER-KEY change only at the
    ///     common-data level, so `ValidityCircuit`'s `DummyProof::new(&list_vd.common)`
    ///     reconstruction and its conditional-verify shape are untouched by this phase.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn wrapper_common_data_is_identical_to_the_falcon_list_wrapper() {
        let _heavy = heavy();
        let falcon_list = crate::falcon_sig::list::ListCircuit::<F, C, D>::new();
        assert_eq!(
            AGG_LIST.cyclic.data.common, falcon_list.cyclic.data.common,
            "the agg-list cyclic wrapper must present the same common data as the Falcon list one"
        );
        // ... while being a DIFFERENT circuit (the statement changed), i.e. the two wrappers'
        // proofs are not interchangeable.
        assert_ne!(
            AGG_LIST.verifier_data().verifier_only.circuit_digest,
            falcon_list.verifier_data().verifier_only.circuit_digest,
            "the two wrappers must not share a verifier key"
        );
        println!(
            "MEASURE agg_list_cyclic degree=2^{} pis={}",
            AGG_LIST.cyclic.data.common.degree_bits(),
            AGG_LIST.cyclic.data.common.num_public_inputs,
        );
    }

    /// A8 truncation guard, re-pinned for the new step: the cyclic wrapper forces `C_0 == 0`, so
    /// the list cannot be seeded mid-chain to hide earlier signing blocks. (Unchanged behaviour
    /// from `ListCircuit`; re-tested because the step circuit is new.)
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn first_step_must_start_from_zero_chain() {
        let _heavy = heavy();
        let entry = AggListEntry::from_agg_public_inputs(&AGG_2.public_inputs).unwrap();
        let bogus_prev = agg_list_commitment(&[entry]);
        assert!(
            AGG_LIST.prove_append(&AGG_2, bogus_prev, &None).is_err(),
            "first step must start from a zero chain"
        );
    }

    /// A mismatched `prev_chain` must break the recursion (the cyclic circuit connects the step's
    /// `prev_chain` PI to the previous proof's output), so steps cannot be reordered or dropped.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn step_rejects_wrong_prev_chain() {
        let _heavy = heavy();
        let first = AGG_LIST
            .prove_append(&AGG_2, Bytes32::zero(), &None)
            .expect("first append");
        let bad = AGG_LIST.prove_append(
            &AGG_2,
            Bytes32::zero(), // lie: should be C_1
            &Some(first),
        );
        assert!(
            bad.is_err(),
            "mismatched prev_chain must break the cyclic chain"
        );
    }

    // ---- cheap native format pins (no proving) -------------------------------------------------

    /// The chain format: order-sensitive, prefix-free, and sensitive to EVERY component of the
    /// widened tuple — message, signer_count and each pk slot. `signer_count` is the component the
    /// old `(m, pk)` leaf could not express, and the one Phase 3's `member_count` binding will
    /// lean on, so its sensitivity is pinned here explicitly.
    #[test]
    fn fold_is_sensitive_to_every_component() {
        let pk = |b: u8| Bytes32::from_u32_slice(&[b as u32, 1, 2, 3, 4, 5, 6, 7]).unwrap();
        let m =
            |b: u8| Bytes32::from_u32_slice(&[0x494d_5342, b as u32, 2, 3, 4, 5, 6, 7]).unwrap();
        let e = |msg: Bytes32, pks: Vec<Bytes32>| AggListEntry {
            message: msg,
            signer_pks: pks,
        };
        let base = e(m(1), vec![pk(0xa1), pk(0xa2)]);

        // message
        assert_ne!(
            agg_list_commitment(&[base.clone()]),
            agg_list_commitment(&[e(m(2), base.signer_pks.clone())])
        );
        // signer_count (and, with it, which slots are padding)
        assert_ne!(
            agg_list_commitment(&[base.clone()]),
            agg_list_commitment(&[e(m(1), vec![pk(0xa1)])])
        );
        // pk identity and pk ORDER (slot j is a different statement than slot k)
        assert_ne!(
            agg_list_commitment(&[base.clone()]),
            agg_list_commitment(&[e(m(1), vec![pk(0xa1), pk(0xa3)])])
        );
        assert_ne!(
            agg_list_commitment(&[base.clone()]),
            agg_list_commitment(&[e(m(1), vec![pk(0xa2), pk(0xa1)])])
        );
        // chain order + prefix-freeness
        let other = e(m(7), vec![pk(0xb1), pk(0xb2)]);
        assert_ne!(
            agg_list_commitment(&[base.clone(), other.clone()]),
            agg_list_commitment(&[other.clone(), base.clone()])
        );
        assert_ne!(
            agg_list_commitment(&[base.clone()]),
            agg_list_commitment(&[base.clone(), other])
        );
        // The empty chain is zero — the value the validity circuit gates on.
        assert_eq!(agg_list_commitment(&[]), Bytes32::zero());
        // Padding is a zero SUFFIX: the 16-slot digest of n signers is the digest of the same n
        // signers followed by explicit zero slots.
        assert_eq!(
            agg_pk_list_digest(&[pk(0xa1), pk(0xa2)]),
            agg_pk_list_digest(&[
                pk(0xa1),
                pk(0xa2),
                Bytes32::default(),
                Bytes32::default(),
                Bytes32::default(),
                Bytes32::default(),
                Bytes32::default(),
                Bytes32::default(),
                Bytes32::default(),
                Bytes32::default(),
                Bytes32::default(),
                Bytes32::default(),
                Bytes32::default(),
                Bytes32::default(),
                Bytes32::default(),
                Bytes32::default(),
            ])
        );
    }

    /// SECURITY (domain separation): the widened leaf must not be confusable with the IMLL
    /// `(m, pk)` leaf the single-signature list folds, nor with the pk-list digest — Poseidon here
    /// is a NO-PAD sponge, so only the leading domain constant separates the schemas.
    #[test]
    fn domains_are_the_documented_tags_and_do_not_collide() {
        assert_eq!(AGG_LIST_LEAF_DOMAIN, u32::from_be_bytes(*b"IMAL"));
        assert_eq!(AGG_PK_LIST_DOMAIN, u32::from_be_bytes(*b"IMPL"));
        assert_ne!(AGG_LIST_LEAF_DOMAIN, AGG_PK_LIST_DOMAIN);
        assert_ne!(
            AGG_LIST_LEAF_DOMAIN,
            crate::poseidon_sig::list::LIST_LEAF_DOMAIN
        );
        assert_ne!(
            AGG_PK_LIST_DOMAIN,
            crate::poseidon_sig::list::LIST_LEAF_DOMAIN
        );
        // A same-argument IMLL leaf and IMAL leaf are different values.
        let m = Bytes32::from_u32_slice(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        let pk = Bytes32::from_u32_slice(&[9, 8, 7, 6, 5, 4, 3, 2]).unwrap();
        let imll: Bytes32 = crate::poseidon_sig::list::list_leaf(m, pk).into();
        let imal: Bytes32 = agg_list_leaf(m, 1, agg_pk_list_digest(&[pk])).into();
        assert_ne!(imll, imal);
    }

    /// The prover-side parser rejects the shapes it must never silently accept: wrong arity, an
    /// out-of-range count, and a NON-left-packed list (a nonzero pk in a padding slot). The last
    /// one matters because the chain would otherwise be computed over a statement the aggregation
    /// circuit cannot produce, making an honest prover's commitment unreproducible in-circuit.
    #[test]
    fn public_input_parser_rejects_malformed_statements() {
        let ok = crate::falcon_sig::agg::falcon_agg_expected_public_inputs::<F>(
            crate::falcon_sig::agg::AGG_LEVELS,
            Bytes32::from_u32_slice(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap(),
            &[Bytes32::from_u32_slice(&[9, 9, 9, 9, 9, 9, 9, 9]).unwrap()],
        );
        assert!(AggListEntry::from_agg_public_inputs(&ok).is_ok());
        assert!(
            AggListEntry::from_agg_public_inputs(&ok[1..]).is_err(),
            "arity"
        );

        let mut zero_count = ok.clone();
        zero_count[FALCON_AGG_COUNT_OFFSET] = F::ZERO;
        assert!(
            AggListEntry::from_agg_public_inputs(&zero_count).is_err(),
            "signer_count = 0"
        );

        let mut too_many = ok.clone();
        too_many[FALCON_AGG_COUNT_OFFSET] = F::from_canonical_usize(MAX_COSIGNERS + 1);
        assert!(
            AggListEntry::from_agg_public_inputs(&too_many).is_err(),
            "signer_count > MAX_COSIGNERS"
        );

        let mut dirty_padding = ok.clone();
        dirty_padding[FALCON_AGG_PK_LIST_OFFSET + BYTES32_LEN] = F::ONE;
        assert!(
            AggListEntry::from_agg_public_inputs(&dirty_padding).is_err(),
            "nonzero padding slot"
        );
    }
}
