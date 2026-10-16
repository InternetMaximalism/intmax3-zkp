//! Concrete Plonky3 configurations for the Regev encryption proof.
//!
//! Default: BabyBear + Poseidon2 transcript + two-adic FRI. BabyBear is both
//! the ciphertext modulus and the proof field, and (unlike Mersenne31) is
//! NTT-friendly, so the *encryptor* also gets fast negacyclic multiplication
//! natively.

use p3_baby_bear::{default_babybear_poseidon2_16, BabyBear, Poseidon2BabyBear};
use p3_challenger::{DuplexChallenger, HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::Field;
use p3_fri::{FriParameters, HidingFriPcs, TwoAdicFriPcs};
use p3_keccak::{Keccak256Hash, KeccakF};
use p3_merkle_tree::{MerkleTreeHidingMmcs, MerkleTreeMmcs};
use p3_symmetric::{
    CompressionFunctionFromHasher, CryptographicHasher, PaddingFreeSponge, SerializingHasher,
    TruncatedPermutation,
};
use p3_uni_stark::StarkConfig;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

pub type Val = BabyBear;
pub type Challenge = BinomialExtensionField<Val, 4>;

pub type Perm = Poseidon2BabyBear<16>;

/// The canonical Poseidon2-BabyBear permutation used everywhere in this crate
/// (transcript, Merkle hashing). It uses Plonky3's published compile-time
/// round constants, **not** an RNG, so it is byte-identical on every target.
///
/// Building the permutation from `rand::rngs::SmallRng` instead would fork the
/// transcript across pointer widths (32-bit wasm vs 64-bit native); see
/// [`crate::portability`].
pub fn canonical_perm() -> Perm {
    default_babybear_poseidon2_16()
}
type Hash = PaddingFreeSponge<Perm, 16, 8, 8>;
type Compress = TruncatedPermutation<Perm, 2, 8, 16>;
type ValMmcs =
    MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, Hash, Compress, 2, 8>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
pub type Challenger = DuplexChallenger<Val, Perm, 16, 8>;
type Dft = Radix2DitParallel<Val>;
pub type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
pub type RegevStarkConfig = StarkConfig<Pcs, Challenge, Challenger>;

/// Production-leaning config: blowup 2, 84 queries, 16-bit grinding
/// (~100-bit conjectured security with the quartic extension).
pub fn default_config() -> RegevStarkConfig {
    make_config(FriParametersSpec {
        log_blowup: 1,
        log_final_poly_len: 0,
        max_log_arity: 4,
        num_queries: 84,
        commit_proof_of_work_bits: 8,
        query_proof_of_work_bits: 16,
    })
}

/// Cheap config for tests: few queries, tiny grinding. NOT secure.
pub fn test_config() -> RegevStarkConfig {
    make_config(FriParametersSpec {
        log_blowup: 1,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 8,
        commit_proof_of_work_bits: 1,
        query_proof_of_work_bits: 1,
    })
}

// --- Zero-knowledge variant (hiding FRI) ---------------------------------
//
// The witness (encryption randomness, noise, message) is secret, so for
// deployments where the proof itself must not leak trace information, use
// this config: `HidingFriPcs` masks committed polynomials with randomness
// and adds a random codeword to the FRI batch (statistical zk).

type ByteHash = Keccak256Hash;
type U64Hash = PaddingFreeSponge<KeccakF, 25, 17, 4>;
type ZkFieldHash = SerializingHasher<U64Hash>;
type ZkCompress = CompressionFunctionFromHasher<U64Hash, 2, 4>;
/// RNG used to blind the hiding Merkle leaves and the FRI mask.
///
/// SECURITY: `MerkleTreeHidingMmcs` documents that this MUST be a
/// cryptographically secure PRNG: the salts of the *opened* leaves are part of
/// the proof, so a predictable generator lets an observer reconstruct the
/// stream and derive the salts of the *unopened* leaves — which destroys the
/// hiding property the whole config exists to provide. `SmallRng`
/// (xoshiro256++) is NOT a CSPRNG and must not be used here.
pub type ZkRng = ChaCha20Rng;

type ZkValMmcs = MerkleTreeHidingMmcs<
    [Val; p3_keccak::VECTOR_LEN],
    [u64; p3_keccak::VECTOR_LEN],
    ZkFieldHash,
    ZkCompress,
    ZkRng,
    2,
    4,
    4,
>;
type ZkChallengeMmcs = ExtensionMmcs<Val, Challenge, ZkValMmcs>;
pub type ZkChallenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
pub type ZkPcs = HidingFriPcs<Val, Dft, ZkValMmcs, ZkChallengeMmcs, ZkRng>;
pub type RegevZkStarkConfig = StarkConfig<ZkPcs, Challenge, ZkChallenger>;

/// Production zero-knowledge config (hiding commitments + randomized FRI
/// batch), seeded from the OS entropy source. Roughly 3-4x the proving cost of
/// [`default_config`] — that gap is the hiding construction itself (blowup
/// 1 -> 2, salted leaves, random codeword), not the hash choice.
pub fn zk_config() -> RegevZkStarkConfig {
    zk_config_seeded(ZkRng::from_rng(&mut rand::rng()))
}

/// ZK config with caller-supplied masking randomness (for reproducible
/// tests; use [`zk_config`] in production).
pub fn zk_config_seeded(rng: ZkRng) -> RegevZkStarkConfig {
    zk_config_with(rng, ZkFriSpec::PRODUCTION)
}

/// Cheap hiding config for tests: few queries, tiny grinding. NOT secure — it
/// exists so the test suite exercises the SAME hiding machinery as production
/// without paying the production query count.
pub fn zk_test_config() -> RegevZkStarkConfig {
    zk_config_with(ZkRng::seed_from_u64(0), ZkFriSpec::TEST)
}

/// FRI parameters for the hiding configs. `log_blowup` must stay >= 2: the
/// hiding PCS spends part of the degree budget on the random codeword.
pub struct ZkFriSpec {
    pub log_blowup: usize,
    pub max_log_arity: usize,
    pub num_queries: usize,
    pub commit_proof_of_work_bits: usize,
    pub query_proof_of_work_bits: usize,
}

impl ZkFriSpec {
    /// ~100-bit conjectured security at rate 1/4.
    ///
    /// `max_log_arity = 4` (not 1): measured at n = 2048 it is both faster to
    /// prove and produces a ~33% smaller proof (199 KB vs 297 KB) than the
    /// arity-1 folding the config previously used.
    pub const PRODUCTION: Self = Self {
        log_blowup: 2,
        max_log_arity: 4,
        num_queries: 42,
        commit_proof_of_work_bits: 8,
        query_proof_of_work_bits: 16,
    };
    pub const TEST: Self = Self {
        log_blowup: 2,
        max_log_arity: 1,
        num_queries: 8,
        commit_proof_of_work_bits: 1,
        query_proof_of_work_bits: 1,
    };
}

/// Derive one independent child RNG per randomness purpose.
///
/// Three consumers draw hiding randomness from the configuration: the input-commitment MMCS
/// (leaf salts), the FRI-commitment MMCS (leaf salts) and the hiding PCS (random trace
/// columns and quotient randomizers). They MUST NOT share one stream: a `clone()` of a
/// ChaCha20 state replays exactly the same output, and the salts are published in every
/// query opening, so a cloned state would publish the masking randomness as well
/// (cryptographic review 2026-10-16, "Hiding salts and masks share cloned RNG state").
/// Each child is seeded from 32 fresh parent bytes mixed with a purpose label.
fn derive_child_rng(parent: &mut ZkRng, purpose: &[u8]) -> ZkRng {
    use rand::Rng as _;
    let mut fresh = [0u8; 32];
    parent.fill_bytes(&mut fresh);
    let seed: [u8; 32] =
        p3_keccak::Keccak256Hash.hash_iter(purpose.iter().chain(fresh.iter()).copied());
    ZkRng::from_seed(seed)
}

fn zk_config_with(mut rng: ZkRng, spec: ZkFriSpec) -> RegevZkStarkConfig {
    let input_salt_rng = derive_child_rng(&mut rng, b"regev-zk/input-mmcs-salts");
    let fri_salt_rng = derive_child_rng(&mut rng, b"regev-zk/fri-mmcs-salts");
    let mask_rng = derive_child_rng(&mut rng, b"regev-zk/pcs-masks");
    let u64_hash = U64Hash::new(KeccakF {});
    let field_hash = ZkFieldHash::new(u64_hash);
    let compress = ZkCompress::new(u64_hash);
    let val_mmcs = ZkValMmcs::new(field_hash, compress, 0, input_salt_rng);
    let challenge_mmcs = ZkChallengeMmcs::new(ZkValMmcs::new(
        ZkFieldHash::new(u64_hash),
        ZkCompress::new(u64_hash),
        0,
        fri_salt_rng,
    ));
    let fri_params = FriParameters {
        log_blowup: spec.log_blowup,
        log_final_poly_len: 0,
        max_log_arity: spec.max_log_arity,
        num_queries: spec.num_queries,
        commit_proof_of_work_bits: spec.commit_proof_of_work_bits,
        query_proof_of_work_bits: spec.query_proof_of_work_bits,
        mmcs: challenge_mmcs,
    };
    let pcs = ZkPcs::new(Dft::default(), val_mmcs, fri_params, 4, mask_rng);
    let challenger = ZkChallenger::from_hasher(vec![], ByteHash {});
    RegevZkStarkConfig::new(pcs, challenger)
}

struct FriParametersSpec {
    log_blowup: usize,
    log_final_poly_len: usize,
    max_log_arity: usize,
    num_queries: usize,
    commit_proof_of_work_bits: usize,
    query_proof_of_work_bits: usize,
}

fn make_config(spec: FriParametersSpec) -> RegevStarkConfig {
    // Poseidon2 permutation drives the Fiat-Shamir transcript, so its round
    // constants MUST be identical on every target. We use Plonky3's canonical
    // published BabyBear constants (`default_babybear_poseidon2_16`): they are
    // compile-time tables, not derived from any RNG.
    //
    // NOTE: do NOT build the permutation from `rand::rngs::SmallRng` here.
    // `SmallRng` is pointer-width-dependent (Xoshiro128++ on 32-bit wasm32,
    // Xoshiro256++ on 64-bit native), so a fixed seed yields *different* round
    // constants per target — which silently forks the transcript and makes a
    // wasm-generated proof fail native verification (FRI `InvalidPowWitness`)
    // and vice-versa. See `portability::transcript_digest` for the regression
    // guard and `tests/portability.rs` for the golden cross-target values.
    let perm = canonical_perm();
    let hash = Hash::new(perm.clone());
    let compress = Compress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let fri_params = FriParameters {
        log_blowup: spec.log_blowup,
        log_final_poly_len: spec.log_final_poly_len,
        max_log_arity: spec.max_log_arity,
        num_queries: spec.num_queries,
        commit_proof_of_work_bits: spec.commit_proof_of_work_bits,
        query_proof_of_work_bits: spec.query_proof_of_work_bits,
        mmcs: challenge_mmcs,
    };
    let pcs = Pcs::new(Dft::default(), val_mmcs, fri_params);
    let challenger = Challenger::new(perm);
    RegevStarkConfig::new(pcs, challenger)
}
