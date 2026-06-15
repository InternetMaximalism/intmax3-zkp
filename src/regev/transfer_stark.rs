//! Plonky3 STARK statements for the Regev payment-channel layer (detail2.md §E; phase P2a:
//! §E-1 channelTxZKP and §E-2 channelUpdateZKP; phase P2b: §E-3 withdrawClaimZKP and the §B-3
//! balance-refresh proof).
//!
//! E-1/E-2 are *dual-key* extensions of the upstream `regev_plonky3::transfer` AIR
//! (single shared public key, 3 ciphertexts): the trace carries TWO public-key column pairs
//! `(a_s, b_s)` (sender) and `(a_r, b_r)` (recipient), and each ciphertext's ring identities are
//! bound to one of the two pairs. E-3 and the refresh proof are built on a shared *decryption
//! core* (key binding + decryption identity + digit extraction + digit→bit normalization, see
//! below).
//!
//! # Statements
//!
//! **E-1 ChannelTx ([`DualKeyTransferAir`], 3 ciphertexts):** `before` and `after` are
//! well-formed encryptions under the SENDER key, `enc_amount` is a well-formed encryption under
//! the RECIPIENT key, and the plaintexts satisfy `before = after + amount` over the integers via
//! a ripple-carry adder on the message-bit columns (underflow is constitutively impossible: all
//! three plaintexts are committed bit vectors, hence non-negative, and the final carry is
//! constrained to zero).
//!
//! **E-2 ChannelUpdate ([`ChannelUpdateAir`], 4 ciphertexts):** `before`, `after`,
//! `sender_delta` are well-formed under the SENDER key, `receiver_delta` is well-formed under
//! the RECIPIENT key, `before = after + sender_delta` (same carry chain), and **both deltas
//! encrypt exactly the PUBLIC `amount`**: the message evaluations `m(z)` of both delta
//! ciphertexts are published, and the verifier recomputes `eval(encode_amount(amount), z)` and
//! requires equality (see the soundness note below).
//!
//! **E-3 WithdrawClaim ([`DecryptionAir`], 1 ciphertext):** "`ct` decrypts to the PUBLIC
//! `amount` under the secret key behind the public `(a, b)`". The secret key `s` (ternary), the
//! pk noise `e_pk` (CBD(2)), the decryption value column `v`, the per-coefficient digits and the
//! centered rounding noise are private witnesses; see the decryption-core section below for the
//! exact constraint system, the rounding convention and the no-wrap/carry-bound analyses.
//!
//! **BalanceRefresh ([`RefreshAir`], 2 ciphertexts):** "`old_ct` and `new_ct` encrypt the same
//! (hidden) plaintext under the same key, and `new_ct` is a fresh well-formed encryption". One
//! combined instance: the decryption core decodes `old_ct`'s digits and normalizes them into a
//! bit column `m`, and that very column is the message of the encryption constraints for
//! `new_ct` — the plaintext-equality link is structural and fully in-circuit.
//!
//! SECURITY (refresh privacy — deviation from the batch-of-two design): the alternative
//! construction (two batch instances sharing the evaluation challenge `z`, each PUBLISHING its
//! bit-column evaluation so the verifier can compare them) is *sound* — `z` is shared across all
//! instances of one `prove_batch` and both columns commit before `z` — but it leaks: a published
//! `m(z)` of a SECRET balance is a plaintext-confirmation oracle (enumerate candidate amounts
//! `A`, compare `eval(encode_amount(A), z)`; upstream's privacy note warns about exactly this
//! dictionary attack on low-entropy messages). The combined AIR keeps the bit column
//! `Kind::Local`, publishes only public-polynomial evaluations, and needs no cross-instance
//! comparison at all.
//!
//! # Fiat-Shamir transcript analysis (threat model F2-A)
//!
//! Upstream `stark::prove_batch` / `verify_batch` (vendored p3-batch-stark with the
//! `EvalGadget` evaluation argument) absorb, in order: (1) instance count and per-instance
//! binding data (degrees, width, quotient chunk count), (2) the **main trace commitment**,
//! (3) **all public values**, (4) preprocessed widths; only then is the shared evaluation
//! challenge `z` sampled, followed by the permutation commitment + published evaluations,
//! `alpha`, the quotient commitment, `zeta`, and the FRI challenges inside `pcs.open`/`verify`.
//!
//! SECURITY: the public values (including our purpose domain word and, for E-2, the public
//! amount) are therefore absorbed BEFORE `z`, `alpha`, `zeta` and every FRI challenge — there is
//! no F2-A gap. The only proof data an adversarial prover can choose *after* seeing `z` are the
//! permutation (Horner) trace and the published `expected_cumulated` evaluations; both are fully
//! pinned relative to the already-committed main trace: the Horner transition/last-row
//! constraints force each auxiliary column to be the running evaluation of its main-trace
//! expression at `z`, the first-row constraint pins the published value to that column, and
//! `alpha`/`zeta` are sampled only after the permutation commitment and the published values are
//! absorbed, so they cannot be adapted to the constraint check either. The outer binding is then
//! the verifier RECOMPUTING the public polynomials' evaluations at `z` from the claimed
//! statement (the very statement whose public values it absorbed) and comparing them with the
//! published values — by Schwartz-Zippel, agreement at the post-commitment challenge `z` implies
//! the committed columns equal the claimed public polynomials except with probability
//! `< n / |EF| ≈ 2^-117` (n = 128, quartic BabyBear extension).
//!
//! # Purpose domain separation (threat model F2-B)
//!
//! SECURITY: the first public value of every instance is the purpose domain word
//! (`CHANNEL_TX_ZKP_DOMAIN`, ...). Public values are absorbed into the Fiat-Shamir challenger
//! before any challenge is drawn, and the VERIFIER rebuilds the public-value vector itself from
//! the purpose it expects (each `verify_*` function hardcodes its own domain constant) — it
//! never reads the domain from the proof. A proof generated under a different purpose therefore
//! replays into a diverged transcript: the verifier's `z`/`alpha`/`zeta`/FRI challenges differ
//! from the prover's, so the PCS opening verification and the constraint check fail (and the
//! recomputed evaluations at the verifier's `z` mismatch the published ones). On top of the
//! transcript binding, [`RealRegevProofVerifier::verify`] independently rejects any
//! purpose/statement-variant mismatch before doing any proof work, and the E-1/E-2 AIRs also
//! differ structurally (trace width, public-value count, published-evaluation count).
//!
//! # Public-amount binding soundness (threat model F2-C, E-2 only)
//!
//! SECURITY: each delta's message column `m` is committed in the main trace (boolean-constrained
//! per row) BEFORE `z` is sampled. Its evaluation `m(z)` is published via the same
//! `Kind::Global` evaluation-argument machinery as the ciphertext polynomials, and
//! [`verify_channel_update`] recomputes `eval(encode_amount(amount), z)` from the PUBLIC amount
//! and requires equality for BOTH deltas. Interpreting the committed column as the coefficient
//! vector of a degree-<128 polynomial, equality with the public encoding polynomial at the
//! post-commitment random point `z` pins the full coefficient vector (Schwartz-Zippel error
//! `< 128 / |EF| ≈ 2^-117`) — including bits 64..128, which `encode_amount` fixes to zero. This
//! simultaneously forces `sender_delta` plaintext == `receiver_delta` plaintext == `amount`.
//! Publishing `m(z)` for the deltas leaks nothing: in E-2 the amount is public by design
//! (detail2 §E-2), so the delta message polynomial is already public information.

#[allow(unused_imports)]
// DebugConstraintBuilder bound is exercised by debug builds of prove_batch.
use p3_air_05::DebugConstraintBuilder;
use p3_air_05::{
    Air, AirBuilder, BaseAir, ExtensionBuilder, PermutationAirBuilder, WindowAccess,
    symbolic::{BaseEntry, SymbolicAirBuilder, SymbolicExpression, SymbolicVariable},
};
use p3_batch_stark::{
    common::{CommonData, ProverData},
    config::StarkGenericConfig as _,
    proof::BatchProof,
    prover::StarkInstance,
};
use p3_field_05::{Field, PrimeCharacteristicRing, PrimeField32};
use p3_lookup::{
    LookupAir,
    folder::{ProverConstraintFolderWithLookups, VerifierConstraintFolderWithLookups},
    lookup_traits::{Kind, Lookup},
};
use p3_matrix_05::dense::RowMajorMatrix;
use regev_plonky3::{
    Challenge, RegevStarkConfig,
    config::{default_config, test_config},
    regev::{
        Ciphertext as UpstreamCiphertext, EncryptionWitness, F, PublicKey as UpstreamPublicKey,
        centered_to_field, field_to_centered,
    },
    stark,
};

use super::{
    encrypt::{
        AmountWitness, RegevCiphertext, RegevError, decrypt_amount, encode_amount, encrypt_amount,
        to_upstream_ct, to_upstream_pk,
    },
    keys::{RegevPk, RegevSk},
    params::{REGEV_N, REGEV_PLAIN_BITS, REGEV_Q, channel_regev_params},
};

// ---------------------------------------------------------------------------
// Purpose domains
// ---------------------------------------------------------------------------

/// Domain word for E-1 channelTxZKP ("IMCZ").
pub const CHANNEL_TX_ZKP_DOMAIN: u32 = 0x494d435a;
/// Domain word for E-2 channelUpdateZKP ("IMUZ").
pub const CHANNEL_UPDATE_ZKP_DOMAIN: u32 = 0x494d555a;
/// Domain word for E-3 withdrawClaimZKP ("IMWZ").
pub const WITHDRAW_CLAIM_ZKP_DOMAIN: u32 = 0x494d575a;
/// Domain word for the balance-refresh proof ("IMRF").
pub const BALANCE_REFRESH_ZKP_DOMAIN: u32 = 0x494d5246;

// SECURITY: every domain word must be < REGEV_Q so that `F::from_u32(domain)` is injective and
// two purposes can never collide in the transcript. "IM.." words are ~0x494d_0000 ≈ 1.23e9,
// well below q = 2_013_265_921.
const _: () = {
    assert!(CHANNEL_TX_ZKP_DOMAIN < super::params::REGEV_Q);
    assert!(CHANNEL_UPDATE_ZKP_DOMAIN < super::params::REGEV_Q);
    assert!(WITHDRAW_CLAIM_ZKP_DOMAIN < super::params::REGEV_Q);
    assert!(BALANCE_REFRESH_ZKP_DOMAIN < super::params::REGEV_Q);
};

/// The four lattice-proof purposes of detail2 §E-4: `ChannelTx` (E-1), `ChannelUpdate` (E-2),
/// `WithdrawClaim` (E-3) and `BalanceRefresh` (§B-3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegevProofPurpose {
    ChannelTx,
    ChannelUpdate,
    WithdrawClaim,
    BalanceRefresh,
}

impl RegevProofPurpose {
    /// The transcript domain word bound into every proof of this purpose.
    pub const fn domain(self) -> u32 {
        match self {
            Self::ChannelTx => CHANNEL_TX_ZKP_DOMAIN,
            Self::ChannelUpdate => CHANNEL_UPDATE_ZKP_DOMAIN,
            Self::WithdrawClaim => WITHDRAW_CLAIM_ZKP_DOMAIN,
            Self::BalanceRefresh => BALANCE_REFRESH_ZKP_DOMAIN,
        }
    }
}

/// STARK parameter strength.
///
/// SECURITY: `Test` uses the upstream `test_config()` (8 FRI queries, 1-bit grinding) and is
/// NOT secure — it exists so the test suite stays fast. `Production` uses `default_config()`
/// (84 queries, 16-bit grinding, ~100-bit conjectured security). The level is chosen by the
/// verifier, never read from the proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegevSecurityLevel {
    Test,
    Production,
}

impl RegevSecurityLevel {
    fn config(self) -> RegevStarkConfig {
        match self {
            Self::Test => test_config(),
            Self::Production => default_config(),
        }
    }
}

// ---------------------------------------------------------------------------
// Column layout (shared by both AIRs)
// ---------------------------------------------------------------------------
//
// Main columns:
//   a_s b_s a_r b_r | c1 c2 r e1u e1v e2u e2v m k1 k2 |×num_cts | carry
//
// Aux (permutation) columns, in lookup order:
//   a_s b_s a_r b_r (exposed) | c1 c2 (exposed) r e1 e2 m k1 k2 |×num_cts
// (`m` is additionally exposed for the ciphertexts flagged in `AirShape::expose_m`.)

const COL_A_S: usize = 0;
const COL_B_S: usize = 1;
const COL_A_R: usize = 2;
const COL_B_R: usize = 3;
const NUM_KEY_COLS: usize = 4;

/// Per-ciphertext main columns (same order as upstream `transfer.rs`).
const CT_COLS: usize = 10;
const OFF_C1: usize = 0;
const OFF_C2: usize = 1;
const OFF_R: usize = 2;
const OFF_E1U: usize = 3;
const OFF_E1V: usize = 4;
const OFF_E2U: usize = 5;
const OFF_E2V: usize = 6;
const OFF_M: usize = 7;
const OFF_K1: usize = 8;
const OFF_K2: usize = 9;

const fn ct_base(j: usize) -> usize {
    NUM_KEY_COLS + j * CT_COLS
}

// Aux (permutation) column layout: 4 key evaluations, then 8 per ciphertext. The aux index of
// each lookup equals its position in `dual_key_lookups`, so this layout is pinned by the
// lookup order there.
const AUX_A_S: usize = 0;
const AUX_B_S: usize = 1;
const AUX_A_R: usize = 2;
const AUX_B_R: usize = 3;
const NUM_KEY_AUX: usize = 4;
const CT_AUX: usize = 8;
const AOFF_C1: usize = 0;
const AOFF_C2: usize = 1;
const AOFF_R: usize = 2;
const AOFF_E1: usize = 3;
const AOFF_E2: usize = 4;
const AOFF_M: usize = 5;
const AOFF_K1: usize = 6;
const AOFF_K2: usize = 7;

const fn aux_base(j: usize) -> usize {
    NUM_KEY_AUX + j * CT_AUX
}

/// Static shape of a dual-key statement: how many ciphertexts, which of them bind to the
/// recipient key pair, which message evaluations are published, and which three ciphertexts the
/// ripple-carry conservation chain runs over.
#[derive(Clone, Copy, Debug)]
struct AirShape {
    num_cts: usize,
    /// `true` → ciphertext `j`'s ring identities use `(a_r, b_r)` instead of `(a_s, b_s)`.
    recipient_ct: &'static [bool],
    /// `true` → ciphertext `j`'s message evaluation `m(z)` is published (`Kind::Global`).
    expose_m: &'static [bool],
    /// Conservation chain roles: `before = after + delta` over message bits.
    carry_before: usize,
    carry_delta: usize,
    carry_after: usize,
}

impl AirShape {
    const fn carry_col(&self) -> usize {
        NUM_KEY_COLS + self.num_cts * CT_COLS
    }

    const fn num_cols(&self) -> usize {
        self.carry_col() + 1
    }

    /// `[domain] ++ extra ++ a_s ++ b_s ++ a_r ++ b_r ++ (c1, c2)×num_cts`.
    const fn num_public_values(&self, n: usize, num_extra: usize) -> usize {
        1 + num_extra + (NUM_KEY_COLS + 2 * self.num_cts) * n
    }

    /// Number of published (`Kind::Global`) evaluations, in lookup order.
    fn num_published_evals(&self) -> usize {
        NUM_KEY_AUX + 2 * self.num_cts + self.expose_m.iter().filter(|&&e| e).count()
    }
}

/// E-1 ciphertext order: `before` (sender), `enc_amount` (recipient), `after` (sender).
const E1_SHAPE: AirShape = AirShape {
    num_cts: 3,
    recipient_ct: &[false, true, false],
    expose_m: &[false, false, false],
    carry_before: 0,
    carry_delta: 1,
    carry_after: 2,
};

/// E-2 ciphertext order: `before` (sender), `after` (sender), `sender_delta` (sender),
/// `receiver_delta` (recipient). Conservation: `before = after + sender_delta`.
const E2_SHAPE: AirShape = AirShape {
    num_cts: 4,
    recipient_ct: &[false, false, false, true],
    expose_m: &[false, false, true, true],
    carry_before: 0,
    carry_delta: 2,
    carry_after: 1,
};

/// Number of extra public values (after the domain word) for E-2: the public amount as four
/// 16-bit limbs.
const E2_NUM_EXTRA_PVS: usize = 4;

// ---------------------------------------------------------------------------
// Shared AIR logic
// ---------------------------------------------------------------------------

/// The evaluation arguments (lookups) of a dual-key AIR, in the order that fixes both the aux
/// column layout and the order of the published evaluations.
fn dual_key_lookups<Fld: Field>(shape: &AirShape) -> Vec<Lookup<Fld>> {
    let main_var = |col: usize| SymbolicVariable::<Fld>::new(BaseEntry::Main { offset: 0 }, col);
    let col = |c: usize| -> Vec<Vec<SymbolicExpression<Fld>>> { vec![vec![main_var(c).into()]] };
    let diff = |u: usize, v: usize| -> Vec<Vec<SymbolicExpression<Fld>>> {
        vec![vec![main_var(u) - main_var(v)]]
    };

    let mut specs: Vec<(Kind, Vec<Vec<SymbolicExpression<Fld>>>)> = vec![
        (Kind::Global("eval:a_s".to_string()), col(COL_A_S)),
        (Kind::Global("eval:b_s".to_string()), col(COL_B_S)),
        (Kind::Global("eval:a_r".to_string()), col(COL_A_R)),
        (Kind::Global("eval:b_r".to_string()), col(COL_B_R)),
    ];
    for j in 0..shape.num_cts {
        let base = ct_base(j);
        let m_kind = if shape.expose_m[j] {
            // SECURITY: publishing m(z) is only sound privacy-wise when the plaintext is public
            // by design (E-2 deltas, whose plaintext is the public amount).
            Kind::Global(format!("eval:m:ct{j}"))
        } else {
            Kind::Local
        };
        specs.extend([
            (Kind::Global(format!("eval:c1:ct{j}")), col(base + OFF_C1)),
            (Kind::Global(format!("eval:c2:ct{j}")), col(base + OFF_C2)),
            (Kind::Local, col(base + OFF_R)),
            (Kind::Local, diff(base + OFF_E1U, base + OFF_E1V)),
            (Kind::Local, diff(base + OFF_E2U, base + OFF_E2V)),
            (m_kind, col(base + OFF_M)),
            (Kind::Local, col(base + OFF_K1)),
            (Kind::Local, col(base + OFF_K2)),
        ]);
    }

    specs
        .into_iter()
        .enumerate()
        .map(|(aux, (kind, element_exprs))| Lookup {
            kind,
            element_exprs,
            multiplicities_exprs: vec![],
            columns: vec![aux],
        })
        .collect()
}

/// Constraint body shared by both AIRs: per-ciphertext smallness, the ripple-carry conservation
/// chain, and the ring identities at the shared evaluation point `z` (each ciphertext bound to
/// its key pair per `shape.recipient_ct`).
fn eval_dual_key<AB>(builder: &mut AB, n: usize, delta_scale: AB::F, shape: &AirShape)
where
    AB: PermutationAirBuilder,
{
    let main = builder.main();
    let local: &[AB::Var] = main.current_slice();
    let next: &[AB::Var] = main.next_slice();

    // --- Per-ciphertext smallness (same constraints as upstream RegevEncAir) ----------------
    for j in 0..shape.num_cts {
        let base = ct_base(j);

        let r: AB::Expr = local[base + OFF_R].into();
        builder.assert_zero(r.clone() * (r.clone() - AB::Expr::ONE) * (r + AB::Expr::ONE));

        for off in [OFF_E1U, OFF_E1V, OFF_E2U, OFF_E2V] {
            let x: AB::Expr = local[base + off].into();
            builder.assert_zero(x.clone() * (x.clone() - AB::Expr::ONE) * (x - AB::Expr::TWO));
        }

        let m: AB::Expr = local[base + OFF_M].into();
        builder.assert_bool(m);
    }

    // --- Ripple-carry conservation: before = after + delta ----------------------------------
    // SECURITY: the last-row form forces the final carry to zero, so the equation holds over
    // the integers — `delta` can never exceed `before` (underflow impossible, detail2 §E-1.2).
    let m_before: AB::Expr = local[ct_base(shape.carry_before) + OFF_M].into();
    let m_delta: AB::Expr = local[ct_base(shape.carry_delta) + OFF_M].into();
    let m_after: AB::Expr = local[ct_base(shape.carry_after) + OFF_M].into();
    let carry: AB::Expr = local[shape.carry_col()].into();
    let carry_next: AB::Expr = next[shape.carry_col()].into();

    builder.assert_bool(carry.clone());
    builder.when_first_row().assert_zero(carry.clone());

    let lhs = m_after + m_delta + carry - m_before;
    // after[i] + delta[i] + c[i] − before[i] = 2·c[i+1]
    builder
        .when_transition()
        .assert_zero(lhs.clone() - carry_next * AB::Expr::TWO);
    // Final carry must be zero: the equation holds over the integers.
    builder.when_last_row().assert_zero(lhs);

    // --- Ring identities at the random point z (one pair per ciphertext) --------------------
    let perm = builder.permutation();
    let s = |aux: usize| -> AB::ExprEF {
        perm.current(aux)
            .expect("permutation trace too narrow")
            .into()
    };

    let z: AB::ExprEF = builder.permutation_randomness()[0].into();
    let mut zn = z;
    for _ in 0..n.trailing_zeros() {
        zn = zn.clone() * zn;
    }
    let zn1 = zn + AB::ExprEF::ONE;

    for j in 0..shape.num_cts {
        // SECURITY: the key-pair selection is what makes the statement dual-key — `enc_amount`
        // (E-1) / `receiver_delta` (E-2) must be well-formed under the RECIPIENT key.
        let (key_a, key_b) = if shape.recipient_ct[j] {
            (AUX_A_R, AUX_B_R)
        } else {
            (AUX_A_S, AUX_B_S)
        };
        let ab = aux_base(j);

        // c1(z) = a(z)·r(z) + e1(z) − (z^n + 1)·k1(z)
        let eq1 = s(key_a) * s(ab + AOFF_R) + s(ab + AOFF_E1)
            - s(ab + AOFF_C1)
            - zn1.clone() * s(ab + AOFF_K1);
        builder.when_first_row().assert_zero_ext(eq1);

        // c2(z) = b(z)·r(z) + e2(z) + Δ·m(z) − (z^n + 1)·k2(z)
        let eq2 = s(key_b) * s(ab + AOFF_R)
            + s(ab + AOFF_E2)
            + s(ab + AOFF_M) * AB::Expr::from(delta_scale)
            - s(ab + AOFF_C2)
            - zn1.clone() * s(ab + AOFF_K2);
        builder.when_first_row().assert_zero_ext(eq2);
    }
}

// ---------------------------------------------------------------------------
// E-1: DualKeyTransferAir (channelTxZKP)
// ---------------------------------------------------------------------------

/// AIR for one E-1 channel transfer: `before`/`after` well-formed under the sender key,
/// `enc_amount` well-formed under the recipient key, `before = after + amount` over the
/// integers (ripple carry, no underflow).
#[derive(Clone, Debug)]
pub struct DualKeyTransferAir<Fld> {
    pub n: usize,
    pub delta_scale: Fld,
}

impl<Fld: Field> DualKeyTransferAir<Fld> {
    pub fn new(n: usize, delta_scale: Fld) -> Self {
        assert!(n.is_power_of_two());
        Self { n, delta_scale }
    }
}

impl<Fld: Field> BaseAir<Fld> for DualKeyTransferAir<Fld> {
    fn width(&self) -> usize {
        E1_SHAPE.num_cols()
    }

    fn num_public_values(&self) -> usize {
        E1_SHAPE.num_public_values(self.n, 0)
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![E1_SHAPE.carry_col()]
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
    }
}

impl<Fld: Field> LookupAir<Fld> for DualKeyTransferAir<Fld> {
    fn get_lookups(&mut self) -> Vec<Lookup<Fld>> {
        dual_key_lookups(&E1_SHAPE)
    }
}

impl<AB> Air<AB> for DualKeyTransferAir<AB::F>
where
    AB: PermutationAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        eval_dual_key(builder, self.n, self.delta_scale, &E1_SHAPE);
    }
}

// ---------------------------------------------------------------------------
// E-2: ChannelUpdateAir (channelUpdateZKP)
// ---------------------------------------------------------------------------

/// AIR for one E-2 channel update: `before`/`after`/`sender_delta` well-formed under the sender
/// key, `receiver_delta` well-formed under the recipient key, `before = after + sender_delta`
/// (ripple carry), and both deltas' message evaluations published so the verifier can pin them
/// to the public amount.
#[derive(Clone, Debug)]
pub struct ChannelUpdateAir<Fld> {
    pub n: usize,
    pub delta_scale: Fld,
}

impl<Fld: Field> ChannelUpdateAir<Fld> {
    pub fn new(n: usize, delta_scale: Fld) -> Self {
        assert!(n.is_power_of_two());
        Self { n, delta_scale }
    }
}

impl<Fld: Field> BaseAir<Fld> for ChannelUpdateAir<Fld> {
    fn width(&self) -> usize {
        E2_SHAPE.num_cols()
    }

    fn num_public_values(&self) -> usize {
        E2_SHAPE.num_public_values(self.n, E2_NUM_EXTRA_PVS)
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![E2_SHAPE.carry_col()]
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
    }
}

impl<Fld: Field> LookupAir<Fld> for ChannelUpdateAir<Fld> {
    fn get_lookups(&mut self) -> Vec<Lookup<Fld>> {
        dual_key_lookups(&E2_SHAPE)
    }
}

impl<AB> Air<AB> for ChannelUpdateAir<AB::F>
where
    AB: PermutationAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        eval_dual_key(builder, self.n, self.delta_scale, &E2_SHAPE);
    }
}

// ---------------------------------------------------------------------------
// Trace and public-value construction
// ---------------------------------------------------------------------------

/// Build the trace of one dual-key instance. The caller has already validated the witnesses
/// (`check_amount_witness` + conservation), so the asserts here are unreachable defense.
fn generate_dual_key_trace(
    shape: &AirShape,
    sender_pk: &UpstreamPublicKey,
    recipient_pk: &UpstreamPublicKey,
    cts: &[&UpstreamCiphertext],
    wits: &[&EncryptionWitness],
) -> RowMajorMatrix<F> {
    let n = sender_pk.a.len();
    let width = shape.num_cols();
    let mut values = F::zero_vec(n * width);
    for i in 0..n {
        let row = &mut values[i * width..(i + 1) * width];
        row[COL_A_S] = sender_pk.a[i];
        row[COL_B_S] = sender_pk.b[i];
        row[COL_A_R] = recipient_pk.a[i];
        row[COL_B_R] = recipient_pk.b[i];
        for (j, (ct, w)) in cts.iter().zip(wits).enumerate() {
            let base = ct_base(j);
            row[base + OFF_C1] = ct.c1[i];
            row[base + OFF_C2] = ct.c2[i];
            row[base + OFF_R] = centered_to_field(w.r[i] as i64);
            row[base + OFF_E1U] = F::from_u8(w.e1u[i]);
            row[base + OFF_E1V] = F::from_u8(w.e1v[i]);
            row[base + OFF_E2U] = F::from_u8(w.e2u[i]);
            row[base + OFF_E2V] = F::from_u8(w.e2v[i]);
            row[base + OFF_M] = F::from_u8(w.m[i]);
            row[base + OFF_K1] = w.k1[i];
            row[base + OFF_K2] = w.k2[i];
        }
    }

    // Ripple-carry chain for before = after + delta over the shape's roles.
    let (wb, wd, wa) = (
        wits[shape.carry_before],
        wits[shape.carry_delta],
        wits[shape.carry_after],
    );
    let carry_col = shape.carry_col();
    let mut carry = 0u8;
    for i in 0..n {
        values[i * width + carry_col] = F::from_u8(carry);
        let sum = wa.m[i] + wd.m[i] + carry;
        let out = sum as i16 - wb.m[i] as i16;
        assert!(
            out == 0 || out == 2,
            "dual-key witness inconsistent at bit {i}: before != after + delta"
        );
        carry = (out / 2) as u8;
    }
    assert_eq!(
        carry, 0,
        "dual-key witness inconsistent: after + delta overflows n bits"
    );

    RowMajorMatrix::new(values, width)
}

/// Public values of one dual-key instance:
/// `[domain] ++ extra ++ a_s ++ b_s ++ a_r ++ b_r ++ (c1, c2)×num_cts`.
///
/// SECURITY: the purpose domain word comes first and `extra` (the E-2 amount limbs) directly
/// after, so every transcript absorbs the purpose and the full public statement before any
/// challenge is sampled (see module docs, F2-A/F2-B).
fn dual_key_public_values(
    domain: u32,
    extra: &[F],
    sender_pk: &UpstreamPublicKey,
    recipient_pk: &UpstreamPublicKey,
    cts: &[&UpstreamCiphertext],
) -> Vec<F> {
    let n = sender_pk.a.len();
    let mut pv = Vec::with_capacity(1 + extra.len() + (NUM_KEY_COLS + 2 * cts.len()) * n);
    pv.push(F::from_u32(domain));
    pv.extend_from_slice(extra);
    pv.extend_from_slice(&sender_pk.a);
    pv.extend_from_slice(&sender_pk.b);
    pv.extend_from_slice(&recipient_pk.a);
    pv.extend_from_slice(&recipient_pk.b);
    for ct in cts {
        pv.extend_from_slice(&ct.c1);
        pv.extend_from_slice(&ct.c2);
    }
    pv
}

/// The public amount as four 16-bit limbs (little-endian).
///
/// SECURITY: limbs must be injective as field elements; 16-bit limbs are < q (a u32 limb could
/// alias `limb` and `limb − q` after the implicit mod-q reduction of `F::from_u32`). The
/// definitive amount binding is the m(z) recomputation in `verify_channel_update`; this
/// absorption is defense in depth.
fn amount_limbs(amount: u64) -> [F; E2_NUM_EXTRA_PVS] {
    core::array::from_fn(|k| F::from_u32(((amount >> (16 * k)) & 0xffff) as u32))
}

// ---------------------------------------------------------------------------
// Witness validation (prove-side)
// ---------------------------------------------------------------------------

/// Full prove-side consistency check of one `(pk, ct, witness)` triple: shapes, smallness
/// ranges, message encoding, and BOTH ring identities over `Z_q[x]` at every coefficient
/// (degree < 2n, including the quotients `k1`, `k2`). A witness passing this check yields a
/// trace satisfying all AIR constraints, so `prove` never produces an unverifiable proof and
/// never panics inside trace generation.
fn check_amount_witness(
    pk: &UpstreamPublicKey,
    ct: &UpstreamCiphertext,
    aw: &AmountWitness,
    label: &str,
) -> Result<(), RegevError> {
    let n = REGEV_N;
    let w = &aw.witness;

    for (name, len) in [
        ("r", w.r.len()),
        ("e1u", w.e1u.len()),
        ("e1v", w.e1v.len()),
        ("e2u", w.e2u.len()),
        ("e2v", w.e2v.len()),
        ("m", w.m.len()),
        ("k1", w.k1.len()),
        ("k2", w.k2.len()),
    ] {
        if len != n {
            return Err(RegevError::InvalidWitness(format!(
                "{label}: witness vector `{name}` has length {len}, expected {n}"
            )));
        }
    }
    if w.r.iter().any(|&x| !(-1..=1).contains(&x)) {
        return Err(RegevError::InvalidWitness(format!(
            "{label}: r is not ternary"
        )));
    }
    if [&w.e1u, &w.e1v, &w.e2u, &w.e2v]
        .iter()
        .any(|h| h.iter().any(|&x| x > 2))
    {
        return Err(RegevError::InvalidWitness(format!(
            "{label}: CBD noise half out of range [0, 2]"
        )));
    }
    if w.m != encode_amount(aw.amount) {
        return Err(RegevError::InvalidWitness(format!(
            "{label}: message bits do not encode the claimed amount {}",
            aw.amount
        )));
    }

    let params = channel_regev_params();
    let delta = F::from_u32(params.delta());
    let r: Vec<F> = w.r.iter().map(|&x| centered_to_field(x as i64)).collect();
    let e1: Vec<F> = w
        .e1u
        .iter()
        .zip(&w.e1v)
        .map(|(&u, &v)| F::from_u8(u) - F::from_u8(v))
        .collect();
    let e2: Vec<F> = w
        .e2u
        .iter()
        .zip(&w.e2v)
        .map(|(&u, &v)| F::from_u8(u) - F::from_u8(v))
        .collect();
    let dm: Vec<F> = w.m.iter().map(|&b| delta * F::from_u8(b)).collect();

    // c1 + (x^n + 1)·k1 = a·r + e1  over Z_q[x] (full degree-<2n comparison).
    if !ring_identity_holds(&pk.a, &r, &e1, &ct.c1, &w.k1) {
        return Err(RegevError::InvalidWitness(format!(
            "{label}: c1 ring identity does not hold for the supplied witness"
        )));
    }
    // c2 + (x^n + 1)·k2 = b·r + e2 + Δ·m.
    let e2_dm: Vec<F> = e2.iter().zip(&dm).map(|(&x, &y)| x + y).collect();
    if !ring_identity_holds(&pk.b, &r, &e2_dm, &ct.c2, &w.k2) {
        return Err(RegevError::InvalidWitness(format!(
            "{label}: c2 ring identity does not hold for the supplied witness"
        )));
    }
    Ok(())
}

/// Checks `key·r + addend == ct + (x^n + 1)·k` coefficient-wise over `Z_q[x]`, degree < 2n.
/// Schoolbook O(n²) — n = 128, negligible next to proving.
fn ring_identity_holds(key: &[F], r: &[F], addend: &[F], ct: &[F], k: &[F]) -> bool {
    let n = key.len();
    let mut lhs = F::zero_vec(2 * n);
    for i in 0..n {
        for j in 0..n {
            lhs[i + j] += key[i] * r[j];
        }
    }
    for i in 0..n {
        lhs[i] += addend[i];
    }
    let mut rhs = F::zero_vec(2 * n);
    for i in 0..n {
        rhs[i] = ct[i] + k[i];
        rhs[n + i] += k[i];
    }
    lhs == rhs
}

// ---------------------------------------------------------------------------
// Generic single-instance prove/verify plumbing
// ---------------------------------------------------------------------------

fn prove_one<A>(
    config: &RegevStarkConfig,
    air: &A,
    trace: &RowMajorMatrix<F>,
    public_values: Vec<F>,
) -> Result<Vec<u8>, RegevError>
where
    A: Clone
        + LookupAir<F>
        + Air<SymbolicAirBuilder<F, Challenge>>
        + for<'a> Air<ProverConstraintFolderWithLookups<'a, RegevStarkConfig>>
        + for<'a> Air<DebugConstraintBuilder<'a, F, Challenge>>,
{
    regev_plonky3::init_thread_pool();
    let lookups = air.clone().get_lookups();
    let instances = vec![StarkInstance {
        air,
        trace,
        public_values,
        lookups,
    }];
    let prover_data = ProverData::from_instances(config, &instances);
    let proof = stark::prove_batch(config, &instances, &prover_data);
    postcard::to_allocvec(&proof).map_err(|e| RegevError::ProofCodec(e.to_string()))
}

/// Deserializes and verifies one dual-key instance; on success returns the shared evaluation
/// challenge `z` and the proof (for the published-evaluation comparison).
///
/// Shape checks (`degree_bits`, published-evaluation count) run BEFORE `verify_batch` so an
/// adversarial proof cannot reach huge-domain construction or out-of-bounds indexing.
fn verify_one<A>(
    config: &RegevStarkConfig,
    mut air: A,
    proof_bytes: &[u8],
    public_values: Vec<F>,
    num_published: usize,
) -> Result<(Challenge, BatchProof<RegevStarkConfig>), RegevError>
where
    A: Clone
        + LookupAir<F>
        + Air<SymbolicAirBuilder<F, Challenge>>
        + for<'a> Air<VerifierConstraintFolderWithLookups<'a, RegevStarkConfig>>,
{
    regev_plonky3::init_thread_pool();
    let proof: BatchProof<RegevStarkConfig> =
        postcard::from_bytes(proof_bytes).map_err(|e| RegevError::ProofCodec(e.to_string()))?;

    // SECURITY: the Horner argument identifies "the polynomial" with "the trace column", so the
    // trace height must equal the ring dimension; reject before building any FRI domain.
    let params = channel_regev_params();
    let expected_db = params.log_n() + config.is_zk();
    if proof.degree_bits.len() != 1 || proof.degree_bits[0] != expected_db {
        return Err(RegevError::ProofVerification(
            "proof shape: expected one instance with trace height == ring dimension".to_string(),
        ));
    }
    if proof.global_lookup_data.len() != 1 || proof.global_lookup_data[0].len() != num_published {
        return Err(RegevError::ProofVerification(format!(
            "proof shape: expected {num_published} published evaluations"
        )));
    }

    let lookups = air.get_lookups();
    let airs = vec![air];
    let common = CommonData::new(None, vec![lookups]);
    let pvs = vec![public_values];

    let challenges = stark::verify_batch(config, &airs, &proof, &pvs, &common)
        .map_err(|e| RegevError::ProofVerification(format!("{e:?}")))?;
    let z = challenges[0][0];
    Ok((z, proof))
}

// ---------------------------------------------------------------------------
// STEP 0 PoC: bare Poseidon2-BabyBear permutation through the batch-stark backend
// ---------------------------------------------------------------------------

/// Prove a bare Poseidon2-BabyBear permutation trace (no public values) through the regev
/// `test_config()` batch-stark backend. Used by the P3 de-risk PoC only.
pub fn prove_poseidon2_poc(
    trace: &RowMajorMatrix<F>,
) -> Result<Vec<u8>, RegevError> {
    let air = super::hash_sig::NoLookupPoseidon2Air::new();
    prove_one(&test_config(), &air, trace, Vec::new())
}

/// Verify a PoC Poseidon2 permutation proof. The shape check inside `verify_one` is specific to
/// the dual-key AIRs, so this PoC path calls `verify_batch` directly via a minimal helper.
pub fn verify_poseidon2_poc(proof_bytes: &[u8]) -> Result<(), RegevError> {
    regev_plonky3::init_thread_pool();
    let mut air = super::hash_sig::NoLookupPoseidon2Air::new();
    let proof: BatchProof<RegevStarkConfig> =
        postcard::from_bytes(proof_bytes).map_err(|e| RegevError::ProofCodec(e.to_string()))?;
    let lookups = air.get_lookups();
    let airs = vec![air];
    let common = CommonData::new(None, vec![lookups]);
    let pvs: Vec<Vec<F>> = vec![Vec::new()];
    stark::verify_batch(&test_config(), &airs, &proof, &pvs, &common)
        .map_err(|e| RegevError::ProofVerification(format!("{e:?}")))?;
    Ok(())
}

/// Horner evaluation of a base-field coefficient vector at the extension-field point `z`.
fn eval_at(coeffs: impl DoubleEndedIterator<Item = F>, z: Challenge) -> Challenge {
    coeffs
        .rev()
        .fold(Challenge::ZERO, |acc, c| acc * z + Challenge::from(c))
}

/// The expected published evaluations in lookup order: `a_s, b_s, a_r, b_r`, then per
/// ciphertext `c1, c2` and — where `shape.expose_m[j]` — the message polynomial, which for the
/// exposed E-2 deltas is `encode_amount(amount)`.
fn expected_published_evals(
    shape: &AirShape,
    sender_pk: &UpstreamPublicKey,
    recipient_pk: &UpstreamPublicKey,
    cts: &[&UpstreamCiphertext],
    exposed_m: Option<&[F]>,
    z: Challenge,
) -> Vec<Challenge> {
    let ev = |coeffs: &[F]| eval_at(coeffs.iter().copied(), z);
    let mut expected = vec![
        ev(&sender_pk.a),
        ev(&sender_pk.b),
        ev(&recipient_pk.a),
        ev(&recipient_pk.b),
    ];
    for (j, ct) in cts.iter().enumerate() {
        expected.push(ev(&ct.c1));
        expected.push(ev(&ct.c2));
        if shape.expose_m[j] {
            expected.push(ev(
                exposed_m.expect("shape exposes m but no public message supplied")
            ));
        }
    }
    expected
}

/// Outer binding: compare the proof's published evaluations against the statement, positionally
/// (the j-th published value is pinned in-circuit to the j-th global lookup's running
/// evaluation, so positional matching is sound — same argument as upstream `verify_transfers`).
fn check_published_evals(
    proof: &BatchProof<RegevStarkConfig>,
    expected: &[Challenge],
) -> Result<(), RegevError> {
    let data = &proof.global_lookup_data[0];
    debug_assert_eq!(data.len(), expected.len(), "checked in verify_one");
    for (j, want) in expected.iter().enumerate() {
        if data[j].expected_cumulated != *want {
            return Err(RegevError::ProofVerification(format!(
                "published evaluation {j} does not match the claimed statement"
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// E-1 prove / verify
// ---------------------------------------------------------------------------

/// Prove E-1 channelTxZKP (detail2 §E-1): `before`/`after` well-formed under `sender_pk`,
/// `enc_amount` well-formed under `recipient_pk`, and `before = after + amount` over the
/// integers. Refuses (no panic) if any witness is inconsistent with its ciphertext or the
/// conservation law is violated (including `before < amount`).
pub fn prove_channel_tx(
    level: RegevSecurityLevel,
    sender_pk: &RegevPk,
    recipient_pk: &RegevPk,
    before: (&RegevCiphertext, &AmountWitness),
    enc_amount: (&RegevCiphertext, &AmountWitness),
    after: (&RegevCiphertext, &AmountWitness),
) -> Result<Vec<u8>, RegevError> {
    prove_dual_key_transfer(
        level,
        CHANNEL_TX_ZKP_DOMAIN,
        sender_pk,
        recipient_pk,
        before,
        enc_amount,
        after,
    )
}

/// Domain-parameterized E-1 prover. Private: only `prove_channel_tx` (and the purpose-binding
/// adversarial test) call this.
fn prove_dual_key_transfer(
    level: RegevSecurityLevel,
    domain: u32,
    sender_pk: &RegevPk,
    recipient_pk: &RegevPk,
    before: (&RegevCiphertext, &AmountWitness),
    enc_amount: (&RegevCiphertext, &AmountWitness),
    after: (&RegevCiphertext, &AmountWitness),
) -> Result<Vec<u8>, RegevError> {
    let spk = to_upstream_pk(sender_pk)?;
    let rpk = to_upstream_pk(recipient_pk)?;
    let cts = [
        to_upstream_ct(before.0)?,
        to_upstream_ct(enc_amount.0)?,
        to_upstream_ct(after.0)?,
    ];

    check_amount_witness(&spk, &cts[0], before.1, "before")?;
    check_amount_witness(&rpk, &cts[1], enc_amount.1, "enc_amount")?;
    check_amount_witness(&spk, &cts[2], after.1, "after")?;

    // Conservation over u64 — equivalent to the in-circuit 128-bit ripple carry because each
    // message vector equals encode_amount(u64) (checked above; bits 64..128 are zero).
    match after.1.amount.checked_add(enc_amount.1.amount) {
        Some(sum) if sum == before.1.amount => {}
        _ => {
            return Err(RegevError::InvalidWitness(format!(
                "conservation violated: before ({}) != after ({}) + amount ({})",
                before.1.amount, after.1.amount, enc_amount.1.amount
            )));
        }
    }

    let params = channel_regev_params();
    let air = DualKeyTransferAir::new(REGEV_N, F::from_u32(params.delta()));
    let ct_refs = [&cts[0], &cts[1], &cts[2]];
    let trace = generate_dual_key_trace(
        &E1_SHAPE,
        &spk,
        &rpk,
        &ct_refs,
        &[&before.1.witness, &enc_amount.1.witness, &after.1.witness],
    );
    let pvs = dual_key_public_values(domain, &[], &spk, &rpk, &ct_refs);
    prove_one(&level.config(), &air, &trace, pvs)
}

/// Verify E-1 channelTxZKP against the claimed statement. Validates all keys and ciphertexts
/// canonically BEFORE touching the proof bytes.
pub fn verify_channel_tx(
    level: RegevSecurityLevel,
    sender_pk: &RegevPk,
    recipient_pk: &RegevPk,
    before: &RegevCiphertext,
    enc_amount: &RegevCiphertext,
    after: &RegevCiphertext,
    proof: &[u8],
) -> Result<(), RegevError> {
    // Canonicality first: a non-canonical statement is rejected before any proof work.
    let spk = to_upstream_pk(sender_pk)?;
    let rpk = to_upstream_pk(recipient_pk)?;
    let cts = [
        to_upstream_ct(before)?,
        to_upstream_ct(enc_amount)?,
        to_upstream_ct(after)?,
    ];
    let ct_refs = [&cts[0], &cts[1], &cts[2]];

    let config = level.config();
    let params = channel_regev_params();
    let air = DualKeyTransferAir::new(REGEV_N, F::from_u32(params.delta()));
    // SECURITY: the verifier rebuilds the public values itself, with ITS purpose domain word —
    // a proof generated for any other purpose diverges the transcript and fails (F2-B).
    let pvs = dual_key_public_values(CHANNEL_TX_ZKP_DOMAIN, &[], &spk, &rpk, &ct_refs);
    let (z, proof) = verify_one(&config, air, proof, pvs, E1_SHAPE.num_published_evals())?;

    let expected = expected_published_evals(&E1_SHAPE, &spk, &rpk, &ct_refs, None, z);
    check_published_evals(&proof, &expected)
}

// ---------------------------------------------------------------------------
// E-2 prove / verify
// ---------------------------------------------------------------------------

/// Prove E-2 channelUpdateZKP (detail2 §E-2): `before`/`after`/`sender_delta` well-formed under
/// `sender_pk`, `receiver_delta` well-formed under `recipient_pk`, `before = after + amount`,
/// and both deltas encrypt exactly the public `amount`.
#[allow(clippy::too_many_arguments)]
pub fn prove_channel_update(
    level: RegevSecurityLevel,
    sender_pk: &RegevPk,
    recipient_pk: &RegevPk,
    before: (&RegevCiphertext, &AmountWitness),
    after: (&RegevCiphertext, &AmountWitness),
    sender_delta: (&RegevCiphertext, &AmountWitness),
    receiver_delta: (&RegevCiphertext, &AmountWitness),
    amount: u64,
) -> Result<Vec<u8>, RegevError> {
    let spk = to_upstream_pk(sender_pk)?;
    let rpk = to_upstream_pk(recipient_pk)?;
    let cts = [
        to_upstream_ct(before.0)?,
        to_upstream_ct(after.0)?,
        to_upstream_ct(sender_delta.0)?,
        to_upstream_ct(receiver_delta.0)?,
    ];

    check_amount_witness(&spk, &cts[0], before.1, "before")?;
    check_amount_witness(&spk, &cts[1], after.1, "after")?;
    check_amount_witness(&spk, &cts[2], sender_delta.1, "sender_delta")?;
    check_amount_witness(&rpk, &cts[3], receiver_delta.1, "receiver_delta")?;

    // Both deltas must encrypt exactly the public amount.
    if sender_delta.1.amount != amount || receiver_delta.1.amount != amount {
        return Err(RegevError::InvalidWitness(format!(
            "delta plaintexts (sender {}, receiver {}) do not match the public amount {amount}",
            sender_delta.1.amount, receiver_delta.1.amount
        )));
    }
    match after.1.amount.checked_add(amount) {
        Some(sum) if sum == before.1.amount => {}
        _ => {
            return Err(RegevError::InvalidWitness(format!(
                "conservation violated: before ({}) != after ({}) + amount ({amount})",
                before.1.amount, after.1.amount
            )));
        }
    }

    let params = channel_regev_params();
    let air = ChannelUpdateAir::new(REGEV_N, F::from_u32(params.delta()));
    let ct_refs = [&cts[0], &cts[1], &cts[2], &cts[3]];
    let trace = generate_dual_key_trace(
        &E2_SHAPE,
        &spk,
        &rpk,
        &ct_refs,
        &[
            &before.1.witness,
            &after.1.witness,
            &sender_delta.1.witness,
            &receiver_delta.1.witness,
        ],
    );
    let pvs = dual_key_public_values(
        CHANNEL_UPDATE_ZKP_DOMAIN,
        &amount_limbs(amount),
        &spk,
        &rpk,
        &ct_refs,
    );
    prove_one(&level.config(), &air, &trace, pvs)
}

/// Verify E-2 channelUpdateZKP against the claimed statement (including the public `amount`).
/// Validates all keys and ciphertexts canonically BEFORE touching the proof bytes.
#[allow(clippy::too_many_arguments)]
pub fn verify_channel_update(
    level: RegevSecurityLevel,
    sender_pk: &RegevPk,
    recipient_pk: &RegevPk,
    before: &RegevCiphertext,
    after: &RegevCiphertext,
    sender_delta: &RegevCiphertext,
    receiver_delta: &RegevCiphertext,
    amount: u64,
    proof: &[u8],
) -> Result<(), RegevError> {
    let spk = to_upstream_pk(sender_pk)?;
    let rpk = to_upstream_pk(recipient_pk)?;
    let cts = [
        to_upstream_ct(before)?,
        to_upstream_ct(after)?,
        to_upstream_ct(sender_delta)?,
        to_upstream_ct(receiver_delta)?,
    ];
    let ct_refs = [&cts[0], &cts[1], &cts[2], &cts[3]];

    let config = level.config();
    let params = channel_regev_params();
    let air = ChannelUpdateAir::new(REGEV_N, F::from_u32(params.delta()));
    let pvs = dual_key_public_values(
        CHANNEL_UPDATE_ZKP_DOMAIN,
        &amount_limbs(amount),
        &spk,
        &rpk,
        &ct_refs,
    );
    let (z, proof) = verify_one(&config, air, proof, pvs, E2_SHAPE.num_published_evals())?;

    // SECURITY (F2-C): pin both deltas' committed message polynomials to the public amount by
    // recomputing eval(encode_amount(amount), z) — see module docs for the soundness argument.
    let m_pub: Vec<F> = encode_amount(amount)
        .iter()
        .map(|&b| F::from_u8(b))
        .collect();
    let expected = expected_published_evals(&E2_SHAPE, &spk, &rpk, &ct_refs, Some(&m_pub), z);
    check_published_evals(&proof, &expected)
}

// ---------------------------------------------------------------------------
// Decryption core (shared by E-3 DecryptionAir and the BalanceRefresh RefreshAir)
// ---------------------------------------------------------------------------
//
// The core proves, for a public key `(a, b)` and a ciphertext `(c1, c2)` (all four public
// polynomials, evaluations published and recomputed by the verifier):
//
//   (1) Key binding at z:    b(z) = a(z)·s(z) + e_pk(z) − (z^n+1)·k_pk(z)
//                            with s ternary and e_pk = e_pk_u − e_pk_v, halves CBD(2)-ranged
//                            (exactly upstream keygen's `b = a·s + e` with `e = u − v`,
//                            `u, v ∈ {0,1,2}`).
//   (2) Decryption at z:     v(z) = c2(z) − c1(z)·s(z) + (z^n+1)·k_v(z)
//                            where `v` is a committed witness column (the canonical
//                            representative of `c2 − c1·s mod (x^n+1)`) and `k_v` the quotient
//                            of `c1·s`. Both identities are between polynomials of degree < 2n,
//                            so agreement at the post-commitment challenge `z` pins them with
//                            Schwartz-Zippel error < 2n/|EF| (same argument as the E-1/E-2 ring
//                            identities).
//   (3) Digit extraction:    per row, over the base field (i.e. mod q):
//                                v_i + Δ/2 = Δ·d_i + ns_i
//                            with d_i ∈ [0, 256) (8 boolean bit columns) and
//                            ns_i ∈ [0, Δ) the SHIFTED centered noise (ns = noise + Δ/2,
//                            noise ∈ [−Δ/2, Δ/2)).
//   (4) Normalization adder: per row, d_i + c_i = bit_i + 2·c_{i+1}, c_0 = 0, final carry 0 —
//                            binds Σ d_i·2^i == Σ bit_i·2^i over the integers, where `bit` is a
//                            boolean column holding the value's binary encoding (public and
//                            pinned to `encode_amount(amount)` for E-3; private and reused as
//                            the fresh-encryption message for the refresh).
//
// # Rounding convention and uniqueness/no-wrap analysis (constraint 3)
//
// Δ = floor(q/256) = 7_864_320 = 15·2^19, and q = 256·Δ + 1 (BabyBear). The decomposition is a
// FIELD equation mod q, which is exactly what makes negative noise on digit 0 work: the
// canonical `v` then sits near q and the equation wraps. Soundness rests on uniqueness mod q:
// if (d, ns) and (d', ns') both satisfy (3) for the same v, then
// Δ·(d−d') + (ns−ns') ≡ 0 (mod q) with |Δ·(d−d') + (ns−ns')| ≤ 255·Δ + (Δ−1) = 256·Δ − 1
// = q − 2 < q, so the difference is exactly 0 and Δ·(d−d') = ns'−ns with |ns'−ns| < Δ forces
// d = d', ns = ns'. The range ns ∈ [0, Δ) is therefore load-bearing: a plain 23-bit
// decomposition (range [0, 2^23) ⊋ [0, Δ)) would allow 255·Δ + 2^23 > q and an adversary could
// alias digit 0 as digit 255. We get the exact range from Δ = 15·2^19:
// ns = lo + (u + v)·2^19 with lo a 19-bit value and u, v two 3-bit values, so
// ns ≤ (2^19 − 1) + 14·2^19 = 15·2^19 − 1 = Δ − 1, and every ns ∈ [0, Δ) is reachable.
//
// Upstream `decrypt` rounds `digit = round(v·t/q) mod t`, whose digit boundaries sit at
// Δ·d − Δ/2 + d/256 — offset by < 1 from this core's boundaries at Δ·d − Δ/2. The two
// conventions agree everywhere except when the accumulated noise lands EXACTLY on a boundary
// (|noise| = Δ/2 ≈ 2^21.9), which is unreachable within the enforced noise budget
// (worst case after MAX_HOMO_ADDS_BEFORE_REFRESH = 64 additions: 64·514 ≈ 2^15, see
// `params.rs`); the prover still re-derives the value from the circuit's own decomposition and
// refuses if it disagrees with the claimed amount.
//
// # Carry-bound analysis (constraint 4)
//
// c_{i+1} = (d_i + c_i − bit_i)/2 with c_0 = 0, d_i ≤ 255, bit_i ∈ {0,1}. By induction
// c_i ≤ 254 ⇒ c_{i+1} ≤ floor((255 + 254)/2) = 254, so 254 is the exact fixed bound, and
// carries CAN exceed 127 for digits near 255 (c_2 can reach 191), so 8 boolean carry columns
// are required and sufficient. (Protocol digits stay ≤ 64, but the circuit must be sound for
// ANY d < 256 an adversarial prover commits.)

/// Message scaling factor `Δ = floor(q / 2^REGEV_PLAIN_BITS)` and its half, as plain u32
/// (compile-time checked against the upstream parameter set).
const DELTA_U32: u32 = REGEV_Q >> REGEV_PLAIN_BITS;
const HALF_DELTA_U32: u32 = DELTA_U32 / 2;

/// Bits of the per-row digit (`d ∈ [0, 2^REGEV_PLAIN_BITS)`).
const DIGIT_BITS: usize = REGEV_PLAIN_BITS;
/// Bits of the low limb of the shifted-noise decomposition.
const NOISE_LO_BITS: usize = 19;
/// Bits of each of the two high-limb halves (`u, v ∈ [0, 7]`, `u + v ∈ [0, 14]`).
const NOISE_HI_HALF_BITS: usize = 3;
/// Bits of the normalization carry (tight bound 254, see the carry-bound analysis above).
const CARRY_BITS: usize = 8;

// SECURITY: the whole digit-extraction soundness argument is arithmetic on these exact values;
// pin them at compile time so a parameter change cannot silently invalidate it.
const _: () = {
    assert!(DELTA_U32 == 7_864_320);
    assert!(DELTA_U32 % 2 == 0);
    // q = 256·Δ + 1 — the no-wrap bound 255·Δ + (Δ − 1) = q − 2 < q.
    assert!(256 * (DELTA_U32 as u64) + 1 == REGEV_Q as u64);
    // Δ = 15·2^19 — the shifted-noise decomposition covers exactly [0, Δ).
    assert!(DELTA_U32 as u64 == 15 << NOISE_LO_BITS);
    assert!((1 << NOISE_LO_BITS) - 1 + 14 * (1 << NOISE_LO_BITS) == DELTA_U32 as u64 - 1);
};

// Decryption-core main columns (shared layout; `RefreshAir` appends encryption columns).
const DEC_A: usize = 0;
const DEC_B: usize = 1;
const DEC_C1: usize = 2;
const DEC_C2: usize = 3;
const DEC_S: usize = 4;
const DEC_EPK_U: usize = 5;
const DEC_EPK_V: usize = 6;
const DEC_K_PK: usize = 7;
const DEC_V: usize = 8;
const DEC_K_V: usize = 9;
const DEC_D_BITS: usize = 10;
const DEC_NOISE_LO: usize = DEC_D_BITS + DIGIT_BITS;
const DEC_NOISE_U: usize = DEC_NOISE_LO + NOISE_LO_BITS;
const DEC_NOISE_V: usize = DEC_NOISE_U + NOISE_HI_HALF_BITS;
const DEC_BIT: usize = DEC_NOISE_V + NOISE_HI_HALF_BITS;
const DEC_CARRY: usize = DEC_BIT + 1;
const DEC_CORE_COLS: usize = DEC_CARRY + CARRY_BITS;

// RefreshAir extra main columns: the fresh ciphertext and its encryption witness (message
// column intentionally ABSENT — the core's `DEC_BIT` column is the message).
const RF_C1_NEW: usize = DEC_CORE_COLS;
const RF_C2_NEW: usize = RF_C1_NEW + 1;
const RF_R: usize = RF_C2_NEW + 1;
const RF_E1U: usize = RF_R + 1;
const RF_E1V: usize = RF_E1U + 1;
const RF_E2U: usize = RF_E1V + 1;
const RF_E2V: usize = RF_E2U + 1;
const RF_K1: usize = RF_E2V + 1;
const RF_K2: usize = RF_K1 + 1;
const RF_COLS: usize = RF_K2 + 1;

// Aux (permutation) columns, in lookup order (= position in the spec lists below).
const DAUX_A: usize = 0;
const DAUX_B: usize = 1;
const DAUX_C1: usize = 2;
const DAUX_C2: usize = 3;
const DAUX_S: usize = 4;
const DAUX_EPK: usize = 5;
const DAUX_K_PK: usize = 6;
const DAUX_V: usize = 7;
const DAUX_K_V: usize = 8;
const DAUX_BIT: usize = 9;
const DEC_CORE_AUX: usize = 10;
const RFAUX_C1_NEW: usize = DEC_CORE_AUX;
const RFAUX_C2_NEW: usize = RFAUX_C1_NEW + 1;
const RFAUX_R: usize = RFAUX_C2_NEW + 1;
const RFAUX_E1: usize = RFAUX_R + 1;
const RFAUX_E2: usize = RFAUX_E1 + 1;
const RFAUX_K1: usize = RFAUX_E2 + 1;
const RFAUX_K2: usize = RFAUX_K1 + 1;

/// Published (`Kind::Global`) evaluations of E-3, in lookup order:
/// `a, b, c1, c2, amount-bits`.
const DEC_NUM_PUBLISHED: usize = 5;
/// Published evaluations of the refresh, in lookup order:
/// `a, b, c1_old, c2_old, c1_new, c2_new` — the bit column stays `Kind::Local` (see the privacy
/// note in the module docs).
const RF_NUM_PUBLISHED: usize = 6;

fn main_col_expr<Fld: Field>(c: usize) -> Vec<Vec<SymbolicExpression<Fld>>> {
    vec![vec![
        SymbolicVariable::<Fld>::new(BaseEntry::Main { offset: 0 }, c).into(),
    ]]
}

fn main_diff_expr<Fld: Field>(u: usize, v: usize) -> Vec<Vec<SymbolicExpression<Fld>>> {
    let var = |c: usize| SymbolicVariable::<Fld>::new(BaseEntry::Main { offset: 0 }, c);
    vec![vec![var(u) - var(v)]]
}

fn specs_to_lookups<Fld: Field>(
    specs: Vec<(Kind, Vec<Vec<SymbolicExpression<Fld>>>)>,
) -> Vec<Lookup<Fld>> {
    specs
        .into_iter()
        .enumerate()
        .map(|(aux, (kind, element_exprs))| Lookup {
            kind,
            element_exprs,
            multiplicities_exprs: vec![],
            columns: vec![aux],
        })
        .collect()
}

/// The decryption core's evaluation arguments. `expose_bit` selects whether the normalized bit
/// column's evaluation is published (E-3: yes, pinned to the public amount by the verifier) or
/// kept hidden (refresh: the bit column is the SECRET balance — publishing its evaluation would
/// be a plaintext-confirmation oracle, see the module docs).
fn decryption_core_lookup_specs<Fld: Field>(
    expose_bit: bool,
) -> Vec<(Kind, Vec<Vec<SymbolicExpression<Fld>>>)> {
    let bit_kind = if expose_bit {
        Kind::Global("eval:amount_bits".to_string())
    } else {
        Kind::Local
    };
    vec![
        (Kind::Global("eval:a".to_string()), main_col_expr(DEC_A)),
        (Kind::Global("eval:b".to_string()), main_col_expr(DEC_B)),
        (Kind::Global("eval:c1".to_string()), main_col_expr(DEC_C1)),
        (Kind::Global("eval:c2".to_string()), main_col_expr(DEC_C2)),
        (Kind::Local, main_col_expr(DEC_S)),
        (Kind::Local, main_diff_expr(DEC_EPK_U, DEC_EPK_V)),
        (Kind::Local, main_col_expr(DEC_K_PK)),
        (Kind::Local, main_col_expr(DEC_V)),
        (Kind::Local, main_col_expr(DEC_K_V)),
        (bit_kind, main_col_expr(DEC_BIT)),
    ]
}

fn refresh_lookup_specs<Fld: Field>() -> Vec<(Kind, Vec<Vec<SymbolicExpression<Fld>>>)> {
    let mut specs = decryption_core_lookup_specs(false);
    specs.extend([
        (
            Kind::Global("eval:c1_new".to_string()),
            main_col_expr(RF_C1_NEW),
        ),
        (
            Kind::Global("eval:c2_new".to_string()),
            main_col_expr(RF_C2_NEW),
        ),
        (Kind::Local, main_col_expr(RF_R)),
        (Kind::Local, main_diff_expr(RF_E1U, RF_E1V)),
        (Kind::Local, main_diff_expr(RF_E2U, RF_E2V)),
        (Kind::Local, main_col_expr(RF_K1)),
        (Kind::Local, main_col_expr(RF_K2)),
    ]);
    specs
}

/// `(z^n + 1)` from the shared evaluation challenge (n a power of two).
fn zn_plus_one<AB: PermutationAirBuilder>(builder: &mut AB, n: usize) -> AB::ExprEF {
    let z: AB::ExprEF = builder.permutation_randomness()[0].into();
    let mut zn = z;
    for _ in 0..n.trailing_zeros() {
        zn = zn.clone() * zn;
    }
    zn + AB::ExprEF::ONE
}

/// Constraint body of the decryption core (constraints (1)–(4) of the section header).
fn eval_decryption_core<AB>(builder: &mut AB, n: usize, delta: AB::F, half_delta: AB::F)
where
    AB: PermutationAirBuilder,
{
    let main = builder.main();
    let local: &[AB::Var] = main.current_slice();
    let next: &[AB::Var] = main.next_slice();

    // --- Smallness: s ternary, e_pk halves CBD(2) (upstream keygen encoding) ----------------
    let s_expr: AB::Expr = local[DEC_S].into();
    builder
        .assert_zero(s_expr.clone() * (s_expr.clone() - AB::Expr::ONE) * (s_expr + AB::Expr::ONE));
    for off in [DEC_EPK_U, DEC_EPK_V] {
        let x: AB::Expr = local[off].into();
        builder.assert_zero(x.clone() * (x.clone() - AB::Expr::ONE) * (x - AB::Expr::TWO));
    }

    // --- Booleanity of every bit column ------------------------------------------------------
    for c in (DEC_D_BITS..DEC_D_BITS + DIGIT_BITS)
        .chain(DEC_NOISE_LO..DEC_NOISE_LO + NOISE_LO_BITS)
        .chain(DEC_NOISE_U..DEC_NOISE_U + NOISE_HI_HALF_BITS)
        .chain(DEC_NOISE_V..DEC_NOISE_V + NOISE_HI_HALF_BITS)
        .chain([DEC_BIT])
        .chain(DEC_CARRY..DEC_CARRY + CARRY_BITS)
    {
        let x: AB::Expr = local[c].into();
        builder.assert_bool(x);
    }

    let pow2 = |j: usize| AB::Expr::from(AB::F::from_u32(1u32 << j));
    let wsum = |vars: &[AB::Var], base: usize, count: usize| -> AB::Expr {
        (0..count).fold(AB::Expr::ZERO, |acc, j| {
            acc + Into::<AB::Expr>::into(vars[base + j]) * pow2(j)
        })
    };

    let d_val = wsum(local, DEC_D_BITS, DIGIT_BITS);
    let noise_lo = wsum(local, DEC_NOISE_LO, NOISE_LO_BITS);
    let noise_u = wsum(local, DEC_NOISE_U, NOISE_HI_HALF_BITS);
    let noise_v = wsum(local, DEC_NOISE_V, NOISE_HI_HALF_BITS);
    // ns ∈ [0, Δ) exactly: lo + (u + v)·2^19 with u, v ∈ [0, 7], Δ = 15·2^19.
    let noise_shifted = noise_lo + (noise_u + noise_v) * pow2(NOISE_LO_BITS);
    let carry_val = wsum(local, DEC_CARRY, CARRY_BITS);
    let carry_next = wsum(next, DEC_CARRY, CARRY_BITS);
    let bit: AB::Expr = local[DEC_BIT].into();
    let v: AB::Expr = local[DEC_V].into();

    // --- (3) Digit extraction: v + Δ/2 = Δ·d + ns (mod q; uniqueness per the no-wrap analysis)
    builder.assert_zero(
        v + AB::Expr::from(half_delta) - d_val.clone() * AB::Expr::from(delta) - noise_shifted,
    );

    // --- (4) Digit→bit normalization adder: Σ d_i·2^i == Σ bit_i·2^i over the integers -------
    // SECURITY: the field equation implies the integer one because every term is range-checked
    // (d ≤ 255, c ≤ 255, bit ≤ 1 ⇒ |d + c − bit − 2c'| ≤ 511 < q), c_0 = 0 and the last-row
    // form forces the final carry to zero.
    builder.when_first_row().assert_zero(carry_val.clone());
    let lhs = d_val + carry_val - bit;
    builder
        .when_transition()
        .assert_zero(lhs.clone() - carry_next * AB::Expr::TWO);
    builder.when_last_row().assert_zero(lhs);

    // --- (1) + (2) Ring identities at the shared challenge z --------------------------------
    let zn1 = zn_plus_one::<AB>(builder, n);
    let perm = builder.permutation();
    let s = |aux: usize| -> AB::ExprEF {
        perm.current(aux)
            .expect("permutation trace too narrow")
            .into()
    };

    // Key binding: a(z)·s(z) + e_pk(z) = b(z) + (z^n + 1)·k_pk(z).
    let eq_key = s(DAUX_A) * s(DAUX_S) + s(DAUX_EPK) - s(DAUX_B) - zn1.clone() * s(DAUX_K_PK);
    builder.when_first_row().assert_zero_ext(eq_key);

    // Decryption: v(z) = c2(z) − c1(z)·s(z) + (z^n + 1)·k_v(z).
    let eq_dec = s(DAUX_C2) - s(DAUX_C1) * s(DAUX_S) + zn1 * s(DAUX_K_V) - s(DAUX_V);
    builder.when_first_row().assert_zero_ext(eq_dec);
}

/// Refresh-only constraints: `new_ct` is a fresh well-formed encryption of the core's
/// normalized bit column under the SAME key `(a, b)` — this in-circuit reuse of the bit column
/// IS the plaintext-equality link.
fn eval_refresh_encryption<AB>(builder: &mut AB, n: usize, delta: AB::F)
where
    AB: PermutationAirBuilder,
{
    let main = builder.main();
    let local: &[AB::Var] = main.current_slice();

    let r: AB::Expr = local[RF_R].into();
    builder.assert_zero(r.clone() * (r.clone() - AB::Expr::ONE) * (r + AB::Expr::ONE));
    for off in [RF_E1U, RF_E1V, RF_E2U, RF_E2V] {
        let x: AB::Expr = local[off].into();
        builder.assert_zero(x.clone() * (x.clone() - AB::Expr::ONE) * (x - AB::Expr::TWO));
    }

    let zn1 = zn_plus_one::<AB>(builder, n);
    let perm = builder.permutation();
    let s = |aux: usize| -> AB::ExprEF {
        perm.current(aux)
            .expect("permutation trace too narrow")
            .into()
    };

    // c1_new(z) = a(z)·r(z) + e1(z) − (z^n + 1)·k1(z).
    let eq1 = s(DAUX_A) * s(RFAUX_R) + s(RFAUX_E1) - s(RFAUX_C1_NEW) - zn1.clone() * s(RFAUX_K1);
    builder.when_first_row().assert_zero_ext(eq1);

    // c2_new(z) = b(z)·r(z) + e2(z) + Δ·m(z) − (z^n + 1)·k2(z), with m = the core's bit column.
    let eq2 = s(DAUX_B) * s(RFAUX_R) + s(RFAUX_E2) + s(DAUX_BIT) * AB::Expr::from(delta)
        - s(RFAUX_C2_NEW)
        - zn1 * s(RFAUX_K2);
    builder.when_first_row().assert_zero_ext(eq2);
}

// ---------------------------------------------------------------------------
// E-3: DecryptionAir (withdrawClaimZKP)
// ---------------------------------------------------------------------------

/// AIR for one E-3 withdraw claim: the public ciphertext decrypts, under the secret key bound to
/// the public `(a, b)`, to digits whose binary normalization equals the PUBLIC amount.
#[derive(Clone, Debug)]
pub struct DecryptionAir<Fld> {
    pub n: usize,
    delta: Fld,
    half_delta: Fld,
}

impl<Fld: Field> DecryptionAir<Fld> {
    pub fn new(n: usize) -> Self {
        assert!(n.is_power_of_two());
        Self {
            n,
            delta: Fld::from_u32(DELTA_U32),
            half_delta: Fld::from_u32(HALF_DELTA_U32),
        }
    }
}

impl<Fld: Field> BaseAir<Fld> for DecryptionAir<Fld> {
    fn width(&self) -> usize {
        DEC_CORE_COLS
    }

    fn num_public_values(&self) -> usize {
        // [domain] ++ amount limbs ++ a ++ b ++ c1 ++ c2.
        1 + E2_NUM_EXTRA_PVS + 4 * self.n
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        (DEC_CARRY..DEC_CARRY + CARRY_BITS).collect()
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
    }
}

impl<Fld: Field> LookupAir<Fld> for DecryptionAir<Fld> {
    fn get_lookups(&mut self) -> Vec<Lookup<Fld>> {
        specs_to_lookups(decryption_core_lookup_specs(true))
    }
}

impl<AB> Air<AB> for DecryptionAir<AB::F>
where
    AB: PermutationAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        eval_decryption_core(builder, self.n, self.delta, self.half_delta);
    }
}

// ---------------------------------------------------------------------------
// BalanceRefresh: RefreshAir (decryption core + fresh re-encryption, one trace)
// ---------------------------------------------------------------------------

/// AIR for one balance refresh: `old_ct` decrypts (under the key bound to the public `(a, b)`)
/// to digits normalized into a HIDDEN bit column, and `new_ct` is a fresh well-formed encryption
/// of exactly that bit column under the same key.
#[derive(Clone, Debug)]
pub struct RefreshAir<Fld> {
    pub n: usize,
    delta: Fld,
    half_delta: Fld,
}

impl<Fld: Field> RefreshAir<Fld> {
    pub fn new(n: usize) -> Self {
        assert!(n.is_power_of_two());
        Self {
            n,
            delta: Fld::from_u32(DELTA_U32),
            half_delta: Fld::from_u32(HALF_DELTA_U32),
        }
    }
}

impl<Fld: Field> BaseAir<Fld> for RefreshAir<Fld> {
    fn width(&self) -> usize {
        RF_COLS
    }

    fn num_public_values(&self) -> usize {
        // [domain] ++ a ++ b ++ c1_old ++ c2_old ++ c1_new ++ c2_new.
        1 + 6 * self.n
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        (DEC_CARRY..DEC_CARRY + CARRY_BITS).collect()
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
    }
}

impl<Fld: Field> LookupAir<Fld> for RefreshAir<Fld> {
    fn get_lookups(&mut self) -> Vec<Lookup<Fld>> {
        specs_to_lookups(refresh_lookup_specs())
    }
}

impl<AB> Air<AB> for RefreshAir<AB::F>
where
    AB: PermutationAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        eval_decryption_core(builder, self.n, self.delta, self.half_delta);
        eval_refresh_encryption(builder, self.n, self.delta);
    }
}

// ---------------------------------------------------------------------------
// Decryption-core witness construction (prove-side)
// ---------------------------------------------------------------------------

/// Schoolbook negacyclic product with quotient: `x·y = lo + (x^n + 1)·hi` over `Z_q[x]`,
/// `deg(lo) < n` (same split as upstream `split_negacyclic`). O(n²), n = 128 — negligible.
fn negacyclic_mul_with_quotient(x: &[F], y: &[F]) -> (Vec<F>, Vec<F>) {
    let n = x.len();
    debug_assert_eq!(y.len(), n);
    let mut prod = F::zero_vec(2 * n);
    for i in 0..n {
        for j in 0..n {
            prod[i + j] += x[i] * y[j];
        }
    }
    let lo: Vec<F> = (0..n).map(|i| prod[i] - prod[n + i]).collect();
    let hi: Vec<F> = (0..n).map(|i| prod[n + i]).collect();
    (lo, hi)
}

/// Full prove-side witness of the decryption core.
struct DecCoreWitness {
    s_field: Vec<F>,
    epk_u: Vec<u8>,
    epk_v: Vec<u8>,
    k_pk: Vec<F>,
    v: Vec<F>,
    k_v: Vec<F>,
    digits: Vec<u8>,
    noise_shifted: Vec<u32>,
    bits: Vec<u8>,
    carries: Vec<u16>,
    /// The value the circuit's own digit decomposition normalizes to.
    value: u64,
}

/// Build (and fully validate) the decryption-core witness for `(pk, sk, ct)`. Refuses cleanly —
/// never panics — when `sk` is malformed, `(pk, sk)` are inconsistent (derived pk noise outside
/// the CBD(2) range), the rounding noise exceeds the Δ/2 budget, or the decoded value does not
/// fit in u64.
fn build_decryption_witness(
    pk: &UpstreamPublicKey,
    sk: &RegevSk,
    ct: &UpstreamCiphertext,
) -> Result<DecCoreWitness, RegevError> {
    let n = REGEV_N;
    if sk.s.len() != n {
        return Err(RegevError::InvalidSk(format!(
            "expected {} coefficients, got {}",
            n,
            sk.s.len()
        )));
    }
    if sk.s.iter().any(|&x| !(-1..=1).contains(&x)) {
        return Err(RegevError::InvalidSk(
            "secret key is not ternary".to_string(),
        ));
    }
    let s_field: Vec<F> = sk.s.iter().map(|&x| centered_to_field(x as i64)).collect();

    // Key binding: recover e_pk = b − (a·s mod (x^n+1)) and decompose it into CBD(2) halves.
    // Upstream keygen does not retain the halves, but any |e| ≤ 2 splits as
    // (max(e,0), max(−e,0)) with both halves in [0, 2] — exactly the AIR's range constraint.
    let (as_lo, k_pk) = negacyclic_mul_with_quotient(&pk.a, &s_field);
    let mut epk_u = Vec::with_capacity(n);
    let mut epk_v = Vec::with_capacity(n);
    for (&b_i, &as_i) in pk.b.iter().zip(&as_lo) {
        let e = field_to_centered(b_i - as_i);
        if !(-2..=2).contains(&e) {
            return Err(RegevError::InvalidSk(
                "secret key is inconsistent with the public key (derived pk noise outside the CBD(2) range)".to_string(),
            ));
        }
        epk_u.push(e.max(0) as u8);
        epk_v.push((-e).max(0) as u8);
    }

    // Decryption value and quotient: v = c2 − (c1·s mod (x^n+1)).
    let (c1s_lo, k_v) = negacyclic_mul_with_quotient(&ct.c1, &s_field);
    let v: Vec<F> = ct.c2.iter().zip(&c1s_lo).map(|(&c2, &x)| c2 - x).collect();

    // Digit/noise decomposition: v + Δ/2 = Δ·d + ns (mod q), d ∈ [0, 256), ns ∈ [0, Δ).
    let q = REGEV_Q as u64;
    let mut digits = Vec::with_capacity(n);
    let mut noise_shifted = Vec::with_capacity(n);
    for &vi in &v {
        let w = (vi.as_canonical_u32() as u64 + HALF_DELTA_U32 as u64) % q;
        let d = w / DELTA_U32 as u64;
        if d >= 1 << DIGIT_BITS {
            // Only w = 256·Δ (= q − 1) lands here: rounding noise exactly at the digit-255
            // boundary, unreachable within the enforced noise budget.
            return Err(RegevError::InvalidWitness(
                "decryption rounding noise exceeds the Δ/2 budget".to_string(),
            ));
        }
        digits.push(d as u8);
        noise_shifted.push((w % DELTA_U32 as u64) as u32);
    }

    // Decode the circuit's value from the decomposition digits.
    let mut value: u128 = 0;
    for (i, &d) in digits.iter().enumerate() {
        if d != 0 {
            if i >= 64 {
                return Err(RegevError::DecryptOverflow);
            }
            value += (d as u128) << i;
        }
    }
    let value = u64::try_from(value).map_err(|_| RegevError::DecryptOverflow)?;
    let bits = encode_amount(value);

    // Normalization carries: d_i + c_i = bit_i + 2·c_{i+1}, c_0 = 0, final carry 0. Always
    // closes when `bits` is the binary encoding of Σ d_i·2^i (which it is, by construction);
    // the checks below are unreachable defense.
    let mut carries = vec![0u16; n];
    let mut carry: u16 = 0;
    for i in 0..n {
        carries[i] = carry;
        let t = digits[i] as i32 + carry as i32 - bits[i] as i32;
        if t < 0 || t % 2 != 0 {
            return Err(RegevError::InvalidWitness(
                "digit normalization adder cannot close".to_string(),
            ));
        }
        carry = (t / 2) as u16;
        debug_assert!(
            carry <= 254,
            "carry bound violated (see carry-bound analysis)"
        );
    }
    if carry != 0 {
        return Err(RegevError::InvalidWitness(
            "digit normalization has a nonzero final carry".to_string(),
        ));
    }

    Ok(DecCoreWitness {
        s_field,
        epk_u,
        epk_v,
        k_pk,
        v,
        k_v,
        digits,
        noise_shifted,
        bits,
        carries,
        value,
    })
}

/// Fill one row of the decryption-core columns.
fn fill_decryption_core_row(
    row: &mut [F],
    i: usize,
    pk: &UpstreamPublicKey,
    ct: &UpstreamCiphertext,
    w: &DecCoreWitness,
) {
    row[DEC_A] = pk.a[i];
    row[DEC_B] = pk.b[i];
    row[DEC_C1] = ct.c1[i];
    row[DEC_C2] = ct.c2[i];
    row[DEC_S] = w.s_field[i];
    row[DEC_EPK_U] = F::from_u8(w.epk_u[i]);
    row[DEC_EPK_V] = F::from_u8(w.epk_v[i]);
    row[DEC_K_PK] = w.k_pk[i];
    row[DEC_V] = w.v[i];
    row[DEC_K_V] = w.k_v[i];
    for j in 0..DIGIT_BITS {
        row[DEC_D_BITS + j] = F::from_u8((w.digits[i] >> j) & 1);
    }
    for j in 0..NOISE_LO_BITS {
        row[DEC_NOISE_LO + j] = F::from_u32((w.noise_shifted[i] >> j) & 1);
    }
    let hi = w.noise_shifted[i] >> NOISE_LO_BITS;
    debug_assert!(hi <= 14, "noise high limb out of range");
    let nu = hi.min(7);
    let nv = hi - nu;
    for j in 0..NOISE_HI_HALF_BITS {
        row[DEC_NOISE_U + j] = F::from_u32((nu >> j) & 1);
        row[DEC_NOISE_V + j] = F::from_u32((nv >> j) & 1);
    }
    row[DEC_BIT] = F::from_u8(w.bits[i]);
    for j in 0..CARRY_BITS {
        row[DEC_CARRY + j] = F::from_u32((w.carries[i] as u32 >> j) & 1);
    }
}

fn generate_decryption_trace(
    pk: &UpstreamPublicKey,
    ct: &UpstreamCiphertext,
    w: &DecCoreWitness,
) -> RowMajorMatrix<F> {
    let n = REGEV_N;
    let mut values = F::zero_vec(n * DEC_CORE_COLS);
    for i in 0..n {
        fill_decryption_core_row(
            &mut values[i * DEC_CORE_COLS..(i + 1) * DEC_CORE_COLS],
            i,
            pk,
            ct,
            w,
        );
    }
    RowMajorMatrix::new(values, DEC_CORE_COLS)
}

fn generate_refresh_trace(
    pk: &UpstreamPublicKey,
    old_ct: &UpstreamCiphertext,
    new_ct: &UpstreamCiphertext,
    core: &DecCoreWitness,
    enc: &EncryptionWitness,
) -> RowMajorMatrix<F> {
    let n = REGEV_N;
    // The core's normalized bits ARE the encryption message — both equal
    // encode_amount(core.value) by construction; unreachable defense.
    assert_eq!(
        core.bits, enc.m,
        "refresh witness inconsistent: normalized bits != fresh encryption message"
    );
    let mut values = F::zero_vec(n * RF_COLS);
    for i in 0..n {
        let row = &mut values[i * RF_COLS..(i + 1) * RF_COLS];
        fill_decryption_core_row(row, i, pk, old_ct, core);
        row[RF_C1_NEW] = new_ct.c1[i];
        row[RF_C2_NEW] = new_ct.c2[i];
        row[RF_R] = centered_to_field(enc.r[i] as i64);
        row[RF_E1U] = F::from_u8(enc.e1u[i]);
        row[RF_E1V] = F::from_u8(enc.e1v[i]);
        row[RF_E2U] = F::from_u8(enc.e2u[i]);
        row[RF_E2V] = F::from_u8(enc.e2v[i]);
        row[RF_K1] = enc.k1[i];
        row[RF_K2] = enc.k2[i];
    }
    RowMajorMatrix::new(values, RF_COLS)
}

// ---------------------------------------------------------------------------
// E-3 prove / verify
// ---------------------------------------------------------------------------

/// E-3 public values: `[domain] ++ amount limbs ++ a ++ b ++ c1 ++ c2` (purpose word and full
/// public statement absorbed before any challenge, F2-A/F2-B — see module docs).
fn decryption_public_values(
    domain: u32,
    amount: u64,
    pk: &UpstreamPublicKey,
    ct: &UpstreamCiphertext,
) -> Vec<F> {
    let mut pv = Vec::with_capacity(1 + E2_NUM_EXTRA_PVS + 4 * REGEV_N);
    pv.push(F::from_u32(domain));
    pv.extend_from_slice(&amount_limbs(amount));
    pv.extend_from_slice(&pk.a);
    pv.extend_from_slice(&pk.b);
    pv.extend_from_slice(&ct.c1);
    pv.extend_from_slice(&ct.c2);
    pv
}

/// Prove E-3 withdrawClaimZKP (detail2 §E-3): "`ct` decrypts to the public `amount` under the
/// secret key behind `pk`". Refuses cleanly (no panic) when `sk` does not match `pk`, when `ct`
/// does not decrypt to `amount`, or when the rounding noise is outside the provable budget.
pub fn prove_withdraw_claim(
    level: RegevSecurityLevel,
    pk: &RegevPk,
    sk: &RegevSk,
    ct: &RegevCiphertext,
    amount: u64,
) -> Result<Vec<u8>, RegevError> {
    prove_withdraw_claim_with_domain(level, WITHDRAW_CLAIM_ZKP_DOMAIN, pk, sk, ct, amount)
}

/// Domain-parameterized E-3 prover. Private: only `prove_withdraw_claim` (and the
/// purpose-binding adversarial test) call this.
fn prove_withdraw_claim_with_domain(
    level: RegevSecurityLevel,
    domain: u32,
    pk: &RegevPk,
    sk: &RegevSk,
    ct: &RegevCiphertext,
    amount: u64,
) -> Result<Vec<u8>, RegevError> {
    let upk = to_upstream_pk(pk)?;
    let uct = to_upstream_ct(ct)?;

    // Precondition: the ciphertext must actually decrypt to the claimed amount under sk
    // (upstream rounding semantics; clean DecryptOverflow on digit/width overflow).
    let value = decrypt_amount(sk, ct)?;
    if value != amount {
        return Err(RegevError::InvalidWitness(format!(
            "ciphertext decrypts to {value}, not the claimed amount {amount}"
        )));
    }

    let w = build_decryption_witness(&upk, sk, &uct)?;
    // The circuit's own digit decomposition must reproduce the claim too (they can differ from
    // upstream rounding only when the noise sits exactly on a digit boundary — see the rounding
    // analysis in the decryption-core docs).
    if w.value != amount {
        return Err(RegevError::InvalidWitness(format!(
            "digit decomposition decodes to {}, not the claimed amount {amount} (rounding-boundary noise)",
            w.value
        )));
    }

    let air = DecryptionAir::<F>::new(REGEV_N);
    let trace = generate_decryption_trace(&upk, &uct, &w);
    let pvs = decryption_public_values(domain, amount, &upk, &uct);
    prove_one(&level.config(), &air, &trace, pvs)
}

/// Verify E-3 withdrawClaimZKP against the claimed statement (pk, ct and PUBLIC amount).
/// Validates the key and ciphertext canonically BEFORE touching the proof bytes.
pub fn verify_withdraw_claim(
    level: RegevSecurityLevel,
    pk: &RegevPk,
    ct: &RegevCiphertext,
    amount: u64,
    proof: &[u8],
) -> Result<(), RegevError> {
    verify_withdraw_claim_with_domain(level, WITHDRAW_CLAIM_ZKP_DOMAIN, pk, ct, amount, proof)
}

/// Domain-parameterized E-3 verifier (private; the purpose-binding test uses it to show the
/// same proof bytes verify under the domain they were created for and no other).
fn verify_withdraw_claim_with_domain(
    level: RegevSecurityLevel,
    domain: u32,
    pk: &RegevPk,
    ct: &RegevCiphertext,
    amount: u64,
    proof: &[u8],
) -> Result<(), RegevError> {
    let upk = to_upstream_pk(pk)?;
    let uct = to_upstream_ct(ct)?;

    let air = DecryptionAir::<F>::new(REGEV_N);
    // SECURITY: the verifier rebuilds the public values itself, with ITS purpose domain word and
    // ITS amount — a proof for any other purpose or amount diverges the transcript (F2-B).
    let pvs = decryption_public_values(domain, amount, &upk, &uct);
    let (z, proof) = verify_one(&level.config(), air, proof, pvs, DEC_NUM_PUBLISHED)?;

    // Outer binding: recompute the public polynomials' evaluations at z, including the public
    // amount's bit polynomial — this pins the in-circuit bit column (and through the
    // normalization adder, the digit decomposition of v) to the claimed amount.
    let ev = |coeffs: &[F]| eval_at(coeffs.iter().copied(), z);
    let m_pub: Vec<F> = encode_amount(amount)
        .iter()
        .map(|&b| F::from_u8(b))
        .collect();
    let expected = vec![ev(&upk.a), ev(&upk.b), ev(&uct.c1), ev(&uct.c2), ev(&m_pub)];
    check_published_evals(&proof, &expected)
}

// ---------------------------------------------------------------------------
// BalanceRefresh prove / verify
// ---------------------------------------------------------------------------

/// Refresh public values: `[domain] ++ a ++ b ++ c1_old ++ c2_old ++ c1_new ++ c2_new`.
fn refresh_public_values(
    domain: u32,
    pk: &UpstreamPublicKey,
    old_ct: &UpstreamCiphertext,
    new_ct: &UpstreamCiphertext,
) -> Vec<F> {
    let mut pv = Vec::with_capacity(1 + 6 * REGEV_N);
    pv.push(F::from_u32(domain));
    pv.extend_from_slice(&pk.a);
    pv.extend_from_slice(&pk.b);
    pv.extend_from_slice(&old_ct.c1);
    pv.extend_from_slice(&old_ct.c2);
    pv.extend_from_slice(&new_ct.c1);
    pv.extend_from_slice(&new_ct.c2);
    pv
}

/// Prove a balance refresh (detail2 §B-3): decrypt `old_ct`, re-encrypt the same value freshly
/// under the same key, and prove plaintext equality + well-formedness of the new ciphertext
/// WITHOUT revealing the value. Returns the fresh ciphertext together with the proof.
///
/// SECURITY: the caller must supply a cryptographically secure RNG for the fresh encryption
/// randomness (same contract as `encrypt_amount`).
pub fn prove_balance_refresh(
    rng: &mut impl rand010::Rng,
    level: RegevSecurityLevel,
    pk: &RegevPk,
    sk: &RegevSk,
    old_ct: &RegevCiphertext,
) -> Result<(RegevCiphertext, Vec<u8>), RegevError> {
    let upk = to_upstream_pk(pk)?;
    let uold = to_upstream_ct(old_ct)?;

    // Precondition: old_ct must decrypt to a u64 value under sk (clean error otherwise).
    let value = decrypt_amount(sk, old_ct)?;
    let core = build_decryption_witness(&upk, sk, &uold)?;
    if core.value != value {
        return Err(RegevError::InvalidWitness(format!(
            "digit decomposition decodes to {}, not the decrypted value {value} (rounding-boundary noise)",
            core.value
        )));
    }

    let (new_ct, aw) = encrypt_amount(rng, pk, value)?;
    let unew = to_upstream_ct(&new_ct)?;
    // Full encryption-witness validation (ranges, encoding, both ring identities) so prove
    // never builds an unsatisfiable trace.
    check_amount_witness(&upk, &unew, &aw, "new_ct")?;

    let air = RefreshAir::<F>::new(REGEV_N);
    let trace = generate_refresh_trace(&upk, &uold, &unew, &core, &aw.witness);
    let pvs = refresh_public_values(BALANCE_REFRESH_ZKP_DOMAIN, &upk, &uold, &unew);
    let proof = prove_one(&level.config(), &air, &trace, pvs)?;
    Ok((new_ct, proof))
}

/// Verify a balance-refresh proof against the claimed statement (pk, old_ct, new_ct).
/// Validates the key and both ciphertexts canonically BEFORE touching the proof bytes.
pub fn verify_balance_refresh(
    level: RegevSecurityLevel,
    pk: &RegevPk,
    old_ct: &RegevCiphertext,
    new_ct: &RegevCiphertext,
    proof: &[u8],
) -> Result<(), RegevError> {
    let upk = to_upstream_pk(pk)?;
    let uold = to_upstream_ct(old_ct)?;
    let unew = to_upstream_ct(new_ct)?;

    let air = RefreshAir::<F>::new(REGEV_N);
    let pvs = refresh_public_values(BALANCE_REFRESH_ZKP_DOMAIN, &upk, &uold, &unew);
    let (z, proof) = verify_one(&level.config(), air, proof, pvs, RF_NUM_PUBLISHED)?;

    let ev = |coeffs: &[F]| eval_at(coeffs.iter().copied(), z);
    let expected = vec![
        ev(&upk.a),
        ev(&upk.b),
        ev(&uold.c1),
        ev(&uold.c2),
        ev(&unew.c1),
        ev(&unew.c2),
    ];
    check_published_evals(&proof, &expected)
}

// ---------------------------------------------------------------------------
// Statement-level verifier (detail2 §E-4)
// ---------------------------------------------------------------------------

/// A public statement for one Regev proof purpose.
#[derive(Clone, Debug)]
pub enum RegevStatement {
    ChannelTx {
        sender_pk: RegevPk,
        recipient_pk: RegevPk,
        before: RegevCiphertext,
        enc_amount: RegevCiphertext,
        after: RegevCiphertext,
    },
    ChannelUpdate {
        sender_pk: RegevPk,
        recipient_pk: RegevPk,
        before: RegevCiphertext,
        after: RegevCiphertext,
        sender_delta: RegevCiphertext,
        receiver_delta: RegevCiphertext,
        amount: u64,
    },
    /// E-3: "`user_amount_ct` decrypts to the public `amount` under the key behind `user_pk`".
    WithdrawClaim {
        user_pk: RegevPk,
        user_amount_ct: RegevCiphertext,
        amount: u64,
    },
    /// Refresh: "`old_ct` and `new_ct` encrypt the same (hidden) plaintext under `pk`, and
    /// `new_ct` is a fresh well-formed encryption".
    BalanceRefresh {
        pk: RegevPk,
        old_ct: RegevCiphertext,
        new_ct: RegevCiphertext,
    },
}

/// In-process Plonky3 verifier for the channel-layer Regev proofs.
#[derive(Clone, Copy, Debug)]
pub struct RealRegevProofVerifier {
    pub level: RegevSecurityLevel,
}

impl RealRegevProofVerifier {
    /// Verify `proof` (postcard-serialized [`BatchProof`]) for `purpose` against `statement`.
    ///
    /// SECURITY: a purpose/statement-variant mismatch is rejected here, before any proof work —
    /// this is the structural half of the F2-B defense; the transcript domain word (checked
    /// inside each `verify_*` function) is the cryptographic half.
    pub fn verify(
        &self,
        purpose: RegevProofPurpose,
        proof: &[u8],
        statement: &RegevStatement,
    ) -> Result<(), RegevError> {
        match (purpose, statement) {
            (
                RegevProofPurpose::ChannelTx,
                RegevStatement::ChannelTx {
                    sender_pk,
                    recipient_pk,
                    before,
                    enc_amount,
                    after,
                },
            ) => verify_channel_tx(
                self.level,
                sender_pk,
                recipient_pk,
                before,
                enc_amount,
                after,
                proof,
            ),
            (
                RegevProofPurpose::ChannelUpdate,
                RegevStatement::ChannelUpdate {
                    sender_pk,
                    recipient_pk,
                    before,
                    after,
                    sender_delta,
                    receiver_delta,
                    amount,
                },
            ) => verify_channel_update(
                self.level,
                sender_pk,
                recipient_pk,
                before,
                after,
                sender_delta,
                receiver_delta,
                *amount,
                proof,
            ),
            (
                RegevProofPurpose::WithdrawClaim,
                RegevStatement::WithdrawClaim {
                    user_pk,
                    user_amount_ct,
                    amount,
                },
            ) => verify_withdraw_claim(self.level, user_pk, user_amount_ct, *amount, proof),
            (
                RegevProofPurpose::BalanceRefresh,
                RegevStatement::BalanceRefresh { pk, old_ct, new_ct },
            ) => verify_balance_refresh(self.level, pk, old_ct, new_ct, proof),
            (purpose, statement) => Err(RegevError::PurposeMismatch(format!(
                "purpose {purpose:?} does not match statement variant {}",
                match statement {
                    RegevStatement::ChannelTx { .. } => "ChannelTx",
                    RegevStatement::ChannelUpdate { .. } => "ChannelUpdate",
                    RegevStatement::WithdrawClaim { .. } => "WithdrawClaim",
                    RegevStatement::BalanceRefresh { .. } => "BalanceRefresh",
                }
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use rand010::{SeedableRng, rngs::SmallRng};

    use super::*;
    use crate::regev::{
        channel_keygen,
        encrypt::encrypt_amount,
        params::{REGEV_N, REGEV_Q},
    };

    const LEVEL: RegevSecurityLevel = RegevSecurityLevel::Test;

    struct TxFixture {
        sender_pk: RegevPk,
        recipient_pk: RegevPk,
        before: (RegevCiphertext, AmountWitness),
        enc_amount: (RegevCiphertext, AmountWitness),
        after: (RegevCiphertext, AmountWitness),
    }

    /// Encrypts a consistent E-1 statement: `before_amt` and `amt` under the right keys, with
    /// `after = before − amount`.
    fn tx_fixture(seed: u64, before_amt: u64, amt: u64) -> TxFixture {
        let mut rng = SmallRng::seed_from_u64(seed);
        let (sender_pk, _) = channel_keygen(&mut rng);
        let (recipient_pk, _) = channel_keygen(&mut rng);
        let before = encrypt_amount(&mut rng, &sender_pk, before_amt).unwrap();
        let enc_amount = encrypt_amount(&mut rng, &recipient_pk, amt).unwrap();
        let after = encrypt_amount(&mut rng, &sender_pk, before_amt - amt).unwrap();
        TxFixture {
            sender_pk,
            recipient_pk,
            before,
            enc_amount,
            after,
        }
    }

    fn prove_fixture(f: &TxFixture) -> Result<Vec<u8>, RegevError> {
        prove_channel_tx(
            LEVEL,
            &f.sender_pk,
            &f.recipient_pk,
            (&f.before.0, &f.before.1),
            (&f.enc_amount.0, &f.enc_amount.1),
            (&f.after.0, &f.after.1),
        )
    }

    fn verify_fixture(f: &TxFixture, proof: &[u8]) -> Result<(), RegevError> {
        verify_channel_tx(
            LEVEL,
            &f.sender_pk,
            &f.recipient_pk,
            &f.before.0,
            &f.enc_amount.0,
            &f.after.0,
            proof,
        )
    }

    struct UpdateFixture {
        sender_pk: RegevPk,
        recipient_pk: RegevPk,
        before: (RegevCiphertext, AmountWitness),
        after: (RegevCiphertext, AmountWitness),
        sender_delta: (RegevCiphertext, AmountWitness),
        receiver_delta: (RegevCiphertext, AmountWitness),
        amount: u64,
    }

    fn update_fixture(seed: u64, before_amt: u64, amount: u64) -> UpdateFixture {
        let mut rng = SmallRng::seed_from_u64(seed);
        let (sender_pk, _) = channel_keygen(&mut rng);
        let (recipient_pk, _) = channel_keygen(&mut rng);
        let before = encrypt_amount(&mut rng, &sender_pk, before_amt).unwrap();
        let after = encrypt_amount(&mut rng, &sender_pk, before_amt - amount).unwrap();
        let sender_delta = encrypt_amount(&mut rng, &sender_pk, amount).unwrap();
        let receiver_delta = encrypt_amount(&mut rng, &recipient_pk, amount).unwrap();
        UpdateFixture {
            sender_pk,
            recipient_pk,
            before,
            after,
            sender_delta,
            receiver_delta,
            amount,
        }
    }

    fn prove_update(f: &UpdateFixture) -> Result<Vec<u8>, RegevError> {
        prove_channel_update(
            LEVEL,
            &f.sender_pk,
            &f.recipient_pk,
            (&f.before.0, &f.before.1),
            (&f.after.0, &f.after.1),
            (&f.sender_delta.0, &f.sender_delta.1),
            (&f.receiver_delta.0, &f.receiver_delta.1),
            f.amount,
        )
    }

    fn verify_update(f: &UpdateFixture, amount: u64, proof: &[u8]) -> Result<(), RegevError> {
        verify_channel_update(
            LEVEL,
            &f.sender_pk,
            &f.recipient_pk,
            &f.before.0,
            &f.after.0,
            &f.sender_delta.0,
            &f.receiver_delta.0,
            amount,
            proof,
        )
    }

    /// Happy path + boundary amounts for E-1: a regular spend, amount = 0 (after == before
    /// plaintext) and amount = before (after encrypts 0).
    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn channel_tx_roundtrip_including_edge_amounts() {
        for (seed, before_amt, amt) in [(100u64, 1_000u64, 250u64), (101, 5, 0), (102, 7, 7)] {
            let f = tx_fixture(seed, before_amt, amt);
            let proof = prove_fixture(&f).unwrap();
            verify_fixture(&f, &proof).unwrap();
        }
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn channel_update_roundtrip() {
        let f = update_fixture(200, 1_000, 250);
        let proof = prove_update(&f).unwrap();
        verify_update(&f, f.amount, &proof).unwrap();
    }

    /// Adversarial: a proof must not verify against a statement whose ciphertexts were tampered
    /// with — flipping a single coefficient of any of the three E-1 ciphertexts (c1 and c2)
    /// must break the published-evaluation binding.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn channel_tx_rejects_tampered_ciphertexts() {
        let f = tx_fixture(300, 1_000, 250);
        let proof = prove_fixture(&f).unwrap();
        verify_fixture(&f, &proof).unwrap();

        for ct_idx in 0..3 {
            for c2 in [false, true] {
                let mut tampered = tx_fixture(300, 1_000, 250);
                // Rebuild the same fixture (same seed) and flip one coefficient, canonically.
                let ct = match ct_idx {
                    0 => &mut tampered.before.0,
                    1 => &mut tampered.enc_amount.0,
                    _ => &mut tampered.after.0,
                };
                let poly = if c2 { &mut ct.c2 } else { &mut ct.c1 };
                poly[0] = (poly[0] + 1) % REGEV_Q;
                assert!(
                    verify_fixture(&tampered, &proof).is_err(),
                    "tampered ct {ct_idx} ({}): verification must fail",
                    if c2 { "c2" } else { "c1" }
                );
            }
        }
    }

    /// Adversarial: an E-2 proof for amount A must not verify with public amount A±1, and a
    /// tampered delta ciphertext must be rejected.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn channel_update_rejects_wrong_public_amount_and_tampering() {
        let f = update_fixture(400, 1_000, 250);
        let proof = prove_update(&f).unwrap();
        verify_update(&f, 250, &proof).unwrap();

        // Wrong public amount: the m(z) recomputation must mismatch.
        assert!(verify_update(&f, 249, &proof).is_err());
        assert!(verify_update(&f, 251, &proof).is_err());

        // Tampered delta ciphertexts.
        for c2 in [false, true] {
            let mut tampered = update_fixture(400, 1_000, 250);
            let poly = if c2 {
                &mut tampered.receiver_delta.0.c2
            } else {
                &mut tampered.sender_delta.0.c1
            };
            poly[REGEV_N - 1] = (poly[REGEV_N - 1] + 1) % REGEV_Q;
            assert!(verify_update(&tampered, 250, &proof).is_err());
        }
    }

    /// Adversarial: the prover must refuse deltas that encrypt a different value than the
    /// claimed public amount (this is the prove-side half of F2-C; the verify-side half is the
    /// m(z) recomputation, exercised above via the wrong-amount checks).
    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn channel_update_prove_refuses_deltas_encrypting_wrong_amount() {
        // Deltas encrypt 251 while the statement claims 250 (conservation built for 251 so the
        // ONLY inconsistency is the public amount).
        let mut f = update_fixture(500, 1_000, 251);
        f.amount = 250;
        assert!(matches!(
            prove_update(&f),
            Err(RegevError::InvalidWitness(_))
        ));

        // Conservation mismatch: before != after + amount.
        let mut rng = SmallRng::seed_from_u64(501);
        let mut f = update_fixture(500, 1_000, 250);
        f.after = encrypt_amount(&mut rng, &f.sender_pk, 1_000 - 249).unwrap();
        assert!(matches!(
            prove_update(&f),
            Err(RegevError::InvalidWitness(_))
        ));
    }

    /// Adversarial F2-B: a proof generated for one purpose must not verify as another.
    /// (a) Same AIR, different domain word only — isolates the transcript binding.
    /// (b) E-1 proof presented to the E-2 verifier on a crafted statement.
    /// (c) Purpose/statement-variant mismatch in the statement-level verifier.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn purpose_binding_rejects_cross_purpose_proofs() {
        let f = tx_fixture(600, 1_000, 250);

        // (a) Identical statement and AIR, but proved under the (P2b) withdraw-claim domain.
        let foreign = prove_dual_key_transfer(
            LEVEL,
            WITHDRAW_CLAIM_ZKP_DOMAIN,
            &f.sender_pk,
            &f.recipient_pk,
            (&f.before.0, &f.before.1),
            (&f.enc_amount.0, &f.enc_amount.1),
            (&f.after.0, &f.after.1),
        )
        .unwrap();
        assert!(
            verify_fixture(&f, &foreign).is_err(),
            "a proof bound to a different purpose domain must not verify as ChannelTx"
        );
        // Sanity: the same bytes DO verify under the domain they were created for.
        // (Direct internal check that the only difference above is the domain word.)
        {
            let spk = to_upstream_pk(&f.sender_pk).unwrap();
            let rpk = to_upstream_pk(&f.recipient_pk).unwrap();
            let cts = [
                to_upstream_ct(&f.before.0).unwrap(),
                to_upstream_ct(&f.enc_amount.0).unwrap(),
                to_upstream_ct(&f.after.0).unwrap(),
            ];
            let ct_refs = [&cts[0], &cts[1], &cts[2]];
            let params = channel_regev_params();
            let air = DualKeyTransferAir::new(REGEV_N, F::from_u32(params.delta()));
            let pvs = dual_key_public_values(WITHDRAW_CLAIM_ZKP_DOMAIN, &[], &spk, &rpk, &ct_refs);
            let (z, proof) = verify_one(
                &LEVEL.config(),
                air,
                &foreign,
                pvs,
                E1_SHAPE.num_published_evals(),
            )
            .unwrap();
            let expected = expected_published_evals(&E1_SHAPE, &spk, &rpk, &ct_refs, None, z);
            check_published_evals(&proof, &expected).unwrap();
        }

        // (b) E-1 proof against the E-2 verifier on a crafted "matching" statement.
        let e1_proof = prove_fixture(&f).unwrap();
        assert!(
            verify_channel_update(
                LEVEL,
                &f.sender_pk,
                &f.recipient_pk,
                &f.before.0,
                &f.after.0,
                &f.enc_amount.0, // crafted: reuse enc_amount as sender_delta
                &f.enc_amount.0, // and as receiver_delta
                250,
                &e1_proof,
            )
            .is_err(),
            "an E-1 proof must not verify as an E-2 statement"
        );

        // (c) Statement-level purpose mismatch is rejected structurally.
        let verifier = RealRegevProofVerifier { level: LEVEL };
        let tx_statement = RegevStatement::ChannelTx {
            sender_pk: f.sender_pk.clone(),
            recipient_pk: f.recipient_pk.clone(),
            before: f.before.0.clone(),
            enc_amount: f.enc_amount.0.clone(),
            after: f.after.0.clone(),
        };
        assert!(matches!(
            verifier.verify(RegevProofPurpose::ChannelUpdate, &e1_proof, &tx_statement),
            Err(RegevError::PurposeMismatch(_))
        ));
        // And the matching dispatch verifies.
        verifier
            .verify(RegevProofPurpose::ChannelTx, &e1_proof, &tx_statement)
            .unwrap();
        // An E-1 proof dispatched as a (matching-variant) WithdrawClaim statement reaches the
        // E-3 verifier and is rejected there (shape + transcript mismatch), never panics.
        let wc_statement = RegevStatement::WithdrawClaim {
            user_pk: f.sender_pk.clone(),
            user_amount_ct: f.before.0.clone(),
            amount: 1,
        };
        assert!(matches!(
            verifier.verify(RegevProofPurpose::WithdrawClaim, &e1_proof, &wc_statement),
            Err(RegevError::ProofVerification(_))
        ));
    }

    /// Adversarial: swapping the sender and recipient keys in the claimed statement must break
    /// the key-evaluation binding.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn channel_tx_rejects_swapped_public_keys() {
        let f = tx_fixture(700, 1_000, 250);
        let proof = prove_fixture(&f).unwrap();
        assert!(
            verify_channel_tx(
                LEVEL,
                &f.recipient_pk, // swapped
                &f.sender_pk,    // swapped
                &f.before.0,
                &f.enc_amount.0,
                &f.after.0,
                &proof,
            )
            .is_err()
        );
    }

    /// Boundary: a non-canonical statement (coefficient >= q, wrong length, bad key) is
    /// rejected with a canonicality error BEFORE any proof bytes are parsed.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn non_canonical_statement_rejected_before_proof_work() {
        let f = tx_fixture(800, 100, 1);
        let garbage = b"not a proof at all";

        let mut bad_ct = f.before.0.clone();
        bad_ct.c1[0] = REGEV_Q;
        assert!(matches!(
            verify_channel_tx(
                LEVEL,
                &f.sender_pk,
                &f.recipient_pk,
                &bad_ct,
                &f.enc_amount.0,
                &f.after.0,
                garbage
            ),
            Err(RegevError::InvalidCiphertext(_))
        ));

        let mut bad_pk = f.sender_pk.clone();
        bad_pk.a.pop();
        assert!(matches!(
            verify_channel_tx(
                LEVEL,
                &bad_pk,
                &f.recipient_pk,
                &f.before.0,
                &f.enc_amount.0,
                &f.after.0,
                garbage
            ),
            Err(RegevError::InvalidPk(_))
        ));

        let mut bad_delta = f.enc_amount.0.clone();
        bad_delta.c2[3] = REGEV_Q + 17;
        assert!(matches!(
            verify_channel_update(
                LEVEL,
                &f.sender_pk,
                &f.recipient_pk,
                &f.before.0,
                &f.after.0,
                &bad_delta,
                &f.enc_amount.0,
                1,
                garbage
            ),
            Err(RegevError::InvalidCiphertext(_))
        ));
    }

    /// Adversarial: `before < amount` has no consistent witness (the carry chain cannot close);
    /// the prover must refuse cleanly instead of producing anything.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn channel_tx_prove_refuses_underflow() {
        let mut rng = SmallRng::seed_from_u64(900);
        let (sender_pk, _) = channel_keygen(&mut rng);
        let (recipient_pk, _) = channel_keygen(&mut rng);
        let before = encrypt_amount(&mut rng, &sender_pk, 5).unwrap();
        let enc_amount = encrypt_amount(&mut rng, &recipient_pk, 9).unwrap();
        // No non-negative `after` satisfies 5 = after + 9; the closest forgery encrypts 0.
        let after = encrypt_amount(&mut rng, &sender_pk, 0).unwrap();
        assert!(matches!(
            prove_channel_tx(
                LEVEL,
                &sender_pk,
                &recipient_pk,
                (&before.0, &before.1),
                (&enc_amount.0, &enc_amount.1),
                (&after.0, &after.1),
            ),
            Err(RegevError::InvalidWitness(_))
        ));
    }

    /// Adversarial: truncated and garbage proof bytes must produce clean errors, never panics.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn garbage_and_truncated_proof_bytes_rejected() {
        let f = tx_fixture(1_000, 100, 30);
        let proof = prove_fixture(&f).unwrap();

        for bad in [
            &proof[..proof.len() / 2], // truncated
            &proof[..0],               // empty
            &[0xffu8; 64][..],         // garbage
            &[0x01u8, 0x02, 0x03][..], // tiny garbage
        ] {
            assert!(
                verify_fixture(&f, bad).is_err(),
                "malformed proof bytes must be rejected"
            );
        }

        // A single flipped byte in a valid proof must also fail (commitment/transcript check).
        let mut flipped = proof.clone();
        let mid = flipped.len() / 2;
        flipped[mid] ^= 0x01;
        assert!(verify_fixture(&f, &flipped).is_err());
    }

    // -----------------------------------------------------------------------
    // E-3 (WithdrawClaim) and BalanceRefresh tests
    // -----------------------------------------------------------------------

    use crate::regev::{MAX_HOMO_ADDS_BEFORE_REFRESH, decrypt_amount, encrypt::add_ciphertexts};

    /// A fresh keypair plus a fresh encryption of `amount` under it.
    fn claim_fixture(seed: u64, amount: u64) -> (RegevPk, crate::regev::RegevSk, RegevCiphertext) {
        let mut rng = SmallRng::seed_from_u64(seed);
        let (pk, sk) = channel_keygen(&mut rng);
        let (ct, _) = encrypt_amount(&mut rng, &pk, amount).unwrap();
        (pk, sk, ct)
    }

    /// `count` stacked homomorphic additions of `amount_each` (digits reach `count` on every
    /// set bit position).
    fn accumulated_ct(
        rng: &mut SmallRng,
        pk: &RegevPk,
        amount_each: u64,
        count: u32,
    ) -> RegevCiphertext {
        let (mut acc, _) = encrypt_amount(rng, pk, amount_each).unwrap();
        for _ in 1..count {
            let (ct, _) = encrypt_amount(rng, pk, amount_each).unwrap();
            acc = add_ciphertexts(&acc, &ct).unwrap();
        }
        acc
    }

    /// Happy path + boundary amounts for E-3 on FRESH ciphertexts: 0, 1, a mid value, and
    /// u64::MAX (all 64 message bits set).
    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn withdraw_claim_roundtrip_fresh_amounts() {
        for (seed, amount) in [
            (2_000u64, 0u64),
            (2_001, 1),
            (2_002, 12_345),
            (2_003, u64::MAX),
        ] {
            let (pk, sk, ct) = claim_fixture(seed, amount);
            let proof = prove_withdraw_claim(LEVEL, &pk, &sk, &ct, amount).unwrap();
            verify_withdraw_claim(LEVEL, &pk, &ct, amount, &proof).unwrap();
        }
    }

    /// Load-bearing test for the withdraw-claim design (D1 + D3): E-3 must work on a ciphertext
    /// accumulated through MAX_HOMO_ADDS_BEFORE_REFRESH = 64 homomorphic additions, where the
    /// per-coefficient digits reach 64 (every low bit of `amount_each` set) and the rounding
    /// noise is the worst the protocol allows.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn withdraw_claim_roundtrip_after_64_homomorphic_adds() {
        let mut rng = SmallRng::seed_from_u64(2_100);
        let (pk, sk) = channel_keygen(&mut rng);
        let amount_each = u32::MAX as u64; // 32 set bits -> digits reach exactly 64.
        let acc = accumulated_ct(&mut rng, &pk, amount_each, MAX_HOMO_ADDS_BEFORE_REFRESH);
        let total = amount_each * MAX_HOMO_ADDS_BEFORE_REFRESH as u64;
        assert_eq!(decrypt_amount(&sk, &acc).unwrap(), total);

        let proof = prove_withdraw_claim(LEVEL, &pk, &sk, &acc, total).unwrap();
        verify_withdraw_claim(LEVEL, &pk, &acc, total, &proof).unwrap();
    }

    /// BalanceRefresh roundtrip on a 64-add accumulated ciphertext: the proof verifies, the
    /// fresh ciphertext decrypts to the same value, and a subsequent E-3 claim works on it.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn balance_refresh_roundtrip_after_64_adds_then_claim() {
        let mut rng = SmallRng::seed_from_u64(2_200);
        let (pk, sk) = channel_keygen(&mut rng);
        let amount_each = u32::MAX as u64;
        let acc = accumulated_ct(&mut rng, &pk, amount_each, MAX_HOMO_ADDS_BEFORE_REFRESH);
        let total = amount_each * MAX_HOMO_ADDS_BEFORE_REFRESH as u64;

        let (new_ct, proof) = prove_balance_refresh(&mut rng, LEVEL, &pk, &sk, &acc).unwrap();
        verify_balance_refresh(LEVEL, &pk, &acc, &new_ct, &proof).unwrap();

        // The fresh ciphertext carries the same value with reset digits/noise...
        assert_eq!(decrypt_amount(&sk, &new_ct).unwrap(), total);
        // ...and supports a subsequent withdraw claim.
        let claim = prove_withdraw_claim(LEVEL, &pk, &sk, &new_ct, total).unwrap();
        verify_withdraw_claim(LEVEL, &pk, &new_ct, total, &claim).unwrap();
    }

    /// Adversarial E-3: a proof for amount A must not verify against A±1 or any other amount,
    /// against a different pk, or against a tampered ciphertext.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn withdraw_claim_rejects_wrong_statement() {
        let amount = 987_654_321u64;
        let (pk, sk, ct) = claim_fixture(2_300, amount);
        let proof = prove_withdraw_claim(LEVEL, &pk, &sk, &ct, amount).unwrap();
        verify_withdraw_claim(LEVEL, &pk, &ct, amount, &proof).unwrap();

        // Wrong public amount (±1 and a distant value B).
        assert!(verify_withdraw_claim(LEVEL, &pk, &ct, amount - 1, &proof).is_err());
        assert!(verify_withdraw_claim(LEVEL, &pk, &ct, amount + 1, &proof).is_err());
        assert!(verify_withdraw_claim(LEVEL, &pk, &ct, 42, &proof).is_err());

        // Wrong public key.
        let mut rng = SmallRng::seed_from_u64(2_301);
        let (other_pk, _) = channel_keygen(&mut rng);
        assert!(verify_withdraw_claim(LEVEL, &other_pk, &ct, amount, &proof).is_err());

        // Tampered ciphertext (c1 and c2, canonically).
        for c2 in [false, true] {
            let mut tampered = ct.clone();
            let poly = if c2 {
                &mut tampered.c2
            } else {
                &mut tampered.c1
            };
            poly[0] = (poly[0] + 1) % REGEV_Q;
            assert!(verify_withdraw_claim(LEVEL, &pk, &tampered, amount, &proof).is_err());
        }
    }

    /// Adversarial E-3 prove-side: the prover must refuse a wrong claimed amount and a secret
    /// key from a different keypair, with clean errors (never a panic or a bogus proof).
    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn withdraw_claim_prove_refuses_inconsistent_witness() {
        let amount = 1_000u64;
        let (pk, sk, ct) = claim_fixture(2_400, amount);

        // Claimed amount differs from the plaintext.
        assert!(matches!(
            prove_withdraw_claim(LEVEL, &pk, &sk, &ct, amount + 1),
            Err(RegevError::InvalidWitness(_))
        ));

        // Secret key of a different keypair: rejected either at decryption (garbage digits) or
        // at the pk/sk consistency check.
        let mut rng = SmallRng::seed_from_u64(2_401);
        let (_, wrong_sk) = channel_keygen(&mut rng);
        assert!(prove_withdraw_claim(LEVEL, &pk, &wrong_sk, &ct, amount).is_err());

        // Malformed (non-ternary) secret key: the decrypt precondition usually fails first with
        // garbage digits (DecryptOverflow); if decryption happens to decode, the witness
        // builder's ternary check (InvalidSk) refuses. Either way prove must error cleanly.
        let mut bad_sk = sk.clone();
        bad_sk.s[0] = 2;
        assert!(matches!(
            prove_withdraw_claim(LEVEL, &pk, &bad_sk, &ct, amount),
            Err(RegevError::InvalidSk(_))
                | Err(RegevError::InvalidWitness(_))
                | Err(RegevError::DecryptOverflow)
        ));
    }

    /// Adversarial F2-B for the P2b statements: purpose replay in every direction.
    /// (a) Same E-3 AIR, different domain word only — isolates the transcript binding.
    /// (b) E-3 proof presented to the refresh verifier and vice versa.
    /// (c) E-1/E-2 proofs presented to the E-3 verifier.
    /// (d) Statement-level dispatch sanity for both new purposes.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn withdraw_claim_and_refresh_purpose_binding() {
        let amount = 555u64;
        let (pk, sk, ct) = claim_fixture(2_500, amount);

        // (a) Identical statement and AIR, proved under the refresh domain word.
        let foreign = prove_withdraw_claim_with_domain(
            LEVEL,
            BALANCE_REFRESH_ZKP_DOMAIN,
            &pk,
            &sk,
            &ct,
            amount,
        )
        .unwrap();
        assert!(
            verify_withdraw_claim(LEVEL, &pk, &ct, amount, &foreign).is_err(),
            "a proof bound to a different purpose domain must not verify as WithdrawClaim"
        );
        // Sanity: the same bytes DO verify under the domain they were created for (the only
        // difference above is the domain word).
        verify_withdraw_claim_with_domain(
            LEVEL,
            BALANCE_REFRESH_ZKP_DOMAIN,
            &pk,
            &ct,
            amount,
            &foreign,
        )
        .unwrap();

        // (b) Cross-purpose replay between the two P2b statements (different AIR shapes AND
        // different transcripts).
        let e3_proof = prove_withdraw_claim(LEVEL, &pk, &sk, &ct, amount).unwrap();
        let mut rng = SmallRng::seed_from_u64(2_501);
        let (other_ct, _) = encrypt_amount(&mut rng, &pk, amount).unwrap();
        assert!(
            verify_balance_refresh(LEVEL, &pk, &ct, &other_ct, &e3_proof).is_err(),
            "an E-3 proof must not verify as a BalanceRefresh statement"
        );
        let (new_ct, refresh_proof) =
            prove_balance_refresh(&mut rng, LEVEL, &pk, &sk, &ct).unwrap();
        assert!(
            verify_withdraw_claim(LEVEL, &pk, &ct, amount, &refresh_proof).is_err(),
            "a refresh proof must not verify as a WithdrawClaim statement"
        );

        // (c) E-1 and E-2 proofs presented to the E-3 verifier.
        let txf = tx_fixture(2_502, 1_000, 250);
        let e1_proof = prove_fixture(&txf).unwrap();
        assert!(verify_withdraw_claim(LEVEL, &pk, &ct, amount, &e1_proof).is_err());
        let upf = update_fixture(2_503, 1_000, 250);
        let e2_proof = prove_update(&upf).unwrap();
        assert!(verify_withdraw_claim(LEVEL, &pk, &ct, amount, &e2_proof).is_err());

        // (d) Statement-level dispatch: matching purpose/statement verifies; mismatches are
        // rejected structurally before any proof work.
        let verifier = RealRegevProofVerifier { level: LEVEL };
        let wc_statement = RegevStatement::WithdrawClaim {
            user_pk: pk.clone(),
            user_amount_ct: ct.clone(),
            amount,
        };
        verifier
            .verify(RegevProofPurpose::WithdrawClaim, &e3_proof, &wc_statement)
            .unwrap();
        let rf_statement = RegevStatement::BalanceRefresh {
            pk: pk.clone(),
            old_ct: ct.clone(),
            new_ct: new_ct.clone(),
        };
        verifier
            .verify(
                RegevProofPurpose::BalanceRefresh,
                &refresh_proof,
                &rf_statement,
            )
            .unwrap();
        assert!(matches!(
            verifier.verify(RegevProofPurpose::BalanceRefresh, &e3_proof, &wc_statement),
            Err(RegevError::PurposeMismatch(_))
        ));
        assert!(matches!(
            verifier.verify(
                RegevProofPurpose::WithdrawClaim,
                &refresh_proof,
                &rf_statement
            ),
            Err(RegevError::PurposeMismatch(_))
        ));
    }

    /// Adversarial refresh: a valid refresh proof must not verify against a substituted
    /// `new_ct` (whether it encrypts the same value or a different one) or a tampered `old_ct`.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn balance_refresh_rejects_substituted_statement() {
        let mut rng = SmallRng::seed_from_u64(2_600);
        let (pk, sk) = channel_keygen(&mut rng);
        let value = 777_777u64;
        let (old_ct, _) = encrypt_amount(&mut rng, &pk, value).unwrap();

        let (new_ct, proof) = prove_balance_refresh(&mut rng, LEVEL, &pk, &sk, &old_ct).unwrap();
        verify_balance_refresh(LEVEL, &pk, &old_ct, &new_ct, &proof).unwrap();

        // Substituted new_ct encrypting value + 1 (prove-side cannot be coerced into this, so
        // the attack surface is the verify-side statement).
        let (forged_plus_one, _) = encrypt_amount(&mut rng, &pk, value + 1).unwrap();
        assert!(verify_balance_refresh(LEVEL, &pk, &old_ct, &forged_plus_one, &proof).is_err());

        // Even a different fresh encryption of the SAME value must fail: the proof binds the
        // exact ciphertext, not just the plaintext.
        let (same_value_other_ct, _) = encrypt_amount(&mut rng, &pk, value).unwrap();
        assert!(verify_balance_refresh(LEVEL, &pk, &old_ct, &same_value_other_ct, &proof).is_err());

        // Tampered old_ct.
        let mut tampered_old = old_ct.clone();
        tampered_old.c2[7] = (tampered_old.c2[7] + 1) % REGEV_Q;
        assert!(verify_balance_refresh(LEVEL, &pk, &tampered_old, &new_ct, &proof).is_err());

        // Wrong pk.
        let (other_pk, _) = channel_keygen(&mut rng);
        assert!(verify_balance_refresh(LEVEL, &other_pk, &old_ct, &new_ct, &proof).is_err());
    }

    /// Adversarial: truncated and garbage proof bytes must produce clean errors for both P2b
    /// verifiers, never panics.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn withdraw_claim_and_refresh_reject_garbage_proofs() {
        let amount = 9u64;
        let (pk, sk, ct) = claim_fixture(2_700, amount);
        let proof = prove_withdraw_claim(LEVEL, &pk, &sk, &ct, amount).unwrap();

        for bad in [
            &proof[..proof.len() / 2],
            &proof[..0],
            &[0xffu8; 64][..],
            &[0x01u8, 0x02, 0x03][..],
        ] {
            assert!(verify_withdraw_claim(LEVEL, &pk, &ct, amount, bad).is_err());
            assert!(verify_balance_refresh(LEVEL, &pk, &ct, &ct, bad).is_err());
        }

        let mut flipped = proof.clone();
        let mid = flipped.len() / 2;
        flipped[mid] ^= 0x01;
        assert!(verify_withdraw_claim(LEVEL, &pk, &ct, amount, &flipped).is_err());
    }
}
