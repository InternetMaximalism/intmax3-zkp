//! Standalone audit probes. Production sources are imported without modification.
use std::fmt::Debug;
use intmax3_zkp::ethereum_types::{
    address::{Address, AddressTarget},
    bytes16::{Bytes16, Bytes16Target},
    bytes32::{Bytes32, Bytes32Target},
    u256::{U256, U256Target},
    u64::{U64, U64Target},
    u32limb_trait::{U32LimbTrait, U32LimbTargetTrait},
};
use num_bigint::BigUint;
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::{Field, PrimeField64}},
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig},
};
use plonky2_bn254::fields::fq::FqTarget;
use serde::{Serialize, de::DeserializeOwned};

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

fn builder() -> CircuitBuilder<F, D> {
    CircuitBuilder::new(CircuitConfig::standard_recursion_config())
}

fn prove_verify(b: CircuitBuilder<F, D>, pw: PartialWitness<F>) -> Vec<u64> {
    let data = b.build::<C>();
    let proof = data.prove(pw).expect("probe proof generation");
    let pi = proof.public_inputs.iter().map(|x| x.to_canonical_u64()).collect();
    data.verify(proof).expect("probe proof verification");
    pi
}

fn encodings<V, T, const N: usize>(name: &str)
where
    V: U32LimbTrait<N> + Debug + PartialEq + Serialize + DeserializeOwned,
    T: U32LimbTargetTrait<N>,
{
    let mut b = builder();
    let mut pw = PartialWitness::new();
    let values = [vec![0; N], vec![u32::MAX; N], (0..N).map(|i| 0x01234567u32.rotate_left((i * 7) as u32)).collect()];
    for limbs in values {
        let v = V::from_u32_slice(&limbs).unwrap();
        assert_eq!(V::from_u64_slice(&v.to_u64_vec()).unwrap(), v);
        assert_eq!(V::from_bytes_be(&v.to_bytes_be()).unwrap(), v);
        assert_eq!(V::from_bits_be(&v.to_bits_be()).unwrap(), v);
        assert_eq!(V::from_hex(&v.to_hex()).unwrap(), v);
        assert_eq!(serde_json::from_str::<V>(&serde_json::to_string(&v).unwrap()).unwrap(), v);
        let t = T::new(&mut b, true);
        t.set_witness(&mut pw, v);
        let bytes = t.to_bytes_be(&mut b);
        for (&target, byte) in bytes.iter().zip(v.to_bytes_be()) {
            pw.set_target(target, F::from_canonical_u8(byte)).unwrap();
        }
        let from_bytes = T::from_bytes_be(&mut b, &bytes);
        from_bytes.connect(&mut b, t);
        let bits = t.to_bits_be(&mut b);
        for (&target, bit) in bits.iter().zip(v.to_bits_be()) {
            pw.set_bool_target(target, bit).unwrap();
        }
        let from_bits = T::from_bits_be(&mut b, &bits);
        from_bits.connect(&mut b, t);
    }
    assert_eq!(V::from_bytes_be(&[1]).unwrap(), V::one());
    assert_eq!(V::from_hex("0x").unwrap(), V::zero());
    assert!(V::from_bytes_be(&vec![0; N * 4 + 1]).is_err());
    assert!(V::from_bits_be(&vec![false; N * 32 + 1]).is_err());
    assert!(V::from_u32_slice(&vec![0; N + 1]).is_err());
    assert!(V::from_u64_slice(&vec![0; N + 1]).is_err());
    let mut bad_limbs = vec![0; N];
    bad_limbs[N - 1] = 1u64 << 32;
    assert!(V::from_u64_slice(&bad_limbs).is_err());
    assert!(V::from_hex("0xg0").is_err());
    assert!(V::from_hex("0x1").is_err());
    prove_verify(b, pw);
    println!("PASS encodings {name}: three native/circuit round trips and malformed-input rejection");
}

fn truncation<V, T, const N: usize>(name: &str)
where V: U32LimbTrait<N>, T: U32LimbTargetTrait<N> {
    let mut b = builder();
    let t = T::new(&mut b, false);
    let mut pw = PartialWitness::new();
    let mut raw = vec![0u64; N];
    raw[N - 1] = (1u64 << 32) + 7;
    for (&target, &value) in t.to_vec().iter().zip(&raw) {
        pw.set_target(target, F::from_canonical_u64(value)).unwrap();
    }
    let decoded: V = t.get_witness(&pw).unwrap();
    assert_eq!(decoded.to_u32_vec()[N - 1], 7);
    assert!(V::from_u64_slice(&raw).is_err());
    println!("CONFIRMED get_witness {name}: 4294967303 -> Ok(7); from_u64_slice rejects the same limb");
}

fn fq_conversion() {
    let mut b = builder();
    let q = FqTarget::<F, D>::zero(&mut b).modulus();
    let mut pw = PartialWitness::new();
    for delta in [0u32, 1] {
        let u = U256Target::new(&mut b, true);
        u.set_witness(&mut pw, U256::try_from(&q + delta).unwrap());
        b.register_public_inputs(&u.to_vec());
        let f: FqTarget<F, D> = u.into();
        assert!(f.mod_taken());
        let canonical = f.is_valid(&mut b);
        b.assert_zero(canonical.target);
        let expected = if delta == 0 { FqTarget::zero(&mut b) } else { FqTarget::one(&mut b) };
        let before = f.is_equal(&mut b, &expected);
        b.assert_zero(before.target);
        let zero = FqTarget::zero(&mut b);
        let normalized = f.add(&mut b, &zero).take_mod(&mut b);
        let after = normalized.is_equal(&mut b, &expected);
        b.assert_one(after.target);
        b.register_public_inputs(&[canonical.target, before.target, after.target]);
    }
    let pi = prove_verify(b, pw);
    assert_eq!(&pi[8..11], &[0, 0, 1]);
    assert_eq!(&pi[19..22], &[0, 0, 1]);
    println!("CONFIRMED U256 -> Fq: q={q}; verified q and q+1 with [is_canonical, equals_expected, equals_expected_after_add_zero]=[0,0,1]");
    println!("Fq proof public inputs: {pi:?}");
}

fn u64_arithmetic() {
    let values = [0u64, 1, (1u64 << 32) - 1, 1u64 << 32, (1u64 << 63) - 1, 1u64 << 63,
        0xffff_ffff_0000_0000, 0xffff_ffff_0000_0001, u64::MAX - 1, u64::MAX];
    let mut b = builder();
    let mut pw = PartialWitness::new();
    let ts: Vec<_> = values.iter().map(|&v| {
        let t = U64Target::new(&mut b, true);
        t.set_witness(&mut pw, U64::from(v)); t
    }).collect();
    let (mut adds, mut subs) = (0, 0);
    for (i, &a) in values.iter().enumerate() {
        for (j, &v) in values.iter().enumerate() {
            let le = ts[i].is_le(&mut b, &ts[j]);
            let lt = ts[i].is_lt(&mut b, &ts[j]);
            let want_le = b.constant_bool(a <= v);
            let want_lt = b.constant_bool(a < v);
            b.connect(le.target, want_le.target);
            b.connect(lt.target, want_lt.target);
            if let Some(sum) = a.checked_add(v) {
                assert_eq!(u64::from(U64::from(a) + U64::from(v)), sum);
                ts[i].add(&mut b, &ts[j]).set_witness(&mut pw, U64::from(sum)); adds += 1;
            }
            if let Some(diff) = a.checked_sub(v) {
                assert_eq!(u64::from(U64::from(a) - U64::from(v)), diff);
                ts[i].sub(&mut b, &ts[j]).set_witness(&mut pw, U64::from(diff)); subs += 1;
            }
        }
    }
    prove_verify(b, pw);
    println!("PASS U64: {} boundary pairs, <= and <, {adds} sums, {subs} differences, all virtual checked inputs", values.len() * values.len());
}

fn u256_arithmetic() {
    let pow = |n| BigUint::from(1u32) << n;
    let mut temp = builder();
    let q = FqTarget::<F, D>::zero(&mut temp).modulus();
    let max = pow(256) - 1u32;
    let values = vec![BigUint::from(0u32), BigUint::from(1u32), pow(32)-1u32, pow(32), pow(64)-1u32,
        pow(64), pow(128), pow(255)-1u32, pow(255), &q-1u32, q, max.clone()];
    let mut b = builder();
    let mut pw = PartialWitness::new();
    let natives: Vec<_> = values.iter().cloned().map(|v| U256::try_from(v).unwrap()).collect();
    let ts: Vec<_> = natives.iter().map(|&v| {
        let t = U256Target::new(&mut b, true); t.set_witness(&mut pw, v); t
    }).collect();
    let (mut adds, mut subs) = (0, 0);
    for (i, a) in values.iter().enumerate() {
        for (j, v) in values.iter().enumerate() {
            assert_eq!(natives[i].cmp(&natives[j]), a.cmp(v));
            let le = ts[i].is_le(&mut b, &ts[j]);
            let lt = ts[i].is_lt(&mut b, &ts[j]);
            let want_le = b.constant_bool(a <= v);
            let want_lt = b.constant_bool(a < v);
            b.connect(le.target, want_le.target);
            b.connect(lt.target, want_lt.target);
            let sum = a + v;
            if sum <= max {
                assert_eq!(BigUint::from(natives[i] + natives[j]), sum);
                ts[i].add(&mut b, &ts[j]).set_witness(&mut pw, U256::try_from(sum).unwrap()); adds += 1;
            }
            if a >= v {
                let diff = a-v;
                assert_eq!(BigUint::from(natives[i] - natives[j]), diff);
                ts[i].sub(&mut b, &ts[j]).set_witness(&mut pw, U256::try_from(diff).unwrap()); subs += 1;
            }
        }
    }
    prove_verify(b, pw);
    assert!(U256::try_from(pow(256)).is_err());
    assert!(Bytes16::try_from(pow(128)).is_err());
    assert!(serde_json::from_str::<U64>("18446744073709551616").is_err());
    assert!(serde_json::from_str::<U256>(&format!("\"{}\"", pow(256))).is_err());
    println!("PASS U256: {} boundary pairs, <= and <, {adds} sums, {subs} differences, all virtual checked inputs", values.len() * values.len());
}

fn mask_bits() {
    let mut b = builder();
    let mut pw = PartialWitness::new();
    for high in [0u32, (1<<29)-1, 1<<29, u32::MAX] {
        let mut limbs = [u32::MAX; 8]; limbs[0] = high;
        let v = Bytes32::from_u32_slice(&limbs).unwrap();
        let t = Bytes32Target::new(&mut b, true); t.set_witness(&mut pw, v);
        let masked = t.remove_3bits(&mut b);
        masked.set_witness(&mut pw, v.remove_3bits());
        assert_eq!(v.remove_3bits().to_u32_vec()[0], high & ((1<<29)-1));
    }
    prove_verify(b, pw);
    println!("PASS remove_3bits: four high-limb boundary cases, native/circuit agree");
}

fn rejection_probe(mode: &str) {
    let mut b = builder();
    let mut pw = PartialWitness::new();
    match mode {
        "u64-add-overflow" | "u64-sub-underflow" => {
            let a = U64Target::new(&mut b, true); let v = U64Target::new(&mut b, true);
            v.set_witness(&mut pw, U64::from(1u64));
            if mode.ends_with("overflow") { a.set_witness(&mut pw, U64::from(u64::MAX)); a.add(&mut b, &v); }
            else { a.set_witness(&mut pw, U64::from(0u64)); a.sub(&mut b, &v); }
        }
        "u256-add-overflow" | "u256-sub-underflow" => {
            let a = U256Target::new(&mut b, true); let v = U256Target::new(&mut b, true);
            v.set_witness(&mut pw, U256::one());
            if mode.ends_with("overflow") { a.set_witness(&mut pw, U256::from_u32_slice(&[u32::MAX;8]).unwrap()); a.add(&mut b, &v); }
            else { a.set_witness(&mut pw, U256::zero()); a.sub(&mut b, &v); }
        }
        "limb-range" | "cmp-range" | "cmp-wrong-result" => {
            let a = U64Target::new(&mut b, mode == "limb-range");
            let limbs = a.to_vec();
            pw.set_target(limbs[0], F::ZERO).unwrap();
            pw.set_target(limbs[1], F::from_canonical_u64(if mode == "cmp-wrong-result" { 0 } else { 1<<32 })).unwrap();
            if mode != "limb-range" {
                let one = U64Target::constant(&mut b, U64::from(1u64));
                let lt = a.is_lt(&mut b, &one);
                if mode == "cmp-wrong-result" { b.assert_zero(lt.target); }
            }
        }
        "byte-range" => {
            let bytes = b.add_virtual_targets(8);
            for (i, &t) in bytes.iter().enumerate() { pw.set_target(t, F::from_canonical_u64(if i==7 {256} else {0})).unwrap(); }
            U64Target::from_bytes_be(&mut b, &bytes);
        }
        _ => panic!("unknown mode {mode}"),
    }
    let data = b.build::<C>();
    match data.prove(pw) {
        Err(e) => println!("REJECTED {mode}: {e}"),
        Ok(proof) => match data.verify(proof) {
            Err(e) => println!("REJECTED {mode}: verification: {e}"),
            Ok(()) => { println!("UNEXPECTED_ACCEPT {mode}"); std::process::exit(99); }
        }
    }
}

fn main() {
    if let Some(mode) = std::env::args().nth(1) { rejection_probe(&mode); return; }
    encodings::<Address,AddressTarget,5>("Address");
    encodings::<Bytes16,Bytes16Target,4>("Bytes16");
    encodings::<Bytes32,Bytes32Target,8>("Bytes32");
    encodings::<U64,U64Target,2>("U64");
    encodings::<U256,U256Target,8>("U256");
    truncation::<Address,AddressTarget,5>("Address");
    truncation::<Bytes16,Bytes16Target,4>("Bytes16");
    truncation::<Bytes32,Bytes32Target,8>("Bytes32");
    truncation::<U64,U64Target,2>("U64");
    truncation::<U256,U256Target,8>("U256");
    fq_conversion();
    u64_arithmetic();
    u256_arithmetic();
    mask_bits();
    println!("ALL POSITIVE AND DEFECT-REPRODUCTION PROBES COMPLETED");
}
