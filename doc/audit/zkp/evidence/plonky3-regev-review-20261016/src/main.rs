use regev_plonky3::*;
use p3_field::PrimeCharacteristicRing;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn main() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x20261016);
    let params = RegevParams::N2048;
    params.validate();
    let (pk, sk) = keygen(&mut rng, &params);
    let message = encode_value_message(12345, params.n);
    let (ct, witness) = encrypt(&mut rng, &params, &pk, &message);
    assert_eq!(decrypt(&params, &sk, &ct), message);
    assert_eq!(decrypt_value(&params, &sk, &ct), 12345);
    let config = zk_config();
    let proof = prove_encryptions(&config, &params, &pk, &[ct.clone()], &[witness.clone()]);
    verify_encryptions(&config, &params, &pk, &[ct.clone()], &proof).unwrap();
    let mut different_ct = ct.clone();
    different_ct.c2[0] += Val::ONE;
    assert!(verify_encryptions(&config, &params, &pk, &[different_ct], &proof).is_err());
    let mut different_pk = pk.clone();
    different_pk.a[0] += Val::ONE;
    assert!(verify_encryptions(&config, &params, &different_pk, &[ct.clone()], &proof).is_err());
    let different_params = RegevParams { plain_bits: 7, ..params };
    assert!(verify_encryptions(&config, &different_params, &pk, &[ct.clone()], &proof).is_err());
    println!("PASS N2048 production ZK encryption/decryption, public-key binding, ciphertext binding, plaintext scaling binding");

    let range = RangeSpec { value_bits: 14, bound: 13000 };
    let range_proof = prove_encryptions_with_range(&config, &params, &pk, &[ct.clone()], &[witness], range);
    verify_encryptions_with_range(&config, &params, &pk, &[ct.clone()], &range_proof, range).unwrap();
    let narrower = RangeSpec { value_bits: 14, bound: 12000 };
    assert!(verify_encryptions_with_range(&config, &params, &pk, &[ct], &range_proof, narrower).is_err());
    println!("PASS production ZK range proof and range-parameter binding");

    let mut cts = Vec::new();
    let mut witnesses = Vec::new();
    for value in [1000, 400, 600] {
        let (ct, witness) = encrypt(&mut rng, &params, &pk, &encode_value_message(value, params.n));
        cts.push(ct);
        witnesses.push(witness);
    }
    let transfer = Transfer { before: cts[0].clone(), delta: cts[1].clone(), after: cts[2].clone() };
    let tw = TransferWitness { before: witnesses[0].clone(), delta: witnesses[1].clone(), after: witnesses[2].clone() };
    let transfer_proof = prove_transfers(&config, &params, &pk, &[transfer.clone()], &[tw]);
    verify_transfers(&config, &params, &pk, &[transfer.clone()], &transfer_proof).unwrap();
    let changed_transfer = Transfer { delta: transfer.after.clone(), after: transfer.delta.clone(), before: transfer.before };
    assert!(verify_transfers(&config, &params, &pk, &[changed_transfer], &transfer_proof).is_err());
    println!("PASS production ZK transfer proof and ordered statement binding");

    let unsupported_eta = RegevParams { eta: 32, ..params };
    unsupported_eta.validate();
    println!("OBSERVED RegevParams::validate accepts unsupported eta=32; implementations always sample CBD(2)");
}
