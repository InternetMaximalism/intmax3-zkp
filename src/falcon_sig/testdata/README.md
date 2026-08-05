# `legacy_single_sig_proof.bin`

A **real** serialized `poseidon_sig::circuit::SingleSigCircuit` proof — the retired
"the proof IS the signature" cosign wire object — captured on 2026-08-06 from the tree at
`79f11ad` (falcon-sig Phase 3), immediately before that circuit was deleted in Phase 4.

Provenance (exactly reproducible from that commit):

```rust
let circuit = SingleSigCircuit::new();
let sk      = GoldilocksSecretKey::from_seed([0x99u8; 32]);
let digest  = Bytes32::from_u32_slice(&[0x0106, 1, 2, 3, 4, 5, 6, 7]).unwrap();
circuit.prove(&sk, digest).unwrap().to_bytes()   // 77_872 bytes
```

Why it is committed: obligation **O-9 / TM-C8** requires an explicit test that a valid OLD
proof blob is rejected by the new verifier — "not merely fails to parse". Once the legacy
circuit is deleted, the only way to keep testing that against a *genuine* artifact rather than
a random byte string is to keep the artifact. Replacing it with random bytes would strictly
weaken the test.

It is inert data: nothing in the tree can verify, parse, or produce this format any more.
