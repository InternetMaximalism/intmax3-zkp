# Keyless public close prover

> **Integration precondition:** public close and every resulting value movement remain
> release-blocked while the separately tracked MLE/WHIR PCS soundness repair and a real
> public-chain acceptance run are unfinished. This tool prepares and locally checks the existing
> proof format; it does not repair the PCS or turn mock/local evidence into production evidence.

`public_close_prover` lets any participant turn the public live-balance backing response into the
same close proof and MLE/WHIR artifact used by the settlement contracts. It consumes no wallet,
Falcon, or Regev secret key. The required N-of-N Falcon signatures are already part of the signed
channel head.

## Input

Download `GET /api/v1/channel/<channel-id>/backing`. The command accepts only API schema version 2,
whose top-level object contains `chainId`, `rollup`, and the flattened
`LiveChannelBackingArtifact`. A stale setup-time `channel_backing.json` is not this schema and is
rejected.

Before proving, obtain these values independently of that HTTP response:

- channel id;
- chain id;
- rollup address;
- SHA-256 of the canonical `balance_vd.bin` shipped by the audited release.

For every chain except local development chain `31337`, the verifier-data SHA-256 argument is
mandatory. Computing the expected hash from the downloaded response itself does not provide a pin
and must not be used in production.

Delegates use the same parser and verifier as a lightweight archive-admission gate:

```sh
target/release/public_close_prover \
  --input public-backing.json \
  --verify-only \
  --expected-channel-id 7 \
  --expected-chain-id 1 \
  --expected-rollup 0x1111111111111111111111111111111111111111 \
  --expected-balance-vd-sha256 0x<64-hex-digits>
```

`--verify-only` emits one compact JSON receipt after verifying the backing/signatures/VD/balance
proof. It does not construct either close circuit. The Node delegate runs it on the exact fsynced
canonical backing file before archive publication and reconciles every receipt field with its own
transport checks.

```sh
cargo run --release --locked --bin public_close_prover -- \
  --input public-backing.json \
  --output-dir public-close-output \
  --expected-channel-id 7 \
  --expected-chain-id 1 \
  --expected-rollup 0x1111111111111111111111111111111111111111 \
  --expected-balance-vd-sha256 0x<64-hex-digits>
```

The output directory contains:

- `close_proof.bin` — the locally self-verified Plonky2 close proof;
- `close_intent_mle.json` — the locally self-verified MLE/WHIR artifact;
- `close_intent.json` — the proof-derived descriptor schema consumed by `RunClose.s.sol`;
- `close_intent_full.json` — the lossless close intent reconstructed from the signed head;
- `close_public_inputs.json` — the exact close public-input limbs;
- `public_close_manifest.json` — deployment bindings, sizes, filenames, and verification status.

## Fail-closed checks

The command rejects the input before expensive proving if any of these conditions fail:

- API schema/source, chain id, rollup, or any nested channel id differs from the independent
  expectation;
- the live head is awaiting N-of-N binding, or its recorded digest/settled chain differs from the
  signed head;
- the declared proof size differs from the supplied proof, or any input/output component exceeds
  its bounded transport size;
- the channel record, balance state, or any N-of-N Falcon signature is invalid;
- verifier data is non-canonical or misses the production SHA-256 pin;
- the balance proof fails against that verifier data, embeds a different cyclic VD, channel,
  settled chain, or private commitment;
- the generated close proof, its serialized round trip, the MLE proof, MLE public inputs, or the
  reconstructed close-intent digest fails local reconciliation.

This path does not alter a circuit, verifier key, or public-input layout. It therefore does not
change proof size or proof time relative to the existing `CloseProver`; it only adds bounded native
validation and artifact persistence around that prover.
