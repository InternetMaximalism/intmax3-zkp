# intmax3-zkp

Zero-knowledge proof circuits for INTMAX3, built with [Plonky2](https://github.com/0xPolygonZero/plonky2).

## Requirements

- Rust nightly (`nightly-2025-03-23`, managed via `rust-toolchain.toml`)
- [wasm-pack](https://rustwasm.github.io/wasm-pack/) (for WebAssembly builds and tests)

## Setup

### Install wasm-pack

```bash
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
```

Or via Cargo:

```bash
cargo install wasm-pack
```

## Build

```bash
cargo build
```

## Test

### Native tests

```bash
cargo test --release
```

### WASM tests

Run tests in a headless Firefox browser:

```bash
wasm-pack test --release --firefox --headless
```

You can also use `--chrome` or `--safari` instead of `--firefox`.
