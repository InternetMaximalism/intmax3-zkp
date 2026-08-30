#!/usr/bin/env bash
# Build the secret-preserving delegate wallet for Node.js. This mirrors build-wallet-wasm.sh but
# emits CommonJS glue consumed by node/common/wallet.js.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT_DIR="pkg-node"
TARGET="wasm32-unknown-unknown"
WASM="target/$TARGET/release/intmax3_zkp.wasm"

echo "[1/2] cargo rustc (cdylib, build-std, release)…"
CARGO_UNSTABLE_BUILD_STD=std,panic_abort \
  cargo rustc --release --lib --target "$TARGET" \
  -Z build-std=std,panic_abort \
  --crate-type cdylib

echo "[2/2] wasm-bindgen → $OUT_DIR (target nodejs)…"
wasm-bindgen "$WASM" --out-dir "$OUT_DIR" --target nodejs

echo "Done. $OUT_DIR/ ready."
