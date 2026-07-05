#!/usr/bin/env bash
# Build the wasm package for the browser wallet.
#
# Why not `wasm-pack`: wasm-pack requires `[lib] crate-type = ["cdylib", ...]` in Cargo.toml, but
# this crate keeps `crate-type = ["rlib"]` because adding `cdylib` breaks native bin linking
# (undefined-symbol errors in src/bin/*, the documented E0463-class collision). `cargo rustc`
# lets us append `--crate-type cdylib` at INVOCATION time (exactly what the Cargo.toml comment
# describes) without touching the manifest, then we run `wasm-bindgen` directly to emit the JS glue.
set -euo pipefail
# Run from the repo root: this script lives in hosting/, but target/ and the output
# pkg/ live at the repo root (one level up).
cd "$(dirname "$0")/.."

OUT_DIR="pkg"
TARGET="wasm32-unknown-unknown"
WASM="target/$TARGET/release/intmax3_zkp.wasm"

echo "[1/3] cargo rustc (cdylib, build-std, release)…"
CARGO_UNSTABLE_BUILD_STD=std,panic_abort \
  cargo rustc --release --lib --target "$TARGET" \
  -Z build-std=std,panic_abort \
  --features regev-parallel \
  --crate-type cdylib
  # `regev-parallel` enables rayon-parallel Regev STARK proving. On wasm it runs on the
  # wasm-bindgen-rayon global pool (the worker calls initThreadPool first); regev's pool.rs
  # build_global() is then a harmless no-op. Multithreaded proving = the requested speedup.

echo "[2/3] wasm-bindgen → $OUT_DIR (target web)…"
wasm-bindgen "$WASM" --out-dir "$OUT_DIR" --target web

echo "[3/3] wasm-opt (bulk-memory + simd)…"
if command -v wasm-opt >/dev/null 2>&1; then
  wasm-opt -O3 --enable-bulk-memory --enable-simd --enable-threads \
    "$OUT_DIR/intmax3_zkp_bg.wasm" -o "$OUT_DIR/intmax3_zkp_bg.wasm"
else
  echo "  (wasm-opt not found; skipping — package still works)"
fi

echo "Done. pkg/ ready."
