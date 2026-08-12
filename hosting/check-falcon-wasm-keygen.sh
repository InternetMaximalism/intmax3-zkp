#!/usr/bin/env bash
# SECURITY GATE — falcon-sig Phase-4 review, check 9.
#
# Proves that Falcon key generation derives the SAME member identity
# `pk_g = Poseidon(IMFK || encode(h))` on wasm32 as it does natively.
#
# WHY THIS IS MEASURED RATHER THAN ARGUED. NTRU keygen runs f64 arithmetic (FFT, Babai
# reduction, rejection bounds). The structural argument for determinism is strong — only
# IEEE-754 `+ - * / floor round sqrt` over a hardcoded twiddle table, `approx_exp` is integer
# FACCT rather than libm — but THIS REPOSITORY HAS ALREADY OBSERVED a wasm-vs-native numeric
# divergence in a proof path: see the note in `.cargo/config.toml` recording that the Regev STARK
# verifier returns different results on wasm32 and native for identical bytes, and that disabling
# simd128 did not fix it. A negative claim over a large vendored numeric surface is exactly the
# kind of argument that failed there.
#
# FAILURE MODE IF IT DIVERGES: a wallet created or restored in the browser derives a DIFFERENT
# pk_g from the same seed than the CLI does. The L1 registration then names an identity that
# wallet cannot reproduce, its co-signatures stop verifying, and the channel becomes permanently
# unclosable — funds stuck, with no error at the moment of divergence.
#
# RUN THIS BEFORE ANY BROWSER DEPLOY, and after any bump of the wasm toolchain, `num-complex`,
# `num-bigint`, or the vendored Falcon math.
#
# The expected value is the SAME anchor the native suite pins in
# `falcon_sig::review_hardening_tests::h2p_and_pk_digest_pinned_vectors`, so native and wasm are
# each compared against one constant rather than against each other.
set -euo pipefail
cd "$(dirname "$0")/.."

PINNED="0x90eed9636e2a86f4043c297a284a6cc24666678312c6bd8a62fc56dc241decf0"
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

echo "[1/3] building wasm32 cdylib (build-std, release)…"
cargo rustc --release --lib --target wasm32-unknown-unknown \
  -Z build-std=std,panic_abort --crate-type cdylib >/dev/null

echo "[2/3] wasm-bindgen…"
wasm-bindgen target/wasm32-unknown-unknown/release/intmax3_zkp.wasm \
  --out-dir "$OUT" --target web >/dev/null

cat > "$OUT/kat.mjs" <<'JS'
// Node shims for the browser globals the rayon worker helper touches at module scope. It is
// never invoked here (no thread pool is started); it only has to import cleanly.
globalThis.self = globalThis;
if (typeof globalThis.addEventListener !== 'function') {
  globalThis.addEventListener = () => {};
  globalThis.removeEventListener = () => {};
}
import fs from 'node:fs';
const { default: init, falcon_pk_g_for_seed_byte } = await import('./intmax3_zkp.js');
await init({ module_or_path: fs.readFileSync(new URL('./intmax3_zkp_bg.wasm', import.meta.url)) });
const PINNED = process.argv[2];
const got = falcon_pk_g_for_seed_byte(42);
console.log("  wasm32 pk_g(seed=[42;32]) =", got);
console.log("  native pinned             =", PINNED);
const a = falcon_pk_g_for_seed_byte(7);
const b = falcon_pk_g_for_seed_byte(7);
const c = falcon_pk_g_for_seed_byte(8);
const ok = got === PINNED && a === b && a !== c;
console.log(ok ? "  PASS — wasm32 and native derive the SAME identity"
               : "  FAIL — DIVERGENCE. Do not ship a browser build.");
process.exit(ok ? 0 : 1);
JS

echo "[3/3] running the KAT under node…"
( cd "$OUT" && node kat.mjs "$PINNED" )
