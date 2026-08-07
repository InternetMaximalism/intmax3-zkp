#!/usr/bin/env bash
# SECURITY GATE (falcon-sig Phase-4 review, check 9) — MUST PASS BEFORE ANY BROWSER DEPLOY.
#
# Verifies that Falcon key generation derives the SAME member identity
# `pk_g = Poseidon(IMFK || encode(h))` on wasm32 as it does natively.
#
# WHY THIS IS MEASURED RATHER THAN ARGUED. NTRU keygen runs f64 arithmetic (FFT, Babai
# reduction, rejection bounds). The structural argument for determinism is strong — the keygen
# path uses only IEEE-754 + - * / floor round sqrt over a hardcoded twiddle table, `approx_exp`
# is integer FACCT rather than libm::exp, and Rust neither contracts to FMA nor reassociates
# without fast-math. But THIS REPOSITORY HAS ALREADY OBSERVED a wasm-vs-native numeric
# divergence in a proof path: see the note in `.cargo/config.toml` recording that the Regev
# STARK verifier returns different results on wasm32 and native for identical bytes, and that
# disabling simd128 did NOT fix it. A negative claim over a large vendored numeric surface is
# exactly the kind of argument that failed there.
#
# FAILURE MODE IF IT DIVERGES: a wallet created or restored in the browser derives a DIFFERENT
# pk_g from the same seed than the CLI does. The L1 registration then names an identity that
# wallet cannot reproduce, its co-signatures stop verifying, and the channel becomes permanently
# unclosable — funds stuck, with no error at the moment of divergence.
#
# The constant below is the SAME anchor the native suite pins
# (falcon_sig::review_hardening_tests::h2p_and_pk_digest_pinned_vectors), so native and wasm are
# each compared against one value rather than against each other.
#
# Usage:  ./hosting/check-falcon-wasm-identity.sh
set -euo pipefail

PINNED="0x90eed9636e2a86f4043c297a284a6cc24666678312c6bd8a62fc56dc241decf0"
TARGET=wasm32-unknown-unknown
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

echo "[1/3] building the wasm cdylib (build-std, release)…"
cargo rustc --release --lib --target "$TARGET" -Z build-std=std,panic_abort --crate-type cdylib

echo "[2/3] generating bindings…"
wasm-bindgen "target/$TARGET/release/intmax3_zkp.wasm" --out-dir "$OUT" --target web

echo "[3/3] running the identity KAT under node…"
cat > "$OUT/kat.mjs" <<'JS'
import fs from 'node:fs';
// The bundle pulls wasm-bindgen-rayon's worker helper, which touches `self` at module scope. No
// thread pool is started here, so a no-op stub is enough to let the module load under Node.
globalThis.self = globalThis.self || { addEventListener(){}, removeEventListener(){}, postMessage(){} };
const mod = await import('./intmax3_zkp.js');
await mod.default({ module_or_path: fs.readFileSync(new URL('./intmax3_zkp_bg.wasm', import.meta.url)) });
const PINNED = process.env.PINNED;
const got = mod.falcon_pk_g_for_seed_byte(42);
console.log("  wasm32 pk_g(seed=[42;32]) =", got);
console.log("  native pinned             =", PINNED);
const a = mod.falcon_pk_g_for_seed_byte(7);
const b = mod.falcon_pk_g_for_seed_byte(7);
const c = mod.falcon_pk_g_for_seed_byte(8);
if (got !== PINNED) {
  console.error("\nDIVERGENCE: wasm32 derived a DIFFERENT identity from the same seed than native.");
  console.error("Do NOT ship a browser build. A restored wallet would be a different member than");
  console.error("the one registered on L1, and its channel could never be closed.");
  process.exit(1);
}
if (a !== b || a === c) { console.error("\nkeygen is not a pure function of the seed"); process.exit(1); }
console.log("\nPASS — wasm32 and native derive the same Falcon identity.");
JS
( cd "$OUT" && PINNED="$PINNED" node kat.mjs )
