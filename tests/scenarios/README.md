# Close-lifecycle test-gap scenarios

Specs for currently-UNTESTED scenarios of the A-3 channel close lifecycle
(deposit → close → settle → withdraw → claim): liveness loss, fund loss,
ordering/duplication mistakes, and randomized/property generators. **Specs only —
not yet implemented as tests.**

`tests/` compiles only top-level `*.rs` as test crates, so this subfolder's `*.md`
files are ignored by `cargo test`.

## Index (by category)
- `A-real-proof-coverage.md` — entry points only mock-verified on-chain; need real MLE/WHIR fixtures (A1–A6).
- `B-liveness.md` — channel/funds stuck if a party refuses / is offline / acts out of order; the C2-disabled BP-censorship grief (B6–B12).
- `C-fund-loss.md` — close situations that could lose or misbind funds (C13–C20).
- `D-multichannel.md` — shared-rollup interference between channels (D20–D25).
- `E-deposit-block-ordering.md` — deposit/block/finalize ordering & duplication hazards (E25–E31).
- `F-state-machine-ordering.md` — close state-machine transition combinations (F30–F37).
- `G-randomized-property.md` — fuzz / property generators + global invariants I1–I5 (G36–G43).

Each scenario has a stable ID matching the original enumeration and a structured
block (Setup · Steps · Assert · Layer · Model-on · Severity · Notes).
