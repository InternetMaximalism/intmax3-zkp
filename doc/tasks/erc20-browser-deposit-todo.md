# ERC-20 deposits from the browser wallet — plan + threat model

Branch `feat/multitoken-channels`. Goal: a user brings their OWN registered ERC-20 (e.g. $ITX)
into a channel from the browser wallet. Today `sendDepositViaWallet` hardcodes `tokenIndex = 0`
and always pays `msg.value`.

## What already holds (verified by reading the code, not assumed)

- `IntmaxRollup.deposit` (`contracts/src/IntmaxRollup.sol:969`): `tokenIndex != 0` requires the
  index registered (`tokenAddressOf`), `msg.value == 0`, and credits a **measured `balanceOf`
  delta** around `safeTransferFrom`. So the wallet must `approve` the ROLLUP first.
- `cosign-l1-deposit-import <slot|auto> <txHash> <rpc> [out] [min_conf] [--allow-unbound-depositor]`
  (`src/bin/channel_member.rs:4212`) reads `amount` / `depositor` / `token_index` from the
  transaction's `Deposited` log. **The browser cannot lie about what it deposited**, and the
  ERC-20 import therefore already works with no relay/CLI change.
- `min_confirmations_for` (`channel_member.rs:4039`): floor 0 / default 0 on anvil (31337),
  floor 1 / default 12 everywhere else. An explicit argument is clamped UP. Neither relay passes
  one — so the enforced depth is always the chain default. **Not lowered by this change.**
- `/api/tokens` serves `symbol`/`name`/`decimals` only via `TokenRegistry.metadataFor`, which
  gates them on the manifest address having been read back EQUAL from the rollup's set-once
  `tokenAddressOf`. NOTE: `verified === true` can still carry `decimals: null`
  (`token-registry.js:344`, `decimalsVerified`), so `verified` alone is NOT sufficient.

## Threat model for the new browser path

| # | Attack | Defence (where) |
|---|--------|-----------------|
| B1 | Relay lists a token with a spoofed symbol so the user deposits the wrong asset | `depositableTokens()` admits a non-native entry only when `verified === true` AND the symbol survives `clampLabel` AND `decimals` is an integer 0..36 AND `address` is a non-zero 20-byte hex. Unverified entries never enter the `<select>`. |
| B2 | Relay lists a token with `decimals: null`, page assumes 18 → 10^12 error for $ITX | same filter refuses it; amounts are denominated with the token's own verified `decimals` via `toUnits`, never the global 18-dp `toBase`. |
| B3 | Relay points `approve` at an attacker spender | the spender is ALWAYS `info.rollup` from `/api/deposit-info`; the token list is never a source of a spender, and no user input is. (`info.rollup` is the same address the deposit is sent to — one source, checked shape.) |
| B4 | Token address swapped for a look-alike contract | the address comes only from the verified `/api/tokens` entry for the SELECTED `tokenIndex`; a mismatched address makes `deposit()` revert on-chain anyway (the rollup uses its own `tokenAddressOf`). |
| B5 | Non-zero `value` on an ERC-20 deposit | `value: '0x0'` passed explicitly; the contract also reverts (`NonEthDepositMustNotCarryEth`) — belt and braces. |
| B6 | Amount silently truncated / rounded so the user signs a different number than shown | `toUnits` REFUSES more fractional digits than the token supports instead of slicing; `> u64::MAX` is refused BEFORE any tx is signed (the import would refuse it and the L1 escrow would be stranded). |
| B7 | User signs blind | the modal renders the exact token label, base amount, spender and token address before the buttons are enabled; the same is logged immediately before each `eth_sendTransaction`. |
| B8 | Confirmation wait treated as failure → user re-deposits, double spend of their own ETH | the import retries only on the CLI's *specific* `has N confirmation(s), need M` refusal and renders `confirming (n/M)`; every other error surfaces immediately. The confirmation default is NOT lowered. |

## Steps

- [x] Read + verify the existing deposit/import/token paths
- [x] Factor the pure browser logic into one extractable region in `wallet-live.html`
- [x] Token selector (verified-only) + per-token amount parsing + preview
- [x] ERC-20 allowance read → conditional `approve` → `deposit(..., value 0)`
- [x] Confirmation-aware import retry + pending UI; Resume Import shares it
- [x] Relays: `minConfirmations` (display only) on `/api/deposit-info`, optional `tokenIndex` on
      the deposit ticket (display only, never forwarded to the import)
- [x] `node/test/deposit-ui.test.js` (extracts the shipped region, runs it in `node:vm`)
- [x] E2E: browser-shaped ERC-20 deposit in `tests/itx_faucet_cli_e2e.rs`

## Outcome

- `cd node && npm test` → **158/158** (was 131; +27 in `node/test/deposit-ui.test.js`).
- `cargo test --release --test itx_faucet_cli_e2e -- --ignored` → **ok, 175.26 s**. The new block
  reports: slot 1 approved + deposited 250 000 000 base units of $ITX with `msg.value 0` from its
  OWN bound address, imported with the relay's exact argv and **no** `--allow-unbound-depositor`;
  in-channel balance 100 000 000 → 350 000 000 and per-token fund 1 000 000 000 000 →
  1 000 250 000 000, i.e. both up by exactly the deposit.
- No Rust `src/` and no Solidity changed, so `forge test` is untouched.

### Deviations (also flagged in the report)

1. **The pure logic lives in a marked region inside `wallet-live.html`**, extracted by the unit
   test and run in `node:vm`, instead of a separate importable module — the page is deployed as a
   single file and a missed second file would break the whole inline module.
2. **`toBase` is now `toUnits(x, 18)`**: it REFUSES more than 18 fractional digits instead of
   slicing them off. Strictly fail-closed, but it is a behaviour change for send/burn/join.
3. **A join/deposit above `u64::MAX` base units is now refused before signing.** Previously the L1
   deposit went through and the import refused it, stranding the escrow.
4. **`/api/deposit-info` is now shape-checked in the page.** If a relay ever served a 20-byte
   `depositRecipient` (the EC2 relay's `b.deposit_recipient || b.rollup` fallback), the deposit is
   now refused instead of being padded into a recipient no channel can import.
