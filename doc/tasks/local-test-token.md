# Local TEST token (2026-09-23)

Anvil chain 31337 only for this deployment.

- Contract: `0x67d269191c92Caf3cD7723F116c85e6E9bf55933`
- Source: `contracts/test/tokens/IntmaxTestTokenTEST.sol`
- Symbol: TEST; decimals: 6; no configured issuance cap; permissionless mint.
- `mint()` issues 10 TEST to the caller on every invocation.
- `mint(address,uint256)` issues an arbitrary number of base units to a recipient.
- Rollup: `0xa85233C63b9Ee964Add6F2cffe00Fd84eb32338f`
- Base token index 1, channel 7 local token slot 1.

Initial provisioning minted 10 TEST to the local operator, approved and deposited all 10
into the rollup, then imported the verified deposit into the user's channel account **7-3**.
The standard pre-sign exit-kit preparation and live deposit proof pipeline were used.
No user wallet impersonation or balance-setting RPC was used.

Deposit transaction:
`0x3abe8ea60e2f111e0258d355b491015c664fcfe79e840681a42375f37380b55b`

Full local receipts: `wallet-live-work/test-token-deployment.json`.
Verified display manifest: `wallet-live-work/ch7/tokens.json`.
The relay was restarted and `/api/tokens?channel=7` returns TEST with `verified: true`.

To mint another 10 TEST directly to the browser's L1 wallet using the unlocked local
operator (this does not deposit them):

```sh
cast send 0x67d269191c92Caf3cD7723F116c85e6E9bf55933 \
  'mint(address,uint256)' 0x9d4f46B2b701AA2875a18e8803338EaF3d466374 10000000 \
  --rpc-url http://127.0.0.1:8545 \
  --from 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 --unlocked
```

Then choose TEST in the wallet's Deposit dialog. Depositing ERC-20 requires native ETH
for gas. This token is intentionally a test faucet, not a production asset.

Validation: two Foundry tests cover repeat minting, total supply, approve/transferFrom,
zero-address mint refusal, and insufficient-balance refusal. Live checks found total
supply and rollup balance both 10,000,000 base units after initial provisioning.


Replacement environment (2026-09-24): HTTPS8000 now uses channels17/18 and rollup
`0xCD8a1C3ba11CF5ECfa6267617243239504a98d90` on the same Anvil8545. The same TEST contract
is registered at base index1; Join adds its channel registry entry through the real exit-kit
pipeline. 10 additional TEST now belongs to the user's L1 wallet, ready for Deposit after Join.
The earlier channel7 deposit remains in the preserved old environment. A disposable channel18
account verified a separate real 10 TEST deposit/import; see `wallet-l1-settlement.md`.
