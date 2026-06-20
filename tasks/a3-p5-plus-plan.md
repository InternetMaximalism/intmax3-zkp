# A-3 P5 以降 計画書(relay + 完全 E2E + stub revert + 後始末)

母艦: `tasks/a3-close-lifecycle-spec.md`(承認済み全スコープ)、`tasks/a3-impl-todo.md`(進捗)。
前提: P1–P4 完成(P4 は `tasks/a3-p4-withdraw-handoff.md` の `withdraw` で締め)。

---

## P5 — relay エンドポイント + anvil 完全 E2E

### P5-A. relay エンドポイント(`wallet/wallet-relay.js`)
既存 `/api/inter/send` 等と同型(channel dir で CLI を起動、cwd 切替)。追加:
- `POST /api/close` → `channel_member close <manager>`(共署名は relay が全 member 所有なので 1 コマンド)
- `POST /api/settle` → `channel_member settle <manager>`
- `POST /api/withdraw` → `channel_member withdraw <manager>`
- `POST /api/claim` → `channel_member claim <manager> <slot>`(CLAIM_RECIPIENT env)
- 各々 ROLLUP/MANAGER/SV を env で渡す。`wallet-relay-ec2.js` も同様。

### P5-B. 完全 E2E テスト(`tests/close_lifecycle_cli_e2e.rs`、新規・heavy・anvil)
**これが close ライフサイクル全 CLI コマンドの live 検証点**。流れ:
1. anvil 起動 + 既存 deploy(`DeployClose.s.sol`)で IntmaxRollup + ChannelSettlementVerifier + ChannelSettlementManager をデプロイ。
2. **VK 初期化**(deploy 後の必須前提):
   - `IntmaxRollup.initializeWithdrawalVk(...)`(既存 withdrawNative 用)
   - `ChannelSettlementVerifier.initializeCloseVk(...)`(close 用、`generate_close_fixture` の VK)
   - `initializeWithdrawalClaimVk(...)`(claim 用)
   - 各 VK は対応する `generate_*_fixture` が出す degreeBits/preprocessedRoot/gatesDigest/whirParams/kIs/subgroupGenPowers。CLI が生成する MLE の VK と一致必須。
3. `registerChannel`(member set / bp / recipients を登録 → manager の member_set_commitment と一致)。
4. CLI 駆動: `setup-backing`(real deposit)→ `init` → 任意の send → **`close`**(requestClose+submitCloseIntent)→ challenge 期間を `anvil`/`cast rpc evm_increaseTime` で進める → **`settle`**(finalizeClose)→ **`withdraw`**(withdrawNative+pullChannelFunds)→ **`claim`**(submitWithdrawalClaim+claimWithdrawalCredit)。
5. **assert**: member の L1 ETH 残高が claim 後に増える(`totalCreditedOut ≤ receivedChannelFunds` の大域ソルベンシー上限内)。強 negative(改竄 close 拒否、stale challenge 等)を `inter_channel_live.rs` のエラー文字列固定パターンで。
- challenge 期間操作: anvil の `evm_increaseTime` + `evm_mine`(cast rpc 経由)。
- **要ユーザー許可**(重い proving + anvil)。`#[cfg_attr(debug_assertions, ignore)]` + release。

### P5 検証の鍵
VK 初期化と registerChannel の整合が最大の落とし穴(member_set_commitment / gatesDigest / finalizedStateRoots の一致)。`CloseLifecycleE2E.t.sol` が fixture 版でこの整合を緑にしているので、その set-up を CLI 駆動版へ写経するのが安全。

---

## P6 — §H-3 stub revert 化(conformance 乖離の解消) + 後始末

### P6-A. specialClose(C2)/ lateOutgoingDebit(C3)の revert 化【セキュリティ】
conformance 監査で判明した **live 乖離**: detail2 §H-3 は両者を「forgeable stub なので entry point を revert せよ」と明記。現状 `ChannelSettlementManager.sol` の `submitSpecialClose` / `submitLateOutgoingDebitCorrection` は **live**(誰でも呼べて `_matches` 偽造スタブが通る)。資金流出は無いが **freeze-grief** 可能。
- 対応: 両 entry point を即時 `revert`(専用 error、例 `SpecialCloseDisabled` / `LateDebitDisabled`)に。stub verifier は残してよいが entry を塞ぐ。
- **影響**: Manager bytecode 変更 → CREATE2 manager アドレス drift → **close-lifecycle fixture 再生成**(A-2 と同手順: `WD_RECIPIENT=<新manager> WD_OUT_PREFIX=close_ cargo run --release --bin generate_withdrawal_fixture` で新アドレス確認 → 再生成)。forge 全緑を再確認。
- detail2 §H-3 を「disposition 実装済み」に更新。

### P6-B. 後始末
- `cmd_close_lifecycle_unimplemented` を撤去(全コマンド実装後)。
- `tasks/a3-close-lifecycle-followup.md` を closed に。
- `tasks/a3-impl-todo.md` 全チェック。
- §K-4 anchor on-chain チェックの不採用(承認済み)を detail2-implementation-notes.md に「承認済み逸脱」として明記。
- (任意)P2 セキュリティレビューが挙げた防御的改善(cancel era-fence 早期チェック、post-close `incoming_tx_index < accumulator.len()`、Regev pk 長検証)を入れるなら P6 で。

---

## 全体の残工数感(目安)
| 項目 | 規模 | 重さ |
|---|---|---|
| P4 `withdraw`(別ハンドオフ) | 大(rollup withdrawal subsystem 移植) | 重い proving |
| P5-A relay | 小(既存パターン) | 軽 |
| P5-B 完全 E2E | 中〜大(VK init/register の整合 + 全コマンド駆動) | 重い(anvil + 実証明) |
| P6-A stub revert + fixture 再生成 | 小〜中 | fixture 再生成 1 回 |
| P6-B 後始末 | 小 | 軽 |

## 不変の鉄則(全 P 共通)
- IntmaxRollup / Manager の bytecode を変えたら close-lifecycle fixture 再生成(metadata-hash 由来の CREATE2 drift)。
- 重い proving / anvil E2E は実行前にユーザー許可。
- soundness は in-circuit。CLI/relay は配線のみ(P2 builder が検証済み)。proof を触る変更は脅威モデル → 別エージェントレビュー。
- 秘密鍵は `.claude/priv` を読まず shell 展開のみ(CLAUDE.md)。
