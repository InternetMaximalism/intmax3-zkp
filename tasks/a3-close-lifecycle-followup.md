# A-3 フォローアップ: channel close / withdraw-to-L1 / settle ライフサイクル(本体実装)

状態: **OPEN(別PR)**。本タスク(監査修正パス)では「安全化のみ」を実施済み。本体は未実装。

## 背景 / 現状
- 入金は実オンチェーン(`setup-backing` が IntmaxRollup へ実 deposit)。
- しかし **L1 出金経路(close/withdraw/settle)が存在しない**。
- L1-close anchor(`ChannelFund.intmax_state_root`)は `setup-backing` で全ゼロの
  **PLACEHOLDER**(`PLACEHOLDER_L1_CLOSE_ANCHOR_HEX`, `src/bin/channel_member.rs`)。
  実 anchor を導出する registration-time 手続き(detail2 §K-4)が未実装のため。
- メモリ `project_channel_close_unification.md`「settlement is currently a stub」と一致。

## 監査パスで実施した安全化(このPRに含む)
- 全ゼロ anchor を named 定数化し「未実装プレースホルダ」であることを明示(greppable)。
- `channel_member` に `close`/`withdraw`/`settle` サブコマンドを **fail-closed スタブ**として追加。
  実装が無いまま誤って呼ばれても、明確なエラーで停止し placeholder anchor を消費させない。

## 本体実装で必要なこと(別PR、フル脅威モデル必須)
- [ ] detail2 §K-4 の registration-time 手続きで **実 L1-close anchor** を導出し、placeholder を置換。
- [ ] close 回路(`src/circuits/channel/close_circuit.rs`)が anchor を本物の rollup state root に
      束縛していることを検証(zero/placeholder anchor を拒否)。
- [ ] `channel_member` の `close`/`withdraw`/`settle` を実際の close-intent 生成 → on-chain
      `ChannelSettlementManager` 提出 → challenge 期間 → payout までドライブできるよう実装。
- [ ] オンチェーン settlement(`ChannelSettlementManager` / `ChannelSettlementVerifier`)との
      E2E を実証明で接続(現状 `CloseLifecycleE2E` は fixture ベース)。
- [ ] 脅威モデル: stale-state close、post-close over-claim、placeholder anchor 混入、
      member-binding 回避、二重出金 を網羅。

## 関連ファイル
- `src/bin/channel_member.rs`(anchor placeholder + fail-closed スタブ)
- `src/circuits/channel/close_circuit.rs`, `close_pis.rs`
- `contracts/src/ChannelSettlementManager.sol`, `ChannelSettlementVerifier.sol`
- `architecture-audit/detail2.md` §K-4
