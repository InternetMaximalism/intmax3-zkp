# A-3 フォローアップ: channel close / withdraw-to-L1 / settle ライフサイクル(本体実装)

状態: **本体実装ほぼ完了**(2026-06, A-3 P1–P6)。下記「監査パスの安全化」は本実装で**置換済み**(歴史記録)。
完了詳細は `tasks/a3-impl-todo.md`。残るは **P5-B 完全 CLI E2E**(close 経路の CLI-members ↔
on-chain-registration 整合 = withdraw パイプラインをチャネルの実 member/deposit に束縛する拡張が必要。
withdraw 単体は anvil live 検証済。close-intent は CloseLifecycleE2E が member-set 不一致で skip する既存ギャップと同根)。

## 完了(本実装、旧スタブを置換)
- ✅ anchor 実値化(P1)。✅ close/settle/withdraw/claim CLI(P3/P4、withdraw は anvil live 検証済)。
- ✅ C2/C3 stub revert 化(P6-A、攻撃者レビュー GO)。✅ relay /api/close|settle|withdraw|claim(P5-A)。

## 旧:背景 / 現状(★本実装で解消済み・歴史記録)
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
