# abstract.md の Lean 安全性証明 — 解説・脅威モデル・限界

`abstract.md`(最小仕様)の 4 安全性質を Lean 4 で形式化し機械検証したものが
[`ChannelSafety.lean`](./ChannelSafety.lean) である。本書はその読み方・信頼基盤・
敵対的レビューで判明した限界を記録する。

## 検証方法

```bash
cd architecture-audit
lean ChannelSafety.lean   # Lean 4.10.0 / core のみ(mathlib 不使用)。exit 0 = 全定理検証済み
```

`sorry` / `axiom` / `native_decide` は不使用(grep で確認済み)。全主張は Lean カーネルが検査する。

## 脅威モデル

- **敵対者**: channel メンバー 3 人中最大 2 人、Block Producer(BP)、channel 外部の任意の者。
  これらは任意のメッセージ・任意の `BalanceState`・任意の close/challenge 提出を行える。
- **守る対象**: abstract.md §0 の 4 性質のうち **safety 側**
  (不正ステートの確定不能・供給量保存・nullifier 再利用不能・出金上限・stale close 不能)。
- **信頼基盤(攻撃不能と仮定するもの)**: SPHINCS+ 署名の偽造、balanceProof / validityProof の
  ZK 健全性破り、L1 コントラクトのバグ、L1 検閲。これらはファイルヘッダの A1–A4 として
  仮説(hypothesis)の形で明示されている。**liveness(タイムアウト到達・L1 包含・配送)は対象外。**

## 定理 ↔ 仕様 対応表

| abstract.md | 性質 | Lean 定理 | 内容 |
|---|---|---|---|
| §3.1 / §4.1 | 認可 | `authorization` | 善良メンバーが 1 人でもいれば、確定(全員署名)した state は必ず valid |
| §3.1 | 認可 | `confirmed_unique_per_version` | 同一 version の確定 state は一意 |
| §3.2 / §4.3 | solvency | `channelTx_preserves_validity` | チャネル内送金は残高保存・非負を保つ(total = provenTotal 不変) |
| §3.4 / §4.3 | solvency | `interSend_preserves_validity` | 減算後 state は valid かつ provenTotal 単調減少(送信側) |
| §3.4 不変則 / §4.1 | 認可 | `atomicity_no_loss_shift` | 送金認可 ⇒ 減算後 state の確定(損失転嫁不能)※仮定の明示化、下記 M 注意 |
| §3.4 | 認可 | `atomicity_comember_unaffected` | 減算は送信者のみが負担、co-member 残高不変 |
| §3.3 / §4.2 | no-double-spend | `apply_conservation` / `exec_conservation` | 供給量変化 = Σdeposit − Σburn(transfer は mint 不能) |
| §2.3 / §4.2 | no-double-spend | `no_double_settlement` | 同一 nullifier(block 番号で束縛)の二重 settle 不能 ※M1 |
| §3.3.1 / §4.3 | solvency | `apply_nonneg` / `exec_nonneg` | rangeProof 条件下で全残高が非負不変 |
| §3.5.4 / §4.2 C2,C5 | 出金 cap | `close_no_overdraw` | Σ出金 ≤ withdrawCap ≤ 実 L2 残高(burn 成功を仮定 ※M2) |
| §3.5.4 / §4.2 C1 | no-double-spend | `close_boundary_no_double_spend` | L1 出金 + 残存 L2 spendable ≤ close 前残高(境界二重支払い不能) |
| §3.5.4 + §3.5.5 | no-double-spend | `exec_exit_bound` | close burn + 全 late claim の総額 ≤ 初期供給 + Σdeposit(集約 solvency) |
| §3.5.2–3.5.3 / §4.4 | 退出 | `challenge_latest_wins` | 最新確定 state を提出すれば stale state での close は不能 |
| 全体合成 | 1–4 | `end_to_end_close_safety` | 各人の受領 ≤ 合意残高、総出金 ≤ 実残高、cap = 合意総額(過不足なし) |
| — | 非空虚性 | §9 Sanity(`oneHonestModel` 等) | 仮定群が矛盾していない(空虚な証明でない)ことの証人 |

## 信頼基盤(ファイルヘッダ A1–A4 の要約)

- **A1** SPHINCS+ 偽造不能(署名 = 述語 `signsState`)
- **A2** balanceProof / validityProof の ZK 健全性(`hsolv` 側条件として遷移系に埋め込み)
- **A3** 善良メンバーの規律(valid のみ署名・1 version 1 state・requestClose 後の署名停止)
- **A4** L1 コントラクトの正しさ(全員署名検査・version 単調置換・Σ出金 ≤ cap)

## 敵対的レビュー所見と対応(2026-06-10)

実装とは別の敵対的レビュー subagent による監査を実施した。所見と処置:

**修正済み(コード/文言に反映)**
1. `interSend_preserves_validity` が `0 ≤ amount` を使っていなかった → 結論に
   「provenTotal 単調減少」を追加し仮定を実質化(§4.3 単調更新に対応)。
2. close + late claim の集約 solvency 定理が無かった → `exec_exit_bound` を追加。
   「同じ L2 残高が close 出金と late claim の両方を裏付ける」攻撃は ledger 層では不能と証明。
3. 非空虚性の証人が全員善良の構成しかなかった → 善良 1 人 + 無制約な敵対者 2 人の
   `oneHonestModel` を追加。
4. `atomicity_no_loss_shift` / `close_no_overdraw` / `no_double_settlement` /
   `challenge_latest_wins` の docstring が証明内容より強く読めた → 仮定と結論の境界を明記。

**モデルの限界として明示(ヘッダ M1–M4。今後の強化候補)**
- **M1 — 1 block 1 settlement 抽象**: `no_double_settlement` は block 番号のみから一意性を導く。
  実システムは `TxV2Tree` で 1 block に複数 tx をバッチするため、block 内一意性は
  `nullifier()` の `transfer_index` / `from` に依存する。これは未モデル。
  *強化案*: block を op のリストにし `(block_number, transfer_index, from)` から一意性を証明。
- **M2 — provenTotal と ledger の未接続**: `BalanceState.provenTotal` は state 層では自由な値で、
  「proof は実残高を超えて証明できない」(A2)は exit 時の `hsolv` でのみ効く。
  したがって `close_no_overdraw` は「L2 burn が成功した」ことを仮定する(導出ではない)。
  *強化案*: `provenTotal ≤ spendable` を結ぶ述語を導入し、署名時点での裏付けを定理化。
- **M3 — OneStatePerVersion は規律仮定**: 並行送金やクラッシュ復旧で善良メンバーが同一 version の
  異なる state に署名する競合は §3.1 のテキストだけでは排除されない。プロトコル実装側で
  single-threaded signing / 永続化を保証する必要がある(仕様へ追記推奨)。
- **M4 — 受信側・lateBalanceProof 個別管理は未モデル**: `flowReceive3`(provenTotal 増加側)と
  「lateBalanceProof は finalBalanceProof と別変数で onchain 保管」(§3.5.5)は個別にはモデルせず、
  `exec_exit_bound` の集約上限で代替している。受信側の偽 balanceProof 拒否(§3.4 flowReceive3
  step 1)の形式化は今後の課題。

**仕様(abstract.md)側への示唆**
- §3.1 に「同一 version への二重署名禁止(クラッシュ復旧含む)」を明文化すべき(M3)。
- §2.3 nullifier の block 内一意性が `transfer_index`/`from` に依存することを
  二重支払い防止の根拠として明記すべき(M1)。

## 結論

abstract.md の 4 性質の safety 側は、A1–A4 の信頼基盤と M1–M4 の抽象化の下で
**全て機械検証済み**。証明が「仮定の明示化」にとどまる箇所(アトミック署名規則、burn 成功)は
docstring とヘッダで明示しており、これらは実装(回路・L1 コントラクト)側で担保すべき
検証項目リストとして読める。
