# abstract2.md(Lattice 版)の Lean 安全性証明 — 解説・脅威モデル・限界

`abstract2.md`(v2 = Lattice/Regev 秘匿版)の安全性質を Lean 4 で形式化し機械検証したものが
[`ChannelSafety2.lean`](./ChannelSafety2.lean) である。v1 の証明
[`ChannelSafety.lean`](./ChannelSafety.lean) を **import で再利用**しており、v1 解説
[`lean-safety-proof.md`](./lean-safety-proof.md) の前提知識を仮定する。

## 検証方法(2 ステップビルド)

```bash
cd architecture-audit
lean ChannelSafety.lean -o ChannelSafety.olean   # v1 をコンパイル(再利用部)
LEAN_PATH=$PWD lean ChannelSafety2.lean          # v2 本体。exit 0 = 全定理検証済み
```

Lean 4.10.0 / core のみ。`sorry` / `axiom` 不使用。

## v1 からの再利用と新規部分

| 区分 | 内容 |
|---|---|
| **再利用(import)** | base 層 ledger 遷移系と全定理(供給量保存・残高非負・nullifier 一意性・集約 exit 上限)、close ゲーム(`L1CloseRule`、`close_no_overdraw`、境界二重支払い)、`Member` 型と補題群 |
| **新規(v2)** | `Ct`(Regev 暗号文の平文意味論)、`EncBalanceState`(暗号化残高 state)、`Tag`(H2: internal / txRoot)、タグ付き署名モデル、`ChannelUpdate`/`UpdateProven`(channelUpdateZKP 健全性契約)、**受信側** `applyReceive`、チャネル横断保存則、構造的アトミック性、暗号化 state 上の challenge ゲーム・close 合成定理 |

## v2 で新たに証明できたこと(v1 との差分)

1. **構造的アトミック性** — v1 では「root 署名と減算 state 署名のアトミック性」は
   `AtomicSigModel.atomic` という**仮定**だった(v1 監査所見 5)。v2 は署名対象が
   `hash(H1, H2)` のペアであるため、`bridgeToV1` により「任意の v2 署名モデルから v1
   `AtomicSigModel` が構成でき、`atomic` フィールドが**証明**される」ことを機械検証した。
   ※ ただし述語モデル上の主張であり、root に入る木の中身との束縛は別問題(M6、後述)。
2. **受信側の形式化**(v1 M4 の一部解消)— `applyReceive` +
   `receive_preserves_validity`(受信者が実際に検証できる事実 `RecipientVerified` のみを仮定)。
3. **チャネル横断保存則** `interChannel_conservation` /
   `interChannel_conservation_bound` — senderΔ と recipientΔ の等量逆符号(channelUpdateZKP)
   により、送信側+受信側チャネル総額の和が保存される。`_bound` 版は「両側が同一の
   `TxLeafHash` コミットメントを開く」束縛を A1(衝突困難性 = `commit` の単射性)として明示。
4. **タグ付き challenge / close 合成** — `challenge_latest_wins2`、`end_to_end_close_safety2`
   (出金は各自の `withdrawClaimZKP` による自分の暗号化残高の証明、他者の協力不要)。

## 定理 ↔ 仕様 対応表(v2 新規分)

| abstract2.md | 性質 | Lean 定理 |
|---|---|---|
| §3.1 / §4.1 | 認可 | `authorization2`, `confirmed_unique_per_version2` |
| §3.2 / §4.3 | solvency | `channelTx2_preserves_validity` |
| §3.4 / §4.3 | solvency | `send_preserves_validity`(provenTotal 単調減少含む) |
| §3.4 flowReceive3 | solvency | `receive_preserves_validity`(NEW) |
| §4.3 delta 両翼束縛 | 保存則 | `interChannel_conservation(_bound)`(NEW) |
| §3.3.2 / §4.1 | 認可 | `TransferAuthorized2`, `authorized_send_state_valid`, `bridgeToV1`(NEW: v1 仮定の定理化) |
| §3.3.5 | 合成 | `settled_transfer_guarantees`(`hcircuit` は仮定、M6) |
| §3.5.2–3.5.3 / §4.4 | 退出 | `challenge_latest_wins2` |
| §3.5.4 | 合成 | `end_to_end_close_safety2` |
| — | 非空虚性 | §9 Sanity(`sampleUpdate_proven`、`oneHonestModel2` 等) |

base 層(§4.2 の no-double-spend 系)は v1 定理がそのまま適用される。

## 信頼基盤(A1–A6)

- **A1** SPHINCS+ 偽造不能 + `hash(H1,H2)` の衝突困難性(署名は (state, tag) ペアを束縛)
- **A2** ZK 健全性(balanceProof / validityProof / channelUpdateZKP / withdrawClaimZKP)
- **A3** 善良メンバー規律(valid のみ署名・1 version 1 state・close 後凍結)
- **A4** L1 コントラクトの正しさ
- **A5** lattice 準同型の正しさ(**ノイズ溢れ・法 p の wraparound が無いことを含む** — 後述所見 6)
- **A6** Regev IND-CPA(秘匿性 = 性質 5。モデル外。構造的事実: base 層 `Ledger` 型には
  member 別データが存在しない)

## 第 2 回敵対的レビュー所見と対応(2026-06-11)

実装と別の敵対的 subagent による監査。16 所見、うち CRITICAL 6 件。

**コードに反映済み**
- 所見 10: `receive_preserves_validity` の仮定を受信者が実際に検証可能な
  `RecipientVerified` に弱化(送信側残高は受信者に見えないため仮定から除去)。
- 所見 8: 横断保存則の「変数共有による束縛」を `interChannel_conservation_bound` で
  明示的なコミットメント単射性(A1)仮定に格上げ。
- 所見 1, 2, 14, 15: `settled_transfer_guarantees` / `bridgeToV1` / A6 の docstring を
  是正(仮定と結論の境界、述語モデル上の主張であることを明記)。
- 所見 5, 6: M5 新設、A5 にノイズ/wraparound の不開示を追記。

**モデル限界として明示(ヘッダ M1–M7)**
- **M5**(所見 5・14): `ValidEncState` は全員の平文に対する述語だが、実際の善良メンバーは
  **自分の成分 + ZKP しか検証できない**。チャネル内誤配分は仕様自身が受容リスクと明記。
  `authorization2` の結論は「善良チェック + A2 の合算が与えるもの」と読むこと。
- **M6**(所見 1・2): `TransferAuthorized2` は state を素の root 番号に束縛するだけで、
  **root の木の中身(TxLeafHash)と減算の一致**は未モデル。`hcircuit` は自由仮説。
  validity 回路制約の形式化(`Apply` を署名モデルと tx 木でパラメータ化)が v3 の本命。
- **M4 改**(所見 9・13): 受信側で形式化したのは**会計**のみ。同一 settled tx の
  **二重 credit を防ぐ仕組み(balanceProof 再計算)は未モデル**。

**仕様(abstract2.md)レベルの問題 — 修正推奨**
- **M7 / 所見 11(最重要)**: flowSend1 step 6 で減算後 state は **L1 取り込み前に**全員署名
  で確定する。tx がブロックに入らなかった場合、「settle されていない減算」を含む version v+1
  の全員署名 state が存在し、close ゲームは最高 version を採るため**起きなかった送金の減算が
  close で強制される**。対策案: (a) `.txRoot` タグ付き state の close 採用に L1 包含証明を
  要求する、(b) 包含確認後にのみ internal version を進める。
- **所見 12**: 送金失敗時の **retry / version 再割当の意味論が未定義**。同一 version での
  再試行は `OneStatePerVersion`(M3)と矛盾し、善良メンバーが詰む。試行ごとに version を
  消費する等の明文化が必要。
- **所見 3**: `H1 = hash(BalanceState)` が `balanceProof` を含むが、署名時点(step 6)では
  減算後 `balanceProof'` は未生成(step 8 で生成)。**H1 は proof オブジェクトを除いた
  `(encBalances, stateVersion, 公開入力)` にコミットする**と明文化すべき。
- **所見 4**: `H2 = 0` の予約値と `tx_tree_root` の数値衝突(空木 root 等)・ドメイン分離が
  未規定。inter-channel 経路で `H2 = 0` を拒否する検証と、署名対象のドメイン分離タグを推奨。

## 改訂(2026-06-11、所見 3・5 の仕様反映)

監査所見 3(H1 の proof 循環)と所見 5(チャネル内 range ZKP 欠落 = M5)を
**abstract2.md の仕様変更として解消**し、モデルを追随させた:

1. **`channelTxZKP`(チャネル内 range ZKP)の必須化** — 送信者が「更新後の自分の暗号化残高 ≥ 0」を
   証明し、co-sign の必須検証項目に追加(abstract2.md §2.2 / §3.2)。
   - Lean: `ChannelTxProven`(ZKP 健全性契約、A2)を導入し、`channelTx2_preserves_validity` の
     仮定をこれに置換。これで同定理の仮定は**全て検証可能な事実**になり、有効 state からの帰納的
     維持が成立(M5 解消)。
   - 新定理 `claims_exactly_fill_cap`: valid な確定 state では Σ(非負成分) = `withdrawCap` が
     **ちょうど**成立 — 負残高成分による「close 出金の横取り」攻撃の封鎖を記録。
2. **`settledTxChain` による state↔balanceProof 束縛** — `H1` は proof オブジェクトでなく
   settle 履歴(`TxLeafHash` / deposit hash)の hash chain にコミット。balance 回路が同じ chain を
   公開入力に expose し、close/challenge 時に L1 が一致照合(abstract2.md §2.1 / §3.5)。
   - **nullifier が使えない理由**: nullifier の preimage は `block_number` を含むため、
     署名時点(flowSend1 step 6、ブロック投稿前)に計算できない。`TxLeafHash` は既知なので
     タイミング問題がない。`block_number` 束縛による二重 settle 防止は base 層 nullifier が続投。
   - Lean §9: `chainOf_injective`(A1 衝突困難性 ⇒ chain 一致 ⇒ 同一 settle 履歴)と
     `chain_binding_resolves_attachment`(chain 一致する proof は state が前提とする履歴の
     総額をちょうど証明する)で束縛の健全性を機械検証。

これにより未解決の仕様課題は **M7(signed-but-unsettled race)と retry/version 意味論、
H2 ドメイン分離**の 3 点に減った。

## 結論

v2 の主要な改善(署名アトミック性の構造化・受信側保存則)は機械検証で裏付けられた。
一方でレビューは、**仕様自体に残る 4 つの未規定点**(M7 の signed-but-unsettled race、
retry 意味論、H1 の proof 循環、H2 ドメイン分離)を特定した。これらは abstract3 で
仕様側を先に更新し、その後 v3 モデル(`Apply` の署名パラメータ化、tx 木束縛、
受信 replay 防止)で形式化を追随させるのが推奨順序である。
