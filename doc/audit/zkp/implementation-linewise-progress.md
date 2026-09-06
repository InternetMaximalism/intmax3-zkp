# 実装の行対応 Lean 化 — 2026-09-06 作業記録

## 結論と対象

**実装全行の形式化・資金健全性の証明は未完了です。** この記録は途中の実装対応と
条件付き証明の成果であり、リリース承認・「盗難も損失も不可能」という証明ではありません。
以前の設計モデルの証明と、現在の実装の証明を混同しないため、独立した
`Zkp.Implementation.*` を既存の Lean プロジェクトに追加しています。

対象ランタイムは親 `05ec7ae94701f05d2aaf97ff796b7f800a6ce1f8`、MLE サブモジュールは
`6cefc6acee18d0d76b52f1c22c0113e3ae8fbf78`。前段の仕様同期・Lean 統合は `acfaa78`。
作業ブランチは `codex/implementation-linewise-lean-20260906` です。
この段階ではランタイム、回路、証明パラメータ、proof format、生成物を変更していません。
証明サイズ・証明生成時間が改善したとも悪化したともベンチマークで主張していません。

信頼モデルは従来どおりです。全 cluster の結託による**自チャネル内部の不正配分**は許容し、
他チャネルの原資の消費は許容しません。最後の N-of-N 署名済み state H と対応する保持済み
exit kit による退出には、新たな channel 署名を要求しないという要件を維持します。
KZG ceremony は受容済みの信頼仮定です。ただし ceremony を信頼することと、codec、
KZG 呼出し、hash binding、回路や Solidity の実装が正しいことは別です。

## 全行の棚卸しとチェックの意味

[implementation-inventory.json](./implementation-inventory.json) は、次をファイル名・SHA-256・
物理行数で列挙します。

| 区分 | ファイル数 | 物理行数 |
|---|---:|---:|
| 親 `contracts/src/**/*.sol`、`src/circuits/**/*.rs` | 71 | 45,178 |
| 列挙した共通部品・暗号部品・MLE Rust/Solidity 依存先 | 165 | 72,019 |
| 合計 | 236 | 117,197 |

依存先は common、ethereum_types、utils、regev、falcon_sig、poseidon_sig、deprecated、
constants、wrapper_config、および MLE の src / contracts/src です。
これは Cargo、Plonky2 本体、外部 u32 gadgets、コンパイラ等の**全推移的依存先**ではありません。
テスト専用ファイルやコメントも物理行数に含まれます。

各 [line-map](./line-map/) は原ファイルの 1 行目から EOF までを、重複・空白区間なく分割します。
各原行は必ず一つの区間に入り、その区間を Lean の実在する定義・定理へ結びます。
ただし「原文 1 行 = Lean 1 行」の機械的逐語変換ではなく、処理・分岐・ループ単位の
**手書き意味モデル**です。翻訳の意味的同値性そのものを、この対応表は証明しません。

状態は `translated`（手書き意味モデル）、`dependency-boundary`（依存先の保証が必要）、
`untranslated`、`test-only`、`non-executable` に分離します。
未対応ファイルはファイル全体を `untranslated` とし、古い抽象モデルが存在しても
自動的に完了にはしません。物理行数や定理件数を「安全性の証明率」に換算しません。
区間内のコメントや構文行を含む分類もあるため、翻訳済区間の物理行数は実行文数ではありません。

## 現在の実装対応

| モデル / 原実装 | 現段階で導出している性質 | 主な未証明境界 |
|---|---|---|
| [SafeERC20](./Zkp/Implementation/SafeERC20.lean) / `SafeERC20.sol` | CALL 失敗・短い応答・false・非正規 bool の扱い、引数の同一性、正常な空応答 / true 応答 | ABI/CALL/rollback、実際の残高変化、呼出し元の再入保護 |
| [BlobJournal](./Zkp/Implementation/BlobJournal.lean) / `BlobKZGVerifier.sol` | blob 数・sidecar サイズ、提出 ID / Rollup / commitment / proof hash / length の journal、非ゼロ記録の不変性、precompile 応答形、payload byte-address 対応 | 多項式評価、assembly、challenge、hash/precompile 本体は未翻訳または依存境界 |
| [SettlementVerifier](./Zkp/Implementation/SettlementVerifier.lean) / `ChannelSettlementVerifier.sol` | pinned adapter/core 呼出し、厳密な PI 長・u32・各位置の対応、close / withdrawal / cancel / claim の引数との結合 | proof soundness、ABI/staticcall、canonical hash encoding、呼出し元の所有権・最新性 |
| [CloseFunding](./Zkp/Implementation/CloseFunding.lean) / `CloseFundingMaterializer.sol` | freeze generation、現在 anchor、正確な proof receipt と再検証、全 vector と registry の対応、一度だけの materialization、token ごとの escrow 減額と credit 増額 | Manager getter の同一スナップショット、Rollup 呼出し、認証済み所有権、EVM 原子性 |
| [CloseAssetBacking](./Zkp/Implementation/CloseAssetBacking.lean) / `close_asset_backing_circuit.rs` | 任意の activity witness から正規 prefix・ゼロ suffix、重複禁止、空木から全額 vector の再構成、列挙外ゼロ、26 PI・92-word digest、private / recursive state の結合 | 有限の経路ごとの Merkle/hash binding、field gate lowering、recursive verifier、Balance 自体の保存性 |
| [U256Arithmetic](./Zkp/Implementation/U256Arithmetic.lean) / `ethereum_types/u256.rs` の target add/sub | 全 limb の carry/borrow 帰納合成、最終ゼロから厳密な加減算、underflow / wrap の排除、正常な carry/borrow の例 | 輸入 u32 gate の局所方程式・canonical range、native shifts/casts、残りの型変換 |
| [ManagerValue](./Zkp/Implementation/ManagerValue.lean) / `ChannelSettlementManager.sol` の限定経路 | claim の token 別上限・nullifier 記録、cap と実受取差分が一致する pull、recipient 固定の一件払い、CEI、close 世代と全 state の burn floor | 残りの close / challenge / cancel / partial-withdrawal、proof、ABI、token、callback frame、返り値 / event の投影 |
| [RollupValue](./Zkp/Implementation/RollupValue.lean) / `IntmaxRollup.sol` の限定経路 | deposit、17 PI の withdrawal set、auth / nullifier 消費、token 別 escrow→credit、指定額だけの pull、別 recipient の credit の保持 | posting / finality / fraud 等の未翻訳関数、proof / hash、実 token 残高、callback による storage 変更・外部 log の順序 |
| [Spend](./Zkp/Implementation/Spend.lean) / `spend_circuit.rs` | 64 件の順序付き減算、同 token の反復減算の累積保存、局所 borrow 方程式からの非 underflow、native / target の差、PI・proof wrapper・constructor の対応 | 有限 Merkle 経路、field / u32 gadgets、転送木・hash、nonce overflow、消費側での is_valid 要求、送受金全体との接続 |

Manager と Rollup は**選択した資金経路だけ**で、ファイル全体の翻訳は未完成です。
各モデルの全行対応状況は上の一覧だけで判断せず、inventory / line-map と検証結果を確認してください。

### 境界を過大主張しないための確認

- helper が成功しても ERC20 の実残高が増減したとは限りません。残高差、正規 token、
  再入、トランザクション全体の rollback は呼出し元・環境と接続する必要があります。
- CloseFunding の actual code は signed-head proof を再検証します。古いコメントだけを読んで
  「receipt だけで許可」とはモデル化していません。
- pooled escrow の合計が足りることは、他チャネルから盗んでいないことの証明ではありません。
  正確な所有 vector の認証・チャネルへの結合を別に要求します。
- CloseAssetBacking の native witness constructor のチェックを、任意の悪意ある witness に
  自動的に仮定しません。回路制約と証明生成前の native admission を分けています。
- Spend では「減算が安全」を結論の前提に置かず、各 limb の借り方程式と入出力の束縛から
  非 underflow を導出して、経路ごとの保存則へ接続します。native nonce の u32 overflow と
  field 加算、native PI parser の切詰め・非ゼロ判定を同一視していません。
- Manager の callback は明記した storage frame の下での投影です。Rollup の callback は
  storage を変更し得る形で残しています。`nonReentrant` が全ての未修飾 entrypoint や
  外部ログの順序まで保証するという仮定は置きません。
- public / private commitment は前提を示した binding です。無限の全入力に対する有限 hash の
  無衝突性を置いていません。Merkle 更新も、実際に辿る有限の木・経路ごとの局所保証です。
- 通常の Lean kernel axioms 以外に `sorry`、`admit`、独自 `axiom`、`native_decide` を
  追加していません。ただし定理の引数に明記した暗号・実行環境の前提は未証明です。

独立レビューで Blob context の呼出し先 / submission ID の明示、返り値 digest の明示、
Merkle 前提の有限 trace への限定を改善しました。これは形式モデル側の精度改善であり、
実装に新たな盗難脆弱性を発見したという報告ではありません。

## 再検証

このチェックポイントのローカル実行結果：

- 既存を含む **67 Lean モジュール**の build 成功。
- 現行 **14 モジュール・545 named theorems** の compiler / 推移的 axioms 検査成功。
  うち今回の実装対応は **9 モジュール・326 定理**。前段は 5 モジュール・219 定理です。
- reviewed-source manifest の **97 ファイル**と MLE gitlink を検証。
- **9 source maps** の原行区間・全ソース inventory・Lean 宣言参照の検査成功。
- guard の回帰テスト **45 件成功**（既存 23 + line inventory 22）。
- 更新した索引・レポート内のローカルリンク **28 件**を確認。

現 inventory の物理行分類は、手書き翻訳 2,485、依存境界 562、非実行 2,368、
テスト専用 512、未翻訳 111,270 行です。未対応ファイルのコメントやテストも未翻訳に
含む粗い分類であり、67 モジュールや 545 定理がこの全てをカバーするという意味ではありません。

Lean 4.10.0 を各プロジェクトの `lean-toolchain` から使用します。リポジトリの root で
別のデフォルト Lean を起動して検証したことにしないでください。

```sh
python3 -B .github/ci/test-lean-safety-guard.py
python3 -B .github/ci/test-lean-line-coverage.py
bash .github/ci/lean-safety-guard.sh
python3 -B .github/ci/lean-line-coverage.py
```

`lake` は PATH に必要です。guard は両 Lean プロジェクトを build し、現行モジュールの全 named
theorem について compiler environment 上の theorem 種別と推移的 axioms を検査します。
line guard はソースの追加・変更、全行区間、参照宣言、未対応ファイルの一覧を検査します。

`lean-line-coverage.py` の PASS は **inventory / links の整合性だけ**です。
`--require-complete` は現行の未完成モデルでは意図的に失敗します。この schema には
source-refinement certificate の形式自体がなく、全行の安全性を認定する機能はありません。

## 続きで必要なこと

1. Manager / Rollup の未翻訳関数、close / cancel / withdrawal / post-close claim の回路を
   順に追加し、全 entrypoint・分岐・外部呼出し・PI の行対応を埋める。
2. Balance / validity / deposit / transfer / withdrawal の各回路を、native admission と
   arbitrary satisfying witness を分離して翻訳する。Spend だけで送受金全体を証明したことにしない。
3. U256、Merkle、Keccak/Poseidon、署名 / decryption、recursion / pinned proof verifier の
   局所保証を実装から導き、今の theorem 引数のまま放置しない。
4. calldata / ABI / revert / reentrancy / checked arithmetic を含む Solidity 実行と、Rust builder
   の実 gate 列について、手書き Lean モデルへの refinement を構築する。
5. 各 slice を一つの状態遷移系に接続し、token ごとの「預入原資 = 未使用原資 + 退出済み額」
   と、channel / nullifier / generation による分離を任意 trace 上で示す。
6. safety と別に、保持した最後の署名済み H・proof/config・DA が利用可能な条件下で、
   追加 channel 署名なしに正常退出が到達可能であることを示す。L1 inclusion / gas / finality /
   storage availability を数学的保存則から捏造しない。

全項目が終わるまで、表やビルド成功を「資金を盗めない・失わないことの全実装証明」として
引用しないでください。
