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
| [BlobJournal](./Zkp/Implementation/BlobJournal.lean) / `BlobKZGVerifier.sol` | journal、sidecar、payload byte-address、順方向 prefix 積・逆方向 batch inversion・最終 scaling の処理、root 定数の modular identities、全 4096 index の bit-reversal involution | barycentric interpolation の完全な正しさ、SimpleCoder assembly、SHA / modexp / point-evaluation の実装、memory / CALL |
| [SettlementVerifier](./Zkp/Implementation/SettlementVerifier.lean) / `ChannelSettlementVerifier.sol` | pinned adapter/core 呼出し、厳密な PI 長・u32・各位置の対応、close / withdrawal / cancel / claim の引数との結合 | proof soundness、ABI/staticcall、canonical hash encoding、呼出し元の所有権・最新性 |
| [CloseFunding](./Zkp/Implementation/CloseFunding.lean) / `CloseFundingMaterializer.sol` | freeze generation、現在 anchor、正確な proof receipt と再検証、全 vector と registry の対応、一度だけの materialization、token ごとの escrow 減額と credit 増額 | Manager getter の同一スナップショット、Rollup 呼出し、認証済み所有権、EVM 原子性 |
| [CloseAssetBacking](./Zkp/Implementation/CloseAssetBacking.lean) / `close_asset_backing_circuit.rs` | 任意の activity witness から正規 prefix・ゼロ suffix、重複禁止、空木から全額 vector の再構成、列挙外ゼロ、26 PI・92-word digest、private / recursive state の結合 | 有限の経路ごとの Merkle/hash binding、field gate lowering、recursive verifier、Balance 自体の保存性 |
| [U256Arithmetic](./Zkp/Implementation/U256Arithmetic.lean) / `ethereum_types/u256.rs` の target add/sub | 全 limb の carry/borrow 帰納合成、最終ゼロから厳密な加減算、underflow / wrap の排除、正常な carry/borrow の例 | 輸入 u32 gate の局所方程式・canonical range、native shifts/casts、残りの型変換 |
| [ManagerValue](./Zkp/Implementation/ManagerValue.lean) / `ChannelSettlementManager.sol` 全明示関数 | close 全 vector の最終化、厳密な期限と絶対 horizon、request / cancel の世代・nonce、PW 認証前の消費・再実行拒否、claim / pull / payout の token 別計数 | proof、ABI、token、callback frame、外部 log の順序、全 entrypoint を含む到達可能状態の不変量、EVM refinement |
| [RollupValue](./Zkp/Implementation/RollupValue.lean) / `IntmaxRollup.sol` 全関数・modifier 群 | 入出金、投稿、最終化、fraud、逆順 rollback、stake 分割、finalize / rollback trace 上の永久 root の保持、withdrawal-set 全 loop の token 別会計 | proof / hash、実 token 残高、callback frame、全 entrypoint を含む時系列・所有権の証明、EVM refinement |
| [Spend](./Zkp/Implementation/Spend.lean) / `spend_circuit.rs` | 64 件の順序付き減算、同 token の反復減算の累積保存、局所 borrow 方程式からの非 underflow、native / target の差、PI・proof wrapper・constructor の対応 | 有限 Merkle 経路、field / u32 gadgets、転送木・hash、nonce overflow、消費側での is_valid 要求、送受金全体との接続 |
| [CloseCircuit](./Zkp/Implementation/CloseCircuit.lean) / `close_circuit.rs` | 任意 witness の member / token prefix、103 PI、IMCH / H1 / TFD の全額 vector binding、署名対象との結合、有限の indexed Merkle insertion による重複拒否 | Falcon aggregate / Balance proof、field lowering、hash binding、fixture 生成部、caller の high-water / backing / finality |
| [ClosePublicInputs](./Zkp/Implementation/ClosePublicInputs.lean) / `close_pis.rs` | native 103-word codec、型幅・正規形の下での roundtrip、全 intent 比較後の witness 投影、92-word TFD | scalar pair の raw shift / OR と circuit の u32 check の差、CloseIntent::new 本体、Serde / Rust compiler、circuit / Solidity 型間の同値性 |
| [CloseEncodingBridge](./Zkp/Implementation/CloseEncodingBridge.lean) / native・circuit の型変換 | 全 20 field の双方向変換、全 103 word の同一性、native canonical domain の下で両 parser が同じ statement を読むこと | Solidity / ABI byte 変換、Rust compiler・実 gate 列、Keccak / proof soundness。モデル間の codec 同値性と実言語同値性は別 |
| [FundFlow](./Zkp/Implementation/FundFlow.lean) / 上記 Manager・Rollup・Materializer の合成 | credit helper 間の成功 / エラー込みの投影同値、対象 accounting trace の token 別総額保存、paid ≤ received、nullifier tombstone・未払い記録の保持、非空の正常 trace | pull の実 dispatch / callback との結合、他 Manager を含む全資金フロー、現物 custody、預入・stake・rollback を含む全 trace の合成 |
| [CancelCloseCircuit](./Zkp/Implementation/CancelCloseCircuit.lean)・[native PI](./Zkp/Implementation/CancelClosePublicInputs.lean) | 取消の厳密な version 増加、freeze nonce の非 wrap 後継、登録 member commitment・署名対象の結合、29語の codec、native admission と任意 witness の分離 | aggregate / Merkle / hash / gate の意味、Manager の取消履歴と pending generation、任意 feature の fixture |
| [WithdrawalClaimCircuit](./Zkp/Implementation/WithdrawalClaimCircuit.lean)・[native PI](./Zkp/Implementation/WithdrawalClaimPublicInputs.lean) | 50語、active member/delegate slot、one-hot token 選択と registry・ciphertext の同一位置、leaf 内 recipient、同じ復号 core 入力・金額、IMW2 nullifier、native 事前検査 | 復号多項式・Merkle・署名済み head の認証、backing、高水位、replay ledger、proof / compiler / gate、任意 feature の fixture |
| [PostCloseClaimCircuit](./Zkp/Implementation/PostCloseClaimCircuit.lean)・[native PI](./Zkp/Implementation/PostCloseClaimPublicInputs.lean) | 57語、token を含む source tx、height20 accumulator / height10 slot の呼出し、member/delegate 共通の recipient、復号 core 金額、IMCK nullifier | 復号・木の参照 root の認証、最新 head・finality・残額・replay、proof / compiler / gate、任意 feature の fixture |
| [H1Gadget](./Zkp/Implementation/H1Gadget.lean) / 共通 H1・leaf と選択した native/hash-output helper | header 37要素 / leaf 104要素の全 field、native/target 順序、Goldilocks の比較・乗算・ゼロ制約から正規 32/32 分割を導出、native cast と target encode-back の違い | imported gate の実制約への lowering、Poseidon、native tree 計算、Rust 表現と compiler、残る BalanceState / hash helper |
| [SettlementCloseBridge](./Zkp/Implementation/SettlementCloseBridge.lean) | 同一 adapter/proof の受理返り値から103語の exact record、IMCS 48 byte / IMTF 368 byte の一致、u32 byte encoding の単射、具体的 hash binding 下で10 token vector 全体の一致 | proof から circuit gates への健全性、実 gate と hash 実装の対応、Manager の資産所有権 / backing |
| [CancelCloseBridge](./Zkp/Implementation/CancelCloseBridge.lean)・[ClaimSettlementBridge](./Zkp/Implementation/ClaimSettlementBridge.lean) | Solidity の29 / 50 / 57語と circuit の全 field の同値、同一受理返り値による金額・受取先・asset の接続、claim と共通 H1/leaf/正規 root の接続 | 保存済み Manager head / nullifier / generation の caller 配線、proof soundness、実行環境、全経路の資金所有権 |

Manager と Rollup は、前回の選択経路から全明示関数へ手書きモデルを拡張しました。
ただし interface / generated getter / assembly / callback の境界は別分類のままで、
**全関数に定義があることと、全実行の資金安全性を証明したことは別です。**
各モデルの全行対応状況は上の一覧だけで判断せず、inventory / line-map と検証結果を確認してください。

`IPinnedMleVerifierV2.sol` は関数本体のない interface です。4 つの ABI 署名を
`SettlementVerifier.PinnedInterface` と [専用対応表](./line-map/pinned-interface.json) に追加しました。
interface の存在から MLE verifier の安全性を証明したことにはしていません。

### 個別証明から合成へ進めた範囲

`FundFlow` は、既存の Materializer / Rollup / Manager の定義を直接 import します。
Materializer の Rollup-credit 展開と、Rollup 側の native / ERC20 振分け・guard・エラーを
同じ ledger へ投影して比較する等式を証明しています。単に似た会計モデルをもう一つ
作って「どちらも安全」とは扱っていません。

その上で、credit → pull → claim → payout の有限 trace について、token ごとの
`Rollup escrow + その Manager の pending credit + Manager received` が保存されること、
`paid ≤ received` が維持されることを証明しています。`received − paid` と既払額への
分解、消費済み nullifier の永続性、未払い payout 記録の上書き拒否も含みます。
100 単位の credit / pull 後に 5 単位を払い、95 単位を保持する非空の正常 trace もあります。

ただしこの trace は全 entrypoint を網羅するものではなく、pull の source call を同一の
Rollup debit へ結び付ける条件が明示されています。native については、実際の modeled
`withdraw` wrapper から ledger debit を導く補題も追加しましたが、callback の storage frame
は未証明の環境条件です。**総額が保存されても、別チャネルから盗んでいないことは別問題**です。
deposit / stake / rollback、全 Manager、資金の所有権、実 token custody、EVM call trace までを
この定理の対象に読み替えないでください。

相互レビューでは、Manager 最終化の外部 digest 呼出し前に Solidity が行う中間状態の書込みを
モデルでも見えるようにする修正点が見つかりました。これは手書きモデルの精度の問題であり、
新たなランタイム脆弱性の実証ではありません。最終値だけでなく呼出し先から見える状態も
照合対象にしています。

native と circuit の公開入力も、同じ順序であるという目視確認から、
`CloseEncodingBridge` の field-by-field 変換と 103-word 等式へ進めました。
native decoder の狭い u8 / u16 count と raw u64 join を消去せず、必要な正規性条件を明示した
interoperability です。Solidity の再計算 digest や ABI bytes との同値性までは含みません。

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
- current module 同士の合成 import は許可しましたが、全モジュールを manifest と
  theorem inventory に登録して検査します。未登録 / historical import、循環、標準 module 名の
  ローカル shadowing を拒否する回帰テストを追加しました。

独立レビューで Blob context の呼出し先 / submission ID の明示、返り値 digest の明示、
Merkle 前提の有限 trace への限定を改善しました。これは形式モデル側の精度改善であり、
実装に新たな盗難脆弱性を発見したという報告ではありません。

## 再検証

### `9a67d8e` 以降：取消・請求・共通 H1・Solidity 接続の checkpoint

- **81 モジュール**を build、現行 **28 モジュール・995 named theorems** の実在・種別・
  推移的 kernel axioms を検査して main guard 成功。前回から **234 定理**追加。
  実装対応は **23 モジュール・776 定理**、前段の仕様側は 5 モジュール・219 定理。
- **133 reviewed-source hashes、1 MLE gitlink、21 source maps** を検証。
  全対応表の宣言参照を Lean compiler で確認して line guard 成功。
- guard 回帰テスト **51 件**（main 29 + line 22）。ランタイム基準 `05ec7ae` に対する
  `src`、`contracts`、`Cargo.toml`、`Cargo.lock` の差分はゼロ。証明サイズ・時間の比較測定は
  実施しておらず、ベンチマーク対象コード・proof parameter を変更していません。
- 物理行分類：手書き翻訳 **6,686**、依存境界 **1,666**、非実行 **4,593**、
  テスト専用 **4,542**、未翻訳 **99,710**。テスト・コメントの分類変更も含むため、
  この減少量を「安全性証明済み実行行数」には換算できません。

今回の合成は、**同一の adapter・proof・返り値**の照合を起点とします。Solidity の
close / cancel / withdrawal / post-close の 103 / 29 / 50 / 57 語を、各回路の全 field と
結びました。IMCS の48 byte、全 token vector の IMTF の368 byte については、単に
「同じはず」と仮定せず、整数分解と byte encoding の単射から一致を導いています。
`CircuitGates` は adapter 受理から自動的に取り出せるとは仮定せず、まだ別の前提です。
従ってこれは **暗号 verifier を含む end-to-end 証明ではありません**。

H1 では37要素 header と104要素 leaf の並びを共通 helper と各 claim 呼出し側で接続し、
Goldilocks の split / equality indicator / multiplication / assert-zero の局所方程式から
32/32分割の正規性と一意性を導きました。native `TryFrom<Bytes32>` は raw u64 の復元・
byte roundtrip であり、target `to_hash_out` の modular reduction + canonical encode-back と
同じ検査ではありません。この違いを消して証明していません。

相互レビューで、前回 CloseCircuit の native member helper に u8 cast **後**の padding mask を
反映する修正を加えました。通常の admission で許されない巨大リストについても、補助関数の
定義を原実装に合わせたものです。runtime の修正・盗難経路の実証ではありません。
対応表の別 module への直接参照、import / derive の扱い、feature fixture と `cfg(test)` の
混同も修正し、strict guard を緩めず再検証しています。

未達の中心は、復号と state-update の実処理、Balance / validity 全経路、proof 受理から実 gate
制約への健全性、Rust/Solidity/EVM refinement、および全 Manager と全 entrypoint を含む
資産所有権・現物 custody・正常退出到達性の合成です。全体の完了・リリース承認ではありません。

### 前回 `9a67d8e` の統合検証（履歴）

- **71 Lean モジュール**を build。現行 **18 モジュール・761 named theorems** の実在・
  theorem 種別・推移的 kernel axioms を確認し、main guard が成功。
  実装対応・合成は **13 モジュール・542 定理**、前段の仕様側は 5 モジュール・219 定理。
  前回 `85f243b` から **216 定理を追加**。件数は全実装の証明率ではありません。
- **106 reviewed-source hashes、1 MLE gitlink、12 source maps** を検証。
  source map の宣言参照も Lean compiler で確認し、line guard が成功。
- guard 回帰テスト **51 件**成功（main 29 + line inventory 22）。
- `git diff --check` 成功。ランタイム基準 `05ec7ae` に対する `src`、`contracts`、
  `Cargo.toml`、`Cargo.lock` の差分はゼロ。MLE サブモジュールの作業ツリーも clean。

現 inventory の物理行分類は、手書き翻訳 **4,824**、依存境界 **1,124**、
非実行 **3,686**、テスト専用 **1,530**、未翻訳 **106,033** 行です。
未対応ファイルのコメント・テストも未翻訳に含みます。これはテストの pass rate や
脆弱性の残存率ではありません。

**`--require-complete` は引き続き失敗するべき状態です。**
全行・全資金フローの証明、Rust / Solidity / gate / EVM の refinement、暗号・実行環境の
前提の検証は未達です。未証明を admission や「acceptance ⇒ safe」の仮定で埋めたり、
完了チェックを緩めたりしていません。未証明は即座に実在する脆弱性を意味しませんが、
「盗難・損失が不可能」の認定には使えません。

### 前回 `85f243b` の検証結果（履歴）

以下は前回コミットの結果であり、追加実装を含む最新の件数ではありません。

- 既存を含む **67 Lean モジュール**の build 成功。
- 現行 **14 モジュール・545 named theorems** の compiler / 推移的 axioms 検査成功。
  うち今回の実装対応は **9 モジュール・326 定理**。前段は 5 モジュール・219 定理です。
- reviewed-source manifest の **97 ファイル**と MLE gitlink を検証。
- **9 source maps** の原行区間・全ソース inventory・Lean 宣言参照の検査成功。
- guard の回帰テスト **45 件成功**（既存 23 + line inventory 22）。
- 更新した索引・レポート内のローカルリンク **28 件**を確認。

前回 inventory の物理行分類は、手書き翻訳 2,485、依存境界 562、非実行 2,368、
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

1. 残る Balance / validity / state-update / decryption 回路の手書き翻訳を追加する。
   Manager / Rollup の関数一覧は埋まったが、ABI・callback・generated getter と全到達可能状態の
   証明を完了したことにはしない。close / cancel / withdrawal / post-close の通常関数と
   native PI は追加済みだが、feature-gated fixture 生成は未翻訳として残す。
   特に `state_update_verifier.rs` と `decryption_gadget.rs` の本体は残る。
2. Balance / validity / deposit / transfer / withdrawal の各回路を、native admission と
   arbitrary satisfying witness を分離して翻訳する。Spend だけで送受金全体を証明したことにしない。
3. U256、Merkle、Keccak/Poseidon、署名 / decryption、recursion / pinned proof verifier の
   局所保証を実装から導き、今の theorem 引数のまま放置しない。H1 の正規分割は局所
   modular equations から導出済みだが、primitive gate 実装の証明まで完了していない。
4. calldata / ABI / revert / reentrancy / checked arithmetic を含む Solidity 実行と、Rust builder
   の実 gate 列について、手書き Lean モデルへの refinement を構築する。
5. 各 slice を一つの状態遷移系に接続し、token ごとの「預入原資 = 未使用原資 + 退出済み額」
   と、channel / nullifier / generation による分離を任意 trace 上で示す。
6. safety と別に、保持した最後の署名済み H・proof/config・DA が利用可能な条件下で、
   追加 channel 署名なしに正常退出が到達可能であることを示す。L1 inclusion / gas / finality /
   storage availability を数学的保存則から捏造しない。

全項目が終わるまで、表やビルド成功を「資金を盗めない・失わないことの全実装証明」として
引用しないでください。
