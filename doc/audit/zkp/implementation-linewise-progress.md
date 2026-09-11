# 実装の行対応 Lean 化 — 2026-09-11 作業記録

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
| [PrivateState](./Zkp/Implementation/PrivateState.lean) / `common/private_state.rs` | 4 root × 4 語 + nonce + salt の厳密な 21 語 preimage、nonce offset 16 / salt offset 17、layout の単射、native `to_u64_vec` と target `to_vec` を別々に転記した順序一致、FullState → PrivateState の root 投影、genesis の空 root / nonce 0 / salt 保持、target 割当と witness 書込み順 | Poseidon の単射性、`AssetTree::init` と `AssetTree::new(height)` の同一性、木の root 計算、compiler refinement |
| [UpdatePrivateState](./Zkp/Implementation/UpdatePrivateState.lean) / `balance/common/update_private_state.rs` | nullifier 挿入 → 旧 asset opening → U256 加算 → 新 asset root → 更新状態の処理順、nullifier error 優先、opening 不一致は加算前に返却、native overflow は panic、成功時に更新される 3 field と保持される sent root / nonce / salt、32 sibling、`is_checked` の有無、`AddGates` からの厳密加算と非 wrap、native 成功経路が local gate family を満たす witness の存在 | nullifier の freshness / 非再利用、IndexedInsertionProof の ordered-set soundness、asset Merkle 所有権、Regev / 転送認可、native/target U256 の一致（明示前提）、gate lowering |
| [UpdatePublicState](./Zkp/Implementation/UpdatePublicState.lean) / `balance/common/update_public_state.rs` | `new == old` なら 63 sibling の dummy proof、異なる state では proof 必須、old block number での Merkle 接続と `new.previousRoot` 比較、target の無条件 path 評価と条件付き最終 root 等式、timestamp hi/lo を含む 5 field 等式、native 検証成功からの target witness | block 増加、timestamp 単調性、canonical L1 chain、finality、reorg、Merkle hash / gate / compiler lowering |
| [BalancePublicInputs](./Zkp/Implementation/BalancePublicInputs.lean) / `balance/balance_pis.rs` | 29 語 prefix（public state 15、block_r、private commitment 4、settled chain 8）の offset、native の exact-length parser と channel 0 拒否、raw field bounds、target の suffix 受容と channel 0 非拒否の分離、verifier data の digest / cap parsing、余分な native cap root の扱い | 輸入 parser guard（channel_id / u63 / u32limb）の実装、field 変換 callback、Poseidon、`block_r ≤ block_number` の呼出し側での強制 |
| [SwitchBoard](./Zkp/Implementation/SwitchBoard.lean) / `balance/switch_board.rs` | 4 flag の sum-one からの一意選択、全 public word と verifier-data tail への selector 適用、inactive branch の dummy verifier / active branch の real verifier 結合、missing dummy index の error、genesis candidate の空 root / nonce 0 / virtual salt、prefix でなく full candidate の選択、HashMap 重複・順序の境界の明示 | proof gadget の soundness、carried VD と supplied balance VD の未結合（outer cyclic-key check が別境界）、`select_vec` の実装、cap count の prove-time config、branch proof と実資金の結合 |
| [BalanceCircuit](./Zkp/Implementation/BalanceCircuit.lean) / `balance/balance_circuit.rs` | 固定 switch verifier 呼出し、full PI parsing と register、common-data 等式と build-success の assertion、cyclic tail の cap → digest 順検査の後に通常検証、serialization で consumed-byte count を捨てる source behavior、deserialize 後に constructor 検査を再実行しない事実 | 再帰 verifier gadget の soundness、`generate_cd` の common data 妥当性、plonky2 `check_cyclic_proof_verifier_data` との一致、`CircuitData::verify`、bincode / gate / generator codec |
| [ChannelStateUpdate](./Zkp/Implementation/ChannelStateUpdate.lean) / `channel/state_update_verifier.rs` | 7 verifier と helper、state / record / descriptor、Regev envelope、20 PI field（266 語）、channel / member / delegate / token slot guard の順序、same-channel fund、選択 token の ciphertext、pending increment / reset、send の `fundAfter + amount = fundBefore`、import debit、refresh の fund 不変、token-register の全状態再構築、u64 overflow profile と U256 final carry panic、7 field だけを受ける signing digest callee、transport bytes が空に強制されること（source 観察） | Falcon / A11 署名の妥当性（helper は構造検査のみ）、durable replay ledger、L1 backing / finality、wallet frontier、`root != oldRoot` は freshness ではない、gate / compiler refinement |
| [DecryptionGadget](./Zkp/Implementation/DecryptionGadget.lean) / `channel/decryption_gadget.rs` | ring `N=2048`、`q=2013265921`、Δ / 丸め、signed / unsigned 表現、negacyclic schoolbook reduction、quotient / wrap / carry、ternary / residual / noise bound、digit の一意性、u64 amount の分解、native build の拒否条件、row fill と hash payload の順序、`CoreGates` から各 row の整数方程式への合成、digit-255 境界の gate 非充足性、全ゼロ割当の充足例 | 復号 oracle / plaintext の意味、秘密鍵の一意性、ciphertext authenticity、recipient entitlement、`FieldProducts` 前提、Boolean / range-check lowering、Keccak / Poseidon binding、Rust / gate / compiler / NTT refinement |

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

### 2026-09-11（第 4 ループ）：close vector の裏付け (c)、NTT 正当性 (d2')、機械的な忠実性証拠、公開文書

運用者指示：「多少緩くてもいいので、安全性の実用的証明として外部に公開できるように、自律的に判断して
間を埋める」（(a0)(d3) は対象外）。計画は `tasks/loop-2026-09-11-backing-and-evidence-plan.md`。

**(c) の再定式化。** 旧 `closeVectorBacked` は「close intent 受理時の金額 ≤ 不透明な per-channel 預入 map」
でした。これは (i) 何も credit しない事象に付いており（credit は materialization で起きる）、
(ii) L2 transfer がある系では正しい不変量ではありません。配備契約が escrow から credit する前に要求
するのは **backing proof**（`CloseAssetBacking`：Balance proof を再帰検証し、private commitment を開き、
extended state の commitment が L1 で finalized な root であることを要求し、token vector から asset tree
を再構成）です。そこで (c) を 7 つに分解しました：
(c0) Materializer の staticcall view = Manager storage snapshot（(f1) 同種の cross-contract 前提；
`SystemSafety.Step.materialize` の `fe` が Manager state に結ばれていなかった事実を B2 の調査で確認）、
(c0b) Manager の `tokenFundsDigest` = 参照 Keccak（Sol :1685-1686）、(c1) backing verifier の健全性
（(a0) と同一 artifact だが Materializer の adapter で）、(c2) `CloseAssetBacking` の命令単位 lowering、
(c3a)(c3b) hash 参照一致と同長 pair の衝突耐性、**(c4) `finalizedBalanceIsBacked` — 残余**：
`CircuitConstraints` を満たす witness の active row の金額が、head が finalize した root における
`l2Entitlement root channel token`（validity chain が account する L2 の権利、パラメータ）以下。
導出定理 `materialized_credits_are_finalized_l2_balances_of_boundary`：受理された materialization の
各 credit は、head-finalized root における backing witness の active row の金額に等しく、L2 entitlement
以下。`SystemSafety.mle_assumption_does_not_imply_fund_safety` は (c4) を具体 witness（active row 22、
entitlement 0）で反証する形に付け替え。放電に必要なのは BalanceCircuit → SwitchBoard → ValidityChain →
DepositChain/WithdrawalChain の合成で、これが次の project です。

**B1：`CloseAssetBacking` の命令単位化（30 → 110 定理）。** 既存の `constructorProgram`（468 entry、
45 constructor）に `holds` を与え、`program_satisfied_implies_constraints` を副仮定なしで証明
（`True` は 25 entry：allocation、config、build）。`CircuitConstraints` は byte 一致。
**B2：`BackingBridge`（新 module、52 定理）。** `materializeSignedHead` 受理からの receipt
（30 conjunct：verifyCompact の語、`validateBackingPublicInputs`、root の finality、attestation、
view getter との一致、26 語の decode）、`limbsToBytes32 = Words8.value`、token vector の byte 単射性
（`word_bytes_token_vector_binding`）、credit が registry vector そのものであること。

**N：NTT 正当性の証明（新 module `NttCorrectness`、157 定理）。**
`ntt_computes_negacyclic_product : FalconGadgetProgram.NttComputesNegacyclicProduct` を無条件に証明。
forward は stage 不変量で「ψ^(2·bitrev(j)+1) での評価」、pointwise は環準同型、inverse は GS が CT を
butterfly 単位で反転する（各段で ×2、9 段で 512 を `n⁻¹` が打ち消す）。逆元表も q の素数性も不要。
これで field (d2') は削除され定理になりました。

**M：機械的な忠実性証拠（Rust、test-only）。** `src/faithfulness.rs` が build 済み `CircuitData` の
`representative_map`・定数 wire・`range_check` 幅・public input 順序を読み、Lean の `holds` の
構造的主張（connect / 定数 / 登録順 / range 幅）を照合。7 program・275 行、177 行 ok、8 行は
mutation（証明失敗を確認）、`not-static`（算術・gadget 意味論）は前提に残る。**不一致ゼロ。**
probe は `#[cfg(test)]` の挿入のみ（削除ゼロ；`shift-linemap.py` は insert-only でなければ失敗する）。
6 本の line map を renumber し挿入部を `test-only` span に（Lean docstring の行引用は挿入前の番号のまま、
`evidence/README.md` に対応表）。実行：18 test / 209 s / peak 26.6 GB。

**P：公開文書 `PRACTICAL-SAFETY-PROOF.md`。** 英語本文＋日本語要旨。主定理、23 field の前提台帳
（各前提の証拠・反証条件・確認方法）、合成定理、再現手順、既知の隙間。

`TrustBoundary` は 18 → **23 field**（(c)→7 個、(d2') 削除）。検証：main guard PASS（132 modules /
現行 79 / 497 hashes）、line guard PASS（169 maps；test-only 25,892 行に増加）、回帰 suite・
ledger-writers・fixture parity green、`--require-complete` は exit 1。現行 named theorems **5,311**
（implementation 74 module・5,092）。runtime の非 test 経路は無変更。

### 2026-09-11（第 3 ループ）：集約スタックの命令単位化と replay ledger の書込元 inventory

計画は `tasks/loop-2026-09-11-aggregate-program-plan.md`。前ループで構造中に唯一残った回路丸ごとの前提
(d1) と、不透明 callback を gate 集合に結ぶ (d2) を、close 系回路と同じ命令単位に落としました。
併せて (g1)(g2) を Solidity の書込元 inventory に還元しています。`TrustBoundary` は 17 → **18 field**。

**G：Falcon gadget の命令列（新 module `FalconGadgetProgram`、47 定理）。** `FalconSigVerifyTarget::build`
（gadget.rs:651-736）の builder 呼び出し 23 個を `GadgetOp` として転記（`True` は 3 個：twiddle table、
β 定数、build）。**NTT は畳み込まず具体的に転記**（`powModQ`・`bitReverse9`・CT-DIT 9 段の
`nttForward`・GS の `nttInverse`・`pointwise`、mod-q 還元 15,872 箇所の商 wire に `modQGates` を課す）。
`gadget_program_satisfied_implies_circuit_satisfied : ProgramSatisfied gadgetProgram a → CircuitSatisfied e circuitProduct (readWitness a)`
を**副仮定なし**で証明。従来の不透明 `PolynomialProduct.mul` は具体的 `circuitProduct` に置き換わり、
残る境界は「この転記された NTT が negacyclic 積に等しい」（`NttComputesNegacyclicProduct`、
`schoolbook_negacyclic` から転記、未証明）だけです。ψ の位数・`n⁻¹`・twiddle の spot check を `decide` で固定。

**A：集約木の命令列（新 module `FalconAggProgram`、78 定理）。** leaf 回路（agg.rs:268-305、8 op）と
level 回路（:370-479、level k で 23 + 8·2^(k−1) op）を転記。Goldilocks 上の `sub/mul/add` を法演算として
`holds` に書き、範囲仮定（count ≤ 2^(k−1)、limb < 2^32）から Nat 等式を導出。
`leaf_program_satisfied_implies_statement`、`level_program_satisfied_implies_compose`
（既存の `levelCompose` に一致）、抽象的な充足関係 `Sat` 上の帰納定理
`satisfiable_top_level_gives_witness_list`（level 3 の充足 ⇒ 1〜8 個の `CircuitSatisfied` 証人と
左詰めの鍵 digest 列）、`sigEnvOf e`（`pkDigest := limbsOfNat ∘ falconPkDigest e`）経由の
`SignerEvidence` 導出、そして gadget 命令列を leaf に継ぎ込んだ `GadgetLevelLowering`
（どの conjunct も builder 呼び出しの転記で、gate 構造を丸ごと含まない）を証明。
2 署名者の level-1 具体例あり。

**I：replay ledger の書込元 inventory（新 module `LedgerWriters`、57 定理）。** 読取専用の調査で、
(g1)(g2) の対象 storage は各 1 箇所しか書込元がないことを確認しました：
`usedWithdrawalNullifiers` :2231（set のみ）、`receivedChannelFunds` :2364、`totalCreditedOut` :2398、
`finalizedChannelFundAmount` :1681（`+=` のみ）、`materializedChannelExit` :461（`== 0` guard 付き）。
proxy・`delegatecall`・`selfdestruct`・assembly `sstore` は無く、Rollup は Manager storage を書けません。
Lean 側では 13 個の Manager entrypoint と 7 個の Materializer entrypoint を列挙し、
`manager_entrypoints_are_ledger_monotone`、`non_step_manager_entrypoints_are_ledger_neutral_except_cap`、
`finalize_close_only_raises_cap`（増分の厳密形）、`materializer_entrypoints_keep_the_latch` を証明。
inventory は `.github/ci/check-ledger-writers.py` が Solidity を走査して照合し（self-test 6 件）、CI に配線しました。

**発見：旧 (g1) の `cap t = cap s` 節は配備契約に反証されます。** `finalizeCloseGuarded`
（`_finalizeClose` :1681 で `cap += …`）は `ManagerValue.finalizeCloseCore` としてモデル化済みですが
`SystemSafety.Step` の constructor ではないため、`Unmodeled` な遷移が `cap` を書きます。
`SystemSafety` は (g1)(g2) を消費していないので下流は無変更のまま、節を単調 `cap s ≤ cap t` に訂正し、
`only_cap_writer_is_outside_step` が唯一の例外として pin しています。

**T2：field の置換。**

| 旧 | 新 | 旧結論の定理 |
|---|---|---|
| (d1) `aggregateStatementLowering`（回路丸ごと）、(d2) `falconPredicateIsGadget`、`Models.sigEnv`/`falconMul` | (d0') `levelRecursionSoundness`（各 level の定数鍵での再帰検証健全性）、(d1') `aggregatePrimitiveLowering`（`GadgetLevelLowering`）、(d2') `nttComputesNegacyclicProduct` | `signature_validity_of_boundary`（結論は `SignerEvidence (sigEnvOf m.falconHash) …`）、`level_lowering_of_boundary` |
| (g1) `durableNullifierLedger`、(g2) `durableMaterializationLatch` | (g1') `ledgerWritersAreInventoried`、(g2') `latchWritersAreInventoried`（(h) 同種の source refinement：「対象 storage に触れるモデル外遷移は inventory 済み entrypoint の実行」） | `durable_nullifier_ledger_of_boundary`（cap 単調）、`durable_materialization_latch_of_boundary`（旧文そのまま） |

`Models` は `aggregateLevelDigest : Nat → List Nat`（level 0〜3）と `aggEnv`（level 回路内の不透明な
子検証関係）を持ちます。digest pinning は `AggregateLevelPinnedDigestIsProgramDigest` として分離。
`signature_gap_is_now_per_primitive` が残余 4 前提を列挙します。**構造中に回路を丸ごと仮定する field は
もう存在しません。** `SystemSafety`・各回路 module・`FalconAggregate`・`FalconCore` は無変更。

検証：main guard PASS（130 modules / 現行 77 / 478 hashes / 1 submodule pin）、line guard PASS（169 maps）、
回帰 3 suite + ledger-writers self-test green、fixture parity green、`--require-complete` は exit 1。
現行 named theorems 5,043（implementation 72 module・4,824）。runtime 差分なし。

### 2026-09-11（第 2 ループ）：hash binding (e1, e2) と署名妥当性 (d) の前提を縮小

役割分担は前ループと同じ（Fable 5.1 が計画と検証、Opus 5 が実装）。計画は
`tasks/loop-2026-09-11-hash-signature-plan.md`。`TrustBoundary` は 13 field → **17 field**、
`Models` から不透明な `signers` 関係を外し、`sigEnv`・`falconHash`・`falconMul`・
`aggregateCircuitDigest`・`authorized`（署名 1 本の粒度の「鍵保持者が承認した」関係）を加えました。

**K：Keccak-256 の参照仕様（新 module `Keccak256`、45 定理）。** Keccak-f[1600]・rate 1088・
原 Keccak padding（`0x01…0x80`）を `List Nat` 上に定義し、出力長 32・byte 正準性・big-endian
`bytesToNat` の単射性を証明。公開ベクトル 2 本（空文字列、`"abc"`）と自作 2 本（135 byte の
padding 境界、200 byte の 2 block）を **`decide` による kernel 証明**として収録（各 1〜4 秒；
Lean 4.10 の kernel は `Nat.land/lor/xor/shiftLeft/shiftRight` を GMP 加速します）。
4 本すべてをランタイム自身の `keccak-hash 0.8.0` crate で独立に再計算し一致を確認しました。
この module は in-repo の source 行を持ちません（回路側は Cargo.lock で
`2507786148ae…` に固定された外部 crate `plonky2_keccak`、契約側は EVM opcode）。
Cargo.lock を manifest の tooling hash に加え、pin の変更が guard に見えるようにしました。

**E：token-funds preimage の ABI 忠実性（`SettlementCloseBridge`、+9 定理）。** Solidity 側の
`tokenFundsPreimage` が 368 byte 固定長で `(registry, count, amounts)` に単射であること、回路側の
`wordBytes (tokenFundsPreimage w)` も `Shape` の下で 368 byte であることを証明
（`token_funds_preimage_injective`、`token_funds_compared_strings_same_length`、`be_bytes_injective`）。
旧 (e2) の docstring が「衝突耐性と ABI 符号化の忠実性」と呼んでいた 2 つのうち後者は消えました。

**D1：署名の橋（新 module `CloseSignatureBridge`、21 定理）。** close 回路の
`AggregateStatement` と `FalconAggregate.AggStatement` の 73 word layout が同一であること
（`to_agg_statement_public_inputs`）、受理された level-3 集約木から `SignerEvidence`
（署名者数・左詰めの鍵 digest 列と零 suffix・単一 message・各 active slot の承認）が出ること
（`accepted_aggregate_tree_gives_signer_evidence`）を証明。`SlotWitness` と `FalconCore.CircuitWitness`
の対応は field ごとに恒等で、唯一の変換 `digestOfLimbs`（8 limb の big-endian 詰め、
bytes32.rs:18-22 / hash_to_point.rs:73-76 / gadget.rs:378-380）は単射性を証明済み。
2 署名者の具体木で 4 前提すべてを満たす非空性例を持ちます。

**T：field の置換（`TrustBoundary` 35 → 43 定理）。**

| 旧 field | 新 field | 旧 field の結論 |
|---|---|---|
| (e1) `circuitKeccakIsSolidityKeccak` | (e1a) `solidityKeccakIsReference`（EVM opcode = 参照仕様）、(e1b) `circuitKeccakIsReference`（`plonky2_keccak` = 参照仕様、(a) の「gadget が `out = e.keccak preimage` を強制する」とは独立） | `circuit_keccak_is_solidity_keccak_of_boundary` |
| (e2) `tokenFundsHashBinding`（不透明 callback） | (e2) 同名、参照 `Keccak256.keccak256` 上の同一 pair に対する衝突耐性 | `token_funds_hash_binding_of_boundary` |
| (d) `signatureValidity`（集約検証 ⇒ 不透明 `signers`） | (d0) `aggregateRecursiveVerifierSoundness`、(d1) `aggregateStatementLowering`、(d2) `falconPredicateIsGadget`、(d3) `falconUnforgeability` | `signature_validity_of_boundary`（⇒ `SignerEvidence`） |

(d0) は plonky2 の FRI 再帰検証器の健全性で、**(a0) の受容には含めません**（同じ pinned
サブモジュールに同居しますが、運用者の受容は MLE/WHIR 検証器に限定した判断です）。
(d1) は `FalconAggregate` に `BuildOp` プログラムがまだ無いため、構造中で唯一残る回路丸ごとの前提
（digest pinning も内包）。(d3) は NTRU/GPV 格子仮定、(e2) は Keccak-256 の衝突耐性で、どちらも
このプロジェクト内では原理的に放電できません。`rejecting_environment_satisfies_every_premise`
は新 field 用の仮説（参照等式 2 本、`noFalconAccept`、`authorizedTrivially`）を取り、
`reference_keccak_models_satisfy_hash_premises` が hash 前提対の非空性を示します。
`SystemSafety` は無変更（`signers`・旧 field を参照していません）。

検証：main guard PASS（127 modules / 現行 74 / 473 hashes / 1 submodule pin）、line guard PASS
（169 maps、新 module は既存 map への合成登録）、回帰 3 suite・fixture parity green、
`--require-complete` は exit 1。現行 named theorems 4,858（implementation 69 module・4,639）。
runtime 差分なし。

### 2026-09-11：gate lowering の前提を回路全体から命令単位へ縮小

対象は `CloseStatementLowering` と claim 側の前提 (b1)(b2) です。「受理された plonky2 statement から
手書きの `CircuitGates` へ」という回路丸ごとの黒箱を、3 層に分解しました。役割分担は
Fable 5.1 が計画と結果確認、Opus 5 が実装です。

**L1（形の統一）。** (b1)(b2) も close と同型の `StatementLowering` に分割し、
`MLE 前提 (a0) + 各回路の lowering` に揃えました。旧 field の結論は
`close_proof_soundness_of_boundary` 等の互換定理として残り、`SystemSafety` の呼び出しは無変更で通ります。
検証で 1 件の問題を捕捉しました。互換定理が入れ子 `namespace` 内の camelCase で宣言されており、
登録器の組み立てる定数名と実体が食い違って guard の公理 probe が失敗する状態でした。
トップレベルの snake_case に改名して解消しています。

**L2（回路ごとの導出）。** 各回路が既にデータとして持っていた builder 呼び出し列
`constructorProgram : List BuildOp` に、命令ごとの局所的な充足意味論 `BuildOp.holds` を与え、
`program_satisfied_implies_gates : ProgramSatisfied constructorProgram a → CircuitGates e (readPublic a) (readWitness a)`
を 3 回路すべてで証明しました。**前提は `ProgramSatisfied` のみで、残余の `EnvironmentGates` は 3 回路ともゼロ**です。

| 回路 | 定理数 | `BuildOp` 追加 | 制約を出さない命令（`True`） | `CircuitGates` の変更 |
|---|---:|---|---|---|
| CloseCircuit | 58 → 92 | 0 | 47 命令中 4（config、build、生 allocation、insertion path） | なし（commit 基準と byte 一致を確認） |
| WithdrawalClaimCircuit | 37 → 53 | 0 | 32 命令中 10（config、profiling observe、build、生 allocation） | なし |
| PostCloseClaimCircuit | 32 → 54 | 1（`add_virtual_target` :372、転記漏れ） | 少数 | なし |

いずれも非空性の例（2 cosigner・非零 genesis fund・実 freeze-nonce 増分など）を持ち、
`readPublic` が期待する statement を読み戻すことまで定理化しています。
`holds` の各ケースは source 行を docstring に引用しており、source が出さない制約は加えていません。
PostClose の `DecryptionHolds` は gate 記録より強く（8192 係数の canonical 性と `a ≠ 0` / `c1 ≠ 0`）、
これは手書き `ConstructorGates` が実回路の下近似であったことを意味します。

**L3（前提の昇格）。** `TrustBoundary` の 3 field を `ClosePrimitiveLowering` /
`WithdrawalPrimitiveLowering` / `PostClosePrimitiveLowering` に置き換えました。内容は
「pinned digest の plonky2 statement が充足可能なら、**同じ** `constructorProgram` を我々の命令意味論で
充足する割当が存在し、それが当該 statement を読み戻す」です。旧 `*StatementLowering` は instance 上の
定理として再導出され、`*_gap_is_now_per_primitive` は受理から「プログラムの充足割当」と「gate」の両方が
出ることを示します。digest pinning は `*PinnedDigestIsProgramDigest m digestOf` として分離し、
`*_digest_pinning_and_program_lowering_give_primitive_lowering` で field に結び付けています。
`TrustBoundary` は 8 → 35 定理、field は 13 個のまま。

**残る前提は次の 2 つに限定されました。**
(i) `BuildOp.holds` の各ケースが plonky2 の対応 primitive の強制内容と一致すること（命令の種類ごとの有限の照合）、
(ii) `pinnedCircuitDigest adapter` が `constructorProgram` の digest であること。
回路全体を黒箱として仮定する箇所は前提から消えました。(a0)、(c)〜(h) は従来どおりです。

line-map には新定理を紐付け（close 46→57、withdrawal 32→46、post-close 30→42 定理）、
境界 `primitive-semantics-faithfulness` を 3 map に追加しました。source hash・行数・span 分割は不変です。

検証：main guard PASS（125 modules / 現行 72 / 470 hashes）、line guard PASS（169 maps）、
回帰 3 suite と fixture parity green、`--require-complete` は exit 1。現行 named theorems 4,775
（implementation 67 module・4,556）。runtime 差分なし。

### 2026-09-10：lib 単体テスト 711 件の全数実行

前回「未確認」として残した回路系・暗号系の lib テストを、submodule 単位の chunk に分けて直列・背景で
全数実行しました。結果は **711 件中 711 件を実行し、修正済みの 1 件を除いて全通過** です。
実行済み集合と `cargo test -- --list` の 711 件を照合し、未実行ゼロ・未通過ゼロを確認しています。

| chunk | 件数 | 秒 | 備考 |
|---|---:|---:|---|
| 中間層（wallet_core, publisher 系ほか 14 module） | 195 | 1,093 | wallet_core は ~18 GB RSS |
| regev | 51 | 6 | 純算術 |
| falcon_sig（measure/bench 除く） | 77 | 390 | 再帰証明を含む |
| circuits::balance / close / cancel_close / close_asset_backing | 49 | 249 | |
| circuits::channel 請求系 + decryption_gadget | 35 | 3,337 | うち `property_vs_native_oracle` 1 件が 40 反復で **45 分・30 GB** |
| circuits::channel::state_update_verifier | 50 | 27 | 最重量 file だがテストは軽い |
| circuits::channel::e2e_flow / validity / withdraw / witness | 63 | 667 | |
| measure / bench 系 | 6 | 158 | 単独実行なら通る。以前の OOM は無フィルタ実行のメモリ蓄積が原因 |
| 個別に取りこぼした 6 件（close_pis, h1_gadget, review_hardening） | 6 | 2 | |

**新たに見つかった失敗 1 件（古いテスト・修正済み `31aaf6c`）。**
`wallet_core::slot_capacity_tests::join_path_reaches_slot_256_and_beyond` は fabricated member に
`RegevPk::padding()`（零多項式）を与え、「build_record は鍵を検査しない」と自ら注記していました。
`b5bafb7`（2026-09-06）で `build_record` が active slot の Regev 鍵に形状・canonical 性・非零・相異を
要求するようになり、テストが取り残されたものです。テストは 2026-07-19 の `f08ba2e` 由来で検査より
7 週間古く、検査側は正当（零の `a` は padding slot 専用）です。修正はテスト側のみで、slot ごとに
異なる非零・canonical な `a[0]` を与え、注記を訂正しました。runtime は変更していません。
検証は Fable 5.1 が分類と計画、Opus 5 が実装を担当し、分類根拠（両 commit の日付、`git show`）を
実装側にも独立に確認させました。

**運用上の教訓 2 点。**
- **libtest の filter は部分文字列一致**で、`withdrawal_claim::` は `withdrawal_claim_circuit::` に
  一致しません。初回 pass で 47 件が実行されずに `ok` と報告され、`--list` との照合で発覚しました。
  末尾 `::` の submodule filter は使わず、必ず全件リストと突き合わせること。
- **OOM の SIGKILL はテスト失敗に見えます。** 無フィルタの `--lib` は `--test-threads=1` でも落ちますが、
  同じテストは chunk 単独なら通ります。chunk 化と `signal: 9` の判別を runner に組み込んでいます。

**CI への反映。** 16 GB の `ubuntu-latest` に載る `regev::` を lib 手順に追加（189 → 240 件）。
`wallet_core::`（18 GB）、`circuits::`（最大 30 GB）、`falcon_sig::`（数 GB の再帰証明）は routine step に
できないため、実測値を手順のコメントに残し、既存の専用 `--test` 手順に委ねます。

### 2026-09-09：確認済み不具合の修正、古いテストの更新、CI の穴を塞ぐ

監査開始以来はじめて **runtime に差分**が出た checkpoint です。基準 `05ec7ae` に対する変更は
`src/utils/poseidon_hash_out.rs`、`src/utils/error.rs`、`src/common/balance_state.rs`（テスト部のみ）と
`.github/workflows/ci.yml` の 4 ファイルです。回路、proof parameter、proof format は変更していません。

**1. 到達不能だった canonical 性検査の修正（根本原因）。**
`TryFrom<Bytes32> for PoseidonHashOut` の round-trip 検査は、`reduce_to_hash_out` が 8 個の u32 limb を
4 個の u64 に組み替えるだけで、`From<PoseidonHashOut> for Bytes32` がそれを厳密に逆変換するため、
**あらゆる入力で成立し決して発火しません**でした。その結果 `ChannelRegRecord::validate` の
非 canonical identity 拒否 3 種が dead code となり、リポジトリ自身のテストが失敗していました。
修正は Goldilocks 位数に対する明示的な要素検査を round-trip の**前**に置き、エラー variant
`PoseidonHashOutError::NonCanonicalElement(usize)` を追加するものです。`reduce_to_hash_out` と
`From` impl は未変更なので、多対一の読み取りを意図して使う多数の呼び出し元は影響を受けません。

**2. 古いテストの更新。** `balance_state` の 2 件が member_count 16 の通過を主張していました
（`fd467ea` で sig-cluster が 8 に制限されて以降は誤り）。`MAX_SIG_CLUSTER` を使うよう更新し、
併せて無効な基底 16 から作られていた否定テスト 3 件も有効な基底に直しました。これらは
「上限超過は拒否される」ことを主張しながら、実際には基底自体が無効なために通っていたものです。

**3. CI の穴を塞ぐ。** workflow は名前付きの `--test` 統合テストのみを実行し、`cargo test --lib` を
一度も走らせていませんでした。上記 3 件の失敗はすべてこの穴に落ちていました。
`lib unit tests (pure-logic modules)` 手順を追加し、`common:: utils:: ethereum_types::` の
**189 テスト・ignored 0** をリポジトリ自身の `rust-test-guard.sh` の下で実行します（約 20 秒）。
`circuits::` / `regev::` / `falcon_sig::` は実回路を構築するため除外しました。実測で `circuits::` だけで
**37 分・25 GB RSS でも完了せず**、無フィルタの `--lib` は `--test-threads=1` でも OOM で SIGKILL されます
（この SIGKILL はテスト失敗に見えます）。これらは既存の専用 `--test` 手順が担当します。

**4. モデルの追随。** guard がただちに source の hash 変化を検出して停止し、意図どおり
「モデル対応を見直してから manifest を更新せよ」と要求しました。見直しの結果、変換を独立にモデル化
していた 5 module を更新しています。

| module | 対応 |
|---|---|
| `H1Gadget` | `nativeTryFrom` を `Except` 化し canonical 性検査を前置。`native_try_from_requires_canonical_elements`、`goldilocks_order_bytes_are_now_rejected` ほか。round-trip 半分が今も到達不能であることは `native_try_from_roundtrip_test_alone_is_unreachable` として保持 |
| `UtilGadgets` | エラー enum に variant を追加し、variant 集合・Display 文言・エラー優先順位（canonical 性が round-trip に先行）を固定 |
| `ChannelRegChain` | `Words8.canonical` を「Goldilocks 要素検査 ∧ round-trip」に分割。`native_canonicality_check_cannot_fail` を **`byte_round_trip_alone_cannot_reject`** に改名（命題は保持、名前と説明が現状と食い違っていたため）。`non_goldilocks_record_rejected` で拒否が live であることを証明 |
| `BlockTypes` | 命題は保持し docstring を訂正。`non_canonical_pk_g_rejection_is_reachable` を追加して両方向を記録 |
| `TxSettlement` | `native_try_from_never_rejects_u32_limbs` と `modulus_encoding_passes_native_try_from` を改名・逆転。**この回路自身の経路は変わりません**：`tx_settlement.rs` は `send_leaf.tx_tree_root` を無変更の多対一 `reduce_to_hash_out` で読むため、修正後の変換が拒否する byte 列を依然として受理します（`native_settlement_accepts_bytes_the_fixed_try_from_rejects`）。非 canonical な tx-tree root の native 拒否は今も `CanonicalRoots` 前提、回路側は `ToHashOutGates` に依存します |

**5. 登録器の安全装置。** `register2.py` は実装 hash の変更を既定で拒否します。今回のように正当な
見直しを経た場合のみ `--accept-source-change=<path>` で明示的に受理する経路を追加しました。
再実行の副作用で hash が動くことはありません。

検証：main guard PASS（125 modules / 現行 72 modules / 470 hashes）、line guard PASS（169 maps）、
回帰 51 件と fixture parity 40 件および 18 fixture・177 項目が green、`--require-complete` は exit 1。
行分類は translated 31,095 / untranslated 41,784。

### 2026-09-08（追記）：MLE サブモジュールを信頼仮定として導入

運用者の判断により、pinned MLE/WHIR サブモジュールを **翻訳せず信頼する** ことにしました。
KZG ceremony と同じ扱いです。この決定は次の 3 か所に記録され、証明としては扱いません。

1. **Lean の名前付き前提。** `TrustBoundary.mleVerifierSoundness`（前提 (a0)）。
   pinned adapter に対し EVM view の `verifyCompactPublicInputs` が語列を返したなら、
   その語列は adapter の pinned circuit digest が同定する回路の plonky2 statement の
   公開入力であり、その statement は充足可能である、という主張です。公理ではなく、
   他の 12 前提と同格の structure field です。
2. **inventory の scope note。** MLE の 68 file・33,974 行は引き続き **untranslated** に分類し、
   検証済みには算入しません。行分類の数値は仮定の導入前後で変わりません。
3. **manifest の commit pin。** `contracts/lib/polygon-plonky2` を
   `6cefc6acee18d0d76b52f1c22c0113e3ae8fbf78` に固定。仮定はこの commit にのみ及び、
   別 revision は未受容の別成果物です。

**この仮定が買うもの。** close 経路について、前提 (a) の隙間が 1 段階に縮みます
（`mle_assumption_reduces_close_soundness_to_gate_lowering`）。残るのは
`CloseStatementLowering`、すなわち digest が同定する plonky2 statement が本モデルの記述する
回路であり、その充足割当が `CircuitGates` の witness を与えるという段だけです。
これは gate 生成と `CloseCircuit.FieldAndGadgetLowering` を要し、証明されていません。

**この仮定が買わないもの（kernel 検証済みの反例つき）。**
`SystemSafety.mle_assumption_does_not_imply_fund_safety` は、(a0) が成立しながら
`TrustBoundary` の instance が存在しない環境を与えます。adapter は実際に受理し、
103 語の close statement を返しますが、そのチャネルは預入していない token を 1 単位主張しており
前提 (c) が破れます。`mle_assumption_alone_does_not_yield_close_gate_soundness` は
lowering が破れる環境を与えます。いずれも vacuous な仮定ではなく実際の受理の上に立ちます。

依然として未証明のもの：回路から gate への lowering、KZG / DA 可用性、呼出し側が渡す公開入力が
実在のチャネルを表すこと、close vector の預入による裏付け (c)、署名妥当性 (d)、
hash の一致と束縛 (e1, e2)、L1 canonical head / finality (f1, f2)、
未モデル化 entrypoint に対する storage 永続性 (g1, g2)、source / EVM / compiler refinement (h)、
および claim 側の前提 (b1, b2)。

### 2026-09-08：依存層と暗号層の翻訳、実在するテスト失敗 3 件

- **125 Lean モジュール**を build。現行 **72 モジュール**、**470 reviewed-source hashes**、
  **169 source maps** を検証して main guard・line guard とも成功。
- 物理行分類：手書き翻訳 **31,085**、依存境界 **10,850**、非実行 **9,816**、
  テスト専用 **23,834**、未翻訳 **41,783**。前回 checkpoint から翻訳が 19,450 → 31,085 に増加。
- 追加 module は 15 件・約 1,790 定理です。木（Merkle / sparse / incremental / indexed）、
  ethereum_types codec、common の値型と channel.rs、block 系の型、utils gadgets と constants、
  Falcon（集約・core・vendor）、Regev（暗号化・transfer STARK・hash 署名）、木の具体化と
  hash chain、MLE prover bridge です。

**前提が実装から導出されたもの。**

| 前提 | 結果 |
|---|---|
| nullifier freshness | `IndexedMerkleTree.accepted_insertion_implies_key_absent`。受理された挿入証明は key の不在を含意します。前提は Poseidon の衝突耐性（葉の 18 語符号化の単射性は証明済み）、順序集合不変条件（空木で成立・挿入で保存）、key の範囲の 3 つのみ。hash 仮定なしでも `insert_fails_iff_key_present` が成立します |
| `select_vec` の選択意味論 | `UtilGadgets.select_vec_one_hot_selects_candidate`。SwitchBoard が仮定していた 4 積和選択を実装から証明。ただし one-hot 性は `select_vec` 自身では強制されません |
| Regev の定数と符号化 | `RegevCore.constants_agree_with_decryption_gadget`。N=2048、q=2013265921、Δ=(q−1)/256 が回路側と一致。金額符号化は u64 上で単射 |
| 木の高さと backing | `TreeInstances` が全 13 木を確定。既登録 module が固定する値との数値不一致はゼロ |
| 定数 | `UtilGadgets` が constants.rs の全定数を固定。他 module の主張との不一致はゼロ |

**リポジトリ自身のテスト失敗 3 件（CI は `cargo test --lib` を実行しないため未検出）。**

1. **実在の不具合。** `common::channel_registration::tests::test_channel_reg_validate_rejects_noncanonical_identity_encodings` が失敗します。`ChannelRegRecord::validate` の非 canonical identity 拒否は到達不能で、`PoseidonHashOut::try_from(Bytes32)` が同じ 32/32 分割を組み直す全域関数であることが原因です。テストは正しい意図を主張しており、コード側の欠陥です。Lean 側でも
   `ChannelRegChain.byte_round_trip_alone_cannot_reject`（旧 `native_canonicality_check_cannot_fail`）と
   `BlockTypes.canonicality_rejections_come_only_from_the_callback` が独立に同じ結論に達していました。
   **2026-09-09 に修正済み。** 下の追記を参照してください。
2. **古いテスト。** `common::balance_state::tests::balance_state_validate_multi_n` と
   `balance_state_delegate_count_regions_and_h1` は member_count 16 が通ることを主張しますが、
   `fd467ea`（sig-cluster を 8 に制限）以降 2..=8 が正です。テスト側の更新漏れです。
3. **CI の盲点そのもの。** `.github/workflows/ci.yml` は個別の統合テストのみを実行し `--lib` を
   一度も走らせません。上記 3 件はいずれもこの盲点に落ちています。なお lib 全体の実行は
   重い回路テストで OOM により SIGKILL されるため、測定系を除いた分割実行が必要です。

**暗号層で確定した認可の連鎖（人間の判断が必要）。**

- **Falcon 検証器は vendor 木に存在しません。** `src/falcon_sig/vendor/` に `fn verify` は 0 件で、
  検証は `mod.rs` と回路側 `batch.rs` にあります。復号器が許す最大係数 2047 が 512 個並ぶと
  二乗ノルムは約 21.5 億で `beta^2 = 34,034,726` を大きく超えます
  （`FalconVendor.decode_range_does_not_imply_norm_bound`）。境界検査は呼び出し側の責務です。
- **回路 gadget が署名を検証するかは、gadget 自身が制約しない 1 本の wire 次第です。**
  wire が 1 なら native の述語全体を検証し、0 なら鍵 commitment と代数関係のみが残り、
  方式唯一の受理判定であるノルム境界検査が定数 0 の範囲検査に置き換わります
  （`FalconCore.padding_slot_norm_gate_is_trivial`）。close / cancel-close は `member_count` に束縛します。
- **受理された集約証明は署名者の相異性も member 集合への所属も示しません。**
  署名者数が実際に受理した slot 数と一致すること、鍵リストが左詰めで残りが厳密に零であること、
  全 slot が同一メッセージに対して評価されたことは証明されています
  （`FalconAggregate.agg_tree_ok_characterization`）。
- **`agg_list.rs:329` の `range_check(count_minus_one, 4)` は署名者数 1〜16 を許します。**
  上限 8 は集約回路の構造からのみ来ており、この検査からは来ていません。
- **hash 署名は再生可能なトークンです。** 検証が確立するのは公開値 `pk_b` の Poseidon2 原像の知識と
  メッセージの Fiat-Shamir 束縛だけで、公開値ベクタに nonce も期限も含まれません。健全性には
  依拠側が `pk_b` を登録済み member leaf から解決し、IMPA digest を一意にして高々一度受理する
  ことが必要ですが、どちらも当該ファイルでは強制されていません。
- **transfer STARK の桁上げ制約族は整数上で健全です。** `value(before) = value(after) + value(delta)`
  と underflow の不在を field 制約から導出しています（`RegevProofs.conservation_over_integers`）。

**その他の source 上の観察。**

- 葉と節点で domain 分離がなく、高さ 32 の空 SendTree と空 TxV2Tree の root が hash 仮定なしで一致します
  （`TreeInstances.empty_send_tree_root_equals_empty_tx_v2_tree_root`）。分離は消費側の回路に依存します。
- `channel_tree.rs` のコメントは member_pubkeys_root を 1024 slot と書きますが、実際は高さ 3 の 8 slot です。
- `channel.rs` の `validate()` は構造のみを制約し、両 root を保ったまま鍵集合全体を差し替えても通ります
  （`ChannelTypes.validate_accepts_substituted_member_set`）。署名検証器は blob の内容に反応しません。
- domain 非衝突の検査は test 専用かつ release で無効です。Lean 側で 63 個の値の非衝突を証明しました。
- `U32LimbTargetTrait::get_witness` は field wire を 2^32 で黙って切り捨てます。
- sparse 木の範囲外 index 更新は葉を記録しつつ root を変えません。
- retired な member-set-update 経路は既定 build では compile されません（`deprecated-msu` feature）。
  ただしこれは manifest の記述のモデル化であり、経路が安全であるという主張ではありません。
- `agg.rs` のコメントは `AGG_LEVELS = 4`・公開入力 137 と書きますが、コードは 3 と 73 です。
  `batch.rs:695` の assert メッセージも 137 のままで、これは assert 発火時に運用者が読む文言です。

### 2026-09-07：全 core file 対応・信頼境界の集約・全 entrypoint 合成の checkpoint

- **110 Lean モジュール**を build。現行 **57 モジュール・2,839 named theorems** の実在・種別・
  推移的 kernel axioms を検査して main guard 成功。実装対応は **52 モジュール・2,620 定理**、
  前段の仕様側は 5 モジュール・219 定理です。前回 `680146f` から **1,566 定理**追加。
- **273 reviewed-source hashes、1 MLE gitlink、76 source maps** を検証して line guard 成功。
- guard 回帰テスト 51 件（main 29 + line 22）に加え、fixture parity の回帰 40 件も成功。
- 物理行分類：手書き翻訳 **19,450**、依存境界 **4,948**、非実行 **6,832**、
  テスト専用 **13,927**、未翻訳 **72,211**。**core 71 file すべてが対応表を持ちます**
  （未対応 core は 0 行）。未翻訳の残りは全て `src/common`、`src/utils`、`src/regev`、
  `src/falcon_sig`、MLE 等の依存側です。これは証明率ではありません。

**信頼境界の集約。** [TrustBoundary](./Zkp/Implementation/TrustBoundary.lean) は、これまで各定理の
引数に散らばっていた未証明の前提を、既存モデルの型で書いた 12 の名前付き field に集約します。
close proof soundness、claim proof soundness、close vector の自チャネル預入による裏付け、
署名妥当性 oracle、有限個の比較対に対する hash binding、L1 canonical head / finality、
durable replay ledger、source/EVM/compiler refinement です。公理は追加していません。
全 verifier が拒否する退化した環境でのみ inhabitation を示し、その環境では資金移動が
一切認可されないことも併記しています。

**全 entrypoint の合成。** [SystemSafety](./Zkp/Implementation/SystemSafety.lean) は Rollup 入金、
withdrawNative / withdrawERC20、materializer credit、Manager pull、submitClaim、
claimCredit payout、close の request / cancel / finalize、rollback を 12 の `Step` で覆い、
任意の有限 trace について次を **前提なしで** 証明します。

- `trace_conserves_per_token`：token ごとの `Rollup escrow + pending + Manager unspent` の保存。
- `trace_channel_attribution`：Manager の `received` が自チャネルの cap を超えないこと、
  cap が書き換わらないこと、materialization が一度 latch されたら保持されること。
- `trace_nullifier_single_use`：消費済み nullifier の永続と、再提出が必ず失敗すること。
- `trace_paid_bounded`：`paid ≤ received` の保存と、保存則の paid / unspent 分解。

前提に依存するのは close / claim の受理から回路 gate 充足への飛躍だけです
（`close_acceptance_binds_statement`、`claim_acceptance_binds_statement`）。
**残る隙間は `close_vector_backing_is_exactly_premise_c` が明示します。**
Rollup escrow は pooled であるため、cap とチャネル自身の預入額を結ぶ部分は依然として前提 (c) です。

**回路と Solidity の一致（4 本）。** 手書きモデル同士の照合ではなく、回路側の語列・byte 列が
Solidity 実装モデルの計算と一致することを導出しました。

| 定理 | 内容 |
|---|---|
| `DepositChain.chain_matches_rollup_fold` | deposit chain の fold が `pendingDepositChain` と一致。preimage の byte 一致は hash 前提なしで kernel 検証 |
| `ChannelRegChain.chain_matches_rollup_fold` | 登録 chain の 244 語 preimage が `hashPreimage (.channelRegistration …)` と byte 一致 |
| `ValidityChain.circuit_pi_layout_matches_solidity_preimage` | 41 語 164 byte の公開入力が `finalize` の hash preimage と一致 |
| `WithdrawalChain.circuit_layout_matches_rollup_verifier` | 17 語が `verifyWithdrawalSet` の再計算と一致。limb マスクが `% 2^253` と等価であることも導出 |

**実 fixture による refinement 証拠。** [fixture-parity](./fixture-parity.md) と
`.github/ci/lean-fixture-parity.py` は、Lean codec を実際の prover fixture で実行し、
Rust / Solidity 側の値と field 単位で照合します。18 fixture・177 項目が一致し、不一致は 0 です。
17 語の withdrawal 公開入力は Lean decoder、Solidity helper の Lean モデル、prover の登録語、
Python による keccak 再計算の 4 経路で一致します。**これは refinement の証明ではなく、
手書きモデルと実出力の一致という証拠**です。

**replay ledger のモデル化。** [SignatureReleaseLedger](./Zkp/Implementation/SignatureReleaseLedger.lean)
は wallet 側 `hosting/wallet/signature-release-ledger.mjs` を対象に、同一 (署名者, channel, 前 digest)
に対して異なる successor の署名が公開されないこと、再試行が保存済み bytes を再生することを
証明します。別デバイス・別ストア、storage 消去、IndexedDB の durability は前提のままです。

### source 側で判明した観察（人間の判断が必要な項目）

いずれも定理として固定してあり、脆弱性の実証ではありません。

1. **チャネル木はブロックを通じた資金保存を強制しません。** `ChannelLeaf` に fund vector がなく、
   公開されるチャネル木 root は IMCH preimage を丸ごと差し替えても不変です
   （`UpdateChannelTree.native_account_root_ignores_channel_state_fields`）。
2. **`update_channel_tree.rs` では署名が一切検証されません。** N-of-N Falcon aggregate も BP 署名も
   検証されず、`bp_sig_chain` への fold のみです。存在証明は別回路の再帰 proof の責務です。
3. **チャネル間送金の対応付けはブロック側で行われません。** 開かれるチャネル木 index は
   `block.channel_id` の 1 つだけで、`destination_channel_id` はどこからも読まれません。
4. **block step の最初の step では初期公開状態と cyclic verifier 鍵が自由な witness** であり、
   timestamp も無制約です（`BlockStep.gates_first_step_verifier_key_is_free` ほか）。
5. **`ChannelRegRecord::validate` の canonicality 検査は到達不能**です。`try_from` が同じ 32/32 分割を
   組み直すため決して失敗しませんでした（`ChannelRegChain.byte_round_trip_alone_cannot_reject`)。2026-09-09 に修正済み。
   非 canonical な identity は witness 構築時ではなく proving 時に失敗します。
6. **回路側で member recipient が制約されません。** `member_pubkeys_root` を変えずに任意の recipient を
   割り当てる充足 witness が存在し、束縛は L1 の chain 一致のみです。
7. **`src/circuits/mod.rs` の `test_utils` は cfg(test) なしの公開 module** で、harness の決定的
   Falcon 鍵導出が production から到達可能です（`CrateLayout.test_utils_not_test_only`、
   `WitnessGenerators.harness_key_material_is_production_reachable`）。鍵は公開 channel id の
   純関数で、slot 符号化は 256 で衝突します（`assert!(slot < 255)` が効いています）。
8. **transfer witness の native 検査に index の範囲検査がなく**、index と index+64 が区別されません。
   6 bit 境界は回路側にのみ存在します。**transfer の token index は回路でも範囲検査されません。**
9. **user-id recipient は Poseidon 出力の上位 byte を tag が上書きするため 248 bit しかコミットしません。**
10. **native と回路で block number 比較が異なります。** send_tx / tx_settlement の native は
    `tx_block_number >= block_r` を許可し、回路は strict `>` を課します（prover 側の不一致）。
11. **`U63Target::enforce_ge` は定義域の上端で順序検査になりません**（下側 0 と上側 `2^63-1` を受理）。
    順序が成り立つのは下側被演算子が `2^63 - 2^32 + 1` 以下のときです。
12. **`withdrawal_prover` は 17 語の公開入力に含まれず**、keccak preimage 経由でのみ束縛されます。
    また契約は空の withdrawal 集合を拒否しますが、回路は拒否しません。


### `e604a36` 以降：Balance / 状態更新 / 復号 gadget の checkpoint

- **89 モジュール**を build、現行 **36 モジュール・1,273 named theorems** の実在・種別・
  推移的 kernel axioms を検査して main guard 成功。前回から **278 定理**追加。
  実装対応は **31 モジュール・1,054 定理**、前段の仕様側は 5 モジュール・219 定理。
- **156 reviewed-source hashes、1 MLE gitlink、29 source maps** を検証。
  全対応表の宣言参照を Lean compiler で確認して line guard 成功。
- guard 回帰テスト **51 件**（main 29 + line 22）。ランタイム基準 `05ec7ae` に対する
  `src`、`contracts`、`Cargo.toml`、`Cargo.lock` の差分はゼロ。MLE サブモジュールは clean。
  ベンチマークは実施しておらず、runtime / proof parameter / proof format を変更していません。
- 物理行分類：手書き翻訳 **9,632**、依存境界 **2,438**、非実行 **5,476**、
  テスト専用 **6,738**、未翻訳 **92,913**。`state_update_verifier.rs` の `cfg(test)` 1,587 行と
  `decryption_gadget.rs` の 221 行、`switch_board.rs` の 223 行をテスト専用へ移した分を含むため、
  未翻訳の減少量を「安全性証明済み実行行数」には換算できません。

今回追加した 8 モジュールは、Balance 側の public input / switch board / 外側回路、
private / public state 更新、channel state-update verifier、復号 gadget の手書き意味モデルです。
各モジュールは独立レビューを受け、以下を修正しました。これはモデル精度の修正であり、
実装に新たな脆弱性を発見したという報告ではありません。

- `ChannelStateUpdate` の 7 つの output 定理は `apply` による bind の剥離に依存していましたが、
  最後の `apply` 失敗時に unifier が `List.range slotCount`（1024 要素）を展開して
  無限に近い再帰（19 GB 超のメモリ）に陥っていました。受理仮説を `bind_ok_iff` で
  連言へ書き換える証明へ置き換え、do-notation の join point（burn / non-burn、receiver の
  有無）を `split` で扱うようにしました。前回 handoff の「standalone compilation 成功」は
  再現できず、`first_index_found` などの 3 証明も修正が必要でした。全体の compile は 4 秒です。
- `ChannelStateUpdate.channelTxDigest` は原実装の `ChannelTx::signing_digest` と同じ
  7 入力だけを受けるよう狭めました（署名 field を読めない callee）。未使用の
  `validateRecord` は削除し、`validate_member_signature_slots` 内の `record.validate()` に
  委ねます。send / fund import の受理から transport envelope の proof bytes が空に強制される
  事実を定理にしました（source 観察であり、健全性の主張ではありません）。
- `DecryptionGadget` に `CoreGates` / `Representatives` / `FieldProducts` から各 row の
  integer 方程式（reduction、key binding、decryption、digit 分解）を導く合成定理
  `core_row_integer` を追加しました。digit-255 境界は gate として非充足であることを示し、
  `native_key_halves` の `omega` 失敗は符号で場合分けして解消しました。
  全ゼロ割当の充足例は production trace ではないことを名前で明示しました。
- `PrivateState` の native / target 順序一致は同一定義の `rfl` でしたが、
  `to_u64_vec` と `to_vec` を別々に転記して比較するよう改めました。`AssetTree::init` と
  `AssetTree::new(height)` の同一性は前提として明記しています。
- `UpdatePrivateState` は nullifier gadget の呼出し関係を「挿入」と誤読されない名前へ変え、
  native 成功経路から local gate family を満たす witness を構成する vacuity guard を
  追加しました。native/target U256 の一致は明示前提のままです。
- `SwitchBoard` は HashMap の重複（serde が last-wins で潰す）・順序と、prove-time の
  cap count が constructor config と同一であることを証明していない旨を明記しました。

`--require-complete` は引き続き失敗するべき状態です。復号 oracle の意味、秘密鍵の一意性、
署名の暗号学的妥当性、replay ledger、L1 finality、Rust / gate / EVM refinement、
全 entrypoint を含む資産所有権は未証明です。

### 前回 `9a67d8e` 以降：取消・請求・共通 H1・Solidity 接続の checkpoint（履歴）

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

0. **core 71 file と依存側の主要部の対応表が完了しました。** 未翻訳は 41,783 行で、
   その大半は MLE サブモジュール（34,000 行弱）で、これは信頼仮定として受容済みです（前提 (a0)）。残る主作業はそこと、
   `channel_registration` の到達不能な canonicality 検査の修正、`balance_state` の古いテスト 2 件の
   更新、そして CI に `cargo test --lib` を追加することです。
1. （履歴）残る依存側の翻訳。Poseidon / keccak / Merkle / Falcon / Regev の実装が現在の opaque callback を
   置き換えるまで、hash binding と署名妥当性は前提のままです。
1. （履歴）残る validity / deposit / transfer / withdrawal 回路と、Balance の send / receive 各回路の
   手書き翻訳を追加する。`state_update_verifier.rs` と `decryption_gadget.rs` の本体、
   Balance の PI / switch board / 外側回路、private / public state 更新は追加済みだが、
   Manager / Rollup の ABI・callback・generated getter と全到達可能状態の証明、
   feature-gated fixture 生成は未翻訳・未証明として残す。
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
