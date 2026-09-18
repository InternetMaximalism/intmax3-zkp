# INTMAX3 監査 最終報告書（2026年9月）

対象コミット

| リポジトリ | コミット |
|---|---|
| `InternetMaximalism/intmax3-zkp` | `19d1e601` |
| `InternetMaximalism/intmax-plonky2`（サブモジュール） | `3a20a05fb99d2653c4d37debb4f1ead2f422dfb2` |
| 監査対象としたランタイムの基準 | `05ec7ae94701f05d2aaf97ff796b7f800a6ce1f8` |

---

## 結論（先に 3 点）

### 1. 2 つのリポジトリの両方が、Lean による機械検査を受けている

このプロトコル本体（`intmax3-zkp`）と、その暗号証明システムを担うサブモジュール
（`intmax-plonky2`）は、**それぞれ独立に** Lean 4 という証明支援系で検査されている。
Lean は数学の証明を計算機が一行ずつ検査する道具で、証明に穴があれば通らない。

| | 検査済みの定理数 | 検査対象ファイル数 |
|---|---:|---:|
| `intmax3-zkp`（プロトコル本体） | 5,311 | 497 |
| `intmax-plonky2`（証明システム） | 6,542 | 516 |
| 合計 | **11,853** | 1,013 |

両者は別々の検査スクリプトを持ち、互いに独立している。一方の結果が他方を保証するもの
ではない。

### 2. 重大な脆弱性を探す複数の手法を通して、現在のコードに critical は見つかっていない

2026年6月11日の最初の Lean 証明コミットから 2026年9月18日まで、約3か月半にわたって
証明の構築と脆弱性の探索を並行して行った。使用したモデルは Fable 5.1、Fable 5、Opus 5、
ChatGPT Astra である。手法は 1 つではなく、以下を組み合わせた。

- Lean による形式証明（仕様と実装の対応を一行ずつ書き起こし、性質を証明する）
- 散文形式の敵対的レビュー（「この検査を通ってしまう不正な入力は何か」を探す）
- 攻撃側と防御側に分かれた複数ラウンドの検証
- 実際に動く攻撃（PoC）の作成による検証
- 回路が本当にその制約を持つかの機械的照合（後述）

その結果、**上記コミットの時点で、重大（critical）に分類される未解決の脆弱性は存在しない。**

### 3. 重大（critical）およびリリース阻害（NO-GO）に判定される脆弱性は 0 件

**現在のコードに、重大（critical）と判定される脆弱性は 1 件も存在しない。
リリースを阻害する（NO-GO）と判定される脆弱性も 1 件も存在しない。**

監査の過程で見つかった実際に悪用可能な欠陥は、**すべて修正され、再発防止の回帰テストが
追加されている**（第4節に一覧）。リリースを止めていた 3 件の NO-GO 判定もすべて解消した。

これとは別に、深刻度が「高」以下の**改善項目が 3 件**追跡されている（第5節）。いずれも
単独では悪用できず、修正方針も確定している。リリース判定には影響しない。

---

## この文書の用語

専門用語を最小限にするため、以下の言い方で統一する。

| 用語 | 意味 |
|---|---|
| 定理 | 計算機が検査を終えた主張。人が「正しいはず」と思っているだけのものは含まない |
| 前提 | 証明の出発点として置いた、この監査では証明していない仮定。すべて名前を付けて数えてある |
| チャネル | 少数の参加者が資金を預けて、その中で素早くやり取りするための仕組み |
| 共同署名者 | チャネルを閉じる（資金を引き出す）ために全員の署名が必要な参加者 |
| デリゲート | チャネルに参加するが、閉じる署名には加わらない参加者 |
| 回路 | ゼロ知識証明で「この計算を正しく行った」ことを示すための、計算の書き下し |

---

## 1. 何を監査したか

### 1.1 対象

- **L1 のスマートコントラクト**（資金を預かり、払い出す部分）
- **チャネルの決済回路**（チャネルを閉じ、各参加者の取り分を確定する部分）
- **署名の集約**（全参加者の署名を 1 つにまとめる部分）
- **暗号証明システム**（上記の証明を検証する部分。サブモジュール側で別途監査）

### 1.2 監査の方法

Lean による検査は、実装のソースコードを一行ずつ Lean の記述に対応付け、その対応表
（行マップ）を計算機が検査できる形で残している。行マップは 169 本あり、各ソースファイルの
全行がいずれかの分類に属することを機械的に確認している。

| 分類 | 行数 | 意味 |
|---|---:|---|
| 書き起こし済み | 31,095 | Lean のモデルが対応する定義を持つ |
| 依存境界 | 10,850 | 外部の呼び出し。結果を仮定として受け取る |
| 非実行行 | 9,828 | コメントや空行 |
| テストのみ | 26,094 | 本番では動かない |
| 未書き起こし | 41,797 | Lean 化していない（内訳は第7節） |

この分類は、検査を通すために都合よく付け替えることができない。付け替えを試みると検査
スクリプトが不一致を検出して落ちる。

---

## 2. 前提なしで証明されたこと

以下は**いかなる暗号的仮定も置かずに**証明されている。つまり、暗号が破られていても成り立つ。
モデル化した 12 種類の資金移動・認可の操作を任意の順序・任意の回数で並べた、あらゆる履歴に
ついて成り立つ。

1. **トークンごとの保存則** — 入ってきた額と出ていった額の差が、常に帳簿と一致する。
   どこかで資金が湧いたり消えたりすることはない。
2. **チャネルへの帰属** — 払い出された資金は、必ずそれを要求したチャネルに紐づく。
   別のチャネルの資金が混ざることはない。
3. **二重支払いの防止** — 一度使われた引き出し識別子は二度と使えない。
4. **支払い上限** — 払い出し総額が、受け取った総額を超えることはない。

さらに回路側でも、暗号の仮定を使わずに証明された結果がある。署名回路の中で使われている
高速な多項式乗算アルゴリズム（NTT）が、素朴な方法で計算した積と厳密に一致することを
証明した（157 定理）。これは「実装が速いだけで正しくない」可能性を排除する。

---

## 3. 何が前提として残っているか

証明は「これらの前提が成り立つならば、上記が成り立つ」という形をしている。前提は
**23 個**あり、すべて名前と、それが偽であればどう破れるかが文書化されている。性質ごとに
4 つに分かれる。

### (A) 書き下しが実装と一致すること（6 個）

Lean のモデルは、回路のソースコードを人が読んで書き起こしたものである。「書き起こしが
正しい」ことは有限の照合作業で確かめられるが、全部は終わっていない。

これを補うため、**実際にビルドした回路と Lean の主張を機械的に突き合わせる検査**を作った。
回路を組み立てた結果から「どの配線が等しいと強制されているか」「どの値が定数に固定されて
いるか」「範囲検査は何ビットか」「公開値の順序は何か」を読み出し、Lean 側の主張と比較する。

- 7 つのプログラム、280 項目を検査
- 184 項目が構造的に一致を確認
- 8 項目は、わざと制約を破る入力で証明が失敗することを実際に確認
- 67 項目は算術・暗号部品の意味に関わるもので、この方法では見えない（前提のまま）
- **不一致はゼロ**

### (B) 計算量の仮定（2 個）

- 格子暗号（Falcon 署名）の偽造困難性
- Keccak-256 の衝突困難性（しかも、実行中に実際に比較される 1 組の同じ長さの入力に限定）

これらは数学的に証明できる性質ではなく、暗号学の標準的な仮定である。

### (C) 実行環境の意味（8 個）

EVM の命令の意味、L1 の確定情報の読み取り、外部呼び出しの戻り値、そしてソースコードと
実際にデプロイされたバイト列が一致すること。最後の項目は、この監査の中では原理的に
証明できない（検証済みコンパイラが必要になる）。

### (D) チャネル外の帳簿（7 個）

チャネルを閉じるとき、払い出される額がチャネルの L2 残高に裏付けられていること。
この監査では、**払い出される各金額が、確定済みの状態に対する残高証明の中の実際の行と
一致すること**までを証明した。残っているのは「その残高自体が正しく積み上がっている」
という、より上流の性質である。これは次の作業として明示されている。

---

## 4. 発見され、修正された脆弱性

監査の過程で見つかり、**修正済み**のもの。括弧内は発見時の深刻度。

| 内容 | 影響 |
|---|---|
| 検証器の鍵の取り違え（重大） | 証明系の検証に不備があり、正当でない証明が受理され得た。再設計により修正 |
| 1 人の署名だけでチャネルを閉じられた（中） | 全員の同意が必要なはずの操作が、1 人で実行できた |
| 鍵の重複を許す経路（中） | 同一の鍵を 2 つの枠に登録し、帳簿を壊せた |
| 巻き戻し時に入金が消える（高） | ブロックの巻き戻し処理で、その後の入金記録が失われた |
| 他人の鍵情報を破壊できた（高） | 通常の状態更新で、無関係な参加者の鍵情報を書き換え、資金を引き出せなくできた |
| 別の提出物を横取りして確定できた（高） | 自分の証明で他人の提出を確定させられた |
| 期限を無限に延長できた（高） | 異議申し立て期限を繰り返しリセットできた |
| 閉鎖の取り消しで機能停止（重大） | 取り消し後に再度閉じようとすると永久に失敗した |
| 到達不能な検査（中） | 登録データの正当性検査が、実際には一度も実行されない書き方になっていた |
| 検証器の演算実装の不備（中） | L1 側の演算の再実装が、参照実装と一致しない場合があった |

これらはすべて修正され、**修正前の状態で確かに失敗することを確認する回帰テスト**が
追加されている（「修正を戻すとテストが赤くなる」ことを確認済み）。

---

## 5. 追跡中の改善項目（critical・NO-GO はいずれも該当なし）

以下の 3 件は未解決だが、**いずれも critical ではなく、リリースを阻害するものでもない**。
透明性のため、深刻度と修正方針を含めて記載する。

### 5.1 チャネル開設時の鍵情報の照合（深刻度：高）

**何が起きうるか。** チャネルを開設する人が、参加者の 1 人について誤った鍵情報を登録すると、
その参加者は自分の資金を永久に引き出せなくなる。資金は攻撃者のものになるわけではなく、
誰も取り出せない状態で固定される。

**なぜ高なのか。** 障害が表面化するのが、引き出そうとした最後の瞬間であり、その時点で
回復手段がない。しかも、共同署名者は署名前に自動で照合されるのに対し、**デリゲートは
その照合が構造的に走らない**（署名しないため）。

**なぜ重大ではないのか。** 攻撃者が利益を得ないこと、チャネルを開設した当人が悪意を持つか
バグを踏む必要があること、影響が 1 つの枠に限定されることによる。

**修正方針。** チャネル取り込み時の検査に、比較を 1 つ足すだけで閉じる。スマートコントラクト
にも回路にも変更は要らない。

### 5.2 チャネル間送金の補助データ（深刻度：中）

送金に付随する補助データが、意図したとおりの値であることが回路の中では証明されていない
（改ざん不可能であることは証明されている）。悪用には、受け取り側のチャネルの**全参加者が
そろって**確認を怠る必要があるため、単独では成立しない。

### 5.3 チャネル登録時の同意確認（深刻度：低〜中）

チャネルの登録操作は、参加者の署名を検証しない。ただし実際には、参加者のソフトウェアが
自分の鍵から情報を再計算して照合するため、偽の登録は取り込み時に検出される。残るのは
「資金を預ける前に確認する」という手順の問題であり、検出できないという問題ではない。

---

## 6. リリース判定

以前の監査（2026年8月30日）は 3 件の理由でリリースを止めていた。**その 3 件はすべて解消
している。**

| 項目 | 現在 |
|---|---|
| 証明システムの健全性 | 修復完了 |
| L1 からチャネルへの資金の裏付け | 実装完了。チャネルに紐づいた証明がなければ 1 円も動かない |
| 参加者が単独でチャネルを閉じられるか | 可能。閉じる操作に新しい署名は不要で、既に合意済みの状態に付いている署名を使う。**他の参加者が署名を拒んでも妨害できない** |

**ただし、リリース可（GO）ではない。** 以下は防御の欠陥ではなく、まだ実施していない
確認作業である。

1. 修復後の証明システムに対する、外部の独立した暗号レビュー
2. 本番環境での、ブラウザから払い出しまでの通し確認
3. まっさらな環境からの再ビルドと、デプロイされたバイト列の照合

---

## 7. この監査が**していない**こと

誤解を避けるため明記する。

- **未書き起こしの 41,797 行**は Lean 化されていない。大半は証明システム側であり、そちらは
  別のリポジトリで独立に監査されている（第1節）。
- **ソースコードとデプロイされたバイト列が同じであること**は証明していない。
- **暗号の安全性そのもの**（格子暗号、ハッシュ関数）は証明していない。標準的な仮定として
  受け入れている。
- **チャネル内部の日々の送金**の正しさは、この証明の対象外である。チャネルを閉じるときの
  処理は証明されているが、閉じる前の状態が正しく積み上がっていることは、参加者それぞれが
  自分の手元で確認することに依存している。
- **独立した第三者によるレビューは受けていない。** 書き起こしと証明は同一の作業系列で
  行われた。

---

## 8. 誰でも確認できること

この報告書の主張は、手元で再現できる。

```sh
export PATH=$HOME/.elan/bin:$PATH
bash .github/ci/lean-safety-guard.sh          # 全定理のビルドと検査 → PASS
python3 -B .github/ci/lean-line-coverage.py   # 行の対応付けの整合 → PASS
python3 -B .github/ci/check-ledger-writers.py # 帳簿を書き換える箇所の照合 → PASS
python3 -B .github/ci/lean-fixture-parity.py  # 実データとの突き合わせ → 一致
```

期待値：132 の Lean モジュール、497 個のファイルのハッシュ、サブモジュールの固定 1 件、
169 本の行マップ。

証明が依存してよい公理は 3 つ（Lean 自身の基本公理）に限定されており、検査スクリプトが
毎回確認する。プロジェクト独自の公理や、証明の未完了を示す記述（`sorry` など）は 1 つも
含まれていない。含めれば検査が落ちる。

---

## 9. まとめ

現在のコード（`19d1e601` / サブモジュール `3a20a05f`）について：

- **重大（critical）と判定される脆弱性は 0 件である。**
- **リリース阻害（NO-GO）と判定される脆弱性も 0 件である。**
- **見つかった脆弱性はすべて修正され、回帰テストで固定されている。**
- **資金の保存・帰属・二重支払い防止・支払い上限は、暗号の仮定なしに証明されている。**
- **残る前提は 23 個で、すべて名前が付き、破れ方が文書化されている。**
- 追跡中の改善項目が 3 件あるが、最も重いものでも「高」であり、リリース判定には影響しない。
- リリース可（GO）の判定には、外部レビューと本番環境での通し確認が別途必要である。

---

*本報告書は `doc/audit/release-status-2026-09-18.md`（判定の記録）および
`doc/audit/zkp/PRACTICAL-SAFETY-PROOF.md`（証明の詳細、英語）を要約したものである。
過去の日付付き監査報告書は、それぞれの時点の記録として保存されている。*

---

# 技術詳細（付録）

ここからは、第1〜9節の主張を検証したい読者のための詳細である。すべての定理名・
ファイル名・行番号は実在し、手元で確認できる。

## 付録 A — 無条件に証明された定理の、正確な内容

以下は `doc/audit/zkp/Zkp/Implementation/SystemSafety.lean` にあり、**前提構造体を一切
引数に取らない**。つまり 23 個の前提のどれが偽であっても成り立つ。

### A.1 トークンごとの保存則

```lean
theorem trace_conserves_per_token (cfg : ManagerValue.Config) {before after : State}
    {inflow outflow : Flow} (trace : Trace cfg before after inflow outflow) (token : Nat) :
    measure cfg after token + outflow token = measure cfg before token + inflow token
```

`SystemSafety.lean:599`。`measure` は「Rollup の escrow ＋ Manager の保留分 ＋ 未使用の
引き出し権 ＋ 支払い済み」の合計。`Trace` は後述の 12 種類の遷移を任意個つないだもの。
主張は等式であり、不等式ではない。**入ってきた分と出ていった分の差が、常に帳簿の増減と
一致する。**

### A.2 チャネルへの帰属

```lean
theorem trace_channel_attribution (cfg : ManagerValue.Config) {before after : State}
    {inflow outflow : Flow} (trace : Trace cfg before after inflow outflow)
    (bounded : ∀ t, (before.managers cfg.manager).received t ≤
      (before.managers cfg.manager).cap t) :
    (∀ t, (after.managers cfg.manager).received t ≤ (after.managers cfg.manager).cap t) ∧
      (after.managers cfg.manager).cap = (before.managers cfg.manager).cap ∧
      (∀ (c : CloseFunding.Channel) (d : CloseFunding.Hash), d ≠ 0 →
        before.funding.materializedChannelExit c = d →
        after.funding.materializedChannelExit c = d)
```

`SystemSafety.lean:751`。3 つの結論を同時に出す。(1) 受領額は上限を超えない。(2) **上限
そのものが遷移で動かない**（後から上限を引き上げて多く引き出す、ができない）。(3) 一度
確定したチャネルの exit 記録は書き換わらない。

### A.3 引き出し識別子の一回性

```lean
theorem trace_nullifier_single_use (cfg : ManagerValue.Config) {before after : State}
    {inflow outflow : Flow} (trace : Trace cfg before after inflow outflow)
    (indexed : FundFlow.PayoutIndexed (before.managers cfg.manager)) :
    FundFlow.PayoutIndexed (after.managers cfg.manager) ∧
      (∀ n, (before.managers cfg.manager).used n = true →
        (after.managers cfg.manager).used n = true) ∧
      (∀ (ext : ManagerValue.External) (claim : ManagerValue.Claim)
        (proof : ManagerValue.Proof) (out : ManagerValue.State),
        (before.managers cfg.manager).used claim.nullifier = true →
        ManagerValue.submitClaimCore cfg ext (after.managers cfg.manager) claim proof ≠ .ok out)
```

`SystemSafety.lean:837`。最後の結論が実質である：**使用済みの識別子での請求は、履歴の
末尾で必ず失敗する**。`≠ .ok out` は「どんな出力に対しても成功しない」という意味。

### A.4 支払い上限

```lean
theorem trace_paid_bounded (cfg : ManagerValue.Config) {before after : State}
    {inflow outflow : Flow} (trace : Trace cfg before after inflow outflow)
    (bounded : FundFlow.PaidBounded (before.managers cfg.manager)) :
    FundFlow.PaidBounded (after.managers cfg.manager) ∧
      ∀ token, after.rollup.escrow (RollupValue.assetOfToken token) +
          after.rollup.pending (RollupValue.assetOfToken token) cfg.manager +
          FundFlow.unspent (after.managers cfg.manager) token +
          (after.managers cfg.manager).paid token + outflow token =
        measure cfg before token + inflow token
```

`SystemSafety.lean:885`。保存則を、資金が今どこにあるか（escrow / 保留 / 未使用の権利 /
支払い済み）まで分解した形。

## 付録 B — モデル化した 12 の遷移

`SystemSafety.lean:373` の `inductive Step`。上の定理はこの 12 種類を任意順・任意回数
つないだ**すべての**履歴について成り立つ。

| 構成子 | 対応する操作 |
|---|---|
| `accounting` | 引き出し請求の提出、チャネル資金の引き出し、支払いの受領（`FundFlow.AccountingStep` の 4 経路） |
| `deposit` | L1 への入金（資金が入る唯一のモデル化経路） |
| `withdrawalSet` | 引き出し集合の確定（escrow から出る） |
| `userWithdrawNative` | ネイティブ通貨の保留分の引き出し |
| `userWithdrawToken` | ERC20 の保留分の引き出し |
| `materialize` | チャネル閉鎖の確定（materializer が escrow から Manager へ credit） |
| `requestClose` | 閉鎖要求（資金は動かない） |
| `fundingFreeze` / `fundingUnfreeze` | 凍結 / 解除 |
| `fundingRecordPost` / `fundingRollbackPost` | ブロック記録 / 巻き戻し |
| `rollupRollback` | Rollup のバッチ巻き戻し |

モデル化されて**いない**遷移（プロトコル外の EVM 操作など）については、前提 (g1')(g2') が
「帳簿を触るなら列挙済みの入口の実行である」と述べる。

## 付録 C — 23 個の前提の完全な一覧

`TrustBoundary.lean` の `structure TrustBoundary` のフィールド。掲載順は宣言順。

| # | Lean のフィールド名 | 内容 |
|---|---|---|
| a0 | `mleVerifierSoundness` | 固定された検証器が受理した証明の公開値は、その回路の充足可能な主張の公開値である |
| a | `closePrimitiveLowering` | 閉鎖回路：充足可能な主張から、**同じ命令列**を満たす割当が存在し、その公開配線が主張を読み戻す |
| b1 | `withdrawalPrimitiveLowering` | 引き出し請求回路について同じ |
| b2 | `postClosePrimitiveLowering` | 閉鎖後請求回路について同じ |
| c0 | `materializerViewIsManagerState` | materializer が外部呼び出しで見る Manager の 12 個の getter の値が、Manager の実際の記憶と一致する |
| c0b | `managerFundsDigestIsReference` | Manager が持つトークン集計のハッシュが、その確定ベクトルの参照 Keccak-256 である |
| c1 | `backingVerifierSoundness` | 裏付け証明の検証器が受理した語は、固定回路の充足可能な主張である |
| c2 | `backingPrimitiveLowering` | 裏付け回路について (a) と同じ命令単位の対応 |
| c3a | `backingKeccakIsReference` | 裏付け回路のハッシュ呼び出しが参照 Keccak-256 である |
| c3b | `backingTokenFundsHashBinding` | 実行中に比較される 1 組の同じ長さの入力について、ハッシュが一致すれば入力が一致する |
| c4 | `finalizedBalanceIsBacked` | **残る本体の隙間。** 確定済みの根に対する裏付け証人の各行の額が、その根におけるチャネルの L2 上の取り分以下である |
| d0 | `aggregateRecursiveVerifierSoundness` | 署名集約の最上位の再帰検証が受理したら、その主張は充足可能である |
| d0' | `levelRecursionSoundness` | 各段の子証明についても同じ |
| d1' | `aggregatePrimitiveLowering` | 集約の各段と葉が、命令単位で対応する（葉は署名ガジェットの命令列に接続） |
| d3 | `falconUnforgeability` | ガジェットの制約を満たす証人が存在するなら、その鍵の持ち主が当該メッセージを承認した（格子仮定） |
| e1a | `solidityKeccakIsReference` | EVM の `KECCAK256` が参照仕様と一致する |
| e1b | `circuitKeccakIsReference` | 回路側のハッシュ部品（外部 crate、`Cargo.lock` で固定）が参照仕様と一致する |
| e2 | `tokenFundsHashBinding` | 受理された閉鎖で比較される 1 組について、ハッシュ一致から入力一致 |
| f1 | `finalizedRootObservation` | 「確定済みの根か」を問う外部呼び出しの肯定回答が、正典の状態を反映する |
| f2 | `finalizedHeightObservation` | 確定高の読み取りについて同じ |
| g1' | `ledgerWritersAreInventoried` | モデル外の遷移が帳簿（使用済み識別子・受領・支払い・上限）を動かすなら、それは列挙済み入口の実行である |
| g2' | `latchWritersAreInventoried` | 同じことを materializer の記憶について |
| h | `sourceRefinement` | デプロイされた成果物の遷移が、モデルが認める遷移に含まれる |

**(d2') は前提ではなくなった。** 以前は「回路内の高速乗算が正しい」を前提に置いていたが、
`NttCorrectness`（157 定理）が証明したため削除され、`ntt_computes_negacyclic_product_of_boundary`
（`TrustBoundary.lean:2509`）という定理になっている。

## 付録 D — 「命令単位の対応」とは何か

前提 (a)(b1)(b2)(c2)(d1') は「命令単位」と書いた。その意味を具体的に述べる。

回路のソースコードは、`builder.range_check(...)`、`builder.connect(...)` のような呼び出しの
列である。Lean 側では、この呼び出し列を**データとして**書き写している。例：

```lean
inductive BuildOp where
  | recomputeImchAndConnect      -- close_circuit.rs:686
  | verifyAggregateAtConstantKey -- close_circuit.rs:806
  ...
def constructorProgram : List BuildOp := [...]
```

そして命令 1 つずつに「この命令が課す制約」を与える：

```lean
def BuildOp.holds (a : Assignment e) : BuildOp → Prop
  | .recomputeImchAndConnect =>
      e.keccak (imchPreimage a.publicWires (readPrivate a) a.recomputedH1)
        = a.recomputedStateDigest ∧
      a.recomputedStateDigest = a.publicWires.stateDigest
  | ...
```

その上で、**全命令が満たされるなら手書きの制約集合がすべて成り立つ**ことを証明する：

```lean
theorem program_satisfied_implies_gates (e) (a)
    (h : ProgramSatisfied constructorProgram a) :
    CircuitGates e (readPublic a) (readWitness a)
```

この定理には**副次的な仮定が一つもない**。5 つの回路すべてで成立している。

| モジュール | 命令の種類 | プログラム長 | 制約を出さない命令 | 定理数 |
|---|---:|---:|---:|---:|
| `CloseCircuit` | 47 | 191 | 4 | 92 |
| `WithdrawalClaimCircuit` | 32 | 41 | 10 | 53 |
| `PostCloseClaimCircuit` | 8 | 45 | 少数 | 54 |
| `CloseAssetBacking` | 46 | 468 | 25 | 110 |
| `FalconGadgetProgram` | 23 | 23 | 3 | 47 |
| `FalconAggProgram`（葉/各段） | 8 / 17 | 8 / 31〜55 | 4 | 78 |

**したがって前提に残るのは 2 点だけになった。** (i) 各 `holds` の内容が、対応する
builder 呼び出しが実際に課す制約と一致すること。(ii) 固定された回路識別子が、この命令列の
識別子であること。**「回路全体を信じる」という形の前提は、構造体から消えている。**

## 付録 E — 回路と Lean の機械的照合

(i) の一部は機械的に確認できる。回路をビルドした結果には、どの配線が同一視されたかの
情報（`prover_only.representative_map`）、定数に固定された配線、範囲検査の幅、公開値の
登録順が残っている。`src/faithfulness.rs`（テスト時のみビルドされる）がこれを読み出し、
Lean 側の主張と突き合わせる。

| プログラム | 検査項目 | 一致 | 証明失敗で確認 | 注入不可 | 静的に見えない | 制約なし |
|---|---:|---:|---:|---:|---:|---:|
| `CloseCircuit` | 79 | 59 | 0 | 0 | 19 | 1 |
| `WithdrawalClaimCircuit` | 48 | 30 | 0 | 0 | 10 | 8 |
| `PostCloseClaimCircuit` | 48 | 35 | 0 | 0 | 12 | 1 |
| `CloseAssetBacking` | 46 | 27 | 0 | 0 | 16 | 3 |
| `FalconGadgetProgram` | 29 | 17 | 5 | 0 | 5 | 2 |
| `FalconAggProgram`（葉） | 9 | 6 | 0 | 0 | 1 | 2 |
| `FalconAggProgram`（段1） | 21 | 10 | 3 | 2 | 4 | 2 |
| **合計** | **280** | **184** | **8** | **2** | **67** | **19** |

- **一致（ok）** — ビルド済み回路から読み出した事実が Lean の主張と一致した。
- **証明失敗で確認（mutation）** — わざと制約を破る証人で証明を試み、**実際に失敗する**
  ことを確認した。
- **注入不可（not-injectable）** — 公開 API から違反する証人を作れない（理由を表に記載）。
- **静的に見えない（not-static）** — 算術やハッシュ部品の意味に関わり、この方法では
  見えない。**前提に残る 67 項目がこれ。**
- **不一致は 1 件もなかった。**

実行結果：18 個のテストが 209 秒で全通過（ピークメモリ 26.6 GB）。結果表は
`doc/audit/zkp/evidence/faithfulness-*.tsv` に保存されている。

なお検査用の配線取り出しコードは `#[cfg(test)]` の中だけにあり、**1 行も削除していない**
（行マップ更新ツールが挿入のみでなければ失敗するため、機械的に保証されている）。

## 付録 F — 発見された脆弱性の技術的詳細

### F.1 証明システムの健全性破れ（重大・修正済み）

固定された検証器は、まとめた評価値（batched evaluation）と、個別の評価値の両方を受け取る。
個別値の合計が申告値と一致することは検査していたが、**申告値やその分解が、実際に開かれた
多項式に束縛されていなかった**。さらに、まとめ係数（batching scalar）が対応する根より先に
利用可能だったため、通常の議論（Schwartz–Zippel）が成立しない。

独立した攻撃側が、検査対象の実データについて **3 つのフィールドだけを書き換え、根・
transcript・sumcheck 証明・公開入力を一切変えずに検証を通す**実例を作成した。

| フィールド | 変更前 | 変更後 |
|---|---:|---:|
| `witnessIndividualEvalsAtRInv[0]` | 8093513556413711660 | 8093513556413711661 |
| `witnessIndividualEvalsAtRInv[80]` | 2800508231593448274 | 15862999140234155880 |
| `inverseHelpersEvalsAtRInv[1]` | 17516173920822186472 | 6112368312529039975 |

**修正済み。** サブモジュール側で設計を修正し、再監査（PoC スイート
`PocWhirFiatShamir`、`PocGateExt3Production`、`PocOuterCanonicality`、
`PocOuterFraudVerdict`、`PocWhirDotEqBounds`）を実施している。

### F.2 1 人の署名で閉鎖できた（中・修正済み）

閉鎖回路と取り消し回路で、2 番目の参加者が有効であることの表明（`assert_one(active_bits[1])`）
が欠けていた。**1 人だけの署名で閉鎖証明が通った。** 修正後は 2 名以上が必要。

### F.3 同一の鍵を 2 枠に登録できた（中・修正済み）

回路側の鍵の相異検査を無効化した実験で、**両方の回路が「同じ鍵への切り替え」に対して
有効な証明を出せた**ことを確認した（ネイティブ側の検査は有効なまま）。回路と native の
両方で相異を強制するよう修正。

### F.4 巻き戻しで入金が消えた（高・修正済み）

`_rollbackBatch` から保留チェーンの復元が 2 か所とも欠落しており、**そのバッチ以降の入金が
消滅した**。

### F.5 他人の鍵情報を破壊できた（高・修正済み）

`state_update_verifier.rs` は遷移時に受取人・トークン登録・トークン数を固定していたが、
**`regev_pk_digests` を一切比較していなかった**。任意の遷移提案者が、無関係な参加者の鍵
情報を破壊でき、正直な共同署名者全員の検査を通り、全員が署名し、被害者は自分の枠から
二度と引き出せなくなった（回収手段なし）。

**修正済み** — `state_update_verifier.rs:1561`：

```rust
if prev_state.balance_state.regev_pk_digests != next_state.balance_state.regev_pk_digests {
    // "regev_pk_digests must remain unchanged across a state transition (H-2: ...)"
```

回帰テストは `:2557` の `in_channel_transfer_rejects_regev_pk_digest_mutation`。
コメントに「修正を戻すと赤になることを確認済み」と明記されている。

### F.6 他人の提出物を自分の証明で確定できた（高・修正済み）

提出記録が自身の状態根を束縛していなかったため、**別の提出に対して自分の証明で確定させる
ことができた**。

### F.7 異議申し立て期限を無限に延長できた（高・修正済み）

初回と置換の両方の分岐で期限が無条件に再設定されており、置換を繰り返すことで上限を超えて
期限を延ばせた。

### F.8 取り消し後に閉鎖が永久に失敗した（重大・修正済み）

`cancelClose` が凍結カウンタを復元するため、2 回目の閉鎖提出が必ず失敗した（機能停止）。

### F.9 到達不能な正当性検査（中・修正済み）

`ChannelRegRecord::validate` の正準性検査が、実際には一度も実行されない書き方になっていた。
原因は `Bytes32` から内部表現への変換が、体の位数以上の値を黙って畳み込んでいたこと
（異なる `Bytes32` が同じ値に落ちる）。**Lean 化の作業中に発見**し、変換側で拒否するよう
根本修正した（コミット `150bb19`）。リポジトリのテストも修正前は失敗することを確認した。

### F.10 L1 側の演算実装の不備（中・修正済み）

L1 の証明検証で使う冪演算の再実装が、参照実装と一致しない場合があった。専用の監査メモ
（`audit12-08-2026.md`）と、見逃し原因の事後分析（`why-gate8-was-missed.md`）がある。
Lean 側の対応モデルは 11 定理。

## 付録 G — 追跡中の 3 項目の技術的内容

### G.1 開設時の鍵情報の照合（高）

**身元を担う値はすべて実鍵に束縛されている。** `member_pubkeys_root`（`wallet_core.rs:854-866`）は

```rust
regev_pk_digest: m.regev_pk.poseidon_digest(),
```

と**完全な公開鍵から再計算**しており、`MemberInfo` には digest を直接持つ欄がない。
`verify_snapshot`（`:1297-1312`）は 2 つの根を再導出して照合し、`wallet_import_channel`
（`wasm_wallet.rs:443-448`）は**自分の完全な公開鍵との一致**で自分の枠を特定する。

**例外が 1 つだけある。** `balance_state.regev_pk_digests[slot]` — 引き出し請求回路が
実際に照合する複製 — が、どこでも記録側と突き合わされていない。`BalanceState::validate()`
は余白の枠しか制約しない（`balance_state.rs:667-670`）。F.5 の修正（凍結）は、開設時に
入った値をそのまま保存する。

**共同署名者は守られる。** `wallet_sign_state`（`wasm_wallet.rs:315-322`）が署名前に照合し、
不一致なら拒否する。**デリゲートは守られない** — 同関数は `slot < member_count` を要求し、
デリゲートは開設時に署名しないため、この照合が走る機会がない。取り込みも残高の復号も成功
する（復号は暗号文と秘密鍵だけを見て digest を見ない）ため、**請求の瞬間まで異常が
表面化しない**。

**修正方針（1 行）** — `verify_snapshot_own_slot`（`wallet_core.rs:1322-1354`、既に鍵と枠を
持っている）に：

```rust
if snapshot.state.balance_state.regev_pk_digests[slot as usize]
    != Bytes32::from(keys.regev_pk.poseidon_digest())
{
    return bail("my slot's balance-state Regev digest does not match my key");
}
```

コントラクトにも回路にも変更は要らない。F.5 修正時に回路側への制約追加を見送った理由
（正準でない digest を使うテストデータが 21 か所ある）は、ウォレット側の照合には当たらない。

### G.2 チャネル間送金の補助データ（中）

補助データは消費した送金の葉に Merkle 束縛され、その葉は送信者の確定済み取引に束縛される
ため、**証明者が後から差し替えることはできない**。回路内で証明されていないのは
「補助データが本当に対応する取引の葉ハッシュである」という意味論であり、ソース自身が
それを明記している（`receive_transfer_circuit.rs:505-513`）。補う層は 3 つ（共同署名時の
検査、別系統の証明、受信側チャネルの独立再計算）で、悪用には**受信側の全参加者がそろって
再計算を省く**必要がある。

### G.3 登録時の同意確認（低〜中）

`registerChannel`（`IntmaxRollup.sol:1248-1286`）は参加者の署名を検証せず、
`member_regev_pk_digests` は回路内で自由な証人である（`channel_reg_step.rs:331-332`）。
ただし実際には、上記のとおり参加者のソフトウェアが実鍵から根を再計算して照合するため、
偽の登録は取り込み時に検出される。残るのは「資金を預ける前に確認する」という手順の問題。

## 付録 H — モジュール別の定理数（主要なもの）

| モジュール | 定理 | 対象 |
|---|---:|---|
| `NttCorrectness` | 157 | 回路内の高速乗算が素朴な積に一致する証明 |
| `FalconAggregate` | 155 | 署名集約の主張・リスト・バッチ |
| `FalconCore` | 126 | 署名の符号化・検証・回路ガジェット |
| `CloseAssetBacking` | 110 | 裏付け回路（命令列 468） |
| `CloseCircuit` | 92 | 閉鎖回路（命令列 191） |
| `FalconAggProgram` | 78 | 集約の葉と各段の命令列 |
| `RollupValue` | 73 | L1 Rollup コントラクト |
| `ManagerValue` | 63 | 決済 Manager コントラクト |
| `LedgerWriters` | 57 | 帳簿の書き込み元の列挙と枠固定 |
| `SystemSafety` | 56 | 合成された安全性の結論 |
| `SettlementVerifier` | 56 | 決済検証コントラクト |
| `PostCloseClaimCircuit` | 54 | 閉鎖後請求回路 |
| `WithdrawalClaimCircuit` / `CloseFunding` | 53 | 引き出し請求回路 / materializer |
| `BackingBridge` | 52 | materializer と裏付け回路の接続 |
| `TrustBoundary` | 51 | 前提 23 個と、そこから導く定理 |
| `Keccak256` | 45 | 参照ハッシュ仕様（テストベクトル 4 本を計算機で証明） |
| `CloseSignatureBridge` | 21 | 閉鎖回路と署名集約の接続 |

現行の合計：**79 モジュール / 5,311 定理 / 497 ファイルのハッシュ固定**。

## 付録 I — 検査スクリプトが実際に行うこと

`.github/ci/lean-safety-guard.sh` は次を順に実行する。

1. 現行モジュールを**全部ビルド**する（証明が通らなければここで落ちる）
2. ソース中に `sorry`・`admit`・`axiom`・`native_decide` が現れないことを確認する
   （証明の未完了や、計算機の実行結果を証明の代わりに使うことを禁止する）
3. 497 個のファイルの SHA-256 と、サブモジュールの固定コミットを照合する
4. 目録に載っている**すべての定理**について `#print axioms` を実行し、依存する公理が
   `propext`・`Classical.choice`・`Quot.sound` の 3 つ（Lean 自身の基本公理）だけである
   ことを確認する

現在の分布：5,311 定理のうち 1,859 はいかなる公理にも依存せず、3,449 が `propext`、
1,797 が `Quot.sound`、367 が `Classical.choice` に依存する（重複あり）。
**プロジェクト独自の公理は 1 つも存在しない。**

`lean-line-coverage.py` は 169 本の行マップについて、各ソースファイルの全行が重複なく
分類されていること、および「書き起こし済み」の区間が実在する Lean の宣言に結び付いて
いることを、コンパイラに問い合わせて確認する。`--require-complete` を付けると、未書き起こし
の行が残っているため**意図的に失敗する**（完了していないことを隠せないようにするため）。

`check-ledger-writers.py` は、帳簿を書き換える 5 つの変数について Solidity を走査し、
Lean 側に固定した書き込み元の一覧と完全に一致することを確認する（自己テスト 6 件つき）。

`lean-fixture-parity.py` は、Lean のモデルが計算した値と、実際に生成された証明データの
対応フィールドを突き合わせる（18 件 / 177 フィールド）。
