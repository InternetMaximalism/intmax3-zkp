# Regev 暗号化レビュー — 2026-10-16

`src/regev/{encrypt,keys,params,mod}.rs` と、その安全性に直接関係する入力境界・乱数・加算回数の呼出元を確認した。**主要な指摘は、公開証明の検証前に受信暗号文を復号する経路と、入力検証前の digest 計算による panic の2件。** 秘密データの寿命にも改善点がある。対象4ファイルの暗号算術、canonical encoding、u64 復号、運用上限内の準同型加算には、新たな正当性の欠陥を確認していない。

| 優先度 | 指摘 | 確認した影響 |
|---|---|---|
| P1 | 送信者認証・暗号化証明より前に秘密鍵で復号する | 未検証暗号文について、復号の成功／overflow の違いが外部応答に出る。鍵回復は未実証 |
| P2 | 公開鍵・暗号文を検証する前に assertion 付き digest を呼ぶ | 本来 `Result` で拒否する外部入力が panic に進む。native release は abort、WASM は trap |
| P3 | 秘密鍵・暗号化 witness の Debug／消去 | 全秘密値を表示でき、通常の heap 解放後に残留する。実際の外部流出は未確認 |

## 対象と再現条件

ローカル `main` の HEAD と、読み取り専用の `git ls-remote origin refs/heads/main` によるリモート main は、共に **`0a2f5a284c0ae6cf6d23e53b810240151e696724`**。対象4ファイルは HEAD と一致する。監査対象は native 暗号化層であり、`hash_sig`／`transfer_stark` の AIR 全体や、Plonky3 の前回レビューをやり直したものではない。

作業ツリーには既存の変更がある。特に Cargo の patch により、固定 `regev_plonky3` のローカルコピー、p3-dft のローカルソース、前回確認した Merkle-tree 修正が有効である。テストはこの現在の依存グラフで実行した結果であり、変更のない HEAD 全体を別 checkout でビルドした結果とは区別する。製品コードは今回変更していない。

外部 Regev の固定 commit は `5495edab5aa8ec7eae02a35e3098ddee384a1f58`。有効な `vendor/regev-plonky3-5495eda/src/regev.rs` は、その固定 git source と byte-identical だった。ローカルの singleton NTT 修正は、今回の `n=2048` の変換経路を変更しない。対象・関連30ファイルの SHA256、HEAD との一致、依存関係の条件は [source-manifest.json](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/regev-encryption-review-20261016/source-manifest.json) に保存した。

メンバー取込み・co-sign の呼出元を確認する前に [sig-cluster と delegates の規則](/Users/andropov/repos/intmax3-zkp/doc/docs/sig-cluster-vs-delegates.md) を読んだ。以下の公開鍵検証は、署名する co-signer と、署名しない delegate の双方の入力形式についての指摘であり、参加・加入規則の変更を提案するものではない。

## F1 P1 公開検証より前の復号と、秘密鍵に依存するエラーの露出

主位置: [CLI の cosign_gate](/Users/andropov/repos/intmax3-zkp/src/bin/channel_member.rs:10939)、[batch の verify_one](/Users/andropov/repos/intmax3-zkp/src/bin/channel_member.rs:11214)、[browser wallet_cosign](/Users/andropov/repos/intmax3-zkp/src/wasm_wallet.rs:970)。ソース上の処理順序とエラー経路を確認した指摘であり、選択暗号文による鍵回復は実行していない。

これらの wrapper は、入力が現在の head を延長することを確認した後、受信者が自身の管理 slot なら、相手が渡した `channel_tx.enc_amount` を秘密鍵で復号する。その後に `verify_send_transition`／`verify_slim_send_tx` を呼ぶため、**送信者の署名と E-1／decrypted E-1 証明が無効でも、秘密鍵を使う復号処理まで到達する**。head の一致や受信 slot の指定は公開情報の条件であり、暗号文の正当性の証明ではない。

[decrypt_amount](/Users/andropov/repos/intmax3-zkp/src/regev/encrypt.rs:213) は、長さと係数の canonicality を検証してから `c2-c1*s` を計算する。その結果で64以上の係数に非ゼロ digit がある場合、または低64 digit の値が u64 に収まらない場合、`DecryptOverflow` を返す。これは秘密鍵に依存する復号結果の判定である。wrapper では、そこで返るエラーと、その後の `transition invalid` 等の認証・証明エラーを区別できる。復号成功時に署名や平文全体が返らなくても、この判定の違いは残る。

外部への経路も確認した。

- [wallet relay の `/api/cosign`](/Users/andropov/repos/intmax3-zkp/hosting/wallet/wallet-relay.js:1130) は CLI のエラーを JSON に返す。[fullCliError](/Users/andropov/repos/intmax3-zkp/hosting/wallet/wallet-relay.js:49) は message・stdout・stderr を含める。既知の channel、利用可能な head、settling／halt 状態、payload の外形、既存 receipt／replay 等の条件はあるが、CLI 呼出前に送信者署名や E-1 を検証していない。
- [projectToSlim](/Users/andropov/repos/intmax3-zkp/hosting/wallet/batch-window.js:60) は必要な state・row・token 位置の存在を確認し、[fatId](/Users/andropov/repos/intmax3-zkp/hosting/wallet/send-receipts.js:9) はその JSON を hash する。どちらも署名・暗号化証明の検証ではない。fresh な単一 request は [soloOne](/Users/andropov/repos/intmax3-zkp/hosting/wallet/wallet-relay.js:1058) から `cosign` に入る。
- relay 自体の global middleware は JSON、HTTP headers、任意の cluster-halt 制御であり、bearer 認証はなく、listen は `0.0.0.0`。実環境の reverse proxy・ネットワーク公開範囲は確認していない。一方、別の [production API](/Users/andropov/repos/intmax3-zkp/api/server.js:15) は bearer 認証・rate limit を持つ。その認証を通った caller が [cosign route](/Users/andropov/repos/intmax3-zkp/api/routes/channel-send.js:9) から同じ CLI に到達することと、token なしでその API を呼べることは区別する。
- browser wrapper も caller にエラーを返すが、その関数を任意の遠隔相手が直接呼べるというブラウザ上の経路までは確認していない。

**影響:** 準同型暗号としての native Regev に必要な公開証明の防壁を迂回して、未検証暗号文の復号判定を問い合わせられる。機密性に関わる境界なので優先修正とする。ただし、問い合わせ回数、回復可能な情報量、実際の鍵回復・資金移動までは本レビューで実証していない。

**修正:** 送信者認証、認証済みデータから再構成した statement、暗号化／送金証明をすべて検証した後に、受信者の秘密鍵で復号する。既存の検証関数を `(recipient_sk=None, expected_amount=None)` で先に実行してから受信者確認を行うか、公開検証と秘密鍵を使う確認を明示的に分割する。受信額のポリシーは維持する。

core の [verify_slim_send_tx](/Users/andropov/repos/intmax3-zkp/src/wallet_core.rs:2015) 自体は、送信者認証、E-1 検証、任意の受信者復号の順に処理する。wrapper の事前復号がこの順序を崩している。単にエラー文字列を同じにするより、未検証入力に対して復号を呼ばない修正が必要である。回帰確認では、無効な署名・証明を秘密鍵操作の前に拒否することを検査する。

## F2 P2 検証より前の digest 計算で外部入力が panic に進む

主位置: [snapshot の鍵 root 計算](/Users/andropov/repos/intmax3-zkp/src/wallet_core.rs:1337)、[registration の鍵 digest](/Users/andropov/repos/intmax3-zkp/src/block_producer.rs:151)、[送金暗号文の署名 digest](/Users/andropov/repos/intmax3-zkp/src/wallet_core.rs:1871)。こちらもソース上の入力経路を確認したもので、新たな不正 request を実行した結果ではない。

[RegevPk::digest](/Users/andropov/repos/intmax3-zkp/src/regev/keys.rs:83)、[poseidon_digest](/Users/andropov/repos/intmax3-zkp/src/regev/keys.rs:102)、[RegevCiphertext::digest](/Users/andropov/repos/intmax3-zkp/src/regev/encrypt.rs:123) は、全 build profile で `assert!(validate().is_ok())` を使う。canonicality を強制する内部の guard としては正しいが、serde の通常の `Deserialize` は `validate()` を呼ばない。外部入力の caller が先に検証する契約が、次の箇所で守られていない。

**公開鍵:** `verify_snapshot_structure` は record・slot の個数と重複等を検査するが、各 member の `regev_pk.validate()` を呼ばず、`regev_pks_array` → `regev_pk_root` → `pk.digest()` に進む。`verify_snapshot` の署名検証はその後なので、無効な署名でもこの assertion に到達する。

- [wallet_import_channel](/Users/andropov/repos/intmax3-zkp/src/wasm_wallet.rs:441) は JSON を deserialize し、自分の鍵が一覧にあることを確認してから `verify_snapshot` を呼ぶ。自分の entry が一致していても、別の参加者の鍵の長さ・係数は未検証のままである。
- native producer の Register は [snapshot の JSON 取込み](/Users/andropov/repos/intmax3-zkp/src/block_producer_service.rs:494) から register／journal apply を経て `register_snapshot` → `from_snapshot` → 同じ `verify_snapshot` に入る。前段の service health・request ID・fingerprint の確認は、公開鍵の形式検証ではない。
- `ProductionChannelRegistration::validate` 自体も、鍵数を確認した後、各鍵の `validate()` より前に `poseidon_digest()` を呼ぶ。fat-send の [member_pubkeys_root 再計算](/Users/andropov/repos/intmax3-zkp/src/wallet_core.rs:1831) にも同じ欠落がある。

**暗号文:** fat-send の `verify_send_core` は、未検証の `enc_amount` について `ChannelTx::signing_digest` を呼ぶ。[その内部](/Users/andropov/repos/intmax3-zkp/src/common/channel.rs:745) が `enc_amount.digest()` を呼ぶので、長さ違い・非 canonical 係数は返り値のエラーになる前に assertion に到達する。slim-send の [署名 digest 計算](/Users/andropov/repos/intmax3-zkp/src/wallet_core.rs:2005) も同様である。

受信者を管理している wrapper では F1 の事前復号が偶然 CT validation を兼ねるが、受信者を管理していない場合はその復号を skip するため、この保護はない。slim の binary decoder は暗号文を検証する一方、[JSON decoder](/Users/andropov/repos/intmax3-zkp/src/wallet_core.rs:721) は通常の serde 経路で、relay の JSON spool もこちらに入る。JS の row／token 外形検査は、暗号文の係数数や `<q` を検査しない。

**影響:** 不正な鍵・暗号文を受理する soundness bypass は確認していない。問題は availability とエラー境界であり、公開 API が通常の `Err` を返さず panic に進むこと。[production release 設定](/Users/andropov/repos/intmax3-zkp/Cargo.toml:307) は `panic="abort"` なので native process は終了する。CLI subprocess の場合はその request の失敗、常駐 native caller の場合は process の停止となる。WASM は trap であり、その後の host の回復範囲は未検証である。

**修正:** snapshot・registration・fat／JSON-slim の trust boundary で、公開鍵と暗号文を hash する前に `validate()?` で拒否する。checked digest／root API、または検証済みの型を使うと再発を防ぎやすい。新参加者 admission の既存関数には形式検査以外のポリシーもあるため、既存 snapshot の形式検査にその関数全体を流用して、加入規則を変えてしまわないこと。回帰確認は、公開 import／verify API が不正形状・非 canonical 係数を通常のエラーで拒否することを対象とする。

## F3 P3 秘密鍵と暗号化 witness の表示・消去

[RegevSk](/Users/andropov/repos/intmax3-zkp/src/regev/keys.rs:119) は `Clone, Debug` と公開 `Vec<i8>` を持ち、秘密全体を Debug 表示できる。zeroizing Drop はなく、[decrypt_amount](/Users/andropov/repos/intmax3-zkp/src/regev/encrypt.rs:223) が作る upstream key の clone にもない。[AmountWitness](/Users/andropov/repos/intmax3-zkp/src/regev/encrypt.rs:146) と upstream `EncryptionWitness` も、金額・暗号化乱数・noise を Debug 表示でき、通常の heap buffer として解放される。

実際の本番ログにこれらのオブジェクト全体を出す箇所は確認していない。鍵・witness は serde 対象ではなく、peer の SendPayload に秘密 witness が含まれることも確認していない。したがってこれはログ・メモリ取得が起きた場合の露出と残留を減らす改善点であり、遠隔流出の実証ではない。

Debug の秘匿化、実際に消去する owner／Drop、秘密 clone や一時多項式の寿命管理を検討する。root key だけを消去しても、upstream への clone や秘密由来の一時値まで自動的に消えるわけではない。

## 算術・エンコード・digest の確認結果

有効な channel parameters は `n=2048`、`q=2,013,265,921`、`η=2`、`t=256`、`Δ=floor(q/t)=7,864,320`。q は upstream field modulus との compile-time assert がある。keygen は uniform な `a`、ternary な `s`、独立した CBD(2) の error から `b=a*s+e` を作る。暗号化は `c1=a*r+e1`、`c2=b*r+e2+Δ*m`、積は full NTT 後に `x^n+1` で還元する。

| 境界 | 確認結果 |
|---|---|
| primitive の入力 | encrypt の PK、decrypt の CT、add の両 CT は、各2本の2048係数と全係数 `<q` を確認してから field に変換する。F2 はこの検証を通さず hash する caller の問題 |
| 金額エンコード | u64 の低64 bit を各係数の0/1に置き、64以上はゼロ。shift は `i<64` で guard される |
| 復号の丸め | 実際の decoder は `floor((256*v+floor(q/2))/q) mod256`。`q=256Δ+1` を含めて検査し、後述の bound 内で全 digit が正しく復元される |
| u64 復号 | 非ゼロの digit が64以上にあれば `DecryptOverflow`。低64 digit は u128 に加算し、最後に u64 への checked conversion。最大中間値 `255*(2^64-1)<2^72` で accumulator は溢れない |
| 準同型加算 | 両入力を検証し、u64 で係数を加えて明示的に mod q。最大 `2q-2` なので overflow・zip による長さの切捨てはない |
| canonical zero | 全ゼロ CT は加法単位元で、正しい長さの秘密鍵の下でゼロに復号される。公開の zero witness が主張する金額は0のみ。通常の randomized Enc(0) とは区別される |
| digest | PK・CT・root の domain と長さ、係数の順序が明示され、Keccak は u32 big-endian。Poseidon への PK 係数の lift は `<q<2^32<p_Goldilocks` で単射。root は鍵の順序も結合する |

`validate_balance_exit_shape` は canonical zero を許し、c1 が全ゼロで c2 が非ゼロの形を拒否する、既存 exit gadget のための admission check である。暗号化の正当性や金額範囲の証明を代替するものではない。

`RegevPk::validate` も形式検査であり、秘密の高 entropy、uniform な鍵生成、秘密鍵の保有まで証明しない。padding の全ゼロ PK が low-level validation を通るのは意図された動作。新参加者 admission は別途、全ゼロ a や重複鍵を拒否する。native の復号は秘密鍵の長さを確認するが ternary 性は確認しないため、以下の noise 保証は適正に生成された一致する鍵を前提とする。外部から秘密鍵が deserialize される経路は見つけていない。

## 加算上限と丸めの余裕

正しく生成された鍵と暗号化について、各係数で `|s|,|r|<=1`、`|e|,|e1|,|e2|<=2` なので、復号誤差は

```text
E = e*r - e1*s + e2
|E_fresh| <= 2n + 2n + 2 = 8,194
```

1個の fresh balance に64回の credit を加えられるため、最も保守的には **65個の fresh noise term** を数える必要がある。合計 bound は **532,610**、各 message digit の最大は65。canonical-zero base の場合は64項でよい。

`q=256Δ+1` の実際の丸めに対し、digit d の補正項は `floor((256E-d+floor(q/2))/q)` になる。全 `0<=d<256` で共通に正しい整数範囲は `|E|<=3,932,159`。65項の bound はこの範囲内であり、digit も256に達しない。全256 digit と誤差の両端で不等式を確認した [check_rounding.py](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/regev-encryption-review-20261016/check_rounding.py) と [出力](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/regev-encryption-review-20261016/rounding.log) を保存した。誤差に対して式が単調なので、端点の不等式はその間の全整数誤差を含む。

[params のコメント](/Users/andropov/repos/intmax3-zkp/src/regev/params.rs:54) は「64 additions」で64 fresh 項の524,416を数えているため、fresh base の1項分を補うべきである。ただし補正後も約7.38倍の noise margin があり、承認済みの64回上限を変更する根拠にはならない。255という digit headroom も、fresh ciphertext の**項数**と追加演算の**回数**を区別して記述するのが正確である。

上限は低レベルの stateless な `add_ciphertexts` 自体では管理しない。[BalanceState validation](/Users/andropov/repos/intmax3-zkp/src/common/balance_state.rs:719) は全 token の count を64以下に制限し、[state-update の increment check](/Users/andropov/repos/intmax3-zkp/src/circuits/channel/state_update_verifier.rs:1843) は旧 count が64なら拒否、次を厳密な+1にする。[batch fold](/Users/andropov/repos/intmax3-zkp/src/wallet_core.rs:2110) は fresh debit の count を0にした後に credit を検査・加算する。確認した直接の呼出元では上限を迂回する箇所を見つけていない。

これは noise／digit の保証であり、平文金額の合計が u64 に収まる保証とは別である。金額が u64 を超えれば、noise が小さくても `decrypt_amount` はエラーを返す。u64 の残高範囲を保つことは、送金・保存則の admission 側の責任である。

## 乱数と秘密情報の境界

公開 API の `channel_keygen`／`encrypt_amount` は `Rng` のみを要求し、`CryptoRng` は型で強制しない。CSPRNG を渡す義務は caller にある。今回確認した private send／refresh／keygen の本番 caller では、CSPRNG または秘密32-byte seed によるその初期化を使い、弱い RNG の誤使用は見つけていない。

browser は `rand010::rng()`、復元は秘密32-byte seed の StdRng。CLI の private send／refresh は OS 乱数32 byte から StdRng を作る。公開 seed を使う deposit credit は既に公開された L1 amount の再構築用、genesis は固定の公開配分または公開ゼロである。明示的な DEV／TEST 用の deterministic contribution と、private amount の暗号化を区別した。

`RegevSk`、`AmountWitness`、`MemberKeys` は peer 向け serde 対象ではない。CLI が refresh の再証明用に amount と seed を保存する `TokenWitness` は秘密 witness と同等の private state であり、確認した保存処理は0600の一時ファイル・rename・最終 mode を使う。peer snapshot にこの seed を含める経路は確認していない。

## テスト結果と限界

**14個の異なる既存テストが成功**した。重複した実行を足して数えていない。

| 分類 | 結果 |
|---|---|
| encrypt／decrypt／add／CT canonicality／digest | 7 passed |
| keygen／PK canonicality／ordered PK root | 3 passed |
| channel parameters | 1 passed |
| domain constants の distinctness | 1 passed |
| canonical-zero witness | 1 passed |
| balance-state canonicality／加算回数上限 | 1 passed |

金額0・1・2・255・2^32・u64上端、wrong key、長さ違い・非 canonical 係数、64項の低 digit／広い金額の加算、固定 digest、zero witness を含む。toolchain は `rustc 1.87.0-nightly (b48576b4d 2025-03-22)`。各コマンド、テスト名、ログは [test-results.json](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/regev-encryption-review-20261016/test-results.json) と同じディレクトリに保存した。65項の保守的な上界は既存64項テストに依存せず、上記の整数不等式でも確認した。

既存正常系テストの成功は F1／F2 の不存在を示さない。両者は公開入力の処理順序と検証契約の欠落から確認した。新しい oracle request、不正 snapshot／CT、偽造 proof、鍵回復を実行したものではない。

[params の197／178-bit見積り](/Users/andropov/repos/intmax3-zkp/src/regev/params.rs:9) は単一の primal-uSVP／core-SVP の数値として記載されている。今回、固定 estimator version・全攻撃・分布・sample 数・cost model を揃えた再計算は行っていない。[lattice-estimator の公式説明](https://github.com/malb/lattice-estimator) も、推定は heuristic で、対象攻撃と cost model に依存するとしている。この表だけで実装全体の128-bit security を認定しない。一方、その再計算をしていないことを新たな暗号解読の発見とも扱わない。

RLWE の暗号学的仮定、CSPRNG 自体の品質、timing／fault／heap disclosure 耐性、WASM 実行時の回復挙動、全プロトコルの保存則と AIR 制約の完全性までは本レビューで証明していない。
