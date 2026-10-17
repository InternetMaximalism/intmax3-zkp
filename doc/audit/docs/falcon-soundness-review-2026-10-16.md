# Falcon 本体と署名検証回路の健全性監査

監査日: 2026年10月16日。対象は `main` の `0a2f5a284c0ae6cf6d23e53b810240151e696724`。`git ls-remote origin refs/heads/main` でリモートとの一致を確認した。対象の `src/falcon_sig/` と、指摘した validity consumer は HEAD から変更されていない。

**P1 の署名履歴の認証漏れを、Falcon 集約リストと validity 回路の接続境界で確認した。Falcon-512 本体や単体の算術ガジェットで不正署名の受理を許す制約欠落は確認していないが、現行システムの署名検証全体を健全とは判断できない。** 併せて、一時的な秘密多項式のコピーが消去されない P3 の問題を確認した。

製品コードは修正していない。本報告、ソース識別情報、既存テストの実行ログを追加した。既存の監査文書の結論は根拠とせず、制約本体と検証経路を確認した。

## 対象

| 対象 | 確認内容 |
|---|---|
| `src/falcon_sig/mod.rs`、`compat.rs`、`vendor/` | 鍵生成・署名、乱数、公開鍵と message の結合、codec、native verification、NTT とノルム、上流との差分 |
| `gadget.rs` | 係数範囲、Goldilocks の canonical split、mod-q 還元、H2P、NTT、ノルム、公開入力、conditional API |
| `batch.rs` | Fiat–Shamir による整数多項式積の検査、整数への対応、count・active flag・padding |
| `agg.rs`、`list.rs`、`agg_list.rs` | 再帰検証鍵、message・count・鍵リストの結合、cyclic wrapper、実際の consumer |
| close／cancel-close／validity の関連箇所 | 署名の検証結果が要求された statement に接続されるか |

ここでの N-of-N は sig-cluster の co-signer を指す。delegate の加入規則の変更を提案するものではない。関連する Plonky2 submodule の HEAD は `3a20a05fb99d2653c4d37debb4f1ead2f422dfb2`。実際の対象ファイルの SHA256 は [source-manifest.json](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/falcon-review-20261016/source-manifest.json) に保存した。

## F1 P1 集約署名リストの内部検証鍵が validity 回路で固定されない

主位置: [validity_circuit.rs](/Users/andropov/repos/intmax3-zkp/src/circuits/validity/block_hash_chain/validity_circuit.rs:249)。ソースに基づく制約欠落であり、完全な偽造 proof の生成・実行は行っていない。独立したレビューと再確認で、同じ欠落を確認した。

`ValidityCircuit::new` は、非ゼロの `final.bp_sig_chain` を証明する `AggListCircuit` proof に対して、通常の `add_proof_target_and_conditionally_verify` を呼ぶ。この helper は外側 proof を検証する定数 VK を固定するが、**cyclic proof の public inputs に含まれる内部 VK をその定数へ結合しない**。

必要な制約は次の処理順序から特定できる。

1. [AggListCircuit](/Users/andropov/repos/intmax3-zkp/src/falcon_sig/agg_list.rs:423) は `AggListStepCircuit` を `CyclicChainCircuit` で包み、外部にはこの cyclic wrapper の verifier data を返す。
2. [CyclicChainCircuit](/Users/andropov/repos/intmax3-zkp/src/utils/hash_chain/cyclic_chain_circuit.rs:59) は再帰用 verifier data を public input として割り当て、その値を使って前段 proof を検証する。現在と前段の「提示された VK」は相互に接続されるが、実際の wrapper の VK との一致はここでは保証しない。
3. Plonky2 の [cyclic recursion の仕様](/Users/andropov/repos/intmax3-zkp/contracts/lib/polygon-plonky2/plonky2/src/recursion/cyclic_recursion.rs:94) は、この事情を明記し、通常の proof 検証に加えて `check_cyclic_proof_verifier_data` 相当の外部チェックを要求している。
4. [通常の conditional helper](/Users/andropov/repos/intmax3-zkp/src/utils/recursively_verifiable.rs:32) にはそのチェックがない。同じファイルの [conditional cyclic helper](/Users/andropov/repos/intmax3-zkp/src/utils/recursively_verifiable.rs:70) は、public-input suffix の circuit digest と constants/sigmas cap の両方を期待 VK に結合する。
5. validity 回路は signature-list proof から先頭8個の chain commitment だけを取り出し、`final.bp_sig_chain` に結合する。後続の `prove`／`verify` に内部 VK のチェックはなく、内部 VK は validity の公開出力にも残らない。

**影響:** 正しい外側 VK で検証される terminal wrapper の proof であっても、前段を別の VK で検証することが許される。最終の genuine な `AggListStep` とその Falcon aggregate は依然として必要だが、それ以前の prefix に含まれる署名履歴の正当性を genesis から帰納的に保証できない。現在の `C == final.bp_sig_chain` チェックだけでは、prefix の署名検証の欠落を補えない。

同じ `CommonCircuitData` であることは VK の一致を意味しない。実際にリポジトリの [internal_dummy_circuit](/Users/andropov/repos/intmax3-zkp/src/utils/dummy.rs:60) は、同じ common data で任意の public inputs を持てる別回路を作るための処理を持つ。これは shape の一致が statement の一致を保証しないことを示すソース上の根拠であり、今回その proof を作成したという意味ではない。

**本番への適用:** [validity prover の回路 factory](/Users/andropov/repos/intmax3-zkp/src/validity_prover_service.rs:2201) は実際の Falcon aggregate、AggList、問題の ValidityCircuit を組み合わせる。廃止済み API だけの問題ではない。honest な `CyclicChainCircuit::prove` が正しい VK を witness に設定することや、サービスが事前に native verification を行うことは、悪意ある prover に対する回路制約の代わりにならない。

**修正:** 249行の呼出しを既存の `add_proof_target_and_conditionally_verify_cyclic` に置換するか、同等の条件付き VK 一致制約を追加する。条件は現在の computed `final.bp_sig_chain != 0` のままでよい。追加する制約により validity の VK が変わるため、依存する VK・fixture・デプロイ設定の更新が必要になる。同じ constructor の block-hash-chain proof は既に cyclic 用 helper を使っている。

回帰テストでは、active branch で内部 VK の digest と cap の**全要素**が定数に結合されることを確認し、正常な初回・追加・複数 span と、chain がゼロの dummy branch を維持する。通常の prover helper だけを使うテストは常に正しい内部 VK を設定するため、この欠落を検出しない。

## F2 P3 一時的な秘密多項式のコピーが消去されない

位置: [Polynomial の zeroize 実装](/Users/andropov/repos/intmax3-zkp/src/falcon_sig/vendor/math/polynomial.rs:652)、[秘密基底の clone](/Users/andropov/repos/intmax3-zkp/src/falcon_sig/vendor/keys/secret_key.rs:375)。固定された上流ソースにも存在する。

`Polynomial<F>` は `Zeroize` と marker trait の `ZeroizeOnDrop` を実装するが、実際の `Drop` 実装や zeroizing destructor の derive を持たない。marker を実装するだけでは、解放時に `zeroize()` は呼ばれない。

通常の keygen／signing が呼ぶ `to_complex_fft` は、秘密 NTRU basis の4多項式を `basis.clone()` で複製する。この整数コピーや秘密由来の FFT 一時値は、その後通常の drop で解放される。`compute_pub_key_poly` にも秘密多項式の clone がある。

**影響:** 後続の heap disclosure、メモリ取得、再利用領域の読取りが起きた場合の秘密残留を増やす。秘密鍵の遠隔回収を実証した指摘ではない。保存されている `SecretKey` と LDL tree は実際の `Drop` で明示的に消去されており、「鍵が全く消去されない」という問題ではない。

**修正:** 秘密一時値を実際の zeroizing owner／scoped guard で管理するか、利用後に明示的に消去する。`Polynomial` 全体への単純な generic `Drop` 追加は、係数 field を move する既存処理や型制約に影響するため、秘密値の所有範囲を明確にして修正する。

## 単体の署名検証と算術制約

以下は、honest witness generator の動作を安全性の根拠にせず、生成される制約と整数上界を追跡した結果である。

| 境界 | 確認結果 |
|---|---|
| native verification | `h_i<12289` を確認し、実際の salt／message から H2P を再計算。`s1=c-s2*h` は有限体の正確な NTT で求め、centered norm を u64 で合計する |
| 署名の wire encoding | version と666-byte長、係数の `[-2047,2047]`、負のゼロ・長い unary・unused bits を確認。全625-byteの再エンコード比較で末尾 padding も固定する |
| identity binding | native の `verify_with_pk_g` と gadget の両方で `Poseidon(IMFK || encode(h)) == pk_g` を内部で確認する。鍵の4係数ずつの14-bit packing は `<2^56<p` |
| H2P | salt は8個の40-bit要素、message は8個のu32 limb。capacity の IMFH、吸収順序、64回の squeeze、各係数への full-field-output の使用が native と circuit で一致する |
| Goldilocks から mod q | canonical な32/32 split に、`hi=2^32-1` なら `lo=0` の条件を加え、`x+p` による第二表現を排除する。`hi*10952+lo<2^46` を32-bit quotientで還元する |
| mod-q 還元 | `t=k*q+r`、quotient の bit幅、`r<q` の両側 range check を確認。最大許容幅でも `2^49*q-1<p` なので、recomposition が field wrap で別整数を選ばない |
| gadget の NTT | root と逆元の関係を build時 assert。全 butterfly・点ごとの積・逆変換・最後の `s1` 還元が range-checked。実際の quotient幅は1／14／15／32 bit |
| centered norm | centering bit は Boolean。誤った bit は各平方を小さくできない。悪意ある bit 選択でも全体は `1024*q^2<2^38<p` なので wrap しない。`beta²-norm` の26-bit check が `norm<=34,034,726` を課す |

ガジェットの `s2` は canonical mod-q residues で、数学的な Falcon の等式とノルムを検証する。native transport の圧縮可能な `[-2047,2047]` だけに制限する形式ではない。この差は既存の module contract に明記されており、今回これによる署名偽造は確認していない。

## batch と再帰合成

`batch.rs` は全 slot の canonical `h`／`s2` と全1023個の `pi` 係数を固定長 Poseidon transcript に入れた後、拡大体 challenge `tau` を得る。各 slot が個別に `pi(tau)=h(tau)*s2(tau)` を検証するので、slot 間の誤差を相殺する形式ではない。`pi` の range check がない点も追跡した。多項式一致が成立すれば、canonical `h*s2` の各整数係数は `512*(q-1)^2<2^37<p` で、field の `pi` はその整数に対応する。

これは Poseidon／Fiat–Shamir の仮定に依存する確率的な検査である。D=2 の約128-bit challenge 空間と、degree<=1022 によるコードが掲げる conservative な `<2^-117` の product-check error は別であり、決定的な積の制約やシステム全体の128-bit認定とは区別する。

active flags は Boolean、先頭 active、非増加で、count はその総和。inactive の公開鍵 limb は flag 倍されてゼロになる。tree aggregate も leaf は unconditional signature verification、子 VK は定数、右子の message／count／鍵リストは存在 flag で制御される。これらに追加の具体的な制約欠落は見つけていない。

aggregate 自体は duplicate な署名鍵を禁止する API ではない。close／cancel-close は検証済み PI の message を回路内で再計算した digest に、count を member_count に、鍵リストを member-set commitment と active-key distinctness に結合している。F1 はこれらの非 cyclic aggregate の確認とは別の、署名履歴の cyclic wrapper の境界である。

## 修正すべき説明と API の注意点

- `gadget.rs:676–679` と `mod.rs` の padding 説明は、inactive slot の鍵が常にゼロ多項式の digest に固定されるとしているが、制約はそうではない。inactive 時も任意の canonical `h` が入り、`pk_g=hash(h)` になる。all-zero padding は便利な witness の一例である。現行の batch／tree／close consumer は inactive の鍵を公開 statement から除外しており、この説明の誤りから現在の偽造経路は確認していない。
- `gadget.rs:736–747` の `<2^36` は最小の centered 値を選んだ場合の上界。prover が選ぶ bit も考慮した上界は `<2^38`。専用の bounds-ledger テストは既に正しい値を使い、どちらも Goldilocks の法より十分小さいため、これはコメントの修正点である。
- `new_conditional` の flag は caller が本当に Boolean に制約し、認証された active 条件に結合する必要がある。`select` だけで Boolean 性が得られるわけではない。
- `from_insecure_ntru_basis_bytes` は4096-byte長しか検証せず、NTRU relation や正しい sampling tree を検証する鍵 import ではない。見つかった非 test caller は明示的な insecure deterministic test-key cache に限られる。信頼できない production 鍵の decoder として扱わない。

## 上流との対応と暗号学的前提

固定 Miden commit `475092a8476bf4c806424579e5d9225b12941c1a` の公開ソース11ファイルを取得し、ローカルコピーと比較した。[比較 inventory](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/falcon-review-20261016/provenance-comparison.json) に URL と SHA256 を保存した。FFT と Falcon field は byte-identical。sampler／ffSampling／NTRU keygen の差は import・型の接続などを確認し、秘密署名演算に未記載の変更は確認していない。上流の reference-signing KAT 全体を今回新たに実行したわけではない。

この実装は SHAKE の代わりに plonky2 Poseidon を H2P に使う、承認済みの独自 instantiation である。[Falcon v1.2 仕様](https://falcon-sign.info/falcon.pdf) の centered-norm 検証と64-bit出力を mod q に還元する設計は参照したが、Poseidon を必要な random oracle と扱う仮定まで標準 Falcon の試験で認定されるわけではない。

浮動小数の signing sampler の side channel／fault 耐性、Gaussian distribution、NTRU／SIS／Poseidon の暗号解析を証明したものではない。side-channel 残留リスクは既存 threat model の TM-C4 でも明示されている。今回、WASM／browser の新たな portability 測定は行っていない。

## 実行結果

固定 nightly toolchain と現在の release test binary で、**61個の異なる既存テストが成功**した。性能測定専用のテストは除外した。

| 分類 | 結果 |
|---|---|
| native signature／codec／identity | 13 passed |
| native review-hardening | 4 passed |
| vendor math | 3 passed |
| 単体 gadget | 22 passed |
| batch | 12 passed |
| tree aggregate の正常系 | 3 passed |
| 単一署名リスト3-entry roundtrip | 1 passed |
| AggList の2-entry cyclic roundtrip | 1 passed |
| AggList の statement 感度／parser | 2 passed |

公開鍵・message・salt の変更、noncanonical 係数、quotient の不正、ノルム境界、空署名・不正な flag、product witness・PI の変更を拒否する既存テストを含む。テストによっては generator の段階で失敗するので、異常系テストの成功だけを制約健全性の証明としてはいない。算術結論は上の制約と上界の検査に基づく。

実行結果とコマンドは [test-results.json](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/falcon-review-20261016/test-results.json)、ログは同じディレクトリに保存した。主な実行方法は次のとおり。

```sh
cargo test --release --locked --offline --lib falcon_sig::tests -- --skip bench_keygen_sign_verify
cargo test --release --locked --offline --lib falcon_sig::review_hardening_tests
cargo test --release --locked --offline --lib falcon_sig::vendor
cargo test --release --locked --offline --lib falcon_sig::gadget::tests:: -- --skip falcon_sig_circuit_measure_1_3_16
cargo test --release --locked --offline --lib falcon_sig::batch::tests:: -- --skip batch_measure
```

F1 について確認したのは、実運用経路にある必須の VK 結合制約の欠落と、その帰納的な保証への影響である。完全な不正 validity proof、L1 での受理、資金移動は再現していない。既存の正常 roundtrip は honest helper が内部 VK を正しく設定する経路を検証するもので、F1 を否定するテストにはならない。
