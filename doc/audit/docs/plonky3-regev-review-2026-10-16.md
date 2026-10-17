# Plonky3 と Regev の健全性監査

監査日: 2026年10月16日。対象は `main` の `0a2f5a284c0ae6cf6d23e53b810240151e696724` と、監査開始時から存在していた未コミットの依存修正。`git ls-remote origin refs/heads/main` で、リモートの main も同じコミットであることを確認した。

**現行 Regev の暗号化・範囲・送金 AIR で、偽の statement の受理を成立させる算術制約の欠落は確認していない。一方、実際に使われる FRI 検証経路には panic を起こす入力検証の不足があり、汎用 MMCS には一部の行列を認証しない設定がある。依存コード全体を「健全性に問題なし」とは判断できない。**

製品コードの修正、ブランチの切り替え、既存変更の取り消しは行っていない。今回追加したのは本報告と検証資料だけである。

## 対象と依存関係

| 対象 | HEAD | 監査した作業ツリー | アプリケーションでの利用 |
|---|---|---|---|
| Plonky3 0.4.2 | `vendor/plonky3/` の FRI、Merkle、uni-STARK | HEAD と同じ | Cargo の直接依存。`src/` と `tests/` で直接利用を確認できなかった |
| Plonky3 0.5.3 | `vendor/p3-{field,fri,merkle-tree,uni-stark,poseidon2-air}-0.5.3/` | Merkle の3ファイルに既存の未コミット修正 | Regev、BabyBear hash signature の証明経路 |
| DFT 0.5.3 | crates.io | 新しい `vendor/p3-dft-0.5.3/` と Cargo patch | Regev の LDE 計算 |
| `regev_plonky3` | git の `5495edab5aa8ec7eae02a35e3098ddee384a1f58` | 新しい `vendor/regev-plonky3-5495eda/` と Cargo patch | 暗号化、NTT、設定、独自 batch STARK |

Regev のローカルコピーと固定 git ソースの差分は、NTT の長さ1の早期 return とそのテストだけだった。HEAD と作業ツリーを混同せず、以下に各指摘の状態を記す。ソースの SHA256 は [source-manifest.json](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/plonky3-regev-review-20261016/source-manifest.json) に保存した。

## 指摘

| ID | 優先度 | 問題 | 現行 Regev への適用 |
|---|---|---|---|
| F1 | P2 | FRI が証明由来の arity と高さを検証する前に使用し、panic に到達する | 対象経路を使用する。ソースによる到達性確認、実行ペイロード未作成 |
| F2 | P2 | MMCS の cap より root 側で混入する小さい行列が認証されない | `cap_height=0` のため該当しない |
| F3 | P2 | MMCS の認証経路全体の長さと cap サイズの検証が不十分 | HEAD の binary は該当。作業ツリーの binary は修正済み、N>2 は残る |
| F4 | P2 | hiding MMCS が固定 salt 長を検証しない | HEAD は該当。作業ツリーの 0.5.3 は修正済み |

P2 は修正すべき問題を示す。汎用 API の指摘を、その条件を使わない現行アプリケーションの資金窃取と同一視しない。

### F1 FRI の arity と高さの検証が遅い

位置: [FRI verifier](/Users/andropov/repos/intmax3-zkp/vendor/p3-fri-0.5.3/src/verifier.rs:95)。HEAD と作業ツリーの両方に残る。

`log_arity` は証明内の各 query opening から読み出される。検証器は query 間の一致を調べるが、`1 <= log_arity <= max_log_arity`、総 reduction と検証対象ドメインの一致、整数・有限体の上限を先に確認しない。119–120行で合計から `log_global_max_height` を作り、175行でその値を `challenger.sample_bits` に渡す。

実際の hiding 設定は `SerializingChallenger32<BabyBear, ...>`。依存 `p3-challenger` 0.5.3 の `serializing_challenger.rs:162–165` は `bits < usize::BITS` と `2^bits <= q` を通常の `assert!` で要求する。したがって許容範囲を超える証明由来の高さは、`InvalidProofShape` を返す前に release でも panic する。後続の `open_input` にも高さの未検証減算、`verify_query` にも arity の未検証 shift がある。

アプリケーションの [verify_one](/Users/andropov/repos/intmax3-zkp/src/regev/transfer_stark.rs:889) は外側の `degree_bits` と公開評価数をチェックするが、FRI の arity はチェックしない。そこから Regev の `stark::verify_batch`、`pcs.verify`、hiding PCS を経由して当該処理に進む。外側の正しい trace 高さだけでは防げない。

**条件と影響:** 先行する形状チェックと PoW が成功する必要がある。本番設定は commit ごとに8 bit、query に16 bit の PoW。arity 自体も query PoW 前の transcript に含まれるので、既存証明の1バイト変更だけで成立するとは主張しない。PoW は公開の再計算可能な作業であり、入力の認証にはならない。panic は native の本リポジトリの release 設定 `panic="abort"` ではプロセス終了になる。完全なネットワーク経由の再現は行っておらず、不正な statement の受理を示す指摘ではない。

**修正:** 検証器が持つ入力ドメインから最大 LDE 高さを導出し、checked arithmetic で各 arity、総 reduction、到達すべき中間高さ、field と sampler の上限を検証する。不整合は PoW や index sampling より前に `InvalidProofShape` として拒否する。0.4.2 にも commit 数から高さを求めて先に使用する同種の API 境界があるが、現行アプリケーションでの利用は確認していない。

### F2 cap を使う混合高さ MMCS が小さい行列を認証しない

位置: [MerkleTree の cap](/Users/andropov/repos/intmax3-zkp/vendor/p3-merkle-tree-0.5.3/src/merkle_tree.rs:199)、[MMCS の成功判定](/Users/andropov/repos/intmax3-zkp/vendor/p3-merkle-tree-0.5.3/src/mmcs.rs:427)。HEAD と作業ツリーの両方に残る。独立した2名のソース確認で同じ結論になった。

具体的な有効形状は、行列の高さ `[8,1]`、binary MMCS、`cap_height=1`。この組合せを禁止する API の記述やガードはない。

1. constructor が作る digest layer の長さは `[8,4,2,1]`。
2. 高さ1の行列は最後の root layer に達した時にだけ混入される（`merkle_tree.rs:157–168`）。
3. `cap(1)` は `4-1-1=2` 番目、長さ2の layer を返す。高さ1の行列はこの commitment に影響しない。
4. verifier は2個の siblings を要求し、`8→4→2` で終了する。高さ1の opening は hash に一度も使われず、残った行列がないかを確認せずに cap の一致だけで `Ok(())` を返す。

これはハッシュ衝突の困難性と無関係な、汎用 commitment の binding 欠落である。上記の小さい行列の値は commitment と verifier の成功判定に関与しない。実行による偽造テストは行っておらず、上記はソースから確定する処理順序である。

**適用範囲:** Regev の通常・hiding MMCS はともに `cap_height=0`（[config.rs](/Users/andropov/repos/intmax3-zkp/vendor/regev-plonky3-5495eda/src/config.rs:163)）。その設定では root まで検証し、小さい行列も取り込む。0.4.2 は root のみの方式。

**修正:** 全行列の混入が済む前の cap を constructor で拒否するか、cap より root 側の混入も認証する形式にする。verifier でも全ての必要な行列が認証されたことを確認する。正常な opening が通るだけの mixed-height テストでは、この欠落は検出できない。

### F3 MMCS の経路長と cap サイズが完全には固定されない

位置: [MMCS の binary ガード](/Users/andropov/repos/intmax3-zkp/vendor/p3-merkle-tree-0.5.3/src/mmcs.rs:344)、[証明長に従うループ](/Users/andropov/repos/intmax3-zkp/vendor/p3-merkle-tree-0.5.3/src/mmcs.rs:381)。

HEAD は最大高さから期待する経路長・cap 数を検証せず、渡された siblings を使い切った位置を cap と解釈する。HEAD の Merkle ソースを一時ディレクトリに取り出し、既存の `repaired_verifier_boundaries` を実行したところ、高さ2の opening が申告高さ8でも受理された。

```text
HEAD: valid=true; changed_height=true; changed_width=true; longer_salt=true; siblings=1
作業ツリー: valid=true; changed_height=false; changed_width=true; longer_salt=false; siblings=1
```

HEAD に対するテストの失敗は、修正後の期待値を満たさないことを再現した意図した結果。[HEAD 実行ログ](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/plonky3-regev-review-20261016/head-mmcs.log) を保存した。比較にはプロジェクトの lockfile を基にした依存解決を使った。

既存の未コミット修正は `N==2` に期待する経路長と cap 数の検証を追加しており、現在の Regev binary 設定を改善する。一方、N>2 では全経路を設定に結合するチェックがなく、各 step の siblings 数を検証するだけである。constructor の停止性・arity schedule の修正だけではこの境界は閉じない。

**修正:** binary 修正をリリース対象に含め、N>2 でも dimensions と設定 cap から期待 schedule・全 siblings 数・cap 数を導出して確認する。N>2 の利用は現在の `src/` で確認していない。不正な FRI/STARK 全体の受理は実証していない。

### F4 hiding MMCS の salt 長の検証が不足する

位置: [hiding MMCS](/Users/andropov/repos/intmax3-zkp/vendor/p3-merkle-tree-0.5.3/src/hiding_mmcs.rs:151)。

HEAD は salt の外側の個数だけを照合し、各 salt が `SALT_ELEMS` 個であることを確認せず row に連結する。既存の境界テストでは4個の salt にゼロを1個追加しても葉の hash が同じになり、HEAD の verifier が受理した。作業ツリーの既存修正は salt 長を先に確認して拒否する。上の HEAD／作業ツリー比較でもこの差を再現した。

固定 salt 形式の検証不足を確認したものであり、salt の別表現だけで資金を偽造できるとは結論しない。0.4.2 の hiding MMCS にも同じ長さチェックがないが、現在の利用を確認していない。

## Regev の設定と API に残る懸念

**salt と mask の乱数ストリームの共有。** [zk_config_with](/Users/andropov/repos/intmax3-zkp/vendor/regev-plonky3-5495eda/src/config.rs:163) は同じ ChaCha20Rng の clone を input MMCS に渡し、その MMCS の clone を FRI MMCS に渡し、元の RNG を PCS の mask に渡す。各 RNG は同じ状態から始まる。salt と mask の BabyBear サンプルには相関があり、公開 salt が mask に使われた乱数と一致する場合がある。ChaCha20 への変更は予測可能な PRNG の問題を改善するが、clone は独立なストリームを作らない。

ただし、この相関から残高・秘密鍵が回収できることは確認していない。mask の残る自由度と trace 形状によるため、**ZK 破綻と断定しない未解決の設計懸念**とする。input salt、FRI salt、PCS mask には別 seed または domain separation を使い、必要な同時分布の前提を明示すべきである。Production ごとに fresh config を作る現行コードでも、証明内の相関は残る。

**`eta` が検証を通るのに無視される。** `RegevParams::validate` は `eta==2` を要求せず、`eta=32` も通る。一方、keygen・encrypt・AIR は CBD(2) に固定されている。安全性評価を `eta` に依存させる下流利用者には設定の誤認を生む。現行チャネルは `REGEV_ETA=2` に固定されているため、この条件では影響しない。未対応値を拒否すべきである。

**公開 lookup 数の検証順序。** upstream の `verify_encryptions` と `verify_transfers` は、inner verification の後で公開評価数を4／8と照合する。inner では個数を前提とする index／assert があるため、依存 API の形状チェックを先に移すべきである。現行の主要な `verify_one` は事前チェックを持つ。この依存 API の問題について完全な不正証明の実行再現は行っていない。

**polynomial 長の API 前提。** upstream の ciphertext 加算と復号は一部の配列を `zip` し、全係数長の一致を完全には確認しない。現行の `RegevCiphertext::validate` と変換・加算 entry point が長さと canonicality を補っている。依存 API 単独でも同じ不変条件を検証する方がよい。

## 検査した制約と既知問題

- Regev: ternary randomness、CBD half の `{0,1,2}` 制約、message と carry の Boolean 制約、carry の初期値0・最終値0、Horner の最終行のアンカー、main commitment 後の共通 challenge、ring quotient identity、公開 polynomial の再評価、trace 高さと ring dimension の一致を確認した。
- range AIR: complement・flag・prefix count・weight・suffix sum の結合と、有限体での wrap を防ぐ `value_bits<=29` を確認した。range API は低位 `value_bits` だけを制限するもので、高位 message がゼロであることまで証明する API ではない。
- field のローカル修正: chunk 処理の MSRV 置換を registry ソースと比較し、同数の complete chunk と tail が計算されることを確認した。具体的な算術の差は見つけていない。
- Poseidon2 AIR: full／partial round、S-box intermediate、post-state の制約を確認した。具体的な round 制約の欠落は見つけていない。
- DFT: 作業ツリーの既存 patch は、Rust が同一 layout を保証しない異なる `DenseMatrix` generic instantiation 間の aggregate transmute を、要素 slice と明示的な matrix 再構築に置換する。実環境で layout 不一致を観測したという指摘ではない。検証した LDE の通常出力は NaiveDft と一致した。
- Regev NTT: 長さ1の bit-reversal shift の問題は、作業ツリーの既存 early return で処理される。チャネルは n=2048 を使い、polynomial 積の NTT 長は4096なので、その境界自体は通常経路ではない。

公式の [FRI size checks](https://github.com/Plonky3/Plonky3/security/advisories/GHSA-m23j-cj9m-ppg9)、[final degree と roll-in](https://github.com/Plonky3/Plonky3/security/advisories/GHSA-f69f-5fx9-w9r9)、[opened values の transcript binding](https://github.com/Plonky3/Plonky3/security/advisories/GHSA-vrmm-4mm5-38vm) に対応する、最終係数数の照合、低次数入力のランダムな roll-in、batch challenge 前の claimed evaluations の observe は、両世代の vendored コードに存在する。

[MultiField32Challenger の advisory](https://github.com/Plonky3/Plonky3/security/advisories/GHSA-vj64-rjf3-w3v7) は 0.4.3／0.5.3 で修正されたもの。0.4.2 は依存グラフにあるが、その challenger の利用を現行ソースで確認していない。現行 Regev は 0.5.3 の別 challenger を使うため、古い版番号だけを根拠に同じ問題の影響ありとはしない。

[PaddingFreeSponge の可変長衝突 advisory](https://github.com/Plonky3/Plonky3/security/advisories/GHSA-3g92-f9ch-qjcm) については、行の固定レイアウトと salt 長が重要になる。MMCS 自体は `Dimensions.width` を検証しないが、FRI は意図的に width=0 を渡し、後で各 row 長を OOD 値と `zip_eq` で照合する。width=0 をそのまま厳密検査する修正は正常な FRI も拒否するため、呼出側と合わせて設計する必要がある。

本番の proof 設定が掲げるのは、42 queries・rate 1/4・16 bit query grinding による約100 bitの conjectured security。Ring-LWE の n=2048 と、証明システムの security level は別のパラメータである。このレビューは128 bitの証明健全性を認定するものではない。

## 実行結果と再現

| 検証 | 結果 |
|---|---|
| リポジトリ固定 toolchain の `cargo test --release --frozen --lib regev:: -- --test-threads=1` | 64 passed、0 failed、17.73秒 |
| N2048 と本番 `zk_config()` による upstream encryption／range／transfer | 正常証明が成功。公開鍵・暗号文・plain_bits・range・transfer の役割順を変えた検証は拒否 |
| 作業ツリー MMCS の既存境界テスト | 2 passed。5,058 binary cases、48 extension cases、155 four-ary cases と mixed-height sweep |
| N=8 の停止性と既存 N-ary sweep | 2 passed。N=4 は48,829、N=8 は37,024、N=16 は36,169の正常 opening |
| rejection sampling の既存境界テスト | 3 passed |
| DFT と NaiveDft の LDE 比較 | 168組。sequential／parallel とも成功 |
| 0.5.3 FRI の既存テスト、uni-STARK no-next-row 正常テスト | 各2 passed／1 passed |
| HEAD MMCS に修正後の既存境界テストを適用 | 期待どおり失敗。誤った高さと長い salt の受理を再現 |

本番設定を使う追加 fixture と実行ログは [検証資料](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/plonky3-regev-review-20261016/Cargo.toml) に保存した。リポジトリ root から次で実行できる。

```sh
cargo run --release --frozen --manifest-path doc/audit/zkp/evidence/plonky3-regev-review-20261016/Cargo.toml
cargo +stable test --offline --manifest-path doc/audit/zkp/agent-tools/mmcs-boundary-tests/Cargo.toml --test observed_mmcs_boundaries --test known_eight_ary_stall --test rejection_sampling -- --nocapture
cargo +stable test --offline --manifest-path doc/audit/zkp/agent-tools/p3-dft-view-tests/Cargo.toml --test view_reconstruction
```

0.4.2 の開発用依存と、0.5.3 の Circle／Mersenne を使う一部の開発用依存は offline cache にないため、そのテスト群は実行していない。全 SIMD target・WASM・compiler／unsafe refinement の網羅的な検証でもない。F1／F2／N>2 の F3 はソースに基づく指摘であり、今回の実行結果と区別する。

## 修正の優先順位

1. 現行 Regev に届く F1 の早期境界チェックを追加する。
2. 既存の binary MMCS・salt 長・DFT・NTT 修正を、対象ファイルと lockfile を含めてリリース管理に載せる。現時点では手元にあるだけで、HEAD に含まれない。
3. 汎用 MMCS で F2 と N>2 の F3 を閉じる。追加テストは正常 opening だけでなく、全行列が実際に commitment に結合していることを検証する。
4. RNG の用途分離、`eta` と公開 lookup 数の事前検証を行う。RNG の相関については修正または同時分布の安全性根拠が必要である。
