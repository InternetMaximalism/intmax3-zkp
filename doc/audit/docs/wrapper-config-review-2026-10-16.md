# Poseidon BN128 wrapper config レビュー — 2026-10-16

**P2 のデコード処理の問題を1件確認した。** 公開されている BN128 hash 型は、不正入力を通常のエラーとして返さず panic する。現行の本番 wrapper がこの設定を使う経路は見つからず、本番へのリモート DoS としての到達性は確認していない。

置換・定数・field の変換・固定長ハッシュ・Fiat–Shamir への接続では、新規の具体的な健全性の欠陥を確認しなかった。参照実装の定数512個と一致し、既存テスト6件が成功した。この結果はシステム全体の安全性の認定ではない。

## 対象とバージョン

ローカル `main` と、読み取り専用の `git ls-remote origin refs/heads/main` で確認したリモート main は、共に **`0a2f5a284c0ae6cf6d23e53b810240151e696724`**。対象は `src/wrapper_config` の5ファイル、計2706行で、HEAD との差分はない。

| ファイル | 確認した内容 |
| --- | --- |
| [mod.rs](/Users/andropov/repos/intmax3-zkp/src/wrapper_config/mod.rs:1) | 公開モジュール |
| [poseidon_bn128.rs](/Users/andropov/repos/intmax3-zkp/src/wrapper_config/poseidon_bn128.rs:33) | 置換、S-box、round 構成、密／疎行列の更新 |
| [poseidon_bn128_constants.rs](/Users/andropov/repos/intmax3-zkp/src/wrapper_config/poseidon_bn128_constants.rs:30) | C・S・M・P の全定数 |
| [plonky2_config.rs](/Users/andropov/repos/intmax3-zkp/src/wrapper_config/plonky2_config.rs:50) | hash・sponge・serde・Plonky2 の各 interface |
| [utils.rs](/Users/andropov/repos/intmax3-zkp/src/wrapper_config/utils.rs:27) | BN254 scalar field と byte representation |

Plonky2 submodule は `3a20a05fb99d2653c4d37debb4f1ead2f422dfb2`。対象と関連24ファイルの SHA256 は [source-manifest.json](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/wrapper-config-review-20261016/source-manifest.json) に保存した。製品コードは変更していない。既存の作業ツリー変更を維持し、テストは現在の Cargo patch／依存グラフで実行した。未変更の HEAD 全体を別 checkout でビルドした結果ではない。

settlement への接続を追う前に [sig-cluster と delegates の規則](/Users/andropov/repos/intmax3-zkp/doc/docs/sig-cluster-vs-delegates.md) を読んだ。今回、両者の加入規則を変更する提案はしていない。

## F1 — P2：不正な hash 表現のデコードで panic する

**位置：** [serde のデコード](/Users/andropov/repos/intmax3-zkp/src/wrapper_config/plonky2_config.rs:135)、[binary のデコード](/Users/andropov/repos/intmax3-zkp/src/wrapper_config/plonky2_config.rs:74)。

`PoseidonBN128HashOut::Deserialize` は `Result<Self, D::Error>` を返す interface だが、入力型の検査、10進文字列の解析、32 byte 配列への変換、canonical な `Fr` への変換をすべて `unwrap` する。文字列以外の JSON、不正な数値文字列、32 byte を超える整数、scalar modulus 以上の整数が panic になる。通常の `serde_json::from_str(...)?` では捕捉できない。

`GenericHashOut::from_bytes` も、入力長が32 byteでない場合、またはその整数が `Fr` の範囲外の場合に panic する。Plonky2 の [Read::read_hash](/Users/andropov/repos/intmax3-zkp/contracts/lib/polygon-plonky2/plonky2/src/util/serialization/mod.rs:257) は必要な byte 数を読んだ後、この関数を呼ぶため、非 canonical な32 byte値は外側の `IoResult` によるエラー処理を抜けて panic する。これは同じ入力境界の問題として1件に数える。

未変更の元ソースを直接取り込む補助プログラムで、次を再現した。

| 入力 | 実行結果 |
| --- | --- |
| JSON の10進文字列 `0`、`r-1` | 両方成功 |
| JSON の整数 `0`（文字列でない） | `Deserialize` 内で panic |
| JSON の文字列 `not-a-number` | 数値解析で panic |
| JSON の10進文字列 `r` | canonical field 変換で panic |
| 32 byte がすべて `0xff` の binary 値 | canonical field 変換で panic |

ここで `r=21888242871839275222246405745257275088548364400416034343698204186575808495617`。各ケースを別 subprocess で実行し、補助プログラムには明示的に `panic=abort` を指定したため、不正入力4件は SIGABRT になった。これは実アプリの panic 設定を測定した結果ではない。unwind 設定なら同じ箇所から panic が伝播し、別途 `catch_unwind` を置く利用側なら捕捉できる。[補助ソース](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/wrapper-config-review-20261016/decoder-probe/probe.rs) と [実行ログ](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/wrapper-config-review-20261016/decoder-probe/probe-results.log) を保存した。

**影響の条件：** この設定で外部の hash／proof を取り込み、panic を封じ込めない利用側では、タスクまたはプロセスを停止させ得る。ただし現在の repo 内には、その設定を使う本番入力経路がない。公開 library API を使う downstream caller や、今後この設定を再導入する際の問題として P2 とした。範囲外の値を mod r で還元して受理するわけではなく、第二表現や不正 proof の受理を示す問題ではない。

**修正方針：** serde の入力エラーは `?` で伝播し、数値・長さ・canonicality の失敗は `D::Error::custom` に変換する。binary 側の既存 trait は `Result` を返せないため、fallible な decode helper を用意し、外部 proof／hash を取り込む境界で canonicality を検査してから trait の処理へ渡す。現在の valid roundtrip テストに加えて、上記の拒否ケースが panic せずエラーになることを確認する。

## 置換と定数

[Fr の宣言](/Users/andropov/repos/intmax3-zkp/src/wrapper_config/utils.rs:27) は BN254 の scalar prime を使い、little-endian の canonical representation を持つ。BN254 の base field との取り違えはない。幅4・rate3・full round8・partial round56、`x^5`、行列の向き、定数を加える順序は、ソースが指定する固定 commit の [iden3 実装](https://github.com/iden3/go-iden3-crypto/blob/e5cf066b8be3da9a3df9544c65818df189fdbebe/poseidon/poseidon.go) と一致した。

round 構成は、初期 ARK `C[0..4)`、前半3 full round の `C[4..16)` と M、4回目の `C[16..20)` と P、56 partial round の `C[20..76)` と S、後半3 full round の `C[76..88)` と M、最後の S-box と M である。C の88個を各1回使用し、最後に余分な ARK を加えていない。

[密行列の計算](/Users/andropov/repos/intmax3-zkp/src/wrapper_config/poseidon_bn128.rs:119) は `out[i] = Σ matrix[j][i] * state[j]` を別配列に計算し、参照と同じ向きで更新する。[疎行列の計算](/Users/andropov/repos/intmax3-zkp/src/wrapper_config/poseidon_bn128.rs:94) は新しい state[0] を先に計算し、他の要素を旧 state[0] で更新した後に代入する。in-place 更新による上書き誤りは見つからない。

[参照の定数表](https://github.com/iden3/go-iden3-crypto/blob/e5cf066b8be3da9a3df9544c65818df189fdbebe/poseidon/constants.go) の width4 用の値と、C88個・S392個・M16個・P16個の**全512個**を整数として独立に照合した。各 index の重複・欠落がなく、全値が canonical な範囲にあり、一致した。さらに M の非空な正方小行列69個すべての行列式が非ゼロ、P と56個の疎行列が可逆、`gcd(5,r-1)=1` であることを確認した。

[照合スクリプト](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/wrapper-config-review-20261016/compare_constants.py)、[ログ](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/wrapper-config-review-20261016/constant-comparison.log)、[参照ソースの URL／SHA256](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/wrapper-config-review-20261016/reference-provenance.json) を保存した。これらは実装の対応と代数的な必要条件の検査であり、round 数に対する新たな暗号解析ではない。

## field 変換、hash、transcript

- **入力 packing：** Goldilocks の canonical u64 を最大3個ずつ little-endian に連結する。最大192 bitで `r` より小さく、mod r への還元や情報落ちはない。1 permutation に最大9個の Goldilocks 要素を吸収する。
- **短い入力：** [hash_or_noop](/Users/andropov/repos/intmax3-zkp/src/wrapper_config/plonky2_config.rs:203) は最大3要素だけを直接格納する。32 byteという hash 長から4要素を許す upstream のデフォルトを使っていないため、任意の256-bit 値を `Fr` に入れる誤りを避けている。
- **digest の field 化：** [to_vec](/Users/andropov/repos/intmax3-zkp/src/wrapper_config/plonky2_config.rs:85) は32 byteを7 byteずつ、固定の5個の Goldilocks 要素に変換する。各 limb は56 bit以下なので p 未満となり、digest 全体を単射的に保持する。Merkle cap の flatten と challenger はこの5要素をすべて使う。
- **Merkle 圧縮：** [two_to_one](/Users/andropov/repos/intmax3-zkp/src/wrapper_config/plonky2_config.rs:216) は `[0,0,left,right]` を permute する。左右の完全な Fr 値を使い、192 bitに切り詰めない。
- **padding：** [hash_pad](/Users/andropov/repos/intmax3-zkp/src/wrapper_config/plonky2_config.rs:193) は `1,0...,1` を加え、Goldilocks 要素数を9の倍数にする。BN128 sponge の rate に対応している。

`hash_no_pad` には、長さの異なる入力を末尾ゼロで同一視し得る性質がある。ただし pinned [Hasher の契約](/Users/andropov/repos/intmax3-zkp/contracts/lib/polygon-plonky2/plonky2/src/plonk/config.rs:46) は、固定長入力に対する collision resistance として明示されている。これは任意長のメッセージ用の prefix-free hash ではない。FRI verifier は Merkle opening の前に [leaf 幅・path 深さ・reduction arity](/Users/andropov/repos/intmax3-zkp/contracts/lib/polygon-plonky2/plonky2/src/fri/validate_shape.rs:53) を検査するため、異なる長さのゼロ拡張だけを、その verifier に対する不正 opening と判断していない。

この設定の commitment hash は BN128 だが、Fiat–Shamir の permutation は Goldilocks Poseidon である。実際の [get_challenges](/Users/andropov/repos/intmax3-zkp/contracts/lib/polygon-plonky2/plonky2/src/plonk/get_challenges.rs:41) は `Challenger<F,C::Hasher>` を作り、Hasher が指定する `PoseidonPermutation<F>` を使う。[observe_hash](/Users/andropov/repos/intmax3-zkp/contracts/lib/polygon-plonky2/plonky2/src/iop/challenger.rs:72) は上記の5要素をすべて吸収する。`InnerHasher=PoseidonHash` は public input の hash などに使われる。これらの役割を区別して確認し、prover／verifier 間の不一致や digest の切捨ては見つからなかった。

## 現行の wrapper と onchain 経路

このモジュールは native の outer hash config であり、BN128 を Goldilocks 回路内で計算する non-native gadget や `AlgebraicHasher` 実装は含まない。repo 内の BN128 型の使用はモジュール内部とテストに限られ、[lib.rs](/Users/andropov/repos/intmax3-zkp/src/lib.rs:50) から公開はされている。[参照検索結果](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/wrapper-config-review-20261016/caller-search.txt) を保存した。

一般の [WrapperCircuit](/Users/andropov/repos/intmax3-zkp/src/utils/wrapper.rs:36) は明示された config で inner proof を検証し、その public input をそのまま公開する。BN128 config を自動選択しない。現在は [wallet_core の C](/Users/andropov/repos/intmax3-zkp/src/wallet_core.rs:144) が `PoseidonGoldilocksConfig` で、[validity service](/Users/andropov/repos/intmax3-zkp/src/validity_prover_service.rs:1015) は `WrapperCircuit<F,C,C,D>` の検証後、同じ回路から MLE proof を生成・検証・export する。

[契約の検証箇所](/Users/andropov/repos/intmax3-zkp/contracts/src/IntmaxRollup.sol:2019) も、固定された `IPinnedMleVerifierV2` の compact proof 検証と public input hash の結合を使う。BN128 hash の10進 serde をそこで呼ばない。この調査は F1 の到達性を確かめるための経路確認であり、MLE／契約全体の再監査ではない。

[mle_onchain_e2e.rs の説明](/Users/andropov/repos/intmax3-zkp/tests/mle_onchain_e2e.rs:8) には2段の BN128 wrap という古い記述があるが、[実際の generator](/Users/andropov/repos/intmax3-zkp/src/bin/generate_e2e_fixture.rs:116) は通常の Poseidon の wrapper を1段使う。`--skip-groth16` も歴史的な no-op で、現行 checkout に gnark verifier の実行経路は見つからない。説明の更新点として扱い、それだけで bypass と判断していない。

## 実行結果と限界

固定 nightly `rustc 1.87.0-nightly (b48576b4d 2025-03-22)` で次を実行し、**6 passed、0 failed、0 ignored** となった。

```sh
/Users/andropov/.cargo/bin/cargo test --offline --release --locked --lib wrapper_config:: -- --test-threads=1
```

内訳は byte roundtrip、serde roundtrip、置換の既知ベクトル4組を検証する1テスト、Merkle の通常 cap／全深さ cap／過大 cap の3テストである。過大 cap のテストは期待された panic で成功する。各テスト名とログは [test-results.json](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/wrapper-config-review-20261016/test-results.json) と同じディレクトリに保存した。補助デコーダの正常2ケース・panic4ケース、および定数照合は、この6件とは別の確認として記録した。

本レビューは Poseidon の暗号解析、全再帰証明の形式証明、削除済み gnark verifier との実行比較を含まない。前回 Falcon レビューの cyclic VK 結合漏れは [既報 F1](/Users/andropov/repos/intmax3-zkp/doc/audit/docs/falcon-soundness-review-2026-10-16.md:21) に残り、今回の wrapper config の検査で解決したとは扱わない。
