# gnark-plonky2-verifier 改修指示書 — Fraud Proof対応

## 背景

### 現状の問題

`gnark/main.go` の `FraudAwareVerifierCircuit.Define()` は以下のようになっている：

```go
verifierChip := verifier.NewVerifierChip(api, c.CommonCircuitData)
verifierChip.Verify(c.Proof, c.PublicInputs, c.VerifierOnlyCircuitData, c.CommonCircuitData)
api.AssertIsEqual(c.ExpectedResult, 1)
```

**問題点:**
1. `verifierChip.Verify()` は内部で `api.AssertIsEqual` を使って制約をかけている
2. 不正な証明を渡すと回路自体が充足不能（unsatisfiable）になり、Groth16証明が生成できない
3. つまり `ExpectedResult == 0`（fraud proof）のケースでは、Groth16証明を生成する方法がない
4. 現在のコードはコメントに「TODO」と書いてあるだけで、fraud pathは未実装

### 目標

**`ExpectedResult` が 0 でも 1 でも有効なGroth16証明を生成できるようにする。**

- `ExpectedResult == 1`: Plonky2証明が**正しい**ことのZK証明（finalize用）
- `ExpectedResult == 0`: Plonky2証明が**間違っている**ことのZK証明（fraud proof用）

---

## アーキテクチャ

### Plonky2検証の構造

Plonky2（PLONK + FRI）の検証は以下のステップからなる：

1. **Public input hash計算** — public inputsのハッシュを計算
2. **Challenges生成** — Fiat-Shamir transcriptから `beta, gamma, alpha, zeta` を導出
3. **Opening値の確認** — `zeta` での多項式評価値が proof.openings に含まれている
4. **Constraint polynomial check** — PLONK制約多項式が `zeta` で `0` に評価されることを確認:
   ```
   constraint_residual = vanishing_poly(zeta) * quotient(zeta) - constraint_evaluation
   assert constraint_residual == 0
   ```
5. **FRI検証** — コミットされた多項式が低次であることの検証

### 改修アプローチ: `Verify` を `VerifyWithResult` に分岐

`succinctlabs/gnark-plonky2-verifier` をforkし、`Verify()` と並行して `VerifyAndReturnResult()` を実装する。

```go
// 現在の Verify() — Assert で制約。成功時のみ充足可能。
func (v *VerifierChip) Verify(proof, pis, vd, cd) {
    // ... 内部で api.AssertIsEqual を多用
}

// 新規: VerifyAndReturnResult() — Assert の代わりに IsEqual で比較し、
// 全チェックの AND を boolean として返す。
func (v *VerifierChip) VerifyAndReturnResult(proof, pis, vd, cd) frontend.Variable {
    // 各ステップで api.IsEqual() を使い、結果を accumulate
    // return allChecksPass (0 or 1)
}
```

### ラッパー回路の改修

```go
func (c *FraudAwareVerifierCircuit) Define(api frontend.API) error {
    api.AssertIsBoolean(c.ExpectedResult)

    verifierChip := verifier.NewVerifierChip(api, c.CommonCircuitData)
    result := verifierChip.VerifyAndReturnResult(
        c.Proof, c.PublicInputs, c.VerifierOnlyCircuitData, c.CommonCircuitData,
    )
    // result は 1 (valid) or 0 (invalid)

    // 核心の制約: 実際の検証結果 == 期待される結果
    api.AssertIsEqual(result, c.ExpectedResult)

    return nil
}
```

---

## 実装手順

### Phase 1: gnark-plonky2-verifier のフォーク

1. `github.com/succinctlabs/gnark-plonky2-verifier` をフォーク
2. `go.mod` の module path を `github.com/user名/gnark-plonky2-verifier` に変更
3. `gnark/go.mod` の依存を fork に向ける

### Phase 2: VerifyAndReturnResult の実装

fork先の `verifier/verifier.go` を改修する。

**核心: `api.AssertIsEqual(a, b)` → `api.IsEqual(a, b)` への変換**

gnark-plonky2-verifier の `Verify()` 内部で行われるすべての assert を特定し、それぞれを `IsEqual` に変換する。結果を `api.And()` で accumulate する。

#### 変換対象の Assert 一覧

gnark-plonky2-verifier のコードを読み、以下のカテゴリの Assert を全て特定する：

1. **Public input hash check**
   ```go
   // Before:
   api.AssertIsEqual(computedHash, expectedHash)
   // After:
   check1 := api.IsEqual(computedHash, expectedHash)
   ```

2. **PLONK constraint evaluation check**
   ```go
   // Before:
   api.AssertIsEqual(constraintEval, 0)
   // After:
   check2 := api.IsEqual(constraintEval, 0)
   ```

3. **Permutation check (Z polynomial)**
   ```go
   // Before:
   api.AssertIsEqual(zCheck, 0)
   // After:
   check3 := api.IsEqual(zCheck, 0)
   ```

4. **FRI consistency checks**
   ```go
   // Before:
   api.AssertIsEqual(friEval, expectedEval)
   // After:
   check4 := api.IsEqual(friEval, expectedEval)
   ```

5. **Merkle cap verification**
   ```go
   // Before:
   api.AssertIsEqual(computedRoot, expectedRoot)
   // After:
   check5 := api.IsEqual(computedRoot, expectedRoot)
   ```

#### 実装パターン

```go
func (v *VerifierChip) VerifyAndReturnResult(
    proof variables.Proof,
    publicInputs variables.PublicInputs,
    verifierData variables.VerifierOnlyCircuitData,
    commonData types.CommonCircuitData,
) frontend.Variable {
    allPass := v.api.Constant(1) // 初期値: true

    // 1. Public input hash
    computedPIHash := v.computePublicInputHash(publicInputs)
    expectedPIHash := v.deriveExpectedPIHash(proof)
    piCheck := v.api.IsEqual(computedPIHash, expectedPIHash)
    allPass = v.api.And(allPass, piCheck)

    // 2. Challenges (Fiat-Shamir) — これは assert ではなく計算なので変更不要
    challenges := v.deriveChallenges(proof, publicInputs, verifierData)

    // 3. Constraint polynomial at zeta
    constraintEval := v.evaluateConstraints(proof, challenges, commonData)
    constraintCheck := v.api.IsEqual(constraintEval, 0)
    allPass = v.api.And(allPass, constraintCheck)

    // 4. Permutation argument
    permCheck := v.checkPermutation(proof, challenges, commonData)
    allPass = v.api.And(allPass, permCheck)

    // 5. FRI verification
    friCheck := v.verifyFRI(proof, challenges, commonData)
    allPass = v.api.And(allPass, friCheck)

    return allPass // 1 = all checks passed, 0 = at least one failed
}
```

**重要な注意:**
- `api.And(a, b)` は gnark の standard API で、ブール値の AND を返す
- `api.IsEqual(a, b)` は `a == b` なら `1`、そうでなければ `0` を返す
- FRI検証内部に多数のAssertがある。**全て**を変換する必要がある
- 変換漏れがあると、invalid proof で回路が unsatisfiable になり fraud proof が生成できない

### Phase 3: 既存テストの維持

fork後も `ExpectedResult == 1` のケースが従来と同じ動作をすることを確認する。

```go
// テスト: valid proof + ExpectedResult=1 → Groth16証明生成成功
func TestValidityProof(t *testing.T) { ... }

// テスト: invalid proof + ExpectedResult=0 → Groth16証明生成成功
func TestFraudProof(t *testing.T) { ... }

// テスト: valid proof + ExpectedResult=0 → Groth16証明生成失敗（unsatisfiable）
func TestValidProofWithFraudExpected_Fails(t *testing.T) { ... }

// テスト: invalid proof + ExpectedResult=1 → Groth16証明生成失敗（unsatisfiable）
func TestInvalidProofWithValidExpected_Fails(t *testing.T) { ... }
```

### Phase 4: gnark/main.go の更新

```go
func (c *FraudAwareVerifierCircuit) Define(api frontend.API) error {
    api.AssertIsBoolean(c.ExpectedResult)

    verifierChip := verifier.NewVerifierChip(api, c.CommonCircuitData)
    result := verifierChip.VerifyAndReturnResult(
        c.Proof, c.PublicInputs,
        c.VerifierOnlyCircuitData, c.CommonCircuitData,
    )

    // 核心: 実検証結果 == 期待結果
    api.AssertIsEqual(result, c.ExpectedResult)
    return nil
}
```

### Phase 5: Solidity側の更新

`IntmaxRollup.sol` の `_fullVerify()` は既に `expected_result` を区別する構造になっている。
Groth16 の public inputs に `ExpectedResult` が含まれるようになるため、
on-chain verifier が `pubInputs[last]` を `expected_result` として解釈するよう確認する。

```solidity
// Groth16 public inputs の末尾が ExpectedResult
uint256 groth16ExpectedResult = groth16.pubInputs[groth16.pubInputs.length - 1];
// finalize(): groth16ExpectedResult == 1 を確認
// fraudProof(): groth16ExpectedResult == 0 を確認
```

---

## gnark-plonky2-verifier の内部構造（参考）

### 依存関係

```
github.com/succinctlabs/gnark-plonky2-verifier v0.1.0
├── verifier/verifier.go     ← Verify() のメインロジック
├── verifier/fri.go          ← FRI検証
├── verifier/plonk.go        ← PLONK制約評価
├── variables/                ← Proof, PublicInputs 等の型定義
└── types/                   ← CommonCircuitData 等の構造体
```

### 改修が必要なファイル（推定）

| ファイル | 変更内容 |
|---|---|
| `verifier/verifier.go` | `VerifyAndReturnResult()` の新規追加。`Verify()` はそのまま残す（後方互換） |
| `verifier/plonk.go` | PLONK制約チェックの `Assert` → `IsEqual` 変換 |
| `verifier/fri.go` | FRI検証の `Assert` → `IsEqual` 変換 |
| `verifier/hash.go` | ハッシュ比較の `Assert` → `IsEqual` 変換（該当する場合） |

---

## 制約数への影響

`api.IsEqual(a, b)` は内部的に `1 - (a-b) * inv(a-b)` のような計算を行うため、
`api.AssertIsEqual(a, b)` （`a - b == 0` の1制約）より制約数が増える。

**見積もり:**
- 現在の回路制約数: `cs.GetNbConstraints()` で確認（ログに出力済み）
- IsEqual変換後: 各Assert箇所につき +2〜3制約
- Assert箇所が仮に100個なら: +200〜300制約の増加
- Groth16 proving time への影響: 微小（全体が数百万制約のオーダーなら無視できる）

---

## テスト方法

### 1. valid proof → ExpectedResult=1

```bash
./gnark-wrapper --data ./test_data --expected-result 1 --out valid.json
# → Groth16証明生成成功
```

### 2. invalid proof → ExpectedResult=0

テスト用の不正proofを生成する方法：
- `proof_with_public_inputs.json` の openings 値を1つ改竄する
- 例: `"openings"` 内の最初の値に `+1` する

```bash
# まず正しいproofデータをコピーして改竄
cp -r ./test_data ./test_data_bad
# proof_with_public_inputs.json の openings を手動で改竄
./gnark-wrapper --data ./test_data_bad --expected-result 0 --out fraud.json
# → Groth16証明生成成功（fraudの証明）
```

### 3. 矛盾ケースの確認

```bash
# valid proof + ExpectedResult=0 → 失敗するはず
./gnark-wrapper --data ./test_data --expected-result 0 --out should_fail.json
# → "Prove error: ..." で終了

# invalid proof + ExpectedResult=1 → 失敗するはず
./gnark-wrapper --data ./test_data_bad --expected-result 1 --out should_fail.json
# → "Prove error: ..." で終了
```

---

## チェックリスト

- [ ] gnark-plonky2-verifier をフォーク
- [ ] `Verify()` 内の全 `AssertIsEqual` / `AssertIsLessOrEqual` 等を特定・リスト化
- [ ] `VerifyAndReturnResult()` を実装（全Assertを IsEqual + And に変換）
- [ ] `Verify()` は後方互換のためそのまま残す
- [ ] 既存テストが `ExpectedResult=1` で通ることを確認
- [ ] invalid proof + `ExpectedResult=0` でGroth16証明が生成できることを確認
- [ ] valid proof + `ExpectedResult=0` でGroth16証明生成が**失敗**することを確認
- [ ] invalid proof + `ExpectedResult=1` でGroth16証明生成が**失敗**することを確認
- [ ] `gnark/go.mod` をfork先に向ける
- [ ] `gnark/main.go` を `VerifyAndReturnResult` に切り替え
- [ ] IntmaxRollup.sol で `pubInputs` から `ExpectedResult` を検証するロジック追加
- [ ] E2Eテスト: Rust → gnark-wrapper → Groth16 proof → Solidity verify
