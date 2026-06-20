# A-3 P4 完成ハンドオフ: CLI `withdraw`(channel funds を rollup → manager へ)

このファイルだけで次スレッドが `withdraw` を実装できるよう、文脈・設計・落とし穴・検証を自己完結で書く。

## 0. 前提(これまでの到達点)
ブランチ `fix/audit-soundness-and-tests`。`tasks/a3-impl-todo.md` と `tasks/a3-close-lifecycle-spec.md` が母艦。
- **P2 完了・検証済み**: `src/wallet_core.rs` に `CloseProver` / `WithdrawalClaimProver` / `CancelCloseProver` / `PostCloseClaimProver`(全て実証明テスト PASS + 独立セキュリティレビュー済み)。
- **P3/P4 配線済み**: `src/bin/channel_member.rs` に `cmd_close`(P3)/ `cmd_settle` / `cmd_claim`(P4)。`contracts/script/RunClose.s.sol` に `submitCloseIntentStep` / `submitWithdrawalClaimStep`(新規追加済み)/ `withdrawNativeStep`(既存)。
- **唯一の欠落 = `withdraw`**。これが無いと `claim` 時点で manager に資金が無い。

## 1. ゴール
`channel_member withdraw <manager_addr> [rpc_url]`:
1. channel の実 deposit に対する **withdrawal 証明**(recipient = manager)を生成(wrap + MLE)。
2. `IntmaxRollup.withdrawNative(ws, prover, mleProof)` で manager の `pendingWithdrawals` を満たす。
3. `ChannelSettlementManager.pullChannelFunds()` で manager に資金を引き込む。

→ その後 `claim` で member に分配。

## 2. なぜ大仕事か(再スコープの根拠)
withdrawal 証明は close 系回路ではなく **rollup の withdrawal サブシステム**。`src/bin/generate_withdrawal_fixture.rs`(~700行)が雛形で、必要なのは:
- `BalanceProcessor` + `BalanceWitnessGenerator`(`src/circuits/test_utils/balance_witness_generator.rs`)
- `BlockWitnessGenerator`(rollup の block 状態 = どの deposit/block か)
- `balance_witness_generator.single_withdrawal_witness(&single_withdrawal_data)` → `single_withdrawal_circuit.prove(...)`
- `WithdrawalProcessor`(`prove_step` → `prove_final(&chain_proof, prover, &ext_public_state)`)
- `ext_public_state`(= `block_witness_generator.current_extended_public_state()` 系。`.commitment()` が withdrawNative の `ext_public_state_commitment` PI に一致せねばならない)
- 出力: 最終 withdrawal 証明 → `WrapperCircuit` + MLE(`wallet_core::wrap_and_export_mle` を流用可)→ `withdrawal_mle.json` + payout(`Withdrawal` struct)

**核心の制約(SECURITY)**: withdrawNative は `if (!finalizedStateRoots[extCommitment]) revert`(`IntmaxRollup.sol:1262`)。つまり withdrawal 証明の `ext_public_state_commitment` は **rollup が finalize 済みの state root** でなければならない。よって channel の deposit を含む block が finalize されている必要がある(P1 の anchor/liveness と同じ前提)。

## 3. 設計(2案、A 推奨)

### 案A(推奨): setup-backing の witness-generator 文脈を再構築して withdraw で使う
`setup-backing`(`channel_member.rs:cmd_setup_backing`)は既に real deposit を行い、`BalanceWitnessGenerator` に deposit witness を入れて balance proof を作っている。同じ deposit パラメータ(channel_id, deposit_salt, recipient, amount)を `ChannelBacking` 等に**永続化**し、`withdraw` で同じ block/witness 文脈を**決定的に再構築**して single_withdrawal_witness を作る。
- 必要な追加永続化: deposit_salt(現状未保存), deposit の block 文脈。`ChannelBacking` に `deposit_salt` 等を追加。
- 利点: 実 deposit に正しく束縛。欠点: block witness の再構築ロジックを generate_withdrawal_fixture から移植。

### 案B: `build_channel_withdrawal` を wallet_core に新設
`generate_withdrawal_fixture` の Step(single_withdrawal → chain → final → wrap+MLE)を `wallet_core` の builder 関数に括り出し、`withdraw` から呼ぶ。入力は (deposit 文脈, recipient=manager, finalized_root)。P2 builder と同じ流儀(fail-closed 前提 + 検証済みテスト)。
- 利点: 再利用可能・テストしやすい。欠点: deposit/block 文脈の引き回しが重い。

**どちらでも generate_withdrawal_fixture が唯一の正解実装**。まずそれを `cargo run --release --bin generate_withdrawal_fixture` で動かし、Step ごとに理解 → 移植。

## 4. 実装手順(具体)
1. `generate_withdrawal_fixture.rs` を読み、withdrawal 証明生成の最小経路を抽出(`fn main` 209行〜、single_withdrawal_witness 452行、prove_step/prove_final 466-487行、ext_public_state 480行、wrap+MLE 出力)。
2. wallet_core に `WithdrawalProver`(または `build_channel_withdrawal`)を追加。`wrap_and_export_mle` を MLE に流用。WD_RECIPIENT に相当する recipient=manager を引数化。
3. `channel_member.rs` に `cmd_withdraw`:
   - args: `<manager> [rpc]`。manager の 20byte → `calculate_recipient_from_address`。
   - deposit 文脈を案A/Bで取得 → withdrawal 証明 + MLE 生成 → `withdrawal_mle.json` + `withdrawal_payout.json` を書く(`cmd_claim` の staging パターンに倣い `contracts/test/data/sepolia_withdrawal_mle.json` / `sepolia_withdrawal_payout.json` へ copy)。
   - `forge script RunClose --sig withdrawNativeStep()`(既存、ROLLUP/MANAGER env)→ 続けて `cast send <manager> pullChannelFunds()`。
   - dispatcher の `"withdraw" => cmd_close_lifecycle_unimplemented` を `cmd_withdraw` に置換。
4. payout 形式: `RunClose._payout()` が読む `sepolia_withdrawal_payout.json` の `Withdrawal` 構造(recipient, amount, …)に合わせる。`generate_withdrawal_fixture` の payout 出力(700行付近)を参照。

## 5. 検証
- **単体(release, heavy)**: `wallet_core` に `a3_withdrawal_prover_builds_and_verifies` 相当を追加し、deposit→withdrawal 証明→`single_withdrawal_circuit.data.verify` で self-verify(P2 の各テストと同型、`#[cfg_attr(debug_assertions, ignore)]`)。
- **live は P5 E2E**(下記計画書): anvil で deposit→finalize→withdrawNative→pullChannelFunds→`pendingWithdrawals[manager]` と manager 残高を assert。

## 6. 落とし穴
- **ext_commitment は finalize 済み root 必須**。E2E は deposit を含む block を必ず finalize してから withdraw。
- **fixture 競合**: `withdraw`/`claim`/`close` が `contracts/test/data/sepolia_*` に staging する。E2E で順序・上書きに注意(各 step の直前に書く)。
- **IntmaxRollup を一切変更しない**: bytecode 変更 = manager CREATE2 アドレス drift = close fixture 再生成(A-2 で経験済み、metadata-hash 由来)。`withdraw` は IntmaxRollup を触らないので不要。
- 重い proving(分単位)。テストは `#[ignore]` + release、live は anvil で都度許可を取る。

## 7. 完了条件
`channel_member withdraw` が実 channel の withdrawal 証明を生成し withdrawNative + pullChannelFunds が通る。→ P4 完成(close→settle→withdraw→claim が CLI で一気通貫)。
