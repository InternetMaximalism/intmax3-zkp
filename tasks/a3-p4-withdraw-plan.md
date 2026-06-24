# A-3 P4 `withdraw` — 実装計画 + 脅威モデル

母艦: `tasks/a3-close-lifecycle-spec.md` / `tasks/a3-impl-todo.md` / `tasks/a3-p4-withdraw-handoff.md`.
決定(ユーザー承認済み): **Q1 = withdraw に全パイプライン内包**, **Q2 = ビルダは wallet_core**, **Q3 = anvil 含め全自動**。

## 0. ゴール(完了条件)
`channel_member withdraw <manager> [rpc]` が、実 channel の withdrawal 証明を生成し、
**registerChannel → deposit → postBlock×3(blob) → finalize → withdrawNative → pullChannelFunds** を
live(anvil)で通す。manager の L1 残高が増えることを assert。

## 1. アーキテクチャ確定事項(調査済み)
- `withdrawNative` は `finalizedStateRoots[extCommitment]` を要求(`IntmaxRollup.sol:1262`)。
  → withdrawal 証明の ext_commitment は **finalize 済み rollup root** 必須。
- finalize は **3 block(registration / deposit / withdrawal-tx)が postBlock 済み**である前提
  (`fullVerify` が `blockHashChainAt[finalBlockNumber]` と照合)。
- postBlock は **EIP-4844 blob tx**(`postBlockAndSubmit`、stake 1 ETH)。**forge script は blob 不可** →
  `cast send --blob --path <128KiB>` で送る(`docs/sepolia-smoke-runbook.md` 既存手順)。
- 権威ある on-chain シーケンス = `contracts/test/WithdrawNativeE2E.t.sol::_runLifecycleThroughFinalize`:
  1. `registerChannel(channelId,bpSlot,0,sphincs[],pkBs[],regev[],recipients[])`
  2. postBlock(block0=registration)  ← blob
  3. `deposit{value}(recipient,token,amount,aux)`(msg.sender == 証明された depositor)
  4. postBlock(block1=deposit)  ← blob
  5. postBlock(block2=withdrawal)  ← blob, この submissionId を finalize
  6. `finalize(subId, finalRoot, vpis, validityMle)`
  7. `withdrawNative(ws, prover, withdrawalMle)`
  8. `pullChannelFunds()`(manager が rollup.withdraw() を引く)
- 生成物 4 点(`generate_withdrawal_fixture.rs` が出力、`build_channel_withdrawal` が同一生成):
  `lifecycle.json` / `lifecycle_validity_mle.json` / `withdrawal_mle.json` / `withdrawal_payout.json`。

## 2. 実装ステップ
- [ ] **S1. wallet_core::build_channel_withdrawal** — `generate_withdrawal_fixture.rs` の全パイプライン
  (Phase1 registration → Phase2 deposit → Phase3 withdrawal-tx → Phase4 block-hash-chain + validity →
  wrap+MLE×2 → sanity re-fold → JSON 4 点組み立て)を `wallet_core.rs` に移設。
  - `ChannelWithdrawalParams { channel_id, deposit_amount, withdrawal_amount, depositor: Option<Address>,
    withdrawal_recipient: Option<Address> }`(None=従来 rng 由来=fixture parity 維持)。
  - 返り値 `ChannelWithdrawalArtifacts { lifecycle_json, validity_mle_json, withdrawal_mle_json, payout_json }`。
  - fixture 構造体(LifecycleFixture 等)を wallet_core へ移し、binary は文字列を書くだけ。
- [ ] **S2. generate_withdrawal_fixture.rs を委譲化** — env(WD_DEPOSITOR/WD_RECIPIENT/WD_OUT_PREFIX)読取り →
  `build_channel_withdrawal` 呼出し → 4 ファイル書込み。**出力は従来と byte 同一**。
- [x] **S3. parity 検証(完了・知見更新)** — **MLE/WHIR 証明は非決定的**(ZK blinding/masking;
  同一バイナリ 2 回で MLE バイト差分)。よって byte-parity は不可能=正しい検証基準ではない。
  実際に確認した正しい基準: **構造/意味フィールド(genesis/final state root, vpis, blocks, deposit,
  registration, withdrawal_payout の recipient/amount/nullifier/ext_commitment)が committed fixture と
  完全一致**(✓)+ ビルダ内部 self-verify(verify_mle_proof×2, single/chain/validity verify, keccak re-fold,
  ext_commitment 一致)が全 PASS(✓ バイナリ完走)。→ port は忠実。committed fixture は git checkout で復元済。
- [ ] **S4. self-verify テスト** — `wallet_core` に `#[cfg_attr(debug_assertions, ignore)] a3_channel_withdrawal_builds_and_verifies`:
  build → withdrawal proof self-verify + ext_commitment==validity final root + withdrawal keccak re-fold 一致。
  P2 各ビルダと同型。
- [ ] **S5. setup-backing の永続化追加** — `ChannelBacking` に `deposit_salt`, `depositor`, `deposit_recipient` を追加
  (depositor は既に live receipt から取得済=`channel_member.rs:360`)。`cmd_withdraw` が同一 deposit を再構築するため。
- [ ] **S6. cmd_withdraw** — 上記 on-chain シーケンスを cast/forge で駆動:
  - build_channel_withdrawal(channel の実 params + recipient=manager)→ 4 JSON 書込み → `sepolia_*` へ staging。
  - registerChannel / deposit / postBlock×3(`cast send --blob --path blob.bin`)/ finalize(forge RunClose finalizeStep)/
    withdrawNative(forge RunClose withdrawNativeStep 既存)/ `cast send <manager> pullChannelFunds()`。
  - dispatcher の `"withdraw" => cmd_close_lifecycle_unimplemented` を `cmd_withdraw` に置換。
- [ ] **S7. live 検証(anvil)** — fresh deploy + VK init(validity/withdrawal)+ register + withdraw 全行程 →
  manager 残高増 assert。`#[ignore]` + release。

## 3. 脅威モデル(attacker subagent 観点)
soundness は **全て in-circuit + on-chain**。CLI は配線のみ。攻撃面の確認:
1. **over/double-withdraw**: nullifier 使用済みマップ + `totalEscrowed` 減算 + `pendingWithdrawals` pull、
   `totalCreditedOut ≤ receivedChannelFunds`(manager 側大域上限)。CLI は値を選べない(payout は proof PI 由来)。✅既存 REAL。
2. **偽 ext_commitment**: `finalizedStateRoots[ext]` gate。finalize が validity MLE/WHIR + PI binding を検証。
   CLI が任意 root を渡しても finalize が落ちる(fail-closed)。✅
3. **改竄 withdrawal set**: withdrawNative が keccak re-fold で pis_hash 照合。amount 改竄→revert。✅(WithdrawNativeE2E で実証)。
4. **depositor 不一致**: deposit hash は msg.sender を folding。証明された depositor と on-chain msg.sender がズレると
   block2 hash 不一致→finalize revert。→ `cast send --private-key` の送信元 = 証明 depositor を保証(persist した depositor を使用)。
5. **registration 不一致**: registerChannel の member set が証明の registration block と不一致→block1 hash 不一致→finalize revert。
   → lifecycle.json の registration をそのまま registerChannel に渡す。
6. **fixture 競合**: withdraw/claim/close が `sepolia_*` に staging。**各 step 直前に書く**(順序厳守)。
7. **build_channel_withdrawal の port バグ**: S3 の byte-parity 検証で reference と一致を担保。差分=即停止。
8. **秘密鍵**: `.claude/priv` は読まず、`--private-key "$(cat …)"` で shell 展開のみ(該当時)。anvil は dev key。
9. **IntmaxRollup/Manager bytecode 不変**: 一切変更しない(CREATE2 drift→fixture 再生成回避)。

**不変条件チェック(完了前必須)**:
- [ ] withdrawal proof self-verify PASS、ext_commitment == validity final root、keccak re-fold 一致(S4)。
- [ ] build_channel_withdrawal が reference と byte 同一(S3)。
- [ ] cmd_withdraw が IntmaxRollup/Manager bytecode を変えない。
- [ ] live で withdrawNative + pullChannelFunds 成功、manager 残高増(S7)。

## 4. 所見ログ
- **S1–S2 完了**: `build_channel_withdrawal` を wallet_core に移設、`generate_withdrawal_fixture` 委譲化。compile OK。
- **S3 完了(知見)**: MLE/WHIR は ZK blinding で非決定的(同一バイナリ 2 回で MLE バイト差)。byte-parity 不可=誤った基準。
  正しい基準で確認: 構造/意味フィールド(state roots, vpis, blocks, deposit, registration, payout)= committed と一致 +
  内部 self-verify 全 PASS。記憶 [[project_mle_whir_nondeterministic]] に保存。
- **S4 完了**: `a3_channel_withdrawal_builds_and_verifies` PASS(94.8s)。amount==要求額、ext_commitment==final root。
- **S5 不要化**: 自己完結パイプライン(cmd_withdraw が自前 deposit、depositor=送信鍵)→ setup-backing 永続化不要。
- **S6 完了**: `cmd_withdraw` 実装、dispatcher 置換、unimplemented スタブ撤去。compile OK。
- **S7 完了(anvil live)**: DeployClose → `INTMAX_CHANNEL=1 ROLLUP=… channel_member withdraw <manager>`。
  結果: manager 0→3 ETH、pendingWithdrawals 3→0、totalEscrowed=7、receivedChannelFunds=3、finalizedBlock=3。**全不変条件 ✓。**

## 5. 完了サマリ
P4 `withdraw` 完成。close ライフサイクル全 CLI コマンド(close→settle→withdraw→claim)が live で一気通貫。
soundness は in-circuit + on-chain(CLI は配線のみ、payout は proof PI 由来で改竄不可、finalize/withdrawNative が
fail-closed gate)。残: P5(relay + 完全 close-lifecycle E2E、real channel deposit との統合)、P6(stub revert 化)。
