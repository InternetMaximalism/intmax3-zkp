# A-3 本実装 進捗トラッカ

仕様: `tasks/a3-close-lifecycle-spec.md`(承認済み・全スコープ)
ブランチ: `fix/audit-soundness-and-tests`(A-2 等と同ブランチ)

承認決定: ①on-chain anchor チェックあり ②全部実装 ③liveness grief は明記のみ

## P1 — 実 L1-close anchor ✅
- [x] 脅威モデル(attacker subagent)— Threat 1-9 列挙。anchor は fund-safe(Option B)、real custody は既存 withdrawal gate(IntmaxRollup.sol:1262)が担保
- [x] PART A: `setup-backing` が `latestFinalizedStateRoot()` を取得→`ChannelBacking.intmax_state_root` に格納、placeholder 廃止、zero 時は警告(liveness 明記)。コンパイル OK
- [x] **PART B は不採用(ユーザー決定 A)**: EIP-170(IntmaxRollup margin 10B、getter ~70B 不可)+ 既存 withdrawal gate と冗長(資金安全に寄与せず)。→ Solidity 変更なし=close fixture 再生成不要、forge 全緑のまま
- [x] テスト回帰なし(setup-backing を駆動する自動テストは存在しない=relay/demo のみ live。anchor 動作確認は P5 E2E)
- 注: anchor 動作の live 確認は P5 の完全 E2E に委譲

## P2 — wallet_core close ビルダ
- [x] 脅威モデル(attacker subagent)— 下記「P2 精密設計」に結論を反映

### P2 精密設計(脅威モデル確定済み、実装ガイド)

**新規 `CloseProver`(wallet_core.rs、非テスト):**
```
pub struct CloseProver { single_sig: &'static SingleSigCircuit, list: ListCircuit, close_circuit: ChannelCloseCircuit<F,C,D> }
CloseProver::new(balance_vd: &VerifierCircuitData) -> Self   // list = ListCircuit::new(single_sig.vd); close = ChannelCloseCircuit::new(balance_vd, list.vd)
```
- `single_sig_circuit()`(L204, 既存共有)を流用。`list_circuit()` も共有 OnceLock 化可。

**`build_close_full_witness(state, member_keys[N], balance_proof, close_nonce, burn_tx_hash, snapshot_mbn) -> ChannelCloseFullWitness`:**
- close_tx = CloseWithdrawal{ channel_id, final_channel_state_digest=state.digest, final_balance_state_h1=state.balance_state.h1(), intmax_state_root=state.channel_fund.intmax_state_root, burn_tx_hash, burn_amount=state.channel_fund.amount, zkp=vec![] }
- close_intent = CloseIntent::new(close_nonce, &state, &close_tx, snapshot_mbn)?  ← **既に fail-closed 束縛検査内蔵**(channel_id/digest/h1/anchor/amount)
- member_auth + list_proof: 各 member_keys[i] で `single_sig.prove(signing_key, state.digest)` → `list.prove_append(&sig, list_commitment(pairs[0..i]), &prev)` を slot 順に fold(fixture::member_auth_for_digest_n と同型、実鍵版)
- **Rust fail-closed 前提(脅威モデル):** 2≤member_count≤MAX、member_keys.len()==member_count、state.digest 計算済み、h1 一致、unallocated_confirmed_incoming==0、pk_g 全 distinct、balance_proof の channel_id/settled_tx_chain が close PI と一致

**`prove_close(full_witness) -> close_proof` = close_circuit.prove(&w)**(member_set_commitment は prove が正値で上書き=tamper 不可)

**`prove_close_mle(close_proof) -> (mle_json, CloseProofFields)`** = WrapperCircuit + setup_mle_vk + prove_with_mle + export_mle_json(generate_close_fixture.rs と同手順)

**IN-CIRCUIT soundness(ビルダが迂回不可、脅威モデル確認済み):** H1/IMCH 再計算束縛、balance proof の channel_id/settled_tx_chain 束縛、ListCircuit C'==C(実署名)、member_set_commitment keccak、active_bits、member pk_g distinct。

**`build_withdrawal_claim(final_balance_state, member_index, regev_sk, recipient) -> claim+proof`:** amount は decryption_core で復号値に in-circuit 束縛(over-claim 不可)、regev pk は H1 commit に Poseidon 束縛。前提: member_index<active、復号 amount 一致、pk digest 一致。
**`build_cancel_close(revived_state, close_intent)` / `build_post_close_claim(...)`:** 同様に既存回路へ配線。

- [x] **CloseProver(new + build_full_witness + prove + close_vd)実装、実証明テストで検証 PASS(48.9s)**。build→prove→verify が通り、negative(鍵数不一致→Err)も。全 public 型を un-gate なしで使用、CloseIntent::new が binding を fail-closed 検査。
- [x] **prove_mle(WrapperCircuit + MLE export、generate_close_fixture 同手順)実装、コンパイル OK**(MLE self-verify 込み。ランタイム検証は P3 の close fixture 生成 or 専用テストで)
- [x] **build_withdrawal_claim(WithdrawalClaimProver)実装、実証明テスト PASS(14.3s)**。slot 復号→amount 導出、E-3 + claim 回路で証明・検証、amount==復号値(over-claim 不可)、padding slot 拒否。wrap+MLE は共有 `wrap_and_export_mle` ヘルパに切り出し(CloseProver も使用)。
- [x] **build_cancel_close(CancelCloseProver)実装、実証明テスト PASS(12.2s)**。revived state の IMCH に member 署名 + list fold、revived_version > close_version の前提を fail-closed、stale 状態 negative。
- [x] **build_post_close_claim(PostCloseClaimProver)実装、実証明テスト PASS(13.7s)**。source_tx から delta 抽出・復号、accumulator から inclusion proof、Stage-3 FullWitness 構築。**P2 全4ビルダ完了。**
- [x] **セキュリティレビュー(別 subagent、攻撃者視点)完了 — soundness 欠陥なし**。全5ビルダが検証済み fixture と field-by-field 一致、soundness は in-circuit、秘密鍵は適切スコープ、nullifier 正規導出、amount は復号由来。任意の防御的改善(必須でない、in-circuit で fail-closed):
  - (任意)CancelCloseProver に era-fence 早期チェック
  - (任意)PostCloseClaimProver に `incoming_tx_index < accumulator.len()` 早期チェック
  - (任意)WithdrawalClaim/PostClose の Regev pk 長/canonical 早期検証

### P2 検証済み(release専用 #[ignore] テスト)
- `a3_close_prover_builds_and_verifies_real_close_proof`(49s): 実 genesis state + 実 balance proof + 3 member 署名 → close 証明生成・検証。
- `a3_withdrawal_claim_prover_builds_and_verifies`(14s): slot0 が復号値 77 を主張・検証、padding slot negative。

## P3 — CLI close + cancel-close
- [x] **`cmd_close <manager> [rpc]` 実装(コンパイル OK)**: load_state + N member 鍵 + balance proof → 検証済み CloseProver で close 証明 + MLE 生成 → `close_intent.json`/`close_intent_mle.json` 出力(generate_close_fixture と同スキーマ、実状態版)→ requestClose(cast)+ submitCloseIntent(RunClose forge step、large calldata)。共署名集約 = CLI 制御 member 全鍵で署名。
  - 生成は検証済み CloseProver を使用。live(deploy+VK init 要)検証は P5 E2E。
- [ ] `cancel-close` 実装
- [ ] anvil で requestClose→submitCloseIntent 確認(P5 E2E)

## P4 — settle + withdraw + claim
- [x] **`settle <manager> [rpc]` 実装(コンパイル OK)**: finalizeClose()(証明不要)を cast。close→Closed 遷移。
- [x] **`claim <manager> <member_slot> [rpc]` 実装(Rust + Solidity コンパイル OK)**: close 再構築 → 検証済み WithdrawalClaimProver で withdrawal-claim MLE + descriptor 生成(amount は復号由来=over-claim 不可)→ RunClose に**動作する `submitWithdrawalClaimStep` を新規追加** → forge submit → claimWithdrawalCredit。env: CLAIM_RECIPIENT + CLOSE_* は close と一致必須。live は P5。
- [x] **`withdraw` 完成(全パイプライン内包・anvil live 検証済)** — 決定: Q1=全パイプライン内包 / Q2=ビルダは wallet_core / Q3=anvil 含め全自動。計画+脅威モデルは `tasks/a3-p4-withdraw-plan.md`。
  - **wallet_core::build_channel_withdrawal**(`ChannelWithdrawalParams`/`ChannelWithdrawalArtifacts`)= `generate_withdrawal_fixture` の全パイプライン(registration→deposit→withdrawal-tx の 3-block 再構築 + balance/single_withdrawal/chain/validity 証明 + wrap+MLE×2 + keccak re-fold + ext_commitment 一致 sanity)を移設。**generate_withdrawal_fixture は委譲化**(1 source of truth)。
  - **知見**: MLE/WHIR 証明は ZK blinding で **非決定的** → byte-parity 不可。検証は意味的(構造フィールド=committed と一致 + 内部 self-verify + on-chain VK 検証)。記憶 [[project_mle_whir_nondeterministic]]。
  - **release self-verify テスト** `a3_channel_withdrawal_builds_and_verifies`(94.8s PASS): build→全 proof self-verify、payout amount==要求額(over-claim 不可)、ext_commitment==final state root。
  - **cmd_withdraw**(`channel_member withdraw <manager> [rpc]`)= build → register(済なら skip)→ deposit(送信元=depositor)→ postBlock×3(`cast send --blob`)→ finalize(forge RunClose, SUB_ID=base+2)→ withdrawNative(forge RunClose)→ pullChannelFunds(cast)。dispatcher 置換 + `cmd_close_lifecycle_unimplemented` 撤去(全コマンド実装済)。
- [x] **anvil で実 ETH 受領 — 検証済**: DeployClose で deploy → `INTMAX_CHANNEL=1 ROLLUP=… channel_member withdraw <manager>` 完走。manager balance 0→3、pendingWithdrawals 3→0(pull 済)、totalEscrowed=7(=10-3)、receivedChannelFunds=3、latestFinalizedBlockNumber=3。**close→settle→withdraw→claim が CLI で一気通貫可能に。**

## P5 — relay + 完全 E2E
- [x] **P5-A `/api/close|settle|withdraw|claim`(完了)**: `wallet/wallet-relay.js` + `wallet-relay-ec2.js` に追加
  (`/api/inter/send` と同型、thin wrapper)。manager を body で受け、rollup は channel_backing.json、RPC は
  local=localhost:8545 / ec2=`process.env.RPC`。close は CLOSE_SV、claim は CLAIM_RECIPIENT、withdraw は ROLLUP を env で渡す。node --check 緑。
- [x] **P5-B 統合コア(完了・unit+heavy 検証済)**: ユーザー決定=フル統合。`build_channel_withdrawal` を
  **チャネルの実 member 鍵 + 実 deposit salt** に束縛できるよう拡張(新引数 `cli_member_keys: Option<&[MemberKeys]>`、
  params に `deposit_salt: Option<Salt>`)。`Some` 時は `ChannelMemberKeys::from_member_keys` +
  `add_channel_registration_keys` で**実 member で登録**、deposit salt も実値 → 1 つの on-chain registration + deposit が
  close/withdraw 両方に使える。`None` は従来(fixture parity)。`ChannelBacking` に `deposit_salt` 永続化(S5、`setup-backing`)。
  `cmd_withdraw` に **integrated 分岐**(backing 有→実 member + 実 deposit、deposit は setup-backing 済なので**再 deposit せず**
  block だけ post / backing 無→従来 standalone)。
  - **検証**: 高速 unit `a3_withdraw_registration_matches_close_member_set`(proving 無し)= withdraw registration の
    member-set commitment が close 経路の `close_member_set_commitment(pk_gs)` と**完全一致**(=1 registration が両立する証明)。
    heavy `a3_channel_withdrawal_builds_and_verifies`(95.6s)= 実 member で全 proof self-verify + registration が CLI member の
    pk_g を emit。両 PASS。full build 緑。
- [~] **P5-B live E2E(着手・2 つの narrow gap で停止)**: ツール完成 — `channel_member export-reg-record`(高速・CLI member
  reg record 出力)+ `contracts/script/DeployCloseCli.s.sol`(CLI member で registerChannel + manager binding + validity/
  withdrawal/close VK init)。anvil で deploy(CLI members)→ setup-backing(deposit 140M・deposit_salt 永続)→ **integrated
  withdraw** を駆動。**判明した残課題2件(どちらも hack せず escalate)**:
  1. **(訂正)close 経路 freeze-nonce は誤診=健全**: `CloseIntent::new`(channel.rs:763)が
     `close_freeze_nonce = state.close_freeze_nonce + 1` を計算し、回路も `pis = state+1` を強制。genesis(0)→ intent(1)、
     requestClose 後の manager(1)と**一致**。`CloseLifecycleE2E` の close-intent skip は **freeze ではなく member-set 不一致**が
     主因で、**本統合(CLI member 統一)が解消**。**ただし別の本物のギャップ**: `cmd_close` は `requestClose()` 直後に
     `submitCloseIntent` を呼ぶが、後者は `GRACE_BEFORE_PROCESS_SECS=600` 経過を要求 → 実チェーンで `GracePeriodNotElapsed`。
     `cmd_close` を request/submit に分割 or E2E で `evm_increaseTime`(soundness 非該当=配線)。
  2. **integrated withdraw の deposit/registration folding 不一致(本物・真因)**: オンチェーンは「`deposit()`/`registerChannel`
     で進んだ pending 連鎖を**最初に post するブロック**が吸収」する。standalone(withdraw が block1,2 を出してから deposit→block3 で
     吸収)は証明モデル(deposit は専用ブロック)と一致したが、integrated は **setup-backing の deposit が全ブロックより前から
     pending** なので **block1(registration)が deposit を吸収**→ 証明の「block2 で deposit」と構造的にズレ → 連鎖全体が不一致
     → `blockHashChainAt[3] ≠ final_block_chain` → finalize false。修正案A(推奨): integrated 時 `build_channel_withdrawal` の
     ブロック構造を「最初のブロックで registration＋deposit を両方折り込む」=オンチェーン吸収順に合わせる(`BlockWitnessGenerator`
     のブロック生成順の再構成。keystone は保つ)。
  → **統合コアは検証済**(member-set 共有 unit + 実 member proof の heavy self-verify)。live 全経路 = #2 案A 修正 + close の
     GRACE 配線。#2 は soundness 非該当(block-hash 整合)だが慎重なモデル再構成が要る。

### P5-B live 着手の進捗(案B採用・2026-06)
ユーザー決定=**案B**(setup-backing はオンチェーン入金せず、withdraw が標準版の順序で入金。証明/回路/ジェネレータ不変)。
実施済み・修正したバグ:
- **案B 実装**: `setup-backing` に `SETUP_BACKING_NO_ONCHAIN_DEPOSIT` モード(off-chain balance proof + params 永続のみ、
  デフォルト=従来どおり実 deposit=デモ不変)。`cmd_withdraw` は常に入金を作る(skip 撤去)。build OK。
- **close GRACE 配線(#1)**: `cmd_close` に `CLOSE_ADVANCE_TIME` で requestClose 後に `evm_increaseTime`。
- **close forge step 名バグ修正**: `cmd_close` が存在しない `submitCloseIntentStep()` を呼んでいた → 正しい `closeIntentStep()` に。
  (close-intent の live submit は今まで未実行だったため潜在していた。)
- **live ツール**: `channel_member export-reg-record`(CLI member の reg record 出力)+ `contracts/script/DeployCloseCli.s.sol`
  (CLI member で registerChannel + manager binding + validity/withdrawal/close VK init)。
- **anvil 検証で到達したところ**: deploy(CLI members)→ setup-backing(no-deposit)→ init → **close: 証明生成 + requestClose +
  grace 通過 + closeIntentStep 実行**まで到達。close 証明の **member_set_commitment / channel_id(7)/ close_freeze_nonce(1)
  はオンチェーンと一致**を確認(Rust↔Solidity の close_member_set_commitment も一致)。
- **#3 delegate_count 解決済**: init のチャネルは 3 members + 1 delegate。close 証明は delegate_count=1 を束縛するので、
  登録を **4-active(3 members + 1 delegate)** で統一: 生成器に `to_reg_record_split`/`add_channel_registration_keys_split`
  (member/delegate split)+ `from_member_keys` を全 active 対応に、`build_channel_withdrawal` は active 数から delegate_count を導出、
  `channel_member` に `cli_active_keys()`(3 members + delegate seed)、`export-reg-record` は 4-active 出力、`DeployCloseCli` は
  4-active registerChannel + manager の member/delegate bindings + **withdrawal-claim VK init** 追加。
- [x] **P5-B 完全 CLI E2E 成功(anvil・real proof・2026-06)** 🎉: `tests`/driver で
  deploy(DeployCloseCli)→ setup-backing(no-deposit)→ gen-contribution+init → **close**(submitCloseIntent OK=**初の live close 検証**)
  → evm_increaseTime → **settle**(channelStatus=Closed)→ **withdraw**(integrated: register skip + deposit + postBlock×3 + finalize OK
  + withdrawNative 140000000 + pullChannelFunds)→ **claim**(member slot 0 が実 ETH 40000000 受領, totalCreditedOut=40000000)。
  全行程グリーン。soundness は in-circuit + on-chain のまま(案B で deposit fold 整合、回路/コントラクト不変)。

## P6 — post-close-claim + stub revert 化 + 後始末
- [ ] post-close-claim CLI/relay(任意・未着手)
- [x] **P6-A specialClose / lateOutgoingDebit revert 化(完了・攻撃者レビュー GO)**: 両 entry を即 revert
  (`SpecialCloseDisabled`/`LateOutgoingDebitDisabled`、`external pure`、selector 維持)。影響テスト 3 件を
  disabled→revert に置換(Manager 全 66 PASS)。Manager bytecode 変更 → 新 CREATE2 manager
  `0xED5e1c64…1A8FA8`、close_ fixture 再生成、CloseLifecycleE2E PASS。詳細 `tasks/a3-p6a-stub-revert-plan.md`。
  dead-code 除去は deferred(detail2 §H-3 に明記)。
- [x] **fail-closed スタブ撤去・followup 更新(完了)**: `cmd_close_lifecycle_unimplemented` は P4 で撤去済。
  `tasks/a3-close-lifecycle-followup.md` を「ほぼ完了」に更新。detail2 §H-3「IMPLEMENTED」、
  detail2-implementation-notes.md に **D10**(§K-4 anchor on-chain チェック不採用=承認済み逸脱、C2/C3 disable)追記。

## 所見ログ
- (P1着手)
- **P5-B 統合ブロッカ(2026-06)**: withdraw 自己生成 registration と close の実 member registration が同一 channel で
  両立不可。完全 E2E には withdraw パイプラインを実 member/deposit へ束縛する拡張が必須(P4 先送り分)。ユーザーに提示。
