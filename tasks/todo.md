# Task: 実 payment channel 化（ハリボテ全廃）— 実 ETH エスクロー + 実 on-chain settlement + 価値移転

Status: IN PROGRESS — ユーザー指示「ハリボテ全部直す・実 payment channel で送金→close・再デプロイ」。
Option A（memory project_channel_close_unification）: channel close = 実 base-intmax L1 native withdrawal、
latestFinalizedStateRoot に束縛、native payout + nullifier。設計調査完了（design ii-b 採用）。

## アーキテクチャ決定（design ii-b、調査確定）
- **出金は ext-commitment 内に無い**（ext_public_state.rs:38-47 に withdrawal root 無し）。
- 既存 `WithdrawalCircuit`(withdrawal_circuit.rs:175) が `Withdrawal{recipient,token_index,amount,nullifier,aux_data}` を
  keccak `withdrawal_hash` chain に畳み、PI `ext_public_state_commitment` で **latestFinalizedStateRoot に束縛済み**。
- → これを**共有 MleVerifier で検証**（withdrawal 用 VK を別途 IntmaxRollup に保持、verify は VK を引数で渡す形）。
  L1 で keccak chain 再畳み込みして各 Withdrawal leaf を proof root に束縛 → nullifier + totalEscrowed underflow で payout。
- **validity VK 再生成は不要**（design i = ext-state に withdrawal root 追加は最も高コストなので回避）。
- EIP-170: 第2 verifier 契約は作らない（共有）。withdrawal VK も同 MleVerifier で。

## 非交渉の不変条件
- **cross-channel solvency（Σ payout ≤ 実 escrow）= 実 ZK 強制**。payout 額は検証済み withdrawal proof の amount PI（prover 申告ではない）。
  `totalEscrowed -= amount` の underflow revert が global guard。
- intra-channel split = 2者の署名 close intent + challenge window（full ZK でなくてよい、accepted）。

## 脅威モデル（attack → mitigation）
- (a) 過大出金/cross-channel theft → payout=検証済み proof の amount、totalEscrowed underflow revert、finalizedChannelFundAmount を非権威 hint に降格。
- (b) 二重出金/replay → rollup-level `withdrawalNullifierUsed[nullifier]`(既存 settled_transfer.nullifier())。manager-level は intra split 用に既存維持。CEI(check→set→pay)。
- (c) 偽造 close state → aggregate は proof で cap、intra は challenge+`_isNewer` strict 順序、member_set_commitment を登録集合に照合（verifyCloseIntent を実体化後）。
- (d) reentrancy → 全 ETH 移動関数 nonReentrant + CEI、pull-payment 優先。
- (e) escrow drift → deposit payable で `msg.value==amount`(ETH index)/`==0`(他)、totalEscrowed 単一 accumulator + underflow revert。
- (f) registerChannel/close front-run → one-time registration(既存) + manager 構築時 commitment 照合、payout recipient は proof PI で固定。
- (g) challenge/grace griefing → `_isNewer` strict `>`、challengeDeadline 固定、pull-payment で finalize ブロック不可。
- (h) 別 finalized root への replay → nullifier は root 非依存で一意、retain した root のみ受理。
- (i) manager 受領 ETH と finalizedChannelFundAmount の乖離 → 受領 msg.value から設定、intent.channelFundAmount は一致 check のみ。

## P3+P4 実行スペック（2026-06-14 調査確定）— close 実体化

決定（ユーザー）: P2 commit 済み（ae06923）→ P3+P4（close を実体化）。

### 現状（調査確定、file:line）
- `ChannelSettlementManager.claimWithdrawalCredit`(827-832): credit を 0 化するだけ、**実 ETH 送金なし**。receive()/fallback() 無し＝ETH 保持不可。
- `finalizedChannelFundAmount`(374): solvency cap だが **intent 申告から copy**(719)＝偽装可。`submitWithdrawalClaim`(770) は cap check 有り、**`submitPostCloseClaim`(786-825) は cap check 欠落**（withdrawalCredits += するが totalWithdrawn 非加算）。
- manager は rollup を `IChannelRegistry`(read-only) として参照、withdrawNative 呼び/受領 経路なし。manager は registerChannel 後にデプロイ（member set/bp を constructor で照合）。
- ChannelSettlementVerifier: 全 verify* が `_matches(proof==keccak(PI))` stub。

### 設計（approved plan project_channel_close_unification と整合）
**核心**: close 集約 settlement = **channel-as-user の withdrawal proof（recipient=manager）を P2 `withdrawNative` で実行** → `pendingWithdrawals[manager]`。manager が実受領し、それを cap として member へ分配。base intmax = channel 単位（base account=channel_id）なので集約引出、member split は channel layer（intra、accepted-stub）。
- **P3-a manager 実 ETH 化**: `receive() payable`（**msg.sender==rollup のみ**、誤送金拒否）+ `pullChannelFunds()`（`rollup.withdraw()` 呼び、balance 差分を `receivedChannelFunds` に記録）。
- **P3-b cap を実受領額に降格**: `finalizedChannelFundAmount` を intent 申告 → **実受領額（pullChannelFunds の balance 差分）** に。intent の channelFundAmount は一致 check のみ（非権威 hint）。これが cross-channel isolation の非交渉不変条件。
- **P3-c claimWithdrawalCredit 実送金**: CEI+nonReentrant、`Σ credits ≤ receivedChannelFunds`、`address(this).balance>=amount`、pull-payment。
- **P3-d submitPostCloseClaim に cap 追加**: totalWithdrawn 加算 + `≤ receivedChannelFunds` 強制（現状欠落の穴を塞ぐ）。
- **P4 verify* 整理（文書化）**: aggregate solvency = withdrawNative の実 MLE proof + 実受領 cap が担う（実強制）。verifyCloseIntent/WithdrawalClaim/PostCloseClaim/SpecialClose/CancelClose/LateOutgoingDebit は **intra-channel 合意（2者 signature+challenge）= accepted-stub** として明示文書化（実 ZK 置換は本スコープ外、intra-channel リスクは accepted）。

### 脅威モデル（attack→mitigation）
- (a) cap 超過分配/cross-channel theft → claimWithdrawalCredit の `Σ≤receivedChannelFunds`+balance check、submitWithdrawalClaim/PostCloseClaim 両方に cap。受領額は withdrawNative の実 proof amount（intent 申告ではない）。
- (b) manager 誤送金滞留 → receive() を rollup のみに制限。
- (c) close proof recipient 偽装 → withdrawNative の pis_hash 束縛（recipient は proof 由来、P2 で実証済み）。
- (d) reentrancy → 全 ETH 移動関数 nonReentrant+CEI、pull-payment。
- (e) finalizedChannelFundAmount 偽装 → 実受領額に降格（pull の balance 差分）、intent 申告無視。
- (f) manager address ↔ proof recipient 一致 → close withdrawal proof の recipient=manager。fixture/テストは CREATE2 等で決定的 manager address を proof 生成時に固定。

### 検証
- Solidity unit: receive 制限、pullChannelFunds、claimWithdrawalCredit 実送金、cap（両 claim）、reentrancy。
- フル e2e（任意・重）: recipient=manager の close withdrawal fixture 再生成（heavy run + CREATE2 manager）→ deposit→close 集約引出→manager 受領→finalizeClose→submitWithdrawalClaim→claimWithdrawalCredit→member 実 ETH。
- 独立敵対レビュー。

### 2026-06-14 P3+P4 完了 ✅（Solidity unit スコープ）
- 実装（ChannelSettlementManager.sol）: `receive()`(rollup のみ) + `pullChannelFunds()`(nonReentrant、balance 差分→receivedChannelFunds) + `claimWithdrawalCredit`(nonReentrant+CEI、実 ETH 送金、`totalCreditedOut+amount<=receivedChannelFunds` = cross-channel solvency cap) + `submitPostCloseClaim` に欠落 cap 追加 + reentrancy guard + `finalizedChannelFundAmount` を非権威 hint に降格。`IChannelRegistry` に `withdraw()` 追加。
- P4: ChannelSettlementVerifier ヘッダに trust-boundary 明文化（verify* は intra-channel accepted-stub、cross-channel solvency は withdrawNative 実 MLE + receivedChannelFunds cap が担保）。
- テスト: ChannelSettlementManager.t.sol に P3 6本追加（receive 拒否/pull/実送金/over-cap revert/postClose cap/reentrancy blocked）。MockChannelRegistry に withdraw()+creditWithdrawal 追加。
- **全 Forge 87/87 green**（IntmaxRollup 47 + ChannelSettlement 31 + MleE2E 2 + MleFinalizeE2E 1 + WithdrawNativeE2E 6）。EIP-170: manager 11.4KB、IntmaxRollup +112B。
- **独立敵対レビュー: SOUND**（critical/high なし）。cross-channel isolation 2層（rollup totalEscrowed + manager receivedChannelFunds）。残 LOW: finalizedChannelFundAmount footgun（intra-channel liveness、accepted・文書化済み）、fundBpBondCredits は intent-level（payout cap で bounded、pre-existing）。
- **元の3ハリボテすべて実体化完了**: ①非payable deposit→実エスクロー(P1) ②settlement digest stub→manager 実 ETH+cap+close→withdrawNative 配線(P3/P4) ③価値移さぬ withdrawal→withdrawNative 実払出(P2)。残 accepted-stub は intra-channel split のみ（cross-channel safety に不要）。
- 残: P7 Sepolia 再デプロイ + 実 2メンバー lifecycle（checkpoint 後）。

---

## P2 実行スペック（2026-06-14 調査確定 — このセッションのスコープ）

決定（ユーザー 2026-06-14）: (1) **pipeline 先・heavy proving は review 後に1回**、(2) **P2 で checkpoint**（anvil で deposit→finalize→withdrawNative を実証→独立レビュー→go/no-go）。P3+ と再デプロイは触らない。

### スコープの現実（調査で判明）
honest な `deposit→finalize→withdrawNative` は、withdrawal proof の `ext_public_state_commitment` が
on-chain `latestFinalizedStateRoot` と一致する必要があり、それは **同一ブロック列（registration→deposit→
withdrawal の3ブロック）に対する実 validity proof を finalize して初めて成立**。よって P2 の heavy run は
withdrawal proof だけでなく **同一チェーンの validity proof も生成**する（実質 P6 lifecycle を内包）。近道なし。
`_postBlock` は実 on-chain の deposit/registration ハッシュ連鎖をブロックハッシュに畳み込むため、テストは
fixture と同一パラメータで `deposit()`/`registerChannel()` を実呼びする。

### 束縛数式（make-or-break、検証済み）
WithdrawalCircuit PI（= wrapped MleProof.publicInputs、**18 limbs**）:
`[ pis_hash(8) ‖ ext_commitment(8) ‖ block_number(2) ]`（withdrawal_circuit.rs:206-208）。
- `pis_hash = remove_3bits( keccak256( withdrawal_hash(32B) ‖ prover(20B) ‖ ext_commitment(32B) ‖ block_number(8B big-endian) ) )`
  - remove_3bits = `value & ((1<<253)-1)`（bytes32.rs:30 `limb[0] &= (1<<29)-1`）。
- `withdrawal_hash` = keccak chain（seed=0）: 各 leaf preimage（152B）=
  `prevHash(32) ‖ recipient(20=address) ‖ tokenIndex(4) ‖ amount(32=uint256 BE) ‖ nullifier(32) ‖ auxData(32)`
  （withdrawal.rs:97 / WITHDRAWAL_LEN=30 / solidity_keccak256 は u32→4B big-endian、`_computeBlockHash` と同規約）。
- on-chain: ext_commitment は PI[8..16] から bytes32 復元 → `== latestFinalizedStateRoot` を検査。
  block_number = PI[16]<<32 | PI[17]。caller 供給の Withdrawal[] から withdrawal_hash を再畳み込み →
  pis_hash 再計算 → PI[0..8] と一致を検査。**payout 額は検証済み PI 束縛の amount（prover 申告ではない）**。

### Rust（新 binary `src/bin/generate_withdrawal_fixture.rs`、e2e.rs + generate_e2e_fixture.rs を鏡映）
最小チェーン: ch1 registration block → deposit(amount=10) block → withdrawal send_tx(amount=3→L1 addr) block。
1. balance proof: receive_deposit → send_tx(withdrawal_transfer)（内部 transfer は省略）。
2. single_withdrawal → withdrawal chain(step, prev=None) → withdrawal final(ext_state after blk3, prover)。
3. validity proof: 3ブロックを block_hash_chain で畳み validity_circuit.prove（e2e.rs:454-495 ループ）。
4. wrap+MLE ×2: validity→`lifecycle_validity_mle.json`、withdrawal→`withdrawal_mle.json`（export_mle_json）。
5. emit: `lifecycle_blocks.json`（3ブロック分の postBlock SubBlock 引数 + deposit()/registerChannel() 引数 +
   各 blockHashChainAt 期待値 + genesis/final root + VPIs）、`withdrawal_payout.json`（Withdrawal[]{recipient,
   token_index,amount,nullifier,auxData} + prover + block_number + ext_commitment）。
   既存 smoke fixture（mle_fixture.json 等）は触らない（別ファイル）。
6. Rust 側 sanity: on-chain 流儀の withdrawal_hash 再畳み込み（seed=0）が proof の withdrawal_hash と一致を assert。

### Solidity（IntmaxRollup.sol）
- 第2 VK を**constructor 追加**（immutable、post-deploy mutation なし＝最小攻撃面）: `withdrawalMleVk` +
  `_whirParamsW` + `_mleKIsW` + `_mleSubgroupGenPowersW` + `whirProtocolIdW` + `whirSplitSessionIdW`。
  MleVerifier は**共有**（EIP-170: 第2 verifier 契約は作らない）。Deploy.s.sol + 既存テスト constructor を機械的更新。
- `_verifyMleWithdrawal(mleProof)`（`_verifyMle` 鏡映、withdrawal VK storage 使用）。
- `withdrawNative(Withdrawal[] calldata ws, address withdrawalProver, uint64 blockNumber, MleProof calldata proof)`:
  CEI+nonReentrant。① `_verifyMleWithdrawal` ② ext_commitment(PI[8..16])==latestFinalizedStateRoot
  ③ withdrawal_hash 再畳み込み→pis_hash 再計算==PI[0..8] ④ 各 w: token_index==ETH_TOKEN_INDEX 要求(v1)、
  `withdrawalNullifierUsed[nullifier]` check→set、`totalEscrowed -= amount`（underflow revert=global cap）、
  `pendingWithdrawals[recipient] += amount`（pull-payment、既存 withdraw() で回収）。
- EIP-170: IntmaxRollup の deployed size を監視。

### テスト（`contracts/test/WithdrawNativeE2E.t.sol`、MleFinalizeE2E.t.sol 鏡映）
deploy(2 VK) → registerChannel/deposit{value:10}/postBlock×3（fixture 引数）→ finalize(validity proof, root=final)
→ withdrawNative(withdrawal proof) が recipient に exact 3 ETH を pendingWithdrawals 計上 + totalEscrowed 10→7 +
recipient が withdraw() で実 ETH 受領。負例: 二重(nullifier) revert、over-cap(amount>totalEscrowed) revert、
ext_commitment≠finalized revert、改竄 Withdrawal(pis_hash 不一致) revert、非 ETH token_index revert。

## フェーズ
- [x] **P1 エスクロー**（小・回路変更なし）: IntmaxRollup.deposit() payable、ETH_TOKEN_INDEX、`msg.value==amount`、`totalEscrowed`、receive 拒否。テスト。**完了（working tree、5/5 green、未コミット）**。
- [ ] **P2 native withdrawal payout（核心・最重）**:
      - Rust: `WithdrawalCircuit` の WrapperCircuit + MLE VK 立ち上げ（validity wrapper 鏡映）+ fixture emitter（generate_*_fixture 新規）。
      - Solidity: IntmaxRollup に `withdrawNative(Withdrawal w, MleProof p)` — withdrawal VK で mleVerifier.verify、`w.ext_public_state_commitment==latestFinalizedStateRoot`、keccak chain 再畳み込みで w を root に束縛、nullifier check/set、`totalEscrowed -=`、CEI+nonReentrant pull-payment。
      - withdrawal VK params を IntmaxRollup に保持（validity VK と別）。EIP-170 監視。
      - テスト（anvil 駆動）: deposit→finalize→withdrawal proof→withdrawNative が正確 ETH 払い出し、二重 revert、over-cap revert。
- [ ] **P3 channel close を withdrawal payout に配線**: manager に receive()、finalizeClose が rollup native withdrawal 着金を要求し `finalizedChannelFundAmount=受領額`、claimWithdrawalCredit を実 ETH 送金(CEI+nonReentrant)。close の Withdrawal.recipient=manager。テスト full close→payout→split。
- [ ] **P0/P4 verifyCloseIntent 実体化 / ChannelSettlementVerifier 整理**: close を withdrawal MLE 経路へ。残り verify*（specialClose 等）は 2者 v1 で signature/challenge ベース維持（accepted-stub、文書化）。member_set_commitment 束縛を実強制。
- [ ] **P5 独立セキュリティレビュー**（実装と別 agent、攻撃者視点）: cap/nullifier/reentrancy/escrow drift/close 束縛。
- [ ] **P6 マルチブロック lifecycle fixture**（register→deposit→transfer→withdrawal/close）。
- [ ] **P7 anvil フル리허설 → Sepolia 再デプロイ + 実 lifecycle 実行**（opus→codex 実 ETH 送金）。

## 検証の要
- P2 で deposit した実 ETH が withdrawNative で正確に払い出され、二重/over-cap が revert（anvil）。
- close→payout→split で codex が実 ETH を引き出せる（Sepolia）。
- 独立レビューで cap=実 proof・nullifier・reentrancy・escrow drift を確認。

## リスク
- 🔴 P2 が最重（WithdrawalCircuit の wrapper+MLE+fixture、新 VK 生成・重い proving）。EIP-170 で第2 verifier 不可＝共有必須、無理なら ext-state に withdrawal root（validity VK 再生成の最悪コンティンジェンシー）。
- 🔴 security-critical（実 ETH を動かす）。各フェーズ独立レビュー必須、CEI/nonReentrant 徹底。
- intra-channel split は accepted-stub（2者 signature+challenge）。

## 進捗記録

### 2026-06-14 P2 進捗
- **P1 escrow: 完了**（working tree、5/5 green、未コミット）。
- **P2 Solidity: 完了（コア）**。IntmaxRollup に `withdrawNative(Withdrawal[],address,MleProof)` +
  束縛ヘルパー（`_foldWithdrawalLeaf`/`_withdrawalPisHash`/`_limbsToBytes32`/`_limbsMatchBytes32`）+
  第2 VK（`initializeWithdrawalVk`、deployer-only set-once、degreeBits>0 必須、共有 MleVerifier）+
  `_verifyMleWithVk(proof,bool)`（validity/withdrawal VK 統合、EIP-170 削減）+ `withdrawalNullifierUsed`。
  EIP-170: IntmaxRollup runtime 24,498B（+78 余裕、production deploy 可）。**回帰なし**: IntmaxRollup.t
  47/47 + MleFinalizeE2E（実 validity finalize が refactor 後も green）+ MleE2E 2/2。
  - blockNumber 引数は除去（PI[16..18] から導出、pis_hash 束縛が値を強制するので冗長check不要）。
- **🔴 BLOCKER 発見（deposit hash chain semantics mismatch）**:
  honest な 3ブロック lifecycle（reg→deposit→withdrawal）で **block3(withdrawal, deposit無し) の
  block hash が on-chain と Rust で不一致** → finalize 不能。
  - Rust（block_witness_generator.rs:617,631）: `projected = self.deposit_hash_chain`（**累積**）を
    各ブロックが carry。block3 は H(0‖dep)（block2 の累積値）を carry。
  - on-chain（_postBlock:594-596）: `batchDepositHashChain = _pendingDepositHashChain`、round 毎に
    **0 へ reset**、carry-forward 無し。empty round の block は depositHash=0 を carry、global
    depositHashChain も 0 に上書き。→ block3 on-chain=0 ≠ Rust=H(0‖dep)。
  - **非対称の証拠**: reg chain は carry-forward 済み（_postBlock:604+ の三項）、deposit chain のみ reset。
    → deposit chain の reset は latent bug の可能性（累積 ledger なのに履歴を失う）。
  - deposit が withdrawal より前のブロックである必要（receive_deposit→send_tx 順序）ため、deposit
    後の empty block は不可避 → 契約変更なしには honest lifecycle finalize 不能。
  - **推奨 fix**: deposit chain を cumulative（carry-forward）化＝reg chain パターンに合わせる。ただし
    deposit()/rollback/`test_blockDepositHash_persistAndRollback`/fraud path への波及精査が必要、
    block-hash 束縛=validity binding に触れる security-sensitive 変更。スコープ外（P2 は「block model 変更なし」前提だった）→ ユーザー判断要。

### 2026-06-14 deposit chain cumulative 化（ユーザー承認: Fix deposit chain）
**脅威モデル（コード前）**:
- 変更内容（最小）: `_pendingDepositHashChain` を **live cumulative chain** にする＝(1) `_postBlock` の
  `_pendingDepositHashChain = bytes32(0)` reset を削除、(2) intermediate sub-block の depositHash を
  `bytes32(0)`→`previousDepositHashChain`（直前 round 終了時の cumulative）。deposit() は不変（cumulative に fold）。
  last sub-block は `batchDepositHashChain = _pendingDepositHashChain`（= 現 cumulative）を carry。
  `depositHashChain = batchDepositHashChain` も不変。reg chain の carry-forward パターンに整合。
- T1 validity binding: cumulative 化は **Rust の cumulative deposit_hash_chain と一致させる修正**（従来は
  multi-round で乖離＝latent bug）。strictly more correct。
- T2 rollback soundness: `_rollbackBatch` は変更不要。`pendingDepositHashChainBefore`/`previousDepositHashChain`
  は postBlock entry 時の cumulative を捕捉済み→復元で正しい状態に戻る。削除されるブロックの
  blockDepositHash は delete（ブロック自体が消えるので 0 化で正）。per-deposit ループ無し＝O(1) 維持。
- T3 re-post: rollback 後 `_pendingDepositHashChain` は cumulative-with-deposits を保持→deposit は pending の
  まま再 post 可能。processedDepositCount も復元。
- T4 empty round: 従来は depositHashChain を 0 に上書き（履歴喪失）→ carry-forward で cumulative 保持。
- T5 既存テスト波及: deposit を伴う prior round が無い限り previousDepositHashChain=0 ＝ intermediate も 0 で
  従来と同一。既存テスト（batchOf3/twoRounds は deposit 無し、persistAndRollback はブロック削除で 0、
  blockHashChannelRegDifferential は `_computeBlockHash` 直叩きで _postBlock 非経由）は不変の見込み。要全実行確認。
- 検証: 全 Forge テスト green + 独立敵対レビュー。
- **完了**: 全変更後 IntmaxRollup.t 47/47 + MleFinalizeE2E green、EIP-170 +47B（production deploy 可）。

### 2026-06-14 P2 pipeline 完成 + 独立レビュー
- Rust `src/bin/generate_withdrawal_fixture.rs`（compiles、reg 抽出は to_reg_record と byte 一致を確認、
  depositor export 漏れ修正、withdrawal keccak 再 fold + ext_commitment の Rust 側 sanity assert 内蔵）。
- Solidity `contracts/test/WithdrawNativeE2E.t.sol`（compiles、fixture 未生成時 self-skip）。FixtureLib 再利用。
- **独立敵対レビュー: SOUND**（theft/double-spend/replay/binding-forge 経路無し、byte layout 全一致）。
  - F1(HIGH, trust boundary): per-token 価値保存は回路の性質。v1 は token0(ETH) のみ escrow＝aggregate cap
    = token0 cap で実質緩和、残りは標準 ZK soundness 前提。
  - **F2(MEDIUM) 修正済み**: withdrawal は `latestFinalizedStateRoot` 完全一致のみ→次 finalize で honest
    withdrawer ロックアウト。`finalizedStateRoots` 集合（permanent、rollback 不可）へ変更＝任意の既 finalized
    root で償還可（nullifier が double-spend を防ぐ）。
  - F3(LOW): rollback が post-batch pending deposit を drop（reg chain と同じ既存 pattern）。文書化。
- 次: heavy proving run（generate_withdrawal_fixture）→ WithdrawNativeE2E を anvil/forge で実行 → checkpoint。

### 2026-06-14 P2 完了（checkpoint 到達）✅
- heavy run 成功（~2分）: 4 fixture 生成、withdrawal keccak re-fold sanity check PASSED。
- **オンチェーンバグ1件発見・修正**: wrapped withdrawal PI は **17 limbs**（block_number は u63=1 field
  element、登録形は 1 limb。pis_hash keccak preimage だけ 2×u32）。`withdrawNative` の `pi.length`
  と block_number 抽出を 18/[hi,lo]→17/単一 limb に修正。
- **WithdrawNativeE2E 6/6 PASS**: fullLifecycle（register→deposit{value}→postBlock×3→finalize(実
  validity MLE)→withdrawNative(実 withdrawal MLE)→正確 ETH 払出 + withdraw() 受領 + totalEscrowed 減算）、
  doubleSpend revert、beforeFinalize revert、tamperedAmount revert、vkNotSet revert、init access/set-once。
- **全 Forge 81/81 green**（回帰ゼロ）。EIP-170 +47B。
- **P2 検証基準すべて達成**: 実 escrow→実 finalize→実 withdrawNative が正確 ETH 払出、二重/finalize前/改竄が revert。
- 未 commit（ユーザー指示待ち）。P3（close→payout 配線）/P4（settlement verifier）/P7（Sepolia 再デプロイ）は checkpoint 後。

## 既存デプロイ（旧 smoke、空ブロック genesis、再デプロイで置換予定）
- IntmaxRollup 0xBa057F093765a0AA4c4001d8deC5171E836A0af0 / MleVerifier 0x4154a4A27Ad06dc57Dab86e3a696e2454a62d871（Sepolia）
- deployer 0x2C0BF10558adafDd21296CbF71dd6FE88c782C80、残高 ~10 ETH（+回収可 1 ETH）
