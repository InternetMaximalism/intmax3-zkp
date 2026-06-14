# Task: Sepolia testnet smoke deploy（段階的・第1マイルストーン）

Status: IN PROGRESS — ユーザー承認済みスコープ「段階的：まず deploy+空ブロック finalize の smoke」。
secrets(RPC/deployer 鍵) はユーザーが .env/keystore で後追い用意。まず秘密情報不要の build + ローカル検証から。

## ゴール（第1マイルストーン = smoke）
Sepolia(Pectra) に MleVerifier + IntmaxRollup を deploy し、**現 fixture（空ブロック#1）で
deploy → postBlock(blob tx) → finalize（実 MLE/WHIR 検証 ON）まで通す**。送金 lifecycle は第2マイルストーン。

## 重要な事実（調査結果）
- 既存テストはフローを**分割**検証: `MleE2E.t.sol`=MLE 検証単体、`IntmaxRollup.t.sol` finalize=degreeBits=0(MLE skip)+ダミーPI。
  **「実 MLE proof + 実 ValidityPI + 実 postBlock block-hash が1つの finalize で噛み合う」フルパスは未テスト** → smoke の核心。
- fixture は `mle_fixture.json`(MLE proof+VK) と `vpi_fixture.json`(state roots) のみ出力。
  **postBlock の SubBlock 引数（block hash 0x3ed4… を再現する channelId/timestamp/txTreeRoot/keyIds + deposit/reg hash chain）は未出力** → 新規に必要。
- block hash = `keccak(prev||channelId||timestamp(u64BE)||keyIds(4B each)||txTreeRoot||depositHashChain||channelRegHashChain)`（IntmaxRollup `_computeBlockHash`、Rust `Block::hash_with_prev_hash` と byte 一致）。
  空ブロック#1: prev=0(genesis), deposit/reg chain=0, channelId=1, txTreeRoot=0, keyIds=[], timestamp=Rust値。
- postBlock は **type-3 blob tx 必須**（`blobhash(0)` 空なら NoBlobAttached revert）。finalize は calldata のみ。
- Pectra は Sepolia 稼働済み（EIP-2537/4844 利用可）。MLE 検証 ~11M gas（block limit 36M 内）。
- genesisStateRoot = `vpi_fixture.initial_ext_commitment`。deploy 時にこれを渡し、誰も他 tx を打たなければ fixture 列を再現可能。

## フェーズ（S1-S6）
- [ ] **S1**（秘密情報不要・最優先 de-risk）emitter 拡張: `block_witness` の Block から `block_fixture.json` を出力
      （channelId, timestamp, txTreeRoot, keyIds[], blockDepositHashChain, blockChannelRegHashChain, proofHash, proofLength, finalStateRoot=final_ext_commitment, genesisStateRoot=initial_ext_commitment）。
- [ ] **S2**（秘密情報不要・de-risk 核心）フルパス Forge テスト `MleFinalizeE2E.t.sol`:
      実 mleVk+genesis で IntmaxRollup deploy → postBlockAndSubmit(vm.blobhashes mock, S1 の SubBlock) → finalize(実 ValidityPI + 実 MleProof, degreeBits>0)。
      **実 MLE 検証 ON で finalize 成功を assert**。失敗時は CLAUDE.md に従い検査を弱めず STOP→調査。
- [ ] **S3** Forge deploy script `script/Deploy.s.sol`: fixtures を読み MleVerifier+ChannelSettlementVerifier+IntmaxRollup を deploy（任意で registerChannel(opus/codex 2人)+ChannelSettlementManager）。
- [ ] **S4** blob tx ツール/runbook: `cast send --blob` で postBlockAndSubmit、`cast send` で finalize。Forge script は blob を素直に送れないため cast 併用。
- [ ] **S5** `foundry.toml [rpc_endpoints]` + `contracts/.env.example` + keystore 手順（`cast wallet import`）。鍵はチャットに出さない。
- [ ] **S6** ユーザーが RPC/鍵を用意後、Sepolia で deploy→postBlock(blob)→finalize を実行・Etherscan 確認。

## 検証の要
- S2 フルパス finalize がローカルで PASS（実 MLE 検証）→ これが通れば Sepolia smoke の主リスクは除去。
- block hash byte 一致（S1 の SubBlock が 0x3ed4… を再現）。
- PI hash 束縛（`_mlePublicInputsMatch`）が実 ValidityPI で成立。

## リスク
- 🔴 block hash / PI hash の byte 不一致で finalize revert（S2 で先に潰す）。
- 🔴 blob tx 送信（Foundry/cast の EIP-4844 対応）。
- open readiness blocker（registerChannel アクセス制御なし=squatting）は smoke では許容、本番前に対応。

## 結果記録
（各フェーズ完了時に追記）
