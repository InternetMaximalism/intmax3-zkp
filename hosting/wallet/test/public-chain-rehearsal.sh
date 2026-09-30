#!/usr/bin/env bash
# Rehearse the PUBLIC-CHAIN deployment end to end on a local anvil, before touching the testnet.
#
# `deploy-settlement` and the relay choose their code path from the chain id (31337 = devnet,
# anything else = the real-chain path), so an anvil started with Sepolia's chain id runs exactly
# the production path: DeployCloseCli, the PREPARED/ACTIVE settlement binding, finalized reads,
# live registration, bootstrap-real-chain.js and wallet-relay.js off devnet. The first Sepolia
# deployment met a dozen defects on that path because it had never run before; this script is
# the rehearsal that was missing. Anvil is given Sepolia's gas limit and a finality lag, and a
# proxy (rpc-limits-proxy.js) enforces publicnode's eth_getLogs range cap.
#
# Usage: public-chain-rehearsal.sh <step>   (run the steps in order; each is re-runnable)
#   chain      start anvil (chain id 11155111) + the limits proxy, pre-mine history, operator keystore
#   rollup     feature-config contracts copy + Deploy.s.sol
#   backing    setup-backing (empty genesis) for every channel
#   late       export the late-incoming config from the channel Balance VD + deploy its verifier
#   bootstrap  bootstrap-real-chain.js up to the envelope, public_close_prover, then settlement,
#              L1 registration and exit kits
#   relay      start wallet-relay.js (HTTPS :$RELAY_PORT, HTTP :$RELAY_PORT+1)
#   env        print the environment (source it to run CLI commands by hand)
#
# Requires: target/release/{channel_member,block_producer_service,public_close_prover,
# export_late_incoming_config} built with --features authenticated-tail-receive, Foundry v1.5.1,
# and TAIL_CONFIGS=<dir with the feature-built *_config.json fixtures> (generate_*_fixture
# --mle-config-only under the same feature).
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../../.." && pwd)"
R="${REHEARSAL_DIR:?set REHEARSAL_DIR to an empty scratch directory}"
CHANNELS="${REHEARSAL_CHANNELS:-7 8}"
CHAIN_ID=11155111
ANVIL_PORT="${ANVIL_PORT:-8597}"
PROXY_PORT="${PROXY_PORT:-8598}"
RELAY_PORT="${RELAY_PORT:-8610}"
RPC="http://127.0.0.1:${PROXY_PORT}"
# Scaled-down public-RPC history: publicnode caps eth_getLogs at 50 000 blocks over ~11.8M blocks
# of history. The rehearsal keeps the property that matters (every log scan must page, and the
# rollup is deployed far above block 0) at a size anvil mines in seconds.
PREMINE_BLOCKS="${PREMINE_BLOCKS:-6000}"
export RPC_LOGS_MAX_RANGE="${RPC_LOGS_MAX_RANGE:-2000}"
ACCOUNT=intmax-rehearsal-anvil0
# anvil's PUBLIC dev accounts (worthless outside a local anvil).
ANVIL0_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
OPERATOR=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
DELEGATE_RECIPIENT_7=0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc
DELEGATE_RECIPIENT_8=0x976EA74026E726554dB657fA54763abd0C3a0aa9
export PATH="$HOME/.foundry/bin:$HOME/.cargo/bin:$PATH"

mkdir -p "$R"
chmod 700 "$R"
BIN="$REPO/target/release"
CONTRACTS="$R/contracts-tail"
WORK="$R/work"

environment() {
  cat <<EOF
export RPC=$RPC
export INTMAX_CHANNELS=$(echo $CHANNELS | tr ' ' ',')
export INTMAX_WORK_DIR=$WORK
export CHANNEL_MEMBER_BIN=$BIN/channel_member
export BLOCK_PRODUCER_BIN=$BIN/block_producer_service
export PUBLIC_CLOSE_PROVER_BIN=$BIN/public_close_prover
export CONTRACTS_DIR=$CONTRACTS
export INTMAX_COSIGNER_KEYFILE=$R/cosigner.key
export CLI_RECIPIENT_SLOT_0=$OPERATOR
export CLI_RECIPIENT_SLOT_1=$OPERATOR
export CLI_RECIPIENT_SLOT_2=$OPERATOR
export INTMAX_L1_ACCOUNT=$ACCOUNT
export ETH_KEYSTORE_ACCOUNT=$ACCOUNT
export ETH_PASSWORD=$R/eth_password
export FOUNDRY_SOLC=0.8.28
export MLE_VERIFIER_CHAIN_ID=$CHAIN_ID
export LATE_MLE_CONFIG_PATH=$CONTRACTS/test/data/late_incoming_mle_config.json
export BOOTSTRAP_DELEGATE_RECIPIENT_7=$DELEGATE_RECIPIENT_7
export BOOTSTRAP_DELEGATE_RECIPIENT_8=$DELEGATE_RECIPIENT_8
EOF
  if [ -f "$R/late_verifier" ]; then echo "export LATE_INCOMING_VERIFIER=$(cat "$R/late_verifier")"; fi
}

load_env() { eval "$(environment)"; }

step_chain() {
  if ! curl -s -o /dev/null "http://127.0.0.1:${ANVIL_PORT}"; then
    # Sepolia: 60M gas, EIP-170/3860 enforced (no --code-size-limit), finalized ~2 epochs behind.
    nohup anvil --chain-id "$CHAIN_ID" --port "$ANVIL_PORT" --hardfork prague --gas-limit 60000000 \
      --block-time 1 --slots-in-an-epoch 32 --silent > "$R/anvil.log" 2>&1 < /dev/null &
    for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:${ANVIL_PORT}" && break; sleep 0.2; done
    # A long history, so log scans must page within the proxy's range cap as on the real chain.
    cast rpc anvil_mine "$(printf '0x%x' "$PREMINE_BLOCKS")" --rpc-url "http://127.0.0.1:${ANVIL_PORT}" > /dev/null
  fi
  if ! curl -s -o /dev/null "$RPC"; then
    nohup node "$REPO/hosting/wallet/test/rpc-limits-proxy.js" "$PROXY_PORT" "http://127.0.0.1:${ANVIL_PORT}" \
      > "$R/proxy.log" 2>&1 < /dev/null &
    for _ in $(seq 1 50); do curl -s -o /dev/null "$RPC" && break; sleep 0.2; done
  fi
  [ "$(cast chain-id --rpc-url "$RPC")" = "$CHAIN_ID" ] || { echo "proxy/anvil not serving chain $CHAIN_ID" >&2; exit 1; }
  umask 077
  if [ ! -f "$R/eth_password" ]; then
    openssl rand -hex 16 > "$R/eth_password"
    # A keystore from an earlier rehearsal is encrypted under that rehearsal's password.
    rm -f "$HOME/.foundry/keystores/$ACCOUNT"
  fi
  [ -f "$R/cosigner.key" ] || openssl rand -hex 32 > "$R/cosigner.key"
  if ! cast wallet list 2>/dev/null | grep -q "^$ACCOUNT"; then
    cast wallet import "$ACCOUNT" --private-key "$ANVIL0_KEY" --unsafe-password "$(cat "$R/eth_password")" > /dev/null
  fi
  echo "chain: anvil :$ANVIL_PORT behind limits proxy $RPC, head $(cast block-number --rpc-url "$RPC")"
}

step_rollup() {
  load_env
  : "${TAIL_CONFIGS:?set TAIL_CONFIGS to the feature-built config fixture directory}"
  if [ ! -d "$CONTRACTS" ]; then
    rsync -a --exclude broadcast/ --exclude cache/ --exclude out/ "$REPO/contracts/" "$CONTRACTS/"
    rm -f "$CONTRACTS"/test/data/*_mle_config.json "$CONTRACTS/test/data/mle_fixture_config.json"
    cp "$TAIL_CONFIGS"/*_config.json "$CONTRACTS/test/data/"
  fi
  local artifact="$CONTRACTS/broadcast/Deploy.s.sol/$CHAIN_ID/run-latest.json"
  if [ ! -f "$artifact" ]; then
    (cd "$CONTRACTS" && FRAUD_TREASURY=$OPERATOR forge script script/Deploy.s.sol --rpc-url "$RPC" \
      --account "$ACCOUNT" --broadcast --slow > "$R/rollup.log" 2>&1) || { tail -30 "$R/rollup.log"; exit 1; }
  fi
  node -e 'const a=require(process.argv[1]);const t=a.transactions.find(t=>t.contractName==="IntmaxRollup"&&t.transactionType==="CREATE");process.stdout.write(t.contractAddress)' "$artifact" > "$R/rollup"
  echo "rollup: $(cat "$R/rollup")"
}

step_backing() {
  load_env
  for ch in $CHANNELS; do
    mkdir -p "$WORK/ch$ch"
    if [ ! -f "$WORK/ch$ch/channel_backing.json" ]; then
      (cd "$WORK/ch$ch" && INTMAX_CHANNEL=$ch SETUP_BACKING_EMPTY_GENESIS=1 \
        "$CHANNEL_MEMBER_BIN" setup-backing "$RPC" "$(cat "$R/rollup")" > "$R/backing-$ch.log" 2>&1) \
        || { tail -20 "$R/backing-$ch.log"; exit 1; }
    fi
    echo "ch$ch backed; balance VD sha256 $(shasum -a 256 "$WORK/ch$ch/balance_vd.bin" | cut -c1-16)"
  done
}

step_late() {
  load_env
  local first; first=$(echo $CHANNELS | cut -d' ' -f1)
  if [ ! -f "$LATE_MLE_CONFIG_PATH" ]; then
    "$BIN/export_late_incoming_config" "$WORK/ch$first/balance_vd.bin" "$LATE_MLE_CONFIG_PATH" > "$R/late-export.log" 2>&1 \
      || { tail -20 "$R/late-export.log"; exit 1; }
  fi
  if [ ! -f "$R/late_verifier" ]; then
    (cd "$CONTRACTS" && forge script script/DeployLateIncomingVerifier.s.sol --rpc-url "$RPC" \
      --account "$ACCOUNT" --broadcast --slow > "$R/late.log" 2>&1) || { tail -30 "$R/late.log"; exit 1; }
    grep -oE "LATE_INCOMING_VERIFIER 0x[0-9a-fA-F]{40}" "$R/late.log" | tail -1 | cut -d' ' -f2 > "$R/late_verifier"
  fi
  echo "late-incoming verifier: $(cat "$R/late_verifier")"
}

step_bootstrap() {
  load_env
  (cd "$REPO" && BOOTSTRAP_STOP_AFTER=envelope node hosting/wallet/bootstrap-real-chain.js $CHANNELS)
  for ch in $CHANNELS; do
    local dir="$WORK/ch$ch" rollup
    rollup=$(cat "$R/rollup")
    if [ ! -f "$dir/settlement.json" ] && [ ! -f "$dir/public_close_bundle/public_close_manifest.json" ]; then
      "$PUBLIC_CLOSE_PROVER_BIN" --input "$dir/installed_exit_kit.json" --output-dir "$dir/public_close_bundle" \
        --expected-channel-id "$ch" --expected-chain-id "$CHAIN_ID" --expected-rollup "$rollup" \
        --expected-balance-vd-sha256 "$(shasum -a 256 "$dir/balance_vd.bin" | cut -d' ' -f1)" > "$R/prover-$ch.log" 2>&1 \
        || { tail -20 "$R/prover-$ch.log"; exit 1; }
    fi
  done
  (cd "$REPO" && node hosting/wallet/bootstrap-real-chain.js $CHANNELS)
}

step_relay() {
  load_env
  mkdir -p "$R/public"
  cp "$REPO/hosting/wallet/wallet-live.html" "$R/public/index.html"
  cp "$REPO/hosting/wallet/wallet-worker.js" "$REPO/hosting/wallet/signature-release-ledger.mjs" \
    "$REPO/hosting/wallet/wallet-outbox.js" "$REPO/hosting/wallet/wallet-transactions.js" "$R/public/"
  [ -e "$R/public/pkg" ] || ln -s "$REPO/pkg" "$R/public/pkg"
  if [ ! -f "$R/tls/cert.pem" ]; then
    mkdir -p "$R/tls"
    openssl req -x509 -newkey rsa:2048 -nodes -days 7 -subj /CN=localhost \
      -keyout "$R/tls/key.pem" -out "$R/tls/cert.pem" > /dev/null 2>&1
  fi
  TLS_CERT="$R/tls/cert.pem" TLS_KEY="$R/tls/key.pem" \
  RELAY_PORT=$RELAY_PORT RELAY_PUBLIC_DIR="$R/public" RELAY_PKG_DIR="$REPO/pkg" \
    nohup node "$REPO/hosting/wallet/wallet-relay.js" > "$R/relay.log" 2>&1 < /dev/null &
  echo $! > "$R/relay.pid"
  for _ in $(seq 1 100); do grep -q "wallet relay on" "$R/relay.log" && break; sleep 0.5; done
  grep "wallet relay on" "$R/relay.log" || { tail -30 "$R/relay.log"; exit 1; }
}

case "${1:-}" in
  chain) step_chain ;;
  rollup) step_rollup ;;
  backing) step_backing ;;
  late) step_late ;;
  bootstrap) step_bootstrap ;;
  relay) step_relay ;;
  env) environment ;;
  *) sed -n '2,24p' "$0"; exit 2 ;;
esac
