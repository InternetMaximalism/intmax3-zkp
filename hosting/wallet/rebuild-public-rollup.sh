#!/usr/bin/env bash
# Rebuild the public testnet on a NEW rollup, run on the relay host after
# `DEPLOY_NEW_ROLLUP=1 hosting/wallet/deploy-relay-host.sh` has installed the new tree and binaries.
#
# A release whose circuits changed (a plonky2 update, a validity or close circuit change) cannot
# finalize anything on the deployed rollup: its verifiers pin the old circuit configurations and
# have no setter. Every pinned configuration is therefore produced again by THIS build, on this
# host, from the verified tree, in the order public-chain-rehearsal.sh rehearses:
#
#   archive    the old rollup's relay state (wallet-live-work, broadcasts, validity export)
#   configs    the feature-built proof-free *_config.json set (generate_*_fixture --mle-config-only),
#              installed into contracts-tail/test/data (refreshed from this release), which every
#              deploy script reads
#   rollup     Deploy.s.sol with the validity verifier pinned to the producer's exported config
#   backing    setup-backing (empty genesis) per channel
#   late       the late-incoming config exported from the channel Balance VD + its verifier
#   bootstrap  bootstrap-real-chain.js (validity record, genesis, settlement, registration, exit kit)
#
# then starts the relay. Every step skips work already done, so a failed run is re-run as is.
# Usage (on the host, relay env in ~/relay): REBUILD_ARCHIVE=<name> nohup hosting/wallet/rebuild-public-rollup.sh
# BASE_STAKE_WEI / POST_STAKE_WEI override Deploy.s.sol's posting bond (0.1 ETH + 0.001 ETH per post).
# RELAY_HOME (default ~/relay), RELAY_SERVICE and RELAY_HEALTH_URL let the rehearsal run this script
# against its local chain.
set -euo pipefail
cd "$(dirname "$0")/../.."
REPO=$PWD
export PATH="$HOME/.foundry/bin:$HOME/.cargo/bin:$PATH"
RELAY_HOME="${RELAY_HOME:-$HOME/relay}"
RELAY_SERVICE="${RELAY_SERVICE:-intmax-wallet-relay}"
RELAY_HEALTH_URL="${RELAY_HEALTH_URL:-https://localhost/api/health}"
BOOTSTRAP_ENV="${BOOTSTRAP_ENV:-$RELAY_HOME/bootstrap.env}"
# shellcheck disable=SC1090
source "$BOOTSTRAP_ENV"
log() { echo "[$(date -u +%T)] $*"; }
A=$RELAY_HOME/archive/${REBUILD_ARCHIVE:?set REBUILD_ARCHIVE to the archive name of the rollup being replaced}
CONTRACTS=${CONTRACTS_DIR:-$REPO/contracts-tail}
DATA=$CONTRACTS/test/data
# Foundry reads and writes ../proof-da-output/ next to the contracts (foundry.toml fs_permissions).
DA=$(dirname "$CONTRACTS")/proof-da-output
WORK=${INTMAX_WORK_DIR:-$REPO/wallet-live-work}
CHAIN_ID=$(cast chain-id --rpc-url "$RPC")
STATE=$RELAY_HOME/rebuild-$REBUILD_ARCHIVE
mkdir -p "$STATE"

if [ ! -d "$A" ]; then
  log "stopping the relay and archiving the old rollup's state to $A"
  sudo systemctl stop "$RELAY_SERVICE"
  mkdir -p "$A"
  [ -d "$WORK" ] && mv "$WORK" "$A/wallet-live-work"
  [ -d "$CONTRACTS/broadcast" ] && mv "$CONTRACTS/broadcast" "$A/broadcast"
  [ -d "$DA" ] && mv "$DA" "$A/proof-da-output"
  cp -a "$DATA" "$A/test-data"
fi
sudo systemctl stop "$RELAY_SERVICE"

if [ ! -f "$STATE/configs.done" ]; then
  log "building the config generators (authenticated-tail-receive)"
  cargo build --release --locked \
    --features authenticated-tail-receive,close-fixture-bin,withdrawal-claim-fixture-bin,post-close-claim-fixture-bin,cancel-close-fixture-bin \
    --bin generate_e2e_fixture --bin generate_withdrawal_fixture --bin generate_burn_withdrawal_fixture \
    --bin generate_c2c_fixture --bin generate_close_fixture --bin generate_withdrawal_claim_fixture \
    --bin generate_post_close_claim_fixture --bin generate_cancel_close_fixture > "$STATE/configs-build.log" 2>&1 \
    || { tail -30 "$STATE/configs-build.log"; exit 1; }
  # Run copies: any other cargo build in this target directory (an integration test builds the
  # package's binaries WITHOUT the feature) would replace target/release/generate_* mid-run, and the
  # configs it then writes pin the wrong circuits. The generators write contracts/test/data relative
  # to their working directory and refuse to overwrite a different circuit identity, so they run in
  # an empty staging tree.
  rm -rf "$STATE/configs" "$STATE/bin" && mkdir -p "$STATE/configs/contracts/test/data" "$STATE/bin"
  cp "$REPO"/target/release/generate_{e2e,withdrawal,burn_withdrawal,c2c,close,withdrawal_claim,post_close_claim,cancel_close}_fixture "$STATE/bin/"
  ( cd "$STATE/configs"
    for g in e2e withdrawal burn_withdrawal c2c close withdrawal_claim post_close_claim cancel_close; do
      log "generate_${g}_fixture --mle-config-only"
      "$STATE/bin/generate_${g}_fixture" --mle-config-only
    done
    log "generate_withdrawal_fixture --mle-config-only (sepolia_)"
    WD_OUT_PREFIX=sepolia_ "$STATE/bin/generate_withdrawal_fixture" --mle-config-only
  ) > "$STATE/configs.log" 2>&1 || { tail -30 "$STATE/configs.log"; exit 1; }
  [ "$(find "$STATE/configs/contracts/test/data" -name '*_config.json' | wc -l | tr -d ' ')" = 16 ] \
    || { echo "expected 16 configs, got: $(ls "$STATE/configs/contracts/test/data")" >&2; exit 1; }
  # The deploy leaves contracts-tail/test/data as the replaced rollup had it: take the rest of it
  # from this release too, as the rehearsal does, rather than run on the old cohort's fixtures.
  rsync -a --delete "$REPO/contracts/test/data/" "$DATA/"
  rm -f "$DATA"/*_config.json
  cp "$STATE/configs/contracts/test/data"/*_config.json "$DATA/"
  (cd "$DATA" && shasum -a 256 ./*_config.json) | tee "$STATE/configs.sha256"
  touch "$STATE/configs.done"
fi

# The deploy scripts below must run on the binaries the relay will run: the deploy installed them.
cargo build --release --locked --features authenticated-tail-receive \
  --bin channel_member --bin block_producer_service --bin public_close_prover \
  --bin export_late_incoming_config > "$STATE/build.log" 2>&1 || { tail -30 "$STATE/build.log"; exit 1; }

log "exporting the producer's validity configuration"
CFG=$(node -e 'process.stdout.write(require("./api/lib/validity-deployment").exportedConfig())')
mkdir -p "$DA"
[ "$CFG" -ef "$DA/$(basename "$CFG")" ] || cp "$CFG" "$DA/"
CFG=$DA/$(basename "$CFG")
SHA=0x$(shasum -a 256 "$CFG" | cut -d' ' -f1)
log "config $CFG sha256 $SHA"
# --skip-simulation: each transaction's gas limit comes from the chain's eth_estimateGas, made
# after the previous one is mined (--slow), not from forge's local simulation, which prices by
# foundry.toml's evm_version. Sepolia's fork of 2026-10-06 charges ~1,540 gas per deployed code
# byte and ~111k per new storage slot: the simulated limit ran the first verifier CREATE out of
# gas (5.15M simulated, 32.2M estimated by the chain).
# A load-balanced RPC can answer that estimate from a node that has not imported the previous
# transaction's block yet: a constructor checking the contract created one transaction earlier
# then reverts (observed: InvalidPinnedMleVerifierCore for a core mined the block before), and
# forge retries the estimate only immediately. Wait and --resume the same run instead.
# Fees: forge's estimator tips ~1 gwei, while Sepolia includes 2-wei tips (2026-11-03: base fee 18
# wei, the lowest decile of tips 2 wei); at the repriced gas the rollup deploy alone (169M gas) cost
# 0.169 ETH that way. Tip FORGE_PRIORITY_FEE_WEI (default 1 mwei) under a max fee of
# FORGE_MAX_FEE_WEI, by default twice the current base fee plus the tip. Both are explicit: given
# only the tip, forge keeps its own max-fee estimate, which falls below a 1 mwei tip when its
# fee-history tip estimate does ("max priority fee per gas higher than max fee per gas"), and a
# large fixed cap is refused because the node reserves gas limit x max fee from the balance (a
# 10-gwei cap asked 0.467 ETH of a 0.423 ETH balance for a 47M-gas CREATE).
forge_fees() {
  local tip=${FORGE_PRIORITY_FEE_WEI:-1000000} base
  base=$(cast base-fee --rpc-url "$RPC" | awk '{print $1}')
  echo --priority-gas-price "$tip" --with-gas-price "${FORGE_MAX_FEE_WEI:-$((2 * base + tip))}"
}
forge_broadcast() {
  local log=$1 attempt fees; shift
  read -ra fees <<< "$(forge_fees)"
  (cd "$CONTRACTS" && forge script "$@" --rpc-url "$RPC" --account "$INTMAX_L1_ACCOUNT" \
    --broadcast --slow --skip-simulation "${fees[@]}") > "$log" 2>&1 && return 0
  for attempt in 1 2 3 4 5; do
    tail -5 "$log" | grep -q 'Failed to estimate gas' || break
    log "a gas estimate failed; resuming $1 in 30 s (attempt $attempt)"
    sleep 30
    read -ra fees <<< "$(forge_fees)"
    (cd "$CONTRACTS" && forge script "$@" --rpc-url "$RPC" --account "$INTMAX_L1_ACCOUNT" \
      --broadcast --slow --skip-simulation "${fees[@]}" --resume) >> "$log" 2>&1 && return 0
  done
  tail -30 "$log"
  return 1
}
ART=$CONTRACTS/broadcast/Deploy.s.sol/$CHAIN_ID/run-latest.json
# A run that stopped on a failed transaction leaves its artifact behind: deploy again unless every
# transaction of the artifact has a successful receipt.
deployed() {
  [ -f "$ART" ] && node -e 'const a=require(process.argv[1]); process.exit(a.transactions.length > 0 && a.transactions.every(t => (a.receipts || []).some(r => r.transactionHash === t.hash && r.status === "0x1")) ? 0 : 1)' "$ART"
}
if ! deployed; then
  log "deploying the rollup"
  FRAUD_TREASURY=$CLI_RECIPIENT_SLOT_0 WALLET_VALIDITY_CONFIG="$CFG" WALLET_VALIDITY_CONFIG_SHA256="$SHA" \
    forge_broadcast "$STATE/rollup.log" script/Deploy.s.sol || exit 1
fi
ROLLUP=$(node -e 'const a=require(process.argv[1]);const t=a.transactions.find(t=>t.contractName==="IntmaxRollup"&&t.transactionType==="CREATE");process.stdout.write(t.contractAddress)' "$ART")
log "rollup $ROLLUP (base stake $(cast call "$ROLLUP" 'baseStake()(uint256)' --rpc-url "$RPC"), post stake $(cast call "$ROLLUP" 'postStake()(uint256)' --rpc-url "$RPC"))"

CHANNELS=${INTMAX_CHANNELS//,/ }
for ch in $CHANNELS; do
  mkdir -p "$WORK/ch$ch"
  if [ ! -f "$WORK/ch$ch/channel_backing.json" ]; then
    log "setup-backing ch$ch"
    (cd "$WORK/ch$ch" && INTMAX_CHANNEL=$ch SETUP_BACKING_EMPTY_GENESIS=1 \
      "$REPO/target/release/channel_member" setup-backing "$RPC" "$ROLLUP" > "$STATE/backing-$ch.log" 2>&1) \
      || { tail -20 "$STATE/backing-$ch.log"; exit 1; }
  fi
done

# The late-incoming verifier pins the config of the channels' Balance VD, which this build defines.
export LATE_MLE_CONFIG_PATH=$DATA/late_incoming_mle_config.json
FIRST=${CHANNELS%% *}
if [ ! -f "$STATE/late_incoming_verifier" ]; then
  log "exporting the late-incoming config from ch$FIRST's Balance VD"
  rm -f "$LATE_MLE_CONFIG_PATH"
  "$REPO/target/release/export_late_incoming_config" "$WORK/ch$FIRST/balance_vd.bin" "$LATE_MLE_CONFIG_PATH" \
    > "$STATE/late-export.log" 2>&1 || { tail -20 "$STATE/late-export.log"; exit 1; }
  log "deploying the late-incoming verifier"
  forge_broadcast "$STATE/late.log" script/DeployLateIncomingVerifier.s.sol || exit 1
  grep -oE "LATE_INCOMING_VERIFIER 0x[0-9a-fA-F]{40}" "$STATE/late.log" | tail -1 | cut -d' ' -f2 > "$STATE/late_incoming_verifier"
fi
export LATE_INCOMING_VERIFIER; LATE_INCOMING_VERIFIER=$(cat "$STATE/late_incoming_verifier")
log "late-incoming verifier $LATE_INCOMING_VERIFIER"
# Later operator runs of the bootstrap source the same file: keep it on this rollup's verifier.
if ! grep -q "^export LATE_INCOMING_VERIFIER=$LATE_INCOMING_VERIFIER\$" "$BOOTSTRAP_ENV"; then
  cp "$BOOTSTRAP_ENV" "$BOOTSTRAP_ENV.before-$REBUILD_ARCHIVE"
  sed "s/^export LATE_INCOMING_VERIFIER=.*/export LATE_INCOMING_VERIFIER=$LATE_INCOMING_VERIFIER/" \
    "$BOOTSTRAP_ENV.before-$REBUILD_ARCHIVE" > "$BOOTSTRAP_ENV"
fi

log "bootstrapping channels (validity check, genesis, live, envelope, close bundle, settlement, registration, exit kit)"
node hosting/wallet/bootstrap-real-chain.js $CHANNELS
log "starting the relay"
sudo systemctl start "$RELAY_SERVICE"
for _ in $(seq 1 600); do curl -skf "$RELAY_HEALTH_URL" > /dev/null && break; sleep 2; done
curl -skf "$RELAY_HEALTH_URL"
echo
log "DONE rollup $ROLLUP"
