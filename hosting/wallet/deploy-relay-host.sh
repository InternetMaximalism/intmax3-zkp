#!/usr/bin/env bash
# Deploy the COMMITTED tree to a relay host, reproducibly, and prove the host runs exactly it.
#
# Until now the testnet host was updated by scp-ing individual files and rebuilding by hand, so
# nothing guaranteed that the host ran what the repository says (a root package.json existed
# only on the host; single files lagged). This ships `git archive HEAD` and the pinned tree of every
# submodule, verifies every tracked file on the host against a sha256 manifest of that commit (and
# of the pinned submodule commits), installs the declared Node
# dependencies, builds the binaries with the protocol feature, refreshes the public files and the
# browser wasm package and restarts the relay, then waits for its health endpoint.
#
# The wasm package (pkg/, not tracked) is built HERE from the same clean tree with
# hosting/build-wallet-wasm.sh and verified on the host against its own sha256 manifest: the
# browser proves against the binaries it ships with, and a package left from an earlier deploy
# would keep running old wallet code next to new binaries.
#
# Usage: DEPLOY_HOST=user@host DEPLOY_KEY=path/to/key.pem hosting/wallet/deploy-relay-host.sh
# A release whose circuits changed cannot finalize on the deployed rollup (its verifiers are pinned
# and immutable): deploy it with DEPLOY_NEW_ROLLUP=1, which installs the tree and binaries, skips
# the re-verification against the rollup being replaced and leaves the relay STOPPED; then run
# hosting/wallet/rebuild-public-rollup.sh on the host, which rebuilds on a new rollup and starts it.
# Host layout (see doc/docs/deploy-runbook.md, public-testnet bring-up): ~/intmax3-zkp with its
# submodules checked out, contracts-tail/ (contracts + feature-built test/data), wallet-live-work/,
# systemd unit intmax-wallet-relay with EnvironmentFile ~/relay/relay.env.
set -euo pipefail

HOST="${DEPLOY_HOST:?set DEPLOY_HOST=user@host}"
KEY="${DEPLOY_KEY:?set DEPLOY_KEY to the ssh key}"
DIR="${REMOTE_DIR:-intmax3-zkp}"
SSH=(ssh -i "$KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$HOST")
SCP=(scp -i "$KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
cd "$(dirname "$0")/../.."

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "uncommitted changes: deploy a commit, not a working tree" >&2; exit 1
fi
REV=$(git rev-parse HEAD)
WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT
git archive --format=tar.gz -o "$WORKDIR/tree.tar.gz" HEAD
# Regular tracked files only, of the repository and (recursively) of its submodules: submodules
# are not in the archive and the host has no .git, so their CONTENT is verified against the pinned
# checkout here, which must itself be at the pinned commits. NUL-separated: paths contain spaces.
if git submodule status --recursive | grep -q '^[-+U]'; then
  echo "submodules are not checked out at their pinned commits" >&2; exit 1
fi
python3 - "$WORKDIR" <<'PY'
import hashlib, os, subprocess, sys
out = sys.argv[1]
def tracked(prefix):
    raw = subprocess.run(["git", "-C", prefix or ".", "ls-files", "-s", "-z"], check=True, capture_output=True).stdout
    for entry in raw.split(b"\0"):
        if not entry:
            continue
        meta, path = entry.split(b"\t", 1)
        if meta.split()[0] == b"160000":
            continue
        yield os.path.join(prefix, path.decode()) if prefix else path.decode()
def digest(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()
subs = subprocess.run(["git", "submodule", "foreach", "--recursive", "--quiet", "echo $displaypath"],
                      check=True, capture_output=True, text=True).stdout.split("\n")
for name, prefixes in (("manifest.sha256", [""]), ("submodules.sha256", [s for s in subs if s])):
    with open(os.path.join(out, name), "w") as manifest:
        for prefix in prefixes:
            for path in tracked(prefix):
                if os.path.islink(path):
                    continue
                manifest.write(f"{digest(path)}  {path}\n")
PY
# Submodules are not in `git archive HEAD`, and the host has no .git to fetch them with: ship the
# pinned tree of each one, so a submodule bump reaches the host. The host checks the trees against
# submodules.sha256 in a staging directory before it replaces its checkouts with them.
mkdir "$WORKDIR/sub"
git submodule foreach --recursive --quiet \
  "git archive --format=tar --prefix=\"\$displaypath/\" HEAD | tar -xf - -C '$WORKDIR/sub'"
COPYFILE_DISABLE=1 tar --no-xattrs -czf "$WORKDIR/submodules.tar.gz" -C "$WORKDIR/sub" .
git submodule foreach --quiet 'echo "$displaypath"' > "$WORKDIR/submodule-paths"
echo "$REV" > "$WORKDIR/REVISION"
echo "[deploy] building the browser wasm package from $REV"
hosting/build-wallet-wasm.sh > "$WORKDIR/wasm-build.log" 2>&1 || { tail -30 "$WORKDIR/wasm-build.log"; exit 1; }
# No AppleDouble (._*) entries or xattr headers: GNU tar on the host would extract them as files.
COPYFILE_DISABLE=1 tar --no-xattrs -czf "$WORKDIR/pkg.tar.gz" -C pkg .
(cd pkg && find . -type f -print0 | sort -z | xargs -0 shasum -a 256) > "$WORKDIR/pkg.sha256"

"${SCP[@]}" "$WORKDIR/tree.tar.gz" "$WORKDIR/manifest.sha256" "$WORKDIR/submodules.sha256" "$WORKDIR/REVISION" \
  "$WORKDIR/submodules.tar.gz" "$WORKDIR/submodule-paths" "$WORKDIR/pkg.tar.gz" "$WORKDIR/pkg.sha256" "$HOST:/tmp/"
"${SSH[@]}" "DIR=$DIR NEW_ROLLUP=${DEPLOY_NEW_ROLLUP:-0} bash -s" <<'REMOTE'
set -euo pipefail
export PATH="$HOME/.foundry/bin:$HOME/.cargo/bin:$PATH"
cd "$HOME/$DIR"
# Everything that can fail runs while the old relay still serves; it is stopped only for the
# short swap at the end. Sources and binaries replaced under a running relay are compatible for
# that window: its JavaScript is already loaded, the daemon keeps its executable's old inode, and
# a CLI change must stay command-compatible with the previous relay (review it as such).
echo "[deploy] verifying $(wc -l < /tmp/submodules.sha256) submodule files of the pinned commits"
rm -rf /tmp/deploy-sub && mkdir /tmp/deploy-sub && tar -xzf /tmp/submodules.tar.gz -C /tmp/deploy-sub
(cd /tmp/deploy-sub && sha256sum --quiet -c /tmp/submodules.sha256)
[ "$(cd /tmp/deploy-sub && find . -type f | wc -l)" = "$(wc -l < /tmp/submodules.sha256)" ] \
  || { echo "[deploy] the submodule trees hold files outside their manifest" >&2; exit 1; }
tar -xzf /tmp/tree.tar.gz -C .
echo "[deploy] verifying $(wc -l < /tmp/manifest.sha256) tracked files against the commit"
sha256sum --quiet -c /tmp/manifest.sha256
# Replace each submodule checkout with its verified tree, so files a bump removed go too. `.git`
# entries are left alone: they point into the machine the host was provisioned from.
while read -r sub; do
  mkdir -p "$sub" && rsync -a --delete --exclude .git "/tmp/deploy-sub/$sub/" "$sub/"
done < /tmp/submodule-paths
sha256sum --quiet -c /tmp/submodules.sha256
echo "[deploy] verifying $(wc -l < /tmp/pkg.sha256) wasm package files"
rm -rf /tmp/deploy-pkg && mkdir /tmp/deploy-pkg && tar -xzf /tmp/pkg.tar.gz -C /tmp/deploy-pkg
(cd /tmp/deploy-pkg && sha256sum --quiet -c /tmp/pkg.sha256)
[ "$(cd /tmp/deploy-pkg && find . -type f | wc -l)" = "$(wc -l < /tmp/pkg.sha256)" ] \
  || { echo "[deploy] the wasm package holds files outside its manifest" >&2; exit 1; }
echo "[deploy] node dependencies (declared manifests only)"
(cd hosting/wallet && npm ci --ignore-scripts --no-audit --no-fund > /dev/null)
(cd node && npm ci --ignore-scripts --no-audit --no-fund > /dev/null)
echo "[deploy] building binaries (authenticated-tail-receive)"
cargo build --release --locked --features authenticated-tail-receive \
  --bin channel_member --bin block_producer_service --bin public_close_prover > /tmp/deploy-build.log 2>&1 \
  || { tail -30 /tmp/deploy-build.log; exit 1; }
# A rollup verified to finalize the producer's blocks stays verified only for the binaries that were
# checked (api/lib/validity-deployment.js). Re-verify the new build before it serves, so a build
# whose validity circuits no longer match the deployed rollup never goes live. Without a record the
# deployment offers no deposits and there is nothing to re-verify.
WORK_DIR=$(grep -h '^INTMAX_WORK_DIR=' "$HOME/relay/relay.env" | cut -d= -f2- || true)
if [ "$NEW_ROLLUP" = 1 ]; then
  echo "[deploy] DEPLOY_NEW_ROLLUP=1: not re-verifying against the rollup being replaced"
elif [ -f "${WORK_DIR:-$HOME/$DIR/wallet-live-work}/producer/validity-deployment.json" ]; then
  echo "[deploy] re-verifying the rollup's validity verifier against the new build"
  (set -a; . "$HOME/relay/relay.env"; set +a; node hosting/wallet/verify-validity-deployment.js > /tmp/deploy-verify.log 2>&1) || {
    tail -5 /tmp/deploy-verify.log
    echo "[deploy] ABORTED before the swap: the new build does not finalize on the deployed rollup. The running relay keeps serving; restarted on these binaries it would refuse deposits." >&2
    exit 1
  }
fi
echo "[deploy] swapping: stopping the relay"
sudo systemctl stop intmax-wallet-relay
rsync -a --delete --exclude 'test/data/' --exclude 'broadcast/' --exclude 'cache/' --exclude 'out/' contracts/ contracts-tail/
# Compile from scratch, as the rehearsal does: an incremental Foundry cache kept across source
# updates once left a stale CloseFundingMaterializer artifact that the deploy script's creation
# code no longer matched, and forge refused the settlement deploy ("ABI decoding failed").
rm -rf contracts-tail/out contracts-tail/cache
cp hosting/wallet/wallet-live.html hosting/wallet/public/index.html
cp hosting/wallet/wallet-worker.js hosting/wallet/signature-release-ledger.mjs \
  hosting/wallet/wallet-outbox.js hosting/wallet/wallet-transactions.js hosting/wallet/public/
PKG_DIR=$(grep -h '^RELAY_PKG_DIR=' "$HOME/relay/relay.env" | cut -d= -f2- || true)
PKG_DIR="${PKG_DIR:-$HOME/$DIR/pkg}"
mkdir -p "$PKG_DIR"
rsync -a --delete /tmp/deploy-pkg/ "$PKG_DIR/"
echo "[deploy] wasm package installed in $PKG_DIR"
cp /tmp/REVISION DEPLOYED_REVISION
if [ "$NEW_ROLLUP" = 1 ]; then
  echo "[deploy] installed $(cat DEPLOYED_REVISION); the relay stays stopped. Next, on the host:"
  echo "  REBUILD_ARCHIVE=<name> nohup hosting/wallet/rebuild-public-rollup.sh > ~/relay/rebuild.log 2>&1 &"
  exit 0
fi
sudo systemctl start intmax-wallet-relay
for _ in $(seq 1 60); do curl -skf https://localhost/api/health > /dev/null && break; sleep 2; done
curl -skf https://localhost/api/health
echo
echo "[deploy] running $(cat DEPLOYED_REVISION)"
REMOTE
