#!/usr/bin/env bash
# Deploy the COMMITTED tree to a relay host, reproducibly, and prove the host runs exactly it.
#
# Until now the testnet host was updated by scp-ing individual files and rebuilding by hand, so
# nothing guaranteed that the host ran what the repository says (a root package.json existed
# only on the host; single files lagged). This ships `git archive HEAD`, verifies every tracked
# file on the host against a sha256 manifest of that commit, installs the declared Node
# dependencies, builds the binaries with the protocol feature, refreshes the public files and
# restarts the relay, then waits for its health endpoint.
#
# Usage: DEPLOY_HOST=user@host DEPLOY_KEY=path/to/key.pem hosting/wallet/deploy-relay-host.sh
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
echo "$REV" > "$WORKDIR/REVISION"

"${SCP[@]}" "$WORKDIR/tree.tar.gz" "$WORKDIR/manifest.sha256" "$WORKDIR/submodules.sha256" "$WORKDIR/REVISION" "$HOST:/tmp/"
"${SSH[@]}" "DIR=$DIR bash -s" <<'REMOTE'
set -euo pipefail
export PATH="$HOME/.foundry/bin:$HOME/.cargo/bin:$PATH"
cd "$HOME/$DIR"
echo "[deploy] stopping the relay"
sudo systemctl stop intmax-wallet-relay
tar -xzf /tmp/tree.tar.gz -C .
echo "[deploy] verifying $(wc -l < /tmp/manifest.sha256) tracked files against the commit"
sha256sum --quiet -c /tmp/manifest.sha256
echo "[deploy] verifying $(wc -l < /tmp/submodules.sha256) submodule files against the pinned checkout"
sha256sum --quiet -c /tmp/submodules.sha256
echo "[deploy] node dependencies (declared manifests only)"
(cd hosting/wallet && npm ci --ignore-scripts --no-audit --no-fund > /dev/null)
(cd node && npm ci --ignore-scripts --no-audit --no-fund > /dev/null)
echo "[deploy] building binaries (authenticated-tail-receive)"
cargo build --release --locked --features authenticated-tail-receive \
  --bin channel_member --bin block_producer_service --bin public_close_prover > /tmp/deploy-build.log 2>&1 \
  || { tail -30 /tmp/deploy-build.log; exit 1; }
echo "[deploy] contracts-tail sources (its test/data keeps the feature-built configs)"
rsync -a --delete --exclude 'test/data/' --exclude 'broadcast/' --exclude 'cache/' --exclude 'out/' contracts/ contracts-tail/
echo "[deploy] public files"
cp hosting/wallet/wallet-live.html hosting/wallet/public/index.html
cp hosting/wallet/wallet-worker.js hosting/wallet/signature-release-ledger.mjs \
  hosting/wallet/wallet-outbox.js hosting/wallet/wallet-transactions.js hosting/wallet/public/
cp /tmp/REVISION DEPLOYED_REVISION
echo "[deploy] starting the relay"
sudo systemctl start intmax-wallet-relay
for _ in $(seq 1 60); do curl -skf https://localhost/api/health > /dev/null && break; sleep 2; done
curl -skf https://localhost/api/health
echo
echo "[deploy] running $(cat DEPLOYED_REVISION)"
REMOTE
