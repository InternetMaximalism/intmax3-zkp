//! `deploy-settlement` MUST pick its forge script from the chain the RPC actually reports.
//!
//! THE DEFECT THIS FILE EXISTS FOR. `cmd_deploy_settlement` hardcoded
//! `script/DeployWalletSettlement.s.sol`. That script wires a `WalletMockMleVerifier` whose
//! `verify` returns **true for any proof**, so every close-intent check on a stack it deploys is
//! vacuous: anyone can close any channel registered with it, to any state, and take the money. The
//! command is reachable from the product's own API (`api/routes/partial-withdrawal.js`,
//! `api/routes/full-withdrawal.js`, `api/routes/settlement.js` all shell out to it with the
//! deployment's configured `RPC`), so pointing the relay at a real network was one config line
//! away from installing a mock verifier on it. The script's own
//! `require(block.chainid == 31337)` would have caught it — as a raw forge revert, after the
//! operator believed the deploy was underway, and only for as long as nobody loosens it.
//!
//! WHAT IS ASSERTED HERE. Every test drives the REAL binary against a fake JSON-RPC endpoint that
//! reports a chosen chain id, exactly as `api/lib/cli.js` drives it (foreign cwd, env only), and
//! checks WHICH deployer the run announced and WHICH precondition it refused on:
//!   * a real chain id never reaches the mock deployer, and refuses on an actionable precondition;
//!   * chain id 31337 still takes the devnet path, unchanged, so the anvil E2Es keep working;
//!   * an unreadable chain id refuses instead of defaulting to either path.
//!
//! WHY THIS IS CHEAP AND STILL MEANINGFUL: every assertion is about what happens BEFORE any
//! transaction is broadcast. That is not a shortcut — "the wrong stack is refused before it is
//! deployed" is precisely the property, so a test that had to deploy first could not express it.
#![cfg(not(debug_assertions))]

use std::{
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

/// The PUBLIC anvil dev account[0] key, verbatim as the CLI knows it.
const ANVIL_DEV_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const TREASURY: &str = "0x00000000000000000000000000000000000f7ea5";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}
fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_channel_member"))
}
fn tool_present(b: &str) -> bool {
    Command::new(b)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// What the fake endpoint answers `eth_chainId` with.
#[derive(Clone, Copy)]
enum Rpc {
    /// A well-formed reply carrying this chain id.
    Chain(u64),
    /// A broken endpoint: the CLI must refuse, not guess.
    Broken,
}

/// A single-purpose JSON-RPC endpoint. Deliberately minimal: the only method the command needs
/// before it makes its decision is `eth_chainId`, and using a fake keeps the decision under test
/// rather than the availability of a node.
struct FakeRpc {
    url: String,
    stop: Arc<AtomicBool>,
}
impl Drop for FakeRpc {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Unblock the accept loop.
        let _ = TcpStream::connect(self.url.trim_start_matches("http://"));
    }
}

fn spawn_rpc(mode: Rpc) -> FakeRpc {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake rpc");
    let url = format!("http://{}", listener.local_addr().unwrap());
    let stop = Arc::new(AtomicBool::new(false));
    let stop_t = stop.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            if stop_t.load(Ordering::SeqCst) {
                return;
            }
            let Ok(mut s) = stream else { continue };
            let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
            let mut buf = [0u8; 8192];
            let n = s.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let id = req
                .split("\"id\":")
                .nth(1)
                .and_then(|r| {
                    let d: String = r
                        .trim_start()
                        .chars()
                        .take_while(|c| c.is_ascii_digit())
                        .collect();
                    d.parse::<u64>().ok()
                })
                .unwrap_or(0);
            let body = match mode {
                Rpc::Chain(id_chain) => {
                    format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":\"0x{id_chain:x}\"}}")
                }
                Rpc::Broken => String::from("not json at all"),
            };
            let status = match mode {
                Rpc::Chain(_) => "200 OK",
                Rpc::Broken => "500 Internal Server Error",
            };
            let resp = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = s.write_all(resp.as_bytes());
            let _ = s.flush();
        }
    });
    FakeRpc { url, stop }
}

/// A per-test work dir OUTSIDE the repo — the shape `api/lib/cli.js` uses
/// (`wallet-live-work/chN`): no `contracts/`, no state, env only.
struct WorkDir(PathBuf);
impl Drop for WorkDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn work_dir(tag: &str) -> WorkDir {
    let d = std::env::temp_dir().join(format!(
        "intmax3-deploy-sel-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).expect("create work dir");
    WorkDir(d)
}

/// Run `deploy-settlement <fake rpc>` the way the product drivers do. Returns (success, output).
fn deploy_settlement(cwd: &std::path::Path, rpc: &str, envs: &[(&str, &str)]) -> (bool, String) {
    let mut cmd = Command::new(bin());
    cmd.args(["deploy-settlement", rpc])
        .current_dir(cwd)
        .env("INTMAX_CHANNEL", "7")
        // The contracts checkout is provided explicitly so these tests exercise the SELECTION,
        // not the checkout resolution (which `exit_path_cwd.rs` covers).
        .env("CONTRACTS_DIR", repo_root().join("contracts"))
        .env_remove("FRAUD_TREASURY")
        .env_remove("INTMAX_DEPOSIT_KEY")
        .env_remove("INTMAX_L1_ACCOUNT")
        .env_remove("ETH_PASSWORD")
        .env_remove("INTMAX_COSIGNER_KEYFILE")
        .env_remove("INTMAX_INSECURE_DETERMINISTIC_KEYS");
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("spawn channel_member");
    let mut s = String::from_utf8_lossy(&out.stdout).to_string();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.success(), s)
}

/// THE assertion this whole file is built around: on a chain that is not the local devnet, the
/// mock deployer must not be named, announced, staged for, or run — at any point, for any reason.
fn assert_no_mock_anywhere(out: &str, chain_id: u64) {
    assert!(
        !out.contains("DeployWalletSettlement"),
        "chain id {chain_id}: the run mentioned the MOCK deployer (always-true MLE verifier):\n{out}"
    );
    assert!(
        !out.contains("devnet-mock"),
        "chain id {chain_id}: the run selected the devnet-mock plan:\n{out}"
    );
}

/// Sepolia. No `FRAUD_TREASURY` — the run must reach the REAL-chain plan and stop on a named,
/// actionable precondition instead of falling back to the mock script or surfacing raw forge
/// output.
///
/// MUTATION SENSITIVITY: reintroducing the hardcoded `DeployWalletSettlement.s.sol` fails this
/// test three times over — the announcement, the mock-name ban, and the FRAUD_TREASURY message.
#[test]
fn a_real_chain_id_selects_the_real_deployer_and_names_its_preconditions() {
    if !tool_present("cast") {
        eprintln!("[skip] foundry `cast` not found — the chain id is read with it");
        return;
    }
    let rpc = spawn_rpc(Rpc::Chain(11155111));
    let w = work_dir("sepolia");
    let (ok, out) = deploy_settlement(&w.0, &rpc.url, &[]);
    assert!(!ok, "a deploy with no FRAUD_TREASURY must fail:\n{out}");
    assert!(
        out.contains("chain id 11155111 → plan: real-chain (script/DeployCloseCli.s.sol)"),
        "the run must announce the real-chain plan it chose:\n{out}"
    );
    assert!(
        out.contains("FRAUD_TREASURY"),
        "the refusal must name the missing variable:\n{out}"
    );
    assert_no_mock_anywhere(&out, 11155111);
}

/// Mainnet, Base, Arbitrum, Optimism, Polygon, Holesky, and two ids adjacent to anvil's. One
/// chain id being handled correctly is not the property — "every chain that is not 31337" is.
#[test]
fn no_real_chain_id_can_reach_the_mock_deployer() {
    if !tool_present("cast") {
        eprintln!("[skip] foundry `cast` not found");
        return;
    }
    for chain in [1u64, 10, 137, 8453, 42161, 17000, 31336, 31338] {
        let rpc = spawn_rpc(Rpc::Chain(chain));
        let w = work_dir(&format!("chain{chain}"));
        let (ok, out) = deploy_settlement(&w.0, &rpc.url, &[]);
        assert!(
            !ok,
            "chain {chain}: must not succeed without preconditions:\n{out}"
        );
        assert!(
            out.contains(&format!("chain id {chain} → plan: real-chain")),
            "chain {chain}: wrong plan announced:\n{out}"
        );
        assert_no_mock_anywhere(&out, chain);
    }
}

/// The anvil path must be untouched: chain id 31337 still selects the devnet deployer and still
/// fails exactly where it always did — on the missing channel state — so
/// `partial_withdrawal_e2e` and the wallet demo keep working.
#[test]
fn the_devnet_chain_id_still_selects_the_devnet_deployer() {
    if !tool_present("cast") {
        eprintln!("[skip] foundry `cast` not found");
        return;
    }
    let rpc = spawn_rpc(Rpc::Chain(31337));
    let w = work_dir("anvil");
    let (ok, out) = deploy_settlement(
        &w.0,
        &rpc.url,
        &[("INTMAX_INSECURE_DETERMINISTIC_KEYS", "1")],
    );
    assert!(!ok, "there is no channel state in this dir:\n{out}");
    assert!(
        out.contains("chain id 31337 → plan: devnet-mock (script/DeployWalletSettlement.s.sol)"),
        "anvil must keep the devnet stack:\n{out}"
    );
    // It proceeded into the ORIGINAL devnet body (which loads channel state first) — i.e. the
    // anvil path is the same code it always was, not a new branch.
    assert!(
        out.contains("cli_state.json")
            || out.contains("no deposit backing")
            || out.contains("state"),
        "the devnet path must fail in its own body, on the missing state:\n{out}"
    );
}

/// An endpoint we cannot read a chain id from must abort. Guessing — in either direction — is the
/// bug: guessing "devnet" installs a mock verifier on an unknown chain.
#[test]
fn an_unreadable_chain_id_is_refused_rather_than_guessed() {
    if !tool_present("cast") {
        eprintln!("[skip] foundry `cast` not found");
        return;
    }
    let rpc = spawn_rpc(Rpc::Broken);
    let w = work_dir("broken");
    let (ok, out) = deploy_settlement(&w.0, &rpc.url, &[]);
    assert!(!ok, "an unreadable chain id must abort:\n{out}");
    assert!(
        !out.contains("plan: devnet-mock") && !out.contains("DeployWalletSettlement"),
        "an unreadable chain id must never select the mock stack:\n{out}"
    );
}

/// The real-chain path must refuse every raw key, including the PUBLIC anvil dev key. A secret in
/// `--private-key <secret>` is readable from the child process' argv.
#[test]
fn the_real_chain_path_refuses_the_public_anvil_dev_key() {
    if !tool_present("cast") {
        eprintln!("[skip] foundry `cast` not found");
        return;
    }
    let rpc = spawn_rpc(Rpc::Chain(11155111));
    let w = work_dir("anvilkey");
    let (ok, out) = deploy_settlement(
        &w.0,
        &rpc.url,
        &[
            ("FRAUD_TREASURY", TREASURY),
            ("INTMAX_DEPOSIT_KEY", ANVIL_DEV_KEY),
        ],
    );
    assert!(!ok, "the public dev key must be refused:\n{out}");
    assert!(
        out.contains("raw private keys") && out.contains("process argv"),
        "the refusal must say WHY:\n{out}"
    );
    assert_no_mock_anywhere(&out, 11155111);
}

/// …and it must refuse an absent keystore account rather than silently falling back to the public
/// Anvil key or accepting a raw private key.
#[test]
fn the_real_chain_path_refuses_an_absent_deploy_key() {
    if !tool_present("cast") {
        eprintln!("[skip] foundry `cast` not found");
        return;
    }
    let rpc = spawn_rpc(Rpc::Chain(11155111));
    let w = work_dir("nokey");
    let (ok, out) = deploy_settlement(&w.0, &rpc.url, &[("FRAUD_TREASURY", TREASURY)]);
    assert!(!ok, "a missing deploy key must be refused:\n{out}");
    assert!(
        out.contains("INTMAX_L1_ACCOUNT is not set") && out.contains("process argv"),
        "the refusal must name the variable:\n{out}"
    );
    assert_no_mock_anywhere(&out, 11155111);
}

/// Registering a channel whose co-signer SECRET keys are publicly derivable is fund-fatal: anyone
/// can mint the N-of-N signatures a close needs. Convenient on anvil, catastrophic anywhere else.
#[test]
fn the_real_chain_path_refuses_publicly_derivable_cosigner_keys() {
    if !tool_present("cast") {
        eprintln!("[skip] foundry `cast` not found");
        return;
    }
    let rpc = spawn_rpc(Rpc::Chain(11155111));
    let w = work_dir("insecurekeys");
    let (ok, out) = deploy_settlement(
        &w.0,
        &rpc.url,
        &[
            ("FRAUD_TREASURY", TREASURY),
            ("INTMAX_L1_ACCOUNT", "test-security-review"),
            ("INTMAX_INSECURE_DETERMINISTIC_KEYS", "1"),
        ],
    );
    assert!(
        !ok,
        "publicly derivable keys must be refused off-devnet:\n{out}"
    );
    assert!(
        out.contains("publicly derivable"),
        "the refusal must say WHY:\n{out}"
    );
    assert_no_mock_anywhere(&out, 11155111);
}

/// `DeployCloseCli.s.sol` deploys its OWN rollup. Running it for a channel that is already backed
/// would leave the deposit on the old rollup and the registration + manager + exit path on the new
/// one — a break the user would only discover at `withdraw`, after paying for the proofs.
#[test]
fn the_real_chain_path_refuses_to_orphan_an_existing_backing() {
    if !tool_present("cast") {
        eprintln!("[skip] foundry `cast` not found");
        return;
    }
    let rpc = spawn_rpc(Rpc::Chain(11155111));
    let w = work_dir("backed");
    std::fs::write(
        w.0.join("channel_backing.json"),
        r#"{"rollup":"0x000000000000000000000000000000000000b0b0"}"#,
    )
    .expect("write backing");
    let (ok, out) = deploy_settlement(
        &w.0,
        &rpc.url,
        &[
            ("FRAUD_TREASURY", TREASURY),
            ("INTMAX_L1_ACCOUNT", "test-orphan-guard"),
        ],
    );
    assert!(!ok, "a backed channel must not get a second rollup:\n{out}");
    assert!(
        out.contains("already backed")
            && out.contains("0x000000000000000000000000000000000000b0b0"),
        "the refusal must name the rollup that holds the money:\n{out}"
    );
    assert!(
        out.contains("setup-backing"),
        "the refusal must state the correct ordering:\n{out}"
    );
    assert_no_mock_anywhere(&out, 11155111);
}

/// A stack already recorded for this channel must not be silently replaced: a second real-chain
/// deploy strands the first rollup, its registration and anything already deposited into it.
#[test]
fn the_real_chain_path_refuses_to_replace_an_existing_settlement_json() {
    if !tool_present("cast") {
        eprintln!("[skip] foundry `cast` not found");
        return;
    }
    let rpc = spawn_rpc(Rpc::Chain(11155111));
    let w = work_dir("existing");
    std::fs::write(
        w.0.join("settlement.json"),
        r#"{"manager":"0x00000000000000000000000000000000000000aa","verifier":"0x00000000000000000000000000000000000000bb","rollup":"0x00000000000000000000000000000000000000cc"}"#,
    )
    .expect("write settlement.json");
    let (ok, out) = deploy_settlement(
        &w.0,
        &rpc.url,
        &[
            ("FRAUD_TREASURY", TREASURY),
            ("INTMAX_L1_ACCOUNT", "test-existing-guard"),
        ],
    );
    assert!(!ok, "a second stack must be refused:\n{out}");
    assert!(
        out.contains("settlement.json already exists"),
        "the refusal must name the file:\n{out}"
    );
    assert_no_mock_anywhere(&out, 11155111);
}
