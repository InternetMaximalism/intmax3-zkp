//! Shared anvil spawn + readiness harness for the integration tests that drive a real local node.
//!
//! # Why this exists (do not "simplify" it back)
//!
//! Every anvil-driving test used to spawn anvil on its own hardcoded port and then "wait for it"
//! by polling `cast block-number --rpc-url http://127.0.0.1:<port>` until the command succeeded.
//! That check is FAIL-OPEN: a successful `cast block-number` proves *some* node answers on that
//! port — it does not prove the node is the one we just spawned.
//!
//! The failure mode this caused, repeatedly:
//!   1. a stale/orphaned anvil (aborted earlier run) or a second concurrent copy of the same test
//!      is already listening on the port;
//!   2. the freshly spawned anvil cannot bind, prints "Address already in use" to a /dev/null
//!      stderr, and exits within milliseconds;
//!   3. the readiness poll succeeds anyway — against the FOREIGN node;
//!   4. the test proceeds against a chain carrying unrelated state and then hangs forever in `forge
//!      script --broadcast`, or dies with `nonce too low`.
//!
//! It never presented as a port conflict; it presented as a mysterious multi-hour hang. So the
//! readiness check here is deliberately three-layered, and each layer answers a different
//! question:
//!   A. `check_port_free` — is the port free BEFORE we spawn? A pre-existing listener is an
//!      environment fault to be reported immediately, never something to wait out.
//!   B. `try_wait` inside the poll loop — is OUR child still alive? A dead child plus a foreign
//!      listener is exactly the case the old `status().success()` poll scored as "up".
//!   C. genesis-height check — is the chain the one we just created (block 0)? Defence in depth
//!      for the TOCTOU window between A and the spawn.
//!
//! Layers A and B are authoritative. Layer C is advisory-but-enforced: it is only sound because
//! anvil under automine mines nothing until a transaction arrives, and nothing touches the node
//! between spawn and this check — so it is skipped when the caller passes flags that legitimately
//! start the chain above genesis (see `SKIPS_GENESIS_CHECK`).
//!
//! anvil's stdout/stderr stay on /dev/null on purpose: anvil logs every RPC call, and a piped
//! stderr that nobody drains fills its buffer and blocks the node mid-test. The pre-flight port
//! check exists precisely so we do not need to read anvil's own "Address already in use".

#![allow(dead_code)] // Not every consumer of this module uses every accessor.

use std::{
    io::ErrorKind,
    net::TcpListener,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

/// Same budget as the hand-rolled loops this replaced (40 polls x 250ms).
const READY_TIMEOUT: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// anvil flags that legitimately put the chain above block 0 at startup, which makes the
/// genesis-height check (layer C) inapplicable. Layers A and B still apply.
const SKIPS_GENESIS_CHECK: &[&str] = &[
    "--block-time",
    "-b",
    "--fork-url",
    "-f",
    "--fork-block-number",
    "--load-state",
    "--state",
];

/// A local anvil owned by this test process. Killed on drop, including on panic unwind.
pub struct AnvilNode {
    child: Child,
    port: u16,
    rpc: String,
}

impl AnvilNode {
    /// Spawn a dedicated anvil on `port` and return only once it is proven to be OURS.
    ///
    /// `--hardfork prague --port <port>` is always supplied; `extra_args` is appended verbatim
    /// (e.g. `["--base-fee", "0"]`). `test_name` only shapes the failure messages.
    ///
    /// Panics — loudly and specifically — if the port is already taken, if the spawned anvil dies,
    /// if it never answers, or if the chain that answers is not at genesis.
    pub fn spawn(test_name: &str, port: u16, extra_args: &[&str]) -> Self {
        Self::spawn_program("anvil", test_name, port, extra_args)
    }

    /// `spawn` with the node binary injectable, so `tests/anvil_port_guard.rs` can exercise the
    /// child-died path (layer B) with a program that exits immediately, instead of needing a real
    /// anvil and one of the reserved ports.
    pub fn spawn_program(program: &str, test_name: &str, port: u16, extra_args: &[&str]) -> Self {
        if let Err(msg) = check_port_free(test_name, port) {
            panic!("{msg}");
        }

        let mut cmd = Command::new(program);
        cmd.args(["--hardfork", "prague", "--port", &port.to_string()])
            .args(extra_args)
            // See the module comment: piping anvil's chatty output and never draining it would
            // block the node.
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = cmd.spawn().unwrap_or_else(|e| {
            panic!("[{test_name}] failed to spawn `{program}` on port {port}: {e}")
        });

        let mut node = Self {
            child,
            port,
            rpc: format!("http://127.0.0.1:{port}"),
        };
        let skip_genesis = extra_args.iter().any(|a| {
            SKIPS_GENESIS_CHECK
                .iter()
                .any(|f| *a == *f || a.starts_with(&format!("{f}=")))
        });
        node.wait_until_ours(test_name, skip_genesis);
        node
    }

    pub fn rpc(&self) -> &str {
        &self.rpc
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Kill the child before panicking, so a failure here can never leave the orphan that causes
    /// the next run's port conflict. (Drop would also do this on unwind, but not under
    /// `panic = "abort"`, and an orphan is the precise disease this module treats.)
    fn die(&mut self, msg: String) -> ! {
        let _ = self.child.kill();
        let _ = self.child.wait();
        panic!("{msg}");
    }

    fn wait_until_ours(&mut self, test_name: &str, skip_genesis: bool) {
        let started = Instant::now();
        let port = self.port;
        let rpc = self.rpc.clone();

        let block = loop {
            // Layer B, checked BEFORE the RPC probe: if our child is gone, any answer on this port
            // is somebody else's node.
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    let held = port_is_busy(port);
                    let culprit = if held {
                        format!(
                            "Port {port} is STILL held, so a DIFFERENT process owns it — it was \
                             taken between the pre-flight check and this spawn (most likely a \
                             second, concurrent run of `{test_name}`). Find and stop it:\n    \
                             lsof -nP -iTCP:{port} -sTCP:LISTEN"
                        )
                    } else {
                        format!(
                            "Port {port} is now free, so this is not a port conflict — anvil \
                             itself failed to start. Check `anvil --version` and re-run the same \
                             flags by hand (this harness sends anvil's output to /dev/null)."
                        )
                    };
                    self.die(format!(
                        "[{test_name}] the anvil THIS TEST SPAWNED on port {port} died during \
                         startup after {:.1}s ({status}).\n{culprit}\nNOTE: the test cannot \
                         continue — a surviving listener on this port would serve an unrelated \
                         chain and every assertion below assumes a fresh one.",
                        started.elapsed().as_secs_f64()
                    ));
                }
                Ok(None) => {}
                Err(e) => self.die(format!(
                    "[{test_name}] could not check whether the spawned anvil (port {port}) is \
                     still alive: {e}"
                )),
            }

            if let Some(block) = query_block_number(&rpc) {
                // Close the window where the child died between the try_wait above and this
                // answer: re-confirm ownership before accepting the response.
                if let Ok(Some(status)) = self.child.try_wait() {
                    self.die(format!(
                        "[{test_name}] port {port} answered `cast block-number` (block \
                         {block:?}), but the anvil THIS TEST SPAWNED is dead ({status}) — the \
                         node answering belongs to another process.\n    lsof -nP -iTCP:{port} \
                         -sTCP:LISTEN"
                    ));
                }
                break block;
            }

            if started.elapsed() >= READY_TIMEOUT {
                self.die(format!(
                    "[{test_name}] the anvil this test spawned on port {port} is ALIVE but never \
                     answered `cast block-number --rpc-url {rpc}` within {:.0}s.\nThis is not a \
                     port conflict (the port was free before the spawn and our process is still \
                     running) — anvil is wedged or the host is badly overloaded. Re-run anvil with \
                     these flags by hand to see its output.",
                    READY_TIMEOUT.as_secs_f64()
                ));
            }
            thread::sleep(POLL_INTERVAL);
        };

        // Layer C. Only meaningful because nothing has touched this node yet and anvil under
        // automine mines no blocks until a transaction arrives.
        if !skip_genesis {
            match block {
                Some(0) => {}
                Some(n) => self.die(format!(
                    "[{test_name}] the node answering on port {port} is at block {n}, not the \
                     genesis block 0 — it is NOT the anvil this test just spawned (a stale or \
                     foreign node holds the port), or it was started with pre-existing \
                     state.\nEvery assertion below assumes a fresh chain, so this run would be \
                     meaningless. Find the offender:\n    lsof -nP -iTCP:{port} -sTCP:LISTEN"
                )),
                // Unparseable output: layers A and B already established ownership, so warn
                // rather than fail on a `cast` output-format change.
                None => eprintln!(
                    "[{test_name}] warning: could not parse `cast block-number` output on port \
                     {port}; skipping the genesis-height cross-check."
                ),
            }
        }
    }
}

impl Drop for AnvilNode {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Layer A. `Ok(())` iff nothing is listening on 127.0.0.1:`port`; otherwise the exact message the
/// caller should fail with. Returned rather than panicked so it is unit-testable.
pub fn check_port_free(test_name: &str, port: u16) -> Result<(), String> {
    match TcpListener::bind(("127.0.0.1", port)) {
        Ok(listener) => {
            drop(listener);
            Ok(())
        }
        Err(e) if e.kind() == ErrorKind::AddrInUse => Err(format!(
            "[{test_name}] port {port} is already in use by another process — refusing to \
             start.\nThis test spawns its OWN anvil on 127.0.0.1:{port} and every assertion \
             below assumes a FRESH chain. A pre-existing listener means either a stale anvil \
             orphaned by an aborted run, or a second copy of this test running concurrently. \
             Waiting it out is not an option: the anvil we spawn would fail to bind and die, the \
             readiness poll would succeed against the FOREIGN node, and the run would hang in \
             `forge script --broadcast` or fail with `nonce too low`.\nFind the offender and stop \
             it, then re-run:\n    lsof -nP -iTCP:{port} -sTCP:LISTEN\n    kill <pid>\n(bind \
             error: {e})"
        )),
        Err(e) => Err(format!(
            "[{test_name}] could not test-bind 127.0.0.1:{port} before spawning anvil: {e}\n\
             Refusing to spawn, because we cannot tell whether the port is free — a foreign node \
             on this port would make every assertion below meaningless."
        )),
    }
}

fn port_is_busy(port: u16) -> bool {
    matches!(TcpListener::bind(("127.0.0.1", port)), Err(e) if e.kind() == ErrorKind::AddrInUse)
}

/// `Some(Some(height))` on a parsed answer, `Some(None)` when the node answered but the height did
/// not parse, `None` when the node did not answer at all.
fn query_block_number(rpc: &str) -> Option<Option<u64>> {
    let out = Command::new("cast")
        .args(["block-number", "--rpc-url", rpc])
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(
        String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse::<u64>()
            .ok(),
    )
}
