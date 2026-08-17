//! Guards the guard: proves the anvil harness's pre-flight port check (layer A, see
//! `tests/anvil_harness/mod.rs`) actually refuses an occupied port instead of failing open.
//!
//! Fast and dependency-free — it binds an OS-assigned ephemeral port, never one of the fixed
//! 8549-8559 ports the heavy E2E tests use, so it is safe to run alongside them.

mod anvil_harness;

use anvil_harness::{AnvilNode, check_port_free};
use std::net::TcpListener;

/// An ephemeral port that nothing is listening on. Never 8549-8559.
fn free_ephemeral_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .expect("bind ephemeral port")
        .local_addr()
        .unwrap()
        .port()
}

#[test]
fn occupied_port_is_refused_with_an_actionable_message() {
    // Hold an ephemeral port exactly the way a stale/orphaned anvil would hold a fixed one.
    let squatter = TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral port");
    let port = squatter.local_addr().unwrap().port();

    let err = check_port_free("anvil_port_guard", port)
        .expect_err("check_port_free must REFUSE a port that is already listening");

    // The message is the whole point: the old "anvil did not come up" sent people chasing anvil,
    // proofs and forge for hours. It must name the port, the test, and the way to find the
    // offending process.
    assert!(
        err.contains(&port.to_string()),
        "message must name the port: {err}"
    );
    assert!(
        err.contains("anvil_port_guard"),
        "message must name the test: {err}"
    );
    assert!(
        err.contains("already in use"),
        "message must say the port is in use: {err}"
    );
    assert!(
        err.contains(&format!("lsof -nP -iTCP:{port}")),
        "message must say how to find the offender: {err}"
    );

    drop(squatter);
}

#[test]
fn free_port_is_accepted() {
    // Fail-closed must not mean fail-always: a port nobody holds has to pass.
    let port = free_ephemeral_port();
    assert!(
        check_port_free("anvil_port_guard", port).is_ok(),
        "an unoccupied port must be accepted"
    );
}

/// Layer B: a node process that dies on startup must be reported as dead, not waited out and not
/// scored as "up". This is the case the old poll got wrong — it only ever asked whether *someone*
/// answered on the port, so a dead child alongside a foreign listener read as success.
#[test]
fn a_node_process_that_dies_is_detected() {
    // `false` exits non-zero immediately: a stand-in for an anvil that cannot bind. No real anvil
    // and no reserved port involved.
    let port = free_ephemeral_port();
    let started = std::time::Instant::now();
    // On the Ok path the node is dropped here, which kills the child.
    let panic = std::panic::catch_unwind(|| {
        AnvilNode::spawn_program("false", "anvil_port_guard", port, &[])
    })
    .err()
    .expect("a node process that exits immediately must NOT be reported as ready");

    let msg = panic.downcast_ref::<String>().cloned().unwrap_or_else(|| {
        panic
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .unwrap_or_default()
    });
    assert!(
        msg.contains("died during startup"),
        "failure must say the spawned node died, not that it 'did not come up': {msg}"
    );
    assert!(
        msg.contains(&port.to_string()),
        "failure must name the port: {msg}"
    );
    // It must notice via try_wait, not by burning the whole readiness budget.
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "death must be detected promptly, not by timing out"
    );
}
