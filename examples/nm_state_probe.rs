//! Probe for whether a monitor session preserves NetworkManager's `Managed`
//! state, or forces the interface back under management on the way out.
//!
//! `rfmon` releases an interface by setting NetworkManager's `Managed` property
//! to `false`, and reclaims it by setting `true`. That second half is
//! unconditional: it never reads what the property was beforehand. So an
//! interface the operator had *deliberately* excluded from NetworkManager (the
//! usual setup for a dedicated capture radio, via `nmcli device set <if> managed
//! no` or an `unmanaged-devices` rule) is handed back to NetworkManager when
//! the session ends, and NM starts probing a card that was excluded on purpose.
//!
//! This example makes that visible. It reads the property, runs one full
//! start/restore cycle, reads it again, and reports whether the value survived.
//!
//! Requires root (CAP_NET_ADMIN) and NetworkManager:
//!
//! ```text
//!   cargo build --example nm_state_probe
//!
//!   # Baseline: the property is preserved when it started as `yes`.
//!   sudo ./target/debug/examples/nm_state_probe wlan1
//!
//!   # The real case: exclude the radio first, then probe.
//!   nmcli device set wlan1 managed no
//!   sudo ./target/debug/examples/nm_state_probe wlan1
//!
//!   nmcli device set wlan1 managed yes   # put it back afterwards
//! ```
//!
//! Exits non-zero when the property changed across the cycle.

use std::process::{Command, ExitCode};

use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

/* Entry point */

#[tokio::main]
async fn main() -> ExitCode {
    init_tracing();

    let Some(iface) = std::env::args().nth(1) else {
        eprintln!("usage: nm_state_probe <iface>");
        return ExitCode::from(2);
    };

    let before = match nm_managed(&iface) {
        Some(value) => value,
        None => {
            error!(
                iface = %iface,
                "could not read GENERAL.NM-MANAGED; is NetworkManager running and the interface present?",
            );
            return ExitCode::FAILURE;
        }
    };
    info!(iface = %iface, managed = %before, "before the session");

    if let Err(error) = cycle(&iface).await {
        error!(%error, "the monitor cycle itself failed; the probe proves nothing");
        return ExitCode::FAILURE;
    }

    let after = match nm_managed(&iface) {
        Some(value) => value,
        None => {
            error!(iface = %iface, "could not read GENERAL.NM-MANAGED after the cycle");
            return ExitCode::FAILURE;
        }
    };
    info!(iface = %iface, managed = %after, "after the session");

    if before == after {
        info!(
            iface = %iface,
            managed = %before,
            "NM-MANAGED survived the session",
        );
        ExitCode::SUCCESS
    } else {
        warn!(
            iface = %iface,
            before = %before,
            after = %after,
            "NM-MANAGED was changed by the session; rfmon handed back an interface \
             NetworkManager was not managing to begin with",
        );
        ExitCode::FAILURE
    }
}

/* Helpers */

// One complete session: enter monitor mode, then restore. The restore is what
// sets `Managed = true`, so it is the half under test.
async fn cycle(iface: &str) -> rfmon::Result<()> {
    let guard = rfmon::start_monitor_on(iface).await?;
    info!(iface = %guard.name(), "in monitor mode");
    let restored = guard.restore().await?;
    info!(iface = %restored, "restored");
    Ok(())
}

// Read NetworkManager's view of whether it manages `iface`.
//
// Read through `nmcli` rather than D-Bus on purpose: it is the same answer an
// operator gets when they check, and it keeps this probe independent of the
// crate's own D-Bus code, which is the code under suspicion.
fn nm_managed(iface: &str) -> Option<String> {
    let output = Command::new("nmcli")
        .args(["-t", "-f", "GENERAL.NM-MANAGED", "device", "show", iface])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()?
        .lines()
        .find_map(|line| {
            line.split_once(':')
                .map(|(_, value)| value.trim().to_string())
        })
        .filter(|value| !value.is_empty())
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,rfmon=debug".into()),
        )
        .with_target(false)
        .init();
}
