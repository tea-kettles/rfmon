//! Enter monitor mode on an interface, rename it, hold, then let the guard's
//! Drop restore the original name and managed networking.
//!
//! Requires root (CAP_NET_ADMIN):
//!   cargo build --example monitor_as
//!   sudo ./target/debug/examples/monitor_as wlan1 mon0        # rename wlan1 -> mon0
//!   sudo ./target/debug/examples/monitor_as wlan1 mon0 36     # ... and tune channel 36
//!
//! The interface is renamed to <new> for the session, then restored to <old>
//! when the `MonitorGuard` drops at the end of scope, even on an early error.

use std::time::Duration;

use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> rfmon::Result<()> {
    init_tracing();

    let old = std::env::args()
        .nth(1)
        .expect("usage: monitor_as <iface> <new_name> [channel]");
    let new = std::env::args()
        .nth(2)
        .expect("usage: monitor_as <iface> <new_name> [channel]");

    let outcome = run(&old, &new).await;

    // By the time we get here the guard has dropped and restored the interface.
    info!(iface = %old, "guard dropped; interface should be back to its original name, managed");
    outcome
}

// Hold the guard for the session's duration; dropping it at the end of this
// scope renames the interface back to `old` and restores managed networking.
async fn run(old: &str, new: &str) -> rfmon::Result<()> {
    let guard = rfmon::start_monitor_as(old, new).await?;
    info!(
        original = %guard.original_name(),
        current = %guard.name(),
        "monitor mode active + renamed (verified)",
    );

    // Optional third argument: a channel to tune to. If it fails, we return
    // early and the guard STILL restores on drop.
    if let Some(channel) = std::env::args().nth(3).and_then(|s| s.parse::<u32>().ok()) {
        guard.set_channel(channel).await?;
        info!(iface = %guard.name(), channel, "tuned channel (20 MHz, verified)");
    }

    // Hold in monitor mode; a real tool would capture here.
    tokio::time::sleep(Duration::from_secs(3)).await;

    info!(iface = %guard.name(), "dropping guard; Drop will restore the original name");
    Ok(())
    // `guard` drops here → renames back to `old` + restores managed networking.
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,rfmon=debug".into()),
        )
        .with_target(false)
        .init();
}
