//! Enter monitor mode (auto-selected or named), optionally tune a channel, hold
//! briefly, then restore.
//!
//! Requires root (CAP_NET_ADMIN):
//!   cargo build --example monitor
//!   sudo ./target/debug/examples/monitor              # auto-select
//!   sudo ./target/debug/examples/monitor wlan0        # target a specific iface
//!   sudo ./target/debug/examples/monitor wlan0 36     # target iface + tune channel 36
//!
//! Targeting an interface that carries your live connection will drop it for
//! the duration (it is restored at the end). Set `RUST_LOG` to adjust verbosity.

use std::time::Duration;

use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> rfmon::Result<()> {
    init_tracing();

    // Auto-select when no interface is named; otherwise target the given one.
    // Either way we get a MonitorGuard that restores the interface on drop.
    let guard = match std::env::args().nth(1) {
        Some(name) => rfmon::start_monitor_on(&name).await?,
        None => rfmon::start_monitor().await?,
    };
    info!(iface = %guard.name(), "monitor mode active (verified)");

    // Run the capture session. If it fails partway, the `?` returns early and
    // the guard's Drop still restores the interface, but the explicit
    // restore().await below is the clean path when the session succeeds.
    session(&guard).await?;

    info!(iface = %guard.name(), "restoring managed networking");
    let restored = guard.restore().await?;
    info!(iface = %restored, "restored");

    Ok(())
}

// The work done while the interface is in monitor mode. A real tool would tune
// and capture here; this just optionally sets a channel and holds briefly.
async fn session(guard: &rfmon::MonitorGuard) -> rfmon::Result<()> {
    // Optional second argument: a channel to tune to (2.4 GHz 1–14, 5 GHz 36+).
    // Tuning through the guard reuses the interface it already resolved, so no
    // re-enumeration. This is the path a channel-hopping loop would take.
    if let Some(channel) = std::env::args().nth(2).and_then(|s| s.parse::<u32>().ok()) {
        guard.set_channel(channel).await?;
        info!(iface = %guard.name(), channel, "tuned channel (20 MHz, verified)");
    }

    // Hold the interface in monitor mode; a real tool would capture here.
    tokio::time::sleep(Duration::from_secs(3)).await;
    Ok(())
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,rfmon=debug".into()),
        )
        .with_target(false)
        .init();
}
