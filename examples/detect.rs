//! Detect wireless interfaces and log what each supports.
//!
//! Run with: `cargo run --example detect`
//! Adjust verbosity with `RUST_LOG` (e.g. `RUST_LOG=rfmon=trace`).

use rfmon::InterfaceInfo;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> rfmon::Result<()> {
    init_tracing();

    let interfaces = InterfaceInfo::detect().await?;
    if interfaces.is_empty() {
        info!("no wireless interfaces found");
        return Ok(());
    }

    for iface in &interfaces {
        let modes: Vec<String> = iface
            .supported_modes()
            .iter()
            .map(|m| m.to_string())
            .collect();
        info!(
            iface = %iface.name(),
            phy = iface.phy_index(),
            index = iface.index(),
            mac = %iface.mac(),
            mode = %iface.mode(),
            driver = iface.driver().unwrap_or("?"),
            bus = %iface.bus(),
            ssid = iface.ssid().unwrap_or("-"),
            monitor_advertised = iface.supports_monitor(),
            monitor_plausible = iface.is_monitor_plausible(),
            score = iface.monitor_score(),
            modes = %modes.join(","),
            "wireless interface",
        );

        for band in iface.bands() {
            let channels: Vec<String> = band
                .frequencies()
                .iter()
                .filter(|f| !f.is_disabled())
                .map(|f| match f.channel() {
                    Some(ch) => ch.to_string(),
                    None => format!("{}MHz", f.mhz()),
                })
                .collect();
            info!(
                iface = %iface.name(),
                band = %band.kind(),
                channels = band.frequencies().len(),
                usable = %channels.join(","),
                "supported band",
            );
        }
    }

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
