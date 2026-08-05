//! End-to-end exercise of the whole public API against real hardware.
//!
//! Every other example demonstrates one call. This one drives all of them in
//! sequence and *independently verifies* each outcome with a fresh
//! `WirelessInterface::detect()`, rather than trusting the value a call
//! returned. A call that reports success while the kernel disagrees is exactly
//! the failure mode this library exists to defend against, so the check has to
//! come from outside the call.
//!
//! Requires root (CAP_NET_ADMIN):
//!
//! ```text
//!   cargo build --example full_cycle
//!   sudo ./target/debug/examples/full_cycle          # whichever radio scores best
//!   sudo ./target/debug/examples/full_cycle wlan1    # target one explicitly
//! ```
//!
//! **Safety.** The target radio is dropped off the network for the duration.
//! With no argument the target is whatever `start_monitor` would choose, which
//! can be a radio carrying a live connection, since association is a heavy scoring
//! penalty, not an exclusion, so an associated radio still wins when nothing
//! better is free. Name an interface explicitly to control which link is
//! disturbed. Every phase restores what it changed, and the last phase audits
//! that the interface is back under its original name in managed mode.
//!
//! A radio already in monitor mode is the one hard exclusion: something else
//! owns it, and every `start_*` call refuses it.
//!
//! The soak in phase 5 is the interference check: it holds monitor mode for a
//! few seconds and re-reads the mode, which is what catches a NetworkManager or
//! wpa_supplicant that was never really released and pulls the card back to
//! managed underneath the capture.

use std::time::Duration;

use rfmon::{
    BandKind, ChannelWidth, Error, InterfaceMode, MonitorGuard, WirelessInterface, channel_from_mhz,
};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

/* Constants */

// How long phase 5 holds monitor mode before re-reading it. Long enough for a
// supplicant that still holds the interface to act, short enough to sit through.
const SOAK: Duration = Duration::from_secs(5);

// Temporary name used by the rename phase. Fifteen characters or fewer, and
// distinctive enough that a leftover is obviously ours.
const RENAME_TO: &str = "rfmoncheck0";

// A name no interface will have, for the not-found paths.
const ABSENT_IFACE: &str = "rfmon-absent0";

/* Types */

// Running tally of checks. Phases keep going after a failed check so one broken
// call does not mask the state of everything after it; `ok()` at the end is what
// decides the exit code.
#[derive(Debug, Default)]
struct Report {
    passed: usize,
    failed: Vec<String>,
    skipped: Vec<String>,
}

/* Implementations */

impl Report {
    // Record a check. Returns the condition so callers can branch on it.
    fn check(&mut self, label: &str, ok: bool) -> bool {
        if ok {
            self.passed += 1;
            info!(check = label, "ok");
        } else {
            self.failed.push(label.to_string());
            error!(check = label, "FAILED");
        }
        ok
    }

    // Record a check that could not run: missing hardware capability, not a
    // defect. Tracked separately so the summary never reads as a clean pass
    // when half the surface was untestable on this box.
    fn skip(&mut self, label: &str, why: &str) {
        self.skipped.push(format!("{label} ({why})"));
        warn!(check = label, reason = why, "skipped");
    }

    fn ok(&self) -> bool {
        self.failed.is_empty()
    }
}

/* Entry point */

#[tokio::main]
async fn main() -> std::process::ExitCode {
    init_tracing();

    let target = std::env::args().nth(1);

    let mut report = Report::default();
    match run(&mut report, target).await {
        Ok(()) => {}
        Err(error) => {
            error!(%error, "aborted before the suite finished");
            report.failed.push(format!("suite aborted: {error}"));
        }
    }

    summarize(&report);
    if report.ok() {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::FAILURE
    }
}

/* Phases */

async fn run(report: &mut Report, target: Option<String>) -> rfmon::Result<()> {
    let interfaces = phase_1_detect(report).await?;
    let target = phase_2_select(report, target, &interfaces)?;
    // Remembered for the final audit: an interface that was idle to begin with
    // has nothing to reassociate to, so its silence at the end is not a symptom.
    let was_associated = interfaces
        .iter()
        .find(|i| i.name() == target)
        .is_some_and(WirelessInterface::is_associated);
    phase_3_error_paths(report).await;

    // Everything past here mutates the interface.
    phase_4_enter(report, &target).await?;
    phase_5_soak(report, &target).await?;
    phase_6_tuning(report, &target).await?;
    phase_7_channel_errors(report, &target).await?;
    phase_8_rename(report, &target).await?;
    phase_9_persist_and_stop(report, &target).await?;
    phase_10_drop_restores(report, &target).await?;
    phase_11_stop_all(report, &target).await?;
    phase_12_final_audit(report, &target, was_associated).await?;
    Ok(())
}

// Enumerate and report what the box has. Also the read-path smoke test: a
// malformed nl80211 join shows up here as a missing band or a zero MAC.
async fn phase_1_detect(report: &mut Report) -> rfmon::Result<Vec<WirelessInterface>> {
    banner("1", "detect");
    let interfaces = WirelessInterface::detect().await?;
    report.check(
        "detect returns at least one interface",
        !interfaces.is_empty(),
    );

    for iface in &interfaces {
        info!(
            iface = %iface.name(),
            index = iface.index(),
            phy = iface.phy_index(),
            mac = %iface.mac(),
            mode = %iface.mode(),
            driver = iface.driver().unwrap_or("?"),
            bus = %iface.bus(),
            ssid = iface.ssid().unwrap_or("-"),
            advertised = iface.supports_monitor(),
            plausible = iface.is_monitor_plausible(),
            score = iface.monitor_score(),
            "interface",
        );

        // Every field the backend populates should be internally consistent.
        report.check(
            &format!("{}: has a non-empty name", iface.name()),
            !iface.name().is_empty(),
        );
        report.check(
            &format!("{}: has a non-zero if_index", iface.name()),
            iface.index() != 0,
        );
        report.check(
            &format!("{}: is_associated agrees with ssid", iface.name()),
            iface.is_associated() == iface.ssid().is_some(),
        );
        report.check(
            &format!("{}: is_monitor agrees with mode", iface.name()),
            iface.is_monitor() == (iface.mode() == InterfaceMode::Monitor),
        );
        report.check(
            &format!(
                "{}: plausible implies advertised or known driver",
                iface.name()
            ),
            !iface.is_monitor_plausible() || iface.supports_monitor() || iface.driver().is_some(),
        );

        // Channel numbers the backend derived must round-trip through the same
        // public mapping a caller would use.
        let round_trips = iface
            .frequencies()
            .all(|f| f.channel() == channel_from_mhz(f.mhz()));
        report.check(
            &format!("{}: channel numbers round-trip from MHz", iface.name()),
            round_trips,
        );

        for band in iface.bands() {
            let usable = band
                .frequencies()
                .iter()
                .filter(|f| !f.is_disabled())
                .count();
            info!(
                iface = %iface.name(),
                band = %band.kind(),
                total = band.frequencies().len(),
                usable,
                "band",
            );
        }
    }
    Ok(interfaces)
}

// Choose the radio to abuse, and sanity-check the scoring while we are here.
fn phase_2_select(
    report: &mut Report,
    requested: Option<String>,
    interfaces: &[WirelessInterface],
) -> rfmon::Result<String> {
    banner("2", "selection");

    // The ranking `start_monitor` would apply. Reported rather than asserted:
    // the right answer depends on the hardware present.
    // Mirrors the library's own rule: a radio already in monitor mode belongs to
    // something else, and every `start_*` call refuses it. Selecting one here
    // would abort the suite in phase 4 rather than testing anything.
    let mut ranked: Vec<&WirelessInterface> = interfaces
        .iter()
        .filter(|i| i.is_monitor_plausible() && !i.is_monitor())
        .collect();
    for busy in interfaces.iter().filter(|i| i.is_monitor()) {
        warn!(iface = %busy.name(), "already in monitor mode; excluded from selection");
    }
    ranked.sort_by_key(|i| -i.monitor_score());
    for iface in &ranked {
        info!(iface = %iface.name(), score = iface.monitor_score(), "candidate");
    }
    report.check("at least one monitor-plausible radio", !ranked.is_empty());

    // An associated interface must always rank below an idle one, or the
    // penalty is not doing its job.
    let worst_idle = ranked
        .iter()
        .filter(|i| !i.is_associated())
        .map(|i| i.monitor_score())
        .min();
    let best_assoc = ranked
        .iter()
        .filter(|i| i.is_associated())
        .map(|i| i.monitor_score())
        .max();
    match (worst_idle, best_assoc) {
        (Some(idle), Some(assoc)) => {
            report.check("idle radios outrank associated ones", idle > assoc);
        }
        _ => report.skip(
            "idle radios outrank associated ones",
            "needs both an idle and an associated radio",
        ),
    }

    let chosen = match requested {
        Some(name) => interfaces
            .iter()
            .find(|i| i.name() == name)
            .ok_or_else(|| Error::NotFound {
                name: name.clone(),
                available: interfaces
                    .iter()
                    .map(WirelessInterface::name)
                    .collect::<Vec<_>>()
                    .join(", "),
            })?,
        // Whatever `pick_best` would pick. Association is a scoring penalty,
        // not an exclusion, so an associated radio is still a valid target
        // when nothing better is free. Filtering them out here would make
        // the suite demonstrate a policy the library does not have.
        // `ranked` is sorted by descending score.
        None => *ranked.first().ok_or(Error::NoMonitorCapable {
            checked: interfaces.len(),
        })?,
    };

    if chosen.is_monitor() {
        error!(
            iface = %chosen.name(),
            "already in monitor mode; something else owns it. Run `rfmon stop_monitor` or \
             `airmon-ng stop` first, or name a different interface",
        );
        return Err(Error::AlreadyMonitor {
            iface: chosen.name().to_string(),
        });
    }

    // Warned about, not refused. The library treats this as a ranking signal, so
    // the suite has to be willing to run against an associated radio or it is
    // not testing the selection policy it claims to.
    if chosen.is_associated() {
        warn!(
            iface = %chosen.name(),
            ssid = chosen.ssid().unwrap_or("?"),
            "the target is carrying a live connection; it will be dropped for the run \
             and restored at the end",
        );
    }

    info!(iface = %chosen.name(), score = chosen.monitor_score(), "target");
    Ok(chosen.name().to_string())
}

// Failures that need no hardware mutation, so they run before anything is
// touched and cannot leave the box in a strange state.
async fn phase_3_error_paths(report: &mut Report) {
    banner("3", "error paths");

    report.check(
        "stop_monitor on an unknown interface is NotFound",
        matches!(
            rfmon::stop_monitor(ABSENT_IFACE).await,
            Err(Error::NotFound { .. })
        ),
    );
    report.check(
        "set_channel on an unknown interface is NotFound",
        matches!(
            rfmon::set_channel(ABSENT_IFACE, 1).await,
            Err(Error::NotFound { .. })
        ),
    );
    report.check(
        "start_monitor_as rejects a name with whitespace",
        matches!(
            rfmon::start_monitor_as(ABSENT_IFACE, "bad name").await,
            Err(Error::InvalidInterfaceName { .. })
        ),
    );
    report.check(
        "start_monitor_as rejects a name with ':'",
        matches!(
            rfmon::start_monitor_as(ABSENT_IFACE, "mon:0").await,
            Err(Error::InvalidInterfaceName { .. })
        ),
    );
    report.check(
        "start_monitor_as rejects an over-long name",
        matches!(
            rfmon::start_monitor_as(ABSENT_IFACE, "0123456789abcdef").await,
            Err(Error::InvalidInterfaceName { .. })
        ),
    );
}

// The core transition, verified from outside the call.
async fn phase_4_enter(report: &mut Report, target: &str) -> rfmon::Result<()> {
    banner("4", "enter monitor mode");

    let guard = rfmon::start_monitor_on(target).await?;
    report.check("guard reports the target name", guard.name() == target);
    report.check(
        "guard reports the same original name",
        guard.original_name() == target,
    );
    report.check(
        "kernel confirms monitor mode",
        mode_of(target).await? == Some(InterfaceMode::Monitor),
    );

    // Leave it in monitor for the soak phase.
    let left = guard.persist();
    report.check("persist returns the current name", left == target);
    report.check(
        "still in monitor mode after the guard is gone",
        mode_of(target).await? == Some(InterfaceMode::Monitor),
    );
    Ok(())
}

// The interference check. If something still holds the interface, it reverts
// here rather than three hours into a capture.
async fn phase_5_soak(report: &mut Report, target: &str) -> rfmon::Result<()> {
    banner("5", "interference soak");
    info!(seconds = SOAK.as_secs(), "holding monitor mode");
    tokio::time::sleep(SOAK).await;

    report.check(
        "monitor mode survived the soak (nothing reclaimed the interface)",
        mode_of(target).await? == Some(InterfaceMode::Monitor),
    );

    // The interface is in monitor mode right now, which makes this the moment
    // to check the ban. rfmon keeps no ownership marker, so it cannot tell its
    // own leftover from another tool's live capture, and taking one it does not
    // own strands the interface in a state neither tool will clean up.
    report.check(
        "entering an interface already in monitor mode is refused",
        matches!(
            rfmon::start_monitor_on(target).await,
            Err(Error::AlreadyMonitor { .. })
        ),
    );
    report.check(
        "the refusal changed nothing",
        mode_of(target).await? == Some(InterfaceMode::Monitor),
    );
    Ok(())
}

// Tune across every band the device actually supports, through both the
// name-based free function and the guard's resolved path.
async fn phase_6_tuning(report: &mut Report, target: &str) -> rfmon::Result<()> {
    banner("6", "channel tuning");

    // Phase 4 left the interface in monitor mode, and entering is refused on a
    // radio already in it, so hand it back before re-acquiring a guard. This is
    // the documented recovery order: stop, then start.
    rfmon::stop_monitor(target).await?;

    let iface = require(target).await?;
    let guard = rfmon::start_monitor_on(target).await?;

    for band in [BandKind::TwoGhz, BandKind::FiveGhz] {
        let Some(channel) = tunable_channel(&iface, band) else {
            report.skip(
                &format!("tune a {band} channel"),
                "device has no usable one",
            );
            continue;
        };

        // Through the guard: no re-enumeration, the channel-hopping path.
        let ok = guard.set_channel(channel).await;
        report.check(
            &format!("tune {band} channel {channel} through the guard"),
            ok.is_ok(),
        );
        if let Err(error) = ok {
            warn!(%error, "tune failed");
        }

        // Through the free function: resolves the name each call.
        report.check(
            &format!("tune {band} channel {channel} by name"),
            rfmon::set_channel(target, channel).await.is_ok(),
        );

        // 40 MHz, if the device has a neighbour to pair with.
        let wide = guard
            .set_channel(channel)
            .with_width(ChannelWidth::Mhz40Above)
            .await;
        let label = format!("tune {band} channel {channel} at HT40+");
        match wide {
            Ok(_) => {
                report.check(&label, true);
            }
            // A driver that *claimed* success and then sat at another width is
            // the lie width verification exists to catch: a real failure.
            Err(error) if is_verify_failure(&error) => {
                warn!(%error, "driver accepted the width and did not honour it");
                report.check(&label, false);
            }
            // A driver that *refuses* 40 MHz is answering honestly: the primary
            // may have no secondary above it in this regulatory domain. A
            // capability gap, not a defect.
            Err(error) => report.skip(&label, &format!("driver refused: {error}")),
        }
    }

    // 6 GHz, only where the hardware has it.
    match tunable_channel(&iface, BandKind::SixGhz) {
        Some(channel) => {
            report.check(
                &format!("tune 6 GHz channel {channel}"),
                guard.set_channel_6g(channel).await.is_ok(),
            );
        }
        None => report.skip("tune a 6 GHz channel", "not a 6E adapter"),
    }

    guard.persist();
    Ok(())
}

// Channel resolution failures, which need the interface in hand but change
// nothing when they fire.
async fn phase_7_channel_errors(report: &mut Report, target: &str) -> rfmon::Result<()> {
    banner("7", "channel errors");
    let iface = require(target).await?;

    // A channel number no band on this device carries.
    let absent = (1..=255).find(|c| !has_channel(&iface, *c)).unwrap_or(255);
    report.check(
        &format!("channel {absent} is ChannelUnavailable"),
        matches!(
            rfmon::set_channel(target, absent).await,
            Err(Error::ChannelUnavailable { .. })
        ),
    );

    // A channel the device has, but the regulatory domain rules out. Reported
    // separately from "not available" because only one of the two has a fix.
    match disabled_channel(&iface) {
        Some(channel) => {
            report.check(
                &format!("channel {channel} is ChannelDisabled, not ChannelUnavailable"),
                matches!(
                    rfmon::set_channel(target, channel).await,
                    Err(Error::ChannelDisabled { .. })
                ),
            );
        }
        None => report.skip(
            "ChannelDisabled",
            "this regulatory domain disables nothing the device has",
        ),
    }

    // A channel this device has, but only in the band the call does not search.
    // On a non-6E adapter every 6 GHz request is simply unavailable instead.
    let five_only = tunable_channel(&iface, BandKind::FiveGhz)
        .filter(|c| !has_channel_in(&iface, *c, BandKind::SixGhz));
    match five_only {
        Some(channel) => {
            report.check(
                &format!("5 GHz channel {channel} via set_channel_6g is WrongBand"),
                matches!(
                    rfmon::set_channel_6g(target, channel).await,
                    Err(Error::WrongBand {
                        alternative: "set_channel",
                        ..
                    })
                ),
            );
        }
        None => report.skip("WrongBand on a 5 GHz-only channel", "no 5 GHz band"),
    }
    Ok(())
}

// Rename for the session, then hand the original name back.
async fn phase_8_rename(report: &mut Report, target: &str) -> rfmon::Result<()> {
    banner("8", "rename");

    // Start from managed so this phase stands alone.
    rfmon::stop_monitor(target).await?;

    let guard = rfmon::start_monitor_as(target, RENAME_TO).await?;
    report.check("guard reports the new name", guard.name() == RENAME_TO);
    report.check(
        "guard remembers the original name",
        guard.original_name() == target,
    );
    report.check(
        "kernel sees the new name in monitor mode",
        mode_of(RENAME_TO).await? == Some(InterfaceMode::Monitor),
    );
    report.check(
        "the original name is gone",
        mode_of(target).await?.is_none(),
    );

    let restored = guard.restore().await?;
    report.check("restore returns the original name", restored == target);
    report.check(
        "the original name is back in managed mode",
        mode_of(target).await? == Some(InterfaceMode::Managed),
    );
    report.check(
        "the temporary name is gone",
        mode_of(RENAME_TO).await?.is_none(),
    );
    Ok(())
}

// persist() then recover by name: the crash-recovery contract, and what the
// CLI does.
async fn phase_9_persist_and_stop(report: &mut Report, target: &str) -> rfmon::Result<()> {
    banner("9", "persist and stop by name");

    let name = rfmon::start_monitor_on(target).await?.persist();
    report.check(
        "persisted interface is still in monitor mode",
        mode_of(&name).await? == Some(InterfaceMode::Monitor),
    );

    let stopped = rfmon::stop_monitor(&name).await?;
    report.check("stop_monitor returns the name", stopped == name);
    report.check(
        "stop_monitor returned it to managed mode",
        mode_of(&name).await? == Some(InterfaceMode::Managed),
    );

    // The fix for the blind-recovery case: stopping an already-managed
    // interface must not bounce the link.
    report.check(
        "stop_monitor on an already-managed interface succeeds",
        rfmon::stop_monitor(&name).await.is_ok(),
    );
    report.check(
        "and leaves it in managed mode",
        mode_of(&name).await? == Some(InterfaceMode::Managed),
    );
    Ok(())
}

// The RAII path: no explicit restore, just scope exit.
async fn phase_10_drop_restores(report: &mut Report, target: &str) -> rfmon::Result<()> {
    banner("10", "drop restores");

    {
        let guard: MonitorGuard = rfmon::start_monitor_on(target).await?;
        report.check(
            "in monitor mode inside the guard's scope",
            mode_of(target).await? == Some(InterfaceMode::Monitor),
        );
        info!(guard = ?guard, "dropping without restore(); expect a warning");
    }
    // Drop runs teardown to completion on its own thread and blocks, so the
    // interface is already restored by the time we get here.
    report.check(
        "drop restored managed mode",
        mode_of(target).await? == Some(InterfaceMode::Managed),
    );
    Ok(())
}

// The emergency sweep, including the guarantee that it leaves managed
// interfaces alone.
async fn phase_11_stop_all(report: &mut Report, target: &str) -> rfmon::Result<()> {
    banner("11", "stop_all_monitors");

    // Put the target back into monitor mode first, so the sweep has real work
    // to do. Without this the phase passes vacuously: by now every earlier
    // phase has restored what it changed, and an empty sweep satisfies every
    // check below without the restore path ever running.
    rfmon::start_monitor_on(target).await?.persist();
    report.check(
        "target is in monitor mode going into the sweep",
        mode_of(target).await? == Some(InterfaceMode::Monitor),
    );

    let before = WirelessInterface::detect().await?;
    let managed_before: Vec<String> = before
        .iter()
        .filter(|i| !i.is_monitor())
        .map(|i| i.name().to_string())
        .collect();

    let restored = rfmon::stop_all_monitors().await?;
    info!(restored = ?restored, "swept");

    report.check(
        "sweep reported the target as restored",
        restored.iter().any(|name| name == target),
    );
    let after = WirelessInterface::detect().await?;
    report.check(
        "no interface is left in monitor mode",
        after.iter().all(|i| !i.is_monitor()),
    );
    report.check(
        "the target is actually back in managed mode",
        mode_of(target).await? == Some(InterfaceMode::Managed),
    );
    report.check(
        "interfaces already managed were not reported as restored",
        managed_before.iter().all(|name| !restored.contains(name)),
    );
    report.check(
        "a second sweep finds nothing to do",
        rfmon::stop_all_monitors().await?.is_empty(),
    );
    Ok(())
}

// The interface must be exactly as we found it.
async fn phase_12_final_audit(
    report: &mut Report,
    target: &str,
    was_associated: bool,
) -> rfmon::Result<()> {
    banner("12", "final audit");

    let iface = require(target).await?;
    report.check(
        "target is back under its original name",
        iface.name() == target,
    );
    report.check("target is in managed mode", !iface.is_monitor());
    report.check(
        "no leftover interface under the temporary name",
        mode_of(RENAME_TO).await?.is_none(),
    );

    match (was_associated, iface.is_associated()) {
        (true, true) => info!(
            ssid = iface.ssid().unwrap_or("?"),
            "target has reassociated"
        ),
        // Not a failure: reassociation is NetworkManager's job and takes time.
        (true, false) => warn!(
            iface = target,
            "target has not reassociated yet; give the network manager a moment",
        ),
        // It was idle before the run, so there is nothing to come back to.
        (false, _) => info!(iface = target, "target was idle before the run"),
    }
    Ok(())
}

/* Helpers */

// The current mode of `name`, or `None` if no interface has that name.
async fn mode_of(name: &str) -> rfmon::Result<Option<InterfaceMode>> {
    Ok(WirelessInterface::detect()
        .await?
        .into_iter()
        .find(|i| i.name() == name)
        .map(|i| i.mode()))
}

// Resolve `name` or fail with the library's own NotFound.
async fn require(name: &str) -> rfmon::Result<WirelessInterface> {
    let interfaces = WirelessInterface::detect().await?;
    let available = interfaces
        .iter()
        .map(WirelessInterface::name)
        .collect::<Vec<_>>()
        .join(", ");
    interfaces
        .into_iter()
        .find(|i| i.name() == name)
        .ok_or(Error::NotFound {
            name: name.to_string(),
            available,
        })
}

// A channel that is usable in `band`: present, enabled, not radar (a DFS
// channel can take seconds to become usable and is not what we are testing).
fn tunable_channel(iface: &WirelessInterface, band: BandKind) -> Option<u32> {
    iface
        .bands()
        .iter()
        .filter(|b| b.kind() == band)
        .flat_map(|b| b.frequencies())
        .find(|f| !f.is_disabled() && !f.is_radar() && f.channel().is_some())
        .and_then(|f| f.channel())
}

// Whether an error means "I did what you asked and then didn't" rather than
// "I cannot do that". Only the former is a library-level failure.
#[cfg(target_os = "linux")]
fn is_verify_failure(error: &Error) -> bool {
    use rfmon::errors::LinuxError;
    matches!(
        error,
        Error::Linux(LinuxError::WidthVerifyFailed { .. } | LinuxError::ChannelVerifyFailed { .. })
    )
}

#[cfg(not(target_os = "linux"))]
fn is_verify_failure(_error: &Error) -> bool {
    false
}

// A channel the device carries but the regulatory domain disables, in a band
// `set_channel` searches. Channels that are enabled *anywhere* are excluded: at
// 2.4/5 GHz they would simply resolve, and at 6 GHz they would report
// `WrongBand`, which outranks the regulatory answer.
fn disabled_channel(iface: &WirelessInterface) -> Option<u32> {
    iface
        .bands()
        .iter()
        .filter(|band| band.kind() != BandKind::SixGhz)
        .flat_map(|band| band.frequencies())
        .filter(|freq| freq.is_disabled())
        .filter_map(|freq| freq.channel())
        .find(|channel| !has_enabled_channel(iface, *channel))
}

fn has_enabled_channel(iface: &WirelessInterface, channel: u32) -> bool {
    iface
        .frequencies()
        .any(|freq| freq.channel() == Some(channel) && !freq.is_disabled())
}

fn has_channel(iface: &WirelessInterface, channel: u32) -> bool {
    iface.frequencies().any(|f| f.channel() == Some(channel))
}

fn has_channel_in(iface: &WirelessInterface, channel: u32, band: BandKind) -> bool {
    iface
        .bands()
        .iter()
        .filter(|b| b.kind() == band)
        .flat_map(|b| b.frequencies())
        .any(|f| f.channel() == Some(channel))
}

fn banner(number: &str, title: &str) {
    info!("──── phase {number}: {title} ────");
}

fn summarize(report: &Report) {
    info!("──── summary ────");
    info!(
        passed = report.passed,
        failed = report.failed.len(),
        skipped = report.skipped.len(),
        "checks",
    );
    for skipped in &report.skipped {
        warn!(check = %skipped, "skipped");
    }
    for failed in &report.failed {
        error!(check = %failed, "failed");
    }
    if report.ok() {
        info!("all checks passed");
    } else {
        error!("suite failed");
    }
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,rfmon=debug".into()),
        )
        .with_target(false)
        .init();
}
