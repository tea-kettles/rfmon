//! Linux monitor-mode backend (nl80211 + rtnetlink + D-Bus).
//!
//! Implements [`MonitorBackend`](crate::monitor::MonitorBackend) for Linux. The
//! moving parts are:
//!
//!   * [`interface`]: nl80211/rtnetlink, enumerating interfaces and switching modes.
//!   * [`netman`]: NetworkManager D-Bus coordination.
//!   * [`supplicant`]: wpa_supplicant D-Bus coordination.
//!
//! Entering monitor mode means releasing the interface from whatever service
//! holds it, switching the iftype, and confirming the switch by reading the
//! mode back. Leaving reverses it: switch back to managed and hand control back.
//! The release/reclaim step is **durable**: it works whether the host runs
//! NetworkManager, bare wpa_supplicant, or neither.

pub(crate) mod interface;
#[cfg(feature = "dbus")]
pub(crate) mod netman;
#[cfg(feature = "dbus")]
pub(crate) mod supplicant;

use std::future::Future;
use std::time::Duration;

use tracing::{debug, instrument, warn};

use crate::errors::{LinuxError, WidthReadback};
use crate::interface::{ChannelWidth, InterfaceMode, WirelessInterface, rank_candidates};
use crate::linux::interface::ChannelState;
use crate::monitor::MonitorBackend;
use crate::{Error, Result};

/* Constants */

// Netlink calls are local and return in milliseconds; this is a generous ceiling
// that bounds the operation (including the calls reached from a blocking `Drop`)
// rather than an expected wait.
pub(crate) const NETLINK_TIMEOUT: Duration = Duration::from_secs(5);

// The D-Bus counterpart: D-Bus calls cross the system bus and can wedge if a
// service is stuck, so the coordination paths are bounded too.
#[cfg(feature = "dbus")]
pub(crate) const DBUS_TIMEOUT: Duration = Duration::from_secs(5);

/* Types */

/// The Linux implementation of [`MonitorBackend`](crate::monitor::MonitorBackend).
#[derive(Debug)]
pub(crate) struct LinuxBackend;

/// Which services were holding an interface when it was released.
///
/// Reclaim is a mirror of release, not a broadcast: handing an interface to a
/// service that never had it is a state change nobody asked for. NetworkManager
/// gains a `Managed = true` on a device the operator had deliberately excluded;
/// wpa_supplicant gains an interface it never knew about, via `CreateInterface`,
/// and then fights the capture it was just handed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Holders {
    network_manager: bool,
    supplicant: bool,
}

impl Holders {
    // Whatever is running on this host. The fallback for the stateless recovery
    // path, where there is no record of who held the interface because this
    // process never released it. See `leave`.
    async fn present<O: LinuxOps>() -> Self {
        Self {
            network_manager: O::nm_present().await,
            supplicant: O::wpa_present().await,
        }
    }

    fn any(self) -> bool {
        self.network_manager || self.supplicant
    }
}

/* Collaborator seam */

// The primitive control operations the Linux orchestration (`enter`, `leave`,
// `start_as`, `release_stack`, `reclaim_stack`) is built from: nl80211/rtnetlink
// mode switching plus the NetworkManager and wpa_supplicant coordination. Those
// orchestration functions are generic over this trait so their rollback and
// release/reclaim ordering can be tested against a recording mock, with the real
// kernel and D-Bus reached only through `RealOps`.
#[allow(async_fn_in_trait)]
trait LinuxOps {
    async fn detect() -> Result<Vec<WirelessInterface>>;
    async fn set_mode(iface: &WirelessInterface, mode: InterfaceMode) -> Result<()>;
    async fn read_mode(index: u32) -> Result<InterfaceMode>;
    async fn set_freq(iface: &WirelessInterface, freq_mhz: u32, width: ChannelWidth) -> Result<()>;
    async fn read_channel(index: u32) -> Result<ChannelState>;
    async fn rename(index: u32, old: &str, new: &str) -> Result<()>;
    async fn nm_present() -> bool;
    async fn nm_release(iface: &str) -> Result<()>;
    async fn nm_reclaim(iface: &str) -> Result<()>;
    async fn wpa_present() -> bool;
    async fn wpa_release(iface: &str) -> Result<()>;
    async fn wpa_reclaim(iface: &str) -> Result<()>;
}

// The production [`LinuxOps`]: forwards each primitive to the real backend module.
#[derive(Debug)]
struct RealOps;

impl LinuxOps for RealOps {
    async fn detect() -> Result<Vec<WirelessInterface>> {
        interface::detect().await
    }
    async fn set_mode(iface: &WirelessInterface, mode: InterfaceMode) -> Result<()> {
        interface::set_mode(iface, mode).await
    }
    async fn read_mode(index: u32) -> Result<InterfaceMode> {
        interface::read_mode(index).await
    }
    async fn set_freq(iface: &WirelessInterface, freq_mhz: u32, width: ChannelWidth) -> Result<()> {
        interface::set_channel(iface.index(), iface.name(), freq_mhz, width).await
    }
    async fn read_channel(index: u32) -> Result<ChannelState> {
        interface::read_channel(index).await
    }
    async fn rename(index: u32, old: &str, new: &str) -> Result<()> {
        interface::rename(index, old, new).await
    }

    // Without the `dbus` feature there is no service to coordinate with, so the
    // presence probes report absent and the release/reclaim calls are no-ops,
    // the same path a headless host that runs neither service takes at runtime.
    async fn nm_present() -> bool {
        #[cfg(feature = "dbus")]
        {
            netman::is_present().await
        }
        #[cfg(not(feature = "dbus"))]
        {
            false
        }
    }
    async fn nm_release(iface: &str) -> Result<()> {
        #[cfg(feature = "dbus")]
        {
            netman::release(iface).await
        }
        #[cfg(not(feature = "dbus"))]
        {
            let _ = iface;
            Ok(())
        }
    }
    async fn nm_reclaim(iface: &str) -> Result<()> {
        #[cfg(feature = "dbus")]
        {
            netman::reclaim(iface).await
        }
        #[cfg(not(feature = "dbus"))]
        {
            let _ = iface;
            Ok(())
        }
    }
    async fn wpa_present() -> bool {
        #[cfg(feature = "dbus")]
        {
            supplicant::is_present().await
        }
        #[cfg(not(feature = "dbus"))]
        {
            false
        }
    }
    async fn wpa_release(iface: &str) -> Result<()> {
        #[cfg(feature = "dbus")]
        {
            supplicant::release(iface).await
        }
        #[cfg(not(feature = "dbus"))]
        {
            let _ = iface;
            Ok(())
        }
    }
    async fn wpa_reclaim(iface: &str) -> Result<()> {
        #[cfg(feature = "dbus")]
        {
            supplicant::reclaim(iface).await
        }
        #[cfg(not(feature = "dbus"))]
        {
            let _ = iface;
            Ok(())
        }
    }
}

/* Implementations */

impl MonitorBackend for LinuxBackend {
    async fn detect() -> Result<Vec<WirelessInterface>> {
        interface::detect().await
    }

    async fn start_auto() -> Result<WirelessInterface> {
        start_auto_impl::<RealOps>().await
    }

    async fn start_on(name: &str) -> Result<WirelessInterface> {
        start_on_impl::<RealOps>(name).await
    }

    async fn start_as(name: &str, new_name: &str) -> Result<WirelessInterface> {
        start_as_impl::<RealOps>(name, new_name).await
    }

    async fn rename(current: &str, new: &str) -> Result<()> {
        let iface = find::<RealOps>(current).await?;
        interface::rename(iface.index(), current, new).await
    }

    async fn set_channel(
        iface: &WirelessInterface,
        freq_mhz: u32,
        width: ChannelWidth,
    ) -> Result<()> {
        set_channel_verified::<RealOps>(iface, freq_mhz, width).await
    }

    async fn stop(name: &str) -> Result<()> {
        leave::<RealOps>(name).await
    }
}

/* Free functions */

// Put a resolved interface into monitor mode: release the network stack, switch
// the iftype, and confirm the switch took. On any failure after release, hand
// control back before returning the error so we never strand the interface.
#[instrument(level = "debug", skip(iface), fields(iface = %iface.name()), err)]
async fn enter<O: LinuxOps>(iface: &WirelessInterface) -> Result<Holders> {
    let name = iface.name();

    // 0. Refuse a radio that is already in monitor mode. `rank_candidates`
    //    filters these out of auto-selection, but `start_monitor_on` and
    //    `start_monitor_as` skip scoring entirely, so the ban lives here, at
    //    the one point all three entry paths pass through, rather than at each of
    //    them. Checked before the release, so a refusal touches nothing.
    if iface.is_monitor() {
        return Err(Error::AlreadyMonitor {
            iface: name.to_string(),
        });
    }

    // 1. Release from whatever is managing the interface. What it took is
    //    carried back to the caller so every later rollback hands the interface
    //    to exactly those services and no others.
    let held = release_stack::<O>(name).await?;

    // 2. Switch to monitor. On failure, reclaim before returning.
    if let Err(error) = O::set_mode(iface, InterfaceMode::Monitor).await {
        let _ = reclaim_stack::<O>(name, held).await;
        return Err(error);
    }

    // 3. Confirm the driver really entered monitor mode. Some adapters accept
    //    the switch without honoring it; roll back if so.
    //
    //    A readback that *errors* rolls back too, rather than propagating. By
    //    this point the interface is already released and already switched, so
    //    returning straight out would strand it: in monitor mode, unmanaged,
    //    and with no guard for the caller to clean up with. That is the same
    //    un-rolled-back shape `start_as_impl` closes after its rename, and it is
    //    reachable here from a transient netlink failure or a USB adapter pulled
    //    between the switch and the read.
    let mode = match O::read_mode(iface.index()).await {
        Ok(mode) => mode,
        Err(error) => {
            let _ = O::set_mode(iface, InterfaceMode::Managed).await;
            let _ = reclaim_stack::<O>(name, held).await;
            return Err(error);
        }
    };
    if mode != InterfaceMode::Monitor {
        let _ = O::set_mode(iface, InterfaceMode::Managed).await;
        let _ = reclaim_stack::<O>(name, held).await;
        return Err(crate::errors::LinuxError::MonitorVerifyFailed {
            iface: name.to_string(),
        }
        .into());
    }

    debug!(iface = name, "interface entered monitor mode (verified)");
    Ok(held)
}

// Set the interface's frequency, then confirm it took by reading it back. A set
// with no confirmation is exactly what the mode path already distrusts: drivers
// accept `SET_WIPHY` and then sit on a different (or no) frequency. On a mismatch
// the channel was not actually applied, so this is a hard error rather than a
// silent wrong-channel capture.
async fn set_channel_verified<O: LinuxOps>(
    iface: &WirelessInterface,
    freq_mhz: u32,
    width: ChannelWidth,
) -> Result<()> {
    O::set_freq(iface, freq_mhz, width).await?;

    let actual = O::read_channel(iface.index()).await?;

    // The primary frequency first: land on the wrong one and nothing else about
    // the readback means anything.
    if actual.freq_mhz != Some(freq_mhz) {
        return Err(LinuxError::ChannelVerifyFailed {
            iface: iface.name().to_string(),
            requested_mhz: freq_mhz,
            actual: actual.freq_mhz.into(),
        }
        .into());
    }

    // Then the width. Right frequency at the wrong bandwidth is the quieter
    // failure (the capture looks fine and simply misses half the channel), so
    // it gets checked rather than assumed from a successful `SET_WIPHY`.
    let observed = classify_width(actual, freq_mhz);
    if observed != WidthReadback::Known(width) {
        return Err(LinuxError::WidthVerifyFailed {
            iface: iface.name().to_string(),
            primary_mhz: freq_mhz,
            requested: width,
            actual: observed,
        }
        .into());
    }

    debug!(iface = %iface.name(), freq_mhz, %width, "interface tuned (verified)");
    Ok(())
}

// Interpret a readback against the primary frequency it was taken at.
//
// 40 MHz is only half-described by the width: which side the secondary channel
// sits on is carried by the segment centre, at primary ± 10 MHz. A device
// reporting 40 MHz with a centre anywhere else is tuned to something the caller
// did not ask for, so that is `Misaligned` rather than silently accepted as one
// of the two HT40 variants.
fn classify_width(actual: ChannelState, primary_mhz: u32) -> WidthReadback {
    let Some(mhz) = actual.width_mhz else {
        return WidthReadback::None;
    };
    match mhz {
        20 => WidthReadback::Known(ChannelWidth::Mhz20),
        40 => match actual.center_mhz {
            Some(center) if center == primary_mhz + 10 => {
                WidthReadback::Known(ChannelWidth::Mhz40Above)
            }
            // Written as an addition so a centre below 10 MHz cannot underflow.
            Some(center) if center + 10 == primary_mhz => {
                WidthReadback::Known(ChannelWidth::Mhz40Below)
            }
            center_mhz => WidthReadback::Misaligned { center_mhz },
        },
        mhz => WidthReadback::Other { mhz },
    }
}

// Select the best capture candidate and enter monitor mode on it.
async fn start_auto_impl<O: LinuxOps>() -> Result<WirelessInterface> {
    let interfaces = O::detect().await?;

    // Say so when something else is already capturing. Selection silently skips
    // these, and silence would be misleading in both directions: if another tool
    // is running, the operator should know before starting a second capture; and
    // if the interface is instead a leftover from a crashed run, this is the
    // only hint that `stop_monitor` is needed to get the radio back. Auto-select
    // is the only path that warns; naming an interface explicitly is a
    // deliberate choice, and refusing it already says the same thing.
    let busy: Vec<&str> = interfaces
        .iter()
        .filter(|iface| iface.is_monitor())
        .map(WirelessInterface::name)
        .collect();
    if !busy.is_empty() {
        warn!(
            in_monitor = %busy.join(", "),
            "interface(s) already in monitor mode were excluded from selection; \
             another capture tool may be running, or a previous session may not have been stopped",
        );
    }

    // Work down the ranked list rather than betting everything on the winner.
    // Monitor capability is a prediction until it is tried: the driver-name
    // table is a heuristic, and a radio that advertises monitor mode can still
    // refuse the switch, so giving up after one candidate fails the whole call
    // on a box that has a perfectly good second radio. `enter` rolls back on
    // failure, so a rejected candidate is left exactly as it was found.
    let candidates = rank_candidates(interfaces)?;
    let total = candidates.len();
    let mut last_error = None;

    for (position, candidate) in candidates.into_iter().enumerate() {
        debug!(
            iface = %candidate.name(),
            driver = candidate.driver().unwrap_or("?"),
            bus = %candidate.bus(),
            score = candidate.monitor_score(),
            candidate = position + 1,
            of = total,
            "trying capture interface",
        );
        match enter::<O>(&candidate).await {
            Ok(_) => return Ok(candidate),
            Err(error) => {
                warn!(
                    iface = %candidate.name(),
                    %error,
                    remaining = total - position - 1,
                    "candidate could not enter monitor mode",
                );
                last_error = Some(error);
            }
        }
    }

    // Every candidate refused. The last failure is the most informative thing
    // to surface: the list is best-first, so it belongs to the weakest radio,
    // but each was already logged above with its own reason.
    Err(last_error.expect("candidates was non-empty, so the loop ran at least once"))
}

// Enter monitor mode on a named interface, skipping selection.
async fn start_on_impl<O: LinuxOps>(name: &str) -> Result<WirelessInterface> {
    let chosen = find::<O>(name).await?;
    enter::<O>(&chosen).await?;
    Ok(chosen)
}

// Note: `enter`'s `Holders` is dropped on the success paths above. Restoring
// happens later, from `leave`, in a call that may not even share a process with
// this one. See the note there on why the stateless path cannot mirror.

// Enter monitor mode on `name` and rename it to `new_name`, rolling the whole
// session back on any failure so a partially-applied rename never strands the
// interface (renamed, in monitor, with no guard for the caller).
async fn start_as_impl<O: LinuxOps>(name: &str, new_name: &str) -> Result<WirelessInterface> {
    let chosen = find::<O>(name).await?;
    let held = enter::<O>(&chosen).await?;

    // Rename once monitor is confirmed. On failure, roll the interface back to
    // managed networking under its original name before returning.
    if let Err(error) = O::rename(chosen.index(), name, new_name).await {
        // Rename back first, and unconditionally. A failure here does not mean
        // the name is unchanged: `rename` applies the new name and *then* brings
        // the link up, reporting the rename error first, so a failed bring-up is
        // indistinguishable from a rename that never happened. Renaming back is
        // addressed by index and is a no-op when the name never changed, which
        // makes it safe to attempt either way, and skipping it would leave the
        // interface under `new_name` while the handback below is addressed to
        // `name`, an interface that no longer exists.
        let _ = O::rename(chosen.index(), new_name, name).await;
        let _ = O::set_mode(&chosen, InterfaceMode::Managed).await;
        let _ = reclaim_stack::<O>(name, held).await;
        return Err(error);
    }

    // Re-detect so the returned interface reflects the new name. The rename has
    // already taken effect, so a failure here would otherwise return an error
    // while leaving the interface renamed, in monitor mode, and with no guard
    // for the caller to clean up: the one un-rolled-back path. Roll the whole
    // session back (rename to original, managed, hand back) before surfacing the
    // error, matching every other failure above.
    match find::<O>(new_name).await {
        Ok(iface) => Ok(iface),
        Err(error) => {
            let _ = O::rename(chosen.index(), new_name, name).await;
            let _ = O::set_mode(&chosen, InterfaceMode::Managed).await;
            let _ = reclaim_stack::<O>(name, held).await;
            Err(error)
        }
    }
}

// Take an interface out of monitor mode and restore normal managed networking.
#[instrument(level = "debug", skip(name), fields(iface = name), err)]
async fn leave<O: LinuxOps>(name: &str) -> Result<()> {
    let iface = find::<O>(name).await?;

    // Only switch mode if there is a switch to make. `set_mode` bounces the
    // link (down, set iftype, up), so running it unconditionally would drop the
    // association of an interface that was never in monitor mode, precisely
    // what `rfmon stop_monitor wlan0` aimed at the host's own uplink would do.
    // `stop_all_monitors` already filters these out before calling; the
    // by-name path needs the same guard, since it is the one run blind after a
    // crash, against a name the caller has not inspected.
    //
    // The handback below still runs either way: another tool may have reverted
    // the mode underneath us (see the README on airmon-ng interference) while
    // the interface remains released from its network manager, and that is
    // exactly the state a recovery caller is trying to repair.
    if iface.is_monitor() {
        // The mode switch is what actually returns the card to managed
        // operation; that is the operation that must succeed. Handing it back to
        // a network manager is a courtesy on top. If only the handback fails the
        // interface is still in managed mode, so report success (the caller
        // asked to leave monitor mode, and it has) and log rather than propagate;
        // otherwise a recovery caller re-runs chasing a problem that is
        // already fixed, and `stop_all_monitors` drops an interface it did
        // restore from its results.
        O::set_mode(&iface, InterfaceMode::Managed).await?;

        // Confirm the switch back actually took, the same way `enter` confirms
        // the switch in. Without this, a driver that accepts the change and
        // stays in monitor leaves the radio capturing while every caller
        // believes it was released, and `stop_all_monitors` reports it as
        // restored, so the sweep meant to fix that state certifies it instead.
        //
        // The handback is deliberately skipped on failure. The mode never
        // changed, so the interface is exactly as it was before this call, and
        // a retry starts from a known state. Handing a still-monitor interface
        // to a network manager would instead invite it to fight the driver.
        let actual = O::read_mode(iface.index()).await?;
        if actual != InterfaceMode::Managed {
            return Err(LinuxError::ManagedVerifyFailed {
                iface: name.to_string(),
                actual,
            }
            .into());
        }
    } else {
        debug!(
            iface = name,
            "interface is not in monitor mode; skipping the mode switch"
        );
    }
    // Nothing here knows who held the interface: `stop_monitor` is name-based
    // and stateless by design, so it is reached after a crash, from another
    // process, or from a guard whose release happened long ago. Falling back to
    // "hand it to whatever is running" is the useful default for a repair tool:
    // an interface stranded unmanaged is the problem being fixed, but it is
    // also the one path that can still hand an interface to a service that never
    // had it. Threading the release record this far would mean carrying it
    // through the cross-platform backend trait and the guard.
    let holders = Holders::present::<O>().await;
    if let Err(error) = reclaim_stack::<O>(name, holders).await {
        warn!(
            iface = name,
            %error,
            "restored to managed mode but could not hand the interface back to a network manager",
        );
    }

    debug!(iface = name, "interface restored to managed networking");
    Ok(())
}

// Resolve a name to a detected interface, or a rich NotFound listing the ones
// that do exist.
async fn find<O: LinuxOps>(name: &str) -> Result<WirelessInterface> {
    let interfaces = O::detect().await?;
    if interfaces.is_empty() {
        return Err(Error::NoInterfaces);
    }

    let available = interfaces
        .iter()
        .map(|iface| iface.name())
        .collect::<Vec<_>>()
        .join(", ");

    interfaces
        .into_iter()
        .find(|iface| iface.name() == name)
        .ok_or(Error::NotFound {
            name: name.to_string(),
            available,
        })
}

// Release the interface from *every* service that might be holding it. On many
// systems both NetworkManager and a standalone wpa_supplicant are running, and
// releasing only via NM leaves wpa_supplicant free to revert the interface out
// of monitor mode (exactly what airmon-ng warns about). So we release both when
// present, not one or the other.
async fn release_stack<O: LinuxOps>(iface: &str) -> Result<Holders> {
    let mut held = Holders::default();

    if O::nm_present().await {
        O::nm_release(iface).await?;
        held.network_manager = true;
    }
    // Even with NM present: a wpa_supplicant that still holds this interface
    // will keep pulling it back to managed mode, so drop it from there too.
    if O::wpa_present().await {
        O::wpa_release(iface).await?;
        held.supplicant = true;
    }

    if !held.any() {
        debug!(
            iface,
            "no NetworkManager or wpa_supplicant present; proceeding directly"
        );
    }
    Ok(held)
}

// Hand the interface back to every service `release_stack` took it from. This
// is a true mirror of release: because release drops the interface from *both*
// NetworkManager and wpa_supplicant when both are present, reclaim must offer it
// back to both, or a standalone supplicant that was released is never told to
// resume managing it. `supplicant::reclaim` is idempotent: if NetworkManager
// already re-added the interface, it is a no-op, so offering to both is safe.
//
// Errors are returned but callers treat them as best-effort: the mode switch
// that actually restores managed operation has already happened by the time
// this runs (see `leave`).
async fn reclaim_stack<O: LinuxOps>(iface: &str, holders: Holders) -> Result<()> {
    if holders.network_manager {
        O::nm_reclaim(iface).await?;
    }
    if holders.supplicant {
        O::wpa_reclaim(iface).await?;
    }
    let reclaimed = holders.any();

    // Debug, not warn: a host running neither service is a documented, supported
    // configuration (the third case in the module docs), not an anomaly. It is
    // the mirror of the same condition in `release_stack`, and logging it louder
    // on the way out than on the way in would flag every restore on a headless
    // box as a problem.
    if !reclaimed {
        debug!(
            iface,
            "no NetworkManager or wpa_supplicant present; interface left in managed mode only"
        );
    }
    Ok(())
}

// Run a mutating control operation under a deadline, mapping an elapsed timer to
// a typed [`LinuxError::OperationTimeout`]. Bounds the netlink and D-Bus paths
// so neither a wedged driver nor a stuck system bus can hang a caller (or the
// blocking `Drop` that joins on teardown) indefinitely.
pub(crate) async fn with_timeout<T>(
    op: &'static str,
    dur: Duration,
    fut: impl Future<Output = Result<T>>,
) -> Result<T> {
    match tokio::time::timeout(dur, fut).await {
        Ok(result) => result,
        Err(_) => Err(LinuxError::OperationTimeout {
            op,
            timeout_ms: dur.as_millis() as u64,
        }
        .into()),
    }
}

/* Tests */

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, MutexGuard};

    use super::*;
    use crate::MacAddr;
    use crate::errors::FrequencyReadback;
    use crate::interface::BusKind;

    // Programmable state for `MockOps`, standing in for the kernel and D-Bus.
    // `detect` returns `interfaces`; `read_mode` returns `read_mode`; `nm_present`
    // / `wpa_present` gate the release/reclaim branches; any op named in `fail`
    // errors; and every call appends to `calls` for exact-sequence assertions.
    struct OpsState {
        interfaces: Vec<WirelessInterface>,
        read_mode: InterfaceMode,
        // What `read_channel` reports back. Default is un-tuned; tests set it
        // to model a driver that honored the set, one that landed elsewhere, or
        // one that accepted the width and quietly narrowed it.
        read_channel: ChannelState,
        nm_present: bool,
        wpa_present: bool,
        fail: Vec<&'static str>,
        // Interfaces whose `set_mode` fails, so a test can fail one radio and
        // leave another working. The blanket `fail` list cannot express that.
        fail_set_mode_on: Vec<String>,
        // Models `interface::rename`'s partial failure: the kernel applies the
        // rename and then bringing the link back up fails, so the call reports
        // an error even though the name really did change.
        rename_takes_then_fails: bool,
        calls: Vec<String>,
    }

    impl OpsState {
        const fn new() -> Self {
            Self {
                interfaces: Vec::new(),
                read_mode: InterfaceMode::Monitor,
                read_channel: ChannelState::UNTUNED,
                nm_present: false,
                wpa_present: false,
                fail: Vec::new(),
                fail_set_mode_on: Vec::new(),
                rename_takes_then_fails: false,
                calls: Vec::new(),
            }
        }
    }

    static OPS: Mutex<OpsState> = Mutex::new(OpsState::new());
    static SERIAL: Mutex<()> = Mutex::new(());

    struct OpsScope(#[allow(dead_code)] MutexGuard<'static, ()>);

    fn ops_scope() -> OpsScope {
        let serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        *OPS.lock().unwrap_or_else(|e| e.into_inner()) = OpsState::new();
        OpsScope(serial)
    }

    fn ops() -> MutexGuard<'static, OpsState> {
        OPS.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn calls() -> Vec<String> {
        ops().calls.clone()
    }

    fn record(entry: impl Into<String>) {
        ops().calls.push(entry.into());
    }

    // Fails the op if it is in the `fail` list.
    fn gate(op: &'static str) -> Result<()> {
        if ops().fail.contains(&op) {
            Err(LinuxError::OperationTimeout { op, timeout_ms: 0 }.into())
        } else {
            Ok(())
        }
    }

    fn iface(name: &str) -> WirelessInterface {
        WirelessInterface {
            name: name.to_string(),
            index: 1,
            phy_index: 0,
            mac: MacAddr::ZERO,
            mode: InterfaceMode::Managed,
            supported_modes: vec![InterfaceMode::Monitor],
            bands: Vec::new(),
            driver: None,
            bus: BusKind::Other,
            ssid: None,
        }
    }

    // The same interface already in monitor mode. `leave` branches on the
    // current mode, so its tests must say which state they start from.
    fn monitor_iface(name: &str) -> WirelessInterface {
        WirelessInterface {
            mode: InterfaceMode::Monitor,
            ..iface(name)
        }
    }

    struct MockOps;

    impl LinuxOps for MockOps {
        async fn detect() -> Result<Vec<WirelessInterface>> {
            record("detect");
            Ok(ops().interfaces.clone())
        }
        async fn set_mode(iface: &WirelessInterface, mode: InterfaceMode) -> Result<()> {
            record(format!("set_mode {} {mode}", iface.name()));
            let refuses = ops().fail_set_mode_on.iter().any(|n| n == iface.name());
            if refuses {
                // Same shape as `gate`'s error; only the targeting differs.
                return Err(LinuxError::OperationTimeout {
                    op: "set_mode",
                    timeout_ms: 0,
                }
                .into());
            }
            gate("set_mode")
        }
        async fn read_mode(_index: u32) -> Result<InterfaceMode> {
            record("read_mode");
            gate("read_mode")?;
            Ok(ops().read_mode)
        }
        async fn set_freq(
            iface: &WirelessInterface,
            freq_mhz: u32,
            _width: ChannelWidth,
        ) -> Result<()> {
            record(format!("set_freq {} {freq_mhz}", iface.name()));
            gate("set_freq")
        }
        async fn read_channel(_index: u32) -> Result<ChannelState> {
            record("read_channel");
            gate("read_channel")?;
            Ok(ops().read_channel)
        }
        async fn rename(_index: u32, old: &str, new: &str) -> Result<()> {
            record(format!("rename {old}->{new}"));
            let partial = ops().rename_takes_then_fails;
            if partial {
                {
                    let mut o = ops();
                    for iface in &mut o.interfaces {
                        if iface.name == old {
                            iface.name = new.to_string();
                        }
                    }
                }
                return Err(LinuxError::OperationTimeout {
                    op: "rename link up",
                    timeout_ms: 0,
                }
                .into());
            }
            gate("rename")
        }
        async fn nm_present() -> bool {
            ops().nm_present
        }
        async fn nm_release(iface: &str) -> Result<()> {
            record(format!("nm_release {iface}"));
            gate("nm_release")
        }
        async fn nm_reclaim(iface: &str) -> Result<()> {
            record(format!("nm_reclaim {iface}"));
            gate("nm_reclaim")
        }
        async fn wpa_present() -> bool {
            ops().wpa_present
        }
        async fn wpa_release(iface: &str) -> Result<()> {
            record(format!("wpa_release {iface}"));
            gate("wpa_release")
        }
        async fn wpa_reclaim(iface: &str) -> Result<()> {
            record(format!("wpa_reclaim {iface}"));
            gate("wpa_reclaim")
        }
    }

    // --- release_stack / reclaim_stack symmetry ---

    #[tokio::test]
    async fn release_stack_drops_from_both() {
        let _scope = ops_scope();
        {
            let mut o = ops();
            o.nm_present = true;
            o.wpa_present = true;
        }
        release_stack::<MockOps>("wlan0").await.unwrap();
        assert_eq!(calls(), vec!["nm_release wlan0", "wpa_release wlan0"]);
    }

    #[tokio::test]
    async fn reclaim_stack_mirrors_release() {
        let _scope = ops_scope();
        {
            let mut o = ops();
            o.nm_present = true;
            o.wpa_present = true;
        }
        // Mirrors a release that took the interface from both.
        let held = release_stack::<MockOps>("wlan0").await.unwrap();
        reclaim_stack::<MockOps>("wlan0", held).await.unwrap();
        assert_eq!(
            calls(),
            vec![
                "nm_release wlan0",
                "wpa_release wlan0",
                "nm_reclaim wlan0",
                "wpa_reclaim wlan0",
            ]
        );
    }

    #[tokio::test]
    async fn reclaim_stack_succeeds_with_no_services() {
        let _scope = ops_scope();
        reclaim_stack::<MockOps>("wlan0", Holders::default())
            .await
            .unwrap();
        assert!(calls().is_empty());
    }

    #[tokio::test]
    async fn reclaim_stack_hands_back_only_to_services_that_held_it() {
        let _scope = ops_scope();
        {
            let mut o = ops();
            // Both services are running, but only NetworkManager was holding
            // the interface; wpa_supplicant never had it.
            o.nm_present = true;
            o.wpa_present = true;
        }
        let held = Holders {
            network_manager: true,
            supplicant: false,
        };
        reclaim_stack::<MockOps>("wlan0", held).await.unwrap();

        // No `wpa_reclaim`: offering it would mean `CreateInterface`, handing
        // the supplicant an interface it never knew about and inviting it to
        // fight whatever the interface is now doing.
        assert_eq!(calls(), vec!["nm_reclaim wlan0"]);
    }

    #[tokio::test]
    async fn release_stack_records_only_the_services_that_were_present() {
        let _scope = ops_scope();
        ops().wpa_present = true;

        let held = release_stack::<MockOps>("wlan0").await.unwrap();
        assert_eq!(
            held,
            Holders {
                network_manager: false,
                supplicant: true,
            }
        );
        assert_eq!(calls(), vec!["wpa_release wlan0"]);
    }

    // --- enter rollback (verify + set_mode failure) ---

    #[tokio::test]
    async fn enter_verifies_then_reports_success() {
        let _scope = ops_scope();
        ops().nm_present = true;
        enter::<MockOps>(&iface("wlan0")).await.unwrap();
        assert_eq!(
            calls(),
            vec!["nm_release wlan0", "set_mode wlan0 monitor", "read_mode",]
        );
    }

    #[tokio::test]
    async fn enter_rolls_back_when_unhonored() {
        let _scope = ops_scope();
        {
            let mut o = ops();
            o.nm_present = true;
            // The switch is accepted but the driver stays managed.
            o.read_mode = InterfaceMode::Managed;
        }
        let err = enter::<MockOps>(&iface("wlan0")).await.unwrap_err();
        assert!(matches!(
            err,
            Error::Linux(LinuxError::MonitorVerifyFailed { .. })
        ));
        // Release, switch, read back not-monitor, then roll back: managed + reclaim.
        assert_eq!(
            calls(),
            vec![
                "nm_release wlan0",
                "set_mode wlan0 monitor",
                "read_mode",
                "set_mode wlan0 managed",
                "nm_reclaim wlan0",
            ]
        );
    }

    #[tokio::test]
    async fn enter_reclaims_on_switch_failure() {
        let _scope = ops_scope();
        {
            let mut o = ops();
            o.nm_present = true;
            o.fail = vec!["set_mode"];
        }
        let err = enter::<MockOps>(&iface("wlan0")).await.unwrap_err();
        assert!(matches!(
            err,
            Error::Linux(LinuxError::OperationTimeout { .. })
        ));
        // No read_mode (switch failed), straight to reclaim; no second set_mode.
        assert_eq!(
            calls(),
            vec![
                "nm_release wlan0",
                "set_mode wlan0 monitor",
                "nm_reclaim wlan0"
            ]
        );
    }

    #[tokio::test]
    async fn start_auto_uses_the_idle_radio_when_another_is_already_capturing() {
        let _scope = ops_scope();
        {
            let mut o = ops();
            // One radio is already in monitor mode: another tool, or a
            // leftover session. The other is free.
            o.interfaces = vec![monitor_iface("wlan0"), iface("wlan1")];
            o.nm_present = true;
        }

        // The busy radio is excluded, not fatal: auto-select warns and carries
        // on with the free one. Refusing outright here would make a single
        // stale interface block every other radio on the box.
        let chosen = start_auto_impl::<MockOps>().await.unwrap();
        assert_eq!(chosen.name(), "wlan1");

        // And the busy one was never touched on the way past.
        let calls = calls();
        assert!(
            !calls.iter().any(|call| call.contains("wlan0")),
            "the radio already capturing must not be touched; calls were {calls:?}",
        );
    }

    #[tokio::test]
    async fn start_auto_refuses_when_every_radio_is_already_capturing() {
        let _scope = ops_scope();
        {
            let mut o = ops();
            o.interfaces = vec![monitor_iface("wlan0"), monitor_iface("wlan1")];
            o.nm_present = true;
        }
        let err = start_auto_impl::<MockOps>().await.unwrap_err();
        assert!(matches!(err, Error::AlreadyMonitor { .. }));
        // Enumeration only; nothing was touched.
        assert_eq!(calls(), vec!["detect"]);
    }

    #[tokio::test]
    async fn enter_refuses_an_interface_already_in_monitor_mode() {
        let _scope = ops_scope();
        ops().nm_present = true;

        let err = enter::<MockOps>(&monitor_iface("wlan0")).await.unwrap_err();
        assert!(matches!(err, Error::AlreadyMonitor { .. }));
        // Refused before the release, so nothing was touched: a rejected call
        // must not disturb the capture that is already running.
        assert!(calls().is_empty(), "calls were {:?}", calls());
    }

    #[tokio::test]
    async fn start_on_refuses_a_busy_interface_by_name() {
        let _scope = ops_scope();
        {
            let mut o = ops();
            // The by-name path skips scoring, so the ban has to catch it too.
            o.interfaces = vec![monitor_iface("wlan0")];
            o.nm_present = true;
        }
        let err = start_on_impl::<MockOps>("wlan0").await.unwrap_err();
        assert!(matches!(err, Error::AlreadyMonitor { .. }));
        assert_eq!(calls(), vec!["detect"]);
    }

    #[tokio::test]
    async fn start_as_refuses_a_busy_interface_by_name() {
        let _scope = ops_scope();
        {
            let mut o = ops();
            o.interfaces = vec![monitor_iface("wlan0")];
            o.nm_present = true;
        }
        let err = start_as_impl::<MockOps>("wlan0", "mon0").await.unwrap_err();
        assert!(matches!(err, Error::AlreadyMonitor { .. }));
        // No rename either: the refusal happens before anything is applied.
        assert_eq!(calls(), vec!["detect"]);
    }

    #[tokio::test]
    async fn enter_rolls_back_on_readback_error() {
        let _scope = ops_scope();
        {
            let mut o = ops();
            o.nm_present = true;
            // The switch is accepted, but confirming it fails outright: a
            // transient netlink error, or the adapter pulled mid-operation.
            o.fail = vec!["read_mode"];
        }
        let err = enter::<MockOps>(&iface("wlan0")).await.unwrap_err();
        // The readback's own error surfaces, not a verify failure.
        assert!(matches!(
            err,
            Error::Linux(LinuxError::OperationTimeout { .. })
        ));
        // Rolling back matters more than the error: without it the interface is
        // left in monitor mode and unmanaged, with no guard to clean it up.
        assert_eq!(
            calls(),
            vec![
                "nm_release wlan0",
                "set_mode wlan0 monitor",
                "read_mode",
                "set_mode wlan0 managed",
                "nm_reclaim wlan0",
            ]
        );
    }

    // --- open findings, asserted as the behaviour we want ---

    #[tokio::test]
    async fn leave_errors_when_managed_mode_is_not_honoured() {
        let _scope = ops_scope();
        {
            let mut o = ops();
            o.interfaces = vec![monitor_iface("wlan0")];
            o.nm_present = true;
            // The switch back is accepted but the driver stays in monitor mode,
            // the same lie `enter` already defends against, on the way out.
            o.read_mode = InterfaceMode::Monitor;
        }
        let err = leave::<MockOps>("wlan0").await.unwrap_err();
        assert!(matches!(
            err,
            Error::Linux(LinuxError::ManagedVerifyFailed {
                actual: InterfaceMode::Monitor,
                ..
            })
        ));
        // No handback: the mode never changed, so the interface is exactly as it
        // was, and offering a still-monitor radio to a network manager would
        // invite it to fight the driver.
        assert_eq!(
            calls(),
            vec!["detect", "set_mode wlan0 managed", "read_mode"]
        );
    }

    #[tokio::test]
    async fn start_as_renames_back_when_the_rename_took_but_failed() {
        let _scope = ops_scope();
        {
            let mut o = ops();
            o.interfaces = vec![iface("wlan0")];
            o.nm_present = true;
            o.rename_takes_then_fails = true;
        }
        let result = start_as_impl::<MockOps>("wlan0", "mon0").await;
        assert!(
            result.is_err(),
            "the rename reported failure, so should this"
        );

        // The name really did change, so rollback has to put it back. Without
        // that, the interface is left under `mon0` while the handback is
        // addressed to `wlan0`, a name no longer on the system.
        let calls = calls();
        assert!(
            calls.contains(&"rename mon0->wlan0".to_string()),
            "rollback must rename back after a rename that took; calls were {calls:?}",
        );
    }

    #[tokio::test]
    async fn start_auto_falls_back_to_the_next_candidate() {
        let _scope = ops_scope();
        {
            let mut o = ops();
            // Two plausible radios. The better-scoring one is a Realtek that
            // advertises monitor mode and then refuses the switch: the case
            // the driver-name heuristic exists to guess at and cannot confirm.
            let mut best = iface("wlan0");
            best.driver = Some("rtl8812au".to_string());
            best.bus = crate::interface::BusKind::Usb;
            let second = iface("wlan1");
            o.interfaces = vec![best, second];
            o.fail_set_mode_on = vec!["wlan0".to_string()];
        }

        let chosen = start_auto_impl::<MockOps>().await;
        match chosen {
            Ok(iface) => assert_eq!(
                iface.name(),
                "wlan1",
                "should have fallen back to the working radio",
            ),
            Err(error) => panic!(
                "gave up after the first candidate instead of trying the next: {error}; \
                 calls were {:?}",
                calls(),
            ),
        }
    }

    // --- with_timeout deadlines ---

    #[tokio::test]
    async fn start_auto_reports_the_last_failure_when_every_candidate_refuses() {
        let _scope = ops_scope();
        {
            let mut o = ops();
            o.interfaces = vec![iface("wlan0"), iface("wlan1")];
            o.fail_set_mode_on = vec!["wlan0".to_string(), "wlan1".to_string()];
        }
        let err = start_auto_impl::<MockOps>().await.unwrap_err();
        assert!(matches!(
            err,
            Error::Linux(LinuxError::OperationTimeout { op: "set_mode", .. })
        ));
        // Both were tried before giving up, in ranked order.
        let calls = calls();
        assert!(
            calls.contains(&"set_mode wlan0 monitor".to_string())
                && calls.contains(&"set_mode wlan1 monitor".to_string()),
            "both candidates should have been attempted; calls were {calls:?}",
        );
    }

    #[tokio::test]
    async fn with_timeout_passes_result_through() {
        let value = with_timeout("quick op", NETLINK_TIMEOUT, async { Ok(7u32) })
            .await
            .unwrap();
        assert_eq!(value, 7);
    }

    #[tokio::test]
    async fn with_timeout_errors_on_deadline() {
        tokio::time::pause();

        // A future that never resolves: only the deadline can end this.
        let op = tokio::spawn(with_timeout("stuck op", NETLINK_TIMEOUT, async {
            std::future::pending::<Result<()>>().await
        }));
        tokio::task::yield_now().await; // let the timer register

        // Just under the deadline: still pending.
        tokio::time::advance(NETLINK_TIMEOUT - Duration::from_millis(1)).await;
        assert!(!op.is_finished());

        // Past it: the typed timeout, carrying the deadline that elapsed.
        tokio::time::advance(Duration::from_millis(2)).await;
        let err = op.await.unwrap().unwrap_err();
        assert!(matches!(
            err,
            Error::Linux(LinuxError::OperationTimeout {
                op: "stuck op",
                timeout_ms: 5_000,
                ..
            })
        ));
    }

    // --- set_channel verification ---

    // A readback for a driver that honoured the request exactly.
    fn honoured(freq_mhz: u32, width: ChannelWidth) -> ChannelState {
        match width {
            ChannelWidth::Mhz20 => ChannelState {
                freq_mhz: Some(freq_mhz),
                width_mhz: Some(20),
                center_mhz: Some(freq_mhz),
            },
            ChannelWidth::Mhz40Above => ChannelState {
                freq_mhz: Some(freq_mhz),
                width_mhz: Some(40),
                center_mhz: Some(freq_mhz + 10),
            },
            ChannelWidth::Mhz40Below => ChannelState {
                freq_mhz: Some(freq_mhz),
                width_mhz: Some(40),
                center_mhz: Some(freq_mhz - 10),
            },
        }
    }

    #[tokio::test]
    async fn set_channel_confirms_the_frequency_took() {
        let _scope = ops_scope();
        ops().read_channel = honoured(5180, ChannelWidth::Mhz20);
        set_channel_verified::<MockOps>(&iface("wlan0"), 5180, ChannelWidth::Mhz20)
            .await
            .unwrap();
        assert_eq!(calls(), vec!["set_freq wlan0 5180", "read_channel"]);
    }

    #[tokio::test]
    async fn set_channel_confirms_both_ht40_variants() {
        for width in [ChannelWidth::Mhz40Above, ChannelWidth::Mhz40Below] {
            let _scope = ops_scope();
            ops().read_channel = honoured(5180, width);
            set_channel_verified::<MockOps>(&iface("wlan0"), 5180, width)
                .await
                .unwrap_or_else(|e| panic!("{width} should verify: {e}"));
        }
    }

    #[tokio::test]
    async fn set_channel_errors_when_the_driver_narrows_the_width() {
        let _scope = ops_scope();
        // The quiet failure: right frequency, but 40 MHz silently became 20.
        ops().read_channel = honoured(5180, ChannelWidth::Mhz20);
        let err = set_channel_verified::<MockOps>(&iface("wlan0"), 5180, ChannelWidth::Mhz40Above)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            Error::Linux(LinuxError::WidthVerifyFailed {
                primary_mhz: 5180,
                requested: ChannelWidth::Mhz40Above,
                actual: WidthReadback::Known(ChannelWidth::Mhz20),
                ..
            })
        ));
    }

    #[tokio::test]
    async fn set_channel_errors_when_ht40_lands_on_the_wrong_side() {
        let _scope = ops_scope();
        // 40 MHz was honoured, but the secondary sits below where we asked above.
        ops().read_channel = honoured(5180, ChannelWidth::Mhz40Below);
        let err = set_channel_verified::<MockOps>(&iface("wlan0"), 5180, ChannelWidth::Mhz40Above)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            Error::Linux(LinuxError::WidthVerifyFailed {
                actual: WidthReadback::Known(ChannelWidth::Mhz40Below),
                ..
            })
        ));
    }

    #[tokio::test]
    async fn set_channel_errors_when_the_segment_centre_is_misaligned() {
        let _scope = ops_scope();
        // 40 MHz at a centre that is neither primary +10 nor -10.
        ops().read_channel = ChannelState {
            freq_mhz: Some(5180),
            width_mhz: Some(40),
            center_mhz: Some(5210),
        };
        let err = set_channel_verified::<MockOps>(&iface("wlan0"), 5180, ChannelWidth::Mhz40Above)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            Error::Linux(LinuxError::WidthVerifyFailed {
                actual: WidthReadback::Misaligned {
                    center_mhz: Some(5210)
                },
                ..
            })
        ));
    }

    #[tokio::test]
    async fn set_channel_errors_when_the_width_is_wider_than_requested() {
        let _scope = ops_scope();
        // Something else left the device at 80 MHz and the set did not narrow it.
        ops().read_channel = ChannelState {
            freq_mhz: Some(5180),
            width_mhz: Some(80),
            center_mhz: Some(5210),
        };
        let err = set_channel_verified::<MockOps>(&iface("wlan0"), 5180, ChannelWidth::Mhz20)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            Error::Linux(LinuxError::WidthVerifyFailed {
                actual: WidthReadback::Other { mhz: 80 },
                ..
            })
        ));
    }

    #[tokio::test]
    async fn set_channel_accepts_ht20_reported_as_plain_20() {
        let _scope = ops_scope();
        // nl80211 distinguishes 20_NOHT from 20; both are 20 MHz for our
        // purposes, and demanding the exact variant would fail honoured sets.
        ops().read_channel = ChannelState {
            freq_mhz: Some(2412),
            width_mhz: Some(20),
            center_mhz: None,
        };
        set_channel_verified::<MockOps>(&iface("wlan0"), 2412, ChannelWidth::Mhz20)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn set_channel_errors_on_mismatch() {
        let _scope = ops_scope();
        // Accepted the set but stayed elsewhere.
        ops().read_channel = honoured(2412, ChannelWidth::Mhz20);
        let err = set_channel_verified::<MockOps>(&iface("wlan0"), 5180, ChannelWidth::Mhz20)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            Error::Linux(LinuxError::ChannelVerifyFailed {
                requested_mhz: 5180,
                actual: FrequencyReadback::Mhz(2412),
                ..
            })
        ));
    }

    #[tokio::test]
    async fn set_channel_errors_when_untuned() {
        let _scope = ops_scope();
        ops().read_channel = ChannelState::UNTUNED; // reports untuned after the set
        let err = set_channel_verified::<MockOps>(&iface("wlan0"), 5180, ChannelWidth::Mhz20)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            Error::Linux(LinuxError::ChannelVerifyFailed {
                actual: FrequencyReadback::None,
                ..
            })
        ));
    }

    // --- leave tolerance ---

    #[tokio::test]
    async fn leave_succeeds_even_when_handback_fails() {
        let _scope = ops_scope();
        {
            let mut o = ops();
            o.interfaces = vec![monitor_iface("wlan0")];
            o.nm_present = true;
            o.fail = vec!["nm_reclaim"];
            // The driver honoured the switch back.
            o.read_mode = InterfaceMode::Managed;
        }
        // The mode switch to managed succeeds and verifies; only the courtesy
        // handback fails.
        leave::<MockOps>("wlan0").await.unwrap();
        assert_eq!(
            calls(),
            vec![
                "detect",
                "set_mode wlan0 managed",
                "read_mode",
                "nm_reclaim wlan0",
            ]
        );
    }

    #[tokio::test]
    async fn leave_skips_switch_when_managed() {
        let _scope = ops_scope();
        {
            let mut o = ops();
            // Managed, not monitor: the blind `stop_monitor wlan0` case.
            o.interfaces = vec![iface("wlan0")];
            o.nm_present = true;
        }
        leave::<MockOps>("wlan0").await.unwrap();
        // No set_mode: bouncing the link would drop a live association on an
        // interface that was never in monitor mode. The handback still runs, in
        // case something else reverted the mode while it sat released.
        assert_eq!(calls(), vec!["detect", "nm_reclaim wlan0"]);
    }

    #[tokio::test]
    async fn leave_fails_on_switch_failure() {
        let _scope = ops_scope();
        {
            let mut o = ops();
            o.interfaces = vec![monitor_iface("wlan0")];
            o.nm_present = true;
            o.fail = vec!["set_mode"];
        }
        let err = leave::<MockOps>("wlan0").await.unwrap_err();
        assert!(matches!(
            err,
            Error::Linux(LinuxError::OperationTimeout { .. })
        ));
        // Reclaim is never reached: the interface is not back in managed mode.
        assert_eq!(calls(), vec!["detect", "set_mode wlan0 managed"]);
    }

    // --- start_as rollback ---

    #[tokio::test]
    async fn start_as_rolls_back_when_rename_fails() {
        let _scope = ops_scope();
        {
            let mut o = ops();
            o.interfaces = vec![iface("wlan0")];
            o.nm_present = true;
            o.fail = vec!["rename"];
        }
        let result = start_as_impl::<MockOps>("wlan0", "mon0").await;
        assert!(matches!(
            result,
            Err(Error::Linux(LinuxError::OperationTimeout { .. }))
        ));
        // find, enter (release/set monitor/read), failed rename, then roll back.
        // The reverse rename runs even though this rename failed outright: the
        // caller cannot tell that from a rename that took and then failed to
        // bring the link up, and it is a no-op when the name never changed.
        assert_eq!(
            calls(),
            vec![
                "detect",
                "nm_release wlan0",
                "set_mode wlan0 monitor",
                "read_mode",
                "rename wlan0->mon0",
                "rename mon0->wlan0",
                "set_mode wlan0 managed",
                "nm_reclaim wlan0",
            ]
        );
    }

    #[tokio::test]
    async fn start_as_rolls_back_on_redetect_failure() {
        let _scope = ops_scope();
        {
            let mut o = ops();
            // `wlan0` exists for the initial find, but the post-rename find for
            // `mon0` will miss: the previously un-rolled-back path.
            o.interfaces = vec![iface("wlan0")];
            o.nm_present = true;
        }
        let result = start_as_impl::<MockOps>("wlan0", "mon0").await;
        assert!(matches!(result, Err(Error::NotFound { .. })));
        // The rename took, so rollback must rename mon0 back to wlan0, restore
        // managed mode, and hand the interface back.
        assert_eq!(
            calls(),
            vec![
                "detect",
                "nm_release wlan0",
                "set_mode wlan0 monitor",
                "read_mode",
                "rename wlan0->mon0",
                "detect",
                "rename mon0->wlan0",
                "set_mode wlan0 managed",
                "nm_reclaim wlan0",
            ]
        );
    }
}
