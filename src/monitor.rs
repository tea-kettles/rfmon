//! Public monitor-mode API and the cross-platform backend seam.
//!
//! This module defines the [`MonitorBackend`] trait, the contract every OS
//! backend implements, plus the version- and distro-agnostic entry points the
//! library is built around:
//!
//!   * [`start_monitor`]: auto-select the best capable interface and enter
//!     monitor mode.
//!   * [`start_monitor_on`]: enter monitor mode on a named interface, skipping
//!     selection.
//!   * [`start_monitor_as`]: enter monitor mode and rename the interface.
//!   * [`stop_monitor`]: the stateless, name-based recovery path.
//!
//! The three `start_*` functions return a [`MonitorGuard`] whose scope owns the
//! session: it restores managed networking when it drops (or via
//! [`MonitorGuard::restore`]). [`stop_monitor`] exists for the cases a guard
//! cannot cover: cleaning up an interface by name across process boundaries,
//! e.g. after a crash left one stranded in monitor mode.
//!
//! The public functions do no OS-specific work themselves; they dispatch to the
//! active platform's [`MonitorBackend`] via the [`Backend`] alias resolved at
//! compile time.

use std::future::{Future, IntoFuture};
use std::pin::Pin;

use tracing::warn;

use crate::cleanup::MonitorGuard;
use crate::interface::{BandScope, ChannelWidth, WirelessInterface, resolve_frequency};
use crate::{Error, Result};

/* Backend selection */
//
// Exactly one backend is compiled in per target OS. Adding a platform means
// implementing `MonitorBackend` for it and wiring an alias here. Under `test`
// the alias resolves to an in-memory mock instead, so the backend-generic
// dispatch (and `MonitorGuard` teardown, which routes through it) is exercised
// without touching real hardware.

#[cfg(all(target_os = "linux", not(test)))]
use crate::linux::LinuxBackend as Backend;
#[cfg(all(not(any(target_os = "linux", target_os = "windows")), not(test)))]
use crate::unsupported::UnsupportedBackend as Backend;
#[cfg(all(target_os = "windows", not(test)))]
use crate::windows::WindowsBackend as Backend;
#[cfg(test)]
use tests::MockBackend as Backend;

/* Traits */

/// The per-platform monitor-mode control contract.
///
/// Each supported OS provides one implementor (a zero-sized backend type). The
/// public `start_monitor` / `start_monitor_on` / `stop_monitor` functions are
/// thin wrappers over these methods, so platform behavior stays entirely inside
/// the backend while the public surface is identical everywhere.
#[allow(async_fn_in_trait)]
pub(crate) trait MonitorBackend {
    /// Enumerate all wireless interfaces with their device capabilities.
    async fn detect() -> Result<Vec<WirelessInterface>>;

    /// Select the best capable interface and put it into monitor mode.
    ///
    /// Returns the interface that was activated. Errors if no interface is
    /// present ([`crate::Error::NoInterfaces`]) or none are monitor-capable
    /// ([`crate::Error::NoMonitorCapable`]).
    async fn start_auto() -> Result<WirelessInterface>;

    /// Put a specific named interface into monitor mode, skipping selection.
    async fn start_on(name: &str) -> Result<WirelessInterface>;

    /// Put a named interface into monitor mode and rename it to `new_name`.
    ///
    /// Returns the interface under its new name.
    async fn start_as(name: &str, new_name: &str) -> Result<WirelessInterface>;

    /// Rename an interface (e.g. back to its original name during teardown).
    async fn rename(current: &str, new: &str) -> Result<()>;

    /// Set the operating channel of a monitor-mode interface.
    async fn set_channel(
        iface: &WirelessInterface,
        freq_mhz: u32,
        width: ChannelWidth,
    ) -> Result<()>;

    /// Take a named interface out of monitor mode and restore managed
    /// networking (returning control to NetworkManager / wpa_supplicant).
    async fn stop(name: &str) -> Result<()>;
}

/* Public API */

/// Automatically select the best monitor-capable interface and enter monitor
/// mode, returning an RAII [`MonitorGuard`].
///
/// Uses the scoring in [`WirelessInterface::monitor_score`] to pick the most
/// suitable radio: a known monitor-capable USB adapter that is idle outranks
/// the built-in card carrying the host's connection.
///
/// The returned guard restores managed networking when it drops (or via
/// [`MonitorGuard::restore`]); read the chosen interface with
/// [`MonitorGuard::name`]. Requires `CAP_NET_ADMIN` (root).
///
/// # Errors
///
/// [`Error::NoInterfaces`] if the system has no wireless interfaces at all,
/// [`Error::NoMonitorCapable`] if none of them is a plausible monitor
/// candidate, or a platform error if the mode switch itself fails. Use
/// [`start_monitor_on`] to skip selection and name the interface yourself.
///
/// Radios already in monitor mode are skipped with a warning naming them, since
/// something else owns them (see [`Error::AlreadyMonitor`]). One busy radio does
/// not block the others; [`Error::AlreadyMonitor`] is returned only when every
/// candidate is busy.
///
/// Candidates are tried in ranked order until one is confirmed in monitor mode.
/// Monitor capability is a prediction until it is tried: the driver-name table
/// is a heuristic, and a radio that advertises the mode can still refuse the
/// switch, so a refusal moves on to the next candidate rather than failing the
/// call. Each attempt rolls back before the next, and the error returned when
/// every candidate refuses is the last one.
///
/// # Examples
///
/// ```no_run
/// # #[tokio::main]
/// # async fn main() -> rfmon::Result<()> {
/// let mon = rfmon::start_monitor().await?;
/// println!("monitoring on {}", mon.name());
/// # Ok(())
/// # }
/// ```
pub async fn start_monitor() -> Result<MonitorGuard> {
    start_monitor_with::<Backend>().await
}

/// Enter monitor mode on a specific interface by name, skipping scoring.
///
/// Returns an RAII [`MonitorGuard`] that restores managed networking when it
/// drops (or via [`MonitorGuard::restore`]). Requires `CAP_NET_ADMIN` (root).
///
/// # Errors
///
/// [`Error::AlreadyMonitor`] if the interface is already in monitor mode. This
/// path skips scoring, so the check that auto-selection applies is enforced here
/// instead: something else owns that interface, and taking it strands a state
/// neither tool will clean up. Call [`stop_monitor`] first if it is stale.
///
/// # Examples
///
/// ```no_run
/// # #[tokio::main]
/// # async fn main() -> rfmon::Result<()> {
/// let mon = rfmon::start_monitor_on("wlan0").await?;
/// assert_eq!(mon.name(), "wlan0");
/// # Ok(())
/// # }
/// ```
pub async fn start_monitor_on(name: &str) -> Result<MonitorGuard> {
    start_monitor_on_with::<Backend>(name).await
}

/// Leave monitor mode on `name` and return the interface to managed networking.
///
/// Switches the interface back to managed mode and hands control to whichever
/// network manager is present: NetworkManager if it is running, otherwise
/// wpa_supplicant, otherwise nothing (a minimal headless host). Returns the
/// name of the interface that was changed.
///
/// An interface that is *not* in monitor mode keeps its current mode: the
/// switch would bounce the link and drop a live association, so calling this on
/// the host's own uplink is harmless. The handback to a network manager still
/// runs, which is what repairs an interface another tool reverted out of
/// monitor mode while it sat released.
///
/// Durable across distributions: a missing NetworkManager or wpa_supplicant is
/// not an error, and a host without a system D-Bus at all is handled too.
/// Requires `CAP_NET_ADMIN` (root).
///
/// # Errors
///
/// The switch back is read back and confirmed, so a driver that accepts it
/// without honoring it yields `ManagedVerifyFailed` rather than a false success;
/// otherwise the radio keeps capturing while every caller believes it was
/// released. The handback is skipped in that case: the mode never changed, so
/// the interface is left exactly as it was and a retry starts from a known
/// state.
///
/// # Examples
///
/// ```no_run
/// # #[tokio::main]
/// # async fn main() -> rfmon::Result<()> {
/// rfmon::stop_monitor("wlan0").await?;
/// # Ok(())
/// # }
/// ```
pub async fn stop_monitor(name: &str) -> Result<String> {
    stop_monitor_with::<Backend>(name).await
}

/// Restore *every* interface currently in monitor mode to managed networking.
///
/// A best-effort emergency sweep for a system-wide mess: it stops each
/// monitor-mode interface it finds, logging (not aborting) on any individual
/// failure, and returns the names it successfully restored. Interfaces already
/// in managed mode are left untouched, so a working connection is not disturbed.
///
/// Requires `CAP_NET_ADMIN` (root). Only enumeration failing is a hard error.
///
/// # Examples
///
/// ```no_run
/// # #[tokio::main]
/// # async fn main() -> rfmon::Result<()> {
/// let restored = rfmon::stop_all_monitors().await?;
/// println!("restored {} interface(s)", restored.len());
/// # Ok(())
/// # }
/// ```
pub async fn stop_all_monitors() -> Result<Vec<String>> {
    stop_all_with::<Backend>().await
}

/// Enter monitor mode on `name` and rename the interface to `new_name`,
/// returning an RAII [`MonitorGuard`].
///
/// Unlike airmon-ng (which creates a second `…mon` interface), rfmon switches
/// the existing device in place, so without this it simply keeps its original
/// name. Use this when you want a distinct, deliberate name for the capture
/// interface.
///
/// Returns [`Error::AlreadyMonitor`] if the interface is already in monitor
/// mode, for the same reason [`start_monitor_on`] does.
///
/// The rename is *scoped* to the guard: [`MonitorGuard::restore`] (or dropping
/// the guard) renames the interface back to `name` and restores managed
/// networking, so the rename never persists past the session. Access the
/// current name with [`MonitorGuard::name`]. Requires `CAP_NET_ADMIN` (root).
///
/// # Examples
///
/// ```no_run
/// # #[tokio::main]
/// # async fn main() -> rfmon::Result<()> {
/// let mon = rfmon::start_monitor_as("wlan0", "capture0").await?;
/// assert_eq!(mon.name(), "capture0");
/// // ... capture on mon.name() ...
/// mon.restore().await?; // renames back to wlan0 and restores managed networking
/// # Ok(())
/// # }
/// ```
pub async fn start_monitor_as(name: &str, new_name: &str) -> Result<MonitorGuard> {
    start_monitor_as_with::<Backend>(name, new_name).await
}

/// Set the operating channel of a monitor-mode interface, on 2.4 or 5 GHz.
///
/// Returns a builder that runs when awaited and yields the interface name. The
/// channel is a plain channel number: 2.4 GHz is 1–14 and 5 GHz is 32–177, and
/// those two do not overlap, so the number alone picks the band. The frequency
/// is then resolved against the channels the device actually supports. Defaults
/// to 20 MHz, which carries all management and EAPOL traffic.
///
/// **6 GHz is deliberately not searched here**, because it reuses channel numbers that
/// 2.4 GHz and 5 GHz already use (1, 5, 9, 13 and 149–177), so a bare number
/// would be ambiguous on a Wi-Fi 6E adapter. Use [`set_channel_6g`] for that
/// band; asking for a 6 GHz-only number here returns
/// [`Error::WrongBand`](crate::Error::WrongBand) naming the call you want.
///
/// Call this after entering monitor mode. Requires `CAP_NET_ADMIN` (root).
///
/// # Examples
///
/// ```no_run
/// use rfmon::ChannelWidth;
///
/// # #[tokio::main]
/// # async fn main() -> rfmon::Result<()> {
/// rfmon::set_channel("wlan0", 6).await?;   // 2.4 GHz ch 6, 20 MHz
/// rfmon::set_channel("wlan0", 149)         // 5 GHz ch 149, 40 MHz
///     .with_width(ChannelWidth::Mhz40Above)
///     .await?;
/// # Ok(())
/// # }
/// ```
pub fn set_channel(iface: &str, channel: u32) -> SetChannel {
    SetChannel::new(iface, channel, BandScope::ExceptSixGhz)
}

/// Set the operating channel of a monitor-mode interface, on 6 GHz.
///
/// The 6 GHz counterpart to [`set_channel`], identical but for the band it
/// searches. 6 GHz channels are numbered 1, 5, 9, … 233 (center frequency
/// 5950 + 5 × channel MHz), which collides with the 2.4 GHz and 5 GHz numbering.
/// Naming the band in the call is what keeps a bare number unambiguous.
///
/// Requires a 6E-capable adapter; on anything else the channel simply is not
/// present and this returns
/// [`Error::ChannelUnavailable`](crate::Error::ChannelUnavailable). Passing a
/// number that is only a 2.4/5 GHz channel returns
/// [`Error::WrongBand`](crate::Error::WrongBand) pointing back at
/// [`set_channel`]. Requires `CAP_NET_ADMIN` (root).
///
/// # Examples
///
/// ```no_run
/// # #[tokio::main]
/// # async fn main() -> rfmon::Result<()> {
/// rfmon::set_channel_6g("wlan0", 1).await?;    // 6 GHz ch 1 = 5955 MHz
/// rfmon::set_channel_6g("wlan0", 149).await?;  // 6 GHz ch 149 = 6695 MHz
/// # Ok(())
/// # }
/// ```
pub fn set_channel_6g(iface: &str, channel: u32) -> SetChannel {
    SetChannel::new(iface, channel, BandScope::SixGhzOnly)
}

/* Types */

/// A pending [`set_channel`] or [`set_channel_6g`] call.
///
/// Configure it with [`with_width`](Self::with_width), then `.await` it.
/// Awaiting resolves the channel against the device, applies it, and yields the
/// interface name. The band is fixed by which function produced the builder, so
/// there is nothing band-related to configure here.
#[derive(Debug)]
#[must_use = "set_channel does nothing until awaited"]
pub struct SetChannel {
    target: Target,
    channel: u32,
    width: ChannelWidth,
    scope: BandScope,
}

// How the interface a channel set targets is obtained. The free `set_channel`
// functions know only a name and must enumerate to resolve it; a `MonitorGuard`
// already holds the resolved interface from when it entered monitor mode, so it
// tunes without a fresh `detect()`, the difference between one `SET_WIPHY` per
// hop and re-enumerating every phy on the system per hop.
#[derive(Debug)]
enum Target {
    ByName(String),
    Resolved(Box<WirelessInterface>),
}

impl SetChannel {
    // Construction for the two free, name-based entry points.
    fn new(iface: &str, channel: u32, scope: BandScope) -> Self {
        Self {
            target: Target::ByName(iface.to_string()),
            channel,
            width: ChannelWidth::Mhz20,
            scope,
        }
    }

    // Construction for the guard methods, which already hold the interface.
    pub(crate) fn from_iface(iface: WirelessInterface, channel: u32, scope: BandScope) -> Self {
        Self {
            target: Target::Resolved(Box::new(iface)),
            channel,
            width: ChannelWidth::Mhz20,
            scope,
        }
    }

    /// Set the channel bandwidth (default [`ChannelWidth::Mhz20`]).
    ///
    /// Named `with_width` rather than `set_width` because it configures a
    /// pending operation rather than assigning to a live object: it consumes
    /// and returns the builder, and nothing reaches the device until the
    /// builder is awaited.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rfmon::ChannelWidth;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> rfmon::Result<()> {
    /// // 40 MHz capture with the secondary channel above the primary.
    /// rfmon::set_channel("wlan0", 36)
    ///     .with_width(ChannelWidth::Mhz40Above)
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_width(mut self, width: ChannelWidth) -> Self {
        self.width = width;
        self
    }
}

impl IntoFuture for SetChannel {
    type Output = Result<String>;
    type IntoFuture = Pin<Box<dyn Future<Output = Result<String>> + Send>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(set_channel_with::<Backend>(self))
    }
}

/* Free functions */

// Backend interface enumeration, exposed to `WirelessInterface::detect`.
pub(crate) async fn detect() -> Result<Vec<WirelessInterface>> {
    Backend::detect().await
}

// Restore a possibly-renamed interface: rename it back to `original` (when it
// differs from `current`), then return it to managed networking. Backs
// [`MonitorGuard`] teardown.
pub(crate) async fn restore_named(current: &str, original: &str) -> Result<String> {
    restore_named_with::<Backend>(current, original).await
}

/* Backend-generic dispatch */
//
// The public entry points above are thin wrappers that pin the compile-time
// `Backend`; the orchestration lives in these `*_with<B>` functions so it can be
// exercised against a mock `MonitorBackend` in tests without touching hardware.
// Everything platform-specific stays below the trait, inside each backend.

async fn start_monitor_with<B: MonitorBackend>() -> Result<MonitorGuard> {
    let iface = B::start_auto().await?;
    Ok(MonitorGuard::new(iface))
}

async fn start_monitor_on_with<B: MonitorBackend>(name: &str) -> Result<MonitorGuard> {
    let iface = B::start_on(name).await?;
    Ok(MonitorGuard::new(iface))
}

async fn start_monitor_as_with<B: MonitorBackend>(
    name: &str,
    new_name: &str,
) -> Result<MonitorGuard> {
    crate::interface::validate_iface_name(new_name)?;
    let iface = B::start_as(name, new_name).await?;
    Ok(MonitorGuard::from_rename(name.to_string(), iface))
}

async fn stop_monitor_with<B: MonitorBackend>(name: &str) -> Result<String> {
    B::stop(name).await?;
    Ok(name.to_string())
}

async fn stop_all_with<B: MonitorBackend>() -> Result<Vec<String>> {
    let interfaces = B::detect().await?;
    let mut restored = Vec::new();

    for iface in interfaces {
        if !iface.is_monitor() {
            continue;
        }
        match B::stop(iface.name()).await {
            Ok(()) => restored.push(iface.name().to_string()),
            Err(error) => warn!(
                iface = %iface.name(),
                %error,
                "failed to restore interface during stop_all_monitors",
            ),
        }
    }

    Ok(restored)
}

async fn set_channel_with<B: MonitorBackend>(request: SetChannel) -> Result<String> {
    // A guard-held interface tunes directly; a bare name is resolved by
    // enumeration. Either way, resolution against the device's real band list
    // still gives the friendly `ChannelUnavailable` / `WrongBand` errors.
    let iface = match request.target {
        Target::Resolved(iface) => *iface,
        Target::ByName(name) => {
            let interfaces = B::detect().await?;
            let available = interfaces
                .iter()
                .map(|i| i.name())
                .collect::<Vec<_>>()
                .join(", ");
            interfaces
                .into_iter()
                .find(|i| i.name() == name)
                .ok_or(Error::NotFound { name, available })?
        }
    };

    let freq = resolve_frequency(&iface, request.channel, request.scope)?;
    B::set_channel(&iface, freq, request.width).await?;
    Ok(iface.name().to_string())
}

async fn restore_named_with<B: MonitorBackend>(current: &str, original: &str) -> Result<String> {
    if current != original {
        B::rename(current, original).await?;
    }
    B::stop(original).await?;
    Ok(original.to_string())
}

/* Tests */

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, MutexGuard};

    use super::*;
    use crate::MacAddr;
    use crate::cleanup::MonitorGuard;
    use crate::interface::{Band, BandKind, BusKind, Frequency, InterfaceMode};

    // Programmable state for `MockBackend`. A single global instance stands in
    // for the kernel: `detect` returns `interfaces`, `stop` errors for any name
    // in `fail_stop`, and every call appends to `calls` so tests can assert the
    // exact sequence a dispatcher made.
    struct MockState {
        interfaces: Vec<WirelessInterface>,
        fail_stop: Vec<String>,
        calls: Vec<String>,
    }

    impl MockState {
        const fn new() -> Self {
            Self {
                interfaces: Vec::new(),
                fail_stop: Vec::new(),
                calls: Vec::new(),
            }
        }
    }

    static MOCK: Mutex<MockState> = Mutex::new(MockState::new());
    // Because `MockState` is a single global, mock-using tests must not run
    // concurrently; each takes this lock for its duration and resets the state.
    static SERIAL: Mutex<()> = Mutex::new(());

    // RAII test scope: serializes mock tests and clears state on entry. Tolerates
    // a poisoned lock from an earlier panicking test so one failure does not
    // cascade into "lock poisoned" noise across the rest.
    struct MockScope(#[allow(dead_code)] MutexGuard<'static, ()>);

    fn mock_scope() -> MockScope {
        let serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        *MOCK.lock().unwrap_or_else(|e| e.into_inner()) = MockState::new();
        MockScope(serial)
    }

    fn lock() -> MutexGuard<'static, MockState> {
        MOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn set_interfaces(interfaces: Vec<WirelessInterface>) {
        lock().interfaces = interfaces;
    }

    fn fail_stop(name: &str) {
        lock().fail_stop.push(name.to_string());
    }

    fn calls() -> Vec<String> {
        lock().calls.clone()
    }

    // A minimal interface carrying 2.4 GHz channel 1 (2412 MHz) so channel
    // resolution has something to resolve against.
    fn iface(name: &str, mode: InterfaceMode) -> WirelessInterface {
        WirelessInterface {
            name: name.to_string(),
            index: 1,
            phy_index: 0,
            mac: MacAddr::ZERO,
            mode,
            supported_modes: vec![InterfaceMode::Monitor],
            bands: vec![Band {
                kind: BandKind::TwoGhz,
                frequencies: vec![Frequency {
                    mhz: 2412,
                    channel: Some(1),
                    disabled: false,
                    radar: false,
                }],
            }],
            driver: None,
            bus: BusKind::Other,
            ssid: None,
        }
    }

    /// In-memory [`MonitorBackend`] used as `Backend` under `test`. Records every
    /// call and returns programmed data; performs no real I/O.
    pub(super) struct MockBackend;

    impl MonitorBackend for MockBackend {
        async fn detect() -> Result<Vec<WirelessInterface>> {
            let mut m = lock();
            m.calls.push("detect".to_string());
            Ok(m.interfaces.clone())
        }

        async fn start_auto() -> Result<WirelessInterface> {
            let mut m = lock();
            m.calls.push("start_auto".to_string());
            m.interfaces.first().cloned().ok_or(Error::NoInterfaces)
        }

        async fn start_on(name: &str) -> Result<WirelessInterface> {
            let mut m = lock();
            m.calls.push(format!("start_on {name}"));
            m.interfaces
                .iter()
                .find(|i| i.name() == name)
                .cloned()
                .ok_or_else(|| Error::NotFound {
                    name: name.to_string(),
                    available: String::new(),
                })
        }

        async fn start_as(name: &str, new_name: &str) -> Result<WirelessInterface> {
            let mut m = lock();
            m.calls.push(format!("start_as {name}->{new_name}"));
            Ok(iface(new_name, InterfaceMode::Monitor))
        }

        async fn rename(current: &str, new: &str) -> Result<()> {
            lock().calls.push(format!("rename {current}->{new}"));
            Ok(())
        }

        async fn set_channel(
            iface: &WirelessInterface,
            freq_mhz: u32,
            _width: ChannelWidth,
        ) -> Result<()> {
            lock()
                .calls
                .push(format!("set_channel {} {freq_mhz}", iface.name()));
            Ok(())
        }

        async fn stop(name: &str) -> Result<()> {
            let mut m = lock();
            m.calls.push(format!("stop {name}"));
            if m.fail_stop.iter().any(|n| n == name) {
                return Err(Error::NotFound {
                    name: name.to_string(),
                    available: String::new(),
                });
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn restore_named_renames_then_stops() {
        let _scope = mock_scope();
        let out = restore_named_with::<MockBackend>("mon0", "wlan0")
            .await
            .unwrap();
        assert_eq!(out, "wlan0");
        // Rename must precede stop: the interface has to carry its original name
        // before it is handed back to a network manager.
        assert_eq!(calls(), vec!["rename mon0->wlan0", "stop wlan0"]);
    }

    #[tokio::test]
    async fn restore_named_skips_matching_rename() {
        let _scope = mock_scope();
        restore_named_with::<MockBackend>("wlan0", "wlan0")
            .await
            .unwrap();
        assert_eq!(calls(), vec!["stop wlan0"]);
    }

    #[tokio::test]
    async fn stop_all_tolerates_failures() {
        let _scope = mock_scope();
        set_interfaces(vec![
            iface("wlan0", InterfaceMode::Monitor),
            iface("wlan1", InterfaceMode::Managed),
            iface("wlan2", InterfaceMode::Monitor),
        ]);
        fail_stop("wlan0");

        let restored = stop_all_with::<MockBackend>().await.unwrap();

        // wlan0's stop failed, wlan1 is managed (never touched), wlan2 restored.
        assert_eq!(restored, vec!["wlan2"]);
        let calls = calls();
        assert!(calls.contains(&"stop wlan0".to_string()));
        assert!(calls.contains(&"stop wlan2".to_string()));
        assert!(!calls.contains(&"stop wlan1".to_string()));
    }

    #[tokio::test]
    async fn set_channel_resolves_frequency() {
        let _scope = mock_scope();
        set_interfaces(vec![iface("wlan0", InterfaceMode::Monitor)]);

        let name =
            set_channel_with::<MockBackend>(SetChannel::new("wlan0", 1, BandScope::ExceptSixGhz))
                .await
                .unwrap();

        assert_eq!(name, "wlan0");
        assert_eq!(calls(), vec!["detect", "set_channel wlan0 2412"]);
    }

    #[tokio::test]
    async fn resolved_target_skips_detect() {
        let _scope = mock_scope();
        // No interfaces are programmed: if the resolved path called detect(),
        // resolution would fail. It must not, since the interface is already in hand.
        let request = SetChannel::from_iface(
            iface("wlan0", InterfaceMode::Monitor),
            1,
            BandScope::ExceptSixGhz,
        );

        let name = set_channel_with::<MockBackend>(request).await.unwrap();

        assert_eq!(name, "wlan0");
        // Straight to set_channel, with no "detect" in the call log.
        assert_eq!(calls(), vec!["set_channel wlan0 2412"]);
    }

    #[tokio::test]
    async fn set_channel_rejects_unknown_iface() {
        let _scope = mock_scope();
        set_interfaces(vec![iface("wlan0", InterfaceMode::Monitor)]);

        let err =
            set_channel_with::<MockBackend>(SetChannel::new("wlan9", 1, BandScope::ExceptSixGhz))
                .await
                .unwrap_err();

        assert!(matches!(err, Error::NotFound { .. }));
    }

    #[tokio::test]
    async fn start_monitor_returns_guard() {
        let _scope = mock_scope();
        set_interfaces(vec![iface("wlan0", InterfaceMode::Monitor)]);

        let guard = start_monitor_with::<MockBackend>().await.unwrap();
        assert_eq!(guard.name(), "wlan0");
        assert_eq!(guard.original_name(), "wlan0");
        guard.persist(); // disarm so the guard's Drop is a no-op
    }

    #[tokio::test]
    async fn start_as_rejects_invalid_name() {
        let _scope = mock_scope();
        let err = start_monitor_as_with::<MockBackend>("wlan0", "bad name")
            .await
            .unwrap_err();
        assert!(matches!(err, Error::InvalidInterfaceName { .. }));
        // Validation happens first, so the backend is never called.
        assert!(calls().is_empty());
    }

    #[tokio::test]
    async fn guard_restore_renames_back_then_stops() {
        let _scope = mock_scope();
        // A renamed session: current `mon0`, original `wlan0`.
        let guard =
            MonitorGuard::from_rename("wlan0".to_string(), iface("mon0", InterfaceMode::Monitor));
        let restored = guard.restore().await.unwrap();
        assert_eq!(restored, "wlan0");
        assert_eq!(calls(), vec!["rename mon0->wlan0", "stop wlan0"]);
    }

    #[tokio::test]
    async fn persisted_guard_drop_touches_nothing() {
        let _scope = mock_scope();
        let guard =
            MonitorGuard::from_rename("wlan0".to_string(), iface("mon0", InterfaceMode::Monitor));
        assert_eq!(guard.persist(), "mon0");
        // persist() disarmed the guard, so dropping it makes no backend calls.
        assert!(calls().is_empty());
    }

    #[tokio::test]
    async fn armed_guard_drop_restores_via_backend() {
        let _scope = mock_scope();
        {
            // Armed guard for a renamed session; dropping it must run teardown.
            let _guard = MonitorGuard::from_rename(
                "wlan0".to_string(),
                iface("mon0", InterfaceMode::Monitor),
            );
        }
        // Drop runs the restore to completion on its own thread and blocks, so
        // by here the mock has recorded the same rename-then-stop as restore().
        assert_eq!(calls(), vec!["rename mon0->wlan0", "stop wlan0"]);
    }
}
