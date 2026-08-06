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
//! The three `start_*` functions return a [`MonitorBuilder`], which does nothing
//! until it is awaited and then yields a [`MonitorGuard`] whose scope owns the
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
use crate::interface::{BandScope, ChannelWidth, InterfaceInfo, Tuning, resolve_frequency};
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
#[cfg(all(not(target_os = "linux"), not(test)))]
use crate::unsupported::UnsupportedBackend as Backend;
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
    async fn detect() -> Result<Vec<InterfaceInfo>>;

    /// Select the best capable interface and put it into monitor mode.
    ///
    /// Returns the interface that was activated. Errors if no interface is
    /// present ([`crate::Error::NoInterfaces`]) or none are monitor-capable
    /// ([`crate::Error::NoMonitorCapable`]).
    async fn start_auto() -> Result<InterfaceInfo>;

    /// Put a specific named interface into monitor mode, skipping selection.
    async fn start_on(name: &str) -> Result<InterfaceInfo>;

    /// Put a named interface into monitor mode and rename it to `new_name`.
    ///
    /// Returns the interface under its new name.
    async fn start_as(name: &str, new_name: &str) -> Result<InterfaceInfo>;

    /// Rename an interface (e.g. back to its original name during teardown).
    async fn rename(current: &str, new: &str) -> Result<()>;

    /// Set the operating channel of a monitor-mode interface.
    async fn set_channel(iface: &InterfaceInfo, freq_mhz: u32, width: ChannelWidth) -> Result<()>;

    /// Read back the channel an interface is currently sitting on.
    ///
    /// Live state, so this always reaches the OS rather than reporting anything
    /// carried from an earlier enumeration.
    async fn read_tuning(iface: &InterfaceInfo) -> Result<Tuning>;

    /// Take a named interface out of monitor mode and restore managed
    /// networking (returning control to NetworkManager / wpa_supplicant).
    async fn stop(name: &str) -> Result<()>;
}

/* Public API */

/// Automatically select the best monitor-capable interface and enter monitor
/// mode.
///
/// Uses the scoring in [`InterfaceInfo::monitor_score`] to pick the most
/// suitable radio: a known monitor-capable USB adapter that is idle outranks
/// the built-in card carrying the host's connection.
///
/// Returns a [`MonitorBuilder`], which does nothing until awaited and then
/// yields an RAII [`MonitorGuard`]. The guard restores managed networking when
/// it drops (or via [`MonitorGuard::restore`]); read the chosen interface with
/// [`MonitorGuard::name`]. Park on a channel in the same statement with
/// [`on_channel`](MonitorBuilder::on_channel). Requires `CAP_NET_ADMIN` (root).
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
///
/// // Or select, enter, and tune in one statement.
/// let mon = rfmon::start_monitor().on_channel(6).await?;
/// # Ok(())
/// # }
/// ```
pub fn start_monitor() -> MonitorBuilder {
    MonitorBuilder::new(StartTarget::Auto)
}

/// Enter monitor mode on a specific interface by name, skipping scoring.
///
/// Returns a [`MonitorBuilder`], which does nothing until awaited and then
/// yields an RAII [`MonitorGuard`] that restores managed networking when it
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
pub fn start_monitor_on(name: &str) -> MonitorBuilder {
    MonitorBuilder::new(StartTarget::Named(name.to_string()))
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
/// returning a [`MonitorBuilder`] that yields an RAII [`MonitorGuard`] when
/// awaited.
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
pub fn start_monitor_as(name: &str, new_name: &str) -> MonitorBuilder {
    MonitorBuilder::new(StartTarget::Renamed {
        name: name.to_string(),
        new_name: new_name.to_string(),
    })
}

/// Set the operating channel of a monitor-mode interface, on 2.4 or 5 GHz.
///
/// Returns a builder that runs when awaited and yields the interface name. The
/// channel is a plain channel number: 2.4 GHz is 1-14 and 5 GHz is 32-177, and
/// those two do not overlap, so the number alone picks the band. The frequency
/// is then resolved against the channels the device actually supports. Defaults
/// to 20 MHz, which carries all management and EAPOL traffic.
///
/// **6 GHz is deliberately not searched here**, because it reuses channel numbers that
/// 2.4 GHz and 5 GHz already use (1, 5, 9, 13 and 149-177), so a bare number
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

/// A pending monitor-mode session, produced by [`start_monitor`],
/// [`start_monitor_on`], or [`start_monitor_as`].
///
/// Nothing has touched the hardware yet: no interface has been released from
/// its network manager, no mode has been switched, nothing has been verified.
/// Awaiting the builder does all of that and yields the [`MonitorGuard`] that
/// owns the session.
///
/// Optionally park the interface on a channel in the same statement with
/// [`on_channel`](Self::on_channel) or [`on_channel_6g`](Self::on_channel_6g),
/// which saves a second round trip and, more importantly, means the session is
/// never briefly live on whatever channel the driver happened to leave it on:
///
/// ```no_run
/// use rfmon::ChannelWidth;
///
/// # #[tokio::main]
/// # async fn main() -> rfmon::Result<()> {
/// let mon = rfmon::start_monitor()
///     .on_channel(36)
///     .with_width(ChannelWidth::Mhz40Above)
///     .await?;
/// # Ok(())
/// # }
/// ```
///
/// If the channel set fails, the session is torn back down and the error
/// returned, rather than handing back a guard parked somewhere the caller did
/// not ask for. See [`on_channel`](Self::on_channel).
#[derive(Debug)]
#[must_use = "a monitor session is not started until the builder is awaited"]
pub struct MonitorBuilder {
    target: StartTarget,
    // The channel to park on once monitor mode is confirmed, carrying the band
    // scope fixed by which `on_channel*` call set it. `None` leaves the
    // interface wherever the driver left it, which is what a caller who only
    // wants the mode switch gets.
    channel: Option<(u32, BandScope)>,
    width: ChannelWidth,
}

// Which interface a pending session targets, and under what name. One variant
// per `start_*` entry point, so the choice of entry point is carried as data
// until the builder is awaited rather than being baked into three separate
// futures.
#[derive(Debug)]
enum StartTarget {
    // Score every interface and take the best capture candidate.
    Auto,
    // A named interface, skipping scoring.
    Named(String),
    // A named interface, renamed to `new_name` for the life of the session.
    Renamed { name: String, new_name: String },
}

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
    Resolved(Box<InterfaceInfo>),
}

impl MonitorBuilder {
    fn new(target: StartTarget) -> Self {
        Self {
            target,
            channel: None,
            width: ChannelWidth::Mhz20,
        }
    }

    /// Park the interface on a 2.4 or 5 GHz channel once monitor mode is
    /// confirmed.
    ///
    /// The channel is resolved and applied exactly as
    /// [`MonitorGuard::set_channel`] would, verified frequency and width
    /// included, but without a second statement or a second interface lookup.
    ///
    /// Named `on_channel` rather than `set_channel` because it configures a
    /// session that has not started yet; nothing is tuned until the builder is
    /// awaited. 6 GHz is not searched here, for the reason
    /// [`set_channel`] explains: use
    /// [`on_channel_6g`](Self::on_channel_6g).
    ///
    /// # Errors
    ///
    /// If the channel cannot be resolved or the tune fails verification, the
    /// session is rolled back (managed mode restored, rename undone, interface
    /// handed back) and the channel error is returned. A guard is never
    /// returned parked on a channel other than the one requested: that is the
    /// silent wrong-channel capture the verified set exists to prevent.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #[tokio::main]
    /// # async fn main() -> rfmon::Result<()> {
    /// let mon = rfmon::start_monitor_on("wlan0").on_channel(11).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn on_channel(mut self, channel: u32) -> Self {
        self.channel = Some((channel, BandScope::ExceptSixGhz));
        self
    }

    /// Park the interface on a 6 GHz channel once monitor mode is confirmed.
    ///
    /// The 6 GHz counterpart to [`on_channel`](Self::on_channel), identical but
    /// for the band it searches. Calling both keeps the last one.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #[tokio::main]
    /// # async fn main() -> rfmon::Result<()> {
    /// let mon = rfmon::start_monitor().on_channel_6g(37).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn on_channel_6g(mut self, channel: u32) -> Self {
        self.channel = Some((channel, BandScope::SixGhzOnly));
        self
    }

    /// Set the bandwidth for the channel this builder will park on (default
    /// [`ChannelWidth::Mhz20`]).
    ///
    /// Has no effect without an [`on_channel`](Self::on_channel) or
    /// [`on_channel_6g`](Self::on_channel_6g), since there is then no channel
    /// set for it to apply to.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rfmon::ChannelWidth;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> rfmon::Result<()> {
    /// let mon = rfmon::start_monitor()
    ///     .on_channel(36)
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

impl IntoFuture for MonitorBuilder {
    type Output = Result<MonitorGuard>;
    type IntoFuture = Pin<Box<dyn Future<Output = Result<MonitorGuard>> + Send>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(start_with::<Backend>(self))
    }
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
    pub(crate) fn from_iface(iface: InterfaceInfo, channel: u32, scope: BandScope) -> Self {
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

// Backend interface enumeration, exposed to `InterfaceInfo::detect`.
pub(crate) async fn detect() -> Result<Vec<InterfaceInfo>> {
    Backend::detect().await
}

// Live channel readback, backing `MonitorGuard::tuning`.
pub(crate) async fn read_tuning(iface: &InterfaceInfo) -> Result<Tuning> {
    Backend::read_tuning(iface).await
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

async fn start_with<B: MonitorBackend>(request: MonitorBuilder) -> Result<MonitorGuard> {
    let guard = match request.target {
        StartTarget::Auto => MonitorGuard::new(B::start_auto().await?),
        StartTarget::Named(name) => MonitorGuard::new(B::start_on(&name).await?),
        StartTarget::Renamed { name, new_name } => {
            // Validated before the backend is touched: a malformed name is the
            // caller's mistake and costs nothing to catch, whereas discovering
            // it from a failed rename means an interface was switched into
            // monitor mode only to be rolled straight back out.
            crate::interface::validate_iface_name(&new_name)?;
            let iface = B::start_as(&name, &new_name).await?;
            MonitorGuard::from_rename(name, iface)
        }
    };

    let Some((channel, scope)) = request.channel else {
        return Ok(guard);
    };

    // Tune through the guard, which already holds the interface `enter`
    // resolved, so this costs one verified `SET_WIPHY` and no re-enumeration.
    let pending = match scope {
        BandScope::ExceptSixGhz => guard.set_channel(channel),
        BandScope::SixGhzOnly => guard.set_channel_6g(channel),
    }
    .with_width(request.width);

    // A guard handed back on the wrong channel is precisely the silent
    // wrong-channel capture `set_channel_verified` exists to prevent, so a
    // failed tune tears the session down instead of returning it
    // half-configured. This mirrors `enter`'s discipline: anything that fails
    // after the interface was released rolls back before returning.
    //
    // The restore is itself fallible. Its error is logged rather than returned,
    // because the channel failure is the one the caller asked about and the one
    // that explains why no guard came back; surfacing the teardown error
    // instead would hide the cause behind a consequence.
    if let Err(error) = set_channel_with::<B>(pending).await {
        if let Err(restore_error) = guard.restore().await {
            warn!(
                %restore_error,
                "could not restore the interface after a failed channel set",
            );
        }
        return Err(error);
    }

    Ok(guard)
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
        interfaces: Vec<InterfaceInfo>,
        fail_stop: Vec<String>,
        // The width the last `set_channel` was asked for. Kept out of the call
        // log because most tests assert on the exact call sequence and would
        // all have to spell out a width they do not care about.
        width: Option<ChannelWidth>,
        // What `read_tuning` reports back.
        tuning: Tuning,
        calls: Vec<String>,
    }

    impl MockState {
        const fn new() -> Self {
            Self {
                interfaces: Vec::new(),
                fail_stop: Vec::new(),
                width: None,
                tuning: Tuning::UNTUNED,
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

    fn set_interfaces(interfaces: Vec<InterfaceInfo>) {
        lock().interfaces = interfaces;
    }

    fn fail_stop(name: &str) {
        lock().fail_stop.push(name.to_string());
    }

    fn calls() -> Vec<String> {
        lock().calls.clone()
    }

    fn width_seen() -> Option<ChannelWidth> {
        lock().width
    }

    fn set_tuning(tuning: Tuning) {
        lock().tuning = tuning;
    }

    // A minimal interface carrying 2.4 GHz channel 1 (2412 MHz) so channel
    // resolution has something to resolve against.
    fn iface(name: &str, mode: InterfaceMode) -> InterfaceInfo {
        InterfaceInfo {
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
        async fn detect() -> Result<Vec<InterfaceInfo>> {
            let mut m = lock();
            m.calls.push("detect".to_string());
            Ok(m.interfaces.clone())
        }

        async fn start_auto() -> Result<InterfaceInfo> {
            let mut m = lock();
            m.calls.push("start_auto".to_string());
            m.interfaces.first().cloned().ok_or(Error::NoInterfaces)
        }

        async fn start_on(name: &str) -> Result<InterfaceInfo> {
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

        async fn start_as(name: &str, new_name: &str) -> Result<InterfaceInfo> {
            let mut m = lock();
            m.calls.push(format!("start_as {name}->{new_name}"));
            Ok(iface(new_name, InterfaceMode::Monitor))
        }

        async fn rename(current: &str, new: &str) -> Result<()> {
            lock().calls.push(format!("rename {current}->{new}"));
            Ok(())
        }

        async fn set_channel(
            iface: &InterfaceInfo,
            freq_mhz: u32,
            width: ChannelWidth,
        ) -> Result<()> {
            let mut m = lock();
            m.calls
                .push(format!("set_channel {} {freq_mhz}", iface.name()));
            m.width = Some(width);
            Ok(())
        }

        async fn read_tuning(iface: &InterfaceInfo) -> Result<Tuning> {
            let mut m = lock();
            m.calls.push(format!("read_tuning {}", iface.name()));
            Ok(m.tuning)
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

        let guard = start_with::<MockBackend>(start_monitor()).await.unwrap();
        assert_eq!(guard.name(), "wlan0");
        assert_eq!(guard.original_name(), "wlan0");
        guard.persist(); // disarm so the guard's Drop is a no-op
    }

    #[tokio::test]
    async fn start_as_rejects_invalid_name() {
        let _scope = mock_scope();
        let err = start_with::<MockBackend>(start_monitor_as("wlan0", "bad name"))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::InvalidInterfaceName { .. }));
        // Validation happens first, so the backend is never called.
        assert!(calls().is_empty());
    }

    // --- InterfaceInfo::lookup ---

    #[tokio::test]
    async fn lookup_finds_an_interface_by_name() {
        let _scope = mock_scope();
        set_interfaces(vec![
            iface("wlan0", InterfaceMode::Managed),
            iface("wlan1", InterfaceMode::Monitor),
        ]);

        let found = InterfaceInfo::lookup("wlan1").await.unwrap();
        assert_eq!(found.name(), "wlan1");
        assert!(found.is_monitor());
        // One enumeration, not one per field: the whole point of handing back
        // the record rather than answering questions about it.
        assert_eq!(calls(), vec!["detect"]);
    }

    #[tokio::test]
    async fn lookup_names_what_does_exist_when_it_misses() {
        let _scope = mock_scope();
        set_interfaces(vec![
            iface("wlan0", InterfaceMode::Managed),
            iface("wlan1", InterfaceMode::Managed),
        ]);

        let err = InterfaceInfo::lookup("wlan9").await.unwrap_err();
        // The available list is the useful half of this error: a wrong name is
        // usually a typo or a renamed interface, and both are answered by
        // seeing the real ones.
        match err {
            Error::NotFound { name, available } => {
                assert_eq!(name, "wlan9");
                assert_eq!(available, "wlan0, wlan1");
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn lookup_distinguishes_an_empty_system_from_a_miss() {
        let _scope = mock_scope();
        // No interfaces at all is a different problem from "not that one", and
        // an empty available list would read as a bug rather than an answer.
        let err = InterfaceInfo::lookup("wlan0").await.unwrap_err();
        assert!(matches!(err, Error::NoInterfaces));
    }

    // --- guard accessors ---

    #[tokio::test]
    async fn guard_exposes_its_interface_info() {
        let _scope = mock_scope();
        set_interfaces(vec![iface("wlan0", InterfaceMode::Monitor)]);

        let guard = start_with::<MockBackend>(start_monitor()).await.unwrap();
        // Static facts come off the snapshot the session already holds, so no
        // further backend traffic.
        assert_eq!(guard.info().name(), "wlan0");
        assert_eq!(guard.info().mac(), MacAddr::ZERO);
        assert_eq!(calls(), vec!["start_auto"]);
        guard.persist();
    }

    #[tokio::test]
    async fn guard_reads_tuning_live() {
        let _scope = mock_scope();
        set_interfaces(vec![iface("wlan0", InterfaceMode::Monitor)]);
        set_tuning(Tuning {
            freq_mhz: Some(2412),
            width_mhz: Some(20),
            center_mhz: Some(2412),
        });

        let guard = start_with::<MockBackend>(start_monitor()).await.unwrap();
        assert_eq!(guard.channel().await.unwrap(), Some(1));
        assert_eq!(guard.frequency().await.unwrap(), Some(2412));
        assert_eq!(guard.width().await.unwrap(), Some(ChannelWidth::Mhz20));

        // Live means live: each accessor reaches the backend rather than
        // reporting anything cached on the guard. It is also why `tuning` is
        // the one to reach for when more than one of these is wanted: this is
        // three reads of a value that arrives in one message.
        assert_eq!(
            calls(),
            vec![
                "start_auto",
                "read_tuning wlan0",
                "read_tuning wlan0",
                "read_tuning wlan0",
            ]
        );
        guard.persist();
    }

    #[tokio::test]
    async fn guard_reports_a_frequency_off_the_channel_grid() {
        let _scope = mock_scope();
        set_interfaces(vec![iface("wlan0", InterfaceMode::Monitor)]);
        // Between 2.4 GHz channels 1 and 2: a real frequency that maps to no
        // channel number. This is the case `frequency` exists for, since
        // `channel` can only answer `None`.
        set_tuning(Tuning {
            freq_mhz: Some(2413),
            width_mhz: Some(20),
            center_mhz: Some(2413),
        });

        let guard = start_with::<MockBackend>(start_monitor()).await.unwrap();
        assert_eq!(guard.channel().await.unwrap(), None);
        assert_eq!(guard.frequency().await.unwrap(), Some(2413));
        guard.persist();
    }

    #[tokio::test]
    async fn guard_tuning_answers_everything_in_one_read() {
        let _scope = mock_scope();
        set_interfaces(vec![iface("wlan0", InterfaceMode::Monitor)]);
        set_tuning(Tuning {
            freq_mhz: Some(5180),
            width_mhz: Some(40),
            center_mhz: Some(5190),
        });

        let guard = start_with::<MockBackend>(start_monitor()).await.unwrap();
        let tuning = guard.tuning().await.unwrap();
        assert_eq!(tuning.channel(), Some(36));
        assert_eq!(tuning.width(), Some(ChannelWidth::Mhz40Above));
        // Both answers from a single readback, which is why `tuning` exists
        // alongside the two conveniences.
        assert_eq!(calls(), vec!["start_auto", "read_tuning wlan0"]);
        guard.persist();
    }

    #[tokio::test]
    async fn guard_reports_an_untuned_interface_without_erroring() {
        let _scope = mock_scope();
        set_interfaces(vec![iface("wlan0", InterfaceMode::Monitor)]);

        let guard = start_with::<MockBackend>(start_monitor()).await.unwrap();
        // Not being on a channel is a state, not a failure: a freshly switched
        // interface reports exactly this until something tunes it.
        assert_eq!(guard.channel().await.unwrap(), None);
        assert!(!guard.tuning().await.unwrap().is_tuned());
        guard.persist();
    }

    // --- MonitorBuilder chaining ---

    #[tokio::test]
    async fn builder_does_nothing_until_awaited() {
        let _scope = mock_scope();
        set_interfaces(vec![iface("wlan0", InterfaceMode::Monitor)]);

        // Built and configured, never awaited: the hardware must be untouched.
        // This is the property `#[must_use]` protects, asserted rather than
        // assumed, since a builder that eagerly started work would make every
        // `start_*` call a side effect at the point of construction.
        let _unawaited = start_monitor()
            .on_channel(1)
            .with_width(ChannelWidth::Mhz40Above);
        assert!(calls().is_empty(), "calls were {:?}", calls());
    }

    #[tokio::test]
    async fn builder_enters_monitor_then_tunes() {
        let _scope = mock_scope();
        set_interfaces(vec![iface("wlan0", InterfaceMode::Monitor)]);

        let guard = start_with::<MockBackend>(start_monitor().on_channel(1))
            .await
            .unwrap();
        assert_eq!(guard.name(), "wlan0");

        // Order matters: the channel is set only after monitor mode is
        // confirmed. Tuning first would apply to an interface still in managed
        // mode, where the mode switch that follows can reset it.
        //
        // No `detect` between the two: the guard carries the interface `enter`
        // already resolved, which is the whole point of tuning through it.
        assert_eq!(calls(), vec!["start_auto", "set_channel wlan0 2412"]);
        guard.persist();
    }

    #[tokio::test]
    async fn builder_without_a_channel_does_not_tune() {
        let _scope = mock_scope();
        set_interfaces(vec![iface("wlan0", InterfaceMode::Monitor)]);

        let guard = start_with::<MockBackend>(start_monitor()).await.unwrap();
        assert_eq!(calls(), vec!["start_auto"]);
        guard.persist();
    }

    #[tokio::test]
    async fn builder_tunes_a_named_interface() {
        let _scope = mock_scope();
        set_interfaces(vec![iface("wlan0", InterfaceMode::Monitor)]);

        let guard = start_with::<MockBackend>(start_monitor_on("wlan0").on_channel(1))
            .await
            .unwrap();
        assert_eq!(calls(), vec!["start_on wlan0", "set_channel wlan0 2412"]);
        guard.persist();
    }

    #[tokio::test]
    async fn builder_rolls_back_when_the_channel_cannot_be_resolved() {
        let _scope = mock_scope();
        // The mock interface carries 2.4 GHz channel 1 only, so channel 44 is
        // not resolvable on it.
        set_interfaces(vec![iface("wlan0", InterfaceMode::Monitor)]);

        let err = start_with::<MockBackend>(start_monitor().on_channel(44))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::ChannelUnavailable { channel: 44, .. }));

        // The session was entered and then torn back down. Returning the guard
        // anyway would leave the caller holding a monitor interface parked on
        // whatever channel the driver defaulted to, which is the failure mode
        // the verified set exists to prevent.
        assert_eq!(calls(), vec!["start_auto", "stop wlan0"]);
    }

    #[tokio::test]
    async fn builder_rollback_undoes_a_rename_too() {
        let _scope = mock_scope();
        set_interfaces(vec![iface("wlan0", InterfaceMode::Monitor)]);

        let err = start_with::<MockBackend>(start_monitor_as("wlan0", "mon0").on_channel(44))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::ChannelUnavailable { .. }));

        // Rollback goes through the guard, so the rename is undone before the
        // interface is handed back, and the handback is addressed to the name
        // the interface actually carries again.
        assert_eq!(
            calls(),
            vec!["start_as wlan0->mon0", "rename mon0->wlan0", "stop wlan0"]
        );
    }

    #[tokio::test]
    async fn builder_carries_the_requested_width() {
        let _scope = mock_scope();
        set_interfaces(vec![iface("wlan0", InterfaceMode::Monitor)]);

        let guard = start_with::<MockBackend>(
            start_monitor()
                .on_channel(1)
                .with_width(ChannelWidth::Mhz40Below),
        )
        .await
        .unwrap();
        assert_eq!(width_seen(), Some(ChannelWidth::Mhz40Below));
        guard.persist();
    }

    #[tokio::test]
    async fn builder_keeps_the_last_band_choice() {
        let _scope = mock_scope();
        set_interfaces(vec![iface("wlan0", InterfaceMode::Monitor)]);

        // `on_channel_6g` then `on_channel` leaves a 2.4/5 GHz request, so
        // channel 1 resolves against the mock's 2.4 GHz band rather than
        // failing as a 6 GHz channel the device does not have.
        let guard = start_with::<MockBackend>(start_monitor().on_channel_6g(1).on_channel(1))
            .await
            .unwrap();
        assert_eq!(calls(), vec!["start_auto", "set_channel wlan0 2412"]);
        guard.persist();
    }

    #[tokio::test]
    async fn builder_resolves_six_ghz_in_the_six_ghz_band() {
        let _scope = mock_scope();
        // 6 GHz channel 1 is 5955 MHz; 2.4 GHz channel 1 is 2412 MHz. Both are
        // present, so the frequency that comes back is what proves the scope
        // was carried through rather than defaulted.
        let mut sixe = iface("wlan0", InterfaceMode::Monitor);
        sixe.bands.push(Band {
            kind: BandKind::SixGhz,
            frequencies: vec![Frequency {
                mhz: 5955,
                channel: Some(1),
                disabled: false,
                radar: false,
            }],
        });
        set_interfaces(vec![sixe]);

        let guard = start_with::<MockBackend>(start_monitor().on_channel_6g(1))
            .await
            .unwrap();
        assert_eq!(calls(), vec!["start_auto", "set_channel wlan0 5955"]);
        guard.persist();
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
