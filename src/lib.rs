//! `rfmon`, a simple, cross-platform library for driving a wireless interface
//! in and out of 802.11 monitor mode.
//!
//! The whole library is three version- and distro-agnostic calls:
//!
//! ```no_run
//! # #[tokio::main]
//! # async fn main() -> rfmon::Result<()> {
//! // Auto-select the best capable interface and enter monitor mode.
//! let mon = rfmon::start_monitor().await?;
//!
//! // ... capture raw 802.11 frames on `mon.name()` ...
//!
//! // Restore normal managed networking (also happens if `mon` just drops).
//! mon.restore().await?;
//! # Ok(())
//! # }
//! ```
//!
//! * [`start_monitor`] picks the best monitor-capable radio using the scoring in
//!   [`InterfaceInfo::monitor_score`].
//! * [`start_monitor_on`] targets a specific interface by name.
//! * [`start_monitor_as`] additionally renames the interface for the session.
//! * [`stop_monitor`] returns an interface to managed networking by name: the
//!   stateless recovery path when you don't hold a guard.
//!
//! The `start_*` functions return a [`MonitorBuilder`], which does nothing until
//! awaited and then yields a [`MonitorGuard`] that restores the interface when it
//! drops (or via [`MonitorGuard::restore`]), so cleanup is scope-safe even on an
//! early return. The builder is also where a channel can be named, so a session
//! is specified in one statement: `start_monitor().on_channel(36).await?`.
//!
//! [`stop_monitor`] covers what a guard cannot: fixing an interface by name
//! after a crash or from another process. Everything requires `CAP_NET_ADMIN`
//! (root) and is durable across distributions. A host with no NetworkManager,
//! bare wpa_supplicant, or neither is handled.
//!
//! # Platform support
//!
//! Linux is fully implemented over nl80211/rtnetlink with NetworkManager and
//! wpa_supplicant coordination. Windows is a compile-only stub pending an
//! Npcap-based backend; its calls return `WindowsError::Unsupported`.
//!
//! # Features
//!
//! * `dbus` *(default)*: release and reclaim the interface through
//!   NetworkManager (`org.freedesktop.NetworkManager`) and wpa_supplicant
//!   (`fi.w1.wpa_supplicant1`) over the system bus. A service that is absent, or
//!   the absence of a system bus altogether, is detected and skipped rather than
//!   treated as an error. Turning this off leaves entering and leaving monitor
//!   mode as the raw nl80211/rtnetlink switch with no service handoff, which is correct
//!   on a host that runs neither, and it drops the whole `zbus` subtree:
//!
//!   ```toml
//!   rfmon = { version = "0.1", default-features = false }
//!   ```
//!
//! * `cli`: build the `rfmon` binary. Off by default so library consumers do
//!   not pull in a tracing subscriber. Install with
//!   `cargo install rfmon --features cli`.
//!
//! # The data model
//!
//! Two types, and interface names as the currency between them.
//!
//! [`InterfaceInfo`] is a *snapshot* of one radio's facts: MAC, bands, driver,
//! bus, and what it was doing when the enumeration ran. Get one from
//! [`InterfaceInfo::detect`] (every interface) or [`InterfaceInfo::lookup`] (one
//! by name); both need no privileges. Every getter on it is a free field read,
//! and it does not track the interface: `is_monitor()` reports what was true at
//! the dump, so re-read it when it matters.
//!
//! [`MonitorGuard`] is an owned *session*. It holds the snapshot it started from
//! ([`MonitorGuard::info`]), reads live state on request
//! ([`MonitorGuard::tuning`]), and restores the interface when it drops.
//!
//! Names are what pass between them and what every entry point takes. A name is
//! also the only one of the three that outlives the process, which is why
//! [`stop_monitor`] takes one rather than an object.

#![warn(missing_docs)]

pub mod errors;

mod cleanup;
mod interface;
mod monitor;

// Under `test`, `monitor` aliases its `Backend` to an in-memory mock, so the
// real platform backend is never dispatched to and its production-only paths
// read as dead code. Allow that under `test` only; non-test `build`/`clippy`
// still flag genuinely unused code here.
#[cfg(target_os = "linux")]
#[cfg_attr(test, allow(dead_code))]
mod linux;
#[cfg(target_os = "windows")]
#[cfg_attr(test, allow(dead_code))]
mod windows;

// Exactly one backend is compiled in per target, and `crate::monitor::Backend`
// aliases it. On an unsupported target the build stops here with an explanation;
// `unsupported` then supplies a placeholder `Backend` so that explanation is the
// *only* error, rather than being buried under an "undeclared type `Backend`"
// at every call site in `monitor`.
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
compile_error!(
    "rfmon has no monitor-mode backend for this target: Linux is implemented \
     over nl80211, Windows is a compile-only stub, and nothing else is supported. \
     802.11 monitor mode is an OS-level capability, so there is no portable fallback."
);
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
mod unsupported;

pub use cleanup::MonitorGuard;
pub use errors::{Error, Result};
pub use interface::{
    Band, BandKind, BusKind, ChannelWidth, Frequency, InterfaceInfo, InterfaceMode, Tuning,
    channel_from_mhz,
};
pub use monitor::{
    MonitorBuilder, SetChannel, set_channel, set_channel_6g, start_monitor, start_monitor_as,
    start_monitor_on, stop_all_monitors, stop_monitor,
};

/* Types */

/// A 48-bit IEEE 802 MAC address.
///
/// # Examples
///
/// ```
/// use rfmon::MacAddr;
///
/// let mac = MacAddr([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
/// assert_eq!(mac.to_string(), "de:ad:be:ef:00:01");
/// ```
///
/// `Debug` is implemented by hand rather than derived: the derived form prints
/// the raw byte array (`MacAddr([222, 173, 190, 239, 0, 1])`), which is
/// unreadable in a log line or an error. The manual impl prints the canonical
/// colon-separated hex a reader can match against `ip link` output.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr(pub [u8; 6]);

/* Implementations */

impl MacAddr {
    /// The all-zero address (`00:00:00:00:00:00`).
    pub const ZERO: MacAddr = MacAddr([0u8; 6]);

    /// Returns the raw six address bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use rfmon::MacAddr;
    ///
    /// let mac = MacAddr([1, 2, 3, 4, 5, 6]);
    /// assert_eq!(mac.as_bytes(), &[1, 2, 3, 4, 5, 6]);
    /// ```
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }
}

impl core::fmt::Display for MacAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let b = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5]
        )
    }
}

impl core::fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MacAddr({self})")
    }
}
