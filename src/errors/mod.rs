//! Crate error types.
//!
//! Platform-specific errors live in per-platform files under `errors/` and are
//! aggregated here into a single public [`Error`]. Each of those files is
//! `cfg`-gated to one target, so the split is what keeps a Linux-only error out
//! of a Windows build. Callers import [`Result`] and either handle the
//! crate-level [`Error`] or match into the platform error it transparently
//! wraps.
//!
//! Selection failures (no interfaces, none monitor-capable, a named interface
//! that does not exist) are *platform-neutral*, since the same logic runs on every
//! OS, so they are variants on [`Error`] directly rather than on any platform
//! error. Giving them their own wrapper enum to mirror the per-platform layout
//! would buy nothing: they are not conditionally compiled, and it would leave
//! the aggregate [`Error`] a wrapper around wrappers, with callers matching two
//! layers deep for something as ordinary as `NotFound`.

#[cfg(target_os = "linux")]
mod linux_errors;
#[cfg(target_os = "windows")]
mod windows_errors;

#[cfg(target_os = "linux")]
pub use linux_errors::{FrequencyReadback, LinuxError, WidthReadback};
#[cfg(target_os = "windows")]
pub use windows_errors::WindowsError;

/// Convenience alias for fallible operations across the crate.
pub type Result<T> = std::result::Result<T, Error>;

/* Types */

/// The unified error type returned across the public API.
///
/// Platform-neutral selection failures are their own variants; anything that
/// originates in an OS-specific control path is wrapped transparently in the
/// matching platform error.
///
/// Marked `#[non_exhaustive]`: new failure modes are expected as backends grow,
/// so downstream `match`es need a wildcard arm and adding a variant stays a
/// minor-version change.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /* Interface selection (platform-neutral) */
    //
    // Failures choosing an interface, independent of the OS backend.
    /// The system reported no wireless interfaces at all.
    #[error("no wireless interfaces found on this system")]
    NoInterfaces,

    /// No detected interface is capable of monitor mode.
    #[error("no monitor-capable wireless interface found (checked {checked} interface(s))")]
    NoMonitorCapable {
        /// How many interfaces were inspected before giving up.
        checked: usize,
    },

    /// The interface is already in monitor mode, so something else owns it.
    ///
    /// `rfmon` switches an interface in place rather than cloning it, and it
    /// keeps no ownership marker, so it cannot tell its own leftover from
    /// another tool's live capture. Taking the interface anyway is destructive
    /// in both directions: it hijacks a capture that may be running, and
    /// restoring it to managed mode afterwards breaks the other tool's teardown:
    /// `airmon-ng stop` looks for monitor mode to identify what it created,
    /// and refuses when it finds a managed interface. That leaves a state
    /// neither tool will clean up.
    ///
    /// Clear it deliberately with [`stop_monitor`](crate::stop_monitor) and then
    /// start again.
    #[error(
        "interface '{iface}' is already in monitor mode and may be in use by another tool; \
         release it with stop_monitor(\"{iface}\") first if that state is stale"
    )]
    AlreadyMonitor {
        /// The interface that is already in monitor mode.
        iface: String,
    },

    /// A named interface was requested but does not exist.
    #[error("wireless interface '{name}' not found (available: [{available}])")]
    NotFound {
        /// The interface name that was requested.
        name: String,
        /// Comma-separated list of interface names that were found.
        available: String,
    },

    /// The interface's device has no such channel, in any band.
    ///
    /// The hardware simply does not reach that frequency. Distinct from
    /// [`ChannelDisabled`](Self::ChannelDisabled), where the device does have
    /// the channel and something else is ruling it out.
    #[error("channel {channel} is not available on interface '{iface}'")]
    ChannelUnavailable {
        /// The channel number that was requested.
        channel: u32,
        /// The interface it was requested on.
        iface: String,
    },

    /// The device has the channel, but the regulatory domain disables it.
    ///
    /// Separated from [`ChannelUnavailable`](Self::ChannelUnavailable) because
    /// the two have different fixes and only one of them has a fix at all. "Not
    /// available" reads as a hardware limit and sends the operator looking for
    /// another adapter; the real cause is usually a regulatory domain narrower
    /// than the hardware (2.4 GHz channels 12 to 14 outside the EU/JP, or most
    /// of 5 GHz on an unset domain), which is a setting, not a limitation.
    ///
    /// `rfmon` does not change the regulatory domain: it is system-wide state
    /// with a lifetime unrelated to any capture session, so it sits outside what
    /// this library manages. `iw reg get` reports it and `iw reg set` changes
    /// it.
    #[error(
        "channel {channel} exists on interface '{iface}' but is disabled by the current \
         regulatory domain (check it with `iw reg get`)"
    )]
    ChannelDisabled {
        /// The channel number that was requested.
        channel: u32,
        /// The interface it was requested on.
        iface: String,
    },

    /// The channel exists on this device, but in the band the call did not
    /// search.
    ///
    /// `set_channel` covers 2.4 and 5 GHz; `set_channel_6g` covers 6 GHz. The
    /// two bands reuse channel numbers (1, 5, 9, 13 and 149–177), so which
    /// function you call is what selects the band, and this error names the one
    /// that would have found the channel.
    #[error("channel {channel} on '{iface}' is in another band; use {alternative}() to tune it")]
    WrongBand {
        /// The channel number that was requested.
        channel: u32,
        /// The interface it was requested on.
        iface: String,
        /// The entry point that searches the band this channel is in, e.g.
        /// `"set_channel_6g"`.
        alternative: &'static str,
    },

    /// The channel number maps to more than one frequency within a single band.
    ///
    /// Cross-band collisions are resolved by the choice of entry point (see
    /// [`WrongBand`](Self::WrongBand)), so this is the residual case: a device
    /// reporting the same channel number twice inside one band.
    #[error("channel {channel} is ambiguous on '{iface}': it matches more than one frequency")]
    AmbiguousChannel {
        /// The channel number that was requested.
        channel: u32,
        /// The interface it was requested on.
        iface: String,
    },

    /// A requested interface name is not a valid kernel netdev name.
    #[error("invalid interface name '{name}': {reason}")]
    InvalidInterfaceName {
        /// The offending name.
        name: String,
        /// Why it was rejected.
        reason: &'static str,
    },

    /* Platform backends */
    //
    // OS-specific control-path failures, wrapped transparently.
    /// A failure in the Linux (nl80211 / NetworkManager / wpa_supplicant) path.
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    Linux(#[from] LinuxError),

    /// A failure in the Windows backend.
    #[cfg(target_os = "windows")]
    #[error(transparent)]
    Windows(#[from] WindowsError),
}
